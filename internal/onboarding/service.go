package onboarding

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"new_radar/internal/mib"
	"new_radar/internal/snmp"

	"gopkg.in/yaml.v3"
)

// mibNewParser wraps mib.NewParser for use in onboarding analysis.
var mibNewParser = mib.NewParser

// CaseStatus tracks the onboarding pipeline state.
type CaseStatus string

const (
	StatusIntake      CaseStatus = "intake"
	StatusEvidence    CaseStatus = "evidence"
	StatusAnalyzing   CaseStatus = "analyzing"
	StatusDraft       CaseStatus = "draft"
	StatusReview      CaseStatus = "review"
	StatusTesting     CaseStatus = "testing"
	StatusApproved    CaseStatus = "approved"
)

// Case represents an onboarding case in the database.
type Case struct {
	ID          int64      `json:"id"`
	Vendor      string     `json:"vendor"`
	Model       string     `json:"model"`
	Firmware    string     `json:"firmware,omitempty"`
	Customer    string     `json:"customer,omitempty"`
	SupportTier string     `json:"support_tier"`
	Status      CaseStatus `json:"status"`
	Owner       string     `json:"owner,omitempty"`
	Dir         string     `json:"dir"` // onboarding/{vendor}_{model}
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// IntakeRequest is the input for creating a new onboarding case.
type IntakeRequest struct {
	Vendor           string   `json:"vendor" yaml:"vendor"`
	Model            string   `json:"model" yaml:"model"`
	Firmware         string   `json:"firmware,omitempty" yaml:"firmware,omitempty"`
	Customer         string   `json:"customer,omitempty" yaml:"customer,omitempty"`
	RequiredFeatures []string `json:"required_features,omitempty" yaml:"required_features,omitempty"`
	SupportTier      string   `json:"support_tier" yaml:"support_tier"`
	Urgency          string   `json:"urgency,omitempty" yaml:"urgency,omitempty"`
	Owner            string   `json:"owner,omitempty" yaml:"owner,omitempty"`
}

// FingerprintRequest is fingerprint data submitted for a case.
type FingerprintRequest struct {
	SysObjectID  string `json:"sys_object_id" yaml:"sysObjectID"`
	SysDescr     string `json:"sys_descr" yaml:"sysDescr"`
	SysName      string `json:"sys_name,omitempty" yaml:"sysName,omitempty"`
	SNMPVersion  string `json:"snmp_version" yaml:"snmp_version"`
	Community    string `json:"community" yaml:"community"`
	IP           string `json:"ip" yaml:"ip"`
	SSHAvailable bool   `json:"ssh_available" yaml:"ssh_available"`
	SSHPrompt    string `json:"ssh_prompt,omitempty" yaml:"ssh_prompt_sample,omitempty"`
	CLIStyle     string `json:"cli_style,omitempty" yaml:"cli_style,omitempty"`
}

// CollectResult summarizes what was collected during auto-collect.
type CollectResult struct {
	Walks []CollectWalk `json:"walks"`
	Total int           `json:"total_entries"`
}

type CollectWalk struct {
	Name    string `json:"name"`
	OIDRoot string `json:"oid_root"`
	Entries int    `json:"entries"`
	File    string `json:"file"`
}

// Service handles onboarding operations.
type Service struct {
	db      *sql.DB
	baseDir string // root onboarding directory
	snmp    *snmp.Client
	// collectCallback is called when async collect completes (taskID, result JSON or error)
	collectCallback func(taskID string, result *CollectResult, err error)
}

func NewService(db *sql.DB, baseDir string) (*Service, error) {
	s := &Service{db: db, baseDir: baseDir}
	if err := s.createTable(); err != nil {
		return nil, err
	}
	return s, nil
}

// SetSNMPClient sets the SNMP client for auto-collect.
func (s *Service) SetSNMPClient(c *snmp.Client) {
	s.snmp = c
}

// SetCollectCallback sets the callback for async collect completion.
func (s *Service) SetCollectCallback(cb func(string, *CollectResult, error)) {
	s.collectCallback = cb
}

func (s *Service) createTable() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS onboarding_cases (
			id          INTEGER PRIMARY KEY,
			vendor      TEXT NOT NULL,
			model       TEXT NOT NULL,
			firmware    TEXT,
			customer    TEXT,
			support_tier TEXT NOT NULL DEFAULT 'B',
			status      TEXT NOT NULL DEFAULT 'intake',
			owner       TEXT,
			dir         TEXT NOT NULL,
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	return err
}

// CreateCase creates a new onboarding case. Rejects duplicates by vendor+model.
func (s *Service) CreateCase(req *IntakeRequest) (*Case, error) {
	// Check for existing case with same vendor+model (case-insensitive)
	var count int
	s.db.QueryRow(
		"SELECT COUNT(*) FROM onboarding_cases WHERE LOWER(vendor)=LOWER(?) AND LOWER(model)=LOWER(?)",
		req.Vendor, req.Model,
	).Scan(&count)
	if count > 0 {
		return nil, fmt.Errorf("onboarding case for %s %s already exists", req.Vendor, req.Model)
	}

	dirName := fmt.Sprintf("%s_%s", strings.ToLower(req.Vendor), strings.ToLower(strings.ReplaceAll(req.Model, " ", "_")))
	caseDir := filepath.Join(s.baseDir, dirName)

	// Create directory structure
	dirs := []string{
		caseDir,
		filepath.Join(caseDir, "evidence"),
		filepath.Join(caseDir, "evidence", "mibs"),
		filepath.Join(caseDir, "ai_drafts"),
		filepath.Join(caseDir, "final"),
		filepath.Join(caseDir, "final", "snmprec"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return nil, fmt.Errorf("create dir %s: %w", d, err)
		}
	}

	// Write intake.yaml
	intakeData, _ := yaml.Marshal(req)
	os.WriteFile(filepath.Join(caseDir, "intake.yaml"), intakeData, 0644)

	now := time.Now()
	tier := req.SupportTier
	if tier == "" {
		tier = "B"
	}

	res, err := s.db.Exec(
		`INSERT INTO onboarding_cases (vendor, model, firmware, customer, support_tier, status, owner, dir, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.Vendor, req.Model, req.Firmware, req.Customer, tier, StatusIntake, req.Owner, dirName, now, now,
	)
	if err != nil {
		return nil, err
	}

	id, _ := res.LastInsertId()
	return &Case{
		ID: id, Vendor: req.Vendor, Model: req.Model, Firmware: req.Firmware,
		Customer: req.Customer, SupportTier: tier, Status: StatusIntake,
		Owner: req.Owner, Dir: dirName, CreatedAt: now, UpdatedAt: now,
	}, nil
}

// GetCase returns an onboarding case by ID.
func (s *Service) GetCase(id int64) (*Case, error) {
	var c Case
	var firmware, customer, owner sql.NullString
	err := s.db.QueryRow(
		`SELECT id, vendor, model, firmware, customer, support_tier, status, owner, dir, created_at, updated_at
		 FROM onboarding_cases WHERE id = ?`, id,
	).Scan(&c.ID, &c.Vendor, &c.Model, &firmware, &customer, &c.SupportTier, &c.Status, &owner, &c.Dir, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	c.Firmware = firmware.String
	c.Customer = customer.String
	c.Owner = owner.String
	return &c, nil
}

// ListCases returns all onboarding cases.
func (s *Service) ListCases() ([]Case, error) {
	rows, err := s.db.Query(
		`SELECT id, vendor, model, firmware, customer, support_tier, status, owner, dir, created_at, updated_at
		 FROM onboarding_cases ORDER BY id DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cases []Case
	for rows.Next() {
		var c Case
		var firmware, customer, owner sql.NullString
		if err := rows.Scan(&c.ID, &c.Vendor, &c.Model, &firmware, &customer, &c.SupportTier, &c.Status, &owner, &c.Dir, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.Firmware = firmware.String
		c.Customer = customer.String
		c.Owner = owner.String
		cases = append(cases, c)
	}
	return cases, rows.Err()
}

// DeleteCase removes an onboarding case and its directory.
func (s *Service) DeleteCase(id int64) error {
	c, err := s.GetCase(id)
	if err != nil {
		return err
	}
	// Remove directory
	os.RemoveAll(filepath.Join(s.baseDir, c.Dir))
	// Remove from DB
	_, err = s.db.Exec("DELETE FROM onboarding_cases WHERE id = ?", id)
	return err
}

func (s *Service) updateStatus(id int64, status CaseStatus) error {
	_, err := s.db.Exec(
		"UPDATE onboarding_cases SET status = ?, updated_at = ? WHERE id = ?",
		status, time.Now(), id,
	)
	return err
}

// SubmitFingerprint saves fingerprint data for a case.
func (s *Service) SubmitFingerprint(id int64, fp *FingerprintRequest) error {
	c, err := s.GetCase(id)
	if err != nil {
		return err
	}

	fpData, _ := yaml.Marshal(fp)
	fpPath := filepath.Join(s.baseDir, c.Dir, "fingerprint.yaml")
	if err := os.WriteFile(fpPath, fpData, 0644); err != nil {
		return err
	}

	return s.updateStatus(id, StatusEvidence)
}

// CollectAsync starts SNMP collection in a background goroutine.
// It calls the collectCallback with (taskID, result, error) when done.
func (s *Service) CollectAsync(id int64, taskID string) {
	go func() {
		result, err := s.Collect(id)
		if s.collectCallback != nil {
			s.collectCallback(taskID, result, err)
		}
	}()
}

// Collect performs SNMP walks against the device and saves them as evidence.
func (s *Service) Collect(id int64) (*CollectResult, error) {
	if s.snmp == nil {
		return nil, fmt.Errorf("SNMP client not configured")
	}

	c, err := s.GetCase(id)
	if err != nil {
		return nil, err
	}

	// Read fingerprint to get connection info
	fpPath := filepath.Join(s.baseDir, c.Dir, "fingerprint.yaml")
	fpData, err := os.ReadFile(fpPath)
	if err != nil {
		return nil, fmt.Errorf("fingerprint not found: submit fingerprint first")
	}
	var fp FingerprintRequest
	if err := yaml.Unmarshal(fpData, &fp); err != nil {
		return nil, fmt.Errorf("invalid fingerprint: %w", err)
	}
	if fp.IP == "" || fp.Community == "" {
		return nil, fmt.Errorf("fingerprint missing ip or community")
	}

	version := snmp.Version2c
	if fp.SNMPVersion == "1" {
		version = snmp.Version1
	}

	// Determine vendor enterprise OID from sysObjectID
	vendorOID := ""
	if strings.HasPrefix(fp.SysObjectID, ".1.3.6.1.4.1.") {
		parts := strings.Split(fp.SysObjectID, ".")
		if len(parts) >= 8 {
			vendorOID = strings.Join(parts[:8], ".")
		}
	}

	// Define walk targets
	type walkTarget struct {
		name    string
		oidRoot string
	}
	targets := []walkTarget{
		{name: "standard", oidRoot: ".1.3.6.1.2.1"},
		{name: "bridge", oidRoot: ".1.3.6.1.2.1.17"},
		{name: "poe", oidRoot: ".1.3.6.1.2.1.105"},
	}
	if vendorOID != "" {
		targets = append(targets, walkTarget{name: "vendor", oidRoot: vendorOID})
	}

	evidenceDir := filepath.Join(s.baseDir, c.Dir, "evidence")
	result := &CollectResult{}

	for _, t := range targets {
		results, err := s.snmp.BulkWalk(fp.IP, fp.Community, version, t.oidRoot)
		if err != nil || len(results) == 0 {
			continue
		}

		// Format as snmpwalk -On output
		var lines []string
		for _, r := range results {
			line := formatWalkLine(r)
			if line != "" {
				lines = append(lines, line)
			}
		}

		if len(lines) == 0 {
			continue
		}

		filename := fmt.Sprintf("%s_%s.walk", strings.ToLower(c.Vendor), t.name)
		walkPath := filepath.Join(evidenceDir, filename)
		os.WriteFile(walkPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)

		result.Walks = append(result.Walks, CollectWalk{
			Name:    t.name,
			OIDRoot: t.oidRoot,
			Entries: len(lines),
			File:    filename,
		})
		result.Total += len(lines)
	}

	if len(result.Walks) == 0 {
		return nil, fmt.Errorf("no SNMP data collected from %s", fp.IP)
	}

	return result, nil
}

// formatWalkLine converts an SNMP result to snmpwalk -On format.
func formatWalkLine(r snmp.Result) string {
	typeName, value := snmpResultToWalkFormat(r)
	if typeName == "" {
		return ""
	}
	return fmt.Sprintf("%s = %s: %s", r.OID, typeName, value)
}

func snmpResultToWalkFormat(r snmp.Result) (string, string) {
	switch r.Type {
	case 0x02: // Integer
		return "INTEGER", fmt.Sprintf("%v", r.Value)
	case 0x04: // OctetString
		switch v := r.Value.(type) {
		case []byte:
			if isPrintable(v) {
				return "STRING", fmt.Sprintf("\"%s\"", string(v))
			}
			return "Hex-STRING", formatHex(v)
		case string:
			return "STRING", fmt.Sprintf("\"%s\"", v)
		default:
			return "STRING", fmt.Sprintf("\"%v\"", v)
		}
	case 0x05: // Null
		return "NULL", ""
	case 0x06: // ObjectIdentifier
		return "OID", fmt.Sprintf("%v", r.Value)
	case 0x40: // IPAddress
		return "IpAddress", fmt.Sprintf("%v", r.Value)
	case 0x41: // Counter32
		return "Counter32", fmt.Sprintf("%v", r.Value)
	case 0x42: // Gauge32
		return "Gauge32", fmt.Sprintf("%v", r.Value)
	case 0x43: // TimeTicks
		return "Timeticks", fmt.Sprintf("(%v)", r.Value)
	case 0x46: // Counter64
		return "Counter64", fmt.Sprintf("%v", r.Value)
	default:
		return "STRING", fmt.Sprintf("\"%v\"", r.Value)
	}
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			if c != '\r' && c != '\n' && c != '\t' {
				return false
			}
		}
	}
	return true
}

func formatHex(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02X", c)
	}
	return strings.Join(parts, " ")
}

// ImportCollected imports a directory created by the offline collector.
// It reads fingerprint.yaml and intake.yaml, creates a case, and moves evidence files.
func (s *Service) ImportCollected(importDir string) (*Case, error) {
	// Read intake.yaml
	intakeData, err := os.ReadFile(filepath.Join(importDir, "intake.yaml"))
	if err != nil {
		return nil, fmt.Errorf("intake.yaml not found in %s: %w", importDir, err)
	}
	var intake map[string]string
	if err := yaml.Unmarshal(intakeData, &intake); err != nil {
		return nil, fmt.Errorf("invalid intake.yaml: %w", err)
	}

	vendor := intake["vendor"]
	model := intake["model"]
	if vendor == "" || model == "" {
		return nil, fmt.Errorf("intake.yaml missing vendor or model")
	}

	// Create the case via normal flow
	req := &IntakeRequest{
		Vendor:      vendor,
		Model:       model,
		Firmware:    intake["firmware"],
		SupportTier: intake["tier"],
		Owner:       "offline-collector",
	}
	c, err := s.CreateCase(req)
	if err != nil {
		return nil, err
	}

	caseDir := filepath.Join(s.baseDir, c.Dir)

	// Copy fingerprint.yaml
	copyIfExists(filepath.Join(importDir, "fingerprint.yaml"), filepath.Join(caseDir, "fingerprint.yaml"))

	// Copy all evidence files
	srcEvidence := filepath.Join(importDir, "evidence")
	dstEvidence := filepath.Join(caseDir, "evidence")
	if entries, err := os.ReadDir(srcEvidence); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			copyIfExists(filepath.Join(srcEvidence, e.Name()), filepath.Join(dstEvidence, e.Name()))
		}
	}

	// Copy report.txt if present
	copyIfExists(filepath.Join(importDir, "report.txt"), filepath.Join(caseDir, "report.txt"))

	// Update status to evidence (ready for analyze)
	s.updateStatus(c.ID, StatusEvidence)
	c.Status = StatusEvidence

	return c, nil
}

// UploadEvidence saves an evidence file (walk, CLI output, MIB).
func (s *Service) UploadEvidence(id int64, filename string, content io.Reader) error {
	c, err := s.GetCase(id)
	if err != nil {
		return err
	}

	evidenceDir := filepath.Join(s.baseDir, c.Dir, "evidence")

	// MIB files go to evidence/mibs/
	destDir := evidenceDir
	if strings.HasSuffix(filename, ".mib") || strings.HasSuffix(filename, ".my") {
		destDir = filepath.Join(evidenceDir, "mibs")
	}

	destPath := filepath.Join(destDir, filename)
	f, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, content)
	return err
}

// Analyze runs the walk analyzer on collected evidence.
func (s *Service) Analyze(id int64) (*AnalysisReport, error) {
	c, err := s.GetCase(id)
	if err != nil {
		return nil, err
	}

	s.updateStatus(id, StatusAnalyzing)

	evidenceDir := filepath.Join(s.baseDir, c.Dir, "evidence")
	draftsDir := filepath.Join(s.baseDir, c.Dir, "ai_drafts")

	// Find all .walk files
	walkFiles := make(map[string]string)
	entries, _ := os.ReadDir(evidenceDir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".walk") {
			walkFiles[e.Name()] = filepath.Join(evidenceDir, e.Name())
		}
	}

	if len(walkFiles) == 0 {
		return nil, fmt.Errorf("no .walk files found in evidence directory")
	}

	// Check for MIB files in evidence/mibs/
	mibDir := filepath.Join(evidenceDir, "mibs")
	var report *AnalysisReport

	if _, err := os.Stat(mibDir); err == nil {
		// MIB files available — use enhanced analysis
		parser := mibNewParser()
		parser.LoadDir(mibDir)
		// Also load subdirectories
		if subEntries, err := os.ReadDir(mibDir); err == nil {
			for _, e := range subEntries {
				if e.IsDir() {
					parser.LoadDir(filepath.Join(mibDir, e.Name()))
				}
			}
		}

		// Convert parser OIDs to analyzer format
		var mibOIDs []MIBOIDEntry
		for _, entry := range parser.GetAllOIDs() {
			mibOIDs = append(mibOIDs, MIBOIDEntry{
				Name:   entry.Name,
				OID:    entry.OID,
				Module: entry.Module,
				Type:   entry.Type,
				Access: entry.Access,
			})
		}

		report, err = AnalyzeWalksWithMIBs(walkFiles, parser, mibOIDs)
		if err != nil {
			return nil, err
		}
		report.MIBModules = parser.ListModules()
	} else {
		// No MIB files — standard analysis
		report, err = AnalyzeWalks(walkFiles)
		if err != nil {
			return nil, err
		}
	}

	// Save analysis report
	reportJSON, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile(filepath.Join(draftsDir, "analysis_report.json"), reportJSON, 0644)

	// Generate fingerprint draft from fingerprint.yaml
	fpDraft := generateFingerprintDraft(c, s.baseDir)
	fpDraftYAML, _ := yaml.Marshal(fpDraft)
	os.WriteFile(filepath.Join(draftsDir, "fingerprint.yaml"), fpDraftYAML, 0644)

	// Generate capability matrix draft
	capMatrix := generateCapabilityDraft(c, report)
	capYAML, _ := yaml.Marshal(capMatrix)
	os.WriteFile(filepath.Join(draftsDir, "capability_matrix.yaml"), capYAML, 0644)

	// Generate vendor profile draft
	vendorProfile := generateVendorProfileDraft(c, report)
	vpYAML, _ := yaml.Marshal(vendorProfile)
	os.WriteFile(filepath.Join(draftsDir, "vendor_profile.yaml"), vpYAML, 0644)

	// Convert walks to snmprec
	for name, path := range walkFiles {
		walkEntries, err := ParseWalkFile(path)
		if err != nil {
			continue
		}
		snmprecLines := WalkToSnmprec(walkEntries)
		snmprecName := strings.TrimSuffix(name, ".walk") + ".snmprec"
		snmprecPath := filepath.Join(draftsDir, snmprecName)
		os.WriteFile(snmprecPath, []byte(strings.Join(snmprecLines, "\n")+"\n"), 0644)
	}

	s.updateStatus(id, StatusDraft)
	return report, nil
}

// GetDrafts returns the AI-generated drafts for a case.
func (s *Service) GetDrafts(id int64) (map[string]interface{}, error) {
	c, err := s.GetCase(id)
	if err != nil {
		return nil, err
	}

	draftsDir := filepath.Join(s.baseDir, c.Dir, "ai_drafts")
	result := make(map[string]interface{})

	// Read each draft file
	files := []string{"analysis_report.json", "capability_matrix.yaml", "vendor_profile.yaml"}
	for _, fname := range files {
		data, err := os.ReadFile(filepath.Join(draftsDir, fname))
		if err != nil {
			continue
		}

		key := strings.TrimSuffix(fname, filepath.Ext(fname))
		if strings.HasSuffix(fname, ".json") {
			var v interface{}
			json.Unmarshal(data, &v)
			result[key] = v
		} else {
			result[key] = string(data)
		}
	}

	return result, nil
}

// Approve deploys the finalized profiles to production.
// If final/ is empty, auto-copies drafts from ai_drafts/ first.
func (s *Service) Approve(id int64) error {
	c, err := s.GetCase(id)
	if err != nil {
		return err
	}

	finalDir := filepath.Join(s.baseDir, c.Dir, "final")
	draftsDir := filepath.Join(s.baseDir, c.Dir, "ai_drafts")

	// Generate fingerprint draft if missing in ai_drafts/
	fpDraftPath := filepath.Join(draftsDir, "fingerprint.yaml")
	if _, err := os.Stat(fpDraftPath); os.IsNotExist(err) {
		fpDraft := generateFingerprintDraft(c, s.baseDir)
		if fpDraftYAML, err := yaml.Marshal(fpDraft); err == nil {
			os.MkdirAll(draftsDir, 0755)
			os.WriteFile(fpDraftPath, fpDraftYAML, 0644)
		}
	}

	// Auto-copy drafts to final/ if final/ has no profile files yet
	draftFiles := []string{"fingerprint.yaml", "capability_matrix.yaml", "vendor_profile.yaml"}
	hasFinal := false
	for _, f := range draftFiles {
		if _, err := os.Stat(filepath.Join(finalDir, f)); err == nil {
			hasFinal = true
			break
		}
	}
	if !hasFinal {
		os.MkdirAll(finalDir, 0755)
		for _, f := range draftFiles {
			copyIfExists(filepath.Join(draftsDir, f), filepath.Join(finalDir, f))
		}
		// Also copy snmprec files
		if entries, err := os.ReadDir(draftsDir); err == nil {
			snmprecDir := filepath.Join(finalDir, "snmprec")
			os.MkdirAll(snmprecDir, 0755)
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".snmprec") {
					copyIfExists(filepath.Join(draftsDir, e.Name()), filepath.Join(snmprecDir, e.Name()))
				}
			}
		}
	}

	// Copy fingerprint to profiles/fingerprints/
	copyIfExists(
		filepath.Join(finalDir, "fingerprint.yaml"),
		filepath.Join("profiles", "fingerprints", c.Dir+".yaml"),
	)

	// Copy capability matrix to profiles/capabilities/
	copyIfExists(
		filepath.Join(finalDir, "capability_matrix.yaml"),
		filepath.Join("profiles", "capabilities", c.Dir+".yaml"),
	)

	// Copy vendor profile to profiles/vendors/
	copyIfExists(
		filepath.Join(finalDir, "vendor_profile.yaml"),
		filepath.Join("profiles", "vendors", c.Dir+".yaml"),
	)

	// Copy override if exists
	copyIfExists(
		filepath.Join(finalDir, "override.yaml"),
		filepath.Join("profiles", "overrides", c.Dir+".yaml"),
	)

	// Copy snmprec files to tests/snmprec/{vendor}/
	snmprecDir := filepath.Join(finalDir, "snmprec")
	vendorTestDir := filepath.Join("tests", "snmprec", strings.ToLower(c.Vendor))
	os.MkdirAll(vendorTestDir, 0755)
	if entries, err := os.ReadDir(snmprecDir); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".snmprec") {
				copyIfExists(
					filepath.Join(snmprecDir, e.Name()),
					filepath.Join(vendorTestDir, e.Name()),
				)
			}
		}
	}

	return s.updateStatus(id, StatusApproved)
}

// VerifyResult holds the result of testing one capability against the real device.
type VerifyResult struct {
	Capability string `json:"capability"`
	Status     string `json:"status"` // ok, fail, skip
	Detail     string `json:"detail"`
	Count      int    `json:"count,omitempty"`
}

// Verify tests the deployed profile capabilities against the real device using SNMP.
func (s *Service) Verify(id int64) ([]VerifyResult, error) {
	if s.snmp == nil {
		return nil, fmt.Errorf("SNMP client not configured")
	}

	c, err := s.GetCase(id)
	if err != nil {
		return nil, err
	}

	// Read fingerprint for connection info
	fpPath := filepath.Join(s.baseDir, c.Dir, "fingerprint.yaml")
	fpData, err := os.ReadFile(fpPath)
	if err != nil {
		return nil, fmt.Errorf("fingerprint not found")
	}
	var fp FingerprintRequest
	if err := yaml.Unmarshal(fpData, &fp); err != nil {
		return nil, err
	}

	version := snmp.Version2c
	if fp.SNMPVersion == "1" {
		version = snmp.Version1
	}

	// Define verification tests: capability → OIDs to check
	tests := []struct {
		capability string
		oids       []string
		desc       string
	}{
		{"system.read", []string{".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.5.0"}, "sysDescr + sysName"},
		{"interfaces.read", []string{".1.3.6.1.2.1.2.2.1.1"}, "ifIndex table walk"},
		{"port.admin.read", []string{".1.3.6.1.2.1.2.2.1.7"}, "ifAdminStatus walk"},
		{"port.oper.read", []string{".1.3.6.1.2.1.2.2.1.8"}, "ifOperStatus walk"},
		{"port.traffic.read", []string{".1.3.6.1.2.1.2.2.1.10"}, "ifInOctets walk"},
		{"mac_table.read", []string{".1.3.6.1.2.1.17.4.3.1", ".1.3.6.1.2.1.17.7.1.2.2.1"}, "bridge/Q-BRIDGE FDB"},
		{"vlan.read", []string{".1.3.6.1.2.1.17.7.1.4.3.1"}, "dot1qVlanStatic"},
		{"poe.status.read", []string{".1.3.6.1.2.1.105.1.1.1"}, "pethPsePort"},
	}

	var results []VerifyResult

	for _, t := range tests {
		vr := VerifyResult{Capability: t.capability}

		// For scalar OIDs (system.read), use Get
		if t.capability == "system.read" {
			res, err := s.snmp.Get(fp.IP, fp.Community, version, t.oids)
			if err != nil {
				vr.Status = "fail"
				vr.Detail = err.Error()
			} else {
				vr.Status = "ok"
				vr.Count = len(res)
				vals := []string{}
				for _, r := range res {
					vals = append(vals, r.AsString())
				}
				vr.Detail = strings.Join(vals, " | ")
			}
		} else {
			// For table OIDs, try walk on each OID until one works
			found := false
			for _, oid := range t.oids {
				res, err := s.snmp.BulkWalk(fp.IP, fp.Community, version, oid)
				if err == nil && len(res) > 0 {
					vr.Status = "ok"
					vr.Count = len(res)
					vr.Detail = fmt.Sprintf("%s: %d entries", t.desc, len(res))
					found = true
					break
				}
			}
			if !found {
				vr.Status = "fail"
				vr.Detail = t.desc + ": no data returned"
			}
		}

		results = append(results, vr)
	}

	return results, nil
}

func copyIfExists(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(dst), 0755)
	return os.WriteFile(dst, data, 0644)
}

// --- Draft generators ---

func generateFingerprintDraft(c *Case, baseDir string) map[string]interface{} {
	profileID := fmt.Sprintf("%s_%s", strings.ToLower(c.Vendor), strings.ToLower(strings.ReplaceAll(c.Model, " ", "_")))

	// Read fingerprint.yaml for sysObjectID and sysDescr
	fpPath := filepath.Join(baseDir, c.Dir, "fingerprint.yaml")
	var fp FingerprintRequest
	if data, err := os.ReadFile(fpPath); err == nil {
		yaml.Unmarshal(data, &fp)
	}

	// Extract enterprise OID prefix from sysObjectID (e.g. ".1.3.6.1.4.1.12356." from ".1.3.6.1.4.1.12356.101.1.80001")
	oidPrefixes := []string{}
	sysOID := strings.TrimPrefix(fp.SysObjectID, ".")
	if strings.HasPrefix(sysOID, "1.3.6.1.4.1.") {
		parts := strings.Split(sysOID, ".")
		if len(parts) >= 7 {
			oidPrefixes = append(oidPrefixes, strings.Join(parts[:7], ".")+".")
		}
	}

	// sysDescr hints — use sysDescr if non-empty, otherwise use vendor name
	descrContains := []string{}
	if fp.SysDescr != "" {
		descrContains = append(descrContains, fp.SysDescr)
	}
	descrContains = append(descrContains, c.Vendor)

	return map[string]interface{}{
		"id":     profileID,
		"vendor": strings.ToLower(c.Vendor),
		"os":     strings.ToLower(c.Vendor),
		"match": map[string]interface{}{
			"sysobjectid_prefix": oidPrefixes,
			"sysdescr_contains":  descrContains,
		},
		"priority": 50,
	}
}

func generateCapabilityDraft(c *Case, report *AnalysisReport) map[string]interface{} {
	caps := make(map[string]interface{})
	for _, cr := range report.Capabilities {
		caps[cr.Capability] = map[string]interface{}{
			"supported":  cr.Supported,
			"confidence": cr.Confidence,
			"evidence":   cr.Evidence,
		}
	}
	return map[string]interface{}{
		"id":           fmt.Sprintf("%s_%s", strings.ToLower(c.Vendor), strings.ToLower(strings.ReplaceAll(c.Model, " ", "_"))),
		"capabilities": caps,
	}
}

func generateVendorProfileDraft(c *Case, report *AnalysisReport) map[string]interface{} {
	mappings := make(map[string]interface{})

	for _, cr := range report.Capabilities {
		if !cr.Supported || len(cr.OIDsFound) == 0 {
			continue
		}

		mapping := map[string]interface{}{
			"primary": map[string]interface{}{
				"method": "snmp",
			},
			"_confidence": cr.Confidence,
			"_evidence":   cr.Evidence,
		}

		// Add OID info
		if len(cr.OIDsFound) == 1 {
			mapping["primary"].(map[string]interface{})["oid_template"] = cr.OIDsFound[0] + ".{ifIndex}"
		} else {
			mapping["primary"].(map[string]interface{})["table"] = cr.OIDsFound[0]
		}

		mappings[cr.Capability] = mapping
	}

	return map[string]interface{}{
		"id": fmt.Sprintf("%s_%s", strings.ToLower(c.Vendor), strings.ToLower(strings.ReplaceAll(c.Model, " ", "_"))),
		"protocols": map[string]interface{}{
			"snmp": map[string]string{"version": "v2c"},
			"ssh":  map[string]interface{}{"enabled": true},
		},
		"mappings": mappings,
	}
}
