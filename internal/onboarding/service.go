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

	"gopkg.in/yaml.v3"
)

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

// Service handles onboarding operations.
type Service struct {
	db      *sql.DB
	baseDir string // root onboarding directory
}

func NewService(db *sql.DB, baseDir string) (*Service, error) {
	s := &Service{db: db, baseDir: baseDir}
	if err := s.createTable(); err != nil {
		return nil, err
	}
	return s, nil
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

// CreateCase creates a new onboarding case.
func (s *Service) CreateCase(req *IntakeRequest) (*Case, error) {
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

	// Run analysis
	report, err := AnalyzeWalks(walkFiles)
	if err != nil {
		return nil, err
	}

	// Save analysis report
	reportJSON, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile(filepath.Join(draftsDir, "analysis_report.json"), reportJSON, 0644)

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
func (s *Service) Approve(id int64) error {
	c, err := s.GetCase(id)
	if err != nil {
		return err
	}

	finalDir := filepath.Join(s.baseDir, c.Dir, "final")

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

func copyIfExists(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(dst), 0755)
	return os.WriteFile(dst, data, 0644)
}

// --- Draft generators ---

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
