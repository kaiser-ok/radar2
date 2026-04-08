package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// --- Layer 1: Device Fingerprint ---

type Fingerprint struct {
	ID       string           `yaml:"id"`
	Vendor   string           `yaml:"vendor"`
	OS       string           `yaml:"os"`
	Match    FingerprintMatch `yaml:"match"`
	Priority int              `yaml:"priority"`

	// compiled (not serialized)
	sysOIDMatchers   []string
	sysDescrMatchers []*regexp.Regexp
}

type FingerprintMatch struct {
	SysObjectIDPrefix []string `yaml:"sysobjectid_prefix"`
	SysDescrContains  []string `yaml:"sysdescr_contains"`
}

// --- Layer 2: Capability Matrix ---

type CapabilityMatrix struct {
	ID           string          `yaml:"id"`
	Capabilities map[string]bool `yaml:"capabilities"`
}

// --- Layer 3: Vendor Profile (mappings) ---

type VendorProfile struct {
	ID        string                       `yaml:"id"`
	Protocols ProfileProtocols             `yaml:"protocols"`
	Mappings  map[string]CapabilityMapping `yaml:"mappings"`
}

type ProfileProtocols struct {
	SNMP ProfileSNMP `yaml:"snmp"`
	SSH  ProfileSSH  `yaml:"ssh"`
}

type ProfileSNMP struct {
	Version string `yaml:"version"`
}

type ProfileSSH struct {
	Enabled      bool   `yaml:"enabled"`
	PromptRegex  string `yaml:"prompt_regex"`
	PagerDisable string `yaml:"pager_disable"`
	Note         string `yaml:"note,omitempty"`
}

type CapabilityMapping struct {
	// Simple (no fallback)
	Method      string            `yaml:"method,omitempty"`
	OIDTemplate string            `yaml:"oid_template,omitempty"`
	OIDs        map[string]string `yaml:"oids,omitempty"`
	Table       string            `yaml:"table,omitempty"`
	Fields      map[string]string `yaml:"fields,omitempty"`
	ValueMap    map[string]int    `yaml:"value_map,omitempty"`
	Commands    interface{}       `yaml:"commands,omitempty"` // string or map or list

	// With fallback
	Primary  *MethodConfig `yaml:"primary,omitempty"`
	Fallback *MethodConfig `yaml:"fallback,omitempty"`
	Verify   *MethodConfig `yaml:"verify,omitempty"`
}

type MethodConfig struct {
	Method      string            `yaml:"method"`
	OIDTemplate string            `yaml:"oid_template,omitempty"`
	OIDs        map[string]string `yaml:"oids,omitempty"`
	Table       string            `yaml:"table,omitempty"`
	Fields      map[string]string `yaml:"fields,omitempty"`
	ValueMap    map[string]int    `yaml:"value_map,omitempty"`
	Commands    interface{}       `yaml:"commands,omitempty"`
}

// --- Layer 4: Override ---

type Override struct {
	ID       string           `yaml:"id"`
	Extends  string           `yaml:"extends"`
	Match    FingerprintMatch `yaml:"match"`
	Overrides struct {
		Capabilities map[string]bool                `yaml:"capabilities,omitempty"`
		Mappings     map[string]CapabilityMapping   `yaml:"mappings,omitempty"`
	} `yaml:"overrides"`
}

// --- Resolved Device Profile (all layers merged) ---

type DeviceProfile struct {
	ID           string
	Vendor       string
	OS           string
	Capabilities map[string]bool
	Mappings     map[string]CapabilityMapping
	Protocols    ProfileProtocols
}

func (dp *DeviceProfile) HasCapability(name string) bool {
	if dp == nil || dp.Capabilities == nil {
		return false
	}
	return dp.Capabilities[name]
}

func (dp *DeviceProfile) GetMapping(capability string) *CapabilityMapping {
	if dp == nil || dp.Mappings == nil {
		return nil
	}
	m, ok := dp.Mappings[capability]
	if !ok {
		return nil
	}
	return &m
}

// --- Profile Registry ---

type ProfileRegistry struct {
	fingerprints []*Fingerprint
	capabilities map[string]*CapabilityMatrix
	vendors      map[string]*VendorProfile
	overrides    []*Override
}

func LoadProfiles(profileDir string) (*ProfileRegistry, error) {
	reg := &ProfileRegistry{
		capabilities: make(map[string]*CapabilityMatrix),
		vendors:      make(map[string]*VendorProfile),
	}

	// Load fingerprints
	fps, err := loadYAMLDir[Fingerprint](filepath.Join(profileDir, "fingerprints"))
	if err != nil {
		return nil, fmt.Errorf("load fingerprints: %w", err)
	}
	for _, fp := range fps {
		fp.sysOIDMatchers = fp.Match.SysObjectIDPrefix
		for _, pat := range fp.Match.SysDescrContains {
			re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(pat))
			if err == nil {
				fp.sysDescrMatchers = append(fp.sysDescrMatchers, re)
			}
		}
		reg.fingerprints = append(reg.fingerprints, fp)
	}
	// Sort by priority descending
	sort.Slice(reg.fingerprints, func(i, j int) bool {
		return reg.fingerprints[i].Priority > reg.fingerprints[j].Priority
	})

	// Load capabilities
	caps, err := loadYAMLDir[CapabilityMatrix](filepath.Join(profileDir, "capabilities"))
	if err != nil {
		return nil, fmt.Errorf("load capabilities: %w", err)
	}
	for _, c := range caps {
		reg.capabilities[c.ID] = c
	}

	// Load vendor profiles
	vps, err := loadYAMLDir[VendorProfile](filepath.Join(profileDir, "vendors"))
	if err != nil {
		return nil, fmt.Errorf("load vendors: %w", err)
	}
	for _, vp := range vps {
		reg.vendors[vp.ID] = vp
	}

	// Load overrides
	ovs, err := loadYAMLDir[Override](filepath.Join(profileDir, "overrides"))
	if err != nil {
		// Overrides are optional
		ovs = nil
	}
	for _, ov := range ovs {
		reg.overrides = append(reg.overrides, ov)
	}

	return reg, nil
}

// DetectDevice matches sysObjectID and sysDescr to find the best device profile.
func (r *ProfileRegistry) DetectDevice(sysObjectID, sysDescr string) *DeviceProfile {
	// Step 1: Find matching fingerprint
	var matched *Fingerprint
	for _, fp := range r.fingerprints {
		if matchFingerprint(fp, sysObjectID, sysDescr) {
			matched = fp
			break // already sorted by priority
		}
	}
	if matched == nil {
		return nil
	}

	// Step 2: Load base capability + vendor profile
	profile := &DeviceProfile{
		ID:     matched.ID,
		Vendor: matched.Vendor,
		OS:     matched.OS,
	}

	if cap, ok := r.capabilities[matched.ID]; ok {
		profile.Capabilities = copyMap(cap.Capabilities)
	}

	if vp, ok := r.vendors[matched.ID]; ok {
		profile.Protocols = vp.Protocols
		profile.Mappings = copyMappings(vp.Mappings)
	}

	// Step 3: Apply overrides
	for _, ov := range r.overrides {
		if ov.Extends != matched.ID {
			continue
		}
		if !matchOverride(ov, sysObjectID, sysDescr) {
			continue
		}
		// Merge override capabilities
		for k, v := range ov.Overrides.Capabilities {
			if profile.Capabilities == nil {
				profile.Capabilities = make(map[string]bool)
			}
			profile.Capabilities[k] = v
		}
		// Merge override mappings
		for k, v := range ov.Overrides.Mappings {
			if profile.Mappings == nil {
				profile.Mappings = make(map[string]CapabilityMapping)
			}
			profile.Mappings[k] = v
		}
		profile.ID = ov.ID
	}

	return profile
}

// GetProfileByID returns a profile by fingerprint ID directly (for manually assigned devices).
func (r *ProfileRegistry) GetProfileByID(id string) *DeviceProfile {
	profile := &DeviceProfile{ID: id}

	if cap, ok := r.capabilities[id]; ok {
		profile.Capabilities = copyMap(cap.Capabilities)
	}
	if vp, ok := r.vendors[id]; ok {
		profile.Vendor = id
		profile.Protocols = vp.Protocols
		profile.Mappings = copyMappings(vp.Mappings)
	}

	return profile
}

func matchFingerprint(fp *Fingerprint, sysObjectID, sysDescr string) bool {
	// Normalize: strip leading dot from sysObjectID
	normalizedOID := strings.TrimPrefix(sysObjectID, ".")

	// Check sysObjectID prefix
	oidMatch := len(fp.sysOIDMatchers) == 0 // if no matchers, pass
	for _, prefix := range fp.sysOIDMatchers {
		if strings.HasPrefix(normalizedOID, prefix) || strings.HasPrefix(sysObjectID, prefix) {
			oidMatch = true
			break
		}
	}

	// Check sysDescr
	descrMatch := len(fp.sysDescrMatchers) == 0
	for _, re := range fp.sysDescrMatchers {
		if re.MatchString(sysDescr) {
			descrMatch = true
			break
		}
	}

	return oidMatch && descrMatch
}

func matchOverride(ov *Override, sysObjectID, sysDescr string) bool {
	for _, pat := range ov.Match.SysDescrContains {
		if strings.Contains(strings.ToLower(sysDescr), strings.ToLower(pat)) {
			return true
		}
	}
	for _, prefix := range ov.Match.SysObjectIDPrefix {
		if strings.HasPrefix(sysObjectID, prefix) {
			return true
		}
	}
	return false
}

func copyMap(src map[string]bool) map[string]bool {
	if src == nil {
		return nil
	}
	dst := make(map[string]bool, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func copyMappings(src map[string]CapabilityMapping) map[string]CapabilityMapping {
	if src == nil {
		return nil
	}
	dst := make(map[string]CapabilityMapping, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// loadYAMLDir loads all YAML files from a directory into a slice of T.
func loadYAMLDir[T any](dir string) ([]*T, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}

	var items []*T
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		var item T
		if err := yaml.Unmarshal(data, &item); err != nil {
			return nil, fmt.Errorf("parse %s: %w", f, err)
		}
		items = append(items, &item)
	}
	return items, nil
}
