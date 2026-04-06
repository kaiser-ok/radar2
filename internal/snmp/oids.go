package snmp

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// OIDRegistry holds the OID map loaded from oids.yaml.
type OIDRegistry struct {
	categories map[string]map[string]string
}

func LoadOIDs(path string) (*OIDRegistry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read OID file %s: %w", path, err)
	}

	var raw map[string]map[string]string
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse OID file %s: %w", path, err)
	}

	return &OIDRegistry{categories: raw}, nil
}

// Get returns an OID by category and key, e.g. Get("mib2", "ifAdminStatus").
func (r *OIDRegistry) Get(category, key string) string {
	if cat, ok := r.categories[category]; ok {
		return cat[key]
	}
	return ""
}

// MustGet returns an OID or panics if not found.
func (r *OIDRegistry) MustGet(category, key string) string {
	oid := r.Get(category, key)
	if oid == "" {
		panic(fmt.Sprintf("OID not found: %s.%s", category, key))
	}
	return oid
}

// Standard MIB-2 OID accessors for common use.

func (r *OIDRegistry) IfAdminStatus() string { return r.Get("mib2", "ifAdminStatus") }
func (r *OIDRegistry) IfOperStatus() string  { return r.Get("mib2", "ifOperStatus") }
func (r *OIDRegistry) IfDescr() string       { return r.Get("mib2", "ifDescr") }
func (r *OIDRegistry) IfAlias() string        { return r.Get("mib2", "ifAlias") }
func (r *OIDRegistry) IfSpeed() string        { return r.Get("mib2", "ifSpeed") }
func (r *OIDRegistry) IfInOctets() string     { return r.Get("mib2", "ifInOctets") }
func (r *OIDRegistry) IfOutOctets() string    { return r.Get("mib2", "ifOutOctets") }
func (r *OIDRegistry) SysDescr() string       { return r.Get("mib2", "sysDescr") }
func (r *OIDRegistry) SysName() string        { return r.Get("mib2", "sysName") }
