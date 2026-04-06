package service

import (
	"fmt"

	"new_radar/internal/config"
	"new_radar/internal/model"
	"new_radar/internal/snmp"
)

type SwitchInfoService struct {
	snmpClient *snmp.Client
	oids       *snmp.OIDRegistry
	profiles   *config.ProfileRegistry
}

func NewSwitchInfoService(sc *snmp.Client, oids *snmp.OIDRegistry, profiles *config.ProfileRegistry) *SwitchInfoService {
	return &SwitchInfoService{snmpClient: sc, oids: oids, profiles: profiles}
}

// CPUResult holds CPU utilization data.
type CPUResult struct {
	Utilization int    `json:"utilization"` // percentage
	Source      string `json:"source"`      // which OID was used
}

// GetCPU returns CPU utilization for a switch.
func (s *SwitchInfoService) GetCPU(sw *model.Switch) (*CPUResult, error) {
	ver := snmp.ParseVersion(sw.SNMPVer)

	// Try vendor-specific CPU OID first
	vendorOID := s.getVendorOID(sw, "cpu")
	if vendorOID != "" {
		results, err := s.snmpClient.Get(sw.IP, sw.Community, ver, []string{vendorOID})
		if err == nil && len(results) > 0 {
			if v, ok := results[0].AsInt(); ok && v >= 0 {
				return &CPUResult{Utilization: v, Source: "vendor"}, nil
			}
		}
	}

	// Try standard HOST-RESOURCES-MIB hrProcessorLoad
	hrProcessorLoad := "1.3.6.1.2.1.25.3.3.1.2.1"
	results, err := s.snmpClient.Get(sw.IP, sw.Community, ver, []string{hrProcessorLoad})
	if err == nil && len(results) > 0 {
		if v, ok := results[0].AsInt(); ok && v >= 0 {
			return &CPUResult{Utilization: v, Source: "hrProcessorLoad"}, nil
		}
	}

	// Try common vendor OIDs as fallback
	fallbackOIDs := []struct {
		oid  string
		name string
	}{
		{"1.3.6.1.4.1.9.9.109.1.1.1.1.8.1", "cisco_cpmCPUTotal5minRev"},
		{"1.3.6.1.4.1.9.2.1.58.0", "cisco_avgBusy5"},
		{"1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0", "hp_switchCpuStat"},
		{"1.3.6.1.4.1.171.12.1.1.6.2.0", "dlink_cpuUtil5min"},
		{"1.3.6.1.4.1.890.1.15.3.2.6.1.13", "zyxel_cpuUtil"},
	}

	for _, fb := range fallbackOIDs {
		results, err := s.snmpClient.Get(sw.IP, sw.Community, ver, []string{fb.oid})
		if err == nil && len(results) > 0 {
			if v, ok := results[0].AsInt(); ok && v >= 0 {
				return &CPUResult{Utilization: v, Source: fb.name}, nil
			}
		}
	}

	return nil, fmt.Errorf("cpu utilization not available")
}

// PortStats holds per-port traffic statistics.
type PortStats struct {
	Index     int    `json:"index"`
	Name      string `json:"name,omitempty"`
	InOctets  uint64 `json:"in_octets"`
	OutOctets uint64 `json:"out_octets"`
	InErrors  int    `json:"in_errors"`
	OutErrors int    `json:"out_errors"`
	Speed     int    `json:"speed,omitempty"`
}

// GetStats returns per-port traffic statistics.
func (s *SwitchInfoService) GetStats(sw *model.Switch) ([]PortStats, error) {
	ver := snmp.ParseVersion(sw.SNMPVer)

	inOctets, err := s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, s.oids.IfInOctets())
	if err != nil {
		return nil, fmt.Errorf("walk ifInOctets: %w", err)
	}

	outOctets, _ := s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, s.oids.IfOutOctets())
	inErrorsOID := s.oids.Get("mib2", "ifInErrors")
	outErrorsOID := s.oids.Get("mib2", "ifOutErrors")
	var inErrors, outErrors []snmp.Result
	if inErrorsOID != "" {
		inErrors, _ = s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, inErrorsOID)
	}
	if outErrorsOID != "" {
		outErrors, _ = s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, outErrorsOID)
	}
	descrs, _ := s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, s.oids.IfDescr())

	outMap := buildUint64Map(outOctets)
	inErrMap := buildIntMap(inErrors)
	outErrMap := buildIntMap(outErrors)
	descrMap := buildStringMap(descrs)

	var stats []PortStats
	for _, r := range inOctets {
		idx := extractIndex(r.OID)
		if idx <= 0 {
			continue
		}
		st := PortStats{
			Index:     idx,
			Name:      descrMap[idx],
			InOctets:  toUint64(r.Value),
			OutOctets: outMap[idx],
			InErrors:  inErrMap[idx],
			OutErrors: outErrMap[idx],
		}
		stats = append(stats, st)
	}
	return stats, nil
}

// VLANEntry holds VLAN information.
type VLANEntry struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	EgressPorts string `json:"egress_ports,omitempty"`
}

// GetVLANs returns VLAN configuration.
func (s *SwitchInfoService) GetVLANs(sw *model.Switch) ([]VLANEntry, error) {
	ver := snmp.ParseVersion(sw.SNMPVer)

	// Q-BRIDGE dot1qVlanStaticName
	vlanNameOID := s.oids.Get("vlan", "dot1qVlanStaticName")
	if vlanNameOID == "" {
		vlanNameOID = "1.3.6.1.2.1.17.7.1.4.3.1.1"
	}

	nameResults, err := s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, vlanNameOID)
	if err != nil {
		return nil, fmt.Errorf("walk vlan names: %w", err)
	}

	var vlans []VLANEntry
	for _, r := range nameResults {
		idx := extractIndex(r.OID)
		if idx <= 0 {
			continue
		}
		vlans = append(vlans, VLANEntry{
			ID:   idx,
			Name: r.AsString(),
		})
	}
	return vlans, nil
}

func (s *SwitchInfoService) getVendorOID(sw *model.Switch, key string) string {
	if s.profiles == nil || sw.Vendor == "" {
		return ""
	}
	profile := s.profiles.GetProfileByID(sw.Vendor)
	if profile == nil {
		return ""
	}
	// Check system.read mappings for vendor-specific OIDs
	mapping := profile.GetMapping("system.read")
	if mapping != nil && mapping.OIDs != nil {
		if oid, ok := mapping.OIDs[key]; ok {
			return oid
		}
	}
	return ""
}

// helpers

func buildUint64Map(results []snmp.Result) map[int]uint64 {
	m := make(map[int]uint64)
	for _, r := range results {
		idx := extractIndex(r.OID)
		if idx > 0 {
			m[idx] = toUint64(r.Value)
		}
	}
	return m
}

func toUint64(v interface{}) uint64 {
	switch val := v.(type) {
	case uint64:
		return val
	case uint:
		return uint64(val)
	case int:
		return uint64(val)
	case int64:
		return uint64(val)
	default:
		return 0
	}
}

