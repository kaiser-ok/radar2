package service

import (
	"fmt"

	"new_radar/internal/config"
	"new_radar/internal/model"
	"new_radar/internal/snmp"

	"github.com/gosnmp/gosnmp"
)

// Standard PoE OIDs (RFC 3621 POWER-ETHERNET-MIB)
const (
	pethPsePortAdminEnable    = "1.3.6.1.2.1.105.1.1.1.3"
	pethPsePortDetectStatus   = "1.3.6.1.2.1.105.1.1.1.6"
	pethPsePortPowerClass     = "1.3.6.1.2.1.105.1.1.1.10"
	pethMainPseOperStatus     = "1.3.6.1.2.1.105.1.3.1.1.3"
	pethMainPsePower          = "1.3.6.1.2.1.105.1.3.1.1.2"
	pethMainPseConsumption    = "1.3.6.1.2.1.105.1.3.1.1.4"
)

type PoEService struct {
	snmpClient *snmp.Client
	oids       *snmp.OIDRegistry
	profiles   *config.ProfileRegistry
}

func NewPoEService(sc *snmp.Client, oids *snmp.OIDRegistry, profiles *config.ProfileRegistry) *PoEService {
	return &PoEService{snmpClient: sc, oids: oids, profiles: profiles}
}

// CheckSupport checks if a switch supports PoE.
func (s *PoEService) CheckSupport(sw *model.Switch) (bool, error) {
	ver := snmp.ParseVersion(sw.SNMPVer)

	// Try standard PoE MIB
	results, err := s.snmpClient.Get(sw.IP, sw.Community, ver, []string{pethMainPseOperStatus + ".1"})
	if err != nil {
		return false, nil // no PoE support
	}

	for _, r := range results {
		if r.Type != gosnmp.NoSuchObject && r.Type != gosnmp.NoSuchInstance {
			return true, nil
		}
	}

	return false, nil
}

// GetReport returns per-port PoE power consumption.
func (s *PoEService) GetReport(sw *model.Switch) (*PoEReport, error) {
	ver := snmp.ParseVersion(sw.SNMPVer)

	// Walk admin enable status
	adminResults, err := s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, pethPsePortAdminEnable)
	if err != nil {
		return nil, fmt.Errorf("walk poe admin: %w", err)
	}

	// Walk detection status
	detectResults, err := s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, pethPsePortDetectStatus)
	if err != nil {
		detectResults = nil
	}

	// Try vendor-specific power consumption OID
	var powerResults []snmp.Result
	vendorPowerOID := s.getVendorPoEOID(sw, "poe_port_power")
	if vendorPowerOID != "" {
		powerResults, _ = s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, vendorPowerOID)
	}

	// Get main PSE info
	mainPower, mainConsumption := s.getMainPSE(sw)

	detectMap := buildIntMap(detectResults)
	powerMap := buildIntMap(powerResults)

	var ports []PoEPortDetail
	for _, r := range adminResults {
		idx := extractIndex(r.OID)
		if idx <= 0 {
			continue
		}
		adminVal, _ := r.AsInt()
		port := PoEPortDetail{
			Port:    idx,
			Enabled: adminVal == 1,
			Status:  poeDetectStatusStr(detectMap[idx]),
		}
		if w, ok := powerMap[idx]; ok {
			port.PowerMW = float64(w)
			port.PowerW = float64(w) / 1000.0
		}
		ports = append(ports, port)
	}

	return &PoEReport{
		Supported:       true,
		TotalPowerW:     float64(mainPower) / 1000.0,
		ConsumptionW:    float64(mainConsumption) / 1000.0,
		Ports:           ports,
	}, nil
}

// SetPoE enables or disables PoE on a port.
func (s *PoEService) SetPoE(sw *model.Switch, port int, enabled bool) error {
	ver := snmp.ParseVersion(sw.SNMPVer)

	// pethPsePortAdminEnable: 1=true (enabled), 2=false (disabled)
	val := 2
	if enabled {
		val = 1
	}

	// OID format: pethPsePortAdminEnable.pseGroupIndex.portIndex
	// Most switches use group 1
	oid := fmt.Sprintf("%s.1.%d", pethPsePortAdminEnable, port)

	return s.snmpClient.Set(sw.IP, sw.Community, ver, oid, gosnmp.Integer, val)
}

func (s *PoEService) getMainPSE(sw *model.Switch) (totalPower, consumption int) {
	ver := snmp.ParseVersion(sw.SNMPVer)
	results, err := s.snmpClient.Get(sw.IP, sw.Community, ver, []string{
		pethMainPsePower + ".1",
		pethMainPseConsumption + ".1",
	})
	if err != nil {
		return 0, 0
	}
	for _, r := range results {
		if containsOID(r.OID, pethMainPsePower) {
			totalPower, _ = r.AsInt()
		}
		if containsOID(r.OID, pethMainPseConsumption) {
			consumption, _ = r.AsInt()
		}
	}
	return
}

func (s *PoEService) getVendorPoEOID(sw *model.Switch, key string) string {
	if s.profiles == nil || sw.Vendor == "" {
		return ""
	}
	profile := s.profiles.GetProfileByID(sw.Vendor)
	if profile == nil {
		return ""
	}
	mapping := profile.GetMapping("poe.status.read")
	if mapping == nil || mapping.OIDs == nil {
		return ""
	}
	if oid, ok := mapping.OIDs["power_consumption"]; ok {
		return oid
	}
	return ""
}

func containsOID(full, prefix string) bool {
	return len(full) >= len(prefix) && full[:len(prefix)] == prefix ||
		len(full) > len(prefix) && full[len(full)-len(prefix):] == prefix
}

func poeDetectStatusStr(v int) string {
	switch v {
	case 1:
		return "disabled"
	case 2:
		return "searching"
	case 3:
		return "deliveringPower"
	case 4:
		return "fault"
	case 5:
		return "test"
	case 6:
		return "otherFault"
	default:
		return "unknown"
	}
}

// PoEReport is the full PoE status for a switch.
type PoEReport struct {
	Supported    bool            `json:"supported"`
	TotalPowerW  float64         `json:"total_power_w"`
	ConsumptionW float64         `json:"consumption_w"`
	Ports        []PoEPortDetail `json:"ports"`
}

type PoEPortDetail struct {
	Port    int     `json:"port"`
	Enabled bool    `json:"enabled"`
	Status  string  `json:"status"`
	PowerMW float64 `json:"power_mw,omitempty"`
	PowerW  float64 `json:"power_w,omitempty"`
}
