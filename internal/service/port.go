package service

import (
	"fmt"
	"strings"

	"new_radar/internal/config"
	"new_radar/internal/model"
	"new_radar/internal/snmp"

	"github.com/gosnmp/gosnmp"
)

type PortService struct {
	snmpClient *snmp.Client
	oids       *snmp.OIDRegistry
	profiles   *config.ProfileRegistry
}

func NewPortService(sc *snmp.Client, oids *snmp.OIDRegistry, profiles *config.ProfileRegistry) *PortService {
	return &PortService{snmpClient: sc, oids: oids, profiles: profiles}
}

// GetAllPorts returns link and admin status for all ports on a switch.
func (s *PortService) GetAllPorts(sw *model.Switch) ([]model.PortInfo, error) {
	ver := snmp.ParseVersion(sw.SNMPVer)

	// Walk ifOperStatus (link status)
	operResults, err := s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, s.oids.IfOperStatus())
	if err != nil {
		return nil, fmt.Errorf("walk ifOperStatus: %w", err)
	}

	// Walk ifAdminStatus
	adminResults, err := s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, s.oids.IfAdminStatus())
	if err != nil {
		return nil, fmt.Errorf("walk ifAdminStatus: %w", err)
	}

	// Walk ifDescr for port names
	descrResults, err := s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, s.oids.IfDescr())
	if err != nil {
		// Non-fatal, descriptions are optional
		descrResults = nil
	}

	// Walk ifSpeed
	speedResults, err := s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, s.oids.IfSpeed())
	if err != nil {
		speedResults = nil
	}

	// Build index maps
	adminMap := buildIntMap(adminResults)
	descrMap := buildStringMap(descrResults)
	speedMap := buildIntMap(speedResults)

	var ports []model.PortInfo
	for _, r := range operResults {
		idx := extractIndex(r.OID)
		if idx <= 0 {
			continue
		}

		operVal, _ := r.AsInt()
		adminVal := adminMap[idx]
		speed := speedMap[idx]

		port := model.PortInfo{
			Index:       idx,
			Name:        descrMap[idx],
			AdminStatus: adminStatusStr(adminVal),
			LinkStatus:  operStatusStr(operVal),
		}
		if speed > 0 {
			port.Speed = formatSpeed(speed)
		}
		ports = append(ports, port)
	}

	return ports, nil
}

// GetPort returns status for a single port.
func (s *PortService) GetPort(sw *model.Switch, portIndex int) (*model.PortInfo, error) {
	ver := snmp.ParseVersion(sw.SNMPVer)
	suffix := fmt.Sprintf(".%d", portIndex)

	oids := []string{
		s.oids.IfOperStatus() + suffix,
		s.oids.IfAdminStatus() + suffix,
		s.oids.IfDescr() + suffix,
		s.oids.IfSpeed() + suffix,
	}

	results, err := s.snmpClient.Get(sw.IP, sw.Community, ver, oids)
	if err != nil {
		return nil, fmt.Errorf("get port %d: %w", portIndex, err)
	}

	port := &model.PortInfo{Index: portIndex}
	for _, r := range results {
		switch {
		case strings.HasPrefix(r.OID, s.oids.IfOperStatus()):
			v, _ := r.AsInt()
			port.LinkStatus = operStatusStr(v)
		case strings.HasPrefix(r.OID, s.oids.IfAdminStatus()):
			v, _ := r.AsInt()
			port.AdminStatus = adminStatusStr(v)
		case strings.HasPrefix(r.OID, s.oids.IfDescr()):
			port.Name = r.AsString()
		case strings.HasPrefix(r.OID, s.oids.IfSpeed()):
			v, _ := r.AsInt()
			if v > 0 {
				port.Speed = formatSpeed(v)
			}
		}
	}

	return port, nil
}

// SetPortAdmin enables or disables a port (ifAdminStatus SET).
func (s *PortService) SetPortAdmin(sw *model.Switch, portIndex int, enabled bool) error {
	ver := snmp.ParseVersion(sw.SNMPVer)
	oid := fmt.Sprintf("%s.%d", s.oids.IfAdminStatus(), portIndex)

	// ifAdminStatus: 1=up, 2=down
	val := 2
	if enabled {
		val = 1
	}

	return s.snmpClient.Set(sw.IP, sw.Community, ver, oid, gosnmp.Integer, val)
}

// GetDescriptions returns port descriptions/aliases for all ports.
func (s *PortService) GetDescriptions(sw *model.Switch) (map[int]string, error) {
	ver := snmp.ParseVersion(sw.SNMPVer)

	// Try ifAlias first (user-configured description)
	results, err := s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, s.oids.IfAlias())
	if err != nil || len(results) == 0 {
		// Fall back to ifDescr
		results, err = s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, s.oids.IfDescr())
		if err != nil {
			return nil, fmt.Errorf("walk port descriptions: %w", err)
		}
	}

	descs := make(map[int]string)
	for _, r := range results {
		idx := extractIndex(r.OID)
		if idx > 0 {
			descs[idx] = r.AsString()
		}
	}
	return descs, nil
}

// helpers

func extractIndex(oid string) int {
	parts := strings.Split(oid, ".")
	if len(parts) == 0 {
		return 0
	}
	last := parts[len(parts)-1]
	var idx int
	fmt.Sscanf(last, "%d", &idx)
	return idx
}

func buildIntMap(results []snmp.Result) map[int]int {
	m := make(map[int]int)
	for _, r := range results {
		idx := extractIndex(r.OID)
		if idx > 0 {
			v, _ := r.AsInt()
			m[idx] = v
		}
	}
	return m
}

func buildStringMap(results []snmp.Result) map[int]string {
	m := make(map[int]string)
	for _, r := range results {
		idx := extractIndex(r.OID)
		if idx > 0 {
			m[idx] = r.AsString()
		}
	}
	return m
}

func adminStatusStr(v int) string {
	switch v {
	case 1:
		return "enabled"
	case 2:
		return "disabled"
	case 3:
		return "testing"
	default:
		return "unknown"
	}
}

func operStatusStr(v int) string {
	switch v {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "testing"
	case 5:
		return "dormant"
	default:
		return "unknown"
	}
}

func formatSpeed(bps int) string {
	switch {
	case bps >= 1000000000:
		return fmt.Sprintf("%dGbps", bps/1000000000)
	case bps >= 1000000:
		return fmt.Sprintf("%dMbps", bps/1000000)
	case bps >= 1000:
		return fmt.Sprintf("%dKbps", bps/1000)
	default:
		return fmt.Sprintf("%dbps", bps)
	}
}
