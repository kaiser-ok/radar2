package service

import (
	"encoding/hex"
	"fmt"
	"strings"

	"new_radar/internal/config"
	"new_radar/internal/model"
	"new_radar/internal/snmp"
)

type FDBService struct {
	snmpClient *snmp.Client
	oids       *snmp.OIDRegistry
	profiles   *config.ProfileRegistry
}

func NewFDBService(sc *snmp.Client, oids *snmp.OIDRegistry, profiles *config.ProfileRegistry) *FDBService {
	return &FDBService{snmpClient: sc, oids: oids, profiles: profiles}
}

// GetFDB returns the forwarding database (MAC address table) for a switch.
func (s *FDBService) GetFDB(sw *model.Switch) ([]model.FDBEntry, error) {
	ver := snmp.ParseVersion(sw.SNMPVer)

	// Try Q-BRIDGE MIB first (dot1qTpFdbPort) — more common on modern switches
	qbridgeOID := s.oids.Get("vlan", "dot1qTpFdbPort")
	if qbridgeOID == "" {
		qbridgeOID = "1.3.6.1.2.1.17.7.1.2.2.1.2"
	}

	results, err := s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, qbridgeOID)
	if err == nil && len(results) > 0 {
		return parseQBridgeFDB(results), nil
	}

	// Fallback to standard bridge MIB (dot1dTpFdbPort)
	bridgeOID := s.oids.Get("bridge", "dot1dTpFdbPort")
	if bridgeOID == "" {
		bridgeOID = "1.3.6.1.2.1.17.4.3.1.2"
	}

	results, err = s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, bridgeOID)
	if err == nil && len(results) > 0 {
		return parseBridgeFDB(results), nil
	}

	// Cisco per-VLAN STP: FDB is only accessible via community@vlan
	// Discover VLANs from Cisco vtpVlanState, then walk FDB per VLAN
	vlans := s.discoverCiscoVLANs(sw.IP, sw.Community, ver)
	if len(vlans) > 0 {
		return s.walkFDBPerVLAN(sw.IP, sw.Community, ver, bridgeOID, vlans), nil
	}

	return nil, fmt.Errorf("walk FDB: no entries found")
}

// discoverCiscoVLANs returns active VLAN IDs from Cisco vtpVlanState.
func (s *FDBService) discoverCiscoVLANs(ip, community string, ver snmp.SnmpVersion) []int {
	// vtpVlanState: .1.3.6.1.4.1.9.9.46.1.3.1.1.2
	results, err := s.snmpClient.BulkWalk(ip, community, ver, ".1.3.6.1.4.1.9.9.46.1.3.1.1.2")
	if err != nil || len(results) == 0 {
		return nil
	}

	var vlans []int
	for _, r := range results {
		// OID: ...2.1.{vlanId} — last component is the VLAN ID
		parts := strings.Split(r.OID, ".")
		if len(parts) == 0 {
			continue
		}
		var vlanID int
		fmt.Sscanf(parts[len(parts)-1], "%d", &vlanID)
		// Skip internal VLANs (1002-1005) and VLAN 0
		if vlanID > 0 && vlanID < 1002 {
			vlans = append(vlans, vlanID)
		}
	}
	return vlans
}

// walkFDBPerVLAN walks FDB using community@vlan for each VLAN.
func (s *FDBService) walkFDBPerVLAN(ip, community string, ver snmp.SnmpVersion, bridgeOID string, vlans []int) []model.FDBEntry {
	var allEntries []model.FDBEntry
	seen := make(map[string]bool) // deduplicate by MAC

	for _, vlan := range vlans {
		vlanCommunity := fmt.Sprintf("%s@%d", community, vlan)
		results, err := s.snmpClient.BulkWalk(ip, vlanCommunity, ver, bridgeOID)
		if err != nil || len(results) == 0 {
			continue
		}
		for _, entry := range parseBridgeFDB(results) {
			if !seen[entry.MAC] {
				entry.VLAN = vlan
				allEntries = append(allEntries, entry)
				seen[entry.MAC] = true
			}
		}
	}
	return allEntries
}

// parseBridgeFDB parses dot1dTpFdbTable results.
// OID format: dot1dTpFdbPort.MAC_AS_DECIMAL_BYTES = port
func parseBridgeFDB(results []snmp.Result) []model.FDBEntry {
	var entries []model.FDBEntry
	for _, r := range results {
		port, ok := r.AsInt()
		if !ok || port < 0 {
			continue
		}
		mac := extractMACFromOID(r.OID)
		if mac == "" {
			continue
		}
		entries = append(entries, model.FDBEntry{
			MAC:  mac,
			Port: port,
		})
	}
	return entries
}

// parseQBridgeFDB parses dot1qTpFdbTable results.
// OID format: dot1qTpFdbPort.VLAN.MAC_AS_DECIMAL_BYTES = port
func parseQBridgeFDB(results []snmp.Result) []model.FDBEntry {
	var entries []model.FDBEntry
	for _, r := range results {
		port, ok := r.AsInt()
		if !ok || port < 0 {
			continue
		}
		mac, vlan := extractMACAndVLANFromOID(r.OID)
		if mac == "" {
			continue
		}
		entries = append(entries, model.FDBEntry{
			MAC:  mac,
			Port: port,
			VLAN: vlan,
		})
	}
	return entries
}

// extractMACFromOID extracts MAC from OID suffix like ...1.2.3.4.5.6 (last 6 octets).
func extractMACFromOID(oid string) string {
	parts := strings.Split(oid, ".")
	if len(parts) < 6 {
		return ""
	}
	octets := parts[len(parts)-6:]
	var mac []byte
	for _, o := range octets {
		var b int
		fmt.Sscanf(o, "%d", &b)
		mac = append(mac, byte(b))
	}
	return hex.EncodeToString(mac)
}

// extractMACAndVLANFromOID extracts VLAN and MAC from Q-BRIDGE OID.
// Format: ...dot1qTpFdbPort.VLAN.MAC[6]
func extractMACAndVLANFromOID(oid string) (string, int) {
	parts := strings.Split(oid, ".")
	if len(parts) < 7 {
		return "", 0
	}
	// Last 6 = MAC, 7th from end = VLAN
	octets := parts[len(parts)-6:]
	var mac []byte
	for _, o := range octets {
		var b int
		fmt.Sscanf(o, "%d", &b)
		mac = append(mac, byte(b))
	}

	var vlan int
	fmt.Sscanf(parts[len(parts)-7], "%d", &vlan)

	return hex.EncodeToString(mac), vlan
}
