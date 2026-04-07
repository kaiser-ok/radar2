package service

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"new_radar/internal/db"
	"new_radar/internal/model"
	"new_radar/internal/snmp"
)

type MACService struct {
	snmpClient *snmp.Client
	oids       *snmp.OIDRegistry
	fdbSvc     *FDBService
	portSvc    *PortService
	macLocRepo *db.MACLocationRepo
	blockedRepo *db.BlockedMACRepo
	switchRepo *db.SwitchRepo
	cacheTTL   time.Duration
}

func NewMACService(
	sc *snmp.Client,
	oids *snmp.OIDRegistry,
	fdbSvc *FDBService,
	portSvc *PortService,
	macLocRepo *db.MACLocationRepo,
	blockedRepo *db.BlockedMACRepo,
	switchRepo *db.SwitchRepo,
) *MACService {
	return &MACService{
		snmpClient:  sc,
		oids:        oids,
		fdbSvc:      fdbSvc,
		portSvc:     portSvc,
		macLocRepo:  macLocRepo,
		blockedRepo: blockedRepo,
		switchRepo:  switchRepo,
		cacheTTL:    5 * time.Minute,
	}
}

// LocateMAC finds which switch and port a MAC address is on.
func (s *MACService) LocateMAC(unitID int64, mac string) (*model.MACLocationResult, error) {
	mac = NormalizeMAC(mac)

	// Check DB cache first
	cached, err := s.macLocRepo.Find(unitID, mac)
	if err == nil && time.Since(cached.UpdatedAt) < s.cacheTTL {
		sw, _ := s.switchRepo.GetByID(cached.SwitchID)
		result := &model.MACLocationResult{
			MAC:      mac,
			SwitchID: cached.SwitchID,
			Port:     cached.Port,
			Cached:   true,
		}
		if sw != nil {
			result.SwitchIP = sw.IP
		}
		return result, nil
	}

	// Live walk all switches in the unit
	switches, err := s.switchRepo.GetByUnit(unitID)
	if err != nil {
		return nil, fmt.Errorf("list switches: %w", err)
	}

	for _, sw := range switches {
		fdbEntries, err := s.fdbSvc.GetFDB(&sw)
		if err != nil {
			continue
		}

		// Get bridge port → ifIndex mapping
		bridgeMap := s.getBridgePortToIfIndexMap(&sw)

		for _, entry := range fdbEntries {
			if entry.MAC == mac {
				ifIndex := entry.Port
				if mapped, ok := bridgeMap[entry.Port]; ok {
					ifIndex = mapped
				}

				// Update cache
				_ = s.macLocRepo.Upsert(unitID, mac, sw.ID, ifIndex)

				return &model.MACLocationResult{
					MAC:      mac,
					SwitchID: sw.ID,
					SwitchIP: sw.IP,
					Port:     ifIndex,
					VLAN:     entry.VLAN,
					Cached:   false,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("MAC %s not found on any switch", mac)
}

// ResolveMACToIP finds the IP address for a MAC by walking ARP tables.
func (s *MACService) ResolveMACToIP(unitID int64, mac string) (string, error) {
	mac = NormalizeMAC(mac)

	switches, err := s.switchRepo.GetByUnit(unitID)
	if err != nil {
		return "", fmt.Errorf("list switches: %w", err)
	}

	for _, sw := range switches {
		entries := s.walkARPTable(&sw)
		for _, e := range entries {
			if NormalizeMAC(e.MAC) == mac {
				return e.IP, nil
			}
		}
	}

	return "", fmt.Errorf("no IP found for MAC %s", mac)
}

// ResolveIPToMAC finds the MAC address for an IP by walking ARP tables.
func (s *MACService) ResolveIPToMAC(unitID int64, ip string) (string, error) {
	switches, err := s.switchRepo.GetByUnit(unitID)
	if err != nil {
		return "", fmt.Errorf("list switches: %w", err)
	}

	for _, sw := range switches {
		entries := s.walkARPTable(&sw)
		for _, e := range entries {
			if e.IP == ip {
				return e.MAC, nil
			}
		}
	}

	return "", fmt.Errorf("no MAC found for IP %s", ip)
}

// RebuildTopology walks FDB on all switches and rebuilds the MAC location cache.
func (s *MACService) RebuildTopology(unitID int64) (*model.TopologyRebuildResult, error) {
	switches, err := s.switchRepo.GetByUnit(unitID)
	if err != nil {
		return nil, fmt.Errorf("list switches: %w", err)
	}

	// Clear existing cache
	_ = s.macLocRepo.DeleteByUnit(unitID)

	result := &model.TopologyRebuildResult{}

	for _, sw := range switches {
		result.SwitchesScanned++

		fdbEntries, err := s.fdbSvc.GetFDB(&sw)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", sw.IP, err))
			continue
		}

		bridgeMap := s.getBridgePortToIfIndexMap(&sw)

		for _, entry := range fdbEntries {
			result.MACsFound++
			ifIndex := entry.Port
			if mapped, ok := bridgeMap[entry.Port]; ok {
				ifIndex = mapped
			}
			if err := s.macLocRepo.Upsert(unitID, entry.MAC, sw.ID, ifIndex); err == nil {
				result.MACsUpdated++
			}
		}
	}

	return result, nil
}

// BlockMAC locates a MAC, disables the port, and records the block.
func (s *MACService) BlockMAC(unitID int64, mac string) (*model.BlockedMAC, error) {
	mac = NormalizeMAC(mac)

	loc, err := s.LocateMAC(unitID, mac)
	if err != nil {
		return nil, fmt.Errorf("cannot locate MAC to block: %w", err)
	}

	sw, err := s.switchRepo.GetByID(loc.SwitchID)
	if err != nil {
		return nil, fmt.Errorf("load switch: %w", err)
	}

	// Disable the port
	if err := s.portSvc.SetPortAdmin(sw, loc.Port, false); err != nil {
		return nil, fmt.Errorf("disable port %d on %s: %w", loc.Port, sw.IP, err)
	}

	// Record in DB
	swID := loc.SwitchID
	port := loc.Port
	if err := s.blockedRepo.Block(unitID, mac, &swID, &port); err != nil {
		return nil, fmt.Errorf("record block: %w", err)
	}

	blocked, _ := s.blockedRepo.Find(unitID, mac)
	return blocked, nil
}

// UnblockMAC re-enables the port and removes the block record.
func (s *MACService) UnblockMAC(unitID int64, mac string) error {
	mac = NormalizeMAC(mac)

	blocked, err := s.blockedRepo.Find(unitID, mac)
	if err == sql.ErrNoRows {
		return fmt.Errorf("MAC %s is not blocked", mac)
	}
	if err != nil {
		return fmt.Errorf("lookup blocked MAC: %w", err)
	}

	// Re-enable port if we know where it was
	if blocked.SwitchID != nil && blocked.Port != nil {
		sw, err := s.switchRepo.GetByID(*blocked.SwitchID)
		if err == nil {
			_ = s.portSvc.SetPortAdmin(sw, *blocked.Port, true)
		}
	}

	return s.blockedRepo.Unblock(unitID, mac)
}

// ListBlocked returns all blocked MACs for a unit.
func (s *MACService) ListBlocked(unitID int64) ([]model.BlockedMAC, error) {
	return s.blockedRepo.GetByUnit(unitID)
}

// --- helpers ---

func (s *MACService) walkARPTable(sw *model.Switch) []model.ARPEntry {
	ver := snmp.ParseVersion(sw.SNMPVer)
	oid := s.oids.Get("arp", "ipNetToMediaPhysAddress")
	if oid == "" {
		oid = "1.3.6.1.2.1.4.22.1.2"
	}

	results, err := s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, oid)
	if err != nil {
		return nil
	}

	var entries []model.ARPEntry
	for _, r := range results {
		// OID suffix: .<ifIndex>.<IP_byte1>.<IP_byte2>.<IP_byte3>.<IP_byte4>
		parts := strings.Split(r.OID, ".")
		if len(parts) < 4 {
			continue
		}
		ip := strings.Join(parts[len(parts)-4:], ".")

		macBytes := r.AsBytes()
		if len(macBytes) != 6 {
			continue
		}
		mac := hex.EncodeToString(macBytes)

		entries = append(entries, model.ARPEntry{IP: ip, MAC: mac})
	}
	return entries
}

func (s *MACService) getBridgePortToIfIndexMap(sw *model.Switch) map[int]int {
	ver := snmp.ParseVersion(sw.SNMPVer)
	oid := s.oids.Get("bridge", "dot1dBasePortIfIndex")
	if oid == "" {
		oid = "1.3.6.1.2.1.17.1.4.1.2"
	}

	results, err := s.snmpClient.BulkWalk(sw.IP, sw.Community, ver, oid)
	if err != nil {
		return nil
	}

	m := make(map[int]int)
	for _, r := range results {
		bridgePort := extractIndex(r.OID)
		ifIndex, ok := r.AsInt()
		if ok && bridgePort > 0 {
			m[bridgePort] = ifIndex
		}
	}
	return m
}

// NormalizeMAC strips separators and lowercases a MAC address to 12-char hex.
func NormalizeMAC(mac string) string {
	mac = strings.ToLower(mac)
	mac = strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac)
	return mac
}
