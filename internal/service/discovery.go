package service

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"new_radar/internal/config"
	"new_radar/internal/snmp"
)

// DiscoveredDevice represents a device found during network scan.
type DiscoveredDevice struct {
	IP          string `json:"ip"`
	SysDescr    string `json:"sys_descr,omitempty"`
	SysObjectID string `json:"sys_object_id,omitempty"`
	SysName     string `json:"sys_name,omitempty"`
	Vendor      string `json:"vendor,omitempty"`
	ProfileID   string `json:"profile_id,omitempty"`
}

type DiscoveryService struct {
	snmpClient *snmp.Client
	profiles   *config.ProfileRegistry
	workers    int
}

func NewDiscoveryService(sc *snmp.Client, profiles *config.ProfileRegistry, workers int) *DiscoveryService {
	if workers <= 0 {
		workers = 20
	}
	return &DiscoveryService{snmpClient: sc, profiles: profiles, workers: workers}
}

// DiscoverSubnet scans a subnet for SNMP-responsive devices.
func (s *DiscoveryService) DiscoverSubnet(subnet, community, snmpVer string) ([]DiscoveredDevice, error) {
	ips, err := expandSubnet(subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet %s: %w", subnet, err)
	}

	ver := snmp.ParseVersion(snmpVer)
	if community == "" {
		community = "public"
	}

	var mu sync.Mutex
	var results []DiscoveredDevice
	var wg sync.WaitGroup

	jobs := make(chan string, len(ips))
	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)

	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				dev := s.probeDevice(ip, community, ver)
				if dev != nil {
					mu.Lock()
					results = append(results, *dev)
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()
	slog.Info("discovery complete", "subnet", subnet, "found", len(results))
	return results, nil
}

func (s *DiscoveryService) probeDevice(ip, community string, ver snmp.SnmpVersion) *DiscoveredDevice {
	oids := []string{
		"1.3.6.1.2.1.1.1.0", // sysDescr
		"1.3.6.1.2.1.1.2.0", // sysObjectID
		"1.3.6.1.2.1.1.5.0", // sysName
	}

	results, err := s.snmpClient.Get(ip, community, ver, oids)
	if err != nil {
		return nil
	}

	dev := &DiscoveredDevice{IP: ip}
	for _, r := range results {
		val := r.AsString()
		switch {
		case strings.HasSuffix(r.OID, "1.1.0"):
			dev.SysDescr = val
		case strings.HasSuffix(r.OID, "1.2.0"):
			dev.SysObjectID = val
		case strings.HasSuffix(r.OID, "1.5.0"):
			dev.SysName = val
		}
	}

	// Auto-detect vendor via profile fingerprint
	if s.profiles != nil && (dev.SysObjectID != "" || dev.SysDescr != "") {
		profile := s.profiles.DetectDevice(dev.SysObjectID, dev.SysDescr)
		if profile != nil {
			dev.Vendor = profile.Vendor
			dev.ProfileID = profile.ID
		}
	}

	return dev
}

// expandSubnet converts CIDR notation to a list of IPs.
func expandSubnet(subnet string) ([]string, error) {
	// Handle single IP
	if !strings.Contains(subnet, "/") {
		return []string{subnet}, nil
	}

	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		// Skip network and broadcast
		ips = append(ips, ip.String())
	}

	// Remove network address (first) and broadcast (last)
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
