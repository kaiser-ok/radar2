package sshcli

import (
	"regexp"
	"strings"
)

// ParsedTable represents a parsed CLI table output.
type ParsedTable struct {
	Headers []string
	Rows    []map[string]string
}

// ParseMACTable parses "show mac address-table" output from various vendors.
func ParseMACTable(output, vendor string) []MACEntry {
	switch strings.ToLower(vendor) {
	case "cisco":
		return parseCiscoMAC(output)
	case "mikrotik":
		return parseMikrotikMAC(output)
	case "dlink":
		return parseDLinkMAC(output)
	default:
		return parseGenericMAC(output)
	}
}

// MACEntry represents a MAC address table entry.
type MACEntry struct {
	VLAN string
	MAC  string
	Type string
	Port string
}

// ParseInterfaces parses "show interfaces status" output.
func ParseInterfaces(output, vendor string) []InterfaceEntry {
	switch strings.ToLower(vendor) {
	case "cisco":
		return parseCiscoInterfaces(output)
	default:
		return nil
	}
}

// InterfaceEntry represents an interface status entry.
type InterfaceEntry struct {
	Port   string
	Name   string
	Status string
	Speed  string
	Duplex string
	VLAN   string
}

// ParseVLANs parses "show vlan brief" output.
func ParseVLANs(output, vendor string) []VLANEntry {
	switch strings.ToLower(vendor) {
	case "cisco":
		return parseCiscoVLANs(output)
	default:
		return nil
	}
}

// VLANEntry represents a VLAN entry.
type VLANEntry struct {
	ID     string
	Name   string
	Status string
	Ports  []string
}

// --- Cisco Parsers ---

var ciscoMACRe = regexp.MustCompile(`(?m)^\s*(\d+)\s+([\da-fA-F]{4}\.[\da-fA-F]{4}\.[\da-fA-F]{4})\s+(\w+)\s+(.+?)\s*$`)

func parseCiscoMAC(output string) []MACEntry {
	var entries []MACEntry
	for _, m := range ciscoMACRe.FindAllStringSubmatch(output, -1) {
		entries = append(entries, MACEntry{
			VLAN: m[1],
			MAC:  normalizeCiscoMAC(m[2]),
			Type: m[3],
			Port: strings.TrimSpace(m[4]),
		})
	}
	return entries
}

func normalizeCiscoMAC(mac string) string {
	// Convert aabb.ccdd.eeff to aa:bb:cc:dd:ee:ff
	mac = strings.ReplaceAll(mac, ".", "")
	if len(mac) != 12 {
		return mac
	}
	return strings.ToLower(mac[0:2] + ":" + mac[2:4] + ":" + mac[4:6] + ":" + mac[6:8] + ":" + mac[8:10] + ":" + mac[10:12])
}

var ciscoIfRe = regexp.MustCompile(`(?m)^(\S+)\s+(.{0,20}?)\s+(connected|notconnect|disabled|err-disabled)\s+(\S+)\s+(a-\S+|\S+)\s+(a-\S+|\S+)\s*$`)

func parseCiscoInterfaces(output string) []InterfaceEntry {
	var entries []InterfaceEntry
	for _, m := range ciscoIfRe.FindAllStringSubmatch(output, -1) {
		entries = append(entries, InterfaceEntry{
			Port:   m[1],
			Name:   strings.TrimSpace(m[2]),
			Status: m[3],
			VLAN:   m[4],
			Duplex: m[5],
			Speed:  m[6],
		})
	}
	return entries
}

var ciscoVLANRe = regexp.MustCompile(`(?m)^(\d+)\s+(\S+)\s+(active|act/unsup)\s*(.*)$`)

func parseCiscoVLANs(output string) []VLANEntry {
	var entries []VLANEntry
	for _, m := range ciscoVLANRe.FindAllStringSubmatch(output, -1) {
		ports := []string{}
		if m[4] != "" {
			for _, p := range strings.Split(m[4], ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					ports = append(ports, p)
				}
			}
		}
		entries = append(entries, VLANEntry{
			ID:     m[1],
			Name:   m[2],
			Status: m[3],
			Ports:  ports,
		})
	}
	return entries
}

// --- Mikrotik Parsers ---

var mikrotikMACRe = regexp.MustCompile(`(?m)^\s*\d+\s+[A-Z]*\s*([\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2})\s+(\S+)\s+`)

func parseMikrotikMAC(output string) []MACEntry {
	var entries []MACEntry
	for _, m := range mikrotikMACRe.FindAllStringSubmatch(output, -1) {
		entries = append(entries, MACEntry{
			MAC:  strings.ToLower(m[1]),
			Port: m[2],
		})
	}
	return entries
}

// --- D-Link Parsers ---

var dlinkMACRe = regexp.MustCompile(`(?m)^\s*(\d+)\s+([\da-fA-F]{2}-[\da-fA-F]{2}-[\da-fA-F]{2}-[\da-fA-F]{2}-[\da-fA-F]{2}-[\da-fA-F]{2})\s+(\S+)\s+(\S+)`)

func parseDLinkMAC(output string) []MACEntry {
	var entries []MACEntry
	for _, m := range dlinkMACRe.FindAllStringSubmatch(output, -1) {
		entries = append(entries, MACEntry{
			VLAN: m[1],
			MAC:  strings.ToLower(strings.ReplaceAll(m[2], "-", ":")),
			Type: m[3],
			Port: m[4],
		})
	}
	return entries
}

// --- Generic Parser ---

var genericMACRe = regexp.MustCompile(`([\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2})`)

func parseGenericMAC(output string) []MACEntry {
	var entries []MACEntry
	seen := map[string]bool{}
	for _, m := range genericMACRe.FindAllStringSubmatch(output, -1) {
		mac := strings.ToLower(strings.ReplaceAll(m[1], "-", ":"))
		if !seen[mac] {
			seen[mac] = true
			entries = append(entries, MACEntry{MAC: mac})
		}
	}
	return entries
}
