package onboarding

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// WalkEntry represents a single line from an snmpwalk output.
type WalkEntry struct {
	OID   string
	Type  string // INTEGER, STRING, OID, Counter32, Gauge32, Timeticks, Hex-STRING, etc.
	Value string
}

// CapabilityResult represents the analysis result for a single capability.
type CapabilityResult struct {
	Capability string `json:"capability" yaml:"capability"`
	Supported  bool   `json:"supported" yaml:"supported"`
	Confidence string `json:"confidence" yaml:"confidence"` // high, medium, low
	Evidence   string `json:"evidence" yaml:"evidence"`
	OIDsFound  []string `json:"oids_found,omitempty" yaml:"oids_found,omitempty"`
}

// AnalysisReport is the full output of walk analysis.
type AnalysisReport struct {
	SysDescr     string             `json:"sys_descr" yaml:"sys_descr"`
	SysObjectID  string             `json:"sys_object_id" yaml:"sys_object_id"`
	SysName      string             `json:"sys_name" yaml:"sys_name"`
	PortCount    int                `json:"port_count" yaml:"port_count"`
	Capabilities []CapabilityResult `json:"capabilities" yaml:"capabilities"`
	VendorTree   string             `json:"vendor_tree,omitempty" yaml:"vendor_tree,omitempty"`
	Summary      string             `json:"summary" yaml:"summary"`
}

// OID prefixes for capability detection
var capabilityOIDs = map[string][]struct {
	prefix string
	desc   string
}{
	"system.read": {
		{".1.3.6.1.2.1.1.1", "sysDescr"},
		{".1.3.6.1.2.1.1.2", "sysObjectID"},
		{".1.3.6.1.2.1.1.3", "sysUpTime"},
		{".1.3.6.1.2.1.1.5", "sysName"},
	},
	"interfaces.read": {
		{".1.3.6.1.2.1.2.2.1.1", "ifIndex"},
		{".1.3.6.1.2.1.2.2.1.2", "ifDescr"},
		{".1.3.6.1.2.1.2.2.1.7", "ifAdminStatus"},
		{".1.3.6.1.2.1.2.2.1.8", "ifOperStatus"},
	},
	"port.admin.read": {
		{".1.3.6.1.2.1.2.2.1.7", "ifAdminStatus"},
	},
	"port.admin.write": {
		{".1.3.6.1.2.1.2.2.1.7", "ifAdminStatus (SET not tested from walk)"},
	},
	"port.oper.read": {
		{".1.3.6.1.2.1.2.2.1.8", "ifOperStatus"},
	},
	"port.traffic.read": {
		{".1.3.6.1.2.1.2.2.1.10", "ifInOctets"},
		{".1.3.6.1.2.1.2.2.1.16", "ifOutOctets"},
	},
	"mac_table.read": {
		{".1.3.6.1.2.1.17.4.3.1", "dot1dTpFdb (bridge MIB)"},
		{".1.3.6.1.2.1.17.7.1.2.2.1", "dot1qTpFdb (Q-BRIDGE)"},
	},
	"vlan.read": {
		{".1.3.6.1.2.1.17.7.1.4.3.1", "dot1qVlanStatic"},
		{".1.3.6.1.2.1.17.7.1.4.2.1", "dot1qVlanCurrent"},
	},
	"poe.status.read": {
		{".1.3.6.1.2.1.105.1.1.1", "pethPsePort"},
		{".1.3.6.1.2.1.105.1.3.1", "pethMainPse"},
	},
	"poe.control.write": {
		{".1.3.6.1.2.1.105.1.1.1.3", "pethPsePortAdminEnable (SET not tested)"},
	},
}

// ParseWalkFile parses an snmpwalk output file (numeric OID format with -On flag).
func ParseWalkFile(path string) ([]WalkEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []WalkEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entry, err := parseWalkLine(line)
		if err != nil {
			continue
		}
		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

// parseWalkLine handles common snmpwalk output formats:
// .1.3.6.1.2.1.1.1.0 = STRING: "Cisco IOS..."
// .1.3.6.1.2.1.2.2.1.7.1 = INTEGER: 1
func parseWalkLine(line string) (WalkEntry, error) {
	parts := strings.SplitN(line, " = ", 2)
	if len(parts) != 2 {
		return WalkEntry{}, fmt.Errorf("invalid walk line")
	}

	oid := strings.TrimSpace(parts[0])
	rest := strings.TrimSpace(parts[1])

	// Parse "TYPE: VALUE"
	typeParts := strings.SplitN(rest, ": ", 2)
	typ := ""
	val := rest
	if len(typeParts) == 2 {
		typ = strings.TrimSpace(typeParts[0])
		val = strings.TrimSpace(typeParts[1])
	}

	// Strip quotes from string values
	val = strings.Trim(val, "\"")

	return WalkEntry{OID: oid, Type: typ, Value: val}, nil
}

// AnalyzeWalks takes multiple walk files and produces a capability analysis report.
func AnalyzeWalks(walkFiles map[string]string) (*AnalysisReport, error) {
	// Parse all walk files into one combined entry list
	var allEntries []WalkEntry
	for name, path := range walkFiles {
		entries, err := ParseWalkFile(path)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		allEntries = append(allEntries, entries...)
	}

	report := &AnalysisReport{}

	// Build OID index for fast prefix lookup
	oidSet := make(map[string][]WalkEntry)
	for _, e := range allEntries {
		oidSet[e.OID] = append(oidSet[e.OID], e)
	}

	// Extract system info
	report.SysDescr = findValue(allEntries, ".1.3.6.1.2.1.1.1.0")
	report.SysObjectID = findValue(allEntries, ".1.3.6.1.2.1.1.2.0")
	report.SysName = findValue(allEntries, ".1.3.6.1.2.1.1.5.0")

	// Count interfaces
	report.PortCount = countPrefix(allEntries, ".1.3.6.1.2.1.2.2.1.1.")

	// Detect vendor tree
	report.VendorTree = detectVendorTree(allEntries)

	// Analyze each capability
	for capName, oidChecks := range capabilityOIDs {
		result := analyzeCapability(capName, oidChecks, allEntries)
		report.Capabilities = append(report.Capabilities, result)
	}

	// Summary
	supported := 0
	for _, c := range report.Capabilities {
		if c.Supported {
			supported++
		}
	}
	report.Summary = fmt.Sprintf("Device: %s (%s), %d ports, %d/%d capabilities detected",
		report.SysDescr, report.SysObjectID, report.PortCount,
		supported, len(report.Capabilities))

	return report, nil
}

func analyzeCapability(name string, checks []struct{ prefix, desc string }, entries []WalkEntry) CapabilityResult {
	result := CapabilityResult{
		Capability: name,
	}

	foundCount := 0
	var evidence []string
	var oidsFound []string

	for _, check := range checks {
		count := countPrefix(entries, check.prefix)
		if count > 0 {
			foundCount++
			evidence = append(evidence, fmt.Sprintf("%s: %d entries", check.desc, count))
			oidsFound = append(oidsFound, check.prefix)
		} else {
			evidence = append(evidence, fmt.Sprintf("%s: not found", check.desc))
		}
	}

	result.OIDsFound = oidsFound

	if foundCount == len(checks) {
		result.Supported = true
		result.Confidence = "high"
	} else if foundCount > 0 {
		result.Supported = true
		result.Confidence = "medium"
	} else {
		result.Supported = false
		result.Confidence = "high" // high confidence it's NOT supported
	}

	// Write operations can't be confirmed from walk alone
	if strings.HasSuffix(name, ".write") && result.Supported {
		result.Confidence = "low"
		evidence = append(evidence, "NOTE: write capability inferred from OID presence, SET not tested")
	}

	result.Evidence = strings.Join(evidence, "; ")
	return result
}

func findValue(entries []WalkEntry, oid string) string {
	for _, e := range entries {
		if e.OID == oid {
			return e.Value
		}
	}
	return ""
}

func countPrefix(entries []WalkEntry, prefix string) int {
	count := 0
	for _, e := range entries {
		if strings.HasPrefix(e.OID, prefix) {
			count++
		}
	}
	return count
}

func detectVendorTree(entries []WalkEntry) string {
	// Find the enterprise OID prefix
	for _, e := range entries {
		if strings.HasPrefix(e.OID, ".1.3.6.1.4.1.") {
			parts := strings.Split(e.OID, ".")
			if len(parts) >= 8 {
				return strings.Join(parts[:8], ".")
			}
		}
	}
	return ""
}

// WalkToSnmprec converts walk entries to snmprec format.
func WalkToSnmprec(entries []WalkEntry) []string {
	var lines []string
	for _, e := range entries {
		oid := strings.TrimPrefix(e.OID, ".")
		typeCode := walkTypeToSnmprec(e.Type)
		value := e.Value

		// Format hex strings
		if e.Type == "Hex-STRING" {
			value = strings.ReplaceAll(strings.TrimSpace(value), " ", "")
			typeCode = "4x"
		}

		lines = append(lines, fmt.Sprintf("%s|%s|%s", oid, typeCode, value))
	}
	return lines
}

func walkTypeToSnmprec(walkType string) string {
	switch walkType {
	case "INTEGER":
		return "2"
	case "STRING", "":
		return "4"
	case "Hex-STRING":
		return "4x"
	case "OID":
		return "6"
	case "NULL":
		return "5"
	case "Counter32":
		return "41"
	case "Gauge32":
		return "42"
	case "Timeticks":
		return "43"
	case "Counter64":
		return "46"
	case "IpAddress":
		return "64"
	default:
		return "4"
	}
}
