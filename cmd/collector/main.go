// collector — Offline SNMP evidence collector for Radar onboarding.
//
// Use this on a laptop at a remote site where the Radar server is unreachable.
// It collects all SNMP data needed for device onboarding, packages it into a
// directory that can be directly imported into the Radar onboarding pipeline.
//
// Usage:
//
//	collector -ip 192.168.1.1 -community public [-version 2c] [-output ./collect]
//
// Output structure (ready to copy into onboarding/{vendor}_{model}/):
//
//	{output}/
//	  fingerprint.yaml          — device identity
//	  intake.yaml               — case metadata
//	  evidence/
//	    {vendor}_standard.walk  — MIB-2 tree (system, interfaces, ports, traffic)
//	    {vendor}_bridge.walk    — Bridge MIB (MAC table, STP)
//	    {vendor}_qbridge.walk   — Q-BRIDGE MIB (802.1Q VLANs, per-VLAN FDB)
//	    {vendor}_poe.walk       — PoE MIB (if supported)
//	    {vendor}_vendor.walk    — Vendor enterprise MIB
//	    {vendor}_vlan_*.walk    — Cisco per-VLAN FDB (if Cisco detected)
//	  report.txt                — human-readable collection summary
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"new_radar/internal/mib"

	"github.com/gosnmp/gosnmp"
	"gopkg.in/yaml.v3"
)

// Enterprise OID → vendor name mapping
var enterpriseVendors = map[string]string{
	"1.3.6.1.4.1.9":     "cisco",
	"1.3.6.1.4.1.171":   "dlink",
	"1.3.6.1.4.1.890":   "zyxel",
	"1.3.6.1.4.1.14988": "mikrotik",
	"1.3.6.1.4.1.11":    "hp",
	"1.3.6.1.4.1.47196": "hp",
	"1.3.6.1.4.1.12356": "fortinet",
	"1.3.6.1.4.1.2636":  "juniper",
	"1.3.6.1.4.1.6486":  "alcatel",
	"1.3.6.1.4.1.6527":  "nokia",
	"1.3.6.1.4.1.25506": "h3c",
	"1.3.6.1.4.1.2011":  "huawei",
}

// capabilityProbes defines specific OIDs to check for each capability.
// These are the same OIDs the walk analyzer uses.
var capabilityProbes = []struct {
	name string
	oids []string
	desc string
}{
	{"system.read", []string{".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.2.0", ".1.3.6.1.2.1.1.5.0"}, "sysDescr, sysObjectID, sysName"},
	{"interfaces.read", []string{".1.3.6.1.2.1.2.2.1.1", ".1.3.6.1.2.1.2.2.1.2"}, "ifIndex, ifDescr"},
	{"port.admin", []string{".1.3.6.1.2.1.2.2.1.7"}, "ifAdminStatus"},
	{"port.oper", []string{".1.3.6.1.2.1.2.2.1.8"}, "ifOperStatus"},
	{"port.traffic", []string{".1.3.6.1.2.1.2.2.1.10", ".1.3.6.1.2.1.2.2.1.16"}, "ifInOctets, ifOutOctets"},
	{"port.description", []string{".1.3.6.1.2.1.31.1.1.1.18"}, "ifAlias"},
	{"port.highspeed", []string{".1.3.6.1.2.1.31.1.1.1.15"}, "ifHighSpeed"},
	{"mac_table(bridge)", []string{".1.3.6.1.2.1.17.4.3.1"}, "dot1dTpFdb"},
	{"mac_table(qbridge)", []string{".1.3.6.1.2.1.17.7.1.2.2.1"}, "dot1qTpFdb"},
	{"vlan.static", []string{".1.3.6.1.2.1.17.7.1.4.3.1"}, "dot1qVlanStatic"},
	{"vlan.current", []string{".1.3.6.1.2.1.17.7.1.4.2.1"}, "dot1qVlanCurrent"},
	{"stp", []string{".1.3.6.1.2.1.17.2"}, "dot1dStp"},
	{"poe.port", []string{".1.3.6.1.2.1.105.1.1.1"}, "pethPsePort"},
	{"poe.main", []string{".1.3.6.1.2.1.105.1.3.1"}, "pethMainPse"},
}

type walkResult struct {
	name    string
	file    string
	entries int
	dur     time.Duration
}

func main() {
	ip := flag.String("ip", "", "Switch IP address (required)")
	community := flag.String("community", "public", "SNMP community string")
	version := flag.String("version", "2c", "SNMP version: 1 or 2c")
	output := flag.String("output", "", "Output directory (default: ./collect_{ip})")
	timeout := flag.Duration("timeout", 10*time.Second, "SNMP timeout per request")
	retries := flag.Int("retries", 1, "SNMP retries")
	deep := flag.Bool("deep", true, "Deep collection: Cisco per-VLAN FDB, capability probing")
	mibsDir := flag.String("mibs", "", "Directory containing vendor MIB files to bundle (optional)")
	flag.Parse()

	if *ip == "" {
		fmt.Fprintln(os.Stderr, "Usage: collector -ip <switch-ip> [-community public] [-version 2c] [-output dir] [-mibs ./mibs]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Collects all SNMP evidence for Radar device onboarding.")
		fmt.Fprintln(os.Stderr, "Output can be copied directly to the Radar server for import.")
		fmt.Fprintln(os.Stderr, "")
		flag.PrintDefaults()
		os.Exit(1)
	}

	outDir := *output
	if outDir == "" {
		outDir = fmt.Sprintf("collect_%s", strings.ReplaceAll(*ip, ".", "_"))
	}

	snmpVer := gosnmp.Version2c
	if *version == "1" {
		snmpVer = gosnmp.Version1
	}

	startTime := time.Now()

	fmt.Printf("╔══════════════════════════════════════╗\n")
	fmt.Printf("║   Radar Offline SNMP Collector       ║\n")
	fmt.Printf("╠══════════════════════════════════════╣\n")
	fmt.Printf("║ Target:    %-25s ║\n", *ip)
	fmt.Printf("║ Community: %-25s ║\n", *community)
	fmt.Printf("║ Version:   SNMPv%-20s ║\n", *version)
	fmt.Printf("║ Deep mode: %-25v ║\n", *deep)
	if *mibsDir != "" {
		fmt.Printf("║ MIBs:      %-25s ║\n", *mibsDir)
	}
	fmt.Printf("║ Output:    %-25s ║\n", outDir+"/")
	fmt.Printf("╚══════════════════════════════════════╝\n\n")

	// === Step 1: Fingerprint ===
	fmt.Print("[1/6] Fingerprinting device... ")
	sess := newSession(*ip, *community, snmpVer, *timeout, *retries)
	if err := sess.Connect(); err != nil {
		fatal("SNMP connect failed: %v", err)
	}

	sysOIDs := []string{
		".1.3.6.1.2.1.1.1.0", // sysDescr
		".1.3.6.1.2.1.1.2.0", // sysObjectID
		".1.3.6.1.2.1.1.3.0", // sysUpTime
		".1.3.6.1.2.1.1.4.0", // sysContact
		".1.3.6.1.2.1.1.5.0", // sysName
		".1.3.6.1.2.1.1.6.0", // sysLocation
	}
	pkt, err := sess.Get(sysOIDs)
	sess.Conn.Close()
	if err != nil {
		fatal("Failed to get system info: %v", err)
	}

	sysDescr := pduString(pkt.Variables[0])
	sysObjectID := pduString(pkt.Variables[1])
	sysUpTime := pduString(pkt.Variables[2])
	sysContact := pduString(pkt.Variables[3])
	sysName := pduString(pkt.Variables[4])
	sysLocation := pduString(pkt.Variables[5])

	fmt.Println("OK")
	fmt.Printf("  sysDescr:    %s\n", sysDescr)
	fmt.Printf("  sysObjectID: %s\n", sysObjectID)
	fmt.Printf("  sysName:     %s\n", sysName)
	fmt.Printf("  sysUpTime:   %s\n", sysUpTime)

	vendor := detectVendor(sysObjectID, sysDescr)
	model := detectModel(vendor, sysDescr, sysName)
	firmware := detectFirmware(sysDescr)
	fmt.Printf("  Vendor:      %s\n", vendor)
	fmt.Printf("  Model:       %s\n", model)
	fmt.Printf("  Firmware:    %s\n\n", firmware)

	// Create output directories
	evidenceDir := filepath.Join(outDir, "evidence")
	os.MkdirAll(evidenceDir, 0755)

	// Save fingerprint.yaml (matches Radar's FingerprintRequest format)
	fp := map[string]string{
		"ip":            *ip,
		"community":     *community,
		"snmp_version":  *version,
		"sys_descr":     sysDescr,
		"sys_object_id": sysObjectID,
		"sys_name":      sysName,
		"sys_uptime":    sysUpTime,
		"sys_contact":   sysContact,
		"sys_location":  sysLocation,
	}
	writeYAML(filepath.Join(outDir, "fingerprint.yaml"), fp)

	// Save intake.yaml
	tier := "C"
	knownVendors := map[string]bool{"cisco": true, "dlink": true, "hp": true, "zyxel": true, "mikrotik": true}
	if knownVendors[vendor] {
		tier = "A"
	}
	intake := map[string]string{
		"vendor":       vendor,
		"model":        model,
		"tier":         tier,
		"firmware":     firmware,
		"status":       "collected",
		"source":       "offline-collector",
		"collected_at": time.Now().Format(time.RFC3339),
	}
	writeYAML(filepath.Join(outDir, "intake.yaml"), intake)

	// === Step 2: MIB-2 standard walk ===
	var allResults []walkResult

	vendorOID := extractVendorOID(sysObjectID)

	type walkTarget struct {
		name    string
		oidRoot string
	}
	targets := []walkTarget{
		{"standard", ".1.3.6.1.2.1"},
		{"bridge", ".1.3.6.1.2.1.17"},
		{"qbridge", ".1.3.6.1.2.1.17.7"},
		{"poe", ".1.3.6.1.2.1.105"},
	}
	if vendorOID != "" {
		targets = append(targets, walkTarget{"vendor", vendorOID})
	}

	step := 2
	for _, t := range targets {
		fmt.Printf("[%d/6] Walking %s (%s)... ", step, t.name, t.oidRoot)
		start := time.Now()

		lines, err := doWalk(*ip, *community, snmpVer, t.oidRoot, *timeout, *retries)
		dur := time.Since(start)

		if err != nil {
			fmt.Printf("SKIP (%v) [%v]\n", err, dur.Round(time.Millisecond))
			continue
		}
		if len(lines) == 0 {
			fmt.Printf("SKIP (no data) [%v]\n", dur.Round(time.Millisecond))
			continue
		}

		filename := fmt.Sprintf("%s_%s.walk", vendor, t.name)
		walkPath := filepath.Join(evidenceDir, filename)
		os.WriteFile(walkPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)

		fmt.Printf("OK (%d entries → %s) [%v]\n", len(lines), filename, dur.Round(time.Millisecond))
		allResults = append(allResults, walkResult{t.name, filename, len(lines), dur})
		step++
	}

	// === Step 3: Cisco per-VLAN FDB ===
	var ciscoVLANs []int
	if *deep && vendor == "cisco" {
		fmt.Print("\n[*] Cisco detected — discovering VLANs (vtpVlanState)... ")
		ciscoVLANs = discoverCiscoVLANs(*ip, *community, snmpVer, *timeout, *retries)
		if len(ciscoVLANs) > 0 {
			fmt.Printf("found %d VLANs: %v\n", len(ciscoVLANs), ciscoVLANs)

			for _, vlan := range ciscoVLANs {
				vlanComm := fmt.Sprintf("%s@%d", *community, vlan)
				fmt.Printf("    VLAN %d: walking bridge FDB (community@%d)... ", vlan, vlan)
				start := time.Now()

				lines, err := doWalk(*ip, vlanComm, snmpVer, ".1.3.6.1.2.1.17.4.3.1", *timeout, *retries)
				dur := time.Since(start)

				if err != nil || len(lines) == 0 {
					fmt.Printf("SKIP (%d entries)\n", len(lines))
					continue
				}

				filename := fmt.Sprintf("%s_vlan_%d.walk", vendor, vlan)
				walkPath := filepath.Join(evidenceDir, filename)
				os.WriteFile(walkPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)

				fmt.Printf("OK (%d MACs) [%v]\n", len(lines), dur.Round(time.Millisecond))
				allResults = append(allResults, walkResult{fmt.Sprintf("vlan_%d", vlan), filename, len(lines), dur})
			}
		} else {
			fmt.Println("no VLANs found (might use Q-BRIDGE instead)")
		}
	}

	// === Step 4: Capability probing ===
	var probeResults []probeResult
	if *deep {
		fmt.Print("\n[*] Probing individual capabilities...\n")
		probeResults = probeCapabilities(*ip, *community, snmpVer, *timeout, *retries)
		for _, pr := range probeResults {
			status := "FAIL"
			if pr.found {
				status = fmt.Sprintf("OK (%d entries)", pr.count)
			}
			fmt.Printf("    %-25s %s\n", pr.name, status)
		}
	}

	// === Step 5: Vendor-specific extra walks ===
	if *deep {
		extraTargets := vendorExtraWalks(vendor)
		if len(extraTargets) > 0 {
			fmt.Printf("\n[*] Vendor-specific walks for %s...\n", vendor)
			for _, t := range extraTargets {
				fmt.Printf("    %s (%s)... ", t.name, t.oidRoot)
				start := time.Now()

				lines, err := doWalk(*ip, *community, snmpVer, t.oidRoot, *timeout, *retries)
				dur := time.Since(start)

				if err != nil || len(lines) == 0 {
					fmt.Println("SKIP")
					continue
				}

				filename := fmt.Sprintf("%s_%s.walk", vendor, t.name)
				walkPath := filepath.Join(evidenceDir, filename)
				os.WriteFile(walkPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)

				fmt.Printf("OK (%d entries) [%v]\n", len(lines), dur.Round(time.Millisecond))
				allResults = append(allResults, walkResult{t.name, filename, len(lines), dur})
			}
		}
	}

	// === Step 6: Bundle MIB files and parse for extra OID discovery ===
	var mibOIDCount int
	var mibModules []string
	var mibExtraOIDs []mibDiscoveredOID
	if *mibsDir != "" {
		mibOIDCount, mibModules, mibExtraOIDs = bundleAndParseMIBs(*mibsDir, outDir, evidenceDir, vendor, *ip, *community, snmpVer, *timeout, *retries, &allResults)
	}

	// === Generate report ===
	totalEntries := 0
	for _, r := range allResults {
		totalEntries += r.entries
	}
	totalDur := time.Since(startTime)

	report := generateReport(fp, intake, vendor, model, firmware, allResults, probeResults, ciscoVLANs, totalEntries, totalDur, mibModules, mibExtraOIDs, mibOIDCount)
	os.WriteFile(filepath.Join(outDir, "report.txt"), []byte(report), 0644)

	fmt.Printf("\n╔══════════════════════════════════════╗\n")
	fmt.Printf("║         Collection Complete           ║\n")
	fmt.Printf("╠══════════════════════════════════════╣\n")
	fmt.Printf("║ Walk files:  %-23d ║\n", len(allResults))
	fmt.Printf("║ Total OIDs:  %-23d ║\n", totalEntries)
	if mibOIDCount > 0 {
		fmt.Printf("║ MIB modules: %-23d ║\n", len(mibModules))
		fmt.Printf("║ MIB OIDs:    %-23d ║\n", mibOIDCount)
	}
	fmt.Printf("║ Duration:    %-23v ║\n", totalDur.Round(time.Second))
	fmt.Printf("║ Output:      %-23s ║\n", outDir+"/")
	fmt.Printf("╚══════════════════════════════════════╝\n\n")

	// Capability summary
	if len(probeResults) > 0 {
		found := 0
		for _, pr := range probeResults {
			if pr.found {
				found++
			}
		}
		fmt.Printf("Capabilities detected: %d/%d\n", found, len(probeResults))
	}

	fmt.Printf("\nTo import into Radar:\n")
	fmt.Printf("  Option A — Copy directory:\n")
	fmt.Printf("    1. scp -r %s/ radar-server:onboarding/%s_%s/\n", outDir, vendor, safeName(model))
	fmt.Printf("    2. Open web UI → Enrolled Devices → the case will auto-appear\n")
	fmt.Printf("    3. Run Analyze → Approve\n")
	fmt.Printf("\n  Option B — API upload:\n")
	fmt.Printf("    1. Create case:\n")
	fmt.Printf("       curl -u admin:gentrice -X POST http://radar:8082/api/v2/onboarding \\\n")
	fmt.Printf("         -H 'Content-Type: application/json' \\\n")
	fmt.Printf("         -d '{\"vendor\":\"%s\",\"model\":\"%s\",\"tier\":\"%s\",\"ip\":\"%s\",\"community\":\"%s\"}'\n", vendor, model, tier, *ip, *community)
	fmt.Printf("    2. Upload each .walk file:\n")
	fmt.Printf("       for f in %s/evidence/*.walk; do\n", outDir)
	fmt.Printf("         curl -u admin:gentrice -X POST http://radar:8082/api/v2/onboarding/{id}/evidence \\\n")
	fmt.Printf("           -F \"file=@$f\"\n")
	fmt.Printf("       done\n")
	fmt.Printf("    3. Analyze + Approve:\n")
	fmt.Printf("       curl -u admin:gentrice -X POST http://radar:8082/api/v2/onboarding/{id}/analyze\n")
	fmt.Printf("       curl -u admin:gentrice -X POST http://radar:8082/api/v2/onboarding/{id}/approve\n")
}

// doWalk performs a BulkWalk (v2c) or Walk (v1) and returns formatted lines.
func doWalk(ip, community string, version gosnmp.SnmpVersion, oidRoot string, timeout time.Duration, retries int) ([]string, error) {
	ws := newSession(ip, community, version, timeout, retries)
	if err := ws.Connect(); err != nil {
		return nil, err
	}
	defer ws.Conn.Close()

	var pdus []gosnmp.SnmpPDU
	var err error
	if version == gosnmp.Version2c {
		err = ws.BulkWalk(oidRoot, func(pdu gosnmp.SnmpPDU) error {
			pdus = append(pdus, pdu)
			return nil
		})
	} else {
		err = ws.Walk(oidRoot, func(pdu gosnmp.SnmpPDU) error {
			pdus = append(pdus, pdu)
			return nil
		})
	}
	if err != nil {
		return nil, err
	}

	var lines []string
	for _, pdu := range pdus {
		line := formatWalkLine(pdu)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

// discoverCiscoVLANs finds active VLANs from Cisco vtpVlanState.
func discoverCiscoVLANs(ip, community string, version gosnmp.SnmpVersion, timeout time.Duration, retries int) []int {
	// vtpVlanState: .1.3.6.1.4.1.9.9.46.1.3.1.1.2
	lines, err := doWalk(ip, community, version, ".1.3.6.1.4.1.9.9.46.1.3.1.1.2", timeout, retries)
	if err != nil || len(lines) == 0 {
		return nil
	}

	var vlans []int
	for _, line := range lines {
		parts := strings.Split(line, " = ")
		if len(parts) == 0 {
			continue
		}
		oidParts := strings.Split(parts[0], ".")
		if len(oidParts) == 0 {
			continue
		}
		var vlanID int
		fmt.Sscanf(oidParts[len(oidParts)-1], "%d", &vlanID)
		// Skip internal VLANs (1002-1005) and 0
		if vlanID > 0 && vlanID < 1002 {
			vlans = append(vlans, vlanID)
		}
	}
	sort.Ints(vlans)
	return vlans
}

type probeResult struct {
	name  string
	desc  string
	found bool
	count int
}

// probeCapabilities tests each capability OID to see if the device responds.
func probeCapabilities(ip, community string, version gosnmp.SnmpVersion, timeout time.Duration, retries int) []probeResult {
	var results []probeResult

	for _, cap := range capabilityProbes {
		pr := probeResult{name: cap.name, desc: cap.desc}
		for _, oid := range cap.oids {
			lines, err := doWalk(ip, community, version, oid, timeout, retries)
			if err == nil && len(lines) > 0 {
				pr.found = true
				pr.count += len(lines)
			}
		}
		results = append(results, pr)
	}
	return results
}

type vendorWalk struct {
	name    string
	oidRoot string
}

// vendorExtraWalks returns additional OIDs to walk for known vendors.
func vendorExtraWalks(vendor string) []vendorWalk {
	switch vendor {
	case "cisco":
		return []vendorWalk{
			// Cisco-specific FDB via community indexing is handled separately.
			// Here we collect other useful Cisco MIBs.
			{"cisco_vtp", ".1.3.6.1.4.1.9.9.46"},         // VTP (VLAN Trunking Protocol)
			{"cisco_stack", ".1.3.6.1.4.1.9.9.500"},       // Cisco stackwise
			{"cisco_env", ".1.3.6.1.4.1.9.9.13"},          // Cisco environmental (temp, fan, PSU)
			{"cisco_cpu", ".1.3.6.1.4.1.9.9.109.1.1.1"},   // cpmCPUTotal
			{"cisco_memory", ".1.3.6.1.4.1.9.9.48.1.1.1"}, // ciscoMemoryPool
		}
	case "dlink":
		return []vendorWalk{
			{"dlink_sys", ".1.3.6.1.4.1.171.12.1"},  // D-Link system info
			{"dlink_port", ".1.3.6.1.4.1.171.12.58"}, // D-Link port config
		}
	case "hp":
		return []vendorWalk{
			{"hp_icf", ".1.3.6.1.4.1.11.2.14"},   // HP/Aruba ICF
			{"hp_poe", ".1.3.6.1.4.1.11.2.14.11"}, // HP PoE extensions
		}
	case "mikrotik":
		return []vendorWalk{
			{"mikrotik_sys", ".1.3.6.1.4.1.14988.1"}, // Mikrotik system
		}
	case "zyxel":
		return []vendorWalk{
			{"zyxel_sys", ".1.3.6.1.4.1.890.1.15"}, // Zyxel managed switch
		}
	case "fortinet":
		return []vendorWalk{
			{"fortinet_sys", ".1.3.6.1.4.1.12356.101"}, // FortiGate system
		}
	case "huawei":
		return []vendorWalk{
			{"huawei_sys", ".1.3.6.1.4.1.2011.5.25"},    // Huawei switch
			{"huawei_cpu", ".1.3.6.1.4.1.2011.6.3.4"},    // Huawei CPU
			{"huawei_mem", ".1.3.6.1.4.1.2011.5.25.31.1"}, // Huawei memory
		}
	case "juniper":
		return []vendorWalk{
			{"juniper_sys", ".1.3.6.1.4.1.2636.3.1"}, // Juniper chassis
		}
	default:
		return nil
	}
}

// mibDiscoveredOID represents an OID found in MIB files that yielded walk data.
type mibDiscoveredOID struct {
	name   string
	oid    string
	module string
	access string
	count  int // entries from walk
}

// bundleAndParseMIBs copies MIB files, parses them, discovers OIDs, and walks any
// enterprise OIDs found in MIBs that haven't been collected yet.
func bundleAndParseMIBs(mibsDir, outDir, evidenceDir, vendor, ip, community string,
	snmpVer gosnmp.SnmpVersion, timeout time.Duration, retries int, allResults *[]walkResult) (int, []string, []mibDiscoveredOID) {

	fmt.Printf("\n[*] Bundling MIB files from %s...\n", mibsDir)

	// Copy MIB files to evidence/mibs/
	dstMibDir := filepath.Join(outDir, "evidence", "mibs")
	os.MkdirAll(dstMibDir, 0755)

	mibPatterns := []string{"*.mib", "*.my", "*.txt", "*.MIB"}
	var copied int
	for _, pat := range mibPatterns {
		matches, _ := filepath.Glob(filepath.Join(mibsDir, pat))
		for _, src := range matches {
			dst := filepath.Join(dstMibDir, filepath.Base(src))
			if data, err := os.ReadFile(src); err == nil {
				os.WriteFile(dst, data, 0644)
				copied++
			}
		}
	}
	// Also check subdirectories (vendor-organized MIBs)
	entries, _ := os.ReadDir(mibsDir)
	for _, e := range entries {
		if e.IsDir() {
			subDir := filepath.Join(mibsDir, e.Name())
			dstSubDir := filepath.Join(dstMibDir, e.Name())
			os.MkdirAll(dstSubDir, 0755)
			for _, pat := range mibPatterns {
				matches, _ := filepath.Glob(filepath.Join(subDir, pat))
				for _, src := range matches {
					dst := filepath.Join(dstSubDir, filepath.Base(src))
					if data, err := os.ReadFile(src); err == nil {
						os.WriteFile(dst, data, 0644)
						copied++
					}
				}
			}
		}
	}
	fmt.Printf("    Copied %d MIB files\n", copied)

	if copied == 0 {
		return 0, nil, nil
	}

	// Parse MIBs
	fmt.Print("    Parsing MIB files... ")
	parser := mib.NewParser()
	if err := parser.LoadDir(dstMibDir); err != nil {
		fmt.Printf("warning: %v\n", err)
	}
	// Also load subdirectories
	subEntries, _ := os.ReadDir(dstMibDir)
	for _, e := range subEntries {
		if e.IsDir() {
			parser.LoadDir(filepath.Join(dstMibDir, e.Name()))
		}
	}

	allOIDs := parser.GetAllOIDs()
	modules := parser.ListModules()
	fmt.Printf("OK (%d modules, %d OIDs resolved)\n", len(modules), len(allOIDs))

	// Discover enterprise OIDs from MIBs that we haven't walked yet
	// Look for read-accessible table/scalar OIDs under the vendor enterprise tree
	fmt.Print("    Scanning MIB OIDs for additional walk targets... ")

	// Collect already-walked OID prefixes
	walkedPrefixes := map[string]bool{
		".1.3.6.1.2.1":   true, // standard
		".1.3.6.1.2.1.17": true, // bridge
		".1.3.6.1.2.1.17.7": true, // qbridge
		".1.3.6.1.2.1.105": true, // poe
	}

	// Find interesting enterprise OIDs from MIB definitions
	var extraOIDs []mib.OIDEntry
	seen := map[string]bool{}
	for _, entry := range allOIDs {
		// Only enterprise OIDs
		if !strings.HasPrefix(entry.OID, "1.3.6.1.4.1.") {
			continue
		}
		// Only read-accessible
		if entry.Access == "not-accessible" || entry.Access == "" {
			continue
		}
		// Get the top-level subtree (first 3 levels under enterprise)
		parts := strings.Split(entry.OID, ".")
		if len(parts) < 9 {
			continue
		}
		// Use 9 components as subtree key (enterprises.X.Y.Z)
		subtree := "." + strings.Join(parts[:9], ".")
		if seen[subtree] || walkedPrefixes[subtree] {
			continue
		}
		seen[subtree] = true
		extraOIDs = append(extraOIDs, entry)
	}
	fmt.Printf("found %d extra subtrees\n", len(extraOIDs))

	// Walk the discovered subtrees
	var discovered []mibDiscoveredOID
	if len(extraOIDs) > 0 {
		fmt.Printf("    Walking MIB-discovered OIDs...\n")
		for _, entry := range extraOIDs {
			parts := strings.Split(entry.OID, ".")
			subtree := "." + strings.Join(parts[:9], ".")

			fmt.Printf("      %s (%s)... ", entry.Name, subtree)
			start := time.Now()

			lines, err := doWalk(ip, community, snmpVer, subtree, timeout, retries)
			dur := time.Since(start)

			d := mibDiscoveredOID{
				name:   entry.Name,
				oid:    subtree,
				module: entry.Module,
				access: entry.Access,
			}

			if err != nil || len(lines) == 0 {
				fmt.Println("SKIP")
				discovered = append(discovered, d)
				continue
			}

			d.count = len(lines)
			discovered = append(discovered, d)

			// Save as walk file
			safeMod := strings.ToLower(strings.ReplaceAll(entry.Module, "-", "_"))
			filename := fmt.Sprintf("%s_mib_%s.walk", vendor, safeMod)
			walkPath := filepath.Join(evidenceDir, filename)

			// Append if file already exists (multiple subtrees from same module)
			if existing, err := os.ReadFile(walkPath); err == nil {
				lines = append([]string{string(existing)}, lines...)
			}
			os.WriteFile(walkPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)

			fmt.Printf("OK (%d entries) [%v]\n", d.count, dur.Round(time.Millisecond))
			*allResults = append(*allResults, walkResult{"mib:" + entry.Name, filename, d.count, dur})
		}
	}

	// Save MIB OID index as reference for the analyzer
	var indexLines []string
	for _, entry := range allOIDs {
		line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s", entry.OID, entry.Name, entry.Module, entry.Type, entry.Access)
		indexLines = append(indexLines, line)
	}
	if len(indexLines) > 0 {
		sort.Strings(indexLines)
		header := "# OID\tName\tModule\tType\tAccess\n"
		os.WriteFile(filepath.Join(outDir, "evidence", "mib_oid_index.tsv"),
			[]byte(header+strings.Join(indexLines, "\n")+"\n"), 0644)
		fmt.Printf("    Saved MIB OID index: %d entries → mib_oid_index.tsv\n", len(indexLines))
	}

	return len(allOIDs), modules, discovered
}

func generateReport(fp map[string]string, intake map[string]string, vendor, model, firmware string,
	walks []walkResult, probes []probeResult, ciscoVLANs []int, totalEntries int, totalDur time.Duration,
	mibModules []string, mibExtra []mibDiscoveredOID, mibOIDCount int) string {
	var b strings.Builder

	b.WriteString("================================================================\n")
	b.WriteString("  Radar Offline Collector — Collection Report\n")
	b.WriteString("================================================================\n\n")

	b.WriteString("Device Information:\n")
	b.WriteString(fmt.Sprintf("  IP:            %s\n", fp["ip"]))
	b.WriteString(fmt.Sprintf("  sysDescr:      %s\n", fp["sys_descr"]))
	b.WriteString(fmt.Sprintf("  sysObjectID:   %s\n", fp["sys_object_id"]))
	b.WriteString(fmt.Sprintf("  sysName:       %s\n", fp["sys_name"]))
	b.WriteString(fmt.Sprintf("  sysUpTime:     %s\n", fp["sys_uptime"]))
	b.WriteString(fmt.Sprintf("  sysContact:    %s\n", fp["sys_contact"]))
	b.WriteString(fmt.Sprintf("  sysLocation:   %s\n", fp["sys_location"]))
	b.WriteString(fmt.Sprintf("  Vendor:        %s\n", vendor))
	b.WriteString(fmt.Sprintf("  Model:         %s\n", model))
	b.WriteString(fmt.Sprintf("  Firmware:      %s\n", firmware))
	b.WriteString(fmt.Sprintf("  Support Tier:  %s\n\n", intake["tier"]))

	b.WriteString("Walk Files Collected:\n")
	for _, w := range walks {
		b.WriteString(fmt.Sprintf("  %-30s %6d entries  (%v)\n", w.file, w.entries, w.dur.Round(time.Millisecond)))
	}
	b.WriteString(fmt.Sprintf("\n  Total: %d entries in %d files\n\n", totalEntries, len(walks)))

	if len(ciscoVLANs) > 0 {
		b.WriteString(fmt.Sprintf("Cisco VLANs discovered: %v\n\n", ciscoVLANs))
	}

	if len(probes) > 0 {
		b.WriteString("Capability Probing Results:\n")
		found, notFound := 0, 0
		for _, pr := range probes {
			status := "NOT FOUND"
			if pr.found {
				status = fmt.Sprintf("FOUND (%d entries)", pr.count)
				found++
			} else {
				notFound++
			}
			b.WriteString(fmt.Sprintf("  %-25s %-20s %s\n", pr.name, status, pr.desc))
		}
		b.WriteString(fmt.Sprintf("\n  Summary: %d/%d capabilities detected\n\n", found, found+notFound))
	}

	if len(mibModules) > 0 {
		b.WriteString(fmt.Sprintf("MIB Files Loaded: %d modules, %d OIDs resolved\n", len(mibModules), mibOIDCount))
		b.WriteString("  Modules: " + strings.Join(mibModules, ", ") + "\n\n")
	}

	if len(mibExtra) > 0 {
		b.WriteString("MIB-Discovered OIDs:\n")
		found := 0
		for _, d := range mibExtra {
			status := "NO DATA"
			if d.count > 0 {
				status = fmt.Sprintf("%d entries", d.count)
				found++
			}
			b.WriteString(fmt.Sprintf("  %-30s %-15s %-12s %s (%s)\n", d.name, d.oid, status, d.module, d.access))
		}
		b.WriteString(fmt.Sprintf("\n  MIB-discovered: %d/%d subtrees had data\n\n", found, len(mibExtra)))
	}

	b.WriteString(fmt.Sprintf("Collection completed in %v\n", totalDur.Round(time.Second)))
	b.WriteString(fmt.Sprintf("Collected at: %s\n", time.Now().Format(time.RFC3339)))

	return b.String()
}

func newSession(target, community string, version gosnmp.SnmpVersion, timeout time.Duration, retries int) *gosnmp.GoSNMP {
	return &gosnmp.GoSNMP{
		Target:    target,
		Port:      161,
		Community: community,
		Version:   version,
		Timeout:   timeout,
		Retries:   retries,
	}
}

func extractVendorOID(sysObjectID string) string {
	cleanOID := strings.TrimPrefix(sysObjectID, ".")
	if strings.HasPrefix(cleanOID, "1.3.6.1.4.1.") {
		parts := strings.Split(cleanOID, ".")
		if len(parts) >= 7 {
			return "." + strings.Join(parts[:7], ".")
		}
	}
	return ""
}

func detectVendor(sysObjectID, sysDescr string) string {
	oid := strings.TrimPrefix(sysObjectID, ".")
	for prefix, vendor := range enterpriseVendors {
		if strings.HasPrefix(oid, prefix+".") || oid == prefix {
			return vendor
		}
	}
	dl := strings.ToLower(sysDescr)
	fallbacks := map[string][]string{
		"cisco":    {"cisco"},
		"mikrotik": {"routeros", "mikrotik"},
		"dlink":    {"d-link", "dlink"},
		"zyxel":    {"zyxel"},
		"hp":       {"aruba", "procurve"},
		"fortinet": {"forti"},
		"juniper":  {"junos", "juniper"},
		"huawei":   {"huawei"},
	}
	for vendor, keywords := range fallbacks {
		for _, kw := range keywords {
			if strings.Contains(dl, kw) {
				return vendor
			}
		}
	}
	return "unknown"
}

func detectModel(vendor, sysDescr, sysName string) string {
	desc := sysDescr
	if desc == "" {
		desc = sysName
	}
	switch vendor {
	case "cisco":
		m := regexp.MustCompile(`C(\d+\w*)`).FindStringSubmatch(desc)
		if m != nil {
			return m[1]
		}
		m = regexp.MustCompile(`Software[^,]*\((\S+?)-`).FindStringSubmatch(desc)
		if m != nil {
			return m[1]
		}
	case "mikrotik":
		m := regexp.MustCompile(`RouterOS\s+(\S+)`).FindStringSubmatch(desc)
		if m != nil {
			return m[1]
		}
	case "fortinet":
		m := regexp.MustCompile(`(FortiGate[\w-]*|FortiSwitch[\w-]*)`).FindStringSubmatch(desc)
		if m != nil {
			return m[1]
		}
	case "dlink":
		m := regexp.MustCompile(`(D[EGXS]S-[\w-]+)`).FindStringSubmatch(desc)
		if m != nil {
			return m[1]
		}
	case "zyxel":
		m := regexp.MustCompile(`(GS\d+[\w-]*|XGS\d+[\w-]*)`).FindStringSubmatch(desc)
		if m != nil {
			return m[1]
		}
	case "huawei":
		m := regexp.MustCompile(`(S\d+[\w-]*|CE\d+[\w-]*)`).FindStringSubmatch(desc)
		if m != nil {
			return m[1]
		}
	}
	if sysName != "" {
		return sysName
	}
	return "unknown"
}

func detectFirmware(sysDescr string) string {
	m := regexp.MustCompile(`Version\s+(\S+)`).FindStringSubmatch(sysDescr)
	if m != nil {
		return strings.TrimRight(m[1], ",")
	}
	m = regexp.MustCompile(`(\d+\.\d+\.\d+)`).FindStringSubmatch(sysDescr)
	if m != nil {
		return m[1]
	}
	return ""
}

func pduString(pdu gosnmp.SnmpPDU) string {
	switch v := pdu.Value.(type) {
	case []byte:
		return string(v)
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

func formatWalkLine(pdu gosnmp.SnmpPDU) string {
	typeName, value := formatPDU(pdu)
	if typeName == "" {
		return ""
	}
	return fmt.Sprintf("%s = %s: %s", pdu.Name, typeName, value)
}

func formatPDU(pdu gosnmp.SnmpPDU) (string, string) {
	switch pdu.Type {
	case gosnmp.Integer:
		return "INTEGER", fmt.Sprintf("%v", pdu.Value)
	case gosnmp.OctetString:
		switch v := pdu.Value.(type) {
		case []byte:
			if isPrintable(v) {
				return "STRING", fmt.Sprintf(`"%s"`, string(v))
			}
			return "Hex-STRING", formatHex(v)
		case string:
			return "STRING", fmt.Sprintf(`"%s"`, v)
		default:
			return "STRING", fmt.Sprintf(`"%v"`, v)
		}
	case gosnmp.Null, gosnmp.NoSuchObject, gosnmp.NoSuchInstance:
		return "", ""
	case gosnmp.ObjectIdentifier:
		return "OID", fmt.Sprintf("%v", pdu.Value)
	case gosnmp.IPAddress:
		return "IpAddress", fmt.Sprintf("%v", pdu.Value)
	case gosnmp.Counter32:
		return "Counter32", fmt.Sprintf("%v", pdu.Value)
	case gosnmp.Gauge32:
		return "Gauge32", fmt.Sprintf("%v", pdu.Value)
	case gosnmp.TimeTicks:
		return "Timeticks", fmt.Sprintf("(%v)", pdu.Value)
	case gosnmp.Counter64:
		return "Counter64", fmt.Sprintf("%v", pdu.Value)
	case gosnmp.OpaqueFloat:
		return "Opaque: Float", fmt.Sprintf("%v", pdu.Value)
	case gosnmp.OpaqueDouble:
		return "Opaque: Double", fmt.Sprintf("%v", pdu.Value)
	default:
		return "STRING", fmt.Sprintf(`"%v"`, pdu.Value)
	}
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			if c != '\r' && c != '\n' && c != '\t' {
				return false
			}
		}
	}
	return true
}

func formatHex(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02X", c)
	}
	return strings.Join(parts, " ")
}

func safeName(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}

func writeYAML(path string, data interface{}) {
	out, err := yaml.Marshal(data)
	if err != nil {
		fatal("Failed to marshal YAML: %v", err)
	}
	if err := os.WriteFile(path, out, 0644); err != nil {
		fatal("Failed to write %s: %v", path, err)
	}
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "\nERROR: "+format+"\n", args...)
	os.Exit(1)
}
