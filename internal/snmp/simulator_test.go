package snmp

import (
	"testing"
)

func TestLoadCiscoSnmprec(t *testing.T) {
	data, err := LoadSnmprec("../../tests/snmprec/cisco/cisco2960_numeric.snmprec")
	if err != nil {
		t.Fatalf("failed to load cisco snmprec: %v", err)
	}
	if data.Count() == 0 {
		t.Fatal("cisco snmprec loaded 0 entries")
	}
	t.Logf("Cisco C2960: loaded %d entries", data.Count())

	// Test sysDescr
	entry := data.Get("1.3.6.1.2.1.1.1.0")
	if entry == nil {
		t.Fatal("sysDescr not found")
	}
	if entry.Type != 4 {
		t.Errorf("sysDescr type = %d, want 4 (OctetString)", entry.Type)
	}
	desc := string(entry.Value.([]byte))
	if len(desc) == 0 {
		t.Error("sysDescr is empty")
	}
	t.Logf("sysDescr: %.80s...", desc)

	// Test sysObjectID
	entry = data.Get("1.3.6.1.2.1.1.2.0")
	if entry == nil {
		t.Fatal("sysObjectID not found")
	}
	if entry.Type != 6 {
		t.Errorf("sysObjectID type = %d, want 6 (OID)", entry.Type)
	}
	t.Logf("sysObjectID: %v", entry.Value)

	// Test sysUpTime
	entry = data.Get("1.3.6.1.2.1.1.3.0")
	if entry == nil {
		t.Fatal("sysUpTime not found")
	}
	if entry.Type != 43 {
		t.Errorf("sysUpTime type = %d, want 43 (TimeTicks)", entry.Type)
	}

	// Test sysName
	entry = data.Get("1.3.6.1.2.1.1.5.0")
	if entry == nil {
		t.Fatal("sysName not found")
	}
	sysName := string(entry.Value.([]byte))
	t.Logf("sysName: %s", sysName)

	// Test GetNext
	next := data.GetNext("1.3.6.1.2.1.1.1.0")
	if next == nil {
		t.Fatal("GetNext after sysDescr returned nil")
	}
	if next.OID != "1.3.6.1.2.1.1.2.0" {
		t.Errorf("GetNext after sysDescr = %s, want sysObjectID", next.OID)
	}

	// Test Walk on ifIndex subtree
	ifIndexEntries := data.GetSubtree("1.3.6.1.2.1.2.2.1.1")
	if len(ifIndexEntries) == 0 {
		t.Fatal("ifIndex walk returned 0 entries")
	}
	t.Logf("ifIndex entries: %d", len(ifIndexEntries))

	// Test Walk on ifDescr subtree
	ifDescrEntries := data.GetSubtree("1.3.6.1.2.1.2.2.1.2")
	if len(ifDescrEntries) == 0 {
		t.Fatal("ifDescr walk returned 0 entries")
	}
	t.Logf("ifDescr entries: %d (first: %s)", len(ifDescrEntries), string(ifDescrEntries[0].Value.([]byte)))
}

func TestLoadMikrotikSnmprec(t *testing.T) {
	data, err := LoadSnmprec("../../tests/snmprec/mikrotik/mikrotik_numeric.snmprec")
	if err != nil {
		t.Fatalf("failed to load mikrotik snmprec: %v", err)
	}
	if data.Count() == 0 {
		t.Fatal("mikrotik snmprec loaded 0 entries")
	}
	t.Logf("Mikrotik CRS328: loaded %d entries", data.Count())

	// Test sysDescr
	entry := data.Get("1.3.6.1.2.1.1.1.0")
	if entry == nil {
		t.Fatal("sysDescr not found")
	}
	desc := string(entry.Value.([]byte))
	if desc != "RouterOS CRS328-24P-4S+" {
		t.Errorf("sysDescr = %q, want RouterOS CRS328-24P-4S+", desc)
	}
	t.Logf("sysDescr: %s", desc)

	// Test sysObjectID (Mikrotik enterprise OID)
	entry = data.Get("1.3.6.1.2.1.1.2.0")
	if entry == nil {
		t.Fatal("sysObjectID not found")
	}
	oid, ok := entry.Value.(string)
	if !ok {
		t.Fatalf("sysObjectID value type = %T, want string", entry.Value)
	}
	if oid != "1.3.6.1.4.1.14988.1" {
		t.Errorf("sysObjectID = %s, want 1.3.6.1.4.1.14988.1", oid)
	}

	// Test ifNumber
	entry = data.Get("1.3.6.1.2.1.2.1.0")
	if entry == nil {
		t.Fatal("ifNumber not found")
	}
	ifNum, ok := entry.Value.(int)
	if !ok {
		t.Fatalf("ifNumber value type = %T, want int", entry.Value)
	}
	if ifNum != 32 {
		t.Errorf("ifNumber = %d, want 32", ifNum)
	}
	t.Logf("ifNumber: %d", ifNum)

	// Test ifIndex subtree
	ifIndexEntries := data.GetSubtree("1.3.6.1.2.1.2.2.1.1")
	if len(ifIndexEntries) != 32 {
		t.Errorf("ifIndex entries = %d, want 32", len(ifIndexEntries))
	}

	// Test Mikrotik-specific OIDs (health)
	// mtxrHlCpuLoad = 1.3.6.1.4.1.14988.1.1.3.14
	cpuEntry := data.Get("1.3.6.1.4.1.14988.1.1.3.14.0")
	if cpuEntry != nil {
		t.Logf("mtxrHlCpuLoad: %v", cpuEntry.Value)
	} else {
		t.Log("mtxrHlCpuLoad: not present (may need .0 suffix or different index)")
	}

	// Test PoE subtree (CRS328-24P has PoE)
	poeEntries := data.GetSubtree("1.3.6.1.4.1.14988.1.1.15")
	t.Logf("Mikrotik PoE entries: %d", len(poeEntries))
}

func TestMockClientCisco(t *testing.T) {
	mock, err := NewMockClientFromFile("../../tests/snmprec/cisco/cisco2960_numeric.snmprec")
	if err != nil {
		t.Fatalf("failed to create mock client: %v", err)
	}

	// Test GET
	results, err := mock.Get("10.0.0.1", "public", Version2c, []string{
		".1.3.6.1.2.1.1.1.0", // sysDescr
		".1.3.6.1.2.1.1.5.0", // sysName
		".1.3.6.1.2.1.1.3.0", // sysUpTime
	})
	if err != nil {
		t.Fatalf("mock GET failed: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}

	sysDescr := results[0].AsString()
	if len(sysDescr) == 0 {
		t.Error("sysDescr is empty")
	}
	t.Logf("GET sysDescr: %.60s...", sysDescr)

	sysName := results[1].AsString()
	if sysName != "Gentrice-CiscoSW.cisco.gentrice.net" {
		t.Errorf("sysName = %q", sysName)
	}
	t.Logf("GET sysName: %s", sysName)

	// Test WALK on ifAdminStatus
	walkResults, err := mock.Walk("10.0.0.1", "public", Version2c, ".1.3.6.1.2.1.2.2.1.7")
	if err != nil {
		t.Fatalf("mock WALK ifAdminStatus failed: %v", err)
	}
	if len(walkResults) == 0 {
		t.Fatal("ifAdminStatus walk returned 0 results")
	}
	t.Logf("WALK ifAdminStatus: %d ports", len(walkResults))

	// Test WALK on ifOperStatus
	walkResults, err = mock.Walk("10.0.0.1", "public", Version2c, ".1.3.6.1.2.1.2.2.1.8")
	if err != nil {
		t.Fatalf("mock WALK ifOperStatus failed: %v", err)
	}
	t.Logf("WALK ifOperStatus: %d ports", len(walkResults))

	// Test GET for non-existent OID
	results, err = mock.Get("10.0.0.1", "public", Version2c, []string{".1.3.6.1.2.1.99.99.99"})
	if err != nil {
		t.Fatalf("mock GET for missing OID failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for missing OID, got %d", len(results))
	}
	if results[0].Value != nil {
		t.Errorf("expected nil value for missing OID, got %v", results[0].Value)
	}
	t.Log("GET missing OID: correctly returned NoSuchObject")

	// Test BulkWalk on PoE
	poeResults, err := mock.BulkWalk("10.0.0.1", "public", Version2c, ".1.3.6.1.2.1.105.1.1.1")
	if err != nil {
		t.Fatalf("mock BulkWalk PoE failed: %v", err)
	}
	t.Logf("BULKWALK PoE pethPsePort: %d entries", len(poeResults))

	// Test WALK on Cisco CPU (cpmCPUTotal5secRev)
	cpuResults, err := mock.Walk("10.0.0.1", "public", Version2c, ".1.3.6.1.4.1.9.9.109.1.1.1.1.6")
	if err != nil {
		t.Fatalf("mock WALK CPU failed: %v", err)
	}
	t.Logf("WALK Cisco CPU 5sec: %d entries", len(cpuResults))
	for _, r := range cpuResults {
		v, _ := r.AsInt()
		t.Logf("  %s = %d%%", r.OID, v)
	}

	// Test WALK on bridge FDB
	fdbResults, err := mock.Walk("10.0.0.1", "public", Version2c, ".1.3.6.1.2.1.17.4.3.1.1")
	if err != nil {
		t.Fatalf("mock WALK FDB failed: %v", err)
	}
	t.Logf("WALK dot1dTpFdbAddress: %d MAC entries", len(fdbResults))

	// Test WALK on Q-BRIDGE FDB
	qfdbResults, err := mock.Walk("10.0.0.1", "public", Version2c, ".1.3.6.1.2.1.17.7.1.2.2.1.2")
	if err != nil {
		t.Fatalf("mock WALK Q-BRIDGE FDB failed: %v", err)
	}
	t.Logf("WALK dot1qTpFdbPort: %d entries", len(qfdbResults))

	// Test WALK on VLAN names
	vlanResults, err := mock.Walk("10.0.0.1", "public", Version2c, ".1.3.6.1.4.1.9.9.46.1.3.1.1.4")
	if err != nil {
		t.Fatalf("mock WALK VLAN names failed: %v", err)
	}
	t.Logf("WALK vtpVlanName: %d VLANs", len(vlanResults))
	for _, r := range vlanResults {
		t.Logf("  %s = %s", r.OID, r.AsString())
	}
}

func TestMockClientMikrotik(t *testing.T) {
	mock, err := NewMockClientFromFile("../../tests/snmprec/mikrotik/mikrotik_numeric.snmprec")
	if err != nil {
		t.Fatalf("failed to create mock client: %v", err)
	}

	// Test GET system info
	results, err := mock.Get("10.0.0.1", "public", Version2c, []string{
		".1.3.6.1.2.1.1.1.0", // sysDescr
		".1.3.6.1.2.1.1.5.0", // sysName
		".1.3.6.1.2.1.2.1.0", // ifNumber
	})
	if err != nil {
		t.Fatalf("mock GET failed: %v", err)
	}

	sysDescr := results[0].AsString()
	if sysDescr != "RouterOS CRS328-24P-4S+" {
		t.Errorf("sysDescr = %q", sysDescr)
	}
	t.Logf("GET sysDescr: %s", sysDescr)

	sysName := results[1].AsString()
	t.Logf("GET sysName: %s", sysName)

	ifNum, _ := results[2].AsInt()
	if ifNum != 32 {
		t.Errorf("ifNumber = %d, want 32", ifNum)
	}
	t.Logf("GET ifNumber: %d", ifNum)

	// Test WALK on ifDescr
	walkResults, err := mock.Walk("10.0.0.1", "public", Version2c, ".1.3.6.1.2.1.2.2.1.2")
	if err != nil {
		t.Fatalf("mock WALK ifDescr failed: %v", err)
	}
	t.Logf("WALK ifDescr: %d interfaces", len(walkResults))
	for i, r := range walkResults {
		if i < 5 {
			t.Logf("  %s = %s", r.OID, r.AsString())
		}
	}

	// Test WALK on Mikrotik PoE
	poeResults, err := mock.Walk("10.0.0.1", "public", Version2c, ".1.3.6.1.4.1.14988.1.1.15")
	if err != nil {
		t.Fatalf("mock WALK Mikrotik PoE failed: %v", err)
	}
	t.Logf("WALK Mikrotik PoE: %d entries", len(poeResults))

	// Test WALK on Mikrotik health
	healthResults, err := mock.Walk("10.0.0.1", "public", Version2c, ".1.3.6.1.4.1.14988.1.1.3")
	if err != nil {
		t.Fatalf("mock WALK Mikrotik health failed: %v", err)
	}
	t.Logf("WALK Mikrotik health: %d entries", len(healthResults))
	for _, r := range healthResults {
		t.Logf("  %s = %v", r.OID, r.Value)
	}

	// Test WALK on bridge FDB
	fdbResults, err := mock.Walk("10.0.0.1", "public", Version2c, ".1.3.6.1.2.1.17.7.1.2.2.1.2")
	if err != nil {
		t.Fatalf("mock WALK Q-BRIDGE FDB failed: %v", err)
	}
	t.Logf("WALK dot1qTpFdbPort: %d entries", len(fdbResults))

	// Test WALK on ifAdminStatus + ifOperStatus
	adminResults, err := mock.Walk("10.0.0.1", "public", Version2c, ".1.3.6.1.2.1.2.2.1.7")
	if err != nil {
		t.Fatalf("mock WALK ifAdminStatus failed: %v", err)
	}
	operResults, err := mock.Walk("10.0.0.1", "public", Version2c, ".1.3.6.1.2.1.2.2.1.8")
	if err != nil {
		t.Fatalf("mock WALK ifOperStatus failed: %v", err)
	}
	t.Logf("WALK ifAdminStatus: %d, ifOperStatus: %d", len(adminResults), len(operResults))
}
