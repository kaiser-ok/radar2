package service

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"new_radar/internal/db"
	"new_radar/internal/snmp"
)

// setupTestDB creates an in-memory SQLite database with schema.
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite3", ":memory:?_foreign_keys=on")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	migration, err := os.ReadFile("../../migrations/001_initial.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := database.Exec(string(migration)); err != nil {
		t.Fatalf("run migration: %v", err)
	}
	return database
}

// seedTestData inserts a unit and a switch, returns (unitID, switchID).
func seedTestData(t *testing.T, database *sql.DB) (int64, int64) {
	t.Helper()
	res, err := database.Exec("INSERT INTO units (name) VALUES ('test-unit')")
	if err != nil {
		t.Fatalf("insert unit: %v", err)
	}
	unitID, _ := res.LastInsertId()

	res, err = database.Exec(
		"INSERT INTO switches (unit_id, ip, community, snmp_ver, access_method) VALUES (?, '10.0.0.1', 'public', '2c', 'snmp')",
		unitID,
	)
	if err != nil {
		t.Fatalf("insert switch: %v", err)
	}
	swID, _ := res.LastInsertId()
	return unitID, swID
}

func newTestMACService(t *testing.T, database *sql.DB, mockClient *snmp.MockClient) *MACService {
	t.Helper()
	oidRegistry, err := snmp.LoadOIDs("../../configs/oids.yaml")
	if err != nil {
		t.Fatalf("load OIDs: %v", err)
	}

	// We can't use MockClient directly since services use *snmp.Client.
	// For this test, we test the service logic by calling methods that
	// use the repos and testing the MAC normalization and DB flow.
	// Full SNMP integration tests require a real or injected client.

	switchRepo := db.NewSwitchRepo(database)
	macLocRepo := db.NewMACLocationRepo(database)
	blockedRepo := db.NewBlockedMACRepo(database)

	// Use nil snmpClient — we'll test DB-level logic and mock the FDB results
	fdbSvc := NewFDBService(nil, oidRegistry, nil)
	portSvc := NewPortService(nil, oidRegistry, nil)

	return NewMACService(nil, oidRegistry, fdbSvc, portSvc, macLocRepo, blockedRepo, switchRepo)
}

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"AA:BB:CC:DD:EE:FF", "aabbccddeeff"},
		{"aa-bb-cc-dd-ee-ff", "aabbccddeeff"},
		{"aabb.ccdd.eeff", "aabbccddeeff"},
		{"AABBCCDDEEFF", "aabbccddeeff"},
		{"aabbccddeeff", "aabbccddeeff"},
	}
	for _, tt := range tests {
		got := NormalizeMAC(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestLocateMAC_FromCache(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()
	unitID, swID := seedTestData(t, database)

	macSvc := newTestMACService(t, database, nil)

	// Pre-populate cache
	macLocRepo := db.NewMACLocationRepo(database)
	err := macLocRepo.Upsert(unitID, "aabbccddeeff", swID, 5)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Should find from cache
	result, err := macSvc.LocateMAC(unitID, "AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatalf("LocateMAC: %v", err)
	}
	if result.MAC != "aabbccddeeff" {
		t.Errorf("MAC = %q, want aabbccddeeff", result.MAC)
	}
	if result.SwitchID != swID {
		t.Errorf("SwitchID = %d, want %d", result.SwitchID, swID)
	}
	if result.Port != 5 {
		t.Errorf("Port = %d, want 5", result.Port)
	}
	if !result.Cached {
		t.Error("expected Cached=true")
	}
	if result.SwitchIP != "10.0.0.1" {
		t.Errorf("SwitchIP = %q, want 10.0.0.1", result.SwitchIP)
	}
	t.Logf("LocateMAC from cache: switch=%d port=%d ip=%s", result.SwitchID, result.Port, result.SwitchIP)
}

func TestBlockUnblockMAC(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()
	unitID, swID := seedTestData(t, database)

	macLocRepo := db.NewMACLocationRepo(database)
	blockedRepo := db.NewBlockedMACRepo(database)

	// Pre-populate MAC location so BlockMAC can find it
	_ = macLocRepo.Upsert(unitID, "001122334455", swID, 3)

	// Block — will fail on SetPortAdmin since snmpClient is nil,
	// so we test the DB layer directly
	err := blockedRepo.Block(unitID, "001122334455", &swID, intPtr(3))
	if err != nil {
		t.Fatalf("Block: %v", err)
	}

	// Verify blocked
	blocked, err := blockedRepo.Find(unitID, "001122334455")
	if err != nil {
		t.Fatalf("Find blocked: %v", err)
	}
	if blocked.MAC != "001122334455" {
		t.Errorf("blocked MAC = %q", blocked.MAC)
	}
	if *blocked.SwitchID != swID {
		t.Errorf("blocked SwitchID = %d, want %d", *blocked.SwitchID, swID)
	}
	if *blocked.Port != 3 {
		t.Errorf("blocked Port = %d, want 3", *blocked.Port)
	}
	t.Logf("Blocked MAC %s on switch %d port %d", blocked.MAC, *blocked.SwitchID, *blocked.Port)

	// List blocked
	list, err := blockedRepo.GetByUnit(unitID)
	if err != nil {
		t.Fatalf("GetByUnit: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("blocked count = %d, want 1", len(list))
	}

	// Unblock
	err = blockedRepo.Unblock(unitID, "001122334455")
	if err != nil {
		t.Fatalf("Unblock: %v", err)
	}

	// Verify unblocked
	list, _ = blockedRepo.GetByUnit(unitID)
	if len(list) != 0 {
		t.Errorf("blocked count after unblock = %d, want 0", len(list))
	}
	t.Log("Unblock: verified empty")
}

func TestRebuildTopology_EmptyUnit(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()

	// Create unit with no switches
	res, _ := database.Exec("INSERT INTO units (name) VALUES ('empty-unit')")
	unitID, _ := res.LastInsertId()

	macSvc := newTestMACService(t, database, nil)

	result, err := macSvc.RebuildTopology(unitID)
	if err != nil {
		t.Fatalf("RebuildTopology: %v", err)
	}
	if result.SwitchesScanned != 0 {
		t.Errorf("SwitchesScanned = %d, want 0", result.SwitchesScanned)
	}
	if result.MACsFound != 0 {
		t.Errorf("MACsFound = %d, want 0", result.MACsFound)
	}
	t.Logf("RebuildTopology empty unit: %+v", result)
}

func TestListBlocked_Empty(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()

	res, _ := database.Exec("INSERT INTO units (name) VALUES ('test')")
	unitID, _ := res.LastInsertId()

	macSvc := newTestMACService(t, database, nil)
	list, err := macSvc.ListBlocked(unitID)
	if err != nil {
		t.Fatalf("ListBlocked: %v", err)
	}
	if list != nil && len(list) != 0 {
		t.Errorf("expected empty list, got %d", len(list))
	}
}

func intPtr(v int) *int {
	return &v
}
