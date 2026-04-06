package snmp

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// SnmprecEntry represents one line from a .snmprec file.
type SnmprecEntry struct {
	OID   string
	Type  byte
	Value interface{}
}

// SnmprecData holds parsed snmprec data, sorted by OID for walk operations.
type SnmprecData struct {
	entries []SnmprecEntry
	index   map[string]int
}

// LoadSnmprec parses a .snmprec file into an in-memory dataset.
func LoadSnmprec(path string) (*SnmprecData, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data := &SnmprecData{
		index: make(map[string]int),
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entry, err := parseSnmprecLine(line)
		if err != nil {
			continue
		}

		data.entries = append(data.entries, entry)
	}

	// Sort by OID for walk support
	sort.Slice(data.entries, func(i, j int) bool {
		return compareOIDs(data.entries[i].OID, data.entries[j].OID) < 0
	})
	for i, e := range data.entries {
		data.index[e.OID] = i
	}

	return data, scanner.Err()
}

// Get returns the entry for an exact OID match.
func (d *SnmprecData) Get(oid string) *SnmprecEntry {
	oid = normalizeOID(oid)
	if idx, ok := d.index[oid]; ok {
		return &d.entries[idx]
	}
	return nil
}

// GetNext returns the next OID after the given one.
func (d *SnmprecData) GetNext(oid string) *SnmprecEntry {
	oid = normalizeOID(oid)
	for i, e := range d.entries {
		if compareOIDs(e.OID, oid) > 0 {
			return &d.entries[i]
		}
	}
	return nil
}

// GetSubtree returns all entries under a given OID prefix.
func (d *SnmprecData) GetSubtree(rootOID string) []SnmprecEntry {
	rootOID = normalizeOID(rootOID)
	prefix := rootOID + "."
	var results []SnmprecEntry
	for _, e := range d.entries {
		if strings.HasPrefix(e.OID, prefix) || e.OID == rootOID {
			results = append(results, e)
		}
	}
	return results
}

// Count returns total number of entries.
func (d *SnmprecData) Count() int {
	return len(d.entries)
}

// --- MockClient: a Client-compatible mock that reads from snmprec data ---

// MockClient implements the same operations as Client but reads from snmprec data.
// Use this in tests instead of hitting real SNMP devices.
type MockClient struct {
	data *SnmprecData
}

// NewMockClient creates a mock SNMP client from snmprec data.
func NewMockClient(data *SnmprecData) *MockClient {
	return &MockClient{data: data}
}

// NewMockClientFromFile creates a mock SNMP client from a .snmprec file.
func NewMockClientFromFile(path string) (*MockClient, error) {
	data, err := LoadSnmprec(path)
	if err != nil {
		return nil, err
	}
	return NewMockClient(data), nil
}

// Get performs a mock SNMP GET from snmprec data.
func (m *MockClient) Get(target, community string, version SnmpVersion, oids []string) ([]Result, error) {
	var results []Result
	for _, oid := range oids {
		entry := m.data.Get(normalizeOID(oid))
		if entry == nil {
			results = append(results, Result{
				OID:   oid,
				Type:  gosnmp.NoSuchObject,
				Value: nil,
			})
			continue
		}
		results = append(results, entryToResult(entry))
	}
	return results, nil
}

// Set is a no-op for mock (records nothing, always succeeds).
func (m *MockClient) Set(target, community string, version SnmpVersion, oid string, valType gosnmp.Asn1BER, value interface{}) error {
	return nil
}

// Walk performs a mock SNMP WALK from snmprec data.
func (m *MockClient) Walk(target, community string, version SnmpVersion, rootOID string) ([]Result, error) {
	entries := m.data.GetSubtree(rootOID)
	var results []Result
	for _, e := range entries {
		results = append(results, entryToResult(&e))
	}
	return results, nil
}

// BulkWalk is the same as Walk for mock.
func (m *MockClient) BulkWalk(target, community string, version SnmpVersion, rootOID string) ([]Result, error) {
	return m.Walk(target, community, version, rootOID)
}

func entryToResult(e *SnmprecEntry) Result {
	r := Result{
		OID:   "." + e.OID,
		Value: e.Value,
	}

	switch e.Type {
	case 2:
		r.Type = gosnmp.Integer
	case 4:
		r.Type = gosnmp.OctetString
	case 6:
		r.Type = gosnmp.ObjectIdentifier
	case 41:
		r.Type = gosnmp.Counter32
	case 42:
		r.Type = gosnmp.Gauge32
	case 43:
		r.Type = gosnmp.TimeTicks
	case 46:
		r.Type = gosnmp.Counter64
	case 64:
		r.Type = gosnmp.IPAddress
	default:
		r.Type = gosnmp.OctetString
	}

	return r
}

// --- parsing helpers ---

func parseSnmprecLine(line string) (SnmprecEntry, error) {
	parts := strings.SplitN(line, "|", 3)
	if len(parts) != 3 {
		return SnmprecEntry{}, fmt.Errorf("invalid snmprec line: %s", line)
	}

	oid := normalizeOID(parts[0])
	typeStr := parts[1]
	valueStr := parts[2]

	// Handle hex-encoded type like "4x"
	isHex := strings.HasSuffix(typeStr, "x")
	if isHex {
		typeStr = strings.TrimSuffix(typeStr, "x")
	}

	typeCode, err := strconv.Atoi(typeStr)
	if err != nil {
		return SnmprecEntry{}, fmt.Errorf("invalid type: %s", parts[1])
	}

	if isHex {
		decoded, _ := hex.DecodeString(valueStr)
		return SnmprecEntry{OID: oid, Type: byte(typeCode), Value: decoded}, nil
	}

	entry := SnmprecEntry{OID: oid, Type: byte(typeCode)}

	switch typeCode {
	case 2: // Integer
		v, _ := strconv.Atoi(valueStr)
		entry.Value = v
	case 4: // OctetString
		entry.Value = []byte(valueStr)
	case 5: // Null
		entry.Value = nil
	case 6: // ObjectIdentifier
		entry.Value = valueStr
	case 41, 42: // Counter32, Gauge32
		v, _ := strconv.ParseUint(valueStr, 10, 32)
		entry.Value = uint(v)
	case 43: // TimeTicks
		v, _ := strconv.ParseUint(valueStr, 10, 32)
		entry.Value = uint32(v)
	case 46: // Counter64
		v, _ := strconv.ParseUint(valueStr, 10, 64)
		entry.Value = uint64(v)
	case 64: // IpAddress
		entry.Value = valueStr
	default:
		entry.Value = []byte(valueStr)
	}

	return entry, nil
}

func normalizeOID(oid string) string {
	oid = strings.TrimSpace(oid)
	if strings.HasPrefix(oid, ".") {
		oid = oid[1:]
	}
	return oid
}

func compareOIDs(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")

	maxLen := len(partsA)
	if len(partsB) > maxLen {
		maxLen = len(partsB)
	}

	for i := 0; i < maxLen; i++ {
		var na, nb int
		if i < len(partsA) {
			na, _ = strconv.Atoi(partsA[i])
		}
		if i < len(partsB) {
			nb, _ = strconv.Atoi(partsB[i])
		}
		if na < nb {
			return -1
		}
		if na > nb {
			return 1
		}
	}

	return len(partsA) - len(partsB)
}
