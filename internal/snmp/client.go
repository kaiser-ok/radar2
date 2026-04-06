package snmp

import (
	"fmt"
	"time"

	"github.com/gosnmp/gosnmp"
)

type SnmpVersion int

const (
	Version1  SnmpVersion = 1
	Version2c SnmpVersion = 2
)

func ParseVersion(s string) SnmpVersion {
	switch s {
	case "1":
		return Version1
	default:
		return Version2c
	}
}

type Result struct {
	OID   string
	Type  gosnmp.Asn1BER
	Value interface{}
}

// Client wraps gosnmp for SNMP operations.
type Client struct {
	Timeout    time.Duration
	Retries    int
	MaxOIDsReq int
}

func NewClient(timeout time.Duration, retries, maxOIDs int) *Client {
	return &Client{
		Timeout:    timeout,
		Retries:    retries,
		MaxOIDsReq: maxOIDs,
	}
}

func (c *Client) newSession(target, community string, version SnmpVersion) *gosnmp.GoSNMP {
	ver := gosnmp.Version2c
	if version == Version1 {
		ver = gosnmp.Version1
	}
	return &gosnmp.GoSNMP{
		Target:    target,
		Port:      161,
		Community: community,
		Version:   ver,
		Timeout:   c.Timeout,
		Retries:   c.Retries,
	}
}

// Get performs SNMP GET for one or more OIDs.
func (c *Client) Get(target, community string, version SnmpVersion, oids []string) ([]Result, error) {
	s := c.newSession(target, community, version)
	if err := s.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect %s: %w", target, err)
	}
	defer s.Conn.Close()

	pkt, err := s.Get(oids)
	if err != nil {
		return nil, fmt.Errorf("snmp get %s: %w", target, err)
	}

	return pduToResults(pkt.Variables), nil
}

// Set performs SNMP SET on a single OID.
func (c *Client) Set(target, community string, version SnmpVersion, oid string, valType gosnmp.Asn1BER, value interface{}) error {
	s := c.newSession(target, community, version)
	if err := s.Connect(); err != nil {
		return fmt.Errorf("snmp connect %s: %w", target, err)
	}
	defer s.Conn.Close()

	pdu := gosnmp.SnmpPDU{
		Name:  oid,
		Type:  valType,
		Value: value,
	}
	_, err := s.Set([]gosnmp.SnmpPDU{pdu})
	if err != nil {
		return fmt.Errorf("snmp set %s %s: %w", target, oid, err)
	}
	return nil
}

// Walk performs SNMP WALK (GETNEXT) on a root OID.
func (c *Client) Walk(target, community string, version SnmpVersion, rootOID string) ([]Result, error) {
	s := c.newSession(target, community, version)
	if err := s.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect %s: %w", target, err)
	}
	defer s.Conn.Close()

	var results []Result
	err := s.Walk(rootOID, func(pdu gosnmp.SnmpPDU) error {
		results = append(results, Result{
			OID:   pdu.Name,
			Type:  pdu.Type,
			Value: pdu.Value,
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("snmp walk %s %s: %w", target, rootOID, err)
	}
	return results, nil
}

// BulkWalk performs SNMP BULKWALK (v2c only, uses GETBULK).
func (c *Client) BulkWalk(target, community string, version SnmpVersion, rootOID string) ([]Result, error) {
	s := c.newSession(target, community, version)
	if err := s.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect %s: %w", target, err)
	}
	defer s.Conn.Close()

	var results []Result
	err := s.BulkWalk(rootOID, func(pdu gosnmp.SnmpPDU) error {
		results = append(results, Result{
			OID:   pdu.Name,
			Type:  pdu.Type,
			Value: pdu.Value,
		})
		return nil
	})
	if err != nil {
		// Fall back to regular Walk for v1 or devices that don't support GETBULK
		return c.Walk(target, community, version, rootOID)
	}
	return results, nil
}

func pduToResults(pdus []gosnmp.SnmpPDU) []Result {
	results := make([]Result, len(pdus))
	for i, pdu := range pdus {
		results[i] = Result{
			OID:   pdu.Name,
			Type:  pdu.Type,
			Value: pdu.Value,
		}
	}
	return results
}

// helpers to extract typed values from Result

func (r Result) AsInt() (int, bool) {
	switch v := r.Value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case uint:
		return int(v), true
	case uint64:
		return int(v), true
	default:
		return 0, false
	}
}

func (r Result) AsString() string {
	switch v := r.Value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func (r Result) AsBytes() []byte {
	switch v := r.Value.(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	default:
		return nil
	}
}
