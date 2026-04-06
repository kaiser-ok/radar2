# Radar v2 Development Daily Log

## 2026-04-06 — Day 1: Foundation + Core Features

### Completed

**Phase 1: Skeleton & Foundation**
- Go project initialized (chi router, SQLite, Viper config)
- HTTP Basic Auth middleware
- SQLite schema: units, switches, blocked_macs, mac_locations, rspan_learned
- DB repos for all entities
- Endpoints: `/api/v2/version`, `/interfaces`, switch CRUD (5 endpoints)

**Phase 2: SNMP Core + Port Operations**
- gosnmp wrapper: Get, Set, Walk, BulkWalk with typed result helpers
- OID registry from `configs/oids.yaml`
- Port service: status, admin control, descriptions
- Endpoints: 4 port endpoints

**4-Layer Device Profile System**
- Layer 1: Fingerprints (sysObjectID + sysDescr matching with priority)
- Layer 2: Capability matrices (boolean per device)
- Layer 3: Vendor profiles (OID/CLI mappings with primary → fallback → verify)
- Layer 4: Model-specific overrides (extends base)
- Profiles created for 5 vendors: Cisco, D-Link, HP/Aruba, Zyxel, Mikrotik
- Override examples: Cisco C2960 (PoE), D-Link DGS-1510 (PoE)
- Go ProfileRegistry with DetectDevice(), HasCapability(), GetMapping()

**MIB Parser & Management**
- Pure Go MIB parser: parses .mib files, resolves OID tree
- MIB store with SQLite cache
- API: upload, lookup, resolve, search (6 endpoints)

**snmprec Test Infrastructure**
- snmprec file parser and MockClient for unit testing
- Sample Cisco C2960 snmprec file
- Directory structure for 5 vendors

**Switch Onboarding System**
- Full SOP document (onboarding.md): 7 stages, tiers A/B/C
- Walk analyzer: auto-detects capabilities with confidence scores
- Onboarding service: case pipeline (intake → evidence → analyze → draft → approve)
- Auto-generates capability matrix + vendor profile drafts from walk files
- Auto-converts walks to snmprec format
- API: 8 onboarding endpoints

**Phase 3: Async Task System**
- In-memory TaskStore with UUID, RWMutex, background cleanup
- ExecService: ping, traceroute, arping, DAD check with context timeout
- API: 5 tool endpoints (4 tools + task polling)

**Phase 4: PoE + Switch Info**
- PoE: support check, per-port power report, enable/disable
- Switch info: CPU (vendor-aware chain), traffic stats, VLANs
- API: 6 endpoints

**Phase 5: SNMP Test + Discovery + FDB** (in progress)
- SNMP test and query endpoints
- Subnet discovery with concurrent worker pool + auto vendor detection
- FDB table query (Q-BRIDGE + bridge MIB fallback)
- Switch reboot placeholder
- API: 5 endpoints

### Attempted
- Mikrotik switch at 192.168.0.254: ping OK, SNMP timeout — needs SNMP enabled on device

### Stats
- **Total endpoints implemented**: ~44
- **Total Go files**: ~30
- **Total lines of code**: ~5,000+
- **Phases completed**: 5 of 9
- **Git commits**: 6

### Tomorrow (Day 2) Priorities
1. Enable SNMP on Mikrotik switch and test onboarding workflow
2. Phase 6: MAC Location + Isolation
3. Phase 2b: SSH/Telnet Support
4. Phase 7: RSPAN (if time permits)
5. Phase 8: Hardening

### Open Questions
- Mikrotik 192.168.0.254: need to enable SNMP and confirm community string
- RSPAN: which switches support it? Need to test 2nd NIC configuration
- SSH: need test credentials for at least one switch to validate CLI parser
