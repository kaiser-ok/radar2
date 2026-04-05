# New Radar v2 — Go SNMP/SSH Device Management System

## Context

Building a **v2 API from scratch** — clean RESTful design, no legacy `beverage_go/api?args=` patterns. The system manages SNMP-enabled network switches with SSH/Telnet fallback for devices with poor SNMP support. Includes RSPAN packet capture on a dedicated 2nd NIC.

- **Language:** Go
- **DB:** SQLite (embedded)
- **MIB:** Hybrid — pre-compiled OID map (YAML) + runtime MIB loading for ad-hoc queries
- **Device access:** Per-device config in DB (`snmp`, `ssh`, or `telnet`)
- **RSPAN:** Configure mirror sessions + capture/analyze traffic on 2nd NIC

---

## v2 API Design

All endpoints under `/api/v2/`, JSON request/response, proper HTTP methods.

### System
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v2/version` | Server version & build info |
| GET | `/api/v2/interfaces` | Server network interfaces |

### Switches (CRUD)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v2/units/{unitId}/switches` | List switches in a unit |
| GET | `/api/v2/switches/{swId}` | Get switch details |
| POST | `/api/v2/units/{unitId}/switches` | Add a switch |
| PUT | `/api/v2/switches/{swId}` | Update switch config |
| DELETE | `/api/v2/switches/{swId}` | Remove a switch |

### Port Operations
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v2/switches/{swId}/ports` | All ports status (link + admin) |
| GET | `/api/v2/switches/{swId}/ports/{port}` | Single port status |
| PUT | `/api/v2/switches/{swId}/ports/{port}/admin` | Enable/disable port (body: `{enabled: bool}`) |
| PUT | `/api/v2/switches/{swId}/ports/{port}/speed` | Set port speed/duplex (body: `{speed, duplex}`) |
| GET | `/api/v2/switches/{swId}/ports/descriptions` | All port descriptions |

### PoE
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v2/switches/{swId}/poe` | PoE support check |
| GET | `/api/v2/switches/{swId}/poe/report` | PoE power report (per-port watts) |
| PUT | `/api/v2/switches/{swId}/poe/{port}` | Enable/disable PoE (body: `{enabled: bool}`) |

### Switch Info
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v2/switches/{swId}/cpu` | CPU utilization |
| GET | `/api/v2/switches/{swId}/stats` | Per-port traffic statistics |
| GET | `/api/v2/switches/{swId}/vlans` | VLAN configuration |
| GET | `/api/v2/switches/{swId}/fdb` | FDB (forwarding database) table |
| DELETE | `/api/v2/switches/{swId}/fdb` | Clear FDB tables (body: `{tables}`) |
| POST | `/api/v2/switches/{swId}/reboot` | Reboot switch |

### Network Tools (Async)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v2/tools/ping` | Async ping (body: `{host, count, unit_id}`) → returns `{task_id}` |
| POST | `/api/v2/tools/traceroute` | Async traceroute (body: `{host, max_hops, unit_id}`) |
| POST | `/api/v2/tools/arping` | Async ARP ping (body: `{host, unit_id}`) |
| POST | `/api/v2/tools/dad-check` | Duplicate Address Detection (body: `{ip, unit_id}`) |
| GET | `/api/v2/tools/tasks/{taskId}` | Poll task result |

### MAC / IP Lookup
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v2/units/{unitId}/mac/{mac}/location` | Locate MAC on switch/port |
| POST | `/api/v2/units/{unitId}/mac/refresh` | Refresh all MAC locations |
| GET | `/api/v2/units/{unitId}/ip/{ip}/resolve` | IP → MAC (ARP cache) |

### MAC Isolation
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v2/units/{unitId}/isolation` | List blocked MACs |
| POST | `/api/v2/units/{unitId}/isolation` | Block MAC (body: `{mac}`) |
| DELETE | `/api/v2/units/{unitId}/isolation/{mac}` | Unblock MAC |

### SNMP
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v2/snmp/test` | Test SNMP connectivity (body: `{ip, community, snmp_ver}`) |
| POST | `/api/v2/snmp/query` | Query specific OID (body: `{ip, community, snmp_ver, oid}`) |
| POST | `/api/v2/snmp/discovery` | Discover devices on subnet (body: `{subnet, community, type}`) |

### Topology
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v2/units/{unitId}/topology/rebuild` | Trigger topology rebuild |
| GET | `/api/v2/units/{unitId}/ports` | Consolidated port info + PoE for all switches |

### RSPAN
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v2/rspan/sessions/{swId}` | Get RSPAN session config |
| POST | `/api/v2/rspan/sessions` | Configure RSPAN session |
| DELETE | `/api/v2/rspan/sessions/{swId}` | Remove RSPAN session |
| POST | `/api/v2/rspan/capture/start` | Start packet capture on 2nd NIC |
| POST | `/api/v2/rspan/capture/stop` | Stop packet capture |
| GET | `/api/v2/rspan/capture/status` | Capture status (running, pkt count, duration) |
| GET | `/api/v2/rspan/capture/{captureId}/download` | Download pcap file |
| GET | `/api/v2/rspan/stats` | Real-time traffic stats (top talkers, protocols) |
| GET | `/api/v2/rspan/learned` | Passively learned MAC/IP pairs |

**Total: ~45 endpoints**

---

## Project Structure

```
new_radar/
├── cmd/radar/main.go                # Entry point, DI wiring
├── internal/
│   ├── config/config.go             # Viper-based YAML + env config
│   ├── auth/basic.go                # HTTP Basic Auth middleware
│   ├── handler/
│   │   ├── handler.go               # Common JSON response helpers
│   │   ├── system.go                # /version, /interfaces
│   │   ├── switches.go              # Switch CRUD
│   │   ├── ports.go                 # Port status, control, speed, descriptions
│   │   ├── poe.go                   # PoE endpoints
│   │   ├── switch_info.go           # CPU, stats, VLANs, FDB, reboot
│   │   ├── tools.go                 # Ping, traceroute, arping, dad_check, task polling
│   │   ├── mac.go                   # MAC location, IP resolve
│   │   ├── isolation.go             # MAC isolation
│   │   ├── snmp.go                  # SNMP test, query, discovery
│   │   ├── topology.go              # Topology rebuild, consolidated port info
│   │   └── rspan.go                 # RSPAN session, capture, stats, learned
│   ├── service/
│   │   ├── port.go                  # Port control, status, description, speed
│   │   ├── poe.go                   # PoE control, report, support
│   │   ├── switch_info.go           # CPU, traffic stats, VLAN, reboot
│   │   ├── fdb.go                   # FDB table query, clear
│   │   ├── topology.go              # Topology rebuild
│   │   ├── location.go              # MAC location, IP-MAC resolution
│   │   ├── isolator.go              # MAC blocking/unblocking
│   │   ├── discovery.go             # Subnet SNMP scanning
│   │   ├── exec.go                  # Ping/traceroute/arping/dad_check
│   │   ├── task.go                  # In-memory async task store
│   │   └── rspan.go                 # RSPAN session config + capture orchestration
│   ├── snmp/
│   │   ├── client.go                # gosnmp wrapper (Get/Set/Walk/BulkWalk)
│   │   ├── oids.go                  # OID registry from YAML
│   │   └── session.go               # Session factory
│   ├── sshcli/
│   │   ├── client.go                # SSH client (golang.org/x/crypto/ssh)
│   │   ├── telnet.go                # Telnet client
│   │   └── parser.go                # CLI output parsers per vendor
│   ├── device/
│   │   └── executor.go              # Routes operations to SNMP or SSH/Telnet
│   ├── rspan/
│   │   ├── capture.go               # Packet capture on 2nd NIC (gopacket/libpcap)
│   │   ├── analyzer.go              # MAC/IP learning, traffic stats
│   │   └── pcap.go                  # Pcap file export
│   ├── db/
│   │   ├── db.go                    # SQLite connection + migrations
│   │   ├── unit.go                  # Unit CRUD
│   │   ├── switch_repo.go           # Switch CRUD
│   │   ├── blocked_mac.go           # Blocked MAC CRUD
│   │   └── mac_location.go          # MAC location cache
│   └── model/model.go               # Shared domain types
├── configs/
│   ├── radar.yaml                   # Server, auth, DB, SNMP, RSPAN settings
│   └── oids.yaml                    # OID map (MIB-2, PoE, vendor-specific)
├── migrations/001_initial.sql
├── go.mod
└── Makefile
```

## Key Libraries

| Purpose | Library |
|---------|---------|
| HTTP Router | `github.com/go-chi/chi/v5` |
| SNMP | `github.com/gosnmp/gosnmp` |
| SQLite | `github.com/mattn/go-sqlite3` |
| Config | `github.com/spf13/viper` |
| Logging | `log/slog` (stdlib) |
| Task IDs | `github.com/google/uuid` |
| SSH | `golang.org/x/crypto/ssh` |
| Telnet | `github.com/ziutek/telnet` |
| Packet Capture | `github.com/google/gopacket` + `libpcap` |

## Architecture

```
HTTP Request → chi Router (BasicAuth middleware)
  → /api/v2/* handlers (parse params, validate, return JSON)
    → Services (business logic, orchestration)
      → Device Executor (routes to SNMP or SSH/Telnet based on per-device config)
        → SNMP Client (gosnmp)
        → SSH/Telnet Client (x/crypto/ssh)
        → DB (SQLite)
        → OS exec (ping/traceroute/arping)
        → RSPAN capture engine (gopacket)
```

- **Handlers** are thin: parse URL params + JSON body, call service, return JSON
- **Services** contain business logic, never import `net/http`
- **Device Executor** checks `switch.access_method` in DB to route to SNMP or SSH/Telnet
- **SNMP Client** is an interface for mock-based testing

## SNMP Design

- **OID Registry** (`configs/oids.yaml`): MIB-2, PoE (RFC 3621), VLAN (Q-BRIDGE), vendor-specific
- **SNMP Client interface**: `Get()`, `Set()`, `Walk()`, `BulkWalk()` — short-lived UDP connections
- **Multi-vendor**: `sysDescr` fingerprinting, stored per switch. Standard OIDs first, vendor fallback

## SSH/Telnet Support

For devices with poor SNMP support (reboot, FDB, port speed, clear FDB, topology rebuild):
- **Device Executor** routes to SSH/Telnet based on `switches.access_method`
- **SSH Client**: `golang.org/x/crypto/ssh`, sends CLI commands, reads output with timeout
- **CLI Parser**: vendor-aware text parsers (Cisco IOS, D-Link, etc.), selected by `switches.vendor`
- **DB fields**: `access_method`, `ssh_user`, `ssh_password`, `ssh_port`

## Async Task System

- In-memory `map[string]*Task` with `sync.RWMutex`
- POST creates task (UUID), spawns goroutine with `exec.CommandContext`
- GET polls by task_id → `{ status: "running"|"finish", output }`
- Supports: `ping`, `traceroute`, `arping`, `dad_check`
- Background cleanup: evict tasks > 30 min every 5 min

## RSPAN

- **Session config**: configure RSPAN on switches via SNMP/SSH (source ports, RSPAN VLAN)
- **Capture engine**: gopacket/libpcap on 2nd NIC, long-lived goroutine, start/stop via API
- **Analyzer**: passive MAC/IP learning + real-time stats (top talkers, protocols, bandwidth)
- **Pcap export**: rotating pcap files, downloadable via API, auto-cleanup

## SQLite Schema

```sql
CREATE TABLE units (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    radar_ip    TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE switches (
    id            INTEGER PRIMARY KEY,
    unit_id       INTEGER NOT NULL REFERENCES units(id),
    name          TEXT,
    ip            TEXT NOT NULL,
    community     TEXT NOT NULL DEFAULT 'public',
    snmp_ver      TEXT NOT NULL DEFAULT '2c',
    vendor        TEXT,
    model         TEXT,
    port_count    INTEGER,
    poe_capable   BOOLEAN DEFAULT 0,
    access_method TEXT DEFAULT 'snmp',  -- snmp, ssh, telnet
    ssh_user      TEXT,
    ssh_password  TEXT,
    ssh_port      INTEGER DEFAULT 22,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE blocked_macs (
    id         INTEGER PRIMARY KEY,
    unit_id    INTEGER NOT NULL REFERENCES units(id),
    mac        TEXT NOT NULL,
    switch_id  INTEGER REFERENCES switches(id),
    port       INTEGER,
    blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(unit_id, mac)
);

CREATE TABLE mac_locations (
    id         INTEGER PRIMARY KEY,
    unit_id    INTEGER NOT NULL REFERENCES units(id),
    mac        TEXT NOT NULL,
    switch_id  INTEGER NOT NULL REFERENCES switches(id),
    port       INTEGER NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(unit_id, mac)
);

CREATE TABLE rspan_learned (
    id         INTEGER PRIMARY KEY,
    unit_id    INTEGER NOT NULL,
    mac        TEXT NOT NULL,
    ip         TEXT,
    vlan       INTEGER,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(unit_id, mac)
);
```

## Implementation Phases

### Phase 1: Skeleton & Foundation
- `go.mod`, `main.go`, config, auth middleware, SQLite setup, migrations
- Endpoints: `GET /api/v2/version`, `GET /api/v2/interfaces`
- Switch CRUD: `GET/POST/PUT/DELETE /api/v2/switches/*`
- Validates: project compiles, routing, auth, DB

### Phase 2: SNMP Core + Port Operations
- SNMP client wrapper, OID registry, session factory
- Device executor (SNMP path first)
- Endpoints: ports status, admin control, descriptions
- Validates: SNMP GET/SET against real switches

### Phase 2b: SSH/Telnet Support
- SSH client, Telnet client, CLI parser
- Extend device executor with SSH/Telnet path
- Endpoints: set port speed, reboot, FDB query, clear FDB
- Validates: SSH into test switch, parse CLI output

### Phase 3: Async Task System
- Task store, exec service
- Endpoints: ping, traceroute, arping, dad_check, task polling
- Validates: goroutine management, all 4 tool types

### Phase 4: PoE + Switch Info
- PoE service, switch info service
- Endpoints: PoE control/report, CPU, stats, VLANs

### Phase 5: SNMP + Discovery + Topology
- SNMP test/query, discovery with worker pool, topology rebuild
- Consolidated port info endpoint

### Phase 6: MAC Location + Isolation
- Bridge MIB walks, MAC location cache, IP-MAC resolution
- MAC isolation (block/unblock)

### Phase 7: RSPAN
- RSPAN session config on switches
- Packet capture engine on 2nd NIC
- MAC/IP learning, pcap export, live stats

### Phase 8: Hardening
- Validation, timeouts, structured logging
- Unit tests, integration tests
- Graceful shutdown, Makefile, build-time version

## Verification

1. **Build**: `go build ./cmd/radar/` succeeds
2. **Start**: server on :8082, `GET /api/v2/version` returns JSON with auth
3. **Switch CRUD**: create/list/update/delete switches via REST
4. **SNMP**: `POST /api/v2/snmp/test` with real switch IP
5. **Port**: `GET /api/v2/switches/{id}/ports` returns port states
6. **Ping**: `POST /api/v2/tools/ping` → poll task → get output
7. **SSH**: set port speed via SSH on a device with `access_method: ssh`
8. **RSPAN**: start capture, download pcap, view learned MACs
