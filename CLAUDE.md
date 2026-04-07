# Radar v2 — Go SNMP/SSH Network Device Management System

## Project Overview

Radar v2 is a Go-based network switch management API that communicates with switches via SNMP (primary) and SSH/Telnet (fallback). It provides RESTful endpoints for port control, PoE management, MAC location, device discovery, FDB queries, and RSPAN packet capture. Designed to manage multi-vendor switch environments from a single probe.

## Tech Stack

- **Language:** Go 1.22
- **Router:** chi/v5
- **Database:** SQLite (embedded, WAL mode) via go-sqlite3
- **SNMP:** gosnmp
- **Config:** Viper (YAML-based, `configs/radar.yaml`)
- **Auth:** HTTP Basic Auth (admin/gentrice)
- **Build:** Makefile, `make build` outputs to `bin/radar`

## Architecture

```
HTTP Request → chi Router → Handler (thin) → Service (logic) → Device Executor → SNMP/SSH/DB
```

- **Handlers** (`internal/handler/`): Parse params, call service, return JSON. No business logic.
- **Services** (`internal/service/`): Business logic, profile-aware device operations.
- **SNMP client** (`internal/snmp/`): gosnmp wrapper with Get/Set/Walk/BulkWalk + OID registry from `configs/oids.yaml`.
- **Device profiles** (`profiles/`): 4-layer YAML system — fingerprints → capabilities → vendor mappings → model overrides.
- **MIB system** (`internal/mib/`): Pure Go MIB parser with SQLite cache.

## Directory Structure

```
cmd/radar/main.go        — Entry point, DI wiring, server startup
internal/
  auth/                  — Basic auth middleware
  config/                — Viper config + VendorRegistry (profile loading)
  db/                    — SQLite connection, migrations, repos (unit, switch, blocked_mac, mac_location)
  handler/               — HTTP handlers (10 files: system, switches, ports, poe, switch_info, tools, mib, snmp, discovery, onboarding)
  service/               — Business logic (port, poe, switch_info, fdb, discovery, exec, task)
  snmp/                  — SNMP client wrapper, OID registry, simulator
  mib/                   — MIB parser + store
  model/                 — Domain types (Unit, Switch, Task, PortInfo, FDB, etc.)
  device/                — Device executor (routes SNMP/SSH based on profile)
  sshcli/                — SSH/Telnet clients + CLI parsing (Phase 2b, planned)
  rspan/                 — RSPAN capture + analysis (Phase 7, planned)
  onboarding/            — Device onboarding workflow (case pipeline, walk analyzer)
configs/
  radar.yaml             — Server, auth, DB, SNMP, task, discovery, RSPAN settings
  oids.yaml              — OID registry (MIB-2, Bridge, Q-Bridge, PoE, CPU)
profiles/
  fingerprints/          — Layer 1: sysObjectID + sysDescr matching
  capabilities/          — Layer 2: Boolean capability matrix per vendor
  vendors/               — Layer 3: OID/CLI mappings with primary/fallback/verify
  overrides/             — Layer 4: Model-specific tweaks
migrations/              — SQLite schema (units, switches, blocked_macs, mac_locations, rspan_learned)
tests/
  snmprec/               — Mock SNMP recordings per vendor (.snmprec files)
  profiles/              — Acceptance test definitions (YAML)
mibs/                    — MIB file directories per vendor (placeholder)
```

## 4-Layer Device Profile System

1. **Fingerprints** (`profiles/fingerprints/`): Match device by sysObjectID prefix + sysDescr regex. Priority-ordered.
2. **Capabilities** (`profiles/capabilities/`): Boolean matrix of what the device can do (port.admin.write, poe.status.read, etc.).
3. **Vendor mappings** (`profiles/vendors/`): OID paths and SSH CLI commands per capability, with primary → fallback → verify chain.
4. **Overrides** (`profiles/overrides/`): Model-specific tweaks that extend the base vendor profile.

Detection flow: `sysDescr` → fingerprint match → load capability + vendor profile → apply override if exists.

## Supported Vendors

D-Link, Cisco, HP/Aruba, Zyxel, Mikrotik. Each has fingerprint, capability, and vendor profile YAML files.

## API

All endpoints under `/api/v2/`, JSON request/response. Server runs on port 8082.

Key endpoint groups: System, Switches CRUD, Port Operations, PoE, Switch Info, Tools (async ping/traceroute/arping/DAD), SNMP test/query, Discovery, FDB, MIB management, Onboarding.

Full API design is in `plan.md`. Legacy API reference in `radar_API.md`. Skills tool status in `radar_tool_list.md`.

## Database

SQLite with 5 core tables: `units`, `switches`, `blocked_macs`, `mac_locations`, `rspan_learned`. Schema in `migrations/001_initial.sql`.

## Build & Run

```bash
make build    # Compile to bin/radar
make run      # Build + run
make test     # Run all tests
make clean    # Remove bin/, radar.db, captures/
make deps     # go mod tidy
```

## Development Status (9 Phases)

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Skeleton & Foundation (config, auth, SQLite, switch CRUD) | Done |
| 2 | SNMP Core + Port Operations (client, OID registry, port control) | Done |
| 2b | SSH/Telnet Support (CLI parser, fallback methods, reboot, FDB) | Pending |
| 3 | Async Task System (ping, traceroute, arping, DAD check) | Done |
| 4 | PoE + Switch Info (PoE control, CPU, stats, VLANs) | Done |
| 5 | SNMP + Discovery + Topology (test/query, worker pool, FDB) | Done |
| 6 | MAC Location + Isolation (bridge walks, MAC cache, block/unblock) | Pending |
| 7 | RSPAN (session config, packet capture on 2nd NIC, MAC/IP learning) | Pending |
| 8 | Hardening (validation, logging, tests, graceful shutdown) | Pending |

## Conventions

- Thin handlers, rich services. Handlers only parse + respond; logic lives in services.
- All vendor-specific behavior is in YAML profiles, not hardcoded in Go.
- Async operations (ping, traceroute, arping, DAD) use in-memory TaskStore with UUID-based polling.
- SNMP simulator + snmprec files for unit testing without real devices.
- Config via `configs/radar.yaml` with env var overrides (Viper).
