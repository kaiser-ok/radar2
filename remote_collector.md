# Remote Collector — Offline SNMP Evidence Collection

## Problem

When onboarding a new switch at a remote client site, the Radar server may not be reachable. The collector is a standalone binary you carry on a USB drive or laptop, run against the switch locally, and bring the collected data back for import.

## Quick Start

```bash
# Build for Linux
make collector

# Build for Windows (take to client site)
make collector-windows

# Run at remote site
./collector -ip 192.168.1.1 -community public

# With vendor MIB files (recommended)
./collector -ip 192.168.1.1 -community public -mibs ./vendor_mibs/

# SNMPv1 device
./collector -ip 192.168.1.1 -community public -version 1

# Custom output directory
./collector -ip 192.168.1.1 -community secret -output ./customer_switch_A
```

## Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-ip` | (required) | Switch IP address |
| `-community` | `public` | SNMP community string |
| `-version` | `2c` | SNMP version: `1` or `2c` |
| `-output` | `collect_{ip}` | Output directory path |
| `-mibs` | (none) | Directory with vendor MIB files to bundle |
| `-deep` | `true` | Deep collection mode (Cisco per-VLAN, capability probing, vendor-specific walks) |
| `-timeout` | `10s` | SNMP timeout per request |
| `-retries` | `1` | SNMP retry count |

## What It Collects

### Standard Walks (always)

| Walk | OID Root | Content |
|------|----------|---------|
| `{vendor}_standard.walk` | `.1.3.6.1.2.1` | MIB-2: system info, interfaces, port status, traffic counters |
| `{vendor}_bridge.walk` | `.1.3.6.1.2.1.17` | Bridge MIB: MAC forwarding table (dot1dTpFdb), STP |
| `{vendor}_qbridge.walk` | `.1.3.6.1.2.1.17.7` | Q-BRIDGE MIB: 802.1Q VLANs, per-VLAN FDB |
| `{vendor}_poe.walk` | `.1.3.6.1.2.1.105` | PoE MIB: pethPsePort, pethMainPse (skipped if no PoE) |
| `{vendor}_vendor.walk` | `.1.3.6.1.4.1.{enterprise}` | Vendor enterprise MIB tree |

### Deep Mode (default on)

#### Capability Probing

Tests 14 individual capabilities against the device:

| Capability | OIDs Tested | What It Tells You |
|------------|-------------|-------------------|
| system.read | sysDescr, sysObjectID, sysName | Basic SNMP connectivity |
| interfaces.read | ifIndex, ifDescr | Port enumeration |
| port.admin | ifAdminStatus | Can read port enable/disable state |
| port.oper | ifOperStatus | Can read port up/down state |
| port.traffic | ifInOctets, ifOutOctets | Traffic counters available |
| port.description | ifAlias | Port descriptions (ifAlias) |
| port.highspeed | ifHighSpeed | 64-bit speed counters |
| mac_table(bridge) | dot1dTpFdb | Classic bridge FDB |
| mac_table(qbridge) | dot1qTpFdb | Q-BRIDGE FDB (802.1Q aware) |
| vlan.static | dot1qVlanStatic | VLAN configuration |
| vlan.current | dot1qVlanCurrent | Active VLAN membership |
| stp | dot1dStp | Spanning Tree Protocol |
| poe.port | pethPsePort | Per-port PoE status |
| poe.main | pethMainPse | PSU-level PoE info |

#### Cisco Per-VLAN FDB

When vendor is detected as Cisco, the collector:

1. Discovers active VLANs via `vtpVlanState` (`.1.3.6.1.4.1.9.9.46.1.3.1.1.2`)
2. Skips internal VLANs (1002-1005)
3. Walks bridge FDB per VLAN using `community@vlan` indexing
4. Saves each as `cisco_vlan_{id}.walk`

This is critical because Cisco IOS uses per-VLAN STP — the standard bridge walk returns nothing without VLAN context.

#### Vendor-Specific Extra Walks

| Vendor | Extra Walks | Content |
|--------|------------|---------|
| Cisco | VTP, stackwise, env, CPU, memory | VLAN trunking, stack config, temperature/fan/PSU, CPU/memory usage |
| D-Link | sys, port | System info, port configuration |
| HP/Aruba | ICF, PoE extensions | HP Intelligent Configuration, vendor PoE |
| Mikrotik | sys | Mikrotik system tree |
| Zyxel | sys | Managed switch tree |
| Fortinet | sys | FortiGate/FortiSwitch system |
| Huawei | sys, CPU, memory | Switch config, CPU, memory |
| Juniper | sys | Chassis information |

### MIB-Enhanced Collection (`-mibs`)

When you provide vendor MIB files, the collector goes further:

1. **Bundles** MIB files into `evidence/mibs/` (including subdirectories)
2. **Parses** all MIBs using Radar's MIB parser — resolves OID names, types, access levels
3. **Discovers** enterprise OID subtrees defined in the MIBs that weren't already walked
4. **Auto-walks** those discovered subtrees, saving results as `{vendor}_mib_{module}.walk`
5. **Generates** `mib_oid_index.tsv` — complete OID reference table for the analyzer

This means if the vendor MIB defines OIDs for features like HA status, license info, or hardware inventory, the collector will automatically try to collect that data even though it's not in the hardcoded list.

**Where to get MIB files:**
- Vendor support portal (most vendors publish MIB packages)
- Device firmware package (often contains a `mibs/` directory)
- Ask the client's network admin — they usually have them

## Auto-Detection

### Vendor Detection

The collector identifies the vendor from `sysObjectID` enterprise OID:

| Enterprise OID | Vendor |
|----------------|--------|
| 1.3.6.1.4.1.9 | Cisco |
| 1.3.6.1.4.1.171 | D-Link |
| 1.3.6.1.4.1.890 | Zyxel |
| 1.3.6.1.4.1.14988 | Mikrotik |
| 1.3.6.1.4.1.11 / 47196 | HP/Aruba |
| 1.3.6.1.4.1.12356 | Fortinet |
| 1.3.6.1.4.1.2636 | Juniper |
| 1.3.6.1.4.1.6486 | Alcatel |
| 1.3.6.1.4.1.6527 | Nokia |
| 1.3.6.1.4.1.25506 | H3C |
| 1.3.6.1.4.1.2011 | Huawei |

Falls back to `sysDescr` text matching if OID is unrecognized.

### Model Detection

Extracted from `sysDescr` using vendor-specific patterns:

- **Cisco:** `C2691`, `Software (C2960-...`
- **Mikrotik:** `RouterOS RB450G`
- **Fortinet:** `FortiGate-VM64-KVM`
- **D-Link:** `DGS-1210-28`
- **Zyxel:** `GS1920-24`
- **Huawei:** `S5720`, `CE6800`

### Support Tier

Automatically assigned based on vendor:
- **Tier A** — Cisco, D-Link, HP/Aruba, Zyxel, Mikrotik (full Radar profile support)
- **Tier C** — All others (new vendor, profiles need to be created)

## Output Structure

```
collect_192_168_1_1/
  fingerprint.yaml                  # Device identity (IP, community, sysDescr, sysObjectID, ...)
  intake.yaml                       # Case metadata (vendor, model, tier, firmware)
  report.txt                        # Human-readable collection summary
  evidence/
    cisco_standard.walk             # MIB-2 tree
    cisco_bridge.walk               # Bridge MIB (MAC table, STP)
    cisco_qbridge.walk              # Q-BRIDGE (VLANs, 802.1Q FDB)
    cisco_poe.walk                  # PoE MIB (if supported)
    cisco_vendor.walk               # Enterprise MIB tree
    cisco_vlan_1.walk               # Per-VLAN FDB (Cisco only)
    cisco_vlan_10.walk
    cisco_vlan_20.walk
    cisco_cisco_vtp.walk            # Vendor-specific: VTP
    cisco_cisco_cpu.walk            # Vendor-specific: CPU
    cisco_cisco_memory.walk         # Vendor-specific: Memory
    cisco_cisco_env.walk            # Vendor-specific: Environment
    cisco_mib_cisco_process_mib.walk  # MIB-discovered walks (with -mibs)
    mib_oid_index.tsv               # MIB OID reference table (with -mibs)
    mibs/                           # Bundled MIB files (with -mibs)
      CISCO-PROCESS-MIB.mib
      CISCO-MEMORY-POOL-MIB.mib
      ...
```

### fingerprint.yaml

```yaml
ip: 192.168.20.211
community: public
snmp_version: 2c
sys_descr: "Cisco IOS Software, 2600 Software (C2691-ADVENTERPRISEK9-M), Version 12.4(15)T14"
sys_object_id: .1.3.6.1.4.1.9.1.122
sys_name: R1
sys_uptime: "1234567"
sys_contact: admin@example.com
sys_location: "Server Room A"
```

### intake.yaml

```yaml
vendor: cisco
model: "2691"
tier: A
firmware: "12.4(15)T14"
status: collected
source: offline-collector
collected_at: "2026-04-09T14:30:00+08:00"
```

### report.txt

Human-readable summary including:
- Device information (all system MIB fields)
- Walk file listing with entry counts and timing
- Cisco VLAN discovery results
- Capability probe results (14 capabilities, FOUND/NOT FOUND)
- MIB modules loaded and OID counts (if `-mibs` used)
- MIB-discovered OID results (which vendor OIDs had data)

## Importing into Radar

### Option A: Direct Directory Copy

Copy the output directory to the Radar server's `onboarding/` directory:

```bash
# From remote site laptop → Radar server
scp -r collect_192_168_1_1/ radar-server:~/new_radar/onboarding/cisco_2691/

# Then on Radar server, use API to create case and run pipeline:
# 1. Import
curl -u admin:gentrice -X POST http://localhost:8082/api/v2/onboarding/import \
  -H 'Content-Type: application/json' \
  -d '{"dir": "/path/to/collect_192_168_1_1"}'

# 2. Analyze (returns capability report)
curl -u admin:gentrice -X POST http://localhost:8082/api/v2/onboarding/{id}/analyze

# 3. Approve (deploys profiles to production)
curl -u admin:gentrice -X POST http://localhost:8082/api/v2/onboarding/{id}/approve
```

### Option B: API Upload

Upload evidence files individually:

```bash
# 1. Create case
curl -u admin:gentrice -X POST http://localhost:8082/api/v2/onboarding \
  -H 'Content-Type: application/json' \
  -d '{"vendor":"cisco","model":"2691","tier":"A","ip":"192.168.20.211","community":"public"}'
# → returns {"id": 5, ...}

# 2. Upload fingerprint
curl -u admin:gentrice -X POST http://localhost:8082/api/v2/onboarding/5/fingerprint \
  -H 'Content-Type: application/json' \
  -d @collect_192_168_1_1/fingerprint.yaml

# 3. Upload each walk file
for f in collect_192_168_1_1/evidence/*.walk; do
  curl -u admin:gentrice -X POST http://localhost:8082/api/v2/onboarding/5/evidence \
    -F "file=@$f"
done

# 4. Upload MIB files (if collected)
for f in collect_192_168_1_1/evidence/mibs/*; do
  curl -u admin:gentrice -X POST http://localhost:8082/api/v2/onboarding/5/evidence \
    -F "file=@$f"
done

# 5. Analyze → Approve
curl -u admin:gentrice -X POST http://localhost:8082/api/v2/onboarding/5/analyze
curl -u admin:gentrice -X POST http://localhost:8082/api/v2/onboarding/5/approve
```

### Option C: Web UI

1. Copy directory to server
2. Use Import API to create the case
3. Open Radar web UI → **Enrolled Devices** → case appears with status "evidence"
4. Click **Analyze** to generate profiles
5. Review drafts, click **Approve** to deploy

## Workflow Summary

```
Remote Site                          Radar Server
───────────                          ────────────
                                     
1. Build collector binary   ──────→  make collector
   (or collector.exe)                make collector-windows
                                     
2. Carry to client site              
                                     
3. Connect laptop to                 
   switch management VLAN            
                                     
4. Run collector            
   ./collector -ip x.x.x.x          
   -community xxx                    
   -mibs ./vendor_mibs/              
                                     
5. Review report.txt                 
   (check capability results)        
                                     
6. Bring data back          ──────→  scp / USB drive
                                     
                                     7. Import:
                                        POST /api/v2/onboarding/import
                                     
                                     8. Analyze:
                                        POST /api/v2/onboarding/{id}/analyze
                                     
                                     9. Approve:
                                        POST /api/v2/onboarding/{id}/approve
                                     
                                     10. Device is now recognized by Radar
```

## Troubleshooting

### "SNMP connect failed"

- Verify IP is reachable: `ping 192.168.1.1`
- Check you're on the management VLAN
- Verify community string with the client
- Try `-timeout 30s` for slow devices

### Most walks return "SKIP"

- Community string might be wrong (read-only access needed)
- Device might only support SNMPv1: try `-version 1`
- Firewall blocking UDP 161

### Cisco bridge walk empty but device is a switch

- This is expected — Cisco uses per-VLAN STP
- Deep mode handles this automatically with `community@vlan`
- If VTP discovery also fails, the device may use Q-BRIDGE instead

### "No data" on vendor walk

- Some devices don't populate their enterprise MIB tree
- The standard MIB-2 walks usually have enough data for a basic profile
- Add `-mibs` with vendor MIB files to discover additional OID subtrees

### MIB parsing warnings

- Warnings like "unresolved import" are normal — MIBs often depend on other MIBs
- The parser resolves what it can; unresolved OIDs are skipped
- For best results, include dependency MIBs (RFC standard MIBs) alongside vendor MIBs

## What to Bring to a Remote Site

1. **collector binary** — compiled for the target OS
2. **Vendor MIB files** — download from vendor support portal before the visit
3. **Client info** — IP ranges, SNMP community strings, management VLAN
4. **USB drive** — to carry data back (walk files can be 1-50 MB depending on device size)
