---
name: Radar Tool List for Skills
description: 18 skill tools requiring Radar API — endpoints, status, and pending Radar Go implementations
type: reference
---

## Skill Tools Requiring Radar API (18 tools)

Radar Probe: HTTP API on port 8082, Basic Auth (`RADAR_API_USER` / `RADAR_API_PASSWORD`)

### Async Tool Execution (`/exec_tool/*`)

| Tool | Radar Function | Endpoint | Status |
|---|---|---|---|
| `ping_target` | `pingAndWait()` | POST `/exec_tool/ping` → GET `/exec_tool/result` | ✅ Done |
| `traceroute` | `tracerouteAndWait()` | POST `/exec_tool/traceroute` → GET `/exec_tool/result` | ⚠️ Local fallback, Radar Go TODO |
| `arping` | `arpingAndWait()` | POST `/exec_tool/arping` → GET `/exec_tool/result` | ⚠️ Local fallback, Radar Go TODO |
| `dad_check` | `dadCheckAndWait()` | POST `/exec_tool/dad_check` → GET `/exec_tool/result` | ⚠️ Local fallback, Radar Go TODO |

### MAC/IP Lookup

| Tool | Radar Function | Endpoint | Status |
|---|---|---|---|
| `mac_locate` | `locateMac()` | GET `/location?u_id={unitId}&mac={mac}` | ✅ Done |
| `ip_resolve` | `resolveIpToMac()` | GET `/rtmi/ip?unit_id={unitId}&ip={ip}` | ✅ Done |

### SNMP

| Tool | Radar Function | Endpoint | Status |
|---|---|---|---|
| `snmp_query` | `snmpOidQuery()` | GET `/snmp_test?unit_id=&ip=&oid=&community=&snmp_ver=2c&output=1` | ✅ Done |

### Device Control (`/beverage_go/api`)

| Tool | Radar Function | Endpoint Args | Status |
|---|---|---|---|
| `port_status_check` | `getPortStatus()` | `args=port_status&args={swId}` | ✅ Done |
| `get_switch_cpu` | `getSwitchCpu()` | `args=cpu_util&args={swId}` | ✅ Done |
| `check_poe_status` | `getPoeReport()` | `args=poe_report&args={swId}&args=list` | ✅ Done |
| `query_fdb` | `queryFdb()` | `args=fdb_table&args={swId}` | ⚠️ Radar Go TODO |
| `disable_port` | `setPort(.., 'off')` | `args=set_port&args={swId}&args=off&args={port}` | ✅ Done |
| `enable_port` | `setPort(.., 'on')` | `args=set_port&args={swId}&args=on&args={port}` | ✅ Done |
| `set_port_speed` | `setPortSpeed()` | `args=set_port_speed&args={swId}&args={port}&args={speed}&args={duplex}` | ⚠️ Radar Go TODO |
| `reboot_switch` | `rebootSwitch()` | `args=reboot&args={swId}` | ⚠️ Radar Go TODO |
| `clear_fdb` | `clearFdb()` | `args=clear_fdb&args={swId}&args={tables}` | ⚠️ Radar Go TODO |
| `trigger_topology_rebuild` | `triggerTopologyRebuild()` | `args=rebuild_topology&args={unitId}` | ⚠️ Radar Go TODO |

### MAC Isolation (`/isolator`)

| Tool | Radar Function | Endpoint | Status |
|---|---|---|---|
| `mac_block` | `isolateMac()` | POST `/isolator` body: `{unit_id, mac, action:'block'}` | ✅ Done |

## Status Summary

- **✅ 11 tools** — Radar API working
- **⚠️ 7 tools** — local fallback / mock, pending Radar Go implementation:
  - `/exec_tool/`: traceroute, arping, dad_check
  - `/beverage_go/api`: fdb_table, set_port_speed, reboot, clear_fdb, rebuild_topology
