# Radar Probe API List

Radar probe is the sole intermediary for all SNMP/device operations. It runs a Go-based HTTP server (`beverage_go`) on port 8082.

## Auth & Connection

- **Base URL:** `http://{radarIP}:8082`
- **Auth:** HTTP Basic Auth (`RADAR_API_USER` / `RADAR_API_PASSWORD`, default `admin`/`gentrice`)
- **radarIP** 來自 MySQL `Unit.radarIP` 欄位，依 UnitID 查詢
- **Default timeout:** 15s（部分操作 30s–60s）

## Endpoints

| # | Category | Method | Endpoint | Description |
|---|----------|--------|----------|-------------|
| 1 | **Ping** | POST | `/exec_tool/ping` | 執行 ping（回傳 task_id，非同步） |
| 2 | **Ping** | GET | `/exec_tool/result?unit_id=&task_id=` | 取得 ping/traceroute 任務結果（輪詢） |
| 3 | **Traceroute** | POST | `/exec_tool/traceroute` | 執行 traceroute（回傳 task_id） |
| 4 | **Port Control** | GET | `/beverage_go/api?args=set_port&args={swId}&args={on\|off}&args={port}&force-exec` | 啟用/停用交換器 port |
| 5 | **Port Status** | GET | `/beverage_go/api?args=port_status&args={swId}` | 取得 port link 狀態（up/down） |
| 6 | **Port Status** | GET | `/beverage_go/api?args=admin_port_status&args={swId}` | 取得 port admin 狀態（enabled/disabled） |
| 7 | **Port Info** | GET | `/sw_table/input?u_id={unitId}` | 整合 port on/off + PoE 資訊 |
| 8 | **Port Desc** | GET | `/sw_port_description?id={swId}` | 取得 port 別名/描述 |
| 9 | **PoE** | GET | `/beverage_go/api?args=poestate&args={enable\|disable}&args={swId}&args={port}&force-exec` | 啟用/停用 PoE |
| 10 | **PoE** | GET | `/beverage_go/api?args=poe_report&args={swId}&args=list` | 取得 PoE 耗電報告 |
| 11 | **PoE** | GET | `/beverage_go/api?args=poe_support&args={swId}` | 檢查是否支援 PoE |
| 12 | **MAC Location** | GET | `/location?u_id={unitId}&mac={mac}` | 查詢 MAC 所在交換器/port |
| 13 | **MAC Location** | GET | `/location/all?unit_id={unitId}` | 重新整理所有 MAC 位置資料 |
| 14 | **IP-MAC** | GET | `/rtmi/ip?unit_id={unitId}&ip={ip}` | 即時 IP→MAC 解析（ARP cache） |
| 15 | **MAC Isolation** | GET | `/isolator?unit_id={unitId}` | 取得已封鎖 MAC 清單 |
| 16 | **MAC Isolation** | POST | `/isolator` | 封鎖 MAC（JSON body: unit_id, mac, action:"block"） |
| 17 | **MAC Isolation** | DELETE | `/isolator` | 解除封鎖 MAC（JSON body: unit_id, mac） |
| 18 | **Switch Info** | GET | `/beverage_go/api?args=cpu_util&args={swId}` | 取得交換器 CPU 使用率 |
| 19 | **Switch Info** | GET | `/beverage_go/api?args=switch_info&args={swId}&args=stat&force-exec` | 取得交換器 port 流量統計 |
| 20 | **Switch Info** | GET | `/beverage_go/api?args=vlan_report&args={swId}` | 取得 VLAN 設定 |
| 21 | **SNMP** | GET | `/snmp_test?unit_id=&ip=&community=&snmp_ver=` | 測試 SNMP 連線 |
| 22 | **SNMP** | GET | `/snmp_test?...&oid=&output=1` | 查詢特定 SNMP OID |
| 23 | **Discovery** | GET | `/beverage_go/api?args=discovery&args={subnet}&args={community}&args={type}` | 觸發網路設備掃描 |
| 24 | **Status** | GET | `/version` | 取得 Radar 版本 |
| 25 | **Status** | GET | `/interface` | 取得 Radar 網路介面資訊 |

## Request/Response Details

### Ping (Async)

**POST** `/exec_tool/ping`
- Body (form-urlencoded): `host`, `count`, `unit_id`
- Response: `{ task_id: string }`

**GET** `/exec_tool/result?unit_id={unitId}&task_id={taskId}`
- Response: `{ exec_status: "running"|"finish", output: string }`

### Traceroute (Async)

**POST** `/exec_tool/traceroute`
- Body (form-urlencoded): `host`, `max_hops`, `unit_id`
- Response: `{ task_id: string }`
- Result polling: same as ping (`/exec_tool/result`)

### Port Control

**GET** `/beverage_go/api?args=set_port&args={swId}&args={on|off}&args={port}&force-exec`
- Response: `{ status: 200, error: string }`

### Port Status

**GET** `/beverage_go/api?args=port_status&args={swId}`
- Returns link status for all ports (text)

**GET** `/beverage_go/api?args=admin_port_status&args={swId}`
- Returns admin status for all ports (text)

### Port Info (Consolidated)

**GET** `/sw_table/input?u_id={unitId}`
- Response: `{ data: [{ sw_id, ports, admin_port_status }] }`
- `admin_port_status`: hex bitmap of port admin states

### Port Description

**GET** `/sw_port_description?id={swId}`
- Response: `{ [portIndex]: "description" }`

### PoE

**GET** `/beverage_go/api?args=poestate&args={enable|disable}&args={swId}&args={port}&force-exec`
- Response: `{ status: 200, error: string }`

**GET** `/beverage_go/api?args=poe_report&args={swId}&args=list`
- Response: `{ data: [{ port: string, watt: number }] }`

**GET** `/beverage_go/api?args=poe_support&args={swId}`
- Response: `{ support: boolean }` or `{ data: boolean }`

### MAC Location

**GET** `/location?u_id={unitId}&mac={mac}`
- MAC format: lowercase, no separators (e.g. `aabbccddeeff`)
- Response: `{ sw_id, sw_port, mac, timestamp }`

**GET** `/location/all?unit_id={unitId}`
- Triggers full refresh, returns OK/fail

### IP-MAC Resolution

**GET** `/rtmi/ip?unit_id={unitId}&ip={ip}`
- Response: `{ mac: string }`

### MAC Isolation

**GET** `/isolator?unit_id={unitId}`
- Response: `{ data: string[] }` (list of blocked MACs)

**POST** `/isolator`
- Body (JSON): `{ unit_id, mac, action: "block" }`

**DELETE** `/isolator`
- Body (JSON): `{ unit_id, mac }`

### Switch Info

**GET** `/beverage_go/api?args=cpu_util&args={swId}`
- Response: `{ cpu_util: number }` or `{ data: number }`

**GET** `/beverage_go/api?args=switch_info&args={swId}&args=stat&force-exec`
- Returns per-port traffic statistics (JSON)

**GET** `/beverage_go/api?args=vlan_report&args={swId}`
- Returns VLAN configuration (JSON)

### SNMP

**GET** `/snmp_test?unit_id={unitId}&ip={ip}&community={community}&snmp_ver={2c|1}`
- Tests SNMP connectivity, returns text

**GET** `/snmp_test?unit_id={unitId}&ip={ip}&community={community}&snmp_ver={ver}&oid={oid}&output=1`
- Queries specific OID, returns text value

### Discovery

**GET** `/beverage_go/api?args=discovery&args={subnet}&args={community}&args={type}`
- `type`: `all` or specific device type
- Timeout: 60s

### Status

**GET** `/version`
- Response: `{ version: string, build_date: string }`

**GET** `/interface`
- Returns Radar's network interfaces (IPs, MACs)
