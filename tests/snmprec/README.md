# SNMP Recording Files (.snmprec)

Place `.snmprec` files here for each vendor/model. These files are used by the test simulator to mock SNMP responses.

## Format

Standard snmprec format: `OID|TYPE|VALUE`

Type codes:
- `2` — Integer
- `4` — OctetString
- `5` — Null
- `6` — ObjectIdentifier
- `41` — Counter32
- `42` — Gauge32
- `43` — TimeTicks
- `46` — Counter64
- `64` — IpAddress
- `65` — Opaque
- `70` — Bits

## Directory Structure

```
tests/snmprec/
├── cisco/
│   ├── c2960.snmprec        # Cisco C2960 24-port
│   └── sg300.snmprec        # Cisco SG300
├── dlink/
│   ├── dgs1210.snmprec      # D-Link DGS-1210-28
│   └── dgs1510.snmprec      # D-Link DGS-1510 (PoE)
├── hp/
│   └── procurve2530.snmprec # HP ProCurve 2530
├── zyxel/
│   └── gs1920.snmprec       # Zyxel GS1920-24
└── mikrotik/
    └── css326.snmprec       # Mikrotik CSS326
```

## How to Record

From a real device:
```bash
snmpwalk -v2c -c public -On 192.168.1.1 .1 > device.snmpwalk
# Then convert to snmprec format
```

Or use snmprec tool:
```bash
snmprec-record --agent-udpv4-endpoint=192.168.1.1 --output-file=device.snmprec
```
