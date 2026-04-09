# Switch Model Onboarding SOP

## Overview

Standard procedure for adding support for a new switch model. The principle is:

> **Evidence first, code never.** New device = YAML profiles only, no Go code changes.

### Full Automatic Flow

The web UI supports a fully automatic onboarding pipeline:

> **Test → Create → Collect → Analyze → Approve → device is recognized and supported.**

When enrolling a new device (including new vendors not yet in the system), the pipeline:
1. **Test** — SNMP connectivity test, auto-detects vendor from sysObjectID enterprise OID, auto-fills model/firmware from sysDescr/sysName
2. **Create** — creates case with auto-selected support tier (A for known vendors, C for new vendors, user can override)
3. **Collect** — walks standard, bridge, PoE, and vendor MIB trees automatically
4. **Analyze** — generates all 3 profile drafts automatically:
   - **Fingerprint** (Layer 1) — sysObjectID prefix + sysDescr matching rules
   - **Capability matrix** (Layer 2) — detected capabilities with confidence levels
   - **Vendor profile** (Layer 3) — OID mappings for each supported capability
5. **Approve** — auto-copies drafts to `final/` (if not manually reviewed), then deploys all profiles to production directories (`profiles/fingerprints/`, `profiles/capabilities/`, `profiles/vendors/`)

After approval, the device is immediately recognized by the system's `ProfileRegistry.DetectDevice()` on next startup/reload.

## Support Tiers

| Tier | Scope | Capabilities |
|------|-------|-------------|
| **A** | Full support | All capabilities: read + write + PoE + VLAN + MAC + mirror |
| **B** | Read-only | system.read, interfaces.read, port.oper.read, mac_table.read, vlan.read |
| **C** | Best effort | system.read, interfaces.read only |

## Stages

### Stage 0: Intake & Classification

**Who:** L1 technician / PM
**Input:** vendor, model, firmware, customer site, required features
**Output:** `intake.yaml`

```yaml
# onboarding/{vendor}_{model}/intake.yaml
vendor: zyxel
model: GS1920-24HPv2
firmware: "V4.70(ABPE.1)"
customer: "Site ABC"
required_features:
  - interfaces.read
  - port.admin.write
  - mac_table.read
  - poe.status.read
  - poe.control.write
support_tier: A
urgency: normal
owner: "engineer_name"
created: "2026-04-06"
```

### Stage 1: Device Fingerprint Collection

**Who:** L1 technician
**Commands:**

```bash
snmpget -v2c -c public <ip> 1.3.6.1.2.1.1.2.0   # sysObjectID
snmpget -v2c -c public <ip> 1.3.6.1.2.1.1.1.0   # sysDescr
snmpget -v2c -c public <ip> 1.3.6.1.2.1.1.5.0   # sysName
```

**Output:** `fingerprint.yaml`

```yaml
# onboarding/{vendor}_{model}/fingerprint.yaml
sysObjectID: "1.3.6.1.4.1.890.1.15.3.86"
sysDescr: "GS1920-24HPv2"
sysName: "SW-FLOOR3"
snmp_version: "2c"
community: "public"
ip: "192.168.1.100"
ssh_available: true
ssh_prompt_sample: "GS1920-24HPv2# "
cli_style: "zyxel"
```

**API:** `POST /api/v2/onboarding` → creates case, auto-generates fingerprint draft
**AI assist:** match against existing fingerprints, suggest which vendor family it belongs to

### Stage 2: Evidence Collection (SNMP Walk + CLI)

**Who:** L1 technician
**Commands:**

```bash
# Standard MIB-2
snmpwalk -v2c -c public -On <ip> 1.3.6.1.2.1 > standard.walk

# Vendor private tree
snmpwalk -v2c -c public -On <ip> 1.3.6.1.4.1 > vendor.walk

# Bridge MIB (MAC table)
snmpwalk -v2c -c public -On <ip> 1.3.6.1.2.1.17 > bridge.walk

# PoE MIB (if applicable)
snmpwalk -v2c -c public -On <ip> 1.3.6.1.2.1.105 > poe.walk

# VLAN Q-BRIDGE
snmpwalk -v2c -c public -On <ip> 1.3.6.1.2.1.17.7 > qbridge.walk
```

**CLI evidence:**

```bash
ssh admin@<ip>
> show mac address-table > cli_show_mac.txt
> show vlan > cli_show_vlan.txt
> show interfaces status > cli_show_interfaces.txt
> show poe status > cli_show_poe.txt
```

**Collect 3 scenarios:** idle, active traffic, feature enabled (PoE/VLAN/mirror)

**Output directory:**

```
onboarding/{vendor}_{model}/evidence/
├── standard.walk
├── vendor.walk
├── bridge.walk
├── poe.walk
├── qbridge.walk
├── cli_show_mac.txt
├── cli_show_vlan.txt
├── cli_show_interfaces.txt
├── cli_show_poe.txt
└── mibs/               # vendor MIB files if available
```

**API:** `POST /api/v2/onboarding/{id}/evidence` → upload walk/CLI files
**Generate snmprec:** walk files are converted to `.snmprec` format for test simulator

### Stage 3: Auto-Analysis & Profile Draft Generation

**Who:** AI / automation + L2 engineer review
**Input:** walk files, MIB files, fingerprint
**Output:** capability matrix + vendor profile drafts with confidence scores

**API:** `POST /api/v2/onboarding/{id}/analyze`

The analyzer scans walk files and produces fingerprint, capability matrix, and vendor profile drafts:

```yaml
# onboarding/{vendor}_{model}/ai_drafts/capability_matrix.yaml
id: zyxel_gs1920_24hpv2
capabilities:
  system.read:
    supported: true
    confidence: high
    evidence: "sysDescr, sysName, sysUpTime all returned values"
  interfaces.read:
    supported: true
    confidence: high
    evidence: "ifTable walk returned 28 entries with ifDescr, ifAdminStatus, ifOperStatus"
  port.admin.write:
    supported: true
    confidence: medium
    evidence: "ifAdminStatus OID exists, SET not yet tested"
  mac_table.read:
    supported: true
    confidence: high
    evidence: "dot1dTpFdbTable returned 45 entries"
  poe.status.read:
    supported: true
    confidence: high
    evidence: "POWER-ETHERNET-MIB responded, 24 port entries"
  poe.control.write:
    supported: true
    confidence: low
    evidence: "pethPsePortAdminEnable OID exists, SET not tested, may need vendor OID"
  vlan.read:
    supported: true
    confidence: medium
    evidence: "dot1qVlanStaticName returned 5 VLANs"
```

```yaml
# onboarding/{vendor}_{model}/ai_drafts/vendor_profile.yaml
id: zyxel_gs1920_24hpv2
mappings:
  interfaces.read:
    primary:
      method: snmp
      table: "1.3.6.1.2.1.2.2.1"
      fields:
        ifIndex: "1"
        ifDescr: "2"
        ifAdminStatus: "7"
        ifOperStatus: "8"
    # ... auto-generated from walk analysis
```

**AI responsibilities:**
- Parse walk files, identify which standard/vendor OID tables have data
- Map found OIDs to capabilities
- Generate candidate mappings with confidence levels
- Flag ambiguous areas for human review

**Human must verify:**
- OIDs actually return correct semantic data (not just "something")
- Write operations work (SET tested on lab device)
- SSH fallback commands produce parseable output

### Stage 4: Profile Finalization

**Who:** L2 engineer
**Input:** AI drafts + manual testing results
**Output:** production-ready profiles

```
onboarding/{vendor}_{model}/final/
├── fingerprint.yaml        → copy to profiles/fingerprints/
├── capability_matrix.yaml  → copy to profiles/capabilities/
├── vendor_profile.yaml     → copy to profiles/vendors/
├── override.yaml           → copy to profiles/overrides/ (if needed)
└── snmprec/                → copy to tests/snmprec/{vendor}/
```

**API:** `POST /api/v2/onboarding/{id}/approve` → auto-copies drafts to `final/` if not manually reviewed, then deploys profiles to production

### Stage 5: Test Execution

**Who:** L2 engineer + QA
**Tests:**

| Test Type | Description | Tool |
|-----------|-------------|------|
| Detection | Fingerprint matches correctly | snmprec mock |
| SNMP read | All read capabilities return valid data | snmprec mock + real device |
| SNMP write | SET operations take effect | Real device only |
| Fallback | SSH commands work when SNMP fails | Real device |
| Parser | CLI output parsed correctly | Recorded CLI output |
| Regression | Existing devices still work | snmprec mock suite |

**API:** `POST /api/v2/onboarding/{id}/test` → runs automated test suite against snmprec
**Output:** `test_report.md`

### Stage 6: Sign-off

**Who:** QA / PM

**Checklist:**
- [ ] Fingerprint matches device correctly
- [ ] All required capabilities tested
- [ ] Write operations verified on real device
- [ ] Fallback paths tested
- [ ] snmprec recording saved for regression
- [ ] Known limitations documented
- [ ] Profile deployed to production
- [ ] Knowledge base updated

### Stage 7: Knowledge Base Update

**Who:** L2 engineer
**What to record:**

```yaml
# onboarding/{vendor}_{model}/final/known_limitations.md
- PoE SET via standard MIB works, but power reading requires vendor OID
- Firmware < V4.50 does not support Q-BRIDGE VLAN walk
- SSH session drops after 300s idle, reconnect needed
- ifIndex starts at 1 but port labels start at 1 (no offset)
```

This feeds back into:
- `profiles/overrides/` — firmware-specific workarounds
- `tests/snmprec/` — regression test data
- This document — lessons learned

---

## Directory Structure

```
onboarding/
└── {vendor}_{model}/
    ├── intake.yaml              # Stage 0: case details
    ├── fingerprint.yaml         # Stage 1: device identity
    ├── evidence/                # Stage 2: raw data
    │   ├── standard.walk
    │   ├── vendor.walk
    │   ├── bridge.walk
    │   ├── poe.walk
    │   ├── qbridge.walk
    │   ├── cli_show_mac.txt
    │   ├── cli_show_vlan.txt
    │   └── mibs/
    ├── ai_drafts/               # Stage 3: auto-generated
    │   ├── capability_matrix.yaml
    │   ├── vendor_profile.yaml
    │   ├── test_cases.yaml
    │   └── analysis_report.md
    └── final/                   # Stage 4-7: approved
        ├── fingerprint.yaml
        ├── capability_matrix.yaml
        ├── vendor_profile.yaml
        ├── override.yaml
        ├── test_report.md
        ├── known_limitations.md
        └── snmprec/
```

## Onboarding API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v2/onboarding` | Create new onboarding case (intake) |
| GET | `/api/v2/onboarding` | List all onboarding cases |
| GET | `/api/v2/onboarding/{id}` | Get case details and status |
| POST | `/api/v2/onboarding/{id}/fingerprint` | Submit fingerprint data |
| POST | `/api/v2/onboarding/{id}/evidence` | Upload walk/CLI/MIB files |
| POST | `/api/v2/onboarding/{id}/analyze` | Trigger auto-analysis |
| GET | `/api/v2/onboarding/{id}/drafts` | Get AI-generated drafts |
| PUT | `/api/v2/onboarding/{id}/drafts` | Engineer edits drafts |
| POST | `/api/v2/onboarding/{id}/test` | Run automated tests |
| GET | `/api/v2/onboarding/{id}/test/report` | Get test results |
| POST | `/api/v2/onboarding/{id}/approve` | Deploy profiles to production |

## Responsibility Matrix

| Role | Stage 0 | Stage 1 | Stage 2 | Stage 3 | Stage 4 | Stage 5 | Stage 6 | Stage 7 |
|------|---------|---------|---------|---------|---------|---------|---------|---------|
| L1 Tech | Intake | Fingerprint | Evidence | — | — | — | — | — |
| AI/Auto | — | Draft FP | Convert snmprec | Analyze + draft | — | Mock tests | — | — |
| L2 Eng | — | — | — | Review | Finalize | Real tests | — | KB update |
| QA/PM | Classify | — | — | — | — | Verify | Sign-off | — |

## Timeline Target

| Day | Activity |
|-----|----------|
| Day 1 | Intake + fingerprint + evidence collection + AI drafts |
| Day 2 | Engineer review + profile finalization + lab testing |
| Day 3 | Real device verification + sign-off + knowledge base update |

## 5 Rules

1. **Evidence first, code never** — collect walk/CLI before touching profiles
2. **Capability first, mapping second** — define what it can do before how
3. **AI drafts only, never production** — all AI output requires human approval
4. **Every model gets regression tests** — snmprec recording is mandatory
5. **Document all limitations** — known issues must be in the override file
