# Project Scope

## What This Repository Is

`mini-soc-lab` is a documentation-first SOC analyst portfolio. It simulates the end-to-end workflow a SOC analyst follows when handling a security alert:

```
Detection → Triage → Playbook → Documentation
```

Each scenario in this repo walks through that workflow using entirely synthetic data, demonstrating analytical thinking, structured communication, and MITRE ATT&CK coverage mapping.

## What This Repository Is Not

- **Not a live attack lab.** No exploitation tools, C2 frameworks, or offensive payloads are included or linked.
- **Not connected to real systems.** There are no real victim machines, real SIEMs, or real network environments referenced here.
- **Not a threat intelligence feed.** IOCs are fictional and must not be used for blocking or hunting in production.

## Scenarios in Scope

| Scenario | ATT&CK Tactic | Status |
|----------|--------------|--------|
| Windows Brute Force (RDP/SMB) | Credential Access | In progress |

## Scenarios Out of Scope (for this public repo)

- Scenarios requiring real customer data or real incident artifacts
- Active exploitation or weaponization demonstrations
- Anything that could cause harm if the repo were cloned and executed

## Intended Audience

Security hiring managers, SOC team leads, and peers reviewing portfolio work.
