# mini-soc-lab

![License](https://img.shields.io/github/license/mvahora2023/mini-soc-lab)
![Last Commit](https://img.shields.io/github/last-commit/mvahora2023/mini-soc-lab)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Enterprise-red)
![Sigma](https://img.shields.io/badge/Sigma-Rules-orange)
![Detection Engineering](https://img.shields.io/badge/Detection-Engineering-blue)

A detection engineering portfolio built around three real-world attack scenarios. Each use case includes simulated log data, a Sigma detection rule, a structured triage report, an incident response playbook, and MITRE ATT&CK coverage mapping.

> All log data, hostnames, IP addresses, usernames, and event entries are entirely synthetic. No real system data is included.

---

## Use Cases

| ID | Technique | MITRE ID | Status |
|---|---|---|---|
| BF-001 | Failed authentication burst (illustrative brute-force scenario) | T1110 | Simulated; 6+ failures / 5m / IP |
| PH-001 | Phishing-related suspicious process creation | T1566 / T1566.001 | Simulated |
| PS-001 | Suspicious PowerShell script block patterns | T1059.001 / T1027 | Simulated |

---

## Repository Structure

```
mini-soc-lab/
├── detections/
│   ├── brute_force_windows/
│   │   ├── sigma_rule.yml         — Sigma detection rule (T1110)
│   │   ├── detection.md           — Detection logic and tuning notes
│   │   ├── background.md          — Attack technique background
│   │   ├── alert.json             — Sample alert object
│   │   └── simulated_logs.log     — Synthetic Windows Security event log
│   ├── phishing_email/
│   │   ├── sigma_rule.yml         — Sigma detection rule (T1566)
│   │   ├── detection.md
│   │   ├── background.md
│   │   ├── alert.json
│   │   └── simulated_logs.log
│   └── suspicious_powershell/
│       ├── sigma_rule.yml         — Sigma detection rule (T1059.001 + T1027)
│       ├── detection.md
│       ├── background.md
│       ├── alert.json
│       └── simulated_logs.log
├── triage-reports/
│   ├── brute_force_001.md         — BF-001 triage report
│   ├── phishing_001.md            — PH-001 triage report
│   ├── powershell_001.md          — PS-001 triage report
│   └── ti_report_bf001.md         — Threat intelligence report (BF-001)
├── playbooks/
│   ├── brute_force_playbook.md    — IR playbook for credential brute force
│   └── phishing_playbook.md       — IR playbook for phishing incidents
├── coverage/
│   ├── MITRE_Coverage_Matrix.md   — Coverage map with 9 identified gaps
│   └── navigator_layer.json       — ATT&CK Navigator layer (import at attack.mitre.org)
└── docs/
    ├── SIEM_QUERIES.md            — Splunk SPL query library for all three use cases
    ├── ATTACK_CHAIN_RECONSTRUCTION.md — Kill chain timelines for all three attacks
    ├── DATA_SANITIZATION_POLICY.md
    ├── EVIDENCE_CHECKLIST.md
    └── PROJECT_SCOPE.md
```

---

## Detection Rules

Each case includes a [Sigma](https://github.com/SigmaHQ/sigma) rule. The brute-force scenario now uses the current **base-rule + event_count correlation** structure. GitHub Actions validates YAML and representative synthetic evidence, but successful conversion and detection efficacy depend on the chosen backend and actual log field mappings. Test correlations before real-world use. See the [Sigma correlation reference](https://sigmahq.io/docs/meta/correlations).

```bash
# Convert to Splunk SPL using sigma-cli
sigma convert -t splunk detections/brute_force_windows/sigma_rule.yml

# Convert to Microsoft Sentinel KQL
sigma convert -t microsoft365defender detections/brute_force_windows/sigma_rule.yml
```

---

## Triage Reports

Triage reports follow a structured format: detection source, severity, Five W's + How analysis, indicators of compromise, containment actions, and post-incident recommendations. The BF-001 report includes a companion [threat intelligence report](triage-reports/ti_report_bf001.md) with TTP analysis, adversary profiling, and IoC durability ratings.

---

## MITRE ATT&CK Coverage

The [coverage matrix](coverage/MITRE_Coverage_Matrix.md) documents 3 detected techniques and 9 identified gaps with remediation priority. Import [navigator_layer.json](coverage/navigator_layer.json) directly into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize coverage.

**Identified gaps (priority order):** T1486 (Ransomware), T1003 (Credential Dumping), T1078 (Valid Accounts), T1562 (Defense Evasion), T1190 (Exploit Public-Facing), T1055 (Process Injection), T1071 (C2 over Web), T1053 (Scheduled Tasks), T1547 (Boot Persistence)

---

## Key Event IDs Referenced

| Event ID | Log | Description |
|---|---|---|
| 4625 | Security | Failed logon — SubStatus 0xC000006A (wrong password) |
| 4771 | Security | Kerberos pre-authentication failed |
| 4104 | PowerShell | Script block logging — captures encoded/obfuscated scripts |
| 4624 | Security | Successful logon — used for pivot detection |
| 4688 | Security | Process creation — used for child process analysis |

---

## License

[MIT](LICENSE) — see the LICENSE file for details.

## Interactive project dashboard (November 2026)

- **[Open this project's public interactive explorer](https://arsh-project-lab.vercel.app/mini-soc-lab/index.html)**
- **[Run the standalone HTML locally](dashboard/index.html)** (no account or service required)
- **[Open the complete public Project Lab](https://arsh-project-lab.vercel.app/)**

Explore synthetic incidents, mapped ATT&CK examples, and documented detection gaps. Source-linked sample data is embedded for offline inspection. Search, group filters and CSV export work locally; checklist review marks (where available) are browser-local only. The page is not a live backend, and changes in this repository will require a separate Vercel deployment until a Git integration is enabled. [Dashboard validation source](tests/dashboard_ui.test.mjs).
