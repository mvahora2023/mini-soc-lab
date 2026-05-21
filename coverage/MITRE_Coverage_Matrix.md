# MITRE ATT&CK Coverage Matrix

This matrix tracks every detection use case in the lab against its ATT&CK technique,
data source, and associated artifacts. Update this file whenever a new use case is
added or an existing one changes status.

## Legend

| Status | Meaning |
|--------|---------|
| Complete | Detection write-up, triage report, and playbook are all finished |
| In Progress | At least one artifact is incomplete |
| Planned | Use case is on the roadmap; no artifacts exist yet |

---

## Coverage Table

| Use Case | MITRE Technique | Sub-technique | Data Source | Detection Artifact | Triage Report | Playbook | Status |
|----------|----------------|--------------|-------------|-------------------|---------------|----------|--------|
| Windows Brute Force | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) | [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/), [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) | Windows Security Log — EventID 4625 | [detection.md](../detections/brute_force_windows/detection.md) | [brute_force_001.md](../triage-reports/brute_force_001.md) | [brute_force_playbook.md](../playbooks/brute_force_playbook.md) | Complete |
| Phishing Email | [T1566 — Phishing](https://attack.mitre.org/techniques/T1566/) | [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/), [T1566.002 Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) | Email Gateway Log, Web Proxy Log | [detection.md](../detections/phishing_email/detection.md) | [phishing_001.md](../triage-reports/phishing_001.md) | [phishing_playbook.md](../playbooks/phishing_playbook.md) | Complete |
| Suspicious PowerShell | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) | T1059.001 (with related: T1027 Obfuscation, T1105 Ingress Tool Transfer, T1087 Account Discovery, T1482 Domain Trust Discovery) | Windows Security Log (4688), PowerShell Operational Log (4104), Sysmon (1, 3) | [detection.md](../detections/suspicious_powershell/detection.md) | [powershell_001.md](../triage-reports/powershell_001.md) | Not yet created | In Progress |

---

## Coverage Gaps

The following ATT&CK techniques are commonly observed alongside or after the covered
use cases but are not yet covered by a detection use case in this lab.

| Technique | ID | Relevant Use Case | Gap Type | Priority |
|-----------|-----|------------------|----------|----------|
| Valid Accounts | T1078 | Brute Force, Phishing | No detection for post-compromise use of harvested credentials | High |
| Email Forwarding Rule | T1114.003 | Phishing | No detection for new inbox forwarding rules post-credential theft | High |
| Remote Services — RDP | T1021.001 | Brute Force | No detection for anomalous RDP lateral movement post-access | High |
| Multi-Factor Auth Interception | T1111 | Phishing | No detection for AiTM proxy token theft | High |
| OS Credential Dumping | T1003 | Brute Force | No detection for LSASS access or credential staging | Medium |
| Account Discovery | T1087 | Brute Force | No detection for pre-spray enumeration of valid usernames (PowerShell use case covers post-execution recon only) | Medium |
| User Execution | T1204.002 | Phishing, PowerShell | Attachment open / macro execution covered by PowerShell use case parent-process variant; full EDR response playbook not yet created | Medium |
| Scheduled Task / Job | T1053 | Brute Force, Phishing, PowerShell | PowerShell use case surfaces evidence of scheduled task persistence; dedicated detection rule not yet created | Low |
| Obfuscated Files / Information | T1027 | PowerShell | Partially covered via -EncodedCommand detection in PS use case; broader obfuscation (file packing, string encoding) not yet covered | Low |

---

## Tactic Coverage Summary

| ATT&CK Tactic | Techniques Covered | Techniques Planned | Gap |
|--------------|-------------------|-------------------|-----|
| Reconnaissance (TA0043) | 0 | 0 | Full gap |
| Initial Access (TA0001) | 1 (T1566) | 0 | Partial |
| Execution (TA0002) | 1 (T1059.001) | 0 | Partial |
| Credential Access (TA0006) | 1 (T1110) | 0 | Partial |
| Discovery (TA0007) | 0 (T1087/T1482 surfaced via PS use case, no standalone rule) | 0 | Partial |
| Collection (TA0009) | 0 | 0 | Full gap |
| Lateral Movement (TA0008) | 0 | 0 | Full gap |
| Persistence (TA0003) | 0 | 0 | Full gap |
| Privilege Escalation (TA0004) | 0 | 0 | Full gap |
| Exfiltration (TA0010) | 0 | 0 | Full gap |

---

*Last updated: 2024-11-18 — suspicious_powershell use case added (T1059.001, T1027, T1105, T1087, T1482)*
