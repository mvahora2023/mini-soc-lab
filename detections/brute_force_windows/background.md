# Background: Windows Brute Force

## What Is a Brute Force Attack?

A brute force attack is a credential-based attack in which an adversary systematically tries a large number of username and password combinations against an authentication service, hoping to find a valid pair. Against Windows systems, common targets include:

- **RDP (Remote Desktop Protocol)** — port 3389, LogonType 10
- **SMB (Server Message Block)** — port 445, LogonType 3
- **NTLM network authentication** — LogonType 3

Two common sub-patterns appear in brute force campaigns:

| Pattern | Description |
|---------|-------------|
| **Credential stuffing / password guessing** | One source IP hammers one target account with many different passwords |
| **Password spray** | One source IP tries a small set of common passwords across many different accounts to avoid lockout thresholds |

## Why SOC Analysts Care

Successful brute force is a primary initial access vector. Once an adversary authenticates, they can:

- Establish persistence (remote access, scheduled tasks)
- Move laterally across the environment
- Escalate privileges using the compromised account
- Exfiltrate data or deploy ransomware

Detecting the *attempt* before a successful logon is critical — failed logon bursts are a leading indicator that gives defenders time to act.

## Required Log Source

**Windows Security Event Log** — must be collected and forwarded to a SIEM or log aggregator.

| Setting | Requirement |
|---------|-------------|
| Audit Policy | `Audit Logon Events` → **Failure** enabled |
| GPO Path | Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy > Logon/Logoff > Audit Logon |
| Log Channel | `Security` (Application and Services Logs) |
| Forwarding | Windows Event Forwarding (WEF) or agent-based collection recommended |

## Key Event: Event ID 4625 — An Account Failed to Log On

This is the primary event generated on the **target system** every time an authentication attempt fails.

### Critical Fields

| Field | Description |
|-------|-------------|
| `TimeCreated` | Timestamp of the failed logon attempt |
| `TargetUserName` | The account name being authenticated |
| `TargetDomainName` | Domain of the target account |
| `LogonType` | Integer indicating the logon method (3=Network, 10=RemoteInteractive) |
| `IpAddress` | Source IP of the authentication request |
| `IpPort` | Source port |
| `Status` | High-level failure code (hex) |
| `SubStatus` | Detailed failure reason (hex) |
| `WorkstationName` | Source machine name (may be blank for network logons) |

### Common SubStatus Codes

| SubStatus | Meaning |
|-----------|---------|
| `0xC000006A` | Correct username, wrong password |
| `0xC0000064` | Username does not exist |
| `0xC000006D` | Generic authentication failure |
| `0xC0000234` | Account locked out |
| `0xC000015B` | User not granted requested logon type |

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | **Credential Access** (TA0006) |
| Technique | **T1110 — Brute Force** |
| Sub-technique | **T1110.001 — Password Guessing** (single account, many passwords) |
| Sub-technique | **T1110.003 — Password Spraying** (many accounts, few passwords) |
| Data Source | `DS0028: Logon Session` / `DS0002: User Account Authentication` |
| Platform | Windows |

## Assumptions (Lab Context)

- All log data in this folder is **100% synthetic** — hand-crafted to demonstrate the attack pattern.
- Source IPs use RFC 5737 documentation ranges (`203.0.113.0/24`) and must never be blocked or used as IOCs.
- Usernames (`admin1`, `user1`) are generic placeholders with no relation to any real account.
- This scenario assumes a Windows Server 2019 domain controller (`DC-01`) exposed on an internal segment, collecting Security event logs forwarded to a simulated SIEM.
