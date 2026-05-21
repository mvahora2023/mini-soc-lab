# Background: Phishing Email (T1566)

## What Is a Phishing Attack?

Phishing is a social engineering technique in which an adversary sends deceptive
email messages designed to trick recipients into taking an action that benefits the
attacker — opening a malicious attachment, clicking a credential-harvesting link, or
replying with sensitive information.

Against enterprise environments, two sub-patterns dominate:

| Pattern | Description | MITRE Sub-technique |
|---------|-------------|---------------------|
| **Spearphishing Attachment** | Email carries a weaponised file (macro Office doc, PDF with exploit, ISO/LNK dropper) | T1566.001 |
| **Spearphishing Link** | Email contains a URL pointing to a credential harvester, drive-by download, or adversary-controlled redirect | T1566.002 |

A successful phishing attempt gives the adversary one or more of:
- Valid credentials (credential harvester page)
- Initial foothold via malware execution (weaponised attachment)
- Sensitive data (direct reply with information)

## Why SOC Analysts Care

Phishing is consistently the leading initial access vector across breach datasets.
Its detection window is narrow: the most damaging actions (payload execution,
credential submission) often occur within minutes of email delivery. Detection at the
**email gateway layer** provides the best opportunity to intercept before impact;
detection at the **endpoint or proxy layer** is the last line of defence.

Key escalation signals:

| Signal | Why It Matters |
|--------|---------------|
| Macro-enabled attachment opened | Possible payload execution — check EDR immediately |
| User clicked phishing URL | Possible credential submission or drive-by download |
| SPF/DKIM/DMARC all fail | Domain is spoofed or sender has no legitimate relationship |
| Lookalike sender domain | Adversary impersonating a trusted brand or internal team |
| Same attachment hash to multiple recipients | Targeted campaign, not opportunistic spam |

## Required Log Sources

### Primary

| Source | What It Provides |
|--------|-----------------|
| **Email gateway / secure email gateway (SEG)** | Sender, recipient, subject, source IP, SPF/DKIM/DMARC results, attachment metadata, URL extraction, verdict |
| **Mail server (MTA) logs** | Delivery status, message routing, bounce events |

### Related

| Source | What It Provides |
|--------|-----------------|
| **Web proxy / DNS logs** | Detect users clicking URLs from email; URL resolution; C2 beacon activity |
| **EDR / endpoint telemetry** | Detect attachment opening, macro execution, child process spawning from Office apps |
| **Active Directory / IAM** | Detect credential use after suspected submission to a harvester |

## Key Log Fields (Email Gateway)

| Field | Description |
|-------|-------------|
| `Timestamp` | Time email was received and processed by gateway |
| `Action` | Gateway verdict: DELIVERED, QUARANTINE, BLOCK, JUNK |
| `MessageID` | Unique identifier for the email (from Message-ID header) |
| `From` | Sender address (MAIL FROM / RFC5321 envelope sender) |
| `FromDisplay` | Display name in the From header (often spoofed separately from address) |
| `To` | Recipient address |
| `Subject` | Email subject line |
| `SourceIP` | IP address of the sending MTA |
| `SPFResult` | SPF authentication result: PASS, FAIL, SOFTFAIL, NONE |
| `DKIMResult` | DKIM signature validation result: PASS, FAIL, NONE |
| `DMARCResult` | DMARC policy result: PASS, FAIL, NONE |
| `DMARCPolicy` | DMARC policy applied: none, quarantine, reject |
| `AttachmentCount` | Number of attachments |
| `AttachmentName` | Filename of each attachment |
| `AttachmentHash` | SHA-256 of attachment (safe to log; not the payload itself) |
| `URLCount` | Number of URLs extracted from body |
| `URL` | Extracted URL(s) |
| `Verdict` | Final gateway classification: CLEAN, SUSPICIOUS, MALICIOUS |

## Email Authentication Primer

Understanding SPF, DKIM, and DMARC is essential for phishing triage.

| Protocol | What It Checks | Failure Meaning |
|----------|----------------|----------------|
| **SPF** | Whether the sending MTA IP is authorised to send for the envelope domain | Sending IP not in the domain's SPF record — possible spoofing or unauthorised relay |
| **DKIM** | Whether the email body and headers were signed by the domain's private key | No valid signature — email may be spoofed or tampered |
| **DMARC** | Policy enforcement when SPF and/or DKIM fail | Domain owner's declared response to failures: none (monitor only), quarantine, or reject |

A legitimate bulk sender failing all three is possible (poor email hygiene) but
unusual for reputable organisations. All three failing together, combined with a
lookalike domain name, is a high-confidence spoofing indicator.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | **Initial Access (TA0001)** |
| Technique | **T1566 — Phishing** |
| Sub-technique | **T1566.001 — Spearphishing Attachment** |
| Sub-technique | **T1566.002 — Spearphishing Link** |
| Data Source | `DS0015: Application Log` (email gateway), `DS0029: Network Traffic` (proxy) |
| Platform | Windows, Linux, macOS (platform-agnostic initial access) |

## Assumptions (Lab Context)

- All log entries in this folder are **100% synthetic** — hand-crafted for portfolio
  demonstration only.
- Sender domains (`hr-documents.example`, `accounts-portal.example`) use the `.example`
  TLD reserved by RFC 2606 for documentation. They are not real domains and must
  not be used as blocklist IOCs.
- Source IPs use RFC 5737 documentation ranges (`203.0.113.0/24`).
- Recipient addresses use `@lab.internal` — a non-routable internal domain.
- The organisation in this scenario runs a generic email security gateway that
  produces structured log output; no vendor-specific field names are used.
