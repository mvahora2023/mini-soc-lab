# Playbook: Phishing Email Response (T1566)

| Field | Value |
|-------|-------|
| Playbook ID | PB-INIT-001 |
| Version | 1.0 |
| Last Reviewed | 2024-11-15 |
| Tactic | Initial Access (TA0001) |
| Technique | T1566 — Phishing |
| Severity | High (default); Critical if credential submission or payload execution confirmed |
| Owner | SOC Tier 1 (triage); SOC Tier 2 (escalation); IR (if compromise confirmed) |
| Related Alert | PHISH-EMAIL-001 |
| Related Detection | `detections/phishing_email/detection.md` |
| Related Triage Template | `triage-reports/phishing_001.md` |

---

## 1. Purpose and Scope

### Purpose

This playbook provides a repeatable, step-by-step response procedure for analysts
handling phishing email alerts. It covers triage, containment (email pull, domain
block, URL block, hash block), eradication, and recovery, with escalation paths
for the critical case where a user has clicked a link or opened a weaponised
attachment.

### Scope

This playbook applies when a detection rule or manual observation identifies:

- Inbound emails with combined authentication failures (SPF/DKIM/DMARC) carrying
  macro-enabled attachments (**T1566.001 — Spearphishing Attachment**)
- Inbound emails with suspicious URLs delivered to user inboxes due to gateway
  policy gaps (**T1566.002 — Spearphishing Link**)
- Proxy evidence of a user clicking a URL from a suspicious email, with or without
  a subsequent form submission (POST event)

### Out of Scope

- Business Email Compromise (BEC) with no malicious attachment or link — handled
  by a separate fraud / financial controls process.
- Malware execution post-attachment-open — hand off to the Endpoint Malware
  Response playbook once execution is confirmed.
- OAuth application phishing (consent grant attacks) — handled by a separate
  Identity / Cloud Access playbook.

### Roles and Responsibilities

| Role | Responsibilities |
|------|----------------|
| SOC Tier 1 Analyst | Execute triage checklist; classify variant; assess recipient and click scope; escalate if warranted |
| SOC Tier 2 Analyst | Deep investigation; sandbox detonation; infrastructure analysis; containment decision authority |
| Email Security / Gateway Team | Email quarantine, recall, and sender/domain blocking |
| Web Proxy / Network Team | URL and IP blocking at proxy or perimeter firewall |
| Identity / AD Team | Password reset, session revocation, OAuth audit |
| Endpoint / EDR Team | Attachment detonation check; process tree review on recipient endpoints |
| Incident Response | Engage if credential compromise or payload execution is confirmed |

---

## 2. Trigger Conditions

### Automated Alert Triggers

**Variant A — Spearphishing Attachment (T1566.001)**

```
Email gateway log:
  SPFResult IN (FAIL, SOFTFAIL)
  AND DKIMResult IN (FAIL, NONE)
  AND AttachmentExtension IN high_risk_list
  AND RecipientCount >= 2 within 30 minutes
  AND SourceIP NOT IN allowlist
```

**Variant B1 — Spearphishing Link (Gateway)**

```
Email gateway log:
  SPFResult IN (FAIL, SOFTFAIL)
  AND URLCount > 0
  AND URLCategory IN (UNCATEGORIZED, NEWLY_REGISTERED, SUSPICIOUS, PHISHING)
  AND RecipientCount >= 2 within 30 minutes
```

**Variant B2 — Spearphishing Link (Proxy Click — Critical Escalation)**

```
Proxy log:
  HTTP GET to uncategorised/suspicious domain
  AND HTTP POST to same host within 60 seconds
  AND Referrer = EMAIL_CLIENT or email delivery timestamp correlates within 30 minutes
```

### Manual Trigger Conditions

Activate this playbook when:

- A user reports receiving a suspicious email asking for credentials or to open
  an attachment.
- Helpdesk reports a user whose account was accessed from an unexpected IP shortly
  after opening email.
- Threat intel or an industry ISAC shares indicators matching emails in your
  gateway logs.
- An email was quarantined but a user requests release — analyst should triage
  before approving any release of flagged messages.

---

## 3. Required Data Sources

### Primary (Must Have for Triage)

| Source | Fields Required |
|--------|----------------|
| **Email gateway log** | `Timestamp`, `Action`, `MessageID`, `From`, `To`, `Subject`, `SourceIP`, `SPFResult`, `DKIMResult`, `DMARCResult`, `DMARCPolicy`, `AttachmentName`, `AttachmentHash`, `URLCount`, `URL`, `Verdict` |

### Related (Check During Investigation)

| Source | Why It Matters |
|--------|---------------|
| **Web proxy / DNS log** | Detect link clicks and form submissions post-delivery; the primary signal for Variant B2 |
| **Email server / MTA log** | Confirm delivery status; identify message routing; detect re-forwarded copies |
| **EDR / endpoint log** | Detect attachment open, macro execution, process spawn from Office app |
| **Active Directory / IAM log** | Detect logons from unexpected IPs or at unusual times after suspected credential theft |
| **Email client audit log** | Detect new inbox rules, mail forwarding, OAuth grants post-compromise |

---

## 4. Triage Checklist

Steps marked `[TIER 1]` should be completed by the first-response analyst.
Steps marked `[TIER 2]` may require escalation before proceeding.

### Step 1 — Validate the Alert `[TIER 1]`

- [ ] Confirm the alert fired on real email gateway or proxy events, not a tuning
  run or simulation.
- [ ] Confirm SourceIP and sender domain are present and not null.
- [ ] Check whether the sender domain matches a known phishing simulation vendor.
  If yes, verify against the simulation calendar and close as Benign TP if confirmed.
- [ ] Record: sender address, sender domain, SourceIP, subject, recipients, attachment
  or URL details.

### Step 2 — Determine Campaign Breadth `[TIER 1]`

- [ ] Query the email gateway for all messages from the same sender domain and SourceIP
  in the past 24 hours. How many recipients were targeted?
- [ ] Query for the same attachment hash across all senders and recipients in the past
  24 hours. A hash seen across multiple senders or multiple domains indicates a broader
  campaign.
- [ ] Query for the same URL domain across all inbound email in the past 24 hours.
- [ ] Record: total recipient count, unique recipient departments or roles.

### Step 3 — Assess Email Authentication Results `[TIER 1]`

- [ ] Check SPF, DKIM, and DMARC results across all emails in the campaign.

| Authentication Pattern | Interpretation |
|------------------------|---------------|
| All three FAIL | Strong spoofing indicator; domain has no authorised relationship |
| SPF FAIL, DKIM NONE, DMARC none | Sender domain has minimal email security; likely a throwaway adversary domain |
| SPF SOFTFAIL, others absent | Partial misconfiguration; may indicate adversary using shared infrastructure |
| SPF PASS, DKIM PASS, DMARC PASS | Genuine sender; investigate whether it is a compromised legitimate account |

- [ ] Record the predominant authentication pattern in the ticket.

### Step 4 — Assess Gateway Action `[TIER 1]`

- [ ] Determine what the gateway did with the emails:
  - `QUARANTINE` / `BLOCK`: email not delivered — proceed to containment without urgency escalation
  - `DELIVERED` / `JUNK`: email reached user inboxes — escalate to Tier 2 and initiate user notification concurrently
  - Mixed (some quarantined, some delivered): treat as DELIVERED across the board
- [ ] For delivered emails: identify **exactly which recipients** received the email in
  their inbox (not quarantine) and proceed to Step 5.

### Step 5 — Assess User Interaction `[TIER 1 / TIER 2]`

**For attachment campaigns:**

- [ ] Query EDR for any of the following on recipient endpoints within 1 hour of email
  delivery:
  - File creation event matching the attachment filename or hash
  - Process spawn from `WINWORD.EXE`, `EXCEL.EXE`, or `OUTLOOK.EXE`
  - Macro execution events (4104 Script Block Logging, or EDR-specific)
- [ ] If execution evidence found: escalate immediately to Tier 2 and IR. Transition
  to the Endpoint Malware Response playbook for the affected host.

**For link campaigns:**

- [ ] Query proxy logs for HTTP GET requests to the phishing URL domain from all
  recipient workstations in the window from email delivery to +2 hours.
- [ ] For any GET found: check for a subsequent POST to the same host within 60 seconds.
  - GET only: user clicked but may not have submitted credentials — still treat as
    at-risk; notify user and monitor account.
  - GET + POST: treat as credential compromise — escalate immediately.
- [ ] Record which users clicked and/or submitted.

### Step 6 — Enrich the Attacker Infrastructure `[TIER 2]`

- [ ] WHOIS / passive DNS on sender domain: registration date, registrar, nameservers.
  A domain registered within the past 30 days is a strong phishing infrastructure indicator.
- [ ] Threat intel lookup on SourceIP: prior abuse reports, ASN, geolocation, hosting provider.
- [ ] Threat intel lookup on AttachmentHash (Variant A): known malware family, sandbox reports.
- [ ] Threat intel lookup on URL domain (Variant B): prior phishing categorisation, hosting.
- [ ] Record all findings in the ticket for future correlation.

### Step 7 — Classify the Alert `[TIER 1]`

| Verdict | Criteria |
|---------|---------|
| **True Positive — High** | Failed auth + lookalike domain + macro attachment or suspicious URL; gateway quarantined; no user interaction |
| **True Positive — Critical** | Any of the above PLUS: email delivered AND user clicked AND POST submitted; or attachment opened and macro executed |
| **False Positive** | Sender is a known legitimate bulk mailer; subject and domain match an active business relationship; auth failures explained by sender ESP migration or misconfiguration |
| **Benign True Positive** | Phishing simulation confirmed; real phishing pattern but from authorised security awareness platform |
| **Undetermined** | Cannot determine delivery status or user interaction; insufficient proxy or EDR data — escalate for data gap investigation |

- [ ] Record verdict and justification in the triage report.

---

## 5. Containment Actions

Execute in the order listed. Do not wait for all enrichment to complete before
beginning containment — start with email pull immediately after verdict is confirmed.

### 5.1 Quarantine or Recall All Campaign Emails

- [ ] For emails already quarantined by gateway: confirm they are not accessible by
  users. Deny any release requests for the affected messages until investigation closes.
- [ ] For emails delivered to inboxes: initiate an email recall or admin-delete via the
  mail server admin console. Verify the recall completed for all affected mailboxes —
  recalls can fail if the user has already moved or forwarded the email.
- [ ] Document the recall action with timestamps and confirmation of success per mailbox.

### 5.2 Block Sender Domain and Source IP at Gateway

- [ ] Add the sender domain(s) to the gateway blocklist (block, not tag-and-deliver).
- [ ] Add the SourceIP(s) to the gateway IP blocklist.
- [ ] Set a 90-day review on the blocks. Adversary infrastructure is often
  short-lived; the block can be removed when the domain is no longer active.

### 5.3 Block Phishing URL at Web Proxy

- [ ] Add the phishing URL domain to the proxy category blocklist.
- [ ] If the URL contains per-recipient tokens, block at the **domain level**, not
  the full URL, to cover all token variants.
- [ ] Confirm the block is applied to all proxy nodes / regional proxies, not just a
  single node.

### 5.4 Block Attachment Hash at Gateway and EDR

- [ ] Add the attachment SHA-256 hash to the email gateway attachment blocklist.
- [ ] Submit the hash to the EDR custom IOC list for detection and prevention on
  all endpoints (in case any copies were saved locally before quarantine).

### 5.5 Protect Affected User Accounts

**For users who clicked + submitted (GET + POST confirmed):**

- [ ] Immediately force a password reset. Do not wait for the user to report symptoms.
- [ ] Revoke all active sessions for the account (sign out all devices).
- [ ] Check MFA enrollment; if not enrolled, enrol before re-enabling access.
- [ ] Notify the user and their manager of the suspected credential exposure.

**For users who clicked (GET only):**

- [ ] Notify the user; request they change their password as a precaution.
- [ ] Monitor the account for 7 days for anomalous logons (unusual IP, unusual hours,
  privilege escalation attempts).

**For users who received but did not click:**

- [ ] Notify with security awareness guidance. No account action required unless
  monitoring reveals anomalous behaviour.

---

## 6. Eradication and Recovery

### 6.1 Audit Compromised Accounts for Persistence

For `user1` and `user2` (or any account with confirmed POST event):

- [ ] Check for new inbox forwarding rules or sweep rules (mail forwarded externally).
- [ ] Check for new OAuth application grants or consented third-party integrations.
- [ ] Check for new email aliases or account modifications.
- [ ] Review privileged group membership changes in the post-incident window.
- [ ] Query Active Directory logon history (EventID 4624) for the 6 hours following
  the POST event. Look for logons from IPs not matching the user's known workstation.

### 6.2 EDR Sweep on Recipient Endpoints

Even if no execution was observed, perform a targeted sweep:

- [ ] Search for files matching the attachment name or hash on all recipient endpoints.
- [ ] Search for any new scheduled tasks, services, or run keys created on recipient
  endpoints in the incident window.
- [ ] Check browser history on affected workstations for additional phishing URLs
  visited that the proxy may not have fully logged.

### 6.3 Verify No Secondary Phishing from Compromised Accounts

Adversaries who successfully harvest email credentials often immediately use the
account to send further phishing internally (internal spearphishing is harder to
detect because it originates from a trusted sender):

- [ ] Query the email gateway for outbound emails sent *from* `user1` or `user2`
  after the suspected compromise time. Look for high-volume sends, unusual recipients,
  or replies-to that differ from the account's address.
- [ ] If internal phishing from a compromised account is detected, expand the
  investigation to all recipients of those internal emails.

### 6.4 Safe Re-enablement

Before returning an account to normal use:

- [ ] Password reset is complete and new password meets complexity policy.
- [ ] MFA is enrolled and tested.
- [ ] No active sessions from unexpected IPs.
- [ ] No inbox rules or OAuth grants of concern.
- [ ] Account owner has been briefed and acknowledged.

---

## 7. Validation Steps

### 7.1 Confirm No Further Delivery from Campaign Infrastructure

- [ ] Query the email gateway for the blocked sender domain(s) and SourceIP(s) for
  24 hours post-block. The hit count should show block actions only, not deliveries.

### 7.2 Confirm URL Is Blocked

- [ ] Test the proxy block by querying proxy logs for any access to the phishing domain
  24 hours post-block. No allows should appear.

### 7.3 Confirm Accounts Are Healthy

- [ ] Verify password reset completed for all required accounts.
- [ ] Verify no new anomalous logons for affected accounts in the 48 hours post-reset.
- [ ] Verify no new inbox rules or OAuth grants.

### 7.4 Confirm Detection Coverage

- [ ] Was the gateway alert timely? Calculate time from first email delivery to alert
  firing. Flag if > 5 minutes.
- [ ] Did the proxy B2 alert fire correctly for the click + POST pattern?
- [ ] Were there any recipients not captured by the initial alert? Run the detection
  query in retrospect to verify completeness.

---

## 8. Documentation Requirements

### Mandatory Ticket Fields

| Field | What to Record |
|-------|---------------|
| Alert ID | PHISH-EMAIL-001 or SIEM reference |
| Campaign Start | Timestamp of first email observed |
| Campaign End | Timestamp of last email or last user interaction |
| Sender Domain(s) | All adversary sending domains identified |
| Source MTA IP(s) | All adversary sending IPs identified |
| Phishing URL(s) | Full URL(s) extracted from email body |
| Attachment Hash | SHA-256 of any weaponised attachment |
| Total Recipients | Count and list of all targeted accounts |
| Delivered vs Quarantined | Count for each action |
| Click Events | Which users clicked; timestamp |
| POST Events | Which users submitted forms; timestamp |
| Credential Compromise Suspected | Yes / No; accounts affected |
| Attachment Execution Suspected | Yes / No; accounts and endpoints affected |
| Verdict | True Positive (High / Critical) / False Positive / Benign TP |
| Containment Actions | Email recall, blocks applied — each with timestamp and owner |
| Eradication Actions | Password resets, audit results, sweep findings |
| Time to Detect | First email timestamp → alert fire timestamp |
| Time to Contain | Alert fire timestamp → email recall + block completion timestamp |
| Analyst | Analyst ID who handled triage and containment |

### Evidence to Attach

- [ ] Triage report (link to `triage-reports/phishing_001.md` or equivalent)
- [ ] Gateway log query results showing campaign scope
- [ ] Proxy log query showing click and POST events
- [ ] Threat intel reports for sender domain, SourceIP, URL, and hash
- [ ] Email recall confirmation receipts
- [ ] Block ticket numbers (gateway and proxy)
- [ ] Password reset confirmation from Identity team
- [ ] EDR sweep results

---

## 9. MITRE ATT&CK Mapping

### Primary Techniques

| Field | Value |
|-------|-------|
| Tactic | Initial Access (TA0001) |
| Technique | T1566 — Phishing |
| Sub-technique | T1566.001 — Spearphishing Attachment |
| Sub-technique | T1566.002 — Spearphishing Link |
| Data Sources | DS0015: Application Log (email gateway), DS0029: Network Traffic (proxy), DS0022: File (EDR — attachment) |

### Adjacent Techniques to Monitor

| Technique | ID | Relationship |
|-----------|----|----|
| Valid Accounts | T1078 | Primary post-phishing risk — harvested credentials used for authenticated access |
| Email Collection | T1114 | If mailbox compromised, adversary may access or exfiltrate email |
| Email Forwarding Rule | T1114.003 | Common persistence after email credential theft — forwards copies to external inbox |
| Multi-Factor Authentication Interception | T1111 | Real-time phishing proxies (AiTM) can intercept MFA tokens — escalates threat severity |
| User Execution | T1204.002 | Victim opens malicious attachment — triggers Endpoint Malware Response playbook |
| Command and Scripting Interpreter | T1059 | Macro in attachment executes VBA/PowerShell — post-execution chain |
| Phishing for Information | T1598 | Reconnaissance phishing (credential forms, reply-based information gathering) — different playbook |

### Detection Coverage

| Technique | Covered by This Playbook | Gap |
|-----------|-------------------------|-----|
| T1566.001 | Yes — Variant A | Sandbox detonation for unknown attachment families is manual |
| T1566.002 | Yes — Variants B1 and B2 | AiTM proxy interception (T1111) is a separate gap |
| T1078 | Partial — post-incident account audit | Real-time credential use detection requires separate detection rule |
| T1114.003 | Yes — eradication step 6.1 | |
| T1204.002 | Partial — EDR sweep | Full execution response requires Endpoint Malware playbook |

---

## 10. Common Mistakes

### Mistake 1: Recalling Only the Directly Alerted Recipients

**What happens:** The alert fires for two recipients, the analyst recalls email
from those two mailboxes, and closes the ticket. Three other recipients who also
received the campaign email — but who were not in the initial alert because their
emails were processed by a different gateway node — are left with the message in
their inboxes.

**How to avoid:**

- Always query the full email gateway (all nodes / all regions) for the sender domain,
  SourceIP, and attachment hash in the prior 24 hours before treating recipient scope
  as complete.
- Do not rely on the alert's recipient list as exhaustive.

---

### Mistake 2: Blocking Only the Full URL Instead of the Domain

**What happens:** The analyst blocks `http://203.0.113.99/portal/reset-password?token=usr2_synthetic`
at the proxy. A user later clicks `http://203.0.113.99/portal/reset-password?token=usr3_synthetic`
(their unique token URL) which is not blocked because it is a different full URL.

**How to avoid:**

- When adversaries use per-recipient URL tokens, block at the **domain or IP level**
  (`203.0.113.99`), not at the full path.
- Confirm the block covers all URL permutations, not just the observed one.

---

### Mistake 3: Approving a Quarantine Release Without Re-triaging

**What happens:** A user or manager escalates to IT to release a quarantined email
("I'm expecting a compensation document from HR"). The helpdesk approves the release
without checking whether the message is under active investigation as a phishing email.
The attachment is delivered and the user opens it.

**How to avoid:**

- All release requests for quarantined messages flagged by the PHISH-EMAIL-001 rule
  must be reviewed by a SOC analyst before approval. Automate a hold on release
  approvals for messages with this alert tag.
- Communicate to helpdesk that quarantine releases require SOC sign-off during active
  investigations.

---

### Mistake 4: Treating GET Without POST as "Not Compromised" and Closing

**What happens:** Proxy logs show a user clicked the link (GET, HTTP 200) but no POST
is observed. The analyst closes the credential-compromise concern as unconfirmed and
takes no account action. The user had submitted credentials via a non-proxied path
(mobile device, personal laptop, direct connection) that the proxy did not log.

**How to avoid:**

- A GET to a phishing URL should always trigger a user notification and a 7-day
  account monitoring period, even without a confirmed POST.
- Ask the user directly whether they entered any information on the page. User
  self-reporting, combined with proxy evidence, gives a more complete picture.
- Check whether the user has any devices that bypass the proxy (MDM, mobile, VPN split
  tunnelling) and query those log sources if available.

---

### Mistake 5: Password Reset Without Session Revocation

**What happens:** The Identity team resets the password for a compromised account.
The adversary, already authenticated with a valid session token, continues operating
using the existing session — which remains valid even after a password change in many
identity platforms unless sessions are explicitly revoked.

**How to avoid:**

- Password reset and session revocation must be performed together.
- "Sign out all devices" or "Revoke all refresh tokens" must be explicitly
  requested in the containment ticket, not assumed to happen automatically.

---

### Mistake 6: Sending a Global All-Staff Alert About the Phishing Campaign

**What happens:** A well-intentioned analyst sends a company-wide email warning all
employees about the phishing campaign, including the subject line and sender address
in the notification. The adversary (who may have an inside view via a compromised
account or is monitoring) updates the campaign with a new subject and domain before
the warning reaches most employees.

**How to avoid:**

- Send targeted notifications only to confirmed recipients of the phishing campaign,
  not organisation-wide.
- Do not include the full subject line or sender address in broad communications —
  provide enough to prompt awareness without providing a roadmap for campaign evasion.
- Coordinate notification timing with block completion — block first, then notify.

---

*Playbook version 1.0 — Synthetic lab environment. Review and adapt all thresholds,
team names, and tool references before use in a production SOC.*
