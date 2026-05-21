# Triage Report: PH-001 — Phishing Email Campaign (T1566)

| Field | Value |
|-------|-------|
| Report ID | PH-001 |
| Date | 2024-11-15 |
| Analyst | analyst1 |
| Alert Rule | PHISH-EMAIL-001 — Phishing Email Campaign |
| Severity | **Critical** (Variant B2: credential submission suspected for 2 users) |
| Status | **Escalate — True Positive / Active Credential Compromise Suspected** |
| MITRE Technique | T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link) |
| Log Sources | Email Gateway Log, Web Proxy Log |
| Affected Users | user1, user2, user3, analyst1, helpdesk1 (all received); user1, user2 (clicked + POST) |

---

## 1. Executive Summary

On 2024-11-15, two sequential phishing campaigns were detected targeting five internal
accounts from two distinct source IPs. The first campaign (Scenario A, 09:10–09:24Z)
delivered macro-enabled Excel attachments via emails that failed all three authentication
checks (SPF, DKIM, DMARC); the email gateway quarantined all five messages before
delivery. The second campaign (Scenario B, 14:30–14:44Z) delivered credential-harvesting
link emails that the gateway soft-flagged but did not block due to a SOFTFAIL-only
DMARC policy. Proxy logs confirm two users (`user2` at 14:38Z and `user1` at 14:41Z)
clicked the link and submitted HTTP POST requests to the harvesting endpoint — consistent
with credential entry on the phishing page. This report is escalated as a **Critical
true positive** due to suspected credential compromise for `user1` and `user2`.

---

## 2. Five W's + How

### Who — Targeted Accounts

| User | Scenario A (Email Received) | Scenario A (Attachment Opened) | Scenario B (Email Received) | Scenario B (Link Clicked) | Scenario B (POST Submitted) |
|------|-----------------------------|-------------------------------|-----------------------------|--------------------------|-----------------------------|
| user1 | Yes — quarantined | No | Yes — delivered | Yes (14:41Z) | Yes (14:41:06Z) — HIGH RISK |
| user2 | Yes — quarantined | No | Yes — delivered | Yes (14:38Z) | Yes (14:38:14Z) — HIGH RISK |
| user3 | Yes — quarantined | No | Yes — delivered | No | No |
| analyst1 | Yes — quarantined | No | Yes — delivered | No | No |
| helpdesk1 | Yes — quarantined | No | Yes — delivered | No | No |

**Priority for immediate action:** `user1` and `user2` — POST events indicate
credential submission. `user3`, `analyst1`, and `helpdesk1` received Scenario B
emails but no click was observed in this log set.

---

### What — Pattern Detected

**Scenario A (T1566.001 — Attachment):**
Five phishing emails with identical attachment (`Q4_Compensation_Review.xlsm`,
SHA-256: `3f4a8b2c...`) failed SPF, DKIM, and DMARC and were quarantined. The
identical hash across all five messages confirms a single weaponised file used in a
coordinated campaign. The `.xlsm` extension is a macro-enabled Excel workbook — a
common dropper format for loader or stealer malware.

**Scenario B (T1566.002 — Link):**
Five emails delivered to inbox from `it-support@accounts-portal.example`, impersonating
an internal IT portal with a password-expiry urgency lure. SPF returned SOFTFAIL; DKIM
and DMARC were absent. The DMARC policy for the domain was `none` (monitor only), so
the gateway delivered rather than quarantined. Each email contained a unique per-recipient
URL tracking token — a common adversary technique to identify which users interact
with the campaign. Two users clicked and subsequently submitted POST requests.

---

### When — Time Windows

| Event | Timestamp (UTC) |
|-------|----------------|
| First Scenario A email quarantined | 2024-11-15 09:10:44Z |
| Last Scenario A email quarantined | 2024-11-15 09:24:31Z |
| Scenario A duration | ~14 minutes |
| First Scenario B email delivered | 2024-11-15 14:30:19Z |
| Last Scenario B email delivered | 2024-11-15 14:44:07Z |
| Scenario B delivery duration | ~14 minutes |
| Gap between campaigns | ~5 hours |
| user2 link click (GET) | 2024-11-15 14:38:12Z |
| user2 form submission (POST) | 2024-11-15 14:38:14Z |
| user1 link click (GET) | 2024-11-15 14:41:03Z |
| user1 form submission (POST) | 2024-11-15 14:41:06Z |

The gap between campaigns (5 hours) may indicate a different adversary operator
session or a deliberate re-targeting after the attachment campaign failed. The
2-second GET-to-POST interval for both users suggests no hesitation — the
credential-harvesting page prompted immediate form submission.

---

### Where — Source Infrastructure

| Indicator | Scenario A | Scenario B |
|-----------|-----------|-----------|
| Sender domain | `hr-documents.example` | `accounts-portal.example` |
| From display name | "HR Documents" | "IT Support Portal" |
| Source MTA IP | `203.0.113.20` | `203.0.113.21` |
| Attachment / URL host | N/A | `203.0.113.99` |
| User source IPs (proxy) | N/A | `192.0.2.102` (user2), `192.0.2.101` (user1) |

Both campaigns originate from the `203.0.113.0/24` documentation range in this
synthetic lab. Both sender domains use `.example` TLD (RFC 2606 reserved).

In a real SOC, WHOIS and passive DNS would be run on both sender domains and the
URL host IP to determine registration age, registrar, ASN, and hosting history —
all commonly indicative of adversary infrastructure when newly registered.

---

### Why — Attacker Objective Hypothesis

The two-campaign sequence suggests a deliberate two-stage strategy:

1. **Stage 1 (Scenario A):** Attempt to deliver a malware payload via macro-enabled
   attachment. Objective: establish a foothold on an endpoint. This failed — all
   emails were quarantined.
2. **Stage 2 (Scenario B):** Pivot to credential harvesting when the attachment
   approach did not result in confirmed payload delivery. Objective: steal valid
   domain credentials for use in subsequent access (T1078 — Valid Accounts).

The per-recipient URL token strongly suggests the adversary wanted to track which
accounts interact with the campaign — typical of targeted attacks where the adversary
values intelligence on active, monitored accounts.

If credentials were successfully harvested (consistent with the POST events), the
likely next objectives are:
- Authenticated access to corporate resources (VPN, email, SharePoint, O365)
- Lateral movement using valid credentials
- Persistence via new accounts, forwarding rules, or OAuth app grants

---

### How — Evidence Chain

```
[1] Scenario A: Adversary sends macro-enabled .xlsm to 5 recipients from 203.0.113.20
        ↓ All 5 quarantined (SPF FAIL + DKIM FAIL + DMARC quarantine policy)
        ↓ No user interaction with attachment
[2] ~5 hours later: Scenario B launched from 203.0.113.21 with link emails
        ↓ Gateway delivers (DMARC policy = none; SOFTFAIL only → no block)
        ↓ Emails arrive in user inboxes
[3] user2 clicks link at 14:38:12Z → GET to 203.0.113.99/portal/reset-password
        ↓ 2 seconds later: POST to /portal/reset-password/submit → credential entry
[4] user1 clicks link at 14:41:03Z → GET to 203.0.113.99/portal/reset-password
        ↓ 3 seconds later: POST to /portal/reset-password/submit → credential entry
[5] 3 remaining users (user3, analyst1, helpdesk1): email delivered, no click observed
```

---

## 3. Evidence

### Quoted Log Lines (Synthetic)

**Scenario A — First quarantined email:**

```
2024-11-15T09:10:44Z Action=QUARANTINE MsgID=<20241115091044.A1B2C3@hr-documents.example> From=no-reply@hr-documents.example FromDisplay="HR Documents" To=user1@lab.internal Subject="Action Required: Q4 Compensation Review" SourceIP=203.0.113.20 SPF=FAIL DKIM=FAIL DMARC=FAIL DMARCPolicy=quarantine AttachmentCount=1 AttachmentName=Q4_Compensation_Review.xlsm AttachmentHash=3f4a8b2c1d9e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a URLCount=0 Verdict=SUSPICIOUS Reason="SPF_FAIL DKIM_FAIL macro_enabled_attachment"
```

**Scenario B — Delivered email (gateway missed):**

```
2024-11-15T14:32:44Z Action=DELIVERED MsgID=<20241115143244.S1T2U3@accounts-portal.example> From=it-support@accounts-portal.example FromDisplay="IT Support Portal" To=user2@lab.internal Subject="Your account password expires in 24 hours - action required" SourceIP=203.0.113.21 SPF=SOFTFAIL DKIM=NONE DMARC=NONE DMARCPolicy=none AttachmentCount=0 URLCount=1 URL1="http://203.0.113.99/portal/reset-password?token=usr2_synthetic" Verdict=SUSPICIOUS Reason="SPF_SOFTFAIL lookalike_domain url_in_body"
```

**Proxy — user2 credential submission:**

```
2024-11-15T14:38:12Z User=user2 SrcIP=192.0.2.102 DestURL="http://203.0.113.99/portal/reset-password?token=usr2_synthetic" Method=GET ResponseCode=200 BytesSent=512 BytesRecv=14820 URLCategory=UNCATEGORIZED ProxyVerdict=ALLOW Referrer=EMAIL_CLIENT
2024-11-15T14:38:14Z User=user2 SrcIP=192.0.2.102 DestURL="http://203.0.113.99/portal/reset-password/submit" Method=POST ResponseCode=200 BytesSent=1240 BytesRecv=4096 URLCategory=UNCATEGORIZED ProxyVerdict=ALLOW Referrer="http://203.0.113.99/portal/reset-password?token=usr2_synthetic"
```

**Proxy — user1 credential submission:**

```
2024-11-15T14:41:03Z User=user1 SrcIP=192.0.2.101 DestURL="http://203.0.113.99/portal/reset-password?token=usr1_synthetic" Method=GET ResponseCode=200 ...
2024-11-15T14:41:06Z User=user1 SrcIP=192.0.2.101 DestURL="http://203.0.113.99/portal/reset-password/submit" Method=POST ResponseCode=200 BytesSent=1198 BytesRecv=4096 ...
```

### Aggregate Counts

| Metric | Scenario A | Scenario B |
|--------|-----------|-----------|
| Total emails | 5 | 5 |
| Distinct recipients | 5 | 5 |
| Gateway action | QUARANTINE (all 5) | DELIVERED (all 5) |
| SPF result | FAIL (all 5) | SOFTFAIL (all 5) |
| DKIM result | FAIL (all 5) | NONE (all 5) |
| Attachment hash (unique) | 1 — same across all 5 | N/A |
| URLs per email | 0 | 1 (unique token per recipient) |
| Users who clicked link | N/A | 2 of 5 |
| POST (form submission) events | N/A | 2 (user1, user2) |

---

## 4. Analysis

### Why This Is a True Positive, Not a False Positive

| Property | Benign Explanation | This Alert |
|----------|--------------------|-----------|
| SPF/DKIM/DMARC all FAIL (Scenario A) | Uncommon; occasionally seen from small vendors with poor hygiene | All three fail simultaneously; domain (`hr-documents.example`) has no prior sending history; new lookalike pattern |
| Identical attachment hash across 5 recipients | Occasionally seen in legitimate bulk mailings | A legitimate HR document would not share the same hash across targeted sends unless bulk — but bulk HR comms use legitimate infrastructure with passing auth |
| Macro-enabled .xlsm from external sender | Occasionally from finance vendors | Combined with failed auth and lookalike domain, no benign explanation holds |
| SPF SOFTFAIL + URL (Scenario B) | Marketing emails may SOFTFAIL | No marketing unsubscribe link; password urgency lure; per-recipient URL token is a campaign tracking technique, not a legitimate personalisation |
| GET + POST to uncategorised URL | Legitimate SaaS tools may be uncategorised initially | The URL host (`203.0.113.99`) has no business relationship; the POST followed the GET within 2–3 seconds; Referrer shows EMAIL_CLIENT origin |

No single factor is dispositive alone. The combination of failed authentication,
lookalike domain pattern, macro attachment, campaign breadth, per-recipient URL
tracking, and the GET+POST proxy signal together form a high-confidence true positive.

### Additional Data to Check in a Real SOC

1. **Attachment sandbox detonation** — Submit `Q4_Compensation_Review.xlsm` to a
   malware sandbox. Look for macro execution, network callback, or dropped payload.
   Identifies the malware family and any additional IOCs.

2. **Active Directory logon history for user1 and user2** — Query for EventID 4624
   (successful logon) for both accounts from unexpected source IPs in the 30 minutes
   following the POST events. Credential submission does not guarantee use, but logon
   from an unrecognised IP after submission would confirm active compromise.

3. **Email account audit for user1 and user2** — Check for new inbox rules
   (auto-forwarding to external addresses), new OAuth app grants, or email sent from
   the accounts in the post-incident window. Common adversary persistence after
   email credential theft.

4. **EDR telemetry on all 5 recipient workstations** — Although no attachment opens
   were observed (Scenario A was quarantined), confirm via EDR that no process
   launched from an Office application or browser in the incident window.

5. **Domain investigation on both sender domains** — WHOIS registration date, hosting
   ASN, certificate transparency records. Newly registered domains hosting credential
   harvesters often share infrastructure across campaigns.

6. **Retrospective proxy search for other users hitting same URL domain** — The 3
   non-clicking users are known from this log set, but confirm no other users
   organisation-wide hit `203.0.113.99` in the same window.

---

## 5. Decision

**Verdict: True Positive — Escalate / Critical**

**Justification:**

- Both campaigns are confirmed phishing based on authentication failures, domain
  pattern, and payload type (macro attachment, credential harvesting URL).
- Scenario A was fully mitigated by the gateway. No attachment delivery or user
  interaction occurred.
- Scenario B resulted in confirmed link clicks and HTTP POST submissions from
  `user1` and `user2` — the proxy evidence is consistent with credential entry on
  a harvesting page. These two accounts must be treated as compromised until proven
  otherwise.
- The 5-hour gap and infrastructure pivot between campaigns (different sender domain,
  different source IP, different payload method) indicates an adaptive adversary, not
  opportunistic spam.
- This alert meets the criteria for **Incident Response escalation** for `user1` and
  `user2` and **Tier 2 investigation** for the remaining three recipients.

---

## 6. Recommended Actions

### Short-Term Containment

| Priority | Action | Owner |
|----------|--------|-------|
| P1 — Immediate | Force password reset for `user1` and `user2`; disable active sessions | Identity / AD team |
| P1 — Immediate | Block sender domains (`hr-documents.example`, `accounts-portal.example`) and source IPs (`203.0.113.20`, `203.0.113.21`) at email gateway | Email security team |
| P1 — Immediate | Block `203.0.113.99` (URL host) at web proxy | Network team |
| P2 — Same day | Recall / delete Scenario B emails from all 5 recipient mailboxes | Email security team |
| P2 — Same day | Block attachment hash `3f4a8b2c...` at gateway and EDR IOC list | SOC Tier 2 |
| P2 — Same day | Audit `user1` and `user2` email accounts for forwarding rules and OAuth app grants | Identity / AD team |
| P3 — 24 hours | Send targeted security notification to all 5 recipients | SOC / Security Awareness |

### Longer-Term Hardening

| Priority | Recommendation | Rationale |
|----------|---------------|-----------|
| H1 | Enforce DMARC `reject` policy review — the Scenario B delivery occurred because the sender domain had DMARC `none` policy; strengthen internal gateway policy to quarantine on SOFTFAIL + uncategorised URL regardless of DMARC policy | Closes the delivery gap that allowed Scenario B to reach inboxes |
| H2 | Enable proxy SSL inspection for UNCATEGORISED URLs | Without TLS inspection, POST body content is blind; inspection would allow credential-in-form detection |
| H3 | Deploy phishing-resistant MFA (hardware key or passkey) for all accounts | Harvested passwords are useless if authentication requires a phishing-resistant second factor |
| H4 | Establish DMARC enforcement on all internal domains (policy: quarantine → reject) | Prevents external actors from spoofing `@lab.internal` domain against employees |

---

*Report authored by: analyst1 | Log sources: Email Gateway Log, Web Proxy Log | Data: synthetic lab only*
