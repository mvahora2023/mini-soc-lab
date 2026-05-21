# Detection: Phishing Email (T1566)

## Detection Objective

Identify inbound phishing emails at two detection layers:

1. **Email gateway layer** — detect before delivery, based on authentication failures,
   suspicious attachment types, and lookalike sender domains.
2. **Proxy / DNS layer** — detect post-delivery URL clicks when the gateway missed
   the email, using click telemetry as a late-stage signal.

Two variants are detected separately because their data sources, aggregation logic,
and urgency differ significantly:

| Variant | Layer | Primary Signal | Urgency |
|---------|-------|---------------|---------|
| A — Spearphishing Attachment (T1566.001) | Email gateway | Auth fail + macro attachment | High — quarantine first, triage second |
| B — Spearphishing Link (T1566.002) | Email gateway + Proxy | Auth fail + URL in body + click event | Critical if POST follows GET — possible credential submission |

---

## Variant A: Spearphishing Attachment (T1566.001)

**Signal:** Email fails SPF and DKIM, has no valid DMARC alignment, and carries
a macro-enabled or otherwise high-risk attachment type.

### Detection Logic (Pseudo-query / Tool-agnostic)

```
EmailGatewayLog
| where Action IN ("QUARANTINE", "DELIVERED", "JUNK")
| where SPFResult IN ("FAIL", "SOFTFAIL")
| where DKIMResult IN ("FAIL", "NONE")
| where AttachmentCount > 0
| where AttachmentName matches_regex
    r"\.(xlsm|docm|xltm|dotm|xlam|pptm|exe|dll|iso|img|lnk|js|vbs|hta|wsf)$"
| summarize
    RecipientCount  = dcount(To),
    RecipientList   = make_set(To),
    UniqueHashes    = dcount(AttachmentHash),
    Subjects        = make_set(Subject),
    FirstSeen       = min(Timestamp),
    LastSeen        = max(Timestamp)
  by From, AttachmentName, AttachmentHash, SourceIP
| where RecipientCount >= 2              // single misdirected email vs campaign
| project FirstSeen, LastSeen, From, SourceIP, AttachmentName, AttachmentHash,
          RecipientCount, RecipientList, Subjects
| order by RecipientCount desc
```

**Key threshold:** `RecipientCount >= 2` distinguishes a targeted campaign from a
single misdirected email. A single failed-auth email with a macro attachment warrants
investigation but not an automatic high-severity alert.

**High-risk attachment extensions:**

| Category | Extensions |
|----------|-----------|
| Macro-enabled Office | `.xlsm`, `.docm`, `.xltm`, `.dotm`, `.xlam`, `.pptm` |
| Executable / dropper | `.exe`, `.dll`, `.iso`, `.img` (container-mounted dropper) |
| Script / shortcut | `.js`, `.vbs`, `.hta`, `.wsf`, `.lnk` |

### Supplemental Signal — Identical Hash Across Recipients

```
EmailGatewayLog
| where AttachmentHash != ""
| summarize RecipientCount = dcount(To), FirstSeen = min(Timestamp)
  by AttachmentHash, From, AttachmentName
| where RecipientCount >= 3
```

Identical attachment hash across 3+ recipients is a strong campaign indicator.
Prioritise for immediate hash-based blocking at the gateway and EDR.

---

## Variant B: Spearphishing Link (T1566.002)

### Sub-variant B1: Gateway Detection (Pre-click)

**Signal:** Email fails SPF/DKIM, contains a URL in the body, and the sender domain
is newly registered, does not resolve, or is a known-lookalike pattern.

```
EmailGatewayLog
| where Action IN ("DELIVERED", "JUNK")   // missed or soft-blocked
| where SPFResult IN ("FAIL", "SOFTFAIL")
| where URLCount > 0
| where URLCategory IN ("UNCATEGORIZED", "NEWLY_REGISTERED", "SUSPICIOUS", "PHISHING")
       OR URLDomain matches_regex r"(login|verify|account|portal|secure|update|alert)\."
| summarize
    RecipientCount = dcount(To),
    RecipientList  = make_set(To),
    UniqueURLs     = dcount(URL1),
    FirstSeen      = min(Timestamp),
    LastSeen       = max(Timestamp)
  by From, SourceIP, Subject
| where RecipientCount >= 2
| project FirstSeen, LastSeen, From, SourceIP, Subject, RecipientCount, RecipientList
```

**Note on unique-per-recipient URLs:** Adversaries often append a unique tracking
token per recipient (e.g., `?token=abc123`). Group by URL *domain* rather than full
URL to avoid undercounting campaign breadth.

### Sub-variant B2: Proxy Click Detection (Post-delivery)

**Signal:** A user's workstation makes an HTTP GET to a URL found in a recently
delivered suspicious email, followed within 30 seconds by an HTTP POST to the same
host — consistent with form submission (credential entry).

```
ProxyLog
| where URLCategory IN ("UNCATEGORIZED", "NEWLY_REGISTERED", "SUSPICIOUS", "PHISHING")
| where HTTPMethod == "GET"
| join kind=inner (
    ProxyLog
    | where HTTPMethod == "POST"
    | where URLCategory IN ("UNCATEGORIZED", "NEWLY_REGISTERED", "SUSPICIOUS", "PHISHING")
  ) on User, URLDomain
| where PostTimestamp between (GetTimestamp .. GetTimestamp + 60s)
| project User, SrcIP, URLDomain, GetTimestamp, PostTimestamp,
          GetURL, PostURL, BytesSentOnPost
| order by GetTimestamp asc
```

**Why GET + POST matters:** A GET to an uncategorised URL is low-confidence alone
(could be a preview). A POST within seconds is consistent with a form submission —
the most direct proxy-layer signal of credential harvesting.

---

## False Positives

| Scenario | Why It Fires | How to Distinguish |
|----------|-------------|-------------------|
| Marketing or newsletter emails | Many bulk senders have poor SPF/DKIM hygiene | Sender domain is known; unsubscribe link present; no lookalike domain pattern; URLCategory = MARKETING |
| Vendor invoices from shared SMTP infrastructure | Third-party billing platforms may fail DKIM for the vendor's domain | Sender IP resolves to a known ESP (SendGrid, Mailchimp, etc.); subject matches known vendor workflow |
| Internal IT password reminder | May share subject keywords with phishing | Sender IP is internal mail relay; SPF PASS; DKIM PASS |
| User testing phishing simulation | Security awareness platforms send deliberate phishing simulation emails | SourceIP matches known simulation vendor; Subject or URL matches simulation campaign list |
| Single failed-auth email with attachment | Could be a misdirected external email with a real attachment | RecipientCount = 1; hash not seen before; no campaign pattern across recipients |

---

## Tuning

### Threshold Tuning

| Parameter | Default | When to Adjust |
|-----------|---------|---------------|
| RecipientCount threshold (campaign) | `>= 2` | Lower to 1 for VIP accounts (C-suite, finance, admin) where even a single targeted email warrants investigation |
| POST-follows-GET window | 60 seconds | Extend to 120s if users often pause between clicking and submitting; shrink to 30s for high-confidence signal |
| Attachment extension list | See above | Add `.one` (OneNote dropper), `.zip/.rar` if password-protected archives are weaponised in your environment |

### Allowlists

```
// Exclude known simulation vendor IPs from campaign alert
| where SourceIP NOT IN known_phishing_simulation_ips

// Exclude known marketing platforms by ASN
| where SenderASN NOT IN known_email_service_provider_asns

// Exclude known-legitimate high-volume senders with poor auth records
| where From NOT IN curated_bulk_sender_allowlist
```

> Allowlists for phishing detections carry risk. Review every allowlist entry
> quarterly — a compromised bulk sender or ESP would be hidden by an allowlist.

### DMARC Policy Tiers

| DMARC Policy | Gateway Behaviour | Analyst Implication |
|-------------|------------------|---------------------|
| `reject` | Hard block at gateway | Email never arrives; alert fires on attempted delivery |
| `quarantine` | Send to quarantine folder | Analyst triage required; user cannot access without release |
| `none` | Deliver; monitoring only | Email arrives in inbox; only proxy/endpoint can catch post-delivery |

A domain with `DMARC=none` (as in Scenario B) provides no enforcement — the email
is delivered regardless of SPF/DKIM result. Detection shifts entirely to the proxy
and endpoint layer after delivery.
