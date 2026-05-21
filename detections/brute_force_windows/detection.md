# Detection: Windows Brute Force (T1110)

## Detection Objective

Identify authentication brute force attempts against Windows systems by detecting
an abnormal volume of EventID 4625 (failed logon) events within a short time
window, grouped by source IP and/or target user.

Two distinct sub-patterns are detected separately because their aggregation keys
and tuning thresholds differ:

| Variant | Aggregation Key | Behavioral Signal |
|---------|----------------|-------------------|
| A — Password Guessing | SourceIP + TargetUser | High failure rate against one account |
| B — Password Spray | SourceIP only | Low-and-slow failures across many accounts |

---

## Variant A: Password Guessing (T1110.001)

**Signal:** One source IP hammers one user account with many passwords rapidly.

### Detection Logic (Pseudo-KQL / Sigma-style)

```
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(5m)
| summarize
    FailureCount = count(),
    FirstSeen    = min(TimeGenerated),
    LastSeen     = max(TimeGenerated),
    SubStatuses  = make_set(SubStatus)
  by SourceIP = IpAddress, TargetUser = TargetUserName
| where FailureCount > 10
| extend DurationSec = datetime_diff('second', LastSeen, FirstSeen)
| extend FailuresPerMin = round((FailureCount * 60.0) / DurationSec, 1)
| project FirstSeen, LastSeen, SourceIP, TargetUser,
          FailureCount, DurationSec, FailuresPerMin, SubStatuses
| order by FailureCount desc
```

**Threshold:** `FailureCount > 10` failures against a single (SourceIP, TargetUser)
pair within a 5-minute sliding window.

**Trigger condition in simulated_logs.log:** 20 failures from `203.0.113.10`
against `admin1` between `08:31:02Z` and `08:32:37Z` (95 seconds).

### Key Fields to Inspect on Alert

| Field | What to Look For |
|-------|-----------------|
| `SubStatus` | `0xC000006A` = valid user, wrong password — confirms account exists |
| `SubStatus` | `0xC0000064` = username not found — attacker guessing usernames too |
| `LogonType` | 3 (Network/SMB) or 10 (RDP) — identifies attacked service |
| `DurationSec` | Very short duration + high count = automated tool |
| `SourcePort` | Incrementing ports suggest scripted/sequential connection attempts |

---

## Variant B: Password Spray (T1110.003)

**Signal:** One source IP tries the same password(s) against many accounts slowly,
staying under per-account lockout thresholds.

### Detection Logic (Pseudo-KQL / Sigma-style)

```
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(30m)
| summarize
    FailureCount    = count(),
    UniqueUsers     = dcount(TargetUserName),
    TargetUserList  = make_set(TargetUserName),
    FirstSeen       = min(TimeGenerated),
    LastSeen        = max(TimeGenerated)
  by SourceIP = IpAddress
| where UniqueUsers >= 5
| where FailureCount <= (UniqueUsers * 3)       // low attempts per user = spray
| project FirstSeen, LastSeen, SourceIP,
          UniqueUsers, FailureCount, TargetUserList
| order by UniqueUsers desc
```

**Thresholds:**
- `UniqueUsers >= 5` distinct accounts targeted from one IP within 30 minutes
- `FailureCount <= UniqueUsers * 3` — guards against misclassifying a
  standard brute force as a spray (spray has ~1–2 attempts per account)

**Trigger condition in simulated_logs.log:** `203.0.113.10` attempts 8 distinct
accounts (`user1`, `user2`, `svc_account1`, `analyst1`, `user3`, `helpdesk1`,
`admin1`, `user4`) between `09:15:01Z` and `09:18:31Z`.

### Additional Spray Indicators

- `SubStatus=0xC000006A` (wrong password, valid user) across all accounts
  suggests attacker has a valid user list
- Highly regular inter-event timing (e.g., exactly 30 seconds between attempts)
  suggests automated tooling with rate-limiting logic
- Targets include service accounts (`svc_account1`) — a common spray escalation
  path because service accounts often have non-expiring passwords

---

## False Positives

| Scenario | Why It Fires | How to Distinguish |
|----------|-------------|-------------------|
| User mistyping their own password | Genuine mistakes can generate 3–5 failures before a correct logon | Low failure count; followed by EventID 4624 (success) from same user/IP; occurs during business hours |
| Password manager / cached credentials after rotation | App or browser retries old password repeatedly | Source is a known internal workstation; EventID 4624 follows once correct credentials propagate |
| Scheduled task or service with outdated credentials | Service restarts generate regular, high-frequency failures | `LogonType=5` (service) or `LogonType=4` (batch); consistent interval; source is internal server |
| IT helpdesk bulk account testing | Helpdesk tooling may test many accounts | Source IP is a known helpdesk subnet; business hours; change request ticket correlates |
| VPN / MFA gateway retries | Some VPN gateways retry auth on timeout | Source IP is the VPN concentrator (known infra); LogonType 3; regular interval |

---

## Tuning

### Threshold Tuning

| Parameter | Default | Rationale for Change |
|-----------|---------|---------------------|
| Variant A failure count | `> 10 / 5 min` | Lower to 5 in high-security environments; raise to 20 in noisy environments after baselining |
| Variant B unique user count | `>= 5 / 30 min` | Lower to 3 if environment has small user population (< 50 accounts) |
| Variant B time window | 30 minutes | Extend to 60 min for slow-and-low spray campaigns; correlate with threat intel |

### Allowlists

Create exclusion rules for known-benign high-volume sources **only after
verifying** the source is truly safe:

```
// Example: exclude known VPN gateway from Variant A
| where IpAddress != "192.0.2.50"    // VPN concentrator — benign high-volume source

// Example: exclude service account from Variant B (monitor separately)
| where TargetUserName != "svc_account1"
```

> Do not allowlist by source IP alone without also scoping by LogonType or
> target. An allowlisted VPN IP that gets compromised becomes a blind spot.

### Time Window Guidance

| Environment Condition | Recommended Window |
|-----------------------|-------------------|
| Automated attack tool (hydra, ncrack) | 1–5 minutes (high speed) |
| Slow credential spray | 30–60 minutes |
| Distributed spray (multiple source IPs) | Requires IP range grouping; 60+ minutes |

### Suppression

After a true positive is confirmed and the source IP is blocked, suppress
further alerts from that IP for 24 hours to prevent alert fatigue during
containment while maintaining visibility on new sources.
