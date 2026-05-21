# Triage Report: BF-001 — Windows Brute Force (T1110)

| Field | Value |
|-------|-------|
| Report ID | BF-001 |
| Date | 2024-11-14 |
| Analyst | analyst1 |
| Alert Rule | BF-WIN-001 — Windows Brute Force (Excessive 4625) |
| Severity | High |
| Status | **Escalate — True Positive** |
| MITRE Technique | T1110.001 (Password Guessing), T1110.003 (Password Spraying) |
| Log Source | Windows Security Event Log — DC-01 |

---

## 1. Executive Summary

On 2024-11-14, two sequential brute force campaigns were detected originating from a
single external source IP (`203.0.113.10`) against domain controller `DC-01`. The
first campaign targeted a single privileged account (`admin1`) with 20 failed logon
attempts in 95 seconds — consistent with an automated password-guessing tool. The
second campaign, beginning 43 minutes later from the same source IP, shifted to a
password-spray pattern across 8 distinct accounts over 3.5 minutes, rotating through
service and analyst accounts. No successful logon (EventID 4624) was observed in the
synthetic log set. The combination of two distinct attack patterns from one source,
including targeting of privileged and service accounts, warrants escalation and
immediate containment.

---

## 2. Five W's + How

### Who — Target Accounts

**Scenario A (Password Guessing):**

| Account | Type | Attack Window |
|---------|------|---------------|
| `admin1` | Privileged / administrative | 08:31:02Z – 08:32:37Z |

**Scenario B (Password Spray):**

| Account | Type | Attack Window |
|---------|------|---------------|
| `user1` | Standard user | 09:15:01Z |
| `user2` | Standard user | 09:15:31Z |
| `svc_account1` | Service account | 09:16:01Z |
| `analyst1` | SOC / analyst role | 09:16:31Z |
| `user3` | Standard user | 09:17:01Z |
| `helpdesk1` | IT support role | 09:17:31Z |
| `admin1` | Privileged / administrative | 09:18:01Z |
| `user4` | Standard user | 09:18:31Z |

The adversary appears to have a working account enumeration list. The inclusion of
`svc_account1` and `helpdesk1` suggests a list with both user and service accounts —
a common artifact of OSINT, prior breach data, or directory enumeration.

---

### What — Pattern Detected

Two distinct credential attack sub-techniques were observed in sequence from the same
source IP within a single 43-minute window:

1. **T1110.001 — Password Guessing:** High-velocity, single-account targeting of
   `admin1`. 20 failures in 95 seconds (~12.6 failures/minute). SubStatus
   `0xC000006A` on all entries confirms the username is valid and the adversary was
   cycling passwords.

2. **T1110.003 — Password Spraying:** After the guessing campaign, the same source IP
   shifted to a slow, distributed pattern — one attempt per account, ~30 seconds
   apart — across 8 accounts. This pacing is characteristic of tooling designed to
   stay under per-account lockout thresholds while maximizing account coverage.

The transition from guessing to spraying suggests an adversary who either adapted
their approach in real time (guessing failed → rotate strategy) or was executing a
scripted multi-phase credential attack.

---

### When — Time Window

| Event | Timestamp (UTC) |
|-------|----------------|
| First observed failure (Scenario A) | 2024-11-14 08:31:02Z |
| Last observed failure (Scenario A) | 2024-11-14 08:32:37Z |
| Gap between campaigns | ~43 minutes |
| First observed failure (Scenario B) | 2024-11-14 09:15:01Z |
| Last observed failure (Scenario B) | 2024-11-14 09:18:31Z |
| Total observed attack window | ~47 minutes |

Both campaigns fall outside typical business-hours activity for an internal actor.
The inter-campaign gap (43 minutes) may reflect the adversary pausing to analyze
results from Scenario A before pivoting.

---

### Where — Source IP and Target Host

| Indicator | Value | Notes |
|-----------|-------|-------|
| Source IP | `203.0.113.10` | External; RFC 5737 documentation range in this lab |
| Target host | `DC-01` | Simulated Windows Server 2019 domain controller |
| LogonType | `3` (Network / SMB) | Both scenarios; not RDP — suggests SMB or NTLM relay surface |
| Source ports | Incrementing (51201–51220, 52001–52008) | Sequential port selection is characteristic of automated tools |

The source IP is the same for both attack phases. In a real SOC, this would prompt
immediate threat intel enrichment (passive DNS, prior abuse reports, geolocation,
ASN) before drawing conclusions.

---

### Why — Attacker Objective Hypothesis

The attack sequence is consistent with an adversary attempting to gain initial access
to the domain environment by compromising a valid Windows domain credential. Likely
objectives, in order of adversary priority:

1. **Privileged access via `admin1`** — the initial guessing campaign directly
   targeted the administrative account, suggesting the adversary identified it as
   high-value (possibly through OSINT or prior reconnaissance).
2. **Fallback to lower-privilege access** — when `admin1` guessing failed, the spray
   pivot attempts to compromise any account that can then be used for lateral movement
   or further enumeration.
3. **Service account compromise** — the inclusion of `svc_account1` in the spray list
   is notable; service accounts frequently have non-expiring passwords and broad
   resource permissions, making them high-value targets for persistence.

No data in the synthetic log set indicates successful access, but the goal appears
to be domain account compromise as a precursor to deeper intrusion.

---

### How — Evidence Chain

The attack progressed in four observable steps:

```
[1] Adversary identifies DC-01 as an SMB/NTLM authentication target (LogonType=3)
        ↓
[2] Automated guessing tool connects sequentially (ports 51201–51220) and cycles
    passwords against admin1 → 20x EventID=4625 / SubStatus=0xC000006A in 95s
        ↓
[3] Guessing campaign ends; 43-minute gap (analysis / tool pivot)
        ↓
[4] Same source IP re-engages with spray pattern: 1 attempt per account, ~30s
    cadence, 8 distinct accounts over 3.5 minutes
```

---

## 3. Evidence

### Quoted Log Lines (Synthetic)

**Scenario A — Opening and closing failures, showing the burst:**

```
2024-11-14T08:31:02Z EventID=4625 TargetUser=admin1 Domain=LAB LogonType=3 SourceIP=203.0.113.10 SourcePort=51201 Status=0xC000006D SubStatus=0xC000006A WorkstationName=- FailureReason="Wrong password"
2024-11-14T08:31:07Z EventID=4625 TargetUser=admin1 Domain=LAB LogonType=3 SourceIP=203.0.113.10 SourcePort=51202 Status=0xC000006D SubStatus=0xC000006A WorkstationName=- FailureReason="Wrong password"
2024-11-14T08:32:37Z EventID=4625 TargetUser=admin1 Domain=LAB LogonType=3 SourceIP=203.0.113.10 SourcePort=51220 Status=0xC000006D SubStatus=0xC000006A WorkstationName=- FailureReason="Wrong password"
```

**Scenario B — Spray pattern, two accounts, 30-second cadence:**

```
2024-11-14T09:15:01Z EventID=4625 TargetUser=user1    Domain=LAB LogonType=3 SourceIP=203.0.113.10 SourcePort=52001 Status=0xC000006D SubStatus=0xC000006A WorkstationName=- FailureReason="Wrong password"
2024-11-14T09:16:01Z EventID=4625 TargetUser=svc_account1 Domain=LAB LogonType=3 SourceIP=203.0.113.10 SourcePort=52003 Status=0xC000006D SubStatus=0xC000006A WorkstationName=- FailureReason="Wrong password"
```

### Aggregate Counts

| Metric | Scenario A | Scenario B |
|--------|-----------|-----------|
| Total EventID=4625 failures | 20 | 8 |
| Duration | 95 seconds | 210 seconds |
| Failures per minute | ~12.6 | ~2.3 |
| Distinct TargetUsers | 1 (`admin1`) | 8 |
| Distinct SourceIPs | 1 | 1 |
| SubStatus code(s) | `0xC000006A` (all) | `0xC000006A` (all) |
| LogonType | 3 (all) | 3 (all) |
| Successful logon (4624) observed | No | No |
| Account lockout (4740) observed | No | No |

**SubStatus note:** `0xC000006A` on every failure means the username was valid and
the password was wrong across both scenarios. The adversary was not guessing
usernames — they had a pre-built valid account list.

---

## 4. Analysis

### Why This Is a True Positive, Not a False Positive

Three observable properties together distinguish this from benign failure bursts:

| Property | Benign Behavior | This Alert |
|----------|----------------|------------|
| Failure velocity | 1–5 failures, trailing off | 20 in 95s, uniform cadence |
| Source port pattern | Single or stable connection | Incrementing ports 51201–51220 (new TCP conn per attempt) |
| Account targeting pattern | One user, one machine, one time | Guessing → spray pivot; 8 distinct accounts |
| SubStatus consistency | Mixed (bad user / bad pass) | 100% `0xC000006A` — valid users, scripted password cycling |
| Inter-event timing | Irregular (human typing) | Exactly 5 seconds (Scenario A), exactly 30 seconds (Scenario B) |

No benign scenario — mistyped password, stale cached credentials, scheduled task,
VPN retry — produces two sequentially distinct attack patterns from one external IP
targeting privileged and service accounts on a domain controller.

### Additional Data to Check in a Real SOC

These steps are not available in the synthetic log set but would be performed before
finalizing the verdict in a production environment:

1. **Check for EventID 4624 (success)** — Query the full Security log for any
   successful logon from `203.0.113.10` in the same time window. A success after the
   failures is a compromise indicator requiring immediate escalation.

2. **Threat intel enrichment on source IP** — Run `203.0.113.10` through threat intel
   platforms (VirusTotal, AbuseIPDB, Shodan) to check for prior abuse reports, known
   scanning infrastructure, or geolocation anomalies.

3. **Check for EventID 4740 (account lockout)** — Confirm whether `admin1` or any
   sprayed accounts triggered lockout. Absence of lockout despite 20 failures
   suggests the lockout threshold may be misconfigured or too permissive.

4. **Review network flows / firewall logs** — Confirm whether `203.0.113.10` is
   reachable from the internet or only from an internal network segment. An external
   IP reaching a domain controller's SMB port (445) is itself an architecture finding.

5. **Baseline comparison** — Compare the failure volume against a 30-day historical
   baseline for DC-01 to rule out a legitimate high-failure source (e.g., a VPN
   gateway) that was not in the allowlist.

6. **Check `admin1` recent logon history** — Review successful logons for `admin1`
   in the prior 7 days to establish a normal pattern and detect any anomalous
   pre-existing access.

---

## 5. Decision

**Verdict: True Positive — Escalate**

**Justification:**

- 20 failed logons in 95 seconds from a single external IP against a privileged
  domain account is well above threshold (rule: >10 in 5 minutes) with no benign
  explanation.
- The pivot to a password spray 43 minutes later from the same IP demonstrates
  adversary persistence and intentionality — this is not a one-time event.
- `0xC000006A` on every failure confirms the adversary holds a valid account list,
  indicating prior reconnaissance or credential exposure.
- A domain controller being targeted over SMB (LogonType 3) from what appears to be
  an external source is a critical attack surface finding independent of whether the
  brute force succeeded.
- No evidence of successful compromise was found in this log set, but absence of
  evidence is not evidence of absence — log completeness must be verified.

This alert meets the criteria for **Tier 2 escalation** and simultaneous initiation
of short-term containment actions.

---

## 6. Recommended Actions

### Short-Term Containment

| Priority | Action | Owner |
|----------|--------|-------|
| P1 — Immediate | Block `203.0.113.10` at the perimeter firewall and any host-based firewall on DC-01. | Network / Firewall team |
| P1 — Immediate | Force password reset for `admin1`. If compromise is confirmed, disable the account and issue a new one. | Identity / AD team |
| P2 — Same day | Verify no EventID 4624 (successful logon) exists from `203.0.113.10` across all domain controllers and member servers. | SOC Tier 2 |
| P2 — Same day | Check account lockout status for all 8 sprayed accounts; reset any that are locked. | Identity / AD team |
| P2 — Same day | Confirm DC-01 Security Event Log completeness — verify no log gaps exist in the attack window. | SOC Tier 1 |

### Longer-Term Hardening

| Priority | Recommendation | Rationale |
|----------|---------------|-----------|
| H1 | Restrict SMB (445) and RDP (3389) on domain controllers to only internal trusted subnets. External IP reaching DC-01 over SMB is the root architecture finding. | Eliminate the attack surface entirely |
| H2 | Lower the account lockout threshold if currently > 10 failures. NIST SP 800-63B recommends lockout after a small number of failed attempts with exponential backoff. | 20 failures without lockout suggests threshold is too permissive |
| H3 | Enable MFA for all privileged accounts (`admin1` and equivalent). Brute force against MFA-protected accounts is significantly less effective. | Defense-in-depth for credential attacks |
| H4 | Implement credential monitoring: alert when any domain account appears in breach databases (HaveIBeenPwned Enterprise, Microsoft Entra ID Protection). | The valid account list suggests prior exposure |
| H5 | Review service account (`svc_account1`) password age and privilege scope. Service accounts with non-expiring passwords and broad permissions are high-value spray targets. | Reduce blast radius if compromised |
| H6 | Deploy a detection rule for sequential incrementing source ports from a single IP (Variant A indicator) as an additional high-precision signal. | Catch scripted tools before failure count threshold is reached |

---

*Report authored by: analyst1 | Log source: DC-01 Windows Security Event Log | Data: synthetic lab only*
