# Playbook: Windows Brute Force Response (T1110)

| Field | Value |
|-------|-------|
| Playbook ID | PB-CRED-001 |
| Version | 1.0 |
| Last Reviewed | 2024-11-14 |
| Tactic | Credential Access (TA0006) |
| Technique | T1110 — Brute Force |
| Severity | High (default); Critical if successful logon follows |
| Owner | SOC Tier 1 (triage); SOC Tier 2 (escalation) |
| Related Alert | BF-WIN-001 |
| Related Detection | `detections/brute_force_windows/detection.md` |
| Related Triage Template | `triage-reports/brute_force_001.md` |

---

## 1. Purpose and Scope

### Purpose

This playbook provides a repeatable, step-by-step response procedure for analysts
handling Windows brute force alerts. It covers the full response lifecycle from
initial triage through containment, eradication, recovery, and documentation.

### Scope

This playbook applies when a detection rule or manual observation identifies an
abnormal volume of Windows EventID 4625 (failed logon) events consistent with:

- **Password guessing (T1110.001):** High-velocity repeated failures against a
  single account from a single source IP.
- **Password spraying (T1110.003):** Low-and-slow failures from a single source IP
  spread across many accounts to avoid per-account lockout thresholds.

### Out of Scope

- Credential dumping (T1003) — handled by a separate playbook.
- Pass-the-Hash / Pass-the-Ticket attacks — handled by a separate playbook.
- Account lockout storms caused by internal misconfigurations — use the
  "Account Lockout — Benign" runbook instead.

### Roles and Responsibilities

| Role | Responsibilities |
|------|----------------|
| SOC Tier 1 Analyst | Execute triage checklist; initial enrichment; determine verdict; escalate if warranted |
| SOC Tier 2 Analyst | Deep investigation; containment decision authority for privileged accounts; IR handoff |
| Identity / AD Team | Account lockout, password reset, access audit |
| Network / Firewall Team | Source IP block at perimeter |
| Incident Response | Engage if successful compromise is confirmed (EventID 4624 follows 4625 burst) |

---

## 2. Trigger Conditions

### Automated Alert Triggers

The following conditions should fire the BF-WIN-001 alert rule and activate this
playbook automatically:

**Variant A — Password Guessing (T1110.001)**

```
> 10 EventID=4625 failures from the same SourceIP against the same TargetUser
within a 5-minute window
LogonType IN (3, 10)   -- Network or RemoteInteractive only
SourceIP NOT IN allowlist
TargetUser NOT ending in "$"   -- exclude machine accounts
```

**Variant B — Password Spray (T1110.003)**

```
>= 5 distinct TargetUsers failed from the same SourceIP within 30 minutes
AND failures-per-user <= 3   -- distinguishes spray from guessing
LogonType IN (3, 10)
SourceIP NOT IN allowlist
```

### Manual Trigger Conditions

Activate this playbook manually when:

- An analyst directly observes a spike in 4625 events that did not fire an automated
  alert (e.g., volume was just under threshold).
- A user reports being unable to log in and IT confirms the account is locked
  (EventID 4740) without an obvious benign cause.
- Threat intel or a partner organisation reports an active credential attack campaign
  targeting your industry or IP range.
- An EventID 4624 (successful logon) is observed from a known-bad or unrecognised
  source IP, prompting a backwards look for preceding 4625 activity.

---

## 3. Required Data Sources

### Primary (Must Have for Triage)

| Event ID | Description | Fields Required |
|----------|-------------|----------------|
| **4625** | An account failed to log on | `TimeGenerated`, `TargetUserName`, `IpAddress`, `LogonType`, `SubStatus`, `WorkstationName` |

Confirm 4625 events are being collected from **all domain controllers and
member servers** in the environment. A gap in collection from any DC is a blind spot.

### Related (Check During Investigation)

| Event ID | Description | Why It Matters |
|----------|-------------|---------------|
| **4624** | An account successfully logged on | If a 4624 follows the 4625 burst from the same source, the attack succeeded |
| **4740** | A user account was locked out | Confirms the burst was large enough to trip lockout policy |
| **4648** | A logon was attempted using explicit credentials | May indicate credential relay or use of stolen credentials post-brute force |
| **4771** | Kerberos pre-authentication failed | Equivalent to 4625 for Kerberos; relevant on DCs |
| **4776** | The domain controller attempted to validate credentials (NTLM) | Appears alongside 4625 for NTLM authentication failures |

### Optional (Enrichment / Correlation)

| Source | Use |
|--------|-----|
| Firewall / proxy logs | Confirm SourceIP reachability; correlate inbound connections to DC ports (445, 3389) |
| DNS logs | Resolve SourceIP to hostname; check for newly observed domains |
| Threat intel platform | Check SourceIP reputation, ASN, geolocation, prior abuse reports |
| Network flow (NetFlow / sFlow) | Correlate connection volume to the 4625 burst window |
| EDR telemetry | Check for process activity on the target host during and after the attack window |

---

## 4. Triage Checklist

Work through these steps in order. Record findings at each step in the ticket.
Steps marked `[TIER 1]` should be completed by the first-response analyst.
Steps marked `[TIER 2]` indicate escalation may be appropriate before proceeding.

### Step 1 — Validate the Alert `[TIER 1]`

- [ ] Open the alert. Confirm it fired on EventID 4625 events, not a test or tuning run.
- [ ] Confirm the SourceIP is present and not null or `127.0.0.1` / `::1` (local logon — not in scope).
- [ ] Confirm LogonType is 3 (Network) or 10 (RemoteInteractive/RDP). If LogonType is 4 or 5, this is likely a service/scheduled task issue — see false positive guidance.
- [ ] Confirm TargetUserName does not end in `$` (machine accounts produce high-volume legitimate noise).
- [ ] Record: SourceIP, TargetUser(s), LogonType, total failure count, time window.

### Step 2 — Baseline the Failure Volume `[TIER 1]`

- [ ] Query 4625 events for the same SourceIP over the prior 30 days. Is this a new source, or has it appeared before at lower volumes?
- [ ] Query 4625 events for the same TargetUser over the prior 30 days. Does this user have a history of self-caused failures (e.g., frequent lockouts from a misconfigured app)?
- [ ] Compare current failure rate (failures/minute) to historical baseline. A rate more than 3× the 90th-percentile baseline is highly anomalous.

### Step 3 — Check SubStatus Codes `[TIER 1]`

- [ ] Pull `SubStatus` values from all 4625 events in the burst.

| SubStatus | Interpretation |
|-----------|---------------|
| `0xC000006A` (all or majority) | Valid username, wrong passwords — attacker has confirmed usernames; high confidence TP |
| `0xC0000064` (majority) | Attacker guessing usernames — may be noisier; check if any `0xC000006A` appear later |
| Mixed | Attacker may have a partial list; treat as TP until disproven |
| `0xC0000234` | Account already locked — failure burst may be ongoing from before lockout |

- [ ] Record the predominant SubStatus in the ticket.

### Step 4 — Check for Successful Logon `[TIER 1]`

- [ ] Query EventID **4624** for the same SourceIP and TargetUser combination in the
  window from 10 minutes before the first 4625 to 60 minutes after the last 4625.
- [ ] **If a 4624 is found:** Escalate immediately to Tier 2 and notify the IR lead.
  The attack may have succeeded. Do not proceed with solo triage — this is now an
  active incident.
- [ ] **If no 4624 is found:** Continue triage. Record finding: "No successful logon
  observed from SourceIP in the investigation window."

### Step 5 — Check Account Lockout Status `[TIER 1]`

- [ ] Query EventID **4740** for TargetUser(s) in the same window.
- [ ] If lockout was triggered: note the timestamp. The account is currently protected
  by lockout. Do not rush to unlock until the source is contained.
- [ ] If no lockout despite a high failure count: check if the lockout policy is
  configured and appropriate. A large burst with no lockout suggests the threshold
  may be too permissive — flag for hardening recommendation.

### Step 6 — Enrich the Source IP `[TIER 1]`

- [ ] Determine if the SourceIP is internal or external.
  - **External:** Proceed with block recommendation. Confirm it is not a shared egress
    IP (corporate VPN, NAT gateway) before blocking. See "Common Mistakes."
  - **Internal:** Investigate the internal host immediately. Brute force from inside
    the network is higher severity (could indicate a compromised workstation or an
    insider threat).
- [ ] Check SourceIP against threat intel (reputation, ASN, geolocation, prior abuse).
  Record the verdict.
- [ ] Check whether the SourceIP has made other connections to the environment (DNS,
  firewall, proxy) beyond port 445/3389.

### Step 7 — Assess Target Account Sensitivity `[TIER 1]`

- [ ] Determine the privilege level of the targeted account(s):
  - Domain Admin, Enterprise Admin, Schema Admin → **Critical** — escalate regardless
    of other findings
  - Service account → **High** — service accounts often have non-expiring passwords
    and broad resource access
  - Standard user → **Medium** — assess based on role and access scope
  - Analyst/IT role → **High** — SOC/IT accounts have elevated privileges in tooling
- [ ] Check if the targeted account(s) have MFA enrolled. If not, note as a hardening
  finding.

### Step 8 — Classify Variant `[TIER 1]`

Based on the aggregated data:

- [ ] **Variant A (Password Guessing):** SourceIP + TargetUser fixed; high velocity;
  SubStatus `0xC000006A`. → Confirm threshold (> 10 failures / 5 min) was exceeded.
- [ ] **Variant B (Password Spray):** SourceIP fixed; 5+ distinct TargetUsers;
  low-and-slow cadence; ~1–3 attempts per user. → Check inter-event timing regularity
  (even spacing is an automation indicator).
- [ ] Record the classified variant in the ticket.

### Step 9 — Render Verdict `[TIER 1]`

Using findings from Steps 1–8, classify the alert:

| Verdict | Criteria |
|---------|---------|
| **True Positive** | External/internal source with high-velocity or spray pattern; SubStatus `0xC000006A`; no obvious benign explanation |
| **False Positive** | Source is a known IT system; LogonType 4/5; single-user low-count failure; followed immediately by 4624 |
| **Benign True Positive** | Real failure burst but from an authorised system with a misconfiguration (e.g., stale service account creds); no malicious source |
| **Undetermined** | Unable to correlate source; insufficient data; escalate to Tier 2 |

- [ ] Record verdict and justification in the triage report.
- [ ] If True Positive or Undetermined: proceed to Containment.
- [ ] If False Positive or Benign True Positive: document and close; create a tuning
  ticket if the rule needs threshold adjustment.

---

## 5. Containment Actions

Execute containment actions **in the order listed**. Do not skip steps.

### 5.1 Block the Source IP

**Condition:** SourceIP is confirmed external and not a shared egress address.

- [ ] Submit a block request to the firewall/perimeter team for the SourceIP.
  Specify: deny inbound from `<SourceIP>` on all ports, not just 445/3389.
- [ ] If host-based firewall (Windows Defender Firewall / EDR policy) is available on
  the target host, apply a local block rule as an interim measure while the perimeter
  block is processed.
- [ ] Record the block ticket number and timestamp in the triage report.
- [ ] Set a 30-day review on the block. Do not set permanent blocks without a review
  cycle — IP addresses are reused.

**Condition:** SourceIP is internal.

- [ ] Do not block at the perimeter. Isolate the source host via EDR network isolation
  or VLAN quarantine.
- [ ] Escalate to Tier 2 immediately. An internal source is a higher-severity finding
  (compromised workstation, pivot from earlier intrusion, insider threat).

### 5.2 Protect the Targeted Account(s)

**If account is NOT locked out and attack is ongoing or unconfirmed stopped:**

- [ ] Coordinate with the Identity/AD team to manually lock the account while the
  investigation is active. Explain the reason — do not lock without informing the
  account owner's manager if it is a privileged account.
- [ ] Do not disable the account yet. Locking preserves the account for forensic
  review and is reversible without a password reset. See "Common Mistakes."

**If account is already locked out (EventID 4740 observed):**

- [ ] Advise the Identity team not to unlock the account until the source IP is blocked
  or isolated. Unlocking an account while the attack source is still active will
  immediately re-expose it.

**If a successful logon (EventID 4624) was observed:**

- [ ] Disable the account immediately. This is now a compromised credential.
- [ ] Escalate to Incident Response.
- [ ] Initiate a forced password reset.

### 5.3 Enable or Enforce MFA on Targeted Accounts

- [ ] Check whether the targeted account(s) have MFA enrolled.
- [ ] If MFA is not enrolled:
  - For privileged accounts: escalate to the Identity team for emergency MFA
    enrollment before the account is re-enabled.
  - For standard users: log as a hardening finding with P2 priority.
- [ ] Note: MFA alone does not eliminate brute force risk against legacy authentication
  protocols (NTLM, basic auth). Disabling legacy auth where possible is a
  complementary hardening step.

---

## 6. Eradication and Recovery

Once the source is blocked and targeted accounts are protected, work through the
following steps to eradicate any residual risk and restore normal operations safely.

### 6.1 Password Reset

- [ ] Force a password reset for all directly targeted accounts (accounts with >1
  failure in the burst).
- [ ] For accounts targeted in a spray (1–3 failures each): assess individually. A
  single failed attempt does not require an immediate reset, but the account should
  be monitored for 7 days post-incident.
- [ ] For any account where a subsequent 4624 was observed from the attacker's IP:
  treat as compromised and reset immediately.
- [ ] Confirm the new password meets complexity requirements and is not derived from
  a pattern (name + year, company + season, etc.).

### 6.2 Audit Recent Access for Targeted Accounts

- [ ] Query EventID 4624 for each targeted account for the 7 days prior to the alert.
  Look for logons from unusual source IPs, at unusual hours, or to unusual systems.
- [ ] If the account is a service account, audit what systems and resources it
  authenticates to. Confirm no new scheduled tasks, services, or connections were
  added in the attack window.
- [ ] For privileged accounts: request a privilege use audit (EventID 4673, 4674) to
  confirm no sensitive operations were performed using the account in the attack window
  or immediately before.

### 6.3 Verify Lockout Policy

- [ ] Retrieve the current account lockout policy from Group Policy.
- [ ] Confirm:
  - `Account lockout threshold`: ≤ 10 invalid attempts (NIST SP 800-63B guidance)
  - `Account lockout duration`: ≥ 15 minutes (or administrator unlock required)
  - `Reset account lockout counter after`: ≥ 15 minutes
- [ ] If the current policy is weaker than the above, raise a hardening ticket.
  Do not change GPO settings during active incident response without change management
  approval.

### 6.4 Review Attack Surface

- [ ] Confirm whether the targeted port (445 for LogonType 3, 3389 for LogonType 10)
  is accessible from the internet.
  - **SMB (445) accessible from internet:** This is a critical finding. SMB should
    never be exposed externally. Raise a P1 hardening ticket.
  - **RDP (3389) accessible from internet:** Restrict to VPN-only or implement an RDP
    gateway. Raise a P1 hardening ticket.
- [ ] Check whether the target host (DC-01 or member server) is directly reachable on
  these ports from untrusted networks, or whether the attack transited through a
  bastion / jump host.

### 6.5 Re-enable Locked Accounts

- [ ] Only re-enable or unlock accounts after:
  - Source IP is confirmed blocked or isolated.
  - Password has been reset.
  - MFA is enrolled (for privileged accounts).
  - Account owner has been notified.
- [ ] Confirm the account owner tests their new credentials successfully before closing
  the ticket.

---

## 7. Validation Steps

After containment and recovery actions are complete, verify the incident is resolved
before closing.

### 7.1 Confirm Attack Has Stopped

- [ ] Query 4625 events from the blocked SourceIP for 60 minutes post-block. The
  count should drop to zero.
- [ ] If failures continue from the same SourceIP: the block was not applied correctly.
  Re-engage the network team.
- [ ] If failures continue from **different IPs with the same pattern:** the adversary
  may have rotated source IPs. Open a new alert and link it to this ticket. Re-run
  the triage checklist from Step 6 (IP enrichment).

### 7.2 Confirm No Residual Successful Access

- [ ] Query EventID 4624 for all targeted accounts for 24 hours post-incident.
  No logons from the attacker's IP or previously unseen IPs should appear.
- [ ] Confirm no new scheduled tasks (EventID 4698), services (EventID 7045), or
  registry run keys were created on the target host during the attack window.

### 7.3 Confirm Account Health

- [ ] Verify all targeted accounts are unlocked and operational.
- [ ] Confirm password reset was completed for all accounts where it was required.
- [ ] Confirm MFA enrollment was completed for any privileged account where it was
  previously absent.

### 7.4 Confirm Detection is Working

- [ ] Verify the alert rule fired correctly and within an acceptable detection latency.
- [ ] If the alert fired late (e.g., > 10 minutes after the first observed failure):
  raise a detection engineering ticket to investigate log collection latency or rule
  timing issues.
- [ ] If the alert did not fire and the incident was identified manually: raise a
  tuning ticket to adjust thresholds or fix collection gaps.

---

## 8. Documentation Requirements

Record the following in the incident ticket before closing. This is required for
audit trails, post-incident review, and detection improvement.

### Mandatory Ticket Fields

| Field | What to Record |
|-------|---------------|
| Alert ID | BF-WIN-001 (or the SIEM alert reference) |
| Incident Start | Timestamp of first observed 4625 event |
| Incident End | Timestamp of last observed 4625 event, or timestamp of effective containment |
| Source IP | The attacker's source IP; include threat intel verdict |
| Target Accounts | All accounts targeted, with privilege classification |
| Failure Count | Total 4625 events observed in the incident window |
| Attack Variant | Variant A (Password Guessing), Variant B (Password Spray), or both |
| Successful Logon | Yes / No (with EventID 4624 reference if Yes) |
| Account Lockout Triggered | Yes / No (with EventID 4740 reference) |
| Verdict | True Positive / False Positive / Benign TP / Undetermined |
| Containment Actions Taken | List each action with timestamp and team responsible |
| Eradication Actions Taken | List password resets, audit results, MFA enrollment |
| Hardening Findings | List any P1/P2 findings raised (exposed ports, missing MFA, weak lockout policy) |
| Time to Detect (TTD) | Duration from first 4625 event to alert firing |
| Time to Contain (TTC) | Duration from alert firing to IP block or account lock applied |
| Analyst | Name / ID of the analyst who handled triage and containment |

### Evidence to Attach or Reference

- [ ] Triage report (link to `triage-reports/brute_force_001.md` or equivalent)
- [ ] SIEM query screenshots or saved searches showing the 4625 burst
- [ ] Threat intel report for the SourceIP
- [ ] Firewall block rule ticket number
- [ ] Account lockout / password reset confirmation from the Identity team
- [ ] Any EventID 4624 evidence (if applicable)

---

## 9. MITRE ATT&CK Mapping

### Primary Technique

| Field | Value |
|-------|-------|
| Tactic | Credential Access (TA0006) |
| Technique | T1110 — Brute Force |
| Sub-technique | T1110.001 — Password Guessing |
| Sub-technique | T1110.003 — Password Spraying |
| Data Source | DS0028: Logon Session; DS0002: User Account Authentication |
| Platform | Windows |

### Adjacent Techniques to Consider

The following techniques are commonly observed before, during, or after a brute
force campaign. Their presence would escalate severity and potentially trigger a
separate playbook.

| Technique | ID | Relationship to Brute Force |
|-----------|----|-----------------------------|
| Valid Accounts | T1078 | Attacker pivots to this after a successful brute force — use of legitimate credentials for access |
| Remote Services — SMB/Windows Admin Shares | T1021.002 | Post-access lateral movement using the compromised credential over SMB |
| Remote Services — Remote Desktop Protocol | T1021.001 | Post-access lateral movement or direct interactive access via RDP |
| Account Discovery | T1087 | May precede spray attacks — attacker enumerates valid usernames to build their target list |
| OS Credential Dumping | T1003 | Post-compromise escalation if attacker gains initial foothold via brute force |
| Inhibit System Recovery | T1490 | Appears in ransomware chains that begin with brute-forced RDP access |

### Detection Coverage

| Technique | Covered by This Playbook | Notes |
|-----------|-------------------------|-------|
| T1110.001 | Yes — Variant A | EventID 4625, high-velocity threshold |
| T1110.003 | Yes — Variant B | EventID 4625, cross-account aggregation |
| T1078 | Partial | EventID 4624 post-burst check covers this signal |
| T1021.001 / T1021.002 | No | Separate lateral movement playbook required |
| T1003 | No | Credential dumping playbook required |

---

## 10. Common Mistakes

These are the most frequent analyst errors when handling brute force alerts. Review
before executing containment actions.

---

### Mistake 1: Blocking a Shared Egress IP (NAT Gateway or VPN Concentrator)

**What happens:** An analyst blocks a SourceIP without checking whether it is a
shared egress address — a corporate VPN gateway, office NAT, or cloud NAT pool.
Blocking it cuts off all users behind that IP, causing an outage that exceeds the
blast radius of the original attack.

**How to avoid:**
- Before submitting a block request, check whether the SourceIP is internal or in a
  known corporate IP range.
- Cross-reference the IP against your asset inventory, firewall allowed-IP lists,
  and VPN endpoint documentation.
- If the IP is external but geolocation/ASN suggests it is a cloud provider or CDN,
  investigate before blocking — it may be a NAT pool shared by many customers.
- When in doubt, apply a rate-limit or alert-only rule rather than an outright block,
  and escalate for verification.

---

### Mistake 2: Disabling an Account Instead of Locking It

**What happens:** An analyst or the Identity team disables a targeted account during
active triage. The account owner cannot work, the disable event sometimes removes
important audit information, and reverting a disable is more disruptive than
reverting a lock.

**How to avoid:**
- During active incident response, prefer locking the account (which sets
  `AccountLockedOut = True`) over disabling it.
- Reserve account disables for confirmed compromise (EventID 4624 from attacker IP
  is observed) or for accounts where compromise cannot be ruled out.
- Always notify the account owner's manager before disabling a privileged account,
  even in a fast-moving incident.

---

### Mistake 3: Closing the Ticket Before Checking for Successful Logon

**What happens:** The analyst confirms no 4624 is present in the 5-minute alert
window and closes the ticket as "attack failed." A 4624 that occurred 20 minutes
later — after the attacker found the correct password on attempt #18 — is missed.

**How to avoid:**
- Always query for EventID 4624 in the window from **10 minutes before the first
  4625** to **60 minutes after the last 4625** from the same SourceIP.
- Do not narrow the query to just the alert window — brute force tools may slow
  down or pause between attempts.

---

### Mistake 4: Treating All T1110 Alerts the Same Severity

**What happens:** A low-count failure burst against a standard user account gets the
same response urgency as a high-count burst against a Domain Admin. The high-severity
case is under-resourced.

**How to avoid:**
- Apply severity modifiers based on target account privilege level. Domain Admin /
  service account targeting → escalate regardless of failure count.
- Apply severity modifiers based on whether a 4624 follows the burst. Success →
  Critical regardless of the preceding failure count.
- Use the account sensitivity tiers in Triage Step 7 as a guide.

---

### Mistake 5: Unlocking an Account Before Blocking the Source

**What happens:** Helpdesk unlocks a user's account in response to a lockout
complaint without knowing the account is actively under attack. The adversary's
tool immediately resumes and re-locks the account — or succeeds on the next attempt.

**How to avoid:**
- Before any account unlock is performed, confirm with the SOC that the source of
  the lockout has been identified.
- If the lockout was caused by a brute force source that has not yet been blocked,
  do not unlock the account until containment is in place.
- Establish a communication channel between the SOC and the Identity/Helpdesk team
  for active incidents so unlock requests can be verified in real time.

---

### Mistake 6: Ignoring a Password Spray Because the Failure Count Is "Low"

**What happens:** A Variant B spray with 8 accounts and 8 total failures looks
"minor" compared to a Variant A with 20 failures against one account. The analyst
deprioritises it. In reality, the spray is a more sophisticated and patient attack.

**How to avoid:**
- Evaluate spray alerts on **distinct account count**, not raw failure count.
- 5+ distinct accounts targeted from one IP is a high-confidence indicator of
  intentional credential attack, regardless of per-account failure volume.
- Note that a spray that succeeds leaves only 1 failure per account in the logs —
  the full attack evidence is only visible through cross-account aggregation.

---

*Playbook version 1.0 — Synthetic lab environment. Review and adapt all thresholds,
team names, and tool references before use in a production SOC.*
