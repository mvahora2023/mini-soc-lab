# Detection: Suspicious PowerShell Execution (T1059.001)

## Detection Objective

Identify adversary abuse of PowerShell by detecting:

1. PowerShell spawned from high-risk parent processes (Office applications, script hosts)
2. PowerShell executed with an obfuscation flag combination associated with malicious use
3. PowerShell spawning discovery or staging child processes consistent with post-exploitation

These three variants are complementary — each catches a different phase or evasion
approach. Running all three in parallel maximises coverage.

| Variant | Primary Signal | Data Source |
|---------|---------------|-------------|
| A — Suspicious Parent Process | Office/script host spawns powershell.exe | 4688 / Sysmon 1 |
| B — Obfuscation Flag Combination | `-enc` + `-ep bypass` + `-w hidden` together | 4688 / Sysmon 1 |
| C — Suspicious Child Processes | powershell.exe spawns recon binaries | 4688 / Sysmon 1 |

A 4104 (Script Block) correlation rule is included as a supplemental high-fidelity
signal that works across all three variants.

---

## Variant A: Suspicious Parent Process (T1059.001)

**Signal:** PowerShell is spawned by a parent process with no legitimate reason to
launch a scripting engine — typically an Office application, browser, PDF reader, or
script host.

### Detection Logic

```
ProcessCreationLog
| where Image endswith "\\powershell.exe"
       or Image endswith "\\pwsh.exe"
| where ParentImage matches_regex
    @"(?i)(WINWORD|EXCEL|POWERPNT|OUTLOOK|MSPUB|ONENOTE|MSACCESS|AcroRd32|
           mshta|wscript|cscript|regsvr32|rundll32|msiexec|InstallUtil)\.exe"
| project Timestamp, Computer, SubjectUser, Image, CommandLine,
          ParentImage, ParentCommandLine, SHA256Image, IntegrityLevel
| order by Timestamp asc
```

**Why these parents are suspicious:**

| Parent | Legitimate PowerShell Use? | Adversary Use |
|--------|--------------------------|---------------|
| `WINWORD.EXE` | None | Macro-delivered loader / downloader |
| `EXCEL.EXE` | None | XLM macro / VBA macro payload |
| `OUTLOOK.EXE` | None | Rule-based or add-in-based execution |
| `mshta.exe` | None | HTA-dropped PowerShell payload |
| `wscript.exe` / `cscript.exe` | Rare / legacy only | JScript or VBScript dropper |
| `regsvr32.exe` | None (Squiblydoo technique) | COM scriptlet → PowerShell |

**Threshold:** No threshold — any instance of these parents spawning PowerShell
should be investigated. This is a near-zero false positive rule in environments where
macros are disabled. If macros are enabled for business reasons, correlate with file
path (known-safe .docm templates) to reduce noise.

---

## Variant B: Obfuscation Flag Combination (T1059.001 + T1027)

**Signal:** PowerShell command line contains multiple flags associated with evasion,
indicating intent to hide execution from users and security tooling.

### Flag Scoring Logic

```
ProcessCreationLog
| where Image endswith "\\powershell.exe"
       or Image endswith "\\pwsh.exe"
| extend FlagScore = 0
| extend FlagScore = FlagScore
    + iif(CommandLine matches_regex @"(?i)(-enc|-EncodedCommand|-e\s+[A-Za-z0-9+/=]{20,})", 3, 0)
    + iif(CommandLine matches_regex @"(?i)(-ep\s+bypass|-ExecutionPolicy\s+bypass)", 2, 0)
    + iif(CommandLine matches_regex @"(?i)(-w\s+hid|-WindowStyle\s+hid)", 2, 0)
    + iif(CommandLine matches_regex @"(?i)(-noni|-NonInteractive)", 1, 0)
    + iif(CommandLine matches_regex @"(?i)(-nop|-NoProfile)", 1, 0)
    + iif(CommandLine matches_regex @"(?i)(-noexit)", 1, 0)
| where FlagScore >= 4
| project Timestamp, Computer, SubjectUser, CommandLine,
          ParentImage, FlagScore, IntegrityLevel
| order by FlagScore desc, Timestamp asc
```

**Score guide:**

| FlagScore | Severity | Interpretation |
|-----------|---------|----------------|
| 1–2 | Low | Single flag; may be legitimate admin script |
| 3 | Medium | Encoded command alone or two evasion flags; investigate |
| 4–5 | High | Multiple evasion flags; strong indication of malicious intent |
| 6+ | Critical | Full obfuscation stack; consistent with post-exploitation framework or automated tool |

**Simulated log trigger:** Event 2 and Event 6 both score 8:
`-ExecutionPolicy Bypass` (+2) + `-WindowStyle Hidden` (+2) + `-NonInteractive` (+1) + `-EncodedCommand` (+3) = 8.

---

## Variant C: Suspicious Child Processes from PowerShell (T1059.001 + T1087 + T1016)

**Signal:** PowerShell spawns discovery or staging utilities commonly associated with
post-exploitation enumeration.

### Detection Logic

```
ProcessCreationLog
| where ParentImage endswith "\\powershell.exe"
       or ParentImage endswith "\\pwsh.exe"
| where Image matches_regex
    @"(?i)(whoami|net\.exe|nltest|ipconfig|arp\.exe|nbtstat|netstat|
           ping\.exe|certutil|bitsadmin|msiexec|regsvr32|wmic|
           vssadmin|bcdedit|schtasks|at\.exe|sc\.exe)$"
| summarize
    ChildCount   = count(),
    ChildImages  = make_set(Image),
    ChildCmdLines = make_set(CommandLine),
    FirstSeen    = min(Timestamp),
    LastSeen     = max(Timestamp)
  by Computer, ParentProcessId, ParentCommandLine, SubjectUser
| where ChildCount >= 2           // single accidental spawn vs deliberate recon pattern
| extend DurationSec = datetime_diff('second', LastSeen, FirstSeen)
| project FirstSeen, LastSeen, Computer, SubjectUser, ParentCommandLine,
          ChildCount, DurationSec, ChildImages, ChildCmdLines
| order by ChildCount desc
```

**High-risk child process combinations:**

| Combination | MITRE Technique | Interpretation |
|-------------|----------------|----------------|
| `whoami` → `net user /domain` → `nltest /domain_trusts` | T1033, T1087, T1482 | Classic AD enumeration sequence; consistent with pre-lateral-movement recon |
| `whoami` → `ipconfig /all` → `arp -a` | T1033, T1016, T1018 | Host and network discovery; consistent with initial access → reconnaissance |
| `certutil -urlcache -split -f` or `bitsadmin /transfer` | T1105 | In-memory or on-disk download using living-off-the-land binary (LOLBin) |
| `vssadmin delete shadows` / `bcdedit /set recoveryenabled no` | T1490 | Pre-ransomware defense impairment |
| `schtasks /create` or `sc create` | T1053, T1543 | Persistence mechanism setup |

**Simulated log trigger:** Scenario B spawns 5 child processes in 28 seconds:
`whoami /all`, `net user /domain`, `nltest /domain_trusts`, `ping -n 1 DC-01`, and
`reg query HKLM\SYSTEM\...` — all from the same parent PID `0x1C40`.

---

## Supplemental: Script Block Logging Correlation (EventID 4104)

**Use this rule to augment any of the three variants above when 4104 logging is enabled.**

```
PowerShellScriptBlock
| where EventID == 4104
| where ScriptBlockText matches_regex
    @"(?i)(IEX|Invoke-Expression|
           DownloadString|DownloadFile|WebClient|WebRequest|
           Start-BitsTransfer|[Cc]ertutil|
           Net\.Sockets\.TCPClient|StreamReader|StreamWriter|
           -join|[char]|0x[0-9a-fA-F]+|
           AmsiUtils|amsiInitFailed|
           [Rr]eflection\.Assembly|[Ll]oad[Ff]ile|[Ll]oad[Ww]ith[Pp]artial[Nn]ame)"
| project Timestamp, Computer, ProcessId, ScriptBlockText
| order by Timestamp asc
```

**Why 4104 is high-fidelity:** PowerShell decodes `-EncodedCommand` payloads before
executing them, and Script Block Logging captures the decoded text. This means
obfuscated payloads are transparent in 4104 even when the 4688 command line shows
only the encoded string. A 4104 hit containing `IEX` + `DownloadString` in the same
script block is effectively definitive evidence of a download cradle.

---

## False Positives

| Scenario | Why It Fires | How to Distinguish |
|----------|-------------|-------------------|
| IT automation scripts with `-ep bypass` | Sysadmins sometimes use policy bypass for legitimate deployment scripts | Parent is `services.exe` or a known task name; script path matches known-safe admin directory; signed with internal code signing cert |
| SCCM / Endpoint Manager deployment | Management agents spawn PowerShell with hidden windows and encoded parameters | Parent process is a known SCCM client binary; SourceIP of task matches management server; user is SYSTEM |
| Security tooling (EDR/AV updates) | Some security products invoke PowerShell internally | Parent is a known security vendor binary; command line matches known-safe vendor signature |
| RMM tools (e.g., ConnectWise, Kaseya) | Remote management platforms use PowerShell heavily | Execution correlates to a known maintenance window; parent matches known RMM agent |
| Developer tooling (npm, pip, cargo build scripts) | Build tools sometimes invoke PowerShell for platform detection | Parent is `node.exe`, `python.exe`, `cargo.exe`; working directory is a known code repository |

---

## Tuning

### Allowlist Candidates

```
// Exclude known management server-spawned PowerShell (Variant B and C)
| where not (ParentImage endswith "\\CCMExec.exe"
             and SubjectUser == "NT AUTHORITY\\SYSTEM")

// Exclude known-safe scheduled task names (Variant B — svchost parent)
| where not (ParentCommandLine contains "Schedule"
             and CommandLine contains known_safe_task_name)

// Exclude code-signed scripts from known internal CA (Variant B)
| where not (SignerName == "LAB Internal CA"
             and SignatureStatus == "Valid")
```

### Parent Process Context

For environments where svchost spawning PowerShell is common (Windows Update,
WSUS, SCCM), tune Variant A to focus on Office parents only and move the
scheduler-parent variant to a lower-severity rule with additional time-of-day context:

```
| where TimeOfDay between (time(22:00:00) .. time(06:00:00))  // after-hours execution
| where ParentImage endswith "\\svchost.exe"
| where SubjectUser != "NT AUTHORITY\\SYSTEM"  // SYSTEM running scheduled maintenance is less suspicious
```

### Script Block Text Tuning

Some legitimate admin frameworks (DSC, Pester, Ansible WinRM) generate 4104 hits
on cmdlets in the suspicious list. Create an allowlist of known-safe script block
hashes rather than suppressing by text pattern to avoid creating detection gaps.
