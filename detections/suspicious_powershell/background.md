# Background: Suspicious PowerShell Execution (T1059.001)

## What Is This Technique?

PowerShell is a legitimate Windows scripting environment used extensively by
administrators, developers, and automated tooling. Adversaries abuse it because:

- It is present by default on every modern Windows system
- It has deep access to the Windows API, .NET runtime, WMI, and COM objects
- It can download and execute code entirely in memory without writing files to disk
- Its execution can be obfuscated to evade signature-based detection

**T1059.001 — PowerShell** describes adversary use of PowerShell to execute commands,
scripts, and payloads at any stage of the attack lifecycle: initial access (macro drops
PowerShell downloader), execution, persistence, lateral movement, and exfiltration.

## Common Adversary Patterns

| Pattern | Command-Line Indicator | Risk |
|---------|----------------------|------|
| **Encoded command** | `-EncodedCommand` / `-enc` / `-e` | Hides true intent from command-line logging and simple signatures |
| **Execution policy bypass** | `-ExecutionPolicy Bypass` / `-ep bypass` | Overrides script execution restrictions |
| **Hidden window** | `-WindowStyle Hidden` / `-w hidden` | Suppresses console window from appearing to the user |
| **Non-interactive / no profile** | `-NonInteractive` / `-noni`, `-NoProfile` / `-nop` | Avoids loading user profiles that may have security monitoring hooks |
| **Download cradle** | `IEX (New-Object Net.WebClient).DownloadString(...)` / `Invoke-WebRequest` / `Start-BitsTransfer` | Fetches and executes remote code without writing a file to disk |
| **AMSI bypass** | Various obfuscated patterns that patch the Anti-Malware Scan Interface in memory | Disables runtime script inspection |
| **Suspicious parent process** | `WINWORD.EXE`, `EXCEL.EXE`, `OUTLOOK.EXE`, `mshta.exe` spawning PowerShell | Strong indicator of macro-delivered or HTML-application-delivered payload |
| **Suspicious child processes** | PowerShell spawning `whoami`, `net`, `nltest`, `ping`, `certutil`, `reg` | Indicates post-exploitation reconnaissance or staging |

## Why SOC Analysts Care

PowerShell is the dominant scripting engine in Windows-targeted attacks. It appears in:

- **Commodity malware delivery** — malicious Office macros that spawn PowerShell to
  download a second-stage loader
- **Living-off-the-land (LotL) attacks** — adversaries avoiding custom tools by using
  built-in Windows capabilities
- **Post-exploitation frameworks** — Cobalt Strike, Metasploit, and others use
  PowerShell extensively for agent delivery, lateral movement, and credential access
- **Ransomware pre-staging** — PowerShell used to disable defenses, enumerate hosts,
  and deploy encryption payloads

The challenge: PowerShell is also used legitimately by IT and DevOps teams. Detection
must discriminate between administrative use and adversary use based on context
(parent process, flags, time of day, user, network activity) rather than the binary
presence of `powershell.exe`.

## Required Log Sources

### Primary

| Source | Event ID / Log | What It Captures |
|--------|---------------|-----------------|
| **Windows Security Log** | EventID **4688** — Process Creation | Parent process, child process, command line (requires "Include command line in process creation events" GPO) |
| **PowerShell Operational Log** | EventID **4104** — Script Block Logging | Actual script content, including decoded text of `-EncodedCommand` payloads |
| **PowerShell Operational Log** | EventID **4103** — Module Logging | Pipeline execution and cmdlet-level logging |
| **Sysmon** (if deployed) | Event ID **1** — Process Create | Full command line, parent process, file hashes — richer than 4688 |
| **Sysmon** (if deployed) | Event ID **3** — Network Connection | Outbound network connections from powershell.exe |

### Related

| Source | What It Provides |
|--------|-----------------|
| **Windows Application Log** | EventID 400/403 — PowerShell engine start/stop (includes host application) |
| **EDR telemetry** | Process tree, memory injection events, AMSI scan results |
| **Proxy / DNS log** | Correlate powershell.exe network connections to URLs or domains |
| **WEF / SIEM** | Aggregated event forwarding from all endpoints |

### Required Audit Policy

| Setting | Path | Required Value |
|---------|------|---------------|
| Process Creation | Advanced Audit > Detailed Tracking > Audit Process Creation | **Success** |
| Command Line in 4688 | GPO: Admin Templates > System > Audit Process Creation | **Enabled** |
| Script Block Logging | GPO: Admin Templates > Windows Components > Windows PowerShell | **Enabled** |
| Module Logging | GPO: Admin Templates > Windows Components > Windows PowerShell | **Enabled** |
| Transcription | GPO: Admin Templates > Windows Components > Windows PowerShell | Optional but recommended |

> Without command-line auditing in 4688 and Script Block Logging (4104), detection
> coverage is severely limited. `-EncodedCommand` payloads are invisible in logs
> without 4104.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | **Execution (TA0002)** |
| Technique | **T1059 — Command and Scripting Interpreter** |
| Sub-technique | **T1059.001 — PowerShell** |
| Related Techniques | T1027 (Obfuscated Files/Information — encoded commands), T1105 (Ingress Tool Transfer — download cradles), T1033 (System Owner/User Discovery — whoami), T1087 (Account Discovery — net user) |
| Data Sources | DS0009: Process; DS0017: Command; DS0012: Script |
| Platform | Windows |

## Assumptions (Lab Context)

- All log entries in this folder are **100% synthetic** — hand-crafted for portfolio
  demonstration only.
- The encoded command strings in `simulated_logs.log` are labeled with decoded
  equivalents in comments; decoded content uses RFC 5737 IPs (`203.0.113.0/24`) and
  does not represent functional malware.
- The simulated environment runs Windows 10/Server 2019 with Sysmon and PowerShell
  Script Block Logging enabled.
- Hostnames (`WORKSTATION-01`, `DC-01`) and usernames (`user1`, `LAB\user1`) are
  generic placeholders with no relation to any real system.
