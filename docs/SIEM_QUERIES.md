# Splunk SPL Queries — SOC Detection Library

Author: Mahmadarsh Vahora  
Last Updated: 2025-05-30  
Data Source: Windows Security Event Log (via Splunk Universal Forwarder or WEF)

---

## Query 1: Failed Login Threshold Detection (T1110 — Brute Force)

**Purpose:** Identifies source IPs generating more than 5 failed logon attempts within a 5-minute window. Triggers on both bad-password SubStatus and missing-account SubStatus to catch both brute force and password spray variants.

**Detection Logic:** Count EventID 4625 per source IP per 5-minute bucket. Alert when count exceeds threshold. Enriches with account names for analyst context.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
| eval SubStatus=lower(SubStatus)
| where SubStatus="0xc000006a" OR SubStatus="0xc0000064"
| where LogonType IN ("2","3","10")
| bucket _time span=5m
| stats
    count AS FailedAttempts,
    dc(Account_Name) AS UniqueAccounts,
    values(Account_Name) AS TargetAccounts,
    min(_time) AS FirstSeen,
    max(_time) AS LastSeen
    BY _time, Source_Network_Address
| where FailedAttempts > 5
| eval FirstSeen=strftime(FirstSeen,"%Y-%m-%d %H:%M:%S")
| eval LastSeen=strftime(LastSeen,"%Y-%m-%d %H:%M:%S")
| eval ThreatLevel=case(
    FailedAttempts >= 50, "CRITICAL",
    FailedAttempts >= 20, "HIGH",
    FailedAttempts >= 10, "MEDIUM",
    true(), "LOW"
  )
| sort - FailedAttempts
| table Source_Network_Address, FailedAttempts, UniqueAccounts, TargetAccounts, FirstSeen, LastSeen, ThreatLevel
```

**What It Finds:**
- Source IPs conducting brute force or password spray attacks
- Distinguishes single-account brute force (UniqueAccounts=1) from spray (UniqueAccounts>1)
- Time-bucketed so the 5-minute window is enforced at search time

**Tuning Guidance:**
- Increase threshold (>5) in environments with known flaky applications
- Whitelist known vulnerability scanners or PAM systems by adding `| where Source_Network_Address!="10.0.0.x"`
- Add `| lookup internal_ip_ranges.csv ip AS Source_Network_Address OUTPUT location` for geo context

---

## Query 2: PowerShell ScriptBlock Obfuscation Detection (T1059.001 + T1027)

**Purpose:** Detects suspicious or obfuscated PowerShell content captured by ScriptBlock logging (EventID 4104). Searches for Base64 encoding markers, download cradles, AMSI bypass strings, and known malicious cmdlets.

**Detection Logic:** Search PowerShell operational log for EventID 4104 entries containing known-bad patterns. Use `rex` to extract the script block text cleanly and `eval` to score severity.

```spl
index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| rex field=_raw "ScriptBlockText=(?P<ScriptBlock>.+?)(?:\r\n|\n|$)" max_match=0
| eval ScriptBlock=coalesce(ScriptBlock, Message)
| eval Indicators=mvappend(
    if(match(ScriptBlock,"(?i)-EncodedCommand|-enc\s|-ec\s"), "EncodedCommand", null()),
    if(match(ScriptBlock,"(?i)DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest"), "DownloadCradle", null()),
    if(match(ScriptBlock,"(?i)Invoke-Expression|\|?\s*IEX\s*\(|\.Invoke\(\)"), "InvokeExpression", null()),
    if(match(ScriptBlock,"(?i)\[char\]|\[Convert\]::FromBase64|ToBase64String|-join\s+\[char\]"), "CharObfuscation", null()),
    if(match(ScriptBlock,"(?i)amsiInitFailed|AmsiUtils|amsiContext"), "AMSIBypass", null()),
    if(match(ScriptBlock,"(?i)Invoke-Mimikatz|sekurlsa|lsadump|Get-GPPPassword"), "CredentialAccess", null()),
    if(match(ScriptBlock,"(?i)Add-MpPreference|Set-MpPreference.*-Disable|Suspend-BitLocker"), "DefenseEvasion", null())
  )
| where isnotnull(Indicators)
| eval IndicatorCount=mvcount(Indicators)
| eval Severity=case(
    match(mvjoin(Indicators,","),"AMSIBypass|CredentialAccess"), "CRITICAL",
    IndicatorCount >= 3, "HIGH",
    IndicatorCount == 2, "MEDIUM",
    true(), "LOW"
  )
| stats
    count AS EventCount,
    values(Indicators) AS DetectedIndicators,
    values(ComputerName) AS Hosts,
    values(User) AS Users,
    max(Severity) AS MaxSeverity,
    min(_time) AS FirstSeen
    BY ScriptBlockId
| sort - EventCount
| eval FirstSeen=strftime(FirstSeen,"%Y-%m-%d %H:%M:%S")
| table ScriptBlockId, MaxSeverity, DetectedIndicators, Users, Hosts, EventCount, FirstSeen
```

**What It Finds:**
- Multi-indicator scoring: each obfuscation technique adds to an indicator count
- CRITICAL triggers immediately on AMSI bypass or known credential tools
- Groups by ScriptBlockId so multi-part scripts are correlated

**Tuning Guidance:**
- Whitelist known admin script hashes using a lookup table: `| lookup safe_scripts.csv ScriptBlockId OUTPUT IsApproved | where IsApproved!="true"`
- Requires PowerShell ScriptBlock Logging enabled via GPO before any data will appear

---

## Query 3: Lateral Movement Indicators (T1021 — Remote Services)

**Purpose:** Detects lateral movement patterns by correlating successful logons (EventID 4624) of type 3 (Network) or type 10 (RemoteInteractive) from a single source account or IP touching multiple distinct destination hosts within a short window.

**Detection Logic:** Count unique destination hosts per source identity per time bucket. An account or IP authenticating to more than 3 distinct hosts in 10 minutes is a high-confidence lateral movement indicator.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624
| where LogonType IN ("3","10")
| eval SourceIdentity=coalesce(Source_Network_Address, Account_Domain+"\"+Account_Name)
| bucket _time span=10m
| stats
    dc(ComputerName) AS UniqueDestinations,
    values(ComputerName) AS DestinationHosts,
    values(Account_Name) AS Accounts,
    count AS TotalLogons,
    min(_time) AS FirstSeen,
    max(_time) AS LastSeen
    BY _time, SourceIdentity, Source_Network_Address
| where UniqueDestinations > 3
| eval FirstSeen=strftime(FirstSeen,"%Y-%m-%d %H:%M:%S")
| eval LastSeen=strftime(LastSeen,"%Y-%m-%d %H:%M:%S")
| eval Priority=case(
    UniqueDestinations >= 10, "P1 - Critical",
    UniqueDestinations >= 6,  "P2 - High",
    UniqueDestinations >= 4,  "P3 - Medium",
    true(), "P4 - Low"
  )
| sort - UniqueDestinations
| table SourceIdentity, Source_Network_Address, UniqueDestinations, DestinationHosts, Accounts, TotalLogons, FirstSeen, LastSeen, Priority
```

**What It Finds:**
- Single source authenticating to many destinations (worm-like propagation or attacker pivoting)
- Separates by LogonType 3 (pass-the-hash, SMB) vs LogonType 10 (RDP hop)
- Priority tier built in for analyst triage

**Tuning Guidance:**
- Filter known IT management tools: `| where NOT match(Source_Network_Address, "^10\.0\.50\.")`  (example SCCM subnet)
- Add `| lookup ad_service_accounts.csv Account_Name OUTPUT IsServiceAccount | where IsServiceAccount!="true"` to suppress known scanner accounts
- Lower threshold to >2 in high-security segments (e.g., domain controllers subnet)

---

## Alert Scheduling Recommendations

| Query | Recommended Schedule | Lookback Window | Alert Threshold |
|---|---|---|---|
| Failed Login Threshold | Every 5 minutes | 5 minutes | Any result |
| PowerShell ScriptBlock | Real-time or every 1 min | 1 minute | Severity = HIGH or CRITICAL |
| Lateral Movement | Every 10 minutes | 10 minutes | Any result |
