# Attack Chain Reconstruction
## Mini SOC Lab — All Documented Incidents

| Field | Value |
|-------|-------|
| Classification | TLP:WHITE |
| Author | Mahmadarsh Vahora |
| Date | 2026-05-30 |
| Incidents Covered | BF-001, PHISH-001, PS-001 |
| Framework | MITRE ATT&CK Enterprise v14 + Unified Kill Chain |

---

## Incident 1: BF-001 — Credential Brute-Force Campaign

```
KILL CHAIN PHASE    ATT&CK TECHNIQUE           EVIDENCE                    DETECTION    GAP?
────────────────────────────────────────────────────────────────────────────────────────────
RECONNAISSANCE      T1595.001                  [INFERRED] Source IP had     NOT          YES
Port Scanning       Active Scanning:           valid account names before   DETECTED     No log
                    Scanning IP Blocks         guessing — implies prior                  coverage
                                               network scan                              for pre-
                                                                                         attack scan

RECONNAISSANCE      T1589.001                  [INFERRED] SubStatus         NOT          YES
Account Discovery   Gather Victim Identity     0xC000006A confirms valid    DETECTED     No external
                    Info: Credentials          usernames known to attacker               account
                                                                                         enum log

CREDENTIAL          T1110.001                  EventID 4625 × 50+           DETECTED     NO
ACCESS              Brute Force:               SubStatus 0xC000006A         (SIEM alert)
Phase 1             Password Guessing          Port 445 (SMB)
                                               Source IP: external

CREDENTIAL          T1110.001 (continued)      Same pattern against          DETECTED     NO
ACCESS              Brute Force:               ports 3389, 22, 5985         (log
Phase 1 pivot       Password Guessing          Sequential port              correlation)
                                               enumeration in 30-min
                                               window

CREDENTIAL          T1110.003                  Pattern shift: fewer          DETECTED     NO
ACCESS              Brute Force:               attempts/account,            (pattern
Phase 2             Password Spraying          distributed across multiple   analysis)
                                               accounts — lockout evasion

LATERAL MOVEMENT    T1021.001                  Internal pivot: identical     PARTIAL      YES
(Phase 2)           Remote Desktop Protocol   port sequence (445, 3389)     (SMB         RDP not
                                               from internal host            monitored;   alerted
                                                                             RDP not)

POST-EXPLOITATION   T1003                      [NOT OBSERVED — GAP]         NOT          YES
(Hypothetical)      OS Credential Dumping      If attacker gained code       DETECTED     Critical
                                               execution, LSASS access       —no          gap
                                               would be undetected           Sysmon
                                                                             EventID 10

PERSISTENCE         T1053 / T1547              [NOT OBSERVED — GAP]         NOT          YES
(Hypothetical)      Scheduled Task /           If attacker established       DETECTED     Two
                    Boot/Logon Autostart       persistence, no detection     —no          persistence
                                               mechanism exists              coverage     gaps

DEFENSE EVASION     T1078                      [NOT OBSERVED — GAP]         NOT          YES
(Hypothetical)      Valid Accounts             If attacker obtained creds    DETECTED     Valid
                                               and used them legitimately,   —no          account
                                               no alert would fire           monitoring   usage blind
                                                                                          spot
```

**BF-001 Summary:** 3 techniques detected, 6 techniques undetected (3 confirmed gaps + 3 hypothetical post-compromise gaps). Critical path gap: T1003 → T1078 → T1547 represents the undetected kill chain continuation that would follow a successful credential access event.

---

## Incident 2: PHISH-001 — Phishing Campaign

```
KILL CHAIN PHASE    ATT&CK TECHNIQUE           EVIDENCE                    DETECTION    GAP?
────────────────────────────────────────────────────────────────────────────────────────────
INITIAL ACCESS      T1566                      Phishing email received by   DETECTED     NO
                    Phishing                   monitored mailbox;           (email
                                               malicious attachment/link    gateway
                                               identified by gateway        alert)

INITIAL ACCESS      T1566.001 or T1566.002     [INFERRED] Specific          DETECTED     NO
                    Spearphishing              sub-technique based on       (gateway
                    Attachment or Link         email structure              classification)

EXECUTION           T1204.002                  [SIMULATED] User click on    DETECTED     NO
(Simulated)         User Execution:            attachment — simulated       (endpoint
                    Malicious File             user interaction for         alert on
                                               detection testing            simulated
                                                                            payload)

EXECUTION           T1059.001                  PowerShell invocation        DETECTED     NO
                    Command and Scripting:     observed in process tree     (Script
                    PowerShell                 following simulated          Block
                                               execution                    Logging)

COMMAND &           T1071.001                  [NOT OBSERVED — GAP]         NOT          YES
CONTROL             Application Layer          HTTP/S C2 traffic would      DETECTED     No proxy
(Hypothetical)      Protocol: Web Protocols    not be detected in           —no proxy    or DNS
                                               current environment          or DNS log   monitoring

COLLECTION          T1087.001                  Account Discovery command    DETECTED     NO
                    Account Discovery:         observed in simulated        (endpoint
                    Local Account              PowerShell execution         log)

EXFILTRATION        T1041                      [NOT OBSERVED — GAP]         NOT          YES
(Hypothetical)      Exfiltration Over C2       Data staging and transfer    DETECTED     No DLP
                    Channel                    would be undetected if       —no DLP      or egress
                                               using standard HTTP/S                     monitoring
```

**PHISH-001 Summary:** 5 techniques detected (including simulated execution), 2 critical post-execution gaps: C2 communication (T1071.001) and data exfiltration (T1041) would proceed undetected after initial compromise.

---

## Incident 3: PS-001 — PowerShell Execution Chain

```
KILL CHAIN PHASE    ATT&CK TECHNIQUE           EVIDENCE                    DETECTION    GAP?
────────────────────────────────────────────────────────────────────────────────────────────
EXECUTION           T1059.001                  PowerShell process           DETECTED     NO
                    Command and Scripting:     invocation logged;           (Script
                    PowerShell                 command line captured        Block
                                               in ScriptBlock log           Logging)

DEFENSE EVASION     T1027                      Base64-encoded command       DETECTED     NO
                    Obfuscated Files           string detected in           (AMSI
                    or Information             ScriptBlock log; AMSI        alert)
                                               triggered on decode

COMMAND & CONTROL   T1105                      Ingress transfer attempt     DETECTED     NO
                    Ingress Tool Transfer      identified in network log    (network
                                               (outbound connection to      log)
                                               external IP during script
                                               execution)

DISCOVERY           T1087                      Account discovery            DETECTED     NO
                    Account Discovery          commands observed in         (endpoint
                                               PowerShell session           log)

DISCOVERY           T1482                      Domain trust enumeration     DETECTED     NO
                    Domain Trust               observed in PowerShell       (endpoint
                    Discovery                  session following            log)
                                               T1087

LATERAL MOVEMENT    T1021 (preparation)        [INFERRED] Account and       PARTIAL      YES
(Intended)          Remote Services            domain enumeration is        (enum        Movement
                                               consistent with lateral      detected;    itself
                                               movement preparation         movement     undetected)
                                               not observed in current      not yet      if executed
                                               logs                         seen)

PROCESS INJECTION   T1055                      [NOT OBSERVED — GAP]         NOT          YES
(Hypothetical)      Process Injection          If script attempted to       DETECTED     No Sysmon
                                               inject into a process,       —no          EventID 8
                                               no detection available       Sysmon       monitoring
                                                                            EventID 8

DEFENSE EVASION     T1562                      [NOT OBSERVED — GAP]         NOT          YES
(Hypothetical)      Impair Defenses            If script attempted to       DETECTED     AV/EDR
                                               disable AV/EDR, no           —no          tamper
                                               detection available          tamper       protection
                                                                            monitoring   monitoring
                                                                                         absent
```

**PS-001 Summary:** 5 techniques detected. PS-001 represents the richest detection coverage of the three incidents — Script Block Logging, AMSI, and network log correlation all contributed. Remaining gaps: process injection (T1055) and AV impairment (T1562) represent the techniques a sophisticated actor would use after the initial PowerShell execution to maintain persistence without re-triggering detections.

---

## Cross-Incident Coverage Matrix

| Tactic | Incident BF-001 | Incident PHISH-001 | Incident PS-001 | Coverage |
|--------|----------------|-------------------|----------------|---------|
| Reconnaissance | PARTIAL | N/A | N/A | Gap |
| Initial Access | N/A | DETECTED | N/A | Covered |
| Execution | N/A | DETECTED | DETECTED | Covered |
| Defense Evasion (T1027) | N/A | N/A | DETECTED | Covered |
| Defense Evasion (T1055) | N/A | N/A | GAP | Gap |
| Defense Evasion (T1562) | N/A | N/A | GAP | Gap |
| Credential Access (T1110) | DETECTED | N/A | N/A | Covered |
| Credential Access (T1003) | GAP | N/A | N/A | Gap |
| Discovery | N/A | DETECTED | DETECTED | Covered |
| Lateral Movement | PARTIAL | N/A | PARTIAL | Gap |
| C2 (T1071) | N/A | GAP | N/A | Gap |
| C2 (T1105) | N/A | N/A | DETECTED | Covered |
| Persistence (T1053) | GAP | N/A | N/A | Gap |
| Persistence (T1547) | GAP | N/A | N/A | Gap |
| Defense Evasion (T1078) | GAP | N/A | N/A | Gap |
| Exfiltration | N/A | GAP | N/A | Gap |
| Impact (T1486) | GAP | N/A | N/A | Gap |

**Total: 9 confirmed coverage gaps across all three incidents.**
