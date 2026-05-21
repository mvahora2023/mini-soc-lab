# Evidence Capture Checklist

Use this checklist when preparing portfolio screenshots. Complete all sanitization
checks before capturing and before adding any image to `evidence/screenshots/`.

---

## Storage Location

All screenshots must be saved to:

```
evidence/screenshots/
```

Use descriptive filenames in kebab-case:

```
evidence/screenshots/readme-overview.png
evidence/screenshots/detection-brute-force-logic.png
evidence/screenshots/triage-report-verdict.png
evidence/screenshots/playbook-triage-checklist.png
```

---

## Sanitization Rules (Must Verify Before Every Screenshot)

- [ ] No real IP addresses visible — only RFC 5737 ranges (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`)
- [ ] No real usernames, account names, or email addresses — only approved placeholders (`user1`, `admin1`, `analyst1`)
- [ ] No real hostnames, domain names, or tenant identifiers — only `DC-01`, `WORKSTATION-01`, `lab.internal`, `example.com`
- [ ] No credentials, tokens, hashes, or API keys visible anywhere in the frame
- [ ] No real SIEM tenant URLs, org names, or subscription IDs in the browser address bar
- [ ] No personal desktop background, taskbar notifications, or other windows visible behind the capture area
- [ ] Capture only the relevant file or section — crop tightly

If any real data appears in the frame, do not capture. Sanitize the source file first,
then re-capture.

---

## Screenshots to Capture

### 1. README Overview Section

**File to show:** `README.md` rendered in a Markdown viewer or GitHub preview

**What to frame:** The top of the file — title, Overview heading, and Repo Structure
section showing the folder tree.

**Purpose:** Establishes the portfolio's scope and professional structure at a glance.

**Filename:** `evidence/screenshots/readme-overview.png`

- [ ] Sanitization check passed
- [ ] Captured
- [ ] Saved to `evidence/screenshots/`

---

### 2. Detection Logic — Brute Force

**File to show:** `detections/brute_force_windows/detection.md`

**What to frame:** Variant A detection logic block (the KQL-style query) and the
threshold section immediately below it. Include enough context to show the detection
objective heading above the code block.

**Purpose:** Demonstrates ability to write structured, threshold-based detection logic
with ATT&CK mapping.

**Filename:** `evidence/screenshots/detection-brute-force-logic.png`

- [ ] Sanitization check passed (no real IPs or users in the query)
- [ ] Captured
- [ ] Saved to `evidence/screenshots/`

---

### 3. Triage Report — Verdict and Evidence Section

**File to show:** `triage-reports/brute_force_001.md`

**What to frame:** Section 3 (Evidence) through Section 5 (Decision). Include the
aggregate counts table and the verdict with justification text.

**Purpose:** Shows analytical reasoning, structured evidence presentation, and
decision documentation — core Tier 1 SOC analyst skills.

**Filename:** `evidence/screenshots/triage-report-verdict.png`

- [ ] Sanitization check passed (verify all quoted log lines use `203.0.113.10` and generic usernames only)
- [ ] Captured
- [ ] Saved to `evidence/screenshots/`

---

### 4. Playbook — Triage Checklist

**File to show:** `playbooks/brute_force_playbook.md`

**What to frame:** Section 4 (Triage Checklist), specifically Steps 1 through 4.
Show the checkbox format, the SubStatus decision table in Step 3, and the escalation
condition in Step 4.

**Purpose:** Demonstrates ability to write actionable, tiered SOC procedures with
embedded decision logic.

**Filename:** `evidence/screenshots/playbook-triage-checklist.png`

- [ ] Sanitization check passed
- [ ] Captured
- [ ] Saved to `evidence/screenshots/`

---

## Optional Screenshots (Nice to Have)

These are not required for the initial portfolio but add depth if time permits.

| Screenshot | File | Section | Filename |
|------------|------|---------|----------|
| Synthetic log pattern | `detections/brute_force_windows/simulated_logs.log` | Scenario A header + first 5 log lines | `evidence/screenshots/synthetic-logs-scenario-a.png` |
| MITRE coverage matrix | `coverage/MITRE_Coverage_Matrix.md` | Full coverage table | `evidence/screenshots/mitre-coverage-matrix.png` |
| Alert definition | `detections/brute_force_windows/alert.json` | Full JSON rendered | `evidence/screenshots/alert-definition-json.png` |
| Playbook common mistakes | `playbooks/brute_force_playbook.md` | Section 10 (first 2 mistakes) | `evidence/screenshots/playbook-common-mistakes.png` |

---

## Capture Tips

- Use a Markdown preview pane (VS Code preview, GitHub, or a local renderer) rather
  than raw source — rendered output is more readable for portfolio reviewers.
- Set your editor to a clean light or dark theme with no clutter in the frame.
- Capture at a resolution where text is legible without zooming (1440px wide minimum).
- Prefer PNG over JPEG for text-heavy screenshots — no compression artifacts on code.
