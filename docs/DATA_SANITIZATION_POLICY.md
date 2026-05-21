# Data Sanitization Policy

## Purpose

This policy governs what data may appear in this repository. All contributors must follow these rules before committing any file.

## Rules

### 1. No Real Identifiers

The following are strictly prohibited:

- Real hostnames or machine names
- Real usernames or account names
- Real internal or external IP addresses
- Real domain names or tenant identifiers
- Real email addresses
- Real organization names or internal system names

### 2. All Logs Are Synthetic

Every log file in this repository is hand-crafted or generated for simulation purposes. No logs may be copied from a real production, lab, or customer environment without full sanitization.

### 3. Approved Placeholder Values

| Category | Approved Values |
|----------|----------------|
| IP addresses | RFC 5737 documentation ranges: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| Usernames | `user1`, `user2`, `analyst1`, `analyst2`, `svc_account1` |
| Hostnames | `WORKSTATION-01`, `DC-01`, `FILESERVER-01` |
| Domains | `example.com`, `lab.internal` |
| Email | `user1@example.com`, `analyst1@example.com` |

### 4. No Credentials or Secrets

- No passwords, hashes, API keys, tokens, or certificates
- No `.env` files, config files, or credential stores — even if values appear redacted

### 5. No Internal Infrastructure Details

- No network diagrams, subnet maps, or topology data derived from real environments
- No references to real SIEM tenants, cloud accounts, or vendor licenses

## Verification Checklist

Before committing, confirm:

- [ ] All IP addresses fall within RFC 5737 documentation ranges
- [ ] All usernames and hostnames use approved placeholder values
- [ ] No file was copied directly from a real environment
- [ ] No credentials, tokens, or secrets are present
- [ ] Log timestamps use a clearly fictional or sanitized date range
