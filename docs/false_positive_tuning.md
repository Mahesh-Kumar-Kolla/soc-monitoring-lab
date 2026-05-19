# False-Positive Tuning Notes

Per-rule documentation of false positives observed during the baseline week, root cause analysis, and tuning applied. Updated as new FPs are identified.

---

## Rule 1 — SSH Brute-Force (Multiple Failures)

### Observed FPs

| # | FP Description | Root Cause | Date Identified |
|---|---------------|------------|-----------------|
| 1 | Internal SSH key rotation script | Iterates through 6 key types per connection attempt | 2026-05-04 |
| 2 | Ansible controller pushing playbooks | Retries on network timeout — generated ~8 failures/min | 2026-05-06 |

### Tuning Applied

**FP #1:** Added source IP of key rotation server (`192.168.100.50`) to suppression list.

In SPL search, add before the `| where` clause:
```splunk
| where src_ip != "192.168.100.50"
```

In Sigma rule, add under `filter_legitimate`:
```yaml
filter_keymgmt:
  src_ip: '192.168.100.50'
```

**FP #2:** Raised threshold from 3 → 5 failures within 60 seconds. This eliminated the Ansible FP while still catching brute-force tools (Hydra default rate: ~20 attempts/sec).

### Current Threshold
- ≥ 5 failures from same src_ip within 60 seconds
- Suppressed src_ips: `192.168.100.50`

---

## Rule 2 — SSH Brute-Force Distributed

### Observed FPs

| # | FP Description | Root Cause | Date Identified |
|---|---------------|------------|-----------------|
| 1 | Three monitoring jump hosts performing parallel SSH health checks | Each jump host generates 3-4 SSH probes per check cycle | 2026-05-05 |

### Tuning Applied

Added CIDR block of the monitoring subnet to suppression:
```splunk
| where NOT cidrmatch("192.168.100.48/29", src_ip)
```

### Current Threshold
- ≥ 3 distinct IPs, each with ≥ 3 failures, within 300 seconds
- Suppressed subnet: `192.168.100.48/29` (monitoring hosts)

---

## Rule 3 — LSASS Memory Dump

### Observed FPs

| # | FP Description | Root Cause | Date Identified |
|---|---------------|------------|-----------------|
| 1 | Developer running `gdb` on a test process | `gdb` uses ptrace/proc access legitimately | 2026-05-07 |
| 2 | Java JVM accessing `/proc/self/mem` for GC | Normal JVM memory management behaviour | 2026-05-08 |

### Tuning Applied

**FP #1:** Added `gdb` and `lldb` to comm exclusion list in both Sigma and SPL rules.

**FP #2:** Added comm filter for `java` processes accessing `/proc/self/mem` only (not other PIDs):
```splunk
| where NOT (comm="java" AND match(target_path, "^/proc/self/"))
```

### Notes

This rule should remain **highly sensitive**. Any new FP exclusion must be documented and reviewed. Do not add blanket UID 0 exclusions — root-level LSASS dumps are still malicious.

---

## Rule 4 — /etc/shadow Unauthorized Access

### Observed FPs

| # | FP Description | Root Cause | Date Identified |
|---|---------------|------------|-----------------|
| 1 | Daily backup cron job (2:00 AM) | Backup script reads `/etc/shadow` for account sync | 2026-05-04 |
| 2 | `libpam` during `sudo` session initialisation | PAM re-reads shadow during privilege escalation check | 2026-05-09 |

### Tuning Applied

**FP #1:** Added backup script path to comm exclusion:
```yaml
filter_legitimate:
  comm:
    - backup_agent
    - rsync
```

**FP #2:** `sudo` and `su` were already in the exclusion list — added explicit `libpam` exclusion.

### Current Exclusion List

`passwd`, `chpasswd`, `shadow`, `useradd`, `usermod`, `chage`, `chsh`, `login`, `sshd`, `su`, `sudo`, `libpam`, `backup_agent`

---

## Rule 5 — SMB Lateral Movement

### Observed FPs

| # | FP Description | Root Cause | Date Identified |
|---|---------------|------------|-----------------|
| 1 | Samba health-check cron (every 5 minutes) | `smbclient -L localhost` generates auth + conn events | 2026-05-05 |
| 2 | IT admin using WinSCP to access Samba share | Legitimate admin activity from known IP | 2026-05-10 |

### Tuning Applied

**FP #1:** Excluded the service account used by the health-check cron:
```splunk
| where user != "svc_samba_health"
```

**FP #2:** Added IT admin workstation IP to suppression list.

### Note

Review this suppression list whenever new admin workstations are onboarded. The intent is to suppress known-good sources, not to whitelist entire subnets.

---

## Rule 6 — RDP Brute-Force + Lateral Movement

### Observed FPs

| # | FP Description | Root Cause | Date Identified |
|---|---------------|------------|-----------------|
| 1 | RDP client on flaky network causing TCP resets | Network instability generated REJ events before successful conn | 2026-05-11 |

### Tuning Applied

**FP #1:** Raised minimum failure count from 3 → 4 before triggering. The flaky-network scenario produced exactly 3 resets; raising the threshold preserved detection while eliminating this FP.

Confirmed: Atomic Red Team T1021.001-1 generates 5 failures before success — still detected at threshold of 4.

---

## General Tuning Principles

1. **Document every change.** Include date, observed FP, root cause, and change made.
2. **Validate after every exclusion.** Re-run the Atomic Red Team test to confirm detection still fires.
3. **Prefer narrow exclusions** (specific IP, user, comm) over broad ones (entire CIDR, UID 0).
4. **Set a review cadence.** Review all exclusions quarterly to remove those that are no longer valid.
5. **Never suppress Critical-severity rules** without explicit sign-off and documentation.
