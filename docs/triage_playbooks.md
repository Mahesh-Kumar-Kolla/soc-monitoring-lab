# Analyst Triage Playbooks

Step-by-step triage procedures for each alert type. Follow these when an alert fires to determine if it is a true positive requiring escalation or a false positive to be closed.

---

## Playbook 1: SSH Brute-Force (Rules #1, #2, #7)

**Alert triggers on:** ≥ 5 SSH authentication failures from a single IP within 60 seconds.

### Step 1 — Verify the alert context

```splunk
index=soc_lab sourcetype=linux:auth src_ip=<ALERT_SRC_IP> earliest=-15m
| table _time, message, src_ip, user
| sort _time
```

Check: Is this a known scanner/monitoring agent? Compare against `known_good_hosts.csv`.

### Step 2 — IOC Pivot: what else has this IP done?

```splunk
index=soc_lab src_ip=<ALERT_SRC_IP> earliest=-24h
| stats count BY sourcetype, message
```

Look for: other failed logins to different hosts, web scraping, port scans in Zeek data.

```splunk
index=soc_lab sourcetype=zeek:conn id.orig_h=<ALERT_SRC_IP> earliest=-24h
| stats count, values(id.resp_p) AS ports, dc(id.resp_h) AS dest_hosts BY id.orig_h
```

High `dest_hosts` or broad port range = likely scanner / botnet node.

### Step 3 — Check for successful login after failures

```splunk
index=soc_lab sourcetype=linux:auth src_ip=<ALERT_SRC_IP> earliest=-15m
    (message="Accepted password for*" OR message="Accepted publickey for*")
```

**If a success event exists:** this is a confirmed breach attempt with potential access — **escalate immediately**.

### Step 4 — Assess post-login activity (if success found)

```splunk
index=soc_lab host=<VICTIM_HOST> earliest=<SUCCESS_TIME> latest=+30m
    sourcetype=linux:audit
| table _time, uid, comm, exe, key
| sort _time
```

Look for: privilege escalation (`sudo`, `su`), file access, new user creation, outbound connections.

### Step 5 — Decision

| Finding | Action |
|---------|--------|
| Failures only, known scanner IP | Close as FP; add IP to monitoring watchlist |
| Failures only, unknown IP | Close; note src_ip in threat intel log |
| Failures + successful login | **Escalate: P2 Incident** |
| Failures + success + post-login activity | **Escalate: P1 Incident — possible compromise** |

---

## Playbook 2: LSASS / Proc Memory Dump (Rules #3, #8)

**Alert triggers on:** Any non-root access to `/proc/<pid>/mem` or known credential-dump process name.

> This alert has a very low false-positive rate. Treat all firings as high-priority until ruled out.

### Step 1 — Identify the offending process

```splunk
index=soc_lab sourcetype=linux:audit key=proc_mem_access earliest=-10m
| rex field=_raw "uid=(?P<uid>\d+) .*pid=(?P<pid>\d+) .*comm=\"(?P<comm>[^\"]+)\" .*exe=\"(?P<exe>[^\"]+)\""
| table _time, host, uid, pid, comm, exe
```

### Step 2 — Trace process lineage

```splunk
index=soc_lab sourcetype=linux:audit host=<ALERT_HOST> pid=<ALERT_PID> earliest=-30m
| rex field=_raw "ppid=(?P<ppid>\d+)"
| table _time, pid, ppid, comm, exe, key
| sort _time
```

Then pivot to the parent PID to identify how the process was launched.

### Step 3 — IOC Pivot: check for network exfiltration

```splunk
index=soc_lab sourcetype=zeek:conn id.orig_h=<ALERT_HOST> earliest=<ALERT_TIME> latest=+30m
| where id.resp_p != 22 AND id.resp_p != 53
| table _time, id.orig_h, id.resp_h, id.resp_p, orig_bytes, resp_bytes
```

Watch for: large outbound transfers to external IPs shortly after the dump event.

### Step 4 — Decision

| Finding | Action |
|---------|--------|
| Known debugging tool (gdb), developer host | Verify with dev team; close if confirmed |
| Unknown process accessing proc/mem | **Escalate: P1 Incident** |
| Dump tool + outbound transfer | **Escalate: P1 — credential exfiltration likely** |

---

## Playbook 3: /etc/shadow Unauthorized Access (Rule #4)

**Alert triggers on:** `openat(/etc/shadow)` by any process not in the authorised list.

### Step 1 — Identify the process and user

```splunk
index=soc_lab sourcetype=linux:audit key=shadow_read earliest=-10m
| rex field=_raw "uid=(?P<uid>\d+) .*comm=\"(?P<comm>[^\"]+)\" .*exe=\"(?P<exe>[^\"]+)\""
| table _time, host, uid, comm, exe
```

### Step 2 — Check if this matches a known scheduled task

Cross-reference with `cron` entries on the host:
```bash
# Run on the endpoint (out-of-band)
grep -r /etc/shadow /etc/cron* /var/spool/cron/crontabs/
```

### Step 3 — IOC Pivot: look for hash cracking setup

```splunk
index=soc_lab sourcetype=linux:audit host=<ALERT_HOST> earliest=<ALERT_TIME> latest=+1h
    (comm IN ("hashcat", "john", "johntheripper") OR exe="*hashcat*" OR exe="*john*")
```

### Step 4 — Decision

| Finding | Action |
|---------|--------|
| Known backup script / cron | Add comm exclusion to Rule #4; close |
| Unknown process, low uid | **Escalate: P2 — potential SUID exploit** |
| Access + hash cracking tool | **Escalate: P1 — active credential attack** |

---

## Playbook 4: SMB Lateral Movement (Rule #5)

**Alert triggers on:** New SMB connection + successful auth from same source within 5 minutes.

### Step 1 — Verify the connection details

```splunk
index=soc_lab sourcetype=zeek:conn id.resp_p=445 id.orig_h=<ALERT_SRC_IP> earliest=-15m
| table _time, id.orig_h, id.resp_h, orig_bytes, resp_bytes, conn_state, duration
```

### Step 2 — Check authentication context

```splunk
index=soc_lab sourcetype=linux:auth src_ip=<ALERT_SRC_IP> earliest=-15m
    (message="session opened*" OR message="Accepted*")
| table _time, message, src_ip, user, host
```

### Step 3 — Look for prior recon activity from the same source

```splunk
index=soc_lab sourcetype=zeek:conn id.orig_h=<ALERT_SRC_IP> earliest=-1h
| stats count, values(id.resp_p) AS ports_scanned, dc(id.resp_h) AS hosts_targeted BY id.orig_h
```

High `hosts_targeted` suggests automated lateral movement sweep.

### Step 4 — Decision

| Finding | Action |
|---------|--------|
| Known service account / admin host | Verify with sysadmin; close if authorised |
| New src IP, single destination | Monitor for further activity; ticket as low |
| Sweep pattern (multiple hosts) | **Escalate: P2 — lateral movement campaign** |
| Interactive session established | **Escalate: P1 — active attacker on network** |

---

## Playbook 5: RDP Brute-Force + Success (Rule #6)

**Alert triggers on:** ≥ 3 RDP failures followed by successful RDP connection from same IP within 120 seconds.

### Step 1 — Confirm the connection sequence in Zeek

```splunk
index=soc_lab sourcetype=zeek:conn id.resp_p=3389 id.orig_h=<ALERT_SRC_IP> earliest=-10m
| table _time, id.orig_h, id.resp_h, conn_state, duration, orig_bytes, resp_bytes
| sort _time
```

Look for the pattern: REJ, REJ, REJ → SF (success).

### Step 2 — Check for post-login activity

```splunk
index=soc_lab host=<VICTIM_HOST> earliest=<SUCCESS_TIME> latest=+1h
    sourcetype=linux:audit
| where key IN ("exec", "shadow_read", "proc_mem_access")
| table _time, uid, comm, exe, key
```

### Step 3 — Decision

| Finding | Action |
|---------|--------|
| Failures only (no SF) | Likely blocked attempt; note src_ip |
| Failures + success, internal IP | Verify with user; may be typo'd password |
| Failures + success, external IP | **Escalate: P1 — unauthorized RDP access** |
| Success + post-login privilege activity | **Escalate: P1 — active compromise** |
