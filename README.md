# SOC Monitoring & SIEM Analysis Lab

A home-lab Security Operations Centre (SOC) built to practice real-world detection engineering, log analysis, and incident triage using industry-standard open-source tooling.

---

## Lab Architecture

```
  Linux Endpoints (2x Ubuntu 22.04)
         │
         ├── Zeek  ──────────────► network telemetry (conn.log, dns.log, http.log)
         ├── auditd ─────────────► process & syscall events
         └── syslog/auth.log ───► authentication events
                  │
          ┌───────┴────────┐
          │  Log Forwarder  │  (Filebeat / Wazuh agent)
          └───────┬────────┘
                  │
     ┌────────────┼────────────┐
     ▼            ▼            ▼
  Splunk       Wazuh        Elastic
  (primary    (HIDS +      (long-term
  SIEM)       alerting)    retention)
```

**Event volume:** ~1,500 events/day  
**Coverage:** Authentication • Process • Network telemetry

---

## Tools & Technologies

| Tool | Role |
|------|------|
| **Splunk** | Primary SIEM, SPL correlation searches, dashboards |
| **Wazuh** | Host-based IDS, file integrity monitoring, active response |
| **Elastic (ELK)** | Long-term log retention, Kibana visualisation |
| **Zeek** | Passive network traffic analysis, protocol parsing |
| **Sigma** | Vendor-neutral detection rule format |
| **Atomic Red Team** | Adversary simulation / detection validation |

---

## Detection Rules

8 correlation rules covering three MITRE ATT&CK tactic areas:

| # | Rule | Technique | Format | Severity |
|---|------|-----------|--------|----------|
| 1 | SSH Brute-Force — Multiple Failures | T1110.001 | Sigma | High |
| 2 | SSH Brute-Force — Distributed (Low & Slow) | T1110.001 | Sigma | Medium |
| 3 | LSASS Memory Dump via Proc Access | T1003.001 | Sigma | Critical |
| 4 | Linux `/etc/shadow` Unauthorized Read | T1003.008 | Sigma | High |
| 5 | Suspicious SMB Lateral Movement | T1021.002 | Sigma | High |
| 6 | RDP Brute-Force & Lateral Movement | T1021.001 | Sigma | High |
| 7 | SSH Brute-Force Correlation (Splunk SPL) | T1110.001 | SPL | High |
| 8 | Credential Dumping — LSASS (Splunk SPL) | T1003.001 | SPL | Critical |

---

## MITRE ATT&CK Coverage

```
Tactic             Technique          Sub-Technique          Rule(s)
─────────────────────────────────────────────────────────────────────
Credential Access  T1110 Brute Force  T1110.001 Password      #1, #2, #7
Credential Access  T1003 OS Cred Dump T1003.001 LSASS Memory  #3, #8
Credential Access  T1003 OS Cred Dump T1003.008 /etc/shadow   #4
Lateral Movement   T1021 Remote Svcs  T1021.002 SMB/WFS       #5
Lateral Movement   T1021 Remote Svcs  T1021.001 RDP           #6
```

Detection coverage validated at **100%** via Atomic Red Team simulations.

---

## Repository Structure

```
soc-monitoring-lab/
├── README.md
├── SOC_Lab_Report.md            ← full technical report
├── rules/
│   ├── sigma/                   ← 5 Sigma YAML rules
│   │   ├── ssh_brute_force.yml
│   │   ├── ssh_brute_force_distributed.yml
│   │   ├── lsass_memory_dump.yml
│   │   ├── etc_shadow_access.yml
│   │   ├── smb_lateral_movement.yml
│   │   └── rdp_lateral_movement.yml
│   └── splunk/                  ← 2 SPL correlation searches
│       ├── ssh_brute_force.spl
│       └── credential_dumping_lsass.spl
├── docs/
│   ├── mitre_mapping.md
│   ├── triage_playbooks.md
│   └── false_positive_tuning.md
└── atomic_red_team/
    └── validation_results.md
```

---

## Key Results

- **~1,500 events/day** ingested from two Linux endpoints across three telemetry types
- **8 detection rules** authored in Sigma / Splunk SPL, covering 5 ATT&CK sub-techniques
- **100% detection coverage** across all mapped ATT&CK techniques validated with Atomic Red Team
- Triage workflows, IOC pivot queries, and false-positive tuning notes documented per rule

---

## Skills Demonstrated

`SIEM Architecture` · `Detection Engineering` · `Sigma Rules` · `Splunk SPL` · `MITRE ATT&CK` · `Threat Hunting` · `Incident Triage` · `Zeek NSM` · `Wazuh HIDS` · `Atomic Red Team`
