# MITRE ATT&CK Mapping

Coverage map for all detection rules in this lab, aligned to MITRE ATT&CK v14.

---

## Coverage Overview

| Tactic | Technique | Sub-Technique | Rule(s) | Status |
|--------|-----------|---------------|---------|--------|
| Credential Access | T1110 Brute Force | T1110.001 Password Guessing | ssh_brute_force.yml, ssh_brute_force_distributed.yml, ssh_brute_force.spl | Covered |
| Credential Access | T1003 OS Credential Dumping | T1003.001 LSASS Memory | lsass_memory_dump.yml, credential_dumping_lsass.spl | Covered |
| Credential Access | T1003 OS Credential Dumping | T1003.008 /etc/passwd and /etc/shadow | etc_shadow_access.yml | Covered |
| Lateral Movement | T1021 Remote Services | T1021.002 SMB/Windows Admin Shares | smb_lateral_movement.yml | Covered |
| Lateral Movement | T1021 Remote Services | T1021.001 Remote Desktop Protocol | rdp_lateral_movement.yml | Covered |

---

## Technique Detail Cards

### T1110.001 — Password Guessing (SSH)

**Tactic:** Credential Access  
**Platform:** Linux, Windows, macOS  
**Data Sources:** Authentication logs, Network traffic  

**Adversary behaviour:** Automated tools (Hydra, Medusa, Ncrack) attempt a high volume of password guesses against SSH (port 22). Variants include single-source high-rate attacks and distributed low-and-slow spraying from botnets.

**Detection logic:**
- Single-source: ≥ 5 failures from one IP within 60 seconds
- Distributed: ≥ 3 IPs each with ≥ 3 failures within 300 seconds

**Key log fields:** `src_ip`, `user`, `Failed password`, timestamp

**Atomic Red Team test:** `T1110.001-1` (SSH password spray with Hydra)

---

### T1003.001 — LSASS Memory

**Tactic:** Credential Access  
**Platform:** Linux (via `/proc/<pid>/mem`), Windows (via LSASS process)  
**Data Sources:** auditd, process creation logs  

**Adversary behaviour:** Attackers access process memory of the authentication daemon (on Linux, typically `sshd`, `login`, or `systemd-logind`) via the `/proc` filesystem or ptrace to extract credentials from memory.

**Detection logic:**
- Any `openat` syscall targeting `/proc/*/mem` by non-root UID (auditd key: `proc_mem_access`)
- Any process with known dump-tool names (mimikatz, procdump, nanodump)

**Key log fields:** `uid`, `pid`, `comm`, `exe`, `key`

**Atomic Red Team test:** `T1003.001-7` (ptrace-based memory access)

---

### T1003.008 — /etc/passwd and /etc/shadow

**Tactic:** Credential Access  
**Platform:** Linux, macOS  
**Data Sources:** auditd  

**Adversary behaviour:** After gaining initial access, attackers read `/etc/shadow` to obtain password hashes for offline cracking. This requires either root or exploitation of a SUID binary.

**Detection logic:**
- Any `openat` call with `name=/etc/shadow` not from an authorised process list

**Key log fields:** `uid`, `gid`, `comm`, `key`, `name`

**Atomic Red Team test:** `T1003.008-1` (direct cat of /etc/shadow)

---

### T1021.002 — SMB/Windows Admin Shares

**Tactic:** Lateral Movement  
**Platform:** Windows, Linux (Samba)  
**Data Sources:** Zeek conn.log, auth.log  

**Adversary behaviour:** After obtaining credentials, adversaries move laterally by authenticating to SMB shares (port 445) on other hosts to execute files or access data.

**Detection logic:**
- Zeek conn.log: new TCP connection to port 445 with state `SF` (completed)
- auth.log: successful session opened within 5 minutes from same source

**Key log fields:** `src_ip`, `dst_ip`, `dst_port`, `conn_state`, `user`

**Atomic Red Team test:** `T1021.002-1` (smbclient share enumeration and access)

---

### T1021.001 — Remote Desktop Protocol

**Tactic:** Lateral Movement  
**Platform:** Windows, Linux (xrdp)  
**Data Sources:** Zeek conn.log  

**Adversary behaviour:** Adversaries use RDP (port 3389) to interactively access remote systems. Often preceded by brute-force when credentials are unknown.

**Detection logic:**
- ≥ 3 TCP resets (REJ/RSTO) to port 3389 from same src IP, followed by a successful connection (SF) within 120 seconds

**Key log fields:** `src_ip`, `dst_ip`, `dst_port`, `conn_state`

**Atomic Red Team test:** `T1021.001-1` (xfreerdp password spray)

---

## ATT&CK Navigator Layer

The following ATT&CK techniques are highlighted in this lab's coverage (Navigator JSON available on request):

```json
{
  "name": "SOC Lab Coverage",
  "versions": {"attack": "14", "navigator": "4.9"},
  "techniques": [
    {"techniqueID": "T1110.001", "score": 100, "color": "#ff6666"},
    {"techniqueID": "T1003.001", "score": 100, "color": "#ff6666"},
    {"techniqueID": "T1003.008", "score": 100, "color": "#ff6666"},
    {"techniqueID": "T1021.002", "score": 100, "color": "#ff6666"},
    {"techniqueID": "T1021.001", "score": 100, "color": "#ff6666"}
  ]
}
```
