# Chain: PostgreSQL Credential Sniff → COPY FROM PROGRAM RCE → Container Escape
Tags: postgresql, tcpdump, tcpkill, credential-sniff, copy-from-program, rce, container-escape, core-pattern, network-sniff, database
Chain Severity: High
Entry Condition: Network visibility to PostgreSQL port 5432 (plaintext / no TLS); `cap_net_raw` capability or root; PostgreSQL superuser credential capturable; running inside container

## Node 1 — PostgreSQL Credential Interception via tcpdump + tcpkill
Technique: [[Web/SQLi_to_RCE#PostgreSQL Credential Interception via tcpdump + tcpkill]]
Strike Vector: "tcpdump plaintext PostgreSQL credential capture"
Condition: Network interface visible to PostgreSQL traffic; `cap_net_raw` or equivalent; PostgreSQL not using TLS (`ssl = off` or client `sslmode=disable`)
Standalone Severity: Med
Branches:
  - Capture PostgreSQL startup packet → extract username + md5 hash or plaintext password via tcpdump → use `tcpkill` to force reconnect and capture cleartext → Node 2
  - TLS in use → credential not in plaintext on wire → [TERMINAL] TLS blocks sniff — look for password in env vars, app config, or postgres data dir
  - `cap_net_raw` denied → check for SUID tcpdump binary, or use eBPF socket tap if kernel version permits
  - md5 hash captured (not plaintext) → crack offline with hashcat mode 11100 (`pg_md5`); provide username as salt

## Node 2 — COPY FROM PROGRAM RCE (Superuser)
Technique: [[Web/SQLi_to_RCE#PostgreSQL COPY FROM PROGRAM RCE (Superuser)]]
Strike Vector: "COPY FROM PROGRAM as superuser"
Condition: Superuser PostgreSQL credentials from Node 1; `psql` or equivalent DB client available; `pg_execute_server_program` privilege (implied by superuser)
Standalone Severity: High
Branches:
  - `COPY (SELECT '') TO PROGRAM '<reverse shell cmd>'` executes as `postgres` OS user → shell inside container → Node 3
  - Credentials valid but user not superuser → check `pg_hba.conf` for local trust auth; attempt `ALTER USER postgres SUPERUSER` if CREATE ROLE priv available
  - `COPY TO PROGRAM` disabled (`allow_system_table_mods=off`) → try `CREATE EXTENSION adminpack` or `CREATE LANGUAGE plpython3u` as alternate exec primitive

## Node 3 — core_pattern Container Escape
Technique: [[Linux/Privilege_Escalation#core_pattern Container Escape]]
Strike Vector: "core_pattern write for container escape"
Condition: Shell as postgres inside container; `/proc/sys/kernel/core_pattern` writable (requires privileged container or `cap_sys_admin`); ability to trigger a core dump
Standalone Severity: Critical
Branches:
  - Write reverse shell path to `/proc/sys/kernel/core_pattern` → trigger crash (e.g., `kill -SIGSEGV $$`) → core dump executes payload on host kernel → Node 4
  - `/proc/sys/kernel/core_pattern` not writable (unprivileged container) → enumerate: Docker socket (`/var/run/docker.sock`), mounted host paths, `cap_sys_ptrace`, `nsenter` availability
  - Privileged container confirmed → mount host filesystem (`mount /dev/sda1 /mnt`), write SSH key or cron → [TERMINAL] Host filesystem access (Critical)

## Node 4 — Host Shell
Technique: [[Linux/Privilege_Escalation#core_pattern Container Escape]]
Strike Vector: "host shell via core_pattern"
Condition: core_pattern payload executed on host → reverse shell callback received
Standalone Severity: Critical
Branches:
  - Reverse shell connects as root on host → enumerate host OS, cloud metadata, pivot → [TERMINAL] Chain Complete (Critical)
  - Shell drops as non-root container runtime user → standard Linux privesc from that user on host
  - Payload fires but no callback → check firewall rules on host; switch to bind shell or DNS callback
