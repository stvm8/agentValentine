# Chain: PostgreSQL pgcrypto Heap Overflow → OS RCE (CVE-2026-2005)
Tags: postgresql, pgcrypto, heap-overflow, buffer-overflow, cve-2026-2005, rce, copy-to-program, db-exploit
Chain Severity: High
Entry Condition: Authenticated SQL access to PostgreSQL ≤ 17.7 / 16.11 / 15.15 / 14.20 / 18.1 with CREATE privilege (no superuser needed)

## Node 1 — pgcrypto Extension Loaded
Technique: [[Web/SQLi_to_RCE#PostgreSQL pgcrypto Heap Overflow]]
Strike Vector: "pgcrypto extension load"
Condition: Auth SQL access + CREATE privilege on database; pgcrypto not already blocked by admin
Standalone Severity: Low
Branches:
  - Extension loads successfully → Node 2
  - CREATE privilege denied → [TERMINAL] Insufficient DB privileges — escalate or pivot to different DB vector

## Node 2 — Info Leak (PIE Base + Heap Addresses)
Technique: [[Web/SQLi_to_RCE#PostgreSQL pgcrypto Heap Overflow]]
Strike Vector: "pgp_pub_decrypt heap overflow info leak"
Condition: pgcrypto loaded; craft RSA/ElGamal payload where (msglen - 3) > 32 to overflow dst buffer
Standalone Severity: Med
Branches:
  - Addresses leaked from returned memory → Node 3
  - Heap layout differs (unusual Postgres build/config) → strike; retry with adjusted offset — ASLR identical across connections to same postmaster so addresses stable
  - Patched version detected → [TERMINAL] CVE patched — check for other DB vectors

## Node 3 — Arbitrary Write → CurrentUserId Overwrite
Technique: [[Web/SQLi_to_RCE#PostgreSQL pgcrypto Heap Overflow]]
Strike Vector: "arbitrary write CurrentUserId"
Condition: PIE base + heap addresses known from Node 2; craft second payload corrupting all four dst struct fields to target CurrentUserId in .data section; write value 10 (BOOTSTRAP_SUPERUSERID)
Standalone Severity: High
Branches:
  - CurrentUserId overwritten → Node 4
  - Write lands on wrong offset (version mismatch) → strike; recalculate offset from correct binary symbols

## Node 4 — Superuser → Full DB Read + COPY TO PROGRAM
Technique: [[Web/SQLi_to_RCE#PostgreSQL pgcrypto Heap Overflow]]
Strike Vector: "COPY TO PROGRAM RCE"
Condition: CurrentUserId = 10 (superuser) for current connection
Standalone Severity: High
Branches:
  - Always: full read access to all tables / all databases on the instance → [TERMINAL] Data exfil / credential harvest (High)
  - COPY TO PROGRAM executes → Node 5 (deployment-dependent — determine first)
  - COPY TO PROGRAM disabled → try `CREATE LANGUAGE plpython3u` or UDF-based exec as alternative OS exec primitive

## Node 5A — Bare Metal / VM Deployment
Condition: PostgreSQL running directly on host OS (systemd service, package install)
Standalone Severity: Critical
Branches:
  - Shell as postgres OS user on host → enumerate sudo rules, cron, SUID, app config files
  - `sudo -l` shows passwordless sudo (common for DBA maintenance scripts) → [TERMINAL] Root on host (Critical)
  - No sudo path → standard Linux privesc from postgres user → [[Linux/PrivEsc]]
  - .pgpass / app configs in postgres home → credential reuse on other host services

## Node 5B — Docker Deployment (default, unprivileged)
Condition: PostgreSQL running inside a standard Docker container
Standalone Severity: High
Branches:
  - Shell as postgres user inside container → enumerate mounted volumes, env vars, network
  - Docker socket mounted (/var/run/docker.sock) → [TERMINAL] Host escape via socket (Critical)
  - Privileged container (`--privileged`) → mount host filesystem → [TERMINAL] Host escape (Critical)
  - Host path volume mounted with write access → drop cron/SSH key on host → [TERMINAL] Host escape (High)
  - None of the above → [TERMINAL] Contained — pivot / network scan from container (Med)
