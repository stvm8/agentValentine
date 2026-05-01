# Chain: SSRF → Internal Service Enumeration → Pivot → Lateral Movement
Tags: ssrf, pivot, internal, network, lateral, rfi, redis, memcached, elastic
Chain Severity: Critical
Entry Condition: SSRF confirmed; internal RFC1918 responses observed (non-metadata)

## Node 1 — Internal Reachability Confirmed
Technique: [[Web/SSRF]]
Strike Vector: "SSRF internal service reach"
Condition: SSRF returns response from RFC1918 address that is not the cloud metadata endpoint
Standalone Severity: High
Branches:
  - Service banner / known port fingerprinted (Redis, Memcached, Elasticsearch, internal HTTP) → Node 2
  - Blind SSRF only (time-based, DNS OOB — no response body) → [TERMINAL] Blind SSRF Internal Reach (Medium)

## Node 2 — Internal Service Exploited
Technique: [[Web/SSRF]]
Strike Vector: "internal service exploit via SSRF"
Condition: Service identified responds to unauthenticated commands or exposes data
Standalone Severity: High
Branches:
  - RCE primitive available (Redis SLAVEOF / Gopher / dict:// writeable config) → Node 3
  - Data exfil only (Elasticsearch index dump, Memcached read) → [TERMINAL] Internal Data Exposure (High)
  - Admin panel accessible (Kibana, internal dashboard) → Node 3 alt (auth bypass or cred reuse)

## Node 3 — Remote Code Execution via Internal Service
Technique: [[Web/SSRF]]
Strike Vector: "RCE via internal service SSRF"
Condition: Command execution achieved on internal host via SSRF-proxied protocol abuse
Standalone Severity: Critical
Branches:
  - Shell on internal host → Node 4
  - File write only (no shell) → [TERMINAL] File Write via SSRF (High)

## Node 4 — Lateral Movement from Internal Host
Technique: [[Pivoting/]]
Strike Vector: "lateral movement from SSRF RCE host"
Condition: Shell active on internal host; network reachability to additional hosts confirmed
Standalone Severity: Critical
Branches:
  - Domain-joined host → [[Chain: ntlm-relay-domain-takeover]] Node 1
  - Cloud-connected host (instance role present) → [[Chain: ssrf-cloud-tenant]] Node 2A
  - Isolated host → [TERMINAL] Internal RCE Isolated Host (Critical)
