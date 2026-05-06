# Valentine 🩸

> *A penetration testing companion built on Claude Code. Not an autopilot — a co-pilot.*

**Status:** ✅ Production Ready | **Version:** 2026-05-06

__The agent is built with Obsidian, however Obsidian is not required for the agent to work__

---

## Design Philosophy

Valentine is not designed to conduct a penetration test from A to Z autonomously.

Valentine is a pentester's companion — helping you navigate complexity, save time, spark creative attack paths, and surface blind spots and rabbit holes you might miss mid-engagement. It is opinionated about one thing: the pentester stays in control.

Valentine learns from every engagement through the Global Brain (SQLite FTS5 learnings database). Both the agent and the pentester grow in knowledge together.

---

## What's Inside

| Component | Size | Status |
|-----------|------|--------|
| **Skills** | 12 | ✅ All deployed (appraisal, network, webapp, api, cloud, robin, report, save, absorb, defense, idorDeep, apiTesting) |
| **Playbooks** | 120 entries | ✅ AD (33), Cloud (27), Web (13), Windows (5), Linux (5), C2 (1), Pivoting (4) + CHAINS (32) |
| **Attack Chains** | 32 entries | ✅ Full multi-step exploitation chains (azure-recon-to-kudu, cloud-cred-spray, k8s-pod-to-admin, etc.) |
| **Learnings** | 127 entries | ✅ SQLite FTS5 database + markdown sync (web, network, cloud, ctf, bounty, general) |
| **Reference Protocols** | 8 files | ✅ ROE, strikes, proposals, learning format, reporting, chains, pivoting, content quality |
| **Integration Hooks** | 2 | ✅ Pre-compact state save, post-bash strike reminders |

---

## Skills

| Skill | Type | Purpose |
|-------|------|---------|
| `/appraisal` | Entry Point | Engagement kickoff — builds workspace, syncs Global Brain, produces phased recon plan with user approval |
| `/network` | Specialist | AD kill chain — enum through domain takeover. BloodHound, Kerberoasting, NTLM relay, lateral movement, persistence |
| `/webapp` | Specialist | OWASP Web Top 10 — injection, auth, access control, business logic, SSRF, security misconfig, finding chains |
| `/api` | Specialist | OWASP API Top 10 — BOLA/IDOR, auth flaws, mass assignment, GraphQL abuse, webhook chains |
| `/cloud` | Specialist | AWS/Azure/GCP — IAM escalation, storage misconfig, compute abuse, cross-account trust, SAML/OIDC, CloudTrail evasion |
| `/idorDeep` | Specialist | Deep IDOR/BFLA methodology — systematic user enumeration, parameter tampering, finding exploitation chains |
| `/apiTesting` | Specialist | Automated OWASP Top 10 baseline — swagger.json parsing, quick wins, vulnerability surfacing |
| `/robin` | Co-Pilot | Strategic advisor — reads state, finds coverage gaps, suggests next moves. Never executes. Checks strikes first. |
| `/report` | Output | Technical report generation — MITRE ATT&CK + OWASP mapping, CWE classification, lesson extraction |
| `/save` | Checkpoint | State snapshot — saves all workspace before context compression or handoff |
| `/absorb` | Learning | Ingests writeups/blogs into Playbooks with dedup checking — adds to INDEX + _FLOW decision trees |
| `/defense` | Learning | Generates defense writeup from engagement notes (template fill for compliance reports) |

---

## Playbook Coverage at a Glance

**Active Directory (33 techniques)** — ACL abuse, BloodHound chains, Kerberoasting, NTLM relay, coercion (PetitPotam, PrinterBug, DFSCoerce), ADCS (ESC1-ESC14), SCCM, Exchange, lateral movement (WMI, PSRemoting, SCM), DCSync, Golden Ticket, trust abuse, AMSI evasion.

**Cloud (27 techniques)** — Azure IAM, token exploitation, managed identities, AWS IAM escalation, credential exposure, GCP service accounts, S3/blob misconfig, CloudTrail evasion, Lambda exploitation, container escape, cross-cloud lateral movement.

**Web & API (13 techniques)** — SQLi → RCE, SSRF, XXE, GraphQL abuse, command injection, auth bypass, BOLA/IDOR, XSS worms, API webshell, race conditions, JWT manipulation, WAF bypass.

**Attack Chains (32 documented chains)** — Azure recon → Kudu exfil, cloud metadata → DB creds, OAuth scope downgrade + lateral, S3 multi-service chains, CI/CD runner compromise, pod escape → cluster admin, and 26 more.

**Pivoting (4 techniques)** — SSH tunnels, chisel, ligolo-ng, socat with topology tracking.

**Windows (5) · Linux (5) · C2/Sliver (1)** — Registry abuse, UAC bypass, SUID/capabilities, cron PATH injection, sudo misconfig, shellcode loaders.

---

## Standard Flow

```
/appraisal → /webapp | /api | /network | /cloud → /robin (when stuck) → /save → /report
```

For API-first engagements with Swagger/Postman:
```
/apiTesting baseline → /api manual exploitation → /apiTesting full suite → /idorDeep (if BOLA found) → /robin → /report
```

---

## Quick Start

```bash
# Start an engagement
/appraisal type: network, platform: CorpAD, client: Acme, scope: 192.168.1.0/24, oos: 192.168.1.1, objective: Domain Admin

# Ask Robin when stuck
/robin I have local admin on WEB01 and SMB signing is enabled. What's next?

# Resume after break
/network continue: Acme

# Feed the brain (writeup ingestion)
/absorb https://blog.example.com/adcs-esc4-writeup

# Run deep IDOR analysis
/idorDeep --from-apiTesting

# Save before clearing context
/save
```

---

## Hard Rules

- **Every proposal ends with `[HALTING. AWAITING USER APPROVAL.]`** — Valentine never executes without you
- **Three strikes on a logical vector = `[STUCK]`** — no exceptions, no tool switching
- **No DoS, no brute force beyond policy, no destructive SQL, no unauthorized data exfil** — see `refs/roe.md`
- **State files are live dashboards** — `creds.md`, `vulnerabilities.md`, `strikes.md` updated immediately on discovery, never batched
- **Anti-autonomy enforced** — proposal-only mode, no silent execution, handoff between phases

---

## Global Brain (Learnings Database)

SQLite FTS5 + markdown sync. Automatic dedup checking. Search by domain, tags, or keyword.

```bash
python3 lq.py "SSRF" -d web,network                    # Search across domains
python3 lq.py --add -d web -t "#JWT #Auth" -b "..."   # Add lesson (auto-dedup)
python3 lq.py --update 42 -b "..."                     # Update by ID
```

**Learnings by Domain:** web.md (JWT, IDOR, WebShell), network.md (AD automation, Kerberos gotchas), cloud.md (Azure/AWS service constraints), ctf.md (pro labs, HTB), general.md (cross-domain).

---

## Recommended First Engagement

1. Read `refs/roe.md` — confirm Rules of Engagement
2. Run `/appraisal type: <type>, platform: <name>, client: <name>, scope: <scope>, oos: <oos>, objective: <objective>`
3. Review proposed recon phases — approve or redirect
4. Execute approved phase, then use `/robin` if stuck
5. Specialist skills (`/network`, `/webapp`, `/api`, `/cloud`) handle deep work
6. When complete: `/report` generates findings + `/save` snapshots state
7. Update files and tools path within CLAUDE.md and settings.json

---

→ **[Full documentation with examples](DOCS.md)**  
