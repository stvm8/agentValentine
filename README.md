# Valentine 🩸

> *A penetration testing companion built on Claude Code. Not an autopilot — a co-pilot.*

---
## Design Philosophy

Valentine is not designed to conduct a penetration test from A to Z autonomously.

Valentine is a pentester's companion — helping you navigate complexity, save time, spark creative attack paths, and surface blind spots and rabbit holes you might miss mid-engagement. It is opinionated about one thing: the pentester stays in control.

Valentine is not perfect. It is designed for continuous learning and improvement, so both the agent and the pentester grow in knowledge with every engagement.

---

## Skills

| Skill | What It Does |
|-------|-------------|
| `/appraisal` | Kickoff — builds workspace, syncs brain, produces phased recon plan and handoff |
| `/network` | AD & network specialist — full kill chain from enum to domain takeover |
| `/webapp` | Web specialist — OWASP Web Top 10 driven |
| `/api` | API specialist — OWASP API Top 10 driven |
| `/cloud` | Cloud specialist — AWS, Azure, GCP |
| `/robin` | Co-pilot — reads your state, finds gaps, suggests next moves. Never executes |
| `/absorb` | Ingests writeups and blog posts into the Playbook library |
| `/save` | Hard checkpoint — snapshots all state before context clear |
| `/report` | Generates technical report with MITRE ATT&CK and OWASP mapping |

---

## Standard Flow

```
/appraisal → /webapp | /api | /network | /cloud → /robin (when stuck) → /save → /report
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

# Feed the brain
/absorb https://blog.example.com/adcs-esc4-writeup

# Save before clearing context
/save
```

---

## Hard Rules

- Every proposal ends with `[HALTING. AWAITING USER APPROVAL.]` — Valentine never executes without you
- Three strikes on a logical vector = `[STUCK]`, no exceptions
- No DoS, no brute force beyond policy, no destructive SQL, no unauthorized data exfil

---

→ **[Full documentation](DOCS.md)**
