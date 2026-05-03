# Valentine — Full Documentation

→ **[Back to README](README.md)**


## Architecture

```
Fleet Config (CLAUDE.md)
└── valentine/
    ├── CLAUDE.md              ← Persona, rules, proposal format, state protocol
    └── .claude/skills/
        ├── appraisal/         ← Engagement kickoff & recon planning
        ├── network/           ← AD, Windows, pivoting specialist
        ├── webapp/            ← Web application specialist
        ├── api/               ← API specialist
        ├── cloud/             ← AWS / Azure / GCP specialist
        ├── robin/             ← Co-pilot review & gap analysis
        ├── absorb/            ← Knowledge ingestion from writeups
        ├── save/              ← State checkpoint
        └── report/            ← Report generation

Playbooks/                     ← Hierarchical technique library
├── AD/          (35 entries)
├── Cloud/       (25 entries)
├── Web/         (12 entries)
├── Windows/     (6 entries)
├── Linux/       (6 entries)
├── Pivoting/    (5 entries)
├── C2/          (2 entries)
└── CHAINS/      (5 attack chains)

learnings/                     ← Global Brain (domain-specific lessons)
├── web.md
├── network.md
├── cloud.md
├── ctf.md
├── bounty.md
└── general.md

hooks/
├── post_bash_strike.sh        ← Auto-injects strike reminder on bash failure
└── precompact_save.sh         ← Snapshots state before context compression
```

---

## Skills — Full Detail

### `/appraisal` — Engagement Kickoff

The entry point for every engagement. Give Valentine your scope, objective, and engagement type — it builds the workspace, syncs the Global Brain, and produces a phased recon plan before executing a single command.

**What it does:**
- Creates all workspace files (`scope.md`, `creds.md`, `vulnerabilities.md`, `strikes.md`, `progress.md`, and domain-specific files)
- Syncs past lessons from the Global Brain against identified technologies
- Queries relevant Playbook INDEX files for known techniques
- Proposes a four-phase recon plan (passive recon → active enum → deep enum → attack vector analysis) and **halts for approval before executing any phase**
- Produces `handoff.md` — a structured document that all specialist skills read on startup

**Usage:**
```
/appraisal type: network, platform: InternalAD, client: Acme, scope: 10.0.0.0/16, oos: 10.0.0.1, objective: Domain Admin
/appraisal type: webapp, platform: WebPortal, client: Beta, scope: https://beta.example.com, oos: /admin, objective: Data exfil
/appraisal type: cloud, platform: AWSProd, client: Gamma, scope: 123456789, oos: none, objective: IAM escalation
```

---

### `/network` — Network & Active Directory Specialist

Takes over from `/appraisal` for internal network and AD engagements. Reads the handoff, restores state, and drives the AD kill chain — enumeration through domain takeover.

**Coverage:**
- BloodHound, Kerberoasting, AS-REP Roasting, DACL abuse
- NTLM relay, coercion attacks (PetitPotam, PrinterBug, DFSCoerce)
- Pass-the-Hash, Pass-the-Ticket, credential spraying
- Lateral movement (WMI, PSRemoting, SCM, admin shares)
- Domain privilege escalation (DCSync, Golden Ticket, trust abuse)
- Pivoting (chisel, ligolo-ng, Sliver SOCKS5) with topology tracking

**Threat Model Triad:**
```
[THREAT MODEL] OS: <OS> | Route: <Direct/Tunnel> | Config: <Protocol> -> <Deduction>
[STRIKE CHECK] Vector: <name> | Strikes: <N>/3
[PROPOSAL] Task: <bounded action>
[HALTING. AWAITING USER APPROVAL.]
```

**Usage:**
```
/network client: Acme, platform: InternalAD
/network continue: Acme
```

---

### `/webapp` — Web Application Specialist

OWASP Web Top 10 (2021) driven. Takes the handoff and maps attack surface to priority vulnerability categories before proposing any tests.

**Coverage:**
- Injection (SQLi, XSS, SSTI, command injection, header injection)
- Access control (IDOR, privilege escalation, forced browsing, path traversal)
- Auth flaws (JWT attacks, session management, MFA bypass, password reset logic)
- Business logic (race conditions, rate limit bypass, workflow abuse)
- SSRF and second-order attacks (PDF generators, webhooks, async processors)
- Security misconfiguration, cryptographic failures
- Finding chaining for maximum impact

**Usage:**
```
/webapp client: Acme, platform: WebPortal
/webapp continue: Acme
```

---

### `/api` — API Specialist

OWASP API Security Top 10 (2023) driven. Focused on modern API attack surfaces — REST, GraphQL, gRPC, and mobile backends.

**Coverage:**
- BOLA / IDOR across every endpoint
- Auth flaws and JWT attacks (alg:none, key confusion, brute)
- Mass assignment and hidden parameter injection
- Function-level authorization bypass and method tampering
- GraphQL depth/complexity abuse, shadow APIs, deprecated versions
- Unsafe third-party consumption and webhook chain abuse

**Usage:**
```
/api client: Acme, platform: MobileAPI
/api continue: Acme
```

---

### `/cloud` — Cloud Specialist

Covers AWS, Azure, and GCP. Reads IAM state from the handoff and maps privilege escalation paths before any action.

**Coverage:**
- IAM enumeration and escalation path mapping (iam:PassRole, sts:AssumeRole, role chaining)
- Storage misconfigs (public buckets, blobs, snapshots, versioned secrets)
- Compute abuse (IMDSv1/v2, Lambda env vars, container escapes, user-data scripts)
- Cross-account trust abuse, SAML/OIDC misconfigs, STS token manipulation
- Serverless attacks (Lambda code review, API Gateway misconfigs, event injection)
- CloudTrail evasion awareness

**Usage:**
```
/cloud client: Acme, platform: AWSProd
/cloud continue: Acme
```

---

### `/robin` — Co-Pilot Review

Your strategic advisor. Does not execute. Reads your full engagement state, cross-references the Playbook and Global Brain, and tells you what you might be missing.

**What Robin does:**
- Reads all workspace files including `strikes.md` first — never suggests exhausted vectors
- Follows the `_FLOW.md` decision trees to identify your current position in the kill chain
- Runs two-stage Playbook retrieval (INDEX grep → full technique read)
- Avoids known-bad techniques by checking `#mistake` and `#hallucination` tags in learnings
- Produces a structured `[ROBIN REVIEW]` with situation summary, coverage gaps, prioritized next moves, and decision points requiring your input

**When to use Robin:**
- Stuck after a failed vector and unsure where to pivot
- Want a second opinion before spending a strike
- Need a full coverage audit mid-engagement
- Starting a new phase and want strategic framing

**Usage:**
```
/robin
/robin I have local admin on WEB01, what should I prioritize?
/robin Is there a chain opportunity here?
```

---

### `/absorb` — Knowledge Ingestion

Reads external writeups, blog posts, CTF walkthroughs, or local files and injects the techniques into the Playbook library. Deduplicates before writing — never creates duplicates.

**What it does:**
- Fetches and strips source content (URL or local file)
- Extracts novel exploit chains, bypasses, and specific tool payloads — ignores definitions
- Dedup-checks against existing Playbook entries before writing
- Writes structured entries with Tags, Trigger, Prereq, Yields, Opsec, and date stamps
- Updates `INDEX.md` for search, `_FLOW.md` for decision flow placement
- Detects multi-technique chains and proposes candidate entries to `CHAINS/INDEX.md` for your review — never creates chain files without approval

**Usage:**
```
/absorb https://blog.example.com/adcs-esc4-writeup
/absorb /tmp/htb-machine-writeup.pdf
```

---

### `/save` — State Checkpoint

Hard override. Immediately halts all activity and saves the complete engagement state to disk. Use before `/clear`, before handing off, or whenever you want a clean snapshot.

**What it saves:**
All workspace files — `creds.md`, `vulnerabilities.md`, `strikes.md`, `progress.md`, `scans.md` and all domain-specific files. Updates `progress.md` with done/in-progress/failed/next structure and a reasoning log.

**Output:**
```
[STATE SAVED] Run '/clear', then resume with: /<specialist_skill> continue: <client>
```

---

### `/report` — Report Generation

Reads all engagement state files and generates a clean technical report. Automatically detects engagement type and applies the correct template (CTF walkthrough vs. full pentest report with business impact and remediation).

**What it produces:**
- Findings sorted Critical → High → Medium → Low → Informational
- OWASP mapping (Web A01-A10 or API API1-API10) for web/api engagements
- MITRE ATT&CK tactic and technique mapping for all engagement types
- CWE classification per finding
- Lesson extraction to the Global Brain after report generation

*Tip: Switch to Haiku model before running `/report` — it handles structured formatting well and saves cost.*

**Usage:**
```
/report client: Acme, platform: WebPortal
```

---

## How to Use Valentine Effectively

### Effective Prompting Patterns

```bash
# Start an engagement
/appraisal type: network, platform: CorpAD, client: Acme, scope: 192.168.1.0/24, oos: 192.168.1.1, objective: Domain Admin

# Ask Robin a focused question
/robin I have a foothold as svc_backup on DC01. SMB signing is enabled. What's next?

# Resume after a break
/network continue: Acme

# Absorb after reading a good writeup
/absorb https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials

# Save before clearing context
/save
```

### What Valentine Will Not Do

- **Execute without approval** — every proposal ends with `[HALTING. AWAITING USER APPROVAL.]`
- **Propose an exhausted vector** — three strikes means [STUCK], no exceptions
- **Dump raw tool output into context** — all large outputs go to disk
- **Violate the ROE** — no DoS, no brute force beyond policy, no destructive SQL, no unauthorized data exfil
- **Run autonomously through an entire engagement** — Valentine proposes one bounded action at a time

---

## The Global Brain

The `learnings/` directory is Valentine's persistent memory across engagements. Every lesson is tagged, timestamped, and checked for duplicates before appending.

| File | Domain |
|------|--------|
| `web.md` | Web application techniques, bypasses, mistakes |
| `network.md` | AD, Windows, pivoting lessons |
| `cloud.md` | AWS, Azure, GCP specific knowledge |
| `ctf.md` | CTF-specific patterns |
| `bounty.md` | Bug bounty context |
| `general.md` | Cross-domain lessons |

Tags `#mistake` and `#hallucination` mark known-bad techniques. Robin checks these before every recommendation.

---

## Hooks

Two lifecycle hooks run automatically:

**`post_bash_strike.sh`** — fires after every failed bash command. Injects a strike reminder into context so Valentine never forgets to update `strikes.md` after a failed exploitation attempt.

**`precompact_save.sh`** — fires before Claude Code compresses context. Snapshots all workspace files to `.snapshots/<timestamp>/` and instructs the compaction summary to preserve critical state (active vector, strike counts, credentials, live sessions, next planned action).

---

## Playbook Coverage

| Domain | Techniques | Chains |
|--------|-----------|--------|
| Active Directory | 35 | ntlm-relay-domain-takeover |
| Cloud (AWS/Azure/GCP) | 25 | azure-blob-to-keyvault, azure-recon-to-kudu-dbexfil, ssrf-cloud-tenant |
| Web | 12 | ssrf-internal-pivot |
| Windows | 6 | — |
| Linux | 6 | — |
| Pivoting | 5 | — |
| C2 (Sliver) | 2 | — |

---

## Design Philosophy

Valentine is opinionated about one thing: **the pentester stays in control**.

The agent reads, proposes, and waits. You approve, reject, or redirect. This is not a limitation — it is the design. An autonomous agent that executes without human review in a live engagement is a liability. Valentine is built to accelerate your decision-making, not replace it.

The strike rule, the anti-autonomy rule, the proposal format, the state files — all of it exists so you can hand off, resume, audit, and report on every decision made during an engagement. Valentine's output is your output.

---

*Built on Claude Code. Designed for pentesters who think.*
