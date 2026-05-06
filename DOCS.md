# Valentine — Full Documentation

**Production Ready:** 2026-05-06 | **Status:** ✅ All systems operational

→ **[Back to README](README.md)**

---

## Architecture

```
Valentine Agent Root
├── README.md                  ← Quick start & capabilities overview
├── DOCS.md                    ← This file (full technical reference)
├── CLAUDE.md                  ← Fleet configuration (paths, rules, hard rules)
├── lq.py                      ← Learnings query tool (SQLite FTS5 + markdown sync)
│
├── valentine/
│   ├── CLAUDE.md              ← Agent persona, threat models, efficiency rules
│   └── .claude/skills/ (12 skills)
│       ├── appraisal/         ← Engagement kickoff & recon planning
│       ├── network/           ← AD, Windows, pivoting specialist
│       ├── webapp/            ← Web application specialist (OWASP Web Top 10)
│       ├── api/               ← API specialist (OWASP API Top 10)
│       ├── apiTesting/        ← Automated OWASP Top 10 baseline
│       ├── idorDeep/          ← Deep IDOR/BFLA methodology
│       ├── cloud/             ← AWS / Azure / GCP specialist
│       ├── robin/             ← Co-pilot review & gap analysis
│       ├── report/            ← Report generation (MITRE ATT&CK + OWASP)
│       ├── save/              ← State checkpoint before context compression
│       ├── absorb/            ← Knowledge ingestion from writeups/blogs
│       ├── defense/           ← Generate defense writeup from notes
│       └── .claude/settings.json ← Focus mode, autoCompact, hooks
│
├── Playbooks/ (120 technique entries)
│   ├── AD/                    ← 33 Active Directory techniques
│   ├── Cloud/                 ← 27 AWS/Azure/GCP techniques  
│   ├── Web/                   ← 13 Web & API techniques
│   ├── Windows/               ← 5 Windows-specific techniques
│   ├── Linux/                 ← 5 Linux privilege escalation techniques
│   ├── Pivoting/              ← 4 Multi-hop & tunnel techniques
│   ├── C2/                    ← 1 Sliver operator guide
│   └── CHAINS/ (32 chains)    ← Multi-step exploitation chains
│       ├── INDEX.md           ← Chain registry (trigger, prereq, yields)
│       ├── _FLOW.md           ← Decision tree for chain selection
│       └── 32 .md files       ← Documented exploitation chains
│
├── learnings/ (Global Brain)
│   ├── learnings.db           ← SQLite FTS5 index (116 KB)
│   ├── web.md                 ← Web & API Security (21 lines)
│   ├── network.md             ← AD & Network Security (26 lines)
│   ├── cloud.md               ← AWS / Azure / GCP (14 lines)
│   ├── ctf.md                 ← CTF & Pro Labs (54 lines)
│   ├── bounty.md              ← Bug Bounty observations (3 lines)
│   └── general.md             ← Cross-domain utilities (9 lines)
│
├── refs/ (Enforced Standards)
│   ├── roe.md                 ← Rules of Engagement (no DoS, no data exfil)
│   ├── strike_protocol.md     ← 3-strike rule on logical vectors
│   ├── proposal_format.md     ← Threat model triad + anti-autonomy format
│   ├── learning_format.md     ← Entry format + dedup rules
│   ├── reporting.md           ← Report generation protocol
│   ├── chain_protocol.md      ← Attack chain format + severity escalation
│   ├── pivot_protocol.md      ← Multi-hop topology tracking
│   └── content_quality.md     ← Playbook entry quality gates
│
└── hooks/ (Lifecycle Automation)
    ├── post_bash_strike.sh    ← Auto-injects strike reminder on bash failure
    └── precompact_save.sh     ← Snapshots state before context compression
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

## Playbook Coverage (120 Techniques + 32 Chains)

| Domain | Count | Techniques | Sample Chains |
|--------|-------|-----------|---|
| **Active Directory** | 33 | ACL abuse, BloodHound, Kerberoasting, AS-REP, NTLM relay, coercion (PetitPotam, PrinterBug, DFSCoerce), ADCS (ESC1-ESC14), SCCM, Exchange, lateral movement, DCSync, Golden Ticket, trust abuse, AMSI evasion, shellcode loaders | ntlm-relay-domain-takeover, adidnsdump-spoof-delegation |
| **Cloud (AWS/Azure/GCP)** | 27 | IAM enumeration, token exploitation, managed identities, credential exposure, S3/blob misconfig, CloudTrail evasion, Lambda exploitation, container escape, cross-account trust, SAML/OIDC, GCP metadata, CI/CD abuse, Kubernetes | azure-recon-to-kudu-dbexfil, cloud-cred-spray-escalation, gcp-sa-lateral-movement, s3-multiservice-chain, terraform-oidc-wildcard-s3 |
| **Web & API** | 13 | SQLi → RCE, SSRF, XXE, GraphQL abuse, command injection, auth bypass, BOLA/IDOR, XSS worms, API webshell, race conditions, JWT manipulation, WAF bypass, mass assignment | ssrf-cloud-tenant, ssrf-internal-pivot, graphql-batching-ratelimit-bypass, race-condition-bulk-export |
| **Windows** | 5 | Registry manipulation, UAC bypass, token impersonation, DLL hijacking, UAC token bleeding | — |
| **Linux** | 5 | SUID/capabilities abuse, cron PATH injection, sudo misconfig, kernel exploits, module loading | — |
| **Pivoting** | 4 | SSH tunnels, chisel, ligolo-ng, socat with topology tracking | — |
| **C2 (Sliver)** | 1 | Sliver operator & session management | — |
| **CHAINS (Multi-step)** | 32 | — | **Sample chains:** azure-blob-deleted-exfil, azure-function-sqli-exfil, azure-multitenant-oauth-blob-exfil, azure-spray-refresh-persistence, azure-spray-teams-exfil, aws-cred-spray-escalation, ci-runner-supply-chain-exfil, cdn-cache-poisoning-cred-harvest, debug-endpoint-cred-exfil, ebs-snapshot-ssh-key-bypass, gcp-aws-multitenant-pivot, go-registration-race-null-admin, k8s-pod-to-cluster-admin-node-proxy, needle-haystack-subdomain-llm, oauth-scope-downgrade-lateral, postgres-pgcrypto-rce, postgres-sniff-host-escape, terraform-statefile-cron-rce |

---

## Getting Started

### Pre-Flight Checklist

1. **Verify all 12 skills are accessible:**
   ```bash
   # You should be able to use:
   /appraisal /network /webapp /api /cloud /robin /report /save /absorb /defense /idorDeep /apiTesting
   ```

2. **Confirm proxy routing (if using Caido):**
   ```bash
   curl -x http://127.0.0.1:8081 https://example.com -v
   ```

3. **Test learnings query:**
   ```bash
   python3 lq.py "SSRF" -d web
   python3 lq.py "Kerberoasting" -d network
   ```

4. **Review engagement ROE:**
   - Read `refs/roe.md` — understand scope limits, brute force policy, data handling
   - Read `valentine/CLAUDE.md` — understand threat models and efficiency rules

5. **Verify tool inventory:**
   - Confirm key tools for your engagement type are installed

### Your First Engagement: Network Pentest Example

```bash
# 1. Kick off with /appraisal
/appraisal type: network, platform: InternalAD, client: Acme, scope: 10.0.0.0/16, oos: 10.0.0.1, objective: Domain Admin

# Valentine will:
# - Create workspace (scope.md, creds.md, vulnerabilities.md, strikes.md, progress.md, ad_enum.md, network_topology.md, attack_vectors.md)
# - Sync Global Brain for AD-specific learnings
# - Query Playbook indexes for known AD techniques
# - Propose 3 recon phases with detailed plans
# - Output: [HALTING. AWAITING USER APPROVAL.]

# 2. Review each phase and approve/redirect
# Example approval: "Yes, run Phase 1 as described."

# 3. Execute Phase 1, then resume Phase 2, etc.

# 4. When Phase 3 enumeration is complete, switch to specialist
/network continue: Acme

# 5. Network skill will:
# - Read handoff.md from /appraisal
# - Analyze AD findings, check strikes.md
# - Propose next vector (e.g., Kerberoasting on discovered SPNs)
# - Always propose, never execute without your approval

# 6. When stuck, ask Robin
/robin I have local admin on WEB01 and SMB signing is enabled. DCSync not working. What's next?

# 7. Save state before context compression
/save

# 8. Generate report
/report client: Acme, platform: InternalAD
```

### Your First Engagement: Web/API Example

```bash
# 1. Quick appraisal for web
/appraisal type: webapp, platform: BetaPortal, client: Gamma, scope: https://beta.gamma.com, oos: /admin, objective: Account takeover

# 2. If Swagger/Postman available, fast-track to API testing
/apiTesting swagger.json

# 3. Findings? Run deep IDOR analysis
/idorDeep --from-apiTesting

# 4. Manual exploitation
/api continue: Gamma

# 5. Full OWASP suite
/apiTesting swagger.json --full

# 6. Ask Robin for chain analysis
/robin I found BOLA on /accounts and SSRF on /render-pdf. How do these chain?

# 7. Generate findings
/report client: Gamma, platform: BetaPortal
```

### Your First Engagement: Cloud Example

```bash
# 1. Cloud pentest kickoff
/appraisal type: cloud, platform: AWSProd, client: Delta, scope: 123456789012, oos: prod-backup, objective: Lateral to managed database

# 2. Run cloud specialist
/cloud continue: Delta

# 3. Cloud skill will:
# - Query IAM policies
# - Enumerate roles, trusts, STS permissions
# - Check S3, Lambda, RDS, parameter store for exposed secrets
# - Map privilege escalation paths
# - Propose bounded exploitation actions

# 4. Example proposal chain:
# Vector 1: Assume role with iam:PassRole → Lambda execution
# Vector 2: Lambda env vars leak RDS password
# Vector 3: RDS credentials grant DMS access → cross-account replication

# 5. Each step: proposal → approval → execution

# 6. Report generation
/report client: Delta, platform: AWSProd
```

---

## How Valentine Works Internally

### The Proposal Loop (Every Action)

1. **Threat Model** — identify the OS, route, config, or tech you're targeting
2. **Strike Check** — read `strikes.md`, ensure the vector hasn't failed 3 times
3. **Tech Constraint Check** — query learnings for known limitations (e.g., "SSRF filter blocks RFC1918")
4. **Playbook Lookup** — grep relevant INDEX.md for matching techniques and prereqs
5. **Chain Analysis** — if successful, check `CHAINS/` for escalation opportunities
6. **Proposal Format** — output threat model, strike status, OPSEC rating, bounded task, failure risk, expected outcome
7. **Halt** — `[HALTING. AWAITING USER APPROVAL.]` — wait for user response
8. **Execution** (only after approval) — run tools, capture output to disk
9. **Logging** — immediately update `strikes.md` on failure, `creds.md` / `vulnerabilities.md` on success
10. **Repeat** — back to step 1 for next vector

### State Files (Live Dashboard)

All state files are updated **immediately** on discovery, never batched:

| File | Purpose | Updated When |
|------|---------|---|
| `progress.md` | Live plan dashboard | Before each phase, when starting/finishing each action |
| `creds.md` | All credentials discovered | Username/password/hash/token obtained |
| `vulnerabilities.md` | All findings with CVSS | Vulnerability confirmed (even if not exploited) |
| `strikes.md` | Strike counter per vector | After each failed exploitation attempt |
| `scans.md` | Tool output index | Scan results captured to disk |
| `endpoint.md` (web/api) | All discovered endpoints | During active recon, parameter discovery |
| `api_schema.md` (api) | Endpoint details | After schema parsing (Swagger, GraphQL introspection) |
| `ad_enum.md` (network) | AD objects discovered | After BloodHound, nxc enum, LDAP queries |
| `network_topology.md` (network) | Multi-hop routing | After each pivot/tunnel established |
| `attack_vectors.md` (network) | Identified kill chain paths | After each enumeration phase |
| `loot.md` (ctf) | Flags and important finds | When each flag/finding confirmed |

### Learnings Database (Global Brain)

**Structure:** SQLite FTS5 full-text index + markdown mirror

**Query modes:**
```bash
python3 lq.py "SSRF bypass WAF" -d web          # OR search, ranked by BM25
python3 lq.py "SSRF bypass WAF" -d web --and    # AND search (all terms required)
python3 lq.py "Kerberoasting" -d network        # Single domain
python3 lq.py "token" -d web,network,cloud      # Multiple domains (OR)
```

**Adding lessons (auto-dedup):**
```bash
python3 lq.py --add -d web -t "#JWT #Auth #Google" -b "When Google OAuth used, always check for code_id_token grant type confusion — can downgrade to implicit flow."
# lq.py checks if a similar entry exists first, never creates duplicates
```

**Updating existing lessons:**
```bash
python3 lq.py --update 42 -b "Updated body text..."
```

**Tags guide:** Use `#Technology`, `#Technique`, `#Constraint`, `#Mistake`, `#Hallucination`
- `#mistake` — known bad technique (Robin checks these)
- `#hallucination` — Claude-generated false positive (Robin avoids these)

### Integration Hooks

**`post_bash_strike.sh`** — Fires after every bash command failure
- Injects strike reminder into context
- Prevents Valentine from forgetting to log strike

**`precompact_save.sh`** — Fires before context compression
- Snapshots all workspace files
- Preserves critical state for context compaction summary:
  - Current vector being attempted
  - Strike counts per vector
  - All discovered credentials
  - Current shells/sessions active
  - Next planned action

---

## Design Philosophy

Valentine is opinionated about one thing: **the pentester stays in control**.

The agent reads, proposes, and waits. You approve, reject, or redirect. This is not a limitation — it is the design. An autonomous agent that executes without human review in a live engagement is a liability. Valentine is built to accelerate your decision-making, not replace it.

The strike rule, the anti-autonomy rule, the proposal format, the state files — all of it exists so you can hand off, resume, audit, and report on every decision made during an engagement. Valentine's output is your output.

---

## Troubleshooting

**"Vector exhausted (3 strikes)"**
- Check `strikes.md` — read the failure reasons for each strike
- Ask `/robin` for gap analysis and alternative paths
- Switch engagement type or domain if applicable

**"Learnings query returns no results"**
- Try broader keywords: `lq.py "SSRF"` vs `lq.py "filter bypass"`
- Check learnings.db exists in `learnings/` directory
- Manual grep: `grep -ri "keyword" learnings/`

**"Proposal format unexpected"**
- Ensure you're reading full skill output (don't cut off at `[PROPOSAL]` line)
- Verify `` — should always end with `[HALTING. AWAITING USER APPROVAL.]`
---

*Built on Claude Code. Designed for pentesters who think.*
