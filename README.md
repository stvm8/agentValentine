---
title: README
created: 2026-04-05
modified: 2026-04-08
type: note
---

# AI Pentest Teams: Master Architecture

A highly optimized, token-efficient, and compartmentalized AI Pentesting framework powered by the Claude Code CLI.

The architecture is divided into specialized AI Agents (living in separate directories), modular Custom Skills, a domain-split Global Brain for continuous learning, and a management layer for cross-agent orchestration.

---

### Table 1: Specialized AI Agents
Each agent is bound by a specific `CLAUDE.md` master instruction file that dictates its persona, Rules of Engagement (ROE), and Threat Modeling framework.

| Agent Directory | Focus Area | Threat Model Triad | Short Description |
| :--- | :--- | :--- | :--- |
| `tksButler/` | **Engagement Management** | N/A (orchestrator) | Orchestrates and tracks authorized pentest engagements. Manages scope, progress, findings, and loot across all phases. Handles cross-agent handoffs and post-engagement archival. Never acts autonomously. |
| `bountyHunter/` | **Bug Bounty (P1-P4)** | Stack + Logic + Feature | Hunts for bounties on platforms like HackerOne/Bugcrowd. Prioritizes low-hanging fruit (P3/P4) and chains them into P1/P2 exploits. |
| `ctfPlayer/` | **CTF / Pro Labs** | OS + Route + Feature | Solves HackTheBox and TryHackMe machines from recon to root. Handles complex Active Directory pivoting and generates technical walkthroughs. |
| `netPen/` | **Enterprise Network** | OS/Device + Protocol/Port + Configuration | Conducts stealthy internal/external network assessments. Focuses on safe AD abuse and lateral movement. |
| `cloudPen/` | **Cloud Infrastructure** | Provider + Service/IAM + Misconfiguration | Audits AWS, Azure, and GCP environments. Identifies IAM privilege escalation paths and misconfigurations. |
| `webApiPen/` | **AppSec & API** | Stack/Framework + Endpoint/Feature + Input Vector | Tests SPAs and headless APIs against OWASP Top 10 (2021) and OWASP API Security Top 10 (2023). |

---

### Table 2: Agent Skills & Commands
Custom commands built using the `.claude/skills/<skill>/SKILL.md` framework. They act as state-machines, guiding the AI through structured workflows.

| Command / Skill | How to Use | Available In | Description |
| :--- | :--- | :--- | :--- |
| `/maestro` | `/maestro engagement: <Name>, focus: <Area>` | `tksButler` | Full engagement review -- restores state, consults playbooks, searches Global Brain, runs gap analysis, updates progress, and proposes prioritized next actions. |
| `/hawkeye` | `/hawkeye engagement: <Name>, given: <Targets>, oos: <OOS>` | `tksButler` | Exhaustive recon/enumeration planner -- passive recon, active enum, deep enum, and attack vector analysis. |
| `/handoff` | `/handoff from: <Agent>, to: <Agent>, target: <Target>` | `tksButler` | Cross-agent target handoff with full intel transfer (creds, recon, topology, findings). |
| `/archive` | `/archive engagement: <Name>` | `tksButler` | Post-engagement archival -- extracts lessons to Global Brain, generates summary, moves workspace to `_archive/`. |
| `/solve` | `/solve platform: <Platform> name: <Name> ...` | `ctfPlayer` | Initializes CTF workspace, syncs Global Brain, and proposes first recon step. Resume: `/solve continue: <Name>` |
| `/hunt` | `/hunt platform: <Platform> program: <Program> ...` | `bountyHunter` | Sets up Bug Bounty workspace, enforces scope boundaries. Resume: `/hunt continue: <Program>` |
| `/brief` | `/brief ROE.md` | `bountyHunter` | Reads ROE document, acknowledges boundaries, isolates a single target for a focused Game Plan. |
| `/work` | `/work client: <Client> project: <Project> ...` | `netPen`, `cloudPen`, `webApiPen` | Initializes professional enterprise engagement. Resume: `/work continue: <Project>` |
| `/enum` | `/enum client: <Client> project: <Project> scope: <CIDR>` | `netPen` | Spawns a Recon-Only Subagent with a strict look-but-don't-touch mandate. |
| `/robin` | `/robin [optional question/focus]` | **ALL AGENTS** | Domain-specific Co-Pilot. Reads engagement state, consults Playbooks, checks mistakes registry, runs gap analysis, and proposes prioritized next moves. |
| `/absorb` | `/absorb <URL or File>` | **ALL AGENTS** | Ingests external blogs/writeups. Extracts novel techniques, dedup-checks against existing Playbooks, and saves to knowledge base. |
| `/save` | `/save` | **ALL AGENTS** | Forces checkpoint of all progress + reasoning log to state files. Shows exact resume command for the agent. |

---

### Table 3: Framework Files & Workspace Structure

| File / Folder | Scope | What it is used for |
| :--- | :--- | :--- |
| `learnings/web.md` | Global | Domain-split Global Brain -- Web & API security lessons (bountyHunter, webApiPen). |
| `learnings/cloud.md` | Global | Domain-split Global Brain -- Cloud security lessons (cloudPen). |
| `learnings/network.md` | Global | Domain-split Global Brain -- Network & AD security lessons (netPen). |
| `learnings/ctf.md` | Global | Domain-split Global Brain -- CTF & Pro Lab lessons (ctfPlayer). |
| `learnings/general.md` | Global | Domain-split Global Brain -- Cross-domain techniques (ALL agents). |
| `{PLAYBOOKS}/` | Global | **Hierarchical Knowledge Base**. Organized by Category/Topic (e.g., `Web/SSRF.md`, `AD/Kerberoasting.md`). Consulted by `/robin`, `/maestro`, and `/hawkeye`. |
| `hooks/precompact_save.sh` | Global | **PreCompact Hook**. Auto-checkpoints state before context compression so reasoning is never lost. |
| `CLAUDE.md` | Agent | The **Master System Prompt**. Forces the agent into its persona, sets anti-rabbit-hole rules, and enforces the Proposal Loop. |
| `_references/` | Agent | Reference material loaded on-demand (e.g., `webApiPen/_references/owasp_checklist.md`). NOT loaded into system prompt permanently. |
| `scope.md` | Target | Strict boundary definitions, IPs, and *What You Cannot Do* constraints. |
| `progress.md` | Target | Phase-based checklist tracking what's done, in-progress, and remaining. |
| `*_state.md` | Target | State checkpoint files with reasoning logs (hunt_state.md, ctf_state.md, pentest_state.md). |
| `scans.md` / `recon.md` | Target | Filtered recon tool output. Raw data always piped to disk first. |
| `creds.md` | Target | Validated passwords, NTLM hashes, API keys, JWTs, and tokens. |
| `loot.md` | Target | Captured flags, sensitive code snippets, or exfiltrated data samples. |
| `network_topology.md` | Target | Live spatial tracking of hosts, subnets, and active tunnels. |
| `vulnerabilities.md` / `findings/` | Target | Confirmed findings mapped to frameworks (OWASP/CWE) with severity and remediation. |
| `handoff.md` | Target | Cross-agent intel transfer package created by `/handoff`. |

---

### `/robin` Domain Specialization

Each agent's `/robin` Co-Pilot is tailored to its domain:

| Agent | Robin Focus | Gap Analysis Specialization |
| :--- | :--- | :--- |
| `bountyHunter` | P4->P1 chaining, scope coverage | Unchained findings, 2nd-order targets, credential leverage, scope gaps |
| `ctfPlayer` | Exploitation & privilege escalation | Unexplored services, privesc vectors, credential reuse, pivot opportunities |
| `netPen` | AD abuse & lateral movement | AD attack paths, relay opportunities, trust abuse, routing gaps |
| `cloudPen` | IAM escalation & cloud misconfigs | IAM paths, metadata abuse, storage misconfigs, service-to-service pivots |
| `webApiPen` | OWASP-driven testing coverage | OWASP coverage gaps, auth boundaries, JWT flaws, API version gaps, chain opportunities |

---

### Global Brain Architecture

The Global Brain is split into domain-specific files under `learnings/` for scalable, low-noise retrieval:

```
learnings/
  web.md         # bountyHunter, webApiPen write here
  cloud.md       # cloudPen writes here
  network.md     # netPen writes here
  ctf.md         # ctfPlayer writes here
  general.md     # Cross-domain lessons (ALL agents)
```

**Entry format:** `#Tag1 #Tag2 [YYYY-MM-DD] Issue: X -> Solution: Y`

**Retrieval patterns:**
- Single domain: `grep -i "<keyword>" learnings/web.md`
- Cross-domain: `grep -ri "<keyword>" learnings/`
- tksButler (orchestrator): always searches all domains

---

### Hook Setup

To install the PreCompact auto-checkpoint hook for any agent:

```json
// Add to <agent>/.claude/settings.local.json
{
  "hooks": {
    "PreCompact": [{
      "matcher": "",
      "hooks": [{
        "type": "command",
        "command": "/absolute/path/to/hooks/precompact_save.sh",
        "timeout": 30
      }]
    }]
  }
}
```

This ensures state is always saved before context compression, even if the user forgets to `/save`.

---

### Core Design Principles

1. **Anti-Autonomy Protocol** -- Every agent must output a Threat Model + Proposal and halt. The human approves before any tool executes.
2. **Token-First Design** -- Pipe to disk, grep before reading, never cat full files. The context window is a finite combat resource.
3. **State-to-Disk** -- All progress lives in standardized `.md` files. Context can be cleared and rebuilt. Everything is Obsidian-compatible.
4. **Domain-Split Knowledge** -- The Global Brain is partitioned by security domain to prevent tag collisions and reduce grep noise at scale.
5. **3-Strike Anti-Rabbit-Hole** -- Strikes count against the logical vector, not exact syntax. Three failures = stop and ask.
6. **Self-Reflection** -- Agents log their own mistakes before reporting. The fleet learns from its failures.
