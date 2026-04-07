---
title: README
created: 2026-04-05
modified: 2026-04-07
type: note
---

# AI Pentest Teams: Master Architecture

This repository contains a highly optimized, token-efficient, and compartmentalized AI Pentesting framework powered by the Claude Code CLI. 

The architecture is divided into specialized AI Agents (living in separate directories), modular Custom Skills, and a shared "Global Brain" to ensure continuous learning and strict OPSEC compliance.

---

### Table 1: Specialized AI Agents
Each agent is bound by a specific `CLAUDE.md` master instruction file that dictates its persona, Rules of Engagement (ROE), and Threat Modeling framework.

| Agent Directory | Focus Area | Short Description |
| :--- | :--- | :--- |
| `tksButler/` | **Engagement Management** | Orchestrates and tracks authorized pentest engagements. Manages scope, progress, findings, and loot across all phases. Never acts autonomously — proposes only. |
| `bountyHunter/` | **Bug Bounty (P1-P4)** | Hunts for bounties on platforms like HackerOne/Bugcrowd. Prioritizes low-hanging fruit (P3/P4) and attempts to chain them into P1/P2 exploits. Strictly obeys ROE and generates copy-pasteable PoC reports. |
| `ctfPlayer/` | **CTF / Pro Labs** | Solves HackTheBox and TryHackMe machines from recon to root. Handles complex Active Directory pivoting (Sliver/Chisel) and generates 0xdf-style technical walkthroughs. |
| `netPen/` | **Enterprise Network** | Conducts stealthy internal/external network assessments. Focuses on safe AD abuse (Kerberoasting, SMB Relay) and lateral movement. Explicitly avoids account lockouts and destructive exploits. |
| `cloudPen/` | **Cloud Infrastructure** | Audits AWS, Azure, and GCP environments. Identifies IAM privilege escalation paths, misconfigurations, and serverless logic flaws without exfiltrating sensitive client data. |
| `webApiPen/` | **AppSec & API** | Tests SPAs and headless APIs against OWASP Top 10 (2021) and OWASP API Security Top 10 (2023). Full OWASP coverage checklist with CWE mapping. Handles JWT, GraphQL, and REST API testing. |

---

### Table 2: Agent Skills & Commands
These custom commands are built using the `.claude/skills/<skill>/SKILL.md` framework. They act as state-machines, guiding the AI through structured workflows.

| Command / Skill | How to Use | Available In | Description |
| :--- | :--- | :--- | :--- |
| `/maestro` | `/maestro engagement: <Name>, focus: <Area>` | `tksButler` | Full engagement review — restores state, consults playbooks, runs gap analysis (blind spots, untried techniques, chained attacks, credential leverage), updates progress, and proposes prioritized next actions. |
| `/hawkeye` | `/hawkeye engagement: <Name>, given: <Targets>, oos: <OOS>` | `tksButler` | Exhaustive recon/enumeration planner — passive recon, active enum, deep enum, and attack vector analysis. Proposes phases for approval before executing. |
| `/solve` | `/solve platform: <Platform> name: <Name> ...`<br>*(Resume: `/solve continue: <Name>`)* | `ctfPlayer` | Initializes workspace, creates placeholder files, checks the Global Brain, and proposes the first recon step for a CTF. |
| `/hunt` | `/hunt platform: <Platform> program: <Program> ...`<br>*(Resume: `/hunt continue: <Program>`)* | `bountyHunter` | Sets up a Bug Bounty workspace, enforces strict out-of-scope boundaries, and proposes token-safe enumeration tasks. |
| `/brief` | `/brief ROE.md` | `bountyHunter` | Reads a massive Rules of Engagement document, acknowledges boundaries, and isolates a single target for a focused Game Plan. |
| `/work` | `/work client: <Client> project: <Project> ...`<br>*(Resume: `/work continue: <Project>`)* | `netPen`, `cloudPen`, `webApiPen` | Initializes a professional enterprise engagement. Enforces ROE, sets up proxy/auth modes, and maps the attack surface. |
| `/enum` | `/enum client: <Client> project: <Project> scope: <CIDR>` | `netPen` | Spawns a "Recon-Only Subagent" with a strict look-but-don't-touch mandate to safely map massive enterprise subnets without exploiting. |
| `/robin` | `/robin [optional question/focus]` | **ALL AGENTS** | Domain-specific Co-Pilot. Reads your engagement state files, consults Playbooks, checks `agent_mistakes.md` for known bad patterns, runs gap analysis tailored to the agent's specialty, and proposes prioritized next moves with a strategy table. |
| `/absorb` | `/absorb <URL or File>` | **ALL AGENTS** | Ingests external blogs, writeups, or PDFs. Strips fluff, extracts novel exploit chains/bypasses, and saves them to the Playbooks knowledge base. |
| `/save` | `/save` | **ALL AGENTS** | Forces the agent to checkpoint all progress to state files so context can be safely cleared with `/clear`. |

---

### Table 3: Framework Files & Workspace Structure
To maintain maximum token efficiency and prevent LLM hallucinations, the agents rely on a strictly standardized local file structure rather than storing data in the chat context window.

| File / Folder | Scope | What it is used for |
| :--- | :--- | :--- |
| `$HOME/Pentester/AI_Teams/Playbooks/` | Global | **Hierarchical Knowledge Base**. Organized by Category/Topic (e.g., `Web/SSRF.md`, `AD/Kerberoasting.md`). Contains step-by-step techniques, tool commands, and decision points. Consulted by `/robin`, `/maestro`, and `/hawkeye` before proposing any approach. |
| `$HOME/Pentester/AI_Teams/agent_learnings.md` | Global | The **"Global Brain"**. A dynamic, tagged database of WAF bypasses, syntax fixes, and successful techniques shared across all agents. Retrieved via `grep -i` with dynamic keywords. |
| `$HOME/Pentester/AI_Teams/agent_mistakes.md` | Global | **Known-Bad Registry**. Logs tools, syntax, or techniques confirmed to be broken or hallucinated. Checked by `/robin` before making suggestions to avoid repeating past mistakes. |
| `CLAUDE.md` | Agent Level | The **Master System Prompt**. Forces the agent into its specific persona, sets anti-rabbit-hole rules, and enforces the `[⚡ PROPOSAL]` execution loop. |
| `_templates/` | Agent Level | Holds Markdown structural blueprints (e.g., `ctfTemplate.md`, `bountyTemplate.md`) that force the AI to generate consultant-grade reports without hallucinating. |
| `scopeExtract.py` | Agent Level | Bugcrowd scope parser (bountyHunter). Extracts in-scope/out-of-scope targets from raw program details into Obsidian-compatible Markdown. |
| `scope.md` | Target Level | Contains strict boundary definitions, IPs, and explicit *What You Cannot Do* instructions for the current target. |
| `progress.md` | Target Level | Phase-based checklist tracking what's done, in-progress, and remaining. Updated by `/maestro` and `/save`. |
| `scans.md` / `recon.md` | Target Level | Filtered output of massive recon tools (Nmap, ffuf, httpx, nuclei). Used to keep the token context window small. |
| `endpoints.md` / `targets.md` | Target Level | Discovered URLs, HTTP methods, parameters, and auth requirements (webApiPen) or high-value endpoints (bountyHunter). |
| `api_schema.md` | Target Level | Parsed and annotated OpenAPI/Swagger/GraphQL schemas (webApiPen). |
| `creds.md` | Target Level | Validated passwords, NTLM hashes, API keys, JWTs, and access tokens. |
| `loot.md` | Target Level | Captured CTF flags, sensitive source code snippets, or exfiltrated data samples. |
| `network_topology.md` | Target Level | Live spatial tracking file. Documents dual-homed hosts, discovered subnets, and active pivot tunnels (Sliver/Chisel). |
| `ad_enum.md` / `iam_enum.md` | Target Level | Active Directory enumeration (netPen) or IAM users/roles/policies (cloudPen). |
| `vulnerabilities.md` / `findings/` | Target Level | Confirmed findings mapped to frameworks (OWASP/CWE) with severity, business impact, reproduction steps, and remediation. |
| `attack_vectors.md` | Target Level | Identified-but-unexploited vulnerabilities logged by recon subagents (netPen `/enum`). |

---

### `/robin` Domain Specialization

Each agent's `/robin` Co-Pilot is tailored to its domain rather than being generic:

| Agent | Robin Focus | Gap Analysis Specialization |
| :--- | :--- | :--- |
| `bountyHunter` | P4→P1 chaining, scope coverage | Unchained findings, 2nd-order targets, credential leverage, scope gaps |
| `ctfPlayer` | Exploitation & privilege escalation | Unexplored services, privesc vectors, credential reuse, pivot opportunities |
| `netPen` | AD abuse & lateral movement | AD attack paths, relay opportunities, trust abuse, routing gaps |
| `cloudPen` | IAM escalation & cloud misconfigs | IAM paths, metadata abuse, storage misconfigs, service-to-service pivots |
| `webApiPen` | OWASP-driven testing coverage | OWASP coverage gaps, auth boundaries, JWT flaws, API version gaps, chain opportunities |
