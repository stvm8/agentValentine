---
title: README
created: 2026-04-05
modified: 2026-04-05
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
| `bountyHunter/` | **Bug Bounty (P1-P4)** | Hunts for bounties on platforms like HackerOne/Bugcrowd. Prioritizes low-hanging fruit (P3/P4) and attempts to chain them into P1/P2 exploits. Strictly obeys ROE and generates copy-pasteable PoC reports. |
| `ctfPlayer/` | **CTF / Pro Labs** | Solves HackTheBox and TryHackMe machines from recon to root. Handles complex Active Directory pivoting (Sliver/Chisel) and generates 0xdf-style technical walkthroughs. |
| `netPen/` | **Enterprise Network** | Conducts stealthy internal/external network assessments. Focuses on safe AD abuse (Kerberoasting, SMB Relay) and lateral movement. Explicitly avoids account lockouts and destructive exploits. |
| `cloudPen/` | **Cloud Infrastructure** | Audits AWS, Azure, and GCP environments. Identifies IAM privilege escalation paths, misconfigurations, and serverless logic flaws without exfiltrating sensitive client data. |
| `webApiPen/` | **AppSec & API** | Tests SPAs and headless APIs against the strict OWASP API Top 10 (2023) and WSTG. Automatically writes Python scripts to handle dynamic Bearer token (EntraID/OAuth) injection. |

---

### Table 2: Agent Skills & Commands
These custom commands are built using the modern `.claude/skills/<skill>/SKILL.md` framework. They act as state-machines, guiding the AI through structured workflows.

| Command / Skill | How to Use | Available In | Description |
| :--- | :--- | :--- | :--- |
| `/solve` | `/solve platform: <Platform> name: <Name> ...`<br>*(Resume: `/solve continue: <Name>`)* | `ctfPlayer` | Initializes workspace, creates placeholder files, checks the Global Brain, and proposes the first recon step for a CTF. |
| `/hunt` | `/hunt platform: <Platform> program: <Program> ...`<br>*(Resume: `/hunt continue: <Program>`)* | `bountyHunter` | Sets up a Bug Bounty workspace, enforces strict out-of-scope boundaries, and proposes token-safe enumeration tasks. |
| `/work` | `/work client: <Client> project: <Project> ...`<br>*(Resume: `/work continue: <Project>`)* | `netPen`, `cloudPen`, `webApiPen` | Initializes a professional enterprise engagement. Enforces ROE, sets up proxy/auth modes, and maps the attack surface. |
| `/enum` | `/enum client: <Client> project: <Project> scope: <CIDR>` | `netPen` | Spawns a "Recon-Only Subagent" with a strict look-but-don't-touch mandate to safely map massive enterprise subnets without exploiting. |
| `/brief` | `/brief ROE.md` | `bountyHunter` | Reads a massive Rules of Engagement document, acknowledges boundaries, and isolates a single target for a focused Game Plan. |
| `/robin` | `/robin [optional question/roadblock]` | **ALL AGENTS** | Calls the Senior Co-Pilot. Safely reads your messy notes, auto-organizes them into standardized files, extracts new lessons to the Global Brain, and suggests the next attack vector. |
| `/absorb` | `/absorb <URL or File>` | **ALL AGENTS** | Ingests external blogs, writeups, or PDFs. Strips fluff, extracts novel exploit chains/bypasses, and permanently injects them into the Global Brain. |

---

### Table 3: Framework Files & Workspace Structure
To maintain maximum token efficiency and prevent LLM hallucinations, the agents rely on a strictly standardized local file structure rather than storing data in the chat context window.

| File / Folder | Scope | What it is used for |
| :--- | :--- | :--- |
| `agent_learnings.md` | Global (Root) | The **"Global Brain"**. A dynamic database of tagged WAF bypasses, syntax fixes, and successful techniques shared across all 5 agents. |
| `CLAUDE.md` | Agent Level | The **Master System Prompt**. Forces the agent into its specific persona, sets anti-rabbit-hole rules, and enforces the `[⚡ PROPOSAL]` execution loop. |
| `_templates/` | Agent Level | Holds Markdown structural blueprints (e.g., `ctfTemplate.md`, `bountyTemplate.md`) that force the AI to generate consultant-grade reports without hallucinating. |
| `notes.md` | Target Level | The user's messy scratchpad. The user dumps raw thoughts and terminal copy-pastes here for `/robin` to read and automatically organize. |
| `scans.md` / `targets.md` | Target Level | Filtered output of massive recon tools (Nmap, ffuf, httpx). Used to keep the token context window small. |
| `creds.md` | Target Level | Auto-populated by `/robin`. Stores validated passwords, NTLM hashes, API keys, and JWTs. |
| `loot.md` | Target Level | Auto-populated by `/robin`. Stores captured CTF flags, sensitive source code snippets, or exfiltrated DB dumps. |
| `network_topology.md` | Target Level | Live spatial tracking file. Documents dual-homed hosts, discovered subnets, and active pivot tunnels (Sliver/Chisel). |
| `vulnerabilities.md` | Target Level | A pre-report staging file where the agent logs confirmed flaws mapped to frameworks (like OWASP) before writing the final walkthrough. |
| `scope.md` | Target Level | Contains strict boundary definitions, IPs, and explicit *What You Cannot Do* instructions for the current target. |
