---
description: Thorough recon/enumeration on a target - leave no stone unturned. (e.g., /hawkeye engagement: ClientX, given: 10.0.0.0/24, oos: 10.0.0.1)
disable-model-invocation: true
---
I am executing the `/hawkeye` command.
**Arguments:** $ARGUMENTS

Parse the arguments for: `engagement:`, `given:` (in-scope targets), `oos:` (out-of-scope targets).

Execute the following sequence:

## 1. Workspace Setup
1. Run `mkdir -p engagements/<engagement>` and `cd` into it.
2. Create `scope.md` with:
   - **In-Scope:** All targets from `given:`
   - **Out-of-Scope:** All targets from `oos:`
   - **Date:** Current date
3. Create placeholder files: `progress.md`, `notes/recon_raw.md`, `findings/`, `loot/`.

## 2. Playbook Reference
1. Search `$HOME/Pentester/AI_Teams/Playbooks/` for reconnaissance and enumeration playbooks relevant to the target type (network, web, cloud, AD, etc.).
2. List which playbooks will be followed. If no relevant playbook exists, note that to the user.

## 3. Recon Plan Proposal
Output a `[🦅 HAWKEYE RECON PLAN]` that covers ALL of the following phases. Do NOT execute anything - propose only:

### Phase 1: Passive Reconnaissance
- OSINT, DNS records, certificate transparency, WHOIS, subdomain enumeration
- Search engine dorking, public data leaks, technology fingerprinting
- Reference applicable playbook steps

### Phase 2: Active Enumeration
- Port scanning (full TCP + top UDP), service version detection
- Banner grabbing, protocol-specific enumeration (SMB, SNMP, LDAP, HTTP, etc.)
- Web technology stack identification, directory/file discovery
- Reference applicable playbook steps

### Phase 3: Deep Enumeration
- Service-specific deep dives based on Phase 2 results
- Authentication mechanism discovery, default credential checks
- API endpoint enumeration, parameter discovery
- SSL/TLS analysis, misconfigurations
- Reference applicable playbook steps

### Phase 4: Attack Vector Analysis
For each discovered service/endpoint, identify potential attack vectors. Present as a sorted table:

| # | Target | Vector | Complexity | Confidence | Notes |
|---|--------|--------|------------|------------|-------|

Sort by complexity (easiest first), then by confidence (highest first).

## 4. Execution
- Wait for user approval before executing ANY phase.
- After each phase, summarize findings into `notes/` and update `progress.md`.
- After all phases, compile the final attack vector table into `findings/attack_vectors.md`.
- Update or create playbook entries in `$HOME/Pentester/AI_Teams/Playbooks/` if new techniques are observed.

## Rules
- NEVER scan or touch out-of-scope targets.
- NEVER skip a phase - be exhaustive.
- Summarize tool output to conserve tokens; store raw data references in `notes/`.
- Always cross-reference findings against playbooks for known techniques.
