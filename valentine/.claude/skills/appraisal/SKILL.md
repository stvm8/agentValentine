---
description: Start a new engagement — thorough recon, enumeration, and attack vector analysis. Produces handoff for specialist skills. (e.g., /appraisal type: network, platform: InternalAD, client: Acme, scope: 10.0.0.0/16, oos: 10.0.0.1, objective: Domain Admin)
disable-model-invocation: true
---
I am executing the `/appraisal` command.
**Arguments:** $ARGUMENTS

Parse the arguments for: `type:` (webapp|api|network|cloud|ctf), `platform:`, `client:`, `scope:`, `oos:`, `objective:`.

## 1. Workspace Setup
1. Run `mkdir -p <platform>/<client> && cd <platform>/<client>`.
2. Create `scope.md`:
   ```
   # Engagement Scope
   **Type:** <type>
   **Platform:** <platform>
   **Client:** <client>
   **In-Scope:** <scope>
   **Out-of-Scope:** <oos>
   **Objective:** <objective>
   **Date:** <current date>
   ```
3. Create common placeholder files: `creds.md`, `vulnerabilities.md`, `strikes.md`, `scans.md`, `progress.md`.
4. Create domain-specific files based on `type:`:
   - webapp/api: `recon.md`, `endpoints.md`, `api_schema.md`
   - network: `ad_enum.md`, `network_topology.md`, `attack_vectors.md`
   - cloud: `assets.md`, `iam_enum.md`
   - ctf: `loot.md`, `network_topology.md`

## 2. Global Brain Sync
Based on `type:`, identify 2-3 core technologies from scope:
- webapp: REST, GraphQL, JWT, framework names
- api: REST, gRPC, GraphQL, authentication methods
- network: ActiveDirectory, SMB, Kerberos, SNMP
- cloud: AWS/Azure/GCP, IAM, S3/Blob, Lambda
- ctf: Cross-domain — identify from scope description

Execute: `grep -ri "<tech1>\|<tech2>" {LEARNINGS}/` to retrieve past lessons across all domains.

## 3. Playbook Sync
Based on `type:`, grep relevant INDEX files:
- webapp/api: `grep -i "<signal>" {PLAYBOOKS}/Web/INDEX.md`
- network: `grep -i "<signal>" {PLAYBOOKS}/AD/INDEX.md {PLAYBOOKS}/Windows/INDEX.md {PLAYBOOKS}/Pivoting/INDEX.md {PLAYBOOKS}/C2/INDEX.md`
- cloud: `grep -i "<signal>" {PLAYBOOKS}/Cloud/INDEX.md`
- ctf: `grep -i "<signal>" {PLAYBOOKS}/*/INDEX.md`

## 4. Recon Plan — Propose ALL Phases (Do NOT Execute Yet)
Output a `[APPRAISAL PLAN]` covering:

### Phase 1: Passive Reconnaissance
Based on type:
- **webapp/api:** Passive URL discovery (`gau`, `waymore`), tech fingerprinting (`httpx`, `whatweb`), JS analysis (`katana --js-crawl`), API schema discovery (Swagger, OpenAPI, GraphQL introspection, Postman collections).
- **network:** DNS enumeration, OSINT, certificate transparency, WHOIS, subdomain enumeration.
- **cloud:** Public cloud asset discovery, DNS, open storage enumeration, certificate transparency.
- **ctf:** Full port scan, banner grab, web stack identification.

### Phase 2: Active Enumeration
Based on type:
- **webapp/api:** Active crawl (`katana`), directory fuzzing (`ffuf`), parameter discovery (`arjun`), auth boundary mapping.
- **network:** Full TCP + top 100 UDP port scan, service version detection, protocol-specific enumeration (SMB, SNMP, LDAP, HTTP).
- **cloud:** Authenticated IAM enumeration, resource inventory, trust mapping.
- **ctf:** Service-specific enumeration, default credential checks.

### Phase 3: Deep Enumeration
Based on type:
- **webapp/api:** `nuclei` scanning (no DoS), `dalfox` on reflected params, `sqlmap` (safe flags), authentication mechanism analysis, JWT analysis.
- **network:** BloodHound ingest, Kerberoasting/AS-REP roast candidate identification, SMB signing check, GPO analysis, trust enumeration.
- **cloud:** IAM policy analysis, privilege escalation path mapping, cross-account trust analysis, metadata endpoint probing.
- **ctf:** Custom service analysis, binary examination, config file hunting, SUID/sudo enumeration.

### Phase 4: Attack Vector Analysis
Present ALL discovered vectors in a prioritized table:

| # | Target | Vector | Complexity | Confidence | Prereqs Met? | Playbook Ref |
|---|--------|--------|------------|------------|--------------|--------------|

Sort by: confidence (highest first), then complexity (easiest first).

`[HALTING. AWAITING USER APPROVAL.]`

## 5. Phase Execution
After user approves each phase:
- Execute the phase.
- Update `scans.md` with filtered results (pipe raw output to disk, grep for actionable data).
- Update `progress.md` with completed actions.
- After each phase, output a brief summary (counts and key findings only) and propose the next phase.

## 6. Handoff Generation
After all recon phases are complete, create `handoff.md`:

```markdown
# Appraisal Handoff
**Date:** <date>
**Type:** <type>
**Client:** <client>
**Platform:** <platform>
**Objective:** <objective>

## Tech Stack Summary
<Discovered technologies, frameworks, versions — bullet list>

## Attack Surface
<Summarized endpoints, services, ports, cloud resources>

## Prioritized Attack Vectors
| # | Target | Vector | Recommended Skill | Complexity | Confidence |
|---|--------|--------|-------------------|------------|------------|

## Credentials Collected
<Any creds found during recon, or "None" if clean>

## Recommended Next Steps
1. Run `/<specialist_skill> client: <client>, platform: <platform>` for the top-priority vector category.
```

Output: `[APPRAISAL COMPLETE] Handoff ready at <platform>/<client>/handoff.md. Recommended specialist: /<skill>`
