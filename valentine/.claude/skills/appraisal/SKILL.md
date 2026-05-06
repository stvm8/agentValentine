---
description: Start a new engagement — thorough recon, enumeration, and attack vector analysis. Produces handoff for specialist skills. (e.g., /appraisal type: network, platform: InternalAD, client: Acme, scope: 10.0.0.0/16, oos: 10.0.0.1, objective: Domain Admin)
disable-model-invocation: true
---
I am executing the `/appraisal` command.
**Arguments:** $ARGUMENTS

Parse the arguments for: `type:` (webapp|api|network|cloud|ctf|blended), `platform:`, `client:`, `scope:`, `oos:`, `objective:`.

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
   - blended: `recon.md`, `endpoints.md`, `api_schema.md`, `ad_enum.md`, `network_topology.md`, `attack_vectors.md`

## 2. Global Brain Sync
Based on `type:`, identify 2-3 core technologies from scope:
- webapp: REST, GraphQL, JWT, framework names
- api: REST, gRPC, GraphQL, authentication methods
- network: ActiveDirectory, SMB, Kerberos, SNMP
- cloud: AWS/Azure/GCP, IAM, S3/Blob, Lambda
- ctf: Cross-domain — identify from scope description
- blended: webapp tech (REST, GraphQL, JWT, framework names) + network tech (ActiveDirectory, SMB, Kerberos) — grep both `{LEARNINGS}/web.md` and `{LEARNINGS}/network.md`

Execute: `python3 {AGENT_ROOT}/lq.py "<tech1> <tech2>"` to retrieve past lessons across all domains (BM25-ranked, OR between terms).

## 3. Playbook Sync
Based on `type:`, grep relevant INDEX files:
- webapp/api: `grep -i "<signal>" {PLAYBOOKS}/Web/INDEX.md`
- network: `grep -i "<signal>" {PLAYBOOKS}/AD/INDEX.md {PLAYBOOKS}/Windows/INDEX.md {PLAYBOOKS}/Pivoting/INDEX.md {PLAYBOOKS}/C2/INDEX.md`
- cloud: `grep -i "<signal>" {PLAYBOOKS}/Cloud/INDEX.md`
- ctf: `grep -i "<signal>" {PLAYBOOKS}/*/INDEX.md`
- blended: `grep -i "<signal>" {PLAYBOOKS}/Web/INDEX.md {PLAYBOOKS}/AD/INDEX.md {PLAYBOOKS}/Windows/INDEX.md {PLAYBOOKS}/Pivoting/INDEX.md {PLAYBOOKS}/C2/INDEX.md {PLAYBOOKS}/Linux/INDEX.md`

## 4. Recon Plan — Propose Phases 1–3 (Do NOT Execute Yet)
Output a `[APPRAISAL PLAN]` describing what will happen in each of the three recon phases:

### Phase 1: Passive Reconnaissance
Based on type:
- **webapp/api:** Passive URL discovery (`gau`, `waymore`), tech fingerprinting (`httpx`, `whatweb`), JS analysis (`katana --js-crawl`), API schema discovery (Swagger, OpenAPI, GraphQL introspection, Postman collections).
- **network:** DNS enumeration, OSINT, certificate transparency, WHOIS, subdomain enumeration.
- **cloud:** Public cloud asset discovery, DNS, open storage enumeration, certificate transparency.
- **ctf:** Full port scan, banner grab, web stack identification.
- **blended:** Run both webapp passive (gau, waymore, httpx, whatweb, katana --js-crawl, API schema discovery) AND network passive (DNS enum, OSINT, cert transparency, WHOIS, subdomain enum). Note where webapp and network attack surface intersect (e.g., app server exposed on internal subnet).

### Phase 2: Active Enumeration
Based on type:
- **webapp/api:** Active crawl (`katana`), directory fuzzing (`ffuf`), parameter discovery (`arjun`), auth boundary mapping.
- **network:** Full TCP + top 100 UDP port scan, service version detection, protocol-specific enumeration (SMB, SNMP, LDAP, HTTP).
- **cloud:** Authenticated IAM enumeration, resource inventory, trust mapping.
- **ctf:** Service-specific enumeration, default credential checks.
- **blended:** Run both webapp active (katana, ffuf, arjun, auth boundary mapping) AND full TCP/UDP port scan with protocol-specific enumeration (SMB, SNMP, LDAP, HTTP). Map which network services are reachable from the webapp.

### Phase 3: Deep Enumeration
Based on type:
- **webapp/api:** `nuclei` scanning (no DoS), `dalfox` on reflected params, `sqlmap` (safe flags), authentication mechanism analysis, JWT analysis.
- **network:** BloodHound ingest, Kerberoasting/AS-REP roast candidate identification, SMB signing check, GPO analysis, trust enumeration.
- **cloud:** IAM policy analysis, privilege escalation path mapping, cross-account trust analysis, metadata endpoint probing.
- **ctf:** Custom service analysis, binary examination, config file hunting, SUID/sudo enumeration.
- **blended:** Run both webapp deep (nuclei, dalfox, sqlmap, JWT/auth analysis) AND network deep (BloodHound ingest, Kerberoasting candidates, SMB signing check). SSRF probing must explicitly test RFC1918 ranges identified in the network scan.

`[HALTING. AWAITING USER APPROVAL.]`

## 5. Phase Execution
After user approves each phase, execute it in order (Phase 1 → 2 → 3):
- Execute the phase.
- Update `scans.md` with filtered results (pipe raw output to disk, grep for actionable data).
- Update `progress.md` with completed actions.
- After each phase, output a brief summary (counts and key findings only) and propose the next phase.

**After Phase 3 completes — Phase 4: Attack Vector Analysis.**
Using findings from Phases 1–3, build the attack vector table from actual discovered data:

| # | Target | Vector | Complexity | Confidence | Prereqs Met? | Playbook Ref |
|---|--------|--------|------------|------------|--------------|--------------|

Sort by: confidence (highest first), then complexity (easiest first).

**HARD STOP: Do NOT propose execution of any vector. Do NOT await user approval. Proceed immediately to Section 6.**

## 6. Handoff Generation
Immediately after outputting the Phase 4 attack vector table, write `handoff.md` unconditionally — do not wait for user input:

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
   - For blended engagements: start with the highest-confidence vector regardless of domain. Run `/webapp` or `/network` (whichever the top vector belongs to) first; the other specialist picks up when a pivot is triggered.
```

Output: `[APPRAISAL COMPLETE] Handoff ready at <platform>/<client>/handoff.md. Recommended specialist: /<skill>`
