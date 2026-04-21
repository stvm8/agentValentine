---
description: Co-Pilot review — analyze your engagement state, query Playbooks & Learnings, and advise on next moves or gaps.
---
I am calling my Co-Pilot via the `/robin` skill.
**My Question/Focus (if any):** $ARGUMENTS

## 1. Understand Role
You are my Co-Pilot for penetration testing. I am doing the manual hacking. Do NOT execute exploits. Your job is to analyze my state and advise me.

## 2. Detect Engagement Type
Read `scope.md` in the current directory. Extract the `Type:` field to determine the engagement domain (webapp, api, network, cloud, ctf).

## 3. Read My State
Read the `.md` files in my current directory:
- `strikes.md` — **READ FIRST.** Check which vectors are exhausted (3/3). Do NOT suggest exhausted vectors.
- `scope.md` — targets, boundaries, ROE
- `progress.md` — what's done, in-progress, failed, and next
- `handoff.md` — if it exists, original appraisal findings
- `vulnerabilities.md` — confirmed findings
- `creds.md` — collected credentials, tokens, hashes

Domain-specific files:
- webapp/api: `recon.md`, `endpoints.md`, `api_schema.md`, `scans.md`
- network: `scans.md`, `ad_enum.md`, `network_topology.md`, `attack_vectors.md`
- cloud: `assets.md`, `iam_enum.md`
- ctf: `loot.md`, `network_topology.md`, `scans.md`

## 4. Decision Flow Consultation
1. Based on state files, identify your **current starting point** (e.g., "No Credentials", "Authenticated User", "Local Admin", "SSRF Confirmed", "IAM User", "Domain User").
2. Read the relevant `_FLOW.md`:
   - webapp/api: `cat {PLAYBOOKS}/Web/_FLOW.md`
   - network: `cat {PLAYBOOKS}/AD/_FLOW.md` (also check Pivoting/_FLOW.md, Windows/_FLOW.md)
   - cloud: `cat {PLAYBOOKS}/Cloud/_FLOW.md`
   - ctf: Read the _FLOW.md matching the challenge type
3. Find your starting point in the flow. Get the shortlist of applicable techniques with file references.
4. Use this shortlist to focus the INDEX.md grep below.

## 5. Playbook Consultation (Two-Stage Retrieval)
1. Identify key signals from state files.
2. Grep relevant INDEX files based on engagement type:
   - webapp/api: `grep -i "<signal>" {PLAYBOOKS}/Web/INDEX.md`
   - network: `grep -i "<signal>" {PLAYBOOKS}/AD/INDEX.md {PLAYBOOKS}/Windows/INDEX.md {PLAYBOOKS}/Pivoting/INDEX.md {PLAYBOOKS}/C2/INDEX.md`
   - cloud: `grep -i "<signal>" {PLAYBOOKS}/Cloud/INDEX.md`
   - ctf: `grep -i "<signal>" {PLAYBOOKS}/*/INDEX.md`
3. For each INDEX match: check **Prereq** against current state. Only pursue if prerequisites are met.
4. For viable matches: read ONLY the matched technique entry from the full Playbook file.
5. Cross-reference against `strikes.md` and `progress.md`.
6. `grep -i "#mistake\|#hallucination" {LEARNINGS}/<domain>.md` to avoid known-bad techniques.

## 6. Domain-Specific Gap Analysis

### If webapp/api:
- OWASP coverage gaps (Web A01-A10 for webapp, API API1-API10 for api)
- Untested endpoints from `endpoints.md` or `api_schema.md`
- Auth boundary testing (horizontal/vertical privesc, BOLA, function-level access)
- Input vectors not yet fuzzed (SQLi, SSTI, XSS, command injection)
- Chain opportunities (info disclosure -> key -> BOLA -> ATO)
- 2nd-order targets (PDF generators, email templates, webhooks, async processors)
- API version gaps (`/v1/`, `/beta/`, `/internal/`)
- JWT/session flaws (algorithm confusion, missing expiry, insecure cookies)

### If network:
- AD attack paths (Kerberoastable SPNs, AS-REP, unconstrained delegation, DACL abuse)
- Relay opportunities (SMB signing, NTLM relay targets, LDAP signing)
- Credential leverage (unhacked hashes, unused tickets)
- Trust abuse (cross-domain/forest, SID history, foreign groups)
- Lateral movement (admin shares, WMI, PSRemoting, RDP)
- Routing gaps (unreachable subnets, missing tunnels)
- Legacy/vulnerable services (MS17-010, PrintNightmare, ZeroLogon)

### If cloud:
- IAM escalation paths (policy abuse, role chaining, cross-account trusts)
- Metadata abuse (IMDS, env vars, Lambda context)
- Storage misconfigs (public buckets, blobs, snapshots)
- Credential leverage (keys/tokens not tested against other services)
- Service-to-service pivots (Lambda->RDS, EC2->S3)
- SCP/permission boundaries to plan around

### If ctf:
- Unexplored services and ports
- Privesc vectors (SUID, sudo, cron, capabilities, kernel)
- Credential reuse across services
- Pivot opportunities to internal hosts
- File system loot (configs, backups, .git, history)
- Routing gaps (tunnels, SOCKS proxies)

## 7. Strategy Output
Output a `[ROBIN REVIEW]` containing:

### Situation Summary
2-3 sentences on current progress and key findings.

### Coverage Status
Brief checklist of what's tested vs. remaining (OWASP categories for web/api, kill chain phases for network/cloud/ctf).

### Recommended Next Moves
| Priority | Action | Rationale | Chain Potential | Risk |
|----------|--------|-----------|-----------------|------|
| 1        | ...    | ...       | ...             | ...  |

Sort by: severity potential (highest first), then effort (easiest first).

### Decision Points
Flag choices that need my input (e.g., "deep-dive SQLi vs. test BOLA first", "relay DC vs. Kerberoast SPNs").