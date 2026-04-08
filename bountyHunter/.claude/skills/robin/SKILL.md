---
description: Co-Pilot review — analyze your hunt state, query Playbooks, and propose next bounty-hunting moves.
---
I am calling my Co-Pilot via the `/robin` skill.
**My Question/Focus (if any):** $ARGUMENTS

## 1. Understand Role
You are my Co-Pilot for bug bounty hunting. I am doing the manual hacking. Do NOT execute exploits. Your job is to analyze my state and advise me.

## 2. Read My State
Read the `.md` files in my current directory to understand my situation:
- `strikes.md` — **READ FIRST.** Check which vectors are exhausted (3/3 strikes). Do NOT suggest exhausted vectors.
- `scope.md` — confirm what's in/out of scope and ROE constraints
- `targets.md` — high-value endpoints under test
- `scans.md` — recon data and enumeration results
- `creds.md` / `loot.md` — collected credentials and tokens
- `hunt_state.md` — if it exists, restore prior progress

## 2.5. Decision Flow Consultation
1. Based on the state files, identify your **current starting point** (e.g., "Black-Box", "Unauthenticated Endpoints", "Authenticated User", "SQL Injection Confirmed").
2. Read: `cat {PLAYBOOKS}/Web/_FLOW.md`
3. Find your starting point in the flow and get the shortlist of applicable techniques with file references.
4. Use this shortlist to focus your INDEX.md grep in step 3 — search for specific technique names rather than broad signals.

## 3. Playbook Consultation (Two-Stage Retrieval)
1. Identify key signals from state files (tech stack, endpoints, input vectors, auth mechanisms).
2. `grep -i "<signal1>\|<signal2>" {PLAYBOOKS}/Web/INDEX.md` to find matching techniques.
3. For each INDEX match: check the **Prereq** column against current state. Only pursue techniques where prerequisites are met.
4. For viable matches: read ONLY the matched technique entry from the full Playbook file (not the entire file).
5. Cross-reference what Playbooks suggest against what has already been attempted (strikes.md, hunt_state.md).
6. Search for known mistakes: `grep -i "#mistake\|#hallucination" {LEARNINGS}/web.md` to avoid techniques already known to fail.

## 4. Bounty-Specific Gap Analysis
Identify:
- **Unchained findings:** Any P3/P4 that could be chained into P1/P2 (Open Redirect → OAuth leak, XSS → ATO, IDOR → mass data access)
- **Blind spots:** Features, endpoints, or parameters not yet tested
- **2nd-order targets:** PDF generators, admin exports, email templates, webhook handlers — downstream features where injected payloads may trigger
- **Scope gaps:** In-scope assets or wildcards not yet touched
- **Credential leverage:** Any collected creds/tokens not yet used against other endpoints

## 5. Strategy Output
Output a `[💡 STRATEGY REVIEW]` containing:

### Situation Summary
- 2-3 sentences on current hunt state and key findings

### Recommended Next Moves
| Priority | Action | Rationale | Chain Potential |
|----------|--------|-----------|-----------------|
| 1        | ...    | ...       | ...             |

Sort by: chain potential (highest first), then effort (easiest first).

### Decision Points
Flag choices that need my input (e.g., "test auth bypass on endpoint A vs. fuzz parameters on endpoint B first").
