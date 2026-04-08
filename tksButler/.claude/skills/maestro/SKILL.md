---
description: Review enumeration data and notes, then propose the next action with full progress tracking. (e.g., /maestro engagement: ClientX, focus: web app)
disable-model-invocation: true
---
I am executing the `/maestro` command.
**Arguments:** $ARGUMENTS

Parse the arguments for: `engagement:` (required), `focus:` (optional - specific area to focus on).

Execute the following sequence:

## 1. State Restoration
1. Navigate to `engagements/<engagement>/`.
2. Read ALL available state files:
   - `scope.md` - confirm what's in/out of scope
   - `progress.md` - understand what's been done, in-progress, and remaining
   - `notes/` - read all note files for raw findings and observations
   - `findings/` - read confirmed findings and attack vectors
   - `loot/` - check collected credentials, tokens, hashes
3. If a `focus:` argument is provided, prioritize that area in the analysis.

## 2. Playbook Consultation
1. Based on the current engagement phase and technologies discovered, search `{PLAYBOOKS}/` for relevant techniques.
2. Cross-reference what playbooks suggest against what has already been attempted (from `progress.md`).
3. Identify playbook steps that have NOT been tried yet.
4. Search the Global Brain across all domains: `grep -ri "<keyword>" {LEARNINGS}/` for relevant past lessons.
5. Search for known mistakes and hallucinations across all domains: `grep -ri "#mistake\|#hallucination" {LEARNINGS}/` to avoid suggesting techniques already known to fail.

## 3. Gap Analysis
Identify:
- **Blind spots:** Areas not yet enumerated or tested
- **Untried techniques:** Playbook steps skipped or not yet attempted
- **Low-hanging fruit:** Easy wins based on current findings
- **Credential opportunities:** Any collected loot not yet leveraged
- **Chained attacks:** Findings that could be combined for higher impact

## 4. Progress Update
Update `progress.md` with current state:
- Mark completed items with status and brief result
- Mark in-progress items with current state
- Add newly identified items as not-started
- Use this format:

```
## Phase: <phase name>
- [x] <completed item> — <brief result/reference>
- [~] <in-progress item> — <current state>
- [ ] <not-started item> — <source: playbook/observation/gap analysis>
```

## 5. Proposal
Output a `[🎯 MAESTRO PROPOSAL]` containing:

### Situation Summary
- 2-3 sentences on current engagement state
- Key findings so far

### Recommended Next Actions
Present as a prioritized list:

| Priority | Action | Rationale | Complexity | Expected Outcome |
|----------|--------|-----------|------------|------------------|
| 1        | ...    | ...       | ...        | ...              |

Sort by: impact (highest first), then complexity (easiest first).

### Decision Points
Flag any choices that need user input (e.g., "noisy scan vs. stealth", "try creds on X or Y first").

## 6. After User Decision
- Once the user picks an action, update `progress.md` to mark it as in-progress.
- If new techniques are discovered during execution, update the relevant playbook in `{PLAYBOOKS}/`.
- After action completes, update `progress.md` with results and re-run the analysis loop if instructed.

## Rules
- NEVER execute actions without user approval - propose only.
- NEVER fabricate findings or assume results.
- Always ground proposals in actual data from engagement files and playbooks.
- Keep proposals concise - cite file paths instead of repeating content.
- Track EVERYTHING in `progress.md` so the next `/maestro` call has full context.
