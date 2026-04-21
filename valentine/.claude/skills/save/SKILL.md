---
description: Save current engagement state, organize all files, and create progress tracking with done/next/failed.
disable-model-invocation: true
---
I am executing the `/save` command.

**HARD OVERRIDE:** Immediately halt all activities and perform a state save.

## 1. Detect Engagement
Read `scope.md` in the current directory to identify engagement type, client, and platform.

## 2. Organize State Files
Verify and update ALL applicable files. If a file has stale or incomplete data, fill it in from your current context.

### Common (all types):
- `creds.md` — ALL collected credentials, hashes, tokens, API keys with source context
- `vulnerabilities.md` — ALL confirmed findings with severity, reproduction steps, evidence
- `strikes.md` — ALL failed vectors logged with strike counts
- `scans.md` — raw tool outputs saved and filtered

### Domain-specific:
- webapp/api: `recon.md`, `endpoints.md`, `api_schema.md`
- network: `ad_enum.md`, `network_topology.md`, `attack_vectors.md`
- cloud: `assets.md`, `iam_enum.md`
- ctf: `loot.md`, `network_topology.md`

## 3. Create/Update progress.md

```markdown
# Engagement Progress
**Client:** <client>
**Platform:** <platform>
**Type:** <type>
**Last Saved:** <current date and time>
**Objective:** <from scope.md>

## Completed Actions
- [x] <action> — <result/reference to file>

## In-Progress
- [~] <action> — <current state>

## Failed / Exhausted
- [!] <vector> — Strike <N>/3: <reason for failure>

## Next Actions
1. <next logical step based on current state>
2. <alternative if #1 is blocked>

## Reasoning Log
- **Current Hypothesis:** <what vector or chain you're pursuing and why>
- **Ruled Out:** <vectors tried and why they failed>
- **Open Questions:** <unknowns that need investigation>
```

## 4. Confirm
Output EXACTLY:
`[STATE SAVED] Run '/clear', then resume with: /<specialist_skill> continue: <client>`
