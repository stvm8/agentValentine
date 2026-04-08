---
description: Hand off a target from one agent to another with full intel transfer. (e.g., /handoff from: netPen, to: webApiPen, target: 10.0.1.50:8080)
disable-model-invocation: true
---
I am executing the `/handoff` command.
**Arguments:** $ARGUMENTS

Parse the arguments for: `from:` (source agent), `to:` (target agent), `target:` (target description), `engagement:` (optional - engagement name).

## 1. Gather Intel from Source
Read the source agent's engagement files to compile transferable intelligence:
- `scope.md` — boundaries and ROE
- `creds.md` — any credentials relevant to the handoff target
- `scans.md` / `recon.md` — reconnaissance data on the target
- `network_topology.md` — routing context if applicable
- `vulnerabilities.md` / `attack_vectors.md` — known findings related to the target

## 2. Create Handoff Package
Create a `handoff.md` file in the target agent's engagement directory with:

```markdown
# Handoff: <source_agent> -> <target_agent>
**Date:** <current date>
**Target:** <target description>
**Reason:** <why this target needs a different specialist>

## Collected Intel
### Credentials
<relevant creds from source>

### Reconnaissance
<relevant scan data, endpoints, tech stack>

### Network Context
<routing info, proxy chains, tunnel configs needed to reach target>

### Known Findings
<vulnerabilities or attack vectors already identified on this target>

### Recommendations
<what the source agent suggests the target agent investigate first>
```

## 3. Output
Output a `[🤝 HANDOFF READY]` block containing:
- Summary of what was transferred
- File path of `handoff.md`
- Suggested command to start work in the target agent (e.g., `/work continue: <project>`)

## Rules
- NEVER fabricate intel — only transfer what exists in actual files
- If source files don't exist, note what's missing in the handoff
- The target agent reads `handoff.md` during its resume/init to bootstrap context
