---
description: Start or resume a Network Pentest
disable-model-invocation: true
tags: [#netPen]
---
I am executing the `/work` command.
**Arguments:** $ARGUMENTS

Evaluate the arguments and execute the corresponding sequence below:

## Syntax 1: New Pentest
If arguments contain client/project/scope:
1. **Workspace:** Run `mkdir -p <client>/<project> && cd <client>/<project>`.
2. **Scope Validation:** Create `scope.md` with ROE. Create placeholders: `scans.md`, `creds.md`, `network_topology.md`, `vulnerabilities.md`.
3. **Global Brain Sync:** Run `grep -i "<core_tech>" $HOME/Pentester/AI_Teams/agent_learnings.md`.
4. **Execution:** Output the first `[⚡ PROPOSAL]` for stealthy reconnaissance.

## Syntax 2: Resume Pentest
If arguments contain 'continue:':
1. **Locate & Navigate:** Find the `<project>` directory and `cd` into it.
2. **State Restoration:** Read `pentest_state.md`, `network_topology.md`, and enum files to rebuild the routing map.
3. **Global Brain Sync:** Dynamically `grep` the learnings file for evasion tactics.
4. **Resume:** Output a `[⚡ PROPOSAL]` to continue lateral movement.
