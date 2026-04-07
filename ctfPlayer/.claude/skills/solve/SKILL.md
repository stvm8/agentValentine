---
description: Start or resume a CTF
disable-model-invocation: true
---
I am executing the `/solve` command.
**Arguments:** $ARGUMENTS

Evaluate the arguments and execute the corresponding sequence below:

## Syntax 1: New CTF
If arguments contain platform/name/given:
1. **Workspace:** Run `mkdir -p <platform>/<name> && cd <platform>/<name>`.
2. **Scope Validation:** Create `scope.md` with the parameters. Create placeholder files: `creds.md`, `loot.md`, `scans.md`, and `network_topology.md`.
3. **Global Brain Sync:** Identify core technologies from `<given>`. Run `grep -i "<tech1>\|<tech2>" $HOME/Pentester/AI_Teams/agent_learnings.md` to retrieve past lessons.
4. **Execution:** Output the first `[⚡ PROPOSAL]` for initial reconnaissance.

## Syntax 2: Resume CTF
If arguments contain 'continue:':
1. **Locate & Navigate:** Find the `<name>` directory in the current workspace and `cd` into it.
2. **State Restoration:** Read `ctf_state.md`, `network_topology.md`, `scope.md`, and `scans.md` to reconstruct spatial awareness.
3. **Global Brain Sync:** Dynamically `grep` the learnings file based on the restored state.
4. **Resume:** Output a `[⚡ PROPOSAL]` for the exact next logical step.
