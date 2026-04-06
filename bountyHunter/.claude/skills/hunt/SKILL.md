---
description: Start or resume a Bug Bounty
disable-model-invocation: true
tags: [#bountyHunter]
---
I am executing the `/hunt` command.
**Arguments:** $ARGUMENTS

Evaluate the arguments and execute the corresponding sequence below:

## Syntax 1: New Hunt
If arguments contain platform/program/scope:
1. **Workspace:** Run `mkdir -p <platform>/<program> && cd <platform>/<program>`.
2. **Scope Validation:** Create `scope.md` with strict parameters. Create placeholders: `targets.md`, `creds.md`, `loot.md`, `scans.md`.
3. **Global Brain Sync:** Run `grep -i "<tech1>\|<tech2>" $HOME/Pentester/AI_Teams/agent_learnings.md`.
4. **Execution:** Output the first `[⚡ PROPOSAL]` for exhaustive, token-safe reconnaissance.

## Syntax 2: Resume Hunt
If arguments contain 'continue:':
1. **Locate & Navigate:** Find the `<program>` directory and `cd` into it.
2. **State Restoration:** Read `hunt_state.md`, `targets.md`, and `scope.md`. Verify pending endpoints.
3. **Global Brain Sync:** Dynamically `grep` the learnings file based on pending targets.
4. **Resume:** Output a `[⚡ PROPOSAL]` to continue exploitation.
