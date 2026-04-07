---
description: Start or resume a Cloud Pentest
disable-model-invocation: true
---
I am executing the `/work` command.
**Arguments:** $ARGUMENTS

Evaluate the arguments and execute the corresponding sequence below:

## Syntax 1: New Cloud Pentest
If arguments contain client/project/scope:
1. **Workspace:** Run `mkdir -p <client>/<project> && cd <client>/<project>`.
2. **Scope Validation:** Create `scope.md` with IAM boundaries. Create placeholders: `assets.md`, `iam_enum.md`, `creds.md`, `vulnerabilities.md`.
3. **Global Brain Sync:** Identify cloud provider. Run `grep -i "<provider>\|IAM\|Cloud" $HOME/Pentester/AI_Teams/agent_learnings.md`.
4. **Execution:** Output the first `[⚡ PROPOSAL]` for authenticated cloud enumeration.

## Syntax 2: Resume Cloud Pentest
If arguments contain 'continue:':
1. **Locate & Navigate:** Find the `<project>` directory and `cd` into it.
2. **State Restoration:** Read `pentest_state.md`, `assets.md`, and `iam_enum.md`.
3. **Global Brain Sync:** Dynamically `grep` the learnings file for SCP bypasses.
4. **Resume:** Output a `[⚡ PROPOSAL]` to continue privilege escalation.
