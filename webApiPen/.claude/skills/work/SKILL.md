---
description: Start or resume a Web/API Pentest (e.g., /work client: Acme, project: WebApp, scope: https://app.acme.com)
disable-model-invocation: true
---
I am executing the `/work` command.
**Arguments:** $ARGUMENTS

Evaluate the arguments and execute the corresponding sequence below:

## Syntax 1: New Web/API Pentest
If arguments contain client/project/scope:
1. **Workspace:** Run `mkdir -p <client>/<project> && cd <client>/<project>`.
2. **Scope Validation:** Create `scope.md` with target URLs, auth boundaries, and out-of-scope items. Create placeholder files: `recon.md`, `endpoints.md`, `api_schema.md`, `vulnerabilities.md`, `creds.md`, `scans.md`, `strikes.md`.
3. **Global Brain Sync:** Identify core technologies from scope (e.g., REST, GraphQL, JWT, specific frameworks). Run `grep -i "<tech1>\|<tech2>" {LEARNINGS}/web.md {LEARNINGS}/general.md` to retrieve past lessons.
4. **Playbook Sync:** `grep -i "<tech1>\|<tech2>" {PLAYBOOKS}/Web/INDEX.md` to retrieve relevant techniques for the target stack.
5. **OWASP Mapping:** Based on scope, identify the most likely OWASP categories (Web A01-A10, API API1-API10) to prioritize.
5. **Execution:** Output the first `[⚡ PROPOSAL]` for passive reconnaissance (tech fingerprinting, URL discovery, schema detection).

## Syntax 2: Resume Web/API Pentest
If arguments contain 'continue:':
1. **Locate & Navigate:** Find the `<project>` directory and `cd` into it.
2. **State Restoration:** Read `pentest_state.md`, `endpoints.md`, `vulnerabilities.md`, and `api_schema.md` to reconstruct testing progress.
3. **Global Brain Sync:** Dynamically `grep -i "<keyword>" {LEARNINGS}/web.md {LEARNINGS}/general.md` based on technologies and vectors from restored state.
4. **Playbook Sync:** `grep -i "<keyword>" {PLAYBOOKS}/Web/INDEX.md` for relevant techniques.
5. **Resume:** Output a `[⚡ PROPOSAL]` for the next untested OWASP category or endpoint.
