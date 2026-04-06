---
description: Spawn a Recon-Only Subagent for massive scopes (e.g., /enum client: Acme project: Internal scope: 10.0.0.0/16)
tags: [#netPen]
---
I am executing the `/enum` command.
**Arguments:** $ARGUMENTS

Evaluate the arguments and execute the following sequence:

1. **Workspace:** Run `mkdir -p <client>/<project> && cd <client>/<project>`.
2. **Scope Validation:** Create `scope.md` with the parameters. Create placeholder files: `scans.md`, `ad_enum.md`, `network_topology.md`, and `attack_vectors.md`.
3. **Subagent Delegation:** Output your first `[⚡ PROPOSAL]`. In this proposal, state that you will spawn a Recon-Only Subagent to exhaustively map the `<scope>`. 
4. **Instructions to Subagent:** Explicitly command the subagent to follow the `<recon_subagent_protocol>`: it must use safe scan speeds, it is forbidden from exploiting, and it must log all discovered vulnerabilities to `attack_vectors.md`.
