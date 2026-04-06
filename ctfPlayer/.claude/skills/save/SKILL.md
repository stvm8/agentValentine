---
description: Force the agent to save its current state so you can /clear
disable-model-invocation: true
tags: [#ctfPlayer]
---
I am executing the `/save` command. 

**HARD OVERRIDE:** You must immediately halt all hacking activities and perform a Phase Reset.
1. Consolidate all current progress, pending tasks, and situational awareness into `ctf_state.md`.
2. Ensure `network_topology.md`, `creds.md`, and `scans.md` are completely up to date.
3. Output EXACTLY this message and nothing else:
`[!] STATE SAVED SUCCESSFULLY. It is now safe to run '/clear'. Once cleared, use your resume command to continue.`
