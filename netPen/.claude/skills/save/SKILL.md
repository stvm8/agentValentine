---
description: Force the agent to save its current state so you can /clear
disable-model-invocation: true
---
I am executing the `/save` command. 

**HARD OVERRIDE:** You must immediately halt all pentest activities and perform a Phase Reset.
1. Consolidate all current progress, lateral movement plans, and situational awareness into `pentest_state.md`.
2. Append a `## Reasoning Log` section to `pentest_state.md` documenting:
   - **Current hypothesis:** What attack path or lateral movement you're pursuing and why
   - **Ruled out:** Vectors tried and why they failed (with brief evidence)
   - **Next steps:** What you would do next if the session continued
3. Ensure `network_topology.md`, `ad_enum.md`, `creds.md`, and `strikes.md` are completely up to date.
4. Output EXACTLY this message and nothing else:
`[!] STATE SAVED. Run '/clear', then resume with: /work continue: <Project>`
