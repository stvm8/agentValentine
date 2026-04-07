---
description: Force the agent to save its current state so you can /clear
disable-model-invocation: true
---
I am executing the `/save` command. 

**HARD OVERRIDE:** You must immediately halt all pentest activities and perform a Phase Reset.
1. Consolidate all current progress, tested vectors, OWASP coverage status, and situational awareness into `pentest_state.md`.
2. Ensure `endpoints.md`, `vulnerabilities.md`, `creds.md`, and `api_schema.md` are completely up to date.
3. Output EXACTLY this message and nothing else:
`[!] STATE SAVED SUCCESSFULLY. It is now safe to run '/clear'. Once cleared, use your resume command to continue.`
