---
description: Call Robin to safely read massive files, organize messy notes, extract global lessons, and suggest vectors.
---
I am calling my co-pilot via the `/robin` skill.
**My Question/Focus (if any):** $ARGUMENTS

**Task:**
1. **SAFE DATA INGESTION (CRITICAL FOR TOKENS):** 
   - Before reading ANY file (`.json`, `.txt`, `.md`, `.log`), you MUST check its size using `wc -l <file>`. 
   - If a file is over 100 lines, DO NOT use `cat`. You MUST use `grep`, `jq`, `awk`, `head`, or `tail` to extract only the relevant anomalies, IP addresses, or errors to protect my token budget.
   - If analyzing images (`.png`/`.jpg`), only do so if the user explicitly requested it.

2. **The Secretary Action (Auto-Organize):** Parse my notes and filtered tool outputs. Extract the valuable data into the correct standardized files:
   - Passwords, hashes, and API keys -> `creds.md`.
   - Captured flags, source code, or sensitive data -> `loot.md`.
   - Endpoints, IPs, or open ports -> `scans.md` or `targets.md`.
   - Subnet discoveries or pivot routes -> `network_topology.md`.
   
3. **Global Brain Update (Extract Learnings):** If my notes/logs show a successfully solved roadblock, a novel bypass, or a specific tool syntax that worked after failing, you MUST extract it as a lesson. 
   - Append it to the Global Brain using this exact format:
     `echo "[Tag1][Tag2] Issue: <What I was stuck on> -> Solution: <How I fixed it>" >> $HOME/Pentester/AI_Teams/agent_learnings.md`

4. **Global Brain Sync (Retrieval):** Briefly `grep` the `$HOME/Pentester/AI_Teams/agent_learnings.md` file for any past bypasses relevant to my *current* active roadblocks.

5. **Actionable Advice:** Output a structured `[💡 STRATEGY REVIEW]` pointing out blind spots. Propose the exact next command, tool, or Caido request I should execute based on your Master Instructions (CLAUDE.md).
