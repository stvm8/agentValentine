# Define base directory
BASE_DIR="$HOME/Pentester/AI_Teams"

# 1. CTF Player Save Command
mkdir -p "$BASE_DIR/ctfPlayer/.claude/skills/save"
cat << 'EOF' > "$BASE_DIR/ctfPlayer/.claude/skills/save/SKILL.md"
---
description: Force the agent to save its current state so you can /clear
disable-model-invocation: true
---
I am executing the `/save` command. 

**HARD OVERRIDE:** You must immediately halt all hacking activities and perform a Phase Reset.
1. Consolidate all current progress, pending tasks, and situational awareness into `ctf_state.md`.
2. Ensure `network_topology.md`, `creds.md`, and `scans.md` are completely up to date.
3. Output EXACTLY this message and nothing else:
`[!] STATE SAVED SUCCESSFULLY. It is now safe to run '/clear'. Once cleared, use your resume command to continue.`
EOF

# 2. Bug Bounty Save Command
mkdir -p "$BASE_DIR/bountyHunter/.claude/skills/save"
cat << 'EOF' > "$BASE_DIR/bountyHunter/.claude/skills/save/SKILL.md"
---
description: Force the agent to save its current state so you can /clear
disable-model-invocation: true
---
I am executing the `/save` command. 

**HARD OVERRIDE:** You must immediately halt all hunting activities and perform a Phase Reset.
1. Consolidate all current progress, pending endpoints, and situational awareness into `hunt_state.md`.
2. Ensure `targets.md`, `creds.md`, and `scans.md` are completely up to date.
3. Output EXACTLY this message and nothing else:
`[!] STATE SAVED SUCCESSFULLY. It is now safe to run '/clear'. Once cleared, use your resume command to continue.`
EOF

# 3. Network Pentest Save Command
mkdir -p "$BASE_DIR/netPen/.claude/skills/save"
cat << 'EOF' > "$BASE_DIR/netPen/.claude/skills/save/SKILL.md"
---
description: Force the agent to save its current state so you can /clear
disable-model-invocation: true
---
I am executing the `/save` command. 

**HARD OVERRIDE:** You must immediately halt all pentest activities and perform a Phase Reset.
1. Consolidate all current progress, lateral movement plans, and situational awareness into `pentest_state.md`.
2. Ensure `network_topology.md`, `ad_enum.md`, and `creds.md` are completely up to date.
3. Output EXACTLY this message and nothing else:
`[!] STATE SAVED SUCCESSFULLY. It is now safe to run '/clear'. Once cleared, use your resume command to continue.`
EOF

# 4. Cloud Pentest Save Command
mkdir -p "$BASE_DIR/cloudPen/.claude/skills/save"
cat << 'EOF' > "$BASE_DIR/cloudPen/.claude/skills/save/SKILL.md"
---
description: Force the agent to save its current state so you can /clear
disable-model-invocation: true
---
I am executing the `/save` command. 

**HARD OVERRIDE:** You must immediately halt all pentest activities and perform a Phase Reset.
1. Consolidate all current progress, privilege escalation paths, and situational awareness into `pentest_state.md`.
2. Ensure `assets.md`, `iam_enum.md`, and `creds.md` are completely up to date.
3. Output EXACTLY this message and nothing else:
`[!] STATE SAVED SUCCESSFULLY. It is now safe to run '/clear'. Once cleared, use your resume command to continue.`
EOF

echo "[+] The /save Skill has been successfully added to all agents!"
