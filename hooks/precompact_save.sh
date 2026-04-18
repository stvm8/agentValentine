#!/bin/bash
# PRECOMPACT AUTO-CHECKPOINT HOOK
#
# Fires before Claude Code compresses the context window.
# Blocks the AI and tells it to checkpoint all state files
# so reasoning context is preserved before compression.
#
# === INSTALL ===
# Add to each agent's .claude/settings.local.json:
#
#   "hooks": {
#     "PreCompact": [{
#       "matcher": "",
#       "hooks": [{
#         "type": "command",
#         "command": "/absolute/path/to/hooks/precompact_save.sh",
#         "timeout": 30
#       }]
#     }]
#   }
#

cat << 'HOOKJSON'
{
  "decision": "block",
  "reason": "EMERGENCY CHECKPOINT — Context is about to be compressed. You MUST immediately: (1) Save all current progress to your state file (hunt_state.md / ctf_state.md / pentest_state.md). (2) Append a Reasoning Log section documenting your current hypothesis, what you've ruled out, and planned next steps. (3) Ensure creds.md, scans.md, and all engagement files are up to date. (4) After saving, output: [!] PRE-COMPACT SAVE COMPLETE. Context may now compress safely."
}
HOOKJSON
