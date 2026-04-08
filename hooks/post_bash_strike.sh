#!/bin/bash
# POST-TOOLUSE BASH STRIKE CHECK HOOK
#
# Fires after every Bash tool call.
# If the command failed (non-zero exit), reminds the agent
# to update strikes.md per the Anti-Rabbit-Hole Protocol.
#
# === INSTALL ===
# Add to each offensive agent's .claude/settings.local.json:
#
#   "hooks": {
#     "PostToolUse": [{
#       "matcher": "Bash",
#       "hooks": [{
#         "type": "command",
#         "command": "/absolute/path/to/hooks/post_bash_strike.sh",
#         "timeout": 10
#       }]
#     }]
#   }
#

# Only fire on non-zero exit codes
if [ "${TOOL_EXIT_CODE:-0}" = "0" ]; then
  cat << 'HOOKJSON'
{
  "decision": "allow"
}
HOOKJSON
  exit 0
fi

cat << 'HOOKJSON'
{
  "decision": "allow",
  "reason": "[STRIKE CHECK] Command exited non-zero. If this was an exploitation attempt on a logical vector, you MUST update strikes.md immediately: echo '## Vector: <logical_vector_name>\n- Strike N/3: [date] <what was tried> -> <why it failed>' >> strikes.md. Read strikes.md before your next proposal to check counts."
}
HOOKJSON
