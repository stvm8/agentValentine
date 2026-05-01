#!/bin/bash
# POST-TOOLUSE BASH STRIKE CHECK HOOK
#
# Fires after every Bash tool call.
# If the command failed (non-zero exit), reminds the agent
# to update strikes.md per the Anti-Rabbit-Hole Protocol.
#
# PostToolUse hooks must NOT return {"decision":"allow"} — that's PreToolUse only.
# Return {} for no message, or {"reason":"..."} to inject a message.

set +e

# Consume stdin JSON payload
TOOL_INPUT=$(cat)

# Check for non-empty stderr (indicates command failure)
STDERR=""
if command -v jq &>/dev/null; then
  STDERR=$(printf '%s' "$TOOL_INPUT" | jq -r '.tool_response.stderr // empty' 2>/dev/null || true)
fi

if [ -n "$STDERR" ]; then
  echo '{"reason":"[STRIKE CHECK] Command exited non-zero. If this was an exploitation attempt on a logical vector, you MUST update strikes.md immediately: echo ## Vector: <logical_vector_name> - Strike N/3: [date] <what was tried> -> <why it failed> >> strikes.md. Read strikes.md before your next proposal to check counts."}'
else
  echo '{}'
fi

exit 0
