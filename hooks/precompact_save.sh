#!/bin/bash
# PreCompact state checkpoint hook
# Snapshots engagement files to disk before context compression.
# Returns additionalContext to guide the compaction summary.

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SNAP_DIR=".snapshots/$TIMESTAMP"
mkdir -p "$SNAP_DIR"

KEY_FILES=(
    scope.md creds.md vulnerabilities.md strikes.md scans.md progress.md
    recon.md endpoints.md handoff.md loot.md attack_vectors.md
    ad_enum.md network_topology.md api_schema.md assets.md iam_enum.md
)

saved=()
for f in "${KEY_FILES[@]}"; do
    src=$(find . -maxdepth 5 -name "$f" -not -path "./.snapshots/*" 2>/dev/null | head -1)
    if [[ -n "$src" ]]; then
        cp "$src" "$SNAP_DIR/"
        saved+=("$f")
    fi
done

files_list=$(IFS=', '; echo "${saved[*]}")
[[ -z "$files_list" ]] && files_list="none"

printf '{"hookSpecificOutput":{"hookEventName":"PreCompact","additionalContext":"[CHECKPOINT %s] Engagement files snapshotted to %s — saved: %s. When writing the compaction summary, preserve: active vector + strike counts, all credentials found, live sessions or tokens, and the next planned action."}}\n' \
    "$TIMESTAMP" "$SNAP_DIR" "$files_list"
