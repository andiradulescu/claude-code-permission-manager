#!/usr/bin/env bash
# docker-allowlist-notify.sh - PostToolUse hook for Docker allowlist suggestions
#
# After any tool runs, checks if docker-gating.sh queued suggestions for
# Portainer Docker operations that weren't auto-allowed. If so, outputs
# additionalContext telling Claude to ask the user about adding them.
#
# Files:
#   ~/.claude/docker-allowed-operations.txt   - persistent allowlist ("METHOD /path" per line)
#   ~/.claude/docker-snoozed-{session}.txt    - session-scoped snooze
#   ~/.claude/docker-dismissed.txt            - permanently dismissed
#   ~/.claude/docker-suggestions-{session}.log - queued suggestions from docker-gating.sh

set -uo pipefail

SUGGESTIONS_DIR="$HOME/.claude"

# Read hook input to get session ID
input=$(cat)
session_id=$(echo "$input" | jq -r '.session_id // empty' 2>/dev/null)
[[ -z "$session_id" ]] && exit 0

SUGGESTIONS_FILE="${SUGGESTIONS_DIR}/docker-suggestions-${session_id}.log"

# Only act if suggestions file exists and has content
[[ ! -f "$SUGGESTIONS_FILE" ]] && exit 0
[[ ! -s "$SUGGESTIONS_FILE" ]] && exit 0

# Skip marker: docker-gating.sh creates this so we skip the PostToolUse
# for the same tool that was just prompted. Remove and wait for next tool.
SKIP_FILE="${SUGGESTIONS_FILE}.skip"
if [[ -f "$SKIP_FILE" ]]; then
  rm -f "$SKIP_FILE"
  exit 0
fi

# Read and dedupe suggestions
suggestions=$(sort -u "$SUGGESTIONS_FILE")

ops=()
while IFS= read -r op; do
  [[ -z "$op" ]] && continue
  ops+=("$op")
done <<< "$suggestions"

[[ ${#ops[@]} -eq 0 ]] && { rm -f "$SUGGESTIONS_FILE"; exit 0; }

# Build the list for Claude
op_list=""
for op in "${ops[@]}"; do
  op_list="${op_list}${op}, "
done
op_list="${op_list%, }"

message="Docker/Portainer operations were just manually approved but aren't in the Docker auto-allow list. Use AskUserQuestion with one question PER operation (do NOT merge them). Each question should have header set to the HTTP method (max 12 chars), and these 3 options: 1) 'Always allow' — append this operation on its own line to ~/.claude/docker-allowed-operations.txt, 2) 'Not now' — append this operation on its own line to ~/.claude/docker-snoozed-${session_id}.txt (session-scoped snooze, won't ask again this session), 3) 'Never ask again' — append this operation on its own line to ~/.claude/docker-dismissed.txt. Docker operations: ${op_list}. Do NOT ask in plain text — always use the AskUserQuestion tool."

jq -n --arg msg "$message" '{
  hookSpecificOutput: {
    hookEventName: "PostToolUse",
    additionalContext: $msg
  }
}'

# Clean up
rm -f "$SUGGESTIONS_FILE"

exit 0
