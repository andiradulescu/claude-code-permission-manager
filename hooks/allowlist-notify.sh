#!/usr/bin/env bash
# allowlist-notify.sh - PostToolUse hook that suggests adding tools to global allowlist
#
# After any tool runs, checks if a session-specific suggestions file exists.
# If it does, outputs additionalContext so Claude knows to ask about it.
# Files are per-session to avoid cross-session interference.

set -uo pipefail

SUGGESTIONS_DIR="$HOME/.claude"

# Read hook input to get session ID
input=$(cat)
session_id=$(echo "$input" | jq -r '.session_id // empty' 2>/dev/null)
[[ -z "$session_id" ]] && exit 0

SUGGESTIONS_FILE="${SUGGESTIONS_DIR}/allowlist-suggestions-${session_id}.log"

# Only act if suggestions file exists and has content
[[ ! -f "$SUGGESTIONS_FILE" ]] && exit 0
[[ ! -s "$SUGGESTIONS_FILE" ]] && exit 0

# Skip marker: the suggest hook creates this so we skip the PostToolUse
# for the same tool that was just permission-approved (additionalContext
# doesn't propagate on that cycle). Remove marker and wait for next tool.
SKIP_FILE="${SUGGESTIONS_FILE}.skip"
if [[ -f "$SKIP_FILE" ]]; then
  rm -f "$SKIP_FILE"
  exit 0
fi

# Read suggestions (dedupe since suggest hook appends)
suggestions=$(sort -u "$SUGGESTIONS_FILE")

perms=()
while IFS= read -r perm; do
  [[ -z "$perm" ]] && continue
  perms+=("$perm")
done <<< "$suggestions"

[[ ${#perms[@]} -eq 0 ]] && { rm -f "$SUGGESTIONS_FILE"; exit 0; }

# Output JSON with additionalContext for Claude
# Each tool gets its own AskUserQuestion question with 3 options
message="These tools were just manually approved but aren't in the global allowlist. Use AskUserQuestion with one question PER tool (do NOT merge them). Each question should have header set to the short tool name, and these 3 options: 1) 'Always allow' — add this entry to permissions.allow in ~/.claude/settings.local.json, 2) 'Not now' — append this entry on its own line to ~/.claude/allowlist-snoozed-${session_id}.txt (session-scoped snooze, won't ask again this session), 3) 'Never ask again' — append this entry on its own line to ~/.claude/allowlist-dismissed.txt. Tools: ${perms[*]}. Do NOT ask in plain text — always use the AskUserQuestion tool."

jq -n --arg msg "$message" '{
  hookSpecificOutput: {
    hookEventName: "PostToolUse",
    additionalContext: $msg
  }
}'

# Clean up the suggestions file so it doesn't fire again
rm -f "$SUGGESTIONS_FILE"

exit 0
