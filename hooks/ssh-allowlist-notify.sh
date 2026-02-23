#!/usr/bin/env bash
# ssh-allowlist-notify.sh - PostToolUse hook for SSH allowlist suggestions
#
# After any tool runs, checks if ssh-gating.sh queued suggestions for
# remote commands that weren't auto-allowed. If so, outputs additionalContext
# telling Claude to ask the user about adding them to the SSH allowlist.
#
# Handles two types of suggestions:
#   Regular: Commands that fell through to permission prompt (option 1)
#     → Ask: Always allow / Not now / Never ask again
#   Swept:  Commands auto-allowed by the sweeper (option 2 cleanup)
#     → Ask: Keep global / Restrict to project / Remove
#
# Files:
#   ~/.claude/ssh-allowed-commands.txt       - persistent global allowlist
#   <git-root>/.claude/ssh-allowed-commands.txt - project-level allowlist
#   ~/.claude/ssh-snoozed-{session}.txt      - session-scoped snooze
#   ~/.claude/ssh-dismissed.txt              - permanently dismissed
#   ~/.claude/ssh-suggestions-{session}.log  - regular suggestions
#   ~/.claude/ssh-swept-{session}.log        - swept suggestions (scope choice)

set -uo pipefail

SUGGESTIONS_DIR="$HOME/.claude"

input=$(cat)
session_id=$(echo "$input" | jq -r '.session_id // empty' 2>/dev/null)
[[ -z "$session_id" ]] && exit 0

SUGGESTIONS_FILE="${SUGGESTIONS_DIR}/ssh-suggestions-${session_id}.log"
SWEPT_FILE="${SUGGESTIONS_DIR}/ssh-swept-${session_id}.log"

# --- Regular suggestions (from gating fallthrough) ---
regular_cmds=()
if [[ -f "$SUGGESTIONS_FILE" && -s "$SUGGESTIONS_FILE" ]]; then
  SKIP_FILE="${SUGGESTIONS_FILE}.skip"
  if [[ -f "$SKIP_FILE" ]]; then
    rm -f "$SKIP_FILE"
  else
    suggestions=$(sort -u "$SUGGESTIONS_FILE")
    while IFS= read -r cmd; do
      [[ -z "$cmd" ]] && continue
      regular_cmds+=("$cmd")
    done <<< "$suggestions"
    rm -f "$SUGGESTIONS_FILE"
  fi
fi

# --- Swept suggestions (from option-2 sweeper) ---
swept_cmds=()
if [[ -f "$SWEPT_FILE" && -s "$SWEPT_FILE" ]]; then
  SWEPT_SKIP="${SWEPT_FILE}.skip"
  if [[ -f "$SWEPT_SKIP" ]]; then
    rm -f "$SWEPT_SKIP"
  else
    swept=$(sort -u "$SWEPT_FILE")
    while IFS= read -r cmd; do
      [[ -z "$cmd" ]] && continue
      swept_cmds+=("$cmd")
    done <<< "$swept"
    rm -f "$SWEPT_FILE"
  fi
fi

# Nothing to report
[[ ${#regular_cmds[@]} -eq 0 && ${#swept_cmds[@]} -eq 0 ]] && exit 0

# Detect git root for project-level scope option
git_root=$(git rev-parse --show-toplevel 2>/dev/null || true)

# Build message
message=""

if [[ ${#regular_cmds[@]} -gt 0 ]]; then
  cmd_list="${regular_cmds[*]}"
  message+="SSH commands were just manually approved but aren't in the SSH auto-allow list. Use AskUserQuestion with one question PER command (do NOT merge them). Each question should have header set to the command name (max 12 chars), and these 3 options: 1) 'Always allow' — append this command on its own line to ~/.claude/ssh-allowed-commands.txt, 2) 'Not now' — append this command on its own line to ~/.claude/ssh-snoozed-${session_id}.txt (session-scoped snooze, won't ask again this session), 3) 'Never ask again' — append this command on its own line to ~/.claude/ssh-dismissed.txt. SSH commands: ${cmd_list}. Do NOT ask in plain text — always use the AskUserQuestion tool."
fi

if [[ ${#swept_cmds[@]} -gt 0 ]]; then
  swept_list="${swept_cmds[*]}"
  [[ -n "$message" ]] && message+=" ADDITIONALLY: "
  if [[ -n "$git_root" ]]; then
    message+="SSH commands were auto-allowed globally by the settings sweeper (user picked 'don't ask again'). Use AskUserQuestion with one question PER command (do NOT merge them). Each question should have header set to the command name (max 12 chars), and these 3 options: 1) 'Keep global' — do nothing (already in ~/.claude/ssh-allowed-commands.txt), 2) 'Project only' — remove this command from ~/.claude/ssh-allowed-commands.txt and append it to ${git_root}/.claude/ssh-allowed-commands.txt instead (create the file if it doesn't exist), 3) 'Remove' — remove this command from ~/.claude/ssh-allowed-commands.txt (revokes the auto-allow, you'll be prompted next time). Swept SSH commands: ${swept_list}. Do NOT ask in plain text — always use the AskUserQuestion tool."
  else
    message+="SSH commands were auto-allowed globally by the settings sweeper (user picked 'don't ask again'). The commands are now in ~/.claude/ssh-allowed-commands.txt. No project context detected, so project-level scoping is not available. Swept SSH commands: ${swept_list}. No action needed."
  fi
fi

jq -n --arg msg "$message" '{
  hookSpecificOutput: {
    hookEventName: "PostToolUse",
    additionalContext: $msg
  }
}'

exit 0
