#!/usr/bin/env bash
# allowlist-suggest.sh - Suggests adding tools to global allowlist when prompted
# PermissionRequest hook for ALL tool types
#
# Uses permission_suggestions from Claude Code's hook input to extract the exact
# permission string, making this work for any tool type (Bash, MCP, Read, Edit,
# Write, WebFetch, Skill, etc.) without special-casing each one.
#
# When any tool triggers a permission prompt, this hook:
# 1. Reads permission_suggestions from the hook input
# 2. Checks if each suggestion is already in the global allowlist
# 3. If not, writes the permission string to ~/.claude/allowlist-suggestions-{session}.log
#
# The AI reads this file (via allowlist-notify.sh PostToolUse hook) and offers
# to add the permissions to the global allowlist.

set -uo pipefail
# NOTE: intentionally no -e — bash 3.2 (macOS default) has a known bug where
# set -e propagates into functions called from && context and command
# substitutions, causing false exits when grep/jq return non-zero.

SUGGESTIONS_DIR="$HOME/.claude"
DISMISSED_FILE="$HOME/.claude/allowlist-dismissed.txt"
GLOBAL_LOCAL="$HOME/.claude/settings.local.json"
GLOBAL_SHARED="$HOME/.claude/settings.json"

# Read hook input
input=$(cat)

# Extract session ID for per-session isolation
session_id=$(echo "$input" | jq -r '.session_id // empty' 2>/dev/null)
[[ -z "$session_id" ]] && exit 0

SUGGESTIONS_FILE="${SUGGESTIONS_DIR}/allowlist-suggestions-${session_id}.log"
SNOOZED_FILE="${SUGGESTIONS_DIR}/allowlist-snoozed-${session_id}.txt"

# Extract permission strings from permission_suggestions
# Format: toolName(ruleContent) if ruleContent exists, otherwise just toolName
perm_strings=$(echo "$input" | jq -r '
  [.permission_suggestions[]?.rules[]? |
    if .ruleContent then
      .toolName + "(" + .ruleContent + ")"
    else
      .toolName
    end
  ] | unique[]' 2>/dev/null)

[[ -z "$perm_strings" ]] && exit 0

# Load global allowlist entries (both settings files)
get_global_permissions() {
  for file in "$GLOBAL_LOCAL" "$GLOBAL_SHARED"; do
    [[ -f "$file" ]] && jq -r '.permissions.allow[]? // empty' "$file" 2>/dev/null
  done
}

global_perms=$(get_global_permissions)

is_globally_allowed() {
  if echo "$global_perms" | grep -qxF "$1" 2>/dev/null; then
    return 0
  else
    return 1
  fi
}

is_dismissed() {
  if [[ -f "$DISMISSED_FILE" ]] && grep -qxF "$1" "$DISMISSED_FILE" 2>/dev/null; then
    return 0
  else
    return 1
  fi
}

is_snoozed() {
  [[ ! -f "$SNOOZED_FILE" ]] && return 1
  # Exact match first
  if grep -qxF "$1" "$SNOOZED_FILE" 2>/dev/null; then
    return 0
  fi
  # For Bash permissions, match on command prefix so snoozing say("foo")
  # also suppresses say("bar"). Extract first word inside Bash(...).
  if [[ "$1" == Bash\(*\) ]]; then
    local content="${1#Bash(}"
    content="${content%)}"
    # Get the command name (first word, before space or colon)
    local cmd="${content%% *}"
    cmd="${cmd%%:*}"
    # Check if any snoozed entry starts with Bash(cmd
    if grep -q "^Bash(${cmd}" "$SNOOZED_FILE" 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

# Filter out shell syntax fragments from chained commands
# Claude Code splits "cmd1 && if cond; then cmd2; fi && cmd3" into separate suggestions
is_shell_fragment() {
  local perm="$1"
  # Only applies to Bash permissions
  [[ "$perm" != Bash\(*\) ]] && return 1
  # Extract the content inside Bash(...)
  local content="${perm#Bash(}"
  content="${content%)}"
  # Remove trailing :* glob if present
  content="${content%:\*}"
  # Shell keywords that aren't real commands
  case "$content" in
    fi|done|esac|";;") return 0 ;;
    then\ *|else\ *|elif\ *|do\ *|if\ *|if\ !\ *) return 0 ;;
  esac
  return 1
}

# Skip SSH commands — handled by ssh-gating.sh / ssh-allowlist-notify.sh
is_ssh_command() {
  [[ "$1" == Bash\(ssh\ *\) ]] && return 0
  return 1
}

# Skip Portainer Docker proxy — handled by docker-gating.sh / docker-allowlist-notify.sh
is_docker_proxy() {
  [[ "$1" == mcp__portainer__dockerProxy* ]] && return 0
  return 1
}

# Skip ADB commands — handled by adb-gating.sh / adb-allowlist-notify.sh
is_adb_command() {
  [[ "$1" == Bash\(adb\ *\) ]] && return 0
  return 1
}

# Check each permission string
wrote_any=false
while IFS= read -r perm; do
  [[ -z "$perm" ]] && continue
  # Skip lines that don't look like valid permission entries
  # (handles multiline bash commands where jq output contains newlines)
  case "$perm" in
    Bash\(*\)|WebFetch\(*\)|WebSearch|Skill\(*\)|mcp__*) ;;
    Read|Write|Edit|Glob|Grep|NotebookEdit) ;;
    *) continue ;;
  esac
  is_shell_fragment "$perm" && continue
  is_ssh_command "$perm" && continue
  is_docker_proxy "$perm" && continue
  is_adb_command "$perm" && continue
  ga=false; di=false; sn=false
  is_globally_allowed "$perm" && ga=true
  is_dismissed "$perm" && di=true
  is_snoozed "$perm" && sn=true
  if ! $ga && ! $di && ! $sn; then
    echo "$perm" >> "$SUGGESTIONS_FILE"
    wrote_any=true
  fi
done <<< "$perm_strings"

# Create skip marker so the notify hook skips the PostToolUse for THIS tool
# (same cycle — additionalContext doesn't propagate on the just-approved tool)
# The NEXT tool's PostToolUse will pick it up.
if $wrote_any; then
  touch "${SUGGESTIONS_FILE}.skip"
fi

exit 0
