#!/usr/bin/env bash
# docker-gating.sh - PreToolUse hook that gates Portainer Docker proxy calls
#
# Intercepts mcp__portainer__dockerProxy tool calls and applies
# allowlist logic based on HTTP method and Docker API path.
#
# Decisions:
#   allow  - GET requests (read-only) + user-allowlisted operations
#   (none) - Everything else falls through to Claude Code's permission prompt
#
# Allowlist sources:
#   1. Built-in: all GET requests (read-only by definition)
#   2. ~/.claude/docker-allowed-operations.txt (user-added, "METHOD /path" per line)
#
# When a non-GET operation is NOT auto-allowed, writes it to a
# session-scoped suggestion file for docker-allowlist-notify.sh to pick up.

set -uo pipefail

# Require jq
command -v jq &>/dev/null || exit 0

DOCKER_ALLOWED_FILE="$HOME/.claude/docker-allowed-operations.txt"
DOCKER_DISMISSED_FILE="$HOME/.claude/docker-dismissed.txt"

# Read tool input from stdin
input=$(cat)

# Only act on mcp__portainer__dockerProxy calls
tool_name=$(echo "$input" | jq -r '.tool_name // empty')
[[ "$tool_name" != "mcp__portainer__dockerProxy" ]] && exit 0

session_id=$(echo "$input" | jq -r '.session_id // empty')

# Extract method and path from tool input
method=$(echo "$input" | jq -r '.tool_input.method // empty')
api_path=$(echo "$input" | jq -r '.tool_input.dockerAPIPath // empty')

[[ -z "$method" || -z "$api_path" ]] && exit 0

# Normalize method to uppercase
method="${method^^}"

# Build operation string: "METHOD /path"
operation="${method} ${api_path}"

# --- Rules ---

allow() {
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
}

# Load user-added allowed operations from file
USER_ALLOWED=()
if [[ -f "$DOCKER_ALLOWED_FILE" ]]; then
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    USER_ALLOWED+=("$line")
  done < "$DOCKER_ALLOWED_FILE"
fi

queue_suggestion() {
  [[ -z "$session_id" ]] && return
  local suggestion_file="$HOME/.claude/docker-suggestions-${session_id}.log"
  local snoozed_file="$HOME/.claude/docker-snoozed-${session_id}.txt"

  # Skip if already dismissed or snoozed
  if [[ -f "$DOCKER_DISMISSED_FILE" ]] && grep -qxF "$1" "$DOCKER_DISMISSED_FILE" 2>/dev/null; then
    return
  fi
  if [[ -f "$snoozed_file" ]] && grep -qxF "$1" "$snoozed_file" 2>/dev/null; then
    return
  fi
  # Skip if already in user allowlist
  for u in "${USER_ALLOWED[@]}"; do
    [[ "$1" == "$u" ]] && return
  done

  echo "$1" >> "$suggestion_file"
  touch "${suggestion_file}.skip"
}

# All GET requests are read-only — auto-allow
[[ "$method" == "GET" ]] && allow

# Built-in safe POST operations (prefix matching)
# These are common operational commands, not destructive
SAFE_POST_PREFIXES=(
  "POST /exec"                  # docker exec (run commands in containers)
  "POST /containers/create"     # create containers
  "POST /images/create"         # pull images
)

# Container lifecycle operations — match any container ID in the path
# e.g., POST /containers/flare-bypasser/start
SAFE_CONTAINER_ACTIONS=(start stop restart)
for prefix in "${SAFE_POST_PREFIXES[@]}"; do
  [[ "$operation" == "$prefix" || "$operation" == "$prefix"/* || "$operation" == "$prefix "* ]] && allow
done

# Match POST /containers/{any-id}/{action}
if [[ "$method" == "POST" && "$api_path" =~ ^/containers/[^/]+/([^/]+)$ ]]; then
  action="${BASH_REMATCH[1]}"
  for safe in "${SAFE_CONTAINER_ACTIONS[@]}"; do
    [[ "$action" == "$safe" ]] && allow
  done
fi

# Check user-added allowed operations (prefix matching)
# "POST /images/create" matches only that exact path
# "POST /containers" matches any POST to /containers/*
for u in "${USER_ALLOWED[@]}"; do
  [[ "$operation" == "$u" || "$operation" == "$u"/* || "$operation" == "$u "* ]] && allow
done

# Not allowed — queue suggestion, fall through to prompt
queue_suggestion "$operation"
exit 0
