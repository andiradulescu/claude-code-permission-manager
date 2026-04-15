#!/usr/bin/env bash
# ssh-gating.sh - PreToolUse hook that gates SSH commands
#
# Intercepts Bash tool calls containing SSH commands and applies
# allowlist logic to the REMOTE command being executed.
#
# Decisions:
#   allow  - Commands in the built-in or user allowlist
#   (none) - Everything else falls through to Claude Code's permission prompt
#
# Allowlist sources:
#   1. Built-in ALLOWED array (read-only commands)
#   2. PM2_READ array (read-only PM2 subcommands)
#   3. ~/.claude/ssh-allowed-commands.txt (user-added, one base command per line)
#
# When a command is NOT auto-allowed, writes the base command to a
# session-scoped suggestion file for ssh-allowlist-notify.sh to pick up.

set -euo pipefail

# Require jq
command -v jq &>/dev/null || exit 0

SSH_ALLOWED_FILE="$HOME/.claude/ssh-allowed-commands.txt"
SSH_DISMISSED_FILE="$HOME/.claude/ssh-dismissed.txt"

# Read hook input early so session_id is available for the sweeper
input=$(cat)
session_id=$(echo "$input" | jq -r '.session_id // empty')
command=$(echo "$input" | jq -r '.tool_input.command // empty')

# Detect git root for project-level files
git_root=$(git rev-parse --show-toplevel 2>/dev/null || true)

# --- Sweep: redirect option-2 entries to SSH allowlist ---
# If user picked "don't ask again" on a prompt, Claude Code added
# Bash(ssh ...:*) to settings.local.json. We move it to the SSH
# allowlist and remove it from settings so the hook stays in control.
# Also queues a swept suggestion so the notification hook can ask
# about global vs project scope.
sweep_ssh_from_settings() {
  local settings_file="$1"
  [[ ! -f "$settings_file" ]] && return

  local ssh_entries
  ssh_entries=$(jq -r '.permissions.allow[]? // empty' "$settings_file" 2>/dev/null | grep '^Bash(ssh ' || true)
  [[ -z "$ssh_entries" ]] && return

  local moved_any=false
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    # Bash(ssh root@server "pm2 restart app":*) → pm2 restart app
    # Bash(ssh -t root@server "cmd":*) → cmd
    # Bash(ssh root@server:*) → empty (no remote cmd, just delete)
    local full_cmd="${entry#Bash(}"
    full_cmd="${full_cmd%:\*)}"
    full_cmd="${full_cmd%)}"
    # Strip "ssh " prefix
    local ssh_args="${full_cmd#ssh }"

    # Parse: skip SSH options, find server, rest is remote command
    read -ra _sw <<< "$ssh_args"
    local j=0 rem_start=-1
    while [[ $j -lt ${#_sw[@]} ]]; do
      case "${_sw[$j]}" in
        -[oFilpJLRDWbcemS]) ((j += 2)); continue ;;
        -o*=*|-[FilpJLRDWbcemS]*) ((j++)); continue ;;
        -[1246AaCfGgKkMNnqsTtVvXxYy]*) ((j++)); continue ;;
        *) rem_start=$((j + 1)); break ;;
      esac
    done

    # No remote command = interactive ssh, just delete the entry
    if [[ $rem_start -lt 0 || $rem_start -ge ${#_sw[@]} ]]; then
      moved_any=true
      continue
    fi

    local remote_cmd="${_sw[*]:$rem_start}"
    # Strip wrapping quotes
    if [[ "$remote_cmd" =~ ^\"(.*)\"$ ]]; then
      remote_cmd="${BASH_REMATCH[1]}"
    elif [[ "$remote_cmd" =~ ^\'(.*)\'$ ]]; then
      remote_cmd="${BASH_REMATCH[1]}"
    fi

    if [[ -n "$remote_cmd" ]]; then
      if ! grep -qxF "$remote_cmd" "$SSH_ALLOWED_FILE" 2>/dev/null; then
        echo "$remote_cmd" >> "$SSH_ALLOWED_FILE"
      fi
      if [[ -n "$session_id" ]]; then
        echo "$remote_cmd" >> "$HOME/.claude/ssh-swept-${session_id}.log"
        touch "$HOME/.claude/ssh-swept-${session_id}.log.skip"
      fi
    fi
    moved_any=true
  done <<< "$ssh_entries"

  if $moved_any; then
    jq 'del(.permissions.allow[] | select(startswith("Bash(ssh ")))' "$settings_file" > "${settings_file}.tmp" \
      && mv "${settings_file}.tmp" "$settings_file"
  fi
}

if [[ -n "$git_root" ]]; then
  sweep_ssh_from_settings "$git_root/.claude/settings.local.json"
fi
sweep_ssh_from_settings "$HOME/.claude/settings.local.json"

[[ -z "$command" ]] && exit 0

# --- SSH Detection ---
# Find the first ssh command in the input.
# For piped commands like `ssh server cat file | grep x`, we only gate the ssh portion.
# Complex multi-line scripts with embedded ssh: fall through to permission prompt.

ssh_line=""
while IFS= read -r line; do
  trimmed="${line#"${line%%[![:space:]]*}"}"
  if [[ "$trimmed" =~ ^ssh[[:space:]] ]]; then
    ssh_line="$trimmed"
    break
  fi
done <<< "$command"

[[ -z "$ssh_line" ]] && exit 0

# --- Parse SSH Arguments ---
# Split into words. This doesn't perfectly handle quoted args, but we
# only need the server name and the base command of the remote side.
# Edge cases fall through to the normal permission prompt (safe default).
read -ra words <<< "$ssh_line"

i=1  # skip "ssh"
server=""
remote_start=-1

while [[ $i -lt ${#words[@]} ]]; do
  word="${words[$i]}"
  case "$word" in
    # Options that consume the next argument as a value
    -[oFilpJLRDWbcemS])
      ((i += 2))
      continue
      ;;
    # Combined option=value (e.g., -oStrictHostKeyChecking=no)
    -o*=*|-[FilpJLRDWbcemS]*)
      ((i++))
      continue
      ;;
    # Boolean flags (can be combined: -vvv, -NT, etc.)
    -[1246AaCfGgKkMNnqsTtVvXxYy]*)
      ((i++))
      continue
      ;;
    # First non-option word is the server
    *)
      server="$word"
      remote_start=$((i + 1))
      break
      ;;
  esac
done

# No server found or no remote command = interactive ssh, let it through
[[ -z "$server" ]] && exit 0
[[ $remote_start -ge ${#words[@]} ]] && exit 0

# Build remote command string from remaining words
remote_cmd="${words[*]:$remote_start}"

# Strip wrapping quotes if the entire remote command is quoted
if [[ "$remote_cmd" =~ ^\"(.*)\"$ ]]; then
  remote_cmd="${BASH_REMATCH[1]}"
elif [[ "$remote_cmd" =~ ^\'(.*)\'$ ]]; then
  remote_cmd="${BASH_REMATCH[1]}"
fi

# Strip local shell operators from the end (2>&1, | grep, etc.)
# These aren't part of the remote command
remote_cmd_clean="$remote_cmd"
remote_cmd_clean="${remote_cmd_clean% 2>&1}"
remote_cmd_clean="${remote_cmd_clean% 2>\/dev\/null}"

# --- Rules ---

# Built-in read-only commands: auto-allow
ALLOWED=(
  cd
  cat head tail grep egrep fgrep zcat zgrep
  ls tree wc stat file less find
  ps top htop df du free uptime uname
  hostname whoami id w who last dmesg
  netstat ss ip ifconfig ping dig nslookup host
  curl wget
  systemctl journalctl service
  docker
  git
  env printenv echo date timedatectl
  lsof
)

# PM2 read-only subcommands
PM2_READ=(list ls l status show logs log env describe monit jlist prettylist id pid info)

# Load user-added allowed commands (global)
USER_ALLOWED=()
if [[ -f "$SSH_ALLOWED_FILE" ]]; then
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    USER_ALLOWED+=("$line")
  done < "$SSH_ALLOWED_FILE"
fi

# Load project-level allowed commands
if [[ -n "$git_root" ]]; then
  _proj_ssh_allowed="$git_root/.claude/ssh-allowed-commands.txt"
  if [[ -f "$_proj_ssh_allowed" ]]; then
    while IFS= read -r line; do
      [[ -z "$line" || "$line" == \#* ]] && continue
      USER_ALLOWED+=("$line")
    done < "$_proj_ssh_allowed"
  fi
fi

# --- Decision ---
allow() {
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
}

queue_suggestion() {
  [[ -z "$session_id" ]] && return
  local suggestion_file="$HOME/.claude/ssh-suggestions-${session_id}.log"
  local snoozed_file="$HOME/.claude/ssh-snoozed-${session_id}.txt"

  if [[ -f "$SSH_DISMISSED_FILE" ]] && grep -qxF "$1" "$SSH_DISMISSED_FILE" 2>/dev/null; then
    return
  fi
  if [[ -f "$snoozed_file" ]] && grep -qxF "$1" "$snoozed_file" 2>/dev/null; then
    return
  fi
  for u in "${USER_ALLOWED[@]}"; do
    [[ "$1" == "$u" ]] && return
  done

  echo "$1" >> "$suggestion_file"
  touch "${suggestion_file}.skip"
}

# --- Compound Command Parsing ---
# Split remote command on && and ; to handle chains like "cd /path && git log"
# Only auto-allow if ALL segments pass the allowlist checks

is_segment_allowed() {
  local seg="$1"
  # Trim whitespace
  seg="${seg#"${seg%%[![:space:]]*}"}"
  seg="${seg%"${seg##*[![:space:]]}"}"
  [[ -z "$seg" ]] && return 0

  local seg_base="${seg%% *}"
  seg_base="${seg_base//\"/}"
  seg_base="${seg_base//\'/}"
  seg_base="${seg_base##*/}"

  # curl/wget can read OR upload. Deny auto-approve when upload/POST flags are
  # present so a remote shell can't be used to exfiltrate data silently.
  if [[ "$seg_base" == "curl" ]]; then
    if [[ "$seg" =~ [[:space:]](-T|--upload-file|-d|--data|--data-binary|--data-raw|--data-urlencode|-F|--form|--post|-X[[:space:]]*(POST|PUT|PATCH|DELETE))([[:space:]=]|$) ]]; then
      return 1
    fi
  fi
  if [[ "$seg_base" == "wget" ]]; then
    if [[ "$seg" =~ [[:space:]](--post-file|--post-data|--method=(POST|PUT|PATCH|DELETE)|--body-file|--body-data)([[:space:]=]|$) ]]; then
      return 1
    fi
  fi

  # PM2: check subcommand against read-only list and user allowlist
  if [[ "$seg_base" == "pm2" ]]; then
    local pm2_sub
    pm2_sub=$(echo "$seg" | awk '{print $2}')
    for r in "${PM2_READ[@]}"; do
      [[ "$pm2_sub" == "$r" ]] && return 0
    done
    for u in "${USER_ALLOWED[@]}"; do
      [[ "$seg" == "$u" || "$seg" == "$u "* ]] && return 0
    done
    return 1
  fi

  # Built-in allowed commands
  for a in "${ALLOWED[@]}"; do
    [[ "$seg_base" == "$a" ]] && return 0
  done

  # User allowlist (prefix matching)
  for u in "${USER_ALLOWED[@]}"; do
    [[ "$seg" == "$u" || "$seg" == "$u "* ]] && return 0
  done

  return 1
}

# Fail closed on shell metacharacters the segment splitter can't safely reason about.
# Command substitution, process substitution, backticks, and standalone backgrounding
# can smuggle commands past the per-segment allowlist check.
if [[ "$remote_cmd_clean" == *'`'* ]] \
  || [[ "$remote_cmd_clean" == *'$('* ]] \
  || [[ "$remote_cmd_clean" == *'<('* ]] \
  || [[ "$remote_cmd_clean" == *'>('* ]] \
  || [[ "$remote_cmd_clean" =~ (^|[^\&])\&([^\&]|$) ]]; then
  queue_suggestion "$remote_cmd_clean"
  exit 0
fi

# Split on all command separators: && || ; |
# Order matters: && and || must be replaced before single & and |
segments="$remote_cmd_clean"
segments="${segments//&&/$'\n'}"
segments="${segments//||/$'\n'}"
segments="${segments//|/$'\n'}"
segments="${segments//;/$'\n'}"

all_allowed=true
failed_segments=()

while IFS= read -r segment; do
  if ! is_segment_allowed "$segment"; then
    all_allowed=false
    # Trim for suggestion
    segment="${segment#"${segment%%[![:space:]]*}"}"
    segment="${segment%"${segment##*[![:space:]]}"}"
    [[ -n "$segment" ]] && failed_segments+=("$segment")
  fi
done <<< "$segments"

if $all_allowed; then
  allow
fi

# Queue failed segments as individual suggestions
for fs in "${failed_segments[@]}"; do
  queue_suggestion "$fs"
done
exit 0
