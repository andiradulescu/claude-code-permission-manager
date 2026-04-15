#!/usr/bin/env bash
# adb-gating.sh - PreToolUse hook that gates ADB commands
#
# Intercepts Bash tool calls containing ADB commands and applies
# allowlist logic to the subcommand and shell commands.
#
# Decisions:
#   allow  - Safe read-only or automation commands
#   (none) - Everything else falls through to Claude Code's permission prompt
#
# Allowlist sources:
#   1. Built-in SAFE arrays (read-only + automation commands)
#   2. ~/.claude/adb-allowed-commands.txt (user-added, one command per line)
#
# When a command is NOT auto-allowed, writes to a session-scoped
# suggestion file for adb-allowlist-notify.sh to pick up.

set -euo pipefail

command -v jq &>/dev/null || exit 0

ADB_ALLOWED_FILE="$HOME/.claude/adb-allowed-commands.txt"
ADB_DISMISSED_FILE="$HOME/.claude/adb-dismissed.txt"

# Read hook input early so session_id is available for the sweeper
input=$(cat)
session_id=$(echo "$input" | jq -r '.session_id // empty')
command=$(echo "$input" | jq -r '.tool_input.command // empty')

# Detect git root for project-level files
git_root=$(git rev-parse --show-toplevel 2>/dev/null || true)

# --- Sweep: redirect option-2 entries to ADB allowlist ---
# If user picked "don't ask again" on a prompt, Claude Code added
# Bash(adb ...:*) to settings.local.json. We move it to the ADB
# allowlist and remove it from settings so the hook stays in control.
# Also queues a swept suggestion so the notification hook can ask
# about global vs project scope.
sweep_adb_from_settings() {
  local settings_file="$1"
  [[ ! -f "$settings_file" ]] && return

  local adb_entries
  adb_entries=$(jq -r '.permissions.allow[]? // empty' "$settings_file" 2>/dev/null | grep '^Bash(adb' || true)
  [[ -z "$adb_entries" ]] && return

  local moved_any=false
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    # Bash(adb push:*) → push
    # Bash(adb shell rm:*) → shell rm
    # Bash(adb:*) → empty (too broad, just delete)
    local cmd="${entry#Bash(adb}"
    cmd="${cmd# }"
    cmd="${cmd%:\*)}"
    cmd="${cmd%)}"

    if [[ -n "$cmd" ]]; then
      if ! grep -qxF "$cmd" "$ADB_ALLOWED_FILE" 2>/dev/null; then
        echo "$cmd" >> "$ADB_ALLOWED_FILE"
      fi
      # Queue swept suggestion for scope notification
      if [[ -n "$session_id" ]]; then
        echo "$cmd" >> "$HOME/.claude/adb-swept-${session_id}.log"
        touch "$HOME/.claude/adb-swept-${session_id}.log.skip"
      fi
    fi
    moved_any=true
  done <<< "$adb_entries"

  if $moved_any; then
    jq 'del(.permissions.allow[] | select(startswith("Bash(adb")))' "$settings_file" > "${settings_file}.tmp" \
      && mv "${settings_file}.tmp" "$settings_file"
  fi
}

if [[ -n "$git_root" ]]; then
  sweep_adb_from_settings "$git_root/.claude/settings.local.json"
fi
sweep_adb_from_settings "$HOME/.claude/settings.local.json"

[[ -z "$command" ]] && exit 0

# --- ADB Detection ---
adb_line=""
while IFS= read -r line; do
  trimmed="${line#"${line%%[![:space:]]*}"}"
  if [[ "$trimmed" =~ ^adb[[:space:]] ]]; then
    adb_line="$trimmed"
    break
  fi
done <<< "$command"

[[ -z "$adb_line" ]] && exit 0

# --- Parse ADB Arguments ---
read -ra words <<< "$adb_line"

i=1  # skip "adb"
subcmd=""
subcmd_start=-1

while [[ $i -lt ${#words[@]} ]]; do
  word="${words[$i]}"
  case "$word" in
    # Options that consume the next argument
    -[stHPL])
      ((i += 2))
      continue
      ;;
    # Boolean flags
    -[de])
      ((i++))
      continue
      ;;
    # First non-option word is the subcommand
    *)
      subcmd="$word"
      subcmd_start=$((i + 1))
      break
      ;;
  esac
done

[[ -z "$subcmd" ]] && exit 0

# --- Rules ---

# Top-level ADB subcommands that are safe (read-only or informational)
SAFE_SUBCMDS=(
  devices version help get-state get-serialno get-devpath
  pull
  logcat
  bugreport jdwp
  forward reverse
  wait-for-device wait-for-recovery wait-for-sideload wait-for-bootloader
  start-server kill-server
  reconnect
)

# Shell commands that are safe (read-only or non-destructive automation)
SAFE_SHELL_CMDS=(
  cd
  ls cat find grep head tail wc stat file
  dumpsys getprop
  uiautomator
  screencap screenrecord
  input    # tap, swipe, text, keyevent — automation
  content  # content provider queries
  logcat
  id whoami
  df du free
  ps top
  date echo
)

# pm subcommands that are safe (read-only)
PM_SAFE=(list path dump resolve-activity)

# am subcommands that are safe (launch/automation)
AM_SAFE=(start broadcast startservice force-stop)

# settings subcommands that are safe (read-only)
SETTINGS_SAFE=(get list)

# Load user-added allowed commands (global)
USER_ALLOWED=()
if [[ -f "$ADB_ALLOWED_FILE" ]]; then
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    USER_ALLOWED+=("$line")
  done < "$ADB_ALLOWED_FILE"
fi

# Load project-level allowed commands
if [[ -n "$git_root" ]]; then
  _proj_adb_allowed="$git_root/.claude/adb-allowed-commands.txt"
  if [[ -f "$_proj_adb_allowed" ]]; then
    while IFS= read -r line; do
      [[ -z "$line" || "$line" == \#* ]] && continue
      USER_ALLOWED+=("$line")
    done < "$_proj_adb_allowed"
  fi
fi

allow() {
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
}

queue_suggestion() {
  [[ -z "$session_id" ]] && return
  local suggestion_file="$HOME/.claude/adb-suggestions-${session_id}.log"
  local snoozed_file="$HOME/.claude/adb-snoozed-${session_id}.txt"

  if [[ -f "$ADB_DISMISSED_FILE" ]] && grep -qxF "$1" "$ADB_DISMISSED_FILE" 2>/dev/null; then
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

# --- Check safe top-level subcommands ---
for s in "${SAFE_SUBCMDS[@]}"; do
  [[ "$subcmd" == "$s" ]] && allow
done

# --- For "adb shell", parse the remote command ---
if [[ "$subcmd" == "shell" ]]; then
  # Interactive shell (no command) — let it through to normal prompt
  [[ $subcmd_start -ge ${#words[@]} ]] && exit 0

  shell_cmd="${words[*]:$subcmd_start}"

  # Strip wrapping quotes
  if [[ "$shell_cmd" =~ ^\"(.*)\"$ ]]; then
    shell_cmd="${BASH_REMATCH[1]}"
  elif [[ "$shell_cmd" =~ ^\'(.*)\'$ ]]; then
    shell_cmd="${BASH_REMATCH[1]}"
  fi

  # Strip local shell operators
  shell_cmd_clean="$shell_cmd"
  shell_cmd_clean="${shell_cmd_clean% 2>&1}"
  shell_cmd_clean="${shell_cmd_clean% 2>\/dev\/null}"

  # --- Compound Command Parsing ---
  is_shell_segment_allowed() {
    local seg="$1"
    seg="${seg#"${seg%%[![:space:]]*}"}"
    seg="${seg%"${seg##*[![:space:]]}"}"
    [[ -z "$seg" ]] && return 0

    local seg_base="${seg%% *}"
    seg_base="${seg_base//\"/}"
    seg_base="${seg_base//\'/}"
    seg_base="${seg_base##*/}"

    # pm: check subcommand
    if [[ "$seg_base" == "pm" ]]; then
      local pm_sub
      pm_sub=$(echo "$seg" | awk '{print $2}')
      for r in "${PM_SAFE[@]}"; do
        [[ "$pm_sub" == "$r" ]] && return 0
      done
      return 1
    fi

    # am: check subcommand
    if [[ "$seg_base" == "am" ]]; then
      local am_sub
      am_sub=$(echo "$seg" | awk '{print $2}')
      for r in "${AM_SAFE[@]}"; do
        [[ "$am_sub" == "$r" ]] && return 0
      done
      return 1
    fi

    # settings: check subcommand (only get/list are safe)
    if [[ "$seg_base" == "settings" ]]; then
      local settings_sub
      settings_sub=$(echo "$seg" | awk '{print $2}')
      for r in "${SETTINGS_SAFE[@]}"; do
        [[ "$settings_sub" == "$r" ]] && return 0
      done
      return 1
    fi

    # Built-in safe shell commands
    for a in "${SAFE_SHELL_CMDS[@]}"; do
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
  if [[ "$shell_cmd_clean" == *'`'* ]] \
    || [[ "$shell_cmd_clean" == *'$('* ]] \
    || [[ "$shell_cmd_clean" == *'<('* ]] \
    || [[ "$shell_cmd_clean" == *'>('* ]] \
    || [[ "$shell_cmd_clean" =~ (^|[^\&])\&([^\&]|$) ]]; then
    queue_suggestion "shell $shell_cmd_clean"
    exit 0
  fi

  # Split on all command separators: && || ; |
  # Order matters: && and || must be replaced before single & and |
  segments="$shell_cmd_clean"
  segments="${segments//&&/$'\n'}"
  segments="${segments//||/$'\n'}"
  segments="${segments//|/$'\n'}"
  segments="${segments//;/$'\n'}"

  all_allowed=true
  failed_segments=()

  while IFS= read -r segment; do
    if ! is_shell_segment_allowed "$segment"; then
      all_allowed=false
      segment="${segment#"${segment%%[![:space:]]*}"}"
      segment="${segment%"${segment##*[![:space:]]}"}"
      [[ -n "$segment" ]] && failed_segments+=("$segment")
    fi
  done <<< "$segments"

  if $all_allowed; then
    allow
  fi

  for fs in "${failed_segments[@]}"; do
    queue_suggestion "shell $fs"
  done
  exit 0
fi

# --- For other subcommands, check user allowlist ---
rest="${words[*]:$((subcmd_start - 1))}"
for u in "${USER_ALLOWED[@]}"; do
  [[ "$rest" == "$u" || "$rest" == "$u "* ]] && allow
done

# Not allowed — queue the subcommand as suggestion
queue_suggestion "$rest"
exit 0
