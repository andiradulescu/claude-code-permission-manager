#!/usr/bin/env bash
# Shared helpers for hook test suites.
#
# Tests run each hook as a subprocess with crafted JSON on stdin and check
# whether the hook's JSON output contains "permissionDecision":"allow". The
# absence of that decision means the hook fell through to a normal permission
# prompt, which is what we want for exploit inputs.
#
# HOME is swapped to a temp directory so hooks that read/write user state
# (allowlist files, suggestion logs) do not touch the real home directory.

set -u

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
HOOKS_DIR="$REPO_ROOT/hooks"

PASS_COUNT=0
FAIL_COUNT=0
FAILED_TESTS=()

# Swap HOME to an isolated temp dir. Creates empty .claude/hooks so that
# hooks delegating to other hooks can find them via $HOME/.claude/hooks.
setup_isolated_home() {
  TEST_HOME=$(mktemp -d -t cc-perm-test.XXXXXX)
  export HOME="$TEST_HOME"
  mkdir -p "$HOME/.claude/hooks"
  # Symlink real hooks into fake HOME so domain delegation works
  for h in "$HOOKS_DIR"/*.sh; do
    ln -sf "$h" "$HOME/.claude/hooks/$(basename "$h")"
  done
  # Run from a non-git dir so `git rev-parse --show-toplevel` returns empty
  cd "$TEST_HOME"
}

teardown_isolated_home() {
  [[ -n "${TEST_HOME:-}" && -d "$TEST_HOME" ]] && rm -rf "$TEST_HOME"
}

# Write a user-level SSH allowlist file for tests.
set_ssh_allowed() {
  printf '%s\n' "$@" > "$HOME/.claude/ssh-allowed-commands.txt"
}

# Write a user-level ADB allowlist file for tests.
set_adb_allowed() {
  printf '%s\n' "$@" > "$HOME/.claude/adb-allowed-commands.txt"
}

_run_hook() {
  local hook="$1" json="$2"
  printf '%s' "$json" | "$hook" 2>/dev/null || true
}

_report() {
  local status="$1" label="$2"
  if [[ "$status" == "PASS" ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf '  \033[32mPASS\033[0m  %s\n' "$label"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILED_TESTS+=("$label")
    printf '  \033[31mFAIL\033[0m  %s\n' "$label"
  fi
}

# assert_allow LABEL HOOK_PATH JSON_INPUT
# Passes if the hook outputs a permissionDecision of "allow".
assert_allow() {
  local label="$1" hook="$2" json="$3"
  local output
  output=$(_run_hook "$hook" "$json")
  if [[ "$output" == *'"permissionDecision":"allow"'* ]]; then
    _report PASS "$label"
  else
    _report FAIL "$label (expected allow, got: ${output:-<empty>})"
  fi
}

# assert_prompt LABEL HOOK_PATH JSON_INPUT
# Passes if the hook does NOT output an allow decision. The hook fell
# through to the normal permission prompt, which is the safe default.
assert_prompt() {
  local label="$1" hook="$2" json="$3"
  local output
  output=$(_run_hook "$hook" "$json")
  if [[ "$output" == *'"permissionDecision":"allow"'* ]]; then
    _report FAIL "$label (expected prompt fallthrough, got allow)"
  else
    _report PASS "$label"
  fi
}

# Construct a PreToolUse Bash hook input JSON from a raw command string.
# Uses jq to handle quoting so tests can pass arbitrary shell as a literal.
mk_bash_input() {
  local cmd="$1"
  jq -n --arg cmd "$cmd" '{session_id: "test", tool_input: {command: $cmd}}'
}

print_summary() {
  local suite="$1"
  local total=$((PASS_COUNT + FAIL_COUNT))
  echo
  if [[ $FAIL_COUNT -eq 0 ]]; then
    printf '\033[32m%s: %d/%d passed\033[0m\n' "$suite" "$PASS_COUNT" "$total"
  else
    printf '\033[31m%s: %d/%d passed (%d failed)\033[0m\n' "$suite" "$PASS_COUNT" "$total" "$FAIL_COUNT"
    for t in "${FAILED_TESTS[@]}"; do
      printf '  - %s\n' "$t"
    done
  fi
}
