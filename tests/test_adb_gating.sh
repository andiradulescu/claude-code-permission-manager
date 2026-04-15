#!/usr/bin/env bash
# Tests for adb-gating.sh
#
# Covers:
#   - Security: metacharacter rejection in adb shell payloads
#   - Security: pipe/compound splitter for shell subcommands
#   - Safe top-level subcommands (devices, logcat, pull, etc.)
#   - Unsafe subcommands falling through
#   - pm/am/settings subcommand gating
#   - Regression: benign compound shell commands

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

HOOK="$HOOKS_DIR/adb-gating.sh"

setup_isolated_home
trap teardown_isolated_home EXIT

echo "adb-gating.sh"

# --- Security: shell metacharacters in adb shell must fall through ---

assert_prompt "reject: adb shell backtick subshell" "$HOOK" \
  "$(mk_bash_input 'adb shell "echo `rm -rf /sdcard`"')"

assert_prompt "reject: adb shell \$() substitution" "$HOOK" \
  "$(mk_bash_input 'adb shell "echo $(rm -rf /sdcard)"')"

assert_prompt "reject: adb shell standalone & chain" "$HOOK" \
  "$(mk_bash_input 'adb shell "ls & rm -rf /sdcard"')"

assert_prompt "reject: adb shell <() process sub" "$HOOK" \
  "$(mk_bash_input 'adb shell "diff <(ls) <(cat file)"')"

# --- Security: pipe/compound splitter must check every segment ---

assert_prompt "reject: ls | pm uninstall" "$HOOK" \
  "$(mk_bash_input 'adb shell "ls | pm uninstall com.target"')"

assert_prompt "reject: ls && rm" "$HOOK" \
  "$(mk_bash_input 'adb shell "ls && rm /sdcard/file"')"

assert_prompt "reject: unsafe pm subcommand" "$HOOK" \
  "$(mk_bash_input 'adb shell "pm uninstall com.target"')"

assert_prompt "reject: unsafe settings put" "$HOOK" \
  "$(mk_bash_input 'adb shell "settings put global airplane_mode_on 1"')"

assert_prompt "reject: disallowed shell rm" "$HOOK" \
  "$(mk_bash_input 'adb shell "rm /sdcard/file"')"

# --- Regression: safe top-level subcommands ---

assert_allow "allow: adb devices" "$HOOK" \
  "$(mk_bash_input 'adb devices')"

assert_allow "allow: adb version" "$HOOK" \
  "$(mk_bash_input 'adb version')"

assert_allow "allow: adb pull" "$HOOK" \
  "$(mk_bash_input 'adb pull /sdcard/file.txt .')"

assert_allow "allow: adb logcat" "$HOOK" \
  "$(mk_bash_input 'adb logcat -d')"

assert_allow "allow: adb -s serial devices" "$HOOK" \
  "$(mk_bash_input 'adb -s emulator-5554 devices')"

# --- Regression: safe adb shell commands ---

assert_allow "allow: adb shell ls" "$HOOK" \
  "$(mk_bash_input 'adb shell "ls /sdcard"')"

assert_allow "allow: adb shell cat" "$HOOK" \
  "$(mk_bash_input 'adb shell "cat /proc/version"')"

assert_allow "allow: adb shell dumpsys battery" "$HOOK" \
  "$(mk_bash_input 'adb shell "dumpsys battery"')"

assert_allow "allow: adb shell getprop" "$HOOK" \
  "$(mk_bash_input 'adb shell "getprop ro.build.version.sdk"')"

assert_allow "allow: adb shell input tap" "$HOOK" \
  "$(mk_bash_input 'adb shell "input tap 500 500"')"

assert_allow "allow: adb shell compound cd && ls" "$HOOK" \
  "$(mk_bash_input 'adb shell "cd /sdcard && ls"')"

assert_allow "allow: adb shell pipe ls | grep" "$HOOK" \
  "$(mk_bash_input 'adb shell "ls /sdcard | grep .txt"')"

# --- pm/am/settings gating ---

assert_allow "allow: pm list packages" "$HOOK" \
  "$(mk_bash_input 'adb shell "pm list packages"')"

assert_allow "allow: am start activity" "$HOOK" \
  "$(mk_bash_input 'adb shell "am start -n com.example/.MainActivity"')"

assert_allow "allow: settings get" "$HOOK" \
  "$(mk_bash_input 'adb shell "settings get global device_name"')"

# --- Input validation ---

assert_prompt "fall through: non-adb command" "$HOOK" \
  "$(mk_bash_input 'ls -la')"

assert_prompt "fall through: adb with no subcommand" "$HOOK" \
  "$(mk_bash_input 'adb')"

assert_prompt "fall through: empty command" "$HOOK" \
  '{"session_id":"test","tool_input":{"command":""}}'

print_summary "adb-gating.sh"
[[ $FAIL_COUNT -eq 0 ]]
