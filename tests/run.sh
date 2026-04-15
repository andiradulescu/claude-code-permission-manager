#!/usr/bin/env bash
# Run all hook test suites and report a combined pass/fail summary.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Dependencies used by the hooks themselves. Skip the suite cleanly if missing
# so CI environments without shfmt/jq don't get cryptic errors.
for dep in jq shfmt; do
  if ! command -v "$dep" &>/dev/null; then
    echo "SKIP: '$dep' is required but not installed (brew install $dep)"
    exit 2
  fi
done

suites=(
  test_auto_approve.sh
  test_ssh_gating.sh
  test_adb_gating.sh
)

total_failed=0
for suite in "${suites[@]}"; do
  echo
  bash "$SCRIPT_DIR/$suite" || total_failed=$((total_failed + 1))
done

echo
if [[ $total_failed -eq 0 ]]; then
  printf '\033[32mAll suites passed\033[0m\n'
  exit 0
else
  printf '\033[31m%d suite(s) failed\033[0m\n' "$total_failed"
  exit 1
fi
