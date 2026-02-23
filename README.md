# Claude Code Permission Manager

Claude Code's "Always Allow" button is broken. It doesn't persist choices, and project settings clobber global settings.

These hooks actually remember your choices.

## The Problem

Claude Code has three long-standing issues with permissions:

1. **"Always Allow" doesn't persist** ([#19487](https://github.com/anthropics/claude-code/issues/19487)) - Click "Always Allow", it prompts you again next session
2. **Project settings replace global settings** ([#17017](https://github.com/anthropics/claude-code/issues/17017)) - If a project has `.claude/settings.local.json`, your user-level allowlist is ignored entirely
3. **Compound commands always prompt** - `ls | grep foo` prompts even when both `ls` and `grep` are allowed individually

These issues span **9 open GitHub issues over 3 years**. This fixes all three.

## How It Works

Three hooks working together:

### 1. Permission Suggestion (`allowlist-suggest.sh`)
When you approve a permission prompt, this hook logs it to a session-specific file. Uses Claude Code's `permission_suggestions` field to extract the exact permission string.

### 2. Permission Notification (`allowlist-notify.sh`)
PostToolUse hook that reads the suggestions file and prompts Claude to ask: "You just approved X. Should I add it to your allowlist?"

Options:
- **Always allow** - Adds to both user-level and project-level allowlists (works around the settings bug)
- **Not now** - Skip this session
- **Never ask** - Dismiss permanently

### 3. Auto-Approval (`auto-approve-allowed-commands.sh`)
PreToolUse hook that parses compound commands (pipes, `&&`, loops, etc.) with `shfmt` and approves them when **all** individual commands are in your allowlist.

Example: `ls | grep foo` → extracts `["ls", "grep foo"]` → checks allowlist → auto-approves if both allowed.

**Domain-specific gating**: For `ssh`, `adb`, and Docker commands, delegates to specialized hooks (`ssh-gating.sh`, `adb-gating.sh`, `docker-gating.sh`) with safety rules for each domain.

## Installation

Drop the hooks in `~/.claude/hooks/`:

```bash
cd ~/.claude/hooks/
# Copy all .sh files from this repo's hooks/ directory here
```

Or clone and symlink:

```bash
git clone https://github.com/studio-corsair/claude-code-permission-manager.git
cd ~/.claude/hooks/
ln -s ~/claude-code-permission-manager/hooks/* .
```

**Requirements:**
- `jq` (for JSON parsing)
- `shfmt` (for shell AST parsing in auto-approve hook)

Install with Homebrew:
```bash
brew install jq shfmt
```

## Hook Registration

The hooks auto-register via Claude Code's hook discovery. On startup, Claude Code scans `~/.claude/hooks/` and registers:

- `allowlist-suggest.sh` → PermissionRequest hook (all tools)
- `allowlist-notify.sh` → PostToolUse hook (Bash, MCP, file operations)
- `auto-approve-allowed-commands.sh` → PreToolUse hook (Bash)
- Domain-specific hooks → PreToolUse (Bash commands for ssh/adb/docker)

No manual configuration needed.

## Usage

After installation:

1. Approve a command when Claude prompts you
2. On the next tool use, Claude asks: "You just approved `Bash(ls:*)`. Should I add it to your allowlist?"
3. Choose "Always allow" to remember it permanently
4. Future uses of that command auto-approve

For compound commands like `ls | grep foo`, if both `ls` and `grep` are in your allowlist, the hook auto-approves without prompting.

## How This Differs from Built-In "Always Allow"

| Feature | Built-In "Always Allow" | These Hooks |
|---------|------------------------|-------------|
| **Persists across sessions** | ❌ Lost on restart | ✅ Saved to settings |
| **Works with project settings** | ❌ Clobbered by project config | ✅ Writes to both user and project |
| **Compound commands** | ❌ Always prompts | ✅ Auto-approves if all parts allowed |
| **Session snooze** | ❌ No option | ✅ "Not now" for session |
| **Permanent dismiss** | ❌ No option | ✅ "Never ask" to dismiss |

## Files

### Core Hooks
- `allowlist-suggest.sh` - Logs approved permissions for AI to review
- `allowlist-notify.sh` - Prompts AI to add permissions to allowlist
- `auto-approve-allowed-commands.sh` - Auto-approves compound commands

### Domain-Specific Hooks
- `ssh-gating.sh` + `ssh-allowlist-notify.sh` - SSH command safety rules and allowlist management
- `adb-gating.sh` + `adb-allowlist-notify.sh` - ADB command safety rules and allowlist management
- `docker-gating.sh` + `docker-allowlist-notify.sh` - Docker command safety rules and allowlist management

Domain hooks know which commands are safe (read-only) vs dangerous (destructive) for their specific domain. Auto-approval delegates to these when it finds ssh/adb/docker commands inside loops or compound statements.

## GitHub Issues This Fixes

- [#19487](https://github.com/anthropics/claude-code/issues/19487) - "Always Allow" doesn't persist
- [#17017](https://github.com/anthropics/claude-code/issues/17017) - Project settings replace global settings
- Plus 7 related issues about permission persistence

## Technical Details

**Permission precedence**: deny > ask > allow

Settings are checked in this order:
1. User-level deny list (`~/.claude/settings.local.json`)
2. Project-level deny list (`.claude/settings.local.json`)
3. User-level ask list
4. Project-level ask list
5. User-level allow list
6. Project-level allow list

The hooks write to **both** user-level and project-level allowlists to work around the settings merge bug.

**Compound command parsing**: Uses `shfmt` to parse Bash syntax into an AST, then extracts all individual commands. Handles pipes, `&&`, `;`, loops (`for`/`while`), conditionals (`if`/then`), subshells, command substitution (`$(...)`, `` `...` ``), and `bash -c` recursively.

**Quote preservation**: When extracting commands, quotes are preserved exactly as they appear (e.g., `grep -E "(int|long)"` keeps the parens and quotes intact).

## License

MIT
