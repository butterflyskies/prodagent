# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.1] - 2026-05-15

### Fixed
- `agent-jj-guard`: `jj git push` (and other `jj git` subcommands) no longer falsely blocked — guard now identifies the actual command being invoked instead of matching `git` anywhere in the token list
- Release workflow: `shasum` command not found on Windows — now falls back to `sha256sum`
- Workspace dependency: `agent-shell-parser` uses `path + version` so local builds use workspace source while published crates resolve from crates.io

### Added
- `agent-shell-parser`: `find_command_position()` — identifies the invoked command in a tokenized word list, skipping leading env-var assignments

## [0.2.0] - 2026-05-14

### Changed
- `agent-jj-guard`: Expanded from 6 blocked destructive git commands to 25 redirected commands with per-command jj equivalents
- `agent-jj-guard`: Informational commands (`status`, `log`, `diff`, `show`, `blame`) now redirect to jj equivalents instead of passing through
- `agent-jj-guard`: `git push`, `git branch`, `git checkout`, `git reset` now blocked unconditionally (previously only blocked with specific flags like `--force`, `-D`, `--hard`)
- `agent-jj-guard`: `jj diff --git` hint included for agents expecting unified diff format

### Added
- `agent-jj-guard`: Coverage for `switch`, `add`, `rm`, `restore`, `clean`, `tag`, `fetch`, `pull`, `clone`, `init`, `remote`
- `agent-jj-guard`: Suggestion quality tests verifying per-command guidance content

### Fixed
- `agent-jj-guard`: Deprecated `-d` flag in rebase suggestions updated to `-o`/`--onto` (jj 0.40)

## [0.1.0] - 2026-05-14

### Added
- `agent-jj-guard`: PreToolUse hook that blocks git commands in jj-colocated repos with per-command jj equivalents (25 commands covered)
- `agent-jj-workspace`: WorktreeCreate hook for creating jj workspaces under `.claude/worktrees/`
- `agent-jj-cleanup`: WorktreeRemove hook for cleaning up jj workspaces
- `agent-shell-parser`: Shared library for JSON input parsing, jj detection, shell tokenization, and guard rules
