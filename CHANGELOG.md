# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-05-16

### Added

#### Parser (`agent-shell-parser`)

- `parse` module — tree-sitter-bash AST-based command decomposition, replacing the hand-rolled `split_compound_command` character scanner used in v0.2
- Recursive pipeline data model — `ParsedPipeline` is a tree where substitutions (`$()`, backticks, `<()`, `>()`) contain recursively-parsed nested pipelines, enabling bottom-up evaluation
- `ParsedCommand` with ordered `CommandArg` args — schema-free structural decomposition into command, flags, and positional arguments, preserving source order for schema-aware consumers
- `resolve_command()` — recursively strips transparent wrappers (env, sudo, command, builtin, nice, nohup, xargs) and classifies unanalyzable patterns (eval, shell -c, source, dynamic `$cmd`)
- `command_characteristics()` — identifies indirect execution patterns and dynamic command positions
- `path` module — `resolve_path()`, `extract_cd_target()`, `extract_git_c_path()`, `effective_cwd()` for tracking working directory changes through compound commands
- `ParsedPipeline` traversal methods — `find_segment()`, `filter_segments()`, `has_parse_errors_recursive()`
- `has_parse_errors` flag — signals when tree-sitter used error recovery, so callers can fail closed
- `dump_ast()` diagnostic function for debugging parse output

#### Guard (`agent-jj-guard`)

- Recursive pipeline checking — blocked git commands now caught inside `$()` substitutions, for-loop iteration values, and nested wrappers (v0.2 only checked top-level segments)
- Adversarial bypass hardening — `eval`, `bash -c`, `source`, `. script.sh`, dynamic `$cmd` blocked; `env`, `sudo`, `command`, `builtin`, `nice`, `nohup`, `xargs` unwrapped and inner command re-checked
- Effective CWD tracking — `cd /other/repo && git status` correctly identifies the git command's working directory, preventing false blocks in non-jj repos

### Changed

- `agent-shell-parser` is now a pure parser library with no policy concepts — the `guard` module (with `BlockedCommand`, `check_git_command`, git blocklist) moved to `agent-jj-guard::policy`
- `agent-jj-guard` works directly with `ParsedCommand` and `CommandArg` from the parser, instead of reconstructing word lists
- `agent-jj-guard` fails closed on parse errors and tree-sitter error recovery
- `agent-jj-guard` error messages say "outside of the coding agent" instead of "outside Claude Code"
- `shell-words` replaced by `shlex` — fixes quoted env var handling (`FOO="bar baz" git push`)

### Removed

- `shell-words` dependency
- `agent-shell-parser::guard` module — policy is the consumer's responsibility
- `find_command_position` from `agent-shell-parser` public API — moved to `agent-jj-guard::policy`

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
