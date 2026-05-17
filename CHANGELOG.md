# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.2] - 2026-05-16

### Fixed

- `agent-jj guard`: Git commands targeting non-jj directories (via `git -C` or `cd /path && git ...`) are no longer blocked when the session CWD is jj-colocated. Previously the guard short-circuited on session CWD without checking the effective target directory.

## [0.4.1] - 2026-05-16

### Fixed

- `agent-jj workspace`: Sanitize workspace name input to prevent path traversal via `../` sequences
- `agent-jj guard`: Allow `git worktree prune` (safe maintenance command was incorrectly blocked)

### Added

- `readme` field in both crate manifests for crates.io display

## [0.4.0] - 2026-05-16

### Changed

- **BREAKING** Consolidated `agent-jj-guard`, `agent-jj-workspace`, and `agent-jj-cleanup` into a single `agent-jj` binary with subcommands (`guard`, `workspace`, `cleanup`)
- **BREAKING** `agent-shell-parser`: Removed `is_jj_colocated()`, `jj_version()`, `require_jj_version()` from public API — jj utility functions inlined into `agent-jj`
- **BREAKING** `agent-shell-parser`: Removed `Error::Jj` variant
- `agent-shell-parser`: Added `#[non_exhaustive]` to `Error` enum

### Removed

- `agent-jj-guard` crate (replaced by `agent-jj guard`)
- `agent-jj-workspace` crate (replaced by `agent-jj workspace`)
- `agent-jj-cleanup` crate (replaced by `agent-jj cleanup`)

## [0.3.0] - 2026-05-16

### Added

#### Parser (`agent-shell-parser`)

- `parse` module — tree-sitter-bash AST-based command decomposition, replacing the hand-rolled `split_compound_command` character scanner used in v0.2
- Recursive pipeline data model — `ParsedPipeline` is a tree where substitutions (`$()`, backticks, `<()`, `>()`) contain recursively-parsed nested pipelines, enabling bottom-up evaluation
- `ParsedCommand` with ordered `CommandArg` args — schema-free structural decomposition into command, flags, and positional arguments, preserving source order for schema-aware consumers
- `resolve_command()` — recursively strips transparent wrappers and classifies unanalyzable patterns (eval, shell -c, source, dynamic `$cmd`). Depth-limited to 32 levels with a global parse budget of 512 to prevent DoS
- `command_characteristics()` — O(1) surface-level classification of indirect execution patterns via `classify_surface` (no recursion)
- Config-driven command classification — all command knowledge lives in `config/commands.json`. 16 wrapper specs: sudo, env, nice, nohup, command, builtin, xargs, parallel, time, timeout, exec, setsid, strace, ionice, chrt, taskset
- `WrapperSpec` with `skip_positionals` — models wrappers that have mandatory positional args before the inner command (e.g., `timeout DURATION cmd`, `chrt PRIORITY cmd`)
- `hook` module — Claude Code hook I/O types (`PreToolUseInput`, `WorktreeCreateInput`, `WorktreeRemoveInput`, `parse_input`)
- `path` module — `resolve_path()`, `extract_cd_target()`, `extract_git_c_path()`, `effective_cwd()` tracking working directory through all git segments in compound commands
- `ParsedPipeline` traversal methods — `find_segment()`, `filter_segments()`, `find_pipeline()`, `any_pipeline()`, `has_parse_errors_recursive()`
- `ParsedPipeline::empty_with_error()` constructor for fail-closed parse failures
- Structured `Redirection` type with `operator`, `fd`, `target` fields and `Display` impl
- `Display` impl for `Operator`
- Input length cap (64 KiB) and global parse budget (512 tree-sitter parses) preventing resource exhaustion
- Combined short flag handling in wrapper stripping (`-uroot` treated as `-u root`)
- Combined short flag detection in unanalyzable flag checks (`sudo -iu` triggers `-i` unanalyzable)

#### Guard (`agent-jj-guard`)

- Recursive pipeline checking — blocked git commands caught inside `$()` substitutions, for-loop iteration values, and nested wrappers
- Adversarial bypass hardening — `eval`, `bash -c`, `source`, `. script.sh`, dynamic `$cmd` blocked; all 16 configured wrappers unwrapped and inner command re-checked
- `sudo -i` / `sudo -s` classified as unanalyzable (spawn interactive shells)
- Effective CWD tracking — returns all git-segment CWDs in compound commands; guard checks if any targets a jj-colocated repo, preventing the multi-cd bypass (`cd /non-jj && git status && cd /jj && git push`)
- 30 blocked git subcommands including submodule, am, apply, update-ref, update-index

### Changed

- `agent-shell-parser` is now a pure parser library with no policy concepts — the `guard` module moved to `agent-jj-guard::policy`
- `agent-jj-guard` works directly with `ParsedCommand` and `CommandArg` from the parser
- `agent-jj-guard` fails closed on parse errors, tree-sitter error recovery, and depth/budget exhaustion
- `agent-jj-guard` error messages say "outside of the coding agent" instead of "outside Claude Code"
- `shell-words` replaced by `shlex` — fixes quoted env var handling (`FOO="bar baz" git push`)
- `walk_list` converted from recursive to iterative — prevents stack overflow on long `&&`/`||` chains
- `strip_with_spec` uses index-based resolution internally (zero-allocation on the hot path)
- `effective_cwd` returns `Vec<String>` (deduplicated) instead of `String`

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
