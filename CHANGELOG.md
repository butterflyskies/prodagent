# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.9.0] - 2026-06-30

### Added

- **New binary**: `prodagent-tool-gate` — PreToolUse hook replacing cc-toolgate, with three-tier config cascade via prodagent-config, structured decision logging to `<data_dir>/prodagent/decisions.log`, `--escalate-deny`/`--dump-config`/`--dump-ast` flags (#64)
- `prodagent-policy`: Path-scoped policy decisions for Bash commands — optional `paths` field (glob list) on policy rules constrains where rules apply, with per-path evaluation through three-tier specificity (command+path > path-only/command-only > effect default), deny-wins aggregation across multi-path commands (#77)
- `prodagent-policy`: `PathGlob` newtype for validated path glob patterns — rejects empty strings and bare `*`/`**`/`/*`/`/**` universal bypasses at construction time (#77)
- `prodagent-policy`: Consent-gated user overrides for project policy decisions — `[policy.overrides]` section lets users explicitly bypass project-level restrictions with conflict detection, structured override config in hook output, and safety rails preserving env gates, escalation flags, and wrapper analysis (#83)
- `prodagent-proofs`: Kani proof harnesses for path evaluation (deny absorption, aggregation monotonicity, tier specificity, evaluation totality), gate-path composition, merge monotonicity, command-scoped path rules, and override properties (no silent weakening, tightening freedom, idempotency, safety rail preservation) (#77, #83)

### Changed

- **BREAKING** Renamed `agent-policy` crate to `prodagent-policy` for crates.io namespace availability (#73)
- `prodagent-types`: `WordKind` enum on `Word` type — words from tree-sitter now carry structural classification (Literal, CommandSubstitution, VariableExpansion, ArithmeticExpansion, Dynamic), eliminating byte-scanning heuristics in `as_classified_assignment()`, `classify_surface()`, and `collect_substitutions()` (#67)
- `prodagent-config`: `load_split()` is now the primitive config loader; `load()` delegates to it, eliminating 70-line copy-paste (#83)
- `prodagent-config`: `MonotonicityViolation` converted from struct to enum with `Relaxation` and `Structural` variants (#83)
- Updated README for v0.8 architecture — dependency graph, configuration section, formal verification section, development instructions (#72)

### Fixed

- `prodagent-types`: Normalize trailing slashes in `AffectedPaths` via camino component re-collection, fixing proptest failures where `foo/` and `foo` were treated as distinct entries (#68)
- `prodagent-policy`: Use `strongest_effect_default` as floor in command and subcommand decision validation — prevents project configs from relaxing mutating/unknown command decisions via mixed effect defaults (#82)
- `prodagent-policy`: Use `strongest_effect_default` as fallback for command-scoped path rules without per-command overrides (#77)
- Update `anyhow` to 1.0.103 to resolve RUSTSEC-2026-0190 unsoundness advisory (#84)
- CI: Add missing crates to publish workflow and release archives (#74)

## [0.8.2] - 2026-06-28

### Added

- Recursive policy evaluation for command substitutions in env assignments (`FOO=$(cmd)`)
- Env snapshot propagation across `&&`/`;` compound command segments
- `AssignmentValue` type-driven classification (Static/CommandSubstitution/VariableExpansion)
- `$((arithmetic))` correctly distinguished from `$(command)` substitutions
- All declaration keywords (`export`/`declare`/`readonly`/`local`/`typeset`) propagate env mutations
- Metamorphic proptest sampling from all transparent KB wrappers
- ADRs and spec documentation for env gate semantics

## [0.8.1] - 2026-06-07

### Changed

- Renamed `agent-types` crate to `prodagent-types` for crates.io publishing
- Added `prodagent-types` to publish workflow
- Reduced crates.io indexing wait times in publish workflow

## [0.8.0] - 2026-06-06

### Added

- **New crate**: `agent-types` — shared types crate (workspace-only, not published) providing `Word`, `WrapperSpec`, `CommandConfig`, `SubcommandPattern`, and compiled default wrapper specs as the single source of truth
- `agent-types`: `SubcommandPattern` newtype with `Borrow<str>` for zero-allocation HashMap lookups, depth validation, and whitespace normalization
- `agent-types`: `DEFAULT_WRAPPER_SPECS` — 19 wrapper specs compiled as Rust constants, replacing the embedded `commands.json`
- `agent-types`: `WrapperEnvPolicy` enum (Inherit/Unknown/Explicit) on `WrapperSpec` for env propagation modeling
- `agent-shell-parser`: `resolve_command_with_extra_wrappers()` — accepts additional WrapperSpecs beyond compiled defaults
- `agent-shell-parser`: `merged_config()` — builds a CommandConfig from defaults + extras with deduplication
- `prodagent-policy`: `derive_wrapper_specs()` — extracts minimal WrapperSpecs from KB-only wrappers and primes the parser at evaluation time, closing the wrapper drift gap
- `prodagent-policy`: Merged CommandConfig cached per `evaluate_command` call and threaded through the evaluation tree (no per-depth cloning)
- `agent-command-knowledge`: KB entries for 7 parser-only wrappers (builtin, command, exec, setsid, ionice, chrt, taskset) completing wrapper list symmetry
- 15 new tests including parser-level stripping tests for watch/ltrace/su, wrapper resolution tests for doas/pkexec, and SubcommandPattern proptests

### Changed

- `agent-shell-parser`: `Word`, `WrapperSpec`, `CommandConfig` moved to `agent-types` (re-exported from original locations for backward compatibility)
- `agent-shell-parser`: Deleted embedded `config/commands.json` — defaults now compiled from `agent-types::DEFAULT_WRAPPER_SPECS`
- `agent-command-knowledge`: `MAX_SUBCOMMAND_DEPTH` moved to `agent-types` (re-exported for backward compatibility)
- `agent-types`: `watch`, `ltrace`, `su` added to `DEFAULT_WRAPPER_SPECS` with proper flag specs (previously KB-only with no parser-level stripping)

### Fixed

- `prodagent-policy`: KB-only wrappers (doas, pkexec) now stripped correctly to reveal and classify the inner command, instead of falling through to the generic "inner command not resolved" path
- `agent-types`: `su` WrapperSpec uses `skip_positionals: 1` to skip the username argument and `-c`/`--command` as unanalyzable flags
- `agent-types`: `watch` WrapperSpec has `-n`/`--interval` as value-consuming flags (previously misparsed interval as inner command)
- `agent-types`: `ltrace` WrapperSpec has `-e`/`-o`/`-p`/`-n`/`-s`/`-A` as value-consuming flags

## [0.7.0] - 2026-05-31

### Added

- **New crate**: `prodagent-policy` — policy engine for agent tool authorization, maps command effects to allow/ask/deny decisions
- `prodagent-policy`: Full parse→classify→decide pipeline via `PolicyEngine::evaluate_command()` — takes a raw command string, returns a final authorization decision
- `prodagent-policy`: `PolicyConfig` with configurable effect-class defaults and per-command/subcommand overrides
- `prodagent-policy`: `PolicyConfigBuilder` for ergonomic config construction (`.allow()` / `.ask()` / `.deny()` / `.subcommand()`)
- `prodagent-policy`: Config validation — rejects non-monotonic effect defaults and no-op override entries at construction time
- `prodagent-policy`: Wrapper handling with floor effect, `escalates_privilege` enforcement, and fail-closed fallback for unresolved inner commands
- `prodagent-policy`: Compound command aggregation (strictest wins), escalation flag detection, redirection escalation
- `prodagent-policy`: 7 property-based tests including wrapper sampling from KB (caught wrapper list drift bug)
- `prodagent-policy`: 43 pipeline and engine integration tests

### Changed

- **BREAKING** `agent-command-knowledge`: `Effect` enum is now `ReadOnly | Mutating | Unknown` — `Destructive` variant removed. Commands previously classified as Destructive are now Mutating; the deny/allow decision belongs in the policy layer, not the knowledge layer.
- `agent-command-knowledge`: All 22 `effect = "destructive"` entries in `commands.toml` changed to `effect = "mutating"`

### Fixed

- `prodagent-policy`: Wrapper fail-open bypass — KB-only wrappers (doas, su, pkexec, watch, ltrace) that the parser couldn't strip now correctly apply floor effect and escalates_privilege instead of defaulting to Allow
- `prodagent-policy`: Bare wrappers (e.g. `sudo` with no arguments) fail-closed to Ask instead of Allow

## [0.6.0] - 2026-05-31

### Added

- **New crate**: `agent-command-knowledge` — command taxonomy and knowledge layer separating "what commands are" from "what to do about them"
- `agent-command-knowledge`: `classify()` function to look up a command's effect, subcommand, escalation flags, affected paths, and env gates from a `KnowledgeBase`
- `agent-command-knowledge`: Core types — `Effect` (ReadOnly < Mutating < Destructive < Unknown), `CommandKnowledge`, `SubcommandMap` with `longest_match`, `FlagSchema`, `EnvGate` (Grant/Require), `PathSpec`, `WrapperKnowledge`
- `agent-command-knowledge`: Embedded TOML defaults covering git (38 subcommands), cargo (32), gh (67 two-word patterns), kubectl (26), 50 simple commands, 14 wrappers
- `agent-command-knowledge`: `KnowledgeOverlay` and `KnowledgeBase::merge()` for user config extension with extend/replace/remove semantics
- `agent-command-knowledge`: `CommandOverlay` and `WrapperOverlay` with `Option` fields for partial merges — unspecified fields preserve base values
- `agent-command-knowledge`: Property-based tests for fail-closed effect invariants
- `agent-shell-parser`: 13 property-based integration tests (API totality, decomposition fidelity, wrapper transparency, fail-closed depth/size)

### Fixed

- `agent-command-knowledge`: `SubcommandMap` deserialization now validates `MAX_SUBCOMMAND_DEPTH` at parse time — previously derived `Deserialize` bypassed the depth check, allowing silently unreachable patterns
- `agent-command-knowledge`: Wrapper overlays no longer silently drop `escalates_privilege` when users only override `floor_effect` in TOML

## [0.5.1] - 2026-05-30

### Fixed

- `agent-shell-parser`: Tree-sitter `ERROR` nodes no longer produce spurious command segments. Previously, error recovery nodes (e.g. from `&;` sequences) hit the catch-all in `walk_ast` and became segments, causing false ASK escalations. The `has_parse_errors` flag already communicates parse failures to consumers.

## [0.5.0] - 2026-05-30

### Added

- `agent-shell-parser`: `ShellSegment::words` — pre-tokenized words from tree-sitter at parse time. Quotes stripped, substitutions preserved as single tokens.
- `agent-shell-parser`: Tree-sitter word extraction for `command`, `declaration_command`, `unset_command`, `variable_assignment`, and `test_command` nodes. Explicit shlex at 4 documented call sites (catch-all, redirected body, heredoc loose words).
- `agent-shell-parser`: Word extraction tests split into `shell_tests.rs`.

### Changed

- **BREAKING** `agent-shell-parser`: `ShellSegment` has a new public field `words: Vec<Word>`. Code that constructs `ShellSegment` directly must include the field.
- **BREAKING** `agent-shell-parser`: All public functions and types that previously used `String` for word/command representations now use `Word`. This includes `resolve_command`, `resolve_command_with` (`&[String]` → `&[Word]`), `strip_with_spec` (`Vec<String>` → `Vec<Word>`), `extract_cd_target` (`Option<&str>` → `Option<&Word>`), `extract_git_c_path` (`Option<String>` → `Option<&Word>`), `tokenize` (`Vec<String>` → `Vec<Word>`), `find_base_command` (`&[String]` → `&[Word]`), `parse_command` return type, and `ParsedCommand`/`CommandArg`/`ParsedFlag` field types.
- `agent-jj`: `guard.rs` and `path.rs` migrated from `tokenize(&seg.command)` to `seg.words`.

### Fixed

- `agent-shell-parser`: Redirect tokens (`>`, `>>`, etc.) excluded from word lists in `redirected_statement` nodes.

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
