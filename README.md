# prodagent

Productionizing AI coding agents — parsing, command knowledge, policy enforcement, and hooks for safe agent tool execution.

## Overview

prodagent is a Rust workspace that gates AI coding agent tool use through a layered security pipeline. A shell command enters as raw text, gets parsed into a structured AST, classified by a knowledge base of known commands, and evaluated against a configurable policy engine that returns allow/ask/deny decisions. The entire stack is fail-closed: unknown commands require confirmation, compound commands take the strictest segment, and parse errors never produce an allow.

The primary binary is `tool-gate`, a Claude Code `PreToolUse` hook that evaluates Bash commands through this pipeline and responds with permission decisions.

## Crates

| Crate | Type | Purpose |
|---|---|---|
| `prodagent-types` | lib | Shared foundation types — `Word`, `WrapperSpec`, `SubcommandPattern`, compiled default configs |
| `agent-shell-parser` | lib | Tree-sitter-bash parsing — shell tokenization, compound commands, substitutions, wrapper resolution |
| `agent-command-knowledge` | lib | Command taxonomy — effect classification, subcommand maps, flag schemas, env gates, path specs |
| `agent-policy` | lib | Policy engine — maps classified commands to Allow/Ask/Deny decisions with configurable rules |
| `prodagent-config` | lib | Three-tier config cascade (defaults / user / project) via figment with monotonicity enforcement |
| `prodagent-tool-gate` | **bin** | `PreToolUse` hook binary — the main entry point for gating agent Bash commands |
| `agent-jj` | **bin** | Claude Code hooks for jj-colocated repos — git guard, workspace creation, cleanup |
| `prodagent-proofs` | lib | Kani formal verification harnesses — 23 proofs for policy security invariants |

### Dependency graph

```
prodagent-types
    |
agent-shell-parser
    |
agent-command-knowledge
    |
agent-policy ------------- prodagent-proofs
    |
prodagent-config
    |
prodagent-tool-gate

agent-jj (depends on agent-shell-parser only)
```

## Architecture

Five-layer separation:

1. **Types** (`prodagent-types`) — Foundational types shared across the workspace. `Word` tokens with domain-specific classification, `WrapperSpec` definitions for transparent command wrappers (sudo, env, nohup, etc.), `SubcommandPattern` validated newtypes, and compiled default wrapper specs. Uses `camino::Utf8PathBuf` for path types throughout.

2. **Parsing** (`agent-shell-parser`) — Tokenize shell commands via tree-sitter-bash AST walks into structured segments. Handles compound commands (`&&`, `||`, `;`, `|`), command substitutions (`$(...)` vs `$((...))`), wrapper chains (`sudo env git commit`), redirections, and environment assignments with substitution tracking. Pure AST-based — no byte-level scanning.

3. **Knowledge** (`agent-command-knowledge`) — Classify commands by effect (`ReadOnly < Mutating < Unknown`). Embedded defaults cover git, cargo, gh, kubectl, and 50+ common commands with subcommand-level granularity, flag schemas, affected path specs, and environment gates. User config extends/overrides via `KnowledgeOverlay`.

4. **Policy** (`agent-policy`) — The security-critical decision layer. Maps classified command effects to `Allow < Ask < Deny` decisions using configurable rules. Handles wrapper escalation, compound command aggregation (strictest wins), escalation flags, redirect detection, env gate evaluation with opaque value handling, and affected path extraction. Configurable opaque env ceiling controls the decision for unknown environment values (default: Ask).

5. **Configuration** (`prodagent-config`) — Three-tier cascade via figment:
   - **Defaults** — compiled into the binary
   - **User** — `~/.config/prodagent/config.toml`
   - **Project** — `.prodagent/config.toml` (per-repo)

   A monotonicity invariant ensures project config can only tighten policy (escalate toward Deny), never weaken it. Validated at load time.

The `Effect` enum is ordered fail-closed: `Unknown` is the most restrictive, so aggregation via `max` never underestimates risk.

## Formal verification

The `prodagent-proofs` crate contains 23 [Kani](https://model-checking.github.io/kani/) proof harnesses verifying security invariants:

- **Policy monotonicity** — compound command evaluation can only escalate, never relax
- **Parse error fail-closed** — parser errors never produce an Allow decision
- **Opaque env ceiling** — unknown environment values respect the configured ceiling
- **Decision ordering** — reflexivity, antisymmetry, transitivity, and security ordering of the decision lattice
- **Deny absorption** — Deny survives all aggregation operations

## Requirements

- Rust toolchain >= 1.93
- [cargo-nextest](https://nexte.st/) for running tests
- [jj-cli](https://github.com/jj-vcs/jj) >= 0.40.0 (for `agent-jj` only)
- [Kani](https://model-checking.github.io/kani/) (for proof harnesses only)

## Install

### tool-gate (recommended)

```bash
cargo install --path crates/prodagent-tool-gate
```

### agent-jj

```bash
cargo install --path crates/agent-jj
```

### Both

```bash
just install
```

## Configuration

### tool-gate

Create `~/.config/prodagent/config.toml` to customize policy:

```toml
[policy.defaults]
read_only = "allow"    # default
mutating = "ask"       # default
unknown = "ask"        # default
```

Per-repo overrides go in `.prodagent/config.toml` (can only tighten, not relax).

Use `tool-gate --dump-config` to inspect the merged three-tier configuration. Use `tool-gate --dump-ast <command>` to see how a command is parsed.

### agent-jj

No configuration needed — it detects jj-colocated repos automatically.

## Hook registration (Claude Code)

### tool-gate

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "tool-gate" }
        ]
      }
    ]
  }
}
```

Optional flags: `--escalate-deny` converts all Deny decisions to Ask (debugging escape hatch).

### agent-jj

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "agent-jj guard" }
        ]
      }
    ],
    "WorktreeCreate": [
      {
        "hooks": [
          { "type": "command", "command": "agent-jj workspace" }
        ]
      }
    ],
    "WorktreeRemove": [
      {
        "hooks": [
          { "type": "command", "command": "agent-jj cleanup" }
        ]
      }
    ]
  }
}
```

## Development

```bash
just check     # fmt + clippy + nextest
just test      # nextest only
just fmt       # format
```

Tests use [rstest](https://docs.rs/rstest/) for parameterized cases and [proptest](https://docs.rs/proptest/) for property-based testing.

## License

MIT OR Apache-2.0
