# prodagent

Productionizing AI coding agents — parsing, command knowledge, and hooks for safe agent tool execution.

## Crates

| Crate | Purpose |
|---|---|
| `agent-shell-parser` | Tree-sitter-bash parsing substrate — shell tokenization, wrapper resolution, CWD tracking |
| `agent-command-knowledge` | Command taxonomy and knowledge layer — what commands *are* (effect, subcommands, flags, paths, env gates), not what to *do* about them |
| `agent-jj` | Claude Code hooks for jj-colocated repos — git guard, workspace creation, cleanup |

## Architecture

Three-layer separation:

1. **Parsing** (`agent-shell-parser`) — Tokenize shell commands into structured segments. Handles compound commands (`&&`, `||`, `;`, `|`), command substitutions, wrapper chains (`sudo env git commit`), redirections.

2. **Knowledge** (`agent-command-knowledge`) — Classify commands by effect (`ReadOnly < Mutating < Destructive < Unknown`). Embedded TOML defaults cover git (38 subcommands), cargo (32), gh (67 patterns), kubectl (26), 50+ simple commands, 14 wrappers. User config extends/overrides via `KnowledgeOverlay`.

3. **Policy** (consumers like `agent-jj`, `cc-toolgate`) — Decide what to do based on classification. The knowledge layer provides the facts; policy layers make the decisions.

The `Effect` enum is ordered fail-closed: `Unknown` is the most restrictive, so aggregation via `max` never underestimates risk.

## Requirements

- Rust toolchain >= 1.88
- [jj-cli](https://github.com/jj-vcs/jj) >= 0.40.0 (for agent-jj)

## Install

```bash
just install
```

Or directly:

```bash
cargo install --path crates/agent-jj
```

## Hook registration (Claude Code)

Add to `~/.claude/settings.json`:

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

## License

MIT OR Apache-2.0
