# prodagent

Agent-agnostic productivity hooks for jj-colocated repositories.

## What's in here

| Crate | Purpose |
|---|---|
| `agent-jj-workspace` | **WorktreeCreate hook** — spins up jj workspaces for agent session isolation |
| `agent-jj-cleanup` | **WorktreeRemove hook** — forgets jj workspaces and removes directories on teardown |
| `agent-jj-guard` | **PreToolUse hook** — blocks destructive git commands in jj repos, suggests jj equivalents |
| `agent-shell-parser` | Shared lib — JSON input parsing, jj detection, shell tokenization, guard rules |

## Requirements

- [jj-cli](https://github.com/jj-vcs/jj) >= 0.40.0
- Rust toolchain (for building from source)

## Install

```bash
just install
```

Or individually:

```bash
cargo install --path crates/agent-jj-workspace
cargo install --path crates/agent-jj-cleanup
cargo install --path crates/agent-jj-guard
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
          { "type": "command", "command": "agent-jj-guard" }
        ]
      }
    ],
    "WorktreeCreate": [
      {
        "hooks": [
          { "type": "command", "command": "agent-jj-workspace" }
        ]
      }
    ],
    "WorktreeRemove": [
      {
        "hooks": [
          { "type": "command", "command": "agent-jj-cleanup" }
        ]
      }
    ]
  }
}
```

## License

MIT OR Apache-2.0
