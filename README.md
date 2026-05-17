# prodagent

Agent-agnostic productivity hooks for jj-colocated repositories.

When an AI coding agent works in a jj repo, it'll instinctively reach for `git commit`, `git push`, etc. These hooks intercept that, block the git command, and tell the agent what jj command to use instead. They also handle workspace isolation so parallel agent sessions don't step on each other.

## What's in here

| Crate | Purpose |
|---|---|
| `agent-jj-guard` | **PreToolUse hook** — intercepts shell commands, parses them with tree-sitter-bash, blocks git in jj repos with per-command jj suggestions |
| `agent-jj-workspace` | **WorktreeCreate hook** — spins up jj workspaces for agent session isolation |
| `agent-jj-cleanup` | **WorktreeRemove hook** — forgets jj workspaces and removes directories on teardown |
| `agent-shell-parser` | Shared library — tree-sitter-bash parsing, config-driven wrapper resolution, CWD tracking, hook I/O types |

The guard handles compound commands (`&&`, `||`, `;`, `|`), command substitutions (`$()`), wrapper chains (`sudo env time git commit`), and various bypass attempts. It uses a config-driven approach — all command knowledge lives in `config/commands.json`, not hardcoded.

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
