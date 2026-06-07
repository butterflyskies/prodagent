# ADR-001: Environment propagation across pipeline segments

## Status

Accepted (2026-06-07)

## Context

prodagent's policy engine evaluates shell commands segment-by-segment within a
pipeline. Each segment previously rebuilt its `EnvSnapshot` from the process
environment, ignoring mutations from earlier segments. This created a fail-open
path:

```bash
# Caught — inline prefix lands in with_assignments, gate fires:
GIT_AUTHOR_NAME=AI-Agent git push

# Caught — wrapper chain threads env:
env GIT_AUTHOR_NAME=AI-Agent git push

# NOT caught — export mutation doesn't reach segment two:
export GIT_AUTHOR_NAME=AI-Agent && git push
```

For a Deny gate this is a fail-open path in a system that is fail-closed
everywhere else.

## Decision

Thread an accumulating `EnvSnapshot` left-to-right through `evaluate_pipeline`.
After evaluating each segment, fold its env mutations into the snapshot for the
next segment — but only across operators that preserve shell state:

| Operator | Propagates env? | Why |
|----------|----------------|-----|
| `&&`     | Yes | Same shell, sequential |
| `;`      | Yes | Same shell, sequential |
| `\|\|`   | No  | Conditional — left side may not have run |
| `\|`     | No  | Left side runs in a subshell |
| `\|&`    | No  | Left side runs in a subshell |
| `&`      | No  | Backgrounded in a subshell |

This mirrors the operator semantics already used by `effective_cwd`
propagation.

## Env mutations that propagate

- `export FOO=bar` — declaration command, standalone
- `declare FOO=bar` / `readonly` / `local` / `typeset` — same
- `FOO=bar` — bare assignment with no command (standalone)
- `FOO=bar cmd` — does NOT propagate; scoped to `cmd`

## Consequences

- `export X=v && gated_cmd` now fires gates on X, closing the fail-open path
- Substitution evaluation inherits the enclosing scope's snapshot
- The three-way direct-position equivalence holds:
  `X=v cmd` ≡ `env X=v cmd` ≡ `export X=v && cmd` for any gate on X
