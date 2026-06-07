# ADR-002: Recursive policy evaluation for command substitutions

## Status

Accepted (2026-06-07)

## Context

Inline env assignments can derive values from command substitutions:
`FOO=$(cmd) outer_cmd`. The original approach (PR #45 v1) marked these as
"statically unknown" and refused to let them satisfy env gates. This is
effectively the same as having no policy — it punts the decision to the user
via Ask.

The value of a command substitution is unknowable statically, but whether the
*operation that produces it* is sanctioned is decidable: classify the inner
command through policy.

## Decision

When the parser sees `FOO=$(inner_cmd)`, the inner command is already extracted
as a fully-parsed `ParsedPipeline` (the parser infrastructure existed). The
policy engine evaluates the inner pipeline recursively:

- **Inner command allowed** → the assignment is "safe." The variable is set
  with opaque text. `Set` gates fire, `Equals` gates don't match.
- **Inner command denied** → propagated via strictest-wins. The whole line
  is denied.
- **Bare variable expansion** (`FOO=$VAR`, `FOO=${VAR}`) → no inner command
  to evaluate. Stays Unknown. This is feature #2 (env value propagation),
  not yet implemented.

## Substitution visibility partition

The env semantics differ by position — this is a shell property, not a
prodagent design choice:

**Direct position** (gate on the outer command):

All three forms are equivalent — the outer command sees X:
```
X=v cmd              # inline prefix
env X=v cmd          # wrapper
export X=v && cmd    # shell mutation
```

**Substitution position** (gate on the inner command inside `$()`):

Inline and wrapper do NOT mutate the parent shell, so the subshell is blind:
```
X=v echo $(gated)        # $(gated) does NOT see X
env X=v echo $(gated)    # $(gated) does NOT see X
```

Export mutates the shell that the subshell forks from:
```
export X=v && echo $(gated)   # $(gated) DOES see X
```

This partition is {inline, wrapper} vs {export} in substitution position.

## Consequences

- `FOO=$(allowed_cmd) gated_cmd` with a `Set` gate on FOO now fires the gate
- `FOO=$(denied_cmd) anything` escalates to denial
- The system no longer punts substitution-derived assignments to Ask
- Bare `$VAR` expansion remains a known gap, tracked for future work
