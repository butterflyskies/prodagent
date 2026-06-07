# Spec: Environment gate semantics

## Overview

Environment gates are conditions on environment variables that modify a
command's policy decision. This spec defines how env values are resolved
across different shell constructs and what invariants the proptest suite
enforces.

## Value resolution

| Construct | Outer command sees X? | Substitution sees X? | Propagates to next segment? |
|-----------|----------------------|---------------------|---------------------------|
| `X=v cmd` | Yes (inline prefix) | No (parent shell unchanged) | No (scoped to cmd) |
| `env X=v cmd` | Yes (wrapper) | No (parent shell unchanged) | No (wrapper scope) |
| `export X=v` | N/A (no command) | N/A | Yes (shell mutation) |
| `export X=v && cmd` | Yes (propagated) | Yes (shell mutated before fork) | Yes |
| `export X=v ; cmd` | Yes (propagated) | Yes | Yes |
| `export X=v \| cmd` | No (subshell) | No | No |
| `export X=v & cmd` | No (background) | No | No |
| `FOO=$(cmd)` | Set if inner allowed | Inner evaluated recursively | Only if standalone |
| `FOO=$VAR` | Unknown | N/A | Unknown propagated |

## Gate evaluation on unknown/opaque values

| Value state | `Set` gate | `Unset` gate | `Equals(v)` gate | `NotEquals(v)` gate |
|-------------|-----------|-------------|-----------------|-------------------|
| Known literal | fires if set | fires if unset | fires if matches | fires if differs |
| Opaque (allowed substitution) | fires (is set) | does not fire | does not fire | does not fire |
| Unknown (denied/variable expansion) | does not fire | does not fire | does not fire | does not fire |
| Unset | does not fire | fires | does not fire | fires |

## Metamorphic properties (proptests)

### Direct-position equivalence

For any gate on variable X with value V applied to command C:

```
decision(X=V C) == decision(env X=V C) == decision(export X=V && C)
```

Generator: `(var_name, value, gate_type, command)` → three renderings.

### Substitution-position partition

For any gate on variable X applied to an inner command inside `$()`:

```
decision(X=V echo $(gated)) == decision(env X=V echo $(gated))
```
Gate does NOT fire in either (subshell blind to X).

```
decision(export X=V && echo $(gated))
```
Gate fires (subshell inherits exported X).

### Declaration command equivalence

All declaration keywords propagate identically:

```
decision(export X=V && C) == decision(declare X=V && C)
  == decision(readonly X=V && C) == decision(local X=V && C)
  == decision(typeset X=V && C)
```

### Non-propagation across pipes and background

```
decision(export X=V | C)   → gate does NOT fire on C
decision(export X=V & C)   → gate does NOT fire on C
decision(export X=V || C)  → gate does NOT fire on C
```

## Future work

- **Env value propagation** (`$VAR` resolution): trace variable values
  through assignment chains to resolve `FOO=$BAR` when BAR is statically
  known. Currently classified as Unknown.
- **Arithmetic expansion**: `$(( expr ))` is not a command substitution;
  it's a value computation. Currently caught by the `$(` prefix check
  and classified as CommandSubstitution. Harmless (conservative) but
  imprecise.
