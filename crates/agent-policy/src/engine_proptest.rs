//! Property-based tests for the policy engine.
//!
//! Discipline (carried over from the parser/knowledge proptests): the
//! generator is the oracle. No property validates `evaluate` by re-running
//! `evaluate`; expected values come from the decision the generator *placed*
//! in a config slot, or from an ordering relation that holds independently of
//! the engine, or from the security spec ("unknown ⇒ at least Ask").

use super::*;
use crate::config::{CommandPolicy, DetailedCommandPolicy, EffectDefaults, PolicyConfig};
use crate::decision::PolicyDecision;
use agent_command_knowledge::{default_knowledge_base, CommandInfo, Effect};
use proptest::prelude::*;
use std::collections::HashMap;

// ── helpers ──────────────────────────────────────────────────────────────────

fn cfg(defaults: EffectDefaults, commands: HashMap<String, CommandPolicy>) -> PolicyConfig {
    PolicyConfig {
        defaults,
        commands,
        ..PolicyConfig::default()
    }
}

/// CommandInfo with a chosen effect and subcommand; all wrapper/path/gate
/// fields defaulted. `wrapper: None` is correct here — the low-level
/// `evaluate` never looks at the wrapper field (that's the high-level path).
fn info(effect: Effect, subcommand: Option<&str>) -> CommandInfo {
    CommandInfo {
        effect,
        subcommand: subcommand.map(|s| s.to_string()),
        ..CommandInfo::unknown()
    }
}

fn rank(d: PolicyDecision) -> u8 {
    match d {
        PolicyDecision::Allow => 0,
        PolicyDecision::Ask => 1,
        PolicyDecision::Deny => 2,
    }
}

fn unrank(r: u8) -> PolicyDecision {
    match r {
        0 => PolicyDecision::Allow,
        1 => PolicyDecision::Ask,
        _ => PolicyDecision::Deny,
    }
}

// ── strategies ───────────────────────────────────────────────────────────────

fn arb_policy_decision() -> impl Strategy<Value = PolicyDecision> {
    prop_oneof![
        Just(PolicyDecision::Allow),
        Just(PolicyDecision::Ask),
        Just(PolicyDecision::Deny),
    ]
}

fn arb_effect() -> impl Strategy<Value = Effect> {
    prop_oneof![
        Just(Effect::ReadOnly),
        Just(Effect::Mutating),
        Just(Effect::Unknown),
    ]
}

fn arb_word() -> impl Strategy<Value = String> {
    "[a-z]{1,8}".prop_map(|s| s.to_string())
}

/// CommandInfo varying the effect *and* the fields `evaluate` is supposed to
/// ignore (escalation, subcommand), so totality is exercised against them.
fn arb_command_info() -> impl Strategy<Value = CommandInfo> {
    (arb_effect(), any::<bool>(), prop::option::of(arb_word())).prop_map(
        |(effect, escalation, subcommand)| CommandInfo {
            effect,
            subcommand,
            has_escalation_flags: escalation,
            ..CommandInfo::unknown()
        },
    )
}

/// The three roles in the precedence test must hold pairwise-distinct
/// decisions — distinctness is what gives the property its mutation-catching
/// power. With three decisions, that's a permutation of (Allow, Ask, Deny).
fn arb_distinct_triple() -> impl Strategy<Value = (PolicyDecision, PolicyDecision, PolicyDecision)>
{
    use PolicyDecision::{Allow, Ask, Deny};
    prop::sample::select(vec![
        (Allow, Ask, Deny),
        (Allow, Deny, Ask),
        (Ask, Allow, Deny),
        (Ask, Deny, Allow),
        (Deny, Allow, Ask),
        (Deny, Ask, Allow),
    ])
}

/// An ordered pair of distinct decisions (base vs. refined subcommand).
fn arb_distinct_pair() -> impl Strategy<Value = (PolicyDecision, PolicyDecision)> {
    use PolicyDecision::{Allow, Ask, Deny};
    prop::sample::select(vec![
        (Allow, Ask),
        (Allow, Deny),
        (Ask, Allow),
        (Ask, Deny),
        (Deny, Allow),
        (Deny, Ask),
    ])
}

/// A monotonic base `EffectDefaults`, a pointwise-≥ tightening that raises
/// exactly one field while staying monotonic, and the effect class whose field
/// was raised. Both configs are valid by construction (so `new` won't reject
/// them). The single-field tightening is the discriminating part: it lets the
/// locality assertion catch a `effect_default` that reads the wrong field.
fn arb_tighten_case() -> impl Strategy<Value = (EffectDefaults, EffectDefaults, Effect)> {
    (
        arb_policy_decision(),
        arb_policy_decision(),
        arb_policy_decision(),
        0u8..3,
        0u8..3,
    )
        .prop_map(|(d0, d1, d2, field, raw)| {
            let mut s = [rank(d0), rank(d1), rank(d2)];
            s.sort_unstable();
            let (a, b, c) = (s[0], s[1], s[2]);
            // Range that keeps the triple sorted after raising `field`.
            let (lo, hi) = match field {
                0 => (a, b),
                1 => (b, c),
                _ => (c, 2),
            };
            let newv = raw.clamp(lo, hi); // ≥ old field value, ≤ neighbor
            let mut t = [a, b, c];
            t[field as usize] = newv;

            let base = EffectDefaults {
                read_only: unrank(a),
                mutating: unrank(b),
                unknown: unrank(c),
            };
            let tight = EffectDefaults {
                read_only: unrank(t[0]),
                mutating: unrank(t[1]),
                unknown: unrank(t[2]),
            };
            let changed = match field {
                0 => Effect::ReadOnly,
                1 => Effect::Mutating,
                _ => Effect::Unknown,
            };
            (base, tight, changed)
        })
}

/// Wrapper names drawn from the *real* default KB — not a hardcoded subset.
/// This is the whole point: sampling from `kb.wrappers` is what exposes the
/// wrappers the parser can't strip.
fn arb_kb_wrapper() -> impl Strategy<Value = String> {
    let names: Vec<String> = default_knowledge_base().wrappers.keys().cloned().collect();
    prop::sample::select(names)
}

// ── properties ───────────────────────────────────────────────────────────────

proptest! {
    /// Fail-closed tripwire on the built-in defaults. The analog of
    /// `new_command_always_defaults_to_unknown` in the knowledge crate:
    /// a guard against a future "friendlier defaults" regression. Uses the
    /// low-level `evaluate`, which by contract ignores escalation — so
    /// ReadOnly stays exactly Allow even when the random info sets escalation.
    #[test]
    fn default_config_is_fail_closed(i in arb_command_info()) {
        let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
        let d = engine.evaluate("not-in-any-override", &i);
        match i.effect {
            Effect::ReadOnly => prop_assert_eq!(d, PolicyDecision::Allow),
            Effect::Mutating | Effect::Unknown =>
                prop_assert!(d >= PolicyDecision::Ask, "{:?} -> {:?}", i.effect, d),
        }
    }

    /// A flat per-command override is honored exactly, for any effect and any
    /// subcommand. Oracle = the decision the generator placed in the slot.
    /// Distinctness over (effect × decision) catches "override ignored, fell
    /// through to effect default".
    #[test]
    fn flat_override_honored_exactly(
        name in "[a-z]{1,8}",
        d in arb_policy_decision(),
        i in arb_command_info(),
    ) {
        let mut cmds = HashMap::new();
        cmds.insert(name.clone(), CommandPolicy::Flat(d));
        let engine = PolicyEngine::new(cfg(EffectDefaults::default(), cmds)).unwrap();
        prop_assert_eq!(engine.evaluate(&name, &i), d);
    }

    /// Precedence: subcommand override beats base override beats effect default.
    /// The three roles hold pairwise-distinct decisions, so each assertion can
    /// only pass if the *right* slot was consulted. Effect is pinned to Unknown
    /// and `unknown` default is set to the effect-default role, so all three
    /// oracle values are generator-placed.
    #[test]
    fn detailed_precedence(
        triple in arb_distinct_triple(),
        other_sub in "[a-z]{3,6}",
    ) {
        let (d_sub, d_base, d_eff) = triple;
        prop_assume!(other_sub != "sub");

        // Monotonic: Allow ≤ Allow ≤ d_eff for every d_eff.
        let defaults = EffectDefaults {
            read_only: PolicyDecision::Allow,
            mutating: PolicyDecision::Allow,
            unknown: d_eff,
        };

        let mut subs = HashMap::new();
        subs.insert("sub".to_string(), d_sub);
        let mut cmds = HashMap::new();
        cmds.insert(
            "c".to_string(),
            CommandPolicy::Detailed(DetailedCommandPolicy {
                base: Some(d_base),
                subcommands: subs,
            }),
        );
        let engine = PolicyEngine::new(cfg(defaults, cmds)).unwrap();

        // matched subcommand → subcommand override
        prop_assert_eq!(engine.evaluate("c", &info(Effect::Unknown, Some("sub"))), d_sub);
        // unmatched subcommand → base override
        prop_assert_eq!(
            engine.evaluate("c", &info(Effect::Unknown, Some(other_sub.as_str()))),
            d_base
        );
        // no subcommand → base override
        prop_assert_eq!(engine.evaluate("c", &info(Effect::Unknown, None)), d_base);
        // command not in overrides → effect default
        prop_assert_eq!(engine.evaluate("z", &info(Effect::Unknown, Some("sub"))), d_eff);
    }

    /// Specificity locality (metamorphic, two-config): adding a more-specific
    /// subcommand override changes the decision only for the matching
    /// (command, subcommand). Non-matching subcommands, the no-subcommand case,
    /// and other commands are untouched. Oracle = equality across the two
    /// configs on the non-matching inputs.
    #[test]
    fn specificity_is_local(
        pair in arb_distinct_pair(),
        other_sub in "[a-z]{3,6}",
    ) {
        let (d_base, d_sub) = pair;
        prop_assume!(other_sub != "sub");

        let base_cmd = || {
            let mut cmds = HashMap::new();
            cmds.insert(
                "c".to_string(),
                CommandPolicy::Detailed(DetailedCommandPolicy {
                    base: Some(d_base),
                    subcommands: HashMap::new(),
                }),
            );
            cmds
        };
        let e1 = PolicyEngine::new(cfg(EffectDefaults::default(), base_cmd())).unwrap();

        let mut subs = HashMap::new();
        subs.insert("sub".to_string(), d_sub);
        let mut cmds2 = HashMap::new();
        cmds2.insert(
            "c".to_string(),
            CommandPolicy::Detailed(DetailedCommandPolicy {
                base: Some(d_base),
                subcommands: subs,
            }),
        );
        let e2 = PolicyEngine::new(cfg(EffectDefaults::default(), cmds2)).unwrap();

        let matched = info(Effect::Unknown, Some("sub"));
        let unmatched = info(Effect::Unknown, Some(other_sub.as_str()));
        let none = info(Effect::Unknown, None);
        let elsewhere = info(Effect::Unknown, Some("sub"));

        // the refinement takes effect only on the matching subcommand
        prop_assert_eq!(e2.evaluate("c", &matched), d_sub);
        // everything else is identical between the two configs
        prop_assert_eq!(e1.evaluate("c", &unmatched), e2.evaluate("c", &unmatched));
        prop_assert_eq!(e1.evaluate("c", &none), e2.evaluate("c", &none));
        prop_assert_eq!(e1.evaluate("z", &elsewhere), e2.evaluate("z", &elsewhere));
    }

    /// Tightening exactly one effect default raises that effect class's
    /// decision (≥) and leaves the other two classes unchanged. The "unchanged"
    /// clause is the discriminating one: it fails if `effect_default` reads the
    /// wrong field (e.g. a Mutating/ReadOnly field swap), which a pure
    /// monotonicity check would miss.
    #[test]
    fn tightening_one_default_is_local(case in arb_tighten_case()) {
        let (base, tight, changed) = case;
        let e_base = PolicyEngine::new(cfg(base, HashMap::new())).unwrap();
        let e_tight = PolicyEngine::new(cfg(tight, HashMap::new())).unwrap();

        for eff in [Effect::ReadOnly, Effect::Mutating, Effect::Unknown] {
            let i = info(eff, None);
            let before = e_base.evaluate("x", &i);
            let after = e_tight.evaluate("x", &i);
            if eff == changed {
                prop_assert!(
                    after >= before,
                    "tightening {:?} loosened its own class: {:?} -> {:?}",
                    eff, before, after
                );
            } else {
                prop_assert_eq!(
                    after, before,
                    "tightening {:?} changed an unrelated class {:?}", changed, eff
                );
            }
        }
    }

    /// Integration over the *real* classify → evaluate chain: an unknown
    /// command (random alpha, asserted absent from the default KB) must
    /// fail closed to at least Ask. The ≥ Ask bound is the security spec, not
    /// a re-run of either function. Catches a break anywhere in the path —
    /// Effect::Unknown default flipping, or classify returning non-Unknown for
    /// unknown input.
    #[test]
    fn unknown_command_fails_closed(
        base in "[a-z]{8,16}",
        args in prop::collection::vec("[a-z]{1,6}", 0..3),
    ) {
        let kb = default_knowledge_base();
        prop_assume!(!kb.commands.contains_key(base.as_str()));
        prop_assume!(!kb.wrappers.contains_key(base.as_str()));

        let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
        let mut parts = vec![base.clone()];
        parts.extend(args);
        let cmd = parts.join(" ");

        let result = engine.evaluate_command(&cmd, kb);
        prop_assert!(
            result.decision >= PolicyDecision::Ask,
            "unknown command `{}` should be ≥ Ask, got {:?}", cmd, result
        );
    }

    /// Running a mutating command under ANY wrapper the KB recognizes must not
    /// be Allow. Wrapping `rm` can only raise the decision (rm is Mutating,
    /// independent of the engine), so the floor is Ask. The wrapper name is
    /// sampled from the real `kb.wrappers`.
    #[test]
    fn wrapper_over_mutating_never_allows(w in arb_kb_wrapper()) {
        let kb = default_knowledge_base();
        let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
        let cmd = format!("{w} rm somefile");

        let result = engine.evaluate_command(&cmd, kb);
        prop_assert!(
            result.decision >= PolicyDecision::Ask,
            "wrapper `{}` over a mutating command must not be Allow; got {:?}",
            w, result
        );
    }

    /// derive_wrapper_specs must never produce a spec whose name collides with
    /// a default wrapper. Sampled from the real KB so any future KB addition
    /// that collides with a newly-added default is caught.
    ///
    /// The assertions are w-dependent only — the sampled wrapper determines
    /// which branch is tested. No exhaustive loop over derived specs.
    #[test]
    fn derive_wrapper_specs_no_overlap_with_defaults(w in arb_kb_wrapper()) {
        let kb = default_knowledge_base();
        let derived = super::derive_wrapper_specs(kb);
        let default_config = parse::default_command_config();

        // If the sampled wrapper IS in defaults, it must NOT be in derived
        let is_default = default_config.wrappers.iter().any(|d| d.name == w);
        let is_derived = derived.iter().any(|s| s.name == w);
        if is_default {
            prop_assert!(
                !is_derived,
                "wrapper '{}' is in defaults but also in derived specs", w
            );
        }
        // If the sampled wrapper is NOT in defaults, it MUST be in derived
        if !is_default {
            prop_assert!(
                is_derived,
                "wrapper '{}' is not in defaults and not in derived specs", w
            );
        }
    }
}

// ── env gate properties ─────────────────────────────────────────────────────

use crate::env_snapshot::{EnvSnapshot, EnvValueOwned};
use agent_command_knowledge::{EnvCondition, EnvGate, EnvGateAction};

fn arb_env_gate_decision() -> impl Strategy<Value = EnvGateAction> {
    prop_oneof![
        Just(EnvGateAction::Allow),
        Just(EnvGateAction::Ask),
        Just(EnvGateAction::Deny),
    ]
}

fn arb_env_condition() -> impl Strategy<Value = EnvCondition> {
    prop_oneof![
        "[a-z]{1,6}".prop_map(EnvCondition::Equals),
        "[a-z]{1,6}".prop_map(EnvCondition::NotEquals),
        Just(EnvCondition::Set),
        Just(EnvCondition::Unset),
    ]
}

fn arb_env_gate() -> impl Strategy<Value = EnvGate> {
    ("[A-Z]{1,4}", arb_env_condition(), arb_env_gate_decision()).prop_map(
        |(var, condition, decision)| EnvGate {
            var,
            condition,
            decision,
        },
    )
}

proptest! {
    /// Strictest-wins monotonicity: adding a gate can only maintain or increase
    /// strictness. Never relaxes below the strictest gate.
    ///
    /// Limitation: when two gates target the same variable with conflicting
    /// conditions (e.g. Set and Unset on "FOO"), the env snapshot can only
    /// satisfy one at a time. The property still holds because the env is built
    /// from the last condition seen per variable, so one gate fires and the
    /// other doesn't — but this means same-var conflicts don't exercise the
    /// "both gates fire" path. A richer generator that avoids same-var
    /// conflicts would strengthen coverage.
    #[test]
    fn env_gate_strictest_wins_monotonicity(
        gates in prop::collection::vec(arb_env_gate(), 0..6),
        extra_gate in arb_env_gate(),
    ) {
        // Build env from gate conditions so each gate actually fires.
        // Equals conditions need the matching value; Set needs any value;
        // Unset needs the var absent (skip it). NotEquals needs a different value.
        let mut env = EnvSnapshot::clean();
        for gate in gates.iter().chain(std::iter::once(&extra_gate)) {
            match &gate.condition {
                EnvCondition::Equals(v) => { env.set(&gate.var, v); }
                EnvCondition::NotEquals(_) => { env.set(&gate.var, "__ne_trigger__"); }
                EnvCondition::Set => { env.set(&gate.var, "present"); }
                EnvCondition::Unset => { /* leave absent so it matches */ }
            }
        }

        let result_without = super::apply_env_gates(&gates, &env, PolicyDecision::Ask);
        let mut extended = gates.clone();
        extended.push(extra_gate);
        let result_with = super::apply_env_gates(&extended, &env, PolicyDecision::Ask);

        match (result_without, result_with) {
            (None, _) => {} // adding a gate from nothing is always fine
            (Some(d1), Some(d2)) => {
                prop_assert!(d2 >= d1,
                    "adding a gate should not relax: {:?} -> {:?}", d1, d2);
            }
            (Some(_), None) => {
                prop_assert!(false, "adding a gate should not remove a decision");
            }
        }
    }

    /// Empty gates = no effect: command with no env_gates produces None
    /// regardless of env state.
    #[test]
    fn empty_gates_no_effect(
        var in "[A-Z]{1,4}",
        value in "[a-z]{1,6}",
    ) {
        let mut env = EnvSnapshot::clean();
        env.set(&var, &value);
        let result = super::apply_env_gates(&[], &env, PolicyDecision::Ask);
        prop_assert!(result.is_none(), "empty gates should produce None");
    }

    /// Deny short-circuit: any gate evaluating to Deny produces Deny regardless
    /// of other gates.
    #[test]
    fn deny_short_circuit(
        gates in prop::collection::vec(arb_env_gate(), 0..5),
        var in "[A-Z]{1,4}",
        value in "[a-z]{1,6}",
    ) {
        // Use a unique var name for the deny gate to avoid collision with
        // generated gates that might overwrite the value
        let deny_var = format!("DENY_{var}");
        let deny_gate = EnvGate {
            var: deny_var.clone(),
            condition: EnvCondition::Equals(value.clone()),
            decision: EnvGateAction::Deny,
        };

        let mut env = EnvSnapshot::clean();
        // Set all other gate vars
        for gate in &gates {
            env.set(&gate.var, "testvalue");
        }
        // Set the deny gate's var LAST to ensure it matches
        env.set(&deny_var, &value);

        let mut all_gates = gates;
        all_gates.push(deny_gate);
        let result = super::apply_env_gates(&all_gates, &env, PolicyDecision::Ask);
        prop_assert_eq!(result, Some(PolicyDecision::Deny),
            "a matching Deny gate should always produce Deny");
    }

    /// Gate order independence: permuting the gates list produces the same
    /// final decision.
    #[test]
    fn gate_order_independence(
        gates in prop::collection::vec(arb_env_gate(), 1..6),
    ) {
        // Build env from gate conditions so each condition type fires.
        let mut env = EnvSnapshot::clean();
        for gate in &gates {
            match &gate.condition {
                EnvCondition::Equals(v) => { env.set(&gate.var, v); }
                EnvCondition::NotEquals(_) => { env.set(&gate.var, "__ne_trigger__"); }
                EnvCondition::Set => { env.set(&gate.var, "present"); }
                EnvCondition::Unset => { /* leave absent so it matches */ }
            }
        }

        let result1 = super::apply_env_gates(&gates, &env, PolicyDecision::Ask);

        let mut reversed = gates.clone();
        reversed.reverse();
        let result2 = super::apply_env_gates(&reversed, &env, PolicyDecision::Ask);

        prop_assert_eq!(result1, result2,
            "gate order should not affect the result");
    }

    /// Condition match symmetry: for Equals/NotEquals with a known value,
    /// exactly one of (matches, doesn't match) is true.
    #[test]
    fn condition_match_symmetry(
        _var in "[A-Z]{1,4}",
        gate_value in "[a-z]{1,6}",
        env_value in "[a-z]{1,6}",
    ) {
        let equals = EnvCondition::Equals(gate_value.clone());
        let not_equals = EnvCondition::NotEquals(gate_value.clone());
        let env_val = Some(EnvValueOwned::Known(env_value.clone()));

        let eq_matches = super::evaluate_condition(&equals, env_val.as_ref());
        let neq_matches = super::evaluate_condition(&not_equals, env_val.as_ref());

        // Exactly one should match (they're complementary on known values)
        prop_assert!(eq_matches != neq_matches,
            "Equals and NotEquals should be complementary for known values: \
             gate_value={}, env_value={}, eq={}, neq={}",
            gate_value, env_value, eq_matches, neq_matches);
    }

    /// Set and Unset are complementary for known and absent values.
    #[test]
    fn set_unset_complementary(
        has_value in any::<bool>(),
        value in "[a-z]{1,6}",
    ) {
        let env_val = if has_value {
            Some(EnvValueOwned::Known(value))
        } else {
            None
        };

        let set_matches = super::evaluate_condition(&EnvCondition::Set, env_val.as_ref());
        let unset_matches = super::evaluate_condition(&EnvCondition::Unset, env_val.as_ref());

        prop_assert!(set_matches != unset_matches,
            "Set and Unset should be complementary: set={}, unset={}",
            set_matches, unset_matches);
    }

    /// Snapshot layering: unsets > overrides > base. A var in unsets is always
    /// None even if in overrides.
    #[test]
    fn snapshot_unset_wins_over_override(
        var in "[A-Z]{1,4}",
        value in "[a-z]{1,6}",
    ) {
        let mut snap = EnvSnapshot::from_process_env();
        snap.set(&var, &value);
        snap.unset(&var);
        prop_assert!(snap.get_value(&var).is_none(),
            "unset should win over override");
    }

    /// env -i isolation: clean-env base makes process env invisible.
    #[test]
    fn clean_env_isolation(
        var in "[A-Z]{1,4}",
    ) {
        let snap = EnvSnapshot::clean();
        // Unless the var is explicitly overridden, it should be None
        prop_assert!(snap.get_value(&var).is_none(),
            "clean env should not resolve vars");
    }
}

// ── Substitution-derived env values ──────────────────────────────────────────

/// An assignment value derived from a command substitution (`$(cmd)` or backticks).
fn arb_command_substitution_value() -> impl Strategy<Value = String> {
    "[a-z]{1,6}".prop_flat_map(|inner| {
        prop_oneof![
            Just(format!("$({inner})")),
            Just(format!("`{inner}`")),
            Just(format!("prefix-$({inner})")),
        ]
    })
}

/// An assignment value derived from a variable expansion (`$VAR`, `${VAR}`).
fn arb_variable_expansion_value() -> impl Strategy<Value = String> {
    "[a-z]{1,6}".prop_flat_map(|inner| {
        prop_oneof![
            Just(format!("${}", inner.to_uppercase())),
            Just(format!("${{{}}}", inner.to_uppercase())),
        ]
    })
}

/// Any dynamic (non-static) assignment value.
fn arb_dynamic_value() -> impl Strategy<Value = String> {
    prop_oneof![
        arb_command_substitution_value(),
        arb_variable_expansion_value(),
    ]
}

/// A literal assignment value with no expansion or substitution syntax.
fn arb_static_value() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_/.:-]{0,8}".prop_filter("must not contain expansion syntax", |v| {
        !v.contains('$') && !v.contains('`')
    })
}

proptest! {
    /// A substitution-derived inline assignment always resolves to `Unknown`
    /// in a basic snapshot (without recursive policy evaluation context).
    #[test]
    fn substitution_derived_value_resolves_unknown(
        var in "[A-Z]{1,4}",
        dynamic in arb_dynamic_value(),
    ) {
        let words = [Word::from(format!("{var}={dynamic}"))];
        let snap = EnvSnapshot::clean().with_assignments(&words);
        prop_assert_eq!(
            snap.get_value(&var),
            Some(EnvValueOwned::Unknown),
            "dynamic value {:?} should resolve to Unknown",
            dynamic
        );
    }

    /// Core invariant: a substitution-derived env value fires all applicable
    /// gates at max restriction. Equals, NotEquals, and Set all fire on
    /// Unknown (opaque) values. Unset does NOT fire (variable IS present).
    #[test]
    fn substitution_derived_value_fires_gates_at_max_restriction(
        var in "[A-Z]{1,4}",
        dynamic in arb_dynamic_value(),
        other_expected in "[a-z]{1,6}",
    ) {
        let words = [Word::from(format!("{var}={dynamic}"))];
        let snap = EnvSnapshot::clean().with_assignments(&words);

        // Equals fires — opaque could match any expected value.
        let equals_literal = vec![EnvGate {
            var: var.clone(),
            condition: EnvCondition::Equals(dynamic.clone()),
            decision: EnvGateAction::Ask,
        }];
        prop_assert_eq!(
            super::apply_env_gates(&equals_literal, &snap, PolicyDecision::Ask),
            Some(PolicyDecision::Ask),
            "Equals gate must fire on opaque value (max restriction)"
        );

        // Equals fires for any expected value.
        let equals_other = vec![EnvGate {
            var: var.clone(),
            condition: EnvCondition::Equals(other_expected),
            decision: EnvGateAction::Ask,
        }];
        prop_assert_eq!(
            super::apply_env_gates(&equals_other, &snap, PolicyDecision::Ask),
            Some(PolicyDecision::Ask),
            "Equals gate must fire on opaque value for any expected"
        );

        // Set fires — variable IS present (opaque).
        let set_gate = vec![EnvGate {
            var: var.clone(),
            condition: EnvCondition::Set,
            decision: EnvGateAction::Allow,
        }];
        prop_assert_eq!(
            super::apply_env_gates(&set_gate, &snap, PolicyDecision::Ask),
            Some(PolicyDecision::Allow),
            "Set gate must fire on opaque value (variable is present)"
        );

        // Unset does NOT fire — variable IS present.
        let unset_gate = vec![EnvGate {
            var: var.clone(),
            condition: EnvCondition::Unset,
            decision: EnvGateAction::Deny,
        }];
        prop_assert_eq!(
            super::apply_env_gates(&unset_gate, &snap, PolicyDecision::Ask),
            None,
            "Unset gate must not fire when variable is present (opaque)"
        );
    }

    /// Oracle / non-vacuity: a static assignment IS classified Static, kept
    /// as a known value, and DOES satisfy a matching Equals gate.
    #[test]
    fn static_value_satisfies_matching_equals(
        var in "[A-Z]{1,4}",
        value in arb_static_value(),
    ) {
        let words = [Word::from(format!("{var}={value}"))];
        let snap = EnvSnapshot::clean().with_assignments(&words);

        prop_assert_eq!(
            snap.get_value(&var),
            Some(EnvValueOwned::Known(value.clone())),
            "static value should resolve to its literal"
        );

        let gates = vec![EnvGate {
            var: var.clone(),
            condition: EnvCondition::Equals(value.clone()),
            decision: EnvGateAction::Deny,
        }];
        prop_assert_eq!(
            super::apply_env_gates(&gates, &snap, PolicyDecision::Ask),
            Some(PolicyDecision::Deny),
            "a matching Equals gate on a static value must fire"
        );
    }

    /// Variable expansion values are always classified as VariableExpansion.
    #[test]
    fn variable_expansion_classified_correctly(
        var in "[A-Z]{1,4}",
        value in arb_variable_expansion_value(),
    ) {
        use agent_shell_parser::parse::AssignmentValue;
        let word = Word::from(format!("{var}={value}"));
        let (_, classified) = word.as_classified_assignment().unwrap();
        prop_assert_eq!(
            classified,
            AssignmentValue::VariableExpansion,
            "variable expansion {:?} should classify as VariableExpansion",
            value
        );
    }

    /// Command substitution values are always classified as CommandSubstitution.
    #[test]
    fn command_substitution_classified_correctly(
        var in "[A-Z]{1,4}",
        value in arb_command_substitution_value(),
    ) {
        use agent_shell_parser::parse::AssignmentValue;
        let word = Word::from(format!("{var}={value}"));
        let (_, classified) = word.as_classified_assignment().unwrap();
        prop_assert_eq!(
            classified,
            AssignmentValue::CommandSubstitution,
            "command substitution {:?} should classify as CommandSubstitution",
            value
        );
    }
}

// ── preserved_from (selective --preserve-env) properties ─────────────────────

/// Classify a var name's state in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
enum VarState {
    Known(String),
    Unknown,
    Absent,
}

/// A description of one var and the state we want it in.
#[derive(Debug, Clone)]
struct VarEntry {
    name: String,
    state: VarState,
}

fn arb_var_name() -> impl Strategy<Value = String> {
    "[A-Z_][A-Z0-9_]{0,7}".prop_map(|s| s.to_string())
}

fn arb_var_value() -> impl Strategy<Value = String> {
    "[a-z]{1,8}".prop_map(|s| s.to_string())
}

fn arb_var_state() -> impl Strategy<Value = VarState> {
    prop_oneof![
        arb_var_value().prop_map(VarState::Known),
        Just(VarState::Unknown),
        Just(VarState::Absent),
    ]
}

fn arb_var_entry() -> impl Strategy<Value = VarEntry> {
    (arb_var_name(), arb_var_state()).prop_map(|(name, state)| VarEntry { name, state })
}

/// Build an `EnvSnapshot` from a list of `VarEntry`s. Uses a clean base so
/// the process env does not bleed in and make assertions non-deterministic.
fn snapshot_from_entries(entries: &[VarEntry]) -> EnvSnapshot {
    let mut snap = EnvSnapshot::clean();
    for entry in entries {
        match &entry.state {
            VarState::Known(v) => snap.set(&entry.name, v),
            VarState::Unknown => snap.set_unknown(&entry.name),
            VarState::Absent => { /* leave absent */ }
        }
    }
    snap
}

proptest! {
    /// Property 1 — Preserve is selective.
    ///
    /// For random env snapshots and random preserve var lists:
    /// - Every preserved var that was Known in the source is Known with the
    ///   same value in the result.
    /// - Every non-preserved var is Unknown (the `fully_unknown` floor).
    ///
    /// Would fail if `preserved_from` accidentally copies non-listed vars, or
    /// if it fails to copy a listed Known var.
    #[test]
    fn preserve_is_selective(
        entries in prop::collection::vec(arb_var_entry(), 0..8),
        preserve_names in prop::collection::vec(arb_var_name(), 0..5),
    ) {
        // Deduplicate entries by name: if the generator produces the same name
        // with different states, snapshot_from_entries keeps the last write, but
        // iterating raw entries would compare an earlier entry's state against the
        // snapshot's last-write-wins state, causing a spurious failure.
        let names: std::collections::HashSet<&str> =
            entries.iter().map(|e| e.name.as_str()).collect();
        prop_assume!(names.len() == entries.len());

        let source = snapshot_from_entries(&entries);
        let preserve_refs: Vec<&str> = preserve_names.iter().map(|s| s.as_str()).collect();
        let result = EnvSnapshot::preserved_from(&source, &preserve_refs);

        let preserve_set: std::collections::HashSet<&str> =
            preserve_refs.iter().copied().collect();

        // Check each entry in the source
        for entry in &entries {
            let name = entry.name.as_str();
            if preserve_set.contains(name) {
                // Listed in preserve: if source has Known, result must have same Known.
                if let VarState::Known(expected) = &entry.state {
                    prop_assert_eq!(
                        result.get_value(name),
                        Some(EnvValueOwned::Known(expected.clone())),
                        "preserved var '{}' with known source value must be Known in result",
                        name
                    );
                }
                // If Unknown or Absent in source, result stays Unknown — no assertion
                // needed (it can't be Known, so any Known result would be wrong, but
                // the var wasn't Known to begin with).
            } else {
                // Not listed: must be Unknown (fully_unknown floor).
                prop_assert_eq!(
                    result.get_value(name),
                    Some(EnvValueOwned::Unknown),
                    "non-preserved var '{}' must be Unknown in result",
                    name
                );
            }
        }
    }

    /// Property 2 — Empty preserve == fully unknown.
    ///
    /// `EnvSnapshot::preserved_from(env, &[])` produces a snapshot where
    /// `is_fully_unknown()` is true and no overrides exist (every var is Unknown).
    ///
    /// Also asserts equivalence with `mark_all_unknown` — both paths must agree.
    ///
    /// Would fail if `preserved_from(&[])` forgets to call `mark_all_unknown`,
    /// or if it accidentally copies some var.
    #[test]
    fn empty_preserve_is_fully_unknown(
        entries in prop::collection::vec(arb_var_entry(), 0..8),
    ) {
        let source = snapshot_from_entries(&entries);
        let result = EnvSnapshot::preserved_from(&source, &[]);

        prop_assert!(
            result.is_fully_unknown(),
            "preserved_from with empty list must be fully_unknown"
        );

        // Every var that existed in source must now be Unknown (not Known, not None).
        for entry in &entries {
            let name = entry.name.as_str();
            prop_assert_eq!(
                result.get_value(name),
                Some(EnvValueOwned::Unknown),
                "var '{}' must be Unknown when preserve list is empty",
                name
            );
        }

        // Equivalent to mark_all_unknown: a clean source with the same entries
        // after mark_all_unknown must also be fully_unknown and agree on all vars.
        let mut all_unknown = snapshot_from_entries(&entries);
        all_unknown.mark_all_unknown();
        prop_assert!(all_unknown.is_fully_unknown());
        for entry in &entries {
            let name = entry.name.as_str();
            prop_assert_eq!(
                result.get_value(name),
                all_unknown.get_value(name),
                "empty preserve and mark_all_unknown must agree on var '{}'",
                name
            );
        }
    }

    /// Property 3 — Full -E subsumes selective.
    ///
    /// For any preserve list and env snapshot, every var that is Known in the
    /// selective result is also Known (with the same value) in the full -E
    /// result (which is a clone of outer).
    ///
    /// Would fail if `preserved_from` produces a Known value that doesn't
    /// exist in the original outer env, i.e. invents data.
    #[test]
    fn full_preserve_subsumes_selective(
        entries in prop::collection::vec(arb_var_entry(), 0..8),
        preserve_names in prop::collection::vec(arb_var_name(), 0..5),
    ) {
        let source = snapshot_from_entries(&entries);
        let preserve_refs: Vec<&str> = preserve_names.iter().map(|s| s.as_str()).collect();

        let full_result = source.clone(); // full -E: just a clone of outer
        let selective_result = EnvSnapshot::preserved_from(&source, &preserve_refs);

        for entry in &entries {
            let name = entry.name.as_str();
            // If selective says Known(v), full must also say Known(v).
            if let Some(EnvValueOwned::Known(selective_val)) = selective_result.get_value(name) {
                prop_assert_eq!(
                    full_result.get_value(name),
                    Some(EnvValueOwned::Known(selective_val.clone())),
                    "full -E must agree with selective on Known var '{}'",
                    name
                );
            }
        }
    }

    /// Property 4 — Trim matters: `preserved_from` does NOT trim internally.
    ///
    /// `preserved_from(env, &[" FOO "])` treats `" FOO "` as a literal var name,
    /// which won't match a var named `"FOO"` in the source snapshot. The caller
    /// (`resolve_sudo_wrapper`) is responsible for trimming before calling
    /// `preserved_from`.
    ///
    /// This property generates var names with optional surrounding whitespace and
    /// verifies: (a) with the padded name, `preserved_from` does NOT preserve the
    /// var (treats it as Unknown); (b) with the trimmed name, it DOES preserve it
    /// (Known with the correct value). This proves the caller must trim.
    #[test]
    fn trim_matters_for_preserved_from(
        entries in prop::collection::vec(arb_var_entry(), 1..8),
    ) {
        let names: std::collections::HashSet<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        prop_assume!(names.len() == entries.len());
        let known_entry = entries.iter().find(|e| matches!(&e.state, VarState::Known(_)));
        prop_assume!(known_entry.is_some());
        let entry = known_entry.unwrap();
        let source = snapshot_from_entries(&entries);
        let trimmed_name = entry.name.as_str();
        let padded_name = format!("  {}  ", trimmed_name);

        let result_padded = EnvSnapshot::preserved_from(&source, &[&padded_name]);
        prop_assert_eq!(
            result_padded.get_value(trimmed_name),
            Some(EnvValueOwned::Unknown),
            "padded name '{}' should NOT match var '{}' — preserved_from doesn't trim",
            padded_name, trimmed_name
        );

        let result_trimmed = EnvSnapshot::preserved_from(&source, &[trimmed_name]);
        if let VarState::Known(expected) = &entry.state {
            prop_assert_eq!(
                result_trimmed.get_value(trimmed_name),
                Some(EnvValueOwned::Known(expected.clone())),
                "trimmed name '{}' should preserve Known value",
                trimmed_name
            );
        }
    }

    /// Property 5 — Idempotence of duplicate vars.
    ///
    /// `preserved_from(env, &["FOO", "FOO"])` == `preserved_from(env, &["FOO"])`.
    ///
    /// Duplicate entries in the preserve list must not change the result.
    ///
    /// Would fail if `preserved_from` had a stateful bug where processing the
    /// same var twice cleared or clobbered it (e.g. if a second pass set_unknown
    /// after a successful set).
    #[test]
    fn duplicate_preserve_vars_idempotent(
        entries in prop::collection::vec(arb_var_entry(), 0..8),
        preserve_names in prop::collection::vec(arb_var_name(), 1..5),
    ) {
        let source = snapshot_from_entries(&entries);

        let deduped_refs: Vec<&str> = preserve_names.iter().map(|s| s.as_str()).collect();

        // Build a doubled list: [FOO, BAR, FOO, BAR] for each name in preserve_names
        let doubled: Vec<&str> = preserve_names
            .iter()
            .map(|s| s.as_str())
            .chain(preserve_names.iter().map(|s| s.as_str()))
            .collect();

        let result_deduped = EnvSnapshot::preserved_from(&source, &deduped_refs);
        let result_doubled = EnvSnapshot::preserved_from(&source, &doubled);

        for entry in &entries {
            let name = entry.name.as_str();
            prop_assert_eq!(
                result_deduped.get_value(name),
                result_doubled.get_value(name),
                "duplicate vars must not change the result for var '{}'",
                name
            );
        }
    }
}

// ── path-scoped decision input properties ────────────────────────────────────
//
// Discipline: the *generator* is the oracle. We build commands from a known
// command whose path spec is `positionals = "all"` (rm/touch/mkdir/rmdir in
// the real KB), so every generated argument is, by definition, an affected
// path — in order. The property then pins that the policy engine surfaces
// exactly those paths on its result. This is the decision-input plumbing
// invariant: the engine neither drops nor invents paths relative to what the
// knowledge layer is contracted to extract. It never re-runs the engine to
// validate the engine.

/// A shell word that is unambiguously a positional path argument: no leading
/// dash (so never a flag), no `=` (so never an assignment), no whitespace or
/// shell metacharacters (so it parses to exactly one word).
fn arb_path_token() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_./]{1,12}".prop_map(|s| s.to_string())
}

/// A command name whose KB path spec is `positionals = "all"`, so that every
/// argument maps 1:1 to an affected path. All four exist in the default KB.
fn arb_all_positional_cmd() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("rm"), Just("touch"), Just("mkdir"), Just("rmdir"),]
}

/// First-seen-order de-duplication, matching `AffectedPaths::union_with`.
fn dedup_first_seen(items: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for it in items {
        if !out.contains(it) {
            out.push(it.clone());
        }
    }
    out
}

proptest! {
    /// For a single `positionals = "all"` command, the engine surfaces exactly
    /// the generated path arguments, in order. Oracle: the generated args.
    /// Catches a regression anywhere in the plumbing (classify → evaluate_segment
    /// → with_paths → fast-path result) that drops or reorders paths.
    #[test]
    fn engine_surfaces_all_positional_paths(
        cmd in arb_all_positional_cmd(),
        args in prop::collection::vec(arb_path_token(), 1..5),
    ) {
        let kb = default_knowledge_base();
        let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
        let line = format!("{cmd} {}", args.join(" "));

        let result = engine.evaluate_command(&line, kb);
        let surfaced: Vec<String> = result
            .affected_paths
            .iter()
            .map(|w| w.as_str().to_string())
            .collect();

        prop_assert_eq!(
            surfaced, args,
            "engine must surface exactly the positional paths for `{}`: {:?}",
            line, result
        );
    }

    /// For a compound `c1 && c2` of two `positionals = "all"` commands, the
    /// aggregate affected paths equal the first-seen-order de-duplicated union
    /// of both commands' arguments. Oracle: the generated args combined by the
    /// independently-defined `dedup_first_seen`. Also pins that each leaf
    /// segment carries its own (raw) paths.
    #[test]
    fn compound_aggregate_is_union_of_segment_paths(
        cmd1 in arb_all_positional_cmd(),
        args1 in prop::collection::vec(arb_path_token(), 1..4),
        cmd2 in arb_all_positional_cmd(),
        args2 in prop::collection::vec(arb_path_token(), 1..4),
    ) {
        let kb = default_knowledge_base();
        let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
        let line = format!("{cmd1} {} && {cmd2} {}", args1.join(" "), args2.join(" "));

        let result = engine.evaluate_command(&line, kb);

        let mut combined = args1.clone();
        combined.extend(args2.clone());
        let expected = dedup_first_seen(&combined);

        let surfaced: Vec<String> = result
            .affected_paths
            .iter()
            .map(|w| w.as_str().to_string())
            .collect();

        prop_assert_eq!(
            surfaced.clone(), expected,
            "compound aggregate must be the first-seen union of segment paths for `{}`: {:?}",
            line, result
        );

        // Every surfaced aggregate path came from some leaf segment, and every
        // leaf-segment path appears in the aggregate (set-level union).
        let leaf_paths: std::collections::BTreeSet<String> = result
            .segments
            .iter()
            .flat_map(|s| s.affected_paths.iter().map(|w| w.as_str().to_string()))
            .collect();
        let surfaced_set: std::collections::BTreeSet<String> =
            surfaced.into_iter().collect();
        prop_assert_eq!(
            leaf_paths, surfaced_set,
            "aggregate path set must equal the union of segment path sets: {:?}",
            result
        );
    }
}
// ── Env propagation metamorphic property ────────────────────────────────────

/// Gate type for the metamorphic test.
#[derive(Debug, Clone)]
enum MetaGateType {
    /// `Set` — fires when variable is present with a known value.
    Set,
    /// `Equals(value)` — fires when variable equals the expected value.
    Equals,
}

fn arb_meta_gate_type() -> impl Strategy<Value = MetaGateType> {
    prop_oneof![Just(MetaGateType::Set), Just(MetaGateType::Equals),]
}

/// Env gate action for the metamorphic test — only Ask and Deny are useful
/// for detection (Allow would be invisible against a ReadOnly command's
/// default Allow).
fn arb_meta_gate_action() -> impl Strategy<Value = EnvGateAction> {
    prop_oneof![Just(EnvGateAction::Ask), Just(EnvGateAction::Deny),]
}

proptest! {
    /// Metamorphic property: for any env gate on variable X with value V,
    /// these four command forms must produce the same policy decision:
    ///
    /// 1. `X=V cmd`             (inline assignment)
    /// 2. `env X=V cmd`         (env wrapper)
    /// 3. `export X=V && cmd`   (export + sequenced)
    /// 4. `nice X=V cmd`        (transparent wrapper from KB)
    ///
    /// The generator produces (var_name, value, gate_type, action) and
    /// renders all four forms. The assertion is that all four decisions
    /// agree — any difference means env propagation or env-wrapper handling
    /// is inconsistent.
    ///
    /// Form 4 samples from all transparent wrappers in the KB (ReadOnly
    /// floor, no env clearing, no privilege escalation) to verify that
    /// inline assignments pass through every transparent wrapper correctly.
    /// The KB itself is the oracle — no hardcoded wrapper names.
    #[test]
    fn env_assignment_forms_are_equivalent(
        var_name in "[A-Z]{2,6}",
        value in "[a-z0-9_]{1,8}",
        gate_type in arb_meta_gate_type(),
        action in arb_meta_gate_action(),
        wrapper_idx in 0..100usize,
    ) {
        // Use a synthetic command name that won't collide with real KB entries.
        let cmd_name = "metamorphic_test_cmd";

        // Collect transparent wrappers from the KB: ReadOnly floor, no
        // env clearing, no privilege escalation. Filter to those whose
        // parser spec has skip_positionals == 0, so `wrapper cmd` works
        // without needing dummy positional args.
        let kb_ref = default_knowledge_base();
        let default_config = agent_shell_parser::parse::default_command_config();
        let transparent_wrappers: Vec<&str> = kb_ref
            .wrappers
            .iter()
            .filter(|(name, w)| {
                w.floor_effect == Effect::ReadOnly
                    && !w.clears_env
                    && !w.escalates_privilege
                    && default_config
                        .wrappers
                        .iter()
                        .find(|s| s.name == **name)
                        .map_or(true, |s| s.skip_positionals == 0)
            })
            .map(|(name, _)| name.as_str())
            .collect();
        prop_assert!(
            !transparent_wrappers.is_empty(),
            "KB must have at least one transparent wrapper"
        );
        let wrapper = transparent_wrappers[wrapper_idx % transparent_wrappers.len()];

        // Build the gate
        let gate = match &gate_type {
            MetaGateType::Set => EnvGate {
                var: var_name.clone(),
                condition: EnvCondition::Set,
                decision: action,
            },
            MetaGateType::Equals => EnvGate {
                var: var_name.clone(),
                condition: EnvCondition::Equals(value.clone()),
                decision: action,
            },
        };

        // Build a KB with the test command carrying the gate
        let mut kb = default_knowledge_base().clone();
        let cmd = agent_command_knowledge::CommandKnowledge {
            name: cmd_name.to_string(),
            effect: Effect::ReadOnly,
            subcommands: Default::default(),
            flags: Default::default(),
            env_gates: vec![gate],
            paths: Default::default(),
            properties: Default::default(),
        };
        kb.commands.insert(cmd_name.to_string(), cmd);

        let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();

        // Form 1: inline assignment
        let form1 = format!("{var_name}={value} {cmd_name}");
        let result1 = engine.evaluate_command(&form1, &kb);

        // Form 2: env wrapper
        let form2 = format!("env {var_name}={value} {cmd_name}");
        let result2 = engine.evaluate_command(&form2, &kb);

        // Form 3: export + &&
        let form3 = format!("export {var_name}={value} && {cmd_name}");
        let result3 = engine.evaluate_command(&form3, &kb);

        // Form 4: inline assignment before a transparent KB wrapper (sampled).
        // Shell semantics: `FOO=bar wrapper cmd` scopes the assignment to the
        // entire command; a transparent wrapper inherits and passes it through.
        let form4 = format!("{var_name}={value} {wrapper} {cmd_name}");
        let result4 = engine.evaluate_command(&form4, &kb);

        // All four must agree on the gate's effect. The sampled wrapper is
        // transparent (ReadOnly floor, no clear, no escalate), so the inline
        // assignment is visible to the inner command and the gate determines
        // the result — same as forms 1-3.
        //
        // Specifically: all four should produce the gate's action as the
        // decision (since ReadOnly base = Allow and gate action ≥ Allow).
        let expected = super::gate_action_to_decision(action);

        prop_assert_eq!(
            result1.decision, expected,
            "form 1 ({}): expected {:?}, got {:?}: {:?}",
            form1, expected, result1.decision, result1
        );
        prop_assert_eq!(
            result2.decision, expected,
            "form 2 ({}): expected {:?}, got {:?}: {:?}",
            form2, expected, result2.decision, result2
        );
        prop_assert_eq!(
            result3.decision, expected,
            "form 3 ({}): expected {:?}, got {:?}: {:?}",
            form3, expected, result3.decision, result3
        );
        prop_assert_eq!(
            result4.decision, expected,
            "form 4 ({}): expected {:?}, got {:?}: {:?}",
            form4, expected, result4.decision, result4
        );
    }
}
