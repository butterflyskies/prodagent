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
    PolicyConfig { defaults, commands }
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

        let result_without = super::apply_env_gates(&gates, &env);
        let mut extended = gates.clone();
        extended.push(extra_gate);
        let result_with = super::apply_env_gates(&extended, &env);

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
        let result = super::apply_env_gates(&[], &env);
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
        let result = super::apply_env_gates(&all_gates, &env);
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

        let result1 = super::apply_env_gates(&gates, &env);

        let mut reversed = gates.clone();
        reversed.reverse();
        let result2 = super::apply_env_gates(&reversed, &env);

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
