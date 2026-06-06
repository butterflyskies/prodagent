use proptest::prelude::*;

use crate::merge::*;
use crate::types::*;

// ---- strategies ----

fn arb_effect() -> impl Strategy<Value = Effect> {
    prop_oneof![
        Just(Effect::ReadOnly),
        Just(Effect::Mutating),
        Just(Effect::Unknown),
    ]
}

fn arb_flag_schema() -> impl Strategy<Value = FlagSchema> {
    (
        prop::collection::vec("[a-z]{1,4}".prop_map(|s| format!("-{s}")), 0..3),
        prop::collection::vec("[a-z]{1,5}".prop_map(|s| format!("--{s}")), 0..3),
        prop::collection::vec("[a-z]{1,5}".prop_map(|s| format!("--{s}")), 0..2),
        prop::collection::vec("[a-z]{1,4}".prop_map(|s| format!("-{s}")), 0..2),
    )
        .prop_map(|(skip_arg, skip_solo, escalation, path)| FlagSchema {
            skip_arg,
            skip_solo,
            escalation,
            path,
        })
}

fn arb_env_gate_decision() -> impl Strategy<Value = EnvGateAction> {
    prop_oneof![
        Just(EnvGateAction::Allow),
        Just(EnvGateAction::Ask),
        Just(EnvGateAction::Deny),
    ]
}

fn arb_env_condition() -> impl Strategy<Value = EnvCondition> {
    prop_oneof![
        "[a-z]{1,5}".prop_map(EnvCondition::Equals),
        "[a-z]{1,5}".prop_map(EnvCondition::NotEquals),
        Just(EnvCondition::Set),
        Just(EnvCondition::Unset),
    ]
}

fn arb_env_gate() -> impl Strategy<Value = EnvGate> {
    ("[A-Z]{2,6}", arb_env_condition(), arb_env_gate_decision()).prop_map(
        |(var, condition, decision)| EnvGate {
            var,
            condition,
            decision,
        },
    )
}

fn arb_command_overlay_without_effect() -> impl Strategy<Value = CommandOverlay> {
    (
        arb_flag_schema(),
        prop::collection::vec(arb_env_gate(), 0..3),
    )
        .prop_map(|(flags, env_gates)| CommandOverlay {
            flags,
            env_gates,
            ..Default::default()
        })
}

fn arb_command_overlay_with_effect() -> impl Strategy<Value = CommandOverlay> {
    (
        arb_effect(),
        arb_flag_schema(),
        prop::collection::vec(arb_env_gate(), 0..3),
    )
        .prop_map(|(effect, flags, env_gates)| CommandOverlay {
            effect: Some(effect),
            flags,
            env_gates,
            ..Default::default()
        })
}

fn single_command_kb(name: &str, effect: Effect) -> KnowledgeBase {
    let mut kb = KnowledgeBase::default();
    kb.commands
        .insert(name.into(), CommandKnowledge::simple(name, effect));
    kb
}

// ---- properties ----

proptest! {
    /// Merging an overlay that doesn't specify an effect never changes the
    /// base command's effect. Fail-closed: a no-op overlay can't weaken policy.
    #[test]
    fn effectless_overlay_never_changes_effect(
        base_effect in arb_effect(),
        overlay in arb_command_overlay_without_effect(),
    ) {
        let mut kb = single_command_kb("c", base_effect);
        let mut ov = KnowledgeOverlay::default();
        ov.commands.insert("c".into(), overlay);
        kb.merge(ov);
        prop_assert_eq!(kb.commands["c"].effect, base_effect);
    }

    /// When an overlay explicitly sets an effect, that exact effect is what
    /// the merged command has — no silent promotion or demotion.
    #[test]
    fn explicit_effect_always_wins(
        base_effect in arb_effect(),
        overlay in arb_command_overlay_with_effect(),
    ) {
        let requested = overlay.effect.unwrap();
        let mut kb = single_command_kb("c", base_effect);
        let mut ov = KnowledgeOverlay::default();
        ov.commands.insert("c".into(), overlay);
        kb.merge(ov);
        prop_assert_eq!(kb.commands["c"].effect, requested);
    }

    /// A new command inserted via overlay without an explicit effect gets
    /// Effect::Unknown (fail-closed). No combination of overlay fields can
    /// produce a more permissive default.
    #[test]
    fn new_command_always_defaults_to_unknown(
        overlay in arb_command_overlay_without_effect(),
    ) {
        let mut kb = KnowledgeBase::default();
        let mut ov = KnowledgeOverlay::default();
        ov.commands.insert("c".into(), overlay);
        kb.merge(ov);
        prop_assert_eq!(kb.commands["c"].effect, Effect::Unknown);
    }
}
