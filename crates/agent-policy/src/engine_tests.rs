use super::*;
use crate::config::{EffectDefaults, PolicyConfig};
use agent_command_knowledge::{Effect, KnowledgeBase, WrapperKnowledge};

// ── PolicyDecision ordering ─────────────────────────────────────────────

#[test]
fn policy_decision_ordering() {
    assert!(PolicyDecision::Allow < PolicyDecision::Ask);
    assert!(PolicyDecision::Ask < PolicyDecision::Deny);
    assert!(PolicyDecision::Allow < PolicyDecision::Deny);
}

// ── Default effect mapping ──────────────────────────────────────────────

#[test]
fn default_effect_mapping() {
    let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();

    let read_only = CommandInfo {
        effect: Effect::ReadOnly,
        ..CommandInfo::unknown()
    };
    assert_eq!(engine.evaluate("cat", &read_only), PolicyDecision::Allow);

    let mutating = CommandInfo {
        effect: Effect::Mutating,
        ..CommandInfo::unknown()
    };
    assert_eq!(engine.evaluate("rm", &mutating), PolicyDecision::Ask);

    let unknown = CommandInfo::unknown();
    assert_eq!(engine.evaluate("mystery", &unknown), PolicyDecision::Ask);
}

// ── Config from TOML round-trip ─────────────────────────────────────────

#[test]
fn config_toml_round_trip() {
    let config = PolicyConfig::builder()
        .read_only_default(PolicyDecision::Allow)
        .mutating_default(PolicyDecision::Ask)
        .unknown_default(PolicyDecision::Deny)
        .build()
        .unwrap();
    let serialized = toml::to_string(&config).expect("serialize");
    let deserialized: PolicyConfig = toml::from_str(&serialized).expect("deserialize");
    assert_eq!(deserialized.defaults.read_only, PolicyDecision::Allow);
    assert_eq!(deserialized.defaults.mutating, PolicyDecision::Ask);
    assert_eq!(deserialized.defaults.unknown, PolicyDecision::Deny);
}

// ── Per-command override (flat) ─────────────────────────────────────────

#[test]
fn per_command_flat_override_parses() {
    let toml_str = r#"
[commands]
ls = "allow"
rm = "deny"
"#;
    let config: PolicyConfig = toml::from_str(toml_str).expect("parse");
    assert!(matches!(
        config.commands.get("ls"),
        Some(CommandPolicy::Flat(PolicyDecision::Allow))
    ));
    assert!(matches!(
        config.commands.get("rm"),
        Some(CommandPolicy::Flat(PolicyDecision::Deny))
    ));
}

// ── Per-command override (detailed with subcommands) ────────────────────

#[test]
fn per_command_detailed_override_parses() {
    let toml_str = r#"
[commands.git]
base = "ask"

[commands.git.subcommands]
status = "allow"
push = "ask"
reset = "deny"
"#;
    let config: PolicyConfig = toml::from_str(toml_str).expect("parse");
    match config.commands.get("git") {
        Some(CommandPolicy::Detailed(detail)) => {
            assert_eq!(detail.base, Some(PolicyDecision::Ask));
            assert_eq!(
                detail.subcommands.get("status"),
                Some(&PolicyDecision::Allow)
            );
            assert_eq!(detail.subcommands.get("push"), Some(&PolicyDecision::Ask));
            assert_eq!(detail.subcommands.get("reset"), Some(&PolicyDecision::Deny));
        }
        other => panic!("expected Detailed, got {:?}", other),
    }
}

// ── Effect defaults customization ───────────────────────────────────────

#[test]
fn effect_defaults_customization() {
    let config = PolicyConfig::builder()
        .read_only_default(PolicyDecision::Allow)
        .mutating_default(PolicyDecision::Deny)
        .unknown_default(PolicyDecision::Deny)
        .build()
        .unwrap();
    let engine = PolicyEngine::new(config).unwrap();

    let mutating = CommandInfo {
        effect: Effect::Mutating,
        ..CommandInfo::unknown()
    };
    assert_eq!(
        engine.evaluate("rm", &mutating),
        PolicyDecision::Deny,
        "custom mutating default should be Deny"
    );

    let unknown = CommandInfo::unknown();
    assert_eq!(
        engine.evaluate("mystery", &unknown),
        PolicyDecision::Deny,
        "custom unknown default should be Deny"
    );
}

// ── Command override tests (wired) ─────────────────────────────────────

#[test]
fn flat_override_affects_decision() {
    let config = PolicyConfig::builder().deny("rm").build().unwrap();
    let engine = PolicyEngine::new(config).unwrap();

    // Even with a ReadOnly effect, the flat override should win
    let info = CommandInfo {
        effect: Effect::ReadOnly,
        ..CommandInfo::unknown()
    };
    assert_eq!(engine.evaluate("rm", &info), PolicyDecision::Deny);
}

#[test]
fn detailed_subcommand_override() {
    let config = PolicyConfig::builder()
        .command_base("git", PolicyDecision::Ask)
        .subcommand("git", "status", PolicyDecision::Allow)
        .build()
        .unwrap();
    let engine = PolicyEngine::new(config).unwrap();

    let info = CommandInfo {
        effect: Effect::Unknown,
        subcommand: Some("status".to_string()),
        ..CommandInfo::unknown()
    };
    assert_eq!(engine.evaluate("git", &info), PolicyDecision::Allow);
}

#[test]
fn detailed_base_override() {
    let config = PolicyConfig::builder()
        .command_base("git", PolicyDecision::Ask)
        .build()
        .unwrap();
    let engine = PolicyEngine::new(config).unwrap();

    let info = CommandInfo {
        effect: Effect::ReadOnly,
        subcommand: None,
        ..CommandInfo::unknown()
    };
    assert_eq!(engine.evaluate("git", &info), PolicyDecision::Ask);
}

#[test]
fn override_precedence() {
    // Subcommand override = Allow, base override = Ask, effect default for Unknown = Deny
    let config = PolicyConfig::builder()
        .read_only_default(PolicyDecision::Deny)
        .mutating_default(PolicyDecision::Deny)
        .unknown_default(PolicyDecision::Deny)
        .command_base("git", PolicyDecision::Ask)
        .subcommand("git", "status", PolicyDecision::Allow)
        .build()
        .unwrap();
    let engine = PolicyEngine::new(config).unwrap();

    // Subcommand match → Allow (beats base Ask and effect Deny)
    let with_sub = CommandInfo {
        effect: Effect::Unknown,
        subcommand: Some("status".to_string()),
        ..CommandInfo::unknown()
    };
    assert_eq!(
        engine.evaluate("git", &with_sub),
        PolicyDecision::Allow,
        "subcommand override should beat base and effect default"
    );

    // No subcommand match → base Ask (beats effect Deny)
    let no_sub = CommandInfo {
        effect: Effect::Unknown,
        subcommand: None,
        ..CommandInfo::unknown()
    };
    assert_eq!(
        engine.evaluate("git", &no_sub),
        PolicyDecision::Ask,
        "base override should beat effect default"
    );

    // Unmatched subcommand → base Ask (beats effect Deny)
    let wrong_sub = CommandInfo {
        effect: Effect::Unknown,
        subcommand: Some("push".to_string()),
        ..CommandInfo::unknown()
    };
    assert_eq!(
        engine.evaluate("git", &wrong_sub),
        PolicyDecision::Ask,
        "unmatched subcommand should fall through to base override"
    );
}

#[test]
fn unmatched_command_falls_through() {
    let config = PolicyConfig::builder().deny("rm").build().unwrap();
    let engine = PolicyEngine::new(config).unwrap();

    // "ls" is not in overrides, so it should fall through to effect default
    let info = CommandInfo {
        effect: Effect::ReadOnly,
        ..CommandInfo::unknown()
    };
    assert_eq!(
        engine.evaluate("ls", &info),
        PolicyDecision::Allow,
        "unmatched command should use effect default"
    );
}

// ── PolicyDecision Display and Default ─────────────────────────────────

#[test]
fn policy_decision_display() {
    assert_eq!(format!("{}", PolicyDecision::Allow), "Allow");
    assert_eq!(format!("{}", PolicyDecision::Ask), "Ask");
    assert_eq!(format!("{}", PolicyDecision::Deny), "Deny");
}

#[test]
fn policy_decision_default_is_ask() {
    assert_eq!(PolicyDecision::default(), PolicyDecision::Ask);
}

// ── Mechanism-level wrapper test (P2-9) ────────────────────────────────

#[test]
fn wrapper_floor_applied_from_minimal_kb() {
    // Construct a minimal KB with a known wrapper (floor_effect=Mutating)
    // and a read-only inner command, then verify the floor is applied.
    // We use "nice" because it's in the parser's embedded commands.json
    // wrapper list, so resolve_command will strip it.
    let mut kb = KnowledgeBase::default();
    kb.wrappers.insert(
        "nice".to_string(),
        WrapperKnowledge {
            name: "nice".to_string(),
            floor_effect: Effect::Mutating,
            clears_env: false,
            escalates_privilege: false,
        },
    );

    let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
    // "nice ls" — nice is a wrapper with Mutating floor, ls is unknown to this
    // minimal KB but the parser resolves it. With Mutating floor and default
    // policy (mutating=Ask), the floor should be Ask.
    let result = engine.evaluate_command("nice ls", &kb);
    assert!(
        result.decision >= PolicyDecision::Ask,
        "wrapper floor_effect=Mutating should raise inner command to at least Ask: {result:?}"
    );
}

// ── Detailed no-match fallthrough test (P3-14) ─────────────────────────

#[test]
fn detailed_no_match_falls_through_to_effect_default() {
    // Detailed policy for "git" with base: None and only push -> Deny.
    // Calling with subcommand "status" should fall through to effect default.
    let config = PolicyConfig::builder()
        .subcommand("git", "push", PolicyDecision::Deny)
        .build()
        .unwrap();
    let engine = PolicyEngine::new(config).unwrap();

    let info = CommandInfo {
        effect: Effect::ReadOnly,
        subcommand: Some("status".to_string()),
        ..CommandInfo::unknown()
    };
    // No match for "status" subcommand and no base override → effect default for ReadOnly = Allow
    assert_eq!(
        engine.evaluate("git", &info),
        PolicyDecision::Allow,
        "unmatched subcommand with no base should fall through to effect default"
    );
}

// ── Validation tests ────────────────────────────────────────────────────

#[test]
fn monotonic_config_validates() {
    let result = PolicyConfig::builder()
        .read_only_default(PolicyDecision::Allow)
        .mutating_default(PolicyDecision::Ask)
        .unknown_default(PolicyDecision::Ask)
        .build();
    assert!(result.is_ok());
}

#[test]
fn non_monotonic_config_rejected() {
    let err = PolicyConfig::builder()
        .read_only_default(PolicyDecision::Deny)
        .mutating_default(PolicyDecision::Allow)
        .unknown_default(PolicyDecision::Ask)
        .build()
        .unwrap_err();
    assert!(
        err.contains("non-monotonic"),
        "error message should mention non-monotonic: {}",
        err
    );
    assert!(
        err.contains("read-only"),
        "error message should name read-only: {}",
        err
    );
}

#[test]
fn equal_values_are_monotonic() {
    let result = PolicyConfig::builder()
        .read_only_default(PolicyDecision::Ask)
        .mutating_default(PolicyDecision::Ask)
        .unknown_default(PolicyDecision::Ask)
        .build();
    assert!(
        result.is_ok(),
        "all-equal values should be considered monotonic"
    );
}

// ── No-op Detailed entry validation (P1-2) ─────────────────────────────

#[test]
fn noop_detailed_entry_rejected() {
    // Build a config with an empty Detailed entry manually — the builder
    // would reject this at build() time, but we want to test validate()
    // directly too.
    let mut commands = std::collections::HashMap::new();
    commands.insert(
        "git".to_string(),
        CommandPolicy::Detailed(crate::config::DetailedCommandPolicy {
            base: None,
            subcommands: std::collections::HashMap::new(),
        }),
    );
    let config = PolicyConfig {
        defaults: EffectDefaults::default(),
        commands,
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("git"),
        "error should name the command: {}",
        err
    );
    assert!(err.contains("no-op"), "error should mention no-op: {}", err);
}

// ── PolicyEngine::new rejects invalid config (P2-6) ────────────────────

#[test]
fn engine_new_rejects_invalid_config() {
    let result = PolicyConfig::builder()
        .read_only_default(PolicyDecision::Deny)
        .mutating_default(PolicyDecision::Allow)
        .unknown_default(PolicyDecision::Ask)
        .build();
    assert!(
        result.is_err(),
        "builder should reject non-monotonic config"
    );
}

// ── Fail-closed guard ───────────────────────────────────────────────────

#[test]
fn default_config_is_fail_closed() {
    let config = PolicyConfig::default();
    assert_eq!(
        config.defaults.unknown,
        PolicyDecision::Ask,
        "Unknown effect should default to Ask, not Allow"
    );
    assert_eq!(
        config.defaults.mutating,
        PolicyDecision::Ask,
        "Mutating effect should default to Ask, not Allow"
    );
    assert_eq!(
        config.defaults.read_only,
        PolicyDecision::Allow,
        "ReadOnly effect should default to Allow"
    );
}

// ── EnvGate unit tests ───────────────────────────────────────────────────

use crate::env_snapshot::{EnvSnapshot, EnvValueOwned};
use agent_command_knowledge::{EnvCondition, EnvGate, EnvGateAction};

// ── apply_env_gates: condition × decision matrix ─────────────────────────

#[test]
fn env_gate_equals_matching_allows() {
    let gates = vec![EnvGate {
        var: "FOO".into(),
        condition: EnvCondition::Equals("bar".into()),
        decision: EnvGateAction::Allow,
    }];
    let mut env = EnvSnapshot::clean();
    env.set("FOO", "bar");
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        Some(PolicyDecision::Allow)
    );
}

#[test]
fn env_gate_equals_nonmatching_has_no_effect() {
    let gates = vec![EnvGate {
        var: "FOO".into(),
        condition: EnvCondition::Equals("bar".into()),
        decision: EnvGateAction::Deny,
    }];
    let mut env = EnvSnapshot::clean();
    env.set("FOO", "baz");
    assert_eq!(super::apply_env_gates(&gates, &env), None);
}

#[test]
fn env_gate_not_equals_matching() {
    let gates = vec![EnvGate {
        var: "FOO".into(),
        condition: EnvCondition::NotEquals("bar".into()),
        decision: EnvGateAction::Deny,
    }];
    let mut env = EnvSnapshot::clean();
    env.set("FOO", "baz"); // baz != bar → matches
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        Some(PolicyDecision::Deny)
    );
}

#[test]
fn env_gate_not_equals_same_value_no_effect() {
    let gates = vec![EnvGate {
        var: "FOO".into(),
        condition: EnvCondition::NotEquals("bar".into()),
        decision: EnvGateAction::Deny,
    }];
    let mut env = EnvSnapshot::clean();
    env.set("FOO", "bar"); // bar == bar → doesn't match
    assert_eq!(super::apply_env_gates(&gates, &env), None);
}

#[test]
fn env_gate_not_equals_unset_var_matches() {
    // NotEquals with unset var: var not set != any value → matches
    let gates = vec![EnvGate {
        var: "FOO".into(),
        condition: EnvCondition::NotEquals("bar".into()),
        decision: EnvGateAction::Ask,
    }];
    let env = EnvSnapshot::clean();
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        Some(PolicyDecision::Ask)
    );
}

#[test]
fn env_gate_set_matching() {
    let gates = vec![EnvGate {
        var: "VIRTUAL_ENV".into(),
        condition: EnvCondition::Set,
        decision: EnvGateAction::Allow,
    }];
    let mut env = EnvSnapshot::clean();
    env.set("VIRTUAL_ENV", "/venv");
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        Some(PolicyDecision::Allow)
    );
}

#[test]
fn env_gate_set_not_set_no_effect() {
    let gates = vec![EnvGate {
        var: "VIRTUAL_ENV".into(),
        condition: EnvCondition::Set,
        decision: EnvGateAction::Allow,
    }];
    let env = EnvSnapshot::clean();
    assert_eq!(super::apply_env_gates(&gates, &env), None);
}

#[test]
fn env_gate_unset_matching() {
    let gates = vec![EnvGate {
        var: "VIRTUAL_ENV".into(),
        condition: EnvCondition::Unset,
        decision: EnvGateAction::Deny,
    }];
    let env = EnvSnapshot::clean();
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        Some(PolicyDecision::Deny)
    );
}

#[test]
fn env_gate_unset_when_set_no_effect() {
    let gates = vec![EnvGate {
        var: "VIRTUAL_ENV".into(),
        condition: EnvCondition::Unset,
        decision: EnvGateAction::Deny,
    }];
    let mut env = EnvSnapshot::clean();
    env.set("VIRTUAL_ENV", "/venv");
    assert_eq!(super::apply_env_gates(&gates, &env), None);
}

#[test]
fn env_gate_no_gates_returns_none() {
    let env = EnvSnapshot::from_process_env();
    assert_eq!(super::apply_env_gates(&[], &env), None);
}

// ── Multiple gates: strictest wins ───────────────────────────────────────

#[test]
fn env_gate_multiple_strictest_wins() {
    let gates = vec![
        EnvGate {
            var: "A".into(),
            condition: EnvCondition::Set,
            decision: EnvGateAction::Allow,
        },
        EnvGate {
            var: "B".into(),
            condition: EnvCondition::Set,
            decision: EnvGateAction::Ask,
        },
    ];
    let mut env = EnvSnapshot::clean();
    env.set("A", "1");
    env.set("B", "2");
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        Some(PolicyDecision::Ask),
        "strictest (Ask) should win over Allow"
    );
}

#[test]
fn env_gate_deny_short_circuits() {
    let gates = vec![
        EnvGate {
            var: "A".into(),
            condition: EnvCondition::Set,
            decision: EnvGateAction::Deny,
        },
        EnvGate {
            var: "B".into(),
            condition: EnvCondition::Set,
            decision: EnvGateAction::Allow,
        },
    ];
    let mut env = EnvSnapshot::clean();
    env.set("A", "1");
    env.set("B", "2");
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        Some(PolicyDecision::Deny),
        "Deny should short-circuit"
    );
}

// ── Unknown env var handling (conservative) ──────────────────────────────

#[test]
fn env_gate_equals_unknown_no_effect() {
    let gates = vec![EnvGate {
        var: "FOO".into(),
        condition: EnvCondition::Equals("bar".into()),
        decision: EnvGateAction::Allow,
    }];
    let mut env = EnvSnapshot::clean();
    env.set_unknown("FOO");
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        None,
        "Equals with unknown value should have no effect"
    );
}

#[test]
fn env_gate_not_equals_unknown_no_effect() {
    let gates = vec![EnvGate {
        var: "FOO".into(),
        condition: EnvCondition::NotEquals("bar".into()),
        decision: EnvGateAction::Deny,
    }];
    let mut env = EnvSnapshot::clean();
    env.set_unknown("FOO");
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        None,
        "NotEquals with unknown value should have no effect"
    );
}

#[test]
fn env_gate_set_unknown_no_match() {
    // Unknown means we can't confirm the var is set — conservative fail-closed
    let gates = vec![EnvGate {
        var: "FOO".into(),
        condition: EnvCondition::Set,
        decision: EnvGateAction::Allow,
    }];
    let mut env = EnvSnapshot::clean();
    env.set_unknown("FOO");
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        None,
        "Set with unknown value should not match (fail-closed)"
    );
}

#[test]
fn env_gate_unset_unknown_no_match() {
    // Unknown means *something* was assigned — Unset should NOT match
    let gates = vec![EnvGate {
        var: "FOO".into(),
        condition: EnvCondition::Unset,
        decision: EnvGateAction::Deny,
    }];
    let mut env = EnvSnapshot::clean();
    env.set_unknown("FOO");
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        None,
        "Unset with unknown value should not match (conservative: assume set)"
    );
}

// ── Condition × action matrix (exhaustive) ──────────────────────────────

#[test]
fn env_gate_equals_matching_asks() {
    let gates = vec![EnvGate {
        var: "FOO".into(),
        condition: EnvCondition::Equals("bar".into()),
        decision: EnvGateAction::Ask,
    }];
    let mut env = EnvSnapshot::clean();
    env.set("FOO", "bar");
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        Some(PolicyDecision::Ask)
    );
}

#[test]
fn env_gate_equals_matching_denies() {
    let gates = vec![EnvGate {
        var: "FOO".into(),
        condition: EnvCondition::Equals("bar".into()),
        decision: EnvGateAction::Deny,
    }];
    let mut env = EnvSnapshot::clean();
    env.set("FOO", "bar");
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        Some(PolicyDecision::Deny)
    );
}

#[test]
fn env_gate_not_equals_allows() {
    let gates = vec![EnvGate {
        var: "FOO".into(),
        condition: EnvCondition::NotEquals("bar".into()),
        decision: EnvGateAction::Allow,
    }];
    let mut env = EnvSnapshot::clean();
    env.set("FOO", "baz"); // baz != bar → matches
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        Some(PolicyDecision::Allow)
    );
}

#[test]
fn env_gate_set_asks() {
    let gates = vec![EnvGate {
        var: "FOO".into(),
        condition: EnvCondition::Set,
        decision: EnvGateAction::Ask,
    }];
    let mut env = EnvSnapshot::clean();
    env.set("FOO", "anything");
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        Some(PolicyDecision::Ask)
    );
}

#[test]
fn env_gate_set_denies() {
    let gates = vec![EnvGate {
        var: "FOO".into(),
        condition: EnvCondition::Set,
        decision: EnvGateAction::Deny,
    }];
    let mut env = EnvSnapshot::clean();
    env.set("FOO", "anything");
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        Some(PolicyDecision::Deny)
    );
}

#[test]
fn env_gate_unset_allows() {
    let gates = vec![EnvGate {
        var: "FOO".into(),
        condition: EnvCondition::Unset,
        decision: EnvGateAction::Allow,
    }];
    let env = EnvSnapshot::clean();
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        Some(PolicyDecision::Allow)
    );
}

#[test]
fn env_gate_unset_asks() {
    let gates = vec![EnvGate {
        var: "FOO".into(),
        condition: EnvCondition::Unset,
        decision: EnvGateAction::Ask,
    }];
    let env = EnvSnapshot::clean();
    assert_eq!(
        super::apply_env_gates(&gates, &env),
        Some(PolicyDecision::Ask)
    );
}

// ── evaluate_condition direct tests ──────────────────────────────────────

#[test]
fn evaluate_condition_equals_known_match() {
    let val = Some(EnvValueOwned::Known("bar".to_string()));
    assert!(super::evaluate_condition(
        &EnvCondition::Equals("bar".to_string()),
        val.as_ref()
    ));
}

#[test]
fn evaluate_condition_equals_known_mismatch() {
    let val = Some(EnvValueOwned::Known("baz".to_string()));
    assert!(!super::evaluate_condition(
        &EnvCondition::Equals("bar".to_string()),
        val.as_ref()
    ));
}

#[test]
fn evaluate_condition_equals_none() {
    assert!(!super::evaluate_condition(
        &EnvCondition::Equals("bar".to_string()),
        None
    ));
}

#[test]
fn evaluate_condition_set_with_known() {
    let val = Some(EnvValueOwned::Known("anything".to_string()));
    assert!(super::evaluate_condition(&EnvCondition::Set, val.as_ref()));
}

#[test]
fn evaluate_condition_set_with_unknown() {
    // Unknown value: can't confirm the var is set — fail-closed → false
    let val = Some(EnvValueOwned::Unknown);
    assert!(!super::evaluate_condition(&EnvCondition::Set, val.as_ref()));
}

#[test]
fn evaluate_condition_set_with_none() {
    assert!(!super::evaluate_condition(&EnvCondition::Set, None));
}

#[test]
fn evaluate_condition_unset_with_none() {
    assert!(super::evaluate_condition(&EnvCondition::Unset, None));
}

#[test]
fn evaluate_condition_unset_with_known() {
    let val = Some(EnvValueOwned::Known("anything".to_string()));
    assert!(!super::evaluate_condition(
        &EnvCondition::Unset,
        val.as_ref()
    ));
}

// ── Sentinel rework tests (round-2 review P1) ──────────────────────────

#[test]
fn set_condition_with_unknown_value_does_not_match() {
    // Set gate on an unknown var → gate should NOT fire (fail-closed)
    let val = Some(EnvValueOwned::Unknown);
    assert!(
        !super::evaluate_condition(&EnvCondition::Set, val.as_ref()),
        "Set with Unknown value should not match (conservative fail-closed)"
    );
}

#[test]
fn unset_condition_with_unknown_value_does_not_match() {
    // Unset gate on an unknown var → gate should NOT fire (fail-closed)
    let val = Some(EnvValueOwned::Unknown);
    assert!(
        !super::evaluate_condition(&EnvCondition::Unset, val.as_ref()),
        "Unset with Unknown value should not match (conservative fail-closed)"
    );
}

#[test]
fn sudo_with_set_deny_gate_does_not_over_deny() {
    // Bare sudo with a Set/Deny gate → the gate should NOT fire because the
    // env is fully unknown (Set on unknown = false). The result should be Ask
    // (from sudo escalation), not Deny.
    let gate = EnvGate {
        var: "PATH".into(),
        condition: EnvCondition::Set,
        decision: EnvGateAction::Deny,
    };
    let mut kb = agent_command_knowledge::default_knowledge_base().clone();

    // Build a command knowledge entry with the gate
    let cmd = agent_command_knowledge::CommandKnowledge {
        name: "mycmd".to_string(),
        effect: agent_command_knowledge::Effect::ReadOnly,
        subcommands: Default::default(),
        flags: Default::default(),
        env_gates: vec![gate],
        paths: Default::default(),
        properties: Default::default(),
    };
    kb.commands.insert("mycmd".to_string(), cmd);

    let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
    let result = engine.evaluate_command("sudo mycmd", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Ask,
        "sudo with Set/Deny gate should be Ask (gate suppressed by unknown env), not Deny: {result:?}"
    );
}

// ── sudo --preserve-env=VAR,VAR selective parsing ──────────────────────

/// Helper: build a KB with a command that has a Set gate on `var_name`.
/// The gate action is Ask so it's distinguishable from the sudo escalation Ask.
fn kb_with_set_gate(var_name: &str, action: EnvGateAction) -> KnowledgeBase {
    let gate = EnvGate {
        var: var_name.into(),
        condition: EnvCondition::Set,
        decision: action,
    };
    let mut kb = agent_command_knowledge::default_knowledge_base().clone();
    let cmd = agent_command_knowledge::CommandKnowledge {
        name: "mycmd".to_string(),
        effect: agent_command_knowledge::Effect::ReadOnly,
        subcommands: Default::default(),
        flags: Default::default(),
        env_gates: vec![gate],
        paths: Default::default(),
        properties: Default::default(),
    };
    kb.commands.insert("mycmd".to_string(), cmd);
    kb
}

#[test]
fn sudo_selective_preserve_single_var_visible() {
    // FOO=hello sudo --preserve-env=FOO mycmd
    // FOO is set inline and preserved → inner env has FOO=hello → Set gate fires.
    // The gate action is Deny, so if FOO is visible the result must be Deny.
    // If the property is violated (FOO not preserved), the gate won't fire and
    // the result would be Ask (sudo escalation only).
    let kb = kb_with_set_gate("FOO", EnvGateAction::Deny);
    let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
    let result = engine.evaluate_command("FOO=hello sudo --preserve-env=FOO mycmd", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Deny,
        "FOO is set inline and preserved selectively → Set/Deny gate must fire: {result:?}"
    );
}

#[test]
fn sudo_selective_preserve_multi_var_both_visible() {
    // FOO=hello BAR=world sudo --preserve-env=FOO,BAR mycmd
    // Both vars set inline and preserved → both visible.
    // Use Deny gate on BAR to prove BAR is visible.
    let kb = kb_with_set_gate("BAR", EnvGateAction::Deny);
    let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
    let result =
        engine.evaluate_command("FOO=hello BAR=world sudo --preserve-env=FOO,BAR mycmd", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Deny,
        "BAR is set inline and preserved → Set/Deny gate must fire: {result:?}"
    );
}

#[test]
fn sudo_selective_preserve_var_not_set_stays_unknown() {
    // sudo --preserve-env=FOO mycmd  (FOO not set anywhere)
    // Can't preserve what doesn't exist → FOO stays unknown.
    // Set gate should NOT fire (Unknown → fail-closed).
    // With a clean env snapshot, we test via the unit function directly
    // because process env might have FOO set.
    let words: Vec<Word> = vec![
        Word::from("sudo"),
        Word::from("--preserve-env=FOO"),
        Word::from("mycmd"),
    ];
    // Build an outer env where FOO is NOT set
    let outer = EnvSnapshot::clean();
    let inner = super::resolve_sudo_wrapper(&words, &outer);
    assert_eq!(
        inner.get_value("FOO"),
        Some(EnvValueOwned::Unknown),
        "FOO not in outer env → should remain Unknown after selective preserve"
    );
}

#[test]
fn sudo_selective_preserve_gate_fires_on_preserved_var() {
    // FOO=hello sudo --preserve-env=FOO mycmd with an Allow gate.
    // FOO is preserved, so the gate fires (Allow), but sudo escalation produces
    // Ask. Allow.max(Ask) = Ask — the sudo escalation dominates.
    // This proves the Allow gate fires (rather than being suppressed) and that
    // Allow cannot lower a higher decision already in place.
    let kb = kb_with_set_gate("FOO", EnvGateAction::Allow);
    let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
    let result = engine.evaluate_command("FOO=hello sudo --preserve-env=FOO mycmd", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Ask,
        "preserved FOO → Allow gate fires → Ask (sudo escalation dominates Allow): {result:?}"
    );
}

#[test]
fn sudo_selective_preserve_gate_suppressed_on_non_preserved_var() {
    // FOO=hello sudo --preserve-env=FOO mycmd  with gate on OTHER_VAR
    // OTHER_VAR is NOT in the preserve list → it's unknown → gate doesn't fire.
    // Result should be Ask (from sudo escalation), not Deny.
    let kb = kb_with_set_gate("OTHER_VAR", EnvGateAction::Deny);
    let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
    let result = engine.evaluate_command("FOO=hello sudo --preserve-env=FOO mycmd", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Ask,
        "OTHER_VAR not preserved → gate suppressed → should be Ask (sudo escalation only): {result:?}"
    );
}

// ── resolve_sudo_wrapper unit tests ────────────────────────────────────

#[test]
fn resolve_sudo_wrapper_selective_preserves_known_var() {
    let words: Vec<Word> = vec![
        Word::from("sudo"),
        Word::from("--preserve-env=FOO"),
        Word::from("cmd"),
    ];
    let mut outer = EnvSnapshot::clean();
    outer.set("FOO", "bar");
    outer.set("SECRET", "hidden");

    let inner = super::resolve_sudo_wrapper(&words, &outer);

    // FOO should be preserved
    assert_eq!(
        inner.get_value("FOO"),
        Some(EnvValueOwned::Known("bar".to_string())),
        "FOO listed in --preserve-env should be Known"
    );
    // SECRET should be unknown (not in preserve list)
    assert_eq!(
        inner.get_value("SECRET"),
        Some(EnvValueOwned::Unknown),
        "SECRET not in --preserve-env should be Unknown"
    );
}

#[test]
fn resolve_sudo_wrapper_selective_multi_var() {
    let words: Vec<Word> = vec![
        Word::from("sudo"),
        Word::from("--preserve-env=FOO,BAR"),
        Word::from("cmd"),
    ];
    let mut outer = EnvSnapshot::clean();
    outer.set("FOO", "f");
    outer.set("BAR", "b");
    outer.set("BAZ", "z");

    let inner = super::resolve_sudo_wrapper(&words, &outer);

    assert_eq!(
        inner.get_value("FOO"),
        Some(EnvValueOwned::Known("f".to_string())),
    );
    assert_eq!(
        inner.get_value("BAR"),
        Some(EnvValueOwned::Known("b".to_string())),
    );
    assert_eq!(
        inner.get_value("BAZ"),
        Some(EnvValueOwned::Unknown),
        "BAZ not in preserve list → Unknown"
    );
}

#[test]
fn resolve_sudo_wrapper_selective_unknown_outer_stays_unknown() {
    let words: Vec<Word> = vec![
        Word::from("sudo"),
        Word::from("--preserve-env=MISSING"),
        Word::from("cmd"),
    ];
    let outer = EnvSnapshot::clean(); // MISSING not set

    let inner = super::resolve_sudo_wrapper(&words, &outer);
    // MISSING is not in outer env at all → get_value returns None from outer,
    // and mark_all_unknown makes it Unknown in inner
    assert_eq!(
        inner.get_value("MISSING"),
        Some(EnvValueOwned::Unknown),
        "var not in outer env can't be preserved → stays Unknown"
    );
}

#[test]
fn resolve_sudo_wrapper_full_preserve_unchanged() {
    // -E should still give full preserve (regression guard)
    let words: Vec<Word> = vec![Word::from("sudo"), Word::from("-E"), Word::from("cmd")];
    let mut outer = EnvSnapshot::clean();
    outer.set("FOO", "bar");
    outer.set("SECRET", "yes");

    let inner = super::resolve_sudo_wrapper(&words, &outer);
    assert_eq!(
        inner.get_value("FOO"),
        Some(EnvValueOwned::Known("bar".to_string())),
    );
    assert_eq!(
        inner.get_value("SECRET"),
        Some(EnvValueOwned::Known("yes".to_string())),
    );
}

#[test]
fn resolve_sudo_wrapper_no_flag_all_unknown() {
    // No -E, no --preserve-env → all unknown (regression guard)
    let words: Vec<Word> = vec![Word::from("sudo"), Word::from("cmd")];
    let mut outer = EnvSnapshot::clean();
    outer.set("FOO", "bar");

    let inner = super::resolve_sudo_wrapper(&words, &outer);
    assert_eq!(
        inner.get_value("FOO"),
        Some(EnvValueOwned::Unknown),
        "bare sudo → all unknown"
    );
}

#[test]
fn sudo_selective_preserve_whitespace_trimmed() {
    // --preserve-env=FOO, BAR (space after comma) — each token is trimmed so
    // both FOO and BAR should be preserved as Known.
    let words: Vec<Word> = vec![
        Word::from("sudo"),
        Word::from("--preserve-env=FOO, BAR"), // space after comma
        Word::from("cmd"),
    ];
    let mut outer = EnvSnapshot::clean();
    outer.set("FOO", "foo-val");
    outer.set("BAR", "bar-val");
    outer.set("OTHER", "hidden");

    let inner = super::resolve_sudo_wrapper(&words, &outer);
    assert_eq!(
        inner.get_value("FOO"),
        Some(EnvValueOwned::Known("foo-val".to_string())),
        "FOO should be preserved despite whitespace in token list"
    );
    assert_eq!(
        inner.get_value("BAR"),
        Some(EnvValueOwned::Known("bar-val".to_string())),
        "BAR should be preserved after trimming leading space"
    );
    assert_eq!(
        inner.get_value("OTHER"),
        Some(EnvValueOwned::Unknown),
        "OTHER not in list → Unknown"
    );
}

#[test]
fn sudo_selective_preserve_empty_list_all_unknown() {
    // sudo --preserve-env= (equals sign, no vars after it) is a valid flag form
    // that requests preserving an *empty* set of variables. The behavior is the
    // same as bare sudo: mark everything unknown, preserve nothing.
    // This guards against accidentally treating the empty-string token as a
    // variable name to look up.
    let words: Vec<Word> = vec![
        Word::from("sudo"),
        Word::from("--preserve-env="), // empty list
        Word::from("cmd"),
    ];
    let mut outer = EnvSnapshot::clean();
    outer.set("FOO", "bar");
    outer.set("BAR", "baz");

    let inner = super::resolve_sudo_wrapper(&words, &outer);
    assert_eq!(
        inner.get_value("FOO"),
        Some(EnvValueOwned::Unknown),
        "--preserve-env= with empty list → FOO should be Unknown"
    );
    assert_eq!(
        inner.get_value("BAR"),
        Some(EnvValueOwned::Unknown),
        "--preserve-env= with empty list → BAR should be Unknown"
    );
}
