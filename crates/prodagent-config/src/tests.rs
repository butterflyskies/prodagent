//! Tests for the three-tier configuration cascade.
//!
//! Covers the four invariants from issue #59:
//! 1. Monotonicity — project can't weaken user policy
//! 2. Determinism — same inputs → same outputs
//! 3. Identity on missing layers — absent layers don't change the result
//! 4. Bounded subtraction — remove_* can't produce invalid state

use std::collections::HashMap;

use agent_policy::config::{CommandPolicy, DetailedCommandPolicy, EffectDefaults, PolicyConfig};
use agent_policy::PolicyDecision;

use crate::monotonicity::{validate_monotonicity, MonotonicityViolation};
use crate::types::{
    ConfigLayer, KnowledgeConfig, PolicyDefaultsOverlay, PolicyOverlay, ProdagentConfig,
};

// ── Helpers ───────────────────────────────────────────────────────────────

fn default_layer() -> ConfigLayer {
    ConfigLayer {
        knowledge: KnowledgeConfig::default(),
        policy: PolicyOverlay {
            defaults: PolicyDefaultsOverlay {
                read_only: Some(PolicyDecision::Allow),
                mutating: Some(PolicyDecision::Ask),
                unknown: Some(PolicyDecision::Ask),
            },
            commands: HashMap::new(),
            remove_commands: vec![],
        },
    }
}

// ── 1. Monotonicity: project can't weaken user policy ─────────────────────

#[test]
fn monotonicity_project_tightens_default_is_ok() {
    let user_policy = PolicyConfig {
        defaults: EffectDefaults {
            read_only: PolicyDecision::Allow,
            mutating: PolicyDecision::Ask,
            unknown: PolicyDecision::Ask,
        },
        commands: HashMap::new(),
    };

    // Project tightens read_only from Allow → Ask
    let project = PolicyOverlay {
        defaults: PolicyDefaultsOverlay {
            read_only: Some(PolicyDecision::Ask),
            ..Default::default()
        },
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert!(violations.is_empty(), "tightening should be allowed");
}

#[test]
fn monotonicity_project_weakens_default_is_violation() {
    let user_policy = PolicyConfig {
        defaults: EffectDefaults {
            read_only: PolicyDecision::Ask,
            mutating: PolicyDecision::Deny,
            unknown: PolicyDecision::Deny,
        },
        commands: HashMap::new(),
    };

    // Project tries to weaken mutating from Deny → Ask
    let project = PolicyOverlay {
        defaults: PolicyDefaultsOverlay {
            mutating: Some(PolicyDecision::Ask),
            ..Default::default()
        },
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].path, "policy.defaults.mutating");
    assert_eq!(violations[0].user_decision, PolicyDecision::Deny);
    assert_eq!(violations[0].project_decision, PolicyDecision::Ask);
}

#[test]
fn monotonicity_project_weakens_command_flat() {
    let mut commands = HashMap::new();
    commands.insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Deny));

    let user_policy = PolicyConfig {
        defaults: EffectDefaults::default(),
        commands,
    };

    // Project tries to allow rm
    let mut proj_commands = HashMap::new();
    proj_commands.insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Allow));

    let project = PolicyOverlay {
        commands: proj_commands,
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].path, "policy.commands.rm");
}

#[test]
fn monotonicity_project_tightens_command_is_ok() {
    let mut commands = HashMap::new();
    commands.insert("git".into(), CommandPolicy::Flat(PolicyDecision::Allow));

    let user_policy = PolicyConfig {
        defaults: EffectDefaults::default(),
        commands,
    };

    // Project tightens git to Ask
    let mut proj_commands = HashMap::new();
    proj_commands.insert("git".into(), CommandPolicy::Flat(PolicyDecision::Ask));

    let project = PolicyOverlay {
        commands: proj_commands,
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert!(violations.is_empty());
}

#[test]
fn monotonicity_project_weakens_subcommand() {
    let mut commands = HashMap::new();
    let mut subcmds = HashMap::new();
    subcmds.insert("push".into(), PolicyDecision::Deny);
    commands.insert(
        "git".into(),
        CommandPolicy::Detailed(DetailedCommandPolicy {
            base: Some(PolicyDecision::Ask),
            subcommands: subcmds,
        }),
    );

    let user_policy = PolicyConfig {
        defaults: EffectDefaults::default(),
        commands,
    };

    // Project tries to allow git push
    let mut proj_subcmds = HashMap::new();
    proj_subcmds.insert("push".into(), PolicyDecision::Allow);
    let mut proj_commands = HashMap::new();
    proj_commands.insert(
        "git".into(),
        CommandPolicy::Detailed(DetailedCommandPolicy {
            base: None,
            subcommands: proj_subcmds,
        }),
    );

    let project = PolicyOverlay {
        commands: proj_commands,
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].path, "policy.commands.git.subcommands.push");
    assert_eq!(violations[0].user_decision, PolicyDecision::Deny);
    assert_eq!(violations[0].project_decision, PolicyDecision::Allow);
}

#[test]
fn monotonicity_project_removes_user_command_is_violation() {
    let mut commands = HashMap::new();
    commands.insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Deny));

    let user_policy = PolicyConfig {
        defaults: EffectDefaults::default(),
        commands,
    };

    // Project tries to remove the user's rm policy
    let project = PolicyOverlay {
        remove_commands: vec!["rm".into()],
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert_eq!(violations.len(), 1);
    assert!(violations[0].path.contains("remove_commands"));
}

#[test]
fn monotonicity_project_removes_nonexistent_command_is_ok() {
    let user_policy = PolicyConfig {
        defaults: EffectDefaults::default(),
        commands: HashMap::new(),
    };

    // Removing a command the user didn't set is a no-op, not a violation
    let project = PolicyOverlay {
        remove_commands: vec!["nonexistent".into()],
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert!(violations.is_empty());
}

#[test]
fn monotonicity_multiple_violations_all_reported() {
    let user_policy = PolicyConfig {
        defaults: EffectDefaults {
            read_only: PolicyDecision::Ask,
            mutating: PolicyDecision::Deny,
            unknown: PolicyDecision::Deny,
        },
        commands: HashMap::new(),
    };

    // Project tries to weaken all three defaults
    let project = PolicyOverlay {
        defaults: PolicyDefaultsOverlay {
            read_only: Some(PolicyDecision::Allow),
            mutating: Some(PolicyDecision::Allow),
            unknown: Some(PolicyDecision::Ask),
        },
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert_eq!(
        violations.len(),
        3,
        "all three violations should be reported"
    );
}

#[test]
fn monotonicity_same_decision_is_ok() {
    let user_policy = PolicyConfig {
        defaults: EffectDefaults {
            read_only: PolicyDecision::Ask,
            mutating: PolicyDecision::Ask,
            unknown: PolicyDecision::Ask,
        },
        commands: HashMap::new(),
    };

    // Project sets the same values — no change, no violation
    let project = PolicyOverlay {
        defaults: PolicyDefaultsOverlay {
            read_only: Some(PolicyDecision::Ask),
            mutating: Some(PolicyDecision::Ask),
            unknown: Some(PolicyDecision::Ask),
        },
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert!(
        violations.is_empty(),
        "identical decisions should not violate"
    );
}

// ── 2. Determinism: same inputs → same outputs ───────────────────────────

#[test]
fn determinism_same_layers_same_result() {
    let defaults = default_layer();
    let user = ConfigLayer {
        policy: PolicyOverlay {
            defaults: PolicyDefaultsOverlay {
                read_only: Some(PolicyDecision::Ask),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let result1 = ProdagentConfig::from_layers(defaults.clone(), Some(user.clone()), None);
    let result2 = ProdagentConfig::from_layers(defaults.clone(), Some(user.clone()), None);

    assert_eq!(
        result1.policy.defaults.read_only,
        result2.policy.defaults.read_only
    );
    assert_eq!(
        result1.policy.defaults.mutating,
        result2.policy.defaults.mutating
    );
    assert_eq!(
        result1.policy.defaults.unknown,
        result2.policy.defaults.unknown
    );
}

#[test]
fn determinism_with_all_three_layers() {
    let defaults = default_layer();
    let user = ConfigLayer {
        policy: PolicyOverlay {
            defaults: PolicyDefaultsOverlay {
                read_only: Some(PolicyDecision::Ask),
                ..Default::default()
            },
            commands: {
                let mut m = HashMap::new();
                m.insert("git".into(), CommandPolicy::Flat(PolicyDecision::Allow));
                m
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let project = ConfigLayer {
        policy: PolicyOverlay {
            defaults: PolicyDefaultsOverlay {
                read_only: Some(PolicyDecision::Deny),
                ..Default::default()
            },
            commands: {
                let mut m = HashMap::new();
                m.insert("git".into(), CommandPolicy::Flat(PolicyDecision::Deny));
                m
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let result1 =
        ProdagentConfig::from_layers(defaults.clone(), Some(user.clone()), Some(project.clone()));
    let result2 =
        ProdagentConfig::from_layers(defaults.clone(), Some(user.clone()), Some(project.clone()));

    assert_eq!(
        result1.policy.defaults.read_only,
        result2.policy.defaults.read_only
    );
    assert_eq!(
        format!("{:?}", result1.policy.commands),
        format!("{:?}", result2.policy.commands),
    );
}

// ── 3. Identity on missing layers ────────────────────────────────────────

#[test]
fn missing_user_layer_equals_defaults() {
    let defaults = default_layer();

    let with_user = ProdagentConfig::from_layers(defaults.clone(), None, None);

    assert_eq!(with_user.policy.defaults.read_only, PolicyDecision::Allow);
    assert_eq!(with_user.policy.defaults.mutating, PolicyDecision::Ask);
    assert_eq!(with_user.policy.defaults.unknown, PolicyDecision::Ask);
    assert!(with_user.policy.commands.is_empty());
}

#[test]
fn missing_project_layer_equals_user_plus_defaults() {
    let defaults = default_layer();
    let user = ConfigLayer {
        policy: PolicyOverlay {
            defaults: PolicyDefaultsOverlay {
                read_only: Some(PolicyDecision::Ask),
                ..Default::default()
            },
            commands: {
                let mut m = HashMap::new();
                m.insert("git".into(), CommandPolicy::Flat(PolicyDecision::Allow));
                m
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let with_project = ProdagentConfig::from_layers(defaults.clone(), Some(user.clone()), None);

    // read_only was overridden by user
    assert_eq!(with_project.policy.defaults.read_only, PolicyDecision::Ask);
    // mutating inherits from defaults
    assert_eq!(with_project.policy.defaults.mutating, PolicyDecision::Ask);
    // git was set by user
    assert_eq!(
        with_project.policy.commands.get("git"),
        Some(&CommandPolicy::Flat(PolicyDecision::Allow))
    );
}

#[test]
fn empty_layers_are_identity() {
    let defaults = default_layer();
    let empty_user = ConfigLayer::default();
    let empty_project = ConfigLayer::default();

    let with_empty =
        ProdagentConfig::from_layers(defaults.clone(), Some(empty_user), Some(empty_project));
    let without = ProdagentConfig::from_layers(defaults.clone(), None, None);

    assert_eq!(
        with_empty.policy.defaults.read_only,
        without.policy.defaults.read_only
    );
    assert_eq!(
        with_empty.policy.defaults.mutating,
        without.policy.defaults.mutating
    );
    assert_eq!(
        with_empty.policy.defaults.unknown,
        without.policy.defaults.unknown
    );
    assert_eq!(
        with_empty.policy.commands.len(),
        without.policy.commands.len()
    );
}

// ── 4. Bounded subtraction: remove semantics ─────────────────────────────

#[test]
fn remove_nonexistent_knowledge_command_is_noop() {
    let defaults = ConfigLayer {
        knowledge: KnowledgeConfig {
            commands: HashMap::new(),
            wrappers: HashMap::new(),
            remove_commands: vec![],
            remove_wrappers: vec![],
        },
        ..default_layer()
    };
    let user = ConfigLayer {
        knowledge: KnowledgeConfig {
            remove_commands: vec!["nonexistent".into()],
            ..Default::default()
        },
        ..Default::default()
    };

    // Should not panic or produce invalid state
    let config = ProdagentConfig::from_layers(defaults, Some(user), None);
    assert!(config.knowledge.commands.is_empty());
}

#[test]
fn remove_nonexistent_policy_command_is_noop() {
    let defaults = default_layer();
    let user = ConfigLayer {
        policy: PolicyOverlay {
            remove_commands: vec!["nonexistent".into()],
            ..Default::default()
        },
        ..Default::default()
    };

    let config = ProdagentConfig::from_layers(defaults, Some(user), None);
    assert!(config.policy.commands.is_empty());
}

#[test]
fn remove_then_readd_works() {
    let defaults = ConfigLayer {
        policy: PolicyOverlay {
            commands: {
                let mut m = HashMap::new();
                m.insert("git".into(), CommandPolicy::Flat(PolicyDecision::Allow));
                m
            },
            ..Default::default()
        },
        ..default_layer()
    };
    let user = ConfigLayer {
        policy: PolicyOverlay {
            remove_commands: vec!["git".into()],
            commands: {
                let mut m = HashMap::new();
                m.insert("git".into(), CommandPolicy::Flat(PolicyDecision::Deny));
                m
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let config = ProdagentConfig::from_layers(defaults, Some(user), None);
    assert_eq!(
        config.policy.commands.get("git"),
        Some(&CommandPolicy::Flat(PolicyDecision::Deny)),
        "re-added command should have the new decision"
    );
}

// ── 5. Merge semantics ──────────────────────────────────────────────────

#[test]
fn project_overrides_user_command_policy() {
    let defaults = default_layer();
    let user = ConfigLayer {
        policy: PolicyOverlay {
            commands: {
                let mut m = HashMap::new();
                m.insert("git".into(), CommandPolicy::Flat(PolicyDecision::Allow));
                m
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let project = ConfigLayer {
        policy: PolicyOverlay {
            commands: {
                let mut m = HashMap::new();
                // Tightening: Allow → Deny (monotonic)
                m.insert("git".into(), CommandPolicy::Flat(PolicyDecision::Deny));
                m
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let config = ProdagentConfig::from_layers(defaults, Some(user), Some(project));
    assert_eq!(
        config.policy.commands.get("git"),
        Some(&CommandPolicy::Flat(PolicyDecision::Deny)),
        "project layer should override user layer"
    );
}

#[test]
fn user_overrides_default_effect_defaults() {
    let defaults = default_layer();
    let user = ConfigLayer {
        policy: PolicyOverlay {
            defaults: PolicyDefaultsOverlay {
                read_only: Some(PolicyDecision::Ask),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let config = ProdagentConfig::from_layers(defaults, Some(user), None);
    assert_eq!(
        config.policy.defaults.read_only,
        PolicyDecision::Ask,
        "user should override default read_only"
    );
    assert_eq!(
        config.policy.defaults.mutating,
        PolicyDecision::Ask,
        "mutating should inherit from defaults"
    );
}

// ── 6. TOML round-trip ──────────────────────────────────────────────────

#[test]
fn toml_config_layer_round_trip() {
    // Parse a minimal layer
    let layer: ConfigLayer = toml::from_str(
        r#"
[policy.defaults]
read_only = "ask"
"#,
    )
    .expect("TOML should parse");

    assert_eq!(layer.policy.defaults.read_only, Some(PolicyDecision::Ask));
    assert!(layer.policy.defaults.mutating.is_none());
    assert!(layer.policy.defaults.unknown.is_none());
}

#[test]
fn toml_full_layer() {
    let toml_str = r#"
[policy.defaults]
read_only = "allow"
mutating = "deny"

[policy.commands]
rm = "deny"
git = "ask"

[knowledge]
remove_commands = []
"#;

    let layer: ConfigLayer = toml::from_str(toml_str).expect("TOML should parse");

    assert_eq!(layer.policy.defaults.read_only, Some(PolicyDecision::Allow));
    assert_eq!(layer.policy.defaults.mutating, Some(PolicyDecision::Deny));
    assert_eq!(
        layer.policy.commands.get("rm"),
        Some(&CommandPolicy::Flat(PolicyDecision::Deny))
    );
    assert_eq!(
        layer.policy.commands.get("git"),
        Some(&CommandPolicy::Flat(PolicyDecision::Ask))
    );
}

// ── 7. Loader with filesystem (tempfile) ────────────────────────────────

#[test]
fn loader_defaults_only() {
    use crate::ConfigLoader;

    let config = ConfigLoader::new().load().expect("defaults should load");
    assert_eq!(config.policy.defaults.read_only, PolicyDecision::Allow);
    assert_eq!(config.policy.defaults.mutating, PolicyDecision::Ask);
    assert_eq!(config.policy.defaults.unknown, PolicyDecision::Ask);
}

#[test]
fn loader_with_user_config() {
    use crate::ConfigLoader;

    let dir = tempfile::tempdir().expect("tempdir");
    let user_path = dir.path().join("config.toml");
    std::fs::write(
        &user_path,
        r#"
[policy.defaults]
read_only = "ask"
"#,
    )
    .unwrap();

    let config = ConfigLoader::new()
        .user_config(&user_path)
        .load()
        .expect("should load");

    assert_eq!(config.policy.defaults.read_only, PolicyDecision::Ask);
    assert_eq!(config.policy.defaults.mutating, PolicyDecision::Ask);
}

#[test]
fn loader_with_valid_project_config() {
    use crate::ConfigLoader;

    let dir = tempfile::tempdir().expect("tempdir");
    let project_path = dir.path().join("config.toml");
    // Project tightens read_only from Allow → Ask — monotonic and
    // internally consistent (read_only Ask <= mutating Ask)
    std::fs::write(
        &project_path,
        r#"
[policy.defaults]
read_only = "ask"
"#,
    )
    .unwrap();

    let config = ConfigLoader::new()
        .project_config(&project_path)
        .load()
        .expect("should load");

    assert_eq!(config.policy.defaults.read_only, PolicyDecision::Ask);
}

#[test]
fn loader_rejects_monotonicity_violation() {
    use crate::loader::ConfigError;
    use crate::ConfigLoader;

    let dir = tempfile::tempdir().expect("tempdir");

    // User config sets read_only to Ask (internally consistent:
    // read_only=Ask <= mutating=Ask <= unknown=Ask)
    let user_path = dir.path().join("user.toml");
    std::fs::write(
        &user_path,
        r#"
[policy.defaults]
read_only = "ask"
"#,
    )
    .unwrap();

    // Project tries to weaken read_only back to Allow
    let project_path = dir.path().join("project.toml");
    std::fs::write(
        &project_path,
        r#"
[policy.defaults]
read_only = "allow"
"#,
    )
    .unwrap();

    let result = ConfigLoader::new()
        .user_config(&user_path)
        .project_config(&project_path)
        .load();

    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::Monotonicity(violations) => {
            assert_eq!(violations.len(), 1);
            assert_eq!(violations[0].path, "policy.defaults.read_only");
        }
        other => panic!("expected Monotonicity error, got: {other}"),
    }
}

#[test]
fn loader_missing_files_are_identity() {
    use crate::ConfigLoader;

    let config = ConfigLoader::new()
        .user_config("/nonexistent/path/config.toml")
        .project_config("/nonexistent/path/config.toml")
        .load()
        .expect("missing files should be silently skipped");

    assert_eq!(config.policy.defaults.read_only, PolicyDecision::Allow);
    assert_eq!(config.policy.defaults.mutating, PolicyDecision::Ask);
}

// ── 8. Policy overlay apply_to ──────────────────────────────────────────

#[test]
fn policy_overlay_apply_to_removes_then_adds() {
    let mut policy = PolicyConfig {
        defaults: EffectDefaults::default(),
        commands: {
            let mut m = HashMap::new();
            m.insert("old-cmd".into(), CommandPolicy::Flat(PolicyDecision::Allow));
            m
        },
    };

    let overlay = PolicyOverlay {
        remove_commands: vec!["old-cmd".into()],
        commands: {
            let mut m = HashMap::new();
            m.insert("old-cmd".into(), CommandPolicy::Flat(PolicyDecision::Deny));
            m
        },
        ..Default::default()
    };

    overlay.apply_to(&mut policy);

    assert_eq!(
        policy.commands.get("old-cmd"),
        Some(&CommandPolicy::Flat(PolicyDecision::Deny)),
        "remove then add should result in the new value"
    );
}

#[test]
fn policy_overlay_partial_defaults_preserves_unset() {
    let mut policy = PolicyConfig {
        defaults: EffectDefaults {
            read_only: PolicyDecision::Allow,
            mutating: PolicyDecision::Ask,
            unknown: PolicyDecision::Deny,
        },
        commands: HashMap::new(),
    };

    let overlay = PolicyOverlay {
        defaults: PolicyDefaultsOverlay {
            mutating: Some(PolicyDecision::Deny),
            ..Default::default()
        },
        ..Default::default()
    };

    overlay.apply_to(&mut policy);

    assert_eq!(
        policy.defaults.read_only,
        PolicyDecision::Allow,
        "read_only should be preserved"
    );
    assert_eq!(
        policy.defaults.mutating,
        PolicyDecision::Deny,
        "mutating should be overridden"
    );
    assert_eq!(
        policy.defaults.unknown,
        PolicyDecision::Deny,
        "unknown should be preserved"
    );
}

// ── 9. MonotonicityViolation Display ────────────────────────────────────

#[test]
fn violation_display_is_informative() {
    let v = MonotonicityViolation {
        path: "policy.defaults.mutating".into(),
        user_decision: PolicyDecision::Deny,
        project_decision: PolicyDecision::Allow,
    };

    let msg = format!("{v}");
    assert!(msg.contains("policy.defaults.mutating"));
    assert!(msg.contains("Deny"));
    assert!(msg.contains("Allow"));
}

// ── 10. Knowledge merge across layers ───────────────────────────────────

#[test]
fn knowledge_remove_accumulates_across_layers() {
    use agent_command_knowledge::merge::CommandOverlay;
    use agent_command_knowledge::Effect;

    let defaults = ConfigLayer {
        knowledge: KnowledgeConfig {
            commands: {
                let mut m = HashMap::new();
                m.insert(
                    "git".into(),
                    CommandOverlay {
                        effect: Some(Effect::Unknown),
                        ..Default::default()
                    },
                );
                m.insert(
                    "rm".into(),
                    CommandOverlay {
                        effect: Some(Effect::Mutating),
                        ..Default::default()
                    },
                );
                m
            },
            ..Default::default()
        },
        ..default_layer()
    };

    let user = ConfigLayer {
        knowledge: KnowledgeConfig {
            remove_commands: vec!["rm".into()],
            ..Default::default()
        },
        ..Default::default()
    };

    let project = ConfigLayer {
        knowledge: KnowledgeConfig {
            remove_commands: vec!["git".into()],
            ..Default::default()
        },
        ..Default::default()
    };

    let config = ProdagentConfig::from_layers(defaults, Some(user), Some(project));

    // Both removals should be accumulated
    assert!(config.knowledge.remove_commands.contains(&"rm".into()));
    assert!(config.knowledge.remove_commands.contains(&"git".into()));
}
