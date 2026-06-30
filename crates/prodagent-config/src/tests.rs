//! Tests for the three-tier configuration cascade.
//!
//! Covers the four invariants from issue #59:
//! 1. Monotonicity — project can't weaken user policy
//! 2. Determinism — same inputs → same outputs
//! 3. Identity on missing layers — absent layers don't change the result
//! 4. Bounded subtraction — remove_* can't produce invalid state

use std::collections::HashMap;

use prodagent_policy::config::{
    CommandPolicy, DetailedCommandPolicy, EffectDefaults, PolicyConfig,
};
use prodagent_policy::PolicyDecision;

use crate::monotonicity::{validate_monotonicity, MonotonicityViolation};
use crate::types::{
    ConfigLayer, KnowledgeConfig, PolicyDefaultsOverlay, PolicyOverlay, ProdagentConfig,
};

// ── Helpers ───────────────────────────────────────────────────────────────

/// Test helper: extract fields from a Relaxation variant, panicking on Structural.
fn unwrap_relaxation(v: &MonotonicityViolation) -> (&str, PolicyDecision, PolicyDecision) {
    match v {
        MonotonicityViolation::Relaxation {
            path,
            user_decision,
            project_decision,
        } => (path.as_str(), *user_decision, *project_decision),
        other => panic!("expected Relaxation, got {other:?}"),
    }
}

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
            opaque_env_ceiling: None,
            path_rules: None,
            overrides: None,
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
        ..PolicyConfig::default()
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
        ..PolicyConfig::default()
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
    assert_eq!(
        unwrap_relaxation(&violations[0]).0,
        "policy.defaults.mutating"
    );
    assert_eq!(unwrap_relaxation(&violations[0]).1, PolicyDecision::Deny);
    assert_eq!(unwrap_relaxation(&violations[0]).2, PolicyDecision::Ask);
}

#[test]
fn monotonicity_project_weakens_command_flat() {
    let mut commands = HashMap::new();
    commands.insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Deny));

    let user_policy = PolicyConfig {
        defaults: EffectDefaults::default(),
        commands,
        ..PolicyConfig::default()
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
    assert_eq!(unwrap_relaxation(&violations[0]).0, "policy.commands.rm");
}

#[test]
fn monotonicity_project_tightens_command_is_ok() {
    let mut commands = HashMap::new();
    commands.insert("git".into(), CommandPolicy::Flat(PolicyDecision::Allow));

    let user_policy = PolicyConfig {
        defaults: EffectDefaults::default(),
        commands,
        ..PolicyConfig::default()
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
        ..PolicyConfig::default()
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
    assert_eq!(
        unwrap_relaxation(&violations[0]).0,
        "policy.commands.git.subcommands.push"
    );
    assert_eq!(unwrap_relaxation(&violations[0]).1, PolicyDecision::Deny);
    assert_eq!(unwrap_relaxation(&violations[0]).2, PolicyDecision::Allow);
}

#[test]
fn monotonicity_project_removes_user_command_is_violation() {
    let mut commands = HashMap::new();
    commands.insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Deny));

    let user_policy = PolicyConfig {
        defaults: EffectDefaults::default(),
        commands,
        ..PolicyConfig::default()
    };

    // Project tries to remove the user's rm policy
    let project = PolicyOverlay {
        remove_commands: vec!["rm".into()],
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert_eq!(violations.len(), 1);
    assert!(
        matches!(&violations[0], MonotonicityViolation::Relaxation { path, .. } if path.contains("remove_commands"))
    );
}

#[test]
fn monotonicity_project_removes_nonexistent_command_is_ok() {
    let user_policy = PolicyConfig {
        defaults: EffectDefaults::default(),
        commands: HashMap::new(),
        ..PolicyConfig::default()
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
        ..PolicyConfig::default()
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
        ..PolicyConfig::default()
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

// ── 2. Layer merge semantics: user overrides defaults, project overrides user ─

#[test]
fn user_layer_overrides_defaults() {
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

    let result = ProdagentConfig::from_layers(defaults, Some(user), None);

    // User layer overrides read_only from Allow → Ask
    assert_eq!(
        result.policy.defaults.read_only,
        PolicyDecision::Ask,
        "user layer should override default read_only"
    );
    // Unset fields in user layer inherit from defaults
    assert_eq!(
        result.policy.defaults.mutating,
        PolicyDecision::Ask,
        "mutating should retain default value"
    );
    assert_eq!(
        result.policy.defaults.unknown,
        PolicyDecision::Ask,
        "unknown should retain default value"
    );
}

#[test]
fn project_layer_overrides_user_layer() {
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

    let result = ProdagentConfig::from_layers(defaults, Some(user), Some(project));

    // Project layer overrides user's Ask → Deny
    assert_eq!(
        result.policy.defaults.read_only,
        PolicyDecision::Deny,
        "project layer should override user read_only"
    );
    // Project layer overrides git: Allow → Deny
    let git_policy = result.policy.commands.get("git");
    assert!(
        git_policy.is_some(),
        "git should be present in merged commands"
    );
    assert_eq!(
        *git_policy.unwrap(),
        CommandPolicy::Flat(PolicyDecision::Deny),
        "project should override user's git policy"
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
        .user_config(camino::Utf8PathBuf::from_path_buf(user_path).unwrap())
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
        .project_config(camino::Utf8PathBuf::from_path_buf(project_path).unwrap())
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
        .user_config(camino::Utf8PathBuf::from_path_buf(user_path).unwrap())
        .project_config(camino::Utf8PathBuf::from_path_buf(project_path).unwrap())
        .load();

    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::Monotonicity(violations) => {
            assert_eq!(violations.len(), 1);
            assert_eq!(
                unwrap_relaxation(&violations[0]).0,
                "policy.defaults.read_only"
            );
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
        ..PolicyConfig::default()
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
        ..PolicyConfig::default()
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
    let v = MonotonicityViolation::Relaxation {
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

// ── 11. Path-scoped rules ─────────────────────────────────────────────────

#[test]
fn monotonicity_path_rule_tightens_is_ok() {
    use prodagent_policy::path_rules::{PathGlob, PathRule};

    let user_policy = PolicyConfig {
        defaults: EffectDefaults {
            read_only: PolicyDecision::Allow,
            mutating: PolicyDecision::Ask,
            unknown: PolicyDecision::Ask,
        },
        commands: HashMap::new(),
        ..PolicyConfig::default()
    };

    // Project adds a path rule that tightens to Deny — monotonic
    let project = PolicyOverlay {
        path_rules: Some(vec![PathRule {
            paths: vec![PathGlob::try_from("/sensitive/*").unwrap()],
            decision: PolicyDecision::Deny,
            command: None,
        }]),
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert!(violations.is_empty(), "tightening path rule should be ok");
}

#[test]
fn monotonicity_path_rule_weakens_is_violation() {
    use prodagent_policy::path_rules::{PathGlob, PathRule};

    let user_policy = PolicyConfig {
        defaults: EffectDefaults {
            read_only: PolicyDecision::Ask,
            mutating: PolicyDecision::Ask,
            unknown: PolicyDecision::Ask,
        },
        commands: HashMap::new(),
        ..PolicyConfig::default()
    };

    // Project tries to add a path rule that weakens to Allow
    let project = PolicyOverlay {
        path_rules: Some(vec![PathRule {
            paths: vec![PathGlob::try_from("/tmp/*").unwrap()],
            decision: PolicyDecision::Allow,
            command: None,
        }]),
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert_eq!(violations.len(), 1, "weakening path rule should be caught");
    assert!(
        matches!(&violations[0], MonotonicityViolation::Relaxation { path, .. } if path.contains("path_rules"))
    );
    assert_eq!(
        unwrap_relaxation(&violations[0]).1,
        PolicyDecision::Ask,
        "user floor should be Ask (strongest effect default)"
    );
    assert_eq!(
        unwrap_relaxation(&violations[0]).2,
        PolicyDecision::Allow,
        "project tried to weaken to Allow"
    );
}

#[test]
fn monotonicity_path_rule_weakens_command_is_violation() {
    use prodagent_policy::path_rules::{PathGlob, PathRule};

    let mut commands = HashMap::new();
    commands.insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Deny));

    let user_policy = PolicyConfig {
        defaults: EffectDefaults::default(),
        commands,
        ..PolicyConfig::default()
    };

    // Project tries to use a path-scoped rule to Allow rm in /tmp
    let project = PolicyOverlay {
        path_rules: Some(vec![PathRule {
            paths: vec![PathGlob::try_from("/tmp/*").unwrap()],
            decision: PolicyDecision::Allow,
            command: Some("rm".to_string()),
        }]),
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert_eq!(
        violations.len(),
        1,
        "path rule weakening a user-denied command should be caught"
    );
    assert!(
        matches!(&violations[0], MonotonicityViolation::Relaxation { path, .. } if path.contains("command=rm"))
    );
    assert_eq!(
        unwrap_relaxation(&violations[0]).1,
        PolicyDecision::Deny,
        "user denied rm"
    );
    assert_eq!(
        unwrap_relaxation(&violations[0]).2,
        PolicyDecision::Allow,
        "project tried to allow rm via path rule"
    );
}

#[test]
fn path_rules_overlay_prepends() {
    use prodagent_policy::path_rules::{PathGlob, PathRule};

    let defaults = default_layer();
    let user = ConfigLayer {
        policy: PolicyOverlay {
            path_rules: Some(vec![PathRule {
                paths: vec![PathGlob::try_from("/tmp/*").unwrap()],
                decision: PolicyDecision::Ask,
                command: None,
            }]),
            ..Default::default()
        },
        ..Default::default()
    };
    let project = ConfigLayer {
        policy: PolicyOverlay {
            path_rules: Some(vec![PathRule {
                paths: vec![PathGlob::try_from("/tmp/scratch/*").unwrap()],
                decision: PolicyDecision::Deny,
                command: None,
            }]),
            ..Default::default()
        },
        ..Default::default()
    };

    let config = ProdagentConfig::from_layers(defaults, Some(user), Some(project));
    assert_eq!(config.policy.path_rules.len(), 2);
    // Project rules are prepended (higher priority)
    assert_eq!(
        config.policy.path_rules[0].paths,
        vec![PathGlob::try_from("/tmp/scratch/*").unwrap()]
    );
    assert_eq!(
        config.policy.path_rules[1].paths,
        vec![PathGlob::try_from("/tmp/*").unwrap()]
    );

    // Verify decision values survived the merge
    assert_eq!(
        config.policy.path_rules[0].decision,
        PolicyDecision::Deny,
        "project rule decision should be preserved"
    );
    assert_eq!(
        config.policy.path_rules[1].decision,
        PolicyDecision::Ask,
        "user rule decision should be preserved"
    );
}

#[test]
fn toml_path_rules_round_trip() {
    use prodagent_policy::path_rules::PathGlob;

    let toml_str = r#"
[policy.defaults]
read_only = "allow"

[[policy.path_rules]]
paths = ["~/dev/*", "/tmp/*"]
decision = "allow"

[[policy.path_rules]]
paths = ["/etc/*"]
decision = "deny"
command = "rm"
"#;

    let layer: ConfigLayer = toml::from_str(toml_str).expect("TOML should parse");
    let rules = layer.policy.path_rules.expect("path_rules should be Some");
    assert_eq!(rules.len(), 2);
    assert_eq!(
        rules[0].paths,
        vec![
            PathGlob::try_from("~/dev/*").unwrap(),
            PathGlob::try_from("/tmp/*").unwrap()
        ]
    );
    assert_eq!(rules[0].decision, PolicyDecision::Allow);
    assert_eq!(rules[0].command, None);
    assert_eq!(rules[1].paths, vec![PathGlob::try_from("/etc/*").unwrap()]);
    assert_eq!(rules[1].decision, PolicyDecision::Deny);
    assert_eq!(rules[1].command, Some("rm".to_string()));
}

#[test]
fn loader_path_rules_from_toml() {
    use crate::ConfigLoader;

    let dir = tempfile::tempdir().expect("tempdir");
    let user_path = dir.path().join("config.toml");
    std::fs::write(
        &user_path,
        r#"
[[policy.path_rules]]
paths = ["/tmp/*"]
decision = "allow"
"#,
    )
    .unwrap();

    let config = ConfigLoader::new()
        .user_config(camino::Utf8PathBuf::from_path_buf(user_path).unwrap())
        .load()
        .expect("should load");

    assert_eq!(config.policy.path_rules.len(), 1);
    assert_eq!(
        config.policy.path_rules[0].paths,
        vec![prodagent_policy::PathGlob::try_from("/tmp/*").unwrap()]
    );
    assert_eq!(config.policy.path_rules[0].decision, PolicyDecision::Allow);
}

#[test]
fn loader_rejects_monotonicity_violation_path_rules() {
    use crate::loader::ConfigError;
    use crate::ConfigLoader;

    let dir = tempfile::tempdir().expect("tempdir");

    // User config sets defaults to Ask
    let user_path = dir.path().join("user.toml");
    std::fs::write(
        &user_path,
        r#"
[policy.defaults]
read_only = "ask"
"#,
    )
    .unwrap();

    // Project tries to weaken via a path rule (Allow when user floor is Ask)
    let project_path = dir.path().join("project.toml");
    std::fs::write(
        &project_path,
        r#"
[[policy.path_rules]]
paths = ["/tmp/*"]
decision = "allow"
"#,
    )
    .unwrap();

    let result = ConfigLoader::new()
        .user_config(camino::Utf8PathBuf::from_path_buf(user_path).unwrap())
        .project_config(camino::Utf8PathBuf::from_path_buf(project_path).unwrap())
        .load();

    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::Monotonicity(violations) => {
            assert_eq!(violations.len(), 1);
            assert!(
                matches!(&violations[0], MonotonicityViolation::Relaxation { path, .. } if path.contains("path_rules"))
            );
        }
        other => panic!("expected Monotonicity error, got: {other}"),
    }
}

#[test]
fn monotonicity_unscoped_path_rule_weakens_mutating_via_mixed_defaults() {
    use prodagent_policy::path_rules::{PathGlob, PathRule};

    // User has read_only: Allow, mutating: Ask — the typical default config.
    // A project adds an unscoped Allow path rule. With the old (incorrect)
    // weakest_effect_default floor, Allow >= Allow would pass. With the
    // correct strongest_effect_default floor, Allow < Ask is a violation.
    let user_policy = PolicyConfig {
        defaults: EffectDefaults {
            read_only: PolicyDecision::Allow,
            mutating: PolicyDecision::Ask,
            unknown: PolicyDecision::Ask,
        },
        commands: HashMap::new(),
        ..PolicyConfig::default()
    };

    let project = PolicyOverlay {
        path_rules: Some(vec![PathRule {
            paths: vec![PathGlob::try_from("/project/*").unwrap()],
            decision: PolicyDecision::Allow,
            command: None,
        }]),
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert_eq!(
        violations.len(),
        1,
        "unscoped Allow path rule must not bypass mutating: Ask — \
         the floor for unscoped rules is the strongest effect default"
    );
    assert_eq!(unwrap_relaxation(&violations[0]).1, PolicyDecision::Ask);
    assert_eq!(unwrap_relaxation(&violations[0]).2, PolicyDecision::Allow);
}

#[test]
fn monotonicity_command_scoped_path_rule_weakens_via_mixed_defaults() {
    use prodagent_policy::path_rules::{PathGlob, PathRule};

    // User has the typical mixed defaults: Allow for read-only, Ask for
    // mutating/unknown. No per-command override for "rm".
    //
    // A project adds a command-scoped Allow path rule for "rm". With the
    // old (incorrect) weakest_effect_default floor, Allow >= Allow would
    // pass. But "rm" is mutating → the user's actual floor is Ask, and
    // the path rule bypasses it at tier 1 (decision used directly, no
    // max(command_default) composition).
    //
    // The fix uses strongest_effect_default as a conservative floor when
    // no per-command override exists. See Invariant #6b in prodagent-proofs.
    let user_policy = PolicyConfig {
        defaults: EffectDefaults {
            read_only: PolicyDecision::Allow,
            mutating: PolicyDecision::Ask,
            unknown: PolicyDecision::Ask,
        },
        commands: HashMap::new(),
        ..PolicyConfig::default()
    };

    let project = PolicyOverlay {
        path_rules: Some(vec![PathRule {
            paths: vec![PathGlob::try_from("/project/*").unwrap()],
            decision: PolicyDecision::Allow,
            command: Some("rm".to_string()),
        }]),
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert_eq!(
        violations.len(),
        1,
        "command-scoped Allow path rule must not bypass mutating: Ask — \
         the floor for command-scoped rules without a per-command override \
         is the strongest effect default"
    );
    assert_eq!(unwrap_relaxation(&violations[0]).1, PolicyDecision::Ask);
    assert_eq!(unwrap_relaxation(&violations[0]).2, PolicyDecision::Allow);
}

// ── 12. Per-command override floor (issue #80) ─────────────────────────────

#[test]
fn monotonicity_command_override_weakens_via_mixed_defaults() {
    // Regression test for issue #80: resolve_command_decision used
    // weakest_effect_default as the floor, letting a project add
    // `rm: Allow` when the user has `mutating: Ask` but no per-command
    // override for `rm`. The weakest default (read_only: Allow) passed
    // validation, but at runtime `rm` is mutating (floor: Ask).
    //
    // Fix: use strongest_effect_default as the floor, matching the
    // path_rule_floor logic from PR #77.
    let user_policy = PolicyConfig {
        defaults: EffectDefaults {
            read_only: PolicyDecision::Allow,
            mutating: PolicyDecision::Ask,
            unknown: PolicyDecision::Ask,
        },
        commands: HashMap::new(),
        ..PolicyConfig::default()
    };

    // Project adds a flat Allow for rm — should be caught
    let mut proj_commands = HashMap::new();
    proj_commands.insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Allow));

    let project = PolicyOverlay {
        commands: proj_commands,
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert_eq!(
        violations.len(),
        1,
        "project `rm: Allow` must not bypass user `mutating: Ask` — \
         the floor for commands without a per-command override is the \
         strongest effect default"
    );
    assert_eq!(unwrap_relaxation(&violations[0]).0, "policy.commands.rm");
    assert_eq!(unwrap_relaxation(&violations[0]).1, PolicyDecision::Ask);
    assert_eq!(unwrap_relaxation(&violations[0]).2, PolicyDecision::Allow);
}

#[test]
fn monotonicity_command_override_tightens_with_mixed_defaults_is_ok() {
    // Counterpart to the regression test above: tightening a command
    // beyond the strongest effect default is always allowed.
    let user_policy = PolicyConfig {
        defaults: EffectDefaults {
            read_only: PolicyDecision::Allow,
            mutating: PolicyDecision::Ask,
            unknown: PolicyDecision::Ask,
        },
        commands: HashMap::new(),
        ..PolicyConfig::default()
    };

    // Project adds rm: Deny — tighter than any default, always ok
    let mut proj_commands = HashMap::new();
    proj_commands.insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Deny));

    let project = PolicyOverlay {
        commands: proj_commands,
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert!(
        violations.is_empty(),
        "tightening beyond strongest default should be allowed"
    );
}

#[test]
fn monotonicity_command_override_ask_with_mixed_defaults_is_ok() {
    // Edge case: project sets rm: Ask, user strongest default is Ask.
    // Same decision = no violation.
    let user_policy = PolicyConfig {
        defaults: EffectDefaults {
            read_only: PolicyDecision::Allow,
            mutating: PolicyDecision::Ask,
            unknown: PolicyDecision::Ask,
        },
        commands: HashMap::new(),
        ..PolicyConfig::default()
    };

    let mut proj_commands = HashMap::new();
    proj_commands.insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Ask));

    let project = PolicyOverlay {
        commands: proj_commands,
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert!(
        violations.is_empty(),
        "matching the strongest default should not violate"
    );
}

#[test]
fn monotonicity_subcommand_override_weakens_via_mixed_defaults() {
    // Same vulnerability pattern as #80 but for subcommand overrides.
    // resolve_subcommand_decision had the same weakest_effect_default bug.
    let user_policy = PolicyConfig {
        defaults: EffectDefaults {
            read_only: PolicyDecision::Allow,
            mutating: PolicyDecision::Ask,
            unknown: PolicyDecision::Ask,
        },
        commands: HashMap::new(),
        ..PolicyConfig::default()
    };

    // Project adds git.push: Allow via detailed policy (no user override for git)
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
    assert_eq!(
        violations.len(),
        1,
        "project `git.push: Allow` must not bypass user `mutating: Ask` — \
         subcommand floor must also use strongest effect default"
    );
    assert_eq!(
        unwrap_relaxation(&violations[0]).0,
        "policy.commands.git.subcommands.push"
    );
    assert_eq!(unwrap_relaxation(&violations[0]).1, PolicyDecision::Ask);
    assert_eq!(unwrap_relaxation(&violations[0]).2, PolicyDecision::Allow);
}

#[test]
fn monotonicity_detailed_base_weakens_via_mixed_defaults() {
    // Variant: project sets a detailed command policy with base: Allow
    // and no subcommands, no user override for the command.
    let user_policy = PolicyConfig {
        defaults: EffectDefaults {
            read_only: PolicyDecision::Allow,
            mutating: PolicyDecision::Ask,
            unknown: PolicyDecision::Deny,
        },
        commands: HashMap::new(),
        ..PolicyConfig::default()
    };

    let mut proj_commands = HashMap::new();
    proj_commands.insert(
        "docker".into(),
        CommandPolicy::Detailed(DetailedCommandPolicy {
            base: Some(PolicyDecision::Allow),
            subcommands: HashMap::new(),
        }),
    );

    let project = PolicyOverlay {
        commands: proj_commands,
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert_eq!(
        violations.len(),
        1,
        "project `docker.base: Allow` must not bypass user `unknown: Deny` — \
         strongest default is Deny"
    );
    assert_eq!(
        unwrap_relaxation(&violations[0]).0,
        "policy.commands.docker.base"
    );
    assert_eq!(unwrap_relaxation(&violations[0]).1, PolicyDecision::Deny);
    assert_eq!(unwrap_relaxation(&violations[0]).2, PolicyDecision::Allow);
}

#[test]
fn monotonicity_command_override_weakens_with_uniform_defaults() {
    // Edge case: all defaults are the same (weakest == strongest).
    // The fix doesn't change behavior here, but this test guards
    // against regressions in strongest_effect_default itself.
    let user_policy = PolicyConfig {
        defaults: EffectDefaults {
            read_only: PolicyDecision::Ask,
            mutating: PolicyDecision::Ask,
            unknown: PolicyDecision::Ask,
        },
        commands: HashMap::new(),
        ..PolicyConfig::default()
    };

    let mut proj_commands = HashMap::new();
    proj_commands.insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Allow));

    let project = PolicyOverlay {
        commands: proj_commands,
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert_eq!(
        violations.len(),
        1,
        "uniform Ask defaults: project rm: Allow must still be caught"
    );
    assert_eq!(unwrap_relaxation(&violations[0]).0, "policy.commands.rm");
    assert_eq!(unwrap_relaxation(&violations[0]).1, PolicyDecision::Ask);
    assert_eq!(unwrap_relaxation(&violations[0]).2, PolicyDecision::Allow);
}

// ── Overrides: project config must not contain overrides ──────────────────

#[test]
fn monotonicity_project_overrides_are_rejected() {
    use prodagent_policy::config::OverrideConfig;

    let user_policy = PolicyConfig::default();

    let project = PolicyOverlay {
        overrides: Some(OverrideConfig {
            commands: {
                let mut m = HashMap::new();
                m.insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Allow));
                m
            },
            path_rules: vec![],
        }),
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert!(
        !violations.is_empty(),
        "project config with overrides should be a monotonicity violation"
    );
    assert!(
        violations.iter().any(|v| matches!(
            v,
            MonotonicityViolation::Structural { path, reason }
                if path.contains("overrides") && reason.contains("must not contain")
        )),
        "violation should reference overrides path"
    );
}

#[test]
fn monotonicity_project_empty_overrides_are_ok() {
    use prodagent_policy::config::OverrideConfig;

    let user_policy = PolicyConfig::default();

    // Empty overrides section should not trigger a violation
    let project = PolicyOverlay {
        overrides: Some(OverrideConfig::default()),
        ..Default::default()
    };

    let violations = validate_monotonicity(&user_policy, &project);
    assert!(
        violations.is_empty(),
        "empty overrides should not be a violation: {violations:?}"
    );
}

// ── Override layer merging ───────────────────────────────────────────────

#[test]
fn user_overrides_survive_project_merge() {
    use prodagent_policy::config::OverrideConfig;

    let base = default_layer();

    let user = ConfigLayer {
        policy: PolicyOverlay {
            overrides: Some(OverrideConfig {
                commands: {
                    let mut m = HashMap::new();
                    m.insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Allow));
                    m
                },
                path_rules: vec![],
            }),
            ..Default::default()
        },
        ..Default::default()
    };

    // Project layer with a restriction on rm
    let project = ConfigLayer {
        policy: PolicyOverlay {
            commands: {
                let mut m = HashMap::new();
                m.insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Deny));
                m
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let config = ProdagentConfig::from_layers(base, Some(user), Some(project));

    // The override should be preserved in the merged config
    assert!(
        matches!(
            config.policy.overrides.commands.get("rm"),
            Some(CommandPolicy::Flat(PolicyDecision::Allow))
        ),
        "user override for rm should survive project merge"
    );

    // The merged policy should have Deny for rm (from project)
    assert!(
        matches!(
            config.policy.commands.get("rm"),
            Some(CommandPolicy::Flat(PolicyDecision::Deny))
        ),
        "project Deny for rm should be in merged commands"
    );
}

// ── Conflict detection model ────────────────────────────────────────────

#[test]
fn conflict_detected_when_project_stricter() {
    use prodagent_policy::PolicyEngine;

    let kb = agent_command_knowledge::default_knowledge_base();

    // User config: rm uses default effect mapping (mutating -> Ask)
    let user_policy = PolicyConfig::default();
    let user_engine = PolicyEngine::new(user_policy).unwrap();

    // Merged config: project adds Deny for rm
    let mut merged_policy = PolicyConfig::default();
    merged_policy
        .commands
        .insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Deny));
    let merged_engine = PolicyEngine::new(merged_policy).unwrap();

    let user_result = user_engine.evaluate_command("rm /tmp/foo", kb);
    let merged_result = merged_engine.evaluate_command("rm /tmp/foo", kb);

    // merged is stricter -> conflict
    assert!(
        merged_result.decision > user_result.decision,
        "merged should be stricter: merged={:?}, user={:?}",
        merged_result.decision,
        user_result.decision
    );
}

#[test]
fn no_conflict_when_user_stricter() {
    use prodagent_policy::PolicyEngine;

    let kb = agent_command_knowledge::default_knowledge_base();

    // User config: rm is Deny
    let mut user_policy = PolicyConfig::default();
    user_policy
        .commands
        .insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Deny));
    let user_engine = PolicyEngine::new(user_policy).unwrap();

    // Merged config: project keeps rm at Ask (user is stricter)
    let merged_policy = PolicyConfig::default();
    let merged_engine = PolicyEngine::new(merged_policy).unwrap();

    // When user is stricter, the merged result will also be strict because
    // in the real cascade, max(user, project) >= user. But if merged_result
    // <= user_result, there's no conflict from the project.
    let user_result = user_engine.evaluate_command("rm /tmp/foo", kb);
    let merged_result = merged_engine.evaluate_command("rm /tmp/foo", kb);

    // In this test the user config is stricter (Deny vs Ask), so the user
    // result should be >= merged. In real config loading, the merged would
    // include the user's Deny too, but this demonstrates the concept.
    assert!(
        user_result.decision >= merged_result.decision,
        "user should be at least as strict: user={:?}, merged={:?}",
        user_result.decision,
        merged_result.decision
    );
}

#[test]
fn override_resolves_conflict_on_subsequent_eval() {
    use prodagent_policy::PolicyEngine;

    let kb = agent_command_knowledge::default_knowledge_base();

    // Merged config: project denies rm, but user has an override
    let mut merged_policy = PolicyConfig::default();
    merged_policy
        .commands
        .insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Deny));
    merged_policy
        .overrides
        .commands
        .insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Allow));
    let merged_engine = PolicyEngine::new(merged_policy).unwrap();

    let result = merged_engine.evaluate_command("rm /tmp/foo", kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Allow,
        "override should resolve the project-vs-user conflict"
    );

    // Without the override, the merged result would be Deny (project restriction).
    // With the override, it's Allow. Verify the override actually changed the outcome.
    let mut merged_no_override = PolicyConfig::default();
    merged_no_override
        .commands
        .insert("rm".into(), CommandPolicy::Flat(PolicyDecision::Deny));
    let engine_no_override = PolicyEngine::new(merged_no_override).unwrap();
    let result_no_override = engine_no_override.evaluate_command("rm /tmp/foo", kb);

    assert_eq!(
        result_no_override.decision,
        PolicyDecision::Deny,
        "without override, project Deny should apply"
    );
    assert!(
        result.decision < result_no_override.decision,
        "override should produce a less strict decision than the project restriction: \
         with_override={:?}, without_override={:?}",
        result.decision,
        result_no_override.decision,
    );
}
