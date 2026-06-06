use agent_types::Word;

use crate::lookup::classify;
use crate::types::*;

use super::*;

// ── helpers ──────────────────────────────────────────────────────────────────

fn base_kb() -> KnowledgeBase {
    let mut kb = KnowledgeBase::default();

    let mut subs = SubcommandMap::new();
    subs.insert("status", SubcommandEntry::with_effect(Effect::ReadOnly));
    subs.insert("push", SubcommandEntry::with_effect(Effect::Mutating));

    kb.commands.insert(
        "git".into(),
        CommandKnowledge {
            name: "git".into(),
            effect: Effect::Unknown,
            subcommands: subs,
            flags: FlagSchema {
                skip_arg: vec!["-C".into()],
                skip_solo: vec!["--bare".into()],
                escalation: vec!["--force".into()],
                path: vec!["-C".into()],
            },
            env_gates: vec![EnvGate::Grant {
                var: "GIT_DIR".into(),
                value: "/repo".into(),
                unlocks: Effect::ReadOnly,
            }],
            paths: PathSpec {
                positionals: PathPositionals::None,
                flags: vec!["-C".into()],
            },
            properties: CommandProperties {
                version_flag: Some("--version".into()),
            },
        },
    );

    let mut rm = CommandKnowledge::simple("rm", Effect::Mutating);
    rm.paths = PathSpec {
        positionals: PathPositionals::All,
        flags: vec![],
    };
    kb.commands.insert("rm".into(), rm);

    kb.wrappers.insert(
        "sudo".into(),
        WrapperKnowledge {
            name: "sudo".into(),
            floor_effect: Effect::Mutating,
            clears_env: false,
            escalates_privilege: true,
        },
    );

    kb
}

fn empty_overlay() -> KnowledgeOverlay {
    KnowledgeOverlay::default()
}

// ── 1. Add new command ──────────────────────────────────────────────────────

#[test]
fn add_new_command() {
    let mut kb = base_kb();
    let mut overlay = empty_overlay();
    overlay.commands.insert(
        "cargo".into(),
        CommandOverlay::with_effect(Effect::Mutating),
    );

    kb.merge(overlay);

    let cargo = kb.commands.get("cargo").expect("cargo should exist");
    assert_eq!(cargo.name, "cargo");
    assert_eq!(cargo.effect, Effect::Mutating);
}

// ── 2. Remove command ───────────────────────────────────────────────────────

#[test]
fn remove_command() {
    let mut kb = base_kb();
    assert!(kb.commands.contains_key("rm"));

    let mut overlay = empty_overlay();
    overlay.remove_commands.push("rm".into());

    kb.merge(overlay);

    assert!(!kb.commands.contains_key("rm"), "rm should be removed");
    // git should be untouched.
    assert!(kb.commands.contains_key("git"));
}

// ── 3. Remove wrapper ──────────────────────────────────────────────────────

#[test]
fn remove_wrapper() {
    let mut kb = base_kb();
    assert!(kb.wrappers.contains_key("sudo"));

    let mut overlay = empty_overlay();
    overlay.remove_wrappers.push("sudo".into());

    kb.merge(overlay);

    assert!(!kb.wrappers.contains_key("sudo"), "sudo should be removed");
}

// ── 4. Merge subcommands ────────────────────────────────────────────────────

#[test]
fn merge_subcommands_into_existing_command() {
    let mut kb = base_kb();
    let mut overlay = empty_overlay();

    let mut new_subs = SubcommandMap::new();
    new_subs.insert("fetch", SubcommandEntry::with_effect(Effect::Mutating));
    overlay.commands.insert(
        "git".into(),
        CommandOverlay {
            subcommands: new_subs,
            ..Default::default()
        },
    );

    kb.merge(overlay);

    let git = kb.commands.get("git").unwrap();
    assert!(git.subcommands.get("fetch").is_some(), "fetch should exist");
    // Original subcommands preserved.
    assert!(git.subcommands.get("status").is_some());
    assert!(git.subcommands.get("push").is_some());
}

// ── 5. Override subcommand ──────────────────────────────────────────────────

#[test]
fn override_existing_subcommand_effect() {
    let mut kb = base_kb();
    let mut overlay = empty_overlay();

    let mut override_subs = SubcommandMap::new();
    override_subs.insert("push", SubcommandEntry::with_effect(Effect::Unknown));
    overlay.commands.insert(
        "git".into(),
        CommandOverlay {
            subcommands: override_subs,
            ..Default::default()
        },
    );

    kb.merge(overlay);

    let git = kb.commands.get("git").unwrap();
    assert_eq!(
        git.subcommands.get("push").unwrap().effect,
        Effect::Unknown,
        "push effect should be overridden"
    );
    // status untouched.
    assert_eq!(
        git.subcommands.get("status").unwrap().effect,
        Effect::ReadOnly,
    );
}

// ── 6. Remove subcommand ────────────────────────────────────────────────────

#[test]
fn remove_subcommand() {
    let mut kb = base_kb();
    assert!(kb
        .commands
        .get("git")
        .unwrap()
        .subcommands
        .get("push")
        .is_some());

    let mut overlay = empty_overlay();
    overlay.commands.insert(
        "git".into(),
        CommandOverlay {
            remove_subcommands: vec!["push".into()],
            ..Default::default()
        },
    );

    kb.merge(overlay);

    let git = kb.commands.get("git").unwrap();
    assert!(
        git.subcommands.get("push").is_none(),
        "push should be removed"
    );
    assert!(git.subcommands.get("status").is_some(), "status preserved");
}

// ── 7. Override effect ──────────────────────────────────────────────────────

#[test]
fn override_effect() {
    let mut kb = base_kb();
    assert_eq!(kb.commands.get("git").unwrap().effect, Effect::Unknown);

    let mut overlay = empty_overlay();
    overlay
        .commands
        .insert("git".into(), CommandOverlay::with_effect(Effect::Mutating));

    kb.merge(overlay);

    assert_eq!(kb.commands.get("git").unwrap().effect, Effect::Mutating);
}

// ── 8. Preserve effect ─────────────────────────────────────────────────────

#[test]
fn preserve_effect_when_not_specified() {
    let mut kb = base_kb();
    let original_effect = kb.commands.get("git").unwrap().effect;

    let mut overlay = empty_overlay();
    overlay.commands.insert(
        "git".into(),
        CommandOverlay::default(), // effect not specified
    );

    kb.merge(overlay);

    assert_eq!(
        kb.commands.get("git").unwrap().effect,
        original_effect,
        "effect should be preserved when not specified"
    );
}

// ── 9. Extend flags ────────────────────────────────────────────────────────

#[test]
fn extend_flags() {
    let mut kb = base_kb();
    let original_skip_arg_len = kb.commands.get("git").unwrap().flags.skip_arg.len();

    let mut overlay = empty_overlay();
    overlay.commands.insert(
        "git".into(),
        CommandOverlay {
            flags: FlagSchema {
                skip_arg: vec!["--work-tree".into()],
                skip_solo: vec!["--no-pager".into()],
                escalation: vec!["--force-with-lease".into()],
                path: vec!["--work-tree".into()],
            },
            ..Default::default()
        },
    );

    kb.merge(overlay);

    let git = kb.commands.get("git").unwrap();
    assert_eq!(
        git.flags.skip_arg.len(),
        original_skip_arg_len + 1,
        "skip_arg should be extended"
    );
    assert!(git.flags.skip_arg.contains(&"--work-tree".into()));
    assert!(
        git.flags.skip_arg.contains(&"-C".into()),
        "original preserved"
    );
    assert!(git.flags.skip_solo.contains(&"--no-pager".into()));
    assert!(git.flags.escalation.contains(&"--force-with-lease".into()));
    assert!(git.flags.path.contains(&"--work-tree".into()));
}

// ── 10. Extend env_gates ────────────────────────────────────────────────────

#[test]
fn extend_env_gates() {
    let mut kb = base_kb();
    assert_eq!(kb.commands.get("git").unwrap().env_gates.len(), 1);

    let mut overlay = empty_overlay();
    overlay.commands.insert(
        "git".into(),
        CommandOverlay {
            env_gates: vec![EnvGate::Require {
                var: "GIT_AUTHOR_NAME".into(),
                value: "test".into(),
            }],
            ..Default::default()
        },
    );

    kb.merge(overlay);

    let git = kb.commands.get("git").unwrap();
    assert_eq!(git.env_gates.len(), 2, "env_gates should be extended");
}

// ── 11. Override paths ──────────────────────────────────────────────────────

#[test]
fn override_paths() {
    let mut kb = base_kb();

    let mut overlay = empty_overlay();
    let new_paths = PathSpec {
        positionals: PathPositionals::All,
        flags: vec!["--output".into()],
    };
    overlay.commands.insert(
        "git".into(),
        CommandOverlay {
            paths: Some(new_paths),
            ..Default::default()
        },
    );

    kb.merge(overlay);

    let git = kb.commands.get("git").unwrap();
    assert!(matches!(git.paths.positionals, PathPositionals::All));
    assert_eq!(git.paths.flags, vec!["--output".to_string()]);
}

// ── 12. Override properties ─────────────────────────────────────────────────

#[test]
fn override_properties() {
    let mut kb = base_kb();
    assert_eq!(
        kb.commands.get("git").unwrap().properties.version_flag,
        Some("--version".into()),
    );

    let mut overlay = empty_overlay();
    overlay.commands.insert(
        "git".into(),
        CommandOverlay {
            properties: Some(CommandProperties {
                version_flag: Some("-V".into()),
            }),
            ..Default::default()
        },
    );

    kb.merge(overlay);

    assert_eq!(
        kb.commands.get("git").unwrap().properties.version_flag,
        Some("-V".into()),
    );
}

// ── 13. Add wrapper ─────────────────────────────────────────────────────────

#[test]
fn add_new_wrapper() {
    let mut kb = base_kb();
    assert!(!kb.wrappers.contains_key("env"));

    let mut overlay = empty_overlay();
    overlay.wrappers.insert(
        "env".into(),
        WrapperOverlay {
            floor_effect: Some(Effect::ReadOnly),
            clears_env: Some(true),
            escalates_privilege: Some(false),
        },
    );

    kb.merge(overlay);

    let env_w = kb.wrappers.get("env").expect("env wrapper should exist");
    assert_eq!(env_w.name, "env", "name should come from the key");
    assert_eq!(env_w.floor_effect, Effect::ReadOnly);
    assert!(env_w.clears_env);
    assert!(!env_w.escalates_privilege);
}

// ── 14. Replace wrapper ─────────────────────────────────────────────────────

#[test]
fn replace_existing_wrapper() {
    let mut kb = base_kb();
    assert!(kb.wrappers.get("sudo").unwrap().escalates_privilege);

    let mut overlay = empty_overlay();
    overlay.wrappers.insert(
        "sudo".into(),
        WrapperOverlay {
            floor_effect: Some(Effect::Mutating),
            clears_env: Some(true),
            escalates_privilege: Some(false),
        },
    );

    kb.merge(overlay);

    let sudo = kb.wrappers.get("sudo").unwrap();
    assert_eq!(sudo.floor_effect, Effect::Mutating, "floor_effect replaced");
    assert!(sudo.clears_env, "clears_env replaced");
    assert!(!sudo.escalates_privilege, "escalates_privilege replaced");
}

// ── 15. Remove then re-add ──────────────────────────────────────────────────

#[test]
fn remove_then_readd_replaces_command() {
    let mut kb = base_kb();
    // rm exists as Mutating with PathSpec::All
    assert_eq!(kb.commands.get("rm").unwrap().effect, Effect::Mutating);

    let mut overlay = empty_overlay();
    // Remove and re-add with different effect.
    overlay.remove_commands.push("rm".into());
    overlay
        .commands
        .insert("rm".into(), CommandOverlay::with_effect(Effect::ReadOnly));

    kb.merge(overlay);

    let rm = kb
        .commands
        .get("rm")
        .expect("rm should exist as replacement");
    assert_eq!(
        rm.effect,
        Effect::ReadOnly,
        "should be the replacement, not the original"
    );
    // Original paths should be gone — this is a fresh insertion.
    assert!(matches!(rm.paths.positionals, PathPositionals::None));
}

// ── 16. Empty overlay ───────────────────────────────────────────────────────

#[test]
fn empty_overlay_is_noop() {
    let kb_before = base_kb();
    let mut kb = base_kb();

    kb.merge(empty_overlay());

    assert_eq!(kb.commands.len(), kb_before.commands.len());
    assert_eq!(kb.wrappers.len(), kb_before.wrappers.len());
    // Spot check a few values.
    assert_eq!(
        kb.commands.get("git").unwrap().effect,
        kb_before.commands.get("git").unwrap().effect,
    );
    assert_eq!(
        kb.wrappers.get("sudo").unwrap().escalates_privilege,
        kb_before.wrappers.get("sudo").unwrap().escalates_privilege,
    );
}

// ── 17. New command defaults to Unknown ─────────────────────────────────────

#[test]
fn new_command_defaults_to_unknown() {
    let mut kb = base_kb();
    let mut overlay = empty_overlay();
    overlay.commands.insert(
        "my-tool".into(),
        CommandOverlay::default(), // effect deliberately omitted
    );

    kb.merge(overlay);

    let tool = kb.commands.get("my-tool").unwrap();
    assert_eq!(
        tool.effect,
        Effect::Unknown,
        "new command without effect should default to Unknown"
    );
}

// ── 18. Duplicate flags are tolerated ──────────────────────────────────────

#[test]
fn duplicate_flags_are_tolerated() {
    let mut kb = base_kb();
    assert!(kb
        .commands
        .get("git")
        .unwrap()
        .flags
        .escalation
        .contains(&"--force".into()));

    let mut overlay = empty_overlay();
    overlay.commands.insert(
        "git".into(),
        CommandOverlay {
            flags: FlagSchema {
                escalation: vec!["--force".into()],
                ..Default::default()
            },
            ..Default::default()
        },
    );

    kb.merge(overlay);

    let git = kb.commands.get("git").unwrap();
    let force_count = git
        .flags
        .escalation
        .iter()
        .filter(|f| f.as_str() == "--force")
        .count();
    assert_eq!(
        force_count, 2,
        "--force should appear twice after merge with duplicate"
    );
}

// ── 19. Subcommand remove and re-add in same overlay ──────────────────────

#[test]
fn subcommand_remove_and_readd_in_same_overlay() {
    let mut kb = base_kb();
    assert_eq!(
        kb.commands
            .get("git")
            .unwrap()
            .subcommands
            .get("push")
            .unwrap()
            .effect,
        Effect::Mutating,
    );

    let mut new_subs = SubcommandMap::new();
    new_subs.insert("push", SubcommandEntry::with_effect(Effect::Unknown));

    let mut overlay = empty_overlay();
    overlay.commands.insert(
        "git".into(),
        CommandOverlay {
            remove_subcommands: vec!["push".into()],
            subcommands: new_subs,
            ..Default::default()
        },
    );

    kb.merge(overlay);

    let git = kb.commands.get("git").unwrap();
    assert_eq!(
        git.subcommands.get("push").unwrap().effect,
        Effect::Unknown,
        "re-added push should have the overlay's effect"
    );
}

// ── 20. Removing nonexistent keys is a no-op ──────────────────────────────

#[test]
fn removing_nonexistent_keys_is_noop() {
    let kb_before = base_kb();
    let mut kb = base_kb();

    let mut overlay = empty_overlay();
    overlay.remove_commands.push("nonexistent-cmd".into());
    overlay.remove_wrappers.push("nonexistent-wrapper".into());
    overlay.commands.insert(
        "git".into(),
        CommandOverlay {
            remove_subcommands: vec!["nonexistent-sub".into()],
            ..Default::default()
        },
    );

    kb.merge(overlay);

    assert_eq!(kb.commands.len(), kb_before.commands.len());
    assert_eq!(kb.wrappers.len(), kb_before.wrappers.len());
    assert_eq!(
        kb.commands.get("git").unwrap().subcommands.len(),
        kb_before.commands.get("git").unwrap().subcommands.len(),
    );
}

// ── 21. TOML round-trip ─────────────────────────────────────────────────────

#[test]
fn toml_round_trip() {
    let overlay_toml = r#"
remove_commands = ["rm"]
remove_wrappers = ["sudo"]

[commands.kubectl]
effect = "mutating"

[commands.kubectl.subcommands.entries.get]
effect = "read-only"

[commands.kubectl.subcommands.entries.apply]
effect = "mutating"

[commands.kubectl.flags]
skip_arg = ["-n", "--namespace"]
escalation = ["--force"]

[commands.git]
# No effect — should preserve base effect.
remove_subcommands = ["push"]

[commands.git.subcommands.entries.stash]
effect = "mutating"

[wrappers.nice]
floor_effect = "read-only"
"#;

    let overlay: KnowledgeOverlay =
        toml::from_str(overlay_toml).expect("overlay TOML should parse");

    let mut kb = base_kb();
    kb.merge(overlay);

    // rm removed.
    assert!(!kb.commands.contains_key("rm"), "rm should be removed");
    // sudo removed.
    assert!(!kb.wrappers.contains_key("sudo"), "sudo should be removed");

    // kubectl added as new command.
    let kubectl = kb.commands.get("kubectl").expect("kubectl should exist");
    assert_eq!(kubectl.effect, Effect::Mutating);
    assert_eq!(
        kubectl.subcommands.get("get").unwrap().effect,
        Effect::ReadOnly,
    );
    assert_eq!(
        kubectl.subcommands.get("apply").unwrap().effect,
        Effect::Mutating,
    );
    assert!(kubectl.flags.skip_arg.contains(&"-n".into()));
    assert!(kubectl.flags.escalation.contains(&"--force".into()));

    // git: push removed, stash added, base effect preserved.
    let git = kb.commands.get("git").unwrap();
    assert_eq!(git.effect, Effect::Unknown, "base effect preserved");
    assert!(git.subcommands.get("push").is_none(), "push removed");
    assert!(git.subcommands.get("status").is_some(), "status preserved");
    assert_eq!(
        git.subcommands.get("stash").unwrap().effect,
        Effect::Mutating,
        "stash added",
    );

    // nice wrapper added — verify serde defaults for omitted fields.
    let nice = kb.wrappers.get("nice").expect("nice wrapper should exist");
    assert_eq!(nice.floor_effect, Effect::ReadOnly);
    assert!(!nice.clears_env, "clears_env should default to false");
    assert!(
        !nice.escalates_privilege,
        "escalates_privilege should default to false"
    );
}

// ── 22. Classify round-trip after merge ────────────────────────────────────

#[test]
fn classify_uses_merged_kb() {
    let mut kb = base_kb();

    let mut new_subs = SubcommandMap::new();
    new_subs.insert("stash", SubcommandEntry::with_effect(Effect::Mutating));

    let mut overlay = empty_overlay();
    overlay.commands.insert(
        "git".into(),
        CommandOverlay {
            subcommands: new_subs,
            ..Default::default()
        },
    );
    kb.merge(overlay);

    let words: Vec<Word> = ["git", "stash"].iter().map(|s| Word::from(*s)).collect();
    let info = classify(&words[0], &words, &kb);
    assert_eq!(info.effect, Effect::Mutating);
    assert_eq!(info.subcommand.as_deref(), Some("stash"));
}

// ── 23. Partial wrapper update preserves unspecified fields ───────────────

#[test]
fn partial_wrapper_update_preserves_unspecified_fields() {
    let mut kb = base_kb();
    // sudo starts with: floor_effect=Mutating, clears_env=false, escalates_privilege=true
    let sudo_before = kb.wrappers.get("sudo").unwrap().clone();
    assert_eq!(sudo_before.floor_effect, Effect::Mutating);
    assert!(!sudo_before.clears_env);
    assert!(sudo_before.escalates_privilege);

    let mut overlay = empty_overlay();
    overlay.wrappers.insert(
        "sudo".into(),
        WrapperOverlay {
            floor_effect: Some(Effect::Unknown),
            // clears_env and escalates_privilege deliberately omitted
            ..Default::default()
        },
    );

    kb.merge(overlay);

    let sudo = kb.wrappers.get("sudo").unwrap();
    assert_eq!(
        sudo.floor_effect,
        Effect::Unknown,
        "floor_effect should be overridden"
    );
    assert_eq!(
        sudo.clears_env, sudo_before.clears_env,
        "clears_env should be preserved from base"
    );
    assert_eq!(
        sudo.escalates_privilege, sudo_before.escalates_privilege,
        "escalates_privilege should be preserved from base"
    );
}

// ── 24. New wrapper defaults floor_effect to Unknown ─────────────────────

#[test]
fn new_wrapper_defaults_floor_effect_to_unknown() {
    let mut kb = base_kb();

    let mut overlay = empty_overlay();
    overlay.wrappers.insert(
        "my-wrapper".into(),
        WrapperOverlay::default(), // all fields omitted
    );

    kb.merge(overlay);

    let w = kb
        .wrappers
        .get("my-wrapper")
        .expect("my-wrapper should exist");
    assert_eq!(
        w.floor_effect,
        Effect::Unknown,
        "new wrapper without floor_effect should default to Unknown (fail-closed)"
    );
    assert!(!w.clears_env, "clears_env should default to false");
    assert!(
        !w.escalates_privilege,
        "escalates_privilege should default to false"
    );
}

// ── 25. TOML partial wrapper preserves base fields ───────────────────────

#[test]
fn toml_partial_wrapper_preserves_base_fields() {
    let overlay_toml = r#"
[wrappers.sudo]
floor_effect = "mutating"
"#;

    let overlay: KnowledgeOverlay =
        toml::from_str(overlay_toml).expect("overlay TOML should parse");

    let mut kb = base_kb();
    // sudo starts with: floor_effect=Mutating, escalates_privilege=true, clears_env=false
    assert_eq!(
        kb.wrappers.get("sudo").unwrap().floor_effect,
        Effect::Mutating
    );
    assert!(kb.wrappers.get("sudo").unwrap().escalates_privilege);
    assert!(!kb.wrappers.get("sudo").unwrap().clears_env);

    kb.merge(overlay);

    let sudo = kb.wrappers.get("sudo").unwrap();
    assert_eq!(
        sudo.floor_effect,
        Effect::Mutating,
        "floor_effect should be overridden from TOML"
    );
    assert!(
        sudo.escalates_privilege,
        "escalates_privilege should be preserved — omitting it in TOML must not reset it"
    );
    assert!(!sudo.clears_env, "clears_env should be preserved from base");
}

// ── 26. Multi-word subcommand removal ─────────────────────────────────────

#[test]
fn remove_multi_word_subcommand() {
    let mut kb = KnowledgeBase::default();
    let mut subs = SubcommandMap::new();
    subs.insert("pr create", SubcommandEntry::with_effect(Effect::Mutating));
    subs.insert("pr list", SubcommandEntry::with_effect(Effect::ReadOnly));
    let mut gh = CommandKnowledge::simple("gh", Effect::Unknown);
    gh.subcommands = subs;
    kb.commands.insert("gh".into(), gh);

    let mut overlay = empty_overlay();
    overlay.commands.insert(
        "gh".into(),
        CommandOverlay {
            remove_subcommands: vec!["pr create".into()],
            ..Default::default()
        },
    );

    kb.merge(overlay);

    let gh = kb.commands.get("gh").unwrap();
    assert!(
        gh.subcommands.get("pr create").is_none(),
        "pr create should be removed"
    );
    assert!(
        gh.subcommands.get("pr list").is_some(),
        "pr list should be preserved"
    );
}
