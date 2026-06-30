use super::super::tokenize::tokenize;
use super::super::types::WrapperEnvPolicy;
use super::*;
use rstest::rstest;

fn words(s: &str) -> Vec<Word> {
    tokenize(s)
}

fn spec(name: &str) -> WrapperSpec {
    WrapperSpec {
        name: name.to_string(),
        short_value_flags: vec!["-v".to_string()],
        long_value_flags: vec!["--val".to_string()],
        unanalyzable_flags: vec![],
        skip_env_assignments: false,
        has_terminator: true,
        skip_positionals: 0,
        env_policy: WrapperEnvPolicy::default(),
    }
}

#[rstest]
#[case::simple_wrapper("wrap inner cmd", "inner cmd")]
#[case::value_consuming_short_flag("wrap -v thing inner cmd", "inner cmd")]
#[case::value_consuming_long_flag("wrap --val thing inner cmd", "inner cmd")]
#[case::long_flag_equals_form("wrap --val=thing inner cmd", "inner cmd")]
#[case::terminator_stops_flag_processing("wrap -x -- -v notflag cmd", "-v notflag cmd")]
#[case::boolean_flag_skipped("wrap -x --verbose inner", "inner")]
#[case::path_prefixed_wrapper("/usr/bin/wrap inner cmd", "inner cmd")]
fn strip_with_spec_resolves_inner(#[case] input: &str, #[case] expected: &str) {
    let s = spec("wrap");
    let result = strip_with_spec(&s, &words(input));
    assert_eq!(result, words(expected));
}

#[rstest]
#[case::truncated_value_flag("wrap -v")]
#[case::no_inner_command("wrap -x --verbose")]
fn strip_with_spec_returns_empty(#[case] input: &str) {
    let s = spec("wrap");
    let result = strip_with_spec(&s, &words(input));
    assert!(result.is_empty(), "expected empty result for: {input}");
}

#[test]
fn strip_env_assignments_when_configured() {
    let s = WrapperSpec {
        name: "wrap".to_string(),
        short_value_flags: vec![],
        long_value_flags: vec![],
        unanalyzable_flags: vec![],
        skip_env_assignments: true,
        has_terminator: false,
        skip_positionals: 0,
        env_policy: WrapperEnvPolicy::default(),
    };
    let result = strip_with_spec(&s, &words("wrap FOO=bar BAZ=qux inner cmd"));
    assert_eq!(result, words("inner cmd"));
}

#[test]
fn resolve_with_custom_config() {
    let config = CommandConfig {
        wrappers: vec![WrapperSpec {
            name: "mywrap".to_string(),
            short_value_flags: vec!["-x".to_string()],
            long_value_flags: vec![],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: false,
            skip_positionals: 0,
            env_policy: WrapperEnvPolicy::default(),
        }],
        shells: vec!["mysh".to_string()],
        eval_commands: vec!["myeval".to_string()],
        source_commands: vec!["mysource".to_string()],
    };

    match resolve_command_with(&words("mywrap -x val inner"), &config) {
        ResolvedCommand::Resolved(p) => assert_eq!(p.command, "inner"),
        _ => panic!("expected Resolved"),
    }

    assert!(matches!(
        resolve_command_with(&words("mysh -c 'code'"), &config),
        ResolvedCommand::Unanalyzable(_)
    ));

    assert!(matches!(
        resolve_command_with(&words("myeval 'code'"), &config),
        ResolvedCommand::Unanalyzable(_)
    ));

    assert!(matches!(
        resolve_command_with(&words("mysource file.sh"), &config),
        ResolvedCommand::Unanalyzable(_)
    ));
}

// ── merged_config + resolve_command_with ───────────────────────────────

#[test]
fn extra_wrapper_recognized_and_inner_resolved() {
    let extra = vec![WrapperSpec {
        name: "mywrap".to_string(),
        short_value_flags: vec!["-x".to_string()],
        long_value_flags: vec![],
        unanalyzable_flags: vec![],
        skip_env_assignments: false,
        has_terminator: false,
        skip_positionals: 0,
        env_policy: WrapperEnvPolicy::default(),
    }];
    let config = merged_config(&extra);
    match resolve_command_with(&words("mywrap -x val inner"), &config) {
        ResolvedCommand::Resolved(p) => assert_eq!(p.command, "inner"),
        other => panic!("expected Resolved(inner), got {:?}", other),
    }
}

#[test]
fn duplicate_extra_wrapper_not_double_added() {
    let extra = vec![WrapperSpec {
        name: "sudo".to_string(),
        short_value_flags: vec![],
        long_value_flags: vec![],
        unanalyzable_flags: vec![],
        skip_env_assignments: false,
        has_terminator: false,
        skip_positionals: 0,
        env_policy: WrapperEnvPolicy::default(),
    }];

    let config = merged_config(&extra);
    assert_eq!(
        config.wrappers.iter().filter(|w| w.name == "sudo").count(),
        1,
        "sudo should appear exactly once in merged config, not be duplicated"
    );

    match resolve_command_with(&words("sudo -u root git commit"), &config) {
        ResolvedCommand::Resolved(p) => assert_eq!(p.command, "git"),
        other => panic!("expected Resolved(git), got {:?}", other),
    }
}

#[test]
fn empty_extra_wrappers_same_as_resolve_command() {
    let ws = words("env FOO=bar git status");
    let config = merged_config(&[]);
    let with_merged = resolve_command_with(&ws, &config);
    let plain = resolve_command(&ws);
    match (with_merged, plain) {
        (ResolvedCommand::Resolved(a), ResolvedCommand::Resolved(b)) => {
            assert_eq!(a.command, b.command);
        }
        (a, b) => panic!("expected both Resolved, got {:?} vs {:?}", a, b),
    }
}

/// After fix: `sudo -- git commit -s` should resolve to `git commit -s`,
/// not Unanalyzable. The `-s` belongs to `git commit` (signoff), not sudo.
#[test]
fn terminator_scopes_unanalyzable_check() {
    let words = vec![
        Word::from("sudo"),
        Word::from("--"),
        Word::from("git"),
        Word::from("commit"),
        Word::from("-s"),
    ];
    match resolve_command(&words) {
        ResolvedCommand::Resolved(p) => assert_eq!(p.command.as_str(), "git"),
        other => panic!("expected Resolved(git), got {:?}", other),
    }
}
