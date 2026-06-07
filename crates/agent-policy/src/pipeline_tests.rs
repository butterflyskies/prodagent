use agent_command_knowledge::{default_knowledge_base, KnowledgeBase, Utf8PathBuf};

use super::*;
use crate::config::PolicyConfig;

fn default_engine() -> PolicyEngine {
    PolicyEngine::new(PolicyConfig::default()).unwrap()
}

fn default_kb() -> &'static KnowledgeBase {
    default_knowledge_base()
}

// ── Simple read-only command ───────────────────────────────────────────

#[test]
fn simple_read_only_allows() {
    let engine = default_engine();
    let result = engine.evaluate_command("ls -la", default_kb());
    assert_eq!(
        result.decision,
        PolicyDecision::Allow,
        "ls -la should be allowed: {result:?}"
    );
}

// ── Mutating command ───────────────────────────────────────────────────

#[test]
fn mutating_command_asks() {
    let engine = default_engine();
    let result = engine.evaluate_command("rm foo", default_kb());
    assert!(
        result.decision >= PolicyDecision::Ask,
        "rm foo should be at least Ask: {result:?}"
    );
}

// ── Unknown command (fail-closed) ──────────────────────────────────────

#[test]
fn unknown_command_asks() {
    let engine = default_engine();
    let result = engine.evaluate_command("asdfghjkl", default_kb());
    assert_eq!(
        result.decision,
        PolicyDecision::Ask,
        "unknown command should fail-closed to Ask: {result:?}"
    );
}

// ── Compound command: strictest wins ───────────────────────────────────

#[test]
fn compound_command_strictest_wins() {
    let engine = default_engine();
    let result = engine.evaluate_command("ls && rm foo", default_kb());
    assert_eq!(
        result.decision,
        PolicyDecision::Ask,
        "compound with rm should be Ask: {result:?}"
    );
}

// ── Structured segment results ─────────────────────────────────────────

#[test]
fn compound_segments_populated() {
    let engine = default_engine();
    let result = engine.evaluate_command("ls && rm foo", default_kb());
    assert_eq!(
        result.segments.len(),
        2,
        "should have 2 segments: {result:?}"
    );
    assert_eq!(result.segments[0].decision, PolicyDecision::Allow);
    assert_eq!(result.segments[1].decision, PolicyDecision::Ask);
}

#[test]
fn simple_command_has_one_segment() {
    let engine = default_engine();
    let result = engine.evaluate_command("ls -la", default_kb());
    assert_eq!(
        result.segments.len(),
        1,
        "simple command should have 1 segment: {result:?}"
    );
    assert_eq!(result.segments[0].decision, PolicyDecision::Allow);
    assert_eq!(result.segments[0].decision, result.decision);
}

// ── Compound header: substitution counting ────────────────────────────

#[test]
fn compound_header_counts_nested_substitutions() {
    let engine = default_engine();
    // echo has 1 sub, cat has 1 sub, basename has 1 sub = 3 total
    let result = engine.evaluate_command("echo $(cat $(basename $(date)))", default_kb());
    assert!(
        result.reason.contains("3 substitution(s)"),
        "deeply nested substitutions should all be counted: {result:?}"
    );
}

#[test]
fn compound_header_counts_structural_substitutions() {
    let engine = default_engine();
    let result = engine.evaluate_command("for i in $(seq 10); do echo $i; done", default_kb());
    assert!(
        result.reason.contains("1 substitution(s)"),
        "structural substitution should be counted: {result:?}"
    );
}

// ── Wrapper command ────────────────────────────────────────────────────

#[test]
fn wrapper_sudo_escalates() {
    let engine = default_engine();
    let kb = default_kb();
    // sudo wraps ls — sudo has a floor effect, so it should be at least
    // what the KB says for sudo's floor.
    let result = engine.evaluate_command("sudo ls", kb);
    // sudo is a wrapper with escalates_privilege — should be at least Ask
    assert!(
        result.decision >= PolicyDecision::Ask,
        "sudo ls should be at least Ask: {result:?}"
    );
    assert!(
        result.reason.contains("wraps"),
        "reason should mention wrapping: {result:?}"
    );
}

// ── Escalation flags ───────────────────────────────────────────────────

#[test]
fn escalation_flags_bump_to_ask() {
    // Set git push to Allow via per-command override, then verify
    // that --force escalation flags still bump it to Ask.
    let config = PolicyConfig::builder()
        .subcommand("git", "push", PolicyDecision::Allow)
        .build()
        .unwrap();
    let engine = PolicyEngine::new(config).unwrap();

    // Without --force, git push should be Allow (our override)
    let result_no_force = engine.evaluate_command("git push", default_kb());
    assert_eq!(
        result_no_force.decision,
        PolicyDecision::Allow,
        "git push without --force should be Allow: {result_no_force:?}"
    );

    // With --force, escalation flags should bump Allow → Ask
    let result = engine.evaluate_command("git push --force", default_kb());
    assert_eq!(
        result.decision,
        PolicyDecision::Ask,
        "git push --force should be Ask due to escalation flags: {result:?}"
    );
    assert!(
        result.reason.contains("escalat"),
        "reason should mention escalation: {result:?}"
    );
}

// ── Redirection bumps Allow → Ask ──────────────────────────────────────

#[test]
fn redirection_bumps_allow_to_ask() {
    let engine = default_engine();
    let result = engine.evaluate_command("ls > file", default_kb());
    assert_eq!(
        result.decision,
        PolicyDecision::Ask,
        "ls with redirection should be Ask: {result:?}"
    );
    assert!(
        result.reason.contains("escalated"),
        "reason should mention escalation due to redirection: {result:?}"
    );
}

// ── Benign redirections (Tier 1: never escalate) ──────────────────────

#[test]
fn redirection_to_dev_null_stays_allow() {
    let engine = default_engine();
    let result = engine.evaluate_command("ls > /dev/null", default_kb());
    assert_eq!(
        result.decision,
        PolicyDecision::Allow,
        "ls > /dev/null should stay Allow (benign): {result:?}"
    );
}

#[test]
fn redirection_stderr_to_stdout_stays_allow() {
    let engine = default_engine();
    let result = engine.evaluate_command("ls 2>&1", default_kb());
    assert_eq!(
        result.decision,
        PolicyDecision::Allow,
        "ls 2>&1 should stay Allow (fd duplication): {result:?}"
    );
}

#[test]
fn redirection_to_file_still_asks() {
    let engine = default_engine();
    let result = engine.evaluate_command("ls > output.txt", default_kb());
    assert_eq!(
        result.decision,
        PolicyDecision::Ask,
        "ls > output.txt should be Ask (non-benign redirection): {result:?}"
    );
    assert!(
        result.reason.contains("escalated"),
        "reason should mention escalation: {result:?}"
    );
}

#[test]
fn redirection_append_to_dev_null_stays_allow() {
    let engine = default_engine();
    let result = engine.evaluate_command("ls >> /dev/null", default_kb());
    assert_eq!(
        result.decision,
        PolicyDecision::Allow,
        "ls >> /dev/null should stay Allow (benign): {result:?}"
    );
}

// ── Parse error (fail-closed) ──────────────────────────────────────────

#[test]
fn empty_command_allows() {
    let engine = default_engine();
    let result = engine.evaluate_command("", default_kb());
    assert_eq!(
        result.decision,
        PolicyDecision::Allow,
        "empty command should be Allow: {result:?}"
    );
}

#[test]
fn parse_error_fails_closed() {
    let engine = default_engine();
    // Incomplete syntax that produces parse errors in tree-sitter
    let result = engine.evaluate_command("if then", default_kb());
    assert!(
        result.decision >= PolicyDecision::Ask,
        "parse errors should fail-closed to at least Ask: {result:?}"
    );
}

// ── Per-command override: Deny ─────────────────────────────────────────

#[test]
fn per_command_override_deny() {
    let config = PolicyConfig::builder().deny("rm").build().unwrap();
    let engine = PolicyEngine::new(config).unwrap();
    let result = engine.evaluate_command("rm foo", default_kb());
    assert_eq!(
        result.decision,
        PolicyDecision::Deny,
        "rm with deny override should be Deny: {result:?}"
    );
}

// ── Compound with pipe ─────────────────────────────────────────────────

#[test]
fn pipe_compound_strictest_wins() {
    let engine = default_engine();
    let result = engine.evaluate_command("cat file | grep pattern", default_kb());
    // Both cat and grep are read-only, so this should be Allow
    assert_eq!(
        result.decision,
        PolicyDecision::Allow,
        "cat | grep should be Allow: {result:?}"
    );
}

// ── Semicolon compound ─────────────────────────────────────────────────

#[test]
fn semicolon_compound_strictest_wins() {
    let engine = default_engine();
    let result = engine.evaluate_command("ls ; rm foo", default_kb());
    assert_eq!(
        result.decision,
        PolicyDecision::Ask,
        "ls ; rm should be Ask: {result:?}"
    );
}

// ── Multiple unknown commands ──────────────────────────────────────────

#[test]
fn multiple_unknown_commands() {
    let engine = default_engine();
    let result = engine.evaluate_command("xyz123 && abc456", default_kb());
    assert_eq!(
        result.decision,
        PolicyDecision::Ask,
        "unknown commands should all be Ask: {result:?}"
    );
}

// ── Empty wrapper guard (P1-1) ────────────────────────────────────────

#[test]
fn bare_sudo_fails_closed() {
    let engine = default_engine();
    let kb = default_kb();
    // Bare wrapper with no inner command — KB knows sudo is a wrapper,
    // so the fallback applies floor + escalates_privilege.
    let result = engine.evaluate_command("sudo", kb);
    assert!(
        result.decision >= PolicyDecision::Ask,
        "bare sudo should be at least Ask (fail-closed): {result:?}"
    );
}

// ── Nested wrapper (P3-13) ────────────────────────────────────────────

#[test]
fn nested_wrapper_sudo_env_ls() {
    let engine = default_engine();
    let kb = default_kb();
    let result = engine.evaluate_command("sudo env ls", kb);
    assert!(
        result.decision >= PolicyDecision::Ask,
        "sudo env ls should be at least Ask: {result:?}"
    );
    assert!(
        result.reason.contains("wraps"),
        "reason should mention the wrapper chain: {result:?}"
    );
}

// ── Read-only subcommand override ──────────────────────────────────────

#[test]
fn git_status_is_read_only() {
    let engine = default_engine();
    let result = engine.evaluate_command("git status", default_kb());
    assert_eq!(
        result.decision,
        PolicyDecision::Allow,
        "git status should be Allow: {result:?}"
    );
}

// ── Wrapper with unanalyzable inner ────────────────────────────────────

#[test]
fn eval_is_unanalyzable() {
    let engine = default_engine();
    let result = engine.evaluate_command("eval 'rm -rf /'", default_kb());
    assert!(
        result.decision >= PolicyDecision::Ask,
        "eval should be at least Ask (unanalyzable): {result:?}"
    );
}

// ── Variable assignment is always safe ─────────────────────────────────

#[test]
fn variable_assignment_allows() {
    let engine = default_engine();
    let result = engine.evaluate_command("FOO=bar", default_kb());
    assert_eq!(
        result.decision,
        PolicyDecision::Allow,
        "bare variable assignment should be Allow: {result:?}"
    );
}

// ── Read-only command in pipeline ──────────────────────────────────────

#[test]
fn read_only_pipeline_allows() {
    let engine = default_engine();
    let result = engine.evaluate_command("ls -la | head -5", default_kb());
    assert_eq!(
        result.decision,
        PolicyDecision::Allow,
        "ls | head should be Allow: {result:?}"
    );
}

// ── KB-only wrapper fail-closed (not in parser's wrapper list) ────────

#[test]
fn doas_wrapper_fails_closed() {
    // doas is in the KB (escalates_privilege=true, floor_effect=mutating)
    // but NOT in the parser's wrapper list. Previously this fell through
    // to Allow — a privilege-escalation bypass.
    let engine = default_engine();
    let kb = default_kb();
    let result = engine.evaluate_command("doas rm -rf /", kb);
    assert!(
        result.decision >= PolicyDecision::Ask,
        "doas rm -rf / must be at least Ask (KB-only wrapper, fail-closed): {result:?}"
    );
}

#[test]
fn su_wrapper_fails_closed() {
    // su is in the KB (escalates_privilege=true, floor_effect=mutating)
    // and in the parser's default wrapper list. su -c is an unanalyzable flag,
    // so this triggers the unanalyzable path.
    let engine = default_engine();
    let kb = default_kb();
    let result = engine.evaluate_command("su -c 'rm -rf /'", kb);
    assert!(
        result.decision >= PolicyDecision::Ask,
        "su -c 'rm -rf /' must be at least Ask (unanalyzable -c flag): {result:?}"
    );
}

#[test]
fn pkexec_wrapper_fails_closed() {
    // pkexec is in the KB (escalates_privilege=true, floor_effect=mutating).
    // It is KB-only (not in the parser's default wrapper list) but gets
    // stripped via KB-derived wrapper specs at evaluation time.
    let engine = default_engine();
    let kb = default_kb();
    let result = engine.evaluate_command("pkexec rm foo", kb);
    assert!(
        result.decision >= PolicyDecision::Ask,
        "pkexec rm foo must be at least Ask (KB-only wrapper, fail-closed): {result:?}"
    );
}

// ── KB-primed parser: wrapper stripping for KB-only wrappers ──────────

#[test]
fn doas_wrapper_resolves_inner_command() {
    // With the unified wrapper list, the policy engine primes the parser
    // with KB-derived WrapperSpecs. This means doas (a KB-only wrapper)
    // can now be stripped to reveal the inner command, and the reason
    // should mention "wraps" rather than just "inner command not resolved".
    let engine = default_engine();
    let kb = default_kb();
    let result = engine.evaluate_command("doas ls", kb);
    assert!(
        result.decision >= PolicyDecision::Ask,
        "doas ls must be at least Ask (escalates_privilege): {result:?}"
    );
    assert!(
        result.reason.contains("wraps"),
        "reason should show wrapper resolved inner command: {result:?}"
    );
    assert!(
        result.reason.contains("ls"),
        "reason should name the inner command 'ls': {result:?}"
    );
}

#[test]
fn pkexec_wrapper_resolves_inner_command() {
    let engine = default_engine();
    let kb = default_kb();
    let result = engine.evaluate_command("pkexec cat /etc/shadow", kb);
    assert!(
        result.decision >= PolicyDecision::Ask,
        "pkexec cat must be at least Ask: {result:?}"
    );
    assert!(
        result.reason.contains("wraps"),
        "reason should show wrapper resolved inner command: {result:?}"
    );
    assert!(
        result.reason.contains("cat"),
        "reason should name the inner command 'cat': {result:?}"
    );
}

// ── derive_wrapper_specs only adds KB-only wrappers ───────────────────

#[test]
fn derive_wrapper_specs_does_not_duplicate_defaults() {
    let kb = default_kb();
    let specs = super::derive_wrapper_specs(kb);
    let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();

    // Default wrappers must NOT appear in derived specs
    for default_name in &[
        "sudo", "env", "nice", "timeout", "strace", "watch", "ltrace", "su",
    ] {
        assert!(
            !names.contains(default_name),
            "{default_name} is a default wrapper — should not appear in derived specs"
        );
    }

    // KB-only wrappers (doas, pkexec) should be present
    assert!(
        names.contains(&"doas"),
        "doas is KB-only — should appear in derived specs"
    );
    assert!(
        names.contains(&"pkexec"),
        "pkexec is KB-only — should appear in derived specs"
    );

    // Total count should match exactly the number of KB wrappers not in defaults
    let default_config = agent_shell_parser::parse::default_command_config();
    let expected_count = kb
        .wrappers
        .keys()
        .filter(|name| !default_config.wrappers.iter().any(|w| &w.name == *name))
        .count();
    assert_eq!(
        specs.len(),
        expected_count,
        "derived spec count should match KB-only wrapper count"
    );
}

// ── Env gate integration tests ────────────────────────────────────────────

use agent_command_knowledge::{
    CommandKnowledge, CommandOverlay, CommandProperties, EnvCondition, EnvGate, EnvGateAction,
    FlagSchema, KnowledgeOverlay, PathSpec, SubcommandEntry, SubcommandMap,
};

fn simple_command(name: &str, effect: agent_command_knowledge::Effect) -> CommandKnowledge {
    CommandKnowledge {
        name: name.to_string(),
        effect,
        subcommands: SubcommandMap::new(),
        flags: FlagSchema::default(),
        env_gates: vec![],
        paths: PathSpec::default(),
        properties: CommandProperties::default(),
    }
}

fn kb_with_env_gate(cmd: &str, gate: EnvGate) -> KnowledgeBase {
    let mut kb = KnowledgeBase::default();
    let mut command = simple_command(cmd, agent_command_knowledge::Effect::ReadOnly);
    command.env_gates = vec![gate];
    kb.commands.insert(cmd.to_string(), command);
    kb
}

#[test]
fn env_gate_inline_assignment_matches_equals() {
    // FOO=bar mycmd → gate on FOO==bar → Allow should match
    let gate = EnvGate {
        var: "TESTGATE_FOO".into(),
        condition: EnvCondition::Equals("bar".into()),
        decision: EnvGateAction::Deny,
    };
    let kb = kb_with_env_gate("mycmd", gate);
    let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
    let result = engine.evaluate_command("TESTGATE_FOO=bar mycmd", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Deny,
        "inline assignment should match Equals gate: {result:?}"
    );
}

#[test]
fn env_gate_inline_assignment_no_match() {
    // FOO=baz mycmd → gate on FOO==bar → no match → Allow (read-only)
    let gate = EnvGate {
        var: "TESTGATE_FOO".into(),
        condition: EnvCondition::Equals("bar".into()),
        decision: EnvGateAction::Deny,
    };
    let kb = kb_with_env_gate("mycmd", gate);
    let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
    let result = engine.evaluate_command("TESTGATE_FOO=baz mycmd", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Allow,
        "non-matching inline assignment should not trigger gate: {result:?}"
    );
}

#[test]
fn env_gate_set_condition_with_inline_assignment() {
    let gate = EnvGate {
        var: "TESTGATE_VAR".into(),
        condition: EnvCondition::Set,
        decision: EnvGateAction::Ask,
    };
    let kb = kb_with_env_gate("mycmd", gate);
    let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
    let result = engine.evaluate_command("TESTGATE_VAR=anything mycmd", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Ask,
        "Set condition should match inline assignment: {result:?}"
    );
}

#[test]
fn env_gate_unset_condition_no_inline_assignment() {
    let gate = EnvGate {
        var: "TESTGATE_DEFINITELY_UNSET_VAR_12345".into(),
        condition: EnvCondition::Unset,
        decision: EnvGateAction::Deny,
    };
    let kb = kb_with_env_gate("mycmd", gate);
    let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
    let result = engine.evaluate_command("mycmd", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Deny,
        "Unset condition should match when var is not in env: {result:?}"
    );
}

#[test]
fn env_gate_no_gates_no_effect() {
    // Command with no env gates — env is not considered
    let mut kb = KnowledgeBase::default();
    kb.commands.insert(
        "mycmd".to_string(),
        simple_command("mycmd", agent_command_knowledge::Effect::ReadOnly),
    );
    let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
    let result = engine.evaluate_command("mycmd", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Allow,
        "no gates should not affect decision: {result:?}"
    );
}

// ── Wrapper env threading integration ──────────────────────────────────────

#[test]
fn env_wrapper_assignments_visible_to_inner() {
    // env FOO=bar mycmd → inner command sees FOO=bar
    let gate = EnvGate {
        var: "TESTGATE_FOO".into(),
        condition: EnvCondition::Equals("bar".into()),
        decision: EnvGateAction::Deny,
    };
    let mut kb = default_kb().clone();
    let mut command = simple_command("mycmd", agent_command_knowledge::Effect::ReadOnly);
    command.env_gates = vec![gate];
    kb.commands.insert("mycmd".to_string(), command);

    let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
    let result = engine.evaluate_command("env TESTGATE_FOO=bar mycmd", &kb);
    assert!(
        result.decision >= PolicyDecision::Deny,
        "env wrapper assignment should be visible to inner command gate: {result:?}"
    );
}

#[test]
fn env_wrapper_unset_removes_var() {
    // First set a gate on TESTGATE_X being Set → Deny.
    // Then: env -u TESTGATE_X mycmd → TESTGATE_X is unset → Set condition doesn't match
    let gate = EnvGate {
        var: "TESTGATE_X".into(),
        condition: EnvCondition::Set,
        decision: EnvGateAction::Deny,
    };
    let mut kb = default_kb().clone();
    let mut command = simple_command("mycmd", agent_command_knowledge::Effect::ReadOnly);
    command.env_gates = vec![gate];
    kb.commands.insert("mycmd".to_string(), command);

    let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
    // TESTGATE_X is not in process env (or if it is, env -u removes it)
    let result = engine.evaluate_command("env -u TESTGATE_X mycmd", &kb);
    // The Set condition should NOT match because we unset it
    assert_eq!(
        result.decision,
        PolicyDecision::Allow,
        "env -u should unset var for inner command: {result:?}"
    );
}

#[test]
fn env_wrapper_clean_env_hides_process_vars() {
    // env -i mycmd → clean env → Set condition on any var should not match
    let gate = EnvGate {
        var: "PATH".into(), // PATH is almost always set in process env
        condition: EnvCondition::Set,
        decision: EnvGateAction::Deny,
    };
    let mut kb = default_kb().clone();
    let mut command = simple_command("mycmd", agent_command_knowledge::Effect::ReadOnly);
    command.env_gates = vec![gate];
    kb.commands.insert("mycmd".to_string(), command);

    let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
    let result = engine.evaluate_command("env -i mycmd", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Allow,
        "env -i should hide process env from inner command: {result:?}"
    );
}

#[test]
fn sudo_without_e_marks_env_unknown() {
    // Use a gate with Equals/Deny where the var IS set in the process env.
    // If sudo correctly marks env as unknown, the Equals condition can't
    // confirm, so the Deny gate is suppressed. Result should be exactly Ask
    // (from sudo escalation), NOT Deny.
    let gate = EnvGate {
        var: "PATH".into(), // PATH is always set in process env
        condition: EnvCondition::Equals(std::env::var("PATH").unwrap_or_default()),
        decision: EnvGateAction::Deny,
    };
    let mut kb = default_kb().clone();
    let mut command = simple_command("mycmd", agent_command_knowledge::Effect::ReadOnly);
    command.env_gates = vec![gate];
    kb.commands.insert("mycmd".to_string(), command);

    let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
    // sudo without -E → env is unknown → Equals can't confirm → Deny suppressed
    let result = engine.evaluate_command("sudo mycmd", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Ask,
        "sudo without -E should be exactly Ask (gate suppressed by unknown env): {result:?}"
    );
}

#[test]
fn sudo_with_e_preserves_env() {
    // Use a gate with Set/Deny on a var that IS set in the process env.
    // If sudo -E correctly preserves env, the Set condition fires and
    // produces Deny, proving the env was preserved.
    let gate = EnvGate {
        var: "PATH".into(), // PATH is always set
        condition: EnvCondition::Set,
        decision: EnvGateAction::Deny,
    };
    let mut kb = default_kb().clone();
    let mut command = simple_command("mycmd", agent_command_knowledge::Effect::ReadOnly);
    command.env_gates = vec![gate];
    kb.commands.insert("mycmd".to_string(), command);

    let engine = PolicyEngine::new(PolicyConfig::default()).unwrap();
    // sudo -E → env preserved → PATH is Set → Deny gate fires
    let result = engine.evaluate_command("sudo -E mycmd", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Deny,
        "sudo -E should produce Deny (gate fired because env preserved): {result:?}"
    );
}

// ── Env gate integration with real KB commands ───────────────────────────────
//
// These tests exercise the full env gate pipeline end-to-end against the real
// default_knowledge_base(), adding env gates via KnowledgeOverlay::merge. They
// use real KB commands (git push, pip install) rather than synthetic "mycmd"
// entries, proving that gates compose correctly with subcommand resolution,
// wrapper stripping, and the base classification pipeline.

/// Helper: clone the default KB and merge an overlay that adds env_gates to
/// the `git` command (command-level gates, inherited by all subcommands).
fn real_kb_with_git_gate(gates: Vec<EnvGate>) -> KnowledgeBase {
    let mut kb = default_kb().clone();
    let overlay = KnowledgeOverlay {
        commands: [(
            "git".into(),
            CommandOverlay {
                env_gates: gates,
                ..Default::default()
            },
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    kb.merge(overlay);
    kb
}

/// Helper: clone the default KB and add `pip` as a new Mutating command with
/// an `install` subcommand and the given env gates on the command.
fn real_kb_with_pip_gate(gate: EnvGate) -> KnowledgeBase {
    real_kb_with_pip_gate_multi(vec![gate])
}

fn real_kb_with_pip_gate_multi(gates: Vec<EnvGate>) -> KnowledgeBase {
    let mut kb = default_kb().clone();
    let mut subs = SubcommandMap::new();
    subs.insert(
        "install",
        SubcommandEntry {
            effect: agent_command_knowledge::Effect::Mutating,
            flags: FlagSchema::default(),
            env_gates: vec![],
            paths: PathSpec::default(),
            subcommands: SubcommandMap::new(),
        },
    );
    let overlay = KnowledgeOverlay {
        commands: [(
            "pip".into(),
            CommandOverlay {
                effect: Some(agent_command_knowledge::Effect::Mutating),
                subcommands: subs,
                env_gates: gates,
                ..Default::default()
            },
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    kb.merge(overlay);
    kb
}

// Negative test: Allow gate with WRONG value does not fire — base is unaffected.
// Uses git status (ReadOnly → Allow base) + a companion Deny gate on a different
// var that always fires. If the mismatched Allow gate incorrectly suppressed the
// Deny gate the result would be Allow; the correct result is Deny.
#[test]
fn real_kb_equals_gate_allow_does_not_lower_base() {
    let allow_gate = EnvGate {
        var: "GIT_AUTHOR_NAME".into(),
        condition: EnvCondition::Equals("AI-Agent".into()),
        decision: EnvGateAction::Allow,
    };
    // Deny gate on a var that IS set via inline assignment, so it always fires.
    let deny_gate = EnvGate {
        var: "GIT_SENTINEL".into(),
        condition: EnvCondition::Set,
        decision: EnvGateAction::Deny,
    };
    // Wrong value for the Equals condition: Allow gate does NOT fire.
    // Deny gate fires: result must be Deny, not Allow.
    let kb = real_kb_with_git_gate(vec![allow_gate, deny_gate]);
    let engine = default_engine();
    let result =
        engine.evaluate_command("GIT_SENTINEL=1 GIT_AUTHOR_NAME=wrong-value git status", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Deny,
        "mismatched Allow gate must not suppress the Deny gate: {result:?}"
    );
}

// Equals gate Deny when the condition matches escalates base Ask → Deny.
#[test]
fn real_kb_equals_gate_deny_on_match() {
    let gate = EnvGate {
        var: "GIT_AUTHOR_NAME".into(),
        condition: EnvCondition::Equals("wrong-identity".into()),
        decision: EnvGateAction::Deny,
    };
    let kb = real_kb_with_git_gate(vec![gate]);
    let engine = default_engine();

    // Inline value matches the Deny gate's expected value → Deny fires →
    // max(Ask, Deny) = Deny.
    let result = engine.evaluate_command("GIT_AUTHOR_NAME=wrong-identity git push", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Deny,
        "Equals gate with Deny should escalate to Deny when value matches: {result:?}"
    );
}

// Unset gate denies when variable is absent.
#[test]
fn real_kb_unset_gate_denies_when_var_absent() {
    let gate = EnvGate {
        var: "PRODAGENT_DEFINITELY_UNSET_12345".into(),
        condition: EnvCondition::Unset,
        decision: EnvGateAction::Deny,
    };
    let kb = real_kb_with_pip_gate(gate);
    let engine = default_engine();

    // PRODAGENT_DEFINITELY_UNSET_12345 is guaranteed absent in any process env.
    // Unset condition matches → Deny fires.
    let result = engine.evaluate_command("pip install requests", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Deny,
        "Unset gate should Deny when var is absent: {result:?}"
    );
}

// Negative test: Set/Allow gate fires but a companion Deny gate on a different
// var also fires — the Allow gate must not suppress the Deny gate.
// Uses pip install (Mutating → Ask base) with VIRTUAL_ENV set via inline
// assignment so the Allow gate fires, plus a Deny gate that always fires.
// If Allow incorrectly suppressed Deny the result would be Ask (not Deny).
#[test]
fn real_kb_set_gate_allow_does_not_lower_base() {
    let allow_gate = EnvGate {
        var: "VIRTUAL_ENV".into(),
        condition: EnvCondition::Set,
        decision: EnvGateAction::Allow,
    };
    // Deny gate on a var that IS always set via inline assignment.
    let deny_gate = EnvGate {
        var: "PIP_SENTINEL".into(),
        condition: EnvCondition::Set,
        decision: EnvGateAction::Deny,
    };
    // Both gates fire: Allow for VIRTUAL_ENV, Deny for PIP_SENTINEL.
    // Strictest must win → Deny, proving Allow did not suppress it.
    let kb = real_kb_with_pip_gate_multi(vec![allow_gate, deny_gate]);
    let engine = default_engine();
    let result = engine.evaluate_command(
        "VIRTUAL_ENV=/home/user/.venv PIP_SENTINEL=1 pip install requests",
        &kb,
    );
    assert_eq!(
        result.decision,
        PolicyDecision::Deny,
        "Set/Allow gate must not suppress a Deny gate that also fires: {result:?}"
    );
}

// env wrapper passes assignments through to inner command's gate.
#[test]
fn real_kb_env_wrapper_passes_assignments_to_inner_gate() {
    let gate = EnvGate {
        var: "GIT_AUTHOR_NAME".into(),
        condition: EnvCondition::Equals("AI-Agent".into()),
        decision: EnvGateAction::Deny,
    };
    let kb = real_kb_with_git_gate(vec![gate]);
    let engine = default_engine();

    // env GIT_AUTHOR_NAME=AI-Agent git push → env wrapper passes the
    // assignment to the inner command. The Equals gate matches → Deny.
    let result = engine.evaluate_command("env GIT_AUTHOR_NAME=AI-Agent git push", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Deny,
        "env wrapper assignment must be visible to inner command's gate: {result:?}"
    );
}

// sudo strips env for inner gate — Equals gate cannot confirm.
#[test]
fn real_kb_sudo_strips_env_for_inner_gate() {
    // Use PATH (always set in process env) with its actual value.
    // Without sudo, the Equals gate would match and Deny.
    // With sudo, env is marked unknown → gate suppressed → Ask.
    let path_value = std::env::var("PATH").unwrap_or_default();
    let gate = EnvGate {
        var: "PATH".into(),
        condition: EnvCondition::Equals(path_value),
        decision: EnvGateAction::Deny,
    };
    let kb = real_kb_with_git_gate(vec![gate]);
    let engine = default_engine();

    let result = engine.evaluate_command("sudo git push", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Ask,
        "sudo should strip env, suppressing the Equals/Deny gate: {result:?}"
    );
}

// Multiple gates: strictest wins (Deny > Allow).
#[test]
fn real_kb_multiple_gates_strictest_wins() {
    let allow_gate = EnvGate {
        var: "GIT_AUTHOR_NAME".into(),
        condition: EnvCondition::Set,
        decision: EnvGateAction::Allow,
    };
    let deny_gate = EnvGate {
        var: "GIT_AUTHOR_NAME".into(),
        condition: EnvCondition::Equals("forbidden".into()),
        decision: EnvGateAction::Deny,
    };

    // GIT_AUTHOR_NAME=forbidden → Set/Allow fires AND Equals/Deny fires.
    // Strictest wins: Deny.
    let kb = real_kb_with_git_gate(vec![allow_gate, deny_gate]);
    let engine = default_engine();
    let result = engine.evaluate_command("GIT_AUTHOR_NAME=forbidden git push", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Deny,
        "when multiple gates fire, strictest (Deny) must win: {result:?}"
    );
}

// ── Path-invoked commands classify by basename ─────────────────────────
//
// Unlike agent-jj's guard (which deliberately blocks most git in
// jj-colocated repos), the general engine must treat a command invoked by
// path exactly like its bare name: `/usr/bin/git status` is the same
// ReadOnly `git status`, and path invocation must not dodge classification
// of mutating subcommands either.

#[test]
fn absolute_path_git_status_allows() {
    let engine = default_engine();
    let result = engine.evaluate_command("/usr/bin/git status", default_kb());
    assert_eq!(
        result.decision,
        PolicyDecision::Allow,
        "/usr/bin/git status should classify like git status: {result:?}"
    );
}

#[test]
fn absolute_path_git_push_asks() {
    let engine = default_engine();
    let result = engine.evaluate_command("/usr/bin/git push", default_kb());
    assert!(
        result.decision >= PolicyDecision::Ask,
        "/usr/bin/git push must not dodge mutating classification: {result:?}"
    );
}

#[test]
fn backslash_escaped_git_classifies_normally() {
    let engine = default_engine();
    let result = engine.evaluate_command(r"\git push", default_kb());
    assert!(
        result.decision >= PolicyDecision::Ask,
        "backslash-escaped git must not dodge classification: {result:?}"
    );
}

// ── Path-scoped decision inputs ─────────────────────────────────────────
//
// The knowledge layer extracts affected paths during classification; these
// tests pin that the policy engine *surfaces* them on the result (the
// decision-input plumbing) rather than discarding them. Authorization
// against those paths is intentionally out of scope.

/// Collect a result's affected paths as plain strings for assertions.
fn paths_of(result: &PolicyResult) -> Vec<String> {
    result
        .affected_paths
        .iter()
        .map(|w| w.as_str().to_string())
        .collect()
}

#[test]
fn simple_command_surfaces_positional_paths() {
    let engine = default_engine();
    // rm has `positionals = "all"` → both args are affected paths.
    let result = engine.evaluate_command("rm foo.txt bar.txt", default_kb());
    assert_eq!(paths_of(&result), vec!["foo.txt", "bar.txt"]);
    // The single segment carries the same paths.
    assert_eq!(result.segments.len(), 1);
    assert_eq!(
        result.segments[0].affected_paths.as_slice(),
        result.affected_paths.as_slice()
    );
}

#[test]
fn last_positional_path_extraction_reaches_result() {
    let engine = default_engine();
    // cp has `positionals = "last"` → only the destination is the affected path.
    let result = engine.evaluate_command("cp src.txt dest.txt", default_kb());
    assert_eq!(paths_of(&result), vec!["dest.txt"]);
}

#[test]
fn read_only_command_with_no_path_spec_has_empty_paths() {
    let engine = default_engine();
    let result = engine.evaluate_command("ls -la", default_kb());
    assert!(
        result.affected_paths.is_empty(),
        "ls has no path spec → no affected paths: {result:?}"
    );
}

#[test]
fn compound_command_aggregates_paths_across_segments() {
    let engine = default_engine();
    let result = engine.evaluate_command("rm a.txt && touch b.txt", default_kb());
    // Aggregate is the union of both segments' paths.
    assert_eq!(paths_of(&result), vec!["a.txt", "b.txt"]);
    // Each leaf segment carries its own paths.
    let seg_a = result
        .segments
        .iter()
        .find(|s| s.label == "rm a.txt")
        .expect("rm segment");
    let seg_b = result
        .segments
        .iter()
        .find(|s| s.label == "touch b.txt")
        .expect("touch segment");
    assert_eq!(
        seg_a.affected_paths.as_slice(),
        &[Utf8PathBuf::from("a.txt")]
    );
    assert_eq!(
        seg_b.affected_paths.as_slice(),
        &[Utf8PathBuf::from("b.txt")]
    );
}

#[test]
fn compound_command_dedupes_aggregate_paths() {
    let engine = default_engine();
    // Same path touched by two segments → appears once in the aggregate.
    let result = engine.evaluate_command("rm shared.txt && touch shared.txt", default_kb());
    assert_eq!(paths_of(&result), vec!["shared.txt"]);
}

#[test]
fn wrapper_surfaces_inner_command_paths() {
    let engine = default_engine();
    // sudo is a privilege-escalating wrapper; the affected paths are the
    // wrapped command's paths, not the wrapper's.
    let result = engine.evaluate_command("sudo rm /etc/hosts", default_kb());
    assert_eq!(paths_of(&result), vec!["/etc/hosts"]);
}

// ── Env propagation across && and ; segments ────────────────────────────────
//
// These tests verify that env mutations from standalone assignments propagate
// to subsequent segments connected by && or ;, but NOT across |, ||, or &.

#[test]
fn export_propagates_across_and_and() {
    // export GIT_AUTHOR_NAME=AI-Agent && git push
    // The export segment sets GIT_AUTHOR_NAME, which should propagate to
    // the git push segment via &&. The Equals gate should fire.
    let gate = EnvGate {
        var: "GIT_AUTHOR_NAME".into(),
        condition: EnvCondition::Equals("AI-Agent".into()),
        decision: EnvGateAction::Deny,
    };
    let kb = real_kb_with_git_gate(vec![gate]);
    let engine = default_engine();
    let result = engine.evaluate_command("export GIT_AUTHOR_NAME=AI-Agent && git push", &kb);
    assert!(
        result.decision >= PolicyDecision::Deny,
        "export across && should propagate env to the next segment: {result:?}"
    );
}

#[test]
fn bare_assignment_propagates_across_and_and() {
    // FOO=bar && echo $FOO
    // Bare assignment propagates via &&. We verify by checking that a Set
    // gate on FOO fires in the second segment.
    let gate = EnvGate {
        var: "TESTPROP_FOO".into(),
        condition: EnvCondition::Set,
        decision: EnvGateAction::Deny,
    };
    let mut kb = default_kb().clone();
    let mut command = simple_command("echo", agent_command_knowledge::Effect::ReadOnly);
    command.env_gates = vec![gate];
    kb.commands.insert("echo".to_string(), command);

    let engine = default_engine();
    let result = engine.evaluate_command("TESTPROP_FOO=bar && echo hello", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Deny,
        "bare assignment should propagate across &&: {result:?}"
    );
}

#[test]
fn scoped_assignment_does_not_propagate() {
    // FOO=bar cmd && echo $FOO
    // FOO=bar is scoped to cmd (inline assignment with a command), so it
    // should NOT propagate to the next segment.
    let gate = EnvGate {
        var: "TESTPROP_SCOPED".into(),
        condition: EnvCondition::Set,
        decision: EnvGateAction::Deny,
    };
    let mut kb = default_kb().clone();
    let mut command = simple_command("echo", agent_command_knowledge::Effect::ReadOnly);
    command.env_gates = vec![gate];
    kb.commands.insert("echo".to_string(), command);

    let engine = default_engine();
    let result = engine.evaluate_command("TESTPROP_SCOPED=bar ls && echo hello", &kb);
    // TESTPROP_SCOPED is scoped to ls, so echo's gate should NOT fire.
    // echo is ReadOnly → Allow. ls is ReadOnly → Allow. Neither gate fires.
    assert_eq!(
        result.decision,
        PolicyDecision::Allow,
        "scoped assignment (FOO=bar cmd) should NOT propagate across &&: {result:?}"
    );
}

#[test]
fn export_does_not_propagate_across_pipe() {
    // export FOO=bar | cmd
    // Pipe creates a subshell on the left; env mutations do NOT propagate.
    // Note: `export` itself is classified as Unknown (Ask), so the compound
    // decision will be at least Ask. We verify env non-propagation by checking
    // that the cat segment specifically is Allow (its gate did not fire).
    let gate = EnvGate {
        var: "TESTPROP_PIPE".into(),
        condition: EnvCondition::Set,
        decision: EnvGateAction::Deny,
    };
    let mut kb = default_kb().clone();
    let mut command = simple_command("cat", agent_command_knowledge::Effect::ReadOnly);
    command.env_gates = vec![gate];
    kb.commands.insert("cat".to_string(), command);

    let engine = default_engine();
    let result = engine.evaluate_command("export TESTPROP_PIPE=bar | cat", &kb);
    // cat's gate should NOT fire because pipe does not propagate.
    // The cat segment should be Allow (its Set/Deny gate did not fire).
    let cat_segment = result
        .segments
        .iter()
        .find(|s| s.label.contains("cat"))
        .expect("should have a cat segment");
    assert_eq!(
        cat_segment.decision,
        PolicyDecision::Allow,
        "cat's gate should NOT fire across pipe (env not propagated): {result:?}"
    );
}

#[test]
fn export_propagates_across_semicolon() {
    // export FOO=bar ; cmd
    // Semicolon runs commands sequentially in the same shell; env propagates.
    let gate = EnvGate {
        var: "TESTPROP_SEMI".into(),
        condition: EnvCondition::Equals("semicolon-val".into()),
        decision: EnvGateAction::Deny,
    };
    let mut kb = default_kb().clone();
    let mut command = simple_command("echo", agent_command_knowledge::Effect::ReadOnly);
    command.env_gates = vec![gate];
    kb.commands.insert("echo".to_string(), command);

    let engine = default_engine();
    let result = engine.evaluate_command("export TESTPROP_SEMI=semicolon-val ; echo hello", &kb);
    assert_eq!(
        result.decision,
        PolicyDecision::Deny,
        "export should propagate across semicolon: {result:?}"
    );
}
