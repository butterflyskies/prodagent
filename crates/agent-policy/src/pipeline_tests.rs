use agent_command_knowledge::{default_knowledge_base, KnowledgeBase};

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
