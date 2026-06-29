//! Unit tests for path-scoped policy rules.

use super::*;

// ── resolve_and_normalize ──────────────────────────────────────────────────

#[test]
fn resolve_dotdot_in_absolute_path() {
    assert_eq!(
        resolve_and_normalize("/tmp/safe/../../etc/shadow"),
        "/etc/shadow"
    );
}

#[test]
fn resolve_dotdot_at_root_clamps() {
    // Can't go above / — .. at root is a no-op
    assert_eq!(resolve_and_normalize("/../../etc"), "/etc");
}

#[test]
fn resolve_dot_components() {
    assert_eq!(resolve_and_normalize("/tmp/./foo/./bar"), "/tmp/foo/bar");
}

#[test]
fn resolve_mixed_dot_and_dotdot() {
    assert_eq!(resolve_and_normalize("/a/./b/../c"), "/a/c");
}

#[test]
fn resolve_relative_dotdot_preserved() {
    // Relative paths that escape above root keep the ..
    assert_eq!(resolve_and_normalize("../../foo"), "../../foo");
}

#[test]
fn resolve_relative_dotdot_partial() {
    assert_eq!(resolve_and_normalize("a/b/../../c"), "c");
}

#[test]
fn resolve_empty_relative() {
    assert_eq!(resolve_and_normalize("."), ".");
}

#[test]
fn resolve_root() {
    assert_eq!(resolve_and_normalize("/"), "/");
}

#[test]
fn resolve_redundant_slashes() {
    assert_eq!(resolve_and_normalize("/tmp//foo///bar"), "/tmp/foo/bar");
}

#[test]
fn resolve_trailing_slash() {
    assert_eq!(resolve_and_normalize("/tmp/foo/"), "/tmp/foo");
}

// ── path_matches ──────────────────────────────────────────────────────────

#[test]
fn exact_match() {
    assert!(path_matches("/home/user/file.txt", "/home/user/file.txt"));
    assert!(!path_matches("/home/user/file.txt", "/home/user/other.txt"));
}

#[test]
fn glob_star_suffix() {
    assert!(path_matches("/home/user/dev/project", "/home/user/dev/*"));
    assert!(path_matches(
        "/home/user/dev/project/file.rs",
        "/home/user/dev/*"
    ));
    // Prefix dir itself matches
    assert!(path_matches("/home/user/dev", "/home/user/dev/*"));
    // Sibling does not
    assert!(!path_matches(
        "/home/user/other/file.rs",
        "/home/user/dev/*"
    ));
}

#[test]
fn glob_double_star_suffix() {
    assert!(path_matches("/tmp/foo/bar/baz", "/tmp/**"));
    assert!(path_matches("/tmp/foo", "/tmp/**"));
    assert!(path_matches("/tmp", "/tmp/**"));
    assert!(!path_matches("/var/tmp", "/tmp/**"));
}

#[test]
fn no_partial_prefix_match() {
    // /home/user/develop should NOT match /home/user/dev/*
    assert!(!path_matches("/home/user/develop", "/home/user/dev/*"));
}

// ── expand_tilde ──────────────────────────────────────────────────────────

#[test]
fn expand_tilde_with_suffix() {
    // Core assertion: non-tilde paths pass through unchanged
    assert_eq!(expand_tilde("/abs/path"), "/abs/path");

    // Tilde expansion only testable when HOME is set
    if let Some(home) = dirs::home_dir() {
        let expanded = expand_tilde("~/dev/project");
        assert_eq!(expanded, format!("{}/dev/project", home.display()));
    }
}

#[test]
fn expand_tilde_bare() {
    if let Some(home) = dirs::home_dir() {
        let expanded = expand_tilde("~");
        assert_eq!(expanded, home.to_string_lossy().as_ref());
    }
}

#[test]
fn no_expand_mid_path() {
    let expanded = expand_tilde("/home/~/file");
    assert_eq!(expanded, "/home/~/file");
}

// ── P1: path traversal bypass ─────────────────────────────────────────────

#[test]
fn traversal_bypass_blocked() {
    // The P1 from PR #76: /tmp/safe/../../etc/shadow should NOT match /tmp/*
    let rules = vec![PathRule {
        paths: vec!["/tmp/*".to_string()],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    // Without .. resolution, this would match. With it, it resolves to
    // /etc/shadow which is outside /tmp/*.
    let result = evaluate_path_rules(&rules, "cat", None, &["/tmp/safe/../../etc/shadow"]);
    assert!(
        result.is_none(),
        "path traversal via .. must not match /tmp/* rule"
    );
}

#[test]
fn traversal_within_allowed_prefix_still_matches() {
    // /tmp/a/../b resolves to /tmp/b, which IS under /tmp/*
    let rules = vec![PathRule {
        paths: vec!["/tmp/*".to_string()],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    let result = evaluate_path_rules(&rules, "cat", None, &["/tmp/a/../b"]);
    assert!(
        result.is_some(),
        "/tmp/a/../b -> /tmp/b should match /tmp/*"
    );
    assert_eq!(result.unwrap().decision, PolicyDecision::Allow);
}

// ── evaluate_path_rules ───────────────────────────────────────────────────

#[test]
fn no_rules_returns_none() {
    let result = evaluate_path_rules(&[], "git", Some("/home/user/dev"), &[]);
    assert!(result.is_none());
}

#[test]
fn cwd_matches_rule() {
    let rules = vec![PathRule {
        paths: vec!["/home/testuser/dev/*".to_string()],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    let result = evaluate_path_rules(&rules, "git", Some("/home/testuser/dev/my-project"), &[]);
    assert!(result.is_some(), "CWD under the rule's prefix should match");
    assert_eq!(result.unwrap().decision, PolicyDecision::Allow);
}

#[test]
fn cwd_matches_rule_with_tilde() {
    // Tilde expansion: only runs when HOME is set
    if let Some(home) = dirs::home_dir() {
        let rules = vec![PathRule {
            paths: vec!["~/dev/*".to_string()],
            decision: PolicyDecision::Allow,
            command: None,
        }];

        let cwd = format!("{}/dev/my-project", home.display());
        let result = evaluate_path_rules(&rules, "git", Some(&cwd), &[]);
        assert!(result.is_some(), "tilde-expanded CWD should match");
        assert_eq!(result.unwrap().decision, PolicyDecision::Allow);
    }
}

#[test]
fn affected_path_matches_rule() {
    let rules = vec![PathRule {
        paths: vec!["/tmp/*".to_string()],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    let result = evaluate_path_rules(&rules, "rm", None, &["/tmp/scratch.txt"]);
    assert!(result.is_some());
    assert_eq!(result.unwrap().decision, PolicyDecision::Allow);
}

#[test]
fn no_match_falls_through() {
    let rules = vec![PathRule {
        paths: vec!["/tmp/*".to_string()],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    let result = evaluate_path_rules(&rules, "rm", Some("/etc"), &["/etc/shadow"]);
    assert!(result.is_none(), "no match should fall through");
}

#[test]
fn command_scoped_rule_matches_only_that_command() {
    let rules = vec![PathRule {
        paths: vec!["/tmp/*".to_string()],
        decision: PolicyDecision::Allow,
        command: Some("git".to_string()),
    }];

    // git should match
    let result = evaluate_path_rules(&rules, "git", Some("/tmp/repo"), &[]);
    assert!(result.is_some());

    // rm should not match (different command)
    let result = evaluate_path_rules(&rules, "rm", Some("/tmp/file"), &[]);
    assert!(result.is_none());
}

#[test]
fn first_matching_rule_wins() {
    let rules = vec![
        PathRule {
            paths: vec!["/tmp/sensitive/*".to_string()],
            decision: PolicyDecision::Deny,
            command: None,
        },
        PathRule {
            paths: vec!["/tmp/*".to_string()],
            decision: PolicyDecision::Allow,
            command: None,
        },
    ];

    // /tmp/sensitive/ — first rule wins (deny)
    let result = evaluate_path_rules(&rules, "rm", None, &["/tmp/sensitive/data.txt"]);
    assert_eq!(result.unwrap().decision, PolicyDecision::Deny);

    // /tmp/other — second rule wins (allow)
    let result = evaluate_path_rules(&rules, "rm", None, &["/tmp/other.txt"]);
    assert_eq!(result.unwrap().decision, PolicyDecision::Allow);
}

#[test]
fn multiple_path_globs_in_rule() {
    let rules = vec![PathRule {
        paths: vec!["/tmp/*".to_string(), "~/dev/*".to_string()],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    // /tmp match
    let result = evaluate_path_rules(&rules, "git", Some("/tmp/repo"), &[]);
    assert!(result.is_some());

    // ~/dev match
    if let Some(home) = dirs::home_dir() {
        let cwd = format!("{}/dev/project", home.display());
        let result = evaluate_path_rules(&rules, "git", Some(&cwd), &[]);
        assert!(result.is_some());
    }

    // Neither
    let result = evaluate_path_rules(&rules, "git", Some("/etc"), &[]);
    assert!(result.is_none());
}

#[test]
fn cwd_with_dotdot_resolved_before_matching() {
    let rules = vec![PathRule {
        paths: vec!["/home/user/dev/*".to_string()],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    // CWD with .. that resolves INTO the allowed prefix
    let result = evaluate_path_rules(&rules, "git", Some("/home/user/dev/a/../b"), &[]);
    assert!(result.is_some());

    // CWD with .. that resolves OUTSIDE the allowed prefix
    let result = evaluate_path_rules(&rules, "git", Some("/home/user/dev/../etc"), &[]);
    assert!(result.is_none());
}

// ── Serialization round-trip ──────────────────────────────────────────────

#[test]
fn path_rule_toml_round_trip() {
    let rule = PathRule {
        paths: vec!["~/dev/*".to_string(), "/tmp/*".to_string()],
        decision: PolicyDecision::Allow,
        command: Some("git".to_string()),
    };

    let serialized = toml::to_string(&rule).expect("serialize");
    let deserialized: PathRule = toml::from_str(&serialized).expect("deserialize");
    assert_eq!(deserialized, rule);
}

#[test]
fn path_rule_toml_without_command() {
    let toml_str = r#"
paths = ["~/dev/*"]
decision = "allow"
"#;
    let rule: PathRule = toml::from_str(toml_str).expect("parse");
    assert_eq!(rule.command, None);
    assert_eq!(rule.decision, PolicyDecision::Allow);
    assert_eq!(rule.paths, vec!["~/dev/*"]);
}
