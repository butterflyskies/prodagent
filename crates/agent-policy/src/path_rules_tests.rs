//! Unit tests for path-scoped policy rules and [`PathGlob`].

use super::*;

/// Default fallback decision for tests that only care about path-rule
/// matching, not the command-level composition.  Allow is the identity
/// for `max`, so the path rule's own decision shows through.
const DEFAULT: PolicyDecision = PolicyDecision::Allow;

/// Construct a [`PathGlob`] from a string literal — panics on invalid patterns.
fn pg(s: &str) -> PathGlob {
    PathGlob::new(s.to_string()).expect("test pattern should be valid")
}

// ══════════════════════════════════════════════════════════════════════════
// PathGlob construction
// ══════════════════════════════════════════════════════════════════════════

#[test]
fn path_glob_valid_patterns() {
    assert!(PathGlob::new("/tmp/*".into()).is_ok());
    assert!(PathGlob::new("/tmp/**".into()).is_ok());
    assert!(PathGlob::new("~/dev/*".into()).is_ok());
    assert!(PathGlob::new("/etc/shadow".into()).is_ok());
    assert!(PathGlob::new("/home/user/dev/project".into()).is_ok());
    assert!(PathGlob::new("/tmp/foo*".into()).is_ok());
}

#[test]
fn path_glob_rejects_empty() {
    assert_eq!(PathGlob::new(String::new()), Err(PathGlobError::Empty));
    assert_eq!(PathGlob::new("   ".into()), Err(PathGlobError::Empty));
}

#[test]
fn path_glob_rejects_bare_star() {
    assert!(matches!(
        PathGlob::new("*".into()),
        Err(PathGlobError::BareGlob(_))
    ));
    assert!(matches!(
        PathGlob::new("**".into()),
        Err(PathGlobError::BareGlob(_))
    ));
    // Trimmed bare globs also rejected
    assert!(matches!(
        PathGlob::new("  *  ".into()),
        Err(PathGlobError::BareGlob(_))
    ));
    assert!(matches!(
        PathGlob::new("  **  ".into()),
        Err(PathGlobError::BareGlob(_))
    ));
}

#[test]
fn path_glob_rejects_root_bare_globs() {
    // /* and /** are root-level universal globs — match everything under /
    assert!(matches!(
        PathGlob::new("/*".into()),
        Err(PathGlobError::BareGlob(_))
    ));
    assert!(matches!(
        PathGlob::new("/**".into()),
        Err(PathGlobError::BareGlob(_))
    ));
    // Trimmed variants
    assert!(matches!(
        PathGlob::new("  /*  ".into()),
        Err(PathGlobError::BareGlob(_))
    ));
    assert!(matches!(
        PathGlob::new("  /**  ".into()),
        Err(PathGlobError::BareGlob(_))
    ));
}

#[test]
fn path_glob_deref() {
    let g = pg("/tmp/*");
    let s: &str = &g;
    assert_eq!(s, "/tmp/*");
    assert_eq!(g.as_str(), "/tmp/*");
    assert_eq!(g.as_ref() as &str, "/tmp/*");
}

#[test]
fn path_glob_debug_shows_string() {
    let g = pg("/tmp/*");
    assert_eq!(format!("{g:?}"), "\"/tmp/*\"");
}

#[test]
fn path_glob_display() {
    let g = pg("/tmp/*");
    assert_eq!(format!("{g}"), "/tmp/*");
}

#[test]
fn path_glob_try_from_string() {
    let g: Result<PathGlob, _> = "/tmp/*".to_string().try_into();
    assert!(g.is_ok());
    let g: Result<PathGlob, _> = "".to_string().try_into();
    assert!(g.is_err());
}

#[test]
fn path_glob_try_from_str() {
    let g: Result<PathGlob, _> = PathGlob::try_from("/tmp/*");
    assert!(g.is_ok());
    let g: Result<PathGlob, _> = PathGlob::try_from("*");
    assert!(g.is_err());
}

#[test]
fn path_glob_into_inner() {
    let g = pg("~/dev/*");
    assert_eq!(g.into_inner(), "~/dev/*");
}

// ── PathGlob serde ─────────────────────────────────────────────────────────

#[test]
fn path_glob_serde_round_trip() {
    let g = pg("/tmp/*");
    let json = serde_json::to_string(&g).expect("serialize");
    assert_eq!(json, "\"/tmp/*\"");
    let deserialized: PathGlob = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deserialized, g);
}

#[test]
fn path_glob_deserialize_rejects_invalid() {
    let result: Result<PathGlob, _> = serde_json::from_str("\"\"");
    assert!(result.is_err(), "empty string should fail deserialization");

    let result: Result<PathGlob, _> = serde_json::from_str("\"*\"");
    assert!(result.is_err(), "bare * should fail deserialization");

    let result: Result<PathGlob, _> = serde_json::from_str("\"**\"");
    assert!(result.is_err(), "bare ** should fail deserialization");

    let result: Result<PathGlob, _> = serde_json::from_str("\"/*\"");
    assert!(result.is_err(), "root /* should fail deserialization");

    let result: Result<PathGlob, _> = serde_json::from_str("\"/**\"");
    assert!(result.is_err(), "root /** should fail deserialization");
}

// ══════════════════════════════════════════════════════════════════════════
// resolve_and_normalize
// ══════════════════════════════════════════════════════════════════════════

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

// ── is_glob_pattern ──────────────────────────────────────────────────────

#[test]
fn is_glob_pattern_detects_star() {
    assert!(is_glob_pattern("/tmp/*"));
    assert!(is_glob_pattern("/tmp/**"));
    assert!(is_glob_pattern("/tmp/foo*"));
    assert!(!is_glob_pattern("/tmp/foo"));
    assert!(!is_glob_pattern("/etc/shadow"));
}

// ── P1: path traversal bypass ─────────────────────────────────────────────

#[test]
fn traversal_bypass_blocked() {
    // The P1 from PR #76: /tmp/safe/../../etc/shadow should NOT match /tmp/*
    let rules = vec![PathRule {
        paths: vec![pg("/tmp/*")],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    // Without .. resolution, this would match. With it, it resolves to
    // /etc/shadow which is outside /tmp/*.
    let result = evaluate_path_rules(
        &rules,
        "cat",
        None,
        &["/tmp/safe/../../etc/shadow"],
        DEFAULT,
    );
    assert!(
        result.is_none(),
        "path traversal via .. must not match /tmp/* rule"
    );
}

#[test]
fn traversal_within_allowed_prefix_still_matches() {
    // /tmp/a/../b resolves to /tmp/b, which IS under /tmp/*
    let rules = vec![PathRule {
        paths: vec![pg("/tmp/*")],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    let result = evaluate_path_rules(&rules, "cat", None, &["/tmp/a/../b"], DEFAULT);
    assert!(
        result.is_some(),
        "/tmp/a/../b -> /tmp/b should match /tmp/*"
    );
    assert_eq!(result.unwrap().decision, PolicyDecision::Allow);
}

// ── evaluate_path_rules: basic matching ─────────────────────────────────

#[test]
fn no_rules_returns_none() {
    let result = evaluate_path_rules(&[], "git", Some("/home/user/dev"), &[], DEFAULT);
    assert!(result.is_none());
}

#[test]
fn cwd_matches_rule() {
    let rules = vec![PathRule {
        paths: vec![pg("/home/testuser/dev/*")],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    let result = evaluate_path_rules(
        &rules,
        "git",
        Some("/home/testuser/dev/my-project"),
        &[],
        DEFAULT,
    );
    assert!(result.is_some(), "CWD under the rule's prefix should match");
    assert_eq!(result.unwrap().decision, PolicyDecision::Allow);
}

#[test]
fn cwd_matches_rule_with_tilde() {
    // Tilde expansion: only runs when HOME is set
    if let Some(home) = dirs::home_dir() {
        let rules = vec![PathRule {
            paths: vec![pg("~/dev/*")],
            decision: PolicyDecision::Allow,
            command: None,
        }];

        let cwd = format!("{}/dev/my-project", home.display());
        let result = evaluate_path_rules(&rules, "git", Some(&cwd), &[], DEFAULT);
        assert!(result.is_some(), "tilde-expanded CWD should match");
        assert_eq!(result.unwrap().decision, PolicyDecision::Allow);
    }
}

#[test]
fn affected_path_matches_rule() {
    let rules = vec![PathRule {
        paths: vec![pg("/tmp/*")],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    let result = evaluate_path_rules(&rules, "rm", None, &["/tmp/scratch.txt"], DEFAULT);
    assert!(result.is_some());
    assert_eq!(result.unwrap().decision, PolicyDecision::Allow);
}

#[test]
fn no_match_falls_through() {
    let rules = vec![PathRule {
        paths: vec![pg("/tmp/*")],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    let result = evaluate_path_rules(&rules, "rm", Some("/etc"), &["/etc/shadow"], DEFAULT);
    assert!(result.is_none(), "no match should fall through");
}

#[test]
fn command_scoped_rule_matches_only_that_command() {
    let rules = vec![PathRule {
        paths: vec![pg("/tmp/*")],
        decision: PolicyDecision::Allow,
        command: Some("git".to_string()),
    }];

    // git should match
    let result = evaluate_path_rules(&rules, "git", Some("/tmp/repo"), &[], DEFAULT);
    assert!(result.is_some());

    // rm should not match (different command)
    let result = evaluate_path_rules(&rules, "rm", Some("/tmp/file"), &[], DEFAULT);
    assert!(result.is_none());
}

#[test]
fn first_matching_rule_wins_within_tier() {
    let rules = vec![
        PathRule {
            paths: vec![pg("/tmp/sensitive/*")],
            decision: PolicyDecision::Deny,
            command: None,
        },
        PathRule {
            paths: vec![pg("/tmp/*")],
            decision: PolicyDecision::Allow,
            command: None,
        },
    ];

    // /tmp/sensitive/ — first rule wins (deny)
    let result = evaluate_path_rules(&rules, "rm", None, &["/tmp/sensitive/data.txt"], DEFAULT);
    assert_eq!(result.unwrap().decision, PolicyDecision::Deny);

    // /tmp/other — second rule wins (allow)
    let result = evaluate_path_rules(&rules, "rm", None, &["/tmp/other.txt"], DEFAULT);
    assert_eq!(result.unwrap().decision, PolicyDecision::Allow);
}

#[test]
fn multiple_path_globs_in_rule() {
    let rules = vec![PathRule {
        paths: vec![pg("/tmp/*"), pg("~/dev/*")],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    // /tmp match
    let result = evaluate_path_rules(&rules, "git", Some("/tmp/repo"), &[], DEFAULT);
    assert!(result.is_some());

    // ~/dev match
    if let Some(home) = dirs::home_dir() {
        let cwd = format!("{}/dev/project", home.display());
        let result = evaluate_path_rules(&rules, "git", Some(&cwd), &[], DEFAULT);
        assert!(result.is_some());
    }

    // Neither
    let result = evaluate_path_rules(&rules, "git", Some("/etc"), &[], DEFAULT);
    assert!(result.is_none());
}

#[test]
fn cwd_with_dotdot_resolved_before_matching() {
    let rules = vec![PathRule {
        paths: vec![pg("/home/user/dev/*")],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    // CWD with .. that resolves INTO the allowed prefix
    let result = evaluate_path_rules(&rules, "git", Some("/home/user/dev/a/../b"), &[], DEFAULT);
    assert!(result.is_some());

    // CWD with .. that resolves OUTSIDE the allowed prefix
    let result = evaluate_path_rules(&rules, "git", Some("/home/user/dev/../etc"), &[], DEFAULT);
    assert!(result.is_none());
}

// ── Per-path evaluation (new model) ─────────────────────────────────────

#[test]
fn multi_path_deny_wins() {
    // cp ~/dev/foo /etc/shadow
    // ~/dev/* Allow, /etc/* Deny → Deny wins
    let rules = vec![
        PathRule {
            paths: vec![pg("/home/user/dev/*")],
            decision: PolicyDecision::Allow,
            command: None,
        },
        PathRule {
            paths: vec![pg("/etc/*")],
            decision: PolicyDecision::Deny,
            command: None,
        },
    ];

    let result = evaluate_path_rules(
        &rules,
        "cp",
        None,
        &["/home/user/dev/foo", "/etc/shadow"],
        DEFAULT,
    );
    assert_eq!(
        result.unwrap().decision,
        PolicyDecision::Deny,
        "any-deny-wins across multiple paths"
    );
}

#[test]
fn multi_path_all_allow() {
    // cp ~/dev/foo ~/dev/bar → both match Allow → Allow
    let rules = vec![PathRule {
        paths: vec![pg("/home/user/dev/*")],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    let result = evaluate_path_rules(
        &rules,
        "cp",
        None,
        &["/home/user/dev/foo", "/home/user/dev/bar"],
        DEFAULT,
    );
    assert_eq!(result.unwrap().decision, PolicyDecision::Allow);
}

#[test]
fn multi_path_mixed_with_fallback() {
    // One path matches Allow rule, other matches no rule → uses command_default.
    // command_default = Ask. Path that matched: max(Allow, Ask) = Ask.
    // Path that didn't match: Ask (command_default). Overall: max(Ask, Ask) = Ask.
    let rules = vec![PathRule {
        paths: vec![pg("/home/user/dev/*")],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    let result = evaluate_path_rules(
        &rules,
        "cp",
        None,
        &["/home/user/dev/foo", "/tmp/file"],
        PolicyDecision::Ask,
    );
    assert_eq!(
        result.unwrap().decision,
        PolicyDecision::Ask,
        "path Allow composed with command Ask → Ask; unmatched path → Ask; max=Ask"
    );
}

#[test]
fn per_path_independent_evaluation() {
    // Old model: ALL paths must match a single rule. This test verifies the
    // new model where each path is evaluated independently.
    //
    // Rule 1: /tmp/sensitive/* → Deny
    // Rule 2: /tmp/* → Allow
    //
    // cp /tmp/sensitive/data /tmp/other →
    //   /tmp/sensitive/data → Rule 1: max(Deny, Allow) = Deny
    //   /tmp/other → Rule 2: max(Allow, Allow) = Allow
    //   max(Deny, Allow) = Deny
    let rules = vec![
        PathRule {
            paths: vec![pg("/tmp/sensitive/*")],
            decision: PolicyDecision::Deny,
            command: None,
        },
        PathRule {
            paths: vec![pg("/tmp/*")],
            decision: PolicyDecision::Allow,
            command: None,
        },
    ];

    let result = evaluate_path_rules(
        &rules,
        "cp",
        None,
        &["/tmp/sensitive/data", "/tmp/other"],
        DEFAULT,
    );
    assert_eq!(
        result.unwrap().decision,
        PolicyDecision::Deny,
        "each path independently matched: sensitive→Deny, other→Allow, max=Deny"
    );
}

// ── Tiered evaluation model ───────────────────────────────────────────────

#[test]
fn cmd_path_overrides_everything() {
    // Command+path rules (tier 1) override unscoped path rules AND command default.
    let rules = vec![
        // Unscoped: /etc/** → Deny
        PathRule {
            paths: vec![pg("/etc/**")],
            decision: PolicyDecision::Deny,
            command: None,
        },
        // Command+path: cat /etc/os-release → Allow
        PathRule {
            paths: vec![pg("/etc/os-release")],
            decision: PolicyDecision::Allow,
            command: Some("cat".to_string()),
        },
    ];

    // cat /etc/os-release → command+path Allow wins (tier 1)
    let result = evaluate_path_rules(
        &rules,
        "cat",
        None,
        &["/etc/os-release"],
        PolicyDecision::Ask,
    );
    assert_eq!(
        result.unwrap().decision,
        PolicyDecision::Allow,
        "command+path Allow overrides unscoped Deny and command Ask"
    );
}

#[test]
fn tier2_path_and_command_compose_via_max() {
    // When no command+path rule matches, path-only and command-only
    // compose via max (strictest wins).
    let rules = vec![PathRule {
        paths: vec![pg("/tmp/*")],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    // Path-only Allow, command-only Ask → max(Allow, Ask) = Ask
    let result = evaluate_path_rules(
        &rules,
        "rm",
        None,
        &["/tmp/scratch.txt"],
        PolicyDecision::Ask,
    );
    assert_eq!(
        result.unwrap().decision,
        PolicyDecision::Ask,
        "max(path=Allow, cmd=Ask) = Ask"
    );

    // Path-only Allow, command-only Allow → max(Allow, Allow) = Allow
    let result = evaluate_path_rules(
        &rules,
        "ls",
        None,
        &["/tmp/scratch.txt"],
        PolicyDecision::Allow,
    );
    assert_eq!(
        result.unwrap().decision,
        PolicyDecision::Allow,
        "max(path=Allow, cmd=Allow) = Allow"
    );

    // Path-only Allow, command-only Deny → max(Allow, Deny) = Deny
    let result = evaluate_path_rules(
        &rules,
        "rm",
        None,
        &["/tmp/scratch.txt"],
        PolicyDecision::Deny,
    );
    assert_eq!(
        result.unwrap().decision,
        PolicyDecision::Deny,
        "max(path=Allow, cmd=Deny) = Deny"
    );
}

#[test]
fn no_path_rule_uses_command_default() {
    // When no path rule matches, evaluate_path_rules returns None.
    let rules = vec![PathRule {
        paths: vec![pg("/tmp/*")],
        decision: PolicyDecision::Allow,
        command: None,
    }];

    let result = evaluate_path_rules(&rules, "rm", None, &["/etc/shadow"], PolicyDecision::Deny);
    assert!(
        result.is_none(),
        "no path rule match → returns None (caller uses command_default)"
    );
}

#[test]
fn exact_path_beats_glob_in_unscoped() {
    // Exact match has higher specificity than glob within unscoped rules.
    let rules = vec![
        // Glob: /etc/** → Deny (listed first, but less specific)
        PathRule {
            paths: vec![pg("/etc/**")],
            decision: PolicyDecision::Deny,
            command: None,
        },
        // Exact: /etc/fake-file → Allow (listed second, but more specific)
        PathRule {
            paths: vec![pg("/etc/fake-file")],
            decision: PolicyDecision::Allow,
            command: None,
        },
    ];

    // /etc/fake-file → exact match wins over glob → Allow
    let result = evaluate_path_rules(&rules, "cat", None, &["/etc/fake-file"], DEFAULT);
    assert_eq!(
        result.unwrap().decision,
        PolicyDecision::Allow,
        "exact match /etc/fake-file must beat glob /etc/**"
    );

    // /etc/shadow → no exact match, glob fires → Deny
    let result = evaluate_path_rules(&rules, "cat", None, &["/etc/shadow"], DEFAULT);
    assert_eq!(
        result.unwrap().decision,
        PolicyDecision::Deny,
        "/etc/shadow matches only the glob → Deny"
    );
}

#[test]
fn cwd_uses_tiered_evaluation() {
    // CWD-only evaluation also uses the tiered model.
    let rules = vec![
        PathRule {
            paths: vec![pg("/tmp/*")],
            decision: PolicyDecision::Ask,
            command: None,
        },
        PathRule {
            paths: vec![pg("/tmp/*")],
            decision: PolicyDecision::Allow,
            command: Some("git".to_string()),
        },
    ];

    // git in /tmp → command+path Allow wins (tier 1)
    let result = evaluate_path_rules(&rules, "git", Some("/tmp/repo"), &[], DEFAULT);
    assert_eq!(
        result.unwrap().decision,
        PolicyDecision::Allow,
        "CWD: command+path rule wins"
    );

    // rm in /tmp → no command+path rule → tier 2: max(path=Ask, cmd=DEFAULT=Allow) = Ask
    let result = evaluate_path_rules(&rules, "rm", Some("/tmp/repo"), &[], DEFAULT);
    assert_eq!(
        result.unwrap().decision,
        PolicyDecision::Ask,
        "CWD: unscoped Ask composes with command default"
    );
}

// ── Spec test cases (from 🦋) ──────────────────────────────────────────────

/// Build the canonical test rule set from the spec.
///
/// Rules:
/// - path: /etc/** → deny
/// - path: /etc/fake-file → allow
/// - command: cat, path: /etc/os-release → allow
/// - command: rm, path: /tmp/** → allow
///
/// Command-level defaults (passed as command_default):
/// - cat → Allow (read-only effect default)
/// - rm  → Ask  (mutating effect default)
fn spec_rules() -> Vec<PathRule> {
    vec![
        PathRule {
            paths: vec![pg("/etc/**")],
            decision: PolicyDecision::Deny,
            command: None,
        },
        PathRule {
            paths: vec![pg("/etc/fake-file")],
            decision: PolicyDecision::Allow,
            command: None,
        },
        PathRule {
            paths: vec![pg("/etc/os-release")],
            decision: PolicyDecision::Allow,
            command: Some("cat".to_string()),
        },
        PathRule {
            paths: vec![pg("/tmp/**")],
            decision: PolicyDecision::Allow,
            command: Some("rm".to_string()),
        },
    ]
}

#[test]
fn spec_cat_etc_os_release() {
    // $ cat /etc/os-release → allow (command+path rule)
    let rules = spec_rules();
    let result = evaluate_path_rules(
        &rules,
        "cat",
        None,
        &["/etc/os-release"],
        PolicyDecision::Allow, // cat = read-only → Allow
    );
    assert_eq!(
        result.unwrap().decision,
        PolicyDecision::Allow,
        "cat /etc/os-release: command+path rule → Allow"
    );
}

#[test]
fn spec_cat_etc_os_release_and_passwd() {
    // $ cat /etc/os-release /etc/passwd → deny
    //   os-release: command+path → Allow
    //   passwd: no cat+path rule → tier 2: max(path=/etc/**→Deny, cmd=Allow) = Deny
    //   max(Allow, Deny) = Deny
    let rules = spec_rules();
    let result = evaluate_path_rules(
        &rules,
        "cat",
        None,
        &["/etc/os-release", "/etc/passwd"],
        PolicyDecision::Allow,
    );
    assert_eq!(
        result.unwrap().decision,
        PolicyDecision::Deny,
        "cat /etc/os-release /etc/passwd: os-release=Allow, passwd=Deny, max=Deny"
    );
}

#[test]
fn spec_rm_tmp_blep() {
    // $ rm /tmp/blep → allow (command+path rule: rm + /tmp/**)
    let rules = spec_rules();
    let result = evaluate_path_rules(
        &rules,
        "rm",
        None,
        &["/tmp/blep"],
        PolicyDecision::Ask, // rm = mutating → Ask
    );
    assert_eq!(
        result.unwrap().decision,
        PolicyDecision::Allow,
        "rm /tmp/blep: command+path rule → Allow"
    );
}

#[test]
fn spec_rm_tmp_blep_and_etc_os_release() {
    // $ rm /tmp/blep /etc/os-release → deny
    //   blep: rm+/tmp/** → Allow (command+path)
    //   os-release: no rm+path rule → tier 2: max(path=/etc/**→Deny, cmd=rm→Ask) = Deny
    //   max(Allow, Deny) = Deny
    let rules = spec_rules();
    let result = evaluate_path_rules(
        &rules,
        "rm",
        None,
        &["/tmp/blep", "/etc/os-release"],
        PolicyDecision::Ask,
    );
    assert_eq!(
        result.unwrap().decision,
        PolicyDecision::Deny,
        "rm /tmp/blep /etc/os-release: blep=Allow, os-release=Deny, max=Deny"
    );
}

#[test]
fn spec_rm_tmp_blep_and_etc_shadow() {
    // $ rm /tmp/blep /etc/shadow → deny
    //   blep: rm+/tmp/** → Allow (command+path)
    //   shadow: no rm+path rule → tier 2: max(path=/etc/**→Deny, cmd=rm→Ask) = Deny
    //   max(Allow, Deny) = Deny
    let rules = spec_rules();
    let result = evaluate_path_rules(
        &rules,
        "rm",
        None,
        &["/tmp/blep", "/etc/shadow"],
        PolicyDecision::Ask,
    );
    assert_eq!(
        result.unwrap().decision,
        PolicyDecision::Deny,
        "rm /tmp/blep /etc/shadow: blep=Allow, shadow=Deny, max=Deny"
    );
}

#[test]
fn spec_rm_tmp_blep_and_etc_fake_file() {
    // $ rm /tmp/blep /etc/fake-file → ask
    //   blep: rm+/tmp/** → Allow (command+path)
    //   fake-file: no rm+path rule → tier 2:
    //     path: exact /etc/fake-file → Allow (beats glob /etc/**→Deny)
    //     cmd: rm → Ask
    //     max(Allow, Ask) = Ask
    //   max(Allow, Ask) = Ask
    let rules = spec_rules();
    let result = evaluate_path_rules(
        &rules,
        "rm",
        None,
        &["/tmp/blep", "/etc/fake-file"],
        PolicyDecision::Ask,
    );
    assert_eq!(
        result.unwrap().decision,
        PolicyDecision::Ask,
        "rm /tmp/blep /etc/fake-file: blep=Allow, fake-file=max(Allow,Ask)=Ask, max=Ask"
    );
}

// ── Serialization round-trip ──────────────────────────────────────────────

#[test]
fn path_rule_toml_round_trip() {
    let rule = PathRule {
        paths: vec![pg("~/dev/*"), pg("/tmp/*")],
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
    assert_eq!(rule.paths, vec![pg("~/dev/*")]);
}

#[test]
fn path_rule_toml_rejects_bare_glob() {
    let toml_str = r#"
paths = ["*"]
decision = "allow"
"#;
    let result: Result<PathRule, _> = toml::from_str(toml_str);
    assert!(result.is_err(), "bare glob should fail deserialization");
}

#[test]
fn path_rule_toml_rejects_root_bare_globs() {
    for pat in ["/*", "/**"] {
        let toml_str = format!(
            r#"
paths = ["{pat}"]
decision = "allow"
"#
        );
        let result: Result<PathRule, _> = toml::from_str(&toml_str);
        assert!(
            result.is_err(),
            "root bare glob {pat:?} should fail deserialization"
        );
    }
}

#[test]
fn path_rule_toml_rejects_empty_pattern() {
    let toml_str = r#"
paths = [""]
decision = "allow"
"#;
    let result: Result<PathRule, _> = toml::from_str(toml_str);
    assert!(result.is_err(), "empty pattern should fail deserialization");
}

// ══════════════════════════════════════════════════════════════════════════
// Property-based tests for PathGlob invariants
// ══════════════════════════════════════════════════════════════════════════

mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// If `PathGlob::new` accepts a string, it must be non-empty after
        /// trimming and not a bare glob pattern.
        #[test]
        fn valid_glob_is_nonempty_and_not_bare(s in ".*") {
            if let Ok(g) = PathGlob::new(s.clone()) {
                let trimmed = s.trim();
                prop_assert!(!trimmed.is_empty(), "accepted empty string");
                prop_assert!(
                    !matches!(trimmed, "*" | "**" | "/*" | "/**"),
                    "accepted bare glob: {trimmed:?}"
                );
                // Inner string is preserved exactly
                prop_assert_eq!(g.as_str(), &s);
            }
        }

        /// Serde round-trip preserves a valid PathGlob exactly.
        #[test]
        fn serde_json_round_trip(s in "[/~][a-z0-9/_.*-]{1,50}") {
            if let Ok(g) = PathGlob::new(s) {
                let json = serde_json::to_string(&g).unwrap();
                let back: PathGlob = serde_json::from_str(&json).unwrap();
                prop_assert_eq!(back, g);
            }
        }

        /// Display returns the original pattern string.
        #[test]
        fn display_matches_inner(s in "[/~][a-z0-9/_.*-]{1,50}") {
            if let Ok(g) = PathGlob::new(s.clone()) {
                prop_assert_eq!(format!("{g}"), s);
            }
        }

        /// Deref, as_str, and AsRef all agree.
        #[test]
        fn deref_asref_consistency(s in "[/~][a-z0-9/_.*-]{1,50}") {
            if let Ok(g) = PathGlob::new(s) {
                let deref: &str = &g;
                let as_str = g.as_str();
                let as_ref: &str = g.as_ref();
                prop_assert_eq!(deref, as_str);
                prop_assert_eq!(deref, as_ref);
            }
        }
    }
}
