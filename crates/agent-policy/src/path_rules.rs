//! Path-scoped policy rules for Bash command authorization.
//!
//! Policy rules gain an optional `paths` field — a list of globs (e.g.
//! `~/dev/*`, `/tmp/**`) that constrain *where* a rule applies. When present,
//! the current working directory and/or the command's [`AffectedPaths`] are
//! checked against those globs. If none match, the rule doesn't fire and
//! evaluation falls through to the next matching rule or the effect-class
//! default.
//!
//! Rules without `paths` behave exactly as they do today — no regression.
//!
//! # Evaluation order
//!
//! Path-scoped rules are an ordered list, evaluated before the `HashMap`-based
//! per-command lookup. This gives "allow here, ask everywhere else" semantics:
//! a path-scoped Allow rule can sit above a broader Ask for the same command.
//!
//! # Security
//!
//! - Paths are canonicalized: `..` components are resolved before matching,
//!   preventing traversal bypasses (e.g. `/tmp/safe/../../etc/shadow`
//!   matching a `/tmp/*` allow rule).
//! - `~` is expanded to the user's home directory.
//! - The monotonicity invariant extends to path-scoped rules: a project
//!   config cannot use a path-scoped rule to Allow something the user-level
//!   policy would Ask or Deny.

use camino::Utf8Path;
use serde::{Deserialize, Serialize};

use crate::decision::PolicyDecision;

/// A single path-scoped policy rule for Bash command authorization.
///
/// Evaluated in order within the `path_rules` list. First match wins.
/// The `command` field scopes the rule to a specific base command (e.g.
/// `"git"`); when absent, the rule applies to all commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathRule {
    /// Path glob patterns where this rule applies.
    ///
    /// Supports:
    /// - `~/dev/*` — anything under ~/dev/
    /// - `/tmp/**` — recursive match under /tmp/
    /// - Literal path (no glob) — exact match
    /// - `~` is expanded to the user's home directory
    pub paths: Vec<String>,

    /// The decision to apply when a path matches.
    pub decision: PolicyDecision,

    /// Optional: restrict this rule to a specific base command.
    /// When absent, the rule applies to all commands.
    #[serde(default)]
    pub command: Option<String>,
}

/// Evaluate path-scoped rules against a command's context.
///
/// Returns `Some(decision)` if a rule matched, `None` if no rule applied
/// (caller should fall through to the existing HashMap/effect-class lookup).
///
/// # Arguments
///
/// * `rules` — ordered list of path-scoped rules (first match wins)
/// * `base_command` — the base command name (e.g. "git", "rm")
/// * `cwd` — current working directory from `PreToolUseInput`, if available
/// * `affected_paths` — paths extracted by the knowledge layer
pub fn evaluate_path_rules(
    rules: &[PathRule],
    base_command: &str,
    cwd: Option<&str>,
    affected_paths: &[&str],
) -> Option<PathRuleResult> {
    for rule in rules {
        // If rule is command-scoped, check command match
        if let Some(ref cmd) = rule.command {
            if cmd != base_command {
                continue;
            }
        }

        // Check if any path (CWD or affected paths) matches any rule glob
        if rule_matches(rule, cwd, affected_paths) {
            return Some(PathRuleResult {
                decision: rule.decision,
                matched_rule: rule.clone(),
            });
        }
    }

    None
}

/// Result of a path-scoped rule evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRuleResult {
    /// The authorization decision from the matching rule.
    pub decision: PolicyDecision,
    /// The rule that matched (for diagnostics/logging).
    pub matched_rule: PathRule,
}

/// Check whether any input path matches any of a rule's path globs.
fn rule_matches(rule: &PathRule, cwd: Option<&str>, affected_paths: &[&str]) -> bool {
    let expanded_patterns: Vec<String> = rule.paths.iter().map(|p| expand_tilde(p)).collect();

    // Check CWD
    if let Some(cwd) = cwd {
        let normalized_cwd = resolve_and_normalize(cwd);
        if expanded_patterns
            .iter()
            .any(|pat| path_matches(&normalized_cwd, pat))
        {
            return true;
        }
    }

    // Check affected paths
    for path in affected_paths {
        let normalized = resolve_and_normalize(path);
        if expanded_patterns
            .iter()
            .any(|pat| path_matches(&normalized, pat))
        {
            return true;
        }
    }

    false
}

/// Resolve `..` and `.` components in a path, then normalize.
///
/// This is the security-critical canonicalization step: it prevents path
/// traversal bypasses where `/tmp/safe/../../etc/shadow` would match a
/// `/tmp/*` allow rule without this resolution.
///
/// Unlike `std::fs::canonicalize()`, this is purely lexical — it does not
/// touch the filesystem, so it works with hypothetical paths that may not
/// exist. The trade-off: symlinks are not resolved. This is acceptable
/// because the threat model is user-authored glob rules matching against
/// paths extracted from command arguments, not filesystem access control.
fn resolve_and_normalize(path: &str) -> String {
    let expanded = expand_tilde(path);
    let utf8_path = Utf8Path::new(&expanded);

    // Resolve . and .. components lexically
    let mut components: Vec<&str> = Vec::new();
    let mut is_absolute = false;

    for component in utf8_path.components() {
        match component {
            camino::Utf8Component::RootDir => {
                is_absolute = true;
                components.clear();
            }
            camino::Utf8Component::CurDir => {
                // Skip `.` components
            }
            camino::Utf8Component::ParentDir => {
                // Pop the last component if possible, otherwise keep `..`
                // (for relative paths that escape above root)
                if components.last().is_some_and(|c| *c != "..") {
                    components.pop();
                } else if !is_absolute {
                    components.push("..");
                }
                // For absolute paths, `..` at root is a no-op (can't go above /)
            }
            camino::Utf8Component::Normal(s) => {
                components.push(s);
            }
            camino::Utf8Component::Prefix(_) => {
                // Windows prefix — not expected but handle gracefully
                is_absolute = true;
            }
        }
    }

    if is_absolute {
        if components.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", components.join("/"))
        }
    } else if components.is_empty() {
        ".".to_string()
    } else {
        components.join("/")
    }
}

/// Expand `~` at the start of a path to the user's home directory.
///
/// Only expands a leading `~/` or a bare `~`. Does not expand `~user`.
fn expand_tilde(path: &str) -> String {
    if path == "~" {
        return dirs::home_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string());
    }
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return format!("{}/{rest}", home.display());
        }
    }
    path.to_string()
}

/// Check whether a path matches a rule pattern.
///
/// Matching rules:
/// - Pattern ending in `/*` or `/**`: prefix match (path starts with the
///   prefix before the `*`). The prefix itself also matches.
/// - Pattern ending in just `*`: same as `/*`.
/// - Literal pattern (no `*`): exact match.
fn path_matches(path: &str, pattern: &str) -> bool {
    // Handle glob suffix patterns
    if let Some(prefix) = pattern.strip_suffix("/**") {
        let prefix = prefix.trim_end_matches('/');
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        let prefix = prefix.trim_end_matches('/');
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        let prefix = prefix.trim_end_matches('/');
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }

    // Exact match
    path == pattern
}

#[cfg(test)]
#[path = "path_rules_tests.rs"]
mod path_rules_tests;
