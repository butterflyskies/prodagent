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
    let expanded_patterns: Vec<String> = rule.paths.iter().map(|p| normalize_pattern(p)).collect();

    let cwd_matches = cwd.is_some_and(|cwd| {
        let normalized_cwd = resolve_and_normalize(cwd);
        expanded_patterns
            .iter()
            .any(|pat| path_matches(&normalized_cwd, pat))
    });

    if affected_paths.is_empty() {
        // No affected paths extracted — CWD alone determines the match.
        return cwd_matches;
    }

    // Affected paths exist — ALL must match the rule's globs.
    // CWD match alone is not sufficient when the command touches
    // paths outside the allowed prefix.
    affected_paths.iter().all(|path| {
        let normalized = resolve_and_normalize(path);
        expanded_patterns
            .iter()
            .any(|pat| path_matches(&normalized, pat))
    })
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

/// Expand tilde and normalize the non-glob portion of a pattern.
///
/// This ensures patterns like `~/dev/../other/*` are resolved to their
/// canonical form before matching, preventing bypasses via `..` in the
/// pattern itself (not just in the matched path).
fn normalize_pattern(pattern: &str) -> String {
    let expanded = expand_tilde(pattern);
    // Find and strip glob suffix
    let (prefix, suffix) = if let Some(p) = expanded.strip_suffix("/**") {
        (p, "/**")
    } else if let Some(p) = expanded.strip_suffix("/*") {
        (p, "/*")
    } else if let Some(p) = expanded.strip_suffix('*') {
        (p, "*")
    } else {
        // No glob — normalize the whole thing
        return resolve_and_normalize(&expanded);
    };

    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return expanded; // bare glob
    }
    let normalized_prefix = resolve_and_normalize(prefix);
    format!("{normalized_prefix}{suffix}")
}

/// Extract the directory prefix from a glob pattern, stripping any
/// trailing `/**`, `/*`, or `*` suffix.
///
/// Non-glob patterns are returned unchanged.
pub fn extract_glob_prefix(pattern: &str) -> String {
    if let Some(p) = pattern.strip_suffix("/**") {
        p.trim_end_matches('/').to_string()
    } else if let Some(p) = pattern.strip_suffix("/*") {
        p.trim_end_matches('/').to_string()
    } else if let Some(p) = pattern.strip_suffix('*') {
        p.trim_end_matches('/').to_string()
    } else {
        pattern.to_string()
    }
}

/// Check whether a `parent` glob pattern covers a `child` glob pattern.
///
/// Both patterns are expanded (tilde) and normalized to a directory prefix.
/// The child is covered if its prefix starts with (or equals) the parent's
/// prefix — i.e., the child is a subtree of the parent.
///
/// This is used by the monotonicity validator to determine whether a
/// user-level path rule structurally covers a project-level path rule.
pub fn glob_covers(parent: &str, child: &str) -> bool {
    let parent_prefix = extract_glob_prefix(&expand_tilde(parent));
    let child_prefix = extract_glob_prefix(&expand_tilde(child));

    let parent_norm = resolve_and_normalize(&parent_prefix);
    let child_norm = resolve_and_normalize(&child_prefix);

    // Child is within parent if child path starts with parent path
    child_norm == parent_norm || child_norm.starts_with(&format!("{parent_norm}/"))
}

/// Check whether a path matches a rule pattern.
///
/// All glob suffixes (`/**`, `/*`, trailing `*`) are treated as recursive
/// prefix matches — there is no semantic difference between them. A bare
/// `*` or `**` (empty prefix after stripping) matches nothing and is
/// rejected at validation time; this function fails closed as a safety net.
///
/// Literal patterns (no `*`) require exact equality.
fn path_matches(path: &str, pattern: &str) -> bool {
    // All glob suffixes (`/**`, `/*`, trailing `*`) are recursive prefix
    // matches. We normalize them into a single code path.
    if let Some(prefix) = pattern
        .strip_suffix("/**")
        .or_else(|| pattern.strip_suffix("/*"))
        .or_else(|| pattern.strip_suffix('*'))
    {
        let prefix = prefix.trim_end_matches('/');
        if prefix.is_empty() {
            return false; // bare `*`/`**` — rejected in validation, fail-closed here
        }
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }

    // Exact match
    path == pattern
}

#[cfg(test)]
#[path = "path_rules_tests.rs"]
mod path_rules_tests;
