//! Path-scoped policy rules for Bash command authorization.
//!
//! Policy rules gain an optional `paths` field — a list of globs (e.g.
//! `~/dev/*`, `/tmp/**`) that constrain *where* a rule applies. When present,
//! the current working directory and/or the command's [`AffectedPaths`] are
//! checked against those globs. If none match, the rule doesn't fire and
//! evaluation falls through to the command-level or effect-class default.
//!
//! # Per-path evaluation
//!
//! Each affected path is evaluated independently using three tiers:
//!
//! 1. **Command+path rules** — rules with a `command` field matching the
//!    base command AND a path pattern matching this path. First match wins.
//!    If found, this is the final per-path decision (most specific,
//!    overrides everything).
//!
//! 2. **Path-only AND command-only, independently** — if no command+path
//!    rule matched, both path-only and command-only policies are evaluated:
//!    - **Path rules**: unscoped rules (no `command` field). Exact path
//!      matches beat glob patterns; first match at each specificity level.
//!    - **Command rules**: the command-level HashMap lookup / effect-class
//!      default (passed as `command_default`).
//!    - The strictest of the two wins: `max(path_decision, command_decision)`.
//!
//! 3. **Fallback** — if no path rule matched at all, the command-level or
//!    effect-class default applies.
//!
//! # Multi-path aggregation
//!
//! Across all affected paths, the strictest (max) per-path decision wins.
//! If ANY path evaluates to Deny, the overall result is Deny. This ensures
//! a dangerous path cannot be hidden among safe ones in a multi-path command
//! (e.g. `cp ~/dev/foo /etc/shadow`).
//!
//! # Security
//!
//! - Paths are canonicalized: `..` components are resolved before matching,
//!   preventing traversal bypasses (e.g. `/tmp/safe/../../etc/shadow`
//!   matching a `/tmp/*` allow rule).
//! - `~` is expanded to the user's home directory.
//! - The monotonicity invariant applies across config layers: a project
//!   config cannot use a path-scoped rule to Allow something the user-level
//!   policy would Ask or Deny. Within a single layer, specificity wins.

use std::fmt;
use std::ops::Deref;

use camino::Utf8Path;
use serde::{Deserialize, Serialize};

use crate::decision::PolicyDecision;

// ── PathGlob newtype ─────────────────────────────────────────────────────

/// A validated path glob pattern for path-scoped policy rules.
///
/// Wraps a `String` that has been validated on construction:
/// - Non-empty
/// - Not a bare `*` or `**` (would match all paths — a universal bypass)
///
/// Invalid patterns are rejected at construction time via [`PathGlob::new`]
/// or `TryFrom<String>`, and during deserialization. This makes invalid
/// glob patterns unrepresentable in [`PathRule`].
///
/// `~` expansion and `..` normalization are handled at match time by
/// [`normalize_pattern`] and [`resolve_and_normalize`] — `PathGlob` stores
/// the original pattern string so that TOML round-trips are lossless.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PathGlob(String);

/// Error returned when constructing an invalid [`PathGlob`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathGlobError {
    /// The pattern string is empty.
    Empty,
    /// The pattern is a bare glob (`*`, `**`, `/*`, `/**`) — would match all paths.
    BareGlob(String),
}

impl fmt::Display for PathGlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathGlobError::Empty => write!(f, "empty path glob pattern"),
            PathGlobError::BareGlob(s) => write!(
                f,
                "bare glob pattern \"{s}\" would match all paths; \
                 use an explicit path prefix (e.g. \"/tmp/*\")"
            ),
        }
    }
}

impl std::error::Error for PathGlobError {}

impl PathGlob {
    /// Construct a new `PathGlob`, validating the pattern.
    ///
    /// # Errors
    ///
    /// Returns [`PathGlobError::Empty`] if the string is empty or whitespace-only.
    /// Returns [`PathGlobError::BareGlob`] if the pattern is a bare glob (`*`,
    /// `**`, `/*`, `/**`) that would match all paths.
    pub fn new(s: String) -> Result<Self, PathGlobError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(PathGlobError::Empty);
        }
        if matches!(trimmed, "*" | "**" | "/*" | "/**") {
            return Err(PathGlobError::BareGlob(s));
        }
        Ok(Self(s))
    }

    /// The raw pattern string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the `PathGlob` and return the inner string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for PathGlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for PathGlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for PathGlob {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PathGlob {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PathGlob {
    type Error = PathGlobError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for PathGlob {
    type Error = PathGlobError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s.to_string())
    }
}

impl Serialize for PathGlob {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PathGlob {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        PathGlob::new(s).map_err(serde::de::Error::custom)
    }
}

// ── PathRule ─────────────────────────────────────────────────────────────

/// A single path-scoped policy rule for Bash command authorization.
///
/// Evaluated in order within the `path_rules` list. First match wins.
/// The `command` field scopes the rule to a specific base command (e.g.
/// `"git"`); when absent, the rule applies to all commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathRule {
    /// Path glob patterns where this rule applies.
    ///
    /// Each pattern is validated on construction — empty strings and bare
    /// `*`/`**` patterns are rejected by [`PathGlob`].
    ///
    /// Supports:
    /// - `~/dev/*` — anything under ~/dev/
    /// - `/tmp/**` — recursive match under /tmp/
    /// - Literal path (no glob) — exact match
    /// - `~` is expanded to the user's home directory at match time
    pub paths: Vec<PathGlob>,

    /// The decision to apply when a path matches.
    pub decision: PolicyDecision,

    /// Optional: restrict this rule to a specific base command.
    /// When absent, the rule applies to all commands.
    #[serde(default)]
    pub command: Option<String>,
}

/// Evaluate path-scoped rules against a command's context.
///
/// Each affected path is evaluated independently using three tiers:
///
/// 1. **Command+path rules** — if a rule has `command` matching the base
///    command AND a path pattern matching the path, that rule's decision
///    is the per-path result (most specific, overrides everything).
///
/// 2. **Path-only AND command-only** — if no command+path rule matched,
///    both path-only rules and the `command_default` are evaluated
///    independently and composed via `max()` (strictest wins).
///    Within path-only rules, exact matches beat globs.
///
/// 3. **Fallback** — if no path rule matched, `command_default` applies.
///
/// Across all affected paths the strictest per-path decision wins: if ANY
/// path evaluates to Deny, the overall result is Deny.
///
/// Returns `Some(PathRuleResult)` if at least one path matched a rule,
/// `None` if no rule applied (caller should use `command_default`).
///
/// When no affected paths are extracted, CWD-only evaluation applies:
/// the CWD is treated as the single path and the same evaluation
/// tiers are used.
///
/// # Arguments
///
/// * `rules` — ordered list of path-scoped rules
/// * `base_command` — the base command name (e.g. "git", "rm")
/// * `cwd` — current working directory, if available
/// * `affected_paths` — paths extracted by the knowledge layer
/// * `command_default` — fallback decision when no path rule matches
pub fn evaluate_path_rules(
    rules: &[PathRule],
    base_command: &str,
    cwd: Option<&str>,
    affected_paths: &[&str],
    command_default: PolicyDecision,
) -> Option<PathRuleResult> {
    if rules.is_empty() {
        return None;
    }

    // Pre-expand patterns for each rule to avoid redundant work.
    let expanded: Vec<ExpandedRule<'_>> = rules
        .iter()
        .map(|rule| ExpandedRule {
            rule,
            patterns: rule.paths.iter().map(|p| normalize_pattern(p)).collect(),
        })
        .collect();

    if affected_paths.is_empty() {
        // No affected paths — CWD-only evaluation.
        let cwd = cwd?;
        let (decision, matched) =
            evaluate_single_path(&expanded, base_command, cwd, command_default);
        return matched.map(|rule| PathRuleResult {
            decision,
            matched_rule: rule.clone(),
        });
    }

    // Per-path evaluation: each affected path independently through the
    // specificity hierarchy. Strictest decision across all paths wins.
    let mut any_matched = false;
    let mut strictest = PolicyDecision::Allow;
    let mut winning_rule: Option<&PathRule> = None;

    for path in affected_paths {
        let (path_decision, matched) =
            evaluate_single_path(&expanded, base_command, path, command_default);

        if let Some(rule) = matched {
            if !any_matched {
                winning_rule = Some(rule);
            }
            any_matched = true;
        }

        if path_decision > strictest {
            strictest = path_decision;
            // Track the rule that contributed to the strictest decision
            // for diagnostics. If the strictest came from command_default
            // (no rule matched this particular path), keep the existing
            // winning_rule from a path that DID match.
            if let Some(rule) = matched {
                winning_rule = Some(rule);
            }
        }

        // Short-circuit: Deny is the maximum possible decision.
        if strictest == PolicyDecision::Deny {
            break;
        }
    }

    if !any_matched {
        return None;
    }

    Some(PathRuleResult {
        decision: strictest,
        // Safety: any_matched is true, so winning_rule was set.
        matched_rule: winning_rule.unwrap().clone(),
    })
}

/// Evaluate user override path rules with per-path fallback decisions.
///
/// Unlike regular path rules, a matched override is authoritative for that
/// path: it may intentionally relax the normal policy. Paths that do not
/// match an override retain their independently computed normal decision, and
/// the strictest per-path decision wins across the command.
///
/// Unscoped overrides never use CWD to lower the normal authorization
/// boundary. When no affected paths were extracted, an unscoped CWD match may
/// preserve or tighten `pathless_fallback`; only an explicitly command-scoped
/// rule may relax it. This prevents an unknown command launched from an
/// approved directory from being treated as confined to that directory while
/// retaining safety-oriented Ask and Deny rules.
///
/// `path_decisions` structurally pairs each extracted path with its normal
/// fallback decision, making length mismatch and truncating `zip` impossible.
/// `pathless_fallback` is the independently evaluated normal decision for a
/// command with no extracted paths.
/// `unscoped_lowering_is_trusted` gates only decisions less restrictive than a
/// path's fallback; tightening and equal decisions remain valid without it.
pub(crate) fn evaluate_override_path_rules(
    rules: &[PathRule],
    base_command: &str,
    cwd: Option<&str>,
    path_decisions: &[(&str, PolicyDecision)],
    pathless_fallback: PolicyDecision,
    unscoped_lowering_is_trusted: bool,
) -> Option<PolicyDecision> {
    if rules.is_empty() {
        return None;
    }

    let expanded: Vec<ExpandedRule<'_>> = rules
        .iter()
        .map(|rule| ExpandedRule {
            rule,
            patterns: rule.paths.iter().map(|p| normalize_pattern(p)).collect(),
        })
        .collect();

    if path_decisions.is_empty() {
        let cwd = cwd?;
        let normalized = resolve_and_normalize(cwd);
        return find_command_scoped_match(&expanded, base_command, &normalized)
            .or_else(|| {
                find_eligible_unscoped_match(&expanded, &normalized, |rule| {
                    rule.decision >= pathless_fallback
                })
                .map(|(_, rule)| rule)
            })
            .map(|rule| rule.decision);
    }

    let mut any_matched = false;
    let mut strictest = PolicyDecision::Allow;

    for &(path, fallback) in path_decisions {
        let normalized = resolve_and_normalize(path);
        let matched =
            find_command_scoped_match(&expanded, base_command, &normalized).or_else(|| {
                find_eligible_unscoped_match(&expanded, &normalized, |rule| {
                    rule.decision >= fallback
                        || (unscoped_lowering_is_trusted
                            && rule
                                .paths
                                .iter()
                                .all(|pattern| pattern.as_str().starts_with('/')))
                })
                .map(|(_, rule)| rule)
            });

        let decision = if let Some(rule) = matched {
            any_matched = true;
            rule.decision
        } else {
            fallback
        };
        strictest = strictest.max(decision);
    }

    any_matched.then_some(strictest)
}

/// Result of a path-scoped rule evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRuleResult {
    /// The authorization decision from the matching rule.
    pub decision: PolicyDecision,
    /// The rule that matched (for diagnostics/logging).
    /// For multi-path commands this is the rule that contributed to the
    /// strictest per-path decision.
    pub matched_rule: PathRule,
}

/// A rule with pre-expanded glob patterns for efficient matching.
struct ExpandedRule<'a> {
    rule: &'a PathRule,
    patterns: Vec<String>,
}

/// Evaluate a single path against the specificity hierarchy.
///
/// Returns the decision and, if a rule matched, a reference to it.
///
/// Evaluation tiers:
///
/// 1. **Command+path rules** — rules with `command` matching `base_command`
///    AND a path pattern matching this path. First match wins. If found,
///    this is the final decision (most specific, overrides everything).
///
/// 2. **Path-only AND command-only, independently** — if no command+path
///    rule matched:
///    - Check unscoped path rules (exact match beats glob, first match
///      at each specificity level).
///    - Use `command_default` (command-only HashMap lookup result).
///    - Take `max(path_decision, command_default)` — strictest wins.
///
/// 3. **Fallback** — if no path rule matched at all, use `command_default`.
fn evaluate_single_path<'a>(
    expanded: &'a [ExpandedRule<'a>],
    base_command: &str,
    path: &str,
    command_default: PolicyDecision,
) -> (PolicyDecision, Option<&'a PathRule>) {
    let normalized = resolve_and_normalize(path);

    // Tier 1: command+path rules (most specific).
    if let Some(rule) = find_command_scoped_match(expanded, base_command, &normalized) {
        return (rule.decision, Some(rule));
    }

    // Tier 2: path-only AND command-only, independently.
    // Path-only: exact match beats glob, first match at each level.
    if let Some((path_decision, rule)) = find_unscoped_match(expanded, &normalized) {
        // Both path and command contribute — strictest wins.
        return (path_decision.max(command_default), Some(rule));
    }

    // Tier 3: no path rule matched — command-level / effect-class default.
    (command_default, None)
}

/// Return the first command-scoped rule matching a normalized path.
fn find_command_scoped_match<'a>(
    expanded: &'a [ExpandedRule<'a>],
    base_command: &str,
    normalized_path: &str,
) -> Option<&'a PathRule> {
    expanded.iter().find_map(|er| {
        (er.rule.command.as_deref() == Some(base_command)
            && er
                .patterns
                .iter()
                .any(|pat| path_matches(normalized_path, pat)))
        .then_some(er.rule)
    })
}

/// Find the first matching unscoped (no `command` field) path rule.
///
/// Exact-match patterns have higher specificity than glob patterns.
/// Within each specificity level, first rule in list order wins.
fn find_unscoped_match<'a>(
    expanded: &'a [ExpandedRule<'a>],
    normalized_path: &str,
) -> Option<(PolicyDecision, &'a PathRule)> {
    find_eligible_unscoped_match(expanded, normalized_path, |_| true)
}

/// Find the first eligible unscoped rule in the normal specificity order.
///
/// Ineligible rules are skipped rather than treated as terminal matches. This
/// matters for overrides: an early relaxation that lacks sufficient proof
/// must not shadow a later tightening rule for the same path.
fn find_eligible_unscoped_match<'a>(
    expanded: &'a [ExpandedRule<'a>],
    normalized_path: &str,
    mut eligible: impl FnMut(&PathRule) -> bool,
) -> Option<(PolicyDecision, &'a PathRule)> {
    // Level 1: exact matches (no glob characters) — most specific.
    for er in expanded {
        if er.rule.command.is_some() || !eligible(er.rule) {
            continue;
        }
        if er
            .patterns
            .iter()
            .any(|pat| !is_glob_pattern(pat) && path_matches(normalized_path, pat))
        {
            return Some((er.rule.decision, er.rule));
        }
    }

    // Level 2: glob matches.
    for er in expanded {
        if er.rule.command.is_some() || !eligible(er.rule) {
            continue;
        }
        if er
            .patterns
            .iter()
            .any(|pat| is_glob_pattern(pat) && path_matches(normalized_path, pat))
        {
            return Some((er.rule.decision, er.rule));
        }
    }

    None
}

/// Check whether a normalized pattern is a glob (contains `*`).
fn is_glob_pattern(pattern: &str) -> bool {
    pattern.contains('*')
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
