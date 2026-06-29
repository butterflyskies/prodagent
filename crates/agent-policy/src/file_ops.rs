//! Policy evaluation for Claude Code's file tools (Write, Edit, Read).
//!
//! Claude Code has dedicated file tools that bypass Bash entirely. Without
//! this module, file operations through those tools are completely unpoliced.
//! This module applies the same effect-based policy logic used for shell
//! commands: Write and Edit are classified as Mutating, Read as ReadOnly.
//!
//! # Path rules
//!
//! Beyond effect-class defaults, file tools support path-scoped rules — an
//! ordered list of path-prefix globs mapped to decisions. Rules are evaluated
//! in order; the first matching rule wins. If no rule matches, the effect-class
//! default applies.
//!
//! Path rules use simple prefix matching with `*` suffix globs (e.g.
//! `~/dev/*`, `/tmp/*`). The `~` prefix is expanded to the user's home
//! directory. A rule without a trailing `*` requires an exact match.
//!
//! # Monotonicity
//!
//! Path rules participate in the monotonicity invariant: a project config
//! cannot use a path rule to Allow something the user-level policy would Ask
//! or Deny.

use camino::Utf8Path;
use serde::{Deserialize, Serialize};

use crate::decision::PolicyDecision;

/// The file tool being invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileToolKind {
    /// Write tool — creates or overwrites a file.
    Write,
    /// Edit tool — applies edits to an existing file.
    Edit,
    /// Read tool — reads file content.
    Read,
}

impl FileToolKind {
    /// Parse a Claude Code tool name into a `FileToolKind`, if applicable.
    pub fn from_tool_name(name: &str) -> Option<Self> {
        match name {
            "Write" => Some(Self::Write),
            "Edit" => Some(Self::Edit),
            "Read" => Some(Self::Read),
            _ => None,
        }
    }

    /// Whether this tool is a mutating operation.
    pub fn is_mutating(self) -> bool {
        matches!(self, Self::Write | Self::Edit)
    }
}

impl std::fmt::Display for FileToolKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Write => write!(f, "Write"),
            Self::Edit => write!(f, "Edit"),
            Self::Read => write!(f, "Read"),
        }
    }
}

/// Configuration for file-tool policy evaluation.
///
/// File tools don't go through the shell parser or command knowledge base —
/// they have a known effect (mutating or read-only) and a known target path.
/// Policy evaluation is simpler: classify by effect, check path rules, done.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileOpsPolicy {
    /// Ordered list of path-scoped rules. First match wins.
    ///
    /// Each rule maps a path glob to a decision. When a file tool targets a
    /// path matching the glob, the rule's decision is used instead of the
    /// effect-class default.
    ///
    /// Rules can be scoped to specific tool kinds (read-only vs mutating)
    /// or apply to all file tools.
    #[serde(default)]
    pub path_rules: Vec<FilePathRule>,
}

/// A single path-scoped rule for file tool operations.
///
/// Evaluated in order within the `path_rules` list. First match wins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilePathRule {
    /// Path glob pattern. Supports:
    /// - Literal paths: `/home/user/file.txt` (exact match)
    /// - Prefix globs: `~/dev/*` (matches anything under ~/dev/)
    /// - `~` is expanded to the user's home directory
    /// - `**` is treated the same as `*` (recursive match under prefix)
    pub path: String,

    /// The decision to apply when the path matches.
    pub decision: PolicyDecision,

    /// Optional: restrict this rule to specific tool kinds.
    /// When `None`, the rule applies to all file tools.
    /// When `Some`, the rule only fires for the specified kinds.
    #[serde(default)]
    pub tools: Option<Vec<FileToolKind>>,
}

/// Result of evaluating a file tool against the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOpResult {
    /// The authorization decision.
    pub decision: PolicyDecision,
    /// Human-readable explanation of the decision.
    pub reason: String,
    /// The target path (after normalization).
    pub path: String,
    /// Which tool was evaluated.
    pub tool: FileToolKind,
}

/// Evaluate a file tool operation against the policy.
///
/// # Arguments
///
/// * `tool` — the file tool being invoked (Write, Edit, Read)
/// * `path` — the target file path from tool_input
/// * `file_ops` — the file-ops policy rules (may be empty/default)
/// * `read_only_default` — the effect-class default for read-only operations
/// * `mutating_default` — the effect-class default for mutating operations
///
/// # Evaluation order
///
/// 1. Check path rules in order. First matching rule wins.
/// 2. If no rule matches, fall back to the effect-class default based on
///    whether the tool is mutating or read-only.
pub fn evaluate_file_tool(
    tool: FileToolKind,
    path: &str,
    file_ops: &FileOpsPolicy,
    read_only_default: PolicyDecision,
    mutating_default: PolicyDecision,
) -> FileOpResult {
    let normalized = normalize_path(path);

    // Check path rules in order — first match wins
    for rule in &file_ops.path_rules {
        // If the rule is scoped to specific tools, check the tool kind
        if let Some(ref tools) = rule.tools {
            if !tools.contains(&tool) {
                continue;
            }
        }

        if path_matches(&normalized, &expand_tilde(&rule.path)) {
            return FileOpResult {
                decision: rule.decision,
                reason: format!(
                    "{tool} {path}: path rule '{}' -> {rule_decision:?}",
                    rule.path,
                    rule_decision = rule.decision,
                ),
                path: normalized,
                tool,
            };
        }
    }

    // No rule matched — fall back to effect-class default
    let effect_default = if tool.is_mutating() {
        mutating_default
    } else {
        read_only_default
    };

    let effect_name = if tool.is_mutating() {
        "mutating"
    } else {
        "read-only"
    };

    FileOpResult {
        decision: effect_default,
        reason: format!("{tool} {path}: effect={effect_name} (default)"),
        path: normalized,
        tool,
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

/// Normalize a file path for consistent matching.
///
/// - Expands `~` to home directory
/// - Strips trailing slashes
/// - Collapses redundant separators via camino
fn normalize_path(path: &str) -> String {
    let expanded = expand_tilde(path);
    // Use camino's component re-collection to normalize
    let utf8_path = Utf8Path::new(&expanded);
    let normalized: String = utf8_path
        .components()
        .collect::<camino::Utf8PathBuf>()
        .into();
    normalized
}

/// Check whether a path matches a rule pattern.
///
/// Matching rules:
/// - Pattern ending in `/*` or `/**`: prefix match (path starts with the
///   prefix before the `*`). The prefix itself also matches (e.g. `~/dev/*`
///   matches `~/dev/` and `~/dev/foo`).
/// - Pattern ending in just `*`: same as `/*` (prefix of everything before `*`).
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
mod tests {
    use super::*;

    // ── FileToolKind ──────────────────────────────────────────────────────

    #[test]
    fn file_tool_kind_from_tool_name() {
        assert_eq!(
            FileToolKind::from_tool_name("Write"),
            Some(FileToolKind::Write)
        );
        assert_eq!(
            FileToolKind::from_tool_name("Edit"),
            Some(FileToolKind::Edit)
        );
        assert_eq!(
            FileToolKind::from_tool_name("Read"),
            Some(FileToolKind::Read)
        );
        assert_eq!(FileToolKind::from_tool_name("Bash"), None);
        assert_eq!(FileToolKind::from_tool_name(""), None);
    }

    #[test]
    fn file_tool_kind_is_mutating() {
        assert!(FileToolKind::Write.is_mutating());
        assert!(FileToolKind::Edit.is_mutating());
        assert!(!FileToolKind::Read.is_mutating());
    }

    // ── path_matches ──────────────────────────────────────────────────────

    #[test]
    fn exact_match() {
        assert!(path_matches("/home/user/file.txt", "/home/user/file.txt"));
        assert!(!path_matches("/home/user/file.txt", "/home/user/other.txt"));
    }

    #[test]
    fn glob_suffix_star() {
        // ~/dev/* should match anything under ~/dev/
        assert!(path_matches(
            "/home/user/dev/project/file.rs",
            "/home/user/dev/*"
        ));
        assert!(path_matches("/home/user/dev/project", "/home/user/dev/*"));
        // The prefix directory itself matches
        assert!(path_matches("/home/user/dev", "/home/user/dev/*"));
        // Sibling should not match
        assert!(!path_matches(
            "/home/user/other/file.rs",
            "/home/user/dev/*"
        ));
    }

    #[test]
    fn glob_suffix_double_star() {
        assert!(path_matches("/tmp/foo/bar/baz", "/tmp/**"));
        assert!(path_matches("/tmp/foo", "/tmp/**"));
        assert!(path_matches("/tmp", "/tmp/**"));
        assert!(!path_matches("/var/tmp", "/tmp/**"));
    }

    #[test]
    fn glob_suffix_slash_star() {
        assert!(path_matches("/home/user/dev/foo", "/home/user/dev/*"));
        assert!(path_matches("/home/user/dev", "/home/user/dev/*"));
    }

    #[test]
    fn no_partial_prefix_match() {
        // /home/user/develop should NOT match /home/user/dev/*
        assert!(!path_matches("/home/user/develop", "/home/user/dev/*"));
    }

    // ── evaluate_file_tool (no rules) ─────────────────────────────────────

    #[test]
    fn default_read_allowed() {
        let policy = FileOpsPolicy::default();
        let result = evaluate_file_tool(
            FileToolKind::Read,
            "/some/file.txt",
            &policy,
            PolicyDecision::Allow,
            PolicyDecision::Ask,
        );
        assert_eq!(result.decision, PolicyDecision::Allow);
        assert!(result.reason.contains("read-only"));
    }

    #[test]
    fn default_write_asks() {
        let policy = FileOpsPolicy::default();
        let result = evaluate_file_tool(
            FileToolKind::Write,
            "/some/file.txt",
            &policy,
            PolicyDecision::Allow,
            PolicyDecision::Ask,
        );
        assert_eq!(result.decision, PolicyDecision::Ask);
        assert!(result.reason.contains("mutating"));
    }

    #[test]
    fn default_edit_asks() {
        let policy = FileOpsPolicy::default();
        let result = evaluate_file_tool(
            FileToolKind::Edit,
            "/some/file.txt",
            &policy,
            PolicyDecision::Allow,
            PolicyDecision::Ask,
        );
        assert_eq!(result.decision, PolicyDecision::Ask);
    }

    // ── evaluate_file_tool (with path rules) ──────────────────────────────

    #[test]
    fn path_rule_overrides_default() {
        let policy = FileOpsPolicy {
            path_rules: vec![FilePathRule {
                path: "/tmp/*".into(),
                decision: PolicyDecision::Allow,
                tools: None,
            }],
        };
        // Write in /tmp/ — rule allows it
        let result = evaluate_file_tool(
            FileToolKind::Write,
            "/tmp/scratch.txt",
            &policy,
            PolicyDecision::Allow,
            PolicyDecision::Ask,
        );
        assert_eq!(result.decision, PolicyDecision::Allow);
        assert!(result.reason.contains("path rule"));

        // Write outside /tmp/ — no rule matches, falls back to mutating default
        let result = evaluate_file_tool(
            FileToolKind::Write,
            "/etc/passwd",
            &policy,
            PolicyDecision::Allow,
            PolicyDecision::Ask,
        );
        assert_eq!(result.decision, PolicyDecision::Ask);
    }

    #[test]
    fn first_matching_rule_wins() {
        let policy = FileOpsPolicy {
            path_rules: vec![
                FilePathRule {
                    path: "/tmp/sensitive/*".into(),
                    decision: PolicyDecision::Deny,
                    tools: None,
                },
                FilePathRule {
                    path: "/tmp/*".into(),
                    decision: PolicyDecision::Allow,
                    tools: None,
                },
            ],
        };
        // /tmp/sensitive/ — first rule wins (deny)
        let result = evaluate_file_tool(
            FileToolKind::Write,
            "/tmp/sensitive/data.txt",
            &policy,
            PolicyDecision::Allow,
            PolicyDecision::Ask,
        );
        assert_eq!(result.decision, PolicyDecision::Deny);

        // /tmp/other — second rule wins (allow)
        let result = evaluate_file_tool(
            FileToolKind::Write,
            "/tmp/other.txt",
            &policy,
            PolicyDecision::Allow,
            PolicyDecision::Ask,
        );
        assert_eq!(result.decision, PolicyDecision::Allow);
    }

    #[test]
    fn tool_scoped_rules() {
        let policy = FileOpsPolicy {
            path_rules: vec![
                // Allow reads anywhere under /etc/
                FilePathRule {
                    path: "/etc/*".into(),
                    decision: PolicyDecision::Allow,
                    tools: Some(vec![FileToolKind::Read]),
                },
                // Deny writes to /etc/
                FilePathRule {
                    path: "/etc/*".into(),
                    decision: PolicyDecision::Deny,
                    tools: Some(vec![FileToolKind::Write, FileToolKind::Edit]),
                },
            ],
        };

        // Read in /etc/ — first rule fires (read-scoped allow)
        let result = evaluate_file_tool(
            FileToolKind::Read,
            "/etc/hosts",
            &policy,
            PolicyDecision::Allow,
            PolicyDecision::Ask,
        );
        assert_eq!(result.decision, PolicyDecision::Allow);

        // Write in /etc/ — first rule skipped (tool mismatch), second fires (deny)
        let result = evaluate_file_tool(
            FileToolKind::Write,
            "/etc/hosts",
            &policy,
            PolicyDecision::Allow,
            PolicyDecision::Ask,
        );
        assert_eq!(result.decision, PolicyDecision::Deny);
    }

    #[test]
    fn deny_rule_blocks_path() {
        let policy = FileOpsPolicy {
            path_rules: vec![FilePathRule {
                path: "/etc/*".into(),
                decision: PolicyDecision::Deny,
                tools: None,
            }],
        };
        let result = evaluate_file_tool(
            FileToolKind::Write,
            "/etc/shadow",
            &policy,
            PolicyDecision::Allow,
            PolicyDecision::Ask,
        );
        assert_eq!(result.decision, PolicyDecision::Deny);
        assert!(result.reason.contains("path rule"));
    }

    // ── normalize_path ───────────────────────────────────────────────────

    #[test]
    fn normalize_strips_redundant_slashes() {
        assert_eq!(normalize_path("/home//user///file"), "/home/user/file");
    }

    #[test]
    fn normalize_strips_trailing_slash() {
        let result = normalize_path("/home/user/dir/");
        assert_eq!(result, "/home/user/dir");
    }

    // ── expand_tilde ─────────────────────────────────────────────────────

    #[test]
    fn expand_tilde_with_suffix() {
        let expanded = expand_tilde("~/dev/project");
        // Should not start with ~ anymore (unless no HOME)
        if let Some(home) = dirs::home_dir() {
            assert_eq!(expanded, format!("{}/dev/project", home.display()));
        }
    }

    #[test]
    fn expand_tilde_bare() {
        let expanded = expand_tilde("~");
        if let Some(home) = dirs::home_dir() {
            assert_eq!(expanded, home.to_string_lossy().as_ref());
        }
    }

    #[test]
    fn no_expand_mid_path() {
        // ~ in the middle of a path should not be expanded
        let expanded = expand_tilde("/home/~/file");
        assert_eq!(expanded, "/home/~/file");
    }
}
