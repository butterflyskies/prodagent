//! File-tool hook evaluation: extract path from tool_input, run through policy.
//!
//! Claude Code's file tools (Write, Edit, Read) carry a `file_path` field in
//! their `tool_input`. This module extracts that path and evaluates it against
//! the policy engine's file-ops rules and effect-class defaults.

use prodagent_policy::config::PolicyConfig;
use prodagent_policy::file_ops::{evaluate_file_tool, FileToolKind};
use prodagent_policy::PolicyDecision;

/// Result of evaluating a file tool operation.
pub struct FileToolResult {
    pub decision: PolicyDecision,
    pub reason: String,
    /// The target path (for logging).
    pub path: String,
}

/// Evaluate a file tool (Write, Edit, Read) against the policy config.
///
/// Returns `None` if the tool_input doesn't contain a `file_path` (no opinion).
/// Returns `Some(result)` with a decision and explanation when a path is found.
pub fn evaluate(
    tool: FileToolKind,
    tool_input: &serde_json::Value,
    policy: &PolicyConfig,
) -> Option<FileToolResult> {
    // Extract file_path from tool_input
    let path = tool_input.get("file_path").and_then(|v| v.as_str())?;
    if path.is_empty() {
        return None;
    }

    let result = evaluate_file_tool(
        tool,
        path,
        &policy.file_ops,
        policy.defaults.read_only,
        policy.defaults.mutating,
    );

    Some(FileToolResult {
        decision: result.decision,
        reason: result.reason,
        path: result.path,
    })
}

#[cfg(test)]
mod tests {
    use prodagent_policy::file_ops::{FileOpsPolicy, FilePathRule};

    use super::*;

    fn make_policy(rules: Vec<FilePathRule>) -> PolicyConfig {
        PolicyConfig {
            file_ops: FileOpsPolicy { path_rules: rules },
            ..PolicyConfig::default()
        }
    }

    fn make_input(path: &str) -> serde_json::Value {
        serde_json::json!({ "file_path": path })
    }

    #[test]
    fn write_uses_mutating_default() {
        let policy = make_policy(vec![]);
        let result = evaluate(FileToolKind::Write, &make_input("/some/file.rs"), &policy);
        let result = result.expect("should have a result");
        assert_eq!(result.decision, PolicyDecision::Ask); // default mutating = Ask
    }

    #[test]
    fn read_uses_read_only_default() {
        let policy = make_policy(vec![]);
        let result = evaluate(FileToolKind::Read, &make_input("/some/file.rs"), &policy);
        let result = result.expect("should have a result");
        assert_eq!(result.decision, PolicyDecision::Allow); // default read_only = Allow
    }

    #[test]
    fn path_rule_allows_write_in_allowed_dir() {
        let policy = make_policy(vec![FilePathRule {
            path: "/tmp/*".into(),
            decision: PolicyDecision::Allow,
            tools: None,
        }]);
        let result = evaluate(
            FileToolKind::Write,
            &make_input("/tmp/scratch.txt"),
            &policy,
        );
        let result = result.expect("should have a result");
        assert_eq!(result.decision, PolicyDecision::Allow);
    }

    #[test]
    fn path_rule_denies_write_to_blocked_dir() {
        let policy = make_policy(vec![FilePathRule {
            path: "/etc/*".into(),
            decision: PolicyDecision::Deny,
            tools: None,
        }]);
        let result = evaluate(FileToolKind::Write, &make_input("/etc/shadow"), &policy);
        let result = result.expect("should have a result");
        assert_eq!(result.decision, PolicyDecision::Deny);
    }

    #[test]
    fn missing_file_path_returns_none() {
        let policy = make_policy(vec![]);
        let input = serde_json::json!({ "content": "hello" });
        assert!(evaluate(FileToolKind::Write, &input, &policy).is_none());
    }

    #[test]
    fn empty_file_path_returns_none() {
        let policy = make_policy(vec![]);
        let input = serde_json::json!({ "file_path": "" });
        assert!(evaluate(FileToolKind::Write, &input, &policy).is_none());
    }
}
