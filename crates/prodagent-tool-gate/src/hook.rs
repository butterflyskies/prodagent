//! Core hook evaluation: stdin → policy engine → stdout.

use agent_command_knowledge::{default_knowledge_base, KnowledgeBase};
use agent_shell_parser::hook::{parse_input, PreToolUseInput};
use prodagent_config::{load_split_and_apply, ConfigLoader};
use prodagent_policy::{derive_wrapper_specs, PolicyDecision, PolicyEngine};
use serde::Serialize;

use crate::decision_log;

/// JSON output wrapper matching Claude Code's hook protocol.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HookOutput {
    hook_specific_output: HookSpecificOutput,
}

/// The inner decision payload.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HookSpecificOutput {
    hook_event_name: &'static str,
    permission_decision: PolicyDecision,
    permission_decision_reason: String,
    /// Conflict information when the project config tightens the decision
    /// beyond the user's own policy. Present only when a conflict exists.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    conflict: Option<ConflictInfo>,
}

/// Project-vs-user conflict metadata.
///
/// Present in the hook output when the merged decision is stricter than
/// the user's own policy because the project config tightened it. The
/// harness should present a three-option consent gate: Allow once / Deny
/// / Always Allow.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConflictInfo {
    /// The decision the project config wanted.
    project_decision: PolicyDecision,
    /// The config entry that "Always Allow" would write to user config.
    override_config: OverrideEntry,
}

/// A config entry describing what to write to user config when the user
/// chooses "Always Allow" on a consent-gated conflict.
///
/// The harness (Claude Code) is responsible for writing this to the user's
/// `~/.config/prodagent/config.toml` under the `[policy.overrides]` section.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OverrideEntry {
    /// The base command this override applies to.
    command: String,
    /// The decision to record (typically "allow").
    decision: PolicyDecision,
    /// Optional: path globs that scope this override. When present, the
    /// override is a path-scoped rule under `[[policy.overrides.path_rules]]`.
    /// When absent, it's a flat command override under `[policy.overrides.commands]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    paths: Option<Vec<String>>,
}

impl HookOutput {
    fn new(decision: PolicyDecision, reason: String) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: decision,
                permission_decision_reason: reason,
                conflict: None,
            },
        }
    }

    fn with_conflict(
        mut self,
        project_decision: PolicyDecision,
        override_config: OverrideEntry,
    ) -> Self {
        self.hook_specific_output.conflict = Some(ConflictInfo {
            project_decision,
            override_config,
        });
        self
    }
}

/// Run the hook: read stdin, evaluate, write stdout, log decision.
pub fn run(escalate_deny: bool) -> anyhow::Result<()> {
    // Parse hook input from stdin
    let input: PreToolUseInput = parse_input()?;

    // Only evaluate Bash commands — exit silently (no opinion) for anything else
    if input.tool_name != "Bash" {
        return Ok(());
    }

    // Extract the command string from tool_input
    let command = match input.tool_input.get("command").and_then(|v| v.as_str()) {
        Some(cmd) if !cmd.is_empty() => cmd,
        _ => return Ok(()), // Empty or missing command — no opinion
    };

    // Load config via three-tier cascade, getting both user-only and merged policies
    let loader = ConfigLoader::from_environment();
    let mut kb = default_knowledge_base().clone();
    let user_kb = kb.clone(); // snapshot before project knowledge is merged
    let (user_policy, merged_policy) = load_split_and_apply(&loader, &mut kb)?;

    let user_engine = PolicyEngine::new(user_policy).map_err(|e| anyhow::anyhow!(e))?;
    let merged_engine = PolicyEngine::new(merged_policy).map_err(|e| anyhow::anyhow!(e))?;

    // Evaluate command through both engines for conflict detection
    let cwd = input.cwd.as_deref();
    let merged_result = merged_engine.evaluate_command_with_cwd(command, &kb, cwd);
    let user_result = user_engine.evaluate_command_with_cwd(command, &user_kb, cwd);

    // Apply --escalate-deny: convert Deny → Ask
    let mut decision = merged_result.decision;
    let mut reason = merged_result.reason.clone();
    if escalate_deny && decision == PolicyDecision::Deny {
        decision = PolicyDecision::Ask;
        reason = format!("{reason} (escalated from deny)");
    }

    // Log the decision
    decision_log::log_decision(&input.tool_name, command, decision, &reason);

    // Detect project-vs-user conflict: the merged decision is stricter than
    // what the user's own config would produce. This means the project config
    // tightened the decision.
    let mut output = HookOutput::new(decision, reason);
    if decision > user_result.decision {
        // Determine the override config based on what the command touches.
        // If the command has affected paths, scope the override to those paths.
        // Otherwise, create a flat command override.
        let base_command = extract_base_command(command, &kb);
        let paths = if !merged_result.affected_paths.is_empty() {
            Some(
                merged_result
                    .affected_paths
                    .iter()
                    .map(|p| {
                        // Derive directory-scoped glob: /tmp/foo -> /tmp/*
                        let path = camino::Utf8Path::new(p.as_str());
                        match path.parent() {
                            Some(parent) if !parent.as_str().is_empty() => {
                                format!("{}/*", parent)
                            }
                            _ => p.to_string(),
                        }
                    })
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            )
        } else {
            None
        };

        let override_entry = OverrideEntry {
            command: base_command,
            decision: PolicyDecision::Allow,
            paths,
        };

        output = output.with_conflict(decision, override_entry);
    }

    // Emit JSON to stdout
    serde_json::to_writer(std::io::stdout(), &output)?;

    Ok(())
}

/// Extract the base command name from a raw command string.
///
/// Uses the shell parser to properly tokenize the command, then skips
/// leading environment assignments and returns the basename of the first
/// real command word (e.g. `/usr/bin/git` -> `git`, `FOO=bar rm -rf` -> `rm`).
///
/// Falls back to naive whitespace splitting if the parser fails.
fn extract_base_command(command: &str, kb: &KnowledgeBase) -> String {
    if let Ok(pipeline) = agent_shell_parser::parse::parse_with_substitutions(command) {
        if let Some(segment) = pipeline.segments.first() {
            let base = segment
                .words
                .iter()
                .find(|w| !w.is_assignment())
                .map(|w| w.basename().to_string())
                .unwrap_or_default();

            // If this is a wrapper, resolve to the inner command
            if !base.is_empty() && kb.wrappers.contains_key(&base) {
                let kb_wrapper_specs = derive_wrapper_specs(kb);
                let merged_config = agent_shell_parser::parse::merged_config(&kb_wrapper_specs);
                let resolved =
                    agent_shell_parser::parse::resolve_command_with(&segment.words, &merged_config);
                if let agent_shell_parser::parse::ResolvedCommand::Resolved(parsed) = resolved {
                    if !parsed.command.is_empty() && parsed.command.as_str() != base {
                        return parsed
                            .command
                            .rsplit('/')
                            .next()
                            .unwrap_or(&parsed.command)
                            .to_string();
                    }
                }
            }

            if !base.is_empty() {
                return base;
            }
        }
    }

    // Fallback: naive split_whitespace parsing
    let words: Vec<&str> = command.split_whitespace().collect();
    for word in &words {
        if is_env_assignment(word) {
            continue; // Skip env assignments like FOO=bar
        }
        return word.rsplit('/').next().unwrap_or(word).to_string();
    }
    command.split_whitespace().next().unwrap_or("").to_string()
}

/// Check if a token looks like a shell environment variable assignment (`KEY=VALUE`).
///
/// A valid env var name starts with a letter or underscore and contains only
/// alphanumerics and underscores — no path separators, no leading digits.
/// This correctly distinguishes `FOO=bar` (env assignment) from `/opt/foo=bar/bin/thing`
/// (a path that happens to contain `=`).
fn is_env_assignment(token: &str) -> bool {
    let Some(eq_pos) = token.find('=') else {
        return false;
    };
    let key = &token[..eq_pos];
    if key.is_empty() {
        return false;
    }
    let first = key.as_bytes()[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_env_assignment_valid_cases() {
        assert!(is_env_assignment("FOO=bar"));
        assert!(is_env_assignment("MY_VAR=hello"));
        assert!(is_env_assignment("_PRIVATE=1"));
        assert!(is_env_assignment("A="));
        assert!(is_env_assignment("FOO=bar=baz"));
    }

    #[test]
    fn is_env_assignment_invalid_cases() {
        // Paths containing =
        assert!(!is_env_assignment("/opt/foo=bar/bin/thing"));
        assert!(!is_env_assignment("./foo=bar"));
        // Starts with digit
        assert!(!is_env_assignment("1FOO=bar"));
        // No equals sign
        assert!(!is_env_assignment("FOO"));
        // Empty key
        assert!(!is_env_assignment("=value"));
        // Flag with =
        assert!(!is_env_assignment("--config=value"));
        // Hyphen in key
        assert!(!is_env_assignment("FOO-BAR=baz"));
    }

    #[test]
    fn fallback_extracts_command_after_env_var() {
        // The fallback path is exercised when the shell parser fails.
        // We test the logic directly via the helper + the same word-loop.
        let extract_fallback = |command: &str| -> String {
            let words: Vec<&str> = command.split_whitespace().collect();
            for word in &words {
                if is_env_assignment(word) {
                    continue;
                }
                return word.rsplit('/').next().unwrap_or(word).to_string();
            }
            command.split_whitespace().next().unwrap_or("").to_string()
        };

        // Normal env var prefix
        assert_eq!(extract_fallback("FOO=bar command"), "command");

        // Multiple env vars
        assert_eq!(extract_fallback("FOO=1 BAR=2 command"), "command");

        // Path with = is treated as the command, not skipped
        assert_eq!(extract_fallback("/opt/foo=bar/bin/thing"), "thing");

        // Absolute path command
        assert_eq!(extract_fallback("/usr/bin/git status"), "git");

        // Plain command
        assert_eq!(extract_fallback("ls -la"), "ls");

        // Env var with underscore key
        assert_eq!(extract_fallback("MY_VAR=hello rm -rf /tmp"), "rm");

        // Token starting with digit containing = is not an env var
        assert_eq!(extract_fallback("1FOO=bar"), "1FOO=bar");

        // Flag with = is not an env var
        assert_eq!(extract_fallback("--config=value"), "--config=value");

        // Only env vars (no command after) falls through to first word
        assert_eq!(extract_fallback("FOO=bar"), "FOO=bar");

        // Empty string
        assert_eq!(extract_fallback(""), "");
    }
}
