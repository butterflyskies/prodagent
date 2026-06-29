//! Core hook evaluation: stdin → policy engine → stdout.

use agent_command_knowledge::default_knowledge_base;
use agent_shell_parser::hook::{parse_input, PreToolUseInput};
use prodagent_config::{load_split_and_apply, ConfigLoader};
use prodagent_policy::{PolicyDecision, PolicyEngine};
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
    /// When true, this decision is stricter than the user's own policy
    /// because the project config tightened it. The harness should present
    /// a three-option consent gate: Allow once / Deny / Always Allow.
    #[serde(skip_serializing_if = "Option::is_none")]
    conflict: Option<bool>,
    /// The decision the project config wanted (only present on conflict).
    #[serde(skip_serializing_if = "Option::is_none")]
    project_decision: Option<PolicyDecision>,
    /// The config entry that "Always Allow" would write to user config
    /// to resolve this conflict permanently (only present on conflict).
    #[serde(skip_serializing_if = "Option::is_none")]
    override_config: Option<OverrideEntry>,
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
                project_decision: None,
                override_config: None,
            },
        }
    }

    fn with_conflict(
        mut self,
        project_decision: PolicyDecision,
        override_config: OverrideEntry,
    ) -> Self {
        self.hook_specific_output.conflict = Some(true);
        self.hook_specific_output.project_decision = Some(project_decision);
        self.hook_specific_output.override_config = Some(override_config);
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
    let (user_policy, merged_policy) = load_split_and_apply(&loader, &mut kb)?;

    let user_engine = PolicyEngine::new(user_policy).map_err(|e| anyhow::anyhow!(e))?;
    let merged_engine = PolicyEngine::new(merged_policy).map_err(|e| anyhow::anyhow!(e))?;

    // Evaluate command through both engines for conflict detection
    let cwd = input.cwd.as_deref();
    let merged_result = merged_engine.evaluate_command_with_cwd(command, &kb, cwd);
    let user_result = user_engine.evaluate_command_with_cwd(command, &kb, cwd);

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
    if merged_result.decision > user_result.decision {
        // Determine the override config based on what the command touches.
        // If the command has affected paths, scope the override to those paths.
        // Otherwise, create a flat command override.
        let base_command = extract_base_command(command);
        let paths = if !merged_result.affected_paths.is_empty() {
            Some(
                merged_result
                    .affected_paths
                    .iter()
                    .map(|p| p.to_string())
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

        output = output.with_conflict(merged_result.decision, override_entry);
    }

    // Emit JSON to stdout
    serde_json::to_writer(std::io::stdout(), &output)?;

    Ok(())
}

/// Extract the base command name from a raw command string.
///
/// Takes the first non-assignment word's basename (e.g. `/usr/bin/git` -> `git`,
/// `FOO=bar rm -rf` -> `rm`).
fn extract_base_command(command: &str) -> String {
    let words: Vec<&str> = command.split_whitespace().collect();
    for word in &words {
        if word.contains('=') && !word.starts_with('-') {
            continue; // Skip env assignments
        }
        // Take basename
        return word.rsplit('/').next().unwrap_or(word).to_string();
    }
    command.split_whitespace().next().unwrap_or("").to_string()
}
