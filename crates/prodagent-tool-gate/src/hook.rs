//! Core hook evaluation: stdin → policy engine → stdout.

use agent_command_knowledge::default_knowledge_base;
use agent_shell_parser::hook::{parse_input, PreToolUseInput};
use prodagent_config::{load_and_apply, ConfigLoader};
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
}

impl HookOutput {
    fn new(decision: PolicyDecision, reason: String) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: decision,
                permission_decision_reason: reason,
            },
        }
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

    // Load config via three-tier cascade
    let loader = ConfigLoader::from_environment();
    let mut kb = default_knowledge_base().clone();
    let policy_config = load_and_apply(&loader, &mut kb)?;
    let engine = PolicyEngine::new(policy_config).map_err(|e| anyhow::anyhow!(e))?;

    // Evaluate command through the policy engine
    let result = engine.evaluate_command(command, &kb);

    // Apply --escalate-deny: convert Deny → Ask
    let mut decision = result.decision;
    let mut reason = result.reason.clone();
    if escalate_deny && decision == PolicyDecision::Deny {
        decision = PolicyDecision::Ask;
        reason = format!("{reason} (escalated from deny)");
    }

    // Log the decision
    decision_log::log_decision(&input.tool_name, command, decision, &reason);

    // Emit JSON to stdout
    let output = HookOutput::new(decision, reason);
    serde_json::to_writer(std::io::stdout(), &output)?;

    Ok(())
}
