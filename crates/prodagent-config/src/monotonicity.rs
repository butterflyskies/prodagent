//! Monotonicity validation for the project → user policy boundary.
//!
//! The security invariant: a project config can **tighten** policy (escalate
//! toward Ask/Deny) but **never weaken** it (relax toward Allow). This
//! prevents an untrusted `.prodagent/config.toml` from granting itself
//! broader access than the user intended.
//!
//! [`PolicyDecision`] is ordered `Allow < Ask < Deny`. A project decision
//! `p` is monotonic with respect to user decision `u` when `p >= u`.
//! Relaxation (`p < u`) is a violation.

use std::fmt;

use agent_policy::config::{CommandPolicy, PolicyConfig};
use agent_policy::PolicyDecision;

use crate::types::PolicyOverlay;

/// A monotonicity violation: the project layer tried to weaken a user-level
/// policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonotonicityViolation {
    /// Human-readable location of the violation (e.g. "defaults.read_only"
    /// or "commands.rm").
    pub path: String,
    /// The user-level decision that the project tried to weaken.
    pub user_decision: PolicyDecision,
    /// The project-level decision that was rejected.
    pub project_decision: PolicyDecision,
}

impl fmt::Display for MonotonicityViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "project config at `{}` tried to relax {:?} → {:?} (user floor is {:?})",
            self.path, self.user_decision, self.project_decision, self.user_decision,
        )
    }
}

/// Validate that a project policy overlay does not weaken any decision
/// established by the user-level policy.
///
/// Returns an empty `Vec` when the project overlay is monotonic (safe).
/// Returns one [`MonotonicityViolation`] per relaxation found.
///
/// # Arguments
///
/// * `user_policy` — the merged policy after defaults + user layer (before
///   project layer is applied). This is the "floor" that the project cannot
///   relax below.
/// * `project_overlay` — the project-level overlay that wants to be applied.
pub fn validate_monotonicity(
    user_policy: &PolicyConfig,
    project_overlay: &PolicyOverlay,
) -> Vec<MonotonicityViolation> {
    let mut violations = Vec::new();

    // ── Effect defaults ───────────────────────────────────────────────────
    if let Some(proj_ro) = project_overlay.defaults.read_only {
        if proj_ro < user_policy.defaults.read_only {
            violations.push(MonotonicityViolation {
                path: "policy.defaults.read_only".into(),
                user_decision: user_policy.defaults.read_only,
                project_decision: proj_ro,
            });
        }
    }
    if let Some(proj_mut) = project_overlay.defaults.mutating {
        if proj_mut < user_policy.defaults.mutating {
            violations.push(MonotonicityViolation {
                path: "policy.defaults.mutating".into(),
                user_decision: user_policy.defaults.mutating,
                project_decision: proj_mut,
            });
        }
    }
    if let Some(proj_unk) = project_overlay.defaults.unknown {
        if proj_unk < user_policy.defaults.unknown {
            violations.push(MonotonicityViolation {
                path: "policy.defaults.unknown".into(),
                user_decision: user_policy.defaults.unknown,
                project_decision: proj_unk,
            });
        }
    }

    // ── Per-command overrides ──────────────────────────────────────────────
    for (cmd_name, proj_policy) in &project_overlay.commands {
        let user_decision = resolve_command_decision(user_policy, cmd_name);
        check_command_policy(
            &mut violations,
            cmd_name,
            user_decision,
            proj_policy,
            user_policy,
        );
    }

    // ── remove_commands cannot remove commands that the user explicitly set ──
    // Removing a user-set command policy effectively resets it to the effect
    // default, which could be weaker. We flag this as a violation.
    for cmd_name in &project_overlay.remove_commands {
        if user_policy.commands.contains_key(cmd_name) {
            // The user explicitly set a policy for this command.
            // Removing it would fall back to effect defaults, which might
            // be weaker. Flag it.
            let user_decision = resolve_command_decision(user_policy, cmd_name);
            violations.push(MonotonicityViolation {
                path: format!("policy.remove_commands[{cmd_name}]"),
                user_decision,
                project_decision: PolicyDecision::Allow, // worst case after removal
            });
        }
    }

    violations
}

/// Resolve the effective decision for a command under a policy config.
///
/// Checks per-command overrides first, then falls back to effect defaults.
/// Since we don't know the command's effect class at config validation time,
/// we use the *weakest* (most permissive) effect default as the floor —
/// this is conservative: if the project is weaker than even the weakest
/// default, it's definitely a violation.
fn resolve_command_decision(policy: &PolicyConfig, cmd_name: &str) -> PolicyDecision {
    match policy.commands.get(cmd_name) {
        Some(CommandPolicy::Flat(d)) => *d,
        Some(CommandPolicy::Detailed(detail)) => {
            // Use the base decision if set; otherwise fall back to weakest default.
            detail
                .base
                .unwrap_or(weakest_effect_default(&policy.defaults))
        }
        None => weakest_effect_default(&policy.defaults),
    }
}

/// The weakest (most permissive) effect default — used as the conservative
/// floor when we can't determine a command's effect class.
fn weakest_effect_default(defaults: &agent_policy::config::EffectDefaults) -> PolicyDecision {
    defaults
        .read_only
        .min(defaults.mutating)
        .min(defaults.unknown)
}

/// Check a project command policy against the user's decision for that command.
fn check_command_policy(
    violations: &mut Vec<MonotonicityViolation>,
    cmd_name: &str,
    user_decision: PolicyDecision,
    proj_policy: &CommandPolicy,
    user_policy: &PolicyConfig,
) {
    match proj_policy {
        CommandPolicy::Flat(proj_decision) => {
            if *proj_decision < user_decision {
                violations.push(MonotonicityViolation {
                    path: format!("policy.commands.{cmd_name}"),
                    user_decision,
                    project_decision: *proj_decision,
                });
            }
        }
        CommandPolicy::Detailed(detail) => {
            // Check base decision if present
            if let Some(proj_base) = detail.base {
                if proj_base < user_decision {
                    violations.push(MonotonicityViolation {
                        path: format!("policy.commands.{cmd_name}.base"),
                        user_decision,
                        project_decision: proj_base,
                    });
                }
            }

            // Check each subcommand override
            for (sub_name, proj_sub_decision) in &detail.subcommands {
                // For subcommands, check against the user's subcommand-level
                // decision if it exists, otherwise the user's command-level decision.
                let user_sub_decision =
                    resolve_subcommand_decision(user_policy, cmd_name, sub_name);
                if *proj_sub_decision < user_sub_decision {
                    violations.push(MonotonicityViolation {
                        path: format!("policy.commands.{cmd_name}.subcommands.{sub_name}"),
                        user_decision: user_sub_decision,
                        project_decision: *proj_sub_decision,
                    });
                }
            }
        }
    }
}

/// Resolve the user's effective decision for a specific subcommand.
fn resolve_subcommand_decision(
    policy: &PolicyConfig,
    cmd_name: &str,
    sub_name: &str,
) -> PolicyDecision {
    match policy.commands.get(cmd_name) {
        Some(CommandPolicy::Flat(d)) => *d,
        Some(CommandPolicy::Detailed(detail)) => {
            if let Some(d) = detail.subcommands.get(sub_name) {
                return *d;
            }
            detail
                .base
                .unwrap_or(weakest_effect_default(&policy.defaults))
        }
        None => weakest_effect_default(&policy.defaults),
    }
}
