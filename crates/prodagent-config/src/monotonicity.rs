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

use prodagent_policy::config::{CommandPolicy, PolicyConfig};
use prodagent_policy::path_rules::{glob_covers, PathRule};
use prodagent_policy::PolicyDecision;

use crate::types::PolicyOverlay;

/// A monotonicity violation: the project layer tried to weaken a user-level
/// policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonotonicityViolation {
    /// The project layer tried to relax a user-level policy decision.
    Relaxation {
        path: String,
        user_decision: PolicyDecision,
        project_decision: PolicyDecision,
    },
    /// A structural violation: the project config uses a feature that is
    /// prohibited at the project level (e.g., overrides).
    Structural { path: String, reason: String },
}

impl fmt::Display for MonotonicityViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Relaxation {
                path,
                user_decision,
                project_decision,
            } => write!(
                f,
                "project config at `{path}` tried to relax {user_decision:?} → {project_decision:?} (user floor is {user_decision:?})",
            ),
            Self::Structural { path, reason } => {
                write!(f, "structural violation at `{path}`: {reason}")
            }
        }
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
            violations.push(MonotonicityViolation::Relaxation {
                path: "policy.defaults.read_only".into(),
                user_decision: user_policy.defaults.read_only,
                project_decision: proj_ro,
            });
        }
    }
    if let Some(proj_mut) = project_overlay.defaults.mutating {
        if proj_mut < user_policy.defaults.mutating {
            violations.push(MonotonicityViolation::Relaxation {
                path: "policy.defaults.mutating".into(),
                user_decision: user_policy.defaults.mutating,
                project_decision: proj_mut,
            });
        }
    }
    if let Some(proj_unk) = project_overlay.defaults.unknown {
        if proj_unk < user_policy.defaults.unknown {
            violations.push(MonotonicityViolation::Relaxation {
                path: "policy.defaults.unknown".into(),
                user_decision: user_policy.defaults.unknown,
                project_decision: proj_unk,
            });
        }
    }

    // ── Opaque env ceiling ─────────────────────────────────────────────────
    if let Some(proj_ceiling) = project_overlay.opaque_env_ceiling {
        if proj_ceiling < user_policy.opaque_env_ceiling {
            violations.push(MonotonicityViolation::Relaxation {
                path: "policy.opaque_env_ceiling".into(),
                user_decision: user_policy.opaque_env_ceiling,
                project_decision: proj_ceiling,
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
            violations.push(MonotonicityViolation::Relaxation {
                path: format!("policy.remove_commands[{cmd_name}]"),
                user_decision,
                project_decision: PolicyDecision::Allow, // worst case after removal
            });
        }
    }

    // ── Overrides ─────────────────────────────────────────────────────────
    // Project configs MUST NOT contain overrides — overrides are a user-only
    // concept. A project config with overrides would allow untrusted config
    // to bypass the monotonicity invariant entirely.
    if let Some(ref overrides) = project_overlay.overrides {
        if !overrides.is_empty() {
            violations.push(MonotonicityViolation::Structural {
                path: "policy.overrides (prohibited in project config)".into(),
                reason: "project configs must not contain user overrides".into(),
            });
        }
    }

    // ── Path-scoped rules ─────────────────────────────────────────────────
    // A project config cannot introduce path-scoped rules that are weaker
    // than the user's effective floor. For command-scoped path rules,
    // compare against the user's decision for that command. For unscoped
    // path rules, compare against the strongest (most restrictive) effect
    // default — the rule fires for all commands regardless of effect class.
    if let Some(ref path_rules) = project_overlay.path_rules {
        for (i, rule) in path_rules.iter().enumerate() {
            let user_floor = path_rule_floor(rule, user_policy);

            // Check against user-level path rules with structural coverage:
            // find all user rules that could match a subset of what the
            // project rule matches, and take the most restrictive as the
            // floor.
            let user_path_floor = user_policy
                .path_rules
                .iter()
                .filter(|r| user_rule_covers_project(r, rule))
                .map(|r| r.decision)
                .max() // most restrictive covering rule
                .unwrap_or(user_floor);

            let effective_floor = user_floor.max(user_path_floor);

            if rule.decision < effective_floor {
                let label = match &rule.command {
                    Some(cmd) => format!(
                        "policy.path_rules[{i}] (command={cmd}, paths={:?})",
                        rule.paths
                    ),
                    None => format!("policy.path_rules[{i}] (paths={:?})", rule.paths),
                };
                violations.push(MonotonicityViolation::Relaxation {
                    path: label,
                    user_decision: effective_floor,
                    project_decision: rule.decision,
                });
            }
        }
    }

    // ── File-ops path rules ────────────────────────────────────────────────
    // A project config cannot introduce file-ops rules that are weaker than
    // the user's effect-class defaults. For read tools, compare against the
    // user's read_only default. For write/edit tools, compare against the
    // user's mutating default. Tool-unscoped rules are compared against the
    // weakest of (read_only, mutating).
    if let Some(ref file_ops) = project_overlay.file_ops {
        for (i, rule) in file_ops.path_rules.iter().enumerate() {
            // For monotonicity, compare against the strictest applicable floor.
            // An unscoped rule can match mutating tools, so the project can't
            // weaken the mutating default via an unscoped Allow. Read-only scoped
            // rules only need to respect the read_only floor.
            let user_floor = match &rule.tools {
                Some(tools) if tools.iter().all(|t| !t.is_mutating()) => {
                    // Read-only scoped rule: compare against read_only default
                    user_policy.defaults.read_only
                }
                Some(tools) if tools.iter().all(|t| t.is_mutating()) => {
                    // Mutating-only scoped rule: compare against mutating default
                    user_policy.defaults.mutating
                }
                _ => {
                    // Unscoped or mixed: compare against mutating default
                    // (strictest applicable class — can't weaken writes)
                    user_policy.defaults.mutating
                }
            };

            // Also check against user-level file_ops rules. If the user has
            // an existing rule for the same path, the project cannot weaken it.
            let user_file_floor = user_policy
                .file_ops
                .path_rules
                .iter()
                .find(|r| r.path == rule.path)
                .map(|r| r.decision)
                .unwrap_or(user_floor);

            let effective_floor = user_floor.max(user_file_floor);

            if rule.decision < effective_floor {
                violations.push(MonotonicityViolation::Relaxation {
                    path: format!("policy.file_ops.path_rules[{i}] ({})", rule.path),
                    user_decision: effective_floor,
                    project_decision: rule.decision,
                });
            }
        }
    }

    violations
}

/// Determine the user-level floor for a path-scoped rule.
///
/// For command-scoped rules, the floor is either the user's explicit
/// per-command override or (when no override exists) the **strongest**
/// effect default. We use strongest because the command's effect class
/// is unknown at validation time — the rule could fire for a command in
/// any class, and the floor must hold for the most restrictive one.
///
/// The Kani proof `merge_monotonicity_command_scoped_path_rules` in
/// `prodagent-proofs` (Invariant #6b) proves that the precise per-effect-
/// class floor is sufficient. Using `strongest_effect_default` is a
/// conservative overapproximation that is also correct — it's tighter
/// than per-effect-class, so any config that passes this check also
/// satisfies the per-effect-class invariant. The trade-off: a project
/// cannot add a permissive path rule for a read-only command when a
/// stricter default exists for mutating/unknown commands. Threading the
/// knowledge base through would enable the precise check.
///
/// For unscoped rules (no `command` field), the same strongest-default
/// floor applies — the rule fires for all commands regardless of class.
fn path_rule_floor(rule: &PathRule, user_policy: &PolicyConfig) -> PolicyDecision {
    match &rule.command {
        Some(cmd) => {
            // If the user explicitly set a per-command policy, use it as
            // the floor — it's the most specific signal of user intent.
            match user_policy.commands.get(cmd.as_str()) {
                Some(CommandPolicy::Flat(d)) => *d,
                Some(CommandPolicy::Detailed(detail)) => detail
                    .base
                    .unwrap_or(strongest_effect_default(&user_policy.defaults)),
                // No per-command override: fall back to strongest effect
                // default. See Invariant #6b proofs for the soundness
                // argument.
                None => strongest_effect_default(&user_policy.defaults),
            }
        }
        None => strongest_effect_default(&user_policy.defaults),
    }
}

/// Resolve the effective decision for a command under a policy config.
///
/// Checks per-command overrides first, then falls back to effect defaults.
/// Since we don't know the command's effect class at config validation time,
/// we use the *strongest* (most restrictive) effect default as the floor —
/// this ensures a project cannot exploit the gap between a permissive
/// read-only default and a stricter mutating/unknown default when no
/// per-command override exists. See Invariant #6b proofs for the soundness
/// argument.
fn resolve_command_decision(policy: &PolicyConfig, cmd_name: &str) -> PolicyDecision {
    match policy.commands.get(cmd_name) {
        Some(CommandPolicy::Flat(d)) => *d,
        Some(CommandPolicy::Detailed(detail)) => {
            // Use the base decision if set; otherwise fall back to strongest default.
            detail
                .base
                .unwrap_or(strongest_effect_default(&policy.defaults))
        }
        None => strongest_effect_default(&policy.defaults),
    }
}

/// The strongest (most restrictive) effect default — used as the floor for
/// per-command overrides and path rules when the command's effect class is
/// unknown at validation time.
fn strongest_effect_default(defaults: &prodagent_policy::config::EffectDefaults) -> PolicyDecision {
    defaults
        .read_only
        .max(defaults.mutating)
        .max(defaults.unknown)
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
                violations.push(MonotonicityViolation::Relaxation {
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
                    violations.push(MonotonicityViolation::Relaxation {
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
                    violations.push(MonotonicityViolation::Relaxation {
                        path: format!("policy.commands.{cmd_name}.subcommands.{sub_name}"),
                        user_decision: user_sub_decision,
                        project_decision: *proj_sub_decision,
                    });
                }
            }
        }
    }
}

/// Check whether a user path rule structurally covers a project path rule.
///
/// A user rule covers a project rule when:
/// 1. The user rule's command scope is equal or broader (`None` covers all)
/// 2. At least one of the project rule's path globs is within the scope
///    of at least one of the user rule's path globs
fn user_rule_covers_project(user_rule: &PathRule, proj_rule: &PathRule) -> bool {
    // Command scope: user None covers anything; user Some(x) only covers Some(x)
    if let Some(ref user_cmd) = user_rule.command {
        match &proj_rule.command {
            Some(proj_cmd) if proj_cmd == user_cmd => {}
            _ => return false,
        }
    }

    // Path coverage: any project glob within any user glob
    proj_rule.paths.iter().any(|proj_pat| {
        user_rule
            .paths
            .iter()
            .any(|user_pat| glob_covers(user_pat, proj_pat))
    })
}

/// Resolve the user's effective decision for a specific subcommand.
///
/// Same floor logic as [`resolve_command_decision`]: when no per-command
/// override exists, the strongest effect default is the correct floor.
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
                .unwrap_or(strongest_effect_default(&policy.defaults))
        }
        None => strongest_effect_default(&policy.defaults),
    }
}
