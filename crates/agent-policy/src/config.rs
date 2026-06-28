use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::decision::PolicyDecision;

/// Policy configuration — effect-class defaults and per-command overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Default decisions for each effect class.
    /// Missing entries fall back to built-in defaults.
    #[serde(default)]
    pub defaults: EffectDefaults,

    /// Per-command decision overrides. Keys are command names,
    /// values are either a flat decision or a map of subcommand -> decision.
    #[serde(default)]
    pub commands: HashMap<String, CommandPolicy>,
}

/// Default effect -> decision mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EffectDefaults {
    pub read_only: PolicyDecision,
    pub mutating: PolicyDecision,
    pub unknown: PolicyDecision,
}

impl Default for EffectDefaults {
    fn default() -> Self {
        Self {
            read_only: PolicyDecision::Allow,
            mutating: PolicyDecision::Ask,
            unknown: PolicyDecision::Ask,
        }
    }
}

impl PolicyConfig {
    /// Validate that effect defaults are monotonic: read_only <= mutating <= unknown.
    ///
    /// A non-monotonic configuration would mean a less-risky effect class has a
    /// stricter decision than a more-risky one, which is almost certainly a mistake.
    pub fn validate(&self) -> Result<(), String> {
        if self.defaults.read_only > self.defaults.mutating {
            return Err(format!(
                "non-monotonic policy defaults: read-only ({:?}) is stricter than mutating ({:?})",
                self.defaults.read_only, self.defaults.mutating
            ));
        }
        if self.defaults.mutating > self.defaults.unknown {
            return Err(format!(
                "non-monotonic policy defaults: mutating ({:?}) is stricter than unknown ({:?})",
                self.defaults.mutating, self.defaults.unknown
            ));
        }

        // Reject Detailed entries that are no-ops (no base override + no subcommands)
        for (name, policy) in &self.commands {
            if let CommandPolicy::Detailed(detail) = policy {
                if detail.base.is_none() && detail.subcommands.is_empty() {
                    return Err(format!(
                        "no-op command policy for \"{name}\": Detailed entry has no base override and no subcommands"
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Per-command policy — either a flat decision or subcommand-level overrides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CommandPolicy {
    /// Flat decision for the entire command.
    Flat(PolicyDecision),
    /// Subcommand-level overrides.
    Detailed(DetailedCommandPolicy),
}

/// Subcommand-level policy with optional base override.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetailedCommandPolicy {
    /// Override for the base command (no subcommand matched).
    #[serde(default)]
    pub base: Option<PolicyDecision>,
    /// Per-subcommand overrides. Keys are space-separated patterns.
    #[serde(default)]
    pub subcommands: HashMap<String, PolicyDecision>,
}

// ── Builder ────────────────────────────────────────────────────────────

impl PolicyConfig {
    /// Start building a `PolicyConfig`.
    pub fn builder() -> PolicyConfigBuilder {
        PolicyConfigBuilder::default()
    }
}

/// Incremental builder for [`PolicyConfig`].
///
/// Provides a fluent API for constructing policy configurations with
/// effect-class defaults and per-command overrides. Validates monotonicity
/// and rejects no-op entries on [`build`](Self::build).
#[derive(Debug, Clone, Default)]
pub struct PolicyConfigBuilder {
    defaults: EffectDefaults,
    commands: HashMap<String, CommandPolicy>,
}

impl PolicyConfigBuilder {
    // ── Effect defaults ────────────────────────────────────────────────

    /// Set the default decision for read-only commands.
    pub fn read_only_default(mut self, d: PolicyDecision) -> Self {
        self.defaults.read_only = d;
        self
    }

    /// Set the default decision for mutating commands.
    pub fn mutating_default(mut self, d: PolicyDecision) -> Self {
        self.defaults.mutating = d;
        self
    }

    /// Set the default decision for commands with unknown effects.
    pub fn unknown_default(mut self, d: PolicyDecision) -> Self {
        self.defaults.unknown = d;
        self
    }

    // ── Flat per-command overrides ─────────────────────────────────────

    /// Allow a command unconditionally (flat override).
    pub fn allow(mut self, command: &str) -> Self {
        self.commands.insert(
            command.to_string(),
            CommandPolicy::Flat(PolicyDecision::Allow),
        );
        self
    }

    /// Require confirmation for a command (flat override).
    pub fn ask(mut self, command: &str) -> Self {
        self.commands.insert(
            command.to_string(),
            CommandPolicy::Flat(PolicyDecision::Ask),
        );
        self
    }

    /// Deny a command unconditionally (flat override).
    pub fn deny(mut self, command: &str) -> Self {
        self.commands.insert(
            command.to_string(),
            CommandPolicy::Flat(PolicyDecision::Deny),
        );
        self
    }

    // ── Detailed per-command with subcommands ──────────────────────────

    /// Set the base decision for a command (the fallback when no subcommand matches).
    ///
    /// If a `Flat` entry already exists for this command, it is upgraded to
    /// `Detailed` with the given decision as the base. If a `Detailed` entry
    /// exists, its base is updated.
    pub fn command_base(mut self, command: &str, decision: PolicyDecision) -> Self {
        match self.commands.get_mut(command) {
            Some(CommandPolicy::Detailed(detail)) => {
                detail.base = Some(decision);
            }
            Some(entry @ CommandPolicy::Flat(_)) => {
                *entry = CommandPolicy::Detailed(DetailedCommandPolicy {
                    base: Some(decision),
                    subcommands: HashMap::new(),
                });
            }
            None => {
                self.commands.insert(
                    command.to_string(),
                    CommandPolicy::Detailed(DetailedCommandPolicy {
                        base: Some(decision),
                        subcommands: HashMap::new(),
                    }),
                );
            }
        }
        self
    }

    /// Add a subcommand override for a command.
    ///
    /// If no entry exists for the command, a `Detailed` entry is created with
    /// `base: None`. If a `Flat` entry exists, it is upgraded to `Detailed`
    /// with the flat decision as the base.
    pub fn subcommand(mut self, command: &str, subcommand: &str, decision: PolicyDecision) -> Self {
        match self.commands.get_mut(command) {
            Some(CommandPolicy::Detailed(detail)) => {
                detail.subcommands.insert(subcommand.to_string(), decision);
            }
            Some(entry @ CommandPolicy::Flat(_)) => {
                let flat_decision = match entry {
                    CommandPolicy::Flat(d) => *d,
                    _ => unreachable!(),
                };
                let mut subcommands = HashMap::new();
                subcommands.insert(subcommand.to_string(), decision);
                *entry = CommandPolicy::Detailed(DetailedCommandPolicy {
                    base: Some(flat_decision),
                    subcommands,
                });
            }
            None => {
                let mut subcommands = HashMap::new();
                subcommands.insert(subcommand.to_string(), decision);
                self.commands.insert(
                    command.to_string(),
                    CommandPolicy::Detailed(DetailedCommandPolicy {
                        base: None,
                        subcommands,
                    }),
                );
            }
        }
        self
    }

    // ── Build ──────────────────────────────────────────────────────────

    /// Consume the builder and return a validated [`PolicyConfig`].
    ///
    /// Returns an error if the configuration is invalid (e.g. non-monotonic
    /// effect defaults or no-op detailed entries).
    pub fn build(self) -> Result<PolicyConfig, String> {
        let config = PolicyConfig {
            defaults: self.defaults,
            commands: self.commands,
        };
        config.validate()?;
        Ok(config)
    }
}
