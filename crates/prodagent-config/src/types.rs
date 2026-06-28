//! Configuration types for the three-tier cascade.
//!
//! [`ProdagentConfig`] is the top-level struct extracted from figment after
//! all layers have been merged. [`ConfigLayer`] is the per-layer overlay
//! type that each TOML file deserializes into.

use std::collections::HashMap;

use agent_command_knowledge::merge::{CommandOverlay, KnowledgeOverlay, WrapperOverlay};
use prodagent_policy::config::{CommandPolicy, EffectDefaults, PolicyConfig};
use prodagent_policy::PolicyDecision;
use serde::{Deserialize, Serialize};

// ── Per-layer overlay ─────────────────────────────────────────────────────

/// A single configuration layer as written in a TOML file.
///
/// This is the user-facing type. Both knowledge and policy sections are
/// optional — omitting a section means "inherit from lower layers."
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigLayer {
    /// Knowledge layer overrides (commands, wrappers, removals).
    #[serde(default)]
    pub knowledge: KnowledgeConfig,

    /// Policy layer overrides (effect defaults, per-command decisions).
    #[serde(default)]
    pub policy: PolicyOverlay,
}

/// Knowledge layer configuration — wraps [`KnowledgeOverlay`] for the
/// figment merge path.
///
/// This type exists so that the TOML structure is `[knowledge.commands.git]`
/// rather than flattening knowledge fields into the top level.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnowledgeConfig {
    /// Commands to add or merge into the base knowledge.
    #[serde(default)]
    pub commands: HashMap<String, CommandOverlay>,
    /// Wrappers to add or merge into the base knowledge.
    #[serde(default)]
    pub wrappers: HashMap<String, WrapperOverlay>,
    /// Command names to remove from the base knowledge.
    #[serde(default)]
    pub remove_commands: Vec<String>,
    /// Wrapper names to remove from the base knowledge.
    #[serde(default)]
    pub remove_wrappers: Vec<String>,
}

impl KnowledgeConfig {
    /// Convert into a [`KnowledgeOverlay`] for application to a
    /// [`KnowledgeBase`](agent_command_knowledge::KnowledgeBase).
    pub fn into_overlay(self) -> KnowledgeOverlay {
        KnowledgeOverlay {
            commands: self.commands,
            wrappers: self.wrappers,
            remove_commands: self.remove_commands,
            remove_wrappers: self.remove_wrappers,
        }
    }

    /// Returns `true` if this knowledge config has no effect (all fields empty).
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
            && self.wrappers.is_empty()
            && self.remove_commands.is_empty()
            && self.remove_wrappers.is_empty()
    }
}

/// Policy layer overlay — optional fields so that omitting a value in TOML
/// preserves the lower layer's value rather than resetting to defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyOverlay {
    /// Override default decisions for effect classes.
    #[serde(default)]
    pub defaults: PolicyDefaultsOverlay,

    /// Per-command decision overrides.
    #[serde(default)]
    pub commands: HashMap<String, CommandPolicy>,

    /// Command names whose policy overrides should be removed from the
    /// inherited config. Processed before additions (same as knowledge layer).
    #[serde(default)]
    pub remove_commands: Vec<String>,

    /// Override the ceiling for opaque env values on value-dependent gates.
    /// See [`PolicyConfig::opaque_env_ceiling`] for details.
    #[serde(default)]
    pub opaque_env_ceiling: Option<PolicyDecision>,
}

/// Optional overrides for effect-class defaults. `None` means "inherit."
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyDefaultsOverlay {
    /// Override the default decision for read-only commands.
    #[serde(default)]
    pub read_only: Option<PolicyDecision>,
    /// Override the default decision for mutating commands.
    #[serde(default)]
    pub mutating: Option<PolicyDecision>,
    /// Override the default decision for unknown-effect commands.
    #[serde(default)]
    pub unknown: Option<PolicyDecision>,
}

impl PolicyDefaultsOverlay {
    /// Returns `true` if no defaults are overridden.
    pub fn is_empty(&self) -> bool {
        self.read_only.is_none() && self.mutating.is_none() && self.unknown.is_none()
    }
}

impl PolicyOverlay {
    /// Returns `true` if this policy overlay has no effect.
    pub fn is_empty(&self) -> bool {
        self.defaults.is_empty()
            && self.commands.is_empty()
            && self.remove_commands.is_empty()
            && self.opaque_env_ceiling.is_none()
    }

    /// Apply this overlay onto a base [`PolicyConfig`], mutating it in place.
    ///
    /// Processing order mirrors the knowledge layer:
    /// 1. Remove commands listed in `remove_commands`.
    /// 2. Override effect defaults (only `Some` values).
    /// 3. Merge per-command overrides (overlay wins on conflict).
    pub fn apply_to(self, base: &mut PolicyConfig) {
        // 1. Removals first.
        for key in &self.remove_commands {
            base.commands.remove(key);
        }

        // 2. Effect defaults — only override when specified.
        if let Some(d) = self.defaults.read_only {
            base.defaults.read_only = d;
        }
        if let Some(d) = self.defaults.mutating {
            base.defaults.mutating = d;
        }
        if let Some(d) = self.defaults.unknown {
            base.defaults.unknown = d;
        }

        // 3. Opaque env ceiling — override when specified.
        if let Some(ceiling) = self.opaque_env_ceiling {
            base.opaque_env_ceiling = ceiling;
        }

        // 4. Per-command overrides — overlay wins.
        for (key, policy) in self.commands {
            base.commands.insert(key, policy);
        }
    }
}

// ── Merged config ─────────────────────────────────────────────────────────

/// The fully merged configuration after all three tiers have been applied.
///
/// This is the final, validated config that consumers use. It contains
/// the merged knowledge overlay (to be applied to a `KnowledgeBase`) and
/// the merged policy config (to be passed to `PolicyEngine::new`).
#[derive(Debug, Clone)]
pub struct ProdagentConfig {
    /// Merged knowledge overlay ready to apply to a `KnowledgeBase`.
    pub knowledge: KnowledgeOverlay,
    /// Merged and validated policy configuration.
    pub policy: PolicyConfig,
}

impl ProdagentConfig {
    /// Build from the three tiers. Each tier is optional except defaults.
    ///
    /// This is the low-level constructor — prefer [`ConfigLoader`](crate::ConfigLoader)
    /// for filesystem-based loading with figment.
    pub(crate) fn from_layers(
        defaults: ConfigLayer,
        user: Option<ConfigLayer>,
        project: Option<ConfigLayer>,
    ) -> Self {
        // Start with defaults
        let mut knowledge = defaults.knowledge;
        let mut policy = PolicyConfig {
            defaults: EffectDefaults {
                read_only: defaults
                    .policy
                    .defaults
                    .read_only
                    .unwrap_or(PolicyDecision::Allow),
                mutating: defaults
                    .policy
                    .defaults
                    .mutating
                    .unwrap_or(PolicyDecision::Ask),
                unknown: defaults
                    .policy
                    .defaults
                    .unknown
                    .unwrap_or(PolicyDecision::Ask),
            },
            commands: defaults.policy.commands,
            ..PolicyConfig::default()
        };

        // Merge user layer
        if let Some(user_layer) = user {
            knowledge = merge_knowledge(knowledge, user_layer.knowledge);
            user_layer.policy.apply_to(&mut policy);
        }

        // Merge project layer
        if let Some(project_layer) = project {
            knowledge = merge_knowledge(knowledge, project_layer.knowledge);
            project_layer.policy.apply_to(&mut policy);
        }

        // Convert the accumulated knowledge config into a single overlay
        let knowledge_overlay = knowledge.into_overlay();

        ProdagentConfig {
            knowledge: knowledge_overlay,
            policy,
        }
    }
}

/// Merge two knowledge configs by accumulating their fields.
///
/// Removals from `overlay` are appended to `base`'s removal lists.
/// Commands and wrappers from `overlay` override `base` on conflict.
fn merge_knowledge(mut base: KnowledgeConfig, overlay: KnowledgeConfig) -> KnowledgeConfig {
    // Accumulate removals
    base.remove_commands.extend(overlay.remove_commands);
    base.remove_wrappers.extend(overlay.remove_wrappers);

    // Overlay commands/wrappers win on conflict
    for (key, cmd) in overlay.commands {
        base.commands.insert(key, cmd);
    }
    for (key, wrapper) in overlay.wrappers {
        base.wrappers.insert(key, wrapper);
    }

    base
}
