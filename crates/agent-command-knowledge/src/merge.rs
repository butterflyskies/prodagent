//! Overlay/merge logic for extending or replacing knowledge base entries.
//!
//! [`KnowledgeOverlay`] is the user-facing config type: it specifies commands
//! and wrappers to add, merge, or remove from a [`KnowledgeBase`].
//! [`CommandOverlay`] mirrors [`CommandKnowledge`] but with optional fields so
//! that unspecified values don't clobber base entries during merge.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::types::{
    CommandKnowledge, CommandProperties, Effect, EnvGate, FlagSchema, KnowledgeBase, PathSpec,
    SubcommandMap, WrapperKnowledge,
};

/// Overlay config for extending/modifying a [`KnowledgeBase`].
///
/// Applied via [`KnowledgeBase::merge`]: removals are processed first, then
/// additions and overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnowledgeOverlay {
    /// Commands to add or merge into the base.
    #[serde(default)]
    pub commands: HashMap<String, CommandOverlay>,
    /// Wrappers to add or wholesale-replace in the base.
    #[serde(default)]
    pub wrappers: HashMap<String, WrapperKnowledge>,
    /// Command names to remove from the base.
    #[serde(default)]
    pub remove_commands: Vec<String>,
    /// Wrapper names to remove from the base.
    #[serde(default)]
    pub remove_wrappers: Vec<String>,
}

/// Overlay for a single command — optional fields so unset values don't
/// clobber base values during merge.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommandOverlay {
    /// Override the base effect. `None` preserves the base value.
    #[serde(default)]
    pub effect: Option<Effect>,
    /// Subcommands to merge into the base (overlay wins on conflict).
    #[serde(default)]
    pub subcommands: SubcommandMap,
    /// Flags to append to the base.
    #[serde(default)]
    pub flags: FlagSchema,
    /// Env gates to append to the base.
    #[serde(default)]
    pub env_gates: Vec<EnvGate>,
    /// Paths to replace base paths. `None` preserves the base value.
    #[serde(default)]
    pub paths: Option<PathSpec>,
    /// Properties to replace base properties. `None` preserves the base value.
    #[serde(default)]
    pub properties: Option<CommandProperties>,
    /// Subcommand patterns to remove from the base before merging.
    /// Patterns are space-separated strings matching the key format used by
    /// `SubcommandMap::insert` (e.g. `"pr create"`, not `"pr"` and `"create"`
    /// as separate entries).
    #[serde(default)]
    pub remove_subcommands: Vec<String>,
}

impl CommandOverlay {
    /// Create an overlay that only sets the effect, leaving everything else defaulted.
    #[cfg(test)]
    pub fn with_effect(effect: Effect) -> Self {
        Self {
            effect: Some(effect),
            ..Default::default()
        }
    }

    /// Apply this overlay onto an existing base command, mutating it in place.
    ///
    /// - Override effect only when specified.
    /// - Remove subcommands listed in `remove_subcommands`, then merge overlay
    ///   subcommands (overlay wins on conflict).
    /// - Append flags and env gates.
    /// - Replace paths and properties only when `Some`.
    pub(crate) fn apply_to(self, base: &mut CommandKnowledge) {
        if let Some(effect) = self.effect {
            base.effect = effect;
        }

        for pattern in &self.remove_subcommands {
            base.subcommands.remove(pattern);
        }
        base.subcommands.extend(self.subcommands);

        base.flags.extend(self.flags);
        base.env_gates.extend(self.env_gates);

        if let Some(paths) = self.paths {
            base.paths = paths;
        }
        if let Some(properties) = self.properties {
            base.properties = properties;
        }
    }

    /// Convert this overlay into a full [`CommandKnowledge`] for insertion as a
    /// new command. Effect defaults to [`Effect::Unknown`] (fail-closed) when
    /// not specified.
    pub(crate) fn into_knowledge(self, key: String) -> CommandKnowledge {
        CommandKnowledge {
            name: key,
            effect: self.effect.unwrap_or(Effect::Unknown),
            subcommands: self.subcommands,
            flags: self.flags,
            env_gates: self.env_gates,
            paths: self.paths.unwrap_or_default(),
            properties: self.properties.unwrap_or_default(),
        }
    }
}

impl KnowledgeBase {
    /// Merge an overlay into this knowledge base.
    ///
    /// Processing order:
    /// 1. **Removals** — commands and wrappers listed in `remove_commands` /
    ///    `remove_wrappers` are deleted from the base.
    /// 2. **Additions / overrides** — overlay commands are merged into existing
    ///    entries (via [`CommandOverlay::apply_to`]) or inserted as new commands
    ///    (via [`CommandOverlay::into_knowledge`]). Overlay wrappers wholesale-
    ///    replace any existing wrapper with the same key.
    pub fn merge(&mut self, overlay: KnowledgeOverlay) {
        // 1. Removals first.
        for key in &overlay.remove_commands {
            self.commands.remove(key);
        }
        for key in &overlay.remove_wrappers {
            self.wrappers.remove(key);
        }

        // 2. Additions / overrides.
        for (key, cmd_overlay) in overlay.commands {
            if let Some(base) = self.commands.get_mut(&key) {
                cmd_overlay.apply_to(base);
            } else {
                self.commands
                    .insert(key.clone(), cmd_overlay.into_knowledge(key));
            }
        }

        for (key, wrapper) in overlay.wrappers {
            self.wrappers.insert(
                key.clone(),
                WrapperKnowledge {
                    name: key,
                    ..wrapper
                },
            );
        }
    }
}

#[cfg(test)]
#[path = "merge_tests.rs"]
mod merge_tests;

#[cfg(test)]
#[path = "merge_proptest.rs"]
mod merge_proptest;
