use std::collections::HashMap;

use camino::Utf8PathBuf;
use prodagent_types::{SubcommandPattern, Word};
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};

// Re-export from prodagent-types — single source of truth.
pub use prodagent_types::MAX_SUBCOMMAND_DEPTH;

/// The effect level of a command or subcommand.
///
/// The derived `Ord` implementation is intentional: variants are ordered from
/// least to most restrictive (`ReadOnly < Mutating < Unknown`).
/// `Unknown` is the most restrictive value so that aggregation via `max` is
/// fail-closed — when the effect cannot be determined, the result is treated as
/// the worst case rather than silently underestimating risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Effect {
    ReadOnly,
    Mutating,
    Unknown,
}

/// What we know about a command — its effect, subcommands, flags, env gates,
/// and path semantics. Knowledge entries come from embedded defaults or
/// user-provided TOML config; they describe commands without making policy
/// decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandKnowledge {
    pub name: String,
    /// Base effect when no subcommand matches.
    pub effect: Effect,
    #[serde(default)]
    pub subcommands: SubcommandMap,
    #[serde(default)]
    pub flags: FlagSchema,
    #[serde(default)]
    pub env_gates: Vec<EnvGate>,
    #[serde(default)]
    pub paths: PathSpec,
    #[serde(default)]
    pub properties: CommandProperties,
}

/// Map of subcommand patterns to their entries. Keys are validated
/// [`SubcommandPattern`]s — space-separated strings (e.g. `"pr create"`)
/// matched via [`longest_match`](SubcommandMap::longest_match).
///
/// Validation lives in the [`SubcommandPattern`] key type itself: constructing
/// a key enforces non-emptiness and [`MAX_SUBCOMMAND_DEPTH`]. Deserialization
/// routes each key through `SubcommandPattern::try_from`, so patterns with too
/// many words (or empty patterns) are rejected at parse time with a clear error
/// naming the offending key. Nested `SubcommandEntry` maps are validated
/// recursively because `SubcommandEntry::subcommands` is itself a
/// `SubcommandMap`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SubcommandMap {
    entries: HashMap<SubcommandPattern, SubcommandEntry>,
}

impl<'de> Deserialize<'de> for SubcommandMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// Wrapper struct to leverage the derived `Deserialize` for the outer
        /// `{ entries: { ... } }` shape. Keys are read as raw `String`s so we
        /// can route each one through `SubcommandPattern` validation below.
        #[derive(Deserialize)]
        struct SubcommandMapRepr {
            #[serde(default)]
            entries: HashMap<String, SubcommandEntry>,
        }

        let repr = SubcommandMapRepr::deserialize(deserializer)?;
        let mut entries = HashMap::with_capacity(repr.entries.len());
        for (key, entry) in repr.entries {
            // The key type carries the validation: non-empty + depth limit.
            // Map its error into a deserialize error so violations still
            // surface as a clear, equivalent parse failure.
            let pattern = SubcommandPattern::try_from(key).map_err(serde::de::Error::custom)?;
            entries.insert(pattern, entry);
        }
        Ok(SubcommandMap { entries })
    }
}

/// A subcommand's knowledge: its effect, flags, env gates, path semantics,
/// and optional nested subcommands for multi-level commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubcommandEntry {
    pub effect: Effect,
    #[serde(default)]
    pub flags: FlagSchema,
    #[serde(default)]
    pub env_gates: Vec<EnvGate>,
    #[serde(default)]
    pub paths: PathSpec,
    #[serde(default)]
    pub subcommands: SubcommandMap,
}

/// Flag-level knowledge for subcommand extraction and path/escalation detection.
///
/// All flag names are strings from config (not parsed `Word`s).
/// `skip_arg` and `skip_solo` must be exhaustive for the command's flags that
/// consume values or stand alone — omitting a value-consuming flag silently
/// corrupts subcommand resolution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlagSchema {
    /// Flags that consume the next word as their value (e.g. `-C`, `--git-dir`).
    #[serde(default)]
    pub skip_arg: Vec<String>,
    /// Standalone boolean flags (e.g. `--bare`, `--no-pager`).
    #[serde(default)]
    pub skip_solo: Vec<String>,
    /// Flags that escalate severity (e.g. `--force`, `--force-with-lease`).
    /// Detected via exact match or `--flag=value` prefix.
    #[serde(default)]
    pub escalation: Vec<String>,
    /// Flags whose values are filesystem paths (e.g. `-C` for git).
    #[serde(default)]
    pub path: Vec<String>,
}

impl FlagSchema {
    /// Append all flags from `other` onto `self`. Duplicates in `skip_arg`,
    /// `skip_solo`, and `escalation` are harmless (consumers use `.any()` scans).
    /// Duplicate `path` entries will produce duplicate `affected_paths` from
    /// `extract_paths` — consumers should tolerate this.
    pub fn extend(&mut self, other: FlagSchema) {
        self.skip_arg.extend(other.skip_arg);
        self.skip_solo.extend(other.skip_solo);
        self.escalation.extend(other.escalation);
        self.path.extend(other.path);
    }
}

/// The action an env gate applies when its condition matches.
///
/// This is the KB-side decision type — it describes what should happen, not
/// the policy engine's final decision. The policy engine maps these to
/// [`PolicyDecision`](agent_policy::PolicyDecision) values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvGateAction {
    Allow,
    Ask,
    Deny,
}

/// Condition on an environment variable's value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvCondition {
    /// Matches when the var is set and equals this value.
    Equals(String),
    /// Matches when the var is unset or has a different value.
    NotEquals(String),
    /// Matches when the var is set (any value).
    Set,
    /// Matches when the var is not set.
    Unset,
}

/// An environment gate — a condition on an environment variable that, when
/// matched, applies a decision to the command.
///
/// When the condition **matches**, the gate's `decision` is applied.
/// When the condition **does not match**, the gate has no effect.
/// Multiple gates on the same command: the **strictest** action wins
/// (Deny > Ask > Allow). A Deny gate short-circuits remaining gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvGate {
    /// Environment variable name to check.
    pub var: String,
    /// Condition to evaluate against the variable's value.
    pub condition: EnvCondition,
    /// Decision to apply when the condition matches.
    pub decision: EnvGateAction,
}

/// Which arguments are filesystem paths — used by the policy layer for
/// path-aware authorization.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathSpec {
    #[serde(default)]
    pub positionals: PathPositionals,
    #[serde(default)]
    pub flags: Vec<String>,
}

/// How positional arguments map to filesystem paths.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PathPositionals {
    #[default]
    None,
    All,
    Tail(usize),
    Last,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommandProperties {
    #[serde(default)]
    pub version_flag: Option<String>,
}

/// Semantic knowledge about a wrapper command, layered on top of
/// agent-shell-parser's `WrapperSpec` (which handles stripping mechanics).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperKnowledge {
    pub name: String,
    /// Minimum effect for any command run under this wrapper.
    pub floor_effect: Effect,
    #[serde(default)]
    pub clears_env: bool,
    #[serde(default)]
    pub escalates_privilege: bool,
}

/// The full knowledge base — all known commands and wrappers. Populated from
/// embedded defaults and extended by user/project TOML config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnowledgeBase {
    #[serde(default)]
    pub commands: HashMap<String, CommandKnowledge>,
    #[serde(default)]
    pub wrappers: HashMap<String, WrapperKnowledge>,
}

/// The result of classifying a command — its effect, matched subcommand,
/// escalation flags, affected paths, env gates, and wrapper info.
/// Produced by [`classify`](crate::classify).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandInfo {
    pub effect: Effect,
    pub subcommand: Option<String>,
    pub has_escalation_flags: bool,
    /// Filesystem paths the command is expected to affect, validated as UTF-8
    /// at the extraction boundary. Non-UTF-8 shell words are skipped during
    /// extraction — they cannot represent valid filesystem paths on platforms
    /// this crate targets.
    pub affected_paths: Vec<Utf8PathBuf>,
    pub env_gates: Vec<EnvGate>,
    pub wrapper: Option<WrapperInfo>,
}

/// Wrapper metadata returned when the base command is a known wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapperInfo {
    pub name: String,
    pub floor_effect: Effect,
    pub clears_env: bool,
    pub escalates_privilege: bool,
}

impl SubcommandEntry {
    /// Create an entry with the given effect and all other fields defaulted.
    #[cfg(test)]
    pub fn with_effect(effect: Effect) -> Self {
        Self {
            effect,
            flags: FlagSchema::default(),
            env_gates: vec![],
            paths: PathSpec::default(),
            subcommands: SubcommandMap::new(),
        }
    }
}

impl CommandKnowledge {
    /// Create a command with the given name, effect, and all other fields defaulted.
    #[cfg(test)]
    pub fn simple(name: impl Into<String>, effect: Effect) -> Self {
        let name = name.into();
        Self {
            name,
            effect,
            subcommands: SubcommandMap::new(),
            flags: FlagSchema::default(),
            env_gates: vec![],
            paths: PathSpec::default(),
            properties: CommandProperties::default(),
        }
    }
}

impl SubcommandMap {
    #[must_use = "returns an empty SubcommandMap"]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Insert a subcommand pattern and its entry.
    ///
    /// # Panics (debug builds)
    ///
    /// The key is constructed via [`SubcommandPattern::new_unchecked`], which
    /// debug-asserts that the pattern is non-empty and does not exceed
    /// [`MAX_SUBCOMMAND_DEPTH`]. The deserialization path validates this
    /// invariant at parse time, so patterns from TOML config are always safe.
    /// This assert catches mistakes in programmatic construction during
    /// development.
    pub fn insert(&mut self, pattern: impl Into<String>, entry: SubcommandEntry) {
        self.entries
            .insert(SubcommandPattern::new_unchecked(pattern), entry);
    }

    #[must_use = "returns the entry if found"]
    pub fn get(&self, pattern: &str) -> Option<&SubcommandEntry> {
        self.entries.get(pattern)
    }

    #[must_use = "returns whether the map has entries"]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &SubcommandEntry)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn extend(&mut self, other: SubcommandMap) {
        // Keys are already validated `SubcommandPattern`s — insert directly.
        self.entries.extend(other.entries);
    }

    pub fn remove(&mut self, pattern: &str) {
        self.entries.remove(pattern);
    }

    #[must_use = "returns the number of entries in the map"]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use = "returns the best-matching entry and how many words it consumed"]
    pub fn longest_match(&self, words: &[&Word]) -> Option<(&SubcommandEntry, usize)> {
        let max_depth = words.len().min(MAX_SUBCOMMAND_DEPTH);
        for depth in (1..=max_depth).rev() {
            let pattern: String = words[..depth]
                .iter()
                .map(|w| w.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            if let Some(entry) = self.entries.get(pattern.as_str()) {
                return Some((entry, depth));
            }
        }
        None
    }
}

impl<'a> IntoIterator for &'a SubcommandMap {
    type Item = (&'a str, &'a SubcommandEntry);
    type IntoIter = std::iter::Map<
        std::collections::hash_map::Iter<'a, SubcommandPattern, SubcommandEntry>,
        fn((&'a SubcommandPattern, &'a SubcommandEntry)) -> (&'a str, &'a SubcommandEntry),
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }
}

impl CommandInfo {
    #[must_use = "returns a default Unknown classification"]
    pub fn unknown() -> Self {
        Self {
            effect: Effect::Unknown,
            subcommand: None,
            has_escalation_flags: false,
            affected_paths: Vec::new(),
            env_gates: vec![],
            wrapper: None,
        }
    }
}

#[cfg(test)]
#[path = "types_tests.rs"]
mod types_tests;

#[cfg(test)]
#[path = "types_proptest.rs"]
mod types_proptest;
