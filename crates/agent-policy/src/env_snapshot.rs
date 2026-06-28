//! Environment snapshot — represents the resolved environment for a segment.
//!
//! The snapshot models three layers of env state:
//! - **Base:** either the process environment or a clean slate (`env -i`).
//! - **Overrides:** inline assignments (`FOO=bar cmd`) or `env FOO=bar` assignments.
//! - **Unsets:** explicit unset requests (`env -u VAR`).
//!
//! Resolution order: unsets > overrides > base > process env.

use std::collections::{HashMap, HashSet};

use agent_shell_parser::parse::types::{AssignmentValue, Word};

/// The resolved environment state for a command segment.
///
/// Supports layered resolution: unsets win over overrides, which win over the
/// base environment, which wins over the process environment (when base is
/// `None`, i.e. inherited).
#[derive(Debug, Clone)]
pub struct EnvSnapshot {
    /// `None` = inherit process env; `Some` = use this instead (e.g. `env -i`).
    base: Option<HashMap<String, String>>,
    /// Overrides applied on top of the base (inline assignments + `env VAR=val`).
    overrides: HashMap<String, String>,
    /// Variables explicitly unset (`env -u VAR`).
    unsets: HashSet<String>,
    /// Variables whose values are unknown (from substitutions we can't evaluate).
    unknown: HashSet<String>,
    /// When true, the entire environment is opaque (e.g. after bare `sudo`).
    /// Explicit overrides set after this flag are still visible via `get_value`.
    fully_unknown: bool,
}

impl EnvSnapshot {
    /// Create a snapshot that inherits from the process environment.
    pub fn from_process_env() -> Self {
        Self {
            base: None,
            overrides: HashMap::new(),
            unsets: HashSet::new(),
            unknown: HashSet::new(),
            fully_unknown: false,
        }
    }

    /// Create a snapshot with a clean environment (no inherited process env).
    /// Equivalent to `env -i`.
    pub fn clean() -> Self {
        Self {
            base: Some(HashMap::new()),
            overrides: HashMap::new(),
            unsets: HashSet::new(),
            unknown: HashSet::new(),
            fully_unknown: false,
        }
    }

    /// Apply inline assignments from a word slice.
    ///
    /// Scans `words` from the beginning, collecting `KEY=VALUE` assignments
    /// until a non-assignment word is found. Statically-known values become
    /// overrides; substitution-derived values (`FOO=$(cmd)`, `FOO=$VAR`) are
    /// marked unknown so the policy layer can never trust a value it cannot see.
    /// The static/dynamic distinction is carried by [`AssignmentValue`] rather
    /// than re-derived here with an ad-hoc string check.
    #[must_use]
    pub fn with_assignments(mut self, words: &[Word]) -> Self {
        for word in words {
            match word.as_classified_assignment() {
                Some((key, AssignmentValue::Static(value))) => self.set(key, value),
                Some((key, AssignmentValue::CommandSubstitution))
                | Some((key, AssignmentValue::VariableExpansion)) => {
                    self.set_unknown(key);
                }
                None => break,
            }
        }
        self
    }

    /// Add a single override.
    pub fn set(&mut self, var: impl Into<String>, value: impl Into<String>) {
        let var = var.into();
        self.unsets.remove(&var);
        self.unknown.remove(&var);
        self.overrides.insert(var, value.into());
    }

    /// Unset a variable.
    pub fn unset(&mut self, var: impl Into<String>) {
        let var = var.into();
        self.overrides.remove(&var);
        self.unknown.remove(&var);
        self.unsets.insert(var);
    }

    /// Mark a variable as having an unknown value.
    pub fn set_unknown(&mut self, var: impl Into<String>) {
        let var = var.into();
        self.overrides.remove(&var);
        self.unsets.remove(&var);
        self.unknown.insert(var);
    }

    /// Switch to a clean base (all process env is discarded).
    ///
    /// Also clears overrides, unsets, and unknowns — `env -i` means "start
    /// from nothing," so prior state should not leak through.
    pub fn reset_to_clean(&mut self) {
        self.base = Some(HashMap::new());
        self.overrides.clear();
        self.unsets.clear();
        self.unknown.clear();
        self.fully_unknown = false;
    }

    /// Mark all variables as unknown (e.g., after `sudo` without `-E`).
    ///
    /// Sets the `fully_unknown` flag and clears overrides, unsets, and
    /// per-variable unknowns — the entire env is opaque. Explicit overrides
    /// set *after* this call are still visible via `get_value` (overrides
    /// are checked before the fully_unknown guard).
    pub fn mark_all_unknown(&mut self) {
        self.base = Some(HashMap::new());
        self.overrides.clear();
        self.unsets.clear();
        self.unknown.clear();
        self.fully_unknown = true;
    }

    /// Returns true if the entire environment is unknown (e.g., after bare `sudo`).
    pub fn is_fully_unknown(&self) -> bool {
        self.fully_unknown
    }

    /// Build a new snapshot that starts fully unknown, then selectively restores
    /// the listed variables from `source` if they have known values there.
    ///
    /// Used by `resolve_sudo_wrapper` for the `--preserve-env=VAR,VAR` case:
    /// the base environment is wiped (everything unknown), then only the
    /// explicitly listed vars are copied through from the outer env.
    ///
    /// Variables not found in `source` (or whose value in `source` is Unknown)
    /// remain Unknown in the returned snapshot.
    pub(crate) fn preserved_from(source: &EnvSnapshot, vars: &[&str]) -> Self {
        let mut env = source.clone();
        env.mark_all_unknown();
        for var in vars {
            if let Some(EnvValueOwned::Known(val)) = source.get_value(var) {
                env.set(*var, val);
            }
            // If outer is Unknown or None, leave as unknown (mark_all_unknown already did that)
        }
        env
    }

    /// Resolve a variable's value, returning an owned string.
    ///
    /// This is the primary resolution method — it handles process env lookup
    /// correctly (unlike `get` which cannot return references to temporaries).
    pub fn get_value(&self, var: &str) -> Option<EnvValueOwned> {
        // 1. Explicit unset wins
        if self.unsets.contains(var) {
            return None;
        }

        // 2. Explicit override (checked BEFORE fully_unknown so that
        //    assignments set after mark_all_unknown are visible)
        if let Some(value) = self.overrides.get(var) {
            return Some(EnvValueOwned::Known(value.clone()));
        }

        // 3. Per-variable unknown (from substitutions we can't evaluate)
        if self.unknown.contains(var) {
            return Some(EnvValueOwned::Unknown);
        }

        // 4. Fully-unknown environment (e.g. after bare sudo)
        if self.fully_unknown {
            return Some(EnvValueOwned::Unknown);
        }

        // 5. Base env
        // 6. Process env (when base is None / inherited)
        match &self.base {
            Some(explicit_base) => explicit_base
                .get(var)
                .map(|v| EnvValueOwned::Known(v.clone())),
            None => std::env::var(var).ok().map(EnvValueOwned::Known),
        }
    }
}

/// Whether a variable's value is known or unknown (owned variant for process env lookups).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvValueOwned {
    /// The variable has a known value.
    Known(String),
    /// The variable's value cannot be determined.
    Unknown,
}

#[cfg(test)]
#[path = "env_snapshot_tests.rs"]
mod env_snapshot_tests;
