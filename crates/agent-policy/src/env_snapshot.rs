//! Environment snapshot — represents the resolved environment for a segment.
//!
//! The snapshot models three layers of env state:
//! - **Base:** either the process environment or a clean slate (`env -i`).
//! - **Overrides:** inline assignments (`FOO=bar cmd`) or `env FOO=bar` assignments.
//! - **Unsets:** explicit unset requests (`env -u VAR`).
//!
//! Resolution order: unsets > overrides > base > process env.

use std::collections::{HashMap, HashSet};

use agent_shell_parser::parse::types::Word;

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
    /// until a non-assignment word is found. These become overrides in the
    /// snapshot.
    #[must_use]
    pub fn with_assignments(mut self, words: &[Word]) -> Self {
        for word in words {
            if let Some((key, value)) = word.as_assignment() {
                // Check if value contains substitution syntax
                if value.contains("$(") || value.contains('`') {
                    self.unknown.insert(key.to_string());
                } else {
                    self.overrides.insert(key.to_string(), value.to_string());
                    self.unsets.remove(key);
                    self.unknown.remove(key);
                }
            } else {
                break;
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
mod tests {
    use super::*;

    #[test]
    fn from_process_env_reads_known_var() {
        // PATH is almost always set
        let snap = EnvSnapshot::from_process_env();
        let result = snap.get_value("PATH");
        assert!(
            matches!(result, Some(EnvValueOwned::Known(_))),
            "PATH should be known: {result:?}"
        );
    }

    #[test]
    fn from_process_env_missing_var_is_none() {
        let snap = EnvSnapshot::from_process_env();
        let result = snap.get_value("__PRODAGENT_TEST_NONEXISTENT_12345__");
        assert!(result.is_none(), "nonexistent var should be None");
    }

    #[test]
    fn override_wins_over_process_env() {
        let mut snap = EnvSnapshot::from_process_env();
        snap.set("PATH", "/custom/path");
        match snap.get_value("PATH") {
            Some(EnvValueOwned::Known(v)) => assert_eq!(v, "/custom/path"),
            other => panic!("expected Known(/custom/path), got {other:?}"),
        }
    }

    #[test]
    fn unset_wins_over_override() {
        let mut snap = EnvSnapshot::from_process_env();
        snap.set("FOO", "bar");
        snap.unset("FOO");
        assert!(snap.get_value("FOO").is_none());
    }

    #[test]
    fn unset_wins_over_process_env() {
        let mut snap = EnvSnapshot::from_process_env();
        snap.unset("PATH");
        assert!(snap.get_value("PATH").is_none());
    }

    #[test]
    fn clean_env_ignores_process_env() {
        let snap = EnvSnapshot::clean();
        assert!(snap.get_value("PATH").is_none());
    }

    #[test]
    fn clean_env_with_override() {
        let mut snap = EnvSnapshot::clean();
        snap.set("FOO", "bar");
        match snap.get_value("FOO") {
            Some(EnvValueOwned::Known(v)) => assert_eq!(v, "bar"),
            other => panic!("expected Known(bar), got {other:?}"),
        }
    }

    #[test]
    fn with_assignments_captures_leading_assignments() {
        let words: Vec<Word> = ["FOO=bar", "BAZ=qux", "cmd"]
            .iter()
            .map(|s| Word::from(*s))
            .collect();
        let snap = EnvSnapshot::from_process_env().with_assignments(&words);
        match snap.get_value("FOO") {
            Some(EnvValueOwned::Known(v)) => assert_eq!(v, "bar"),
            other => panic!("expected Known(bar), got {other:?}"),
        }
        match snap.get_value("BAZ") {
            Some(EnvValueOwned::Known(v)) => assert_eq!(v, "qux"),
            other => panic!("expected Known(qux), got {other:?}"),
        }
    }

    #[test]
    fn with_assignments_stops_at_non_assignment() {
        let words: Vec<Word> = ["FOO=bar", "cmd", "BAZ=qux"]
            .iter()
            .map(|s| Word::from(*s))
            .collect();
        let snap = EnvSnapshot::from_process_env().with_assignments(&words);
        assert!(matches!(
            snap.get_value("FOO"),
            Some(EnvValueOwned::Known(_))
        ));
        // BAZ=qux comes after "cmd", so it should NOT be captured
        assert!(
            !snap.overrides.contains_key("BAZ"),
            "assignments after command should not be captured"
        );
    }

    #[test]
    fn unknown_var_from_substitution() {
        let mut snap = EnvSnapshot::from_process_env();
        snap.set_unknown("FOO");
        assert!(matches!(
            snap.get_value("FOO"),
            Some(EnvValueOwned::Unknown)
        ));
    }

    #[test]
    fn fully_unknown_env() {
        let mut snap = EnvSnapshot::from_process_env();
        snap.mark_all_unknown();
        assert!(snap.is_fully_unknown());
        assert!(matches!(
            snap.get_value("PATH"),
            Some(EnvValueOwned::Unknown)
        ));
        assert!(matches!(
            snap.get_value("ANYTHING"),
            Some(EnvValueOwned::Unknown)
        ));
    }

    #[test]
    fn override_clears_unset() {
        let mut snap = EnvSnapshot::from_process_env();
        snap.unset("FOO");
        assert!(snap.get_value("FOO").is_none());
        snap.set("FOO", "new");
        match snap.get_value("FOO") {
            Some(EnvValueOwned::Known(v)) => assert_eq!(v, "new"),
            other => panic!("expected Known(new), got {other:?}"),
        }
    }

    #[test]
    fn layering_order_unset_override_base() {
        // Start clean with explicit base
        let mut snap = EnvSnapshot::clean();
        snap.set("A", "from-override");
        snap.set("B", "from-override");
        snap.unset("B");

        match snap.get_value("A") {
            Some(EnvValueOwned::Known(v)) => assert_eq!(v, "from-override"),
            other => panic!("expected Known, got {other:?}"),
        }
        assert!(snap.get_value("B").is_none(), "B should be unset");
    }

    #[test]
    fn reset_to_clean_clears_overrides_and_unknowns() {
        // FOO=bar env -i mycmd — FOO must NOT be visible after reset_to_clean
        let mut snap = EnvSnapshot::from_process_env();
        snap.set("FOO", "bar");
        snap.set_unknown("BAZ");
        snap.unset("QUX");
        snap.reset_to_clean();
        assert!(
            snap.get_value("FOO").is_none(),
            "FOO should not be visible after reset_to_clean"
        );
        assert!(
            snap.get_value("BAZ").is_none(),
            "BAZ (unknown) should not be visible after reset_to_clean"
        );
        assert!(
            snap.get_value("QUX").is_none(),
            "QUX (unset) should not be visible after reset_to_clean"
        );
        // PATH from process env should also be gone
        assert!(
            snap.get_value("PATH").is_none(),
            "PATH should not be visible after reset_to_clean"
        );
    }

    #[test]
    fn reset_to_clean_clears_fully_unknown() {
        let mut snap = EnvSnapshot::from_process_env();
        snap.mark_all_unknown();
        assert!(snap.is_fully_unknown());
        snap.reset_to_clean();
        assert!(
            !snap.is_fully_unknown(),
            "fully_unknown should be cleared after reset_to_clean"
        );
        assert!(
            snap.get_value("ANY").is_none(),
            "vars should be None (absent) after reset_to_clean, not Unknown"
        );
    }

    #[test]
    fn with_assignments_clears_unknown_when_known_value_set() {
        // Start with FOO in unknown, then with_assignments sets FOO=bar
        let mut snap = EnvSnapshot::from_process_env();
        snap.set_unknown("FOO");
        assert!(
            matches!(snap.get_value("FOO"), Some(EnvValueOwned::Unknown)),
            "FOO should be Unknown before assignment"
        );

        let words: Vec<Word> = ["FOO=bar", "cmd"].iter().map(|s| Word::from(*s)).collect();
        let snap = snap.with_assignments(&words);
        match snap.get_value("FOO") {
            Some(EnvValueOwned::Known(v)) => assert_eq!(v, "bar"),
            other => panic!("expected Known(bar) after with_assignments, got {other:?}"),
        }
    }

    #[test]
    fn with_assignments_substitution_marks_unknown() {
        let words: Vec<Word> = ["FOO=$(echo bar)", "cmd"]
            .iter()
            .map(|s| Word::from(*s))
            .collect();
        let snap = EnvSnapshot::from_process_env().with_assignments(&words);
        assert!(matches!(
            snap.get_value("FOO"),
            Some(EnvValueOwned::Unknown)
        ));
    }

    #[test]
    fn set_after_mark_all_unknown_is_visible() {
        // mark_all_unknown, then set FOO=bar → get_value(FOO) should return Known("bar")
        // because explicit overrides are checked before the fully_unknown guard.
        let mut snap = EnvSnapshot::from_process_env();
        snap.mark_all_unknown();
        assert!(snap.is_fully_unknown());
        snap.set("FOO", "bar");
        match snap.get_value("FOO") {
            Some(EnvValueOwned::Known(v)) => assert_eq!(v, "bar"),
            other => panic!("expected Known(bar) after set on fully-unknown env, got {other:?}"),
        }
        // Other vars should still be unknown
        assert!(
            matches!(snap.get_value("OTHER"), Some(EnvValueOwned::Unknown)),
            "unset vars should still be Unknown in fully-unknown env"
        );
    }
}
