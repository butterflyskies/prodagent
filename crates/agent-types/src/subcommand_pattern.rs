use std::borrow::Borrow;
use std::fmt;

/// Maximum number of words that can form a subcommand pattern.
///
/// Patterns with more words than this will never be matched by `longest_match`.
/// Construction validates that patterns respect this limit.
pub const MAX_SUBCOMMAND_DEPTH: usize = 4;

/// A validated subcommand pattern for HashMap key use.
///
/// Wraps a `String` that represents a space-separated subcommand pattern
/// (e.g. `"pr create"`, `"repo view"`). Validates on construction that:
/// - The pattern is non-empty
/// - It does not exceed [`MAX_SUBCOMMAND_DEPTH`] words
///
/// Implements `Borrow<str>` for zero-allocation HashMap lookups —
/// callers can query a `HashMap<SubcommandPattern, V>` with `&str`.
#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SubcommandPattern(String);

/// Error returned when constructing a [`SubcommandPattern`] with an invalid value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubcommandPatternError {
    /// The pattern is empty.
    Empty,
    /// The pattern exceeds [`MAX_SUBCOMMAND_DEPTH`] words.
    TooDeep { pattern: String, depth: usize },
}

impl fmt::Display for SubcommandPatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "subcommand pattern is empty"),
            Self::TooDeep { pattern, depth } => write!(
                f,
                "subcommand pattern '{pattern}' has {depth} words, \
                 exceeding MAX_SUBCOMMAND_DEPTH ({MAX_SUBCOMMAND_DEPTH})"
            ),
        }
    }
}

impl std::error::Error for SubcommandPatternError {}

impl SubcommandPattern {
    /// Create a new validated subcommand pattern.
    ///
    /// # Errors
    ///
    /// Returns [`SubcommandPatternError::Empty`] if the pattern is empty or
    /// whitespace-only, or [`SubcommandPatternError::TooDeep`] if it exceeds
    /// [`MAX_SUBCOMMAND_DEPTH`] words.
    pub fn new(pattern: impl Into<String>) -> Result<Self, SubcommandPatternError> {
        let pattern = pattern.into();
        let depth = pattern.split_whitespace().count();
        if depth == 0 {
            return Err(SubcommandPatternError::Empty);
        }
        if depth > MAX_SUBCOMMAND_DEPTH {
            return Err(SubcommandPatternError::TooDeep { pattern, depth });
        }
        let normalized = pattern.split_whitespace().collect::<Vec<_>>().join(" ");
        Ok(SubcommandPattern(normalized))
    }

    /// Create a subcommand pattern without validation.
    ///
    /// # Safety (logical)
    ///
    /// The caller must ensure the pattern is non-empty and does not exceed
    /// [`MAX_SUBCOMMAND_DEPTH`] words. Debug builds will assert this.
    /// Whitespace is normalized (leading/trailing trimmed, internal runs
    /// collapsed to single spaces) to match `new()` behavior.
    pub fn new_unchecked(pattern: impl Into<String>) -> Self {
        let pattern: String = pattern.into();
        let pattern = pattern.split_whitespace().collect::<Vec<_>>().join(" ");
        debug_assert!(
            !pattern.is_empty(),
            "SubcommandPattern::new_unchecked called with empty pattern"
        );
        debug_assert!(
            pattern.split_whitespace().count() <= MAX_SUBCOMMAND_DEPTH,
            "SubcommandPattern::new_unchecked: pattern '{}' exceeds MAX_SUBCOMMAND_DEPTH ({})",
            pattern,
            MAX_SUBCOMMAND_DEPTH,
        );
        SubcommandPattern(pattern)
    }

    /// Return the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner `String`.
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Number of words in this pattern.
    pub fn depth(&self) -> usize {
        self.0.split_whitespace().count()
    }
}

// --- TryFrom<String> for serde ---

impl TryFrom<String> for SubcommandPattern {
    type Error = SubcommandPatternError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        SubcommandPattern::new(s)
    }
}

impl From<SubcommandPattern> for String {
    fn from(p: SubcommandPattern) -> String {
        p.0
    }
}

// --- Borrow<str> for zero-allocation HashMap lookups ---

impl Borrow<str> for SubcommandPattern {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SubcommandPattern {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for SubcommandPattern {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

// --- Display / Debug ---

impl fmt::Display for SubcommandPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for SubcommandPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

// --- PartialEq with str types ---

impl PartialEq<str> for SubcommandPattern {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for SubcommandPattern {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arb_word() -> impl Strategy<Value = String> {
        "[a-z]{1,6}"
    }

    /// Generate a pattern string with 1..=MAX_SUBCOMMAND_DEPTH words.
    fn arb_valid_pattern() -> impl Strategy<Value = String> {
        prop::collection::vec(arb_word(), 1..=MAX_SUBCOMMAND_DEPTH)
            .prop_map(|words| words.join(" "))
    }

    proptest! {
        /// depth() matches split_whitespace().count() for any valid pattern.
        #[test]
        fn depth_matches_word_count(s in arb_valid_pattern()) {
            let p = SubcommandPattern::new(s.clone()).unwrap();
            prop_assert_eq!(
                p.depth(),
                s.split_whitespace().count(),
                "depth mismatch for pattern '{}'", s
            );
        }

        /// serde round-trip preserves equality.
        #[test]
        fn serde_round_trip_preserves_equality(s in arb_valid_pattern()) {
            let p = SubcommandPattern::new(s).unwrap();
            let json = serde_json::to_string(&p).unwrap();
            let parsed: SubcommandPattern = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(p, parsed);
        }

        /// Whitespace normalization: leading/trailing/extra internal whitespace
        /// is collapsed so that depth matches logical word count.
        #[test]
        fn whitespace_normalized_on_construction(
            words in prop::collection::vec(arb_word(), 1..=MAX_SUBCOMMAND_DEPTH),
        ) {
            // Build a pattern with irregular whitespace
            let messy = format!("  {}  ", words.join("   "));
            let p = SubcommandPattern::new(messy).unwrap();
            let expected = words.join(" ");
            prop_assert_eq!(
                p.as_str(), expected.as_str(),
                "pattern should be normalized"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_single_word() {
        let p = SubcommandPattern::new("status").unwrap();
        assert_eq!(p.as_str(), "status");
        assert_eq!(p.depth(), 1);
    }

    #[test]
    fn valid_multi_word() {
        let p = SubcommandPattern::new("pr create").unwrap();
        assert_eq!(p.as_str(), "pr create");
        assert_eq!(p.depth(), 2);
    }

    #[test]
    fn valid_max_depth() {
        let p = SubcommandPattern::new("a b c d").unwrap();
        assert_eq!(p.depth(), 4);
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            SubcommandPattern::new(""),
            Err(SubcommandPatternError::Empty)
        ));
    }

    #[test]
    fn rejects_too_deep() {
        let err = SubcommandPattern::new("a b c d e").unwrap_err();
        assert!(matches!(
            err,
            SubcommandPatternError::TooDeep { depth: 5, .. }
        ));
    }

    #[test]
    fn borrow_str_for_hashmap_lookup() {
        use std::collections::HashMap;
        let mut map: HashMap<SubcommandPattern, i32> = HashMap::new();
        map.insert(SubcommandPattern::new("status").unwrap(), 42);
        // Zero-allocation lookup with &str
        assert_eq!(map.get("status"), Some(&42));
    }

    #[test]
    fn serde_round_trip() {
        let p = SubcommandPattern::new("pr create").unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let parsed: SubcommandPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(p, parsed);
    }

    #[test]
    fn serde_rejects_invalid() {
        let result: Result<SubcommandPattern, _> = serde_json::from_str("\"a b c d e\"");
        assert!(result.is_err());
    }
}
