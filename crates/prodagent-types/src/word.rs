use std::borrow::Borrow;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

// ---------------------------------------------------------------------------
// WordKind — structural classification from tree-sitter AST
// ---------------------------------------------------------------------------

/// Structural classification of a shell word based on tree-sitter AST node
/// types.
///
/// When words are extracted from the tree-sitter parse tree, the node type
/// (and its children) determines the kind. This lets downstream code check
/// structural metadata instead of byte-scanning for `$`, `$(`, backticks,
/// etc.
///
/// Words constructed from raw strings (e.g. `Word::from("...")`) default to
/// [`Unclassified`](Self::Unclassified), which falls back to byte scanning
/// for classification methods like [`as_classified_assignment`](Word::as_classified_assignment).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum WordKind {
    /// Not yet classified — from string construction or shlex fallback.
    /// Falls back to byte scanning for classification.
    #[default]
    Unclassified,
    /// Plain literal — classified by tree-sitter as having no expansions.
    Literal,
    /// Contains a command substitution (`$(cmd)` or `` `cmd` ``).
    CommandSubstitution,
    /// Contains a variable expansion (`$VAR` or `${VAR}`).
    VariableExpansion,
    /// Contains an arithmetic expansion (`$((expr))`).
    ArithmeticExpansion,
    /// Contains multiple expansion types (e.g. `$(cmd)-$VAR`).
    /// Treated conservatively — command substitution semantics win
    /// (there IS an inner command to evaluate).
    Dynamic,
}

impl WordKind {
    /// Whether this kind represents an expansion that makes the runtime value
    /// unknowable at parse time.
    pub fn is_expansion(self) -> bool {
        matches!(
            self,
            WordKind::CommandSubstitution
                | WordKind::VariableExpansion
                | WordKind::ArithmeticExpansion
                | WordKind::Dynamic
        )
    }

    /// Whether this kind contains a command substitution whose inner command
    /// can be recursively evaluated through policy.
    pub fn has_command_substitution(self) -> bool {
        matches!(self, WordKind::CommandSubstitution | WordKind::Dynamic)
    }
}

// ---------------------------------------------------------------------------
// Word newtype
// ---------------------------------------------------------------------------

/// A single shell word token.
///
/// Wraps a `String` with domain-specific helpers for shell analysis (flag
/// detection, env assignment parsing, basename extraction) and optional
/// structural classification from the tree-sitter AST.
///
/// Derefs to `str` for seamless use wherever a string slice is expected.
///
/// Note: `Word` carries raw shell text extracted from the parse tree. It is
/// not sanitized or validated — consumers must not treat word equality as
/// proof of command identity without considering the full resolution pipeline.
///
/// ## Equality and hashing
///
/// Equality and hashing are based on text content only — the [`WordKind`]
/// metadata does not participate. This preserves backward compatibility and
/// ensures words compare correctly regardless of how they were constructed.
#[derive(Clone)]
pub struct Word {
    text: String,
    kind: WordKind,
}

impl Word {
    /// Create a word with explicit structural classification.
    ///
    /// Used by the tree-sitter word extraction path in `walk.rs`.
    pub fn with_kind(text: impl Into<String>, kind: WordKind) -> Self {
        Word {
            text: text.into(),
            kind,
        }
    }

    /// Create a word classified as a literal (no expansions).
    ///
    /// Use when the tree-sitter node type guarantees no expansions
    /// (e.g. bracket delimiters, operators, raw strings).
    pub fn literal(text: impl Into<String>) -> Self {
        Word {
            text: text.into(),
            kind: WordKind::Literal,
        }
    }

    /// The word's structural classification from the tree-sitter AST.
    ///
    /// Returns [`WordKind::Unclassified`] for words constructed from raw
    /// strings (e.g. via `Word::from`).
    pub fn kind(&self) -> WordKind {
        self.kind
    }

    /// Whether this word contains a shell expansion that makes its runtime
    /// value unknowable at parse time.
    ///
    /// For tree-sitter-classified words, uses structural metadata. For
    /// unclassified words (from string construction), falls back to
    /// checking for `$` or backtick characters.
    pub fn is_expansion(&self) -> bool {
        match self.kind {
            WordKind::Unclassified => self.text.contains('$') || self.text.contains('`'),
            WordKind::Literal => false,
            _ => true,
        }
    }

    /// Returns `true` if this word starts with `-`.
    pub fn is_flag(&self) -> bool {
        self.text.starts_with('-')
    }

    /// Returns `true` if this word is a valid `KEY=VALUE` environment assignment.
    pub fn is_assignment(&self) -> bool {
        is_env_assignment(&self.text)
    }

    /// Split at the first `=` and return `(key, value)` if the key is a valid
    /// environment variable name.
    pub fn as_assignment(&self) -> Option<(&str, &str)> {
        let eq_pos = self.text.find('=')?;
        let key = &self.text[..eq_pos];
        if is_valid_env_key(key) {
            Some((key, &self.text[eq_pos + 1..]))
        } else {
            None
        }
    }

    /// Like [`as_assignment`](Self::as_assignment), but classifies the value as
    /// [`AssignmentValue::Static`], [`AssignmentValue::CommandSubstitution`], or
    /// [`AssignmentValue::VariableExpansion`] depending on the word's structural
    /// metadata from tree-sitter.
    ///
    /// When the word has tree-sitter classification ([`WordKind`] is not
    /// `Unclassified`), the structural metadata is used directly — no byte
    /// scanning. For unclassified words (string-constructed), falls back to
    /// [`AssignmentValue::classify`] which scans the value text.
    ///
    /// Carrying the classification in the return type means the policy layer
    /// cannot accidentally trust a value it has no way of seeing.
    pub fn as_classified_assignment(&self) -> Option<(&str, AssignmentValue<'_>)> {
        let (key, value) = self.as_assignment()?;
        let av = match self.kind {
            WordKind::CommandSubstitution | WordKind::Dynamic => {
                AssignmentValue::CommandSubstitution
            }
            WordKind::VariableExpansion | WordKind::ArithmeticExpansion => {
                AssignmentValue::VariableExpansion
            }
            WordKind::Literal => AssignmentValue::Static(value),
            WordKind::Unclassified => AssignmentValue::classify(value),
        };
        Some((key, av))
    }

    /// Strip the path prefix, e.g. `/usr/bin/ls` -> `ls`.
    pub fn basename(&self) -> &str {
        match self.text.rsplit_once('/') {
            Some((_, name)) if !name.is_empty() => name,
            _ => &self.text,
        }
    }

    /// Explicit accessor for the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Consume and return the inner `String`.
    pub fn into_inner(self) -> String {
        self.text
    }
}

// --- PartialEq / Eq / Hash (text-only, ignoring kind) ---

impl PartialEq for Word {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}

impl Eq for Word {}

impl Hash for Word {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.text.hash(state);
    }
}

// --- Serde (transparent — serializes as bare string, kind is transient) ---

impl serde::Serialize for Word {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.text.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Word {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Ok(Word {
            text,
            kind: WordKind::Unclassified,
        })
    }
}

// --- Deref / AsRef / Borrow ---

impl Deref for Word {
    type Target = str;

    fn deref(&self) -> &str {
        &self.text
    }
}

impl AsRef<str> for Word {
    fn as_ref(&self) -> &str {
        &self.text
    }
}

impl Borrow<str> for Word {
    fn borrow(&self) -> &str {
        &self.text
    }
}

// --- Display / Debug ---

impl fmt::Display for Word {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl fmt::Debug for Word {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.text, f)
    }
}

// --- From conversions (default to Unclassified for backward compat) ---

impl From<String> for Word {
    fn from(s: String) -> Self {
        Word {
            text: s,
            kind: WordKind::Unclassified,
        }
    }
}

impl From<&str> for Word {
    fn from(s: &str) -> Self {
        Word {
            text: s.to_string(),
            kind: WordKind::Unclassified,
        }
    }
}

// --- PartialEq with str types ---

impl PartialEq<str> for Word {
    fn eq(&self, other: &str) -> bool {
        self.text == other
    }
}

impl PartialEq<&str> for Word {
    fn eq(&self, other: &&str) -> bool {
        self.text == *other
    }
}

impl PartialEq<Word> for str {
    fn eq(&self, other: &Word) -> bool {
        self == other.text
    }
}

impl PartialEq<Word> for &str {
    fn eq(&self, other: &Word) -> bool {
        *self == other.text
    }
}

impl PartialEq<String> for Word {
    fn eq(&self, other: &String) -> bool {
        self.text == *other
    }
}

impl PartialEq<Word> for String {
    fn eq(&self, other: &Word) -> bool {
        *self == other.text
    }
}

// ---------------------------------------------------------------------------
// Assignment value classification
// ---------------------------------------------------------------------------

/// The value side of a shell env assignment (`KEY=VALUE`), classified by
/// whether it can be resolved statically and whether it contains an inner
/// command that can be recursively evaluated through policy.
///
/// The policy engine uses this to decide how to populate the environment
/// snapshot:
///
/// - [`Static`](Self::Static) — known literal, used directly.
/// - [`CommandSubstitution`](Self::CommandSubstitution) — contains `$(cmd)` or
///   backtick-quoted command. The inner command can be recursively evaluated
///   through policy; if allowed, the assignment is "safe" (set, value opaque).
/// - [`VariableExpansion`](Self::VariableExpansion) — contains `$VAR` or
///   `${VAR}`. No inner command to evaluate; the value is truly unknowable
///   at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentValue<'a> {
    /// A literal value, fully known from the command text (e.g. `FOO=bar`).
    Static(&'a str),
    /// A value derived from a command substitution (`$(cmd)` or `` `cmd` ``).
    /// The inner command can be recursively evaluated through policy.
    CommandSubstitution,
    /// A value derived from a variable expansion (`$VAR`, `${VAR}`).
    /// No inner command exists; the runtime value is truly unknowable.
    VariableExpansion,
}

impl<'a> AssignmentValue<'a> {
    /// Classify a raw assignment value by byte scanning.
    ///
    /// This is the **fallback** path for words without tree-sitter structural
    /// metadata (i.e. [`WordKind::Unclassified`]). When a word carries
    /// tree-sitter classification, [`Word::as_classified_assignment`] uses
    /// the structural metadata directly and does not call this method.
    ///
    /// A value containing `$(` or a backtick is classified as
    /// `CommandSubstitution` — these have inner commands that can be
    /// recursively evaluated through policy.
    ///
    /// A value containing `$` (but no `$(` or backtick) is classified as
    /// `VariableExpansion` — these reference shell variables whose values
    /// are unknowable at parse time.
    ///
    /// Everything else is `Static`.
    pub fn classify(value: &'a str) -> Self {
        // Backtick-quoted commands are always command substitutions
        if value.contains('`') {
            return AssignmentValue::CommandSubstitution;
        }
        // Check if there's a $( that isn't $(( (arithmetic expansion).
        // A value like FOO=$(cmd)-$((1+2)) has both — command substitution wins.
        if value.contains("$(") {
            let bytes = value.as_bytes();
            let mut i = 0;
            while i + 1 < bytes.len() {
                if bytes[i] == b'$' && bytes[i + 1] == b'(' {
                    if i + 2 >= bytes.len() || bytes[i + 2] != b'(' {
                        // Found a bare $( — this is a command substitution
                        return AssignmentValue::CommandSubstitution;
                    }
                    i += 3; // skip $((
                } else {
                    i += 1;
                }
            }
            // All $( were $(( — arithmetic only, treat as variable expansion
            // (conservative: value is unknowable but no command to evaluate)
            return AssignmentValue::VariableExpansion;
        }
        if value.contains('$') {
            AssignmentValue::VariableExpansion
        } else {
            AssignmentValue::Static(value)
        }
    }

    /// The literal value if [`Static`](Self::Static), otherwise `None`.
    pub fn static_value(self) -> Option<&'a str> {
        match self {
            AssignmentValue::Static(v) => Some(v),
            AssignmentValue::CommandSubstitution | AssignmentValue::VariableExpansion => None,
        }
    }

    /// Whether this value is dynamic (not a static literal).
    pub fn is_dynamic(self) -> bool {
        !matches!(self, AssignmentValue::Static(_))
    }

    /// Whether this value contains a command substitution that can be
    /// recursively evaluated through policy.
    pub fn is_command_substitution(self) -> bool {
        matches!(self, AssignmentValue::CommandSubstitution)
    }
}

// --- Env assignment helpers (used by Word and by the parser's tokenizer) ---

/// Check if a token is a valid `KEY=VALUE` environment assignment.
pub fn is_env_assignment(token: &str) -> bool {
    match token.find('=') {
        Some(eq_pos) => is_valid_env_key(&token[..eq_pos]),
        None => false,
    }
}

/// Check if a string is a valid environment variable key.
pub fn is_valid_env_key(key: &str) -> bool {
    !key.is_empty()
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && key
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn word_deref_to_str() {
        let w = Word::from("hello");
        let s: &str = &w;
        assert_eq!(s, "hello");
    }

    #[rstest]
    #[case::short_flag("-v", true)]
    #[case::long_flag("--verbose", true)]
    #[case::not_flag("hello", false)]
    fn word_is_flag(#[case] input: &str, #[case] expected: bool) {
        assert_eq!(Word::from(input).is_flag(), expected);
    }

    #[test]
    fn word_assignment() {
        let w = Word::from("FOO=bar");
        assert!(w.is_assignment());
        assert_eq!(w.as_assignment(), Some(("FOO", "bar")));
    }

    #[test]
    fn word_not_assignment() {
        let w = Word::from("git");
        assert!(!w.is_assignment());
        assert_eq!(w.as_assignment(), None);
    }

    #[rstest]
    #[case::absolute_path("/usr/bin/ls", "ls")]
    #[case::bare_name("ls", "ls")]
    fn word_basename(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(Word::from(input).basename(), expected);
    }

    #[test]
    fn word_equality_with_str() {
        let w = Word::from("hello");
        assert_eq!(w, "hello");
        assert_eq!("hello", w);
    }

    #[test]
    fn word_equality_ignores_kind() {
        let a = Word::from("hello");
        let b = Word::literal("hello");
        let c = Word::with_kind("hello", WordKind::CommandSubstitution);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[rstest]
    #[case::valid_simple("FOO=bar", true)]
    #[case::valid_underscore("_A=1", true)]
    #[case::invalid_digit_start("123=bad", false)]
    #[case::invalid_no_equals("no_equals", false)]
    fn env_assignment_validation(#[case] input: &str, #[case] expected: bool) {
        assert_eq!(is_env_assignment(input), expected);
    }

    // ── WordKind ─────────────────────────────────────────────────────────

    #[test]
    fn word_kind_default_is_unclassified() {
        assert_eq!(Word::from("x").kind(), WordKind::Unclassified);
    }

    #[test]
    fn word_kind_literal() {
        assert_eq!(Word::literal("x").kind(), WordKind::Literal);
    }

    #[test]
    fn word_kind_with_kind() {
        let w = Word::with_kind("$(cmd)", WordKind::CommandSubstitution);
        assert_eq!(w.kind(), WordKind::CommandSubstitution);
    }

    // ── is_expansion: classified words use structural metadata ────────────

    #[rstest]
    #[case::literal_not_expansion("hello", WordKind::Literal, false)]
    #[case::command_substitution("$(cmd)", WordKind::CommandSubstitution, true)]
    #[case::variable_expansion("$VAR", WordKind::VariableExpansion, true)]
    #[case::arithmetic_expansion("$((1+2))", WordKind::ArithmeticExpansion, true)]
    #[case::dynamic("$(cmd)-$VAR", WordKind::Dynamic, true)]
    fn is_expansion_classified(#[case] text: &str, #[case] kind: WordKind, #[case] expected: bool) {
        assert_eq!(Word::with_kind(text, kind).is_expansion(), expected);
    }

    // ── is_expansion: unclassified words fall back to byte scanning ──────

    #[rstest]
    #[case::dollar_var("$VAR", true)]
    #[case::dollar_paren("$(cmd)", true)]
    #[case::backtick("`cmd`", true)]
    #[case::plain("hello", false)]
    fn is_expansion_unclassified(#[case] text: &str, #[case] expected: bool) {
        assert_eq!(Word::from(text).is_expansion(), expected);
    }

    // ── AssignmentValue::classify ─────────────────────────────────────────

    #[rstest]
    #[case::bare_literal("bar", AssignmentValue::Static("bar"))]
    #[case::empty("", AssignmentValue::Static(""))]
    #[case::path_like("a/b-c.d", AssignmentValue::Static("a/b-c.d"))]
    #[case::dollar_paren("$(echo hi)", AssignmentValue::CommandSubstitution)]
    #[case::backtick("`echo hi`", AssignmentValue::CommandSubstitution)]
    #[case::dollar_paren_prefix("prefix-$(date)", AssignmentValue::CommandSubstitution)]
    #[case::dollar_var("$VAR", AssignmentValue::VariableExpansion)]
    #[case::dollar_brace("${VAR}", AssignmentValue::VariableExpansion)]
    #[case::dollar_brace_default("${VAR:-default}", AssignmentValue::VariableExpansion)]
    #[case::cmd_sub_priority_over_var("$VAR-$(cmd)", AssignmentValue::CommandSubstitution)]
    #[case::arithmetic("$((1+2))", AssignmentValue::VariableExpansion)]
    #[case::arithmetic_prefix("prefix-$((x+1))", AssignmentValue::VariableExpansion)]
    #[case::mixed_cmd_sub_and_arithmetic("$(cmd)-$((1+2))", AssignmentValue::CommandSubstitution)]
    // Pins conservative (fail-closed) behavior — $((cmd) && evil) is currently
    // VariableExpansion. Update if classify() is improved to parse this as
    // CommandSubstitution.
    #[case::adversarial_double_paren("$((cmd) && evil)", AssignmentValue::VariableExpansion)]
    fn assignment_value_classify(#[case] input: &str, #[case] expected: AssignmentValue<'_>) {
        assert_eq!(AssignmentValue::classify(input), expected);
    }

    // ── as_classified_assignment: unclassified (byte scanning fallback) ──

    #[rstest]
    #[case::static_value("FOO=bar", Some(("FOO", AssignmentValue::Static("bar"))))]
    #[case::variable_expansion("FOO=$VAR", Some(("FOO", AssignmentValue::VariableExpansion)))]
    #[case::command_sub("FOO=$(id -u)", Some(("FOO", AssignmentValue::CommandSubstitution)))]
    #[case::backtick_sub("FOO=`id -u`", Some(("FOO", AssignmentValue::CommandSubstitution)))]
    #[case::not_assignment("git", None)]
    fn classified_assignment_unclassified(
        #[case] input: &str,
        #[case] expected: Option<(&str, AssignmentValue<'_>)>,
    ) {
        assert_eq!(Word::from(input).as_classified_assignment(), expected);
    }

    // ── as_classified_assignment: tree-sitter-classified words ────────────

    #[rstest]
    #[case::literal("FOO=bar", WordKind::Literal, "FOO", AssignmentValue::Static("bar"))]
    #[case::command_sub(
        "FOO=$(cmd)",
        WordKind::CommandSubstitution,
        "FOO",
        AssignmentValue::CommandSubstitution
    )]
    #[case::variable_expansion(
        "FOO=$VAR",
        WordKind::VariableExpansion,
        "FOO",
        AssignmentValue::VariableExpansion
    )]
    #[case::arithmetic(
        "FOO=$((1+2))",
        WordKind::ArithmeticExpansion,
        "FOO",
        AssignmentValue::VariableExpansion
    )]
    #[case::dynamic(
        "FOO=$(cmd)-$VAR",
        WordKind::Dynamic,
        "FOO",
        AssignmentValue::CommandSubstitution
    )]
    fn classified_assignment_with_kind(
        #[case] text: &str,
        #[case] kind: WordKind,
        #[case] expected_key: &str,
        #[case] expected_value: AssignmentValue<'_>,
    ) {
        assert_eq!(
            Word::with_kind(text, kind).as_classified_assignment(),
            Some((expected_key, expected_value))
        );
    }

    #[test]
    fn assignment_value_accessors() {
        assert_eq!(AssignmentValue::Static("x").static_value(), Some("x"));
        assert_eq!(AssignmentValue::CommandSubstitution.static_value(), None);
        assert_eq!(AssignmentValue::VariableExpansion.static_value(), None);

        assert!(AssignmentValue::CommandSubstitution.is_dynamic());
        assert!(AssignmentValue::VariableExpansion.is_dynamic());
        assert!(!AssignmentValue::Static("x").is_dynamic());

        assert!(AssignmentValue::CommandSubstitution.is_command_substitution());
        assert!(!AssignmentValue::VariableExpansion.is_command_substitution());
        assert!(!AssignmentValue::Static("x").is_command_substitution());
    }

    // ── Serde round-trip ─────────────────────────────────────────────────

    #[test]
    fn serde_transparent_roundtrip() {
        let w = Word::with_kind("hello", WordKind::CommandSubstitution);
        let json = serde_json::to_string(&w).unwrap();
        assert_eq!(json, "\"hello\"");
        let w2: Word = serde_json::from_str(&json).unwrap();
        assert_eq!(w2, "hello");
        // Deserialized word is Unclassified (kind is transient)
        assert_eq!(w2.kind(), WordKind::Unclassified);
    }
}
