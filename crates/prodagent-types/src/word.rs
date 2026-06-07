use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;

// ---------------------------------------------------------------------------
// Word newtype
// ---------------------------------------------------------------------------

/// A single shell word token.
///
/// Wraps a `String` with domain-specific helpers for shell analysis (flag
/// detection, env assignment parsing, basename extraction). Derefs to `str`
/// for seamless use wherever a string slice is expected.
///
/// Note: `Word` carries raw shell text extracted from the parse tree. It is
/// not sanitized or validated — consumers must not treat word equality as
/// proof of command identity without considering the full resolution pipeline.
#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Word(String);

impl Word {
    /// Returns `true` if this word starts with `-`.
    pub fn is_flag(&self) -> bool {
        self.0.starts_with('-')
    }

    /// Returns `true` if this word is a valid `KEY=VALUE` environment assignment.
    pub fn is_assignment(&self) -> bool {
        is_env_assignment(&self.0)
    }

    /// Split at the first `=` and return `(key, value)` if the key is a valid
    /// environment variable name.
    pub fn as_assignment(&self) -> Option<(&str, &str)> {
        let eq_pos = self.0.find('=')?;
        let key = &self.0[..eq_pos];
        if is_valid_env_key(key) {
            Some((key, &self.0[eq_pos + 1..]))
        } else {
            None
        }
    }

    /// Strip the path prefix, e.g. `/usr/bin/ls` -> `ls`.
    pub fn basename(&self) -> &str {
        match self.0.rsplit_once('/') {
            Some((_, name)) if !name.is_empty() => name,
            _ => &self.0,
        }
    }

    /// Explicit accessor for the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner `String`.
    pub fn into_inner(self) -> String {
        self.0
    }
}

// --- Deref / AsRef / Borrow ---

impl Deref for Word {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Word {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for Word {
    fn borrow(&self) -> &str {
        &self.0
    }
}

// --- Display / Debug ---

impl fmt::Display for Word {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Word {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

// --- From conversions ---

impl From<String> for Word {
    fn from(s: String) -> Self {
        Word(s)
    }
}

impl From<&str> for Word {
    fn from(s: &str) -> Self {
        Word(s.to_string())
    }
}

// --- PartialEq with str types ---

impl PartialEq<str> for Word {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Word {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Word> for str {
    fn eq(&self, other: &Word) -> bool {
        self == other.0
    }
}

impl PartialEq<Word> for &str {
    fn eq(&self, other: &Word) -> bool {
        *self == other.0
    }
}

impl PartialEq<String> for Word {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Word> for String {
    fn eq(&self, other: &Word) -> bool {
        *self == other.0
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

    #[test]
    fn word_deref_to_str() {
        let w = Word::from("hello");
        let s: &str = &w;
        assert_eq!(s, "hello");
    }

    #[test]
    fn word_is_flag() {
        assert!(Word::from("-v").is_flag());
        assert!(Word::from("--verbose").is_flag());
        assert!(!Word::from("hello").is_flag());
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

    #[test]
    fn word_basename() {
        assert_eq!(Word::from("/usr/bin/ls").basename(), "ls");
        assert_eq!(Word::from("ls").basename(), "ls");
    }

    #[test]
    fn word_equality_with_str() {
        let w = Word::from("hello");
        assert_eq!(w, "hello");
        assert_eq!("hello", w);
    }

    #[test]
    fn env_assignment_checks() {
        assert!(is_env_assignment("FOO=bar"));
        assert!(is_env_assignment("_A=1"));
        assert!(!is_env_assignment("123=bad"));
        assert!(!is_env_assignment("no_equals"));
    }
}
