//! Unit tests for [`AffectedPaths`].

use super::AffectedPaths;
use agent_shell_parser::parse::Word;

fn w(s: &str) -> Word {
    Word::from(s)
}

#[test]
fn new_preserves_order_and_duplicates() {
    let paths = AffectedPaths::new(vec![w("a"), w("b"), w("a")]);
    assert_eq!(paths.as_slice(), &[w("a"), w("b"), w("a")]);
    assert_eq!(paths.len(), 3);
    assert!(!paths.is_empty());
}

#[test]
fn empty_is_empty() {
    let paths = AffectedPaths::empty();
    assert!(paths.is_empty());
    assert_eq!(paths.len(), 0);
    assert_eq!(AffectedPaths::default(), AffectedPaths::empty());
}

#[test]
fn union_with_dedupes_preserving_first_seen_order() {
    let mut a = AffectedPaths::new(vec![w("x"), w("y")]);
    let b = AffectedPaths::new(vec![w("y"), w("z"), w("x")]);
    a.union_with(&b);
    // y and x already present; only z is appended, at the end.
    assert_eq!(a.as_slice(), &[w("x"), w("y"), w("z")]);
}

#[test]
fn union_with_empty_is_noop() {
    let mut a = AffectedPaths::new(vec![w("p")]);
    a.union_with(&AffectedPaths::empty());
    assert_eq!(a.as_slice(), &[w("p")]);
}

#[test]
fn from_vec_matches_new() {
    let v = vec![w("one"), w("two")];
    let from: AffectedPaths = v.clone().into();
    assert_eq!(from, AffectedPaths::new(v));
}

#[test]
fn iter_yields_all_paths() {
    let paths = AffectedPaths::new(vec![w("a"), w("b")]);
    let collected: Vec<&Word> = paths.iter().collect();
    assert_eq!(collected, vec![&w("a"), &w("b")]);
    // &AffectedPaths IntoIterator agrees.
    let via_into: Vec<&Word> = (&paths).into_iter().collect();
    assert_eq!(via_into, collected);
}
