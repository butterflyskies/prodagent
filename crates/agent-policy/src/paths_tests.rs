//! Unit tests for [`AffectedPaths`].

use camino::Utf8PathBuf;

use super::AffectedPaths;

fn p(s: &str) -> Utf8PathBuf {
    // Go through AffectedPaths::new to get normalised form for assertions.
    Utf8PathBuf::from(s)
}

// ── Trailing-slash normalisation (issue #65) ────────────────────────────────

#[test]
fn new_normalises_trailing_slash() {
    let paths = AffectedPaths::new(vec![p("foo/"), p("bar/baz/"), p("qux")]);
    assert_eq!(
        paths.as_slice(),
        &[p("foo"), p("bar/baz"), p("qux")],
        "trailing separators should be stripped on construction"
    );
}

#[test]
fn union_with_dedupes_trailing_slash_variants() {
    let mut a = AffectedPaths::new(vec![p("_/")]);
    let b = AffectedPaths::new(vec![p("_")]);
    a.union_with(&b);
    assert_eq!(
        a.as_slice(),
        &[p("_")],
        "\"_/\" and \"_\" must collapse to a single entry"
    );
}

#[test]
fn union_with_dedupes_trailing_slash_reversed() {
    let mut a = AffectedPaths::new(vec![p("_")]);
    let b = AffectedPaths::new(vec![p("_/")]);
    a.union_with(&b);
    assert_eq!(
        a.as_slice(),
        &[p("_")],
        "order of slash/no-slash should not matter"
    );
}

#[test]
fn normalisation_preserves_root_and_dot() {
    let paths = AffectedPaths::new(vec![p("/"), p("."), p("./foo")]);
    // Root stays "/", dot stays ".", "./foo" stays "./foo".
    assert_eq!(paths.as_slice(), &[p("/"), p("."), p("./foo")]);
}

#[test]
fn from_iter_normalises() {
    let paths: AffectedPaths = vec![p("a/"), p("b")].into_iter().collect();
    assert_eq!(paths.as_slice(), &[p("a"), p("b")]);
}

#[test]
fn new_preserves_order_and_duplicates() {
    let paths = AffectedPaths::new(vec![p("a"), p("b"), p("a")]);
    assert_eq!(paths.as_slice(), &[p("a"), p("b"), p("a")]);
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
    let mut a = AffectedPaths::new(vec![p("x"), p("y")]);
    let b = AffectedPaths::new(vec![p("y"), p("z"), p("x")]);
    a.union_with(&b);
    // y and x already present; only z is appended, at the end.
    assert_eq!(a.as_slice(), &[p("x"), p("y"), p("z")]);
}

#[test]
fn union_with_empty_is_noop() {
    let mut a = AffectedPaths::new(vec![p("/tmp/file")]);
    a.union_with(&AffectedPaths::empty());
    assert_eq!(a.as_slice(), &[p("/tmp/file")]);
}

#[test]
fn from_vec_matches_new() {
    let v = vec![p("one"), p("two")];
    let from: AffectedPaths = v.clone().into();
    assert_eq!(from, AffectedPaths::new(v));
}

#[test]
fn iter_yields_all_paths() {
    let paths = AffectedPaths::new(vec![p("/a"), p("/b")]);
    let collected: Vec<&Utf8PathBuf> = paths.iter().collect();
    assert_eq!(collected, vec![&p("/a"), &p("/b")]);
    // &AffectedPaths IntoIterator agrees.
    let via_into: Vec<&Utf8PathBuf> = (&paths).into_iter().collect();
    assert_eq!(via_into, collected);
}
