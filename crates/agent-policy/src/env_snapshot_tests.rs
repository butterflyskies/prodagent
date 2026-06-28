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
fn with_assignments_command_substitution_is_unknown() {
    let words = [Word::from("FOO=$(id -u)"), Word::from("cmd")];
    let snap = EnvSnapshot::clean().with_assignments(&words);
    assert_eq!(snap.get_value("FOO"), Some(EnvValueOwned::Unknown));
}

#[test]
fn with_assignments_backtick_is_unknown() {
    let words = [Word::from("FOO=`id -u`"), Word::from("cmd")];
    let snap = EnvSnapshot::clean().with_assignments(&words);
    assert_eq!(snap.get_value("FOO"), Some(EnvValueOwned::Unknown));
}

#[test]
fn with_assignments_variable_expansion_is_unknown() {
    // The gap the old `.contains("$(")` check missed: `FOO=$VAR` and
    // `FOO=${VAR}` are dynamic too — they must not be stored as a known
    // literal `"$VAR"`.
    for spec in ["FOO=$VAR", "FOO=${VAR}", "FOO=${VAR:-default}"] {
        let words = [Word::from(spec), Word::from("cmd")];
        let snap = EnvSnapshot::clean().with_assignments(&words);
        assert_eq!(
            snap.get_value("FOO"),
            Some(EnvValueOwned::Unknown),
            "{spec} should resolve to Unknown"
        );
    }
}

#[test]
fn with_assignments_literal_is_known() {
    let words = [Word::from("FOO=production"), Word::from("cmd")];
    let snap = EnvSnapshot::clean().with_assignments(&words);
    match snap.get_value("FOO") {
        Some(EnvValueOwned::Known(v)) => assert_eq!(v, "production"),
        other => panic!("expected Known(production), got {other:?}"),
    }
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

// ── EnvSnapshot::preserved_from ──────────────────────────────────────────

#[test]
fn preserved_from_copies_known_vars() {
    let mut source = EnvSnapshot::clean();
    source.set("FOO", "foo-val");
    source.set("BAR", "bar-val");
    source.set("OTHER", "should-not-appear");

    let result = EnvSnapshot::preserved_from(&source, &["FOO", "BAR"]);

    assert_eq!(
        result.get_value("FOO"),
        Some(EnvValueOwned::Known("foo-val".to_string())),
        "FOO listed in vars should be Known"
    );
    assert_eq!(
        result.get_value("BAR"),
        Some(EnvValueOwned::Known("bar-val".to_string())),
        "BAR listed in vars should be Known"
    );
    assert_eq!(
        result.get_value("OTHER"),
        Some(EnvValueOwned::Unknown),
        "OTHER not in vars list should be Unknown"
    );
}

#[test]
fn preserved_from_unknown_source_stays_unknown() {
    let mut source = EnvSnapshot::clean();
    source.set_unknown("FOO"); // FOO has unknown value in source

    let result = EnvSnapshot::preserved_from(&source, &["FOO"]);

    assert_eq!(
        result.get_value("FOO"),
        Some(EnvValueOwned::Unknown),
        "Unknown value in source cannot be preserved → stays Unknown"
    );
}

#[test]
fn preserved_from_absent_var_stays_unknown() {
    let source = EnvSnapshot::clean(); // FOO not set at all

    let result = EnvSnapshot::preserved_from(&source, &["FOO"]);

    assert_eq!(
        result.get_value("FOO"),
        Some(EnvValueOwned::Unknown),
        "Absent var in source cannot be preserved → stays Unknown"
    );
}

#[test]
fn preserved_from_empty_vars_all_unknown() {
    let mut source = EnvSnapshot::clean();
    source.set("FOO", "val");

    let result = EnvSnapshot::preserved_from(&source, &[]);

    assert_eq!(
        result.get_value("FOO"),
        Some(EnvValueOwned::Unknown),
        "Empty vars list → everything Unknown"
    );
}
