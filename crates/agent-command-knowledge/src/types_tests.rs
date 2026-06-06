use agent_types::Word;

use super::*;

#[test]
fn effect_ordering() {
    assert!(Effect::ReadOnly < Effect::Mutating);
    assert!(Effect::Mutating < Effect::Unknown);
}

#[test]
fn subcommand_map_longest_match_two_word() {
    let mut map = SubcommandMap::new();
    map.insert("pr", SubcommandEntry::with_effect(Effect::Unknown));
    map.insert("pr list", SubcommandEntry::with_effect(Effect::ReadOnly));
    map.insert("pr create", SubcommandEntry::with_effect(Effect::Mutating));

    let words: Vec<Word> = ["pr", "create", "--draft"]
        .iter()
        .map(|s| Word::from(*s))
        .collect();
    let refs: Vec<&Word> = words.iter().collect();
    let (entry, depth) = map.longest_match(&refs).unwrap();
    assert_eq!(entry.effect, Effect::Mutating);
    assert_eq!(depth, 2);
}

#[test]
fn subcommand_map_longest_match_single_word() {
    let mut map = SubcommandMap::new();
    map.insert("status", SubcommandEntry::with_effect(Effect::ReadOnly));

    let words = [Word::from("status")];
    let refs: Vec<&Word> = words.iter().collect();
    let (entry, depth) = map.longest_match(&refs).unwrap();
    assert_eq!(entry.effect, Effect::ReadOnly);
    assert_eq!(depth, 1);
}

#[test]
fn subcommand_map_no_match() {
    let map = SubcommandMap::new();
    let words = [Word::from("frobnicate")];
    let refs: Vec<&Word> = words.iter().collect();
    assert!(map.longest_match(&refs).is_none());
}

#[test]
fn subcommand_map_fallback_to_shorter() {
    let mut map = SubcommandMap::new();
    map.insert("pr", SubcommandEntry::with_effect(Effect::Unknown));

    let words: Vec<Word> = ["pr", "unknown-sub"]
        .iter()
        .map(|s| Word::from(*s))
        .collect();
    let refs: Vec<&Word> = words.iter().collect();
    let (entry, depth) = map.longest_match(&refs).unwrap();
    assert_eq!(entry.effect, Effect::Unknown);
    assert_eq!(depth, 1);
}

#[test]
fn command_info_unknown_default() {
    let info = CommandInfo::unknown();
    assert_eq!(info.effect, Effect::Unknown);
    assert!(info.subcommand.is_none());
    assert!(!info.has_escalation_flags);
    assert!(info.affected_paths.is_empty());
    assert!(info.env_gates.is_empty());
    assert!(info.wrapper.is_none());
}

// ── SubcommandMap deserialization depth validation ───────────────────────────

#[test]
fn deserialize_valid_max_depth_pattern() {
    // A 4-word pattern (exactly MAX_SUBCOMMAND_DEPTH) should succeed.
    let toml_str = r#"
[entries."one two three four"]
effect = "read-only"
"#;
    let map: SubcommandMap = toml::from_str(toml_str).expect("4-word pattern should parse");
    assert!(map.get("one two three four").is_some());
}

#[test]
fn deserialize_rejects_exceeding_depth_pattern() {
    // A 5-word pattern exceeds MAX_SUBCOMMAND_DEPTH and should fail.
    let toml_str = r#"
[entries."one two three four five"]
effect = "read-only"
"#;
    let err = toml::from_str::<SubcommandMap>(toml_str).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("one two three four five"),
        "error should name the offending pattern, got: {msg}"
    );
    assert!(
        msg.contains("MAX_SUBCOMMAND_DEPTH"),
        "error should mention MAX_SUBCOMMAND_DEPTH, got: {msg}"
    );
}

#[test]
fn deserialize_overlay_with_invalid_subcommand_pattern_rejected() {
    use crate::merge::KnowledgeOverlay;

    let toml_str = r#"
[commands.my-tool.subcommands.entries."a b c d e"]
effect = "mutating"
"#;
    let err = toml::from_str::<KnowledgeOverlay>(toml_str).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("a b c d e"),
        "error should name the offending pattern, got: {msg}"
    );
}

#[test]
fn deserialize_mixed_valid_and_invalid_patterns_rejected() {
    // If any single pattern exceeds depth, the whole map is rejected.
    let toml_str = r#"
[entries.status]
effect = "read-only"

[entries."one two three four five"]
effect = "mutating"
"#;
    assert!(
        toml::from_str::<SubcommandMap>(toml_str).is_err(),
        "map with any invalid pattern should fail"
    );
}
