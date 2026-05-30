use agent_shell_parser::parse::types::Word;

use super::*;

#[test]
fn effect_ordering() {
    assert!(Effect::ReadOnly < Effect::Mutating);
    assert!(Effect::Mutating < Effect::Destructive);
    assert!(Effect::Destructive < Effect::Unknown);
}

#[test]
fn subcommand_map_longest_match_two_word() {
    let mut map = SubcommandMap::new();
    map.insert(
        "pr",
        SubcommandEntry {
            effect: Effect::Unknown,
            flags: FlagSchema::default(),
            env_gates: vec![],
            paths: PathSpec::default(),
            subcommands: SubcommandMap::new(),
        },
    );
    map.insert(
        "pr list",
        SubcommandEntry {
            effect: Effect::ReadOnly,
            flags: FlagSchema::default(),
            env_gates: vec![],
            paths: PathSpec::default(),
            subcommands: SubcommandMap::new(),
        },
    );
    map.insert(
        "pr create",
        SubcommandEntry {
            effect: Effect::Mutating,
            flags: FlagSchema::default(),
            env_gates: vec![],
            paths: PathSpec::default(),
            subcommands: SubcommandMap::new(),
        },
    );

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
    map.insert(
        "status",
        SubcommandEntry {
            effect: Effect::ReadOnly,
            flags: FlagSchema::default(),
            env_gates: vec![],
            paths: PathSpec::default(),
            subcommands: SubcommandMap::new(),
        },
    );

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
    map.insert(
        "pr",
        SubcommandEntry {
            effect: Effect::Unknown,
            flags: FlagSchema::default(),
            env_gates: vec![],
            paths: PathSpec::default(),
            subcommands: SubcommandMap::new(),
        },
    );

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
