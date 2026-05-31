use agent_shell_parser::parse::types::Word;
use proptest::prelude::*;

use super::*;

fn arb_effect() -> impl Strategy<Value = Effect> {
    prop_oneof![
        Just(Effect::ReadOnly),
        Just(Effect::Mutating),
        Just(Effect::Destructive),
        Just(Effect::Unknown),
    ]
}

fn arb_subcommand_entry() -> impl Strategy<Value = SubcommandEntry> {
    arb_effect().prop_map(SubcommandEntry::with_effect)
}

fn arb_word() -> impl Strategy<Value = String> {
    "[a-z]{1,8}"
}

fn arb_pattern() -> impl Strategy<Value = String> {
    prop_oneof![
        arb_word(),
        (arb_word(), arb_word()).prop_map(|(a, b)| format!("{a} {b}")),
        (arb_word(), arb_word(), arb_word()).prop_map(|(a, b, c)| format!("{a} {b} {c}")),
    ]
}

fn arb_subcommand_map() -> impl Strategy<Value = SubcommandMap> {
    prop::collection::vec((arb_pattern(), arb_subcommand_entry()), 0..10).prop_map(|entries| {
        let mut map = SubcommandMap::new();
        for (pattern, entry) in entries {
            map.insert(pattern, entry);
        }
        map
    })
}

fn arb_word_list() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(arb_word(), 1..6)
}

proptest! {
    #[test]
    fn match_depth_bounded_by_input_length(
        map in arb_subcommand_map(),
        input in arb_word_list(),
    ) {
        let words: Vec<Word> = input.iter().map(|s| Word::from(s.as_str())).collect();
        let refs: Vec<&Word> = words.iter().collect();
        if let Some((_, depth)) = map.longest_match(&refs) {
            prop_assert!(depth <= input.len());
        }
    }

    #[test]
    fn matched_pattern_exists_in_map(
        map in arb_subcommand_map(),
        input in arb_word_list(),
    ) {
        let words: Vec<Word> = input.iter().map(|s| Word::from(s.as_str())).collect();
        let refs: Vec<&Word> = words.iter().collect();
        if let Some((entry, depth)) = map.longest_match(&refs) {
            let pattern = input[..depth].join(" ");
            let looked_up = map.get(&pattern);
            prop_assert!(looked_up.is_some(), "matched pattern '{}' not found via get()", pattern);
            prop_assert_eq!(looked_up.unwrap().effect, entry.effect);
        }
    }

    #[test]
    fn no_longer_match_exists(
        map in arb_subcommand_map(),
        input in arb_word_list(),
    ) {
        let words: Vec<Word> = input.iter().map(|s| Word::from(s.as_str())).collect();
        let refs: Vec<&Word> = words.iter().collect();
        let matched_depth = map.longest_match(&refs).map(|(_, d)| d).unwrap_or(0);

        for longer in (matched_depth + 1)..=input.len().min(4) {
            let longer_pattern = input[..longer].join(" ");
            prop_assert!(
                map.get(&longer_pattern).is_none(),
                "found longer match '{}' at depth {} but longest_match returned depth {}",
                longer_pattern, longer, matched_depth
            );
        }
    }

    #[test]
    fn trailing_words_dont_change_match(
        map in arb_subcommand_map(),
        base in arb_word_list(),
        extra in arb_word_list(),
    ) {
        let base_words: Vec<Word> = base.iter().map(|s| Word::from(s.as_str())).collect();
        let base_refs: Vec<&Word> = base_words.iter().collect();
        let base_result = map.longest_match(&base_refs);

        let mut extended = base.clone();
        extended.extend(extra);
        let ext_words: Vec<Word> = extended.iter().map(|s| Word::from(s.as_str())).collect();
        let ext_refs: Vec<&Word> = ext_words.iter().collect();
        let ext_result = map.longest_match(&ext_refs);

        match (base_result, ext_result) {
            (Some((base_entry, base_depth)), Some((ext_entry, ext_depth))) => {
                prop_assert!(ext_depth >= base_depth,
                    "extending input should not shorten match: base={}, ext={}",
                    base_depth, ext_depth
                );
                if ext_depth == base_depth {
                    prop_assert_eq!(base_entry.effect, ext_entry.effect);
                }
            }
            (Some(_), None) => {
                prop_assert!(false, "extending input lost a match that existed");
            }
            _ => {}
        }
    }

    #[test]
    fn empty_input_never_matches(map in arb_subcommand_map()) {
        let empty: Vec<&Word> = vec![];
        prop_assert!(map.longest_match(&empty).is_none());
    }

    #[test]
    fn empty_map_never_matches(input in arb_word_list()) {
        let map = SubcommandMap::new();
        let words: Vec<Word> = input.iter().map(|s| Word::from(s.as_str())).collect();
        let refs: Vec<&Word> = words.iter().collect();
        prop_assert!(map.longest_match(&refs).is_none());
    }
}
