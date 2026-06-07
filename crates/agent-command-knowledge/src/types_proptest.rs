use prodagent_types::Word;
use proptest::prelude::*;

use super::*;

fn arb_effect() -> impl Strategy<Value = Effect> {
    prop_oneof![
        Just(Effect::ReadOnly),
        Just(Effect::Mutating),
        Just(Effect::Unknown),
    ]
}

fn arb_subcommand_entry() -> impl Strategy<Value = SubcommandEntry> {
    arb_effect().prop_map(SubcommandEntry::with_effect)
}

/// Draw words from a small fixed vocabulary so that map keys (built from
/// `arb_word`) and lookup inputs (also built from `arb_word`) actually
/// collide. With an open `[a-z]{1,8}` alphabet the two never share values and
/// `longest_match` returns `None` on essentially every case, leaving the
/// Some-branch assertions vacuous. A shared pool makes matches fire on a large
/// fraction of cases, genuinely exercising longest-match correctness.
fn arb_word() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "pr", "create", "list", "repo", "view", "status", "push", "pull",
    ])
    .prop_map(String::from)
}

/// Generate a valid subcommand pattern: 1..=MAX_SUBCOMMAND_DEPTH whitespace-free
/// words joined by single spaces. Every value is a legal `SubcommandPattern`
/// key (non-empty, within the depth limit), so `SubcommandMap::insert` never
/// trips the newtype's debug-assert.
fn arb_pattern() -> impl Strategy<Value = String> {
    prop::collection::vec(arb_word(), 1..=MAX_SUBCOMMAND_DEPTH).prop_map(|words| words.join(" "))
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

/// A valid key whose words are joined with irregular whitespace (leading,
/// trailing, and multi-space runs). After normalization this is a legal
/// pattern, so it must deserialize successfully and round-trip to a
/// single-space form.
fn arb_irregular_valid_key() -> impl Strategy<Value = String> {
    prop::collection::vec(arb_word(), 1..=MAX_SUBCOMMAND_DEPTH)
        .prop_map(|words| format!("  {}  ", words.join("   ")))
}

/// A key with strictly more than `MAX_SUBCOMMAND_DEPTH` words — always invalid.
fn arb_too_deep_key() -> impl Strategy<Value = String> {
    prop::collection::vec(
        arb_word(),
        (MAX_SUBCOMMAND_DEPTH + 1)..=(MAX_SUBCOMMAND_DEPTH + 3),
    )
    .prop_map(|words| words.join(" "))
}

/// An arbitrary TOML map key, mixing valid patterns (single- and
/// irregular-whitespace), over-depth patterns, and empty/whitespace-only
/// patterns. Weighted toward valid keys so both the `Ok` and `Err` arms of the
/// deserialization invariant get exercised.
fn arb_key() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => arb_pattern(),
        2 => arb_irregular_valid_key(),
        1 => arb_too_deep_key(),
        1 => Just(String::new()),
        1 => Just("   ".to_string()),
    ]
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

    /// The validation invariant the refactor rides on: a TOML map deserializes
    /// into a `SubcommandMap` iff every key is non-empty and within
    /// `MAX_SUBCOMMAND_DEPTH`, and every key in a successfully-parsed map is
    /// whitespace-normalized (so `longest_match`, which joins with single
    /// spaces, can still find it).
    #[test]
    fn deserialize_ok_iff_all_keys_valid_and_normalized(
        raw_keys in prop::collection::vec(arb_key(), 0..6),
    ) {
        // Distinct raw keys only: TOML rejects duplicate keys structurally,
        // which is a different failure mode than the validation we're testing.
        let mut keys = raw_keys;
        keys.sort();
        keys.dedup();

        // Every key (words separated by single spaces, double-quoted) is safe
        // to embed in a TOML basic-string key — the vocabulary is `[a-z]` only.
        let mut toml_src = String::new();
        for key in &keys {
            toml_src.push_str(&format!("[entries.\"{key}\"]\neffect = \"read-only\"\n"));
        }

        let all_valid = keys.iter().all(|k| {
            let depth = k.split_whitespace().count();
            (1..=MAX_SUBCOMMAND_DEPTH).contains(&depth)
        });

        let result = toml::from_str::<SubcommandMap>(&toml_src);
        prop_assert_eq!(
            result.is_ok(),
            all_valid,
            "deserialize Ok={} but all_valid={} for keys {:?}",
            result.is_ok(),
            all_valid,
            keys
        );

        if let Ok(map) = result {
            for (pattern, _entry) in map.iter() {
                let depth = pattern.split_whitespace().count();
                prop_assert!(
                    (1..=MAX_SUBCOMMAND_DEPTH).contains(&depth),
                    "deserialized key '{}' has depth {} outside 1..={}",
                    pattern, depth, MAX_SUBCOMMAND_DEPTH
                );
                let normalized = pattern.split_whitespace().collect::<Vec<_>>().join(" ");
                prop_assert_eq!(
                    pattern, normalized.as_str(),
                    "deserialized key is not whitespace-normalized"
                );
            }
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
