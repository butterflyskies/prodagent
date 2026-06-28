use camino::Utf8PathBuf;
use prodagent_types::Word;
use proptest::prelude::*;

use crate::lookup::classify;
use crate::types::*;

// ---- shared strategies ----

fn arb_effect() -> impl Strategy<Value = Effect> {
    prop_oneof![
        Just(Effect::ReadOnly),
        Just(Effect::Mutating),
        Just(Effect::Unknown),
    ]
}

fn arb_word() -> impl Strategy<Value = String> {
    "[a-z]{1,6}"
}

fn arb_flag() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z]{1,4}".prop_map(|s| format!("-{s}")),
        "[a-z]{1,5}".prop_map(|s| format!("--{s}")),
    ]
}

fn arb_env_gate_decision() -> impl Strategy<Value = EnvGateAction> {
    prop_oneof![
        Just(EnvGateAction::Allow),
        Just(EnvGateAction::Ask),
        Just(EnvGateAction::Deny),
    ]
}

fn arb_env_condition() -> impl Strategy<Value = EnvCondition> {
    prop_oneof![
        arb_word().prop_map(EnvCondition::Equals),
        arb_word().prop_map(EnvCondition::NotEquals),
        Just(EnvCondition::Set),
        Just(EnvCondition::Unset),
    ]
}

fn arb_env_gate() -> impl Strategy<Value = EnvGate> {
    (arb_word(), arb_env_condition(), arb_env_gate_decision()).prop_map(
        |(var, condition, decision)| EnvGate {
            var,
            condition,
            decision,
        },
    )
}

fn arb_path_positionals() -> impl Strategy<Value = PathPositionals> {
    prop_oneof![
        Just(PathPositionals::None),
        Just(PathPositionals::All),
        Just(PathPositionals::Last),
        (0usize..4).prop_map(PathPositionals::Tail),
    ]
}

fn single_cmd_kb(
    cmd: &str,
    sub_pattern: &str,
    entry: SubcommandEntry,
    cmd_flags: FlagSchema,
) -> KnowledgeBase {
    let mut sub_map = SubcommandMap::new();
    sub_map.insert(sub_pattern.to_string(), entry);
    let mut command = CommandKnowledge::simple(cmd, Effect::Unknown);
    command.subcommands = sub_map;
    command.flags = cmd_flags;
    let mut kb = KnowledgeBase::default();
    kb.commands.insert(cmd.to_string(), command);
    kb
}

// ===========================================================================
// Path extraction — positional modes, checked against an independent oracle.
// The generator builds [cmd, sub_words..., P...] with NO flags, so the
// positional region after the command + subcommand is exactly P. Expected
// paths are derived from P by the *definition* of each mode, not by classify.
// ===========================================================================
fn arb_positional_path_case(
) -> impl Strategy<Value = (KnowledgeBase, String, Vec<Word>, Vec<Utf8PathBuf>)> {
    (
        arb_word(),
        prop::collection::vec(arb_word(), 1..3),
        prop::collection::vec(arb_word(), 0..5),
        arb_path_positionals(),
        arb_effect(),
    )
        .prop_map(|(cmd, sub_words, p, mode, effect)| {
            let mut entry = SubcommandEntry::with_effect(effect);
            entry.paths = PathSpec {
                positionals: mode.clone(),
                flags: vec![],
            };
            let kb = single_cmd_kb(&cmd, &sub_words.join(" "), entry, FlagSchema::default());

            let mut input: Vec<Word> = vec![Word::from(cmd.as_str())];
            input.extend(sub_words.iter().map(|s| Word::from(s.as_str())));
            input.extend(p.iter().map(|s| Word::from(s.as_str())));

            let expected: Vec<Utf8PathBuf> = match mode {
                PathPositionals::None => vec![],
                PathPositionals::All => p.iter().map(|s| Utf8PathBuf::from(s.as_str())).collect(),
                PathPositionals::Last => p
                    .last()
                    .map(|s| Utf8PathBuf::from(s.as_str()))
                    .into_iter()
                    .collect(),
                PathPositionals::Tail(k) => p
                    .iter()
                    .skip(k)
                    .map(|s| Utf8PathBuf::from(s.as_str()))
                    .collect(),
            };
            (kb, cmd, input, expected)
        })
}

// ===========================================================================
// Path extraction — path FLAGS (`-C val` and `--flag=val`), independent oracle.
// Subcommand paths = None, so affected_paths must be exactly the flag values.
// ===========================================================================
fn arb_path_flag_case(
) -> impl Strategy<Value = (KnowledgeBase, String, Vec<Word>, Vec<Utf8PathBuf>)> {
    (
        arb_word(),
        arb_word(),
        arb_flag(),
        prop::collection::vec(arb_word(), 1..4),
        any::<bool>(),
    )
        .prop_map(|(cmd, sub, flag, vals, use_equals)| {
            let entry = SubcommandEntry::with_effect(Effect::Mutating);
            let cmd_flags = FlagSchema {
                path: vec![flag.clone()],
                ..Default::default()
            };
            let kb = single_cmd_kb(&cmd, &sub, entry, cmd_flags);

            let mut input = vec![Word::from(cmd.as_str()), Word::from(sub.as_str())];
            let mut expected = Vec::new();
            for v in &vals {
                if use_equals {
                    input.push(Word::from(format!("{flag}={v}").as_str()));
                } else {
                    input.push(Word::from(flag.as_str()));
                    input.push(Word::from(v.as_str()));
                }
                expected.push(Utf8PathBuf::from(v.as_str()));
            }
            (kb, cmd, input, expected)
        })
}

// ===========================================================================
// skip_arg flag value before subcommand: the consumed value must not be
// counted as a positional, and the subcommand word must not leak into paths.
// ===========================================================================
fn arb_skip_arg_before_subcommand(
) -> impl Strategy<Value = (KnowledgeBase, String, Vec<Word>, Vec<Utf8PathBuf>)> {
    (
        arb_word(),
        arb_word(),
        arb_flag(),
        arb_word(),
        prop::collection::vec(arb_word(), 0..3),
    )
        .prop_map(|(cmd, sub, skip_flag, skip_val, p)| {
            let mut entry = SubcommandEntry::with_effect(Effect::Mutating);
            entry.paths = PathSpec {
                positionals: PathPositionals::All,
                flags: vec![],
            };
            let cmd_flags = FlagSchema {
                skip_arg: vec![skip_flag.clone()],
                ..Default::default()
            };
            let kb = single_cmd_kb(&cmd, &sub, entry, cmd_flags);

            // [cmd, -C, val, sub, p...]
            let mut input = vec![
                Word::from(cmd.as_str()),
                Word::from(skip_flag.as_str()),
                Word::from(skip_val.as_str()),
                Word::from(sub.as_str()),
            ];
            input.extend(p.iter().map(|s| Word::from(s.as_str())));

            let expected: Vec<Utf8PathBuf> =
                p.iter().map(|s| Utf8PathBuf::from(s.as_str())).collect();
            (kb, cmd, input, expected)
        })
}

fn arb_escalation_kb(
) -> impl Strategy<Value = (KnowledgeBase, String, String, Vec<String>, Vec<String>)> {
    (
        arb_word(),
        arb_word(),
        prop::collection::vec(arb_flag(), 0..3),
        prop::collection::vec(arb_flag(), 0..3),
    )
        .prop_map(|(cmd, sub, esc_cmd, esc_sub)| {
            let mut entry = SubcommandEntry::with_effect(Effect::Mutating);
            entry.flags = FlagSchema {
                escalation: esc_sub.clone(),
                ..Default::default()
            };
            let cmd_flags = FlagSchema {
                escalation: esc_cmd.clone(),
                ..Default::default()
            };
            let kb = single_cmd_kb(&cmd, &sub, entry, cmd_flags);
            (kb, cmd, sub, esc_cmd, esc_sub)
        })
}

proptest! {
    #[test]
    fn positional_paths_match_oracle(
        (kb, cmd, input, expected) in arb_positional_path_case()
    ) {
        let info = classify(&Word::from(cmd.as_str()), &input, &kb);
        prop_assert_eq!(info.affected_paths, expected,
            "positional extraction diverged from oracle for {:?}", input);
    }

    #[test]
    fn flag_paths_match_oracle(
        (kb, cmd, input, expected) in arb_path_flag_case()
    ) {
        let info = classify(&Word::from(cmd.as_str()), &input, &kb);
        prop_assert_eq!(info.affected_paths, expected,
            "flag-path extraction diverged from oracle for {:?}", input);
    }

    #[test]
    fn skip_arg_value_before_subcommand(
        (kb, cmd, input, expected) in arb_skip_arg_before_subcommand()
    ) {
        let info = classify(&Word::from(cmd.as_str()), &input, &kb);
        prop_assert_eq!(info.affected_paths, expected,
            "skip_arg/positional desync for {:?}", input);
    }

    #[test]
    fn no_escalation_flag_means_false(
        (kb, cmd, sub, ec, es) in arb_escalation_kb(),
        noise in prop::collection::vec(arb_flag(), 0..3),
        plain in prop::collection::vec(arb_word(), 0..4),
    ) {
        let esc: Vec<String> = ec.iter().chain(es.iter()).cloned().collect();
        let mut input = vec![Word::from(cmd.as_str()), Word::from(sub.as_str())];
        for f in &noise {
            if !esc.contains(f) {
                input.push(Word::from(f.as_str()));
            }
        }
        for w in &plain {
            input.push(Word::from(w.as_str()));
        }
        let info = classify(&Word::from(cmd.as_str()), &input, &kb);
        prop_assert!(!info.has_escalation_flags, "false escalation positive");
    }

    #[test]
    fn present_escalation_flag_means_true(
        (kb, cmd, sub, ec, es) in arb_escalation_kb()
    ) {
        let all: Vec<String> = ec.into_iter().chain(es).collect();
        prop_assume!(!all.is_empty());
        let chosen = all[0].clone();
        let input = vec![
            Word::from(cmd.as_str()),
            Word::from(sub.as_str()),
            Word::from(chosen.as_str()),
        ];
        let info = classify(&Word::from(cmd.as_str()), &input, &kb);
        prop_assert!(info.has_escalation_flags,
            "escalation flag {} not detected", chosen);
    }

    #[test]
    fn command_shadows_wrapper(
        name in arb_word(),
        eff in arb_effect(),
        floor in arb_effect(),
        args in prop::collection::vec(arb_word(), 0..3),
    ) {
        let mut kb = single_cmd_kb(
            &name,
            "noop",
            SubcommandEntry::with_effect(Effect::ReadOnly),
            FlagSchema::default(),
        );
        kb.commands.get_mut(&name).unwrap().effect = eff;
        kb.wrappers.insert(
            name.clone(),
            WrapperKnowledge {
                name: name.clone(),
                floor_effect: floor,
                clears_env: false,
                escalates_privilege: false,
            },
        );
        let mut input = vec![Word::from(name.as_str())];
        input.extend(args.iter().map(|s| Word::from(s.as_str())));
        let info = classify(&Word::from(name.as_str()), &input, &kb);
        prop_assert!(info.wrapper.is_none(), "command entry must shadow wrapper");
    }

    #[test]
    fn unknown_command_is_fully_unknown(
        cmd in arb_word(),
        args in prop::collection::vec(arb_word(), 0..4),
    ) {
        let kb = KnowledgeBase::default();
        let mut input = vec![Word::from(cmd.as_str())];
        input.extend(args.iter().map(|s| Word::from(s.as_str())));
        let info = classify(&Word::from(cmd.as_str()), &input, &kb);
        prop_assert_eq!(info.effect, Effect::Unknown);
        prop_assert!(info.subcommand.is_none());
        prop_assert!(!info.has_escalation_flags);
        prop_assert!(info.affected_paths.is_empty());
        prop_assert!(info.env_gates.is_empty());
        prop_assert!(info.wrapper.is_none());
    }

    #[test]
    fn env_gates_accumulate(
        cmd in arb_word(),
        sub in arb_word(),
        cmd_gate in arb_env_gate(),
        sub_gate in arb_env_gate(),
        extra in prop::collection::vec(arb_word(), 0..3),
    ) {
        let mut entry = SubcommandEntry::with_effect(Effect::ReadOnly);
        entry.env_gates = vec![sub_gate.clone()];
        let mut kb = single_cmd_kb(&cmd, &sub, entry, FlagSchema::default());
        kb.commands.get_mut(&cmd).unwrap().env_gates = vec![cmd_gate.clone()];

        let mut input = vec![Word::from(cmd.as_str()), Word::from(sub.as_str())];
        input.extend(extra.iter().map(|s| Word::from(s.as_str())));
        let info = classify(&Word::from(cmd.as_str()), &input, &kb);
        prop_assert!(info.env_gates.contains(&cmd_gate), "command gate missing");
        prop_assert!(info.env_gates.contains(&sub_gate), "subcommand gate missing");
    }

    #[test]
    fn env_gates_no_subcommand_match_has_only_command_gates(
        cmd in arb_word(),
        sub in arb_word(),
        other in arb_word(),
        cmd_gate in arb_env_gate(),
        sub_gate in arb_env_gate(),
    ) {
        // Ensure the non-matching word is distinct from the registered subcommand,
        // and the two gates are distinct (so the sub_gate check is meaningful).
        prop_assume!(other != sub);
        prop_assume!(cmd_gate != sub_gate);
        let mut entry = SubcommandEntry::with_effect(Effect::ReadOnly);
        entry.env_gates = vec![sub_gate.clone()];
        let mut kb = single_cmd_kb(&cmd, &sub, entry, FlagSchema::default());
        kb.commands.get_mut(&cmd).unwrap().env_gates = vec![cmd_gate.clone()];

        // Call with `other` so the subcommand does NOT match.
        let input = vec![Word::from(cmd.as_str()), Word::from(other.as_str())];
        let info = classify(&Word::from(cmd.as_str()), &input, &kb);
        prop_assert!(info.subcommand.is_none(), "expected no subcommand match");
        prop_assert!(info.env_gates.contains(&cmd_gate), "command gate missing");
        prop_assert!(!info.env_gates.contains(&sub_gate), "sub gate must not appear when subcommand not matched");
    }
}
