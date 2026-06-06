//! Property-based tests for the parsing substrate.
//!
//! This crate is the security boundary the guard and classifier trust: it
//! decomposes untrusted command strings so no blocked command can hide, and
//! it must fail *closed* (surface `has_parse_errors` / `Unanalyzable`) when it
//! can't analyze something. These properties target that contract directly.
//!
//! Discipline: properties never validate the parser by re-running the parser.
//! The structural generators build inputs whose intended decomposition is known
//! (so the generator is the oracle); the robustness and fail-closed properties
//! assert documented postconditions.

use agent_shell_parser::parse::{
    base_command, command_characteristics, env_vars, find_base_command, has_output_redirection,
    parse_command, parse_with_substitutions, resolve_command, tokenize, Operator, Redirection,
    ResolvedCommand, Word,
};
use proptest::prelude::*;

// --- alphabets that stay inside the "plain command" subset of shell syntax ---

const SHELL_KEYWORDS: &[&str] = &[
    "if", "then", "else", "elif", "fi", "for", "do", "done", "while", "until", "case", "esac",
    "function", "select", "in", "time", "coproc",
];
const SHELLS: &[&str] = &[
    "bash", "sh", "dash", "zsh", "fish", "ksh", "tcsh", "csh", "mksh", "yash", "rbash",
];
const WRAPPER_NAMES: &[&str] = &[
    "sudo", "env", "nice", "nohup", "command", "builtin", "xargs", "parallel", "time", "timeout",
    "exec", "setsid", "strace", "ionice", "chrt", "taskset", "watch", "ltrace", "su",
];
const BARE_WRAPPERS: &[&str] = &[
    "sudo", "env", "nice", "nohup", "command", "builtin", "time", "exec", "setsid", "ionice",
    "xargs", "parallel", "strace", "watch", "ltrace",
];

fn is_special(w: &str) -> bool {
    SHELL_KEYWORDS.contains(&w)
        || SHELLS.contains(&w)
        || WRAPPER_NAMES.contains(&w)
        || w == "eval"
        || w == "source"
        || w == "."
        || w.starts_with('$')
}

fn arb_plain_word() -> impl Strategy<Value = String> {
    "[a-z]{1,6}".prop_filter("special shell token", |w| !is_special(w))
}

fn arb_flag() -> impl Strategy<Value = String> {
    prop_oneof!["-[a-z]{1,3}", "--[a-z]{1,6}"]
}

fn arb_word() -> impl Strategy<Value = String> {
    prop_oneof![arb_plain_word(), arb_flag()]
}

fn arb_simple_command() -> impl Strategy<Value = Vec<String>> {
    (arb_plain_word(), prop::collection::vec(arb_word(), 0..4)).prop_map(|(base, args)| {
        let mut v = vec![base];
        v.extend(args);
        v
    })
}

fn to_words(strs: &[String]) -> Vec<Word> {
    strs.iter().map(|s| Word::from(s.as_str())).collect()
}

// --- robustness: the public API is total on arbitrary input ---

fn arb_token() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("$("),
        Just("`"),
        Just("<("),
        Just(">("),
        Just(")"),
        Just("&&"),
        Just("||"),
        Just("|"),
        Just("|&"),
        Just(";"),
        Just("&"),
        Just(">"),
        Just(">>"),
        Just("<"),
        Just("2>&1"),
        Just("/dev/null"),
        Just("'"),
        Just("\""),
        Just("\\"),
        Just("{"),
        Just("}"),
        Just("(("),
        Just("[["),
        Just("]]"),
        Just("$x"),
        Just("${y}"),
        Just("if"),
        Just("then"),
        Just("fi"),
        Just("for"),
        Just("do"),
        Just("done"),
        Just("eval"),
        Just("sudo"),
        Just("git"),
        Just("sh"),
        Just("-c"),
        Just("echo"),
        Just("a"),
        Just("b"),
        Just("\n"),
    ]
}

fn hammer(s: &str) {
    if let Ok(p) = parse_with_substitutions(s) {
        let _ = p.has_parse_errors_recursive();
        let _ = p.filter_segments(&|seg| Some(seg.words.len()));
        let _ = p.fold_segments(0usize, &|acc, seg| acc + seg.words.len());
        let _ = p.find_segment(&|seg| seg.words.first().map(|w| w.as_str().to_string()));
        let _ = p.any_pipeline(&|q| q.has_parse_errors);
    }
    let _ = has_output_redirection(s);
    let toks = tokenize(s);
    let _ = parse_command(s);
    let _ = resolve_command(&toks);
    let _ = find_base_command(&toks);
    let _ = base_command(s);
    let _ = command_characteristics(s);
    let _ = env_vars(s);
}

proptest! {
    #[test]
    fn api_total_on_structured_garbage(toks in prop::collection::vec(arb_token(), 0..40)) {
        hammer(&toks.join(" "));
    }

    #[test]
    fn api_total_on_raw_ascii(s in "[ -~\n\t]{0,120}") {
        hammer(&s);
    }

    #[test]
    fn uniform_operator_decomposition(
        cmds in prop::collection::vec(arb_simple_command(), 1..6),
        op in prop_oneof![Just("&&"), Just("||"), Just("|"), Just(";")],
    ) {
        let sep = format!(" {op} ");
        let rendered = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join(&sep);
        let p = parse_with_substitutions(&rendered).unwrap();

        prop_assert_eq!(p.segments.len(), cmds.len(), "segment count for {:?}", rendered);
        for (seg, cmd) in p.segments.iter().zip(&cmds) {
            prop_assert_eq!(seg.words.clone(), to_words(cmd), "words for {:?}", rendered);
        }
        if cmds.len() > 1 {
            let expected_op = match op {
                "&&" => Operator::And,
                "||" => Operator::Or,
                "|" => Operator::Pipe,
                ";" => Operator::Semi,
                _ => unreachable!(),
            };
            prop_assert_eq!(p.operators.clone(), vec![expected_op; cmds.len() - 1]);
        }
    }

    #[test]
    fn quotes_strip_and_single_quotes_are_inert(
        head in arb_plain_word(),
        phrase_words in prop::collection::vec(arb_plain_word(), 2..4),
        inner in arb_plain_word(),
    ) {
        let phrase = phrase_words.join(" ");
        let expected = vec![Word::from(head.as_str()), Word::from(phrase.as_str())];

        let p1 = parse_with_substitutions(&format!("{head} '{phrase}'")).unwrap();
        prop_assert_eq!(p1.segments.len(), 1);
        prop_assert_eq!(p1.segments[0].words.clone(), expected.clone());

        let p2 = parse_with_substitutions(&format!("{head} \"{phrase}\"")).unwrap();
        prop_assert_eq!(p2.segments[0].words.clone(), expected);

        let p3 = parse_with_substitutions(&format!("{head} '$({inner})'")).unwrap();
        prop_assert!(p3.segments[0].substitutions.is_empty(),
            "single-quoted $() must not be parsed as a substitution");

        // Double-quoted $() IS parsed as a substitution
        let p4 = parse_with_substitutions(&format!("{head} \"$({inner})\"")).unwrap();
        prop_assert!(!p4.segments[0].substitutions.is_empty(),
            "double-quoted $() must be parsed as a substitution");
    }

    #[test]
    fn substitution_command_is_reachable(
        inner in arb_simple_command(),
        delim in prop_oneof![Just("dollar"), Just("backtick"), Just("proc")],
    ) {
        let inner_str = inner.join(" ");
        let outer = match delim {
            "dollar" => format!("echo $({inner_str})"),
            "backtick" => format!("echo `{inner_str}`"),
            _ => format!("echo <({inner_str})"),
        };
        let p = parse_with_substitutions(&outer).unwrap();

        prop_assert_eq!(p.segments.len(), 1);
        prop_assert_eq!(p.segments[0].substitutions.len(), 1);
        let inner_pipe = &p.segments[0].substitutions[0].pipeline;
        prop_assert_eq!(inner_pipe.segments.len(), 1);
        prop_assert_eq!(inner_pipe.segments[0].words.clone(), to_words(&inner));

        let bases: Vec<String> = p.filter_segments(&|seg| Some(find_base_command(&seg.words)));
        let inner_base = find_base_command(&to_words(&inner));
        prop_assert_eq!(bases.first().cloned(), Some(inner_base.clone()));
        prop_assert!(bases.contains(&inner_base));
    }

    #[test]
    fn transparent_wrappers_resolve_to_inner(
        chain in prop::collection::vec(proptest::sample::select(BARE_WRAPPERS.to_vec()), 1..6),
        inner in (arb_plain_word(), prop::collection::vec(arb_plain_word(), 0..3))
            .prop_map(|(base, args)| { let mut v = vec![base]; v.extend(args); v }),
    ) {
        let mut words: Vec<Word> = chain.iter().map(|w| Word::from(*w)).collect();
        words.extend(to_words(&inner));
        let inner_base = find_base_command(&to_words(&inner));
        match resolve_command(&words) {
            ResolvedCommand::Resolved(p) => {
                prop_assert_eq!(p.command.as_str(), inner_base.as_str())
            }
            other => prop_assert!(false, "expected Resolved({inner_base}), got {:?}", other),
        }
    }

    #[test]
    fn deep_wrapper_chain_fails_closed(
        chain in prop::collection::vec(proptest::sample::select(BARE_WRAPPERS.to_vec()), 33..45),
        inner in arb_simple_command(),
    ) {
        let mut words: Vec<Word> = chain.iter().map(|w| Word::from(*w)).collect();
        words.extend(to_words(&inner));
        prop_assert!(
            matches!(resolve_command(&words), ResolvedCommand::Unanalyzable(_)),
            "chain past the resolve depth limit must fail closed"
        );
    }

    #[test]
    fn unanalyzable_inner_stays_unanalyzable(
        chain in prop::collection::vec(proptest::sample::select(BARE_WRAPPERS.to_vec()), 0..6),
        inner in prop_oneof![
            arb_plain_word()
                .prop_map(|p| vec![Word::from("eval"), Word::from(p.as_str())]),
            arb_plain_word()
                .prop_map(|p| vec![Word::from("sh"), Word::from("-c"), Word::from(p.as_str())]),
            arb_plain_word()
                .prop_map(|p| vec![Word::from("source"), Word::from(p.as_str())]),
            Just(vec![Word::from("$dyn"), Word::from("arg")]),
        ],
    ) {
        let mut words: Vec<Word> = chain.iter().map(|w| Word::from(*w)).collect();
        words.extend(inner);
        prop_assert!(
            matches!(resolve_command(&words), ResolvedCommand::Unanalyzable(_)),
            "unanalyzable command wrapped in transparent wrappers must remain unanalyzable"
        );
    }

    #[test]
    fn oversize_input_fails_closed(pad in 1usize..200) {
        let big = "a".repeat(64 * 1024 + pad);
        let p = parse_with_substitutions(&big).unwrap();
        prop_assert!(p.has_parse_errors);
        prop_assert!(p.segments.is_empty());
    }

    #[test]
    fn deep_substitution_nesting_fails_closed(depth in 33usize..40) {
        let mut cmd = String::from("x");
        for _ in 0..depth {
            cmd = format!("echo $({cmd})");
        }
        let p = parse_with_substitutions(&cmd).unwrap();
        prop_assert_eq!(p.segments.len(), 1);
        prop_assert!(
            p.has_parse_errors_recursive(),
            "nesting past the substitution depth cap must surface a parse error"
        );
    }

    #[test]
    fn output_redirection_core(
        cmd in arb_simple_command(),
        file in arb_plain_word(),
        append in any::<bool>(),
    ) {
        let c = cmd.join(" ");
        let op = if append { ">>" } else { ">" };
        let r = has_output_redirection(&format!("{c} {op} {file}")).unwrap();
        prop_assert_eq!(
            r,
            Some(Redirection {
                operator: op,
                fd: None,
                target: file.clone()
            })
        );

        let devnull_cmd = format!("{c} > /dev/null");
        prop_assert!(has_output_redirection(&devnull_cmd).unwrap().is_none());
        let dup_cmd = format!("{c} 2>&1");
        prop_assert!(has_output_redirection(&dup_cmd).unwrap().is_none());
    }

    #[test]
    fn base_command_skips_env_and_classifies_plain(
        envs in prop::collection::vec(
            ("[A-Za-z_][A-Za-z0-9_]{0,5}", "[a-z0-9]{0,5}"),
            0..4,
        ),
        cmd in arb_plain_word(),
        args in prop::collection::vec(arb_plain_word(), 0..3),
    ) {
        let mut parts: Vec<String> = envs.iter().map(|(k, v)| format!("{k}={v}")).collect();
        parts.push(cmd.clone());
        parts.extend(args);
        let s = parts.join(" ");

        prop_assert_eq!(base_command(&s), cmd.clone());
        let c = command_characteristics(&s);
        prop_assert_eq!(c.base_command, cmd);
        prop_assert!(
            c.indirect_execution.is_none(),
            "plain command misclassified as indirect"
        );
        prop_assert!(!c.has_dynamic_command);
    }

    /// fold_segments collecting all segments produces the same sequence as
    /// filter_segments returning Some for all — formalizes the traversal-order
    /// guarantee.
    #[test]
    fn fold_segments_traversal_order_matches_filter_segments(
        cmds in prop::collection::vec(arb_simple_command(), 1..6),
        op in prop_oneof![Just("&&"), Just("||"), Just("|"), Just(";")],
    ) {
        let sep = format!(" {op} ");
        let rendered = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join(&sep);
        let p = parse_with_substitutions(&rendered).unwrap();

        let filtered: Vec<String> = p.filter_segments(&|seg| Some(seg.command.clone()));
        let folded: Vec<String> = p.fold_segments(Vec::new(), &|mut acc, seg| {
            acc.push(seg.command.clone());
            acc
        });
        prop_assert_eq!(
            folded, filtered,
            "traversal order mismatch for {:?}", rendered
        );
    }

    /// Fail-safe: an unanalyzable flag in the wrapper's own flag region
    /// (before the inner command starts) forces Unanalyzable.
    #[test]
    fn wrapper_unanalyzable_flag_collision_fails_closed(
        (wrapper, flag) in prop_oneof![
            Just(("sudo", "-i")),
            Just(("sudo", "-s")),
            Just(("env", "-S")),
            Just(("env", "--split-string")),
        ],
        inner_base in arb_plain_word(),
        extra in prop::collection::vec(arb_plain_word(), 0..3),
    ) {
        // Place the unanalyzable flag before the inner command — i.e. in
        // the wrapper's own flag region where it should be detected.
        let mut words = vec![Word::from(wrapper), Word::from(flag)];
        words.push(Word::from(inner_base.as_str()));
        words.extend(extra.iter().map(|s| Word::from(s.as_str())));
        prop_assert!(
            matches!(resolve_command(&words), ResolvedCommand::Unanalyzable(_)),
            "a token colliding with the wrapper's unanalyzable flags must fail closed"
        );
    }

    /// Dual of wrapper_unanalyzable_flag_collision_fails_closed: when a flag
    /// that collides with the wrapper's unanalyzable list appears *after* the
    /// inner command starts, it belongs to the inner command and must not
    /// trigger the wrapper's fail-closed path.
    ///
    /// Two placement strategies:
    ///   1. After a `--` terminator:  `sudo -- inner -s`
    ///   2. As a trailing arg (no terminator): `sudo inner -s`
    ///
    /// In both cases the result must be Resolved(inner).
    #[test]
    fn colliding_flag_after_inner_command_resolves(
        (wrapper, flag) in prop_oneof![
            Just(("sudo", "-i")),
            Just(("sudo", "-s")),
            Just(("env", "-S")),
            Just(("env", "--split-string")),
        ],
        inner_base in arb_plain_word(),
        extra in prop::collection::vec(arb_plain_word(), 0..3),
        use_terminator in any::<bool>(),
    ) {
        // Build: wrapper [--] inner [extra...] flag
        let mut words = vec![Word::from(wrapper)];
        if use_terminator {
            words.push(Word::from("--"));
        }
        words.push(Word::from(inner_base.as_str()));
        words.extend(extra.iter().map(|s| Word::from(s.as_str())));
        words.push(Word::from(flag));

        match resolve_command(&words) {
            ResolvedCommand::Resolved(p) => {
                prop_assert_eq!(
                    p.command.as_str(),
                    inner_base.as_str(),
                    "colliding flag after inner command must resolve to the inner command"
                );
            }
            other => prop_assert!(
                false,
                "expected Resolved({inner_base}), got {:?} — colliding flag placed after \
                 inner command start should not trigger wrapper's unanalyzable check",
                other,
            ),
        }
    }
}
