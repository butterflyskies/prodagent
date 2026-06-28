//! Metamorphic proptest: tree-sitter classification vs byte-scanning classification.
//!
//! For any well-formed shell assignment string, the tree-sitter-derived
//! classification (WordKind → as_classified_assignment) must agree with
//! byte-scanning classification (Word::from → as_classified_assignment →
//! AssignmentValue::classify). When they disagree, the byte scanner must be
//! MORE restrictive — that is the safety invariant.
//!
//! Discipline: the generator is the oracle for well-formedness. The
//! restrictiveness ordering (Static < VariableExpansion < CommandSubstitution)
//! is defined independently of both classification paths. The property never
//! validates a classifier by re-running the same classifier.

use agent_shell_parser::parse::{parse_with_substitutions, AssignmentValue, Word, WordKind};
use proptest::prelude::*;

const PROPTEST_CASES: u32 = 1024;

// ── Restrictiveness ordering ────────────────────────────────────────────────

/// Restrictiveness rank: higher = more conservative.
///
/// - `Static` (0): fully known literal — least restrictive.
/// - `VariableExpansion` (1): unknowable value, no inner command.
/// - `CommandSubstitution` (2): inner command, recursively evaluated — most
///   restrictive.
fn restrictiveness(av: &AssignmentValue) -> u8 {
    match av {
        AssignmentValue::Static(_) => 0,
        AssignmentValue::VariableExpansion => 1,
        AssignmentValue::CommandSubstitution => 2,
    }
}

fn classification_label(av: &AssignmentValue) -> &'static str {
    match av {
        AssignmentValue::Static(_) => "Static",
        AssignmentValue::VariableExpansion => "VariableExpansion",
        AssignmentValue::CommandSubstitution => "CommandSubstitution",
    }
}

// ── Generators ──────────────────────────────────────────────────────────────

/// Valid environment variable key: starts with letter or underscore,
/// followed by alphanumerics and underscores.
fn arb_env_key() -> impl Strategy<Value = String> {
    "[A-Z][A-Z0-9_]{0,5}"
}

/// Literal value with no shell expansion characters.
fn arb_literal_value() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_./:]{0,10}".prop_filter("no expansion chars", |v| {
        !v.contains('$') && !v.contains('`')
    })
}

/// Non-empty literal value (for use as a prefix/suffix in mixed forms).
fn arb_nonempty_literal() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_./]{1,8}".prop_filter("no expansion chars", |v| {
        !v.contains('$') && !v.contains('`')
    })
}

/// Shell reserved words that confuse tree-sitter when used inside backtick
/// substitutions (e.g. `` `for` `` parses as a keyword, not a command).
const SHELL_RESERVED: &[&str] = &[
    "if", "then", "else", "elif", "fi", "do", "done", "case", "esac", "while", "until", "for",
    "in", "function", "select", "time", "coproc",
];

/// Simple command name for use inside substitutions.
fn arb_cmd_name() -> impl Strategy<Value = String> {
    "[a-z]{2,6}".prop_filter("not a shell reserved word", |s| {
        !SHELL_RESERVED.contains(&s.as_str())
    })
}

/// Simple variable name for use in expansions.
fn arb_var_name() -> impl Strategy<Value = String> {
    "[A-Z][A-Z0-9_]{0,4}"
}

/// Generate the value side of a well-formed shell assignment.
///
/// Each variant produces a syntactically valid shell value that tree-sitter
/// can parse without errors. The variants cover all WordKind classification
/// categories: Literal, CommandSubstitution, VariableExpansion,
/// ArithmeticExpansion, and Dynamic (mixed).
fn arb_assignment_value() -> impl Strategy<Value = String> {
    prop_oneof![
        // ── Static / Literal ──
        3 => arb_literal_value(),
        // ── Command substitution: $(cmd) ──
        2 => arb_cmd_name().prop_map(|cmd| format!("$({cmd})")),
        // ── Command substitution: $(cmd arg) ──
        1 => (arb_cmd_name(), arb_cmd_name())
            .prop_map(|(cmd, arg)| format!("$({cmd} {arg})")),
        // ── Backtick command substitution: `cmd` ──
        2 => arb_cmd_name().prop_map(|cmd| format!("`{cmd}`")),
        // ── Variable expansion: $VAR ──
        2 => arb_var_name().prop_map(|var| format!("${var}")),
        // ── Variable expansion: ${VAR} ──
        2 => arb_var_name().prop_map(|var| format!("${{{var}}}")),
        // ── Variable expansion: ${VAR:-default} ──
        1 => (arb_var_name(), arb_nonempty_literal())
            .prop_map(|(var, def)| format!("${{{var}:-{def}}}")),
        // ── Arithmetic expansion: $((expr)) ──
        2 => (1u32..100, 1u32..100)
            .prop_map(|(a, b)| format!("$(({a}+{b}))")),
        // ── Mixed: literal$(cmd) — Dynamic/CommandSubstitution ──
        1 => (arb_nonempty_literal(), arb_cmd_name())
            .prop_map(|(lit, cmd)| format!("{lit}$({cmd})")),
        // ── Mixed: $VAR$(cmd) — Dynamic ──
        1 => (arb_var_name(), arb_cmd_name())
            .prop_map(|(var, cmd)| format!("${var}$({cmd})")),
        // ── Mixed: literal$VAR — VariableExpansion ──
        1 => (arb_nonempty_literal(), arb_var_name())
            .prop_map(|(lit, var)| format!("{lit}${var}")),
        // ── Mixed: $(cmd)$((expr)) — Dynamic ──
        1 => (arb_cmd_name(), 1u32..50, 1u32..50)
            .prop_map(|(cmd, a, b)| format!("$({cmd})$(({a}+{b}))")),
        // ── Nested command substitution: $(cmd $(inner)) ──
        2 => (arb_cmd_name(), arb_cmd_name())
            .prop_map(|(outer, inner)| format!("$({outer} $({inner}))")),
        // ── Command substitution containing variable expansion: $(cmd ${VAR}) ──
        2 => (arb_cmd_name(), arb_var_name())
            .prop_map(|(cmd, var)| format!("$({cmd} ${{{var}}})")),
        // ── Variable expansion with command substitution default: ${VAR:-$(cmd)} ──
        2 => (arb_var_name(), arb_cmd_name())
            .prop_map(|(var, cmd)| format!("${{{var}:-$({cmd})}}")),
    ]
}

/// Generate a complete well-formed shell assignment string: `KEY=VALUE`.
fn arb_assignment() -> impl Strategy<Value = String> {
    (arb_env_key(), arb_assignment_value()).prop_map(|(key, value)| format!("{key}={value}"))
}

// ── Command-word generators ─────────────────────────────────────────────────

/// Generate a command word (not an assignment value) for expansion testing.
///
/// Each variant produces a syntactically valid shell word that might appear
/// as the command name in a pipeline segment. The proptest verifies that
/// `Word::is_expansion()` agrees with `starts_with('$')` — the structural
/// check must match the string-level heuristic for command words.
fn arb_command_word() -> impl Strategy<Value = String> {
    prop_oneof![
        // ── Literal command name ──
        3 => arb_cmd_name(),
        // ── Variable expansion: $CMD ──
        2 => arb_var_name().prop_map(|var| format!("${var}")),
        // ── Variable expansion: ${CMD} ──
        2 => arb_var_name().prop_map(|var| format!("${{{var}}}")),
        // ── Command substitution: $(cmd) ──
        2 => arb_cmd_name().prop_map(|cmd| format!("$({cmd})")),
        // ── Backtick substitution: `cmd` ──
        2 => arb_cmd_name().prop_map(|cmd| format!("`{cmd}`")),
        // ── Arithmetic expansion: $((expr)) ──
        1 => (1u32..100, 1u32..100)
            .prop_map(|(a, b)| format!("$(({a}+{b}))")),
        // ── Nested: $(cmd $(inner)) ──
        1 => (arb_cmd_name(), arb_cmd_name())
            .prop_map(|(outer, inner)| format!("$({outer} $({inner}))")),
        // ── Literal path command ──
        2 => arb_cmd_name().prop_map(|cmd| format!("/usr/bin/{cmd}")),
    ]
}

// ── Properties ──────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// Metamorphic property: for any well-formed shell assignment, tree-sitter
    /// classification and byte-scanning classification agree on the
    /// AssignmentValue category. When they disagree, the byte scanner must be
    /// at least as restrictive as tree-sitter (never less).
    ///
    /// This is the safety invariant for the AST-purity migration: if the
    /// system falls back to byte scanning (Unclassified words from string
    /// construction or shlex), it must never produce a LESS conservative
    /// classification than the tree-sitter structural path.
    ///
    /// Oracle: the restrictiveness ordering Static < VariableExpansion <
    /// CommandSubstitution is defined independently of both classification
    /// paths.
    #[test]
    fn tree_sitter_agrees_with_byte_scanning(assignment in arb_assignment()) {
        // ── Path 1: tree-sitter classification ──────────────────────────
        //
        // Parse the assignment through tree-sitter, extract the Word with
        // structural WordKind, and classify via as_classified_assignment().
        let pipeline = parse_with_substitutions(&assignment)
            .expect("well-formed assignment should parse");
        prop_assert!(
            !pipeline.segments.is_empty(),
            "parse produced no segments for {:?}",
            assignment
        );
        prop_assert!(
            !pipeline.segments[0].words.is_empty(),
            "segment has no words for {:?}",
            assignment
        );

        let ts_word = &pipeline.segments[0].words[0];

        // Tree-sitter must have classified this word (not Unclassified).
        // Unclassified means the tree-sitter path failed to provide
        // structural metadata — a gap in the AST-purity migration.
        prop_assert_ne!(
            ts_word.kind(),
            WordKind::Unclassified,
            "tree-sitter produced Unclassified for {:?} — \
             AST classification gap",
            assignment
        );

        let ts_result = ts_word.as_classified_assignment();
        prop_assert!(
            ts_result.is_some(),
            "tree-sitter word {:?} (kind={:?}) is not a valid assignment",
            ts_word.as_str(),
            ts_word.kind()
        );
        let (ts_key, ts_value) = ts_result.unwrap();

        // ── Path 2: byte-scanning classification ────────────────────────
        //
        // Create a Word::from() (Unclassified) and classify via
        // as_classified_assignment(), which falls back to
        // AssignmentValue::classify() byte scanning.
        let bs_word = Word::from(assignment.as_str());
        prop_assert_eq!(
            bs_word.kind(),
            WordKind::Unclassified,
            "Word::from must produce Unclassified"
        );

        let bs_result = bs_word.as_classified_assignment();
        prop_assert!(
            bs_result.is_some(),
            "byte-scanning word {:?} is not a valid assignment",
            assignment
        );
        let (bs_key, bs_value) = bs_result.unwrap();

        // ── Keys must agree ─────────────────────────────────────────────
        prop_assert_eq!(
            ts_key, bs_key,
            "keys diverged: tree-sitter={:?} vs byte-scanner={:?} for {:?}",
            ts_key, bs_key, assignment
        );

        // ── Safety invariant ────────────────────────────────────────────
        //
        // byte_scanner_restrictiveness >= tree_sitter_restrictiveness
        //
        // If they agree (equal rank): the classification is consistent.
        // If byte scanner is MORE restrictive: safe — the fallback path
        //   is conservative. Expected for some edge cases.
        // If byte scanner is LESS restrictive: SAFETY VIOLATION — the
        //   fallback path would under-classify a dangerous value.
        let ts_rank = restrictiveness(&ts_value);
        let bs_rank = restrictiveness(&bs_value);

        prop_assert!(
            bs_rank >= ts_rank,
            "SAFETY VIOLATION: byte scanner ({}, rank={}) is LESS \
             restrictive than tree-sitter ({}, rank={}) for {:?}",
            classification_label(&bs_value),
            bs_rank,
            classification_label(&ts_value),
            ts_rank,
            assignment
        );
    }

    /// Metamorphic property: for command words (not assignment values),
    /// `Word::is_expansion()` must agree with `starts_with('$')` or
    /// `contains('`')`.
    ///
    /// This covers the `resolve.rs` / `tokenize.rs` path where command-name
    /// classification gates whether a pipeline segment is treated as indirect
    /// execution. The structural check (tree-sitter WordKind) must match the
    /// string-level heuristic for all generated command words.
    ///
    /// Oracle: a command word is an expansion if and only if it starts with
    /// `$` or contains a backtick — defined independently of both the
    /// structural and byte-scanning classification paths.
    #[test]
    fn command_name_expansion_agrees_with_string_check(word_text in arb_command_word()) {
        let string_says_expansion =
            word_text.starts_with('$') || word_text.contains('`');

        // ── Classified word (simulating tree-sitter path) ──────────────
        //
        // Parse a dummy command line through tree-sitter to get structural
        // classification of the command word.
        let dummy_cmd = format!("{word_text} arg");
        let pipeline = parse_with_substitutions(&dummy_cmd);

        if let Ok(pipeline) = pipeline {
            if let Some(seg) = pipeline.segments.first() {
                if let Some(ts_word) = seg.words.first() {
                    let structural_says_expansion = ts_word.is_expansion();
                    prop_assert_eq!(
                        structural_says_expansion,
                        string_says_expansion,
                        "tree-sitter is_expansion()={} but string check={} for {:?} (kind={:?})",
                        structural_says_expansion,
                        string_says_expansion,
                        word_text,
                        ts_word.kind()
                    );
                }
            }
        }

        // ── Unclassified word (simulating byte-scanning path) ──────────
        //
        // Word::from produces Unclassified — is_expansion() falls back to
        // checking for $ or backtick characters.
        let bs_word = Word::from(word_text.as_str());
        let byte_says_expansion = bs_word.is_expansion();

        prop_assert_eq!(
            byte_says_expansion,
            string_says_expansion,
            "byte-scanning is_expansion()={} but string check={} for {:?}",
            byte_says_expansion,
            string_says_expansion,
            word_text
        );
    }
}
