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

/// Simple command name for use inside substitutions.
fn arb_cmd_name() -> impl Strategy<Value = String> {
    "[a-z]{2,6}"
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
    ]
}

/// Generate a complete well-formed shell assignment string: `KEY=VALUE`.
fn arb_assignment() -> impl Strategy<Value = String> {
    (arb_env_key(), arb_assignment_value()).prop_map(|(key, value)| format!("{key}={value}"))
}

// ── Properties ──────────────────────────────────────────────────────────────

proptest! {
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
}
