//! Shell command parsing backed by tree-sitter-bash.
//!
//! Public API:
//!
//! - [`parse_with_substitutions`] — decomposes a shell command into a
//!   recursive [`ParsedPipeline`] tree.
//! - [`has_output_redirection`] — mutation-detection for redirects.
//! - [`dump_ast`] — diagnostic output.
//!
//! The parser uses tree-sitter-bash for a full AST, then walks it to
//! produce segments joined by operators. Substitutions (`$()`, backticks,
//! `<()`, `>()`) are recursively parsed into nested pipelines — the
//! result is a tree that can be evaluated bottom-up (catamorphism).
//!
//! # Control flow handling
//!
//! Shell keywords (`for`, `if`, `while`, `case`) are grammar structure,
//! not commands. The walker recurses into their bodies and extracts the
//! actual commands as segments.
//!
//! # Redirection propagation
//!
//! When a control flow construct has output redirection
//! (e.g. `for ... done > file`), it propagates to inner segments via
//! [`ShellSegment::redirection`].

use super::redirect::detect_redirections;
use super::subst::{assign_substitutions, build_segments, collect_substitutions};
use super::types::{ParseError, ParsedPipeline, ShellSegment, Word};
use super::walk::walk_ast;
use std::cell::{Cell, RefCell};
use tree_sitter::{Parser, Tree};

/// Maximum number of tree-sitter parse calls across all recursion levels.
/// Prevents exponential fan-out DoS (e.g. `echo $(a) $(b) $(c) ...` nested).
const MAX_TOTAL_PARSES: usize = 512;

/// Maximum input length accepted by the parser (64 KiB).
const MAX_INPUT_LENGTH: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Thread-local parser
// ---------------------------------------------------------------------------

thread_local! {
    /// tree-sitter `Parser` is `!Send`, so we use `thread_local!` storage.
    ///
    /// # Async safety
    ///
    /// The `RefCell` borrow is acquired and released within the synchronous
    /// `parse_tree()` call — it never crosses an `.await` point. Each
    /// thread in an async runtime pool gets its own parser instance.
    /// `parse_tree()` must remain synchronous.
    static TS_PARSER: RefCell<Parser> = RefCell::new({
        let mut p = Parser::new();
        p.set_language(&tree_sitter_bash::LANGUAGE.into())
            .expect("failed to load bash grammar");
        p
    });
}

fn parse_tree(source: &str, budget: &Cell<usize>) -> Result<Tree, ParseError> {
    let count = budget.get();
    if count >= MAX_TOTAL_PARSES {
        return Err(ParseError);
    }
    budget.set(count + 1);
    TS_PARSER.with(|p| p.borrow_mut().parse(source, None).ok_or(ParseError))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a shell command into a recursive pipeline tree.
///
/// Substitutions are recursively parsed: `echo $(cmd1 && cmd2)` produces
/// a segment whose substitution contains a two-segment pipeline. The tree
/// can be evaluated bottom-up — inner substitutions execute first.
///
/// Recursion depth is capped at 32 levels. Deeper nesting produces an
/// empty pipeline with `has_parse_errors: true`.
pub fn parse_with_substitutions(command: &str) -> Result<ParsedPipeline, ParseError> {
    if command.len() > MAX_INPUT_LENGTH {
        return Ok(ParsedPipeline::empty_with_error());
    }
    let budget = Cell::new(0);
    parse_with_substitutions_impl(command, 0, &budget)
}

fn parse_with_substitutions_impl(
    command: &str,
    depth: usize,
    budget: &Cell<usize>,
) -> Result<ParsedPipeline, ParseError> {
    let tree = parse_tree(command, budget)?;
    let root = tree.root_node();
    let source = command.as_bytes();
    let has_parse_errors = root.has_error();

    let mut raw_substs = Vec::new();
    collect_substitutions(root, source, &mut raw_substs);

    let walk = walk_ast(root, source);

    let trimmed = command.trim();
    let is_trivial = walk.segments.len() <= 1
        && raw_substs.is_empty()
        && walk
            .segments
            .first()
            .is_none_or(|seg| seg.start == 0 && seg.end >= trimmed.len());

    if is_trivial {
        let first_seg = walk.segments.first();
        let redir = first_seg
            .and_then(|seg| seg.redirection.clone())
            .or_else(|| detect_redirections(root, source));
        let words = first_seg.map(|seg| seg.words.clone()).unwrap_or_else(|| {
            // No segment produced (e.g. empty program) — shlex the trimmed text.
            shlex::split(trimmed)
                .unwrap_or_else(|| trimmed.split_whitespace().map(String::from).collect())
                .into_iter()
                .map(Word::from)
                .collect()
        });
        return Ok(ParsedPipeline {
            segments: vec![ShellSegment {
                command: trimmed.to_string(),
                words,
                redirection: redir,
                substitutions: vec![],
            }],
            operators: vec![],
            structural_substitutions: vec![],
            has_parse_errors,
        });
    }

    let built = build_segments(&walk, command);
    let (per_segment_subs, structural_subs) =
        assign_substitutions(&raw_substs, &built, depth, &|inner, d| {
            parse_with_substitutions_impl(inner, d, budget)
        });

    let segments: Vec<ShellSegment> = built
        .into_iter()
        .zip(per_segment_subs)
        .map(|(b, subs)| ShellSegment {
            command: b.command,
            words: b.words,
            redirection: b.redirection,
            substitutions: subs,
        })
        .collect();

    Ok(ParsedPipeline {
        segments,
        operators: walk.operators,
        structural_substitutions: structural_subs,
        has_parse_errors,
    })
}

/// Check whether `command` contains output redirection.
pub fn has_output_redirection(
    command: &str,
) -> Result<Option<super::types::Redirection>, ParseError> {
    let budget = Cell::new(0);
    let tree = parse_tree(command, &budget)?;
    Ok(detect_redirections(tree.root_node(), command.as_bytes()))
}

/// Diagnostic: dump the tree-sitter AST and parsed pipeline.
///
/// Sections 1 (AST dump) and 3 (redirection check) share a single
/// parse tree. Section 2 (pipeline decomposition) calls
/// [`parse_with_substitutions`] separately — it builds the recursive
/// pipeline structure from scratch.
pub fn dump_ast(command: &str) -> Result<String, ParseError> {
    use std::fmt::Write;
    let mut out = String::new();

    let budget = Cell::new(0);
    let tree = parse_tree(command, &budget)?;
    let root = tree.root_node();
    let source = command.as_bytes();

    // Section 1: raw AST
    writeln!(out, "── tree-sitter AST ──").unwrap();
    fn print_node(out: &mut String, node: tree_sitter::Node, source: &[u8], indent: usize) {
        let text = node.utf8_text(source).unwrap_or("???");
        let short: String = text.chars().take(60).collect();
        let tag = if node.is_named() { "named" } else { "anon" };
        writeln!(
            out,
            "{}{} [{}] {:?}",
            "  ".repeat(indent),
            node.kind(),
            tag,
            short
        )
        .unwrap();
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            print_node(out, child, source, indent + 1);
        }
    }
    print_node(&mut out, root, source, 0);

    // Section 2: parsed pipeline (reuses the public API — separate parse is
    // unavoidable here since parse_with_substitutions_impl builds from scratch,
    // but this is a diagnostic function so the cost is acceptable)
    let pipeline = parse_with_substitutions(command)?;
    writeln!(out, "\n── parsed pipeline ──").unwrap();
    if pipeline.has_parse_errors {
        writeln!(out, "  (parse errors detected — best-effort result)").unwrap();
    }
    fn print_pipeline(out: &mut String, p: &ParsedPipeline, indent: usize) {
        let pad = "  ".repeat(indent);
        for sub in &p.structural_substitutions {
            writeln!(
                out,
                "{pad}structural subst bytes {}..{}:",
                sub.start, sub.end
            )
            .unwrap();
            print_pipeline(out, &sub.pipeline, indent + 1);
        }
        for (i, seg) in p.segments.iter().enumerate() {
            let redir = seg
                .redirection
                .as_ref()
                .map(|r| format!(" [{r}]"))
                .unwrap_or_default();
            writeln!(out, "{pad}segment {i}: {:?}{redir}", seg.command).unwrap();
            if !seg.words.is_empty() {
                writeln!(out, "{pad}  words: {:?}", seg.words).unwrap();
            }
            for sub in &seg.substitutions {
                writeln!(out, "{pad}  subst bytes {}..{}:", sub.start, sub.end).unwrap();
                print_pipeline(out, &sub.pipeline, indent + 2);
            }
            if i < p.operators.len() {
                writeln!(out, "{pad}operator: {}", p.operators[i]).unwrap();
            }
        }
    }
    print_pipeline(&mut out, &pipeline, 1);

    // Section 3: redirection check (reuses the tree from section 1)
    let redir = detect_redirections(root, source);
    writeln!(out, "\n── output redirection ──").unwrap();
    match redir {
        Some(r) => writeln!(out, "  {r}").unwrap(),
        None => writeln!(out, "  (none)").unwrap(),
    }

    Ok(out)
}

#[cfg(test)]
#[path = "shell_inline_tests.rs"]
mod shell_inline_tests;

#[cfg(test)]
#[path = "shell_tests.rs"]
mod shell_tests;
