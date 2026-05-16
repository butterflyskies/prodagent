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
use super::types::{ParseError, ParsedPipeline, ShellSegment};
use super::walk::walk_ast;
use std::cell::RefCell;
use tree_sitter::{Parser, Tree};

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

fn parse_tree(source: &str) -> Result<Tree, ParseError> {
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
    parse_with_substitutions_impl(command, 0)
}

fn parse_with_substitutions_impl(
    command: &str,
    depth: usize,
) -> Result<ParsedPipeline, ParseError> {
    let tree = parse_tree(command)?;
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
        let redir = walk
            .segments
            .first()
            .and_then(|seg| seg.redirection.clone())
            .or_else(|| detect_redirections(root, source));
        return Ok(ParsedPipeline {
            segments: vec![ShellSegment {
                command: trimmed.to_string(),
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
        assign_substitutions(&raw_substs, &built, depth, &parse_with_substitutions_impl);

    let segments: Vec<ShellSegment> = built
        .into_iter()
        .zip(per_segment_subs)
        .map(|(b, subs)| ShellSegment {
            command: b.command,
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
    let tree = parse_tree(command)?;
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

    let tree = parse_tree(command)?;
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
                .map(|r| format!(" [{}]", r.description))
                .unwrap_or_default();
            writeln!(out, "{pad}segment {i}: {:?}{redir}", seg.command).unwrap();
            for sub in &seg.substitutions {
                writeln!(out, "{pad}  subst bytes {}..{}:", sub.start, sub.end).unwrap();
                print_pipeline(out, &sub.pipeline, indent + 2);
            }
            if i < p.operators.len() {
                writeln!(out, "{pad}operator: {}", p.operators[i].as_str()).unwrap();
            }
        }
    }
    print_pipeline(&mut out, &pipeline, 1);

    // Section 3: redirection check (reuses the tree from section 1)
    let redir = detect_redirections(root, source);
    writeln!(out, "\n── output redirection ──").unwrap();
    match redir {
        Some(r) => writeln!(out, "  {}", r.description).unwrap(),
        None => writeln!(out, "  (none)").unwrap(),
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(cmd: &str) -> ParsedPipeline {
        parse_with_substitutions(cmd).expect("parse failed")
    }

    // --- Compound splitting ---

    #[test]
    fn simple_command() {
        let p = parse("ls -la");
        assert_eq!(p.segments.len(), 1);
        assert_eq!(p.segments[0].command, "ls -la");
        assert!(p.operators.is_empty());
        assert!(p.segments[0].substitutions.is_empty());
        assert!(p.structural_substitutions.is_empty());
    }

    #[test]
    fn pipe() {
        let p = parse("ls | grep foo");
        assert_eq!(p.segments.len(), 2);
        assert_eq!(p.segments[0].command, "ls");
        assert_eq!(p.segments[1].command, "grep foo");
        assert_eq!(p.operators, vec![super::super::types::Operator::Pipe]);
    }

    #[test]
    fn and_then() {
        let p = parse("mkdir foo && cd foo");
        assert_eq!(p.segments.len(), 2);
        assert_eq!(p.operators, vec![super::super::types::Operator::And]);
    }

    #[test]
    fn or_else() {
        let p = parse("test -f x || echo missing");
        assert_eq!(p.segments.len(), 2);
        assert_eq!(p.operators, vec![super::super::types::Operator::Or]);
    }

    #[test]
    fn semicolon() {
        let p = parse("echo a; echo b");
        assert_eq!(p.segments.len(), 2);
        assert_eq!(p.segments[0].command, "echo a");
        assert_eq!(p.segments[1].command, "echo b");
    }

    #[test]
    fn triple_and() {
        let p = parse("a && b && c");
        assert_eq!(p.segments.len(), 3);
        assert_eq!(
            p.operators,
            vec![
                super::super::types::Operator::And,
                super::super::types::Operator::And
            ]
        );
    }

    #[test]
    fn mixed_operators() {
        let p = parse("a && b || c");
        assert_eq!(p.segments.len(), 3);
        assert_eq!(
            p.operators,
            vec![
                super::super::types::Operator::And,
                super::super::types::Operator::Or
            ]
        );
    }

    #[test]
    fn quoted_operator_not_split() {
        let p = parse(r#"echo "a && b""#);
        assert_eq!(p.segments.len(), 1);
    }

    // --- Substitutions (recursive) ---

    #[test]
    fn dollar_paren_substitution() {
        let p = parse("echo $(date)");
        assert_eq!(p.segments[0].command, "echo $(date)");
        assert_eq!(p.segments[0].substitutions.len(), 1);
        let sub = &p.segments[0].substitutions[0];
        assert_eq!(sub.pipeline.segments.len(), 1);
        assert_eq!(sub.pipeline.segments[0].command, "date");
    }

    #[test]
    fn backtick_substitution() {
        let p = parse("echo `date`");
        assert_eq!(p.segments[0].command, "echo `date`");
        assert_eq!(p.segments[0].substitutions.len(), 1);
        assert_eq!(
            p.segments[0].substitutions[0].pipeline.segments[0].command,
            "date"
        );
    }

    #[test]
    fn single_quoted_not_substituted() {
        let p = parse("echo '$(date)'");
        assert!(p.segments[0].substitutions.is_empty());
    }

    #[test]
    fn double_quoted_is_substituted() {
        let p = parse(r#"echo "$(date)""#);
        assert_eq!(p.segments[0].substitutions.len(), 1);
    }

    #[test]
    fn process_substitution() {
        let p = parse("diff <(ls a) <(ls b)");
        assert_eq!(p.segments[0].substitutions.len(), 2);
        assert_eq!(
            p.segments[0].substitutions[0].pipeline.segments[0].command,
            "ls a"
        );
        assert_eq!(
            p.segments[0].substitutions[1].pipeline.segments[0].command,
            "ls b"
        );
    }

    #[test]
    fn nested_substitution() {
        let p = parse("echo $(cat $(find . -name foo))");
        assert_eq!(p.segments[0].substitutions.len(), 1);
        let outer = &p.segments[0].substitutions[0].pipeline;
        assert_eq!(outer.segments[0].substitutions.len(), 1);
        let inner = &outer.segments[0].substitutions[0].pipeline;
        assert_eq!(inner.segments[0].command, "find . -name foo");
    }

    #[test]
    fn substitution_byte_positions() {
        let p = parse("echo $(date)");
        let sub = &p.segments[0].substitutions[0];
        // "echo $(date)" — $(date) starts at byte 5, ends at 12
        assert_eq!(sub.start, 5);
        assert_eq!(sub.end, 12);
        assert_eq!(&p.segments[0].command[sub.start..sub.end], "$(date)");
    }

    #[test]
    fn substitution_in_second_segment() {
        let p = parse("echo hi && echo $(date)");
        assert!(p.segments[0].substitutions.is_empty());
        assert_eq!(p.segments[1].substitutions.len(), 1);
        let sub = &p.segments[1].substitutions[0];
        assert_eq!(&p.segments[1].command[sub.start..sub.end], "$(date)");
    }

    #[test]
    fn compound_substitution_content() {
        let p = parse("echo $(cmd1 && cmd2)");
        let inner = &p.segments[0].substitutions[0].pipeline;
        assert_eq!(inner.segments.len(), 2);
        assert_eq!(inner.operators, vec![super::super::types::Operator::And]);
    }

    // --- Structural (orphan) substitutions ---

    #[test]
    fn structural_substitution_in_for_loop() {
        let p = parse("for i in $(seq 10); do echo $i; done");
        assert_eq!(p.structural_substitutions.len(), 1);
        assert_eq!(
            p.structural_substitutions[0].pipeline.segments[0].command,
            "seq 10"
        );
    }

    #[test]
    fn structural_substitution_in_case_subject() {
        let p = parse("case $(git status) in clean) echo ok ;; esac");
        assert_eq!(p.structural_substitutions.len(), 1);
        assert_eq!(
            p.structural_substitutions[0].pipeline.segments[0].command,
            "git status"
        );
    }

    // --- Control flow ---

    #[test]
    fn for_loop_extracts_body() {
        let p = parse("for i in *; do echo \"$i\"; done");
        assert!(p.segments.iter().all(|s| !s.command.starts_with("for")));
        assert!(p.segments.iter().any(|s| s.command.contains("echo")));
    }

    #[test]
    fn if_statement_extracts_body() {
        let p = parse("if test -f x; then echo yes; fi");
        assert!(p.segments.iter().any(|s| s.command.contains("test")));
        assert!(p.segments.iter().any(|s| s.command.contains("echo")));
    }

    #[test]
    fn while_loop_extracts_body() {
        let p = parse("while true; do sleep 1; done");
        assert!(p.segments.iter().any(|s| s.command.contains("true")));
        assert!(p.segments.iter().any(|s| s.command.contains("sleep")));
    }

    #[test]
    fn case_pattern_not_treated_as_command() {
        let p = parse(r#"case $x in rm) echo hi ;; kubectl) echo bye ;; esac"#);
        assert!(!p.segments.iter().any(|s| s.command.trim() == "rm"));
        assert!(p.segments.iter().any(|s| s.command.contains("echo hi")));
    }

    #[test]
    fn if_test_command_extracted() {
        let p = parse("if [[ -f foo ]]; then git commit; fi");
        assert!(p.segments.iter().any(|s| s.command.contains("[[")));
        assert!(p.segments.iter().any(|s| s.command.contains("git commit")));
    }

    #[test]
    fn if_test_command_substitution_has_segment() {
        let p = parse(r#"if [[ $(git status) == "clean" ]]; then echo ok; fi"#);
        let test_seg = p
            .segments
            .iter()
            .find(|s| s.command.contains("[["))
            .unwrap();
        assert_eq!(test_seg.substitutions.len(), 1);
        assert_eq!(
            test_seg.substitutions[0].pipeline.segments[0].command,
            "git status"
        );
    }

    #[test]
    fn compound_heredoc_pipe_unwraps_body() {
        let cmd = "while true; do shred /dev/sda; done <<EOF | cat\nstuff\nEOF";
        let p = parse(cmd);
        assert!(!p.segments.iter().any(|s| s.command.starts_with("while")));
        assert!(p.segments.iter().any(|s| s.command.contains("shred")));
        assert!(p.segments.iter().any(|s| s.command.trim() == "cat"));
    }

    // --- Background operator ---

    #[test]
    fn background_operator() {
        let p = parse("sleep 10 & git commit -m test");
        assert_eq!(p.segments.len(), 2);
        assert_eq!(p.segments[0].command, "sleep 10");
        assert_eq!(p.segments[1].command, "git commit -m test");
        assert_eq!(p.operators, vec![super::super::types::Operator::Background]);
    }

    // --- Redirection detection ---

    #[test]
    fn redir_simple_gt() {
        assert!(has_output_redirection("echo hi > file").unwrap().is_some());
    }

    #[test]
    fn redir_append() {
        assert!(has_output_redirection("echo hi >> file").unwrap().is_some());
    }

    #[test]
    fn no_redir_devnull() {
        assert!(has_output_redirection("cmd > /dev/null").unwrap().is_none());
    }

    #[test]
    fn no_redir_fd_dup() {
        assert!(has_output_redirection("cmd 2>&1").unwrap().is_none());
    }

    #[test]
    fn no_redir_fd_close() {
        assert!(has_output_redirection("cmd >&-").unwrap().is_none());
    }

    #[test]
    fn redir_custom_fd_target() {
        let r = has_output_redirection("cmd >&3").unwrap();
        assert!(r.is_some());
        assert!(r.unwrap().description.contains("custom fd target"));
    }

    #[test]
    fn redir_clobber() {
        assert!(has_output_redirection("echo hi >| file.txt")
            .unwrap()
            .is_some());
    }

    #[test]
    fn redir_read_write() {
        let r = has_output_redirection("cat <> file.txt").unwrap();
        assert!(r.is_some());
    }

    // --- Redirection propagation ---

    #[test]
    fn redirect_list_only_last_segment() {
        let p = parse("export FOO=bar && cat > /tmp/file");
        assert!(p.segments[0].redirection.is_none());
        assert!(p.segments[1].redirection.is_some());
    }

    #[test]
    fn redirect_for_loop_all_segments() {
        let p = parse("for i in *; do echo $i; done > /tmp/out");
        assert!(p.segments.iter().all(|s| s.redirection.is_some()));
    }

    #[test]
    fn redirect_pipeline_only_last() {
        let p = parse("echo hello | cat > /tmp/file");
        assert!(p.segments[0].redirection.is_none());
        assert!(p.segments[1].redirection.is_some());
    }

    // --- has_parse_errors ---

    #[test]
    fn well_formed_no_errors() {
        assert!(!parse("echo hello").has_parse_errors);
    }

    // --- Recursion depth limit ---

    #[test]
    fn deeply_nested_substitutions_capped() {
        let mut cmd = "echo x".to_string();
        for _ in 0..40 {
            cmd = format!("echo $({cmd})");
        }
        let p = parse(&cmd);
        // Should not stack overflow. Inner pipelines beyond depth 32 have
        // has_parse_errors: true and empty segments.
        assert_eq!(p.segments.len(), 1);
        assert!(p.has_parse_errors_recursive());

        // Walk into substitution chain to verify depth cap
        let mut current = &p;
        for _ in 0..33 {
            let sub = &current.segments[0].substitutions[0];
            current = &sub.pipeline;
        }
        // At depth 33 (past the cap of 32), should have parse errors
        assert!(current.has_parse_errors);
        assert!(current.segments.is_empty());
    }

    // --- Background operator ---

    #[test]
    fn background_and_disown() {
        let p = parse("waybar & disown");
        assert_eq!(p.segments.len(), 2);
        assert_eq!(p.segments[0].command, "waybar");
        assert_eq!(p.segments[1].command, "disown");
        assert_eq!(p.operators, vec![super::super::types::Operator::Background]);
    }

    // --- Structural substitution byte offsets ---

    #[test]
    fn structural_substitution_byte_offsets() {
        // "for i in $(seq 10); do echo $i; done"
        //           ^        ^
        //           10       20
        let cmd = "for i in $(seq 10); do echo $i; done";
        let p = parse(cmd);
        assert_eq!(p.structural_substitutions.len(), 1);
        let sub = &p.structural_substitutions[0];
        assert_eq!(&cmd[sub.start..sub.end], "$(seq 10)");
    }

    // --- Redirect edge cases ---

    #[test]
    fn no_redir_fd_close_input() {
        assert!(has_output_redirection("cmd <&-").unwrap().is_none());
    }

    #[test]
    fn no_redir_fd_close_2() {
        assert!(has_output_redirection("cmd 2>&-").unwrap().is_none());
    }

    // --- Additional AST node coverage ---

    #[test]
    fn until_loop_extracts_body() {
        let p = parse("until false; do echo waiting; sleep 1; done");
        assert!(!p.segments.iter().any(|s| s.command.starts_with("until")));
        assert!(p.segments.iter().any(|s| s.command.contains("echo")));
        assert!(p.segments.iter().any(|s| s.command.contains("sleep")));
    }

    #[test]
    fn elif_clause_extracts_all_branches() {
        let p = parse("if test -f a; then echo a; elif test -f b; then echo b; else echo c; fi");
        assert!(p.segments.iter().any(|s| s.command.contains("test -f a")));
        assert!(p.segments.iter().any(|s| s.command.contains("echo a")));
        assert!(p.segments.iter().any(|s| s.command.contains("test -f b")));
        assert!(p.segments.iter().any(|s| s.command.contains("echo b")));
        assert!(p.segments.iter().any(|s| s.command.contains("echo c")));
    }

    #[test]
    fn function_definition_body_extracted() {
        let p = parse("foo() { echo hello; ls; }");
        assert!(p.segments.iter().any(|s| s.command.contains("echo hello")));
        assert!(p.segments.iter().any(|s| s.command == "ls"));
        assert!(!p.segments.iter().any(|s| s.command.contains("foo()")));
    }

    #[test]
    fn c_style_for_loop() {
        let p = parse("for ((i=0; i<10; i++)); do echo $i; done");
        assert!(p.segments.iter().any(|s| s.command.contains("echo")));
    }

    #[test]
    fn negated_command_extracts_inner() {
        let p = parse("! git status");
        assert!(p.segments.iter().any(|s| s.command.contains("git status")));
    }

    #[test]
    fn pipe_err_operator() {
        let p = parse("cmd1 |& cmd2");
        assert_eq!(p.segments.len(), 2);
        assert_eq!(p.operators, vec![super::super::types::Operator::PipeErr]);
    }

    #[test]
    fn function_with_for_body() {
        let p = parse("f() for i in *; do echo $i; done");
        assert!(p.segments.iter().any(|s| s.command.contains("echo")));
    }
}
