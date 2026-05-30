//! Word extraction tests for the shell parser.
//!
//! These verify the `words` field on [`ShellSegment`] — pre-tokenized word
//! lists that correctly preserve substitution syntax as single tokens.

use super::parse_with_substitutions;
use super::ParsedPipeline;

fn parse(cmd: &str) -> ParsedPipeline {
    parse_with_substitutions(cmd).expect("parse failed")
}

#[test]
fn words_simple_command() {
    let p = parse("ls -la /tmp");
    assert_eq!(p.segments[0].words, vec!["ls", "-la", "/tmp"]);
}

#[test]
fn words_with_substitution_preserved() {
    // The key correctness case: shlex would split inside $(...)
    let p = parse("echo $(date) stuff");
    assert_eq!(p.segments[0].words, vec!["echo", "$(date)", "stuff"]);
}

#[test]
fn words_export_with_substitution() {
    // export FOO=$(echo test) BAR=baz — shlex gets this wrong
    let p = parse("export FOO=$(echo test) BAR=baz");
    assert_eq!(
        p.segments[0].words,
        vec!["export", "FOO=$(echo test)", "BAR=baz"]
    );
}

#[test]
fn words_env_var_prefix() {
    let p = parse("FOO=bar git push");
    assert_eq!(p.segments[0].words, vec!["FOO=bar", "git", "push"]);
}

#[test]
fn words_quoted_string() {
    let p = parse("git commit -m 'test message'");
    // Quotes are stripped — consumers get semantic content
    assert_eq!(
        p.segments[0].words,
        vec!["git", "commit", "-m", "test message"]
    );
}

#[test]
fn words_double_quoted_string() {
    let p = parse(r#"echo "hello world""#);
    assert_eq!(p.segments[0].words, vec!["echo", "hello world"]);
}

#[test]
fn words_backtick_substitution() {
    let p = parse("echo `date` more");
    assert_eq!(p.segments[0].words, vec!["echo", "`date`", "more"]);
}

#[test]
fn words_process_substitution() {
    let p = parse("diff <(ls a) <(ls b)");
    assert_eq!(p.segments[0].words, vec!["diff", "<(ls a)", "<(ls b)"]);
}

#[test]
fn words_unset_command() {
    let p = parse("unset FOO BAR");
    assert_eq!(p.segments[0].words, vec!["unset", "FOO", "BAR"]);
}

#[test]
fn words_compound_segments() {
    let p = parse("echo a && ls -la");
    assert_eq!(p.segments[0].words, vec!["echo", "a"]);
    assert_eq!(p.segments[1].words, vec!["ls", "-la"]);
}

#[test]
fn words_piped_segments() {
    let p = parse("ls | grep foo");
    assert_eq!(p.segments[0].words, vec!["ls"]);
    assert_eq!(p.segments[1].words, vec!["grep", "foo"]);
}

#[test]
fn words_nested_substitution() {
    let p = parse("echo $(cat $(find . -name foo))");
    // Outer segment includes the full substitution as one word
    assert_eq!(
        p.segments[0].words,
        vec!["echo", "$(cat $(find . -name foo))"]
    );
    // Inner substitution's segment
    let inner = &p.segments[0].substitutions[0].pipeline;
    assert_eq!(inner.segments[0].words, vec!["cat", "$(find . -name foo)"]);
    // Innermost
    let innermost = &inner.segments[0].substitutions[0].pipeline;
    assert_eq!(
        innermost.segments[0].words,
        vec!["find", ".", "-name", "foo"]
    );
}

#[test]
fn words_for_loop_body() {
    let p = parse("for i in *; do echo $i; done");
    let echo_seg = p
        .segments
        .iter()
        .find(|s| s.command.contains("echo"))
        .unwrap();
    assert_eq!(echo_seg.words, vec!["echo", "$i"]);
}

#[test]
fn words_declaration_with_flags() {
    let p = parse("declare -x FOO=bar");
    assert_eq!(p.segments[0].words, vec!["declare", "-x", "FOO=bar"]);
}

#[test]
fn words_test_command_double_bracket_file() {
    // tree-sitter extraction of [[ -f "foo" ]]
    let p = parse(r#"[[ -f "foo" ]]"#);
    assert_eq!(p.segments[0].words, vec!["[[", "-f", "foo", "]]"]);
}

#[test]
fn words_test_command_single_bracket_z() {
    // tree-sitter extraction of [ -z "$var" ]
    let p = parse(r#"[ -z "$var" ]"#);
    assert_eq!(p.segments[0].words, vec!["[", "-z", "$var", "]"]);
}

#[test]
fn words_test_command_binary_comparison() {
    // tree-sitter extraction of [[ "$a" == "$b" ]]
    let p = parse(r#"[[ "$a" == "$b" ]]"#);
    assert_eq!(p.segments[0].words, vec!["[[", "$a", "==", "$b", "]]"]);
}

#[test]
fn words_test_command_quoted_with_spaces() {
    // Quoted strings in test commands should have quotes stripped
    let p = parse(r#"[[ -f "foo bar" ]]"#);
    assert_eq!(p.segments[0].words, vec!["[[", "-f", "foo bar", "]]"]);
}

#[test]
fn words_variable_assignment_standalone() {
    let p = parse("FOO=bar");
    assert_eq!(p.segments[0].words, vec!["FOO=bar"]);
}

#[test]
fn words_variable_assignments_plural() {
    let p = parse("FOO=bar BAZ=qux");
    assert_eq!(p.segments[0].words, vec!["FOO=bar", "BAZ=qux"]);
}

#[test]
fn words_substitution_in_second_segment() {
    let p = parse("echo hi && echo $(date)");
    assert_eq!(p.segments[0].words, vec!["echo", "hi"]);
    assert_eq!(p.segments[1].words, vec!["echo", "$(date)"]);
}

#[test]
fn words_multiple_substitutions() {
    let p = parse("echo $(date) $(whoami)");
    assert_eq!(p.segments[0].words, vec!["echo", "$(date)", "$(whoami)"]);
}

#[test]
fn words_with_redirect_excluded() {
    // Redirects should not appear in the word list
    let p = parse("echo hello > /tmp/out");
    assert_eq!(p.segments[0].words, vec!["echo", "hello"]);
}

#[test]
fn words_concatenation() {
    // Concatenation (e.g. ${FOO}bar) is one word in tree-sitter
    let p = parse("echo ${FOO}bar");
    assert_eq!(p.segments[0].words, vec!["echo", "${FOO}bar"]);
}

#[test]
fn words_heredoc_command() {
    // Command before heredoc should have words (via tree-sitter extraction)
    let p = parse("cat <<EOF\nhello\nEOF");
    let cat_seg = p
        .segments
        .iter()
        .find(|s| s.command.contains("cat"))
        .unwrap();
    assert_eq!(cat_seg.words, vec!["cat"]);
}
