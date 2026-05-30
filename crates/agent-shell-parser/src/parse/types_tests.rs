use super::super::parse_with_substitutions;

fn parse(cmd: &str) -> super::ParsedPipeline {
    parse_with_substitutions(cmd).expect("parse failed")
}

// --- find_segment ---

#[test]
fn find_segment_returns_first_match() {
    let p = parse("echo hello && ls -la");
    let found = p.find_segment(&|seg| {
        if seg.command.starts_with("ls") {
            Some(seg.command.clone())
        } else {
            None
        }
    });
    assert_eq!(found.as_deref(), Some("ls -la"));
}

#[test]
fn find_segment_returns_none_when_no_match() {
    let p = parse("echo hello && ls -la");
    let found = p.find_segment(&|seg| {
        if seg.command.starts_with("git") {
            Some(())
        } else {
            None
        }
    });
    assert!(found.is_none());
}

#[test]
fn find_segment_recurses_into_substitutions() {
    let p = parse("echo $(git status)");
    let found = p.find_segment(&|seg| {
        if seg.command.contains("git status") {
            Some(seg.command.clone())
        } else {
            None
        }
    });
    assert_eq!(found.as_deref(), Some("git status"));
}

#[test]
fn find_segment_visits_substitutions_before_parent() {
    // In "echo $(date)", the walker should visit "date" before "echo $(date)".
    // filter_segments with Some for all collects in traversal order.
    let p = parse("echo $(date)");
    let all: Vec<String> = p.filter_segments(&|seg| Some(seg.command.clone()));
    assert_eq!(all, vec!["date", "echo $(date)"]);
}

#[test]
fn find_segment_visits_structural_substitutions_first() {
    let p = parse("for i in $(seq 10); do echo $i; done");
    let all: Vec<String> = p.filter_segments(&|seg| Some(seg.command.clone()));
    assert_eq!(all[0], "seq 10");
}

// --- filter_segments ---

#[test]
fn filter_segments_collects_all_matches() {
    let p = parse("echo a && echo b && ls c");
    let echoes: Vec<String> = p.filter_segments(&|seg| {
        if seg.command.starts_with("echo") {
            Some(seg.command.clone())
        } else {
            None
        }
    });
    assert_eq!(echoes, vec!["echo a", "echo b"]);
}

#[test]
fn filter_segments_collects_from_nested() {
    let p = parse("echo $(git status && git diff)");
    let gits: Vec<String> = p.filter_segments(&|seg| {
        if seg.command.starts_with("git") {
            Some(seg.command.clone())
        } else {
            None
        }
    });
    assert_eq!(gits, vec!["git status", "git diff"]);
}

// --- has_parse_errors_recursive ---

#[test]
fn no_errors_on_valid_input() {
    assert!(!parse("echo hello").has_parse_errors_recursive());
}

#[test]
fn no_errors_on_compound() {
    assert!(!parse("echo a && echo b | cat").has_parse_errors_recursive());
}

#[test]
fn no_errors_on_substitution() {
    assert!(!parse("echo $(date)").has_parse_errors_recursive());
}
