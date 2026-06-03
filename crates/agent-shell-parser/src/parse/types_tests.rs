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

// --- fold_segments ---

#[test]
fn fold_segments_counts_all() {
    let p = parse("echo a && ls -la && cat file");
    let count = p.fold_segments(0usize, &|acc, _seg| acc + 1);
    assert_eq!(count, 3);
}

#[test]
fn fold_segments_counts_nested() {
    let p = parse("echo $(git status && git diff)");
    let count = p.fold_segments(0usize, &|acc, _seg| acc + 1);
    // "git status", "git diff" (nested), then "echo $(git status && git diff)" (parent)
    assert_eq!(count, 3);
}

#[test]
fn fold_segments_accumulates_value() {
    let p = parse("echo a && echo b && echo c");
    let commands = p.fold_segments(String::new(), &|mut acc, seg| {
        if !acc.is_empty() {
            acc.push(',');
        }
        acc.push_str(&seg.command);
        acc
    });
    assert_eq!(commands, "echo a,echo b,echo c");
}

#[test]
fn fold_segments_matches_filter_segments_count() {
    let p = parse("echo $(git status) && ls");
    let filtered: Vec<String> = p.filter_segments(&|seg| Some(seg.command.clone()));
    let folded = p.fold_segments(0usize, &|acc, _seg| acc + 1);
    assert_eq!(folded, filtered.len());
}

#[test]
fn fold_segments_visits_structural_substitutions() {
    let p = parse("for i in $(seq 10); do echo $i; done");
    let first = p.fold_segments(String::new(), &|acc, seg| {
        if acc.is_empty() {
            seg.command.clone()
        } else {
            acc
        }
    });
    assert_eq!(first, "seq 10");
}

#[test]
fn fold_segments_traversal_order_matches_filter_segments() {
    // Stronger than count-only: assert that fold visits segments in the
    // exact same order as filter_segments.
    for input in [
        "echo a && ls -la && cat file",
        "echo $(git status && git diff)",
        "for i in $(seq 10); do echo $i; done",
        "echo $(date) && ls $(pwd) | grep foo",
    ] {
        let p = parse(input);
        let filtered: Vec<String> = p.filter_segments(&|seg| Some(seg.command.clone()));
        let folded: Vec<String> = p.fold_segments(Vec::new(), &|mut acc, seg| {
            acc.push(seg.command.clone());
            acc
        });
        assert_eq!(folded, filtered, "traversal order mismatch for {:?}", input);
    }
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
