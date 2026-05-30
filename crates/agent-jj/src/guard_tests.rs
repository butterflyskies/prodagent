use super::*;
use agent_shell_parser::parse::parse_with_substitutions;

fn is_blocked(cmd: &str) -> bool {
    let pipeline = parse_with_substitutions(cmd).unwrap();
    pipeline
        .find_segment(&|seg| policy::check_segment(&seg.words))
        .is_some()
}

// --- Integration tests: pipeline decomposition + recursive traversal ---

#[test]
fn blocks_git_in_compound() {
    assert!(is_blocked("echo hello && git commit -m test"));
}

#[test]
fn blocks_git_in_substitution() {
    assert!(is_blocked("echo $(git commit -m test)"));
}

#[test]
fn blocks_git_in_for_loop_values() {
    assert!(is_blocked("for i in $(git rebase main); do echo $i; done"));
}

#[test]
fn blocks_git_in_pipe() {
    assert!(is_blocked("echo test | git commit -m test"));
}

#[test]
fn blocks_git_after_background() {
    assert!(is_blocked("sleep 10 & git commit -m test"));
}

#[test]
fn blocks_eval_in_substitution() {
    assert!(is_blocked("echo $(eval \"git commit\")"));
}

#[test]
fn blocks_nested_wrappers() {
    assert!(is_blocked("sudo env git commit"));
}

#[test]
fn allows_non_git_pipeline() {
    assert!(!is_blocked("ls -la | grep foo"));
}

#[test]
fn respects_quotes() {
    assert!(!is_blocked(r#"echo "git commit -m test""#));
}

// --- effective_cwd ---

fn ecwd(cmd: &str, session: &str) -> Vec<String> {
    let pipeline = parse_with_substitutions(cmd).unwrap();
    crate::path::effective_cwd(&pipeline, session)
}

#[test]
fn cwd_no_cd_returns_session() {
    assert_eq!(ecwd("git status", "/session"), vec!["/session"]);
}

#[test]
fn cwd_cd_absolute_and_git() {
    assert_eq!(
        ecwd("cd /other/repo && git status", "/session"),
        vec!["/other/repo"]
    );
}

#[test]
fn cwd_cd_absolute_semi_git() {
    assert_eq!(
        ecwd("cd /other/repo; git status", "/session"),
        vec!["/other/repo"]
    );
}

#[test]
fn cwd_cd_relative() {
    assert_eq!(
        ecwd("cd subdir && git status", "/session"),
        vec!["/session/subdir"]
    );
}

#[test]
fn cwd_cd_or_does_not_propagate() {
    assert_eq!(
        ecwd("cd /other || git status", "/session"),
        vec!["/session"]
    );
}

#[test]
fn cwd_cd_pipe_does_not_propagate() {
    assert_eq!(ecwd("cd /other | git status", "/session"), vec!["/session"]);
}

#[test]
fn cwd_git_dash_c_absolute() {
    assert_eq!(
        ecwd("git -C /other/repo status", "/session"),
        vec!["/other/repo"]
    );
}

#[test]
fn cwd_git_dash_c_relative() {
    assert_eq!(
        ecwd("git -C ../sibling status", "/session"),
        vec!["/session/../sibling"]
    );
}

#[test]
fn cwd_cd_then_git_dash_c() {
    assert_eq!(
        ecwd("cd /foo && git -C /bar status", "/session"),
        vec!["/bar"]
    );
}

#[test]
fn cwd_no_git_returns_last_cd() {
    assert_eq!(ecwd("cd /other && ls -la", "/session"), vec!["/other"]);
}

#[test]
fn cwd_multiple_cds() {
    assert_eq!(ecwd("cd /a && cd /b && git status", "/session"), vec!["/b"]);
}

#[test]
fn cwd_multiple_git_segments_different_cwds() {
    assert_eq!(
        ecwd(
            "cd /non-jj-repo && git status && cd /jj-repo && git push origin main",
            "/session"
        ),
        vec!["/non-jj-repo", "/jj-repo"]
    );
}

#[test]
fn cwd_multiple_git_segments_same_cwd() {
    assert_eq!(ecwd("git status && git log", "/session"), vec!["/session"]);
}

// --- CWD-based gating (jj detection via evaluate()) ---

fn is_allowed(cmd: &str, session_cwd: &str, jj_paths: &[&str]) -> bool {
    let v = evaluate(cmd, session_cwd, |p| {
        jj_paths.iter().any(|j| p == Path::new(j))
    });
    matches!(v, Verdict::Allow)
}

#[test]
fn allows_git_targeting_non_jj_from_jj_session() {
    assert!(is_allowed("cd /other && git push", "/jj", &["/jj"]));
}

#[test]
fn blocks_git_targeting_jj_from_non_jj_session() {
    assert!(!is_allowed("cd /jj && git push", "/other", &["/jj"]));
}

#[test]
fn allows_git_dash_c_to_non_jj_from_jj_session() {
    assert!(is_allowed("git -C /other status", "/jj", &["/jj"]));
}

#[test]
fn blocks_git_dash_c_to_jj_from_non_jj_session() {
    assert!(!is_allowed("git -C /jj status", "/other", &["/jj"]));
}

#[test]
fn blocks_git_in_jj_session_no_cd() {
    assert!(!is_allowed("git status", "/jj", &["/jj"]));
}
