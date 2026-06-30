use super::*;
use agent_shell_parser::parse::parse_with_substitutions;
use rstest::rstest;

fn is_blocked(cmd: &str) -> bool {
    let pipeline = parse_with_substitutions(cmd).unwrap();
    pipeline
        .find_segment(&|seg| policy::check_segment(&seg.words))
        .is_some()
}

// --- Integration tests: pipeline decomposition + recursive traversal ---

#[rstest]
#[case::git_in_compound("echo hello && git commit -m test", true)]
#[case::git_in_substitution("echo $(git commit -m test)", true)]
#[case::git_in_for_loop("for i in $(git rebase main); do echo $i; done", true)]
#[case::git_in_pipe("echo test | git commit -m test", true)]
#[case::git_after_background("sleep 10 & git commit -m test", true)]
#[case::eval_in_substitution(r#"echo $(eval "git commit")"#, true)]
#[case::nested_wrappers("sudo env git commit", true)]
#[case::non_git_pipeline("ls -la | grep foo", false)]
#[case::respects_quotes(r#"echo "git commit -m test""#, false)]
fn pipeline_blocking(#[case] cmd: &str, #[case] expected_blocked: bool) {
    assert_eq!(is_blocked(cmd), expected_blocked, "command: {cmd}");
}

// --- effective_cwd ---

fn ecwd(cmd: &str, session: &str) -> Vec<String> {
    let pipeline = parse_with_substitutions(cmd).unwrap();
    crate::path::effective_cwd(&pipeline, session)
}

#[rstest]
#[case::no_cd_returns_session("git status", "/session", vec!["/session"])]
#[case::cd_absolute_and_git("cd /other/repo && git status", "/session", vec!["/other/repo"])]
#[case::cd_absolute_semi_git("cd /other/repo; git status", "/session", vec!["/other/repo"])]
#[case::cd_relative("cd subdir && git status", "/session", vec!["/session/subdir"])]
#[case::cd_or_does_not_propagate("cd /other || git status", "/session", vec!["/session"])]
#[case::cd_pipe_does_not_propagate("cd /other | git status", "/session", vec!["/session"])]
#[case::git_dash_c_absolute("git -C /other/repo status", "/session", vec!["/other/repo"])]
#[case::git_dash_c_relative("git -C ../sibling status", "/session", vec!["/session/../sibling"])]
#[case::cd_then_git_dash_c("cd /foo && git -C /bar status", "/session", vec!["/bar"])]
#[case::no_git_returns_last_cd("cd /other && ls -la", "/session", vec!["/other"])]
#[case::multiple_cds("cd /a && cd /b && git status", "/session", vec!["/b"])]
#[case::multiple_git_segments_different_cwds(
    "cd /non-jj-repo && git status && cd /jj-repo && git push origin main",
    "/session",
    vec!["/non-jj-repo", "/jj-repo"]
)]
#[case::multiple_git_segments_same_cwd("git status && git log", "/session", vec!["/session"])]
fn effective_cwd_resolution(#[case] cmd: &str, #[case] session: &str, #[case] expected: Vec<&str>) {
    let result = ecwd(cmd, session);
    let expected: Vec<String> = expected.into_iter().map(String::from).collect();
    assert_eq!(result, expected, "cmd={cmd}, session={session}");
}

// --- CWD-based gating (jj detection via evaluate()) ---

fn is_allowed(cmd: &str, session_cwd: &str, jj_paths: &[&str]) -> bool {
    let v = evaluate(cmd, session_cwd, |p| {
        jj_paths.iter().any(|j| p == Path::new(j))
    });
    matches!(v, Verdict::Allow)
}

#[rstest]
#[case::git_targeting_non_jj_from_jj("cd /other && git push", "/jj", &["/jj"], true)]
#[case::git_targeting_jj_from_non_jj("cd /jj && git push", "/other", &["/jj"], false)]
#[case::git_c_to_non_jj_from_jj("git -C /other status", "/jj", &["/jj"], true)]
#[case::git_c_to_jj_from_non_jj("git -C /jj status", "/other", &["/jj"], false)]
#[case::git_in_jj_session_no_cd("git status", "/jj", &["/jj"], false)]
fn cwd_based_gating(
    #[case] cmd: &str,
    #[case] session_cwd: &str,
    #[case] jj_paths: &[&str],
    #[case] expected_allowed: bool,
) {
    assert_eq!(
        is_allowed(cmd, session_cwd, jj_paths),
        expected_allowed,
        "cmd={cmd}"
    );
}
