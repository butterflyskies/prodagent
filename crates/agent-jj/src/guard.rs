use std::path::Path;
use std::process::Command;

use agent_shell_parser::parse::{parse_with_substitutions, tokenize};
use anyhow::Context;

use crate::policy;

fn is_jj_colocated(cwd: &Path) -> bool {
    Command::new("jj")
        .arg("root")
        .current_dir(cwd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn run() -> anyhow::Result<()> {
    let input: agent_shell_parser::hook::PreToolUseInput =
        agent_shell_parser::hook::parse_input().context("failed to parse PreToolUse hook input")?;

    if input.tool_name != "Bash" {
        std::process::exit(0);
    }

    let command = input
        .tool_input
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if command.is_empty() {
        std::process::exit(0);
    }

    let session_cwd = input.cwd.as_deref().unwrap_or(".");

    let pipeline = match parse_with_substitutions(command) {
        Ok(p) => p,
        Err(_) => {
            eprintln!(
                "BLOCKED: failed to parse command — refusing to allow.\n\n\
                 The command could not be safely analyzed. If you believe this is \
                 a false positive, run the command from outside of the coding agent."
            );
            std::process::exit(2);
        }
    };

    let session_is_jj = is_jj_colocated(Path::new(session_cwd));
    if !session_is_jj {
        let effective_cwds = agent_shell_parser::path::effective_cwd(&pipeline, session_cwd);
        let any_jj = effective_cwds
            .iter()
            .any(|cwd| is_jj_colocated(Path::new(cwd)));
        if !any_jj {
            std::process::exit(0);
        }
    }

    if pipeline.has_parse_errors_recursive() {
        eprintln!(
            "BLOCKED: command could not be fully parsed — refusing to allow.\n\n\
             The shell syntax triggered error recovery in the parser, which means \
             some commands may not have been analyzed. If you believe this is a \
             false positive, run the command from outside of the coding agent."
        );
        std::process::exit(2);
    }

    let blocked = pipeline.find_segment(&|seg| {
        let words = tokenize(&seg.command);
        policy::check_segment(&words)
    });

    if let Some(blocked) = blocked {
        eprintln!("{blocked}");
        std::process::exit(2);
    }

    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_shell_parser::parse::parse_with_substitutions;

    fn is_blocked(cmd: &str) -> bool {
        let pipeline = parse_with_substitutions(cmd).unwrap();
        pipeline
            .find_segment(&|seg| {
                let words = tokenize(&seg.command);
                policy::check_segment(&words)
            })
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
        agent_shell_parser::path::effective_cwd(&pipeline, session)
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
}
