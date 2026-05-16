use std::path::Path;

use agent_shell_parser::parse::{parse_with_substitutions, tokenize};
use anyhow::Context;

mod policy;

fn main() -> anyhow::Result<()> {
    let input: agent_shell_parser::PreToolUseInput =
        agent_shell_parser::parse_input().context("failed to parse PreToolUse hook input")?;

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

    let effective_cwd = agent_shell_parser::path::effective_cwd(&pipeline, session_cwd);
    if !agent_shell_parser::is_jj_colocated(Path::new(&effective_cwd)) {
        std::process::exit(0);
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

    fn is_blocked(cmd: &str) -> bool {
        let pipeline = parse_with_substitutions(cmd).unwrap();
        pipeline
            .find_segment(&|seg| {
                let words = tokenize(&seg.command);
                policy::check_segment(&words)
            })
            .is_some()
    }

    #[test]
    fn blocks_simple_git_commit() {
        assert!(is_blocked("git commit -m test"));
    }

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
    fn blocks_git_status() {
        assert!(is_blocked("git status"));
    }

    #[test]
    fn blocks_git_log_in_compound() {
        assert!(is_blocked("git log --oneline && echo done"));
    }

    #[test]
    fn allows_non_git() {
        assert!(!is_blocked("ls -la | grep foo"));
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
    fn respects_quotes() {
        assert!(!is_blocked(r#"echo "git commit -m test""#));
    }

    // --- Indirect execution (adversarial bypass) ---

    #[test]
    fn blocks_eval_git() {
        assert!(is_blocked("eval \"git commit\""));
    }

    #[test]
    fn blocks_bash_c_git() {
        assert!(is_blocked("bash -c \"git commit\""));
    }

    #[test]
    fn blocks_env_git() {
        assert!(is_blocked("env git commit"));
    }

    #[test]
    fn blocks_sudo_git() {
        assert!(is_blocked("sudo git commit"));
    }

    #[test]
    fn blocks_command_git() {
        assert!(is_blocked("command git commit"));
    }

    #[test]
    fn blocks_source_script() {
        assert!(is_blocked("source script.sh"));
    }

    #[test]
    fn blocks_dot_source_script() {
        assert!(is_blocked(". script.sh"));
    }

    #[test]
    fn blocks_xargs_git() {
        assert!(is_blocked("xargs git commit"));
    }

    #[test]
    fn blocks_dynamic_command() {
        assert!(is_blocked("$cmd args"));
    }

    #[test]
    fn blocks_sudo_env_git() {
        assert!(is_blocked("sudo env git commit"));
    }

    #[test]
    fn blocks_env_with_vars_git() {
        assert!(is_blocked("env FOO=bar git push"));
    }

    #[test]
    fn blocks_nohup_git() {
        assert!(is_blocked("nohup git push &"));
    }

    #[test]
    fn blocks_eval_in_substitution() {
        assert!(is_blocked("echo $(eval \"git commit\")"));
    }

    #[test]
    fn blocks_bash_script() {
        assert!(is_blocked("bash deploy.sh"));
    }

    #[test]
    fn allows_xargs_ls() {
        assert!(!is_blocked("xargs ls -la"));
    }

    #[test]
    fn allows_env_ls() {
        assert!(!is_blocked("env ls -la"));
    }

    #[test]
    fn allows_sudo_ls() {
        assert!(!is_blocked("sudo ls -la"));
    }

    // --- effective_cwd ---

    fn ecwd(cmd: &str, session: &str) -> String {
        let pipeline = parse_with_substitutions(cmd).unwrap();
        agent_shell_parser::path::effective_cwd(&pipeline, session)
    }

    #[test]
    fn cwd_no_cd_returns_session() {
        assert_eq!(ecwd("git status", "/session"), "/session");
    }

    #[test]
    fn cwd_cd_absolute_and_git() {
        assert_eq!(
            ecwd("cd /other/repo && git status", "/session"),
            "/other/repo"
        );
    }

    #[test]
    fn cwd_cd_absolute_semi_git() {
        assert_eq!(
            ecwd("cd /other/repo; git status", "/session"),
            "/other/repo"
        );
    }

    #[test]
    fn cwd_cd_relative() {
        assert_eq!(
            ecwd("cd subdir && git status", "/session"),
            "/session/subdir"
        );
    }

    #[test]
    fn cwd_cd_or_does_not_propagate() {
        assert_eq!(ecwd("cd /other || git status", "/session"), "/session");
    }

    #[test]
    fn cwd_cd_pipe_does_not_propagate() {
        assert_eq!(ecwd("cd /other | git status", "/session"), "/session");
    }

    #[test]
    fn cwd_git_dash_c_absolute() {
        assert_eq!(ecwd("git -C /other/repo status", "/session"), "/other/repo");
    }

    #[test]
    fn cwd_git_dash_c_relative() {
        assert_eq!(
            ecwd("git -C ../sibling status", "/session"),
            "/session/../sibling"
        );
    }

    #[test]
    fn cwd_cd_then_git_dash_c() {
        assert_eq!(ecwd("cd /foo && git -C /bar status", "/session"), "/bar");
    }

    #[test]
    fn cwd_no_git_returns_last_cd() {
        assert_eq!(ecwd("cd /other && ls -la", "/session"), "/other");
    }

    #[test]
    fn cwd_multiple_cds() {
        assert_eq!(ecwd("cd /a && cd /b && git status", "/session"), "/b");
    }
}
