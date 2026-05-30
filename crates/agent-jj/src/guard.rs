use std::path::Path;
use std::process::Command;

use agent_shell_parser::parse::parse_with_substitutions;
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

enum Verdict {
    Allow,
    Block(String),
}

fn evaluate(cmd: &str, session_cwd: &str, detect_jj: impl Fn(&Path) -> bool) -> Verdict {
    let pipeline = match parse_with_substitutions(cmd) {
        Ok(p) => p,
        Err(_) => {
            return Verdict::Block(
                "BLOCKED: failed to parse command — refusing to allow.\n\n\
                 The command could not be safely analyzed. If you believe this is \
                 a false positive, run the command from outside of the coding agent."
                    .into(),
            );
        }
    };

    let effective_cwds = crate::path::effective_cwd(&pipeline, session_cwd);
    let any_jj = effective_cwds.iter().any(|cwd| detect_jj(Path::new(cwd)));
    if !any_jj {
        return Verdict::Allow;
    }

    if pipeline.has_parse_errors_recursive() {
        return Verdict::Block(
            "BLOCKED: command could not be fully parsed — refusing to allow.\n\n\
             The shell syntax triggered error recovery in the parser, which means \
             some commands may not have been analyzed. If you believe this is a \
             false positive, run the command from outside of the coding agent."
                .into(),
        );
    }

    let blocked = pipeline.find_segment(&|seg| policy::check_segment(&seg.words));

    match blocked {
        Some(b) => Verdict::Block(b.to_string()),
        None => Verdict::Allow,
    }
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

    match evaluate(command, session_cwd, is_jj_colocated) {
        Verdict::Allow => std::process::exit(0),
        Verdict::Block(msg) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
#[path = "guard_tests.rs"]
mod guard_tests;
