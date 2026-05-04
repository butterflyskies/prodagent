use std::path::Path;

use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let input: agent_shell_parser::PreToolUseInput =
        agent_shell_parser::parse_input().context("failed to parse PreToolUse hook input")?;

    // Only inspect Bash tool calls
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

    // Short-circuit: not a jj-colocated repo
    let cwd = input.cwd.as_deref().unwrap_or(".");
    if !agent_shell_parser::is_jj_colocated(Path::new(cwd)) {
        std::process::exit(0);
    }

    // Tokenize and check each command segment (split on && and ||)
    let segments = split_compound_command(command);

    for segment in &segments {
        let words = match shell_words::split(segment) {
            Ok(w) => w,
            Err(_) => continue, // unparseable segment — let it through
        };

        if let Some(blocked) = agent_shell_parser::guard::check_git_command(&words) {
            eprintln!("{blocked}");
            std::process::exit(2);
        }
    }

    std::process::exit(0);
}

fn split_compound_command(cmd: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut quote_char = ' ';
    let bytes = cmd.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let ch = bytes[i] as char;

        if in_quotes {
            if ch == quote_char {
                in_quotes = false;
            } else if ch == '\\' && quote_char == '"' {
                i += 1; // skip escaped char
            }
        } else {
            match ch {
                '\'' | '"' => {
                    in_quotes = true;
                    quote_char = ch;
                }
                '&' if i + 1 < bytes.len() && bytes[i + 1] == b'&' => {
                    segments.push(&cmd[start..i]);
                    i += 2;
                    start = i;
                    continue;
                }
                '|' if i + 1 < bytes.len() && bytes[i + 1] == b'|' => {
                    segments.push(&cmd[start..i]);
                    i += 2;
                    start = i;
                    continue;
                }
                '|' => {
                    segments.push(&cmd[start..i]);
                    i += 1;
                    start = i;
                    continue;
                }
                ';' => {
                    segments.push(&cmd[start..i]);
                    i += 1;
                    start = i;
                    continue;
                }
                _ => {}
            }
        }
        i += 1;
    }

    if start < cmd.len() {
        segments.push(&cmd[start..]);
    }

    segments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_and() {
        let segs = split_compound_command("git status && git commit -m test");
        assert_eq!(segs, vec!["git status ", " git commit -m test"]);
    }

    #[test]
    fn splits_on_or() {
        let segs = split_compound_command("git status || echo failed");
        assert_eq!(segs, vec!["git status ", " echo failed"]);
    }

    #[test]
    fn splits_on_pipe() {
        let segs = split_compound_command("git log | head -10");
        assert_eq!(segs, vec!["git log ", " head -10"]);
    }

    #[test]
    fn splits_on_semicolon() {
        let segs = split_compound_command("cd repo; git commit -m x");
        assert_eq!(segs, vec!["cd repo", " git commit -m x"]);
    }

    #[test]
    fn respects_quotes() {
        let segs = split_compound_command(r#"echo "a && b" && git commit"#);
        assert_eq!(segs.len(), 2);
        assert!(segs[0].contains("a && b"));
        assert!(segs[1].contains("git commit"));
    }
}
