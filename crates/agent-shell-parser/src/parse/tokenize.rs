use super::types::{
    CommandArg, CommandCharacteristics, IndirectExecution, ParsedCommand, ParsedFlag,
};

const INDIRECT_EVAL: &[&str] = &["eval"];
const INDIRECT_SHELL_SPAWN: &[&str] = &["bash", "sh", "dash", "zsh", "fish", "ksh"];
const INDIRECT_WRAPPER: &[&str] = &[
    "env", "command", "builtin", "nice", "nohup", "sudo", "xargs",
];
const INDIRECT_SOURCE: &[&str] = &["source", "."];

/// Analyze a command segment for security-relevant properties.
///
/// Identifies the base command, indirect execution patterns, and
/// dynamic command positions that cannot be statically resolved.
pub fn command_characteristics(command: &str) -> CommandCharacteristics {
    let tokens = shlex_or_whitespace(command);
    let cmd = tokens
        .iter()
        .find(|t| !is_env_assignment(t))
        .map(String::as_str)
        .unwrap_or("");

    let base = match cmd.rsplit_once('/') {
        Some((_, name)) if !name.is_empty() => name,
        _ => cmd,
    };

    let has_dynamic_command = base.starts_with('$');

    let indirect_execution = if INDIRECT_EVAL.contains(&base) {
        Some(IndirectExecution::Eval)
    } else if INDIRECT_SHELL_SPAWN.contains(&base) {
        let has_c_flag = tokens.iter().any(|t| t == "-c");
        if has_c_flag {
            Some(IndirectExecution::ShellSpawn)
        } else {
            // bash script.sh — similar to source, contents unanalyzable
            Some(IndirectExecution::SourceScript)
        }
    } else if INDIRECT_WRAPPER.contains(&base) {
        Some(IndirectExecution::CommandWrapper)
    } else if INDIRECT_SOURCE.contains(&base) {
        Some(IndirectExecution::SourceScript)
    } else {
        None
    };

    CommandCharacteristics {
        base_command: base.to_string(),
        indirect_execution,
        has_dynamic_command,
    }
}

/// Extract the first real command word, skipping leading `KEY=VALUE` assignments.
///
/// Uses shlex for correct handling of quoted values like `FOO="bar baz"`.
/// Returns the basename of the command (e.g. `/usr/bin/ls` → `ls`).
pub fn base_command(command: &str) -> String {
    command_characteristics(command).base_command
}

/// Extract leading `KEY=VALUE` pairs from a command string.
///
/// Uses shlex for correct handling of quoted values like `FOO="bar baz"`.
/// Stops at the first token that is not a valid assignment.
pub fn env_vars(command: &str) -> Vec<(String, String)> {
    let tokens = shlex_or_whitespace(command);
    let mut result = Vec::new();
    for token in &tokens {
        if let Some(eq_pos) = token.find('=') {
            let key = &token[..eq_pos];
            if is_valid_env_key(key) {
                let val = &token[eq_pos + 1..];
                result.push((key.to_string(), val.to_string()));
                continue;
            }
        }
        break;
    }
    result
}

/// Tokenize a command segment into words using shlex (POSIX word splitting).
///
/// Falls back to whitespace splitting if shlex cannot parse the input
/// (e.g. unmatched quotes). The fallback preserves quote characters in
/// the resulting tokens.
pub fn tokenize(command: &str) -> Vec<String> {
    shlex_or_whitespace(command)
}

pub(crate) fn is_env_assignment(token: &str) -> bool {
    match token.find('=') {
        Some(eq_pos) => is_valid_env_key(&token[..eq_pos]),
        None => false,
    }
}

pub(crate) fn is_valid_env_key(key: &str) -> bool {
    !key.is_empty()
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && key
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
}

/// Parse a command string into structured components with arguments in source order.
///
/// This is a schema-free parse. Flags are identified syntactically
/// (tokens starting with `-`). `--flag=value` splits into name and
/// value; all other flags are treated as value-less. Without knowing
/// a command's flag definitions, `--flag value` is ambiguous — the
/// value appears as a separate positional argument.
pub fn parse_command(command: &str) -> ParsedCommand {
    let tokens = shlex_or_whitespace(command);

    let cmd_idx = tokens.iter().position(|t| !is_env_assignment(t));
    let Some(cmd_idx) = cmd_idx else {
        return ParsedCommand {
            command: String::new(),
            args: vec![],
        };
    };

    let cmd_token = &tokens[cmd_idx];
    let base = match cmd_token.rsplit_once('/') {
        Some((_, name)) if !name.is_empty() => name.to_string(),
        _ => cmd_token.to_string(),
    };

    let mut args = Vec::new();
    let mut past_double_dash = false;

    for token in &tokens[cmd_idx + 1..] {
        if past_double_dash {
            args.push(CommandArg::Positional(token.clone()));
            continue;
        }
        if token == "--" {
            past_double_dash = true;
            continue;
        }
        if let Some(rest) = token.strip_prefix("--") {
            if let Some((name, value)) = rest.split_once('=') {
                args.push(CommandArg::Flag(ParsedFlag {
                    name: format!("--{name}"),
                    value: Some(value.to_string()),
                }));
            } else {
                args.push(CommandArg::Flag(ParsedFlag {
                    name: token.clone(),
                    value: None,
                }));
            }
        } else if token.starts_with('-') && token.len() > 1 {
            args.push(CommandArg::Flag(ParsedFlag {
                name: token.clone(),
                value: None,
            }));
        } else {
            args.push(CommandArg::Positional(token.clone()));
        }
    }

    ParsedCommand {
        command: base,
        args,
    }
}

fn shlex_or_whitespace(command: &str) -> Vec<String> {
    shlex::split(command).unwrap_or_else(|| command.split_whitespace().map(String::from).collect())
}

#[cfg(test)]
mod tests {
    use super::super::types::IndirectExecution;
    use super::*;

    #[test]
    fn base_command_simple() {
        assert_eq!(base_command("ls -la"), "ls");
    }

    #[test]
    fn base_command_with_env() {
        assert_eq!(
            base_command("GIT_CONFIG_GLOBAL=~/.gitconfig.ai git push"),
            "git"
        );
    }

    #[test]
    fn base_command_absolute_path() {
        assert_eq!(base_command("/usr/bin/ls -la"), "ls");
    }

    #[test]
    fn base_command_relative_path() {
        assert_eq!(base_command("./script.sh --flag"), "script.sh");
    }

    #[test]
    fn base_command_deep_path() {
        assert_eq!(
            base_command("/home/user/dev/tool/target/release/tool --dump-config"),
            "tool"
        );
    }

    #[test]
    fn base_command_env_with_path() {
        assert_eq!(base_command("FOO=bar /usr/local/bin/git status"), "git");
    }

    #[test]
    fn base_command_empty() {
        assert_eq!(base_command(""), "");
    }

    #[test]
    fn base_command_quoted_env_value() {
        assert_eq!(
            base_command(r#"GIT_AUTHOR_NAME="Jane Doe" git commit"#),
            "git"
        );
    }

    #[test]
    fn base_command_single_quoted_env_value() {
        assert_eq!(base_command("FOO='bar baz' git push"), "git");
    }

    #[test]
    fn base_command_multiple_quoted_env() {
        assert_eq!(base_command(r#"A="x y" B='1 2' git status"#), "git");
    }

    #[test]
    fn env_vars_single() {
        assert_eq!(env_vars("FOO=bar cmd"), vec![("FOO".into(), "bar".into())]);
    }

    #[test]
    fn env_vars_multiple() {
        assert_eq!(
            env_vars("A=1 B=2 cmd"),
            vec![("A".into(), "1".into()), ("B".into(), "2".into())]
        );
    }

    #[test]
    fn env_vars_none() {
        assert!(env_vars("cmd --flag").is_empty());
    }

    #[test]
    fn env_vars_quoted_value() {
        assert_eq!(
            env_vars(r#"FOO="bar baz" cmd"#),
            vec![("FOO".into(), "bar baz".into())]
        );
    }

    #[test]
    fn env_vars_single_quoted_value() {
        assert_eq!(
            env_vars("FOO='bar baz' cmd"),
            vec![("FOO".into(), "bar baz".into())]
        );
    }

    #[test]
    fn env_vars_value_with_equals() {
        assert_eq!(
            env_vars(r#"OPTS="--foo=bar" cmd"#),
            vec![("OPTS".into(), "--foo=bar".into())]
        );
    }

    #[test]
    fn tokenize_simple() {
        assert_eq!(tokenize("ls -la /tmp"), vec!["ls", "-la", "/tmp"]);
    }

    #[test]
    fn tokenize_quoted() {
        assert_eq!(tokenize("echo 'hello world'"), vec!["echo", "hello world"]);
    }

    #[test]
    fn tokenize_double_quoted() {
        assert_eq!(
            tokenize("echo \"hello world\""),
            vec!["echo", "hello world"]
        );
    }

    // --- command_characteristics ---

    #[test]
    fn characteristics_eval() {
        let c = command_characteristics("eval \"git commit\"");
        assert_eq!(c.base_command, "eval");
        assert_eq!(c.indirect_execution, Some(IndirectExecution::Eval));
        assert!(!c.has_dynamic_command);
    }

    #[test]
    fn characteristics_bash_c() {
        let c = command_characteristics("bash -c \"git commit\"");
        assert_eq!(c.base_command, "bash");
        assert_eq!(c.indirect_execution, Some(IndirectExecution::ShellSpawn));
    }

    #[test]
    fn characteristics_bash_script() {
        let c = command_characteristics("bash script.sh");
        assert_eq!(c.base_command, "bash");
        assert_eq!(c.indirect_execution, Some(IndirectExecution::SourceScript));
    }

    #[test]
    fn characteristics_env_wrapper() {
        let c = command_characteristics("env git commit");
        assert_eq!(c.base_command, "env");
        assert_eq!(
            c.indirect_execution,
            Some(IndirectExecution::CommandWrapper)
        );
    }

    #[test]
    fn characteristics_sudo_wrapper() {
        let c = command_characteristics("sudo git commit");
        assert_eq!(c.base_command, "sudo");
        assert_eq!(
            c.indirect_execution,
            Some(IndirectExecution::CommandWrapper)
        );
    }

    #[test]
    fn characteristics_xargs() {
        let c = command_characteristics("xargs git commit");
        assert_eq!(c.base_command, "xargs");
        assert_eq!(
            c.indirect_execution,
            Some(IndirectExecution::CommandWrapper)
        );
    }

    #[test]
    fn characteristics_source() {
        let c = command_characteristics("source script.sh");
        assert_eq!(c.base_command, "source");
        assert_eq!(c.indirect_execution, Some(IndirectExecution::SourceScript));
    }

    #[test]
    fn characteristics_dot_source() {
        let c = command_characteristics(". script.sh");
        assert_eq!(c.base_command, ".");
        assert_eq!(c.indirect_execution, Some(IndirectExecution::SourceScript));
    }

    #[test]
    fn characteristics_dynamic_command() {
        let c = command_characteristics("$cmd args");
        assert!(c.has_dynamic_command);
    }

    #[test]
    fn characteristics_normal_command() {
        let c = command_characteristics("ls -la");
        assert_eq!(c.base_command, "ls");
        assert!(c.indirect_execution.is_none());
        assert!(!c.has_dynamic_command);
    }

    #[test]
    fn characteristics_env_with_vars() {
        let c = command_characteristics("FOO=bar env git commit");
        assert_eq!(c.base_command, "env");
        assert_eq!(
            c.indirect_execution,
            Some(IndirectExecution::CommandWrapper)
        );
    }

    // --- parse_command ---

    #[test]
    fn parse_simple_command() {
        let p = parse_command("ls -la /tmp");
        assert_eq!(p.command, "ls");
        assert_eq!(p.subcommand(), Some("/tmp"));
        assert_eq!(p.flags().count(), 1);
        assert_eq!(p.flags().next().map(|f| f.name.as_str()), Some("-la"));
        assert_eq!(p.positional().collect::<Vec<_>>(), vec!["/tmp"]);
    }

    #[test]
    fn parse_git_push() {
        let p = parse_command("git push --force origin main");
        assert_eq!(p.command, "git");
        assert_eq!(p.subcommand(), Some("push"));
        assert!(p.has_flag("--force"));
        assert_eq!(
            p.positional().collect::<Vec<_>>(),
            vec!["push", "origin", "main"]
        );
    }

    #[test]
    fn parse_flag_with_equals() {
        let p = parse_command("cargo build --color=always");
        assert_eq!(p.command, "cargo");
        let flags: Vec<_> = p.flags().collect();
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].name, "--color");
        assert_eq!(flags[0].value.as_deref(), Some("always"));
    }

    #[test]
    fn parse_double_dash_separator() {
        let p = parse_command("git log -- file.rs");
        assert_eq!(p.command, "git");
        assert!(p.positional().any(|s| s == "file.rs"));
    }

    #[test]
    fn parse_with_env_vars() {
        let p = parse_command("FOO=bar git status");
        assert_eq!(p.command, "git");
        assert_eq!(p.subcommand(), Some("status"));
    }

    #[test]
    fn parse_path_command() {
        let p = parse_command("/usr/bin/git commit -m test");
        assert_eq!(p.command, "git");
        assert_eq!(p.subcommand(), Some("commit"));
    }

    #[test]
    fn parse_empty() {
        let p = parse_command("");
        assert_eq!(p.command, "");
        assert!(p.subcommand().is_none());
    }
}
