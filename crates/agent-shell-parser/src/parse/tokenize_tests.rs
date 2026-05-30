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
