use std::sync::LazyLock;

/// Describes how to strip a transparent wrapper command to find the inner command.
///
/// Each wrapper has different flag semantics. This struct captures just enough
/// to correctly skip past the wrapper and its flags to the real command.
/// Designed for deserialization from config files — consumers load specs from
/// JSON/TOML/YAML and pass them to [`resolve_command_with`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WrapperSpec {
    /// Command name to match (basename, e.g., "sudo").
    pub name: String,
    /// Short flags that consume the next token as a value (e.g., `["-u", "-g"]`).
    #[serde(default)]
    pub short_value_flags: Vec<String>,
    /// Long flags that consume the next token as a value (e.g., `["--user", "--group"]`).
    #[serde(default)]
    pub long_value_flags: Vec<String>,
    /// Flags whose presence makes the entire invocation unanalyzable.
    /// Example: `env -S` executes its value as a command string (eval-equivalent).
    #[serde(default)]
    pub unanalyzable_flags: Vec<String>,
    /// Whether to skip leading `KEY=VALUE` tokens after the wrapper (env-style).
    #[serde(default)]
    pub skip_env_assignments: bool,
    /// Whether `--` terminates flag processing for this wrapper.
    #[serde(default)]
    pub has_terminator: bool,
    /// Number of leading positional arguments to skip before the inner command.
    ///
    /// Some wrappers require mandatory positional args before the command:
    /// `timeout DURATION cmd`, `chrt PRIORITY cmd`, `taskset MASK cmd`.
    /// Set this to the number of positionals to consume before treating
    /// the next non-flag token as the inner command.
    #[serde(default)]
    pub skip_positionals: usize,
}

/// Complete command classification configuration.
///
/// Drives all indirect execution detection — no command knowledge is hardcoded
/// in the parser source. Consumers load this from JSON/TOML/YAML and pass it
/// to [`resolve_command_with`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommandConfig {
    /// Transparent wrappers that execute an inner command (env, sudo, etc.).
    pub wrappers: Vec<WrapperSpec>,
    /// Shells that can spawn inline code via `-c` (bash, sh, zsh, etc.).
    pub shells: Vec<String>,
    /// Commands that execute their argument as shell code (eval).
    pub eval_commands: Vec<String>,
    /// Commands that execute a file in the current shell (source, `.`).
    pub source_commands: Vec<String>,
}

// ---------------------------------------------------------------------------
// Default wrapper specs — single source of truth
// ---------------------------------------------------------------------------

/// The canonical set of wrapper specs compiled into both the parser and the KB.
///
/// This is the single source of truth for wrapper stripping mechanics. The
/// policy engine can extend this set at runtime with KB-derived wrappers via
/// `merged_config()` and `resolve_command_with()`.
pub static DEFAULT_WRAPPER_SPECS: LazyLock<Vec<WrapperSpec>> = LazyLock::new(|| {
    vec![
        WrapperSpec {
            name: "sudo".into(),
            short_value_flags: vec![
                "-u".into(),
                "-g".into(),
                "-C".into(),
                "-D".into(),
                "-R".into(),
                "-T".into(),
                "-U".into(),
                "-p".into(),
                "-h".into(),
                "-r".into(),
                "-t".into(),
            ],
            long_value_flags: vec![
                "--user".into(),
                "--group".into(),
                "--close-from".into(),
                "--chdir".into(),
                "--role".into(),
                "--type".into(),
                "--host".into(),
                "--other-user".into(),
                "--prompt".into(),
                "--command-timeout".into(),
            ],
            unanalyzable_flags: vec!["-i".into(), "-s".into()],
            skip_env_assignments: false,
            has_terminator: true,
            skip_positionals: 0,
        },
        WrapperSpec {
            name: "env".into(),
            short_value_flags: vec!["-u".into(), "-C".into()],
            long_value_flags: vec!["--unset".into(), "--chdir".into()],
            unanalyzable_flags: vec!["-S".into(), "--split-string".into()],
            skip_env_assignments: true,
            has_terminator: true,
            skip_positionals: 0,
        },
        WrapperSpec {
            name: "nice".into(),
            short_value_flags: vec!["-n".into()],
            long_value_flags: vec!["--adjustment".into()],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: false,
            skip_positionals: 0,
        },
        WrapperSpec {
            name: "nohup".into(),
            short_value_flags: vec![],
            long_value_flags: vec![],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: false,
            skip_positionals: 0,
        },
        WrapperSpec {
            name: "command".into(),
            short_value_flags: vec![],
            long_value_flags: vec![],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: false,
            skip_positionals: 0,
        },
        WrapperSpec {
            name: "builtin".into(),
            short_value_flags: vec![],
            long_value_flags: vec![],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: false,
            skip_positionals: 0,
        },
        WrapperSpec {
            name: "xargs".into(),
            short_value_flags: vec![
                "-I".into(),
                "-n".into(),
                "-P".into(),
                "-L".into(),
                "-s".into(),
                "-d".into(),
                "-a".into(),
                "-E".into(),
            ],
            long_value_flags: vec![
                "--max-args".into(),
                "--max-procs".into(),
                "--max-lines".into(),
                "--max-chars".into(),
                "--delimiter".into(),
                "--arg-file".into(),
                "--replace".into(),
                "--eof".into(),
            ],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: false,
            skip_positionals: 0,
        },
        WrapperSpec {
            name: "parallel".into(),
            short_value_flags: vec![
                "-j".into(),
                "-S".into(),
                "-E".into(),
                "-I".into(),
                "-s".into(),
                "-n".into(),
                "-L".into(),
                "-a".into(),
                "-d".into(),
            ],
            long_value_flags: vec![
                "--jobs".into(),
                "--sshlogin".into(),
                "--sshloginfile".into(),
                "--slf".into(),
                "--colsep".into(),
                "--recend".into(),
                "--recstart".into(),
                "--arg-file".into(),
                "--max-args".into(),
                "--max-lines".into(),
                "--max-chars".into(),
                "--delimiter".into(),
                "--replace".into(),
                "--eof".into(),
                "--retries".into(),
                "--timeout".into(),
                "--delay".into(),
                "--memfree".into(),
                "--tmpdir".into(),
                "--results".into(),
                "--joblog".into(),
                "--halt".into(),
                "--resume-failed".into(),
                "--tagstring".into(),
                "--header".into(),
                "--block".into(),
                "--block-size".into(),
                "--files".into(),
            ],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: true,
            skip_positionals: 0,
        },
        WrapperSpec {
            name: "time".into(),
            short_value_flags: vec![],
            long_value_flags: vec![],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: false,
            skip_positionals: 0,
        },
        WrapperSpec {
            name: "timeout".into(),
            short_value_flags: vec!["-k".into(), "-s".into()],
            long_value_flags: vec!["--signal".into(), "--kill-after".into()],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: false,
            skip_positionals: 1,
        },
        WrapperSpec {
            name: "exec".into(),
            short_value_flags: vec!["-a".into()],
            long_value_flags: vec![],
            unanalyzable_flags: vec![],
            skip_env_assignments: true,
            has_terminator: true,
            skip_positionals: 0,
        },
        WrapperSpec {
            name: "setsid".into(),
            short_value_flags: vec![],
            long_value_flags: vec![],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: false,
            skip_positionals: 0,
        },
        WrapperSpec {
            name: "strace".into(),
            short_value_flags: vec![
                "-e".into(),
                "-o".into(),
                "-p".into(),
                "-s".into(),
                "-I".into(),
                "-b".into(),
                "-X".into(),
                "-P".into(),
            ],
            long_value_flags: vec![
                "--output".into(),
                "--trace".into(),
                "--signal".into(),
                "--status".into(),
            ],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: true,
            skip_positionals: 0,
        },
        WrapperSpec {
            name: "ionice".into(),
            short_value_flags: vec!["-c".into(), "-n".into(), "-p".into()],
            long_value_flags: vec!["--class".into(), "--classdata".into()],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: false,
            skip_positionals: 0,
        },
        WrapperSpec {
            name: "chrt".into(),
            short_value_flags: vec!["-p".into()],
            long_value_flags: vec!["--pid".into()],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: false,
            skip_positionals: 1,
        },
        WrapperSpec {
            name: "taskset".into(),
            short_value_flags: vec!["-p".into()],
            long_value_flags: vec!["--pid".into()],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: false,
            skip_positionals: 1,
        },
        WrapperSpec {
            name: "watch".into(),
            short_value_flags: vec!["-n".into()],
            long_value_flags: vec!["--interval".into()],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: false,
            skip_positionals: 0,
        },
        WrapperSpec {
            name: "ltrace".into(),
            short_value_flags: vec![
                "-e".into(),
                "-o".into(),
                "-p".into(),
                "-n".into(),
                "-s".into(),
                "-A".into(),
            ],
            long_value_flags: vec![],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: true,
            skip_positionals: 0,
        },
        WrapperSpec {
            name: "su".into(),
            short_value_flags: vec!["-s".into(), "-g".into(), "-G".into(), "-w".into()],
            long_value_flags: vec![
                "--shell".into(),
                "--group".into(),
                "--supp-group".into(),
                "--whitelist-environment".into(),
            ],
            unanalyzable_flags: vec!["-c".into(), "--command".into()],
            skip_env_assignments: false,
            has_terminator: true,
            skip_positionals: 1,
        },
    ]
});

/// The canonical set of shell names for indirect execution detection.
pub static DEFAULT_SHELLS: LazyLock<Vec<String>> = LazyLock::new(|| {
    vec![
        "bash".into(),
        "sh".into(),
        "dash".into(),
        "zsh".into(),
        "fish".into(),
        "ksh".into(),
        "tcsh".into(),
        "csh".into(),
        "mksh".into(),
        "yash".into(),
        "rbash".into(),
    ]
});

/// The canonical set of eval-like commands.
pub static DEFAULT_EVAL_COMMANDS: LazyLock<Vec<String>> = LazyLock::new(|| vec!["eval".into()]);

/// The canonical set of source-like commands.
pub static DEFAULT_SOURCE_COMMANDS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["source".into(), ".".into()]);

/// Build a [`CommandConfig`] from the canonical default specs.
///
/// This replaces the embedded `commands.json` file — the defaults are now
/// compiled in from this shared crate rather than maintained as a separate
/// config file.
pub fn default_command_config() -> CommandConfig {
    CommandConfig {
        wrappers: DEFAULT_WRAPPER_SPECS.clone(),
        shells: DEFAULT_SHELLS.clone(),
        eval_commands: DEFAULT_EVAL_COMMANDS.clone(),
        source_commands: DEFAULT_SOURCE_COMMANDS.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_wrapper_specs_not_empty() {
        assert!(!DEFAULT_WRAPPER_SPECS.is_empty());
    }

    #[test]
    fn default_command_config_has_all_defaults() {
        let config = default_command_config();
        assert!(!config.wrappers.is_empty());
        assert!(!config.shells.is_empty());
        assert!(!config.eval_commands.is_empty());
        assert!(!config.source_commands.is_empty());
    }

    #[test]
    fn default_wrappers_match_known_names() {
        let names: Vec<&str> = DEFAULT_WRAPPER_SPECS
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        for expected in &[
            "sudo", "env", "nice", "nohup", "command", "builtin", "xargs", "parallel", "time",
            "timeout", "exec", "setsid", "strace", "ionice", "chrt", "taskset", "watch", "ltrace",
            "su",
        ] {
            assert!(names.contains(expected), "missing wrapper: {expected}");
        }
    }

    #[test]
    fn wrapper_spec_round_trips_through_json() {
        let config = default_command_config();
        let json = serde_json::to_string(&config).expect("serialize");
        let parsed: CommandConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, parsed);
    }
}
