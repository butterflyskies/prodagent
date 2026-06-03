use agent_shell_parser::parse::{
    command_characteristics, resolve_command, tokenize, IndirectExecution, ResolvedCommand, Word,
};

fn words(s: &str) -> Vec<Word> {
    tokenize(s)
}

fn resolved_command_name(cmd: &str) -> String {
    match resolve_command(&words(cmd)) {
        ResolvedCommand::Resolved(p) => p.command.into_inner(),
        ResolvedCommand::Unanalyzable(u) => format!("UNANALYZABLE:{}", u.command),
        _ => "UNKNOWN".to_string(),
    }
}

// --- env ---

#[test]
fn env_strips_to_inner() {
    assert_eq!(resolved_command_name("env git commit"), "git");
}

#[test]
fn env_u_strips_value() {
    assert_eq!(resolved_command_name("env -u HOME git commit"), "git");
}

#[test]
fn env_unset_long_strips_value() {
    assert_eq!(resolved_command_name("env --unset HOME git commit"), "git");
}

#[test]
fn env_unset_equals_strips() {
    assert_eq!(resolved_command_name("env --unset=HOME git commit"), "git");
}

#[test]
fn env_c_strips_value() {
    assert_eq!(resolved_command_name("env -C /tmp git commit"), "git");
}

#[test]
fn env_chdir_long_strips() {
    assert_eq!(resolved_command_name("env --chdir /tmp git commit"), "git");
}

#[test]
fn env_s_is_unanalyzable() {
    assert!(resolved_command_name("env -S 'git commit' git push").starts_with("UNANALYZABLE"));
}

#[test]
fn env_split_string_long_is_unanalyzable() {
    assert!(resolved_command_name("env --split-string='git commit'").starts_with("UNANALYZABLE"));
}

#[test]
fn env_with_assignments() {
    assert_eq!(
        resolved_command_name("env FOO=bar BAZ=qux git commit"),
        "git"
    );
}

#[test]
fn env_mixed_flags_and_assignments() {
    assert_eq!(
        resolved_command_name("env -u HOME FOO=bar -C /tmp git status"),
        "git"
    );
}

#[test]
fn env_terminator() {
    assert_eq!(resolved_command_name("env -- git commit"), "git");
}

#[test]
fn env_i_flag_strips() {
    assert_eq!(resolved_command_name("env -i git commit"), "git");
}

// --- sudo ---

#[test]
fn sudo_strips_to_inner() {
    assert_eq!(resolved_command_name("sudo git commit"), "git");
}

#[test]
fn sudo_u_short_strips() {
    assert_eq!(resolved_command_name("sudo -u root git commit"), "git");
}

#[test]
fn sudo_user_long_strips() {
    assert_eq!(resolved_command_name("sudo --user root git commit"), "git");
}

#[test]
fn sudo_user_equals_strips() {
    assert_eq!(resolved_command_name("sudo --user=root git commit"), "git");
}

#[test]
fn sudo_multiple_flags() {
    assert_eq!(
        resolved_command_name("sudo -u admin -g wheel git commit"),
        "git"
    );
}

#[test]
fn sudo_boolean_flags_skipped() {
    assert_eq!(resolved_command_name("sudo -E -H -n git commit"), "git");
}

#[test]
fn sudo_terminator() {
    assert_eq!(resolved_command_name("sudo -- git commit"), "git");
}

#[test]
fn sudo_truncated_value_flag() {
    match resolve_command(&words("sudo -u")) {
        ResolvedCommand::Resolved(p) => assert_eq!(p.command, ""),
        _ => panic!("expected Resolved with empty command"),
    }
}

// --- nice ---

#[test]
fn nice_strips_to_inner() {
    assert_eq!(resolved_command_name("nice git commit"), "git");
}

#[test]
fn nice_n_short_strips_value() {
    assert_eq!(resolved_command_name("nice -n 10 git commit"), "git");
}

#[test]
fn nice_adjustment_long_strips() {
    assert_eq!(
        resolved_command_name("nice --adjustment 5 git commit"),
        "git"
    );
}

#[test]
fn nice_adjustment_equals_strips() {
    assert_eq!(
        resolved_command_name("nice --adjustment=5 git commit"),
        "git"
    );
}

// --- nohup ---

#[test]
fn nohup_strips_to_inner() {
    assert_eq!(resolved_command_name("nohup git push"), "git");
}

// --- command ---

#[test]
fn command_strips_to_inner() {
    assert_eq!(resolved_command_name("command git commit"), "git");
}

#[test]
fn command_p_flag_strips() {
    assert_eq!(resolved_command_name("command -p git commit"), "git");
}

#[test]
fn command_v_flag_strips() {
    assert_eq!(resolved_command_name("command -v git"), "git");
}

// --- builtin ---

#[test]
fn builtin_strips_to_inner() {
    assert_eq!(resolved_command_name("builtin echo hello"), "echo");
}

// --- xargs ---

#[test]
fn xargs_strips_to_inner() {
    assert_eq!(resolved_command_name("xargs git commit"), "git");
}

#[test]
fn xargs_p_flag_strips() {
    assert_eq!(resolved_command_name("xargs -P 4 git commit"), "git");
}

#[test]
fn xargs_p_inline_strips() {
    assert_eq!(resolved_command_name("xargs -P4 git commit"), "git");
}

#[test]
fn xargs_n_flag_strips() {
    assert_eq!(resolved_command_name("xargs -n 1 git commit"), "git");
}

#[test]
fn xargs_multiple_value_flags() {
    assert_eq!(
        resolved_command_name("xargs -n 1 -P 4 -I {} git commit"),
        "git"
    );
}

#[test]
fn xargs_long_flags() {
    assert_eq!(
        resolved_command_name("xargs --max-procs=4 --max-args 1 git commit"),
        "git"
    );
}

// --- parallel ---

#[test]
fn parallel_strips_to_inner() {
    assert_eq!(resolved_command_name("parallel git push"), "git");
}

#[test]
fn parallel_j_flag_strips() {
    assert_eq!(resolved_command_name("parallel -j 4 git push"), "git");
}

#[test]
fn parallel_long_jobs_strips() {
    assert_eq!(resolved_command_name("parallel --jobs 4 git push"), "git");
}

#[test]
fn parallel_multiple_flags() {
    assert_eq!(
        resolved_command_name("parallel -j 4 -k --tag git push"),
        "git"
    );
}

// --- nested wrappers ---

#[test]
fn sudo_env_git() {
    assert_eq!(resolved_command_name("sudo env FOO=bar git commit"), "git");
}

#[test]
fn sudo_env_u_git() {
    assert_eq!(
        resolved_command_name("sudo -u deploy env -C /app git pull"),
        "git"
    );
}

#[test]
fn env_nice_git() {
    assert_eq!(
        resolved_command_name("env FOO=bar nice -n 5 git push"),
        "git"
    );
}

// --- non-wrappers pass through ---

#[test]
fn plain_git() {
    assert_eq!(resolved_command_name("git status"), "git");
}

#[test]
fn plain_ls() {
    assert_eq!(resolved_command_name("ls -la /tmp"), "ls");
}

#[test]
fn env_vars_before_command() {
    assert_eq!(resolved_command_name("GIT_CONFIG=x git push"), "git");
}

// --- time ---

#[test]
fn time_strips_to_inner() {
    assert_eq!(resolved_command_name("time git commit"), "git");
}

#[test]
fn time_with_flags() {
    assert_eq!(resolved_command_name("time -p git commit"), "git");
}

// --- timeout ---

/// timeout's usage is `timeout [options] duration command`. The duration is
/// a mandatory positional before the command. With the current WrapperSpec
/// (no positional-skip awareness), stripping stops at the first non-flag
#[test]
fn timeout_strips_to_inner() {
    assert_eq!(resolved_command_name("timeout 60 git commit"), "git");
}

#[test]
fn timeout_k_flag_strips() {
    assert_eq!(resolved_command_name("timeout -k 10 60 git commit"), "git");
}

#[test]
fn timeout_signal_long_strips() {
    assert_eq!(
        resolved_command_name("timeout --signal=TERM 60 git commit"),
        "git"
    );
}

#[test]
fn timeout_s_flag_strips() {
    assert_eq!(
        resolved_command_name("timeout -s TERM 60 git commit"),
        "git"
    );
}

// --- exec ---

#[test]
fn exec_strips_to_inner() {
    assert_eq!(resolved_command_name("exec git commit"), "git");
}

#[test]
fn exec_with_env() {
    assert_eq!(resolved_command_name("exec FOO=bar git commit"), "git");
}

#[test]
fn exec_a_flag_strips() {
    assert_eq!(resolved_command_name("exec -a alias git commit"), "git");
}

// --- setsid ---

#[test]
fn setsid_strips_to_inner() {
    assert_eq!(resolved_command_name("setsid git commit"), "git");
}

#[test]
fn setsid_with_flags() {
    assert_eq!(resolved_command_name("setsid -f git commit"), "git");
}

// --- strace ---

#[test]
fn strace_strips_to_inner() {
    assert_eq!(resolved_command_name("strace git commit"), "git");
}

#[test]
fn strace_o_flag_strips() {
    assert_eq!(
        resolved_command_name("strace -o /dev/null git commit"),
        "git"
    );
}

#[test]
fn strace_terminator() {
    assert_eq!(resolved_command_name("strace -- git commit"), "git");
}

// --- ionice ---

#[test]
fn ionice_strips_to_inner() {
    assert_eq!(resolved_command_name("ionice git commit"), "git");
}

#[test]
fn ionice_c_n_strips() {
    assert_eq!(resolved_command_name("ionice -c 2 -n 7 git commit"), "git");
}

// --- chrt ---

/// chrt's usage is `chrt [options] priority command`. The priority is a
/// positional arg that comes before the actual command. With the current
/// WrapperSpec (no positional-count awareness), stripping stops at the
#[test]
fn chrt_with_priority() {
    assert_eq!(resolved_command_name("chrt -f 10 git commit"), "git");
}

// --- taskset ---

#[test]
fn taskset_strips_to_inner() {
    assert_eq!(resolved_command_name("taskset 0x1 git commit"), "git");
}

/// taskset -c: `-c` consumes the next token as a value (cpu-list),
/// so the next non-flag token is the actual command.
#[test]
fn taskset_c_flag() {
    assert_eq!(resolved_command_name("taskset -c 0-3 git commit"), "git");
}

// --- sudo unanalyzable flags ---

#[test]
fn sudo_i_is_unanalyzable() {
    assert!(resolved_command_name("sudo -i git commit").starts_with("UNANALYZABLE"));
}

#[test]
fn sudo_s_is_unanalyzable() {
    assert!(resolved_command_name("sudo -s git commit").starts_with("UNANALYZABLE"));
}

// --- terminator scopes unanalyzable-flag check ---

#[test]
fn sudo_terminator_scopes_unanalyzable_flags() {
    // -s after -- belongs to `git commit`, not sudo
    assert_eq!(resolved_command_name("sudo -- git commit -s"), "git");
}

#[test]
fn sudo_s_before_terminator_is_unanalyzable() {
    assert!(resolved_command_name("sudo -s -- git commit").starts_with("UNANALYZABLE"));
}

#[test]
fn sudo_git_commit_s_without_terminator() {
    // -s is git-commit's signoff flag, not sudo's -s (login shell).
    // Without a `--` terminator, the parser must still recognize that -s
    // appears after the inner command starts and scope it to git, not sudo.
    assert_eq!(resolved_command_name("sudo git commit -s"), "git");
}

// --- combined short flags ---

#[test]
fn sudo_combined_u_value() {
    assert_eq!(resolved_command_name("sudo -uroot git commit"), "git");
}

#[test]
fn sudo_combined_iu_is_unanalyzable() {
    assert!(resolved_command_name("sudo -iu root git commit").starts_with("UNANALYZABLE"));
}

#[test]
fn sudo_combined_si_is_unanalyzable() {
    assert!(resolved_command_name("sudo -si git commit").starts_with("UNANALYZABLE"));
}

#[test]
fn env_combined_s_is_unanalyzable() {
    assert!(resolved_command_name("env -Si git commit").starts_with("UNANALYZABLE"));
}

// --- resolve_command with default config ---

#[test]
fn resolve_plain_command() {
    assert_eq!(resolved_command_name("git commit"), "git");
}

#[test]
fn resolve_dynamic_is_unanalyzable() {
    assert!(resolved_command_name("$cmd args").starts_with("UNANALYZABLE"));
}

#[test]
fn resolve_depth_limit() {
    let mut tokens: Vec<Word> = Vec::new();
    for i in 0..33 {
        if i % 2 == 0 {
            tokens.push(Word::from("sudo"));
        } else {
            tokens.push(Word::from("env"));
        }
    }
    tokens.push(Word::from("git"));
    tokens.push(Word::from("commit"));

    let result = resolve_command(&tokens);
    assert!(matches!(result, ResolvedCommand::Unanalyzable(_)));
}

// --- command_characteristics with default config ---

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
