use agent_shell_parser::parse::{
    command_characteristics, resolve_command, tokenize, IndirectExecution, ResolvedCommand, Word,
};
use rstest::rstest;

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

// --- wrapper resolves to inner command ---

#[rstest]
// env
#[case::env_strips_to_inner("env git commit", "git")]
#[case::env_u_strips_value("env -u HOME git commit", "git")]
#[case::env_unset_long_strips_value("env --unset HOME git commit", "git")]
#[case::env_unset_equals_strips("env --unset=HOME git commit", "git")]
#[case::env_c_strips_value("env -C /tmp git commit", "git")]
#[case::env_chdir_long_strips("env --chdir /tmp git commit", "git")]
#[case::env_with_assignments("env FOO=bar BAZ=qux git commit", "git")]
#[case::env_mixed_flags_and_assignments("env -u HOME FOO=bar -C /tmp git status", "git")]
#[case::env_terminator("env -- git commit", "git")]
#[case::env_i_flag_strips("env -i git commit", "git")]
// sudo
#[case::sudo_strips_to_inner("sudo git commit", "git")]
#[case::sudo_u_short_strips("sudo -u root git commit", "git")]
#[case::sudo_user_long_strips("sudo --user root git commit", "git")]
#[case::sudo_user_equals_strips("sudo --user=root git commit", "git")]
#[case::sudo_multiple_flags("sudo -u admin -g wheel git commit", "git")]
#[case::sudo_boolean_flags_skipped("sudo -E -H -n git commit", "git")]
#[case::sudo_terminator("sudo -- git commit", "git")]
// nice
#[case::nice_strips_to_inner("nice git commit", "git")]
#[case::nice_n_short_strips_value("nice -n 10 git commit", "git")]
#[case::nice_adjustment_long_strips("nice --adjustment 5 git commit", "git")]
#[case::nice_adjustment_equals_strips("nice --adjustment=5 git commit", "git")]
// nohup
#[case::nohup_strips_to_inner("nohup git push", "git")]
// command
#[case::command_strips_to_inner("command git commit", "git")]
#[case::command_p_flag_strips("command -p git commit", "git")]
#[case::command_v_flag_strips("command -v git", "git")]
// builtin
#[case::builtin_strips_to_inner("builtin echo hello", "echo")]
// xargs
#[case::xargs_strips_to_inner("xargs git commit", "git")]
#[case::xargs_p_flag_strips("xargs -P 4 git commit", "git")]
#[case::xargs_p_inline_strips("xargs -P4 git commit", "git")]
#[case::xargs_n_flag_strips("xargs -n 1 git commit", "git")]
#[case::xargs_multiple_value_flags("xargs -n 1 -P 4 -I {} git commit", "git")]
#[case::xargs_long_flags("xargs --max-procs=4 --max-args 1 git commit", "git")]
// parallel
#[case::parallel_strips_to_inner("parallel git push", "git")]
#[case::parallel_j_flag_strips("parallel -j 4 git push", "git")]
#[case::parallel_long_jobs_strips("parallel --jobs 4 git push", "git")]
#[case::parallel_multiple_flags("parallel -j 4 -k --tag git push", "git")]
// nested wrappers
#[case::sudo_env_git("sudo env FOO=bar git commit", "git")]
#[case::sudo_env_u_git("sudo -u deploy env -C /app git pull", "git")]
#[case::env_nice_git("env FOO=bar nice -n 5 git push", "git")]
// non-wrappers pass through
#[case::plain_git("git status", "git")]
#[case::plain_ls("ls -la /tmp", "ls")]
#[case::env_vars_before_command("GIT_CONFIG=x git push", "git")]
// time
#[case::time_strips_to_inner("time git commit", "git")]
#[case::time_with_flags("time -p git commit", "git")]
// timeout
#[case::timeout_strips_to_inner("timeout 60 git commit", "git")]
#[case::timeout_k_flag_strips("timeout -k 10 60 git commit", "git")]
#[case::timeout_signal_long_strips("timeout --signal=TERM 60 git commit", "git")]
#[case::timeout_s_flag_strips("timeout -s TERM 60 git commit", "git")]
// exec
#[case::exec_strips_to_inner("exec git commit", "git")]
#[case::exec_with_env("exec FOO=bar git commit", "git")]
#[case::exec_a_flag_strips("exec -a alias git commit", "git")]
// setsid
#[case::setsid_strips_to_inner("setsid git commit", "git")]
#[case::setsid_with_flags("setsid -f git commit", "git")]
// strace
#[case::strace_strips_to_inner("strace git commit", "git")]
#[case::strace_o_flag_strips("strace -o /dev/null git commit", "git")]
#[case::strace_terminator("strace -- git commit", "git")]
// ionice
#[case::ionice_strips_to_inner("ionice git commit", "git")]
#[case::ionice_c_n_strips("ionice -c 2 -n 7 git commit", "git")]
// chrt
#[case::chrt_with_priority("chrt -f 10 git commit", "git")]
// taskset
#[case::taskset_strips_to_inner("taskset 0x1 git commit", "git")]
#[case::taskset_c_flag("taskset -c 0-3 git commit", "git")]
// watch
#[case::watch_n_strips_interval_to_inner("watch -n 5 rm somefile", "rm")]
#[case::watch_interval_long_strips_to_inner("watch --interval 5 rm somefile", "rm")]
// ltrace
#[case::ltrace_e_strips_filter_to_inner("ltrace -e malloc rm somefile", "rm")]
#[case::ltrace_multiple_value_flags_strips("ltrace -e malloc -o /tmp/trace rm somefile", "rm")]
// su
#[case::su_skips_username_to_inner("su root ls", "ls")]
#[case::su_with_shell_flag_skips_value_and_username("su -s /bin/bash root ls", "ls")]
// After --, the parser treats everything as inner command — skip_positionals
// doesn't apply post-terminator. `su -- root ls` resolves to `root`, not `ls`.
// This is a semantic mismatch (real su treats root as username after --)
// but is fail-closed: `root` as a command is Unknown → Ask.
#[case::su_terminator_treats_next_as_inner("su -- root ls", "root")]
// long-form value flags
#[case::sudo_chroot_long_consumes_value("sudo --chroot /var/jail git commit", "git")]
#[case::sudo_chroot_equals_consumes_value("sudo --chroot=/var/jail git commit", "git")]
// terminator scopes unanalyzable-flag check
#[case::sudo_terminator_scopes_unanalyzable_flags("sudo -- git commit -s", "git")]
// -s is git-commit's signoff flag, not sudo's -s (login shell).
// Without a `--` terminator, the parser must still recognize that -s
// appears after the inner command starts and scope it to git, not sudo.
#[case::sudo_git_commit_s_without_terminator("sudo git commit -s", "git")]
// combined short flags
#[case::sudo_combined_u_value("sudo -uroot git commit", "git")]
// resolve_command with default config
#[case::resolve_plain_command("git commit", "git")]
fn wrapper_resolves_to_inner_command(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(resolved_command_name(input), expected);
}

// --- wrapper is unanalyzable ---

#[rstest]
// env
#[case::env_s_is_unanalyzable("env -S 'git commit' git push")]
#[case::env_split_string_long_is_unanalyzable("env --split-string='git commit'")]
#[case::env_combined_s_is_unanalyzable("env -Si git commit")]
// sudo
#[case::sudo_i_is_unanalyzable("sudo -i git commit")]
#[case::sudo_s_is_unanalyzable("sudo -s git commit")]
#[case::sudo_login_long_is_unanalyzable("sudo --login git commit")]
#[case::sudo_shell_long_is_unanalyzable("sudo --shell git commit")]
#[case::sudo_s_before_terminator_is_unanalyzable("sudo -s -- git commit")]
#[case::sudo_combined_iu_is_unanalyzable("sudo -iu root git commit")]
#[case::sudo_combined_si_is_unanalyzable("sudo -si git commit")]
// su
#[case::su_c_is_unanalyzable("su -c 'rm -rf /'")]
// dynamic command
#[case::resolve_dynamic_is_unanalyzable("$cmd args")]
fn wrapper_is_unanalyzable(#[case] input: &str) {
    assert!(resolved_command_name(input).starts_with("UNANALYZABLE"));
}

// --- standalone tests ---

#[test]
fn sudo_truncated_value_flag() {
    match resolve_command(&words("sudo -u")) {
        ResolvedCommand::Resolved(p) => assert_eq!(p.command, ""),
        _ => panic!("expected Resolved with empty command"),
    }
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

// --- characteristics: indirect execution ---

#[rstest]
#[case::eval("eval \"git commit\"", "eval", IndirectExecution::Eval)]
#[case::bash_c("bash -c \"git commit\"", "bash", IndirectExecution::ShellSpawn)]
#[case::bash_script("bash script.sh", "bash", IndirectExecution::SourceScript)]
#[case::env_wrapper("env git commit", "env", IndirectExecution::CommandWrapper)]
#[case::sudo_wrapper("sudo git commit", "sudo", IndirectExecution::CommandWrapper)]
#[case::source("source script.sh", "source", IndirectExecution::SourceScript)]
#[case::dot_source(". script.sh", ".", IndirectExecution::SourceScript)]
fn characteristics_indirect_execution(
    #[case] input: &str,
    #[case] expected_base: &str,
    #[case] expected_execution: IndirectExecution,
) {
    let c = command_characteristics(input);
    assert_eq!(c.base_command, expected_base);
    assert_eq!(c.indirect_execution, Some(expected_execution));
    assert!(!c.has_dynamic_command);
}

// --- standalone characteristics tests ---

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
