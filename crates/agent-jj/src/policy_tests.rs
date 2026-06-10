use super::*;
use agent_shell_parser::parse::{tokenize, Word};

fn words(s: &str) -> Vec<Word> {
    tokenize(s)
}

fn is_blocked_segment(cmd: &str) -> bool {
    check_segment(&words(cmd)).is_some()
}

// --- Destructive / state-modifying ---

#[test]
fn blocks_git_commit() {
    assert!(is_blocked_segment("git commit -m 'test'"));
}

#[test]
fn blocks_git_rebase() {
    assert!(is_blocked_segment("git rebase main"));
}

#[test]
fn blocks_git_merge() {
    assert!(is_blocked_segment("git merge feature-branch"));
}

#[test]
fn blocks_git_stash() {
    assert!(is_blocked_segment("git stash pop"));
}

#[test]
fn blocks_git_revert() {
    assert!(is_blocked_segment("git revert HEAD"));
}

#[test]
fn blocks_git_cherry_pick() {
    assert!(is_blocked_segment("git cherry-pick abc123"));
}

#[test]
fn blocks_git_reset_hard() {
    assert!(is_blocked_segment("git reset --hard HEAD~1"));
}

#[test]
fn blocks_git_reset_without_flags() {
    assert!(is_blocked_segment("git reset HEAD file.rs"));
}

// --- Navigation / working copy ---

#[test]
fn blocks_git_checkout() {
    assert!(is_blocked_segment("git checkout main"));
}

#[test]
fn blocks_git_checkout_dash_b() {
    assert!(is_blocked_segment("git checkout -b new-branch"));
}

#[test]
fn blocks_bare_git_checkout() {
    assert!(is_blocked_segment("git checkout"));
}

#[test]
fn blocks_git_switch() {
    assert!(is_blocked_segment("git switch feature-branch"));
}

// --- Staging / file tracking ---

#[test]
fn blocks_git_add() {
    assert!(is_blocked_segment("git add ."));
}

#[test]
fn blocks_git_rm() {
    assert!(is_blocked_segment("git rm --cached file.rs"));
}

#[test]
fn blocks_git_restore() {
    assert!(is_blocked_segment("git restore --source HEAD~1 file.rs"));
}

#[test]
fn blocks_git_clean() {
    assert!(is_blocked_segment("git clean -fd"));
}

// --- Branch / bookmark management ---

#[test]
fn blocks_git_branch_list() {
    assert!(is_blocked_segment("git branch"));
}

#[test]
fn blocks_git_branch_create() {
    assert!(is_blocked_segment("git branch new-feature"));
}

#[test]
fn blocks_git_branch_delete() {
    assert!(is_blocked_segment("git branch -D feature-x"));
}

#[test]
fn blocks_git_tag() {
    assert!(is_blocked_segment("git tag v1.0.0"));
}

// --- Remote operations ---

#[test]
fn blocks_git_push() {
    assert!(is_blocked_segment("git push origin main"));
}

#[test]
fn blocks_git_push_force() {
    assert!(is_blocked_segment("git push --force origin main"));
}

#[test]
fn blocks_git_fetch() {
    assert!(is_blocked_segment("git fetch origin"));
}

#[test]
fn blocks_git_pull() {
    assert!(is_blocked_segment("git pull --rebase origin main"));
}

#[test]
fn blocks_git_clone() {
    assert!(is_blocked_segment(
        "git clone https://github.com/example/repo.git"
    ));
}

#[test]
fn blocks_git_init() {
    assert!(is_blocked_segment("git init"));
}

#[test]
fn blocks_git_remote() {
    assert!(is_blocked_segment(
        "git remote add origin https://github.com/example/repo.git"
    ));
}

// --- Informational ---

#[test]
fn blocks_git_status() {
    assert!(is_blocked_segment("git status"));
}

#[test]
fn blocks_git_log() {
    assert!(is_blocked_segment("git log --oneline -10"));
}

#[test]
fn blocks_git_diff() {
    assert!(is_blocked_segment("git diff --stat"));
}

#[test]
fn blocks_git_show() {
    assert!(is_blocked_segment("git show HEAD"));
}

#[test]
fn blocks_git_blame() {
    assert!(is_blocked_segment("git blame src/main.rs"));
}

// --- Worktree (selective) ---

#[test]
fn blocks_git_worktree_add() {
    assert!(is_blocked_segment("git worktree add ../other-dir"));
}

#[test]
fn allows_git_worktree_list() {
    assert!(!is_blocked_segment("git worktree list"));
}

#[test]
fn allows_git_worktree_repair() {
    assert!(!is_blocked_segment("git worktree repair"));
}

#[test]
fn allows_git_worktree_prune() {
    assert!(!is_blocked_segment("git worktree prune"));
}

// --- Allowed through ---

#[test]
fn allows_gh_commands() {
    assert!(!is_blocked_segment("gh pr create --title test"));
}

#[test]
fn allows_git_config() {
    assert!(!is_blocked_segment("git config user.name"));
}

#[test]
fn allows_git_bisect() {
    assert!(!is_blocked_segment("git bisect start"));
}

// --- Flag handling ---

#[test]
fn handles_git_with_global_flags() {
    assert!(is_blocked_segment("git -C /tmp/repo status"));
}

#[test]
fn handles_git_no_pager() {
    assert!(is_blocked_segment("git --no-pager log"));
}

// --- jj git subcommands must not be blocked ---

#[test]
fn allows_jj_git_push() {
    assert!(!is_blocked_segment("jj git push --bookmark main"));
}

#[test]
fn allows_jj_git_fetch() {
    assert!(!is_blocked_segment("jj git fetch"));
}

#[test]
fn allows_jj_git_clone() {
    assert!(!is_blocked_segment(
        "jj git clone --colocate https://example.com/repo.git"
    ));
}

#[test]
fn allows_jj_git_remote() {
    assert!(!is_blocked_segment("jj git remote list"));
}

#[test]
fn allows_jj_git_init() {
    assert!(!is_blocked_segment("jj git init --colocate"));
}

// --- Env-var-prefixed git commands should still be blocked ---

#[test]
fn blocks_env_prefixed_git_push() {
    assert!(is_blocked_segment(
        "GIT_CONFIG_GLOBAL=~/.gitconfig.ai git push origin main"
    ));
}

#[test]
fn blocks_env_prefixed_git_commit() {
    assert!(is_blocked_segment("FOO=bar BAZ=qux git commit -m test"));
}

// --- Suggestion quality ---

#[test]
fn status_suggestion_mentions_jj_status() {
    let blocked = check_segment(&words("git status")).unwrap();
    assert!(
        blocked.suggestion.contains("jj status"),
        "suggestion should mention jj status"
    );
}

#[test]
fn diff_suggestion_covers_common_forms() {
    let blocked = check_segment(&words("git diff")).unwrap();
    assert!(
        blocked.suggestion.contains("jj diff"),
        "should mention jj diff"
    );
    assert!(
        blocked.suggestion.contains("--from"),
        "should mention --from/--to form"
    );
    assert!(
        blocked.suggestion.contains("--git"),
        "should mention --git for unified diff format"
    );
    assert!(
        blocked.suggestion.contains("--stat"),
        "should mention --stat"
    );
}

#[test]
fn push_suggestion_mentions_bookmark() {
    let blocked = check_segment(&words("git push origin main")).unwrap();
    assert!(
        blocked.suggestion.contains("jj git push"),
        "should mention jj git push"
    );
    assert!(
        blocked.suggestion.contains("--bookmark"),
        "should mention --bookmark"
    );
}

#[test]
fn branch_suggestion_covers_list_create_delete() {
    let blocked = check_segment(&words("git branch")).unwrap();
    assert!(
        blocked.suggestion.contains("bookmark list"),
        "should cover list"
    );
    assert!(
        blocked.suggestion.contains("bookmark create"),
        "should cover create"
    );
    assert!(
        blocked.suggestion.contains("bookmark delete"),
        "should cover delete"
    );
}

// --- Indirect execution ---

#[test]
fn blocks_eval() {
    assert!(is_blocked_segment("eval \"git commit\""));
}

#[test]
fn blocks_bash_c() {
    assert!(is_blocked_segment("bash -c \"git commit\""));
}

#[test]
fn blocks_sh_c() {
    assert!(is_blocked_segment("sh -c \"git commit -m test\""));
}

#[test]
fn blocks_source() {
    assert!(is_blocked_segment("source script.sh"));
}

#[test]
fn blocks_dot_source() {
    assert!(is_blocked_segment(". script.sh"));
}

#[test]
fn blocks_dynamic_command() {
    assert!(is_blocked_segment("$cmd args"));
}

#[test]
fn blocks_bash_script() {
    assert!(is_blocked_segment("bash script.sh"));
}

#[test]
fn blocks_env_git() {
    assert!(is_blocked_segment("env git commit"));
}

#[test]
fn blocks_sudo_git() {
    assert!(is_blocked_segment("sudo git commit"));
}

#[test]
fn blocks_sudo_with_flags_git() {
    assert!(is_blocked_segment("sudo -u root git commit"));
}

#[test]
fn blocks_command_git() {
    assert!(is_blocked_segment("command git commit"));
}

#[test]
fn blocks_env_with_vars_git() {
    assert!(is_blocked_segment("env FOO=bar git commit"));
}

#[test]
fn blocks_xargs_git() {
    assert!(is_blocked_segment("xargs git commit"));
}

#[test]
fn allows_env_ls() {
    assert!(!is_blocked_segment("env ls -la"));
}

#[test]
fn allows_sudo_ls() {
    assert!(!is_blocked_segment("sudo ls -la"));
}

#[test]
fn allows_normal_command() {
    assert!(!is_blocked_segment("ls -la"));
}

// --- New blocked git subcommands ---

#[test]
fn blocks_git_submodule() {
    assert!(is_blocked_segment(
        "git submodule add https://example.com/repo.git"
    ));
}

#[test]
fn blocks_git_am() {
    assert!(is_blocked_segment("git am patch.mbox"));
}

#[test]
fn blocks_git_apply() {
    assert!(is_blocked_segment("git apply patch.diff"));
}

#[test]
fn blocks_git_update_ref() {
    assert!(is_blocked_segment("git update-ref HEAD abc123"));
}

#[test]
fn blocks_git_update_index() {
    assert!(is_blocked_segment(
        "git update-index --assume-unchanged file"
    ));
}

// --- Wrappers around git commands ---

#[test]
fn blocks_time_git() {
    assert!(is_blocked_segment("time git commit"));
}

#[test]
fn blocks_timeout_git() {
    assert!(is_blocked_segment("timeout 60 git commit"));
}

#[test]
fn blocks_exec_git() {
    assert!(is_blocked_segment("exec git commit"));
}

#[test]
fn blocks_strace_git() {
    assert!(is_blocked_segment("strace git commit"));
}

#[test]
fn blocks_setsid_git() {
    assert!(is_blocked_segment("setsid git commit"));
}

#[test]
fn allows_time_ls() {
    assert!(!is_blocked_segment("time ls"));
}

#[test]
fn blocks_nohup_git() {
    assert!(is_blocked_segment("nohup git push"));
}

#[test]
fn allows_xargs_ls() {
    assert!(!is_blocked_segment("xargs ls -la"));
}

// --- Invocation forms that must still resolve to git ---
//
// These pin basename normalization and escape handling: invoking git by
// path or with a backslash escape must hit the same block as plain `git`.
// Asserting the specific blocked command (not just is_some) ensures these
// resolve to `git commit` rather than tripping a generic unanalyzable block.

fn blocked_as(cmd: &str) -> Option<&'static str> {
    check_segment(&words(cmd)).map(|b| b.command)
}

#[test]
fn blocks_git_by_absolute_path() {
    assert_eq!(
        blocked_as("/usr/bin/git commit -m test"),
        Some("git commit")
    );
}

#[test]
fn blocks_git_by_relative_path() {
    assert_eq!(blocked_as("./git commit -m test"), Some("git commit"));
}

#[test]
fn blocks_backslash_escaped_git() {
    // `\git` suppresses shell alias/function lookup but still runs git
    assert_eq!(blocked_as(r"\git commit -m test"), Some("git commit"));
}

#[test]
fn allows_permitted_subcommand_by_absolute_path() {
    // Path resolution must not over-block: subcommands allowed for plain
    // `git` stay allowed when git is invoked by path.
    assert!(!is_blocked_segment("/usr/bin/git config user.name"));
}
