use super::*;
use agent_shell_parser::parse::{tokenize, Word};
use rstest::rstest;

fn words(s: &str) -> Vec<Word> {
    tokenize(s)
}

fn is_blocked_segment(cmd: &str) -> bool {
    check_segment(&words(cmd)).is_some()
}

// --- All commands that should be blocked ---

#[rstest]
// Destructive / state-modifying
#[case::git_commit("git commit -m 'test'")]
#[case::git_rebase("git rebase main")]
#[case::git_merge("git merge feature-branch")]
#[case::git_stash("git stash pop")]
#[case::git_revert("git revert HEAD")]
#[case::git_cherry_pick("git cherry-pick abc123")]
#[case::git_reset_hard("git reset --hard HEAD~1")]
#[case::git_reset_without_flags("git reset HEAD file.rs")]
// Navigation / working copy
#[case::git_checkout("git checkout main")]
#[case::git_checkout_dash_b("git checkout -b new-branch")]
#[case::bare_checkout("git checkout")]
#[case::git_switch("git switch feature-branch")]
// Staging / file tracking
#[case::git_add("git add .")]
#[case::git_rm("git rm --cached file.rs")]
#[case::git_restore("git restore --source HEAD~1 file.rs")]
#[case::git_clean("git clean -fd")]
// Branch / bookmark management
#[case::branch_list("git branch")]
#[case::branch_create("git branch new-feature")]
#[case::branch_delete("git branch -D feature-x")]
#[case::git_tag("git tag v1.0.0")]
// Remote operations
#[case::git_push("git push origin main")]
#[case::push_force("git push --force origin main")]
#[case::git_fetch("git fetch origin")]
#[case::git_pull("git pull --rebase origin main")]
#[case::git_clone("git clone https://github.com/example/repo.git")]
#[case::git_init("git init")]
#[case::git_remote("git remote add origin https://github.com/example/repo.git")]
// Informational
#[case::git_status("git status")]
#[case::git_log("git log --oneline -10")]
#[case::git_diff("git diff --stat")]
#[case::git_show("git show HEAD")]
#[case::git_blame("git blame src/main.rs")]
// Worktree (add is blocked)
#[case::worktree_add("git worktree add ../other-dir")]
// Flag handling
#[case::with_global_flags("git -C /tmp/repo status")]
#[case::no_pager("git --no-pager log")]
// Env-var-prefixed
#[case::env_prefixed("GIT_CONFIG_GLOBAL=~/.gitconfig.ai git push origin main")]
#[case::env_prefixed_multi("FOO=bar BAZ=qux git commit -m test")]
// Indirect execution
#[case::eval("eval \"git commit\"")]
#[case::bash_c("bash -c \"git commit\"")]
#[case::sh_c("sh -c \"git commit -m test\"")]
#[case::source("source script.sh")]
#[case::dot_source(". script.sh")]
#[case::dynamic_command("$cmd args")]
#[case::bash_script("bash script.sh")]
// Wrapper-prefixed
#[case::env_git("env git commit")]
#[case::sudo_git("sudo git commit")]
#[case::sudo_with_flags_git("sudo -u root git commit")]
#[case::command_git("command git commit")]
#[case::env_with_vars_git("env FOO=bar git commit")]
#[case::xargs_git("xargs git commit")]
#[case::time_git("time git commit")]
#[case::timeout_git("timeout 60 git commit")]
#[case::exec_git("exec git commit")]
#[case::strace_git("strace git commit")]
#[case::setsid_git("setsid git commit")]
#[case::nohup_git("nohup git push")]
// New subcommands
#[case::submodule("git submodule add https://example.com/repo.git")]
#[case::am("git am patch.mbox")]
#[case::apply("git apply patch.diff")]
#[case::update_ref("git update-ref HEAD abc123")]
#[case::update_index("git update-index --assume-unchanged file")]
fn segment_is_blocked(#[case] cmd: &str) {
    assert!(is_blocked_segment(cmd), "expected blocked: {cmd}");
}

// --- All commands that should be allowed ---

#[rstest]
#[case::git_worktree_list("git worktree list")]
#[case::git_worktree_repair("git worktree repair")]
#[case::git_worktree_prune("git worktree prune")]
#[case::gh_commands("gh pr create --title test")]
#[case::git_config("git config user.name")]
#[case::git_bisect("git bisect start")]
#[case::jj_git_push("jj git push --bookmark main")]
#[case::jj_git_fetch("jj git fetch")]
#[case::jj_git_clone("jj git clone --colocate https://example.com/repo.git")]
#[case::jj_git_remote("jj git remote list")]
#[case::jj_git_init("jj git init --colocate")]
#[case::env_ls("env ls -la")]
#[case::sudo_ls("sudo ls -la")]
#[case::normal_command("ls -la")]
#[case::time_ls("time ls")]
#[case::xargs_ls("xargs ls -la")]
#[case::permitted_by_path("/usr/bin/git config user.name")]
fn segment_is_allowed(#[case] cmd: &str) {
    assert!(!is_blocked_segment(cmd), "expected allowed: {cmd}");
}

// --- Invocation forms that must resolve to specific git commands ---

fn blocked_as(cmd: &str) -> Option<&'static str> {
    check_segment(&words(cmd)).map(|b| b.command)
}

#[rstest]
#[case::absolute_path("/usr/bin/git commit -m test", "git commit")]
#[case::relative_path("./git commit -m test", "git commit")]
#[case::backslash_escaped(r"\git commit -m test", "git commit")]
fn blocked_as_command(#[case] cmd: &str, #[case] expected: &str) {
    assert_eq!(blocked_as(cmd), Some(expected), "command: {cmd}");
}

// --- Suggestion quality (heterogeneous assertions, kept standalone) ---

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
