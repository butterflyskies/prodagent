use agent_shell_parser::parse::{
    resolve_command, CommandArg, IndirectExecution, ParsedCommand, ResolvedCommand,
};
use std::fmt;

#[derive(Debug, Clone)]
pub struct BlockedCommand {
    pub command: &'static str,
    pub reason: &'static str,
    pub suggestion: &'static str,
}

impl fmt::Display for BlockedCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BLOCKED: `{}` — {}\n\nThis is a jj-colocated repo. Use jj instead:\n\n  {}",
            self.command, self.reason, self.suggestion
        )
    }
}

static BLOCKED_COMMANDS: &[(&str, BlockedCommand)] = &[
    // History / state-modifying
    ("commit", BlockedCommand {
        command: "git commit",
        reason: "git commit bypasses jj's change tracking.",
        suggestion: "jj describe -m '...'  (set message on current change)\n  jj new  (start a new change after the current one)",
    }),
    ("rebase", BlockedCommand {
        command: "git rebase",
        reason: "git rebase conflicts with jj's history management.",
        suggestion: "jj rebase -s <source> -o <destination>\n  jj rebase -b @ -o main@origin  (rebase current work onto updated remote)",
    }),
    ("merge", BlockedCommand {
        command: "git merge",
        reason: "git merge conflicts with jj's history management.",
        suggestion: "jj new <parent-a> <parent-b>  (create a merge change)",
    }),
    ("stash", BlockedCommand {
        command: "git stash",
        reason: "jj snapshots the working copy automatically — stash is unnecessary.",
        suggestion: "jj new  (start fresh change; previous work is already snapshotted)",
    }),
    ("revert", BlockedCommand {
        command: "git revert",
        reason: "git revert bypasses jj's change tracking.",
        suggestion: "jj backout -r <change-id>",
    }),
    ("cherry-pick", BlockedCommand {
        command: "git cherry-pick",
        reason: "git cherry-pick bypasses jj's change tracking.",
        suggestion: "jj duplicate <change-id>  then  jj rebase -s <new> -o <destination>",
    }),
    ("reset", BlockedCommand {
        command: "git reset",
        reason: "git reset modifies state that jj manages.",
        suggestion: "jj restore <path>  (restore files from parent change)\n  jj abandon  (discard a change entirely)",
    }),
    // Navigation / working copy
    ("checkout", BlockedCommand {
        command: "git checkout",
        reason: "git checkout conflicts with jj's working-copy management.",
        suggestion: "jj edit <change-id>  (switch to an existing change)\n  jj new <parent>  (start new work after a change)\n  jj restore --from <change-id> <path>  (restore specific files)",
    }),
    ("switch", BlockedCommand {
        command: "git switch",
        reason: "git switch conflicts with jj's working-copy management.",
        suggestion: "jj edit <change-id>  (switch to an existing change)\n  jj new <parent>  (start new work after a change)",
    }),
    // Staging / file tracking
    ("add", BlockedCommand {
        command: "git add",
        reason: "jj has no staging area — it snapshots the working copy automatically.",
        suggestion: "No action needed for tracked files — jj sees changes automatically.\n  jj file track <path>  (start tracking a new untracked file)",
    }),
    ("rm", BlockedCommand {
        command: "git rm",
        reason: "jj has no staging area — file tracking works differently.",
        suggestion: "jj file untrack <path>  (stop tracking a file)\n  Or just delete the file — jj will notice.",
    }),
    ("restore", BlockedCommand {
        command: "git restore",
        reason: "git restore conflicts with jj's working-copy management.",
        suggestion: "jj restore <path>  (restore files from parent)\n  jj restore --from <change-id> <path>  (restore from a specific change)",
    }),
    ("clean", BlockedCommand {
        command: "git clean",
        reason: "git clean can delete files that jj is tracking.",
        suggestion: "jj restore  (restore the working copy to match the parent change)",
    }),
    // Branch / bookmark management
    ("branch", BlockedCommand {
        command: "git branch",
        reason: "jj uses bookmarks instead of git branches.",
        suggestion: "jj bookmark list  (list bookmarks)\n  jj bookmark create <name>  (create a bookmark at @)\n  jj bookmark delete <name>  (delete a bookmark)\n  jj bookmark move --to <change-id> <name>  (move a bookmark)",
    }),
    ("tag", BlockedCommand {
        command: "git tag",
        reason: "jj does not manage tags directly.",
        suggestion: "jj tag list  (list tags)\n  jj git push --tag <name>  (push a tag to remote)",
    }),
    // Remote operations
    ("push", BlockedCommand {
        command: "git push",
        reason: "jj manages push safety automatically — use jj git push.",
        suggestion: "jj git push --bookmark <name>  (push a specific bookmark)\n  jj git push --change <change-id>  (push and auto-create bookmark)\n  jj git push --all  (push all bookmarks)",
    }),
    ("fetch", BlockedCommand {
        command: "git fetch",
        reason: "Use jj git fetch to keep jj's view of remotes consistent.",
        suggestion: "jj git fetch  (fetch from all remotes)\n  jj git fetch --remote <name>  (fetch from a specific remote)",
    }),
    ("pull", BlockedCommand {
        command: "git pull",
        reason: "jj has no pull — fetch and rebase are separate steps.",
        suggestion: "jj git fetch  (fetch latest from remote)\n  jj rebase -b @ -o main@origin  (rebase onto updated remote, if needed)",
    }),
    // Repository setup
    ("clone", BlockedCommand {
        command: "git clone",
        reason: "Use jj git clone to get a jj-native repo from the start.",
        suggestion: "jj git clone --colocate <url>  (clone with jj+git colocated)",
    }),
    ("init", BlockedCommand {
        command: "git init",
        reason: "Use jj git init to set up jj from the start.",
        suggestion: "jj git init --colocate  (initialize jj+git colocated repo)",
    }),
    ("remote", BlockedCommand {
        command: "git remote",
        reason: "Use jj git remote to keep jj's view consistent.",
        suggestion: "jj git remote list  (list remotes)\n  jj git remote add <name> <url>  (add a remote)\n  jj git remote remove <name>  (remove a remote)\n  jj git remote rename <old> <new>  (rename a remote)",
    }),
    // Informational
    ("status", BlockedCommand {
        command: "git status",
        reason: "jj status understands jj's change model and shows richer information.",
        suggestion: "jj status  (show working-copy changes and current change info)",
    }),
    ("log", BlockedCommand {
        command: "git log",
        reason: "jj log shows the change graph with change-ids, which are more useful than commit SHAs.",
        suggestion: "jj log  (show change graph)\n  jj log -r <revset>  (filter, e.g. 'jj log -r main..@')",
    }),
    ("diff", BlockedCommand {
        command: "git diff",
        reason: "jj diff understands jj's change model and requires no staging.",
        suggestion: "jj diff  (diff of current change vs parent)\n  jj diff -r <change-id>  (diff of a specific change)\n  jj diff --from <a> --to <b>  (diff between two revisions)\n  jj diff --git  (unified diff format, like git diff)\n  jj diff --stat  (summary of changes)",
    }),
    ("show", BlockedCommand {
        command: "git show",
        reason: "jj show uses change-ids and understands jj's change model.",
        suggestion: "jj show <change-id>  (show a specific change with message and diff)",
    }),
    ("blame", BlockedCommand {
        command: "git blame",
        reason: "jj has its own annotation command.",
        suggestion: "jj file annotate <path>  (show per-line change attribution)",
    }),
    // Patch / low-level ref manipulation
    ("submodule", BlockedCommand {
        command: "git submodule",
        reason: "modifies .gitmodules and submodule state",
        suggestion: "jj does not support submodules — manage dependencies through other means",
    }),
    ("am", BlockedCommand {
        command: "git am",
        reason: "applies patches and creates commits",
        suggestion: "use `jj` to create changes from patches",
    }),
    ("apply", BlockedCommand {
        command: "git apply",
        reason: "applies patches to the working tree",
        suggestion: "use `jj` to manage working copy changes",
    }),
    ("update-ref", BlockedCommand {
        command: "git update-ref",
        reason: "directly manipulates refs",
        suggestion: "use `jj bookmark` to manage references",
    }),
    ("update-index", BlockedCommand {
        command: "git update-index",
        reason: "directly manipulates the index",
        suggestion: "use `jj` to manage the working copy",
    }),
];

static BLOCKED_EVAL: BlockedCommand = BlockedCommand {
    command: "eval",
    reason: "eval executes arbitrary shell code that cannot be statically analyzed.",
    suggestion: "Write the command directly instead of wrapping it in eval.",
};

static BLOCKED_SHELL_SPAWN: BlockedCommand = BlockedCommand {
    command: "shell -c",
    reason: "spawning a shell with -c executes code that cannot be statically analyzed.",
    suggestion: "Write the command directly instead of wrapping it in bash/sh -c.",
};

static BLOCKED_SOURCE: BlockedCommand = BlockedCommand {
    command: "source",
    reason: "sourced scripts execute code that cannot be statically analyzed.",
    suggestion: "Run the script contents directly instead of sourcing it.",
};

static BLOCKED_UNANALYZABLE: BlockedCommand = BlockedCommand {
    command: "unknown indirect",
    reason: "this command uses an indirect execution pattern that cannot be statically analyzed.",
    suggestion: "Run the command from outside of the coding agent.",
};

/// git global flags that consume the following token as a value.
const GIT_GLOBAL_ARG_FLAGS: &[&str] = &["-C", "-c", "--git-dir", "--work-tree", "--namespace"];

/// Extract the git subcommand from a parsed command, skipping git global flags
/// that consume positional values.
fn git_subcommand(parsed: &ParsedCommand) -> Option<&str> {
    let mut skip_next = false;
    for arg in &parsed.args {
        match arg {
            CommandArg::Flag(f)
                if GIT_GLOBAL_ARG_FLAGS.contains(&f.name.as_str()) && f.value.is_none() =>
            {
                skip_next = true;
            }
            CommandArg::Positional(_) if skip_next => {
                skip_next = false;
            }
            CommandArg::Positional(s) => return Some(s.as_str()),
            _ => {}
        }
    }
    None
}

fn check_git_command(parsed: &ParsedCommand) -> Option<&'static BlockedCommand> {
    if parsed.command != "git" {
        return None;
    }
    let subcommand = git_subcommand(parsed)?;

    for (name, blocked) in BLOCKED_COMMANDS {
        if subcommand == *name {
            return Some(blocked);
        }
    }

    if subcommand == "worktree" {
        let wt_sub = parsed
            .args
            .iter()
            .filter_map(|a| match a {
                CommandArg::Positional(s) => Some(s.as_str()),
                _ => None,
            })
            .skip_while(|s| *s != "worktree")
            .nth(1);
        if let Some(wt_cmd) = wt_sub {
            if wt_cmd != "list" && wt_cmd != "repair" && wt_cmd != "prune" {
                static WORKTREE_BLOCKED: BlockedCommand = BlockedCommand {
                    command: "git worktree",
                    reason: "git worktrees are invisible to jj — use jj workspaces instead.",
                    suggestion: "jj workspace add <path> --name <name>  (create)\n  jj workspace forget <name>  (remove)",
                };
                return Some(&WORKTREE_BLOCKED);
            }
        }
    }

    None
}

/// Check a tokenized command against jj-guard policy.
///
/// Resolves indirection (wrappers, eval, etc.) then checks whether
/// the effective command is a blocked git operation.
pub fn check_segment(words: &[String]) -> Option<&'static BlockedCommand> {
    match resolve_command(words) {
        ResolvedCommand::Unanalyzable(u) => match u.kind {
            IndirectExecution::Eval => Some(&BLOCKED_EVAL),
            IndirectExecution::ShellSpawn => Some(&BLOCKED_SHELL_SPAWN),
            IndirectExecution::SourceScript => Some(&BLOCKED_SOURCE),
            IndirectExecution::CommandWrapper => Some(&BLOCKED_UNANALYZABLE),
            // #[non_exhaustive]: fail closed on future IndirectExecution variants
            _ => Some(&BLOCKED_UNANALYZABLE),
        },
        ResolvedCommand::Resolved(ref parsed) => check_git_command(parsed),
        // #[non_exhaustive]: fail closed on future ResolvedCommand variants
        _ => Some(&BLOCKED_UNANALYZABLE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_shell_parser::parse::tokenize;

    fn words(s: &str) -> Vec<String> {
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
}
