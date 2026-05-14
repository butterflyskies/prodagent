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
];

pub fn check_git_command(words: &[String]) -> Option<&'static BlockedCommand> {
    let git_idx = words.iter().position(|w| w == "git")?;
    let subcommand = find_git_subcommand(words, git_idx)?;

    for (name, blocked) in BLOCKED_COMMANDS {
        if subcommand == *name {
            return Some(blocked);
        }
    }

    // Special case: git worktree (allow list/repair, block others)
    if subcommand == "worktree" {
        let rest = &words[git_idx..];
        let wt_sub = rest.iter().skip_while(|w| *w != "worktree").nth(1);
        if let Some(wt_cmd) = wt_sub {
            if wt_cmd != "list" && wt_cmd != "repair" {
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

const GIT_GLOBAL_ARG_FLAGS: &[&str] = &["-C", "-c", "--git-dir", "--work-tree", "--namespace"];
const GIT_GLOBAL_SOLO_FLAGS: &[&str] = &["--bare", "--no-pager", "--no-replace-objects"];

fn find_git_subcommand(words: &[String], git_idx: usize) -> Option<String> {
    let mut i = git_idx + 1;
    while i < words.len() {
        let word = &words[i];
        if GIT_GLOBAL_ARG_FLAGS.iter().any(|f| word == f) {
            i += 2;
        } else if GIT_GLOBAL_SOLO_FLAGS.iter().any(|f| word == f) || word.starts_with('-') {
            i += 1;
        } else {
            return Some(word.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(s: &str) -> Vec<String> {
        shell_words::split(s).unwrap()
    }

    // --- Destructive / state-modifying ---

    #[test]
    fn blocks_git_commit() {
        let w = words("git commit -m 'test'");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_rebase() {
        let w = words("git rebase main");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_merge() {
        let w = words("git merge feature-branch");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_stash() {
        let w = words("git stash pop");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_revert() {
        let w = words("git revert HEAD");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_cherry_pick() {
        let w = words("git cherry-pick abc123");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_reset_hard() {
        let w = words("git reset --hard HEAD~1");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_reset_without_flags() {
        let w = words("git reset HEAD file.rs");
        assert!(check_git_command(&w).is_some());
    }

    // --- Navigation / working copy ---

    #[test]
    fn blocks_git_checkout() {
        let w = words("git checkout main");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_checkout_dash_b() {
        let w = words("git checkout -b new-branch");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_bare_git_checkout() {
        let w = words("git checkout");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_switch() {
        let w = words("git switch feature-branch");
        assert!(check_git_command(&w).is_some());
    }

    // --- Staging / file tracking ---

    #[test]
    fn blocks_git_add() {
        let w = words("git add .");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_rm() {
        let w = words("git rm --cached file.rs");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_restore() {
        let w = words("git restore --source HEAD~1 file.rs");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_clean() {
        let w = words("git clean -fd");
        assert!(check_git_command(&w).is_some());
    }

    // --- Branch / bookmark management ---

    #[test]
    fn blocks_git_branch_list() {
        let w = words("git branch");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_branch_create() {
        let w = words("git branch new-feature");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_branch_delete() {
        let w = words("git branch -D feature-x");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_tag() {
        let w = words("git tag v1.0.0");
        assert!(check_git_command(&w).is_some());
    }

    // --- Remote operations ---

    #[test]
    fn blocks_git_push() {
        let w = words("git push origin main");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_push_force() {
        let w = words("git push --force origin main");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_fetch() {
        let w = words("git fetch origin");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_pull() {
        let w = words("git pull --rebase origin main");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_clone() {
        let w = words("git clone https://github.com/example/repo.git");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_init() {
        let w = words("git init");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_remote() {
        let w = words("git remote add origin https://github.com/example/repo.git");
        assert!(check_git_command(&w).is_some());
    }

    // --- Informational ---

    #[test]
    fn blocks_git_status() {
        let w = words("git status");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_log() {
        let w = words("git log --oneline -10");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_diff() {
        let w = words("git diff --stat");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_show() {
        let w = words("git show HEAD");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_blame() {
        let w = words("git blame src/main.rs");
        assert!(check_git_command(&w).is_some());
    }

    // --- Worktree (selective) ---

    #[test]
    fn blocks_git_worktree_add() {
        let w = words("git worktree add ../other-dir");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn allows_git_worktree_list() {
        let w = words("git worktree list");
        assert!(check_git_command(&w).is_none());
    }

    #[test]
    fn allows_git_worktree_repair() {
        let w = words("git worktree repair");
        assert!(check_git_command(&w).is_none());
    }

    // --- Allowed through (no jj equivalent) ---

    #[test]
    fn allows_gh_commands() {
        let w = words("gh pr create --title test");
        assert!(check_git_command(&w).is_none());
    }

    #[test]
    fn allows_git_config() {
        let w = words("git config user.name");
        assert!(check_git_command(&w).is_none());
    }

    #[test]
    fn allows_git_bisect() {
        let w = words("git bisect start");
        assert!(check_git_command(&w).is_none());
    }

    // --- Flag handling ---

    #[test]
    fn handles_git_with_global_flags() {
        let w = words("git -C /tmp/repo status");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn handles_git_no_pager() {
        let w = words("git --no-pager log");
        assert!(check_git_command(&w).is_some());
    }

    // --- Suggestion quality ---

    #[test]
    fn status_suggestion_mentions_jj_status() {
        let w = words("git status");
        let blocked = check_git_command(&w).unwrap();
        assert!(
            blocked.suggestion.contains("jj status"),
            "suggestion should mention jj status"
        );
    }

    #[test]
    fn diff_suggestion_covers_common_forms() {
        let w = words("git diff");
        let blocked = check_git_command(&w).unwrap();
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
        let w = words("git push origin main");
        let blocked = check_git_command(&w).unwrap();
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
        let w = words("git branch");
        let blocked = check_git_command(&w).unwrap();
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
}
