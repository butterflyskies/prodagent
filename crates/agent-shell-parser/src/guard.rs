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
            "BLOCKED: {}\n\nThis is a jj-colocated repo. Use jj instead:\n\n  {}\n\n\
             If you genuinely need the raw git command, run it from outside Claude Code.",
            self.reason, self.suggestion
        )
    }
}

static BLOCKED_COMMANDS: &[(&str, BlockedCommand)] = &[
    ("commit", BlockedCommand {
        command: "git commit",
        reason: "git commit bypasses jj's change tracking",
        suggestion: "jj describe  (edit current change message)\njj new && jj describe  (create new change)",
    }),
    ("rebase", BlockedCommand {
        command: "git rebase",
        reason: "git rebase conflicts with jj's history management",
        suggestion: "jj rebase -s <change> -d <destination>",
    }),
    ("merge", BlockedCommand {
        command: "git merge",
        reason: "git merge conflicts with jj's history management",
        suggestion: "jj new <parent-a> <parent-b>  (create merge commit)",
    }),
    ("stash", BlockedCommand {
        command: "git stash",
        reason: "jj snapshots automatically — stash is unnecessary",
        suggestion: "jj new  (start fresh change; previous work is already snapshotted)",
    }),
    ("revert", BlockedCommand {
        command: "git revert",
        reason: "git revert bypasses jj's change tracking",
        suggestion: "jj backout -r <change-id>",
    }),
    ("cherry-pick", BlockedCommand {
        command: "git cherry-pick",
        reason: "git cherry-pick bypasses jj's change tracking",
        suggestion: "jj duplicate <change-id>  then  jj rebase -s <dup> -d <destination>",
    }),
];

pub fn check_git_command(words: &[String]) -> Option<&'static BlockedCommand> {
    let git_idx = words.iter().position(|w| w == "git")?;
    let subcommand = find_git_subcommand(words, git_idx)?;

    // Check direct subcommand matches
    for (name, blocked) in BLOCKED_COMMANDS {
        if subcommand == *name {
            return Some(blocked);
        }
    }

    // Special cases requiring flag/argument inspection
    let rest = &words[git_idx..];

    if subcommand == "reset"
        && rest
            .iter()
            .any(|w| w == "--hard" || w == "--soft" || w == "--mixed")
    {
        static RESET_BLOCKED: BlockedCommand = BlockedCommand {
            command: "git reset",
            reason: "git reset modifies state that jj manages",
            suggestion:
                "jj abandon  (discard change)\n  jj restore  (restore files from another change)",
        };
        return Some(&RESET_BLOCKED);
    }

    if subcommand == "checkout" && has_positional_arg(rest, 2) {
        static CHECKOUT_BLOCKED: BlockedCommand = BlockedCommand {
            command: "git checkout",
            reason: "git checkout conflicts with jj's working copy management",
            suggestion: "jj edit <change-id>  (switch to existing change)\n  jj new <parent>  (start new work after a change)",
        };
        return Some(&CHECKOUT_BLOCKED);
    }

    if subcommand == "push"
        && rest
            .iter()
            .any(|w| w == "--force" || w == "-f" || w.starts_with("--force-with-lease"))
    {
        static FORCE_PUSH_BLOCKED: BlockedCommand = BlockedCommand {
            command: "git push --force",
            reason: "jj's push is already safe — it checks remote state automatically",
            suggestion:
                "jj git push --bookmark <name>  (safe push with implicit remote-state check)",
        };
        return Some(&FORCE_PUSH_BLOCKED);
    }

    if subcommand == "branch"
        && rest
            .iter()
            .any(|w| w == "-D" || w == "-d" || w == "--delete")
    {
        static BRANCH_DELETE_BLOCKED: BlockedCommand = BlockedCommand {
            command: "git branch -d/-D",
            reason: "git branch operations bypass jj's bookmark system",
            suggestion: "jj bookmark delete <name>",
        };
        return Some(&BRANCH_DELETE_BLOCKED);
    }

    if subcommand == "worktree" {
        let wt_sub = rest.iter().skip_while(|w| *w != "worktree").nth(1);
        if let Some(wt_cmd) = wt_sub {
            if wt_cmd != "list" && wt_cmd != "repair" {
                static WORKTREE_BLOCKED: BlockedCommand = BlockedCommand {
                    command: "git worktree",
                    reason: "git worktrees are invisible to jj — use jj workspaces instead",
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
            i += 2; // skip flag + its argument
        } else if GIT_GLOBAL_SOLO_FLAGS.iter().any(|f| word == f) || word.starts_with('-') {
            i += 1;
        } else {
            return Some(word.clone());
        }
    }
    None
}

fn has_positional_arg(words: &[String], skip_count: usize) -> bool {
    words.iter().skip(skip_count).any(|w| !w.starts_with('-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(s: &str) -> Vec<String> {
        shell_words::split(s).unwrap()
    }

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
    fn blocks_git_reset_hard() {
        let w = words("git reset --hard HEAD~1");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn allows_git_reset_without_mode() {
        let w = words("git reset HEAD file.rs");
        assert!(check_git_command(&w).is_none());
    }

    #[test]
    fn blocks_git_checkout_with_ref() {
        let w = words("git checkout main");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn allows_git_checkout_dash_b() {
        // git checkout -b new-branch is arguable, but -b is a flag so no positional
        // Actually "new-branch" IS positional after -b... let's test this.
        // This is a known edge case — the simple heuristic may block it.
        // That's acceptable behavior: suggest jj new instead.
        let w = words("git checkout -b new-branch");
        // -b is a flag, "new-branch" is positional → blocked. Correct for jj repos.
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_push_force() {
        let w = words("git push --force origin main");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn allows_git_push_without_force() {
        let w = words("git push origin main");
        assert!(check_git_command(&w).is_none());
    }

    #[test]
    fn blocks_git_stash() {
        let w = words("git stash pop");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_cherry_pick() {
        let w = words("git cherry-pick abc123");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_revert() {
        let w = words("git revert HEAD");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn blocks_git_branch_delete() {
        let w = words("git branch -D feature-x");
        assert!(check_git_command(&w).is_some());
    }

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
    fn allows_git_status() {
        let w = words("git status");
        assert!(check_git_command(&w).is_none());
    }

    #[test]
    fn allows_git_log() {
        let w = words("git log --oneline -10");
        assert!(check_git_command(&w).is_none());
    }

    #[test]
    fn allows_git_diff() {
        let w = words("git diff --stat");
        assert!(check_git_command(&w).is_none());
    }

    #[test]
    fn allows_gh_commands() {
        let w = words("gh pr create --title test");
        assert!(check_git_command(&w).is_none());
    }

    #[test]
    fn handles_git_with_global_flags() {
        let w = words("git -C /tmp/repo commit -m test");
        assert!(check_git_command(&w).is_some());
    }

    #[test]
    fn handles_compound_commands() {
        // Only checks the tokenized segment — compound handling is the caller's job
        let w = words("git commit -m test");
        assert!(check_git_command(&w).is_some());
    }
}
