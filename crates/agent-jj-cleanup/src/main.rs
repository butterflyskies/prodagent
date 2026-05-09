use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let input: agent_shell_parser::WorktreeRemoveInput =
        agent_shell_parser::parse_input().context("failed to parse WorktreeRemove hook input")?;

    let worktree_path = PathBuf::from(&input.worktree_path);
    let workspace_name = derive_workspace_name(&worktree_path);

    // Find the parent repo by looking for .jj in ancestors of the worktree's parent
    let parent_repo = find_parent_repo(&worktree_path);

    if let Some(repo_dir) = parent_repo {
        // Forget the workspace — tolerate failure (may already be forgotten)
        let output = Command::new("jj")
            .args(["workspace", "forget", &workspace_name])
            .current_dir(&repo_dir)
            .output();

        match output {
            Ok(o) if !o.status.success() => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                eprintln!("note: jj workspace forget {workspace_name}: {stderr}");
            }
            Err(e) => {
                eprintln!("note: could not run jj workspace forget: {e}");
            }
            _ => {}
        }
    }

    // Remove the directory
    if worktree_path.exists() {
        std::fs::remove_dir_all(&worktree_path)
            .with_context(|| format!("failed to remove {}", worktree_path.display()))?;
    }

    Ok(())
}

fn derive_workspace_name(worktree_path: &Path) -> String {
    let dir_name = worktree_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    format!("agent-{dir_name}")
}

fn find_parent_repo(worktree_path: &Path) -> Option<PathBuf> {
    // Worktrees live under <repo>/.claude/worktrees/<name>
    // Walk up to find .jj directory
    let mut current = worktree_path.parent()?;
    loop {
        if current.join(".jj").is_dir() {
            return Some(current.to_path_buf());
        }
        current = current.parent()?;
    }
}
