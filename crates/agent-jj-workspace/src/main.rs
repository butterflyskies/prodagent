use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context};

fn main() -> anyhow::Result<()> {
    if let Err(msg) = agent_shell_parser::require_jj_version(0, 40) {
        eprintln!("{msg}");
        std::process::exit(1);
    }

    let input: agent_shell_parser::WorktreeCreateInput =
        agent_shell_parser::parse_input().context("failed to parse WorktreeCreate hook input")?;

    let cwd = PathBuf::from(&input.cwd);
    let workspace_name = format!("agent-{}", input.name);
    let worktree_path = cwd.join(".claude").join("worktrees").join(&input.name);

    std::fs::create_dir_all(&worktree_path)
        .with_context(|| format!("failed to create directory: {}", worktree_path.display()))?;

    let output = Command::new("jj")
        .args([
            "workspace",
            "add",
            &worktree_path.to_string_lossy(),
            "--name",
            &workspace_name,
        ])
        .current_dir(&cwd)
        .output()
        .context("failed to run jj workspace add")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Clean up the directory we created if jj failed
        let _ = std::fs::remove_dir_all(&worktree_path);
        bail!("jj workspace add failed: {stderr}");
    }

    // Print any jj output to stderr for visibility
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }

    // Print the absolute worktree path to stdout — Claude Code uses this
    let abs_path = worktree_path.canonicalize().unwrap_or(worktree_path);
    print!("{}", abs_path.display());

    Ok(())
}
