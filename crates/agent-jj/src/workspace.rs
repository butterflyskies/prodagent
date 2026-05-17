use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context};

fn jj_version() -> Option<(u32, u32, u32)> {
    let output = Command::new("jj").arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let version_str = text.strip_prefix("jj ")?;
    let mut parts = version_str.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

fn require_jj_version(min_major: u32, min_minor: u32) -> Result<(), String> {
    match jj_version() {
        None => Err("jj-cli not found. Install with: cargo install --locked jj-cli".into()),
        Some((major, minor, _))
            if major < min_major || (major == min_major && minor < min_minor) =>
        {
            Err(format!(
                "jj-cli {major}.{minor} found, but >= {min_major}.{min_minor} required. \
                 Upgrade with: cargo install --locked jj-cli"
            ))
        }
        Some(_) => Ok(()),
    }
}

pub fn run() -> anyhow::Result<()> {
    if let Err(msg) = require_jj_version(0, 40) {
        eprintln!("{msg}");
        std::process::exit(1);
    }

    let input: agent_shell_parser::hook::WorktreeCreateInput =
        agent_shell_parser::hook::parse_input()
            .context("failed to parse WorktreeCreate hook input")?;

    let cwd = PathBuf::from(&input.cwd);
    let name = Path::new(&input.name)
        .file_name()
        .context("invalid workspace name")?
        .to_string_lossy();
    let workspace_name = format!("agent-{name}");
    let worktree_path = cwd.join(".claude").join("worktrees").join(&*name);

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
        let _ = std::fs::remove_dir_all(&worktree_path);
        bail!("jj workspace add failed: {stderr}");
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }

    let abs_path = worktree_path.canonicalize().unwrap_or(worktree_path);
    print!("{}", abs_path.display());

    Ok(())
}
