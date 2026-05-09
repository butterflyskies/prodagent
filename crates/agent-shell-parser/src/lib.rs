use serde::Deserialize;
use std::path::Path;
use std::process::Command;

pub mod guard;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read stdin: {0}")]
    Stdin(#[from] std::io::Error),
    #[error("failed to parse JSON input: {0}")]
    Json(#[from] serde_json::Error),
    #[error("jj command failed: {0}")]
    Jj(String),
}

#[derive(Debug, Deserialize)]
pub struct WorktreeCreateInput {
    pub name: String,
    pub cwd: String,
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WorktreeRemoveInput {
    pub worktree_path: String,
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PreToolUseInput {
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: serde_json::Value,
    #[serde(default)]
    pub cwd: Option<String>,
}

pub fn parse_input<T: serde::de::DeserializeOwned>() -> Result<T, Error> {
    let input = std::io::read_to_string(std::io::stdin())?;
    Ok(serde_json::from_str(&input)?)
}

pub fn is_jj_colocated(cwd: &Path) -> bool {
    Command::new("jj")
        .arg("root")
        .current_dir(cwd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn jj_version() -> Option<(u32, u32, u32)> {
    let output = Command::new("jj").arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let version_str = text.strip_prefix("jj ")?;
    let mut parts = version_str.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

pub fn require_jj_version(min_major: u32, min_minor: u32) -> Result<(), String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_worktree_create_input() {
        let json = r#"{"name": "test-feature", "cwd": "/tmp/repo", "session_id": "abc123"}"#;
        let input: WorktreeCreateInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.name, "test-feature");
        assert_eq!(input.cwd, "/tmp/repo");
        assert_eq!(input.session_id.as_deref(), Some("abc123"));
    }

    #[test]
    fn parse_worktree_remove_input() {
        let json = r#"{"worktree_path": "/tmp/repo/.claude/worktrees/test-feature"}"#;
        let input: WorktreeRemoveInput = serde_json::from_str(json).unwrap();
        assert_eq!(
            input.worktree_path,
            "/tmp/repo/.claude/worktrees/test-feature"
        );
        assert!(input.session_id.is_none());
    }

    #[test]
    fn parse_pre_tool_use_input() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "git commit -m test"}, "cwd": "/tmp/repo"}"#;
        let input: PreToolUseInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.cwd.as_deref(), Some("/tmp/repo"));
    }
}
