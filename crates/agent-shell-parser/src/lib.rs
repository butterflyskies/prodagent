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

/// Returns the index of the first token that is the actual command being invoked,
/// skipping leading env-var assignments (`FOO=bar`).
///
/// An env-var assignment is a token matching `[A-Za-z_][A-Za-z0-9_]*=.*`.
pub fn find_command_position(words: &[String]) -> Option<usize> {
    for (i, word) in words.iter().enumerate() {
        if is_env_assignment(word) {
            continue;
        }
        return Some(i);
    }
    None
}

fn is_env_assignment(word: &str) -> bool {
    let Some(eq) = word.find('=') else {
        return false;
    };
    if eq == 0 {
        return false;
    }
    let name = &word[..eq];
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
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
    fn command_position_simple() {
        let w: Vec<String> = vec!["git".into(), "push".into()];
        assert_eq!(find_command_position(&w), Some(0));
    }

    #[test]
    fn command_position_with_env_vars() {
        let w: Vec<String> = vec!["FOO=bar".into(), "git".into(), "push".into()];
        assert_eq!(find_command_position(&w), Some(1));
    }

    #[test]
    fn command_position_multiple_env_vars() {
        let w: Vec<String> = vec!["A=1".into(), "B=2".into(), "git".into(), "push".into()];
        assert_eq!(find_command_position(&w), Some(2));
    }

    #[test]
    fn command_position_jj() {
        let w: Vec<String> = vec!["jj".into(), "git".into(), "push".into()];
        assert_eq!(find_command_position(&w), Some(0));
    }

    #[test]
    fn command_position_empty() {
        let w: Vec<String> = vec![];
        assert_eq!(find_command_position(&w), None);
    }

    #[test]
    fn command_position_only_assignments() {
        let w: Vec<String> = vec!["FOO=bar".into()];
        assert_eq!(find_command_position(&w), None);
    }

    #[test]
    fn env_assignment_valid() {
        assert!(is_env_assignment("FOO=bar"));
        assert!(is_env_assignment("_X=1"));
        assert!(is_env_assignment("GIT_CONFIG_GLOBAL=~/.gitconfig.ai"));
    }

    #[test]
    fn env_assignment_invalid() {
        assert!(!is_env_assignment("git"));
        assert!(!is_env_assignment("--flag=value"));
        assert!(!is_env_assignment("=bar"));
        assert!(!is_env_assignment("123=bar"));
    }

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
