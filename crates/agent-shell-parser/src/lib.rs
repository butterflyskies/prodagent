use std::path::Path;
use std::process::Command;

pub mod hook;
pub mod parse;
pub mod path;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read stdin: {0}")]
    Stdin(#[from] std::io::Error),
    #[error("failed to parse JSON input: {0}")]
    Json(#[from] serde_json::Error),
    #[error("jj command failed: {0}")]
    Jj(String),
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
