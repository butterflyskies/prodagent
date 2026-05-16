use std::path::PathBuf;

use crate::parse::{base_command, tokenize, Operator, ParsedPipeline};

/// Resolve a cd target path against a base (current working) directory.
///
/// Absolute paths are returned as-is. `~` and `~/...` expand via `$HOME`.
/// Relative paths are joined onto `base`.
pub fn resolve_path(target: &str, base: &str) -> String {
    if target.starts_with('/') {
        target.to_string()
    } else if target == "~" || target.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            let rest = target.strip_prefix("~/").unwrap_or("");
            if rest.is_empty() {
                home.to_string_lossy().to_string()
            } else {
                PathBuf::from(home).join(rest).to_string_lossy().to_string()
            }
        } else {
            target.to_string()
        }
    } else {
        PathBuf::from(base)
            .join(target)
            .to_string_lossy()
            .to_string()
    }
}

/// Return the first non-flag, non-`cd` argument from a `cd` command's word list.
pub fn extract_cd_target(words: &[String]) -> Option<&str> {
    words
        .iter()
        .find(|w| !w.starts_with('-') && *w != "cd")
        .map(String::as_str)
}

/// Extract the path from `git -C <path>` if present.
pub fn extract_git_c_path(words: &[String]) -> Option<String> {
    let git_idx = words.iter().position(|w| w == "git")?;
    let mut i = git_idx + 1;
    while i < words.len() {
        if words[i] == "-C" {
            return words.get(i + 1).cloned();
        }
        i += 1;
    }
    None
}

/// Determine the effective working directory for commands in a pipeline.
///
/// Tracks `cd <path>` segments that propagate through `&&` or `;` operators.
/// Pipe, pipe-err, or, and background operators reset to session cwd since
/// cd in those contexts runs in a subshell or on the failure path.
///
/// Also handles `git -C <path>` by checking any git segment for a -C flag.
pub fn effective_cwd(pipeline: &ParsedPipeline, session_cwd: &str) -> String {
    let mut cwd = session_cwd.to_string();

    for (i, seg) in pipeline.segments.iter().enumerate() {
        let words = tokenize(&seg.command);
        if words.is_empty() {
            continue;
        }

        let base = base_command(&seg.command);

        if base == "cd" {
            if let Some(target) = extract_cd_target(&words) {
                cwd = resolve_path(target, &cwd);
            }
        }

        if base == "git" {
            let git_cwd = extract_git_c_path(&words);
            if let Some(path) = git_cwd {
                if path.starts_with('/') {
                    return path;
                }
                return PathBuf::from(&cwd)
                    .join(&path)
                    .to_string_lossy()
                    .to_string();
            }
            return cwd;
        }

        // Only propagate cwd through && and ;
        if i < pipeline.operators.len() {
            match pipeline.operators[i] {
                Operator::And | Operator::Semi => {}
                _ => cwd = session_cwd.to_string(),
            }
        }
    }

    cwd
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- resolve_path ---

    #[test]
    fn resolve_absolute() {
        assert_eq!(resolve_path("/abs/path", "/base"), "/abs/path");
    }

    #[test]
    fn resolve_relative() {
        assert_eq!(resolve_path("subdir", "/base"), "/base/subdir");
    }

    #[test]
    fn resolve_tilde_alone() {
        let home = std::env::var("HOME").unwrap_or_default();
        assert_eq!(resolve_path("~", "/base"), home);
    }

    #[test]
    fn resolve_tilde_subdir() {
        let home = std::env::var("HOME").unwrap_or_default();
        let result = resolve_path("~/docs", "/base");
        assert_eq!(result, format!("{home}/docs"));
    }

    // --- extract_cd_target ---

    #[test]
    fn cd_target_normal() {
        let words: Vec<String> = ["cd", "/foo"].iter().map(|s| s.to_string()).collect();
        assert_eq!(extract_cd_target(&words), Some("/foo"));
    }

    #[test]
    fn cd_target_with_flags() {
        let words: Vec<String> = ["cd", "-L", "/foo"].iter().map(|s| s.to_string()).collect();
        assert_eq!(extract_cd_target(&words), Some("/foo"));
    }

    #[test]
    fn cd_target_no_args() {
        let words: Vec<String> = ["cd"].iter().map(|s| s.to_string()).collect();
        assert_eq!(extract_cd_target(&words), None);
    }

    // --- extract_git_c_path ---

    #[test]
    fn git_c_path_present() {
        let words: Vec<String> = ["git", "-C", "/repo", "status"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(extract_git_c_path(&words), Some("/repo".to_string()));
    }

    #[test]
    fn git_c_path_absent() {
        let words: Vec<String> = ["git", "status"].iter().map(|s| s.to_string()).collect();
        assert_eq!(extract_git_c_path(&words), None);
    }

    #[test]
    fn git_c_path_multiple_flags() {
        let words: Vec<String> = ["git", "--no-pager", "-C", "/repo", "log"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(extract_git_c_path(&words), Some("/repo".to_string()));
    }
}
