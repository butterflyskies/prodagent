use std::path::PathBuf;

use agent_shell_parser::parse::{find_base_command, Operator, ParsedPipeline, Word};

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
pub fn extract_cd_target(words: &[Word]) -> Option<&Word> {
    words.iter().find(|w| !w.starts_with('-') && *w != "cd")
}

/// Extract the path from `git -C <path>` if present.
pub fn extract_git_c_path(words: &[Word]) -> Option<&Word> {
    let git_idx = words.iter().position(|w| w == "git")?;
    let mut i = git_idx + 1;
    while i < words.len() {
        if words[i] == "-C" {
            return words.get(i + 1);
        }
        i += 1;
    }
    None
}

/// Determine the effective working directory for each git command in a pipeline.
///
/// Tracks `cd <path>` segments that propagate through `&&` or `;` operators.
/// Pipe, pipe-err, or, and background operators reset to session cwd since
/// cd in those contexts runs in a subshell or on the failure path.
///
/// Also handles `git -C <path>` by checking any git segment for a -C flag.
///
/// Returns a list of effective CWDs — one for each git segment encountered.
/// If no git segments exist, returns a single-element vec with the final
/// tracked CWD (preserving the previous behavior for non-git pipelines).
pub fn effective_cwd(pipeline: &ParsedPipeline, session_cwd: &str) -> Vec<String> {
    let mut cwd = session_cwd.to_string();
    let mut git_cwds: Vec<String> = Vec::new();

    for (i, seg) in pipeline.segments.iter().enumerate() {
        let words = &seg.words;
        if words.is_empty() {
            // Only propagate cwd through && and ;
            if i < pipeline.operators.len() {
                match pipeline.operators[i] {
                    Operator::And | Operator::Semi => {}
                    _ => cwd = session_cwd.to_string(),
                }
            }
            continue;
        }

        let base = find_base_command(&seg.words);

        if base == "cd" {
            if let Some(target) = extract_cd_target(words) {
                cwd = resolve_path(target, &cwd);
            }
        }

        if base == "git" {
            let resolved = if let Some(path) = extract_git_c_path(words) {
                if path.starts_with('/') {
                    path.to_string()
                } else {
                    PathBuf::from(&cwd)
                        .join(path.as_str())
                        .to_string_lossy()
                        .to_string()
                }
            } else {
                cwd.clone()
            };
            git_cwds.push(resolved);
        }

        // Only propagate cwd through && and ;
        if i < pipeline.operators.len() {
            match pipeline.operators[i] {
                Operator::And | Operator::Semi => {}
                _ => cwd = session_cwd.to_string(),
            }
        }
    }

    if git_cwds.is_empty() {
        vec![cwd]
    } else {
        git_cwds.dedup();
        git_cwds
    }
}

#[cfg(test)]
#[path = "path_tests.rs"]
mod path_tests;
