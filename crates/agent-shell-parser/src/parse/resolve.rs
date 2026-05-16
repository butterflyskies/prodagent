use super::tokenize::{command_characteristics, is_env_assignment, parse_command};
use super::types::{IndirectExecution, ResolvedCommand, UnanalyzableCommand};

/// Resolve a command through the indirection layer.
///
/// Recursively strips transparent wrappers (env, sudo, command, etc.)
/// and returns either a structurally parsed command or an unanalyzable
/// classification.
///
/// For dynamic commands (`$cmd`), returns `Unanalyzable` with
/// [`IndirectExecution::Eval`] as the kind (closest semantic match:
/// the effective command is determined at runtime).
pub fn resolve_command(words: &[String]) -> ResolvedCommand {
    let chars = command_characteristics(&words.join(" "));

    if chars.has_dynamic_command {
        return ResolvedCommand::Unanalyzable(UnanalyzableCommand {
            command: chars.base_command,
            kind: IndirectExecution::Eval,
        });
    }

    match chars.indirect_execution {
        Some(
            kind @ (IndirectExecution::Eval
            | IndirectExecution::ShellSpawn
            | IndirectExecution::SourceScript),
        ) => ResolvedCommand::Unanalyzable(UnanalyzableCommand {
            command: chars.base_command,
            kind,
        }),
        Some(IndirectExecution::CommandWrapper) => {
            let inner = strip_wrapper(&chars.base_command, words);
            if inner.len() < words.len() {
                resolve_command(&inner)
            } else {
                ResolvedCommand::Resolved(parse_command(&inner.join(" ")))
            }
        }
        None => ResolvedCommand::Resolved(parse_command(&words.join(" "))),
    }
}

/// Strip a transparent wrapper command and return the remaining arguments.
///
/// For most wrappers (env, command, builtin), drops the wrapper word and
/// any flags it consumes. For sudo, drops sudo and its flags until the
/// first non-flag argument.
fn strip_wrapper(wrapper: &str, words: &[String]) -> Vec<String> {
    let wrapper_idx = words.iter().position(|w| {
        let base = match w.rsplit_once('/') {
            Some((_, name)) => name,
            None => w.as_str(),
        };
        base == wrapper
    });
    let start = wrapper_idx.map(|i| i + 1).unwrap_or(0);

    match wrapper {
        "sudo" => {
            let mut i = start;
            while i < words.len() {
                let w = &words[i];
                if w.starts_with('-') {
                    if matches!(w.as_str(), "-u" | "-g" | "-C" | "-D" | "-R" | "-T") {
                        i += 2;
                    } else {
                        i += 1;
                    }
                } else {
                    break;
                }
            }
            words[i..].to_vec()
        }
        "env" => {
            let mut i = start;
            while i < words.len() {
                let w = &words[i];
                if w.starts_with('-') || is_env_assignment(w) {
                    i += 1;
                } else {
                    break;
                }
            }
            words[i..].to_vec()
        }
        "nice" | "nohup" => {
            let mut i = start;
            while i < words.len() && words[i].starts_with('-') {
                i += 1;
            }
            words[i..].to_vec()
        }
        _ => words[start..].to_vec(),
    }
}
