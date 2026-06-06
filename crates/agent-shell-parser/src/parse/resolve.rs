use std::sync::LazyLock;

use super::tokenize::{find_base_command, is_env_assignment};
use super::types::{
    CommandConfig, IndirectExecution, ParsedCommand, ResolvedCommand, UnanalyzableCommand, Word,
    WrapperSpec,
};

static DEFAULT_CONFIG: LazyLock<CommandConfig> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../config/commands.json"))
        .expect("embedded commands.json is invalid")
});

/// Return the embedded default command configuration.
pub fn default_command_config() -> &'static CommandConfig {
    &DEFAULT_CONFIG
}

/// Resolve a command through the indirection layer using the default config.
///
/// Recursively strips transparent wrappers and classifies unanalyzable
/// patterns (eval, shell spawn, source) based on the embedded command config.
pub fn resolve_command(words: &[Word]) -> ResolvedCommand {
    resolve_command_with(words, &DEFAULT_CONFIG)
}

/// Maximum recursion depth for wrapper resolution to prevent unbounded loops.
const MAX_RESOLVE_DEPTH: usize = 32;

/// Resolve a command through the indirection layer using a custom config.
///
/// Same as [`resolve_command`] but accepts caller-provided [`CommandConfig`],
/// allowing consumers to extend or replace the default command knowledge.
pub fn resolve_command_with(words: &[Word], config: &CommandConfig) -> ResolvedCommand {
    resolve_command_impl(words, config, 0)
}

/// Classify the surface-level command without recursing into wrappers.
///
/// Returns `Some(kind)` if the command is an indirect execution pattern,
/// `None` if it's a plain command. This is O(1) in wrapper depth — it only
/// looks at the outermost command.
pub(crate) fn classify_surface(
    base: &str,
    words: &[Word],
    config: &CommandConfig,
) -> Option<IndirectExecution> {
    if base.starts_with('$') {
        return Some(IndirectExecution::Eval);
    }
    if config.eval_commands.iter().any(|c| c == base) {
        return Some(IndirectExecution::Eval);
    }
    if config.shells.iter().any(|s| s == base) {
        let has_c_flag = words.iter().any(|w| w == "-c");
        return Some(if has_c_flag {
            IndirectExecution::ShellSpawn
        } else {
            IndirectExecution::SourceScript
        });
    }
    if config.source_commands.iter().any(|c| c == base) {
        return Some(IndirectExecution::SourceScript);
    }
    if config.wrappers.iter().any(|w| w.name == base) {
        return Some(IndirectExecution::CommandWrapper);
    }
    None
}

fn resolve_command_impl(words: &[Word], config: &CommandConfig, depth: usize) -> ResolvedCommand {
    if depth >= MAX_RESOLVE_DEPTH {
        return ResolvedCommand::Unanalyzable(UnanalyzableCommand {
            command: find_base_command(words),
            kind: IndirectExecution::CommandWrapper,
        });
    }

    let base = find_base_command(words);

    match classify_surface(&base, words, config) {
        Some(IndirectExecution::CommandWrapper) => {}
        Some(kind) => {
            return ResolvedCommand::Unanalyzable(UnanalyzableCommand {
                command: base,
                kind,
            });
        }
        None => {
            return ResolvedCommand::Resolved(ParsedCommand::from_words(words));
        }
    }

    // It's a wrapper — find where the inner command starts, check for
    // unanalyzable flags only in the wrapper's own flag region, then recurse.
    let spec = config.wrappers.iter().find(|s| s.name == base).unwrap();
    let inner_start = strip_with_spec_idx(spec, words);

    // Scope the unanalyzable-flag scan to the wrapper's own tokens —
    // everything before the inner command starts. Tokens after `--` or
    // after the inner command boundary belong to the inner command and
    // must not be matched against the wrapper's unanalyzable flags.
    let flag_region = match inner_start {
        Some(idx) => &words[..idx],
        None => words,
    };
    if !spec.unanalyzable_flags.is_empty()
        && flag_region.iter().any(|w| {
            spec.unanalyzable_flags.iter().any(|f| {
                w == f
                    || w.starts_with(&format!("{f}="))
                    || (f.starts_with('-')
                        && f.len() == 2
                        && w.starts_with('-')
                        && !w.starts_with("--")
                        && w.contains(f.chars().last().unwrap()))
            })
        })
    {
        return ResolvedCommand::Unanalyzable(UnanalyzableCommand {
            command: base,
            kind: IndirectExecution::Eval,
        });
    }

    match inner_start {
        None => ResolvedCommand::Resolved(ParsedCommand::from_words(&[])),
        Some(idx) => {
            debug_assert_ne!(idx, 0, "wrapper should always advance past itself");
            resolve_command_impl(&words[idx..], config, depth + 1)
        }
    }
}

/// Strip a wrapper command using its spec and return the remaining arguments.
///
/// Correctly handles value-consuming flags, env assignments, and `--`
/// terminators as specified by the [`WrapperSpec`].
pub fn strip_with_spec(spec: &WrapperSpec, words: &[Word]) -> Vec<Word> {
    match strip_with_spec_idx(spec, words) {
        None => vec![],
        Some(idx) => words[idx..].to_vec(),
    }
}

/// Strip a wrapper command using its spec and return the index where the inner
/// command starts, or `None` if no inner command was found.
///
/// This avoids allocating a new `Vec<Word>` — callers can slice the original
/// word list directly.
///
/// Correctly handles value-consuming flags (including combined short forms like
/// `-uroot`), env assignments, and `--` terminators as specified by the
/// [`WrapperSpec`].
fn strip_with_spec_idx(spec: &WrapperSpec, words: &[Word]) -> Option<usize> {
    let wrapper_idx = words.iter().position(|w| {
        let base = match w.rsplit_once('/') {
            Some((_, name)) => name,
            None => w.as_str(),
        };
        base == spec.name
    });
    let start = wrapper_idx.map(|i| i + 1).unwrap_or(0);

    let mut i = start;
    let mut positionals_skipped = 0;
    while i < words.len() {
        let w = &words[i];

        if spec.has_terminator && w == "--" {
            i += 1;
            break;
        }

        if spec.skip_env_assignments && is_env_assignment(w) {
            i += 1;
            continue;
        }

        if w.starts_with('-') && w.len() > 1 {
            // Exact match for value-consuming flags (e.g., `-u` consuming next token)
            if spec.short_value_flags.iter().any(|f| w == f)
                || spec.long_value_flags.iter().any(|f| w == f)
            {
                i += 2;
                if i > words.len() {
                    return None;
                }
                continue;
            }
            // Long flags with `=` form (e.g., `--user=root`)
            if let Some((flag_part, _)) = w.split_once('=') {
                if spec.long_value_flags.iter().any(|f| f == flag_part)
                    || spec.short_value_flags.iter().any(|f| f == flag_part)
                {
                    i += 1;
                    continue;
                }
            }
            // Combined short flags (e.g., `-uroot` where `-u` is a value flag)
            // The value is embedded in the token — consume it and continue.
            if spec
                .short_value_flags
                .iter()
                .any(|f| w.starts_with(f.as_str()) && w.len() > f.len())
            {
                i += 1;
                continue;
            }
            // Boolean flag — skip it
            i += 1;
            continue;
        }

        if positionals_skipped < spec.skip_positionals {
            positionals_skipped += 1;
            i += 1;
            continue;
        }

        break;
    }

    if i >= words.len() {
        return None;
    }
    Some(i)
}

#[cfg(test)]
#[path = "resolve_tests.rs"]
mod resolve_tests;
