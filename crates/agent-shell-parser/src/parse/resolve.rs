use std::sync::LazyLock;

use super::tokenize::{find_base_command, is_env_assignment, parse_command};
use super::types::{
    CommandConfig, IndirectExecution, ResolvedCommand, UnanalyzableCommand, WrapperSpec,
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
pub fn resolve_command(words: &[String]) -> ResolvedCommand {
    resolve_command_with(words, &DEFAULT_CONFIG)
}

/// Maximum recursion depth for wrapper resolution to prevent unbounded loops.
const MAX_RESOLVE_DEPTH: usize = 32;

/// Resolve a command through the indirection layer using a custom config.
///
/// Same as [`resolve_command`] but accepts caller-provided [`CommandConfig`],
/// allowing consumers to extend or replace the default command knowledge.
pub fn resolve_command_with(words: &[String], config: &CommandConfig) -> ResolvedCommand {
    resolve_command_impl(words, config, 0)
}

/// Classify the surface-level command without recursing into wrappers.
///
/// Returns `Some(kind)` if the command is an indirect execution pattern,
/// `None` if it's a plain command. This is O(1) in wrapper depth — it only
/// looks at the outermost command.
pub(crate) fn classify_surface(
    base: &str,
    words: &[String],
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

fn resolve_command_impl(words: &[String], config: &CommandConfig, depth: usize) -> ResolvedCommand {
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
        None => return ResolvedCommand::Resolved(parse_command(&words.join(" "))),
    }

    // It's a wrapper — check for unanalyzable flags, then strip and recurse.
    let spec = config.wrappers.iter().find(|s| s.name == base).unwrap();
    if !spec.unanalyzable_flags.is_empty()
        && words.iter().any(|w| {
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
    let inner_start = strip_with_spec_idx(spec, words);
    match inner_start {
        None => return ResolvedCommand::Resolved(parse_command("")),
        Some(idx) => {
            debug_assert_ne!(idx, 0, "wrapper should always advance past itself");
            if idx > 0 {
                return resolve_command_impl(&words[idx..], config, depth + 1);
            }
        }
    }

    ResolvedCommand::Resolved(parse_command(&words.join(" ")))
}

/// Strip a wrapper command using its spec and return the remaining arguments.
///
/// Correctly handles value-consuming flags, env assignments, and `--`
/// terminators as specified by the [`WrapperSpec`].
pub fn strip_with_spec(spec: &WrapperSpec, words: &[String]) -> Vec<String> {
    match strip_with_spec_idx(spec, words) {
        None => vec![],
        Some(idx) => words[idx..].to_vec(),
    }
}

/// Strip a wrapper command using its spec and return the index where the inner
/// command starts, or `None` if no inner command was found.
///
/// This avoids allocating a new `Vec<String>` — callers can slice the original
/// word list directly.
///
/// Correctly handles value-consuming flags (including combined short forms like
/// `-uroot`), env assignments, and `--` terminators as specified by the
/// [`WrapperSpec`].
fn strip_with_spec_idx(spec: &WrapperSpec, words: &[String]) -> Option<usize> {
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
mod tests {
    use super::*;

    fn words(s: &str) -> Vec<String> {
        shlex::split(s).unwrap_or_else(|| s.split_whitespace().map(String::from).collect())
    }

    fn spec(name: &str) -> WrapperSpec {
        WrapperSpec {
            name: name.to_string(),
            short_value_flags: vec!["-v".to_string()],
            long_value_flags: vec!["--val".to_string()],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: true,
            skip_positionals: 0,
        }
    }

    #[test]
    fn strip_simple_wrapper() {
        let s = spec("wrap");
        let result = strip_with_spec(&s, &words("wrap inner cmd"));
        assert_eq!(result, words("inner cmd"));
    }

    #[test]
    fn strip_value_consuming_short_flag() {
        let s = spec("wrap");
        let result = strip_with_spec(&s, &words("wrap -v thing inner cmd"));
        assert_eq!(result, words("inner cmd"));
    }

    #[test]
    fn strip_value_consuming_long_flag() {
        let s = spec("wrap");
        let result = strip_with_spec(&s, &words("wrap --val thing inner cmd"));
        assert_eq!(result, words("inner cmd"));
    }

    #[test]
    fn strip_long_flag_equals_form() {
        let s = spec("wrap");
        let result = strip_with_spec(&s, &words("wrap --val=thing inner cmd"));
        assert_eq!(result, words("inner cmd"));
    }

    #[test]
    fn strip_terminator_stops_flag_processing() {
        let s = spec("wrap");
        let result = strip_with_spec(&s, &words("wrap -x -- -v notflag cmd"));
        assert_eq!(result, words("-v notflag cmd"));
    }

    #[test]
    fn strip_boolean_flag_skipped() {
        let s = spec("wrap");
        let result = strip_with_spec(&s, &words("wrap -x --verbose inner"));
        assert_eq!(result, words("inner"));
    }

    #[test]
    fn strip_env_assignments_when_configured() {
        let s = WrapperSpec {
            name: "wrap".to_string(),
            short_value_flags: vec![],
            long_value_flags: vec![],
            unanalyzable_flags: vec![],
            skip_env_assignments: true,
            has_terminator: false,
            skip_positionals: 0,
        };
        let result = strip_with_spec(&s, &words("wrap FOO=bar BAZ=qux inner cmd"));
        assert_eq!(result, words("inner cmd"));
    }

    #[test]
    fn strip_truncated_value_flag_returns_empty() {
        let s = spec("wrap");
        let result = strip_with_spec(&s, &words("wrap -v"));
        assert!(result.is_empty());
    }

    #[test]
    fn strip_no_inner_command_returns_empty() {
        let s = spec("wrap");
        let result = strip_with_spec(&s, &words("wrap -x --verbose"));
        assert!(result.is_empty());
    }

    #[test]
    fn strip_path_prefixed_wrapper() {
        let s = spec("wrap");
        let result = strip_with_spec(&s, &words("/usr/bin/wrap inner cmd"));
        assert_eq!(result, words("inner cmd"));
    }

    #[test]
    fn resolve_with_custom_config() {
        let config = CommandConfig {
            wrappers: vec![WrapperSpec {
                name: "mywrap".to_string(),
                short_value_flags: vec!["-x".to_string()],
                long_value_flags: vec![],
                unanalyzable_flags: vec![],
                skip_env_assignments: false,
                has_terminator: false,
                skip_positionals: 0,
            }],
            shells: vec!["mysh".to_string()],
            eval_commands: vec!["myeval".to_string()],
            source_commands: vec!["mysource".to_string()],
        };

        match resolve_command_with(&words("mywrap -x val inner"), &config) {
            ResolvedCommand::Resolved(p) => assert_eq!(p.command, "inner"),
            _ => panic!("expected Resolved"),
        }

        assert!(matches!(
            resolve_command_with(&words("mysh -c 'code'"), &config),
            ResolvedCommand::Unanalyzable(_)
        ));

        assert!(matches!(
            resolve_command_with(&words("myeval 'code'"), &config),
            ResolvedCommand::Unanalyzable(_)
        ));

        assert!(matches!(
            resolve_command_with(&words("mysource file.sh"), &config),
            ResolvedCommand::Unanalyzable(_)
        ));
    }
}
