use super::resolve::{classify_surface, default_command_config};
use super::types::{CommandCharacteristics, ParsedCommand, Word};

/// Extract the base command name from a word list, skipping env assignments
/// and stripping path prefixes.
pub fn find_base_command(words: &[Word]) -> String {
    let cmd = words
        .iter()
        .find(|t| !is_env_assignment(t))
        .map(|w| w.as_str())
        .unwrap_or("");

    match cmd.rsplit_once('/') {
        Some((_, name)) if !name.is_empty() => name.to_string(),
        _ => cmd.to_string(),
    }
}

/// Analyze a command segment for security-relevant properties.
///
/// Reports the surface-level command classification: what the outermost
/// command is and whether it's an indirect execution pattern. This is
/// O(1) in wrapper depth — it does not recurse.
///
/// For the fully-resolved inner command (after recursively stripping
/// wrappers), use [`resolve_command`](super::resolve::resolve_command).
pub fn command_characteristics(command: &str) -> CommandCharacteristics {
    let tokens = shlex_or_whitespace_words(command);
    let base = find_base_command(&tokens);
    // Use Word::is_expansion() which checks structural metadata when
    // available, falling back to starts_with('$') for unclassified words.
    let cmd_word = tokens.iter().find(|t| !is_env_assignment(t));
    let has_dynamic_command = cmd_word.is_some_and(|w| w.is_expansion());
    let indirect_execution = classify_surface(&base, &tokens, default_command_config());

    CommandCharacteristics {
        base_command: base,
        indirect_execution,
        has_dynamic_command,
    }
}

/// Extract the first real command word, skipping leading `KEY=VALUE` assignments.
///
/// Uses shlex for correct handling of quoted values like `FOO="bar baz"`.
/// Returns the basename of the command (e.g. `/usr/bin/ls` → `ls`).
pub fn base_command(command: &str) -> String {
    command_characteristics(command).base_command
}

/// Extract leading `KEY=VALUE` pairs from a command string.
///
/// Uses shlex for correct handling of quoted values like `FOO="bar baz"`.
/// Stops at the first token that is not a valid assignment.
pub fn env_vars(command: &str) -> Vec<(String, String)> {
    let tokens = shlex_or_whitespace_words(command);
    let mut result = Vec::new();
    for token in &tokens {
        if let Some(eq_pos) = token.find('=') {
            let key = &token[..eq_pos];
            if is_valid_env_key(key) {
                let val = &token[eq_pos + 1..];
                result.push((key.to_string(), val.to_string()));
                continue;
            }
        }
        break;
    }
    result
}

/// Tokenize a command segment into words using shlex (POSIX word splitting).
///
/// Falls back to whitespace splitting if shlex cannot parse the input
/// (e.g. unmatched quotes). The fallback preserves quote characters in
/// the resulting tokens.
pub fn tokenize(command: &str) -> Vec<Word> {
    shlex_or_whitespace_words(command)
}

// Re-export from agent-types for use within the parser crate.
pub(crate) use prodagent_types::word::{is_env_assignment, is_valid_env_key};

/// Parse a command string into structured components with arguments in source order.
///
/// This is a schema-free parse. Flags are identified syntactically
/// (tokens starting with `-`). `--flag=value` splits into name and
/// value; all other flags are treated as value-less. Without knowing
/// a command's flag definitions, `--flag value` is ambiguous — the
/// value appears as a separate positional argument.
pub fn parse_command(command: &str) -> ParsedCommand {
    let tokens = shlex_or_whitespace_words(command);
    ParsedCommand::from_words(&tokens)
}

pub(crate) fn shlex_or_whitespace_words(command: &str) -> Vec<Word> {
    shlex::split(command)
        .unwrap_or_else(|| command.split_whitespace().map(String::from).collect())
        .into_iter()
        .map(Word::from)
        .collect()
}

#[cfg(test)]
#[path = "tokenize_tests.rs"]
mod tokenize_tests;
