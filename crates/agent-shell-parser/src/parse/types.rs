use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;

use super::tokenize::{is_env_assignment, is_valid_env_key};

// ---------------------------------------------------------------------------
// Word newtype
// ---------------------------------------------------------------------------

/// A single shell word token.
///
/// Wraps a `String` with domain-specific helpers for shell analysis (flag
/// detection, env assignment parsing, basename extraction). Derefs to `str`
/// for seamless use wherever a string slice is expected.
///
/// Note: `Word` carries raw shell text extracted from the parse tree. It is
/// not sanitized or validated — consumers must not treat word equality as
/// proof of command identity without considering the full resolution pipeline.
#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Word(String);

impl Word {
    /// Returns `true` if this word starts with `-`.
    pub fn is_flag(&self) -> bool {
        self.0.starts_with('-')
    }

    /// Returns `true` if this word is a valid `KEY=VALUE` environment assignment.
    pub fn is_assignment(&self) -> bool {
        is_env_assignment(&self.0)
    }

    /// Split at the first `=` and return `(key, value)` if the key is a valid
    /// environment variable name.
    pub fn as_assignment(&self) -> Option<(&str, &str)> {
        let eq_pos = self.0.find('=')?;
        let key = &self.0[..eq_pos];
        if is_valid_env_key(key) {
            Some((key, &self.0[eq_pos + 1..]))
        } else {
            None
        }
    }

    /// Strip the path prefix, e.g. `/usr/bin/ls` -> `ls`.
    pub fn basename(&self) -> &str {
        match self.0.rsplit_once('/') {
            Some((_, name)) if !name.is_empty() => name,
            _ => &self.0,
        }
    }

    /// Explicit accessor for the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner `String`.
    pub fn into_inner(self) -> String {
        self.0
    }
}

// --- Deref / AsRef / Borrow ---

impl Deref for Word {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Word {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for Word {
    fn borrow(&self) -> &str {
        &self.0
    }
}

// --- Display / Debug ---

impl fmt::Display for Word {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Word {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

// --- From conversions ---

impl From<String> for Word {
    fn from(s: String) -> Self {
        Word(s)
    }
}

impl From<&str> for Word {
    fn from(s: &str) -> Self {
        Word(s.to_string())
    }
}

// --- PartialEq with str types ---

impl PartialEq<str> for Word {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Word {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Word> for str {
    fn eq(&self, other: &Word) -> bool {
        self == other.0
    }
}

impl PartialEq<Word> for &str {
    fn eq(&self, other: &Word) -> bool {
        *self == other.0
    }
}

impl PartialEq<String> for Word {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Word> for String {
    fn eq(&self, other: &Word) -> bool {
        *self == other.0
    }
}

/// Shell operator separating consecutive pipeline segments.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Operator {
    /// `&&` — run next only if previous succeeded
    And,
    /// `||` — run next only if previous failed
    Or,
    /// `;` — run next unconditionally
    Semi,
    /// `|` — pipe stdout
    Pipe,
    /// `|&` — pipe stdout+stderr
    PipeErr,
    /// `&` — previous command backgrounded, next runs immediately
    Background,
}

impl Operator {
    pub fn as_str(&self) -> &'static str {
        match self {
            Operator::And => "&&",
            Operator::Or => "||",
            Operator::Semi => ";",
            Operator::Pipe => "|",
            Operator::PipeErr => "|&",
            Operator::Background => "&",
        }
    }
}

impl fmt::Display for Operator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A fully decomposed compound command.
///
/// This is a recursive structure: segments may contain substitutions, and
/// each substitution contains a recursively-parsed [`ParsedPipeline`].
/// Evaluation proceeds bottom-up (a catamorphism): inner substitutions are
/// evaluated first, their output feeds the outer command.
#[derive(Debug, Clone)]
pub struct ParsedPipeline {
    pub segments: Vec<ShellSegment>,
    /// Operators between consecutive segments.
    pub operators: Vec<Operator>,
    /// Substitutions in non-command structural positions: `for`-loop
    /// iteration values (`for i in $(cmd)`), `case` subjects
    /// (`case $(cmd) in`).
    ///
    /// These execute before any segment in this pipeline. Each is
    /// recursively parsed.
    pub structural_substitutions: Vec<SubstitutionSpan>,
    /// `true` when tree-sitter produced error-recovery nodes in the AST.
    ///
    /// The pipeline is still usable — tree-sitter always produces a tree —
    /// but callers should treat the result as best-effort.
    pub has_parse_errors: bool,
}

impl ParsedPipeline {
    /// An empty pipeline representing a parse failure.
    pub fn empty_with_error() -> Self {
        Self {
            segments: vec![],
            operators: vec![],
            structural_substitutions: vec![],
            has_parse_errors: true,
        }
    }

    /// Walk all pipelines in the tree (this one and all nested ones),
    /// depth-first. Returns the first `Some(T)` produced by `f`.
    ///
    /// This is the lowest-level traversal primitive — it visits pipeline
    /// nodes rather than segments, enabling checks on pipeline-level
    /// properties (like `has_parse_errors`).
    pub fn find_pipeline<T>(&self, f: &impl Fn(&ParsedPipeline) -> Option<T>) -> Option<T> {
        if let Some(hit) = f(self) {
            return Some(hit);
        }
        for sub in &self.structural_substitutions {
            if let Some(hit) = sub.pipeline.find_pipeline(f) {
                return Some(hit);
            }
        }
        for seg in &self.segments {
            for sub in &seg.substitutions {
                if let Some(hit) = sub.pipeline.find_pipeline(f) {
                    return Some(hit);
                }
            }
        }
        None
    }

    /// Returns `true` if any pipeline in the tree satisfies `f`.
    pub fn any_pipeline(&self, f: &impl Fn(&ParsedPipeline) -> bool) -> bool {
        self.find_pipeline(&|p| if f(p) { Some(()) } else { None })
            .is_some()
    }

    /// Walk the pipeline tree depth-first in execution order, applying `f`
    /// to each [`ShellSegment`]. Returns the first `Some(T)` produced by
    /// `f`, or `None` if every segment returns `None`.
    ///
    /// Traversal order mirrors shell evaluation:
    /// 1. Structural substitutions (for-loop values, case subjects)
    /// 2. For each segment: its substitutions first, then the segment itself
    ///
    /// This is the canonical way to inspect every command in the tree.
    /// Both "does any segment satisfy P?" and "find the first segment
    /// matching P" reduce to this.
    pub fn find_segment<T>(&self, f: &impl Fn(&ShellSegment) -> Option<T>) -> Option<T> {
        for sub in &self.structural_substitutions {
            if let Some(hit) = sub.pipeline.find_segment(f) {
                return Some(hit);
            }
        }
        for seg in &self.segments {
            for sub in &seg.substitutions {
                if let Some(hit) = sub.pipeline.find_segment(f) {
                    return Some(hit);
                }
            }
            if let Some(hit) = f(seg) {
                return Some(hit);
            }
        }
        None
    }

    /// Walk the pipeline tree depth-first, applying `f` to each
    /// [`ShellSegment`] and collecting every non-`None` result.
    ///
    /// Same traversal order as [`find_segment`](Self::find_segment) but
    /// does not short-circuit.
    pub fn filter_segments<T>(&self, f: &impl Fn(&ShellSegment) -> Option<T>) -> Vec<T> {
        let mut out = Vec::new();
        self.filter_segments_into(f, &mut out);
        out
    }

    fn filter_segments_into<T>(&self, f: &impl Fn(&ShellSegment) -> Option<T>, out: &mut Vec<T>) {
        for sub in &self.structural_substitutions {
            sub.pipeline.filter_segments_into(f, out);
        }
        for seg in &self.segments {
            for sub in &seg.substitutions {
                sub.pipeline.filter_segments_into(f, out);
            }
            if let Some(hit) = f(seg) {
                out.push(hit);
            }
        }
    }

    /// Walk the pipeline tree depth-first, threading an accumulator through
    /// every [`ShellSegment`] and returning the final value.
    ///
    /// Same traversal order as [`filter_segments`](Self::filter_segments) but
    /// without allocating — callers that only need to aggregate a value
    /// (count, sum, max, boolean) avoid the intermediate `Vec`.
    ///
    /// Unlike `filter_segments`, which only collects `Some` results, `f` is
    /// called unconditionally on every segment in the tree — there is no
    /// filtering step. Callers control what to accumulate inside `f`.
    pub fn fold_segments<T>(&self, init: T, f: &impl Fn(T, &ShellSegment) -> T) -> T {
        let mut acc = init;
        for sub in &self.structural_substitutions {
            acc = sub.pipeline.fold_segments(acc, f);
        }
        for seg in &self.segments {
            for sub in &seg.substitutions {
                acc = sub.pipeline.fold_segments(acc, f);
            }
            acc = f(acc, seg);
        }
        acc
    }

    /// Returns `true` if this pipeline or any nested substitution has
    /// parse errors.
    ///
    /// When tree-sitter uses error recovery, some commands may not have
    /// been extracted. Callers enforcing a security boundary should
    /// treat a `true` return as "cannot safely analyze — fail closed."
    pub fn has_parse_errors_recursive(&self) -> bool {
        self.any_pipeline(&|p| p.has_parse_errors)
    }
}

/// A single evaluable command within a compound pipeline.
#[derive(Debug, Clone)]
pub struct ShellSegment {
    /// The command text, exactly as it appears in the source (trimmed).
    ///
    /// Substitution syntax (`$()`, backticks, `<()`, `>()`) is preserved
    /// verbatim — the [`substitutions`](Self::substitutions) field carries
    /// the recursively-parsed contents with byte positions into this text.
    pub command: String,

    /// Pre-tokenized word list as tree-sitter understood word boundaries.
    ///
    /// Unlike shlex tokenization of [`command`](Self::command), this
    /// correctly preserves substitution syntax as single tokens. For
    /// example, `export FOO=$(echo test) BAR=baz` produces
    /// `["export", "FOO=$(echo test)", "BAR=baz"]` — shlex would
    /// incorrectly split inside the `$(...)`.
    ///
    /// Quotes are stripped: `"foo bar"` becomes `foo bar`. Both
    /// tree-sitter extraction and shlex fallback produce unquoted tokens.
    /// Substitution delimiters (`$(...)`, `` `...` ``, `<(...)`) are
    /// preserved as-is since they are semantic, not syntactic wrappers.
    ///
    /// Falls back to shlex/whitespace tokenization when tree-sitter does
    /// not provide word-level structure (e.g. unknown node types or
    /// heredoc loose words). The fallback is documented per node type in
    /// the parser source.
    pub words: Vec<Word>,

    /// Output redirection detected on a wrapping construct.
    ///
    /// When the parser extracts commands from inside a control-flow block
    /// that has output redirection (e.g. `for ... done > file`), the
    /// redirect is not present in the segment's `command` text. This field
    /// carries the redirection so the eval layer can escalate the decision.
    pub redirection: Option<Redirection>,

    /// Substitutions within this segment's command text, in source order.
    ///
    /// Each substitution is evaluated before this segment's command.
    /// `start`/`end` byte offsets index into [`command`](Self::command).
    pub substitutions: Vec<SubstitutionSpan>,
}

/// A command substitution's position and recursively-parsed contents.
#[derive(Debug, Clone)]
pub struct SubstitutionSpan {
    /// Byte offset of the substitution start within the parent's text.
    ///
    /// For substitutions on a [`ShellSegment`], this indexes into
    /// `segment.command`. For structural substitutions on a
    /// [`ParsedPipeline`], this is relative to the source text passed
    /// to [`parse_with_substitutions`] at this recursion level (for
    /// nested pipelines, that is the inner text of the parent
    /// substitution, not the top-level command string).
    pub start: usize,
    /// Byte offset past the end of the substitution.
    pub end: usize,
    /// The recursively-parsed inner pipeline.
    pub pipeline: ParsedPipeline,
}

/// Describes an output redirection that may mutate filesystem state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirection {
    /// The redirection operator (e.g., `>`, `>>`, `>|`, `&>`, `&>>`, `<>`, `>&`).
    pub operator: &'static str,
    /// Source file descriptor, if explicitly specified (e.g., `2>` → `Some(2)`).
    pub fd: Option<u32>,
    /// Destination (file path, fd number for `>&N`, or empty for `<>`).
    pub target: String,
}

impl fmt::Display for Redirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.fd {
            Some(fd) => write!(
                f,
                "output redirection ({fd}{} {})",
                self.operator, self.target
            ),
            None => write!(f, "output redirection ({} {})", self.operator, self.target),
        }
    }
}

/// Tree-sitter failed to produce a syntax tree.
///
/// Extremely rare in practice — tree-sitter handles any input, including
/// malformed shell. The only known causes are memory allocation failure
/// or a cancelled parse.
#[derive(Debug, thiserror::Error)]
#[error("tree-sitter failed to produce a syntax tree")]
pub struct ParseError;

/// Classification of indirect execution patterns that may hide commands
/// from static analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndirectExecution {
    /// `eval "..."` — argument string is executed as shell code.
    /// Cannot be statically analyzed in the general case.
    Eval,
    /// `bash -c "..."` / `sh -c "..."` — spawns a new shell with
    /// inline code. Cannot be statically analyzed.
    ShellSpawn,
    /// `env cmd` / `command cmd` / `sudo cmd` — transparent wrapper
    /// around another command. Strip the wrapper and re-analyze.
    CommandWrapper,
    /// `source file` / `. file` — executes a script in the current
    /// shell. Contents cannot be statically analyzed.
    SourceScript,
}

/// Properties of a parsed command segment relevant to security analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandCharacteristics {
    /// Base command name (path stripped, env vars skipped).
    pub base_command: String,
    /// If this is an indirect execution wrapper, what kind.
    pub indirect_execution: Option<IndirectExecution>,
    /// Whether the command position contains a variable expansion
    /// (`$cmd`, `${cmd}`) that cannot be statically resolved.
    pub has_dynamic_command: bool,
}

/// A parsed flag from a command's argument list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedFlag {
    /// The flag name without its value (e.g., `--force`, `-f`).
    pub name: Word,
    /// Value if specified with `=` (e.g., `--color=always` → `Some("always")`).
    pub value: Option<Word>,
}

/// An argument in a parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommandArg {
    /// A flag token (e.g., `--force`, `-f`, `--color=always`).
    Flag(ParsedFlag),
    /// A non-flag token (subcommand, path, or other argument).
    Positional(Word),
}

/// Structurally decomposed command with arguments in source order.
///
/// Schema-free parse: flags are identified syntactically (tokens starting
/// with `-`). Without a command's flag definitions, `--flag value` is
/// ambiguous — the value appears as a separate positional. Schema-aware
/// consumers walk `args` to associate values with flags they know about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand {
    /// Base command name (path stripped, env vars skipped).
    pub command: Word,
    /// Arguments in source order — flags and positionals interleaved.
    pub args: Vec<CommandArg>,
}

impl ParsedCommand {
    /// Construct a `ParsedCommand` directly from a word slice, avoiding a
    /// string round-trip through shlex.
    ///
    /// - First word that is not an env assignment becomes the `command`
    ///   (with path prefix stripped).
    /// - Remaining words are classified as [`CommandArg::Flag`] or
    ///   [`CommandArg::Positional`] using the same schema-free rules as
    ///   [`parse_command`](super::tokenize::parse_command).
    pub fn from_words(words: &[Word]) -> Self {
        let cmd_idx = words.iter().position(|w| !w.is_assignment());
        let Some(cmd_idx) = cmd_idx else {
            return ParsedCommand {
                command: Word::from(""),
                args: vec![],
            };
        };

        let base = Word::from(words[cmd_idx].basename());

        let mut args = Vec::new();
        let mut past_double_dash = false;

        for token in &words[cmd_idx + 1..] {
            if past_double_dash {
                args.push(CommandArg::Positional(token.clone()));
                continue;
            }
            if token == "--" {
                past_double_dash = true;
                continue;
            }
            if let Some(rest) = token.strip_prefix("--") {
                if let Some((name, value)) = rest.split_once('=') {
                    args.push(CommandArg::Flag(ParsedFlag {
                        name: Word::from(format!("--{name}")),
                        value: Some(Word::from(value)),
                    }));
                } else {
                    args.push(CommandArg::Flag(ParsedFlag {
                        name: token.clone(),
                        value: None,
                    }));
                }
            } else if token.starts_with('-') && token.len() > 1 {
                args.push(CommandArg::Flag(ParsedFlag {
                    name: token.clone(),
                    value: None,
                }));
            } else {
                args.push(CommandArg::Positional(token.clone()));
            }
        }

        ParsedCommand {
            command: base,
            args,
        }
    }

    /// First positional argument (often a subcommand).
    pub fn subcommand(&self) -> Option<&str> {
        self.args.iter().find_map(|a| match a {
            CommandArg::Positional(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Iterate over all flags.
    pub fn flags(&self) -> impl Iterator<Item = &ParsedFlag> {
        self.args.iter().filter_map(|a| match a {
            CommandArg::Flag(f) => Some(f),
            _ => None,
        })
    }

    /// Iterate over all positional arguments.
    pub fn positional(&self) -> impl Iterator<Item = &str> {
        self.args.iter().filter_map(|a| match a {
            CommandArg::Positional(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Check if a flag is present by name (e.g., `--force` or `-f`).
    pub fn has_flag(&self, name: &str) -> bool {
        self.flags().any(|f| f.name == name)
    }

    /// Reconstruct a flat word list.
    pub fn to_words(&self) -> Vec<Word> {
        let mut words = vec![self.command.clone()];
        for arg in &self.args {
            match arg {
                CommandArg::Flag(f) => match &f.value {
                    Some(v) => words.push(Word::from(format!("{}={}", f.name, v))),
                    None => words.push(f.name.clone()),
                },
                CommandArg::Positional(s) => words.push(s.clone()),
            }
        }
        words
    }
}

/// Result of resolving a command through the indirection layer.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ResolvedCommand {
    /// Wrappers stripped, command structurally parsed.
    Resolved(ParsedCommand),
    /// The command is unanalyzable — eval, source, shell -c, dynamic `$cmd`.
    Unanalyzable(UnanalyzableCommand),
}

/// A command that cannot be statically analyzed.
#[derive(Debug, Clone)]
pub struct UnanalyzableCommand {
    /// The command that triggered the classification (e.g., `eval`, `bash`).
    pub command: String,
    /// Why it's unanalyzable.
    pub kind: IndirectExecution,
}

/// Describes how to strip a transparent wrapper command to find the inner command.
///
/// Each wrapper has different flag semantics. This struct captures just enough
/// to correctly skip past the wrapper and its flags to the real command.
/// Designed for deserialization from config files — consumers load specs from
/// JSON/TOML/YAML and pass them to [`resolve_command_with`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WrapperSpec {
    /// Command name to match (basename, e.g., "sudo").
    pub name: String,
    /// Short flags that consume the next token as a value (e.g., `["-u", "-g"]`).
    #[serde(default)]
    pub short_value_flags: Vec<String>,
    /// Long flags that consume the next token as a value (e.g., `["--user", "--group"]`).
    #[serde(default)]
    pub long_value_flags: Vec<String>,
    /// Flags whose presence makes the entire invocation unanalyzable.
    /// Example: `env -S` executes its value as a command string (eval-equivalent).
    #[serde(default)]
    pub unanalyzable_flags: Vec<String>,
    /// Whether to skip leading `KEY=VALUE` tokens after the wrapper (env-style).
    #[serde(default)]
    pub skip_env_assignments: bool,
    /// Whether `--` terminates flag processing for this wrapper.
    #[serde(default)]
    pub has_terminator: bool,
    /// Number of leading positional arguments to skip before the inner command.
    ///
    /// Some wrappers require mandatory positional args before the command:
    /// `timeout DURATION cmd`, `chrt PRIORITY cmd`, `taskset MASK cmd`.
    /// Set this to the number of positionals to consume before treating
    /// the next non-flag token as the inner command.
    #[serde(default)]
    pub skip_positionals: usize,
}

/// Complete command classification configuration.
///
/// Drives all indirect execution detection — no command knowledge is hardcoded
/// in the parser source. Consumers load this from JSON/TOML/YAML and pass it
/// to [`resolve_command_with`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommandConfig {
    /// Transparent wrappers that execute an inner command (env, sudo, etc.).
    pub wrappers: Vec<WrapperSpec>,
    /// Shells that can spawn inline code via `-c` (bash, sh, zsh, etc.).
    /// When invoked without `-c`, classified as script execution.
    pub shells: Vec<String>,
    /// Commands that execute their argument as shell code (eval).
    pub eval_commands: Vec<String>,
    /// Commands that execute a file in the current shell (source, `.`).
    pub source_commands: Vec<String>,
}

#[cfg(test)]
#[path = "types_tests.rs"]
mod types_tests;
