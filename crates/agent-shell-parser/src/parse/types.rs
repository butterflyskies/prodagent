/// Shell operator separating consecutive pipeline segments.
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Returns `true` if this pipeline or any nested substitution has
    /// parse errors.
    ///
    /// When tree-sitter uses error recovery, some commands may not have
    /// been extracted. Callers enforcing a security boundary should
    /// treat a `true` return as "cannot safely analyze — fail closed."
    pub fn has_parse_errors_recursive(&self) -> bool {
        if self.has_parse_errors {
            return true;
        }
        for sub in &self.structural_substitutions {
            if sub.pipeline.has_parse_errors_recursive() {
                return true;
            }
        }
        for seg in &self.segments {
            for sub in &seg.substitutions {
                if sub.pipeline.has_parse_errors_recursive() {
                    return true;
                }
            }
        }
        false
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
    pub description: String,
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
    pub name: String,
    /// Value if specified with `=` (e.g., `--color=always` → `Some("always")`).
    pub value: Option<String>,
}

/// An argument in a parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandArg {
    /// A flag token (e.g., `--force`, `-f`, `--color=always`).
    Flag(ParsedFlag),
    /// A non-flag token (subcommand, path, or other argument).
    Positional(String),
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
    pub command: String,
    /// Arguments in source order — flags and positionals interleaved.
    pub args: Vec<CommandArg>,
}

impl ParsedCommand {
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
    pub fn to_words(&self) -> Vec<String> {
        let mut words = vec![self.command.clone()];
        for arg in &self.args {
            match arg {
                CommandArg::Flag(f) => match &f.value {
                    Some(v) => words.push(format!("{}={}", f.name, v)),
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

#[cfg(test)]
mod tests {
    use super::super::parse_with_substitutions;

    fn parse(cmd: &str) -> super::ParsedPipeline {
        parse_with_substitutions(cmd).expect("parse failed")
    }

    // --- find_segment ---

    #[test]
    fn find_segment_returns_first_match() {
        let p = parse("echo hello && ls -la");
        let found = p.find_segment(&|seg| {
            if seg.command.starts_with("ls") {
                Some(seg.command.clone())
            } else {
                None
            }
        });
        assert_eq!(found.as_deref(), Some("ls -la"));
    }

    #[test]
    fn find_segment_returns_none_when_no_match() {
        let p = parse("echo hello && ls -la");
        let found = p.find_segment(&|seg| {
            if seg.command.starts_with("git") {
                Some(())
            } else {
                None
            }
        });
        assert!(found.is_none());
    }

    #[test]
    fn find_segment_recurses_into_substitutions() {
        let p = parse("echo $(git status)");
        let found = p.find_segment(&|seg| {
            if seg.command.contains("git status") {
                Some(seg.command.clone())
            } else {
                None
            }
        });
        assert_eq!(found.as_deref(), Some("git status"));
    }

    #[test]
    fn find_segment_visits_substitutions_before_parent() {
        // In "echo $(date)", the walker should visit "date" before "echo $(date)".
        // filter_segments with Some for all collects in traversal order.
        let p = parse("echo $(date)");
        let all: Vec<String> = p.filter_segments(&|seg| Some(seg.command.clone()));
        assert_eq!(all, vec!["date", "echo $(date)"]);
    }

    #[test]
    fn find_segment_visits_structural_substitutions_first() {
        let p = parse("for i in $(seq 10); do echo $i; done");
        let all: Vec<String> = p.filter_segments(&|seg| Some(seg.command.clone()));
        assert_eq!(all[0], "seq 10");
    }

    // --- filter_segments ---

    #[test]
    fn filter_segments_collects_all_matches() {
        let p = parse("echo a && echo b && ls c");
        let echoes: Vec<String> = p.filter_segments(&|seg| {
            if seg.command.starts_with("echo") {
                Some(seg.command.clone())
            } else {
                None
            }
        });
        assert_eq!(echoes, vec!["echo a", "echo b"]);
    }

    #[test]
    fn filter_segments_collects_from_nested() {
        let p = parse("echo $(git status && git diff)");
        let gits: Vec<String> = p.filter_segments(&|seg| {
            if seg.command.starts_with("git") {
                Some(seg.command.clone())
            } else {
                None
            }
        });
        assert_eq!(gits, vec!["git status", "git diff"]);
    }

    // --- has_parse_errors_recursive ---

    #[test]
    fn no_errors_on_valid_input() {
        assert!(!parse("echo hello").has_parse_errors_recursive());
    }

    #[test]
    fn no_errors_on_compound() {
        assert!(!parse("echo a && echo b | cat").has_parse_errors_recursive());
    }

    #[test]
    fn no_errors_on_substitution() {
        assert!(!parse("echo $(date)").has_parse_errors_recursive());
    }
}
