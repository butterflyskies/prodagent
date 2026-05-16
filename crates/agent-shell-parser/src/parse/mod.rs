//! Shell command parsing and structural analysis.
//!
//! This module is **policy-free** — it decomposes shell commands into
//! structured representations but makes no allow/deny decisions.
//! Consumers (agent-jj-guard, cc-toolgate) build policy on top.
//!
//! ## Entry points
//!
//! - [`parse_with_substitutions`] — decompose a compound shell command
//!   into a recursive [`ParsedPipeline`] tree.
//! - [`parse_command`] — structurally parse a single command into
//!   [`ParsedCommand`] with ordered [`CommandArg`]s (flags and positionals
//!   in source order).
//! - [`resolve_command`] — strip transparent wrappers (env, sudo, etc.)
//!   and classify unanalyzable patterns (eval, source, shell -c).
//!
//! ## Design principles
//!
//! - **Parser annotates, consumer decides.** The library classifies
//!   commands; the consumer interprets classifications as policy.
//! - **Schema-free argument parsing.** `ParsedCommand` identifies flags
//!   syntactically (`-` prefix). Flag-value association requires the
//!   consumer's knowledge of the command's schema. Arguments are kept
//!   in source order so consumers can walk them with schema awareness.
//! - **Fail-closed on ambiguity.** Parse errors and unresolvable
//!   patterns (dynamic `$cmd`, eval) are surfaced, not hidden.

mod redirect;
mod resolve;
pub mod shell;
mod subst;
pub mod tokenize;
pub mod types;
mod walk;

pub use resolve::{default_command_config, resolve_command, resolve_command_with, strip_with_spec};
pub use shell::{dump_ast, has_output_redirection, parse_with_substitutions};
pub use tokenize::{
    base_command, command_characteristics, env_vars, find_base_command, parse_command, tokenize,
};
pub use types::{
    CommandArg, CommandCharacteristics, CommandConfig, IndirectExecution, Operator, ParseError,
    ParsedCommand, ParsedFlag, ParsedPipeline, Redirection, ResolvedCommand, ShellSegment,
    SubstitutionSpan, UnanalyzableCommand, WrapperSpec,
};
