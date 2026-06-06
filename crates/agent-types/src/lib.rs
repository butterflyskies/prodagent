//! Shared types for the agent crate ecosystem.
//!
//! This crate is the single source of truth for cross-boundary types that
//! multiple agent crates depend on:
//!
//! - [`Word`] — a single shell word token with domain-specific helpers.
//! - [`WrapperSpec`] — describes how to strip a transparent wrapper command.
//! - [`CommandConfig`] — complete command classification configuration.
//! - [`SubcommandPattern`] — validated newtype for subcommand HashMap keys.
//! - [`DEFAULT_WRAPPER_SPECS`] — canonical wrapper specs compiled into both
//!   parser and KB.
//!
//! Workspace-only — not published to crates.io.

mod subcommand_pattern;
pub mod word;
mod wrapper;

pub use subcommand_pattern::{SubcommandPattern, SubcommandPatternError, MAX_SUBCOMMAND_DEPTH};
pub use word::Word;
pub use wrapper::{
    default_command_config, CommandConfig, WrapperSpec, DEFAULT_EVAL_COMMANDS, DEFAULT_SHELLS,
    DEFAULT_SOURCE_COMMANDS, DEFAULT_WRAPPER_SPECS,
};
