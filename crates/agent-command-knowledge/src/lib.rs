//! Command taxonomy and knowledge layer.
//!
//! Separates "what commands are" (this crate) from "what to do about them"
//! (policy, in consumers). Provides [`classify`]
//! to look up a command's [`Effect`], subcommand, escalation flags, affected
//! paths, and env gates from a [`KnowledgeBase`].

pub mod lookup;
pub mod types;

pub use lookup::classify;
pub use types::{
    CommandInfo, CommandKnowledge, CommandProperties, Effect, EnvGate, FlagSchema, KnowledgeBase,
    PathPositionals, PathSpec, SubcommandEntry, SubcommandMap, WrapperInfo, WrapperKnowledge,
    MAX_SUBCOMMAND_DEPTH,
};
