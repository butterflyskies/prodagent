//! Command taxonomy and knowledge layer.
//!
//! Separates "what commands are" (this crate) from "what to do about them"
//! (policy, in consumers). Provides [`classify`]
//! to look up a command's [`Effect`], subcommand, escalation flags, affected
//! paths, and env gates from a [`KnowledgeBase`].
//!
//! Use [`default_knowledge_base`] to obtain the embedded defaults covering
//! git, cargo, gh, kubectl, and common shell commands.

pub mod defaults;
pub mod lookup;
pub mod merge;
pub mod types;

pub use defaults::default_knowledge_base;
pub use lookup::classify;
pub use merge::{CommandOverlay, KnowledgeOverlay, WrapperOverlay};
pub use types::{
    CommandInfo, CommandKnowledge, CommandProperties, Effect, EnvGate, FlagSchema, KnowledgeBase,
    PathPositionals, PathSpec, SubcommandEntry, SubcommandMap, WrapperInfo, WrapperKnowledge,
    MAX_SUBCOMMAND_DEPTH,
};
