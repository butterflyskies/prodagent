//! Policy engine for agent tool-use authorization.
//!
//! Maps command [`Effect`](agent_command_knowledge::Effect)s to
//! [`PolicyDecision`]s via configurable defaults and per-command overrides.
//!
//! Two API levels:
//! - **High-level:** [`PolicyEngine::evaluate_command`] takes a raw command
//!   string and a [`KnowledgeBase`](agent_command_knowledge::KnowledgeBase),
//!   handles parsing, classification, wrapper resolution, escalation, and
//!   redirection detection, and returns a [`PolicyResult`].
//! - **Low-level:** [`PolicyEngine::evaluate`] takes a pre-classified
//!   [`CommandInfo`](agent_command_knowledge::CommandInfo) and returns a
//!   [`PolicyDecision`]. Useful for consumers that do their own parsing.

pub mod config;
pub mod decision;
pub mod engine;
pub mod env_snapshot;
pub mod governed_writes;
pub mod path_rules;
pub mod paths;

pub use config::{OverrideConfig, PolicyConfig, PolicyConfigBuilder};
pub use decision::PolicyDecision;
pub use engine::{derive_wrapper_specs, PolicyEngine, PolicyResult, SegmentResult};
pub use env_snapshot::{EnvSnapshot, EnvValueOwned};
pub use governed_writes::{
    GovernedDirectory, GovernedWriteMatch, ManagedGuidance, ManagedGuidanceRule,
};
pub use path_rules::{evaluate_path_rules, PathGlob, PathGlobError, PathRule, PathRuleResult};
pub use paths::AffectedPaths;
