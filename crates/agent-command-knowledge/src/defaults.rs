//! Embedded default command knowledge base.
//!
//! Provides a lazily-initialized static [`KnowledgeBase`] parsed from the
//! embedded `config/commands.toml`. This covers all commands known to
//! cc-toolgate and agent-jj.

use std::sync::LazyLock;

use crate::types::KnowledgeBase;

static DEFAULT_KB: LazyLock<KnowledgeBase> = LazyLock::new(|| {
    toml::from_str(include_str!("../config/commands.toml"))
        .expect("embedded commands.toml is invalid")
});

/// Returns a reference to the embedded default knowledge base.
///
/// The base is parsed once from `config/commands.toml` (embedded at compile
/// time) and cached for the process lifetime. Panics if the embedded TOML is
/// malformed — this is a compile-time invariant enforced by tests.
pub fn default_knowledge_base() -> &'static KnowledgeBase {
    &DEFAULT_KB
}

#[cfg(test)]
#[path = "defaults_tests.rs"]
mod defaults_tests;
