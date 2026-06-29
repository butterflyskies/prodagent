//! Three-tier configuration cascade for prodagent.
//!
//! Loads configuration from three layers, merged in order (later wins):
//!
//! 1. **Defaults** — embedded in the binary at compile time.
//! 2. **User** — `~/.config/prodagent/config.toml` (personal preferences, policy floor).
//! 3. **Project** — `.prodagent/config.toml` (repo-specific overrides, untrusted).
//!
//! Each layer can define values in two domains:
//!
//! - **Knowledge layer** — command specs, path specs, wrappers (what tools exist).
//! - **Policy layer** — allow/ask/deny rules (what's permitted and at what friction).
//!
//! # Security invariant: monotonicity
//!
//! Project config can *tighten* user policy (escalate to Ask/Deny) but **never
//! weaken** it (allow what user denies, remove friction). This is enforced by
//! [`validate_monotonicity`] after figment merges the layers.
//!
//! # Provenance
//!
//! Figment tracks which provider set each value. Use
//! [`ConfigLoader::figment`] to inspect provenance via figment's metadata API.

mod loader;
mod monotonicity;
mod types;

pub use loader::{load_and_apply, load_split_and_apply, ConfigError, ConfigLoader};
pub use monotonicity::{validate_monotonicity, MonotonicityViolation};
pub use types::{ConfigLayer, KnowledgeConfig, PolicyOverlay, ProdagentConfig};

#[cfg(test)]
mod tests;
