use std::fmt;

use serde::{Deserialize, Serialize};

/// The authorization decision for a command.
///
/// Ordered by restrictiveness: `Allow < Ask < Deny`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyDecision {
    Allow,
    #[default]
    Ask,
    Deny,
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "Allow"),
            Self::Ask => write!(f, "Ask"),
            Self::Deny => write!(f, "Deny"),
        }
    }
}
