//! Path inputs to policy decisions.
//!
//! The knowledge layer extracts the filesystem paths a command is expected to
//! affect — see
//! [`CommandInfo::affected_paths`](agent_command_knowledge::CommandInfo::affected_paths).
//! Historically the policy engine discarded those paths: a decision said
//! "Allow / Ask / Deny" with no record of *which* paths it pertained to.
//!
//! [`AffectedPaths`] carries that path set alongside every
//! [`PolicyResult`](crate::PolicyResult) and
//! [`SegmentResult`](crate::SegmentResult). This is the decision-*input*
//! plumbing for path-scoped policy: it makes the affected paths a first-class
//! part of the evaluation result so that downstream authorization (e.g.
//! checking affected paths against a set of authorized trees) can be
//! path-scoped. The authorization check itself is intentionally out of scope
//! here — this layer only ensures the paths reach the decision.
//!
//! Modelling the path set as a newtype (rather than passing bare
//! `Vec<Utf8PathBuf>` around) keeps the plumbing type-driven: callers can't
//! accidentally swap a path list for some other collection, and the union/dedup
//! semantics used to aggregate paths across compound-command segments live in
//! one place.

use camino::Utf8PathBuf;

/// Normalize a path by re-collecting its [`camino`] components.
///
/// This strips trailing separators (`foo/` → `foo`) and collapses redundant
/// separators (`a//b` → `a/b`), giving a canonical string representation so
/// that paths differing only in trailing slash are recognised as duplicates
/// during [`AffectedPaths::union_with`].
fn normalize(path: Utf8PathBuf) -> Utf8PathBuf {
    path.components().collect()
}

/// The set of filesystem paths a command (or compound command) is expected to
/// affect, as extracted by the knowledge layer and carried alongside a policy
/// decision.
///
/// Paths are normalised on construction via [`camino`] component
/// re-collection — trailing separators and redundant slashes are stripped so
/// that dedup in [`AffectedPaths::union_with`] is slash-insensitive.
///
/// For a single command this is the knowledge layer's list with canonical
/// path forms (order-preserving, including any duplicates the extraction
/// yielded). When aggregated across compound-command segments via
/// [`AffectedPaths::union_with`], duplicates are collapsed while first-seen
/// order is preserved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AffectedPaths(Vec<Utf8PathBuf>);

impl AffectedPaths {
    /// Wrap a list of paths from the knowledge layer.
    ///
    /// Each path is normalised (trailing separators stripped) but no
    /// de-duplication or reordering is applied — this faithfully mirrors the
    /// knowledge layer's `affected_paths` for a single command so that the
    /// engine neither adds nor drops paths.
    #[must_use]
    pub fn new(paths: Vec<Utf8PathBuf>) -> Self {
        Self(paths.into_iter().map(normalize).collect())
    }

    /// An empty path set (no paths affected, or none extracted).
    #[must_use]
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Whether no paths are recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of paths recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The paths as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[Utf8PathBuf] {
        &self.0
    }

    /// Iterate over the paths.
    pub fn iter(&self) -> std::slice::Iter<'_, Utf8PathBuf> {
        self.0.iter()
    }

    /// Fold another path set into this one, collapsing duplicates while
    /// preserving first-seen order.
    ///
    /// Used to aggregate the per-segment path sets of a compound command into
    /// a single set on the overall [`PolicyResult`](crate::PolicyResult).
    pub fn union_with(&mut self, other: &AffectedPaths) {
        for path in &other.0 {
            if !self.0.contains(path) {
                self.0.push(path.clone());
            }
        }
    }
}

impl From<Vec<Utf8PathBuf>> for AffectedPaths {
    fn from(paths: Vec<Utf8PathBuf>) -> Self {
        Self::new(paths)
    }
}

impl FromIterator<Utf8PathBuf> for AffectedPaths {
    fn from_iter<I: IntoIterator<Item = Utf8PathBuf>>(iter: I) -> Self {
        Self(iter.into_iter().map(normalize).collect())
    }
}

impl<'a> IntoIterator for &'a AffectedPaths {
    type Item = &'a Utf8PathBuf;
    type IntoIter = std::slice::Iter<'a, Utf8PathBuf>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(test)]
#[path = "paths_tests.rs"]
mod paths_tests;
