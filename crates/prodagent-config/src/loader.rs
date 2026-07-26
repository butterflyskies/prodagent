//! Figment-based three-tier configuration loader.
//!
//! Uses figment's provider chain to merge TOML files in order:
//! defaults → user → project. Figment handles the merge semantics and
//! tracks provenance (which file set which value) for free.

use camino::{Utf8Path, Utf8PathBuf};

use figment::providers::{Format, Toml};
use figment::Figment;
use thiserror::Error;

use agent_command_knowledge::KnowledgeBase;
use prodagent_policy::config::PolicyConfig;
use prodagent_policy::PolicyDecision;

use crate::monotonicity::{validate_monotonicity, MonotonicityViolation};
use crate::types::{ConfigLayer, ProdagentConfig};

/// Default TOML configuration embedded in the binary.
///
/// This provides sensible defaults for all config values. Users and projects
/// only need to override what they want to change.
const DEFAULT_CONFIG: &str = include_str!("defaults.toml");

/// Errors from configuration loading and validation.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Figment extraction failed (malformed TOML, type mismatch, etc.)
    #[error("config extraction error: {0}")]
    Extraction(Box<figment::Error>),

    /// The merged policy config failed internal validation (e.g. non-monotonic
    /// effect defaults where read_only > mutating).
    #[error("policy validation error: {0}")]
    PolicyValidation(String),

    /// The project layer violated the monotonicity invariant — it tried to
    /// weaken a user-level policy decision.
    #[error("monotonicity violation(s) in project config:\n{}", format_violations(.0))]
    Monotonicity(Vec<MonotonicityViolation>),
}

fn format_violations(violations: &[MonotonicityViolation]) -> String {
    violations
        .iter()
        .map(|v| format!("  - {v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Builder for loading and merging prodagent configuration.
///
/// Constructs a figment provider chain from three tiers, extracts the
/// merged config, and runs validation (policy invariants + monotonicity).
///
/// # Example
///
/// ```no_run
/// use prodagent_config::ConfigLoader;
///
/// let config = ConfigLoader::new()
///     .user_config("~/.config/prodagent/config.toml")
///     .project_config(".prodagent/config.toml")
///     .load()
///     .expect("config should be valid");
/// ```
pub struct ConfigLoader {
    user_path: Option<Utf8PathBuf>,
    project_path: Option<Utf8PathBuf>,
}

impl ConfigLoader {
    /// Create a new loader with only embedded defaults.
    pub fn new() -> Self {
        Self {
            user_path: None,
            project_path: None,
        }
    }

    /// Set the user config path (`~/.config/prodagent/config.toml`).
    ///
    /// The file is optional — if it doesn't exist, the user layer is skipped
    /// silently (figment treats missing files as empty providers).
    pub fn user_config(mut self, path: impl Into<Utf8PathBuf>) -> Self {
        self.user_path = Some(path.into());
        self
    }

    /// Set the project config path (`.prodagent/config.toml`).
    ///
    /// The file is optional — if it doesn't exist, the project layer is
    /// skipped silently.
    pub fn project_config(mut self, path: impl Into<Utf8PathBuf>) -> Self {
        self.project_path = Some(path.into());
        self
    }

    /// Build the figment provider chain.
    ///
    /// Exposed for provenance inspection — callers can use
    /// `figment.metadata()` to see which file set which value.
    pub fn figment(&self) -> Figment {
        let mut figment = Figment::new().merge(Toml::string(DEFAULT_CONFIG));

        if let Some(ref path) = self.user_path {
            figment = figment.merge(Toml::file(path));
        }

        // Project layer is NOT merged into the main figment — it's extracted
        // separately so we can validate monotonicity before applying.
        // Only knowledge values from the project are merged here; policy
        // values go through monotonicity validation first.

        figment
    }

    /// Load, merge, and validate the full configuration.
    ///
    /// Returns the merged [`ProdagentConfig`] or an error if:
    /// - TOML files are malformed
    /// - The merged policy fails internal validation
    /// - The project layer violates monotonicity
    pub fn load(&self) -> Result<ProdagentConfig, ConfigError> {
        let (_, config) = self.load_split()?;
        Ok(config)
    }

    /// Load and return both the user-only policy and the fully merged config.
    ///
    /// Used by the hook's conflict detection: comparing the user-only evaluation
    /// against the merged evaluation reveals project-vs-user conflicts.
    ///
    /// Returns `(user_only_policy, merged_config)`.
    pub fn load_split(&self) -> Result<(PolicyConfig, ProdagentConfig), ConfigError> {
        // Extract defaults + user layer
        let base_figment = self.figment();
        let base_layer: ConfigLayer = base_figment
            .extract()
            .map_err(|e| ConfigError::Extraction(Box::new(e)))?;

        // Build the user-level policy (defaults + user, before project)
        let user_policy = PolicyConfig {
            defaults: prodagent_policy::config::EffectDefaults {
                read_only: base_layer
                    .policy
                    .defaults
                    .read_only
                    .unwrap_or(PolicyDecision::Allow),
                mutating: base_layer
                    .policy
                    .defaults
                    .mutating
                    .unwrap_or(PolicyDecision::Ask),
                unknown: base_layer
                    .policy
                    .defaults
                    .unknown
                    .unwrap_or(PolicyDecision::Ask),
            },
            commands: base_layer.policy.commands.clone(),
            opaque_env_ceiling: base_layer
                .policy
                .opaque_env_ceiling
                .unwrap_or(PolicyDecision::Ask),
            path_rules: base_layer.policy.path_rules.clone().unwrap_or_default(),
            overrides: base_layer.policy.overrides.clone().unwrap_or_default(),
        };

        // Validate user-level policy
        user_policy
            .validate()
            .map_err(ConfigError::PolicyValidation)?;

        // Extract project layer if path exists
        let project_layer: Option<ConfigLayer> = if let Some(ref path) = self.project_path {
            if path.exists() {
                let project_figment = Figment::new().merge(Toml::file(path));
                Some(
                    project_figment
                        .extract()
                        .map_err(|e| ConfigError::Extraction(Box::new(e)))?,
                )
            } else {
                None
            }
        } else {
            None
        };

        // Validate monotonicity before merging project layer
        if let Some(ref project) = project_layer {
            let mut violations = validate_monotonicity(&user_policy, &project.policy);
            if !project.governed_writes.is_empty() {
                violations.push(MonotonicityViolation::Structural {
                    path: "governed_writes (prohibited in project config)".into(),
                    reason: "project files cannot authenticate their own contribution guidance"
                        .into(),
                });
            }
            if !violations.is_empty() {
                return Err(ConfigError::Monotonicity(violations));
            }
        }

        // Build the final merged config
        let config = ProdagentConfig::from_layers(base_layer, None, project_layer);

        // Final validation of the fully merged policy
        config
            .policy
            .validate()
            .map_err(ConfigError::PolicyValidation)?;

        Ok((user_policy, config))
    }

    /// Load configuration from the standard filesystem locations.
    ///
    /// Discovers:
    /// - User config: `<config_dir>/prodagent/config.toml` (XDG-compliant via `dirs::config_dir`)
    /// - Project config: walks up from `cwd` looking for `.prodagent/config.toml`
    pub fn from_environment() -> Self {
        let mut loader = Self::new();

        // User config — use XDG-compliant config directory
        if let Some(config_dir) = dirs::config_dir() {
            if let Ok(config_dir) = Utf8PathBuf::try_from(config_dir) {
                let user_path = config_dir.join("prodagent").join("config.toml");
                loader.user_path = Some(user_path);
            }
        }

        // Project config — walk up from CWD
        if let Ok(cwd) = std::env::current_dir()
            .ok()
            .and_then(|p| Utf8PathBuf::from_path_buf(p).ok())
            .ok_or(())
        {
            if let Some(project_root) = find_project_root(&cwd) {
                let project_path = project_root.join("config.toml");
                if project_path.exists() {
                    loader.project_path = Some(project_path);
                }
            }
        }

        loader
    }
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// Walk up from `start` looking for a `.prodagent` directory.
/// Returns the `.prodagent` directory path if found.
fn find_project_root(start: &Utf8Path) -> Option<Utf8PathBuf> {
    let mut current = Some(start);
    while let Some(dir) = current {
        let candidate = dir.join(".prodagent");
        if candidate.is_dir() {
            return Some(candidate);
        }
        current = dir.parent();
    }
    None
}

/// Load a [`ProdagentConfig`] and apply its knowledge overlay to a
/// [`KnowledgeBase`].
///
/// Convenience function that combines loading with knowledge base mutation.
/// The returned policy config is ready for `PolicyEngine::new`.
pub fn load_and_apply(
    loader: &ConfigLoader,
    kb: &mut KnowledgeBase,
) -> Result<PolicyConfig, ConfigError> {
    let config = loader.load()?;
    kb.merge(config.knowledge);
    Ok(config.policy)
}

/// Load split configs and apply the knowledge overlay.
///
/// Returns `(user_only_policy, merged_policy)`. The `user_only_policy` has
/// the knowledge overlay applied to a clone of the KB so both policies see
/// the same command knowledge.
///
/// Used by the hook for conflict detection: comparing evaluations under
/// `user_only_policy` vs `merged_policy` reveals project-vs-user conflicts.
pub fn load_split_and_apply(
    loader: &ConfigLoader,
    kb: &mut KnowledgeBase,
) -> Result<(PolicyConfig, PolicyConfig), ConfigError> {
    let (user_policy, config) = loader.load_split()?;
    kb.merge(config.knowledge);
    Ok((user_policy, config.policy))
}
