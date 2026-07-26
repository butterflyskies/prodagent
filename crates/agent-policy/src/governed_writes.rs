//! Managed guidance for shell writes into governed directories.
//!
//! This module deliberately recognizes a small syntax surface: output
//! redirections with literal path targets, optionally following literal `cd`
//! transitions in an ordered top-level command chain. The shell parser remains
//! syntax-only; interpreting `cd` and resolving paths belongs here.

use std::collections::HashSet;

use agent_shell_parser::parse::{self, Operator, ShellSegment};
use camino::{Utf8Component, Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A validated absolute directory governed by managed configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GovernedDirectory(Utf8PathBuf);

impl GovernedDirectory {
    /// The normalized absolute directory path.
    #[must_use]
    pub fn as_path(&self) -> &Utf8Path {
        &self.0
    }
}

impl TryFrom<String> for GovernedDirectory {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let path = Utf8Path::new(value.trim());
        if !path.is_absolute() {
            return Err("governed directory must be an absolute path".into());
        }
        Ok(Self(normalize_absolute(path)))
    }
}

impl Serialize for GovernedDirectory {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for GovernedDirectory {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

/// One trusted directory-to-guidance mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedGuidanceRule {
    /// Directory whose shell writes are refused.
    directory: GovernedDirectory,
    /// Contribution instructions injected into the hook reason.
    guide: String,
    /// Optional link to a contribution template.
    #[serde(default)]
    template: Option<String>,
}

impl ManagedGuidanceRule {
    /// Construct and validate a managed guidance rule.
    pub fn new(
        directory: impl Into<String>,
        guide: impl Into<String>,
        template: Option<String>,
    ) -> Result<Self, String> {
        let rule = Self {
            directory: directory.into().try_into()?,
            guide: guide.into(),
            template,
        };
        rule.validate()?;
        Ok(rule)
    }

    /// Governed directory for this rule.
    #[must_use]
    pub fn directory(&self) -> &GovernedDirectory {
        &self.directory
    }

    /// Managed contribution instructions.
    #[must_use]
    pub fn guide(&self) -> &str {
        &self.guide
    }

    /// Optional managed contribution template link.
    #[must_use]
    pub fn template(&self) -> Option<&str> {
        self.template.as_deref()
    }

    fn validate(&self) -> Result<(), String> {
        if self.guide.trim().is_empty() {
            return Err(format!(
                "governed write guide for `{}` must not be empty",
                self.directory.as_path()
            ));
        }
        if self
            .template
            .as_ref()
            .is_some_and(|link| link.trim().is_empty())
        {
            return Err(format!(
                "governed write template for `{}` must not be empty",
                self.directory.as_path()
            ));
        }
        Ok(())
    }
}

/// A verified set of managed guidance rules.
///
/// Construction validates every rule and rejects duplicate directories.
/// Rules are sorted most-specific-first so nested governed directories select
/// their own guidance deterministically.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManagedGuidance {
    rules: Vec<ManagedGuidanceRule>,
}

impl ManagedGuidance {
    /// Validate and construct managed guidance.
    pub fn try_new(mut rules: Vec<ManagedGuidanceRule>) -> Result<Self, String> {
        let mut directories = HashSet::new();
        for rule in &rules {
            rule.validate()?;
            if !directories.insert(rule.directory.clone()) {
                return Err(format!(
                    "duplicate governed write directory `{}`",
                    rule.directory.as_path()
                ));
            }
        }
        rules.sort_by_key(|rule| std::cmp::Reverse(rule.directory.as_path().components().count()));
        Ok(Self { rules })
    }

    /// Whether no governed directories are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Inspect the verified rules.
    #[must_use]
    pub fn rules(&self) -> &[ManagedGuidanceRule] {
        &self.rules
    }

    /// Find a recognized shell write into a governed directory.
    ///
    /// Relative destinations are resolved against the hook CWD plus preceding
    /// literal `cd DIR` transitions connected with `&&` or `;`. Dynamic or
    /// otherwise ambiguous transitions are not guessed.
    #[must_use]
    pub fn evaluate(&self, command: &str, cwd: Option<&str>) -> Option<GovernedWriteMatch<'_>> {
        if self.rules.is_empty() {
            return None;
        }
        let pipeline = parse::parse_with_substitutions(command).ok()?;

        let mut effective_cwds = cwd
            .map(Utf8Path::new)
            .filter(|path| path.is_absolute())
            .map(normalize_absolute)
            .into_iter()
            .collect::<Vec<_>>();

        for (index, segment) in pipeline.segments.iter().enumerate() {
            let destinations: Vec<Utf8PathBuf> = if effective_cwds.is_empty() {
                resolve_redirections(segment, None)
            } else {
                effective_cwds
                    .iter()
                    .flat_map(|cwd| resolve_redirections(segment, Some(cwd)))
                    .collect()
            };
            for destination in destinations {
                if let Some(rule) = self
                    .rules
                    .iter()
                    .find(|rule| destination.starts_with(rule.directory.as_path()))
                {
                    return Some(GovernedWriteMatch { destination, rule });
                }
            }

            let Some(operator) = pipeline.operators.get(index) else {
                continue;
            };
            if !is_cd(segment) {
                continue;
            }

            let transitioned = if effective_cwds.is_empty() {
                literal_cd_target(segment, None).into_iter().collect()
            } else {
                effective_cwds
                    .iter()
                    .filter_map(|cwd| literal_cd_target(segment, Some(cwd)))
                    .collect::<Vec<_>>()
            };

            match operator {
                // The next segment runs only after a successful cd, so the
                // original CWD is no longer possible.
                Operator::And => effective_cwds = transitioned,
                // The next segment runs whether cd succeeds or fails. Without
                // consulting mutable filesystem state, both CWDs are possible.
                Operator::Semi => {
                    effective_cwds.extend(transitioned);
                    effective_cwds.sort();
                    effective_cwds.dedup();
                }
                // `cd ... || next` reaches next only on failure, while
                // pipeline/background cd cannot change the parent shell CWD.
                Operator::Or | Operator::Pipe | Operator::PipeErr | Operator::Background => {}
                _ => {}
            }
        }
        None
    }
}

impl Serialize for ManagedGuidance {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.rules.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ManagedGuidance {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let rules = Vec::<ManagedGuidanceRule>::deserialize(deserializer)?;
        Self::try_new(rules).map_err(serde::de::Error::custom)
    }
}

/// A governed write found in an original shell command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedWriteMatch<'a> {
    /// Resolved absolute destination.
    destination: Utf8PathBuf,
    /// Most-specific managed guidance rule.
    rule: &'a ManagedGuidanceRule,
}

impl GovernedWriteMatch<'_> {
    /// Resolved absolute destination.
    #[must_use]
    pub fn destination(&self) -> &Utf8Path {
        &self.destination
    }

    /// Most-specific managed guidance rule.
    #[must_use]
    pub fn rule(&self) -> &ManagedGuidanceRule {
        self.rule
    }
}

fn resolve_redirections(segment: &ShellSegment, cwd: Option<&Utf8Path>) -> Vec<Utf8PathBuf> {
    let mut redirections = parse::output_redirections(&segment.command).unwrap_or_default();
    if let Some(inherited) = &segment.redirection {
        if !redirections.contains(inherited) {
            redirections.push(inherited.clone());
        }
    }
    redirections
        .iter()
        .filter_map(|redirection| resolve_redirection(redirection, cwd))
        .collect()
}

fn resolve_redirection(
    redirection: &agent_shell_parser::parse::Redirection,
    cwd: Option<&Utf8Path>,
) -> Option<Utf8PathBuf> {
    if !matches!(
        redirection.operator,
        ">" | ">>" | ">|" | "&>" | "&>>" | "<>" | ">&"
    ) {
        return None;
    }
    if redirection.operator == ">&" && redirection.target.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    resolve_literal_path(&redirection.target, cwd)
}

fn is_cd(segment: &ShellSegment) -> bool {
    segment
        .words
        .first()
        .is_some_and(|word| word.as_str() == "cd")
}

fn literal_cd_target(segment: &ShellSegment, cwd: Option<&Utf8Path>) -> Option<Utf8PathBuf> {
    if segment.redirection.is_some() || !segment.substitutions.is_empty() {
        return None;
    }
    let words = &segment.words;
    if words.len() != 2 || words[0].as_str() != "cd" {
        return None;
    }
    resolve_literal_path(words[1].as_str(), cwd)
}

fn resolve_literal_path(target: &str, cwd: Option<&Utf8Path>) -> Option<Utf8PathBuf> {
    if target.is_empty()
        || target
            .bytes()
            .any(|byte| matches!(byte, b'$' | b'`' | b'*' | b'?' | b'[' | b']' | b'{' | b'}'))
        || target.starts_with('~')
    {
        return None;
    }

    let path = Utf8Path::new(target);
    if path.is_absolute() {
        Some(normalize_absolute(path))
    } else {
        cwd.map(|base| normalize_absolute(&base.join(path)))
    }
}

fn normalize_absolute(path: &Utf8Path) -> Utf8PathBuf {
    debug_assert!(path.is_absolute());
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Utf8Component::RootDir | Utf8Component::Prefix(_) => parts.clear(),
            Utf8Component::CurDir => {}
            Utf8Component::ParentDir => {
                parts.pop();
            }
            Utf8Component::Normal(part) => parts.push(part),
        }
    }
    let mut normalized = Utf8PathBuf::from("/");
    for part in parts {
        normalized.push(part);
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guidance(directory: &str) -> ManagedGuidance {
        ManagedGuidance::try_new(vec![ManagedGuidanceRule {
            directory: directory.to_string().try_into().unwrap(),
            guide: "Use the incident template and include an owner.".into(),
            template: Some("https://example.test/incident-template".into()),
        }])
        .unwrap()
    }

    #[test]
    fn governed_append_after_literal_cd_is_matched() {
        let policy = guidance("/work/incidents");
        let hit = policy
            .evaluate("cd incidents && echo updated >> report.md", Some("/work"))
            .unwrap();

        assert_eq!(
            hit.destination,
            Utf8PathBuf::from("/work/incidents/report.md")
        );
        assert_eq!(
            hit.rule.directory.as_path(),
            Utf8Path::new("/work/incidents")
        );
    }

    #[test]
    fn semicolon_cd_checks_success_and_failure_cwds() {
        let policy = guidance("/work/incidents");

        let success_path = policy
            .evaluate("cd incidents ; echo updated > report.md", Some("/work"))
            .unwrap();
        assert_eq!(
            success_path.destination,
            Utf8PathBuf::from("/work/incidents/report.md")
        );

        let failure_path = policy
            .evaluate(
                "cd /somewhere-else ; echo updated > report.md",
                Some("/work/incidents"),
            )
            .unwrap();
        assert_eq!(
            failure_path.destination,
            Utf8PathBuf::from("/work/incidents/report.md")
        );
    }

    #[test]
    fn ampersand_redirect_is_matched_but_fd_duplication_is_not() {
        let policy = guidance("/work/incidents");

        assert!(policy
            .evaluate("echo updated >& /work/incidents/report.md", Some("/work"))
            .is_some());
        assert!(policy
            .evaluate("echo updated >&3", Some("/work/incidents"))
            .is_none());
    }

    #[test]
    fn every_redirection_destination_is_checked() {
        let policy = guidance("/work/incidents");

        let hit = policy
            .evaluate(
                "echo updated > /work/notes.txt 2> /work/incidents/error.log",
                Some("/work"),
            )
            .unwrap();
        assert_eq!(
            hit.destination,
            Utf8PathBuf::from("/work/incidents/error.log")
        );
    }

    #[test]
    fn recovered_read_write_redirect_is_checked() {
        let policy = guidance("/work/incidents");

        let hit = policy
            .evaluate("cd incidents && cat <> report.md", Some("/work"))
            .unwrap();
        assert_eq!(
            hit.destination,
            Utf8PathBuf::from("/work/incidents/report.md")
        );
    }

    #[test]
    fn outside_write_and_reads_are_unchanged() {
        let policy = guidance("/work/incidents");

        assert!(policy
            .evaluate("echo updated >> notes.md", Some("/work"))
            .is_none());
        assert!(policy
            .evaluate("cat incidents/report.md", Some("/work"))
            .is_none());
    }

    #[test]
    fn dynamic_cd_is_not_guessed() {
        let policy = guidance("/work/incidents");

        assert!(policy
            .evaluate("cd \"$TARGET\" && echo updated >> report.md", Some("/work"))
            .is_none());
    }

    #[test]
    fn most_specific_directory_owns_guidance() {
        let policy = ManagedGuidance::try_new(vec![
            ManagedGuidanceRule {
                directory: "/work".to_string().try_into().unwrap(),
                guide: "broad".into(),
                template: None,
            },
            ManagedGuidanceRule {
                directory: "/work/incidents".to_string().try_into().unwrap(),
                guide: "specific".into(),
                template: None,
            },
        ])
        .unwrap();

        let hit = policy
            .evaluate("echo updated > /work/incidents/one.md", Some("/elsewhere"))
            .unwrap();
        assert_eq!(hit.rule.guide, "specific");
    }

    #[test]
    fn invalid_managed_guidance_is_rejected() {
        let duplicate = ManagedGuidance::try_new(vec![
            ManagedGuidanceRule {
                directory: "/work".to_string().try_into().unwrap(),
                guide: "one".into(),
                template: None,
            },
            ManagedGuidanceRule {
                directory: "/work/.".to_string().try_into().unwrap(),
                guide: "two".into(),
                template: None,
            },
        ]);
        assert!(duplicate.is_err());

        let empty_guide = ManagedGuidance::try_new(vec![ManagedGuidanceRule {
            directory: "/work".to_string().try_into().unwrap(),
            guide: " ".into(),
            template: None,
        }]);
        assert!(empty_guide.is_err());
    }
}
