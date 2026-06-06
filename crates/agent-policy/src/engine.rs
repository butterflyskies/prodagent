use agent_command_knowledge::{classify, CommandInfo, Effect, KnowledgeBase};
use agent_shell_parser::parse::{
    self, ParsedPipeline, Redirection, ResolvedCommand, ShellSegment, Word,
};

use crate::config::{CommandPolicy, PolicyConfig};
use crate::decision::PolicyDecision;

/// Per-segment breakdown within a compound command evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentResult {
    pub label: String,
    pub decision: PolicyDecision,
    pub reason: String,
}

/// The result of evaluating a raw command string through the full pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct PolicyResult {
    pub decision: PolicyDecision,
    pub reason: String,
    /// Per-segment breakdown for compound commands. Empty for simple commands.
    pub segments: Vec<SegmentResult>,
}

impl PolicyResult {
    fn simple(decision: PolicyDecision, reason: impl Into<String>) -> Self {
        Self {
            decision,
            reason: reason.into(),
            segments: Vec::new(),
        }
    }
}

/// Policy engine — evaluates command classifications against policy config.
pub struct PolicyEngine {
    config: PolicyConfig,
}

impl PolicyEngine {
    pub fn new(config: PolicyConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self { config })
    }

    // ── High-level API: raw command string → final decision ────────────

    /// Evaluate a raw command string against the knowledge base and policy config.
    ///
    /// Handles compound commands, wrappers, escalation flags, and redirections.
    /// This is the primary entry point — callers pass an unparsed command string
    /// and receive a final authorization decision with explanation.
    pub fn evaluate_command(&self, command: &str, kb: &KnowledgeBase) -> PolicyResult {
        let pipeline = match parse::parse_with_substitutions(command) {
            Ok(p) => p,
            Err(_) => {
                return PolicyResult::simple(PolicyDecision::Ask, "parse error (fail-closed)");
            }
        };

        let has_parse_errors = pipeline.has_parse_errors_recursive();

        let has_substitutions = pipeline
            .find_segment(&|seg| (!seg.substitutions.is_empty()).then_some(()))
            .is_some()
            || !pipeline.structural_substitutions.is_empty();

        // Single segment, no compound structure → evaluate directly
        if pipeline.segments.len() <= 1 && !has_substitutions && !has_parse_errors {
            return match pipeline.segments.first() {
                Some(segment) => {
                    let result = self.evaluate_segment(segment, kb);
                    let seg = SegmentResult {
                        label: segment.command.trim().to_string(),
                        decision: result.decision,
                        reason: result.reason.clone(),
                    };
                    PolicyResult {
                        decision: result.decision,
                        reason: result.reason,
                        segments: vec![seg],
                    }
                }
                None => PolicyResult::simple(PolicyDecision::Allow, "empty"),
            };
        }

        // Compound or error case: evaluate full pipeline, strictest wins
        let mut segments = Vec::new();
        let mut strictest = self.evaluate_pipeline(&pipeline, kb, &mut segments);
        if has_parse_errors {
            strictest = strictest.max(PolicyDecision::Ask);
        }

        let header = compound_header(&pipeline, has_parse_errors, has_substitutions);
        let reason_lines: Vec<String> = segments
            .iter()
            .map(|s| format!("  [{}] -> {:?}: {}", s.label, s.decision, s.reason))
            .collect();

        PolicyResult {
            decision: strictest,
            reason: format!("{header}:\n{}", reason_lines.join("\n")),
            segments,
        }
    }

    /// Core wrapper resolution: classify inner command, apply floor and escalates_privilege.
    /// Redirection is handled by the caller (`evaluate_segment`).
    fn resolve_wrapper_core(
        &self,
        base_command: &str,
        words: &[Word],
        kb: &KnowledgeBase,
        depth: u8,
    ) -> PolicyResult {
        if depth > 8 {
            return PolicyResult::simple(
                PolicyDecision::Ask,
                "wrapper chain too deep (fail-closed)",
            );
        }

        let resolved = parse::resolve_command(words);
        match resolved {
            ResolvedCommand::Resolved(ref parsed)
                if !parsed.command.is_empty() && parsed.command.as_str() != base_command =>
            {
                let inner_words = parsed.to_words();
                let inner_base = Word::from(parsed.command.as_str());
                let inner_info = classify(&inner_base, &inner_words, kb);

                let wrapper_kb = kb.wrappers.get(base_command);

                // Get wrapper floor from KB
                let floor = wrapper_kb
                    .map(|w| self.effect_default(w.floor_effect))
                    .unwrap_or(PolicyDecision::Allow);

                let inner_decision = if inner_info.wrapper.is_some() {
                    let inner_result = self.resolve_wrapper_core(
                        parsed.command.as_str(),
                        &inner_words,
                        kb,
                        depth + 1,
                    );
                    inner_result.decision
                } else {
                    let mut d = self.evaluate(parsed.command.as_str(), &inner_info);
                    if inner_info.has_escalation_flags && d < PolicyDecision::Ask {
                        d = PolicyDecision::Ask;
                    }
                    d
                };

                let mut decision = floor.max(inner_decision);
                let mut reason = format!(
                    "{base_command} wraps {}: effect={:?}",
                    parsed.command, inner_info.effect
                );

                // Privilege-escalating wrappers bump to at least Ask
                let escalates = wrapper_kb.map(|w| w.escalates_privilege).unwrap_or(false);
                if escalates {
                    decision = decision.max(PolicyDecision::Ask);
                    if !reason.contains("escalated") {
                        reason = format!("{reason} (escalated: privilege escalation)");
                    }
                }

                PolicyResult::simple(decision, reason)
            }
            ResolvedCommand::Unanalyzable(_) => PolicyResult::simple(
                PolicyDecision::Ask,
                format!("{base_command} wraps unanalyzable command"),
            ),
            _ => {
                // Parser couldn't strip to a distinct inner command.
                // If the KB says this is a wrapper, apply floor + escalation
                // rather than defaulting to Allow (fail-closed).
                if let Some(wrapper) = kb.wrappers.get(base_command) {
                    let floor = self.effect_default(wrapper.floor_effect);
                    // floor.max(Ask) guarantees at least Ask, which also covers
                    // escalates_privilege (Ask is the privilege-escalation floor).
                    let decision = floor.max(PolicyDecision::Ask);
                    PolicyResult::simple(
                        decision,
                        format!("{base_command} (wrapper, inner command not resolved)"),
                    )
                } else {
                    PolicyResult::simple(
                        PolicyDecision::Allow,
                        format!("{base_command} (no wrapped command)"),
                    )
                }
            }
        }
    }

    /// Recursively evaluate a pipeline tree, collecting per-segment results.
    fn evaluate_pipeline(
        &self,
        pipeline: &ParsedPipeline,
        kb: &KnowledgeBase,
        segments: &mut Vec<SegmentResult>,
    ) -> PolicyDecision {
        let mut strictest = PolicyDecision::Allow;

        for sub in &pipeline.structural_substitutions {
            let sub_decision = self.evaluate_pipeline(&sub.pipeline, kb, segments);
            let label = pipeline_label(&sub.pipeline, "structural-subst");
            segments.push(SegmentResult {
                label,
                decision: sub_decision,
                reason: "(nested)".into(),
            });
            if sub_decision > strictest {
                strictest = sub_decision;
            }
        }

        for segment in &pipeline.segments {
            for sub in &segment.substitutions {
                let sub_decision = self.evaluate_pipeline(&sub.pipeline, kb, segments);
                let label = pipeline_label(&sub.pipeline, "subst");
                segments.push(SegmentResult {
                    label,
                    decision: sub_decision,
                    reason: "(nested)".into(),
                });
                if sub_decision > strictest {
                    strictest = sub_decision;
                }
            }

            let result = self.evaluate_segment(segment, kb);
            let label = segment.command.trim().to_string();
            segments.push(SegmentResult {
                label,
                decision: result.decision,
                reason: result.reason,
            });
            if result.decision > strictest {
                strictest = result.decision;
            }
        }

        strictest
    }

    /// Evaluate a single shell segment from a parsed pipeline.
    fn evaluate_segment(&self, segment: &ShellSegment, kb: &KnowledgeBase) -> PolicyResult {
        let words = &segment.words;
        let base_command = base_command_from_words(words);

        // Bare variable assignment
        if words.len() == 1 && words[0].as_assignment().is_some() {
            return PolicyResult::simple(
                PolicyDecision::Allow,
                format!("variable assignment: {}", words[0]),
            );
        }

        if base_command.is_empty() {
            return PolicyResult::simple(PolicyDecision::Allow, "empty");
        }

        let base_word = Word::from(base_command.as_str());
        let info = classify(&base_word, words, kb);

        // Wrapper handling
        if info.wrapper.is_some() {
            let mut result = self.resolve_wrapper_core(&base_command, words, kb, 0);
            maybe_escalate_for_redirection(&mut result, segment);
            return result;
        }

        let mut result = PolicyResult::simple(
            self.evaluate(&base_command, &info),
            format!("{base_command}: effect={:?}", info.effect),
        );

        if info.has_escalation_flags && result.decision < PolicyDecision::Ask {
            result.decision = PolicyDecision::Ask;
            result.reason = format!("{} (escalated: escalation flags)", result.reason);
        }

        maybe_escalate_for_redirection(&mut result, segment);
        result
    }

    // ── Low-level API: pre-classified command → decision ───────────────

    /// Evaluate a classified command against policy.
    /// Returns the most specific applicable decision.
    pub(crate) fn evaluate(&self, base_command: &str, info: &CommandInfo) -> PolicyDecision {
        // 1. Check per-command override (most specific)
        if let Some(decision) = self.command_override(base_command, info) {
            return decision;
        }

        // 2. Fall back to effect-class default mapping
        self.effect_default(info.effect)
    }

    fn command_override(&self, base_command: &str, info: &CommandInfo) -> Option<PolicyDecision> {
        match self.config.commands.get(base_command)? {
            CommandPolicy::Flat(decision) => Some(*decision),
            CommandPolicy::Detailed(detail) => {
                // If there's a matching subcommand override, use it
                if let Some(sub) = &info.subcommand {
                    if let Some(decision) = detail.subcommands.get(sub.as_str()) {
                        return Some(*decision);
                    }
                }
                // Otherwise fall back to the base override if present
                detail.base
            }
        }
    }

    fn effect_default(&self, effect: Effect) -> PolicyDecision {
        match effect {
            Effect::ReadOnly => self.config.defaults.read_only,
            Effect::Mutating => self.config.defaults.mutating,
            Effect::Unknown => self.config.defaults.unknown,
        }
    }
}

/// Build a label for a substitution pipeline (e.g. `subst[$(git status)]`).
fn pipeline_label(pipeline: &ParsedPipeline, prefix: &str) -> String {
    let inner: String = pipeline
        .segments
        .iter()
        .map(|s| s.command.as_str())
        .collect::<Vec<_>>()
        .join(" && ");
    let inner = inner.trim();
    format!("{prefix}[$({inner})]")
}

/// Escalate Allow → Ask if the segment contains a non-benign redirection.
///
/// Checks both segment-level redirection (from wrapping constructs like
/// `redirected_statement`) and inline redirection parsed from the command text.
fn maybe_escalate_for_redirection(result: &mut PolicyResult, segment: &ShellSegment) {
    if result.decision != PolicyDecision::Allow {
        return;
    }
    if let Some(ref r) = segment.redirection {
        if !is_benign_redirection(r) {
            result.decision = PolicyDecision::Ask;
            result.reason = format!("{} (escalated: wrapping {r})", result.reason);
            return;
        }
    }
    if let Some(ref redir) =
        parse::has_output_redirection(&segment.command).unwrap_or(Some(Redirection {
            operator: ">",
            fd: None,
            target: "(parse error)".into(),
        }))
    {
        if !is_benign_redirection(redir) {
            result.decision = PolicyDecision::Ask;
            result.reason = format!("{} (escalated: {redir})", result.reason);
        }
    }
}

/// Build the header line for compound command results.
fn compound_header(
    pipeline: &ParsedPipeline,
    has_parse_errors: bool,
    has_substitutions: bool,
) -> String {
    let mut desc = Vec::new();
    if has_parse_errors {
        desc.push("parse errors, fail-closed".to_string());
    }
    if !pipeline.operators.is_empty() {
        let mut unique_ops: Vec<&str> = pipeline.operators.iter().map(|o| o.as_str()).collect();
        unique_ops.sort();
        unique_ops.dedup();
        desc.push(unique_ops.join(", "));
    }
    if has_substitutions {
        let total: usize = pipeline.fold_segments(0, &|acc, seg| acc + seg.substitutions.len())
            + pipeline.structural_substitutions.len();
        desc.push(format!("{total} substitution(s)"));
    }
    if desc.is_empty() {
        "compound command".into()
    } else {
        format!("compound command ({})", desc.join("; "))
    }
}

/// Check whether a redirection is structurally harmless and should not
/// escalate an Allow decision.
///
/// Tier 1 (never escalate):
/// - `/dev/null` — discarding output (both `>` and `>>`)
/// - fd duplication — target starts with `&` (e.g. `2>&1`, `>&2`)
fn is_benign_redirection(redir: &Redirection) -> bool {
    // /dev/null — discarding output
    if redir.target.as_str() == "/dev/null" {
        return true;
    }
    // fd duplication — e.g. 2>&1, >&2, 1>&2
    if redir.target.starts_with('&') {
        return true;
    }
    false
}

/// Extract the base command name from pre-tokenized words.
///
/// Skips leading `KEY=VALUE` env var assignments, then returns the basename
/// of the first non-assignment word (e.g. `/usr/bin/git` -> `git`).
fn base_command_from_words(words: &[Word]) -> String {
    for word in words {
        if word.is_assignment() {
            continue;
        }
        return word.basename().to_string();
    }
    String::new()
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod engine_tests;

#[cfg(test)]
#[path = "pipeline_tests.rs"]
mod pipeline_tests;

#[cfg(test)]
#[path = "engine_proptest.rs"]
mod engine_proptest;
