use agent_command_knowledge::{
    classify, CommandInfo, Effect, EnvCondition, EnvGate, EnvGateAction, KnowledgeBase,
};
use agent_shell_parser::parse::{
    self, CommandConfig, ParsedPipeline, Redirection, ResolvedCommand, ShellSegment, Word,
    WrapperEnvPolicy, WrapperSpec,
};

use crate::config::{CommandPolicy, PolicyConfig};
use crate::decision::PolicyDecision;
use crate::env_snapshot::{EnvSnapshot, EnvValueOwned};

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

        // Build the merged config once: defaults + KB-derived wrappers.
        // This is threaded through as &CommandConfig, eliminating per-depth cloning.
        let kb_wrapper_specs = derive_wrapper_specs(kb);
        let merged_config = parse::merged_config(&kb_wrapper_specs);

        // Single segment, no compound structure → evaluate directly
        if pipeline.segments.len() <= 1 && !has_substitutions && !has_parse_errors {
            return match pipeline.segments.first() {
                Some(segment) => {
                    let result = self.evaluate_segment(segment, kb, &merged_config);
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
        let mut strictest = self.evaluate_pipeline(&pipeline, kb, &merged_config, &mut segments);
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
    ///
    /// `env` is the accumulated environment snapshot from outer wrappers and
    /// inline assignments. Each wrapper may mutate the snapshot before passing
    /// it to the inner command.
    fn resolve_wrapper_core(
        &self,
        base_command: &str,
        words: &[Word],
        kb: &KnowledgeBase,
        merged_config: &CommandConfig,
        depth: u8,
        env: &EnvSnapshot,
    ) -> PolicyResult {
        if depth > 8 {
            return PolicyResult::simple(
                PolicyDecision::Ask,
                "wrapper chain too deep (fail-closed)",
            );
        }

        // Compute the env snapshot for the inner command based on wrapper type
        let inner_env = resolve_wrapper_env(base_command, words, env, merged_config);

        let resolved = parse::resolve_command_with(words, merged_config);
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
                        merged_config,
                        depth + 1,
                        &inner_env,
                    );
                    inner_result.decision
                } else {
                    let mut d = self.evaluate(parsed.command.as_str(), &inner_info);

                    // Apply env gates with the accumulated snapshot
                    if let Some(gate_decision) = apply_env_gates(&inner_info.env_gates, &inner_env)
                    {
                        d = d.max(gate_decision);
                    }

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
        merged_config: &CommandConfig,
        segments: &mut Vec<SegmentResult>,
    ) -> PolicyDecision {
        let mut strictest = PolicyDecision::Allow;

        for sub in &pipeline.structural_substitutions {
            let sub_decision = self.evaluate_pipeline(&sub.pipeline, kb, merged_config, segments);
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
                let sub_decision =
                    self.evaluate_pipeline(&sub.pipeline, kb, merged_config, segments);
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

            let result = self.evaluate_segment(segment, kb, merged_config);
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
    fn evaluate_segment(
        &self,
        segment: &ShellSegment,
        kb: &KnowledgeBase,
        merged_config: &CommandConfig,
    ) -> PolicyResult {
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

        // Build env snapshot: process env + inline assignments
        let env = EnvSnapshot::from_process_env().with_assignments(words);

        // Wrapper handling — use pre-built merged config
        if info.wrapper.is_some() {
            let mut result =
                self.resolve_wrapper_core(&base_command, words, kb, merged_config, 0, &env);
            maybe_escalate_for_redirection(&mut result, segment);
            return result;
        }

        // Apply env gates after classification and per-command overrides (gates can only escalate)
        let mut decision = self.evaluate(&base_command, &info);
        if let Some(gate_decision) = apply_env_gates(&info.env_gates, &env) {
            decision = decision.max(gate_decision);
        }

        let mut result = PolicyResult::simple(
            decision,
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

/// Derive [`WrapperSpec`]s from the knowledge base's wrapper entries.
///
/// KB wrappers that are already in the parser's default config are skipped —
/// this only produces specs for KB-only wrappers (e.g. `doas`, `pkexec`)
/// that the parser doesn't know about by default. These minimal specs have no
/// value flags or special behavior, but they let the parser recognize the
/// wrapper and strip it to find the inner command.
///
/// This is the bridge that closes the drift gap: the KB is the single source
/// of truth for "what is a wrapper," and the policy engine primes the parser
/// with that knowledge at evaluation time.
fn derive_wrapper_specs(kb: &KnowledgeBase) -> Vec<WrapperSpec> {
    let default_config = parse::default_command_config();
    kb.wrappers
        .iter()
        .filter(|(name, _)| !default_config.wrappers.iter().any(|w| &w.name == *name))
        .map(|(name, knowledge)| WrapperSpec {
            name: name.clone(),
            short_value_flags: vec![],
            long_value_flags: vec![],
            unanalyzable_flags: vec![],
            skip_env_assignments: false,
            has_terminator: false,
            skip_positionals: 0,
            env_policy: if knowledge.clears_env {
                WrapperEnvPolicy::Unknown
            } else {
                WrapperEnvPolicy::Inherit
            },
        })
        .collect()
}

/// Compute the inner command's environment based on the wrapper's env policy.
///
/// Dispatches on [`WrapperEnvPolicy`] from the wrapper's spec:
/// - `Explicit` (e.g. `env`): captures assignments, `-u` (unset), `-i` (clean).
/// - `Unknown` (e.g. `sudo`, `su`): marks env as unknown unless `-E`/`--preserve-env`.
/// - `Inherit` (e.g. `nice`, `timeout`): env passes through unchanged.
fn resolve_wrapper_env(
    wrapper_name: &str,
    words: &[Word],
    outer_env: &EnvSnapshot,
    merged_config: &CommandConfig,
) -> EnvSnapshot {
    let policy = merged_config
        .wrappers
        .iter()
        .find(|w| w.name == wrapper_name)
        .map(|w| w.env_policy)
        .unwrap_or_default();

    match policy {
        WrapperEnvPolicy::Explicit => resolve_env_wrapper(words, outer_env),
        WrapperEnvPolicy::Unknown => resolve_sudo_wrapper(words, outer_env),
        WrapperEnvPolicy::Inherit => outer_env.clone(),
    }
}

/// Resolve env mutations from an `env` wrapper invocation.
///
/// Handles:
/// - `env -i` → clean base (discard all inherited env)
/// - `env -u VAR` → unset VAR
/// - `env FOO=bar` → set FOO=bar
fn resolve_env_wrapper(words: &[Word], outer_env: &EnvSnapshot) -> EnvSnapshot {
    let mut env = outer_env.clone();

    // Find the `env` command in the words (skip leading assignments)
    let env_idx = words
        .iter()
        .position(|w| w.basename() == "env")
        .unwrap_or(0);

    let mut i = env_idx + 1;
    while i < words.len() {
        let w = &words[i];

        // -i / --ignore-environment → clean env
        if w == "-i" || w == "--ignore-environment" {
            env.reset_to_clean();
            i += 1;
            continue;
        }

        // -u VAR / --unset=VAR → unset
        if w == "-u" || w == "--unset" {
            if i + 1 < words.len() {
                env.unset(words[i + 1].as_str());
                i += 2;
                continue;
            }
            break;
        }
        if let Some(rest) = w.strip_prefix("--unset=") {
            env.unset(rest);
            i += 1;
            continue;
        }

        // Combined -uVAR form
        if w.starts_with("-u") && w.len() > 2 && !w.starts_with("--") {
            env.unset(&w[2..]);
            i += 1;
            continue;
        }

        // -C dir / --chdir=dir → skip (doesn't affect env)
        if w == "-C" || w == "--chdir" {
            i += 2;
            continue;
        }
        if w.starts_with("--chdir=") {
            i += 1;
            continue;
        }

        // -S / --split-string → the rest is unanalyzable, stop
        if w == "-S" || w == "--split-string" {
            break;
        }

        // Skip other flags
        if w.starts_with('-') && w.len() > 1 {
            i += 1;
            continue;
        }

        // KEY=VALUE assignment → set override
        if let Some((key, value)) = w.as_assignment() {
            if value.contains("$(") || value.contains('`') {
                env.set_unknown(key);
            } else {
                env.set(key, value);
            }
            i += 1;
            continue;
        }

        // Non-flag, non-assignment → inner command starts, stop
        break;
    }

    env
}

/// Resolve env for a `sudo`-like wrapper (any wrapper with `WrapperEnvPolicy::Unknown`).
///
/// Default sudo behavior resets the environment (sudoers `env_reset`), which
/// we can't observe from userspace. The conservative approach:
/// - No flag → mark all env as unknown
/// - `-E` / `--preserve-env` (without `=`) → env passes through
/// - `--preserve-env=VAR,VAR` → parse the comma-separated list; preserve
///   listed vars from outer env, mark everything else unknown
fn resolve_sudo_wrapper(words: &[Word], outer_env: &EnvSnapshot) -> EnvSnapshot {
    let has_full_preserve = words.iter().any(|w| w == "-E" || w == "--preserve-env");

    if has_full_preserve {
        return outer_env.clone();
    }

    // Check for selective --preserve-env=VAR,VAR
    // Trim each token so that `--preserve-env=FOO, BAR` (with spaces) is treated
    // the same as `--preserve-env=FOO,BAR`.
    let selective_vars: Vec<&str> = words
        .iter()
        .filter_map(|w| w.as_str().strip_prefix("--preserve-env="))
        .flat_map(|val| val.split(','))
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .collect();

    // Use EnvSnapshot::preserved_from: starts fully unknown, then restores
    // only the listed vars that have known values in the outer env.
    EnvSnapshot::preserved_from(outer_env, &selective_vars)
}

/// Evaluate env gates against an environment snapshot.
///
/// Returns `Some(decision)` if any gate matched, `None` if no gates matched
/// or there are no gates. When multiple gates match, the **strictest** action
/// wins (Deny > Ask > Allow). A Deny gate short-circuits remaining evaluation.
///
/// Unknown env var handling (conservative fail-closed):
/// - `Equals` with unknown value → non-matching (gate has no effect)
/// - `NotEquals` with unknown value → non-matching (gate has no effect)
/// - `Set` with unknown value → non-matching (can't confirm the var is set)
/// - `Unset` with unknown value → non-matching (can't confirm the var is absent)
fn apply_env_gates(gates: &[EnvGate], env: &EnvSnapshot) -> Option<PolicyDecision> {
    if gates.is_empty() {
        return None;
    }

    let mut strictest: Option<PolicyDecision> = None;

    for gate in gates {
        let env_val = env.get_value(&gate.var);
        let matches = evaluate_condition(&gate.condition, env_val.as_ref());

        if matches {
            let decision = gate_action_to_decision(gate.decision);

            // Deny short-circuits
            if decision == PolicyDecision::Deny {
                return Some(PolicyDecision::Deny);
            }

            strictest = Some(match strictest {
                Some(current) => current.max(decision),
                None => decision,
            });
        }
    }

    strictest
}

/// Evaluate an env condition against a resolved env value.
///
/// Conservative fail-closed behavior: when the value is `Unknown`, all
/// conditions return `false` — the gate does not fire. Only concrete
/// `Known` values (or `None` for `Unset`) cause a gate to match.
fn evaluate_condition(condition: &EnvCondition, value: Option<&EnvValueOwned>) -> bool {
    match condition {
        EnvCondition::Equals(expected) => match value {
            Some(EnvValueOwned::Known(actual)) => actual == expected,
            Some(EnvValueOwned::Unknown) => false, // can't confirm equality
            None => false,                         // var not set
        },
        EnvCondition::NotEquals(expected) => match value {
            Some(EnvValueOwned::Known(actual)) => actual != expected,
            Some(EnvValueOwned::Unknown) => false, // can't confirm inequality
            None => true,                          // var not set ≠ any value
        },
        EnvCondition::Set => matches!(value, Some(EnvValueOwned::Known(_))),
        EnvCondition::Unset => value.is_none(),
    }
}

/// Map a KB-side gate action to a policy decision.
fn gate_action_to_decision(action: EnvGateAction) -> PolicyDecision {
    match action {
        EnvGateAction::Allow => PolicyDecision::Allow,
        EnvGateAction::Ask => PolicyDecision::Ask,
        EnvGateAction::Deny => PolicyDecision::Deny,
    }
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
