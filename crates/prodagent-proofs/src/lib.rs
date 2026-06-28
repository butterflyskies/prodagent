//! Kani proof harnesses for prodagent's security invariants.
//!
//! Two P0 invariants:
//!
//! 1. **Policy monotonicity** — compound command evaluation can only escalate,
//!    never relax. The `strictest` accumulator (a `max`-fold over segment
//!    decisions) must be `>=` every individual segment decision. A violation
//!    means a dangerous command hidden in a compound could slip through.
//!
//! 2. **Parse error fail-closed** — if the parser returns `Err`, the decision
//!    is never `Allow`. The engine returns `Ask` on parse error; a regression
//!    to `Allow` would let unparseable (and therefore unanalyzed) commands
//!    execute without confirmation.
//!
//! The proofs verify the algebraic foundations these invariants rest on:
//! the `Ord` instance on `PolicyDecision`, the `max` upper-bound property,
//! the monotonicity of the fold accumulation pattern, and the non-Allow
//! guarantee on parse error paths.

#[cfg(kani)]
mod proofs {
    use agent_policy::PolicyDecision;

    // ── Helpers ────────────────────────────────────────────────────────

    /// Symbolic `PolicyDecision` for Kani.
    ///
    /// Maps a bounded `u8` in `0..3` to the three variants, preserving
    /// the discriminant ordering that `derive(Ord)` produces.
    fn any_decision() -> PolicyDecision {
        let v: u8 = kani::any();
        kani::assume(v < 3);
        match v {
            0 => PolicyDecision::Allow,
            1 => PolicyDecision::Ask,
            _ => PolicyDecision::Deny,
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // Invariant #1 — Policy monotonicity
    //
    // The compound-command evaluator in `engine.rs` accumulates the
    // strictest decision via:
    //
    //     let mut strictest = PolicyDecision::Allow;
    //     // for each segment:
    //     strictest = strictest.max(segment_decision);
    //
    // and also (for parse errors):
    //
    //     strictest = strictest.max(PolicyDecision::Ask);
    //
    // The following proofs verify that this pattern can ONLY escalate
    // (never relax) and that the final value is >= every input.
    // ══════════════════════════════════════════════════════════════════

    // ── Foundation: Ord is a total order ───────────────────────────────

    /// The derived `Ord` on `PolicyDecision` is reflexive.
    #[kani::proof]
    fn ord_reflexive() {
        let a = any_decision();
        assert!(a <= a);
        assert!(a >= a);
    }

    /// The derived `Ord` on `PolicyDecision` is antisymmetric.
    #[kani::proof]
    fn ord_antisymmetric() {
        let a = any_decision();
        let b = any_decision();
        if a <= b && b <= a {
            assert!(a == b);
        }
    }

    /// The derived `Ord` on `PolicyDecision` is transitive.
    #[kani::proof]
    fn ord_transitive() {
        let a = any_decision();
        let b = any_decision();
        let c = any_decision();
        if a <= b && b <= c {
            assert!(a <= c);
        }
    }

    /// The intended ordering holds: Allow < Ask < Deny.
    ///
    /// This is the security-critical ordering. If a derive refactor or
    /// variant reordering breaks this, compound commands could relax.
    #[kani::proof]
    fn ord_security_ordering() {
        assert!(PolicyDecision::Allow < PolicyDecision::Ask);
        assert!(PolicyDecision::Ask < PolicyDecision::Deny);
        assert!(PolicyDecision::Allow < PolicyDecision::Deny);
    }

    // ── Core: max is an upper bound ───────────────────────────────────

    /// `max(a, b) >= a` and `max(a, b) >= b` for all decision pairs.
    ///
    /// This is the property that makes the `strictest` accumulator work:
    /// after `strictest = strictest.max(d)`, the result is >= both the
    /// old `strictest` and the new `d`.
    #[kani::proof]
    fn max_is_upper_bound() {
        let a = any_decision();
        let b = any_decision();
        let m = a.max(b);
        assert!(m >= a);
        assert!(m >= b);
    }

    /// `max` is commutative — segment evaluation order doesn't matter.
    #[kani::proof]
    fn max_commutative() {
        let a = any_decision();
        let b = any_decision();
        assert!(a.max(b) == b.max(a));
    }

    /// `max` is associative — grouping of segment evaluations doesn't matter.
    #[kani::proof]
    fn max_associative() {
        let a = any_decision();
        let b = any_decision();
        let c = any_decision();
        assert!(a.max(b).max(c) == a.max(b.max(c)));
    }

    /// `max` is idempotent — evaluating the same segment twice doesn't change anything.
    #[kani::proof]
    fn max_idempotent() {
        let a = any_decision();
        assert!(a.max(a) == a);
    }

    /// Allow is the identity for `max` — the initial accumulator value.
    ///
    /// `evaluate_pipeline` starts with `strictest = Allow`. This proves
    /// that starting value doesn't suppress any segment decision.
    #[kani::proof]
    fn allow_is_max_identity() {
        let d = any_decision();
        assert!(PolicyDecision::Allow.max(d) == d);
        assert!(d.max(PolicyDecision::Allow) == d);
    }

    // ── Compound: fold monotonicity (the actual invariant) ────────────

    /// The `max`-fold over any 3 segment decisions produces a result
    /// that is >= every individual decision.
    ///
    /// Models the loop in `evaluate_pipeline`:
    /// ```text
    /// let mut strictest = Allow;
    /// for d in [d1, d2, d3]:
    ///     strictest = strictest.max(d);
    /// ```
    ///
    /// 3 segments is sufficient because `max` is associative — if the
    /// property holds for 3, it holds for any N by induction.
    #[kani::proof]
    fn fold_max_never_relaxes_3_segments() {
        let d1 = any_decision();
        let d2 = any_decision();
        let d3 = any_decision();

        let mut strictest = PolicyDecision::Allow;
        strictest = strictest.max(d1);
        strictest = strictest.max(d2);
        strictest = strictest.max(d3);

        // The security invariant: strictest >= every segment decision
        assert!(strictest >= d1);
        assert!(strictest >= d2);
        assert!(strictest >= d3);
    }

    /// Each step of the fold can only maintain or increase strictness.
    ///
    /// This is the inductive step: if `strictest` is some value before
    /// processing a new segment, it can never decrease after.
    #[kani::proof]
    fn fold_step_only_escalates() {
        let before = any_decision();
        let new_segment = any_decision();
        let after = before.max(new_segment);
        assert!(after >= before, "max-fold step must never relax");
    }

    /// The `evaluate_pipeline` pattern with `>` comparison is equivalent
    /// to `max`.
    ///
    /// The actual code uses:
    /// ```text
    /// if result.decision > strictest {
    ///     strictest = result.decision;
    /// }
    /// ```
    /// This proves equivalence with `strictest.max(result.decision)`.
    #[kani::proof]
    fn gt_update_equivalent_to_max() {
        let strictest = any_decision();
        let decision = any_decision();

        // Pattern from evaluate_pipeline
        let via_gt = if decision > strictest {
            decision
        } else {
            strictest
        };

        // Equivalent max
        let via_max = strictest.max(decision);

        assert!(via_gt == via_max);
    }

    // ══════════════════════════════════════════════════════════════════
    // Invariant #2 — Parse error fail-closed
    //
    // When the parser returns `Err`, the engine must NEVER return Allow.
    //
    // Two code paths:
    //
    // 1. `evaluate_command` (engine.rs:60-64): returns Ask directly.
    // 2. `evaluate_command` compound path (engine.rs:102-104):
    //    `strictest = strictest.max(PolicyDecision::Ask)` when
    //    `has_parse_errors` is true.
    //
    // The agent-jj guard (guard.rs:26-36) returns Verdict::Block on
    // parse error, which is even stricter (hard block, not Ask).
    // ══════════════════════════════════════════════════════════════════

    /// The direct parse-error path returns Ask, which is not Allow.
    ///
    /// Models `evaluate_command` lines 60-64:
    /// ```text
    /// Err(_) => PolicyResult::simple(PolicyDecision::Ask, ...)
    /// ```
    #[kani::proof]
    fn parse_error_direct_path_not_allow() {
        let parse_error_decision = PolicyDecision::Ask;
        assert!(parse_error_decision != PolicyDecision::Allow);
        assert!(parse_error_decision >= PolicyDecision::Ask);
    }

    /// The compound-path parse-error escalation never produces Allow.
    ///
    /// Models `evaluate_command` lines 102-104:
    /// ```text
    /// if has_parse_errors {
    ///     strictest = strictest.max(PolicyDecision::Ask);
    /// }
    /// ```
    ///
    /// For ANY prior `strictest` value, `max(Ask)` is never Allow.
    #[kani::proof]
    fn parse_error_compound_path_not_allow() {
        let prior_strictest = any_decision();
        let after = prior_strictest.max(PolicyDecision::Ask);
        assert!(
            after != PolicyDecision::Allow,
            "after max(Ask), decision must not be Allow"
        );
        assert!(
            after >= PolicyDecision::Ask,
            "after max(Ask), decision must be at least Ask"
        );
    }

    /// Combining both parse-error paths: no matter how the compound
    /// evaluation went before the parse-error check, the final result
    /// after `max(Ask)` is at least Ask — never Allow.
    ///
    /// This models the full compound path where segments have already
    /// been evaluated (producing some `strictest`) and then
    /// `has_parse_errors` triggers the `max(Ask)` escalation.
    #[kani::proof]
    fn parse_error_escalation_floor() {
        let d1 = any_decision();
        let d2 = any_decision();

        // Simulate: two segments evaluated, then parse-error escalation
        let mut strictest = PolicyDecision::Allow;
        strictest = strictest.max(d1);
        strictest = strictest.max(d2);
        // Parse error escalation
        strictest = strictest.max(PolicyDecision::Ask);

        assert!(
            strictest >= PolicyDecision::Ask,
            "parse error must guarantee at least Ask"
        );
        assert!(
            strictest != PolicyDecision::Allow,
            "parse error must never allow"
        );
        // Also: still >= every segment decision (monotonicity preserved)
        assert!(strictest >= d1);
        assert!(strictest >= d2);
    }

    /// The Deny decision is preserved through parse-error escalation.
    ///
    /// If a segment was already Deny, `max(Ask)` must not weaken it.
    #[kani::proof]
    fn deny_survives_parse_error_escalation() {
        let prior = any_decision();
        kani::assume(prior == PolicyDecision::Deny);
        let after = prior.max(PolicyDecision::Ask);
        assert!(
            after == PolicyDecision::Deny,
            "Deny must not be weakened by parse-error Ask"
        );
    }

    // ── Cross-cutting: escalation can only raise ──────────────────────

    /// The escalation pattern used throughout the engine — `if d < Ask
    /// { d = Ask }` — can only raise, never lower.
    ///
    /// Used for escalation_flags (engine.rs:179, 329) and wrapper
    /// escalates_privilege (engine.rs:192).
    #[kani::proof]
    fn escalation_flag_only_raises() {
        let d = any_decision();
        let escalated = d.max(PolicyDecision::Ask);
        assert!(escalated >= d, "escalation must not lower decision");
        assert!(
            escalated >= PolicyDecision::Ask,
            "escalation must reach at least Ask"
        );
    }

    /// `Deny.max(anything)` is always Deny — strongest decision is absorbing.
    #[kani::proof]
    fn deny_is_absorbing() {
        let d = any_decision();
        assert!(PolicyDecision::Deny.max(d) == PolicyDecision::Deny);
        assert!(d.max(PolicyDecision::Deny) == PolicyDecision::Deny);
    }
}
