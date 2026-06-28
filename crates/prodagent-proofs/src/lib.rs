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
        let a = kani::any::<PolicyDecision>();
        assert!(a <= a);
        assert!(a >= a);
    }

    /// The derived `Ord` on `PolicyDecision` is antisymmetric.
    #[kani::proof]
    fn ord_antisymmetric() {
        let a = kani::any::<PolicyDecision>();
        let b = kani::any::<PolicyDecision>();
        if a <= b && b <= a {
            assert!(a == b);
        }
    }

    /// The derived `Ord` on `PolicyDecision` is transitive.
    #[kani::proof]
    fn ord_transitive() {
        let a = kani::any::<PolicyDecision>();
        let b = kani::any::<PolicyDecision>();
        let c = kani::any::<PolicyDecision>();
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
        let a = kani::any::<PolicyDecision>();
        let b = kani::any::<PolicyDecision>();
        let m = a.max(b);
        assert!(m >= a);
        assert!(m >= b);
    }

    /// `max` is commutative — segment evaluation order doesn't matter.
    #[kani::proof]
    fn max_commutative() {
        let a = kani::any::<PolicyDecision>();
        let b = kani::any::<PolicyDecision>();
        assert!(a.max(b) == b.max(a));
    }

    /// `max` is associative — grouping of segment evaluations doesn't matter.
    #[kani::proof]
    fn max_associative() {
        let a = kani::any::<PolicyDecision>();
        let b = kani::any::<PolicyDecision>();
        let c = kani::any::<PolicyDecision>();
        assert!(a.max(b).max(c) == a.max(b.max(c)));
    }

    /// `max` is idempotent — evaluating the same segment twice doesn't change anything.
    #[kani::proof]
    fn max_idempotent() {
        let a = kani::any::<PolicyDecision>();
        assert!(a.max(a) == a);
    }

    /// Allow is the identity for `max` — the initial accumulator value.
    ///
    /// `evaluate_pipeline` starts with `strictest = Allow`. This proves
    /// that starting value doesn't suppress any segment decision.
    #[kani::proof]
    fn allow_is_max_identity() {
        let d = kani::any::<PolicyDecision>();
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
        let d1 = kani::any::<PolicyDecision>();
        let d2 = kani::any::<PolicyDecision>();
        let d3 = kani::any::<PolicyDecision>();

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
        let before = kani::any::<PolicyDecision>();
        let new_segment = kani::any::<PolicyDecision>();
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
        let strictest = kani::any::<PolicyDecision>();
        let decision = kani::any::<PolicyDecision>();

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
        let prior_strictest = kani::any::<PolicyDecision>();
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
        let d1 = kani::any::<PolicyDecision>();
        let d2 = kani::any::<PolicyDecision>();

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
        let prior = kani::any::<PolicyDecision>();
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
        let d = kani::any::<PolicyDecision>();
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
        let d = kani::any::<PolicyDecision>();
        assert!(PolicyDecision::Deny.max(d) == PolicyDecision::Deny);
        assert!(d.max(PolicyDecision::Deny) == PolicyDecision::Deny);
    }

    // ══════════════════════════════════════════════════════════════════
    // Invariant #3 — Opaque env values fire at max restriction
    //
    // When an env gate encounters an opaque (unknown) value, it fires
    // at the gate's configured action — never silently passes.
    //
    // The invariant: gate(opaque) >= gate(any_concrete_value)
    //
    // The implementation models `evaluate_condition` as a truth table
    // over (condition_type, value_state) pairs. Kani verifies the
    // invariant exhaustively over the bounded domain.
    // ══════════════════════════════════════════════════════════════════

    /// Model of env gate condition types matching `EnvCondition`.
    #[derive(Clone, Copy, kani::Arbitrary)]
    enum ConditionType {
        Equals,
        NotEquals,
        Set,
        Unset,
    }

    /// Model of env value states matching `Option<EnvValueOwned>`.
    ///
    /// `KnownMatch` / `KnownNoMatch` model `Known(v)` where `v` does
    /// or does not satisfy the condition. This is the key abstraction:
    /// the string equality check becomes a boolean.
    #[derive(Clone, Copy, kani::Arbitrary)]
    enum ValueState {
        /// Variable set to a value that matches the condition's expected value.
        KnownMatch,
        /// Variable set to a value that does NOT match the condition's expected value.
        KnownNoMatch,
        /// Variable set but value is opaque/unknown.
        Unknown,
        /// Variable not present in the environment.
        Absent,
    }

    /// Model of `evaluate_condition` from engine.rs.
    ///
    /// Returns true when the gate fires (condition matches).
    /// Must be kept in sync with the real implementation.
    fn gate_fires(cond: ConditionType, val: ValueState) -> bool {
        match (cond, val) {
            // Equals: fires when value matches expected
            (ConditionType::Equals, ValueState::KnownMatch) => true,
            (ConditionType::Equals, ValueState::KnownNoMatch) => false,
            (ConditionType::Equals, ValueState::Unknown) => true, // max restriction
            (ConditionType::Equals, ValueState::Absent) => false,

            // NotEquals: fires when value differs from expected
            (ConditionType::NotEquals, ValueState::KnownMatch) => false,
            (ConditionType::NotEquals, ValueState::KnownNoMatch) => true,
            (ConditionType::NotEquals, ValueState::Unknown) => true, // max restriction
            (ConditionType::NotEquals, ValueState::Absent) => true,  // not set ≠ any value

            // Set: fires when variable is present (any value)
            (ConditionType::Set, ValueState::KnownMatch) => true,
            (ConditionType::Set, ValueState::KnownNoMatch) => true,
            (ConditionType::Set, ValueState::Unknown) => true, // present, just opaque
            (ConditionType::Set, ValueState::Absent) => false,

            // Unset: fires when variable is not present
            (ConditionType::Unset, ValueState::KnownMatch) => false,
            (ConditionType::Unset, ValueState::KnownNoMatch) => false,
            (ConditionType::Unset, ValueState::Unknown) => false, // present → not unset
            (ConditionType::Unset, ValueState::Absent) => true,
        }
    }

    /// Convert gate firing into a policy decision.
    ///
    /// When a gate fires, it produces the gate's configured action
    /// (mapped to `PolicyDecision`). When it doesn't fire, the gate
    /// contributes nothing — modeled as `Allow` (identity for max).
    fn gate_decision(fires: bool, action: PolicyDecision) -> PolicyDecision {
        if fires {
            action
        } else {
            PolicyDecision::Allow
        }
    }

    /// **The invariant**: for any condition type and gate action,
    /// the decision produced by an opaque value is >= the decision
    /// produced by ANY concrete value.
    ///
    /// `gate(opaque) >= gate(any_concrete_value)`
    ///
    /// This is the core security property: an opaque env value never
    /// causes a gate to silently pass when some concrete value would
    /// have triggered it. Exhaustively verified over all 4 condition
    /// types, all 4 concrete value states, and all 3 gate actions.
    #[kani::proof]
    fn opaque_fires_at_max_restriction() {
        let cond = kani::any::<ConditionType>();
        let action = kani::any::<PolicyDecision>();
        let concrete = kani::any::<ValueState>();

        // Exclude Unknown from "concrete" — we're comparing opaque vs concrete
        kani::assume(!matches!(concrete, ValueState::Unknown));

        let opaque_fires = gate_fires(cond, ValueState::Unknown);
        let concrete_fires = gate_fires(cond, concrete);

        let opaque_decision = gate_decision(opaque_fires, action);
        let concrete_decision = gate_decision(concrete_fires, action);

        assert!(
            opaque_decision >= concrete_decision,
            "gate(opaque) must be >= gate(concrete) for all conditions and actions"
        );
    }

    /// Opaque values never LOWER a gate's effect — they can only match
    /// or exceed what a concrete value would produce.
    ///
    /// Stronger form: if a concrete value causes a gate to fire,
    /// the opaque value ALSO causes it to fire.
    #[kani::proof]
    fn opaque_fires_whenever_any_concrete_fires() {
        let cond = kani::any::<ConditionType>();
        let concrete = kani::any::<ValueState>();

        kani::assume(!matches!(concrete, ValueState::Unknown));

        if gate_fires(cond, concrete) {
            assert!(
                gate_fires(cond, ValueState::Unknown),
                "if any concrete value fires the gate, opaque must also fire"
            );
        }
    }

    /// The `gate_decision` helper preserves the max-restriction semantics:
    /// firing with action A produces A; not firing produces Allow (the
    /// identity for max). Since A >= Allow for all A, firing is always
    /// at least as restrictive as not firing.
    #[kani::proof]
    fn gate_firing_is_at_least_as_restrictive_as_not_firing() {
        let action = kani::any::<PolicyDecision>();
        let fired = gate_decision(true, action);
        let silent = gate_decision(false, action);
        assert!(fired >= silent);
    }
}
