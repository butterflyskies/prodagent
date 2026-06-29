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
    use prodagent_policy::PolicyDecision;

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
    // Invariant #3 — Opaque env values respect the configured ceiling
    //
    // When an env gate encounters an opaque (unknown) value on a
    // value-dependent condition (Equals/NotEquals), the decision is
    // the configured `opaque_env_ceiling` — not the gate's own action.
    // Structural conditions (Set/Unset) are deterministic for opaque
    // values and always use the gate's own action.
    //
    // The invariant: for value-dependent gates,
    //   gate(opaque, ceiling) == ceiling
    // For structural gates:
    //   gate(opaque) == gate(concrete_match)
    //
    // The implementation models `evaluate_condition` + the ceiling
    // override as a truth table. Kani verifies exhaustively.
    // ══════════════════════════════════════════════════════════════════

    /// Model of env gate condition types matching `EnvCondition`.
    #[derive(Clone, Copy, kani::Arbitrary)]
    enum ConditionType {
        Equals,
        NotEquals,
        Set,
        Unset,
    }

    /// Whether a condition is value-dependent (Equals/NotEquals) or
    /// structural (Set/Unset). Only value-dependent gates use the
    /// ceiling for opaque values.
    fn is_value_dependent(cond: ConditionType) -> bool {
        matches!(cond, ConditionType::Equals | ConditionType::NotEquals)
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
            (ConditionType::Equals, ValueState::Unknown) => true, // opaque: fires
            (ConditionType::Equals, ValueState::Absent) => false,

            // NotEquals: fires when value differs from expected
            (ConditionType::NotEquals, ValueState::KnownMatch) => false,
            (ConditionType::NotEquals, ValueState::KnownNoMatch) => true,
            (ConditionType::NotEquals, ValueState::Unknown) => true, // opaque: fires
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

    /// Convert gate firing into a policy decision, accounting for the
    /// opaque_env_ceiling on value-dependent conditions.
    ///
    /// When a gate fires:
    /// - Value-dependent (Equals/NotEquals) with opaque value → `ceiling`
    /// - Structural (Set/Unset) or concrete value → gate's own `action`
    /// When a gate doesn't fire → `Allow` (identity for max).
    fn gate_decision(
        fires: bool,
        action: PolicyDecision,
        val: ValueState,
        cond: ConditionType,
        ceiling: PolicyDecision,
    ) -> PolicyDecision {
        if fires {
            if matches!(val, ValueState::Unknown) && is_value_dependent(cond) {
                ceiling
            } else {
                action
            }
        } else {
            PolicyDecision::Allow
        }
    }

    /// **The invariant**: for value-dependent gates, the decision
    /// produced by an opaque value equals the configured ceiling.
    ///
    /// `gate(opaque, ceiling) == ceiling` for Equals/NotEquals.
    ///
    /// This is the core configurability property: the engine respects
    /// the user's chosen ceiling for opaque values on value-dependent
    /// gates. Exhaustively verified over all condition types and all
    /// ceiling values.
    #[kani::proof]
    fn opaque_respects_configured_ceiling() {
        let cond = kani::any::<ConditionType>();
        let action = kani::any::<PolicyDecision>();
        let ceiling = kani::any::<PolicyDecision>();

        let opaque_fires = gate_fires(cond, ValueState::Unknown);
        let opaque_decision =
            gate_decision(opaque_fires, action, ValueState::Unknown, cond, ceiling);

        if is_value_dependent(cond) {
            // Value-dependent gates with opaque: decision == ceiling
            // (because opaque always fires for Equals/NotEquals)
            assert!(
                opaque_decision == ceiling,
                "value-dependent gate(opaque) must equal configured ceiling"
            );
        } else {
            // Structural gates: opaque uses gate's action (unchanged)
            let expected =
                gate_decision(opaque_fires, action, ValueState::KnownMatch, cond, ceiling);
            assert!(
                opaque_decision == expected,
                "structural gate(opaque) must use gate's own action"
            );
        }
    }

    /// Opaque values never LOWER a gate's effect relative to the ceiling.
    ///
    /// For any concrete value, `gate(opaque, ceiling) >= ceiling` for
    /// value-dependent gates. Combined with `max` accumulation, this
    /// ensures the ceiling is respected.
    #[kani::proof]
    fn opaque_at_least_ceiling_for_value_dependent() {
        let cond = kani::any::<ConditionType>();
        let ceiling = kani::any::<PolicyDecision>();
        let action = kani::any::<PolicyDecision>();

        kani::assume(is_value_dependent(cond));

        let opaque_fires = gate_fires(cond, ValueState::Unknown);
        let opaque_decision =
            gate_decision(opaque_fires, action, ValueState::Unknown, cond, ceiling);

        assert!(
            opaque_decision >= ceiling,
            "opaque value on value-dependent gate must be >= ceiling"
        );
    }

    /// Opaque values still fire whenever any concrete value fires
    /// (the gate_fires truth table is unchanged — ceiling only affects
    /// the DECISION, not WHETHER the gate fires).
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

    /// Structural gates are unaffected by the ceiling — their decision
    /// for opaque values equals their decision for concrete values
    /// (when the gate fires in both cases).
    #[kani::proof]
    fn structural_gates_ignore_ceiling() {
        let cond = kani::any::<ConditionType>();
        let action = kani::any::<PolicyDecision>();
        let ceiling = kani::any::<PolicyDecision>();

        kani::assume(!is_value_dependent(cond));

        let opaque_decision = gate_decision(
            gate_fires(cond, ValueState::Unknown),
            action,
            ValueState::Unknown,
            cond,
            ceiling,
        );
        let concrete_decision = gate_decision(
            gate_fires(cond, ValueState::KnownMatch),
            action,
            ValueState::KnownMatch,
            cond,
            ceiling,
        );

        // For Set: both fire → both get `action`
        // For Unset: opaque doesn't fire (Allow), concrete doesn't fire (Allow)
        // Either way, ceiling is irrelevant.
        assert!(
            opaque_decision == concrete_decision,
            "structural gate must produce same decision for opaque and concrete"
        );
    }

    /// The `gate_decision` helper preserves monotonicity: firing with
    /// any decision is always at least as restrictive as not firing.
    #[kani::proof]
    fn gate_firing_is_at_least_as_restrictive_as_not_firing() {
        let action = kani::any::<PolicyDecision>();
        let cond = kani::any::<ConditionType>();
        let ceiling = kani::any::<PolicyDecision>();
        let val = kani::any::<ValueState>();

        let fired = gate_decision(true, action, val, cond, ceiling);
        let silent = gate_decision(false, action, val, cond, ceiling);
        assert!(fired >= silent);
    }

    // ══════════════════════════════════════════════════════════════════
    // Invariant #4 — Per-path evaluation with deny-wins aggregation
    //
    // Path-scoped rules evaluate each affected path independently
    // through a tiered evaluation:
    //
    //   Tier 1: Command+path rule matches → use its decision (done).
    //   Tier 2: No command+path match → evaluate path-only and
    //           command-only independently, take max (strictest).
    //   Tier 3: No path rule matched → command-level default.
    //
    // Across all paths the strictest decision wins. The security
    // invariant: if ANY path's per-path decision is Deny, the
    // aggregate is Deny — a dangerous path cannot be hidden among
    // safe ones in a multi-path command.
    //
    // The proofs model the per-path tiered lookup as a function
    // from symbolic booleans (does the path match each tier?) to
    // a decision, then verify the max-fold aggregation.
    // ══════════════════════════════════════════════════════════════════

    /// Model of the per-path tiered evaluation.
    ///
    /// For a single path:
    /// - If a command+path rule matches → use its decision
    /// - Else if a path-only rule matches → max(path_decision, command_default)
    /// - Else → command_default
    fn per_path_decision(
        cmd_path_matches: bool,
        cmd_path_decision: PolicyDecision,
        path_only_matches: bool,
        path_only_decision: PolicyDecision,
        command_default: PolicyDecision,
    ) -> PolicyDecision {
        if cmd_path_matches {
            cmd_path_decision
        } else if path_only_matches {
            path_only_decision.max(command_default)
        } else {
            command_default
        }
    }

    /// If any per-path decision is Deny, the max-fold aggregate is Deny.
    ///
    /// Models a 3-path command where each path independently evaluates
    /// through the tiered hierarchy. Proves the core security property:
    /// deny is absorbing across the path aggregation.
    #[kani::proof]
    fn path_deny_absorbing_in_aggregate() {
        // 3 paths, each with independent tier matches
        let cp1: bool = kani::any();
        let cp1_d: PolicyDecision = kani::any();
        let po1: bool = kani::any();
        let po1_d: PolicyDecision = kani::any();

        let cp2: bool = kani::any();
        let cp2_d: PolicyDecision = kani::any();
        let po2: bool = kani::any();
        let po2_d: PolicyDecision = kani::any();

        let cp3: bool = kani::any();
        let cp3_d: PolicyDecision = kani::any();
        let po3: bool = kani::any();
        let po3_d: PolicyDecision = kani::any();

        let default: PolicyDecision = kani::any();

        let d1 = per_path_decision(cp1, cp1_d, po1, po1_d, default);
        let d2 = per_path_decision(cp2, cp2_d, po2, po2_d, default);
        let d3 = per_path_decision(cp3, cp3_d, po3, po3_d, default);

        let aggregate = d1.max(d2).max(d3);

        // Core invariant: if any per-path decision is Deny, aggregate is Deny
        if d1 == PolicyDecision::Deny || d2 == PolicyDecision::Deny || d3 == PolicyDecision::Deny {
            assert!(
                aggregate == PolicyDecision::Deny,
                "deny in any path must produce deny in aggregate"
            );
        }
    }

    /// The aggregate is always >= every individual per-path decision.
    ///
    /// Monotonicity of the max-fold: the aggregate never relaxes below
    /// any single path's decision.
    #[kani::proof]
    fn path_aggregate_never_relaxes() {
        let cp1: bool = kani::any();
        let cp1_d: PolicyDecision = kani::any();
        let po1: bool = kani::any();
        let po1_d: PolicyDecision = kani::any();

        let cp2: bool = kani::any();
        let cp2_d: PolicyDecision = kani::any();
        let po2: bool = kani::any();
        let po2_d: PolicyDecision = kani::any();

        let default: PolicyDecision = kani::any();

        let d1 = per_path_decision(cp1, cp1_d, po1, po1_d, default);
        let d2 = per_path_decision(cp2, cp2_d, po2, po2_d, default);

        let aggregate = d1.max(d2);

        assert!(aggregate >= d1, "aggregate must be >= path 1 decision");
        assert!(aggregate >= d2, "aggregate must be >= path 2 decision");
    }

    /// Command+path rules are the highest specificity tier: when one
    /// matches, neither path-only rules nor the command default can
    /// override it for that path.
    #[kani::proof]
    fn cmd_path_is_highest_specificity() {
        let cp_decision: PolicyDecision = kani::any();
        let po_decision: PolicyDecision = kani::any();
        let default: PolicyDecision = kani::any();

        // When command+path matches, result equals cp_decision
        // regardless of path-only and default.
        let result_both = per_path_decision(true, cp_decision, true, po_decision, default);
        let result_cp_only = per_path_decision(true, cp_decision, false, po_decision, default);

        assert!(
            result_both == cp_decision,
            "command+path must win even when path-only also matches"
        );
        assert!(
            result_cp_only == cp_decision,
            "command+path must win when path-only does not match"
        );
    }

    /// Tier 2 (path-only match) is at least as strict as either
    /// the path-only decision or the command default alone.
    ///
    /// This is the max composition property: when tier 2 fires,
    /// the result is `max(path_decision, command_default) >= both`.
    #[kani::proof]
    fn tier2_is_at_least_as_strict_as_components() {
        let po_decision: PolicyDecision = kani::any();
        let default: PolicyDecision = kani::any();

        // Tier 2 fires when command+path doesn't match but path-only does
        let result = per_path_decision(false, PolicyDecision::Allow, true, po_decision, default);

        assert!(
            result >= po_decision,
            "tier 2 must be >= path-only decision"
        );
        assert!(result >= default, "tier 2 must be >= command default");
    }

    /// Adding more paths to a multi-path command can only maintain or
    /// increase the aggregate strictness — never relax it.
    ///
    /// This is the inductive step for N-path commands: if the aggregate
    /// of N paths is `current`, adding path N+1 can only produce
    /// `current.max(d_new) >= current`.
    #[kani::proof]
    fn adding_path_only_escalates() {
        let current_aggregate: PolicyDecision = kani::any();

        let cp_match: bool = kani::any();
        let cp_d: PolicyDecision = kani::any();
        let po_match: bool = kani::any();
        let po_d: PolicyDecision = kani::any();
        let default: PolicyDecision = kani::any();

        let new_path_decision = per_path_decision(cp_match, cp_d, po_match, po_d, default);
        let new_aggregate = current_aggregate.max(new_path_decision);

        assert!(
            new_aggregate >= current_aggregate,
            "adding a path must not relax the aggregate"
        );
    }

    /// The tiered evaluation is a total function: for every
    /// combination of match booleans, every path gets a decision.
    ///
    /// The result always comes from one of the three sources:
    /// the command+path decision, the path-only decision (possibly
    /// raised by command_default), or the command_default alone.
    #[kani::proof]
    fn evaluation_is_total() {
        let cp_match: bool = kani::any();
        let cp_d: PolicyDecision = kani::any();
        let po_match: bool = kani::any();
        let po_d: PolicyDecision = kani::any();
        let default: PolicyDecision = kani::any();

        let result = per_path_decision(cp_match, cp_d, po_match, po_d, default);

        // Result must be derived from the inputs — it's either:
        // cp_d, max(po_d, default), or default
        let possible_cp = cp_d;
        let possible_tier2 = po_d.max(default);
        let possible_tier3 = default;

        assert!(
            result == possible_cp || result == possible_tier2 || result == possible_tier3,
            "result must come from one of the three tiers"
        );
    }
}
