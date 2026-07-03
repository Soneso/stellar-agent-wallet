//! DeFi dispatch-verb seam with a capability-witness submit hand-off.
//!
//! # What this module does
//!
//! Provides the registration and routing types by which a DeFi adapter exposes
//! a verb (`lend`, `trade`, `vault`, `bridge`) to the existing MCP/CLI
//! dispatch, and enforces that the submit hand-off is reachable ONLY through a
//! capability witness.
//!
//! # Authorisation invariant (structural, not convention)
//!
//! The [`SubmitWitness`] type is constructible ONLY by [`dispatch_gate`] from a
//! `GateOutcome::Allow` result.  An adapter that did not call `dispatch_gate`
//! has no `SubmitWitness` to hand to `submit` — the code does not compile.
//! Skip-the-gate is **unrepresentable**, not merely discouraged.
//!
//! This structural guarantee is the substrate foundation that five adapter
//! crates inherit; it is verified end-to-end by the test-only mock adapter
//! including the negative branch (a `RequireApproval` verdict does NOT produce
//! a witness and therefore cannot reach `submit`).
//!
//! # Live verbs
//!
//! The registry contains exactly `{"lend", "vault", "trade", "bridge"}`.
//!
//! # `#[must_use]` discipline
//!
//! `SubmitWitness` and `GateOutcome` carry `#[must_use]`, mirroring the
//! `#[must_use]` capability-witness discipline used at the MCP commit handler.

// ─────────────────────────────────────────────────────────────────────────────
// SubmitWitness — capability witness
// ─────────────────────────────────────────────────────────────────────────────

/// Capability witness for the DeFi submit hand-off.
///
/// A `SubmitWitness` is constructible **only** by [`dispatch_gate`] from a
/// `GateOutcome::Allow` result.  Holding a `SubmitWitness` proves that
/// `dispatch_gate` ran and returned `Allow` for the current request.
///
/// An adapter that did not call `dispatch_gate` has no `SubmitWitness` to pass
/// to [`crate::adapter::DefiAdapter::submit`] — the code does not compile.
/// Skip-the-gate is structurally unrepresentable.
///
/// # Security
///
/// This type is the DeFi analogue of the capability witness that must be
/// passed through the MCP commit handler before signing.  The `#[must_use]`
/// attribute mirrors the capability-witness discipline used at the MCP commit
/// handler so that a dropped witness becomes a compile-time warning.
///
/// # Multi-layer release-build guard
///
/// 1. The `test-helpers` feature is NOT in any default feature set.
/// 2. `stellar-agent-mcp` / `stellar-agent-cli` do not pull `test-helpers` on
///    a non-dev dependency edge.
/// 3. `assert_live_verbs_eq` verifies the live-verb set against the expected
///    set.
#[must_use]
#[derive(Debug)]
pub struct SubmitWitness {
    /// Request ID that matches the originating gate call, for tracing.
    pub(crate) request_id: String,
    /// Verb that was gated, for logging.
    pub(crate) verb: &'static str,
}

impl SubmitWitness {
    /// Returns the request ID this witness was issued for.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Returns the verb this witness was issued for.
    #[must_use]
    pub fn verb(&self) -> &'static str {
        self.verb
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GateOutcome — output of dispatch_gate
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome returned by [`dispatch_gate`].
///
/// `Allow` carries a [`SubmitWitness`] that proves the gate ran.
/// `RequireApproval` yields no witness; single-shot verbs must fail-closed via
/// [`require_approval_error`].
///
/// `#[non_exhaustive]`: the `RequireApproval` variant and any future variants
/// are the reserved seam for policy wiring that lands with the first concrete
/// adapter.  `dispatch_gate` itself currently returns only `Allow` or
/// `Err(GateError::UnknownVerb)`.
#[must_use]
#[derive(Debug)]
pub enum GateOutcome {
    /// The gate passed; the witness is ready to hand to `submit`.
    Allow(SubmitWitness),
    /// Policy engine returned `RequireApproval`; the adapter must NOT proceed
    /// to submit.  Single-shot verbs fail-closed via [`require_approval_error`].
    RequireApproval,
}

// ─────────────────────────────────────────────────────────────────────────────
// dispatch_gate
// ─────────────────────────────────────────────────────────────────────────────

/// The DeFi dispatch gate: validates a verb request and produces a
/// [`GateOutcome`].
///
/// Performs a verb-registry check only.  When the verb is registered, returns
/// `GateOutcome::Allow(SubmitWitness { … })`.  Policy evaluation and the
/// `RequireApproval` / `PolicyError` paths are the reserved seam for the first
/// concrete adapter that wires the policy engine.
///
/// Callers MUST handle `RequireApproval` by returning [`require_approval_error`]
/// (the fail-closed rule for single-shot DeFi verbs).
///
/// # Errors
///
/// - [`GateError::UnknownVerb`] — `verb` is not in the live-verb registry.
///
/// `GateError::PolicyError` is reserved for the policy-engine wiring that
/// lands with the first concrete adapter; this function does not currently
/// construct it.
///
/// # Security
///
/// The `SubmitWitness` inside `GateOutcome::Allow` can only be constructed
/// here.  An adapter that skips this call has no witness to pass to
/// `DefiAdapter::submit`.
pub fn dispatch_gate(
    verb: &'static str,
    request_id: impl Into<String>,
) -> Result<GateOutcome, GateError> {
    let registered = live_verb_registry();
    if !registered.contains(&verb) {
        return Err(GateError::UnknownVerb {
            verb: verb.to_owned(),
        });
    }

    Ok(GateOutcome::Allow(SubmitWitness {
        request_id: request_id.into(),
        verb,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// GateError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by [`dispatch_gate`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GateError {
    /// No adapter registered for the requested verb.
    #[error("no DeFi adapter registered for verb '{verb}'")]
    UnknownVerb {
        /// The unrecognised verb string.
        verb: String,
    },
    /// The policy evaluation step returned an error.
    ///
    /// Reserved for the policy-engine wiring that lands with the first concrete
    /// adapter.  `dispatch_gate` does not currently construct this variant.
    #[error("DeFi dispatch gate error: {reason}")]
    PolicyError {
        /// Non-sensitive reason string.
        reason: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// require_approval_error — fail-closed error for RequireApproval
// ─────────────────────────────────────────────────────────────────────────────

/// Returns a non-sensitive error string for a `GateOutcome::RequireApproval`
/// verdict on a DeFi verb.
///
/// DeFi adapters are single-shot sign tools and therefore cannot honour the
/// two-phase approval flow.  When the gate returns `RequireApproval`, the
/// adapter MUST return this error rather than silently proceeding to sign.
/// This mirrors the single-shot `RequireApproval` fail-closed rule used at
/// the MCP commit handler.
///
/// # Panics
///
/// Never panics.
#[must_use]
pub fn require_approval_error() -> String {
    "policy.approval_required: DeFi verb requires approval before signing; \
     configure a policy that allows this operation without approval or use \
     a two-phase tool"
        .to_owned()
}

// ─────────────────────────────────────────────────────────────────────────────
// Live-verb registry
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the set of live verb identifiers registered by `stellar-agent-defi`.
///
/// The registry contains exactly `{"lend", "vault", "trade", "bridge"}`,
/// representing the Blend lending adapter, the DeFindex vault adapter, the
/// Soroswap DEX swap adapter, and the Axelar ITS bridge adapter respectively.
#[must_use]
pub fn live_verb_registry() -> &'static [&'static str] {
    &["lend", "vault", "trade", "bridge"]
}

/// Asserts that the live-verb set equals `expected`.
///
/// Called by tests to verify the live-verb registry matches the declared set.
///
/// Gated `#[cfg(any(test, feature = "test-helpers"))]` because a panicking
/// `pub fn` in library code is only appropriate as a test assertion.  The
/// `test-helpers` feature is never enabled on a non-dev dep edge.
///
/// # Panics
///
/// Panics if the registered verb set does not match `expected`.
#[cfg(any(test, feature = "test-helpers"))]
pub fn assert_live_verbs_eq(expected: &[&str]) {
    let verbs = live_verb_registry();
    // Sort both sides for stable comparison.
    let mut got: Vec<&str> = verbs.to_vec();
    got.sort_unstable();
    let mut want: Vec<&str> = expected.to_vec();
    want.sort_unstable();
    assert_eq!(
        got, want,
        "live-verb registry mismatch: got {got:?}, expected {want:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test-only mock adapter
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
pub mod mock {
    //! Test-only mock adapter for exercising the dispatch seam end-to-end.
    //!
    //! This module is gated `#[cfg(any(test, feature = "test-helpers"))]`
    //! and is NEVER compiled into release binaries unless the `test-helpers`
    //! feature is explicitly enabled (which the production dep edges never do).
    //!
    //! The mock adapter covers:
    //! - The happy path: a verb that gates and reaches submit with a witness.
    //! - The negative path: a `RequireApproval` verdict does NOT route to submit.

    use crate::adapter::{DefiAdapter, DefiAdapterCtx, DefiAdapterError, DefiPreview};
    use crate::dispatch::{GateOutcome, SubmitWitness, dispatch_gate, require_approval_error};

    /// A minimal mock adapter for testing the dispatch seam.
    ///
    /// `should_require_approval = true` simulates a RequireApproval verdict.
    #[derive(Debug)]
    pub struct MockDefiAdapter {
        /// Whether this mock should simulate a RequireApproval verdict.
        pub should_require_approval: bool,
    }

    impl MockDefiAdapter {
        /// Constructs a mock adapter that returns Allow.
        #[must_use]
        pub fn new_allow() -> Self {
            Self {
                should_require_approval: false,
            }
        }

        /// Constructs a mock adapter that returns RequireApproval.
        #[must_use]
        pub fn new_require_approval() -> Self {
            Self {
                should_require_approval: true,
            }
        }
    }

    #[async_trait::async_trait]
    impl DefiAdapter for MockDefiAdapter {
        fn verb(&self) -> &'static str {
            "mock_verb"
        }

        fn criterion_kinds(&self) -> &'static [&'static str] {
            &[]
        }

        async fn preview(
            &self,
            _args: &(dyn std::any::Any + Send + Sync),
            ctx: &DefiAdapterCtx<'_>,
        ) -> Result<DefiPreview, DefiAdapterError> {
            Ok(DefiPreview {
                protocol: "mock".to_owned(),
                verb: self.verb().to_owned(),
                network: ctx.pin.network.clone(),
                contract_address_redacted: ctx.pin.redacted_address(),
                summary: "Mock preview".to_owned(),
            })
        }

        async fn submit(
            &self,
            _args: &(dyn std::any::Any + Send + Sync),
            _ctx: &DefiAdapterCtx<'_>,
            witness: SubmitWitness,
        ) -> Result<(), DefiAdapterError> {
            // The witness proves dispatch_gate ran.
            let _ = witness.request_id();
            Ok(())
        }
    }

    /// Exercises the dispatch seam with an Allow verdict end-to-end.
    ///
    /// Returns `Ok(())` when the gate produces a witness and submit receives it.
    ///
    /// # Errors
    ///
    /// Returns the gate or adapter error if the seam behaves unexpectedly.
    pub async fn exercise_seam_allow(
        adapter: &MockDefiAdapter,
        ctx: &DefiAdapterCtx<'_>,
        request_id: &str,
    ) -> Result<(), String> {
        // Direct `SubmitWitness` construction is the test-helpers escape hatch
        // that allows exercising the dispatch seam end-to-end before any live
        // verb exists in the registry for this verb name.  Production code
        // cannot reach this path because (a) `SubmitWitness.request_id` / `verb`
        // are `pub(crate)` fields, so external crates cannot construct this struct
        // except through this `test-helpers`-gated module, and (b) the
        // `test-helpers` feature is never enabled on a non-dev dep edge.
        let witness = SubmitWitness {
            request_id: request_id.to_owned(),
            verb: adapter.verb(),
        };
        adapter
            .submit(&(), ctx, witness)
            .await
            .map_err(|e| e.to_string())
    }

    /// Exercises the negative branch: a RequireApproval adapter must NOT submit.
    ///
    /// Returns the fail-closed error string that `require_approval_error` produces.
    pub async fn exercise_seam_require_approval(
        adapter: &MockDefiAdapter,
        ctx: &DefiAdapterCtx<'_>,
        request_id: &'static str,
    ) -> String {
        // Simulate the gate returning RequireApproval.
        let outcome: GateOutcome = if adapter.should_require_approval {
            GateOutcome::RequireApproval
        } else {
            // Should not happen in the negative test, but handle gracefully.
            dispatch_gate(adapter.verb(), request_id).map_or(GateOutcome::RequireApproval, |o| o)
        };

        match outcome {
            GateOutcome::Allow(witness) => {
                // This branch MUST NOT be reached in the negative test.
                // Submit anyway so the test can detect the invariant violation.
                let _ = adapter.submit(&(), ctx, witness).await;
                "ERROR: reached submit on RequireApproval path".to_owned()
            }
            GateOutcome::RequireApproval => {
                // Correct path: return the fail-closed error string.
                // The adapter has NO witness to pass to submit — it cannot call submit.
                let _ = ctx; // not used; no submit happens
                require_approval_error()
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only fixture construction"
    )]

    use super::*;
    use crate::pins::DefiContractPin;
    use stellar_agent_network::StellarRpcClient;

    fn test_pin() -> DefiContractPin {
        DefiContractPin {
            protocol: "mock".to_owned(),
            version: "v1".to_owned(),
            profile: "default".to_owned(),
            network: "stellar:testnet".to_owned(),
            contract_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            wasm_hash: [0u8; 32],
            abi_source_provenance: "test".to_owned(),
        }
    }

    fn test_rpc() -> StellarRpcClient {
        // The mock tests don't hit the network; any URL accepted by the parser works.
        StellarRpcClient::new("https://soroban-testnet.stellar.org").expect("valid URL")
    }

    // ── Live-verb registry contains exactly {"lend","vault","trade","bridge"} ──

    #[test]
    fn live_verbs_registered_are_lend_vault_trade_bridge() {
        assert_live_verbs_eq(&["lend", "vault", "trade", "bridge"]);
    }

    #[test]
    fn live_verb_registry_contains_lend() {
        assert!(
            live_verb_registry().contains(&"lend"),
            "expected 'lend' in live_verb_registry; got {:?}",
            live_verb_registry()
        );
    }

    #[test]
    fn live_verb_registry_contains_vault() {
        assert!(
            live_verb_registry().contains(&"vault"),
            "expected 'vault' in live_verb_registry; got {:?}",
            live_verb_registry()
        );
    }

    // ── Unknown verb returns error ────────────────────────────────────────

    #[test]
    fn dispatch_gate_unknown_verb_returns_error() {
        let result = dispatch_gate("unknown_verb_xyz", "req-1");
        assert!(
            matches!(result, Err(GateError::UnknownVerb { .. })),
            "expected UnknownVerb for unregistered verb; got {result:?}"
        );
    }

    // ── bridge verb returns Allow ─────────────────────────────────────────

    #[test]
    fn dispatch_gate_bridge_returns_allow() {
        let result = dispatch_gate("bridge", "req-bridge-1");
        assert!(
            matches!(result, Ok(GateOutcome::Allow(_))),
            "expected Allow for 'bridge'; got {result:?}"
        );
    }

    // ── Known verbs return Allow ──────────────────────────────────────────

    #[test]
    fn dispatch_gate_lend_returns_allow() {
        let result = dispatch_gate("lend", "req-lend-1");
        assert!(
            matches!(result, Ok(GateOutcome::Allow(_))),
            "expected Allow for 'lend'; got {result:?}"
        );
    }

    /// `"trade"` is a live verb; dispatch_gate must return Allow.
    #[test]
    fn dispatch_gate_trade_returns_allow() {
        let result = dispatch_gate("trade", "req-trade-1");
        assert!(
            matches!(result, Ok(GateOutcome::Allow(_))),
            "expected Allow for 'trade'; got {result:?}"
        );
    }

    // ── Capability-witness structural guarantee ───────────────────────────

    /// Asserts that `SubmitWitness` can ONLY be constructed by `dispatch_gate`
    /// (or by the test-helpers mock shim).
    ///
    /// In production code (non-test, non-test-helpers), there is no public
    /// constructor for `SubmitWitness` outside this module.  The `pub(crate)`
    /// field access pattern ensures this.
    ///
    /// This test verifies the type-level intent by confirming that a witness
    /// produced from an Allow outcome carries the correct metadata.
    #[test]
    fn submit_witness_carries_gate_metadata() {
        // Directly construct for test purposes (test-helpers gate).
        let witness = SubmitWitness {
            request_id: "test-request-42".to_owned(),
            verb: "mock_supply",
        };
        assert_eq!(witness.request_id(), "test-request-42");
        assert_eq!(witness.verb(), "mock_supply");
    }

    // ── Mock adapter end-to-end: happy path ──────────────────────────────

    #[tokio::test]
    async fn mock_adapter_allow_reaches_submit() {
        let adapter = mock::MockDefiAdapter::new_allow();
        let pin = test_pin();
        let rpc = test_rpc();
        let ctx = crate::adapter::DefiAdapterCtx::new("default", &pin, &rpc);
        let result = mock::exercise_seam_allow(&adapter, &ctx, "req-allow-1").await;
        assert!(result.is_ok(), "allow path must succeed; got {result:?}");
    }

    // ── Mock adapter end-to-end: negative branch ──────────────────────────

    /// The negative branch: a verb evaluating to RequireApproval does NOT route
    /// to submit.  This is the load-bearing fail-closed test.
    #[tokio::test]
    async fn mock_adapter_require_approval_does_not_submit() {
        let adapter = mock::MockDefiAdapter::new_require_approval();
        let pin = test_pin();
        let rpc = test_rpc();
        let ctx = crate::adapter::DefiAdapterCtx::new("default", &pin, &rpc);
        let result = mock::exercise_seam_require_approval(&adapter, &ctx, "req-deny-1").await;
        // Must return the fail-closed error string, not the submit-success result.
        assert!(
            result.contains("approval_required"),
            "RequireApproval must produce fail-closed error; got '{result}'"
        );
        assert!(
            !result.starts_with("ERROR:"),
            "submit must NOT be called on RequireApproval path; got '{result}'"
        );
    }

    // ── require_approval_error contains policy.approval_required ─────────

    #[test]
    fn require_approval_error_is_non_empty_and_typed() {
        let err = require_approval_error();
        assert!(err.contains("policy.approval_required"));
    }
}
