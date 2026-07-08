//! DeFi adapter trait surface and typed-preview type.
//!
//! # What this module does
//!
//! Defines the thin substrate that the five DeFi protocol crates implement:
//!
//! - [`DefiPreview`] — the typed, JSON-default, human-renderable preview
//!   produced at approval.  No raw-vector or opaque-calldata signing is
//!   representable; this is a type-level guarantee (no `raw: Vec<Val>` field,
//!   no `extra: serde_json::Value` escape hatch).
//!
//! - [`DefiAdapterCtx`] — the context handle passed to adapters at preview
//!   time.  Carries the active profile name, the resolved `DefiContractPin` for
//!   the verb, and an RPC accessor.  `#[non_exhaustive]` so further fields grow
//!   additively without a breaking trait change.
//!
//! - [`DefiAdapter`] — the adapter trait.  Declares verb identity, produces a
//!   `DefiPreview`, declares the policy-criterion `kind`s it contributes, and
//!   hands off to submit.  Guards are existing `Criterion` impls (no new policy
//!   engine added).
//!
//! # No-opaque-calldata discipline
//!
//! `DefiPreview` has NO escape-hatch field.  This is a TYPE-LEVEL guarantee,
//! not a convention.  A `DefiPreview` instance is safe to present to a user for
//! approval because every field is typed and human-renderable; there is no
//! opaque byte vector or raw JSON blob that could hide contract call data.
//!
//! # EvalContext views
//!
//! No concrete `EvalContext` view is added in this substrate.  Protocol crates
//! add their views via the existing `EvalContext` extension pattern in
//! `stellar-agent-core`'s policy engine.

use stellar_agent_core::ContextRuleId;

use crate::dispatch::SubmitWitness;
use crate::pins::DefiContractPin;
use stellar_agent_network::{Signer, StellarRpcClient};

// ─────────────────────────────────────────────────────────────────────────────
// DefiPreview — typed, serde + schemars, no escape hatch
// ─────────────────────────────────────────────────────────────────────────────

/// Typed preview produced by a `DefiAdapter` at approval time.
///
/// All fields are typed; there is **no escape-hatch field** (`raw: Vec<Val>`,
/// `extra: serde_json::Value`, or any opaque byte blob).  This is a type-level
/// guarantee of the no-opaque-calldata discipline.
///
/// Every field is human-renderable and JSON-serializable, making the preview
/// safe to present to a user for approval without risk of hidden calldata.
///
/// Protocol-specific fields are added by each protocol crate.  This type
/// defines the common identity fields only.
///
/// Protocol crates add `schemars::JsonSchema` on their MCP wrapper types when
/// they consume `rmcp` (which activates the schemars derive).  This substrate
/// type is serde-only to avoid the rmcp transitive dep at the foundational
/// layer.
///
/// # Examples
///
/// ```
/// use stellar_agent_defi::adapter::DefiPreview;
///
/// let preview = DefiPreview::new(
///     "blend", "supply", "stellar:testnet",
///     "CAAAA\u{2026}AAAAB", "Supply 100 USDC to Blend pool",
/// );
/// assert_eq!(preview.verb, "supply");
/// ```
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct DefiPreview {
    /// Protocol identifier (e.g. `"blend"`, `"defindex"`, `"axelar"`).
    pub protocol: String,
    /// Verb identifier (e.g. `"supply"`, `"borrow"`, `"trade"`).
    pub verb: String,
    /// Network (e.g. `"stellar:testnet"`, `"stellar:pubnet"`).
    pub network: String,
    /// First-5-last-5 redacted contract address for display.
    ///
    /// The full address is NOT included in `DefiPreview` to avoid leaking it
    /// into approval UI surfaces per the redaction rules.
    pub contract_address_redacted: String,
    /// Human-readable one-line summary for display in the approval UI.
    pub summary: String,
}

impl DefiPreview {
    /// Constructs a `DefiPreview` with all required fields.
    ///
    /// Provided because `DefiPreview` is `#[non_exhaustive]`; external callers
    /// cannot use struct-literal syntax and must use this constructor.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_defi::adapter::DefiPreview;
    ///
    /// let p = DefiPreview::new(
    ///     "blend",
    ///     "supply",
    ///     "stellar:testnet",
    ///     "CAAAA\u{2026}AAAAB",
    ///     "Supply 100 USDC",
    /// );
    /// assert_eq!(p.protocol, "blend");
    /// ```
    #[must_use]
    pub fn new(
        protocol: impl Into<String>,
        verb: impl Into<String>,
        network: impl Into<String>,
        contract_address_redacted: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            protocol: protocol.into(),
            verb: verb.into(),
            network: network.into(),
            contract_address_redacted: contract_address_redacted.into(),
            summary: summary.into(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DefiAdapterCtx — context handle for adapters
// ─────────────────────────────────────────────────────────────────────────────

/// Context passed to [`DefiAdapter::preview`] and [`DefiAdapter::submit`].
///
/// Carries the structural context required by protocol adapters: active profile
/// name, the resolved `DefiContractPin` for the verb, primary RPC accessor, and
/// the submit-time context (signer, network passphrase, chain ID, optional
/// secondary RPC, timeout).
///
/// `#[non_exhaustive]` so further fields grow additively without breaking
/// the trait signature.
///
/// # Submit context fields
///
/// The `signer`, `network_passphrase`, `chain_id`, `secondary_rpc`, and
/// `timeout` fields carry everything a concrete adapter's `submit` needs to
/// call `submit_signed_invoke` without re-implementing that logic in the MCP
/// tool or CLI.  The secondary RPC is threaded here rather than via a separate
/// site because it is structurally part of the adapter's submit context.
///
/// Fields are `Option<...>` where the value is genuinely optional for
/// preview-only calls (no signer needed for preview).  `submit` returns a
/// `DefiAdapterError::InvalidArguments` when required fields are `None`.
///
/// # `auth_rule_ids`
///
/// OZ smart-account context-rule IDs used when signing the auth entry inside
/// `submit_signed_invoke`.  One entry per auth context the operation produces.
/// For the DEX swap via `wallet.execute(router, fn, args)`, the Soroswap
/// router-direct path always produces **exactly 2** auth contexts for the
/// wallet: (1) the `execute` entrypoint call, and (2) the `token_in.transfer`
/// call from the wallet (soroswap-core/router:617 @ bb90a65).  Pass two rule
/// IDs: `&[ContextRuleId::new(0), ContextRuleId::new(0)]` for freshly deployed
/// accounts with only the constructor bootstrap rule.
///
/// `None` is interpreted by the DEX swap adapter as
/// `&[ContextRuleId::new(0), ContextRuleId::new(0)]` (bootstrap default for
/// the execute-via-wallet 2-auth-context path).  Other adapters may use a
/// different default count appropriate for their invocation pattern.
#[non_exhaustive]
pub struct DefiAdapterCtx<'a> {
    /// Name of the active profile (e.g. `"default"`, `"testnet"`).
    pub profile_name: &'a str,
    /// Resolved contract pin for the verb being previewed or submitted.
    pub pin: &'a DefiContractPin,
    /// Primary Stellar RPC client for on-chain reads and submit.
    pub primary_rpc: &'a StellarRpcClient,
    /// Signer for the smart-account auth-digest and source-account envelope.
    ///
    /// `None` during preview-only calls where signing is not performed.
    /// `submit` requires `Some`; returns `InvalidArguments` otherwise.
    pub signer: Option<&'a (dyn Signer + Send + Sync)>,
    /// Stellar network passphrase (e.g. `"Test SDF Network ; September 2015"`).
    ///
    /// Required by `submit_signed_invoke`; `None` during preview-only calls.
    pub network_passphrase: Option<&'a str>,
    /// CAIP-2 chain identifier (e.g. `"stellar:testnet"`, `"stellar:mainnet"`).
    ///
    /// Required by `submit_signed_invoke`; `None` during preview-only calls.
    pub chain_id: Option<&'a str>,
    /// Optional secondary Stellar RPC for the two-RPC cross-check.
    ///
    /// When `None`, the primary RPC is used for both sides of any two-RPC
    /// check (degraded security).  Configuring a distinct secondary is
    /// strongly recommended for mainnet operations.
    pub secondary_rpc: Option<&'a StellarRpcClient>,
    /// Submit polling timeout.
    ///
    /// `None` uses a caller-determined default inside the adapter (60s).
    pub timeout: Option<std::time::Duration>,
    /// OZ smart-account context-rule IDs for the auth entry.
    ///
    /// One entry per auth context the operation produces.  The required count
    /// depends on the adapter's invocation pattern.  For the DEX swap adapter
    /// (`DexSwapAdapter`), the Soroswap router-direct path via
    /// `wallet.execute(router, fn, args)` always produces 2 auth contexts:
    /// the `execute` call and the `token_in.transfer` call.  Pass two entries:
    /// `&[ContextRuleId::new(0), ContextRuleId::new(0)]` for bootstrap accounts.
    ///
    /// `None` delegates the default count decision to the concrete adapter.
    pub auth_rule_ids: Option<&'a [ContextRuleId]>,
    /// Audit writer for the value-action row emitted after a confirmed submit.
    ///
    /// `None` for preview-only calls and any caller that does not record value
    /// rows. When `Some`, the adapter emits a `ValueActionSubmitted` row in the
    /// submit Ok arm; the writer MUST have been opened with the profile's audit
    /// chain-root HMAC key so `audit verify` covers the row.
    pub audit_writer:
        Option<std::sync::Arc<std::sync::Mutex<stellar_agent_core::audit_log::AuditWriter>>>,
    /// Gate-derived value legs recorded in the value-action row — the same
    /// descriptor the policy gate sized (single-derivation invariant). Emission
    /// is skipped when `None`.
    pub audit_legs: Option<&'a [stellar_agent_core::audit_log::ValueLegRecord]>,
    /// MCP/CLI tool identity for the audit row's outer `tool` field (e.g.
    /// `"stellar_blend_lend"`). Emission is skipped when `None`.
    pub audit_tool: Option<&'a str>,
}

impl<'a> DefiAdapterCtx<'a> {
    /// Constructs a preview-only `DefiAdapterCtx` (no submit context).
    ///
    /// Submit fields (`signer`, `network_passphrase`, `chain_id`, `secondary_rpc`,
    /// `timeout`) are `None`.  Calling `DefiAdapter::submit` on a context
    /// built with this constructor returns `DefiAdapterError::InvalidArguments`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_defi::adapter::DefiAdapterCtx;
    /// use stellar_agent_defi::pins::DefiContractPin;
    /// use stellar_agent_network::StellarRpcClient;
    ///
    /// let pin = DefiContractPin::new(
    ///     "blend", "v2", "default", "stellar:testnet",
    ///     "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
    ///     [0u8; 32], "895845f",
    /// );
    /// let rpc = StellarRpcClient::new("https://soroban-testnet.stellar.org")
    ///     .expect("valid URL");
    /// let ctx = DefiAdapterCtx::new("default", &pin, &rpc);
    /// assert_eq!(ctx.profile_name, "default");
    /// ```
    #[must_use]
    pub fn new(
        profile_name: &'a str,
        pin: &'a DefiContractPin,
        primary_rpc: &'a StellarRpcClient,
    ) -> Self {
        Self {
            profile_name,
            pin,
            primary_rpc,
            signer: None,
            network_passphrase: None,
            chain_id: None,
            secondary_rpc: None,
            timeout: None,
            auth_rule_ids: None,
            audit_writer: None,
            audit_legs: None,
            audit_tool: None,
        }
    }

    /// Constructs a full `DefiAdapterCtx` with submit context.
    ///
    /// Use this constructor when the adapter's `submit` method will be called.
    /// Preview-only callers may use [`Self::new`] instead.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use stellar_agent_defi::adapter::DefiAdapterCtx;
    /// use stellar_agent_defi::pins::DefiContractPin;
    /// use stellar_agent_network::{Signer, StellarRpcClient};
    ///
    /// // (signer obtained from signer_from_keyring in production)
    /// # fn example(pin: &DefiContractPin, rpc: &StellarRpcClient, signer: &(dyn Signer + Send + Sync)) {
    /// let ctx = DefiAdapterCtx::new_with_submit_ctx(
    ///     "default", pin, rpc,
    ///     Some(signer),
    ///     Some("Test SDF Network ; September 2015"),
    ///     Some("stellar:testnet"),
    ///     None, // secondary_rpc
    ///     Some(Duration::from_secs(60)),
    /// );
    /// # }
    /// ```
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_submit_ctx(
        profile_name: &'a str,
        pin: &'a DefiContractPin,
        primary_rpc: &'a StellarRpcClient,
        signer: Option<&'a (dyn Signer + Send + Sync)>,
        network_passphrase: Option<&'a str>,
        chain_id: Option<&'a str>,
        secondary_rpc: Option<&'a StellarRpcClient>,
        timeout: Option<std::time::Duration>,
    ) -> Self {
        Self {
            profile_name,
            pin,
            primary_rpc,
            signer,
            network_passphrase,
            chain_id,
            secondary_rpc,
            timeout,
            auth_rule_ids: None,
            audit_writer: None,
            audit_legs: None,
            audit_tool: None,
        }
    }

    /// Emits a `ValueActionSubmitted` audit row for a confirmed DeFi submit.
    ///
    /// No-op unless an audit writer, gate-derived legs, tool identity, and
    /// chain id were all threaded into this context. Non-fatal: the submit has
    /// already confirmed, so a row-write failure logs a warning and does not
    /// affect the caller. `tx_hash_redacted` MUST already be redacted.
    pub fn emit_value_action_submitted(
        &self,
        tx_hash_redacted: &str,
        ledger: u32,
        request_id: &str,
    ) {
        let (Some(writer), Some(legs), Some(tool), Some(chain_id)) = (
            self.audit_writer.as_ref(),
            self.audit_legs,
            self.audit_tool,
            self.chain_id,
        ) else {
            return;
        };

        let entry = stellar_agent_core::audit_log::AuditEntry::new_value_action_submitted(
            tool,
            chain_id,
            legs.to_vec(),
            tx_hash_redacted,
            ledger,
            stellar_agent_core::audit_log::PolicyDecision::Allow,
            None,
            None,
            request_id,
        );

        match writer.lock() {
            Ok(mut guard) => {
                if let Err(e) = guard.write_entry(entry) {
                    tracing::warn!(
                        error = %e,
                        "defi value audit: write_entry failed; ValueActionSubmitted NOT emitted"
                    );
                }
            }
            Err(_) => {
                tracing::warn!(
                    "defi value audit: writer mutex poisoned; ValueActionSubmitted NOT emitted"
                );
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DefiAdapter — the adapter trait
// ─────────────────────────────────────────────────────────────────────────────

/// The DeFi adapter trait implemented by each protocol crate.
///
/// Declares verb identity, produces a [`DefiPreview`] from typed arguments and
/// a [`DefiAdapterCtx`], declares the policy-criterion `kind`s it contributes
/// (the guards are existing `Criterion` impls — no new policy engine), and
/// hands off to submit via the [`SubmitWitness`] seam.
///
/// # Context handle
///
/// The `&DefiAdapterCtx<'_>` parameter carries the structural context required
/// by protocol adapters (profile name, pin, RPC accessor) without forcing a
/// trait-signature change as adapters are added.
#[async_trait::async_trait]
pub trait DefiAdapter: Send + Sync + std::fmt::Debug {
    /// The verb identifier this adapter handles (e.g. `"supply"`, `"trade"`).
    ///
    /// Must be a stable, snake_case identifier unique within the dispatch
    /// registry.
    fn verb(&self) -> &'static str;

    /// The policy-criterion `kind`s this adapter contributes.
    ///
    /// Returns the snake_case `kind` strings this adapter's guards register.
    /// Used by the dispatch registry to enumerate criterion contributions.
    ///
    /// Returns an empty slice if no adapter-specific criteria exist.
    fn criterion_kinds(&self) -> &'static [&'static str];

    /// Produces a typed [`DefiPreview`] from the supplied typed arguments and
    /// context.
    ///
    /// Called at the simulate step before the sign-time gate runs.  The preview
    /// is presented to the user for approval.
    ///
    /// # Errors
    ///
    /// Returns [`DefiAdapterError`] when preview construction fails (e.g. RPC
    /// error fetching oracle price, invalid argument combination).
    async fn preview(
        &self,
        args: &(dyn std::any::Any + Send + Sync),
        ctx: &DefiAdapterCtx<'_>,
    ) -> Result<DefiPreview, DefiAdapterError>;

    /// Executes the adapter's submit logic, consuming the [`SubmitWitness`].
    ///
    /// The `witness` was constructed by the dispatch seam from a
    /// `GateOutcome::Allow`; its existence proves that the gate ran.
    /// Skip-the-gate is structurally unrepresentable because `SubmitWitness`
    /// is only constructible by the seam.
    ///
    /// # Errors
    ///
    /// Returns [`DefiAdapterError`] when the submit step fails.
    async fn submit(
        &self,
        args: &(dyn std::any::Any + Send + Sync),
        ctx: &DefiAdapterCtx<'_>,
        witness: SubmitWitness,
    ) -> Result<(), DefiAdapterError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// DefiAdapterError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by [`DefiAdapter`] methods.
///
/// All variants carry non-sensitive strings; secret material (keys, hashes,
/// addresses) must be redacted by the caller before constructing this error
/// per the redaction rules (strkeys to first-5-last-5, WASM hashes to
/// first-8 hex).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DefiAdapterError {
    /// The supplied arguments are invalid or malformed.
    #[error("invalid adapter arguments: {reason}")]
    InvalidArguments {
        /// Non-sensitive reason string.
        reason: String,
    },
    /// A network or RPC error occurred during preview or submit.
    #[error("adapter network error: {reason}")]
    Network {
        /// Non-sensitive reason string; URLs must be redacted to authority-only.
        reason: String,
    },
    /// The contract-pin verification failed before submit.
    #[error("adapter pin verification failed: {reason}")]
    PinFailed {
        /// Non-sensitive reason string; hashes and addresses must be redacted
        /// (first-8 hex and first-5-last-5 respectively).
        reason: String,
    },
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

    #[test]
    fn defi_preview_new_constructor() {
        let p = DefiPreview::new(
            "blend",
            "supply",
            "stellar:testnet",
            "CAAAA\u{2026}AAAAB",
            "Supply 100 USDC",
        );
        assert_eq!(p.protocol, "blend");
        assert_eq!(p.verb, "supply");
        assert_eq!(p.network, "stellar:testnet");
        assert_eq!(p.contract_address_redacted, "CAAAA\u{2026}AAAAB");
        assert_eq!(p.summary, "Supply 100 USDC");
    }

    #[test]
    fn defi_adapter_ctx_new_with_submit_ctx() {
        use crate::pins::DefiContractPin;
        use stellar_agent_network::StellarRpcClient;

        let pin = DefiContractPin {
            protocol: "blend".to_owned(),
            version: "v2".to_owned(),
            profile: "default".to_owned(),
            network: "stellar:testnet".to_owned(),
            contract_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            wasm_hash: [0u8; 32],
            abi_source_provenance: "test".to_owned(),
        };
        let rpc = StellarRpcClient::new("https://soroban-testnet.stellar.org").expect("valid URL");
        let ctx = super::DefiAdapterCtx::new_with_submit_ctx(
            "default",
            &pin,
            &rpc,
            None,
            Some("Test SDF Network ; September 2015"),
            Some("stellar:testnet"),
            None,
            Some(std::time::Duration::from_secs(60)),
        );
        assert_eq!(ctx.profile_name, "default");
        assert!(ctx.signer.is_none());
        assert_eq!(
            ctx.network_passphrase,
            Some("Test SDF Network ; September 2015")
        );
        assert_eq!(ctx.chain_id, Some("stellar:testnet"));
        assert!(ctx.secondary_rpc.is_none());
        assert_eq!(ctx.timeout, Some(std::time::Duration::from_secs(60)));
    }

    #[test]
    fn defi_preview_is_serde_roundtrip() {
        let preview = DefiPreview {
            protocol: "blend".to_owned(),
            verb: "supply".to_owned(),
            network: "stellar:testnet".to_owned(),
            contract_address_redacted: "CAAAA\u{2026}AAAAB".to_owned(),
            summary: "Supply 100 USDC to Blend pool".to_owned(),
        };
        let json = serde_json::to_string(&preview).expect("serialize");
        let back: DefiPreview = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(preview, back);
    }

    #[test]
    fn defi_preview_has_no_extra_opaque_field() {
        // The DefiPreview type must NOT have any field that would allow opaque
        // calldata to be smuggled through approval.  This test builds a DefiPreview
        // and verifies the JSON schema contains only the declared named fields.
        let preview = DefiPreview {
            protocol: "blend".to_owned(),
            verb: "supply".to_owned(),
            network: "stellar:testnet".to_owned(),
            contract_address_redacted: "CAAAA\u{2026}AAAAB".to_owned(),
            summary: "Supply 100 USDC".to_owned(),
        };
        let json = serde_json::to_value(&preview).expect("to_value");
        let obj = json.as_object().expect("is object");
        // Only the declared fields must appear.
        let allowed_keys: std::collections::BTreeSet<&str> = [
            "protocol",
            "verb",
            "network",
            "contract_address_redacted",
            "summary",
        ]
        .iter()
        .copied()
        .collect();
        for key in obj.keys() {
            assert!(
                allowed_keys.contains(key.as_str()),
                "unexpected field '{key}' in DefiPreview — no escape-hatch fields allowed"
            );
        }
    }
}
