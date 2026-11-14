//! `stellar_sep43_sign_transaction` MCP tool — SEP-43 `signTransaction`.
//!
//! Signs a base64-encoded `TransactionEnvelope` XDR and returns the signed
//! envelope with the signer's address.
//!
//! Per `sep-0043.md` lines :62-76.
//!
//! # Signing path
//!
//! Loads the signer from `profile.mcp_signer_default` via
//! `stellar_agent_network::keyring::enrolled_keyring_signer`, then dispatches to
//! `stellar_agent_sep43::StellarAgentModule::sign_transaction`.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use crate::server::WalletServer;

// ─────────────────────────────────────────────────────────────────────────────
// Argument type
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_sep43_sign_transaction` MCP tool.
///
/// # Schema
///
/// - `chain_id` — CAIP-2 chain identifier; validated against the active profile.
/// - `transaction_xdr` — base64-encoded `TransactionEnvelope` XDR.
/// - `network_passphrase` — optional; if provided must match profile passphrase.
/// - `address` — optional signer address (G-strkey); if provided must match
///   the active signer.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct Sep43SignTransactionArgs {
    /// CAIP-2 chain identifier (e.g. `"stellar:testnet"`).
    pub chain_id: String,

    /// Base64-encoded `TransactionEnvelope` XDR to sign.
    pub transaction_xdr: String,

    /// Optional Stellar network passphrase override.
    ///
    /// If provided, must equal the profile's `network_passphrase` exactly.
    /// Mismatch → error code -3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_passphrase: Option<String>,

    /// Optional signer address (G-strkey).
    ///
    /// If provided, must match the active signer enrolled in the profile.
    /// Mismatch → error code -3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Signs a `TransactionEnvelope` XDR (SEP-43 `signTransaction`).
///
/// Loads the signer from the profile's default keyring entry and signs the
/// provided transaction XDR.  Returns
/// `{ "signedTxXdr": "...", "signerAddress": "G..." }` on success or a
/// SEP-43 spec-compliant `{ "code": N, "message": "..." }` error object.
///
/// # Tool annotations
///
/// - `readOnlyHint = false` — creates a signature over the transaction.
/// - `destructiveHint = false` — `signTransaction` per SEP-43 does NOT submit;
///   the `submit?` opt defaults to `false`. Submission is a separate step.
///
/// # SEP-43 reference
///
/// `sep-0043.md` lines :62-76 — `signTransaction(xdr, opts?)`.
///
/// # Errors
///
/// Returns a tool-level error (not a JSON-RPC error) when:
/// - `chain_id` does not match the active profile.
/// - `transaction_xdr` is not valid base64 `TransactionEnvelope`.
/// - `network_passphrase` is provided but does not match the profile.
/// - `address` is provided but does not match the active signer.
/// - The keyring entry for the signer cannot be loaded.
///
/// # Examples
///
/// ```json
/// {
///   "chain_id": "stellar:testnet",
///   "transaction_xdr": "AAAAAQAA..."
/// }
/// ```
#[mcp_tool_router]
#[tool_router(router = sep43_sign_transaction_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_sep43_sign_transaction",
        destructive_hint = false,
        read_only_hint = false,
        chain_id_required = true,
        value_kind = "opaque_sign"
    )]
    #[tool(
        name = "stellar_sep43_sign_transaction",
        description = "Sign a TransactionEnvelope XDR (SEP-43 signTransaction). \
                       Does NOT submit — signing only. \
                       Returns { signedTxXdr: string, signerAddress: string }. \
                       read_only_hint=false; destructive_hint=false.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn stellar_sep43_sign_transaction(
        &self,
        Parameters(args): Parameters<Sep43SignTransactionArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Mainnet structural refusal — before any key access or signing.
        // This tool returns a signature the caller broadcasts externally; the
        // submit-layer mainnet gate never fires because the wallet does not
        // submit. Refuse on a mainnet profile so no valid mainnet signature is
        // ever produced. Wire code: network.mainnet_write_forbidden.
        if self.context.chain_id.is_mainnet() {
            return Ok(crate::tools::common::mainnet_signing_forbidden_result());
        }

        if let Err(result) =
            crate::tools::common::check_sep43_envelope_address_forms(&args.transaction_xdr)
        {
            return Ok(result);
        }

        let args_value = json!({
            "chain_id": &args.chain_id,
            "transaction_xdr_len": args.transaction_xdr.len(),
        });
        // Single-shot sign tool: a RequireApproval verdict is fail-closed.
        // The two-phase approval flow is not supported on this path.
        let dispatch_outcome = match self
            .dispatch_gate(
                "stellar_sep43_sign_transaction",
                &args_value,
                &args.chain_id,
            )
            .await
        {
            Ok(o) => o,
            Err(e) => return e.into_result(),
        };
        match dispatch_outcome {
            crate::tools::common::DispatchOutcome::Allow(_) => {}
            crate::tools::common::DispatchOutcome::RequireApproval(_) => {
                return Ok(crate::tools::common::single_shot_require_approval_error());
            }
        }

        // ── Audit pre-flight: prove the writer is acquirable BEFORE signing ──
        // Runs AFTER the dispatch gate: a policy denial or approval
        // escalation signs nothing and needs no audit setup, so it must
        // surface its own code rather than audit.chain_key_unavailable. The
        // pre-flight still precedes every signing-key access — sign-only
        // tools produce a signature the caller broadcasts externally, so the
        // signature must not exist unless the row recording its production
        // can be written.
        let audit_writer = match crate::tools::value_audit::require_value_audit_writer(
            &self.profile,
            &self.profile_name_for_approval(),
            self.audit_binding,
        ) {
            Ok(w) => w,
            Err(err) => {
                return Ok(crate::tools::common::business_error_result(
                    err.code(),
                    err.to_string(),
                ));
            }
        };

        use std::sync::Arc;
        use stellar_agent_network::keyring::enrolled_keyring_signer;
        use stellar_agent_sep43::StellarAgentModule;
        use stellar_agent_sep43::module::ModuleAdapter;

        let account = self.profile.mcp_signer_default.account.as_str();

        // Load the signer from the keyring.
        let signer_handle = match enrolled_keyring_signer(
            &self.profile_name_for_approval(),
            &self.profile,
            account,
            self.established_owner().as_ref(),
        )
        .await
        {
            Ok(h) => h,
            Err(err) => {
                if matches!(
                    &err,
                    stellar_agent_core::error::WalletError::Auth(
                        stellar_agent_core::error::AuthError::EnrolledSignerUnpinned { .. }
                            | stellar_agent_core::error::AuthError::EnrolledSignerMismatch { .. }
                            | stellar_agent_core::error::AuthError::EnrolledIdentityUnusable { .. }
                    )
                ) {
                    return Ok(crate::tools::common::business_error_result(
                        err.code(),
                        err.to_string(),
                    ));
                }

                let sep43_err = stellar_agent_sep43::Sep43Error::WalletUnlockFailed {
                    detail: format!("keyring load failed: {err}"),
                };
                return Ok(crate::tools::common::business_error_result(
                    sep43_err.wire_code(),
                    sep43_err.to_string(),
                ));
            }
        };

        let signer_g = signer_handle.public_key().to_string();
        let profile = Arc::clone(&self.profile);
        let signer: Arc<dyn stellar_agent_network::signing::Signer + Send + Sync> =
            Arc::new(signer_handle);
        let module = StellarAgentModule::new(profile, signer);

        match module
            .sign_transaction(
                &args.transaction_xdr,
                args.network_passphrase.as_deref(),
                args.address.as_deref(),
            )
            .await
        {
            Ok(value) => {
                // Record that the signature was produced: the payload digest
                // (redacted) and the redacted signer — never the signature or
                // the payload. Best-effort past this point: the signature
                // exists, so a write failure warns and never changes the
                // result.
                let payload_digest = {
                    use sha2::{Digest as _, Sha256};
                    hex::encode(Sha256::digest(args.transaction_xdr.as_bytes()))
                };
                let entry =
                    stellar_agent_core::audit_log::entry::AuditEntry::new_opaque_payload_signed(
                        "stellar_sep43_sign_transaction",
                        args.chain_id.as_str(),
                        stellar_agent_network::submit::redact_tx_hash(&payload_digest),
                        stellar_agent_core::observability::RedactedStrkey::from_full(&signer_g),
                        uuid::Uuid::new_v4().to_string(),
                    );
                crate::tools::value_audit::emit_value_audit_row_with_writer(
                    &audit_writer,
                    &self.profile_name_for_approval(),
                    entry,
                );

                let envelope = stellar_agent_core::envelope::Envelope::ok(value);
                let json_str = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                Ok(CallToolResult::success(vec![Content::text(json_str)]))
            }
            Err(err) => Ok(crate::tools::common::business_error_result(
                err.wire_code(),
                err.to_string(),
            )),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_sep43_sign_transaction` with the given args, bypassing the
    /// rmcp transport.
    ///
    /// # Errors
    ///
    /// Propagates `rmcp::ErrorData` from the `dispatch_gate` preamble (e.g.
    /// chain_id mismatch, policy deny, `RequireApproval` fail-closed).
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Feature gate
    ///
    /// Gated on the `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_sep43_sign_transaction(
        &self,
        args: Sep43SignTransactionArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_sep43_sign_transaction(rmcp::handler::server::wrapper::Parameters(args))
            .await
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
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use stellar_agent_core::policy::ToolDescriptor;
    use stellar_agent_core::policy::v1::{
        AccountIdentityView, AccountReservesView, CounterpartyCacheView, Sep10SessionView,
        Sep45SessionView,
    };
    use stellar_agent_core::policy::{
        ApprovalRequest, Decision, DenyReason, PolicyEngine, PolicyError,
    };
    use stellar_agent_core::profile::schema::Profile;

    struct RequireApprovalEngine;

    impl PolicyEngine for RequireApprovalEngine {
        fn evaluate(
            &self,
            _tool: &ToolDescriptor,
            _args: &serde_json::Value,
            _profile: &Profile,
            _account_view: Option<&dyn AccountReservesView>,
            _identity_view: Option<&dyn AccountIdentityView>,
            _counterparty_cache: Option<&dyn CounterpartyCacheView>,
            _sep10_sessions: Option<&dyn Sep10SessionView>,
            _sep45_sessions: Option<&dyn Sep45SessionView>,
            _now_ms: u64,
        ) -> Result<Decision, PolicyError> {
            Ok(Decision::RequireApproval(ApprovalRequest::new(
                "test-nonce".into(),
                120,
            )))
        }
    }

    struct DenyEngine;

    impl PolicyEngine for DenyEngine {
        fn evaluate(
            &self,
            _tool: &ToolDescriptor,
            _args: &serde_json::Value,
            _profile: &Profile,
            _account_view: Option<&dyn AccountReservesView>,
            _identity_view: Option<&dyn AccountIdentityView>,
            _counterparty_cache: Option<&dyn CounterpartyCacheView>,
            _sep10_sessions: Option<&dyn Sep10SessionView>,
            _sep45_sessions: Option<&dyn Sep45SessionView>,
            _now_ms: u64,
        ) -> Result<Decision, PolicyError> {
            Ok(Decision::Deny(DenyReason::NoMatchingRule))
        }
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn muxed_contract_intake_refuses_before_state() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let reads = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&reads);
        stellar_agent_test_support::keyring_mock::install_with_read_hooks(vec![
            stellar_agent_test_support::keyring_mock::ReadHook::new(
                "svc",
                "acct",
                Arc::new(move || {
                    observed.fetch_add(1, Ordering::SeqCst);
                }),
            ),
        ])
        .unwrap();
        let server = make_require_approval_server();
        let before = std::fs::read_dir(home.path()).unwrap().count();
        let result = server
            .call_stellar_sep43_sign_transaction(Sep43SignTransactionArgs {
                chain_id: "stellar:testnet".to_owned(),
                transaction_xdr: stellar_agent_test_support::xdr_fixtures::muxed_contract_envelope(
                ),
                address: None,
                network_passphrase: None,
            })
            .await
            .unwrap();
        let (code, message, _) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "sep43.invalid_xdr");
        assert!(message.ends_with("a muxed contract address (W) is not accepted on this path"));
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), before);
    }

    fn make_require_approval_server() -> crate::server::WalletServer {
        use std::sync::Arc;
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_noop_engine()
            .build();
        // No audit chain key is seeded at this profile's coordinate: gate
        // verdicts (RequireApproval here) precede the audit pre-flight, so
        // this scenario must complete without one — the test's assertion on
        // the fail-closed approval error doubles as the ordering pin.
        let mut server = crate::server::WalletServer::new(profile)
            .expect("WalletServer::new must not fail in tests");
        server.policy_engine = Arc::new(RequireApprovalEngine);
        server
    }

    /// A Noop-engine mainnet server over a fresh mock keyring store; callers
    /// hold the `keyring` serial key.
    fn make_mainnet_server() -> crate::server::WalletServer {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring");
        crate::server::WalletServer::new(
            Profile::builder_mainnet(
                "https://rpc.example.invalid",
                "svc",
                "acct",
                "n-svc",
                "n-acct",
            )
            .with_noop_engine()
            .build(),
        )
        .expect("WalletServer::new must not fail in tests")
    }

    /// A mainnet profile MUST refuse `stellar_sep43_sign_transaction`
    /// structurally before any key access: the result is the normalised
    /// business-error envelope carrying the canonical
    /// `network.mainnet_write_forbidden` wire code, and it MUST NOT contain a
    /// signed transaction.
    ///
    /// The keyring mock is intentionally NOT installed: reaching the keyring
    /// would surface a `wallet_unlock_failed` message instead, so this test also
    /// proves the refusal fires before key access.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn mainnet_profile_refuses_before_signing_no_signature_produced() {
        let server = make_mainnet_server();
        let args = Sep43SignTransactionArgs {
            chain_id: "stellar:mainnet".to_owned(),
            transaction_xdr: "AAAAAQAA".to_owned(),
            network_passphrase: None,
            address: None,
        };
        let result = server
            .call_stellar_sep43_sign_transaction(args)
            .await
            .expect("structural mainnet refusal is surfaced as Ok(is_error), not Err");
        let (code, message, text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(
            code, "network.mainnet_write_forbidden",
            "mainnet refusal must carry the canonical wire code"
        );
        assert!(
            !message.contains("keyring") && !message.contains("unlock"),
            "refusal must fire before key access — message must not mention keyring/unlock: {message}"
        );
        assert!(
            !text.contains("signedTxXdr"),
            "no signature must be produced on mainnet; got: {text}"
        );
    }

    /// A policy denial precedes the audit pre-flight: with a denying engine
    /// AND an unminted audit chain key, the surfaced wire code is the policy
    /// denial — a denial signs nothing and needs no audit setup, so it must
    /// never be masked by `audit.chain_key_unavailable`.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn policy_denial_precedes_the_audit_preflight() {
        use std::sync::Arc;
        stellar_agent_test_support::keyring_mock::install().ok();
        let profile = Profile::builder_testnet(
            "svc-s43tx-denyfirst",
            "acct-s43tx-denyfirst",
            "n-svc",
            "n-acct",
        )
        .with_noop_engine()
        .build();
        let mut server =
            crate::server::WalletServer::new(profile).expect("WalletServer::new in tests");
        server.policy_engine = Arc::new(DenyEngine);
        let args = Sep43SignTransactionArgs {
            chain_id: "stellar:testnet".to_owned(),
            transaction_xdr: "AAAAAQAA".to_owned(),
            network_passphrase: None,
            address: None,
        };
        let result = server
            .call_stellar_sep43_sign_transaction(args)
            .await
            .expect("denial must be a business envelope, not a protocol error");
        let (code, _message, text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "policy.deny.no_matching_rule");
        assert!(
            !text.contains("signedTxXdr"),
            "no signature may be produced on a policy denial; got: {text}"
        );
    }

    /// An unminted audit chain key refuses BEFORE any signing: after the
    /// dispatch gate allows, the pre-flight fires ahead of the signer load,
    /// so no signature is ever produced and the wire code matches every
    /// other signing tool.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn unminted_audit_key_refused_before_signing() {
        stellar_agent_test_support::keyring_mock::install().ok();
        // Unique coordinates; the audit chain-root key is deliberately NOT
        // seeded at this profile's derived coordinate.
        let profile = Profile::builder_testnet(
            "svc-s43tx-unminted",
            "acct-s43tx-unminted",
            "n-svc",
            "n-acct",
        )
        .with_noop_engine()
        .build();
        let server = crate::server::WalletServer::new(profile).expect("WalletServer::new in tests");
        let args = Sep43SignTransactionArgs {
            chain_id: "stellar:testnet".to_owned(),
            transaction_xdr: "AAAAAQAA".to_owned(),
            network_passphrase: None,
            address: None,
        };
        let result = server
            .call_stellar_sep43_sign_transaction(args)
            .await
            .expect("refusal must be a business envelope, not a protocol error");
        let (code, _message, text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "audit.chain_key_unavailable");
        assert!(
            !text.contains("signedTxXdr"),
            "no signature may be produced on an audit pre-flight refusal; got: {text}"
        );
    }

    /// A testnet profile naming the seed coordinate of mainnet profile `v`
    /// gets no transaction signature: the record bound to `v` refuses before
    /// the seed is read, with `v.toml` absent from the profiles directory.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn a_signer_bound_elsewhere_refuses_transaction_signing() {
        let mut fixture = crate::tools::message_signing_tests::Fixture::new();
        let reads = fixture.transplant_from_mainnet_victim();
        let mut builder = stellar_agent_network::builder::ClassicOpBuilder::new(
            &fixture.account,
            1,
            "Test SDF Network ; September 2015",
            100,
        );
        builder
            .payment(
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                stellar_agent_core::StellarAmount::from_stroops(10_000_000),
                &stellar_agent_network::builder::Asset::parse("native").expect("native asset"),
            )
            .expect("payment op");
        let result = fixture
            .server()
            .call_stellar_sep43_sign_transaction(Sep43SignTransactionArgs {
                chain_id: "stellar:testnet".to_owned(),
                transaction_xdr: builder.build().expect("valid envelope"),
                network_passphrase: None,
                address: None,
            })
            .await
            .expect("a refusal is a business envelope");
        let (code, message, text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "auth.enrolled_identity_unusable", "{text}");
        assert!(message.contains("(bound_elsewhere)"), "{message}");
        assert!(!text.contains("signedTxXdr"), "{text}");
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// A successful sign records an `opaque_payload_signed` row carrying the
    /// redacted payload digest at the profile's configured audit log path.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn successful_sign_records_opaque_payload_signed_row() {
        use base64::Engine as _;
        stellar_agent_test_support::keyring_mock::install().ok();
        let dir = tempfile::tempdir().expect("tempdir");

        // Enroll a signer seed; the account coordinate is the seed's derived
        // G-strkey (account-as-identity: signer_from_keyring verifies the
        // loaded seed derives to the account it was addressed by).
        let seed = [0x5Au8; 32];
        let s_strkey = stellar_strkey::ed25519::PrivateKey::from_payload(&seed)
            .expect("seed strkey")
            .as_unredacted()
            .to_string()
            .to_string();
        let derived_g = {
            let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
            stellar_strkey::ed25519::PublicKey(vk.to_bytes()).to_string()
        };
        keyring_core::Entry::new("svc-s43tx-row", &derived_g)
            .expect("Entry::new")
            .set_password(&s_strkey)
            .expect("set_password");

        let profile =
            Profile::builder_testnet("svc-s43tx-row", derived_g.as_str(), "n-svc", "n-acct")
                .with_noop_engine()
                .audit_log_path(dir.path().join("audit.jsonl"))
                .build();
        // Seed the audit chain-root key (unique profile name — no registry
        // contention with other tests).
        let coord = profile.audit_log_hash_chain_key_id.clone();
        let key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x41u8; 32]);
        keyring_core::Entry::new(&coord.service, &coord.account)
            .expect("Entry::new for audit key")
            .set_password(&key_b64)
            .expect("set_password for audit key");
        crate::tools::identity_fixture::store_signer_identity(&profile, seed);
        let server = crate::server::WalletServer::new(profile).expect("WalletServer::new in tests");

        // A minimal valid testnet envelope built offline (source = the
        // canonical all-zero ed25519 public key strkey).
        let mut builder = stellar_agent_network::builder::ClassicOpBuilder::new(
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            1,
            "Test SDF Network ; September 2015",
            100,
        );
        builder
            .payment(
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                stellar_agent_core::StellarAmount::from_stroops(10_000_000),
                &stellar_agent_network::builder::Asset::parse("native").expect("native asset"),
            )
            .expect("payment op");
        let tx_xdr = builder.build().expect("valid envelope");

        let args = Sep43SignTransactionArgs {
            chain_id: "stellar:testnet".to_owned(),
            transaction_xdr: tx_xdr.clone(),
            network_passphrase: None,
            address: None,
        };
        let result = server
            .call_stellar_sep43_sign_transaction(args)
            .await
            .expect("sign must succeed");
        let text = result
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.clone())
            .expect("result must carry a text content block");
        assert_ne!(result.is_error, Some(true), "sign must not error: {text}");
        assert!(
            text.contains("signedTxXdr"),
            "successful sign must return the signed envelope; got: {text}"
        );

        let log = std::fs::read_to_string(dir.path().join("audit.jsonl"))
            .expect("audit log must exist after the row emission");
        assert!(
            log.contains("\"opaque_payload_signed\""),
            "the opaque_payload_signed row must be written; got:\n{log}"
        );
        let digest = {
            use sha2::{Digest as _, Sha256};
            hex::encode(Sha256::digest(tx_xdr.as_bytes()))
        };
        let redacted = stellar_agent_network::submit::redact_tx_hash(&digest);
        assert!(
            log.contains(&redacted),
            "the row must carry the redacted payload digest {redacted}; got:\n{log}"
        );
    }

    /// A `RequireApproval` policy verdict on `stellar_sep43_sign_transaction`
    /// must return fail-closed `ErrorData` with wire code
    /// `policy.approval_required_unsupported` and MUST NOT sign the transaction.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn require_approval_verdict_is_fail_closed_no_signature_produced() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let server = make_require_approval_server();
        let args = Sep43SignTransactionArgs {
            chain_id: "stellar:testnet".to_owned(),
            transaction_xdr: "AAAAAQAA".to_owned(),
            network_passphrase: None,
            address: None,
        };
        let result = server.call_stellar_sep43_sign_transaction(args).await;
        let result = result.expect(
            "RequireApproval must return Ok(is_error) envelope, not a protocol error or a signature",
        );
        let (code, message, text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(
            code, "policy.approval_required_unsupported",
            "wire code must be policy.approval_required_unsupported"
        );
        assert!(
            message.contains("single-shot"),
            "error message must mention single-shot; got: {message}"
        );
        assert!(
            !text.contains("\"signature\""),
            "fail-closed approval refusal must not produce a signature; got: {text}"
        );
    }

    /// Supplied XDR keeps M. Signing a supplied payment, both path
    /// payments and an account merge to G, M0 and M17 returns the same
    /// transaction bytes with one signature added.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn muxed_supplied_xdr_preserved() {
        use base64::Engine as _;
        use stellar_xdr::{
            Asset, Limits, Memo, MuxedAccount, MuxedAccountMed25519, Operation, OperationBody,
            PathPaymentStrictReceiveOp, PathPaymentStrictSendOp, PaymentOp, Preconditions, ReadXdr,
            SequenceNumber, Transaction, TransactionEnvelope, TransactionExt,
            TransactionV1Envelope, Uint256, WriteXdr,
        };
        stellar_agent_test_support::keyring_mock::install().ok();
        let dir = tempfile::tempdir().expect("tempdir");
        let seed = [0x5Bu8; 32];
        let source = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let derived_g = stellar_strkey::ed25519::PublicKey(source).to_string();
        keyring_core::Entry::new("svc-s43tx-mux", &derived_g)
            .unwrap()
            .set_password(
                stellar_strkey::ed25519::PrivateKey(seed)
                    .as_unredacted()
                    .to_string()
                    .as_str(),
            )
            .unwrap();
        let profile =
            Profile::builder_testnet("svc-s43tx-mux", derived_g.as_str(), "n-svc", "n-acct")
                .with_noop_engine()
                .audit_log_path(dir.path().join("audit.jsonl"))
                .build();
        let coord = profile.audit_log_hash_chain_key_id.clone();
        keyring_core::Entry::new(&coord.service, &coord.account)
            .unwrap()
            .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x41u8; 32]))
            .unwrap();
        crate::tools::identity_fixture::store_signer_identity(&profile, seed);
        let server = crate::server::WalletServer::new(profile).expect("WalletServer::new");

        let key = [0xAF; 32];
        let destinations = [
            MuxedAccount::Ed25519(Uint256(key)),
            MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
                id: 0,
                ed25519: Uint256(key),
            }),
            MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
                id: 17,
                ed25519: Uint256(key),
            }),
        ];
        for destination in destinations {
            let bodies = [
                OperationBody::Payment(PaymentOp {
                    destination: destination.clone(),
                    asset: Asset::Native,
                    amount: 5,
                }),
                OperationBody::PathPaymentStrictReceive(PathPaymentStrictReceiveOp {
                    send_asset: Asset::Native,
                    send_max: 9,
                    destination: destination.clone(),
                    dest_asset: Asset::Native,
                    dest_amount: 5,
                    path: Vec::new().try_into().unwrap(),
                }),
                OperationBody::PathPaymentStrictSend(PathPaymentStrictSendOp {
                    send_asset: Asset::Native,
                    send_amount: 9,
                    destination: destination.clone(),
                    dest_asset: Asset::Native,
                    dest_min: 5,
                    path: Vec::new().try_into().unwrap(),
                }),
                OperationBody::AccountMerge(destination.clone()),
            ];
            for (sequence, body) in (1_i64..).zip(bodies) {
                let tx = Transaction {
                    source_account: MuxedAccount::Ed25519(Uint256(source)),
                    fee: 100,
                    seq_num: SequenceNumber(sequence),
                    cond: Preconditions::None,
                    memo: Memo::None,
                    operations: vec![Operation {
                        source_account: None,
                        body,
                    }]
                    .try_into()
                    .unwrap(),
                    ext: TransactionExt::V0,
                };
                let unsigned = TransactionEnvelope::Tx(TransactionV1Envelope {
                    tx: tx.clone(),
                    signatures: Vec::new().try_into().unwrap(),
                })
                .to_xdr_base64(Limits::none())
                .unwrap();
                let result = server
                    .call_stellar_sep43_sign_transaction(Sep43SignTransactionArgs {
                        chain_id: "stellar:testnet".to_owned(),
                        transaction_xdr: unsigned,
                        network_passphrase: None,
                        address: None,
                    })
                    .await
                    .expect("sign");
                let text = result.content[0].as_text().unwrap().text.clone();
                assert_ne!(result.is_error, Some(true), "{text}");
                let json: serde_json::Value = serde_json::from_str(&text).unwrap();
                let signed = json["data"]["signedTxXdr"]
                    .as_str()
                    .or_else(|| json["signedTxXdr"].as_str())
                    .unwrap_or_else(|| panic!("{text}"));
                let TransactionEnvelope::Tx(signed) =
                    TransactionEnvelope::from_xdr_base64(signed, Limits::none()).unwrap()
                else {
                    panic!("a v1 envelope");
                };
                assert_eq!(signed.signatures.len(), 1);
                assert_eq!(
                    signed.tx.to_xdr(Limits::none()).unwrap(),
                    tx.to_xdr(Limits::none()).unwrap(),
                    "the signed operation bytes are the supplied ones: {destination:?}"
                );
            }
        }
    }
}
