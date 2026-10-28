//! `stellar_sep43_sign_message` MCP tool — SEP-43 `signMessage`.
//!
//! Signs an arbitrary UTF-8 message string and returns the signature as
//! standard base64 with the signer's address.
//!
//! Per `sep-0043.md` lines :90-100.

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

/// Arguments for the `stellar_sep43_sign_message` MCP tool.
///
/// # Schema
///
/// - `chain_id` — CAIP-2 chain identifier.
/// - `message` — UTF-8 message to sign (must be non-empty).
/// - `network_passphrase` — optional network passphrase; if provided, must match the active profile.
/// - `address` — optional signer address; if provided must match active signer.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct Sep43SignMessageArgs {
    /// CAIP-2 chain identifier (e.g. `"stellar:testnet"`).
    pub chain_id: String,

    /// UTF-8 message string to sign.
    ///
    /// Must be non-empty. Signed with the SEP-53 prefixed digest
    /// `SHA-256("Stellar Signed Message:\n" ‖ message)`.
    pub message: String,

    /// Optional network passphrase; if provided, must match the active profile.
    ///
    /// Acts as a caller-intent validation gate. The passphrase is not mixed into
    /// the signed bytes; message signing is network-independent per SEP-43 v1.2.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_passphrase: Option<String>,

    /// Optional signer address (G-strkey).
    ///
    /// If provided, must match the active signer enrolled in the profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Signs an arbitrary message string (SEP-43 `signMessage`).
///
/// Signs the SEP-53 prefixed digest `SHA-256("Stellar Signed Message:\n" ‖ message)`
/// with the active signer. Produces the same signature bytes as
/// `stellar_sep53_sign_message`; the tools differ only in response field naming
/// and in that the SEP-53 tool additionally accepts base64 binary input (this
/// tool signs the UTF-8 message string only).
///
/// Returns `{ "signedMessage": "<base64>", "signerAddress": "G..." }` on success.
///
/// # Tool annotations
///
/// - `readOnlyHint = false` — creates a signature over the message.
/// - `destructiveHint = false` — signing does not submit a transaction.
///
/// # SEP-43 reference
///
/// `sep-0043.md` lines :90-100 — `signMessage(message, opts?)`.
///
/// # Errors
///
/// Returns a tool-level error when:
/// - `chain_id` does not match the profile.
/// - `message` is empty.
/// - The signer is overlaid, conflicts with local scope, or belongs to a mainnet sibling.
/// - The profiles directory or a sibling cannot be read.
/// - The audit writer or signer keyring entry cannot be loaded.
///
/// # Examples
///
/// ```json
/// { "chain_id": "stellar:testnet", "message": "hello stellar" }
/// ```
#[mcp_tool_router]
#[tool_router(router = sep43_sign_message_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_sep43_sign_message",
        destructive_hint = false,
        read_only_hint = false,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_sep43_sign_message",
        description = "Sign an arbitrary UTF-8 message (SEP-43 signMessage). \
                       Signs the SEP-53 prefixed digest SHA-256('Stellar Signed Message:\\n' + message). \
                       Returns { signedMessage: string (base64), signerAddress: string }. \
                       read_only_hint=false; destructive_hint=false.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn stellar_sep43_sign_message(
        &self,
        Parameters(args): Parameters<Sep43SignMessageArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Mainnet structural refusal — before any key access or signing.
        // This tool returns a signature the caller can use externally; refuse on
        // a mainnet profile so no mainnet signature is ever produced. Wire code:
        // network.mainnet_write_forbidden.
        if self.context.chain_id.is_mainnet() {
            return Ok(crate::tools::common::mainnet_signing_forbidden_result());
        }

        let args_value = json!({
            "chain_id": &args.chain_id,
            "message_len": args.message.len(),
        });
        // Single-shot sign tool: a RequireApproval verdict is fail-closed.
        // The two-phase approval flow is not supported on this path.
        let dispatch_outcome = match self
            .dispatch_gate("stellar_sep43_sign_message", &args_value, &args.chain_id)
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

        let audit_writer = match self.message_signing_preflight() {
            Ok(writer) => writer,
            Err(refusal) => return Ok(refusal),
        };

        use std::sync::Arc;
        use stellar_agent_network::keyring::enrolled_keyring_signer;
        use stellar_agent_sep43::StellarAgentModule;
        use stellar_agent_sep43::module::ModuleAdapter;

        let account = self.profile.mcp_signer_default.account.as_str();

        let signer_handle = match enrolled_keyring_signer(
            &self.profile_name_for_approval(),
            &self.profile,
            account,
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

        let signer_g = account.to_owned();
        let profile = Arc::clone(&self.profile);
        let signer: Arc<dyn stellar_agent_network::signing::Signer + Send + Sync> =
            Arc::new(signer_handle);
        let module = StellarAgentModule::new(profile, signer);

        match module
            .sign_message(
                &args.message,
                args.network_passphrase.as_deref(),
                args.address.as_deref(),
            )
            .await
        {
            Ok(value) => {
                // The signature exists; audit append failures warn and preserve the result.
                crate::tools::value_audit::emit_value_audit_row_with_writer(
                    &audit_writer,
                    &self.profile_name_for_approval(),
                    crate::tools::message_signing::message_signed_row(
                        "stellar_sep43_sign_message",
                        args.chain_id.as_str(),
                        args.message.as_bytes(),
                        &signer_g,
                    ),
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
    /// Calls `stellar_sep43_sign_message` with the given args, bypassing the
    /// rmcp transport.
    ///
    /// Integration-test entry point for handler-level checks.
    ///
    /// # Errors
    ///
    /// Propagates `rmcp::ErrorData` from the `dispatch_gate` preamble (e.g.
    /// chain_id mismatch, policy deny, `RequireApproval` fail-closed).
    /// Signing errors are returned as `Ok(CallToolResult)` with
    /// `is_error = Some(true)`.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Feature gate
    ///
    /// Gated on the `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_sep43_sign_message(
        &self,
        args: Sep43SignMessageArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_sep43_sign_message(rmcp::handler::server::wrapper::Parameters(args))
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
    use stellar_agent_core::policy::{ApprovalRequest, Decision, PolicyEngine, PolicyError};
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
        ) -> Result<Decision, PolicyError> {
            Ok(Decision::RequireApproval(ApprovalRequest::new(
                "test-nonce".into(),
                120,
            )))
        }
    }

    fn make_require_approval_server() -> crate::server::WalletServer {
        use std::sync::Arc;
        let mut server = crate::server::WalletServer::new(
            Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
                .with_noop_engine()
                .build(),
        )
        .expect("WalletServer::new must not fail in tests");
        server.policy_engine = Arc::new(RequireApprovalEngine);
        server
    }

    fn make_mainnet_server() -> crate::server::WalletServer {
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

    /// A mainnet profile MUST refuse `stellar_sep43_sign_message` structurally
    /// before any key access: the result is the normalised business-error
    /// envelope carrying the canonical `network.mainnet_write_forbidden` wire
    /// code, and it MUST NOT contain a `signedMessage`.
    ///
    /// The keyring mock is intentionally NOT installed, and the message asserts
    /// the refusal did not reach the keyring (no `keyring`/`unlock` string), so a
    /// regressed guard that let signing proceed via a leaked key path fails here.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn mainnet_profile_refuses_before_signing_no_signature_produced() {
        let server = make_mainnet_server();
        let args = Sep43SignMessageArgs {
            chain_id: "stellar:mainnet".to_owned(),
            message: "hello stellar".to_owned(),
            network_passphrase: None,
            address: None,
        };
        let result = server
            .call_stellar_sep43_sign_message(args)
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
            !text.contains("signedMessage"),
            "no signature must be produced on mainnet; got: {text}"
        );
    }

    #[tokio::test]
    async fn sign_message_mainnet_refusal_reads_context() {
        use crate::tools::common::{assert_business_envelope, mainnet_signing_forbidden_result};
        let profile = Profile::builder_testnet_named("context", "s", "a", "n", "a")
            .with_noop_engine()
            .build();
        let mut server = crate::server::WalletServer::new(profile).unwrap();
        server.context = stellar_agent_network::NetworkContext::new(
            stellar_agent_core::profile::caip2::Caip2::Mainnet,
            server.profile.rpc_url.clone(),
        );
        let result = server
            .stellar_sep43_sign_message(rmcp::handler::server::wrapper::Parameters(
                crate::tools::sep43_sign_message::Sep43SignMessageArgs {
                    chain_id: "stellar:testnet".to_owned(),
                    message: "context pin".to_owned(),
                    network_passphrase: None,
                    address: None,
                },
            ))
            .await
            .unwrap();
        let (code, message, _) = assert_business_envelope(&result);
        let (expected_code, expected_message, _) =
            assert_business_envelope(&mainnet_signing_forbidden_result());
        assert_eq!(code, expected_code);
        assert_eq!(message, expected_message);
    }

    /// A `RequireApproval` policy verdict on `stellar_sep43_sign_message` must
    /// fail closed with the normalised business-error envelope carrying wire code
    /// `policy.approval_required_unsupported`, and MUST NOT produce a signature.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn require_approval_verdict_is_fail_closed_no_signature_produced() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let server = make_require_approval_server();
        let args = Sep43SignMessageArgs {
            chain_id: "stellar:testnet".to_owned(),
            message: "hello stellar".to_owned(),
            network_passphrase: None,
            address: None,
        };
        let result = server.call_stellar_sep43_sign_message(args).await.expect(
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

    fn message_args() -> Sep43SignMessageArgs {
        Sep43SignMessageArgs {
            chain_id: "stellar:testnet".to_owned(),
            message: crate::tools::message_signing_tests::MESSAGE.to_owned(),
            network_passphrase: None,
            address: None,
        }
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn message_scope_scenario_a_refuses_before_key_access() {
        let fixture = crate::tools::message_signing_tests::Fixture::new();
        fixture.mainnet_sibling(false);
        let result = fixture
            .server()
            .call_stellar_sep43_sign_message(message_args())
            .await
            .unwrap();
        crate::tools::message_signing_tests::assert_refusal(&result, "profile.key_scope_conflict");
        let (_, message, text) = crate::tools::common::assert_business_envelope(&result);
        assert!(message.contains("mainnet"));
        assert!(!text.contains("keyring"));
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn message_scope_scenario_b_refuses_signer_overlay() {
        let mut fixture = crate::tools::message_signing_tests::Fixture::new();
        fixture.overlay_mainnet_signer();
        let result = fixture
            .server()
            .call_stellar_sep43_sign_message(message_args())
            .await
            .unwrap();
        crate::tools::message_signing_tests::assert_refusal(
            &result,
            "profile.non_overlayable_field",
        );
        let (_, message, text) = crate::tools::common::assert_business_envelope(&result);
        assert!(message.contains("message signing"));
        assert!(!text.contains("keyring"));
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn message_scope_refuses_testnet_shared_signer_coordinate() {
        let fixture = crate::tools::message_signing_tests::Fixture::new();
        let mut sibling = fixture.mainnet_sibling(true);
        sibling.chain_id = stellar_agent_core::profile::caip2::Caip2::Testnet;
        stellar_agent_core::profile::loader::save_to_dir(
            "main",
            &sibling,
            &fixture.dir.path().join("profiles"),
        )
        .unwrap();
        let result = fixture
            .server()
            .call_stellar_sep43_sign_message(message_args())
            .await
            .unwrap();
        crate::tools::message_signing_tests::assert_refusal(&result, "profile.key_scope_conflict");
        let (_, message, _) = crate::tools::common::assert_business_envelope(&result);
        assert!(message.contains("also named") || message.contains("also names"));
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn message_signing_records_one_redacted_row_and_verifies() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fixture = crate::tools::message_signing_tests::Fixture::new();
        fixture.seed_signer();
        fixture.seed_audit();
        let result = fixture
            .server()
            .call_stellar_sep43_sign_message(message_args())
            .await
            .unwrap();
        fixture.assert_signed_row(
            &result,
            "stellar_sep43_sign_message",
            "signedMessage",
            "signerAddress",
        );
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn message_signing_unacquirable_audit_writer_refuses_before_signer_load() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let mut fixture = crate::tools::message_signing_tests::Fixture::new();
        fixture.seed_audit();
        fixture.profile.audit_log_path = fixture.dir.path().to_path_buf();
        let result = fixture
            .server()
            .call_stellar_sep43_sign_message(message_args())
            .await
            .unwrap();
        crate::tools::message_signing_tests::assert_refusal(&result, "audit.chain_key_unavailable");
    }
}
