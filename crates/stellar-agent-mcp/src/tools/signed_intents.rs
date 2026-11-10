//! Read-only inspection of authenticated smart-account intent charges.

use crate::server::WalletServer;
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_mcp_macros::mcp_tool_router;

/// Arguments for the active profile's retained intent view.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde", deny_unknown_fields)]
pub struct SignedIntentsArgs {}

#[mcp_tool_router]
#[tool_router(router = signed_intents_tool_router, vis = "pub(crate)")]
impl WalletServer {
    /// Lists retained charges without writing wallet state.
    #[mcp_tool_item(
        name = "stellar_signed_intents_list",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = false,
        value_kind = "read_only"
    )]
    #[tool(
        name = "stellar_signed_intents_list",
        description = "List authenticated smart-account intent charges. The view reports the accounting horizon, retention boundary, purpose, schedule terminal state, and reset requirements without changing state.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn stellar_signed_intents_list(
        &self,
        Parameters(_args): Parameters<SignedIntentsArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let chain = self.profile.chain_id.caip2_str();
        if let Err(error) = self
            .dispatch_gate("stellar_signed_intents_list", &serde_json::json!({}), chain)
            .await
        {
            return error.into_result();
        }
        let intents = match self
            .window_store
            .signed_intents(&self.profile_name_for_approval(), &self.profile)
        {
            Ok(intents) => intents,
            Err(_) => {
                return Ok(super::common::business_error_result(
                    "submission.record_unavailable",
                    "the authenticated intent window is unavailable",
                ));
            }
        };
        let envelope = Envelope::ok(serde_json::json!({ "signed_intents": intents }));
        let json = envelope.to_json_pretty().map_err(|_| {
            rmcp::ErrorData::internal_error("intent view serialization refuses", None)
        })?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture assertions")]
    use super::*;

    struct DenyIntentList;

    impl stellar_agent_core::policy::PolicyEngine for DenyIntentList {
        fn evaluate(
            &self,
            tool: &stellar_agent_core::policy::ToolDescriptor,
            _args: &serde_json::Value,
            _profile: &stellar_agent_core::profile::schema::Profile,
            _account_view: Option<&dyn stellar_agent_core::policy::v1::AccountReservesView>,
            _identity_view: Option<&dyn stellar_agent_core::policy::v1::AccountIdentityView>,
            _counterparty_cache: Option<&dyn stellar_agent_core::policy::v1::CounterpartyCacheView>,
            _sep10_sessions: Option<&dyn stellar_agent_core::policy::v1::Sep10SessionView>,
            _sep45_sessions: Option<&dyn stellar_agent_core::policy::v1::Sep45SessionView>,
            _now_ms: u64,
        ) -> Result<stellar_agent_core::policy::Decision, stellar_agent_core::policy::PolicyError>
        {
            assert_eq!(tool.name, "stellar_signed_intents_list");
            Ok(stellar_agent_core::policy::Decision::Deny(
                stellar_agent_core::policy::DenyReason::NoMatchingRule,
            ))
        }
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn intent_view_reads_without_writing_and_refuses_tampering() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let profile = stellar_agent_core::profile::schema::Profile::builder_testnet_named(
            "intent",
            "view",
            "account",
            "view-nonce",
            "account",
        )
        .with_noop_engine()
        .build();
        let store =
            stellar_agent_network::policy_state::PersistedWindowStore::for_profile("intent");
        stellar_agent_network::signed_intent::test_helpers::seed_two_intents(&profile, &store)
            .unwrap();
        let mut server = WalletServer::new(profile.clone()).unwrap();
        server.window_store = store.clone();
        server.policy_engine =
            std::sync::Arc::new(stellar_agent_core::policy::v1::PolicyEngineV1::new(
                stellar_agent_core::policy::v1::loader::PolicyDocument {
                    version: 1,
                    scope: stellar_agent_core::policy::v1::loader::ScopeId::AllProfiles,
                    rules: vec![stellar_agent_core::policy::v1::loader::PolicyRule {
                        r#match: stellar_agent_core::policy::v1::loader::RuleMatch {
                            tool: "*".into(),
                            chain: "*".into(),
                        },
                        criteria: vec![],
                        decision: stellar_agent_core::policy::Decision::Allow,
                        allow_opaque_signing: false,
                    }],
                    signature: None,
                },
                "intent".to_owned(),
            ));
        let before = std::fs::read(store.path()).unwrap();
        let key = &profile.policy_window_state_key_id;
        let generation = keyring_core::Entry::new(
            &key.service,
            &stellar_agent_core::profile::schema::generation_account(&key.account),
        )
        .unwrap();
        let generation_before = generation.get_password().unwrap();
        let result = server
            .stellar_signed_intents_list(Parameters(SignedIntentsArgs {}))
            .await
            .unwrap();
        let rmcp::model::RawContent::Text(text) = &result.content[0].raw else {
            panic!("text");
        };
        let value: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        let intents = value["data"]["signed_intents"].as_array().unwrap();
        assert_eq!(intents.len(), 2, "{value}");
        for intent in intents {
            assert_eq!(
                intent["status"],
                if intent["bound_tx_hash"].is_null() {
                    "authorization exposed, submission unknown"
                } else {
                    "authorization exposed, submission bound"
                }
            );
        }
        assert!(
            intents
                .iter()
                .any(|i| i["status"] == "authorization exposed, submission unknown")
        );
        assert!(
            intents
                .iter()
                .any(|i| i["status"] == "authorization exposed, submission bound")
        );
        assert!(intents.iter().all(|i| i["accounting_horizon"] == "open"));
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
        assert_eq!(generation.get_password().unwrap(), generation_before);
        let mut corrupt = before;
        corrupt[0] ^= 1;
        std::fs::write(store.path(), &corrupt).unwrap();
        let stateful_policy = server.policy_engine.clone();
        server.policy_engine = std::sync::Arc::new(DenyIntentList);
        let result = server
            .stellar_signed_intents_list(Parameters(SignedIntentsArgs {}))
            .await
            .unwrap();
        let rmcp::model::RawContent::Text(text) = &result.content[0].raw else {
            panic!("text");
        };
        let value: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        assert_eq!(value["error"]["code"], "policy.deny.no_matching_rule");
        assert!(value["data"].is_null());
        server.policy_engine = stateful_policy;
        let result = server
            .stellar_signed_intents_list(Parameters(SignedIntentsArgs {}))
            .await
            .unwrap();
        let rmcp::model::RawContent::Text(text) = &result.content[0].raw else {
            panic!("text");
        };
        let value: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        assert_eq!(value["error"]["code"], "policy.engine_required");
        assert_eq!(std::fs::read(store.path()).unwrap(), corrupt);
        assert_eq!(generation.get_password().unwrap(), generation_before);
    }
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial(keyring)]
    async fn intent_views_report_horizons_without_mutation() {
        use stellar_agent_network::intent_view_test_helpers::IntentViewFixture;
        for mode in ["invoke", "done", "unset", "unclassified"] {
            let fixture = IntentViewFixture::new(mode).await;
            let mut server = WalletServer::new(fixture.profile.clone()).unwrap();
            server.window_store = fixture.store.clone();
            for endpoint_state in ["complete", "missing", "unreadable"] {
                fixture.set_endpoints(endpoint_state);
                let result = server
                    .stellar_signed_intents_list(Parameters(SignedIntentsArgs {}))
                    .await
                    .unwrap();
                assert_ne!(result.is_error, Some(true));
                let text = result.content[0].as_text().unwrap();
                let envelope: serde_json::Value = serde_json::from_str(&text.text).unwrap();
                let value = envelope["data"]["signed_intents"].clone();
                assert_eq!(value.as_array().unwrap().len(), 1);
                fixture.assert_view(&value, endpoint_state);
                fixture.assert_unchanged().await;
            }
            for missing in [false, true] {
                fixture.damage_store(missing);
                let result = server
                    .stellar_signed_intents_list(Parameters(SignedIntentsArgs {}))
                    .await
                    .unwrap();
                assert_eq!(result.is_error, Some(true));
                let text = result.content[0].as_text().unwrap();
                let envelope: serde_json::Value = serde_json::from_str(&text.text).unwrap();
                assert_eq!(envelope["error"]["code"], "submission.record_unavailable");
                fixture.assert_resources_unchanged().await;
                if missing {
                    assert!(!fixture.store.path().exists());
                }
            }
        }
    }
}
