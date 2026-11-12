//! Decision authority at every classic CLI value boundary.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test assertions")]

use serde_json::{Value, json};
use stellar_agent_core::policy::v1::{canonical::canonical_bytes, signature::digest};

use crate::commands::accounts::create::tests::mainnet_full as create;
use crate::commands::claim::tests::mainnet_full as claim;
use crate::commands::pay::tests::mainnet_full as pay;
use crate::commands::trustline::tests::mainnet_full as trustline;
use crate::common::mainnet_write_fixture::{
    AGENT_SEED, DESTINATION, ISSUER, MainnetFixture, Spec, claim_rule, create_rule, pay_rule,
    trustline_rule,
};
use crate::common::signer_ceremony::signer_resolutions_on_this_thread;
use crate::test_rpc::ClassicRpc;

#[derive(Clone, Copy)]
enum Verb {
    Pay,
    Claim,
    Create,
    Trustline,
}

impl Verb {
    const ALL: [Self; 4] = [Self::Pay, Self::Claim, Self::Create, Self::Trustline];

    fn rule(self, decision: &str, extra: &str) -> String {
        match self {
            Self::Pay => pay_rule(decision, extra),
            Self::Claim => claim_rule(decision, extra),
            Self::Create => create_rule(decision, extra),
            Self::Trustline => trustline_rule(decision, extra),
        }
    }

    fn index(self) -> u32 {
        match self {
            Self::Pay => 0,
            Self::Create => 1,
            Self::Claim => 2,
            Self::Trustline => 3,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Pay => "pay",
            Self::Claim => "claim",
            Self::Create => "accounts create",
            Self::Trustline => "trustline",
        }
    }

    fn tool(self) -> &'static str {
        match self {
            Self::Pay => "stellar_pay",
            Self::Claim => "stellar_claim",
            Self::Create => "stellar_create_account",
            Self::Trustline => "stellar_trustline",
        }
    }

    fn ledger(self) -> ClassicRpc {
        let agent = stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED);
        match self {
            Self::Pay | Self::Create => ClassicRpc::mainnet(&[&agent, DESTINATION, ISSUER]),
            Self::Claim => claim::ledger(true, 100_000_000),
            Self::Trustline => trustline::ledger(true, 0),
        }
    }

    fn spec(self, name: &'static str) -> Spec {
        Spec::new(name).primary(self.ledger()).oracle(self.ledger())
    }

    async fn run(self, fixture: &MainnetFixture) -> (i32, Value) {
        match self {
            Self::Pay => {
                crate::common::render::take_rendered_for_test();
                let code = pay::run_code(fixture, &pay::mainnet_args(fixture)).await;
                let documents = crate::common::render::take_rendered_for_test();
                assert_eq!(documents.len(), 1, "one stdout envelope");
                (code, documents.into_iter().next().unwrap())
            }
            Self::Claim => {
                let r = claim::run(fixture, &claim::mainnet_args(fixture)).await;
                (r.code, r.envelope)
            }
            Self::Create => {
                crate::common::render::take_rendered_for_test();
                let code = create::run_code(fixture, &create::mainnet_args(fixture)).await;
                let documents = crate::common::render::take_rendered_for_test();
                assert_eq!(documents.len(), 1, "one stdout envelope");
                (code, documents.into_iter().next().unwrap())
            }
            Self::Trustline => {
                let r = trustline::run(fixture, &trustline::mainnet_args(fixture)).await;
                (r.code, r.envelope)
            }
        }
    }
}

/// Asserts the governing policy facts on the pending value row.
pub(crate) fn assert_provenance(fixture: &MainnetFixture, approval: bool, index: u32) {
    let raw = std::fs::read_to_string(fixture.policy_path()).unwrap();
    let expected = stellar_agent_core::hex::encode(&digest(&canonical_bytes(&raw).unwrap()));
    assert_eq!(expected.len(), 64);
    let rows = fixture.audit_rows("value_action_pending");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["policy_digest"], expected);
    assert_eq!(rows[0]["rule_index"], index);
    assert_eq!(
        rows[0]["policy_decision"],
        if approval {
            "require_approval"
        } else {
            "allow"
        }
    );
}

/// Asserts signature, authority, consent, and audit properties after submission.
pub(crate) async fn assert_authorized(fixture: &MainnetFixture, approval: bool, index: u32) {
    let sent = fixture.sent_envelopes().await;
    assert_eq!(sent.len(), 1);
    fixture.assert_signed_by_agent(&sent[0]);
    assert_provenance(fixture, approval, index);
    let body = fixture.window_body();
    let records = body["authorizations"].as_array().unwrap();
    assert!(!records.is_empty());
    for record in records {
        assert_eq!(
            record.get("policy_authority").is_none(),
            approval,
            "{record}"
        );
        assert_eq!(record.get("approval_nonce").is_some(), approval, "{record}");
    }
    if approval {
        assert_eq!(fixture.summaries().len(), 1);
        assert_eq!(fixture.audit_rows("approval_attested").len(), 1);
        let entries = fixture.pending_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind_name, "Consumed");
    } else {
        fixture.assert_no_consent_ceremony();
        assert!(fixture.pending_entries().is_empty());
        assert!(fixture.audit_rows("approval_attested").is_empty());
    }
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_value_verb_follows_the_decision() {
    let names = [
        [
            "authority-pay-allow",
            "authority-pay-approval",
            "authority-pay-refused",
        ],
        [
            "authority-claim-allow",
            "authority-claim-approval",
            "authority-claim-refused",
        ],
        [
            "authority-create-allow",
            "authority-create-approval",
            "authority-create-refused",
        ],
        [
            "authority-trustline-allow",
            "authority-trustline-approval",
            "authority-trustline-refused",
        ],
    ];
    for (verb, names) in Verb::ALL.into_iter().zip(names) {
        for (row, name) in names.into_iter().enumerate() {
            let approval = row != 0;
            let spec = verb.spec(name);
            let spec = if approval {
                spec
            } else {
                spec.rules(vec![verb.rule("allow", "")])
            };
            let mut fixture = spec.build().await;
            fixture.present_with(crate::common::mainnet_presence::driver::credential(
                stellar_agent_test_support::webauthn::fixture_authenticator(),
                if row == 1 { 5 } else { 1 },
            ));
            let before = signer_resolutions_on_this_thread();
            let (code, envelope) = verb.run(&fixture).await;
            if row == 2 {
                assert_eq!(code, 1, "{envelope}");
                assert_eq!(envelope["error"]["code"], "approval.presence_invalid");
                assert_eq!(signer_resolutions_on_this_thread(), before);
                assert!(fixture.sent_envelopes().await.is_empty());
                assert!(fixture.pending_entries().is_empty());
                assert!(fixture.audit_rows("approval_attested").is_empty());
            } else {
                assert_eq!(code, 0, "{envelope}");
                assert_eq!(signer_resolutions_on_this_thread(), before + 1);
                assert_authorized(&fixture, approval, if approval { verb.index() } else { 0 })
                    .await;
            }
            assert_eq!(fixture.ceremonies().len(), usize::from(approval));
        }
    }
    for (verb, name) in Verb::ALL.into_iter().zip([
        "authority-pay-hold",
        "authority-claim-hold",
        "authority-create-hold",
        "authority-trustline-hold",
    ]) {
        let fixture = verb
            .spec(name)
            .rules(vec![verb.rule("allow", "")])
            .primary(verb.ledger().with_script(|method, _, _| {
                (method == "getTransaction").then(|| {
                    json!({
                        "status": "FAILED", "latestLedger": 1006, "oldestLedger": 1,
                        "resultXdr": "AAAAAAAAAGT////7AAAAAA=="
                    })
                })
            }))
            .build()
            .await;
        let (code, envelope) = verb.run(&fixture).await;
        assert_eq!(code, 1, "{envelope}");
        assert_eq!(envelope["error"]["code"], "submission.tx_timeout");
        assert_eq!(fixture.pending_reservations(), 1);
        assert_authorized(&fixture, false, 0).await;
    }
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn require_approval_pending_row_carries_provenance() {
    for (verb, name) in Verb::ALL.into_iter().zip([
        "provenance-pay",
        "provenance-claim",
        "provenance-create",
        "provenance-trustline",
    ]) {
        let fixture = verb.spec(name).build().await;
        let (code, envelope) = verb.run(&fixture).await;
        assert_eq!(code, 0, "{envelope}");
        assert_provenance(&fixture, true, verb.index());
    }
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn cli_policy_refusals_render_once_at_the_boundary() {
    use crate::commands::policy_engine::{
        claim_policy_args, create_policy_args, evaluate_mainnet_policy, load_mainnet_policy_engine,
        pay_policy_args, trustline_policy_args,
    };
    use crate::common::mainnet_confirm::render_authority_refusal;
    use crate::common::mainnet_write::{mainnet_context, mainnet_profiles_dir};
    use crate::common::mainnet_write_fixture::{NEW_ACCOUNT, TRUSTLINE_ASSET};
    use stellar_agent_core::mainnet::decision::MainnetRefusal;
    use stellar_agent_core::policy::ToolValueKind;
    use stellar_agent_core::profile::name::{ProfileNameSource, resolve_profile_name};
    use stellar_agent_network::mainnet::authority::AuthorityRefusal;
    let names = [
        [
            "boundary-pay-deny",
            "boundary-pay-engine",
            "boundary-pay-clock",
        ],
        [
            "boundary-claim-deny",
            "boundary-claim-engine",
            "boundary-claim-clock",
        ],
        [
            "boundary-create-deny",
            "boundary-create-engine",
            "boundary-create-clock",
        ],
        [
            "boundary-trustline-deny",
            "boundary-trustline-engine",
            "boundary-trustline-clock",
        ],
    ];
    for (verb, names) in Verb::ALL.into_iter().zip(names) {
        for (case, name) in names.into_iter().enumerate() {
            let extra = if case == 1 {
                "{ kind = \"sep10_session_active\" },".to_owned()
            } else {
                String::new()
            };
            let fixture = verb
                .spec(name)
                .rules(vec![
                    verb.rule(if case == 0 { "deny" } else { "allow" }, &extra),
                ])
                .build()
                .await;
            let context = mainnet_context(
                &fixture.profile(),
                &resolve_profile_name(Some(name)),
                Default::default(),
            )
            .unwrap();
            let policy = load_mainnet_policy_engine(
                verb.name(),
                "policy.engine_unavailable",
                &context,
                ProfileNameSource::Flag,
                &mainnet_profiles_dir().unwrap(),
            )
            .unwrap();
            let args = match verb {
                Verb::Pay => pay_policy_args(10_000_000, "native", DESTINATION),
                Verb::Claim => claim_policy_args("00000000"),
                Verb::Create => create_policy_args(20_000_000, NEW_ACCOUNT),
                Verb::Trustline => trustline_policy_args(&fixture.agent.g, TRUSTLINE_ASSET),
            };
            let _clock = (case == 2).then(stellar_agent_core::policy::v1::criteria::state_store::set_policy_clock_error_for_test);
            let Err(refusal) = evaluate_mainnet_policy(
                &policy.verified,
                context.profile(),
                verb.tool(),
                ToolValueKind::MovesValue,
                context.chain().caip2_str(),
                &args,
                None,
                None,
            ) else {
                panic!("the evaluation must refuse")
            };
            match (&refusal, case) {
                (AuthorityRefusal::Refusal(MainnetRefusal::Denied { .. }), 0)
                | (AuthorityRefusal::Refusal(MainnetRefusal::Engine(_)), 1)
                | (AuthorityRefusal::Refusal(MainnetRefusal::Clock(_)), 2) => {}
                _ => panic!("unexpected typed refusal: {refusal:?}"),
            }
            let (code, message) = match case {
                0 => ("policy.deny.explicit_rule_deny", format!("{} operation denied by operator policy", verb.name())),
                1 => ("policy.engine_required", format!("criterion evaluation failed: sep10_session_active criterion configured for tool '{}' but sep10_sessions view was not populated by the dispatch site; EvalContext::with_sep10_sessions() required", verb.tool())),
                _ => ("wallet.clock_error", "system clock error: wallet clock error: policy clock unavailable (test injection)".to_owned()),
            };
            let mut envelope = render_authority_refusal(verb.name(), refusal);
            envelope.request_id = "guard".to_owned();
            let expected = format!(
                "{{\"ok\":false,\"error\":{{\"code\":\"{code}\",\"message\":\"{message}\"}},\"request_id\":\"guard\"}}"
            );
            assert_eq!(serde_json::to_string(&envelope).unwrap(), expected);
            let mut out = Vec::new();
            assert_eq!(
                crate::common::render::write_envelope(&mut out, &envelope, 1),
                1
            );
            assert_eq!(
                serde_json::from_slice::<Value>(&out).unwrap(),
                serde_json::from_str::<Value>(&expected).unwrap()
            );
            {
                let (exit, mut rendered) = verb.run(&fixture).await;
                assert_eq!(exit, 1, "{rendered}");
                rendered["request_id"] = json!("guard");
                let mut expected: Value = serde_json::from_str(&expected).unwrap();
                if matches!(verb, Verb::Claim) {
                    expected["error"]["details"] = json!({"preview": {
                        "amount_display": "10.0000000", "amount_stroops": "100000000",
                        "asset_code": null, "asset_issuer": null,
                        "balance_id_hex72": format!("00000000{}", "ab".repeat(32)),
                        "balance_id_strkey": "BAAKXK5LVOV2XK5LVOV2XK5LVOV2XK5LVOV2XK5LVOV2XK5LVOV2XK6UVM",
                        "claimants": [{"destination": fixture.agent.g, "predicate_kind": "Unconditional"}],
                        "clawback_enabled": false, "is_claimant": true, "predicate_satisfied": true,
                        "window": {"valid_from": null, "valid_until": null}
                    }});
                }
                assert_eq!(rendered, expected);
                fixture.assert_no_consent_ceremony();
                assert!(fixture.sent_envelopes().await.is_empty());
            }
        }
    }
    let source = include_str!("../commands/policy_engine.rs");
    let start = source
        .find("pub(crate) fn evaluate_mainnet_policy(")
        .unwrap();
    let body = &source[start..start + source[start..].find("\n}\n").unwrap()];
    assert!(!body.contains("Envelope"));
    assert!(!body.contains("render_authority_refusal"));
    assert!(!body.contains("unexpected_decision()"));
    assert!(body.contains("MainnetAuthority::from_decision(&decision, None)"));
    assert!(body.contains("AuthorityRefusal::Internal(error)"));
    for source in [
        include_str!("../commands/pay.rs"),
        include_str!("../commands/claim.rs"),
        include_str!("../commands/trustline.rs"),
        include_str!("../commands/accounts/create.rs"),
    ] {
        let start = source
            .find("let evaluation = match evaluate_mainnet_policy(")
            .unwrap();
        let boundary = &source[start..start + source[start..].find("\n    };").unwrap()];
        assert_eq!(boundary.matches("render_authority_refusal(").count(), 1);
    }
}
