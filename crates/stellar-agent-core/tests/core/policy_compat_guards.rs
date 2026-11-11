//! Compatibility guards for signed version 2 policies.
//!
//! An existing signed version 2 document keeps loading, keeps its canonical
//! bytes and digest, and keeps its counterparty denial byte for byte.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]

use ed25519_dalek::{Signer as _, SigningKey};
use stellar_agent_core::{
    policy::{
        DenyReason, McpToolRegistration, ToolDescriptor, ToolValueKind,
        v1::{
            EvalContext, PolicyStateStore,
            canonical::canonical_bytes,
            loader::load_signed_policy_text,
            mainnet_minimum,
            value::{ActionKind, ValueClass, ValueLeg},
        },
    },
    profile::{caip2::MAINNET_PASSPHRASE, schema::Profile},
};
use toml_edit::DocumentMut;

pub(crate) const FIXTURE: &str = include_str!("../fixtures/policy-v2.toml");

/// The canonical bytes the owner signature of the fixture covers.
pub(crate) const FIXTURE_CANONICAL: &str = r#"version = 2
scope = "profile:operator"
sequence = 7

[mainnet]
profile = "operator"
endpoint_host = "rpc.example.invalid"
installation_nonce_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
classic_max_fee_per_op_stroops = 500
authorization_ttl_seconds = 60
approval_credentials = [{ credential_id_b64url = "WlpaWlpaWlpaWlpaWlpaWg", public_key_sec1_b64url = "BEYtuhrk_BqWi02s8gzdbb4frjSqlxUUpj00BcPRz9ODtYu7CMEzg0KMWFPHHEyFHhNLBWgh5Gj-Cpd6v0MT3eE" }]

[mainnet.cross_check_thresholds]
"USD:GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF" = "100"
native = "10000000000"

[[rules]]
match = { chain = "stellar:mainnet", tool = "stellar_pay" }
criteria = [{ assets = ["native"], kind = "asset_allowlist" }, { allowlist = ["GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"], kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"] }, { asset = "native", kind = "per_tx_cap", max_stroops = "100" }, { asset = "native", kind = "per_period_cap", max_stroops = "200", window = "1d" }, { kind = "rate_limit", max_calls = 10, window = "1d" }]
decision = "require_approval"
reason = "review"
ttl_secs = 3600
allow_opaque_signing = false
"#;

/// The BLAKE3 digest of [`FIXTURE_CANONICAL`], in lowercase hex.
pub(crate) const FIXTURE_DIGEST_HEX: &str =
    "27215114bd1abcb23ed88923946dead88dde5de7251c571e2ee4adc451b3bc74";

/// A well-formed account outside the fixture's counterparty allowlist.
const UNLISTED: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

/// The fixed evaluation time of the guards, in Unix milliseconds.
const NOW_MS: u64 = 1_700_000_000_000;

fn mainnet_profile() -> Profile {
    Profile::builder_mainnet_named(
        "operator",
        "https://rpc.example.invalid",
        "s",
        "a",
        "n",
        "a",
    )
    .build()
}

fn owner_key() -> SigningKey {
    SigningKey::from_bytes(&[11; 32])
}

/// Signs `raw` with `key` over the BLAKE3 digest of its canonical bytes.
fn signed(raw: &str, key: &SigningKey) -> String {
    let canonical = canonical_bytes(raw).unwrap();
    let signature = key.sign(blake3::hash(&canonical).as_bytes());
    format!(
        "{raw}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
        stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes()),
        stellar_agent_core::hex::encode(&signature.to_bytes())
    )
}

#[test]
fn existing_v2_loads_unchanged() {
    let key = owner_key();
    let document = load_signed_policy_text(
        &signed(FIXTURE, &key),
        "operator",
        &key.verifying_key().to_bytes(),
        MAINNET_PASSPHRASE,
    )
    .unwrap();
    assert_eq!(document.version, 2);
    assert_eq!(document.rules.len(), 1);
    let kinds: Vec<_> = document.rules[0]
        .criteria
        .iter()
        .map(|c| c.kind())
        .collect();
    assert_eq!(
        kinds,
        [
            "asset_allowlist",
            "counterparty_allowlist",
            "per_tx_cap",
            "per_period_cap",
            "rate_limit"
        ]
    );
    let doc = FIXTURE.parse::<DocumentMut>().unwrap();
    mainnet_minimum::validate(&doc, &mainnet_profile(), "operator").unwrap();
}

#[test]
fn existing_v2_canonical_bytes_and_digest_match_literals() {
    let canonical = canonical_bytes(FIXTURE).unwrap();
    assert_eq!(
        String::from_utf8(canonical.clone()).unwrap(),
        FIXTURE_CANONICAL
    );
    assert_eq!(
        stellar_agent_core::hex::encode(blake3::hash(&canonical).as_bytes()),
        FIXTURE_DIGEST_HEX
    );
}

#[test]
fn counterparty_deny_mode_is_byte_identical() {
    let key = owner_key();
    let document = load_signed_policy_text(
        &signed(FIXTURE, &key),
        "operator",
        &key.verifying_key().to_bytes(),
        MAINNET_PASSPHRASE,
    )
    .unwrap();
    let criterion = document.rules[0]
        .criteria
        .iter()
        .find(|c| c.kind() == "counterparty_allowlist")
        .unwrap();
    let tool = ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_pay",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    });
    let profile = mainnet_profile();
    let args = serde_json::json!({
        "destination": UNLISTED,
        "asset": "native",
        "amount_stroops": "50",
    });
    let store = PolicyStateStore::new();
    let ctx = EvalContext::new(
        &tool,
        &args,
        "operator",
        &profile,
        &store,
        1_700_000_000_000,
    )
    .with_value(ValueClass::single(ValueLeg {
        kind: ActionKind::Payment,
        amount: Some(50),
        asset: Some("native".to_owned()),
        destination: Some(UNLISTED.to_owned()),
    }));
    let denial: DenyReason = criterion.evaluate(&ctx).unwrap().unwrap();
    assert_eq!(
        serde_json::to_string(&denial).unwrap(),
        format!(r#"{{"CounterpartyDenied":{{"kind":"G_ACCOUNT","value":"{UNLISTED}"}}}}"#)
    );
    assert_eq!(denial.code(), "counterparty_denied");
    assert_eq!(denial.wire_code(), "policy.deny.counterparty_denied");
    let error = stellar_agent_core::error::WalletError::PolicyDenied {
        reason: Box::new(denial),
    };
    assert_eq!(error.code(), "policy.deny.counterparty_denied");
}

#[test]
fn absent_origin_keys_keep_canonical_bytes() {
    let v1 = "version = 1\nscope = \"profile:operator\"\n[[rules]]\nmatch = { tool = \"stellar_balances\", chain = \"*\" }\ncriteria = []\ndecision = \"allow\"\n";
    let v2 = v1.replace("version = 1", "version = 2\nsequence = 7");
    let expected = [
        (
            "version = 1\nscope = \"profile:operator\"\n\n[[rules]]\nmatch = { tool = \"stellar_balances\", chain = \"*\" }\ncriteria = []\ndecision = \"allow\"\n",
            "11db81b838a1f823ea6534c98b2c20939fdd84750aee8e4a0399b071dd0f5df7",
            "7fccb1671fd1d35fa12de252cd3a3f38d02e34a884a7acd3f166a6f74295d0eb3cd56b7845858d51437ad4a0bcc36cf2683f66bb7bd76a613bff70cd2e299004",
        ),
        (
            "version = 2\nscope = \"profile:operator\"\nsequence = 7\n\n[[rules]]\nmatch = { chain = \"*\", tool = \"stellar_balances\" }\ncriteria = []\ndecision = \"allow\"\n",
            "3f5dbe3df74a7499e75e93ca1f6f907ea2de22f6aa232669e192955064acd334",
            "e1b7f1d7d27bc3cf78f0ef6fe4202a5e428700e35c1e4dbd3b9cfc1f529fd35a886522205a1f30956cca8c3283fd4e4e7753be0c47c7ad9eedf7afcf6fe0540c",
        ),
        (
            FIXTURE_CANONICAL,
            "27215114bd1abcb23ed88923946dead88dde5de7251c571e2ee4adc451b3bc74",
            "2405f4764555bdb0c2a4dee21c4f213c2b74df40759eaf2f432fde5e2c45df7fba196e0684c1b71337a25965e7ea75335830090d49438c3a22aecbc2b103f205",
        ),
    ];
    for (raw, (expected_bytes, expected_digest, expected_sig)) in
        [v1, v2.as_str(), FIXTURE].into_iter().zip(expected)
    {
        let bytes = canonical_bytes(raw).unwrap();
        let digest = blake3::hash(&bytes);
        let sig = owner_key().sign(digest.as_bytes());
        assert_eq!(bytes, expected_bytes.as_bytes());
        assert_eq!(digest.to_hex().as_str(), expected_digest);
        assert_eq!(
            stellar_agent_core::hex::encode(&sig.to_bytes()),
            expected_sig
        );
        load_signed_policy_text(
            &signed(raw, &owner_key()),
            "operator",
            &owner_key().verifying_key().to_bytes(),
            MAINNET_PASSPHRASE,
        )
        .unwrap();
    }
}

#[test]
fn absent_origin_keys_keep_evaluation() {
    use stellar_agent_core::policy::{
        ApprovalRequest, Decision, PolicyEngine,
        v1::{PolicyEngineV1, criteria::counterparty_allowlist::RecipientClass},
    };
    let mut tool = ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_pay",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    });
    tool.chain_id = "stellar:mainnet".into();
    let args = serde_json::json!({"destination": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF", "asset": "native", "amount_stroops": "50"});
    // A leading rule for another tool moves the deciding rule to ordinal 1.
    let leading = "[[rules]]\nmatch = { chain = \"stellar:mainnet\", tool = \"stellar_balances\" }\ncriteria = []\ndecision = \"allow\"\n\n[[rules]]";
    for (decision, ordinal) in [
        ("allow", 0),
        ("require_approval", 0),
        ("deny", 0),
        ("allow", 1),
        ("require_approval", 1),
        ("deny", 1),
    ] {
        let raw = FIXTURE.replace(
            "decision = \"require_approval\"",
            &format!("decision = \"{decision}\""),
        );
        let raw = if ordinal == 1 {
            raw.replace("[[rules]]", leading)
        } else {
            raw
        };
        let raw = if decision == "require_approval" {
            raw
        } else {
            raw.replace("reason = \"review\"\n", "")
                .replace("ttl_secs = 3600\n", "")
        };
        let document = load_signed_policy_text(
            &signed(&raw, &owner_key()),
            "operator",
            &owner_key().verifying_key().to_bytes(),
            MAINNET_PASSPHRASE,
        )
        .unwrap();
        let engine = PolicyEngineV1::new(document, "operator".into());
        let result = engine
            .evaluate_full(
                &tool,
                &args,
                &mainnet_profile(),
                None,
                None,
                None,
                None,
                None,
                NOW_MS,
            )
            .unwrap();
        let expected = match decision {
            "allow" => Decision::Allow,
            "require_approval" => Decision::RequireApproval(
                ApprovalRequest::new(String::new(), 3600).with_reason("review".into()),
            ),
            _ => Decision::Deny(DenyReason::ExplicitRuleDeny),
        };
        assert_eq!(result.decision, expected);
        assert!(!result.provisional);
        assert_eq!(result.rule_ordinal, Some(ordinal));
        if decision == "deny" {
            assert!(result.value_effects.is_none());
        } else {
            let effects = result.value_effects.unwrap();
            assert_eq!(
                effects.legs(),
                &[ValueLeg {
                    kind: ActionKind::Payment,
                    amount: Some(50),
                    asset: Some("native".into()),
                    destination: Some(
                        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".into()
                    ),
                }]
            );
            assert_eq!(effects.memo(), None);
            assert_eq!(effects.recipient_class(), Some(RecipientClass::Listed));
        }
        let provisional = engine
            .evaluate_provisional(
                &tool,
                &args,
                &mainnet_profile(),
                stellar_agent_core::policy::v1::value::derive_value_class("stellar_pay", &args),
                None,
                None,
                None,
                None,
                None,
                NOW_MS,
            )
            .unwrap();
        assert_eq!(provisional.decision, expected);
        assert!(provisional.provisional);
        assert_eq!(provisional.rule_ordinal, Some(ordinal));
    }
}
