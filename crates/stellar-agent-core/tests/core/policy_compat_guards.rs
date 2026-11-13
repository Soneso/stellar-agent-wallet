//! Compatibility guards for signed version 2 policies.
//!
//! An existing signed version 2 document keeps loading, keeps its canonical
//! bytes and digest, and keeps its counterparty denial byte for byte. A
//! policy with equal `unlisted` tables on two rules reproduces its literal
//! bytes, digest, and signed text, loads, and decides as its tables state.

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
            criteria::state_store::policy_now_ms,
            loader::load_signed_policy_text,
            mainnet_minimum,
            value::{ActionKind, ValueClass, ValueLeg},
        },
    },
    profile::{
        caip2::{MAINNET_PASSPHRASE, TESTNET_PASSPHRASE},
        schema::Profile,
    },
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

/// A policy whose two rules carry equal `unlisted` tables.
const SHARED_BUDGET: &str = r#"version = 2
scope = "profile:operator"
sequence = 1

[[rules]]
match = { tool = "stellar_pay", chain = "stellar:testnet" }
criteria = [{ kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = [], unlisted = { mode = "budget", asset = "native", per_tx_stroops = 10, per_period_stroops = 20, window = "1d" } }]
decision = "allow"

[[rules]]
match = { tool = "stellar_x402_create_payment", chain = "stellar:testnet" }
criteria = [{ kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = [], unlisted = { mode = "budget", asset = "native", per_tx_stroops = 10, per_period_stroops = 20, window = "1d" } }]
decision = "allow"
"#;

const SHARED_DENY: &str = r#"version = 2
scope = "profile:operator"
sequence = 1

[[rules]]
match = { tool = "stellar_pay", chain = "stellar:testnet" }
criteria = [{ kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = ["GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H"], unlisted = { mode = "deny" } }]
decision = "allow"

[[rules]]
match = { tool = "stellar_x402_create_payment", chain = "stellar:testnet" }
criteria = [{ kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = ["GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H"], unlisted = { mode = "deny" } }]
decision = "allow"
"#;

const SHARED_APPROVAL: &str = r#"version = 2
scope = "profile:operator"
sequence = 1

[[rules]]
match = { tool = "stellar_pay", chain = "stellar:testnet" }
criteria = [{ kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = [], unlisted = { mode = "approval" } }]
decision = "allow"

[[rules]]
match = { tool = "stellar_x402_create_payment", chain = "stellar:testnet" }
criteria = [{ kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = [], unlisted = { mode = "approval" } }]
decision = "allow"
"#;

/// The signature block the owner key appends to [`SHARED_BUDGET`].
const SHARED_BUDGET_SIGNATURE: &str = r#"
[signature]
owner_id = "GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2"
sig = "e38a30112f0f15d013624231ccae20472abe256ec7bee6a7fa7ab552df8c1dc568287b081fc100091ed7a9a033f24b98f05e3e107cae3df10a3764e375210206"
"#;

const SHARED_BUDGET_CANONICAL: &str = r#"version = 2
scope = "profile:operator"
sequence = 1

[[rules]]
match = { chain = "stellar:testnet", tool = "stellar_pay" }
criteria = [{ allowlist = [], kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], unlisted = { asset = "native", mode = "budget", per_period_stroops = 20, per_tx_stroops = 10, window = "1d" } }]
decision = "allow"

[[rules]]
match = { chain = "stellar:testnet", tool = "stellar_x402_create_payment" }
criteria = [{ allowlist = [], kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], unlisted = { asset = "native", mode = "budget", per_period_stroops = 20, per_tx_stroops = 10, window = "1d" } }]
decision = "allow"
"#;

const SHARED_BUDGET_DIGEST_HEX: &str =
    "3f3cb09a64a83e1ff984e205acc39e23084474a04091fdf3c1effbec0356be40";

/// The signature block the owner key appends to [`SHARED_DENY`].
const SHARED_DENY_SIGNATURE: &str = r#"
[signature]
owner_id = "GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2"
sig = "a67a67062f104f37c9e75d23447ba4023760c056700486986d0556aa5272238047a1631846f3aca8700d9a8a8b8946f5ddb79ed903dece08190fa940e3fcce0b"
"#;

const SHARED_DENY_CANONICAL: &str = r#"version = 2
scope = "profile:operator"
sequence = 1

[[rules]]
match = { chain = "stellar:testnet", tool = "stellar_pay" }
criteria = [{ allowlist = ["GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H"], kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], unlisted = { mode = "deny" } }]
decision = "allow"

[[rules]]
match = { chain = "stellar:testnet", tool = "stellar_x402_create_payment" }
criteria = [{ allowlist = ["GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H"], kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], unlisted = { mode = "deny" } }]
decision = "allow"
"#;

const SHARED_DENY_DIGEST_HEX: &str =
    "f291e9f2d24e55aa90d6d83f0d99ee2059cbdc7293711f18643eaf2620cc7369";

/// The signature block the owner key appends to [`SHARED_APPROVAL`].
const SHARED_APPROVAL_SIGNATURE: &str = r#"
[signature]
owner_id = "GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2"
sig = "038d0aaba11f159d2513f50abcc7934d9af35c9dd39848c37d10106b25c5de9eca4afb239043ba68b8379ff79ecbecbb3419909135e9d50781dfb0ad30074b03"
"#;

const SHARED_APPROVAL_CANONICAL: &str = r#"version = 2
scope = "profile:operator"
sequence = 1

[[rules]]
match = { chain = "stellar:testnet", tool = "stellar_pay" }
criteria = [{ allowlist = [], kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], unlisted = { mode = "approval" } }]
decision = "allow"

[[rules]]
match = { chain = "stellar:testnet", tool = "stellar_x402_create_payment" }
criteria = [{ allowlist = [], kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], unlisted = { mode = "approval" } }]
decision = "allow"
"#;

const SHARED_APPROVAL_DIGEST_HEX: &str =
    "86b3574a446f7c2f3b284698a5b10e865855969323b02fe38e5deed2043f12c9";

/// The G strkey of `[1; 32]`, the recipient of the shared-table decisions.
const RECIPIENT: &str = "GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H";

/// Asserts that `raw` reproduces its literal canonical bytes, digest, and
/// signed text, and loads the signed text on the test network into an engine.
fn shared_engine(
    raw: &str,
    signature: &str,
    canonical: &str,
    digest_hex: &str,
) -> stellar_agent_core::policy::v1::PolicyEngineV1 {
    let bytes = canonical_bytes(raw).unwrap();
    assert_eq!(String::from_utf8(bytes.clone()).unwrap(), canonical);
    assert_eq!(
        stellar_agent_core::hex::encode(blake3::hash(&bytes).as_bytes()),
        digest_hex
    );
    let text = format!("{raw}{signature}");
    assert_eq!(signed(raw, &owner_key()), text);
    let document = load_signed_policy_text(
        &text,
        "operator",
        &owner_key().verifying_key().to_bytes(),
        TESTNET_PASSPHRASE,
    )
    .unwrap();
    assert_eq!(document.rules.len(), 2);
    stellar_agent_core::policy::v1::PolicyEngineV1::new_with_store(
        document,
        "operator".to_owned(),
        PolicyStateStore::new(),
    )
}

fn testnet_tool(name: &'static str) -> ToolDescriptor {
    let mut tool = ToolDescriptor::from_registration(&McpToolRegistration {
        name,
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    });
    tool.chain_id = "stellar:testnet".into();
    tool
}

fn testnet_profile() -> Profile {
    Profile::builder_testnet_named("operator", "s", "a", "n", "a").build()
}

/// A native payment of `amount` stroops to [`RECIPIENT`].
fn native_payment(amount: i128) -> ValueClass {
    ValueClass::single(ValueLeg {
        kind: ActionKind::Payment,
        amount: Some(amount),
        asset: Some("native".to_owned()),
        destination: Some(RECIPIENT.to_owned()),
    })
}

fn shared_evaluate(
    engine: &stellar_agent_core::policy::v1::PolicyEngineV1,
    tool: &ToolDescriptor,
    amount: i128,
) -> stellar_agent_core::policy::Evaluation {
    use stellar_agent_core::policy::PolicyEngine as _;
    engine
        .evaluate_with_value_full(
            tool,
            &serde_json::Value::Null,
            &testnet_profile(),
            native_payment(amount),
            None,
            None,
            None,
            None,
            None,
            policy_now_ms().unwrap(),
        )
        .unwrap()
}

/// Equal budget tables on `stellar_pay` and `stellar_x402_create_payment`
/// load and draw on one counter.
#[test]
fn equal_budget_tables_share_one_counter() {
    use stellar_agent_core::policy::{Decision, UnlistedBound};
    let engine = shared_engine(
        SHARED_BUDGET,
        SHARED_BUDGET_SIGNATURE,
        SHARED_BUDGET_CANONICAL,
        SHARED_BUDGET_DIGEST_HEX,
    );
    let pay = testnet_tool("stellar_pay");
    let x402 = testnet_tool("stellar_x402_create_payment");
    assert_eq!(shared_evaluate(&engine, &x402, 1).decision, Decision::Allow);
    for _ in 0..2 {
        let evaluation = shared_evaluate(&engine, &pay, 10);
        assert_eq!(evaluation.decision, Decision::Allow);
        engine
            .record_confirmed(
                &pay,
                &testnet_profile(),
                &ValueClass::Value(evaluation.value_effects.unwrap()),
            )
            .unwrap();
    }
    let exceeded = Decision::Deny(DenyReason::UnlistedBudgetExceeded {
        asset: "native".to_owned(),
        bound: UnlistedBound::PerPeriod,
        max_stroops: 20,
        attempted_stroops: 1,
    });
    let refusal = shared_evaluate(&engine, &x402, 1).decision;
    assert_eq!(refusal, exceeded);
    let Decision::Deny(reason) = refusal else {
        unreachable!()
    };
    assert_eq!(reason.code(), "unlisted_budget_exceeded");
    assert_eq!(shared_evaluate(&engine, &pay, 1).decision, exceeded);
}

/// Equal `deny` tables on two rules load, and a listed recipient passes.
#[test]
fn equal_deny_tables_load_and_allow_listed() {
    use stellar_agent_core::policy::Decision;
    let engine = shared_engine(
        SHARED_DENY,
        SHARED_DENY_SIGNATURE,
        SHARED_DENY_CANONICAL,
        SHARED_DENY_DIGEST_HEX,
    );
    for tool in ["stellar_pay", "stellar_x402_create_payment"] {
        let evaluation = shared_evaluate(&engine, &testnet_tool(tool), 1);
        assert_eq!(evaluation.decision, Decision::Allow, "{tool}");
    }
}

/// Equal `approval` tables on two rules load, and an unlisted recipient
/// requires approval.
#[test]
fn equal_approval_tables_load_and_escalate() {
    use stellar_agent_core::policy::Decision;
    let engine = shared_engine(
        SHARED_APPROVAL,
        SHARED_APPROVAL_SIGNATURE,
        SHARED_APPROVAL_CANONICAL,
        SHARED_APPROVAL_DIGEST_HEX,
    );
    for tool in ["stellar_pay", "stellar_x402_create_payment"] {
        let evaluation = shared_evaluate(&engine, &testnet_tool(tool), 1);
        assert!(
            matches!(evaluation.decision, Decision::RequireApproval(_)),
            "{tool}: {:?}",
            evaluation.decision
        );
    }
}
