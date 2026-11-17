#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use super::*;
use crate::account::{AccountView, AssetView, BalanceView, ThresholdsView};
use crate::mainnet::{MainnetConsumer, digest::BindingFacts};
use crate::policy_state::{DomainBinding, MintAuthority, MintRequest, NativeReservation};
use stellar_agent_core::policy::v1::{FloorInput, ObservedAccount};
use stellar_agent_core::policy::{
    Decision, McpToolRegistration, PolicyEngine, ToolDescriptor, ToolValueKind,
};

#[test]
#[serial_test::serial]
fn floor_checked_input_uses_verified_first_rule_and_operating_source() {
    use stellar_agent_core::policy::v1::verified::{
        OwnerKeySource, PinMode, PolicyLoad, load_verified_policy,
    };
    use stellar_agent_core::policy::v1::{PolicyStateStore, canonical, signature};
    let mut f = crate::mainnet::fixtures::ResolverFixture::new();
    let path = f.policy_path();
    let signed = std::fs::read_to_string(&path).unwrap();
    let raw = signed.split("[signature]").next().unwrap();
    let first = raw.replace("sequence = 7", "sequence = 8").replace("criteria = [", "criteria = [\n { kind = \"balance_floor\", min_stroops = 20 },\n { kind = \"balance_floor\", min_stroops = 90 },");
    let weaker = raw[raw.find("[[rules]]").unwrap()..].replace(
        "criteria = [",
        "criteria = [\n { kind = \"balance_floor\", min_stroops = 0 },",
    );
    let body = format!("{first}\n{weaker}");
    let owner = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    let sig = signature::sign(
        &signature::digest(&canonical::canonical_bytes(&body).unwrap()),
        &owner,
    );
    std::fs::write(
        &path,
        format!(
            "{body}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
            stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()),
            stellar_agent_core::hex::encode(&sig)
        ),
    )
    .unwrap();
    f.policy = load_verified_policy(
        &PolicyLoad {
            path: &path,
            profile: &f.profile,
            profile_name: "operator",
            owner_pubkey: &owner.verifying_key().to_bytes(),
            owner_source: OwnerKeySource::Keyring,
            window_path: f.window.path(),
        },
        PolicyStateStore::new(),
        PinMode::Advance,
    )
    .unwrap();
    let mut tool = ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_pay",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    });
    tool.chain_id = "stellar:mainnet".to_owned();
    let source = stellar_strkey::ed25519::PublicKey(f.signer.public_key())
        .to_string()
        .to_string();
    let view = AccountView::new(
        source.clone(),
        1,
        0,
        vec![BalanceView::new(
            AssetView::native(),
            "0.0000160".to_owned(),
            None,
            "0".to_owned(),
            "0".to_owned(),
        )],
        ThresholdsView::new(1, 1, 1, 1),
        vec![],
        None,
        None,
    );
    let observed = ObservedAccount::new(view.clone(), 100, f.now, f.now - 5_000);
    let input = FloorInput {
        observed: &observed,
        effective_reservations_stroops: 0,
    };
    let args = serde_json::json!({"chain_id": "stellar:mainnet", "amount_stroops": "50", "asset": "native", "destination": f.source.destination(), "total_fee_stroops": 0});
    let evaluation = f
        .policy
        .engine()
        .evaluate_full(
            &tool,
            &args,
            &f.profile,
            Some(&input),
            None,
            None,
            None,
            None,
            f.now,
        )
        .unwrap();
    assert_eq!(evaluation.decision, Decision::Allow);
    let mut request = MintRequest {
        chain: f.profile.chain_id,
        binding: DomainBinding::Transaction {
            unsigned_envelope_sha256: [1; 32],
            tx_hash: [2; 32],
            source,
            sequence: 1,
        },
        consumer: MainnetConsumer::CliPay,
        policy_sequence: f.policy.sequence(),
        policy_digest: f.policy.digest(),
        authority: MintAuthority::Approval {
            nonce: "floor-checked".to_owned(),
            expires_at_ms: f.now + 120_000,
        },
        chain_deadline_ms: None,
        authorization_ttl_ms: 120_000,
        bindings: BindingFacts {
            endpoint: None,
            signer: f.signer.fact_digest(),
            policy: f.policy.fact_digest(),
            enablement: [4; 32],
            witness: None,
            reservation: None,
            authority: [7; 32],
            audit: [8; 32],
        },
        holds: vec![],
        parent: None,
        operation: None,
        intent_digest: None,
        predecessor: None,
        approval_operation: None,
        native_reservation: Some(NativeReservation {
            debit_stroops: 50,
            fee_stroops: 0,
        }),
        floor: None,
    };
    let readiness = crate::operational::OperationalReport {
        latest_ledger: 100,
        close_time_unix: (f.now - 5_000) / 1_000,
        close_lag_seconds: 5,
    };
    let checked = |seen: &ObservedAccount<AccountView>,
                   evaluation: &stellar_agent_core::policy::Evaluation,
                   request: &MintRequest| {
        CheckedFloor::for_mint(
            &f.context, &f.policy, &tool, evaluation, &f.signer, seen, &readiness, request,
        )
    };
    let floor = checked(&observed, &evaluation, &request).unwrap().unwrap();
    assert_eq!(
        floor.minimum, 90,
        "all floors of the first deciding rule apply"
    );
    let mut wrong_rule = evaluation.clone();
    wrong_rule.rule_ordinal = Some(1);
    assert!(
        checked(&observed, &wrong_rule, &request).is_err(),
        "a later weaker rule cannot be selected"
    );
    let mut payee_view = view.clone();
    payee_view.account_id = f.source.destination().to_owned();
    assert!(
        checked(
            &ObservedAccount::new(payee_view, 100, f.now, f.now - 5_000),
            &evaluation,
            &request
        )
        .is_err(),
        "payee is not the balance source"
    );
    for (ledger, close) in [(99, f.now - 5_000), (100, f.now - 10_000)] {
        assert!(
            checked(
                &ObservedAccount::new(view.clone(), ledger, f.now, close),
                &evaluation,
                &request
            )
            .is_err(),
            "readiness coverage"
        );
    }
    for field in [0, 1, 2] {
        let mut changed = request.clone();
        if field == 0 {
            changed.chain = stellar_agent_core::profile::caip2::Caip2::Testnet;
        } else if field == 1 {
            changed.policy_digest = [8; 32];
        } else {
            changed.consumer = MainnetConsumer::X402Create;
        }
        assert!(
            checked(&observed, &evaluation, &changed).is_err(),
            "chain, policy and consumer binding"
        );
    }
    request.floor = Some(floor);
    f.window.mint_authorization(&f.profile, &request).unwrap();
    let mut second = request.clone();
    second.binding = DomainBinding::Transaction {
        unsigned_envelope_sha256: [3; 32],
        tx_hash: [4; 32],
        source: view.account_id.clone(),
        sequence: 2,
    };
    second.authority = MintAuthority::Approval {
        nonce: "floor-next".to_owned(),
        expires_at_ms: f.now + 120_000,
    };
    second.floor = checked(&observed, &evaluation, &second).unwrap();
    assert!(
        matches!(f.window.mint_authorization(&f.profile, &second), Err(WindowStoreError::PolicyDenied { reason })
        if *reason == DenyReason::AccountFloorRefused { min_stroops: 90, balance_after_stroops: 60 }),
        "real checked facts reach locked mint"
    );
}

#[test]
fn floor_refusal_carriers_keep_codes() {
    let cases = [
        (
            WindowStoreError::PolicyDenied {
                reason: Box::new(DenyReason::AccountUnread),
            },
            "account.unread",
        ),
        (
            WindowStoreError::PolicyDenied {
                reason: Box::new(DenyReason::AccountStale { age_ms: 120_001 }),
            },
            "account.stale",
        ),
        (
            WindowStoreError::PolicyDenied {
                reason: Box::new(DenyReason::AccountFloorRefused {
                    min_stroops: 20,
                    balance_after_stroops: 19,
                }),
            },
            "account.floor_refused",
        ),
        (
            WindowStoreError::AccountingInvalid,
            "policy.accounting_invalid",
        ),
        (
            WindowStoreError::AccountingOverflow,
            "policy.accounting_overflow",
        ),
    ];
    for (error, code) in cases {
        if code == "policy.accounting_invalid" {
            assert_eq!(
                error.to_string(),
                "a policy accounting amount or fee is invalid",
                "native invalid diagnostic"
            );
            assert!(
                error
                    .operation_error()
                    .unwrap()
                    .to_string()
                    .contains("a policy accounting amount or fee is invalid"),
                "operation invalid diagnostic"
            );
        } else if code == "policy.accounting_overflow" {
            assert_eq!(
                error.to_string(),
                "the policy accounting sum overflows; nothing was recorded",
                "native overflow diagnostic"
            );
        }
        assert_eq!(
            error.operation_error().map(|error| error.code()),
            Some(code),
            "operation carrier"
        );
        let operation = crate::operation_entry::operation_refusal(error);
        assert_eq!(operation.code(), code);
    }
    for reason in [
        DenyReason::AccountUnread,
        DenyReason::AccountStale { age_ms: 120_001 },
        DenyReason::AccountFloorRefused {
            min_stroops: 20,
            balance_after_stroops: 19,
        },
    ] {
        let code = reason.code();
        let error: stellar_agent_core::error::WalletError =
            crate::mainnet::mint::store_error(WindowStoreError::PolicyDenied {
                reason: Box::new(reason),
            })
            .into();
        assert_eq!(error.code(), code, "standalone carrier");
    }
    for (error, code, message) in [
        (
            WindowStoreError::AccountingInvalid,
            "policy.accounting_invalid",
            "a policy accounting amount or fee is invalid",
        ),
        (
            WindowStoreError::AccountingOverflow,
            "policy.accounting_overflow",
            "the policy accounting sum overflows; nothing was recorded",
        ),
    ] {
        let refusal = crate::mainnet::mint::store_error(error);
        assert_eq!(
            refusal.to_string(),
            message,
            "standalone accounting diagnostic"
        );
        let wallet: stellar_agent_core::error::WalletError = refusal.into();
        assert_eq!(wallet.code(), code, "standalone accounting code");
    }
}
