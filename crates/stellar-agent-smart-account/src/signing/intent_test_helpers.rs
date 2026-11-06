//! Checked admission fixtures for signing tests.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture invariants")]

use super::gate::SigningGate;
use std::sync::{Arc, OnceLock};
use stellar_agent_core::policy::{
    McpToolRegistration, NoopPolicyEngine, PolicyEngine, ToolDescriptor, ToolValueKind,
};
use stellar_agent_core::profile::{caip2::TESTNET_PASSPHRASE, schema::Profile};
use stellar_agent_network::{IntentSubject, NoValueAdmission, SignedIntentPlan, SignerDescriptor};

fn shared_admission() -> &'static (tempfile::TempDir, Arc<NoValueAdmission>) {
    static ADMISSION: OnceLock<(tempfile::TempDir, Arc<NoValueAdmission>)> = OnceLock::new();
    ADMISSION.get_or_init(|| {
        let (directory, admission) = no_value_admission_owned();
        (directory, Arc::new(admission))
    })
}

/// Returns an explicit policy with no applicable window limit.
pub fn no_value_admission() -> &'static NoValueAdmission {
    &shared_admission().1
}

/// Shares the admission whose directory guard lives for the process.
pub fn shared_no_value_admission() -> Arc<NoValueAdmission> {
    Arc::clone(&shared_admission().1)
}

/// Builds an owned checked no-limit admission fixture.
/// The caller installs the mock keyring under its test's serial lock.
///
/// # Panics
/// Panics if the fixture cannot form a valid signing plan.
pub fn no_value_admission_owned() -> (tempfile::TempDir, NoValueAdmission) {
    let name = format!("intent-fixture-{}", uuid::Uuid::new_v4());
    let scratch = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp");
    std::fs::create_dir_all(&scratch).unwrap();
    let directory = tempfile::Builder::new()
        .prefix("intent-fixture-")
        .tempdir_in(scratch)
        .unwrap();
    let profile = Profile::builder_testnet_named(
        &name,
        &format!("{name}-owner"),
        "account",
        &format!("{name}-nonce"),
        "account",
    )
    .build();
    let tool = ToolDescriptor::from_registration(&McpToolRegistration {
        name: "fixture",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::ReadOnly,
    });
    let sizing = NoopPolicyEngine.size_no_value(&tool, &profile, 0).unwrap();
    let store = stellar_agent_network::policy_state::PersistedWindowStore::at_path(
        directory.path().join(format!("{name}.window")),
    )
    .with_profile_directory(&name, directory.path().to_owned());
    (
        directory,
        NoValueAdmission::with_store(profile, store, sizing).unwrap(),
    )
}

/// Checks exact envelope bounds at the shared gate before signer exposure.
/// The caller owns the mock keyring and serial test lock.
///
/// # Panics
/// Panics if a changed bound reaches a signer or consumes the proof.
#[cfg(test)]
pub async fn assert_envelope_bounds_refuse_before_signing() {
    use super::gate::{SignerMatch, SigningRequest};
    use stellar_agent_network::signing::test_doubles::CountingSigner;
    use stellar_agent_network::signing::{Signer as _, TxSigningPayload};
    use stellar_agent_network::{AuthSubject, SigningPayload};
    use stellar_xdr::*;
    let signer = CountingSigner::new([0; 32]);
    let (fixture, mut envelope) =
        stellar_agent_network::signed_intent::test_helpers::intent_fixture_kind(2);
    let TransactionEnvelope::Tx(tx) = &mut envelope else {
        panic!("the fixture uses a V1 envelope");
    };
    tx.tx.cond = Preconditions::V2(PreconditionsV2 {
        time_bounds: None,
        ledger_bounds: Some(LedgerBounds {
            min_ledger: 0,
            max_ledger: 50,
        }),
        min_seq_num: None,
        min_seq_age: Duration(0),
        min_seq_ledger_gap: 0,
        extra_signers: VecM::default(),
    });
    let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
        panic!("the fixture invokes a host function");
    };
    let plan = fixture
        .with_envelope_max_ledger(50)
        .unwrap()
        .classify_purpose(&op.host_function, None)
        .unwrap();
    assert_eq!(
        plan.subjects()
            .iter()
            .filter_map(IntentSubject::expiration)
            .max(),
        Some(100)
    );
    assert_eq!(plan.check_envelope(&envelope), Ok(()));
    let (_directory, admission) = no_value_admission_owned();
    let signing_gate = SigningGate::new(admission.admit(&plan).await.unwrap());
    let source = stellar_strkey::ed25519::PublicKey([0; 32])
        .to_string()
        .to_string();
    for maximum in [None, Some(0), Some(49), Some(51)] {
        let mut changed = envelope.clone();
        let TransactionEnvelope::Tx(tx) = &mut changed else {
            panic!("the fixture uses a V1 envelope");
        };
        let Preconditions::V2(conditions) = &mut tx.tx.cond else {
            panic!("the fixture uses V2 preconditions");
        };
        conditions.ledger_bounds = maximum.map(|max_ledger| LedgerBounds {
            min_ledger: 0,
            max_ledger,
        });
        let result = signing_gate.authorize(SigningRequest {
            subject: AuthSubject::source(&source).unwrap(),
            signer: SignerMatch::Exact(SignerDescriptor::AccountKey {
                public_key: [0; 32],
            }),
            payload: SigningPayload::Envelope(&changed),
        });
        if result.is_ok() {
            let _ = signer
                .sign_tx_payload(
                    &TxSigningPayload::for_envelope(&changed, TESTNET_PASSPHRASE).unwrap(),
                )
                .await;
        }
        assert!(
            matches!(
                result,
                Err(crate::SaError::IntentBindingMismatch {
                    field: "expiration"
                })
            ),
            "{maximum:?}: {result:?}"
        );
        assert_eq!(signer.sign_calls(), 0);
        assert!(signing_gate.exposure().is_none());
    }
    assert!(signing_gate.take_unexposed().is_some());
    assert!(signing_gate.exposure().is_none());
}

/// Admits the named fixture subjects without a durable charge.
///
/// # Panics
/// Panics if the fixture cannot form a valid signing plan.
pub fn gate(subjects: Vec<IntentSubject>) -> SigningGate {
    use std::future::Future as _;
    let expiration = subjects.iter().filter_map(IntentSubject::expiration).max();
    let source = stellar_strkey::ed25519::PublicKey([0; 32])
        .to_string()
        .as_str()
        .to_owned();
    let plan = SignedIntentPlan::new(
        TESTNET_PASSPHRASE,
        "fixture",
        &source,
        1,
        [7; 32],
        subjects,
        expiration,
    )
    .unwrap();
    let mut admission = std::pin::pin!(no_value_admission().admit(&plan));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match admission.as_mut().poll(&mut context) {
        std::task::Poll::Ready(proof) => SigningGate::new(proof.unwrap()),
        std::task::Poll::Pending => {
            panic!("the checked fixture admission completes synchronously")
        }
    }
}

/// Plans a partial and optional delegated entries with fixed fixture nonces.
///
/// # Panics
/// Panics if the fixture cannot form a valid signing plan.
#[allow(
    clippy::needless_pass_by_value,
    reason = "fixtures supply owned descriptor lists"
)]
pub fn partial_gate(
    partial: &crate::managers::auth_entry::PartialSorobanAuthorizationEntry,
    descriptors: Vec<SignerDescriptor>,
    delegated: bool,
) -> SigningGate {
    let mut subjects = vec![
        IntentSubject::smart_account(
            &partial.smart_account,
            partial.nonce,
            partial.signature_expiration_ledger,
            &partial.root_invocation,
            partial
                .context_rule_ids
                .iter()
                .map(stellar_agent_core::smart_account::rule_id::ContextRuleId::as_u32)
                .collect(),
            descriptors.clone(),
        )
        .unwrap(),
    ];
    if delegated {
        let root = crate::managers::auth_entry::delegated_g_key_invocation(
            &partial.smart_account,
            &partial.auth_digest,
        )
        .unwrap();
        for (index, descriptor) in descriptors.iter().enumerate() {
            if let SignerDescriptor::Delegated { account } = descriptor {
                subjects.push(
                    IntentSubject::account_key(
                        &account_address(*account),
                        i64::try_from(index + 1).unwrap(),
                        partial.signature_expiration_ledger,
                        &root,
                    )
                    .unwrap(),
                );
            }
        }
    }
    gate(subjects)
}

/// Creates the canonical address for a fixture key.
pub fn account_address(key: [u8; 32]) -> stellar_xdr::ScAddress {
    stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
        stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(key)),
    ))
}

/// Plans one delegated entry with its explicit nonce.
///
/// # Panics
/// Panics if the fixture cannot form a valid signing plan.
pub fn delegated_gate(
    smart_account: &stellar_xdr::ScAddress,
    digest: &[u8; 32],
    expiration: u32,
    key: [u8; 32],
    nonce: i64,
) -> SigningGate {
    let root =
        crate::managers::auth_entry::delegated_g_key_invocation(smart_account, digest).unwrap();
    gate(vec![
        IntentSubject::account_key(&account_address(key), nonce, expiration, &root).unwrap(),
    ])
}

/// A checked no-limit recorder for submission tests unrelated to window limits.
pub struct NoLimitRecorder;

#[async_trait::async_trait]
impl stellar_agent_network::SubmissionRecorder for NoLimitRecorder {
    async fn admit_signed_intent(
        &self,
        plan: &SignedIntentPlan,
    ) -> Result<stellar_agent_network::IntentProof, stellar_agent_core::WalletError> {
        no_value_admission().admit(plan).await
    }
    async fn cancel_unexposed(
        &self,
        proof: stellar_agent_network::IntentProof,
    ) -> Result<(), stellar_agent_core::WalletError> {
        no_value_admission().cancel_unexposed(proof).await
    }
    async fn pre_send_bound(
        &self,
        intent: &stellar_agent_network::SubmissionIntent,
        _: &stellar_agent_network::IntentBinding<'_>,
    ) -> Result<(), stellar_agent_core::WalletError> {
        self.pre_send(intent).await
    }
    async fn pre_send(
        &self,
        _: &stellar_agent_network::SubmissionIntent,
    ) -> Result<(), stellar_agent_core::WalletError> {
        Ok(())
    }
    async fn outcome(
        &self,
        _: &stellar_agent_network::SubmissionIntent,
        _: &stellar_agent_network::SubmissionOutcome,
    ) {
    }
}

/// Builds an external descriptor from the fixture's verifier and key bytes.
///
/// # Panics
/// Panics if the fixture cannot form a valid signing plan.
pub fn external(verifier: &stellar_xdr::ScAddress, key: [u8; 32]) -> SignerDescriptor {
    use sha2::Digest as _;
    SignerDescriptor::External {
        verifier: crate::managers::rules::scaddress_to_strkey(verifier).unwrap(),
        key_data_sha256: sha2::Sha256::digest(key).into(),
    }
}

/// Resolves software fixture keys and plans a mixed signing set.
#[cfg(test)]
pub(crate) async fn mixed_gate(
    partial: &crate::managers::auth_entry::PartialSorobanAuthorizationEntry,
    signers: &[crate::managers::auth_entry::MixedSigner<'_>],
) -> SigningGate {
    let mut descriptors = Vec::new();
    for signer in signers {
        let key = signer.signer.public_key().await.unwrap().0;
        descriptors.push(match &signer.kind {
            crate::managers::auth_entry::MixedSignerKind::Delegated => {
                SignerDescriptor::Delegated { account: key }
            }
            crate::managers::auth_entry::MixedSignerKind::ExternalEd25519 { verifier } => {
                external(verifier, key)
            }
        });
    }
    partial_gate(partial, descriptors, true)
}
