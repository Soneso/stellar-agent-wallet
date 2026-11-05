//! Checked admission fixtures for signing tests.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture invariants")]

use super::gate::SigningGate;
use std::sync::OnceLock;
use stellar_agent_core::policy::{
    McpToolRegistration, NoopPolicyEngine, PolicyEngine, ToolDescriptor, ToolValueKind,
};
use stellar_agent_core::profile::{caip2::TESTNET_PASSPHRASE, schema::Profile};
use stellar_agent_network::{IntentSubject, NoValueAdmission, SignedIntentPlan, SignerDescriptor};

/// Returns an explicit policy with no applicable window limit.
pub fn no_value_admission() -> &'static NoValueAdmission {
    static ADMISSION: OnceLock<NoValueAdmission> = OnceLock::new();
    ADMISSION.get_or_init(no_value_admission_owned)
}

/// Builds an owned checked no-limit admission fixture.
///
/// # Panics
/// Panics if the fixture cannot form a valid signing plan.
pub fn no_value_admission_owned() -> NoValueAdmission {
    let profile =
        Profile::builder_testnet("intent-fixture", "account", "intent-fixture", "account").build();
    let tool = ToolDescriptor::from_registration(&McpToolRegistration {
        name: "fixture",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::ReadOnly,
    });
    let sizing = NoopPolicyEngine.size_no_value(&tool, &profile, 0).unwrap();
    NoValueAdmission::new(profile, "intent-fixture", sizing).unwrap()
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
        std::task::Poll::Pending => panic!("an empty checked sizing requires no I/O"),
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
