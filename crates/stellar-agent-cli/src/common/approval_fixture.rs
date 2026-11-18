//! Durable approval records for CLI consent fixtures.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test assertions")]

use stellar_agent_core::approval::{ApprovalKind, PendingApproval, mainnet_consent_subject};
use stellar_agent_network::policy_state::PersistedWindowStore;

/// Opens the operation and its durable record for a consent fixture.
pub(crate) fn open_record(
    name: &str,
    profile: &stellar_agent_core::profile::Profile,
    entry: &PendingApproval,
) -> stellar_agent_network::policy_state::WireApproval {
    use stellar_agent_core::approval::witness::ApprovedKind;
    use stellar_agent_core::audit_log::PolicyDecision;
    use stellar_agent_network::operation_entry::pending_approval_facts;
    use stellar_agent_network::policy_state::{
        ApprovalRecorder, BusinessId, IntentSlot, OpenOutcome, OpenRequest, OperationAudit,
        OperationKind, OperationRecorder, OperationTool, X402Intent,
    };
    struct Rows;
    impl OperationAudit for Rows {
        fn append(&mut self, _: stellar_agent_core::audit_log::AuditEntry) -> Result<(), String> {
            Ok(())
        }
    }
    let window = PersistedWindowStore::for_profile(name);
    let (kind, tool, approved, intent, envelope) = match &entry.kind {
        ApprovalKind::X402Payment {
            intent_digest,
            asset,
            payee,
            amount,
            ..
        } => (
            OperationKind::X402Payment,
            OperationTool::X402CreatePayment,
            ApprovedKind::X402Payment,
            IntentSlot::X402 {
                intent_digest: *intent_digest,
                intent: X402Intent {
                    network: profile.chain_id.caip2_str().to_owned(),
                    asset: asset.clone(),
                    payer: stellar_strkey::ed25519::PublicKey([1; 32])
                        .to_string()
                        .to_string(),
                    pay_to: payee.clone(),
                    amount: amount.clone(),
                },
            },
            None,
        ),
        other => {
            let (kind, tool, approved, xdr) = match other {
                ApprovalKind::PaymentSimulated {
                    envelope_xdr_b64, ..
                } => (
                    OperationKind::Pay,
                    OperationTool::StellarPay,
                    ApprovedKind::Payment,
                    envelope_xdr_b64,
                ),
                ApprovalKind::ClaimSimulated {
                    envelope_xdr_b64, ..
                } => (
                    OperationKind::Claim,
                    OperationTool::StellarClaim,
                    ApprovedKind::Claim,
                    envelope_xdr_b64,
                ),
                ApprovalKind::TrustlineSimulated {
                    envelope_xdr_b64, ..
                } => (
                    OperationKind::Trustline,
                    OperationTool::StellarTrustline,
                    ApprovedKind::Trustline,
                    envelope_xdr_b64,
                ),
                _ => unreachable!(),
            };
            (
                kind,
                tool,
                approved,
                stellar_agent_network::operation_entry::envelope_slot(&[7; 32], xdr, 0),
                Some(xdr.clone()),
            )
        }
    };
    let opened = OperationRecorder::new(&window, profile, &mut Rows, "fixture")
        .open(&OpenRequest {
            business_id: BusinessId::parse(&entry.approval_nonce).unwrap(),
            tool,
            kind,
            intent,
            envelope_xdr: envelope,
            prepared_decision: None,
            rule_ttl_ms: None,
        })
        .unwrap();
    let OpenOutcome::New(handle) = opened else {
        unreachable!()
    };
    let facts = pending_approval_facts(
        entry,
        &handle,
        approved,
        mainnet_consent_subject(
            entry,
            &stellar_agent_core::approval::AttestationBinding::new(
                name,
                profile.chain_id.caip2_str(),
            ),
        )
        .unwrap(),
        entry.expires_at_unix_ms - entry.created_at_unix_ms,
    );
    ApprovalRecorder::new(&window, profile, &mut Rows, "fixture")
        .open_pending(handle.id(), &facts, PolicyDecision::RequireApproval)
        .unwrap()
        .record
}

/// A writer over the audit log of `profile` with the keyed, anchored access
/// of profile `name`.
#[allow(
    dead_code,
    reason = "the CLI integration target includes this file and uses only open_record"
)]
pub(crate) fn keyed_writer(
    profile: &stellar_agent_core::profile::Profile,
    name: &str,
) -> stellar_agent_core::audit_log::AuditWriter {
    stellar_agent_core::audit_log::AuditWriter::open(
        profile.audit_log_path.clone(),
        Some(
            stellar_agent_network::keyring::keyed_audit_access(
                profile,
                name,
                stellar_agent_core::audit_log::BindingCheck::Enforce,
            )
            .unwrap(),
        ),
    )
    .unwrap()
}

/// Seeds `count` reserved evidence slots of foreign identities, each
/// beginning with the byte `tag`, in the keyed audit log of `profile`.
#[allow(
    dead_code,
    reason = "the CLI integration target includes this file and uses only open_record"
)]
pub(crate) fn seed_foreign_evidence(
    profile: &stellar_agent_core::profile::Profile,
    name: &str,
    tag: u8,
    count: usize,
) {
    let (key, anchor) = stellar_agent_network::keyring::keyed_audit_access(
        profile,
        name,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
    )
    .unwrap()
    .into_parts();
    let identities: Vec<_> = (0..count)
        .map(|i| {
            let mut identity = [tag; 32];
            identity[..8].copy_from_slice(&(i as u64).to_be_bytes());
            identity
        })
        .collect();
    stellar_agent_core::audit_log::test_helpers::seed_reserved_evidence(
        &profile.audit_log_path,
        anchor.as_ref(),
        &key,
        &identities,
        u64::MAX,
    )
    .unwrap();
}
