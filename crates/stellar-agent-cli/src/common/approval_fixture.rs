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
