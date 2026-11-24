use super::*;

#[test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
fn canonical_shared_producer_consent_uses_full_subject() {
    use crate::tools::common::tests::mainnet::Fixture;
    use stellar_agent_core::approval::{IntentAsset, IntentPayload, MemoFact, fixtures};
    let f = Fixture::new(|raw| raw);
    let server = &f.server;
    // The legacy-attested shared producer runs unenforced for every kind.
    let _unenforced =
        stellar_agent_network::policy_state::approvals::ConsentEvidenceDisableGuard::every_kind(
            &server.profile_name_for_approval(),
        );
    for kind in 1..4 {
        let source = f.envelope.source();
        let destination = f.envelope.destination();
        let (payload, tool, operation_kind) = match kind {
            1 => (
                IntentPayload::CreateAccount {
                    destination: destination.into(),
                    starting_balance_stroops: 17,
                },
                OperationTool::StellarCreateAccount,
                OperationKind::CreateAccount,
            ),
            2 => (
                IntentPayload::Trustline {
                    issuer: destination.into(),
                    code: "UsD".into(),
                    limit_stroops: 0,
                },
                OperationTool::StellarTrustline,
                OperationKind::Trustline,
            ),
            _ => (
                IntentPayload::Claim {
                    balance_id: format!("00000000{}", "09".repeat(32)),
                    claimant: source.into(),
                    asset: IntentAsset::Native,
                    amount_stroops: 71,
                },
                OperationTool::StellarClaim,
                OperationKind::Claim,
            ),
        };
        let intent = operation_entry::classic_intent(
            IntentBaseFacts::new(
                server.security_profile(),
                source,
                server.current_mainnet_policy().unwrap(),
                ClassicFeeChoice::Explicit(500),
                MemoFact::None,
            ),
            payload,
        )
        .unwrap();
        let operation = server
            .prepare_entry(
                BusinessId::parse(&format!("canonical-consent-{kind}")).unwrap(),
                Preparation::Canonical {
                    intent: Box::new(intent.clone()),
                    decision: PolicyDecision::RequireApproval,
                    rule_ttl_ms: Some(120_000),
                },
            )
            .unwrap();
        let xdr = operation_entry::intent_envelope(
            &intent,
            server.context.network_passphrase(),
            2,
            100,
            stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1000 + 60,
        )
        .unwrap();
        let handle = server
            .prepared_envelope(Some(&operation), tool, operation_kind, xdr.clone())
            .unwrap()
            .handle
            .unwrap();
        let directory = server.resolve_approval_dir().unwrap();
        let path = directory.join(format!("{}.toml", server.profile_name_for_approval()));
        let mut entry = match kind {
            1 => PendingApproval::new_payment_pending(
                xdr.clone(),
                xdr.as_bytes(),
                destination.into(),
                17,
                "XLM".into(),
                None,
                100,
                2,
                "1000".into(),
                120_000,
            )
            .unwrap(),
            2 => fixtures::trustline_pending(
                source,
                "UsD",
                destination,
                Some(0),
                100,
                2,
                "1000".into(),
                120_000,
            ),
            _ => fixtures::claim_pending(
                source,
                [9; 32],
                Some(("XLM", 71)),
                100,
                2,
                "1000".into(),
                120_000,
            ),
        };
        // Keep the retained envelope and the independent pending display facts together.
        match &mut entry.kind {
            ApprovalKind::TrustlineSimulated {
                envelope_xdr_b64,
                envelope_sha256_hex,
                ..
            }
            | ApprovalKind::ClaimSimulated {
                envelope_xdr_b64,
                envelope_sha256_hex,
                ..
            } => {
                *envelope_xdr_b64 = xdr.clone();
                *envelope_sha256_hex = hex::encode(
                    stellar_agent_core::approval::subject::approval_subject_classic(&xdr),
                );
            }
            _ => {}
        }
        let result = server
            .classic_pending_approval(
                Some(&handle),
                intent.approved_kind(),
                PolicyDecision::RequireApproval,
                crate::tools::business_entry::Staged {
                    build: |stored: Option<&stellar_agent_core::approval::ClassicIntent>| {
                        let mut entry = entry.clone();
                        operation_entry::stage_pending(&mut entry, stored, 120_000).unwrap();
                        Ok(entry)
                    },
                    insert: |entry: PendingApproval| {
                        open_inbox(&path)
                            .unwrap()
                            .insert(entry.clone(), entry.created_at_unix_ms)
                            .unwrap();
                        Ok(entry)
                    },
                },
            )
            .unwrap();
        let proof = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f.attest(&result)));
        assert!(
            proof.is_ok(),
            "shared producer canonical completion succeeds"
        );
        let record = ApprovalStatus::new(&server.window_store, server.security_profile())
            .find_by_nonce(&result.approval_nonce)
            .unwrap()
            .unwrap()
            .record;
        assert_eq!(
            record.subject,
            *intent.digest().as_bytes(),
            "shared producer retains full consent subject"
        );
        let consent = record
            .consent
            .expect("shared producer fixture completes durable canonical consent");
        assert_eq!(
            consent.execution_expires_at_ms,
            consent.consent_at_ms + 120_000
        );
        assert_eq!(
            consent.payload.unwrap().row_provenance,
            Some(stellar_agent_network::policy_state::RowProvenance::Written)
        );
        assert_eq!(
            open_inbox(&path)
                .unwrap()
                .get(&result.approval_nonce)
                .unwrap()
                .attestation_version,
            6,
            "shared producer persists V6"
        );
    }
}
