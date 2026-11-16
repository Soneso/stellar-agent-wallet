#[cfg(test)]
mod tests {
    use super::super::*;
    use stellar_agent_core::audit_log::{
        BindingCheck, MAX_EVIDENCE_ENTRIES, test_helpers::seed_reserved_evidence,
    };
    use stellar_agent_network::policy_state::approvals::{
        ConsentDeliveryV1, ConsentEvidenceEnforcementGuard, ConsentEvidenceInventoryGuard,
    };

    fn initialize(fixture: &MainnetConsentFixture) {
        let mut writer = AuditWriter::open(
            fixture.audit_path(),
            Some(
                stellar_agent_network::keyring::keyed_audit_access(
                    fixture.profile(),
                    fixture.name(),
                    BindingCheck::Enforce,
                )
                .unwrap(),
            ),
        )
        .unwrap();
        writer.initialize_consent_evidence().unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn approve_reacquires_before_presence() {
        for mode in ["inventory", "capacity", "corrupt", "mismatch"] {
            let fixture = fixture(&format!("approve-reserve-{mode}"));
            let entry = fixture.payment(300_000);
            park(&fixture, &entry);
            let _enabled =
                ConsentEvidenceEnforcementGuard::new(fixture.name(), ApprovedKind::Payment);
            let _ready =
                (mode != "inventory").then(|| ConsentEvidenceInventoryGuard::new(fixture.name()));
            initialize(&fixture);
            if mode == "capacity" {
                let access = stellar_agent_network::keyring::keyed_audit_access(
                    fixture.profile(),
                    fixture.name(),
                    BindingCheck::Enforce,
                )
                .unwrap();
                let (key, anchor) = access.into_parts();
                let ids: Vec<_> = (0..MAX_EVIDENCE_ENTRIES)
                    .map(|i| {
                        let mut id = [0xee; 32];
                        id[..8].copy_from_slice(&(i as u64).to_be_bytes());
                        id
                    })
                    .collect();
                seed_reserved_evidence(
                    &fixture.audit_path(),
                    anchor.as_ref(),
                    &key,
                    &ids,
                    u64::MAX,
                )
                .unwrap();
            }
            if mode == "corrupt" {
                for suffix in [".evidence.0", ".evidence.1"] {
                    let mut path =
                        stellar_agent_core::audit_log::outbox_path(&fixture.audit_path())
                            .into_os_string();
                    path.push(suffix);
                    std::fs::write(PathBuf::from(path), b"torn evidence").unwrap();
                }
            }
            if mode == "mismatch" {
                let mut pending = PendingApprovalStore::open(fixture.store_path()).unwrap();
                let mut changed = entry.clone();
                changed.expires_at_unix_ms -= 1;
                pending.remove(&entry.approval_nonce).unwrap();
                pending.insert(changed, entry.created_at_unix_ms).unwrap();
            }
            let _presence = driver::install(driver::fixture_credential());
            let (code, result) = invoke(fixture.name(), &entry.approval_nonce, false).await;
            assert_eq!(code, 1);
            assert_eq!(
                result["error"]["code"],
                match mode {
                    "capacity" => "approval.evidence_capacity",
                    "mismatch" => "approval.attestation_invalid",
                    _ => "audit.outbox_evidence_unusable",
                },
                "the real command preserves the admission refusal"
            );
            assert!(
                driver::ceremonies().is_empty(),
                "reacquisition precedes presence"
            );
            assert!(
                stored(&fixture, &entry.approval_nonce)
                    .attestation_blob_b64
                    .is_none()
            );
            assert!(record(&fixture, &entry.approval_nonce).consent.is_none());
        }
    }

    #[tokio::test]
    #[serial]
    async fn approve_publication_failure_recovers_the_original_grant() {
        let fixture = fixture("approve-publication-recovery");
        let entry = fixture.payment(300_000);
        let pending = park(&fixture, &entry);
        let _enabled = ConsentEvidenceEnforcementGuard::new(fixture.name(), ApprovedKind::Payment);
        let _ready = ConsentEvidenceInventoryGuard::new(fixture.name());
        initialize(&fixture);
        let _presence = driver::install(driver::fixture_credential());
        let fault = arm_accounting_fault(COMMIT_FAULT_AFTER_PREPARED);
        let (code, result) = invoke(fixture.name(), &entry.approval_nonce, false).await;
        drop(fault);
        assert_eq!(code, 1);
        assert_eq!(result["error"]["code"], "submission.record_unavailable");
        let attested = stored(&fixture, &entry.approval_nonce);
        assert!(attested.consent_publication.is_some());
        assert!(
            record(&fixture, &entry.approval_nonce).consent.is_none(),
            "failed publication exposes no durable grant"
        );
        let (_, result) = invoke(fixture.name(), &entry.approval_nonce, false).await;
        assert_eq!(result["error"]["code"], "approval.already_attested");
        let consent = record(&fixture, &entry.approval_nonce).consent.unwrap();
        assert_eq!(
            consent.delivery,
            Some(ConsentDeliveryV1::direct_anchored(pending.id)),
            "retry uses authenticated original delivery"
        );
        assert_eq!(
            consent.consent_at_ms,
            attested.mainnet_presence.unwrap().verified_at_unix_ms()
        );
        assert_eq!(consent_rows(fixture.profile()).len(), 1);
        assert_eq!(driver::ceremonies().len(), 1);
    }

    #[tokio::test]
    #[serial]
    async fn published_approve_repeat_does_no_proof_or_commit_work() {
        let fixture = fixture("approve-publication-repeat");
        let entry = fixture.payment(300_000);
        park(&fixture, &entry);
        let _enabled = ConsentEvidenceEnforcementGuard::new(fixture.name(), ApprovedKind::Payment);
        let _ready = ConsentEvidenceInventoryGuard::new(fixture.name());
        initialize(&fixture);
        let _presence = driver::install(driver::fixture_credential());
        assert_eq!(
            invoke(fixture.name(), &entry.approval_nonce, false).await.0,
            0
        );
        let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
        let mut attested = store.get(&entry.approval_nonce).unwrap().clone();
        attested.attestation_blob_b64 = Some(URL_SAFE_NO_PAD.encode([0; 32]));
        attested.consent_publication = None;
        store.remove(&entry.approval_nonce).unwrap();
        store.insert(attested, entry.created_at_unix_ms).unwrap();
        drop(store);
        let window = PersistedWindowStore::for_profile(fixture.name());
        let before = std::fs::read(window.path()).unwrap();
        let _observed = observe_commit(|_| panic!("published repeats perform no commit"));
        let (_, result) = invoke(fixture.name(), &entry.approval_nonce, false).await;
        assert_eq!(
            result["error"]["code"], "approval.already_attested",
            "published repeats perform no proof verification"
        );
        assert_eq!(std::fs::read(window.path()).unwrap(), before);
        assert_eq!(driver::ceremonies().len(), 1);
        assert_eq!(consent_rows(fixture.profile()).len(), 1);
    }
}
