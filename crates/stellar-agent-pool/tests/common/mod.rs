//! Real submission records in isolated temporary state.
#![allow(
    clippy::unwrap_used,
    reason = "test and benchmark fixture construction"
)]
use std::sync::{Arc, Mutex};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::profile::{receipt::ReceiptStore, schema::Profile};
use stellar_agent_network::{WalletSubmissionRecorder, policy_state::PersistedWindowStore};

pub struct RecorderFixture {
    pub dir: tempfile::TempDir,
    pub profile: Profile,
    pub receipts: ReceiptStore,
    pub legs: Vec<stellar_agent_core::audit_log::schema::ValueLegRecord>,
    audit: Arc<Mutex<AuditWriter>>,
}

impl RecorderFixture {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let profile = Profile::builder_testnet("pool-test", "source", "pool-test", "nonce")
            .audit_log_path(dir.path().join("audit.log"))
            .build();
        let receipts = ReceiptStore::open_at(dir.path(), "pool-test").unwrap();
        let audit = Arc::new(Mutex::new(
            AuditWriter::open(profile.audit_log_path.clone(), None).unwrap(),
        ));
        Self {
            dir,
            profile,
            receipts,
            legs: Vec::new(),
            audit,
        }
    }

    pub fn recorder(&self) -> WalletSubmissionRecorder<'_> {
        WalletSubmissionRecorder::new(
            &self.profile,
            "pool-test",
            "pool submission",
            Some("stellar:testnet".to_owned()),
            stellar_agent_core::audit_log::PolicyDecision::Allow,
            self.legs.clone(),
            Vec::new(),
            self.receipts.clone(),
            PersistedWindowStore::at_path(self.dir.path().join("window")),
            Some(self.audit.clone()),
            None,
            "pool-test-request",
            stellar_agent_core::timefmt::now_unix_ms().unwrap(),
        )
    }
}

/// Advances only the confirmation deadline after a real loopback poll has begun.
/// A six-second I/O bound catches stalled mocks; the submission retains its
/// production 120-second deadline, inside a 360-second virtual outer bound.
#[allow(dead_code, reason = "shared by the initialization timeout pin")]
pub async fn expire_confirmation<F: std::future::Future>(
    future: F,
    server: &wiremock::MockServer,
) -> F::Output {
    tokio::time::timeout(std::time::Duration::from_secs(360), async {
        tokio::pin!(future);
        let observed_poll = tokio::time::timeout(std::time::Duration::from_secs(6), async {
            loop {
                if server.received_requests().await.unwrap().iter().any(|request| {
                    serde_json::from_slice::<serde_json::Value>(&request.body).unwrap()["method"] == "getTransaction"
                }) { break; }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        });
        tokio::select! {
            result = &mut future => result,
            result = observed_poll => {
                result.unwrap();
                tokio::time::pause();
                tokio::time::advance(std::time::Duration::from_secs(121)).await;
                tokio::time::resume();
                tokio::time::timeout(std::time::Duration::from_secs(6), future).await.unwrap()
            }
        }
    }).await.unwrap()
}
