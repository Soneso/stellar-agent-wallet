//! Production submission recorder state for the protocol acceptance suites.
//!
//! The DEX and DeFindex testnet acceptance suites record each submission the
//! way the CLI records it. This module holds the one copy of that wallet state.
//! It is gated behind the `test-helpers` feature and never reaches a release
//! binary.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "acceptance fixtures fail the test on a broken precondition"
)]

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use stellar_agent_core::policy::v1::{PolicyEngineV1, ValueEffects};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::policy_state::{PersistedWindowStore, SignedIntentView};
use stellar_agent_network::{AuditWriterHandle, WalletSubmissionRecorder};

/// The daily `native` cap the acceptance policies size an action against: 100 XLM.
///
/// The cap is far above the actions, so it never refuses. Its role is to give
/// the debit leg a window entry, which the recorder charges as the signed
/// intent before the first signature.
pub const NATIVE_DAILY_CAP_STROOPS: i128 = 1_000_000_000;

/// Wallet state the production submission recorder writes for one submission.
///
/// The receipt store and the spending-window file live in a directory the
/// state owns, and the window store's key lives in the in-memory keyring.
/// The run never touches an operator's wallet state.
///
/// The recorder is built the way the CLI builds it: the policy engine sizes the
/// gate's value effects. That sizing is both the recorder's window entries and
/// its signing admission.
pub struct SubmissionRecordState {
    dir: tempfile::TempDir,
    profile: Profile,
    profile_name: String,
    chain_id: String,
    engine: PolicyEngineV1,
}

impl SubmissionRecordState {
    /// Creates the state for `profile_name` on `chain_id`, auditing to
    /// `audit_log_path`.
    ///
    /// The first call in a process installs the in-memory keyring. The policy
    /// allows every tool on every chain under the daily `native` cap
    /// [`NATIVE_DAILY_CAP_STROOPS`].
    ///
    /// # Panics
    ///
    /// Panics when the in-memory keyring cannot be installed or the record
    /// directory cannot be created.
    #[must_use]
    pub fn new(profile_name: &str, chain_id: &str, audit_log_path: &Path) -> Self {
        use stellar_agent_core::policy::{
            Decision,
            v1::{
                PolicyDocument, PolicyRule, RuleMatch, ScopeId,
                criteria::per_period_cap::{PerPeriodCapCriterion, Window},
            },
        };

        static KEYRING: std::sync::Once = std::sync::Once::new();
        KEYRING.call_once(|| {
            stellar_agent_test_support::keyring_mock::install()
                .expect("install the in-memory keyring");
        });
        let dir = tempfile::Builder::new()
            .prefix(profile_name)
            .tempdir()
            .expect("create the record directory");
        let profile = Profile::builder_testnet(
            "stellar-agent-signer",
            profile_name,
            "stellar-agent-nonce",
            profile_name,
        )
        .audit_log_path(audit_log_path)
        .build();
        let engine = PolicyEngineV1::new(
            PolicyDocument {
                version: 1,
                scope: ScopeId::AllProfiles,
                signature: None,
                rules: vec![PolicyRule {
                    r#match: RuleMatch {
                        tool: "*".into(),
                        chain: "*".into(),
                    },
                    criteria: vec![Box::new(PerPeriodCapCriterion::new(
                        "native".into(),
                        Window::parse("1d").expect("a one-day window"),
                        NATIVE_DAILY_CAP_STROOPS,
                    ))],
                    decision: Decision::Allow,
                    allow_opaque_signing: false,
                }],
            },
            profile_name.to_owned(),
        );
        Self {
            dir,
            profile,
            profile_name: profile_name.to_owned(),
            chain_id: chain_id.to_owned(),
            engine,
        }
    }

    fn window_store(&self) -> PersistedWindowStore {
        PersistedWindowStore::at_path(self.dir.path().join("policy-window-state.json"))
    }

    /// Builds the recorder for one submission of `tool` with `effects`.
    ///
    /// # Panics
    ///
    /// Panics when the acceptance policy does not size `effects`, or when the
    /// receipt store or the clock cannot be read.
    #[must_use]
    pub fn recorder(
        &self,
        tool: &'static str,
        effects: &ValueEffects,
        audit: AuditWriterHandle,
    ) -> WalletSubmissionRecorder<'_> {
        use stellar_agent_core::policy::{
            McpToolRegistration, PolicyEngine, ToolDescriptor, ToolValueKind,
            v1::{SizingOutcome, ValueClass},
        };

        let mut descriptor = ToolDescriptor::from_registration(&McpToolRegistration {
            name: tool,
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: ToolValueKind::MovesValue,
        });
        descriptor.chain_id = self.chain_id.clone();
        let sizing = match self
            .engine
            .record_confirmed_checked(
                &descriptor,
                &self.profile,
                &ValueClass::Value(effects.clone()),
            )
            .expect("the acceptance policy sizes the action")
        {
            SizingOutcome::Sized(sizing) => sizing,
            other => panic!("the acceptance policy must size the action, got {other:?}"),
        };
        let legs = effects.legs().iter().map(Into::into).collect();
        let window_entries = sizing.entries().to_vec();
        WalletSubmissionRecorder::new(
            &self.profile,
            self.profile_name.clone(),
            tool,
            Some(self.chain_id.clone()),
            stellar_agent_core::audit_log::PolicyDecision::Allow,
            legs,
            window_entries,
            stellar_agent_core::profile::receipt::ReceiptStore::open_at(
                self.dir.path(),
                &self.profile_name,
            )
            .expect("open the receipt store"),
            self.window_store(),
            Some(audit),
            None,
            format!("{}-{}", self.profile_name, now_secs()),
            stellar_agent_core::timefmt::now_unix_ms().expect("read the clock"),
        )
        .with_signing_sizing(sizing)
    }

    /// The amount and call count the durable window holds under the daily
    /// `native` cap, read back the way the policy gate reads it.
    ///
    /// # Panics
    ///
    /// Panics when the window state cannot be loaded or queried.
    #[must_use]
    pub fn native_window(&self) -> (i128, u32) {
        let state = stellar_agent_core::policy::v1::PolicyStateStore::new();
        self.window_store()
            .load_into(&self.profile_name, &self.profile, &state)
            .expect("load the window state");
        state
            .query_window(
                &stellar_agent_core::policy::v1::criteria::state_store::StateKey::new(
                    &self.profile_name,
                    1,
                    "native",
                    86_400,
                ),
                stellar_agent_core::timefmt::now_unix_ms().expect("read the clock"),
            )
            .expect("query the window")
    }

    /// The reservations the window still holds open.
    ///
    /// # Panics
    ///
    /// Panics when the window state cannot be read.
    #[must_use]
    pub fn pending_reservations(&self) -> usize {
        self.window_store()
            .pending_reservations(&self.profile)
            .expect("read the pending reservations")
            .len()
    }

    /// The signed intents the window holds, in admission order.
    ///
    /// # Panics
    ///
    /// Panics when the window state cannot be read or does not authenticate.
    #[must_use]
    pub fn signed_intents(&self) -> Vec<SignedIntentView> {
        self.window_store()
            .signed_intents(&self.profile_name, &self.profile)
            .expect("read the signed intents")
    }
}

/// The current UNIX time in seconds, which keeps request ids distinct per run.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must work")
        .as_secs()
}
