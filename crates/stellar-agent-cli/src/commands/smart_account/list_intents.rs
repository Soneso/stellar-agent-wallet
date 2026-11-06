//! Read-only inspection of retained smart-account intent charges.

use super::common::{load_command_profile, map_access_error};
use crate::common::{render::render_json, resolve_profile_name};
use clap::Args;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::{SubmissionError, WalletError};
use stellar_agent_network::policy_state::PersistedWindowStore;

/// Arguments for the retained intent view.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ListIntentsArgs {
    /// The profile whose authenticated intent records are listed.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,
    /// Output format.
    #[arg(long, value_enum, default_value = "json")]
    pub output: OutputFormat,
}

/// Lists authenticated intents without changing their records.
pub async fn run(args: &ListIntentsArgs) -> i32 {
    if matches!(args.output, OutputFormat::Table) {
        tracing::warn!(
            "--output table is accepted for forward compatibility but only the \
             JSON renderer is shipped; falling back to JSON"
        );
    }
    let resolved = resolve_profile_name(args.profile.as_deref());
    let (profile, _) = match load_command_profile(&resolved) {
        Ok(profile) => profile,
        Err(error) => {
            render_json(&Envelope::<()>::err(&map_access_error(&error)));
            return 1;
        }
    };
    match list(
        &resolved.name,
        &profile,
        super::common::ensure_keyring_store,
    ) {
        Ok(intents) => {
            render_json(&Envelope::ok(
                serde_json::json!({ "signed_intents": intents }),
            ));
            0
        }
        Err(error) => {
            render_json(&Envelope::<()>::err(&error));
            1
        }
    }
}

fn list(
    name: &str,
    profile: &stellar_agent_core::profile::schema::Profile,
    ensure: impl FnOnce() -> Result<(), WalletError>,
) -> Result<Vec<stellar_agent_network::policy_state::SignedIntentView>, WalletError> {
    ensure()?;
    read_intents(name, profile)
}

fn read_intents(
    name: &str,
    profile: &stellar_agent_core::profile::schema::Profile,
) -> Result<Vec<stellar_agent_network::policy_state::SignedIntentView>, WalletError> {
    PersistedWindowStore::for_profile(name)
        .signed_intents(name, profile)
        .map_err(|_| {
            WalletError::Submission(SubmissionError::RecordUnavailable {
                detail: "the authenticated intent window is unavailable".to_owned(),
            })
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture assertions")]
    use super::*;

    struct RestoreStore(Option<std::sync::Arc<keyring_core::CredentialStore>>);

    impl Drop for RestoreStore {
        fn drop(&mut self) {
            keyring_core::unset_default_store();
            if let Some(store) = self.0.take() {
                keyring_core::set_default_store(store);
            }
        }
    }

    #[test]
    #[serial_test::serial]
    fn a_fresh_process_registers_its_keyring_before_reading() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let mut results = Vec::new();
        for (name, expected) in [("intent", 2), ("fresh", 0)] {
            let profile = stellar_agent_core::profile::schema::Profile::builder_testnet_named(
                name,
                "view",
                "account",
                "view-nonce",
                "account",
            )
            .build();
            let store = PersistedWindowStore::for_profile(name);
            if expected == 2 {
                stellar_agent_network::signed_intent::test_helpers::seed_two_intents(
                    &profile, &store,
                )
                .unwrap();
            } else {
                assert!(!store.path().exists());
            }
            let saved = keyring_core::unset_default_store().unwrap();
            let _restore = RestoreStore(Some(saved.clone()));
            let mut calls = 0;
            let result = list(name, &profile, || {
                super::super::common::ensure_keyring_store_with(|| {
                    keyring_core::set_default_store(saved.clone());
                    calls += 1;
                    Ok(())
                })
            });
            results.push((
                name,
                result
                    .map(|intents| intents.len())
                    .map_err(|error| error.code().to_owned()),
                calls,
            ));
        }
        assert_eq!(results, [("intent", Ok(2), 1), ("fresh", Ok(0), 1)]);
    }

    #[test]
    #[serial_test::serial]
    fn intent_view_reads_without_writing_and_refuses_tampering() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let profile = stellar_agent_core::profile::schema::Profile::builder_testnet_named(
            "intent",
            "view",
            "account",
            "view-nonce",
            "account",
        )
        .build();
        let store = PersistedWindowStore::for_profile("intent");
        stellar_agent_network::signed_intent::test_helpers::seed_two_intents(&profile, &store)
            .unwrap();
        let before = stellar_agent_test_support::file_sha256(store.path());
        let key = &profile.policy_window_state_key_id;
        let generation = keyring_core::Entry::new(
            &key.service,
            &stellar_agent_core::profile::schema::generation_account(&key.account),
        )
        .unwrap();
        let generation_before = generation.get_password().unwrap();
        let intents = read_intents("intent", &profile).unwrap();
        assert_eq!(intents.len(), 2);
        for intent in &intents {
            assert_eq!(
                intent.status,
                if intent.bound_tx_hash.is_some() {
                    "authorization exposed, submission bound"
                } else {
                    "authorization exposed, submission unknown"
                }
            );
        }
        let mut labels = intents
            .iter()
            .map(|i| i.status.as_str())
            .collect::<Vec<_>>();
        labels.sort_unstable();
        assert_eq!(
            labels,
            [
                "authorization exposed, submission bound",
                "authorization exposed, submission unknown"
            ]
        );
        assert!(
            intents
                .iter()
                .all(|i| i.accounting_horizon == "open" && i.legs.len() == 2)
        );
        assert_eq!(
            stellar_agent_test_support::file_sha256(store.path()),
            before
        );
        assert_eq!(generation.get_password().unwrap(), generation_before);
        let mut corrupt = std::fs::read(store.path()).unwrap();
        corrupt[0] ^= 1;
        std::fs::write(store.path(), &corrupt).unwrap();
        let corrupt_digest = stellar_agent_test_support::file_sha256(store.path());
        assert_eq!(
            read_intents("intent", &profile).unwrap_err().code(),
            "submission.record_unavailable"
        );
        assert_eq!(
            stellar_agent_test_support::file_sha256(store.path()),
            corrupt_digest
        );
        assert_eq!(generation.get_password().unwrap(), generation_before);
    }
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn intent_views_report_horizons_without_mutation() {
        use stellar_agent_network::intent_view_test_helpers::IntentViewFixture;
        for mode in ["invoke", "done", "unset", "unclassified"] {
            let fixture = IntentViewFixture::new(mode).await;
            for endpoint_state in ["complete", "missing", "unreadable"] {
                fixture.set_endpoints(endpoint_state);
                let value =
                    serde_json::to_value(list("intent", &fixture.profile, || Ok(())).unwrap())
                        .unwrap();
                assert_eq!(value.as_array().unwrap().len(), 1);
                fixture.assert_view(&value, endpoint_state);
                fixture.assert_unchanged().await;
            }
            for missing in [false, true] {
                fixture.damage_store(missing);
                let error = list("intent", &fixture.profile, || Ok(())).unwrap_err();
                assert!(
                    matches!(&error, WalletError::Submission(SubmissionError::RecordUnavailable { detail }) if detail == "the authenticated intent window is unavailable")
                );
                assert_eq!(error.code(), "submission.record_unavailable");
                fixture.assert_resources_unchanged().await;
                if missing {
                    assert!(!fixture.store.path().exists());
                }
            }
        }
    }
}
