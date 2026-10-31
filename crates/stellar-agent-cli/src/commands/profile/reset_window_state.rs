//! `stellar-agent profile reset-window-state <name> --reason <reason>` —
//! re-initialise the persisted policy-window-state store to empty.
//!
//! # Command-group placement
//!
//! Placed under `profile` (not a new top-level `policy` group): every other
//! per-profile keyring/state lifecycle command (`enroll-*`, `rotate-*-key`,
//! `sign-policy`) already lives here, and this command has the identical
//! shape (load profile → keyring/state op → audit row) as the `rotate-*-key`
//! siblings. Introducing a new top-level group for one command would fragment
//! an already-established taxonomy without a second command to justify it.
//!
//! # When to use
//!
//! The window-state store fails closed on an unreadable, tampered
//! (HMAC-mismatched), or unparseable file: `per_period_cap` / `rate_limit` /
//! `bundle_per_period_cap` / `bundle_rate_limit` criteria deny every call with
//! `CriterionEvaluationFailed` until the store is recovered. This command is
//! that recovery path — it discards accumulated history (the operator loses
//! period-cap continuity for the reset profile) rather than attempting
//! partial repair of a file whose integrity cannot be established.
//!
//! # Audit-row ordering
//!
//! The command acquires the audit writer, then the store lock. It records the
//! live wiped accrual before minting a key or replacing the store. A reset whose
//! row cannot be written refuses on every chain. A running MCP server holds the
//! audit writer, so the operator stops it before resetting.
//!
//! The row records intent and the generation pair. Completion requires loading
//! the empty store at the recorded generation after the mutation.
//!
//! # Newer formats
//!
//! On every chain, a store whose authenticated format version is newer than
//! this build reads refuses the reset with
//! `profile.reset_window_state_newer_version` and changes nothing; the build
//! that wrote it reads it.
//!
//! # Mainnet profiles
//!
//! An enablement nonce requires `--owner-secret-env VAR` holding the pinned
//! owner's seed in every build. The nonce and pin are read under the scoped
//! store lock. With the flag, the seed must match the pin even without a nonce.
//! Owner and pin refusals write no row and change no store, generation or key.
//! The row records the owner's signature over the profile, chain, store digest,
//! generation pair, reason bounded to 80 Unicode characters and request id.
//!
//! In a build with mainnet writes, the store of a mainnet profile refuses to
//! load when it cannot be verified (`policy.window_state_unverifiable`). This
//! command resets such a store, and the audit row's `reason` names the defect
//! it recovers from beside the operator's reason. A verifiable store that
//! still holds an open mainnet authorization refuses the reset with
//! `profile.reset_window_state_open_authorizations` and changes nothing.
//!
//! # Output (JSON envelope)
//!
//! The success envelope reports the wiped accrual. The audit row also carries
//! `owner_authorization` when `--owner-secret-env` supplies the pinned seed.
//!
//! On success:
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "profile": "default",
//!     "reset": true,
//!     "reason": "corrupt-file recovery",
//!     "wiped": {
//!       "previous": "missing", "entry_count": 0, "buckets": [],
//!       "truncated": false, "generation_before": null, "generation_after": 1
//!     }
//!   },
//!   "request_id": "..."
//! }
//! ```
//!
//! # Errors
//!
//! Returns exit code `1` when the profile cannot be loaded or the store
//! reset fails, an enabled profile lacks the owner seed, the seed is invalid,
//! the pin is absent or unreadable, or the supplied seed does not match it.

use super::owner_seed::{OwnerSeedError, with_owner_seed};
use clap::{ArgGroup, Args};
use serde::Serialize;
use stellar_agent_core::audit_log::BindingCheck;
use stellar_agent_core::audit_log::KeyPurpose;
use stellar_agent_core::audit_log::schema::{
    WindowResetAuthorization, WipedAccrualRecord, bound_window_reset_reason,
};
use stellar_agent_core::audit_log::{AuditEntry, AuditWriter, WriterError, audit_writer_refusal};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, ValidationError, WalletError, WalletStateError};
use stellar_agent_core::policy::PolicyError;
use stellar_agent_core::policy::pin::PinState;
use stellar_agent_core::policy::v1::signature::{WindowResetStatement, sign, window_reset_digest};
use stellar_agent_core::profile::owner_key::encode_owner_public_key;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_core::profile::{ResolvedProfileName, loader};
use stellar_agent_network::keyring::init_platform_keyring_store;
use stellar_agent_network::policy_state::{
    PersistedWindowStore, ResetError, ResetRecord, StateDefect, WindowStoreError,
};
use uuid::Uuid;

use crate::common::profile_access::{
    injected_profile_load, profile_access_envelope, reconcile_loaded_profile,
};
use crate::common::render;

use crate::commands::value_audit::{
    acquire_keyed_audit_writer, append_value_audit_row_strict, audit_writer_open_failed,
};

use super::audit_emit::emit_keyring_key_written_with_writer;

/// Arguments for `stellar-agent profile reset-window-state`.
#[derive(Debug, Args)]
#[non_exhaustive]
#[command(group(ArgGroup::new("profile_target").args(["name", "profile"]).required(true)))]
pub(crate) struct ResetWindowStateArgs {
    /// Profile name whose policy-window-state store should be reset, positional
    /// form.
    ///
    /// Exactly one of this positional `NAME` or the `--profile <NAME>` flag is
    /// required; supplying both, or neither, is a usage error.
    #[arg(value_name = "NAME")]
    pub(crate) name: Option<String>,

    /// Profile name whose policy-window-state store should be reset, flag form;
    /// an alternative to the positional `NAME`.
    ///
    /// Exactly one of the positional `NAME` or this `--profile <NAME>` flag is
    /// required; supplying both, or neither, is a usage error.
    #[arg(long, value_name = "NAME")]
    pub(crate) profile: Option<String>,

    /// Operator-supplied reason for the reset, recorded in the audit row
    /// (e.g. `"corrupt-file recovery"`).
    #[arg(long)]
    pub(crate) reason: String,

    /// Environment variable containing the pinned policy owner's S-strkey.
    /// Supply the variable name, never the secret itself.
    #[arg(long, value_name = "VAR")]
    pub(crate) owner_secret_env: Option<String>,
}

impl ResetWindowStateArgs {
    /// Returns the resolved profile name.
    ///
    /// The clap arg group over the positional `NAME` and `--profile` is
    /// `required` and mutually exclusive, so a parsed invocation sets exactly
    /// one of the two fields; this returns whichever was supplied.
    pub(super) fn profile_name(&self) -> &str {
        self.name
            .as_deref()
            .or(self.profile.as_deref())
            .unwrap_or_default()
    }
}

/// Success payload for the `reset-window-state` envelope.
#[derive(Debug, Serialize)]
struct ResetWindowStateData {
    /// Name of the profile whose window-state store was reset.
    profile: String,
    /// Always `true` on success.
    reset: bool,
    /// The operator-supplied reason, echoed back.
    reason: String,
    /// Live accrual recorded before the mutation.
    wiped: WipedAccrualRecord,
}

/// Runs `stellar-agent profile reset-window-state <name> --reason <reason>`.
///
/// Returns `0` on success, `1` on error.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &ResetWindowStateArgs) -> i32 {
    run_with_dependencies(args, injected_profile_load, init_platform_keyring_store).await
}

/// Runs the reset with profile loading and keyring initialization supplied.
async fn run_with_dependencies(
    args: &ResetWindowStateArgs,
    load_profile: impl FnOnce(&str) -> Result<Profile, loader::ProfileLoadError>,
    init_keyring: impl FnOnce() -> Result<(), WalletError>,
) -> i32 {
    if args.reason.trim().is_empty() {
        render::render_json(&Envelope::<()>::err_raw(
            "validation.reason_empty",
            "--reason must contain non-whitespace text",
        ));
        return 1;
    }

    let profile = match reconcile_loaded_profile(
        load_profile(args.profile_name()),
        &ResolvedProfileName::from_flag(args.profile_name()),
    ) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(profile = %args.profile_name(), error = %e, "profile access refused");
            render::render_json(&profile_access_envelope(&e, args.profile_name()));
            return 1;
        }
    };

    if let Err(e) = stellar_agent_core::profile::owner_key::refuse_installation_key_coordinate(
        &profile.policy_window_state_key_id,
        stellar_agent_network::policy_state::POLICY_STATE_KEY_FIELD,
    ) {
        render::render_json(&Envelope::err(&e));
        return 1;
    }
    if let Err(e) = init_keyring() {
        render::render_json(&Envelope::err(&e));
        return 1;
    }

    if let Some(var) = args.owner_secret_env.as_deref() {
        return match with_owner_seed(
            var,
            "profile-reset-window-state",
            profile.wallet.mlock_required,
            profile.wallet.unlock_ttl_seconds,
            async |key| Ok::<_, OwnerSeedError>(reset_with_owner(args, &profile, Some(key))),
        )
        .await
        {
            Ok(code) => code,
            Err(error) => {
                let error = match error {
                    OwnerSeedError::NotSet { var } => {
                        WalletError::Validation(ValidationError::SecretEnvNotSet { var })
                    }
                    OwnerSeedError::Invalid { var } => {
                        WalletError::Validation(ValidationError::SecretEnvInvalid { var })
                    }
                    OwnerSeedError::Unlock(detail) => {
                        WalletError::WalletState(WalletStateError::UnlockFailed { detail })
                    }
                };
                render::render_json(&Envelope::err(&error));
                1
            }
        };
    }
    reset_with_owner(args, &profile, None)
}

/// Acquires the writer and resets with the seed already unlocked, when supplied.
fn reset_with_owner(
    args: &ResetWindowStateArgs,
    profile: &Profile,
    key: Option<&ed25519_dalek::SigningKey>,
) -> i32 {
    let name = args.profile_name();
    let writer = match acquire_keyed_audit_writer(profile, name, BindingCheck::Enforce) {
        Ok(writer) => writer,
        Err(error) => {
            render::render_json(&Envelope::err(&error.into_wallet_error(name)));
            return 1;
        }
    };
    let mut writer = match writer.lock() {
        Ok(writer) => writer,
        Err(_) => {
            render::render_json(&Envelope::err(&audit_writer_open_failed(name)));
            return 1;
        }
    };
    let now_ms = match stellar_agent_core::timefmt::now_unix_ms() {
        Ok(now) => now,
        Err(error) => {
            render::render_json(&Envelope::<()>::err_raw(
                "wallet.clock_error",
                error.to_string(),
            ));
            return 1;
        }
    };
    let store = PersistedWindowStore::for_profile(name);
    let request_id = Uuid::new_v4().to_string();
    let result = store.reset(profile, now_ms, |record| {
        let reason = bound_window_reset_reason(&recorded_reason(&args.reason, record.defect));
        let owner_authorization =
            authorize_reset(record, key, profile, name, &reason, &request_id)?;
        record_window_reset(
            &mut writer,
            name,
            &reason,
            &request_id,
            profile.chain_id.caip2_str(),
            record.accrual,
            owner_authorization,
        )
        .map_err(ResetRefusal::Wallet)
    });
    let minted = match &result {
        Ok(outcome) => outcome.mint.newly_minted,
        Err(ResetError::Store { minted, .. }) => *minted,
        Err(ResetError::Recorder(_)) => false,
    };
    if minted {
        emit_keyring_key_written_with_writer(
            &mut writer,
            name,
            "profile_reset_window_state",
            KeyPurpose::PolicyWindowStateHmac,
            &profile.policy_window_state_key_id,
            None,
            &request_id,
        );
    }
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(error) => {
            let error = match error {
                ResetError::Recorder(error) => error,
                ResetError::Store { error, .. } => ResetRefusal::Wallet(store_refusal(name, error)),
            };
            render::render_json(&Envelope::<()>::err_raw(error.code(), error.message()));
            return 1;
        }
    };

    render::render_json(&Envelope::ok(ResetWindowStateData {
        profile: args.profile_name().to_owned(),
        reset: true,
        reason: args.reason.clone(),
        wiped: outcome.accrual,
    }));
    0
}

/// A typed refusal rendered by the reset ceremony.
enum ResetRefusal {
    Validation(ValidationError),
    Policy(PolicyError),
    PinAbsent { profile: String },
    Wallet(WalletError),
}

impl ResetRefusal {
    fn code(&self) -> &'static str {
        match self {
            Self::Validation(error) => error.code(),
            Self::Policy(error) => error.wire_code(),
            Self::PinAbsent { .. } => PolicyError::PinAbsent.wire_code(),
            Self::Wallet(error) => error.code(),
        }
    }

    fn message(&self) -> String {
        match self {
            Self::Validation(error) => error.to_string(),
            Self::Policy(error) => error.to_string(),
            Self::PinAbsent { profile } => format!(
                "no policy pin names an owner for profile '{profile}'; \
                 run without --owner-secret-env"
            ),
            Self::Wallet(error) => error.to_string(),
        }
    }
}

/// Checks the live nonce and pin under the store lock and signs the reset.
fn authorize_reset(
    record: &ResetRecord<'_>,
    key: Option<&ed25519_dalek::SigningKey>,
    profile: &Profile,
    name: &str,
    reason: &str,
    request_id: &str,
) -> Result<Option<WindowResetAuthorization>, ResetRefusal> {
    let enabled = stellar_agent_core::mainnet::enablement::has_enablement_nonce(profile)
        .map_err(ResetRefusal::Validation)?;
    if enabled && key.is_none() {
        return Err(ResetRefusal::Validation(
            ValidationError::ResetWindowStateOwnerRequired {
                profile: name.to_owned(),
            },
        ));
    }
    let Some(key) = key else {
        return Ok(None);
    };
    let pin = record
        .pin()
        .map_err(|error| ResetRefusal::Policy(PolicyError::from(error)))?;
    let PinState::Present(pin) = pin else {
        return Err(ResetRefusal::PinAbsent {
            profile: name.to_owned(),
        });
    };
    let derived = key.verifying_key().to_bytes();
    if derived != pin.owner() {
        return Err(ResetRefusal::Validation(
            ValidationError::ResetWindowStateOwnerMismatch {
                profile: name.to_owned(),
                derived: encode_owner_public_key(&derived),
                pinned: encode_owner_public_key(&pin.owner()),
            },
        ));
    }
    let digest = window_reset_digest(&WindowResetStatement {
        profile: name,
        chain_id: profile.chain_id.caip2_str(),
        store_sha256: record.store_sha256,
        generation_before: record.accrual.generation_before,
        generation_after: record.accrual.generation_after,
        reason,
        request_id,
    });
    Ok(Some(WindowResetAuthorization {
        owner_redacted: stellar_agent_core::observability::RedactedStrkey::from_full(
            &encode_owner_public_key(&derived),
        ),
        store_sha256: record
            .store_sha256
            .map(|hash| stellar_agent_core::hex::encode(&hash)),
        signature: stellar_agent_core::hex::encode(&sign(&digest, key)),
    }))
}

/// The reason the audit row records: the operator's reason and, when the reset
/// recovers an unverifiable mainnet store, the defect found.
fn recorded_reason(reason: &str, defect: Option<StateDefect>) -> String {
    match defect {
        Some(defect) => format!("{reason} (unverifiable state: {defect})"),
        None => reason.to_owned(),
    }
}

/// Maps a store failure of the reset to its agent-facing error.
///
/// A store written by a newer build and the mainnet refusals carry their own
/// validation codes; every other store failure is a wallet defect.
fn store_refusal(name: &str, error: WindowStoreError) -> WalletError {
    match error {
        WindowStoreError::UnsupportedVersion { version, max } => {
            WalletError::Validation(ValidationError::ResetWindowStateNewerVersion {
                profile: name.to_owned(),
                version,
                max,
            })
        }
        #[cfg(feature = "mainnet-write")]
        WindowStoreError::MainnetStateUnverifiable { defect } => {
            WalletError::Validation(ValidationError::WindowStateUnverifiable {
                profile: name.to_owned(),
                defect: defect.label(),
            })
        }
        #[cfg(feature = "mainnet-write")]
        WindowStoreError::OpenAuthorizations { open } => {
            WalletError::Validation(ValidationError::ResetWindowStateOpenAuthorizations {
                profile: name.to_owned(),
                open,
            })
        }
        error => WalletError::Internal(InternalError::UnexpectedState {
            detail: format!("policy_window_state.reset_failed: {error}"),
        }),
    }
}

/// Records the attempted reset before the store or generation changes.
///
/// Three steps run under the held writer, and a refusal at any of them stops
/// the reset. [`AuditWriter::require_anchor_current`] first refuses a behind
/// tip anchor before the row is written. The reset row follows. The second
/// [`AuditWriter::require_anchor_current`] refuses when the row's own anchor
/// write failed, so the store is never wiped on a row the anchor does not
/// cover. A refusal there leaves a durable row describing an attempted reset
/// that did not take effect.
fn record_window_reset(
    writer: &mut AuditWriter,
    name: &str,
    reason: &str,
    request_id: &str,
    chain_id: &str,
    accrual: &WipedAccrualRecord,
    owner_authorization: Option<WindowResetAuthorization>,
) -> Result<(), WalletError> {
    writer
        .require_anchor_current()
        .map_err(|e| anchor_refusal(name, &e))?;
    let entry = AuditEntry::new_policy_window_state_reset(
        "profile_reset_window_state",
        name,
        reason,
        request_id,
        chain_id,
        accrual.clone(),
        owner_authorization,
    );
    append_value_audit_row_strict(writer, name, entry)?;
    writer
        .require_anchor_current()
        .map_err(|e| anchor_refusal(name, &e))
}

/// Maps a tip-anchor refusal to the audit refusal and logs it the way a refused
/// strict append is logged.
fn anchor_refusal(name: &str, e: &WriterError) -> WalletError {
    tracing::warn!(
        profile = %name,
        error = %e,
        "audit tip anchor cannot be written; refusing the reset that requires it"
    );
    audit_writer_refusal(name, e)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use clap::Parser;
    use clap::error::ErrorKind;
    use serial_test::serial;

    use super::*;

    /// Local flatten wrapper so the `ResetWindowStateArgs` clap contract can be
    /// parsed in isolation from the full command tree. The required `--reason`
    /// is supplied in every case so the only variable under test is the
    /// profile-target group.
    #[derive(Debug, Parser)]
    struct Wrap {
        #[command(flatten)]
        args: ResetWindowStateArgs,
    }

    #[test]
    fn positional_name_is_accepted() {
        let w = Wrap::try_parse_from(["prog", "acme", "--reason", "recovery"])
            .expect("positional parses");
        assert_eq!(w.args.profile_name(), "acme");
    }

    #[test]
    fn profile_flag_is_accepted() {
        let w = Wrap::try_parse_from(["prog", "--profile", "acme", "--reason", "recovery"])
            .expect("flag parses");
        assert_eq!(w.args.profile_name(), "acme");
    }

    #[test]
    fn the_owner_secret_env_flag_parses() {
        let parsed = Wrap::try_parse_from([
            "prog",
            "acme",
            "--reason",
            "repair",
            "--owner-secret-env",
            "OWNER_SEED",
        ])
        .unwrap();
        assert_eq!(parsed.args.owner_secret_env.as_deref(), Some("OWNER_SEED"));
        let absent = Wrap::try_parse_from(["prog", "acme", "--reason", "repair"]).unwrap();
        assert!(absent.args.owner_secret_env.is_none());
    }

    #[test]
    fn both_positional_and_flag_is_a_conflict() {
        let err =
            Wrap::try_parse_from(["prog", "acme", "--profile", "other", "--reason", "recovery"])
                .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn neither_positional_nor_flag_is_missing_required() {
        let err = Wrap::try_parse_from(["prog", "--reason", "recovery"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[tokio::test]
    #[serial]
    async fn reset_window_state_nonexistent_profile_returns_exit_1() {
        let args = ResetWindowStateArgs {
            name: Some("__nonexistent_reset_window_state__".to_owned()),
            profile: None,
            reason: "test".to_owned(),
            owner_secret_env: None,
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }

    #[test]
    #[serial]
    fn an_anchor_refusal_preserves_window_state_and_generation() {
        use std::sync::Arc;
        use stellar_agent_core::audit_log::KeyedAuditAccess;
        use stellar_agent_core::audit_log::tip_anchor::InMemoryTipAnchorStore;
        use stellar_agent_core::policy::v1::criteria::state_store::{
            StateKey, WindowEntry, WindowLimit,
        };
        use stellar_agent_core::profile::schema::{Profile, generation_account};
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let profile =
            Profile::builder_testnet_named("reset-anchor", "signer", "account", "nonce", "account")
                .with_noop_engine()
                .audit_log_path(dir.path().join("audit.jsonl"))
                .build();
        let path = dir.path().join("window.json");
        let store = PersistedWindowStore::at_path(path.clone());
        store
            .record_and_persist(
                &profile,
                &[WindowEntry::new(
                    StateKey::new("reset-anchor", 3, "native", 86_400),
                    100_000,
                    99,
                    WindowLimit::Amount {
                        asset: "native".to_owned(),
                        window: "1d".to_owned(),
                        max_stroops: 1_000,
                    },
                )],
            )
            .unwrap();
        let key = &profile.policy_window_state_key_id;
        let generation =
            keyring_core::Entry::new(&key.service, &generation_account(&key.account)).unwrap();
        let before = std::fs::read(&path).unwrap();
        let counter = generation.get_password().unwrap();
        let anchor = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = AuditWriter::open(
            profile.audit_log_path.clone(),
            Some(KeyedAuditAccess::new(
                zeroize::Zeroizing::new([0x5a; 32]),
                anchor.clone(),
            )),
        )
        .unwrap();
        anchor.set_failing(true);
        let result = store.reset(&profile, 100_000, |record| {
            record_window_reset(
                &mut writer,
                "reset-anchor",
                "repair",
                "reset-request",
                "stellar:testnet",
                record.accrual,
                None,
            )
        });
        let Err(ResetError::Recorder(error)) = result else {
            panic!("an unanchored reset row must refuse the wipe");
        };
        assert_eq!(error.code(), "audit.chain_key_unavailable");
        assert!(error.to_string().contains("audit.tip_anchor_unavailable"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(generation.get_password().unwrap(), counter);
        // The open's boundary row and the unanchored reset row.
        let rows = std::fs::read(&profile.audit_log_path).unwrap();
        assert_eq!(String::from_utf8_lossy(&rows).lines().count(), 2);
        assert!(
            store
                .reset(&profile, 100_000, |record| record_window_reset(
                    &mut writer,
                    "reset-anchor",
                    "repair",
                    "reset-request",
                    "stellar:testnet",
                    record.accrual,
                    None,
                ))
                .is_err()
        );
        assert_eq!(std::fs::read(&profile.audit_log_path).unwrap(), rows);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(generation.get_password().unwrap(), counter);
    }

    #[test]
    #[serial]
    fn the_enablement_nonce_is_read_under_the_store_lock() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use stellar_agent_core::policy::state_lock::{StateLockError, WindowStoreLock};
        use stellar_agent_core::profile::schema::{
            default_policy_window_state_path_for, mainnet_enablement_entry_ref,
        };
        use stellar_agent_test_support::keyring_mock::{ReadHook, install_with_read_hooks};

        let dir = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let name = "reset-nonce-lock";
        let profile = Profile::builder_testnet_named(name, "signer", "account", "nonce", "account")
            .with_noop_engine()
            .audit_log_path(dir.path().join("audit.jsonl"))
            .build();
        let path = default_policy_window_state_path_for(name);
        let coordinate = profile.policy_window_state_key_id.clone();
        let nonce = mainnet_enablement_entry_ref(&coordinate);
        let reads = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&reads);
        install_with_read_hooks(vec![ReadHook::new(
            &nonce.service,
            &nonce.account,
            Arc::new(move || {
                assert!(matches!(
                    WindowStoreLock::acquire_for(&path, &coordinate),
                    Err(StateLockError::WriterLocked)
                ));
                observed.fetch_add(1, Ordering::SeqCst);
            }),
        )])
        .unwrap();
        let audit_key = &profile.audit_log_hash_chain_key_id;
        use base64::Engine as _;
        keyring_core::Entry::new(&audit_key.service, &audit_key.account)
            .unwrap()
            .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x2c; 32]))
            .unwrap();
        let args = ResetWindowStateArgs {
            name: Some(name.to_owned()),
            profile: None,
            reason: "repair".to_owned(),
            owner_secret_env: None,
        };
        assert_eq!(reset_with_owner(&args, &profile, None), 0);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_recorded_reason_names_the_defect_it_recovers_from() {
        assert_eq!(recorded_reason("repair", None), "repair");
        assert_eq!(
            recorded_reason("repair", Some(StateDefect::HmacInvalid)),
            "repair (unverifiable state: hmac_invalid)"
        );
        assert_eq!(
            recorded_reason("repair", Some(StateDefect::MissingFileWithGeneration)),
            "repair (unverifiable state: missing_file_with_generation)"
        );
    }

    #[test]
    fn an_ordinary_store_failure_is_a_wallet_defect() {
        let error = store_refusal("acme", WindowStoreError::HmacMismatch);
        assert_eq!(error.code(), "internal.unexpected_state");
        assert!(
            error
                .to_string()
                .contains("policy_window_state.reset_failed")
        );
    }

    #[test]
    fn a_store_from_a_newer_build_is_a_validation_refusal() {
        let error = store_refusal(
            "acme",
            WindowStoreError::UnsupportedVersion { version: 5, max: 4 },
        );
        assert_eq!(error.code(), "profile.reset_window_state_newer_version");
        assert_eq!(
            error.category(),
            stellar_agent_core::error::ErrorCategory::Validation
        );
        let text = error.to_string();
        assert!(text.contains("profile 'acme'"), "{text}");
        assert!(text.contains("format version 5"), "{text}");
        assert!(text.contains("version 4 this build reads"), "{text}");
        assert!(text.contains("Use the build that wrote it"), "{text}");
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    fn the_mainnet_store_refusals_keep_their_codes() {
        let unverifiable = store_refusal(
            "acme",
            WindowStoreError::MainnetStateUnverifiable {
                defect: StateDefect::GenerationMismatch,
            },
        );
        assert_eq!(unverifiable.code(), "policy.window_state_unverifiable");
        let text = unverifiable.to_string();
        assert!(text.contains("generation_mismatch"), "{text}");
        assert!(
            text.contains("stellar-agent profile reset-window-state acme --reason <reason>"),
            "{text}"
        );
        let open = store_refusal("acme", WindowStoreError::OpenAuthorizations { open: 2 });
        assert_eq!(
            open.code(),
            "profile.reset_window_state_open_authorizations"
        );
        assert!(open.to_string().contains('2'), "{open}");
    }

    /// Window reset refuses installation coordinates before opening keys.
    #[tokio::test]
    #[serial_test::serial]
    async fn installation_coordinate_refuses_without_writing() {
        crate::common::installation_key_fixture::assert_installation_profile_refusal(
            |profile| &mut profile.policy_window_state_key_id,
            async |fixture, profile, name| {
                let args = ResetWindowStateArgs {
                    name: Some(name.to_owned()),
                    profile: None,
                    reason: "reset fixture".to_owned(),
                    owner_secret_env: None,
                };
                run_with_dependencies(&args, |_| Ok(profile.clone()), || fixture.init()).await
            },
        )
        .await;
    }
}
