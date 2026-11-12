//! `stellar-agent profile reset-window-state <name> --reason <reason>` clears
//! the window history; the successor keeps every authorization record whose
//! approval can still be presented.
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
//! The command clears verified accumulated history and establishes an empty
//! store only when both the file and protected generation are absent.
//! The successor keeps every authorization record whose approval can still be
//! presented on the store clock.
//! A tampered, unparseable, or rolled-back store refuses before
//! the reset row, as does missing authenticated network provenance.
//! No verb recovers such state in this release; create a profile under a new name.
//! File I/O failures refuse without changing state; retry after access is restored.
//!
//! # Audit-row ordering
//!
//! The command acquires the audit writer, then the store lock. It records the
//! live wiped accrual before minting a key or replacing the store. A reset whose
//! row cannot be written refuses on every chain. A running MCP server holds the
//! audit writer, so the operator stops it before resetting.
//!
//! The row records intent and the generation pair. Completion requires loading
//! the successor at the recorded generation after the mutation.
//!
//! # Owed accounting events
//!
//! Before the reset, the command delivers every owed
//! `submission_accounting_expired` event under the writer it holds. A reset
//! refuses with `submission.record_unavailable` while any such event stays
//! unacknowledged, and the successor keeps each acknowledged record whose
//! receipt projection is incomplete.
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
//! owner's seed in every build. The store reads the nonce and pin under its lock
//! and verifies the owner's signature over the reset statement before the row.
//! Without a nonce, a pin or enrolled owner still requires consent.
//! The pin takes precedence; absent pins use the verified enrolled owner key.
//! Only genuinely ownerless state permits unsigned reset.
//! Owner, pin and signature refusals write no row and change no store,
//! generation or key. The row records the owner's signature over the profile,
//! chain, store digest, generation pair, reason bounded to 50 Unicode
//! characters, request id and the store's challenge.
//!
//! In a build with mainnet writes, unverifiable mainnet state refuses with
//! `policy.window_state_unverifiable`. A verifiable store that still holds
//! an open mainnet authorization refuses the reset with
//! `profile.reset_window_state_open_authorizations` and changes nothing.
//!
//! # Output (JSON envelope)
//!
//! The success envelope reports the wiped accrual. The audit row also carries
//! `owner_authorization` when `--owner-secret-env` supplies the selected owner's seed.
//! Reset preserves stored total-budget entries and creates no epoch.
//!
//! On success:
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "profile": "default",
//!     "reset": true,
//!     "reason": "clear verified window history",
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
//! Returns exit code `1` when the profile cannot be loaded or the store reset
//! fails. It also returns `1` when an owner-protected profile lacks the seed, the
//! seed is invalid or names another owner, authority is absent or unreadable, or
//! the signature does not verify.

use super::owner_seed::{OwnerSeedError, with_owner_seed};
use clap::{ArgGroup, Args};
use serde::Serialize;
use stellar_agent_core::audit_log::BindingCheck;
use stellar_agent_core::audit_log::KeyPurpose;
use stellar_agent_core::audit_log::schema::{WindowResetAuthorization, WipedAccrualRecord};
use stellar_agent_core::audit_log::{AuditEntry, AuditWriter, WriterError, audit_writer_refusal};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{
    InternalError, SubmissionError, ValidationError, WalletError, WalletStateError,
};
use stellar_agent_core::policy::PolicyError;
use stellar_agent_core::policy::v1::signature::sign;
use stellar_agent_core::profile::owner_key::encode_owner_public_key;
use stellar_agent_core::profile::receipt::ReceiptStore;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_core::profile::{ResolvedProfileName, loader};
use stellar_agent_network::keyring::init_platform_keyring_store;
use stellar_agent_network::policy_state::{
    OwnerResetSignature, PersistedWindowStore, ResetConsent, ResetError, ResetRecord,
    WindowStoreError, deliver_accounting_expiries,
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
    /// (e.g. `"clear verified window history"`).
    #[arg(long)]
    pub(crate) reason: String,

    /// Environment variable containing the selected policy owner's S-strkey.
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
            tracing::debug!(error = %e, "profile access refused");
            render::render_json(&profile_access_envelope(&e));
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
                    OwnerSeedError::NotSet => {
                        WalletError::Validation(ValidationError::SecretEnvNotSet)
                    }
                    OwnerSeedError::Invalid => {
                        WalletError::Validation(ValidationError::SecretEnvInvalid)
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
    // Owed accounting events are delivered under the held writer first; the
    // reset refuses while any stays unacknowledged. A store that cannot be
    // read is left to the reset, which reports its own refusal.
    if store
        .owed_accounting_expiries(profile)
        .is_ok_and(|owed| !owed.unacknowledged.is_empty())
    {
        let receipts = ReceiptStore::open(name).ok();
        if let Err(error) =
            deliver_accounting_expiries(&mut writer, &store, profile, name, receipts.as_ref())
        {
            render::render_json(&Envelope::err(&error));
            return 1;
        }
    }
    let request_id = Uuid::new_v4().to_string();
    let result = store.reset(
        profile,
        name,
        now_ms,
        &args.reason,
        &request_id,
        |record| Ok(sign_reset(record, key)),
        |record, consent| {
            record_window_reset(
                &mut writer,
                name,
                record.reason,
                record.request_id,
                record.chain_id,
                record.accrual,
                owner_authorization(record, consent),
            )
            .map_err(ResetRefusal::Wallet)
        },
    );
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
                ResetError::Store { error, .. } => reset_refusal(name, error),
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

/// Signs the reset statement with the owner seed, when one is supplied.
///
/// The store verifies the returned consent under its lock; the command reads
/// neither the enablement nonce nor the pin.
fn sign_reset(record: &ResetRecord<'_>, key: Option<&ed25519_dalek::SigningKey>) -> ResetConsent {
    ResetConsent {
        owner_signature: key.map(|key| OwnerResetSignature {
            owner: key.verifying_key().to_bytes(),
            signature: sign(&record.statement_digest(), key),
        }),
    }
}

/// The audit row's record of the verified owner signature, when presented.
fn owner_authorization(
    record: &ResetRecord<'_>,
    consent: &ResetConsent,
) -> Option<WindowResetAuthorization> {
    consent
        .owner_signature
        .map(|signed| WindowResetAuthorization {
            owner_redacted: stellar_agent_core::observability::RedactedStrkey::from_full(
                &encode_owner_public_key(&signed.owner),
            ),
            store_sha256: record
                .store_sha256
                .map(|hash| stellar_agent_core::hex::encode(&hash)),
            challenge: stellar_agent_core::hex::encode(&record.challenge),
            signature: stellar_agent_core::hex::encode(&signed.signature),
        })
}

/// Maps a store failure of the reset, including a consent refusal, to its
/// rendered refusal.
fn reset_refusal(name: &str, error: WindowStoreError) -> ResetRefusal {
    let profile = name.to_owned();
    match error {
        WindowStoreError::ResetOwnerRequired => {
            ResetRefusal::Validation(ValidationError::ResetWindowStateOwnerRequired { profile })
        }
        WindowStoreError::ResetOwnerMismatch { presented, pinned } => {
            ResetRefusal::Validation(ValidationError::ResetWindowStateOwnerMismatch {
                profile,
                derived: encode_owner_public_key(&presented),
                pinned: encode_owner_public_key(&pinned),
            })
        }
        WindowStoreError::ResetPinAbsent => ResetRefusal::PinAbsent { profile },
        WindowStoreError::ResetPinUnreadable(error) => {
            ResetRefusal::Policy(PolicyError::from(error))
        }
        WindowStoreError::ResetEnablementUnreadable(error) => ResetRefusal::Validation(error),
        WindowStoreError::ResetOwnerUnreadable(error) => ResetRefusal::Wallet(error),
        WindowStoreError::ResetSignatureInvalid => {
            ResetRefusal::Validation(ValidationError::ResetWindowStateSignatureInvalid { profile })
        }
        WindowStoreError::ResetConsentReplayed => {
            ResetRefusal::Policy(PolicyError::ResetConsentReplayed)
        }
        error => ResetRefusal::Wallet(store_refusal(name, error)),
    }
}

/// Maps a store failure of the reset to its agent-facing error.
///
/// A store written by a newer build and the mainnet refusals carry their own
/// validation codes; every other store failure is a wallet defect.
fn store_refusal(name: &str, error: WindowStoreError) -> WalletError {
    if let Some(refusal) = error.chain_validation_error() {
        return WalletError::Validation(refusal);
    }
    match error {
        WindowStoreError::UnsupportedVersion => {
            WalletError::Validation(ValidationError::ResetWindowStateNewerVersion {
                profile: name.to_owned(),
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
        error @ (WindowStoreError::AccountingAuditOwed
        | WindowStoreError::SignedIntentLive { .. }) => {
            WalletError::Submission(SubmissionError::RecordUnavailable {
                detail: error.to_string(),
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
    fn owner_reset_audit_failure_changes_no_state() {
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
        let owner = ed25519_dalek::SigningKey::from_bytes(&[0x51; 32]);
        let coordinate = &profile.policy_owner_key_id;
        keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .unwrap()
            .set_password(&encode_owner_public_key(&owner.verifying_key().to_bytes()))
            .unwrap();
        let consent = |record: &ResetRecord<'_>| {
            Ok(ResetConsent {
                owner_signature: Some(stellar_agent_network::policy_state::OwnerResetSignature {
                    owner: owner.verifying_key().to_bytes(),
                    signature: stellar_agent_core::policy::v1::signature::sign(
                        &record.statement_digest(),
                        &owner,
                    ),
                }),
            })
        };
        let result = store.reset(
            &profile,
            "reset-anchor",
            100_000,
            "repair",
            "reset-request",
            consent,
            |record, consent| {
                record_window_reset(
                    &mut writer,
                    "reset-anchor",
                    record.reason,
                    record.request_id,
                    record.chain_id,
                    record.accrual,
                    owner_authorization(record, consent),
                )
            },
        );
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
                .reset(
                    &profile,
                    "reset-anchor",
                    100_000,
                    "repair",
                    "reset-request",
                    consent,
                    |record, consent| record_window_reset(
                        &mut writer,
                        "reset-anchor",
                        record.reason,
                        record.request_id,
                        record.chain_id,
                        record.accrual,
                        owner_authorization(record, consent),
                    ),
                )
                .is_err()
        );
        assert_eq!(std::fs::read(&profile.audit_log_path).unwrap(), rows);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(generation.get_password().unwrap(), counter);
    }

    #[test]
    #[serial]
    fn the_enablement_nonce_is_read_under_the_store_lock() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};
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
        let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let nonce_reads = Arc::new(AtomicUsize::new(0));
        let handle_slot: Arc<Mutex<Option<std::sync::Arc<std::sync::Mutex<AuditWriter>>>>> =
            Arc::new(Mutex::new(None));
        let writer_held = {
            let handle_slot = Arc::clone(&handle_slot);
            move || {
                let slot = handle_slot.lock().unwrap();
                let handle = slot
                    .as_ref()
                    .expect("the test takes the writer handle first");
                assert!(matches!(
                    handle.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ));
            }
        };
        let nonce_hook = {
            let order = Arc::clone(&order);
            let nonce_reads = Arc::clone(&nonce_reads);
            let writer_held = writer_held.clone();
            let path = path.clone();
            let coordinate = coordinate.clone();
            Arc::new(move || {
                assert!(matches!(
                    WindowStoreLock::acquire_for(&path, &coordinate),
                    Err(StateLockError::WriterLocked)
                ));
                writer_held();
                order.lock().unwrap().push("nonce");
                nonce_reads.fetch_add(1, Ordering::SeqCst);
            })
        };
        let key_hook = {
            let order = Arc::clone(&order);
            Arc::new(move || {
                writer_held();
                order.lock().unwrap().push("key");
            })
        };
        install_with_read_hooks(vec![
            ReadHook::new(&nonce.service, &nonce.account, nonce_hook),
            ReadHook::new(&coordinate.service, &coordinate.account, key_hook),
        ])
        .unwrap();
        let audit_key = &profile.audit_log_hash_chain_key_id;
        use base64::Engine as _;
        keyring_core::Entry::new(&audit_key.service, &audit_key.account)
            .unwrap()
            .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x2c; 32]))
            .unwrap();
        let handle = acquire_keyed_audit_writer(&profile, name, BindingCheck::Enforce)
            .unwrap_or_else(|_| panic!("the profile's audit writer opens"));
        *handle_slot.lock().unwrap() = Some(handle);
        let args = ResetWindowStateArgs {
            name: Some(name.to_owned()),
            profile: None,
            reason: "repair".to_owned(),
            owner_secret_env: None,
        };
        assert_eq!(reset_with_owner(&args, &profile, None), 0);
        assert_eq!(nonce_reads.load(Ordering::SeqCst), 1);
        let order = order.lock().unwrap();
        let first_key = order.iter().position(|read| *read == "key");
        let first_nonce = order.iter().position(|read| *read == "nonce");
        assert!(
            matches!((first_key, first_nonce), (Some(key), Some(nonce)) if key < nonce),
            "{order:?}"
        );
    }

    #[test]
    fn reset_consent_refusals_keep_their_codes() {
        let pinned = [0x11; 32];
        let presented = [0x22; 32];
        let cases = [
            (
                WindowStoreError::ResetOwnerRequired,
                "profile.reset_window_state_owner_required",
            ),
            (
                WindowStoreError::ResetOwnerMismatch { presented, pinned },
                "profile.reset_window_state_owner_mismatch",
            ),
            (WindowStoreError::ResetPinAbsent, "policy.pin_absent"),
            (
                WindowStoreError::ResetPinUnreadable(
                    stellar_agent_core::policy::pin::PinError::Malformed {
                        detail: "not a pin".to_owned(),
                    },
                ),
                "policy.pin_unusable",
            ),
            (
                WindowStoreError::ResetEnablementUnreadable(
                    ValidationError::MainnetEnablementInvalid { binding: "nonce" },
                ),
                "profile.mainnet_enablement_invalid",
            ),
            (
                WindowStoreError::ResetSignatureInvalid,
                "profile.reset_window_state_signature_invalid",
            ),
            (
                WindowStoreError::ResetConsentReplayed,
                "policy.reset_consent_replayed",
            ),
            (
                WindowStoreError::ResetProfileMismatch,
                "internal.unexpected_state",
            ),
        ];
        for (error, code) in cases {
            let label = format!("{error:?}");
            let refusal = reset_refusal("acme", error);
            assert_eq!(refusal.code(), code, "{label}");
            if code == "profile.reset_window_state_owner_mismatch" {
                let message = refusal.message();
                assert!(
                    message.contains(&encode_owner_public_key(&presented)),
                    "{message}"
                );
                assert!(
                    message.contains(&encode_owner_public_key(&pinned)),
                    "{message}"
                );
            }
        }
    }

    #[test]
    #[serial]
    fn reset_explains_permanent_and_missing_secondary_blocks() {
        use stellar_agent_network::intent_view_test_helpers::{PERMANENT, SECONDARY};
        for (permanent, missing) in [(true, false), (false, true), (true, true)] {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let profile = Profile::builder_testnet_named(
                "intent",
                "reset",
                "account",
                "reset-nonce",
                "account",
            )
            .build();
            let mut stored =
                "chain_id = \"stellar:testnet\"\nrpc_url = \"https://primary.example/rpc\"\n"
                    .to_owned();
            if !missing {
                stored.push_str("secondary_rpc_url = \"https://secondary.example/rpc\"\n");
            }
            std::fs::write(dir.path().join("intent.toml"), stored).unwrap();
            let store = PersistedWindowStore::at_path(dir.path().join("intent.window"))
                .with_profile_directory("intent", dir.path().to_owned());
            let (mut plan, envelope) =
                stellar_agent_network::signed_intent::test_helpers::intent_fixture_plan(1, 60);
            if !permanent {
                let stellar_xdr::TransactionEnvelope::Tx(tx) = &envelope else {
                    panic!("transaction")
                };
                let stellar_xdr::OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body
                else {
                    panic!("invoke")
                };
                plan = plan
                    .classify_purpose(&op.host_function, None)
                    .unwrap()
                    .with_envelope_max_ledger(100)
                    .unwrap();
            }
            let _exposure = store.admit_signed_intent(&profile, &plan).unwrap().expose();
            let before = std::fs::read(store.path()).unwrap();
            let result = store.reset(
                &profile,
                "intent",
                1000,
                "fixture",
                "fixture",
                |_| -> Result<ResetConsent, ()> { panic!("no authorization ceremony") },
                |_, _| -> Result<(), ()> { panic!("no reset row") },
            );
            let Err(stellar_agent_network::policy_state::ResetError::Store {
                error,
                minted: false,
            }) = result
            else {
                panic!("live intent refusal")
            };
            let rendered = store_refusal("intent", error);
            assert_eq!(rendered.code(), "submission.record_unavailable");
            assert_eq!(rendered.to_string().contains(PERMANENT), permanent);
            assert_eq!(rendered.to_string().contains(SECONDARY), missing);
            assert_eq!(std::fs::read(store.path()).unwrap(), before);
        }
    }

    #[test]
    fn reset_store_scope_refusals_keep_their_codes() {
        for (refusal, code) in [
            (
                WindowStoreError::ChainMismatch,
                "policy.window_chain_mismatch",
            ),
            (
                WindowStoreError::ChainUnverifiable,
                "policy.window_chain_unverifiable",
            ),
        ] {
            let error = store_refusal("scope-test", refusal);
            assert_eq!(error.code(), code);
            assert!(matches!(error, WalletError::Validation(_)));
            assert!(!error.to_string().contains("reset-window-state"));
        }
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
        let error = store_refusal("acme", WindowStoreError::UnsupportedVersion);
        assert_eq!(error.code(), "profile.reset_window_state_newer_version");
        assert_eq!(
            error.category(),
            stellar_agent_core::error::ErrorCategory::Validation
        );
        assert_eq!(
            error.to_string(),
            "the policy window-state of profile 'acme' cannot be reset: policy window-state \
             version must be supported by this build; use the build that wrote the file"
        );
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    fn the_mainnet_store_refusals_keep_their_codes() {
        let unverifiable = store_refusal(
            "acme",
            WindowStoreError::MainnetStateUnverifiable {
                defect: stellar_agent_network::policy_state::StateDefect::GenerationMismatch,
            },
        );
        assert_eq!(unverifiable.code(), "policy.window_state_unverifiable");
        let text = unverifiable.to_string();
        assert!(text.contains("generation_mismatch"), "{text}");
        assert!(
            text.contains(
                "No verb recovers such state in this release; create a profile under a new name."
            ),
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
