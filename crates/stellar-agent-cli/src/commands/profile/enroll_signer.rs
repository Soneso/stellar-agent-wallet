//! `stellar-agent profile enroll-signer` — import an operator-held ed25519
//! seed into the profile's MCP signer keyring entry.
//!
//! Every MCP fund-movement tool and the keyring-signing CLI verbs resolve their
//! signer via `signer_from_keyring(&profile.mcp_signer_default, …)`.  That entry
//! stores the seed as an `S…` ed25519 secret-key strkey — the exact form
//! `signer_from_keyring` parses back with `PrivateKey::from_string`.  No other
//! shipped command writes it; on a clean install the entry is absent and all
//! MCP signing fails with `auth.keyring_not_found`.  This command closes that
//! gap: it reads the operator's S-strkey from a named environment variable,
//! derives the public address, and stores the S-strkey at the profile's
//! `mcp_signer_default` coordinate.
//!
//! # Account-as-identity
//!
//! The `mcp_signer_default` coordinate's `account` field is both the keyring
//! account name and the G-strkey identity that `signer_from_keyring` verifies
//! the loaded seed against.  `stellar-agent profile init` mints new profiles
//! with the literal placeholder account `"default"` because the signer's
//! eventual G-strkey is not known until a seed is enrolled.  Enrollment
//! classifies the coordinate from its RAW ON-DISK value
//! (`loader::read_signer_ref`) — never from the environment-merged load, so a
//! transient `STELLAR_AGENT_*` overlay cannot influence what gets persisted
//! into the trust root — and resolves three cases:
//!
//! - **Placeholder** (`account` is exactly the literal `"default"`) — this is
//!   the coordinate's first enrollment.  `loader::pin_signer_account` patches
//!   ONLY `mcp_signer_default.account` in the on-disk document to the derived
//!   G-strkey (every other stored key survives verbatim), BEFORE the keyring
//!   write, so `signer_from_keyring` resolves correctly the moment the
//!   profile is next loaded.  Persisting the account first keeps the flow
//!   convergent: if the process dies between the two writes, the account
//!   already equals the derived address, so re-running enroll-signer takes
//!   the "pinned" branch below and simply retries the keyring write.  Every
//!   refusal path precedes the pin, so a refused run modifies nothing.
//! - **Pinned** (`account` parses as a G-strkey — set by a prior enrollment,
//!   or by an operator who hand-edited the TOML) — enrollment refuses unless
//!   the supplied seed derives to that exact address, printing the address to
//!   set `account` to.  A different secret can never silently redirect an
//!   already-established signer identity, and the profile TOML is never
//!   rewritten in this branch.
//! - **Malformed** (anything else — a typo'd or truncated strkey, an
//!   M-strkey, stray whitespace) — refused with
//!   `enroll_signer.account_malformed` rather than treated as a placeholder:
//!   a broken pin is surfaced to the operator, never silently replaced.
//!
//! `EnrollSignerData::account_populated` reports which branch a given run took.
//!
//! # Identity record
//!
//! After the seed write, enrollment writes the signer identity record
//! `{"v":1,"public_key":"G...","role":"agent"}` at the signer's service,
//! account `enrolled-identity`, and records a `signer_identity_enrolled` audit
//! row. Mainnet authorization reads the enrolled key from that record, never
//! from the seed. Success is reported only after the record is written. When
//! the record write fails, the seed and the pin stay as written, and the run
//! reports `profile.enroll_signer_identity_incomplete` with the remedy.
//!
//! A `--force` replacement removes the old record before it writes the seed.
//! If the removal succeeds and the seed write fails, the run reports the same
//! code and leaves the seed coordinate unchanged. A previous seed kept there
//! can be repaired with `--repair-identity` when it derives to the pin, or
//! replaced by a re-run with `--force`. With no previous seed, a plain re-run
//! enrolls. When the removal finds no record, a failed seed write keeps its
//! keyring error code.
//!
//! `--repair-identity` is that remedy. It loads the existing seed through the
//! zeroizing keyring loader, requires it to derive to the on-disk pin, and
//! writes only the identity record. A record that already names the pinned key
//! is left as it is; any other stored record refuses. The seed and the pin are
//! never written by a repair.
//!
//! # Secret handling
//!
//! The seed is read from the environment through the shared mlock-protected
//! ceremony (`resolve_software_signer_from_env`); the S-strkey string is held
//! only in `Zeroizing` wrappers and written verbatim to the platform keyring.
//! The seed is never returned, logged, or placed in the JSON envelope — only
//! the derived public address (G-strkey) and the keyring coordinate are
//! reported.
//!
//! # Output (JSON envelope)
//!
//! On success:
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "profile": "default",
//!     "enrolled": true,
//!     "public_address": "G...",
//!     "keyring_service": "stellar-agent-signer-default",
//!     "keyring_account": "G...",
//!     "replaced": false,
//!     "account_populated": true
//!   },
//!   "request_id": "..."
//! }
//! ```

use std::path::PathBuf;

use clap::Args;
use keyring_core::Entry as KeyringEntry;
use serde::Serialize;
use zeroize::Zeroizing;

use stellar_agent_core::audit_log::KeyPurpose;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{AuthError, InternalError, ValidationError, WalletError};
use stellar_agent_core::observability::RedactedStrkey;
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile, signer_identity_entry_ref};
use stellar_agent_core::profile::signer_identity::SignerIdentityRecord;
use stellar_agent_network::Signer as _;
use stellar_agent_network::keyring::{
    KeyringOperation, init_platform_keyring_store, read_keyring_string, signer_from_keyring,
    write_keyring_string,
};
use uuid::Uuid;

use crate::common::profile_access::{
    injected_profile_load, profile_access_envelope, reconcile_loaded_profile,
};
use crate::common::signer_ceremony::resolve_software_signer_from_env;
use crate::common::{render, resolve_profile_name};
use stellar_agent_core::observability::redact_path_in_message;

use super::audit_emit::{emit_keyring_key_written, emit_signer_identity_enrolled};

/// The literal placeholder account minted by `profile init` and the first-run
/// fallback. Only this exact value is populated at enrollment; any other
/// non-G-strkey value is refused as a malformed pin.
use stellar_agent_core::profile::schema::SIGNER_PLACEHOLDER_ACCOUNT as PLACEHOLDER_ACCOUNT;

/// Arguments for `stellar-agent profile enroll-signer`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct EnrollSignerArgs {
    /// Profile whose MCP signer entry should be enrolled.
    ///
    /// Defaults to the `STELLAR_AGENT_PROFILE` env var, then `"default"`.
    #[arg(long = "profile", value_name = "NAME")]
    pub(crate) profile: Option<String>,

    /// Name of the environment variable that holds the signer S-strkey.
    ///
    /// The flag takes the variable NAME, never the secret itself. Required
    /// unless `--repair-identity` is given.
    #[arg(
        long,
        value_name = "VAR",
        required_unless_present = "repair_identity",
        conflicts_with = "repair_identity"
    )]
    pub(crate) secret_env: Option<String>,

    /// Expected signer public address (G-strkey).
    ///
    /// When set, enrollment refuses unless the seed derives to this address —
    /// a guard against enrolling the wrong secret.
    #[arg(long, value_name = "G_STRKEY")]
    pub(crate) expected_address: Option<String>,

    /// Replace an already-enrolled entry.
    ///
    /// Without this flag, enrollment refuses when the keyring coordinate
    /// already holds a value.
    #[arg(long, default_value_t = false, conflicts_with = "repair_identity")]
    pub(crate) force: bool,

    /// Write only the signer identity record of an existing enrollment.
    ///
    /// Loads the enrolled seed, requires it to derive to the profile's pinned
    /// signer address, and writes the identity record. The seed and the pin
    /// are left as they are. Refuses when a different record is stored.
    #[arg(long, default_value_t = false)]
    pub(crate) repair_identity: bool,
}

/// Success payload for the `enroll-signer` envelope.
#[derive(Debug, Serialize)]
struct EnrollSignerData {
    /// Name of the profile whose signer was enrolled.
    profile: String,
    /// Always `true` on success.
    enrolled: bool,
    /// The G-strkey the enrolled seed derives to.
    public_address: String,
    /// Keyring service coordinate the seed was written to.
    keyring_service: String,
    /// Keyring account coordinate the seed was written to (equals
    /// `public_address`).
    keyring_account: String,
    /// `true` when an existing entry was replaced (`--force`).
    replaced: bool,
    /// The public address the replaced entry resolved to, when a prior entry
    /// existed and its stored value could be parsed.  Absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_address: Option<String>,
    /// `true` when the profile's on-disk `mcp_signer_default.account` was the
    /// literal placeholder `"default"` and this run pinned it to the derived
    /// public address (patching only that key in the profile file).  `false`
    /// when the account already pinned a G-strkey identity (see
    /// "Account-as-identity" in the module documentation).
    account_populated: bool,
    /// Keyring account of the signer identity record written beside the seed.
    identity_keyring_account: String,
}

/// Success payload for the `enroll-signer --repair-identity` envelope.
#[derive(Debug, Serialize)]
struct RepairIdentityData {
    /// Name of the profile whose identity record was repaired.
    profile: String,
    /// The pinned signer address the existing seed derives to.
    public_address: String,
    /// Keyring service of the identity record.
    keyring_service: String,
    /// Keyring account of the identity record.
    keyring_account: String,
    /// `true` when this run wrote the record; `false` when a matching record
    /// was already stored.
    written: bool,
}

/// Runs `stellar-agent profile enroll-signer`.
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
pub(crate) async fn run(args: &EnrollSignerArgs) -> i32 {
    run_with_dependencies(
        args,
        injected_profile_load,
        loader::read_signer_ref,
        loader::pin_signer_account,
        init_platform_keyring_store,
        |name| std::env::var(name),
        write_keyring_string,
        &mut std::io::stdout(),
    )
    .await
}

/// Enrollment with profile access, keyring initialization, the second secret
/// read, and output injected. Production uses the real environment read and
/// raw profile patch; tests can observe refusals against a temporary profile.
#[allow(
    clippy::too_many_arguments,
    reason = "each injected dependency is a seam the tests drive on its own"
)]
async fn run_with_dependencies<
    LoadProfile,
    ReadRawSignerRef,
    PinSigner,
    InitKeyring,
    ReadSecret,
    WriteIdentity,
>(
    args: &EnrollSignerArgs,
    load_profile: LoadProfile,
    read_raw_signer_ref: ReadRawSignerRef,
    pin_signer: PinSigner,
    init_keyring: InitKeyring,
    read_secret: ReadSecret,
    write_identity: WriteIdentity,
    out: &mut dyn std::io::Write,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<Profile, loader::ProfileLoadError>,
    ReadRawSignerRef: Fn(&str) -> Result<KeyringEntryRef, loader::ProfileLoadError>,
    PinSigner: Fn(&str, &str) -> Result<PathBuf, loader::ProfileSaveError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
    ReadSecret: Fn(&str) -> Result<String, std::env::VarError>,
    WriteIdentity: Fn(&KeyringEntryRef, &str) -> Result<(), WalletError>,
{
    // `--profile`, then `STELLAR_AGENT_PROFILE`, then `"default"`.
    let resolved = resolve_profile_name(args.profile.as_deref());
    let profile_name = resolved.name.clone();

    // ── Load profile first, then initialise the keyring store ─────────────────
    // The env-merged load supplies the audit-emission context at the end of
    // the flow; every enrollment DECISION below uses the raw on-disk signer
    // reference instead, so environment overlays stay load-time-only.
    // Reconciled in the CALLER of the injected loader: several test closures
    // ignore the name they are handed, so a check placed inside one would be
    // bypassed by every test that supplies it.
    let profile = match reconcile_loaded_profile(load_profile(&profile_name), &resolved) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(profile = %profile_name, error = %e, "profile access refused");
            return render::write_envelope(out, &profile_access_envelope(&e, &profile_name), 1);
        }
    };
    if let Err(e) = init_keyring() {
        return render::write_envelope(out, &Envelope::<()>::err(&e), 1);
    }

    // ── Raw on-disk signer reference ───────────────────────────────────────────
    // Classification (placeholder vs pinned) and the pin itself operate on
    // the stored document alone: a `STELLAR_AGENT_MCP_SIGNER_DEFAULT`
    // environment overlay can redirect a load, but must never influence what
    // enrollment persists into the trust root.
    let signer_ref = match read_raw_signer_ref(&profile_name) {
        Ok(r) => r,
        Err(loader::ProfileLoadError::NotFound { name, .. }) => {
            let err = WalletError::Validation(ValidationError::ProfileNotFound { name });
            return render::write_envelope(out, &Envelope::<()>::err(&err), 1);
        }
        // An unreadable or malformed stored document is operator-correctable
        // input, not a wallet defect, so it stays in the validation class with
        // its cause carried — the same rule the profile load above follows.
        Err(e) => {
            let err = WalletError::Validation(ValidationError::ConfigInvalid {
                component: "profile",
                reason: redact_path_in_message(&format!(
                    "failed to read the on-disk signer reference for profile \
                     '{profile_name}': {e}"
                )),
            });
            return render::write_envelope(out, &Envelope::<()>::err(&err), 1);
        }
    };

    if args.repair_identity {
        return repair_identity(
            args,
            &profile,
            &profile_name,
            &signer_ref,
            &write_identity,
            out,
        )
        .await;
    }
    // The Option type permits absence; clap requires this argument unless repairing.
    // This branch is unreachable through clap.
    let Some(secret_env) = args.secret_env.as_deref() else {
        return render::write_envelope(
            out,
            &Envelope::<()>::err_raw(
                "enroll_signer.secret_env_required",
                "--secret-env is required unless --repair-identity is given",
            ),
            1,
        );
    };

    // ── Derive the public address from the env S-strkey ───────────────────────
    // Reuses the shared mlock-protected env-seed ceremony; the seed never leaves
    // the ceremony's Zeroizing wrappers.
    let derived_g =
        match resolve_software_signer_from_env(secret_env, "profile-enroll-signer", &profile).await
        {
            Ok(outcome) => match outcome.signer.public_key().await {
                Ok(pk) => pk.to_string().to_string(),
                Err(e) => {
                    return render::write_envelope(out, &Envelope::<()>::err(&e), 1);
                }
            },
            Err(e) => {
                return render::write_envelope(out, &Envelope::<()>::err(&e), 1);
            }
        };

    // ── Optional --expected-address guard (no write on mismatch) ──────────────
    if let Err(envelope) = check_expected_address(
        args.expected_address.as_deref(),
        &derived_g,
        &format!("the seed in '{secret_env}'"),
    ) {
        return render::write_envelope(out, &envelope, 1);
    }

    // ── Account-as-identity resolution ────────────────────────────────────────
    // See "Account-as-identity" in the module documentation, evaluated on the
    // RAW on-disk value: the literal placeholder `"default"` (the value
    // `profile init` and the first-run fallback mint) is populated; a valid
    // G-strkey is a pinned identity (refuse on mismatch, never rewrite); any
    // other value is a malformed pin and is refused rather than replaced.
    let account_is_pinned_identity =
        stellar_strkey::ed25519::PublicKey::from_string(&signer_ref.account).is_ok();

    if account_is_pinned_identity && signer_ref.account != derived_g {
        return render::write_envelope(
            out,
            &Envelope::<()>::err_raw(
                "enroll_signer.account_identity_mismatch",
                format!(
                    "profile '{profile_name}' enrolls the MCP signer at account '{}', but the \
                 supplied seed derives to '{derived_g}'. Set the profile's mcp_signer_default \
                 account to '{derived_g}' (or supply the seed whose address is '{}') and \
                 re-run; no entry was written.",
                    signer_ref.account, signer_ref.account
                ),
            ),
            1,
        );
    }

    if !account_is_pinned_identity && !signer_ref.is_signer_placeholder() {
        return render::write_envelope(
            out,
            &Envelope::<()>::err_raw(
                "enroll_signer.account_malformed",
                format!(
                    "profile '{profile_name}' names signer account '{}', which is neither the \
                 placeholder '{PLACEHOLDER_ACCOUNT}' nor a valid G-strkey; a malformed pin is \
                 refused rather than replaced. Set the profile's mcp_signer_default account to \
                 '{PLACEHOLDER_ACCOUNT}' (to enroll fresh) or to the signer's G-strkey, then \
                 re-run; no entry was written and the profile was not modified.",
                    signer_ref.account
                ),
            ),
            1,
        );
    }

    let account_populated = !account_is_pinned_identity;

    let entry_ref = KeyringEntryRef::new(signer_ref.service.clone(), derived_g.clone());

    // ── Overwrite protection ──────────────────────────────────────────────────
    let entry = match KeyringEntry::new(&entry_ref.service, &entry_ref.account) {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!("enroll-signer: keyring entry construction failed");
            return render::write_envelope(
                out,
                &Envelope::<()>::err(
                    &stellar_agent_network::keyring::map_keyring_operation_error(
                        &e,
                        KeyringOperation::Construct,
                        &entry_ref.service,
                    ),
                ),
                1,
            );
        }
    };

    let existing_present = match entry.get_password() {
        // The probe retrieves the value to test for existence — for an
        // already-enrolled entry that is a live S-strkey. `keyring_core` 1.0.0
        // has no non-retrieving probe, so wrap the retrieved secret in
        // `Zeroizing` to clear the heap allocation instead of dropping a plain
        // `String`.
        Ok(existing) => {
            drop(Zeroizing::new(existing));
            true
        }
        Err(keyring_core::Error::NoEntry) => false,
        Err(e) => {
            tracing::debug!("enroll-signer: existence probe failed");
            return render::write_envelope(
                out,
                &Envelope::<()>::err(
                    &stellar_agent_network::keyring::map_keyring_operation_error(
                        &e,
                        KeyringOperation::Read,
                        &entry_ref.service,
                    ),
                ),
                1,
            );
        }
    };

    if existing_present && !args.force {
        return render::write_envelope(
            out,
            &Envelope::<()>::err_raw(
                "enroll_signer.entry_exists",
                format!(
                    "an entry is already enrolled at keyring service '{}' account '{}'; \
                 pass --force to replace it",
                    entry_ref.service, entry_ref.account
                ),
            ),
            1,
        );
    }

    // Derive the address the replaced entry resolves to for the envelope. Reuses
    // the real keyring consumer path; addresses only, never the seed.
    let previous_address: Option<String> = if existing_present {
        match keyring_seed_address(&entry_ref, &entry_ref.account).await {
            Ok(address) => Some(address),
            Err(WalletError::Auth(AuthError::SignerKeyMismatch { got, .. })) => Some(got),
            Err(_) => None,
        }
    } else {
        None
    };

    let s_strkey: Zeroizing<String> = match read_secret(secret_env) {
        Ok(v) => Zeroizing::new(v),
        Err(_) => {
            return render::write_envelope(
                out,
                &Envelope::<()>::err(&WalletError::Validation(ValidationError::SecretEnvNotSet {
                    var: secret_env.to_owned(),
                })),
                1,
            );
        }
    };
    // Every refusal, including an unset secret variable, precedes the pin and
    // leaves the profile unmodified. The pin precedes the keyring write so a
    // failed write leaves the pinned address and a re-run retries that write.
    // Only `mcp_signer_default.account` changes in the stored document.
    if account_populated && let Err(e) = pin_signer(&profile_name, &derived_g) {
        return render::write_envelope(
            out,
            &Envelope::<()>::err(&WalletError::Internal(InternalError::UnexpectedState {
                detail: format!(
                    "failed to persist the derived signer address into profile \
                     '{profile_name}': {e}"
                ),
            })),
            1,
        );
    }

    // A replacement removes the old identity before changing the seed, so a
    // partial enrollment leaves no record naming a different seed.
    let identity_ref = signer_identity_entry_ref(&entry_ref);
    let mut identity_removed = false;
    if args.force {
        let deletion = keyring_core::Entry::new(&identity_ref.service, &identity_ref.account)
            .and_then(|entry| entry.delete_credential());
        match deletion {
            Ok(()) => identity_removed = true,
            Err(keyring_core::Error::NoEntry) => {}
            Err(error) => {
                let error = stellar_agent_network::keyring::map_keyring_operation_error(
                    &error,
                    KeyringOperation::Write,
                    &identity_ref.service,
                );
                return render::write_envelope(out, &Envelope::<()>::err(&error), 1);
            }
        }
    }

    // ── Write the S-strkey verbatim to the keyring coordinate ─────────────────
    if let Err(e) = entry.set_password(&s_strkey) {
        tracing::debug!("enroll-signer: set_password failed");
        drop(s_strkey);
        // Classify the write failure: a non-interactive Windows session must
        // surface as auth.keyring_interactive_session_required (this is the
        // first keyring write a new deployment performs), not "not found".
        let error = stellar_agent_network::keyring::map_keyring_operation_error(
            &e,
            KeyringOperation::Write,
            &entry_ref.service,
        );
        let envelope = if identity_removed {
            identity_removed_before_failed_seed(
                &profile_name,
                &entry_ref,
                &identity_ref,
                existing_present,
                &error,
            )
        } else {
            Envelope::<()>::err(&error)
        };
        return render::write_envelope(out, &envelope, 1);
    }
    drop(s_strkey);

    let request_id = Uuid::new_v4().to_string();
    emit_keyring_key_written(
        &profile,
        &profile_name,
        "profile_enroll_signer",
        KeyPurpose::McpSignerSeed,
        &entry_ref,
        Some(RedactedStrkey::from_full(&derived_g)),
        &request_id,
    );

    // ── The identity record beside the seed ───────────────────────────────────
    // The seed and the pin are committed. A failed record write leaves both,
    // and the operator writes the record alone with `--repair-identity`.
    let record = match identity_record_for(&derived_g) {
        Ok(record) => record,
        Err(envelope) => return render::write_envelope(out, &envelope, 1),
    };
    if let Err(error) = write_identity(&identity_ref, &record.render()) {
        tracing::debug!(error = %error, "enroll-signer: identity record write failed");
        return render::write_envelope(
            out,
            &identity_incomplete(&profile_name, &entry_ref, &identity_ref, &error),
            1,
        );
    }
    emit_signer_identity_enrolled(
        &profile,
        &profile_name,
        "profile_enroll_signer",
        &identity_ref,
        RedactedStrkey::from_full(&derived_g),
        &request_id,
    );

    // Info-level log omits the address and coordinate to avoid leaking operator
    // topology; the JSON envelope carries the full detail.
    tracing::info!("MCP signer enrolled for profile '{profile_name}'");
    render::write_envelope(
        out,
        &Envelope::ok(EnrollSignerData {
            profile: profile_name.clone(),
            enrolled: true,
            public_address: derived_g,
            keyring_service: entry_ref.service.clone(),
            keyring_account: entry_ref.account.clone(),
            replaced: existing_present,
            previous_address,
            account_populated,
            identity_keyring_account: identity_ref.account,
        }),
        0,
    )
}

/// The address the seed stored at `entry_ref` derives to, loaded through the
/// zeroizing keyring loader, which refuses a seed that does not derive to
/// `expected`. Addresses only, never the seed.
async fn keyring_seed_address(
    entry_ref: &KeyringEntryRef,
    expected: &str,
) -> Result<String, WalletError> {
    // `KeyringSignHandle::public_key` returns the cached derived address
    // synchronously and infallibly.
    signer_from_keyring(entry_ref, expected)
        .await
        .map(|handle| handle.public_key().to_string().to_string())
}

/// Refuses unless `derived` equals the `--expected-address` guard, when one is
/// given. `source` names where the derived address came from.
fn check_expected_address(
    expected: Option<&str>,
    derived: &str,
    source: &str,
) -> Result<(), Envelope<()>> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if stellar_strkey::ed25519::PublicKey::from_string(expected).is_err() {
        return Err(Envelope::<()>::err_raw(
            "enroll_signer.expected_address_invalid",
            format!("--expected-address is not a valid G-strkey: {expected}"),
        ));
    }
    if expected != derived {
        return Err(Envelope::<()>::err_raw(
            "enroll_signer.expected_address_mismatch",
            format!(
                "{source} derives to {derived}, which does not match --expected-address \
                 {expected}; no entry was written"
            ),
        ));
    }
    Ok(())
}

/// The identity record for the agent key `public_g`.
fn identity_record_for(public_g: &str) -> Result<SignerIdentityRecord, Envelope<()>> {
    stellar_strkey::ed25519::PublicKey::from_string(public_g)
        .map(|key| SignerIdentityRecord::agent(key.0))
        .map_err(|_| {
            Envelope::<()>::err(&WalletError::Internal(InternalError::UnexpectedState {
                detail: "the derived signer address is not a G-strkey".to_owned(),
            }))
        })
}

/// The partial-enrollment refusal: the seed and the pin are written, the
/// identity record is not.
fn identity_incomplete(
    profile_name: &str,
    seed_ref: &KeyringEntryRef,
    identity_ref: &KeyringEntryRef,
    error: &WalletError,
) -> Envelope<()> {
    Envelope::<()>::err_raw(
        "profile.enroll_signer_identity_incomplete",
        format!(
            "the signer seed of profile '{profile_name}' is enrolled at keyring service '{}' \
             account '{}', but its identity record at account '{}' could not be written ({}). \
             The seed and the pin are kept. Run `stellar-agent profile enroll-signer --profile \
             {profile_name} --repair-identity` to write the record.",
            seed_ref.service,
            seed_ref.account,
            identity_ref.account,
            error.code(),
        ),
    )
}

/// The refusal of a `--force` replacement whose seed write failed after the
/// identity record was removed: the record is gone, the seed coordinate holds
/// what it held before, and the remedy depends on whether that is a seed.
///
/// The code is `profile.enroll_signer_identity_incomplete`, as for a failed
/// record write, because the run ends with no identity record; the message
/// carries the code of the keyring failure.
fn identity_removed_before_failed_seed(
    profile_name: &str,
    seed_ref: &KeyringEntryRef,
    identity_ref: &KeyringEntryRef,
    previous_seed_kept: bool,
    error: &WalletError,
) -> Envelope<()> {
    let state = if previous_seed_kept {
        format!(
            "The previous seed is kept. Re-run with `--force` to replace it, or run \
             `stellar-agent profile enroll-signer --profile {profile_name} --repair-identity` \
             to write the record for the kept seed when it derives to the pinned address."
        )
    } else {
        "No seed was stored there. Re-run the command to enroll the seed.".to_owned()
    };
    Envelope::<()>::err_raw(
        "profile.enroll_signer_identity_incomplete",
        format!(
            "the replacement seed of profile '{profile_name}' could not be written to keyring \
             service '{}' account '{}' ({}). The identity record at account '{}' was removed \
             before the write. {state}",
            seed_ref.service,
            seed_ref.account,
            error.code(),
            identity_ref.account,
        ),
    )
}

/// Writes the identity record of an existing enrollment, as
/// `--repair-identity` asks.
///
/// The on-disk pin must name a G-strkey, and the seed stored at that
/// coordinate must derive to it. A stored record that names the pin as an
/// agent key is left as it is; any other stored record refuses. Writes only
/// the record.
async fn repair_identity<WriteIdentity>(
    args: &EnrollSignerArgs,
    profile: &Profile,
    profile_name: &str,
    signer_ref: &KeyringEntryRef,
    write_identity: &WriteIdentity,
    out: &mut dyn std::io::Write,
) -> i32
where
    WriteIdentity: Fn(&KeyringEntryRef, &str) -> Result<(), WalletError>,
{
    if signer_ref.is_signer_placeholder()
        || stellar_strkey::ed25519::PublicKey::from_string(&signer_ref.account).is_err()
    {
        return render::write_envelope(
            out,
            &Envelope::<()>::err_raw(
                "enroll_signer.repair_unpinned",
                format!(
                    "profile '{profile_name}' pins no signer address at \
                     `mcp_signer_default.account` ('{}'), so there is no enrollment to repair. \
                     Enroll the signer with `stellar-agent profile enroll-signer --profile \
                     {profile_name} --secret-env <VAR>`.",
                    signer_ref.account
                ),
            ),
            1,
        );
    }
    let pinned = signer_ref.account.clone();
    let derived = match keyring_seed_address(signer_ref, &pinned).await {
        Ok(address) => address,
        Err(error) => return render::write_envelope(out, &Envelope::<()>::err(&error), 1),
    };
    if let Err(envelope) = check_expected_address(
        args.expected_address.as_deref(),
        &derived,
        "the enrolled seed",
    ) {
        return render::write_envelope(out, &envelope, 1);
    }
    let record = match identity_record_for(&derived) {
        Ok(record) => record,
        Err(envelope) => return render::write_envelope(out, &envelope, 1),
    };
    let identity_ref = signer_identity_entry_ref(signer_ref);
    let written = match read_keyring_string(&identity_ref) {
        Ok(None) => {
            if let Err(error) = write_identity(&identity_ref, &record.render()) {
                return render::write_envelope(out, &Envelope::<()>::err(&error), 1);
            }
            let request_id = Uuid::new_v4().to_string();
            emit_signer_identity_enrolled(
                profile,
                profile_name,
                "profile_enroll_signer",
                &identity_ref,
                RedactedStrkey::from_full(&derived),
                &request_id,
            );
            true
        }
        Ok(Some(stored)) => {
            if SignerIdentityRecord::parse(&stored).ok() != Some(record) {
                return render::write_envelope(
                    out,
                    &Envelope::<()>::err_raw(
                        "enroll_signer.identity_conflict",
                        format!(
                            "keyring service '{}' account '{}' holds an identity record that \
                             does not name the pinned signer {derived} as the agent key; the \
                             repair writes nothing. Remove that entry, then run the repair \
                             again.",
                            identity_ref.service, identity_ref.account
                        ),
                    ),
                    1,
                );
            }
            false
        }
        Err(error) => return render::write_envelope(out, &Envelope::<()>::err(&error), 1),
    };
    tracing::info!("signer identity record repaired for profile '{profile_name}'");
    render::write_envelope(
        out,
        &Envelope::ok(RepairIdentityData {
            profile: profile_name.to_owned(),
            public_address: derived,
            keyring_service: identity_ref.service,
            keyring_account: identity_ref.account,
            written,
        }),
        0,
    )
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
        reason = "test-only assertions"
    )]

    use keyring_core::Entry as KeyringEntry;
    use serial_test::serial;
    use stellar_agent_test_support::keyring_mock;

    use super::*;

    const SIGNER_SERVICE: &str = "stellar-agent-signer-enroll-test";

    /// Deterministic `(S-strkey, derived G-strkey)` for a fixed 32-byte seed.
    fn seed_material(seed: [u8; 32]) -> (String, String) {
        let s_strkey = stellar_strkey::ed25519::PrivateKey(seed)
            .as_unredacted()
            .to_string()
            .to_string();
        let verifying = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let g = stellar_strkey::ed25519::PublicKey(verifying.to_bytes())
            .to_string()
            .to_string();
        (s_strkey, g)
    }

    /// Builds an in-memory testnet profile whose `mcp_signer_default` account is
    /// `account`, under the test signer service.
    fn profile_with_signer_account(account: &str) -> Profile {
        Profile::builder_testnet_named(
            "enroll-signer-test",
            SIGNER_SERVICE,
            account,
            "stellar-agent-nonce-enroll-test",
            "enroll-signer-test",
        )
        .build()
    }

    /// RAII env-var guard; `#[serial]` on every test using it prevents
    /// concurrent env access.
    struct EnvGuard {
        var: String,
    }
    impl EnvGuard {
        #[allow(
            unsafe_code,
            reason = "test-only env mutation; #[serial] prevents concurrent access"
        )]
        fn set(var: String, value: &str) -> Self {
            // SAFETY: serialised by #[serial]; no concurrent env access.
            unsafe {
                std::env::set_var(&var, value);
            }
            Self { var }
        }
    }
    impl Drop for EnvGuard {
        #[allow(unsafe_code, reason = "test-only env cleanup")]
        fn drop(&mut self) {
            // SAFETY: same as set(); serialised by #[serial].
            unsafe {
                std::env::remove_var(&self.var);
            }
        }
    }

    fn args(secret_env: &str, expected: Option<&str>, force: bool) -> EnrollSignerArgs {
        EnrollSignerArgs {
            profile: Some("enroll-signer-test".to_owned()),
            secret_env: Some(secret_env.to_owned()),
            expected_address: expected.map(str::to_owned),
            force,
            repair_identity: false,
        }
    }

    fn unique_var(tag: &str) -> String {
        format!("ENROLL_SIGNER_TEST_{tag}_{}", std::process::id())
    }

    /// A `pin_signer` stub that panics if invoked.
    ///
    /// Used by every fixture whose `mcp_signer_default.account` already pins a
    /// G-strkey identity (and by refusal fixtures), asserting those paths
    /// never write the profile TOML (see "Account-as-identity" in the module
    /// documentation).
    fn pin_signer_must_not_be_called(
        _name: &str,
        _account: &str,
    ) -> Result<PathBuf, loader::ProfileSaveError> {
        panic!(
            "pin_signer must not be called when the account already pins a \
             G-strkey identity or the run refuses"
        );
    }

    /// Builds the raw-signer-ref injection for a profile fixture: the raw
    /// on-disk view in these unit tests is the fixture's own signer ref.
    fn raw_ref_of(
        profile: &Profile,
    ) -> impl Fn(&str) -> Result<KeyringEntryRef, loader::ProfileLoadError> + 'static {
        let r = profile.mcp_signer_default.clone();
        move |_n| Ok(r.clone())
    }

    #[tokio::test]
    #[serial]
    async fn enroll_happy_path_writes_entry_and_produces_working_signer() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, derived_g) = seed_material([0x11u8; 32]);
        let var = unique_var("HAPPY");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        let profile = profile_with_signer_account(&derived_g);
        let entry_ref = profile.mcp_signer_default.clone();

        let raw = raw_ref_of(&profile);
        let code = run_with_dependencies(
            &args(&var, None, false),
            move |_n| Ok(profile.clone()),
            raw,
            pin_signer_must_not_be_called,
            || Ok(()),
            |name| std::env::var(name),
            write_keyring_string,
            &mut Vec::new(),
        )
        .await;
        assert_eq!(code, 0, "enroll must succeed on a clean coordinate");

        // The verbatim S-strkey is stored at the coordinate. Compare via a
        // boolean so a failure never prints the secret.
        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        let stored = entry.get_password().expect("entry must be present");
        assert!(
            stored == s_strkey,
            "the stored value must be the verbatim S-strkey"
        );

        // #25 acceptance: the real consumer path resolves a WORKING signer whose
        // derived address matches the enrolled account identity.
        let handle = signer_from_keyring(&entry_ref, &entry_ref.account)
            .await
            .expect("signer_from_keyring must succeed after enroll");
        assert_eq!(handle.public_key().to_string().to_string(), derived_g);
    }

    #[tokio::test]
    #[serial]
    async fn expected_address_mismatch_refuses_without_writing() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, derived_g) = seed_material([0x22u8; 32]);
        let var = unique_var("EXPECTED");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        let profile = profile_with_signer_account(&derived_g);
        let entry_ref = profile.mcp_signer_default.clone();

        // A different, valid G-strkey as the wrong expectation.
        let (_other_s, other_g) = seed_material([0x33u8; 32]);

        let raw = raw_ref_of(&profile);
        let code = run_with_dependencies(
            &args(&var, Some(&other_g), false),
            move |_n| Ok(profile.clone()),
            raw,
            pin_signer_must_not_be_called,
            || Ok(()),
            |name| std::env::var(name),
            write_keyring_string,
            &mut Vec::new(),
        )
        .await;
        assert_eq!(code, 1, "a mismatched --expected-address must refuse");

        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        assert!(
            entry.get_password().is_err(),
            "no entry must be written on expected-address mismatch"
        );
    }

    #[tokio::test]
    #[serial]
    async fn account_identity_mismatch_refuses_without_writing() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, _derived_g) = seed_material([0x44u8; 32]);
        let var = unique_var("IDENTITY");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        // Profile's signer account is a DIFFERENT address than the seed derives
        // to — the "account = default / placeholder" failure mode.
        let (_other_s, wrong_account) = seed_material([0x55u8; 32]);
        let profile = profile_with_signer_account(&wrong_account);
        let entry_ref = profile.mcp_signer_default.clone();

        let raw = raw_ref_of(&profile);
        let code = run_with_dependencies(
            &args(&var, None, false),
            move |_n| Ok(profile.clone()),
            raw,
            pin_signer_must_not_be_called,
            || Ok(()),
            |name| std::env::var(name),
            write_keyring_string,
            &mut Vec::new(),
        )
        .await;
        assert_eq!(code, 1, "an account-identity mismatch must refuse");

        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        assert!(
            entry.get_password().is_err(),
            "no entry must be written on account-identity mismatch"
        );
    }

    #[tokio::test]
    #[serial]
    async fn overwrite_without_force_is_refused() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, derived_g) = seed_material([0x11u8; 32]);
        let var = unique_var("NOFORCE");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        let profile = profile_with_signer_account(&derived_g);
        let entry_ref = profile.mcp_signer_default.clone();

        // Pre-seed the coordinate.
        let pre = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        pre.set_password("preexisting-sentinel").unwrap();

        let raw = raw_ref_of(&profile);
        let code = run_with_dependencies(
            &args(&var, None, false),
            move |_n| Ok(profile.clone()),
            raw,
            pin_signer_must_not_be_called,
            || Ok(()),
            |name| std::env::var(name),
            write_keyring_string,
            &mut Vec::new(),
        )
        .await;
        assert_eq!(code, 1, "enroll must refuse to overwrite without --force");

        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        assert_eq!(
            entry.get_password().unwrap(),
            "preexisting-sentinel",
            "the existing entry must be left untouched"
        );
    }

    #[tokio::test]
    #[serial]
    async fn force_replaces_existing_entry() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, derived_g) = seed_material([0x11u8; 32]);
        let var = unique_var("FORCE");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        let profile = profile_with_signer_account(&derived_g);
        let entry_ref = profile.mcp_signer_default.clone();

        // Pre-seed with a different valid S-strkey (deriving to another address)
        // so the previous-address derivation exercises the mismatch branch.
        let (other_s, _other_g) = seed_material([0x66u8; 32]);
        let pre = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        pre.set_password(&other_s).unwrap();

        let raw = raw_ref_of(&profile);
        let code = run_with_dependencies(
            &args(&var, None, true),
            move |_n| Ok(profile.clone()),
            raw,
            pin_signer_must_not_be_called,
            || Ok(()),
            |name| std::env::var(name),
            write_keyring_string,
            &mut Vec::new(),
        )
        .await;
        assert_eq!(code, 0, "--force must replace the existing entry");

        // Compare via a boolean so a failure never prints the secret.
        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        let stored = entry.get_password().unwrap();
        assert!(
            stored == s_strkey,
            "the coordinate must now hold the newly enrolled S-strkey"
        );
    }

    /// The completeness round trip a `profile init`-minted profile requires:
    /// the on-disk `mcp_signer_default.account` starts as the literal
    /// placeholder `"default"`, so enrollment must pin it to the derived
    /// G-strkey BEFORE writing the keyring secret, and the keyring write
    /// itself must land at the DERIVED coordinate, not the placeholder one.
    /// The pin closure asserts the ordering: when it runs, the keyring
    /// coordinate must still be empty. Without this flow, an `init`-created
    /// profile could never enroll a working signer (see "Account-as-identity"
    /// in the module documentation).
    #[tokio::test]
    #[serial]
    async fn enroll_on_placeholder_account_populates_profile_before_keyring_write() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, derived_g) = seed_material([0x77u8; 32]);
        let var = unique_var("PLACEHOLDER");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        // The literal placeholder `profile init` mints.
        let profile = profile_with_signer_account("default");
        let signer_service = profile.mcp_signer_default.service.clone();
        let raw = raw_ref_of(&profile);

        let pinned: std::sync::Arc<std::sync::Mutex<Option<(String, String)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let pinned_for_closure = pinned.clone();
        let service_for_closure = signer_service.clone();

        let code = run_with_dependencies(
            &args(&var, None, false),
            move |_n| Ok(profile.clone()),
            raw,
            move |name, account| {
                // Ordering pin: the keyring write must not have happened yet
                // when the profile pin runs (TOML-before-keyring convergence).
                let probe = KeyringEntry::new(&service_for_closure, account).unwrap();
                assert!(
                    probe.get_password().is_err(),
                    "the keyring coordinate must still be empty when the pin runs"
                );
                *pinned_for_closure.lock().unwrap() = Some((name.to_owned(), account.to_owned()));
                Ok(PathBuf::from("/unused-in-test/default.toml"))
            },
            || Ok(()),
            |name| std::env::var(name),
            write_keyring_string,
            &mut Vec::new(),
        )
        .await;
        assert_eq!(code, 0, "enroll must succeed against a placeholder account");

        let (pinned_name, pinned_account) = pinned
            .lock()
            .unwrap()
            .clone()
            .expect("pin_signer must have been called for a placeholder account");
        assert_eq!(pinned_name, "enroll-signer-test");
        assert_eq!(
            pinned_account, derived_g,
            "the pin must carry the derived G-strkey"
        );

        // The keyring secret itself lands at the DERIVED coordinate, not the
        // placeholder — the exact coordinate a subsequent profile load (which
        // now carries the derived account) resolves via `signer_from_keyring`.
        let entry = KeyringEntry::new(&signer_service, &derived_g).unwrap();
        let stored = entry
            .get_password()
            .expect("entry must be present at the derived coordinate");
        assert!(
            stored == s_strkey,
            "the stored value must be the verbatim S-strkey"
        );

        let entry_ref = KeyringEntryRef::new(signer_service, derived_g.clone());
        let handle = signer_from_keyring(&entry_ref, &derived_g)
            .await
            .expect("signer_from_keyring must succeed after enroll");
        assert_eq!(handle.public_key().to_string().to_string(), derived_g);
    }

    /// An on-disk account that is neither the literal placeholder nor a valid
    /// G-strkey (a typo'd pin) is refused: nothing is pinned and no keyring
    /// entry is written. A broken pin must be surfaced, never replaced.
    #[tokio::test]
    #[serial]
    async fn malformed_account_pin_refuses_without_writing() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, derived_g) = seed_material([0x88u8; 32]);
        let var = unique_var("MALFORMED");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        // A truncated G-strkey: not the placeholder, not a valid strkey.
        let profile = profile_with_signer_account("GAQAA5L65LSYH7CQ3VTJ7F3HHLG");
        let signer_service = profile.mcp_signer_default.service.clone();
        let raw = raw_ref_of(&profile);

        let code = run_with_dependencies(
            &args(&var, None, false),
            move |_n| Ok(profile.clone()),
            raw,
            pin_signer_must_not_be_called,
            || Ok(()),
            |name| std::env::var(name),
            write_keyring_string,
            &mut Vec::new(),
        )
        .await;
        assert_eq!(code, 1, "a malformed account pin must refuse");

        let entry = KeyringEntry::new(&signer_service, &derived_g).unwrap();
        assert!(
            entry.get_password().is_err(),
            "no keyring entry must be written on a malformed-pin refusal"
        );
    }

    /// End-to-end environment immunity through the PRODUCTION loader
    /// functions: a `STELLAR_AGENT_MCP_SIGNER_DEFAULT` overlay must neither
    /// influence the enrollment classification nor leak into the pinned
    /// on-disk document. The profile lives in a real temp dir; the raw read
    /// and the pin are the production `read_signer_ref_on_disk` /
    /// `pin_signer_account_on_disk` over that dir.
    #[tokio::test]
    #[serial]
    async fn env_overlay_never_reaches_the_on_disk_pin() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, derived_g) = seed_material([0x99u8; 32]);
        let var = unique_var("ENVIMMUNE");
        let _seed_guard = EnvGuard::set(var.clone(), &s_strkey);
        // An overlay that would redirect the signer ref on an env-merged load.
        let _overlay_guard = EnvGuard::set(
            "STELLAR_AGENT_MCP_SIGNER_DEFAULT".to_owned(),
            r#"{service="env-injected-svc",account="default"}"#,
        );

        let dir = tempfile::tempdir().unwrap();
        let profile = profile_with_signer_account("default");
        loader::save_to_dir("enroll-signer-test", &profile, dir.path()).unwrap();

        let dir_for_read = dir.path().to_path_buf();
        let dir_for_pin = dir.path().to_path_buf();
        let profile_for_load = profile.clone();
        let code = run_with_dependencies(
            &args(&var, None, false),
            move |_n| Ok(profile_for_load.clone()),
            move |n| loader::read_signer_ref_on_disk(n, &dir_for_read),
            move |n, g| loader::pin_signer_account_on_disk(n, &dir_for_pin, g),
            || Ok(()),
            |name| std::env::var(name),
            write_keyring_string,
            &mut Vec::new(),
        )
        .await;
        assert_eq!(code, 0, "enroll must succeed with the overlay set");

        let written = std::fs::read_to_string(dir.path().join("enroll-signer-test.toml")).unwrap();
        assert!(
            written.contains(&format!("account = \"{derived_g}\"")),
            "the on-disk pin must carry the derived G-strkey; got:\n{written}"
        );
        assert!(
            written.contains(&format!("service = \"{SIGNER_SERVICE}\"")),
            "the on-disk service must be the stored one; got:\n{written}"
        );
        assert!(
            !written.contains("env-injected-svc"),
            "no environment overlay value may leak into the stored document; got:\n{written}"
        );

        // The keyring write landed at the ON-DISK service, not the env one.
        let entry = KeyringEntry::new(SIGNER_SERVICE, &derived_g).unwrap();
        assert!(
            entry.get_password().is_ok(),
            "the secret must be stored at the on-disk service coordinate"
        );
    }

    #[tokio::test]
    #[serial]
    async fn second_secret_read_refusal_leaves_profile_and_keyring_unchanged() {
        keyring_mock::install().unwrap();
        let (seed, address) = seed_material([0x63; 32]);
        let var = unique_var("SECOND_READ");
        let _guard = EnvGuard::set(var.clone(), &seed);
        let dir = tempfile::tempdir().unwrap();
        let profile = profile_with_signer_account("default");
        loader::save_to_dir("enroll-signer-test", &profile, dir.path()).unwrap();
        let path = dir.path().join("enroll-signer-test.toml");
        let before = std::fs::read(&path).unwrap();
        let second_read = std::cell::Cell::new(false);
        let mut output = Vec::new();
        let code = run_with_dependencies(
            &args(&var, None, false),
            |_| Ok(profile.clone()),
            |name| loader::read_signer_ref_on_disk(name, dir.path()),
            |name, account| loader::pin_signer_account_on_disk(name, dir.path(), account),
            || Ok(()),
            |_| {
                second_read.set(true);
                Err(std::env::VarError::NotPresent)
            },
            write_keyring_string,
            &mut output,
        )
        .await;
        assert!(
            second_read.get(),
            "the real ceremony must reach the second read"
        );
        assert_eq!(code, 1);
        assert_eq!(
            render::single_json_document(&output)["error"]["code"],
            "validation.secret_env_not_set"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "a secret-read refusal must leave the profile bytes unchanged"
        );
        assert!(matches!(
            KeyringEntry::new(SIGNER_SERVICE, &address)
                .unwrap()
                .get_password(),
            Err(keyring_core::Error::NoEntry)
        ));
    }

    #[tokio::test]
    #[serial]
    async fn initially_unset_secret_refuses_before_pin_and_second_read() {
        keyring_mock::install().unwrap();
        let var = unique_var("INITIALLY_UNSET");
        assert!(std::env::var(&var).is_err());
        let profile = profile_with_signer_account("default");
        let mut output = Vec::new();
        let code = run_with_dependencies(
            &args(&var, None, false),
            |_| Ok(profile.clone()),
            raw_ref_of(&profile),
            pin_signer_must_not_be_called,
            || Ok(()),
            |_| panic!("an unset variable must refuse in the ceremony"),
            write_keyring_string,
            &mut output,
        )
        .await;
        assert_eq!(code, 1);
        assert_eq!(
            render::single_json_document(&output)["error"]["code"],
            "validation.secret_env_not_set"
        );
    }

    // Real `run()`: a nonexistent profile bails at the profile-load arm (mapped
    // to `ProfileNotFound`, matching the sibling rotate commands) before any
    // keyring or environment access. Defensive `#[serial]`: even though `run()`
    // early-exits before `init_platform_keyring_store()`, the test binary
    // observes a flaky race (~1 in 30 runs) where an `Arc<CredentialStore>` swap
    // during parallel execution clobbers a sibling `#[serial]` test's mock
    // store, surfacing as `Auth(KeyringNotFound)` for the sibling. Serialising
    // defensively eliminates the cross-test interference at trivial cost.
    #[tokio::test]
    #[serial]
    async fn enroll_nonexistent_profile_returns_exit_1() {
        let args = EnrollSignerArgs {
            profile: Some("__nonexistent_enroll_signer__".to_owned()),
            secret_env: Some("__UNSET_ENROLL_SIGNER_VAR__".to_owned()),
            expected_address: None,
            force: false,
            repair_identity: false,
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }

    // ── identity record and repair ──────────────────────────────────────

    fn identity_ref() -> KeyringEntryRef {
        KeyringEntryRef::new(SIGNER_SERVICE, "enrolled-identity")
    }

    fn stored_identity() -> Option<String> {
        stellar_agent_network::keyring::read_keyring_string(&identity_ref()).unwrap()
    }

    fn agent_record_of(g: &str) -> String {
        SignerIdentityRecord::agent(
            stellar_strkey::ed25519::PublicKey::from_string(g)
                .unwrap()
                .0,
        )
        .render()
    }

    fn repair_args() -> EnrollSignerArgs {
        EnrollSignerArgs {
            profile: Some("enroll-signer-test".to_owned()),
            secret_env: None,
            expected_address: None,
            force: false,
            repair_identity: true,
        }
    }

    fn write_identity_must_not_be_called(
        _entry: &KeyringEntryRef,
        _value: &str,
    ) -> Result<(), WalletError> {
        panic!("the identity record must not be written");
    }

    #[tokio::test]
    #[serial]
    async fn enrollment_writes_the_identity_record_after_the_seed() {
        keyring_mock::install().unwrap();
        let (s_strkey, derived_g) = seed_material([0x41; 32]);
        let var = unique_var("IDENTITY");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);
        let profile = profile_with_signer_account(&derived_g);
        let seed_ref = profile.mcp_signer_default.clone();
        let raw = raw_ref_of(&profile);
        let mut output = Vec::new();
        let code = run_with_dependencies(
            &args(&var, None, false),
            move |_n| Ok(profile.clone()),
            raw,
            pin_signer_must_not_be_called,
            || Ok(()),
            |name| std::env::var(name),
            |entry: &KeyringEntryRef, value: &str| {
                assert!(
                    KeyringEntry::new(&seed_ref.service, &seed_ref.account)
                        .unwrap()
                        .get_password()
                        .is_ok(),
                    "the seed is written before the identity record"
                );
                write_keyring_string(entry, value)
            },
            &mut output,
        )
        .await;
        assert_eq!(code, 0);
        let json = render::single_json_document(&output);
        assert_eq!(
            json["data"]["identity_keyring_account"],
            "enrolled-identity"
        );
        assert_eq!(stored_identity(), Some(agent_record_of(&derived_g)));
    }

    #[tokio::test]
    #[serial]
    async fn a_failed_identity_write_reports_a_partial_enrollment() {
        keyring_mock::install().unwrap();
        let (s_strkey, derived_g) = seed_material([0x42; 32]);
        let var = unique_var("PARTIAL");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);
        let profile = profile_with_signer_account("default");
        let pinned = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let pinned_for_closure = pinned.clone();
        let raw = raw_ref_of(&profile);
        let mut output = Vec::new();
        let code = run_with_dependencies(
            &args(&var, None, false),
            move |_n| Ok(profile.clone()),
            raw,
            move |_name, account| {
                *pinned_for_closure.lock().unwrap() = Some(account.to_owned());
                Ok(PathBuf::from("/dev/null"))
            },
            || Ok(()),
            |name| std::env::var(name),
            |_entry: &KeyringEntryRef, _value: &str| {
                Err(WalletError::Auth(AuthError::KeyringLocked))
            },
            &mut output,
        )
        .await;
        assert_eq!(code, 1);
        let json = render::single_json_document(&output);
        assert_eq!(
            json["error"]["code"],
            "profile.enroll_signer_identity_incomplete"
        );
        let message = json["error"]["message"].as_str().unwrap();
        assert!(
            message.contains(
                "stellar-agent profile enroll-signer --profile enroll-signer-test --repair-identity"
            ),
            "{message}"
        );
        assert!(message.contains("auth.keyring_locked"), "{message}");
        assert_eq!(pinned.lock().unwrap().as_deref(), Some(derived_g.as_str()));
        assert!(
            KeyringEntry::new(SIGNER_SERVICE, &derived_g)
                .unwrap()
                .get_password()
                .unwrap()
                == s_strkey,
            "the seed is kept"
        );
        assert_eq!(stored_identity(), None);
    }

    #[tokio::test]
    #[serial]
    async fn a_repair_writes_only_the_identity_record_and_is_idempotent() {
        keyring_mock::install().unwrap();
        let (s_strkey, derived_g) = seed_material([0x43; 32]);
        KeyringEntry::new(SIGNER_SERVICE, &derived_g)
            .unwrap()
            .set_password(&s_strkey)
            .unwrap();
        let profile = profile_with_signer_account(&derived_g);
        for (written, writer) in [
            (
                true,
                write_keyring_string as fn(&KeyringEntryRef, &str) -> Result<(), WalletError>,
            ),
            (false, write_identity_must_not_be_called),
        ] {
            let loaded = profile.clone();
            let mut output = Vec::new();
            let code = run_with_dependencies(
                &repair_args(),
                move |_n| Ok(loaded.clone()),
                raw_ref_of(&profile),
                pin_signer_must_not_be_called,
                || Ok(()),
                |_| panic!("a repair reads no secret variable"),
                writer,
                &mut output,
            )
            .await;
            assert_eq!(code, 0, "{}", String::from_utf8_lossy(&output));
            let json = render::single_json_document(&output);
            assert_eq!(json["data"]["written"], written);
            assert_eq!(json["data"]["public_address"], derived_g);
            assert_eq!(json["data"]["keyring_account"], "enrolled-identity");
            assert_eq!(stored_identity(), Some(agent_record_of(&derived_g)));
        }
        assert!(
            KeyringEntry::new(SIGNER_SERVICE, &derived_g)
                .unwrap()
                .get_password()
                .unwrap()
                == s_strkey,
            "the seed is unchanged"
        );
    }

    #[tokio::test]
    #[serial]
    async fn a_repair_refuses_a_conflicting_record_or_seed() {
        // Another key's record is a conflict and stays as it is.
        keyring_mock::install().unwrap();
        let (s_strkey, derived_g) = seed_material([0x44; 32]);
        let (_, other_g) = seed_material([0x45; 32]);
        KeyringEntry::new(SIGNER_SERVICE, &derived_g)
            .unwrap()
            .set_password(&s_strkey)
            .unwrap();
        write_keyring_string(&identity_ref(), &agent_record_of(&other_g)).unwrap();
        let profile = profile_with_signer_account(&derived_g);
        let loaded = profile.clone();
        let mut output = Vec::new();
        let code = run_with_dependencies(
            &repair_args(),
            move |_n| Ok(loaded.clone()),
            raw_ref_of(&profile),
            pin_signer_must_not_be_called,
            || Ok(()),
            |_| panic!("a repair reads no secret variable"),
            write_identity_must_not_be_called,
            &mut output,
        )
        .await;
        assert_eq!(code, 1);
        assert_eq!(
            render::single_json_document(&output)["error"]["code"],
            "enroll_signer.identity_conflict"
        );
        assert_eq!(stored_identity(), Some(agent_record_of(&other_g)));

        // A seed that derives to another address than the pin refuses.
        keyring_mock::install().unwrap();
        KeyringEntry::new(SIGNER_SERVICE, &other_g)
            .unwrap()
            .set_password(&s_strkey)
            .unwrap();
        let mismatched = profile_with_signer_account(&other_g);
        let loaded = mismatched.clone();
        let mut output = Vec::new();
        let code = run_with_dependencies(
            &repair_args(),
            move |_n| Ok(loaded.clone()),
            raw_ref_of(&mismatched),
            pin_signer_must_not_be_called,
            || Ok(()),
            |_| panic!("a repair reads no secret variable"),
            write_identity_must_not_be_called,
            &mut output,
        )
        .await;
        assert_eq!(code, 1);
        assert_eq!(
            render::single_json_document(&output)["error"]["code"],
            "auth.signer_key_mismatch"
        );
        assert_eq!(stored_identity(), None);

        // No seed, or no pin, leaves nothing to repair.
        for account in [other_g.as_str(), "default"] {
            keyring_mock::install().unwrap();
            let unpinned = profile_with_signer_account(account);
            let loaded = unpinned.clone();
            let mut output = Vec::new();
            let code = run_with_dependencies(
                &repair_args(),
                move |_n| Ok(loaded.clone()),
                raw_ref_of(&unpinned),
                pin_signer_must_not_be_called,
                || Ok(()),
                |_| panic!("a repair reads no secret variable"),
                write_identity_must_not_be_called,
                &mut output,
            )
            .await;
            assert_eq!(code, 1, "{account}");
            let expected = if account == "default" {
                "enroll_signer.repair_unpinned"
            } else {
                "auth.keyring_not_found"
            };
            assert_eq!(
                render::single_json_document(&output)["error"]["code"],
                expected
            );
            assert_eq!(stored_identity(), None);
        }
    }

    #[derive(Debug, clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        args: EnrollSignerArgs,
    }

    #[test]
    fn the_repair_flag_excludes_the_secret_and_the_replacement() {
        use clap::Parser as _;
        use clap::error::ErrorKind;
        let repair = Wrap::try_parse_from(["prog", "--repair-identity"]).unwrap();
        assert!(repair.args.repair_identity);
        assert!(repair.args.secret_env.is_none());
        for conflicting in [
            vec!["prog", "--repair-identity", "--secret-env", "VAR"],
            vec!["prog", "--repair-identity", "--force"],
        ] {
            assert_eq!(
                Wrap::try_parse_from(conflicting).unwrap_err().kind(),
                ErrorKind::ArgumentConflict
            );
        }
        assert_eq!(
            Wrap::try_parse_from(["prog"]).unwrap_err().kind(),
            ErrorKind::MissingRequiredArgument
        );
        let enroll = Wrap::try_parse_from(["prog", "--secret-env", "VAR"]).unwrap();
        assert_eq!(enroll.args.secret_env.as_deref(), Some("VAR"));
    }

    #[tokio::test]
    #[serial]
    async fn a_force_replacement_removes_the_old_identity_before_a_failed_write() {
        keyring_mock::install().unwrap();
        let (s_strkey, derived_g) = seed_material([0x42; 32]);
        let var = unique_var("PARTIAL");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);
        let profile = profile_with_signer_account(&derived_g);
        KeyringEntry::new(SIGNER_SERVICE, &derived_g)
            .unwrap()
            .set_password(&s_strkey)
            .unwrap();
        write_keyring_string(&identity_ref(), &agent_record_of(&derived_g)).unwrap();
        let pinned = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let pinned_for_closure = pinned.clone();
        let raw = raw_ref_of(&profile);
        let mut output = Vec::new();
        let code = run_with_dependencies(
            &args(&var, None, true),
            move |_n| Ok(profile.clone()),
            raw,
            move |_name, account| {
                *pinned_for_closure.lock().unwrap() = Some(account.to_owned());
                Ok(PathBuf::from("/dev/null"))
            },
            || Ok(()),
            |name| std::env::var(name),
            |_entry: &KeyringEntryRef, _value: &str| {
                Err(WalletError::Auth(AuthError::KeyringLocked))
            },
            &mut output,
        )
        .await;
        assert_eq!(code, 1);
        let json = render::single_json_document(&output);
        assert_eq!(
            json["error"]["code"],
            "profile.enroll_signer_identity_incomplete"
        );
        let message = json["error"]["message"].as_str().unwrap();
        assert!(
            message.contains(
                "stellar-agent profile enroll-signer --profile enroll-signer-test --repair-identity"
            ),
            "{message}"
        );
        assert!(message.contains("auth.keyring_locked"), "{message}");
        assert_eq!(pinned.lock().unwrap().as_deref(), None);
        assert!(
            KeyringEntry::new(SIGNER_SERVICE, &derived_g)
                .unwrap()
                .get_password()
                .unwrap()
                == s_strkey,
            "the seed is kept"
        );
        assert_eq!(stored_identity(), None);
    }

    /// A `--force` replacement whose seed write fails after the identity
    /// record was removed reports the removal and what the seed coordinate
    /// still holds, and leaves no record.
    #[tokio::test]
    #[serial]
    async fn a_failed_seed_write_after_the_removal_reports_the_removed_record() {
        let (s_strkey, derived_g) = seed_material([0x45; 32]);
        let (old_seed, _) = seed_material([0x46; 32]);
        for previous in [Some(old_seed.as_str()), None] {
            keyring_mock::install_with_write_error(
                SIGNER_SERVICE,
                &derived_g,
                previous,
                keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other("seed"))),
            )
            .unwrap();
            write_keyring_string(&identity_ref(), &agent_record_of(&derived_g)).unwrap();
            let var = unique_var("SEED_AFTER_REMOVAL");
            let _guard = EnvGuard::set(var.clone(), &s_strkey);
            let profile = profile_with_signer_account(&derived_g);
            let raw = raw_ref_of(&profile);
            let mut output = Vec::new();
            let code = run_with_dependencies(
                &args(&var, None, true),
                move |_n| Ok(profile.clone()),
                raw,
                pin_signer_must_not_be_called,
                || Ok(()),
                |name| std::env::var(name),
                write_identity_must_not_be_called,
                &mut output,
            )
            .await;
            assert_eq!(code, 1);
            let json = render::single_json_document(&output);
            assert_eq!(
                json["error"]["code"],
                "profile.enroll_signer_identity_incomplete"
            );
            let message = json["error"]["message"].as_str().unwrap();
            assert!(message.contains("auth.keyring_platform_error"), "{message}");
            assert!(
                message.contains(
                    "The identity record at account 'enrolled-identity' was removed before the \
                     write."
                ),
                "{message}"
            );
            assert_eq!(stored_identity(), None);
            let stored = KeyringEntry::new(SIGNER_SERVICE, &derived_g)
                .unwrap()
                .get_password();
            match previous {
                Some(seed) => {
                    assert!(
                        message.contains("The previous seed is kept. Re-run with `--force`"),
                        "{message}"
                    );
                    assert!(
                        message.contains(
                            "stellar-agent profile enroll-signer --profile enroll-signer-test \
                             --repair-identity"
                        ),
                        "{message}"
                    );
                    assert!(
                        stored.unwrap() == seed,
                        "the previous seed is kept at the coordinate"
                    );
                }
                None => {
                    assert!(
                        message.contains("No seed was stored there. Re-run the command"),
                        "{message}"
                    );
                    assert!(
                        matches!(stored, Err(keyring_core::Error::NoEntry)),
                        "no seed is written"
                    );
                }
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn a_repair_refuses_a_malformed_identity_record() {
        // A malformed record is a conflict and stays as it is.
        keyring_mock::install().unwrap();
        let (s_strkey, derived_g) = seed_material([0x44; 32]);

        KeyringEntry::new(SIGNER_SERVICE, &derived_g)
            .unwrap()
            .set_password(&s_strkey)
            .unwrap();
        write_keyring_string(&identity_ref(), "malformed identity").unwrap();
        let profile = profile_with_signer_account(&derived_g);
        let loaded = profile.clone();
        let mut output = Vec::new();
        let code = run_with_dependencies(
            &repair_args(),
            move |_n| Ok(loaded.clone()),
            raw_ref_of(&profile),
            pin_signer_must_not_be_called,
            || Ok(()),
            |_| panic!("a repair reads no secret variable"),
            write_identity_must_not_be_called,
            &mut output,
        )
        .await;
        assert_eq!(code, 1);
        assert_eq!(
            render::single_json_document(&output)["error"]["code"],
            "enroll_signer.identity_conflict"
        );
        assert_eq!(stored_identity(), Some("malformed identity".to_owned()));
    }

    #[tokio::test]
    #[serial]
    async fn repair_identity_records_the_enrollment_audit_row() {
        keyring_mock::install().unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        let (seed, public) = seed_material([0x49; 32]);
        KeyringEntry::new(SIGNER_SERVICE, &public)
            .unwrap()
            .set_password(&seed)
            .unwrap();
        let mut profile = profile_with_signer_account(&public);
        profile.audit_log_path = dir.path().join("audit.jsonl");
        stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test("enroll-signer-test");
        stellar_agent_network::keyring::rotate_keyring_secret_32(
            &profile.audit_log_hash_chain_key_id.service,
            &profile.audit_log_hash_chain_key_id.account,
        )
        .unwrap();
        let loaded = profile.clone();
        let mut output = Vec::new();
        let code = run_with_dependencies(
            &repair_args(),
            move |_| Ok(loaded.clone()),
            raw_ref_of(&profile),
            pin_signer_must_not_be_called,
            || Ok(()),
            |_| panic!("no secret variable"),
            write_keyring_string,
            &mut output,
        )
        .await;
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&output));
        let log = std::fs::read_to_string(&profile.audit_log_path).unwrap();
        assert!(log.contains("signer_identity_enrolled"), "{log}");
        assert!(log.contains("enrolled-identity"));
        assert!(!log.contains(&seed));
    }
}
