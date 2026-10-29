//! Audited installation binding for a named mainnet profile.
//!
//! Before it stores a nonce, the ceremony keeps a present policy pin and
//! otherwise pins the installed policy, which must be a signed v2 policy.
//! An installation that already holds a nonce but no pin is refused with
//! `policy.pin_absent`, with and without `--rotate`, before anything is
//! written: no wallet command establishes the pin of an enabled installation.
//!
//! Refusals use `profile.enable_mainnet_profile_flag_required`,
//! `profile.enable_mainnet_default_refused`, `profile.enable_mainnet_not_mainnet`,
//! `profile.mainnet_oracle_required`, `profile.enable_mainnet_precondition`,
//! `profile.enable_mainnet_nonce_exists`, and `policy.pin_absent`. The pin
//! step returns the `policy.*` code of its verified load, such as
//! `policy.owner_signature_invalid`, `policy.sequence_rollback`, or
//! `policy.state_lock_busy`, and strict audit errors retain their own codes.
//! A process on a headless keyring backend is refused with
//! `network.mainnet_keyring_backend_unsupported` in both modes, before any
//! keyring entry is read. A profile without a usable oracle is refused with
//! `profile.mainnet_oracle_required` before any keyring entry is read.
//! `--check` reports every check as `passed`, `failed`, or `not_evaluated`,
//! reads the prerequisite state, keyring entries included, and writes no
//! nonce, pin, policy change, or audit row; a missing oracle is a failed check
//! there.

use super::sign_policy::atomic_write_string;
use crate::{
    commands::value_audit::emit_value_audit_row_strict,
    common::{profile_access::load_profile_reconciled, render},
};
use clap::Args;
use serde::Serialize;
use sha2::Digest as _;
use std::path::Path;
use stellar_agent_core::{
    audit_log::{
        AuditEntry, BindingCheck,
        entry::NewToolInvocation,
        schema::{EventKind, PolicyDecision},
    },
    envelope::Envelope,
    mainnet::{
        enablement::{
            has_enablement_nonce, normalize_endpoint_host, read_enablement_nonce, verify_enablement,
        },
        oracle::require_mainnet_oracle,
    },
    policy::{
        PolicyError,
        pin::PinState,
        v1::{
            PolicyStateStore,
            mainnet_minimum::{self, RequirementStatus},
            verified::{OwnerKeySource, PolicyInspection, PolicyLoad, inspect_verified_policy},
        },
    },
    profile::{
        loader,
        name::ProfileNameSource,
        owner_key::decode_owner_public_key,
        schema::{
            KeyringEntryRef, PolicyEngineKind, Profile, default_policy_dir,
            default_policy_window_state_path_for, default_profile_dir,
            mainnet_enablement_entry_ref,
        },
        signer_identity::enrolled_signer_pin,
    },
};
use stellar_agent_network::{
    keyring::{EnrolledRole, KeyringOperation, enrolled_signer, map_keyring_operation_error},
    policy_state::PersistedWindowStore,
};

type Failure = (&'static str, String);

/// Arguments for `profile enable-mainnet`.
#[derive(Debug, Args)]
pub struct EnableMainnetArgs {
    /// Explicit name of the mainnet profile.
    #[arg(long)]
    pub(crate) profile: Option<String>,
    /// Check all bindings and restrictions without changing persisted state.
    #[arg(long, conflicts_with = "rotate")]
    check: bool,
    /// Replace the installation nonce and bind the policy to it. A policy
    /// without a `[mainnet]` table is bound in full.
    #[arg(long)]
    rotate: bool,
}

/// The outcome of one reported check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Passed,
    Failed,
    NotEvaluated,
}

/// The oracle check: a mainnet profile is enabled only with
/// `oracle_provider_url` and its `providers.oracle` record, the oracle every
/// mainnet write requires.
fn oracle_check(profile: &Profile) -> Check {
    let result = require_mainnet_oracle(profile);
    Check {
        item: "oracle_provider_url".into(),
        status: if result.is_ok() {
            Status::Passed
        } else {
            Status::Failed
        },
        detail: result.err().map(|error| error.to_string()),
    }
}

#[derive(Serialize)]
struct Check {
    item: String,
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

fn precondition(detail: impl Into<String>) -> Failure {
    ("profile.enable_mainnet_precondition", detail.into())
}

/// Renders a policy error with its wire code once, whether or not its text
/// already starts with the code.
fn policy_failure(error: &PolicyError) -> String {
    let text = error.to_string();
    if text.starts_with(error.wire_code()) {
        text
    } else {
        format!("{}: {text}", error.wire_code())
    }
}

/// Reads the profile's owner public key, telling an absent entry apart from
/// an unreadable entry and from a value that is not a public key.
fn read_owner_key(coordinate: &KeyringEntryRef) -> Result<[u8; 32], String> {
    let entry =
        keyring_core::Entry::new(&coordinate.service, &coordinate.account).map_err(|e| {
            let classified =
                map_keyring_operation_error(&e, KeyringOperation::Construct, &coordinate.service);
            format!("owner key unreadable ({classified})")
        })?;
    let raw = match entry.get_password() {
        Ok(raw) => zeroize::Zeroizing::new(raw),
        Err(keyring_core::Error::NoEntry) => return Err("owner key not enrolled".into()),
        Err(e) => {
            let classified =
                map_keyring_operation_error(&e, KeyringOperation::Read, &coordinate.service);
            return Err(format!("owner key unreadable ({classified})"));
        }
    };
    decode_owner_public_key(&raw)
        .map(|(key, _)| key)
        .ok_or_else(|| "owner key is not a G-strkey or a 32-byte base64 public key".into())
}

/// Runs the ceremony or its read-only inspection and renders a JSON envelope.
pub(crate) fn run(args: &EnableMainnetArgs) -> i32 {
    let result = (|| {
        let name = args.profile.as_deref().ok_or_else(|| {
            (
                "profile.enable_mainnet_profile_flag_required",
                "supply --profile".into(),
            )
        })?;
        if name == "default" {
            return Err((
                "profile.enable_mainnet_default_refused",
                "use a dedicated profile".into(),
            ));
        }
        let profile = load_profile_reconciled(
            &stellar_agent_core::profile::ResolvedProfileName::from_flag(name),
        )
        .map_err(|e| precondition(e.to_string()))?;
        let profile_dir = default_profile_dir().map_err(|e| precondition(e.to_string()))?;
        let policy_path = default_policy_dir()
            .map_err(|e| precondition(e.to_string()))?
            .join(format!("{name}.toml"));
        stellar_agent_network::keyring::init_platform_keyring_store()
            .map_err(|e| precondition(e.to_string()))?;
        execute(
            args,
            name,
            &profile,
            &profile_dir,
            &policy_path,
            &default_policy_window_state_path_for(name),
            |entry| {
                emit_value_audit_row_strict(&profile, name, BindingCheck::Enforce, entry)
                    .map_err(|e| (e.code(), e.to_string()))
            },
            atomic_write_string,
        )
    })();
    let status = exit_code(&result);
    match result {
        Ok(data) => render::render_json(&Envelope::ok(data)),
        Err((code, detail)) => render::render_json(&Envelope::<()>::err_raw(code, detail)),
    }
    status
}

/// The exit code of a run: 1 for a refusal and for an inspection with a
/// failed check, 0 otherwise.
fn exit_code(result: &Result<serde_json::Value, Failure>) -> i32 {
    match result {
        Ok(data) => i32::from(
            !data
                .get("valid")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true),
        ),
        Err(_) => 1,
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the command binds disk paths, an injectable strict audit emitter, and an \
              injectable policy writer"
)]
pub(super) fn execute(
    args: &EnableMainnetArgs,
    name: &str,
    profile: &Profile,
    profile_dir: &Path,
    policy_path: &Path,
    window_path: &Path,
    emit: impl FnOnce(AuditEntry) -> Result<(), Failure>,
    write_policy: impl FnOnce(&Path, &str) -> std::io::Result<()>,
) -> Result<serde_json::Value, Failure> {
    if args.profile.as_deref() != Some(name) {
        return Err((
            "profile.enable_mainnet_profile_flag_required",
            "supply --profile".into(),
        ));
    }
    if name == "default" {
        return Err((
            "profile.enable_mainnet_default_refused",
            "use a dedicated profile".into(),
        ));
    }
    if !profile.chain_id.is_mainnet() {
        return Err(("profile.enable_mainnet_not_mainnet", "chain_id".into()));
    }
    stellar_agent_network::mainnet::audit_readiness::refuse_headless_keyring_backend()
        .map_err(|e| (e.code(), e.to_string()))?;
    if !args.check {
        require_mainnet_oracle(profile).map_err(|e| (e.code(), e.to_string()))?;
    }
    let mut checks = Vec::new();
    let mut record = |item: &str, result: Result<(), String>| {
        checks.push(Check {
            item: item.into(),
            status: if result.is_ok() {
                Status::Passed
            } else {
                Status::Failed
            },
            detail: result.err(),
        });
    };
    let disk = loader::read_mainnet_view_on_disk(name, profile_dir);
    record(
        "chain_id",
        disk.as_ref().map_err(ToString::to_string).and_then(|disk| {
            if disk.chain_id == profile.chain_id {
                Ok(())
            } else {
                Err("on-disk and merged chain_id differ".into())
            }
        }),
    );
    record(
        "rpc_url",
        disk.as_ref().map_err(ToString::to_string).and_then(|disk| {
            if disk.rpc_url == profile.rpc_url {
                Ok(())
            } else {
                Err("on-disk and merged rpc_url differ".into())
            }
        }),
    );
    record(
        "engine",
        if profile.policy.engine == PolicyEngineKind::V1 {
            Ok(())
        } else {
            Err("engine v1 required".into())
        },
    );
    let owner = read_owner_key(&KeyringEntryRef::default_owner_key(name));
    record(
        "owner_key",
        owner.as_ref().map(|_| ()).map_err(Clone::clone),
    );
    let signer = enrolled_signer_pin(name, profile)
        .map_err(|e| e.to_string())
        .and_then(|pin| {
            let pin = pin.ok_or_else(|| "mainnet signer pin absent".to_owned())?;
            let key = stellar_strkey::ed25519::PublicKey::from_string(&pin)
                .map_err(|e| e.to_string())?
                .0;
            enrolled_signer(name, profile_dir, profile, EnrolledRole::Agent, &key)
                .map(|_| ())
                .map_err(|e| e.to_string())
        });
    record("enrolled_signer", signer);
    let findings = stellar_agent_core::profile::key_scope::key_scope_findings_in_dir(
        profile,
        name,
        profile_dir,
    );
    record(
        "key_scope",
        if findings.is_empty() {
            Ok(())
        } else {
            Err(findings
                .iter()
                .map(|f| f.message(name))
                .collect::<Vec<_>>()
                .join("; "))
        },
    );
    if args.check {
        let state = PolicyStateStore::new();
        let inspection = PersistedWindowStore::at_path(window_path.to_path_buf())
            .load_into(name, profile, &state)
            .map_err(|e| e.to_string())
            .and_then(|()| owner.clone())
            .map(|owner| {
                inspect_verified_policy(
                    &PolicyLoad {
                        path: policy_path,
                        profile,
                        profile_name: name,
                        owner_pubkey: &owner,
                        owner_source: OwnerKeySource::Keyring,
                        window_path,
                    },
                    state,
                )
            });
        checks.extend(inspection_checks(&inspection, name, profile, profile_dir));
        checks.push(oracle_check(profile));
        let valid = checks.iter().all(|c| c.status != Status::Failed);
        return Ok(serde_json::json!({
            "profile": name,
            "valid": valid,
            "checks": checks,
        }));
    }
    if let Some(failed) = checks.iter().find(|check| check.status == Status::Failed) {
        return Err(precondition(format!(
            "{}: {}",
            failed.item,
            failed.detail.as_deref().unwrap_or("failed")
        )));
    }
    let raw = std::fs::read_to_string(policy_path)
        .map_err(|e| precondition(format!("policy_file: {e}")))?;
    let body = raw
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| precondition(format!("policy_file: {e}")))?;
    let coordinate = mainnet_enablement_entry_ref(&profile.policy_window_state_key_id);
    let entry = keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .map_err(|_| precondition("nonce"))?;
    let exists = has_enablement_nonce(profile).map_err(|_| precondition("nonce unreadable"))?;
    if exists {
        refuse_absent_pin(name, profile, window_path, &coordinate)?;
    }
    if exists && !args.rotate {
        return Err((
            "profile.enable_mainnet_nonce_exists",
            "an installation nonce is already stored; rerun with --rotate to replace it and \
             bind the policy to the new nonce"
                .into(),
        ));
    }
    let host = normalize_endpoint_host(&profile.rpc_url).map_err(|e| (e.code(), e.to_string()))?;
    use rand_core::{OsRng, RngCore as _};
    let mut random = zeroize::Zeroizing::new([0_u8; 32]);
    OsRng
        .try_fill_bytes(random.as_mut())
        .map_err(|_| precondition("nonce randomness"))?;
    let nonce = zeroize::Zeroizing::new(stellar_agent_core::hex::encode(random.as_ref()));
    let digest = stellar_agent_core::hex::encode(&sha2::Sha256::digest(nonce.as_bytes()));
    let rewritten = rewrite_policy(&body, name, &host, &digest, args.rotate)?;
    ensure_policy_pin(name, profile, policy_path, window_path)?;
    let mut audit = AuditEntry::new_tool_invocation(NewToolInvocation::new(
        "mainnet_enablement_minted",
        "stellar:mainnet",
        vec![],
        PolicyDecision::Allow,
        uuid::Uuid::new_v4().to_string(),
    ));
    audit.event_kind = EventKind::MainnetEnablementMinted {
        profile: name.into(),
        endpoint_host: host.clone(),
        installation_nonce_sha256: digest.clone(),
        rotated: args.rotate,
    };
    // The audit row precedes the nonce, and the nonce precedes the policy
    // rewrite. A rewrite that fails after the nonce write leaves a stored
    // nonce the policy does not name; `--rotate` then binds the policy in
    // full, with its own audit row first.
    emit(audit)?;
    entry
        .set_password(&nonce)
        .map_err(|_| precondition("nonce write failed"))?;
    write_policy(policy_path, &rewritten)
        .map_err(|e| precondition(format!("policy rewrite: {e}")))?;
    let mut next = vec![
        "Set [mainnet].classic_max_fee_per_op_stroops, optional authorization_ttl_seconds, \
         and cross_check_thresholds."
            .to_owned(),
        format!("stellar-agent profile sign-policy --profile {name} --secret-env OWNER_SEED"),
    ];
    if !cfg!(feature = "mainnet-write") {
        next.push("Mainnet writes require a build with mainnet-write enabled.".into());
    }
    Ok(serde_json::json!({
        "profile": name,
        "endpoint_host": host,
        "installation_nonce_sha256": digest,
        "policy_path": policy_path,
        "policy_needs_signature": true,
        "rotated": args.rotate,
        "next": next,
    }))
}

/// Refuses an installation that holds an enablement nonce at `nonce` but no
/// readable pin, before anything is written. The pin is read without
/// creating the lock file or its directory. When the lock file is missing
/// but the pin entry exists, the refusal names the lock file, which a
/// command that builds the V1 policy engine recreates; only a missing pin
/// entry prescribes removing the nonce.
///
/// # Errors
/// `policy.pin_absent` naming the missing lock file or the nonce entry to
/// remove, or the code of the lock or pin read failure.
fn refuse_absent_pin(
    name: &str,
    profile: &Profile,
    window_path: &Path,
    nonce: &KeyringEntryRef,
) -> Result<(), Failure> {
    use stellar_agent_core::policy::{pin, v1::verified::read_pin_without_creating};
    let state = read_pin_without_creating(window_path, profile)
        .map_err(|e| (e.wire_code(), e.to_string()))?;
    if let PinState::Present(_) = state {
        return Ok(());
    }
    let pin_entry = pin::entry_present(&profile.policy_window_state_key_id).map_err(|e| {
        let e = PolicyError::from(e);
        (e.wire_code(), e.to_string())
    })?;
    if pin_entry {
        return Err((
            PolicyError::PinAbsent.wire_code(),
            format!(
                "the policy-state lock file of profile '{name}' is missing, so its policy pin \
                 cannot be read; a command that builds the V1 policy engine recreates the lock \
                 file, and this command can run after it; nothing was written"
            ),
        ));
    }
    Err((
        PolicyError::PinAbsent.wire_code(),
        format!(
            "the installation holds a mainnet enablement nonce but no policy pin, and no wallet \
             command establishes the pin of an enabled installation; remove the keyring entry \
             with service '{}' and account '{}' with the platform keyring tool, rerun \
             `stellar-agent profile enable-mainnet --profile {name}`, and sign the rebound \
             policy; nothing was written",
            nonce.service, nonce.account
        ),
    ))
}

/// Preserves an existing pin, or establishes one from the installed signed
/// v2 policy before a nonce is written. The caller has refused an
/// installation that holds a nonce but no pin, and the verified load refuses
/// that state again under the lock.
fn ensure_policy_pin(
    name: &str,
    profile: &Profile,
    policy_path: &Path,
    window_path: &Path,
) -> Result<(), Failure> {
    use stellar_agent_core::policy::v1::verified::{
        PinMode, load_verified_policy, read_pin_without_creating,
    };
    let error = |e: PolicyError| (e.wire_code(), e.to_string());
    if let PinState::Present(_) = read_pin_without_creating(window_path, profile).map_err(error)? {
        return Ok(());
    }
    if let Some(parent) = window_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| precondition(format!("policy state directory: {e}")))?;
    }
    let owner = read_owner_key(&KeyringEntryRef::default_owner_key(name)).map_err(precondition)?;
    let verified = load_verified_policy(
        &PolicyLoad {
            path: policy_path,
            profile,
            profile_name: name,
            owner_pubkey: &owner,
            owner_source: OwnerKeySource::Keyring,
            window_path,
        },
        PolicyStateStore::new(),
        PinMode::Advance,
    )
    .map_err(error)?;
    if verified.sequence() == 0 {
        return Err(precondition("sign a v2 policy before enabling mainnet"));
    }
    Ok(())
}

/// The checks a compare-only inspection yields: the verified policy, the pin
/// it compared against, the installation binding, and every minimum
/// requirement on the verified document, in [`mainnet_minimum::REQUIREMENTS`]
/// order.
///
/// The pin check fails when the pin could not be read or the comparison
/// refused. `inspection` is `Err` when the inspection could not run: the
/// window state did not load or the owner key is unusable.
fn inspection_checks(
    inspection: &Result<PolicyInspection, String>,
    name: &str,
    profile: &Profile,
    profile_dir: &Path,
) -> Vec<Check> {
    let check = |item: &str, status, detail: Option<String>| Check {
        item: item.into(),
        status,
        detail,
    };
    let not_loaded = || Some("the verified policy did not load".to_owned());
    let mut checks = Vec::new();
    let (verified, pin, document) = match inspection {
        Ok(inspection) => (
            inspection.verified.as_ref().map_err(policy_failure),
            inspection.pin.as_ref(),
            inspection.document.as_ref(),
        ),
        Err(detail) => (Err(detail.clone()), None, None),
    };
    checks.push(match &verified {
        Ok(_) => check("verified_policy", Status::Passed, None),
        Err(detail) => check("verified_policy", Status::Failed, Some(detail.clone())),
    });
    let pin_failure = match inspection {
        Ok(PolicyInspection {
            verified:
                Err(
                    error @ (PolicyError::StateLockBusy
                    | PolicyError::StateLockIo { .. }
                    | PolicyError::PinUnusable { .. }
                    | PolicyError::PinAbsent
                    | PolicyError::OwnerRotationRequired
                    | PolicyError::OwnerRotationInvalid
                    | PolicyError::SequenceRollback
                    | PolicyError::SequenceFork),
                ),
            ..
        }) => Some(policy_failure(error)),
        _ => None,
    };
    checks.push(match (pin, pin_failure) {
        (Some(PinState::Present(pin)), Some(failure)) => check(
            "pin",
            Status::Failed,
            Some(format!("{failure}; pinned sequence {}", pin.sequence())),
        ),
        (_, Some(failure)) => check("pin", Status::Failed, Some(failure)),
        (Some(PinState::Absent), None) => {
            check("pin", Status::Passed, Some("absent (first use)".into()))
        }
        (Some(PinState::Present(pin)), None) => check(
            "pin",
            Status::Passed,
            Some(format!("sequence {}", pin.sequence())),
        ),
        (None, None) => check(
            "pin",
            Status::NotEvaluated,
            Some("the verified load stopped before the pin comparison".into()),
        ),
    });
    checks.push(match &verified {
        Ok(verified) => match verify_enablement(
            verified,
            name,
            ProfileNameSource::Flag,
            profile,
            profile_dir,
            &read_enablement_nonce,
        ) {
            Ok(_) => check("enablement", Status::Passed, None),
            Err(error) => check("enablement", Status::Failed, Some(error.to_string())),
        },
        Err(_) => check("enablement", Status::NotEvaluated, not_loaded()),
    });
    match document {
        Some(document) => {
            for outcome in mainnet_minimum::evaluate(document, profile, name) {
                checks.push(match outcome.status {
                    RequirementStatus::Passed => check(outcome.requirement, Status::Passed, None),
                    RequirementStatus::Failed { detail, .. } => {
                        check(outcome.requirement, Status::Failed, Some(detail))
                    }
                    RequirementStatus::NotEvaluated { detail } => check(
                        outcome.requirement,
                        Status::NotEvaluated,
                        Some(detail.into()),
                    ),
                });
            }
        }
        None => {
            for &requirement in mainnet_minimum::REQUIREMENTS {
                checks.push(check(requirement, Status::NotEvaluated, not_loaded()));
            }
        }
    }
    checks
}

/// Writes the installation binding into the policy body.
///
/// A first ceremony, and a rotation of a body without a `[mainnet]` table,
/// bind in full: version 2, the profile, the endpoint host, and the nonce
/// digest. A rotation of a bound body replaces only the nonce digest.
fn rewrite_policy(
    body: &toml_edit::DocumentMut,
    name: &str,
    host: &str,
    digest: &str,
    rotate: bool,
) -> Result<String, Failure> {
    let mut body = body.clone();
    if !matches!(
        body.get("version").and_then(toml_edit::Item::as_integer),
        Some(1 | 2)
    ) {
        return Err(precondition("body_version"));
    }
    let bound = body
        .get("mainnet")
        .and_then(toml_edit::Item::as_table_like)
        .is_some();
    if !rotate || !bound {
        body["version"] = toml_edit::value(2);
        if !body.contains_key("mainnet") {
            body["mainnet"] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        let table = body
            .get_mut("mainnet")
            .and_then(toml_edit::Item::as_table_like_mut)
            .ok_or_else(|| precondition("mainnet_table"))?;
        table.insert("profile", toml_edit::value(name));
        table.insert("endpoint_host", toml_edit::value(host));
    }
    let table = body
        .get_mut("mainnet")
        .and_then(toml_edit::Item::as_table_like_mut)
        .ok_or_else(|| precondition("mainnet_table"))?;
    table.insert("installation_nonce_sha256", toml_edit::value(digest));
    Ok(body.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test fixtures fail loudly"
    )]
    use super::*;
    use ed25519_dalek::SigningKey;
    use serial_test::serial;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};
    use stellar_agent_core::error::MainnetOracleGap;
    use stellar_agent_core::{
        mainnet::verified_policy::VerifiedPolicy,
        policy::{
            pin::{self, Pin, PinScope},
            state_lock::WindowStoreLock,
            v1::verified::{PinMode, load_verified_policy, read_pin_without_creating},
        },
        profile::{
            schema::{PrimaryProviderRecord, ProviderRecord, signer_identity_entry_ref},
            signer_identity::SignerIdentityRecord,
        },
    };
    use stellar_agent_test_support::keyring_mock;
    const FULL: &str = include_str!("../../../../stellar-agent-core/tests/fixtures/policy-v2.toml");

    struct Fixture {
        dir: tempfile::TempDir,
        profile: Profile,
        args: EnableMainnetArgs,
        owner: SigningKey,
        window: std::path::PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            keyring_mock::install().unwrap();
            Self::seeded(Self::profile())
        }
        /// A fixture whose keyring store records in `reads` the coordinate of
        /// every secret read at a keyring entry the ceremony can reach: each
        /// coordinate the profile names and each one derived from them.
        fn recording(reads: &Arc<Mutex<Vec<String>>>) -> Self {
            let profile = Self::profile();
            let window = &profile.policy_window_state_key_id;
            let mut coordinates = vec![
                profile.mcp_signer_default.clone(),
                profile.mcp_nonce_key_alias.clone(),
                profile.audit_log_hash_chain_key_id.clone(),
                profile.policy_owner_key_id.clone(),
                profile.attestation_key_id.clone(),
                profile.counterparty_cache_key_id.clone(),
                window.clone(),
                stellar_agent_core::profile::schema::policy_pin_entry_ref(window),
                mainnet_enablement_entry_ref(window),
                signer_identity_entry_ref(&profile.mcp_signer_default),
                KeyringEntryRef::default_owner_key("operator"),
                KeyringEntryRef::default_audit_binding("operator"),
                KeyringEntryRef::default_mpp_state_key("operator"),
            ];
            coordinates.extend(profile.pool_master_key_id.clone());
            let hooks = coordinates
                .into_iter()
                .map(|coordinate| {
                    let reads = Arc::clone(reads);
                    let label = format!("{}/{}", coordinate.service, coordinate.account);
                    keyring_mock::ReadHook::new(
                        &coordinate.service,
                        &coordinate.account,
                        Arc::new(move || reads.lock().unwrap().push(label.clone())),
                    )
                })
                .collect();
            keyring_mock::install_with_read_hooks(hooks).unwrap();
            Self::seeded(profile)
        }
        fn profile() -> Profile {
            let signer = stellar_strkey::ed25519::PublicKey([2; 32])
                .to_string()
                .to_string();
            Profile::builder_mainnet_named(
                "operator",
                "https://rpc.example.invalid",
                "stellar-agent-signer-operator",
                &signer,
                "stellar-agent-nonce-operator",
                "default",
            )
            .primary_provider(PrimaryProviderRecord::new(
                "Primary operator",
                "rpc.example.invalid",
            ))
            .oracle_provider_url(url::Url::parse("https://oracle.example.invalid").unwrap())
            .oracle_provider(ProviderRecord::new(
                "Oracle operator",
                "oracle.example.invalid",
                true,
            ))
            .build()
        }
        /// Saves `profile` and seeds the keyring and the policy of an
        /// installation ready for its first enablement.
        fn seeded(profile: Profile) -> Self {
            let dir = tempfile::tempdir().unwrap();
            loader::save_to_dir("operator", &profile, &dir.path().join("profiles")).unwrap();
            let owner = SigningKey::from_bytes(&[11; 32]);
            put(
                &KeyringEntryRef::default_owner_key("operator"),
                &stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()).to_string(),
            );
            put(
                &signer_identity_entry_ref(&profile.mcp_signer_default),
                &SignerIdentityRecord::agent([2; 32]).render(),
            );
            let mut body = FULL.parse::<toml_edit::DocumentMut>().unwrap();
            body.remove("mainnet");
            body["sequence"] = toml_edit::value(1);
            std::fs::write(dir.path().join("policy.toml"), body.to_string()).unwrap();
            let window = dir.path().join("state.window");
            let fixture = Self {
                dir,
                profile,
                args: EnableMainnetArgs {
                    profile: Some("operator".into()),
                    check: false,
                    rotate: false,
                },
                owner,
                window,
            };
            fixture.sign(&body.to_string());
            fixture
        }
        fn path(&self) -> std::path::PathBuf {
            self.dir.path().join("policy.toml")
        }
        fn nonce_ref(&self) -> KeyringEntryRef {
            mainnet_enablement_entry_ref(&self.profile.policy_window_state_key_id)
        }
        fn append_audit(&self, entry: &AuditEntry) {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.dir.path().join("audit.jsonl"))
                .unwrap();
            writeln!(file, "{}", serde_json::to_string(entry).unwrap()).unwrap();
        }
        fn run_with(
            &self,
            emit: impl FnOnce(AuditEntry) -> Result<(), Failure>,
            write_policy: impl FnOnce(&Path, &str) -> std::io::Result<()>,
        ) -> Result<serde_json::Value, Failure> {
            execute(
                &self.args,
                "operator",
                &self.profile,
                &self.dir.path().join("profiles"),
                &self.path(),
                &self.window,
                emit,
                write_policy,
            )
        }
        fn run(&self) -> Result<serde_json::Value, Failure> {
            self.run_with(
                |entry| {
                    self.append_audit(&entry);
                    Ok(())
                },
                atomic_write_string,
            )
        }
        fn sign(&self, raw: &str) {
            let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
            doc.remove("signature");
            let raw = doc.to_string();
            let canonical =
                stellar_agent_core::policy::v1::canonical::canonical_bytes(&raw).unwrap();
            let digest = stellar_agent_core::policy::v1::signature::digest(&canonical);
            let signature = stellar_agent_core::policy::v1::signature::sign(&digest, &self.owner);
            std::fs::write(
                self.path(),
                format!(
                    "{raw}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
                    stellar_strkey::ed25519::PublicKey(self.owner.verifying_key().to_bytes()),
                    stellar_agent_core::hex::encode(&signature)
                ),
            )
            .unwrap();
        }
        /// Signs `FULL` bound to the stored nonce at `sequence`.
        fn signed_body(&self, sequence: i64) {
            let nonce = get(&self.nonce_ref()).unwrap();
            let digest = stellar_agent_core::hex::encode(&sha2::Sha256::digest(nonce.as_bytes()));
            self.sign(
                &FULL
                    .replace(&"0".repeat(64), &digest)
                    .replace("sequence = 7", &format!("sequence = {sequence}")),
            );
        }
        /// Completes the rewritten policy with a fee cap and `sequence`, signs
        /// it, and loads it with installation verification.
        fn sign_rewritten_and_verify(&self, sequence: i64) -> VerifiedPolicy {
            let raw = std::fs::read_to_string(self.path()).unwrap();
            let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
            doc["mainnet"]["classic_max_fee_per_op_stroops"] = toml_edit::value(500);
            doc["sequence"] = toml_edit::value(sequence);
            let body = doc.to_string();
            stellar_agent_core::policy::v1::validate_unsigned_policy(&body, "operator").unwrap();
            self.sign(&body);
            let owner = self.owner.verifying_key().to_bytes();
            let verified = load_verified_policy(
                &PolicyLoad {
                    path: &self.path(),
                    profile: &self.profile,
                    profile_name: "operator",
                    owner_pubkey: &owner,
                    owner_source: OwnerKeySource::Keyring,
                    window_path: &self.window,
                },
                PolicyStateStore::new(),
                PinMode::Advance,
            )
            .unwrap();
            assert_eq!(verified.sequence(), sequence);
            verify_enablement(
                &verified,
                "operator",
                ProfileNameSource::Flag,
                &self.profile,
                &self.dir.path().join("profiles"),
                &read_enablement_nonce,
            )
            .unwrap();
            verified
        }
        /// The pin, read without creating the lock file.
        fn pin(&self) -> PinState {
            read_pin_without_creating(&self.window, &self.profile).unwrap()
        }
        fn put_pin(&self, sequence: i64) {
            let lock = WindowStoreLock::acquire_for(
                &self.window,
                &self.profile.policy_window_state_key_id,
            )
            .unwrap();
            pin::write(
                &lock,
                &PinScope::for_profile(&self.window, &self.profile),
                &Pin::new(sequence, [1; 32], self.owner.verifying_key().to_bytes()).unwrap(),
            )
            .unwrap();
        }
        /// Every path under the fixture directory, relative and sorted.
        fn listing(&self) -> Vec<std::path::PathBuf> {
            fn walk(root: &Path, dir: &Path, out: &mut Vec<std::path::PathBuf>) {
                for entry in std::fs::read_dir(dir).unwrap() {
                    let path = entry.unwrap().path();
                    out.push(path.strip_prefix(root).unwrap().to_path_buf());
                    if path.is_dir() {
                        walk(root, &path, out);
                    }
                }
            }
            let mut out = Vec::new();
            walk(self.dir.path(), self.dir.path(), &mut out);
            out.sort();
            out
        }
    }
    fn put(coordinate: &KeyringEntryRef, raw: &str) {
        keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .unwrap()
            .set_password(raw)
            .unwrap();
    }
    fn get(coordinate: &KeyringEntryRef) -> Option<String> {
        keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .unwrap()
            .get_password()
            .ok()
    }
    /// The `(status, detail)` of one reported check.
    fn check_of(output: &serde_json::Value, item: &str) -> (String, Option<String>) {
        let check = output["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["item"] == item)
            .unwrap_or_else(|| panic!("no check {item}: {output}"));
        (
            check["status"].as_str().unwrap().to_owned(),
            check["detail"].as_str().map(str::to_owned),
        )
    }

    #[test]
    #[serial]
    fn ceremony_pins_the_verified_policy_before_enablement() {
        let fixture = Fixture::new();
        let initial = load_verified_policy(
            &PolicyLoad {
                path: &fixture.path(),
                profile: &fixture.profile,
                profile_name: "operator",
                owner_pubkey: &fixture.owner.verifying_key().to_bytes(),
                owner_source: OwnerKeySource::Keyring,
                window_path: &fixture.window,
            },
            PolicyStateStore::new(),
            PinMode::CompareOnly,
        )
        .unwrap();
        let output = fixture
            .run_with(
                |entry| {
                    assert_eq!(
                        fixture.pin(),
                        PinState::Present(
                            Pin::new(initial.sequence(), initial.digest(), initial.owner())
                                .unwrap()
                        )
                    );
                    assert!(get(&fixture.nonce_ref()).is_none());
                    fixture.append_audit(&entry);
                    Ok(())
                },
                atomic_write_string,
            )
            .unwrap();
        let raw = std::fs::read_to_string(fixture.path()).unwrap();
        let doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
        assert_eq!(doc["version"].as_integer(), Some(2));
        assert_eq!(doc["sequence"].as_integer(), Some(1));
        assert_eq!(doc["mainnet"]["profile"].as_str(), Some("operator"));
        assert_eq!(output["policy_needs_signature"], true);
        assert_eq!(output["rotated"], false);
        assert!(
            output["next"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str().unwrap().contains("sign-policy"))
        );
        let next = output["next"].to_string();
        for field in [
            "classic_max_fee_per_op_stroops",
            "authorization_ttl_seconds",
            "cross_check_thresholds",
        ] {
            assert!(next.contains(field));
        }
        assert_eq!(
            next.contains("build with mainnet-write enabled"),
            !cfg!(feature = "mainnet-write")
        );
        fixture.sign_rewritten_and_verify(2);
    }
    #[test]
    #[serial]
    fn check_preserves_every_persisted_value_for_absent_and_advancing_pins() {
        let mut fixture = Fixture::new();
        fixture.run().unwrap();
        fixture.signed_body(7);
        fixture.args.check = true;
        for present in [false, true] {
            if present {
                fixture.put_pin(1);
            } else {
                let coord = stellar_agent_core::profile::schema::policy_pin_entry_ref(
                    &fixture.profile.policy_window_state_key_id,
                );
                keyring_core::Entry::new(&coord.service, &coord.account)
                    .unwrap()
                    .delete_credential()
                    .unwrap();
            }
            let file = std::fs::read(fixture.path()).unwrap();
            let nonce = get(&fixture.nonce_ref());
            let pin = fixture.pin();
            let audit = std::fs::read(fixture.dir.path().join("audit.jsonl")).unwrap();
            let listing = fixture.listing();
            let output = fixture.run().unwrap();
            assert_eq!(output["valid"], present, "{output}");
            let expected_pin = if present {
                "sequence 1"
            } else {
                "policy.pin_absent"
            };
            assert_eq!(
                check_of(&output, "pin"),
                (
                    if present { "passed" } else { "failed" }.to_owned(),
                    Some(expected_pin.to_owned())
                )
            );
            assert_eq!(std::fs::read(fixture.path()).unwrap(), file);
            assert_eq!(get(&fixture.nonce_ref()), nonce);
            assert_eq!(fixture.pin(), pin);
            assert_eq!(
                std::fs::read(fixture.dir.path().join("audit.jsonl")).unwrap(),
                audit
            );
            assert_eq!(fixture.listing(), listing);
        }
    }
    #[test]
    #[serial]
    fn check_before_enablement_reports_a_first_use_pin_and_creates_nothing() {
        for window in ["absent/state.window", "state.window"] {
            let mut fixture = Fixture::new();
            fixture.window = fixture.dir.path().join(window);
            fixture.sign(FULL);
            fixture.args.check = true;
            let listing = fixture.listing();
            let output = fixture.run().unwrap();
            assert_eq!(output["valid"], false, "{window}: {output}");
            assert_eq!(
                check_of(&output, "verified_policy"),
                ("passed".to_owned(), None),
                "{window}"
            );
            assert_eq!(
                check_of(&output, "pin"),
                ("passed".to_owned(), Some("absent (first use)".to_owned())),
                "{window}"
            );
            // No nonce is stored yet, so the installation binding is the one
            // failed check.
            let failed: Vec<_> = output["checks"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|check| check["status"] == "failed")
                .map(|check| check["item"].as_str().unwrap().to_owned())
                .collect();
            assert_eq!(failed, ["enablement"], "{window}: {output}");
            assert_eq!(
                check_of(&output, "enablement").1.as_deref(),
                Some("profile.mainnet_enablement_invalid: nonce"),
                "{window}"
            );
            assert_eq!(fixture.listing(), listing, "{window}");
        }
    }
    #[test]
    #[serial]
    fn first_enablement_refuses_a_v1_or_unsigned_policy_and_writes_nothing() {
        for (body, code) in [
            ("v1", "profile.enable_mainnet_precondition"),
            ("unsigned", "policy.policy_file_parse_failed"),
        ] {
            let fixture = Fixture::new();
            let mut doc = std::fs::read_to_string(fixture.path())
                .unwrap()
                .parse::<toml_edit::DocumentMut>()
                .unwrap();
            if body == "v1" {
                doc.remove("sequence");
                doc["version"] = toml_edit::value(1);
                fixture.sign(&doc.to_string());
            } else {
                doc.remove("signature");
                std::fs::write(fixture.path(), doc.to_string()).unwrap();
            }
            let file = std::fs::read(fixture.path()).unwrap();
            let (refused, detail) = fixture.run().unwrap_err();
            assert_eq!(refused, code, "{body}: {detail}");
            if body == "v1" {
                assert_eq!(detail, "sign a v2 policy before enabling mainnet");
            }
            assert_eq!(get(&fixture.nonce_ref()), None, "{body}");
            assert!(!fixture.dir.path().join("audit.jsonl").exists(), "{body}");
            assert_eq!(fixture.pin(), PinState::Absent, "{body}");
            assert_eq!(std::fs::read(fixture.path()).unwrap(), file, "{body}");
        }
    }
    #[test]
    #[serial]
    fn rotate_leaves_an_existing_pin_unchanged() {
        let mut fixture = Fixture::new();
        fixture.run().unwrap();
        let pinned = fixture.pin();
        assert!(matches!(&pinned, PinState::Present(pin) if pin.sequence() == 1));
        // The rewritten policy is not signed yet; the rotation keeps the pin
        // and loads nothing.
        fixture.args.rotate = true;
        fixture.run().unwrap();
        assert_eq!(fixture.pin(), pinned);
        fixture.sign_rewritten_and_verify(2);
        let advanced = fixture.pin();
        fixture.run().unwrap();
        assert_eq!(fixture.pin(), advanced);
        fixture.sign_rewritten_and_verify(3);
    }
    /// An installation that holds a nonce but no pin refuses both forms of
    /// the ceremony with `policy.pin_absent`, whether the pin entry alone or
    /// also the lock file is missing, and writes no nonce, pin, audit row,
    /// policy, or file.
    #[test]
    #[serial]
    fn an_enabled_installation_without_a_pin_refuses_both_forms_and_writes_nothing() {
        use stellar_agent_core::policy::state_lock::window_lock_path;
        for missing in ["pin", "pin_and_lock"] {
            let mut fixture = Fixture::new();
            fixture.run().unwrap();
            fixture.sign_rewritten_and_verify(2);
            let pin = stellar_agent_core::profile::schema::policy_pin_entry_ref(
                &fixture.profile.policy_window_state_key_id,
            );
            keyring_core::Entry::new(&pin.service, &pin.account)
                .unwrap()
                .delete_credential()
                .unwrap();
            if missing == "pin_and_lock" {
                std::fs::remove_file(window_lock_path(&fixture.window)).unwrap();
            }
            let nonce = get(&fixture.nonce_ref()).unwrap();
            let policy = std::fs::read(fixture.path()).unwrap();
            let audit = std::fs::read(fixture.dir.path().join("audit.jsonl")).unwrap();
            let listing = fixture.listing();
            for rotate in [false, true] {
                fixture.args.rotate = rotate;
                let (code, detail) = fixture.run().unwrap_err();
                assert_eq!(code, "policy.pin_absent", "{missing}, {rotate}: {detail}");
                assert!(
                    detail.contains(&fixture.nonce_ref().account),
                    "{missing}, {rotate}: {detail}"
                );
                assert_eq!(get(&fixture.nonce_ref()), Some(nonce.clone()));
                assert_eq!(fixture.pin(), PinState::Absent);
                assert_eq!(std::fs::read(fixture.path()).unwrap(), policy);
                assert_eq!(
                    std::fs::read(fixture.dir.path().join("audit.jsonl")).unwrap(),
                    audit
                );
                assert_eq!(fixture.listing(), listing, "{missing}, {rotate}");
            }
        }
    }
    /// A missing lock file beside a present pin entry refuses both forms with
    /// `policy.pin_absent` and a message that names the lock file and does
    /// not prescribe removing the nonce, and writes nothing. A verified load
    /// in `PinMode::Advance` then recreates the lock and keeps the pin and the
    /// nonce.
    #[test]
    #[serial]
    fn a_missing_lock_file_refuses_both_forms_without_prescribing_nonce_removal() {
        use stellar_agent_core::policy::state_lock::window_lock_path;
        let mut fixture = Fixture::new();
        fixture.run().unwrap();
        fixture.sign_rewritten_and_verify(2);
        let pinned = fixture.pin();
        let pin = stellar_agent_core::profile::schema::policy_pin_entry_ref(
            &fixture.profile.policy_window_state_key_id,
        );
        let stored_pin = get(&pin).unwrap();
        std::fs::remove_file(window_lock_path(&fixture.window)).unwrap();
        let nonce = get(&fixture.nonce_ref()).unwrap();
        let policy = std::fs::read(fixture.path()).unwrap();
        let audit = std::fs::read(fixture.dir.path().join("audit.jsonl")).unwrap();
        let listing = fixture.listing();
        for rotate in [false, true] {
            fixture.args.rotate = rotate;
            let (code, detail) = fixture.run().unwrap_err();
            assert_eq!(code, "policy.pin_absent", "{rotate}: {detail}");
            assert!(
                detail.contains("policy-state lock file of profile 'operator' is missing"),
                "{rotate}: {detail}"
            );
            assert!(
                !detail.contains(&fixture.nonce_ref().account),
                "{rotate}: {detail}"
            );
            assert_eq!(get(&fixture.nonce_ref()), Some(nonce.clone()));
            assert_eq!(get(&pin), Some(stored_pin.clone()));
            assert_eq!(std::fs::read(fixture.path()).unwrap(), policy);
            assert_eq!(
                std::fs::read(fixture.dir.path().join("audit.jsonl")).unwrap(),
                audit
            );
            assert_eq!(fixture.listing(), listing, "{rotate}");
        }
        load_verified_policy(
            &PolicyLoad {
                path: &fixture.path(),
                profile: &fixture.profile,
                profile_name: "operator",
                owner_pubkey: &fixture.owner.verifying_key().to_bytes(),
                owner_source: OwnerKeySource::Keyring,
                window_path: &fixture.window,
            },
            PolicyStateStore::new(),
            PinMode::Advance,
        )
        .unwrap();
        assert!(window_lock_path(&fixture.window).exists());
        assert_eq!(fixture.pin(), pinned);
        assert_eq!(get(&fixture.nonce_ref()), Some(nonce));
    }
    /// The documented recovery: with the nonce entry removed, the first
    /// enablement pins the installed signed policy and stores a new nonce.
    /// Neither the policy bound to the replaced nonce nor the unsigned
    /// rewrite authorizes a mainnet write until the owner signs the rebound
    /// policy at a higher sequence.
    #[test]
    #[serial]
    fn removing_the_nonce_entry_lets_the_first_enablement_pin_the_installed_policy() {
        let fixture = Fixture::new();
        fixture.run().unwrap();
        fixture.sign_rewritten_and_verify(2);
        let pinned = fixture.pin();
        let bound_to_old_nonce = std::fs::read_to_string(fixture.path()).unwrap();
        let old_nonce = get(&fixture.nonce_ref()).unwrap();
        for coordinate in [
            stellar_agent_core::profile::schema::policy_pin_entry_ref(
                &fixture.profile.policy_window_state_key_id,
            ),
            fixture.nonce_ref(),
        ] {
            keyring_core::Entry::new(&coordinate.service, &coordinate.account)
                .unwrap()
                .delete_credential()
                .unwrap();
        }
        let load = |fixture: &Fixture| {
            load_verified_policy(
                &PolicyLoad {
                    path: &fixture.path(),
                    profile: &fixture.profile,
                    profile_name: "operator",
                    owner_pubkey: &fixture.owner.verifying_key().to_bytes(),
                    owner_source: OwnerKeySource::Keyring,
                    window_path: &fixture.window,
                },
                PolicyStateStore::new(),
                PinMode::CompareOnly,
            )
        };
        let output = fixture.run().unwrap();
        assert_eq!(output["rotated"], false);
        assert_eq!(fixture.pin(), pinned);
        assert_ne!(get(&fixture.nonce_ref()).unwrap(), old_nonce);
        let rebound = std::fs::read_to_string(fixture.path()).unwrap();
        assert_eq!(
            load(&fixture).err().unwrap().wire_code(),
            "policy.owner_signature_invalid"
        );
        std::fs::write(fixture.path(), &bound_to_old_nonce).unwrap();
        let verified = load(&fixture).unwrap();
        assert_eq!(
            verify_enablement(
                &verified,
                "operator",
                ProfileNameSource::Flag,
                &fixture.profile,
                &fixture.dir.path().join("profiles"),
                &read_enablement_nonce,
            )
            .unwrap_err()
            .code(),
            "profile.mainnet_enablement_invalid"
        );
        std::fs::write(fixture.path(), rebound).unwrap();
        fixture.sign_rewritten_and_verify(3);
    }
    #[test]
    #[serial]
    fn check_reports_v1_minimum_and_preserves_older_owner_form() {
        use base64::Engine as _;
        let mut fixture = Fixture::new();
        fixture.args.check = true;
        let owner = KeyringEntryRef::default_owner_key("operator");
        let older = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(fixture.owner.verifying_key().to_bytes());
        put(&owner, &older);
        let mut doc = std::fs::read_to_string(fixture.path())
            .unwrap()
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        doc.remove("signature");
        doc.remove("sequence");
        doc["version"] = toml_edit::value(1);
        fixture.sign(&doc.to_string());
        let output = fixture.run().unwrap();
        let items: Vec<_> = output["checks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|check| check["item"].as_str().unwrap().to_owned())
            .collect();
        let mut expected_items: Vec<String> = [
            "chain_id",
            "rpc_url",
            "engine",
            "owner_key",
            "enrolled_signer",
            "key_scope",
            "verified_policy",
            "pin",
            "enablement",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        expected_items.extend(
            mainnet_minimum::REQUIREMENTS
                .iter()
                .map(|r| (*r).to_owned()),
        );
        expected_items.push("oracle_provider_url".to_owned());
        assert_eq!(items, expected_items);
        assert_eq!(output["valid"], false);
        for item in &expected_items {
            let (status, detail) = check_of(&output, item);
            let missing_table = Some("the [mainnet] table is missing".to_owned());
            let expected = match item.as_str() {
                "body_version" => (
                    "failed",
                    Some("version must be 2 with a positive integer sequence".to_owned()),
                ),
                "mainnet_table" | "fee_cap" | "thresholds" | "ttl" => ("failed", missing_table),
                "pin" => ("passed", Some("absent (first use)".to_owned())),
                "enablement" => (
                    "failed",
                    Some(
                        stellar_agent_core::error::ValidationError::MainnetEnablementInvalid {
                            binding: "mainnet_table",
                        }
                        .to_string(),
                    ),
                ),
                _ => ("passed", None),
            };
            assert_eq!(
                (status.as_str(), detail),
                (expected.0, expected.1),
                "{item}"
            );
        }
        assert_eq!(get(&owner), Some(older));
        assert_eq!(get(&fixture.nonce_ref()), None);
        assert!(!fixture.dir.path().join("audit.jsonl").exists());
    }
    #[test]
    #[serial]
    fn check_without_a_verified_policy_evaluates_no_requirement() {
        let mut fixture = Fixture::new();
        let mut doc = std::fs::read_to_string(fixture.path())
            .unwrap()
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        doc.remove("signature");
        std::fs::write(fixture.path(), doc.to_string()).unwrap();
        fixture.args.check = true;
        let output = fixture.run().unwrap();
        assert_eq!(output["valid"], false);
        assert_eq!(
            check_of(&output, "verified_policy"),
            (
                "failed".to_owned(),
                Some(
                    "policy.policy_file_parse_failed: policy file parse failed: policy file has \
                     no `[signature]` table; sign it with `stellar-agent profile sign-policy \
                     --profile operator`"
                        .to_owned()
                )
            )
        );
        assert_eq!(
            check_of(&output, "pin"),
            (
                "not_evaluated".to_owned(),
                Some("the verified load stopped before the pin comparison".to_owned())
            )
        );
        for &item in ["enablement"].iter().chain(mainnet_minimum::REQUIREMENTS) {
            assert_eq!(
                check_of(&output, item),
                (
                    "not_evaluated".to_owned(),
                    Some("the verified policy did not load".to_owned())
                ),
                "{item}"
            );
        }
    }
    #[test]
    #[serial]
    fn check_exits_one_exactly_when_a_check_failed() {
        let mut fixture = Fixture::new();
        let ceremony = fixture.run();
        assert!(ceremony.as_ref().unwrap().get("valid").is_none());
        assert_eq!(exit_code(&ceremony), 0);
        fixture.signed_body(7);
        fixture.args.check = true;
        let passed = fixture.run();
        assert_eq!(passed.as_ref().unwrap()["valid"], true);
        assert_eq!(exit_code(&passed), 0);
        fixture.put_pin(9);
        let failed = fixture.run();
        assert_eq!(failed.as_ref().unwrap()["valid"], false);
        assert_eq!(exit_code(&failed), 1);
        fixture.args.check = false;
        let refused = fixture.run();
        assert_eq!(
            refused.as_ref().unwrap_err().0,
            "profile.enable_mainnet_nonce_exists"
        );
        assert_eq!(exit_code(&refused), 1);
    }
    /// The two ways a profile lacks a usable oracle: no URL, and a URL
    /// without its `providers.oracle` record.
    fn without_oracle(profile: &Profile, gap: MainnetOracleGap) -> Profile {
        let mut profile = profile.clone();
        match gap {
            MainnetOracleGap::UrlMissing => profile.oracle_provider_url = None,
            MainnetOracleGap::RecordMissing => {
                profile.providers.as_mut().unwrap().oracle = None;
            }
            _ => unreachable!(),
        }
        profile
    }
    const GAPS: [MainnetOracleGap; 2] = [
        MainnetOracleGap::UrlMissing,
        MainnetOracleGap::RecordMissing,
    ];

    /// On an enabled installation, `--check` passes the oracle check of a
    /// complete oracle, and reports a missing URL or a missing record as a
    /// failed check with its detail, exits 1, and writes nothing.
    #[test]
    #[serial]
    fn mainnet_oracle_required_check_fails_without_an_oracle() {
        let mut fixture = Fixture::new();
        fixture.run().unwrap();
        fixture.signed_body(7);
        fixture.args.check = true;

        let output = fixture.run().unwrap();
        assert_eq!(output["valid"], true, "{output}");
        assert_eq!(
            check_of(&output, "oracle_provider_url"),
            ("passed".to_owned(), None)
        );

        let complete = fixture.profile.clone();
        for gap in GAPS {
            fixture.profile = without_oracle(&complete, gap);
            let file = std::fs::read(fixture.path()).unwrap();
            let nonce = get(&fixture.nonce_ref());
            let pin = fixture.pin();
            let audit = std::fs::read(fixture.dir.path().join("audit.jsonl")).unwrap();
            let listing = fixture.listing();
            let output = fixture.run();
            assert_eq!(exit_code(&output), 1, "{gap:?}");
            let output = output.unwrap();
            assert_eq!(output["valid"], false, "{gap:?}: {output}");
            assert_eq!(
                check_of(&output, "oracle_provider_url"),
                ("failed".to_owned(), Some(gap.text().to_owned())),
                "{gap:?}"
            );
            let failed: Vec<_> = output["checks"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|check| check["status"] == "failed")
                .map(|check| check["item"].as_str().unwrap().to_owned())
                .collect();
            assert_eq!(failed, ["oracle_provider_url"], "{gap:?}: {output}");
            assert_eq!(std::fs::read(fixture.path()).unwrap(), file, "{gap:?}");
            assert_eq!(get(&fixture.nonce_ref()), nonce, "{gap:?}");
            assert_eq!(fixture.pin(), pin, "{gap:?}");
            assert_eq!(
                std::fs::read(fixture.dir.path().join("audit.jsonl")).unwrap(),
                audit,
                "{gap:?}"
            );
            assert_eq!(fixture.listing(), listing, "{gap:?}");
        }
    }

    /// The ceremony refuses a profile without a usable oracle with
    /// `profile.mainnet_oracle_required`, for the first enablement and for a
    /// rotation, before it reads any keyring entry, and writes no pin, nonce,
    /// policy, audit row, or file. The recording store observes the reads of
    /// the successful rotation that follows once the oracle is restored.
    #[test]
    #[serial]
    fn mainnet_oracle_required_enablement_refuses_without_an_oracle() {
        let reads = Arc::new(Mutex::new(Vec::new()));
        let take = || std::mem::take(&mut *reads.lock().unwrap());
        for gap in GAPS {
            let mut fixture = Fixture::recording(&reads);
            fixture.profile = without_oracle(&fixture.profile, gap);
            let file = std::fs::read(fixture.path()).unwrap();
            let listing = fixture.listing();
            let mut audited = false;
            take();
            let refused = fixture
                .run_with(
                    |_| {
                        audited = true;
                        Ok(())
                    },
                    atomic_write_string,
                )
                .unwrap_err();
            assert_eq!(take(), Vec::<String>::new(), "{gap:?}: keyring reads");
            assert_eq!(
                refused,
                ("profile.mainnet_oracle_required", gap.text().to_owned()),
                "{gap:?}"
            );
            assert!(!audited, "{gap:?}");
            assert_eq!(get(&fixture.nonce_ref()), None, "{gap:?}");
            assert_eq!(fixture.pin(), PinState::Absent, "{gap:?}");
            assert_eq!(std::fs::read(fixture.path()).unwrap(), file, "{gap:?}");
            assert_eq!(fixture.listing(), listing, "{gap:?}");
        }

        // A rotation of an enabled installation whose oracle was removed
        // keeps its nonce, pin, and policy.
        for gap in GAPS {
            let mut fixture = Fixture::recording(&reads);
            fixture.run().unwrap();
            let complete = fixture.profile.clone();
            fixture.profile = without_oracle(&complete, gap);
            fixture.args.rotate = true;
            let file = std::fs::read(fixture.path()).unwrap();
            let nonce = get(&fixture.nonce_ref());
            let pin = fixture.pin();
            let audit = std::fs::read(fixture.dir.path().join("audit.jsonl")).unwrap();
            let listing = fixture.listing();
            take();
            let refused = fixture.run().unwrap_err();
            assert_eq!(take(), Vec::<String>::new(), "{gap:?}: keyring reads");
            assert_eq!(refused.0, "profile.mainnet_oracle_required", "{gap:?}");
            assert_eq!(std::fs::read(fixture.path()).unwrap(), file, "{gap:?}");
            assert_eq!(get(&fixture.nonce_ref()), nonce, "{gap:?}");
            assert_eq!(fixture.pin(), pin, "{gap:?}");
            assert_eq!(
                std::fs::read(fixture.dir.path().join("audit.jsonl")).unwrap(),
                audit,
                "{gap:?}"
            );
            assert_eq!(fixture.listing(), listing, "{gap:?}");
            fixture.profile = complete;
            take();
            fixture.run().unwrap();
            let owner = KeyringEntryRef::default_owner_key("operator");
            assert!(
                take().contains(&format!("{}/{}", owner.service, owner.account)),
                "{gap:?}: the rotation reads the owner key"
            );
            assert_ne!(get(&fixture.nonce_ref()), nonce, "{gap:?}");
        }
    }
    #[test]
    #[serial]
    fn check_reports_a_failed_pin_comparison_on_the_pin() {
        let mut fixture = Fixture::new();
        fixture.run().unwrap();
        fixture.signed_body(7);
        fixture.put_pin(9);
        fixture.args.check = true;
        let output = fixture.run().unwrap();
        assert_eq!(output["valid"], false);
        assert_eq!(
            check_of(&output, "verified_policy"),
            (
                "failed".to_owned(),
                Some("policy.sequence_rollback".to_owned())
            )
        );
        assert_eq!(
            check_of(&output, "pin"),
            (
                "failed".to_owned(),
                Some("policy.sequence_rollback; pinned sequence 9".to_owned())
            )
        );
        assert_eq!(check_of(&output, "fee_cap"), ("passed".to_owned(), None));
    }
    #[test]
    #[serial]
    fn rotate_replaces_only_digest_and_invalidates_old_nonce() {
        let mut fixture = Fixture::new();
        fixture.run().unwrap();
        fixture.signed_body(7);
        let old_nonce = get(&fixture.nonce_ref()).unwrap();
        assert_eq!(
            fixture.run().unwrap_err(),
            (
                "profile.enable_mainnet_nonce_exists",
                "an installation nonce is already stored; rerun with --rotate to replace it and \
                 bind the policy to the new nonce"
                    .to_owned()
            )
        );
        let before = std::fs::read_to_string(fixture.path()).unwrap();
        fixture.args.rotate = true;
        let output = fixture.run().unwrap();
        assert_eq!(output["rotated"], true);
        assert_ne!(get(&fixture.nonce_ref()).unwrap(), old_nonce);
        let mut old = before.parse::<toml_edit::DocumentMut>().unwrap();
        old["mainnet"]["installation_nonce_sha256"] =
            toml_edit::value(output["installation_nonce_sha256"].as_str().unwrap());
        assert_eq!(
            std::fs::read_to_string(fixture.path()).unwrap(),
            old.to_string()
        );
    }
    #[test]
    #[serial]
    fn rotate_binds_in_full_after_a_failed_policy_rewrite() {
        let mut fixture = Fixture::new();
        let before = std::fs::read(fixture.path()).unwrap();
        let nonce_at_audit = RefCell::new(Vec::new());
        let failed = fixture.run_with(
            |entry| {
                nonce_at_audit.borrow_mut().push(get(&fixture.nonce_ref()));
                fixture.append_audit(&entry);
                Ok(())
            },
            |_, _| Err(std::io::Error::other("injected")),
        );
        assert_eq!(
            failed.unwrap_err(),
            (
                "profile.enable_mainnet_precondition",
                "policy rewrite: injected".to_owned()
            )
        );
        let stored = get(&fixture.nonce_ref()).unwrap();
        assert_eq!(std::fs::read(fixture.path()).unwrap(), before);
        assert_eq!(
            fixture.run().unwrap_err().0,
            "profile.enable_mainnet_nonce_exists"
        );
        fixture.args.rotate = true;
        let output = fixture
            .run_with(
                |entry| {
                    nonce_at_audit.borrow_mut().push(get(&fixture.nonce_ref()));
                    fixture.append_audit(&entry);
                    Ok(())
                },
                atomic_write_string,
            )
            .unwrap();
        assert_eq!(output["rotated"], true);
        assert_eq!(
            *nonce_at_audit.borrow(),
            vec![None, Some(stored.clone())],
            "each audit row precedes its nonce write"
        );
        assert_ne!(get(&fixture.nonce_ref()).unwrap(), stored);
        let doc = std::fs::read_to_string(fixture.path())
            .unwrap()
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        assert_eq!(doc["version"].as_integer(), Some(2));
        assert_eq!(doc["mainnet"]["profile"].as_str(), Some("operator"));
        assert_eq!(
            doc["mainnet"]["endpoint_host"].as_str(),
            Some("rpc.example.invalid")
        );
        assert_eq!(
            doc["mainnet"]["installation_nonce_sha256"].as_str(),
            output["installation_nonce_sha256"].as_str()
        );
        let audit = std::fs::read_to_string(fixture.dir.path().join("audit.jsonl")).unwrap();
        let rows: Vec<serde_json::Value> = audit
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        let rotated: Vec<_> = rows.iter().map(|row| row["rotated"].as_bool()).collect();
        assert_eq!(rotated, vec![Some(false), Some(true)], "{audit}");
        fixture.sign_rewritten_and_verify(2);
    }
    #[test]
    #[serial]
    fn audit_failure_leaves_nonce_and_policy_untouched() {
        let fixture = Fixture::new();
        let before = std::fs::read(fixture.path()).unwrap();
        let result = fixture.run_with(
            |_| Err(("audit.injected", "failed".into())),
            atomic_write_string,
        );
        assert_eq!(result.unwrap_err().0, "audit.injected");
        assert!(get(&fixture.nonce_ref()).is_none());
        assert_eq!(std::fs::read(fixture.path()).unwrap(), before);
    }
    #[test]
    #[serial]
    fn nonce_failure_leaves_audit_row_and_unchanged_policy() {
        let fixture = Fixture::new();
        let coordinate = fixture.nonce_ref();
        keyring_mock::install_with_write_error(
            &coordinate.service,
            &coordinate.account,
            None,
            keyring_core::Error::NoEntry,
        )
        .unwrap();
        put(
            &KeyringEntryRef::default_owner_key("operator"),
            &stellar_strkey::ed25519::PublicKey(fixture.owner.verifying_key().to_bytes())
                .to_string(),
        );
        put(
            &signer_identity_entry_ref(&fixture.profile.mcp_signer_default),
            &SignerIdentityRecord::agent([2; 32]).render(),
        );
        let before = std::fs::read(fixture.path()).unwrap();
        assert_eq!(
            fixture.run().unwrap_err(),
            (
                "profile.enable_mainnet_precondition",
                "nonce write failed".to_owned()
            )
        );
        let audit = std::fs::read_to_string(fixture.dir.path().join("audit.jsonl")).unwrap();
        assert!(audit.contains("mainnet_enablement_minted"));
        assert_eq!(std::fs::read(fixture.path()).unwrap(), before);
        assert!(get(&coordinate).is_none());
    }
    /// A process on the headless keyring store is refused with the backend
    /// named, in both modes, and nothing is written.
    #[test]
    #[serial]
    fn a_headless_keyring_backend_refuses_enable_mainnet() {
        for check in [false, true] {
            let mut fixture = Fixture::new();
            fixture.args.check = check;
            let listing = fixture.listing();
            keyring_core::set_default_store(std::sync::Arc::new(
                stellar_agent_headless_keyring::store::HeadlessStore::new(
                    fixture.dir.path().join("headless").join("store.keyring"),
                    stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(
                        std::sync::Arc::new(zeroize::Zeroizing::new([0x42; 32])),
                    ),
                ),
            ));
            let result = fixture.run();
            keyring_mock::install().unwrap();
            let (code, detail) = result.expect_err("a headless backend must refuse");
            assert_eq!(
                code, "network.mainnet_keyring_backend_unsupported",
                "{detail}"
            );
            assert!(detail.contains("headless-env"), "{detail}");
            assert_eq!(fixture.listing(), listing, "the refusal writes nothing");
        }
    }

    #[test]
    #[serial]
    fn ceremony_preconditions_refuse_before_effects() {
        for defect in [
            "flag",
            "chain_id",
            "disk_chain",
            "rpc_url",
            "engine",
            "owner",
            "owner_absent",
            "signer",
            "signer_absent",
            "key_scope",
        ] {
            let mut fixture = Fixture::new();
            match defect {
                "flag" => fixture.args.profile = None,
                "chain_id" => {
                    fixture.profile.chain_id = stellar_agent_core::profile::caip2::Caip2::Testnet
                }
                "disk_chain" => {
                    let mut disk = fixture.profile.clone();
                    disk.chain_id = stellar_agent_core::profile::caip2::Caip2::Testnet;
                    loader::save_to_dir("operator", &disk, &fixture.dir.path().join("profiles"))
                        .unwrap();
                }
                "signer_absent" => {
                    let coord = signer_identity_entry_ref(&fixture.profile.mcp_signer_default);
                    keyring_core::Entry::new(&coord.service, &coord.account)
                        .unwrap()
                        .delete_credential()
                        .unwrap();
                }
                "rpc_url" => fixture.profile.rpc_url = "https://other.example.invalid".into(),
                "engine" => fixture.profile.policy.engine = PolicyEngineKind::Noop,
                "owner" => put(&KeyringEntryRef::default_owner_key("operator"), "malformed"),
                "owner_absent" => {
                    let coord = KeyringEntryRef::default_owner_key("operator");
                    keyring_core::Entry::new(&coord.service, &coord.account)
                        .unwrap()
                        .delete_credential()
                        .unwrap();
                }
                "signer" => put(
                    &signer_identity_entry_ref(&fixture.profile.mcp_signer_default),
                    &SignerIdentityRecord::agent([3; 32]).render(),
                ),
                _ => {
                    fixture.profile.policy_window_state_key_id =
                        KeyringEntryRef::default_policy_window_state_key("other")
                }
            }
            let (code, detail) = fixture.run().unwrap_err();
            let (expected_code, expected_detail) = match defect {
                "flag" => (
                    "profile.enable_mainnet_profile_flag_required",
                    "supply --profile",
                ),
                "chain_id" => ("profile.enable_mainnet_not_mainnet", "chain_id"),
                "disk_chain" => (
                    "profile.enable_mainnet_precondition",
                    "chain_id: on-disk and merged chain_id differ",
                ),
                "rpc_url" => (
                    "profile.enable_mainnet_precondition",
                    "rpc_url: on-disk and merged rpc_url differ",
                ),
                "engine" => (
                    "profile.enable_mainnet_precondition",
                    "engine: engine v1 required",
                ),
                "owner" => (
                    "profile.enable_mainnet_precondition",
                    "owner_key: owner key is not a G-strkey or a 32-byte base64 public key",
                ),
                "owner_absent" => (
                    "profile.enable_mainnet_precondition",
                    "owner_key: owner key not enrolled",
                ),
                "signer" | "signer_absent" => {
                    ("profile.enable_mainnet_precondition", "enrolled_signer: ")
                }
                _ => ("profile.enable_mainnet_precondition", "key_scope: "),
            };
            assert_eq!(code, expected_code, "{defect}");
            if expected_detail.ends_with(": ") {
                assert!(
                    detail.starts_with(expected_detail) && detail.len() > expected_detail.len(),
                    "{defect}: {detail}"
                );
            } else {
                assert_eq!(detail, expected_detail, "{defect}");
            }
            assert!(!fixture.dir.path().join("audit.jsonl").exists(), "{defect}");
            assert!(get(&fixture.nonce_ref()).is_none(), "{defect}");
        }
        let fixture = Fixture::new();
        assert_eq!(
            execute(
                &EnableMainnetArgs {
                    profile: Some("default".into()),
                    check: false,
                    rotate: false
                },
                "default",
                &fixture.profile,
                fixture.dir.path(),
                &fixture.path(),
                &fixture.window,
                |_| Ok(()),
                atomic_write_string,
            )
            .unwrap_err()
            .0,
            "profile.enable_mainnet_default_refused"
        );
    }
    /// An unreadable owner entry is reported as unreadable, never as an
    /// absent enrollment.
    #[test]
    #[serial]
    fn unreadable_owner_key_is_not_reported_as_not_enrolled() {
        let fixture = Fixture::new();
        let coordinate = KeyringEntryRef::default_owner_key("operator");
        keyring_mock::inject_no_logon_session(&coordinate.service, &coordinate.account).unwrap();
        let (code, detail) = fixture.run().unwrap_err();
        assert_eq!(code, "profile.enable_mainnet_precondition");
        assert!(
            detail.starts_with("owner_key: owner key unreadable ("),
            "{detail}"
        );
    }
    #[test]
    fn policy_rewrite_preserves_other_keys_byte_for_byte() {
        let raw = "# header\nversion = 1 # version\nscope = 'profile:operator' # scope\n\n\
            [[rules]] # rule\nmatch = { tool = 'stellar_balances', chain = 'stellar:mainnet' }\n\
            criteria = [] # criteria\ndecision = 'allow' # decision\n";
        let body = raw.parse::<toml_edit::DocumentMut>().unwrap();
        let rewritten = rewrite_policy(
            &body,
            "operator",
            "rpc.example.invalid",
            &"0".repeat(64),
            false,
        )
        .unwrap();
        let unchanged = raw.split_once("scope").unwrap().1;
        assert!(rewritten.contains(&format!("scope{unchanged}")));
    }
}
