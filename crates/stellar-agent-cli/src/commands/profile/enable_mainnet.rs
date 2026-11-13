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
//! `profile.enable_mainnet_nonce_exists`, `profile.spending_preview_unwritable`,
//! and `policy.pin_absent`. The pin
//! step returns its `policy.*` verification error, such as
//! `policy.owner_signature_invalid` or `policy.state_lock_busy`.
//! Strict audit errors retain their own codes.
//! A process on a headless keyring backend is refused with
//! `network.mainnet_keyring_backend_unsupported` in every mode before any keyring read.
//! The ceremony requires a usable oracle before it reads keyring entries.
//! `--state` reads only nonce presence after profile and backend checks.
//! It exits 0 for enabled, 3 for absent, and 1 for unreadable.
//! It exposes no nonce bytes or backend error text.
//! `--check` reports every check as `passed`, `failed`, or `not_evaluated`.
//! It reads the prerequisite state, keyring entries included, and writes no
//! nonce, pin, policy change, or audit row. A missing oracle is a failed
//! check there. Its `spending_summary` states the bounds of the installed signed
//! body, `verified` when the verified load passed and `unavailable`
//! otherwise, and `null` when no signed body was read. `--check` and
//! `--state` write no preview.
//!
//! The ceremony writes the spending preview to stderr as one JSON line
//! before its first write: the bounds of the rebound body with
//! `authority_status = "requires_signature"`. It summarizes the bytes
//! `sign-policy` signs from the written body, with the sequence signing
//! assigns against the pin the ceremony leaves. A preview that cannot be
//! written refuses with `profile.spending_preview_unwritable` and writes
//! nothing. Every later refusal carries the preview at
//! `error.details.preview`, and the result repeats it as `spending_summary`.
//! A full binding writes `classic_max_fee_per_op_stroops = 10000` into
//! `[mainnet]` when the body states no fee cap, and keeps an authored one.

use super::sign_policy::{SequenceRefusal, assign_signing_sequence, atomic_write_string};
use crate::{
    commands::value_audit::emit_value_audit_row_strict,
    common::{
        profile_access::load_profile_reconciled,
        render,
        spending_preview::{SpendingPreview, with_shown_preview},
    },
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
    envelope::{Envelope, OutputFormat},
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
            presets::{AuthorityStatus, PRESET_FEE_PER_OPERATION_STROOPS, summarize},
            verified::{OwnerKeySource, PolicyInspection, PolicyLoad, inspect_verified_policy},
        },
    },
    profile::{
        loader,
        name::ProfileNameSource,
        owner_key::decode_owner_public_key,
        schema::{
            KeyringEntryRef, PolicyEngineKind, Profile, default_policy_dir, default_profile_dir,
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
    /// Inspect installation nonce presence without changing persisted state.
    #[arg(long, conflicts_with_all = ["check", "rotate"])]
    state: bool,
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

/// Parses the policy body the enablement binds.
///
/// A body that is not valid TOML is refused by the position of the failure;
/// the offending line is not repeated.
fn parse_policy_body(raw: &str) -> Result<toml_edit::DocumentMut, Failure> {
    raw.parse::<toml_edit::DocumentMut>().map_err(|e| {
        precondition(format!(
            "policy_file: {}",
            stellar_agent_core::policy::toml_syntax_detail(raw, &e)
        ))
    })
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
    decode_owner_public_key(&raw).map_err(|error| match error {
        stellar_agent_core::profile::owner_key::OwnerKeyDecodeError::OlderForm => {
            "owner key is in the older base64 form; enroll the owner public key again".into()
        }
        _ => "owner key is not a G-strkey".into(),
    })
}

/// Runs the ceremony or its read-only inspection and renders a JSON envelope.
pub(crate) fn run(args: &EnableMainnetArgs) -> i32 {
    run_with_keyring(
        args,
        stellar_agent_network::keyring::init_platform_keyring_store,
    )
}

/// Runs enablement with keyring initialization supplied.
fn run_with_keyring(
    args: &EnableMainnetArgs,
    init_keyring: impl FnOnce() -> Result<(), stellar_agent_core::error::WalletError>,
) -> i32 {
    let mut stderr = std::io::stderr();
    let mut preview = SpendingPreview::new(&mut stderr);
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
        stellar_agent_core::profile::owner_key::refuse_installation_key_coordinate(
            &profile.policy_window_state_key_id,
            "policy_window_state_key_id",
        )
        .map_err(|e| (e.code(), e.to_string()))?;
        init_keyring().map_err(|e| precondition(e.to_string()))?;
        execute(
            args,
            name,
            &profile,
            &profile_dir,
            &policy_path,
            &PersistedWindowStore::for_profile(name),
            |entry| {
                emit_value_audit_row_strict(&profile, name, BindingCheck::Enforce, entry)
                    .map_err(|e| (e.code(), e.to_string()))
            },
            atomic_write_string,
            &mut preview,
        )
    })();
    let status = exit_code(&result);
    match result {
        Ok(data) => render::render_json(&Envelope::ok(data)),
        Err((code, detail)) => {
            render::render_json(&failure_envelope(code, detail, preview.shown()));
        }
    }
    status
}

/// The envelope of a refusal, with the spending preview at
/// `error.details.preview` once one was shown.
fn failure_envelope(
    code: &str,
    detail: String,
    preview: Option<&serde_json::Value>,
) -> Envelope<()> {
    with_shown_preview(Envelope::<()>::err_raw(code, detail), preview)
}

/// 1 for a refusal, a failed check, or an unreadable nonce; 3 for an absent nonce; 0 otherwise.
fn exit_code(result: &Result<serde_json::Value, Failure>) -> i32 {
    match result {
        Ok(data) if data.get("state").is_some() => match data["state"].as_str() {
            Some("enabled") => 0,
            Some("absent") => 3,
            _ => 1,
        },
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
    reason = "the command binds disk paths, an injectable strict audit emitter, an \
              injectable policy writer, and the spending preview it shows before its first \
              write"
)]
pub(super) fn execute(
    args: &EnableMainnetArgs,
    name: &str,
    profile: &Profile,
    profile_dir: &Path,
    policy_path: &Path,
    window: &PersistedWindowStore,
    emit: impl FnOnce(AuditEntry) -> Result<(), Failure>,
    write_policy: impl FnOnce(&Path, &str) -> std::io::Result<()>,
    preview: &mut SpendingPreview<'_>,
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
    if args.state {
        let coordinate = mainnet_enablement_entry_ref(&profile.policy_window_state_key_id);
        let (state, code) = match has_enablement_nonce(profile) {
            Ok(true) => ("enabled", None),
            Ok(false) => ("absent", None),
            Err(_) => ("unreadable", Some("profile.mainnet_enablement_invalid")),
        };
        let mut data = serde_json::json!({
            "profile": name,
            "state": state,
            "nonce_entry": {"service": coordinate.service, "account": coordinate.account},
        });
        if let Some(code) = code {
            data["code"] = code.into();
        }
        return Ok(data);
    }
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
            let owner = owner.as_ref().map_err(Clone::clone)?;
            enrolled_signer(name, profile_dir, profile, EnrolledRole::Agent, &key, owner)
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
        let inspection = window
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
                        window_path: window.path(),
                    },
                    state,
                )
            });
        // The installed body's bounds, labeled by the outcome of its
        // verified load; `null` when no signed body was read.
        let spending_summary = inspection.as_ref().ok().and_then(|inspection| {
            inspection.document.as_ref().map(|document| {
                let status = if inspection.verified.is_ok() {
                    AuthorityStatus::Verified
                } else {
                    AuthorityStatus::Unavailable
                };
                summarize(document, &profile.network_passphrase, status)
            })
        });
        checks.extend(inspection_checks(&inspection, name, profile, profile_dir));
        checks.push(oracle_check(profile));
        let valid = checks.iter().all(|c| c.status != Status::Failed);
        return Ok(serde_json::json!({
            "profile": name,
            "valid": valid,
            "checks": checks,
            "spending_summary": spending_summary,
        }));
    }
    if let Some(failed) = checks.iter().find(|check| check.status == Status::Failed) {
        return Err(precondition(format!(
            "{}: {}",
            failed.item,
            failed.detail.as_deref().unwrap_or("failed")
        )));
    }
    // The signed body the installation holds, read as the check branch reads
    // it; the preview summarizes the bound body only when one was read.
    let installed = {
        let state = PolicyStateStore::new();
        match (window.load_into(name, profile, &state), owner.as_ref()) {
            (Ok(()), Ok(owner)) => {
                inspect_verified_policy(
                    &PolicyLoad {
                        path: policy_path,
                        profile,
                        profile_name: name,
                        owner_pubkey: owner,
                        owner_source: OwnerKeySource::Keyring,
                        window_path: window.path(),
                    },
                    state,
                )
                .document
            }
            _ => None,
        }
    };
    let raw = std::fs::read_to_string(policy_path)
        .map_err(|e| precondition(format!("policy_file: {e}")))?;
    let body = parse_policy_body(&raw)?;
    let coordinate = mainnet_enablement_entry_ref(&profile.policy_window_state_key_id);
    let entry = keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .map_err(|_| precondition("nonce"))?;
    let exists = has_enablement_nonce(profile).map_err(|_| precondition("nonce unreadable"))?;
    if exists {
        refuse_absent_pin(name, profile, window.path(), &coordinate)?;
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
    // The bounds of the bytes the owner signs next, before the first write:
    // the rebound body with the sequence signing assigns it.
    let spending_summary = match installed {
        Some(_) => {
            let pin = signing_pin(name, profile, window.path(), &body)?;
            Some(summarize(
                &parse_policy_body(&signing_body(&rewritten, pin)?)?,
                &profile.network_passphrase,
                AuthorityStatus::RequiresSignature,
            ))
        }
        None => None,
    };
    preview.show(spending_summary.as_ref(), None, OutputFormat::Json)?;
    ensure_policy_pin(name, profile, policy_path, window.path(), &body)?;
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
        "Review [mainnet].classic_max_fee_per_op_stroops (10000 when absent), and set optional \
         authorization_ttl_seconds and cross_check_thresholds."
            .to_owned(),
        format!(
            "Enroll an approval credential with stellar-agent approve credential enroll \
             --profile {name} and add its entry to [mainnet].approval_credentials."
        ),
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
        "spending_summary": spending_summary,
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
    let state =
        read_pin_without_creating(window_path, profile).map_err(|e| pin_read_failure(name, e))?;
    if let PinState::Present(_) = state {
        return Ok(());
    }
    let pin_entry = pin::entry_present(&profile.policy_window_state_key_id)
        .map_err(|e| pin_read_failure(name, PolicyError::from(e)))?;
    if pin_entry {
        return Err((
            PolicyError::PinAbsent.wire_code(),
            missing_pin_lock_detail(name),
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

/// The cause and recovery when a pin entry exists without its lock file.
fn missing_pin_lock_detail(name: &str) -> String {
    format!(
        "the policy-state lock file of profile '{name}' is missing, so its policy pin \
         cannot be read; a command that builds the V1 policy engine recreates the lock \
         file, and this command can run after it; nothing was written"
    )
}

/// The refusal of a pin read before the first write. An unusable pin names
/// the profile, that nothing was written, and the recovery. A malformed pin
/// has no repair command, because a replacement could lower the recorded
/// sequence the replay protection keeps. Every other failure keeps its own
/// message.
fn pin_read_failure(name: &str, error: PolicyError) -> Failure {
    let code = error.wire_code();
    match error {
        PolicyError::PinUnusable { detail } => (
            code,
            format!(
                "the policy pin of profile '{name}' cannot be used ({detail}); nothing was \
                 written. Rerun this command once the keyring is reachable if it was \
                 unavailable. No command repairs a malformed pin in this release, since a \
                 replacement could lower its recorded sequence; create a profile under a new \
                 name."
            ),
        ),
        other => (code, other.to_string()),
    }
}

/// The pinned sequence `sign-policy` reads after this ceremony: the
/// existing pin, which [`ensure_policy_pin`] preserves, or else the sequence
/// of the signed `body` it pins.
fn signing_pin(
    name: &str,
    profile: &Profile,
    window_path: &Path,
    body: &toml_edit::DocumentMut,
) -> Result<Option<i64>, Failure> {
    use stellar_agent_core::policy::v1::verified::read_pin_without_creating;
    match read_pin_without_creating(window_path, profile).map_err(|e| pin_read_failure(name, e))? {
        PinState::Present(pin) => Ok(Some(pin.sequence())),
        PinState::Absent => Ok(body.get("sequence").and_then(toml_edit::Item::as_integer)),
    }
}

/// The bytes `sign-policy` signs from the rebound body `rewritten` when the
/// installation pins `pin`: the body with the sequence signing assigns.
fn signing_body(rewritten: &str, pin: Option<i64>) -> Result<String, Failure> {
    let mut body = parse_policy_body(rewritten)?;
    match assign_signing_sequence(&mut body, pin) {
        Ok(Some(_)) => Ok(body.to_string()),
        Ok(None) => Ok(rewritten.to_owned()),
        Err(SequenceRefusal::Invalid) => Err(precondition(
            "policy_file: the sequence must be in 1..=i64::MAX",
        )),
        Err(SequenceRefusal::Exhausted) => Err(precondition(
            "policy_file: the sequence cannot advance past i64::MAX",
        )),
    }
}

/// Preserves an existing pin or pins a signed v2 body before storing a nonce.
/// The caller refuses installations with a nonce and no pin.
/// Provisioning verification repeats that refusal under the lock.
fn ensure_policy_pin(
    name: &str,
    profile: &Profile,
    policy_path: &Path,
    window_path: &Path,
    body: &toml_edit::DocumentMut,
) -> Result<(), Failure> {
    use stellar_agent_core::policy::v1::verified::{
        pin_provisioning_policy, read_pin_without_creating,
    };
    let error = |e: PolicyError| (e.wire_code(), e.to_string());
    if let PinState::Present(_) =
        read_pin_without_creating(window_path, profile).map_err(|e| pin_read_failure(name, e))?
    {
        return Ok(());
    }
    if let Some(parent) = window_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| precondition(format!("policy state directory: {e}")))?;
    }
    let owner = read_owner_key(&KeyringEntryRef::default_owner_key(name)).map_err(precondition)?;
    if body.get("version").and_then(toml_edit::Item::as_integer) != Some(2) {
        stellar_agent_core::policy::v1::loader::load_signed_policy_text(
            &body.to_string(),
            name,
            &owner,
            &profile.network_passphrase,
        )
        .map_err(error)?;
        return Err(precondition("sign a v2 policy before enabling mainnet"));
    }
    pin_provisioning_policy(
        &PolicyLoad {
            path: policy_path,
            profile,
            profile_name: name,
            owner_pubkey: &owner,
            owner_source: OwnerKeySource::Keyring,
            window_path,
        },
        body,
    )
    .map_err(error)
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
        (Some(PinState::Absent), failure) => {
            match stellar_agent_core::policy::pin::entry_present(
                &profile.policy_window_state_key_id,
            ) {
                Ok(true) => check(
                    "pin",
                    Status::Failed,
                    Some(format!(
                        "{}: {}",
                        PolicyError::PinAbsent.wire_code(),
                        missing_pin_lock_detail(name)
                    )),
                ),
                Ok(false) => match failure {
                    Some(failure) => check("pin", Status::Failed, Some(failure)),
                    None => check("pin", Status::Passed, Some("absent (first use)".into())),
                },
                Err(error) => check(
                    "pin",
                    Status::Failed,
                    Some(policy_failure(&PolicyError::from(error))),
                ),
            }
        }
        (None, Some(failure)) => check("pin", Status::Failed, Some(failure)),
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
    // The parsed credential requirement also fails when an empty list has
    // no canonical form, so this row stays actionable without a document.
    if let Ok(PolicyInspection {
        verified:
            Err(
                error @ PolicyError::MainnetMinimumUnmet {
                    requirement: "approval_credentials",
                    ..
                },
            ),
        ..
    }) = inspection
        && let Some(row) = checks
            .iter_mut()
            .find(|row| row.item == "approval_credentials")
    {
        *row = check(
            "approval_credentials",
            Status::Failed,
            Some(policy_failure(error)),
        );
    }
    checks
}

/// Writes the installation binding into the policy body.
///
/// A first ceremony, and a rotation of a body without a `[mainnet]` table,
/// bind in full: version 2, the profile, the endpoint host, and the nonce
/// digest. A full binding also writes the preset fee cap,
/// `classic_max_fee_per_op_stroops = 10000`, when the body states none, and
/// keeps an authored cap. A rotation of a bound body replaces only the nonce
/// digest.
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
        if !table.contains_key("classic_max_fee_per_op_stroops") {
            let fee = i64::try_from(PRESET_FEE_PER_OPERATION_STROOPS)
                .map_err(|_| precondition("classic_max_fee_per_op_stroops"))?;
            table.insert("classic_max_fee_per_op_stroops", toml_edit::value(fee));
        }
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

    /// A policy body whose malformed line holds a credential is refused by the
    /// position of the failure; the line is not repeated.
    #[test]
    fn a_malformed_policy_line_is_reported_by_position_only() {
        use stellar_agent_test_support::rejected_value::{
            CREDENTIAL_MARKER, assert_no_marker_in_text,
        };
        let body =
            format!("version = 2\nscope = \"profile:x\"\nsecret = {CREDENTIAL_MARKER} here\n");
        let (code, detail) = parse_policy_body(&body).unwrap_err();
        assert_eq!(code, "profile.enable_mainnet_precondition");
        assert!(
            detail.starts_with("policy_file: not valid TOML: line 3, column "),
            "{detail}"
        );
        assert_no_marker_in_text(&detail, CREDENTIAL_MARKER);
        assert!(parse_policy_body(FULL).is_ok());
    }

    struct Fixture {
        dir: tempfile::TempDir,
        profile: Profile,
        args: EnableMainnetArgs,
        owner: SigningKey,
        window: std::path::PathBuf,
        /// What the ceremony wrote as its spending preview.
        preview: RefCell<Vec<u8>>,
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
                &SignerIdentityRecord::signed_for_test([2; 32], "operator", &profile, &owner)
                    .render()
                    .unwrap(),
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
                    state: false,
                    rotate: false,
                },
                owner,
                window,
                preview: RefCell::new(Vec::new()),
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
            let mut buffer = self.preview.borrow_mut();
            self.execute_into(&mut *buffer, emit, write_policy)
        }
        /// Runs the ceremony with its preview written to `out`.
        fn run_into(&self, out: &mut dyn std::io::Write) -> Result<serde_json::Value, Failure> {
            self.execute_into(
                out,
                |entry| {
                    self.append_audit(&entry);
                    Ok(())
                },
                atomic_write_string,
            )
        }
        fn execute_into(
            &self,
            out: &mut dyn std::io::Write,
            emit: impl FnOnce(AuditEntry) -> Result<(), Failure>,
            write_policy: impl FnOnce(&Path, &str) -> std::io::Result<()>,
        ) -> Result<serde_json::Value, Failure> {
            execute(
                &self.args,
                "operator",
                &self.profile,
                &self.dir.path().join("profiles"),
                &self.path(),
                &PersistedWindowStore::at_path(self.window.clone()),
                emit,
                write_policy,
                &mut SpendingPreview::new(out),
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
        /// The rewritten policy completed with a fee cap, `sequence` and
        /// `credentials` approval credential entries, unsigned.
        fn rewritten_body(&self, sequence: i64, credentials: usize) -> String {
            let raw = std::fs::read_to_string(self.path()).unwrap();
            let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
            doc.remove("signature");
            doc["mainnet"]["classic_max_fee_per_op_stroops"] = toml_edit::value(500);
            doc["sequence"] = toml_edit::value(sequence);
            let authenticator = stellar_agent_test_support::webauthn::fixture_authenticator();
            let mut list = toml_edit::Array::new();
            for _ in 0..credentials {
                let mut credential = toml_edit::InlineTable::new();
                credential.insert(
                    "credential_id_b64url",
                    authenticator.credential_id_b64url().into(),
                );
                credential.insert(
                    "public_key_sec1_b64url",
                    authenticator.public_key_sec1_b64url().into(),
                );
                list.push(credential);
            }
            doc["mainnet"]["approval_credentials"] = toml_edit::value(list);
            doc.to_string()
        }
        /// Completes the rewritten policy with a fee cap, `sequence` and the
        /// fixture approval credential, signs it, and loads it with
        /// installation verification.
        fn sign_rewritten_and_verify(&self, sequence: i64) -> VerifiedPolicy {
            let body = self.rewritten_body(sequence, 1);
            stellar_agent_core::policy::v1::validate_unsigned_policy(
                &body,
                "operator",
                &self.profile.network_passphrase,
            )
            .unwrap();
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
            pin::write_for_test(
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
            "approval_credentials",
            "stellar-agent approve credential enroll --profile operator",
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
    fn enablement_refuses_a_transplanted_signer() {
        let mut f = Fixture::new();
        let original = f.profile.clone();
        f.profile.mcp_signer_default.service = KeyringEntryRef::default_signer("v").service;
        let profiles = f.dir.path().join("profiles");
        loader::save_to_dir("v", &original, &profiles).unwrap();
        std::fs::rename(
            profiles.join("v.toml"),
            f.dir.path().join("removed-profile"),
        )
        .unwrap();
        loader::save_to_dir("operator", &f.profile, &profiles).unwrap();
        put(
            &signer_identity_entry_ref(&f.profile.mcp_signer_default),
            &SignerIdentityRecord::signed_for_test([2; 32], "v", &f.profile, &f.owner)
                .render()
                .unwrap(),
        );
        assert!(
            stellar_agent_core::profile::key_scope::key_scope_findings_in_dir(
                &f.profile, "operator", &profiles
            )
            .is_empty()
        );
        f.args.check = true;
        let result = f.run().unwrap();
        let (status, detail) = check_of(&result, "enrolled_signer");
        assert_eq!(status, "failed");
        assert!(detail.unwrap().contains("bound_elsewhere"));
        assert_eq!(check_of(&result, "key_scope").0, "passed");
    }

    #[test]
    #[serial]
    fn an_unbound_signer_names_the_bind_signer_remedy() {
        let mut f = Fixture::new();
        put(
            &signer_identity_entry_ref(&f.profile.mcp_signer_default),
            &SignerIdentityRecord::agent([2; 32], "operator", f.profile.chain_id)
                .render()
                .unwrap(),
        );
        f.args.check = true;
        let result = f.run().unwrap();
        let (status, detail) = check_of(&result, "enrolled_signer");
        assert_eq!(status, "failed");
        let detail = detail.unwrap();
        assert!(detail.contains("(unbound)"), "{detail}");
        assert!(
            detail.contains(
                "stellar-agent profile bind-signer --profile operator --owner-secret-env <VAR>"
            ),
            "{detail}"
        );
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
    fn check_reports_a_missing_lock_for_a_present_pin_with_or_without_a_nonce() {
        use stellar_agent_core::policy::state_lock::window_lock_path;
        for nonce_present in [true, false] {
            let mut fixture = Fixture::new();
            fixture.run().unwrap();
            fixture.sign_rewritten_and_verify(2);
            let pin = stellar_agent_core::profile::schema::policy_pin_entry_ref(
                &fixture.profile.policy_window_state_key_id,
            );
            let stored_pin = get(&pin).unwrap();
            std::fs::remove_file(window_lock_path(
                &fixture.window,
                &fixture.profile.policy_window_state_key_id,
            ))
            .unwrap();
            let (code, remedy) = refuse_absent_pin(
                "operator",
                &fixture.profile,
                &fixture.window,
                &fixture.nonce_ref(),
            )
            .unwrap_err();
            if !nonce_present {
                let nonce = fixture.nonce_ref();
                keyring_core::Entry::new(&nonce.service, &nonce.account)
                    .unwrap()
                    .delete_credential()
                    .unwrap();
            }
            let nonce = get(&fixture.nonce_ref());
            let policy = std::fs::read(fixture.path()).unwrap();
            let audit = std::fs::read(fixture.dir.path().join("audit.jsonl")).unwrap();
            let listing = fixture.listing();
            fixture.args.check = true;
            let output = fixture.run().unwrap();
            assert_eq!(output["valid"], false);
            let (status, detail) = check_of(&output, "pin");
            assert_eq!(status, "failed", "nonce present: {nonce_present}");
            let detail = detail.unwrap();
            assert_eq!(detail, format!("{code}: {remedy}"));
            assert!(detail.contains("policy-state lock file of profile 'operator' is missing"));
            assert!(!detail.contains("remove"));
            assert!(!detail.contains("nonce"));
            assert_ne!(detail, "absent (first use)");
            assert_eq!(get(&fixture.nonce_ref()), nonce);
            assert_eq!(get(&pin), Some(stored_pin));
            assert_eq!(std::fs::read(fixture.path()).unwrap(), policy);
            assert_eq!(
                std::fs::read(fixture.dir.path().join("audit.jsonl")).unwrap(),
                audit
            );
            assert_eq!(fixture.listing(), listing);
        }
    }

    #[test]
    #[serial]
    fn check_reports_an_unreadable_pin_when_its_lock_is_missing() {
        use stellar_agent_core::policy::state_lock::window_lock_path;
        for nonce_present in [true, false] {
            let mut fixture = Fixture::new();
            fixture.run().unwrap();
            fixture.sign_rewritten_and_verify(2);
            std::fs::remove_file(window_lock_path(
                &fixture.window,
                &fixture.profile.policy_window_state_key_id,
            ))
            .unwrap();
            if !nonce_present {
                let nonce = fixture.nonce_ref();
                keyring_core::Entry::new(&nonce.service, &nonce.account)
                    .unwrap()
                    .delete_credential()
                    .unwrap();
            }
            let pin = stellar_agent_core::profile::schema::policy_pin_entry_ref(
                &fixture.profile.policy_window_state_key_id,
            );
            keyring_mock::inject_error(
                &pin.service,
                &pin.account,
                keyring_core::Error::BadStoreFormat("injected read failure".into()),
            )
            .unwrap();
            fixture.args.check = true;
            let output = fixture.run().unwrap();
            assert_eq!(output["valid"], false);
            let (status, detail) = check_of(&output, "pin");
            assert_eq!(status, "failed", "nonce present: {nonce_present}");
            let detail = detail.unwrap();
            assert!(detail.starts_with("policy.pin_unusable:"), "{detail}");
            assert!(!detail.contains("absent (first use)"));
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
                std::fs::remove_file(window_lock_path(
                    &fixture.window,
                    &fixture.profile.policy_window_state_key_id,
                ))
                .unwrap();
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
    /// A malformed pin refuses both forms of the ceremony, with and without
    /// a nonce, with `policy.pin_unusable`. The message names the profile,
    /// that nothing was written, and the recovery. The ceremony writes no
    /// nonce, pin, audit row, policy, or file.
    #[test]
    #[serial]
    fn an_unusable_pin_refuses_with_its_recovery_and_writes_nothing() {
        for nonce_present in [true, false] {
            let mut fixture = Fixture::new();
            fixture.run().unwrap();
            fixture.sign_rewritten_and_verify(2);
            let pin = stellar_agent_core::profile::schema::policy_pin_entry_ref(
                &fixture.profile.policy_window_state_key_id,
            );
            put(&pin, "not a pin");
            if !nonce_present {
                let nonce = fixture.nonce_ref();
                keyring_core::Entry::new(&nonce.service, &nonce.account)
                    .unwrap()
                    .delete_credential()
                    .unwrap();
            }
            let nonce = get(&fixture.nonce_ref());
            let policy = std::fs::read(fixture.path()).unwrap();
            let audit = std::fs::read(fixture.dir.path().join("audit.jsonl")).unwrap();
            let listing = fixture.listing();
            for rotate in [false, true] {
                fixture.args.rotate = rotate;
                let case = format!("nonce {nonce_present}, rotate {rotate}");
                let (code, detail) = fixture.run().unwrap_err();
                assert_eq!(code, "policy.pin_unusable", "{case}: {detail}");
                assert!(
                    detail.starts_with("the policy pin of profile 'operator' cannot be used ("),
                    "{case}: {detail}"
                );
                assert!(
                    detail.contains("); nothing was written. "),
                    "{case}: {detail}"
                );
                assert!(
                    detail.ends_with(
                        "No command repairs a malformed pin in this release, since a \
                         replacement could lower its recorded sequence; create a profile \
                         under a new name."
                    ),
                    "{case}: {detail}"
                );
                assert_eq!(get(&pin).as_deref(), Some("not a pin"), "{case}");
                assert_eq!(get(&fixture.nonce_ref()), nonce, "{case}");
                assert_eq!(std::fs::read(fixture.path()).unwrap(), policy, "{case}");
                assert_eq!(
                    std::fs::read(fixture.dir.path().join("audit.jsonl")).unwrap(),
                    audit,
                    "{case}"
                );
                assert_eq!(fixture.listing(), listing, "{case}");
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
        std::fs::remove_file(window_lock_path(
            &fixture.window,
            &fixture.profile.policy_window_state_key_id,
        ))
        .unwrap();
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
        assert!(
            window_lock_path(&fixture.window, &fixture.profile.policy_window_state_key_id,)
                .exists()
        );
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
    fn check_reports_an_older_form_owner_entry_as_failed() {
        use base64::Engine as _;
        let mut fixture = Fixture::new();
        fixture.args.check = true;
        let owner = KeyringEntryRef::default_owner_key("operator");
        let older = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(fixture.owner.verifying_key().to_bytes());
        put(&owner, &older);
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
            let expected = match item.as_str() {
                "owner_key" | "verified_policy" | "enrolled_signer" => (
                    "failed",
                    Some(
                        "owner key is in the older base64 form; enroll the owner public key again"
                            .to_owned(),
                    ),
                ),
                "pin" => (
                    "not_evaluated",
                    Some("the verified load stopped before the pin comparison".to_owned()),
                ),
                "enablement" => (
                    "not_evaluated",
                    Some("the verified policy did not load".to_owned()),
                ),
                item if mainnet_minimum::REQUIREMENTS.contains(&item) => (
                    "not_evaluated",
                    Some("the verified policy did not load".to_owned()),
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
    /// A first enablement from a v2 policy without `[mainnet]` still pins
    /// and enables. The check then names `approval_credentials` when the
    /// owner signed the bound body without one or with an empty list, and
    /// passes it once the body lists a credential.
    #[test]
    #[serial]
    fn enablement_check_reports_approval_credentials() {
        let mut fixture = Fixture::new();
        fixture.run().unwrap();
        assert!(get(&fixture.nonce_ref()).is_some());
        assert!(matches!(fixture.pin(), PinState::Present(_)));
        let bound = std::fs::read_to_string(fixture.path()).unwrap();
        fixture.args.check = true;
        // The owner signs the body without the array; the empty array has
        // no canonical form, so it is added to the signed file afterwards.
        for empty in [false, true] {
            std::fs::write(fixture.path(), &bound).unwrap();
            let mut doc = fixture
                .rewritten_body(2, 0)
                .parse::<toml_edit::DocumentMut>()
                .unwrap();
            doc["mainnet"]
                .as_table_like_mut()
                .unwrap()
                .remove("approval_credentials");
            fixture.sign(&doc.to_string());
            if empty {
                let signed = std::fs::read_to_string(fixture.path()).unwrap();
                let mut signed = signed.parse::<toml_edit::DocumentMut>().unwrap();
                signed["mainnet"]["approval_credentials"] =
                    toml_edit::value(toml_edit::Array::new());
                std::fs::write(fixture.path(), signed.to_string()).unwrap();
            }
            let output = fixture.run().unwrap();
            assert_eq!(output["valid"], false, "{empty}");
            assert_eq!(
                check_of(&output, "approval_credentials"),
                (
                    "failed".to_owned(),
                    Some(
                        "policy.mainnet_minimum_unmet: requirement=approval_credentials, rule=None"
                            .to_owned()
                    )
                ),
                "{empty}"
            );
            let (status, detail) = check_of(&output, "verified_policy");
            assert_eq!(status, "failed", "{empty}");
            assert!(
                detail
                    .as_deref()
                    .unwrap()
                    .contains("requirement=approval_credentials"),
                "{empty}: {detail:?}"
            );
        }
        std::fs::write(fixture.path(), &bound).unwrap();
        fixture.sign(&fixture.rewritten_body(2, 1));
        let output = fixture.run().unwrap();
        assert_eq!(
            check_of(&output, "approval_credentials"),
            ("passed".to_owned(), None)
        );
        assert_eq!(
            check_of(&output, "verified_policy"),
            ("passed".to_owned(), None)
        );
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
            &SignerIdentityRecord::signed_for_test(
                [2; 32],
                "operator",
                &fixture.profile,
                &fixture.owner,
            )
            .render()
            .unwrap(),
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
                    &SignerIdentityRecord::signed_for_test(
                        [3; 32],
                        "operator",
                        &fixture.profile,
                        &fixture.owner,
                    )
                    .render()
                    .unwrap(),
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
                    "owner_key: owner key is not a G-strkey",
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
                    state: false,
                    rotate: false
                },
                "default",
                &fixture.profile,
                fixture.dir.path(),
                &fixture.path(),
                &PersistedWindowStore::at_path(fixture.window.clone()),
                |_| Ok(()),
                atomic_write_string,
                &mut SpendingPreview::new(&mut std::io::sink()),
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

    /// Enablement refuses a reserved window-key service before opening keys.
    #[test]
    #[serial_test::serial]
    fn installation_coordinate_refuses_without_writing() {
        use crate::common::installation_key_fixture::InstallationKeyFixture;
        let fixture = InstallationKeyFixture::new("stellar-agent-toolsets");
        let name = "pin-coordinate-refusal";
        let mut profile = Profile::builder_testnet_named(name, "s", "a", "n", "a").build();
        profile.policy_window_state_key_id = fixture.coordinate.clone();
        loader::save_to_dir(name, &profile, &fixture.home().join("profiles")).unwrap();
        let args = EnableMainnetArgs {
            profile: Some(name.to_owned()),
            check: false,
            state: false,
            rotate: true,
        };
        fixture.assert_rendered_refusal(run_with_keyring(&args, || fixture.init()));
    }

    #[test]
    #[serial]
    fn check_output_unchanged() {
        let mut fixture = Fixture::new();
        fixture.run().unwrap();
        fixture.signed_body(7);
        fixture.args.check = true;
        let expected = [
            r#"{"ok":true,"data":{"checks":[{"item":"chain_id","status":"passed"},{"item":"rpc_url","status":"passed"},{"item":"engine","status":"passed"},{"item":"owner_key","status":"passed"},{"item":"enrolled_signer","status":"passed"},{"item":"key_scope","status":"passed"},{"item":"verified_policy","status":"passed"},{"detail":"sequence 1","item":"pin","status":"passed"},{"item":"enablement","status":"passed"},{"item":"body_version","status":"passed"},{"item":"mainnet_table","status":"passed"},{"item":"rules_empty","status":"passed"},{"item":"scope","status":"passed"},{"item":"chain","status":"passed"},{"item":"tool","status":"passed"},{"item":"opaque","status":"passed"},{"item":"rule_ttl","status":"passed"},{"item":"asset_allowlist","status":"passed"},{"item":"destination","status":"passed"},{"item":"home_domain","status":"passed"},{"item":"per_tx_cap","status":"passed"},{"item":"per_period_cap","status":"passed"},{"item":"rate_limit","status":"passed"},{"item":"fee_cap","status":"passed"},{"item":"thresholds","status":"passed"},{"item":"ttl","status":"passed"},{"item":"approval_credentials","status":"passed"},{"item":"approval.cert_pin_without_origin","status":"passed"},{"item":"approval.origin_without_cert_pin","status":"passed"},{"item":"oracle_provider_url","status":"passed"}],"profile":"operator","valid":true},"request_id":"fixed-id"}"#,
            r#"{"ok":true,"data":{"checks":[{"item":"chain_id","status":"passed"},{"item":"rpc_url","status":"passed"},{"item":"engine","status":"passed"},{"item":"owner_key","status":"passed"},{"item":"enrolled_signer","status":"passed"},{"item":"key_scope","status":"passed"},{"detail":"policy.sequence_rollback","item":"verified_policy","status":"failed"},{"detail":"policy.sequence_rollback; pinned sequence 9","item":"pin","status":"failed"},{"detail":"the verified policy did not load","item":"enablement","status":"not_evaluated"},{"item":"body_version","status":"passed"},{"item":"mainnet_table","status":"passed"},{"item":"rules_empty","status":"passed"},{"item":"scope","status":"passed"},{"item":"chain","status":"passed"},{"item":"tool","status":"passed"},{"item":"opaque","status":"passed"},{"item":"rule_ttl","status":"passed"},{"item":"asset_allowlist","status":"passed"},{"item":"destination","status":"passed"},{"item":"home_domain","status":"passed"},{"item":"per_tx_cap","status":"passed"},{"item":"per_period_cap","status":"passed"},{"item":"rate_limit","status":"passed"},{"item":"fee_cap","status":"passed"},{"item":"thresholds","status":"passed"},{"item":"ttl","status":"passed"},{"item":"approval_credentials","status":"passed"},{"item":"approval.cert_pin_without_origin","status":"passed"},{"item":"approval.origin_without_cert_pin","status":"passed"},{"item":"oracle_provider_url","status":"passed"}],"profile":"operator","valid":false},"request_id":"fixed-id"}"#,
        ];
        for (failed, expected) in [false, true].into_iter().zip(expected) {
            if failed {
                fixture.put_pin(9);
            }
            let before = persisted(&fixture);
            let pin = fixture.pin();
            let nonce = get(&fixture.nonce_ref());
            let result = fixture.run();
            assert_eq!(exit_code(&result), i32::from(failed));
            let mut data = result.unwrap();
            let summary = data
                .as_object_mut()
                .unwrap()
                .remove("spending_summary")
                .unwrap();
            assert_eq!(
                summary["authority_status"],
                if failed { "unavailable" } else { "verified" }
            );
            let envelope = Envelope::ok_with_request_id(data, "fixed-id".into());
            let mut bytes = Vec::new();
            render::render_json_to(&mut bytes, &envelope).unwrap();
            assert_eq!(bytes, format!("{expected}\n").as_bytes());
            assert_eq!(persisted(&fixture), before);
            assert_eq!(fixture.pin(), pin);
            assert_eq!(get(&fixture.nonce_ref()), nonce);
        }
    }
    /// `--check` summarizes the installed signed body and writes nothing:
    /// no preview, nonce, pin, policy change, or audit row; `--state`
    /// writes no preview either.
    #[test]
    #[serial]
    fn enable_check_summarizes_without_writes() {
        let mut fixture = Fixture::new();
        fixture.run().unwrap();
        fixture.signed_body(7);
        fixture.preview.borrow_mut().clear();
        fixture.args.check = true;
        let before = persisted(&fixture);
        let pin = fixture.pin();
        let nonce = get(&fixture.nonce_ref());
        let output = fixture.run().unwrap();
        let summary = &output["spending_summary"];
        assert_eq!(summary["authority_status"], "verified");
        assert_eq!(summary["sequence"], 7);
        assert_eq!(summary["fee_cap_status"], "signed");
        assert!(fixture.preview.borrow().is_empty());
        assert_eq!(persisted(&fixture), before);
        assert_eq!(fixture.pin(), pin);
        assert_eq!(get(&fixture.nonce_ref()), nonce);

        fixture.args.check = false;
        fixture.args.state = true;
        assert_eq!(fixture.run().unwrap()["state"], "enabled");
        assert!(fixture.preview.borrow().is_empty());
        assert_eq!(persisted(&fixture), before);
    }

    /// A body whose verified load fails is summarized as `unavailable`, and
    /// a file that yields no signed body as `null`.
    #[test]
    #[serial]
    fn enable_unverified_never_labeled_verified() {
        let mut fixture = Fixture::new();
        fixture.run().unwrap();
        fixture.signed_body(7);
        fixture.args.check = true;
        fixture.put_pin(9);
        let output = fixture.run().unwrap();
        assert_eq!(check_of(&output, "verified_policy").0, "failed");
        assert_eq!(
            output["spending_summary"]["authority_status"],
            "unavailable"
        );
        assert_eq!(output["spending_summary"]["sequence"], 7);

        let raw = std::fs::read_to_string(fixture.path()).unwrap();
        let unsigned = raw.split("\n[signature]").next().unwrap().to_owned();
        std::fs::write(fixture.path(), unsigned).unwrap();
        let output = fixture.run().unwrap();
        assert_eq!(check_of(&output, "verified_policy").0, "failed");
        assert!(output["spending_summary"].is_null(), "{output}");
    }

    /// The ceremony previews the rebound body: the signature it requires,
    /// the fee cap the rewrite signs, and no plan; the result repeats it.
    #[test]
    #[serial]
    fn enable_preview_shows_bound_body() {
        let fixture = Fixture::new();
        let result = fixture.run().unwrap();
        let text = String::from_utf8(fixture.preview.borrow().clone()).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        let preview: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(preview["phase"], "before_write");
        assert!(preview.get("plan").is_none(), "{preview}");
        let summary = &preview["spending_summary"];
        assert_eq!(summary["authority_status"], "requires_signature");
        assert_eq!(summary["fee_cap_status"], "signed");
        let rewritten = std::fs::read_to_string(fixture.path())
            .unwrap()
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let fee = rewritten["mainnet"]["classic_max_fee_per_op_stroops"]
            .as_integer()
            .unwrap();
        assert_eq!(fee, 10_000);
        assert_eq!(summary["classic_max_fee_per_op_stroops"], fee);
        assert_eq!(result["spending_summary"], *summary);
    }

    /// The preview summarizes the bytes `sign-policy` signs from the rebound
    /// body. With the pin the ceremony leaves, signing prepares exactly the
    /// previewed body, and the previewed summary equals the summary of the
    /// signed bytes field by field. A rotation of a bound body is signed
    /// without an edit, so its written body is signed as it stands.
    #[test]
    #[serial]
    fn enable_preview_is_the_signed_body() {
        let mut fixture = Fixture::new();
        fixture.run().unwrap();
        let first: serde_json::Value = serde_json::from_slice(&fixture.preview.borrow()).unwrap();
        // The installed body holds sequence 1; signing assigns 2.
        assert_eq!(first["spending_summary"]["sequence"], 2);

        fixture.sign_rewritten_and_verify(2);
        fixture.args.rotate = true;
        fixture.preview.borrow_mut().clear();
        fixture.run().unwrap();
        let shown: serde_json::Value = serde_json::from_slice(&fixture.preview.borrow()).unwrap();
        let written = std::fs::read_to_string(fixture.path()).unwrap();
        let PinState::Present(pin) = fixture.pin() else {
            panic!("the ceremony leaves a pin");
        };
        let signed = super::super::sign_policy::prepare_policy(
            &written,
            &fixture.profile,
            "operator",
            &fixture.path(),
            &fixture.window,
        )
        .unwrap();
        assert_eq!(
            signing_body(&written, Some(pin.sequence())).unwrap(),
            signed.raw
        );
        let summary = serde_json::to_value(summarize(
            &parse_policy_body(&signed.raw).unwrap(),
            &fixture.profile.network_passphrase,
            AuthorityStatus::RequiresSignature,
        ))
        .unwrap();
        let shown = shown["spending_summary"].as_object().unwrap();
        let summary = summary.as_object().unwrap();
        assert_eq!(
            shown.keys().collect::<Vec<_>>(),
            summary.keys().collect::<Vec<_>>()
        );
        for (field, value) in summary {
            assert_eq!(&shown[field], value, "{field}");
        }
        assert_eq!(shown["sequence"], 3);
    }

    /// A stderr writer that records, at each write and flush, whether the
    /// pin, the nonce, or the audit row exists yet.
    struct WriteWatch<'f> {
        fixture: &'f Fixture,
        seen: Vec<(bool, bool, bool)>,
    }

    impl WriteWatch<'_> {
        fn record(&mut self) {
            self.seen.push((
                matches!(self.fixture.pin(), PinState::Present(_)),
                get(&self.fixture.nonce_ref()).is_some(),
                self.fixture.dir.path().join("audit.jsonl").exists(),
            ));
        }
    }

    impl std::io::Write for WriteWatch<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.record();
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.record();
            Ok(())
        }
    }

    /// The preview reaches stderr before the pin, the audit row, and the
    /// nonce exist.
    #[test]
    #[serial]
    fn enable_preview_precedes_pin_write() {
        let fixture = Fixture::new();
        assert!(matches!(fixture.pin(), PinState::Absent));
        let mut watch = WriteWatch {
            fixture: &fixture,
            seen: Vec::new(),
        };
        fixture.run_into(&mut watch).unwrap();
        let seen = watch.seen;
        assert!(seen.len() >= 2, "{seen:?}");
        assert!(seen.iter().all(|s| *s == (false, false, false)), "{seen:?}");
        assert!(matches!(fixture.pin(), PinState::Present(_)));
        assert!(get(&fixture.nonce_ref()).is_some());
    }

    /// A preview that cannot be written refuses with its code before any
    /// write.
    #[test]
    #[serial]
    fn enable_preview_failure_prevents_writes() {
        for writer in [render::FailingWriter::Write, render::FailingWriter::Flush] {
            let fixture = Fixture::new();
            let before = persisted(&fixture);
            let mut out = writer;
            let (code, detail) = fixture.run_into(&mut out).unwrap_err();
            assert_eq!(code, "profile.spending_preview_unwritable", "{writer:?}");
            assert!(detail.ends_with("; nothing was written"), "{detail}");
            assert_eq!(persisted(&fixture), before, "{writer:?}");
            assert!(matches!(fixture.pin(), PinState::Absent), "{writer:?}");
            assert!(get(&fixture.nonce_ref()).is_none(), "{writer:?}");
        }
    }

    /// A refusal after the preview carries it at `error.details.preview`;
    /// one before it carries none.
    #[test]
    #[serial]
    fn failure_envelope_carries_preview() {
        let fixture = Fixture::new();
        let (code, detail) = fixture
            .run_with(
                |_| Err(("audit.write_failed", "the audit row failed".into())),
                atomic_write_string,
            )
            .unwrap_err();
        let shown: serde_json::Value = serde_json::from_slice(&fixture.preview.borrow()).unwrap();
        let envelope = serde_json::to_value(failure_envelope(code, detail, Some(&shown))).unwrap();
        assert_eq!(envelope["error"]["code"], "audit.write_failed");
        assert_eq!(envelope["error"]["message"], "the audit row failed");
        assert_eq!(envelope["error"]["details"]["preview"], shown);
        assert_eq!(
            envelope["error"]["details"]["preview"]["spending_summary"]["authority_status"],
            "requires_signature"
        );
        let envelope = serde_json::to_value(failure_envelope(
            "profile.enable_mainnet_precondition",
            "nonce".into(),
            None,
        ))
        .unwrap();
        assert!(envelope["error"]["details"].is_null(), "{envelope}");
    }

    /// A full binding fills the preset fee cap when the body states none and
    /// keeps an authored one; a rotation of a bound body leaves the fee alone.
    #[test]
    #[serial]
    fn enablement_fills_absent_fee_keeps_authored() {
        let fee = |rewritten: &str| {
            rewritten.parse::<toml_edit::DocumentMut>().unwrap()["mainnet"]
                .get("classic_max_fee_per_op_stroops")
                .and_then(toml_edit::Item::as_integer)
        };
        let digest = "0".repeat(64);
        let unbound = "version = 2\nscope = \"profile:operator\"\nsequence = 1\n";
        let authored = format!("{unbound}\n[mainnet]\nclassic_max_fee_per_op_stroops = 500\n");
        let bound = format!(
            "{unbound}\n[mainnet]\nprofile = \"operator\"\nendpoint_host = \"rpc.example.invalid\"\n\
             installation_nonce_sha256 = \"{}\"\n",
            "1".repeat(64)
        );
        let rewrite = |raw: &str, rotate: bool| {
            rewrite_policy(
                &raw.parse().unwrap(),
                "operator",
                "rpc.example.invalid",
                &digest,
                rotate,
            )
            .unwrap()
        };
        for rotate in [false, true] {
            assert_eq!(fee(&rewrite(unbound, rotate)), Some(10_000), "{rotate}");
        }
        assert_eq!(fee(&rewrite(&authored, false)), Some(500));
        let rotated = rewrite(&bound, true);
        assert_eq!(fee(&rotated), None);
        assert!(rotated.contains(&digest));
        assert_eq!(fee(&rewrite(&bound, false)), Some(10_000));

        let fixture = Fixture::new();
        fixture.run().unwrap();
        assert_eq!(
            fee(&std::fs::read_to_string(fixture.path()).unwrap()),
            Some(10_000)
        );
    }

    fn unbound_body(remote: bool) -> String {
        let raw = if remote {
            include_str!(
                "../../../../stellar-agent-core/tests/fixtures/policy-v2-remote-approval.toml"
            )
        } else {
            FULL
        };
        let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
        let table = doc["mainnet"].as_table_like_mut().unwrap();
        for field in ["profile", "endpoint_host", "installation_nonce_sha256"] {
            table.remove(field);
        }
        doc.to_string()
    }

    fn persisted(fixture: &Fixture) -> Vec<(std::path::PathBuf, Vec<u8>)> {
        fixture
            .listing()
            .into_iter()
            .filter(|path| fixture.dir.path().join(path).is_file())
            .map(|path| {
                let bytes = std::fs::read(fixture.dir.path().join(&path)).unwrap();
                (path, bytes)
            })
            .collect()
    }

    #[test]
    #[serial]
    fn state_envelope_and_exit_codes() {
        use clap::Parser;
        #[derive(Debug, Parser)]
        struct Command {
            #[command(flatten)]
            args: EnableMainnetArgs,
        }
        for conflict in ["--check", "--rotate"] {
            assert_eq!(
                Command::try_parse_from(["command", "--state", conflict])
                    .unwrap_err()
                    .kind(),
                clap::error::ErrorKind::ArgumentConflict
            );
        }
        for (state, status) in [("absent", 3), ("enabled", 0), ("unreadable", 1)] {
            let mut fixture = Fixture::new();
            let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(fixture.dir.path());
            fixture.profile.oracle_provider_url = None;
            fixture.profile.providers.as_mut().unwrap().oracle = None;
            fixture.profile.policy.engine = PolicyEngineKind::Noop;
            loader::save_to_dir(
                "operator",
                &fixture.profile,
                &fixture.dir.path().join("profiles"),
            )
            .unwrap();
            let pin = stellar_agent_core::profile::schema::policy_pin_entry_ref(
                &fixture.profile.policy_window_state_key_id,
            );
            let owner = KeyringEntryRef::default_owner_key("operator");
            let forbid_pin = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let pin_probe = forbid_pin.clone();
            keyring_mock::install_with_read_hooks(vec![
                keyring_mock::ReadHook::new(
                    &pin.service,
                    &pin.account,
                    Arc::new(move || {
                        assert!(
                            !pin_probe.load(std::sync::atomic::Ordering::SeqCst),
                            "state reads a pin"
                        )
                    }),
                ),
                keyring_mock::ReadHook::new(
                    &owner.service,
                    &owner.account,
                    Arc::new(|| panic!("state reads an owner")),
                ),
            ])
            .unwrap();
            put(&pin, "unchanged-pin");
            std::fs::write(fixture.path(), "unparseable policy").unwrap();
            std::fs::write(fixture.dir.path().join("audit.jsonl"), "unchanged-audit").unwrap();
            if state != "absent" {
                put(&fixture.nonce_ref(), "unchanged-nonce");
            }
            let before = persisted(&fixture);
            let listing = fixture.listing();
            fixture.args.state = true;
            if state == "unreadable" {
                let coordinate = fixture.nonce_ref();
                keyring_mock::inject_no_logon_session(&coordinate.service, &coordinate.account)
                    .unwrap();
            }
            render::take_rendered_for_test();
            assert_eq!(run_with_keyring(&fixture.args, || Ok(())), status);
            let mut output = render::take_rendered_for_test();
            assert_eq!(output.len(), 1);
            output[0]["request_id"] = "fixed-id".into();
            let mut data = serde_json::json!({
                "profile": "operator", "state": state,
                "nonce_entry": {"service": "stellar-agent-policy-window-operator", "account": "default-mainnet-enablement"},
            });
            if state == "unreadable" {
                data["code"] = "profile.mainnet_enablement_invalid".into();
            }
            assert_eq!(
                output[0],
                serde_json::to_value(Envelope::ok_with_request_id(data, "fixed-id".into()))
                    .unwrap()
            );
            forbid_pin.store(false, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(get(&pin).as_deref(), Some("unchanged-pin"));
            forbid_pin.store(true, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(persisted(&fixture), before);
            assert_eq!(fixture.listing(), listing);
            assert_eq!(
                get(&fixture.nonce_ref()),
                (state != "absent").then(|| "unchanged-nonce".to_owned())
            );
            render::take_rendered_for_test();
            assert_eq!(
                run_with_keyring(&fixture.args, || Err(
                    stellar_agent_core::error::ValidationError::MainnetEnablementInvalid {
                        binding: "nonce"
                    }
                    .into()
                )),
                1
            );
            let output = render::take_rendered_for_test();
            assert_eq!(output[0]["ok"], false);
            assert_eq!(
                output[0]["error"]["code"],
                "profile.enable_mainnet_precondition"
            );
            assert!(output[0].get("data").is_none());
            fixture.args.profile = Some("missing-profile".into());
            let mut failures = Vec::new();
            for state in [false, true] {
                fixture.args.state = state;
                render::take_rendered_for_test();
                assert_eq!(
                    run_with_keyring(&fixture.args, || panic!(
                        "profile load must precede initialization"
                    )),
                    1
                );
                let mut rendered = render::take_rendered_for_test().remove(0);
                rendered["request_id"] = "fixed-id".into();
                assert_eq!(rendered["ok"], false);
                assert_eq!(
                    rendered["error"]["code"],
                    "profile.enable_mainnet_precondition"
                );
                failures.push(rendered);
            }
            assert_eq!(failures[0], failures[1]);
            fixture.args.profile = Some("operator".into());
            fixture.args.state = true;
            fixture.profile.policy_window_state_key_id =
                KeyringEntryRef::new("configured-window", "configured");
            if state != "absent" {
                put(&fixture.nonce_ref(), "configured-nonce");
            }
            if state == "unreadable" {
                let coordinate = fixture.nonce_ref();
                keyring_mock::inject_no_logon_session(&coordinate.service, &coordinate.account)
                    .unwrap();
            }
            let result = fixture.run_with(
                |_| panic!("state emits audit"),
                |_, _| panic!("state writes policy"),
            );
            assert_eq!(exit_code(&result), status);
            let output = result.unwrap();
            assert_eq!(output["state"], state);
            assert_eq!(
                output["nonce_entry"],
                serde_json::json!({"service": "configured-window", "account": "configured-mainnet-enablement"})
            );
            assert_eq!(persisted(&fixture), before);
            assert_eq!(
                get(&fixture.nonce_ref()),
                (state != "absent").then(|| "configured-nonce".to_owned())
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn initial_pin_accepts_binding_free_body() {
        let fixture = Fixture::new();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(fixture.dir.path());
        let mut profile = fixture.profile.clone();
        profile.wallet.mlock_required = stellar_agent_core::wallet::MlockRequired::Warn;
        std::fs::write(fixture.path(), unbound_body(false)).unwrap();
        let (status, output) =
            super::super::sign_policy::tests::native_sign(&profile, &fixture.path(), false).await;
        assert_eq!(status, 0, "{output}");
        let signed = std::fs::read_to_string(fixture.path()).unwrap();
        let canonical =
            stellar_agent_core::policy::v1::canonical::canonical_bytes(&signed).unwrap();
        let expected = Pin::new(
            8,
            stellar_agent_core::policy::v1::signature::digest(&canonical),
            fixture.owner.verifying_key().to_bytes(),
        )
        .unwrap();
        assert!(
            stellar_agent_core::policy::v1::verified::validate_profile_body(
                &signed.parse().unwrap(),
                &profile
            )
            .is_err()
        );
        let load = PolicyLoad {
            path: &fixture.path(),
            profile: &profile,
            profile_name: "operator",
            owner_pubkey: &fixture.owner.verifying_key().to_bytes(),
            owner_source: OwnerKeySource::Keyring,
            window_path: &fixture.window,
        };
        assert!(
            load_verified_policy(&load, PolicyStateStore::new(), PinMode::CompareOnly).is_err()
        );
        fixture.run().unwrap();
        assert_eq!(fixture.pin(), PinState::Present(expected));
        let before = fixture.pin();
        std::fs::write(fixture.path(), "invalid policy").unwrap();
        ensure_policy_pin(
            "operator",
            &fixture.profile,
            &fixture.path(),
            &fixture.window,
            &toml_edit::DocumentMut::new(),
        )
        .unwrap();
        assert_eq!(fixture.pin(), before);
        assert_eq!(
            std::fs::read_to_string(fixture.path()).unwrap(),
            "invalid policy"
        );
    }

    #[test]
    #[serial]
    fn initial_pin_verifies_signature_sequence_and_owner() {
        for defect in [
            "unsigned",
            "tampered",
            "wrong-owner",
            "v1",
            "missing-sequence",
            "zero",
            "negative",
        ] {
            let fixture = Fixture::new();
            let mut doc = unbound_body(false)
                .parse::<toml_edit::DocumentMut>()
                .unwrap();
            match defect {
                "v1" => {
                    doc.remove("mainnet");
                    doc.remove("sequence");
                    doc["version"] = toml_edit::value(1);
                }
                "zero" => doc["sequence"] = toml_edit::value(0),
                "negative" => doc["sequence"] = toml_edit::value(-1),
                _ => (),
            }
            fixture.sign(&doc.to_string());
            match defect {
                "missing-sequence" => {
                    let mut signed = std::fs::read_to_string(fixture.path())
                        .unwrap()
                        .parse::<toml_edit::DocumentMut>()
                        .unwrap();
                    signed.remove("sequence");
                    std::fs::write(fixture.path(), signed.to_string()).unwrap();
                }
                "unsigned" => std::fs::write(fixture.path(), doc.to_string()).unwrap(),
                "tampered" => {
                    let raw = std::fs::read_to_string(fixture.path())
                        .unwrap()
                        .replace("review", "altered");
                    std::fs::write(fixture.path(), raw).unwrap();
                }
                "wrong-owner" => {
                    let other = SigningKey::from_bytes(&[12; 32]);
                    put(
                        &KeyringEntryRef::default_owner_key("operator"),
                        &stellar_strkey::ed25519::PublicKey(other.verifying_key().to_bytes())
                            .to_string(),
                    );
                    put(
                        &signer_identity_entry_ref(&fixture.profile.mcp_signer_default),
                        &SignerIdentityRecord::signed_for_test(
                            [2; 32],
                            "operator",
                            &fixture.profile,
                            &other,
                        )
                        .render()
                        .unwrap(),
                    );
                }
                _ => (),
            }
            let before = std::fs::read(fixture.path()).unwrap();
            let error = fixture.run().unwrap_err();
            let expected = match defect {
                "tampered" | "wrong-owner" => "policy.owner_signature_invalid",
                "v1" => "profile.enable_mainnet_precondition",
                _ => "policy.policy_file_parse_failed",
            };
            assert_eq!(error.0, expected, "{defect}: {error:?}");
            assert_eq!(std::fs::read(fixture.path()).unwrap(), before);
            assert_eq!(fixture.pin(), PinState::Absent);
            assert!(get(&fixture.nonce_ref()).is_none());
            assert!(!fixture.dir.path().join("audit.jsonl").exists());
        }
    }

    #[test]
    #[serial]
    fn initial_pin_loader_refuses_v1_and_nonpositive_sequence() {
        use stellar_agent_core::policy::v1::verified::pin_provisioning_policy;

        for defect in ["v1", "zero", "negative"] {
            let fixture = Fixture::new();
            let mut body = unbound_body(false)
                .parse::<toml_edit::DocumentMut>()
                .unwrap();
            match defect {
                "v1" => {
                    body.remove("mainnet");
                    body.remove("sequence");
                    body["version"] = toml_edit::value(1);
                }
                "zero" => body["sequence"] = toml_edit::value(0),
                "negative" => body["sequence"] = toml_edit::value(-1),
                _ => unreachable!(),
            }
            fixture.sign(&body.to_string());
            let bytes = std::fs::read_to_string(fixture.path()).unwrap();
            let error = pin_provisioning_policy(
                &PolicyLoad {
                    path: &fixture.path(),
                    profile: &fixture.profile,
                    profile_name: "operator",
                    owner_pubkey: &fixture.owner.verifying_key().to_bytes(),
                    owner_source: OwnerKeySource::Keyring,
                    window_path: &fixture.window,
                },
                &bytes.parse().unwrap(),
            )
            .unwrap_err();
            assert_eq!(error.wire_code(), "policy.policy_file_parse_failed");
            assert!(
                error.to_string().contains(if defect == "v1" {
                    "initial pin requires a v2 policy"
                } else {
                    "v2 sequence must be an integer in 1..=i64::MAX"
                }),
                "{defect}: {error}"
            );
            assert_eq!(fixture.pin(), PinState::Absent);
            assert_eq!(std::fs::read_to_string(fixture.path()).unwrap(), bytes);
        }
    }

    #[test]
    #[serial]
    fn unsigned_v1_reports_signature_error_before_version_refusal() {
        let fixture = Fixture::new();
        let mut body = unbound_body(false)
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        body.remove("mainnet");
        body.remove("sequence");
        body["version"] = toml_edit::value(1);
        let bytes = body.to_string();
        std::fs::write(fixture.path(), &bytes).unwrap();
        let error = fixture.run().unwrap_err();
        assert_eq!(error.0, "policy.policy_file_parse_failed");
        assert!(error.1.contains("no `[signature]` table"), "{error:?}");
        assert_eq!(fixture.pin(), PinState::Absent);
        assert_eq!(std::fs::read_to_string(fixture.path()).unwrap(), bytes);
        assert!(get(&fixture.nonce_ref()).is_none());
        assert!(!fixture.dir.path().join("audit.jsonl").exists());
    }

    #[test]
    #[serial]
    fn initial_pin_uses_the_supplied_body() {
        let fixture = Fixture::new();
        fixture.sign(&unbound_body(false));
        let raw = std::fs::read_to_string(fixture.path()).unwrap();
        let body = raw.parse().unwrap();
        let canonical = stellar_agent_core::policy::v1::canonical::canonical_bytes(&raw).unwrap();
        std::fs::write(fixture.path(), "invalid policy").unwrap();
        ensure_policy_pin(
            "operator",
            &fixture.profile,
            &fixture.path(),
            &fixture.window,
            &body,
        )
        .unwrap();
        assert_eq!(
            fixture.pin(),
            PinState::Present(
                Pin::new(
                    7,
                    stellar_agent_core::policy::v1::signature::digest(&canonical),
                    fixture.owner.verifying_key().to_bytes(),
                )
                .unwrap()
            )
        );
        assert_eq!(
            std::fs::read_to_string(fixture.path()).unwrap(),
            "invalid policy"
        );
        assert!(get(&fixture.nonce_ref()).is_none());
        assert!(!fixture.dir.path().join("audit.jsonl").exists());
    }

    #[tokio::test]
    #[serial]
    async fn partial_binding_fields_refuse() {
        let fields = ["profile", "endpoint_host", "installation_nonce_sha256"];
        for mask in 1_u8..7 {
            for nonce in ["absent", "present", "unreadable"] {
                let present = nonce == "present";
                let fixture = Fixture::new();
                let _home =
                    stellar_agent_test_support::StellarAgentHomeGuard::new(fixture.dir.path());
                let mut doc = FULL.parse::<toml_edit::DocumentMut>().unwrap();
                for (index, field) in fields.iter().enumerate() {
                    if mask & (1 << index) == 0 {
                        doc["mainnet"].as_table_like_mut().unwrap().remove(field);
                    }
                }
                let strict = stellar_agent_core::policy::v1::verified::validate_profile_body(
                    &doc,
                    &fixture.profile,
                )
                .unwrap_err();
                let body = doc.to_string();
                std::fs::write(fixture.path(), &body).unwrap();
                if present {
                    put(&fixture.nonce_ref(), "fixture-nonce");
                }
                if nonce == "unreadable" {
                    let coordinate = fixture.nonce_ref();
                    keyring_mock::inject_no_logon_session(&coordinate.service, &coordinate.account)
                        .unwrap();
                }
                let (status, output) = super::super::sign_policy::tests::native_sign(
                    &fixture.profile,
                    &fixture.path(),
                    false,
                )
                .await;
                assert_eq!(status, 1);
                assert_eq!(output["error"]["code"], strict.wire_code());
                assert!(
                    output["error"]["message"]
                        .as_str()
                        .unwrap()
                        .contains(&strict.to_string())
                );
                assert_eq!(std::fs::read_to_string(fixture.path()).unwrap(), body);
                assert_eq!(fixture.pin(), PinState::Absent);
                fixture.sign(&body);
                let signed = std::fs::read(fixture.path()).unwrap();
                let error = ensure_policy_pin(
                    "operator",
                    &fixture.profile,
                    &fixture.path(),
                    &fixture.window,
                    &std::str::from_utf8(&signed).unwrap().parse().unwrap(),
                )
                .unwrap_err();
                assert_eq!(error.0, strict.wire_code());
                assert_eq!(error.1, strict.to_string());
                assert_eq!(std::fs::read(fixture.path()).unwrap(), signed);
                assert_eq!(fixture.pin(), PinState::Absent);
                assert_eq!(
                    get(&fixture.nonce_ref()),
                    present.then(|| "fixture-nonce".to_owned())
                );
                assert!(!fixture.dir.path().join("audit.jsonl").exists());
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn provisioning_nonbinding_checks_remain_strict() {
        for defect in [
            "scope",
            "keys",
            "fee",
            "credentials",
            "ttl",
            "thresholds",
            "origin",
            "certificate",
            "minimum",
        ] {
            let fixture = Fixture::new();
            let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(fixture.dir.path());
            let mut doc = unbound_body(false)
                .parse::<toml_edit::DocumentMut>()
                .unwrap();
            match defect {
                "scope" => doc["scope"] = toml_edit::value("profile:other"),
                "keys" => doc["mainnet"]["unknown"] = toml_edit::value(true),
                "fee" => doc["mainnet"]["classic_max_fee_per_op_stroops"] = toml_edit::value(-1),
                "credentials" => {
                    doc["mainnet"]
                        .as_table_like_mut()
                        .unwrap()
                        .remove("approval_credentials");
                }
                "ttl" => doc["mainnet"]["authorization_ttl_seconds"] = toml_edit::value(-1),
                "thresholds" => {
                    doc["mainnet"]["cross_check_thresholds"]["native"] = toml_edit::value("-1")
                }
                "origin" => {
                    doc["mainnet"]["approval_origin"] =
                        toml_edit::value("http://approve.example.invalid")
                }
                "certificate" => {
                    doc["mainnet"]["approval_cert_spki_sha256"] = toml_edit::value("invalid-pin")
                }
                "minimum" => {
                    doc["rules"]
                        .as_array_of_tables_mut()
                        .unwrap()
                        .get_mut(0)
                        .unwrap()["ttl_secs"] = toml_edit::value(86401)
                }
                _ => unreachable!(),
            }
            let body = doc.to_string();
            let applicable = defect != "minimum" || cfg!(feature = "mainnet-write");
            let core_code = match defect {
                "credentials" => "policy.mainnet_minimum_unmet",
                "fee" | "ttl" | "thresholds" | "minimum" if cfg!(feature = "mainnet-write") => {
                    "policy.mainnet_minimum_unmet"
                }
                _ => "policy.policy_file_parse_failed",
            };
            let signing_code = match defect {
                "scope" | "origin" | "certificate" => "sign_policy.policy_body_invalid",
                "keys" => "sign_policy.canonicalization_failed",
                _ => core_code,
            };
            let mut profile = fixture.profile.clone();
            profile.wallet.mlock_required = stellar_agent_core::wallet::MlockRequired::Warn;
            std::fs::write(fixture.path(), &body).unwrap();
            let (status, output) =
                super::super::sign_policy::tests::native_sign(&profile, &fixture.path(), false)
                    .await;
            if applicable {
                assert_eq!(status, 1, "{defect}: {output}");
                assert_eq!(output["error"]["code"], signing_code, "{defect}: {output}");
                assert_eq!(std::fs::read_to_string(fixture.path()).unwrap(), body);
                assert_eq!(fixture.pin(), PinState::Absent);
            } else {
                assert_eq!(status, 0, "{output}");
            }
            if defect == "keys" {
                std::fs::write(
                    fixture.path(),
                    format!(
                        "{body}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
                        stellar_strkey::ed25519::PublicKey(
                            fixture.owner.verifying_key().to_bytes()
                        ),
                        "00".repeat(64)
                    ),
                )
                .unwrap();
            } else {
                fixture.sign(&body);
            }
            let signed = std::fs::read(fixture.path()).unwrap();
            let result = fixture.run();
            if applicable {
                assert_eq!(result.unwrap_err().0, core_code, "{defect}");
                assert_eq!(std::fs::read(fixture.path()).unwrap(), signed);
                assert_eq!(fixture.pin(), PinState::Absent);
                assert!(get(&fixture.nonce_ref()).is_none());
                assert!(!fixture.dir.path().join("audit.jsonl").exists());
            } else {
                result.unwrap();
            }
        }
    }

    #[test]
    #[serial]
    fn initial_pin_concurrent_pin_returns_unchanged() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let profile = Fixture::profile();
        let owner_coordinate = KeyringEntryRef::default_owner_key("operator");
        let hook_path = Arc::new(Mutex::new(None::<std::path::PathBuf>));
        let hook_path_copy = hook_path.clone();
        let armed = Arc::new(AtomicBool::new(false));
        let hook_armed = armed.clone();
        let hook_profile = profile.clone();
        let concurrent = Pin::new(12, [12; 32], [12; 32]).unwrap();
        let hook_pin = concurrent.clone();
        keyring_mock::install_with_read_hooks(vec![keyring_mock::ReadHook::new(
            &owner_coordinate.service,
            &owner_coordinate.account,
            Arc::new(move || {
                if hook_armed.swap(false, Ordering::SeqCst) {
                    let path = hook_path_copy.lock().unwrap().clone().unwrap();
                    let lock = WindowStoreLock::acquire_for(
                        &path,
                        &hook_profile.policy_window_state_key_id,
                    )
                    .unwrap();
                    pin::write_for_test(
                        &lock,
                        &PinScope::for_profile(&path, &hook_profile),
                        &hook_pin,
                    )
                    .unwrap();
                }
            }),
        )])
        .unwrap();
        let fixture = Fixture::seeded(profile);
        fixture.sign(&unbound_body(false));
        let mut other_profile = fixture.profile.clone();
        other_profile.policy_window_state_key_id =
            KeyringEntryRef::default_policy_window_state_key("other");
        let other_window = fixture.dir.path().join("other.window");
        let other_pin = Pin::new(4, [4; 32], [4; 32]).unwrap();
        let other_lock =
            WindowStoreLock::acquire_for(&other_window, &other_profile.policy_window_state_key_id)
                .unwrap();
        pin::write_for_test(
            &other_lock,
            &PinScope::for_profile(&other_window, &other_profile),
            &other_pin,
        )
        .unwrap();
        drop(other_lock);
        *hook_path.lock().unwrap() = Some(fixture.window.clone());
        armed.store(true, Ordering::SeqCst);
        let bytes = std::fs::read(fixture.path()).unwrap();
        ensure_policy_pin(
            "operator",
            &fixture.profile,
            &fixture.path(),
            &fixture.window,
            &std::str::from_utf8(&bytes).unwrap().parse().unwrap(),
        )
        .unwrap();
        assert!(!armed.load(Ordering::SeqCst));
        assert_eq!(fixture.pin(), PinState::Present(concurrent.clone()));
        assert_eq!(
            read_pin_without_creating(&other_window, &other_profile).unwrap(),
            PinState::Present(other_pin.clone())
        );
        assert_eq!(std::fs::read(fixture.path()).unwrap(), bytes);
        assert!(get(&fixture.nonce_ref()).is_none());
        assert!(!fixture.dir.path().join("audit.jsonl").exists());
        fixture.run().unwrap();
        assert_eq!(fixture.pin(), PinState::Present(concurrent));
        assert_eq!(
            read_pin_without_creating(&other_window, &other_profile).unwrap(),
            PinState::Present(other_pin)
        );
        assert!(get(&fixture.nonce_ref()).is_some());
    }

    #[test]
    #[serial]
    fn initial_pin_nonce_guard_holds_the_lock() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        for unreadable in [false, true] {
            let profile = Fixture::profile();
            let coordinate = mainnet_enablement_entry_ref(&profile.policy_window_state_key_id);
            let hook_coordinate = coordinate.clone();
            let hook_profile = profile.clone();
            let hook_path = Arc::new(Mutex::new(None::<std::path::PathBuf>));
            let path_copy = hook_path.clone();
            let probes = Arc::new(AtomicUsize::new(0));
            let count = probes.clone();
            keyring_mock::install_with_read_hooks(vec![keyring_mock::ReadHook::new(
                &coordinate.service, &coordinate.account, Arc::new(move || {
                    if count.fetch_add(1, Ordering::SeqCst) == 1 {
                        let path = path_copy.lock().unwrap().clone().unwrap();
                        assert!(matches!(WindowStoreLock::acquire_for(&path, &hook_profile.policy_window_state_key_id),
                            Err(stellar_agent_core::policy::state_lock::StateLockError::WriterLocked)), "nonce recheck holds the state lock");
                        if unreadable {
                            keyring_mock::inject_no_logon_session(&hook_coordinate.service, &hook_coordinate.account).unwrap();
                        } else { put(&hook_coordinate, "concurrent-nonce"); }
                    }
                }),
            )]).unwrap();
            let fixture = Fixture::seeded(profile);
            *hook_path.lock().unwrap() = Some(fixture.window.clone());
            fixture.sign(&unbound_body(false));
            let bytes = std::fs::read(fixture.path()).unwrap();
            let error = fixture.run().unwrap_err();
            assert_eq!(probes.load(Ordering::SeqCst), 2);
            assert_eq!(
                error.0,
                if unreadable {
                    "policy.pin_unusable"
                } else {
                    "policy.pin_absent"
                }
            );
            assert_eq!(fixture.pin(), PinState::Absent);
            assert_eq!(std::fs::read(fixture.path()).unwrap(), bytes);
            assert!(!fixture.dir.path().join("audit.jsonl").exists());
        }
    }

    fn cycle_fixture() -> (Fixture, stellar_agent_test_support::StellarAgentHomeGuard) {
        let mut fixture = Fixture::new();
        let home = stellar_agent_test_support::StellarAgentHomeGuard::new(fixture.dir.path());
        fixture.profile.wallet.mlock_required = stellar_agent_core::wallet::MlockRequired::Warn;
        fixture.window =
            stellar_agent_core::profile::schema::default_policy_window_state_path_for("operator");
        (fixture, home)
    }

    async fn enable_native_body(fixture: &Fixture, remote: bool) -> serde_json::Value {
        std::fs::write(fixture.path(), unbound_body(remote)).unwrap();
        let (status, output) =
            super::super::sign_policy::tests::native_sign(&fixture.profile, &fixture.path(), false)
                .await;
        assert_eq!(status, 0, "{output}");
        assert_eq!(output["data"]["sequence"], 8);
        assert_eq!(fixture.pin(), PinState::Absent);
        fixture.run().unwrap()
    }

    async fn sign_bound_body(fixture: &Fixture) -> (i32, serde_json::Value) {
        super::super::sign_policy::tests::native_sign(&fixture.profile, &fixture.path(), false)
            .await
    }

    fn check_native_body(fixture: &mut Fixture) -> Result<serde_json::Value, Failure> {
        fixture.args.check = true;
        let result = fixture.run();
        fixture.args.check = false;
        result
    }

    fn native_state(fixture: &mut Fixture) -> Result<serde_json::Value, Failure> {
        fixture.args.state = true;
        let result = fixture.run();
        fixture.args.state = false;
        result
    }

    #[tokio::test]
    #[serial]
    async fn enablement_persists_while_check_fails() {
        let (mut fixture, _home) = cycle_fixture();
        enable_native_body(&fixture, false).await;
        let snapshot = persisted(&fixture);
        let nonce = get(&fixture.nonce_ref());
        assert!(nonce.is_some());
        let stale = check_native_body(&mut fixture);
        assert_eq!(exit_code(&stale), 1);
        assert_eq!(stale.unwrap()["valid"], false);
        let state = native_state(&mut fixture);
        assert_eq!(exit_code(&state), 0);
        assert_eq!(state.unwrap()["state"], "enabled");
        assert_eq!(
            fixture.run().unwrap_err().0,
            "profile.enable_mainnet_nonce_exists"
        );
        assert_eq!(persisted(&fixture), snapshot);
        assert_eq!(get(&fixture.nonce_ref()), nonce);
    }

    fn assert_enabled_bindings(fixture: &Fixture, enabled: &serde_json::Value) -> PinState {
        assert_eq!(enabled["policy_needs_signature"], true);
        let pin = fixture.pin();
        assert!(matches!(&pin, PinState::Present(pin) if pin.sequence() == 8));
        let rewritten = std::fs::read_to_string(fixture.path()).unwrap();
        let body = rewritten.parse::<toml_edit::DocumentMut>().unwrap();
        assert_eq!(body["mainnet"]["profile"].as_str(), Some("operator"));
        assert_eq!(
            body["mainnet"]["endpoint_host"].as_str(),
            Some("rpc.example.invalid")
        );
        assert_eq!(
            body["mainnet"]["installation_nonce_sha256"].as_str(),
            enabled["installation_nonce_sha256"].as_str()
        );
        pin
    }

    #[tokio::test]
    #[serial]
    async fn post_enable_resign() {
        let (fixture, _home) = cycle_fixture();
        let enabled = enable_native_body(&fixture, false).await;
        let pin = assert_enabled_bindings(&fixture, &enabled);
        let (status, signed) = sign_bound_body(&fixture).await;
        assert_eq!(status, 0, "{signed}");
        assert_eq!(signed["data"]["sequence"], 9);
        assert_eq!(signed["data"]["previous_sequence"], 8);
        assert_eq!(fixture.pin(), pin);
    }

    #[tokio::test]
    #[serial]
    async fn final_check_after_bound_signing() {
        let (mut fixture, _home) = cycle_fixture();
        enable_native_body(&fixture, false).await;
        let (status, signed) = sign_bound_body(&fixture).await;
        assert_eq!(status, 0, "{signed}");
        let snapshot = persisted(&fixture);
        let pin = fixture.pin();
        let nonce = get(&fixture.nonce_ref());
        let final_check = check_native_body(&mut fixture);
        assert_eq!(exit_code(&final_check), 0, "{final_check:?}");
        assert_eq!(final_check.unwrap()["valid"], true);
        let state = native_state(&mut fixture);
        assert_eq!(exit_code(&state), 0);
        assert_eq!(state.unwrap()["state"], "enabled");
        assert_eq!(persisted(&fixture), snapshot);
        assert_eq!(fixture.pin(), pin);
        assert_eq!(get(&fixture.nonce_ref()), nonce);
    }

    #[tokio::test]
    #[serial]
    async fn local_cycle_completes() {
        let (mut fixture, _home) = cycle_fixture();
        enable_native_body(&fixture, false).await;
        let (status, signed) = sign_bound_body(&fixture).await;
        assert_eq!(status, 0, "{signed}");
        assert_eq!(signed["data"]["sequence"], 9);
        let checked = check_native_body(&mut fixture);
        assert_eq!(exit_code(&checked), 0, "{checked:?}");
        assert_eq!(checked.unwrap()["valid"], true);
        let state = native_state(&mut fixture);
        assert_eq!(exit_code(&state), 0);
        assert_eq!(state.unwrap()["state"], "enabled");
        assert!(matches!(fixture.pin(), PinState::Present(pin) if pin.sequence() == 8));
        assert!(get(&fixture.nonce_ref()).is_some());
    }
    #[tokio::test]
    #[serial]
    async fn remote_bootstrap_cycle() {
        let (mut fixture, _home) = cycle_fixture();
        let enabled = enable_native_body(&fixture, true).await;
        let pin = assert_enabled_bindings(&fixture, &enabled);
        let snapshot = persisted(&fixture);
        let nonce = get(&fixture.nonce_ref());
        assert!(nonce.is_some());
        let stale = check_native_body(&mut fixture);
        assert_eq!(exit_code(&stale), 1);
        assert_eq!(stale.unwrap()["valid"], false);
        let state = native_state(&mut fixture);
        assert_eq!(exit_code(&state), 0);
        assert_eq!(state.unwrap()["state"], "enabled");
        assert_eq!(
            fixture.run().unwrap_err().0,
            "profile.enable_mainnet_nonce_exists"
        );
        assert_eq!(persisted(&fixture), snapshot);
        assert_eq!(get(&fixture.nonce_ref()), nonce);
        let (status, signed) = sign_bound_body(&fixture).await;
        assert_eq!(status, 0, "{signed}");
        assert_eq!(signed["data"]["sequence"], 9);
        assert_eq!(signed["data"]["previous_sequence"], 8);
        assert_eq!(fixture.pin(), pin);
        let snapshot = persisted(&fixture);
        let checked = check_native_body(&mut fixture);
        assert_eq!(exit_code(&checked), 0, "{checked:?}");
        assert_eq!(checked.unwrap()["valid"], true);
        let state = native_state(&mut fixture);
        assert_eq!(exit_code(&state), 0);
        assert_eq!(state.unwrap()["state"], "enabled");
        assert_eq!(persisted(&fixture), snapshot);
        assert_eq!(fixture.pin(), pin);
        assert_eq!(get(&fixture.nonce_ref()), nonce);
    }
}
