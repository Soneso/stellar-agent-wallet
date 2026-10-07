//! `stellar-agent audit verify <log-path>` subcommand.
//!
//! Walks the hash-chained audit log at `<log-path>` and verifies that the
//! chain of SHA-256 hashes is intact from the oldest rotated file to the
//! current active file.
//!
//! # HMAC verification
//!
//! When `--profile <name>` is supplied, the CLI loads that profile's audit
//! keyring reference and verifies chain-root HMAC sidecars.  Without
//! `--profile`, the CLI verifies the hash chain only and `hmac_verified`
//! remains `false`.
//!
//! # Tip-anchor verification
//!
//! The chain walk and the chain-root signatures verify a PREFIX of the log, so
//! an older copy of the active file, or a truncated one, passes both.  The
//! keyring-held tip anchor is what pins the END of the chain.  It is checked
//! only when `--profile <name>` is supplied AND the positional log path is the
//! one that profile configures: the anchor names a PATH, and comparing it
//! against a file it does not describe would report a mismatch that means
//! nothing.  Every other case reports `anchor.status = "not_checked"` with the
//! reason, and the hash chain is still fully verified.
//!
//! # Audit binding
//!
//! With `--profile <name>`, the profile's audit binding is read from the
//! keyring and never written. A binding that names another log path or audit
//! key, or that does not parse, exits 1 with `audit.log_binding_changed`. An
//! absent or equal binding proceeds, and a keyring read error fails closed.
//!
//! # Output
//!
//! With `--output json` (the default): a JSON envelope wrapping
//! `AuditVerifyResult`.
//!
//! # Exit codes
//!
//! - 0 on success (chain intact).
//! - 1 on any integrity violation or I/O error.

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Args;
use keyring_core::Entry as KeyringEntry;
use serde::{Deserialize, Serialize};
use stellar_agent_core::profile::ResolvedProfileName;
use stellar_agent_core::{
    audit_log::{
        BindingCheck,
        health::AuditWriterHealth,
        outbox::inspect_outbox,
        tip_anchor::{TipAnchor, TipAnchorStore as _, normalize_path_lexically},
        verify::{FileVerifyResult, VerifyError, VerifyWarning, verify_log_with_health},
    },
    envelope::{Envelope, OutputFormat},
    error::{InternalError, WalletError},
    profile::schema::Profile,
};
use stellar_agent_network::keyring::{
    KeyringOperation, KeyringTipAnchorStore, check_audit_binding, init_platform_keyring_store,
    map_keyring_operation_error,
};
use zeroize::Zeroizing;

use crate::common::profile_access::load_profile_reconciled;

/// Arguments for the `audit verify` subcommand.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Path to the audit log file to verify.
    ///
    /// Typically `~/.local/share/stellar-agent/audit/<profile>.jsonl` on
    /// Linux, `~/Library/Application Support/Soneso.stellar-agent/audit/<profile>.jsonl`
    /// on macOS, or `%LOCALAPPDATA%\Soneso\stellar-agent\data\audit\<profile>.jsonl` on
    /// Windows.
    #[arg(value_name = "LOG_PATH")]
    pub log_path: PathBuf,

    /// Profile whose audit-log HMAC key should verify chain-root sidecars.
    ///
    /// When omitted, only the hash chain is verified and `hmac_verified` is
    /// reported as `false`.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Output format: `json` (the default).
    #[arg(
        long,
        default_value_t = OutputFormat::DEFAULT,
        value_name = "FORMAT"
    )]
    pub output: OutputFormat,
}

/// The JSON payload returned by `audit verify` on success.
///
/// Serialised inside a standard [`Envelope`] envelope.
///
/// # HMAC verification status
///
/// `hmac_verified` reflects the verifier result.  This CLI currently supplies
/// an HMAC key only when `--profile <name>` is supplied.  Without `--profile`,
/// the field is `false` and the hash chain is still fully verified.
///
/// # Tip anchor
///
/// `anchor` reports whether the keyring-held tip anchor was compared against
/// the log, and when it was not, why.  See the module rustdoc.
///
/// # Audit writer health
///
/// `audit_writer_degraded` reflects the session-level health of the audit
/// writer.  In the CLI context this field is always `false` — health
/// degradation is a session property of a running MCP server, not a
/// log-file property.  The field is present so downstream tooling can parse
/// the field uniformly regardless of whether the output was produced by the
/// CLI or by an MCP tool that has access to the live health handle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuditVerifyResult {
    /// Number of entries verified across all files.
    pub entries_verified: usize,
    /// Number of log files walked (active + rotated).
    pub files_walked: usize,
    /// Whether the HMAC chain-root signature was verified.
    ///
    /// The CLI emits `true` only when `--profile <name>` supplies an audit key
    /// and every chain-root sidecar verifies.
    pub hmac_verified: bool,
    /// Per-file verification results in verifier walk order.
    pub per_file: Vec<FileVerifyResult>,
    /// Informational verifier warnings that do not make verification fail.
    pub warnings: Vec<VerifyWarning>,
    /// Whether the audit-writer mutex was poisoned during the current server
    /// session.  Always `false` in the CLI context — health is a session
    /// property of the MCP server.  See module rustdoc for details.
    pub audit_writer_degraded: bool,
    /// Whether the keyring-held tip anchor was checked, and if not, why.
    pub anchor: AuditAnchorStatus,
    /// Number of consent rows queued in the audit outbox beside the log and
    /// not yet drained into it: the newline-terminated lines of
    /// `<log>.outbox`, read without taking the outbox lock.
    ///
    /// Queued rows sit outside the tip anchor until a draining writer appends
    /// them. A torn or unparseable outbox adds a warning and leaves the chain
    /// verdict unchanged. An outbox that cannot be read has no count: the
    /// field is omitted, an `outbox_unreadable` warning names the condition,
    /// and the chain verdict is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbox_pending: Option<usize>,
}

/// Whether `audit verify` compared the log against its keyring-held tip anchor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuditAnchorStatus {
    /// `"verified"` when the anchor was loaded and matched the log's tip;
    /// `"not_checked"` otherwise.
    pub status: String,
    /// Why the anchor was not checked.  `None` when it was.
    pub reason: Option<String>,
}

impl AuditAnchorStatus {
    /// The anchor was loaded and the walk matched it.
    fn verified() -> Self {
        Self {
            status: "verified".to_owned(),
            reason: None,
        }
    }

    /// The anchor was not compared, for the stated reason.
    fn not_checked(reason: impl Into<String>) -> Self {
        Self {
            status: "not_checked".to_owned(),
            reason: Some(reason.into()),
        }
    }
}

/// Runs the `audit verify` subcommand.
///
/// Verifies the hash chain of the audit log at `args.log_path`.  On success
/// emits a JSON envelope with [`AuditVerifyResult`] and exits 0.  On failure
/// emits an error envelope and exits 1.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the envelope and exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &VerifyArgs) -> i32 {
    // On Unix, verify that the supplied path's parent directory is owned by
    // the invoking user.  A directory owned by another user could be used to
    // substitute log files or sidecars.
    // On Windows the ownership check is skipped — NTFS ACLs provide equivalent
    // protection; an explicit UID check would require a different Win32 API
    // surface not yet in scope.
    #[cfg(unix)]
    if let Err(e) = check_parent_owner(&args.log_path) {
        let wallet_err = stellar_agent_core::WalletError::Internal(
            stellar_agent_core::error::InternalError::InvariantViolated { detail: e },
        );
        let envelope = Envelope::<()>::err(&wallet_err);
        emit_envelope(&envelope, args.output);
        return 1;
    }

    match verify_to_result(args) {
        Ok(result) => {
            emit_envelope(&Envelope::ok(result), args.output);
            0
        }
        Err(VerifyFailure::Wallet(e)) => {
            emit_envelope(&Envelope::<()>::err(&e), args.output);
            1
        }
        Err(VerifyFailure::Raw { code, message }) => {
            emit_envelope(&Envelope::<()>::err_raw(code, message), args.output);
            1
        }
    }
}

/// How `audit verify` failed.
///
/// Verifier failures carry their audit wire codes and diagnostic text.
/// A missing log has a validation category and a remediation message.
/// Profile and ownership pre-checks carry their own codes.
#[derive(Debug)]
enum VerifyFailure {
    /// A typed error; the envelope takes its code and message.
    Wallet(WalletError),
    /// A verifier failure carrying its own wire code and diagnostic message.
    Raw {
        /// Wire code for the envelope.
        code: &'static str,
        /// Operator-facing message.
        message: String,
    },
}

impl From<WalletError> for VerifyFailure {
    fn from(e: WalletError) -> Self {
        Self::Wallet(e)
    }
}

/// Resolves the profile inputs, walks the log, and builds the result payload.
///
/// Split out of [`run`] so the full path from arguments to payload — including
/// whether the tip anchor was checked and why — is reachable without capturing
/// stdout.
fn verify_to_result(args: &VerifyArgs) -> Result<AuditVerifyResult, VerifyFailure> {
    let ResolvedVerifyInputs {
        hmac_key,
        anchor,
        anchor_skip_reason,
    } = resolve_profile_inputs(args.profile.as_deref(), &args.log_path)?;

    // Create a fresh health instance — in the CLI context the health latch is
    // never marked degraded (health is a session property of the MCP server).
    // Using `verify_log_with_health` ensures the output schema is consistent
    // with any future MCP-tool caller that has access to a live handle.
    let health = AuditWriterHealth::new();
    let handle = health.handle();
    let ok_with_health = verify_log_with_health(
        &args.log_path,
        hmac_key.as_deref(),
        anchor.as_ref(),
        &handle,
    )
    .map_err(|err| verify_failure(&err))?;

    let ok = ok_with_health.verify_ok;
    let mut warnings = ok.warnings;
    let outbox_pending = inspect_outbox_into(&args.log_path, &mut warnings);
    Ok(AuditVerifyResult {
        entries_verified: ok.entries_verified,
        files_walked: ok.files_walked,
        hmac_verified: ok.hmac_verified,
        per_file: ok.per_file,
        warnings,
        audit_writer_degraded: ok_with_health.audit_writer_degraded,
        anchor: match anchor_skip_reason {
            Some(reason) => AuditAnchorStatus::not_checked(reason),
            None => AuditAnchorStatus::verified(),
        },
        outbox_pending,
    })
}

/// Counts the rows queued in the audit outbox beside `log_path`, adding a
/// warning for a torn, unparseable, or unreadable outbox.
///
/// Reads without the outbox lock, so the count describes the file at the
/// moment it was read. An absent outbox counts zero; an outbox that cannot be
/// read has no count, `None`. Nothing here changes the chain verdict.
fn inspect_outbox_into(
    log_path: &std::path::Path,
    warnings: &mut Vec<VerifyWarning>,
) -> Option<usize> {
    match inspect_outbox(log_path) {
        Ok(inspection) => {
            if inspection.torn_bytes > 0 {
                warnings.push(VerifyWarning::OutboxTornTail {
                    torn_bytes: inspection.torn_bytes,
                });
            }
            if !inspection.unparseable_lines.is_empty() {
                warnings.push(VerifyWarning::OutboxUnparseable {
                    lines: inspection.unparseable_lines,
                });
            }
            Some(inspection.pending)
        }
        Err(e) => {
            warnings.push(VerifyWarning::OutboxUnreadable {
                error_kind: format!("{:?}", e.kind()),
            });
            None
        }
    }
}

/// What `--profile` contributed to this verification.
struct ResolvedVerifyInputs {
    /// The profile's audit chain-root HMAC key, when `--profile` was supplied.
    hmac_key: Option<Zeroizing<[u8; 32]>>,
    /// The keyring-held tip anchor, when it applies to the supplied path and
    /// has been written.
    anchor: Option<TipAnchor>,
    /// Why the anchor was not checked.  `None` means it was.
    anchor_skip_reason: Option<String>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Resolves the audit HMAC key and the tip anchor from `--profile`.
///
/// The anchor names a PATH, so it is loaded only when `log_path` is the very
/// file the profile configures; a path that differs is verified as a plain chain
/// walk and the reason is reported. An absent anchor is likewise a reason, not a
/// failure: a log whose first keyed use has not happened yet has none.
fn resolve_profile_inputs(
    profile_name: Option<&str>,
    log_path: &std::path::Path,
) -> Result<ResolvedVerifyInputs, WalletError> {
    let Some(profile_name) = profile_name else {
        return Ok(ResolvedVerifyInputs {
            hmac_key: None,
            anchor: None,
            anchor_skip_reason: Some(
                "no --profile supplied; the tip anchor is held per profile".to_owned(),
            ),
        });
    };
    let resolved = ResolvedProfileName::from_flag(profile_name);
    let profile = load_profile_for_verify(&resolved)?;
    init_platform_keyring_store()?;
    resolve_profile_inputs_with_profile(&profile, profile_name, log_path)
}

/// The half of [`resolve_profile_inputs`] that works from an already-loaded
/// profile.
///
/// Split out so the path-scope rule and the absent-anchor case are reachable
/// without a persisted profile file.
///
/// The profile's audit binding is read first and never written: a record that
/// differs or does not parse refuses with `audit.log_binding_changed`, an
/// absent or equal one proceeds, and a read error fails closed.
fn resolve_profile_inputs_with_profile(
    profile: &Profile,
    profile_name: &str,
    log_path: &std::path::Path,
) -> Result<ResolvedVerifyInputs, WalletError> {
    check_audit_binding(profile, profile_name, BindingCheck::CheckOnly)?;
    let hmac_key = Some(load_audit_hmac_key(profile, profile_name)?);

    if normalize_path_lexically(log_path) != normalize_path_lexically(&profile.audit_log_path) {
        return Ok(ResolvedVerifyInputs {
            hmac_key,
            anchor: None,
            anchor_skip_reason: Some(format!(
                "the supplied log path is not the audit log profile '{profile_name}' \
                 configures; the tip anchor names a path, not a profile"
            )),
        });
    }

    let store = KeyringTipAnchorStore::new(&profile.audit_log_hash_chain_key_id, log_path);
    match store.load_anchor() {
        Ok(Some(anchor)) => Ok(ResolvedVerifyInputs {
            hmac_key,
            anchor: Some(anchor),
            anchor_skip_reason: None,
        }),
        Ok(None) => Ok(ResolvedVerifyInputs {
            hmac_key,
            anchor: None,
            anchor_skip_reason: Some(
                "no tip anchor has been written for this log path yet; it is adopted on the \
                 next value-moving verb"
                    .to_owned(),
            ),
        }),
        Err(e) => Err(WalletError::Internal(InternalError::UnexpectedState {
            detail: format!("audit.tip_anchor_unavailable: {e}"),
        })),
    }
}

/// Loads the named profile, reconciled, and maps the failure into the CLI
/// envelope model.
///
/// The cause is carried through rather than flattened: the HMAC key this
/// profile supplies decides whether the log verifies, so "the file names
/// another profile" and "the file is malformed" must be distinguishable in the
/// refusal.
fn load_profile_for_verify(resolved: &ResolvedProfileName) -> Result<Profile, WalletError> {
    let profile_name = &resolved.name;
    load_profile_reconciled(resolved).map_err(|e| {
        tracing::debug!(
            profile = %profile_name,
            error = %e,
            "profile access refused for audit verify"
        );
        e.to_wallet_error(profile_name)
    })
}

/// Loads and decodes the profile's audit-log HMAC key from keyring.
///
/// Secret residency follows the CLI key-loading pattern used by approval
/// attestation: keyring text and decoded bytes live in `Zeroizing` wrappers,
/// and errors report only non-secret keyring coordinates or fixed labels.
///
/// A coordinate in the owner key namespace is refused before the read, and a
/// key equal to the owner public key of `profile` selected as `profile_name`
/// is refused after decoding, both with
/// `validation.key_matches_owner_public_key`.
fn load_audit_hmac_key(
    profile: &Profile,
    profile_name: &str,
) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    use stellar_agent_core::profile::owner_key;
    let entry_ref = &profile.audit_log_hash_chain_key_id;
    owner_key::refuse_owner_key_coordinate(
        entry_ref,
        stellar_agent_network::keyring::AUDIT_KEY_FIELD,
    )?;
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        tracing::debug!(
            service = %entry_ref.service,
            "keyring Entry::new failed for audit verify HMAC key"
        );
        map_keyring_operation_error(&e, KeyringOperation::Construct, &entry_ref.service)
    })?;

    let secret_b64 = Zeroizing::new(entry.get_password().map_err(|e| {
        tracing::debug!(
            service = %entry_ref.service,
            "get_password failed for audit verify HMAC key"
        );
        map_keyring_operation_error(&e, KeyringOperation::Read, &entry_ref.service)
    })?);

    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(secret_b64.as_bytes()).map_err(|e| {
        tracing::debug!(error = %e, "audit verify HMAC key base64 decode failed");
        WalletError::Internal(InternalError::UnexpectedState {
            detail: "audit.key_decode_failed: audit HMAC key is not valid base64".to_owned(),
        })
    })?);

    if decoded.len() != 32 {
        return Err(WalletError::Internal(InternalError::UnexpectedState {
            detail: format!(
                "audit.key_length_error: audit HMAC key must be 32 bytes, got {}",
                decoded.len()
            ),
        }));
    }

    owner_key::refuse_owner_public_key(
        decoded.as_slice(),
        &owner_key::OwnerKeyContext::for_profile(profile_name, profile),
        stellar_agent_network::keyring::AUDIT_KEY_FIELD,
    )?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(decoded.as_slice());
    Ok(key)
}

/// Checks that the parent directory of `path` is owned by the invoking user.
///
/// Used on Unix to reject audit log paths whose parent directory is owned by
/// a different UID — such a directory could be used to substitute log files or
/// sidecars.
///
/// On Windows this function is not compiled (NTFS ACLs are used instead; see
/// the `#[cfg(unix)]` call site in [`run`]).
///
/// # Errors
///
/// Returns a human-readable error string when:
/// - The path has no parent directory component.
/// - The parent directory's metadata cannot be read.
/// - The parent directory's owner UID does not match the invoking user's UID.
#[cfg(unix)]
fn check_parent_owner(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let parent = path
        .parent()
        .ok_or_else(|| "audit log path must have a parent directory component".to_owned())?;

    let meta = std::fs::metadata(parent)
        .map_err(|e| format!("audit.io_error: cannot read parent directory metadata: {e}"))?;

    // Declare `geteuid` via the Rust 2024 `unsafe extern "C" { safe fn ... }`
    // pattern: the FFI declaration carries the `unsafe extern` qualifier (the
    // linker contract is unsafe), but `safe fn` asserts the call itself is
    // sound and lets us invoke it without an `unsafe` expression at the call
    // site.  This avoids both an inline `unsafe { ... }` block and a direct
    // `libc::geteuid()` call (which is itself `unsafe fn` and would still
    // require an `unsafe` block + `#[allow(unsafe_code)]`).
    //
    // SAFETY: POSIX-mandated signature; `geteuid()` takes no arguments,
    // cannot fail, and does not interact with Rust's memory model.  Narrowly
    // scoped to this function's path-owner check.
    #[allow(
        unsafe_code,
        reason = "POSIX geteuid() is infallible; the `safe fn` declaration in the \
                  unsafe-extern block is the idiomatic Rust 2024 pattern for known-safe FFI"
    )]
    let invoking_uid: u32 = {
        unsafe extern "C" {
            safe fn geteuid() -> u32;
        }
        geteuid()
    };
    let dir_uid = meta.uid();

    if invoking_uid != dir_uid {
        return Err(format!(
            "audit.path_owner_mismatch: parent directory of log file is owned by \
             UID {dir_uid} but the invoking user is UID {invoking_uid}; \
             refusing to verify a log whose directory is not owned by the current user"
        ));
    }

    Ok(())
}

/// Preserves each verifier code and its diagnostic text in the envelope.
/// A missing log carries the validation message with its remediation.
fn verify_failure(err: &VerifyError) -> VerifyFailure {
    match err {
        VerifyError::LogNotFound { path } => VerifyFailure::Wallet(WalletError::Validation(
            stellar_agent_core::ValidationError::AuditLogNotFound { path: path.clone() },
        )),
        _ => VerifyFailure::Raw {
            code: err.wire_code(),
            message: err.to_string(),
        },
    }
}

/// Writes the envelope to stdout in the requested format.
///
/// All variants currently emit compact JSON (JSON is the default and only
/// stable format; future variants will extend this match).
fn emit_envelope<T: Serialize>(envelope: &Envelope<T>, _format: OutputFormat) {
    // `#[non_exhaustive]` on `OutputFormat` — future variants default to JSON.
    // The explicit `Json` arm and the wildcard arm are byte-identical, so they
    // collapse to a single emit path.
    #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
    match envelope.to_json_compact() {
        Ok(json) => println!("{json}"),
        Err(e) => {
            #[allow(clippy::print_stderr, reason = "fatal serialisation failure")]
            {
                eprintln!("stellar-agent: JSON serialisation failed: {e}");
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use keyring_core::Entry as KeyringEntry;
    use serial_test::serial;
    use stellar_agent_core::PartialRotationState;
    use stellar_agent_core::audit_log::{
        entry::{AuditEntry, NewToolInvocation},
        schema::PolicyDecision,
        signer_set::SignerSetCanonicalBodyError,
        verify::verify_log,
        writer::AuditWriter,
    };
    use stellar_agent_core::profile::schema::Profile;
    use stellar_agent_test_support::keyring_mock;
    use tempfile::TempDir;

    #[test]
    fn no_profile_inputs_skip_hmac_and_anchor() {
        let inputs = resolve_profile_inputs(None, std::path::Path::new("audit.jsonl"))
            .expect("no profile is needed for hash-chain verification");
        assert!(inputs.hmac_key.is_none());
        assert!(inputs.anchor.is_none());
        assert_eq!(
            inputs.anchor_skip_reason.as_deref(),
            Some("no --profile supplied; the tip anchor is held per profile")
        );
    }

    fn make_writer_and_entries(path: PathBuf, count: usize, hmac_key: Option<&[u8; 32]>) {
        let hmac_key = hmac_key.map(|key| Zeroizing::new(*key));
        let mut writer = match hmac_key {
            Some(key) => AuditWriter::open_keyed_unanchored_for_test(path, key).unwrap(),
            None => AuditWriter::open(path, None).unwrap(),
        };
        for _ in 0..count {
            let entry = AuditEntry::new_tool_invocation(NewToolInvocation::new(
                "stellar_pay_commit",
                "stellar:testnet",
                vec!["destination".to_owned()],
                PolicyDecision::Allow,
                uuid::Uuid::new_v4().to_string(),
            ));
            writer.write_entry(entry).unwrap();
        }
    }

    #[tokio::test]
    async fn run_valid_log_exits_0() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        make_writer_and_entries(path.clone(), 3, None);

        let args = VerifyArgs {
            log_path: path,
            profile: None,
            output: OutputFormat::DEFAULT,
        };
        let code = run(&args).await;
        assert_eq!(code, 0);
    }

    #[tokio::test]
    async fn run_missing_log_exits_1() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.jsonl");

        let args = VerifyArgs {
            log_path: path,
            profile: None,
            output: OutputFormat::DEFAULT,
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }

    #[tokio::test]
    async fn run_empty_log_exits_0() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::File::create(&path).unwrap();

        let args = VerifyArgs {
            log_path: path,
            profile: None,
            output: OutputFormat::DEFAULT,
        };
        let code = run(&args).await;
        assert_eq!(code, 0);
    }

    #[test]
    #[serial]
    fn load_audit_hmac_key_decodes_profile_keyring_entry() {
        stellar_agent_test_support::keyring_mock::install().ok();

        let profile = Profile::builder_testnet_named(
            "audit-verify-key-test",
            "stellar-agent-signer",
            "audit-verify-key-test",
            "stellar-agent-nonce",
            "audit-verify-key-test",
        )
        .build();
        let key = [0x42u8; 32];
        let entry_ref = &profile.audit_log_hash_chain_key_id;
        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        entry.set_password(&URL_SAFE_NO_PAD.encode(key)).unwrap();

        let loaded = load_audit_hmac_key(&profile, "test-profile").unwrap();
        assert_eq!(loaded.as_ref(), &key);
    }

    #[test]
    #[serial]
    fn load_audit_hmac_key_rejects_wrong_length_key() {
        stellar_agent_test_support::keyring_mock::install().ok();

        let profile = Profile::builder_testnet_named(
            "audit-verify-short-key-test",
            "stellar-agent-signer",
            "audit-verify-short-key-test",
            "stellar-agent-nonce",
            "audit-verify-short-key-test",
        )
        .build();
        let entry_ref = &profile.audit_log_hash_chain_key_id;
        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        entry
            .set_password(&URL_SAFE_NO_PAD.encode([0x42u8; 31]))
            .unwrap();

        let Err(err) = load_audit_hmac_key(&profile, "test-profile") else {
            panic!("the load refuses");
        };
        assert!(
            matches!(
                err,
                WalletError::Internal(InternalError::UnexpectedState { .. })
            ),
            "expected UnexpectedState for wrong-length key, got {err:?}"
        );
    }

    /// An audit key equal to the owner public key in the older form refuses
    /// with the owner code naming the field. A G-strkey owner value is refused
    /// by the length rule, and an owner-namespace coordinate refuses before
    /// any read.
    #[test]
    #[serial]
    fn load_audit_hmac_key_refuses_owner_key_forms() {
        use stellar_agent_core::profile::schema::KeyringEntryRef;
        stellar_agent_test_support::keyring_mock::install().ok();
        let name = "audit-verify-owner";
        let mut profile = Profile::builder_testnet_named(name, "s", "a", "n", "a").build();
        let put = |entry_ref: &KeyringEntryRef, value: &str| {
            KeyringEntry::new(&entry_ref.service, &entry_ref.account)
                .unwrap()
                .set_password(value)
                .unwrap();
        };
        let older_form = URL_SAFE_NO_PAD.encode([0x3d_u8; 32]);
        put(&profile.audit_log_hash_chain_key_id, &older_form);
        assert!(load_audit_hmac_key(&profile, name).is_ok());
        put(&KeyringEntryRef::default_owner_key(name), &older_form);
        let Err(err) = load_audit_hmac_key(&profile, name) else {
            panic!("the load refuses");
        };
        assert_eq!(err.code(), "validation.key_matches_owner_public_key");
        assert!(
            err.to_string().contains("audit_log_hash_chain_key_id"),
            "{err}"
        );

        put(
            &profile.audit_log_hash_chain_key_id,
            &stellar_agent_core::profile::owner_key::encode_owner_public_key(&[0x3d; 32]),
        );
        let Err(err) = load_audit_hmac_key(&profile, name) else {
            panic!("the load refuses");
        };
        assert!(err.to_string().contains("got 42"), "{err}");

        profile.audit_log_hash_chain_key_id =
            KeyringEntryRef::new("stellar-agent-owner-B", "default");
        stellar_agent_test_support::keyring_mock::inject_error(
            "stellar-agent-owner-B",
            "default",
            keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other("planted"))),
        )
        .unwrap();
        let Err(err) = load_audit_hmac_key(&profile, name) else {
            panic!("the load refuses");
        };
        assert_eq!(err.code(), "validation.key_matches_owner_public_key");
        assert!(matches!(
            KeyringEntry::new("stellar-agent-owner-B", "default")
                .unwrap()
                .get_password(),
            Err(keyring_core::Error::PlatformFailure(_))
        ));
    }

    /// A non-interactive Windows session (the `ERROR_NO_SUCH_LOGON_SESSION`
    /// shape injected at the audit-key coordinates) must surface as
    /// `auth.keyring_interactive_session_required`, not `auth.keyring_not_found`.
    #[test]
    #[serial]
    fn load_audit_hmac_key_surfaces_interactive_session_required() {
        stellar_agent_test_support::keyring_mock::install().ok();

        let profile = Profile::builder_testnet_named(
            "audit-verify-no-logon-test",
            "stellar-agent-signer",
            "audit-verify-no-logon-test",
            "stellar-agent-nonce",
            "audit-verify-no-logon-test",
        )
        .build();
        let entry_ref = &profile.audit_log_hash_chain_key_id;
        stellar_agent_test_support::keyring_mock::inject_no_logon_session(
            &entry_ref.service,
            &entry_ref.account,
        )
        .unwrap();

        let Err(err) = load_audit_hmac_key(&profile, "test-profile") else {
            panic!("the load refuses");
        };
        assert_eq!(err.code(), "auth.keyring_interactive_session_required");
    }

    /// A platform-store failure at the audit-key coordinates must surface as
    /// `auth.keyring_platform_error`, not `auth.keyring_not_found`.
    #[test]
    #[serial]
    fn load_audit_hmac_key_surfaces_platform_error() {
        stellar_agent_test_support::keyring_mock::install().ok();

        let profile = Profile::builder_testnet_named(
            "audit-verify-platform-err-test",
            "stellar-agent-signer",
            "audit-verify-platform-err-test",
            "stellar-agent-nonce",
            "audit-verify-platform-err-test",
        )
        .build();
        let entry_ref = &profile.audit_log_hash_chain_key_id;
        stellar_agent_test_support::keyring_mock::inject_error(
            &entry_ref.service,
            &entry_ref.account,
            keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other(
                "simulated platform failure",
            ))),
        )
        .unwrap();

        let Err(err) = load_audit_hmac_key(&profile, "test-profile") else {
            panic!("the load refuses");
        };
        assert_eq!(err.code(), "auth.keyring_platform_error");
    }

    #[test]
    fn verify_log_with_profile_key_reports_hmac_verified() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let key = [0x42u8; 32];
        make_writer_and_entries(path.clone(), 3, Some(&key));

        let ok = verify_log(&path, Some(&key)).unwrap();
        assert!(ok.hmac_verified);
    }

    #[test]
    fn verify_log_without_profile_key_reports_hmac_unverified() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let key = [0x42u8; 32];
        make_writer_and_entries(path.clone(), 3, Some(&key));

        let ok = verify_log(&path, None).unwrap();
        assert!(!ok.hmac_verified);
    }

    #[test]
    fn verify_failure_preserves_all_wire_codes_and_messages() {
        let cases = [
            (
                VerifyError::ChainBroken {
                    line: 5,
                    file: "f.jsonl".to_owned(),
                    reason: "previous_entry_hash_mismatch",
                },
                "audit.chain_broken",
            ),
            (
                VerifyError::RotationGap {
                    file: "f.jsonl".to_owned(),
                },
                "audit.rotation_gap",
            ),
            (
                VerifyError::HmacMismatch {
                    file: "f.jsonl".to_owned(),
                },
                "audit.hmac_mismatch",
            ),
            (
                VerifyError::HmacSidecarMissing {
                    file: "f.jsonl".to_owned(),
                },
                "audit.hmac_sidecar_missing",
            ),
            (
                VerifyError::TooManyRotatedFiles { found: 99, cap: 10 },
                "audit.too_many_rotated_files",
            ),
            (
                VerifyError::NonRegularFileLogPath {
                    path: "f.jsonl".into(),
                },
                "audit.non_regular_file_log_path",
            ),
            (
                VerifyError::ParseError {
                    line: 1,
                    detail: "bad json".to_owned(),
                },
                "audit.parse_error",
            ),
            (
                VerifyError::PathContract {
                    detail: "invalid path".to_owned(),
                },
                "audit.path_contract",
            ),
            (
                VerifyError::LogNotFound {
                    path: "/tmp/audit.jsonl".to_owned(),
                },
                "audit.log_not_found",
            ),
            (
                VerifyError::Io(std::io::Error::other("read failed")),
                "audit.io_error",
            ),
            (
                VerifyError::SignerSetCanonicalBody(
                    SignerSetCanonicalBodyError::MalformedObservedSignerSet {
                        reason: "inconsistent count",
                    },
                ),
                "audit.signer_set_canonical_body",
            ),
            (
                VerifyError::PartialRotation {
                    state: PartialRotationState::MidRename {
                        tmp_path: "audit.tmp".into(),
                        size_bytes: 1,
                    },
                    recovery_hint: "recovery runbook".to_owned(),
                },
                "audit.partial_rotation",
            ),
            (
                VerifyError::TipAnchorMismatch {
                    expected_count: 2,
                    expected_offset: 20,
                    actual_count: 1,
                    actual_offset: 10,
                    reason: "count mismatch",
                },
                "audit.tip_anchor_mismatch",
            ),
        ];
        for (err, expected_code) in cases {
            match verify_failure(&err) {
                VerifyFailure::Raw { code, message } => {
                    assert_ne!(expected_code, "audit.log_not_found");
                    assert_eq!(code, expected_code);
                    assert_eq!(message, err.to_string());
                }
                VerifyFailure::Wallet(error) => {
                    assert_eq!(expected_code, "audit.log_not_found");
                    assert_eq!(error.code(), expected_code);
                    assert_eq!(
                        error.category(),
                        stellar_agent_core::ErrorCategory::Validation
                    );
                    assert_eq!(
                        error.message(),
                        "audit log not found at /tmp/audit.jsonl; nothing has been written to the audit log yet, or the log path is incorrect"
                    );
                }
            }
        }
    }

    /// Verifier diagnostics carry their wire code exactly once.
    #[test]
    fn verify_failure_message_has_single_code_prefix() {
        for (err, code) in [
            (
                VerifyError::ChainBroken {
                    line: 5,
                    file: "f.jsonl".to_owned(),
                    reason: "previous_entry_hash_mismatch",
                },
                "audit.chain_broken",
            ),
            (
                VerifyError::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "denied",
                )),
                "audit.io_error",
            ),
        ] {
            let VerifyFailure::Raw { message, .. } = verify_failure(&err) else {
                panic!("verifier diagnostics use raw envelopes");
            };
            assert_eq!(
                message.matches(&format!("{code}:")).count(),
                1,
                "message must contain the wire code prefix exactly once (not doubled), \
                 got: {message}"
            );
        }
    }

    /// A missing primary log classifies as validation-class with the
    /// `audit.log_not_found` code and an actionable, single-prefix message.
    #[test]
    fn verify_failure_log_not_found_is_validation_class() {
        let err = VerifyError::LogNotFound {
            path: "/tmp/audit.jsonl".to_owned(),
        };
        let VerifyFailure::Wallet(we) = verify_failure(&err) else {
            panic!("missing log has a validation error");
        };
        assert!(
            matches!(we, stellar_agent_core::WalletError::Validation(_)),
            "missing primary log must be validation-class, got {we:?}"
        );
        assert_eq!(
            we.code(),
            "audit.log_not_found",
            "envelope code must be audit.log_not_found"
        );
        let message = we.message();
        assert!(
            message.contains("/tmp/audit.jsonl"),
            "message must name the missing path: {message}"
        );
        assert!(
            !message.contains("audit.log_not_found:"),
            "the code is the envelope code field, not a message prefix: {message}"
        );
    }

    /// `verify_log_with_health` returns the same entries/files count as
    /// `verify_log`, with `audit_writer_degraded` reflecting the health handle.
    #[test]
    fn verify_log_with_health_reports_degraded_state() {
        use stellar_agent_core::audit_log::health::AuditWriterHealth;
        use stellar_agent_core::audit_log::verify::verify_log_with_health;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        make_writer_and_entries(path.clone(), 2, None);

        let health = AuditWriterHealth::new();

        // Non-degraded path: health flag false initially.
        let handle = health.handle();
        let ok_with_health = verify_log_with_health(&path, None, None, &handle).unwrap();
        assert_eq!(ok_with_health.verify_ok.entries_verified, 2);
        assert!(
            !ok_with_health.audit_writer_degraded,
            "must start non-degraded"
        );

        // Degraded path: mark the health owner, then a fresh handle should flip.
        health.mark_degraded();
        let handle2 = health.handle();
        let ok_degraded = verify_log_with_health(&path, None, None, &handle2).unwrap();
        assert!(
            ok_degraded.audit_writer_degraded,
            "must reflect degradation from owner"
        );
    }

    // ── Tip-anchor reporting ─────────────────────────────────────────────────

    #[test]
    fn without_a_profile_the_anchor_is_reported_as_not_checked() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        make_writer_and_entries(path.clone(), 2, None);

        let args = VerifyArgs {
            log_path: path,
            profile: None,
            output: OutputFormat::DEFAULT,
        };
        let result = verify_to_result(&args).expect("the chain walk must still succeed");

        assert_eq!(result.entries_verified, 2, "the chain is still verified");
        assert_eq!(result.anchor.status, "not_checked");
        let reason = result.anchor.reason.expect("a skipped check must say why");
        assert!(
            reason.contains("--profile"),
            "the reason must name what is missing: {reason}"
        );
    }

    #[test]
    #[serial]
    fn a_path_other_than_the_profile_log_reports_the_anchor_as_not_checked() {
        keyring_mock::install().expect("mock keyring store");

        let dir = TempDir::new().unwrap();
        let profile_log = dir.path().join("audit.jsonl");
        let other_log = dir.path().join("elsewhere.jsonl");
        make_writer_and_entries(other_log.clone(), 1, None);

        let mut profile =
            Profile::builder_testnet("anchor-scope", "acct", "n-svc", "n-acct").build();
        profile.audit_log_path = profile_log;
        let coord = profile.audit_log_hash_chain_key_id.clone();
        stellar_agent_network::keyring::rotate_keyring_secret_32(&coord.service, &coord.account)
            .expect("seed audit key");

        let resolved = resolve_profile_inputs_with_profile(&profile, "anchor-scope", &other_log)
            .expect("a mismatched path is reported, not refused");
        assert!(resolved.anchor.is_none());
        let reason = resolved
            .anchor_skip_reason
            .expect("a skipped check must say why");
        assert!(
            reason.contains("names a path"),
            "the reason must explain that the anchor is path-scoped: {reason}"
        );
    }

    #[test]
    #[serial]
    fn an_unanchored_log_reports_the_anchor_as_not_checked() {
        keyring_mock::install().expect("mock keyring store");

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        make_writer_and_entries(path.clone(), 1, None);

        let mut profile =
            Profile::builder_testnet("anchor-absent", "acct", "n-svc", "n-acct").build();
        profile.audit_log_path = path.clone();
        let coord = profile.audit_log_hash_chain_key_id.clone();
        stellar_agent_network::keyring::rotate_keyring_secret_32(&coord.service, &coord.account)
            .expect("seed audit key");

        let resolved = resolve_profile_inputs_with_profile(&profile, "anchor-absent", &path)
            .expect("an unanchored log verifies as a plain chain walk");
        assert!(resolved.anchor.is_none());
        assert!(
            resolved
                .anchor_skip_reason
                .expect("a skipped check must say why")
                .contains("no tip anchor")
        );
    }

    /// A profile whose audit key is minted and whose log holds one entry.
    fn binding_profile(name: &str, dir: &std::path::Path) -> Profile {
        let path = dir.join("audit.jsonl");
        make_writer_and_entries(path.clone(), 1, None);
        let mut profile = Profile::builder_testnet(name, "acct", "n-svc", "n-acct").build();
        profile.audit_log_path = path;
        let coord = profile.audit_log_hash_chain_key_id.clone();
        stellar_agent_network::keyring::rotate_keyring_secret_32(&coord.service, &coord.account)
            .expect("seed audit key");
        profile
    }

    fn recorded_binding(name: &str) -> Option<String> {
        stellar_agent_network::keyring::KeyringAuditBindingStore::for_profile(name)
            .load_raw()
            .expect("read binding")
    }

    #[test]
    #[serial]
    fn verify_refuses_a_changed_binding() {
        keyring_mock::install().expect("mock keyring store");
        let dir = TempDir::new().unwrap();
        let profile = binding_profile("verify-binding", dir.path());
        let mut elsewhere = profile.clone();
        elsewhere.audit_log_path = dir.path().join("elsewhere.jsonl");
        let recorded = stellar_agent_core::audit_log::AuditBinding::for_profile(&elsewhere);
        stellar_agent_network::keyring::KeyringAuditBindingStore::for_profile("verify-binding")
            .store(&recorded)
            .expect("record a binding for another path");

        let Err(err) = resolve_profile_inputs_with_profile(
            &profile,
            "verify-binding",
            &profile.audit_log_path,
        ) else {
            panic!("a changed binding refuses");
        };
        assert_eq!(err.code(), "audit.log_binding_changed");
        assert!(
            recorded_binding("verify-binding") == Some(recorded.to_keyring_value()),
            "verify never rewrites the binding"
        );
    }

    #[test]
    #[serial]
    fn verify_reads_an_absent_binding_and_writes_nothing() {
        keyring_mock::install().expect("mock keyring store");
        let dir = TempDir::new().unwrap();
        let profile = binding_profile("verify-absent", dir.path());

        resolve_profile_inputs_with_profile(&profile, "verify-absent", &profile.audit_log_path)
            .expect("an absent binding proceeds");
        assert!(
            recorded_binding("verify-absent").is_none(),
            "verify records no binding"
        );

        let expected = stellar_agent_core::audit_log::AuditBinding::for_profile(&profile);
        stellar_agent_network::keyring::KeyringAuditBindingStore::for_profile("verify-absent")
            .store(&expected)
            .expect("record");
        resolve_profile_inputs_with_profile(&profile, "verify-absent", &profile.audit_log_path)
            .expect("an equal binding proceeds");
    }

    #[test]
    #[serial]
    fn verify_fails_closed_on_a_binding_read_error() {
        keyring_mock::install().expect("mock keyring store");
        let dir = TempDir::new().unwrap();
        let profile = binding_profile("verify-read-error", dir.path());
        let coordinate =
            stellar_agent_core::profile::schema::KeyringEntryRef::default_audit_binding(
                "verify-read-error",
            );
        keyring_mock::inject_error(
            &coordinate.service,
            &coordinate.account,
            keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("planted"))),
        )
        .expect("inject");

        let Err(err) = resolve_profile_inputs_with_profile(
            &profile,
            "verify-read-error",
            &profile.audit_log_path,
        ) else {
            panic!("a read error fails closed");
        };
        assert_eq!(
            err.category(),
            stellar_agent_core::error::ErrorCategory::Auth
        );
        assert!(
            recorded_binding("verify-read-error").is_none(),
            "a read error records nothing"
        );
    }

    #[test]
    fn a_tip_anchor_mismatch_carries_the_verifiers_own_detail() {
        let err = VerifyError::TipAnchorMismatch {
            expected_count: 12,
            expected_offset: 3400,
            actual_count: 9,
            actual_offset: 2600,
            reason: "the active file's tip is not the anchored tip",
        };
        let VerifyFailure::Raw { code, message } = verify_failure(&err) else {
            panic!("a tip-anchor mismatch must carry the verifier's own message");
        };
        assert_eq!(code, "audit.tip_anchor_mismatch");
        for expected in ["12", "3400", "9", "2600", "is not the anchored tip"] {
            assert!(
                message.contains(expected),
                "the message must keep the verifier's {expected}: {message}"
            );
        }
        assert!(
            !message.contains("signing refuses"),
            "`audit verify` does not sign; the signing sentence must not appear: {message}"
        );
        assert!(
            !message.contains("sha256:"),
            "no digest in an operator-facing refusal: {message}"
        );
    }

    // ── The audit outbox ──────────────────────────────────────────────────────

    fn queue_consent(path: &std::path::Path, request_id: &str) {
        stellar_agent_core::audit_log::AuditOutbox::for_log(path)
            .append(
                &stellar_agent_core::audit_log::AuditEntry::new_approval_attested(
                    "PaymentSimulated",
                    "stellar_pay_commit",
                    None,
                    "ABCDEFGHIJKLMNOPQRSTUV",
                    "cli",
                    request_id,
                ),
            )
            .unwrap();
    }

    fn append_to_outbox(path: &std::path::Path, bytes: &[u8]) {
        use std::io::Write as _;
        let outbox = stellar_agent_core::audit_log::AuditOutbox::for_log(path);
        std::fs::OpenOptions::new()
            .append(true)
            .open(outbox.path())
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    #[test]
    fn verify_reports_outbox_pending_and_warns_on_a_torn_outbox() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        make_writer_and_entries(path.clone(), 2, None);
        queue_consent(&path, "queued-1");
        queue_consent(&path, "queued-2");
        append_to_outbox(&path, b"{\"ts\":\"torn");

        let result = verify_to_result(&VerifyArgs {
            log_path: path,
            profile: None,
            output: OutputFormat::DEFAULT,
        })
        .unwrap_or_else(|_| panic!("the chain verdict is unchanged"));
        assert_eq!(result.entries_verified, 2);
        assert_eq!(result.outbox_pending, Some(2));
        assert!(
            result
                .warnings
                .iter()
                .any(|w| matches!(w, VerifyWarning::OutboxTornTail { torn_bytes: 11 })),
            "{:?}",
            result.warnings
        );
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["outbox_pending"], 2);
    }

    #[test]
    fn verify_warns_on_an_unparseable_outbox_line_and_keeps_the_verdict() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        make_writer_and_entries(path.clone(), 1, None);
        queue_consent(&path, "queued-1");
        append_to_outbox(&path, b"not an audit entry\n");

        let result = verify_to_result(&VerifyArgs {
            log_path: path,
            profile: None,
            output: OutputFormat::DEFAULT,
        })
        .unwrap_or_else(|_| panic!("the chain verdict is unchanged"));
        assert_eq!(result.outbox_pending, Some(2), "every complete line counts");
        assert!(
            result.warnings.iter().any(
                |w| matches!(w, VerifyWarning::OutboxUnparseable { lines } if lines == &vec![2])
            ),
            "{:?}",
            result.warnings
        );
    }

    #[test]
    fn verify_without_an_outbox_reports_nothing_pending() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        make_writer_and_entries(path.clone(), 1, None);
        let result = verify_to_result(&VerifyArgs {
            log_path: path,
            profile: None,
            output: OutputFormat::DEFAULT,
        })
        .unwrap_or_else(|_| panic!("verifies"));
        assert_eq!(
            result.outbox_pending,
            Some(0),
            "an absent outbox counts zero"
        );
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["outbox_pending"], 0);
    }

    /// An outbox that cannot be read has no count: the field is omitted, the
    /// warning names the condition, and the chain verdict is unchanged. An
    /// empty outbox, by contrast, counts zero with no warning.
    #[test]
    fn verify_reports_no_count_for_an_unreadable_outbox() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        make_writer_and_entries(path.clone(), 2, None);
        let outbox = stellar_agent_core::audit_log::AuditOutbox::for_log(&path);
        let args = || VerifyArgs {
            log_path: path.clone(),
            profile: None,
            output: OutputFormat::DEFAULT,
        };

        std::fs::write(outbox.path(), b"").unwrap();
        let empty = verify_to_result(&args()).unwrap_or_else(|_| panic!("verifies"));
        assert_eq!(empty.outbox_pending, Some(0), "an empty outbox counts zero");
        assert!(empty.warnings.is_empty(), "{:?}", empty.warnings);

        // A directory in the outbox's place cannot be read as a file.
        std::fs::remove_file(outbox.path()).unwrap();
        std::fs::create_dir(outbox.path()).unwrap();
        let unreadable =
            verify_to_result(&args()).unwrap_or_else(|_| panic!("the chain verdict is unchanged"));
        assert_eq!(unreadable.entries_verified, 2);
        assert_eq!(unreadable.outbox_pending, None, "no count is reported");
        assert!(
            unreadable
                .warnings
                .iter()
                .any(|w| matches!(w, VerifyWarning::OutboxUnreadable { .. })),
            "{:?}",
            unreadable.warnings
        );
        let json = serde_json::to_value(&unreadable).unwrap();
        assert!(
            json.get("outbox_pending").is_none(),
            "an unreadable outbox omits the count: {json}"
        );
    }
}
