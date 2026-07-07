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
use stellar_agent_core::{
    audit_log::{
        health::AuditWriterHealth,
        verify::{FileVerifyResult, VerifyError, VerifyWarning, verify_log_with_health},
    },
    envelope::{Envelope, OutputFormat},
    error::{AuthError, InternalError, ValidationError, WalletError},
    profile::{loader, schema::Profile},
};
use stellar_agent_network::keyring::init_platform_keyring_store;
use zeroize::Zeroizing;

/// Arguments for the `audit verify` subcommand.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Path to the audit log file to verify.
    ///
    /// Typically `~/.local/state/stellar-agent/audit/<profile>.jsonl` on
    /// Linux, `~/Library/Application Support/stellar-agent/audit/<profile>.jsonl`
    /// on macOS, or `%LOCALAPPDATA%\stellar-agent\audit\<profile>.jsonl` on
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

    let hmac_key = match resolve_hmac_key(args.profile.as_deref()) {
        Ok(key) => key,
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            emit_envelope(&envelope, args.output);
            return 1;
        }
    };
    // Create a fresh health instance — in the CLI context the health latch is
    // never marked degraded (health is a session property of the MCP server).
    // Using `verify_log_with_health` ensures the output schema is consistent
    // with any future MCP-tool caller that has access to a live handle.
    let health = AuditWriterHealth::new();
    let handle = health.handle();
    match verify_log_with_health(&args.log_path, hmac_key.as_deref(), &handle) {
        Ok(ok_with_health) => {
            let ok = ok_with_health.verify_ok;
            let result = AuditVerifyResult {
                entries_verified: ok.entries_verified,
                files_walked: ok.files_walked,
                hmac_verified: ok.hmac_verified,
                per_file: ok.per_file,
                warnings: ok.warnings,
                audit_writer_degraded: ok_with_health.audit_writer_degraded,
            };
            let envelope = Envelope::ok(result);
            emit_envelope(&envelope, args.output);
            0
        }
        Err(err) => {
            let wallet_err = map_verify_error(&err);
            let envelope = Envelope::<()>::err(&wallet_err);
            emit_envelope(&envelope, args.output);
            1
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Resolves the optional audit-log HMAC key requested by `--profile`.
fn resolve_hmac_key(
    profile_name: Option<&str>,
) -> Result<Option<Zeroizing<[u8; 32]>>, WalletError> {
    let Some(profile_name) = profile_name else {
        return Ok(None);
    };

    let profile = load_profile_for_verify(profile_name)?;
    init_platform_keyring_store()?;
    load_audit_hmac_key(&profile).map(Some)
}

/// Loads the named profile and maps loader errors into the CLI envelope model.
fn load_profile_for_verify(profile_name: &str) -> Result<Profile, WalletError> {
    loader::load(profile_name, None).map_err(|e| match e {
        loader::ProfileLoadError::NotFound { name, .. } => {
            WalletError::Validation(ValidationError::ProfileNotFound { name })
        }
        _ => {
            tracing::debug!(profile = %profile_name, error = %e, "profile load failed for audit verify");
            WalletError::Validation(ValidationError::ProfileNotFound {
                name: profile_name.to_owned(),
            })
        }
    })
}

/// Loads and decodes the profile's audit-log HMAC key from keyring.
///
/// Secret residency follows the CLI key-loading pattern used by approval
/// attestation: keyring text and decoded bytes live in `Zeroizing` wrappers,
/// and errors report only non-secret keyring coordinates or fixed labels.
fn load_audit_hmac_key(profile: &Profile) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    let entry_ref = &profile.audit_log_hash_chain_key_id;
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        tracing::debug!(
            error = %e,
            service = %entry_ref.service,
            "keyring Entry::new failed for audit verify HMAC key"
        );
        WalletError::Auth(AuthError::KeyringNotFound {
            name: format!("{}:{}", entry_ref.service, entry_ref.account),
        })
    })?;

    let secret_b64 = Zeroizing::new(entry.get_password().map_err(|e| {
        tracing::debug!(
            error = %e,
            service = %entry_ref.service,
            "get_password failed for audit verify HMAC key"
        );
        WalletError::Auth(AuthError::KeyringNotFound {
            name: format!("{}:{}", entry_ref.service, entry_ref.account),
        })
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

/// Maps a [`VerifyError`] to a [`stellar_agent_core::WalletError`] for
/// uniform envelope output.
///
/// # Mapping rationale
///
/// All integrity violations (`ChainBroken`, `RotationGap`, `HmacMismatch`,
/// `HmacSidecarMissing`) map to
/// `WalletError::Internal(InternalError::InvariantViolated)`.  The audit log
/// being corrupt IS an invariant violation at the substrate level — it
/// indicates that the tamper-evidence guarantee has been compromised.  Using
/// `WalletError::Auth` would imply the violation is in an auth flow; these
/// errors instead mean the audit infrastructure itself has been tampered with.
///
/// `ParseError` also maps to `InvariantViolated` because parseable log lines
/// are a hard invariant (a log line that cannot be parsed means the file was
/// externally modified).
///
/// `PathContract` and `Io` map to `Internal(UnexpectedState)` because the log
/// path must satisfy the verifier contract and the log file should be readable
/// when the path is correct.
///
/// `LogNotFound` maps to `Validation(AuditLogNotFound)` — a missing primary log
/// is a user-actionable condition (nothing logged yet, or a wrong path), not an
/// integrity violation, and surfaces the `audit.log_not_found` wire code with
/// an actionable message.
///
/// The `detail` is the `VerifyError` Display string alone: every variant's
/// Display already begins with its own wire code (e.g. `"audit.io_error: ..."`),
/// so prefixing `wire_code()` again would double it.
fn map_verify_error(err: &VerifyError) -> stellar_agent_core::WalletError {
    use stellar_agent_core::error::{InternalError, ValidationError};

    let msg = err.to_string();

    match err {
        VerifyError::LogNotFound { path } => {
            stellar_agent_core::WalletError::Validation(ValidationError::AuditLogNotFound {
                path: path.clone(),
            })
        }
        VerifyError::ChainBroken { .. }
        | VerifyError::RotationGap { .. }
        | VerifyError::HmacMismatch { .. }
        | VerifyError::HmacSidecarMissing { .. }
        | VerifyError::ParseError { .. } => {
            stellar_agent_core::WalletError::Internal(InternalError::InvariantViolated {
                detail: msg,
            })
        }
        VerifyError::PathContract { .. } | VerifyError::Io(_) => {
            stellar_agent_core::WalletError::Internal(InternalError::UnexpectedState {
                detail: msg,
            })
        }
        _ => stellar_agent_core::WalletError::Internal(InternalError::UnexpectedState {
            detail: msg,
        }),
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
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "test-only")]
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use keyring_core::Entry as KeyringEntry;
    use serial_test::serial;
    use stellar_agent_core::audit_log::{
        entry::{AuditEntry, NewToolInvocation},
        schema::PolicyDecision,
        verify::verify_log,
        writer::AuditWriter,
    };
    use stellar_agent_core::profile::schema::Profile;
    use tempfile::TempDir;

    fn make_writer_and_entries(path: PathBuf, count: usize, hmac_key: Option<&[u8; 32]>) {
        let hmac_key = hmac_key.map(|key| Zeroizing::new(*key));
        let mut writer = AuditWriter::open(path, hmac_key).unwrap();
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

    /// A tampered hash chain must be detected: corrupting any byte in a
    /// non-final line invalidates the hash recorded in the following entry's
    /// `previous_entry_hash` field, so `run` must return exit code 1.
    ///
    /// This test would fail (returning 0) if the hash-chain verification were
    /// removed or broken, because the tamper would go undetected.
    #[tokio::test]
    async fn run_tampered_log_exits_1() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit_tampered.jsonl");

        // Write 3 valid entries so the chain has at least one non-final line
        // (line 1) whose corruption will be detected by line 2's check.
        make_writer_and_entries(path.clone(), 3, None);

        // Read the file, corrupt one byte in the first (non-final) line, and
        // write the modified content back.  Changing any byte in the JSON body
        // of a non-final line causes the next entry's `previous_entry_hash`
        // check to fail.
        let content = std::fs::read(&path).unwrap();
        let first_newline = content
            .iter()
            .position(|&b| b == b'\n')
            .expect("at least one newline must exist");
        // Corrupt one byte in the middle of the first line.  The byte chosen
        // is well inside the JSON body (not at the very start of the line,
        // which might be whitespace or `{`).  XOR with 0x01 flips the
        // lowest bit — guaranteed to change the byte regardless of its value.
        let mut tampered = content.clone();
        let corrupt_pos = first_newline / 2;
        tampered[corrupt_pos] ^= 0x01;
        std::fs::write(&path, &tampered).unwrap();

        let args = VerifyArgs {
            log_path: path,
            profile: None,
            output: OutputFormat::DEFAULT,
        };
        let code = run(&args).await;
        assert_eq!(code, 1, "tampered hash chain must exit with code 1");
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

        let loaded = load_audit_hmac_key(&profile).unwrap();
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

        let err = load_audit_hmac_key(&profile).unwrap_err();
        assert!(
            matches!(
                err,
                WalletError::Internal(InternalError::UnexpectedState { .. })
            ),
            "expected UnexpectedState for wrong-length key, got {err:?}"
        );
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
    fn map_verify_error_chain_broken_is_invariant_violated() {
        let err = VerifyError::ChainBroken {
            line: 5,
            file: "f.jsonl".to_owned(),
            reason: "previous_entry_hash_mismatch",
        };
        let we = map_verify_error(&err);
        assert!(
            matches!(
                we,
                stellar_agent_core::WalletError::Internal(
                    stellar_agent_core::InternalError::InvariantViolated { .. }
                )
            ),
            "expected InvariantViolated, got {we:?}"
        );
    }

    #[test]
    fn map_verify_error_rotation_gap_is_invariant_violated() {
        let err = VerifyError::RotationGap {
            file: "missing.jsonl".to_owned(),
        };
        let we = map_verify_error(&err);
        assert!(
            matches!(
                we,
                stellar_agent_core::WalletError::Internal(
                    stellar_agent_core::InternalError::InvariantViolated { .. }
                )
            ),
            "expected InvariantViolated, got {we:?}"
        );
    }

    #[test]
    fn map_verify_error_hmac_mismatch_is_invariant_violated() {
        let err = VerifyError::HmacMismatch {
            file: "f.jsonl".to_owned(),
        };
        let we = map_verify_error(&err);
        assert!(
            matches!(
                we,
                stellar_agent_core::WalletError::Internal(
                    stellar_agent_core::InternalError::InvariantViolated { .. }
                )
            ),
            "expected InvariantViolated, got {we:?}"
        );
    }

    #[test]
    fn map_verify_error_hmac_sidecar_missing_is_invariant_violated() {
        let err = VerifyError::HmacSidecarMissing {
            file: "f.jsonl".to_owned(),
        };
        let we = map_verify_error(&err);
        assert!(
            matches!(
                we,
                stellar_agent_core::WalletError::Internal(
                    stellar_agent_core::InternalError::InvariantViolated { .. }
                )
            ),
            "expected InvariantViolated, got {we:?}"
        );
    }

    #[test]
    fn map_verify_error_parse_error_is_invariant_violated() {
        let err = VerifyError::ParseError {
            line: 1,
            detail: "bad json".to_owned(),
        };
        let we = map_verify_error(&err);
        assert!(
            matches!(
                we,
                stellar_agent_core::WalletError::Internal(
                    stellar_agent_core::InternalError::InvariantViolated { .. }
                )
            ),
            "expected InvariantViolated, got {we:?}"
        );
    }

    #[test]
    fn map_verify_error_io_is_unexpected_state() {
        let err = VerifyError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ));
        let we = map_verify_error(&err);
        assert!(
            matches!(
                we,
                stellar_agent_core::WalletError::Internal(
                    stellar_agent_core::InternalError::UnexpectedState { .. }
                )
            ),
            "expected UnexpectedState, got {we:?}"
        );
    }

    #[test]
    fn map_verify_error_path_contract_is_unexpected_state() {
        let err = VerifyError::PathContract {
            detail: "log path has no UTF-8 file name".to_owned(),
        };
        let we = map_verify_error(&err);
        assert!(
            matches!(
                we,
                stellar_agent_core::WalletError::Internal(
                    stellar_agent_core::InternalError::UnexpectedState { .. }
                )
            ),
            "expected UnexpectedState, got {we:?}"
        );
    }

    /// The envelope message must carry each variant's wire code exactly once —
    /// `VerifyError` Display already begins with the code, so `map_verify_error`
    /// must not prepend it again. Covers two variants across both `Internal`
    /// arms.
    #[test]
    fn map_verify_error_message_has_single_code_prefix() {
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
            let message = map_verify_error(&err).message();
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
    fn map_verify_error_log_not_found_is_validation_class() {
        let err = VerifyError::LogNotFound {
            path: "/tmp/audit.jsonl".to_owned(),
        };
        let we = map_verify_error(&err);
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
        let ok_with_health = verify_log_with_health(&path, None, &handle).unwrap();
        assert_eq!(ok_with_health.verify_ok.entries_verified, 2);
        assert!(
            !ok_with_health.audit_writer_degraded,
            "must start non-degraded"
        );

        // Degraded path: mark the health owner, then a fresh handle should flip.
        health.mark_degraded();
        let handle2 = health.handle();
        let ok_degraded = verify_log_with_health(&path, None, &handle2).unwrap();
        assert!(
            ok_degraded.audit_writer_degraded,
            "must reflect degradation from owner"
        );
    }
}
