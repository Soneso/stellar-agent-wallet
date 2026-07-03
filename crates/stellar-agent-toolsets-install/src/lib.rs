//! Toolset install and uninstall with cryptographic provenance for the Stellar
//! agent wallet.
//!
//! ## What this crate does
//!
//! Installs and uninstalls toolsets with cryptographic provenance:
//!
//! 1. **Hash verification** — SHA-256 of the package bytes is compared to the
//!    signed `shasum` (constant-time).
//! 2. **Publisher signature + trust set** — ed25519 `verify_strict` over a
//!    canonical domain-separated, length-prefixed preimage; signer must be in
//!    the local trust set.
//! 3. **Safe extraction** — iterate tar entries with type-first checks, lexical
//!    containment, no-follow writes, ASCII-only entry-name gate, and size
//!    bounds; NEVER `tar::Archive::unpack`.
//! 4. **Parse + validate** — calls `stellar-agent-toolsets::parse_toolset`
//!    on the extracted directory.
//! 5. **Attestation gate** — if the toolset declares a key-touching capability
//!    (e.g. `sign-payment`), verifies an auditor `ToolsetAttestation` signed by a
//!    key in `auditor-trust.txt` over `(package, version, shasum, capabilities)`.
//!    The gate fires AFTER the identity cross-check and BEFORE the atomic
//!    rename, so it can never be confused by an unverified identity.  A named
//!    override (`override_attestation: true`) logs a structured warn and
//!    proceeds.
//! 6. **Pin record** — atomic write of `(package, version, shasum, publisher,
//!    installed_at, capabilities, allowed_tools)` after successful extraction.
//! 7. **Uninstall** — reconstructs the directory path from the validated pin
//!    package name; no-follow removal.
//!
//! ## What this crate does NOT do
//!
//! - Runtime MCP/CLI tool registration or capability enforcement — these belong
//!   to the separate runtime layer that consumes the pin record.
//! - First-invoke gate — also a runtime-layer concern.
//! - Auditor network or hosted/on-chain registry.
//! - Hosted registry fetch.
//!
//! ## Extraction safety model
//!
//! **Verification proves ORIGIN + INTEGRITY, not content SAFETY.**  A
//! trusted-but-compromised publisher or an operator-added-unaudited key can
//! still ship hostile content.  The extractor (`extract`) and parser
//! (`stellar-agent-toolsets::parse_toolset`) MUST be safe on fully-adversarial
//! bytes on their own merits.  Verify-before-extract is defence-in-depth
//! only, not the safety boundary.
//!
//! ## Capability-source invariant
//!
//! **INVARIANT:** the install-time capability gate, the attestation preimage
//! binding, and the runtime capability grant ALL read capabilities from the
//! **signature-verified pin record**, which is written from the parse of the
//! signature-verified bytes.  NONE of them re-parse the post-install on-disk
//! `TOOLSET.md`.  This closes the capability-omission/post-install-tamper bypass:
//! a toolset installed with no declared capability whose on-disk `TOOLSET.md` is
//! later edited to add `sign-payment` is still refused at the signing path,
//! because the runtime grant reads the pin, not the file.
//!
//! ## Sibling crates
//!
//! - `stellar-agent-toolsets` — toolset format parse + validation.
//! - `stellar-agent-core` — profile management, `default_toolsets_dir()`.
//!
//! The wallet CLI and MCP server are the intended consumers of the
//! `install_toolset` / `uninstall_toolset` API.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Auditor attestation format, verification, and trust-set.
///
/// Exposed publicly so that integration tests can verify the canonical
/// attestation preimage byte layout against
/// `tests/vectors/toolset-attestation-v1.json`.
pub mod attestation;
pub mod error;
pub(crate) mod extract;
pub(crate) mod hash;
pub(crate) mod pin;
/// Low-level signature primitives.
///
/// Exposed publicly so that integration tests can verify the canonical
/// preimage byte layout against `tests/vectors/toolset-sig-v1.json`.
pub mod signature;

pub use attestation::{ATTESTATION_DOMAIN_TAG, ToolsetAttestation, load_auditor_trust_set};
pub use error::ToolsetInstallError;
pub use hash::sha256_hex_of;
pub use pin::{ToolsetPinRecord, read_pin};
pub use signature::{DOMAIN_TAG, load_trust_set, parse_trust_set_content};
pub use stellar_agent_toolsets::CapabilitySet;

/// The outcome of the attestation gate from a successful install.
///
/// Returned by [`install_toolset`] and [`install_toolset_from_path`] so callers
/// can report the actual gate decision rather than inferring it from inputs.
/// The variant reflects what the gate ACTUALLY did, not what flags were set:
///
/// - `Attested` — the toolset declared a key-touching capability AND a valid
///   attestation from a trusted auditor was verified.
/// - `Overridden` — the toolset declared a key-touching capability AND the gate
///   was bypassed via `override_attestation = true` (effective override: the
///   flag actually suppressed a firing gate).
/// - `NotRequired` — the toolset declared no key-touching capabilities; the
///   attestation gate did not fire regardless of what flags were set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationOutcome {
    /// A valid attestation from a trusted auditor was verified.
    Attested,
    /// The gate was bypassed via `override_attestation`; this was an effective
    /// bypass (key-touching toolset, gate would have refused without it).
    Overridden,
    /// The toolset has no key-touching capabilities; gate did not fire.
    NotRequired,
}

impl AttestationOutcome {
    /// Returns a lowercase ASCII string suitable for JSON output.
    ///
    /// - `"attested"` for [`AttestationOutcome::Attested`]
    /// - `"overridden"` for [`AttestationOutcome::Overridden`]
    /// - `"not-required"` for [`AttestationOutcome::NotRequired`]
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_toolsets_install::AttestationOutcome;
    ///
    /// assert_eq!(AttestationOutcome::Attested.as_str(), "attested");
    /// assert_eq!(AttestationOutcome::Overridden.as_str(), "overridden");
    /// assert_eq!(AttestationOutcome::NotRequired.as_str(), "not-required");
    /// ```
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attested => "attested",
            Self::Overridden => "overridden",
            Self::NotRequired => "not-required",
        }
    }
}

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::Path;

use semver::Version;
use stellar_strkey::ed25519::PublicKey as StrPublicKey;
use tracing::{debug, info, warn};

// ── Size and count limits ─────────────────────────────────────────────────────

/// Maximum package file size in bytes (16 MiB).
///
/// Reading is aborted at this limit without buffering the full input
/// (`Read::take` guard).
pub const MAX_PACKAGE_BYTES: usize = 16 * 1024 * 1024;

/// Maximum total decompressed output size in bytes (64 MiB).
///
/// Applied as a `Read::take` cap on the gzip decoder output to prevent
/// decompression bombs.
pub const MAX_TOTAL_DECOMPRESSED: usize = 64 * 1024 * 1024;

/// Maximum per-entry decompressed size in bytes (32 MiB).
pub const MAX_ENTRY_BYTES: usize = 32 * 1024 * 1024;

/// Maximum number of archive entries.
pub const MAX_ENTRIES: usize = 4_096;

/// Maximum entry name length in bytes.
pub const MAX_NAME_LEN: usize = 4_096;

/// Maximum path component count.
pub const MAX_NAME_COMPONENTS: usize = 64;

/// Maximum trust-set file size in bytes.
pub const MAX_TRUST_SET_BYTES: usize = 64 * 1024;

/// Maximum number of entries in the trust set.
pub const MAX_TRUST_SET_ENTRIES: usize = 1_024;

/// Maximum attestation JSON file size in bytes (16 KiB).
///
/// A `ToolsetAttestation` JSON contains at most: a package name (≤ 64 bytes), a
/// version string (≤ 64 bytes), a 64-char hex shasum, a short capability token
/// list (a handful of tokens ≤ ~256 bytes each), a 64-char hex auditor pubkey,
/// and a 128-char hex signature.  Even accounting for JSON field names and
/// whitespace the well-formed maximum is well under 1 KiB.  16 KiB is two
/// orders of magnitude above the content-driven maximum and prevents a trivial
/// DoS via a large attacker-controlled file.
///
/// The attestation file is attacker-controllable (the path comes from the CLI).
/// Like `MAX_TRUST_SET_BYTES` and `MAX_PACKAGE_BYTES`, reading is aborted at
/// this limit without buffering the full input.
pub const MAX_ATTESTATION_BYTES: usize = 16 * 1024;

/// Maximum version string length in bytes (before SemVer parse).
pub const MAX_VERSION_LEN: usize = 64;

// ── Install options ───────────────────────────────────────────────────────────

/// Options for [`install_toolset`].
///
/// # Examples
///
/// ```
/// use stellar_agent_toolsets_install::InstallOptions;
///
/// // Default: refuse reinstall, refuse downgrade, refuse attestation bypass.
/// let opts = InstallOptions::default();
/// assert!(!opts.force);
/// assert!(!opts.allow_downgrade);
/// assert!(!opts.override_attestation);
/// ```
#[derive(Debug, Clone, Default)]
pub struct InstallOptions {
    /// If `true`, reinstall even if the toolset is already installed.
    ///
    /// The existing installation is uninstalled first (through the pin record),
    /// then the new version is installed.  A version downgrade is still refused
    /// unless `allow_downgrade` is also `true`.
    pub force: bool,

    /// If `true`, allow installing a version older than the installed one.
    ///
    /// Only meaningful when `force` is also `true`.  Without `force`, the
    /// `AlreadyInstalled` error fires before the downgrade check.
    pub allow_downgrade: bool,

    /// If `true`, bypass the attestation gate for key-touching toolsets.
    ///
    /// When this flag is set AND a key-touching toolset has no valid attestation,
    /// the gate is skipped with an explicit structured `warn!` audit line and
    /// the install proceeds with outcome `overridden`.
    ///
    /// **This is the ONLY sanctioned bypass of the attestation gate.**  No
    /// environment variable, no config default, and no second bool skips the
    /// gate.
    ///
    /// Override skips only the INSTALL gate.  A toolset installed under override
    /// still has its `sign-payment` capability persisted INERT in the pin and
    /// still faces the first-invoke + forced per-action approval at signing
    /// time.
    ///
    /// The warn + `overridden` outcome fire ONLY when the override actually
    /// suppressed a firing gate — i.e. a key-touching toolset with no valid
    /// attestation.  Setting this flag on a non-key-touching toolset reports
    /// `not-required` as if the flag were absent.
    ///
    /// Defaults `false`.
    pub override_attestation: bool,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Installs a toolset from a signed `.tar.gz` package given as bytes.
///
/// ## Install flow
///
/// 1. Validate inputs (package name, version string, shasum format).
/// 2. Load publisher trust set.
/// 3. Check publisher trust set membership.
/// 4. Read package + recompute SHA-256 hash.
/// 5. Verify publisher ed25519 signature over the canonical preimage.
/// 6. Check already-installed per `options`.
/// 7. Safe-extract from the verified buffer to a staging directory.
/// 8. Parse + validate `TOOLSET.md`; rollback staging on failure.
/// 9. Identity cross-check: extracted `TOOLSET.md` `name` == `package`.
///    Step 9b — Attestation gate: if the verified capability set contains
///    any key-touching capability, load the auditor trust set and verify the
///    supplied `attestation` (or bypass if `override_attestation` is set).
///    Rollback staging on any refusal; NO pin is written on refusal.
/// 10. Atomic rename staging → final.
/// 11. Atomic pin write (capabilities persisted from signature-verified parse).
///
/// ## Attestation gate placement
///
/// The gate fires AFTER the identity cross-check (`toolset.name == package`) and
/// BEFORE the atomic rename.  This is the earliest point at which the declared
/// capability set AND the package identity are BOTH verified.  Running the gate
/// before the identity cross-check would allow an attestation to be validated
/// against an unconfirmed identity.
///
/// ## Capability-source invariant
///
/// The gate and the attestation preimage binding read capabilities from the
/// signature-verified parse of `TOOLSET.md` — NEVER from a re-parse of the
/// on-disk file.
///
/// ## Streaming cap
///
/// This entry point accepts a pre-read `&[u8]` buffer.  The caller is
/// responsible for applying the [`MAX_PACKAGE_BYTES`] cap before calling
/// this function.  For file-path based install with an automatic cap, use
/// [`install_toolset_from_path`] instead — the CLI MUST use that entry point.
///
/// ## Security invariant
///
/// Extraction and parsing are safe on adversarial bytes on their own merits.
/// Signature verification is defence-in-depth, not the safety boundary.
///
/// # Errors
///
/// Returns a [`ToolsetInstallError`] variant for any failure in the above steps.
///
/// # Examples
///
/// ```rust,ignore
/// // The byte values below are illustrative placeholders.
/// // A real call requires a genuine signed package, a correct SHA-256
/// // shasum, a valid ed25519 signature, and a trusted publisher key.
/// use std::path::Path;
/// use stellar_agent_toolsets_install::{InstallOptions, install_toolset};
///
/// let package_bytes = std::fs::read("my-toolset-1.0.0.tar.gz").unwrap();
/// let outcome = install_toolset(
///     "my-toolset",
///     "1.0.0",
///     &package_bytes,
///     "a64hexchars...",  // 64-char lowercase hex SHA-256 of package_bytes
///     &[0u8; 64],        // ed25519 signature bytes (placeholder)
///     &[0u8; 32],        // publisher public key bytes (placeholder)
///     Path::new("/path/to/toolsets"),
///     Path::new("/path/to/trust.txt"),
///     None,
///     Path::new("/path/to/auditor-trust.txt"),
///     &InstallOptions::default(),
/// ).unwrap();
/// // outcome is AttestationOutcome::Attested, Overridden, or NotRequired
/// // depending on the toolset's declared capabilities and install options.
/// ```
#[allow(clippy::too_many_arguments)]
pub fn install_toolset(
    package: &str,
    version: &str,
    package_bytes: &[u8],
    signed_shasum: &str,
    signature_bytes: &[u8; 64],
    publisher_pubkey_bytes: &[u8; 32],
    toolsets_root: &Path,
    trust_set_path: &Path,
    attestation: Option<&ToolsetAttestation>,
    auditor_trust_set_path: &Path,
    options: &InstallOptions,
) -> Result<AttestationOutcome, ToolsetInstallError> {
    // ── Step 1: Validate inputs ───────────────────────────────────────────────
    validate_package_name(package)
        .map_err(|detail| ToolsetInstallError::InvalidPackageName { detail })?;

    // Version: length cap first, then SemVer parse.
    let parsed_version = parse_version_str(version)?;

    // Validate the shasum: must be exactly 64 LOWERCASE hex chars.
    // Uppercase hex is rejected with a precise error rather than deferring
    // to a downstream SignatureInvalid.
    if signed_shasum.len() != 64 {
        return Err(ToolsetInstallError::InvalidShasum {
            detail: format!(
                "signed_shasum must be exactly 64 lowercase hex characters, got {}",
                signed_shasum.len()
            ),
        });
    }
    for ch in signed_shasum.chars() {
        if !ch.is_ascii_hexdigit() || ch.is_ascii_uppercase() {
            return Err(ToolsetInstallError::InvalidShasum {
                detail: format!(
                    "signed_shasum contains invalid character {ch:?}; \
                     must be 64 lowercase hex characters (0-9 a-f)"
                ),
            });
        }
    }

    debug!(package, version, "starting toolset install");

    // ── Step 2: Load trust set ────────────────────────────────────────────────
    let trust_set: BTreeSet<[u8; 32]> = load_trust_set(trust_set_path)?;

    // ── Step 3: Check trust set membership before heavy work ─────────────────
    signature::check_signer_trusted(publisher_pubkey_bytes, &trust_set)?;

    // ── Step 4: Read package + recompute hash ─────────────────────────────────
    // The package_bytes slice is already in memory (caller read it with the cap).
    // We verify the hash over the provided bytes.
    let verified_bytes = hash::read_and_verify_hash(package_bytes, signed_shasum)?;

    // ── Step 5: Verify signature (using RECOMPUTED hash) ─────────────────────
    signature::verify_signature(
        package,
        version,
        signed_shasum,
        signature_bytes,
        publisher_pubkey_bytes,
    )?;

    // ── Step 6: Check already-installed ──────────────────────────────────────
    // Create toolsets_root if it doesn't exist yet.
    std::fs::create_dir_all(toolsets_root).map_err(ToolsetInstallError::from_io)?;

    if let Some(existing_pin) = pin::read_pin(package, toolsets_root)? {
        if !options.force {
            return Err(ToolsetInstallError::AlreadyInstalled {
                package: package.to_owned(),
                installed_version: existing_pin.version.clone(),
            });
        }

        // --force: check for downgrade.
        if !options.allow_downgrade {
            check_not_downgrade(version, &existing_pin.version, &parsed_version)?;
        }

        // Uninstall existing version first (through pin).
        debug!(package, existing_version = %existing_pin.version, "force-reinstalling: removing existing install");
        uninstall_inner(package, toolsets_root)?;
    }

    // ── Step 7: Safe extraction ───────────────────────────────────────────────
    let staging = extract::extract_and_move(&verified_bytes, package, toolsets_root)?;
    let staging_pkg_dir = staging.path().join(package);

    // ── Step 8: Parse + validate TOOLSET.md ────────────────────────────────────
    let toolset = match stellar_agent_toolsets::parse_toolset(&staging_pkg_dir) {
        Ok(s) => s,
        Err(e) => {
            // Roll back: remove staging dir.
            warn!(package, error = %e, "TOOLSET.md parse failed; rolling back staging");
            let _ = std::fs::remove_dir_all(staging.path());
            return Err(ToolsetInstallError::ToolsetFormat(e));
        }
    };

    // ── Step 8a: Compute TOOLSET.md content digest ──────────────────────────────
    //
    // Read the extracted TOOLSET.md bytes from the staging dir to produce a
    // SHA-256 content digest for dispatch-time tamper detection.  This must
    // happen AFTER Step 8 (parse succeeds, so the file is valid) and BEFORE
    // Step 10 (atomic rename to final), so the bytes are from the
    // signature-verified package.
    //
    // On I/O failure: log a warn and proceed without the digest (None).
    // The capability-source invariant (capabilities from pin, not re-parsed
    // TOOLSET.md) ensures safety; the digest check is additive tamper-evidence.
    let toolset_md_shasum: Option<String> = {
        let toolset_md_path = staging_pkg_dir.join("TOOLSET.md");
        match std::fs::read(&toolset_md_path) {
            Ok(bytes) => {
                let digest = hash::sha256_hex_of(&bytes);
                debug!(
                    package,
                    "computed TOOLSET.md content digest for dispatch-time re-verification"
                );
                Some(digest)
            }
            Err(e) => {
                warn!(
                    package,
                    error = %e,
                    "failed to read TOOLSET.md for content digest; pin will skip dispatch-time re-verification"
                );
                None
            }
        }
    };

    // ── Step 9: Identity cross-check ─────────────────────────────────────────
    if toolset.name != package {
        let _ = std::fs::remove_dir_all(staging.path());
        return Err(ToolsetInstallError::IdentityMismatch {
            field: "name",
            extracted: stellar_agent_toolsets::sanitise_display(&toolset.name, 64),
            expected: package.to_owned(),
        });
    }

    // ── Step 9b: Attestation gate ─────────────────────────────────────────────
    //
    // Gate placement: AFTER Step 9 (identity cross-check proves toolset.name ==
    // package) and BEFORE Step 10 (atomic rename).  This is the earliest point
    // at which the declared capability set AND the package identity are BOTH
    // verified.  Running the gate before Step 9 would allow an attestation
    // to be validated against an unconfirmed identity.
    //
    // Capability source: `toolset.capabilities` comes from the signature-verified
    // parse of TOOLSET.md (Step 8) — NEVER from a re-parse of the on-disk file
    // (capability-source invariant).
    //
    // Rollback: any error path uses `let _ = std::fs::remove_dir_all(staging.path())`
    // identical to the Step 8/9 form.  No pin is written on refusal (Step 11 is
    // after this gate) — no partial-install window.
    let is_key_touching = toolset.capabilities.iter().any(|c| c.is_key_touching());

    // `gate_outcome` is set inside the if-block and used at the Ok(outcome) return.
    let gate_outcome = if is_key_touching {
        if options.override_attestation {
            // Override is effective (key-touching toolset + gate would have refused)
            // → emit structured warn and proceed with outcome `Overridden`.
            // Shasum is redacted to first-8-last-8.
            let shasum_redacted = stellar_agent_core::hex::redact_hex_first8_last8(signed_shasum);
            warn!(
                package,
                version,
                shasum = %shasum_redacted,
                attestation = "overridden",
                "attestation gate bypassed via override_attestation; \
                 toolset declares key-touching capability but no attestation was verified"
            );
            AttestationOutcome::Overridden
        } else {
            // Require a valid attestation.
            let att = match attestation {
                Some(a) => a,
                None => {
                    let _ = std::fs::remove_dir_all(staging.path());
                    return Err(ToolsetInstallError::AttestationRequired {
                        package: package.to_owned(),
                    });
                }
            };

            // ── Field cross-checks ────────────────────────────────────────────
            if att.package != package {
                let _ = std::fs::remove_dir_all(staging.path());
                return Err(ToolsetInstallError::AttestationFieldMismatch { field: "package" });
            }
            if att.version != version {
                let _ = std::fs::remove_dir_all(staging.path());
                return Err(ToolsetInstallError::AttestationFieldMismatch { field: "version" });
            }
            if att.shasum != signed_shasum {
                let _ = std::fs::remove_dir_all(staging.path());
                return Err(ToolsetInstallError::AttestationFieldMismatch { field: "shasum" });
            }
            if att.capabilities != toolset.capabilities {
                let _ = std::fs::remove_dir_all(staging.path());
                return Err(ToolsetInstallError::AttestationFieldMismatch {
                    field: "capabilities",
                });
            }

            // ── Auditor trust set + verify ────────────────────────────────────
            //
            // Both the trust-set membership check and the signature verify use
            // `att.auditor_pubkey` — the SAME bytes (single key source).
            // No second key path exists.
            let auditor_trust_set = attestation::load_auditor_trust_set(auditor_trust_set_path)
                .inspect_err(|_| {
                    // Any auditor trust-set load failure is a rollback.
                    let _ = std::fs::remove_dir_all(staging.path());
                })?;

            attestation::check_auditor_trusted(&att.auditor_pubkey, &auditor_trust_set)
                .inspect_err(|_| {
                    let _ = std::fs::remove_dir_all(staging.path());
                })?;

            attestation::verify_attestation_signature(att, &toolset.capabilities).inspect_err(
                |_| {
                    let _ = std::fs::remove_dir_all(staging.path());
                },
            )?;

            // ── Self-attestation warning ──────────────────────────────────────
            //
            // If the accepted attestation's auditor_pubkey is ALSO present in
            // the PUBLISHER trust set (not the auditor trust set — those are
            // separate), emit a warn.  Not refused (over-constrains small-operator
            // setups) but made visible.
            //
            // `redact_strkey_first5_last5` already handles the invalid-point case
            // by returning "G...?" internally, so no double-fallback is needed.
            let publisher_trust_set_result = signature::load_trust_set(trust_set_path);
            if let Ok(publisher_trust_set) = publisher_trust_set_result
                && publisher_trust_set.contains(&att.auditor_pubkey)
            {
                // `from_payload` on a key that just passed `VerifyingKey::from_bytes`
                // (in verify_attestation_signature) is always valid, but we handle
                // the error branch via the redact helper's own "G...?" fallback.
                let key_str = StrPublicKey::from_payload(&att.auditor_pubkey)
                    .map(|pk| {
                        stellar_agent_core::observability::redact::redact_strkey_first5_last5(
                            &pk.to_string(),
                        )
                    })
                    .unwrap_or_else(|_| "G...?".to_owned());
                warn!(
                    package,
                    version,
                    auditor_key = %key_str,
                    "attestation auditor is also this package's publisher; self-attestation"
                );
            }

            debug!(package, version, "attestation verified successfully");
            AttestationOutcome::Attested
        }
    } else {
        // Non-key-touching toolset: gate does not fire regardless of flags.
        debug!(
            package,
            version, "attestation not required (no key-touching capabilities)"
        );
        AttestationOutcome::NotRequired
    };

    // ── Step 10: Atomic rename staging → final ────────────────────────────────
    let final_dir = toolsets_root.join(package);
    if final_dir.exists() {
        std::fs::remove_dir_all(&final_dir).map_err(ToolsetInstallError::from_io)?;
    }

    let staging_pkg_path = staging.path().join(package);
    std::fs::rename(&staging_pkg_path, &final_dir).map_err(|e| {
        let _ = std::fs::remove_dir_all(staging.path());
        ToolsetInstallError::from_io(e)
    })?;

    // Drop the TempDir without deleting (we moved its contents).
    // Close the TempDir handle; since we moved the package dir out, the
    // staging dir is now empty (or near-empty). Best-effort cleanup.
    let _ = staging.close();

    // ── Step 11: Atomic pin write ─────────────────────────────────────────────
    // `stellar_strkey` returns a heapless::String<56>; convert to std String.
    let publisher_strkey: String = StrPublicKey(*publisher_pubkey_bytes)
        .to_string()
        .as_str()
        .to_owned();
    let installed_at = current_utc_timestamp();

    let pin_record = ToolsetPinRecord {
        package: package.to_owned(),
        version: version.to_owned(),
        shasum: signed_shasum.to_owned(),
        publisher: publisher_strkey,
        installed_at,
        // Persist capabilities + allowed_tools from the signature-verified parse
        // so dispatch can read them without re-parsing the unverified on-disk TOOLSET.md.
        capabilities: toolset.capabilities.clone(),
        allowed_tools: toolset.allowed_tools.clone(),
        toolset_md_shasum,
    };

    if let Err(e) = pin::write_pin_atomic(&pin_record, toolsets_root) {
        // Pin write failed: roll back the moved dir.
        warn!(package, error = %e, "pin write failed; rolling back installed dir");
        let _ = std::fs::remove_dir_all(&final_dir);
        return Err(e);
    }

    info!(package, version, "toolset installed successfully");
    Ok(gate_outcome)
}

/// Installs a toolset from a signed `.tar.gz` file at `path`.
///
/// This is the **CLI-preferred entry point** (streaming-cap invariant).  It
/// opens the file and applies a `Read::take` cap of `MAX_PACKAGE_BYTES + 1` on
/// the OS file handle BEFORE materialising the buffer, so a multi-gigabyte or
/// FIFO file cannot OOM the process.
///
/// `metadata().len()` is NOT trusted (the source is untrusted).  Only the
/// actual bytes read through the capped reader count.
///
/// On success, delegates to [`install_toolset`] with the verified buffer.
/// The `attestation` and `auditor_trust_set_path` parameters are threaded
/// through to the gate in [`install_toolset`] — the gate cannot be bypassed by
/// using this entry point.
///
/// # Errors
///
/// - [`ToolsetInstallError::Io`] — cannot open or read the package file.
/// - [`ToolsetInstallError::PackageTooLarge`] — file exceeds [`MAX_PACKAGE_BYTES`].
/// - Any error from [`install_toolset`].
#[allow(clippy::too_many_arguments)]
pub fn install_toolset_from_path(
    package: &str,
    version: &str,
    package_path: &Path,
    signed_shasum: &str,
    signature_bytes: &[u8; 64],
    publisher_pubkey_bytes: &[u8; 32],
    toolsets_root: &Path,
    trust_set_path: &Path,
    attestation: Option<&ToolsetAttestation>,
    auditor_trust_set_path: &Path,
    options: &InstallOptions,
) -> Result<AttestationOutcome, ToolsetInstallError> {
    // Open the file and apply the streaming cap BEFORE reading.
    // Do NOT call metadata().len() — the source is untrusted.
    let file = std::fs::File::open(package_path).map_err(ToolsetInstallError::from_io)?;
    let mut limited = file.take((MAX_PACKAGE_BYTES as u64) + 1);
    let mut buf: Vec<u8> = Vec::with_capacity((MAX_PACKAGE_BYTES).min(64 * 1024));
    limited
        .read_to_end(&mut buf)
        .map_err(ToolsetInstallError::from_io)?;

    if buf.len() > MAX_PACKAGE_BYTES {
        return Err(ToolsetInstallError::PackageTooLarge {
            cap: MAX_PACKAGE_BYTES,
        });
    }

    install_toolset(
        package,
        version,
        &buf,
        signed_shasum,
        signature_bytes,
        publisher_pubkey_bytes,
        toolsets_root,
        trust_set_path,
        attestation,
        auditor_trust_set_path,
        options,
    )
}

/// Uninstalls a previously-installed toolset.
///
/// 1. Reads the pin record for `package`.
/// 2. Validates the stored package name.
/// 3. Reconstructs the directory path as `<toolsets_root>/<package>` (NEVER
///    trusts a stored path).
/// 4. Verifies the reconstructed path via `symlink_metadata` (no-follow).
/// 5. Removes the directory and pin record.
///
/// Returns [`ToolsetInstallError::NotInstalled`] if no pin record exists.
///
/// # Errors
///
/// - [`ToolsetInstallError::NotInstalled`] — toolset is not installed.
/// - [`ToolsetInstallError::PinRecordMalformed`] — pin record is invalid.
/// - [`ToolsetInstallError::Io`] — I/O error during removal.
///
/// # Examples
///
/// ```rust,ignore
/// use std::path::Path;
/// use stellar_agent_toolsets_install::uninstall_toolset;
///
/// uninstall_toolset("my-toolset", Path::new("/path/to/toolsets")).unwrap();
/// ```
pub fn uninstall_toolset(package: &str, toolsets_root: &Path) -> Result<(), ToolsetInstallError> {
    validate_package_name(package)
        .map_err(|detail| ToolsetInstallError::InvalidPackageName { detail })?;
    uninstall_inner(package, toolsets_root)
}

/// Inner uninstall (called by both the public API and force-reinstall).
fn uninstall_inner(package: &str, toolsets_root: &Path) -> Result<(), ToolsetInstallError> {
    // Read the pin record.
    let pin = pin::read_pin(package, toolsets_root)?;
    let pin = match pin {
        Some(p) => p,
        None => {
            return Err(ToolsetInstallError::NotInstalled {
                package: package.to_owned(),
            });
        }
    };

    // Validate the stored name.
    if let Err(reason) = validate_package_name(&pin.package) {
        return Err(ToolsetInstallError::PinRecordMalformed {
            detail: format!(
                "stored package name '{}' is invalid: {reason}",
                stellar_agent_toolsets::sanitise_display(&pin.package, 64)
            ),
        });
    }

    // Reconstruct the path from the VALIDATED name (never trust a stored path).
    let toolset_dir = toolsets_root.join(&pin.package);

    // Lexical containment check: ensure the reconstructed path is inside toolsets_root.
    check_path_within_root(&toolset_dir, toolsets_root)?;

    // No-follow check on the toolset directory leaf.
    match std::fs::symlink_metadata(&toolset_dir) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(ToolsetInstallError::PinRecordMalformed {
                detail: format!(
                    "toolset directory '{}' is a symlink; refusing removal",
                    stellar_agent_toolsets::sanitise_display(
                        &toolset_dir.display().to_string(),
                        256
                    )
                ),
            });
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Dir doesn't exist but pin exists; remove the orphan pin.
            warn!(
                package,
                "toolset dir not found but pin exists; removing orphan pin"
            );
            pin::remove_pin(package, toolsets_root)?;
            return Err(ToolsetInstallError::NotInstalled {
                package: package.to_owned(),
            });
        }
        Err(e) => return Err(ToolsetInstallError::from_io(e)),
    }

    // Re-check immediately before removal (TOCTOU residual mitigation).
    // Rely on std's remove_dir_all symlink-hardening (Rust ≥ 1.0 on all
    // supported platforms refuses to descend into a symlink during recursive
    // removal on Unix; Windows uses FILE_FLAG_OPEN_REPARSE_POINT).
    // Note: the TOCTOU window between stat and removal is residual-MINOR and
    // bounded by the name-reconstruction (we never act on a stored path).
    std::fs::remove_dir_all(&toolset_dir).map_err(ToolsetInstallError::from_io)?;

    // Remove the pin record (best-effort; the toolset dir is already gone).
    pin::remove_pin(package, toolsets_root)?;

    info!(package, "toolset uninstalled successfully");
    Ok(())
}

// ── Helper functions ──────────────────────────────────────────────────────────

/// Validates a package name against the `[a-z0-9-]` rule.
///
/// Returns `Ok(())` on success, `Err(reason)` with a description string on
/// failure.  The caller wraps this in the appropriate [`ToolsetInstallError`]
/// variant.
///
/// **Security:** this validator rejects `/`, `\`, `.`, `..`, and all characters
/// outside `[a-z0-9-]`, making it safe to use as a path-traversal guard before
/// constructing a filesystem path from a toolset name.
///
/// # Errors
///
/// Returns a string describing why validation failed.
pub fn validate_package_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("package name is empty".to_owned());
    }
    if name.len() > 64 {
        return Err("package name exceeds 64 characters".to_owned());
    }
    for ch in name.chars() {
        if !matches!(ch, 'a'..='z' | '0'..='9' | '-') {
            // `{ch:?}` debug-escapes control/non-printable chars (e.g. `\n`, ESC) so
            // an attacker-influenced name cannot inject a raw control byte / newline
            // into a rendered error or log line.
            return Err(format!("package name contains invalid character {ch:?}"));
        }
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err("package name must not start or end with a hyphen".to_owned());
    }
    if name.contains("--") {
        return Err("package name must not contain consecutive hyphens".to_owned());
    }
    Ok(())
}

/// Parses and validates a version string.
///
/// Applies length cap (1..=[`MAX_VERSION_LEN`]) first, then SemVer parse.
fn parse_version_str(version: &str) -> Result<Version, ToolsetInstallError> {
    if version.is_empty() || version.len() > MAX_VERSION_LEN {
        return Err(ToolsetInstallError::InvalidVersion {
            detail: format!(
                "version must be 1..={MAX_VERSION_LEN} characters, got {}",
                version.len()
            ),
        });
    }
    Version::parse(version).map_err(|e| ToolsetInstallError::InvalidVersion {
        detail: stellar_agent_toolsets::sanitise_display(&e.to_string(), 256),
    })
}

/// Checks that installing `new_version` over `installed_version_str` is not a
/// downgrade.
///
/// If either version is unparseable as SemVer, the reinstall is refused
/// (lexical string comparison is NOT used).
fn check_not_downgrade(
    new_version_str: &str,
    installed_version_str: &str,
    parsed_new: &Version,
) -> Result<(), ToolsetInstallError> {
    let parsed_installed = Version::parse(installed_version_str).map_err(|_| {
        ToolsetInstallError::VersionDowngrade {
            new_version: new_version_str.to_owned(),
            installed_version: installed_version_str.to_owned(),
        }
    })?;

    // SemVer precedence: new < installed → downgrade refused.
    if parsed_new < &parsed_installed {
        return Err(ToolsetInstallError::VersionDowngrade {
            new_version: new_version_str.to_owned(),
            installed_version: installed_version_str.to_owned(),
        });
    }

    Ok(())
}

/// Checks that `path` is lexically contained within `root`.
fn check_path_within_root(path: &Path, root: &Path) -> Result<(), ToolsetInstallError> {
    // Use starts_with on the PathBuf components for a clean lexical check.
    // This is safe because the path was reconstructed from a validated package
    // name — no `..` can appear.
    if !path.starts_with(root) {
        return Err(ToolsetInstallError::PinRecordMalformed {
            detail: "reconstructed toolset path escapes toolsets root".to_owned(),
        });
    }
    Ok(())
}

/// Returns the current UTC timestamp as an RFC-3339 string (`YYYY-MM-DDTHH:MM:SSZ`).
///
/// Delegates to [`stellar_agent_core::timefmt::format_rfc3339_utc`], the
/// in-tree canonical ISO-8601 timestamp formatter used by the audit-log subsystem.
fn current_utc_timestamp() -> String {
    stellar_agent_core::timefmt::format_rfc3339_utc(std::time::SystemTime::now())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cast_possible_truncation,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use std::io::Write as _;

    use ed25519_dalek::{Signer, SigningKey};
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use sha2::{Digest, Sha256};
    use stellar_strkey::ed25519::PublicKey as StrPublicKey;
    use tempfile::TempDir;

    use super::*;

    // ── AttestationOutcome::as_str ────────────────────────────────────────────

    #[test]
    fn attestation_outcome_as_str_all_variants() {
        assert_eq!(AttestationOutcome::Attested.as_str(), "attested");
        assert_eq!(AttestationOutcome::Overridden.as_str(), "overridden");
        assert_eq!(AttestationOutcome::NotRequired.as_str(), "not-required");
    }

    // ── install_toolset: Step-1 shasum validation ───────────────────────────────

    /// Fixture: repeated character string of length n.
    fn dummy_shasum_of_len(n: usize, ch: char) -> String {
        std::iter::repeat_n(ch, n).collect()
    }

    #[test]
    fn install_toolset_rejects_shasum_too_short() {
        // 63-char shasum → Step-1 length check fires; we don't need real package bytes
        // because validation exits before reading the package.
        let dir = TempDir::new().unwrap();
        let trust_path = dir.path().join("trust.txt");
        std::fs::write(&trust_path, b"").unwrap();
        let auditor_trust_path = dir.path().join("auditor-trust.txt");
        std::fs::write(&auditor_trust_path, b"").unwrap();

        let bad_shasum = dummy_shasum_of_len(63, 'a');
        let sig = [0u8; 64];
        let pubkey = [0u8; 32];
        let opts = InstallOptions::default();

        let err = install_toolset(
            "my-toolset",
            "1.0.0",
            &[0u8; 32],
            &bad_shasum,
            &sig,
            &pubkey,
            dir.path(),
            &trust_path,
            None,
            &auditor_trust_path,
            &opts,
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::InvalidShasum { .. }),
            "expected InvalidShasum for short shasum, got: {err:?}"
        );
    }

    #[test]
    fn install_toolset_rejects_shasum_too_long() {
        let dir = TempDir::new().unwrap();
        let trust_path = dir.path().join("trust.txt");
        std::fs::write(&trust_path, b"").unwrap();
        let auditor_trust_path = dir.path().join("auditor-trust.txt");
        std::fs::write(&auditor_trust_path, b"").unwrap();

        let bad_shasum = dummy_shasum_of_len(65, 'a');
        let sig = [0u8; 64];
        let pubkey = [0u8; 32];
        let opts = InstallOptions::default();

        let err = install_toolset(
            "my-toolset",
            "1.0.0",
            &[0u8; 32],
            &bad_shasum,
            &sig,
            &pubkey,
            dir.path(),
            &trust_path,
            None,
            &auditor_trust_path,
            &opts,
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::InvalidShasum { .. }),
            "expected InvalidShasum for long shasum, got: {err:?}"
        );
    }

    #[test]
    fn install_toolset_rejects_uppercase_in_shasum() {
        let dir = TempDir::new().unwrap();
        let trust_path = dir.path().join("trust.txt");
        std::fs::write(&trust_path, b"").unwrap();
        let auditor_trust_path = dir.path().join("auditor-trust.txt");
        std::fs::write(&auditor_trust_path, b"").unwrap();

        // 64 chars but contains an uppercase 'A'
        let bad_shasum = format!("A{}", "a".repeat(63));
        let sig = [0u8; 64];
        let pubkey = [0u8; 32];
        let opts = InstallOptions::default();

        let err = install_toolset(
            "my-toolset",
            "1.0.0",
            &[0u8; 32],
            &bad_shasum,
            &sig,
            &pubkey,
            dir.path(),
            &trust_path,
            None,
            &auditor_trust_path,
            &opts,
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::InvalidShasum { .. }),
            "expected InvalidShasum for uppercase shasum char, got: {err:?}"
        );
    }

    // ── Shared test-fixture helpers ───────────────────────────────────────────

    /// Builds a minimal `.tar.gz` with `<name>/TOOLSET.md` containing `content`.
    fn make_toolset_tar_gz(name: &str, content: &str) -> Vec<u8> {
        let mut ar = tar::Builder::new(Vec::new());

        let mut dir_header = tar::Header::new_gnu();
        dir_header.set_entry_type(tar::EntryType::Directory);
        dir_header.set_path(format!("{name}/")).unwrap();
        dir_header.set_size(0);
        dir_header.set_mode(0o755);
        dir_header.set_cksum();
        ar.append(&dir_header, &[][..]).unwrap();

        let bytes = content.as_bytes();
        let mut fh = tar::Header::new_gnu();
        fh.set_entry_type(tar::EntryType::Regular);
        fh.set_path(format!("{name}/TOOLSET.md")).unwrap();
        fh.set_size(bytes.len() as u64);
        fh.set_mode(0o644);
        fh.set_cksum();
        ar.append(&fh, bytes).unwrap();

        let tar_bytes = ar.into_inner().unwrap();
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    /// Signs `data` with `publisher_sk` and returns `([u8;64] sig, lowercase shasum)`.
    fn sign_package(
        name: &str,
        version: &str,
        data: &[u8],
        publisher_sk: &SigningKey,
    ) -> ([u8; 64], String) {
        let mut h = Sha256::new();
        h.update(data);
        let shasum = hex::encode(h.finalize());
        let preimage = signature::build_preimage(name, version, &shasum);
        let sig: [u8; 64] = publisher_sk.sign(&preimage).to_bytes();
        (sig, shasum)
    }

    /// Writes publisher trust file for `publisher_pk` at `dir/trust.txt`.
    fn write_publisher_trust(dir: &std::path::Path, publisher_pk: [u8; 32]) -> std::path::PathBuf {
        let strkey = StrPublicKey(publisher_pk).to_string();
        let strkey_s: String = strkey.as_str().to_owned();
        let path = dir.join("trust.txt");
        std::fs::write(&path, format!("{strkey_s}\n")).unwrap();
        path
    }

    /// Writes an empty auditor trust file (forces `TrustSetEmpty` if reached).
    fn write_empty_auditor_trust(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("auditor-trust.txt");
        std::fs::write(&path, b"").unwrap();
        path
    }

    /// Minimal TOOLSET.md with no capabilities (non-key-touching).
    fn toolset_md_no_caps(name: &str) -> String {
        format!("---\nname: {name}\ndescription: A test toolset.\n---\n\nBody.\n")
    }

    // ── install_toolset: identity mismatch (Step 9) ─────────────────────────────

    #[test]
    fn install_toolset_name_dir_mismatch_in_toolset_md_refused() {
        // A TOOLSET.md where `name:` does not match the containing directory name.
        // `parse_toolset` catches this as `ToolsetFormatError::NameDirMismatch` at Step 8,
        // which surfaces as `ToolsetInstallError::ToolsetFormat`.
        //
        // The `IdentityMismatch` variant at Step 9 is a defense-in-depth guard; this
        // test covers the `ToolsetFormat` path that fires first in practice.
        let dir = TempDir::new().unwrap();
        let toolsets_root = dir.path().join("toolsets");

        use rand_core::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();

        // Tarball top-level == "my-toolset" (matches package arg), but TOOLSET.md says a different name.
        let toolset_content = toolset_md_no_caps("wrong-name-in-toolset-md");
        let package_bytes = make_toolset_tar_gz("my-toolset", &toolset_content);
        let (sig, shasum) = sign_package("my-toolset", "1.0.0", &package_bytes, &sk);

        let trust_path = write_publisher_trust(dir.path(), pk);
        let auditor_trust_path = write_empty_auditor_trust(dir.path());

        let err = install_toolset(
            "my-toolset",
            "1.0.0",
            &package_bytes,
            &shasum,
            &sig,
            &pk,
            &toolsets_root,
            &trust_path,
            None,
            &auditor_trust_path,
            &InstallOptions::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::ToolsetFormat(..)),
            "expected ToolsetFormat for name/dir mismatch, got: {err:?}"
        );
    }

    // ── install_toolset: AlreadyInstalled + force-reinstall ─────────────────────

    #[test]
    fn install_toolset_already_installed_rejected_without_force() {
        let dir = TempDir::new().unwrap();
        let toolsets_root = dir.path().join("toolsets");
        std::fs::create_dir_all(&toolsets_root).unwrap();

        let toolset_content = toolset_md_no_caps("my-toolset");
        let package_bytes = make_toolset_tar_gz("my-toolset", &toolset_content);
        use rand_core::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        let (sig, shasum) = sign_package("my-toolset", "1.0.0", &package_bytes, &sk);
        let trust_path = write_publisher_trust(dir.path(), pk);
        let auditor_trust_path = write_empty_auditor_trust(dir.path());

        // First install.
        install_toolset(
            "my-toolset",
            "1.0.0",
            &package_bytes,
            &shasum,
            &sig,
            &pk,
            &toolsets_root,
            &trust_path,
            None,
            &auditor_trust_path,
            &InstallOptions::default(),
        )
        .unwrap();

        // Second install without force.
        let err = install_toolset(
            "my-toolset",
            "1.0.0",
            &package_bytes,
            &shasum,
            &sig,
            &pk,
            &toolsets_root,
            &trust_path,
            None,
            &auditor_trust_path,
            &InstallOptions::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::AlreadyInstalled { .. }),
            "expected AlreadyInstalled, got: {err:?}"
        );
    }

    #[test]
    fn install_toolset_force_reinstall_succeeds() {
        // Covers the force-reinstall `final_dir.exists()` removal branch in install_toolset.
        let dir = TempDir::new().unwrap();
        let toolsets_root = dir.path().join("toolsets");
        std::fs::create_dir_all(&toolsets_root).unwrap();

        let toolset_content = toolset_md_no_caps("my-toolset");
        let package_bytes = make_toolset_tar_gz("my-toolset", &toolset_content);
        use rand_core::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        let (sig, shasum) = sign_package("my-toolset", "1.0.0", &package_bytes, &sk);
        let trust_path = write_publisher_trust(dir.path(), pk);
        let auditor_trust_path = write_empty_auditor_trust(dir.path());

        // First install.
        install_toolset(
            "my-toolset",
            "1.0.0",
            &package_bytes,
            &shasum,
            &sig,
            &pk,
            &toolsets_root,
            &trust_path,
            None,
            &auditor_trust_path,
            &InstallOptions::default(),
        )
        .unwrap();

        // Force-reinstall (same version — not a downgrade).
        let opts = InstallOptions {
            force: true,
            allow_downgrade: false,
            override_attestation: false,
        };
        install_toolset(
            "my-toolset",
            "1.0.0",
            &package_bytes,
            &shasum,
            &sig,
            &pk,
            &toolsets_root,
            &trust_path,
            None,
            &auditor_trust_path,
            &opts,
        )
        .unwrap();
    }

    // ── Attestation gate paths ────────────────────────────────────────────────

    /// Builds a minimal `TOOLSET.md` that declares `sign-payment` (key-touching).
    fn toolset_md_with_sign_payment(name: &str) -> String {
        format!(
            "---\nname: {name}\ndescription: Test toolset with key-touching capability.\nmetadata:\n  stellar-agent-capabilities: sign-payment\n---\n\nBody.\n"
        )
    }

    /// Builds and signs a package from `content` with a freshly generated keypair.
    /// Returns (package_bytes, sig, pubkey, shasum).
    fn build_signed_package(
        name: &str,
        version: &str,
        content: &str,
    ) -> (Vec<u8>, [u8; 64], [u8; 32], String, SigningKey) {
        use rand_core::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        let package_bytes = make_toolset_tar_gz(name, content);
        let (sig, shasum) = sign_package(name, version, &package_bytes, &sk);
        (package_bytes, sig, pk, shasum, sk)
    }

    #[test]
    fn install_toolset_key_touching_missing_attestation_returns_attestation_required() {
        // A toolset that declares sign-payment with no attestation and no override
        // → AttestationRequired.  This covers the "required but not provided" branch
        // (attestation = None, override = false, key-touching = true).
        let dir = TempDir::new().unwrap();
        let toolsets_root = dir.path().join("toolsets");

        let content = toolset_md_with_sign_payment("my-toolset");
        let (package_bytes, sig, pk, shasum, _sk) =
            build_signed_package("my-toolset", "1.0.0", &content);
        let trust_path = write_publisher_trust(dir.path(), pk);
        // Auditor trust file: any non-empty content (gate fires before reaching it).
        let auditor_trust_path = dir.path().join("auditor-trust.txt");
        {
            use rand_core::OsRng;
            let auditor_sk = SigningKey::generate(&mut OsRng);
            let auditor_pk = auditor_sk.verifying_key().to_bytes();
            let auditor_strkey = StrPublicKey(auditor_pk).to_string();
            std::fs::write(
                &auditor_trust_path,
                format!("{}\n", auditor_strkey.as_str()),
            )
            .unwrap();
        }

        let err = install_toolset(
            "my-toolset",
            "1.0.0",
            &package_bytes,
            &shasum,
            &sig,
            &pk,
            &toolsets_root,
            &trust_path,
            None, // no attestation
            &auditor_trust_path,
            &InstallOptions::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::AttestationRequired { .. }),
            "expected AttestationRequired, got: {err:?}"
        );
    }

    #[test]
    fn install_toolset_key_touching_absent_auditor_trust_set_returns_trust_set_empty() {
        // Key-touching toolset + attestation supplied + auditor trust file absent
        // → inspects the error from load_auditor_trust_set, returns TrustSetEmpty.
        use ed25519_dalek::Signer as _;
        use stellar_agent_toolsets::parse_capability_value_pub;

        let dir = TempDir::new().unwrap();
        let toolsets_root = dir.path().join("toolsets");

        let content = toolset_md_with_sign_payment("my-toolset");
        let (package_bytes, sig, pk, shasum, _sk) =
            build_signed_package("my-toolset", "1.0.0", &content);
        let trust_path = write_publisher_trust(dir.path(), pk);

        // Build a valid-looking attestation (it won't reach verification anyway because
        // the trust set load will fail first).
        let auditor_sk = {
            use rand_core::OsRng;
            SigningKey::generate(&mut OsRng)
        };
        let auditor_pk = auditor_sk.verifying_key().to_bytes();
        let caps = parse_capability_value_pub("sign-payment").unwrap();
        let preimage =
            attestation::build_attestation_preimage("my-toolset", "1.0.0", &shasum, &caps);
        let att_sig: [u8; 64] = auditor_sk.sign(&preimage).to_bytes();
        let att = ToolsetAttestation {
            package: "my-toolset".to_owned(),
            version: "1.0.0".to_owned(),
            shasum: shasum.clone(),
            capabilities: caps,
            auditor_pubkey: auditor_pk,
            signature: att_sig,
        };

        // Auditor trust file does NOT exist → TrustSetEmpty.
        let nonexistent_trust = dir.path().join("no-auditor-trust.txt");

        let err = install_toolset(
            "my-toolset",
            "1.0.0",
            &package_bytes,
            &shasum,
            &sig,
            &pk,
            &toolsets_root,
            &trust_path,
            Some(&att),
            &nonexistent_trust,
            &InstallOptions::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::TrustSetEmpty),
            "expected TrustSetEmpty for absent auditor trust file, got: {err:?}"
        );
    }

    #[test]
    fn install_toolset_key_touching_self_attestation_emits_warn_but_succeeds() {
        // Self-attestation: the auditor's key is ALSO in the publisher trust set.
        // install_toolset should succeed (only a warn is emitted) and return Attested.
        // Covers the self-attestation warn branch in install_toolset Step 9b.
        use ed25519_dalek::Signer as _;
        use rand_core::OsRng;
        use stellar_agent_toolsets::parse_capability_value_pub;

        let dir = TempDir::new().unwrap();
        let toolsets_root = dir.path().join("toolsets");

        // Use a single shared key for both publisher and auditor (self-attestation).
        let shared_sk = SigningKey::generate(&mut OsRng);
        let shared_pk = shared_sk.verifying_key().to_bytes();

        // Build and sign the package with shared_sk (publisher = shared_pk).
        let content = toolset_md_with_sign_payment("my-toolset");
        let pkg = make_toolset_tar_gz("my-toolset", &content);
        let (sig, shasum) = sign_package("my-toolset", "1.0.0", &pkg, &shared_sk);

        // Publisher trust set: shared_pk.
        let publisher_strkey = StrPublicKey(shared_pk).to_string();
        let trust_path = dir.path().join("trust.txt");
        std::fs::write(&trust_path, format!("{}\n", publisher_strkey.as_str())).unwrap();

        // Auditor trust set: ALSO shared_pk (self-attestation scenario).
        let auditor_trust_path = dir.path().join("auditor-trust.txt");
        std::fs::write(
            &auditor_trust_path,
            format!("{}\n", publisher_strkey.as_str()),
        )
        .unwrap();

        // Build attestation over (package, version, shasum, caps) signed with shared_sk.
        let caps = parse_capability_value_pub("sign-payment").unwrap();
        let att_preimage =
            attestation::build_attestation_preimage("my-toolset", "1.0.0", &shasum, &caps);
        let att_sig: [u8; 64] = shared_sk.sign(&att_preimage).to_bytes();
        let att = ToolsetAttestation {
            package: "my-toolset".to_owned(),
            version: "1.0.0".to_owned(),
            shasum: shasum.clone(),
            capabilities: caps,
            auditor_pubkey: shared_pk,
            signature: att_sig,
        };

        let outcome = install_toolset(
            "my-toolset",
            "1.0.0",
            &pkg,
            &shasum,
            &sig,
            &shared_pk,
            &toolsets_root,
            &trust_path,
            Some(&att),
            &auditor_trust_path,
            &InstallOptions::default(),
        )
        .unwrap();

        assert_eq!(
            outcome,
            AttestationOutcome::Attested,
            "expected Attested for self-attestation (should succeed with warn)"
        );
    }

    // ── install_toolset_from_path ───────────────────────────────────────────────

    #[test]
    fn install_toolset_from_path_missing_file_returns_io_error() {
        let dir = TempDir::new().unwrap();
        let trust_path = write_publisher_trust(dir.path(), [0u8; 32]);
        let auditor_trust_path = write_empty_auditor_trust(dir.path());
        let nonexistent = dir.path().join("nonexistent.tar.gz");

        let err = install_toolset_from_path(
            "my-toolset",
            "1.0.0",
            &nonexistent,
            &"a".repeat(64),
            &[0u8; 64],
            &[0u8; 32],
            dir.path(),
            &trust_path,
            None,
            &auditor_trust_path,
            &InstallOptions::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::Io { .. }),
            "expected Io for missing file, got: {err:?}"
        );
    }

    #[test]
    fn install_toolset_from_path_oversize_file_returns_too_large() {
        // Write a file of MAX_PACKAGE_BYTES + 1 bytes.
        let dir = TempDir::new().unwrap();
        let big_path = dir.path().join("big.tar.gz");
        {
            let f = std::fs::File::create(&big_path).unwrap();
            let mut w = std::io::BufWriter::new(f);
            // Write MAX_PACKAGE_BYTES + 1 zero bytes.
            let chunk = vec![0u8; 4096];
            let mut written = 0usize;
            let target = MAX_PACKAGE_BYTES + 1;
            while written < target {
                let to_write = chunk.len().min(target - written);
                w.write_all(&chunk[..to_write]).unwrap();
                written += to_write;
            }
        }
        // We don't need real trust files since validation exits before reaching them.
        let trust_path = dir.path().join("trust.txt");
        std::fs::write(&trust_path, b"").unwrap();
        let auditor_trust_path = dir.path().join("auditor-trust.txt");
        std::fs::write(&auditor_trust_path, b"").unwrap();

        let err = install_toolset_from_path(
            "my-toolset",
            "1.0.0",
            &big_path,
            &"a".repeat(64),
            &[0u8; 64],
            &[0u8; 32],
            dir.path(),
            &trust_path,
            None,
            &auditor_trust_path,
            &InstallOptions::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::PackageTooLarge { .. }),
            "expected PackageTooLarge, got: {err:?}"
        );
    }

    #[test]
    fn install_toolset_from_path_delegates_to_install_toolset() {
        // A valid file that delegates through to install_toolset.
        // The install flow is: validate → load trust set → check signer trusted → hash verify.
        // The trust file contains the publisher key, so Step 3 passes.
        // The wrong shasum (all 'a's) does not match the real package hash → HashMismatch.
        let dir = TempDir::new().unwrap();
        let pkg = make_toolset_tar_gz("my-toolset", &toolset_md_no_caps("my-toolset"));
        let pkg_path = dir.path().join("my-toolset-1.0.0.tar.gz");
        std::fs::write(&pkg_path, &pkg).unwrap();

        use rand_core::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        let trust_path = write_publisher_trust(dir.path(), pk);
        let auditor_trust_path = write_empty_auditor_trust(dir.path());
        let toolsets_root = dir.path().join("toolsets");

        // 64-char lowercase hex shasum that does NOT match the actual package bytes.
        let wrong_shasum = "a".repeat(64);
        let dummy_sig = [0u8; 64];

        let err = install_toolset_from_path(
            "my-toolset",
            "1.0.0",
            &pkg_path,
            &wrong_shasum,
            &dummy_sig,
            &pk,
            &toolsets_root,
            &trust_path,
            None,
            &auditor_trust_path,
            &InstallOptions::default(),
        )
        .unwrap_err();
        // Trust set is non-empty and contains publisher key → Step 3 passes.
        // Hash recomputed from file bytes differs from "aaa...a" → HashMismatch.
        assert!(
            matches!(err, ToolsetInstallError::HashMismatch),
            "expected HashMismatch for wrong shasum, got: {err:?}"
        );
    }

    // ── validate_package_name: edge cases ────────────────────────────────────

    #[test]
    fn validate_package_name_exceeds_64_chars_rejected() {
        let long_name = "a".repeat(65);
        let err = validate_package_name(&long_name).unwrap_err();
        assert!(
            err.contains("exceeds 64"),
            "expected 'exceeds 64' error, got: {err}"
        );
    }

    // ── check_not_downgrade: invalid installed version ────────────────────────

    #[test]
    fn check_not_downgrade_invalid_installed_version_returns_version_downgrade() {
        // If the installed version is not valid semver, refuse the reinstall.
        let new_version = parse_version_str("2.0.0").unwrap();
        let err = check_not_downgrade("2.0.0", "not-semver", &new_version).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::VersionDowngrade { .. }),
            "expected VersionDowngrade for invalid installed version, got: {err:?}"
        );
    }

    // ── uninstall_toolset ───────────────────────────────────────────────────────

    #[test]
    fn uninstall_toolset_not_installed_returns_not_installed() {
        let dir = TempDir::new().unwrap();
        let toolsets_root = dir.path().join("toolsets");
        std::fs::create_dir_all(&toolsets_root).unwrap();

        let err = uninstall_toolset("my-toolset", &toolsets_root).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::NotInstalled { .. }),
            "expected NotInstalled, got: {err:?}"
        );
    }

    #[test]
    fn uninstall_toolset_invalid_package_name_rejected() {
        let dir = TempDir::new().unwrap();
        let err = uninstall_toolset("../evil", dir.path()).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::InvalidPackageName { .. }),
            "expected InvalidPackageName for traversal name, got: {err:?}"
        );
    }

    #[test]
    fn uninstall_toolset_pin_with_invalid_stored_name_returns_malformed() {
        // Write a pin JSON where the stored "package" field fails validate_package_name.
        // Covers the stored-package-name validation branch in uninstall_inner.
        use pin::PIN_FILE_NAME;
        let dir = TempDir::new().unwrap();
        let toolsets_root = dir.path().join("toolsets");
        let pkg_dir = toolsets_root.join("my-toolset");
        std::fs::create_dir_all(&pkg_dir).unwrap();

        // Write a pin where the stored package name contains an illegal character.
        let bad_pin = r#"{
            "package": "INVALID_NAME",
            "version": "1.0.0",
            "shasum": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "publisher": "GABC...XYZ",
            "installed_at": "2026-06-01T00:00:00Z"
        }"#;
        std::fs::write(pkg_dir.join(PIN_FILE_NAME), bad_pin).unwrap();

        let err = uninstall_toolset("my-toolset", &toolsets_root).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::PinRecordMalformed { .. }),
            "expected PinRecordMalformed for invalid stored name, got: {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn uninstall_toolset_symlink_toolset_dir_returns_pin_record_malformed() {
        // If the reconstructed toolset directory is a symlink, uninstall must refuse.
        // Covers the symlink branch in uninstall_inner.
        use pin::PIN_FILE_NAME;
        let dir = TempDir::new().unwrap();
        let toolsets_root = dir.path().join("toolsets");
        // Create a real target directory.
        let real_target = dir.path().join("real-target");
        std::fs::create_dir_all(&real_target).unwrap();
        std::fs::create_dir_all(&toolsets_root).unwrap();

        // Create the package directory as a symlink pointing to real_target.
        let pkg_dir = toolsets_root.join("my-toolset");
        std::os::unix::fs::symlink(&real_target, &pkg_dir).unwrap();

        // Write a valid pin inside the package dir (via the symlink — we need the pin
        // to be readable so read_pin returns Some).
        let record = pin::ToolsetPinRecord {
            package: "my-toolset".to_owned(),
            version: "1.0.0".to_owned(),
            shasum: "a".repeat(64),
            publisher: "GABC...XYZ".to_owned(),
            installed_at: "2026-06-01T00:00:00Z".to_owned(),
            capabilities: stellar_agent_toolsets::CapabilitySet::empty(),
            allowed_tools: vec![],
            toolset_md_shasum: None,
        };
        // Write pin via the symlink so read_pin can find it.
        let pin_path = pkg_dir.join(PIN_FILE_NAME);
        let pin_json = serde_json::to_string_pretty(&record).unwrap();
        std::fs::write(&pin_path, pin_json.as_bytes()).unwrap();
        // Verify read_pin finds the pin through the symlink.
        let loaded = pin::read_pin("my-toolset", &toolsets_root)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.package, "my-toolset");

        // Now uninstall — should fail because the toolset directory IS a symlink.
        let err = uninstall_toolset("my-toolset", &toolsets_root).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::PinRecordMalformed { .. }),
            "expected PinRecordMalformed for symlink toolset dir, got: {err:?}"
        );
    }

    // ── validate_package_name ─────────────────────────────────────────────────

    #[test]
    fn valid_names_accepted() {
        for name in &["my-toolset", "toolset123", "a", "abc-def-123"] {
            validate_package_name(name)
                .unwrap_or_else(|e| panic!("'{name}' should be valid, got: {e}"));
        }
    }

    #[test]
    fn invalid_names_rejected() {
        let cases = [
            "",                    // empty
            "-starts-with-hyphen", // leading hyphen
            "ends-with-hyphen-",   // trailing hyphen
            "double--hyphen",      // consecutive hyphens
            "UpperCase",           // uppercase
            "has space",           // space
            "unicode-café",        // non-ASCII
        ];
        for name in &cases {
            assert!(
                validate_package_name(name).is_err(),
                "'{name}' should be invalid"
            );
        }
    }

    // ── parse_version_str ─────────────────────────────────────────────────────

    #[test]
    fn valid_semver_parsed() {
        parse_version_str("1.0.0").unwrap();
        parse_version_str("1.0.0-alpha").unwrap();
        parse_version_str("1.0.0-alpha.1").unwrap();
    }

    #[test]
    fn invalid_semver_rejected() {
        parse_version_str("not-semver").unwrap_err();
        parse_version_str("").unwrap_err();
        parse_version_str(&"a".repeat(MAX_VERSION_LEN + 1)).unwrap_err();
    }

    // ── check_not_downgrade ───────────────────────────────────────────────────

    #[test]
    fn semver_precedence_test_vector() {
        // 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-beta < 1.0.0 < 1.0.1
        let versions = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-beta",
            "1.0.0",
            "1.0.1",
        ];
        for i in 0..versions.len() {
            for j in (i + 1)..versions.len() {
                let older = versions[i];
                let newer = versions[j];
                let parsed_newer = parse_version_str(newer).unwrap();
                // Installing newer over older → not downgrade → OK.
                check_not_downgrade(newer, older, &parsed_newer).unwrap_or_else(|e| {
                    panic!("installing {newer} over {older} should not be a downgrade: {e:?}")
                });
                // Installing older over newer → downgrade → Err.
                let parsed_older = parse_version_str(older).unwrap();
                let result = check_not_downgrade(older, newer, &parsed_older);
                assert!(
                    result.is_err(),
                    "installing {older} over {newer} should be a downgrade"
                );
            }
        }
    }

    #[test]
    fn same_version_is_not_downgrade() {
        let v = parse_version_str("1.0.0").unwrap();
        // Installing same version is not a downgrade (== not <).
        check_not_downgrade("1.0.0", "1.0.0", &v).unwrap();
    }

    // ── check_path_within_root ────────────────────────────────────────────────

    #[test]
    fn path_inside_root_accepted() {
        use std::path::PathBuf;
        let root = PathBuf::from("/toolsets");
        let path = PathBuf::from("/toolsets/my-toolset");
        check_path_within_root(&path, &root).unwrap();
    }

    #[test]
    fn path_outside_root_rejected() {
        use std::path::PathBuf;
        let root = PathBuf::from("/toolsets");
        let path = PathBuf::from("/etc/passwd");
        check_path_within_root(&path, &root).unwrap_err();
    }

    // ── current_utc_timestamp ─────────────────────────────────────────────────

    #[test]
    fn current_utc_timestamp_returns_rfc3339() {
        let ts = current_utc_timestamp();
        // Must end with Z and have the shape YYYY-MM-DDTHH:MM:SSZ (20 chars).
        assert!(ts.ends_with('Z'), "timestamp must end with Z: {ts}");
        assert_eq!(ts.len(), 20, "timestamp must be 20 chars (no millis): {ts}");
    }
}
