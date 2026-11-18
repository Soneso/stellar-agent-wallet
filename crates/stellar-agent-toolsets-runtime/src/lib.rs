//! Capability→tool matrix, gated resolver, and four-part enforcement for
//! installed toolsets.
//!
//! This crate is the toolset isolation boundary for the Stellar agent wallet. It
//! provides:
//!
//! - [`matrix::grants_for_capability`] — the static `Capability → &[&'static str]`
//!   UNGATED allowlist of trusted tool names a capability grants.
//! - [`GATED_MATRIX_ENTRIES`] — the SEPARATE gated tier for
//!   signing-adjacent capabilities.
//! - [`SIGNING_DENYLIST`] — the explicit by-name denylist of signing/key/policy
//!   tools that are NEVER grantable regardless of declared capabilities.
//! - [`ToolsetRuntimeError`] — closed-set typed refusal variants.
//! - [`check_toolset_action`] — the four-part enforcement function (ungated).
//! - [`resolve_toolset_sign_payment_gated`] — the GATED resolver entry point;
//!   a distinct entry point from [`resolve_toolset_and_check`], NOT a
//!   `route_to_matrix_tool` arm.
//! - [`list_pinned_toolsets`] — enumerate installed toolsets + their declared actions.
//!
//! ## What a toolset bounds
//!
//! A toolset narrows what the dispatcher (`stellar_toolset_invoke`) routes: an
//! action reaches a wallet tool only when the toolset's declared capabilities
//! grant it. A toolset does not narrow the native tools the same MCP server
//! registers; an agent connected to the server can call those directly. The
//! `toolset` argument of an invocation is chosen by the caller, and the server
//! binds no session to a toolset. The operator policy and the approvals bound
//! native and routed calls alike.
//!
//! ## Security guarantees
//!
//! **Signing isolation of the dispatcher is STRUCTURAL**: the ungated
//! capability→tool matrix ([`matrix::grants_for_capability`]) contains no
//! signing/key/policy tool regardless of any capability declaration, and
//! [`SIGNING_DENYLIST`] holds every destructive registry tool. Even a toolset
//! declaring every capability cannot reach a signing tool through the ungated
//! route.
//!
//! **Gated signing path**: `stellar_pay_commit` is reachable through the
//! dispatcher ONLY via `resolve_toolset_sign_payment_gated`, which requires BOTH:
//! 1. The four-part check (toolset declared `sign-payment`; the gated action
//!    resolves; tool ∈ `allowed_tools`).
//! 2. A current, matching first-invoke grant in the [`ToolsetGrantStore`].
//!
//! A `DispatchOutcome::Allow` from the policy engine is OVERRIDDEN to
//! `RequireApproval` for all toolset-routed payments (unconditional per-action
//! approval).
//!
//! **Authenticated install record**: both resolvers and the list read the
//! capabilities from the install record, whose HMAC tag is verified under the
//! installation's [`PinKey`] (a secret in the platform keyring). A record that
//! does not verify refuses with [`ToolsetRuntimeError::PinUnverifiable`]. The
//! record carries the `TOOLSET.md` digest, and both resolvers compare it with
//! the file on disk before any routing.
//!
//! ## Primary consumers
//!
//! The MCP server crate consumes `stellar_toolset_list`, `stellar_toolset_invoke`,
//! and the gated `stellar_toolset_invoke` path routing to `stellar_pay_commit`.
//! The CLI crate consumes `toolsets list` and `toolsets run <name> <action>`.
//!
//! ## What this crate does NOT do
//!
//! - Per-action attestation verification gate — performed by the consumer
//!   (CLI/MCP) layer, not this crate. This crate DOES build HMAC-attested
//!   grants via [`record_first_invoke_grant`]; the verification of those
//!   grants on each action invocation is the consumer's responsibility.
//! - Dynamic tool registration — explicitly out of scope.
//! - Restricting the native tools of a server; the operator policy does that.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod matrix;

pub use error::ToolsetRuntimeError;
pub use matrix::{
    GATED_MATRIX_ENTRIES, SIGN_PAYMENT_GATED_TOOLS, SIGNING_DENYLIST, gated_grants_for_capability,
    resolve_action,
};

use std::path::{Path, PathBuf};

use serde::Serialize;
use stellar_agent_core::approval::toolset_grant::ToolsetGrantReader;
use stellar_agent_core::approval::{
    ApprovalError, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, DEFAULT_TTL_MS, GrantQuery,
    PendingApproval, TOOLSET_GRANT_DEFAULT_TTL_MS, ToolsetGrant, ToolsetGrantStore,
    build_attested_grant, default_toolset_grants_path, open_with_retry,
};
use stellar_agent_toolsets::{Capability, CapabilitySet, sanitise_display};
pub use stellar_agent_toolsets_install::PinKey;
use stellar_agent_toolsets_install::{
    TOOLSETS_LOCK_FILE_NAME, ToolsetInstallError, ToolsetPinRecord, ToolsetsReadLock,
    lock_existing_toolsets_shared, lock_toolsets_shared,
};
use tracing::debug;

// ── Public API ────────────────────────────────────────────────────────────────

/// A single installed-toolset entry as returned by [`list_pinned_toolsets`].
///
/// All string fields are run through [`sanitise_display`] before being stored
/// in this struct. The filesystem path of the installation is NEVER included.
#[derive(Debug, Clone, Serialize)]
pub struct ToolsetListEntry {
    /// Sanitised toolset package name.
    pub name: String,
    /// Always empty; reserved for a future human-readable summary.
    ///
    /// `ToolsetPinRecord` carries only the fields needed for enforcement and does
    /// not store a description, so this is populated as an empty string.
    pub description: String,
    /// Declared capabilities (display tokens, sorted).
    pub capabilities: Vec<String>,
    /// Intersective `allowed_tools` from the pin record (sanitised).
    ///
    /// An empty list means the toolset did not declare `allowed_tools`, so the
    /// full capability grant applies. A non-empty list further restricts which
    /// tools within a capability grant the toolset may reach.
    pub allowed_tools: Vec<String>,
    /// Installed version.
    pub version: String,
    /// Tool names reachable through the UNGATED matrix for this toolset's capabilities.
    ///
    /// Enumerates only tools from the ungated capability→tool matrix
    /// ([`matrix::grants_for_capability`]), optionally filtered by `allowed_tools`.
    /// Gated tools (e.g. `stellar_pay_commit` for `sign-payment`) are reachable
    /// solely through the first-invoke gated path and are intentionally NOT listed
    /// here — the declared capability itself is visible in the `capabilities` field.
    pub actions: Vec<String>,
}

/// Reads all pinned toolset installs from `toolsets_root` and returns their
/// [`ToolsetListEntry`] records.
///
/// Walks `toolsets_root` for subdirectories, attempts to read the pin record
/// from each under `pin_key`, and skips entries whose pin files are absent
/// (logged at debug), malformed or do not verify (logged at warn). This is
/// intentionally resilient so a single corrupted install does not block
/// listing all others. With `pin_key` `None` no record verifies, so the list
/// is empty. The toolsets lock file is skipped by name and never opened.
///
/// The returned list is sorted by toolset name for deterministic output.
///
/// # Errors
///
/// - [`ToolsetRuntimeError::Io`] if `toolsets_root` itself cannot be read.
pub fn list_pinned_toolsets(
    toolsets_root: &Path,
    pin_key: Option<&PinKey>,
) -> Result<Vec<ToolsetListEntry>, ToolsetRuntimeError> {
    // If the toolsets_root does not exist yet, return an empty list rather than
    // an error — it's valid to have no toolsets installed.
    if !toolsets_root.exists() {
        return Ok(Vec::new());
    }

    let read_dir = std::fs::read_dir(toolsets_root)
        .map_err(|e| ToolsetRuntimeError::Io(e.kind().to_string()))?;

    let mut entries: Vec<ToolsetListEntry> = Vec::new();

    for dir_entry in read_dir {
        let dir_entry = match dir_entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "error reading toolsets_root entry; skipping");
                continue;
            }
        };

        if dir_entry.file_name() == TOOLSETS_LOCK_FILE_NAME {
            continue;
        }
        let path = dir_entry.path();
        if !path.is_dir() {
            continue;
        }

        let pkg_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_owned(),
            None => continue,
        };

        let pin = match stellar_agent_toolsets_install::read_pin(&pkg_name, toolsets_root, pin_key)
        {
            Ok(Some(p)) => p,
            Ok(None) => {
                debug!(package = %pkg_name, "no pin record; skipping");
                continue;
            }
            Err(ToolsetInstallError::PinRecordUnverifiable { .. }) => {
                tracing::warn!(
                    package = %pkg_name,
                    "pin record does not verify; skipping (uninstall and install the toolset again)"
                );
                continue;
            }
            Err(ToolsetInstallError::InvalidPackageName { .. }) => {
                tracing::warn!("toolsets root entry must name a valid package; skipping");
                continue;
            }
            Err(e) => {
                tracing::warn!(package = %pkg_name, error = %e, "malformed pin; skipping");
                continue;
            }
        };

        entries.push(pin_to_list_entry(&pin));
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Four-part enforcement check for a toolset action.
///
/// Returns the `&'static str` registry tool name `T` that the action resolves
/// to when ALL four parts pass. The caller MUST route through the returned
/// constant — NOT through any toolset-supplied string.
///
/// ## Four-part logic
///
/// (a) The `action` name resolves — via a CLOSED lookup against the matrix —
///     to a registry tool-name constant `T` (`&'static str`).
///
/// (b) `T` is in the grant set of some capability `C`.
///
/// (c) `C` is in the toolset's declared [`CapabilitySet`] (from the pin).
///
/// (d) `T` is in the toolset's `allowed_tools` (intersective narrowing — can
///     only SUBTRACT from the capability grant, never add). When
///     `allowed_tools` is empty the narrowing is vacuously satisfied.
///
/// SIGNING IS STRUCTURALLY EXCLUDED: the matrix contains no signing/key/policy
/// tool, so even a toolset with all capabilities declared can never reach a
/// signer via the ungated path.
///
/// The dispatch gate of the routed tool (`dispatch_gate`) runs AFTER this
/// check — the toolset gate is ADDITIVE, never substitutive.
///
/// # Errors
///
/// Returns a distinct [`ToolsetRuntimeError`] variant for each failure mode:
///
/// - [`ToolsetRuntimeError::UnknownToolsetAction`] — part (a) failed.
/// - [`ToolsetRuntimeError::CapabilityNotDeclared`] — part (c) failed
///   (the tool exists in the matrix but no granting capability is declared
///   by this toolset).
/// - [`ToolsetRuntimeError::ToolNotAllowed`] — part (d) failed (`allowed_tools`
///   narrowing excluded the tool).
pub fn check_toolset_action(
    action: &str,
    capabilities: &CapabilitySet,
    allowed_tools: &[String],
) -> Result<&'static str, ToolsetRuntimeError> {
    // Part (a): resolve action → registry constant T via the CLOSED matrix.
    let (tool_name, granting_capability) = resolve_action(action)?;

    // Part (b) is already satisfied by resolve_action returning a constant
    // from the matrix — T ∈ grant set of granting_capability by definition.

    // Part (c): granting_capability ∈ toolset's declared CapabilitySet.
    if !capabilities.contains(granting_capability) {
        return Err(ToolsetRuntimeError::CapabilityNotDeclared {
            action: sanitise_display(action, 128),
            capability: granting_capability.to_string(),
        });
    }

    // Part (d): T ∈ allowed_tools (intersective narrowing).
    // An empty allowed_tools list is vacuously satisfied (no narrowing).
    if !allowed_tools.is_empty() && !allowed_tools.iter().any(|t| t == tool_name) {
        return Err(ToolsetRuntimeError::ToolNotAllowed {
            tool: sanitise_display(tool_name, 128),
            action: sanitise_display(action, 128),
        });
    }

    Ok(tool_name)
}

/// Resolves and validates a toolset from its pin record, then runs the four-part
/// enforcement check.
///
/// Validates `toolset_name` against the `[a-z0-9-]` charset BEFORE any filesystem
/// access (path-traversal defence): names containing `/`, `\`, `.`, `..`, or
/// any character outside `[a-z0-9-]` are rejected immediately with
/// [`ToolsetRuntimeError::ToolsetNotInstalled`] and produce NO filesystem read.
///
/// Reads the pin ONCE from `toolsets_root` (TOCTOU avoidance), verifies its
/// tag under `pin_key`, and uses the snapshot for the entire check. Returns
/// `(tool_name, pin)` on success so the caller can use the pin record for
/// further context.
///
/// ## Dispatch-time content re-verification
///
/// Re-reads the on-disk `TOOLSET.md` and compares its SHA-256 against the
/// digest in the authenticated pin. A mismatch
/// or an unreadable file returns [`ToolsetRuntimeError::ContentDigestMismatch`]
/// and refuses dispatch.
///
/// # Errors
///
/// - [`ToolsetRuntimeError::ToolsetNotInstalled`]: `toolset_name` fails charset
///   validation (`[a-z0-9-]`), or no pin record exists for the name.
/// - [`ToolsetRuntimeError::PinUnverifiable`]: a pin record exists but
///   `pin_key` is `None` or the record does not verify under it.
/// - [`ToolsetRuntimeError::Io`]: I/O error reading the pin, or a malformed pin.
/// - [`ToolsetRuntimeError::ContentDigestMismatch`]: on-disk `TOOLSET.md` hash
///   differs from the install-time digest stored in the pin.
/// - Any [`check_toolset_action`] error.
pub fn resolve_toolset_and_check(
    toolset_name: &str,
    action: &str,
    toolsets_root: &Path,
    pin_key: Option<&PinKey>,
) -> Result<(&'static str, ToolsetPinRecord), ToolsetRuntimeError> {
    // Validate toolset_name against [a-z0-9-] BEFORE any filesystem access.
    // Rejects `/`, `\`, `.`, `..`, and all other chars outside the charset.
    // Uses the same validator as the install path.
    stellar_agent_toolsets_install::validate_package_name(toolset_name)
        .map_err(|_| ToolsetRuntimeError::ToolsetNotInstalled)?;

    // Read the pin ONCE — snapshot for the entire check (TOCTOU avoidance).
    let pin = read_verified_pin(toolset_name, toolsets_root, pin_key)?;
    verify_manifest_digest(toolset_name, toolsets_root, &pin)?;

    let capabilities = &pin.capabilities;
    let allowed_tools = &pin.allowed_tools;

    let tool_name = check_toolset_action(action, capabilities, allowed_tools)?;

    Ok((tool_name, pin))
}

/// Compares the on-disk `TOOLSET.md` of `toolset_name` with the digest the
/// authenticated pin recorded at install time.
///
/// Both digests are non-secret hex strings; plain string comparison is
/// correct. A file that cannot be read refuses (fail-closed): the toolset is
/// installed but its manifest is gone or unreadable.
///
/// # Errors
///
/// - [`ToolsetRuntimeError::ContentDigestMismatch`]: the file cannot be read
///   or its SHA-256 differs from `pin.toolset_md_shasum`.
fn verify_manifest_digest(
    toolset_name: &str,
    toolsets_root: &Path,
    pin: &ToolsetPinRecord,
) -> Result<(), ToolsetRuntimeError> {
    let toolset_md_path = toolsets_root.join(toolset_name).join("TOOLSET.md");
    let toolset_md_bytes = std::fs::read(&toolset_md_path).map_err(|_| {
        ToolsetRuntimeError::ContentDigestMismatch {
            name: sanitise_display(toolset_name, 64),
        }
    })?;
    let actual_digest = stellar_agent_toolsets_install::sha256_hex_of(&toolset_md_bytes);
    if actual_digest != pin.toolset_md_shasum {
        tracing::warn!(
            toolset = %toolset_name,
            "dispatch-time TOOLSET.md content digest mismatch; refusing dispatch"
        );
        return Err(ToolsetRuntimeError::ContentDigestMismatch {
            name: sanitise_display(toolset_name, 64),
        });
    }
    debug!(toolset = %toolset_name, "dispatch-time TOOLSET.md content digest verified");
    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Reads and verifies the pin of an already name-validated `toolset_name`.
///
/// An absent record is [`ToolsetRuntimeError::ToolsetNotInstalled`]; a record
/// that does not verify under `pin_key` (or any record when `pin_key` is
/// `None`) is [`ToolsetRuntimeError::PinUnverifiable`]. Other read errors map
/// to a kind-level [`ToolsetRuntimeError::Io`] so the toolsets path does not
/// leak through the error.
fn read_verified_pin(
    toolset_name: &str,
    toolsets_root: &Path,
    pin_key: Option<&PinKey>,
) -> Result<ToolsetPinRecord, ToolsetRuntimeError> {
    match stellar_agent_toolsets_install::read_pin(toolset_name, toolsets_root, pin_key) {
        Ok(Some(pin)) => Ok(pin),
        Ok(None) => Err(ToolsetRuntimeError::ToolsetNotInstalled),
        Err(ToolsetInstallError::PinRecordUnverifiable { .. }) => {
            Err(ToolsetRuntimeError::PinUnverifiable {
                name: sanitise_display(toolset_name, 64),
            })
        }
        Err(e) => Err(ToolsetRuntimeError::Io(install_error_kind_str(&e))),
    }
}

/// Intersective `allowed_tools` narrowing: an empty `allowed_tools` grants every
/// matrix tool; a non-empty one restricts to its listed members.
///
/// Shared by the enforcement path ([`check_toolset_action`] part (d)) and the
/// listing path ([`pin_to_list_entry`]) so both apply one definition of the
/// narrowing rule and cannot diverge.
fn allowed_by_narrowing(allowed_tools: &[String], tool: &str) -> bool {
    allowed_tools.is_empty() || allowed_tools.iter().any(|t| t == tool)
}

/// Converts a [`ToolsetPinRecord`] into a [`ToolsetListEntry`].
///
/// All author-controlled string fields are sanitised before populating the
/// entry. The installed filesystem path is NEVER included.
fn pin_to_list_entry(pin: &ToolsetPinRecord) -> ToolsetListEntry {
    let name = sanitise_display(&pin.package, 64);
    let version = sanitise_display(&pin.version, 64);

    let capabilities: Vec<String> = pin.capabilities.iter().map(|c| c.to_string()).collect();

    let allowed_tools: Vec<String> = pin
        .allowed_tools
        .iter()
        .map(|t| sanitise_display(t, 128))
        .collect();

    // Compute the actions this toolset can invoke: for each declared capability,
    // look up the grant set in the matrix, optionally filter by allowed_tools.
    let mut actions: Vec<String> = Vec::new();
    for cap in pin.capabilities.iter() {
        let grants = matrix::grants_for_capability(cap);
        for &tool in grants {
            // If allowed_tools is non-empty, only include tools present in it.
            if allowed_by_narrowing(&pin.allowed_tools, tool) {
                let sanitised = sanitise_display(tool, 128);
                if !actions.contains(&sanitised) {
                    actions.push(sanitised);
                }
            }
        }
    }
    actions.sort();

    // description: always empty. ToolsetPinRecord carries only enforcement fields,
    // not a description. Reading the on-disk TOOLSET.md here would (a) embed a
    // filesystem path and (b) re-introduce TOCTOU, so the field remains empty.
    let description = String::new();

    ToolsetListEntry {
        name,
        description,
        capabilities,
        allowed_tools,
        version,
        actions,
    }
}

// ── Gated resolver ────────────────────────────────────────────────────────────

/// Parameters for the gated toolset resolve + first-invoke gate check.
///
/// Carries all fields needed by [`resolve_toolset_sign_payment_gated`] in a
/// single struct to avoid an excessively long argument list.
pub struct GatedInvokeParams<'a> {
    /// Package name of the toolset to invoke.
    pub toolset_name: &'a str,
    /// Action name to invoke (must map to a gated tool via the gated matrix).
    pub action: &'a str,
    /// Root directory of installed toolsets.
    pub toolsets_root: &'a Path,
    /// Profile name (used to locate the approval store + grant store).
    pub profile_name: &'a str,
    /// The profile's attestation key.
    pub attestation_key: &'a [u8; 32],
    /// The binding under which the profile's grants are attested.
    pub attestation_binding: &'a stellar_agent_core::approval::AttestationBinding<'a>,
    /// Canonical G-strkey or M-strkey destination from the AUTHORITATIVE
    /// envelope decode (never from toolset-supplied args). An M-strkey keeps
    /// its mux ID, and grants match it exactly.
    pub authoritative_destination: &'a str,
    /// Full `"code:issuer"` or `"XLM"` asset from the AUTHORITATIVE envelope.
    pub authoritative_asset: &'a str,
    /// Payment amount in stroops from the AUTHORITATIVE envelope.
    pub authoritative_amount_stroops: i64,
    /// Current time in Unix milliseconds (for TTL checks).
    pub now_unix_ms: u64,
    /// Platform-stable user identity (from `process_uid_for_attestation()`).
    pub process_uid: &'a str,
    /// The installation's pin key, or `None` when none is available; with
    /// `None` an installed toolset refuses with
    /// [`ToolsetRuntimeError::PinUnverifiable`].
    pub pin_key: Option<&'a PinKey>,
    /// Optional override for the approval store directory (test-only).
    #[cfg(feature = "test-helpers")]
    pub approval_dir_override: Option<std::path::PathBuf>,
    /// Optional override for the grant store path (test-only).
    #[cfg(feature = "test-helpers")]
    pub grant_store_path_override: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for GatedInvokeParams<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatedInvokeParams")
            .field("toolset_name", &self.toolset_name)
            .field("action", &self.action)
            .field("profile_name", &self.profile_name)
            .field("attestation_key", &"[REDACTED]")
            .field("pin_key", &self.pin_key.map(|_| "[REDACTED]"))
            .finish_non_exhaustive()
    }
}

/// Result of the gated toolset resolver.
///
/// Returned by [`resolve_toolset_sign_payment_gated`].
#[derive(Debug)]
pub enum GatedResolveOutcome {
    /// The gated tool name (`"stellar_pay_commit"`) was resolved and a current
    /// grant was found. The per-action approval gate MUST be forced on
    /// unconditionally by the caller.
    Resolved {
        /// The static tool name constant (`"stellar_pay_commit"`).
        tool_name: &'static str,
        /// The grant that matched, with the installation and invocation it
        /// was verified for.
        grant: Box<VerifiedToolsetGrant>,
    },
    /// The first-invoke gate fired: no current grant exists or the parameters
    /// are novel. A `ToolsetFirstInvokeGate` pending approval was queued;
    /// `approval_nonce` is the nonce the caller returns to the agent.
    FirstInvokeApprovalRequired {
        /// Nonce of the queued `ToolsetFirstInvokeGate` pending approval.
        approval_nonce: String,
        /// Sanitised toolset name for the error/response payload.
        toolset_name: String,
        /// Capability token (e.g. `"sign-payment"`).
        capability: String,
    },
}

/// The invocation a grant was verified for. The resolved tool and capability
/// follow from `action` through the closed gated matrix.
#[derive(PartialEq, Eq)]
struct GrantInvocation {
    profile_name: String,
    chain_id: String,
    toolset_name: String,
    action: String,
    destination: String,
    asset: String,
    amount_stroops: i64,
    toolsets_root: PathBuf,
    grant_store_path: PathBuf,
}

/// A grant the gated resolver verified, with the authenticated installation
/// and the exact invocation it was verified for.
///
/// Only the resolver constructs one. It is a snapshot: it grants no signing
/// authority and holds no lock. [`acquire_toolset_grant_lease`] checks it
/// against the current records and locks them.
pub struct VerifiedToolsetGrant {
    pin: ToolsetPinRecord,
    grant: ToolsetGrant,
    invocation: GrantInvocation,
}

impl std::fmt::Debug for VerifiedToolsetGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedToolsetGrant")
            .field("grant_id", &self.grant.grant_id)
            .field("expires_at_unix_ms", &self.grant.expires_at_unix_ms)
            .finish_non_exhaustive()
    }
}

impl VerifiedToolsetGrant {
    /// The stored identifier of the verified grant.
    #[must_use]
    pub fn grant_id(&self) -> &str {
        &self.grant.grant_id
    }

    /// The grant's stored expiry in Unix milliseconds. No check renews it.
    #[must_use]
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.grant.expires_at_unix_ms
    }

    /// The authenticated install record the grant was verified against.
    #[must_use]
    pub fn pin(&self) -> &ToolsetPinRecord {
        &self.pin
    }
}

/// The current invocation a [`VerifiedToolsetGrant`] is rechecked for.
///
/// Every field must equal the invocation the grant was verified for.
pub struct GrantRecheckParams<'a> {
    /// Package name of the toolset.
    pub toolset_name: &'a str,
    /// Action name, exactly as invoked.
    pub action: &'a str,
    /// Root directory of installed toolsets.
    pub toolsets_root: &'a Path,
    /// Profile name that locates the grant store.
    pub profile_name: &'a str,
    /// The profile's attestation key.
    pub attestation_key: &'a [u8; 32],
    /// The binding under which the profile's grants are attested.
    pub attestation_binding: &'a stellar_agent_core::approval::AttestationBinding<'a>,
    /// Destination from the authoritative envelope decode.
    pub authoritative_destination: &'a str,
    /// Asset from the authoritative envelope decode.
    pub authoritative_asset: &'a str,
    /// Payment amount in stroops from the authoritative envelope decode.
    pub authoritative_amount_stroops: i64,
    /// The installation's pin key.
    pub pin_key: Option<&'a PinKey>,
    /// Optional override for the grant store path (test-only).
    #[cfg(feature = "test-helpers")]
    pub grant_store_path_override: Option<PathBuf>,
}

/// Shared locks on the toolsets root and the profile's grant store, held
/// with the grant they protect, in that order.
///
/// While a lease lives, no install, forced reinstall, or uninstall in the
/// root and no grant insertion or revocation of the profile proceeds. The
/// lease does not stop the clock: a consumer checks
/// [`VerifiedToolsetGrant::expires_at_unix_ms`] at the moment it relies on it.
#[derive(Debug)]
pub struct ToolsetGrantLease {
    grant: VerifiedToolsetGrant,
    _grants: ToolsetGrantReader,
    _root: ToolsetsReadLock,
}

impl ToolsetGrantLease {
    /// The grant as checked when the lease was acquired.
    #[must_use]
    pub fn grant(&self) -> &VerifiedToolsetGrant {
        &self.grant
    }
}

/// Locks and rechecks `expected` for the current invocation in `params`.
///
/// Takes the shared root lock, then the shared grant lock, from existing
/// lock files only. The reread install record must equal the snapshot, and
/// the grant itself, not another of equal coverage, must still verify. The
/// clock is read after both locks and again before returning; the stored
/// expiry is never renewed.
///
/// # Errors
///
/// [`ToolsetRuntimeError::GrantInvocationMismatch`] when any invocation field
/// differs, `CoordinationUnavailable`, `CoordinationBusy`, `GrantChanged`,
/// `GrantExpired`, [`ToolsetRuntimeError::Io`] for an unavailable clock, and
/// the binding, install, manifest, capability, amount, and store errors of
/// [`resolve_toolset_sign_payment_gated`].
pub fn acquire_toolset_grant_lease(
    expected: &VerifiedToolsetGrant,
    params: &GrantRecheckParams<'_>,
) -> Result<ToolsetGrantLease, ToolsetRuntimeError> {
    acquire_lease_with_clock(expected, params, &mut || {
        stellar_agent_core::timefmt::now_unix_ms()
            .map_err(|_| ToolsetRuntimeError::Io("clock_unavailable".to_owned()))
    })
}

/// Rechecks `expected` as [`acquire_toolset_grant_lease`] does and releases
/// the locks at once.
///
/// # Errors
///
/// As [`acquire_toolset_grant_lease`].
pub fn recheck_toolset_grant(
    expected: &VerifiedToolsetGrant,
    params: &GrantRecheckParams<'_>,
) -> Result<(), ToolsetRuntimeError> {
    acquire_toolset_grant_lease(expected, params).map(drop)
}

fn acquire_lease_with_clock(
    expected: &VerifiedToolsetGrant,
    params: &GrantRecheckParams<'_>,
    clock: &mut dyn FnMut() -> Result<u64, ToolsetRuntimeError>,
) -> Result<ToolsetGrantLease, ToolsetRuntimeError> {
    if params.attestation_binding.profile_name != params.profile_name {
        return Err(ToolsetRuntimeError::BindingMismatch);
    }
    #[cfg(feature = "test-helpers")]
    let override_path = params.grant_store_path_override.clone();
    #[cfg(not(feature = "test-helpers"))]
    let override_path = None;
    let invocation = GrantInvocation {
        profile_name: params.profile_name.to_owned(),
        chain_id: params.attestation_binding.chain_id.to_owned(),
        toolset_name: params.toolset_name.to_owned(),
        action: params.action.to_owned(),
        destination: params.authoritative_destination.to_owned(),
        asset: params.authoritative_asset.to_owned(),
        amount_stroops: params.authoritative_amount_stroops,
        toolsets_root: params.toolsets_root.to_path_buf(),
        grant_store_path: grant_store_path(params.profile_name, override_path)?,
    };
    if invocation != expected.invocation {
        return Err(ToolsetRuntimeError::GrantInvocationMismatch);
    }

    let root = lock_existing_toolsets_shared(params.toolsets_root)
        .map_err(root_lock_error)?
        .ok_or(ToolsetRuntimeError::CoordinationUnavailable)?;
    let install = verify_gated_install(
        params.toolset_name,
        params.action,
        params.toolsets_root,
        params.pin_key,
        params.authoritative_amount_stroops,
    )?;
    if install.pin != expected.pin {
        return Err(ToolsetRuntimeError::GrantChanged);
    }
    let grants = ToolsetGrantReader::open_existing(&invocation.grant_store_path)
        .map_err(grant_store_open_error)?
        .ok_or(ToolsetRuntimeError::CoordinationUnavailable)?;

    let now_unix_ms = clock()?;
    if expected.grant.is_expired(now_unix_ms) {
        return Err(ToolsetRuntimeError::GrantExpired);
    }
    let capability = install.capability.to_string();
    let query = grant_query(&invocation, &install.pin, &capability, now_unix_ms);
    if grants
        .find_verified(
            &expected.grant,
            &query,
            params.attestation_key,
            params.attestation_binding,
        )
        .is_none()
    {
        return Err(ToolsetRuntimeError::GrantChanged);
    }
    if expected.grant.is_expired(clock()?) {
        return Err(ToolsetRuntimeError::GrantExpired);
    }
    Ok(ToolsetGrantLease {
        grant: VerifiedToolsetGrant {
            pin: install.pin,
            grant: expected.grant.clone(),
            invocation,
        },
        _grants: grants,
        _root: root,
    })
}

/// The install record and gated route both resolution and recheck verify.
struct GatedInstall {
    pin: ToolsetPinRecord,
    tool_name: &'static str,
    capability: Capability,
}

/// Verifies the pin, the manifest, the gated action, the declared
/// capability, the `allowed_tools` narrowing, and a positive amount, in
/// that order, for an already name-validated `toolset_name`.
fn verify_gated_install(
    toolset_name: &str,
    action: &str,
    toolsets_root: &Path,
    pin_key: Option<&PinKey>,
    amount_stroops: i64,
) -> Result<GatedInstall, ToolsetRuntimeError> {
    let pin = read_verified_pin(toolset_name, toolsets_root, pin_key)?;
    verify_manifest_digest(toolset_name, toolsets_root, &pin)?;

    // Part (a): the action resolves in the GATED matrix, not the ungated one;
    // part (b) follows from the matrix itself.
    let (tool_name, capability) = resolve_gated_action(action)?;

    // Part (c): the granting capability is declared.
    if !pin.capabilities.contains(capability) {
        return Err(ToolsetRuntimeError::CapabilityNotDeclared {
            action: sanitise_display(action, 128),
            capability: capability.to_string(),
        });
    }

    // Part (d): the tool survives the allowed_tools narrowing.
    if !allowed_by_narrowing(&pin.allowed_tools, tool_name) {
        return Err(ToolsetRuntimeError::ToolNotAllowed {
            tool: sanitise_display(tool_name, 128),
            action: sanitise_display(action, 128),
        });
    }

    // A zero or negative amount is structurally invalid for a payment, and a
    // grant of the bucket [0, N] would otherwise cover it. The caller's
    // envelope decode is not trusted to have enforced positivity.
    if amount_stroops <= 0 {
        return Err(ToolsetRuntimeError::InvalidAuthoritativeAmount);
    }
    Ok(GatedInstall {
        pin,
        tool_name,
        capability,
    })
}

/// Grants issued before this instant belong to an earlier installation: the
/// start of the second after the authenticated install time. An install time
/// that does not parse honors no grant.
fn install_cutoff_ms(pin: &ToolsetPinRecord) -> u64 {
    stellar_agent_core::timefmt::parse_rfc3339_utc(&pin.installed_at).map_or_else(
        || {
            tracing::warn!(
                toolset = %pin.package,
                "first-invoke gate: the pin's install time does not parse; honoring no grant"
            );
            u64::MAX
        },
        |installed_secs| (installed_secs + 1) * 1_000,
    )
}

fn grant_query<'a>(
    invocation: &'a GrantInvocation,
    pin: &'a ToolsetPinRecord,
    capability: &'a str,
    now_unix_ms: u64,
) -> GrantQuery<'a> {
    GrantQuery {
        toolset_name: &invocation.toolset_name,
        install_id: &pin.install_id,
        package_version: &pin.version,
        package_shasum: &pin.shasum,
        capability,
        destination: &invocation.destination,
        asset: &invocation.asset,
        amount_stroops: invocation.amount_stroops,
        now_unix_ms,
        not_before_unix_ms: install_cutoff_ms(pin),
    }
}

/// The grant store path of `profile_name`, or `override_path` when given.
fn grant_store_path(
    profile_name: &str,
    override_path: Option<PathBuf>,
) -> Result<PathBuf, ToolsetRuntimeError> {
    match override_path {
        Some(path) => Ok(path),
        None => default_toolset_grants_path(profile_name).map_err(|e| {
            ToolsetRuntimeError::GrantStoreError {
                detail: format!("grant_store_path: {e}"),
            }
        }),
    }
}

fn root_lock_error(error: ToolsetInstallError) -> ToolsetRuntimeError {
    match error {
        ToolsetInstallError::Busy => ToolsetRuntimeError::CoordinationBusy,
        other => ToolsetRuntimeError::Io(install_error_kind_str(&other)),
    }
}

fn grant_store_open_error(error: ApprovalError) -> ToolsetRuntimeError {
    match error {
        ApprovalError::WriterLocked => ToolsetRuntimeError::CoordinationBusy,
        other => ToolsetRuntimeError::GrantStoreError {
            detail: format!("open: {other}"),
        },
    }
}

/// The GATED resolver for toolset-routed `sign-payment` invocations.
///
/// This is a **DISTINCT entry point** from [`resolve_toolset_and_check`] — it is
/// NOT a `route_to_matrix_tool` arm. It implements the full enforcement ordering:
///
/// 1. **Four-part check** (via the gated matrix): toolset declared `sign-payment`;
///    the action maps to a gated constant; the tool is in `allowed_tools`.
/// 2. **First-invoke gate**: check the grant store for a verified, current grant
///    from the current installation.
///    If none → queue `ToolsetFirstInvokeGate` approval, return
///    [`GatedResolveOutcome::FirstInvokeApprovalRequired`], REFUSE.
/// 3. On grant match → return [`GatedResolveOutcome::Resolved`] with the
///    [`VerifiedToolsetGrant`]. The CALLER MUST then route to
///    `stellar_pay_commit` with the per-action `PaymentSimulated` approval
///    FORCED ON UNCONDITIONALLY.
///
/// # Locks
///
/// Steps 1 and 2 hold the shared root lock, and step 2 the exclusive grant
/// lock, each taken without waiting and created when absent. Both release
/// before a first-invoke approval is queued.
///
/// # Security
///
/// - All matching is computed from the AUTHORITATIVE envelope params in
///   `params` — NEVER from toolset-supplied args.
/// - A `DispatchOutcome::Allow` from the policy engine MUST be overridden to
///   `RequireApproval` by the caller for toolset-routed payments. This function
///   returns `GatedResolveOutcome::Resolved` to signal the path is open; the
///   unconditional per-action approval enforcement is the caller's responsibility.
/// - Only a verified version 3 grant for the current install identity, version
///   and shasum, within the default TTL and issued after the current
///   installation suppresses the first-invoke prompt. A forged or edited grant
///   suppresses nothing. Per-action payment approval always fires.
///
/// # Errors
///
/// - [`ToolsetRuntimeError::ToolsetNotInstalled`]: toolset not installed or
///   name fails charset validation.
/// - [`ToolsetRuntimeError::BindingMismatch`]: the binding names another profile.
/// - [`ToolsetRuntimeError::PinUnverifiable`]: the pin record does not verify
///   under `params.pin_key`, or no key is available.
/// - [`ToolsetRuntimeError::ContentDigestMismatch`]: the on-disk `TOOLSET.md`
///   differs from the digest in the pin, or cannot be read.
/// - [`ToolsetRuntimeError::UnknownToolsetAction`]: action not in the gated matrix.
/// - [`ToolsetRuntimeError::CapabilityNotDeclared`]: `sign-payment` not declared.
/// - [`ToolsetRuntimeError::ToolNotAllowed`]: tool excluded by `allowed_tools`.
/// - [`ToolsetRuntimeError::CoordinationBusy`]: an install, uninstall, or grant
///   writer holds the root or grant lock, or a grant lease holds the grant lock.
/// - [`ToolsetRuntimeError::GrantStoreError`]: I/O error accessing the grant store.
/// - [`ToolsetRuntimeError::Io`]: I/O error accessing the pending-approval store.
///
/// # Returns
///
/// Returns `Ok(GatedResolveOutcome::FirstInvokeApprovalRequired { .. })` when
/// the gate fires (NOT an `Err`), so the caller can cleanly distinguish
/// "gate fired, queue approval" from "hard error".
#[allow(clippy::too_many_lines)]
pub fn resolve_toolset_sign_payment_gated(
    params: &GatedInvokeParams<'_>,
) -> Result<GatedResolveOutcome, ToolsetRuntimeError> {
    if params.attestation_binding.profile_name != params.profile_name {
        return Err(ToolsetRuntimeError::BindingMismatch);
    }
    let toolset_name = params.toolset_name;
    let action = params.action;

    // ── Step 0: Validate toolset_name charset ───────────────────────────────────
    stellar_agent_toolsets_install::validate_package_name(toolset_name)
        .map_err(|_| ToolsetRuntimeError::ToolsetNotInstalled)?;

    // ── Step 1: Under the shared root lock, read and verify the pin ONCE and
    // run the gated four-part check ────────────────────────────────────────────
    let root_lock = lock_toolsets_shared(params.toolsets_root)
        .map_err(root_lock_error)?
        .ok_or(ToolsetRuntimeError::ToolsetNotInstalled)?;
    let GatedInstall {
        pin,
        tool_name,
        capability: granting_capability,
    } = verify_gated_install(
        toolset_name,
        action,
        params.toolsets_root,
        params.pin_key,
        params.authoritative_amount_stroops,
    )?;
    let amount = params.authoritative_amount_stroops;

    // ── Step 2: First-invoke gate check ──────────────────────────────────────
    //
    // Under the exclusive grant lock, look for a verified, current grant
    // from the current installation.
    // All matching is computed from the AUTHORITATIVE envelope params.
    #[cfg(feature = "test-helpers")]
    let override_path = params.grant_store_path_override.clone();
    #[cfg(not(feature = "test-helpers"))]
    let override_path = None;
    let invocation = GrantInvocation {
        profile_name: params.profile_name.to_owned(),
        chain_id: params.attestation_binding.chain_id.to_owned(),
        toolset_name: toolset_name.to_owned(),
        action: action.to_owned(),
        destination: params.authoritative_destination.to_owned(),
        asset: params.authoritative_asset.to_owned(),
        amount_stroops: amount,
        toolsets_root: params.toolsets_root.to_path_buf(),
        grant_store_path: grant_store_path(params.profile_name, override_path)?,
    };
    let grant_store =
        ToolsetGrantStore::open(invocation.grant_store_path.clone(), params.now_unix_ms)
            .map_err(grant_store_open_error)?;

    let capability_str = granting_capability.to_string();
    let query = grant_query(&invocation, &pin, &capability_str, params.now_unix_ms);
    if let Some(grant) =
        grant_store.find_matching(&query, params.attestation_key, params.attestation_binding)
    {
        // Grant found — the first-invoke gate is short-circuited.
        // The CALLER MUST force the per-action PaymentSimulated approval
        // unconditionally (Override Allow → RequireApproval).
        tracing::debug!(
            toolset = %toolset_name,
            capability = %capability_str,
            "first-invoke gate: matching grant found; routing to gated tool (per-action approval will be forced on by caller)"
        );
        let grant = Box::new(VerifiedToolsetGrant {
            grant: grant.clone(),
            pin,
            invocation,
        });
        return Ok(GatedResolveOutcome::Resolved { tool_name, grant });
    }

    // ── No current grant: queue the first-invoke gate approval ───────────────
    // Both locks release first, so a grant writer is never held up behind
    // the pending-approval store.
    drop((grant_store, root_lock));
    #[cfg(test)]
    tests::before_first_invoke_queue();

    // Compute the bucket bounds from the authoritative amount. Conservative:
    // the bucket is the range [0, amount] — any future invoke with amount >
    // amount_max_stroops re-prompts. A one-time grant for X stroops does NOT
    // authorise payments exceeding X.
    //
    // amount_min_stroops = 0: the lower bound is 0 (any non-negative amount
    // ≤ amount_max is within the bucket).
    // amount_max_stroops = amount: positive (checked above).
    let amount_min_stroops = 0_i64;
    let amount_max_stroops = amount;
    let destination = params.authoritative_destination;
    let asset = params.authoritative_asset;

    // Use the caller-supplied process_uid directly. The caller is responsible
    // for providing the platform-stable user identity; honoring it here keeps
    // the field meaningful and consistent with record_first_invoke_grant, which
    // also trusts its caller-supplied process_uid.
    let uid = params.process_uid.to_owned();

    // Queue the ToolsetFirstInvokeGate pending approval.
    let pending = PendingApproval::new_toolset_first_invoke_gate_pending(
        toolset_name.to_owned(),
        pin.install_id.clone(),
        pin.version.clone(),
        pin.shasum.clone(),
        capability_str.clone(),
        destination.to_owned(),
        asset.to_owned(),
        amount_min_stroops,
        amount_max_stroops,
        uid,
        DEFAULT_TTL_MS,
    )
    .map_err(|e| ToolsetRuntimeError::Io(format!("new_toolset_gate_pending: {e}")))?;

    let approval_nonce = pending.approval_nonce.clone();

    // Persist to the pending-approval store.
    let approval_store_path = {
        #[cfg(feature = "test-helpers")]
        {
            if let Some(ref override_dir) = params.approval_dir_override {
                override_dir.join(format!("{}.toml", params.profile_name))
            } else {
                build_approval_store_path(params.profile_name).ok_or_else(|| {
                    ToolsetRuntimeError::Io("approval_store_path: dir unavailable".to_owned())
                })?
            }
        }
        #[cfg(not(feature = "test-helpers"))]
        {
            build_approval_store_path(params.profile_name).ok_or_else(|| {
                ToolsetRuntimeError::Io("approval_store_path: dir unavailable".to_owned())
            })?
        }
    };

    let mut approval_store = open_with_retry(
        &approval_store_path,
        DEFAULT_RETRY_ATTEMPTS,
        DEFAULT_RETRY_BACKOFF,
    )
    .map_err(|e| ToolsetRuntimeError::Io(format!("approval_store_open: {e}")))?;

    approval_store
        .insert(pending, params.now_unix_ms)
        .map_err(|e| ToolsetRuntimeError::Io(format!("approval_store_insert: {e}")))?;

    tracing::debug!(
        toolset = %toolset_name,
        capability = %capability_str,
        nonce = %approval_nonce,
        "first-invoke gate: no current grant; queued ToolsetFirstInvokeGate approval"
    );

    Ok(GatedResolveOutcome::FirstInvokeApprovalRequired {
        approval_nonce,
        toolset_name: sanitise_display(toolset_name, 64),
        capability: sanitise_display(&capability_str, 64),
    })
}

/// Optional override for the grant store path passed to [`record_first_invoke_grant`].
///
/// Pass `None` in production — the path is resolved via `default_toolset_grants_path`.
/// Pass `Some(path)` in integration tests to write to a `TempDir`.
pub type GrantStorePathOverride = Option<std::path::PathBuf>;

/// Records a confirmed first-invoke grant after the operator approves a
/// `ToolsetFirstInvokeGate` pending approval.
///
/// Called by the CLI `approve` handler after verifying the attestation.
/// The grant is persisted to the grant store with the supplied attestation key.
///
/// Pass `None` for `grant_store_path_override` in production. Integration tests
/// pass `Some(path)` pointing to a `tempfile::TempDir` to avoid writing to the
/// real grant store.
///
/// # Errors
///
/// - [`ToolsetRuntimeError::BindingMismatch`] when the binding names another profile.
/// - [`ToolsetRuntimeError::CoordinationBusy`] while another grant writer or a
///   grant lease holds the grant lock.
/// - [`ToolsetRuntimeError::GrantStoreError`] on grant store I/O failure.
#[allow(clippy::too_many_arguments)]
pub fn record_first_invoke_grant(
    profile_name: &str,
    toolset_name: &str,
    install_id: &str,
    package_version: &str,
    package_shasum: &str,
    capability: &str,
    destination: &str,
    asset: &str,
    amount_min_stroops: i64,
    amount_max_stroops: i64,
    process_uid: &str,
    now_unix_ms: u64,
    attestation_key: &[u8; 32],
    binding: &stellar_agent_core::approval::AttestationBinding<'_>,
    // Optional override for the grant store path.
    // Pass `None` in production; `Some(path)` in integration tests.
    grant_store_path_override: GrantStorePathOverride,
) -> Result<ToolsetGrant, ToolsetRuntimeError> {
    if binding.profile_name != profile_name {
        return Err(ToolsetRuntimeError::BindingMismatch);
    }
    let grant = build_attested_grant(
        toolset_name.to_owned(),
        install_id.to_owned(),
        package_version.to_owned(),
        package_shasum.to_owned(),
        capability.to_owned(),
        destination.to_owned(),
        asset.to_owned(),
        amount_min_stroops,
        amount_max_stroops,
        process_uid.to_owned(),
        now_unix_ms,
        TOOLSET_GRANT_DEFAULT_TTL_MS,
        attestation_key,
        binding,
    )
    .map_err(|e| ToolsetRuntimeError::GrantStoreError {
        detail: format!("build_attested_grant: {e}"),
    })?;

    let grant_store_path = grant_store_path(profile_name, grant_store_path_override)?;
    let mut store =
        ToolsetGrantStore::open(grant_store_path, now_unix_ms).map_err(grant_store_open_error)?;

    let grant_clone = grant.clone();
    store
        .insert(grant)
        .map_err(|e| ToolsetRuntimeError::GrantStoreError {
            detail: format!("insert: {e}"),
        })?;

    Ok(grant_clone)
}

/// Resolves a gated action string to a `(&'static str, Capability)` pair
/// via the CLOSED gated matrix lookup.
///
/// Returns `Ok((tool_name, granting_capability))` if the action is in the
/// gated matrix, or `Err(ToolsetRuntimeError::UnknownToolsetAction)` otherwise.
///
/// This ensures the gated tool name is a compile-time constant — a
/// toolset-supplied `String` cannot become a `&'static str`.
///
/// # Errors
///
/// - [`ToolsetRuntimeError::UnknownToolsetAction`] — the action is not in the
///   gated matrix.
pub fn resolve_gated_action(
    action: &str,
) -> Result<(&'static str, Capability), ToolsetRuntimeError> {
    for (cap, tools) in matrix::GATED_MATRIX_ENTRIES {
        for tool in *tools {
            if *tool == action {
                return Ok((tool, *cap));
            }
        }
    }
    Err(ToolsetRuntimeError::UnknownToolsetAction)
}

/// Helper: build the pending-approval store path from profile name.
///
/// Returns `None` if the approval dir cannot be resolved; the caller converts
/// to a `ToolsetRuntimeError::Io`.
fn build_approval_store_path(profile_name: &str) -> Option<std::path::PathBuf> {
    let dir = stellar_agent_core::profile::schema::default_approval_dir().ok()?;
    Some(dir.join(format!("{profile_name}.toml")))
}

// ── Re-exports for consumers ─────────────────────────────────────────────────

/// Re-export [`stellar_agent_toolsets_install::read_pin`] as a crate-level
/// convenience so MCP/CLI consumers can read pins without adding a direct dep
/// on `stellar-agent-toolsets-install`.
pub use stellar_agent_toolsets_install::read_pin;

/// Re-export [`stellar_agent_toolsets_install::validate_package_name`] so callers
/// can pre-validate toolset names before calling [`resolve_toolset_and_check`].
pub use stellar_agent_toolsets_install::validate_package_name;

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Maps a [`ToolsetInstallError`] to a kind-level
/// I/O message string for use in [`ToolsetRuntimeError::Io`].
///
/// Uses `io::ErrorKind` level granularity to avoid leaking `toolsets_root`
/// through this conversion (a future path-annotating I/O error cannot reach
/// `ToolsetRuntimeError::Io` via this function).
fn install_error_kind_str(e: &ToolsetInstallError) -> String {
    // ToolsetInstallError already sanitises its Io variant internally, but we
    // want a fixed-class message not the full Display (which may embed detail).
    // For non-Io variants (PinRecordMalformed etc.) we use the variant name only.
    match e {
        ToolsetInstallError::Io { .. } => "io_error".to_owned(),
        ToolsetInstallError::PinRecordMalformed { .. } => "pin_record_malformed".to_owned(),
        _ => "install_error".to_owned(),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in unit tests"
)]
mod tests {
    use super::*;

    thread_local! {
        /// Runs on the resolver's thread just before it opens the
        /// pending-approval store on a first-invoke miss.
        static BEFORE_FIRST_INVOKE_QUEUE: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn before_first_invoke_queue() {
        BEFORE_FIRST_INVOKE_QUEUE.with_borrow_mut(|hook| {
            if let Some(hook) = hook {
                hook();
            }
        });
    }

    /// The pin key every fixture record is tagged under.
    fn test_pin_key() -> &'static PinKey {
        static KEY: std::sync::LazyLock<PinKey> =
            std::sync::LazyLock::new(|| PinKey::from_bytes(zeroize::Zeroizing::new([0x5a; 32])));
        &KEY
    }

    fn all_caps() -> CapabilitySet {
        // Build a full capability set by parsing the known tokens.
        stellar_agent_toolsets::parse_capability_value_pub(
            "read-balance propose-transaction suggest-destination observe-event",
        )
        .unwrap()
    }

    // ── check_toolset_action: part (a) — unknown action ────────────────────────

    #[test]
    fn unknown_action_returns_error() {
        let caps = all_caps();
        let err = check_toolset_action("no-such-action", &caps, &[]).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::UnknownToolsetAction),
            "expected UnknownToolsetAction, got: {err:?}"
        );
    }

    // ── check_toolset_action: part (c) — capability not declared ───────────────

    #[test]
    fn capability_not_declared_returns_error() {
        // ReadBalance is not declared; action "stellar_balances" requires it.
        let empty_caps = CapabilitySet::empty();
        let err = check_toolset_action("stellar_balances", &empty_caps, &[]).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::CapabilityNotDeclared { .. }),
            "expected CapabilityNotDeclared, got: {err:?}"
        );
    }

    #[test]
    fn empty_capability_set_refuses_all_known_actions() {
        let empty_caps = CapabilitySet::empty();
        // Every action in the matrix must fail with CapabilityNotDeclared.
        for (action, _cap) in matrix::ALL_MATRIX_ENTRIES {
            let err = check_toolset_action(action, &empty_caps, &[]).unwrap_err();
            assert!(
                matches!(err, ToolsetRuntimeError::CapabilityNotDeclared { .. }),
                "action {action}: expected CapabilityNotDeclared, got: {err:?}"
            );
        }
    }

    // ── check_toolset_action: part (d) — allowed_tools narrowing ───────────────

    #[test]
    fn allowed_tools_narrowing_excludes_tool() {
        // ReadBalance is declared, but allowed_tools is non-empty and excludes
        // stellar_balances.
        let caps = stellar_agent_toolsets::parse_capability_value_pub("read-balance").unwrap();
        let err = check_toolset_action("stellar_balances", &caps, &["some-other-tool".to_owned()])
            .unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolNotAllowed { .. }),
            "expected ToolNotAllowed, got: {err:?}"
        );
    }

    #[test]
    fn allowed_tools_empty_vacuously_satisfied() {
        let caps = stellar_agent_toolsets::parse_capability_value_pub("read-balance").unwrap();
        let tool = check_toolset_action("stellar_balances", &caps, &[]).unwrap();
        assert_eq!(tool, "stellar_balances");
    }

    // ── Signing-tool-in-allowed_tools still refused ───────────────────────────

    #[test]
    fn all_caps_plus_signing_in_allowed_tools_still_refused() {
        // Declare every capability and list a signing tool in allowed_tools.
        // The matrix has no signing tool, so resolve_action must fail first.
        let caps = all_caps();
        let allowed = vec![
            "stellar_sep43_sign_transaction".to_owned(),
            "stellar_sep53_sign_message".to_owned(),
            "stellar_pay_commit".to_owned(),
        ];
        for signing_tool in &allowed {
            let err = check_toolset_action(signing_tool, &caps, &allowed).unwrap_err();
            assert!(
                matches!(err, ToolsetRuntimeError::UnknownToolsetAction),
                "signing tool {signing_tool}: expected UnknownToolsetAction (not in matrix), got: {err:?}"
            );
        }
    }

    // ── read-balance toolset invoking propose action is refused ─────────────────

    #[test]
    fn read_balance_toolset_cannot_invoke_propose_action() {
        let caps = stellar_agent_toolsets::parse_capability_value_pub("read-balance").unwrap();
        // stellar_pay is only granted by ProposeTransaction, not ReadBalance.
        let err = check_toolset_action("stellar_pay", &caps, &[]).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::CapabilityNotDeclared { .. }),
            "expected CapabilityNotDeclared, got: {err:?}"
        );
    }

    // ── Dispatcher tools are unreachable via any capability ───────────────────

    #[test]
    fn dispatcher_tools_not_reachable_via_any_capability() {
        let caps = all_caps();
        // stellar_toolset_list and stellar_toolset_invoke must not be in the matrix.
        for dispatcher_tool in ["stellar_toolset_list", "stellar_toolset_invoke"] {
            let err = check_toolset_action(dispatcher_tool, &caps, &[]).unwrap_err();
            assert!(
                matches!(err, ToolsetRuntimeError::UnknownToolsetAction),
                "dispatcher tool {dispatcher_tool}: expected UnknownToolsetAction, got: {err:?}"
            );
        }
    }

    // ── Happy-path: ReadBalance → stellar_balances ───────────────────────────

    #[test]
    fn read_balance_grants_stellar_balances() {
        let caps = stellar_agent_toolsets::parse_capability_value_pub("read-balance").unwrap();
        let tool = check_toolset_action("stellar_balances", &caps, &[]).unwrap();
        assert_eq!(tool, "stellar_balances");
    }

    // ── Happy-path: ProposeTransaction → stellar_pay ─────────────────────────

    #[test]
    fn propose_transaction_grants_stellar_pay() {
        let caps =
            stellar_agent_toolsets::parse_capability_value_pub("propose-transaction").unwrap();
        let tool = check_toolset_action("stellar_pay", &caps, &[]).unwrap();
        assert_eq!(tool, "stellar_pay");
    }

    // ── Happy-path: ReadRules → stellar_rules_list / stellar_rules_get ───────

    /// A toolset granting ONLY `read-rules` resolves exactly the two
    /// rules-observability tools through the runtime grant path
    /// (`check_toolset_action` → `resolve_action` → `grants_for_capability`)
    /// — the offline guard against the `grants_for_capability` `_ => &[]`
    /// wildcard silently swallowing the new capability.
    #[test]
    fn read_rules_grants_exactly_stellar_rules_list_and_get() {
        let caps = stellar_agent_toolsets::parse_capability_value_pub("read-rules").unwrap();

        let list_tool = check_toolset_action("stellar_rules_list", &caps, &[]).unwrap();
        assert_eq!(list_tool, "stellar_rules_list");

        let get_tool = check_toolset_action("stellar_rules_get", &caps, &[]).unwrap();
        assert_eq!(get_tool, "stellar_rules_get");

        // Negative: read-rules must NOT grant any other matrix tool.
        for other in matrix::ALL_MATRIX_TOOL_NAMES {
            if *other == "stellar_rules_list" || *other == "stellar_rules_get" {
                continue;
            }
            let err = check_toolset_action(other, &caps, &[]).unwrap_err();
            assert!(
                matches!(err, ToolsetRuntimeError::CapabilityNotDeclared { .. }),
                "read-rules must not grant '{other}'; got {err:?}"
            );
        }
    }

    /// A toolset that does NOT declare `read-rules` cannot invoke either
    /// rules-observability tool.
    #[test]
    fn toolset_without_read_rules_cannot_invoke_rules_tools() {
        let caps = stellar_agent_toolsets::parse_capability_value_pub("read-balance").unwrap();
        for tool in ["stellar_rules_list", "stellar_rules_get"] {
            let err = check_toolset_action(tool, &caps, &[]).unwrap_err();
            assert!(
                matches!(err, ToolsetRuntimeError::CapabilityNotDeclared { .. }),
                "expected CapabilityNotDeclared for '{tool}', got: {err:?}"
            );
        }
    }

    // ── list_pinned_toolsets: empty toolsets_root ─────────────────────────────────

    #[test]
    fn list_pinned_toolsets_empty_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let list = list_pinned_toolsets(dir.path(), Some(test_pin_key())).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn list_pinned_toolsets_nonexistent_dir() {
        let list = list_pinned_toolsets(
            std::path::Path::new("/nonexistent/toolsets_root"),
            Some(test_pin_key()),
        )
        .unwrap();
        assert!(list.is_empty());
    }

    // ── Path-traversal adversarial tests ─────────────────────────────────────
    //
    // Verifies that `resolve_toolset_and_check` rejects attacker-controlled toolset
    // names containing path components (slash, backslash, dotdot) BEFORE any
    // filesystem read. All cases must return ToolsetNotInstalled with NO filesystem
    // access outside the (empty) temp dir.

    #[test]
    fn path_traversal_dotdot_slash_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = resolve_toolset_and_check(
            "../foo",
            "stellar_balances",
            dir.path(),
            Some(test_pin_key()),
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled),
            "expected ToolsetNotInstalled for '../foo', got: {err:?}"
        );
    }

    #[test]
    fn path_traversal_slash_in_name_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let err =
            resolve_toolset_and_check("a/b", "stellar_balances", dir.path(), Some(test_pin_key()))
                .unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled),
            "expected ToolsetNotInstalled for 'a/b', got: {err:?}"
        );
    }

    #[test]
    fn path_traversal_backslash_in_name_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        // "..\\foo" on any platform: backslash is not in [a-z0-9-], so rejected.
        let err = resolve_toolset_and_check(
            "..\\foo",
            "stellar_balances",
            dir.path(),
            Some(test_pin_key()),
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled),
            "expected ToolsetNotInstalled for '..\\\\foo', got: {err:?}"
        );
    }

    #[test]
    fn path_traversal_dotdot_alone_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let err =
            resolve_toolset_and_check("..", "stellar_balances", dir.path(), Some(test_pin_key()))
                .unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled),
            "expected ToolsetNotInstalled for '..', got: {err:?}"
        );
    }

    #[test]
    fn path_traversal_dot_alone_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let err =
            resolve_toolset_and_check(".", "stellar_balances", dir.path(), Some(test_pin_key()))
                .unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled),
            "expected ToolsetNotInstalled for '.', got: {err:?}"
        );
    }

    #[test]
    fn path_traversal_uppercase_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = resolve_toolset_and_check(
            "MyToolset",
            "stellar_balances",
            dir.path(),
            Some(test_pin_key()),
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled),
            "expected ToolsetNotInstalled for 'MyToolset', got: {err:?}"
        );
    }

    #[test]
    fn path_traversal_null_byte_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = resolve_toolset_and_check(
            "toolset\0name",
            "stellar_balances",
            dir.path(),
            Some(test_pin_key()),
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled),
            "expected ToolsetNotInstalled for null-byte name, got: {err:?}"
        );
    }

    // ── Dispatch-time TOOLSET.md content re-verification ───────────────────────
    //
    // Scenarios:
    //
    //   (A) TOOLSET.md is unmodified → dispatch succeeds.
    //   (B) TOOLSET.md is tampered   → ContentDigestMismatch.
    //   (C) TOOLSET.md is missing    → ContentDigestMismatch.
    //
    // Setup: write a minimal valid TOOLSET.md + a tagged pin record into a
    // tempdir.

    /// Writes a minimal valid `TOOLSET.md` to `<toolsets_root>/<pkg>/TOOLSET.md`.
    fn write_toolset_md(toolsets_root: &std::path::Path, pkg: &str, content: &str) {
        let toolset_dir = toolsets_root.join(pkg);
        std::fs::create_dir_all(&toolset_dir).unwrap();
        std::fs::write(toolset_dir.join("TOOLSET.md"), content).unwrap();
    }

    /// Writes `pin` to `<toolsets_root>/<package>/` as a record tagged under
    /// [`test_pin_key`].
    fn write_pin(toolsets_root: &std::path::Path, pin: &ToolsetPinRecord) {
        stellar_agent_toolsets_install::write_pin_for_test(pin, toolsets_root, test_pin_key())
            .unwrap();
    }

    /// Writes a `TOOLSET.md` for `pkg` declaring `caps` and a tagged pin record
    /// carrying its digest, as an install would.
    fn write_toolset_fixture(
        toolsets_root: &std::path::Path,
        pkg: &str,
        caps: &str,
        allowed_tools: Vec<String>,
        installed_at: &str,
    ) -> ToolsetPinRecord {
        let capability_lines: String = caps
            .split_whitespace()
            .map(|token| format!("  - {token}\n"))
            .collect();
        let content = format!(
            "---\nname: {pkg}\ndescription: test toolset\nstellar-agent-capabilities:\n{capability_lines}---\n# {pkg}\n"
        );
        write_toolset_md(toolsets_root, pkg, &content);
        let pin = ToolsetPinRecord::build_for_test(
            pkg,
            "1.0.0",
            "d".repeat(64),
            "GABC1234567890123456789012345678901234567890123456",
            installed_at,
            stellar_agent_toolsets::parse_capability_value_pub(caps).unwrap(),
            allowed_tools,
            stellar_agent_toolsets_install::sha256_hex_of(content.as_bytes()),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        write_pin(toolsets_root, &pin);
        pin
    }

    /// Applies `edit` to the stored JSON of `pkg`'s record without re-tagging it.
    fn edit_stored_pin(
        toolsets_root: &std::path::Path,
        pkg: &str,
        edit: impl FnOnce(&mut serde_json::Value),
    ) {
        let path = toolsets_root
            .join(pkg)
            .join(".stellar-agent-toolset-pin.json");
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        edit(&mut value);
        std::fs::write(&path, serde_json::to_string(&value).unwrap()).unwrap();
    }

    /// Adds `token` to the stored capability list of `pkg`'s record.
    fn add_stored_capability(toolsets_root: &std::path::Path, pkg: &str, token: &str) {
        edit_stored_pin(toolsets_root, pkg, |value| {
            value["capabilities"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!(token));
        });
    }

    /// Returns a minimal valid TOOLSET.md content string for package `pkg` with
    /// `read-balance` capability.
    fn minimal_toolset_md(pkg: &str) -> String {
        format!(
            "---\nname: {pkg}\ndescription: test toolset\nstellar-agent-capabilities:\n  - read-balance\n---\n# {pkg}\n"
        )
    }

    // ── (A) Unmodified TOOLSET.md → dispatches ──────────────────────────────────

    #[test]
    fn content_digest_match_allows_dispatch() {
        let dir = tempfile::TempDir::new().unwrap();
        let toolsets_root = dir.path();
        let pkg = "my-toolset";

        let toolset_md_content = minimal_toolset_md(pkg);
        write_toolset_md(toolsets_root, pkg, &toolset_md_content);

        // Compute the expected digest of the TOOLSET.md bytes.
        let expected_digest =
            stellar_agent_toolsets_install::sha256_hex_of(toolset_md_content.as_bytes());

        let caps = stellar_agent_toolsets::parse_capability_value_pub("read-balance").unwrap();
        let pin = stellar_agent_toolsets_install::ToolsetPinRecord::build_for_test(
            pkg,
            "1.0.0",
            "a".repeat(64),
            "GABC1234567890123456789012345678901234567890123456",
            "2026-06-12T00:00:00Z",
            caps,
            vec![],
            expected_digest,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        write_pin(toolsets_root, &pin);

        // Dispatch must succeed — TOOLSET.md is unmodified.
        let result =
            resolve_toolset_and_check(pkg, "stellar_balances", toolsets_root, Some(test_pin_key()));
        assert!(
            result.is_ok(),
            "dispatch must succeed when TOOLSET.md digest matches pin: {result:?}"
        );
        let (tool_name, _) = result.unwrap();
        assert_eq!(tool_name, "stellar_balances");
    }

    // ── (B) Tampered TOOLSET.md → ContentDigestMismatch ─────────────────────────

    #[test]
    fn content_digest_mismatch_refuses_dispatch() {
        let dir = tempfile::TempDir::new().unwrap();
        let toolsets_root = dir.path();
        let pkg = "my-toolset";

        let original_content = minimal_toolset_md(pkg);
        write_toolset_md(toolsets_root, pkg, &original_content);

        // Store the digest of the original content.
        let original_digest =
            stellar_agent_toolsets_install::sha256_hex_of(original_content.as_bytes());

        let caps = stellar_agent_toolsets::parse_capability_value_pub("read-balance").unwrap();
        let pin = stellar_agent_toolsets_install::ToolsetPinRecord::build_for_test(
            pkg,
            "1.0.0",
            "a".repeat(64),
            "GABC1234567890123456789012345678901234567890123456",
            "2026-06-12T00:00:00Z",
            caps,
            vec![],
            original_digest,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        write_pin(toolsets_root, &pin);

        // Tamper with TOOLSET.md (write attacker-controlled content).
        // The pin's toolset_md_shasum still refers to the original bytes.
        let tampered_content = format!(
            "---\nname: {pkg}\ndescription: TAMPERED BY ATTACKER\nstellar-agent-capabilities:\n  - read-balance\n---\n"
        );
        std::fs::write(
            toolsets_root.join(pkg).join("TOOLSET.md"),
            &tampered_content,
        )
        .unwrap();

        // Dispatch must fail with ContentDigestMismatch.
        let err =
            resolve_toolset_and_check(pkg, "stellar_balances", toolsets_root, Some(test_pin_key()))
                .unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ContentDigestMismatch { .. }),
            "expected ContentDigestMismatch for tampered TOOLSET.md, got: {err:?}"
        );
        // Error message must name the toolset.
        let msg = err.to_string();
        assert!(
            msg.contains(pkg),
            "ContentDigestMismatch message must include toolset name; got: {msg}"
        );
    }

    // ── (C) Missing TOOLSET.md → ContentDigestMismatch ──────────────────────────

    #[test]
    fn ungated_resolver_refuses_a_missing_manifest() {
        let dir = tempfile::TempDir::new().unwrap();
        let toolsets_root = dir.path();
        let pkg = "my-toolset";

        // Create the toolset dir but NO TOOLSET.md file.
        std::fs::create_dir_all(toolsets_root.join(pkg)).unwrap();

        let caps = stellar_agent_toolsets::parse_capability_value_pub("read-balance").unwrap();
        let pin = stellar_agent_toolsets_install::ToolsetPinRecord::build_for_test(
            pkg,
            "1.0.0",
            "a".repeat(64),
            "GABC1234567890123456789012345678901234567890123456",
            "2026-06-12T00:00:00Z",
            caps,
            vec![],
            "a".repeat(64),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        write_pin(toolsets_root, &pin);

        // TOOLSET.md is missing: the read fails, so dispatch fails closed with
        // ContentDigestMismatch.
        let err =
            resolve_toolset_and_check(pkg, "stellar_balances", toolsets_root, Some(test_pin_key()))
                .unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ContentDigestMismatch { .. }),
            "missing TOOLSET.md must refuse dispatch: {err:?}"
        );
    }

    // ── Authenticated pin: ungated resolver ───────────────────────────────────

    #[test]
    fn ungated_resolver_refuses_an_edited_pin() {
        let dir = tempfile::TempDir::new().unwrap();
        let toolsets_root = dir.path();
        write_toolset_fixture(
            toolsets_root,
            "read-toolset",
            "read-balance",
            vec![],
            "2026-06-12T00:00:00Z",
        );
        let err = resolve_toolset_and_check(
            "read-toolset",
            "stellar_pay",
            toolsets_root,
            Some(test_pin_key()),
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::CapabilityNotDeclared { .. }),
            "{err:?}"
        );

        add_stored_capability(toolsets_root, "read-toolset", "propose-transaction");
        let err = resolve_toolset_and_check(
            "read-toolset",
            "stellar_pay",
            toolsets_root,
            Some(test_pin_key()),
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::PinUnverifiable { .. }),
            "an edited capability must refuse, got: {err:?}"
        );
        assert!(err.to_string().contains("toolset.pin_unverifiable"));
        assert!(err.to_string().contains("read-toolset"));
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    fn resolvers_without_a_key_report_unverifiable_and_not_installed() {
        let fixture = GatedGrantFixture::new();
        let toolsets_root = fixture.dir.path();
        write_toolset_fixture(
            toolsets_root,
            "read-toolset",
            "read-balance",
            vec![],
            "2026-06-12T00:00:00Z",
        );

        let err =
            resolve_toolset_and_check("read-toolset", "stellar_balances", toolsets_root, None)
                .unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::PinUnverifiable { .. }),
            "{err:?}"
        );
        let err =
            resolve_toolset_and_check("absent-toolset", "stellar_balances", toolsets_root, None)
                .unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled),
            "{err:?}"
        );

        let mut params = fixture.params();
        params.pin_key = None;
        let err = resolve_toolset_sign_payment_gated(&params).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::PinUnverifiable { .. }),
            "{err:?}"
        );
        params.toolset_name = "absent-toolset";
        let err = resolve_toolset_sign_payment_gated(&params).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled),
            "{err:?}"
        );
    }

    #[test]
    fn list_skips_a_pin_that_does_not_verify() {
        let dir = tempfile::TempDir::new().unwrap();
        let toolsets_root = dir.path();
        for pkg in ["alpha-toolset", "beta-toolset"] {
            write_toolset_fixture(
                toolsets_root,
                pkg,
                "read-balance",
                vec![],
                "2026-06-12T00:00:00Z",
            );
        }
        add_stored_capability(toolsets_root, "beta-toolset", "propose-transaction");

        let list = list_pinned_toolsets(toolsets_root, Some(test_pin_key())).unwrap();
        let names: Vec<&str> = list.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, vec!["alpha-toolset"]);
        assert!(
            list_pinned_toolsets(toolsets_root, None)
                .unwrap()
                .is_empty(),
            "without a key no record verifies"
        );
    }

    /// A held lock remains compatible with listing, including on Windows.
    /// This is a regression guard: the regular file and invalid package name
    /// also exclude the lock entry, so it does not isolate the name check.
    #[test]
    fn list_with_a_held_lock_is_a_compatibility_guard() {
        let dir = tempfile::TempDir::new().unwrap();
        let toolsets_root = dir.path();
        write_toolset_fixture(
            toolsets_root,
            "alpha-toolset",
            "read-balance",
            vec![],
            "2026-06-12T00:00:00Z",
        );
        let _lock = stellar_agent_toolsets_install::lock_toolsets(toolsets_root).unwrap();
        let list = list_pinned_toolsets(toolsets_root, Some(test_pin_key())).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "alpha-toolset");
    }

    // ── list_pinned_toolsets: directory with valid pin records ──────────────────

    #[test]
    fn list_pinned_toolsets_with_valid_pins() {
        let dir = tempfile::TempDir::new().unwrap();
        let toolsets_root = dir.path();

        // Write two toolsets: "alpha-toolset" and "beta-toolset", in reverse order so
        // sorting is verified.
        for pkg in ["beta-toolset", "alpha-toolset"] {
            write_toolset_md(toolsets_root, pkg, &minimal_toolset_md(pkg));
            let caps = stellar_agent_toolsets::parse_capability_value_pub("read-balance").unwrap();
            let pin = stellar_agent_toolsets_install::ToolsetPinRecord::build_for_test(
                pkg,
                "1.0.0",
                "a".repeat(64),
                "GABC1234567890123456789012345678901234567890123456",
                "2026-06-12T00:00:00Z",
                caps,
                vec![],
                "e".repeat(64),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            );
            write_pin(toolsets_root, &pin);
        }

        let list = list_pinned_toolsets(toolsets_root, Some(test_pin_key())).unwrap();
        assert_eq!(list.len(), 2, "should find both toolsets");
        // Sorted by name: alpha-toolset before beta-toolset.
        assert_eq!(list[0].name, "alpha-toolset");
        assert_eq!(list[1].name, "beta-toolset");
        // Each should have stellar_balances in actions.
        assert!(list[0].actions.contains(&"stellar_balances".to_owned()));
        assert!(list[0].version == "1.0.0");
        assert!(
            list[0].description.is_empty(),
            "description is always empty"
        );
    }

    /// A directory whose name fails the package rule gets its own warning,
    /// which names neither the entry nor the validation detail.
    #[test]
    fn list_warns_about_an_invalid_entry_without_naming_it() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("credmarker7!")).unwrap();
        let mut listed = None;
        let logs = stellar_agent_test_support::log_capture::with_captured_logs(|| {
            listed = Some(list_pinned_toolsets(tmp.path(), Some(test_pin_key())).unwrap());
        });
        assert_eq!(listed.map(|entries| entries.len()), Some(0));
        assert!(
            logs.contains("toolsets root entry must name a valid package; skipping"),
            "{logs}"
        );
        assert!(!logs.contains("credmarker7"), "{logs}");
        assert!(!logs.contains("package="), "{logs}");
    }

    #[test]
    fn list_pinned_toolsets_skips_entry_without_pin() {
        let dir = tempfile::TempDir::new().unwrap();
        let toolsets_root = dir.path();

        // Create a subdirectory but with no pin record.
        std::fs::create_dir_all(toolsets_root.join("orphan-dir")).unwrap();
        // A valid toolset with pin.
        write_toolset_md(
            toolsets_root,
            "good-toolset",
            &minimal_toolset_md("good-toolset"),
        );
        let caps = stellar_agent_toolsets::parse_capability_value_pub("read-balance").unwrap();
        let pin = stellar_agent_toolsets_install::ToolsetPinRecord::build_for_test(
            "good-toolset",
            "2.0.0",
            "b".repeat(64),
            "GABC1234567890123456789012345678901234567890123456",
            "2026-06-12T00:00:00Z",
            caps,
            vec![],
            "e".repeat(64),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        write_pin(toolsets_root, &pin);

        let list = list_pinned_toolsets(toolsets_root, Some(test_pin_key())).unwrap();
        assert_eq!(list.len(), 1, "orphan dir without pin must be skipped");
        assert_eq!(list[0].name, "good-toolset");
    }

    #[test]
    fn list_pinned_toolsets_with_allowed_tools_narrowing() {
        let dir = tempfile::TempDir::new().unwrap();
        let toolsets_root = dir.path();
        let pkg = "narrow-toolset";

        write_toolset_md(toolsets_root, pkg, &minimal_toolset_md(pkg));
        let caps =
            stellar_agent_toolsets::parse_capability_value_pub("read-balance suggest-destination")
                .unwrap();
        // allowed_tools is non-empty: only stellar_balances is permitted.
        let pin = stellar_agent_toolsets_install::ToolsetPinRecord::build_for_test(
            pkg,
            "1.0.0",
            "c".repeat(64),
            "GABC1234567890123456789012345678901234567890123456",
            "2026-06-12T00:00:00Z",
            caps,
            vec!["stellar_balances".to_owned()],
            "e".repeat(64),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        write_pin(toolsets_root, &pin);

        let list = list_pinned_toolsets(toolsets_root, Some(test_pin_key())).unwrap();
        assert_eq!(list.len(), 1);
        // Only stellar_balances should be in actions (the SuggestDestination tools
        // are not in allowed_tools so they must be filtered out).
        assert_eq!(list[0].actions, vec!["stellar_balances"]);
        assert_eq!(list[0].allowed_tools, vec!["stellar_balances"]);
    }

    // ── check_toolset_action: allowed_tools narrowing passes ────────────────────

    #[test]
    fn allowed_tools_narrowing_passes_when_tool_included() {
        // ReadBalance declared; allowed_tools is non-empty and INCLUDES stellar_balances.
        // The narrowing is satisfied and the tool should be returned.
        let caps = stellar_agent_toolsets::parse_capability_value_pub("read-balance").unwrap();
        let allowed = vec!["stellar_balances".to_owned(), "some-other".to_owned()];
        let tool = check_toolset_action("stellar_balances", &caps, &allowed).unwrap();
        assert_eq!(tool, "stellar_balances");
    }

    // ── resolve_toolset_and_check: invalid name → ToolsetNotInstalled ─────────────

    #[test]
    fn resolve_toolset_and_check_invalid_charset_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        // Name with space is outside [a-z0-9-]
        let err = resolve_toolset_and_check(
            "bad name",
            "stellar_balances",
            dir.path(),
            Some(test_pin_key()),
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled),
            "expected ToolsetNotInstalled, got: {err:?}"
        );
    }

    // ── resolve_toolset_and_check: valid name, pin absent → ToolsetNotInstalled ───
    //
    // Verifies the ToolsetNotInstalled path when the name passes charset
    // validation but no pin record exists in the toolsets_root directory.

    #[test]
    fn resolve_toolset_and_check_valid_name_toolset_not_installed() {
        let dir = tempfile::TempDir::new().unwrap();
        // "stellar-balances" is a valid [a-z0-9-] name but has no pin record.
        let err = resolve_toolset_and_check(
            "valid-name",
            "stellar_balances",
            dir.path(),
            Some(test_pin_key()),
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled),
            "expected ToolsetNotInstalled for a valid name with no pin record, got: {err:?}"
        );
    }

    // ── Gated resolver tests (require test-helpers feature for overrides) ─────

    /// Builds and writes a pin with `sign-payment` capability.
    #[cfg(feature = "test-helpers")]
    fn write_sign_payment_pin(toolsets_root: &std::path::Path, pkg: &str) {
        write_toolset_fixture(
            toolsets_root,
            pkg,
            "sign-payment",
            vec![],
            "1970-01-01T00:00:00Z",
        );
    }

    #[cfg(feature = "test-helpers")]
    struct GatedGrantFixture {
        dir: tempfile::TempDir,
        binding: stellar_agent_core::approval::AttestationBinding<'static>,
    }

    #[cfg(feature = "test-helpers")]
    impl GatedGrantFixture {
        const NOW_MS: u64 = 1_777_552_496_000;
        const KEY: [u8; 32] = [0x42; 32];
        const DESTINATION: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

        fn new() -> Self {
            let fixture = Self {
                dir: tempfile::TempDir::new().unwrap(),
                binding: stellar_agent_core::approval::AttestationBinding::new(
                    "test",
                    "stellar:testnet",
                ),
            };
            write_sign_payment_pin(fixture.dir.path(), "pay-toolset");
            fixture
        }

        fn params(&self) -> GatedInvokeParams<'_> {
            GatedInvokeParams {
                toolset_name: "pay-toolset",
                action: "stellar_pay_commit",
                toolsets_root: self.dir.path(),
                profile_name: "test",
                attestation_key: &Self::KEY,
                attestation_binding: &self.binding,
                authoritative_destination: Self::DESTINATION,
                authoritative_asset: "XLM",
                authoritative_amount_stroops: 10,
                now_unix_ms: Self::NOW_MS,
                process_uid: "1000",
                pin_key: Some(test_pin_key()),
                approval_dir_override: Some(self.dir.path().join("approvals")),
                grant_store_path_override: Some(self.dir.path().join("grants.toml")),
            }
        }

        fn record_grant(&self) -> ToolsetGrant {
            self.record_grant_result().unwrap()
        }

        fn record_grant_result(&self) -> Result<ToolsetGrant, ToolsetRuntimeError> {
            let profile = stellar_agent_core::profile::schema::Profile::builder_testnet(
                "svc", "test", "nonce", "test",
            )
            .build();
            let context =
                stellar_agent_core::approval::ApprovalContext::from_profile("test", &profile);
            record_first_invoke_grant(
                "test",
                "pay-toolset",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "1.0.0",
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "sign-payment",
                Self::DESTINATION,
                "XLM",
                0,
                10,
                "1000",
                Self::NOW_MS,
                &Self::KEY,
                &context.binding(),
                self.params().grant_store_path_override,
            )
        }

        /// Resolves the fixture invocation, which must find a grant.
        fn resolve(&self) -> VerifiedToolsetGrant {
            match resolve_toolset_sign_payment_gated(&self.params()).unwrap() {
                GatedResolveOutcome::Resolved {
                    tool_name: "stellar_pay_commit",
                    grant,
                } => *grant,
                other => panic!("expected Resolved: {other:?}"),
            }
        }

        fn recheck_params(&self) -> GrantRecheckParams<'_> {
            let params = self.params();
            GrantRecheckParams {
                toolset_name: params.toolset_name,
                action: params.action,
                toolsets_root: params.toolsets_root,
                profile_name: params.profile_name,
                attestation_key: params.attestation_key,
                attestation_binding: params.attestation_binding,
                authoritative_destination: params.authoritative_destination,
                authoritative_asset: params.authoritative_asset,
                authoritative_amount_stroops: params.authoritative_amount_stroops,
                pin_key: params.pin_key,
                grant_store_path_override: params.grant_store_path_override,
            }
        }

        /// Acquires a lease with the clock fixed at [`Self::NOW_MS`].
        fn lease(
            &self,
            token: &VerifiedToolsetGrant,
        ) -> Result<ToolsetGrantLease, ToolsetRuntimeError> {
            acquire_lease_with_clock(token, &self.recheck_params(), &mut || Ok(Self::NOW_MS))
        }

        fn recheck(&self, token: &VerifiedToolsetGrant) -> Result<(), ToolsetRuntimeError> {
            recheck_at_fixture_time(token, &self.recheck_params())
        }

        fn grants_path(&self) -> PathBuf {
            self.dir.path().join("grants.toml")
        }

        fn approval_count(&self) -> usize {
            let path = self.dir.path().join("approvals").join("test.toml");
            if !path.exists() {
                return 0;
            }
            stellar_agent_core::approval::PendingApprovalStore::open(path)
                .unwrap()
                .snapshot(0)
                .len()
        }

        fn set_install_time(&self, installed_at: &str) {
            let mut pin = stellar_agent_toolsets_install::read_pin(
                "pay-toolset",
                self.dir.path(),
                Some(test_pin_key()),
            )
            .unwrap()
            .unwrap();
            pin.installed_at = installed_at.to_owned();
            write_pin(self.dir.path(), &pin);
        }

        fn assert_first_invoke(&self) {
            let outcome = resolve_toolset_sign_payment_gated(&self.params()).unwrap();
            assert!(
                matches!(
                    outcome,
                    GatedResolveOutcome::FirstInvokeApprovalRequired { .. }
                ),
                "{outcome:?}"
            );
        }
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    #[serial_test::serial]
    fn gated_resolver_refuses_an_edited_manifest() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let fixture = GatedGrantFixture::new();
        fixture.record_grant();
        std::fs::write(
            fixture.dir.path().join("pay-toolset").join("TOOLSET.md"),
            "---\nname: pay-toolset\ndescription: edited\n---\n",
        )
        .unwrap();
        let err = resolve_toolset_sign_payment_gated(&fixture.params()).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ContentDigestMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    #[serial_test::serial]
    fn gated_resolver_refuses_an_edited_pin() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let fixture = GatedGrantFixture::new();
        fixture.record_grant();
        add_stored_capability(fixture.dir.path(), "pay-toolset", "read-balance");
        let err = resolve_toolset_sign_payment_gated(&fixture.params()).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::PinUnverifiable { .. }),
            "{err:?}"
        );
    }

    /// A grant issued before the recorded install time is honored only when the
    /// record says so; moving the stored install time earlier without the key
    /// must not reopen it.
    #[test]
    #[cfg(feature = "test-helpers")]
    #[serial_test::serial]
    fn gated_resolver_refuses_an_edited_install_time() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let fixture = GatedGrantFixture::new();
        fixture.record_grant();
        fixture.set_install_time("2026-04-30T13:34:56Z");
        fixture.assert_first_invoke();
        edit_stored_pin(fixture.dir.path(), "pay-toolset", |value| {
            value["installed_at"] = serde_json::json!("1970-01-01T00:00:00Z");
        });
        let err = resolve_toolset_sign_payment_gated(&fixture.params()).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::PinUnverifiable { .. }),
            "{err:?}"
        );
    }

    /// The hand-written grant is issued now and expires after the default TTL,
    /// the farthest expiry the lifetime and issue-time checks admit, so only its
    /// missing attestation refuses it.
    #[test]
    #[cfg(feature = "test-helpers")]
    fn gated_resolver_ignores_a_forged_grant() {
        let fixture = GatedGrantFixture::new();
        let granted_at = GatedGrantFixture::NOW_MS;
        let text = format!(
            r#"[[grants]]
grant_id = "forged"
toolset_name = "pay-toolset"
capability = "sign-payment"
destination = "{}"
asset = "XLM"
amount_min_stroops = 0
amount_max_stroops = 9223372036854775807
granted_at_unix_ms = {granted_at}
expires_at_unix_ms = {}
process_uid_at_grant = "1000"
attestation_version = 3
"#,
            GatedGrantFixture::DESTINATION,
            granted_at + TOOLSET_GRANT_DEFAULT_TTL_MS
        );
        std::fs::write(fixture.dir.path().join("grants.toml"), text).unwrap();
        fixture.assert_first_invoke();
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    #[serial_test::serial]
    fn gated_resolver_ignores_a_grant_from_an_earlier_install() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let fixture = GatedGrantFixture::new();
        fixture.record_grant();
        fixture.set_install_time("2026-04-30T13:34:56Z");
        fixture.assert_first_invoke();
        fixture.set_install_time("2026-04-30T11:34:56Z");
        assert!(matches!(
            resolve_toolset_sign_payment_gated(&fixture.params()).unwrap(),
            GatedResolveOutcome::Resolved { .. }
        ));
        fixture.set_install_time("2026-04-30T12:34:56Z");
        fixture.assert_first_invoke();
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    #[serial_test::serial]
    fn gated_resolver_ignores_a_pin_without_a_parsable_install_time() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let fixture = GatedGrantFixture::new();
        fixture.record_grant();
        fixture.set_install_time("yesterday");
        fixture.assert_first_invoke();
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    #[serial_test::serial]
    fn a_grant_recorded_by_the_approval_path_resolves() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let fixture = GatedGrantFixture::new();
        let recorded = fixture.record_grant();
        let grant = fixture.resolve();
        assert_eq!(grant.grant_id(), recorded.grant_id);
        assert_eq!(grant.expires_at_unix_ms(), recorded.expires_at_unix_ms);
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    fn gated_resolver_grant_store_error_names_the_position_only() {
        let fixture = GatedGrantFixture::new();
        let blob = "Q".repeat(43);
        std::fs::write(
            fixture.dir.path().join("grants.toml"),
            format!("[[grants]]\ngrant_id = \"test\"\nattestation_blob_b64 = \"{blob}"),
        )
        .unwrap();
        let err = resolve_toolset_sign_payment_gated(&fixture.params()).unwrap_err();
        let ToolsetRuntimeError::GrantStoreError { detail } = err else {
            panic!("expected GrantStoreError: {err:?}");
        };
        assert!(detail.contains("line 3"), "{detail}");
        assert!(!detail.contains(&blob), "{detail}");
        assert!(!detail.contains("attestation_blob_b64"), "{detail}");
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    fn gated_invoke_params_debug_redacts_the_attestation_key() {
        let fixture = GatedGrantFixture::new();
        let rendered = format!("{:?}", fixture.params());
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(&format!("{:?}", GatedGrantFixture::KEY)));
        assert!(!rendered.contains(&format!("{:?}", [0x5a_u8; 32])));
        assert!(rendered.contains("pin_key"));
    }

    // ── Gated resolver: invalid toolset name → ToolsetNotInstalled ───────────────

    #[test]
    #[cfg(feature = "test-helpers")]
    fn gated_resolver_invalid_toolset_name_rejected() {
        let toolsets_dir = tempfile::TempDir::new().unwrap();
        let approval_dir = tempfile::TempDir::new().unwrap();
        let grant_dir = tempfile::TempDir::new().unwrap();

        let params = GatedInvokeParams {
            toolset_name: "Bad Name!",
            action: "stellar_pay_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            attestation_key: &[0u8; 32],
            attestation_binding: &stellar_agent_core::approval::AttestationBinding::new(
                "test",
                "stellar:testnet",
            ),
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: 10_000_000,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
            pin_key: Some(test_pin_key()),
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_dir.path().join("grants.json")),
        };

        let err = resolve_toolset_sign_payment_gated(&params).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled),
            "expected ToolsetNotInstalled, got: {err:?}"
        );
    }

    // ── Gated resolver: toolset not installed → ToolsetNotInstalled ──────────────

    #[test]
    #[cfg(feature = "test-helpers")]
    fn gated_resolver_toolset_not_installed() {
        let toolsets_dir = tempfile::TempDir::new().unwrap();
        let approval_dir = tempfile::TempDir::new().unwrap();
        let grant_dir = tempfile::TempDir::new().unwrap();

        let params = GatedInvokeParams {
            toolset_name: "not-installed",
            action: "stellar_pay_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            attestation_key: &[0u8; 32],
            attestation_binding: &stellar_agent_core::approval::AttestationBinding::new(
                "test",
                "stellar:testnet",
            ),
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: 10_000_000,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
            pin_key: Some(test_pin_key()),
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_dir.path().join("grants.json")),
        };

        let err = resolve_toolset_sign_payment_gated(&params).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled),
            "expected ToolsetNotInstalled, got: {err:?}"
        );
    }

    // ── Gated resolver: action not in gated matrix → UnknownToolsetAction ──────

    #[test]
    #[cfg(feature = "test-helpers")]
    fn gated_resolver_ungated_action_rejected() {
        let toolsets_dir = tempfile::TempDir::new().unwrap();
        let approval_dir = tempfile::TempDir::new().unwrap();
        let grant_dir = tempfile::TempDir::new().unwrap();

        write_sign_payment_pin(toolsets_dir.path(), "pay-toolset");

        let params = GatedInvokeParams {
            toolset_name: "pay-toolset",
            // stellar_pay is an ungated action — must not resolve via the gated matrix.
            action: "stellar_pay",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            attestation_key: &[0u8; 32],
            attestation_binding: &stellar_agent_core::approval::AttestationBinding::new(
                "test",
                "stellar:testnet",
            ),
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: 10_000_000,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
            pin_key: Some(test_pin_key()),
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_dir.path().join("grants.json")),
        };

        let err = resolve_toolset_sign_payment_gated(&params).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::UnknownToolsetAction),
            "ungated action must not resolve via gated matrix, got: {err:?}"
        );
    }

    // ── Gated resolver: sign-payment not declared → CapabilityNotDeclared ────

    #[test]
    #[cfg(feature = "test-helpers")]
    fn gated_resolver_sign_payment_not_declared() {
        let toolsets_dir = tempfile::TempDir::new().unwrap();
        let approval_dir = tempfile::TempDir::new().unwrap();
        let grant_dir = tempfile::TempDir::new().unwrap();

        // Pin with read-balance only — no sign-payment.
        write_toolset_fixture(
            toolsets_dir.path(),
            "read-toolset",
            "read-balance",
            vec![],
            "2026-06-12T00:00:00Z",
        );

        let params = GatedInvokeParams {
            toolset_name: "read-toolset",
            action: "stellar_pay_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            attestation_key: &[0u8; 32],
            attestation_binding: &stellar_agent_core::approval::AttestationBinding::new(
                "test",
                "stellar:testnet",
            ),
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: 10_000_000,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
            pin_key: Some(test_pin_key()),
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_dir.path().join("grants.json")),
        };

        let err = resolve_toolset_sign_payment_gated(&params).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::CapabilityNotDeclared { .. }),
            "expected CapabilityNotDeclared, got: {err:?}"
        );
    }

    // ── Gated resolver: allowed_tools excludes stellar_pay_commit → ToolNotAllowed

    #[test]
    #[cfg(feature = "test-helpers")]
    fn gated_resolver_tool_not_in_allowed_tools() {
        let toolsets_dir = tempfile::TempDir::new().unwrap();
        let approval_dir = tempfile::TempDir::new().unwrap();
        let grant_dir = tempfile::TempDir::new().unwrap();

        // sign-payment declared but allowed_tools excludes stellar_pay_commit.
        write_toolset_fixture(
            toolsets_dir.path(),
            "narrow-pay-toolset",
            "sign-payment",
            vec!["some-other-tool".to_owned()],
            "2026-06-12T00:00:00Z",
        );

        let params = GatedInvokeParams {
            toolset_name: "narrow-pay-toolset",
            action: "stellar_pay_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            attestation_key: &[0u8; 32],
            attestation_binding: &stellar_agent_core::approval::AttestationBinding::new(
                "test",
                "stellar:testnet",
            ),
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: 10_000_000,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
            pin_key: Some(test_pin_key()),
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_dir.path().join("grants.json")),
        };

        let err = resolve_toolset_sign_payment_gated(&params).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolNotAllowed { .. }),
            "expected ToolNotAllowed, got: {err:?}"
        );
    }

    // ── Gated resolver: no grant → FirstInvokeApprovalRequired ───────────────

    #[test]
    #[cfg(feature = "test-helpers")]
    fn gated_resolver_no_grant_queues_first_invoke_gate() {
        let toolsets_dir = tempfile::TempDir::new().unwrap();
        let approval_dir = tempfile::TempDir::new().unwrap();
        let grant_dir = tempfile::TempDir::new().unwrap();

        write_sign_payment_pin(toolsets_dir.path(), "pay-toolset");

        let params = GatedInvokeParams {
            toolset_name: "pay-toolset",
            action: "stellar_pay_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            attestation_key: &[0u8; 32],
            attestation_binding: &stellar_agent_core::approval::AttestationBinding::new(
                "test",
                "stellar:testnet",
            ),
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: 10_000_000,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
            pin_key: Some(test_pin_key()),
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_dir.path().join("grants.json")),
        };

        let outcome = resolve_toolset_sign_payment_gated(&params).unwrap();
        match outcome {
            GatedResolveOutcome::FirstInvokeApprovalRequired {
                approval_nonce,
                toolset_name,
                capability,
            } => {
                assert!(
                    !approval_nonce.is_empty(),
                    "approval_nonce must be non-empty"
                );
                assert_eq!(toolset_name, "pay-toolset");
                assert_eq!(capability, "sign-payment");
            }
            GatedResolveOutcome::Resolved { .. } => {
                panic!("expected FirstInvokeApprovalRequired, got Resolved");
            }
        }
    }

    // ── Gated resolver: with grant → Resolved ────────────────────────────────

    #[test]
    #[cfg(feature = "test-helpers")]
    fn gated_resolver_with_matching_grant_returns_resolved() {
        use stellar_agent_core::approval::process_uid_for_attestation;

        let toolsets_dir = tempfile::TempDir::new().unwrap();
        let approval_dir = tempfile::TempDir::new().unwrap();
        let grant_dir = tempfile::TempDir::new().unwrap();
        let grant_path = grant_dir.path().join("grants.json");

        write_sign_payment_pin(toolsets_dir.path(), "pay-toolset");

        let now_unix_ms: u64 = 1_000_000;
        let destination = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
        let asset = "XLM";
        let amount_stroops: i64 = 10_000_000;
        let attestation_key = [0u8; 32];
        let uid = process_uid_for_attestation().unwrap();

        // Write a matching grant to the grant store before calling the resolver.
        let recorded = record_first_invoke_grant(
            "test",
            "pay-toolset",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1.0.0",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "sign-payment",
            destination,
            asset,
            0,
            amount_stroops,
            &uid,
            now_unix_ms,
            &attestation_key,
            &stellar_agent_core::approval::AttestationBinding::new("test", "stellar:testnet"),
            Some(grant_path.clone()),
        )
        .unwrap();

        let params = GatedInvokeParams {
            toolset_name: "pay-toolset",
            action: "stellar_pay_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            attestation_key: &attestation_key,
            attestation_binding: &stellar_agent_core::approval::AttestationBinding::new(
                "test",
                "stellar:testnet",
            ),
            authoritative_destination: destination,
            authoritative_asset: asset,
            authoritative_amount_stroops: amount_stroops,
            now_unix_ms,
            process_uid: &uid,
            pin_key: Some(test_pin_key()),
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_path),
        };

        let outcome = resolve_toolset_sign_payment_gated(&params).unwrap();
        match outcome {
            GatedResolveOutcome::Resolved { tool_name, grant } => {
                assert_eq!(tool_name, "stellar_pay_commit");
                assert_eq!(grant.grant_id(), recorded.grant_id);
                assert_eq!(
                    grant.expires_at_unix_ms(),
                    now_unix_ms + TOOLSET_GRANT_DEFAULT_TTL_MS
                );
                assert_eq!(grant.pin().install_id, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            }
            GatedResolveOutcome::FirstInvokeApprovalRequired { .. } => {
                panic!("expected Resolved, got FirstInvokeApprovalRequired");
            }
        }
    }

    // ── SignRuleCreate gated resolver (Package D, GH issue #8) ────────────────
    //
    // `resolve_toolset_sign_payment_gated` is reused as-is for `sign-rule-create`
    // (it is generic over the GATED matrix / Capability, despite its name): the
    // "destination/asset/amount" triple is repurposed as the bucket-matching
    // dimension for rule-create grants — `authoritative_destination` carries the
    // smart-account C-strkey (the correct re-prompt dimension: a DIFFERENT
    // smart account should re-trigger first-invoke consent, exactly like a
    // different payment destination does), `authoritative_asset` is a fixed
    // sentinel (`"context-rule"`, not a real asset), and
    // `authoritative_amount_stroops` is a fixed positive dummy (`1`) since the
    // amount dimension carries no independent meaning here. The per-proposal
    // `RuleProposalSimulated` attestation (verified inside
    // `stellar_rule_create_commit`) remains the REAL, unconditional per-action
    // security boundary — this first-invoke gate is only the one-time
    // "this toolset may attempt rule-create for this smart account" consent.

    use crate::matrix::{SIGN_RULE_CREATE_AMOUNT_SENTINEL, SIGN_RULE_CREATE_ASSET_SENTINEL};

    fn write_sign_rule_create_pin(toolsets_root: &std::path::Path, pkg: &str) {
        write_toolset_fixture(
            toolsets_root,
            pkg,
            "sign-rule-create",
            vec![],
            "1970-01-01T00:00:00Z",
        );
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    fn gated_resolver_sign_rule_create_no_grant_queues_first_invoke_gate() {
        let toolsets_dir = tempfile::TempDir::new().unwrap();
        let approval_dir = tempfile::TempDir::new().unwrap();
        let grant_dir = tempfile::TempDir::new().unwrap();

        write_sign_rule_create_pin(toolsets_dir.path(), "rule-toolset");

        let params = GatedInvokeParams {
            toolset_name: "rule-toolset",
            action: "stellar_rule_create_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            attestation_key: &[0u8; 32],
            attestation_binding: &stellar_agent_core::approval::AttestationBinding::new(
                "test",
                "stellar:testnet",
            ),
            authoritative_destination: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            authoritative_asset: SIGN_RULE_CREATE_ASSET_SENTINEL,
            authoritative_amount_stroops: SIGN_RULE_CREATE_AMOUNT_SENTINEL,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
            pin_key: Some(test_pin_key()),
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_dir.path().join("grants.json")),
        };

        let outcome = resolve_toolset_sign_payment_gated(&params).unwrap();
        match outcome {
            GatedResolveOutcome::FirstInvokeApprovalRequired {
                approval_nonce,
                toolset_name,
                capability,
            } => {
                assert!(
                    !approval_nonce.is_empty(),
                    "approval_nonce must be non-empty"
                );
                assert_eq!(toolset_name, "rule-toolset");
                assert_eq!(capability, "sign-rule-create");
            }
            GatedResolveOutcome::Resolved { .. } => {
                panic!("expected FirstInvokeApprovalRequired, got Resolved");
            }
        }
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    fn gated_resolver_sign_rule_create_with_matching_grant_returns_resolved() {
        use stellar_agent_core::approval::process_uid_for_attestation;

        let toolsets_dir = tempfile::TempDir::new().unwrap();
        let approval_dir = tempfile::TempDir::new().unwrap();
        let grant_dir = tempfile::TempDir::new().unwrap();
        let grant_path = grant_dir.path().join("grants.json");

        write_sign_rule_create_pin(toolsets_dir.path(), "rule-toolset");

        let now_unix_ms: u64 = 1_000_000;
        let smart_account = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let attestation_key = [0u8; 32];
        let uid = process_uid_for_attestation().unwrap();

        let recorded = record_first_invoke_grant(
            "test",
            "rule-toolset",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1.0.0",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "sign-rule-create",
            smart_account,
            SIGN_RULE_CREATE_ASSET_SENTINEL,
            0,
            SIGN_RULE_CREATE_AMOUNT_SENTINEL,
            &uid,
            now_unix_ms,
            &attestation_key,
            &stellar_agent_core::approval::AttestationBinding::new("test", "stellar:testnet"),
            Some(grant_path.clone()),
        )
        .unwrap();

        let params = GatedInvokeParams {
            toolset_name: "rule-toolset",
            action: "stellar_rule_create_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            attestation_key: &attestation_key,
            attestation_binding: &stellar_agent_core::approval::AttestationBinding::new(
                "test",
                "stellar:testnet",
            ),
            authoritative_destination: smart_account,
            authoritative_asset: SIGN_RULE_CREATE_ASSET_SENTINEL,
            authoritative_amount_stroops: SIGN_RULE_CREATE_AMOUNT_SENTINEL,
            now_unix_ms,
            process_uid: &uid,
            pin_key: Some(test_pin_key()),
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_path),
        };

        let outcome = resolve_toolset_sign_payment_gated(&params).unwrap();
        match outcome {
            GatedResolveOutcome::Resolved { tool_name, grant } => {
                assert_eq!(tool_name, "stellar_rule_create_commit");
                assert_eq!(grant.grant_id(), recorded.grant_id);
                assert_eq!(grant.expires_at_unix_ms(), recorded.expires_at_unix_ms);
                assert_eq!(grant.grant.destination(), smart_account);
                assert_eq!(grant.grant.asset, SIGN_RULE_CREATE_ASSET_SENTINEL);
            }
            GatedResolveOutcome::FirstInvokeApprovalRequired { .. } => {
                panic!("expected Resolved, got FirstInvokeApprovalRequired");
            }
        }
    }

    /// Negative: a toolset granting ONLY `propose-transaction` (ungated) can
    /// invoke `stellar_rule_create` (the propose step) but NOT
    /// `stellar_rule_create_commit` (gated; requires `sign-rule-create`) via
    /// the ungated path.
    #[test]
    fn propose_transaction_grants_stellar_rule_create_but_not_commit() {
        let caps =
            stellar_agent_toolsets::parse_capability_value_pub("propose-transaction").unwrap();
        let tool = check_toolset_action("stellar_rule_create", &caps, &[]).unwrap();
        assert_eq!(tool, "stellar_rule_create");

        let err = check_toolset_action("stellar_rule_create_commit", &caps, &[]).unwrap_err();
        assert!(matches!(err, ToolsetRuntimeError::UnknownToolsetAction));
    }

    // ── Gated resolver: zero amount rejected EVEN WITH a matching grant ───────
    // Regression guard: the positivity check must run BEFORE the grant lookup,
    // so a grant covering the [0, N] bucket cannot resolve a zero-stroop invoke
    // to the signing tool.

    #[test]
    #[cfg(feature = "test-helpers")]
    fn gated_resolver_grant_present_zero_amount_rejected() {
        use stellar_agent_core::approval::process_uid_for_attestation;

        let toolsets_dir = tempfile::TempDir::new().unwrap();
        let approval_dir = tempfile::TempDir::new().unwrap();
        let grant_dir = tempfile::TempDir::new().unwrap();
        let grant_path = grant_dir.path().join("grants.json");

        write_sign_payment_pin(toolsets_dir.path(), "pay-toolset");

        let now_unix_ms: u64 = 1_000_000;
        let destination = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
        let asset = "XLM";
        let attestation_key = [0u8; 32];
        let uid = process_uid_for_attestation().unwrap();

        // A grant covering [0, 10_000_000] would match a zero-stroop invoke if
        // the positivity check ran after the grant lookup.
        record_first_invoke_grant(
            "test",
            "pay-toolset",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1.0.0",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "sign-payment",
            destination,
            asset,
            0,
            10_000_000,
            &uid,
            now_unix_ms,
            &attestation_key,
            &stellar_agent_core::approval::AttestationBinding::new("test", "stellar:testnet"),
            Some(grant_path.clone()),
        )
        .unwrap();

        let params = GatedInvokeParams {
            toolset_name: "pay-toolset",
            action: "stellar_pay_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            attestation_key: &attestation_key,
            attestation_binding: &stellar_agent_core::approval::AttestationBinding::new(
                "test",
                "stellar:testnet",
            ),
            authoritative_destination: destination,
            authoritative_asset: asset,
            authoritative_amount_stroops: 0,
            now_unix_ms,
            process_uid: &uid,
            pin_key: Some(test_pin_key()),
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_path),
        };

        let err = resolve_toolset_sign_payment_gated(&params).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::InvalidAuthoritativeAmount),
            "a zero amount must be rejected even when a [0, N] grant exists; got: {err:?}"
        );
    }

    // ── Gated resolver: non-positive amount → InvalidAuthoritativeAmount ─────

    #[test]
    #[cfg(feature = "test-helpers")]
    fn gated_resolver_zero_amount_rejected() {
        let toolsets_dir = tempfile::TempDir::new().unwrap();
        let approval_dir = tempfile::TempDir::new().unwrap();
        let grant_dir = tempfile::TempDir::new().unwrap();

        write_sign_payment_pin(toolsets_dir.path(), "pay-toolset");

        let params = GatedInvokeParams {
            toolset_name: "pay-toolset",
            action: "stellar_pay_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            attestation_key: &[0u8; 32],
            attestation_binding: &stellar_agent_core::approval::AttestationBinding::new(
                "test",
                "stellar:testnet",
            ),
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: 0,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
            pin_key: Some(test_pin_key()),
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_dir.path().join("grants.json")),
        };

        let err = resolve_toolset_sign_payment_gated(&params).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::InvalidAuthoritativeAmount),
            "expected InvalidAuthoritativeAmount(0), got: {err:?}"
        );
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    fn gated_resolver_negative_amount_rejected() {
        let toolsets_dir = tempfile::TempDir::new().unwrap();
        let approval_dir = tempfile::TempDir::new().unwrap();
        let grant_dir = tempfile::TempDir::new().unwrap();

        write_sign_payment_pin(toolsets_dir.path(), "pay-toolset");

        let params = GatedInvokeParams {
            toolset_name: "pay-toolset",
            action: "stellar_pay_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            attestation_key: &[0u8; 32],
            attestation_binding: &stellar_agent_core::approval::AttestationBinding::new(
                "test",
                "stellar:testnet",
            ),
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: -1,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
            pin_key: Some(test_pin_key()),
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_dir.path().join("grants.json")),
        };

        let err = resolve_toolset_sign_payment_gated(&params).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::InvalidAuthoritativeAmount),
            "expected InvalidAuthoritativeAmount(-1), got: {err:?}"
        );
        assert_eq!(
            err.to_string(),
            "toolset.invalid_authoritative_amount: authoritative_amount_stroops must be > 0"
        );
        stellar_agent_test_support::rejected_value::assert_no_marker(&err, "-1");
    }

    // ── Gated resolver: queued pending carries caller-supplied process_uid ────
    //
    // The queued ToolsetFirstInvokeGate pending carries the caller-supplied
    // process_uid. This test reads the pending-approval store after queuing and
    // asserts the stored process_uid equals the supplied value. The invariant is
    // that the resolver HONORS the caller-supplied value and does not recompute
    // it internally — the caller controls the identity for attestation purposes.

    #[test]
    #[cfg(feature = "test-helpers")]
    fn gated_resolver_queued_pending_uses_caller_supplied_process_uid() {
        let toolsets_dir = tempfile::TempDir::new().unwrap();
        let approval_dir = tempfile::TempDir::new().unwrap();
        let grant_dir = tempfile::TempDir::new().unwrap();

        write_sign_payment_pin(toolsets_dir.path(), "pay-toolset");

        // Synthetic uid that the caller supplies; the resolver must store it
        // verbatim without recomputing via process_uid_for_attestation().
        let supplied_uid = "1234567890";

        let params = GatedInvokeParams {
            toolset_name: "pay-toolset",
            action: "stellar_pay_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            attestation_key: &[0u8; 32],
            attestation_binding: &stellar_agent_core::approval::AttestationBinding::new(
                "test",
                "stellar:testnet",
            ),
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: 10_000_000,
            now_unix_ms: 1_000_000,
            process_uid: supplied_uid,
            pin_key: Some(test_pin_key()),
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_dir.path().join("grants.json")),
        };

        let outcome = resolve_toolset_sign_payment_gated(&params).unwrap();
        let approval_nonce = match outcome {
            GatedResolveOutcome::FirstInvokeApprovalRequired { approval_nonce, .. } => {
                approval_nonce
            }
            GatedResolveOutcome::Resolved { .. } => {
                panic!("expected FirstInvokeApprovalRequired, got Resolved");
            }
        };

        // Read the persisted pending from the approval store and verify its
        // process_uid equals the supplied value. process_uid is a top-level
        // field on PendingApproval (not inside ApprovalKind).
        let store_path = approval_dir.path().join("test.toml");
        let store = stellar_agent_core::approval::PendingApprovalStore::open(store_path).unwrap();
        let pending = store
            .get(&approval_nonce)
            .expect("queued pending must be findable by nonce");

        assert_eq!(
            pending.process_uid, supplied_uid,
            "queued pending's process_uid must equal the caller-supplied value '{}'; \
             got '{}' — would differ if the resolver recomputed it internally",
            supplied_uid, pending.process_uid
        );
    }

    // ── Gated resolver: over-max amount re-prompts ───────────────────────────
    //
    // A grant with a bounded amount_max is stored. An invoke with
    // authoritative_amount_stroops ABOVE that max must NOT return Resolved —
    // the grant does not match, so the resolver re-prompts (queues a new
    // ToolsetFirstInvokeGate pending and returns FirstInvokeApprovalRequired).

    #[test]
    #[cfg(feature = "test-helpers")]
    fn gated_resolver_over_max_amount_re_prompts() {
        use stellar_agent_core::approval::process_uid_for_attestation;

        let toolsets_dir = tempfile::TempDir::new().unwrap();
        let approval_dir = tempfile::TempDir::new().unwrap();
        let grant_dir = tempfile::TempDir::new().unwrap();
        let grant_path = grant_dir.path().join("grants.json");

        write_sign_payment_pin(toolsets_dir.path(), "pay-toolset");

        let now_unix_ms: u64 = 1_000_000;
        let destination = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
        let asset = "XLM";
        let grant_max_stroops: i64 = 10_000_000; // 1 XLM
        let attestation_key = [0u8; 32];
        let uid = process_uid_for_attestation().unwrap();

        // Store a grant covering [0, 10_000_000].
        record_first_invoke_grant(
            "test",
            "pay-toolset",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1.0.0",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "sign-payment",
            destination,
            asset,
            0,
            grant_max_stroops,
            &uid,
            now_unix_ms,
            &attestation_key,
            &stellar_agent_core::approval::AttestationBinding::new("test", "stellar:testnet"),
            Some(grant_path.clone()),
        )
        .unwrap();

        // Invoke with an amount ABOVE the grant's max — should NOT match.
        let over_max_stroops: i64 = grant_max_stroops + 1;

        let params = GatedInvokeParams {
            toolset_name: "pay-toolset",
            action: "stellar_pay_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            attestation_key: &attestation_key,
            attestation_binding: &stellar_agent_core::approval::AttestationBinding::new(
                "test",
                "stellar:testnet",
            ),
            authoritative_destination: destination,
            authoritative_asset: asset,
            authoritative_amount_stroops: over_max_stroops,
            now_unix_ms,
            process_uid: &uid,
            pin_key: Some(test_pin_key()),
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_path),
        };

        let outcome = resolve_toolset_sign_payment_gated(&params).unwrap();

        // Must NOT return Resolved — the grant's amount_max is exceeded.
        assert!(
            matches!(
                outcome,
                GatedResolveOutcome::FirstInvokeApprovalRequired { .. }
            ),
            "amount above grant max must re-prompt (FirstInvokeApprovalRequired), \
             got Resolved — the existing grant must not match an over-max amount"
        );

        // Verify the outcome carries a non-empty nonce (a new pending was queued).
        match outcome {
            GatedResolveOutcome::FirstInvokeApprovalRequired { approval_nonce, .. } => {
                assert!(
                    !approval_nonce.is_empty(),
                    "re-prompt must carry a non-empty approval_nonce"
                );
            }
            GatedResolveOutcome::Resolved { .. } => unreachable!(),
        }
    }

    // ── record_first_invoke_grant: happy path ─────────────────────────────────

    #[test]
    #[cfg(feature = "test-helpers")]
    fn record_first_invoke_grant_persists_to_store() {
        use stellar_agent_core::approval::process_uid_for_attestation;

        let grant_dir = tempfile::TempDir::new().unwrap();
        let grant_path = grant_dir.path().join("grants.json");

        let now_unix_ms: u64 = 2_000_000;
        let uid = process_uid_for_attestation().unwrap();
        let attestation_key = [1u8; 32];

        let grant = record_first_invoke_grant(
            "test",
            "my-toolset",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1.0.0",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "sign-payment",
            "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            "XLM",
            0,
            50_000_000,
            &uid,
            now_unix_ms,
            &attestation_key,
            &stellar_agent_core::approval::AttestationBinding::new("test", "stellar:testnet"),
            Some(grant_path.clone()),
        )
        .unwrap();

        assert_eq!(grant.toolset_name, "my-toolset");
        assert_eq!(grant.capability(), "sign-payment");

        // The stored HMAC verifies under the issuing key and fails under another key.
        assert!(
            grant.verify_attestation(
                &attestation_key,
                &stellar_agent_core::approval::AttestationBinding::new("test", "stellar:testnet")
            ),
            "grant must verify against the attestation key it was built with"
        );
        assert!(
            !grant.verify_attestation(
                &[0xff; 32],
                &stellar_agent_core::approval::AttestationBinding::new("test", "stellar:testnet")
            ),
            "grant must NOT verify against a wrong attestation key"
        );

        // Re-open the store and verify the grant is persisted.
        let store =
            stellar_agent_core::approval::ToolsetGrantStore::open(grant_path, now_unix_ms).unwrap();
        let found = store.find_matching(
            &GrantQuery {
                toolset_name: "my-toolset",
                install_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                package_version: "1.0.0",
                package_shasum: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                capability: "sign-payment",
                destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
                asset: "XLM",
                amount_stroops: 30_000_000,
                now_unix_ms,
                not_before_unix_ms: 0,
            },
            &attestation_key,
            &stellar_agent_core::approval::AttestationBinding::new("test", "stellar:testnet"),
        );
        assert!(found.is_some(), "persisted grant must be findable in store");
    }

    /// A signed `pay-toolset` 1.0.0 package and its trust files in a toolsets
    /// root. The package bytes and signature are deterministic, so another
    /// process rebuilds the same package for the same root.
    #[cfg(feature = "test-helpers")]
    struct SignedInstall {
        root: PathBuf,
        package: Vec<u8>,
        shasum: String,
        signature: [u8; 64],
        publisher: [u8; 32],
    }

    #[cfg(feature = "test-helpers")]
    impl SignedInstall {
        /// Builds the package and writes its trust files in `root`.
        fn new(root: &Path) -> Self {
            let signed = Self::package(root);
            std::fs::write(
                root.join("trust.txt"),
                stellar_strkey::ed25519::PublicKey(signed.publisher).to_string(),
            )
            .unwrap();
            std::fs::write(root.join("auditor-trust.txt"), "").unwrap();
            signed
        }

        /// Builds the package for a root whose trust files exist.
        fn package(root: &Path) -> Self {
            use ed25519_dalek::{Signer as _, SigningKey};
            use std::io::Write as _;

            let manifest = b"---\nname: pay-toolset\ndescription: test payment toolset\nmetadata:\n  stellar-agent-capabilities: sign-payment\n---\nBody.\n";
            let mut archive = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_gnu();
            header.set_size(u64::try_from(manifest.len()).unwrap());
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, "pay-toolset/TOOLSET.md", &manifest[..])
                .unwrap();
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&archive.into_inner().unwrap()).unwrap();
            let package = encoder.finish().unwrap();
            let shasum = stellar_agent_toolsets_install::sha256_hex_of(&package);
            let signer = SigningKey::from_bytes(&[17; 32]);
            let publisher = signer.verifying_key().to_bytes();
            let signature = signer
                .sign(&stellar_agent_toolsets_install::signature::build_preimage(
                    "pay-toolset",
                    "1.0.0",
                    &shasum,
                ))
                .to_bytes();
            Self {
                root: root.to_path_buf(),
                package,
                shasum,
                signature,
                publisher,
            }
        }

        /// Forces an install under the exclusive root lock.
        fn try_install(&self) -> Result<(), ToolsetInstallError> {
            let lock = stellar_agent_toolsets_install::lock_toolsets(&self.root)?;
            stellar_agent_toolsets_install::install_toolset(
                "pay-toolset",
                "1.0.0",
                &self.package,
                &self.shasum,
                &self.signature,
                &self.publisher,
                &self.root,
                &self.root.join("trust.txt"),
                None,
                &self.root.join("auditor-trust.txt"),
                &stellar_agent_toolsets_install::InstallOptions {
                    force: true,
                    override_attestation: true,
                    ..stellar_agent_toolsets_install::InstallOptions::default()
                },
                &lock,
                test_pin_key(),
            )
            .map(drop)
        }

        /// Uninstalls under the exclusive root lock.
        fn uninstall(&self) -> Result<(), ToolsetInstallError> {
            let lock = stellar_agent_toolsets_install::lock_toolsets(&self.root)?;
            stellar_agent_toolsets_install::uninstall_toolset("pay-toolset", &self.root, &lock)
        }
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    #[serial_test::serial]
    fn a_grant_approved_for_an_earlier_install_is_not_honored() {
        use stellar_agent_core::approval::{ApprovalKind, PendingApprovalStore};
        use stellar_agent_toolsets_install::read_pin;

        let _storage = storage_guard();
        let fixture = GatedGrantFixture::new();
        let signed = SignedInstall::new(fixture.dir.path());
        let try_install = || signed.try_install();
        let install = || {
            try_install().unwrap();
            // Both authentic pins carry the same second, independent of test duration.
            fixture.set_install_time("2026-01-01T00:00:00Z");
            read_pin("pay-toolset", fixture.dir.path(), Some(test_pin_key()))
                .unwrap()
                .unwrap()
        };
        let pin_a = install();
        let GatedResolveOutcome::FirstInvokeApprovalRequired { approval_nonce, .. } =
            resolve_toolset_sign_payment_gated(&fixture.params()).unwrap()
        else {
            panic!("installation A needs consent")
        };
        let approval_path = fixture.dir.path().join("approvals/test.toml");
        let queued = {
            let store = PendingApprovalStore::open(approval_path.clone()).unwrap();
            store.get(&approval_nonce).unwrap().clone()
        };
        let pin_b = install();
        assert_eq!(pin_a.installed_at, pin_b.installed_at);
        let ApprovalKind::ToolsetFirstInvokeGate {
            toolset_name,
            install_id,
            package_version,
            package_shasum,
            capability,
            destination,
            asset,
            amount_min_stroops,
            amount_max_stroops,
        } = queued.kind
        else {
            panic!("expected a gate request")
        };
        assert_eq!(install_id, pin_a.install_id);
        record_first_invoke_grant(
            "test",
            &toolset_name,
            &install_id,
            &package_version,
            &package_shasum,
            &capability,
            &destination,
            &asset,
            amount_min_stroops,
            amount_max_stroops,
            "1000",
            GatedGrantFixture::NOW_MS,
            &GatedGrantFixture::KEY,
            &fixture.binding,
            fixture.params().grant_store_path_override,
        )
        .unwrap();
        let GatedResolveOutcome::FirstInvokeApprovalRequired {
            approval_nonce: fresh_nonce,
            ..
        } = resolve_toolset_sign_payment_gated(&fixture.params()).unwrap()
        else {
            panic!("installation B must request fresh consent")
        };
        assert_ne!(approval_nonce, fresh_nonce);
        let store = PendingApprovalStore::open(approval_path).unwrap();
        let ApprovalKind::ToolsetFirstInvokeGate {
            install_id,
            package_version,
            package_shasum,
            ..
        } = &store.get(&fresh_nonce).unwrap().kind
        else {
            panic!("expected a new gate request")
        };
        assert_eq!(install_id, &pin_b.install_id);
        assert_eq!(package_version, &pin_b.version);
        assert_eq!(package_shasum, &pin_b.shasum);
        drop(store);

        // A lease on installation B's grant holds off a forced reinstall, an
        // uninstall, and every grant writer; each leaves the pin unchanged.
        record_first_invoke_grant(
            "test",
            "pay-toolset",
            &pin_b.install_id,
            &pin_b.version,
            &pin_b.shasum,
            "sign-payment",
            GatedGrantFixture::DESTINATION,
            "XLM",
            0,
            10,
            "1000",
            GatedGrantFixture::NOW_MS,
            &GatedGrantFixture::KEY,
            &fixture.binding,
            Some(fixture.grants_path()),
        )
        .unwrap();
        let token = fixture.resolve();
        assert_eq!(token.pin(), &pin_b);
        let lease = fixture.lease(&token).unwrap();
        let uninstall = || signed.uninstall();
        assert!(matches!(try_install(), Err(ToolsetInstallError::Busy)));
        assert!(matches!(uninstall(), Err(ToolsetInstallError::Busy)));
        let current = read_pin("pay-toolset", fixture.dir.path(), Some(test_pin_key()));
        assert_eq!(
            current.unwrap().unwrap(),
            pin_b,
            "the leased pin is unchanged"
        );
        assert!(matches!(
            fixture.record_grant_result(),
            Err(ToolsetRuntimeError::CoordinationBusy)
        ));
        drop(lease);

        let pin_c = install();
        assert_ne!(pin_c.install_id, pin_b.install_id);
        let error = fixture.recheck(&token).unwrap_err();
        assert!(
            matches!(error, ToolsetRuntimeError::GrantChanged),
            "{error:?}"
        );
        uninstall().unwrap();
        let error = fixture.recheck(&token).unwrap_err();
        assert!(
            matches!(error, ToolsetRuntimeError::ToolsetNotInstalled),
            "{error:?}"
        );
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    fn a_binding_for_another_profile_is_refused() {
        let fixture = GatedGrantFixture::new();
        let binding = stellar_agent_core::approval::AttestationBinding::new(
            "binding-marker",
            "stellar:testnet",
        );
        let untouched = fixture.dir.path().join("untouched");
        let mut params = fixture.params();
        params.profile_name = "store-marker";
        params.attestation_binding = &binding;
        params.grant_store_path_override = Some(untouched.join("grants.toml"));
        params.approval_dir_override = Some(untouched.join("approvals"));
        let error = resolve_toolset_sign_payment_gated(&params).unwrap_err();
        let grant_error = record_first_invoke_grant(
            "store-marker",
            "pay-toolset",
            &"a".repeat(32),
            "1.0.0",
            &"d".repeat(64),
            "sign-payment",
            GatedGrantFixture::DESTINATION,
            "XLM",
            0,
            10,
            "1000",
            GatedGrantFixture::NOW_MS,
            &GatedGrantFixture::KEY,
            &binding,
            params.grant_store_path_override.clone(),
        )
        .unwrap_err();
        for error in [error, grant_error] {
            assert!(matches!(error, ToolsetRuntimeError::BindingMismatch));
            assert!(error.to_string().contains("toolset.binding_mismatch"));
            for rendered in [error.to_string(), format!("{error:?}")] {
                assert!(!rendered.contains("binding-marker"));
                assert!(!rendered.contains("store-marker"));
            }
            assert!(std::error::Error::source(&error).is_none());
        }
        assert!(!untouched.exists(), "neither entry point opens a store");
    }

    // ── Verified grants, leases, and rechecks ─────────────────────────────────

    /// Every file under `dir` with its bytes; directories appear with no bytes.
    #[cfg(feature = "test-helpers")]
    fn tree(dir: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                entries.extend(tree(&path));
                entries.push((path, None));
            } else {
                let bytes = std::fs::read(&path).unwrap();
                entries.push((path, Some(bytes)));
            }
        }
        entries.sort();
        entries
    }

    /// Rechecks with the clock fixed at [`GatedGrantFixture::NOW_MS`].
    #[cfg(feature = "test-helpers")]
    fn recheck_at_fixture_time(
        token: &VerifiedToolsetGrant,
        params: &GrantRecheckParams<'_>,
    ) -> Result<(), ToolsetRuntimeError> {
        acquire_lease_with_clock(token, params, &mut || Ok(GatedGrantFixture::NOW_MS)).map(drop)
    }

    /// Wallet state confined to a sandbox until the guard and sandbox drop.
    #[cfg(feature = "test-helpers")]
    type StorageGuard = (
        stellar_agent_test_support::StellarAgentHomeGuard,
        stellar_agent_test_support::sandbox::StateSandbox,
    );

    #[cfg(feature = "test-helpers")]
    fn storage_guard() -> StorageGuard {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let guard = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        (guard, sandbox)
    }

    /// The fixture with one recorded grant and the token resolving it returns.
    #[cfg(feature = "test-helpers")]
    fn leased_fixture() -> (StorageGuard, GatedGrantFixture, VerifiedToolsetGrant) {
        let storage = storage_guard();
        let fixture = GatedGrantFixture::new();
        fixture.record_grant();
        let token = fixture.resolve();
        (storage, fixture, token)
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    #[serial_test::serial]
    fn the_resolved_grant_keeps_its_stored_identity_and_expiry() {
        let _storage = storage_guard();
        let fixture = GatedGrantFixture::new();
        let grant = build_attested_grant(
            "pay-toolset".to_owned(),
            "a".repeat(32),
            "1.0.0".to_owned(),
            "d".repeat(64),
            "sign-payment".to_owned(),
            GatedGrantFixture::DESTINATION.to_owned(),
            "XLM".to_owned(),
            0,
            10,
            "1000".to_owned(),
            GatedGrantFixture::NOW_MS,
            60_000,
            &GatedGrantFixture::KEY,
            &fixture.binding,
        )
        .unwrap();
        ToolsetGrantStore::open(fixture.grants_path(), 0)
            .unwrap()
            .insert(grant.clone())
            .unwrap();
        let mut params = fixture.params();
        params.now_unix_ms = GatedGrantFixture::NOW_MS + 1_000;
        let GatedResolveOutcome::Resolved { grant: token, .. } =
            resolve_toolset_sign_payment_gated(&params).unwrap()
        else {
            panic!("the stored grant covers the invocation")
        };
        assert_eq!(token.grant_id(), grant.grant_id);
        assert_eq!(
            token.expires_at_unix_ms(),
            GatedGrantFixture::NOW_MS + 60_000
        );
        assert_eq!(token.grant, grant);
        let pin = read_pin("pay-toolset", fixture.dir.path(), Some(test_pin_key()));
        assert_eq!(token.pin(), &pin.unwrap().unwrap());
        let rendered = format!("{token:?}");
        assert!(rendered.contains(&grant.grant_id), "{rendered}");
        for hidden in [
            grant.attestation_blob_b64.as_deref().unwrap(),
            fixture.dir.path().to_str().unwrap(),
        ] {
            assert!(!rendered.contains(hidden), "{rendered}");
        }
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    #[serial_test::serial]
    fn the_public_lease_reads_the_system_clock() {
        let (_storage, fixture, expired) = leased_fixture();
        let error = acquire_toolset_grant_lease(&expired, &fixture.recheck_params()).unwrap_err();
        assert!(
            matches!(error, ToolsetRuntimeError::GrantExpired),
            "{error:?}"
        );

        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        let recorded = record_first_invoke_grant(
            "test",
            "pay-toolset",
            &"a".repeat(32),
            "1.0.0",
            &"d".repeat(64),
            "sign-payment",
            GatedGrantFixture::DESTINATION,
            "XLM",
            0,
            10,
            "1000",
            now,
            &GatedGrantFixture::KEY,
            &fixture.binding,
            Some(fixture.grants_path()),
        )
        .unwrap();
        let mut params = fixture.params();
        params.now_unix_ms = now;
        let GatedResolveOutcome::Resolved { grant: current, .. } =
            resolve_toolset_sign_payment_gated(&params).unwrap()
        else {
            panic!("the current grant covers the invocation")
        };
        assert_eq!(current.grant_id(), recorded.grant_id);
        let lease = acquire_toolset_grant_lease(&current, &fixture.recheck_params()).unwrap();
        assert_eq!(lease.grant().grant_id(), recorded.grant_id);
        drop(lease);
        recheck_toolset_grant(&current, &fixture.recheck_params()).unwrap();
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    #[serial_test::serial]
    fn a_lease_holds_off_every_writer_until_it_drops() {
        fn assert_send<T: Send>() {}
        assert_send::<ToolsetGrantLease>();
        let (_sandbox, fixture, token) = leased_fixture();
        let lease = fixture.lease(&token).unwrap();
        assert_eq!(lease.grant().grant_id(), token.grant_id());
        assert_eq!(
            lease.grant().expires_at_unix_ms(),
            token.expires_at_unix_ms()
        );
        let second = fixture.lease(&token);
        assert!(second.is_ok(), "two leases coexist: {second:?}");
        let grants = std::fs::read(fixture.grants_path()).unwrap();

        assert!(matches!(
            fixture.record_grant_result(),
            Err(ToolsetRuntimeError::CoordinationBusy)
        ));
        assert!(matches!(
            ToolsetGrantStore::open(fixture.grants_path(), 0),
            Err(ApprovalError::WriterLocked)
        ));
        assert!(matches!(
            resolve_toolset_sign_payment_gated(&fixture.params()),
            Err(ToolsetRuntimeError::CoordinationBusy)
        ));
        assert!(matches!(
            stellar_agent_toolsets_install::lock_toolsets(fixture.dir.path()),
            Err(ToolsetInstallError::Busy)
        ));
        assert_eq!(std::fs::read(fixture.grants_path()).unwrap(), grants);
        assert_eq!(fixture.approval_count(), 0);
        drop((lease, second));

        fixture.record_grant();
        drop(stellar_agent_toolsets_install::lock_toolsets(fixture.dir.path()).unwrap());
        fixture.recheck(&token).unwrap();
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    #[serial_test::serial]
    fn a_recheck_refuses_another_invocation() {
        let (_sandbox, fixture, token) = leased_fixture();
        let other_binding =
            stellar_agent_core::approval::AttestationBinding::new("other", "stellar:testnet");
        let pubnet =
            stellar_agent_core::approval::AttestationBinding::new("test", "stellar:pubnet");
        let other_root = tempfile::TempDir::new().unwrap();
        type Change = fn(&mut GrantRecheckParams<'_>);
        let changes: [(&str, Change); 7] = [
            ("toolset", |p| p.toolset_name = "pay-toolset-2"),
            ("action", |p| p.action = "stellar_rule_create_commit"),
            ("destination", |p| {
                p.authoritative_destination =
                    "GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H";
            }),
            ("amount within the bucket", |p| {
                p.authoritative_amount_stroops = 5;
            }),
            ("asset", |p| {
                p.authoritative_asset =
                    "USDC:GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H";
            }),
            ("grant store", |p| {
                p.grant_store_path_override = Some(PathBuf::from("other.toml"));
            }),
            ("chain", |_| {}),
        ];
        let before = tree(fixture.dir.path());
        for (name, change) in changes {
            let mut params = fixture.recheck_params();
            change(&mut params);
            if name == "chain" {
                params.attestation_binding = &pubnet;
            }
            let error = recheck_at_fixture_time(&token, &params).unwrap_err();
            assert!(
                matches!(error, ToolsetRuntimeError::GrantInvocationMismatch),
                "{name}: {error:?}"
            );
        }
        let mut params = fixture.recheck_params();
        params.toolsets_root = other_root.path();
        let error = recheck_at_fixture_time(&token, &params).unwrap_err();
        assert!(matches!(
            error,
            ToolsetRuntimeError::GrantInvocationMismatch
        ));
        params = fixture.recheck_params();
        params.profile_name = "other";
        params.attestation_binding = &other_binding;
        let error = recheck_at_fixture_time(&token, &params).unwrap_err();
        assert!(matches!(
            error,
            ToolsetRuntimeError::GrantInvocationMismatch
        ));
        params.profile_name = "test";
        let error = recheck_at_fixture_time(&token, &params).unwrap_err();
        assert!(matches!(error, ToolsetRuntimeError::BindingMismatch));
        assert_eq!(tree(fixture.dir.path()), before);
        assert_eq!(fixture.approval_count(), 0);

        let mut invoke = fixture.params();
        invoke.authoritative_amount_stroops = 5;
        let GatedResolveOutcome::Resolved { grant: rebound, .. } =
            resolve_toolset_sign_payment_gated(&invoke).unwrap()
        else {
            panic!("a new resolution binds the new amount")
        };
        let mut params = fixture.recheck_params();
        params.authoritative_amount_stroops = 5;
        recheck_at_fixture_time(&rebound, &params).unwrap();
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    #[serial_test::serial]
    fn a_recheck_finds_only_the_verified_grant_and_installation() {
        let (_sandbox, fixture, token) = leased_fixture();
        let recheck = || fixture.recheck(&token);

        // A matching grant stored ahead of the original leaves it valid.
        let original = std::fs::read_to_string(fixture.grants_path()).unwrap();
        let mut store = ToolsetGrantStore::open(fixture.grants_path(), 0).unwrap();
        store.revoke_all().unwrap();
        drop(store);
        let replacement = fixture.record_grant();
        let ahead = std::fs::read_to_string(fixture.grants_path()).unwrap();
        std::fs::write(
            fixture.grants_path(),
            format!("{ahead}\n{}", original.trim_start()),
        )
        .unwrap();
        recheck().unwrap();

        // Only the replacement remains: equal coverage is not the same consent.
        std::fs::write(fixture.grants_path(), &ahead).unwrap();
        let error = recheck().unwrap_err();
        assert!(
            matches!(error, ToolsetRuntimeError::GrantChanged),
            "{error:?}"
        );
        assert_eq!(fixture.resolve().grant_id(), replacement.grant_id);

        // Revoked.
        let mut store = ToolsetGrantStore::open(fixture.grants_path(), 0).unwrap();
        store.revoke_toolset("pay-toolset").unwrap();
        drop(store);
        let error = recheck().unwrap_err();
        assert!(
            matches!(error, ToolsetRuntimeError::GrantChanged),
            "{error:?}"
        );

        // An edited lifetime no longer verifies.
        std::fs::write(
            fixture.grants_path(),
            original.replace("expires_at_unix_ms = ", "expires_at_unix_ms = 1"),
        )
        .unwrap();
        let error = recheck().unwrap_err();
        assert!(
            matches!(error, ToolsetRuntimeError::GrantChanged),
            "{error:?}"
        );
        std::fs::write(fixture.grants_path(), &original).unwrap();
        recheck().unwrap();

        // A new authentic install record is another installation.
        fixture.set_install_time("1970-01-01T00:00:01Z");
        let error = recheck().unwrap_err();
        assert!(
            matches!(error, ToolsetRuntimeError::GrantChanged),
            "{error:?}"
        );
        fixture.set_install_time("1970-01-01T00:00:00Z");
        recheck().unwrap();

        // An edited record, capability, or manifest refuses as at resolution.
        let manifest = fixture.dir.path().join("pay-toolset").join("TOOLSET.md");
        let manifest_bytes = std::fs::read(&manifest).unwrap();
        std::fs::write(&manifest, "---\nname: pay-toolset\n---\n").unwrap();
        let error = recheck().unwrap_err();
        assert!(matches!(
            error,
            ToolsetRuntimeError::ContentDigestMismatch { .. }
        ));
        std::fs::remove_file(&manifest).unwrap();
        let error = recheck().unwrap_err();
        assert!(matches!(
            error,
            ToolsetRuntimeError::ContentDigestMismatch { .. }
        ));
        std::fs::write(&manifest, manifest_bytes).unwrap();
        recheck().unwrap();
        add_stored_capability(fixture.dir.path(), "pay-toolset", "read-balance");
        let error = recheck().unwrap_err();
        assert!(matches!(error, ToolsetRuntimeError::PinUnverifiable { .. }));
        write_toolset_fixture(
            fixture.dir.path(),
            "pay-toolset",
            "read-balance",
            vec![],
            "1970-01-01T00:00:00Z",
        );
        let error = recheck().unwrap_err();
        assert!(
            matches!(error, ToolsetRuntimeError::CapabilityNotDeclared { .. }),
            "{error:?}"
        );
        write_toolset_fixture(
            fixture.dir.path(),
            "pay-toolset",
            "sign-payment",
            vec!["stellar_balances".to_owned()],
            "1970-01-01T00:00:00Z",
        );
        let error = recheck().unwrap_err();
        assert!(
            matches!(error, ToolsetRuntimeError::ToolNotAllowed { .. }),
            "{error:?}"
        );
        assert_eq!(fixture.approval_count(), 0);
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    #[serial_test::serial]
    fn a_recheck_creates_repairs_and_prunes_nothing() {
        let (_sandbox, fixture, token) = leased_fixture();
        let grants = fixture.grants_path();
        let sidecar = fixture.dir.path().join("grants.toml.lock");
        let root_lock = fixture.dir.path().join(TOOLSETS_LOCK_FILE_NAME);
        assert!(
            sidecar.is_file() && root_lock.is_file(),
            "resolution made both"
        );
        let stored = std::fs::read(&grants).unwrap();
        let check = |expected: fn(&ToolsetRuntimeError) -> bool, case: &str| {
            let before = tree(fixture.dir.path());
            let error = fixture.recheck(&token).unwrap_err();
            assert!(expected(&error), "{case}: {error:?}");
            assert_eq!(tree(fixture.dir.path()), before, "{case} changed the tree");
        };

        std::fs::remove_file(&sidecar).unwrap();
        check(
            |e| matches!(e, ToolsetRuntimeError::CoordinationUnavailable),
            "absent grant sidecar",
        );
        std::fs::write(&sidecar, "").unwrap();
        std::fs::remove_file(&root_lock).unwrap();
        check(
            |e| matches!(e, ToolsetRuntimeError::CoordinationUnavailable),
            "absent root lock",
        );
        std::fs::write(&root_lock, "").unwrap();
        std::fs::remove_file(&grants).unwrap();
        check(
            |e| matches!(e, ToolsetRuntimeError::GrantChanged),
            "absent data file",
        );
        std::fs::write(&grants, "[[grants]]\ngrant_id = ").unwrap();
        check(
            |e| matches!(e, ToolsetRuntimeError::GrantStoreError { .. }),
            "malformed data file",
        );
        std::fs::remove_file(&grants).unwrap();
        std::fs::create_dir(&grants).unwrap();
        check(
            |e| matches!(e, ToolsetRuntimeError::GrantStoreError { .. }),
            "unreadable data file",
        );
        std::fs::remove_dir(&grants).unwrap();
        std::fs::write(&grants, &stored).unwrap();
        let before = tree(fixture.dir.path());
        let error =
            acquire_lease_with_clock(&token, &fixture.recheck_params(), &mut || Ok(u64::MAX))
                .unwrap_err();
        assert!(matches!(error, ToolsetRuntimeError::GrantExpired));
        assert_eq!(
            tree(fixture.dir.path()),
            before,
            "an expired grant stays stored"
        );
        assert_eq!(fixture.approval_count(), 0);

        // Ordinary resolution of a store without lock files recreates them
        // and returns the existing grant unchanged, without a prompt.
        std::fs::remove_file(&sidecar).unwrap();
        std::fs::remove_file(&root_lock).unwrap();
        let again = fixture.resolve();
        assert_eq!(again.grant_id(), token.grant_id());
        assert!(sidecar.is_file() && root_lock.is_file());
        assert_eq!(std::fs::read(&grants).unwrap(), stored);
        fixture.recheck(&token).unwrap();
        assert_eq!(fixture.approval_count(), 0);
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    #[serial_test::serial]
    fn a_lease_reads_a_fresh_clock_under_its_locks_and_never_renews() {
        let (_sandbox, fixture, token) = leased_fixture();
        let expiry = token.expires_at_unix_ms();
        let issued = token.grant.granted_at_unix_ms;
        let stored = std::fs::read(fixture.grants_path()).unwrap();
        let acquire = |samples: &[u64]| {
            let mut samples = samples.iter().copied();
            acquire_lease_with_clock(&token, &fixture.recheck_params(), &mut || {
                assert!(
                    matches!(
                        ToolsetGrantStore::open(fixture.grants_path(), 0),
                        Err(ApprovalError::WriterLocked)
                    ),
                    "the clock is read while the grant lock is held"
                );
                samples
                    .next()
                    .ok_or_else(|| ToolsetRuntimeError::Io("clock_unavailable".to_owned()))
            })
        };
        let lease = acquire(&[expiry - 1, expiry - 1]).unwrap();
        assert_eq!(lease.grant().expires_at_unix_ms(), expiry);
        drop(lease);
        for (samples, case) in [
            (&[expiry][..], "at expiry"),
            (&[expiry + 1][..], "after expiry"),
            (&[expiry - 1, expiry][..], "expiry crossed before return"),
        ] {
            let error = acquire(samples).unwrap_err();
            assert!(
                matches!(error, ToolsetRuntimeError::GrantExpired),
                "{case}: {error:?}"
            );
        }
        let error = acquire(&[issued - 1, issued - 1]).unwrap_err();
        assert!(
            matches!(error, ToolsetRuntimeError::GrantChanged),
            "a clock before the issue time verifies no grant: {error:?}"
        );
        let error = acquire(&[]).unwrap_err();
        assert_eq!(error.to_string(), "toolset.io_error: clock_unavailable");
        let error = acquire(&[expiry - 1]).unwrap_err();
        assert_eq!(error.to_string(), "toolset.io_error: clock_unavailable");
        assert_eq!(std::fs::read(fixture.grants_path()).unwrap(), stored);
        assert_eq!(token.expires_at_unix_ms(), expiry);
        assert_eq!(fixture.approval_count(), 0);
        drop(ToolsetGrantStore::open(fixture.grants_path(), 0).unwrap());
    }

    #[test]
    #[cfg(feature = "test-helpers")]
    #[serial_test::serial]
    fn a_first_invoke_miss_releases_both_locks_before_queueing() {
        let _storage = storage_guard();
        let fixture = GatedGrantFixture::new();
        let grants = fixture.grants_path();
        let root = fixture.dir.path().to_path_buf();
        let ran = std::rc::Rc::new(std::cell::Cell::new(false));
        let seen = std::rc::Rc::clone(&ran);
        BEFORE_FIRST_INVOKE_QUEUE.set(Some(Box::new(move || {
            ToolsetGrantStore::open(grants.clone(), 0)
                .expect("a grant writer opens while queueing");
            drop(
                stellar_agent_toolsets_install::lock_toolsets(&root).expect("an install proceeds"),
            );
            seen.set(true);
        })));
        let outcome = resolve_toolset_sign_payment_gated(&fixture.params());
        BEFORE_FIRST_INVOKE_QUEUE.set(None);
        assert!(matches!(
            outcome.unwrap(),
            GatedResolveOutcome::FirstInvokeApprovalRequired { .. }
        ));
        assert!(ran.get(), "the hook ran before the approval store opened");
        assert_eq!(fixture.approval_count(), 1);
    }

    // ── Locks across processes ────────────────────────────────────────────────

    #[cfg(feature = "test-helpers")]
    const LOCK_PROCESS_TEST: &str = "tests::lease_and_writer_locks_hold_across_processes";
    #[cfg(feature = "test-helpers")]
    const LOCK_PROCESS_ROLE: &str = "TOOLSET_LOCK_PROCESS_ROLE";
    #[cfg(feature = "test-helpers")]
    const LOCK_PROCESS_ROOT: &str = "TOOLSET_LOCK_PROCESS_ROOT";

    /// Records the fixture grant terms for `pin` in the grant store of `root`.
    #[cfg(feature = "test-helpers")]
    fn record_grant_for(
        root: &Path,
        pin: &ToolsetPinRecord,
    ) -> Result<ToolsetGrant, ToolsetRuntimeError> {
        record_first_invoke_grant(
            "test",
            "pay-toolset",
            &pin.install_id,
            &pin.version,
            &pin.shasum,
            "sign-payment",
            GatedGrantFixture::DESTINATION,
            "XLM",
            0,
            10,
            "1000",
            GatedGrantFixture::NOW_MS,
            &GatedGrantFixture::KEY,
            &stellar_agent_core::approval::AttestationBinding::new("test", "stellar:testnet"),
            Some(root.join("grants.toml")),
        )
    }

    /// Every file under `root` with its bytes, except the lock files.
    #[cfg(feature = "test-helpers")]
    fn protected_files(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        tree(root)
            .into_iter()
            .filter(|(path, _)| path.extension().is_none_or(|ext| ext != "lock"))
            .collect()
    }

    /// A copy of this test binary in one role, synchronized through its
    /// standard input and output pipes.
    #[cfg(feature = "test-helpers")]
    struct LockPeer {
        role: &'static str,
        child: std::process::Child,
        stdout: std::io::BufReader<std::process::ChildStdout>,
    }

    #[cfg(feature = "test-helpers")]
    impl LockPeer {
        fn spawn(role: &'static str, root: &Path, home: &Path) -> Self {
            use std::process::{Command, Stdio};
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", LOCK_PROCESS_TEST, "--nocapture"])
                .env(LOCK_PROCESS_ROLE, role)
                .env(LOCK_PROCESS_ROOT, root)
                .env("STELLAR_AGENT_HOME", home)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let stdout = std::io::BufReader::new(child.stdout.take().unwrap());
            Self {
                role,
                child,
                stdout,
            }
        }

        /// Reads the child's output through the line `marker`.
        fn wait_for(&mut self, marker: &str) {
            use std::io::BufRead as _;
            let mut line = String::new();
            loop {
                line.clear();
                if self.stdout.read_line(&mut line).unwrap() == 0 {
                    let (_, report) = self.finish();
                    panic!("{report}; the child printed no {marker} line");
                }
                if line.trim() == marker {
                    return;
                }
            }
        }

        /// Sends the byte the child waits for.
        fn release(&mut self) {
            use std::io::Write as _;
            let stdin = self.child.stdin.as_mut().unwrap();
            stdin.write_all(b"1").unwrap();
            stdin.flush().unwrap();
        }

        /// Waits for the child's exit and describes its status and stderr.
        fn finish(&mut self) -> (std::process::ExitStatus, String) {
            use std::io::Read as _;
            drop(self.child.stdin.take());
            let mut stderr = String::new();
            if let Some(mut pipe) = self.child.stderr.take() {
                pipe.read_to_string(&mut stderr).unwrap();
            }
            let status = self.child.wait().unwrap();
            let report = format!("child {}: {status}; stderr: {stderr}", self.role);
            (status, report)
        }
    }

    #[cfg(feature = "test-helpers")]
    fn signal_parent(marker: &str) {
        use std::io::Write as _;
        let mut output = std::io::stdout();
        writeln!(output, "{marker}").unwrap();
        output.flush().unwrap();
    }

    #[cfg(feature = "test-helpers")]
    fn await_parent() {
        use std::io::Read as _;
        std::io::stdin().read_exact(&mut [0]).unwrap();
    }

    /// Signals that a lock is held, then exits on the parent's byte without
    /// running the destructor of the caller's guard.
    #[cfg(feature = "test-helpers")]
    fn exit_holding_the_lock() -> ! {
        signal_parent("locked");
        await_parent();
        std::process::exit(0)
    }

    /// The child side of [`lease_and_writer_locks_hold_across_processes`].
    #[cfg(feature = "test-helpers")]
    fn lock_process_child(role: &str, root: &Path) {
        let grants = root.join("grants.toml");
        match role {
            "writers" => {
                let signed = SignedInstall::package(root);
                let pin = stellar_agent_toolsets_install::read_pin(
                    "pay-toolset",
                    root,
                    Some(test_pin_key()),
                )
                .unwrap()
                .unwrap();
                let install = signed.try_install();
                assert!(
                    matches!(install, Err(ToolsetInstallError::Busy)),
                    "a forced install refuses during the lease: {install:?}"
                );
                let uninstall = signed.uninstall();
                assert!(
                    matches!(uninstall, Err(ToolsetInstallError::Busy)),
                    "an uninstall refuses during the lease: {uninstall:?}"
                );
                let recorded = record_grant_for(root, &pin);
                assert!(
                    matches!(recorded, Err(ToolsetRuntimeError::CoordinationBusy)),
                    "grant recording refuses during the lease: {recorded:?}"
                );
                let revoker = ToolsetGrantStore::open(grants.clone(), 0);
                assert!(
                    matches!(revoker, Err(ApprovalError::WriterLocked)),
                    "revocation refuses during the lease: {revoker:?}"
                );
                signal_parent("refused");
                await_parent();
                record_grant_for(root, &pin).unwrap();
                signal_parent("recorded");
                await_parent();
                let removed = ToolsetGrantStore::open(grants, 0)
                    .unwrap()
                    .revoke_toolset("pay-toolset")
                    .unwrap();
                assert_eq!(removed, 2, "revocation removes both grants");
                signal_parent("revoked");
                await_parent();
                signed.try_install().unwrap();
                signal_parent("reinstalled");
                await_parent();
                signed.uninstall().unwrap();
                signal_parent("uninstalled");
            }
            "root" => {
                let _held = stellar_agent_toolsets_install::lock_toolsets(root).unwrap();
                exit_holding_the_lock();
            }
            "grants" => {
                let _held = ToolsetGrantStore::open(grants, 0).unwrap();
                exit_holding_the_lock();
            }
            "approvals" => {
                let _held = stellar_agent_core::approval::PendingApprovalStore::open(
                    root.join("approvals").join("test.toml"),
                )
                .unwrap();
                exit_holding_the_lock();
            }
            other => panic!("unknown role {other}"),
        }
    }

    /// The shared lease and the exclusive writers exclude each other across
    /// processes. A child that exits holding a lock releases it, and the
    /// resolver releases both locks before it waits on the approval store.
    #[test]
    #[cfg(feature = "test-helpers")]
    #[serial_test::serial]
    #[allow(clippy::too_many_lines)]
    fn lease_and_writer_locks_hold_across_processes() {
        use stellar_agent_core::approval::PendingApprovalStore;

        if let (Ok(role), Some(root)) = (
            std::env::var(LOCK_PROCESS_ROLE),
            std::env::var_os(LOCK_PROCESS_ROOT),
        ) {
            lock_process_child(&role, Path::new(&root));
            return;
        }
        let storage = storage_guard();
        let home = storage.1.path().join("child-home");
        stellar_agent_test_support::sandbox::mark_sandbox(&home).unwrap();
        let fixture = GatedGrantFixture::new();
        let root = fixture.dir.path();
        let signed = SignedInstall::new(root);
        let install = || {
            signed.try_install().unwrap();
            // Grants recorded at the fixture time postdate this install.
            fixture.set_install_time("2026-01-01T00:00:00Z");
            stellar_agent_toolsets_install::read_pin("pay-toolset", root, Some(test_pin_key()))
                .unwrap()
                .unwrap()
        };
        let pin = install();
        record_grant_for(root, &pin).unwrap();
        let token = fixture.resolve();

        // Child holder: each exclusive lock refuses the recheck until the
        // child exits without releasing it.
        for role in ["root", "grants"] {
            let mut peer = LockPeer::spawn(role, root, &home);
            peer.wait_for("locked");
            let held = fixture.recheck(&token);
            peer.release();
            let (status, report) = peer.finish();
            let reacquired = (0..200).any(|_| {
                fixture.recheck(&token).is_ok() || {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    false
                }
            });
            assert!(status.success(), "{report}");
            assert!(
                matches!(held, Err(ToolsetRuntimeError::CoordinationBusy)),
                "the child's {role} lock refuses the recheck: {held:?}; {report}"
            );
            assert!(
                reacquired,
                "the lock releases at the child's exit: {report}"
            );
        }

        // Parent holder: every writer in the child refuses during the lease
        // and succeeds after it.
        let lease = fixture.lease(&token).unwrap();
        let before = protected_files(root);
        let mut peer = LockPeer::spawn("writers", root, &home);
        peer.wait_for("refused");
        let during = protected_files(root);
        drop(lease);
        peer.release();
        peer.wait_for("recorded");
        let recorded = fixture.recheck(&token);
        peer.release();
        peer.wait_for("revoked");
        let revoked = fixture.recheck(&token);
        peer.release();
        peer.wait_for("reinstalled");
        let reinstalled = fixture.recheck(&token);
        peer.release();
        peer.wait_for("uninstalled");
        let uninstalled = fixture.recheck(&token);
        let (status, report) = peer.finish();
        assert!(status.success(), "{report}");
        assert!(
            during == before,
            "the refused writers change no protected byte: {report}"
        );
        assert!(
            recorded.is_ok(),
            "another grant leaves the original: {recorded:?}; {report}"
        );
        assert!(
            matches!(revoked, Err(ToolsetRuntimeError::GrantChanged)),
            "a revoked grant refuses: {revoked:?}; {report}"
        );
        assert!(
            matches!(reinstalled, Err(ToolsetRuntimeError::GrantChanged)),
            "a reinstall refuses: {reinstalled:?}; {report}"
        );
        assert!(
            matches!(uninstalled, Err(ToolsetRuntimeError::ToolsetNotInstalled)),
            "an uninstall refuses: {uninstalled:?}; {report}"
        );

        // Child-held approval store: at the queue hook both writers proceed.
        let _fresh = install();
        let mut peer = Some(LockPeer::spawn("approvals", root, &home));
        peer.as_mut().unwrap().wait_for("locked");
        let seen = std::rc::Rc::new(std::cell::RefCell::new(None));
        let record = std::rc::Rc::clone(&seen);
        let approvals = root.join("approvals").join("test.toml");
        let grants = fixture.grants_path();
        let hook_root = root.to_path_buf();
        BEFORE_FIRST_INVOKE_QUEUE.set(Some(Box::new(move || {
            let held = PendingApprovalStore::open(approvals.clone()).map(drop);
            let grant_writer = ToolsetGrantStore::open(grants.clone(), 0).map(drop);
            let root_writer = stellar_agent_toolsets_install::lock_toolsets(&hook_root).map(drop);
            let mut peer = peer.take().unwrap();
            peer.release();
            *record.borrow_mut() = Some((held, grant_writer, root_writer, peer.finish()));
        })));
        let outcome = resolve_toolset_sign_payment_gated(&fixture.params());
        BEFORE_FIRST_INVOKE_QUEUE.set(None);
        let (held, grant_writer, root_writer, (status, report)) =
            seen.take().expect("the resolver reaches the queue hook");
        assert!(status.success(), "{report}");
        assert!(
            matches!(held, Err(ApprovalError::WriterLocked)),
            "the child holds the approval store at the hook: {held:?}; {report}"
        );
        assert!(
            grant_writer.is_ok(),
            "a grant writer opens at the hook: {grant_writer:?}; {report}"
        );
        assert!(
            root_writer.is_ok(),
            "an installer locks the root at the hook: {root_writer:?}; {report}"
        );
        assert!(
            matches!(
                outcome,
                Ok(GatedResolveOutcome::FirstInvokeApprovalRequired { .. })
            ),
            "the miss queues after the child exits: {outcome:?}; {report}"
        );
        assert_eq!(fixture.approval_count(), 1, "{report}");
    }
}
