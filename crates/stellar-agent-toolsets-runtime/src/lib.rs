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
//! ## Security guarantees
//!
//! **Signing isolation is STRUCTURAL**: the ungated capability→tool matrix
//! ([`matrix::grants_for_capability`]) contains no signing/key/policy tool
//! regardless of any capability declaration. Even a toolset declaring every
//! capability cannot reach a signing tool via the ungated path. This is the
//! isolation boundary between the toolset guest code and the wallet's signing
//! infrastructure.
//!
//! **Gated signing path**: `stellar_pay_commit` is reachable ONLY through
//! `resolve_toolset_sign_payment_gated`, which requires BOTH:
//! 1. The four-part check (toolset declared `sign-payment`; the gated action
//!    resolves; tool ∈ `allowed_tools`).
//! 2. A current, matching first-invoke grant in the [`ToolsetGrantStore`].
//!
//! A `DispatchOutcome::Allow` from the policy engine is OVERRIDDEN to
//! `RequireApproval` for all toolset-routed payments (unconditional per-action
//! approval).
//!
//! ## Primary consumers
//!
//! The MCP server crate consumes `stellar_toolset_list`, `stellar_toolset_invoke`,
//! and the gated `stellar_toolset_invoke` path routing to `stellar_pay_commit`.
//! The CLI crate consumes `toolset list` and `toolset run <name> <action>`.
//!
//! ## What this crate does NOT do
//!
//! - Per-action attestation verification gate — performed by the consumer
//!   (CLI/MCP) layer, not this crate. This crate DOES build HMAC-attested
//!   grants via [`record_first_invoke_grant`]; the verification of those
//!   grants on each action invocation is the consumer's responsibility.
//! - Dynamic tool registration — explicitly out of scope.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod matrix;

pub use error::ToolsetRuntimeError;
pub use matrix::{
    GATED_MATRIX_ENTRIES, SIGN_PAYMENT_GATED_TOOLS, SIGNING_DENYLIST, gated_grants_for_capability,
    resolve_action,
};

use std::path::Path;

use serde::Serialize;
use stellar_agent_core::approval::{
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, DEFAULT_TTL_MS, PendingApproval,
    TOOLSET_GRANT_DEFAULT_TTL_MS, ToolsetGrant, ToolsetGrantStore, build_attested_grant,
    default_toolset_grants_path, open_with_retry,
};
use stellar_agent_toolsets::{Capability, CapabilitySet, sanitise_display};
use stellar_agent_toolsets_install::ToolsetPinRecord;
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
/// from each, and skips entries whose pin files are absent (logged at debug)
/// or malformed (logged at warn). This is intentionally resilient so a single
/// corrupted install does not block listing all others.
///
/// The returned list is sorted by toolset name for deterministic output.
///
/// # Errors
///
/// - [`ToolsetRuntimeError::Io`] if `toolsets_root` itself cannot be read.
pub fn list_pinned_toolsets(
    toolsets_root: &Path,
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

        let path = dir_entry.path();
        if !path.is_dir() {
            continue;
        }

        let pkg_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_owned(),
            None => continue,
        };

        let pin = match stellar_agent_toolsets_install::read_pin(&pkg_name, toolsets_root) {
            Ok(Some(p)) => p,
            Ok(None) => {
                debug!(package = %pkg_name, "no pin record; skipping");
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
/// Reads the pin ONCE from `toolsets_root` (TOCTOU avoidance) and uses the
/// snapshot for the entire check. Returns `(tool_name, pin)` on success so the
/// caller can use the pin record for further context.
///
/// ## Dispatch-time content re-verification
///
/// If the pin's `toolset_md_shasum` field is `Some`, re-reads the on-disk
/// `TOOLSET.md` and compares its SHA-256 against the recorded digest. A
/// mismatch returns [`ToolsetRuntimeError::ContentDigestMismatch`] and refuses
/// dispatch. Pins without this field skip the check — the capability-source
/// invariant (capabilities from the pin, not re-parsed `TOOLSET.md`) ensures
/// tampered manifests cannot escalate capabilities regardless.
///
/// # Errors
///
/// - [`ToolsetRuntimeError::ToolsetNotInstalled`] — `toolset_name` fails charset
///   validation (`[a-z0-9-]`), or no pin record exists for the name.
/// - [`ToolsetRuntimeError::Io`] — I/O error reading the pin.
/// - [`ToolsetRuntimeError::ContentDigestMismatch`] — on-disk `TOOLSET.md` hash
///   differs from the install-time digest stored in the pin.
/// - Any [`check_toolset_action`] error.
pub fn resolve_toolset_and_check(
    toolset_name: &str,
    action: &str,
    toolsets_root: &Path,
) -> Result<(&'static str, ToolsetPinRecord), ToolsetRuntimeError> {
    // Validate toolset_name against [a-z0-9-] BEFORE any filesystem access.
    // Rejects `/`, `\`, `.`, `..`, and all other chars outside the charset.
    // Uses the same validator as the install path.
    stellar_agent_toolsets_install::validate_package_name(toolset_name).map_err(|_| {
        ToolsetRuntimeError::ToolsetNotInstalled {
            name: sanitise_display(toolset_name, 64),
        }
    })?;

    // Read the pin ONCE — snapshot for the entire check (TOCTOU avoidance).
    // Map ToolsetInstallError to ToolsetRuntimeError::Io using a kind-level message
    // to avoid leaking the toolsets_root path via full error Display.
    let pin = stellar_agent_toolsets_install::read_pin(toolset_name, toolsets_root)
        .map_err(|e| ToolsetRuntimeError::Io(install_error_kind_str(&e)))?
        .ok_or_else(|| ToolsetRuntimeError::ToolsetNotInstalled {
            name: sanitise_display(toolset_name, 64),
        })?;

    // ── Dispatch-time content re-verification ─────────────────────────────────
    //
    // If the pin carries a TOOLSET.md digest, re-read the on-disk TOOLSET.md,
    // recompute SHA-256, and compare. Mismatch → refuse dispatch.
    //
    // Both digests are non-secret hex strings; plain string comparison is
    // correct (no timing attack).
    //
    // On I/O error reading TOOLSET.md: refuse dispatch (fail-closed). The toolset
    // is installed but the manifest is unreadable — something is wrong.
    if let Some(ref expected_digest) = pin.toolset_md_shasum {
        let toolset_md_path = toolsets_root.join(toolset_name).join("TOOLSET.md");
        let toolset_md_bytes = std::fs::read(&toolset_md_path).map_err(|_| {
            ToolsetRuntimeError::ContentDigestMismatch {
                name: sanitise_display(toolset_name, 64),
            }
        })?;
        let actual_digest = stellar_agent_toolsets_install::sha256_hex_of(&toolset_md_bytes);
        if actual_digest != *expected_digest {
            tracing::warn!(
                toolset = %toolset_name,
                "dispatch-time TOOLSET.md content digest mismatch; refusing dispatch"
            );
            return Err(ToolsetRuntimeError::ContentDigestMismatch {
                name: sanitise_display(toolset_name, 64),
            });
        }
        debug!(toolset = %toolset_name, "dispatch-time TOOLSET.md content digest verified");
    }

    let capabilities = &pin.capabilities;
    let allowed_tools = &pin.allowed_tools;

    let tool_name = check_toolset_action(action, capabilities, allowed_tools)?;

    Ok((tool_name, pin))
}

// ── Internal helpers ──────────────────────────────────────────────────────────

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
#[derive(Debug)]
pub struct GatedInvokeParams<'a> {
    /// Package name of the toolset to invoke.
    pub toolset_name: &'a str,
    /// Action name to invoke (must map to a gated tool via the gated matrix).
    pub action: &'a str,
    /// Root directory of installed toolsets.
    pub toolsets_root: &'a Path,
    /// Profile name (used to locate the approval store + grant store).
    pub profile_name: &'a str,
    /// Canonical G-strkey destination from the AUTHORITATIVE envelope decode
    /// (never from toolset-supplied args).
    pub authoritative_destination: &'a str,
    /// Full `"code:issuer"` or `"XLM"` asset from the AUTHORITATIVE envelope.
    pub authoritative_asset: &'a str,
    /// Payment amount in stroops from the AUTHORITATIVE envelope.
    pub authoritative_amount_stroops: i64,
    /// Current time in Unix milliseconds (for TTL checks).
    pub now_unix_ms: u64,
    /// Platform-stable user identity (from `process_uid_for_attestation()`).
    pub process_uid: &'a str,
    /// Optional override for the approval store directory (test-only).
    #[cfg(feature = "test-helpers")]
    pub approval_dir_override: Option<std::path::PathBuf>,
    /// Optional override for the grant store path (test-only).
    #[cfg(feature = "test-helpers")]
    pub grant_store_path_override: Option<std::path::PathBuf>,
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

/// The GATED resolver for toolset-routed `sign-payment` invocations.
///
/// This is a **DISTINCT entry point** from [`resolve_toolset_and_check`] — it is
/// NOT a `route_to_matrix_tool` arm. It implements the full enforcement ordering:
///
/// 1. **Four-part check** (via the gated matrix): toolset declared `sign-payment`;
///    the action maps to a gated constant; the tool is in `allowed_tools`.
/// 2. **First-invoke gate**: check the grant store for a current, matching grant.
///    If none → queue `ToolsetFirstInvokeGate` approval, return
///    [`GatedResolveOutcome::FirstInvokeApprovalRequired`], REFUSE.
/// 3. On grant match → return [`GatedResolveOutcome::Resolved`]. The CALLER
///    MUST then route to `stellar_pay_commit` with the per-action
///    `PaymentSimulated` approval FORCED ON UNCONDITIONALLY.
///
/// # Security
///
/// - All matching is computed from the AUTHORITATIVE envelope params in
///   `params` — NEVER from toolset-supplied args.
/// - A `DispatchOutcome::Allow` from the policy engine MUST be overridden to
///   `RequireApproval` by the caller for toolset-routed payments. This function
///   returns `GatedResolveOutcome::Resolved` to signal the path is open; the
///   unconditional per-action approval enforcement is the caller's responsibility.
/// - A tampered/forged grant can at worst suppress the first-invoke re-prompt;
///   it CANNOT bypass the forced per-action `PaymentSimulated` approval.
///
/// # Errors
///
/// - [`ToolsetRuntimeError::ToolsetNotInstalled`] — toolset not installed or
///   name fails charset validation.
/// - [`ToolsetRuntimeError::UnknownToolsetAction`] — action not in the gated matrix.
/// - [`ToolsetRuntimeError::CapabilityNotDeclared`] — `sign-payment` not declared.
/// - [`ToolsetRuntimeError::ToolNotAllowed`] — tool excluded by `allowed_tools`.
/// - [`ToolsetRuntimeError::GrantStoreError`] — I/O error accessing the grant store.
/// - [`ToolsetRuntimeError::Io`] — I/O error accessing the pending-approval store.
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
    let toolset_name = params.toolset_name;
    let action = params.action;

    // ── Step 0: Validate toolset_name charset ───────────────────────────────────
    stellar_agent_toolsets_install::validate_package_name(toolset_name).map_err(|_| {
        ToolsetRuntimeError::ToolsetNotInstalled {
            name: sanitise_display(toolset_name, 64),
        }
    })?;

    // ── Step 0b: Read pin ONCE (TOCTOU avoidance) ─────────────────────────────
    let pin = stellar_agent_toolsets_install::read_pin(toolset_name, params.toolsets_root)
        .map_err(|e| ToolsetRuntimeError::Io(install_error_kind_str(&e)))?
        .ok_or_else(|| ToolsetRuntimeError::ToolsetNotInstalled {
            name: sanitise_display(toolset_name, 64),
        })?;

    // ── Step 1: Gated four-part check ─────────────────────────────────────────
    //
    // Part (a): action must resolve in the GATED matrix (not the ungated one).
    // The gated matrix returns (tool_name, granting_capability) for sign-payment.
    let (tool_name, granting_capability) = resolve_gated_action(action)?;

    // Part (b): tool_name IS in the gated matrix by construction (implied by (a)).

    // Part (c): granting_capability must be in the toolset's declared CapabilitySet.
    if !pin.capabilities.contains(granting_capability) {
        return Err(ToolsetRuntimeError::CapabilityNotDeclared {
            action: sanitise_display(action, 128),
            capability: granting_capability.to_string(),
        });
    }

    // Part (d): tool must be in allowed_tools (intersective narrowing).
    if !allowed_by_narrowing(&pin.allowed_tools, tool_name) {
        return Err(ToolsetRuntimeError::ToolNotAllowed {
            tool: sanitise_display(tool_name, 128),
            action: sanitise_display(action, 128),
        });
    }

    // Reject non-positive authoritative amounts before ANY grant-store lookup.
    // A zero or negative amount from the decoded envelope is structurally invalid
    // for a payment. Checking here fails closed on BOTH the grant-hit and the
    // no-grant paths: a grant covering the [0, N] bucket would otherwise match a
    // zero-stroop invoke and resolve to the signing tool. The caller's
    // authoritative envelope decode is not trusted to have enforced positivity.
    let amount = params.authoritative_amount_stroops;
    if amount <= 0 {
        return Err(ToolsetRuntimeError::InvalidAuthoritativeAmount {
            amount_stroops: amount,
        });
    }

    // ── Step 2: First-invoke gate check ──────────────────────────────────────
    //
    // Load the grant store and look for a current, matching grant.
    // All matching is computed from the AUTHORITATIVE envelope params.
    let grant_store_path = {
        #[cfg(feature = "test-helpers")]
        {
            if let Some(ref p) = params.grant_store_path_override {
                p.clone()
            } else {
                default_toolset_grants_path(params.profile_name).map_err(|e| {
                    ToolsetRuntimeError::GrantStoreError {
                        detail: format!("grant_store_path: {e}"),
                    }
                })?
            }
        }
        #[cfg(not(feature = "test-helpers"))]
        {
            default_toolset_grants_path(params.profile_name).map_err(|e| {
                ToolsetRuntimeError::GrantStoreError {
                    detail: format!("grant_store_path: {e}"),
                }
            })?
        }
    };

    let grant_store =
        ToolsetGrantStore::open(grant_store_path, params.now_unix_ms).map_err(|e| {
            ToolsetRuntimeError::GrantStoreError {
                detail: format!("open: {e}"),
            }
        })?;

    let capability_str = granting_capability.to_string();
    let matching_grant = grant_store.find_matching(
        toolset_name,
        &capability_str,
        params.authoritative_destination,
        params.authoritative_asset,
        params.authoritative_amount_stroops,
        params.now_unix_ms,
    );

    if matching_grant.is_some() {
        // Grant found — the first-invoke gate is short-circuited.
        // The CALLER MUST force the per-action PaymentSimulated approval
        // unconditionally (Override Allow → RequireApproval).
        tracing::debug!(
            toolset = %toolset_name,
            capability = %capability_str,
            "first-invoke gate: matching grant found; routing to gated tool (per-action approval will be forced on by caller)"
        );
        return Ok(GatedResolveOutcome::Resolved { tool_name });
    }

    // ── No current grant: queue the first-invoke gate approval ───────────────
    // (Non-positive amounts were already rejected before the grant lookup.)

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
/// - [`ToolsetRuntimeError::GrantStoreError`] on grant store I/O failure.
#[allow(clippy::too_many_arguments)]
pub fn record_first_invoke_grant(
    profile_name: &str,
    toolset_name: &str,
    capability: &str,
    destination: &str,
    asset: &str,
    amount_min_stroops: i64,
    amount_max_stroops: i64,
    process_uid: &str,
    now_unix_ms: u64,
    attestation_key: &[u8; 32],
    // Optional override for the grant store path.
    // Pass `None` in production; `Some(path)` in integration tests.
    grant_store_path_override: GrantStorePathOverride,
) -> Result<ToolsetGrant, ToolsetRuntimeError> {
    let grant = build_attested_grant(
        toolset_name.to_owned(),
        capability.to_owned(),
        destination.to_owned(),
        asset.to_owned(),
        amount_min_stroops,
        amount_max_stroops,
        process_uid.to_owned(),
        now_unix_ms,
        TOOLSET_GRANT_DEFAULT_TTL_MS,
        attestation_key,
    )
    .map_err(|e| ToolsetRuntimeError::GrantStoreError {
        detail: format!("build_attested_grant: {e}"),
    })?;

    let grant_store_path = if let Some(p) = grant_store_path_override {
        p
    } else {
        default_toolset_grants_path(profile_name).map_err(|e| {
            ToolsetRuntimeError::GrantStoreError {
                detail: format!("grant_store_path: {e}"),
            }
        })?
    };

    let mut store = ToolsetGrantStore::open(grant_store_path, now_unix_ms).map_err(|e| {
        ToolsetRuntimeError::GrantStoreError {
            detail: format!("open: {e}"),
        }
    })?;

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
    Err(ToolsetRuntimeError::UnknownToolsetAction {
        action: sanitise_display(action, 128),
    })
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

/// Maps a [`stellar_agent_toolsets_install::ToolsetInstallError`] to a kind-level
/// I/O message string for use in [`ToolsetRuntimeError::Io`].
///
/// Uses `io::ErrorKind` level granularity to avoid leaking `toolsets_root`
/// through this conversion (a future path-annotating I/O error cannot reach
/// `ToolsetRuntimeError::Io` via this function).
fn install_error_kind_str(e: &stellar_agent_toolsets_install::ToolsetInstallError) -> String {
    // ToolsetInstallError already sanitises its Io variant internally, but we
    // want a fixed-class message not the full Display (which may embed detail).
    // For non-Io variants (PinRecordMalformed etc.) we use the variant name only.
    use stellar_agent_toolsets_install::ToolsetInstallError;
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
            matches!(err, ToolsetRuntimeError::UnknownToolsetAction { .. }),
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
                matches!(err, ToolsetRuntimeError::UnknownToolsetAction { .. }),
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
                matches!(err, ToolsetRuntimeError::UnknownToolsetAction { .. }),
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
        let list = list_pinned_toolsets(dir.path()).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn list_pinned_toolsets_nonexistent_dir() {
        let list =
            list_pinned_toolsets(std::path::Path::new("/nonexistent/toolsets_root")).unwrap();
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
        let err = resolve_toolset_and_check("../foo", "stellar_balances", dir.path()).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled { .. }),
            "expected ToolsetNotInstalled for '../foo', got: {err:?}"
        );
    }

    #[test]
    fn path_traversal_slash_in_name_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = resolve_toolset_and_check("a/b", "stellar_balances", dir.path()).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled { .. }),
            "expected ToolsetNotInstalled for 'a/b', got: {err:?}"
        );
    }

    #[test]
    fn path_traversal_backslash_in_name_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        // "..\\foo" on any platform: backslash is not in [a-z0-9-], so rejected.
        let err = resolve_toolset_and_check("..\\foo", "stellar_balances", dir.path()).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled { .. }),
            "expected ToolsetNotInstalled for '..\\\\foo', got: {err:?}"
        );
    }

    #[test]
    fn path_traversal_dotdot_alone_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = resolve_toolset_and_check("..", "stellar_balances", dir.path()).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled { .. }),
            "expected ToolsetNotInstalled for '..', got: {err:?}"
        );
    }

    #[test]
    fn path_traversal_dot_alone_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = resolve_toolset_and_check(".", "stellar_balances", dir.path()).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled { .. }),
            "expected ToolsetNotInstalled for '.', got: {err:?}"
        );
    }

    #[test]
    fn path_traversal_uppercase_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let err =
            resolve_toolset_and_check("MyToolset", "stellar_balances", dir.path()).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled { .. }),
            "expected ToolsetNotInstalled for 'MyToolset', got: {err:?}"
        );
    }

    #[test]
    fn path_traversal_null_byte_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let err =
            resolve_toolset_and_check("toolset\0name", "stellar_balances", dir.path()).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled { .. }),
            "expected ToolsetNotInstalled for null-byte name, got: {err:?}"
        );
    }

    // ── Dispatch-time TOOLSET.md content re-verification ───────────────────────
    //
    // Three scenarios:
    //
    //   (A) Pin has toolset_md_shasum; TOOLSET.md is unmodified → dispatch succeeds.
    //   (B) Pin has toolset_md_shasum; TOOLSET.md is tampered  → ContentDigestMismatch.
    //   (C) Pin has toolset_md_shasum = None (no digest stored) → check skipped.
    //
    // Setup: write a minimal valid TOOLSET.md + a hand-crafted pin record into a
    // tempdir.

    /// Writes a minimal valid `TOOLSET.md` to `<toolsets_root>/<pkg>/TOOLSET.md`.
    fn write_toolset_md(toolsets_root: &std::path::Path, pkg: &str, content: &str) {
        let toolset_dir = toolsets_root.join(pkg);
        std::fs::create_dir_all(&toolset_dir).unwrap();
        std::fs::write(toolset_dir.join("TOOLSET.md"), content).unwrap();
    }

    /// Writes a pin record JSON to `<toolsets_root>/<pkg>/.stellar-agent-toolset-pin.json`.
    fn write_pin_json(
        toolsets_root: &std::path::Path,
        pkg: &str,
        pin: &stellar_agent_toolsets_install::ToolsetPinRecord,
    ) {
        let json = serde_json::to_string_pretty(pin).unwrap();
        std::fs::write(
            toolsets_root
                .join(pkg)
                .join(".stellar-agent-toolset-pin.json"),
            json,
        )
        .unwrap();
    }

    /// Returns a minimal valid TOOLSET.md content string for package `pkg` with
    /// `read-balance` capability.
    fn minimal_toolset_md(pkg: &str) -> String {
        format!(
            "---\nname: {pkg}\ndescription: test toolset\nstellar-agent-capabilities:\n  - read-balance\n---\n# {pkg}\n"
        )
    }

    // ── (A) Unmodified TOOLSET.md with toolset_md_shasum → dispatches ────────────

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
            Some(expected_digest),
        );
        write_pin_json(toolsets_root, pkg, &pin);

        // Dispatch must succeed — TOOLSET.md is unmodified.
        let result = resolve_toolset_and_check(pkg, "stellar_balances", toolsets_root);
        assert!(
            result.is_ok(),
            "dispatch must succeed when TOOLSET.md digest matches pin: {result:?}"
        );
        let (tool_name, _) = result.unwrap();
        assert_eq!(tool_name, "stellar_balances");
    }

    // ── (B) Tampered TOOLSET.md with toolset_md_shasum → ContentDigestMismatch ──

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
            Some(original_digest),
        );
        write_pin_json(toolsets_root, pkg, &pin);

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
        let err = resolve_toolset_and_check(pkg, "stellar_balances", toolsets_root).unwrap_err();
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

    // ── (C) Legacy pin (toolset_md_shasum = None) → check skipped ─────────────

    #[test]
    fn legacy_pin_without_toolset_md_shasum_skips_content_check() {
        let dir = tempfile::TempDir::new().unwrap();
        let toolsets_root = dir.path();
        let pkg = "my-toolset";

        write_toolset_md(toolsets_root, pkg, &minimal_toolset_md(pkg));

        // Pin has no toolset_md_shasum.
        let caps = stellar_agent_toolsets::parse_capability_value_pub("read-balance").unwrap();
        let pin = stellar_agent_toolsets_install::ToolsetPinRecord::build_for_test(
            pkg,
            "1.0.0",
            "a".repeat(64),
            "GABC1234567890123456789012345678901234567890123456",
            "2026-06-12T00:00:00Z",
            caps,
            vec![],
            None,
        );
        write_pin_json(toolsets_root, pkg, &pin);

        // Dispatch must succeed even if TOOLSET.md was modified — pin has no
        // digest to compare against, so the check is skipped. The
        // capability-source invariant ensures capability escalation is still
        // impossible via the on-disk TOOLSET.md.
        let result = resolve_toolset_and_check(pkg, "stellar_balances", toolsets_root);
        assert!(
            result.is_ok(),
            "pin without toolset_md_shasum must skip content check and dispatch: {result:?}"
        );
    }

    // ── Missing TOOLSET.md when toolset_md_shasum is Some → ContentDigestMismatch

    #[test]
    fn missing_toolset_md_when_digest_expected_refuses_dispatch() {
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
            Some("a".repeat(64)),
        );
        write_pin_json(toolsets_root, pkg, &pin);

        // TOOLSET.md is missing — I/O error on read → fail-closed ContentDigestMismatch.
        let err = resolve_toolset_and_check(pkg, "stellar_balances", toolsets_root).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ContentDigestMismatch { .. }),
            "missing TOOLSET.md with digest in pin must refuse dispatch: {err:?}"
        );
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
                None,
            );
            write_pin_json(toolsets_root, pkg, &pin);
        }

        let list = list_pinned_toolsets(toolsets_root).unwrap();
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
            None,
        );
        write_pin_json(toolsets_root, "good-toolset", &pin);

        let list = list_pinned_toolsets(toolsets_root).unwrap();
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
            None,
        );
        write_pin_json(toolsets_root, pkg, &pin);

        let list = list_pinned_toolsets(toolsets_root).unwrap();
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
        let err =
            resolve_toolset_and_check("bad name", "stellar_balances", dir.path()).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled { .. }),
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
        let err =
            resolve_toolset_and_check("valid-name", "stellar_balances", dir.path()).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled { .. }),
            "expected ToolsetNotInstalled for a valid name with no pin record, got: {err:?}"
        );
    }

    // ── Gated resolver tests (require test-helpers feature for overrides) ─────

    /// Builds and writes a pin with `sign-payment` capability.
    #[cfg(feature = "test-helpers")]
    fn write_sign_payment_pin(toolsets_root: &std::path::Path, pkg: &str) {
        std::fs::create_dir_all(toolsets_root.join(pkg)).unwrap();
        let caps = stellar_agent_toolsets::parse_capability_value_pub("sign-payment").unwrap();
        let pin = stellar_agent_toolsets_install::ToolsetPinRecord::build_for_test(
            pkg,
            "1.0.0",
            "d".repeat(64),
            "GABC1234567890123456789012345678901234567890123456",
            "2026-06-12T00:00:00Z",
            caps,
            vec![],
            None,
        );
        write_pin_json(toolsets_root, pkg, &pin);
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
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: 10_000_000,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_dir.path().join("grants.json")),
        };

        let err = resolve_toolset_sign_payment_gated(&params).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled { .. }),
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
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: 10_000_000,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_dir.path().join("grants.json")),
        };

        let err = resolve_toolset_sign_payment_gated(&params).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::ToolsetNotInstalled { .. }),
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
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: 10_000_000,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_dir.path().join("grants.json")),
        };

        let err = resolve_toolset_sign_payment_gated(&params).unwrap_err();
        assert!(
            matches!(err, ToolsetRuntimeError::UnknownToolsetAction { .. }),
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
        let caps = stellar_agent_toolsets::parse_capability_value_pub("read-balance").unwrap();
        let pin = stellar_agent_toolsets_install::ToolsetPinRecord::build_for_test(
            "read-toolset",
            "1.0.0",
            "e".repeat(64),
            "GABC1234567890123456789012345678901234567890123456",
            "2026-06-12T00:00:00Z",
            caps,
            vec![],
            None,
        );
        std::fs::create_dir_all(toolsets_dir.path().join("read-toolset")).unwrap();
        write_pin_json(toolsets_dir.path(), "read-toolset", &pin);

        let params = GatedInvokeParams {
            toolset_name: "read-toolset",
            action: "stellar_pay_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: 10_000_000,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
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
        let caps = stellar_agent_toolsets::parse_capability_value_pub("sign-payment").unwrap();
        let pin = stellar_agent_toolsets_install::ToolsetPinRecord::build_for_test(
            "narrow-pay-toolset",
            "1.0.0",
            "f".repeat(64),
            "GABC1234567890123456789012345678901234567890123456",
            "2026-06-12T00:00:00Z",
            caps,
            vec!["some-other-tool".to_owned()],
            None,
        );
        std::fs::create_dir_all(toolsets_dir.path().join("narrow-pay-toolset")).unwrap();
        write_pin_json(toolsets_dir.path(), "narrow-pay-toolset", &pin);

        let params = GatedInvokeParams {
            toolset_name: "narrow-pay-toolset",
            action: "stellar_pay_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: 10_000_000,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
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
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: 10_000_000,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
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
        record_first_invoke_grant(
            "test",
            "pay-toolset",
            "sign-payment",
            destination,
            asset,
            0,
            amount_stroops,
            &uid,
            now_unix_ms,
            &attestation_key,
            Some(grant_path.clone()),
        )
        .unwrap();

        let params = GatedInvokeParams {
            toolset_name: "pay-toolset",
            action: "stellar_pay_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            authoritative_destination: destination,
            authoritative_asset: asset,
            authoritative_amount_stroops: amount_stroops,
            now_unix_ms,
            process_uid: &uid,
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_path),
        };

        let outcome = resolve_toolset_sign_payment_gated(&params).unwrap();
        match outcome {
            GatedResolveOutcome::Resolved { tool_name } => {
                assert_eq!(tool_name, "stellar_pay_commit");
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
        std::fs::create_dir_all(toolsets_root.join(pkg)).unwrap();
        let caps = stellar_agent_toolsets::parse_capability_value_pub("sign-rule-create").unwrap();
        let pin = stellar_agent_toolsets_install::ToolsetPinRecord::build_for_test(
            pkg,
            "1.0.0",
            "d".repeat(64),
            "GABC1234567890123456789012345678901234567890123456",
            "2026-06-12T00:00:00Z",
            caps,
            vec![],
            None,
        );
        write_pin_json(toolsets_root, pkg, &pin);
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
            authoritative_destination: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            authoritative_asset: SIGN_RULE_CREATE_ASSET_SENTINEL,
            authoritative_amount_stroops: SIGN_RULE_CREATE_AMOUNT_SENTINEL,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
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

        record_first_invoke_grant(
            "test",
            "rule-toolset",
            "sign-rule-create",
            smart_account,
            SIGN_RULE_CREATE_ASSET_SENTINEL,
            0,
            SIGN_RULE_CREATE_AMOUNT_SENTINEL,
            &uid,
            now_unix_ms,
            &attestation_key,
            Some(grant_path.clone()),
        )
        .unwrap();

        let params = GatedInvokeParams {
            toolset_name: "rule-toolset",
            action: "stellar_rule_create_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            authoritative_destination: smart_account,
            authoritative_asset: SIGN_RULE_CREATE_ASSET_SENTINEL,
            authoritative_amount_stroops: SIGN_RULE_CREATE_AMOUNT_SENTINEL,
            now_unix_ms,
            process_uid: &uid,
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_path),
        };

        let outcome = resolve_toolset_sign_payment_gated(&params).unwrap();
        match outcome {
            GatedResolveOutcome::Resolved { tool_name } => {
                assert_eq!(tool_name, "stellar_rule_create_commit");
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
        assert!(matches!(
            err,
            ToolsetRuntimeError::UnknownToolsetAction { .. }
        ));
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
            "sign-payment",
            destination,
            asset,
            0,
            10_000_000,
            &uid,
            now_unix_ms,
            &attestation_key,
            Some(grant_path.clone()),
        )
        .unwrap();

        let params = GatedInvokeParams {
            toolset_name: "pay-toolset",
            action: "stellar_pay_commit",
            toolsets_root: toolsets_dir.path(),
            profile_name: "test",
            authoritative_destination: destination,
            authoritative_asset: asset,
            authoritative_amount_stroops: 0,
            now_unix_ms,
            process_uid: &uid,
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_path),
        };

        let err = resolve_toolset_sign_payment_gated(&params).unwrap_err();
        assert!(
            matches!(
                err,
                ToolsetRuntimeError::InvalidAuthoritativeAmount { amount_stroops: 0 }
            ),
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
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: 0,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_dir.path().join("grants.json")),
        };

        let err = resolve_toolset_sign_payment_gated(&params).unwrap_err();
        assert!(
            matches!(
                err,
                ToolsetRuntimeError::InvalidAuthoritativeAmount { amount_stroops: 0 }
            ),
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
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: -1,
            now_unix_ms: 1_000_000,
            process_uid: "uid-test",
            approval_dir_override: Some(approval_dir.path().to_path_buf()),
            grant_store_path_override: Some(grant_dir.path().join("grants.json")),
        };

        let err = resolve_toolset_sign_payment_gated(&params).unwrap_err();
        assert!(
            matches!(
                err,
                ToolsetRuntimeError::InvalidAuthoritativeAmount { amount_stroops: -1 }
            ),
            "expected InvalidAuthoritativeAmount(-1), got: {err:?}"
        );
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
            authoritative_destination: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            authoritative_asset: "XLM",
            authoritative_amount_stroops: 10_000_000,
            now_unix_ms: 1_000_000,
            process_uid: supplied_uid,
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
            "sign-payment",
            destination,
            asset,
            0,
            grant_max_stroops,
            &uid,
            now_unix_ms,
            &attestation_key,
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
            authoritative_destination: destination,
            authoritative_asset: asset,
            authoritative_amount_stroops: over_max_stroops,
            now_unix_ms,
            process_uid: &uid,
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
            "prod",
            "my-toolset",
            "sign-payment",
            "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            "XLM",
            0,
            50_000_000,
            &uid,
            now_unix_ms,
            &attestation_key,
            Some(grant_path.clone()),
        )
        .unwrap();

        assert_eq!(grant.toolset_name, "my-toolset");
        assert_eq!(grant.capability, "sign-payment");

        // The security-load-bearing output is the HMAC attestation blob (the
        // grant store's matching does NOT verify it). Bind the test to that
        // cryptographic output: it must verify against the real key and be
        // rejected under a wrong key.
        assert!(
            grant.verify_attestation(&attestation_key),
            "grant must verify against the attestation key it was built with"
        );
        assert!(
            !grant.verify_attestation(&[0xff; 32]),
            "grant must NOT verify against a wrong attestation key"
        );

        // Re-open the store and verify the grant is persisted.
        let store =
            stellar_agent_core::approval::ToolsetGrantStore::open(grant_path, now_unix_ms).unwrap();
        let found = store.find_matching(
            "my-toolset",
            "sign-payment",
            "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            "XLM",
            30_000_000, // within [0, 50_000_000]
            now_unix_ms,
        );
        assert!(found.is_some(), "persisted grant must be findable in store");
    }
}
