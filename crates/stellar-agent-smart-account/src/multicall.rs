//! Multicall router invocation for the OZ smart-account bundle flow.
//!
//! # Surface
//!
//! - [`MULTICALL_WASM`] / [`MULTICALL_WASM_SHA256`] — vendored router WASM + pinned digest.
//! - [`MulticallRegistry`] — per-network address registry with binary-const trust-anchor
//!   enforcement at register, lookup, and load time.
//! - [`MulticallInvocation`] — typed description of a single inner call in a bundle.
//! - [`MulticallSubmitArgs`] — full argument set for [`submit_multicall_bundle`].
//! - [`MulticallResult`] / [`MulticallInnerResult`] — structured return values.
//! - [`submit_multicall_bundle`] — 8-step submit flow with policy gate + cross-RPC
//!   trust-anchor enforcement + audit emission.
//! - [`build_exec_invocations`] — pure XDR encoder for the router's `invocations` arg.
//! - `cross_rpc_compare_simulate_responses` / `cross_rpc_compare_wasm_hashes` — comparators
//!   consumed by the `submit_signed_invoke` Step 4 dispatch.
//! - [`classify_required_checks`] — returns `&["multicall"]` for host-functions
//!   targeting a registered multicall address; `&[]` otherwise.
//!
//! # Canonical-source citations
//!
//! The router contract's `invocations: Vec<(Address, Symbol, Vec<Val>)>` tuple shape
//! is cited from the Meridian Pay smart-wallet-demo-app router contract at SHA `8f4bfdc`
//! (`contracts/router/src/lib.rs`, `exec` function signature, lines 21-22).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hex;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sha2::{Digest as _, Sha256};
use stellar_xdr::{HostFunction, InvokeContractArgs, ScAddress, ScSymbol, ScVal, VecM};
use tracing::warn;

use stellar_agent_core::audit_log::AuditWriter;
use stellar_agent_core::audit_log::schema::EventKind;
use stellar_agent_core::observability::{RedactedStrkey, redact_strkey_first5_last5};
use stellar_agent_core::policy::v1::bundle::{BundleStateOverlay, BundleView, decompose_bundle};
use stellar_agent_core::policy::v1::{PolicyEngineV1, PolicyStateStore};
use stellar_agent_core::policy::{Decision, DenyReason};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::signing::Signer;

use crate::SaError;
use crate::error::PostSubmitVerificationKind;
use crate::managers::rules::parse_c_strkey_to_smart_account;
use crate::submit::{MulticallCheck, ResolvedFeePerOp, SubmitInvokeArgs, submit_signed_invoke};

// ── WASM provenance constants ─────────────────────────────────────────────────

/// Vendored multicall router WASM bytes.
///
/// Included at compile time from `vendor/multicall/v0.1.0/multicall.wasm`.
/// The build.rs gate (`crates/stellar-agent-smart-account/build.rs` `WASM_PINS`)
/// verifies the SHA-256 at compile time; this `include_bytes!` binding ships
/// the bytes into the binary for runtime deployment and runtime verification.
///
/// SHA-256 provenance: `vendor/multicall/v0.1.0/REFERENCE.md`.
/// Runtime defence-in-depth: `multicall_wasm_sha256_matches_provenance` test.
pub const MULTICALL_WASM: &[u8] = include_bytes!("../../../vendor/multicall/v0.1.0/multicall.wasm");

/// Expected SHA-256 of [`MULTICALL_WASM`], as 64-char lowercase hex.
///
/// This constant MUST equal the `expected_sha256` in
/// `crates/stellar-agent-smart-account/build.rs` `WASM_PINS` for the
/// `multicall.wasm` entry. A CI gate enforces byte-exact equality between
/// the two copies.
///
/// # Trust-anchor rotation
///
/// When the vendored WASM changes, BOTH this constant AND the matching
/// `build.rs` `WASM_PINS` entry MUST be updated atomically in the same commit.
/// The repo gate fails the build when they diverge.
pub const MULTICALL_WASM_SHA256: &str =
    "267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4";

// ── Bundle-size caps ──────────────────────────────────────────────────────────

/// Default maximum number of inner invocations in a multicall bundle.
///
/// A bundle with more than this many inners is rejected at Step 1 (build
/// validation) with `MulticallFailed { phase: "build" }` before any policy gate
/// or RPC round-trip.
///
/// The operator may register a LOWER cap via the `inner_invocation_count_cap`
/// policy criterion; they cannot raise above [`UPPER_BOUND_MULTICALL_BUNDLE_CAP`].
pub const MULTICALL_BUNDLE_CAP: u32 = 50;

/// Absolute ceiling for the multicall bundle size.
///
/// Matches OZ `MAX_SIGNERS × MAX_POLICIES = 75` storage-entry upper bound.
/// No policy configuration or CLI flag may raise the effective cap above this value.
pub const UPPER_BOUND_MULTICALL_BUNDLE_CAP: u32 = 75;

/// Compile-time invariant: the effective host-side cap MUST NOT exceed the
/// absolute amplification ceiling. A future refactor that raises
/// `MULTICALL_BUNDLE_CAP` above `UPPER_BOUND_MULTICALL_BUNDLE_CAP` would
/// fail this assertion at build time, surfacing the amplification-defence
/// violation immediately rather than at runtime.
const _: () = assert!(
    MULTICALL_BUNDLE_CAP <= UPPER_BOUND_MULTICALL_BUNDLE_CAP,
    "MULTICALL_BUNDLE_CAP must not exceed UPPER_BOUND_MULTICALL_BUNDLE_CAP \
     (amplification-defence ceiling)",
);

/// Phase inventory for `SaError::MulticallFailed::phase`.
///
/// Closed 7-value set. Every production emit site MUST use a string from this
/// set; a CI gate enforces that the closed set is not silently extended.
pub(crate) const MULTICALL_FAILED_PHASES: &[&str] = &[
    "build",
    "policy_gate",
    "rpc_divergence",
    "simulate",
    "sign",
    "submit",
    "post_submit_verification",
];

// ── Closed-set compile-time enforcement ──────────────────────────────────────

/// Compile-time size assertion: MULTICALL_FAILED_PHASES must have exactly 7 entries.
const _: () = {
    assert!(
        MULTICALL_FAILED_PHASES.len() == 7,
        "MULTICALL_FAILED_PHASES must have exactly 7 entries (closed set)"
    );
};

// ── MulticallInvocation ───────────────────────────────────────────────────────

/// A single inner invocation within a multicall bundle.
///
/// Caller-supplied before bundle validation. Each field is validated at
/// Step 1 (build) of [`submit_multicall_bundle`]: `target_contract` as a valid
/// C-strkey, `fn_name` as a valid Soroban symbol string (≤32 UTF-8 bytes,
/// no special characters), and `args_json` as a JSON value.
///
/// # Canonical source
///
/// The router contract's `invocations: Vec<(Address, Symbol, Vec<Val>)>` tuple
/// type is cited from the Meridian Pay smart-wallet-demo-app router contract
/// at SHA `8f4bfdc` (`contracts/router/src/lib.rs`, `exec` signature, lines 21-22).
#[derive(Debug, Clone)]
pub struct MulticallInvocation {
    /// C-strkey of the target contract to invoke.
    ///
    /// Validated at Step 1 via `stellar_strkey::Contract::from_string`.
    pub target_contract: String,
    /// Soroban symbol name of the function to call.
    ///
    /// Validated at Step 1 as ≤ 32 UTF-8 bytes with no special characters
    /// (Soroban symbol constraint per soroban-env-host).
    pub fn_name: String,
    /// JSON-encoded arguments for the function call.
    ///
    /// Step 1 validates that this is a JSON array; individual element shapes
    /// are not validated host-side (the router contract passes them directly
    /// as `Vec<Val>` to the target).
    pub args_json: serde_json::Value,
}

// ── MulticallSubmitArgs ───────────────────────────────────────────────────────

/// Arguments for [`submit_multicall_bundle`].
///
/// All fields are required; there are no optional defaults. The non-`Option`
/// `secondary_rpc_url` field enforces at the type level that the caller has
/// configured a secondary RPC endpoint — the cross-RPC 4-way trust-anchor
/// equality check requires it.
pub struct MulticallSubmitArgs<'a> {
    /// C-strkey of the smart-account contract executing the multicall.
    pub smart_account: &'a str,
    /// Context-rule ID under which the multicall is authorised.
    pub rule_id: u32,
    /// The ordered list of inner invocations to bundle atomically.
    ///
    /// Length must be in `[1, MULTICALL_BUNDLE_CAP]`; validated at Step 1.
    pub bundle: Vec<MulticallInvocation>,
    /// Signer for auth-entry construction and envelope signing.
    pub signer: &'a (dyn Signer + Send + Sync),
    /// Primary Soroban RPC URL (simulate + submit).
    pub primary_rpc_url: &'a str,
    /// Secondary Soroban RPC URL (mandatory for 4-way trust-anchor equality).
    ///
    /// Non-`Option` by design — a secondary RPC URL is unconditionally required
    /// for multicall submission (cross-RPC trust-anchor model).
    pub secondary_rpc_url: &'a str,
    /// Stellar network passphrase (auth-digest + envelope signing).
    pub network_passphrase: &'a str,
    /// Policy engine for per-inner + bundle-level gate evaluation at Step 2.
    pub policy_engine: Arc<PolicyEngineV1>,
    /// Active profile for policy evaluation.
    pub profile: &'a Profile,
    /// Optional audit writer for structured event emission.
    ///
    /// `None` disables audit emission; Step 4 sets `MulticallResult::audit_degraded = true`
    /// when `Some(writer)` is present but emission fails post-submit.
    pub audit_writer: Option<Arc<Mutex<AuditWriter>>>,
    /// Submission polling timeout.
    pub timeout: Duration,
    /// Per-operation base fee in stroops.
    pub fee: ResolvedFeePerOp,
    /// CAIP-2 chain identifier (e.g. `"stellar:testnet"`).
    pub chain_id: &'a str,
    /// Per-invocation UUIDv4 request correlation ID for audit log entries.
    ///
    /// Callers MUST generate a fresh `uuid::Uuid::new_v4().to_string()` per
    /// `submit_multicall_bundle` call.  All audit rows emitted in a single
    /// bundle submission share this `request_id` for forensic correlation.
    pub request_id: &'a str,
}

// ── MulticallResult ───────────────────────────────────────────────────────────

/// Outcome of a successful [`submit_multicall_bundle`] call.
///
/// `audit_degraded` is `true` when the bundle was submitted and confirmed
/// on-chain but the post-submit audit emission failed.  The caller should surface
/// this as a warning; the transaction itself landed and is irreversible.
#[derive(Debug)]
pub struct MulticallResult {
    /// Transaction hash of the confirmed multicall bundle (first-8-last-8 redacted form).
    pub bundle_tx_hash: String,
    /// Ledger sequence at which the bundle was confirmed.
    pub ledger: u32,
    /// Number of inner invocations in the bundle (matches `bundle.len()`).
    pub inner_count: u32,
    /// Per-inner return values parsed from the on-chain result.
    pub inner_results: Vec<MulticallInnerResult>,
    /// `true` when the bundle landed on-chain but audit emission failed post-submit.
    ///
    /// The transaction is irreversible; the caller SHOULD surface this as a
    /// `tracing::error!` and continue (not retry the submission).
    pub audit_degraded: bool,
}

/// Return value from a single inner invocation within a confirmed multicall bundle.
#[derive(Debug)]
pub struct MulticallInnerResult {
    /// Zero-based index of this inner within the bundle.
    pub inner_index: u32,
    /// C-strkey of the target contract (redacted first-5-last-5).
    pub target_contract: String,
    /// Function name that was called.
    pub fn_name: String,
    /// Base64-encoded `ScVal` return value from the router's result `Vec<Val>`.
    ///
    /// `None` when the return value is `Val::Void` or when base64 encoding fails.
    pub return_scval_b64: String,
}

// ── MulticallRegistry ─────────────────────────────────────────────────────────

/// Environment-variable name to override the networks.toml registry path.
///
/// When set to a non-empty path, `MulticallRegistry::load` uses that path
/// instead of the caller-supplied `config_path` argument.  This supports test
/// isolation (writing to a temp file instead of `~/.config/stellar-agent/networks.toml`)
/// and operator overrides for non-standard installation layouts.
///
/// # Example
///
/// ```sh
/// STELLAR_AGENT_NETWORKS_TOML=/tmp/my-networks.toml smart-account register-multicall ...
/// ```
pub const STELLAR_AGENT_MULTICALL_REGISTRY_TOML_ENV: &str = "STELLAR_AGENT_NETWORKS_TOML";

/// Per-network multicall router registry.
///
/// Maps network passphrases to deployed multicall router contract addresses and
/// their associated WASM SHA-256 fingerprints. Backed by
/// `~/.config/stellar-agent/networks.toml` (same file as `VerifierRegistry`;
/// each registry type owns its own `[multicall.<network_safename>]` section).
///
/// # Binary-const trust-anchor consistency
///
/// Three enforcement points:
/// 1. **Register-time**: `register` refuses `wasm_sha256 != MULTICALL_WASM_SHA256`.
/// 2. **Lookup-time**: `lookup` refuses stored `wasm_sha256 != MULTICALL_WASM_SHA256`.
/// 3. **Re-register drift**: existing entry with different SHA →
///    `SaError::MulticallSha256Drift`.
///
/// # Per-entry load tolerance
///
/// `load` skips malformed entries (bad C-strkey, bad hex SHA, non-canonical network)
/// and accumulates `RegistryLoadWarning` values in `partial_load_warnings` (capped
/// at 32 entries; per-warning text capped at 256 bytes). The whole load never fails
/// due to a single corrupted entry; operators can recover via
/// `smart-account unregister-multicall --force`.
///
/// # Thread safety
///
/// Not `Sync` — designed for single-operator CLI invocation.
///
#[derive(Debug)]
pub struct MulticallRegistry {
    entries: Vec<MulticallRegistryEntry>,
    config_path: PathBuf,
    /// Warnings accumulated during `load` for malformed entries.
    ///
    /// Capped at 32 entries; per-entry text capped at 256 bytes (truncated
    /// with `"..."` suffix). Callers inspect this after `load` to surface
    /// operator-facing diagnostics.
    pub partial_load_warnings: Vec<RegistryLoadWarning>,
}

/// A single network → multicall router mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MulticallRegistryEntry {
    /// Stellar network passphrase (canonical network identity).
    pub network_passphrase: String,
    /// Deployed multicall router contract C-strkey.
    ///
    /// Full C-strkey (56 characters, starting with `C`). Not redacted here;
    /// call sites that log this value apply
    /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
    pub address: String,
    /// SHA-256 of the vendored multicall WASM, as 64-char lowercase hex.
    ///
    /// Verified against `MULTICALL_WASM_SHA256` at register-time and
    /// lookup-time. Must equal `MULTICALL_WASM_SHA256` at both points.
    pub wasm_sha256: String,
}

/// Load-tolerance warning for a malformed registry entry.
///
/// Accumulated in [`MulticallRegistry::partial_load_warnings`] during `load`.
/// Text is capped at 256 bytes (truncated with `"..."` suffix).
#[derive(Debug, Clone)]
pub struct RegistryLoadWarning {
    /// Network safename (TOML section key; not the passphrase).
    pub network_safename: String,
    /// Human-readable reason the entry was skipped.
    ///
    /// Capped at 256 bytes; truncated with `"..."` suffix when longer.
    pub reason: String,
}

/// Raw on-disk TOML schema for multicall entries in `networks.toml`.
///
/// Parsed from `[multicall.<network_safename>]` sections.
#[derive(Debug, Default, Serialize, Deserialize)]
struct MulticallRegistryFile {
    /// Map from network safename (TOML table key) to entry.
    #[serde(default)]
    multicall: std::collections::HashMap<String, RawMulticallEntry>,
}

/// Per-network raw TOML entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawMulticallEntry {
    network_passphrase: String,
    address: String,
    wasm_sha256: String,
}

impl From<&MulticallRegistryEntry> for RawMulticallEntry {
    fn from(e: &MulticallRegistryEntry) -> Self {
        Self {
            network_passphrase: e.network_passphrase.clone(),
            address: e.address.clone(),
            wasm_sha256: e.wasm_sha256.clone(),
        }
    }
}

/// A raw unparsed registry entry returned by `unregister_force`.
///
/// Carries the raw string values from the on-disk TOML entry before any
/// strkey or hex validation. Used by the `--force` corruption-recovery path
/// in the CLI `unregister-multicall` command.
#[derive(Debug, Clone)]
pub struct RawEntry {
    /// Network safename (TOML section key).
    pub network_safename: String,
    /// Raw address string from TOML (may be invalid strkey).
    pub address: String,
    /// Raw wasm_sha256 string from TOML (may be invalid hex).
    pub wasm_sha256: String,
    /// Raw network passphrase from TOML.
    pub network_passphrase: String,
}

impl MulticallRegistry {
    /// Loads the registry from the given path or `STELLAR_AGENT_NETWORKS_TOML` override.
    ///
    /// Path resolution order:
    /// 1. If `STELLAR_AGENT_NETWORKS_TOML` is set in the process environment,
    ///    that path overrides `config_path`.
    /// 2. Otherwise, `config_path` is used.
    ///
    /// If the resolved file does not exist, returns an empty registry. Malformed
    /// entries are skipped and accumulated in `partial_load_warnings`; the load
    /// never fails due to a single corrupted entry.
    ///
    /// # Errors
    ///
    /// - `SaError::NetworksTomlIo` — file exists but cannot be read.
    /// - `SaError::NetworksTomlParse` — file exists but TOML is invalid.
    pub fn load(config_path: &Path) -> Result<Self, SaError> {
        // Honour the env-var override (test isolation + operator flexibility).
        // The const `STELLAR_AGENT_MULTICALL_REGISTRY_TOML_ENV` is the canonical
        // env-var name; rustdoc on the const describes this behaviour.
        let actual_path: std::borrow::Cow<'_, Path> =
            match std::env::var(STELLAR_AGENT_MULTICALL_REGISTRY_TOML_ENV) {
                Ok(override_str) if !override_str.is_empty() => {
                    std::borrow::Cow::Owned(PathBuf::from(override_str))
                }
                _ => std::borrow::Cow::Borrowed(config_path),
            };
        let actual_path: &Path = actual_path.as_ref();

        let mut registry = Self {
            entries: Vec::new(),
            config_path: actual_path.to_path_buf(),
            partial_load_warnings: Vec::new(),
        };

        if !actual_path.exists() {
            return Ok(registry);
        }

        let contents =
            std::fs::read_to_string(actual_path).map_err(|e| SaError::NetworksTomlIo {
                source: e,
                path: actual_path.to_path_buf(),
            })?;

        let file: MulticallRegistryFile =
            toml::from_str(&contents).map_err(|e| SaError::NetworksTomlParse {
                source: e,
                path: actual_path.to_path_buf(),
            })?;

        const WARNING_CAP: usize = 32;
        const WARNING_TEXT_CAP: usize = 256;

        for (safename, raw) in file.multicall {
            // Validate C-strkey address.
            if stellar_strkey::Contract::from_string(&raw.address).is_err() {
                if registry.partial_load_warnings.len() < WARNING_CAP {
                    registry.partial_load_warnings.push(RegistryLoadWarning {
                        network_safename: safename.clone(),
                        reason: truncate_warning(
                            &format!("invalid C-strkey address: {}", raw.address),
                            WARNING_TEXT_CAP,
                        ),
                    });
                }
                warn!(
                    network_safename = %safename,
                    "multicall registry: skipping entry with invalid C-strkey address"
                );
                continue;
            }

            // Validate hex SHA-256.
            if !is_valid_sha256_hex(&raw.wasm_sha256) {
                if registry.partial_load_warnings.len() < WARNING_CAP {
                    registry.partial_load_warnings.push(RegistryLoadWarning {
                        network_safename: safename.clone(),
                        reason: truncate_warning(
                            &format!("invalid SHA-256 hex: {}", raw.wasm_sha256),
                            WARNING_TEXT_CAP,
                        ),
                    });
                }
                warn!(
                    network_safename = %safename,
                    "multicall registry: skipping entry with invalid wasm_sha256 hex"
                );
                continue;
            }

            // Warn on SHA drift but still load (emits warning; lookup will refuse).
            if raw.wasm_sha256 != MULTICALL_WASM_SHA256 {
                if registry.partial_load_warnings.len() < WARNING_CAP {
                    registry.partial_load_warnings.push(RegistryLoadWarning {
                        network_safename: safename.clone(),
                        reason: truncate_warning(
                            &format!(
                                "wasm_sha256 {} != MULTICALL_WASM_SHA256 {}; \
                                 lookup will refuse (update wasm_sha256 after re-vendoring)",
                                &raw.wasm_sha256[..8.min(raw.wasm_sha256.len())],
                                &MULTICALL_WASM_SHA256[..8],
                            ),
                            WARNING_TEXT_CAP,
                        ),
                    });
                }
                warn!(
                    network_safename = %safename,
                    "multicall registry: entry wasm_sha256 does not match binary const; \
                     lookup will return MulticallSha256Drift"
                );
            }

            registry.entries.push(MulticallRegistryEntry {
                network_passphrase: raw.network_passphrase,
                address: raw.address,
                wasm_sha256: raw.wasm_sha256,
            });
        }

        Ok(registry)
    }

    /// Returns the registry entry for `network_passphrase`, or `None`.
    ///
    /// Returns `None` (not `Err`) when no entry is found. Returns
    /// `Err(SaError::MulticallSha256Drift)` when an entry exists but its
    /// `wasm_sha256` does not equal [`MULTICALL_WASM_SHA256`] — the entry is
    /// present but cannot be trusted.
    ///
    /// # Errors
    ///
    /// - `SaError::MulticallSha256Drift` — stored SHA differs from binary const.
    pub fn lookup(
        &self,
        network_passphrase: &str,
    ) -> Result<Option<&MulticallRegistryEntry>, SaError> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.network_passphrase == network_passphrase);

        let Some(entry) = entry else {
            return Ok(None);
        };

        if entry.wasm_sha256 != MULTICALL_WASM_SHA256 {
            return Err(SaError::MulticallSha256Drift {
                attempted: entry.wasm_sha256.clone(),
                expected: MULTICALL_WASM_SHA256.to_owned(),
                existing: Some(entry.wasm_sha256.clone()),
            });
        }

        Ok(Some(entry))
    }

    /// Registers a new multicall router entry for `entry.network_passphrase`.
    ///
    /// # Binary-const trust-anchor enforcement
    ///
    /// Refuses if `entry.wasm_sha256 != MULTICALL_WASM_SHA256` with
    /// `SaError::MulticallSha256Drift`. Refuses re-registration with a different
    /// SHA when an entry already exists.
    ///
    /// # Errors
    ///
    /// - `SaError::MulticallSha256Drift` — `entry.wasm_sha256` does not match
    ///   `MULTICALL_WASM_SHA256`, or an existing entry has a different SHA.
    pub fn register(&mut self, entry: MulticallRegistryEntry) -> Result<(), SaError> {
        // Binary-const trust-anchor enforcement at register-time.
        if entry.wasm_sha256 != MULTICALL_WASM_SHA256 {
            return Err(SaError::MulticallSha256Drift {
                attempted: entry.wasm_sha256.clone(),
                expected: MULTICALL_WASM_SHA256.to_owned(),
                existing: None,
            });
        }

        // Drift guard on re-register.
        if let Some(existing) = self
            .entries
            .iter()
            .find(|e| e.network_passphrase == entry.network_passphrase)
        {
            if existing.wasm_sha256 != entry.wasm_sha256 {
                return Err(SaError::MulticallSha256Drift {
                    attempted: entry.wasm_sha256.clone(),
                    expected: MULTICALL_WASM_SHA256.to_owned(),
                    existing: Some(existing.wasm_sha256.clone()),
                });
            }
            // Same SHA → idempotent; no mutation.
            return Ok(());
        }

        self.entries.push(entry);
        Ok(())
    }

    /// Removes and returns the registry entry for `network_passphrase`.
    ///
    /// # Errors
    ///
    /// - `SaError::MulticallRegistryEntryNotFound` when no entry exists for
    ///   `network_passphrase`.
    pub fn unregister(
        &mut self,
        network_passphrase: &str,
    ) -> Result<MulticallRegistryEntry, SaError> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.network_passphrase == network_passphrase)
            .ok_or_else(|| SaError::MulticallRegistryEntryNotFound {
                network_safename: network_passphrase.to_owned(),
            })?;
        Ok(self.entries.remove(idx))
    }

    /// Forcibly removes the entry identified by `network_safename` (TOML key),
    /// bypassing strkey/hex validation.
    ///
    /// This is the corruption-recovery path for `smart-account unregister-multicall
    /// --force`. It locates entries by `network_safename` (the TOML section key)
    /// rather than `network_passphrase`, and returns the raw string values before
    /// validation for forensic audit emission.
    ///
    /// # Errors
    ///
    /// - `SaError::MulticallRegistryEntryNotFound` when no entry exists with the
    ///   given safename. (The safename is matched as the section key used at load
    ///   time. For `unregister_force`, the caller passes the network safename as
    ///   stored in TOML, not the passphrase.)
    ///
    /// # Safety invariant
    ///
    /// This is a destructive recovery path. The `--force` path emits a
    /// `SaMulticallUnregisteredForce` audit row with raw (possibly invalid) values.
    pub fn unregister_force(&mut self, network_safename: &str) -> Result<RawEntry, SaError> {
        // For force-unregister, we match on the stored passphrase field containing
        // the safename as a prefix match heuristic, since the registry stores
        // passphrase not safename. When entries are not parseable, the passphrase
        // field carries the raw safename from the TOML section key.
        let idx = self
            .entries
            .iter()
            .position(|e| {
                network_safename_from_passphrase(&e.network_passphrase) == network_safename
                    || e.network_passphrase == network_safename
            })
            .ok_or_else(|| SaError::MulticallRegistryEntryNotFound {
                network_safename: network_safename.to_owned(),
            })?;
        let entry = self.entries.remove(idx);
        Ok(RawEntry {
            network_safename: network_safename.to_owned(),
            address: entry.address,
            wasm_sha256: entry.wasm_sha256,
            network_passphrase: entry.network_passphrase,
        })
    }

    /// Persists the registry to disk atomically.
    ///
    /// Writes to a sibling temp file in the same directory, then renames into
    /// place (intra-filesystem rename is atomic on POSIX). The parent directory
    /// is created with mode `0700`; the file is written with mode `0600` on POSIX.
    ///
    /// The file format merges with any existing `[multicall.*]` sections; existing
    /// non-multicall sections (e.g. `[networks.*]` from `VerifierRegistry`) are
    /// preserved when the TOML file is round-tripped.
    ///
    /// # Errors
    ///
    /// - `SaError::NetworksTomlIo` — any I/O failure.
    pub fn save(&self) -> Result<(), SaError> {
        let path = &self.config_path;

        // Ensure parent directory exists with restricted permissions.
        let parent = path.parent().ok_or_else(|| SaError::NetworksTomlIo {
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "registry path has no parent directory",
            ),
            path: path.clone(),
        })?;

        create_dir_0700(parent).map_err(|e| SaError::NetworksTomlIo {
            source: e,
            path: parent.to_path_buf(),
        })?;

        // Build the multicall section of the TOML file.
        let mut multicall_map = std::collections::HashMap::new();
        for entry in &self.entries {
            let safename = network_safename_from_passphrase(&entry.network_passphrase);
            multicall_map.insert(safename, RawMulticallEntry::from(entry));
        }
        let file = MulticallRegistryFile {
            multicall: multicall_map,
        };

        let toml_str = toml::to_string_pretty(&file).map_err(|e| SaError::NetworksTomlIo {
            source: std::io::Error::other(e.to_string()),
            path: path.clone(),
        })?;

        atomic_write_0600(path, toml_str.as_bytes()).map_err(|e| SaError::NetworksTomlIo {
            source: e,
            path: path.clone(),
        })?;

        Ok(())
    }

    /// Returns the config path this registry was loaded from (or will save to).
    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }
}

/// Adapter implementing `stellar_agent_core::profile::loader::MulticallRegistryHook`
/// so that `Profile::load_*` functions can refuse profiles registering a multicall
/// without providing a secondary RPC URL.
///
/// The trait-object hook pattern at
/// `crates/stellar-agent-core/src/profile/loader.rs` requires a `Send + Sync`
/// implementor that collapses both error and present-vs-absent into the trait's
/// binary `Option<()>` contract. Drift-class lookup errors are folded to `None`
/// (absent for hook purposes) because the loader's downstream guard cares only
/// about presence — the drift detection itself fires at `submit_multicall_bundle`
/// time via the binary-const consistency check.
impl stellar_agent_core::profile::loader::MulticallRegistryHook for MulticallRegistry {
    fn lookup(&self, network_passphrase: &str) -> Option<()> {
        match Self::lookup(self, network_passphrase) {
            Ok(Some(_)) => Some(()),
            Ok(None) | Err(_) => None,
        }
    }
}

// ── Cross-RPC comparators ─────────────────────────────────────────────────────

/// Enforces byte-exact equality between the four WASM hash sources.
///
/// The four sources are:
/// 1. `registry_sha256` — hex from the local `MulticallRegistry`.
/// 2. `primary_on_chain_hex` — hex returned by the primary RPC for the deployed contract.
/// 3. `secondary_on_chain_hex` — hex returned by the secondary RPC.
/// 4. [`MULTICALL_WASM_SHA256`] — the binary const compiled into the wallet.
///
/// All four must agree byte-exact.
///
/// Returns `Err(SaError::MulticallFailed { phase: "rpc_divergence", .. })` if
/// any pair disagrees. The error message identifies which leg diverged with
/// first-8-hex prefix of the observed hash (no full URL, no full hash).
pub(crate) fn cross_rpc_compare_wasm_hashes(
    registry_sha256: &str,
    primary_on_chain_hex: &str,
    secondary_on_chain_hex: &str,
) -> Result<(), SaError> {
    let expected = MULTICALL_WASM_SHA256;

    if registry_sha256 != expected {
        return Err(SaError::MulticallFailed {
            phase: "rpc_divergence",
            redacted_reason: format!(
                "registry leg reported {}; expected {}",
                &registry_sha256[..8.min(registry_sha256.len())],
                &expected[..8],
            ),
            post_submit_kind: None,
        });
    }

    if primary_on_chain_hex != expected {
        return Err(SaError::MulticallFailed {
            phase: "rpc_divergence",
            redacted_reason: format!(
                "primary-RPC leg reported {}; expected {}",
                &primary_on_chain_hex[..8.min(primary_on_chain_hex.len())],
                &expected[..8],
            ),
            post_submit_kind: None,
        });
    }

    if secondary_on_chain_hex != expected {
        return Err(SaError::MulticallFailed {
            phase: "rpc_divergence",
            redacted_reason: format!(
                "secondary-RPC leg reported {}; expected {}",
                &secondary_on_chain_hex[..8.min(secondary_on_chain_hex.len())],
                &expected[..8],
            ),
            post_submit_kind: None,
        });
    }

    Ok(())
}

// ── Step-4 dispatch helpers ───────────────────────────────────────────────────

/// Fetches the on-chain WASM hash for a deployed contract via an RPC endpoint.
///
/// Used by `submit.rs` Step 4 to obtain primary-RPC and secondary-RPC hashes
/// for the 4-way equality check.
///
/// Returns the WASM hash as a lowercase hex string, or
/// `SaError::MulticallFailed { phase: "rpc_divergence", .. }` on any RPC
/// failure.
///
/// # Canonical source
///
/// The `LedgerKeyContractData { key: ScVal::LedgerKeyContractInstance, ... }`
/// pattern is cited from
/// `crates/stellar-agent-smart-account/src/deployment/deploy.rs:1258-1265`
/// (local reference; mirrors the soroban-env-host `data_helper.rs` contract
/// instance lookup pattern).
///
/// Uses `stellar_rpc_client::Client` (not `stellar_agent_network::StellarRpcClient`)
/// to keep XDR type families consistent — both use the same stellar-xdr version
/// as the workspace, avoiding type-incompatibility at the `LedgerKey` site.
///
pub(crate) async fn fetch_wasm_hash_via_rpc(
    rpc_url: &str,
    contract_address: &str,
    timeout: std::time::Duration,
) -> Result<String, SaError> {
    use stellar_rpc_client::Client;
    use stellar_xdr::{
        ContractDataDurability, ContractExecutable, ContractId, Hash, LedgerEntryData, LedgerKey,
        LedgerKeyContractData, ReadXdr, ScAddress, ScVal,
    };

    let rpc_err = |detail: String| SaError::MulticallFailed {
        phase: "rpc_divergence",
        redacted_reason: detail,
        post_submit_kind: None,
    };

    let server = Client::new(rpc_url).map_err(|e| {
        rpc_err(format!(
            "Server construction failed for wasm-hash fetch: {e}"
        ))
    })?;

    // Parse the contract C-strkey to derive the ScAddress.
    let c_strkey = stellar_strkey::Contract::from_string(contract_address)
        .map_err(|e| rpc_err(format!("invalid multicall router address strkey: {e}")))?;
    let contract_scaddr = ScAddress::Contract(ContractId(Hash(c_strkey.0)));

    // Build the `ContractData { key: LedgerKeyContractInstance }` ledger key.
    // Mirrors deploy.rs:1258-1263 (local SHA).
    let instance_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: contract_scaddr,
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });

    let resp = tokio::time::timeout(timeout, server.get_ledger_entries(&[instance_key]))
        .await
        .map_err(|_| {
            rpc_err("get_ledger_entries timed out for contract instance fetch".to_owned())
        })?
        .map_err(|e| {
            rpc_err(format!(
                "get_ledger_entries failed for contract instance fetch: {e}"
            ))
        })?;

    let entries = resp.entries.unwrap_or_default();
    let entry = entries.first().ok_or_else(|| {
        rpc_err("RPC returned no contract-instance entry for multicall router address".to_owned())
    })?;

    // Decode the XDR from the LedgerEntryResult. stellar-rpc-client exposes
    // `entry.xdr: String` (base64); decode via LedgerEntryData::from_xdr_base64.
    let entry_data = LedgerEntryData::from_xdr_base64(
        &entry.xdr,
        stellar_agent_xdr_limits::untrusted_decode_limits(entry.xdr.len()),
    )
    .map_err(|_| rpc_err("RPC returned malformed ledger-entry XDR".to_owned()))?;

    let LedgerEntryData::ContractData(cd) = entry_data else {
        return Err(rpc_err("ledger entry was not ContractData".to_owned()));
    };

    let hash_bytes: [u8; 32] = match &cd.val {
        ScVal::ContractInstance(inst) => match &inst.executable {
            ContractExecutable::Wasm(Hash(b)) => *b,
            ContractExecutable::StellarAsset => {
                return Err(rpc_err(
                    "multicall router deployed as StellarAsset (not WASM)".to_owned(),
                ));
            }
        },
        _ => {
            return Err(rpc_err(
                "ContractData val was not ContractInstance".to_owned(),
            ));
        }
    };

    Ok(hex::encode(hash_bytes))
}

/// Compares primary vs secondary `SimulateTransactionResponse` for the multicall
/// cross-RPC trust-anchor check.
///
/// Called by `submit.rs` Step 4 after fetching the secondary simulation.
/// Compares:
///
/// 1. **`sub_invocations` auth-tree** — byte-exact via XDR serialization of the
///    auth entries returned by each RPC. A divergence here means one RPC is
///    trying to inject additional authorizations the caller did not request,
///    which is a rogue-RPC attack vector.
/// 2. **`transaction_data` (footprint)** — byte-exact via XDR serialization.
/// 3. **`min_resource_fee`** — within ±5% numeric tolerance.
///
/// The `latest_ledger` fields are deliberately NOT compared because the two RPCs
/// may be at different ledger heights.
///
/// Returns `Ok(())` on agreement; `Err(SaError::MulticallFailed { phase: "rpc_divergence" })`
/// on divergence.
pub(crate) fn cross_rpc_compare_simulate_responses(
    primary: &stellar_rpc_client::SimulateTransactionResponse,
    secondary: &stellar_rpc_client::SimulateTransactionResponse,
) -> Result<(), SaError> {
    use stellar_xdr::{Limits, WriteXdr};

    // ── Check 1: sub_invocations auth-tree byte-exact ────────────────────────
    //
    // `stellar_rpc_client::SimulateTransactionResponse::results` is
    // a private field. Access is through the public `results()` method which
    // returns `Result<Vec<SimulateHostFunctionResult>>`.
    //
    // A rogue primary RPC could return escalated sub_invocations (e.g. adding
    // extra `transfer` sub-invocations) that the wallet would blindly sign.
    // Byte-exact comparison between primary and secondary RPCs detects this.
    //
    // We serialize each `SorobanAuthorizationEntry` to XDR base64 via
    // `WriteXdr::to_xdr_base64` and sort before comparing to be insensitive to
    // entry ordering (both RPCs should return the same set).
    let primary_auth: Vec<String> = {
        let mut entries: Vec<String> = primary
            .results()
            .ok()
            .and_then(|results| results.into_iter().next())
            .map(|r| r.auth)
            .unwrap_or_default()
            .iter()
            .map(|entry| {
                entry
                    .to_xdr_base64(Limits::none())
                    .unwrap_or_else(|_| String::new())
            })
            .collect();
        entries.sort();
        entries
    };
    let secondary_auth: Vec<String> = {
        let mut entries: Vec<String> = secondary
            .results()
            .ok()
            .and_then(|results| results.into_iter().next())
            .map(|r| r.auth)
            .unwrap_or_default()
            .iter()
            .map(|entry| {
                entry
                    .to_xdr_base64(Limits::none())
                    .unwrap_or_else(|_| String::new())
            })
            .collect();
        entries.sort();
        entries
    };

    if primary_auth != secondary_auth {
        // Surface first-8 chars of each side's first auth-entry XDR for forensics.
        let p_prefix = primary_auth
            .first()
            .map(|s: &String| &s[..8_usize.min(s.len())])
            .unwrap_or("(empty)");
        let s_prefix = secondary_auth
            .first()
            .map(|s: &String| &s[..8_usize.min(s.len())])
            .unwrap_or("(empty)");
        return Err(SaError::MulticallFailed {
            phase: "rpc_divergence",
            redacted_reason: format!(
                "sub_invocations tree disagreement: primary {p_prefix}, secondary {s_prefix}"
            ),
            post_submit_kind: None,
        });
    }

    // ── Check 2: transaction_data (footprint) byte-exact ─────────────────────
    //
    // Both must be present (a None transaction_data indicates a simulate error,
    // which is caught before Step 4 by the panic-insulation pre-check in submit.rs).
    // transaction_data() returns Result<SorobanTransactionData>; convert to Option.
    let primary_td = primary.transaction_data().ok();
    let secondary_td = secondary.transaction_data().ok();

    match (primary_td, secondary_td) {
        (None, None) => {
            // Both returned no footprint — divergence check is irrelevant;
            // submit will fail at Step 6 when the footprint is absent.
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(SaError::MulticallFailed {
                phase: "rpc_divergence",
                redacted_reason:
                    "primary RPC returned transaction_data but secondary did not (or vice versa)"
                        .to_owned(),
                post_submit_kind: None,
            });
        }
        (Some(p_td), Some(s_td)) => {
            // Compare as XDR base64 strings.
            // `SorobanTransactionData::to_xdr_base64` is from stellar-baselib::xdr::WriteXdr.
            let p_xdr = p_td.to_xdr_base64(Limits::none()).unwrap_or_default();
            let s_xdr = s_td.to_xdr_base64(Limits::none()).unwrap_or_default();
            if p_xdr != s_xdr {
                return Err(SaError::MulticallFailed {
                    phase: "rpc_divergence",
                    redacted_reason:
                        "footprint (transaction_data) diverges between primary and secondary RPC"
                            .to_owned(),
                    post_submit_kind: None,
                });
            }
        }
    }

    // ── Check 3: min_resource_fee within ±5% numeric tolerance ───────────────
    // min_resource_fee is u64.
    let primary_fee = primary.min_resource_fee;
    let secondary_fee = secondary.min_resource_fee;

    check_numeric_tolerance("min_resource_fee", primary_fee, secondary_fee)?;

    Ok(())
}

// ── classify_required_checks ──────────────────────────────────────────────────

/// Returns the required checks slice for a given `HostFunction`.
///
/// Returns `&["multicall"]` when `host_function` targets a contract address
/// that is registered in `registry` for the active network. Returns `&[]` for
/// all other host-function shapes.
///
/// The discriminator lives here (in the multicall-aware module) rather than in
/// `submit.rs` because `submit.rs` is substrate-only and carries no knowledge
/// of `MulticallRegistry` semantics.
#[must_use]
pub fn classify_required_checks(
    host_function: &HostFunction,
    registry: &MulticallRegistry,
    network_passphrase: &str,
) -> &'static [&'static str] {
    let HostFunction::InvokeContract(inv) = host_function else {
        return &[];
    };

    let contract_strkey: String = match &inv.contract_address {
        ScAddress::Contract(id) => {
            // `stellar_strkey::Contract::to_string()` returns `heapless::String<56>`;
            // convert to `std::string::String` via `.as_str().to_owned()` so it is
            // comparable with `entry.address: String` (mirrors scaddress_to_strkey
            // pattern in rules.rs).
            stellar_strkey::Contract(id.0.0)
                .to_string()
                .as_str()
                .to_owned()
        }
        // Non-contract addresses are not multicall router targets; classify as empty.
        ScAddress::Account(_)
        | ScAddress::MuxedAccount(_)
        | ScAddress::ClaimableBalance(_)
        | ScAddress::LiquidityPool(_) => return &[],
    };

    // Check if the target contract is a registered multicall router.
    match registry.lookup(network_passphrase) {
        Ok(Some(entry)) if entry.address == contract_strkey => &["multicall"],
        _ => &[],
    }
}

// ── build_exec_invocations ────────────────────────────────────────────────────

/// Encodes a `Vec<MulticallInvocation>` into the XDR `ScVal` representation
/// required by the multicall router's `invocations` argument.
///
/// The router contract's `exec(caller, invocations: Vec<(Address, Symbol, Vec<Val>)>)`
/// signature is cited from the Meridian Pay smart-wallet-demo-app router at
/// SHA `8f4bfdc` (`contracts/router/src/lib.rs:21-22`).
///
/// Each `MulticallInvocation` becomes a `ScVal::Vec` containing three elements:
/// 1. `ScVal::Address` — the target contract address.
/// 2. `ScVal::Symbol` — the function name.
/// 3. `ScVal::Vec` — the function arguments as a `Vec<Val>`.
///
/// # Errors
///
/// - `SaError::MulticallFailed { phase: "build", .. }` on any XDR encoding
///   failure (invalid C-strkey, invalid symbol, argument encoding error).
pub fn build_exec_invocations(bundle: &[MulticallInvocation]) -> Result<Vec<ScVal>, SaError> {
    use stellar_xdr::{ContractId, Hash, ScAddress};

    let build_err = |reason: String| SaError::MulticallFailed {
        phase: "build",
        redacted_reason: reason,
        post_submit_kind: None,
    };

    let mut result = Vec::with_capacity(bundle.len());

    for (idx, invocation) in bundle.iter().enumerate() {
        // 1. Encode the contract address as ScVal::Address.
        let contract_strkey = stellar_strkey::Contract::from_string(&invocation.target_contract)
            .map_err(|e| {
                build_err(format!(
                    "inner[{idx}]: invalid target_contract C-strkey: {e}"
                ))
            })?;
        let contract_id = ContractId(Hash(contract_strkey.0));
        let address_val = ScVal::Address(ScAddress::Contract(contract_id));

        // 2. Encode the function name as ScVal::Symbol.
        let symbol_str = validate_soroban_symbol(&invocation.fn_name)
            .map_err(|e| build_err(format!("inner[{idx}]: invalid fn_name symbol: {e}")))?;
        let symbol_val =
            ScVal::Symbol(ScSymbol(symbol_str.as_bytes().try_into().map_err(
                |_| build_err(format!("inner[{idx}]: fn_name symbol encoding failed")),
            )?));

        // 3. Encode the JSON args as ScVal::Vec of ScVal elements.
        let args = json_args_to_scval_vec(&invocation.args_json, idx)
            .map_err(|e| build_err(format!("inner[{idx}]: args encoding failed: {e}")))?;

        // 4. Build the (Address, Symbol, Vec<Val>) tuple as a ScVal::Vec.
        let tuple_elements: VecM<ScVal> = vec![address_val, symbol_val, args]
            .try_into()
            .map_err(|_| build_err(format!("inner[{idx}]: tuple VecM encoding failed")))?;
        result.push(ScVal::Vec(Some(tuple_elements.into())));
    }

    Ok(result)
}

// ── submit_multicall_bundle ───────────────────────────────────────────────────

/// Submits a multicall bundle as a single signed `InvokeHostFunction` transaction.
///
/// # 8-step flow
///
/// 1. **build** — validate bundle size ∈ [1, `MULTICALL_BUNDLE_CAP`]; validate
///    each invocation shape (C-strkey target, symbol fn_name, JSON args). Fail-CLOSED
///    `MulticallFailed { phase: "build" }` + emit `SaMulticallBundleDenied`.
/// 2. **policy_gate** — decompose bundle via `decompose_bundle` → build `BundleView`
///    → call `policy_engine.evaluate_bundle`. On `Deny` → `MulticallFailed { phase: "policy_gate" }`
///    + emit `SaMulticallBundleDenied { denied_inner_index }`.
/// 3. **submit** — build `HostFunction` targeting the registered multicall address;
///    build `MulticallCheck`; call `submit_signed_invoke` with
///    `required_checks: &["multicall"]`. The free function performs wasm-hash pre-flight
///    + simulate + cross-RPC check + sign + submit + post-submit verification.
/// 4. **audit** — on `Ok`, emit `SaMulticallBundleSubmitted` + N
///    `SaMulticallInnerExecuted` rows. On failure, emit `SaMulticallBundleDenied`
///    with the appropriate `refusal_phase`.
///
/// # Errors
///
/// - `SaError::MulticallFailed { phase: "build", .. }` — bundle shape invalid.
/// - `SaError::MulticallFailed { phase: "policy_gate", .. }` — policy denied.
/// - `SaError::MulticallFailed { phase: "rpc_divergence", .. }` — cross-RPC check failed.
/// - `SaError::MulticallFailed { phase: "simulate", .. }` — RPC simulate error.
/// - `SaError::MulticallFailed { phase: "sign", .. }` — auth-entry signing error.
/// - `SaError::MulticallFailed { phase: "submit", .. }` — on-chain submission error.
/// - `SaError::MulticallFailed { phase: "post_submit_verification", .. }` — on-chain
///   result did not match the expected inner count.
/// - `SaError::MulticallRegistryEntryNotFound` — no multicall router registered for
///   `args.network_passphrase`.
///
/// # Audit-emission discipline
///
/// Audit emission is caller-side relative to `submit_signed_invoke`. This function emits
/// its OWN audit rows for the multicall-specific events after the free function returns.
pub async fn submit_multicall_bundle(
    args: MulticallSubmitArgs<'_>,
    registry: &MulticallRegistry,
) -> Result<MulticallResult, SaError> {
    let smart_account_redacted = redact_strkey_first5_last5(args.smart_account);

    // Warn when primary and secondary RPC URLs are identical. The trust-anchor
    // check degrades to single-RPC when both point to the same endpoint.
    if args.primary_rpc_url == args.secondary_rpc_url {
        warn!(
            smart_account = %smart_account_redacted,
            "submit_multicall_bundle: primary_rpc_url == secondary_rpc_url; \
             cross-RPC trust-anchor degrades to single-RPC verification"
        );
    }

    // Helper: emit a denied audit row.
    let chain_id = args.chain_id;
    let request_id = args.request_id;
    let emit_denied = |writer: &Option<Arc<Mutex<AuditWriter>>>,
                       denied_inner_index: Option<u32>,
                       observed_inner_count: Option<u32>,
                       bundle_tx_hash_redacted: Option<String>,
                       deny_wire_code: String,
                       refusal_phase: &str,
                       inner_count: u32| {
        emit_audit_event(
            writer,
            EventKind::SaMulticallBundleDenied {
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted.clone(),
                ),
                rule_id: args.rule_id,
                inner_count,
                denied_inner_index,
                observed_inner_count,
                deny_wire_code,
                refusal_phase: refusal_phase.to_owned(),
                bundle_tx_hash_redacted,
            },
            chain_id,
            request_id,
        )
    };

    // ── Step 1: build validation ──────────────────────────────────────────────

    let inner_count = u32::try_from(args.bundle.len()).unwrap_or(u32::MAX);

    if args.bundle.is_empty() {
        let _ = emit_denied(
            &args.audit_writer,
            None,
            None,
            None,
            "multicall.bundle_empty".to_owned(),
            "build",
            0,
        );
        return Err(SaError::MulticallFailed {
            phase: "build",
            redacted_reason: "bundle must contain at least 1 invocation".to_owned(),
            post_submit_kind: None,
        });
    }

    if args.bundle.len() > MULTICALL_BUNDLE_CAP as usize {
        let _ = emit_denied(
            &args.audit_writer,
            None,
            None,
            None,
            "multicall.bundle_too_large".to_owned(),
            "build",
            inner_count,
        );
        return Err(SaError::MulticallFailed {
            phase: "build",
            redacted_reason: format!(
                "bundle length {} exceeds MULTICALL_BUNDLE_CAP {}",
                args.bundle.len(),
                MULTICALL_BUNDLE_CAP,
            ),
            post_submit_kind: None,
        });
    }

    // Per-invocation shape validation.
    for (idx, inv) in args.bundle.iter().enumerate() {
        if stellar_strkey::Contract::from_string(&inv.target_contract).is_err() {
            let _ = emit_denied(
                &args.audit_writer,
                Some(u32::try_from(idx).unwrap_or(u32::MAX)),
                None,
                None,
                "multicall.invalid_target_contract".to_owned(),
                "build",
                inner_count,
            );
            return Err(SaError::MulticallFailed {
                phase: "build",
                redacted_reason: format!("inner[{idx}]: invalid C-strkey target_contract"),
                post_submit_kind: None,
            });
        }
        if validate_soroban_symbol(&inv.fn_name).is_err() {
            let _ = emit_denied(
                &args.audit_writer,
                Some(u32::try_from(idx).unwrap_or(u32::MAX)),
                None,
                None,
                "multicall.invalid_fn_name".to_owned(),
                "build",
                inner_count,
            );
            return Err(SaError::MulticallFailed {
                phase: "build",
                redacted_reason: format!(
                    "inner[{idx}]: fn_name '{}' is not a valid Soroban symbol",
                    inv.fn_name
                ),
                post_submit_kind: None,
            });
        }
        if !inv.args_json.is_array() && !inv.args_json.is_null() {
            let _ = emit_denied(
                &args.audit_writer,
                Some(u32::try_from(idx).unwrap_or(u32::MAX)),
                None,
                None,
                "multicall.invalid_args_json".to_owned(),
                "build",
                inner_count,
            );
            return Err(SaError::MulticallFailed {
                phase: "build",
                redacted_reason: format!("inner[{idx}]: args_json must be a JSON array or null"),
                post_submit_kind: None,
            });
        }
    }

    // ── Step 2: policy gate ───────────────────────────────────────────────────

    // Decompose bundle into typed descriptors for policy evaluation.
    let raw_bundle: Vec<(String, String, Vec<serde_json::Value>)> = args
        .bundle
        .iter()
        .map(|inv| {
            let args_vec = if let Some(arr) = inv.args_json.as_array() {
                arr.clone()
            } else {
                Vec::new()
            };
            (inv.target_contract.clone(), inv.fn_name.clone(), args_vec)
        })
        .collect();

    let descriptors = decompose_bundle(&raw_bundle);

    let overlay = BundleStateOverlay::default();
    let bundle_view = BundleView {
        inners: &descriptors,
        overlay: &overlay,
    };

    // Build a synthetic ToolDescriptor for multicall.
    use stellar_agent_core::policy::{McpToolRegistration, ToolDescriptor};
    let tool_reg = McpToolRegistration {
        name: "wallet_multicall",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
    };
    let tool = ToolDescriptor::from_registration(&tool_reg);
    let eval_args = serde_json::json!({
        "smart_account": args.smart_account,
        "rule_id": args.rule_id,
    });
    let state_store = PolicyStateStore::new();

    let policy_decision = args
        .policy_engine
        .evaluate_bundle(&tool, &eval_args, args.profile, &bundle_view)
        .map_err(|e| SaError::MulticallFailed {
            phase: "policy_gate",
            redacted_reason: format!("policy engine error: {e}"),
            post_submit_kind: None,
        })?;

    if let Decision::Deny(ref deny_reason) = policy_decision {
        let (denied_inner_index, deny_wire_code) = match deny_reason {
            DenyReason::BundleDenied {
                inner_index,
                deny_reason,
            } => (
                Some(*inner_index),
                format!("multicall.{}", deny_reason_wire_code(deny_reason)),
            ),
            other => (None, format!("multicall.{}", deny_reason_wire_code(other))),
        };

        let _ = emit_denied(
            &args.audit_writer,
            denied_inner_index,
            None,
            None,
            deny_wire_code,
            "policy_gate",
            inner_count,
        );

        return Err(SaError::MulticallFailed {
            phase: "policy_gate",
            redacted_reason: "policy denied the multicall bundle".to_owned(),
            post_submit_kind: None,
        });
    }
    drop(state_store);

    // ── Step 3: submit via free function ─────────────────────────────────────

    // Look up the registered multicall router address for this network.
    let registry_entry = registry.lookup(args.network_passphrase)?.ok_or_else(|| {
        SaError::MulticallRegistryEntryNotFound {
            network_safename: network_safename_from_passphrase(args.network_passphrase),
        }
    })?;

    // Build the exec invocations XDR arg.
    let exec_invocations_xdr = build_exec_invocations(&args.bundle)?;

    // Build the InvokeContractArgs for the router's `exec` function.
    let exec_invocations_scval: VecM<ScVal> =
        exec_invocations_xdr
            .try_into()
            .map_err(|_| SaError::MulticallFailed {
                phase: "build",
                redacted_reason: "exec invocations VecM encoding failed".to_owned(),
                post_submit_kind: None,
            })?;

    // Caller address (smart_account).
    let caller_scaddr = parse_c_strkey_to_smart_account(args.smart_account)?;
    let caller_scval = ScVal::Address(caller_scaddr);

    // Build the args for `exec(caller, invocations)`.
    let all_args: VecM<ScVal> = vec![
        caller_scval,
        ScVal::Vec(Some(exec_invocations_scval.into())),
    ]
    .try_into()
    .map_err(|_| SaError::MulticallFailed {
        phase: "build",
        redacted_reason: "exec all_args VecM encoding failed".to_owned(),
        post_submit_kind: None,
    })?;

    // Parse the router contract address.
    let router_contract =
        stellar_strkey::Contract::from_string(&registry_entry.address).map_err(|e| {
            SaError::MulticallFailed {
                phase: "build",
                redacted_reason: format!("invalid registry address strkey: {e}"),
                post_submit_kind: None,
            }
        })?;

    use stellar_xdr::{ContractId, Hash};
    let router_scaddr = ScAddress::Contract(ContractId(Hash(router_contract.0)));

    let invoke_args = InvokeContractArgs {
        contract_address: router_scaddr,
        function_name: ScSymbol(b"exec".as_slice().try_into().map_err(|_| {
            SaError::MulticallFailed {
                phase: "build",
                redacted_reason: "exec symbol encoding failed".to_owned(),
                post_submit_kind: None,
            }
        })?),
        args: all_args,
    };

    let host_function = HostFunction::InvokeContract(invoke_args);

    // Build the MulticallCheck for the submit path.
    let multicall_check = MulticallCheck {
        bundle_descriptors: descriptors,
        registry_entry_address: registry_entry.address.clone(),
        registry_entry_wasm_sha256: registry_entry.wasm_sha256.clone(),
        network_passphrase: args.network_passphrase.to_owned(),
    };

    use stellar_agent_core::smart_account::rule_id::ContextRuleId;
    let rule_id = ContextRuleId::from(args.rule_id);
    let auth_rule_ids = vec![rule_id];

    let submit_result = submit_signed_invoke(
        SubmitInvokeArgs::builder()
            .target_contract(args.smart_account)
            .auth_rule_ids(&auth_rule_ids)
            .host_function(host_function)
            .signer(args.signer)
            .primary_rpc_url(args.primary_rpc_url)
            .secondary_rpc_url(args.secondary_rpc_url)
            .network_passphrase(args.network_passphrase)
            .chain_id(args.chain_id)
            .timeout(args.timeout)
            .fee(args.fee)
            .op_label("multicall_bundle")
            .emit_observability_logs(true)
            .required_checks(&["multicall"])
            .multicall_check(multicall_check)
            .build(),
    )
    .await;

    // ── Step 4: audit ─────────────────────────────────────────────────────────

    match submit_result {
        Err(ref sa_err) => {
            // Map SaError to a MulticallFailed phase.
            let phase = map_sa_error_to_multicall_phase(sa_err);
            let deny_wire_code = format!("multicall.{}", sa_err.wire_code());

            let _ = emit_denied(
                &args.audit_writer,
                None,
                None,
                None,
                deny_wire_code,
                phase,
                inner_count,
            );

            Err(SaError::MulticallFailed {
                phase,
                redacted_reason: format!("submit error: {}", sa_err.wire_code()),
                post_submit_kind: None,
            })
        }
        Ok(submit_ok) => {
            // Redact the real transaction hash to first-8-last-8 before logging or emitting.
            let bundle_tx_hash_redacted = stellar_agent_network::redact_tx_hash(&submit_ok.tx_hash);

            // Build inner results from the on-chain return value.
            // The router returns a Vec<Val> with one entry per inner in bundle order.
            // Failure here means the bundle landed on-chain but the post-submit
            // verification detected a shape anomaly — emit a denied row and return.
            let inner_results = match build_inner_results(
                &args.bundle,
                &submit_ok.return_val,
                &bundle_tx_hash_redacted,
            ) {
                Ok(results) => results,
                Err(sa_err) => {
                    // Router return value was malformed or inner-count mismatched.
                    // Use the typed post-submit discriminator for audit routing.
                    let (deny_wire_code, observed_inner_count) = match sa_err {
                        SaError::MulticallFailed {
                            post_submit_kind:
                                Some(PostSubmitVerificationKind::InnerCountMismatch {
                                    observed_inner_count,
                                }),
                            ..
                        } => (
                            "multicall.post_submit_inner_count_mismatch".to_owned(),
                            Some(observed_inner_count),
                        ),
                        SaError::MulticallFailed {
                            post_submit_kind:
                                Some(
                                    PostSubmitVerificationKind::XdrEmptyVec
                                    | PostSubmitVerificationKind::XdrUnexpectedShape { .. },
                                )
                                | None,
                            ..
                        } => ("multicall.post_submit_xdr_parse_failed".to_owned(), None),
                        _ => ("multicall.post_submit_xdr_parse_failed".to_owned(), None),
                    };

                    let _ = emit_denied(
                        &args.audit_writer,
                        None,
                        observed_inner_count,
                        Some(bundle_tx_hash_redacted.clone()),
                        deny_wire_code,
                        "post_submit_verification",
                        inner_count,
                    );
                    return Err(sa_err);
                }
            };

            let mut audit_degraded = false;

            // Emit parent row.
            let parent_ok = emit_audit_event(
                &args.audit_writer,
                EventKind::SaMulticallBundleSubmitted {
                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                        smart_account_redacted.clone(),
                    ),
                    rule_id: args.rule_id,
                    bundle_tx_hash_redacted: bundle_tx_hash_redacted.clone(),
                    inner_count,
                },
                chain_id,
                request_id,
            );
            if parent_ok.is_err() {
                audit_degraded = true;
            }

            // Emit per-inner rows.
            for inner in &inner_results {
                let row_ok = emit_audit_event(
                    &args.audit_writer,
                    EventKind::SaMulticallInnerExecuted {
                        bundle_tx_hash_redacted: bundle_tx_hash_redacted.clone(),
                        inner_index: inner.inner_index,
                        target_contract_redacted: RedactedStrkey::from_full(&inner.target_contract),
                        fn_name: inner.fn_name.clone(),
                        return_scval_b64_prefix: if inner.return_scval_b64.is_empty() {
                            None
                        } else {
                            Some(
                                inner.return_scval_b64[..32.min(inner.return_scval_b64.len())]
                                    .to_owned(),
                            )
                        },
                    },
                    chain_id,
                    request_id,
                );
                if row_ok.is_err() {
                    audit_degraded = true;
                }
            }

            if audit_degraded {
                tracing::error!(
                    smart_account = %smart_account_redacted,
                    rule_id = args.rule_id,
                    "multicall: audit emission failed post-submit (bundle landed on-chain)"
                );
            }

            Ok(MulticallResult {
                bundle_tx_hash: bundle_tx_hash_redacted,
                ledger: submit_ok.ledger,
                inner_count,
                inner_results,
                audit_degraded,
            })
        }
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Validates that `s` is a valid Soroban symbol string (≤ 32 bytes, alphanumeric
/// or `_`).
///
/// Returns `Ok(&str)` on success, `Err(String)` describing the violation.
fn validate_soroban_symbol(s: &str) -> Result<&str, String> {
    if s.is_empty() {
        return Err("symbol must not be empty".to_owned());
    }
    if s.len() > 32 {
        return Err(format!(
            "symbol '{}' exceeds 32-byte Soroban limit",
            &s[..32.min(s.len())]
        ));
    }
    for c in s.chars() {
        if !c.is_ascii_alphanumeric() && c != '_' {
            return Err(format!("symbol contains invalid character '{c}'"));
        }
    }
    Ok(s)
}

/// Converts JSON arguments to a `ScVal::Vec`.
///
/// Supported JSON element shapes and their `ScVal` mappings:
///
/// | JSON shape | Condition | `ScVal` result |
/// |------------|-----------|----------------|
/// | `Number` (non-negative, fits u64) | `as_u64()` succeeds | `I128(Int128Parts { hi: 0, lo: v })` |
/// | `Number` (negative, fits i64) | `as_i64()` succeeds and value is negative | `I128(Int128Parts { hi: -1, lo: v as u64 })` (sign-extended) |
/// | `String` | — | `ScVal::String` |
/// | `Null` | (empty args list sentinel) | produces empty `Vec<Val>` |
/// | `Array` | (only at top level; NOT nested) | the elements of the array |
/// | Any other shape (bool, object, nested array) | — | **explicit error** |
///
/// Non-primitive JSON shapes are rejected with an explicit error rather than
/// silently converting to `ScVal::Void`. The router passes arguments directly
/// as `Vec<Val>` to the target contract; a `Void` from a caller-supplied
/// `true` or `{ "key": "val" }` would produce an incorrect invocation
/// that the target contract cannot decode.
///
/// # Negative integer encoding
///
/// Soroban `I128` encodes sign via two's-complement 128-bit split:
/// - Non-negative `v` (0 ≤ v ≤ i64::MAX): `hi = 0`, `lo = v as u64`.
/// - Negative `v` (i64::MIN ≤ v < 0): `hi = -1` (all-1-bits high word),
///   `lo = v as u64` (two's complement bit pattern).
///
/// This matches the `Int128Parts` encoding in `soroban-env-common`.
///
/// # Errors
///
/// Returns a description string on encoding failure or unsupported JSON shape.
fn json_args_to_scval_vec(args_json: &serde_json::Value, idx: usize) -> Result<ScVal, String> {
    use stellar_xdr::{Int128Parts, ScString};

    let arr = match args_json {
        serde_json::Value::Array(a) => a.clone(),
        serde_json::Value::Null => Vec::new(),
        _ => {
            return Err(format!("inner[{idx}] args_json is not an array"));
        }
    };

    let mut elements: Vec<ScVal> = Vec::with_capacity(arr.len());
    for (elem_idx, elem) in arr.iter().enumerate() {
        let scval = match elem {
            serde_json::Value::Number(n) => {
                // Prefer u64 path for non-negative numbers (avoids i64 sign truncation
                // for values in (i64::MAX, u64::MAX]).
                if let Some(v) = n.as_u64() {
                    ScVal::I128(Int128Parts { hi: 0, lo: v })
                } else if let Some(v) = n.as_i64() {
                    // Negative value: sign-extend to 128-bit two's complement.
                    // hi = -1 (all 1-bits) when v < 0; lo = v as u64 (bit pattern).
                    // Canonical source: soroban-env-common `val.rs` Int128Parts encoding.
                    ScVal::I128(Int128Parts {
                        hi: -1_i64,
                        lo: v as u64,
                    })
                } else {
                    return Err(format!(
                        "inner[{idx}] arg[{elem_idx}]: numeric value out of i64/u64 range"
                    ));
                }
            }
            serde_json::Value::String(s) => {
                ScVal::String(ScString(s.as_bytes().try_into().map_err(|_| {
                    format!("inner[{idx}] arg[{elem_idx}]: string arg too long")
                })?))
            }
            serde_json::Value::Bool(_)
            | serde_json::Value::Object(_)
            | serde_json::Value::Array(_) => {
                // Non-primitive JSON shapes are explicitly refused.  The caller
                // must encode complex args as pre-serialised XDR base64 strings
                // or decompose them into scalar fields before passing to this API.
                let kind = match elem {
                    serde_json::Value::Bool(_) => "Bool",
                    serde_json::Value::Object(_) => "Object",
                    serde_json::Value::Array(_) => "Array (nested)",
                    _ => "unknown",
                };
                return Err(format!(
                    "inner[{idx}] arg[{elem_idx}]: unsupported JSON argument shape '{kind}'; \
                     encode complex args as pre-serialised XDR base64 strings"
                ));
            }
            serde_json::Value::Null => {
                // Null at argument level is encoded as Void.  Distinct from null
                // at the top-level (which signals an empty args list).
                ScVal::Void
            }
        };
        elements.push(scval);
    }

    let vecm: VecM<ScVal> = elements
        .try_into()
        .map_err(|_| format!("inner[{idx}] args VecM encoding failed"))?;

    Ok(ScVal::Vec(Some(vecm.into())))
}

/// Builds `MulticallInnerResult` values from the confirmed on-chain return value.
///
/// The multicall router returns `ScVal::Vec(Some(VecM))` where each element is
/// the per-inner return value in bundle order. Canonical source: the Meridian Pay
/// smart-wallet-demo-app router at SHA `8f4bfdc` (`contracts/router/src/lib.rs`,
/// lines 35-40) — `exec` collects inner results into a `Vec<Val>` and returns
/// it as a Soroban `Vec<Val>`.
///
/// # Errors
///
/// Returns `Err(SaError::MulticallFailed { phase: "post_submit_verification", .. })` when:
/// - `return_val` is not `ScVal::Vec(Some(_))` (XDR parse failure / unexpected shape).
/// - The parsed vector length does not equal `bundle.len()` (inner-count mismatch).
///
/// On success, returns `Ok((redacted_tx_hash, inner_results))`.
fn build_inner_results(
    bundle: &[MulticallInvocation],
    return_val: &ScVal,
    // `bundle_tx_hash_redacted` is embedded in inner-result rows for auditability.
    bundle_tx_hash_redacted: &str,
) -> Result<Vec<MulticallInnerResult>, SaError> {
    use stellar_xdr::{Limits, WriteXdr};

    let post_verify_err =
        |reason: String, kind: PostSubmitVerificationKind| SaError::MulticallFailed {
            phase: "post_submit_verification",
            redacted_reason: reason,
            post_submit_kind: Some(kind),
        };

    // Emit at trace level for post-submit auditability (tx_hash is already
    // redacted to first-8-last-8 by the caller before reaching here).
    tracing::trace!(
        bundle_tx_hash_redacted = %bundle_tx_hash_redacted,
        "post_submit_verification: parsing router return value"
    );

    // The router returns ScVal::Vec(Some(VecM)) with one element per inner.
    let parsed: Vec<ScVal> = match return_val {
        ScVal::Vec(Some(vecm)) => vecm.to_vec(),
        ScVal::Vec(None) => {
            return Err(post_verify_err(
                "router return value is ScVal::Vec(None) — expected non-empty Vec".to_owned(),
                PostSubmitVerificationKind::XdrEmptyVec,
            ));
        }
        other => {
            let observed_discriminant = scval_discriminant_name(other);
            return Err(post_verify_err(
                format!(
                    "router return value is not ScVal::Vec; got discriminant {}",
                    observed_discriminant
                ),
                PostSubmitVerificationKind::XdrUnexpectedShape {
                    observed_discriminant,
                },
            ));
        }
    };

    // Inner-count must equal the submitted bundle length.
    if parsed.len() != bundle.len() {
        return Err(post_verify_err(
            format!(
                "inner-count mismatch: bundle={}, on-chain={}",
                bundle.len(),
                parsed.len()
            ),
            PostSubmitVerificationKind::InnerCountMismatch {
                observed_inner_count: u32::try_from(parsed.len()).unwrap_or(u32::MAX),
            },
        ));
    }

    // Build per-inner result rows.
    let mut results = Vec::with_capacity(bundle.len());
    for (idx, (inv, inner_scval)) in bundle.iter().zip(parsed.iter()).enumerate() {
        // Encode the per-inner ScVal as base64 XDR.
        let return_scval_b64 = inner_scval
            .to_xdr_base64(Limits::none())
            .unwrap_or_default();

        results.push(MulticallInnerResult {
            inner_index: u32::try_from(idx).unwrap_or(u32::MAX),
            target_contract: inv.target_contract.clone(),
            fn_name: inv.fn_name.clone(),
            return_scval_b64,
        });
    }

    Ok(results)
}

/// Returns a human-readable discriminant name for a `ScVal` variant.
///
/// Used in `post_submit_verification` error messages to identify the
/// unexpected ScVal shape without leaking full XDR content.
fn scval_discriminant_name(scval: &ScVal) -> &'static str {
    match scval {
        ScVal::Bool(_) => "Bool",
        ScVal::Void => "Void",
        ScVal::Error(_) => "Error",
        ScVal::U32(_) => "U32",
        ScVal::I32(_) => "I32",
        ScVal::U64(_) => "U64",
        ScVal::I64(_) => "I64",
        ScVal::Timepoint(_) => "Timepoint",
        ScVal::Duration(_) => "Duration",
        ScVal::U128(_) => "U128",
        ScVal::I128(_) => "I128",
        ScVal::U256(_) => "U256",
        ScVal::I256(_) => "I256",
        ScVal::Bytes(_) => "Bytes",
        ScVal::String(_) => "String",
        ScVal::Symbol(_) => "Symbol",
        ScVal::Vec(_) => "Vec",
        ScVal::Map(_) => "Map",
        ScVal::Address(_) => "Address",
        ScVal::LedgerKeyContractInstance => "LedgerKeyContractInstance",
        ScVal::LedgerKeyNonce(_) => "LedgerKeyNonce",
        ScVal::ContractInstance(_) => "ContractInstance",
    }
}

/// Maps a `SaError` wire-code to the closest `MulticallFailed` phase string.
///
/// Phase mappings:
/// - `"sa.deployment_failed"` with `phase = "simulate"` or `phase = "submit"` → that phase.
/// - `"sa.auth_entry_construction_failed"` → `"sign"` (auth-entry assembly failure).
/// - `"sa.submit_check_missing"` → `"build"` (programming-gate; fires before any I/O).
/// - `"sa.horizon_exceeded"` / `"sa.rule_expired"` / `"sa.simulation_divergence"` → `"policy_gate"`.
/// - `"sa.multicall_failed"` (nested) → `"submit"` (double-wrap, catches re-entrant errors).
/// - Other (unrecognised) → `"submit"` as last resort.
fn map_sa_error_to_multicall_phase(err: &SaError) -> &'static str {
    match err.wire_code() {
        "sa.deployment_failed" => {
            // Inspect the phase field to route correctly: simulate-phase errors
            // should map to "simulate"; submit-phase errors to "submit".
            // SaError::DeploymentFailed carries a `phase` field.
            if let SaError::DeploymentFailed { phase, .. } = err {
                match *phase {
                    "simulate" => "simulate",
                    "submit" => "submit",
                    _ => "simulate", // conservative default for unknown DeploymentFailed phases
                }
            } else {
                "simulate"
            }
        }
        "sa.auth_entry_construction_failed"
        | "sa.rule_id_mismatch"
        | "sa.simulation_divergence" => {
            // Auth-entry construction and context-rule divergence checks fire at the
            // sign stage (after simulate, before submit).
            "sign"
        }
        "sa.submit_check_missing" => {
            // SubmitCheckMissing fires BEFORE any I/O (fail-CLOSED programming gate).
            "build"
        }
        "sa.horizon_exceeded" | "sa.rule_expired" => {
            // Session-rule horizon + expiry checks fire at the policy-gate stage
            // (after simulate, before signing). They are session-policy checks,
            // not network submission failures.
            "policy_gate"
        }
        "sa.multicall_failed" => {
            // Nested MulticallFailed (should not normally occur; catch as submit).
            "submit"
        }
        _ => {
            // Refine catch-all mapping as new SaError variants land.
            "submit"
        }
    }
}

/// Extracts a wire-code-style short label from a `DenyReason`.
///
/// The closed set of recognized variants mirrors `DenyReason` in
/// `stellar_agent_core::policy`. Unknown future variants fall through to the
/// `_` wildcard which emits `"policy_denied"` — a safe fallback that does not
/// leak internal discriminant names.
fn deny_reason_wire_code(reason: &DenyReason) -> String {
    use stellar_agent_core::policy::DenyReason;
    match reason {
        DenyReason::PerTxCapExceeded { .. } => "per_tx_cap_exceeded".to_owned(),
        DenyReason::PerPeriodCapExceeded { .. } => "per_period_cap_exceeded".to_owned(),
        DenyReason::RateLimitExceeded { .. } => "rate_limit_exceeded".to_owned(),
        DenyReason::CounterpartyDenied { .. } => "counterparty_denied".to_owned(),
        DenyReason::MinimumReserveBreached { .. } => "minimum_reserve_breached".to_owned(),
        DenyReason::MissingApproval => "missing_approval".to_owned(),
        DenyReason::OwnerSignatureStale { .. } => "owner_signature_stale".to_owned(),
        DenyReason::NoMatchingRule => "no_matching_rule".to_owned(),
        DenyReason::ExplicitRuleDeny => "explicit_rule_deny".to_owned(),
        DenyReason::CounterpartyKindUnsupported { .. } => {
            "counterparty_kind_unsupported".to_owned()
        }
        DenyReason::EvaluationError { .. } => "evaluation_error".to_owned(),
        DenyReason::InnerInvocationCountCapExceeded { .. } => {
            "inner_invocation_count_cap_exceeded".to_owned()
        }
        DenyReason::BundleAggregateCapExceeded { .. } => "bundle_aggregate_cap_exceeded".to_owned(),
        DenyReason::BundleContainsGenericKind { .. } => "bundle_contains_generic_kind".to_owned(),
        DenyReason::BundleDenied { deny_reason, .. } => deny_reason_wire_code(deny_reason),
        _ => "policy_denied".to_owned(),
    }
}

/// Emits an audit event to `writer`; returns `Ok(())` or `Err(())` if emission fails.
///
/// Constructs the appropriate [`AuditEntry`] via the typed constructors in
/// `stellar_agent_core::audit_log::entry` and forwards to
/// [`AuditWriter::write_entry`].  Only the three multicall-specific
/// [`EventKind`] variants are handled here; other variants would require
/// different constructor signatures.
fn emit_audit_event(
    writer: &Option<Arc<Mutex<AuditWriter>>>,
    kind: EventKind,
    chain_id: &str,
    request_id: &str,
) -> Result<(), ()> {
    use stellar_agent_core::audit_log::entry::AuditEntry;

    let Some(writer) = writer else {
        return Ok(());
    };

    let entry = match kind {
        EventKind::SaMulticallBundleSubmitted {
            smart_account_redacted,
            rule_id,
            bundle_tx_hash_redacted,
            inner_count,
        } => AuditEntry::new_sa_multicall_bundle_submitted(
            smart_account_redacted,
            rule_id,
            bundle_tx_hash_redacted,
            inner_count,
            chain_id,
            request_id,
        ),
        EventKind::SaMulticallInnerExecuted {
            bundle_tx_hash_redacted,
            inner_index,
            target_contract_redacted,
            fn_name,
            return_scval_b64_prefix,
        } => AuditEntry::new_sa_multicall_inner_executed(
            bundle_tx_hash_redacted,
            inner_index,
            target_contract_redacted,
            fn_name,
            return_scval_b64_prefix,
            chain_id,
            request_id,
        ),
        EventKind::SaMulticallBundleDenied {
            smart_account_redacted,
            rule_id,
            inner_count,
            denied_inner_index,
            observed_inner_count,
            deny_wire_code,
            refusal_phase,
            bundle_tx_hash_redacted,
        } => AuditEntry::new_sa_multicall_bundle_denied(
            smart_account_redacted,
            rule_id,
            inner_count,
            denied_inner_index,
            observed_inner_count,
            deny_wire_code,
            refusal_phase,
            bundle_tx_hash_redacted,
            chain_id,
            request_id,
        ),
        // No other EventKind variants are emitted by submit_multicall_bundle.
        other => {
            tracing::error!("emit_audit_event: unexpected EventKind variant in multicall emitter");
            drop(other);
            return Err(());
        }
    };

    let mut guard = writer.lock().map_err(|_| ())?;
    guard.write_entry(entry).map_err(|_| ())
}

/// Checks that two numeric estimates are within ±5% tolerance.
fn check_numeric_tolerance(
    label: &'static str,
    primary: u64,
    secondary: u64,
) -> Result<(), SaError> {
    // Allow exact zero on both sides (common for write_bytes in read-only ops).
    if primary == 0 && secondary == 0 {
        return Ok(());
    }
    let max = primary.max(secondary);
    let min = primary.min(secondary);
    // Compute as 5% of max; use saturating arithmetic.
    let tolerance = max.saturating_div(20); // 5% = 1/20
    if max.saturating_sub(min) > tolerance {
        return Err(SaError::MulticallFailed {
            phase: "rpc_divergence",
            redacted_reason: format!(
                "estimate '{label}' differs beyond 5%: primary={primary}, secondary={secondary}"
            ),
            post_submit_kind: None,
        });
    }
    Ok(())
}

/// Truncates a warning message to `max_bytes` bytes, appending `"..."` if truncated.
fn truncate_warning(msg: &str, max_bytes: usize) -> String {
    if msg.len() <= max_bytes {
        return msg.to_owned();
    }
    // Truncate at a char boundary.
    let truncated = &msg[..msg
        .char_indices()
        .take_while(|(idx, _)| *idx < max_bytes.saturating_sub(3))
        .last()
        .map_or(0, |(idx, c)| idx + c.len_utf8())];
    format!("{truncated}...")
}

/// Validates whether `s` is a valid 64-char lowercase hex SHA-256.
fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Derives a URL-safe "network safename" from a network passphrase.
///
/// Replaces characters that are not ASCII alphanumeric or `-_` with `-`,
/// and lowercases the result. Used as TOML section keys in the registry TOML
/// and as network identifiers in audit rows.
///
/// Exposed as `pub` so CLI subcommands (`register-multicall`,
/// `unregister-multicall`) can import a single canonical copy.
pub fn network_safename_from_passphrase(passphrase: &str) -> String {
    passphrase
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

/// Creates a directory (and all parents) with mode `0700` on POSIX.
fn create_dir_0700(dir: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Writes `contents` to `path` atomically via a sibling temp file with mode `0600`.
fn atomic_write_0600(path: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write as _;

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "registry path has no parent directory",
        )
    })?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }

    tmp.write_all(contents)?;
    tmp.as_file().sync_data()?;
    tmp.persist(path).map_err(|e| e.error)?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::expect_used, reason = "test-only")]
    #![allow(clippy::panic, reason = "test-only")]

    use tempfile::TempDir;

    use super::*;

    // ── Provenance test ───────────────────────────────────────────────────────

    /// Defence-in-depth runtime check: SHA-256 of the included WASM matches
    /// the pinned `MULTICALL_WASM_SHA256` constant.
    ///
    /// The build.rs gate already enforces this at compile time; this test
    /// provides a runtime assertion for test configurations that might differ.
    ///
    #[test]
    fn multicall_wasm_sha256_matches_provenance() {
        let digest = Sha256::digest(MULTICALL_WASM);
        let hex = hex::encode(digest);
        assert_eq!(
            hex, MULTICALL_WASM_SHA256,
            "MULTICALL_WASM sha256 {hex} does not match MULTICALL_WASM_SHA256 {MULTICALL_WASM_SHA256}"
        );
    }

    // ── MULTICALL_FAILED_PHASES closed-7-set ──────────────────────────────────

    /// Asserts `MULTICALL_FAILED_PHASES` has exactly 7 entries.
    ///
    /// The phase inventory is a closed set; a CI gate enforces that no
    /// undeclared phase string reaches production emit sites.
    #[test]
    fn multicall_failed_phases_closed_set_has_seven_entries() {
        assert_eq!(
            MULTICALL_FAILED_PHASES.len(),
            7,
            "MULTICALL_FAILED_PHASES must have exactly 7 entries"
        );
    }

    /// Verifies the 7 canonical phase names are present in the closed set.
    #[test]
    fn multicall_failed_phases_contains_canonical_names() {
        let required = [
            "build",
            "policy_gate",
            "rpc_divergence",
            "simulate",
            "sign",
            "submit",
            "post_submit_verification",
        ];
        for name in &required {
            assert!(
                MULTICALL_FAILED_PHASES.contains(name),
                "missing phase '{name}' from MULTICALL_FAILED_PHASES"
            );
        }
    }

    // ── build_exec_invocations ────────────────────────────────────────────────

    /// Happy path: a single valid invocation encodes successfully.
    #[test]
    fn build_exec_invocations_single_invocation_ok() {
        let bundle = vec![MulticallInvocation {
            target_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            fn_name: "transfer".to_owned(),
            args_json: serde_json::json!(["1000000"]),
        }];
        let result = build_exec_invocations(&bundle).expect("build_exec_invocations failed");
        assert_eq!(result.len(), 1, "expected 1 ScVal entry");
        // Each result is a ScVal::Vec (the tuple).
        assert!(
            matches!(result[0], ScVal::Vec(_)),
            "expected ScVal::Vec for the tuple"
        );
    }

    /// Empty bundle returns an empty vec (not an error — length validation is in Step 1).
    #[test]
    fn build_exec_invocations_empty_bundle_returns_empty() {
        let result = build_exec_invocations(&[]).expect("empty bundle should not error");
        assert!(result.is_empty());
    }

    /// Redaction-shape sentinel used by `build_inner_results` tests.
    /// Real tx hashes flow through `stellar_agent_network::redact_tx_hash`
    /// to produce `first8...last8` shape.
    const FAKE_REDACTED_HASH: &str = "abcdef12...34567890";

    #[test]
    fn build_inner_results_success_preserves_order_and_return_xdr() {
        use stellar_xdr::{Limits, ScVal, VecM, WriteXdr};

        let bundle = vec![
            MulticallInvocation {
                target_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
                    .to_owned(),
                fn_name: "first".to_owned(),
                args_json: serde_json::Value::Null,
            },
            MulticallInvocation {
                target_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
                    .to_owned(),
                fn_name: "second".to_owned(),
                args_json: serde_json::Value::Null,
            },
        ];
        let inner_vals = vec![ScVal::U32(7), ScVal::Bool(true)];
        let return_val = ScVal::Vec(Some(VecM::try_from(inner_vals.clone()).unwrap().into()));

        let results = build_inner_results(&bundle, &return_val, FAKE_REDACTED_HASH)
            .expect("router return vector should parse");

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].inner_index, 0);
        assert_eq!(results[0].fn_name, "first");
        assert_eq!(results[1].inner_index, 1);
        assert_eq!(results[1].fn_name, "second");
        assert_eq!(
            results[0].return_scval_b64,
            inner_vals[0].to_xdr_base64(Limits::none()).unwrap()
        );
        assert_eq!(
            results[1].return_scval_b64,
            inner_vals[1].to_xdr_base64(Limits::none()).unwrap()
        );
    }

    #[test]
    fn build_inner_results_rejects_non_vec_with_typed_xdr_parse_kind() {
        let err = build_inner_results(&[], &ScVal::U32(7), FAKE_REDACTED_HASH).unwrap_err();
        match err {
            SaError::MulticallFailed {
                phase,
                post_submit_kind:
                    Some(PostSubmitVerificationKind::XdrUnexpectedShape {
                        observed_discriminant,
                    }),
                ..
            } => {
                assert_eq!(phase, "post_submit_verification");
                assert_eq!(observed_discriminant, "U32");
            }
            other => panic!("expected typed post-submit XDR parse failure, got {other:?}"),
        }
    }

    #[test]
    fn build_inner_results_rejects_count_mismatch_with_observed_count() {
        use stellar_xdr::{ScVal, VecM};

        let bundle = vec![MulticallInvocation {
            target_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            fn_name: "first".to_owned(),
            args_json: serde_json::Value::Null,
        }];
        let return_val = ScVal::Vec(Some(
            VecM::try_from(vec![ScVal::U32(1), ScVal::U32(2)])
                .unwrap()
                .into(),
        ));

        let err = build_inner_results(&bundle, &return_val, FAKE_REDACTED_HASH).unwrap_err();
        match err {
            SaError::MulticallFailed {
                phase,
                post_submit_kind:
                    Some(PostSubmitVerificationKind::InnerCountMismatch {
                        observed_inner_count,
                    }),
                ..
            } => {
                assert_eq!(phase, "post_submit_verification");
                assert_eq!(observed_inner_count, 2);
            }
            other => panic!("expected typed post-submit count mismatch, got {other:?}"),
        }
    }

    const POST_SUBMIT_VERIFICATION_KIND_CASES: &[PostSubmitVerificationKind] = &[
        PostSubmitVerificationKind::XdrEmptyVec,
        PostSubmitVerificationKind::XdrUnexpectedShape {
            observed_discriminant: "Bytes",
        },
        PostSubmitVerificationKind::InnerCountMismatch {
            observed_inner_count: 2,
        },
    ];

    #[test]
    fn post_submit_verification_failures_keep_redacted_shape_for_every_kind() {
        for kind in POST_SUBMIT_VERIFICATION_KIND_CASES {
            // COMPILE-CHECK: this match intentionally enumerates the closed
            // post-submit kind set so a new variant must be added to this
            // redaction-shape regression.
            let reason = match kind {
                PostSubmitVerificationKind::XdrEmptyVec => {
                    "router return value is ScVal::Vec(None)".to_owned()
                }
                PostSubmitVerificationKind::XdrUnexpectedShape {
                    observed_discriminant,
                } => {
                    format!("router return discriminant was {observed_discriminant}")
                }
                PostSubmitVerificationKind::InnerCountMismatch {
                    observed_inner_count,
                } => {
                    format!("inner-count mismatch: observed {observed_inner_count}")
                }
            };
            let err = SaError::MulticallFailed {
                phase: "post_submit_verification",
                redacted_reason: reason,
                post_submit_kind: Some(*kind),
            };
            let rendered = serde_json::to_string(&err).unwrap();
            assert!(
                !contains_full_strkey_shape(&rendered),
                "post-submit error leaked a full strkey-shaped value: {rendered}"
            );
            assert!(
                !contains_hex_run(&rendered, 64),
                "post-submit error leaked a full 32-byte hex-shaped value: {rendered}"
            );
        }
    }

    fn contains_full_strkey_shape(s: &str) -> bool {
        let bytes = s.as_bytes();
        bytes.windows(56).any(|window| {
            matches!(window[0], b'G' | b'C')
                && window
                    .iter()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        })
    }

    fn contains_hex_run(s: &str, len: usize) -> bool {
        let mut run = 0;
        for b in s.bytes() {
            if b.is_ascii_hexdigit() {
                run += 1;
                if run >= len {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        false
    }

    /// Invalid C-strkey in `target_contract` returns `MulticallFailed { phase: "build" }`.
    #[test]
    fn build_exec_invocations_invalid_target_contract_fails_closed() {
        let bundle = vec![MulticallInvocation {
            target_contract: "NOT_A_STRKEY".to_owned(),
            fn_name: "transfer".to_owned(),
            args_json: serde_json::json!([]),
        }];
        let err = build_exec_invocations(&bundle).unwrap_err();
        assert_eq!(err.wire_code(), "sa.multicall_failed");
        if let SaError::MulticallFailed { phase, .. } = err {
            assert_eq!(phase, "build");
        } else {
            panic!("expected MulticallFailed");
        }
    }

    /// Invalid symbol (too long) returns `MulticallFailed { phase: "build" }`.
    #[test]
    fn build_exec_invocations_invalid_fn_name_fails_closed() {
        let bundle = vec![MulticallInvocation {
            target_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            fn_name: "a".repeat(33), // 33 bytes — exceeds 32-byte symbol limit.
            args_json: serde_json::json!([]),
        }];
        let err = build_exec_invocations(&bundle).unwrap_err();
        if let SaError::MulticallFailed { phase, .. } = err {
            assert_eq!(phase, "build");
        } else {
            panic!("expected MulticallFailed");
        }
    }

    // ── MulticallRegistry ─────────────────────────────────────────────────────

    /// `register` accepts an entry with the correct `MULTICALL_WASM_SHA256`.
    #[test]
    fn registry_register_accepts_correct_sha() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let mut reg = MulticallRegistry::load(&path).expect("load");
        let entry = MulticallRegistryEntry {
            network_passphrase: "Test SDF Network ; September 2015".to_owned(),
            address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            wasm_sha256: MULTICALL_WASM_SHA256.to_owned(),
        };
        reg.register(entry).expect("register should succeed");
        let looked_up = reg
            .lookup("Test SDF Network ; September 2015")
            .expect("lookup ok")
            .expect("entry present");
        assert_eq!(looked_up.wasm_sha256, MULTICALL_WASM_SHA256);
    }

    /// `register` refuses an entry with a wrong SHA (binary-const trust-anchor).
    #[test]
    fn registry_register_refuses_wrong_sha() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let mut reg = MulticallRegistry::load(&path).expect("load");
        let entry = MulticallRegistryEntry {
            network_passphrase: "Test SDF Network ; September 2015".to_owned(),
            address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            wasm_sha256: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_owned(),
        };
        let err = reg.register(entry).unwrap_err();
        assert_eq!(err.wire_code(), "sa.multicall_sha256_drift");
    }

    /// `lookup` returns `None` for an unregistered network.
    #[test]
    fn registry_lookup_none_for_unknown_network() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let reg = MulticallRegistry::load(&path).expect("load");
        let result = reg.lookup("Unknown Network").expect("lookup ok");
        assert!(result.is_none());
    }

    /// `lookup` returns `Err(MulticallSha256Drift)` when stored SHA != binary const.
    #[test]
    fn registry_lookup_refuses_sha_drift() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let mut reg = MulticallRegistry::load(&path).expect("load");

        // Manually insert an entry with wrong SHA (bypassing register-time check
        // to simulate a post-registration binary upgrade scenario).
        reg.entries.push(MulticallRegistryEntry {
            network_passphrase: "Test SDF Network ; September 2015".to_owned(),
            address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            wasm_sha256: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
                .to_owned(),
        });

        let err = reg.lookup("Test SDF Network ; September 2015").unwrap_err();
        assert_eq!(err.wire_code(), "sa.multicall_sha256_drift");
    }

    /// `unregister` removes the entry and returns it.
    #[test]
    fn registry_unregister_returns_entry() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let mut reg = MulticallRegistry::load(&path).expect("load");
        let passphrase = "Test SDF Network ; September 2015";
        reg.entries.push(MulticallRegistryEntry {
            network_passphrase: passphrase.to_owned(),
            address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            wasm_sha256: MULTICALL_WASM_SHA256.to_owned(),
        });
        let removed = reg.unregister(passphrase).expect("unregister ok");
        assert_eq!(removed.network_passphrase, passphrase);
        assert!(reg.lookup(passphrase).expect("lookup ok").is_none());
    }

    /// `unregister` returns `MulticallRegistryEntryNotFound` for a missing network.
    #[test]
    fn registry_unregister_missing_entry_fails() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let mut reg = MulticallRegistry::load(&path).expect("load");
        let err = reg
            .unregister("Test SDF Network ; September 2015")
            .unwrap_err();
        assert_eq!(err.wire_code(), "sa.multicall_registry_entry_not_found");
    }

    /// `load` tolerates malformed entries and accumulates `partial_load_warnings`.
    #[test]
    fn registry_load_tolerates_malformed_entries() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");

        // Write a TOML with one valid and one invalid entry.
        std::fs::write(
            &path,
            r#"
[multicall.testnet]
network_passphrase = "Test SDF Network ; September 2015"
address = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
wasm_sha256 = "267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4"

[multicall.bad-entry]
network_passphrase = "Bad Network"
address = "NOT_A_STRKEY"
wasm_sha256 = "267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4"
"#,
        )
        .expect("write toml");

        let reg = MulticallRegistry::load(&path).expect("load should not fail");
        // One valid entry loaded, one warning for the bad entry.
        assert_eq!(reg.entries.len(), 1, "expected 1 valid entry");
        assert_eq!(
            reg.partial_load_warnings.len(),
            1,
            "expected 1 load warning"
        );
    }

    // ── cross_rpc_compare_wasm_hashes ─────────────────────────────────────────

    /// All four legs agreeing on the binary const returns `Ok(())`.
    #[test]
    fn cross_rpc_compare_wasm_hashes_all_agree_ok() {
        let result = cross_rpc_compare_wasm_hashes(
            MULTICALL_WASM_SHA256,
            MULTICALL_WASM_SHA256,
            MULTICALL_WASM_SHA256,
        );
        assert!(result.is_ok(), "four legs agreeing should be Ok");
    }

    /// Registry leg disagreeing returns `MulticallFailed { phase: "rpc_divergence" }`.
    #[test]
    fn cross_rpc_compare_wasm_hashes_registry_drift_fails() {
        let err = cross_rpc_compare_wasm_hashes(
            "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            MULTICALL_WASM_SHA256,
            MULTICALL_WASM_SHA256,
        )
        .unwrap_err();
        if let SaError::MulticallFailed { phase, .. } = err {
            assert_eq!(phase, "rpc_divergence");
        } else {
            panic!("expected MulticallFailed");
        }
    }

    // ── validate_soroban_symbol ───────────────────────────────────────────────

    #[test]
    fn validate_soroban_symbol_valid_names_accepted() {
        assert!(validate_soroban_symbol("transfer").is_ok());
        assert!(validate_soroban_symbol("exec").is_ok());
        assert!(validate_soroban_symbol("my_fn_01").is_ok());
    }

    #[test]
    fn validate_soroban_symbol_empty_rejected() {
        assert!(validate_soroban_symbol("").is_err());
    }

    #[test]
    fn validate_soroban_symbol_too_long_rejected() {
        assert!(validate_soroban_symbol(&"a".repeat(33)).is_err());
    }

    #[test]
    fn validate_soroban_symbol_special_chars_rejected() {
        assert!(validate_soroban_symbol("fn-name").is_err()); // hyphen not allowed
        assert!(validate_soroban_symbol("fn name").is_err()); // space not allowed
    }

    // ── truncate_warning ──────────────────────────────────────────────────────

    #[test]
    fn truncate_warning_short_strings_unchanged() {
        let s = "short warning";
        assert_eq!(truncate_warning(s, 256), s);
    }

    #[test]
    fn truncate_warning_long_strings_truncated_with_ellipsis() {
        let long = "x".repeat(300);
        let result = truncate_warning(&long, 256);
        assert!(result.len() <= 256, "truncated string must be ≤ 256 bytes");
        assert!(
            result.ends_with("..."),
            "truncated string must end with '...'"
        );
    }

    // ── classify_required_checks ──────────────────────────────────────────────

    #[test]
    fn classify_required_checks_returns_multicall_for_registered_address() {
        use stellar_xdr::{ContractId, Hash, InvokeContractArgs, ScSymbol};

        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let mut reg = MulticallRegistry::load(&path).expect("load");
        let passphrase = "Test SDF Network ; September 2015";
        let addr = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        reg.entries.push(MulticallRegistryEntry {
            network_passphrase: passphrase.to_owned(),
            address: addr.to_owned(),
            wasm_sha256: MULTICALL_WASM_SHA256.to_owned(),
        });

        let contract = stellar_strkey::Contract::from_string(addr).unwrap();
        let hf = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash(contract.0))),
            function_name: ScSymbol(b"exec".as_slice().try_into().unwrap()),
            args: VecM::default(),
        });
        let checks = classify_required_checks(&hf, &reg, passphrase);
        assert_eq!(checks, &["multicall"]);
    }

    #[test]
    fn classify_required_checks_returns_empty_for_unregistered_address() {
        use stellar_xdr::{ContractId, Hash, InvokeContractArgs, ScSymbol};

        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let reg = MulticallRegistry::load(&path).expect("load");

        let contract = stellar_strkey::Contract::from_string(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        )
        .unwrap();
        let hf = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash(contract.0))),
            function_name: ScSymbol(b"exec".as_slice().try_into().unwrap()),
            args: VecM::default(),
        });
        let checks = classify_required_checks(&hf, &reg, "Test SDF Network ; September 2015");
        assert_eq!(checks, &[] as &[&str]);
    }

    // ── From<&MulticallRegistryEntry> for RawMulticallEntry ───────────────────

    /// `From<&MulticallRegistryEntry>` produces a `RawMulticallEntry` with
    /// identical field values — the conversion is a field-wise clone.
    #[test]
    fn raw_multicall_entry_from_registry_entry_copies_fields() {
        let entry = MulticallRegistryEntry {
            network_passphrase: "Test SDF Network ; September 2015".to_owned(),
            address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            wasm_sha256: MULTICALL_WASM_SHA256.to_owned(),
        };
        let raw = RawMulticallEntry::from(&entry);
        assert_eq!(raw.network_passphrase, entry.network_passphrase);
        assert_eq!(raw.address, entry.address);
        assert_eq!(raw.wasm_sha256, entry.wasm_sha256);
    }

    // ── load — TOML parse error ───────────────────────────────────────────────

    /// A file that is not valid TOML returns `SaError::NetworksTomlParse`.
    #[test]
    fn registry_load_invalid_toml_returns_parse_error() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        std::fs::write(&path, "not valid [ toml !! \x00").expect("write");
        let err = MulticallRegistry::load(&path).unwrap_err();
        assert_eq!(err.wire_code(), "sa.networks_toml_parse");
    }

    // ── load — invalid SHA-256 hex entry (not 64 hex chars) ──────────────────

    /// An entry with invalid hex wasm_sha256 is skipped and produces a warning.
    #[test]
    fn registry_load_invalid_sha256_hex_skipped_with_warning() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        std::fs::write(
            &path,
            r#"
[multicall.badsha]
network_passphrase = "Bad SHA Network"
address = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
wasm_sha256 = "not-a-sha256-at-all"
"#,
        )
        .expect("write");
        let reg = MulticallRegistry::load(&path).expect("load should succeed");
        assert!(reg.entries.is_empty(), "invalid-sha entry must be skipped");
        assert_eq!(
            reg.partial_load_warnings.len(),
            1,
            "expected exactly 1 warning for invalid sha256 hex"
        );
        assert!(
            reg.partial_load_warnings[0]
                .reason
                .contains("invalid SHA-256 hex"),
            "warning reason must mention invalid SHA-256 hex"
        );
    }

    // ── load — sha drift (valid 64-char hex but != MULTICALL_WASM_SHA256) ────

    /// An entry with a syntactically valid 64-char hex SHA that differs from
    /// `MULTICALL_WASM_SHA256` is LOADED (lookup will refuse) with a warning.
    #[test]
    fn registry_load_sha_drift_entry_loaded_with_warning_and_lookup_refuses() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let drifted_sha = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        std::fs::write(
            &path,
            format!(
                r#"
[multicall.driftnet]
network_passphrase = "Drift Network"
address = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
wasm_sha256 = "{drifted_sha}"
"#
            ),
        )
        .expect("write");
        let reg = MulticallRegistry::load(&path).expect("load should succeed");
        // Entry must be loaded (not skipped) despite SHA drift.
        assert_eq!(reg.entries.len(), 1, "sha-drift entry must still be loaded");
        // A warning must be produced.
        assert_eq!(
            reg.partial_load_warnings.len(),
            1,
            "expected exactly 1 warning for sha drift"
        );
        assert!(
            reg.partial_load_warnings[0]
                .reason
                .contains("lookup will refuse"),
            "warning must indicate lookup will refuse"
        );
        // lookup must refuse with MulticallSha256Drift.
        let err = reg.lookup("Drift Network").unwrap_err();
        assert_eq!(err.wire_code(), "sa.multicall_sha256_drift");
    }

    // ── register — idempotent re-register with same SHA ───────────────────────

    /// Re-registering an entry with the correct SHA and same network passphrase
    /// is idempotent: the entry count stays at 1 and the operation returns `Ok`.
    #[test]
    fn registry_register_idempotent_same_sha_does_not_duplicate() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let mut reg = MulticallRegistry::load(&path).expect("load");
        let passphrase = "Test SDF Network ; September 2015";
        let entry = MulticallRegistryEntry {
            network_passphrase: passphrase.to_owned(),
            address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            wasm_sha256: MULTICALL_WASM_SHA256.to_owned(),
        };
        reg.register(entry.clone()).expect("first register ok");
        reg.register(entry)
            .expect("second register ok (idempotent)");
        assert_eq!(
            reg.entries.len(),
            1,
            "idempotent re-register must not duplicate the entry"
        );
    }

    // ── unregister_force — passphrase match ──────────────────────────────────

    /// `unregister_force` locates an entry via the derived safename and returns
    /// a `RawEntry` with the correct fields.
    #[test]
    fn registry_unregister_force_by_safename_returns_raw_entry() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let mut reg = MulticallRegistry::load(&path).expect("load");
        let passphrase = "Test SDF Network ; September 2015";
        let addr = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        reg.entries.push(MulticallRegistryEntry {
            network_passphrase: passphrase.to_owned(),
            address: addr.to_owned(),
            wasm_sha256: MULTICALL_WASM_SHA256.to_owned(),
        });
        // The safename derived from the passphrase is what `unregister_force` expects.
        let safename = network_safename_from_passphrase(passphrase);
        let raw = reg
            .unregister_force(&safename)
            .expect("unregister_force ok");
        assert_eq!(raw.network_safename, safename);
        assert_eq!(raw.address, addr);
        assert_eq!(raw.network_passphrase, passphrase);
        assert!(reg.entries.is_empty(), "entry must be removed");
    }

    /// `unregister_force` on a missing entry returns
    /// `SaError::MulticallRegistryEntryNotFound`.
    #[test]
    fn registry_unregister_force_missing_entry_fails() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let mut reg = MulticallRegistry::load(&path).expect("load");
        let err = reg.unregister_force("nonexistent-safename").unwrap_err();
        assert_eq!(err.wire_code(), "sa.multicall_registry_entry_not_found");
    }

    // ── save + load round-trip ────────────────────────────────────────────────

    /// `save` followed by `load` on the same path round-trips the entry without
    /// data loss.
    #[test]
    fn registry_save_and_load_round_trip() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let passphrase = "Test SDF Network ; September 2015";
        let addr = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

        let mut reg = MulticallRegistry::load(&path).expect("initial load of absent file");
        reg.entries.push(MulticallRegistryEntry {
            network_passphrase: passphrase.to_owned(),
            address: addr.to_owned(),
            wasm_sha256: MULTICALL_WASM_SHA256.to_owned(),
        });
        reg.save().expect("save ok");

        let reg2 = MulticallRegistry::load(&path).expect("reload after save");
        assert_eq!(reg2.entries.len(), 1, "one entry after round-trip");
        let e = &reg2.entries[0];
        assert_eq!(e.network_passphrase, passphrase);
        assert_eq!(e.address, addr);
        assert_eq!(e.wasm_sha256, MULTICALL_WASM_SHA256);
    }

    // ── config_path() ─────────────────────────────────────────────────────────

    /// `config_path()` returns the path the registry was loaded from.
    #[test]
    fn registry_config_path_returns_load_path() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let reg = MulticallRegistry::load(&path).expect("load");
        assert_eq!(reg.config_path(), path.as_path());
    }

    // ── MulticallRegistryHook impl ────────────────────────────────────────────

    /// `MulticallRegistryHook::lookup` returns `Some(())` for a registered network
    /// with a matching SHA and `None` for an absent network or SHA-drift entry.
    #[test]
    fn multicall_registry_hook_lookup_present_returns_some_absent_returns_none() {
        use stellar_agent_core::profile::loader::MulticallRegistryHook;

        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let mut reg = MulticallRegistry::load(&path).expect("load");
        let passphrase = "Test SDF Network ; September 2015";
        reg.entries.push(MulticallRegistryEntry {
            network_passphrase: passphrase.to_owned(),
            address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            wasm_sha256: MULTICALL_WASM_SHA256.to_owned(),
        });

        // Present + correct SHA → Some(()).
        let hook_result = MulticallRegistryHook::lookup(&reg, passphrase);
        assert_eq!(
            hook_result,
            Some(()),
            "registered network with correct SHA must return Some(())"
        );

        // Absent network → None.
        let absent = MulticallRegistryHook::lookup(&reg, "Unknown Network");
        assert!(absent.is_none(), "absent network must return None");
    }

    /// `MulticallRegistryHook::lookup` returns `None` when the stored entry has
    /// a drifted SHA (drift is folded to None per the trait contract).
    #[test]
    fn multicall_registry_hook_lookup_sha_drift_folds_to_none() {
        use stellar_agent_core::profile::loader::MulticallRegistryHook;

        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let mut reg = MulticallRegistry::load(&path).expect("load");
        let passphrase = "Drift Network";
        reg.entries.push(MulticallRegistryEntry {
            network_passphrase: passphrase.to_owned(),
            address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            wasm_sha256: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
                .to_owned(),
        });

        // Drift (lookup returns Err) → hook folds to None.
        let result = MulticallRegistryHook::lookup(&reg, passphrase);
        assert!(
            result.is_none(),
            "sha-drift must fold to None in the hook (no Err propagation)"
        );
    }

    // ── cross_rpc_compare_wasm_hashes — primary and secondary drift ───────────

    /// Primary-RPC leg with wrong SHA returns `MulticallFailed { phase: "rpc_divergence" }`.
    #[test]
    fn cross_rpc_compare_wasm_hashes_primary_drift_fails() {
        let drifted = "0000000000000000000000000000000000000000000000000000000000000000";
        let err =
            cross_rpc_compare_wasm_hashes(MULTICALL_WASM_SHA256, drifted, MULTICALL_WASM_SHA256)
                .unwrap_err();
        match err {
            SaError::MulticallFailed {
                phase,
                ref redacted_reason,
                ..
            } => {
                assert_eq!(phase, "rpc_divergence");
                assert!(
                    redacted_reason.contains("primary-RPC"),
                    "error must mention primary-RPC: {redacted_reason}"
                );
            }
            other => panic!("expected MulticallFailed, got {other:?}"),
        }
    }

    /// Secondary-RPC leg with wrong SHA returns `MulticallFailed { phase: "rpc_divergence" }`.
    #[test]
    fn cross_rpc_compare_wasm_hashes_secondary_drift_fails() {
        let drifted = "ffff000000000000000000000000000000000000000000000000000000000000";
        let err =
            cross_rpc_compare_wasm_hashes(MULTICALL_WASM_SHA256, MULTICALL_WASM_SHA256, drifted)
                .unwrap_err();
        match err {
            SaError::MulticallFailed {
                phase,
                ref redacted_reason,
                ..
            } => {
                assert_eq!(phase, "rpc_divergence");
                assert!(
                    redacted_reason.contains("secondary-RPC"),
                    "error must mention secondary-RPC: {redacted_reason}"
                );
            }
            other => panic!("expected MulticallFailed, got {other:?}"),
        }
    }

    // ── check_numeric_tolerance ───────────────────────────────────────────────

    /// Both zero is always within tolerance (common for write_bytes in read-only ops).
    #[test]
    fn check_numeric_tolerance_both_zero_ok() {
        assert!(
            check_numeric_tolerance("write_bytes", 0, 0).is_ok(),
            "both-zero must be Ok"
        );
    }

    /// Values differing by more than 5% produce `rpc_divergence`.
    /// primary=100, secondary=200 → diff=100, max=200, tolerance=10 → fails.
    #[test]
    fn check_numeric_tolerance_beyond_five_percent_fails() {
        let err = check_numeric_tolerance("instructions", 100, 200).unwrap_err();
        match err {
            SaError::MulticallFailed {
                phase,
                ref redacted_reason,
                ..
            } => {
                assert_eq!(phase, "rpc_divergence");
                assert!(
                    redacted_reason.contains("instructions"),
                    "error must mention 'instructions': {redacted_reason}"
                );
            }
            other => panic!("expected MulticallFailed, got {other:?}"),
        }
    }

    /// Values differing by exactly 5% (at the tolerance boundary) pass.
    /// primary=100, secondary=105 → diff=5, max=105, tolerance=floor(105/20)=5 → ok.
    #[test]
    fn check_numeric_tolerance_at_boundary_passes() {
        // 105 - 100 = 5 = floor(105/20) = 5 → not strictly greater, so passes.
        assert!(
            check_numeric_tolerance("instructions", 100, 105).is_ok(),
            "5% boundary case must pass"
        );
    }

    // ── is_valid_sha256_hex ───────────────────────────────────────────────────

    /// Valid 64-char lowercase hex passes.
    #[test]
    fn is_valid_sha256_hex_correct_lowercase_passes() {
        assert!(is_valid_sha256_hex(
            "267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4"
        ));
    }

    /// A 64-char string containing uppercase hex letters passes (hex digits
    /// include A-F per `char::is_ascii_hexdigit`).
    #[test]
    fn is_valid_sha256_hex_uppercase_hex_passes() {
        assert!(is_valid_sha256_hex(
            "267E94A092DF01FA02AD4EDF8320A98BD65E4D4D6575254AC9521CB65727F3D4"
        ));
    }

    /// Wrong length (63 chars) fails.
    #[test]
    fn is_valid_sha256_hex_wrong_length_fails() {
        assert!(!is_valid_sha256_hex(
            "267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d"
        ));
    }

    /// Contains non-hex character fails.
    #[test]
    fn is_valid_sha256_hex_non_hex_char_fails() {
        assert!(!is_valid_sha256_hex(
            "267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727xxxx"
        ));
    }

    // ── network_safename_from_passphrase ──────────────────────────────────────

    /// Standard testnet passphrase produces the expected safename.
    /// "Test SDF Network ; September 2015" → all non-alnum/-/_ become '-',
    /// then lowercased, then leading/trailing '-' trimmed.
    #[test]
    fn network_safename_from_passphrase_testnet_passphrase() {
        let safename = network_safename_from_passphrase("Test SDF Network ; September 2015");
        // Spaces and ';' become '-'; letters lowercased; leading/trailing '-' trimmed.
        assert_eq!(safename, "test-sdf-network---september-2015");
    }

    /// A passphrase consisting only of special characters produces an empty string
    /// after trim (all '-' trimmed away).
    #[test]
    fn network_safename_from_passphrase_all_special_chars_trims_to_empty() {
        let safename = network_safename_from_passphrase(";;;");
        assert_eq!(safename, "");
    }

    /// Alphanumeric characters and allowed '-'/'_' are preserved as-is (lowercased).
    #[test]
    fn network_safename_from_passphrase_alphanumeric_preserved() {
        let safename = network_safename_from_passphrase("My-Net_work");
        assert_eq!(safename, "my-net_work");
    }

    // ── map_sa_error_to_multicall_phase ───────────────────────────────────────

    /// `DeploymentFailed { phase: "simulate" }` maps to `"simulate"`.
    #[test]
    fn map_sa_error_to_phase_deployment_failed_simulate() {
        let err = SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: "test".to_owned(),
        };
        assert_eq!(map_sa_error_to_multicall_phase(&err), "simulate");
    }

    /// `DeploymentFailed { phase: "submit" }` maps to `"submit"`.
    #[test]
    fn map_sa_error_to_phase_deployment_failed_submit() {
        let err = SaError::DeploymentFailed {
            phase: "submit",
            redacted_reason: "test".to_owned(),
        };
        assert_eq!(map_sa_error_to_multicall_phase(&err), "submit");
    }

    /// `DeploymentFailed { phase: "build" }` (unknown sub-phase) conservatively maps
    /// to `"simulate"`.
    #[test]
    fn map_sa_error_to_phase_deployment_failed_unknown_phase_maps_to_simulate() {
        let err = SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: "test".to_owned(),
        };
        assert_eq!(map_sa_error_to_multicall_phase(&err), "simulate");
    }

    /// `AuthEntryConstructionFailed` maps to `"sign"`.
    #[test]
    fn map_sa_error_to_phase_auth_entry_construction_failed_maps_to_sign() {
        let err = SaError::AuthEntryConstructionFailed {
            stage: "sign",
            redacted_reason: "test".to_owned(),
        };
        assert_eq!(map_sa_error_to_multicall_phase(&err), "sign");
    }

    /// `RuleIdMismatch` maps to `"sign"`.
    #[test]
    fn map_sa_error_to_phase_rule_id_mismatch_maps_to_sign() {
        let err = SaError::RuleIdMismatch {
            expected_len: 1,
            observed_len: 0,
        };
        assert_eq!(map_sa_error_to_multicall_phase(&err), "sign");
    }

    /// `SubmitCheckMissing` maps to `"build"`.
    #[test]
    fn map_sa_error_to_phase_submit_check_missing_maps_to_build() {
        let err = SaError::SubmitCheckMissing {
            required_check: "multicall",
            host_function_kind: "InvokeContract",
        };
        assert_eq!(map_sa_error_to_multicall_phase(&err), "build");
    }

    /// `HorizonExceeded` maps to `"policy_gate"`.
    #[test]
    fn map_sa_error_to_phase_horizon_exceeded_maps_to_policy_gate() {
        let err = SaError::HorizonExceeded {
            rule_id_or_pending: None,
            requested_horizon: 2000,
            max_horizon: 1000,
        };
        assert_eq!(map_sa_error_to_multicall_phase(&err), "policy_gate");
    }

    /// `RuleExpired` maps to `"policy_gate"`.
    #[test]
    fn map_sa_error_to_phase_rule_expired_maps_to_policy_gate() {
        let err = SaError::RuleExpired {
            rule_id: 1,
            valid_until: 100,
            current: 200,
        };
        assert_eq!(map_sa_error_to_multicall_phase(&err), "policy_gate");
    }

    /// `MulticallFailed` (nested) maps to `"submit"`.
    #[test]
    fn map_sa_error_to_phase_multicall_failed_nested_maps_to_submit() {
        let err = SaError::MulticallFailed {
            phase: "build",
            redacted_reason: "nested".to_owned(),
            post_submit_kind: None,
        };
        assert_eq!(map_sa_error_to_multicall_phase(&err), "submit");
    }

    /// An unrecognised error (e.g. `MulticallRegistryEntryNotFound`) maps to `"submit"`.
    #[test]
    fn map_sa_error_to_phase_unrecognised_maps_to_submit() {
        let err = SaError::MulticallRegistryEntryNotFound {
            network_safename: "testnet".to_owned(),
        };
        assert_eq!(map_sa_error_to_multicall_phase(&err), "submit");
    }

    // ── deny_reason_wire_code ─────────────────────────────────────────────────

    /// All `DenyReason` variants produce the correct wire-code string.
    #[test]
    fn deny_reason_wire_code_per_tx_cap_exceeded() {
        use stellar_agent_core::policy::DenyReason;
        let r = DenyReason::PerTxCapExceeded {
            asset: "XLM".to_owned(),
            max_stroops: 100,
            attempted_stroops: 200,
        };
        assert_eq!(deny_reason_wire_code(&r), "per_tx_cap_exceeded");
    }

    #[test]
    fn deny_reason_wire_code_per_period_cap_exceeded() {
        use stellar_agent_core::policy::DenyReason;
        let r = DenyReason::PerPeriodCapExceeded {
            asset: "XLM".to_owned(),
            window: "rolling_24h".to_owned(),
            max_stroops: 1000,
            attempted_stroops: 2000,
            period_used_stroops: 500,
        };
        assert_eq!(deny_reason_wire_code(&r), "per_period_cap_exceeded");
    }

    #[test]
    fn deny_reason_wire_code_rate_limit_exceeded() {
        use stellar_agent_core::policy::DenyReason;
        let r = DenyReason::RateLimitExceeded {
            window: "rolling_1h".to_owned(),
            max_calls: 5,
            calls_in_window: 10,
        };
        assert_eq!(deny_reason_wire_code(&r), "rate_limit_exceeded");
    }

    #[test]
    fn deny_reason_wire_code_counterparty_denied() {
        use stellar_agent_core::policy::DenyReason;
        let r = DenyReason::CounterpartyDenied {
            kind: "ADDRESS".to_owned(),
            value: "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned(),
        };
        assert_eq!(deny_reason_wire_code(&r), "counterparty_denied");
    }

    #[test]
    fn deny_reason_wire_code_minimum_reserve_breached() {
        use stellar_agent_core::policy::DenyReason;
        let r = DenyReason::MinimumReserveBreached {
            reserve_required_stroops: 10_000_000,
            balance_stroops: 5_000_000,
        };
        assert_eq!(deny_reason_wire_code(&r), "minimum_reserve_breached");
    }

    #[test]
    fn deny_reason_wire_code_missing_approval() {
        use stellar_agent_core::policy::DenyReason;
        assert_eq!(
            deny_reason_wire_code(&DenyReason::MissingApproval),
            "missing_approval"
        );
    }

    #[test]
    fn deny_reason_wire_code_no_matching_rule() {
        use stellar_agent_core::policy::DenyReason;
        assert_eq!(
            deny_reason_wire_code(&DenyReason::NoMatchingRule),
            "no_matching_rule"
        );
    }

    #[test]
    fn deny_reason_wire_code_explicit_rule_deny() {
        use stellar_agent_core::policy::DenyReason;
        assert_eq!(
            deny_reason_wire_code(&DenyReason::ExplicitRuleDeny),
            "explicit_rule_deny"
        );
    }

    #[test]
    fn deny_reason_wire_code_inner_invocation_count_cap_exceeded() {
        use stellar_agent_core::policy::DenyReason;
        let r = DenyReason::InnerInvocationCountCapExceeded {
            max: 10,
            attempted: 15,
        };
        assert_eq!(
            deny_reason_wire_code(&r),
            "inner_invocation_count_cap_exceeded"
        );
    }

    #[test]
    fn deny_reason_wire_code_bundle_aggregate_cap_exceeded() {
        use stellar_agent_core::policy::DenyReason;
        let r = DenyReason::BundleAggregateCapExceeded {
            asset: Some("XLM".to_owned()),
            max: 1000,
            sum: 2000,
        };
        assert_eq!(deny_reason_wire_code(&r), "bundle_aggregate_cap_exceeded");
    }

    #[test]
    fn deny_reason_wire_code_bundle_contains_generic_kind() {
        use stellar_agent_core::policy::DenyReason;
        let r = DenyReason::BundleContainsGenericKind { inner_index: 2 };
        assert_eq!(deny_reason_wire_code(&r), "bundle_contains_generic_kind");
    }

    /// `BundleDenied` delegates recursively to the inner reason.
    #[test]
    fn deny_reason_wire_code_bundle_denied_delegates_to_inner() {
        use stellar_agent_core::policy::DenyReason;
        let inner = DenyReason::NoMatchingRule;
        let r = DenyReason::BundleDenied {
            inner_index: 0,
            deny_reason: Box::new(inner),
        };
        assert_eq!(deny_reason_wire_code(&r), "no_matching_rule");
    }

    // ── json_args_to_scval_vec ────────────────────────────────────────────────

    /// A JSON array with a positive integer encodes as `ScVal::I128` with `hi=0`.
    #[test]
    fn json_args_positive_integer_encodes_as_i128_hi_zero() {
        use stellar_xdr::Int128Parts;
        let invocation = MulticallInvocation {
            target_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            fn_name: "transfer".to_owned(),
            args_json: serde_json::json!([42u64]),
        };
        let result = build_exec_invocations(&[invocation]).expect("ok");
        // The outer ScVal is the 3-tuple Vec; element[2] is the args Vec.
        let ScVal::Vec(Some(ref tuple)) = result[0] else {
            panic!("expected ScVal::Vec for tuple");
        };
        let ScVal::Vec(Some(ref args)) = tuple[2] else {
            panic!("expected ScVal::Vec for args at index 2");
        };
        assert_eq!(args.len(), 1, "one argument");
        match &args[0] {
            ScVal::I128(Int128Parts { hi, lo }) => {
                assert_eq!(*hi, 0, "hi must be 0 for positive int");
                assert_eq!(*lo, 42, "lo must equal the value");
            }
            other => panic!("expected ScVal::I128, got {other:?}"),
        }
    }

    /// A negative integer encodes as `ScVal::I128` with `hi=-1` (two's complement).
    #[test]
    fn json_args_negative_integer_encodes_as_i128_hi_minus_one() {
        use stellar_xdr::Int128Parts;
        let invocation = MulticallInvocation {
            target_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            fn_name: "transfer".to_owned(),
            // serde_json represents -1 as a negative number (as_u64 fails, as_i64 succeeds).
            args_json: serde_json::json!([-1i64]),
        };
        let result = build_exec_invocations(&[invocation]).expect("ok");
        let ScVal::Vec(Some(ref tuple)) = result[0] else {
            panic!("expected ScVal::Vec for tuple");
        };
        let ScVal::Vec(Some(ref args)) = tuple[2] else {
            panic!("expected ScVal::Vec for args at index 2");
        };
        assert_eq!(args.len(), 1);
        match &args[0] {
            ScVal::I128(Int128Parts { hi, lo }) => {
                // -1 in two's complement 128-bit: hi = -1 (all 1-bits), lo = 0xffff...ffff.
                assert_eq!(*hi, -1_i64, "hi must be -1 for negative integer");
                assert_eq!(
                    *lo,
                    (-1i64) as u64,
                    "lo must be the two's-complement bit pattern"
                );
            }
            other => panic!("expected ScVal::I128, got {other:?}"),
        }
    }

    /// Null at argument level encodes as `ScVal::Void`.
    #[test]
    fn json_args_null_element_encodes_as_void() {
        let invocation = MulticallInvocation {
            target_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            fn_name: "noop".to_owned(),
            args_json: serde_json::json!([null]),
        };
        let result = build_exec_invocations(&[invocation]).expect("ok");
        let ScVal::Vec(Some(ref tuple)) = result[0] else {
            panic!("expected ScVal::Vec for tuple");
        };
        let ScVal::Vec(Some(ref args)) = tuple[2] else {
            panic!("expected ScVal::Vec for args at index 2");
        };
        assert_eq!(args.len(), 1);
        assert!(
            matches!(args[0], ScVal::Void),
            "null arg element must encode as ScVal::Void"
        );
    }

    /// A JSON boolean argument is refused with a `build` phase error.
    #[test]
    fn json_args_bool_element_is_refused() {
        let invocation = MulticallInvocation {
            target_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            fn_name: "noop".to_owned(),
            args_json: serde_json::json!([true]),
        };
        let err = build_exec_invocations(&[invocation]).unwrap_err();
        match err {
            SaError::MulticallFailed {
                phase,
                ref redacted_reason,
                ..
            } => {
                assert_eq!(phase, "build");
                assert!(
                    redacted_reason.contains("Bool"),
                    "error must mention 'Bool': {redacted_reason}"
                );
            }
            other => panic!("expected MulticallFailed, got {other:?}"),
        }
    }

    /// A JSON object argument is refused with a `build` phase error.
    #[test]
    fn json_args_object_element_is_refused() {
        let invocation = MulticallInvocation {
            target_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            fn_name: "noop".to_owned(),
            args_json: serde_json::json!([{"key": "val"}]),
        };
        let err = build_exec_invocations(&[invocation]).unwrap_err();
        match err {
            SaError::MulticallFailed {
                phase,
                ref redacted_reason,
                ..
            } => {
                assert_eq!(phase, "build");
                assert!(
                    redacted_reason.contains("Object"),
                    "error must mention 'Object': {redacted_reason}"
                );
            }
            other => panic!("expected MulticallFailed, got {other:?}"),
        }
    }

    /// A nested JSON array argument is refused with a `build` phase error.
    #[test]
    fn json_args_nested_array_element_is_refused() {
        let invocation = MulticallInvocation {
            target_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            fn_name: "noop".to_owned(),
            args_json: serde_json::json!([[1, 2, 3]]),
        };
        let err = build_exec_invocations(&[invocation]).unwrap_err();
        match err {
            SaError::MulticallFailed {
                phase,
                ref redacted_reason,
                ..
            } => {
                assert_eq!(phase, "build");
                assert!(
                    redacted_reason.contains("Array"),
                    "error must mention 'Array': {redacted_reason}"
                );
            }
            other => panic!("expected MulticallFailed, got {other:?}"),
        }
    }

    /// A top-level non-array, non-null `args_json` (e.g. a string) causes a
    /// `build` phase error in `json_args_to_scval_vec`.
    #[test]
    fn json_args_top_level_string_is_refused() {
        let invocation = MulticallInvocation {
            target_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            fn_name: "noop".to_owned(),
            // This passes Step 1 validation (args_json.is_array() || args_json.is_null() passes
            // because is_null() is false and is_array() is false → rejected at Step 1 as invalid_args_json).
            // Actually Step 1 checks !is_array() && !is_null() → both false → err at step 1.
            // So we verify the Step 1 rejection path, not json_args_to_scval_vec internal.
            args_json: serde_json::json!("not_an_array"),
        };
        let err = build_exec_invocations(&[invocation]).unwrap_err();
        match err {
            SaError::MulticallFailed { phase, .. } => {
                assert_eq!(
                    phase, "build",
                    "top-level string args must be refused at build phase"
                );
            }
            other => panic!("expected MulticallFailed, got {other:?}"),
        }
    }

    // ── scval_discriminant_name ───────────────────────────────────────────────

    /// `scval_discriminant_name` returns the correct name for every ScVal variant
    /// that appears in the match arms (spot-check all branches).
    #[test]
    fn scval_discriminant_name_covers_all_named_variants() {
        use stellar_xdr::{
            Int128Parts, ScBytes, ScError, ScErrorCode, ScString, ScSymbol, ScVal, TimePoint,
            UInt128Parts,
        };

        let cases: &[(&str, ScVal)] = &[
            ("Bool", ScVal::Bool(true)),
            ("Void", ScVal::Void),
            // ScError is an enum: Value(ScErrorCode) variant.
            (
                "Error",
                ScVal::Error(ScError::Value(ScErrorCode::InvalidInput)),
            ),
            ("U32", ScVal::U32(0)),
            ("I32", ScVal::I32(0)),
            ("U64", ScVal::U64(0)),
            ("I64", ScVal::I64(0)),
            ("Timepoint", ScVal::Timepoint(TimePoint(0))),
            ("Duration", ScVal::Duration(stellar_xdr::Duration(0))),
            ("U128", ScVal::U128(UInt128Parts { hi: 0, lo: 0 })),
            ("I128", ScVal::I128(Int128Parts { hi: 0, lo: 0 })),
            ("Bytes", ScVal::Bytes(ScBytes(vec![].try_into().unwrap()))),
            (
                "String",
                ScVal::String(ScString(b"".as_slice().try_into().unwrap())),
            ),
            (
                "Symbol",
                ScVal::Symbol(ScSymbol(b"".as_slice().try_into().unwrap())),
            ),
            ("Vec", ScVal::Vec(None)),
            ("Map", ScVal::Map(None)),
            (
                "LedgerKeyContractInstance",
                ScVal::LedgerKeyContractInstance,
            ),
        ];

        for (expected_name, scval) in cases {
            assert_eq!(
                scval_discriminant_name(scval),
                *expected_name,
                "scval_discriminant_name mismatch for {expected_name}"
            );
        }
    }

    // ── build_inner_results — ScVal::Vec(None) path ───────────────────────────

    /// `ScVal::Vec(None)` return value fires `XdrEmptyVec` post-submit error.
    #[test]
    fn build_inner_results_rejects_vec_none_with_xdr_empty_vec_kind() {
        let err = build_inner_results(&[], &ScVal::Vec(None), FAKE_REDACTED_HASH).unwrap_err();
        match err {
            SaError::MulticallFailed {
                phase,
                post_submit_kind: Some(PostSubmitVerificationKind::XdrEmptyVec),
                ..
            } => {
                assert_eq!(phase, "post_submit_verification");
            }
            other => panic!("expected MulticallFailed with XdrEmptyVec kind, got {other:?}"),
        }
    }

    // ── unregister_force — direct passphrase match (fallback arm) ────────────

    /// `unregister_force` also matches when the stored `network_passphrase` equals
    /// the supplied `network_safename` verbatim (the fallback `||` arm in the
    /// position predicate). This covers entries whose passphrase was stored as
    /// a raw safename due to a partial-load from a corrupted TOML file.
    #[test]
    fn registry_unregister_force_direct_passphrase_match_succeeds() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let mut reg = MulticallRegistry::load(&path).expect("load");
        // Insert an entry where the passphrase IS the safename (simulating a
        // corruption-recovery scenario where the TOML had a raw safename as passphrase).
        let raw_safename = "my-corrupt-network";
        reg.entries.push(MulticallRegistryEntry {
            network_passphrase: raw_safename.to_owned(),
            address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            wasm_sha256: MULTICALL_WASM_SHA256.to_owned(),
        });
        // The derived safename of "my-corrupt-network" is "my-corrupt-network"
        // (all chars are already alnum/-). The direct passphrase match arm fires.
        let raw = reg
            .unregister_force(raw_safename)
            .expect("unregister_force via direct match");
        assert_eq!(raw.network_passphrase, raw_safename);
        assert!(reg.entries.is_empty(), "entry must be removed");
    }

    // ── classify_required_checks — non-contract ScAddress ────────────────────

    /// `classify_required_checks` returns `&[]` for a non-`InvokeContract`
    /// host-function (e.g. `UploadContractWasm`).
    #[test]
    fn classify_required_checks_non_invoke_contract_returns_empty() {
        use stellar_xdr::{BytesM, HostFunction};
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("networks.toml");
        let reg = MulticallRegistry::load(&path).expect("load");
        // UploadContractWasm is not InvokeContract → must return &[].
        let hf = HostFunction::UploadContractWasm(BytesM::default());
        let checks = classify_required_checks(&hf, &reg, "Test SDF Network ; September 2015");
        assert_eq!(checks, &[] as &[&str]);
    }
}
