//! Deployed-contract registry (`~/.config/stellar-agent/networks.toml`).
//!
//! Maps Stellar network passphrases to the wallet's per-network deployed
//! contracts — the WebAuthn verifier, the Ed25519 verifier, and the
//! spending-limit policy — together with their vendored WASM SHA-256
//! fingerprints.  Backed by a TOML file at the OS-conventional config path
//! (`~/.config/stellar-agent/networks.toml` on macOS/Linux, overridable via
//! `STELLAR_AGENT_NETWORKS_TOML` for tests and non-standard deployments).
//!
//! # Additive schema contract
//!
//! Each per-network record has three independently-optional contract slots
//! (WebAuthn verifier, Ed25519 verifier, spending-limit policy).  The on-disk
//! TOML fields are all optional with `#[serde(default, skip_serializing_if =
//! "Option::is_none")]`, so:
//!
//! - TOML written before the schema was widened (WebAuthn-only, carrying the
//!   three `webauthn_verifier_*` fields) parses unchanged.
//! - A network entry with only an Ed25519 verifier, only a spending-limit
//!   policy, or any subset is representable; absent slots are omitted from the
//!   serialised output rather than written as explicit nulls.
//! - Adding a new contract slot never requires migrating an existing file.
//!
//! # Key types
//!
//! - [`VerifierRegistry`] — the registry itself; load with [`VerifierRegistry::open`],
//!   mutate with the `record_*` methods, persist with [`VerifierRegistry::persist`].
//! - [`WebAuthnVerifierEntry`] / [`Ed25519VerifierEntry`] /
//!   [`SpendingLimitPolicyEntry`] — the three per-network contract records.
//! - [`RecordOutcome`] — result of a `record_*` call.
//!
//! # Invariants enforced
//!
//! - **Sha256-drift guard**: re-recording a verifier for a network that already has an
//!   entry with a DIFFERENT `wasm_sha256` is refused with
//!   [`crate::SaError::WebAuthnVerifierSha256Drift`].  This prevents silent re-deployment
//!   of a different WASM version against a stale registry entry.
//! - **Idempotency**: re-recording with the same `wasm_sha256` returns
//!   [`RecordOutcome::AlreadyRecorded`] and leaves the original entry (including its
//!   `deployed_at_unix_ms` timestamp) unchanged.
//! - **Atomic write**: [`VerifierRegistry::persist`] writes to a temp file then renames
//!   to atomically replace the registry on disk.  Parent directory is created with mode
//!   `0700`; file is written with mode `0600` on POSIX.
//!
//! # File schema (TOML)
//!
//! ```toml
//! # ~/.config/stellar-agent/networks.toml
//! [networks."Test SDF Network ; September 2015"]
//! webauthn_verifier_address = "CABC...XYZ"
//! webauthn_verifier_wasm_sha256 = "9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7"
//! webauthn_verifier_deployed_at_unix_ms = 1747000000000
//!
//! [networks."Public Global Stellar Network ; September 2015"]
//! # (not yet configured)
//! ```
//!
//! Network passphrase is the TOML table key and is the canonical source of truth for
//! network identity.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::SaError;

/// Environment-variable name used to override the default registry path.
///
/// When set, [`VerifierRegistry::open`] reads from (and [`VerifierRegistry::persist`]
/// writes to) the path supplied by this variable rather than the OS-conventional default.
///
/// Primarily intended for integration tests that must not touch `~/.config`.
pub const STELLAR_AGENT_NETWORKS_TOML_ENV: &str = "STELLAR_AGENT_NETWORKS_TOML";

// ── Outcome type ──────────────────────────────────────────────────────────────

/// Outcome of a [`VerifierRegistry::record_webauthn_verifier`] call.
///
/// # Examples
///
/// ```
/// # use stellar_agent_smart_account::verifiers::{VerifierRegistry, RecordOutcome};
/// # use std::path::PathBuf;
/// # let dir = tempfile::tempdir().expect("tempdir");
/// # let path = dir.path().join("networks.toml");
/// let mut reg = VerifierRegistry::open_at(path).expect("open");
/// let outcome = reg
///     .record_webauthn_verifier(
///         "Test SDF Network ; September 2015",
///         "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
///         "9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7".to_owned(),
///     )
///     .expect("record");
/// assert_eq!(outcome, RecordOutcome::Recorded);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordOutcome {
    /// The verifier entry was newly written to the registry.
    Recorded,
    /// An entry with an identical `wasm_sha256` already existed; no change was made.
    AlreadyRecorded,
}

// ── Entry type ────────────────────────────────────────────────────────────────

/// A single network → WebAuthn-verifier mapping entry.
///
/// All fields are non-secret: the contract address is a C-strkey (public ledger
/// data), the WASM sha256 is a cryptographic digest of public WASM bytes, and the
/// deploy timestamp is a public event time.
///
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnVerifierEntry {
    /// Deployed verifier contract C-strkey on the Stellar network.
    ///
    /// Full C-strkey (56 characters, starting with `C`).  Not redacted here;
    /// call sites that log this value apply
    /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
    pub address: String,

    /// SHA-256 of the vendored WASM that was deployed, as 64-char lowercase hex.
    ///
    /// Verified against `crate::webauthn_verifier::WEBAUTHN_VERIFIER_WASM_SHA256`
    /// at deploy time by the runtime SHA gate in `deploy_webauthn_verifier`.
    pub wasm_sha256: String,

    /// Unix timestamp in milliseconds at which this entry was recorded.
    ///
    /// Populated by [`VerifierRegistry::record_webauthn_verifier`] from
    /// `SystemTime::now()`.  Used for forensic correlation in operator runbooks.
    pub deployed_at_unix_ms: u64,
}

/// A single network → Ed25519-verifier mapping entry.
///
/// Mirrors [`WebAuthnVerifierEntry`]: all fields are non-secret (a contract
/// C-strkey, a WASM sha256 digest, and a deploy timestamp).  Records the
/// per-network deployment of the OZ `multisig-ed25519-verifier-example`
/// contract used by External-Ed25519 signers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519VerifierEntry {
    /// Deployed Ed25519-verifier contract C-strkey on the Stellar network.
    ///
    /// Full C-strkey (56 characters, starting with `C`).  Not redacted here;
    /// call sites that log this value apply
    /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
    pub address: String,

    /// SHA-256 of the vendored WASM that was deployed, as 64-char lowercase hex.
    ///
    /// Verified against `crate::ed25519_verifier::ED25519_VERIFIER_WASM_SHA256`
    /// at deploy time by the runtime SHA gate in `deploy_ed25519_verifier`.
    pub wasm_sha256: String,

    /// Unix timestamp in milliseconds at which this entry was recorded.
    pub deployed_at_unix_ms: u64,
}

/// A single network → spending-limit-policy mapping entry.
///
/// Mirrors [`WebAuthnVerifierEntry`]: all fields are non-secret.  Records the
/// per-network deployment of the OZ `multisig-spending-limit-policy-example`
/// singleton.  One deployed instance serves every account and context rule on
/// the network (the policy keys all state by
/// `AccountContext(smart_account, context_rule_id)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendingLimitPolicyEntry {
    /// Deployed spending-limit-policy contract C-strkey on the Stellar network.
    ///
    /// Full C-strkey (56 characters, starting with `C`).  Not redacted here.
    pub address: String,

    /// SHA-256 of the vendored WASM that was deployed, as 64-char lowercase hex.
    ///
    /// Verified against
    /// `crate::spending_limit_policy::SPENDING_LIMIT_POLICY_WASM_SHA256` at
    /// deploy time by the runtime SHA gate in `deploy_spending_limit_policy`.
    pub wasm_sha256: String,

    /// Unix timestamp in milliseconds at which this entry was recorded.
    pub deployed_at_unix_ms: u64,
}

// ── In-memory record ──────────────────────────────────────────────────────────

/// In-memory per-network record aggregating all deployed contracts.
///
/// Each contract slot is independently optional: a network may have only a
/// WebAuthn verifier, only an Ed25519 verifier, only a spending-limit policy,
/// any combination, or none.  This is the load-bearing part of the additive
/// schema — a network entry is representable with any subset present.
#[derive(Debug, Clone, Default)]
struct NetworkRecord {
    /// Deployed WebAuthn verifier, if any.
    webauthn: Option<WebAuthnVerifierEntry>,
    /// Deployed Ed25519 verifier, if any.
    ed25519: Option<Ed25519VerifierEntry>,
    /// Deployed spending-limit policy, if any.
    spending_limit_policy: Option<SpendingLimitPolicyEntry>,
}

impl NetworkRecord {
    /// Returns `true` when no contract slot is populated.
    fn is_empty(&self) -> bool {
        self.webauthn.is_none() && self.ed25519.is_none() && self.spending_limit_policy.is_none()
    }
}

// ── Wire schema for TOML file ─────────────────────────────────────────────────

/// On-disk TOML schema root: `{ networks: { "<passphrase>": <NetworkEntry> } }`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct RegistryFile {
    /// Map from network passphrase to the network-specific entries.
    #[serde(default)]
    networks: HashMap<String, NetworkEntry>,
}

/// Per-network fields in the on-disk TOML representation.
///
/// Uses flat snake_case field names with a per-contract prefix (keeps all
/// contract fields at the same TOML level).  Every field is optional with
/// `#[serde(default, skip_serializing_if = "Option::is_none")]`, so:
///
/// - TOML written before the schema widening (WebAuthn-only, with the three
///   `webauthn_verifier_*` fields present) parses unchanged.
/// - A network entry with only an Ed25519 verifier, only a spending-limit
///   policy, or any subset is representable, and absent contract slots are
///   omitted from the serialised output rather than written as explicit nulls.
///
/// A contract slot is materialised into its typed entry only when all three of
/// its fields are present; a partially-populated slot (e.g. an address without a
/// sha256) is treated as absent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct NetworkEntry {
    /// Deployed WebAuthn-verifier contract C-strkey.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    webauthn_verifier_address: Option<String>,
    /// SHA-256 of the deployed WebAuthn-verifier WASM, 64-char lowercase hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    webauthn_verifier_wasm_sha256: Option<String>,
    /// Unix timestamp in milliseconds when the WebAuthn-verifier entry was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    webauthn_verifier_deployed_at_unix_ms: Option<u64>,

    /// Deployed Ed25519-verifier contract C-strkey.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ed25519_verifier_address: Option<String>,
    /// SHA-256 of the deployed Ed25519-verifier WASM, 64-char lowercase hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ed25519_verifier_wasm_sha256: Option<String>,
    /// Unix timestamp in milliseconds when the Ed25519-verifier entry was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ed25519_verifier_deployed_at_unix_ms: Option<u64>,

    /// Deployed spending-limit-policy contract C-strkey.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spending_limit_policy_address: Option<String>,
    /// SHA-256 of the deployed spending-limit-policy WASM, 64-char lowercase hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spending_limit_policy_wasm_sha256: Option<String>,
    /// Unix timestamp in milliseconds when the spending-limit-policy entry was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spending_limit_policy_deployed_at_unix_ms: Option<u64>,
}

impl From<&NetworkRecord> for NetworkEntry {
    fn from(r: &NetworkRecord) -> Self {
        let mut e = NetworkEntry::default();
        if let Some(w) = &r.webauthn {
            e.webauthn_verifier_address = Some(w.address.clone());
            e.webauthn_verifier_wasm_sha256 = Some(w.wasm_sha256.clone());
            e.webauthn_verifier_deployed_at_unix_ms = Some(w.deployed_at_unix_ms);
        }
        if let Some(v) = &r.ed25519 {
            e.ed25519_verifier_address = Some(v.address.clone());
            e.ed25519_verifier_wasm_sha256 = Some(v.wasm_sha256.clone());
            e.ed25519_verifier_deployed_at_unix_ms = Some(v.deployed_at_unix_ms);
        }
        if let Some(p) = &r.spending_limit_policy {
            e.spending_limit_policy_address = Some(p.address.clone());
            e.spending_limit_policy_wasm_sha256 = Some(p.wasm_sha256.clone());
            e.spending_limit_policy_deployed_at_unix_ms = Some(p.deployed_at_unix_ms);
        }
        e
    }
}

impl From<NetworkEntry> for NetworkRecord {
    fn from(n: NetworkEntry) -> Self {
        let webauthn = match (
            n.webauthn_verifier_address,
            n.webauthn_verifier_wasm_sha256,
            n.webauthn_verifier_deployed_at_unix_ms,
        ) {
            (Some(address), Some(wasm_sha256), Some(deployed_at_unix_ms)) => {
                Some(WebAuthnVerifierEntry {
                    address,
                    wasm_sha256,
                    deployed_at_unix_ms,
                })
            }
            _ => None,
        };
        let ed25519 = match (
            n.ed25519_verifier_address,
            n.ed25519_verifier_wasm_sha256,
            n.ed25519_verifier_deployed_at_unix_ms,
        ) {
            (Some(address), Some(wasm_sha256), Some(deployed_at_unix_ms)) => {
                Some(Ed25519VerifierEntry {
                    address,
                    wasm_sha256,
                    deployed_at_unix_ms,
                })
            }
            _ => None,
        };
        let spending_limit_policy = match (
            n.spending_limit_policy_address,
            n.spending_limit_policy_wasm_sha256,
            n.spending_limit_policy_deployed_at_unix_ms,
        ) {
            (Some(address), Some(wasm_sha256), Some(deployed_at_unix_ms)) => {
                Some(SpendingLimitPolicyEntry {
                    address,
                    wasm_sha256,
                    deployed_at_unix_ms,
                })
            }
            _ => None,
        };
        Self {
            webauthn,
            ed25519,
            spending_limit_policy,
        }
    }
}

// ── Registry ──────────────────────────────────────────────────────────────────

/// WebAuthn-verifier contract registry.
///
/// Backed by `~/.config/stellar-agent/networks.toml` (or `STELLAR_AGENT_NETWORKS_TOML`
/// override).  Load with [`VerifierRegistry::open`]; persist with
/// [`VerifierRegistry::persist`].
///
/// # Thread safety
///
/// `VerifierRegistry` is not `Sync` — it is intended for use from a single operator
/// CLI invocation.  Concurrent mutation across threads or processes is not supported;
/// the TOML file is NOT protected by an advisory lock.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_smart_account::verifiers::VerifierRegistry;
///
/// let mut reg = VerifierRegistry::open().expect("load registry");
/// if let Some(entry) = reg.webauthn_verifier_for("Test SDF Network ; September 2015") {
///     println!("verifier: {}", entry.address);
/// }
/// ```
#[derive(Debug)]
pub struct VerifierRegistry {
    /// The resolved path to `networks.toml` (used by [`VerifierRegistry::persist`]).
    path: PathBuf,
    /// In-memory per-network records keyed by network passphrase.
    entries: HashMap<String, NetworkRecord>,
}

impl VerifierRegistry {
    /// Opens the registry from the default OS-config path or `STELLAR_AGENT_NETWORKS_TOML`
    /// env-var override.
    ///
    /// If the file does not exist the registry is initialised empty; calling
    /// [`VerifierRegistry::persist`] will create the file.
    ///
    /// # Default path resolution
    ///
    /// | Platform | Default path |
    /// |----------|--------------|
    /// | macOS    | `~/Library/Application Support/stellar-agent/networks.toml` |
    /// | Linux    | `~/.config/stellar-agent/networks.toml` |
    /// | Windows  | `%APPDATA%\stellar-agent\networks.toml` |
    ///
    /// The env-var `STELLAR_AGENT_NETWORKS_TOML` overrides the platform default when set.
    ///
    /// # Errors
    ///
    /// - [`SaError::NetworksTomlIo`] — the file exists but cannot be read.
    /// - [`SaError::NetworksTomlParse`] — the file exists but contains invalid TOML.
    /// - [`SaError::NetworksTomlIo`] — the default config directory cannot be
    ///   determined (XDG / home-dir resolution failure).
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_smart_account::verifiers::VerifierRegistry;
    ///
    /// let reg = VerifierRegistry::open().expect("open registry");
    /// ```
    pub fn open() -> Result<Self, SaError> {
        let path = resolve_default_path()?;
        Self::open_at(path)
    }

    /// Opens the registry from an explicit filesystem path.
    ///
    /// This is the primary test-override entry point: tests pass a temporary-directory
    /// path to avoid touching `~/.config`.
    ///
    /// If the file does not exist the registry is initialised empty; calling
    /// [`VerifierRegistry::persist`] will create the file.
    ///
    /// # Errors
    ///
    /// - [`SaError::NetworksTomlIo`] — the file exists but cannot be read.
    /// - [`SaError::NetworksTomlParse`] — the file exists but contains invalid TOML.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stellar_agent_smart_account::verifiers::VerifierRegistry;
    /// # use std::path::PathBuf;
    /// # let dir = tempfile::tempdir().expect("tempdir");
    /// # let path = dir.path().join("networks.toml");
    /// let reg = VerifierRegistry::open_at(path).expect("open registry");
    /// assert!(reg.webauthn_verifier_for("Test SDF Network ; September 2015").is_none());
    /// ```
    pub fn open_at(path: PathBuf) -> Result<Self, SaError> {
        if !path.exists() {
            // File absent → empty registry; persist() will create it.
            return Ok(Self {
                path,
                entries: HashMap::new(),
            });
        }

        let contents = std::fs::read_to_string(&path).map_err(|e| SaError::NetworksTomlIo {
            source: e,
            path: path.clone(),
        })?;

        let file: RegistryFile =
            toml::from_str(&contents).map_err(|e| SaError::NetworksTomlParse {
                source: e,
                path: path.clone(),
            })?;

        let entries = file
            .networks
            .into_iter()
            .map(|(passphrase, net)| (passphrase, NetworkRecord::from(net)))
            .collect();

        Ok(Self { path, entries })
    }

    /// Returns the [`WebAuthnVerifierEntry`] for the given network passphrase, or `None`
    /// if no entry is recorded.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stellar_agent_smart_account::verifiers::VerifierRegistry;
    /// # use std::path::PathBuf;
    /// # let dir = tempfile::tempdir().expect("tempdir");
    /// # let path = dir.path().join("networks.toml");
    /// let reg = VerifierRegistry::open_at(path).expect("open");
    /// assert!(reg.webauthn_verifier_for("Test SDF Network ; September 2015").is_none());
    /// ```
    #[must_use]
    pub fn webauthn_verifier_for(
        &self,
        network_passphrase: &str,
    ) -> Option<&WebAuthnVerifierEntry> {
        self.entries
            .get(network_passphrase)
            .and_then(|r| r.webauthn.as_ref())
    }

    /// Returns the [`Ed25519VerifierEntry`] for the given network passphrase, or
    /// `None` if no Ed25519 verifier is recorded.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stellar_agent_smart_account::verifiers::VerifierRegistry;
    /// # let dir = tempfile::tempdir().expect("tempdir");
    /// # let path = dir.path().join("networks.toml");
    /// let reg = VerifierRegistry::open_at(path).expect("open");
    /// assert!(reg.ed25519_verifier_for("Test SDF Network ; September 2015").is_none());
    /// ```
    #[must_use]
    pub fn ed25519_verifier_for(&self, network_passphrase: &str) -> Option<&Ed25519VerifierEntry> {
        self.entries
            .get(network_passphrase)
            .and_then(|r| r.ed25519.as_ref())
    }

    /// Returns the [`SpendingLimitPolicyEntry`] for the given network passphrase,
    /// or `None` if no spending-limit policy is recorded.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stellar_agent_smart_account::verifiers::VerifierRegistry;
    /// # let dir = tempfile::tempdir().expect("tempdir");
    /// # let path = dir.path().join("networks.toml");
    /// let reg = VerifierRegistry::open_at(path).expect("open");
    /// assert!(reg.spending_limit_policy_for("Test SDF Network ; September 2015").is_none());
    /// ```
    #[must_use]
    pub fn spending_limit_policy_for(
        &self,
        network_passphrase: &str,
    ) -> Option<&SpendingLimitPolicyEntry> {
        self.entries
            .get(network_passphrase)
            .and_then(|r| r.spending_limit_policy.as_ref())
    }

    /// Records a newly deployed WebAuthn-verifier entry for the given network.
    ///
    /// # Idempotency
    ///
    /// If an entry already exists for `network_passphrase` with the **same** `wasm_sha256`
    /// as `wasm_sha256`, the existing entry is preserved (including its original
    /// `deployed_at_unix_ms`) and [`RecordOutcome::AlreadyRecorded`] is returned.
    /// [`VerifierRegistry::persist`] is a no-op in this case.
    ///
    /// # Sha256-drift guard
    ///
    /// If an entry already exists for `network_passphrase` with a **different** `wasm_sha256`,
    /// the call is refused with [`SaError::WebAuthnVerifierSha256Drift`].  The operator must
    /// re-vendor the WASM, update `WEBAUTHN_VERIFIER_WASM_SHA256`, and redeploy before recording
    /// a new entry.
    ///
    /// # Errors
    ///
    /// - [`SaError::WebAuthnVerifierSha256Drift`] — existing entry for this network uses a
    ///   different `wasm_sha256`.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stellar_agent_smart_account::verifiers::{VerifierRegistry, RecordOutcome};
    /// # let dir = tempfile::tempdir().expect("tempdir");
    /// # let path = dir.path().join("networks.toml");
    /// let mut reg = VerifierRegistry::open_at(path).expect("open");
    /// let addr = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned();
    /// let sha = "9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7".to_owned();
    /// let outcome1 = reg.record_webauthn_verifier("Test SDF Network ; September 2015", addr.clone(), sha.clone()).expect("record");
    /// let outcome2 = reg.record_webauthn_verifier("Test SDF Network ; September 2015", addr, sha).expect("idempotent");
    /// assert_eq!(outcome1, RecordOutcome::Recorded);
    /// assert_eq!(outcome2, RecordOutcome::AlreadyRecorded);
    /// ```
    pub fn record_webauthn_verifier(
        &mut self,
        network_passphrase: &str,
        address: String,
        wasm_sha256: String,
    ) -> Result<RecordOutcome, SaError> {
        let record = self
            .entries
            .entry(network_passphrase.to_owned())
            .or_default();
        if let Some(existing) = &record.webauthn {
            if existing.wasm_sha256 == wasm_sha256 {
                // Same sha256 → idempotent; no modification needed.
                return Ok(RecordOutcome::AlreadyRecorded);
            }
            // Different sha256 → refuse.
            return Err(SaError::WebAuthnVerifierSha256Drift {
                network: network_passphrase.to_owned(),
                recorded: existing.wasm_sha256.clone(),
                attempted: wasm_sha256,
            });
        }

        record.webauthn = Some(WebAuthnVerifierEntry {
            address,
            wasm_sha256,
            deployed_at_unix_ms: unix_now_ms(),
        });
        Ok(RecordOutcome::Recorded)
    }

    /// Records a newly deployed Ed25519-verifier entry for the given network.
    ///
    /// Mirrors [`VerifierRegistry::record_webauthn_verifier`]: idempotent when
    /// the `wasm_sha256` matches an existing Ed25519-verifier entry for the
    /// network, and refused with [`SaError::Ed25519VerifierSha256Drift`] when an
    /// existing entry uses a different `wasm_sha256`.  The record is stored
    /// alongside (not replacing) any existing WebAuthn-verifier or
    /// spending-limit-policy entry for the same network.
    ///
    /// # Errors
    ///
    /// - [`SaError::Ed25519VerifierSha256Drift`] — existing Ed25519-verifier
    ///   entry for this network uses a different `wasm_sha256`.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stellar_agent_smart_account::verifiers::{VerifierRegistry, RecordOutcome};
    /// # let dir = tempfile::tempdir().expect("tempdir");
    /// # let path = dir.path().join("networks.toml");
    /// let mut reg = VerifierRegistry::open_at(path).expect("open");
    /// let addr = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned();
    /// let sha = "ea13b07083a8275e7bade954e4ccc1827495f253c18dc06edcc49104c11fb725".to_owned();
    /// let outcome = reg
    ///     .record_ed25519_verifier("Test SDF Network ; September 2015", addr, sha)
    ///     .expect("record");
    /// assert_eq!(outcome, RecordOutcome::Recorded);
    /// ```
    pub fn record_ed25519_verifier(
        &mut self,
        network_passphrase: &str,
        address: String,
        wasm_sha256: String,
    ) -> Result<RecordOutcome, SaError> {
        let record = self
            .entries
            .entry(network_passphrase.to_owned())
            .or_default();
        if let Some(existing) = &record.ed25519 {
            if existing.wasm_sha256 == wasm_sha256 {
                return Ok(RecordOutcome::AlreadyRecorded);
            }
            return Err(SaError::Ed25519VerifierSha256Drift {
                network: network_passphrase.to_owned(),
                recorded: existing.wasm_sha256.clone(),
                attempted: wasm_sha256,
            });
        }

        record.ed25519 = Some(Ed25519VerifierEntry {
            address,
            wasm_sha256,
            deployed_at_unix_ms: unix_now_ms(),
        });
        Ok(RecordOutcome::Recorded)
    }

    /// Records a newly deployed spending-limit-policy entry for the given
    /// network.
    ///
    /// Mirrors [`VerifierRegistry::record_webauthn_verifier`]: idempotent when
    /// the `wasm_sha256` matches an existing spending-limit-policy entry for the
    /// network, and refused with [`SaError::SpendingLimitPolicySha256Drift`] when
    /// an existing entry uses a different `wasm_sha256`.  The record is stored
    /// alongside (not replacing) any existing verifier entry for the network.
    ///
    /// # Errors
    ///
    /// - [`SaError::SpendingLimitPolicySha256Drift`] — existing
    ///   spending-limit-policy entry for this network uses a different
    ///   `wasm_sha256`.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stellar_agent_smart_account::verifiers::{VerifierRegistry, RecordOutcome};
    /// # let dir = tempfile::tempdir().expect("tempdir");
    /// # let path = dir.path().join("networks.toml");
    /// let mut reg = VerifierRegistry::open_at(path).expect("open");
    /// let addr = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned();
    /// let sha = "0e8da0ccff5c444520085ac1973d3c8023fdd04f727ee11ae7290a49dffbbaf5".to_owned();
    /// let outcome = reg
    ///     .record_spending_limit_policy("Test SDF Network ; September 2015", addr, sha)
    ///     .expect("record");
    /// assert_eq!(outcome, RecordOutcome::Recorded);
    /// ```
    pub fn record_spending_limit_policy(
        &mut self,
        network_passphrase: &str,
        address: String,
        wasm_sha256: String,
    ) -> Result<RecordOutcome, SaError> {
        let record = self
            .entries
            .entry(network_passphrase.to_owned())
            .or_default();
        if let Some(existing) = &record.spending_limit_policy {
            if existing.wasm_sha256 == wasm_sha256 {
                return Ok(RecordOutcome::AlreadyRecorded);
            }
            return Err(SaError::SpendingLimitPolicySha256Drift {
                network: network_passphrase.to_owned(),
                recorded: existing.wasm_sha256.clone(),
                attempted: wasm_sha256,
            });
        }

        record.spending_limit_policy = Some(SpendingLimitPolicyEntry {
            address,
            wasm_sha256,
            deployed_at_unix_ms: unix_now_ms(),
        });
        Ok(RecordOutcome::Recorded)
    }

    /// Persists the registry to disk.
    ///
    /// Uses an atomic write: the TOML is written to a sibling temp file in the same
    /// parent directory, then renamed into place.  The temp file (and final file) are
    /// created with mode `0600` on POSIX.  The parent directory is created (recursively)
    /// with mode `0700` on POSIX if it does not already exist.
    ///
    /// # Errors
    ///
    /// - [`SaError::NetworksTomlIo`] — any I/O failure during directory creation,
    ///   temp-file write, `fsync`, or rename.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stellar_agent_smart_account::verifiers::{VerifierRegistry, RecordOutcome};
    /// # let dir = tempfile::tempdir().expect("tempdir");
    /// # let path = dir.path().join("networks.toml");
    /// let mut reg = VerifierRegistry::open_at(path.clone()).expect("open");
    /// reg.record_webauthn_verifier(
    ///     "Test SDF Network ; September 2015",
    ///     "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
    ///     "9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7".to_owned(),
    /// ).expect("record");
    /// reg.persist().expect("persist");
    /// assert!(path.exists());
    /// ```
    pub fn persist(&self) -> Result<(), SaError> {
        let path = &self.path;

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

        // Build the TOML file contents.  Fully-empty records (no contract slot
        // populated) are omitted so a transiently-created-then-emptied entry
        // does not persist an all-null network table.
        let file = RegistryFile {
            networks: self
                .entries
                .iter()
                .filter(|(_, v)| !v.is_empty())
                .map(|(k, v)| (k.clone(), NetworkEntry::from(v)))
                .collect(),
        };

        let toml_str = toml::to_string_pretty(&file).map_err(|e| {
            // toml::ser::Error does not implement std::io::Error; wrap as io::Error.
            SaError::NetworksTomlIo {
                source: std::io::Error::other(e.to_string()),
                path: path.clone(),
            }
        })?;

        // Atomic write: write to temp file, fsync, rename.
        atomic_write_0600(path, toml_str.as_bytes()).map_err(|e| SaError::NetworksTomlIo {
            source: e,
            path: path.clone(),
        })?;

        Ok(())
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Returns the current wall-clock time as Unix milliseconds.
///
/// Falls back to `0` if `SystemTime::now()` predates the Unix epoch (impossible in
/// practice; guarded for forward-compat with no-std / mocked time environments).
fn unix_now_ms() -> u64 {
    unix_duration_to_ms(SystemTime::now().duration_since(UNIX_EPOCH))
}

fn unix_duration_to_ms(duration: Result<Duration, std::time::SystemTimeError>) -> u64 {
    let duration = match duration {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "unix_now_ms: SystemTime::now() before UNIX_EPOCH; falling back to 0ms",
            );
            Duration::ZERO
        }
    };
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

/// Resolves the default registry path from the OS config directory or `STELLAR_AGENT_NETWORKS_TOML`.
///
/// # Errors
///
/// Returns [`SaError::NetworksTomlIo`] if neither the env-var override nor the
/// OS config directory can be resolved.
fn resolve_default_path() -> Result<PathBuf, SaError> {
    let env_override = std::env::var(STELLAR_AGENT_NETWORKS_TOML_ENV).ok();
    resolve_default_path_with_override(env_override.as_deref())
}

/// Inner helper for [`resolve_default_path`] that takes the env-var value as a
/// pure parameter.
///
/// Split out of `resolve_default_path` so the env-var override branch is unit-
/// testable without process-global env-var mutation (which is `unsafe fn` in
/// Rust 2024 and incompatible with the crate's `#![forbid(unsafe_code)]`).  The
/// outer function is a thin wrapper that reads `std::env::var` and forwards.
fn resolve_default_path_with_override(env_override: Option<&str>) -> Result<PathBuf, SaError> {
    if let Some(val) = env_override {
        return Ok(PathBuf::from(val));
    }

    let config_dir = dirs_config_dir().ok_or_else(|| SaError::NetworksTomlIo {
        source: std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine OS config directory; set STELLAR_AGENT_NETWORKS_TOML",
        ),
        path: PathBuf::from("<config-dir>"),
    })?;

    Ok(config_dir.join("stellar-agent").join("networks.toml"))
}

/// Returns the OS-conventional user config directory.
///
/// | Platform | Path |
/// |----------|------|
/// | macOS    | `~/Library/Application Support` |
/// | Linux    | `~/.config` (XDG `$XDG_CONFIG_HOME` if set) |
/// | Windows  | `%APPDATA%` |
///
/// Returns `None` when home-directory resolution fails (rare but possible in
/// container / CI environments with no `$HOME`).
fn dirs_config_dir() -> Option<PathBuf> {
    // `directories` crate: ProjectDirs and BaseDirs resolution per OS conventions.
    // We use `directories::BaseDirs::new()` which gives XDG config on Linux,
    // ~/Library/Application Support on macOS, %APPDATA% on Windows.
    directories::BaseDirs::new().map(|b| b.config_dir().to_path_buf())
}

/// Creates a directory (and all parents) with mode `0700` on POSIX, or using the
/// default OS permissions on non-POSIX platforms.
///
/// # Errors
///
/// Returns `io::Error` on any filesystem failure.
fn create_dir_0700(dir: &std::path::Path) -> Result<(), std::io::Error> {
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

/// Writes `contents` to `path` atomically via a sibling temp file.
///
/// 1. Create a named temp file in the same directory as `path` (avoids cross-device
///    rename issues; the rename is then intra-filesystem and atomic on POSIX).
/// 2. Set the temp file to mode `0600` on POSIX before writing.
/// 3. Write + `sync_data`.
/// 4. Rename the temp file over `path`.
///
/// On non-POSIX platforms step 2 is skipped (mode bits are not meaningful on Windows).
///
/// # Errors
///
/// Returns `io::Error` on any filesystem failure.
fn atomic_write_0600(path: &std::path::Path, contents: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write as _;

    // The parent directory must exist before creating the temp file.
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "registry path has no parent directory",
        )
    })?;

    // Create a named temp file in the same directory.
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;

    // Set mode 0600 on POSIX before writing any data.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }

    tmp.write_all(contents)?;
    tmp.as_file().sync_data()?;

    // Atomically rename into place.
    tmp.persist(path).map_err(|e| e.error)?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::expect_used, reason = "test-only")]
    #![allow(
        clippy::panic,
        reason = "test-only: failure-arm assertion for unexpected error variants"
    )]

    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::*;
    use crate::SaError;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn testnet() -> &'static str {
        "Test SDF Network ; September 2015"
    }

    fn fake_address() -> String {
        "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned()
    }

    fn fake_sha256() -> String {
        "9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7".to_owned()
    }

    fn alt_sha256() -> String {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()
    }

    /// Creates a temp dir and returns the TempDir guard + a path inside it.
    fn temp_registry() -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("networks.toml");
        (dir, path)
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn unix_duration_to_ms_error_path_returns_zero() {
        let before_epoch = UNIX_EPOCH.duration_since(UNIX_EPOCH + Duration::from_millis(1));

        assert_eq!(unix_duration_to_ms(before_epoch), 0);
    }

    /// `open_at()` on a non-existent path returns an empty registry; `persist()`
    /// creates the file and sets the parent directory to mode `0700` on Unix.
    #[test]
    fn open_creates_empty_registry_when_file_absent() {
        let (_guard, path) = temp_registry();
        assert!(
            !path.exists(),
            "pre-condition: file must not exist before open"
        );

        let reg = VerifierRegistry::open_at(path.clone()).expect("open empty");
        assert!(
            reg.webauthn_verifier_for(testnet()).is_none(),
            "empty registry must return None for any passphrase"
        );

        reg.persist().expect("persist empty registry");
        assert!(path.exists(), "persist must create the file");

        // Check parent dir permissions on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let parent_meta = std::fs::metadata(path.parent().unwrap()).unwrap();
            // The temp dir itself is created by `tempfile::tempdir()` with 0700;
            // our `create_dir_0700` is called on the parent but the dir already exists.
            // We assert the FILE permissions are 0600.
            let file_meta = std::fs::metadata(&path).unwrap();
            assert_eq!(
                file_meta.permissions().mode() & 0o777,
                0o600,
                "persisted file must have mode 0600"
            );
            // parent dir is the tempdir; mode may not be exactly 0700 due to tempfile
            // crate defaults; we check ours at persist_file_perms_0600 instead.
            let _ = parent_meta;
        }
    }

    /// Recording a verifier then re-opening the registry returns the same entry.
    #[test]
    fn record_then_lookup_round_trip() {
        let (_guard, path) = temp_registry();
        let mut reg = VerifierRegistry::open_at(path.clone()).expect("open");

        let outcome = reg
            .record_webauthn_verifier(testnet(), fake_address(), fake_sha256())
            .expect("record");
        assert_eq!(outcome, RecordOutcome::Recorded);
        reg.persist().expect("persist");

        // Re-open and look up.
        let reg2 = VerifierRegistry::open_at(path).expect("re-open");
        let entry = reg2
            .webauthn_verifier_for(testnet())
            .expect("entry must survive round-trip");
        assert_eq!(entry.address, fake_address());
        assert_eq!(entry.wasm_sha256, fake_sha256());
        assert!(entry.deployed_at_unix_ms > 0, "timestamp must be non-zero");
    }

    /// Second `record_webauthn_verifier` with the same `wasm_sha256` returns
    /// `AlreadyRecorded` and does not modify the stored entry.
    #[test]
    fn record_idempotent_when_sha256_matches() {
        let (_guard, path) = temp_registry();
        let mut reg = VerifierRegistry::open_at(path).expect("open");

        let _ = reg
            .record_webauthn_verifier(testnet(), fake_address(), fake_sha256())
            .expect("first record");

        // Record the same sha256 again.
        let outcome2 = reg
            .record_webauthn_verifier(testnet(), fake_address(), fake_sha256())
            .expect("idempotent record");
        assert_eq!(outcome2, RecordOutcome::AlreadyRecorded);

        // The timestamp must not change (original entry preserved).
        let t1 = reg
            .webauthn_verifier_for(testnet())
            .expect("entry exists")
            .deployed_at_unix_ms;
        let _ = reg
            .record_webauthn_verifier(testnet(), fake_address(), fake_sha256())
            .expect("second idempotent");
        let t2 = reg
            .webauthn_verifier_for(testnet())
            .expect("entry still exists")
            .deployed_at_unix_ms;
        assert_eq!(t1, t2, "timestamp must be unchanged on AlreadyRecorded");
    }

    /// Second `record_webauthn_verifier` with a different `wasm_sha256` returns
    /// `SaError::WebAuthnVerifierSha256Drift`.
    #[test]
    fn record_rejects_sha256_drift() {
        let (_guard, path) = temp_registry();
        let mut reg = VerifierRegistry::open_at(path).expect("open");

        reg.record_webauthn_verifier(testnet(), fake_address(), fake_sha256())
            .expect("first record");

        let err = reg
            .record_webauthn_verifier(testnet(), fake_address(), alt_sha256())
            .expect_err("must reject different sha256");

        assert!(
            matches!(
                err,
                SaError::WebAuthnVerifierSha256Drift {
                    ref network,
                    ref recorded,
                    ref attempted,
                } if network == testnet()
                    && recorded == &fake_sha256()
                    && attempted == &alt_sha256()
            ),
            "unexpected error: {err:?}"
        );
    }

    fn ed25519_sha256() -> String {
        "ea13b07083a8275e7bade954e4ccc1827495f253c18dc06edcc49104c11fb725".to_owned()
    }

    fn spending_limit_sha256() -> String {
        "0e8da0ccff5c444520085ac1973d3c8023fdd04f727ee11ae7290a49dffbbaf5".to_owned()
    }

    /// A pre-widening on-disk TOML fixture (WebAuthn-only, using the three
    /// `webauthn_verifier_*` fields) still parses unchanged, and the WebAuthn
    /// entry is materialised while the Ed25519 / spending-limit slots are absent.
    #[test]
    fn legacy_webauthn_only_toml_parses_unchanged() {
        use std::io::Write as _;

        let (_guard, path) = temp_registry();
        let mut f = std::fs::File::create(&path).expect("create");
        write!(
            f,
            "[networks.\"{net}\"]\n\
             webauthn_verifier_address = \"{addr}\"\n\
             webauthn_verifier_wasm_sha256 = \"{sha}\"\n\
             webauthn_verifier_deployed_at_unix_ms = 1747000000000\n",
            net = testnet(),
            addr = fake_address(),
            sha = fake_sha256(),
        )
        .expect("write legacy toml");
        drop(f);

        let reg = VerifierRegistry::open_at(path).expect("open legacy toml");
        let webauthn = reg
            .webauthn_verifier_for(testnet())
            .expect("legacy webauthn entry must survive");
        assert_eq!(webauthn.address, fake_address());
        assert_eq!(webauthn.wasm_sha256, fake_sha256());
        assert_eq!(webauthn.deployed_at_unix_ms, 1_747_000_000_000);
        assert!(
            reg.ed25519_verifier_for(testnet()).is_none(),
            "legacy toml has no ed25519 verifier"
        );
        assert!(
            reg.spending_limit_policy_for(testnet()).is_none(),
            "legacy toml has no spending-limit policy"
        );
    }

    /// An Ed25519-only entry round-trips through persist + re-open with no
    /// WebAuthn or spending-limit slot materialised.
    #[test]
    fn ed25519_only_entry_round_trips() {
        let (_guard, path) = temp_registry();
        let mut reg = VerifierRegistry::open_at(path.clone()).expect("open");
        let outcome = reg
            .record_ed25519_verifier(testnet(), fake_address(), ed25519_sha256())
            .expect("record");
        assert_eq!(outcome, RecordOutcome::Recorded);
        reg.persist().expect("persist");

        let reg2 = VerifierRegistry::open_at(path).expect("re-open");
        let entry = reg2
            .ed25519_verifier_for(testnet())
            .expect("ed25519 entry must survive round-trip");
        assert_eq!(entry.address, fake_address());
        assert_eq!(entry.wasm_sha256, ed25519_sha256());
        assert!(entry.deployed_at_unix_ms > 0);
        assert!(reg2.webauthn_verifier_for(testnet()).is_none());
        assert!(reg2.spending_limit_policy_for(testnet()).is_none());
    }

    /// A spending-limit-only entry round-trips independently of any verifier.
    #[test]
    fn spending_limit_only_entry_round_trips() {
        let (_guard, path) = temp_registry();
        let mut reg = VerifierRegistry::open_at(path.clone()).expect("open");
        reg.record_spending_limit_policy(testnet(), fake_address(), spending_limit_sha256())
            .expect("record");
        reg.persist().expect("persist");

        let reg2 = VerifierRegistry::open_at(path).expect("re-open");
        let entry = reg2
            .spending_limit_policy_for(testnet())
            .expect("spending-limit entry must survive round-trip");
        assert_eq!(entry.wasm_sha256, spending_limit_sha256());
        assert!(reg2.webauthn_verifier_for(testnet()).is_none());
        assert!(reg2.ed25519_verifier_for(testnet()).is_none());
    }

    /// All three contract slots populated for one network round-trip together
    /// without clobbering each other.
    #[test]
    fn all_three_slots_round_trip_together() {
        let (_guard, path) = temp_registry();
        let mut reg = VerifierRegistry::open_at(path.clone()).expect("open");
        reg.record_webauthn_verifier(testnet(), fake_address(), fake_sha256())
            .expect("record webauthn");
        reg.record_ed25519_verifier(testnet(), fake_address(), ed25519_sha256())
            .expect("record ed25519");
        reg.record_spending_limit_policy(testnet(), fake_address(), spending_limit_sha256())
            .expect("record spending-limit");
        reg.persist().expect("persist");

        let reg2 = VerifierRegistry::open_at(path).expect("re-open");
        assert_eq!(
            reg2.webauthn_verifier_for(testnet())
                .expect("webauthn")
                .wasm_sha256,
            fake_sha256()
        );
        assert_eq!(
            reg2.ed25519_verifier_for(testnet())
                .expect("ed25519")
                .wasm_sha256,
            ed25519_sha256()
        );
        assert_eq!(
            reg2.spending_limit_policy_for(testnet())
                .expect("spending-limit")
                .wasm_sha256,
            spending_limit_sha256()
        );
    }

    /// Re-recording an Ed25519 verifier with a different sha256 is refused with
    /// the dedicated drift error, mirroring the WebAuthn drift guard.
    #[test]
    fn ed25519_record_rejects_sha256_drift() {
        let (_guard, path) = temp_registry();
        let mut reg = VerifierRegistry::open_at(path).expect("open");
        reg.record_ed25519_verifier(testnet(), fake_address(), ed25519_sha256())
            .expect("first record");
        let err = reg
            .record_ed25519_verifier(testnet(), fake_address(), alt_sha256())
            .expect_err("must reject different sha256");
        assert!(
            matches!(
                err,
                SaError::Ed25519VerifierSha256Drift { ref network, .. } if network == testnet()
            ),
            "unexpected error: {err:?}"
        );
    }

    /// `persist` writes the file with mode `0600` on Unix.
    #[cfg(unix)]
    #[test]
    fn persist_file_perms_0600() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_guard, path) = temp_registry();
        let mut reg = VerifierRegistry::open_at(path.clone()).expect("open");
        reg.record_webauthn_verifier(testnet(), fake_address(), fake_sha256())
            .expect("record");
        reg.persist().expect("persist");

        let meta = std::fs::metadata(&path).expect("metadata");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "persisted networks.toml must have mode 0600"
        );
    }

    /// `open_at()` on a file with garbage TOML returns `NetworksTomlParse`.
    #[test]
    fn parse_rejects_malformed_toml() {
        use std::io::Write as _;

        let (_guard, path) = temp_registry();
        let mut f = std::fs::File::create(&path).expect("create file");
        f.write_all(b"[[[invalid toml\n").expect("write");
        drop(f);

        let err = VerifierRegistry::open_at(path.clone()).expect_err("must fail");
        let expected_path = path;
        assert!(
            matches!(
                err,
                SaError::NetworksTomlParse { path: ref err_path, .. }
                    if *err_path == expected_path
            ),
            "unexpected error: {err:?}"
        );
    }

    /// `resolve_default_path_with_override(Some(path))` returns the env-supplied
    /// path verbatim, bypassing OS-conventional config-dir resolution.
    ///
    /// Tested via the inner `resolve_default_path_with_override(env_override)`
    /// helper rather than `resolve_default_path()` directly so the test does
    /// not need to mutate process-global env state — env-var mutation is
    /// `unsafe fn` in Rust 2024 and incompatible with the crate's
    /// `#![forbid(unsafe_code)]`.
    #[test]
    fn resolve_default_path_honours_env_override() {
        let (_guard, override_path) = temp_registry();
        let override_str = override_path.to_str().expect("path must be utf-8");

        let resolved = resolve_default_path_with_override(Some(override_str))
            .expect("override path must resolve");
        assert_eq!(
            resolved, override_path,
            "env-var path must take precedence over OS config dir"
        );
    }

    /// `resolve_default_path_with_override(None)` falls through to the OS-
    /// conventional config-dir path.  Best-effort: this depends on
    /// `dirs::config_dir()` being resolvable on the test host.  When unresolvable
    /// (rare CI / container environment), the function returns
    /// `NetworksTomlIo` — also a valid outcome, so the test accepts
    /// either successful resolution (with the expected suffix) or that error.
    #[test]
    fn resolve_default_path_falls_through_to_os_config() {
        match resolve_default_path_with_override(None) {
            Ok(path) => assert!(
                path.ends_with("stellar-agent/networks.toml"),
                "OS-conventional path must end with stellar-agent/networks.toml, got: {path:?}"
            ),
            Err(SaError::NetworksTomlIo { .. }) => {
                // Acceptable on hosts with no resolvable config dir.
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    /// `persist()` creates a missing parent directory with mode `0700` on Unix.
    /// Covers the `create_dir_0700` code path which is only triggered when the
    /// parent does not already exist (tests using `tempfile::tempdir()` pre-create
    /// the parent).
    #[cfg(unix)]
    #[test]
    fn persist_creates_parent_dir_with_mode_0700() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        // Nested subdir does NOT exist yet — `persist()` must create it.
        let subdir = dir.path().join("nested-config");
        let path = subdir.join("networks.toml");
        assert!(!subdir.exists(), "pre-condition: subdir must not exist");

        let reg = VerifierRegistry::open_at(path.clone()).expect("open empty");
        reg.persist().expect("persist must create parent dir");

        assert!(subdir.exists(), "persist must create the parent directory");
        let parent_meta = std::fs::metadata(&subdir).expect("parent dir metadata");
        assert_eq!(
            parent_meta.permissions().mode() & 0o777,
            0o700,
            "newly-created parent directory must have mode 0700"
        );
    }

    /// Wire-code round-trip: `NetworksTomlParse` serialises with the expected
    /// adjacently-tagged shape and its wire code is stable.
    #[test]
    fn wire_code_round_trip_config_parse() {
        let err = SaError::NetworksTomlParse {
            source: toml::from_str::<toml::Value>("bad = ").unwrap_err(),
            path: PathBuf::from("/tmp/networks.toml"),
        };
        assert_eq!(err.wire_code(), "sa.networks_toml_parse");
        let json = serde_json::to_string(&err).expect("serialize");
        assert!(json.contains("\"wire_code\""));
        assert!(json.contains("sa.networks_toml_parse"));
    }
}
