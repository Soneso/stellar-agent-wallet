//! MCP server handler, tool registry, and transport construction.
//!
//! This module wires together:
//!
//! - `WalletServer` — the rmcp `ServerHandler` implementation.
//! - Tool dispatch via the merged `ToolRouter` built from tool-family sub-routers
//!   (one per tool family in `tools/`).
//! - Policy-engine dispatch gate.
//! - MCP resource registration (`mcp-resource://usage.md`).
//! - `#[mcp_tool_router]`/`#[mcp_tool_item]`-driven tool registry (fail-closed).
//!
//! # Tool registry
//!
//! Every tool fn is annotated with both rmcp's `#[tool(...)]` and the wallet-owned
//! `#[mcp_tool_item(...)]` fn-level marker inside a `#[mcp_tool_router]` impl block.
//! The `#[mcp_tool_router]` expansion emits
//! `inventory::submit!{ McpToolRegistration { ... } }` items at module scope.
//! `WalletServer::new` calls `build_tool_registry()` which iterates
//! `inventory::iter::<McpToolRegistration>()` and builds a
//! `HashMap<&'static str, ToolDescriptor>`.
//!
//! `WalletServer::new` is **fallible** (returns `Result`) — if two registrations
//! claim the same tool name, `build_tool_registry()` returns
//! `Err(BuildRegistryError::DuplicateRegistration)` and the server refuses to start.
//! This is the fail-closed contract: duplicate names cannot shadow
//! `destructive_hint` values and thereby bypass the mainnet gate.
//!
//! # Transport construction
//!
//! Transport construction (the `BoundedStdioTransport` and the `run` fn) lives
//! in [`crate::transport`].
//!
//! # Policy-engine gate
//!
//! Every `tools/call` path unconditionally routes through `dispatch_gate`,
//! which calls `policy_engine.evaluate(...)`.  The call site is in production
//! code (not behind a feature flag) so the policy-engine impl can be swapped
//! without changing the dispatch path.
//!
//! # Nonce wiring
//!
//! `WalletServer` holds an `Arc<NonceMint>` (per-profile HMAC minter) and an
//! `Arc<TokioMutex<ReplayWindow>>` (in-memory single-use tracker).  Both are
//! constructed at startup via `WalletServer::new`.  The `stellar_create_account`
//! simulate step mints a nonce; `stellar_create_account_commit` verifies it.
//!
//! The `ToolCatalogueAdapter` implements
//! [`stellar_agent_nonce::ToolCatalogue`] over the `tool_registry` `HashMap` so
//! `NonceMint::mint` can validate tool names without depending on the MCP
//! framework types.
//!
//! # MCP resources
//!
//! - `mcp-resource://accounts/<G>` - public-key directory for enrolled
//!   G-strkey accounts.
//! - `mcp-resource://profiles/<name>` - non-secret profile metadata.

use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};

use ed25519_dalek::PUBLIC_KEY_LENGTH;
use rmcp::serde::Serialize;
use rmcp::{
    RoleServer, ServerHandler,
    handler::server::router::tool::ToolRouter,
    model::{
        AnnotateAble, Implementation, InitializeResult, ListResourcesResult,
        PaginatedRequestParams, ProtocolVersion, ReadResourceRequestParams, ReadResourceResult,
        ResourceContents, ServerCapabilities,
    },
    service::RequestContext,
    tool_handler,
};
use serde_json::json;
use stellar_agent_core::policy::v1::PolicyEngineV1;
use stellar_agent_core::{
    policy::{BuildRegistryError, NoopPolicyEngine, PolicyEngine, ToolDescriptor},
    profile::loader,
    profile::schema::{KeyringEntryRef, PolicyEngineKind, Profile, default_policy_dir},
    timefmt::{Clock, default_clock},
};
use stellar_agent_network::{CounterpartyResolver, NoopCounterpartyResolver, StellarTomlResolver};
use stellar_agent_nonce::{NonceMint, ReplayWindow};
use tokio::sync::Mutex as TokioMutex;

use crate::tools::common::{ToolCatalogueAdapter, build_tool_registry};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Prefix used by [`KeyringEntryRef::default_owner_key`] for the `service`
/// field of owner-key keyring entries.
///
/// `KeyringEntryRef::default_owner_key(name)` sets:
///
/// - `service = "stellar-agent-owner-<name>"`
/// - `account = "default"`
///
/// `build_policy_engine` derives the profile name by stripping this prefix
/// from `policy_owner_key_id.service` rather than using `account` (which is
/// always `"default"`, making it useless as a discriminator).
const OWNER_KEY_SERVICE_PREFIX: &str = "stellar-agent-owner-";
const USAGE_RESOURCE_URI: &str = "mcp-resource://usage.md";
const PROFILE_RESOURCE_PREFIX: &str = "mcp-resource://profiles/";
const ACCOUNT_RESOURCE_PREFIX: &str = "mcp-resource://accounts/";

#[derive(Debug, Serialize)]
#[serde(crate = "rmcp::serde")]
struct ProfileMetadataResource {
    chain_id: String,
    rpc_url: String,
    network_passphrase: String,
    mcp_disabled: bool,
    usd_threshold: u64,
}

#[derive(Debug, Serialize)]
#[serde(crate = "rmcp::serde")]
struct AccountDirectoryResource {
    account_id: String,
    chain_id: String,
    network_passphrase: String,
}

impl AccountDirectoryResource {
    fn new(account_id: &str, profile: &Profile) -> Self {
        Self {
            account_id: account_id.to_owned(),
            chain_id: profile.chain_id.caip2_str().to_owned(),
            network_passphrase: profile.network_passphrase.clone(),
        }
    }
}

impl From<&Profile> for ProfileMetadataResource {
    fn from(profile: &Profile) -> Self {
        Self {
            chain_id: profile.chain_id.caip2_str().to_owned(),
            rpc_url: profile.rpc_url.clone(),
            network_passphrase: profile.network_passphrase.clone(),
            mcp_disabled: profile.mcp_disabled,
            usd_threshold: profile.usd_threshold,
        }
    }
}

fn profile_resource_uri(name: &str) -> String {
    format!("{PROFILE_RESOURCE_PREFIX}{name}")
}

fn profile_resource_name_from_uri(uri: &str) -> Option<&str> {
    let name = uri.strip_prefix(PROFILE_RESOURCE_PREFIX)?;
    if name.is_empty() || name.contains('/') || name.contains('\\') {
        return None;
    }
    Some(name)
}

fn profile_resource_for_name(name: &str) -> rmcp::model::Resource {
    rmcp::model::RawResource::new(
        profile_resource_uri(name),
        format!("Non-secret metadata for profile `{name}`"),
    )
    .no_annotation()
}

fn profile_metadata_json(profile: &Profile) -> Result<String, rmcp::ErrorData> {
    serde_json::to_string_pretty(&ProfileMetadataResource::from(profile))
        .map_err(|_| rmcp::ErrorData::internal_error("profile_resource_serialize_failed", None))
}

fn profile_resource_load_error(name: &str) -> rmcp::ErrorData {
    rmcp::ErrorData::internal_error(
        "profile_resource_unloadable",
        Some(json!({ "profile": name })),
    )
}

fn profile_resource_not_found(uri: &str) -> rmcp::ErrorData {
    rmcp::ErrorData::resource_not_found("resource_not_found", Some(json!({ "uri": uri })))
}

fn account_resource_uri(account_id: &str) -> String {
    format!("{ACCOUNT_RESOURCE_PREFIX}{account_id}")
}

fn account_resource_id_from_uri(uri: &str) -> Result<&str, rmcp::ErrorData> {
    let account_id = uri
        .strip_prefix(ACCOUNT_RESOURCE_PREFIX)
        .ok_or_else(|| profile_resource_not_found(uri))?;
    if account_id.is_empty() || account_id.contains('/') || account_id.contains('\\') {
        return Err(account_resource_invalid_account_id(uri));
    }
    validate_account_resource_id(account_id)
        .map_err(|_| account_resource_invalid_account_id(uri))?;
    Ok(account_id)
}

fn account_resource_invalid_account_id(uri: &str) -> rmcp::ErrorData {
    rmcp::ErrorData::invalid_params("invalid_account_resource_id", Some(json!({ "uri": uri })))
}

fn validate_account_resource_id(account_id: &str) -> Result<(), ()> {
    stellar_strkey::ed25519::PublicKey::from_string(account_id)
        .map(|_| ())
        .map_err(|_| ())
}

fn profile_enrolled_account_id(profile: &Profile) -> Option<&str> {
    let account = profile.mcp_signer_default.account.as_str();
    validate_account_resource_id(account).ok()?;
    Some(account)
}

fn enrolled_account_ids_from_profiles<'a, I>(profiles: I) -> Vec<String>
where
    I: IntoIterator<Item = &'a Profile>,
{
    let mut account_ids = profiles
        .into_iter()
        .filter_map(profile_enrolled_account_id)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    account_ids.sort();
    account_ids.dedup();
    account_ids
}

fn enrolled_account_ids(active_profile: &Profile) -> Vec<String> {
    let mut account_ids = enrolled_account_ids_from_profiles([active_profile]);

    if let Ok(profile_names) = loader::list_profiles() {
        for name in profile_names {
            if let Ok(profile) = loader::load(&name, None)
                && let Some(account_id) = profile_enrolled_account_id(&profile)
            {
                account_ids.push(account_id.to_owned());
            }
        }
    }

    account_ids.sort();
    account_ids.dedup();
    account_ids
}

fn account_resource_for_id(account_id: &str) -> rmcp::model::Resource {
    rmcp::model::RawResource::new(
        account_resource_uri(account_id),
        format!("Public account directory entry for `{account_id}`"),
    )
    .no_annotation()
}

fn account_directory_json(account_id: &str, profile: &Profile) -> Result<String, rmcp::ErrorData> {
    serde_json::to_string_pretty(&AccountDirectoryResource::new(account_id, profile))
        .map_err(|_| rmcp::ErrorData::internal_error("account_resource_serialize_failed", None))
}

// ─────────────────────────────────────────────────────────────────────────────
// Back-compat re-exports (tests import via `stellar_agent_mcp::server::*`)
// ─────────────────────────────────────────────────────────────────────────────

/// Re-exported for back-compat: resource content generator.
pub use crate::resources::usage_md_content;
/// Re-exported for back-compat: argument types for `stellar_balances`.
pub use crate::tools::balances::{
    MAX_TRUSTLINE_ASSETS_PER_CALL, StellarBalancesArgs, TrustlineAssetArg,
};
/// Re-exported for back-compat: argument types for `stellar_claim`.
pub use crate::tools::claim::{StellarClaimArgs, StellarClaimCommitArgs};
/// Re-exported for integration-test coverage of registry duplicate checks.
pub use crate::tools::common::check_duplicate_registrations;
/// Re-exported for back-compat: argument types for `stellar_create_account`.
pub use crate::tools::create_account::{StellarCreateAccountArgs, StellarCreateAccountCommitArgs};
/// Re-exported for the MCP-tool-layer decimal-string wire acceptance test:
/// argument type for `stellar_dex_quote`.
pub use crate::tools::dex_trade::DexQuoteArgs;
/// Re-exported for back-compat: argument type for `stellar_fee_stats`.
pub use crate::tools::fee_stats::StellarFeeStatsArgs;
/// Re-exported for back-compat: argument type for `stellar_friendbot`.
pub use crate::tools::friendbot::StellarFriendbotArgs;
/// Re-exported for back-compat: argument types for `stellar_pay`.
pub use crate::tools::pay::{StellarPayArgs, StellarPayCommitArgs};
/// Re-exported for testnet acceptance tests: argument and signer/policy grammar
/// types for `stellar_rule_create` / `stellar_rule_create_commit`.
pub use crate::tools::rule_create::{
    RuleCreatePolicyArg, RuleCreateSignerArg, StellarRuleCreateArgs, StellarRuleCreateCommitArgs,
};
/// Re-exported for testnet acceptance tests: argument types for
/// `stellar_rules_list` / `stellar_rules_get`.
pub use crate::tools::rules::{StellarRulesGetArgs, StellarRulesListArgs};
/// Re-exported for testnet acceptance and integration tests.
pub use crate::tools::sep43_sign_and_submit_transaction::Sep43SignAndSubmitTransactionArgs;
pub use crate::tools::toolsets::StellarToolsetInvokeArgs;
/// Re-exported for back-compat: argument types for `stellar_trustline`.
pub use crate::tools::trustline::{StellarTrustlineArgs, StellarTrustlineCommitArgs};
/// Re-exported for testnet acceptance and integration tests: x402 authenticated-payment args.
pub use crate::tools::x402_authenticated_payment::X402AuthenticatedPaymentArgs;
/// Re-exported for integration tests: x402 create-payment args.
pub use crate::tools::x402_create_payment::X402CreatePaymentArgs;
/// Re-exported for integration tests: x402 parse-receipt args.
pub use crate::tools::x402_parse_receipt::X402ParseReceiptArgs;

// ─────────────────────────────────────────────────────────────────────────────
// Policy engine construction helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Fetches the owner public key (ed25519, URL-safe base64-encoded) from the
/// keyring entry `stellar-agent-owner-<profile_name>` / `"default"`.
///
/// The stored value is a URL-safe base64-encoded 32-byte ed25519 public key
/// (same format written at policy-sign time).  The function opens the entry,
/// reads the password, decodes the bytes, and returns the raw 32-byte array.
///
/// # Errors
///
/// - [`BuildRegistryError::OwnerKeyringEntryUnreadable`] if `keyring_core::Entry::new`
///   fails (e.g. the keyring store is not initialised).
/// - [`BuildRegistryError::OwnerKeyAbsent`] if the entry exists but has no
///   stored value.
/// - [`BuildRegistryError::OwnerKeyDecodeFailed`] if the stored value is not
///   valid URL-safe base64.
/// - [`BuildRegistryError::OwnerKeyLengthMismatch`] if the decoded key is not
///   exactly 32 bytes.
fn fetch_owner_pubkey_from_keyring(
    profile_name: &str,
) -> Result<[u8; PUBLIC_KEY_LENGTH], BuildRegistryError> {
    use keyring_core::Entry as KeyringEntry;

    let entry_ref = KeyringEntryRef::default_owner_key(profile_name);
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        BuildRegistryError::OwnerKeyringEntryUnreadable {
            profile: profile_name.to_owned(),
            detail: e.to_string(),
        }
    })?;

    let raw = entry
        .get_password()
        .map_err(|e| BuildRegistryError::OwnerKeyAbsent {
            profile: profile_name.to_owned(),
            detail: e.to_string(),
        })?;

    // URL-safe base64, no padding — written at policy-sign time.
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw.trim())
        .map_err(|e| BuildRegistryError::OwnerKeyDecodeFailed {
            profile: profile_name.to_owned(),
            detail: e.to_string(),
        })?;

    let actual_len = bytes.len();
    if actual_len != PUBLIC_KEY_LENGTH {
        return Err(BuildRegistryError::OwnerKeyLengthMismatch {
            profile: profile_name.to_owned(),
            actual_len,
            expected_len: PUBLIC_KEY_LENGTH,
        });
    }

    let mut arr = [0u8; PUBLIC_KEY_LENGTH];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Derives the profile name from `profile.policy_owner_key_id.service` by
/// stripping the [`OWNER_KEY_SERVICE_PREFIX`].
///
/// [`KeyringEntryRef::default_owner_key(name)`] sets:
///
/// - `service = "stellar-agent-owner-<name>"`
/// - `account = "default"` (literal — not the profile name)
///
/// Using `account` directly would always produce `"default"`, causing every
/// profile to share the same policy file path and scope name.  Stripping the
/// service prefix recovers the actual profile name.
///
/// # Errors
///
/// Returns [`BuildRegistryError::PolicyEngineError`] when the `service` field
/// does not start with [`OWNER_KEY_SERVICE_PREFIX`], which indicates the
/// profile was constructed without using `KeyringEntryRef::default_owner_key`.
fn profile_name_from_key_ref(profile: &Profile) -> Result<String, BuildRegistryError> {
    let service = &profile.policy_owner_key_id.service;
    service
        .strip_prefix(OWNER_KEY_SERVICE_PREFIX)
        .map(ToOwned::to_owned)
        .ok_or_else(|| BuildRegistryError::PolicyEngineError {
            detail: format!(
                "policy_owner_key_id.service '{service}' does not start with \
                 expected prefix '{OWNER_KEY_SERVICE_PREFIX}'; cannot derive \
                 profile name for policy engine construction"
            ),
        })
}

fn counterparty_cache_dir(profile_name: &str) -> Option<std::path::PathBuf> {
    directories::ProjectDirs::from("", "Soneso", "stellar-agent").map(|dirs| {
        dirs.data_local_dir()
            .join("counterparty")
            .join(profile_name)
    })
}

fn build_counterparty_resolver(profile: &Profile) -> Arc<dyn CounterpartyResolver> {
    let Ok(profile_name) = profile_name_from_key_ref(profile) else {
        tracing::debug!("counterparty resolver disabled: profile name derivation failed");
        return Arc::new(NoopCounterpartyResolver);
    };
    let Some(cache_dir) = counterparty_cache_dir(&profile_name) else {
        tracing::debug!("counterparty resolver disabled: OS cache directory unavailable");
        return Arc::new(NoopCounterpartyResolver);
    };
    if !cache_dir.exists() {
        return Arc::new(NoopCounterpartyResolver);
    }
    match StellarTomlResolver::new(&profile_name, cache_dir, Duration::from_secs(3600)) {
        Ok(resolver) => Arc::new(resolver),
        Err(err) => {
            tracing::debug!(error = %err, "counterparty resolver disabled: construction failed");
            Arc::new(NoopCounterpartyResolver)
        }
    }
}

/// Constructs the concrete [`PolicyEngine`] for the given profile.
///
/// Dispatches on `profile.policy.engine`:
///
/// - [`PolicyEngineKind::Noop`] → [`NoopPolicyEngine`].
/// - [`PolicyEngineKind::V1`] → derives the profile name from the owner-key
///   service entry (stripping [`OWNER_KEY_SERVICE_PREFIX`]), fetches the
///   owner public key from the keyring, and loads the owner-signed policy
///   file from `<state_dir>/policies/<profile_name>.toml`, or from an injected
///   policy directory in tests.
/// - Unknown variants → [`BuildRegistryError::UnsupportedEngineKind`]
///   (fail-closed).
///
/// # Errors
///
/// - [`BuildRegistryError::PolicyEngineError`] — profile name cannot be
///   derived from `policy_owner_key_id.service`.
/// - [`BuildRegistryError::OwnerKeyringEntryUnreadable`] — keyring entry
///   could not be opened.
/// - [`BuildRegistryError::OwnerKeyAbsent`] — owner key not in keyring.
/// - [`BuildRegistryError::OwnerKeyDecodeFailed`] — stored value is not
///   valid base64.
/// - [`BuildRegistryError::OwnerKeyLengthMismatch`] — decoded key is not
///   32 bytes.
/// - [`BuildRegistryError::PolicyDirResolutionFailed`] — OS state directory
///   could not be determined.
/// - [`BuildRegistryError::PolicyFileLoadFailed`] — policy file I/O or
///   signature verification failed.
/// - [`BuildRegistryError::UnsupportedEngineKind`] — unknown
///   `PolicyEngineKind` variant.
fn build_policy_engine(
    profile: &Profile,
    policy_dir_override: Option<&Path>,
) -> Result<Arc<dyn PolicyEngine>, BuildRegistryError> {
    match profile.policy.engine {
        PolicyEngineKind::Noop => Ok(Arc::new(NoopPolicyEngine)),
        PolicyEngineKind::V1 => {
            // Derive the profile name from the service prefix, not from
            // `account` which is always the literal "default".
            let profile_name = profile_name_from_key_ref(profile)?;

            // Fetch the owner public key from the keyring.  This validates
            // that the operator has initialised the owner key before enabling V1.
            let owner_pubkey = fetch_owner_pubkey_from_keyring(&profile_name)?;

            let policy_dir = policy_dir_override.map_or_else(
                || default_policy_dir().map_err(|_| BuildRegistryError::PolicyDirResolutionFailed),
                |dir| Ok(dir.to_path_buf()),
            )?;
            let policy_path = policy_dir.join(format!("{profile_name}.toml"));

            let document = stellar_agent_core::policy::v1::loader::load_signed_policy(
                &policy_path,
                &profile_name,
                &owner_pubkey,
            )
            .map_err(|source| BuildRegistryError::PolicyFileLoadFailed {
                profile: profile_name.clone(),
                source,
            })?;

            Ok(Arc::new(PolicyEngineV1::new(document, profile_name)))
        }
        // Fail-closed: unknown PolicyEngineKind variants are NOT silently
        // downgraded to NoopPolicyEngine.  A silent downgrade would allow a
        // malformed or future-version profile to bypass the operator's intended
        // policy engine without any error.
        _ => Err(BuildRegistryError::UnsupportedEngineKind {
            kind: format!("{:?}", profile.policy.engine),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WalletServer
// ─────────────────────────────────────────────────────────────────────────────

/// MCP server handler for the Stellar agent wallet.
///
/// Holds the active profile, the policy engine, the tool registry built from
/// `#[mcp_tool_item]`-annotated fns, the nonce minter, and the replay window.
///
/// Tool dispatch routes through `policy_engine.evaluate(...)` before calling
/// the network layer.
///
/// # Tool registry
///
/// `WalletServer::new` calls `build_tool_registry` which iterates
/// `inventory::iter::<McpToolRegistration>()`.  The registry is consulted at
/// every `tools/call` dispatch to produce the `ToolDescriptor` for the policy
/// engine — single source of truth, no duplication between the `#[tool]` and
/// `#[mcp_tool_item]` annotations on the same fn.
///
/// The constructor is **fallible**: if two `McpToolRegistration` values claim the
/// same tool name, `WalletServer::new` returns
/// `Err(BuildRegistryError::DuplicateRegistration)`.  Callers must propagate or
/// handle this error; the server is fail-closed on duplicate registration.
///
/// # Nonce fields
///
/// `nonce_mint` holds the per-profile `NonceMint` used by simulate tools.
/// `replay_window` is the in-memory single-use tracker wrapped in a
/// `TokioMutex` for async-safe access across `tools/call` dispatch points.
/// Both are `Arc`-wrapped for the `Clone` requirement on `WalletServer`.
#[derive(Clone)]
pub struct WalletServer {
    pub(crate) profile: Arc<Profile>,
    pub(crate) policy_engine: Arc<dyn PolicyEngine>,
    /// Tool registry built from `#[mcp_tool_item]` attributes at startup.
    ///
    /// Maps tool name → [`ToolDescriptor`]; used by `tools/call` dispatch to
    /// retrieve the descriptor for the policy-engine gate without duplicating
    /// annotation values.
    pub(crate) tool_registry: Arc<HashMap<&'static str, ToolDescriptor>>,
    /// Adapter over [`Self::tool_registry`] for nonce minting.
    ///
    /// Built once at startup so simulate handlers can borrow it without
    /// constructing a fresh adapter on every call.
    pub(crate) tool_catalogue: Arc<ToolCatalogueAdapter>,
    /// Per-profile nonce minter.
    ///
    /// Holds only the non-secret keyring coordinate pair.  The HMAC key is
    /// lazy-loaded from the platform keyring on every `mint` / `verify` call
    /// and zeroised immediately after (see `stellar-agent-nonce` crate docs).
    pub(crate) nonce_mint: Arc<NonceMint>,
    /// In-memory single-use nonce tracker.
    ///
    /// Wrapped in `TokioMutex` because the `verify` call is in an `async`
    /// handler; `parking_lot::Mutex` would block the async runtime if the
    /// lock is contended.  The lock is held only for the duration of the
    /// `verify` call (sub-microsecond, no await inside).
    pub(crate) replay_window: Arc<TokioMutex<ReplayWindow>>,
    /// Per-profile counterparty resolver used to build a frozen cache snapshot
    /// for policy evaluation at each MCP dispatch.
    pub(crate) counterparty_resolver: Arc<dyn CounterpartyResolver>,
    /// Merged tool router built once at server construction and reused by rmcp dispatch.
    pub(crate) tool_router: ToolRouter<WalletServer>,
    /// Wall-clock source for approval-expiry checks.
    pub(crate) clock: Arc<dyn Clock>,
    /// Test-only override for the approval-store directory.
    ///
    /// `None` in production: `verify_attestation_gate` resolves the directory
    /// via `stellar_agent_core::profile::schema::default_approval_dir()`.
    ///
    /// Set via [`WalletServer::set_approval_dir_for_test`] (gated on
    /// `#[cfg(any(test, feature = "test-helpers"))]`) to route integration tests
    /// away from `~/Library/Application Support/Soneso.stellar-agent/approvals/`
    /// and into a per-test `tempfile::TempDir`.
    ///
    /// Gated on `test-helpers` feature or `#[cfg(test)]`.
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) approval_dir_override: Option<std::path::PathBuf>,

    /// Test-only override for the toolset-grant store path.
    ///
    /// `None` in production: `resolve_toolset_sign_payment_gated` resolves
    /// the path via `default_toolset_grants_path`.  Set via
    /// [`WalletServer::set_grant_store_path_for_test`] so integration tests
    /// write to a per-test `tempfile::TempDir`.
    ///
    /// Gated on `test-helpers` feature or `#[cfg(test)]`.
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) grant_store_path_override: Option<std::path::PathBuf>,

    /// Test-only override for the toolsets root directory.
    ///
    /// `None` in production: `stellar_toolset_invoke` resolves the toolsets root
    /// via `default_toolsets_dir()`.  Set via
    /// [`WalletServer::set_toolsets_root_for_test`] so integration tests write to
    /// a per-test `tempfile::TempDir` without touching the real toolsets dir.
    ///
    /// Gated on `test-helpers` feature or `#[cfg(test)]`.
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) toolsets_root_override: Option<std::path::PathBuf>,
}

impl WalletServer {
    /// Constructs a `WalletServer` with the given profile.
    ///
    /// Builds the tool registry from `inventory::iter::<McpToolRegistration>()`
    /// (populated by `#[mcp_tool_item]` attributes at link time) and wraps it
    /// in an `Arc` for `Clone` sharing.
    ///
    /// Constructs the `NonceMint` from the profile (non-failing; defers keyring
    /// load to mint/verify time) and an empty `ReplayWindow`.
    ///
    /// The policy engine is selected by `build_policy_engine` per
    /// `profile.policy.engine`: `Noop` → [`NoopPolicyEngine`]; `V1` →
    /// [`PolicyEngineV1`] loaded from the OS-conventional policy directory.
    /// Newly-minted profiles default to `V1`.
    ///
    /// `init_platform_keyring_store` MUST be called before `WalletServer::new`
    /// when the server is used in production; see `main.rs` for the correct
    /// startup order.  Tests call `stellar_agent_test_support::keyring_mock::install`
    /// instead.
    ///
    /// # Errors
    ///
    /// Returns [`BuildRegistryError::DuplicateRegistration`] if two
    /// `McpToolRegistration` values with the same `name` are present in the
    /// `inventory` registry.  This indicates a compile-time authoring error
    /// (two fns declared with the same `#[mcp_tool_item(name = "...")]`).
    /// The server is fail-closed: it MUST NOT start with an ambiguous registry
    /// because duplicate names allow `destructive_hint` shadowing.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn new(profile: Profile) -> Result<Self, BuildRegistryError> {
        Self::new_with_clock(profile, default_clock())
    }

    /// Constructs a [`WalletServer`] with an injected [`Clock`].
    ///
    /// Crate-internal counterpart to [`WalletServer::new`] used by tests that
    /// need to force clock-error code paths through `verify_attestation_gate`
    /// and other clock-reading surfaces. Production code uses [`WalletServer::new`]
    /// which threads [`SystemClock`](stellar_agent_core::timefmt::SystemClock).
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`WalletServer::new`].
    pub(crate) fn new_with_clock(
        profile: Profile,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, BuildRegistryError> {
        Self::new_with_clock_and_policy_dir(profile, clock, None)
    }

    fn new_with_clock_and_policy_dir(
        profile: Profile,
        clock: Arc<dyn Clock>,
        policy_dir_override: Option<&Path>,
    ) -> Result<Self, BuildRegistryError> {
        // NonceMint::from_profile is infallible in the current implementation
        // (no reachability probe at construction time).  The `?` is for forward
        // compatibility; the only currently-possible NonceError variants at
        // construction time are none.
        let nonce_mint =
            NonceMint::from_profile(&profile).map_err(|e| BuildRegistryError::NonceMintInit {
                detail: e.to_string(),
            })?;

        let policy_engine: Arc<dyn PolicyEngine> =
            build_policy_engine(&profile, policy_dir_override)?;

        let tool_registry = Arc::new(build_tool_registry()?);
        let tool_catalogue = Arc::new(ToolCatalogueAdapter::new(Arc::clone(&tool_registry)));
        let counterparty_resolver = build_counterparty_resolver(&profile);

        Ok(Self {
            profile: Arc::new(profile),
            policy_engine,
            tool_registry,
            tool_catalogue,
            nonce_mint: Arc::new(nonce_mint),
            replay_window: Arc::new(TokioMutex::new(ReplayWindow::new())),
            counterparty_resolver,
            tool_router: Self::merged_tool_router(),
            clock,
            #[cfg(any(test, feature = "test-helpers"))]
            approval_dir_override: None,
            #[cfg(any(test, feature = "test-helpers"))]
            grant_store_path_override: None,
            #[cfg(any(test, feature = "test-helpers"))]
            toolsets_root_override: None,
        })
    }

    /// Returns a reference to the `ToolDescriptor` for the given tool name from
    /// the built-at-startup registry, or `None` if the tool is not registered.
    ///
    /// Used by `registry_walk.rs` integration tests to verify that the
    /// `#[mcp_tool_item]` annotation values flow through correctly to the
    /// policy-engine dispatch site.
    #[must_use]
    pub fn tool_registry_descriptor(&self, name: &str) -> Option<&ToolDescriptor> {
        self.tool_registry.get(name)
    }

    /// Returns the names of all tools registered in the merged rmcp `ToolRouter`.
    ///
    /// Used by `registry_walk.rs` to cross-check the router entries against the
    /// inventory registry for router ↔ registry parity.
    #[must_use]
    pub fn router_tool_names() -> Vec<String> {
        Self::merged_tool_router()
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect()
    }

    /// Returns every registered tool's full rmcp `Tool` descriptor, including
    /// its JSON Schema `input_schema`.
    ///
    /// Used by `registry_walk.rs`'s wire-format drift guard, which walks every
    /// tool's input schema for integer/number-typed properties whose names
    /// match a value-denominated pattern (see that test for the allowlist).
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[must_use]
    pub fn all_registered_tools() -> Vec<rmcp::model::Tool> {
        Self::merged_tool_router().list_all()
    }

    /// Single source of truth for sub-router composition.
    ///
    /// Consumed by [`WalletServer::new`] (initial `tool_router` field
    /// population) and [`WalletServer::router_tool_names`] (test parity check).
    /// Runtime dispatch uses the prebuilt `self.tool_router` field through the
    /// `#[tool_handler(router = self.tool_router)]` macro attribute. Adding a
    /// tool family means editing this method only.
    fn merged_tool_router() -> ToolRouter<WalletServer> {
        let mut router = Self::balances_tool_router();
        router.merge(Self::fee_stats_tool_router());
        router.merge(Self::friendbot_tool_router());
        router.merge(Self::create_account_tool_router());
        router.merge(Self::pay_tool_router());
        // SEP-43 ModuleInterface tools.
        router.merge(Self::sep43_get_address_tool_router());
        router.merge(Self::sep43_get_network_tool_router());
        router.merge(Self::sep43_sign_transaction_tool_router());
        router.merge(Self::sep43_sign_auth_entry_tool_router());
        router.merge(Self::sep43_sign_message_tool_router());
        // SEP-43 sign-and-submit (WC v2 stellar_signAndSubmitXDR).
        router.merge(Self::sep43_sign_and_submit_transaction_tool_router());
        // x402 Exact Stellar payment scheme tools.
        router.merge(Self::x402_create_payment_tool_router());
        router.merge(Self::x402_parse_receipt_tool_router());
        // SEP-48 typed-preview + SEP-47 claim-discovery.
        router.merge(Self::sep48_preview_invocation_tool_router());
        router.merge(Self::sep47_discover_tool_router());
        // SEP-53 prefixed message sign/verify.
        router.merge(Self::sep53_sign_message_tool_router());
        router.merge(Self::sep53_verify_message_tool_router());
        // SEP-7 inbound URI parse + verify.
        router.merge(Self::sep7_parse_uri_tool_router());
        // SEP-6 discovery + SEP-24 interactive hand-off.
        router.merge(Self::sep6_deposit_info_tool_router());
        router.merge(Self::sep24_interactive_url_tool_router());
        // x402 authenticated payment (SEP-10 identity gate).
        router.merge(Self::x402_authenticated_payment_tool_router());
        // Generic toolset-invocation surface (list + invoke).
        router.merge(Self::toolsets_tool_router());
        // Blend lending adapter — deposit/withdraw verbs.
        router.merge(Self::blend_lend_tool_router());
        // DeFindex vault adapter — vault deposit/withdraw.
        router.merge(Self::vault_tool_router());
        // Soroswap DEX swap adapter — trade + quote verbs.
        router.merge(Self::dex_trade_tool_router());
        // Stablecoin substrate — trustline verb.
        router.merge(Self::trustline_tool_router());
        router.merge(Self::claim_tool_router());
        // Smart-account rules observability — read-only.
        router.merge(Self::rules_tool_router());
        router.merge(Self::rules_get_tool_router());
        // Agent-proposed context rules (Package D, GH issue #8).
        router.merge(Self::rule_create_tool_router());
        router
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Approval-spine helpers
// ─────────────────────────────────────────────────────────────────────────────

impl WalletServer {
    /// Derives the profile name string for approval-store path construction.
    ///
    /// Uses the same `OWNER_KEY_SERVICE_PREFIX`-strip logic as
    /// `profile_name_from_key_ref`.  Falls back to `"default"` if the
    /// service field does not start with the expected prefix so that approval-store
    /// paths are always well-formed even when called on a profile built without
    /// `KeyringEntryRef::default_owner_key`.
    ///
    /// The returned string is used to construct the pending-approval store path:
    /// `~/.local/state/stellar-agent/approvals/<profile_name>.toml`.
    ///
    /// Exposed as `pub` (not `pub(crate)`) because integration tests in
    /// `tests/approval_spine_integration.rs` need to verify the name-derivation
    /// logic.  The method derives only a non-secret string (the profile name);
    /// there is no security concern with public visibility.
    pub fn profile_name_for_approval(&self) -> String {
        let service = &self.profile.policy_owner_key_id.service;
        service
            .strip_prefix(OWNER_KEY_SERVICE_PREFIX)
            .unwrap_or("default")
            .to_owned()
    }

    /// Resolves the pending-approval store directory, honoring the test-only
    /// override so integration tests never write into the operator's real
    /// approval directory.
    pub(crate) fn resolve_approval_dir(
        &self,
    ) -> Result<std::path::PathBuf, stellar_agent_core::profile::schema::StateDirError> {
        #[cfg(any(test, feature = "test-helpers"))]
        if let Some(ref override_dir) = self.approval_dir_override {
            return Ok(override_dir.clone());
        }
        stellar_agent_core::profile::schema::default_approval_dir()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Replaces the active [`PolicyEngine`] for cross-track integration testing.
    ///
    /// The integration test in `tests/policy_v1_integration.rs` builds a real
    /// [`PolicyEngineV1`] from a signed temp policy file and substitutes it
    /// here so the dispatch gate can be exercised end-to-end without touching
    /// the OS-conventional policy directory or the keyring.
    ///
    /// Gated on `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub fn set_policy_engine_for_test(&mut self, engine: Arc<dyn PolicyEngine>) {
        self.policy_engine = engine;
    }

    /// Constructs a [`WalletServer`] with a test-local policy directory.
    ///
    /// Production construction passes `None` to [`build_policy_engine`], which
    /// preserves the OS-conventional [`default_policy_dir`] behavior.  This
    /// helper passes `Some(policy_dir)` so integration tests can exercise the
    /// full V1 policy-engine startup path without writing to operator state.
    ///
    /// The caller must keep the backing `tempfile::TempDir` alive for at least
    /// as long as construction can read the policy file.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`WalletServer::new`].
    #[doc(hidden)]
    pub fn new_with_policy_dir_for_test(
        profile: Profile,
        policy_dir: &Path,
    ) -> Result<Self, BuildRegistryError> {
        Self::new_with_clock_and_policy_dir(profile, default_clock(), Some(policy_dir))
    }

    /// Overrides the approval-store directory used by [`verify_attestation_gate`].
    ///
    /// In production `verify_attestation_gate` resolves the directory via
    /// `stellar_agent_core::profile::schema::default_approval_dir()`, which
    /// returns `~/Library/Application Support/Soneso.stellar-agent/approvals/`
    /// on macOS.  Without this override, integration tests that exercise the
    /// attestation gate pollute the developer's real wallet state.
    ///
    /// Each test must pass a `tempfile::TempDir` bound to a local variable that
    /// outlives the server; the `PathBuf` stored here is derived from the dir.
    ///
    /// Gated on `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub fn set_approval_dir_for_test(&mut self, dir: std::path::PathBuf) {
        self.approval_dir_override = Some(dir);
    }

    /// Overrides the toolset-grant store path used by the gated resolver.
    ///
    /// In production the path is resolved via `default_toolset_grants_path`.
    /// Integration tests set this to a path inside a `tempfile::TempDir`.
    ///
    /// Gated on `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub fn set_grant_store_path_for_test(&mut self, path: std::path::PathBuf) {
        self.grant_store_path_override = Some(path);
    }

    /// Overrides the toolsets root directory used by `stellar_toolset_invoke`.
    ///
    /// In production the toolsets root is resolved via `default_toolsets_dir()`.
    /// Integration tests set this to a path inside a `tempfile::TempDir` so the
    /// tests do not read or write the real installed toolsets.
    ///
    /// Gated on `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub fn set_toolsets_root_for_test(&mut self, path: std::path::PathBuf) {
        self.toolsets_root_override = Some(path);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ServerHandler implementation
// ─────────────────────────────────────────────────────────────────────────────

#[tool_handler(router = self.tool_router)]
impl ServerHandler for WalletServer {
    fn get_info(&self) -> InitializeResult {
        // The static portion of the instructions string describing tools and resources.
        const INSTRUCTIONS_STATIC: &str = "Stellar agent wallet MCP server. \
             Tools: stellar_balances (fetch native XLM balance and optional \
             trustline balances for a Stellar account, read-only); \
             stellar_friendbot (fund a testnet account via Friendbot, \
             testnet-only, destructive); \
             stellar_create_account (simulate step: build CreateAccount envelope \
             and mint nonce, returns envelope_xdr+nonce+expires_at_unix_ms); \
             stellar_create_account_commit (commit step: verify nonce, re-check \
             envelope, sign via keyring, submit — testnet-only, destructive); \
             stellar_pay (simulate step: build Payment envelope for native or \
             non-native assets, runs SEP-29 memo-required check, mints nonce); \
             stellar_pay_commit (commit step: verify nonce, re-check envelope, \
             sign via keyring, submit — testnet-only, destructive); \
             stellar_sep43_get_address (SEP-43 getAddress: returns the active \
             wallet address, read-only); \
             stellar_sep43_get_network (SEP-43 getNetwork: returns active network \
             name and passphrase, read-only); \
             stellar_sep43_sign_transaction (SEP-43 signTransaction: signs a \
             TransactionEnvelope XDR, returns signedTxXdr + signerAddress, \
             NOT destructive — does not submit); \
             stellar_sep43_sign_auth_entry (SEP-43 signAuthEntry: signs a \
             SorobanAuthorizationEntry XDR for G-key credentials, returns \
             signedAuthEntry + signerAddress, NOT destructive — does not submit); \
             stellar_sep43_sign_message (SEP-43 signMessage: signs an arbitrary \
             UTF-8 message via sha256(message) then ed25519, returns \
             signedMessage (hex) + signerAddress, NOT destructive); \
             stellar_sep43_sign_and_submit_transaction (SEP-43 signAndSubmit / \
             WC v2 stellar_signAndSubmitXDR: signs and submits a \
             TransactionEnvelope XDR, returns signedTxXdr + txHash + status, \
             destructive); \
             stellar_x402_create_payment (x402 v2 Exact Stellar payer: construct \
             and sign a PAYMENT-SIGNATURE payload from a PaymentRequirements \
             object, returns paymentSignature + payer + asset + amount + payTo + \
             network, read_only=false, not destructive — wallet does not submit); \
             stellar_x402_parse_receipt (x402 v2 receipt decode: parse a \
             PAYMENT-RESPONSE header value into a structured SettleResponse, \
             returns success + transaction + payer + network + errorReason, \
             read_only=true); \
             stellar_sep48_preview_invocation (SEP-48 typed-preview: fetch the \
             on-chain contract spec and render typed arg names + JSON values for \
             an InvokeHostFunction invocation, supply transaction_xdr or \
             contract_id+function, read_only=true); \
             stellar_sep47_discover (SEP-47 Contract Interface Discovery: read \
             the contractmetav0 sep meta entry and return the list of SEPs the \
             contract claims to implement, returns supported_seps:[...], \
             read_only=true); \
             stellar_sep53_sign_message (SEP-53 prefixed message signing: \
             SHA-256('Stellar Signed Message:\\n' + message) → ed25519, accepts \
             utf8 or base64 message_encoding, returns signature (base64) + \
             signer_public_key, read_only=false, not destructive); \
             stellar_sep53_verify_message (SEP-53 message verification: verify \
             a base64 signature against a G-strkey public key and message, \
             returns { valid: true } or an error, read_only=true); \
             stellar_sep7_parse_uri (SEP-7 inbound URI parse + verify: parse a \
             web+stellar:tx/pay?... URI into a structured preview, optionally \
             performs fresh stellar.toml fetch + ed25519 signature verification, \
             returns operation/fields/callback-authority/signature_status/ \
             origin_verified, NEVER auto-signs or auto-POSTs, read_only=true); \
             stellar_sep6_deposit_info (SEP-6 anchor capability discovery: \
             GET /info ONLY, returns decoded anchor capabilities including \
             authentication_required per asset, NEVER calls /deposit or /withdraw \
             or any KYC endpoint, read_only=true); \
             stellar_sep24_interactive_url (SEP-24 interactive deposit/withdraw \
             hand-off: resolve TRANSFER_SERVER_SEP0024, POST \
             /transactions/{deposit|withdraw}/interactive with SEP-10/45 JWT, \
             returns interactive_url + transaction_id + handoff_note, wallet \
             NEVER opens/scrapes the URL, NEVER transmits KYC fields, \
             read_only=false, not destructive); \
             stellar_x402_authenticated_payment (x402 v2 Exact Stellar payer with \
             SEP-10 identity gate: resolves home_domain stellar.toml → \
             WEB_AUTH_ENDPOINT + SIGNING_KEY → SSRF bind → ephemeral SEP-10 \
             challenge/response → JWT, then constructs PAYMENT-SIGNATURE, returns \
             paymentSignature + authorization (Bearer JWT) + payer + asset + \
             amount + payTo + home_domain + network + payto_anchored, gate aborts \
             BEFORE payment on any identity failure, read_only=false, not destructive); \
             stellar_fee_stats (fetch network fee statistics for fee estimation, \
             read-only); \
             stellar_blend_lend (Blend lending pool supply/withdraw/borrow/repay \
             via an ordered trust gate — pool WASM-hash pin, oracle allowlist, \
             oracle-staleness — then smart-account submit, destructive); \
             stellar_defindex_vault_deposit (DeFindex vault deposit via \
             smart-account submit, destructive); \
             stellar_defindex_vault_withdraw (DeFindex vault withdraw via \
             smart-account submit, destructive); \
             stellar_dex_trade (Soroswap ROUTER-DIRECT swap with venue allowlist, \
             router WASM-hash pin, and on-chain slippage re-verify, then \
             smart-account submit, destructive); \
             stellar_dex_quote (on-chain Soroswap get_amounts_out quote, \
             read-only); \
             stellar_trustline (simulate step: build ChangeTrust envelope, run the \
             issuer clawback-flag gate, mint nonce); \
             stellar_trustline_commit (commit step: verify nonce, re-check \
             envelope, sign via keyring, submit, destructive); \
             stellar_claim (simulate step: fetch the claimable-balance entry, \
             render a typed preview, run the claim guards (claimant, predicate, \
             trustline, fee affordability), build a ClaimClaimableBalance \
             envelope, mint nonce); \
             stellar_claim_commit (commit step: verify nonce, re-fetch and \
             re-check the entry, re-check envelope, sign via keyring, submit, \
             destructive); \
             stellar_toolset_list (enumerate installed toolsets and their invocable \
             actions, read-only); \
             stellar_toolset_invoke (invoke a named action of an installed toolset, \
             routed to a trusted tool through capability enforcement); \
             stellar_rules_list (enumerate active context rules on a smart account: \
             rule_id, name, context_type_label, valid_until, signer_count, \
             policy_count, plus as_of_ledger, read_only=true); \
             stellar_rules_get (read a single context rule's metadata, its policies \
             with best-effort identified_kind classification, and — when exactly \
             one attached policy identifies as spending-limit — the budget \
             snapshot (spending_limit, period_ledgers, in_window_spent, \
             remaining_budget, as_of_ledger); in_window_spent/remaining_budget are \
             exact only as of as_of_ledger, read_only=true); \
             stellar_rule_create (propose step, testnet-only: resolve signers \
             (delegated, raw external, or webauthn passkey by credential name — \
             resolved to bytes at propose time), policies (raw or typed \
             spending-limit), context, name, expiry, and auth_rule_ids; simulate \
             the add_context_rule installation, mint a domain-separated proposal \
             digest, and park the full resolved definition as a pending \
             approval, returns approval_nonce+expires_at_unix_ms+summary); \
             stellar_rule_create_commit (commit step, testnet-only: ALWAYS \
             requires operator attestation regardless of the policy verdict — \
             the agent never holds rule-write authority; verify the operator's \
             attestation over the resolved definition via a dedicated gate, \
             recompute the digest from the stored snapshot, install the rule — \
             destructive). \
             Resources: mcp-resource://usage.md (tool documentation), \
             mcp-resource://profiles/<name> (non-secret profile metadata), \
             mcp-resource://accounts/<G> (public account directory). \
             Chain IDs: stellar:testnet, stellar:mainnet.";

        InitializeResult::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::new(
            "stellar-agent-mcp",
            env!("CARGO_PKG_VERSION"),
        ))
        .with_protocol_version(ProtocolVersion::V_2024_11_05)
        .with_instructions(INSTRUCTIONS_STATIC)
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, rmcp::ErrorData> {
        let profile_names = loader::list_profiles()
            .map_err(|_| rmcp::ErrorData::internal_error("profile_resource_list_failed", None))?;
        let mut resources = vec![
            rmcp::model::RawResource::new(
                USAGE_RESOURCE_URI,
                "Tool usage documentation".to_owned(),
            )
            .no_annotation(),
        ];
        resources.extend(
            profile_names
                .iter()
                .map(|name| profile_resource_for_name(name)),
        );
        resources.extend(
            enrolled_account_ids(&self.profile)
                .iter()
                .map(|account_id| account_resource_for_id(account_id)),
        );

        Ok(ListResourcesResult {
            resources,
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, rmcp::ErrorData> {
        match request.uri.as_str() {
            USAGE_RESOURCE_URI => {
                let content = usage_md_content();
                Ok(ReadResourceResult::new(vec![ResourceContents::text(
                    content,
                    USAGE_RESOURCE_URI,
                )]))
            }
            uri if uri.starts_with(PROFILE_RESOURCE_PREFIX) => {
                let Some(name) = profile_resource_name_from_uri(uri) else {
                    return Err(profile_resource_not_found(uri));
                };
                let profile_names = loader::list_profiles().map_err(|_| {
                    rmcp::ErrorData::internal_error("profile_resource_list_failed", None)
                })?;
                if !profile_names
                    .iter()
                    .any(|profile_name| profile_name == name)
                {
                    return Err(profile_resource_not_found(uri));
                }

                let profile =
                    loader::load(name, None).map_err(|_| profile_resource_load_error(name))?;
                let content = profile_metadata_json(&profile)?;
                Ok(ReadResourceResult::new(vec![
                    ResourceContents::text(content, uri).with_mime_type("application/json"),
                ]))
            }
            uri if uri.starts_with(ACCOUNT_RESOURCE_PREFIX) => {
                let account_id = account_resource_id_from_uri(uri)?;
                if !enrolled_account_ids(&self.profile)
                    .iter()
                    .any(|enrolled| enrolled == account_id)
                {
                    return Err(profile_resource_not_found(uri));
                }

                let content = account_directory_json(account_id, &self.profile)?;
                Ok(ReadResourceResult::new(vec![
                    ResourceContents::text(content, uri).with_mime_type("application/json"),
                ]))
            }
            _ => Err(profile_resource_not_found(&request.uri)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use serde_json::Value;
    use stellar_agent_core::profile::schema::{MINIMUM_FLOOR, Profile};

    use super::*;

    const SOURCE_G: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

    fn test_profile() -> Profile {
        Profile::builder_testnet(
            "stellar-agent-signer-alice",
            "default",
            "stellar-agent-nonce-alice",
            "default",
        )
        .with_profile_name("alice")
        .usd_threshold(MINIMUM_FLOOR + 42)
        .build()
    }

    fn test_account_profile() -> Profile {
        Profile::builder_testnet(
            "stellar-agent-signer-alice",
            SOURCE_G,
            "stellar-agent-nonce-alice",
            "default",
        )
        .with_profile_name("alice")
        .build()
    }

    #[test]
    fn profile_resource_uri_rejects_path_shapes() {
        assert_eq!(
            profile_resource_name_from_uri("mcp-resource://profiles/alice"),
            Some("alice")
        );
        assert!(profile_resource_name_from_uri("mcp-resource://profiles/").is_none());
        assert!(profile_resource_name_from_uri("mcp-resource://profiles/../alice").is_none());
        assert!(profile_resource_name_from_uri("mcp-resource://profiles/a/b").is_none());
        assert!(profile_resource_name_from_uri("mcp-resource://profiles/a\\b").is_none());
    }

    #[test]
    fn profile_resource_for_name_uses_profile_uri() {
        let resource = profile_resource_for_name("alice");
        assert_eq!(resource.raw.uri, "mcp-resource://profiles/alice");
        assert_eq!(resource.raw.name, "Non-secret metadata for profile `alice`");
    }

    #[test]
    fn profile_metadata_json_is_exact_allowlist() {
        let text = profile_metadata_json(&test_profile()).expect("metadata serializes");
        let value: Value = serde_json::from_str(&text).expect("valid json");
        let object = value.as_object().expect("metadata object");
        let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "chain_id",
                "mcp_disabled",
                "network_passphrase",
                "rpc_url",
                "usd_threshold"
            ]
        );
        assert_eq!(value["chain_id"], "stellar:testnet");
        assert_eq!(value["mcp_disabled"], false);
        assert_eq!(value["usd_threshold"], MINIMUM_FLOOR + 42);

        assert!(!text.contains("stellar-agent-signer"));
        assert!(!text.contains("stellar-agent-nonce"));
        assert!(!text.contains("mcp_signer_default"));
        assert!(!text.contains("mcp_nonce_key_alias"));
        assert!(!text.contains("policy_owner_key_id"));
        assert!(!text.contains("audit_log_hash_chain_key_id"));
        assert!(!text.contains("attestation_key_id"));
        assert!(!text.contains("counterparty_cache_key_id"));
    }

    #[test]
    fn account_resource_uri_round_trips_g_strkey() {
        let uri = account_resource_uri(SOURCE_G);
        assert_eq!(uri, format!("mcp-resource://accounts/{SOURCE_G}"));
        assert_eq!(account_resource_id_from_uri(&uri).unwrap(), SOURCE_G);

        let resources = enrolled_account_ids_from_profiles([&test_account_profile()]);
        assert_eq!(resources, [SOURCE_G]);
        let resource = account_resource_for_id(SOURCE_G);
        assert_eq!(resource.raw.uri, uri);
        assert_eq!(
            resource.raw.name,
            format!("Public account directory entry for `{SOURCE_G}`")
        );
    }

    #[test]
    fn account_resource_uri_rejects_invalid_g_strkey() {
        let err =
            account_resource_id_from_uri("mcp-resource://accounts/not-a-g-strkey").unwrap_err();
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert_eq!(err.message, "invalid_account_resource_id");

        assert!(
            account_resource_id_from_uri("mcp-resource://accounts/").is_err(),
            "empty account resource must be rejected"
        );
        assert!(
            account_resource_id_from_uri("mcp-resource://accounts/../alice").is_err(),
            "path-like account resource must be rejected"
        );
    }

    #[test]
    fn account_directory_json_is_exact_allowlist() {
        let profile = test_account_profile();
        let text = account_directory_json(SOURCE_G, &profile).expect("account json serializes");
        let value: Value = serde_json::from_str(&text).expect("valid json");
        let object = value.as_object().expect("account metadata object");
        let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(keys, ["account_id", "chain_id", "network_passphrase"]);
        assert_eq!(value["account_id"], SOURCE_G);
        assert_eq!(value["chain_id"], "stellar:testnet");

        assert!(!text.contains("stellar-agent-signer"));
        assert!(!text.contains("stellar-agent-nonce"));
        assert!(!text.contains("mcp_signer_default"));
        assert!(!text.contains("mcp_nonce_key_alias"));
        assert!(!text.contains("policy_owner_key_id"));
        assert!(!text.contains("audit_log_hash_chain_key_id"));
        assert!(!text.contains("attestation_key_id"));
        assert!(!text.contains("counterparty_cache_key_id"));
    }
}
