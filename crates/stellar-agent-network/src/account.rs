//! On-chain account view and the `fetch_account` RPC query.
//!
//! `AccountView` is the stable, serialisable projection of Stellar on-chain
//! account state consumed by CLI commands and MCP tools. `fetch_account`
//! queries the Stellar RPC `getLedgerEntries` method for the `LedgerKey::Account`
//! entry, parses the returned XDR, and maps it to an `AccountView`.
//!
//! # Trustline enumeration
//!
//! The Stellar RPC `getLedgerEntries` supports `LedgerKey::Trustline` entries,
//! but requires knowing the trustline key (account ID + asset) in advance —
//! there is no "list all trustlines for account X" RPC method.  The caller
//! passes an explicit `&[Asset]` slice to `fetch_account`; when non-empty,
//! both the `LedgerKey::Account` entry and one `LedgerKey::Trustline` per
//! asset are fetched in a **single** batched `getLedgerEntries` call.  Assets
//! that the account does not currently trust are silently omitted from the
//! returned `balances` list (not present = no trustline; matches Horizon
//! semantics where trustlines that do not exist simply do not appear in the
//! `/accounts/:id` response).
//!
//! # home_domain surface
//!
//! `AccountEntry.home_domain` is surfaced as `AccountView.home_domain:
//! Option<String>`.  The field is populated in `project_account_entry` by
//! reading the XDR `String32` byte slice and validating the shared lowercase
//! LDH `home_domain` rule.  Empty values, Unicode, uppercase, underscores, and
//! other non-LDH bytes are mapped to `None`.
//!
//! # Account lookup
//!
//! All account lookups route through `getLedgerEntries`, not the Horizon REST API.

use serde::{Deserialize, Serialize};
pub use stellar_agent_core::BASE_RESERVE_STROOPS;
use stellar_agent_core::amount::StellarAmount;
use stellar_agent_core::error::{NetworkError, ProtocolError, ValidationError, WalletError};
pub(crate) use stellar_agent_core::observability::redact_strkey_first5_last5 as redact_account_id;
use stellar_agent_core::{STELLAR_DECIMALS, STROOPS_PER_XLM};
use stellar_rpc_client::Error as RpcError;
use stellar_xdr::{
    AccountEntry, AccountId, LedgerEntryData, LedgerKey, LedgerKeyAccount, LedgerKeyData,
    LedgerKeyTrustLine, PublicKey, ReadXdr, Signer as XdrSigner, Uint256, WriteXdr,
};

use crate::builder::Asset;
use crate::client::StellarRpcClient;
use crate::counterparty::validation::is_valid_ldh_home_domain;
use crate::redact::redact_url_authority;

// ─────────────────────────────────────────────────────────────────────────────
// AccountView and sub-types
// ─────────────────────────────────────────────────────────────────────────────

/// A serialisable, `#[non_exhaustive]` view of a Stellar account's on-chain
/// state.
///
/// Produced by [`fetch_account`] and consumed by the `balances` CLI command
/// and MCP tools. All balance strings use the 7-decimal Stellar representation
/// (e.g. `"1234.5678900"`) matching [`stellar_agent_core::StellarAmount`]
/// formatting.
///
/// # Non-exhaustive note
///
/// New fields may be added in future versions without a breaking API change.
/// Match arms over this struct must include a `..` wildcard.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::{StellarRpcClient, fetch_account};
///
/// # async fn run() -> Result<(), stellar_agent_core::WalletError> {
/// let client = StellarRpcClient::new("https://soroban-testnet.stellar.org")?;
/// let view = fetch_account(&client, "GABC...XYZ", &[]).await?;
/// println!("native balance: {}", view.balances[0].balance);
/// # Ok(()) }
/// ```
#[non_exhaustive]
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountView {
    /// The Stellar G-strkey of the queried account.
    ///
    /// Full account ID shown to the operator; redaction applies at log
    /// boundaries only, not in user-facing output.
    pub account_id: String,

    /// The current sequence number of the account.
    pub sequence_number: i64,

    /// The number of subentries owned by this account (signers, trustlines,
    /// offers, data entries).
    ///
    /// Per the Stellar protocol, each subentry requires an additional
    /// [`BASE_RESERVE_STROOPS`] of native XLM to be held as a minimum reserve.
    /// The total minimum reserve is `(2 + subentry_count) * BASE_RESERVE_STROOPS`.
    ///
    /// XDR source: `AccountEntry.num_sub_entries` (`Uint32` / `u32`).
    pub subentry_count: u32,

    /// All balances associated with this account.
    ///
    /// Native XLM is always first.  Trustline entries (when requested) follow
    /// in the order specified by the `trustline_assets` argument to
    /// [`fetch_account`]; assets the account does not currently trust are
    /// silently omitted from the list — not represented as zero-balance
    /// placeholders.
    pub balances: Vec<BalanceView>,

    /// The low, medium, high, and master-weight thresholds.
    pub thresholds: ThresholdsView,

    /// All signers on this account (including the master key).
    pub signers: Vec<SignerView>,

    /// The account's self-asserted operator `home_domain`, when set on-chain.
    ///
    /// Sourced from `AccountEntry.home_domain` (XDR `String32`, max 32 bytes).
    /// `None` when the on-chain field is empty or fails lowercase LDH validation.
    ///
    /// Used by `CounterpartyAllowlistCriterion` (`HOME_DOMAIN` match path).
    /// Lowercase LDH validation is applied during projection as defence-in-depth
    /// against IDN homoglyph injection: non-LDH values produce `None` rather than
    /// a potentially misleading or malformed string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_domain: Option<String>,

    /// Typed projection of the account's `flags` bitfield.
    ///
    /// Sourced from `AccountEntry.flags` (`u32`).  Each bit is mapped to a
    /// named boolean:
    ///
    /// - `auth_required` — `AUTH_REQUIRED_FLAG = 0x1`
    /// - `auth_revocable` — `AUTH_REVOCABLE_FLAG = 0x2`
    /// - `auth_immutable` — `AUTH_IMMUTABLE_FLAG = 0x4`
    /// - `auth_clawback_enabled` — `AUTH_CLAWBACK_ENABLED_FLAG = 0x8`
    ///
    /// `None` when the `AccountEntry` could not be decoded (defensive).
    /// In practice the flags are always present when `fetch_account` succeeds.
    ///
    /// The `auth_clawback_enabled` bit gates the `trustline` verb's clawback
    /// disclosure check; `auth_revocable` is informational only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_flags: Option<AccountFlagsView>,
}

/// A typed projection of `AccountEntry.flags` into named boolean fields.
///
/// Each field corresponds to one bit in the `AccountFlags` XDR enum.
/// Boolean flags are third-party public facts and may be logged freely.
///
/// Bit values from the `AccountFlags` XDR enum:
/// - `RequiredFlag = 1`
/// - `RevocableFlag = 2`
/// - `ImmutableFlag = 4`
/// - `ClawbackEnabledFlag = 8`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountFlagsView {
    /// `AUTH_REQUIRED_FLAG = 0x1`: trustlines require explicit issuer authorisation.
    pub auth_required: bool,
    /// `AUTH_REVOCABLE_FLAG = 0x2`: issuer can revoke (freeze) trustlines.
    pub auth_revocable: bool,
    /// `AUTH_IMMUTABLE_FLAG = 0x4`: all `AUTH_*` flags are now read-only.
    pub auth_immutable: bool,
    /// `AUTH_CLAWBACK_ENABLED_FLAG = 0x8`: trustlines are created with clawback enabled.
    pub auth_clawback_enabled: bool,
}

impl AccountFlagsView {
    /// Projects a raw `u32` flags value into an `AccountFlagsView`.
    ///
    /// Bit constants from the `AccountFlags` XDR enum:
    /// `RequiredFlag = 1`, `RevocableFlag = 2`,
    /// `ImmutableFlag = 4`, `ClawbackEnabledFlag = 8`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_network::account::AccountFlagsView;
    ///
    /// let v = AccountFlagsView::from_raw(0x0A); // RevocableFlag(0x2) | ClawbackEnabledFlag(0x8)
    /// assert!(!v.auth_required);
    /// assert!(v.auth_revocable);
    /// assert!(!v.auth_immutable);
    /// assert!(v.auth_clawback_enabled);
    /// ```
    #[must_use]
    pub fn from_raw(flags: u32) -> Self {
        Self {
            auth_required: (flags & 0x1) != 0,
            auth_revocable: (flags & 0x2) != 0,
            auth_immutable: (flags & 0x4) != 0,
            auth_clawback_enabled: (flags & 0x8) != 0,
        }
    }
}

impl AccountView {
    /// Constructs an `AccountView`.
    ///
    /// Intended for test fixtures and mock-RPC integration tests that need to
    /// construct a view without going through the network.
    ///
    /// Pre-1.0: positional parameters may be extended without a semver break.
    /// At 1.0 freeze, this will be replaced with a builder.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_network::{AccountView, AssetView, BalanceView, ThresholdsView};
    ///
    /// let view = AccountView::new(
    ///     "GABC".to_owned(),
    ///     42,
    ///     0,
    ///     vec![BalanceView::new(
    ///         AssetView::native(),
    ///         "100.0000000".to_owned(),
    ///         None,
    ///         "0.0000000".to_owned(),
    ///         "0.0000000".to_owned(),
    ///     )],
    ///     ThresholdsView::new(1, 0, 0, 0),
    ///     vec![],
    ///     None,
    ///     None,
    /// );
    /// assert_eq!(view.account_id, "GABC");
    /// assert_eq!(view.subentry_count, 0);
    /// assert_eq!(view.home_domain, None);
    /// assert_eq!(view.account_flags, None);
    /// ```
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: String,
        sequence_number: i64,
        subentry_count: u32,
        balances: Vec<BalanceView>,
        thresholds: ThresholdsView,
        signers: Vec<SignerView>,
        home_domain: Option<String>,
        account_flags: Option<AccountFlagsView>,
    ) -> Self {
        Self {
            account_id,
            sequence_number,
            subentry_count,
            balances,
            thresholds,
            signers,
            home_domain,
            account_flags,
        }
    }

    /// Computes the minimum native XLM reserve (in stroops) that this account
    /// must hold and cannot spend.
    ///
    /// The Stellar protocol formula is `(2 + subentry_count) * base_reserve`.
    /// The base reserve is a protocol-level constant; the `base_reserve_stroops`
    /// parameter exists so callers can pass a future operator-configured value
    /// without requiring a new method.  Pass [`BASE_RESERVE_STROOPS`] for the
    /// protocol default.
    ///
    /// Multiplication uses [`i64::saturating_mul`] to guard against adversarial
    /// input.  In practice `subentry_count` is bounded by the Stellar protocol
    /// at 1000; the product cannot overflow a real `i64` at that scale.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_network::{
    ///     AccountView, AssetView, BalanceView, ThresholdsView, BASE_RESERVE_STROOPS,
    /// };
    ///
    /// let view = AccountView::new(
    ///     "GABC".to_owned(),
    ///     1,
    ///     3,   // three subentries
    ///     vec![BalanceView::new(
    ///         AssetView::native(),
    ///         "100.0000000".to_owned(),
    ///         None,
    ///         "0.0000000".to_owned(),
    ///         "0.0000000".to_owned(),
    ///     )],
    ///     ThresholdsView::new(1, 0, 0, 0),
    ///     vec![],
    ///     None,
    ///     None,
    /// );
    /// // (2 + 3) * 5_000_000 = 25_000_000 stroops
    /// assert_eq!(view.reserves_stroops(BASE_RESERVE_STROOPS), 25_000_000);
    /// ```
    ///
    /// # Behaviour with negative input
    ///
    /// Negative `base_reserve_stroops` is a caller-error; the function does not
    /// assert against it.  Pass [`BASE_RESERVE_STROOPS`] for protocol-default
    /// behaviour.  Future profile-driven base_reserve overrides will validate
    /// non-negativity at the validation boundary.
    ///
    /// # Notes on saturating arithmetic
    ///
    /// Returns are saturating; callers should treat the saturated `i64::MAX` case
    /// as unreachable in practice (subentry_count protocol-capped at 1000) but
    /// should NOT chain `checked_sub` against this value — `saturating_sub` is
    /// the right operator at the call site, since under-reserved accounts produce
    /// `available = 0` which is the operational signal we want to surface as
    /// `InsufficientBalance{have:"0"}`.
    ///
    #[must_use]
    pub fn reserves_stroops(&self, base_reserve_stroops: i64) -> i64 {
        // i64::from(u32) is always safe; no `as` cast.
        (i64::from(self.subentry_count).saturating_add(2)).saturating_mul(base_reserve_stroops)
    }
}

/// A single balance entry — either the native XLM balance or a trustline.
///
/// `asset` distinguishes native from non-native entries. `limit` is `None`
/// for the native entry and `Some(...)` for trustlines.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceView {
    /// The asset this balance represents.
    pub asset: AssetView,

    /// The balance amount as a 7-decimal decimal string (e.g. `"1234.5678900"`).
    ///
    /// Formatted via the same logic as `stellar_agent_core::StellarAmount::Display`.
    pub balance: String,

    /// The trustline limit, or `None` for the native (XLM) entry.
    ///
    /// For trustlines, the value `Some("9223372036854775807.0000000")` indicates
    /// that the account set no explicit limit (Stellar protocol maximum `i64`
    /// stroops = `9_223_372_036_854_775_807`), which Horizon renders as
    /// `"922337203685.4775807"`.  This wallet renders the raw stroop decimal.
    pub limit: Option<String>,

    /// Liabilities from open buy offers, as a 7-decimal decimal string.
    pub buying_liabilities: String,

    /// Liabilities from open sell offers, as a 7-decimal decimal string.
    pub selling_liabilities: String,
}

impl BalanceView {
    /// Constructs a `BalanceView`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_network::{AssetView, BalanceView};
    ///
    /// let b = BalanceView::new(
    ///     AssetView::native(),
    ///     "100.0000000".to_owned(),
    ///     None,
    ///     "0.0000000".to_owned(),
    ///     "0.0000000".to_owned(),
    /// );
    /// assert_eq!(b.balance, "100.0000000");
    /// ```
    #[must_use]
    pub fn new(
        asset: AssetView,
        balance: String,
        limit: Option<String>,
        buying_liabilities: String,
        selling_liabilities: String,
    ) -> Self {
        Self {
            asset,
            balance,
            limit,
            buying_liabilities,
            selling_liabilities,
        }
    }

    /// Parses the `balance` field to stroops using the canonical decimal-to-stroops
    /// parser.
    ///
    /// Uses `StellarAmount::parse_with_unit` with integer-only arithmetic to
    /// avoid f64 precision loss for large balances (≥ ~9 million XLM).
    ///
    /// # Errors
    ///
    /// - [`WalletError::Validation`] wrapping a [`ValidationError`] variant if
    ///   `self.balance` cannot be parsed as a 7-decimal XLM string.  In practice
    ///   this should never happen for values returned by [`fetch_account`] (they
    ///   are produced by `format_stroops`, which always emits a valid 7-decimal
    ///   string), but the fallible path is preserved for defensive handling of
    ///   externally-supplied `BalanceView` instances.
    /// - [`WalletError::Validation`] wrapping [`ValidationError::AmountOutOfRange`]
    ///   if the parsed stroop value is negative.  Defence-in-depth: on-chain
    ///   balances are always ≥ 0; a negative result indicates a malformed RPC
    ///   response (e.g. a leading `'-'` in the balance string).
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_network::{AssetView, BalanceView};
    ///
    /// let b = BalanceView::new(
    ///     AssetView::native(),
    ///     "9999999999.9999999".to_owned(),
    ///     None,
    ///     "0.0000000".to_owned(),
    ///     "0.0000000".to_owned(),
    /// );
    /// // 9_999_999_999.9999999 XLM = 99_999_999_999_999_999 stroops
    /// assert_eq!(b.balance_stroops().unwrap(), 99_999_999_999_999_999i64);
    /// ```
    pub fn balance_stroops(&self) -> Result<i64, WalletError> {
        // Format as "NNN.NNNNNNN XLM" so parse_with_unit can accept it.
        // The balance string from format_stroops is already 7-decimal but lacks
        // the unit suffix.
        let with_unit = format!("{} XLM", self.balance);
        let stroops = StellarAmount::parse_with_unit(&with_unit)
            .map(|a| a.as_stroops())
            .map_err(|e: ValidationError| WalletError::Validation(e))?;
        // Defence-in-depth: on-chain balances are always >= 0; a negative parse
        // result indicates a malformed RPC response (e.g. leading '-' in the
        // balance string).
        if stroops < 0 {
            return Err(WalletError::Validation(ValidationError::AmountOutOfRange {
                amount: format!(
                    "BalanceView::balance_stroops: negative stroop value ({stroops}) for '{}'",
                    self.balance
                ),
            }));
        }
        Ok(stroops)
    }
}

/// Asset identifier for a balance entry.
///
/// `"native"` for XLM. Non-native assets carry `code` and `issuer`.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetView {
    /// `"native"` for XLM; the alphanumeric asset code otherwise (e.g. `"USDC"`).
    pub asset_type: String,

    /// `None` for native XLM; the issuer G-strkey otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

impl AssetView {
    /// Constructs the native XLM asset view.
    #[must_use]
    pub fn native() -> Self {
        Self {
            asset_type: "native".to_owned(),
            issuer: None,
        }
    }

    /// Constructs a non-native asset view.
    ///
    /// # Panics
    ///
    /// Never panics.
    #[must_use]
    pub fn credit(code: impl Into<String>, issuer: impl Into<String>) -> Self {
        Self {
            asset_type: code.into(),
            issuer: Some(issuer.into()),
        }
    }
}

/// The three operation thresholds and the master-key weight for an account.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdsView {
    /// Weight required for low-threshold operations.
    pub low: u8,
    /// Weight required for medium-threshold operations.
    pub med: u8,
    /// Weight required for high-threshold operations.
    pub high: u8,
    /// The master key weight.
    pub master: u8,
}

impl ThresholdsView {
    /// Constructs a `ThresholdsView` with all four threshold values.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_network::ThresholdsView;
    ///
    /// let t = ThresholdsView::new(1, 2, 3, 4);
    /// assert_eq!(t.master, 1);
    /// assert_eq!(t.low, 2);
    /// ```
    #[must_use]
    pub fn new(master: u8, low: u8, med: u8, high: u8) -> Self {
        Self {
            master,
            low,
            med,
            high,
        }
    }
}

/// A single signer on an account.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerView {
    /// The signer's public key as a G-strkey (ed25519) or other strkey variant.
    pub key: String,
    /// The weight assigned to this signer.
    pub weight: u32,
    /// The signer type: `"ed25519"`, `"hash_x"`, or `"pre_auth_tx"`.
    pub signer_type: String,
}

impl SignerView {
    /// Constructs a `SignerView`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_network::SignerView;
    ///
    /// let s = SignerView::new("GABC".to_owned(), 1, "ed25519".to_owned());
    /// assert_eq!(s.weight, 1);
    /// ```
    #[must_use]
    pub fn new(key: String, weight: u32, signer_type: String) -> Self {
        Self {
            key,
            weight,
            signer_type,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// fetch_account
// ─────────────────────────────────────────────────────────────────────────────

/// Fetches the current on-chain state of a Stellar account via Stellar RPC.
///
/// When `trustline_assets` is empty, issues a single `getLedgerEntries` call
/// for the `LedgerKey::Account` entry and returns an [`AccountView`] with the
/// native XLM balance only.
///
/// When `trustline_assets` is non-empty, issues a **single** batched
/// `getLedgerEntries` call for all N+1 keys (1 account key + N trustline
/// keys).  The account entry is projected to the `AccountView` base; each
/// present trustline entry is appended to `balances`.  Trustline keys that
/// return no entry (account does not trust that asset) are silently omitted.
///
/// Account IDs appearing in `tracing::debug!` calls are redacted to the
/// first-5-last-5 form.  The returned `AccountView` carries the full account
/// ID for user-facing output.
///
/// # Errors
///
/// - [`WalletError::Network`] wrapping [`NetworkError::AccountNotFound`] if the
///   account does not exist on the network.
/// - [`WalletError::Network`] wrapping [`NetworkError::RpcTimeout`] if the RPC
///   request times out.
/// - [`WalletError::Network`] wrapping [`NetworkError::RpcUnreachable`] if the
///   endpoint is unreachable.
/// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`]
///   if the returned XDR cannot be decoded or a trustline asset cannot be
///   converted to XDR (should not occur for validated [`Asset`] values).
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::{StellarRpcClient, fetch_account};
///
/// # async fn run() -> Result<(), stellar_agent_core::WalletError> {
/// let client = StellarRpcClient::new("https://soroban-testnet.stellar.org")?;
/// // Native-only (no trustline assets requested):
/// let account = fetch_account(&client, "GABC...XYZ", &[]).await?;
/// assert_eq!(account.balances[0].asset.asset_type, "native");
/// # Ok(()) }
/// ```
pub async fn fetch_account(
    client: &StellarRpcClient,
    account_id: &str,
    trustline_assets: &[Asset],
) -> Result<AccountView, WalletError> {
    // Redact account ID at the log boundary.
    let redacted = redact_account_id(account_id);
    tracing::debug!(
        account_id = %redacted,
        trustline_count = trustline_assets.len(),
        "fetch_account: querying RPC"
    );

    // Parse the account_id into the XDR AccountId for key construction.
    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_id).map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("invalid account_id for fetch_account: {e}"),
        })
    })?;
    let xdr_account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes.0)));

    // Build the ledger keys: 1 account key + N trustline keys.
    let account_key = LedgerKey::Account(LedgerKeyAccount {
        account_id: xdr_account_id.clone(),
    });

    let mut keys: Vec<LedgerKey> = Vec::with_capacity(1 + trustline_assets.len());
    keys.push(account_key);

    for asset in trustline_assets {
        let tl_asset = asset.to_xdr_trust_line_asset()?;
        keys.push(LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: xdr_account_id.clone(),
            asset: tl_asset,
        }));
    }

    // Single batched RPC call for all keys.
    let response = client
        .inner
        .get_ledger_entries(&keys)
        .await
        .map_err(|e| map_rpc_error_generic(&e, &client.url))?;

    let entries = response.entries.unwrap_or_default();

    // Decode each response key XDR exactly once and classify entries (Account
    // vs Trustline), populating a HashMap from base64-key → entry-index for
    // the trustline lookup step.  Then iterate `trustline_assets` in
    // caller-supplied order and look up each by re-encoding its expected
    // LedgerKey to base64.  This guarantees `view.balances[1..]` is in
    // caller-specified order regardless of RPC response order.
    //
    // The RPC returns `LedgerEntryResult { key: LedgerKey XDR, xdr: LedgerEntryData XDR }`.
    // `entry.xdr` is `LedgerEntryData`, NOT a full `LedgerEntry`.  This matches the
    // `get_account` helper in rs-stellar-rpc-client which decodes via
    // `LedgerEntryData::read_xdr_base64`.
    let mut account_entry_opt: Option<AccountEntry> = None;
    // key_to_entry_idx: maps the raw base64 key string to its position in entries.
    let mut key_to_entry_idx: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::with_capacity(entries.len());

    for (idx, e) in entries.iter().enumerate() {
        // Keys and entry data come from an untrusted RPC response; bounded limits
        // prevent a malformed nested structure from exhausting the stack.
        let lk = LedgerKey::from_xdr_base64(
            &e.key,
            stellar_agent_xdr_limits::untrusted_decode_limits(e.key.len()),
        )
        .map_err(|err| {
            WalletError::Protocol(ProtocolError::XdrCodecFailed {
                detail: format!("failed to decode ledger key XDR: {err}"),
            })
        })?;

        match lk {
            LedgerKey::Account(_) => {
                // Decode the entry data as LedgerEntryData (what the RPC returns).
                let led = LedgerEntryData::from_xdr_base64(
                    &e.xdr,
                    stellar_agent_xdr_limits::untrusted_decode_limits(e.xdr.len()),
                )
                .map_err(|err| {
                    WalletError::Protocol(ProtocolError::XdrCodecFailed {
                        detail: format!("failed to decode account entry data XDR: {err}"),
                    })
                })?;
                if let LedgerEntryData::Account(ae) = led {
                    account_entry_opt = Some(ae);
                }
            }
            LedgerKey::Trustline(_) => {
                key_to_entry_idx.insert(e.key.as_str(), idx);
            }
            _ => {}
        }
    }

    let account_entry_data = account_entry_opt.ok_or_else(|| {
        WalletError::Network(NetworkError::AccountNotFound {
            account_id: account_id.to_owned(),
        })
    })?;

    tracing::debug!(account_id = %redacted, "fetch_account: account entry received");

    let mut view = project_account_entry(account_id, &account_entry_data)?;

    // Append trustline entries in request order.
    //
    // Iterating over `trustline_assets` (the caller-supplied slice) guarantees
    // that `view.balances[1..]` is in the same order as the request.  Assets
    // the account does not trust (absent from the RPC response) are silently
    // omitted — not represented as zero-balance placeholders.
    for asset in trustline_assets {
        // Reconstruct the expected LedgerKey for this asset.
        let tl_asset = asset.to_xdr_trust_line_asset()?;
        let expected_key = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: xdr_account_id.clone(),
            asset: tl_asset,
        });
        let expected_key_b64 = expected_key
            .to_xdr_base64(stellar_xdr::Limits::none())
            .map_err(|e| {
                WalletError::Protocol(ProtocolError::XdrCodecFailed {
                    detail: format!("failed to encode trustline key for lookup: {e}"),
                })
            })?;

        let Some(&idx) = key_to_entry_idx.get(expected_key_b64.as_str()) else {
            // RPC did not return this trustline — account does not trust this asset.
            continue;
        };

        // Trustline entry data comes from an untrusted RPC response; bounded
        // limits prevent a malformed nested structure from exhausting the stack.
        let led = LedgerEntryData::from_xdr_base64(
            &entries[idx].xdr,
            stellar_agent_xdr_limits::untrusted_decode_limits(entries[idx].xdr.len()),
        )
        .map_err(|e| {
            WalletError::Protocol(ProtocolError::XdrCodecFailed {
                detail: format!("failed to decode trustline entry data XDR: {e}"),
            })
        })?;

        if let LedgerEntryData::Trustline(tl_entry) = led {
            let balance_view = project_trustline_entry(&tl_entry)?;
            view.balances.push(balance_view);
        }
    }

    Ok(view)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Projects an XDR `TrustLineEntry` into a [`BalanceView`].
///
/// The `balance` and `limit` fields are formatted using the same 7-decimal
/// logic as the native XLM entry.  Liabilities live in
/// `TrustLineEntryExt::V1(v1).liabilities`; V0 (no extension) is treated as
/// zero liabilities.
///
/// Asset reconstruction:
/// - `TrustLineAsset::Native` → `AssetView::native()` (edge case; native XLM
///   does not normally appear as a trustline, but handled defensively).
/// - `TrustLineAsset::CreditAlphanum4` / `CreditAlphanum12` → `AssetView::credit`
///   with the null-padded code bytes trimmed and the issuer G-strkey encoded.
/// - `TrustLineAsset::PoolShare` → returns `WalletError::Protocol`; liquidity-pool
///   share trustlines are not supported.  Callers should never pass a `PoolShare`
///   asset to `fetch_account`.
fn project_trustline_entry(tl: &stellar_xdr::TrustLineEntry) -> Result<BalanceView, WalletError> {
    use stellar_xdr::TrustLineAsset;

    let asset_view = match &tl.asset {
        TrustLineAsset::Native => AssetView::native(),
        TrustLineAsset::CreditAlphanum4(a) => {
            // Strip trailing null bytes from the 4-byte code array and validate ASCII.
            let code = trim_asset_code(&a.asset_code.0)?;
            let issuer = account_id_to_strkey(&a.issuer);
            AssetView::credit(code, issuer)
        }
        TrustLineAsset::CreditAlphanum12(a) => {
            let code = trim_asset_code(&a.asset_code.0)?;
            let issuer = account_id_to_strkey(&a.issuer);
            AssetView::credit(code, issuer)
        }
        TrustLineAsset::PoolShare(_) => {
            return Err(WalletError::Protocol(ProtocolError::XdrCodecFailed {
                detail: "liquidity-pool share trustlines are not supported in fetch_account"
                    .to_owned(),
            }));
        }
    };

    let (buying_liabilities, selling_liabilities) = extract_trustline_liabilities(tl);

    Ok(BalanceView {
        asset: asset_view,
        balance: format_stroops(tl.balance),
        limit: Some(format_stroops(tl.limit)),
        buying_liabilities: format_stroops(buying_liabilities),
        selling_liabilities: format_stroops(selling_liabilities),
    })
}

/// Extracts buying and selling liabilities from a `TrustLineEntry`, if present.
///
/// `TrustLineEntryExt::V1` carries liabilities; `V0` (no extension) returns
/// zero liabilities.
fn extract_trustline_liabilities(tl: &stellar_xdr::TrustLineEntry) -> (i64, i64) {
    use stellar_xdr::TrustLineEntryExt;
    match &tl.ext {
        TrustLineEntryExt::V0 => (0, 0),
        TrustLineEntryExt::V1(v1) => (v1.liabilities.buying, v1.liabilities.selling),
    }
}

/// Trims trailing null bytes from a fixed-length XDR asset code byte array,
/// validates strict ASCII-alphanumeric invariant, and returns the code string.
///
/// XDR `AssetCode4` and `AssetCode12` are null-padded on the right; e.g. `"USD\0"`
/// for a 3-character code in a 4-byte array.
///
/// # Strict ASCII invariant
///
/// All non-null bytes MUST be ASCII alphanumeric (`[A-Za-z0-9]`).  This matches
/// the `Asset::parse` validation enforced at the T3 boundary; XDR that violates
/// this invariant would never be produced by a correctly-functioning Stellar node
/// but is validated here defensively against malformed RPC responses.
///
/// # Errors
///
/// Returns [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`]
/// if the byte slice contains non-null bytes after the first null (mid-string null),
/// if any non-null byte is non-ASCII or non-alphanumeric, or if the trimmed bytes
/// cannot be encoded as UTF-8 (unreachable after the ASCII check, but included
/// for exhaustiveness).
fn trim_asset_code(bytes: &[u8]) -> Result<String, WalletError> {
    let trimmed: Vec<u8> = bytes.iter().take_while(|&&b| b != 0).copied().collect();

    // Reject codes with mid-string nulls: `take_while(b != 0)` stops at the
    // FIRST null; a malformed XDR blob such as `[b'U', b'S', 0, b'X']` must
    // not silently produce "US".  Require that all bytes after the first null
    // are also null.
    let trimmed_len = trimmed.len();
    if bytes[trimmed_len..].iter().any(|&b| b != 0) {
        return Err(WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!(
                "asset code has non-null bytes after trailing nulls; hex prefix: {}",
                bytes
                    .iter()
                    .take(24)
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ),
        }));
    }

    if !trimmed.iter().all(|b| b.is_ascii_alphanumeric()) {
        // Hex-only output avoids control-character injection at downstream
        // rendering paths.  Length-bounded at 24 bytes.
        return Err(WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!(
                "asset code contains non-ASCII or non-alphanumeric byte(s); hex prefix: {}",
                trimmed
                    .iter()
                    .take(24)
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ),
        }));
    }

    // Safe: all bytes are ASCII (subset of UTF-8) per the check above.
    String::from_utf8(trimmed).map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("asset code is not valid UTF-8 despite ASCII check: {e}"),
        })
    })
}

/// Encodes an XDR `AccountId` as a G-strkey string.
///
/// This function is infallible: the XDR `AccountId` union has only one variant
/// (`PublicKeyTypeEd25519`), so the `match` is exhaustive at the protocol level.
fn account_id_to_strkey(account_id: &AccountId) -> String {
    use stellar_xdr::PublicKey;
    // NOTE: `stellar_strkey::ed25519::PublicKey::to_string()` returns a typed
    // fixed-length string (`String<56>`), not `std::string::String`.  The
    // second `.to_string()` converts to the owned heap `String` the caller
    // expects.  This double-call is a load-bearing coercion; removing either
    // `.to_string()` is a compile error.  See also `project_signer` below.
    match &account_id.0 {
        PublicKey::PublicKeyTypeEd25519(bytes) => stellar_strkey::ed25519::PublicKey(bytes.0)
            .to_string()
            .to_string(),
    }
}

/// Projects an XDR `AccountEntry` into an [`AccountView`].
fn project_account_entry(
    account_id: &str,
    entry: &AccountEntry,
) -> Result<AccountView, WalletError> {
    // Native XLM balance from the account entry.
    let native_balance = format_stroops(entry.balance);

    // Liabilities live in AccountEntryExt > V1.
    let (buying_liabilities, selling_liabilities) = extract_liabilities(entry);

    let balances = vec![BalanceView {
        asset: AssetView::native(),
        balance: native_balance,
        limit: None,
        buying_liabilities: format_stroops(buying_liabilities),
        selling_liabilities: format_stroops(selling_liabilities),
    }];

    // Thresholds: bytes [0]=master, [1]=low, [2]=med, [3]=high.
    // `Thresholds` in XDR is a 4-byte opaque. The byte layout is defined in
    // the Stellar XDR schema as `[master_weight, low, medium, high]`.
    let th = &entry.thresholds.0;
    let thresholds = ThresholdsView {
        master: th[0],
        low: th[1],
        med: th[2],
        high: th[3],
    };

    let signers = entry
        .signers
        .iter()
        .map(project_signer)
        .collect::<Result<Vec<_>, _>>()?;

    // XDR field: AccountEntry.num_sub_entries is Uint32 (a newtype over u32).
    // `entry.num_sub_entries` is a plain `u32` in the stellar-xdr Rust binding
    // (the Uint32 newtype is transparent; .0 is not needed for u32).
    // Verified against stellar-xdr AccountEntry schema: `numSubEntries: Uint32`.
    let subentry_count = entry.num_sub_entries;

    // `entry.home_domain` is a `String32` (newtype over `StringM<32>`).
    // Via Deref, `as_vec()` yields `&Vec<u8>`.  The same lowercase LDH
    // validation used by SEP-1 fetch and policy loading is applied so malformed
    // RPC responses cannot produce a string the cache/fetch path would reject.
    let home_domain = project_home_domain(entry.home_domain.as_vec());

    // Project AccountEntry.flags to AccountFlagsView.
    // `AccountEntry.flags` is a `u32`; bit constants from the AccountFlags XDR enum.
    let account_flags = Some(AccountFlagsView::from_raw(entry.flags));

    Ok(AccountView {
        account_id: account_id.to_owned(),
        sequence_number: entry.seq_num.0,
        subentry_count,
        balances,
        thresholds,
        signers,
        home_domain,
        account_flags,
    })
}

/// Extracts buying and selling liabilities from the `AccountEntryExt`, if present.
///
/// `AccountEntryExt::V1` carries liabilities; `V0` (no extension) returns
/// zero liabilities. This is safe because V0 accounts have no open offers.
fn extract_liabilities(entry: &AccountEntry) -> (i64, i64) {
    use stellar_xdr::AccountEntryExt;
    match &entry.ext {
        AccountEntryExt::V0 => (0, 0),
        AccountEntryExt::V1(v1) => (v1.liabilities.buying, v1.liabilities.selling),
    }
}

/// Projects an XDR `Signer` into a [`SignerView`].
fn project_signer(signer: &XdrSigner) -> Result<SignerView, WalletError> {
    use stellar_xdr::SignerKey;

    // NOTE: `stellar_strkey::<variant>::to_string()` returns a typed
    // fixed-length string (`String<56>`), not `std::string::String`.
    // The second `.to_string()` converts to the owned heap `String` the
    // `SignerView.key` field expects.  This double-call is a load-bearing
    // coercion; removing either `.to_string()` is a compile error.
    let (key, signer_type) = match &signer.key {
        SignerKey::Ed25519(bytes) => {
            let strkey = stellar_strkey::ed25519::PublicKey(bytes.0)
                .to_string()
                .to_string();
            (strkey, "ed25519".to_owned())
        }
        SignerKey::PreAuthTx(bytes) => {
            let strkey = stellar_strkey::PreAuthTx(bytes.0).to_string().to_string();
            (strkey, "pre_auth_tx".to_owned())
        }
        SignerKey::HashX(bytes) => {
            let strkey = stellar_strkey::HashX(bytes.0).to_string().to_string();
            (strkey, "hash_x".to_owned())
        }
        // Ed25519SignedPayload is used for multi-op signed payloads (Protocol 19+).
        // Encode the public key portion as the signer key display.
        SignerKey::Ed25519SignedPayload(payload) => {
            let strkey = stellar_strkey::ed25519::PublicKey(payload.ed25519.0)
                .to_string()
                .to_string();
            (strkey, "ed25519_signed_payload".to_owned())
        }
    };

    Ok(SignerView {
        key,
        weight: signer.weight,
        signer_type,
    })
}

/// Projects an XDR `home_domain` byte slice from `AccountEntry.home_domain`
/// (a `String32`, max 32 bytes) into an `Option<String>`.
///
/// Returns `Some(domain)` when the byte slice decodes to UTF-8 and passes the
/// shared lowercase LDH `home_domain` validator (`a-z`, `0-9`, `-`, `.`, no
/// empty labels and no leading/trailing separator).  Returns `None` for an
/// empty slice or any value rejected by that helper.
///
/// # Why LDH rather than just `str::from_utf8`
///
/// The `CounterpartyAllowlistCriterion` `HOME_DOMAIN` path performs byte-
/// equality comparison against operator-configured allowlist entries.
/// Accepting arbitrary Unicode or looser printable ASCII (including Cyrillic
/// homoglyphs, uppercase variants, or underscores) would silently undermine
/// that defence and diverge from the SEP-1 fetch/cache path.
fn project_home_domain(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let domain = std::str::from_utf8(bytes).ok()?;
    is_valid_ldh_home_domain(domain).then(|| domain.to_owned())
}

/// Formats a stroop integer as a 7-decimal decimal string.
///
/// e.g. `10_000_000` → `"1.0000000"`, `0` → `"0.0000000"`.
///
/// Uses the same formatting logic as `stellar_agent_core::StellarAmount::Display`.
fn format_stroops(stroops: i64) -> String {
    // Use integer arithmetic to avoid floating-point imprecision.
    let abs = stroops.unsigned_abs();
    let whole = abs / (STROOPS_PER_XLM as u64);
    let frac = abs % (STROOPS_PER_XLM as u64);
    let sign = if stroops < 0 { "-" } else { "" };
    format!(
        "{sign}{whole}.{frac:0>width$}",
        width = STELLAR_DECIMALS as usize
    )
}

/// Fetches the value of an account data entry (account `manageData`) by key.
///
/// Constructs a `LedgerKey::Data { account_id, data_name }` key and calls
/// `getLedgerEntries`. If the entry is present, returns its value bytes.
/// If absent, returns `None`. The returned bytes are the raw `DataValue`
/// payload (UTF-8 or binary, up to 64 bytes per the Stellar protocol).
///
/// # Errors
///
/// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`] if
///   the key or returned XDR cannot be encoded / decoded.
/// - [`WalletError::Network`] wrapping [`NetworkError::RpcUnreachable`] or
///   [`NetworkError::RpcTimeout`] on transport errors.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::{StellarRpcClient, account::fetch_data_entry};
///
/// # async fn run() -> Result<(), stellar_agent_core::WalletError> {
/// let client = StellarRpcClient::new("https://soroban-testnet.stellar.org")?;
/// let val = fetch_data_entry(&client, "GABC...XYZ", "config.memo_required").await?;
/// println!("{:?}", val); // Some(b"1") or None
/// # Ok(()) }
/// ```
pub async fn fetch_data_entry(
    client: &StellarRpcClient,
    account_id: &str,
    data_key: &str,
) -> Result<Option<Vec<u8>>, WalletError> {
    use stellar_xdr::{AccountId, PublicKey, Uint256};

    let redacted = redact_account_id(account_id);
    tracing::debug!(
        account_id = %redacted,
        data_key = %data_key,
        "fetch_data_entry: querying RPC"
    );

    // Parse the account_id into the XDR AccountId.
    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_id).map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("invalid account_id for data-entry lookup: {e}"),
        })
    })?;
    let xdr_account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes.0)));

    // Encode the data key as String64 (StringM<64> newtype).
    // String64 = StringM<64>; construct via StringM<64>::try_from(Vec<u8>).
    let key_bytes = data_key.as_bytes().to_vec();
    let string_m: stellar_xdr::StringM<64> = key_bytes.try_into().map_err(|_| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("data_key '{data_key}' exceeds 64-byte limit for String64"),
        })
    })?;
    let data_name = stellar_xdr::String64::from(string_m);

    let ledger_key = LedgerKey::Data(LedgerKeyData {
        account_id: xdr_account_id,
        data_name,
    });

    let response = client
        .inner
        .get_ledger_entries(&[ledger_key])
        .await
        .map_err(|e| map_rpc_error_generic(&e, &client.url))?;

    let entries = response.entries.unwrap_or_default();
    if entries.is_empty() {
        return Ok(None);
    }

    // Decode the first (and only) entry's XDR.
    // The RPC returns `LedgerEntryResult.xdr` as `LedgerEntryData` XDR
    // (not a full `LedgerEntry`), matching the `get_ledger_entries` wire
    // format verified against rs-stellar-rpc-client line ~1140.
    // Data entry XDR comes from an untrusted RPC response; bounded limits
    // prevent a malformed nested structure from exhausting the stack.
    let xdr_str = &entries[0].xdr;
    let entry_data = LedgerEntryData::from_xdr_base64(
        xdr_str,
        stellar_agent_xdr_limits::untrusted_decode_limits(xdr_str.len()),
    )
    .map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("failed to decode DataEntry XDR: {e}"),
        })
    })?;

    match entry_data {
        LedgerEntryData::Data(data_entry) => Ok(Some(data_entry.data_value.0.to_vec())),
        other => Err(WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("expected DataEntry, got {:?}", other.discriminant()),
        })),
    }
}

/// Maps a generic `stellar_rpc_client::Error` to a [`WalletError`] without
/// an account-ID context. Used by operations that are not account-specific
/// (e.g. data-entry lookups that already validated the account separately).
fn map_rpc_error_generic(e: &RpcError, url: &str) -> WalletError {
    match e {
        RpcError::TransactionSubmissionTimeout => WalletError::Network(NetworkError::RpcTimeout {
            url: redact_url_authority(url),
            timeout_secs: 30,
        }),
        RpcError::Xdr(_) => WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: e.to_string(),
        }),
        _ => WalletError::Network(NetworkError::RpcUnreachable {
            url: redact_url_authority(url),
            reason: e.to_string(),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only; assertions via unwrap/expect are idiomatic in unit tests"
)]
mod tests {
    use super::*;

    // ─── balance_stroops unit tests ───────────────────────────────────────────

    #[test]
    fn balance_stroops_one_xlm() {
        let b = BalanceView::new(
            AssetView::native(),
            "1.0000000".to_owned(),
            None,
            "0.0000000".to_owned(),
            "0.0000000".to_owned(),
        );
        assert_eq!(b.balance_stroops().unwrap(), 10_000_000);
    }

    /// Large balance near i64::MAX must round-trip without f64 precision loss.
    ///
    /// 9_999_999_999.9999999 XLM = 99_999_999_999_999_999 stroops.  An f64
    /// parse would silently lose sub-stroop precision; `balance_stroops` uses
    /// the integer-only parser so the value is exact.
    #[test]
    fn balance_stroops_large_no_precision_loss() {
        let b = BalanceView::new(
            AssetView::native(),
            "9999999999.9999999".to_owned(),
            None,
            "0.0000000".to_owned(),
            "0.0000000".to_owned(),
        );
        // 9_999_999_999 * 10_000_000 + 9_999_999 = 99_999_999_999_999_999
        assert_eq!(b.balance_stroops().unwrap(), 99_999_999_999_999_999_i64);
    }

    #[test]
    fn balance_stroops_zero() {
        let b = BalanceView::new(
            AssetView::native(),
            "0.0000000".to_owned(),
            None,
            "0.0000000".to_owned(),
            "0.0000000".to_owned(),
        );
        assert_eq!(b.balance_stroops().unwrap(), 0);
    }

    #[test]
    fn balance_stroops_err_on_invalid() {
        let b = BalanceView::new(
            AssetView::native(),
            "not_a_number".to_owned(),
            None,
            "0.0000000".to_owned(),
            "0.0000000".to_owned(),
        );
        assert!(
            b.balance_stroops().is_err(),
            "invalid balance string must return Err"
        );
    }

    #[test]
    fn format_stroops_zero() {
        assert_eq!(format_stroops(0), "0.0000000");
    }

    #[test]
    fn format_stroops_one_xlm() {
        assert_eq!(format_stroops(STROOPS_PER_XLM), "1.0000000");
    }

    #[test]
    fn format_stroops_fractional() {
        assert_eq!(format_stroops(100), "0.0000100");
    }

    #[test]
    fn format_stroops_large() {
        assert_eq!(format_stroops(1_000_000_000_000_i64), "100000.0000000");
    }

    #[test]
    fn redacts_long_account_id() {
        let id = "GABC1234567890XYZ";
        // first 5 chars: "GABC1"; last 5 chars: "0XYZ" is only 4; last 5 is "90XYZ"
        let r = redact_account_id(id);
        assert!(r.starts_with("GABC1"), "must start with first-5: got {r}");
        assert!(r.ends_with("90XYZ"), "must end with last-5: got {r}");
        assert!(r.contains("..."), "must contain ellipsis: got {r}");
    }

    #[test]
    fn redacts_short_account_id() {
        assert_eq!(redact_account_id("GABC"), "G...?");
    }

    // ─── AccountView::reserves unit tests ────────────────────────────────────

    fn make_view_with_subentries(subentry_count: u32) -> AccountView {
        AccountView::new(
            "GABC".to_owned(),
            1,
            subentry_count,
            vec![BalanceView::new(
                AssetView::native(),
                "100.0000000".to_owned(),
                None,
                "0.0000000".to_owned(),
                "0.0000000".to_owned(),
            )],
            ThresholdsView::new(1, 0, 0, 0),
            vec![],
            None,
            None,
        )
    }

    /// Zero subentries: (2 + 0) * 5_000_000 = 10_000_000 stroops.
    #[test]
    fn reserves_zero_subentries() {
        let view = make_view_with_subentries(0);
        assert_eq!(view.reserves_stroops(BASE_RESERVE_STROOPS), 10_000_000);
    }

    /// 1 subentry: (2 + 1) * 5_000_000 = 15_000_000 stroops.
    #[test]
    fn reserves_one_subentry() {
        let view = make_view_with_subentries(1);
        assert_eq!(view.reserves_stroops(BASE_RESERVE_STROOPS), 15_000_000);
    }

    /// 5 subentries: (2 + 5) * 5_000_000 = 35_000_000 stroops.
    #[test]
    fn reserves_five_subentries() {
        let view = make_view_with_subentries(5);
        assert_eq!(view.reserves_stroops(BASE_RESERVE_STROOPS), 35_000_000);
    }

    /// 25 subentries: (2 + 25) * 5_000_000 = 135_000_000 stroops.
    #[test]
    fn reserves_twenty_five_subentries() {
        let view = make_view_with_subentries(25);
        assert_eq!(view.reserves_stroops(BASE_RESERVE_STROOPS), 135_000_000);
    }

    /// Protocol maximum 1000 subentries: (2 + 1000) * 5_000_000 = 5_010_000_000.
    /// Must not overflow i64 (max ~9.2 * 10^18; 5 * 10^9 is well within bounds).
    #[test]
    fn reserves_max_protocol_subentries() {
        let view = make_view_with_subentries(1000);
        assert_eq!(
            view.reserves_stroops(BASE_RESERVE_STROOPS),
            5_010_000_000_i64
        );
    }

    /// `subentry_count` field returns the value set at construction.
    #[test]
    fn subentry_count_field() {
        let view = make_view_with_subentries(7);
        assert_eq!(view.subentry_count, 7);
    }

    /// `reserves()` with u32::MAX subentries does not overflow and does not panic.
    ///
    /// `i64::from(u32::MAX)` is `4_294_967_295`; `saturating_add(2)` gives
    /// `4_294_967_297`; multiplied by `5_000_000` gives `21_474_836_485_000_000`.
    /// That value fits inside `i64::MAX` so `saturating_mul` returns the exact
    /// product.  A second call with `base_reserve_stroops = i64::MAX` exercises
    /// the saturation path and must return `i64::MAX` without panicking.
    #[test]
    fn reserves_u32_max_subentries_no_panic() {
        let view = make_view_with_subentries(u32::MAX);
        // (2 + 4_294_967_295) * 5_000_000 = 21_474_836_485_000_000 — within i64.
        let result = view.reserves_stroops(BASE_RESERVE_STROOPS);
        assert_eq!(
            result, 21_474_836_485_000_000_i64,
            "reserves with u32::MAX subentries must fit i64 exactly"
        );
        // Confirm saturating_mul handles a deliberately huge base_reserve without
        // panicking (adversarial caller; real value is always BASE_RESERVE_STROOPS).
        let clamped = view.reserves_stroops(i64::MAX);
        assert_eq!(
            clamped,
            i64::MAX,
            "saturating_mul with i64::MAX base_reserve must return i64::MAX"
        );
    }

    #[test]
    fn asset_view_native() {
        let a = AssetView::native();
        assert_eq!(a.asset_type, "native");
        assert!(a.issuer.is_none());
    }

    #[test]
    fn asset_view_credit() {
        let a = AssetView::credit("USDC", "GA5Z...");
        assert_eq!(a.asset_type, "USDC");
        assert_eq!(a.issuer.as_deref(), Some("GA5Z..."));
    }

    // ─── trim_asset_code unit tests ───────────────────────────────────────────

    #[test]
    fn trim_asset_code_valid_alphanum4() {
        assert_eq!(trim_asset_code(b"USDC").unwrap(), "USDC");
    }

    #[test]
    fn trim_asset_code_null_padded() {
        let mut bytes = [0u8; 4];
        bytes[..2].copy_from_slice(b"XL");
        assert_eq!(trim_asset_code(&bytes).unwrap(), "XL");
    }

    #[test]
    fn trim_asset_code_rejects_non_alphanumeric() {
        // Hyphen is not alphanumeric.
        let result = trim_asset_code(b"US-D");
        assert!(result.is_err(), "non-alphanumeric must be rejected");
        // Error message must use hex, not Debug-print of Vec<u8>.
        let msg = result.unwrap_err().to_string();
        assert!(
            !msg.contains('['),
            "error must not contain debug-format brackets, got: {msg}"
        );
    }

    /// Reject codes with non-null bytes after the first null (mid-string null).
    ///
    /// A malformed XDR blob `[b'U', b'S', 0, b'X']` must produce an error;
    /// `take_while` alone would silently produce `"US"`.
    #[test]
    fn trim_asset_code_rejects_middle_null() {
        // Mid-null: 'U', 'S', NUL, 'X', NUL — trailing byte after first null is non-null.
        let bytes = [b'U', b'S', 0, b'X', 0];
        let result = trim_asset_code(&bytes);
        assert!(
            result.is_err(),
            "mid-string null must be rejected; got: {result:?}"
        );
    }

    #[test]
    fn trim_asset_code_error_uses_hex_not_debug() {
        // Non-ASCII byte (0x80) should produce hex output, not Debug-format.
        let bytes = [0x80u8, b'S', b'D', b'C'];
        let result = trim_asset_code(&bytes);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        // Must contain hex-format prefix (e.g. "80"), not Debug-format like "[128, ...]".
        assert!(
            msg.contains("80"),
            "error must contain hex byte '80': {msg}"
        );
        assert!(
            !msg.contains('['),
            "error must not use Debug-format brackets: {msg}"
        );
    }

    // ─── home_domain projection tests ────────────────────────────────────────

    /// `project_home_domain` returns `Some("circle.com")` for the byte sequence
    /// `b"circle.com"` — a valid strict-ASCII home_domain.
    #[test]
    fn home_domain_field_strict_ascii_lowercase_match() {
        let result = project_home_domain(b"circle.com");
        assert_eq!(result.as_deref(), Some("circle.com"));
    }

    /// `project_home_domain` returns `None` for an empty byte slice — the
    /// on-chain `AccountEntry.home_domain` has no home_domain set.
    #[test]
    fn home_domain_field_none_when_xdr_entry_empty() {
        let result = project_home_domain(b"");
        assert!(result.is_none(), "empty slice must project to None");
    }

    /// `project_home_domain` returns `None` when the byte slice contains
    /// non-ASCII bytes (e.g. 0x80, 0x81 — high-byte Latin supplement).
    ///
    /// Defence-in-depth against IDN homoglyph injection: a Cyrillic 'с' (U+0441)
    /// looks identical to ASCII 'c' but encodes as two non-ASCII bytes in UTF-8.
    /// Strict-ASCII gating ensures the field is always byte-comparable.
    #[test]
    fn home_domain_field_none_when_xdr_entry_non_ascii() {
        // 0x80..0x81 are continuation bytes / high-byte Latin supplement.
        let non_ascii = &[0x80u8, 0x81, b'c', b'o', b'm'];
        let result = project_home_domain(non_ascii);
        assert!(result.is_none(), "non-ASCII bytes must project to None");
    }

    /// Uppercase on-chain values are not surfaced to policy evaluation.
    #[test]
    fn home_domain_field_none_when_xdr_entry_uppercase() {
        let result = project_home_domain(b"Circle.com");
        assert!(
            result.is_none(),
            "uppercase bytes must project to None under shared LDH validation"
        );
    }

    /// Projection rejects printable ASCII that is not LDH, matching the
    /// SEP-1 fetch/cache path.
    #[test]
    fn home_domain_field_none_when_xdr_entry_underscore() {
        let result = project_home_domain(b"circle_pay.com");
        assert!(
            result.is_none(),
            "underscore must project to None under shared LDH validation"
        );
    }

    /// `project_home_domain` returns `Some(domain)` when the byte slice is a
    /// valid populated home_domain from an XDR entry (simulated path through
    /// `project_account_entry`).
    #[test]
    fn home_domain_field_populated_from_xdr_entry_when_set() {
        // Simulate the XDR projection path: `project_home_domain` is the
        // same function called by `project_account_entry`.
        let bytes = b"example.com";
        let result = project_home_domain(bytes);
        assert_eq!(
            result.as_deref(),
            Some("example.com"),
            "valid ASCII home_domain must be projected"
        );
    }

    /// Pins `AccountView::new` positional API shape: `home_domain` is the 7th
    /// argument and `account_flags` is the 8th.
    ///
    /// A constructor signature change will cause this test to fail to compile,
    /// surfacing the breaking change immediately.
    #[test]
    fn account_view_new_positional_signature_includes_home_domain_and_flags() {
        let flags = AccountFlagsView::from_raw(0x2); // AUTH_REVOCABLE_FLAG
        let view = AccountView::new(
            "GABC".to_owned(),
            1,
            0,
            vec![BalanceView::new(
                AssetView::native(),
                "10.0000000".to_owned(),
                None,
                "0.0000000".to_owned(),
                "0.0000000".to_owned(),
            )],
            ThresholdsView::new(1, 0, 0, 0),
            vec![],
            Some("stellar.org".to_owned()),
            Some(flags),
        );
        assert_eq!(
            view.home_domain.as_deref(),
            Some("stellar.org"),
            "home_domain must be the 7th positional arg"
        );
        assert!(
            view.account_flags
                .as_ref()
                .is_some_and(|f| f.auth_revocable),
            "account_flags must be the 8th positional arg"
        );
        // Confirm None round-trips as well.
        let view_no_domain = AccountView::new(
            "GDEF".to_owned(),
            2,
            0,
            vec![],
            ThresholdsView::new(1, 0, 0, 0),
            vec![],
            None,
            None,
        );
        assert!(
            view_no_domain.home_domain.is_none(),
            "None must round-trip through the constructor"
        );
        assert!(
            view_no_domain.account_flags.is_none(),
            "None account_flags must round-trip through the constructor"
        );
    }
}
