//! Classic-operation transaction builder façade over `stellar-baselib`.
//!
//! `ClassicOpBuilder` constructs a `TransactionEnvelope` for classic
//! operations (`payment`). The builder assembles operations, memo, fee, and
//! source account then produces a base64-encoded unsigned `TransactionEnvelope`
//! XDR string via `build()`. Signing is separated into `build_and_sign()`, which
//! calls `signer.sign_tx_payload` exactly once and attaches the resulting
//! `DecoratedSignature` to the envelope.
//!
//! # Transaction assembly approach
//!
//! This module uses baselib's `Account` + `TransactionBuilder` / `Transaction` +
//! `TransactionBehavior` to construct the unsigned envelope, then serialises it
//! to base64 XDR.  `stellar-baselib` 0.5.8 re-exports the workspace
//! `stellar_xdr` directly as `stellar_baselib::xdr`, so both use the same XDR
//! types and there is no version bridge.
//!
//! `attach_signature` consumes the base64 string (rather than the
//! `TransactionEnvelope` directly) because that is the interface contract
//! shared with hardware-signing paths that operate on serialised bytes.
//!
//! # Signing discipline
//!
//! `build_and_sign` delegates to `signing::envelope_signing::attach_signature`,
//! which is the single permitted call site for `signer.sign_tx_payload`.
//! It invokes the signer exactly once. Retries in the submit layer operate
//! on the already-signed envelope bytes.

use stellar_agent_core::StellarAmount;
use stellar_agent_core::error::{InternalError, ProtocolError, ValidationError, WalletError};
use stellar_baselib::account::{Account, AccountBehavior};
use stellar_baselib::asset::{Asset as BaselibAsset, AssetBehavior};
use stellar_baselib::operation::Operation as BaselibOperation;
use stellar_baselib::transaction::{Transaction, TransactionBehavior};
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
// stellar-baselib 0.5.8 re-exports stellar_xdr directly as stellar_baselib::xdr,
// so stellar_baselib::xdr::{Limits, Memo, WriteXdr} and the workspace
// stellar_xdr::{Limits, Memo, WriteXdr} are the same types.
use stellar_xdr::{Limits, Memo as BaselibMemo, WriteXdr};

use crate::signing::Signer;

// ─────────────────────────────────────────────────────────────────────────────
// Public re-export of attach_signature for multi-signer use
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) use crate::signing::envelope_signing::attach_signature;

// ─────────────────────────────────────────────────────────────────────────────
// Asset
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed Stellar asset descriptor.
///
/// The grammar is:
/// - `"native"` or `"XLM"` → [`Asset::Native`]
/// - `"<CODE>:<G-strkey>"` → [`Asset::Credit`] (Alphanum4 if `CODE.len() ≤ 4`,
///   Alphanum12 if `5 ≤ CODE.len() ≤ 12`)
///
/// Other shapes produce [`WalletError::Validation`] wrapping
/// [`ValidationError::AssetInvalid`].
///
/// # Stability
///
/// `#[non_exhaustive]` because Stellar supports liquidity-pool share assets
/// and future protocol updates may add further asset classes.  External match
/// arms must include a wildcard fallback.
///
/// # Examples
///
/// ```
/// use stellar_agent_network::builder::Asset;
///
/// let native = Asset::parse("native").unwrap();
/// assert!(matches!(native, Asset::Native));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asset {
    /// The native XLM asset.
    Native,
    /// A non-native asset with a code and issuer G-strkey.
    Credit {
        /// The asset code (1-12 alphanumeric characters).
        code: String,
        /// The issuer's G-strkey.
        issuer: String,
    },
}

impl Asset {
    /// Parses an asset descriptor string.
    ///
    /// Accepts:
    /// - `"native"` or `"XLM"` (case-insensitive) → [`Asset::Native`]
    /// - `"<CODE>:<G-strkey>"` → [`Asset::Credit`]
    ///
    /// # Errors
    ///
    /// Returns [`WalletError::Validation`] wrapping [`ValidationError::AssetInvalid`]
    /// for any other shape.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_network::builder::Asset;
    ///
    /// assert!(matches!(Asset::parse("native"), Ok(Asset::Native)));
    /// assert!(matches!(Asset::parse("XLM"), Ok(Asset::Native)));
    /// assert!(Asset::parse("BADASSET").is_err());
    /// ```
    pub fn parse(input: &str) -> Result<Self, WalletError> {
        let lower = input.to_lowercase();
        if lower == "native" || lower == "xlm" {
            return Ok(Self::Native);
        }

        // Must be CODE:ISSUER
        let Some((code, issuer)) = input.split_once(':') else {
            return Err(WalletError::Validation(ValidationError::AssetInvalid {
                input: input.to_owned(),
            }));
        };

        let code_len = code.len();
        if code_len == 0 || code_len > 12 || !code.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(WalletError::Validation(ValidationError::AssetInvalid {
                input: input.to_owned(),
            }));
        }

        // Validate issuer as a valid G-strkey.
        stellar_strkey::ed25519::PublicKey::from_string(issuer).map_err(|_| {
            WalletError::Validation(ValidationError::AssetInvalid {
                input: input.to_owned(),
            })
        })?;

        Ok(Self::Credit {
            code: code.to_owned(),
            issuer: issuer.to_owned(),
        })
    }

    /// Constructs an [`Asset::Credit`] from a code and issuer string without a
    /// `CODE:ISSUER` round-trip.
    ///
    /// Applies the same validation as [`Asset::parse`] but accepts the code and
    /// issuer separately, avoiding a `format!("{code}:{issuer}")` allocation at
    /// the MCP handler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError::Validation`] wrapping [`ValidationError::AssetInvalid`]
    /// if the code is empty, exceeds 12 characters, is not all ASCII alphanumeric,
    /// or if the issuer is not a valid G-strkey.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_network::builder::Asset;
    ///
    /// const ISSUER: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    /// let asset = Asset::from_code_and_issuer("USDC", ISSUER).unwrap();
    /// assert!(matches!(asset, Asset::Credit { .. }));
    /// assert!(Asset::from_code_and_issuer("US-DC", ISSUER).is_err());
    /// ```
    pub fn from_code_and_issuer(code: &str, issuer: &str) -> Result<Self, WalletError> {
        let code_len = code.len();
        if code_len == 0 || code_len > 12 || !code.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(WalletError::Validation(ValidationError::AssetInvalid {
                input: code.to_owned(),
            }));
        }
        stellar_strkey::ed25519::PublicKey::from_string(issuer).map_err(|_| {
            WalletError::Validation(ValidationError::AssetInvalid {
                input: issuer.to_owned(),
            })
        })?;
        Ok(Self::Credit {
            code: code.to_owned(),
            issuer: issuer.to_owned(),
        })
    }

    /// Converts to the `stellar-baselib` `Asset` type used for operation construction.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError::Protocol`] if the baselib `Asset::new` rejects the
    /// input (should not occur when `Asset::parse` was used, but defensive).
    pub(crate) fn to_baselib(&self) -> Result<BaselibAsset, WalletError> {
        match self {
            Self::Native => Ok(BaselibAsset::native()),
            Self::Credit { code, issuer } => BaselibAsset::new(code, Some(issuer)).map_err(|e| {
                WalletError::Protocol(ProtocolError::XdrCodecFailed {
                    detail: format!("asset conversion to baselib failed: {e}"),
                })
            }),
        }
    }

    /// Converts to a `stellar_xdr::TrustLineAsset` for `LedgerKey::Trustline`
    /// construction.
    ///
    /// Used by [`crate::account::fetch_account`] to build trustline ledger keys when
    /// the caller passes a non-empty `trustline_assets` slice.  The conversion is
    /// `pub(crate)` because it is an internal XDR plumbing detail; callers interact
    /// with [`Asset`], not with XDR types.
    ///
    /// # Rationale for code-length-based discrimination
    ///
    /// The Stellar XDR schema encodes asset codes up to 4 bytes as `AssetCode4`
    /// (`[u8; 4]` zero-padded) and 5-12 bytes as `AssetCode12` (`[u8; 12]` zero-padded).
    /// The `Asset::parse` validation already enforces `1 ≤ code.len() ≤ 12`, so the
    /// `> 12` arm is unreachable from a parsed asset, but is handled defensively to
    /// avoid a panic in `unwrap`.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`] if the
    ///   issuer G-strkey cannot be decoded (should not occur when `Asset::parse` was
    ///   used, but defensive).
    /// - [`WalletError::Protocol`] if the asset code length is out of range (unreachable
    ///   from validated `Asset` values, but defensive).
    pub(crate) fn to_xdr_trust_line_asset(
        &self,
    ) -> Result<stellar_xdr::TrustLineAsset, WalletError> {
        use stellar_xdr::{
            AccountId, AlphaNum4, AlphaNum12, AssetCode4, AssetCode12, PublicKey, TrustLineAsset,
            Uint256,
        };

        match self {
            Self::Native => Ok(TrustLineAsset::Native),
            Self::Credit { code, issuer } => {
                // Decode the issuer G-strkey.
                let pk_bytes =
                    stellar_strkey::ed25519::PublicKey::from_string(issuer).map_err(|e| {
                        WalletError::Protocol(ProtocolError::XdrCodecFailed {
                            detail: format!(
                                "invalid issuer G-strkey for TrustLineAsset conversion: {e}"
                            ),
                        })
                    })?;
                let xdr_issuer = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes.0)));

                let code_bytes = code.as_bytes();
                if code_bytes.len() <= 4 {
                    let mut arr = [0u8; 4];
                    arr[..code_bytes.len()].copy_from_slice(code_bytes);
                    Ok(TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                        asset_code: AssetCode4(arr),
                        issuer: xdr_issuer,
                    }))
                } else if code_bytes.len() <= 12 {
                    let mut arr = [0u8; 12];
                    arr[..code_bytes.len()].copy_from_slice(code_bytes);
                    Ok(TrustLineAsset::CreditAlphanum12(AlphaNum12 {
                        asset_code: AssetCode12(arr),
                        issuer: xdr_issuer,
                    }))
                } else {
                    Err(WalletError::Protocol(ProtocolError::XdrCodecFailed {
                        detail: format!(
                            "asset code '{}' length {} exceeds 12-byte maximum",
                            code,
                            code_bytes.len()
                        ),
                    }))
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ClassicOpBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// The number of seconds added to the current close-time for the short
/// `timeBounds` default.
///
/// Value: **30 seconds**. A short window bounds mempool replay exposure:
/// once a transaction's `timeBounds` lapses, a fresh sequence-safe replacement
/// can be submitted without double-spend risk.
/// Per-flow configurable via [`ClassicOpBuilder::with_time_bounds`].
pub const SHORT_TIMEBOUNDS_DELTA_SECS: u64 = 30;

/// A thin façade over `stellar-baselib` for classic operations.
///
/// Operations are added via [`ClassicOpBuilder::payment`]; memo via
/// [`ClassicOpBuilder::memo`]; time bounds via
/// [`ClassicOpBuilder::with_time_bounds`] or
/// [`ClassicOpBuilder::with_short_timebounds`]; fee is set at construction time.
/// Call [`ClassicOpBuilder::build`] to obtain the base64-encoded unsigned
/// `TransactionEnvelope`, or [`ClassicOpBuilder::build_and_sign`] to sign it
/// immediately.
///
/// # Time bounds
///
/// By default the built transaction carries no time bounds
/// (`Preconditions::None`). Callers that want mempool-replay protection should
/// call [`ClassicOpBuilder::with_short_timebounds`] with the current ledger
/// close time, which sets `max_time = close_time + 30s`.
///
/// # Signing
///
/// [`ClassicOpBuilder::build_and_sign`] is the single permitted call site for
/// `signer.sign_tx_payload`. The signer is called exactly once. Retries in the
/// submit layer reuse the already-signed envelope bytes.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
/// use stellar_agent_core::StellarAmount;
///
/// let mut builder = ClassicOpBuilder::new(
///     "GABC...SRC",
///     100,
///     "Test SDF Network ; September 2015",
///     100,
/// );
/// let _builder = builder.payment(
///     "GDEF...DST",
///     StellarAmount::from_stroops(10_000_000),
///     &Asset::Native,
/// ).unwrap();
/// ```
#[non_exhaustive]
pub struct ClassicOpBuilder {
    pub(crate) source_account: String,
    pub(crate) sequence_number: i64,
    pub(crate) network_passphrase: String,
    pub(crate) fee: u32,
    /// Operations stored as XDR operations (workspace stellar_xdr types, re-exported by baselib).
    pub(crate) operations: Vec<stellar_baselib::xdr::Operation>,
    pub(crate) memo: Option<BaselibMemo>,
    /// Optional time bounds set by `with_time_bounds` / `with_short_timebounds`.
    ///
    /// `None` → `Preconditions::None` in the built envelope.
    pub(crate) time_bounds: Option<stellar_baselib::xdr::TimeBounds>,
}

impl ClassicOpBuilder {
    /// Constructs a new `ClassicOpBuilder`.
    ///
    /// `fee_stroops` is the base fee in stroops per operation.  The XDR
    /// `Transaction.fee` field is the total fee, computed as per-operation fee
    /// multiplied by the transaction operation count.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_network::builder::ClassicOpBuilder;
    ///
    /// let builder = ClassicOpBuilder::new(
    ///     "GABC...XYZ",
    ///     100,
    ///     "Test SDF Network ; September 2015",
    ///     100,
    /// );
    /// ```
    #[must_use]
    pub fn new(
        source_account: impl Into<String>,
        sequence_number: i64,
        network_passphrase: impl Into<String>,
        fee_stroops: u32,
    ) -> Self {
        Self {
            source_account: source_account.into(),
            sequence_number,
            network_passphrase: network_passphrase.into(),
            fee: fee_stroops,
            operations: Vec::new(),
            memo: None,
            time_bounds: None,
        }
    }

    /// Adds a `CreateAccount` operation.
    ///
    /// Creates a new Stellar account funded by the source (sponsor) with
    /// `starting_balance`. The source account must be able to cover the
    /// starting balance plus the base reserve for the new account.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Validation`] wrapping [`ValidationError::AddressInvalid`]
    ///   if the destination G-strkey is invalid.
    /// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`]
    ///   if XDR construction fails.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_network::builder::ClassicOpBuilder;
    /// use stellar_agent_core::StellarAmount;
    ///
    /// let mut builder = ClassicOpBuilder::new(
    ///     "GABC...SRC",
    ///     100,
    ///     "Test SDF Network ; September 2015",
    ///     100,
    /// );
    /// builder.create_account(
    ///     "GDEF...NEW",
    ///     StellarAmount::from_stroops(50_000_000),
    /// ).unwrap();
    /// ```
    pub fn create_account(
        &mut self,
        destination: &str,
        starting_balance: StellarAmount,
    ) -> Result<&mut Self, WalletError> {
        // Validate destination is a valid G-strkey.
        stellar_strkey::ed25519::PublicKey::from_string(destination).map_err(|_| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: destination.to_owned(),
            })
        })?;

        let stroops = starting_balance.as_stroops();

        let xdr_op = BaselibOperation::new()
            .create_account(destination, stroops)
            .map_err(|e| {
                WalletError::Protocol(ProtocolError::XdrCodecFailed {
                    detail: format!("create_account op construction failed: {e:?}"),
                })
            })?;

        self.operations.push(xdr_op);
        Ok(self)
    }

    /// Adds a payment operation.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Validation`] wrapping [`ValidationError::AddressInvalid`]
    ///   if the destination is invalid.
    /// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`]
    ///   if XDR construction fails.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
    /// use stellar_agent_core::StellarAmount;
    ///
    /// let mut builder = ClassicOpBuilder::new(
    ///     "GABC...SRC",
    ///     100,
    ///     "Test SDF Network ; September 2015",
    ///     100,
    /// );
    /// builder.payment(
    ///     "GDEF...DST",
    ///     StellarAmount::from_stroops(10_000_000),
    ///     &Asset::Native,
    /// ).unwrap();
    /// ```
    pub fn payment(
        &mut self,
        destination: &str,
        amount: StellarAmount,
        asset: &Asset,
    ) -> Result<&mut Self, WalletError> {
        // Validate destination is a valid G-strkey.
        stellar_strkey::ed25519::PublicKey::from_string(destination).map_err(|_| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: destination.to_owned(),
            })
        })?;

        let baselib_asset = asset.to_baselib()?;
        let stroops = amount.as_stroops();

        let xdr_op = BaselibOperation::new()
            .payment(destination, &baselib_asset, stroops)
            .map_err(|e| {
                WalletError::Protocol(ProtocolError::XdrCodecFailed {
                    detail: format!("payment op construction failed: {e:?}"),
                })
            })?;

        self.operations.push(xdr_op);
        Ok(self)
    }

    /// Adds a `BeginSponsoringFutureReserves` operation with an explicit
    /// per-operation source account.
    ///
    /// This is the first operation of the CAP-33 sponsored-account-creation
    /// sandwich.  For each channel `i`, the triple is:
    ///
    /// ```text
    /// op0: BeginSponsoringFutureReserves { source=funder, sponsoredID=channel_i }
    /// op1: CreateAccount { source=funder, dest=channel_i, starting_balance=0 }
    /// op2: EndSponsoringFutureReserves { source=channel_i }
    /// ```
    ///
    /// See CAP-33 §"Example: Sponsoring Account Creation".
    ///
    /// # Op-level source account
    ///
    /// The `op_source` parameter sets the XDR `Operation.source_account` field
    /// (per-op source override), distinct from the transaction-level
    /// `source_account`.  In the CAP-33 sandwich, `op_source` is the funder
    /// (sponsor/creator), NOT the transaction source.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Validation`] wrapping [`ValidationError::AddressInvalid`]
    ///   if either `op_source` or `sponsored_id` is not a valid G-strkey.
    /// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`]
    ///   if baselib op construction fails.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_network::builder::ClassicOpBuilder;
    ///
    /// let mut builder = ClassicOpBuilder::new(
    ///     "GABC...FUNDER",
    ///     100,
    ///     "Test SDF Network ; September 2015",
    ///     100,
    /// );
    /// builder.begin_sponsoring_future_reserves(
    ///     "GABC...FUNDER",   // op_source = funder
    ///     "GDEF...CHANNEL",  // sponsored_id = new channel account
    /// ).unwrap();
    /// ```
    pub fn begin_sponsoring_future_reserves(
        &mut self,
        op_source: &str,
        sponsored_id: &str,
    ) -> Result<&mut Self, WalletError> {
        // Validate both addresses as valid G-strkeys.
        stellar_strkey::ed25519::PublicKey::from_string(op_source).map_err(|_| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: op_source.to_owned(),
            })
        })?;
        stellar_strkey::ed25519::PublicKey::from_string(sponsored_id).map_err(|_| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: sponsored_id.to_owned(),
            })
        })?;

        // Build with per-operation source.
        // `Operation::with_source` parses the source as a MuxedAccount.
        // `begin_sponsoring_future_reserves(sponsored_id)` sets the sponsoredID
        // to the channel account (CAP-33).
        let xdr_op = BaselibOperation::with_source(op_source)
            .map_err(|e| {
                WalletError::Protocol(ProtocolError::XdrCodecFailed {
                    detail: format!("begin_sponsoring: with_source failed: {e:?}"),
                })
            })?
            .begin_sponsoring_future_reserves(sponsored_id)
            .map_err(|e| {
                WalletError::Protocol(ProtocolError::XdrCodecFailed {
                    detail: format!(
                        "begin_sponsoring_future_reserves op construction failed: {e:?}"
                    ),
                })
            })?;

        self.operations.push(xdr_op);
        Ok(self)
    }

    /// Adds a `CreateAccount` operation with an explicit per-operation source
    /// account and a zero starting balance.
    ///
    /// This is the second operation of the CAP-33 sponsored-account-creation
    /// sandwich.  The starting balance is `0` because the base reserve is
    /// covered by the sponsoring account (the sponsor pays the reserve via
    /// `BeginSponsoringFutureReserves`).
    ///
    /// CAP-33: `startingBalance >= 0` is permitted.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Validation`] wrapping [`ValidationError::AddressInvalid`]
    ///   if either address is invalid.
    /// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`]
    ///   if baselib op construction fails.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn create_account_sponsored(
        &mut self,
        op_source: &str,
        destination: &str,
    ) -> Result<&mut Self, WalletError> {
        // Validate both addresses.
        stellar_strkey::ed25519::PublicKey::from_string(op_source).map_err(|_| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: op_source.to_owned(),
            })
        })?;
        stellar_strkey::ed25519::PublicKey::from_string(destination).map_err(|_| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: destination.to_owned(),
            })
        })?;

        // Starting balance is 0 (CAP-33 sponsored creation; base reserve paid by sponsor).
        // stellar-baselib create_account takes stroops as i64.
        // 0 stroops = zero starting balance.
        let xdr_op = BaselibOperation::with_source(op_source)
            .map_err(|e| {
                WalletError::Protocol(ProtocolError::XdrCodecFailed {
                    detail: format!("create_account_sponsored: with_source failed: {e:?}"),
                })
            })?
            .create_account(destination, 0i64)
            .map_err(|e| {
                WalletError::Protocol(ProtocolError::XdrCodecFailed {
                    detail: format!("create_account_sponsored op construction failed: {e:?}"),
                })
            })?;

        self.operations.push(xdr_op);
        Ok(self)
    }

    /// Adds a `ChangeTrust` operation.
    ///
    /// Creates or updates a trustline on the wallet's classic G-account for
    /// `asset`.  The `limit` parameter is the maximum number of units the
    /// account is willing to hold; `None` defaults to `i64::MAX` per Stellar
    /// convention (unlimited trustline).
    ///
    /// A `limit` of `0` removes the trustline entirely.  Trustline removal is
    /// out of scope for the `trustline` verb at v1, but the operation is
    /// available here for test fixtures that require ephemeral issuer setup.
    ///
    /// # Byte-layout
    ///
    /// `ChangeTrustOp` XDR schema (stellar-xdr):
    /// ```text
    /// pub struct ChangeTrustOp { pub line: ChangeTrustAsset, pub limit: i64 }
    /// ```
    /// `limit = i64::MAX` is the conventional "maximum / unlimited" trustline
    /// value per the Stellar protocol; `limit = 0` removes the trustline.
    ///
    /// Threshold: Medium (stellar-baselib `op_list/change_trust.rs`).
    ///
    /// # Errors
    ///
    /// - [`WalletError::Validation`] wrapping [`ValidationError::AssetInvalid`]
    ///   if `asset` is [`Asset::Native`] (trustlines cannot be created for XLM).
    /// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`]
    ///   if baselib op construction fails.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
    ///
    /// const USDC_TESTNET: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
    ///
    /// let mut builder = ClassicOpBuilder::new(
    ///     "GABC...WALLET",
    ///     100,
    ///     "Test SDF Network ; September 2015",
    ///     100,
    /// );
    /// let asset = Asset::from_code_and_issuer("USDC", USDC_TESTNET).unwrap();
    /// builder.change_trust(&asset, None).unwrap();
    /// ```
    pub fn change_trust(
        &mut self,
        asset: &Asset,
        limit: Option<i64>,
    ) -> Result<&mut Self, WalletError> {
        if matches!(asset, Asset::Native) {
            return Err(WalletError::Validation(ValidationError::AssetInvalid {
                input: "native (XLM): trustlines can only be created for non-native assets"
                    .to_owned(),
            }));
        }

        let baselib_asset = asset.to_baselib()?;

        let xdr_op = BaselibOperation::new()
            .change_trust(&baselib_asset, limit)
            .map_err(|e| {
                WalletError::Protocol(ProtocolError::XdrCodecFailed {
                    detail: format!("change_trust op construction failed: {e:?}"),
                })
            })?;

        self.operations.push(xdr_op);
        Ok(self)
    }

    /// Adds a `ClaimClaimableBalance` operation.
    ///
    /// `balance_id_hash_hex` MUST be the bare 64-character hex-encoded
    /// 32-byte claimable-balance hash — NOT the 72-hex canonical id (which
    /// additionally carries the 8-hex `00000000` V0 type-discriminant
    /// prefix) and NOT the `B...` strkey. `stellar_agent_claimable::id::BalanceId::to_hex64`
    /// is the intended producer of this string; that crate is the only place
    /// balance-id normalization across the three accepted textual forms
    /// happens.
    ///
    /// # Byte-layout
    ///
    /// `ClaimClaimableBalanceOp` XDR schema (stellar-xdr):
    /// ```text
    /// pub struct ClaimClaimableBalanceOp { pub balance_id: ClaimableBalanceId }
    /// pub enum ClaimableBalanceId { ClaimableBalanceIdTypeV0(Hash) }
    /// ```
    /// `stellar-baselib`'s `Operation::claim_claimable_balance` hex-decodes
    /// `balance_id_hash_hex` into the 32-byte `Hash` and wraps it in
    /// `ClaimableBalanceIdTypeV0` — V0 is the only id type the protocol
    /// currently defines.
    ///
    /// Threshold: Medium (stellar-baselib `op_list/claim_claimable_balance.rs`).
    ///
    /// # Errors
    ///
    /// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`]
    ///   if `balance_id_hash_hex` is not exactly 64 hex characters or
    ///   baselib op construction otherwise fails.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_network::builder::ClassicOpBuilder;
    ///
    /// let mut builder = ClassicOpBuilder::new(
    ///     "GABC...WALLET",
    ///     100,
    ///     "Test SDF Network ; September 2015",
    ///     100,
    /// );
    /// builder.claim_claimable_balance(&"ab".repeat(32)).unwrap();
    /// ```
    pub fn claim_claimable_balance(
        &mut self,
        balance_id_hash_hex: &str,
    ) -> Result<&mut Self, WalletError> {
        let xdr_op = BaselibOperation::new()
            .claim_claimable_balance(balance_id_hash_hex)
            .map_err(|e| {
                WalletError::Protocol(ProtocolError::XdrCodecFailed {
                    detail: format!("claim_claimable_balance op construction failed: {e:?}"),
                })
            })?;

        self.operations.push(xdr_op);
        Ok(self)
    }

    /// Adds a `SetOptions` operation that sets (and optionally clears) account
    /// flag bits.
    ///
    /// This is a minimal `SetOptions` operation: it only touches the `set_flags`
    /// and `clear_flags` fields.  All other `SetOptionsOp` fields
    /// (`inflation_dest`, thresholds, `home_domain`, `signer`) are `None` and
    /// are not written to the XDR.
    ///
    /// The primary use case is setting `AUTH_CLAWBACK_ENABLED_FLAG (0x8)` +
    /// `AUTH_REVOCABLE_FLAG (0x2)` on an ephemeral testnet issuer account,
    /// where constructing a raw `SetOptionsOp` XDR inline is error-prone and
    /// bypasses the builder's XDR bridge invariant.
    ///
    /// # Byte-layout
    ///
    /// `SetOptionsOp` XDR schema (stellar-xdr):
    /// ```text
    /// pub struct SetOptionsOp {
    ///     pub inflation_dest: Option<AccountId>,
    ///     pub clear_flags: Option<u32>,
    ///     pub set_flags: Option<u32>,
    ///     ...
    /// }
    /// ```
    /// `AccountFlags` enum bit values: `RequiredFlag = 1`, `RevocableFlag = 2`,
    /// `ImmutableFlag = 4`, `ClawbackEnabledFlag = 8`.
    ///
    /// Threshold: Low for `AUTH_*` flags (set/clear flags only); Medium for
    /// other field combinations (stellar-baselib `op_list/set_options.rs`).
    ///
    /// # Parameters
    ///
    /// - `set_flags`: bitmask of flags to set (use `AUTH_*_FLAG` constants
    ///   from `stellar_agent_stablecoin::flags`).
    /// - `clear_flags`: optional bitmask of flags to clear simultaneously.
    ///   `None` means no flags are cleared.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`]
    ///   if baselib op construction fails.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_network::builder::ClassicOpBuilder;
    ///
    /// // Set AUTH_REVOCABLE (0x2) | AUTH_CLAWBACK_ENABLED (0x8) on an account.
    /// let mut builder = ClassicOpBuilder::new(
    ///     "GABC...ISSUER",
    ///     100,
    ///     "Test SDF Network ; September 2015",
    ///     100,
    /// );
    /// builder.set_options_flags(0x2 | 0x8, None).unwrap();
    /// ```
    pub fn set_options_flags(
        &mut self,
        set_flags: u32,
        clear_flags: Option<u32>,
    ) -> Result<&mut Self, WalletError> {
        let xdr_op = BaselibOperation::new()
            .set_options(
                None,
                clear_flags,
                set_flags,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .map_err(|e| {
                WalletError::Protocol(ProtocolError::XdrCodecFailed {
                    detail: format!("set_options_flags op construction failed: {e:?}"),
                })
            })?;

        self.operations.push(xdr_op);
        Ok(self)
    }

    /// Adds an `EndSponsoringFutureReserves` operation with an explicit
    /// per-operation source account.
    ///
    /// This is the third operation of the CAP-33 sponsored-account-creation
    /// sandwich.  The `op_source` is the NEWLY CREATED channel account.  The
    /// channel must sign the transaction to authorise this operation.
    ///
    /// CAP-33: `EndSponsoringFutureReserves` has `sourceAccount: A` (the new
    /// account), which terminates the is-sponsoring-future-reserves relationship.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Validation`] wrapping [`ValidationError::AddressInvalid`]
    ///   if `op_source` is not a valid G-strkey.
    /// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`]
    ///   if baselib op construction fails.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn end_sponsoring_future_reserves(
        &mut self,
        op_source: &str,
    ) -> Result<&mut Self, WalletError> {
        stellar_strkey::ed25519::PublicKey::from_string(op_source).map_err(|_| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: op_source.to_owned(),
            })
        })?;

        let xdr_op = BaselibOperation::with_source(op_source)
            .map_err(|e| {
                WalletError::Protocol(ProtocolError::XdrCodecFailed {
                    detail: format!("end_sponsoring: with_source failed: {e:?}"),
                })
            })?
            .end_sponsoring_future_reserves()
            .map_err(|e| {
                WalletError::Protocol(ProtocolError::XdrCodecFailed {
                    detail: format!("end_sponsoring_future_reserves op construction failed: {e:?}"),
                })
            })?;

        self.operations.push(xdr_op);
        Ok(self)
    }

    /// Builds and signs the transaction envelope with multiple signers, returning
    /// the signed base64 XDR.
    ///
    /// Used for the CAP-33 sponsored-account-creation sandwich where both the
    /// funder AND every newly-created channel account must sign:
    /// - The funder signs the transaction + its `Begin`/`Create` operations.
    /// - Each channel signs its own `EndSponsoringFutureReserves` operation.
    ///
    /// `attach_signature` is called once per signer, in order.  Each call
    /// appends one `DecoratedSignature` to the envelope.
    ///
    /// This method calls `signer.sign_tx_payload` exactly once per signer in
    /// `signers`.  The first signer is the funder (transaction source); the
    /// remaining signers are the channel accounts (one per channel, in derivation
    /// order).
    ///
    /// # Errors
    ///
    /// - [`WalletError::Internal`] if no operations have been added.
    /// - [`WalletError::Protocol`] on XDR failures.
    /// - [`WalletError::Auth`] or [`WalletError::WalletState`] from any signer.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_network::builder::ClassicOpBuilder;
    /// use stellar_agent_network::SoftwareSigningKey;
    ///
    /// # async fn run() -> Result<(), stellar_agent_core::WalletError> {
    /// let builder = ClassicOpBuilder::new(
    ///     "GABC...FUNDER", 100, "Test SDF Network ; September 2015", 100,
    /// );
    /// let funder_key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
    /// let channel_key = SoftwareSigningKey::new_from_bytes([2u8; 32]);
    /// let signers: Vec<&dyn stellar_agent_network::signing::Signer> =
    ///     vec![&funder_key, &channel_key];
    /// let _signed_xdr = builder.build_and_sign_multi(&signers).await?;
    /// # Ok(()) }
    /// ```
    pub async fn build_and_sign_multi(
        self,
        signers: &[&dyn Signer],
    ) -> Result<String, WalletError> {
        if signers.is_empty() {
            return Err(WalletError::Internal(InternalError::UnexpectedState {
                detail: "build_and_sign_multi called with no signers".to_owned(),
            }));
        }

        let network_passphrase = self.network_passphrase.clone();

        // Build unsigned envelope via baselib → base64 XDR.
        let unsigned_b64 = self.build_baselib_envelope_b64()?;

        // Attach each signer's signature in sequence.
        // Each call to `attach_signature` decodes the current envelope, appends
        // one DecoratedSignature, and returns the re-encoded envelope.
        let mut current_b64 = unsigned_b64;
        for signer in signers {
            current_b64 = attach_signature(&current_b64, *signer, &network_passphrase).await?;
        }

        Ok(current_b64)
    }

    /// Sets the transaction memo.
    ///
    /// `stellar-baselib` 0.5.8 re-exports the workspace `stellar_xdr` directly,
    /// so `stellar_xdr::Memo` and `stellar_baselib::xdr::Memo` are the same type.
    /// The memo is stored as-is; no XDR round-trip is required.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Validation`] wrapping [`ValidationError::MemoInvalidType`]
    ///   if a TEXT memo exceeds 28 bytes.
    pub fn memo(&mut self, memo: &stellar_xdr::Memo) -> Result<&mut Self, WalletError> {
        use stellar_xdr::Memo as CurrMemo;

        // Validate TEXT length.
        if let CurrMemo::Text(ref t) = *memo
            && t.len() > 28
        {
            return Err(WalletError::Validation(ValidationError::MemoInvalidType {
                memo_type: format!("TEXT (length {} exceeds 28-byte maximum)", t.len()),
            }));
        }

        self.memo = Some(memo.clone());
        Ok(self)
    }

    /// Sets explicit time bounds on the built transaction.
    ///
    /// Both `min_time` and `max_time` are **absolute** unix seconds.
    /// `min_time = 0` means no lower bound; `max_time = 0` means no upper bound
    /// (though an explicit 0 `max_time` makes little practical sense).
    ///
    /// The built envelope will carry `Preconditions::Time(TimeBounds { min_time,
    /// max_time })`.
    ///
    /// # Byte-layout
    ///
    /// stellar-xdr: `TimeBounds { min_time: TimePoint(u64), max_time: TimePoint(u64) }`.
    /// `Preconditions::Time(TimeBounds)`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_network::builder::ClassicOpBuilder;
    ///
    /// let mut builder = ClassicOpBuilder::new(
    ///     "GABC...SRC", 100, "Test SDF Network ; September 2015", 100,
    /// );
    /// // Set timeBounds: valid from now, expires in 60 seconds.
    /// let current_unix = 1_800_000_000u64;
    /// builder.with_time_bounds(0, current_unix + 60);
    /// ```
    pub fn with_time_bounds(&mut self, min_time: u64, max_time: u64) -> &mut Self {
        use stellar_baselib::xdr::{TimeBounds, TimePoint};
        self.time_bounds = Some(TimeBounds {
            min_time: TimePoint(min_time),
            max_time: TimePoint(max_time),
        });
        self
    }

    /// Sets short time bounds using a 30-second window from `close_time`.
    ///
    /// Equivalent to `with_time_bounds(0, close_time + 30)`.
    ///
    /// The 30-second window bounds mempool replay exposure while giving the
    /// network enough time to include the transaction.  Use `close_time` from
    /// the most recent `get_latest_ledger()` response (`closed_at` unix seconds).
    ///
    /// Callers that need a longer window call
    /// [`ClassicOpBuilder::with_time_bounds`] directly.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_network::builder::ClassicOpBuilder;
    ///
    /// let mut builder = ClassicOpBuilder::new(
    ///     "GABC...SRC", 100, "Test SDF Network ; September 2015", 100,
    /// );
    /// let close_time: u64 = 1_800_000_000; // from get_latest_ledger()
    /// builder.with_short_timebounds(close_time);
    /// ```
    pub fn with_short_timebounds(&mut self, close_time: u64) -> &mut Self {
        // saturating_add prevents overflow for a near-u64::MAX close_time.
        // The method rustdoc says "Never panics"; a wrapping add would silently
        // set max_time = DELTA - 1 (an already-expired window).
        self.with_time_bounds(
            0,
            close_time.saturating_add(crate::builder::SHORT_TIMEBOUNDS_DELTA_SECS),
        )
    }

    /// Builds the unsigned `TransactionEnvelope` and returns it as a
    /// base64-encoded XDR string.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Internal`] if no operations have been added.
    /// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`] on
    ///   XDR serialisation failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
    /// use stellar_agent_core::StellarAmount;
    ///
    /// let mut builder = ClassicOpBuilder::new(
    ///     "GABC...SRC", 100, "Test SDF Network ; September 2015", 100,
    /// );
    /// builder.payment("GDEF...DST", StellarAmount::from_stroops(10_000_000), &Asset::Native).unwrap();
    /// let _xdr = builder.build().unwrap();
    /// ```
    pub fn build(self) -> Result<String, WalletError> {
        self.build_baselib_envelope_b64()
    }

    /// Builds and signs the transaction envelope, returning the signed base64 XDR.
    ///
    /// Signs using `signer.sign_tx_payload` exactly once.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Internal`] if no operations have been added.
    /// - [`WalletError::Protocol`] on XDR failures.
    /// - [`WalletError::Auth`] or [`WalletError::WalletState`] from the signer.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
    /// use stellar_agent_network::SoftwareSigningKey;
    /// use stellar_agent_core::StellarAmount;
    ///
    /// # async fn run() -> Result<(), stellar_agent_core::WalletError> {
    /// let mut builder = ClassicOpBuilder::new(
    ///     "GABC...SRC", 100, "Test SDF Network ; September 2015", 100,
    /// );
    /// builder.payment("GDEF...DST", StellarAmount::from_stroops(10_000_000), &Asset::Native)?;
    /// let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
    /// let _signed_xdr = builder.build_and_sign(&key).await?;
    /// # Ok(()) }
    /// ```
    pub async fn build_and_sign(self, signer: &dyn Signer) -> Result<String, WalletError> {
        let network_passphrase = self.network_passphrase.clone();

        // Build unsigned envelope via baselib → base64 XDR.
        let unsigned_b64 = self.build_baselib_envelope_b64()?;

        // Delegate to the single SEP-23 signing call site.
        // `attach_signature` handles payload construction, SHA-256, signer
        // invocation, signature attachment, and re-encoding.
        crate::signing::envelope_signing::attach_signature(
            &unsigned_b64,
            signer,
            &network_passphrase,
        )
        .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// Uses stellar-baselib to build the transaction and serialise the envelope
    /// to a base64 XDR string.
    fn build_baselib_envelope_b64(self) -> Result<String, WalletError> {
        if self.operations.is_empty() {
            return Err(WalletError::Internal(InternalError::UnexpectedState {
                detail: "ClassicOpBuilder::build called with no operations".to_owned(),
            }));
        }

        // stellar-baselib Account requires a mutable borrow for TransactionBuilder.
        let seq_str = self.sequence_number.to_string();
        let mut account = Account::new(&self.source_account, &seq_str).map_err(|e| {
            WalletError::Protocol(ProtocolError::XdrCodecFailed {
                detail: format!("baselib Account::new failed: {e}"),
            })
        })?;

        let mut tx_builder = TransactionBuilder::new(&mut account, &self.network_passphrase, None);
        // stellar-baselib expects a per-operation fee and multiplies by the
        // operation count when building the XDR transaction fee.
        tx_builder.fee(self.fee);

        for op in self.operations {
            tx_builder.add_operation(op);
        }

        // Take the memo and time_bounds out before building so we can inject
        // them after.
        let memo_opt = self.memo;
        let time_bounds_opt = self.time_bounds;

        let mut tx: Transaction = tx_builder.build();

        // Inject memo after building. The baselib builder's add_memo only handles TEXT;
        // we set the field directly for all memo types.
        if let Some(memo) = memo_opt {
            tx.memo = Some(memo);
        }

        // Inject time bounds. The baselib `TransactionBuilder` has no dedicated
        // time-bounds setter; we set the field directly on the built Transaction.
        // `stellar-baselib src/transaction.rs` exposes `pub time_bounds: Option<xdr::TimeBounds>`.
        // Setting this field before `to_envelope()` causes the builder to emit
        // `Preconditions::Time(TimeBounds{min_time, max_time})` in the XDR.
        if let Some(tb) = time_bounds_opt {
            tx.time_bounds = Some(tb);
        }

        // to_envelope returns the signed envelope; since signatures is empty,
        // this gives us the unsigned V1 envelope.
        let envelope = tx.to_envelope().map_err(|e| {
            WalletError::Protocol(ProtocolError::XdrCodecFailed {
                detail: format!("baselib to_envelope failed: {e}"),
            })
        })?;

        // Encode as base64; attach_signature and submit paths consume base64 strings.
        // stellar-baselib 0.5.8 re-exports stellar_xdr, so WriteXdr here is the
        // same trait as the workspace stellar_xdr::WriteXdr.
        envelope.to_xdr_base64(Limits::none()).map_err(|e| {
            WalletError::Protocol(ProtocolError::XdrCodecFailed {
                detail: format!("envelope XDR base64 encode failed: {e}"),
            })
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::err_expect,
        reason = "test-only; the OK type is not Debug, so .err().expect() is used instead of .expect_err()"
    )]

    use stellar_agent_core::StellarAmount;
    use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};

    use super::*;

    // A valid testnet G-strkey for test fixtures (seed [1u8;32] via ed25519-dalek).
    const TEST_SOURCE: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
    // Known-valid G-strkey from test-support (GBPXXOA5... verified in secret_patterns.rs).
    const TEST_DEST: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

    #[test]
    fn asset_parse_native() {
        assert_eq!(Asset::parse("native").unwrap(), Asset::Native);
        assert_eq!(Asset::parse("XLM").unwrap(), Asset::Native);
        assert_eq!(Asset::parse("xlm").unwrap(), Asset::Native);
    }

    #[test]
    fn asset_parse_credit() {
        let issuer = TEST_SOURCE;
        let input = format!("USDC:{issuer}");
        let asset = Asset::parse(&input).unwrap();
        assert!(matches!(asset, Asset::Credit { ref code, .. } if code == "USDC"));
    }

    #[test]
    fn asset_parse_invalid_no_colon() {
        assert!(Asset::parse("USDC").is_err());
    }

    #[test]
    fn asset_parse_invalid_bad_issuer() {
        assert!(Asset::parse("USDC:NOTASTRKEY").is_err());
    }

    #[test]
    fn asset_parse_code_too_long() {
        let issuer = TEST_SOURCE;
        let input = format!("TOOLONGCODE123:{issuer}");
        assert!(Asset::parse(&input).is_err());
    }

    #[test]
    fn builder_payment_produces_decodable_xdr() {
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .payment(
                TEST_DEST,
                StellarAmount::from_stroops(10_000_000),
                &Asset::Native,
            )
            .unwrap();
        // Verify no errors.
        let xdr = builder.build().unwrap();
        // Verify the XDR decodes without error with the workspace stellar-xdr.
        TransactionEnvelope::from_xdr_base64(&xdr, Limits::none())
            .expect("must decode as a valid TransactionEnvelope");
    }

    #[test]
    fn builder_create_account_produces_decodable_xdr() {
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .create_account(TEST_DEST, StellarAmount::from_stroops(50_000_000))
            .unwrap();
        let xdr = builder.build().unwrap();
        TransactionEnvelope::from_xdr_base64(&xdr, Limits::none())
            .expect("must decode as a valid TransactionEnvelope");
    }

    #[test]
    fn builder_create_account_invalid_destination_returns_validation_error() {
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        let result = builder.create_account("NOTASTRKEY", StellarAmount::from_stroops(50_000_000));
        assert!(result.is_err(), "invalid destination must return an error");
        // Use .err().expect() to extract the error without requiring
        // ClassicOpBuilder: Debug (T: Debug bound on unwrap_err).
        let err = result
            .err()
            .expect("checked is_err above; must be an error variant");
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AddressInvalid { .. })
            ),
            "expected AddressInvalid, got: {err:?}"
        );
    }

    #[test]
    fn builder_build_no_ops_returns_internal_error() {
        let builder = ClassicOpBuilder::new(TEST_SOURCE, 100, "Test", 100);
        let err = builder.build().unwrap_err();
        assert!(matches!(
            err,
            WalletError::Internal(InternalError::UnexpectedState { .. })
        ));
    }

    /// Round-trips every `Memo` variant through the builder and asserts that
    /// encoding via baselib's `to_xdr_base64` and re-decoding with the workspace
    /// `stellar_xdr` produces byte-for-byte identical output.
    ///
    /// Since stellar-baselib 0.5.8 re-exports the workspace `stellar_xdr`
    /// directly, this is a self-consistency check of the XDR serialisation
    /// rather than a cross-version bridge test.
    #[test]
    fn memo_bridge_round_trip_all_variants() {
        use stellar_xdr::Memo as CurrMemo;
        use stellar_xdr::{Hash, Limits, ReadXdr, TransactionEnvelope, WriteXdr};

        let variants: Vec<CurrMemo> = vec![
            CurrMemo::None,
            CurrMemo::Text("hello".as_bytes().to_vec().try_into().unwrap()),
            CurrMemo::Id(42),
            CurrMemo::Hash(Hash([0xABu8; 32])),
            CurrMemo::Return(Hash([0xCDu8; 32])),
        ];

        for memo in variants {
            // Build a transaction with this memo variant.
            let mut builder =
                ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
            builder
                .payment(
                    TEST_DEST,
                    StellarAmount::from_stroops(10_000_000),
                    &Asset::Native,
                )
                .expect("payment op");
            builder.memo(&memo).expect("memo");
            let xdr_b64 = builder.build().expect("build");

            // Re-decode with the workspace xdr and verify round-trip.
            let envelope = TransactionEnvelope::from_xdr_base64(&xdr_b64, Limits::none())
                .expect("round-trip decode must succeed");
            let re_encoded = envelope
                .to_xdr_base64(Limits::none())
                .expect("re-encode must succeed");

            assert_eq!(
                xdr_b64, re_encoded,
                "baselib→workspace XDR bridge must be byte-for-byte stable for memo {memo:?}"
            );
        }
    }

    #[tokio::test]
    async fn build_and_sign_produces_one_signature() {
        use crate::signing::software::SoftwareSigningKey;

        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .payment(
                TEST_DEST,
                StellarAmount::from_stroops(10_000_000),
                &Asset::Native,
            )
            .unwrap();

        let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
        let signed_xdr = builder.build_and_sign(&key).await.unwrap();

        let env =
            TransactionEnvelope::from_xdr_base64(&signed_xdr, Limits::none()).expect("must decode");

        match env {
            TransactionEnvelope::Tx(v1) => {
                assert_eq!(v1.signatures.len(), 1, "exactly one signature expected");
                assert_eq!(v1.signatures[0].signature.0.len(), 64);
            }
            other => panic!("expected Tx envelope, got: {other:?}"),
        }
    }

    /// `with_short_timebounds(close_time)` produces a `Preconditions::Time` envelope
    /// with `max_time == close_time + 30`.
    ///
    /// Confirms that time bounds are correctly encoded in the produced
    /// `TransactionEnvelope` XDR.  Any drift in the `stellar-baselib
    /// Transaction.time_bounds` field assignment or the `Preconditions::Time`
    /// XDR encoding fires this test at CI time.
    #[test]
    fn builder_with_short_timebounds_encodes_correct_max_time() {
        use stellar_xdr::{Limits, Preconditions, ReadXdr, TransactionEnvelope};

        let close_time: u64 = 1_800_000_000;
        let expected_max_time = close_time + 30;

        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .payment(
                TEST_DEST,
                StellarAmount::from_stroops(10_000_000),
                &Asset::Native,
            )
            .unwrap();
        builder.with_short_timebounds(close_time);
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none())
            .expect("must decode as a valid TransactionEnvelope");

        let cond = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.cond,
            other => panic!("expected V1 envelope, got: {other:?}"),
        };

        match cond {
            Preconditions::Time(tb) => {
                assert_eq!(
                    tb.min_time.0, 0,
                    "min_time must be 0 for with_short_timebounds"
                );
                assert_eq!(
                    tb.max_time.0, expected_max_time,
                    "max_time must be close_time + 30 = {expected_max_time}; got {}",
                    tb.max_time.0
                );
            }
            other => panic!("expected Preconditions::Time, got: {other:?}"),
        }
    }

    /// `with_time_bounds(min, max)` encodes both values correctly.
    #[test]
    fn builder_with_time_bounds_encodes_both_fields() {
        use stellar_xdr::{Limits, Preconditions, ReadXdr, TransactionEnvelope};

        let min_time: u64 = 1_700_000_000;
        let max_time: u64 = 1_800_000_000;

        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .payment(
                TEST_DEST,
                StellarAmount::from_stroops(10_000_000),
                &Asset::Native,
            )
            .unwrap();
        builder.with_time_bounds(min_time, max_time);
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none())
            .expect("must decode as a valid TransactionEnvelope");

        let cond = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.cond,
            other => panic!("expected V1 envelope, got: {other:?}"),
        };

        match cond {
            Preconditions::Time(tb) => {
                assert_eq!(tb.min_time.0, min_time);
                assert_eq!(tb.max_time.0, max_time);
            }
            other => panic!("expected Preconditions::Time, got: {other:?}"),
        }
    }

    /// Without calling `with_time_bounds` or `with_short_timebounds`, the
    /// envelope carries `Preconditions::None`.
    #[test]
    fn builder_without_time_bounds_encodes_preconditions_none() {
        use stellar_xdr::{Limits, Preconditions, ReadXdr, TransactionEnvelope};

        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .payment(
                TEST_DEST,
                StellarAmount::from_stroops(10_000_000),
                &Asset::Native,
            )
            .unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none())
            .expect("must decode as a valid TransactionEnvelope");

        let cond = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.cond,
            other => panic!("expected V1 envelope, got: {other:?}"),
        };

        assert!(
            matches!(cond, Preconditions::None),
            "expected Preconditions::None when no time bounds set; got: {cond:?}"
        );
    }

    /// Confirms `ClassicOpBuilder::new(source, current_seq, ...)` produces an
    /// envelope with `seq_num = current_seq + 1`. The +1 increment happens inside
    /// `stellar_baselib::TransactionBuilder::build` via `Account::increment_sequence_number`,
    /// matching js-stellar-base convention: caller passes the CURRENT sequence number
    /// and the builder bumps it.  Callers MUST NOT pre-increment.
    #[test]
    fn builder_envelope_seq_num_is_caller_seq_plus_one() {
        let mut b =
            ClassicOpBuilder::new(TEST_SOURCE, 100, "Test SDF Network ; September 2015", 100);
        b.create_account(TEST_DEST, StellarAmount::from_stroops(50_000_000))
            .unwrap();
        let xdr = b.build().unwrap();
        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).unwrap();
        let seq = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.seq_num.0,
            other => panic!("expected V1 envelope, got {:?}", other),
        };
        assert_eq!(
            seq, 101,
            "expected current_seq(100) + 1; got {seq}. \
            TransactionBuilder::build auto-increments (transaction_builder.rs:187); \
            passing current_seq+1 to ClassicOpBuilder::new produces current_seq+2 \
            in the envelope, which Stellar core rejects with TxBadSeq."
        );
    }

    /// `change_trust` with `limit = None` produces a decodable `ChangeTrust`
    /// envelope with `limit = i64::MAX`.
    ///
    /// `ChangeTrustOp { line: ChangeTrustAsset, limit: i64 }` (stellar-xdr schema).
    /// `limit = None` maps to `i64::MAX` (stellar-baselib `op_list/change_trust.rs`).
    #[test]
    fn change_trust_default_limit_produces_decodable_xdr() {
        use stellar_xdr::{OperationBody, ReadXdr, TransactionEnvelope};

        let issuer = TEST_SOURCE;
        let asset = Asset::from_code_and_issuer("USDC", issuer).unwrap();

        let mut builder =
            ClassicOpBuilder::new(TEST_DEST, 101, "Test SDF Network ; September 2015", 100);
        builder.change_trust(&asset, None).unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none())
            .expect("must decode as a valid TransactionEnvelope");

        let op = match env {
            TransactionEnvelope::Tx(v1) => {
                assert_eq!(v1.tx.operations.len(), 1);
                v1.tx.operations.into_vec().remove(0)
            }
            other => panic!("expected V1 envelope, got: {other:?}"),
        };

        match op.body {
            OperationBody::ChangeTrust(ct) => {
                assert_eq!(ct.limit, i64::MAX, "default limit must be i64::MAX");
            }
            other => panic!("expected ChangeTrust, got: {other:?}"),
        }
    }

    /// `change_trust` with an explicit limit encodes that limit in the XDR.
    #[test]
    fn change_trust_explicit_limit_encodes_correctly() {
        use stellar_xdr::{OperationBody, ReadXdr, TransactionEnvelope};

        let issuer = TEST_SOURCE;
        let asset = Asset::from_code_and_issuer("USDC", issuer).unwrap();
        let explicit_limit: i64 = 100_000_000_000; // 10,000 USDC at 7 decimals

        let mut builder =
            ClassicOpBuilder::new(TEST_DEST, 101, "Test SDF Network ; September 2015", 100);
        builder.change_trust(&asset, Some(explicit_limit)).unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");

        let op = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.operations.into_vec().remove(0),
            other => panic!("expected V1 envelope, got: {other:?}"),
        };

        match op.body {
            OperationBody::ChangeTrust(ct) => {
                assert_eq!(ct.limit, explicit_limit);
            }
            other => panic!("expected ChangeTrust, got: {other:?}"),
        }
    }

    /// `claim_claimable_balance` builds a single-op `ClaimClaimableBalance`
    /// transaction whose op body decodes back to the same 32-byte hash.
    #[test]
    fn claim_claimable_balance_builds_decodable_xdr() {
        use stellar_xdr::{ClaimableBalanceId, OperationBody, ReadXdr, TransactionEnvelope};

        let hash_hex = "ab".repeat(32);

        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder.claim_claimable_balance(&hash_hex).unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none())
            .expect("must decode as a valid TransactionEnvelope");

        let op = match env {
            TransactionEnvelope::Tx(v1) => {
                assert_eq!(v1.tx.operations.len(), 1);
                v1.tx.operations.into_vec().remove(0)
            }
            other => panic!("expected V1 envelope, got: {other:?}"),
        };

        match op.body {
            OperationBody::ClaimClaimableBalance(op) => match op.balance_id {
                ClaimableBalanceId::ClaimableBalanceIdTypeV0(hash) => {
                    assert_eq!(hash.0, [0xab_u8; 32]);
                }
            },
            other => panic!("expected ClaimClaimableBalance, got: {other:?}"),
        }
    }

    /// `claim_claimable_balance` with a malformed (non-64-hex) id string
    /// returns `WalletError::Protocol(XdrCodecFailed)`, not a panic.
    #[test]
    fn claim_claimable_balance_invalid_hex_returns_xdr_codec_failed() {
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        let result = builder.claim_claimable_balance("not-valid-hex");
        let is_xdr_codec_failed = matches!(
            result,
            Err(WalletError::Protocol(ProtocolError::XdrCodecFailed { .. }))
        );
        assert!(
            is_xdr_codec_failed,
            "expected Err(ProtocolError::XdrCodecFailed) for a malformed hex id"
        );
    }

    /// `change_trust` with `Asset::Native` returns `ValidationError::AssetInvalid`.
    ///
    /// The Stellar protocol does not permit trustlines for the native asset.
    #[test]
    fn change_trust_native_returns_asset_invalid() {
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        let result = builder.change_trust(&Asset::Native, None);
        let is_asset_invalid = matches!(
            result,
            Err(WalletError::Validation(
                ValidationError::AssetInvalid { .. }
            ))
        );
        assert!(
            is_asset_invalid,
            "expected Err(ValidationError::AssetInvalid) for Asset::Native"
        );
    }

    /// `set_options_flags` with `set_flags = 0x0A` (RevocableFlag | ClawbackEnabledFlag)
    /// produces a decodable `SetOptions` envelope with those flags set.
    ///
    /// `SetOptionsOp { set_flags: Option<u32>, clear_flags: Option<u32>, ... }` (stellar-xdr schema).
    /// `RevocableFlag = 0x2`, `ClawbackEnabledFlag = 0x8` from `AccountFlags`.
    #[test]
    fn set_options_flags_set_clawback_and_revocable() {
        use stellar_xdr::{OperationBody, ReadXdr, TransactionEnvelope};

        // AUTH_REVOCABLE_FLAG(0x2) | AUTH_CLAWBACK_ENABLED_FLAG(0x8)
        let set_flags: u32 = 0x2 | 0x8;

        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder.set_options_flags(set_flags, None).unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");

        let op = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.operations.into_vec().remove(0),
            other => panic!("expected V1 envelope, got: {other:?}"),
        };

        match op.body {
            OperationBody::SetOptions(so) => {
                assert_eq!(so.set_flags, Some(0x0A), "set_flags must be 0x0A");
                assert_eq!(so.clear_flags, None, "no flags cleared");
                // All other fields must be None (flags-only op).
                assert!(so.inflation_dest.is_none());
                assert!(so.master_weight.is_none());
                assert!(so.low_threshold.is_none());
                assert!(so.med_threshold.is_none());
                assert!(so.high_threshold.is_none());
                assert!(so.home_domain.is_none());
                assert!(so.signer.is_none());
            }
            other => panic!("expected SetOptions, got: {other:?}"),
        }
    }

    /// `set_options_flags` with `clear_flags = Some(0x2)` sets the clear_flags
    /// field and does not set set_flags.
    #[test]
    fn set_options_flags_with_clear_flags() {
        use stellar_xdr::{OperationBody, ReadXdr, TransactionEnvelope};

        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        // set AUTH_IMMUTABLE(0x4) and clear AUTH_REVOCABLE(0x2)
        builder.set_options_flags(0x4, Some(0x2)).unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");

        let op = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.operations.into_vec().remove(0),
            other => panic!("expected V1 envelope, got: {other:?}"),
        };

        match op.body {
            OperationBody::SetOptions(so) => {
                assert_eq!(so.set_flags, Some(0x4));
                assert_eq!(so.clear_flags, Some(0x2));
            }
            other => panic!("expected SetOptions, got: {other:?}"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Asset::parse — additional variants
    // ─────────────────────────────────────────────────────────────────────────

    /// A credit code of 5–12 alphanumeric characters produces `Asset::Credit`
    /// with the correct code stored.  The Stellar XDR schema calls codes of
    /// 5–12 characters `AssetAlphanum12`; `Asset::parse` must accept them.
    #[test]
    fn asset_parse_alphanum12_code() {
        let issuer = TEST_SOURCE;
        let input = format!("LONGTOKEN:{issuer}");
        let asset = Asset::parse(&input).unwrap();
        match asset {
            Asset::Credit { code, issuer: iss } => {
                assert_eq!(code, "LONGTOKEN");
                assert_eq!(iss, issuer);
            }
            other => panic!("expected Asset::Credit, got: {other:?}"),
        }
    }

    /// An empty code segment before `:` is rejected with `AssetInvalid`.
    #[test]
    fn asset_parse_empty_code_is_invalid() {
        let issuer = TEST_SOURCE;
        let input = format!(":{issuer}");
        let err = Asset::parse(&input).unwrap_err();
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AssetInvalid { .. })
            ),
            "expected AssetInvalid for empty code, got: {err:?}"
        );
    }

    /// A non-alphanumeric character in the code segment is rejected.
    #[test]
    fn asset_parse_non_alphanumeric_code_is_invalid() {
        let issuer = TEST_SOURCE;
        let input = format!("US-DC:{issuer}");
        let err = Asset::parse(&input).unwrap_err();
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AssetInvalid { .. })
            ),
            "expected AssetInvalid for non-alphanumeric code, got: {err:?}"
        );
    }

    /// Exactly 12 alphanumeric characters is the maximum accepted code length.
    #[test]
    fn asset_parse_exactly_12_char_code_accepted() {
        let issuer = TEST_SOURCE;
        let input = format!("ABCDEFGHIJKL:{issuer}");
        let asset = Asset::parse(&input).unwrap();
        assert!(matches!(asset, Asset::Credit { ref code, .. } if code == "ABCDEFGHIJKL"));
    }

    /// `"native"` with any capitalisation resolves to `Asset::Native`.
    #[test]
    fn asset_parse_native_case_variants() {
        assert_eq!(Asset::parse("NATIVE").unwrap(), Asset::Native);
        assert_eq!(Asset::parse("Native").unwrap(), Asset::Native);
        assert_eq!(Asset::parse("XLM").unwrap(), Asset::Native);
        assert_eq!(Asset::parse("Xlm").unwrap(), Asset::Native);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Asset::from_code_and_issuer — error paths
    // ─────────────────────────────────────────────────────────────────────────

    /// An empty code string is rejected with `AssetInvalid`.
    #[test]
    fn from_code_and_issuer_empty_code_is_invalid() {
        let err = Asset::from_code_and_issuer("", TEST_SOURCE).unwrap_err();
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AssetInvalid { .. })
            ),
            "expected AssetInvalid for empty code, got: {err:?}"
        );
    }

    /// A code longer than 12 characters is rejected.
    #[test]
    fn from_code_and_issuer_code_too_long_is_invalid() {
        let err = Asset::from_code_and_issuer("ABCDEFGHIJKLM", TEST_SOURCE).unwrap_err();
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AssetInvalid { .. })
            ),
            "expected AssetInvalid for 13-char code, got: {err:?}"
        );
    }

    /// A code with non-alphanumeric characters is rejected.
    #[test]
    fn from_code_and_issuer_non_alphanumeric_code_is_invalid() {
        let err = Asset::from_code_and_issuer("US-DC", TEST_SOURCE).unwrap_err();
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AssetInvalid { .. })
            ),
            "expected AssetInvalid for non-alphanumeric code, got: {err:?}"
        );
    }

    /// An invalid issuer G-strkey is rejected even when the code is valid.
    #[test]
    fn from_code_and_issuer_bad_issuer_is_invalid() {
        let err = Asset::from_code_and_issuer("USDC", "NOTASTRKEY").unwrap_err();
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AssetInvalid { .. })
            ),
            "expected AssetInvalid for bad issuer, got: {err:?}"
        );
    }

    /// Happy path: 1-char code and valid issuer produces `Asset::Credit`.
    #[test]
    fn from_code_and_issuer_single_char_code_accepted() {
        let asset = Asset::from_code_and_issuer("X", TEST_SOURCE).unwrap();
        assert!(matches!(asset, Asset::Credit { ref code, .. } if code == "X"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Asset::to_xdr_trust_line_asset
    // ─────────────────────────────────────────────────────────────────────────

    /// `Asset::Native` converts to `TrustLineAsset::Native`.
    #[test]
    fn to_xdr_trust_line_asset_native() {
        use stellar_xdr::TrustLineAsset;
        let asset = Asset::Native;
        let tla = asset.to_xdr_trust_line_asset().unwrap();
        assert!(
            matches!(tla, TrustLineAsset::Native),
            "expected TrustLineAsset::Native"
        );
    }

    /// A 4-character code produces `TrustLineAsset::CreditAlphanum4` with the
    /// code bytes zero-padded to 4 bytes in the XDR.
    #[test]
    fn to_xdr_trust_line_asset_alphanum4_code_bytes() {
        use stellar_xdr::{AssetCode4, TrustLineAsset};
        let asset = Asset::from_code_and_issuer("USDC", TEST_SOURCE).unwrap();
        let tla = asset.to_xdr_trust_line_asset().unwrap();
        match tla {
            TrustLineAsset::CreditAlphanum4(an4) => {
                // "USDC" in ASCII is [0x55, 0x53, 0x44, 0x43]; zero-padded to 4 bytes.
                let expected = AssetCode4(*b"USDC");
                assert_eq!(an4.asset_code, expected, "AssetCode4 bytes must match");
            }
            other => panic!("expected CreditAlphanum4, got: {other:?}"),
        }
    }

    /// A code shorter than 4 characters is zero-padded to 4 bytes (`AssetCode4`).
    #[test]
    fn to_xdr_trust_line_asset_alphanum4_short_code_zero_padded() {
        use stellar_xdr::TrustLineAsset;
        let asset = Asset::from_code_and_issuer("XLM", TEST_SOURCE).unwrap();
        let tla = asset.to_xdr_trust_line_asset().unwrap();
        match tla {
            TrustLineAsset::CreditAlphanum4(an4) => {
                // "XLM" → [0x58, 0x4C, 0x4D, 0x00] (zero-padded).
                assert_eq!(an4.asset_code.0[0], b'X');
                assert_eq!(an4.asset_code.0[1], b'L');
                assert_eq!(an4.asset_code.0[2], b'M');
                assert_eq!(an4.asset_code.0[3], 0x00, "must be zero-padded");
            }
            other => panic!("expected CreditAlphanum4, got: {other:?}"),
        }
    }

    /// A 5-character code produces `TrustLineAsset::CreditAlphanum12` with the
    /// code bytes zero-padded to 12 bytes in the XDR.
    #[test]
    fn to_xdr_trust_line_asset_alphanum12_code_bytes() {
        use stellar_xdr::TrustLineAsset;
        let asset = Asset::from_code_and_issuer("TOKEN", TEST_SOURCE).unwrap();
        let tla = asset.to_xdr_trust_line_asset().unwrap();
        match tla {
            TrustLineAsset::CreditAlphanum12(an12) => {
                assert_eq!(&an12.asset_code.0[..5], b"TOKEN");
                // Bytes 5–11 must be zero-padded.
                assert_eq!(&an12.asset_code.0[5..], &[0u8; 7]);
            }
            other => panic!("expected CreditAlphanum12, got: {other:?}"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // payment with credit asset
    // ─────────────────────────────────────────────────────────────────────────

    /// A payment with a non-native credit asset encodes `OperationBody::Payment`
    /// with `Asset::CreditAlphanum4` in the XDR.
    #[test]
    fn payment_credit_asset_encodes_correct_asset_in_xdr() {
        use stellar_xdr::{OperationBody, ReadXdr, TransactionEnvelope};

        let asset = Asset::from_code_and_issuer("USDC", TEST_SOURCE).unwrap();
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .payment(TEST_DEST, StellarAmount::from_stroops(5_000_000), &asset)
            .unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");
        let op = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.operations.into_vec().remove(0),
            other => panic!("expected V1 envelope, got: {other:?}"),
        };
        match op.body {
            OperationBody::Payment(pay) => {
                // Amount must survive the round-trip.
                assert_eq!(pay.amount, 5_000_000, "amount must be 5_000_000 stroops");
                // Asset must be encoded as CreditAlphanum4 with code "USDC".
                match pay.asset {
                    stellar_xdr::Asset::CreditAlphanum4(an4) => {
                        assert_eq!(&an4.asset_code.0, b"USDC");
                    }
                    other => panic!("expected CreditAlphanum4 asset, got: {other:?}"),
                }
            }
            other => panic!("expected Payment op, got: {other:?}"),
        }
    }

    /// A payment with an invalid destination returns `ValidationError::AddressInvalid`.
    #[test]
    fn payment_invalid_destination_returns_address_invalid() {
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        let err = builder
            .payment(
                "BADADDRESS",
                StellarAmount::from_stroops(100),
                &Asset::Native,
            )
            .err()
            .expect("expected error");
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AddressInvalid { .. })
            ),
            "expected AddressInvalid for bad destination, got: {err:?}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // begin_sponsoring_future_reserves
    // ─────────────────────────────────────────────────────────────────────────

    /// `begin_sponsoring_future_reserves` with valid addresses produces a
    /// decodable `BeginSponsoringFutureReserves` operation in the XDR.
    #[test]
    fn begin_sponsoring_future_reserves_produces_decodable_xdr() {
        use stellar_xdr::{OperationBody, ReadXdr, TransactionEnvelope};

        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .begin_sponsoring_future_reserves(TEST_SOURCE, TEST_DEST)
            .unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");
        let op = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.operations.into_vec().remove(0),
            other => panic!("expected V1 envelope, got: {other:?}"),
        };
        match op.body {
            OperationBody::BeginSponsoringFutureReserves(bsfr) => {
                // The sponsored_id AccountId must encode the TEST_DEST public key.
                let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(TEST_DEST).unwrap();
                let expected_pk =
                    stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(pk_bytes.0));
                // AccountId is a newtype wrapper: AccountId(PublicKey).
                assert_eq!(
                    bsfr.sponsored_id.0, expected_pk,
                    "sponsored_id must encode TEST_DEST public key"
                );
            }
            other => panic!("expected BeginSponsoringFutureReserves op, got: {other:?}"),
        }
    }

    /// An invalid `op_source` returns `ValidationError::AddressInvalid`.
    #[test]
    fn begin_sponsoring_future_reserves_invalid_op_source_returns_address_invalid() {
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        let err = builder
            .begin_sponsoring_future_reserves("BADADDRESS", TEST_DEST)
            .err()
            .expect("expected error");
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AddressInvalid { .. })
            ),
            "expected AddressInvalid for bad op_source, got: {err:?}"
        );
    }

    /// An invalid `sponsored_id` returns `ValidationError::AddressInvalid`.
    #[test]
    fn begin_sponsoring_future_reserves_invalid_sponsored_id_returns_address_invalid() {
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        let err = builder
            .begin_sponsoring_future_reserves(TEST_SOURCE, "BADADDRESS")
            .err()
            .expect("expected error");
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AddressInvalid { .. })
            ),
            "expected AddressInvalid for bad sponsored_id, got: {err:?}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // create_account_sponsored
    // ─────────────────────────────────────────────────────────────────────────

    /// `create_account_sponsored` with valid addresses produces a decodable
    /// `CreateAccount` operation with `starting_balance = 0` in the XDR.
    #[test]
    fn create_account_sponsored_produces_zero_balance_create_account() {
        use stellar_xdr::{OperationBody, ReadXdr, TransactionEnvelope};

        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .create_account_sponsored(TEST_SOURCE, TEST_DEST)
            .unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");
        let op = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.operations.into_vec().remove(0),
            other => panic!("expected V1 envelope, got: {other:?}"),
        };
        match op.body {
            OperationBody::CreateAccount(ca) => {
                assert_eq!(
                    ca.starting_balance, 0,
                    "sponsored create_account starting balance must be 0"
                );
            }
            other => panic!("expected CreateAccount op, got: {other:?}"),
        }
    }

    /// An invalid `op_source` in `create_account_sponsored` returns `AddressInvalid`.
    #[test]
    fn create_account_sponsored_invalid_op_source_returns_address_invalid() {
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        let err = builder
            .create_account_sponsored("BADADDRESS", TEST_DEST)
            .err()
            .expect("expected error");
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AddressInvalid { .. })
            ),
            "expected AddressInvalid for bad op_source, got: {err:?}"
        );
    }

    /// An invalid `destination` in `create_account_sponsored` returns `AddressInvalid`.
    #[test]
    fn create_account_sponsored_invalid_destination_returns_address_invalid() {
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        let err = builder
            .create_account_sponsored(TEST_SOURCE, "BADADDRESS")
            .err()
            .expect("expected error");
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AddressInvalid { .. })
            ),
            "expected AddressInvalid for bad destination, got: {err:?}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // end_sponsoring_future_reserves
    // ─────────────────────────────────────────────────────────────────────────

    /// `end_sponsoring_future_reserves` with a valid address produces a
    /// decodable `EndSponsoringFutureReserves` operation in the XDR, and the
    /// per-op source account matches the supplied address.
    #[test]
    fn end_sponsoring_future_reserves_produces_decodable_xdr() {
        use stellar_xdr::{OperationBody, ReadXdr, TransactionEnvelope};

        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder.end_sponsoring_future_reserves(TEST_DEST).unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");
        let op = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.operations.into_vec().remove(0),
            other => panic!("expected V1 envelope, got: {other:?}"),
        };
        assert!(
            matches!(op.body, OperationBody::EndSponsoringFutureReserves),
            "expected EndSponsoringFutureReserves op body, got: {:?}",
            op.body
        );
    }

    /// An invalid `op_source` in `end_sponsoring_future_reserves` returns `AddressInvalid`.
    #[test]
    fn end_sponsoring_future_reserves_invalid_op_source_returns_address_invalid() {
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        let err = builder
            .end_sponsoring_future_reserves("BADADDRESS")
            .err()
            .expect("expected error");
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AddressInvalid { .. })
            ),
            "expected AddressInvalid for bad op_source, got: {err:?}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // build_and_sign_multi
    // ─────────────────────────────────────────────────────────────────────────

    /// `build_and_sign_multi` with zero signers returns
    /// `WalletError::Internal(InternalError::UnexpectedState)`.
    #[tokio::test]
    async fn build_and_sign_multi_no_signers_returns_internal_error() {
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .payment(
                TEST_DEST,
                StellarAmount::from_stroops(10_000_000),
                &Asset::Native,
            )
            .unwrap();
        let err = builder.build_and_sign_multi(&[]).await.unwrap_err();
        assert!(
            matches!(
                err,
                WalletError::Internal(InternalError::UnexpectedState { .. })
            ),
            "expected InternalError::UnexpectedState with no signers, got: {err:?}"
        );
    }

    /// `build_and_sign_multi` with two signers produces exactly two signatures
    /// in the XDR envelope.
    #[tokio::test]
    async fn build_and_sign_multi_two_signers_produces_two_signatures() {
        use crate::signing::Signer;
        use crate::signing::software::SoftwareSigningKey;

        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .payment(
                TEST_DEST,
                StellarAmount::from_stroops(10_000_000),
                &Asset::Native,
            )
            .unwrap();

        let key1 = SoftwareSigningKey::new_from_bytes([1u8; 32]);
        let key2 = SoftwareSigningKey::new_from_bytes([2u8; 32]);
        let signers: Vec<&dyn Signer> = vec![&key1, &key2];
        let signed_xdr = builder.build_and_sign_multi(&signers).await.unwrap();

        let env =
            TransactionEnvelope::from_xdr_base64(&signed_xdr, Limits::none()).expect("must decode");

        match env {
            TransactionEnvelope::Tx(v1) => {
                assert_eq!(
                    v1.signatures.len(),
                    2,
                    "exactly two signatures expected for two signers"
                );
                // Each signature must be 64 bytes.
                assert_eq!(v1.signatures[0].signature.0.len(), 64);
                assert_eq!(v1.signatures[1].signature.0.len(), 64);
                // The two hints (last 4 bytes of each signer's public key) must differ.
                assert_ne!(
                    v1.signatures[0].hint, v1.signatures[1].hint,
                    "hints for distinct keys must differ"
                );
            }
            other => panic!("expected Tx envelope, got: {other:?}"),
        }
    }

    /// `build_and_sign_multi` with a single signer produces exactly one signature
    /// — matching `build_and_sign` behaviour.
    #[tokio::test]
    async fn build_and_sign_multi_one_signer_matches_build_and_sign() {
        use crate::signing::Signer;
        use crate::signing::software::SoftwareSigningKey;

        let key = SoftwareSigningKey::new_from_bytes([7u8; 32]);

        // build_and_sign path.
        let mut b1 =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        b1.payment(
            TEST_DEST,
            StellarAmount::from_stroops(10_000_000),
            &Asset::Native,
        )
        .unwrap();
        let signed_single = b1.build_and_sign(&key).await.unwrap();

        // build_and_sign_multi path.
        let mut b2 =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        b2.payment(
            TEST_DEST,
            StellarAmount::from_stroops(10_000_000),
            &Asset::Native,
        )
        .unwrap();
        let signers: Vec<&dyn Signer> = vec![&key];
        let signed_multi = b2.build_and_sign_multi(&signers).await.unwrap();

        // Both paths must produce identical signed envelopes.
        assert_eq!(
            signed_single, signed_multi,
            "build_and_sign and build_and_sign_multi(1 signer) must produce the same envelope"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // fee encoding
    // ─────────────────────────────────────────────────────────────────────────

    /// The XDR `Transaction.fee` field is `fee_stroops * op_count`.
    /// stellar-baselib multiplies the per-op fee by the operation count when
    /// building the transaction XDR.  Two operations at 100 stroops/op → 200.
    #[test]
    fn fee_is_per_op_fee_times_op_count() {
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .payment(
                TEST_DEST,
                StellarAmount::from_stroops(5_000_000),
                &Asset::Native,
            )
            .unwrap();
        // Add a second op (create_account at TEST_DEST as destination, which is already a valid
        // address). The fee field must be 100*2 = 200.
        builder
            .create_account(TEST_SOURCE, StellarAmount::from_stroops(50_000_000))
            .unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");
        let fee = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.fee,
            other => panic!("expected V1 envelope, got: {other:?}"),
        };
        assert_eq!(
            fee, 200,
            "fee must be per-op-fee(100) * op-count(2) = 200; got {fee}"
        );
    }

    /// A two-operation envelope contains exactly two operations in the
    /// `operations` array.
    #[test]
    fn multi_op_transaction_contains_correct_op_count() {
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .payment(
                TEST_DEST,
                StellarAmount::from_stroops(5_000_000),
                &Asset::Native,
            )
            .unwrap();
        builder
            .create_account(TEST_SOURCE, StellarAmount::from_stroops(50_000_000))
            .unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");
        let op_count = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.operations.len(),
            other => panic!("expected V1 envelope, got: {other:?}"),
        };
        assert_eq!(
            op_count, 2,
            "two operations must be present in the envelope"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // memo()
    // ─────────────────────────────────────────────────────────────────────────

    /// `StringM::<28>` enforces the TEXT memo 28-byte length limit at XDR
    /// construction time, so a >28-byte `Memo::Text` cannot be constructed
    /// from safe public API and therefore cannot reach `builder.memo()`.
    /// This test asserts the boundary at the type level: 28 bytes accepted,
    /// 29 bytes rejected.
    #[test]
    fn string_m_28_enforces_memo_text_28_byte_boundary() {
        // 28 bytes: accepted.
        let ok: Result<stellar_xdr::StringM<28>, _> = "a".repeat(28).into_bytes().try_into();
        assert!(ok.is_ok(), "28 bytes must be accepted by StringM::<28>");
        assert_eq!(ok.unwrap().len(), 28);

        // 29 bytes: rejected by StringM::<28>; builder.memo() is never reached.
        let too_long: Result<stellar_xdr::StringM<28>, _> = "a".repeat(29).into_bytes().try_into();
        assert!(
            too_long.is_err(),
            "StringM::<28> must reject a 29-byte input"
        );
    }

    /// `builder.memo()` with a `Memo::None` leaves the transaction memo as
    /// `Memo::None` in the XDR.
    #[test]
    fn builder_memo_none_leaves_no_memo_in_xdr() {
        use stellar_xdr::{Memo as CurrMemo, ReadXdr, TransactionEnvelope};

        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .payment(
                TEST_DEST,
                StellarAmount::from_stroops(1_000_000),
                &Asset::Native,
            )
            .unwrap();
        builder.memo(&CurrMemo::None).unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");
        let memo = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.memo,
            other => panic!("expected V1 envelope, got: {other:?}"),
        };
        assert!(
            matches!(memo, CurrMemo::None),
            "Memo::None must be encoded as Memo::None in XDR"
        );
    }

    /// `builder.memo()` with a `Memo::Id` encodes the ID correctly in the XDR.
    #[test]
    fn builder_memo_id_encodes_correctly_in_xdr() {
        use stellar_xdr::{Memo as CurrMemo, ReadXdr, TransactionEnvelope};

        let expected_id: u64 = 0xDEAD_BEEF_1234_5678;
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .payment(
                TEST_DEST,
                StellarAmount::from_stroops(1_000_000),
                &Asset::Native,
            )
            .unwrap();
        builder.memo(&CurrMemo::Id(expected_id)).unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");
        let memo = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.memo,
            other => panic!("expected V1 envelope, got: {other:?}"),
        };
        match memo {
            CurrMemo::Id(id) => {
                assert_eq!(id, expected_id, "memo ID must survive XDR round-trip");
            }
            other => panic!("expected Memo::Id, got: {other:?}"),
        }
    }

    /// `builder.memo()` with a `Memo::Hash` encodes the 32-byte hash in the XDR.
    #[test]
    fn builder_memo_hash_encodes_correctly_in_xdr() {
        use stellar_xdr::{Hash, Memo as CurrMemo, ReadXdr, TransactionEnvelope};

        let hash_bytes = [0xAB_u8; 32];
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .payment(
                TEST_DEST,
                StellarAmount::from_stroops(1_000_000),
                &Asset::Native,
            )
            .unwrap();
        builder.memo(&CurrMemo::Hash(Hash(hash_bytes))).unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");
        let memo = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.memo,
            other => panic!("expected V1 envelope, got: {other:?}"),
        };
        match memo {
            CurrMemo::Hash(h) => {
                assert_eq!(
                    h.0, hash_bytes,
                    "memo Hash bytes must survive XDR round-trip"
                );
            }
            other => panic!("expected Memo::Hash, got: {other:?}"),
        }
    }

    /// `builder.memo()` with a `Memo::Return` encodes the 32-byte return hash.
    #[test]
    fn builder_memo_return_encodes_correctly_in_xdr() {
        use stellar_xdr::{Hash, Memo as CurrMemo, ReadXdr, TransactionEnvelope};

        let return_bytes = [0xCD_u8; 32];
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .payment(
                TEST_DEST,
                StellarAmount::from_stroops(1_000_000),
                &Asset::Native,
            )
            .unwrap();
        builder.memo(&CurrMemo::Return(Hash(return_bytes))).unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");
        let memo = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.memo,
            other => panic!("expected V1 envelope, got: {other:?}"),
        };
        match memo {
            CurrMemo::Return(h) => {
                assert_eq!(
                    h.0, return_bytes,
                    "memo Return bytes must survive XDR round-trip"
                );
            }
            other => panic!("expected Memo::Return, got: {other:?}"),
        }
    }

    /// `builder.memo()` with a `Memo::Text` encodes the text bytes in the XDR.
    #[test]
    fn builder_memo_text_encodes_correctly_in_xdr() {
        use stellar_xdr::{Memo as CurrMemo, ReadXdr, TransactionEnvelope};

        let text = b"hello-memo";
        let string_m: stellar_xdr::StringM<28> = text.to_vec().try_into().expect("fits in 28");
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .payment(
                TEST_DEST,
                StellarAmount::from_stroops(1_000_000),
                &Asset::Native,
            )
            .unwrap();
        builder.memo(&CurrMemo::Text(string_m)).unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");
        let memo = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.memo,
            other => panic!("expected V1 envelope, got: {other:?}"),
        };
        match memo {
            CurrMemo::Text(t) => {
                assert_eq!(
                    t.as_slice(),
                    text,
                    "memo Text bytes must survive XDR round-trip"
                );
            }
            other => panic!("expected Memo::Text, got: {other:?}"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // with_short_timebounds — saturation at u64::MAX
    // ─────────────────────────────────────────────────────────────────────────

    /// `with_short_timebounds(u64::MAX)` saturates at `u64::MAX` rather than
    /// wrapping (which would produce a past max_time and a confusingly expired
    /// envelope).
    #[test]
    fn with_short_timebounds_near_max_u64_saturates() {
        use stellar_xdr::{Preconditions, ReadXdr, TransactionEnvelope};

        let close_time = u64::MAX;
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .payment(
                TEST_DEST,
                StellarAmount::from_stroops(1_000_000),
                &Asset::Native,
            )
            .unwrap();
        builder.with_short_timebounds(close_time);
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");
        let cond = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.cond,
            other => panic!("expected V1 envelope, got: {other:?}"),
        };
        match cond {
            Preconditions::Time(tb) => {
                assert_eq!(
                    tb.max_time.0,
                    u64::MAX,
                    "max_time must saturate at u64::MAX, not wrap to {}",
                    tb.max_time.0
                );
            }
            other => panic!("expected Preconditions::Time, got: {other:?}"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // create_account payment amount round-trip
    // ─────────────────────────────────────────────────────────────────────────

    /// `create_account` encodes the exact starting balance in the XDR.
    #[test]
    fn create_account_starting_balance_encodes_correctly() {
        use stellar_xdr::{OperationBody, ReadXdr, TransactionEnvelope};

        let starting_balance_stroops: i64 = 25_000_000; // 2.5 XLM
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .create_account(
                TEST_DEST,
                StellarAmount::from_stroops(starting_balance_stroops),
            )
            .unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");
        let op = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.operations.into_vec().remove(0),
            other => panic!("expected V1 envelope, got: {other:?}"),
        };
        match op.body {
            OperationBody::CreateAccount(ca) => {
                assert_eq!(
                    ca.starting_balance, starting_balance_stroops,
                    "starting balance must encode as {starting_balance_stroops} stroops"
                );
            }
            other => panic!("expected CreateAccount op, got: {other:?}"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Asset::parse — payment amount encodes correctly for native asset
    // ─────────────────────────────────────────────────────────────────────────

    /// A native-asset payment encodes `OperationBody::Payment` with
    /// `Asset::Native` in the XDR and the exact stroops amount.
    #[test]
    fn payment_native_asset_amount_round_trip() {
        use stellar_xdr::{OperationBody, ReadXdr, TransactionEnvelope};

        let amount: i64 = 12_345_678;
        let mut builder =
            ClassicOpBuilder::new(TEST_SOURCE, 101, "Test SDF Network ; September 2015", 100);
        builder
            .payment(
                TEST_DEST,
                StellarAmount::from_stroops(amount),
                &Asset::Native,
            )
            .unwrap();
        let xdr = builder.build().unwrap();

        let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");
        let op = match env {
            TransactionEnvelope::Tx(v1) => v1.tx.operations.into_vec().remove(0),
            other => panic!("expected V1 envelope, got: {other:?}"),
        };
        match op.body {
            OperationBody::Payment(pay) => {
                assert_eq!(
                    pay.amount, amount,
                    "payment amount must encode as {amount} stroops"
                );
                assert!(
                    matches!(pay.asset, stellar_xdr::Asset::Native),
                    "asset must be Native"
                );
            }
            other => panic!("expected Payment op, got: {other:?}"),
        }
    }
}
