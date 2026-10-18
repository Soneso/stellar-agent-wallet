//! Observations supplied by each classic transaction path.

use crate::account::{AccountFlagsView, AccountView, project_trustline_entry};
use stellar_agent_core::{
    asset_id::CanonicalAsset,
    error::{ProtocolError, WalletError},
};
use stellar_xdr::ClaimableBalanceEntry;

/// Source or funder account fields used by the action.
#[derive(Debug, Clone)]
pub struct AccountObservation {
    /// Canonical account address.
    pub account_id: String,
    /// Current account sequence.
    pub sequence: i64,
    /// Native balance in stroops.
    pub native_balance: i64,
    /// Number of subentries used in reserve calculations.
    pub subentry_count: u32,
    /// Projected authorization flags.
    pub flags: Option<AccountFlagsView>,
}

impl AccountObservation {
    /// Copies the account view used by the primary decision.
    ///
    /// # Errors
    /// Refuses a missing or unparseable native balance.
    pub fn from_view(view: &AccountView) -> Result<Self, WalletError> {
        let native = view.balances.first().ok_or_else(invalid_observation)?;
        Ok(Self {
            account_id: view.account_id.clone(),
            sequence: view.sequence_number,
            native_balance: native.balance_stroops()?,
            subentry_count: view.subentry_count,
            flags: view.account_flags.clone(),
        })
    }
}

pub(super) fn invalid_observation() -> WalletError {
    ProtocolError::XdrCodecFailed {
        detail: "invalid cross-check observation".to_owned(),
    }
    .into()
}

/// Destination presence and policy identity fields.
#[derive(Debug, Clone)]
pub struct DestinationObservation {
    /// Canonical destination address.
    pub account_id: String,
    /// Present account's projected home domain and authorization flags.
    pub present: Option<(Option<String>, Option<AccountFlagsView>)>,
}

impl DestinationObservation {
    /// Copies destination presence and identity from the primary read.
    #[must_use]
    pub fn from_view(account_id: &str, view: Option<&AccountView>) -> Self {
        Self {
            account_id: account_id.to_owned(),
            present: view.map(|v| (v.home_domain.clone(), v.account_flags.clone())),
        }
    }
}

/// Issuer presence and authorization flags.
#[derive(Debug, Clone)]
pub struct IssuerObservation {
    /// Issuer account address.
    pub account_id: String,
    /// Outer `None` means the account is absent.
    pub flags: Option<Option<AccountFlagsView>>,
}

impl IssuerObservation {
    /// Copies issuer presence and flags from the primary read.
    #[must_use]
    pub fn from_view(account_id: &str, view: Option<&AccountView>) -> Self {
        Self {
            account_id: account_id.to_owned(),
            flags: view.map(|v| v.account_flags.clone()),
        }
    }
}

/// Trustline presence and the fields used by the claim guard.
#[derive(Debug, Clone)]
pub struct TrustlineObservation {
    /// Trustline owner.
    pub account_id: String,
    /// Classic asset identity.
    pub asset: CanonicalAsset,
    /// Present trustline's balance, limit, and raw authorization flags.
    pub state: Option<(i64, i64, u32)>,
}

impl TrustlineObservation {
    /// Projects the balance with the projection the primary read uses, and
    /// takes the limit and the raw authorization flags from the entry.
    ///
    /// # Errors
    /// Refuses an unsupported asset or a balance the projection rejects.
    pub fn from_entry(
        account_id: &str,
        asset: CanonicalAsset,
        entry: Option<&stellar_xdr::TrustLineEntry>,
    ) -> Result<Self, WalletError> {
        let state = entry
            .map(|entry| {
                let view = project_trustline_entry(entry)?;
                Ok::<_, WalletError>((view.balance_stroops()?, entry.limit, entry.flags))
            })
            .transpose()?;
        Ok(Self {
            account_id: account_id.to_owned(),
            asset,
            state,
        })
    }
}

impl TrustlineObservation {
    /// Reads the raw trustline of `account_id` for the send asset on the
    /// primary and builds the observation from it.
    ///
    /// A native send asset has no trustline and yields `None`; an issued asset
    /// yields an observation whose state is `None` when the account holds no
    /// trustline for it.
    ///
    /// # Errors
    /// Refuses an asset outside the canonical classic alphabet with
    /// `validation.asset_invalid`, and passes through the refusals of
    /// [`crate::account::fetch_trustline_entry`] and [`Self::from_entry`].
    pub async fn read_send_asset(
        client: &crate::client::StellarRpcClient,
        account_id: &str,
        asset: &crate::builder::Asset,
    ) -> Result<Option<Self>, WalletError> {
        if matches!(asset, crate::builder::Asset::Native) {
            return Ok(None);
        }
        let canonical = asset.to_canonical()?;
        let entry = crate::account::fetch_trustline_entry(
            client,
            account_id,
            &asset.to_xdr_trust_line_asset()?,
        )
        .await?;
        Self::from_entry(account_id, canonical, entry.as_ref()).map(Some)
    }
}

/// Claimable-balance identity and the complete record used by the claim guard.
#[derive(Debug, Clone)]
pub struct ClaimableBalanceObservation {
    /// V0 balance identifier.
    pub balance_id: [u8; 32],
    /// Present record, or absence observed on the primary.
    pub entry: Option<ClaimableBalanceEntry>,
}

/// Whether the primary read the SEP-29 flag for a memo-less envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoObservation {
    /// The flag was not read: the envelope carries a memo, or pays a muxed
    /// destination whose id carries it.
    NotRead,
    /// Normalized primary flag.
    Read(bool),
}

/// Payment observations used before signing.
#[derive(Debug, Clone)]
pub struct PayWitnessInputs {
    /// Source account used to build and evaluate the payment.
    pub source: AccountObservation,
    /// Destination identity used by policy.
    pub destination: DestinationObservation,
    /// Primary SEP-29 observation.
    pub memo: MemoObservation,
    /// The source's trustline for an issued send asset; `None` for a native
    /// send asset.
    pub trustline: Option<TrustlineObservation>,
}

/// Account creation observations used before signing.
#[derive(Debug, Clone)]
pub struct CreateAccountWitnessInputs {
    /// Funding source.
    pub source: AccountObservation,
}

/// Trustline observations used before signing.
#[derive(Debug, Clone)]
pub struct TrustlineWitnessInputs {
    /// Transaction source.
    pub source: AccountObservation,
    /// Issuer flags behind the clawback disclosure gate.
    pub issuer: IssuerObservation,
}

/// Claim observations used before signing.
#[derive(Debug, Clone)]
pub struct ClaimWitnessInputs {
    /// Transaction source.
    pub source: AccountObservation,
    /// Trustline read by a full claim stage.
    pub trustline: Option<TrustlineObservation>,
    /// Claim record read by the stage.
    pub balance: Option<ClaimableBalanceObservation>,
}

/// Pool initialization observations used before signing.
#[derive(Debug, Clone)]
pub struct PoolInitWitnessInputs {
    /// Account funding the channels.
    pub funder: AccountObservation,
    /// Channels the primary reports absent, in their configured order.
    pub absent_channels: Vec<String>,
}

/// Observations for one supported classic path.
#[derive(Debug, Clone)]
pub enum ClassicInputs {
    /// Payment.
    Pay(PayWitnessInputs),
    /// Account creation.
    CreateAccount(CreateAccountWitnessInputs),
    /// Trustline change.
    Trustline(TrustlineWitnessInputs),
    /// Claim.
    Claim(ClaimWitnessInputs),
    /// Pool initialization.
    PoolInit(PoolInitWitnessInputs),
}

macro_rules! from_inputs {
    ($($ty:ident => $variant:ident),* $(,)?) => {$(
        impl From<$ty> for ClassicInputs {
            fn from(value: $ty) -> Self { Self::$variant(value) }
        }
    )*};
}
from_inputs! {
    PayWitnessInputs => Pay, CreateAccountWitnessInputs => CreateAccount,
    TrustlineWitnessInputs => Trustline, ClaimWitnessInputs => Claim,
    PoolInitWitnessInputs => PoolInit,
}

impl ClassicInputs {
    pub(super) fn memo_check(&self) -> bool {
        matches!(
            self,
            Self::Pay(PayWitnessInputs {
                memo: MemoObservation::Read(_),
                ..
            })
        )
    }
}
