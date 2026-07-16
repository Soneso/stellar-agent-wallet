//! Strict Machine Payments Protocol support for Stellar payments.
//!
//! This crate owns bounded MPP wire parsing, request-context binding, and
//! credential and receipt encoding. It intentionally does not perform HTTP or
//! MCP transport on behalf of callers.

pub mod challenge;
pub mod context;
pub mod credential;
pub mod error;
pub mod json;
pub mod limits;
pub mod policy;
pub mod receipt;
pub mod reconcile;
pub mod service;
pub mod sponsored;
pub mod state;
pub mod store;

pub use challenge::{
    ChallengeEcho, ChallengeInput, SelectedChallenge, StellarChargeRequest, select_and_validate,
};
pub use context::{HttpRequestContext, McpOperationKind, McpRequestContext, RequestContext};
pub use credential::{CredentialOutput, build_credential};
pub use error::{MppError, MppErrorCode};
pub use policy::mpp_value_effects;
pub use receipt::{PaymentReceipt, ReceiptInput, parse_receipt};
pub use reconcile::{
    ReconciliationResult, ReconciliationRpc, StellarReconciliationRpc, TransactionObservation,
    TransactionStatus, reconcile_transaction,
};
pub use service::{
    ApprovalDisposition, AuthorizationPreview, AuthorizationStatusView, AuthorizedCharge,
    WithheldCharge, authorization_status, commit_authorization, persist_prepared_authorization,
    verify_pending_approval,
};
pub use sponsored::{
    PreparedSponsoredCharge, SponsoredRpc, StellarSponsoredRpc, commit_sponsored, prepare_sponsored,
};
pub use state::{
    AuthorizationRecord, AuthorizationStatus, HostObservation, LedgerOutcome,
    authorization_fingerprint,
};
pub use store::MppAuthorizationStore;

/// Supported MPP payment method.
pub const STELLAR_METHOD: &str = "stellar";

/// Supported MPP intent.
pub const CHARGE_INTENT: &str = "charge";

/// Only network enabled for MPP in the alpha release.
pub const TESTNET_NETWORK: &str = "stellar:testnet";

/// Released TypeScript SDK used for conformance fixtures.
pub const MPP_TYPESCRIPT_SDK_PIN: &str = "@stellar/mpp@0.7.1";
