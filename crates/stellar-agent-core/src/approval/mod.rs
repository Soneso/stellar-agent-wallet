//! Wallet-owned approval spine: storage and cryptographic substrate.
//!
//! Provides the `stellar-agent approve --id <nonce> --profile <name>` CLI half and the MCP
//! commit-path verifier.  Supports a kinded approval shape:
//! `PaymentSimulated`, `TrustlineSimulated`, `ClaimSimulated`, `SignWithPasskey`, `RegisterPasskey`,
//! `ToolsetFirstInvokeGate`, `TrustlineClawbackOptIn`, `RuleProposalSimulated`,
//! `MppChargeSimulated`, `Rejected` and `Consumed`.
//!
//! # Security posture
//!
//! Three properties:
//!
//! 1. **Keyring-holder attestation, NOT user-attestation.** The attestation
//!    key lives in the platform keyring (macOS Keychain / Linux Secret Service).
//!    Approving `stellar-agent approve --id <nonce> --profile <name>` proves that the keyring
//!    holder (the wallet owner) ran the approve command — not that a
//!    human clicked "yes" in the agent UI.  The UI rendering at step 3 of
//!    the flow is agent-controlled; the wallet-controlled rendering at step 4
//!    (`stellar-agent approve`) is the binding attestation.
//!
//! 2. **Cross-account-on-host non-replay.** The HMAC input binds
//!    `process_uid_for_attestation()` (numeric UID on Unix).  An attestation
//!    blob minted by user 1000 cannot be replayed by user 2000, even on the
//!    same host.
//!
//! 3. **No multi-process isolation.** The pending-approvals store is a TOML
//!    file on disk.  An attacker with write access to that file can remove
//!    entries (forcing re-approval), but cannot forge an attestation blob
//!    because the HMAC key lives only in the keyring.
//!
//! # Indistinguishability boundary
//!
//! This internal layer DOES distinguish `Expired`, `NotFound`, and
//! `AlreadyAttested`.  The MCP `_commit` boundary collapses all three to the
//! single wire code `policy.approval_required` (indistinguishability
//! invariant).  Internal `tracing::debug!` distinguishes for operator
//! forensics.
//!
//! # File lock discipline
//!
//! [`PendingApprovalStore::open`] acquires an exclusive advisory lock on a
//! sidecar `<profile>.toml.lock` file via [`std::fs::File::try_lock`] (stable
//! Rust 1.89).  The lock is held for the lifetime of the store and released on
//! `Drop`.  A second opener on the same path returns
//! [`ApprovalError::WriterLocked`] immediately.
//!
//! # Integration consumers
//!
//! - **CLI** `stellar-agent approve --id <nonce> --profile <name>`: loads the store, renders
//!   the wallet-controlled summary, reads y/n from tty, calls
//!   [`PendingApprovalStore::record_attestation`] on approval.
//! - **MCP `_commit` verifier**: calls [`verify_attestation`] with the
//!   caller-supplied `attestation_blob` under the layout the record stores,
//!   then collapses any error to `policy.approval_required`.
//! - **Mainnet consent**: [`presence`](crate::approval::presence) issues a WebAuthn challenge for a
//!   pending entry and verifies the assertion against the credential keys of
//!   the owner-signed mainnet policy; the attester records a version 5
//!   attestation bound to the retained receipt.
//! - **Mainnet proof**: [`witness::verify_approval`](crate::approval::witness::verify_approval)
//!   loads the record and the key itself, accepts only a version 5
//!   attestation with a mainnet passkey approver, reads the current signed
//!   policy through [`presence_policy`](crate::approval::presence_policy), and verifies the stored assertion
//!   again under it.
//! - **Bridge POST handler**: calls
//!   [`PendingApprovalStore::record_passkey_assertion`] after verifying the
//!   WebAuthn assertion from the browser ceremony.

pub mod assertion_input;
pub mod attest;
pub mod attestation;
mod context;
pub mod error;
#[cfg(any(test, feature = "test-helpers"))]
pub mod fixtures;
#[cfg(any(test, feature = "test-helpers"))]
pub mod mainnet_fixtures;
pub mod mpp;
pub mod operator_credentials;
pub mod presence;
pub mod presence_policy;
pub mod registration_input;
pub mod remote_authorization;
pub mod retry;
pub mod rule_proposal;
pub mod store;
pub mod subject;
pub mod toolset_grant;
pub mod user_id;
pub mod view;
pub mod webauthn;
pub mod witness;

pub use assertion_input::AssertionInput;
pub use attest::{
    ConsentAudit, ConsentAuthorization, Surface, ToolsetGrantRequest, attest_and_persist,
    attest_mainnet_confirmation, classic_entry_summary, decode_sha256_hex, load_and_validate_entry,
    load_attestation_key,
};
pub use attestation::AttestationBinding;
pub use attestation::{
    ATTESTATION_VERSION, ATTESTATION_VERSION_V2, AttestationScope, AttestedApprover,
    AttestedLifetime, MAINNET_ATTESTATION_VERSION, PENDING_ATTESTATION_VERSION,
    RULE_PROPOSAL_DOMAIN_TAG, TOOLSET_GATE_DOMAIN_TAG, TRUSTLINE_CLAWBACK_OPT_IN_DOMAIN_TAG,
    compute_attestation, compute_attestation_v4, compute_attestation_v5,
    compute_rule_proposal_digest, compute_toolset_gate_digest,
    compute_trustline_clawback_opt_in_digest, envelope_sha256, verify_attestation,
    verify_toolset_gate_attestation,
};
pub use context::{ApprovalContext, approve_hint};
pub use error::ApprovalError;
pub use operator_credentials::{
    OperatorApprovalCredential, OperatorApprovalCredentialStore,
    default_operator_approval_credentials_path,
};
pub use presence::{
    ApprovalCredentialError, MAINNET_APPROVAL_RP_ID, MainnetApprovalCredential,
    MainnetAssertionWire, MainnetPresenceOptions, MainnetPresenceReceipt, PendingMainnetPresence,
    VerifiedMainnetPresence, issue_mainnet_presence, mainnet_consent_subject,
    mainnet_consent_view_digest, mainnet_presence_origin, verify_mainnet_presence,
};
pub use presence_policy::{CurrentMainnetApprovalPolicy, MainnetApprovalAuthority};
pub use registration_input::RegistrationInput;
pub use remote_authorization::{RemoteApprovalAuthority, RemoteApprovalAuthorization};
pub use retry::{DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, open_with_retry};
pub use rule_proposal::{
    CONTEXT_RULE_PROPOSAL_SNAPSHOT_VERSION, ContextRuleProposalSnapshot,
    DecodedSpendingLimitParams, RuleProposalContextType, RuleProposalPolicy, RuleProposalSigner,
    RuleProposalSignerKind, try_decode_spending_limit_params,
};
pub use store::{
    ApprovalKind, ConsumedOutcome, DEFAULT_TTL_MS, EXPECTED_NONCE_LEN,
    MAINNET_CONFIRMATION_TTL_SECONDS, PendingApproval, PendingApprovalStore, RuleProposalGateError,
    generate_csrf_token, governing_ttl_ms,
};
pub use toolset_grant::{
    GrantQuery, TOOLSET_GRANT_DEFAULT_TTL_MS, ToolsetGrant, ToolsetGrantStore,
    build_attested_grant, default_toolset_grants_path,
};
pub use user_id::{ApproverIdentity, VerifiedPasskeyAssertion, process_uid_for_attestation};
pub use view::{ApprovalSummaryView, PendingApprovalView};
