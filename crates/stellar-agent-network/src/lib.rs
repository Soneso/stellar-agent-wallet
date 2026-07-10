//! Stellar RPC network client, account query, transaction assembly, and
//! hardware-signing adapter for the Stellar agent wallet.
//!
//! # What this crate does
//!
//! Provides a typed wrapper around `stellar-rpc-client` (`StellarRpcClient`),
//! the account-view projection (`AccountView`, `fetch_account`), transaction
//! assembly (`ClassicOpBuilder`, `builder::Asset`), SEP-29 memo-required
//! enforcement (`sep29`), hardware-signer preparation (`SigningKey`), Friendbot
//! funding (`fund_with_friendbot`), the submission primitive
//! (`submit_transaction_and_wait`), and the idempotent submit wrapper
//! ([`idempotent_submit::submit_transaction_idempotent`]).
//!
//! # Primary consumers
//!
//! - `stellar-agent-cli` — CLI binary; invokes `fetch_account` for the
//!   `balances` command and `submit_transaction_and_wait` for write commands.
//! - `stellar-agent-mcp` — MCP server binary.
//!
//! # Non-goals
//!
//! - This crate does not implement policy evaluation; that lives in
//!   `stellar-agent-core`.
//! - This crate does not speak to the Horizon REST API. All account and
//!   submission traffic goes through Stellar RPC (`getLedgerEntries`,
//!   `sendTransaction`, `getTransaction`).
//! - Smart-account signing flows remain in `stellar-agent-core::smart_account`.
//!
//! # Related crates
//!
//! - `stellar-agent-core` — typed errors, amounts, envelopes.
//! - `stellar-rpc-client` — underlying JSON-RPC transport.
//! - `stellar-baselib` — classic-operation XDR builders.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod account;
pub mod builder;
pub mod client;
pub mod counterparty;
pub mod fee_bump;
pub mod fee_bump_retry;
pub mod fees;
pub mod friendbot;
pub mod idempotent_submit;
pub mod keyring;
pub mod memo;
pub mod policy_state;
pub mod policy_view;
pub mod redact;
pub mod retry;
pub mod sep29;
pub mod signing;
pub mod simulation_audit;
pub mod submit;
pub mod wasm_hash;

pub use counterparty::fetch::build_bounded_https_client;
pub use counterparty::{
    CounterpartyCacheSnapshot, CounterpartyError, CounterpartyKindParseError, CounterpartyResolver,
    MinimalCurrency, MinimalSep1, NoopCounterpartyResolver, StellarTomlBinding,
    StellarTomlResolver, is_valid_ldh_home_domain, parse_minimal_sep1,
};
pub use memo::parse_memo_fields;
pub use redact::{redact_rpc_error, redact_url_authority};

pub use account::{
    AccountView, AssetView, BASE_RESERVE_STROOPS, BalanceView, SignerView, ThresholdsView,
    fetch_account, fetch_data_entry,
};
pub use builder::{Asset, ClassicOpBuilder};
pub use client::StellarRpcClient;
pub use fee_bump::{FeeBumpError, build_and_sign_fee_bump};
pub use fee_bump_retry::submit_fee_bump_idempotent;
#[cfg(any(test, feature = "test-loopback"))]
pub use fees::validate_rpc_url_allowing_loopback;
pub use fees::{
    ALLOWED_RPC_HOSTS, ClassicFeeChoice, ClassicFeeSelection, FeeDistribution, FeePercentile,
    FeeStatsView, RpcUrlError, fetch_fee_stats, parse_classic_fee_choice,
    resolve_classic_fee_selection, validate_rpc_url,
};
pub use friendbot::{
    ALLOWED_FRIENDBOT_HOSTS, FriendbotResult, FriendbotUrlError, default_friendbot_url,
    fund_with_friendbot, redact_url_userinfo, validate_friendbot_url,
};
pub use idempotent_submit::{reconcile_receipt, submit_transaction_idempotent};
pub use keyring::{KeyringSignHandle, init_platform_keyring_store, signer_from_keyring};
pub use retry::RetryPolicy;
pub use signing::source::{signer_from_env, signer_from_ledger};
pub use signing::wallet::signer_from_wallet;
pub use signing::{HardwareSigningKey, Signer, SigningKey, SoftwareSigningKey, WebAuthnAssertion};
pub use simulation_audit::{
    AuthEntryFingerprint, fingerprint_soroban_auth_entries, verify_auth_entries_unchanged,
};
pub use stellar_rpc_client::{GetLedgerEntriesResponse, LedgerEntryResult};
pub use submit::{
    SubmissionResult, SubmissionSignerKind, redact_tx_hash, submit_transaction_and_wait,
};
pub use wasm_hash::{
    FetchContractWasmHashError, WasmHashDivergenceError, WasmHashFetch, fetch_contract_wasm_hash,
};
