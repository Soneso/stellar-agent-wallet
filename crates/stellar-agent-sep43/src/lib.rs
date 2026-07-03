//! SEP-43 v1.2.1 Wallet Protocol — 5-method `ModuleInterface` dispatch
//! substrate for the Stellar agent wallet.
//!
//! # What this crate does
//!
//! Implements the agent-side SEP-43 `ModuleInterface` per
//! [SEP-43 v1.2.1](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0043.md)
//! (method shape and error codes).
//!
//! Provides the dispatch substrate:
//!
//! - [`Sep43Error`] — typed error enum covering all SEP-43 error code groups
//!   (-1 internal, -2 external, -3 client-invalid, -4 user-rejected) per
//!   SEP-43 v1.2.1. Each variant carries a stable
//!   [`Sep43Error::wire_code`] string for audit-log emission and a
//!   [`Sep43Error::to_sep43_response`] JSON serialiser for the spec-compliant
//!   `{ code, message, ext? }` wire shape.
//! - [`ActiveAddressType`] — discriminated union of the three active-address
//!   kinds (`ClassicG`, `SmartAccountC`, `MuxedM`).
//! - [`resolve_active_address`] — resolves the active wallet address from the
//!   profile (the strkey from `mcp_signer_default.account`; G, C, or M).
//! - [`validate_strkey`] — validates an input strkey and returns its kind.
//! - [`ModuleAdapter`] — async trait declaring the 5 SEP-43 method signatures
//!   (`get_address`, `sign_transaction`, `sign_auth_entry`, `sign_message`,
//!   `get_network`).
//! - [`StellarAgentModule`] — concrete implementation of [`ModuleAdapter`] that
//!   dispatches each method through the per-method module files under `module/`.
//!
//! # Primary consumers
//!
//! - `stellar-agent-mcp`: 5 MCP tools
//!   (`stellar_sep43_get_address`, `stellar_sep43_sign_transaction`,
//!   `stellar_sep43_sign_auth_entry`, `stellar_sep43_sign_message`,
//!   `stellar_sep43_get_network`) each dispatch to the corresponding
//!   `StellarAgentModule` method.
//!
//! # What this crate does NOT do
//!
//! - Does NOT implement the optional `submit`/`submitUrl` opts of
//!   `signTransaction` (transactions are returned signed, not submitted).
//! - Does NOT implement multi-signer quorum; the `sign_auth_entry` path signs a
//!   single-signer `HashIdPreimage::SorobanAuthorization` preimage with one
//!   ed25519 G-key and returns the raw signature (the requester assembles the
//!   credentials). The Protocol-23 `SorobanAuthorizationWithAddress` preimage
//!   variant is not supported and is refused.
//! - Does NOT open any HTTP/HTTPS connections (interop is stdio-based via MCP).
//!
//! # Module overview
//!
//! | Module | Contents |
//! |---|---|
//! | [`error`] | [`Sep43Error`] typed error enum + `wire_code()` + `to_sep43_response()` |
//! | [`address`] | [`ActiveAddressType`], [`resolve_active_address`], [`validate_strkey`] |
//! | [`signing`] | Low-level signing dispatch shared by the method modules |
//! | [`module`] | [`ModuleAdapter`] trait + [`StellarAgentModule`] dispatch impl |
//!
//! # Shared SEP-43 error vocabulary
//!
//! `Sep43Error` variants `WalletUnlockFailed`, `XdrSerializationFailed`, and
//! `RpcError` are part of the shared SEP-43 error vocabulary and are actively
//! constructed by the MCP consumer layer when the underlying wallet operation
//! fails.  `KeyringError` and `HorizonError` are defined here so that all
//! SEP-43 error codes originate from a single typed enum; they are reserved for
//! completeness and are not currently constructed by any consumer.  All five
//! variants are intentionally present in this crate and are not dead code.
//!
//! # Reference
//!
//! - SEP-43 v1.2.1 — `ModuleInterface` method shapes and error codes.
//! - Stellar-Wallets-Kit `types/mod.ts` — canonical `ModuleInterface` TypeScript definition.
//! - stellar-xdr `HashIdPreimageSorobanAuthorization` — preimage layout for
//!   `signAuthEntry` payload computation (see `signing.rs`).

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::missing_errors_doc)]
#![deny(clippy::missing_panics_doc)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod address;
pub mod error;
pub mod module;
pub mod signing;

pub use address::{ActiveAddressType, resolve_active_address, validate_strkey};
pub use error::Sep43Error;
pub use module::{ModuleAdapter, StellarAgentModule};
