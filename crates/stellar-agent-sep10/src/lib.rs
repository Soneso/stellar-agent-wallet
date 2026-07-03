//! SEP-10 Stellar Web Authentication client.
//!
//! Implements the client side of
//! [SEP-10 Stellar Web Authentication](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0010.md)
//! version 3.4.1.
//!
//! ## What this crate does
//!
//! - [`Challenge`] — parsed and fully-validated SEP-10 challenge transaction.
//!   [`Challenge::parse_and_validate`] performs the complete 13-point validation.
//!   Fail-closed on every check.
//! - [`Sep10Session`] — JWT session holder with decoded claims (`sub`, `iss`,
//!   `iat`, `exp`, `client_domain`). [`Sep10Session::parse`] hand-rolls JWT
//!   segment splitting + base64-url decode + `serde_json` claim extraction.
//!   The JWT signature is NOT verified — the server-issued JWT is trusted via TLS;
//!   see [`Sep10Session::parse`] for the rationale.
//! - [`Sep10Client`] + [`ChallengeRequest`] — async HTTP client:
//!   [`Sep10Client::fetch_challenge`] GET + [`Sep10Client::submit_signed_challenge`] POST.
//! - [`ephemeral::auth_with_ephemeral_key`] — per-request ephemeral ed25519
//!   keypair flow. Generates a fresh `ed25519_dalek::SigningKey` per call via
//!   `rand_core::OsRng`; the key is zeroized on drop.
//!
//! ## Module overview
//!
//! | Module | Contents |
//! |---|---|
//! | [`error`] | [`Sep10Error`] typed error enum + `wire_code()` |
//! | [`challenge`] | [`Challenge`] type + 13-point validation |
//! | [`session`] | [`Sep10Session`] JWT holder + claim accessors |
//! | [`client`] | [`Sep10Client`] HTTP client |
//! | [`ephemeral`] | per-request ephemeral-key signing flow |

pub mod challenge;
pub mod client;
pub mod ephemeral;
pub mod error;
pub mod session;

pub use challenge::Challenge;
pub use client::{ChallengeRequest, Sep10Client};
pub use error::Sep10Error;
pub use session::Sep10Session;
