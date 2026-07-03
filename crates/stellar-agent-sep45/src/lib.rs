//! SEP-45 v0.1.1 Web Authentication for Contract Accounts — challenge
//! validation substrate and JWT session handling.
//!
//! # What this crate does
//!
//! Implements the client-side SEP-45 Web Authentication for Contract Accounts
//! protocol.
//!
//! - [`Sep45Error`] — typed error enum covering all validation failure paths,
//!   each with a stable `wire_code()` string for audit-log emission.
//! - [`AuthorizationEntries`] — parsed and fully-validated SEP-45 challenge
//!   response. [`AuthorizationEntries::parse_and_validate`] enforces
//!   steps 1-12 of the 13-point validation (step 13, footprint, is deferred — it requires
//!   simulation results unavailable at challenge-fetch time). Fail-closed: any
//!   validation step failure returns a typed `Sep45Error`.
//! - [`Sep45Session`] — JWT session holder with decoded claims (`sub`, `iss`,
//!   `iat`, `exp`, `client_domain`). [`Sep45Session::parse`] hand-rolls JWT
//!   segment splitting + base64-url decode + `serde_json` claim extraction —
//!   NO signature verification (spec-compliant: server-issued JWT over HTTPS;
//!   client trusts issuer via TLS).
//! - [`Sep45Client`] — async HTTPS client: `fetch_challenge` GET +
//!   `submit_signed_challenge` POST. HTTPS-only security floor enforced at
//!   the `reqwest` layer.
//! - [`auth_with_ephemeral_key`] — per-request ephemeral ed25519 keypair flow.
//!   Generates a fresh `OsRng`-seeded key, signs the SEP-45 client entry, and
//!   submits the signed entries to obtain a `Sep45Session` JWT. Suitable only
//!   for contracts that accept the ephemeral public key or require no client
//!   signature.
//! - [`sign_authorization_entries`] — signing flow for real, persistent
//!   signer keypairs. Signs the client entry with one or more ed25519 keys
//!   and returns re-encoded XDR for the caller to submit via
//!   [`Sep45Client::submit_signed_challenge`].
//! - [`ChallengeRequest`] — typed request builder for [`auth_with_ephemeral_key`]
//!   and [`Sep45Client::fetch_challenge`].
//!
//! # What this crate does NOT do
//!
//! - Does NOT verify the JWT signature (spec-compliant non-verification;
//!   TLS authenticates the server; documented in [`Sep45Session::parse`]
//!   rustdoc).
//! - Does NOT validate footprint `read_write` keys (requires simulation
//!   results not available without a full contract invocation).
//! - Does NOT access the keyring or the wallet seed (pure decode + validate).
//!
//! # Module overview
//!
//! | Module | Contents |
//! |---|---|
//! | `error` | [`Sep45Error`] typed error enum + `wire_code()` |
//! | `entries` | [`AuthorizationEntries`] type + 13-point validation |
//! | `session` | [`Sep45Session`] JWT holder + claim accessors |
//! | `client` | [`Sep45Client`] async HTTPS client + [`ChallengeRequest`] |
//! | `ephemeral` | [`auth_with_ephemeral_key`] and [`sign_authorization_entries`] |

pub mod client;
pub mod entries;
pub mod ephemeral;
pub mod error;
pub mod session;

pub use client::{ChallengeRequest, Sep45Client};
pub use entries::AuthorizationEntries;
pub use ephemeral::{auth_with_ephemeral_key, sign_authorization_entries};
pub use error::Sep45Error;
pub use session::Sep45Session;
