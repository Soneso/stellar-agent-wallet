//! SEP-5 / BIP-44 HD-path key derivation for the Stellar agent wallet.
//!
//! ## What this crate does
//!
//! Deterministic derivation of ed25519
//! Stellar keypairs along the BIP-44 path `m/44'/148'/index'` using
//! SLIP-0010 hardened child-key derivation.  Input is a BIP-39 mnemonic phrase
//! (with optional passphrase) or a pre-computed 64-byte BIP-39 seed.  Output
//! is a [`DerivedAccount`] that exposes the `G...` public key freely and
//! wraps the 32-byte secret seed in a [`secrecy::SecretBox`].
//!
//! ## What this crate does NOT do
//!
//! - Mnemonic generation (derivation from an existing phrase only).
//! - Non-hardened derivation (ed25519 SLIP-0010 is hardened-only; the API
//!   does not expose a path to derive non-hardened children).
//! - Any network I/O, file I/O, or random number generation.
//! - MCP tools or CLI commands (pure local-derivation substrate).

pub mod account;
pub mod error;
mod slip10;
pub mod wallet;

pub use account::DerivedAccount;
pub use error::DeriveError;
pub use wallet::Sep5Wallet;
