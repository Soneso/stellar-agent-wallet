//! Typed error enum for SEP-5 HD-path key derivation.
//!
//! `DeriveError` is the single error type returned by all fallible operations
//! in this crate.  No variant carries key material; `IndexOutOfRange` carries
//! only the unhardened account index supplied by the caller.

use thiserror::Error;

/// Errors that can occur during SEP-5 HD-path key derivation.
///
/// No variant contains secret key material.  `IndexOutOfRange` records the
/// caller-supplied unhardened account index so the caller can surface a
/// meaningful message without the crate leaking internal state.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DeriveError {
    /// The BIP-39 mnemonic phrase could not be parsed.
    ///
    /// This covers bad checksums, unknown words, and invalid word counts.
    /// No phrase bytes are included in the error message.
    #[error("invalid BIP-39 mnemonic phrase")]
    InvalidMnemonic(#[from] bip39::Error),

    /// The account index is `>= 2^31` and cannot be hardened.
    ///
    /// The BIP-44 / SEP-5 derivation path `m/44'/148'/index'` requires
    /// `index < 2^31` (the hardened child number is `index | 0x80000000`;
    /// for `index >= 2^31` the high bit is already set, making the account
    /// number ambiguous).  Reject before applying the hardening bit.
    ///
    /// The guard fires on the *unhardened* account number, before the
    /// hardening bit is applied.
    #[error("account index {index} is out of range; must be < 2^31 (2_147_483_648)")]
    IndexOutOfRange {
        /// The unhardened account index supplied by the caller.
        index: u32,
    },
}
