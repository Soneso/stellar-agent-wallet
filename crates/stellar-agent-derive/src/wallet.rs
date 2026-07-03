//! `Sep5Wallet`: the primary entry point for SEP-5 HD-path derivation.
//!
//! `Sep5Wallet` wraps a 64-byte BIP-39 seed in a `Zeroizing` buffer and
//! exposes a single derivation method.  Construction is either from a BIP-39
//! mnemonic phrase (fallible) or from a pre-computed 64-byte seed (infallible).
//!
//! BIP-44 hardened path `m/44'/148'/<index>'` over SLIP-0010 ed25519.

use bip39::Mnemonic;
use zeroize::Zeroizing;

use crate::account::DerivedAccount;
use crate::error::DeriveError;
use crate::slip10;

/// BIP-44 purpose constant: `44'` (always hardened).
///
/// Source: BIP-0044 §"Purpose"; SEP-5 §"Multi-Account Hierarchy for Deterministic Wallets".
const BIP44_PURPOSE: u32 = 44;

/// Stellar coin-type assigned in SLIP-0044: `148'` (always hardened).
///
/// Source: SEP-5 §"Multi-Account Hierarchy for Deterministic Wallets";
/// SLIP-0044 row for Stellar (coin type 148).
const STELLAR_COIN_TYPE: u32 = 148;

/// An HD wallet seeded from a BIP-39 mnemonic or a pre-computed 64-byte seed.
///
/// The wallet derives Stellar keypairs along the SEP-5 path `m/44'/148'/index'`
/// using SLIP-0010 ed25519 hardened derivation.  Non-hardened paths are
/// structurally impossible through the public API: the only varying input is
/// `index: u32`, which is always hardened before use, and any `index >= 2^31`
/// is rejected with a typed error before the hardening bit is applied.
///
/// ## Note on passphrase coverage
///
/// SEP-5 Test 4 uses a non-empty BIP-39 passphrase (`p4ssphr4se`), exercising
/// the `to_seed_normalized` (NFKD) passphrase path; see `tests/sep5_vectors.rs`.
pub struct Sep5Wallet {
    /// The 64-byte BIP-39 seed, held in a `Zeroizing` buffer.
    ///
    /// `bip39::Mnemonic::to_seed_normalized` does NOT zeroize its return
    /// value; we wrap it immediately.
    seed: Zeroizing<[u8; 64]>,
}

impl Sep5Wallet {
    /// Construct a `Sep5Wallet` from a BIP-39 mnemonic phrase and optional
    /// passphrase.
    ///
    /// The passphrase is normalised to NFKD form via `to_seed_normalized` per
    /// BIP-39 §"Generating the mnemonic".  An empty string `""` is the standard
    /// "no passphrase" value.
    ///
    /// The resulting 64-byte seed is moved into a `Zeroizing` buffer
    /// immediately; `bip39` does NOT zeroize its return value.
    ///
    /// # Errors
    ///
    /// Returns [`DeriveError::InvalidMnemonic`] if the phrase has an invalid
    /// checksum, contains unknown words, or has an unsupported word count.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use stellar_agent_derive::Sep5Wallet;
    /// let wallet = Sep5Wallet::from_mnemonic(
    ///     "illness spike retreat truth genius clock brain pass fit cave bargain toe",
    ///     "",
    /// ).unwrap();
    /// let account = wallet.derive_account(0).unwrap();
    /// assert_eq!(
    ///     account.public_key_strkey(),
    ///     "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6",
    /// );
    /// ```
    pub fn from_mnemonic(phrase: &str, passphrase: &str) -> Result<Self, DeriveError> {
        let mnemonic: Mnemonic = phrase.parse()?;
        // to_seed_normalized returns [u8; 64] without zeroizing; wrap immediately.
        let raw_seed = mnemonic.to_seed_normalized(passphrase);
        let seed = Zeroizing::new(raw_seed);
        Ok(Self { seed })
    }

    /// Construct a `Sep5Wallet` from a `Zeroizing`-wrapped 64-byte BIP-39 seed.
    ///
    /// The wrapper is consumed and its bytes move directly into the wallet's
    /// internal `Zeroizing` storage, so no bare `[u8; 64]` stack temporary forms
    /// that would bypass the zeroize-on-drop guarantee.  Use this when the seed
    /// is already held in a `Zeroizing` buffer (e.g. loaded from the OS keyring).
    ///
    /// When the wallet is subsequently dropped, `self.seed` zeroizes the bytes;
    /// the caller's original `Zeroizing` was consumed (and thus zeroized) on
    /// entry to this constructor.
    ///
    /// # Security
    ///
    /// This is the preferred call site for concurrent derivation from a master
    /// seed: the caller holds a `Zeroizing<[u8; 64]>` and passes a fresh clone
    /// into each derivation.  Using this constructor prevents the clone from
    /// forming an un-zeroized temporary on the stack.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use stellar_agent_derive::Sep5Wallet;
    /// # use zeroize::Zeroizing;
    /// // The Zeroizing wrapper is consumed; no bare-array temporary forms.
    /// let seed = Zeroizing::new([0u8; 64]);
    /// let wallet = Sep5Wallet::from_bip39_seed_zeroizing(seed);
    /// assert!(wallet.derive_account(0).is_ok());
    /// ```
    pub fn from_bip39_seed_zeroizing(seed: Zeroizing<[u8; 64]>) -> Self {
        Self { seed }
    }

    /// Derive the Stellar keypair at `m/44'/148'/index'`.
    ///
    /// `index` is the **unhardened** BIP-44 account number (0, 1, 2, …).
    /// The guard against `index >= 2^31` fires BEFORE the hardening bit is
    /// applied, so there is no ambiguity between the logical account number and
    /// the on-wire hardened index.
    ///
    /// All three path segments (`44'`, `148'`, `index'`) are derived with
    /// hardened child-key derivation.  Intermediate `ExtendedKey` values are
    /// zeroized after each fold.
    ///
    /// # Errors
    ///
    /// Returns [`DeriveError::IndexOutOfRange`] when `index >= 2_147_483_648`
    /// (2^31).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use stellar_agent_derive::Sep5Wallet;
    /// let wallet = Sep5Wallet::from_mnemonic(
    ///     "illness spike retreat truth genius clock brain pass fit cave bargain toe",
    ///     "",
    /// ).unwrap();
    /// // Derive account 0 — primary key per SEP-5.
    /// let account = wallet.derive_account(0).unwrap();
    /// assert_eq!(
    ///     account.public_key_strkey(),
    ///     "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6",
    /// );
    /// ```
    pub fn derive_account(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        // Index guard FIRST, on the unhardened account number.
        // The hardened child number is `index | 0x80000000`; this is only
        // unambiguous when `index < 2^31`.
        if index >= 0x8000_0000 {
            return Err(DeriveError::IndexOutOfRange { index });
        }

        // Clone the seed into a local Zeroizing buffer so `master_key` can
        // take ownership (and zeroize the local copy on drop) without
        // consuming `self.seed`.
        let seed_copy = Zeroizing::new(*self.seed);

        // Master key: m
        let master = slip10::master_key(seed_copy);

        // m/44' — purpose
        let purpose = slip10::hardened_child(master, BIP44_PURPOSE);

        // m/44'/148' — coin type (Stellar)
        let coin = slip10::hardened_child(purpose, STELLAR_COIN_TYPE);

        // m/44'/148'/index' — account
        let account_key = slip10::hardened_child(coin, index);

        Ok(DerivedAccount::from_secret_seed(account_key.key, index))
    }
}

/// Redacted `Debug` — the seed is never printed.
impl std::fmt::Debug for Sep5Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sep5Wallet")
            .field("seed", &"[redacted]")
            .finish()
    }
}
