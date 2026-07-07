//! `DerivedAccount`: the result of a SEP-5 HD-path derivation.
//!
//! Exposes the public key's `G...` strkey freely.  The 32-byte secret seed is
//! reachable only through a `secrecy::SecretBox<[u8; 32]>` accessor so the
//! consumer controls exposure and the key never appears in `Debug` output or
//! error messages.

use ed25519_dalek::SigningKey;
use secrecy::SecretBox;
use stellar_strkey::ed25519::PublicKey as StrkeyPublicKey;
use zeroize::Zeroizing;

/// The result of a single SEP-5 `m/44'/148'/index'` derivation.
///
/// The public key's `G...` Stellar strkey is freely accessible.  The 32-byte
/// ed25519 secret seed is held in a `SecretBox<[u8; 32]>` (zeroize-on-drop,
/// compile-time `Display` ban) and is only accessible via
/// [`DerivedAccount::secret_seed`].
///
/// `Debug` is implemented explicitly and redacts all secret material.
pub struct DerivedAccount {
    /// The ed25519 public key bytes.
    pub_key_bytes: [u8; 32],
    /// The unhardened BIP-44 account index used to derive this keypair.
    index: u32,
    /// The 32-byte ed25519 secret seed, held in a secret-hygiene wrapper.
    secret: SecretBox<[u8; 32]>,
}

impl DerivedAccount {
    /// Construct a `DerivedAccount` from a 32-byte secret seed and its index.
    ///
    /// `seed` is taken by value so its `Zeroizing` drop fires when this
    /// function returns, clearing the caller's stack copy.  The bytes are
    /// copied into a `SecretBox` which zeroes the heap allocation on drop.
    ///
    /// A 32-byte slice is always a valid ed25519 seed for
    /// `SigningKey::from_bytes`, so this constructor is infallible.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn from_secret_seed(seed: Zeroizing<[u8; 32]>, index: u32) -> Self {
        // `from_bytes` takes &[u8; 32]; `Zeroizing<[u8; 32]>` derefs to the array.
        let signing_key = SigningKey::from_bytes(&seed);
        let pub_key_bytes = signing_key.verifying_key().to_bytes();
        // Write the seed straight into the SecretBox's heap allocation so no
        // bare [u8; 32] copy of the secret forms on the stack; `seed` is
        // zeroized when its Zeroizing wrapper drops at end of scope.
        let secret = SecretBox::init_with_mut(|s: &mut [u8; 32]| s.copy_from_slice(&seed[..]));
        Self {
            pub_key_bytes,
            index,
            secret,
        }
    }

    /// The `G...` Stellar strkey for this account's public key.
    ///
    /// This is the canonical representation for displaying or transmitting
    /// the public identity of a derived account.
    #[must_use]
    pub fn public_key_strkey(&self) -> String {
        // stellar-strkey `PublicKey::to_string()` is an inherent method
        // returning `heapless::String<56>`; the `.as_str().to_owned()` chain
        // converts it to a `std::string::String`.
        StrkeyPublicKey(self.pub_key_bytes)
            .to_string()
            .as_str()
            .to_owned()
    }

    /// A reference to the 32-byte ed25519 secret seed inside its secret-hygiene
    /// wrapper.
    ///
    /// The consumer must hold the `SecretBox` for exactly as long as needed and
    /// drop it promptly.  The `S...` strkey can be produced inside the consumer
    /// from the exposed bytes if needed, but should NOT be logged or stored in
    /// plaintext.
    #[must_use]
    pub fn secret_seed(&self) -> &SecretBox<[u8; 32]> {
        &self.secret
    }
}

/// Redacted `Debug` implementation — no secret material.
impl std::fmt::Debug for DerivedAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedAccount")
            .field("index", &self.index)
            .field("public_key", &self.public_key_strkey())
            .field("secret", &"[redacted]")
            .finish()
    }
}
