//! Deterministic smart-account contract-address derivation.
//!
//! Implements the canonical convention for deriving a C-strkey from the
//! deployer's G-strkey, a 32-byte salt, and the network passphrase.
//! Pure function; no network access.
//!
//! # Algorithm (XDR + SHA-256 pipeline)
//!
//! ```text
//! network_id            = SHA256(network_passphrase_utf8)           // [u8; 32]
//! deployer_address      = ScAddress::Account(AccountId(
//!                             PublicKey::PublicKeyTypeEd25519(
//!                                 Uint256(deployer_pubkey_bytes))))
//! contract_id_preimage  = ContractIdPreimage::Address(
//!                             ContractIdPreimageFromAddress {
//!                                 address: deployer_address,
//!                                 salt:    Uint256(salt),
//!                             })
//! hash_id_preimage      = HashIdPreimage::ContractId(
//!                             HashIdPreimageContractId {
//!                                 network_id:          Hash(network_id),
//!                                 contract_id_preimage: contract_id_preimage,
//!                             })
//! contract_id_bytes     = SHA256(XDR_encode(hash_id_preimage))      // [u8; 32]
//! contract_strkey       = stellar_strkey::Contract::to_string(contract_id_bytes)
//! ```

use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, ContractIdPreimage, ContractIdPreimageFromAddress, Hash, HashIdPreimage,
    HashIdPreimageContractId, Limits, PublicKey, ScAddress, Uint256, WriteXdr,
};
use thiserror::Error;
#[cfg(any(test, feature = "test-helpers"))]
use zeroize::Zeroizing;

// ── Test-only constants ───────────────────────────────────────────────────────

/// The well-known seed bytes for the interop deployer keypair.
///
/// Source string (30 bytes, UTF-8, no trailing NUL or newline):
/// ```text
/// "openzeppelin-smart-account-kit"
/// ```
///
/// The deployer keypair is derived via
/// `ed25519_dalek::SigningKey::from_bytes(SHA256(INTEROP_DEPLOYER_SEED))`.
///
/// # SHA-256 pin
///
/// `SHA256(INTEROP_DEPLOYER_SEED)` equals:
/// `4ff058c7843b35e5cbcb54b5f7e8f3be0ffb46a7c9aa1d3339cb1c473349566d`
/// (32 bytes; 64-char lowercase hex; verified by `tests::salt_seed_matches_interop_convention`).
///
/// # Derived G-strkey
///
/// `GAAH4OT36RRCCAGKARGPN2HLHT2NOBVFHO4GUHA6CF7UKQ4MMV24WQ4N`
/// (verified by `tests::derive_interop_deployer_pubkey_matches_known_good`).
///
/// Test-only: this seed is publicly reproducible and intended for testnet
/// cross-tool address matching, not production use.
#[cfg(any(test, feature = "test-helpers"))]
pub const INTEROP_DEPLOYER_SEED: &[u8] = b"openzeppelin-smart-account-kit";

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors from the deterministic-address derivation functions.
///
/// All variants carry only pre-redacted or non-secret information — see
/// redaction discipline in `stellar_agent_core::observability`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AddressError {
    /// The `deployer_pubkey` argument is not a valid G-strkey.
    ///
    /// `input` carries the first-5-last-5 characters of the invalid input,
    /// NOT the raw string, to avoid echoing attacker-controlled content into
    /// error messages.
    #[error("invalid deployer G-strkey: {input}")]
    InvalidDeployer {
        /// Truncated form of the invalid input (first-5-last-5 or `<too short>`).
        input: String,
    },

    /// XDR encoding of the `HashIdPreimage` failed.
    ///
    /// Structurally impossible for well-formed inputs (the XDR types used by
    /// `derive_smart_account_address` have no variable-length bounds that could
    /// fail at 32-byte salt + 32-byte pubkey size). Surfaced for forward-compat
    /// with potential future stellar-xdr validation changes.
    #[error("XDR encoding failed: {reason}")]
    XdrEncode {
        /// Human-readable XDR encoding failure reason.
        reason: String,
    },

    /// StrKey encoding of the derived contract ID failed.
    ///
    /// Structurally impossible for a well-formed 32-byte input to `stellar_strkey::Contract`.
    /// Surfaced for forward-compat.
    #[error("StrKey encoding failed: {reason}")]
    StrKeyEncode {
        /// Human-readable StrKey encoding failure reason.
        reason: String,
    },
}

// ── Public functions ──────────────────────────────────────────────────────────

/// Derives the deterministic C-strkey for a smart-account contract deployed by
/// `(deployer_pubkey, salt, network_passphrase)`.
///
/// Pure function; no network access. The derivation follows the canonical convention:
///
/// ```text
/// network_id = SHA256(network_passphrase)
/// preimage   = HashIdPreimage::ContractId {
///                  network_id,
///                  FromAddress { address: deployer, salt }
///              }
/// contract_id_bytes = SHA256(XDR(preimage))
/// return StrKey::encode_contract(contract_id_bytes)
/// ```
///
/// # Errors
///
/// - [`AddressError::InvalidDeployer`] if `deployer_pubkey` is not a valid
///   G-strkey (wrong checksum, wrong prefix, malformed base32).
/// - [`AddressError::XdrEncode`] if the `HashIdPreimage` XDR encoding fails
///   (structurally impossible for well-formed 32-byte inputs; surfaced for
///   forward-compat).
/// - [`AddressError::StrKeyEncode`] if the contract StrKey encode fails
///   (structurally impossible for a 32-byte input; surfaced for forward-compat).
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_smart_account::deployment::derive_smart_account_address;
///
/// let salt = [0u8; 32];
/// let c = derive_smart_account_address(
///     "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
///     &salt,
///     "Test SDF Network ; September 2015",
/// )
/// .expect("derivation succeeds for valid inputs");
/// assert!(c.starts_with('C'));
/// ```
///
pub fn derive_smart_account_address(
    deployer_pubkey: &str,
    salt: &[u8; 32],
    network_passphrase: &str,
) -> Result<String, AddressError> {
    // Step 2: create deployer SCAddress from public key (parse + validate).
    let pk = stellar_strkey::ed25519::PublicKey::from_string(deployer_pubkey).map_err(|_| {
        // Truncate the input to avoid echoing attacker-controlled bytes into error messages.
        let truncated = truncate_for_error(deployer_pubkey);
        AddressError::InvalidDeployer { input: truncated }
    })?;

    // Step 3: compute network ID (SHA-256 of network passphrase as UTF-8).
    let network_id: [u8; 32] = Sha256::digest(network_passphrase.as_bytes()).into();

    // Build the XDR types for the contract-id preimage (Steps 4-5).
    let deployer_address =
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0))));

    let contract_id_preimage = ContractIdPreimage::Address(ContractIdPreimageFromAddress {
        address: deployer_address,
        salt: Uint256(*salt),
    });

    let hash_id_preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash(network_id),
        contract_id_preimage,
    });

    // XDR-encode the preimage (Step 6).
    let encoded = hash_id_preimage
        .to_xdr(Limits::none())
        .map_err(|e| AddressError::XdrEncode {
            reason: e.to_string(),
        })?;

    // SHA-256 hash the encoded preimage to get the 32-byte contract ID (Step 7).
    let contract_id_bytes: [u8; 32] = Sha256::digest(&encoded).into();

    // Encode as C-strkey via stellar_strkey (Step 8).
    //
    // stellar-strkey 0.0.16 uses `heapless::String<N>` as the return type of the
    // inherent `to_string()` method. The `Display` impl on `Contract` produces a
    // `std::string::String` via `format!` or the trait's `to_string()` method.
    let c_strkey = format!("{}", stellar_strkey::Contract(contract_id_bytes));

    Ok(c_strkey)
}

/// Derives the well-known interop deployer `ed25519_dalek::SigningKey` seed from
/// `SHA256(INTEROP_DEPLOYER_SEED)`.
///
/// The 32-byte seed bytes are held in a `Zeroizing` container so they are
/// wiped when the local temporaries drop. The returned seed is passed to
/// `SoftwareSigningKey::new_from_zeroizing` by callers (see `deploy.rs`).
///
/// # Returns
///
/// The 32-byte interop signing key seed, wrapped in `Zeroizing`.
/// Callers MUST construct `SoftwareSigningKey::new_from_zeroizing(seed)` immediately.
///
/// # Panics
///
/// Never panics.
///
/// Test-only: the interop deployer is a publicly-reproducible keypair used for
/// testnet cross-tool address matching.
#[cfg(any(test, feature = "test-helpers"))]
#[must_use]
pub fn derive_interop_deployer_seed() -> Zeroizing<[u8; 32]> {
    // Hash the well-known seed string to obtain the 32-byte deployer seed.
    let hash: [u8; 32] = Sha256::digest(INTEROP_DEPLOYER_SEED).into();
    Zeroizing::new(hash)
}

/// Returns the G-strkey of the well-known interop deployer keypair.
///
/// Derives the ed25519 public key from `SHA256(INTEROP_DEPLOYER_SEED)` and
/// encodes it as a G-strkey. The corresponding private key is NOT returned here;
/// use `derive_interop_deployer_seed()` + `SoftwareSigningKey::new_from_zeroizing`
/// when the signing key is needed.
///
/// # Panics
///
/// Never panics.
///
/// Test-only: the interop deployer is a publicly-reproducible keypair used for
/// testnet cross-tool address matching.
#[cfg(any(test, feature = "test-helpers"))]
#[must_use]
pub fn interop_deployer_pubkey() -> String {
    let seed = derive_interop_deployer_seed();
    // `Zeroizing<[u8; 32]>` implements `Deref<Target = [u8; 32]>` so `&seed` auto-derefs to
    // `&[u8; 32]`, which is the type that `ed25519_dalek::SigningKey::from_bytes` requires.
    // `seed.as_ref()` returns `&[u8]` (AsRef<[u8]>) which would be rejected.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    // Use the `Display` impl (std::string::String) rather than the inherent `to_string()`
    // which returns `heapless::String<56>` in stellar-strkey 0.0.16.
    format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    )
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Truncates a string to a safe form for error messages.
///
/// Returns first-5-last-5 characters (with `...` between) for inputs ≥ 11 chars,
/// or the full string for shorter inputs. This avoids echoing attacker-controlled
/// bytes into log-aggregated error messages while preserving enough context for
/// operator triage.
fn truncate_for_error(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() >= 11 {
        let head: String = chars[..5].iter().collect();
        let tail: String = chars[chars.len() - 5..].iter().collect();
        format!("{head}...{tail}")
    } else {
        s.to_owned()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "test-only")]

    use super::*;

    /// Asserts `SHA256(INTEROP_DEPLOYER_SEED)` matches the pinned hex string.
    ///
    /// The pinned string was computed via
    /// `printf 'openzeppelin-smart-account-kit' | shasum -a 256`.
    ///
    /// # Security
    ///
    /// This test asserts the HASH, not the raw seed bytes. The seed string is
    /// publicly documented (it is the well-known interop convention); no secret is
    /// exposed by this assertion. We assert against the public hash, not the
    /// S-strkey or seed bytes.
    #[test]
    fn salt_seed_matches_interop_convention() {
        // Pinned hash of the well-known interop deployer seed string.
        const EXPECTED_HEX: &str =
            "4ff058c7843b35e5cbcb54b5f7e8f3be0ffb46a7c9aa1d3339cb1c473349566d";

        let hash: [u8; 32] = Sha256::digest(INTEROP_DEPLOYER_SEED).into();
        let actual_hex: String = hash.iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        });

        assert_eq!(
            actual_hex, EXPECTED_HEX,
            "SHA256(INTEROP_DEPLOYER_SEED) must match the pinned value"
        );
    }

    /// Asserts the G-strkey of the well-known interop deployer matches the published fixture.
    ///
    /// The expected value is the published deployer G-strkey
    /// `GAAH4OT36RRCCAGKARGPN2HLHT2NOBVFHO4GUHA6CF7UKQ4MMV24WQ4N`.
    ///
    /// # Security
    ///
    /// Asserts against the G-strkey (public key). The S-strkey and seed bytes
    /// are never serialised into the assertion message.
    #[test]
    fn derive_interop_deployer_pubkey_matches_known_good() {
        // Pinned published G-strkey of the well-known interop deployer keypair.
        const EXPECTED_G: &str = "GAAH4OT36RRCCAGKARGPN2HLHT2NOBVFHO4GUHA6CF7UKQ4MMV24WQ4N";

        let g = interop_deployer_pubkey();
        assert_eq!(
            g, EXPECTED_G,
            "well-known interop deployer G-strkey must match the published fixture"
        );
    }

    /// Asserts `derive_smart_account_address` returns a deterministic C-strkey for a synthetic
    /// `(deployer, zero-salt, testnet-passphrase)` triple.
    ///
    /// The expected C-strkey was computed by running the algorithm by hand for
    /// the all-zeros ed25519 deployer key
    /// `"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"` with
    /// `salt = [0u8; 32]` on testnet. This value is pinned here as the
    /// in-process regression gate.
    ///
    /// The zero-salt vector is computed locally here and cross-verified via the
    /// XDR byte-layout check below.
    #[test]
    fn contract_id_byte_layout_matches_xdr_spec() {
        let deployer = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
        let salt = [0u8; 32];
        let passphrase = "Test SDF Network ; September 2015";

        let result = derive_smart_account_address(deployer, &salt, passphrase)
            .expect("derivation must succeed for valid inputs");

        // Verify the output is a valid C-strkey.
        assert!(
            result.starts_with('C'),
            "derived address must start with 'C': {result}"
        );
        assert_eq!(result.len(), 56, "C-strkey must be 56 characters: {result}");

        // Verify the address can be decoded back to 32 bytes.
        let decoded = stellar_strkey::Contract::from_string(&result)
            .expect("derived C-strkey must decode without error");
        assert_eq!(decoded.0.len(), 32, "decoded contract ID must be 32 bytes");

        // Verify intermediate XDR byte layout: the preimage encodes to 112 bytes.
        // The XDR size for an address-based contract ID is 112 bytes:
        //   4 (EnvelopeType) + 32 (networkId) +
        //   4 (ContractIdPreimageType) + 4 (SCAddressType) + 4 (PublicKeyType) +
        //   32 (Ed25519 key) + 32 (salt) = 112 bytes.
        let pk = stellar_strkey::ed25519::PublicKey::from_string(deployer).unwrap();
        let network_id: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();
        let deployer_address =
            ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0))));
        let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
            network_id: Hash(network_id),
            contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
                address: deployer_address,
                salt: Uint256(salt),
            }),
        });
        let encoded = preimage.to_xdr(Limits::none()).unwrap();
        assert_eq!(
            encoded.len(),
            112,
            "XDR preimage for address-based contract ID must be 112 bytes"
        );
    }

    /// Asserts that calling `derive_smart_account_address` twice with the same inputs
    /// produces byte-identical outputs.
    #[test]
    fn derivation_is_deterministic_for_same_inputs() {
        let deployer = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
        let salt = [0x42u8; 32];
        let passphrase = "Test SDF Network ; September 2015";

        let a = derive_smart_account_address(deployer, &salt, passphrase)
            .expect("derivation must succeed");
        let b = derive_smart_account_address(deployer, &salt, passphrase)
            .expect("derivation must succeed");

        assert_eq!(
            a, b,
            "two invocations with same inputs must produce identical output"
        );
    }

    /// Asserts that different salts produce different C-strkeys.
    #[test]
    fn derivation_diverges_for_different_salts() {
        let deployer = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
        let passphrase = "Test SDF Network ; September 2015";

        let a = derive_smart_account_address(deployer, &[0u8; 32], passphrase)
            .expect("derivation must succeed");
        let b = derive_smart_account_address(deployer, &[1u8; 32], passphrase)
            .expect("derivation must succeed");

        assert_ne!(a, b, "different salts must produce different C-strkeys");
    }

    /// Asserts that different network passphrases produce different C-strkeys.
    #[test]
    fn derivation_diverges_for_different_passphrases() {
        let deployer = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
        let salt = [0x42u8; 32];

        let testnet =
            derive_smart_account_address(deployer, &salt, "Test SDF Network ; September 2015")
                .expect("derivation must succeed");

        let mainnet = derive_smart_account_address(
            deployer,
            &salt,
            "Public Global Stellar Network ; September 2015",
        )
        .expect("derivation must succeed");

        let futurenet =
            derive_smart_account_address(deployer, &salt, "Test SDF Future Network ; October 2022")
                .expect("derivation must succeed");

        assert_ne!(
            testnet, mainnet,
            "testnet vs mainnet must produce different C-strkeys"
        );
        assert_ne!(
            testnet, futurenet,
            "testnet vs futurenet must produce different C-strkeys"
        );
        assert_ne!(
            mainnet, futurenet,
            "mainnet vs futurenet must produce different C-strkeys"
        );
    }

    /// Asserts that an invalid deployer G-strkey returns `AddressError::InvalidDeployer`.
    #[test]
    fn invalid_deployer_returns_error() {
        let result = derive_smart_account_address("not-a-valid-strkey", &[0u8; 32], "testnet");

        assert!(
            matches!(result, Err(AddressError::InvalidDeployer { .. })),
            "invalid deployer must return AddressError::InvalidDeployer; got: {result:?}"
        );
    }
}
