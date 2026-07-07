//! SLIP-0010 ed25519 master-key generation and hardened child-key derivation.
//!
//! This module implements the ed25519 curve section of SLIP-0010 as required
//! by SEP-5.  ed25519 supports **hardened derivation only**; there is no
//! key-validity retry step (that step is secp256k1 / NIST P-256 specific).
//!
//! ## Byte layout
//!
//! - **Master key**: `(key, chain_code) = HMAC-SHA512(key="ed25519 seed", data=seed)`.
//!   Source: SLIP-0010 §"Master key generation", ed25519 row.
//!
//! - **Hardened child**: `I = HMAC-SHA512(key=chain_code_par, data = 0x00 || key_par(32 bytes) || ser32(i))`
//!   with `i = index | 0x80000000`, `ser32` big-endian 4-byte.
//!   Source: SLIP-0010 §"Private parent key → private child key", ed25519 (hardened-only) row.
//!
//! - **No key-validity retry**: SLIP-0010 specifies the retry loop
//!   (`if parse256(I_L) >= n or k_i == 0`) **only** for secp256k1 and NIST-P256.
//!   For ed25519 the 32-byte HMAC left-half is accepted unconditionally as the
//!   child secret seed.  Do NOT add a retry.
//!
//! ## Zeroization
//!
//! At each fold iteration the HMAC-SHA512 output is written directly into a
//! `Zeroizing<[u8; 64]>` buffer via `FixedOutput::finalize_into`; no
//! un-zeroized 64-byte copy of the intermediate `I` value ever exists on the
//! stack.  The buffer zeroizes on drop immediately after `split_i` copies its
//! halves into the returned `ExtendedKey`.  The caller-supplied BIP-39 seed is
//! accepted as `Zeroizing<[u8; 64]>` so it is also zeroed on drop.

use hmac::{
    Hmac, KeyInit, Mac,
    digest::{FixedOutput, array::Array},
};
use sha2::Sha512;
use zeroize::Zeroizing;

/// HMAC-SHA512 salt for the SLIP-0010 ed25519 master-key step.
///
/// Source: SLIP-0010 §"Master key generation", ed25519 row — the curve key
/// is the UTF-8 string `"ed25519 seed"`.
const SLIP10_ED25519_SEED_KEY: &[u8] = b"ed25519 seed";

/// The BIP-32 / SLIP-0010 hardened-offset constant (2^31).
///
/// Source: SLIP-0010 §"Private parent key → private child key";
/// BIP-32 §"Child key derivation (CKD) functions".
const BIP32_HARDENED_OFFSET: u32 = 0x8000_0000;

/// A SLIP-0010 extended private key: 32-byte secret + 32-byte chain code.
///
/// Both halves are held in `Zeroizing` wrappers and zeroed on drop.
/// Splitting is done from the 64-byte HMAC-SHA512 output, which is itself
/// zeroized after the split.
pub(crate) struct ExtendedKey {
    /// The 32-byte ed25519 secret seed (left half of the HMAC output).
    pub(crate) key: Zeroizing<[u8; 32]>,
    /// The 32-byte chain code (right half of the HMAC output).
    pub(crate) chain_code: Zeroizing<[u8; 32]>,
}

/// Derive the SLIP-0010 master extended key from a 64-byte BIP-39 seed.
///
/// `seed` is taken by value so the caller relinquishes ownership and its
/// `Zeroizing` drop fires when this function returns.
///
/// # Algorithm
///
/// `(key, chain_code) = HMAC-SHA512(key="ed25519 seed", data=seed)`
///
/// Source: SLIP-0010 §"Master key generation", ed25519 row.
///
/// # Panics
///
/// This function cannot panic: `SLIP10_ED25519_SEED_KEY` is a non-empty
/// static byte string that satisfies `Hmac::<Sha512>::new_from_slice`'s
/// length precondition for all non-empty keys.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn master_key(seed: Zeroizing<[u8; 64]>) -> ExtendedKey {
    // SLIP10_ED25519_SEED_KEY is a non-empty static byte string (12 bytes);
    // Hmac::new_from_slice fails only on zero-length keys, which is impossible
    // here.  The #[allow] is intentional (provably infallible).
    #[allow(clippy::expect_used)]
    let mut mac = Hmac::<Sha512>::new_from_slice(SLIP10_ED25519_SEED_KEY)
        .expect("SLIP10_ED25519_SEED_KEY is a non-empty static key");
    mac.update(seed.as_ref());
    // Write the HMAC output directly into a Zeroizing buffer; no un-zeroized
    // copy of the 64-byte intermediate ever exists on the stack.
    // Array<u8, U64> is repr(transparent) over [u8; 64]; the cast is sound.
    let mut i = Zeroizing::new([0u8; 64]);
    FixedOutput::finalize_into(mac, Array::cast_from_core_mut(&mut i));
    let out = split_i(&i);
    // `i` drops here, zeroizing the HMAC output bytes.
    out
}

/// Derive a hardened child extended key from a parent extended key and index.
///
/// `index` is the **unhardened** BIP-44 account number (`0`, `1`, `2`, …).
/// The hardened child number is `index | 0x80000000`; the guard against
/// `index >= 2^31` fires before this function is called, in
/// [`crate::wallet::Sep5Wallet::derive_account`].
///
/// # Algorithm
///
/// ```text
/// data    = 0x00 || key_par(32 bytes) || ser32(index | 0x80000000)
/// I       = HMAC-SHA512(key=chain_code_par, data=data)
/// (key, chain_code) = (I[0..32], I[32..64])
/// ```
///
/// Source: SLIP-0010 §"Private parent key → private child key", ed25519 row.
/// `ser32` is big-endian 4-byte, offset 33 in the preimage.
///
/// # No key-validity retry
///
/// SLIP-0010 specifies a retry loop for secp256k1/NIST-P256 when
/// `parse256(I_L) >= curve_order` or the derived key is zero.
/// For ed25519, the HMAC output is used unconditionally; no retry.
///
/// # Zeroization
///
/// The 37-byte preimage buffer zeroizes on drop.  The HMAC output is written
/// directly into a `Zeroizing<[u8; 64]>` buffer and zeroizes on drop after
/// `split_i` copies out the key halves.  The parent `ExtendedKey` is consumed
/// and its fields zeroize when it drops.
///
/// # Panics
///
/// Cannot panic: `parent.chain_code` is always 32 bytes, which satisfies
/// `Hmac::<Sha512>::new_from_slice`'s non-empty key precondition.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn hardened_child(parent: ExtendedKey, index: u32) -> ExtendedKey {
    // Preimage: 0x00 || 32-byte key || 4-byte ser32(i)  — 37 bytes total.
    // Source: SLIP-0010 §"Private parent key → private child key".
    let mut data = Zeroizing::new([0u8; 37]);
    // data[0] = 0x00 (already zero-initialised)
    // data[1..33] = key_par
    data[1..33].copy_from_slice(parent.key.as_ref());
    // data[33..37] = ser32(index | BIP32_HARDENED_OFFSET), big-endian.
    let hardened_index = index | BIP32_HARDENED_OFFSET;
    data[33..37].copy_from_slice(&hardened_index.to_be_bytes());

    // chain_code is always 32 bytes (set via copy_from_slice from a 64-byte
    // HMAC output in the previous fold); Hmac::new_from_slice fails only on
    // zero-length keys, which is impossible here.
    // The #[allow] is intentional (provably infallible).
    #[allow(clippy::expect_used)]
    let mut mac = Hmac::<Sha512>::new_from_slice(parent.chain_code.as_ref())
        .expect("chain_code is a 32-byte non-empty key");
    mac.update(data.as_ref());
    // Write the HMAC output directly into a Zeroizing buffer; no un-zeroized
    // copy of the 64-byte intermediate ever exists on the stack.
    // Array<u8, U64> is repr(transparent) over [u8; 64]; the cast is sound.
    let mut i = Zeroizing::new([0u8; 64]);
    FixedOutput::finalize_into(mac, Array::cast_from_core_mut(&mut i));
    let out = split_i(&i);
    // `i` drops here, zeroizing the HMAC output bytes.
    out
}

/// Split a 64-byte HMAC-SHA512 output `I` into `(key=I[0..32], chain_code=I[32..64])`.
///
/// Called at every fold iteration.  The caller holds `i` in a
/// `Zeroizing<[u8; 64]>` buffer that zeroizes on drop after this returns.
fn split_i(i: &[u8; 64]) -> ExtendedKey {
    // Left 32 bytes → key; right 32 bytes → chain_code.
    let mut key = Zeroizing::new([0u8; 32]);
    let mut chain_code = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&i[..32]);
    chain_code.copy_from_slice(&i[32..]);
    ExtendedKey { key, chain_code }
}
