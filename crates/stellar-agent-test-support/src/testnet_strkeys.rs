//! Testnet strkey synthesis helpers — build structurally valid Stellar
//! strkeys at runtime from a 32-byte seed, used by tests that need canonical
//! strkey input without committing literal strkey strings to source.
//!
//! Secret-key (`S...`) strkey literals must never appear in tracked source, so
//! every caller synthesises the strkey form at test time from disposable seed
//! bytes.
//!
//! # Relation to the oracle validator
//!
//! The synthesiser here and the oracle validator in [`crate::secret_patterns`]
//! (`is_valid_s_strkey`, `base32_decode_56`, `crc16_xmodem`) share a single
//! CRC-16/XMODEM implementation — the one in `secret_patterns.rs` — which
//! this module calls via a `pub(crate)` delegation. The base32 pair, on the
//! other hand, is two genuinely independent code paths: this module's
//! [`base32_encode_35`] uses a byte-for-byte alphabet table (`BASE32_ALPHABET`)
//! and shift-left-by-5 bit ordering; the oracle's `base32_decode_56` uses
//! ASCII range matches (`b'A'..=b'Z'`, `b'2'..=b'7'`) and shift-right-by-5
//! bit ordering. Round-trip tests that synthesise here and validate via the
//! oracle therefore cross-check the alphabet literal and bit ordering on
//! both sides — a drift in either base32 path surfaces as a test failure.
//!
//! CRC drift is impossible because only one CRC implementation exists (shared
//! via the `pub(crate)` delegation above); there is deliberately no second copy
//! to drift against.
//!
//! The independent oracle's hand-rolled validators are retained on purpose:
//! `secret_patterns.rs` does not call `stellar-strkey`, which keeps the oracle
//! independent from the production redactor. Do not replace either side with
//! `stellar-strkey` — that would collapse the oracle into the code it checks.
//!
//! # Version bytes
//!
//! These match the strkey version-byte definitions in `stellar-strkey`. The
//! constants below cover every strkey variant the tests need.

/// Disposable testnet fixture seed bytes.
///
/// Carries no funds on any network; safe to embed in tests that need a
/// reproducible synthesis seed. The encoded S-strkey form derived from these
/// bytes is never committed to source.
pub const TESTNET_FIXTURE_SEED: [u8; 32] = [
    0x24, 0x6C, 0x53, 0x36, 0x22, 0x1F, 0x04, 0xBE, 0x7E, 0x0D, 0xF7, 0xEF, 0x8E, 0xF6, 0xBB, 0xCF,
    0x69, 0x19, 0xB5, 0x48, 0xF0, 0x23, 0xF0, 0x87, 0xE8, 0x67, 0x3E, 0x6E, 0xD0, 0x7A, 0x6F, 0x5C,
];

/// `PrivateKeyEd25519` version byte (`18 << 3 = 0x90`).
///
/// Decodes to an `S`-prefixed strkey carrying an ed25519 secret seed.
pub const VERSION_PRIVATE_KEY: u8 = 18 << 3;

/// `PreAuthTx` version byte (`19 << 3 = 0x98`).
///
/// Decodes to a `T`-prefixed strkey.
pub const VERSION_PRE_AUTH_TX: u8 = 19 << 3;

/// `HashX` version byte (`23 << 3 = 0xB8`).
///
/// Decodes to an `X`-prefixed strkey.
pub const VERSION_HASH_X: u8 = 23 << 3;

/// `PublicKeyEd25519` version byte (`6 << 3 = 0x30`).
///
/// Decodes to a `G`-prefixed strkey. Included for negative-test synthesis —
/// G-strkeys are public data and must NOT be flagged by the secret redactor.
pub const VERSION_PUBLIC_KEY: u8 = 6 << 3;

/// RFC 4648 base32 alphabet: `A`-`Z` followed by `2`-`7`.
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encodes 35 bytes as a 56-character RFC 4648 base32 string (no padding).
///
/// `35 * 8 = 280` bits = `56 * 5` bits exactly, so encoding consumes all
/// input with no remainder.
///
/// # Panics
///
/// Cannot panic in release builds. In debug builds, two `debug_assert_eq!`
/// post-conditions (bit buffer fully consumed; output length exactly 56)
/// panic if the invariants are violated. Both are unreachable by
/// construction given a 35-byte input; the asserts exist to catch a future
/// refactor that changes the byte count or alphabet size.
#[must_use]
pub fn base32_encode_35(input: &[u8; 35]) -> String {
    let mut out = String::with_capacity(56);
    let mut bit_buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in input {
        bit_buf = (bit_buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((bit_buf >> bits) & 0x1F) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    debug_assert_eq!(bits, 0, "35 bytes encodes cleanly to 56 base32 chars");
    debug_assert_eq!(out.len(), 56);
    out
}

/// Synthesises a structurally valid Stellar strkey from a version byte and a
/// 32-byte seed payload.
///
/// `version_byte` selects the strkey kind:
/// - [`VERSION_PRIVATE_KEY`] → `S`-prefix (ed25519 secret seed)
/// - [`VERSION_PRE_AUTH_TX`] → `T`-prefix
/// - [`VERSION_HASH_X`] → `X`-prefix
/// - [`VERSION_PUBLIC_KEY`] → `G`-prefix (for negative tests only)
///
/// Returns a 56-character RFC 4648 base32 string — the canonical Stellar
/// strkey wire form. Used in place of committing literal strkeys, and delegates
/// CRC-16/XMODEM to [`crate::secret_patterns::crc16_xmodem`] so the oracle and
/// the synthesiser share one implementation.
#[must_use]
pub fn strkey_from_seed(version_byte: u8, seed: &[u8; 32]) -> String {
    let mut payload = [0u8; 35];
    payload[0] = version_byte;
    payload[1..33].copy_from_slice(seed);
    let crc = crate::secret_patterns::crc16_xmodem(&payload[..33]);
    payload[33] = (crc & 0xFF) as u8;
    payload[34] = (crc >> 8) as u8;
    base32_encode_35(&payload)
}

/// Synthesises a strkey whose stored CRC is intentionally corrupted.
///
/// The returned string has the shape of a valid strkey (matches the usual
/// `<prefix>[A-Z2-7]{55}` pattern) but the stored CRC trailer disagrees
/// with the CRC computed over the payload, so any validator that runs the
/// CRC check rejects it. Useful for negative tests of the CRC-16
/// validation step in [`crate::secret_patterns::assert_no_secret_bytes`].
///
/// The last base32 character is replaced deterministically: `A` becomes
/// `B`, and any other base32 character becomes `A`. Two consecutive calls
/// on the same input therefore do NOT return to the original value — the
/// function is a one-shot corruption, not an involution. Alphabet validity
/// is preserved.
///
/// # Panics
///
/// Cannot panic in release builds. In debug builds, a `debug_assert_eq!`
/// documents the 56-char invariant of the underlying [`strkey_from_seed`]
/// call; violating it would mean the synthesiser itself changed contract.
#[must_use]
pub fn strkey_with_bad_crc(version_byte: u8, seed: &[u8; 32]) -> String {
    let mut out = strkey_from_seed(version_byte, seed);
    debug_assert_eq!(out.len(), 56, "strkey_from_seed invariant: 56 base32 chars");
    // `strkey_from_seed` returns exactly 56 ASCII base32 chars; `String::pop`
    // is O(1) on ASCII and returns the trailing `char` as `Some(_)`. In the
    // impossible `None` case (invariant broken), the function returns the
    // unmodified string — debug builds catch the violation via the assert
    // above; release builds degrade gracefully without panicking.
    if let Some(last) = out.pop() {
        out.push(if last == 'A' { 'B' } else { 'A' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_encode_35_produces_56_chars() {
        let input = [0u8; 35];
        let out = base32_encode_35(&input);
        assert_eq!(out.len(), 56);
        assert!(out.chars().all(|c| c == 'A'));
    }

    #[test]
    fn strkey_from_seed_has_expected_prefix() {
        assert!(strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED).starts_with('S'));
        assert!(strkey_from_seed(VERSION_PRE_AUTH_TX, &TESTNET_FIXTURE_SEED).starts_with('T'));
        assert!(strkey_from_seed(VERSION_HASH_X, &TESTNET_FIXTURE_SEED).starts_with('X'));
        assert!(strkey_from_seed(VERSION_PUBLIC_KEY, &TESTNET_FIXTURE_SEED).starts_with('G'));
    }

    #[test]
    fn strkey_from_seed_is_56_chars() {
        let s = strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
        assert_eq!(s.len(), 56);
    }

    #[test]
    fn strkey_with_bad_crc_differs_only_in_last_char() {
        let good = strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
        let bad = strkey_with_bad_crc(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
        assert_eq!(good.len(), bad.len());
        assert_eq!(&good[..55], &bad[..55]);
        assert_ne!(&good[55..], &bad[55..]);
    }

    #[test]
    fn strkey_with_bad_crc_a_branch_flips_to_b() {
        // First seed in a 0..256 search whose synthesized S-strkey ends in `A`.
        let seed = [
            0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let good = strkey_from_seed(VERSION_PRIVATE_KEY, &seed);
        let bad = strkey_with_bad_crc(VERSION_PRIVATE_KEY, &seed);

        assert!(good.ends_with('A'), "{good}");
        assert_eq!(good.len(), bad.len());
        assert_eq!(&good[..55], &bad[..55]);
        assert_eq!(&bad[55..], "B");
    }

    #[test]
    fn strkey_with_bad_crc_stays_in_base32_alphabet() {
        let bad = strkey_with_bad_crc(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
        assert!(
            bad.chars()
                .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)),
            "{bad}"
        );
    }

    /// Round-trip cross-check: synthesise an S-strkey here and feed it to
    /// the oracle's `assert_no_secret_bytes`. The oracle must recognise it
    /// as secret material and panic. Exercises the base32 alphabet and bit
    /// ordering end-to-end against the oracle's `base32_decode_56`
    /// (a genuinely separate implementation); CRC is shared by delegation.
    #[test]
    #[should_panic(expected = "S-strkey hit")]
    fn oracle_accepts_synthesised_s_strkey() {
        let s = strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
        crate::secret_patterns::assert_no_secret_bytes(s.as_bytes());
    }

    /// Round-trip negative: an S-strkey with a corrupted CRC must NOT be
    /// flagged by the oracle — the oracle decodes via its independent
    /// base32 path, then applies the shared CRC-16, and rejects the
    /// mismatched trailer. No panic expected.
    #[test]
    fn oracle_rejects_strkey_with_bad_crc() {
        let s = strkey_with_bad_crc(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
        let log_line = format!("log {s} context");
        crate::secret_patterns::assert_no_secret_bytes(log_line.as_bytes());
    }
}
