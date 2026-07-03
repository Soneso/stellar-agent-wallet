//! Pattern-based detection of secret material in captured log bytes.
//!
//! Provides [`assert_no_secret_bytes`], which scans a byte slice for patterns
//! that indicate secret material leaked into log output. Three detection
//! strategies are applied in order:
//!
//! 1. **Stellar S-strkey detection**: regex candidate
//!    `S[A-Z2-7]{55}` followed by RFC 4648 base32 decode, version-byte check
//!    (`0x90`), and CRC-16/XMODEM validation. Produces zero false positives on
//!    non-Stellar base32 strings.
//!
//! 2. **BIP-39 mnemonic heuristic**: scans for runs
//!    of 12 or 24 lowercase space-separated words (3-8 chars each) where every
//!    word appears in the English BIP-39 word list.
//!
//! 3. **Sensitive field-name catch-all**: detects
//!    occurrences of known sensitive field names (`secret`, `private_key`, etc.)
//!    followed by a value that is not the expected `[REDACTED]` sentinel. Used
//!    to catch callers who bypassed the formatter by pre-serialising a string.
//!
//! Any hit indicates secret material in the captured bytes.

// `assert_no_secret_bytes` is a test-harness assertion function; panicking on
// detection is the intended behaviour (panics on any hit).
// The `expect`s inside `sstrkey_re` / `mnemonic_re` are on regex literals
// that cannot fail — the patterns are ASCII-only and validated at review time.
// Both warrant an allow here so the workspace lints do not block the crate.
#![allow(clippy::expect_used, clippy::panic)]

use crate::bip39_english::BIP39_ENGLISH;
use regex_lite::Regex;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Regex compilation — compiled once per process via OnceLock.
// ---------------------------------------------------------------------------

/// Compiled regex for candidate Stellar S-strkey sequences.
fn sstrkey_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // SAFETY: the pattern is a validated ASCII literal; Regex::new cannot
        // fail for this input.
        Regex::new(r"S[A-Z2-7]{55}").expect("S-strkey regex is valid ASCII; compile cannot fail")
    })
}

/// Compiled regex that matches a run of 12 or 24 lowercase words (3-8 chars
/// each) separated by single spaces.  The word character class `[a-z]{3,8}`
/// excludes digits and punctuation, which prevents ordinary prose from
/// matching.
fn mnemonic_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Matches either 12 or 24 space-separated lowercase words of 3-8 chars.
        // The two alternatives are listed longest-first so the 24-word branch
        // has priority when both would match.
        //
        // Pattern breakdown:
        //   (?:WORD WORD ... WORD)  — 23 repetitions of "word " followed by 1 word
        // We inline both counts directly to keep the regex simple.
        let word = "[a-z]{3,8}";
        let sep = " ";
        let run_24 = format!("{word}{sep}").repeat(23) + word;
        let run_12 = format!("{word}{sep}").repeat(11) + word;
        let pattern = format!("(?:{run_24})|(?:{run_12})");
        // SAFETY: the pattern is built from ASCII character-class literals only;
        // Regex::new cannot fail for this input.
        Regex::new(&pattern).expect("mnemonic regex is valid ASCII; compile cannot fail")
    })
}

// ---------------------------------------------------------------------------
// Sensitive field names (redact list).
// ---------------------------------------------------------------------------

/// Field names whose presence in captured output followed by a non-REDACTED
/// value indicates a secret leak.
const SENSITIVE_FIELD_NAMES: &[&str] = &[
    "key",
    "private_key",
    "privatekey",
    "priv",
    "sk",
    "signing_key",
    "seed",
    "seed_phrase",
    "secret",
    "secret_key",
    "mnemonic",
    "passphrase",
    "password",
    "keypair",
    "credential",
    "credentials",
    "entropy",
    "wif",
    "xdr_secret",
    "auth_cred",
];

// ---------------------------------------------------------------------------
// Base32 decode — RFC 4648, no padding, uppercase alphabet A-Z and 2-7.
// ---------------------------------------------------------------------------

/// Decodes a 56-character RFC 4648 base32 string (A-Z, 2-7, no padding) into
/// exactly 35 bytes.
///
/// Returns `None` if any character is outside the alphabet or if the decoded
/// length is not 35 bytes.
fn base32_decode_56(s: &str) -> Option<[u8; 35]> {
    debug_assert_eq!(s.len(), 56, "caller must pass exactly 56-char candidate");
    if s.len() != 56 {
        return None;
    }

    // 56 base32 characters * 5 bits = 280 bits = 35 bytes exactly.
    let mut out = [0u8; 35];
    let bytes = s.as_bytes();

    let mut bit_buf: u32 = 0;
    let mut bits_in_buf: u32 = 0;
    let mut out_idx: usize = 0;

    for &c in bytes {
        let val: u32 = match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'2'..=b'7' => u32::from(c - b'2') + 26,
            _ => return None, // character outside base32 alphabet
        };
        bit_buf = (bit_buf << 5) | val;
        bits_in_buf += 5;
        if bits_in_buf >= 8 {
            bits_in_buf -= 8;
            out[out_idx] = ((bit_buf >> bits_in_buf) & 0xFF) as u8;
            out_idx += 1;
        }
    }

    // All 280 bits should be consumed into 35 bytes.
    debug_assert_eq!(out_idx, 35);
    if out_idx == 35 { Some(out) } else { None }
}

// ---------------------------------------------------------------------------
// CRC-16/XMODEM — poly 0x1021, init 0x0000, no reflection, XOR-out 0.
// The checksum is stored in the last 2 bytes of the strkey in little-endian
// order (verified against the Flutter SDK implementation and test vectors).
// ---------------------------------------------------------------------------

/// Computes CRC-16/XMODEM over `data`.
///
/// Polynomial `0x1021`, initial value `0x0000`, no input/output reflection,
/// XOR-out `0`. The Stellar network encodes the result in little-endian byte
/// order in the strkey trailer.
///
/// `pub(crate)` so the synthesis helpers in [`crate::testnet_strkeys`] can
/// share this single implementation rather than duplicating it.
#[must_use]
pub(crate) fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ---------------------------------------------------------------------------
// S-strkey validation.
// ---------------------------------------------------------------------------

/// Version byte for `ed25519SecretSeed` strkeys (Stellar strkey spec, SEP-23).
///
/// Value: `18 << 3 = 0x90`.  Verified against the JS Stellar SDK source at
/// `js-stellar-base/src/strkey.js` line 8: `ed25519SecretSeed: 18 << 3`.
const SSTRKEY_VERSION_BYTE: u8 = 0x90;

/// Returns `true` if `candidate` is a structurally valid Stellar S-strkey.
///
/// Validation steps (per Stellar strkey specification / SEP-23):
/// 1. Decode from RFC 4648 base32 to 35 bytes.
/// 2. Check that byte 0 equals `0x90` (version byte for `ed25519SecretSeed`).
/// 3. Verify that the last two bytes (little-endian CRC-16/XMODEM) match the
///    checksum computed over the first 33 bytes.
///
/// A candidate that fails any step is not a valid S-strkey and does not trigger
/// a panic — this prevents false positives on arbitrary 56-char base32 strings.
fn is_valid_s_strkey(candidate: &str) -> bool {
    let decoded = match base32_decode_56(candidate) {
        Some(d) => d,
        None => return false,
    };

    if decoded[0] != SSTRKEY_VERSION_BYTE {
        return false;
    }

    let data = &decoded[..33];
    let stored_crc = u16::from(decoded[33]) | (u16::from(decoded[34]) << 8);
    let computed_crc = crc16_xmodem(data);

    computed_crc == stored_crc
}

// ---------------------------------------------------------------------------
// BIP-39 mnemonic detection helpers.
// ---------------------------------------------------------------------------

/// Returns `true` if every word in `words` is present in [`BIP39_ENGLISH`].
///
/// The word list is sorted lexicographically, so binary search is used for
/// O(log n) per-word lookup.
fn all_words_in_bip39(words: &[&str]) -> bool {
    words.iter().all(|w| BIP39_ENGLISH.binary_search(w).is_ok())
}

// ---------------------------------------------------------------------------
// Sensitive-field detection.
// ---------------------------------------------------------------------------

/// Case-insensitive ASCII substring search: returns the byte offset of the
/// first occurrence of `needle` in `haystack` with `eq_ignore_ascii_case`
/// matching per byte, or `None`.
///
/// The needle MUST be pure ASCII. When a match is returned, `pos` is
/// guaranteed to be on a UTF-8 char boundary in `haystack`, because every
/// ASCII byte is a single-byte code point and cannot appear as a UTF-8
/// continuation byte (those have the high bit set). Corollary:
/// `pos + needle.len()` is also on a char boundary, so slicing
/// `haystack[pos..pos + needle.len()]` is safe even if `haystack` contains
/// non-ASCII characters elsewhere.
fn find_ascii_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    debug_assert!(
        needle.iter().all(|b| b.is_ascii()),
        "find_ascii_ci: needle must be pure ASCII"
    );
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w.iter().zip(needle).all(|(h, n)| h.eq_ignore_ascii_case(n)))
}

/// Returns `Some((field_name, byte_offset))` if `text` contains a sensitive
/// field name followed by a non-REDACTED value; otherwise returns `None`.
///
/// Two patterns are checked for each field name:
///
/// - JSON format: `"<name>":"<value>"` where `<value>` is not `[REDACTED]`.
/// - Key=value format: `<name>=<value>` where `<value>` is not `[REDACTED]`
///   and not `"[REDACTED]"`.
///
/// The check is case-insensitive on the field name. Field names in
/// [`SENSITIVE_FIELD_NAMES`] are all ASCII, so case-insensitive matching on
/// byte slices is both correct and panic-free on arbitrary UTF-8 input — an
/// earlier implementation used `text.to_lowercase()` and indexed `text` with
/// offsets from the (potentially-longer) lowered string, which could panic
/// on non-char-boundary indices when the input contained Unicode characters
/// like `İ` → `i` + combining-mark or `ß` → `SS` that change byte length
/// under `to_lowercase`.
fn find_sensitive_field(text: &str) -> Option<(&'static str, usize)> {
    let text_bytes = text.as_bytes();

    for &field in SENSITIVE_FIELD_NAMES {
        // JSON pattern: `"<field>":"<value>"`.
        let json_key = format!("\"{field}\":\"");
        if let Some(pos) = find_ascii_ci(text_bytes, json_key.as_bytes()) {
            let value_start = pos + json_key.len();
            // Find the closing `"` relative to value_start. `"` is ASCII, so
            // its byte-offset position is on a char boundary.
            if let Some(rel) = text_bytes[value_start..].iter().position(|&b| b == b'"') {
                let value = &text[value_start..value_start + rel];
                if value != "[REDACTED]" {
                    return Some((field, pos));
                }
            }
        }

        // JSON pattern without quotes around value (numeric / bool / null):
        // `"<field>":<non-string>` — not checked here. Numeric / bool values
        // are scanned by the runtime redactor at
        // the field level before they are serialised to text, so the
        // capture should already carry `[REDACTED]` when the field name is
        // on the redact list. Per-field-type detection in this text
        // scanner would duplicate that work and add false-positive risk.

        // Key=value pattern: `<field>=<value>` where value is not REDACTED.
        let kv_key = format!("{field}=");
        if let Some(pos) = find_ascii_ci(text_bytes, kv_key.as_bytes()) {
            let value_start = pos + kv_key.len();
            // Value extends to the next whitespace, comma, brace, or quote.
            // Using char-based `.find(|c: char| ...)` keeps the end offset on
            // a char boundary even when non-ASCII Unicode whitespace appears.
            let value_end = text[value_start..]
                .find(|c: char| c.is_whitespace() || c == ',' || c == '}' || c == '"')
                .map(|n| value_start + n)
                .unwrap_or(text.len());
            let value = &text[value_start..value_end];
            if value != "[REDACTED]" && !value.is_empty() {
                return Some((field, pos));
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Public assertion.
// ---------------------------------------------------------------------------

/// Asserts that `captured` contains no secret material that matches the
/// never-log patterns.
///
/// Three checks are applied:
///
/// 1. **S-strkey**: any 56-character candidate matching `S[A-Z2-7]{55}` that
///    passes CRC-16/XMODEM validation (version byte `0x90`) triggers a panic.
///    Non-Stellar base32 strings of the same shape are rejected by the
///    validation step and do not trigger a panic.
///
/// 2. **BIP-39 mnemonic**: any run of 12 or 24 lowercase space-separated words
///    (3-8 chars each) where every word appears in the English BIP-39 word list
///    triggers a panic.
///
/// 3. **Sensitive field name**: any occurrence of a sensitive field name (see
///    redact list) followed by a value that
///    is not exactly `[REDACTED]` or `"[REDACTED]"` triggers a panic.
///
/// # Panics
///
/// Panics on any pattern match. This is the intended behaviour for a
/// test-assertion function (panics on any hit). The panic
/// message includes the pattern name, the byte offset of the first hit, and a
/// redacted hex preview of the first 32 bytes of `captured`. The full capture
/// is never included to avoid re-emitting secret material in test output.
pub fn assert_no_secret_bytes(captured: &[u8]) {
    let text = String::from_utf8_lossy(captured);

    // --- Check 1: S-strkey detection ---
    for m in sstrkey_re().find_iter(&text) {
        if is_valid_s_strkey(m.as_str()) {
            let offset = m.start();
            let preview = redacted_hex_preview(captured, offset);
            panic!(
                "assert_no_secret_bytes: S-strkey hit at offset {offset}: {preview}\n  \
                 Full capture suppressed to avoid leaking in test output."
            );
        }
    }

    // --- Check 2: BIP-39 mnemonic detection ---
    for m in mnemonic_re().find_iter(&text) {
        let candidate = m.as_str();
        let words: Vec<&str> = candidate.split(' ').collect();
        let count = words.len();
        if (count == 12 || count == 24) && all_words_in_bip39(&words) {
            let offset = m.start();
            let preview = redacted_hex_preview(captured, offset);
            panic!(
                "assert_no_secret_bytes: BIP-39 mnemonic ({count} words) hit at offset \
                 {offset}: {preview}\n  \
                 Full capture suppressed to avoid leaking in test output."
            );
        }
    }

    // --- Check 3: Sensitive field name detection ---
    if let Some((field, offset)) = find_sensitive_field(&text) {
        // No hex preview for this panic path. The hit itself is a value
        // carried by a sensitive field name; a hex preview of the capture
        // would likely include those bytes verbatim and re-emit the
        // suspected secret into test output (CI logs, PR artefacts). The
        // field name and offset are enough to locate the leak.
        panic!(
            "assert_no_secret_bytes: sensitive field name \"{field}\" with non-REDACTED \
             value at offset {offset}. Full capture suppressed to avoid leaking in test output."
        );
    }
}

// ---------------------------------------------------------------------------
// Internal helpers.
// ---------------------------------------------------------------------------

/// Returns a hex string of the first 32 bytes of `captured`, with any
/// S-strkey or BIP-39 mnemonic run replaced by `[REDACTED]` in the UTF-8
/// text view before hex-encoding the preview slice.
///
/// This guarantees that the panic message itself does not re-emit the secret
/// material even via hex.
fn redacted_hex_preview(captured: &[u8], _hit_offset: usize) -> String {
    let text = String::from_utf8_lossy(captured);

    // Redact any S-strkey candidate (regardless of CRC validity) in the
    // preview to prevent partial leakage.
    let mut redacted = sstrkey_re().replace_all(&text, "[REDACTED]").into_owned();

    // Redact any mnemonic-shaped run in the preview.
    redacted = mnemonic_re()
        .replace_all(&redacted, "[REDACTED]")
        .into_owned();

    let preview_bytes = redacted.as_bytes();
    let len = preview_bytes.len().min(32);
    preview_bytes[..len]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// Unit tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testnet_strkeys::{
        TESTNET_FIXTURE_SEED, VERSION_PRIVATE_KEY, strkey_from_seed, strkey_with_bad_crc,
    };

    /// Local alias for the canonical S-strkey synthesis path. Keeps the test
    /// bodies readable without re-specifying the version byte each time; the
    /// tests in this module always exercise the S-strkey codepath against the
    /// oracle in the parent module.
    fn sstrkey_from_seed(seed: &[u8; 32]) -> String {
        strkey_from_seed(VERSION_PRIVATE_KEY, seed)
    }

    /// Local alias for the bad-CRC synthesis path, paired with
    /// [`sstrkey_from_seed`] for readability.
    fn sstrkey_with_bad_crc(seed: &[u8; 32]) -> String {
        strkey_with_bad_crc(VERSION_PRIVATE_KEY, seed)
    }

    // -------------------------------------------------------------------------
    // CRC-16/XMODEM known-answer tests.
    // -------------------------------------------------------------------------

    #[test]
    fn crc16_known_answer_empty() {
        // CRC-16/XMODEM over empty input is 0x0000.
        assert_eq!(crc16_xmodem(&[]), 0x0000);
    }

    #[test]
    fn crc16_known_answer_ascii() {
        // CRC-16/XMODEM("123456789") = 0x31C3 per the canonical test vector.
        assert_eq!(crc16_xmodem(b"123456789"), 0x31C3);
    }

    // -------------------------------------------------------------------------
    // Base32 decode tests.
    // -------------------------------------------------------------------------

    #[test]
    fn base32_decode_valid_sstrkey() {
        // The test fixture decodes to 35 bytes.
        let strkey = sstrkey_from_seed(&TESTNET_FIXTURE_SEED);
        let decoded = base32_decode_56(&strkey);
        assert!(decoded.is_some());
        let d = decoded.expect("test fixture is a valid S-strkey");
        assert_eq!(d.len(), 35);
        assert_eq!(d[0], SSTRKEY_VERSION_BYTE);
    }

    #[test]
    fn base32_decode_rejects_invalid_char() {
        // '1' and '8' are outside the RFC 4648 base32 alphabet (A-Z, 2-7).
        let bad = "S1BGWKM3CD4IL47QN6X54N6Y33T3JDNVI6AIJ6CD5IM47HG3IG4O36XC";
        assert!(base32_decode_56(bad).is_none());
    }

    // -------------------------------------------------------------------------
    // S-strkey validation tests.
    // -------------------------------------------------------------------------

    #[test]
    fn valid_s_strkey_passes() {
        let strkey = sstrkey_from_seed(&TESTNET_FIXTURE_SEED);
        assert!(is_valid_s_strkey(&strkey));
    }

    #[test]
    fn crc_mismatch_rejected() {
        // A CRC-corrupted strkey must fail validation: the regex matches, but
        // the CRC check rejects. Synthesised at runtime so no literal S-strkey
        // appears in source.
        let bad_crc = sstrkey_with_bad_crc(&TESTNET_FIXTURE_SEED);
        assert!(!is_valid_s_strkey(&bad_crc));
    }

    #[test]
    fn wrong_version_byte_rejected() {
        // A G-strkey starts with version byte 0x30 (ed25519 public key).
        // It does not begin with 'S', so it will not match the regex, but we
        // also verify the version-byte check logic directly.
        let decoded = base32_decode_56("GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL");
        if let Some(d) = decoded {
            // Version byte should be 0x30, not 0x90.
            assert_ne!(d[0], SSTRKEY_VERSION_BYTE);
        }
        // The strkey validation function must reject it regardless.
        assert!(!is_valid_s_strkey(
            "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL"
        ));
    }

    // -------------------------------------------------------------------------
    // assert_no_secret_bytes — S-strkey tests.
    // -------------------------------------------------------------------------

    #[test]
    #[should_panic(expected = "assert_no_secret_bytes: S-strkey hit")]
    fn sstrkey_in_log_panics() {
        let strkey = sstrkey_from_seed(&TESTNET_FIXTURE_SEED);
        let log_line = format!("{{\"level\":\"ERROR\",\"fields\":{{\"key\":\"{strkey}\"}}}}");
        assert_no_secret_bytes(log_line.as_bytes());
    }

    #[test]
    fn clean_log_line_does_not_panic() {
        let log_line = b"{\"level\":\"INFO\",\"fields\":{\"account\":\"GAAAA..ZZZZZ\"}}";
        assert_no_secret_bytes(log_line);
    }

    #[test]
    fn non_stellar_base32_does_not_panic() {
        // 56 chars matching S[A-Z2-7]{55} but with an invalid CRC-16.
        // Constructed at runtime from TESTNET_FIXTURE_SEED with the final
        // base32 char flipped so the regex fires but CRC validation rejects.
        let fake = sstrkey_with_bad_crc(&TESTNET_FIXTURE_SEED);
        let log_line = format!("some log text {fake} more text");
        assert_no_secret_bytes(log_line.as_bytes());
    }

    // -------------------------------------------------------------------------
    // assert_no_secret_bytes — BIP-39 mnemonic tests.
    // -------------------------------------------------------------------------

    // A known 12-word BIP-39 mnemonic (disposable testnet fixture).
    // Words sourced from the canonical BIP-39 English word list.
    // This mnemonic does not derive any funded wallet.
    const TESTNET_FIXTURE_MNEMONIC_12: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // A known 24-word BIP-39 mnemonic (disposable testnet fixture).
    const TESTNET_FIXTURE_MNEMONIC_24: &str = "abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon art";

    #[test]
    #[should_panic(expected = "assert_no_secret_bytes: BIP-39 mnemonic")]
    fn bip39_12_word_mnemonic_panics() {
        let log_line = format!("seed phrase: {TESTNET_FIXTURE_MNEMONIC_12}");
        assert_no_secret_bytes(log_line.as_bytes());
    }

    #[test]
    #[should_panic(expected = "assert_no_secret_bytes: BIP-39 mnemonic")]
    fn bip39_24_word_mnemonic_panics() {
        let log_line = format!("seed phrase: {TESTNET_FIXTURE_MNEMONIC_24}");
        assert_no_secret_bytes(log_line.as_bytes());
    }

    #[test]
    fn non_bip39_words_do_not_panic() {
        // 12 words where several are not in the BIP-39 English word list.
        // "the", "and", "but", "not", "for", "are", "was" are common English
        // words absent from the BIP-39 list.  The check must not panic because
        // not every word matches.
        let log_line = b"the and but not for are was abandon ability able about above";
        assert_no_secret_bytes(log_line);
    }

    #[test]
    fn fewer_than_12_bip39_words_do_not_panic() {
        // A run of 11 BIP-39 words is below the minimum threshold.
        let log_line =
            b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert_no_secret_bytes(log_line);
    }

    // -------------------------------------------------------------------------
    // assert_no_secret_bytes — sensitive field name tests.
    // -------------------------------------------------------------------------

    #[test]
    #[should_panic(expected = "assert_no_secret_bytes: sensitive field name")]
    fn secret_field_with_value_panics() {
        let log_line = br#"{"level":"ERROR","fields":{"secret":"mysecretvalue"}}"#;
        assert_no_secret_bytes(log_line);
    }

    #[test]
    #[should_panic(expected = "assert_no_secret_bytes: sensitive field name")]
    fn private_key_field_panics() {
        let log_line = br#"{"fields":{"private_key":"rawkeydata"}}"#;
        assert_no_secret_bytes(log_line);
    }

    #[test]
    fn redacted_sentinel_does_not_panic() {
        // A field named `secret` with value `[REDACTED]` must pass.
        let log_line = br#"{"fields":{"secret":"[REDACTED]"}}"#;
        assert_no_secret_bytes(log_line);
    }

    #[test]
    fn account_id_redacted_does_not_panic() {
        // `account_id` is not on the sensitive field list; it is pass-through.
        let log_line = br#"{"fields":{"account_id":"[REDACTED]"}}"#;
        assert_no_secret_bytes(log_line);
    }

    #[test]
    fn public_key_g_strkey_does_not_panic() {
        // A G-strkey is a public key, not a secret.  It does not start with S,
        // so the S-strkey check cannot fire.  The field name `public_key` is not
        // in the sensitive field list.
        let log_line =
            br#"{"fields":{"public_key":"GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL"}}"#;
        assert_no_secret_bytes(log_line);
    }

    #[test]
    fn password_field_no_value_passes_redacted() {
        // password=[REDACTED] must not panic.
        let log_line = b"password=[REDACTED] other=data";
        assert_no_secret_bytes(log_line);
    }

    #[test]
    #[should_panic(expected = "assert_no_secret_bytes: sensitive field name")]
    fn password_field_with_value_panics() {
        let log_line = b"password=hunter2 other=data";
        assert_no_secret_bytes(log_line);
    }

    // -------------------------------------------------------------------------
    // Robustness: non-ASCII Unicode input must not panic.
    // -------------------------------------------------------------------------

    /// Non-ASCII Unicode must not trigger a char-boundary panic: `to_lowercase`
    /// can grow a character (`İ` U+0130 is 2 bytes but lowercases to 3), so a
    /// scan that lowercases must never index the original string with offsets
    /// taken from the lowered one.
    #[test]
    fn non_ascii_unicode_does_not_panic() {
        let log_line = "İstanbul log line with password=hunter2";
        // `assert_no_secret_bytes` must not panic on input that is neither
        // a secret nor a sensitive-field match; the kv pattern DOES hit
        // `password=hunter2` here, so we expect a panic from that check
        // specifically, not a char-boundary panic from the string scanning.
        let result = std::panic::catch_unwind(|| {
            assert_no_secret_bytes(log_line.as_bytes());
        });
        match result {
            Err(panic) => {
                let msg = panic_message(&panic);
                assert!(
                    msg.contains("sensitive field name \"password\""),
                    "unexpected panic message: {msg}"
                );
            }
            Ok(()) => panic!("expected a sensitive-field panic, got clean pass"),
        }
    }

    /// Regression test for non-ASCII input with no sensitive patterns: must
    /// pass cleanly (no panic of any kind).
    #[test]
    fn non_ascii_clean_input_passes() {
        let log_line = "İstanbul benign log with account=[REDACTED]";
        assert_no_secret_bytes(log_line.as_bytes());
    }

    /// Regression test for the `to_lowercase` byte-growth edge case with
    /// German sharp-S (`ß` → `SS`).
    #[test]
    fn german_sharp_s_does_not_panic() {
        let log_line = "gruße ok password=hunter2";
        let result = std::panic::catch_unwind(|| {
            assert_no_secret_bytes(log_line.as_bytes());
        });
        assert!(result.is_err(), "expected sensitive-field panic");
    }

    /// Helper: extract the panic message as a &str from a panic payload.
    fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
        if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = payload.downcast_ref::<&str>() {
            (*s).to_owned()
        } else {
            "<non-string panic payload>".to_owned()
        }
    }

    // -------------------------------------------------------------------------
    // Smoke test: CaptureWriter + tracing subscriber + benign info!.
    // -------------------------------------------------------------------------

    #[test]
    fn smoke_benign_info_event_passes() {
        use crate::log_capture::CaptureWriter;

        let capture = CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(operation = "test", status = "ok", "benign log event");
        });
        assert_no_secret_bytes(&capture.captured());
    }
}
