//! Shared audit-log redaction helpers for audit decision reasons and
//! observability fields.  Sibling callers include
//! [`crate::audit_log::entry::redact_decision_reason`] and the observability
//! redaction layer; candidates are accepted only after `stellar-strkey`
//! validation, so prefix-only prose such as `"My account is on hold"` is not
//! redacted.

/// Replace public, contract, pre-auth-tx, muxed-account, and signed-payload
/// strkeys with first-5 + `...` + last-5 redaction in `input`.
///
/// # Returns
///
/// Returns `(redacted, did_redact)`, where `did_redact` is `true` iff at least
/// one validated strkey was replaced.
pub(crate) fn redact_account_strkeys_first5_last5(input: &str) -> (String, bool) {
    use stellar_strkey::Strkey;

    let bytes = input.as_bytes();
    let len = bytes.len();
    if len < 56 {
        return (input.to_owned(), false);
    }

    let mut output = String::with_capacity(len);
    let mut pos = 0usize;
    let mut did_redact = false;

    'scan: while pos < len {
        let first = bytes[pos];
        if matches!(first, b'G' | b'C' | b'T' | b'M' | b'P') {
            for &candidate_len in account_strkey_candidate_lengths(first) {
                if pos + candidate_len > len {
                    continue;
                }
                let window = &bytes[pos..pos + candidate_len];
                if !window
                    .iter()
                    .all(|&b| matches!(b, b'A'..=b'Z' | b'2'..=b'7'))
                {
                    continue;
                }
                let Ok(candidate) = std::str::from_utf8(window) else {
                    continue;
                };
                if matches!(
                    Strkey::from_string(candidate),
                    Ok(Strkey::PublicKeyEd25519(_)
                        | Strkey::Contract(_)
                        | Strkey::PreAuthTx(_)
                        | Strkey::MuxedAccountEd25519(_)
                        | Strkey::SignedPayloadEd25519(_))
                ) {
                    output.push_str(&candidate[..5]);
                    output.push_str("...");
                    output.push_str(&candidate[candidate_len - 5..]);
                    pos += candidate_len;
                    did_redact = true;
                    continue 'scan;
                }
            }
        }
        if let Some(ch) = input[pos..].chars().next() {
            output.push(ch);
            pos += ch.len_utf8();
        } else {
            break;
        }
    }

    (output, did_redact)
}

/// String-only convenience for callers that do not need the `did_redact` gate.
#[inline]
pub(crate) fn redact_account_strkeys_first5_last5_string(input: &str) -> String {
    redact_account_strkeys_first5_last5(input).0
}

fn account_strkey_candidate_lengths(first: u8) -> &'static [usize] {
    match first {
        b'G' | b'C' | b'T' => &[56],
        b'M' => &[69],
        // SignedPayloadEd25519 (`P`) is variable length in stellar-strkey.
        // The on-wire binary form is `1 + 32 + 4 + padded_payload + 2`
        // bytes, where `padded_payload ∈ {4, 8, ..., 64}` (inner payload
        // length is padded to the next multiple of 4 per the SEP-23 strkey
        // spec).  The base32-no-pad encoded length is
        // `(binary_len * 8 + 4) / 5`, yielding 16 distinct canonical lengths.
        // Scanning only these (descending for greedy-longest-first) avoids
        // 81 impossible `Strkey::from_string` attempts on `P`-prefix paths.
        // The 16 values are verified by the
        // `signed_payload_all_canonical_lengths_are_redacted` test.
        b'P' => &[
            165, 159, 152, 146, 140, 133, 127, 120, 114, 108, 101, 95, 88, 82, 76, 69,
        ],
        _ => unreachable!("candidate lengths are only requested for supported prefixes"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use super::*;

    const ACCOUNT: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    const MUXED_ACCOUNT: &str =
        "MA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAAAAAAAAAPCICBKU";
    const SIGNED_PAYLOAD: &str =
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAACAAAAAABNWS";

    pub(crate) fn pre_auth_tx_strkey() -> String {
        format!(
            "{}",
            stellar_strkey::Strkey::PreAuthTx(stellar_strkey::PreAuthTx([0x33u8; 32]))
        )
    }

    pub(crate) fn long_signed_payload_strkey() -> String {
        let strkey = stellar_strkey::Strkey::SignedPayloadEd25519(
            stellar_strkey::ed25519::SignedPayload::new([0xA5u8; 32], &[0x5Au8; 64]).unwrap(),
        );
        format!("{strkey}")
    }

    #[test]
    fn account_strkey_redaction_keeps_first5_and_last5() {
        let input = format!("destination={ACCOUNT}");

        let (redacted, did_redact) = redact_account_strkeys_first5_last5(&input);

        assert!(did_redact);
        assert_eq!(redacted, "destination=GA5ZS...4KZVN");
    }

    #[test]
    fn muxed_account_strkey_redaction_keeps_first5_and_last5() {
        let input = format!("source={MUXED_ACCOUNT}");

        let (redacted, did_redact) = redact_account_strkeys_first5_last5(&input);

        assert!(did_redact);
        assert_eq!(redacted, "source=MA3D5...ICBKU");
    }

    #[test]
    fn signed_payload_strkey_redaction_keeps_first5_and_last5() {
        let input = format!("signer={SIGNED_PAYLOAD}");

        let (redacted, did_redact) = redact_account_strkeys_first5_last5(&input);

        assert!(did_redact);
        assert_eq!(redacted, "signer=PA7QY...ABNWS");
    }

    /// Verifies that every canonical `SignedPayloadEd25519` encoded length is
    /// covered by the `b'P'` candidate-length table.  Materialises a strkey for
    /// every inner-payload length in `1..=64` and asserts each one is redacted.
    /// The encoded-length set produced must exactly equal the candidate table at
    /// `account_strkey_candidate_lengths(b'P')`.
    #[test]
    fn signed_payload_all_canonical_lengths_are_redacted() {
        use std::collections::BTreeSet;

        let mut observed_lengths: BTreeSet<usize> = BTreeSet::new();
        for inner_len in 1usize..=64 {
            let inner: std::vec::Vec<u8> = vec![0x5A; inner_len];
            let strkey = stellar_strkey::Strkey::SignedPayloadEd25519(
                stellar_strkey::ed25519::SignedPayload::new([0xA5u8; 32], &inner).unwrap(),
            );
            let strkey = format!("{strkey}");
            let encoded_len = strkey.len();
            observed_lengths.insert(encoded_len);

            let input = format!("signer={strkey}");
            let (redacted, did_redact) = redact_account_strkeys_first5_last5(&input);
            assert!(
                did_redact,
                "inner_len={inner_len} (encoded_len={encoded_len}) must be redacted; got: {redacted}"
            );
            assert!(
                !redacted.contains(&strkey),
                "inner_len={inner_len} (encoded_len={encoded_len}) full strkey must not survive in output: {redacted}"
            );
        }

        let candidate_set: BTreeSet<usize> = account_strkey_candidate_lengths(b'P')
            .iter()
            .copied()
            .collect();
        assert_eq!(
            observed_lengths, candidate_set,
            "candidate-length table must equal the empirical canonical set; \
             observed={observed_lengths:?} candidate={candidate_set:?}",
        );
        assert_eq!(
            observed_lengths.len(),
            16,
            "SignedPayloadEd25519 produces exactly 16 canonical encoded lengths"
        );
    }

    #[test]
    fn signed_payload_165_char_is_redacted() {
        let signed_payload = long_signed_payload_strkey();
        assert_eq!(signed_payload.len(), 165);
        let expected = format!(
            "signer={}...{}",
            &signed_payload[..5],
            &signed_payload[160..]
        );
        let input = format!("signer={signed_payload}");

        let (redacted, did_redact) = redact_account_strkeys_first5_last5(&input);

        assert!(did_redact);
        assert_eq!(redacted, expected);
        assert!(
            !redacted.contains(&signed_payload),
            "full signed-payload strkey must be redacted"
        );
    }

    #[test]
    fn pre_auth_tx_strkey_is_redacted() {
        let pre_auth_tx = pre_auth_tx_strkey();
        assert_eq!(pre_auth_tx.len(), 56);
        let input = format!("signer={pre_auth_tx}");

        let (redacted, did_redact) = redact_account_strkeys_first5_last5(&input);

        assert!(did_redact);
        assert_eq!(
            redacted,
            format!("signer={}...{}", &pre_auth_tx[..5], &pre_auth_tx[51..])
        );
    }

    #[test]
    fn muxed_account_false_positive_is_not_redacted() {
        let input = "My account is on hold";

        let (redacted, did_redact) = redact_account_strkeys_first5_last5(input);

        assert!(!did_redact);
        assert_eq!(redacted, input);
    }

    #[test]
    fn signed_payload_false_positive_is_not_redacted() {
        let input = "Please contact support";

        let (redacted, did_redact) = redact_account_strkeys_first5_last5(input);

        assert!(!did_redact);
        assert_eq!(redacted, input);
    }

    #[test]
    fn pre_auth_tx_prefix_prose_is_not_redacted() {
        let input = "This is a test message";

        let (redacted, did_redact) = redact_account_strkeys_first5_last5(input);

        assert!(!did_redact);
        assert_eq!(redacted, input);
    }

    #[test]
    fn mixed_prefix_strkeys_are_redacted_together() {
        let pre_auth_tx = pre_auth_tx_strkey();
        let input = format!("g={ACCOUNT} m={MUXED_ACCOUNT} p={SIGNED_PAYLOAD} t={pre_auth_tx}");

        let (redacted, did_redact) = redact_account_strkeys_first5_last5(&input);

        assert!(did_redact);
        assert_eq!(
            redacted,
            format!(
                "g=GA5ZS...4KZVN m=MA3D5...ICBKU p=PA7QY...ABNWS t={}...{}",
                &pre_auth_tx[..5],
                &pre_auth_tx[51..]
            )
        );
    }
}
