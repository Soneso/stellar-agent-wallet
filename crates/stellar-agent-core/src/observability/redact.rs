//! Shared observability redaction helpers for non-secret public identifiers.

/// Applies the first-5-last-5 redaction rule to Stellar strkeys.
///
/// Returns `"G...?"` for inputs shorter than 11 characters, which cannot
/// accommodate `first5 + "..." + last5` without overlap. Real public account
/// and contract strkeys are longer; the fallback is defensive.
#[must_use]
pub fn redact_strkey_first5_last5(value: &str) -> String {
    if value.chars().count() > 10 {
        let first = value.chars().take(5).collect::<String>();
        let last = value
            .chars()
            .rev()
            .take(5)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<String>();
        format!("{first}...{last}")
    } else {
        "G...?".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_strkey_first5_last5_short_returns_fallback() {
        assert_eq!(redact_strkey_first5_last5("GABC"), "G...?");
        assert_eq!(redact_strkey_first5_last5(""), "G...?");
    }

    #[test]
    fn redact_strkey_first5_last5_long_returns_first5_last5() {
        let id = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

        let redacted = redact_strkey_first5_last5(id);

        assert_eq!(redacted, "GAQAA...QSTVY");
        assert!(!redacted.contains(id));
    }

    #[test]
    fn redact_strkey_first5_last5_non_ascii_does_not_panic() {
        assert_eq!(
            redact_strkey_first5_last5("🚀ABCD🚀ABCD🚀"),
            "🚀ABCD...ABCD🚀"
        );
        assert_eq!(redact_strkey_first5_last5("G🚀ABCD"), "G...?");
    }
}
