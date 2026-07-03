//! Shared counterparty identity validation helpers.
//!
//! The core crate owns the canonical `home_domain` syntax check because policy
//! loading lives here and `stellar-agent-core` must not depend on
//! `stellar-agent-network`.  Network code re-exports this helper so fetch,
//! cache, and on-chain projection paths use the same byte-level rule.

/// Maximum accepted `home_domain` byte length.
///
/// SEP-1 treats `home_domain` as a DNS hostname.  This parser accepts the
/// policy/network input form up to the DNS wire-name boundary without a
/// trailing root dot.
pub const MAX_HOME_DOMAIN_BYTES: usize = 255;

/// Maximum accepted byte length for one DNS label.
pub const MAX_HOME_DOMAIN_LABEL_BYTES: usize = 63;

/// Returns `true` when `home_domain` is a canonical lowercase LDH home domain.
///
/// Accepted bytes are lowercase ASCII letters, digits, hyphen, and dot.
/// The value must not start or end with a hyphen or dot, must not contain
/// empty labels, and each label must be at most 63 bytes.
///
/// The helper performs syntax validation only.  It does not resolve DNS, apply
/// IDNA / punycode conversion, or validate each DNS label independently.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::counterparty::is_valid_ldh_home_domain;
///
/// assert!(is_valid_ldh_home_domain("circle.com"));
/// assert!(!is_valid_ldh_home_domain("Circle.com"));
/// ```
#[must_use]
pub fn is_valid_ldh_home_domain(home_domain: &str) -> bool {
    if home_domain.is_empty()
        || home_domain.len() > MAX_HOME_DOMAIN_BYTES
        || !home_domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
        || home_domain.starts_with(['.', '-'])
        || home_domain.ends_with(['.', '-'])
    {
        return false;
    }

    home_domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_HOME_DOMAIN_LABEL_BYTES
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

#[cfg(test)]
mod tests {
    use super::is_valid_ldh_home_domain;

    fn repeated_label_domain(label_lengths: &[usize]) -> String {
        label_lengths
            .iter()
            .enumerate()
            .map(|(i, len)| {
                let ch = char::from(b'a' + (i % 26) as u8);
                ch.to_string().repeat(*len)
            })
            .collect::<Vec<_>>()
            .join(".")
    }

    #[test]
    fn accepts_lowercase_ldh_domain() {
        assert!(is_valid_ldh_home_domain("circle.com"));
        assert!(is_valid_ldh_home_domain("my-bank1.com"));
    }

    #[test]
    fn rejects_empty_domain() {
        assert!(!is_valid_ldh_home_domain(""));
    }

    #[test]
    fn accepts_dns_length_boundaries() {
        assert!(is_valid_ldh_home_domain(&"a".repeat(32)));
        assert!(is_valid_ldh_home_domain(&repeated_label_domain(&[
            63, 63, 63, 62
        ])));
        assert!(is_valid_ldh_home_domain(&repeated_label_domain(&[
            63, 63, 63, 63
        ])));
        assert!(!is_valid_ldh_home_domain(&repeated_label_domain(&[
            63, 63, 63, 62, 1
        ])));

        // Total-length cap (separate from label cap): 5 labels of 63 bytes + 4 dots = 319 bytes.
        // Each label is within the 63-byte label cap, so this exercises the 255-byte total cap.
        let too_long_total = format!(
            "{}.{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63),
            "e".repeat(63),
        );
        assert_eq!(too_long_total.len(), 319);
        assert!(!is_valid_ldh_home_domain(&too_long_total));

        // Defence-in-depth label-cap case: one 1024-byte label is rejected by
        // the per-label limit before the total-length cap matters.
        assert!(!is_valid_ldh_home_domain(&"a".repeat(1024)));
    }

    #[test]
    fn rejects_uppercase_ascii() {
        assert!(!is_valid_ldh_home_domain("Circle.com"));
    }

    #[test]
    fn rejects_underscore() {
        assert!(!is_valid_ldh_home_domain("circle_pay.com"));
    }

    #[test]
    fn rejects_leading_or_trailing_dot_or_hyphen() {
        assert!(!is_valid_ldh_home_domain(".circle.com"));
        assert!(!is_valid_ldh_home_domain("circle.com."));
        assert!(!is_valid_ldh_home_domain("-circle.com"));
        assert!(!is_valid_ldh_home_domain("circle.com-"));
        assert!(!is_valid_ldh_home_domain("circle.-com"));
        assert!(!is_valid_ldh_home_domain("circle-.com"));
    }

    #[test]
    fn rejects_empty_or_oversized_labels() {
        assert!(!is_valid_ldh_home_domain("circle..com"));
        assert!(!is_valid_ldh_home_domain(&format!(
            "{}.com",
            "a".repeat(64)
        )));
    }

    #[test]
    fn rejects_non_ascii() {
        assert!(!is_valid_ldh_home_domain("сircle.com"));
    }
}
