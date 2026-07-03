//! Shared counterparty validation façade for network-facing code.
//!
//! The canonical implementation lives in `stellar-agent-core` so the policy
//! loader and network stack cannot drift while preserving the crate dependency
//! direction (`network` depends on `core`, never the reverse).

pub use stellar_agent_core::counterparty::is_valid_ldh_home_domain;

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
