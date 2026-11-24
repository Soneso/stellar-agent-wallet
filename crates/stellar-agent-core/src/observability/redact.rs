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

/// Maximum byte length of the string returned by [`untrusted_display_bounded`],
/// including the truncation marker.
pub const UNTRUSTED_DISPLAY_MAX_BYTES: usize = 64;

/// Marker appended by [`untrusted_display_bounded`] when it truncates.
const TRUNCATION_MARKER: &str = "...";

/// Whether `c` is a character untrusted text must never carry raw onto an
/// approval surface, a terminal or a log line.
///
/// The set is C0, DEL and C1 (`char::is_control`), the line and paragraph
/// separators U+2028 and U+2029, and every Unicode format character (general
/// category Cf), among them the bidirectional overrides and isolates, the
/// zero-width characters including U+200C and U+200D, the soft hyphen, the
/// byte-order mark and the tag characters. These characters move the cursor,
/// recolor, reorder or hide the text around them. [`escape_untrusted_text`]
/// and [`untrusted_display_bounded`] render each as a visible escape, and memo
/// input refuses them, so an accepted memo never needs one.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::observability::redact::is_untrusted_format_character;
///
/// assert!(is_untrusted_format_character('\u{1b}'));
/// assert!(is_untrusted_format_character('\u{202E}'));
/// assert!(is_untrusted_format_character('\u{200D}'));
/// assert!(!is_untrusted_format_character('\u{e9}'));
/// ```
#[must_use]
pub const fn is_untrusted_format_character(c: char) -> bool {
    c.is_control()
        || matches!(c,
        '\u{00AD}' | '\u{0600}'..='\u{0605}' | '\u{061C}' | '\u{06DD}' | '\u{070F}'
        | '\u{0890}'..='\u{0891}' | '\u{08E2}' | '\u{180E}'
        | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}'
        | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' | '\u{110BD}' | '\u{110CD}'
        | '\u{13430}'..='\u{1343F}' | '\u{1BCA0}'..='\u{1BCA3}'
        | '\u{1D173}'..='\u{1D17A}' | '\u{E0001}' | '\u{E0020}'..='\u{E007F}')
}

/// Renders untrusted bytes (for example an owner-chosen ledger string) for a
/// log line, error string, audit row or MCP envelope.
///
/// The bytes are decoded lossily as UTF-8. Backslash, double quote and every
/// character [`is_untrusted_format_character`] names (C0, DEL, C1, U+2028,
/// U+2029 and every Unicode format character, category Cf) are rendered as
/// Rust escape sequences, so the output is a single printable
/// line whose escapes are unambiguous. The result is at most
/// [`UNTRUSTED_DISPLAY_MAX_BYTES`] bytes; a longer rendering is cut at an
/// escape-sequence and character boundary and ends in `...`.
///
/// Only a bounded prefix of the input is decoded, so the cost is independent
/// of the input length.
#[must_use]
pub fn untrusted_display_bounded(bytes: &[u8]) -> String {
    // Every input byte renders to at least one output byte (a valid character
    // keeps its width, an invalid sequence of up to three bytes renders as the
    // three-byte replacement character, escapes only widen). A prefix of
    // `MAX + 4` bytes therefore renders past the cap whenever the input is
    // longer than the prefix, and the at most one replacement character a
    // prefix cut can introduce sits beyond the truncation point.
    let prefix_len = bytes.len().min(UNTRUSTED_DISPLAY_MAX_BYTES + 4);
    let input_cut = prefix_len < bytes.len();
    let decoded = String::from_utf8_lossy(&bytes[..prefix_len]);

    let mut rendered = String::with_capacity(UNTRUSTED_DISPLAY_MAX_BYTES + 8);
    // Byte offset after each rendered character or escape sequence; the
    // truncation point is always one of these, so no escape is split.
    let mut boundaries: Vec<usize> = Vec::with_capacity(prefix_len);
    for c in decoded.chars() {
        if c == '\\' || c == '"' || is_untrusted_format_character(c) {
            rendered.extend(c.escape_default());
        } else {
            rendered.push(c);
        }
        boundaries.push(rendered.len());
    }

    if !input_cut && rendered.len() <= UNTRUSTED_DISPLAY_MAX_BYTES {
        return rendered;
    }
    let budget = UNTRUSTED_DISPLAY_MAX_BYTES - TRUNCATION_MARKER.len();
    let cut = boundaries
        .iter()
        .copied()
        .take_while(|&end| end <= budget)
        .last()
        .unwrap_or(0);
    rendered.truncate(cut);
    rendered.push_str(TRUNCATION_MARKER);
    rendered
}

/// Renders untrusted text for an approval surface, in full.
///
/// Backslash and every character [`is_untrusted_format_character`] names
/// (C0, DEL, C1, U+2028, U+2029 and every Unicode format character, category
/// Cf) are rendered as Rust escape sequences such as `\u{1b}` and
/// `\u{202e}`; every other character is kept.
/// Nothing is removed, so a value that carried such a character shows that
/// it did, and the escaped backslash keeps a literal `\u{1b}` in the input
/// distinguishable from an escaped control character. The result holds no
/// character a terminal or a browser interprets as a cursor movement, a
/// color change or a direction change.
///
/// Every approval surface renders memo text, asset codes, addresses and the
/// other summary fields through this one rule: the CLI writes the result to
/// the terminal, and the HTML surfaces HTML-escape the result.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::observability::redact::escape_untrusted_text;
///
/// assert_eq!(escape_untrusted_text("invoice 42"), "invoice 42");
/// assert_eq!(escape_untrusted_text("a\u{1b}[1Ab"), "a\\u{1b}[1Ab");
/// assert_eq!(escape_untrusted_text("a\u{202E}b"), "a\\u{202e}b");
/// assert_eq!(escape_untrusted_text("caf\u{e9}"), "caf\u{e9}");
/// ```
#[must_use]
pub fn escape_untrusted_text(text: &str) -> String {
    let mut rendered = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '\\' || is_untrusted_format_character(c) {
            rendered.extend(c.escape_default());
        } else {
            rendered.push(c);
        }
    }
    rendered
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "test-only assertions")]

    use super::*;

    #[test]
    fn untrusted_display_passes_short_printable_text_through() {
        assert_eq!(untrusted_display_bounded(b"blend-pool-v2"), "blend-pool-v2");
        assert_eq!(untrusted_display_bounded(b""), "");
    }

    #[test]
    fn untrusted_display_escapes_controls_quotes_backslash_and_bidi() {
        let input = "a\nb\u{1b}[31mc\"d\\e\u{202E}f\u{200B}g".as_bytes();
        assert_eq!(
            untrusted_display_bounded(input),
            "a\\nb\\u{1b}[31mc\\\"d\\\\e\\u{202e}f\\u{200b}g"
        );
    }

    #[test]
    fn untrusted_display_renders_invalid_utf8_lossily() {
        assert_eq!(untrusted_display_bounded(&[b'o', 0xff, b'k']), "o\u{FFFD}k");
    }

    #[test]
    fn untrusted_display_bounds_long_input_with_marker() {
        let long = vec![b'x'; 10_000];
        let out = untrusted_display_bounded(&long);
        assert_eq!(out.len(), UNTRUSTED_DISPLAY_MAX_BYTES);
        assert!(out.ends_with("..."));
        assert_eq!(&out[..UNTRUSTED_DISPLAY_MAX_BYTES - 3], "x".repeat(61));
    }

    #[test]
    fn untrusted_display_exactly_at_cap_is_not_truncated() {
        let exact = vec![b'y'; UNTRUSTED_DISPLAY_MAX_BYTES];
        assert_eq!(
            untrusted_display_bounded(&exact),
            "y".repeat(UNTRUSTED_DISPLAY_MAX_BYTES)
        );
        let over = vec![b'y'; UNTRUSTED_DISPLAY_MAX_BYTES + 1];
        let out = untrusted_display_bounded(&over);
        assert_eq!(out, format!("{}...", "y".repeat(61)));
    }

    #[test]
    fn untrusted_display_never_splits_an_escape_or_character() {
        // 20 control bytes render as 20 five-byte `\u{1}` escapes (100 bytes).
        let controls = vec![0x01u8; 20];
        let out = untrusted_display_bounded(&controls);
        assert!(out.len() <= UNTRUSTED_DISPLAY_MAX_BYTES);
        let body = out.strip_suffix("...").expect("truncated");
        assert_eq!(body, "\\u{1}".repeat(body.len() / 5));
        assert_eq!(body.len() % 5, 0);

        // Four-byte characters are never cut mid-sequence.
        let wide = "\u{1F680}".repeat(40);
        let out = untrusted_display_bounded(wide.as_bytes());
        assert!(out.len() <= UNTRUSTED_DISPLAY_MAX_BYTES);
        assert_eq!(out, format!("{}...", "\u{1F680}".repeat(15)));
    }

    #[test]
    fn escape_untrusted_text_renders_every_control_class_visibly() {
        assert_eq!(
            escape_untrusted_text("a\u{1b}[1A\u{1b}[2Kb"),
            "a\\u{1b}[1A\\u{1b}[2Kb"
        );
        assert_eq!(escape_untrusted_text("a\rb\nc\td"), "a\\rb\\nc\\td");
        assert_eq!(escape_untrusted_text("\u{0}\u{7f}"), "\\u{0}\\u{7f}");
        assert_eq!(escape_untrusted_text("\u{85}\u{9b}"), "\\u{85}\\u{9b}");
        for (control, escaped) in [
            ('\u{202A}', "\\u{202a}"),
            ('\u{202E}', "\\u{202e}"),
            ('\u{2066}', "\\u{2066}"),
            ('\u{2069}', "\\u{2069}"),
            ('\u{200B}', "\\u{200b}"),
            ('\u{FEFF}', "\\u{feff}"),
        ] {
            assert_eq!(
                escape_untrusted_text(&format!("x{control}y")),
                format!("x{escaped}y"),
                "{control:?}"
            );
        }
    }

    #[test]
    fn escape_untrusted_text_keeps_printable_text_and_escapes_backslash() {
        assert_eq!(
            escape_untrusted_text("Zahlung f\u{fc}r M\u{e4}rz"),
            "Zahlung f\u{fc}r M\u{e4}rz"
        );
        assert_eq!(
            escape_untrusted_text("\u{4e2d}\u{6587} \"q\" <b>"),
            "\u{4e2d}\u{6587} \"q\" <b>"
        );
        assert_eq!(escape_untrusted_text("a\\u{1b}b"), "a\\\\u{1b}b");
        assert_eq!(escape_untrusted_text(""), "");
    }

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
