//! The single HTML-escaping definition every server-rendered operator page
//! uses for dynamic text.
//!
//! [`html_escape`] escapes the five markup-significant ASCII characters and
//! replaces bidirectional and invisible-format code points with U+FFFD. It
//! lives here, beside [`brand`](crate::brand), because every serving crate
//! needs it and a second copy would drift: a page that escapes through a
//! different definition is a page whose escaping guarantees differ.
//!
//! The output is safe both as element text and as a double-quoted attribute
//! value. It is NOT safe in an unquoted attribute, in a `<script>` body, or in
//! a `<style>` body; no page places a dynamic value in any of those contexts.

/// `true` for a bidirectional-override or invisible-format code point.
///
/// U+061C (Arabic letter mark), U+200B..U+200F (zero-width space, joiners, and
/// the LTR/RTL marks), U+202A..U+202E (the embedding and override controls,
/// including U+202E RIGHT-TO-LEFT OVERRIDE), U+2066..U+2069 (the isolates),
/// and U+FEFF (zero-width no-break space).
const fn is_bidi_or_format_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
    )
}

/// HTML-escapes a string for safe interpolation into element text or a
/// double-quoted attribute value, and neutralises bidirectional and
/// invisible-format controls.
///
/// The five-character escaping stops a value from becoming markup. The control
/// substitution stops a value from lying about itself while staying valid text:
/// a memo or asset code carrying U+202E reverses the rendering of everything
/// after it, so an operator reading a destination or an amount on the decision
/// surface can see a different string than the one being signed. Every such
/// code point is replaced with U+FFFD, which is visible, so the tampering shows
/// rather than takes effect.
///
/// One pass covers both: the control set and the five escaped ASCII characters
/// are disjoint, so ordering between them cannot matter.
///
/// # Examples
///
/// ```
/// use stellar_agent_loopback_http::escape::html_escape;
///
/// assert_eq!(html_escape("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&#x27;");
/// assert_eq!(html_escape("a\u{202E}b"), "a\u{FFFD}b");
/// ```
#[must_use]
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c if is_bidi_or_format_control(c) => out.push('\u{FFFD}'),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_the_five_markup_characters() {
        assert_eq!(html_escape("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&#x27;");
    }

    #[test]
    fn a_script_payload_becomes_inert_text() {
        assert_eq!(
            html_escape("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
    }

    #[test]
    fn an_attribute_breakout_payload_is_neutralised() {
        assert_eq!(
            html_escape(r#"" onmouseover="x"#),
            "&quot; onmouseover=&quot;x"
        );
    }

    #[test]
    fn neutralises_bidi_and_invisible_format_controls() {
        for control in [
            '\u{061C}', '\u{200B}', '\u{200F}', '\u{202A}', '\u{202E}', '\u{2066}', '\u{2069}',
            '\u{FEFF}',
        ] {
            let escaped = html_escape(&format!("a{control}b"));
            assert_eq!(
                escaped, "a\u{FFFD}b",
                "control {control:?} must be replaced"
            );
        }
    }

    #[test]
    fn leaves_ordinary_non_ascii_text_intact() {
        assert_eq!(html_escape("a\u{00E9}\u{4E2D}b"), "a\u{00E9}\u{4E2D}b");
    }
}
