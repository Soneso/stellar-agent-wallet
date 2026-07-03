//! Render-time sanitisation for attacker-controlled string fields.
//!
//! Fields like `token`, `key`, `detail`, `name`, and `dir` in
//! [`crate::ToolsetFormatError`] variants echo content authored by a third party
//! (the toolset author).  When these strings are rendered in a terminal,
//! log stream, or MCP JSON error response, they may contain:
//!
//! - ANSI escape sequences that can overwrite terminal state (terminal spoof).
//! - Newlines that inject false log lines (log injection).
//! - Excessively long content that floods log output (log amplification).
//!
//! This module provides [`sanitise_display`], which:
//!
//! 1. Truncates the string to `cap` Unicode scalar values (not bytes), appending
//!    `…` (U+2026 HORIZONTAL ELLIPSIS) if truncated so the reader knows the
//!    output was cut.
//! 2. Replaces all ASCII control characters (U+0000–U+001F, U+007F) and the
//!    DEL character with `?`.
//! 3. Strips ANSI CSI escape sequences of the form `ESC [ … m` (and other
//!    common `ESC [` sequences used for cursor control / erase).
//!
//! The function is public — it is called from the `Display` impls on
//! `ToolsetFormatError` via the `#[error]` format strings, and is intended for
//! reuse by the install layer for redacting I/O error paths in install errors.

/// Sanitise a string for safe inclusion in a rendered error message.
///
/// Truncates to `cap` Unicode scalar values, replacing control characters and
/// stripping ANSI CSI escape sequences.  Appends `…` (U+2026 HORIZONTAL ELLIPSIS)
/// if the value was truncated.
///
/// ## Truncation contract
///
/// The output contains at most `cap` Unicode scalar values from the input,
/// PLUS the single `…` character when truncation occurs.  A 256-character `cap`
/// therefore yields at most 257 scalar values in the truncated case.
/// ASCII control characters (U+0000–U+001F, U+007F) are replaced with `?`.
/// ANSI CSI sequences (`ESC [` … final-byte) and OSC sequences are stripped
/// entirely before the cap is applied.
///
/// ## Visibility
///
/// `sanitise_display` is `pub`.  Its behaviour is observable through the
/// `Display` impl of [`crate::ToolsetFormatError`] variants that carry
/// attacker-controlled strings (`token`, `key`, `detail`, `name`, `dir`),
/// and is intended for reuse by the install layer for redacting I/O error
/// paths and other attacker-influenced strings.
///
/// # Examples
///
/// ```
/// use stellar_agent_toolsets::ToolsetFormatError;
///
/// // A token with ANSI escape codes and a newline — the rendered error must
/// // not contain raw escape bytes or newlines.
/// let err = ToolsetFormatError::UnknownCapability {
///     token: "\x1b[31mbad\ntoken\x1b[0m".to_owned(),
/// };
/// let rendered = err.to_string();
/// assert!(!rendered.contains('\x1b'), "ANSI escape must be stripped");
/// assert_eq!(rendered.lines().count(), 1, "newline must be replaced");
/// ```
pub fn sanitise_display(value: &str, cap: usize) -> String {
    // Strip ANSI CSI escape sequences first: ESC (U+001B) followed by '[' and
    // any sequence of bytes up to a byte in 0x40-0x7E (the final byte of a CSI).
    let stripped = strip_ansi_csi(value);

    // Collect Unicode scalar values (chars) so that the cap is in code-points,
    // not bytes (avoids splitting multi-byte sequences).
    let chars: Vec<char> = stripped.chars().collect();
    let (truncated, was_truncated) = if chars.len() > cap {
        (&chars[..cap], true)
    } else {
        (&chars[..], false)
    };

    // Replace ASCII control characters with '?'.
    let mut out = String::with_capacity(truncated.len() + 3);
    for &ch in truncated {
        if ch.is_ascii_control() {
            out.push('?');
        } else {
            out.push(ch);
        }
    }

    if was_truncated {
        out.push('\u{2026}'); // U+2026 HORIZONTAL ELLIPSIS
    }

    out
}

/// Strip ANSI CSI escape sequences from `s`.
///
/// An ANSI CSI sequence is: ESC (0x1B) + '[' (0x5B) + zero or more parameter /
/// intermediate bytes (0x20–0x3F) + one final byte (0x40–0x7E).  We also strip
/// the two-byte ESC+letter sequences (`ESC c`, `ESC =`, etc.) and OSC sequences
/// (ESC + ']' + ... + BEL/ST) as a defence-in-depth measure.
fn strip_ansi_csi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\x1B' {
            // ESC — start of an escape sequence.
            match chars.peek() {
                Some(&'[') => {
                    // CSI: ESC [ ... final_byte(0x40-0x7E)
                    chars.next(); // consume '['
                    for inner in chars.by_ref() {
                        let b = inner as u32;
                        if (0x40..=0x7E).contains(&b) {
                            break; // consumed the final byte; done with this CSI
                        }
                        // parameter/intermediate bytes: 0x20-0x3F — consume and discard
                    }
                }
                Some(&']') => {
                    // OSC: ESC ] ... BEL or ESC \
                    chars.next(); // consume ']'
                    while let Some(inner) = chars.next() {
                        if inner == '\x07' {
                            break; // BEL terminates OSC
                        }
                        if inner == '\x1B' {
                            // ST = ESC \
                            if chars.peek() == Some(&'\\') {
                                chars.next();
                            }
                            break;
                        }
                    }
                }
                Some(_) => {
                    // Two-byte ESC+char (Fe sequence): discard both.
                    chars.next();
                }
                None => {
                    // Trailing ESC with no following char: discard.
                }
            }
        } else {
            out.push(ch);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn no_change_on_clean_string() {
        assert_eq!(sanitise_display("hello-world", 256), "hello-world");
    }

    #[test]
    fn truncation_appends_ellipsis() {
        let s = "abcde";
        let result = sanitise_display(s, 3);
        assert_eq!(result, "abc\u{2026}");
    }

    #[test]
    fn truncation_at_exact_cap_no_ellipsis() {
        let s = "abcde";
        let result = sanitise_display(s, 5);
        assert_eq!(result, "abcde");
    }

    #[test]
    fn control_chars_replaced_with_question_mark() {
        let s = "hello\nworld\x00end";
        let result = sanitise_display(s, 256);
        // newline (0x0A) is a control char; NUL (0x00) is a control char
        assert_eq!(result, "hello?world?end");
    }

    #[test]
    fn ansi_csi_colour_code_stripped() {
        // ESC [ 31 m (red text) before "foo" and ESC [ 0 m (reset) after
        let s = "\x1b[31mfoo\x1b[0m";
        let result = sanitise_display(s, 256);
        assert_eq!(result, "foo");
    }

    #[test]
    fn ansi_csi_cursor_move_stripped() {
        // ESC [ 2 J (erase display)
        let s = "before\x1b[2Jafter";
        let result = sanitise_display(s, 256);
        assert_eq!(result, "beforeafter");
    }

    #[test]
    fn osc_sequence_stripped() {
        // ESC ] 0 ; title BEL
        let s = "\x1b]0;window title\x07content";
        let result = sanitise_display(s, 256);
        assert_eq!(result, "content");
    }

    #[test]
    fn ten_kb_token_truncated_and_sanitised() {
        let big = "a".repeat(10_240);
        let result = sanitise_display(&big, 256);
        assert_eq!(result.chars().count(), 257); // 256 + ellipsis
        assert!(result.ends_with('\u{2026}'));
    }

    #[test]
    fn newline_in_token_replaced() {
        let s = "valid\nnewline";
        let result = sanitise_display(s, 256);
        assert!(!result.contains('\n'));
        assert!(result.contains('?'));
    }

    #[test]
    fn empty_string_unchanged() {
        assert_eq!(sanitise_display("", 256), "");
    }

    #[test]
    fn unicode_multibyte_cap_is_by_char_not_byte() {
        // "你好" is 6 bytes but 2 chars
        let s = "你好world";
        let result = sanitise_display(s, 4);
        // cap=4 chars: "你好wo" + ellipsis
        assert_eq!(result, "你好wo\u{2026}");
    }

    // ── ANSI strip paths: terminal-escape defence ─────────────────────────────
    //
    // Invariant asserted by every test below: the result contains no raw ESC
    // byte (0x1B), regardless of input.  This is a fail-closed property —
    // escape sequences are always stripped, never passed through.

    /// OSC sequence ended by ESC-backslash ST (`ESC \`).
    ///
    /// Input: `ESC ] 0 ; t ESC \ after`
    /// The OSC body is `0;t`; the ST terminator `ESC \` closes it.
    /// The trailing literal text `after` must survive.
    #[test]
    fn osc_st_terminator_stripped() {
        let input = "\x1b]0;t\x1b\\after";
        let result = sanitise_display(input, 256);
        assert!(
            !result.contains('\x1b'),
            "result must contain no ESC byte: {result:?}"
        );
        assert_eq!(result, "after", "text after ST-terminated OSC must survive");
    }

    /// OSC sequence with no BEL or ST terminator (drained to EOF).
    ///
    /// Input: `ESC ] 0 ; unterminated`
    /// The OSC body is never closed; the strip loop drains all remaining chars.
    /// Nothing survives to the output.
    #[test]
    fn osc_unterminated_drained_to_eof() {
        let input = "\x1b]0;unterminated";
        let result = sanitise_display(input, 256);
        assert!(
            !result.contains('\x1b'),
            "result must contain no ESC byte: {result:?}"
        );
        assert_eq!(
            result, "",
            "unterminated OSC drains all chars; output is empty"
        );
    }

    /// Two-byte Fe sequence (`ESC` + single char).
    ///
    /// Input: `a ESC c b`
    /// Both bytes of the Fe sequence (`ESC` + `c`) are discarded.
    /// The surrounding literal chars `a` and `b` survive.
    #[test]
    fn two_byte_fe_sequence_stripped() {
        let input = "a\x1bcb";
        let result = sanitise_display(input, 256);
        assert!(
            !result.contains('\x1b'),
            "result must contain no ESC byte: {result:?}"
        );
        assert_eq!(
            result, "ab",
            "surrounding chars survive; ESC+c is discarded"
        );
    }

    /// Trailing lone ESC with no following char.
    ///
    /// Input: `trail ESC`
    /// The ESC at the end of the string has no following char; it is discarded.
    #[test]
    fn trailing_lone_esc_stripped() {
        let input = "trail\x1b";
        let result = sanitise_display(input, 256);
        assert!(
            !result.contains('\x1b'),
            "result must contain no ESC byte: {result:?}"
        );
        assert_eq!(result, "trail", "trailing lone ESC is discarded");
    }
}
