//! Shared CLI output helpers.
//!
//! Single canonical implementation of the shared CLI output helpers;
//! `pay.rs` and `accounts/create.rs` delegate here.
//!
//! # Invariants
//!
//! - `render_json` is the sole call site for `Envelope<T>::to_json_compact`.
//!   All `print_success` / `print_error` fallback arms delegate here (M13).
//! - `sanitize_for_table` is the sole call site for stripping terminal-escape
//!   sequences from user-facing table output (N6).

use stellar_agent_core::envelope::Envelope;

/// Renders an `Envelope<T>` as compact JSON to stdout.
///
/// Used as the fallback for all non-table output formats so the JSON rendering
/// logic has a single implementation (M13).
///
/// # Panics
///
/// Never panics. Serialisation failures are reported to stderr as a fatal
/// diagnostic and do not unwind.
pub fn render_json<T: serde::Serialize>(envelope: &Envelope<T>) {
    #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
    match envelope.to_json_compact() {
        Ok(json) => println!("{json}"),
        Err(e) => {
            #[allow(clippy::print_stderr, reason = "fatal serialisation failure")]
            {
                eprintln!("stellar-agent: JSON serialisation failed: {e}");
            }
        }
    }
}

/// Strips non-ASCII-printable characters from a string for safe table rendering.
///
/// Filters out any character that is not `is_ascii_graphic()` or a plain space,
/// preventing terminal-escape injection in `--output table` output (N6).
///
/// # Examples
///
/// ```text
/// // sanitize_for_table("hello\x1b[1mworld\x07") strips ESC and BEL,
/// // leaving "hello[1mworld" (only non-graphic ASCII is stripped).
/// ```
#[must_use]
pub fn sanitize_for_table(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_escape_and_control_chars() {
        let input = "hello\x1b[1mworld\x07";
        let sanitized = sanitize_for_table(input);
        assert!(!sanitized.contains('\x1b'), "escape must be stripped");
        assert!(!sanitized.contains('\x07'), "bell must be stripped");
        assert!(sanitized.contains("hello"), "printable chars must survive");
    }

    #[test]
    fn sanitize_preserves_printable_ascii_and_space() {
        let input = "error 0x6511 app not open";
        assert_eq!(sanitize_for_table(input), input);
    }

    #[test]
    fn sanitize_strips_non_ascii_unicode() {
        // Unicode characters are not ascii_graphic.
        let input = "abc\u{00E9}def"; // 'é'
        let out = sanitize_for_table(input);
        assert_eq!(out, "abcdef");
    }

    #[test]
    fn sanitize_empty_input_returns_empty() {
        assert_eq!(sanitize_for_table(""), "");
    }
}
