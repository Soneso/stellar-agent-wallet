//! Shared CLI output helpers.
//!
//! Single canonical implementation of the shared CLI output helpers;
//! `pay.rs` and `accounts/create.rs` delegate here.
//!
//! # Invariants
//!
//! - `render_json_to` is the sole call site for `Envelope<T>::to_json_compact`.
//!   `render_json` and every `print_success` / `print_error` fallback arm
//!   delegate to it.
//! - `sanitize_for_table` is the sole call site for stripping terminal-escape
//!   sequences from user-facing table output (N6).
//! - A command that computes a typed preview before its later stages reports
//!   one envelope: the preview rides in the success data or, through
//!   [`with_preview_detail`], in the failure's `error.details.preview`.
//! - A command whose output cannot be written exits `1`: [`render_json`] ends
//!   the process through [`exit_on_output_failure`], and [`write_envelope`]
//!   and [`exit_code_after_output`] map a write or flush failure to that code.

use std::io::Write;

use stellar_agent_core::envelope::Envelope;

/// Renders an `Envelope<T>` as compact JSON to stdout.
///
/// Used as the fallback for all non-table output formats so the JSON rendering
/// logic has a single implementation (M13).
///
/// Rendering is the last step of every command that calls this function. An
/// envelope that cannot be serialized, written, or flushed ends the process
/// through [`exit_on_output_failure`], so the command exits `1`.
///
/// # Panics
///
/// Never panics.
pub fn render_json<T: serde::Serialize>(envelope: &Envelope<T>) {
    if let Err(e) = render_json_to(&mut std::io::stdout().lock(), envelope) {
        exit_on_output_failure(&e);
    }
}

/// Reports an output failure on stderr and ends the process with exit code
/// `1`.
///
/// Invariant: a command never exits `0` without delivering its envelope. A
/// failed write or flush of stdout leaves the caller without the result, and
/// an error envelope cannot reach it either, so stderr carries the failure.
/// The standard library treats a write to a closed or read-only stdout
/// descriptor (`EBADF`) as successful, so that case never reaches this
/// function.
pub(crate) fn exit_on_output_failure(error: &std::io::Error) -> ! {
    report_output_failure_to(&mut std::io::stderr(), error);
    std::process::exit(1)
}

/// Renders an `Envelope<T>` as one line of compact JSON to `out` and flushes
/// it.
///
/// Production output goes through [`render_json`], which supplies stdout; a
/// command that takes its writer as a parameter passes it here so a test can
/// read exactly what the command prints.
///
/// # Errors
///
/// Returns the I/O error when the envelope cannot be serialized, written, or
/// flushed. The output is then incomplete, so the caller must not report
/// success; [`write_envelope`] maps the failure to exit code `1`.
pub(crate) fn render_json_to<T: serde::Serialize>(
    out: &mut dyn Write,
    envelope: &Envelope<T>,
) -> std::io::Result<()> {
    let json = envelope
        .to_json_compact()
        .map_err(|e| std::io::Error::other(format!("JSON serialization failed: {e}")))?;
    writeln!(out, "{json}")?;
    out.flush()
}

/// Writes `envelope` to `out` and returns `exit_code`, or reports the output
/// failure on stderr and returns `1`.
///
/// A command whose result envelope cannot reach its writer has not reported
/// that result, so it exits `1` even when the result was a success. An error
/// envelope cannot be written either, so the failure goes to stderr.
#[must_use]
pub(crate) fn write_envelope<T: serde::Serialize>(
    out: &mut dyn Write,
    envelope: &Envelope<T>,
    exit_code: i32,
) -> i32 {
    write_envelope_reporting_to(out, &mut std::io::stderr(), envelope, exit_code)
}

/// [`write_envelope`] with the diagnostic stream injected, so a test can read
/// the failure line.
fn write_envelope_reporting_to<T: serde::Serialize>(
    out: &mut dyn Write,
    diagnostics: &mut dyn Write,
    envelope: &Envelope<T>,
    exit_code: i32,
) -> i32 {
    exit_code_reporting_to(diagnostics, render_json_to(out, envelope), exit_code)
}

/// Returns `exit_code` when the output reached its writer, and otherwise
/// reports the failure on stderr and returns `1`.
#[must_use]
pub(crate) fn exit_code_after_output(written: std::io::Result<()>, exit_code: i32) -> i32 {
    exit_code_reporting_to(&mut std::io::stderr(), written, exit_code)
}

/// [`exit_code_after_output`] with the diagnostic stream injected, so a test
/// can read the failure line.
fn exit_code_reporting_to(
    diagnostics: &mut dyn Write,
    written: std::io::Result<()>,
    exit_code: i32,
) -> i32 {
    match written {
        Ok(()) => exit_code,
        Err(e) => {
            report_output_failure_to(diagnostics, &e);
            1
        }
    }
}

/// Writes the output-failure line to `diagnostics`, normally stderr, the one
/// stream left to carry it.
///
/// A failure to write this line leaves nothing further to report to, so it
/// is ignored; the exit code still records the failure.
fn report_output_failure_to(diagnostics: &mut dyn Write, error: &std::io::Error) {
    let _ = writeln!(
        diagnostics,
        "stellar-agent: writing the command output failed: {error}"
    );
}

/// A success payload with the command's typed preview beside its fields.
///
/// Serializes as the fields of `result` followed by `preview`; an absent
/// preview is omitted.
#[derive(Debug, serde::Serialize)]
pub(crate) struct WithPreview<T: serde::Serialize, P: serde::Serialize> {
    /// The command's success payload.
    #[serde(flatten)]
    pub(crate) result: T,
    /// The typed preview the command computed before its later stages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) preview: Option<P>,
}

/// Places `preview` at `error.details.preview` of a failure envelope.
///
/// A failure after a command's preview stage still reports the preview, so
/// the operator sees what the command was about to sign. Every field the
/// failure's `details` object already carries is kept beside it. A `details`
/// value that is not an object, such as a string, is kept under
/// `details.detail` so the preview can sit beside it. An envelope without an
/// error is returned unchanged.
#[must_use]
pub(crate) fn with_preview_detail(
    mut envelope: Envelope<()>,
    preview: serde_json::Value,
) -> Envelope<()> {
    if let Some(error) = envelope.error.as_mut() {
        let mut details = match error.details.take() {
            Some(serde_json::Value::Object(map)) => map,
            Some(other) => {
                let mut map = serde_json::Map::new();
                map.insert("detail".to_owned(), other);
                map
            }
            None => serde_json::Map::new(),
        };
        details.insert("preview".to_owned(), preview);
        error.details = Some(serde_json::Value::Object(details));
    }
    envelope
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

/// Parses `bytes` as exactly one JSON document and panics on anything else,
/// trailing content included.
///
/// Test support for the commands that take their output writer as a
/// parameter: what they wrote must be one envelope.
#[cfg(test)]
#[allow(clippy::panic, reason = "test-only assertion helper")]
pub(crate) fn single_json_document(bytes: &[u8]) -> serde_json::Value {
    let text = String::from_utf8_lossy(bytes);
    let mut stream = serde_json::Deserializer::from_slice(bytes).into_iter::<serde_json::Value>();
    let first = match stream.next() {
        Some(Ok(value)) => value,
        Some(Err(e)) => panic!("output is not JSON ({e}): {text}"),
        None => panic!("output holds no JSON document: {text:?}"),
    };
    assert!(
        stream.next().is_none(),
        "output must hold exactly one JSON document: {text}"
    );
    first
}

/// Test support: a writer that fails at one point of the output path.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum FailingWriter {
    /// Every `write` fails.
    Write,
    /// Writes succeed and `flush` fails.
    Flush,
}

#[cfg(test)]
impl Write for FailingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Write => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "write refused",
            )),
            Self::Flush => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Write => Ok(()),
            Self::Flush => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "flush refused",
            )),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "test-only assertions")]

    use super::*;

    #[test]
    fn render_json_to_writes_one_compact_line() {
        let mut out = Vec::new();
        let written = render_json_to(
            &mut out,
            &Envelope::ok_with_request_id(serde_json::json!({ "a": 1 }), "id".to_owned()),
        );
        assert!(written.is_ok(), "{written:?}");
        assert_eq!(
            String::from_utf8(out.clone()).unwrap_or_default(),
            "{\"ok\":true,\"data\":{\"a\":1},\"request_id\":\"id\"}\n"
        );
        assert_eq!(single_json_document(&out)["data"]["a"], 1);
    }

    /// A write failure and a flush failure each surface as an error, and a
    /// success envelope that cannot be written exits `1`.
    #[test]
    fn an_output_failure_is_an_error_and_exits_one() {
        let envelope = Envelope::ok(serde_json::json!({ "a": 1 }));
        for mut writer in [FailingWriter::Write, FailingWriter::Flush] {
            let error = render_json_to(&mut writer, &envelope).expect_err("output must fail");
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe, "{writer:?}");
            assert_eq!(write_envelope(&mut writer, &envelope, 0), 1, "{writer:?}");
        }
        assert_eq!(write_envelope(&mut Vec::new(), &envelope, 0), 0);
    }

    /// An error envelope that cannot be written or flushed exits `1` and
    /// names the output failure on the diagnostic stream.
    #[test]
    fn an_undeliverable_error_envelope_names_the_failure_on_stderr() {
        let envelope = Envelope::<()>::err_raw("network.rpc_unreachable", "unreachable");
        for (mut writer, cause) in [
            (FailingWriter::Write, "write refused"),
            (FailingWriter::Flush, "flush refused"),
        ] {
            let mut diagnostics = Vec::new();
            let code = write_envelope_reporting_to(&mut writer, &mut diagnostics, &envelope, 1);
            assert_eq!(code, 1, "{writer:?}");
            assert_eq!(
                String::from_utf8_lossy(&diagnostics),
                format!("stellar-agent: writing the command output failed: {cause}\n"),
                "{writer:?}"
            );
        }
    }

    /// A delivered envelope keeps the caller's exit code, nonzero included,
    /// and writes nothing to the diagnostic stream.
    #[test]
    fn a_delivered_envelope_keeps_the_callers_code() {
        let envelope = Envelope::<()>::err_raw("network.rpc_unreachable", "unreachable");
        let mut out = Vec::new();
        let mut diagnostics = Vec::new();
        assert_eq!(
            write_envelope_reporting_to(&mut out, &mut diagnostics, &envelope, 7),
            7
        );
        assert_eq!(
            single_json_document(&out)["error"]["code"],
            "network.rpc_unreachable"
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(exit_code_reporting_to(&mut diagnostics, Ok(()), 7), 7);
        assert_eq!(exit_code_after_output(Ok(()), 7), 7);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    /// The helper the single-envelope tests rely on refuses a second
    /// document.
    #[test]
    #[should_panic(expected = "exactly one JSON document")]
    fn single_json_document_refuses_a_second_document() {
        single_json_document(b"{\"ok\":true}\n{\"ok\":false}\n");
    }

    /// The preview lands beside the detail a failure already carries.
    #[test]
    fn with_preview_detail_keeps_existing_object_fields() {
        let envelope = Envelope::<()>::err_raw_with_details(
            "submission.tx_timeout",
            "not confirmed",
            serde_json::json!({ "tx_hash": "ab" }),
        );
        let envelope = with_preview_detail(envelope, serde_json::json!({ "code": "USDC" }));
        let details = envelope
            .error
            .as_ref()
            .and_then(|e| e.details.clone())
            .unwrap_or_default();
        assert_eq!(
            details,
            serde_json::json!({ "tx_hash": "ab", "preview": { "code": "USDC" } })
        );
    }

    #[test]
    fn with_preview_detail_creates_details_on_a_plain_failure() {
        let envelope = with_preview_detail(
            Envelope::<()>::err_raw("trustline.invalid_fee", "bad fee"),
            serde_json::json!({ "code": "USDC" }),
        );
        let error = envelope.error.as_ref();
        assert_eq!(
            error.map(|e| e.code.as_str()),
            Some("trustline.invalid_fee")
        );
        assert_eq!(
            error.and_then(|e| e.details.clone()),
            Some(serde_json::json!({ "preview": { "code": "USDC" } }))
        );
    }

    #[test]
    fn with_preview_detail_keeps_a_non_object_detail() {
        let envelope =
            Envelope::<()>::err_raw_with_details("x.y", "message", serde_json::json!("scalar"));
        let envelope = with_preview_detail(envelope, serde_json::json!({ "code": "USDC" }));
        assert_eq!(
            envelope.error.and_then(|e| e.details),
            Some(serde_json::json!({ "detail": "scalar", "preview": { "code": "USDC" } }))
        );
    }

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
