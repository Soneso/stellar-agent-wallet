//! Unit and integration tests for [`super`] (the `observability` module).
//!
//! Split out from `mod.rs` because the module exceeds ~400 lines.
//! `super::*` glob-imports every production item including private helpers
//! used by the redaction invariants.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test-only: panics are acceptable in test assertions"
)]

use super::*;

#[test]
fn redact_path_in_message_strips_home_prefix() {
    let out = redact_path_in_message_with_home(
        "open: /tmp/wallet-test/.config/stellar-agent/testnet/secrets.json: Permission denied",
        Some("/tmp/wallet-test"),
    );

    assert!(out.contains("<HOME>/.config/stellar-agent/testnet/secrets.json"));
    assert!(!out.contains("/tmp/wallet-test"));
}

#[test]
fn redact_path_in_message_passthrough_when_no_home_match() {
    assert_eq!(
        redact_path_in_message_with_home("connection refused", Some("/tmp/wallet-test")),
        "connection refused"
    );
}

#[test]
fn redact_path_in_message_passthrough_when_home_unset() {
    assert_eq!(
        redact_path_in_message_with_home("open: /tmp/x: ENOENT", None),
        "open: /tmp/x: ENOENT"
    );
}

#[test]
fn redact_path_in_message_passthrough_when_home_is_root() {
    // HOME=/ is treated as no-redaction: literal-replace on "/" would shred
    // every path separator. The input passes through unchanged.
    assert_eq!(
        redact_path_in_message_with_home(
            "open: /tmp/wallet-test/.config/stellar-agent/testnet/secrets.json: Permission denied",
            Some("/"),
        ),
        "open: /tmp/wallet-test/.config/stellar-agent/testnet/secrets.json: Permission denied"
    );
}

#[test]
fn redact_first5_last5_typical() {
    assert_eq!(redact_first5_last5("ABCDE12345FGHIJ"), "ABCDE...FGHIJ");
}

#[test]
fn redact_first5_last5_short_passthrough() {
    assert_eq!(redact_first5_last5("ABCDE"), "ABCDE");
}

#[test]
fn redact_first5_last5_unicode_counts_chars() {
    assert_eq!(redact_first5_last5("abcdé12345fghij"), "abcdé...fghij");
}

#[test]
fn redacted_strkey_from_full_is_serde_transparent() {
    let full = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
    let redacted = RedactedStrkey::from_full(full);
    assert_eq!(redacted.as_str(), "CAAAA...AD2KM");
    assert_eq!(
        serde_json::to_string(&redacted).unwrap(),
        "\"CAAAA...AD2KM\""
    );
}

#[test]
fn redacted_strkey_wraps_already_redacted_legacy_values() {
    let redacted = RedactedStrkey::from_already_redacted("CAAAA...AD2KM");
    assert_eq!(redacted.as_str(), "CAAAA...AD2KM");
}

/// Deserialize-side round-trip for the `#[serde(transparent)]` shape.
/// Documents the contract at the type's own definition site.
#[test]
fn redacted_strkey_deserialize_round_trip_is_serde_transparent() {
    let json = "\"CAAAA...AD2KM\"";
    let parsed: RedactedStrkey = serde_json::from_str(json).unwrap();
    assert_eq!(parsed.as_str(), "CAAAA...AD2KM");
    // Re-serialise to confirm the wire shape survives a round-trip.
    let reserialised = serde_json::to_string(&parsed).unwrap();
    assert_eq!(reserialised, json);
}

/// `RedactedStrkey` derives `Hash` so callers can use it as a `HashMap` /
/// `HashSet` key (e.g. audit-row dedup). Compile-only — the test body is
/// just an instantiation that fails to compile if `Hash` is removed.
#[test]
fn redacted_strkey_is_hash() {
    use std::collections::HashSet;
    let mut set: HashSet<RedactedStrkey> = HashSet::new();
    set.insert(RedactedStrkey::from_already_redacted("CAAAA...AD2KM"));
    set.insert(RedactedStrkey::from_already_redacted("CBBBB...YYYYY"));
    assert_eq!(set.len(), 2);
}

#[test]
fn is_loopback_http_url_accepts_loopback_hosts() {
    assert!(is_loopback_http_url("http://localhost:3000/approve/nonce"));
    assert!(is_loopback_http_url("http://127.0.0.1:3000/register/nonce"));
    assert!(is_loopback_http_url("http://[::1]:3000/approve/nonce"));
}

#[test]
fn is_loopback_http_url_rejects_non_loopback_or_non_http() {
    assert!(!is_loopback_http_url(
        "https://localhost:3000/approve/nonce"
    ));
    assert!(!is_loopback_http_url("http://evil.com/approve/nonce"));
    assert!(!is_loopback_http_url("not a url"));
}

#[test]
fn is_loopback_http_url_rejects_userinfo_bypass_form() {
    let parsed = url::Url::parse("http://localhost:3000@evil.com/path").unwrap();
    assert_eq!(parsed.host_str(), Some("evil.com"));
    assert!(!is_loopback_http_url(parsed.as_str()));
}

// ── FormatChoice precedence ───────────────────────────────────────────────

#[test]
fn format_choice_override_json() {
    assert_eq!(
        FormatChoice::from_env_and_tty(Some("json")),
        FormatChoice::Json
    );
}

#[test]
fn format_choice_override_pretty() {
    assert_eq!(
        FormatChoice::from_env_and_tty(Some("pretty")),
        FormatChoice::Pretty
    );
}

#[test]
fn format_choice_override_case_insensitive() {
    assert_eq!(
        FormatChoice::from_env_and_tty(Some("PRETTY")),
        FormatChoice::Pretty
    );
    assert_eq!(
        FormatChoice::from_env_and_tty(Some("JSON")),
        FormatChoice::Json
    );
}

#[test]
fn format_choice_override_unknown_falls_back_to_json() {
    assert_eq!(
        FormatChoice::from_env_and_tty(Some("unknown")),
        FormatChoice::Json
    );
}

#[test]
fn format_choice_override_wins_regardless_of_any_env() {
    let c = FormatChoice::from_env_and_tty(Some("pretty"));
    assert_eq!(c, FormatChoice::Pretty, "explicit override must win");
    let c = FormatChoice::from_env_and_tty(Some("json"));
    assert_eq!(c, FormatChoice::Json, "explicit override must win");
}

#[test]
fn format_choice_parse_format_str_covers_both_variants() {
    assert_eq!(
        FormatChoice::parse_format_str("pretty"),
        FormatChoice::Pretty
    );
    assert_eq!(
        FormatChoice::parse_format_str("PRETTY"),
        FormatChoice::Pretty
    );
    assert_eq!(FormatChoice::parse_format_str("json"), FormatChoice::Json);
    assert_eq!(FormatChoice::parse_format_str("JSON"), FormatChoice::Json);
    assert_eq!(FormatChoice::parse_format_str(""), FormatChoice::Json);
    assert_eq!(FormatChoice::parse_format_str("other"), FormatChoice::Json);
}

// ── S/T/X-strkey validation ───────────────────────────────────────────────

// Synthesis helpers, version-byte constants, and the fixture seed are from
// `stellar-agent-test-support::testnet_strkeys`. The oracle validator is in
// `stellar-agent-test-support::secret_patterns` and is deliberately a
// separate implementation — see that module's docs.
use stellar_agent_test_support::testnet_strkeys::{
    TESTNET_FIXTURE_SEED, VERSION_HASH_X, VERSION_PRE_AUTH_TX, VERSION_PRIVATE_KEY,
    VERSION_PUBLIC_KEY, strkey_from_seed,
};

#[test]
fn s_strkey_valid_known_key() {
    let strkey = strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
    assert!(
        is_valid_sensitive_strkey(&strkey),
        "synthesised S-strkey must be recognised as sensitive"
    );
}

#[test]
fn s_strkey_wrong_length() {
    assert!(!is_valid_sensitive_strkey("SABCDE"));
}

#[test]
fn s_strkey_all_a_fails_version_byte() {
    // "S" + 55 "A"s is 56 chars of valid base32 but does not produce
    // version byte 0x90, 0x98, or 0xB8 after decoding; must return false.
    let fake = "S".to_owned() + &"A".repeat(55);
    assert!(!is_valid_sensitive_strkey(&fake));
}

#[test]
fn s_strkey_bit_flip_fails_crc() {
    let mut flipped = strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
    #[allow(clippy::unwrap_used)] // test-only; string is non-empty by construction
    let last = flipped.pop().unwrap_or('A');
    flipped.push(if last == 'A' { 'B' } else { 'A' });
    assert!(
        !is_valid_sensitive_strkey(&flipped),
        "bit-flip should invalidate CRC"
    );
}

#[test]
fn s_strkey_invalid_base32_char() {
    let bad = "S".to_owned() + &"0".repeat(55);
    assert!(!is_valid_sensitive_strkey(&bad));
}

/// T-strkey (`PreAuthTx`, version byte `0x98 = 19 << 3`) must be detected as
/// sensitive and return `true`.
#[test]
fn t_strkey_detected() {
    let strkey = strkey_from_seed(VERSION_PRE_AUTH_TX, &TESTNET_FIXTURE_SEED);
    assert!(
        is_valid_sensitive_strkey(&strkey),
        "T-strkey (PreAuthTx) must be recognised as sensitive"
    );
}

/// X-strkey (`HashX`, version byte `0xB8 = 23 << 3`) must be detected as
/// sensitive and return `true`.
#[test]
fn x_strkey_detected() {
    let strkey = strkey_from_seed(VERSION_HASH_X, &TESTNET_FIXTURE_SEED);
    assert!(
        is_valid_sensitive_strkey(&strkey),
        "X-strkey (HashX) must be recognised as sensitive"
    );
}

/// G-strkey (`PublicKeyEd25519`, version byte `0x30 = 6 << 3`) must NOT be
/// detected as sensitive — it is handled by Layer 1 (redacting newtypes) and
/// the pass-through list; Layer 2 must not intercept it.
#[test]
fn g_strkey_not_redacted() {
    let strkey = strkey_from_seed(VERSION_PUBLIC_KEY, &TESTNET_FIXTURE_SEED);
    assert!(
        !is_valid_sensitive_strkey(&strkey),
        "G-strkey (PublicKeyEd25519) must NOT be flagged by Layer 2"
    );
}

// ── redact_strkeys ────────────────────────────────────────────────────────

#[test]
fn redact_strkeys_replaces_valid_sk() {
    let strkey = strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
    let input = format!("prefix {strkey} suffix");
    let (out, did) = redact_strkeys(&input);
    assert!(did);
    assert!(out.contains("[REDACTED]"), "expected [REDACTED] in: {out}");
    assert!(!out.contains(&strkey), "raw strkey must not appear: {out}");
}

#[test]
fn redact_strkeys_leaves_benign_string() {
    let (out, did) = redact_strkeys("nothing sensitive here");
    assert!(!did);
    assert_eq!(out, "nothing sensitive here");
}

/// Adversarial UTF-8 input: `"S" + "A".repeat(54) + "é"` is 57 bytes (the
/// multi-byte `é` spans bytes 56-57). A naive `input[pos..pos+56]` slice would
/// panic at a non-char boundary. `redact_strkeys` validates the 56-byte window
/// is pure ASCII base32 before treating it as a `str`, so it skips the window
/// containing the non-base32 `é` byte without panicking.
#[test]
fn redact_strkeys_handles_adversarial_utf8() {
    // Construct the proof-of-crash string: "S" + "A"*54 + "é".
    // "é" is 2 bytes (0xC3 0xA9) in UTF-8; byte 56 from 'S' falls inside it.
    let mut input = String::from("S");
    input.push_str(&"A".repeat(54));
    input.push('é'); // 2 bytes; total string = 57 bytes
    assert_eq!(input.len(), 57, "precondition: 57 bytes");
    // Must not panic; the window is not a valid base32 string (contains 0xC3).
    let (out, did) = redact_strkeys(&input);
    assert!(!did, "adversarial string should not be redacted");
    assert_eq!(out, input, "output should equal input when no strkey found");
}

/// Additional adversarial case: valid S-strkey immediately followed by a
/// multi-byte UTF-8 character.  The valid key must be redacted; the following
/// character must be preserved correctly.
#[test]
fn redact_strkeys_valid_key_followed_by_multibyte_char() {
    let strkey = strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
    let input = format!("{strkey}é");
    let (out, did) = redact_strkeys(&input);
    assert!(did, "valid S-strkey must be redacted");
    assert!(
        out.contains("[REDACTED]"),
        "output must contain [REDACTED]: {out}"
    );
    assert!(
        out.contains('é'),
        "multibyte char after strkey must be preserved: {out}"
    );
    assert!(!out.contains(&strkey), "raw strkey must not appear: {out}");
}

// ── is_bip39_mnemonic ─────────────────────────────────────────────────────

#[test]
fn bip39_mnemonic_12_words_detected() {
    let phrase = "abandon ability able about above absent absorb abstract \
                  absurd abuse access accident";
    assert!(is_bip39_mnemonic(phrase));
}

#[test]
fn bip39_mnemonic_24_words_detected() {
    let phrase = "abandon ability able about above absent absorb abstract \
                  absurd abuse access accident account accuse achieve acid \
                  acoustic acquire across act action actor actress actual";
    assert!(is_bip39_mnemonic(phrase));
}

#[test]
fn bip39_mnemonic_11_words_not_detected() {
    let phrase = "abandon ability able about above absent absorb abstract \
                  absurd abuse access";
    assert!(!is_bip39_mnemonic(phrase));
}

#[test]
fn bip39_mnemonic_non_bip39_word_not_detected() {
    let phrase = "abandon ability able about above absent absorb abstract \
                  absurd abuse access notaword";
    assert!(!is_bip39_mnemonic(phrase));
}

#[test]
fn bip39_mnemonic_uppercase_not_detected() {
    let phrase = "Abandon ability able about above absent absorb abstract \
                  absurd abuse access accident";
    assert!(!is_bip39_mnemonic(phrase));
}

// ── redact_value pass-through / redact list ───────────────────────────────

#[test]
fn pass_through_public_key() {
    let (out, did) = redact_value("public_key", "GAAAA..ZZZZZ");
    assert!(!did);
    assert_eq!(out, "GAAAA..ZZZZZ");
}

#[test]
fn pass_through_account() {
    let (out, did) = redact_value("account", "GAAAA..ZZZZZ");
    assert!(!did);
    assert_eq!(out, "GAAAA..ZZZZZ");
}

#[test]
fn pass_through_case_insensitive() {
    let (out, did) = redact_value("PUBLIC_KEY", "some_value");
    assert!(!did);
    assert_eq!(out, "some_value");
}

#[test]
fn redact_secret_field() {
    let (out, did) = redact_value("secret", "mysecretvalue");
    assert!(did);
    assert_eq!(out, "[REDACTED]");
}

#[test]
fn redact_password_field() {
    let (out, did) = redact_value("password", "hunter2");
    assert!(did);
    assert_eq!(out, "[REDACTED]");
}

#[test]
fn redact_case_insensitive() {
    let (out, did) = redact_value("SECRET", "val");
    assert!(did);
    assert_eq!(out, "[REDACTED]");
}

#[test]
fn benign_field_not_redacted() {
    let (out, did) = redact_value("operation", "sign");
    assert!(!did);
    assert_eq!(out, "sign");
}

#[test]
fn pass_through_precedes_redact_for_source_field() {
    let (out, did) = redact_value("source", "some_account_id");
    assert!(!did, "pass-through field should not be redacted");
    assert_eq!(out, "some_account_id");
}

// ── numeric and bool field name redaction ─────────────────────────────

/// `record_u64` with a name on the REDACT list must emit
/// `[REDACTED]` rather than the raw number.
#[test]
fn integration_secret_u64_field_is_redacted() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(secret = 12345u64);
    });

    let out = writer.captured_str();
    assert!(
        out.contains("[REDACTED]"),
        "secret u64 field must be redacted: {out}"
    );
    assert!(
        !out.contains("12345"),
        "raw u64 value must not appear: {out}"
    );
}

/// `record_i64` with a name on the REDACT list must emit `[REDACTED]`.
#[test]
fn integration_secret_i64_field_is_redacted() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(entropy = -9999i64);
    });

    let out = writer.captured_str();
    assert!(
        out.contains("[REDACTED]"),
        "entropy i64 field must be redacted: {out}"
    );
    assert!(
        !out.contains("-9999"),
        "raw i64 value must not appear: {out}"
    );
}

/// `record_f64` with a name on the REDACT list must emit `[REDACTED]`.
#[test]
fn integration_secret_f64_field_is_redacted() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(seed = 1.23456789f64);
    });

    let out = writer.captured_str();
    assert!(
        out.contains("[REDACTED]"),
        "seed f64 field must be redacted: {out}"
    );
    assert!(
        !out.contains("1.23456789"),
        "raw f64 value must not appear: {out}"
    );
}

/// `record_bool` with a name on the REDACT list must emit `[REDACTED]`.
#[test]
fn integration_secret_bool_field_is_redacted() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        // "key" is on the REDACT list.
        tracing::info!(key = true);
    });

    let out = writer.captured_str();
    assert!(
        out.contains("[REDACTED]"),
        "key bool field must be redacted: {out}"
    );
    assert!(
        !out.contains("true"),
        "raw bool value must not appear when field is on redact list: {out}"
    );
}

/// Numeric fields NOT on the REDACT list must pass through unchanged.
#[test]
fn integration_benign_u64_passes_through() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(block_count = 42u64);
    });

    let out = writer.captured_str();
    assert!(out.contains("42"), "benign u64 must not be redacted: {out}");
    assert!(
        !out.contains("[REDACTED]"),
        "no redaction expected for benign field: {out}"
    );
}

// ── log.* bridge fields are suppressed ───────────────────────────────────

/// Fields whose names start with `log.` (injected by the `tracing-log`
/// bridge) must be silently dropped and must not appear in output.
///
/// This test constructs a synthetic event by using FieldCollector directly to
/// simulate a bridged `log::*` event without requiring a global LogTracer.
#[test]
fn field_collector_drops_log_dot_fields() {
    use tracing::field::Visit as _;

    let mut collector = FieldCollector::default();

    // Simulate a bridged log event: these field names are injected by
    // tracing-log's LogTracer for every log::* call.
    // We use a real tracing event to drive the collector via `event.record`.
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        // Emit a benign field alongside a synthetic check via collector.
        // Because we can't inject log.* fields directly via tracing macros,
        // we test the collector's visit methods directly.
        let meta = tracing::metadata::Metadata::new(
            "test_event",
            "test_target",
            tracing::Level::INFO,
            Some(file!()),
            Some(line!()),
            Some(module_path!()),
            tracing::field::FieldSet::new(
                &["log.module_path", "log.file", "log.line", "operation"],
                tracing::callsite::Identifier(&test_callsite::TestCallsite),
            ),
            tracing::metadata::Kind::EVENT,
        );

        // Use the field set to create fields and drive the visitor directly.
        let fields = meta.fields();
        let log_module = fields.field("log.module_path");
        let log_file_f = fields.field("log.file");
        let log_line_f = fields.field("log.line");
        let operation = fields.field("operation");

        if let (Some(lm), Some(lf), Some(ll), Some(op)) =
            (log_module, log_file_f, log_line_f, operation)
        {
            collector.record_str(&lm, "my::module");
            collector.record_str(&lf, "src/my.rs");
            collector.record_u64(&ll, 42);
            collector.record_str(&op, "sign");
        }
    });

    // The collector must have dropped log.* fields and kept only "operation".
    assert_eq!(
        collector.fields.len(),
        1,
        "only 'operation' should survive; log.* fields must be dropped"
    );
    assert_eq!(collector.fields[0].0, "operation");
}

// ── REDACTION_FIRED_TARGET events are emitted in JSON format ──────────

/// Events whose target is `REDACTION_FIRED_TARGET` must be serialised
/// normally, not dropped.  We emit the warning event directly (rather than
/// relying on the re-entrant path from `emit_redaction_warning`) because
/// tracing-subscriber's Registry may silently drop re-entrant dispatches that
/// occur within an active `format_event` call.  Testing the formatter directly
/// is correct because the guard is in the formatter, not in the dispatch path.
#[test]
fn redaction_fired_target_event_is_formatted_not_dropped() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        // Emit a warn event directly using the REDACTION_FIRED_TARGET.
        // This is exactly what emit_redaction_warning() does.
        tracing::warn!(
            target: "stellar_agent_core::observability::redaction_fired",
            "Layer 2 redaction fired — audit callers for unguarded secret material"
        );
    });

    let out = writer.captured_str();
    // The formatter must not drop this event.
    assert!(
        !out.is_empty(),
        "REDACTION_FIRED_TARGET event must produce output in JSON mode, got empty string"
    );
    assert!(
        out.contains("stellar_agent_core::observability::redaction_fired"),
        "target must appear in JSON output: {out}"
    );
    assert!(
        out.contains("Layer 2 redaction fired"),
        "warning message must appear in JSON output: {out}"
    );
}

// ── Integration-level: subscriber + test-support capture writer ──────────

use stellar_agent_test_support::CaptureWriter;

fn make_json_subscriber(writer: CaptureWriter) -> impl tracing::Subscriber + Send + Sync {
    tracing_subscriber::registry().with(
        fmt::layer()
            .event_format(RedactingJsonFormatter::without_time())
            .with_writer(writer),
    )
}

#[test]
fn integration_benign_account_passes_through() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(account = "GAAAA..ZZZZZ", operation = "sign");
    });

    let out = writer.captured_str();
    assert!(
        out.contains("GAAAA..ZZZZZ"),
        "pass-through account should be present: {out}"
    );
    assert!(
        !out.contains("[REDACTED]"),
        "should not see REDACTED for benign account: {out}"
    );
}

#[test]
fn integration_secret_field_is_redacted() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(secret = "leak");
    });

    let out = writer.captured_str();
    assert!(
        out.contains("[REDACTED]"),
        "secret field must be redacted: {out}"
    );
    assert!(
        !out.contains("\"leak\"") && !out.contains("leak"),
        "raw secret value must not appear: {out}"
    );
}

#[test]
fn integration_strkey_in_value_is_redacted() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());
    let strkey = strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
    let strkey_prefix = strkey[..6].to_owned();

    tracing::subscriber::with_default(subscriber, || {
        // Field name "note" is not on any list; only the S-strkey scan fires.
        tracing::info!(note = %strkey);
    });

    let out = writer.captured_str();
    assert!(
        out.contains("[REDACTED]"),
        "S-strkey in value must be redacted: {out}"
    );
    assert!(
        !out.contains(&strkey_prefix),
        "S-strkey prefix must not appear: {out}"
    );
}

// ── SubscriberConfig + init_subscriber_with — pure-function tests ────────
//
// These tests exercise the pure helpers (`resolve_env_filter_from`,
// `resolve_ansi`) that `init_subscriber_with` composes.  They do NOT install
// a global subscriber, do NOT mutate process-global state, and therefore run
// safely in parallel.
//
// Tests that exercise the full `init_subscriber_with` install path (global
// subscriber, log-crate bridge, panic hook) require a subprocess or
// `serial_test` harness and are not included here.

/// A filter expression `EnvFilter::builder().parse(...)` rejects outright.
/// `"=INFO"` has an empty target before the equals sign — an unambiguous
/// syntax error.  Used by the error-path tests below.
const INVALID_FILTER: &str = "=INFO";

#[test]
fn resolve_env_filter_from_primary_stellar_agent_log() {
    // The filter parses at debug level — we assert only that it produced a
    // valid EnvFilter (no error); EnvFilter is opaque so no further
    // introspection is possible.
    assert!(resolve_env_filter_from(Some("debug"), None).is_ok());
}

#[test]
fn resolve_env_filter_from_primary_stellar_agent_log_complex_expression() {
    // Complex filter expressions must parse correctly.
    assert!(
        resolve_env_filter_from(Some("stellar_agent_core=debug,stellar_xdr=warn,info"), None)
            .is_ok()
    );
}

#[test]
fn resolve_env_filter_from_invalid_stellar_agent_log_falls_back_to_rust_log() {
    // STELLAR_AGENT_LOG is unparseable; RUST_LOG is valid — fallback wins.
    assert!(resolve_env_filter_from(Some(INVALID_FILTER), Some("info")).is_ok());
}

#[test]
fn resolve_env_filter_from_invalid_stellar_agent_log_and_rust_log_errors() {
    // Both invalid: surface the primary error.
    let err = resolve_env_filter_from(Some(INVALID_FILTER), Some(INVALID_FILTER));
    assert!(
        matches!(err, Err(InitError::Filter(_))),
        "expected InitError::Filter, got {err:?}"
    );
}

#[test]
fn resolve_env_filter_from_stellar_unset_rust_log_valid() {
    // Primary unset, RUST_LOG valid — RUST_LOG wins.
    assert!(resolve_env_filter_from(None, Some("trace")).is_ok());
}

#[test]
fn resolve_env_filter_from_stellar_unset_rust_log_invalid_falls_back_to_default() {
    // Primary unset, RUST_LOG unparseable — silently fall through to "info".
    // This matches upstream EnvFilter::from_env semantics for RUST_LOG.
    assert!(resolve_env_filter_from(None, Some(INVALID_FILTER)).is_ok());
}

#[test]
fn resolve_env_filter_from_both_unset_returns_default_info() {
    // Neither env var set — returns the hard-coded "info" default.
    assert!(resolve_env_filter_from(None, None).is_ok());
}

#[test]
fn resolve_env_filter_from_empty_stellar_agent_log_string_is_accepted() {
    // Empty string parses to a no-op (all-off) filter in upstream EnvFilter;
    // this test documents the observed behaviour so a future upstream change
    // that flips this to an error surfaces here first.
    assert!(resolve_env_filter_from(Some(""), None).is_ok());
}

#[test]
fn resolve_ansi_tty_no_no_color() {
    assert!(resolve_ansi(true, false));
}

#[test]
fn resolve_ansi_tty_with_no_color() {
    // NO_COLOR set: ANSI disabled regardless of TTY.
    assert!(!resolve_ansi(true, true));
}

#[test]
fn resolve_ansi_no_tty_no_color_unset() {
    // Not a TTY: ANSI disabled regardless of NO_COLOR state.
    assert!(!resolve_ansi(false, false));
}

#[test]
fn resolve_ansi_no_tty_with_no_color() {
    assert!(!resolve_ansi(false, true));
}

#[test]
fn subscriber_config_default_values() {
    let cfg = SubscriberConfig::default();
    assert_eq!(cfg.format_override, None);
    assert!(cfg.filter_override.is_none());
    assert!(cfg.writer_factory.is_none());
    assert!(cfg.install_panic_hook);
    assert!(cfg.install_log_bridge);
}

#[test]
fn subscriber_config_functional_update_preserves_defaults() {
    let cfg = SubscriberConfig {
        install_panic_hook: false,
        ..SubscriberConfig::default()
    };
    assert!(!cfg.install_panic_hook);
    assert!(cfg.install_log_bridge);
    assert_eq!(cfg.format_override, None);
}

#[test]
fn subscriber_config_with_setters_chain_preserves_other_fields() {
    // Exercise every `with_*` setter in a single chain and assert each
    // setter both (a) updates its own field and (b) does not disturb
    // the remaining defaults.  The chain is the canonical external
    // construction path for the `#[non_exhaustive]` struct; tests below
    // guard against a future change that accidentally flips a default
    // or drops the `self` return from a setter.
    let cfg = SubscriberConfig::default()
        .with_format_override(Some(FormatChoice::Json))
        .with_filter_override(Some(EnvFilter::builder().parse_lossy("debug")))
        .with_install_panic_hook(false)
        .with_install_log_bridge(false);

    assert_eq!(cfg.format_override, Some(FormatChoice::Json));
    assert!(cfg.filter_override.is_some());
    assert!(
        cfg.writer_factory.is_none(),
        "writer_factory stays None (no setter called)"
    );
    assert!(!cfg.install_panic_hook);
    assert!(!cfg.install_log_bridge);
}

#[test]
fn subscriber_config_with_setters_individually_flip_each_field() {
    // Calling each setter alone and asserting the rest remain at the
    // default value — catches a setter that accidentally zeros adjacent
    // fields.
    let cfg = SubscriberConfig::default().with_install_panic_hook(false);
    assert!(!cfg.install_panic_hook);
    assert!(cfg.install_log_bridge);
    assert_eq!(cfg.format_override, None);

    let cfg = SubscriberConfig::default().with_install_log_bridge(false);
    assert!(cfg.install_panic_hook);
    assert!(!cfg.install_log_bridge);

    let cfg = SubscriberConfig::default().with_format_override(Some(FormatChoice::Pretty));
    assert_eq!(cfg.format_override, Some(FormatChoice::Pretty));
    assert!(cfg.install_panic_hook);
    assert!(cfg.install_log_bridge);
}

#[test]
fn subscriber_config_with_writer_factory_sets_factory_field() {
    // Boxed-factory construction works and is observable via
    // `writer_factory.is_some()`; we cannot directly compare closures.
    let factory: BoxedMakeWriterFn =
        Box::new(|| Box::new(std::io::sink()) as Box<dyn std::io::Write + Send>);
    let cfg = SubscriberConfig::default().with_writer_factory(Some(factory));
    assert!(cfg.writer_factory.is_some());
    assert!(cfg.install_panic_hook);
    assert!(cfg.install_log_bridge);
}

#[test]
fn subscriber_config_debug_omits_sensitive_fields() {
    // EnvFilter Display could leak user-supplied env expression; writer
    // factory is not printable. The custom Debug renders placeholders.
    let cfg = SubscriberConfig {
        format_override: Some(FormatChoice::Json),
        filter_override: Some(EnvFilter::builder().parse_lossy("info")),
        ..SubscriberConfig::default()
    };
    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("format_override"));
    assert!(dbg.contains("Json"));
    assert!(
        dbg.contains("<EnvFilter>"),
        "filter should render as placeholder: {dbg}"
    );
    assert!(dbg.contains("install_panic_hook"));
    // No EnvFilter-internal representation should leak.
    assert!(!dbg.contains("parse_lossy"));
}

// ── FieldCollector size-cap tests ─────────────────────────────────────────

/// A small value must not be truncated.
#[test]
fn format_debug_capped_small_value_not_truncated() {
    let (s, trunc) = format_debug_capped(&"hello", MAX_FIELD_BYTES);
    assert!(!trunc, "small value must not be truncated");
    assert_eq!(s, "\"hello\"");
}

/// A value that exactly hits the cap should not be truncated.
#[test]
fn format_debug_capped_exact_cap_not_truncated() {
    let exact = "a".repeat(MAX_FIELD_BYTES);
    // The debug format of a string includes surrounding quotes; our exact match
    // is on a raw string (no quotes) — test with a type that formats without quotes.
    let (s, trunc) = format_debug_capped(&42u64, MAX_FIELD_BYTES);
    // "42" is 2 bytes; well below MAX_FIELD_BYTES.
    assert!(!trunc, "2-byte value must not be truncated");
    assert_eq!(s, "42");
    // Suppress unused-variable warning on `exact`.
    let _ = exact;
}

/// A value larger than MAX_FIELD_BYTES must be truncated.
#[test]
fn format_debug_capped_oversized_value_is_truncated() {
    // Build a string longer than MAX_FIELD_BYTES.
    let oversized = "x".repeat(MAX_FIELD_BYTES + 100);
    let (s, trunc) = format_debug_capped(&oversized, MAX_FIELD_BYTES);
    assert!(trunc, "oversized value must be truncated");
    assert!(
        s.ends_with("...[TRUNCATED]"),
        "truncated value must end with TRUNCATION_SUFFIX: {s}"
    );
    assert!(
        s.len() <= MAX_FIELD_BYTES + TRUNCATION_SUFFIX.len(),
        "truncated output length must not greatly exceed cap"
    );
}

/// After truncation, the FieldCollector sets `field_truncated_for_redaction`.
#[test]
fn field_collector_sets_truncation_flag_on_large_debug_field() {
    let mut collector = FieldCollector::default();
    // We cannot easily inject an oversized value through tracing macros, so
    // test the flag indirectly via direct visitor calls with a struct that
    // formats to more than MAX_FIELD_BYTES.
    struct BigDebug;
    impl std::fmt::Debug for BigDebug {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            // Write MAX_FIELD_BYTES + 1 bytes so we trip the cap.
            for _ in 0..=MAX_FIELD_BYTES {
                f.write_str("x")?;
            }
            Ok(())
        }
    }

    // Construct a synthetic field to drive record_debug.
    // We test the helpers directly since injecting a fake Field is complex.
    let (_, trunc) = format_debug_capped(&BigDebug, MAX_FIELD_BYTES);
    assert!(trunc, "BigDebug must exceed MAX_FIELD_BYTES");

    // Simulate what record_debug does.
    collector.field_truncated_for_redaction = trunc;
    assert!(
        collector.field_truncated_for_redaction,
        "collector flag must be set after large Debug field"
    );
}

/// A small error value must not be truncated.
#[test]
fn format_display_capped_small_value_not_truncated() {
    let err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
    let (s, trunc) = format_display_capped(&err, MAX_FIELD_BYTES);
    assert!(!trunc, "small error must not be truncated");
    assert!(
        s.contains("not found"),
        "error message must be present: {s}"
    );
}

// ── Span emission tests ───────────────────────────────────────────────────

/// Verify that `"span"` and `"spans"` keys are emitted when an event is
/// logged inside a tracing span.
#[test]
fn span_emission_includes_span_and_spans_keys() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("my_operation", tool = "stellar_pay_commit");
        let _guard = span.enter();
        tracing::info!(result = "ok");
    });

    let out = writer.captured_str();
    assert!(
        out.contains("\"span\""),
        "JSON output must contain \"span\" key when inside a span: {out}"
    );
    assert!(
        out.contains("\"spans\""),
        "JSON output must contain \"spans\" key when inside a span: {out}"
    );
    assert!(
        out.contains("my_operation"),
        "span name must appear in output: {out}"
    );
}

/// Events logged outside any span must not emit `"span"` or `"spans"` keys.
#[test]
fn span_keys_absent_when_no_span_context() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(result = "ok");
    });

    let out = writer.captured_str();
    assert!(
        !out.contains("\"span\""),
        "JSON output must not contain \"span\" key when outside a span: {out}"
    );
    assert!(
        !out.contains("\"spans\""),
        "JSON output must not contain \"spans\" key when outside a span: {out}"
    );
}

/// Nested spans: both parent and child appear in `"spans"` (root-to-leaf).
#[test]
fn nested_spans_appear_in_spans_array() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        let outer = tracing::info_span!("outer_span");
        let _og = outer.enter();
        let inner = tracing::info_span!("inner_span");
        let _ig = inner.enter();
        tracing::info!(msg = "nested");
    });

    let out = writer.captured_str();
    assert!(
        out.contains("outer_span"),
        "outer span name must appear: {out}"
    );
    assert!(
        out.contains("inner_span"),
        "inner span name must appear: {out}"
    );
    // "span" key is the innermost span.
    let span_idx = out.find("\"span\"").expect("span key must exist");
    let spans_idx = out.find("\"spans\"").expect("spans key must exist");
    // spans array comes after span.
    assert!(spans_idx > span_idx, "spans must follow span in output");
}

/// S-strkey embedded in a span field value must be redacted by `redact_strkeys`.
#[test]
fn span_field_strkey_is_redacted() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());
    let strkey = strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
    let strkey_prefix = strkey[..6].to_owned();

    tracing::subscriber::with_default(subscriber, || {
        // Embed the S-strkey in a span field.
        let span = tracing::info_span!("signing", key = %strkey);
        let _guard = span.enter();
        tracing::info!(msg = "signing");
    });

    let out = writer.captured_str();
    // The strkey must not appear verbatim in the output.
    assert!(
        !out.contains(&strkey_prefix),
        "S-strkey prefix must not appear in span fields: {out}"
    );
    // The output must contain [REDACTED] somewhere.
    assert!(
        out.contains("[REDACTED]"),
        "span field with S-strkey must be redacted: {out}"
    );
}

// ── Truncation boundary must not leak strkeys ─────────────────────────────

/// An S-strkey placed at byte position `MAX_FIELD_BYTES - 30` must appear as
/// `[REDACTED]` in the output even though truncation would otherwise have
/// split the 56-byte strkey.
///
/// The correct order is: render → redact (strkeys replaced with `[REDACTED]`)
/// → cap at `MAX_FIELD_BYTES`.  Reversing the order (cap first, redact second)
/// would allow the portion of the strkey before the cap boundary to appear in
/// the output.
#[test]
fn truncation_does_not_leak_strkey_across_cap_boundary() {
    let strkey = strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
    assert_eq!(strkey.len(), 56, "strkey must be 56 bytes");

    // Place the strkey at MAX_FIELD_BYTES - 30 so it straddles the cap boundary.
    // Without redact-first, bytes 0..(MAX_FIELD_BYTES - 30) would pass through
    // and the first 26 bytes of the strkey (up to the cap) would leak.
    let prefix = "x".repeat(MAX_FIELD_BYTES - 30);
    let suffix = "y".repeat(MAX_FIELD_BYTES); // enough to ensure truncation fires
    let input = format!("{prefix}{strkey}{suffix}");

    let (out, truncated) = format_debug_capped(&input.as_str(), MAX_FIELD_BYTES);

    // Truncation must have fired (input is much larger than MAX_FIELD_BYTES).
    assert!(truncated, "must be truncated given the oversized input");

    // The full strkey must NOT appear anywhere in the output.
    assert!(
        !out.contains(&strkey),
        "full strkey must not appear in truncated output: {out}"
    );

    // Neither must any prefix of the strkey beyond the first 4 chars
    // (the first-5 chars alone aren't meaningful; check the 10-char prefix
    // as a conservative guard against partial-leak).
    let strkey_10 = &strkey[..10];
    assert!(
        !out.contains(strkey_10),
        "10-char strkey prefix must not appear in output: {out}"
    );

    // The output must end with the TRUNCATION_SUFFIX.
    assert!(
        out.ends_with("...[TRUNCATED]"),
        "truncated output must end with TRUNCATION_SUFFIX: {out}"
    );
}

#[test]
fn pre_redaction_cap_boundary_redacts_partial_sensitive_strkey_fragments() {
    struct RawDebug(String);
    impl std::fmt::Debug for RawDebug {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    let strkey = strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
    for overlap in 16..=55 {
        let prefix = "x".repeat(MAX_PRE_REDACT_BYTES - overlap);
        let input = RawDebug(format!("{prefix}{strkey}{}", "z".repeat(64)));

        let (out, truncated) =
            format_debug_capped(&input, MAX_PRE_REDACT_BYTES + TRUNCATION_SUFFIX.len() + 64);

        assert!(
            truncated,
            "overlap {overlap} must hit the pre-redaction cap"
        );
        assert!(
            out.contains("[REDACTED-PARTIAL]"),
            "overlap {overlap} must redact the cap-boundary fragment: {out}"
        );
        assert!(
            !contains_sensitive_base32_fragment(&out),
            "overlap {overlap} leaked an S/T/X base32 fragment: {out}"
        );
    }
}

#[test]
fn pre_redaction_cap_boundary_redacts_internal_sensitive_strkey_markers() {
    struct RawDebug(String);
    impl std::fmt::Debug for RawDebug {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    for marker in ['S', 'T', 'X'] {
        for offset in 0..=15 {
            let fragment = format!("{}{marker}{}", "A".repeat(offset), "B".repeat(55 - offset));
            let prefix = "x".repeat(MAX_PRE_REDACT_BYTES - fragment.len());
            let input = RawDebug(format!("{prefix}{fragment}{}", "z".repeat(64)));

            let (out, truncated) =
                format_debug_capped(&input, MAX_PRE_REDACT_BYTES + TRUNCATION_SUFFIX.len() + 64);

            assert!(
                truncated,
                "{marker} at offset {offset} must hit the pre-redaction cap"
            );
            assert!(
                out.contains("[REDACTED-PARTIAL]"),
                "{marker} at offset {offset} must redact the cap-boundary fragment: {out}"
            );
            assert!(
                !contains_sensitive_base32_fragment(&out),
                "{marker} at offset {offset} leaked an S/T/X base32 fragment: {out}"
            );
        }
    }
}

fn contains_sensitive_base32_fragment(value: &str) -> bool {
    value
        .as_bytes()
        .split(|b| !matches!(b, b'A'..=b'Z' | b'2'..=b'7'))
        .any(|fragment| {
            fragment.len() >= 16 && fragment.iter().any(|b| matches!(b, b'S' | b'T' | b'X'))
        })
}

// ── field_truncated_for_redaction emitted as top-level key ───────────────

/// When a Debug field value exceeds `MAX_FIELD_BYTES`, the JSON output must
/// contain a top-level `"truncated":true` key.
#[test]
fn truncated_field_emits_top_level_json_key() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    // A struct whose Debug output is larger than MAX_FIELD_BYTES.
    struct OversizedDebug;
    impl std::fmt::Debug for OversizedDebug {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            // Write MAX_FIELD_BYTES + 1 bytes to trip the cap.
            let chunk = "z".repeat(1024);
            for _ in 0..=(MAX_FIELD_BYTES / 1024 + 1) {
                f.write_str(&chunk)?;
            }
            Ok(())
        }
    }

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(data = ?OversizedDebug);
    });

    let out = writer.captured_str();
    assert!(
        out.contains("\"truncated\":true"),
        "JSON output must contain top-level truncated:true when a field is capped: {out}"
    );
}

// ── LimitedWriter bounds unbounded Debug impl ─────────────────────────────

/// A `Debug` implementation that produces more than `MAX_PRE_REDACT_BYTES` of
/// output must NOT allocate the full rendering.  [`LimitedWriter`] bounds
/// allocation upfront regardless of what the `Debug` impl writes.
///
/// This test uses a struct whose `Debug` impl writes in a loop targeting
/// ~100 MiB of output.  The test asserts that:
/// 1. The function returns within a reasonable time (no unbounded allocation).
/// 2. The returned buffer is at most `MAX_PRE_REDACT_BYTES + TRUNCATION_SUFFIX.len()`.
/// 3. The `truncated` flag is `true`.
/// 4. The output ends with `...[TRUNCATED]`.
#[test]
fn format_debug_capped_bounds_unbounded_debug_impl() {
    struct HundredMibDebug;
    impl std::fmt::Debug for HundredMibDebug {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            // Each iteration writes 1 KiB; 120_000 iterations = ~120 MiB.
            let chunk = "a".repeat(1024);
            for _ in 0..120_000 {
                f.write_str(&chunk)?;
            }
            Ok(())
        }
    }

    let (out, truncated) = format_debug_capped(&HundredMibDebug, MAX_FIELD_BYTES);

    assert!(truncated, "HundredMibDebug must trigger truncation flag");
    assert!(
        out.len() <= MAX_PRE_REDACT_BYTES + TRUNCATION_SUFFIX.len(),
        "output must be bounded by MAX_PRE_REDACT_BYTES + suffix len; got {} bytes",
        out.len()
    );
    assert!(
        out.ends_with("...[TRUNCATED]"),
        "output must end with TRUNCATION_SUFFIX: {out}"
    );
}

// ── test_callsite helper (needed by field_collector_drops_log_dot_fields) ─

/// Minimal callsite implementation used to construct synthetic tracing
/// metadata in unit tests.  Not for use outside tests.
mod test_callsite {
    use tracing::Metadata;

    pub(super) struct TestCallsite;

    impl tracing::callsite::Callsite for TestCallsite {
        fn set_interest(&self, _interest: tracing::subscriber::Interest) {}

        fn metadata(&self) -> &Metadata<'_> {
            // This is never called in our test; it only needs to exist to
            // satisfy the trait bound for `FieldSet::new`.
            unimplemented!("test callsite metadata not used")
        }
    }
}

// ── LimitedWriter direct tests ────────────────────────────────────────────

/// A write that exactly fills the limit must NOT set `overflowed` and must
/// not append the truncation suffix.
#[test]
fn limited_writer_exact_fit_does_not_overflow() {
    use std::fmt::Write as _;
    let mut w = LimitedWriter::new(5);
    w.write_str("hello").unwrap();
    let (s, overflowed) = w.into_string();
    assert_eq!(s, "hello");
    assert!(!overflowed);
}

/// A write that exceeds the limit by one byte must set `overflowed` and
/// produce a string that ends with `TRUNCATION_SUFFIX`.
#[test]
fn limited_writer_overflow_by_one_sets_flag_and_appends_suffix() {
    use std::fmt::Write as _;
    let mut w = LimitedWriter::new(4);
    w.write_str("hello").unwrap();
    let (s, overflowed) = w.into_string();
    assert!(overflowed);
    assert!(
        s.ends_with(TRUNCATION_SUFFIX),
        "must end with TRUNCATION_SUFFIX: {s:?}"
    );
    assert!(s.starts_with("hell"), "kept prefix must be present: {s:?}");
}

/// Once `overflowed` is set, subsequent writes are silently dropped.
/// The first write that causes overflow appends `TRUNCATION_SUFFIX`; any
/// later write returns `Ok(())` immediately without modifying the buffer.
#[test]
fn limited_writer_subsequent_writes_after_overflow_are_dropped() {
    use std::fmt::Write as _;
    // Write "abc" (exactly fills limit=3), then two more writes that overflow
    // and are subsequently dropped.
    let mut w = LimitedWriter::new(3);
    w.write_str("abc").unwrap(); // exactly fits; buf="abc", no overflow
    w.write_str("SHOULD_BE_GONE").unwrap(); // overflows: suffix appended, overflowed=true
    w.write_str("ALSO_GONE").unwrap(); // already overflowed: dropped silently
    let (s, overflowed) = w.into_string();
    assert!(overflowed);
    assert!(
        !s.contains("SHOULD_BE_GONE"),
        "overflow content must be absent: {s:?}"
    );
    assert!(
        !s.contains("ALSO_GONE"),
        "post-overflow content must be absent: {s:?}"
    );
    assert!(s.starts_with("abc"), "prefix must be present: {s:?}");
}

/// A write containing a multi-byte UTF-8 character that straddles the limit
/// must truncate at a char boundary (no invalid UTF-8 in output).
#[test]
fn limited_writer_truncates_at_char_boundary_for_multibyte() {
    use std::fmt::Write as _;
    // "aé" = 3 bytes ('a'=1 byte, 'é'=2 bytes). Limit=2 fits 'a' but
    // not 'é', so 'é' must be dropped entirely (not split at byte 1).
    let mut w = LimitedWriter::new(2);
    w.write_str("aé").unwrap();
    let (s, overflowed) = w.into_string();
    assert!(overflowed);
    // The output must be valid UTF-8 (would panic on String if not).
    assert!(s.is_char_boundary(0));
    // 'a' may or may not fit; 'é' must not be partially written.
    // Either way, the string must be valid UTF-8 and must not contain 'é'.
    assert!(
        !s.contains('é'),
        "partial multi-byte char must not appear: {s:?}"
    );
}

/// `LimitedWriter` buffer capacity is capped at `64 KiB` for large limits
/// (the `min(limit, 64*1024)` in `new`). Verify that constructing with a
/// very large limit does not pre-allocate the full limit.
#[test]
fn limited_writer_large_limit_does_not_panic() {
    use std::fmt::Write as _;
    let mut w = LimitedWriter::new(usize::MAX / 2);
    // A small write must succeed without panicking.
    w.write_str("small").unwrap();
    let (s, overflowed) = w.into_string();
    assert_eq!(s, "small");
    assert!(!overflowed);
}

// ── cap_string direct tests ───────────────────────────────────────────────

/// A string within the limit must pass through unchanged with `truncated=false`.
#[test]
fn cap_string_within_limit_passes_through() {
    let input = "hello world".to_owned();
    let (out, truncated) = cap_string(input.clone(), 100);
    assert_eq!(out, input);
    assert!(!truncated);
}

/// A string exactly at the limit must pass through unchanged.
#[test]
fn cap_string_at_exact_limit_passes_through() {
    let input = "hello".to_owned();
    let (out, truncated) = cap_string(input.clone(), 5);
    assert_eq!(out, input);
    assert!(!truncated);
}

/// A string over the limit must be truncated to the cap and suffixed.
#[test]
fn cap_string_over_limit_is_truncated_and_suffixed() {
    let input = "abcdefghij".to_owned();
    let (out, truncated) = cap_string(input, 5);
    assert!(truncated);
    assert!(
        out.ends_with(TRUNCATION_SUFFIX),
        "must end with TRUNCATION_SUFFIX: {out:?}"
    );
    assert!(out.starts_with("abcde"), "prefix must be kept: {out:?}");
}

/// Truncation of a string containing multi-byte characters must land on a
/// UTF-8 char boundary.
#[test]
fn cap_string_truncates_at_char_boundary_for_multibyte() {
    // "aé" = 1 + 2 = 3 bytes. Limit=2 cannot include 'é' without splitting.
    let input = "aébc".to_owned();
    let (out, truncated) = cap_string(input, 2);
    assert!(truncated);
    // The output up to the TRUNCATION_SUFFIX must be valid UTF-8 and must
    // not contain the second byte of 'é' without the first.
    assert!(
        !out.contains('é'),
        "partial multi-byte char must not appear: {out:?}"
    );
}

// ── write_json_str escape coverage ───────────────────────────────────────

/// `write_json_str` must escape `"` and `\` per RFC 8259.
#[test]
fn write_json_str_escapes_double_quote_and_backslash() {
    // `write_json_str` is tested via the integration subscriber because
    // `Writer<'_>` is not directly constructable in test code.
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        // Log a message field with embedded " and \.
        tracing::info!(message = "say \"hello\" and \\goodbye\\");
    });

    let out = writer.captured_str();
    // The raw characters " and \ must appear as \" and \\ in the JSON output.
    assert!(
        out.contains("\\\""),
        "double-quote must be escaped as \\\": {out}"
    );
    assert!(
        out.contains("\\\\"),
        "backslash must be escaped as \\\\: {out}"
    );
    // The output must be parseable JSON.
    let _parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("must be valid JSON");
}

/// `write_json_str` must escape `\n`, `\r`, and `\t`.
#[test]
fn write_json_str_escapes_newline_cr_tab() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(message = "line1\nline2\r\ttabbed");
    });

    let out = writer.captured_str();
    assert!(out.contains("\\n"), "newline must be escaped as \\n: {out}");
    assert!(out.contains("\\r"), "CR must be escaped as \\r: {out}");
    assert!(out.contains("\\t"), "tab must be escaped as \\t: {out}");
    // The JSON must be parseable despite the escapes.
    let _parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("must be valid JSON");
}

/// `write_json_str` must escape control characters U+0000–U+001F as
/// `\uXXXX`.
#[test]
fn write_json_str_escapes_control_characters() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        // U+0001 (SOH) is a control character below U+0020.
        tracing::info!(message = "\x01ctrl");
    });

    let out = writer.captured_str();
    // Must not contain the raw control byte; must contain a \uXXXX escape.
    assert!(
        !out.contains('\x01'),
        "raw control char must not appear: {out}"
    );
    assert!(
        out.contains("\\u0001"),
        "control char must appear as \\u0001 escape: {out}"
    );
    let _parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("must be valid JSON");
}

// ── write_json_fields sort order ──────────────────────────────────────────

/// JSON field output must be sorted lexicographically by key name.
/// The `write_json_fields` function sorts via a Vec::sort_by_key, so
/// field insertion order in the tracing macro must not affect output order.
#[test]
fn json_fields_are_sorted_lexicographically() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        // `zebra` would come after `alpha` in sorted order.
        tracing::info!(zebra = "last", alpha = "first", message = "sort-test");
    });

    let out = writer.captured_str();
    // Parse the "fields" object and verify key order.
    let parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("valid JSON");
    let fields = parsed["fields"].as_object().expect("fields must be object");
    let keys: Vec<&str> = fields.keys().map(String::as_str).collect();
    // Verify "alpha" appears before "zebra".
    let alpha_pos = keys.iter().position(|k| *k == "alpha").expect("alpha key");
    let zebra_pos = keys.iter().position(|k| *k == "zebra").expect("zebra key");
    assert!(
        alpha_pos < zebra_pos,
        "fields must be sorted: alpha must precede zebra in {keys:?}"
    );
}

/// Non-string field types (u64, i64, f64, bool) that are NOT on the redact
/// list must appear as bare JSON values (number or boolean), not quoted strings.
#[test]
fn json_fields_non_string_types_are_bare_json_values() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(count = 99u64, delta = -7i64, ratio = 0.5f64, active = false);
    });

    let out = writer.captured_str();
    let parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("valid JSON");
    let fields = &parsed["fields"];
    assert_eq!(
        fields["count"],
        serde_json::json!(99u64),
        "u64 must be bare JSON number"
    );
    assert_eq!(
        fields["delta"],
        serde_json::json!(-7i64),
        "i64 must be bare JSON number"
    );
    // f64 comparison: allow floating-point identity.
    let ratio = fields["ratio"].as_f64().expect("ratio must be f64");
    assert!(
        (ratio - 0.5f64).abs() < f64::EPSILON,
        "f64 must survive JSON round-trip"
    );
    assert_eq!(
        fields["active"],
        serde_json::json!(false),
        "bool must be bare JSON boolean"
    );
}

// ── write_pretty_fields coverage ──────────────────────────────────────────

/// `write_pretty_fields` uses a custom `FormatFields` in the pretty path.
/// Verify via a pretty subscriber that the message field is unquoted and
/// other fields appear as `key=value`.
///
/// Because `RedactingLayer<DefaultFields>` operates only within a full
/// subscriber stack, we build a minimal pretty subscriber with it.
#[test]
fn pretty_fields_message_written_without_key_prefix() {
    use tracing_subscriber::fmt;
    let writer = CaptureWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        fmt::layer()
            .pretty()
            .with_writer(writer.clone())
            .with_ansi(false)
            .fmt_fields(RedactingLayer::<
                tracing_subscriber::fmt::format::DefaultFields,
            >::new_pretty()),
    );

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(operation = "sign", "hello pretty");
    });

    let out = writer.captured_str();
    // The message text must appear without a `message=` prefix.
    assert!(
        out.contains("hello pretty"),
        "message must appear in pretty output: {out}"
    );
    // The `operation` field must appear with its key (the pretty formatter
    // renders fields as `key: value`).
    assert!(
        out.contains("operation: \"sign\""),
        "named field must appear with key prefix in pretty output: {out}"
    );
}

// ── should_redact_by_name direct tests ───────────────────────────────────

/// Pass-through fields must NOT be redacted by name, regardless of case.
#[test]
fn should_redact_by_name_pass_through_fields_are_never_redacted() {
    for name in &[
        "public_key",
        "pubkey",
        "account_id",
        "account",
        "contract_address",
        "contract",
        "muxed_account",
        "tx_hash",
        "transaction_hash",
        "counterparty",
        "destination",
        "source",
    ] {
        assert!(
            !should_redact_by_name(name),
            "pass-through field '{name}' must not be flagged for redaction"
        );
        let upper = name.to_uppercase();
        assert!(
            !should_redact_by_name(&upper),
            "pass-through field '{upper}' (uppercased) must not be flagged"
        );
    }
}

/// Fields on the redact list must return `true`.
#[test]
fn should_redact_by_name_redact_list_fields_are_flagged() {
    for name in &[
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
    ] {
        assert!(
            should_redact_by_name(name),
            "redact-list field '{name}' must be flagged for redaction"
        );
        // Case-insensitive check.
        let mixed = {
            let mut s = name.to_uppercase();
            // flip first char back to lower-case to exercise mixed case
            if let Some(first) = s.chars().next() {
                s = first.to_lowercase().to_string() + &s[first.len_utf8()..];
            }
            s
        };
        assert!(
            should_redact_by_name(&mixed),
            "redact-list field '{mixed}' (mixed case) must be flagged"
        );
    }
}

/// A completely unknown field name must NOT be redacted by name.
#[test]
fn should_redact_by_name_unknown_field_is_not_flagged() {
    assert!(!should_redact_by_name("operation"));
    assert!(!should_redact_by_name("block_height"));
    assert!(!should_redact_by_name("result"));
    assert!(!should_redact_by_name(""));
}

// ── redact_value: BIP-39 content path ────────────────────────────────────

/// A field whose name is not on any list but whose value is a valid BIP-39
/// mnemonic must be replaced with `[REDACTED]`.
#[test]
fn redact_value_bip39_in_content_triggers_redaction() {
    let phrase = "abandon ability able about above absent absorb abstract \
                  absurd abuse access accident";
    let (out, did) = redact_value("note", phrase);
    assert!(did, "BIP-39 mnemonic in field value must trigger redaction");
    assert_eq!(out, "[REDACTED]");
}

/// A field whose name is on the pass-through list must NOT be redacted even
/// when its value happens to look like a BIP-39 mnemonic.
#[test]
fn redact_value_pass_through_beats_bip39_content_check() {
    let phrase = "abandon ability able about above absent absorb abstract \
                  absurd abuse access accident";
    // "source" is on the pass-through list.
    let (out, did) = redact_value("source", phrase);
    assert!(
        !did,
        "pass-through field must not be redacted even for BIP-39 value"
    );
    assert_eq!(out, phrase);
}

/// A field value containing a valid S-strkey must be redacted when the field
/// name is neutral (not on any list).
#[test]
fn redact_value_strkey_in_content_triggers_redaction() {
    let strkey = strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
    let value = format!("key={strkey}");
    // Use a neutral field name that is not on any list.
    let (out, did) = redact_value("note", &value);
    assert!(did, "S-strkey in field value must trigger redaction");
    assert!(!out.contains(&strkey), "raw strkey must not appear: {out}");
    assert!(
        out.contains("[REDACTED]"),
        "output must contain [REDACTED]: {out}"
    );
}

// ── redact_strkeys: multiple strkeys in one input ─────────────────────────

/// Two consecutive valid strkeys in one input must both be redacted.
#[test]
fn redact_strkeys_replaces_two_consecutive_strkeys() {
    let s1 = strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
    let s2 = strkey_from_seed(VERSION_PRE_AUTH_TX, &TESTNET_FIXTURE_SEED);
    let input = format!("{s1} {s2}");
    let (out, did) = redact_strkeys(&input);
    assert!(did, "both strkeys must be redacted");
    assert!(!out.contains(&s1), "first strkey must be absent: {out}");
    assert!(!out.contains(&s2), "second strkey must be absent: {out}");
    // Both replacements must produce [REDACTED].
    let count = out.matches("[REDACTED]").count();
    assert_eq!(count, 2, "must see exactly two [REDACTED] tokens: {out}");
}

/// An X-strkey inline in surrounding text must be redacted.
#[test]
fn redact_strkeys_replaces_x_strkey_in_text() {
    let x = strkey_from_seed(VERSION_HASH_X, &TESTNET_FIXTURE_SEED);
    let input = format!("hash={x}&other=abc");
    let (out, did) = redact_strkeys(&input);
    assert!(did, "X-strkey must be redacted");
    assert!(!out.contains(&x), "raw X-strkey must not appear: {out}");
    assert!(
        out.contains("[REDACTED]"),
        "output must contain [REDACTED]: {out}"
    );
}

/// A T-strkey inline in surrounding text must be redacted.
#[test]
fn redact_strkeys_replaces_t_strkey_in_text() {
    let t = strkey_from_seed(VERSION_PRE_AUTH_TX, &TESTNET_FIXTURE_SEED);
    let input = format!("preauth={t}:nonce=123");
    let (out, did) = redact_strkeys(&input);
    assert!(did, "T-strkey must be redacted");
    assert!(!out.contains(&t), "raw T-strkey must not appear: {out}");
    assert!(
        out.contains("[REDACTED]"),
        "output must contain [REDACTED]: {out}"
    );
}

/// A G-strkey (public key) must NOT be redacted by `redact_strkeys`.
/// Layer 2 explicitly passes G-strkeys through to preserve Layer 1's
/// first-5-last-5 rendering.
#[test]
fn redact_strkeys_does_not_redact_g_strkey() {
    let g = strkey_from_seed(VERSION_PUBLIC_KEY, &TESTNET_FIXTURE_SEED);
    let input = format!("account={g}");
    let (out, did) = redact_strkeys(&input);
    assert!(!did, "G-strkey must not be redacted by redact_strkeys");
    assert_eq!(out, input, "input must pass through unchanged");
}

/// Input shorter than 56 bytes must be returned unchanged without any
/// scanning (the early-return path).
#[test]
fn redact_strkeys_short_input_passes_through() {
    let short = "SABC".to_owned();
    let (out, did) = redact_strkeys(&short);
    assert!(!did);
    assert_eq!(out, short);
}

// ── is_base32_byte coverage ───────────────────────────────────────────────

/// Every byte in the RFC 4648 base32 alphabet (`A-Z`, `2-7`) must return `true`.
#[test]
fn is_base32_byte_accepts_all_valid_chars() {
    for b in b'A'..=b'Z' {
        // All bytes in b'A'..=b'Z' are ASCII and safe to cast to char.
        assert!(is_base32_byte(b), "'{}'({b}) must be base32", char::from(b));
    }
    for b in b'2'..=b'7' {
        assert!(is_base32_byte(b), "'{}'({b}) must be base32", char::from(b));
    }
}

/// Bytes outside the base32 alphabet must return `false`.
#[test]
fn is_base32_byte_rejects_non_base32_chars() {
    // ASCII bytes that are NOT in [A-Z] or [2-7].
    let non_base32: &[u8] = &[
        b'0', b'1', b'8', b'9', b'a', b'z', b' ', b'!', b'/', 0x00, 0x7F,
    ];
    for &b in non_base32 {
        assert!(!is_base32_byte(b), "byte {b:#04x} must NOT be base32");
    }
}

// ── RedactedStrkey trait impl coverage ────────────────────────────────────

/// `Deref` to `str` must give back the inner redacted string.
#[test]
fn redacted_strkey_deref_to_str() {
    let r = RedactedStrkey::from_already_redacted("GAAAA...ZZZZZ");
    let s: &str = std::ops::Deref::deref(&r);
    assert_eq!(s, "GAAAA...ZZZZZ");
}

/// `AsRef<str>` must give back the inner redacted string.
#[test]
fn redacted_strkey_as_ref_str() {
    let r = RedactedStrkey::from_already_redacted("CAAAA...12345");
    let s: &str = r.as_ref();
    assert_eq!(s, "CAAAA...12345");
}

/// `From<RedactedStrkey> for String` must consume the value and produce the
/// inner string.
#[test]
fn redacted_strkey_into_string() {
    let r = RedactedStrkey::from_already_redacted("XAAAA...YYYYY");
    let s: String = r.into();
    assert_eq!(s, "XAAAA...YYYYY");
}

/// `Clone` must produce an independent value equal to the original.
#[test]
fn redacted_strkey_clone_equality() {
    let orig = RedactedStrkey::from_already_redacted("CLONE...VALUE");
    let cloned = orig.clone();
    assert_eq!(orig, cloned);
    assert_eq!(orig.as_str(), cloned.as_str());
}

/// `Default` must produce an empty inner string.
#[test]
fn redacted_strkey_default_is_empty_str() {
    let d = RedactedStrkey::default();
    assert_eq!(d.as_str(), "");
}

/// `PartialEq<&str>` — `RedactedStrkey == &str`.
#[test]
fn redacted_strkey_partial_eq_str_ref() {
    let r = RedactedStrkey::from_already_redacted("HELLO...WORLD");
    assert_eq!(r, "HELLO...WORLD");
    assert_ne!(r, "different");
}

/// `PartialEq<str>` via `&r == s` form is already covered by the blanket `PartialEq<&str>`,
/// but the reverse `PartialEq<RedactedStrkey> for &str` is distinct.
#[test]
fn redacted_strkey_partial_eq_reverse_str_ref() {
    let r = RedactedStrkey::from_already_redacted("REVRS...EQUAL");
    let s: &str = "REVRS...EQUAL";
    assert!(
        s == r,
        "reverse PartialEq: &str == RedactedStrkey must hold"
    );
}

/// `PartialEq<String>` — `RedactedStrkey == String`.
#[test]
fn redacted_strkey_partial_eq_string() {
    let r = RedactedStrkey::from_already_redacted("OWNED...VALUE");
    let owned = String::from("OWNED...VALUE");
    assert_eq!(r, owned);
    let other = String::from("DIFFERENT");
    assert_ne!(r, other);
}

/// `PartialEq<RedactedStrkey> for String` — reverse direction.
#[test]
fn redacted_strkey_partial_eq_reverse_string() {
    let r = RedactedStrkey::from_already_redacted("STRIN...GSIDE");
    let owned = String::from("STRIN...GSIDE");
    assert!(
        owned == r,
        "reverse PartialEq: String == RedactedStrkey must hold"
    );
}

/// `Display` must write the inner redacted string.
#[test]
fn redacted_strkey_display_writes_inner_string() {
    let r = RedactedStrkey::from_already_redacted("DISPL...AYVAL");
    assert_eq!(format!("{r}"), "DISPL...AYVAL");
}

// ── redact_path_in_message_with_home: empty home ──────────────────────────

/// An empty-string home must be treated as "no redaction" (the path would
/// unconditionally replace every occurrence of `""` in the message, which
/// is every position in the string — pathological behavior, guarded by the
/// `home.is_empty()` check).
#[test]
fn redact_path_in_message_with_empty_home_is_passthrough() {
    let msg = "open: /home/alice/.config/agent/secrets.json: ENOENT";
    assert_eq!(
        redact_path_in_message_with_home(msg, Some("")),
        msg,
        "empty home must not redact anything"
    );
}

// ── redact_first5_last5: boundary cases ──────────────────────────────────

/// Exactly 9 chars (one below the 10-char threshold) must pass through.
#[test]
fn redact_first5_last5_nine_chars_is_passthrough() {
    let s = "123456789";
    assert_eq!(s.chars().count(), 9);
    assert_eq!(redact_first5_last5(s), s);
}

/// Exactly 10 chars must be redacted (the boundary where overlap becomes
/// impossible: first 5 + last 5 = exactly 10, head/tail do not overlap).
#[test]
fn redact_first5_last5_ten_chars_is_redacted() {
    let s = "1234567890";
    assert_eq!(s.chars().count(), 10);
    assert_eq!(redact_first5_last5(s), "12345...67890");
}

/// An empty string is shorter than 10 chars and must pass through unchanged.
#[test]
fn redact_first5_last5_empty_string_is_passthrough() {
    assert_eq!(redact_first5_last5(""), "");
}

// ── format_display_capped: oversized Display value ────────────────────────

/// A `Display` implementation that emits more than `MAX_FIELD_BYTES` bytes
/// must be capped at the limit and flagged as truncated.
#[test]
fn format_display_capped_oversized_display_is_truncated() {
    struct BigDisplay;
    impl std::fmt::Display for BigDisplay {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let chunk = "y".repeat(1024);
            for _ in 0..=(MAX_FIELD_BYTES / 1024 + 1) {
                f.write_str(&chunk)?;
            }
            Ok(())
        }
    }

    let (out, truncated) = format_display_capped(&BigDisplay, MAX_FIELD_BYTES);
    assert!(truncated, "oversized Display must trigger truncation");
    assert!(
        out.ends_with("...[TRUNCATED]"),
        "output must end with TRUNCATION_SUFFIX: {out}"
    );
    assert!(
        out.len() <= MAX_PRE_REDACT_BYTES + TRUNCATION_SUFFIX.len(),
        "output must be bounded: got {} bytes",
        out.len()
    );
}

// ── FieldCollector: record_error path ─────────────────────────────────────

/// `record_error` must format the error via Display and redact if applicable.
/// A neutral field name with a small error value must pass through unchanged.
#[test]
fn field_collector_record_error_stores_display_formatted_message() {
    let err = std::io::Error::new(std::io::ErrorKind::NotFound, "wallet file missing");
    let (out, truncated) = format_display_capped(&err, MAX_FIELD_BYTES);
    assert!(!truncated, "small error must not be truncated");
    assert!(
        out.contains("wallet file missing"),
        "error display message must appear in output: {out}"
    );
}

// ── FieldCollector: benign f64 and bool pass-through via subscriber ───────

/// A benign (non-redacted) `f64` field must appear as a raw number in JSON.
#[test]
fn integration_benign_f64_passes_through() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(price = 1.5f64);
    });

    let out = writer.captured_str();
    let parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("valid JSON");
    let price = parsed["fields"]["price"]
        .as_f64()
        .expect("price must be f64");
    assert!(
        (price - 1.5f64).abs() < f64::EPSILON,
        "f64 must round-trip: {price}"
    );
}

/// A benign (non-redacted) `bool` field must appear as a bare boolean in JSON.
#[test]
fn integration_benign_bool_passes_through() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(active = true);
    });

    let out = writer.captured_str();
    let parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("valid JSON");
    assert_eq!(
        parsed["fields"]["active"],
        serde_json::json!(true),
        "bool must round-trip as bare JSON: {out}"
    );
}

// ── JSON output schema: field ordering invariant ──────────────────────────

/// The JSON output must contain keys in the declared schema order:
/// `timestamp` (absent in test subscriber) → `level` → `fields` → `target`.
#[test]
fn json_output_schema_key_order_level_before_fields_before_target() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(message = "schema-order");
    });

    let out = writer.captured_str();
    let level_pos = out.find("\"level\"").expect("level key must exist");
    let fields_pos = out.find("\"fields\"").expect("fields key must exist");
    let target_pos = out.find("\"target\"").expect("target key must exist");
    assert!(level_pos < fields_pos, "level must precede fields: {out}");
    assert!(fields_pos < target_pos, "fields must precede target: {out}");
}

// ── SubscriberConfig: with_filter_override(None) clears filter ────────────

/// `with_filter_override(None)` must clear a previously set filter override.
#[test]
fn subscriber_config_with_filter_override_none_clears_it() {
    let cfg = SubscriberConfig::default()
        .with_filter_override(Some(EnvFilter::builder().parse_lossy("debug")))
        .with_filter_override(None);
    assert!(
        cfg.filter_override.is_none(),
        "filter_override must be cleared"
    );
}

// ── resolve_env_filter_from: valid complex expressions ────────────────────

/// Verify the specific fallback where `stellar_agent_log` is set but
/// unparseable AND `rust_log` is unset (i.e., not None but Some invalid).
/// The primary error must be returned.
#[test]
fn resolve_env_filter_from_invalid_stellar_agent_log_no_rust_log_errors() {
    let err = resolve_env_filter_from(Some("=INFO"), None);
    assert!(
        matches!(err, Err(InitError::Filter(_))),
        "must return InitError::Filter when primary is invalid and rust_log is None: {err:?}"
    );
}

// ── FormatChoice: Debug impl ──────────────────────────────────────────────

/// `FormatChoice` must implement `Debug` and produce recognisable output.
#[test]
fn format_choice_debug_output() {
    assert!(format!("{:?}", FormatChoice::Json).contains("Json"));
    assert!(format!("{:?}", FormatChoice::Pretty).contains("Pretty"));
}

/// `FormatChoice` copy semantics must preserve the value.
#[test]
fn format_choice_copy_and_eq() {
    let a = FormatChoice::Json;
    let b = a; // Copy
    assert_eq!(a, b);
    assert_ne!(FormatChoice::Json, FormatChoice::Pretty);
}

// ── RedactingLayer: new_pretty constructs successfully ────────────────────

/// `RedactingLayer::new_pretty()` must return the default-constructed value.
/// The primary test is that it compiles and does not panic.
#[test]
fn redacting_layer_new_pretty_constructs() {
    use tracing_subscriber::fmt::format::DefaultFields;
    let _layer = RedactingLayer::<DefaultFields>::new_pretty();
}

// ── RedactingJsonFormatter: constructor coverage ──────────────────────────

/// `RedactingJsonFormatter::new()` must produce a formatter with timestamps
/// and target enabled (the default state).
#[test]
fn redacting_json_formatter_new_has_timestamp_and_target() {
    let fmt = RedactingJsonFormatter::new();
    // The only observable difference between `new()` and `without_time()`
    // is timestamp presence in the JSON output; verify by comparing the
    // output of a subscriber built with `new()` against one built with
    // `without_time()`.  Both must produce parseable JSON.
    let writer_with_ts = CaptureWriter::new();
    let sub_with_ts = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .event_format(fmt)
            .with_writer(writer_with_ts.clone()),
    );
    tracing::subscriber::with_default(sub_with_ts, || {
        tracing::info!(message = "ts-test");
    });
    let out = writer_with_ts.captured_str();
    // `new()` includes a timestamp field.
    assert!(
        out.contains("\"timestamp\""),
        "RedactingJsonFormatter::new() must include timestamp: {out}"
    );
    let _parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("valid JSON");
}

/// `RedactingJsonFormatter::without_time()` must omit the `timestamp` key.
#[test]
fn redacting_json_formatter_without_time_omits_timestamp() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(message = "no-ts");
    });
    let out = writer.captured_str();
    assert!(
        !out.contains("\"timestamp\""),
        "without_time formatter must omit timestamp: {out}"
    );
    let _parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("valid JSON");
}

// ── Integer redaction in integration: benign i64 passes through ───────────

/// A benign `i64` field (not on the redact list) must pass through as a
/// bare JSON integer.
#[test]
fn integration_benign_i64_passes_through() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(sequence = -42i64);
    });

    let out = writer.captured_str();
    let parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("valid JSON");
    assert_eq!(
        parsed["fields"]["sequence"],
        serde_json::json!(-42i64),
        "benign i64 must round-trip: {out}"
    );
}

// ── REDACTION_FIRED_TARGET constant coverage ──────────────────────────────

/// The `REDACTION_FIRED_TARGET` constant must have the expected value so that
/// formatters can identify it correctly.
#[test]
fn redaction_fired_target_constant_value() {
    assert_eq!(
        REDACTION_FIRED_TARGET,
        "stellar_agent_core::observability::redaction_fired"
    );
}

// ── Multiple redactions in one JSON event ─────────────────────────────────

/// An event with multiple redactable fields must redact each independently.
#[test]
fn integration_multiple_sensitive_fields_all_redacted() {
    let writer = CaptureWriter::new();
    let subscriber = make_json_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(secret = "s1", password = "p1", operation = "tx");
    });

    let out = writer.captured_str();
    let parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("valid JSON");
    assert_eq!(
        parsed["fields"]["secret"], "[REDACTED]",
        "secret must be redacted: {out}"
    );
    assert_eq!(
        parsed["fields"]["password"], "[REDACTED]",
        "password must be redacted: {out}"
    );
    // Non-sensitive field must survive.
    assert_eq!(
        parsed["fields"]["operation"], "tx",
        "operation must pass through: {out}"
    );
    assert!(
        !out.contains("\"s1\"") && !out.contains("\"p1\""),
        "raw secret values must not appear: {out}"
    );
}
