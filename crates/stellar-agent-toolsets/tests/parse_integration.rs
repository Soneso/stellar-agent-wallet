//! Integration tests for [`stellar_agent_toolsets::parse_toolset`].
#![allow(clippy::unwrap_used, clippy::expect_used)]
//!
//! Each test group covers one category of the agentskills format specification.
//!
//! Fixtures live under `tests/fixtures/`:
//! - `valid-minimal/` — one valid minimal toolset (name + description only).
//! - `valid-full/` — one valid toolset with all optional fields + capability manifest.
//! - `invalid-*/` — one toolset per refusal rule.

use std::path::Path;

use stellar_agent_toolsets::{Capability, ToolsetFormatError, parse_toolset};

fn fixture(rel: &str) -> std::path::PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir).join("tests/fixtures").join(rel)
}

// ── Valid minimal toolset ───────────────────────────────────────────────────────

#[test]
fn ac1_valid_minimal_toolset_parses() {
    let dir = fixture("valid-minimal/read-balance");
    let toolset = parse_toolset(&dir).expect("valid minimal toolset should parse");
    assert_eq!(toolset.name, "read-balance");
    assert!(!toolset.description.is_empty());
    assert!(toolset.license.is_none());
    assert!(toolset.compatibility.is_none());
    assert!(toolset.metadata.is_empty());
    assert!(toolset.allowed_tools.is_empty());
    assert!(toolset.capabilities.is_empty());
    assert!(!toolset.instructions.is_empty());
}

// ── Valid full toolset ──────────────────────────────────────────────────────────

#[test]
fn ac1_valid_full_toolset_parses() {
    let dir = fixture("valid-full/portfolio-summary");
    let toolset = parse_toolset(&dir).expect("valid full toolset should parse");
    assert_eq!(toolset.name, "portfolio-summary");
    assert_eq!(toolset.license.as_deref(), Some("Apache-2.0"));
    assert!(toolset.compatibility.is_some());
    assert!(!toolset.metadata.is_empty());
    assert!(!toolset.allowed_tools.is_empty());
    // Capability manifest: read-balance + observe-event
    assert!(toolset.capabilities.contains(Capability::ReadBalance));
    assert!(toolset.capabilities.contains(Capability::ObserveEvent));
    assert_eq!(toolset.capabilities.len(), 2);
    // metadata map retains the capability key (not stripped).
    assert!(toolset.metadata.contains_key("stellar-agent-capabilities"));
}

// ── Name validation ───────────────────────────────────────────────────────────

#[test]
fn ac2_name_too_long_refused() {
    let dir = fixture(
        "invalid-name-too-long/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let err = parse_toolset(&dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::NameTooLong),
        "expected NameTooLong, got {err:?}"
    );
}

#[test]
fn ac2_name_uppercase_refused() {
    let dir = fixture("invalid-name-uppercase/MyToolset");
    let err = parse_toolset(&dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::NameInvalidChar),
        "expected NameInvalidChar, got {err:?}"
    );
}

#[test]
fn ac2_name_leading_hyphen_refused() {
    let dir = fixture("invalid-name-leading-hyphen/-bad-toolset");
    let err = parse_toolset(&dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::NameLeadingTrailingHyphen),
        "expected NameLeadingTrailingHyphen, got {err:?}"
    );
}

#[test]
fn ac2_name_consecutive_hyphens_refused() {
    let dir = fixture("invalid-name-consecutive-hyphens/bad--toolset");
    let err = parse_toolset(&dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::NameConsecutiveHyphens),
        "expected NameConsecutiveHyphens, got {err:?}"
    );
}

#[test]
fn ac2_name_dir_mismatch_refused() {
    let dir = fixture("invalid-name-dir-mismatch/my-toolset");
    let err = parse_toolset(&dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::NameDirMismatch { .. }),
        "expected NameDirMismatch, got {err:?}"
    );
}

// ── Description + compatibility validation ────────────────────────────────────

#[test]
fn ac3_description_empty_refused() {
    let dir = fixture("invalid-description-empty/no-desc");
    let err = parse_toolset(&dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::DescriptionEmpty),
        "expected DescriptionEmpty, got {err:?}"
    );
}

#[test]
fn ac3_description_too_long_refused() {
    let dir = fixture("invalid-description-too-long/long-desc");
    let err = parse_toolset(&dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::DescriptionTooLong),
        "expected DescriptionTooLong, got {err:?}"
    );
}

// ── Capability manifest ───────────────────────────────────────────────────────

#[test]
fn ac4_known_capability_tokens_parse() {
    // Tested via the valid-full fixture above (ac1_valid_full_toolset_parses).
    let dir = fixture("valid-full/portfolio-summary");
    let toolset = parse_toolset(&dir).unwrap();
    assert!(toolset.capabilities.contains(Capability::ReadBalance));
    assert!(toolset.capabilities.contains(Capability::ObserveEvent));
}

#[test]
fn ac4_unknown_token_refused() {
    let dir = fixture("invalid-capability-unknown/unknown-cap");
    let err = parse_toolset(&dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::UnknownCapability { .. }),
        "expected UnknownCapability, got {err:?}"
    );
}

#[test]
fn ac4_capability_non_string_refused() {
    let dir = fixture("invalid-capability-non-string/non-string-cap");
    let err = parse_toolset(&dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::CapabilityManifestMalformed { .. }),
        "expected CapabilityManifestMalformed, got {err:?}"
    );
}

// ── Structural parse failures ─────────────────────────────────────────────────

#[test]
fn ac5_no_frontmatter_refused() {
    let dir = fixture("invalid-no-frontmatter/my-toolset");
    let err = parse_toolset(&dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::MissingFrontmatter),
        "expected MissingFrontmatter, got {err:?}"
    );
}

// ── No-bare-sign airtightness ─────────────────────────────────────────────────

#[test]
fn ac6_bare_sign_transaction_refused() {
    let dir = fixture("invalid-capability-bare-sign/sign-toolset");
    let err = parse_toolset(&dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::BareSignTransactionForbidden),
        "expected BareSignTransactionForbidden, got {err:?}"
    );
}

#[test]
fn ac6_sign_transaction_uppercase_refused_at_charset_gate() {
    // Inline toolset with Sign-Transaction (uppercase) in metadata.
    // Parse inline via a temp dir.
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("test-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    write!(
        f,
        "---\nname: test-toolset\ndescription: test\nmetadata:\n  stellar-agent-capabilities: Sign-Transaction\n---\n"
    )
    .unwrap();

    let err = parse_toolset(&toolset_dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::CapabilityTokenInvalidChar { .. }),
        "expected CapabilityTokenInvalidChar for 'Sign-Transaction', got {err:?}"
    );
}

#[test]
fn ac6_sign_transaction_all_caps_refused_at_charset_gate() {
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("test-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    write!(
        f,
        "---\nname: test-toolset\ndescription: test\nmetadata:\n  stellar-agent-capabilities: SIGN-TRANSACTION\n---\n"
    )
    .unwrap();

    let err = parse_toolset(&toolset_dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::CapabilityTokenInvalidChar { .. }),
        "expected CapabilityTokenInvalidChar for 'SIGN-TRANSACTION', got {err:?}"
    );
}

#[test]
fn ac6_sign_transaction_underscore_refused_at_charset_gate() {
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("test-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    write!(
        f,
        "---\nname: test-toolset\ndescription: test\nmetadata:\n  stellar-agent-capabilities: sign_transaction\n---\n"
    )
    .unwrap();

    let err = parse_toolset(&toolset_dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::CapabilityTokenInvalidChar { .. }),
        "expected CapabilityTokenInvalidChar for 'sign_transaction', got {err:?}"
    );
}

#[test]
fn ac6_sign_transaction_whitespace_padded_refused() {
    // Whitespace is stripped by tokenisation, leaving "sign-transaction" which
    // then hits BareSignTransactionForbidden.
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("test-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    write!(
        f,
        "---\nname: test-toolset\ndescription: test\nmetadata:\n  stellar-agent-capabilities: \"  sign-transaction  \"\n---\n"
    )
    .unwrap();

    let err = parse_toolset(&toolset_dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::BareSignTransactionForbidden),
        "expected BareSignTransactionForbidden for whitespace-padded token, got {err:?}"
    );
}

#[test]
fn ac6_sign_transaction_unicode_homoglyph_refused_at_charset_gate() {
    // Cyrillic 's' look-alike (ѕ, U+0455) — charset gate must catch it.
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("test-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    // ѕ is U+0455, a Cyrillic small letter dze that looks like 's'
    write!(
        f,
        "---\nname: test-toolset\ndescription: test\nmetadata:\n  stellar-agent-capabilities: \"\u{0455}ign-transaction\"\n---\n"
    )
    .unwrap();

    let err = parse_toolset(&toolset_dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::CapabilityTokenInvalidChar { .. }),
        "expected CapabilityTokenInvalidChar for homoglyph token, got {err:?}"
    );
}

// ── Capability smuggling ──────────────────────────────────────────────────────

#[test]
fn ac7_duplicate_capability_key_refused() {
    // YAML permits duplicate keys; we refuse.
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("test-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    write!(
        f,
        "---\nname: test-toolset\ndescription: test\nmetadata:\n  stellar-agent-capabilities: read-balance\n  stellar-agent-capabilities: observe-event\n---\n"
    )
    .unwrap();

    let err = parse_toolset(&toolset_dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::DuplicateKey { .. }),
        "expected DuplicateKey, got {err:?}"
    );
}

#[test]
fn ac7_duplicate_top_level_key_refused() {
    let dir = fixture("invalid-duplicate-key/dup-key");
    let err = parse_toolset(&dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::DuplicateKey { .. }),
        "expected DuplicateKey, got {err:?}"
    );
}

#[test]
fn ac7_reserved_metadata_key_refused() {
    let dir = fixture("invalid-reserved-metadata-key/reserved-key");
    let err = parse_toolset(&dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::ReservedMetadataKey { .. }),
        "expected ReservedMetadataKey, got {err:?}"
    );
}

#[test]
fn ac7_capability_invalid_char_refused() {
    let dir = fixture("invalid-capability-invalid-char/bad-char-cap");
    let err = parse_toolset(&dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::CapabilityTokenInvalidChar { .. }),
        "expected CapabilityTokenInvalidChar, got {err:?}"
    );
}

// ── Resource bounds ───────────────────────────────────────────────────────────

#[test]
fn ac8_file_too_large_refused() {
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("big-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    // 256 KiB + 1 byte
    let big_content = vec![b'x'; 256 * 1024 + 1];
    f.write_all(&big_content).unwrap();

    let err = parse_toolset(&toolset_dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::ToolsetFileTooLarge { .. }),
        "expected ToolsetFileTooLarge, got {err:?}"
    );
}

#[test]
fn ac8_yaml_alias_bomb_refused_without_oom() {
    // A minimal alias-bomb: define anchor &a on a scalar, then alias *a many
    // times.  The event-based parser must emit Event::Alias immediately and we
    // refuse pre-expansion — no OOM, no stack-overflow.
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("alias-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    write!(f, "---\na: &a large_value\nb: *a\nc: *a\n---\n").unwrap();

    let err = parse_toolset(&toolset_dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::YamlAnchorsForbidden),
        "expected YamlAnchorsForbidden for alias bomb, got {err:?}"
    );
}

#[test]
fn ac8_deep_nesting_refused_without_stack_overflow() {
    // 10 levels of nesting > MAX_DEPTH (8).
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("deep-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    write!(
        f,
        "---\na:\n  b:\n    c:\n      d:\n        e:\n          f:\n            g:\n              h:\n                i:\n                  j: deep\n---\n"
    )
    .unwrap();

    let err = parse_toolset(&toolset_dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::FrontmatterTooDeep),
        "expected FrontmatterTooDeep, got {err:?}"
    );
}

/// A deeply-nested FLOW-style document must return `Err` without stack overflow.
///
/// The iterative event-pull loop must stop at the depth bound before the structure
/// is materialised.  This test exercises the full `parse_toolset` path (not just
/// `parse_frontmatter`) to ensure the depth bound is wired end-to-end.
#[test]
fn ac8_deeply_nested_flow_document_refused_without_stack_overflow() {
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("deep-flow-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();

    // Build a frontmatter string with 20 000 open brackets (~20 KB of `[`).
    // Each `[` encodes one level of FLOW sequence nesting; MAX_DEPTH is 8, so
    // the guard fires after 9 `[` chars — the rest is never reached.
    let deep_brackets: String = "[".repeat(20_000);
    write!(f, "---\n{deep_brackets}\n---\n").unwrap();

    let err = parse_toolset(&toolset_dir).unwrap_err();
    assert!(
        matches!(
            err,
            ToolsetFormatError::FrontmatterTooDeep
                | ToolsetFormatError::MalformedFrontmatter { .. }
        ),
        "expected FrontmatterTooDeep or MalformedFrontmatter for deeply-nested FLOW document; \
        got {err:?}"
    );
}

/// A deeply-nested FLOW mapping must also be refused before parser recursion.
///
/// `{a:{a:…}}` repeated to depth 5 000 must be caught by the event-level depth
/// bound without stack overflow.
#[test]
fn ac8_deeply_nested_flow_mapping_refused_without_stack_overflow() {
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("deep-map-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();

    // 5 000 levels of `{a:` is ~15 KB.
    let levels = 5_000_usize;
    let deep_braces: String = "{a:".repeat(levels);
    write!(f, "---\n{deep_braces}\n---\n").unwrap();

    let err = parse_toolset(&toolset_dir).unwrap_err();
    assert!(
        matches!(
            err,
            ToolsetFormatError::FrontmatterTooDeep
                | ToolsetFormatError::MalformedFrontmatter { .. }
        ),
        "expected FrontmatterTooDeep or MalformedFrontmatter for deeply-nested FLOW mapping; \
        got {err:?}"
    );
}

// ── Render hardening ──────────────────────────────────────────────────────────

#[test]
fn ac9_ansi_in_error_token_is_sanitised() {
    // A token with an ANSI escape sequence; the Display of the error must not
    // echo raw escape bytes.
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("test-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    // Token with ANSI red-text escape before "Unknown" and reset after.
    write!(
        f,
        "---\nname: test-toolset\ndescription: test\nmetadata:\n  stellar-agent-capabilities: \"\\x1b[31mUnknown\\x1b[0m\"\n---\n"
    )
    .unwrap();

    let result = parse_toolset(&toolset_dir);
    // Whether it errors or succeeds, the error Display must not contain raw ESC.
    if let Err(ref e) = result {
        let rendered = e.to_string();
        assert!(
            !rendered.contains('\x1b'),
            "ANSI escape leaked into error message: {rendered:?}"
        );
    }
}

#[test]
fn ac9_newline_in_error_token_sanitised() {
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("test-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    // Capability token with a literal newline injected via YAML scalar folding.
    // YAML plain scalars cannot contain newlines, so use a double-quoted scalar.
    write!(
        f,
        "---\nname: test-toolset\ndescription: test\nmetadata:\n  stellar-agent-capabilities: \"read\\nbalance\"\n---\n"
    )
    .unwrap();

    let result = parse_toolset(&toolset_dir);
    if let Err(ref e) = result {
        let rendered = e.to_string();
        assert!(
            !rendered.contains('\n') || rendered.lines().count() == 1,
            "newline leaked into single-line error message: {rendered:?}"
        );
    }
}

#[test]
fn ac9_10kb_token_truncated_in_error_display() {
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("test-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    // A 10 KB token; write as a quoted string to avoid YAML parsing issues.
    let big_token = "a".repeat(10_240);
    write!(
        f,
        "---\nname: test-toolset\ndescription: test\nmetadata:\n  stellar-agent-capabilities: \"{big_token}\"\n---\n"
    )
    .unwrap();

    if let Err(e) = parse_toolset(&toolset_dir) {
        let rendered = e.to_string();
        // The rendered error must not be more than ~300 chars (256 + overhead).
        assert!(
            rendered.len() <= 512,
            "large token not truncated in error: len={}",
            rendered.len()
        );
        // Must end with the ellipsis marker if truncated.
        assert!(
            rendered.contains('\u{2026}'),
            "truncated error should contain ellipsis: {rendered}"
        );
    }
}

// ── No-panic table ────────────────────────────────────────────────────────────

/// Feed adversarial inputs through `parse_toolset` and assert that each one
/// returns `Err`, never panics, OOMs, or stack-overflows.
#[test]
fn ac10_no_panic_table() {
    use std::io::Write;

    struct Case {
        name: &'static str,
        content: &'static [u8],
    }

    let cases: &[Case] = &[
        Case {
            name: "truncated-utf8",
            content: b"---\nname: foo\ndesc",
        },
        Case {
            name: "garbage-binary",
            content: b"---\n\x00\x01\x02\x03\xff\xfe\n---\n",
        },
        Case {
            name: "alias-bomb",
            content: b"---\na: &a large\nb: *a\n---\n",
        },
        Case {
            name: "deep-nest",
            content: b"---\na:\n  b:\n    c:\n      d:\n        e:\n          f:\n            g:\n              h:\n                i: x\n---\n",
        },
        Case {
            name: "empty-file",
            content: b"",
        },
        Case {
            name: "only-fence",
            content: b"---\n",
        },
    ];

    for case in cases {
        let tmp = tempfile::TempDir::new().unwrap();
        let toolset_dir = tmp.path().join("test-toolset");
        std::fs::create_dir_all(&toolset_dir).unwrap();
        let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
        f.write_all(case.content).unwrap();

        let result = parse_toolset(&toolset_dir);
        assert!(
            result.is_err(),
            "no-panic table case '{}' unexpectedly succeeded",
            case.name
        );
    }
}

// ── Forward-compatibility: unknown keys are skipped, known keys still parsed ──

/// An unknown mapping-valued top-level key BEFORE the `metadata` block must not
/// swallow the real metadata block.  The `read-balance` capability declared AFTER
/// the unknown map must be parsed.
#[test]
fn unknown_map_before_metadata_capabilities_preserved() {
    let dir = fixture("forward-compat-unknown-map/test-toolset");
    let toolset =
        parse_toolset(&dir).expect("toolset with unknown map before metadata should parse");
    assert!(
        toolset
            .capabilities
            .contains(stellar_agent_toolsets::Capability::ReadBalance),
        "read-balance must be parsed even when an unknown map precedes the metadata block; \
        got capabilities: {:?}",
        toolset.capabilities.len()
    );
    assert_eq!(toolset.capabilities.len(), 1);
}

/// `sign-transaction` in `metadata` placed AFTER a leading unknown nested mapping
/// must still produce `BareSignTransactionForbidden`, NOT `Ok` with an empty
/// capability set.
#[test]
fn sign_transaction_behind_unknown_map_still_refused() {
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("test-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    // NOTE: indentation must be explicit in the literal (no `\n\` continuation).
    f.write_all(
        b"---\nname: test-toolset\ndescription: test\nextended-info:\n  author: example\n  url: https://example.com\nmetadata:\n  stellar-agent-capabilities: sign-transaction\n---\n",
    )
    .unwrap();

    let err = parse_toolset(&toolset_dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::BareSignTransactionForbidden),
        "expected BareSignTransactionForbidden when sign-transaction is behind an unknown map; \
        got {err:?}"
    );
}

/// An unknown mapping-valued top-level key followed by a `stellar-agent-policy`
/// metadata key must still produce `ReservedMetadataKey`.
#[test]
fn unknown_map_then_reserved_metadata_key_refused() {
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("test-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    f.write_all(
        b"---\nname: test-toolset\ndescription: test\nextended-info:\n  author: example\nmetadata:\n  stellar-agent-policy: some-policy\n---\n",
    )
    .unwrap();

    let err = parse_toolset(&toolset_dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::ReservedMetadataKey { .. }),
        "expected ReservedMetadataKey; got {err:?}"
    );
}

/// An inner key of an unknown nested map whose name equals a top-level key
/// (e.g. `name:`) must NOT produce a false `DuplicateKey` error.
/// The inner key lives in a different (skipped) namespace.
#[test]
fn inner_key_same_as_top_level_no_false_duplicate() {
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("test-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    // The inner `name:` key inside `extended-info` must be skipped, not inserted
    // into top_level_seen_keys.
    // NOTE: use write_all with byte slices to avoid Rust string-literal `\n\`
    // line-continuation stripping indentation.
    f.write_all(
        b"---\nname: test-toolset\ndescription: A test toolset.\nextended-info:\n  name: inner-name-should-be-skipped\n  version: \"1.0\"\nmetadata:\n  stellar-agent-capabilities: read-balance\n---\n",
    )
    .unwrap();

    let toolset = parse_toolset(&toolset_dir)
        .expect("inner key with same name as top-level key must NOT produce DuplicateKey");
    assert!(
        toolset
            .capabilities
            .contains(stellar_agent_toolsets::Capability::ReadBalance)
    );
}

/// An unknown SEQUENCE-valued top-level key must be skipped without producing a
/// spurious `DuplicateKey` error.
#[test]
fn unknown_sequence_top_level_no_spurious_error() {
    let dir = fixture("forward-compat-unknown-seq/test-toolset");
    let toolset =
        parse_toolset(&dir).expect("toolset with unknown sequence top-level key should parse");
    assert!(
        toolset
            .capabilities
            .contains(stellar_agent_toolsets::Capability::ReadBalance),
        "read-balance must be parsed after a top-level sequence key; got {:?}",
        toolset.capabilities.len()
    );
}

/// Malformed YAML must produce `MalformedFrontmatter`.
#[test]
fn ac5_malformed_yaml_produces_malformed_frontmatter() {
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("test-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    // Deliberately invalid YAML: unmatched quote, tab in indentation.
    write!(
        f,
        "---\nname: test-toolset\ndescription: \"unterminated\nfoo: bar\n---\n"
    )
    .unwrap();

    let err = parse_toolset(&toolset_dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::MalformedFrontmatter { .. }),
        "expected MalformedFrontmatter for invalid YAML, got {err:?}"
    );
}

/// Non-UTF-8 bytes must produce `NotUtf8`.
#[test]
fn ac5_non_utf8_bytes_produce_not_utf8() {
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("test-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    // Write a frontmatter fence followed by invalid UTF-8 bytes.
    f.write_all(b"---\n").unwrap();
    f.write_all(b"\xff\xfe invalid utf8\n").unwrap();
    f.write_all(b"---\n").unwrap();

    let err = parse_toolset(&toolset_dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::NotUtf8),
        "expected NotUtf8 for non-UTF-8 TOOLSET.md, got {err:?}"
    );
}

/// CRLF frontmatter fence must be accepted (`split_frontmatter` handles CRLF).
#[test]
fn ac5_crlf_frontmatter_fence_accepted() {
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("test-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    // CRLF line endings throughout, including the opening fence.
    f.write_all(b"---\r\nname: test-toolset\r\ndescription: A test toolset.\r\n---\r\n")
        .unwrap();

    let toolset = parse_toolset(&toolset_dir).expect("CRLF frontmatter fence must be accepted");
    assert_eq!(toolset.name, "test-toolset");
}

/// A lone CR (`\r` without `\n`) opening fence is NOT accepted.
///
/// The agentskills format requires `\n` or `\r\n` line endings for the TOOLSET.md
/// fence; lone CR is not a recognised line ending.
#[test]
fn ac5_lone_cr_frontmatter_fence_refused() {
    use std::io::Write;
    let tmp = tempfile::TempDir::new().unwrap();
    let toolset_dir = tmp.path().join("test-toolset");
    std::fs::create_dir_all(&toolset_dir).unwrap();
    let mut f = std::fs::File::create(toolset_dir.join("TOOLSET.md")).unwrap();
    // Lone CR after the opening fence (not CRLF, not LF).
    f.write_all(b"---\rname: test-toolset\rdescription: A test toolset.\r---\r")
        .unwrap();

    let err = parse_toolset(&toolset_dir).unwrap_err();
    assert!(
        matches!(err, ToolsetFormatError::MissingFrontmatter),
        "lone CR opening fence must produce MissingFrontmatter, got {err:?}"
    );
}

// ── Render sanitisation: error Display does not leak raw control chars ────────

#[test]
fn error_display_io_is_sanitised() {
    let err = ToolsetFormatError::Io {
        detail: "error\x01detail".to_owned(),
    };
    let s = err.to_string();
    assert!(!s.contains('\x01'), "control char leaked: {s:?}");
}

#[test]
fn error_display_duplicate_key_sanitised() {
    let err = ToolsetFormatError::DuplicateKey {
        key: "key\x1b[31mred\x1b[0m".to_owned(),
    };
    let s = err.to_string();
    assert!(!s.contains('\x1b'), "ANSI escape leaked: {s:?}");
}

#[test]
fn error_display_unknown_capability_sanitised() {
    let err = ToolsetFormatError::UnknownCapability {
        token: "tok\ninjection".to_owned(),
    };
    let s = err.to_string();
    // The rendered error must be a single line (no newline injection).
    assert!(s.lines().count() == 1, "newline injected into error: {s:?}");
}
