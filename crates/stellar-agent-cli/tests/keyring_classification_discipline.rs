//! Source-scan regression test for the keyring-failure classification
//! discipline (issue #94).
//!
//! Every production keyring operation — entry construction (`Entry::new`),
//! reads (`get_password`), and writes (`set_password`) — must route its
//! `keyring_core::Error` through `classify_keyring_error` /
//! `map_keyring_error` (hosted in `stellar-agent-core`, re-exported from
//! `stellar_agent_network::keyring`). Hand-rolling
//! `AuthError::KeyringNotFound` around a keyring operation misreports
//! environmental causes — most notably a non-interactive Windows session,
//! which must surface as `AuthError::KeyringInteractiveSessionRequired`, not
//! "not found".
//!
//! This test enforces the issue's acceptance criterion — "no production call
//! site hand-rolls `KeyringNotFound` around a keyring operation" — as a
//! per-occurrence rule: within a bounded window after each raw keyring-op
//! occurrence, an `AuthError::KeyringNotFound { ... }` construction is
//! forbidden unless the occurrence is on the explicit allow-set below. The
//! per-occurrence granularity is what makes the rule mutation-gateable: any
//! single arm that regresses to the hand-rolled shape fails this test.
//!
//! Mechanics that matter (and why the naive `split("#[cfg(test)]")` used by
//! `audit_path_discipline.rs` is insufficient here):
//! - Test modules are excluded ATTRIBUTE-AWARELY: only a `#[cfg(test)]` (or
//!   `#[cfg(any(test, ...))]`) attribute that gates a `mod` item is removed,
//!   brace-matched to its end. A first-substring split defeats itself on a
//!   mid-file `#[cfg(test)] fn` helper (mcp `tools/common.rs` has one at the
//!   `assert_business_envelope` helper, with the production `load_attestation_key`
//!   AFTER it) and on a `#[cfg(any(test, feature = "test-helpers"))]` field
//!   (mcp `server.rs`), both of which would wrongly truncate the production
//!   scan.
//! - Comments and string / char / raw-string literal interiors are blanked
//!   before matching, so braces inside `format!` templates do not corrupt the
//!   brace-matching and message text like `"AuthError::KeyringNotFound"` (a
//!   diagnostic label) is not mistaken for a construction.

#![allow(clippy::expect_used, clippy::panic, reason = "test-only")]

/// A raw keyring-op occurrence that is permitted to sit near an
/// `AuthError::KeyringNotFound { ... }` construction/pattern, with the reason.
///
/// `file` is a path suffix; `anchor` is a token that must appear inside the
/// occurrence's forbidden window (so the exemption is pinned to the specific
/// code region — a brand-new raw op elsewhere in the same file is NOT
/// exempted).
struct AllowEntry {
    file: &'static str,
    anchor: &'static str,
    invariant: &'static str,
}

/// The exhaustive allow-set. Any occurrence not covered here that constructs
/// `AuthError::KeyringNotFound` within its window is a discipline violation.
const ALLOW_SET: &[AllowEntry] = &[
    // The classifier home. Constructs KeyringNotFound as its OUTPUT; no raw
    // keyring op runs inside these functions, so this entry is a forward guard
    // rather than a currently-firing occurrence.
    AllowEntry {
        file: "stellar-agent-core/src/keyring_errors.rs",
        anchor: "classify_keyring_error",
        invariant: "the classifier itself maps keyring_core::Error into AuthError; \
                    KeyringNotFound is the classified OUTPUT, not a hand-roll",
    },
    // init_platform_keyring_store hand-rolls KeyringNotFound around Store::new()
    // (store CONSTRUCTION, not a credential op). Per the classifier's own
    // contract, the interactive-session (1312) case cannot arise from store
    // construction, so classification is not applicable. Store::new() is not a
    // raw-op needle, so this is a forward guard.
    AllowEntry {
        file: "stellar-agent-network/src/keyring.rs",
        anchor: "init_platform_keyring_store",
        invariant: "store construction cannot surface the interactive-session case; \
                    see the invariant comment in init_platform_keyring_store",
    },
    // Non-AuthError typed errors: NoEntry is distinguished, every other cause
    // keeps the raw text inside the crate-local error and nothing is discarded.
    // These do not construct AuthError::KeyringNotFound, so they are forward
    // guards; full surface-layer classification is a candidate follow-up.
    AllowEntry {
        file: "stellar-agent-network/src/policy_state/store.rs",
        anchor: "WindowStoreError::Keyring",
        invariant: "generation-counter keyring failures are carried in \
                    WindowStoreError::Keyring; NoEntry distinguished (first-run signal)",
    },
    AllowEntry {
        file: "stellar-agent-network/src/counterparty/cache.rs",
        anchor: "CounterpartyError::KeyringUnavailable",
        invariant: "counterparty HMAC-key keyring failures are carried in \
                    CounterpartyError::KeyringUnavailable; NoEntry distinguished",
    },
    // url::Url::set_password — matches the `.set_password(` needle but is not a
    // keyring API.
    AllowEntry {
        file: "stellar-agent-network/src/redact.rs",
        anchor: "set_password(None)",
        invariant: "url::Url::set_password redacts a URL userinfo password; not a \
                    keyring operation",
    },
];

/// Raw keyring-op needles. `Entry::new(` covers both `KeyringEntry::new(` and
/// `keyring_core::Entry::new(`. Known limitation: an alias import
/// (`use keyring_core::Entry as X; X::new(...)`) evades the constructor
/// needle; the credential-op needles match by method name regardless of any
/// alias, and entry construction cannot produce the interactive-session case,
/// so the misreport class stays covered.
const RAW_OP_NEEDLES: &[&str] = &["Entry::new(", ".get_password(", ".set_password("];

/// The forbidden construction/pattern.
const FORBIDDEN: &str = "AuthError::KeyringNotFound {";

/// Number of lines after (and including) a raw-op occurrence's line that form
/// the forbidden window. The bound is deliberately tight: every hand-rolled
/// arm this rule guards against sits inside the `map_err` closure a few lines
/// after its raw op, while the nearest LEGITIMATE `KeyringNotFound` (the
/// S-strkey parse rewrap after `signer_from_keyring`'s classified
/// `get_password` in network/src/keyring.rs) sits 12 lines after the op and
/// must stay OUTSIDE the window — an allow-set exemption there would also
/// mask a regression of the classified arm itself.
const WINDOW_LINES: usize = 10;

#[test]
fn no_production_call_site_hand_rolls_keyring_not_found() {
    for allow in ALLOW_SET {
        assert!(
            !allow.invariant.trim().is_empty(),
            "allow-set entry for {} (anchor `{}`) must document its invariant",
            allow.file,
            allow.anchor
        );
    }

    let crates_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ is the parent of this crate's manifest dir");

    let mut rs_files = Vec::new();
    let mut crates_scanned = 0usize;
    for entry in std::fs::read_dir(crates_root).expect("read crates/") {
        let crate_dir = entry.expect("crates/ entry").path();
        let src = crate_dir.join("src");
        if src.is_dir() {
            crates_scanned += 1;
            collect_rs_files(&src, &mut rs_files);
        }
    }
    assert!(
        crates_scanned >= 30,
        "expected to scan every workspace crate's src/ tree; found only {crates_scanned}"
    );

    let mut total_raw_ops = 0usize;
    let mut violations = Vec::new();

    for path in &rs_files {
        let source = std::fs::read_to_string(path).expect("read source");
        let production = strip_test_modules(&clean_source(&source));
        let lines: Vec<&str> = production.lines().collect();
        let rel = relative_path(path, crates_root);

        for (idx, line) in lines.iter().enumerate() {
            if !RAW_OP_NEEDLES.iter().any(|n| line.contains(n)) {
                continue;
            }
            total_raw_ops += 1;

            let window_end = (idx + WINDOW_LINES).min(lines.len().saturating_sub(1));
            let window = lines[idx..=window_end].join("\n");
            if !window.contains(FORBIDDEN) {
                continue;
            }

            // A forbidden construction sits in this occurrence's window. It is
            // permitted only if an allow-set entry for this file has its anchor
            // inside the window.
            let exempt = ALLOW_SET
                .iter()
                .any(|a| rel.ends_with(a.file) && window.contains(a.anchor));
            if !exempt {
                violations.push(format!(
                    "{rel}:{} — a raw keyring op is followed within {WINDOW_LINES} lines by \
                     `{FORBIDDEN} ... }}`; route the failure through \
                     `map_keyring_error(&e, &<coord>.service)` (or add an allow-set entry \
                     with a documented invariant if this is a legitimate exemption)",
                    idx + 1
                ));
            }
        }
    }

    assert!(
        total_raw_ops > 15,
        "expected the scan to see the known production keyring-op sites; found {total_raw_ops}"
    );
    assert!(
        violations.is_empty(),
        "keyring-classification discipline violated:\n{}",
        violations.join("\n")
    );
}

/// Recursively collects `.rs` files under `dir`.
fn collect_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Renders `path` relative to `crates_root` with forward slashes, so the
/// allow-set suffixes match on every platform.
fn relative_path(path: &std::path::Path, crates_root: &std::path::Path) -> String {
    path.strip_prefix(crates_root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Blanks comment bodies and string / char / raw-string literal interiors,
/// replacing each affected byte with a space and preserving newlines so line
/// numbers are stable. After this pass, every `{`/`}` is structural and every
/// remaining `AuthError::KeyringNotFound {` or raw-op needle is real code.
fn clean_source(src: &str) -> String {
    let b = src.as_bytes();
    let n = b.len();
    let mut out = b.to_vec();
    let blank = |out: &mut [u8], idx: usize| {
        if out[idx] != b'\n' {
            out[idx] = b' ';
        }
    };

    let mut i = 0;
    while i < n {
        let c = b[i];

        // Line comment.
        if c == b'/' && i + 1 < n && b[i + 1] == b'/' {
            while i < n && b[i] != b'\n' {
                out[i] = b' ';
                i += 1;
            }
            continue;
        }

        // Block comment (non-nesting is sufficient for this codebase's needs;
        // rustfmt does not emit nested block comments in the scanned files).
        if c == b'/' && i + 1 < n && b[i + 1] == b'*' {
            out[i] = b' ';
            out[i + 1] = b' ';
            i += 2;
            while i < n {
                if b[i] == b'*' && i + 1 < n && b[i + 1] == b'/' {
                    out[i] = b' ';
                    out[i + 1] = b' ';
                    i += 2;
                    break;
                }
                blank(&mut out, i);
                i += 1;
            }
            continue;
        }

        // Raw string: r"..." / r#"..."# / br"..." / br#"..."#.
        if (c == b'r' || c == b'b')
            && is_ident_boundary(b, i)
            && let Some(after) = try_blank_raw_string(&mut out, b, i)
        {
            i = after;
            continue;
        }

        // Normal string literal.
        if c == b'"' {
            i += 1; // keep the opening quote
            while i < n {
                match b[i] {
                    b'\\' => {
                        out[i] = b' ';
                        if i + 1 < n {
                            blank(&mut out, i + 1);
                        }
                        i += 2;
                    }
                    b'"' => {
                        i += 1; // keep the closing quote
                        break;
                    }
                    _ => {
                        blank(&mut out, i);
                        i += 1;
                    }
                }
            }
            continue;
        }

        // Char literal or lifetime.
        if c == b'\'' {
            i = blank_char_or_skip_lifetime(&mut out, b, i);
            continue;
        }

        i += 1;
    }

    String::from_utf8(out).expect("clean_source produced valid utf-8")
}

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// True when the byte at `i` begins a token (so `r`/`b` there could be a raw
/// string prefix rather than the tail of an identifier).
fn is_ident_boundary(b: &[u8], i: usize) -> bool {
    i == 0 || !is_ident_byte(b[i - 1])
}

/// If `b[start..]` opens a raw string, blank its interior and return the index
/// just past the closing delimiter; otherwise return `None`.
fn try_blank_raw_string(out: &mut [u8], b: &[u8], start: usize) -> Option<usize> {
    let n = b.len();
    let mut j = start;
    if b[j] == b'b' {
        j += 1;
    }
    if j >= n || b[j] != b'r' {
        return None;
    }
    j += 1;
    let mut hashes = 0usize;
    while j < n && b[j] == b'#' {
        hashes += 1;
        j += 1;
    }
    if j >= n || b[j] != b'"' {
        return None;
    }
    j += 1; // past opening quote
    while j < n {
        if b[j] == b'"' {
            let mut k = j + 1;
            let mut cnt = 0usize;
            while k < n && cnt < hashes && b[k] == b'#' {
                k += 1;
                cnt += 1;
            }
            if cnt == hashes {
                return Some(k); // closing delimiter consumed
            }
        }
        if b[j] != b'\n' {
            out[j] = b' ';
        }
        j += 1;
    }
    Some(j)
}

/// Handles a `'` at `i`: blanks a char literal's interior and returns the index
/// past it, or (for a lifetime / lone quote) returns `i + 1` leaving the
/// following identifier as code.
fn blank_char_or_skip_lifetime(out: &mut [u8], b: &[u8], i: usize) -> usize {
    let n = b.len();
    // Escaped char literal: '\n', '\'', '\u{7f}', ...
    if i + 1 < n && b[i + 1] == b'\\' {
        let mut j = i + 2;
        while j < n && b[j] != b'\'' && b[j] != b'\n' {
            j += 1;
        }
        if j < n && b[j] == b'\'' {
            for k in (i + 1)..j {
                if b[k] != b'\n' {
                    out[k] = b' ';
                }
            }
            return j + 1;
        }
        return i + 1;
    }
    // Simple char literal: 'X'.
    if i + 2 < n && b[i + 2] == b'\'' {
        out[i + 1] = b' ';
        return i + 3;
    }
    // Lifetime ('a, 'static) or a lone quote.
    i + 1
}

/// Blanks every `#[cfg(test)]` / `#[cfg(any(test, ...))]`-gated `mod` block
/// (attributes through the brace-matched close), preserving newlines. Operates
/// on already-cleaned source so brace matching is exact.
fn strip_test_modules(cleaned: &str) -> String {
    let bytes = cleaned.as_bytes();
    let mut out = bytes.to_vec();

    let line_starts: Vec<usize> = std::iter::once(0)
        .chain(cleaned.match_indices('\n').map(|(idx, _)| idx + 1))
        .collect();
    let lines: Vec<&str> = cleaned.lines().collect();

    for (li, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("mod ") {
            continue;
        }
        if !preceding_attrs_are_test_gated(&lines, li) {
            continue;
        }
        // Find the opening brace of this mod (on this line or a later one).
        // A declaration form (`mod name;`) has no inline body to strip — its
        // semicolon precedes any brace, and the module's own FILE is scanned
        // as production (the safe direction). Without this check the brace
        // search would match an unrelated later `{` and blank production code.
        let mod_line_start = line_starts[li];
        let semi = find_from(bytes, mod_line_start, b';');
        let Some(open) = find_from(bytes, mod_line_start, b'{') else {
            continue;
        };
        if semi.is_some_and(|s| s < open) {
            continue;
        }
        let Some(close) = matching_brace(bytes, open) else {
            continue;
        };
        // Blank from the first attribute line's start through the close brace.
        let block_start = line_starts[first_attr_line(&lines, li)];
        for byte in out.iter_mut().take(close + 1).skip(block_start) {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }

    String::from_utf8(out).expect("strip_test_modules produced valid utf-8")
}

/// Walks upward from the `mod` line over contiguous attribute / blank lines and
/// reports whether any attribute gates on `test`.
fn preceding_attrs_are_test_gated(lines: &[&str], mod_line: usize) -> bool {
    let mut gated = false;
    let mut li = mod_line;
    while li > 0 {
        let prev = lines[li - 1].trim();
        if prev.is_empty() {
            li -= 1;
            continue;
        }
        if prev.starts_with("#[") || prev.starts_with("#!") {
            if attr_gates_on_test(prev) {
                gated = true;
            }
            li -= 1;
            continue;
        }
        break;
    }
    gated
}

/// Index of the first contiguous attribute/blank line preceding the `mod` line
/// (so the whole gated block, attributes included, is blanked).
fn first_attr_line(lines: &[&str], mod_line: usize) -> usize {
    let mut li = mod_line;
    while li > 0 {
        let prev = lines[li - 1].trim();
        if prev.is_empty() || prev.starts_with("#[") || prev.starts_with("#!") {
            li -= 1;
        } else {
            break;
        }
    }
    li
}

/// True when a cfg attribute line has a bare `test` predicate token. String
/// interiors are already blanked, so `feature = "test-helpers"` cannot match.
fn attr_gates_on_test(attr: &str) -> bool {
    if !attr.contains("cfg(") {
        return false;
    }
    attr.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .any(|tok| tok == "test")
}

fn find_from(bytes: &[u8], from: usize, needle: u8) -> Option<usize> {
    (from..bytes.len()).find(|&j| bytes[j] == needle)
}

/// Matches the brace opened at `open_idx` on cleaned source (interior braces of
/// strings/comments are already blanked, so the count is exact).
fn matching_brace(bytes: &[u8], open_idx: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (j, &byte) in bytes.iter().enumerate().skip(open_idx) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(j);
                }
            }
            _ => {}
        }
    }
    None
}
