//! Source-scan regression test: nothing substitutes the literal `"default"`
//! for a profile selector, in either of the two shapes that can (issue #113).
//!
//! `docs/cli-reference/index.md` documents one resolution order for the whole
//! CLI: `--profile`, then `STELLAR_AGENT_PROFILE`, then `"default"`. Two
//! constructs defeat it, and neither is caught by the compiler:
//!
//! 1. **A clap `default_value` on the profile flag.** Clap substitutes the
//!    literal before the command runs, so `resolve_profile_name` can never see
//!    that no name was supplied and the environment variable is unreachable.
//!    `Option<String>` with a `default_value` compiles.
//! 2. **A handler-side `.unwrap_or("default")`.** The flag is a clean
//!    `Option<String>`, and the call site discards the `None` that the
//!    environment variable would have filled. This shape is invisible to a
//!    `default_value` scan.
//!
//! `Option<String>` plus `resolve_profile_name(args.profile.as_deref())` is the
//! only shape that honours the documented order. This test enforces both rules.
//!
//! # The rule keys on the FIELD, never on the literal
//!
//! `default_value = "default"` is legitimate on flags that are not profile
//! selectors — `smart_account/rules.rs`'s `--context` selector is exactly that
//! and must keep its default. Scanning for the literal would either break that
//! flag or force an exemption that hides a real profile-field regression.
//!
//! A field counts as a profile selector when it is NAMED `profile` **or** its
//! clap attributes declare `long = "profile"`. The second half closes the
//! rename evasion: `#[arg(long = "profile", default_value = "default")] pub
//! profile_override: String` is the same defect on the same flag.
//!
//! # Scope
//!
//! Every `.rs` file under this crate's `src/`, production code only:
//! `#[cfg(test)]`-gated modules are stripped attribute-awarely (a fixture
//! struct in a test module may carry whatever clap attributes it needs).
//!
//! Known blind spots of the line-based scan, none of which occurs in this tree
//! (rustfmt splits attributes onto their own lines):
//!
//! - An attribute and its field on ONE line (`#[arg(long)] pub profile: String,`)
//!   is read as an attribute line and the field is not admitted.
//! - A field declared through a macro expansion is not source-visible.
//!
//! Both `#[arg(...)]` and the older `#[clap(...)]` spelling are admitted.

#![allow(clippy::expect_used, clippy::panic, reason = "test-only")]

/// A clap field named `profile` that is permitted to carry a `default_value`,
/// with the reason and the work that removes it.
///
/// `file` is a path suffix relative to this crate's `src/`.
struct AllowEntry {
    file: &'static str,
    justification: &'static str,
}

/// The exhaustive allow-set.
///
/// These three verbs load through `load_profile_or_synthesize_testnet`, which
/// synthesises a `PolicyEngineKind::Noop` profile when the named file does not
/// exist, and nothing on their signing path refuses a synthesised origin.
/// Honouring `STELLAR_AGENT_PROFILE` before that refusal exists would turn a
/// stale variable in a shell profile or a CI job into a silent policy-engine
/// bypass on the strongest-consequence path: the run would resolve the stale
/// name, miss the file, synthesise a `Noop` engine, and sign.
///
/// PR 2 (issues #112 / #114) converts all three in the same commit that makes
/// an explicitly-named, missing profile refuse, and empties this allow-set.
/// Every entry is asserted to be LIVE below, so the exemption cannot outlive
/// the reason for it: once a listed field is converted, this test fails until
/// its entry is removed.
const ALLOW_SET: &[AllowEntry] = &[
    AllowEntry {
        file: "commands/pay.rs",
        justification: "synthesis-backed loader; converted in PR 2 with the provenance refusal",
    },
    AllowEntry {
        file: "commands/claim.rs",
        justification: "synthesis-backed loader; converted in PR 2 with the provenance refusal",
    },
    AllowEntry {
        file: "commands/accounts/create.rs",
        justification: "synthesis-backed loader; converted in PR 2 with the provenance refusal",
    },
];

/// Exact number of clap profile selectors in production code.
///
/// Pinned exactly, not as a floor: a scanner bug that dropped a whole
/// visibility class (say every `pub(crate)` field) would still clear a loose
/// floor and report a clean tree. Adding or removing a profile-selecting
/// subcommand is expected to move this number — update it in the same commit.
const PROFILE_FIELDS: usize = 68;

/// Call-site shapes that substitute the literal `"default"` for an absent
/// profile name, discarding the environment variable the flag left `None` for.
const MANUAL_DEFAULT_NEEDLES: &[&str] = &[
    r#"unwrap_or("default")"#,
    r#"unwrap_or_else(|| "default""#,
    r#"unwrap_or_default_profile"#,
];

/// Lines before a manual-default occurrence that are searched for the `profile`
/// context. Covers the rustfmt-split builder chain
/// (`args\n.profile\n.as_deref()\n.unwrap_or("default")`).
const MANUAL_DEFAULT_WINDOW: usize = 4;

#[test]
fn no_clap_profile_field_carries_a_default_value() {
    for allow in ALLOW_SET {
        assert!(
            !allow.justification.trim().is_empty(),
            "allow-set entry for {} must document its justification",
            allow.file
        );
    }

    let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut rs_files = Vec::new();
    collect_rs_files(&src_root, &mut rs_files);
    assert!(
        rs_files.len() > 50,
        "expected to scan this crate's whole src/ tree; found only {} files",
        rs_files.len()
    );

    let mut seen: Vec<String> = Vec::new();
    let mut defaulted: Vec<(String, usize)> = Vec::new();
    let mut manual_defaults: Vec<String> = Vec::new();

    for path in &rs_files {
        let source = std::fs::read_to_string(path).expect("read source");
        let raw_lines: Vec<&str> = source.lines().collect();
        // `clean_source` and `strip_test_modules` both preserve line numbering,
        // so a field's attribute span indexes the raw lines too. The raw text is
        // needed for `long = "profile"`, whose literal the cleaning pass blanks.
        let production = strip_test_modules(&clean_source(&source));
        let rel = relative_path(path, &src_root);

        for field in clap_profile_fields(&production, &raw_lines) {
            seen.push(format!("{rel}:{}", field.line));
            if field.attrs.contains("default_value") {
                defaulted.push((rel.clone(), field.line));
            }
        }

        // The call-site shape: an `Option<String>` flag whose `None` — the very
        // signal the environment variable fills — is thrown away at the use site.
        //
        // The needle carries a string LITERAL, which the cleaning pass blanks,
        // so the raw line supplies the match. The cleaned line still gates it:
        // the `unwrap_or` identifier survives cleaning, while a doc comment
        // quoting the same call does not, so prose cannot raise a violation.
        let production_lines: Vec<&str> = production.lines().collect();
        for (idx, cleaned_line) in production_lines.iter().enumerate() {
            if !cleaned_line.contains("unwrap_or") {
                continue;
            }
            let raw = raw_lines.get(idx).copied().unwrap_or_default();
            if !MANUAL_DEFAULT_NEEDLES.iter().any(|n| raw.contains(n)) {
                continue;
            }
            let start = idx.saturating_sub(MANUAL_DEFAULT_WINDOW);
            let window = production_lines[start..=idx].join(" ");
            if window.contains("profile") {
                manual_defaults.push(format!(
                    "{rel}:{} — a profile name falls back to the literal \"default\" at the \
                     call site, so STELLAR_AGENT_PROFILE is discarded even though the flag \
                     is optional; resolve with `resolve_profile_name(args.profile.as_deref())`",
                    idx + 1
                ));
            }
        }
    }

    assert_eq!(
        seen.len(),
        PROFILE_FIELDS,
        "the scan must see every clap profile selector; a change in this number means a \
         selector was added or removed (update the constant) or the scanner stopped \
         matching a shape (fix the scanner). Seen:\n{}",
        seen.join("\n")
    );
    assert!(
        manual_defaults.is_empty(),
        "profile-flag discipline violated:\n{}",
        manual_defaults.join("\n")
    );

    // Every defaulted field must be allow-listed…
    let violations: Vec<String> = defaulted
        .iter()
        .filter(|(file, _)| !ALLOW_SET.iter().any(|a| file == a.file))
        .map(|(file, line)| {
            format!(
                "{file}:{line} — a clap profile selector (a field named `profile`, or one \
                 declaring `long = \"profile\"`) carries `default_value`, so \
                 STELLAR_AGENT_PROFILE can never be read for this command; declare it as \
                 `#[arg(long = \"profile\", value_name = \"NAME\")] pub profile: Option<String>` \
                 and resolve it with `resolve_profile_name(args.profile.as_deref())`"
            )
        })
        .collect();
    assert!(
        violations.is_empty(),
        "profile-flag discipline violated:\n{}",
        violations.join("\n")
    );

    // …and every allow-list entry must still be needed. A stale entry is a
    // standing exemption for a field that no longer exists, which would silently
    // cover a future regression in the same file.
    let stale: Vec<&str> = ALLOW_SET
        .iter()
        .filter(|a| !defaulted.iter().any(|(file, _)| file == a.file))
        .map(|a| a.file)
        .collect();
    assert!(
        stale.is_empty(),
        "allow-set entries no longer describe a defaulted `profile` field and must be \
         removed: {stale:?}"
    );
}

/// One clap-attributed profile-selector field declaration.
struct ClapField {
    /// 1-based line number of the field declaration.
    line: usize,
    /// The attribute block attached to it, joined (cleaned source: string
    /// interiors are blanked, so this matches identifiers such as
    /// `default_value`, never literals).
    attrs: String,
}

/// Collects every clap profile selector: a field carrying an `#[arg(...)]` /
/// `#[clap(...)]` attribute that is either NAMED `profile` or declares
/// `long = "profile"`.
///
/// The clap attribute requirement is what keeps struct-literal initialisers
/// (`profile: Some("x".to_owned()),`) and function parameters out of the scan:
/// only a field declaration can be preceded by `#[arg(...)]`.
///
/// `raw_lines` is the UNCLEANED source, indexed identically; the flag-name
/// half of the admission rule reads a string literal, which the cleaning pass
/// blanks.
fn clap_profile_fields(production: &str, raw_lines: &[&str]) -> Vec<ClapField> {
    let mut out = Vec::new();
    let mut attrs = String::new();
    let mut attr_start: Option<usize> = None;
    let mut attr_depth = 0i32;

    for (idx, line) in production.lines().enumerate() {
        let trimmed = line.trim();

        if attr_depth > 0 {
            attrs.push(' ');
            attrs.push_str(trimmed);
            attr_depth += bracket_delta(trimmed);
            continue;
        }

        if trimmed.starts_with("#[") {
            if attrs.is_empty() {
                attr_start = Some(idx);
            }
            attrs.push(' ');
            attrs.push_str(trimmed);
            attr_depth = bracket_delta(trimmed);
            continue;
        }

        // Doc comments and blank lines sit inside an attribute block without
        // ending it.
        if trimmed.is_empty() || trimmed.starts_with("///") || trimmed.starts_with("//") {
            continue;
        }

        let is_clap_field = attrs.contains("#[arg(") || attrs.contains("#[clap(");
        if is_clap_field {
            let raw_attrs = attr_start
                .map(|start| raw_lines[start..=idx].join(" "))
                .unwrap_or_default();
            if is_field_declaration(trimmed, "profile") || declares_profile_flag(&raw_attrs) {
                out.push(ClapField {
                    line: idx + 1,
                    attrs: std::mem::take(&mut attrs),
                });
            }
        }
        attrs.clear();
        attr_start = None;
    }

    out
}

/// True when a clap attribute block declares the long flag `--profile`,
/// whatever the field is named.
fn declares_profile_flag(raw_attrs: &str) -> bool {
    let dense: String = raw_attrs.chars().filter(|c| !c.is_whitespace()).collect();
    dense.contains(r#"long="profile""#)
}

/// True for a struct-field declaration whose name is exactly `name`.
fn is_field_declaration(trimmed: &str, name: &str) -> bool {
    // A trailing line comment survives the cleaning pass as a bare `//`, which
    // would otherwise hide the field-terminating comma.
    let code = trimmed.split("//").next().unwrap_or(trimmed).trim_end();
    let rest = code
        .strip_prefix("pub(crate) ")
        .or_else(|| code.strip_prefix("pub "))
        .or_else(|| code.strip_prefix("pub(super) "))
        .unwrap_or(code);
    let Some(after_name) = rest.strip_prefix(name).and_then(|r| r.strip_prefix(':')) else {
        return false;
    };
    // A declaration names a type and ends the field; requiring the trailing
    // comma keeps the shape unambiguous.
    code.ends_with(',') && !after_name.trim().is_empty()
}

/// Net `[` minus `]` on a line, so a multi-line attribute is tracked to its end.
fn bracket_delta(line: &str) -> i32 {
    line.chars().fold(0i32, |acc, c| match c {
        '[' => acc + 1,
        ']' => acc - 1,
        _ => acc,
    })
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

/// Renders `path` relative to `src_root` with forward slashes, so the allow-set
/// suffixes match on every platform.
fn relative_path(path: &std::path::Path, src_root: &std::path::Path) -> String {
    path.strip_prefix(src_root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Blanks comment bodies and string / char / raw-string literal interiors,
/// replacing each affected byte with a space and preserving newlines so line
/// numbers are stable. After this pass every `{`/`}` and `[`/`]` is structural,
/// so brace matching and attribute tracking are exact, and prose mentioning
/// `default_value` cannot be mistaken for an attribute.
///
/// Mirrors `keyring_classification_discipline.rs`'s pass; kept per-file rather
/// than shared because the two scans are independent gates.
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

        // Line comment. Doc comments are blanked to their `//` prefix, which is
        // enough for the scan: the prefix keeps the line recognisable as a
        // comment while its prose can no longer match an attribute token.
        if c == b'/' && i + 1 < n && b[i + 1] == b'/' {
            i += 2;
            while i < n && b[i] != b'\n' {
                out[i] = b' ';
                i += 1;
            }
            continue;
        }

        // Block comment.
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
    if i + 2 < n && b[i + 2] == b'\'' {
        out[i + 1] = b' ';
        return i + 3;
    }
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

/// Index of the first contiguous attribute/blank line preceding the `mod` line.
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

/// Matches the brace opened at `open_idx` on cleaned source.
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
