//! Source-scan regression test for the profile-access choke point (issue #107).
//!
//! Every production profile load in this crate must go through
//! `src/common/profile_access.rs`, because that is the one place a loaded
//! profile is reconciled against the name the operator selected. A command
//! that calls `profile::loader::load` directly gets a `Profile` nobody
//! checked, and reopens #107 for that command alone — silently, because the
//! command still works for a self-consistent profile.
//!
//! The allowlist is the security-relevant part of this file. An entry added
//! later without the reasoning below re-exempts a command from the
//! reconciliation, so each entry states the invariant that makes the exemption
//! safe.
//!
//! # Scope
//!
//! `crates/stellar-agent-cli/src/` ENTIRE, not `src/commands/`. The shared
//! signer ceremony lives at `src/common/signer_ceremony.rs` and resolves the
//! `[wallet]` security posture that governs every `--*-secret-env` unlock — a
//! scan limited to the command tree would miss precisely the helper that most
//! needs the rule.
//!
//! # Known limits of a source scan
//!
//! This is a textual rule, not a type-level one, and the gaps are named here so
//! a reader does not mistake it for a proof:
//!
//! - **Import-form evasion.** `use stellar_agent_core::profile::loader::load;`
//!   followed by a bare `load(name, None)` matches no needle. The bare-`load(`
//!   needle below closes the common shape; a rename import
//!   (`use ...::load as fetch;`) still evades it.
//! - **Alias imports of the module.** `use ...::profile::loader as l;` then
//!   `l::load(` evades the module-qualified needles.
//! - **`#[cfg(any(test, feature = "..."))]` modules are stripped** along with
//!   `#[cfg(test)]` ones, because the attribute walk keys on a bare `test`
//!   token anywhere in the predicate. A production path gated behind such a
//!   module would not be scanned.
//!
//! Each gap requires an author to write an unusual import specifically to
//! bypass the rule. The rule's job is to catch the ordinary regression — a
//! direct `loader::load(` added to a command — which it does per occurrence.
//!
//! # Mechanics
//!
//! Comments and string / char / raw-string interiors are blanked before
//! matching, so a `loader::load(` inside a doc comment or a diagnostic string
//! is not mistaken for a call. `#[cfg(test)]`-gated `mod` blocks are removed
//! attribute-awarely and brace-matched, so unit-test fixtures that construct a
//! divergent profile deliberately — `commands/policy_engine.rs`'s window-state
//! round trip is the one that matters — are out of scope: they exercise state
//! keying BELOW the choke point and must keep doing so.

#![allow(clippy::expect_used, clippy::panic, reason = "test-only")]

/// A production call site permitted to invoke the profile loader directly.
///
/// `file` is a path suffix relative to `crates/`; `anchor` is a token that must
/// appear within [`WINDOW_LINES`] of the occurrence, so the exemption is pinned
/// to one code region rather than to a whole file — a new direct load elsewhere
/// in the same file is still a violation.
struct AllowEntry {
    file: &'static str,
    anchor: &'static str,
    /// Lines either side of the occurrence in which `anchor` must appear.
    ///
    /// Structural entries use `0` — the anchor is on the call's own line — so
    /// two exemptions in the same file cannot absorb each other's occurrences.
    /// An entry justified by a comment block needs a window wide enough to
    /// reach it.
    window: usize,
    /// How many occurrences this entry is expected to cover. Pinned so a new
    /// direct load added inside the same anchored region is a violation rather
    /// than something the existing exemption quietly absorbs.
    occurrences: usize,
    invariant: &'static str,
}

/// The exhaustive allow-set.
const ALLOW_SET: &[AllowEntry] = &[
    // The choke point itself. Structural: the reconciliation is implemented
    // here, so this is where the loader is called.
    AllowEntry {
        file: "stellar-agent-cli/src/common/profile_access.rs",
        anchor: "profile_loader::load(",
        window: 0,
        // The reconciled load, and the raw load `injected_profile_load` wraps.
        occurrences: 2,
        invariant: "the choke point implements the reconciliation; the loader has to be \
                    called somewhere and this module is that somewhere",
    },
    // The blessed unreconciled loader. It exists so the dependency-injection
    // seams have one raw load to inject; its CALLERS reconcile. Anchored to its
    // own definition, so a command body calling it scans as a violation.
    AllowEntry {
        file: "stellar-agent-cli/src/common/profile_access.rs",
        anchor: "pub(crate) fn injected_profile_load",
        window: 0,
        occurrences: 1,
        invariant: "the definition of the seam-injected raw load; every caller reconciles \
                    through `reconcile_loaded_profile` or \
                    `load_profile_or_synthesize_testnet_with`. A call to it from a command \
                    body is a violation, which is why the needle set includes it",
    },
    // `profile show` displays the offending field.
    AllowEntry {
        file: "stellar-agent-cli/src/commands/profile/show.rs",
        anchor: "RECONCILIATION-EXEMPT",
        window: WINDOW_LINES,
        occurrences: 1,
        invariant: "the command exists to DISPLAY policy_owner_key_id, which is what an \
                    operator reads to repair a mismatch; refusing here would make a \
                    mismatched profile impossible to inspect and leave the refusal's own \
                    recovery advice uncompletable. It performs no keyed operation: no \
                    store is opened, no key minted, nothing signed, and no per-profile \
                    path derived from the loaded contents",
    },
];

/// Needles that name a direct profile-loader call.
///
/// `load_from_dir` is deliberately absent: it takes an explicit directory and
/// has zero production call sites in this crate (every occurrence is a test
/// fixture). Adding it would make the rule fire on those fixtures without
/// closing any production path.
/// The needles are deliberately NON-OVERLAPPING. `loader::load(` is a suffix of
/// every module-qualified form this crate uses — `profile_loader::load(`,
/// `profile::loader::load(`, `stellar_agent_core::profile::loader::load(` — so
/// one needle covers all of them and counts each call site exactly once. Adding
/// the longer forms as separate needles would count one call two or three
/// times and make the per-occurrence budget meaningless.
const LOADER_NEEDLES: &[&str] = &[
    "loader::load(",
    // The blessed unreconciled loader is watched too: without it, a command
    // body could call the one function whose contract is "the caller must
    // reconcile" and scan clean.
    "injected_profile_load(",
];

/// Needles for the bare-call import form (`use ...::loader::load;` then
/// `load(`), matched only when the file carries such an import.
///
/// Scoped this way because a bare `load(` needle applied unconditionally would
/// match unrelated helpers named `load` across the tree.
const BARE_IMPORT_MARKERS: &[&str] = &[
    "use stellar_agent_core::profile::loader::load;",
    "profile::loader::{load",
    "loader::{self, load",
    "loader::{load",
];

/// The window an entry justified by a comment block uses.
///
/// Wide enough to reach an in-source justification written immediately above
/// the call — `profile/show.rs` puts its anchor there — and narrow enough that
/// a second, unjustified load further down the same function does not inherit
/// the exemption. Structural entries use a window of `0` instead.
const WINDOW_LINES: usize = 22;

#[test]
fn no_production_call_site_loads_a_profile_outside_the_choke_point() {
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
    let cli_src = crates_root.join("stellar-agent-cli").join("src");
    assert!(cli_src.is_dir(), "the CLI src/ tree must exist");

    let mut rs_files = Vec::new();
    collect_rs_files(&cli_src, &mut rs_files);
    assert!(
        rs_files.len() > 50,
        "expected to scan the whole CLI src/ tree; found only {} files",
        rs_files.len()
    );

    // The scan must reach `src/common/`, not just `src/commands/`: the signer
    // ceremony is the fail-open site a commands-only scope would miss.
    assert!(
        rs_files
            .iter()
            .any(|p| p.ends_with("common/signer_ceremony.rs")),
        "the scan scope must include src/common/, where the shared signer ceremony lives"
    );

    let mut total_occurrences = 0usize;
    let mut exempt_counts = vec![0usize; ALLOW_SET.len()];
    let mut violations = Vec::new();

    for path in &rs_files {
        let source = std::fs::read_to_string(path).expect("read source");
        let production = strip_test_modules(&clean_source(&source));
        let lines: Vec<&str> = production.lines().collect();
        // Both passes preserve newlines, so line N of `production` is line N of
        // `source`. Occurrences are found in the cleaned text (no comment or
        // string false positives); allow-set anchors are matched against the
        // ORIGINAL, because an in-source justification is a comment and the
        // cleaned text has none.
        let original_lines: Vec<&str> = source.lines().collect();
        assert_eq!(
            lines.len(),
            original_lines.len(),
            "the cleaning passes must preserve line numbering in {}",
            path.display()
        );
        let rel = relative_path(path, crates_root);

        // The bare-call import form is refused outright: routing a command
        // through it would defeat the module-qualified needles below.
        for marker in BARE_IMPORT_MARKERS {
            if production.contains(marker) {
                violations.push(format!(
                    "{rel} — imports the profile loader in bare-call form (`{marker}`), which \
                     the module-qualified needles cannot see. Use \
                     `crate::common::profile_access` instead."
                ));
            }
        }

        for (idx, line) in lines.iter().enumerate() {
            // Count MATCHES, not lines: two calls on one line are two
            // occurrences, and a line-granular count would let the second hide
            // behind the first's exemption.
            let matches: usize = LOADER_NEEDLES.iter().map(|n| line.matches(n).count()).sum();
            if matches == 0 {
                continue;
            }
            total_occurrences += matches;

            let exempt = ALLOW_SET.iter().position(|a| {
                if !rel.ends_with(a.file) {
                    return false;
                }
                let start = idx.saturating_sub(a.window);
                let end = (idx + a.window).min(original_lines.len().saturating_sub(1));
                original_lines[start..=end].join("\n").contains(a.anchor)
            });
            if let Some(entry) = exempt {
                exempt_counts[entry] += matches;
                continue;
            }
            violations.push(format!(
                "{rel}:{} — a production profile load bypasses the reconciliation choke \
                 point; route it through `crate::common::profile_access` \
                 (`load_profile_reconciled`, `load_profile_reconciled_by_requested_name`, \
                 `load_profile_or_synthesize_testnet`, `reconcile_loaded_profile`, or \
                 `injected_profile_load` for a dependency-injection seam whose CALLER \
                 reconciles). Adding an allow-set entry instead re-opens #107 for this \
                 command and requires the invariant that makes it safe.",
                idx + 1
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "profile-reconciliation discipline violated:\n{}",
        violations.join("\n")
    );
    // Every allow-set entry must cover exactly the occurrences it claims. A
    // stale entry is a standing permission for a call site that no longer
    // exists; an undercount means a new direct load was absorbed by an existing
    // exemption instead of being reported.
    for (entry, matched) in ALLOW_SET.iter().zip(&exempt_counts) {
        assert_eq!(
            *matched, entry.occurrences,
            "allow-set entry {} (anchor `{}`) claims {} occurrence(s) but matched {matched}",
            entry.file, entry.anchor, entry.occurrences
        );
    }
    let expected_exempt: usize = ALLOW_SET.iter().map(|a| a.occurrences).sum();
    assert_eq!(
        total_occurrences, expected_exempt,
        "every production loader occurrence must be an allow-set one; the scan saw \
         {total_occurrences} against {expected_exempt} allowed"
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
/// numbers are stable.
///
/// Comments are blanked here so an occurrence needle cannot match inside one;
/// allow-set anchors are matched against the ORIGINAL text instead, so an
/// in-source justification written as a comment still pins its exemption.
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
/// past it, or (for a lifetime / lone quote) returns `i + 1`.
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
        // A declaration form (`mod name;`) has no inline body to strip; its
        // own FILE is scanned as production, which is the safe direction.
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
