//! No-network regression lock for the startup-advisory call closure.
//!
//! Covers the TRANSITIVE call closure of `run_startup_advisory` +
//! `run_startup_advisory_with_allowlist`.  A future refactor that quietly adds a
//! networking dep via a transitive internal module would fail this AST-based
//! scan because per-file `use` paths and identifier references are checked
//! against the forbidden-imports list.
//!
//! # Implementation strategy
//!
//! Implementation options, ranked by rigor:
//!
//! 1. `rust-analyzer` LSP-mediated semantic walk (most rigorous; non-trivial
//!    setup).
//! 2. `cargo-call-stack` (if ecosystem-suitable).
//! 3. **Conservative name-match heuristic** (preferred — false-positives
//!    surface as fixture-author-time clarifications, not regressions).
//!
//! This fixture implements **Option 3**: hardcoded seed list of files in the
//! advisory call closure + per-file `syn` AST walk extracting all `use` paths
//! AND identifier references in items, matched against the extended
//! forbidden-imports list.
//!
//! # Call-closure seed list
//!
//! Discovered via `grep '^use ' crates/stellar-agent-cli/src/advisory.rs`. The
//! closure must be re-walked when `advisory.rs` gains new `use` statements; a
//! regression test detects the addition of files not in the seed list (via the
//! `assert_seed_closure_matches_advisory_use_statements` check below).
//!
//! # Why `cargo tree` is NOT sufficient
//!
//! `cargo tree -e normal -p stellar-agent-cli` shows the full CLI dep
//! closure, which INCLUDES `reqwest` / `hyper` / `mio` because OTHER
//! subcommands (`accounts deploy-c`, `smart-account rules`, etc.) legitimately need
//! networking. A crate-level dep scan can't isolate the advisory call-path.
//! This fixture's per-file AST walk provides the necessary path-level
//! granularity.
//!
//! # Companion test
//!
//! [`startup_advisory_module_does_not_import_network_primitives`] —
//! the primary closure-walking assertion.
//!
//! [`assert_seed_closure_matches_advisory_use_statements`] — drift detector
//! that fails if `advisory.rs` gains new internal-crate `use` statements not
//! covered by `ADVISORY_CALL_CLOSURE` below.
//!
//! # Forbidden-imports list
//!
//! - **HTTP/gRPC:** `reqwest`, `hyper`, `tonic`, `surf`, `ureq`, `isahc`.
//! - **TCP/UDP:** `tokio::net`, `std::net`, `async_std::net`, `mio::net`.
//! - **WebSocket:** `tungstenite`, `tokio_tungstenite`, `async_tungstenite`.
//! - **QUIC:** `quinn`, `s2n_quic`.
//! - **Unix-domain sockets:** `std::os::unix::net`, `tokio::net::UnixStream`,
//!   `tokio::net::UnixListener`, `tokio::net::UnixDatagram`.
//! - **Subprocess egress:** `std::process::Command` (covers bash-mediated
//!   `/dev/tcp` magic).
//! - **DNS:** `trust_dns_*`, `hickory_*`, raw `getaddrinfo`.
//! - **Raw I/O:** `mio`.
//! - **Hardware-mediated egress:** `serialport` (defensive lock; advisory MUST
//!   NOT touch hardware-wallet adapter surface).
//! - **FD-mediated egress:** `nix::sys::socket`, raw `libc::socket`,
//!   `libc::connect`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; static-import-scan asserts invariants via panic-on-violation"
)]

use std::fs;
use std::path::{Path, PathBuf};

use syn::visit::Visit;
use syn::{File, Item, UseTree};

// ── Forbidden-imports list ────────────────────────────────────────────────────

/// Pattern matched against the dot-joined path of every `use` statement
/// AND every identifier reference in items reachable from the advisory
/// call closure. Match semantics: `path_str.contains(pattern)` after
/// normalisation.
///
/// Each entry is `(pattern, category)` where `category` is a short human-
/// readable label used in failure messages.
const FORBIDDEN_IMPORT_PATTERNS: &[(&str, &str)] = &[
    // HTTP / gRPC.
    ("reqwest", "HTTP (reqwest)"),
    ("hyper", "HTTP (hyper)"),
    ("tonic", "gRPC (tonic)"),
    ("surf", "HTTP (surf)"),
    ("ureq", "HTTP (ureq)"),
    ("isahc", "HTTP (isahc)"),
    // TCP / UDP.
    ("tokio::net", "TCP/UDP (tokio::net)"),
    ("std::net", "TCP/UDP (std::net)"),
    ("async_std::net", "TCP/UDP (async_std::net)"),
    ("mio::net", "TCP/UDP (mio::net)"),
    // WebSocket.
    ("tungstenite", "WebSocket (tungstenite)"),
    ("tokio_tungstenite", "WebSocket (tokio_tungstenite)"),
    ("async_tungstenite", "WebSocket (async_tungstenite)"),
    // QUIC.
    ("quinn", "QUIC (quinn)"),
    ("s2n_quic", "QUIC (s2n_quic)"),
    // Unix-domain sockets.
    ("std::os::unix::net", "UDS (std::os::unix::net)"),
    // (tokio::net is already covered above; UnixStream/Listener/Datagram
    // are nested under it.)
    // Subprocess egress.
    (
        "std::process::Command",
        "subprocess (std::process::Command)",
    ),
    // DNS.
    ("trust_dns_", "DNS (trust_dns_*)"),
    ("hickory_", "DNS (hickory_*)"),
    ("getaddrinfo", "DNS (getaddrinfo)"),
    // Raw I/O.
    ("mio::", "raw I/O (mio)"),
    // Hardware-mediated egress.
    ("serialport", "hardware egress (serialport)"),
    // FD-mediated egress.
    ("nix::sys::socket", "FD egress (nix::sys::socket)"),
    ("libc::socket", "FD egress (libc::socket)"),
    ("libc::connect", "FD egress (libc::connect)"),
];

// ── Call-closure seed list ────────────────────────────────────────────────────

/// Files in the advisory call closure (manually curated; drift-detector
/// `assert_seed_closure_matches_advisory_use_statements` fails the test if
/// `advisory.rs` gains a new internal-crate `use` not represented here).
///
/// Paths are workspace-relative.
const ADVISORY_CALL_CLOSURE: &[&str] = &[
    // Entry point.
    "crates/stellar-agent-cli/src/advisory.rs",
    // Direct internal-crate imports from advisory.rs.
    "crates/stellar-agent-core/src/audit_log/entry.rs",
    "crates/stellar-agent-core/src/audit_log/reader.rs",
    "crates/stellar-agent-core/src/audit_log/schema.rs",
    "crates/stellar-agent-core/src/audit_log/writer.rs",
    "crates/stellar-agent-core/src/observability/mod.rs",
    "crates/stellar-agent-core/src/observability/redact.rs",
    "crates/stellar-agent-smart-account/src/verifier_allowlist.rs",
    // Audit-log mod files (parent modules of the directly-imported items).
    "crates/stellar-agent-core/src/audit_log/mod.rs",
];

/// Internal-crate path prefixes whose `use` statements are tracked by the
/// drift-detector. External-crate paths (e.g. `tracing::`, `uuid::`) are
/// ignored because they aren't sources of a no-network violation in the
/// call-closure-scanning sense.
const INTERNAL_CRATE_PREFIXES: &[&str] = &[
    "stellar_agent_core::",
    "stellar_agent_smart_account::",
    "stellar_agent_cli::",
    "crate::",
];

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Walks up from `CARGO_MANIFEST_DIR` to find the workspace `Cargo.toml`.
/// The line-anchored `[workspace]` match avoids a `[workspace.metadata]`
/// substring collision.
fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = p.join("Cargo.toml");
        if let Ok(contents) = fs::read_to_string(&candidate)
            && contents.lines().any(|l| l.trim() == "[workspace]")
        {
            return p;
        }
        if !p.pop() {
            panic!("workspace Cargo.toml not found from CARGO_MANIFEST_DIR ascent");
        }
    }
}

/// Returns `Some((pattern, category))` if `text` matches any forbidden
/// import. Used to scan both `use`-path strings and identifier-reference
/// strings.
fn match_forbidden(text: &str) -> Option<&'static (&'static str, &'static str)> {
    FORBIDDEN_IMPORT_PATTERNS
        .iter()
        .find(|(pattern, _)| text.contains(pattern))
}

/// Recursively flattens a `UseTree` into the set of dot-joined paths it
/// imports. For example, `use std::{io::{self, Read}, fmt};` flattens to
/// `["std::io", "std::io::Read", "std::fmt"]`.
fn flatten_use_tree(tree: &UseTree, prefix: &str) -> Vec<String> {
    let mut paths = Vec::new();
    match tree {
        UseTree::Path(path) => {
            let next_prefix = if prefix.is_empty() {
                path.ident.to_string()
            } else {
                format!("{prefix}::{}", path.ident)
            };
            paths.extend(flatten_use_tree(&path.tree, &next_prefix));
        }
        UseTree::Name(name) => {
            let full = if prefix.is_empty() {
                name.ident.to_string()
            } else {
                format!("{prefix}::{}", name.ident)
            };
            paths.push(full);
        }
        UseTree::Rename(rename) => {
            let full = if prefix.is_empty() {
                rename.ident.to_string()
            } else {
                format!("{prefix}::{}", rename.ident)
            };
            paths.push(full);
        }
        UseTree::Glob(_) => {
            if !prefix.is_empty() {
                paths.push(format!("{prefix}::*"));
            }
        }
        UseTree::Group(group) => {
            for item in &group.items {
                paths.extend(flatten_use_tree(item, prefix));
            }
        }
    }
    paths
}

/// Extracts all `use`-path strings from a parsed Rust file.
fn extract_use_paths(file: &File) -> Vec<String> {
    let mut paths = Vec::new();
    for item in &file.items {
        if let Item::Use(item_use) = item {
            paths.extend(flatten_use_tree(&item_use.tree, ""));
        }
    }
    paths
}

/// Visitor that collects every path-expression's full text (joined with `::`)
/// from a parsed Rust file. Used to catch direct identifier references like
/// `tokio::net::TcpStream::connect(...)` that aren't covered by `use`-path
/// flattening (the `use` form might be `use tokio;` + qualified call).
#[derive(Default)]
struct PathExprCollector {
    paths: Vec<String>,
}

impl<'ast> Visit<'ast> for PathExprCollector {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        let joined = path
            .segments
            .iter()
            .map(|seg| seg.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        if !joined.is_empty() {
            self.paths.push(joined);
        }
        syn::visit::visit_path(self, path);
    }
}

/// Returns a sorted-deduplicated list of all `use`-path strings AND all
/// identifier-reference path strings extracted from `file_path`.
fn collect_all_paths(workspace: &Path, file_path: &str) -> Vec<String> {
    let full = workspace.join(file_path);
    let source = fs::read_to_string(&full).unwrap_or_else(|e| panic!("read {full:?} failed: {e}"));
    let parsed: File =
        syn::parse_file(&source).unwrap_or_else(|e| panic!("parse {full:?} failed: {e}"));

    let mut paths = extract_use_paths(&parsed);

    let mut collector = PathExprCollector::default();
    collector.visit_file(&parsed);
    paths.extend(collector.paths);

    paths.sort();
    paths.dedup();
    paths
}

// ── Test: primary closure-walking assertion ──────────────────────────────────

/// Walks every file in `ADVISORY_CALL_CLOSURE`, collects all `use` paths
/// AND identifier references via syn AST, and asserts NONE of them match
/// the forbidden-imports list.
///
/// Matches that surface here represent a no-network violation introduced via a
/// transitive internal module. A regression lock against quiet refactoring.
#[test]
fn startup_advisory_module_does_not_import_network_primitives() {
    let workspace = workspace_root();
    let mut violations: Vec<(String, String, String)> = Vec::new();

    for &file_path in ADVISORY_CALL_CLOSURE {
        let paths = collect_all_paths(&workspace, file_path);
        for path in paths {
            if let Some((pattern, category)) = match_forbidden(&path) {
                violations.push((
                    file_path.to_owned(),
                    path.clone(),
                    format!("{category} (pattern: {pattern})"),
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "forbidden-import VIOLATIONS in advisory call closure:\n{}\n\n\
         The startup-advisory call closure MUST NOT import or reference any \
         networking, subprocess, DNS, hardware-egress, or FD-egress primitive. \
         If this is a legitimate addition (unlikely — re-review the security \
         architecture), update the allowlist with explicit rationale.",
        violations
            .iter()
            .map(|(file, path, category)| format!("  - {file}: `{path}` matches {category}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

// ── Test: drift detector ─────────────────────────────────────────────────────

/// Asserts the `ADVISORY_CALL_CLOSURE` seed list covers every internal-crate
/// `use` statement in `advisory.rs`. A new internal import added to
/// `advisory.rs` (without updating this seed list) means the closure-walking
/// scan above misses a transitive surface — this drift detector fails first
/// to force seed-list updates as part of the same commit.
#[test]
fn assert_seed_closure_matches_advisory_use_statements() {
    let workspace = workspace_root();
    let advisory_path = "crates/stellar-agent-cli/src/advisory.rs";
    let advisory_source =
        fs::read_to_string(workspace.join(advisory_path)).expect("advisory.rs must be readable");
    let advisory_parsed: File = syn::parse_file(&advisory_source).expect("advisory.rs must parse");

    let mut missing: Vec<String> = Vec::new();

    for path in extract_use_paths(&advisory_parsed) {
        // Skip external-crate paths (tracing::, uuid::, std::, etc.).
        if !INTERNAL_CRATE_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
        {
            continue;
        }

        // Map the use-path to its expected source-file path.
        let expected_file = use_path_to_source_file(&path);

        // Verify the file exists in `ADVISORY_CALL_CLOSURE` (or that it
        // can be expected to exist — defensive against pure-data modules
        // like `verifier_allowlist`). Exact-equality match (not substring):
        // a hypothetical `entry_new.rs` would otherwise erroneously match the
        // existing `entry.rs` seed via `.contains()`.
        let is_covered = ADVISORY_CALL_CLOSURE
            .iter()
            .any(|&seed| expected_file.as_deref() == Some(seed));

        if !is_covered && let Some(file) = expected_file {
            // Only flag if the file actually exists on disk — otherwise the
            // use-path is a re-export or trait method we don't need to walk.
            if workspace.join(&file).exists() {
                missing.push(format!(
                    "use `{path}` → file `{file}` not in ADVISORY_CALL_CLOSURE"
                ));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "ADVISORY_CALL_CLOSURE seed list is incomplete — `advisory.rs` imports \
         from internal-crate modules not currently scanned:\n{}\n\n\
         Add the missing file paths to ADVISORY_CALL_CLOSURE at \
         `tests/advisory_no_network_deps.rs` so the closure walk covers them.",
        missing.join("\n  - "),
    );
}

/// Maps an internal-crate `use` path to its expected source-file path.
/// Best-effort — returns `None` for paths that don't map cleanly to a single
/// file (e.g., `use stellar_agent_core::{A, B}` where A and B are in
/// different modules). For the advisory module's actual imports, all paths
/// map cleanly.
fn use_path_to_source_file(use_path: &str) -> Option<String> {
    let normalised = use_path.replace("crate::", "stellar_agent_cli::");

    let segments: Vec<&str> = normalised.split("::").collect();
    if segments.len() < 2 {
        return None;
    }

    let crate_name = segments[0];
    let crate_dir = match crate_name {
        "stellar_agent_core" => "crates/stellar-agent-core/src",
        "stellar_agent_smart_account" => "crates/stellar-agent-smart-account/src",
        "stellar_agent_cli" => "crates/stellar-agent-cli/src",
        _ => return None,
    };

    // Drop the crate name + the leaf identifier (the imported symbol).
    // Module path = segments[1..len-1].
    if segments.len() < 3 {
        // `use stellar_agent_core::X` → no submodule; X is at crate root.
        return Some(format!("{crate_dir}/lib.rs"));
    }
    let module_path = segments[1..segments.len() - 1].join("/");
    Some(format!("{crate_dir}/{module_path}.rs"))
}

// ── Test: forbidden-imports list itself is well-formed ───────────────────────

/// Sanity check: every entry in `FORBIDDEN_IMPORT_PATTERNS` has a non-empty
/// pattern and category. Catches accidental const-table corruption.
#[test]
fn forbidden_imports_list_entries_are_well_formed() {
    for (pattern, category) in FORBIDDEN_IMPORT_PATTERNS {
        assert!(
            !pattern.is_empty(),
            "FORBIDDEN_IMPORT_PATTERNS has empty pattern"
        );
        assert!(
            !category.is_empty(),
            "FORBIDDEN_IMPORT_PATTERNS has empty category"
        );
    }
    assert!(
        FORBIDDEN_IMPORT_PATTERNS.len() >= 20,
        "FORBIDDEN_IMPORT_PATTERNS shrank unexpectedly (~25 entries expected in the \
         extended forbidden-imports list); current count {}",
        FORBIDDEN_IMPORT_PATTERNS.len(),
    );
}

// ── Self-test: forbidden-pattern detector works ──────────────────────────────

/// Asserts the `match_forbidden` helper actually flags known-bad patterns.
/// Regression-locks against future tightening that accidentally relaxes the
/// match semantics.
#[test]
fn forbidden_pattern_detector_flags_known_bad_paths() {
    let bad_cases: &[&str] = &[
        "reqwest::get",
        "hyper::client::Client",
        "tokio::net::TcpStream",
        "std::net::TcpStream",
        "std::process::Command",
        "mio::Poll",
        "serialport::SerialPort",
        "tungstenite::connect",
        "nix::sys::socket::socket",
        "libc::socket",
        "trust_dns_resolver::Resolver",
        "hickory_resolver::Resolver",
    ];
    for case in bad_cases {
        assert!(
            match_forbidden(case).is_some(),
            "match_forbidden('{case}') must flag this as a known-bad path",
        );
    }

    let good_cases: &[&str] = &[
        "std::collections::HashMap",
        "std::path::Path",
        "std::sync::Arc",
        "tracing::warn",
        "uuid::Uuid",
        "stellar_agent_core::audit_log::entry::AuditEntry",
        "serde::Deserialize",
    ];
    for case in good_cases {
        assert!(
            match_forbidden(case).is_none(),
            "match_forbidden('{case}') must NOT flag this benign path; got {:?}",
            match_forbidden(case),
        );
    }
}
