//! Source-scan pin: every CLI verb that builds a signer checks the profile's
//! halt marker.
//!
//! The halt check sits in each verb, right after the profile load, because
//! the signer constructors are shared with the MCP server and several verbs
//! make RPC requests before they build a signer. `profile_halt.rs` runs one
//! invocation per existing check site and proves each refuses before any
//! signer read or request. That placement has no single chokepoint a new
//! verb would pass through, so this scan holds the rule for files and verbs
//! the subprocess suite does not name yet:
//!
//! - every production file under `src/` that calls a signer constructor also
//!   calls `halt::ensure_not_halted(`, except the files that define those
//!   constructors;
//! - in the multi-verb files `smart_account/rules.rs` and
//!   `smart_account/signers.rs`, every function that loads the command
//!   profile also calls the check, except the named read verbs.
//!
//! The scan reads production code only: everything from the top-level
//! `#[cfg(test)]` test module on is dropped, and `//` comment lines never
//! count.

#![allow(clippy::expect_used, clippy::panic, reason = "test-only")]

use std::path::{Path, PathBuf};

/// Call forms that build or resolve a signing key.
const SIGNER_CONSTRUCTORS: &[&str] = &[
    "enrolled_keyring_signer(",
    "lazy_signer_from_keyring(",
    "resolve_signer(",
    "CommonHandlerContext::new(",
    "resolve_deployer_keypair(",
    "require_enrolled_signer(",
];

/// The call form of the halt check.
const HALT_CHECK: &str = "halt::ensure_not_halted(";

/// Files that define the signer constructors; their callers hold the check.
const DEFINITION_FILES: &[&str] = &[
    "commands/smart_account/common.rs",
    "common/signer_ceremony.rs",
];

/// Multi-verb files whose profile-loading functions are checked one by one.
const MULTI_VERB_FILES: &[&str] = &[
    "commands/smart_account/rules.rs",
    "commands/smart_account/signers.rs",
];

/// Read verbs in the multi-verb files: they build no signer.
const READ_VERBS: &[(&str, &str)] = &[
    ("commands/smart_account/rules.rs", "get_run"),
    ("commands/smart_account/rules.rs", "verify_pins_run"),
    ("commands/smart_account/rules.rs", "get_spending_limit_run"),
    ("commands/smart_account/signers.rs", "list_run"),
    ("commands/smart_account/signers.rs", "refresh_run"),
];

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("source directory reads") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The production lines of a source file: up to the first top-level
/// `#[cfg(test)]` line that gates a `mod`, without `//` comment lines.
fn production_lines(source: &str) -> Vec<&str> {
    let all: Vec<&str> = source.lines().collect();
    let end = all
        .windows(2)
        .position(|pair| pair[0] == "#[cfg(test)]" && pair[1].starts_with("mod "))
        .unwrap_or(all.len());
    all[..end]
        .iter()
        .copied()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect()
}

fn relative(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .expect("path under src")
        .to_string_lossy()
        .replace('\\', "/")
}

/// The top-level functions of `lines` as `(name, body lines)`, split at each
/// line that starts a top-level `fn`.
fn top_level_functions<'a>(lines: &[&'a str]) -> Vec<(String, Vec<&'a str>)> {
    let mut functions: Vec<(String, Vec<&'a str>)> = Vec::new();
    for line in lines {
        let starts_fn = !line.starts_with(' ')
            && line.contains("fn ")
            && !line.trim_start().starts_with("impl");
        if starts_fn {
            let rest = line.split_once("fn ").expect("fn line").1;
            let name = rest
                .split(['(', '<', ' '])
                .next()
                .expect("function name")
                .to_owned();
            functions.push((name, vec![line]));
        } else if let Some((_, body)) = functions.last_mut() {
            body.push(line);
        }
    }
    functions
}

#[test]
fn every_signer_building_file_checks_the_halt_marker() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&root, &mut files);
    let mut signer_files = Vec::new();
    let mut violations = Vec::new();
    for path in files {
        let source = std::fs::read_to_string(&path).expect("source reads");
        let lines = production_lines(&source);
        let name = relative(&path, &root);
        let builds_signer = lines
            .iter()
            .any(|line| SIGNER_CONSTRUCTORS.iter().any(|call| line.contains(call)));
        if !builds_signer || DEFINITION_FILES.contains(&name.as_str()) {
            continue;
        }
        signer_files.push(name.clone());
        if !lines.iter().any(|line| line.contains(HALT_CHECK)) {
            violations.push(format!(
                "{name}: builds a signer and never checks the halt marker"
            ));
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
    for file in MULTI_VERB_FILES {
        assert!(
            signer_files.iter().any(|seen| seen == file),
            "the scan must see {file} as a signer-building file"
        );
    }
}

#[test]
fn every_write_verb_in_the_multi_verb_files_checks_the_halt_marker() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut violations = Vec::new();
    let mut checked = 0usize;
    let mut read_seen = Vec::new();
    for file in MULTI_VERB_FILES {
        let source = std::fs::read_to_string(root.join(file)).expect("source reads");
        let lines = production_lines(&source);
        for (function, body) in top_level_functions(&lines) {
            if !body
                .iter()
                .any(|line| line.contains("load_command_profile("))
            {
                continue;
            }
            if READ_VERBS.contains(&(file, function.as_str())) {
                read_seen.push((*file, function));
                continue;
            }
            checked += 1;
            if !body.iter().any(|line| line.contains(HALT_CHECK)) {
                violations.push(format!(
                    "{file}::{function} loads the profile and never checks the halt marker"
                ));
            }
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
    assert_eq!(
        read_seen.len(),
        READ_VERBS.len(),
        "every listed read verb must still load the profile: {read_seen:?}"
    );
    assert_eq!(
        checked, 13,
        "seven rules and six signers write verbs load the profile; a change in this number means a verb was added or removed"
    );
}
