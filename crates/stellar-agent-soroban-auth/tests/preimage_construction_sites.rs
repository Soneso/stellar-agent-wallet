//! Source scan: Soroban authorization preimages are built through this crate.
//!
//! Production code outside `crates/stellar-agent-soroban-auth/src/` must not
//! name the variant forms `HashIdPreimage::SorobanAuthorization(` or
//! `HashIdPreimage::SorobanAuthorizationWithAddress(`, in a construction or a
//! pattern, except at the sites listed in [`ALLOWED_SITES`] with their exact
//! occurrence counts. A site that moves to
//! [`stellar_agent_soroban_auth::build_auth_preimage`] must drop its entry, and
//! a new occurrence in a scanned region fails the scan.
//!
//! Scanned region per file: the lines outside inline test modules, with `//`
//! comment lines removed. An inline test module runs from a line whose trimmed
//! text is `#[cfg(test)]` and whose next non-blank line opens an inline
//! `mod ... {`, through the next line that is the attribute line's leading
//! whitespace followed by `}` (rustfmt aligns a module's closing brace with
//! its attribute); scanning resumes after it. A
//! `#[cfg(test)]` on any other item, including an out-of-line `mod name;`
//! declaration, is scanned.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "a scan failure must stop with the violated invariant"
)]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// The variant forms the scan counts, in a construction or a pattern.
const PATTERNS: &[&str] = &[
    "HashIdPreimage::SorobanAuthorization(",
    "HashIdPreimage::SorobanAuthorizationWithAddress(",
];

/// The crate that owns preimage construction; its sources are not scanned.
const OWNER_PREFIX: &str = "crates/stellar-agent-soroban-auth/src/";

/// Production sites that name a variant form and the exact number of
/// occurrences expected in the scanned region of each file.
const ALLOWED_SITES: &[(&str, usize)] = &[
    (
        "crates/stellar-agent-smart-account/src/managers/auth_entry.rs",
        2,
    ),
    (
        "crates/stellar-agent-smart-account/src/timelock_submit.rs",
        1,
    ),
    ("crates/stellar-agent-x402/src/exact.rs", 1),
    ("crates/stellar-agent-mpp/src/sponsored.rs", 1),
    ("crates/stellar-agent-mpp/src/reconcile.rs", 1),
    ("crates/stellar-agent-sep45/src/ephemeral.rs", 2),
    ("crates/stellar-agent-sep45/src/entries.rs", 1),
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root resolves")
}

fn collect_rust_files(directory: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(directory).unwrap_or_else(|e| panic!("read_dir {}: {e}", directory.display()));
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Returns the repository-relative path with forward slashes.
fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("scanned path is under the workspace root")
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Returns whether `lines[index]` is the `#[cfg(test)]` attribute of an inline
/// test module: its next non-blank line opens `mod ... {`.
fn opens_inline_test_module(lines: &[&str], index: usize) -> bool {
    lines[index].trim() == "#[cfg(test)]"
        && lines[index + 1..]
            .iter()
            .map(|next| next.trim())
            .find(|next| !next.is_empty())
            .is_some_and(|next| next.starts_with("mod ") && next.ends_with('{'))
}

/// Returns the scanned region of `source`: the lines outside inline test
/// modules, without `//` comment lines.
fn scanned_region(source: &str) -> Vec<&str> {
    let lines: Vec<&str> = source.lines().collect();
    let mut region = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if opens_inline_test_module(&lines, index) {
            let attribute = lines[index];
            let indent = &attribute[..attribute.len() - attribute.trim_start().len()];
            let close = format!("{indent}}}");
            index = lines[index..]
                .iter()
                .position(|line| *line == close)
                .map_or(lines.len(), |offset| index + offset + 1);
            continue;
        }
        let line = lines[index];
        if !line.trim_start().starts_with("//") {
            region.push(line);
        }
        index += 1;
    }
    region
}

fn count_occurrences(region: &[&str]) -> usize {
    region
        .iter()
        .map(|line| {
            PATTERNS
                .iter()
                .map(|pattern| line.matches(pattern).count())
                .sum::<usize>()
        })
        .sum()
}

#[test]
fn soroban_auth_preimages_are_built_only_at_listed_sites() {
    let root = workspace_root();
    let mut files = Vec::new();
    let crates = fs::read_dir(root.join("crates")).expect("crates directory");
    for crate_dir in crates {
        let src = crate_dir.expect("crate entry").path().join("src");
        if src.is_dir() {
            collect_rust_files(&src, &mut files);
        }
    }
    files.sort();

    let mut found: BTreeMap<String, usize> = BTreeMap::new();
    let mut scanned = 0_usize;
    for path in &files {
        let rel = relative(&root, path);
        if rel.contains("/vendor/") || rel.starts_with(OWNER_PREFIX) {
            continue;
        }
        let source = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {rel}: {e}"))
            .replace("\r\n", "\n");
        scanned += 1;
        let count = count_occurrences(&scanned_region(&source));
        if count > 0 {
            found.insert(rel, count);
        }
    }
    assert!(
        scanned > 100,
        "the scan must cover the workspace sources, scanned {scanned} files"
    );

    let expected: BTreeMap<String, usize> = ALLOWED_SITES
        .iter()
        .map(|(path, count)| ((*path).to_owned(), *count))
        .collect();
    assert_eq!(
        found, expected,
        "Soroban authorization preimage variant forms outside \
         stellar-agent-soroban-auth must match the allowlist exactly; build new \
         preimages with stellar_agent_soroban_auth::build_auth_preimage and \
         update ALLOWED_SITES when a listed site migrates"
    );
}

#[test]
fn scanned_region_skips_inline_test_modules_only() {
    let source = "\
fn a() {}
#[cfg(test)]
use x::y;
// HashIdPreimage::SorobanAuthorization( in a comment
    /// HashIdPreimage::SorobanAuthorization( in a doc comment
let p = HashIdPreimage::SorobanAuthorization(x);
#[cfg(test)]

mod tests {
    let q = HashIdPreimage::SorobanAuthorizationWithAddress(y);
}
";
    let region = scanned_region(source);
    assert_eq!(count_occurrences(&region), 1);
    assert!(region.contains(&"#[cfg(test)]"));
    assert!(!region.iter().any(|line| line.contains("mod tests")));

    // An out-of-line test module declaration is scanned past.
    let declared = "#[cfg(test)]\nmod helpers;\nlet p = HashIdPreimage::SorobanAuthorization(x);\n";
    assert_eq!(count_occurrences(&scanned_region(declared)), 1);

    // Production code after an inline test module is scanned; an occurrence
    // inside the module is not.
    let after =
        "#[cfg(test)]\nmod tests {\n    x\n}\nlet p = HashIdPreimage::SorobanAuthorization(x);\n";
    assert_eq!(count_occurrences(&scanned_region(after)), 1);
    let inside = "#[cfg(test)]\nmod tests {\n    let q = HashIdPreimage::SorobanAuthorization(y);\n}\nfn b() {}\n";
    let inside_region = scanned_region(inside);
    assert_eq!(count_occurrences(&inside_region), 0);
    assert_eq!(inside_region, vec!["fn b() {}"]);

    // An indented inline test module ends at its own aligned closing brace;
    // production code after it in the enclosing module is scanned.
    let nested = "mod a {\n    #[cfg(test)]\n    mod tests {\n        x\n    }\n    let p = HashIdPreimage::SorobanAuthorization(x);\n}\n";
    assert_eq!(count_occurrences(&scanned_region(nested)), 1);
}
