#!/usr/bin/env python3
"""Run check-docs-reads.py against scratch workspaces and check each verdict."""

import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).with_name("check-docs-reads.py")
WORKSPACE = '[workspace]\nmembers = ["crates/*"]\nresolver = "2"\n'
PACKAGE = '[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2021"\n'
LIB_HEAD = "//! Fixture crate.\n\npub fn value() -> u32 {\n    1\n}\n"
COVERED_TEST = """
#[cfg(test)]
mod tests {
    #[test]
    fn guide_names_the_value() {
        let guide = include_str!("../../../docs/guide.md");
        assert!(guide.contains("value"));
    }
}
"""
UNCOVERED_TEST = """
#[cfg(test)]
mod more_tests {
    #[test]
    fn readme_is_present() {
        assert!(!include_str!("../../../README.md").is_empty());
    }
}
"""
CRATE_DOC = '#![doc = include_str!("../../../docs/guide.md")]\n'
NON_DOC = """
#[cfg(test)]
mod fixture_tests {
    #[test]
    fn fixture_parses() {
        assert!(include_str!("fixture.txt").contains("x"));
        assert!(include_str!("../NOTES.md").contains("x"));
    }
}
"""
HELPER_TEST = """
fn read_doc(relative: &str) -> String {
    std::fs::read_to_string(relative).unwrap()
}

fn changelog() -> String {
    read_doc("../../changelog.d/entry.added.md")
}

#[test]
fn changelog_has_an_entry() {
    assert!(changelog().starts_with("- "));
}

#[test]
fn unrelated() {
    assert_eq!(1, 1);
}
"""
CFG_TEST_FILE_PARENT = "#[cfg(test)]\nmod doc_tests;\n"
CFG_TEST_FILE = """
#[test]
fn skill_reference_exists() {
    assert!(std::path::Path::new("../../skills/stellar-agent-wallet/references/cli.md").exists());
}
"""
DIR_WALK = """
#[test]
fn every_page_has_a_title() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for entry in std::fs::read_dir(root.join("docs")).unwrap() {
        let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        assert!(!text.is_empty());
    }
}
"""
FORMATTED = """
fn page(name: &str) -> String {
    std::fs::read_to_string(format!("../../docs/{name}.md")).unwrap()
}

#[test]
fn guide_page_reads() {
    assert!(page("guide").contains("value"));
}
"""
GLOBBED = """
#[test]
fn pages_match_the_glob() {
    let pattern = "../../docs/**/*.md";
    assert!(pattern.ends_with(".md"));
}
"""
JOINED_SKILL = """
#[test]
fn skill_reference_is_joined() {
    let path = std::path::Path::new("../..").join("skills").join("stellar-agent-wallet").join("references");
    assert!(path.join("cli.md").exists());
}
"""
PRODUCTION_INCLUDE = '\npub const GUIDE: &str = include_str!("../../../docs/guide.md");\n'
PRODUCTION_CONCAT = ('\npub const GUIDE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), '
                     '"/../../docs/guide.md"));\n')
TWO_HOP = """
fn raw_changelog() -> String {
    std::fs::read_to_string("../../changelog.d/entry.added.md").unwrap()
}

fn first_entry() -> String {
    raw_changelog().lines().next().unwrap().to_owned()
}

#[test]
fn first_entry_is_an_item() {
    assert!(first_entry().starts_with("- "));
}
"""
BYTES_TEST = """
#[cfg(test)]
mod byte_tests {
    #[test]
    fn guide_bytes_are_utf8() {
        assert!(std::str::from_utf8(include_bytes!("../../../docs/guide.md")).is_ok());
    }
}
"""
ITEM_DOC = '\n#[doc = include_str!("../../../docs/guide.md")]\npub struct Limits;\n'
MODULE_DOC = '#![doc = include_str!("../../../docs/guide.md")]\n'
PLACEHOLDER_FIRST = """
#[test]
fn guide_from_manifest_dir() {
    let path = format!("{}/../../docs/guide.md", env!("CARGO_MANIFEST_DIR"));
    assert!(std::fs::read_to_string(path).unwrap().contains("value"));
}

#[test]
fn page_from_root() {
    let (root, name) = (env!("CARGO_MANIFEST_DIR"), "guide");
    assert!(std::path::Path::new(&format!("{root}/../../docs/{name}.md")).exists());
}
"""
BUILD_SCRIPT = 'fn main() {\n    let text = include_str!("../../docs/guide.md");\n    println!("{}", text.len());\n}\n'
BUILD_SCRIPT_READ = """fn main() {
    let text = std::fs::read_to_string("../../docs/guide.md").unwrap();
    println!("cargo:rerun-if-changed=../../docs/guide.md");
    std::fs::write(std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("guide.txt"), text).unwrap();
}
"""
ROOT_AFTER_PLACEHOLDER = """
#[test]
fn readme_from_manifest_dir() {
    let path = format!("{}/../../README.md", env!("CARGO_MANIFEST_DIR"));
    assert!(std::fs::read_to_string(path).unwrap().starts_with('#'));
}

#[test]
fn changelog_from_root() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    assert!(std::path::Path::new(&format!("{root}/CHANGELOG.md")).exists());
}

#[test]
fn root_pages_by_glob() {
    let pattern = "../../*.md";
    assert!(pattern.ends_with(".md"));
}
"""
ARCHIVE_ENTRY = """
#[test]
fn archive_entry_names_the_manifest() {
    let package = "pay";
    assert_eq!(format!("{package}/TOOLSET.md"), "pay/TOOLSET.md");
}
"""
INLINE_MODULE_DOC = '\nmod inner {\n    #![doc = include_str!("../../../docs/guide.md")]\n}\n'
KEYED_BUILD = 'fn main() {\n    let _ = include_str!("../../../docs/guide.md");\n}\n'
PROSE_AFTER_PLACEHOLDER = """
#[cfg(test)]
mod listing_tests {
    #[test]
    fn page_list_is_complete() {
        let name = "guide";
        assert!(!name.is_empty(), "{name} must be listed in the /docs/ index");
    }
}
"""
PROSE = """
#[cfg(test)]
mod prose_tests {
    #[test]
    fn message_names_a_doc() {
        let hint = "see docs/guide.md for the steps";
        assert!(hint.len() > 3);
    }
}
"""


def workspace(tmp, lib_extra="", tests=None, files=None):
    root = Path(tempfile.mkdtemp(dir=tmp))
    write = {
        "Cargo.toml": WORKSPACE,
        "README.md": "# Fixture\n",
        "docs/guide.md": "The value is 1.\n",
        "changelog.d/entry.added.md": "- Entry.\n",
        "skills/stellar-agent-wallet/references/cli.md": "cli\n",
        "crates/alpha/Cargo.toml": PACKAGE.format(name="alpha"),
        "crates/alpha/NOTES.md": "x\n",
        "crates/alpha/src/fixture.txt": "x\n",
        "crates/alpha/src/lib.rs": LIB_HEAD + lib_extra,
    }
    for name, body in (tests or {}).items():
        write[f"crates/alpha/tests/{name}"] = body
    write.update(files or {})
    for relative, body in write.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return root


def run(root, registry):
    path = root / "registry.tsv"
    path.write_text("".join("\t".join(row) + "\n" for row in registry))
    result = subprocess.run([sys.executable, str(SCRIPT.resolve()), "--root", str(root), "--registry", str(path)],
                            capture_output=True, text=True, check=False)
    return result.returncode, result.stdout + result.stderr


# label, lib.rs extra, tests/ files, other files, registry rows, expected exit, fragments the output holds.
CASES = [
    ("covered read", COVERED_TEST, None, None,
     [("alpha", "lib", "tests::guide_names_the_value")], 0, ["1 documentation reads covered"]),
    ("uncovered read", COVERED_TEST + UNCOVERED_TEST, None, None,
     [("alpha", "lib", "tests::guide_names_the_value")], 1,
     ["crates/alpha/src/lib.rs:20: include_str! of README.md in test readme_is_present",
      "1 uncovered read(s)"]),
    ("read listed under the wrong target", COVERED_TEST, None, None,
     [("alpha", "test:guide", "tests::guide_names_the_value")], 1,
     ["crates/alpha/src/lib.rs:11: include_str! of docs/guide.md in test guide_names_the_value"]),
    ("crate-doc include without a doc row", "", None, {"crates/alpha/src/lib.rs": CRATE_DOC + LIB_HEAD}, [], 1,
     ["crates/alpha/src/lib.rs:1: crate docs include docs/guide.md; add: alpha\tdoc\t-"]),
    ("crate-doc include with a doc row", "", None, {"crates/alpha/src/lib.rs": CRATE_DOC + LIB_HEAD},
     [("alpha", "doc", "-")], 0, ["1 documentation reads covered"]),
    ("non-documentation include needs no entry", NON_DOC, None, None, [], 0,
     ["0 documentation reads covered by 0 registry rows"]),
    ("helper read reached by a test", "", {"history.rs": HELPER_TEST}, None,
     [("alpha", "test:history", "changelog_has_an_entry")], 0, ["1 documentation reads covered"]),
    ("helper read without its test", "", {"history.rs": HELPER_TEST}, None,
     [("alpha", "test:history", "unrelated")], 1,
     ["crates/alpha/tests/history.rs:7: string literal of changelog.d/entry.added.md in test "
      "changelog_has_an_entry"]),
    ("cfg(test) module file", CFG_TEST_FILE_PARENT, None, {"crates/alpha/src/doc_tests.rs": CFG_TEST_FILE}, [], 1,
     ["crates/alpha/src/doc_tests.rs:4: string literal of skills/stellar-agent-wallet/references/cli.md"]),
    ("prose that names a doc is no read", PROSE, None, None, [], 0, ["0 documentation reads covered"]),
    ("read_dir walk of the docs directory", "", {"walk.rs": DIR_WALK}, None, [], 1,
     ["crates/alpha/tests/walk.rs:5: string literal of docs in test every_page_has_a_title",
      "add: alpha\ttest:walk\tevery_page_has_a_title"]),
    ("read_dir walk of the docs directory with its row", "", {"walk.rs": DIR_WALK}, None,
     [("alpha", "test:walk", "every_page_has_a_title")], 0, ["1 documentation reads covered"]),
    ("formatted path in a helper", "", {"pages.rs": FORMATTED}, None, [], 1,
     ["crates/alpha/tests/pages.rs:3: string literal of docs in test guide_page_reads"]),
    ("glob of the docs directory", "", {"glob.rs": GLOBBED}, None, [], 1,
     ["crates/alpha/tests/glob.rs:4: string literal of docs in test pages_match_the_glob"]),
    ("skill path joined from parts", "", {"skill.rs": JOINED_SKILL}, None, [], 1,
     ["crates/alpha/tests/skill.rs:4: string literal of skills in test skill_reference_is_joined"]),
    ("production include with a row for its package", PRODUCTION_INCLUDE + COVERED_TEST, None, None,
     [("alpha", "lib", "tests::guide_names_the_value")], 1,
     ["crates/alpha/src/lib.rs:7: include_str! of docs/guide.md outside test code"]),
    ("production concat! include", PRODUCTION_CONCAT, None, None, [], 1,
     ["crates/alpha/src/lib.rs:7: include_str! of docs/guide.md outside test code"]),
    ("test moved to another module", COVERED_TEST, None, None,
     [("alpha", "lib", "moved::guide_names_the_value")], 1,
     ["include_str! of docs/guide.md in test guide_names_the_value",
      "add: alpha\tlib\ttests::guide_names_the_value"]),
    ("test listed under another test target", "", {"history.rs": HELPER_TEST, "other.rs": "\n"}, None,
     [("alpha", "test:other", "changelog_has_an_entry")], 1,
     ["add: alpha\ttest:history\tchangelog_has_an_entry"]),
    ("two-hop helper reached by its test", "", {"entries.rs": TWO_HOP}, None,
     [("alpha", "test:entries", "first_entry_is_an_item")], 0, ["1 documentation reads covered"]),
    ("include_bytes! in a test without its row", BYTES_TEST, None, None, [], 1,
     ["crates/alpha/src/lib.rs:11: include_bytes! of docs/guide.md in test guide_bytes_are_utf8"]),
    ("item-level doc include with a doc row", ITEM_DOC, None, None, [("alpha", "doc", "-")], 1,
     ["crates/alpha/src/lib.rs:7: include_str! of docs/guide.md outside test code"]),
    ("module-level inner doc include with a doc row", "pub mod guide;\n", None,
     {"crates/alpha/src/guide.rs": MODULE_DOC}, [("alpha", "doc", "-")], 1,
     ["crates/alpha/src/guide.rs:1: include_str! of docs/guide.md outside test code"]),
    ("path literals that start with a placeholder", "", {"lead.rs": PLACEHOLDER_FIRST}, None, [], 1,
     ["crates/alpha/tests/lead.rs:4: string literal of docs/guide.md in test guide_from_manifest_dir",
      "crates/alpha/tests/lead.rs:11: string literal of docs in test page_from_root"]),
    ("build script include", "", None, {"crates/alpha/build.rs": BUILD_SCRIPT}, [], 1,
     ["crates/alpha/build.rs:2: include_str! of docs/guide.md outside test code"]),
    ("build script that reads a doc at run time", "", None, {"crates/alpha/build.rs": BUILD_SCRIPT_READ}, [], 1,
     ["crates/alpha/build.rs:2: build-script string literal of docs/guide.md outside test code",
      "crates/alpha/build.rs:3: build-script string literal of docs/guide.md outside test code"]),
    ("root documentation files after a placeholder or wildcard", "", {"root.rs": ROOT_AFTER_PLACEHOLDER},
     {"CHANGELOG.md": "# Changelog\n"}, [], 1,
     ["crates/alpha/tests/root.rs:4: string literal of README.md in test readme_from_manifest_dir",
      "crates/alpha/tests/root.rs:11: string literal of CHANGELOG.md in test changelog_from_root",
      "crates/alpha/tests/root.rs:16: string literal of *.md in test root_pages_by_glob"]),
    ("archive entry name after a placeholder is no read", "", {"archive.rs": ARCHIVE_ENTRY}, None, [], 0,
     ["0 documentation reads covered"]),
    ("inner doc include in an inline module with a doc row", INLINE_MODULE_DOC, None, None,
     [("alpha", "doc", "-")], 1, ["crates/alpha/src/lib.rs:8: include_str! of docs/guide.md outside test code"]),
    ("build script named by the build key", "", None,
     {"crates/alpha/Cargo.toml": PACKAGE.format(name="alpha") + 'build = "scripts/generate.rs"\n',
      "crates/alpha/scripts/generate.rs": KEYED_BUILD}, [], 1,
     ["crates/alpha/scripts/generate.rs:2: include_str! of docs/guide.md outside test code"]),
    ("prose after a placeholder is no read", PROSE_AFTER_PLACEHOLDER, None, None, [], 0,
     ["0 documentation reads covered"]),
    ("registry row for an absent package", COVERED_TEST, None, None,
     [("alpha", "lib", "tests::guide_names_the_value"), ("beta", "lib", "x")], 1,
     ["beta is not a workspace member"]),
]


def main():
    scratch = SCRIPT.resolve().parents[2] / "target" / "tmp"
    scratch.mkdir(parents=True, exist_ok=True)
    failures = []
    with tempfile.TemporaryDirectory(prefix="check-docs-reads-", dir=scratch) as tmp:
        for label, lib_extra, tests, files, registry, expected, fragments in CASES:
            root = workspace(tmp, lib_extra, tests, files)
            rc, output = run(root, registry)
            missing = [fragment for fragment in fragments if fragment not in output]
            if rc != expected or missing:
                failures.append(f"{label}: exit {rc}, expected {expected}; missing {missing}; output:\n{output}")
            else:
                print(f"ok   {label}")
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    if failures:
        return 1
    print("documentation read check tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
