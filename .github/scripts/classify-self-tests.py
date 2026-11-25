#!/usr/bin/env python3
"""Select self-tests by their inputs; only proven next diffs can skip them."""

import fnmatch
import os
import sys

from changed_paths import collect

BASE = (".github/**", "Cargo.toml", "**/Cargo.toml", "Cargo.lock", "**/Cargo.lock",
        "rust-toolchain.toml", "Cross.toml", "deny.toml", "scripts/**", "contracts/**")
GROUPS = {
    "scripts": (),  # Any deletion (including a rename source) checks CODEOWNERS.
    "rust": ("crates/**", "build.rs", "**/build.rs", "docs/maintainers/building.md"),
    "docs": ("*.md", "skills/**", ".claude-plugin/**"),
    "preflight": ("changelog.d/**", "CHANGELOG.md", "CONTRIBUTING.md",
                  "docs/maintainers/building.md", "skills/**",
                  "crates/stellar-agent-smart-account/vendor/cap85-beacon/v0.1.0/REFERENCE.md",
                  "crates/stellar-agent-sep7/src/lib.rs", "crates/stellar-agent-sep5/src/lib.rs",
                  "crates/stellar-agent-windows-identity/src/lib.rs",
                  "crates/stellar-agent-test-support/src/lib.rs"),
}


def classify(environ):
    files, reason = collect(environ)
    if files is None:
        return dict.fromkeys(GROUPS, True), reason
    deleted, reason = collect(environ, deleted=True)
    if deleted is None:
        return dict.fromkeys(GROUPS, True), reason
    selected = {
        group: any(fnmatch.fnmatchcase(path, pattern)
                   for path in files for pattern in BASE + extra)
        or (group == "scripts" and bool(deleted))
        for group, extra in GROUPS.items()
    }
    return selected, "selected self-tests from changed inputs"


def main():
    selected, reason = classify(os.environ)
    print(f"classify-self-tests: {reason}", file=sys.stderr)
    for group, enabled in selected.items():
        print(f"selftest_{group}={'true' if enabled else 'false'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
