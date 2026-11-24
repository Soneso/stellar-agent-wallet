#!/usr/bin/env python3
"""Run classify-docs-only.py against scratch Git histories and check each result."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile

SCRIPT = Path(__file__).with_name("classify-docs-only.py")
BASE_FILES = {
    "README.md": "readme\n",
    "Cargo.toml": "[workspace]\n",
    "docs/maintainers/building.md": "building\n",
    "changelog.d/README.md": "fragments\n",
    "skills/stellar-agent-wallet/references/cli-reference.md": "reference\n",
    "skills/stellar-agent-wallet.zip": "archive\n",
    "crates/core/src/lib.rs": "pub fn f() {}\n",
    ".github/workflows/ci.yml": "name: CI\n",
}
# label, base ref, files written in the head commit, renames (old, new), expected output.
CASES = [
    ("docs only", "next", {"docs/maintainers/building.md": "edit\n", "docs/new.md": "new\n"}, [], "true"),
    ("root README.md only", "next", {"README.md": "edit\n"}, [], "true"),
    ("changelog.d only", "next", {"changelog.d/topic.changed.md": "- Entry.\n"}, [], "true"),
    ("skill reference only", "next",
     {"skills/stellar-agent-wallet/references/cli-reference.md": "edit\n"}, [], "true"),
    ("one .rs file", "next", {"docs/new.md": "new\n", "crates/core/src/lib.rs": "pub fn g() {}\n"}, [],
     "false"),
    ("workflow file", "next", {".github/workflows/ci.yml": "name: CI2\n"}, [], "false"),
    ("skill archive", "next", {"skills/stellar-agent-wallet.zip": "archive2\n"}, [], "false"),
    ("Cargo.toml", "next", {"Cargo.toml": "[workspace]\nmembers = []\n"}, [], "false"),
    ("empty list", "next", {}, [], "false"),
    ("base of main", "main", {"docs/new.md": "new\n"}, [], "false"),
    ("source renamed into docs", "next", {}, [("crates/core/src/lib.rs", "docs/lib.md")], "false"),
    ("nested changelog.d path", "next", {"changelog.d/sub/entry.md": "- Entry.\n"}, [], "false"),
    ("other skill", "next", {"skills/README.md": "edit\n"}, [], "false"),
]


def git(root, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME="Fixture", GIT_COMMITTER_NAME="Fixture",
               GIT_AUTHOR_EMAIL="fixture", GIT_COMMITTER_EMAIL="fixture",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True,
                          env=env).stdout.strip()


def write(root, files):
    for relative, body in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)


def classify(root, environ):
    env = {key: value for key, value in os.environ.items()
           if key not in ("EVENT_NAME", "BASE_REF", "BASE_SHA", "HEAD_SHA")}
    env.update(environ)
    result = subprocess.run([sys.executable, str(SCRIPT.resolve())], cwd=root, capture_output=True, text=True,
                            env=env, check=False)
    return result.returncode, result.stdout


def main():
    scratch = SCRIPT.resolve().parents[2] / "target" / "tmp"
    scratch.mkdir(parents=True, exist_ok=True)
    failures = []
    with tempfile.TemporaryDirectory(prefix="classify-docs-only-", dir=scratch) as tmp:
        root = Path(tmp)
        git(root, "init", "--quiet", "--initial-branch=next")
        write(root, BASE_FILES)
        git(root, "add", "--all")
        git(root, "commit", "--quiet", "-m", "base")
        base = git(root, "rev-parse", "HEAD")
        checks = []
        for label, base_ref, files, renames, expected in CASES:
            git(root, "checkout", "--quiet", "--detach", base)
            write(root, files)
            for old, new in renames:
                git(root, "mv", old, new)
            git(root, "add", "--all")
            git(root, "commit", "--quiet", "--allow-empty", "-m", label)
            head = git(root, "rev-parse", "HEAD")
            environ = {"EVENT_NAME": "pull_request", "BASE_REF": base_ref, "BASE_SHA": base, "HEAD_SHA": head}
            checks.append((label, environ, expected))
        head = checks[0][1]["HEAD_SHA"]
        checks += [
            ("push event", {"EVENT_NAME": "push", "BASE_REF": "", "BASE_SHA": base, "HEAD_SHA": head}, "false"),
            ("unknown event", {}, "false"),
            ("git error on an absent commit", {"EVENT_NAME": "pull_request", "BASE_REF": "next",
                                               "BASE_SHA": "0" * 40, "HEAD_SHA": head}, "false"),
            ("malformed head", {"EVENT_NAME": "pull_request", "BASE_REF": "next",
                                "BASE_SHA": base, "HEAD_SHA": "HEAD"}, "false"),
        ]
        for label, environ, expected in checks:
            rc, output = classify(root, environ)
            wanted = f"docs_only={expected}\n"
            if rc != 0 or output != wanted:
                failures.append(f"{label}: exit {rc}, output {output!r}, expected {wanted!r}")
            else:
                print(f"ok   {label}: docs_only={expected}")
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    if failures:
        return 1
    print("docs-only classifier tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
