#!/usr/bin/env python3
"""Print whether a pull request or unforced push into next is docs-only.

The script reads the event from the environment: EVENT_NAME, BASE_REF,
BASE_SHA, HEAD_SHA, REF, BEFORE_SHA, AFTER_SHA, and FORCED. Pull requests use
the merge-base diff; pushes compare BEFORE_SHA to AFTER_SHA directly.
It runs ``git diff --name-only --no-renames`` and prints one line for
``$GITHUB_OUTPUT``: ``docs_only=true`` or ``docs_only=false``.

A documentation path is one of:

- ``docs/**/*.md``
- ``*.md`` at the repository root
- ``changelog.d/*.md``
- ``skills/stellar-agent-wallet/**/*.md``

The result is true only for a pull request or unforced push into next
whose changed files are all documentation paths. Every other case prints
false: another event or base, a missing or malformed commit, a git error, an
empty file list, and any other path. ``--no-renames`` lists both sides of a
rename, so moving a source file under ``docs/`` counts as a source change.
"""

import os
import re
import subprocess
import sys

from docs_paths import is_documentation

INTEGRATION_BRANCH = "next"
SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def changed_files(base, head, *, push=False):
    """Return changed paths, or None when git cannot compare the commits."""
    try:
        result = subprocess.run(
            ["git", "-c", "core.quotePath=false", "diff", "--name-only", "--no-renames", "-z",
             *([base, head] if push else [f"{base}...{head}"]), "--"],
            capture_output=True, check=False)
    except OSError as err:
        print(f"classify-docs-only: git did not start: {err}", file=sys.stderr)
        return None
    if result.returncode != 0:
        print(f"classify-docs-only: git diff exited {result.returncode}: "
              f"{result.stderr.decode(errors='replace').strip()}", file=sys.stderr)
        return None
    return [path for path in result.stdout.decode(errors="surrogateescape").split("\0") if path]


def classify(environ):
    """Returns (docs_only, reason) for the event the environment describes."""
    event = environ.get("EVENT_NAME", "")
    if event == "push":
        if environ.get("REF") != f"refs/heads/{INTEGRATION_BRANCH}":
            return False, "push is not into next"
        if environ.get("FORCED") != "false":
            return False, "push is not explicitly unforced"
        base, head = environ.get("BEFORE_SHA", ""), environ.get("AFTER_SHA", "")
        if any(not re.fullmatch(r"[0-9a-fA-F]{40}", sha) or sha == "0" * 40
               for sha in (base, head)):
            return False, "before or after is not a nonzero 40-hex commit SHA"
    elif event == "pull_request":
        base_ref = environ.get("BASE_REF", "")
        if base_ref != INTEGRATION_BRANCH:
            return False, f"base {base_ref or '(none)'} is not {INTEGRATION_BRANCH}"
        base, head = environ.get("BASE_SHA", ""), environ.get("HEAD_SHA", "")
        if not SHA.fullmatch(base) or not SHA.fullmatch(head):
            return False, "base or head is not a full commit SHA"
    else:
        return False, f"event {event or '(none)'} is not pull_request or push"
    files = changed_files(base, head, push=event == "push")
    if files is None:
        return False, "git diff failed"
    if not files:
        return False, "the diff changes no file"
    others = [path for path in files if not is_documentation(path)]
    if others:
        return False, f"{len(others)} of {len(files)} changed files are not documentation, first {others[0]}"
    return True, f"all {len(files)} changed files are documentation"


def main():
    try:
        docs_only, reason = classify(os.environ)
    except Exception as err:  # Any failure prints false.
        docs_only, reason = False, f"unexpected error: {err}"
    print(f"classify-docs-only: {reason}", file=sys.stderr)
    print(f"docs_only={'true' if docs_only else 'false'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
