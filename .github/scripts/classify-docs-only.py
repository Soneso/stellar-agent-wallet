#!/usr/bin/env python3
"""Print whether a pull request into next changes only documentation.

The script reads the event from the environment: EVENT_NAME, BASE_REF,
BASE_SHA, and HEAD_SHA. It runs ``git diff --name-only --no-renames
BASE_SHA...HEAD_SHA`` in the current directory and prints one line for
``$GITHUB_OUTPUT``: ``docs_only=true`` or ``docs_only=false``.

A documentation path is one of:

- ``docs/**/*.md``
- ``*.md`` at the repository root
- ``changelog.d/*.md``
- ``skills/stellar-agent-wallet/**/*.md``

The result is true only for a pull_request event whose base is next
and whose changed files are all documentation paths. Every other case prints
false: another event or base, a missing or malformed commit, a git error, an
empty file list, and any other path. ``--no-renames`` lists both sides of a
rename, so moving a source file under ``docs/`` counts as a source change.
"""

import os
import re
import subprocess
import sys

INTEGRATION_BRANCH = "next"
SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def is_documentation(path):
    """Whether one repository-relative path is a documentation path."""
    if not path.endswith(".md"):
        return False
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    if len(parts) == 1:
        return True
    if parts[0] == "docs":
        return True
    if parts[0] == "changelog.d":
        return len(parts) == 2
    return parts[:2] == ["skills", "stellar-agent-wallet"] and len(parts) > 2


def changed_files(base, head):
    """Returns the changed paths between the merge base and head, or None on a git error."""
    try:
        result = subprocess.run(
            ["git", "-c", "core.quotePath=false", "diff", "--name-only", "--no-renames", "-z",
             f"{base}...{head}", "--"],
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
    if event != "pull_request":
        return False, f"event {event or '(none)'} is not pull_request"
    base_ref = environ.get("BASE_REF", "")
    if base_ref != INTEGRATION_BRANCH:
        return False, f"base {base_ref or '(none)'} is not {INTEGRATION_BRANCH}"
    base, head = environ.get("BASE_SHA", ""), environ.get("HEAD_SHA", "")
    if not SHA.fullmatch(base) or not SHA.fullmatch(head):
        return False, "base or head is not a full commit SHA"
    files = changed_files(base, head)
    if files is None:
        return False, "git diff failed"
    if not files:
        return False, "the pull request changes no file"
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
