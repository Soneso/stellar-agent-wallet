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
import sys

from changed_paths import collect
from docs_paths import is_documentation


def classify(environ):
    """Returns (docs_only, reason) for the event the environment describes."""
    files, reason = collect(environ)
    if files is None:
        return False, reason
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
