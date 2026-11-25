"""Collect next-branch diffs; uncertainty must never skip work.

The ordinary diff is the docs-only classifier's NUL-separated, no-renames
collection. The optional deletion filter also exposes rename sources, without
changing that ordinary diff. An empty deletion list is valid.
"""

import re
import subprocess
import sys

INTEGRATION_BRANCH = "next"
SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def changed_files(base, head, *, push=False, deleted=False):
    """Return changed paths, or None when git cannot compare the commits."""
    try:
        result = subprocess.run(
            ["git", "-c", "core.quotePath=false", "diff", "--name-only", "--no-renames", "-z",
             *(["--diff-filter=D"] if deleted else []),
             *([base, head] if push else [f"{base}...{head}"]), "--"],
            capture_output=True, check=False)
    except OSError as err:
        print(f"changed_paths: git did not start: {err}", file=sys.stderr)
        return None
    if result.returncode != 0:
        print(f"changed_paths: git diff exited {result.returncode}: "
              f"{result.stderr.decode(errors='replace').strip()}", file=sys.stderr)
        return None
    return [path for path in result.stdout.decode(errors="surrogateescape").split("\0") if path]


def collect(environ, *, deleted=False):
    """Return (paths, reason); None means the event cannot safely select tests."""
    event = environ.get("EVENT_NAME", "")
    if event == "push":
        if environ.get("REF") != f"refs/heads/{INTEGRATION_BRANCH}":
            return None, "push is not into next"
        if environ.get("FORCED") != "false":
            return None, "push is not explicitly unforced"
        base, head = environ.get("BEFORE_SHA", ""), environ.get("AFTER_SHA", "")
        if any(not re.fullmatch(r"[0-9a-fA-F]{40}", sha) or sha == "0" * 40
               for sha in (base, head)):
            return None, "before or after is not a nonzero 40-hex commit SHA"
    elif event == "pull_request":
        base_ref = environ.get("BASE_REF", "")
        if base_ref != INTEGRATION_BRANCH:
            return None, f"base {base_ref or '(none)'} is not {INTEGRATION_BRANCH}"
        base, head = environ.get("BASE_SHA", ""), environ.get("HEAD_SHA", "")
        if not SHA.fullmatch(base) or not SHA.fullmatch(head):
            return None, "base or head is not a full commit SHA"
    else:
        return None, f"event {event or '(none)'} is not pull_request or push"
    files = changed_files(base, head, push=event == "push", deleted=deleted)
    if files is None:
        return None, "git diff failed"
    if not files and not deleted:
        return None, "the diff changes no file"
    return files, f"{len(files)} changed paths"
