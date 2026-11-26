#!/usr/bin/env python3
"""Fail unless every CI job reports the result required by the classifier."""

import json
import os
import sys

EXPECTED_JOBS = {
    "changes", "fmt", "clippy", "doc", "test", "feature-on-clippy",
    "feature-on-doc", "feature-on-test", "docs-tests", "feature-discipline",
    "release-shape", "inbox-js", "mpp-interop", "sdk-v17-interop",
    "release-contracts", "windows-storage", "platform-keyring", "deploy-scripts",
    "machete", "deny",
    "feature-on-test-shadow", "feature-on-test-extra", "feature-on-test-compare",
}
DOCS_REQUIRED = {"changes", "docs-tests", "feature-discipline", "release-contracts"}


def main():
    try:
        needs = json.loads(os.environ.get("NEEDS_JSON", ""))
        if not isinstance(needs, dict):
            raise ValueError("NEEDS_JSON must be an object")
    except (ValueError, TypeError) as error:
        print(f"FAIL: invalid NEEDS_JSON: {error}")
        return 1
    docs_only = os.environ.get("DOCS_ONLY", "")
    valid_mode = docs_only in ("true", "false")
    failed = not valid_mode
    if not valid_mode:
        print(f"FAIL: DOCS_ONLY must be true or false, got {docs_only!r}")
    for job in sorted(EXPECTED_JOBS | needs.keys()):
        entry = needs.get(job)
        result = entry.get("result") if isinstance(entry, dict) else None
        if job not in EXPECTED_JOBS:
            ok, rule = False, "unknown job"
        elif job not in needs:
            ok, rule = False, "expected job is missing"
        elif result not in ("success", "skipped"):
            ok, rule = False, "result must be success or skipped"
        elif job == "changes":
            ok, rule = result == "success", "changes must succeed"
        elif not valid_mode:
            ok, rule = False, "cannot select a rule with invalid DOCS_ONLY"
        else:
            required = job in DOCS_REQUIRED if docs_only == "true" else job != "docs-tests"
            expected = "success" if required else "skipped"
            ok = result == expected
            rule = f"docs_only={docs_only} requires {expected}"
        print(f"{job}: {result or '(missing)'}: {'ok' if ok else 'FAIL'}: {rule}")
        failed |= not ok
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
