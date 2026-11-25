#!/usr/bin/env python3
"""Exercise the aggregate's success paths and every fail-closed decision."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

SCRIPT = Path(__file__).with_name("ci-result.py")
spec = importlib.util.spec_from_file_location("ci_result", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
DOCS_REQUIRED = {"changes", "docs-tests", "feature-discipline", "release-contracts"}


def main():
    full = {job: {"result": "skipped" if job == "docs-tests" else "success"}
            for job in module.EXPECTED_JOBS}
    docs = {job: {"result": "success" if job in DOCS_REQUIRED else "skipped"}
            for job in module.EXPECTED_JOBS}
    cases = [("docs-only success", docs, "true", 0), ("full success", full, "false", 0)]
    for job in sorted(DOCS_REQUIRED):
        cases.append((f"docs required {job} skipped", dict(docs, **{job: {"result": "skipped"}}), "true", 1))
    for label, base, mode, job, result in [
        ("docs job ran", docs, "true", "fmt", "success"),
        ("full required job skipped", full, "false", "fmt", "skipped"),
        ("docs-tests ran in full", full, "false", "docs-tests", "success"),
        ("cancelled job", full, "false", "test", "cancelled"),
        ("failed job", full, "false", "test", "failure"),
        ("changes failed", full, "false", "changes", "failure"),
        ("unknown job", full, "false", "unknown", "success"),
        ("invalid result", full, "false", "fmt", "pending"),
    ]:
        cases.append((label, dict(base, **{job: {"result": result}}), mode, 1))
    cases.extend([
        ("missing job", {job: value for job, value in full.items() if job != "fmt"}, "false", 1),
        ("empty DOCS_ONLY", full, "", 1),
        ("invalid DOCS_ONLY", full, "yes", 1),
        ("non-object needs", [], "false", 1),
        ("invalid job record", dict(full, fmt=None), "false", 1),
    ])
    failures = []
    for label, needs, mode, expected in cases:
        result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True,
                                env=dict(os.environ, NEEDS_JSON=json.dumps(needs), DOCS_ONLY=mode))
        if result.returncode != expected or (expected == 1 and "FAIL" not in result.stdout):
            failures.append(f"{label}: exit {result.returncode}, expected {expected}: {result.stdout}{result.stderr}")
        elif isinstance(needs, dict) and any(f"{job}:" not in result.stdout
                                           for job in module.EXPECTED_JOBS | needs.keys()):
            failures.append(f"{label}: missing per-job explanation")
        else:
            print(f"ok   {label}")
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    return int(bool(failures))


if __name__ == "__main__":
    sys.exit(main())
