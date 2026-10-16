#!/usr/bin/env python3
"""Offline regression checks for check-coverage.py.

Each case writes a coverage document with the given file entries, runs the
gate on it, and checks the exit status and the message.
"""

import json
import pathlib
import subprocess
import sys
import tempfile

SCRIPT = pathlib.Path(__file__).resolve().parent / "check-coverage.py"
ROOT = "/work/stellar-agent-wallet"


def entry(filename, covered, count):
    return {"filename": filename, "summary": {"lines": {"covered": covered, "count": count}}}


# The floor of stellar-agent-cli is 42 and the floor of stellar-agent-core is 91.
CASES = [
    (
        "clone under a directory named crates",
        [entry("/home/dev/crates/stellar-agent-wallet/crates/stellar-agent-cli/src/main.rs", 50, 100)],
        0,
        ["stellar-agent-cli ", "all crates meet their coverage floor"],
    ),
    (
        "files under tests/src and examples/src add no lines",
        [
            entry(f"{ROOT}/crates/stellar-agent-core/src/lib.rs", 91, 100),
            entry(f"{ROOT}/crates/stellar-agent-core/tests/src/fixture.rs", 0, 100),
            entry(f"{ROOT}/crates/stellar-agent-core/examples/src/main.rs", 0, 100),
        ],
        0,
        ["91/100", "all crates meet their coverage floor"],
    ),
    (
        "crate at its floor",
        [entry(f"{ROOT}/crates/stellar-agent-core/src/lib.rs", 91, 100)],
        0,
        ["all crates meet their coverage floor"],
    ),
    (
        "crate short of its floor",
        [entry(f"{ROOT}/crates/stellar-agent-core/src/lib.rs", 90, 100)],
        1,
        ["stellar-agent-core: 90.00% < floor 91%"],
    ),
]


def main():
    failures = []
    for label, files, want_rc, fragments in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            cov_path = pathlib.Path(tmp) / "cov.json"
            cov_path.write_text(json.dumps({"data": [{"files": files}]}))
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(cov_path)],
                capture_output=True, text=True, check=False,
            )
            output = result.stdout + result.stderr
            missing = [fragment for fragment in fragments if fragment not in output]
            if result.returncode != want_rc or missing:
                failures.append(f"{label}: exit {result.returncode} (expected {want_rc}), "
                                f"missing {missing!r}: {output.strip()}")
            else:
                print(f"ok   {label}")
    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"{len(failures)} check-coverage case(s) failed", file=sys.stderr)
        return 1
    print("check-coverage tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
