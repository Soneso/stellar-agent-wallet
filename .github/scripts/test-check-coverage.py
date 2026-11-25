#!/usr/bin/env python3
"""Offline regression checks for check-coverage.py.

Each case writes a coverage document with the given file entries, runs the
gate on it, and checks the exit status and the message.
"""

import contextlib
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tempfile

SCRIPT = pathlib.Path(__file__).resolve().parent / "check-coverage.py"
ROOT = "/work/stellar-agent-wallet"
EXEMPT = "stellar-agent-smart-account-acceptance"


def workspace(root, members, sources=None):
    (root / "Cargo.toml").write_text('[workspace]\nmembers = ' +
                                    json.dumps([f"crates/{name}" for name in members]) + '\n')
    for name in members:
        (root / "crates" / name / "src").mkdir(parents=True, exist_ok=True)
        (root / "crates" / name / "Cargo.toml").write_text(
            f'[package]\nname = "{name}"\nversion = "0.1.0"\n')
    for relative, text in (sources or {}).items():
        path = root / "crates" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


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
            members = {file["filename"].split("/crates/")[-1].split("/")[0] for file in files}
            workspace(pathlib.Path(tmp), members)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(cov_path), "--configuration", "feature-off", "--root", tmp],
                capture_output=True, text=True, check=False,
            )
            output = result.stdout + result.stderr
            missing = [fragment for fragment in fragments if fragment not in output]
            if result.returncode != want_rc or missing:
                failures.append(f"{label}: exit {result.returncode} (expected {want_rc}), "
                                f"missing {missing!r}: {output.strip()}")
            else:
                print(f"ok   {label}")
    spec = importlib.util.spec_from_file_location("coverage_gate", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for label, members, patterns, excluded, expected, fragment in [
        ("glob ignores directories without manifests", ["alpha"], ["crates/*"], [], 0, "all crates meet"),
        ("glob includes missing report member", ["alpha", "beta"], ["crates/*"], [], 1, "beta: missing from report"),
        ("glob honors exclusions", ["alpha", "beta"], ["crates/*"], ["crates/b*"], 0, "all crates meet"),
        ("empty member list", [], [], [], 1, "workspace has no members"),
        ("all members excluded", ["alpha"], ["crates/*"], ["crates/*"], 1, "workspace has no members"),
        ("glob without manifests", ["alpha"], ["crates/notes*"], [], 1, "workspace has no members"),
    ]:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace(root, members)
            (root / "crates" / "notes").mkdir(parents=True)
            (root / "Cargo.toml").write_text('[workspace]\nmembers = ' + json.dumps(patterns) +
                                            '\nexclude = ' + json.dumps(excluded) + '\n')
            cov = root / "cov.json"
            files = [] if expected == 1 and "no members" in fragment else [
                entry(f"{ROOT}/crates/alpha/src/lib.rs", 100, 100)]
            cov.write_text(json.dumps({"data": [{"files": files}]}))
            result = subprocess.run([sys.executable, str(SCRIPT), str(cov), "--configuration", "feature-off",
                                     "--root", tmp], capture_output=True, text=True)
            output = result.stdout + result.stderr
            if result.returncode != expected or fragment not in output:
                failures.append(f"{label}: expected exit {expected} and {fragment!r}: {output}")
            else:
                print(f"ok   {label}")
    for label, members, files, sources, expected, fragment in [
        ("missing member", ["alpha", "beta"], [entry(f"{ROOT}/crates/alpha/src/lib.rs", 100, 100)],
         {}, 1, "beta: missing from report"),
        ("zero-line crate", ["alpha"], [entry(f"{ROOT}/crates/alpha/src/lib.rs", 0, 0)],
         {}, 1, "zero lines in report"),
        ("unknown zero-line crate", ["alpha"], [entry(f"{ROOT}/crates/alpha/src/lib.rs", 100, 100),
                                               entry(f"{ROOT}/crates/extra/src/lib.rs", 0, 0)],
         {}, 1, "extra: zero lines in report"),
        ("exemption omitted", [EXEMPT], [], {f"{EXEMPT}/src/lib.rs": "//! Documentation\n\n// comment\n/// doc\n"},
         0, "exempt while src"),
        ("exemption zero lines", [EXEMPT], [entry(f"{ROOT}/crates/{EXEMPT}/src/lib.rs", 0, 0)],
         {f"{EXEMPT}/src/lib.rs": "// comment\n"}, 0, "exempt while src"),
        ("exemption ends with function", [EXEMPT], [], {f"{EXEMPT}/src/lib.rs": "pub fn f() {}\n"},
         1, "exemption ends"),
        ("exemption zero lines with code", [EXEMPT], [entry(f"{ROOT}/crates/{EXEMPT}/src/lib.rs", 0, 0)],
         {f"{EXEMPT}/src/lib.rs": "pub fn f() {}\n"}, 1, "exemption ends"),
        ("exemption empty src", [EXEMPT], [], {}, 1, "exemption ends"),
        ("exemption bin code", [EXEMPT], [], {f"{EXEMPT}/src/lib.rs": "// comment\n",
                                             f"{EXEMPT}/src/bin/tool.rs": "fn main() {}\n"},
         1, "exemption ends"),
    ]:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace(root, members, sources)
            cov = root / "cov.json"
            cov.write_text(json.dumps({"data": [{"files": files}]}))
            result = subprocess.run([sys.executable, str(SCRIPT), str(cov), "--configuration", "feature-off",
                                     "--root", tmp], capture_output=True, text=True)
            output = result.stdout + result.stderr
            if result.returncode != expected or fragment not in output:
                failures.append(f"{label}: expected exit {expected} and {fragment!r}: {output}")
            else:
                print(f"ok   {label}")
    module.FLOORS = {"feature-off": {"stellar-agent-core": 40},
                     "feature-on": {"stellar-agent-core": 60}}
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "cov.json"
        path.write_text(json.dumps({"data": [{"files": [entry(f"{ROOT}/crates/stellar-agent-core/src/lib.rs", 50, 100)]}]}))
        workspace(pathlib.Path(tmp), ["stellar-agent-core"])
        for configuration, expected in (("feature-off", 0), ("feature-on", 1)):
            with contextlib.redirect_stdout(io.StringIO()):
                rc = module.main(str(path), configuration, tmp)
            if rc != expected:
                failures.append(f"configuration-selection-{configuration}: exit {rc}, expected {expected}")
        for args in ([], ["--configuration", "unknown"]):
            result = subprocess.run([sys.executable, str(SCRIPT), str(path), *args], capture_output=True)
            if result.returncode != 2:
                failures.append("configuration-required: invalid configuration accepted")
    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"{len(failures)} check-coverage case(s) failed", file=sys.stderr)
        return 1
    print("check-coverage tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
