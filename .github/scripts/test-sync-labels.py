#!/usr/bin/env python3
"""Exercise label validation and synchronization with an offline gh stub.

Uses the same Python interpreter as sync-labels.py, which needs PyYAML.
Also checks that each CODEOWNERS pattern names an existing repository path.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github/scripts/sync-labels.py"

LABELS = [
    ("good first issue", "7057ff", "Docs, scripts, or checks; a few hours; the issue states the acceptance command"),
    ("help wanted", "008672", "Rust code or tests; needs the gate suite; the issue states the design"),
    ("area: docs", "0075ca", "Documentation and the agent skill"),
    ("area: ci", "0e8a16", "Workflows, scripts, and checks"),
    ("area: cli", "1d76db", "The `stellar-agent` CLI"),
    ("area: mcp", "5319e7", "The MCP server"),
    ("area: smart-account", "c2e0c6", "Smart-account governance"),
    ("area: mpp", "fbca04", "Agent payments with MPP"),
    ("security-sensitive", "b60205", "Signing, key handling, or serialized state; second review pass"),
    ("coverage", "c5def5", "CI runs the coverage gate on this pull request"),
    ("waiting on author", "fef2c0", "The next step is the contributor's"),
    ("waiting on maintainer", "d4c5f9", "The next step is ours"),
    ("stale", "ededed", "No activity for 14 days; closes after 21"),
    ("hacktoberfest-accepted", "ff7518", "Counts for Hacktoberfest after the review"),
]
HONEST = [dict(zip(("name", "color", "description"), values)) for values in LABELS]
SAMPLE = {"name": "example", "color": "123abc", "description": "Example label"}
STUB = '''import json
import os
import sys

with open(os.environ["LABEL_TEST_LOG"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(sys.argv[1:]) + "\\n")
if os.environ.get("GH_TOKEN") != "label-test-token":
    sys.exit(19)
if sys.argv[3] == os.environ.get("LABEL_TEST_FAIL"):
    print("stub failure", file=sys.stderr)
    sys.exit(17)
'''


def arguments(entries, repo=None):
    calls = []
    for entry in entries:
        call = ["label", "create", entry["name"], "--color", entry["color"],
                "--description", entry["description"], "--force"]
        if repo is not None:
            call.extend(["--repo", repo])
        calls.append(call)
    return calls


def check_codeowners():
    tracked = set(subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True,
        text=True).stdout.split("\0"))
    patterns = set()
    for line in (ROOT / ".github/CODEOWNERS").read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        pattern, owner = line.split()
        assert owner == "@christian-rogobete", line
        assert pattern.startswith("/") and ".." not in pattern.split("/"), line
        assert pattern not in patterns, f"duplicate pattern: {pattern}"
        patterns.add(pattern)
        relative = pattern.lstrip("/")
        if pattern.endswith("/"):
            assert (ROOT / relative).is_dir(), f"missing directory: {pattern}"
        else:
            assert relative in tracked, f"untracked or missing file: {pattern}"
    assert patterns, "CODEOWNERS has no paths"


def main():
    failures = []
    count = 0

    def case(name, test):
        nonlocal count
        count += 1
        try:
            test()
        except Exception as error:
            failures.append(name)
            print(f"FAIL {name}: {error}", file=sys.stderr)
        else:
            print(f"ok   {name}")

    with tempfile.TemporaryDirectory(prefix="label-tests-") as directory:
        scratch = pathlib.Path(directory)
        stub = scratch / "gh"
        stub.write_text(f"#!{sys.executable}\n" + STUB)
        stub.chmod(0o755)
        log = scratch / "calls.jsonl"
        fixture = scratch / "labels.yml"
        env = dict(os.environ, PATH=str(scratch) + os.pathsep + os.environ.get("PATH", ""),
                   LABEL_TEST_LOG=str(log), GH_TOKEN="label-test-token", LABEL_TEST_FAIL="")

        def run(raw=None, errors=(), check=False, repo=None, fail=None, rc=0,
                calls=(), missing=False, no_gh=False, prefix=None):
            log.write_text("")
            command = [sys.executable, str(SCRIPT)]
            if raw is not None:
                fixture.write_bytes(raw if isinstance(raw, bytes) else raw.encode("utf-8"))
                command.append(str(fixture))
            if missing:
                command.append(str(scratch / "absent.yml"))
            if check:
                command.append("--check")
            if repo is not None:
                command.extend(["--repo", repo])
            call_env = dict(env, LABEL_TEST_FAIL=fail or "")
            if no_gh:
                empty = scratch / "empty-path"
                empty.mkdir(exist_ok=True)
                call_env["PATH"] = str(empty)
            result = subprocess.run(command, env=call_env, cwd=ROOT,
                                    capture_output=True, text=True, check=False)
            assert result.returncode == rc, (
                f"exit {result.returncode}, expected {rc}: {result.stderr.strip()}")
            synced = "".join(f"synced {call[2]}\n" for call in calls if call[2] != fail)
            assert result.stdout == synced, f"stdout {result.stdout!r}, expected {synced!r}"
            lines = result.stderr.splitlines()
            if prefix is not None:
                assert len(lines) == 1 and lines[0].startswith(prefix), lines
            else:
                assert lines == list(errors), f"errors {lines!r}, expected {errors!r}"
            recorded = [json.loads(line) for line in log.read_text().splitlines()]
            assert recorded == list(calls), f"calls {recorded!r}, expected {calls!r}"
            assert "label-test-token" not in result.stdout + result.stderr + log.read_text()

        def invalid(name, document, errors):
            case(name, lambda: run(json.dumps(document), errors=errors, rc=1))

        def honest_file():
            document = yaml.safe_load((ROOT / ".github/labels.yml").read_text())
            assert document == HONEST, "label file differs from the required table"
            run(check=True)

        case("honest file: --check, exact table, and no gh calls", honest_file)
        case("--check works without gh on PATH", lambda: run(check=True, no_gh=True))
        for name, document in (("mapping", {}), ("null", None), ("string", "labels")):
            invalid(f"document is a {name}, not a list", document, ["labels: expected a list"])
        for name, entry in (("string", "label"), ("null", None), ("list", [])):
            invalid(f"entry is a {name}, not a mapping", [entry], ["entry 1: expected a mapping"])
        keys_error = ["entry 1: expected exactly name, color, and description keys"]
        for field in SAMPLE:
            invalid(f"missing {field} key", [{k: v for k, v in SAMPLE.items() if k != field}], keys_error)
        invalid("extra key", [dict(SAMPLE, extra="value")], keys_error)
        invalid("key has whitespace", [{"name ": "example", "color": "123abc", "description": "Example"}], keys_error)
        for field in SAMPLE:
            for value in (None, 123456, True, [], {}):
                invalid(f"{field} rejects {type(value).__name__}", [dict(SAMPLE, **{field: value})],
                        [f"entry 1: {field} must be a string"])
        invalid("empty name", [dict(SAMPLE, name="")], ["entry 1: name must not be empty"])
        invalid("duplicate name", [SAMPLE, dict(SAMPLE, color="abcdef")],
                ["entry 2: duplicate name 'example'"])
        for color in ("ABCDEF", "#123abc", "123ab", "123abcd", "123abg", ""):
            invalid(f"invalid color {color!r}", [dict(SAMPLE, color=color)],
                    ["entry 1: color must be six lowercase hex digits without #"])
        invalid("description at 100 characters", [dict(SAMPLE, description="x" * 100)],
                ["entry 1: description must be under 100 characters"])
        invalid("description over 100 characters", [dict(SAMPLE, description="x" * 101)],
                ["entry 1: description must be under 100 characters"])
        for field in SAMPLE:
            for position, value in (("leading", " " + SAMPLE[field]),
                                    ("trailing", SAMPLE[field] + " "),
                                    ("newline", SAMPLE[field] + "\n")):
                errors = [f"entry 1: {field} has leading or trailing whitespace"]
                if field == "color":
                    errors.append("entry 1: color must be six lowercase hex digits without #")
                invalid(f"{field} {position} whitespace", [dict(SAMPLE, **{field: value})], errors)
        invalid("all errors precede any gh call", [SAMPLE, dict(SAMPLE, color="XYZ", description="x" * 100)],
                ["entry 2: duplicate name 'example'",
                 "entry 2: color must be six lowercase hex digits without #",
                 "entry 2: description must be under 100 characters"])
        case("malformed YAML", lambda: run("- name: [", rc=1, prefix="labels: cannot read valid YAML:"))
        case("unsafe YAML tag", lambda: run("!!python/object:builtins.object {}", rc=1,
                                           prefix="labels: cannot read valid YAML:"))
        case("invalid UTF-8", lambda: run(b"\xff", rc=1, prefix="labels: cannot read valid YAML:"))
        case("missing file", lambda: run(missing=True, rc=1, prefix="labels: cannot read valid YAML:"))
        case("empty list", lambda: run("[]"))
        for length in (0, 99):
            case(f"description accepts {length} characters",
                 lambda length=length: run(json.dumps([dict(SAMPLE, description="x" * length)]), check=True))
        case("Unicode description counts characters", lambda: run(
            json.dumps([dict(SAMPLE, description="é" * 99)]), check=True))
        case("sync sends exact argv for every label and inherits GH_TOKEN",
             lambda: run(calls=arguments(HONEST)))
        case("--repo reaches every gh call",
             lambda: run(repo="owner/project", calls=arguments(HONEST, "owner/project")))
        case("--check with --repo makes no gh calls", lambda: run(check=True, repo="owner/project"))
        case("gh failure names the label and stops immediately", lambda: run(
            fail=HONEST[1]["name"], rc=2, calls=arguments(HONEST[:2]),
            errors=["stub failure", "gh failed for label 'help wanted': exit 17"]))
        case("missing gh returns exit 2 and names the label", lambda: run(
            no_gh=True, rc=2, errors=["gh failed for label 'good first issue': cannot execute gh"]))
        literal = [dict(SAMPLE, name="literal; $(echo name)", description="Quotes ' and \"; $(echo text)")]
        case("shell metacharacters remain literal arguments",
             lambda: run(json.dumps(literal), calls=arguments(literal)))
        case("CODEOWNERS patterns name existing paths", check_codeowners)

    if failures:
        print(f"{len(failures)} of {count} label cases fail", file=sys.stderr)
        return 1
    print(f"all {count} label cases pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
