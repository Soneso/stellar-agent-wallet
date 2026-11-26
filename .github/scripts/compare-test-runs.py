#!/usr/bin/env python3
"""Compare stable nextest evidence with Cargo/libtest discovery from the shadow."""

import argparse
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(text):
    return json.loads(text, object_pairs_hook=unique_object,
                      parse_constant=lambda value: require(False, f"invalid JSON constant: {value}"))


def nonempty(value):
    require(isinstance(value, str) and bool(value), "expected nonempty string")
    return value


def target_identity(package, kind, name):
    require(isinstance(kind, list) and len(kind) == 1, "unsupported target kind")
    return nonempty(package), nonempty(kind[0]), nonempty(name)


def cargo_artifacts(text):
    require(text.endswith("\n"), "truncated cargo records")
    records = [read_json(line) for line in text.splitlines()]
    require(records[-1] == {"reason": "build-finished", "success": True},
            "missing successful build-finished record")
    artifacts = {}
    for record in records[:-1]:
        reason = record["reason"]
        require(reason in ("compiler-artifact", "compiler-message", "build-script-executed"),
                "unexpected cargo record")
        if reason == "compiler-artifact":
            require(type(record["profile"]["test"]) is bool and
                    (record["executable"] is None or
                     isinstance(record["executable"], str) and bool(record["executable"])),
                    "invalid cargo artifact")
        if reason == "compiler-artifact" and record["profile"]["test"] and record["executable"]:
            nonempty(record["manifest_path"])
            key = (nonempty(record["package_id"]), tuple(record["target"]["kind"]),
                   nonempty(record["target"]["name"]))
            require(key not in artifacts, "duplicate cargo test executable")
            artifacts[key] = record
    require(artifacts, "no cargo test executables")
    return artifacts


def libtest_list(text):
    require(isinstance(text, str), "invalid libtest list")
    require(not text or text.endswith("\n"), "truncated libtest list")
    names = set()
    for line in text.splitlines():
        require(line.endswith(": test"), "unsupported libtest list line")
        name = nonempty(line[:-6])
        require(name not in names, "duplicate libtest test")
        names.add(name)
    return names


def capture(cargo_path, output):
    text = cargo_path.read_text()
    artifacts = cargo_artifacts(text)
    # Reuse the proof matrix's Cargo dynamic-library environment, including
    # rustc's stable target-libdir query for proc-macro test executables.
    helper = runpy.run_path(str(Path(__file__).with_name("check-proof-matrix.py")))
    problems = []
    libdir = helper["target_libdir"](problems)
    require(libdir is not None, "cannot locate Rust libraries: " + "; ".join(problems))
    native = [helper["search_path"](linked) for message in map(read_json, text.splitlines())
              if message["reason"] == "build-script-executed" for linked in message["linked_paths"]]
    entries = []
    for record in artifacts.values():
        manifest_path = Path(record["manifest_path"])
        manifest = tomllib.loads(manifest_path.read_text())
        package = nonempty(manifest["package"]["name"])
        target_identity(package, record["target"]["kind"], record["target"]["name"])
        environment = helper["dylib_environment"](Path(record["executable"]), native, libdir)
        args = [record["executable"], "--list", "--format", "terse"]
        all_tests = subprocess.run(args, check=True, capture_output=True, text=True,
                                   cwd=manifest_path.parent, env=environment).stdout
        ignored = subprocess.run([record["executable"], "--list", "--ignored", "--format", "terse"],
                                 check=True, capture_output=True, text=True,
                                 cwd=manifest_path.parent, env=environment).stdout
        require(libtest_list(ignored) <= libtest_list(all_tests), "ignored tests outside list")
        entries.append({"package_id": record["package_id"], "package": package,
                        "kind": record["target"]["kind"], "target": record["target"]["name"],
                        "tests": all_tests, "ignored": ignored})
    output.write_text(json.dumps({"version": 1, "executables": entries}) + "\n")


def shadow_tests(cargo_text, document):
    artifacts = cargo_artifacts(cargo_text)
    require(type(document["version"]) is int and document["version"] == 1, "unsupported shadow version")
    seen, targets, tests, ignored = set(), set(), set(), set()
    for entry in document["executables"]:
        key = (entry["package_id"], tuple(entry["kind"]), entry["target"])
        require(key in artifacts and key not in seen, "unexpected or repeated shadow executable")
        seen.add(key)
        identity = target_identity(entry["package"], entry["kind"], entry["target"])
        require(identity not in targets, "ambiguous shadow identity")
        targets.add(identity)
        names, skips = libtest_list(entry["tests"]), libtest_list(entry["ignored"])
        require(skips <= names, "ignored tests outside list")
        tests.update((*identity, name) for name in names)
        ignored.update((*identity, name) for name in skips)
    require(seen == artifacts.keys(), "missing shadow executable")
    return tests, ignored


def partition(document):
    tests, ignored, universe, binaries = set(), set(), set(), {}
    total = 0
    for suite in document["rust-suites"].values():
        identity = target_identity(suite["package-name"], [suite["kind"]], suite["binary-name"])
        binary_id = nonempty(suite["binary-id"])
        require(binary_id not in binaries and identity not in binaries.values(), "ambiguous nextest binary")
        binaries[binary_id] = identity
        require(suite["status"] == "listed", "unlisted nextest suite")
        for name, case in suite["testcases"].items():
            total += 1
            require(type(case["ignored"]) is bool, "invalid ignored flag")
            match = case["filter-match"]
            key = (*identity, nonempty(name))
            universe.add(key)
            require(match == {"status": "mismatch", "reason": "ignored"} if case["ignored"] else
                    match in ({"status": "matches"}, {"status": "mismatch", "reason": "partition"}),
                    "unexpected nextest filter")
            if case["ignored"]:
                ignored.add(key)
            if match["status"] == "mismatch":
                continue
            tests.add(key)
    require(type(document["test-count"]) is int and document["test-count"] == total,
            "nextest test count differs")
    require(binaries, "no nextest binaries")
    require(tests, "no matched nextest tests")
    return tests, ignored, universe, binaries


def junit_tests(text, tests, ignored, binaries):
    root = ET.fromstring(text)
    require(root.tag == "testsuites", "invalid JUnit root")
    require(int(root.get("failures", "0")) == 0 and int(root.get("errors", "0")) == 0,
            "non-passing JUnit root count")
    seen = set()
    for suite in root:
        require(suite.tag == "testsuite" and suite.get("name") in binaries, "unknown JUnit suite")
        identity = binaries[suite.get("name")]
        require(all(child.tag in ("testcase", "system-out", "system-err", "properties") for child in suite),
                "non-passing JUnit suite outcome")
        require(int(suite.get("failures", "0")) == 0 and int(suite.get("errors", "0")) == 0,
                "non-passing JUnit suite count")
        for case in suite.findall("testcase"):
            key = (*identity, nonempty(case.get("name")))
            require(key in tests and key not in seen, "outside partition or duplicate JUnit test")
            require(case.get("classname") == suite.get("name"), "wrong JUnit classname")
            require(key not in ignored, "ignored test executed")
            require(all(child.tag in ("system-out", "system-err", "properties") for child in case),
                    "non-passing JUnit outcome")
            seen.add(key)
        require(int(suite.attrib["tests"]) == len(suite.findall("testcase")), "JUnit count differs")
    require(seen, "no JUnit tests")
    require(seen == tests - ignored, "missing JUnit test")
    require(int(root.attrib["tests"]) == len(seen), "JUnit root test count differs")


def compare(root):
    shadow = root / "feature-on-shadow"
    expected, expected_ignored = shadow_tests((shadow / "cargo-tests.jsonl").read_text(),
                                              read_json((shadow / "shadow.json").read_text()))
    union = set()
    for shard in (1, 2, 3):
        directory = root / f"feature-on-shard-{shard}"
        tests, ignored, listed, binaries = partition(read_json((directory / "partition.json").read_text()))
        require(ignored == expected_ignored, "ignored sets differ")
        require(listed == expected, "listed universe differs from shadow")
        require(not union & tests, "test in two shards")
        union.update(tests)
        junit_tests((directory / "target/nextest/ci/junit.xml").read_text(), tests, ignored, binaries)
    require(union == expected - expected_ignored, "partition union differs from shadow")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    try:
        require(len(args.paths) == (2 if args.capture else 1), "wrong number of paths")
        if args.capture:
            capture(*map(Path, args.paths))
        else:
            compare(Path(args.paths[0]))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ET.ParseError,
            subprocess.CalledProcessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
