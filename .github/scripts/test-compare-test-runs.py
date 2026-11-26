#!/usr/bin/env python3
"""Offline fixtures for discovery, partition membership, and terminal outcomes."""

import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).with_name("compare-test-runs.py")
spec = importlib.util.spec_from_file_location("compare_test_runs", SCRIPT)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def artifact():
    return {"reason": "compiler-artifact", "package_id": "path+file:///source#pkg@1.0.0",
            "target": {"kind": ["lib"], "name": "pkg"}, "profile": {"test": True},
            "executable": "/build/pkg-hash", "manifest_path": "/source/Cargo.toml"}


def cargo(records=None):
    return "".join(json.dumps(row) + "\n" for row in (
        (records if records is not None else [artifact()]) + [{"reason": "build-finished", "success": True}]))


def listing(shard):
    return {"test-count": 4, "rust-suites": {"pkg": {
        "package-name": "pkg", "status": "listed",
        "package-id": artifact()["package_id"], "binary-path": "/build/pkg-hash",
        "build-platform": "target", "cwd": "/source",
        "binary-id": "pkg", "binary-name": "pkg", "kind": "lib",
        "testcases": {name: {"kind": "test", "ignored": name == "skip", "filter-match":
                            {"status": "mismatch", "reason": "ignored"} if name == "skip" else
                            {"status": "matches"} if owner == shard else
                            {"status": "mismatch", "reason": "partition"}}
                      for name, owner in (("one", 1), ("two", 2), ("three", 3), ("skip", 3))}}}}


def junit(name):
    return ('<testsuites tests="1"><testsuite name="pkg" tests="1">'
            f'<testcase classname="pkg" name="{name}"/></testsuite></testsuites>')


class Comparison(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.helper = {"target_libdir": Mock(return_value=Path("/sysroot/lib")),
                       "search_path": Mock(return_value=Path("/build/native")),
                       "dylib_environment": Mock(return_value={"LD_LIBRARY_PATH": "/libraries"})}
        self.shadow = {"version": 1, "executables": [{"package_id": artifact()["package_id"],
            "package": "pkg", "kind": ["lib"], "target": "pkg",
            "tests": "one: test\ntwo: test\nthree: test\nskip: test\n", "ignored": "skip: test\n"}]}
        self.write("feature-on-shadow/cargo-tests.jsonl", cargo())
        self.write("feature-on-shadow/shadow.json", json.dumps(self.shadow))
        for shard, name in enumerate(("one", "two", "three"), 1):
            self.write(f"feature-on-shard-{shard}/partition.json", json.dumps(listing(shard)))
            self.write(f"feature-on-shard-{shard}/target/nextest/ci/junit.xml", junit(name))

    def write(self, path, text):
        path = self.root / path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def bad_partition(self, mutate, message):
        doc = listing(1)
        mutate(doc)
        self.write("feature-on-shard-1/partition.json", json.dumps(doc))
        with self.assertRaisesRegex(ValueError, message):
            checker.compare(self.root)

    def bad_junit(self, text, message):
        self.write("feature-on-shard-1/target/nextest/ci/junit.xml", text)
        with self.assertRaisesRegex(ValueError, message):
            checker.compare(self.root)

    def test_pass(self):
        try:
            checker.compare(self.root)
        except Exception as error:
            self.fail(f'valid evidence rejected: {error}')

    def test_profile(self):
        profile = checker.tomllib.loads((SCRIPT.parents[2] / ".config/nextest.toml").read_text())
        self.assertIs(profile["profile"]["ci"]["fail-fast"], False)
        self.assertIs(type(profile["profile"]["ci"]["retries"]), int)
        self.assertEqual(profile, {"profile": {"ci": {"fail-fast": False, "retries": 0,
                                                     "junit": {"path": "junit.xml"}}}, "test-groups": {}})

    def test_producer_guard(self):
        workflow = (SCRIPT.parents[2] / ".github/workflows/ci.yml").read_text()
        block = workflow.split("      - name: Require successful producers\n", 1)[1]
        command = re.search(r"^        run: (.+)$", block, re.MULTILINE)[1]
        for shards in ("success", "failure", "cancelled", "skipped", ""):
            for shadow in ("success", "failure", "cancelled", "skipped", ""):
                result = subprocess.run(["bash", "-c", command],
                                        env=dict(os.environ, SHARDS_RESULT=shards, SHADOW_RESULT=shadow))
                self.assertEqual(result.returncode, 0 if shards == shadow == "success" else 1,
                                 (shards, shadow))

    def test_two_shards(self):
        self.write("feature-on-shard-2/partition.json", json.dumps(listing(1)))
        with self.assertRaisesRegex(ValueError, "two shards"):
            checker.compare(self.root)

    def test_union(self):
        self.shadow["executables"][0]["tests"] += "absent: test\n"
        self.write("feature-on-shadow/shadow.json", json.dumps(self.shadow))
        for shard in (1, 2, 3):
            doc = listing(shard)
            doc["test-count"] += 1
            doc["rust-suites"]["pkg"]["testcases"]["absent"] = {
                "kind": "test", "ignored": False,
                "filter-match": {"status": "mismatch", "reason": "partition"}}
            self.write(f"feature-on-shard-{shard}/partition.json", json.dumps(doc))
        with self.assertRaisesRegex(ValueError, "union differs"):
            checker.compare(self.root)

    def test_ignored_sets(self):
        self.shadow["executables"][0]["ignored"] = ""
        self.write("feature-on-shadow/shadow.json", json.dumps(self.shadow))
        with self.assertRaisesRegex(ValueError, "ignored sets"):
            checker.compare(self.root)

    def test_missing_outcome(self):
        self.shadow["executables"][0]["tests"] += "four: test\n"
        self.write("feature-on-shadow/shadow.json", json.dumps(self.shadow))
        for shard in (1, 2, 3):
            doc = listing(shard)
            doc["test-count"] += 1
            doc["rust-suites"]["pkg"]["testcases"]["four"] = {
                "kind": "test", "ignored": False,
                "filter-match": {"status": "matches"} if shard == 1 else
                                {"status": "mismatch", "reason": "partition"}}
            self.write(f"feature-on-shard-{shard}/partition.json", json.dumps(doc))
        self.bad_junit(junit("one"), "^missing JUnit test$")

    def test_no_outcomes(self):
        self.bad_junit('<testsuites/>', "^no JUnit tests$")

    def test_outside(self):
        self.bad_junit(junit("two"), "outside partition")

    def test_failure(self):
        self.bad_junit(junit("one").replace('/>', '><failure/></testcase>'), "non-passing")

    def test_error(self):
        self.bad_junit(junit("one").replace('/>', '><error/></testcase>'), "non-passing")

    def test_skipped(self):
        self.bad_junit(junit("one").replace('/>', '><skipped/></testcase>'), "non-passing")

    def test_retry(self):
        self.bad_junit(junit("one").replace('/>', '><rerunFailure/></testcase>'), "non-passing")

    def test_duplicate_outcome(self):
        self.bad_junit(junit("one").replace('</testsuite>',
            '<testcase classname="pkg" name="one"/></testsuite>'), "duplicate JUnit")

    def test_classname(self):
        self.bad_junit(junit("one").replace('classname="pkg"', 'classname="other"'), "classname")

    def test_suite(self):
        self.bad_junit(junit("one").replace('name="pkg"', 'name="other"'), "unknown JUnit suite")

    def test_suite_tag(self):
        self.bad_junit(junit("one").replace('<testsuite ', '<other ').replace('</testsuite>', '</other>'),
                       "unknown JUnit suite")

    def test_root(self):
        self.bad_junit('<other/>', "invalid JUnit root")

    def test_junit_count(self):
        self.bad_junit(junit("one").replace('tests="1"', 'tests="2"'), "JUnit count")

    def test_suite_failure(self):
        self.bad_junit(junit("one").replace('</testsuite>', '<failure/></testsuite>'), "suite outcome")

    def test_suite_failure_count(self):
        for field in ("failures", "errors"):
            self.bad_junit(junit("one").replace('<testsuite name="pkg" tests="1"', f'<testsuite name="pkg" tests="1" {field}="1"'), "suite count")

    def test_root_failure_count(self):
        for field in ("failures", "errors"):
            self.bad_junit(junit("one").replace('<testsuites tests="1">', f'<testsuites {field}="1">'), "root count")

    def test_root_test_count(self):
        self.bad_junit(junit("one").replace('<testsuites tests="1">', '<testsuites tests="2">'), "root test count")

    def test_junit_output(self):
        output = '<system-out>output</system-out><system-err>stderr</system-err><properties/>'
        text = junit("one").replace('/>', '>' + output + '</testcase>')
        self.write("feature-on-shard-1/target/nextest/ci/junit.xml", text.replace('</testsuite>', output + '</testsuite>'))
        checker.compare(self.root)

    def test_partition_values(self):
        doc = listing(3)
        doc["rust-suites"]["pkg"]["package-name"] = "package"
        doc["rust-suites"]["pkg"].update({"binary-id": "id", "binary-name": "target", "kind": "test"})
        self.assertEqual(checker.partition(doc),
                         ({("package", "test", "target", "three")},
                          {("package", "test", "target", "skip")},
                          {("package", "test", "target", name) for name in ("one", "two", "three", "skip")}, {"id": ("package", "test", "target")}))

    def test_shadow_collision(self):
        second = dict(artifact(), package_id="other-version")
        doc = copy.deepcopy(self.shadow)
        doc["executables"].append(dict(doc["executables"][0], package_id="other-version"))
        with self.assertRaisesRegex(ValueError, "ambiguous shadow"):
            checker.shadow_tests(cargo([artifact(), second]), doc)

    def test_ignored_execution(self):
        path = "feature-on-shard-3/target/nextest/ci/junit.xml"
        self.write(path, junit("skip"))
        with self.assertRaisesRegex(ValueError, "outside partition"):
            checker.compare(self.root)

    def test_missing_input(self):
        (self.root / "feature-on-shard-2/partition.json").unlink()
        with self.assertRaises(OSError):
            checker.compare(self.root)

    def test_truncated_json(self):
        self.write("feature-on-shard-1/partition.json", '{"rust-suites":')
        with self.assertRaises(ValueError):
            checker.compare(self.root)

    def test_truncated_xml(self):
        self.write("feature-on-shard-1/target/nextest/ci/junit.xml", '<testsuites>')
        with self.assertRaises(checker.ET.ParseError):
            checker.compare(self.root)

    def test_duplicate_json(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            checker.read_json('{"a":1,"a":2}')

    def test_nonfinite_json(self):
        with self.assertRaisesRegex(ValueError, "invalid JSON constant"):
            checker.read_json('{"a":NaN}')

    def test_count(self):
        self.bad_partition(lambda d: d.update({"test-count": 99}), "test count")

    def test_count_type(self):
        doc = listing(1)
        doc["rust-suites"]["pkg"]["testcases"] = {"one": doc["rust-suites"]["pkg"]["testcases"]["one"]}
        doc["test-count"] = True
        with self.assertRaisesRegex(ValueError, "test count"):
            checker.partition(doc)

    def test_filter(self):
        self.bad_partition(lambda d: d["rust-suites"]["pkg"]["testcases"]["one"].update(
            {"filter-match": {"status": "mismatch", "reason": "expression"}}), "unexpected nextest filter")

    def test_false_ignored_filter(self):
        self.bad_partition(lambda d: d["rust-suites"]["pkg"]["testcases"]["one"].update(
            {"filter-match": {"status": "mismatch", "reason": "ignored"}}), "unexpected nextest filter")

    def test_ignored_matches_filter(self):
        self.bad_partition(lambda d: d["rust-suites"]["pkg"]["testcases"]["skip"].update(
            {"filter-match": {"status": "matches"}}), "unexpected nextest filter")

    def test_ignored_partition_filter(self):
        self.bad_partition(lambda d: d["rust-suites"]["pkg"]["testcases"]["skip"].update(
            {"filter-match": {"status": "mismatch", "reason": "partition"}}), "unexpected nextest filter")

    def test_filter_shapes(self):
        for name in ("one", "skip"):
            for match in ({"status": "matches", "extra": True}, {"status": "mismatch"},
                          {"status": "mismatch", "reason": "ignored", "extra": True},
                          {"status": "mismatch", "reason": "partition", "extra": True}, None, [], "matches"):
                with self.subTest(name=name, match=match):
                    self.bad_partition(lambda d: d["rust-suites"]["pkg"]["testcases"][name].update(
                        {"filter-match": match}), "unexpected nextest filter")

    def test_each_ignored_set(self):
        doc = listing(2)
        del doc["rust-suites"]["pkg"]["testcases"]["skip"]
        doc["test-count"] -= 1
        self.write("feature-on-shard-2/partition.json", json.dumps(doc))
        with self.assertRaisesRegex(ValueError, "ignored sets"):
            checker.compare(self.root)

    def test_universe(self):
        doc = listing(2)
        del doc["rust-suites"]["pkg"]["testcases"]["one"]
        doc["test-count"] -= 1
        self.write("feature-on-shard-2/partition.json", json.dumps(doc))
        with self.assertRaisesRegex(ValueError, "^listed universe differs from shadow$"):
            checker.compare(self.root)

    def test_shared_extra_universe(self):
        for shard in (1, 2, 3):
            doc = listing(shard)
            doc["test-count"] += 1
            doc["rust-suites"]["pkg"]["testcases"]["extra"] = {
                "kind": "test", "ignored": False,
                "filter-match": {"status": "mismatch", "reason": "partition"}}
            self.write(f"feature-on-shard-{shard}/partition.json", json.dumps(doc))
        with self.assertRaisesRegex(ValueError, "^listed universe differs from shadow$"):
            checker.compare(self.root)

    def test_empty_partition_name(self):
        def mutate(doc):
            cases = doc["rust-suites"]["pkg"]["testcases"]
            cases[""] = cases.pop("two")
        self.bad_partition(mutate, "nonempty")

    def test_empty_partition(self):
        self.bad_partition(lambda d: d["rust-suites"]["pkg"]["testcases"]["one"].update(
            {"filter-match": {"status": "mismatch", "reason": "partition"}}), "no matched")

    def test_empty_junit(self):
        with self.assertRaisesRegex(ValueError, "no JUnit tests"):
            checker.junit_tests('<testsuites tests="0"/>', set(), set(), {})

    def test_required_root_count(self):
        with self.assertRaises(KeyError):
            checker.junit_tests(junit("one").replace('<testsuites tests="1">', '<testsuites>'),
                                {("pkg", "lib", "pkg", "one")}, set(), {"pkg": ("pkg", "lib", "pkg")})

    def test_ignored_matched(self):
        with self.assertRaisesRegex(ValueError, "ignored test executed"):
            checker.junit_tests(junit("skip"), {("pkg", "lib", "pkg", "skip")},
                                {("pkg", "lib", "pkg", "skip")}, {"pkg": ("pkg", "lib", "pkg")})

    def test_ignored_type(self):
        self.bad_partition(lambda d: d["rust-suites"]["pkg"]["testcases"]["one"].update(
            {"ignored": "false"}), "ignored flag")

    def test_unlisted(self):
        self.bad_partition(lambda d: d["rust-suites"]["pkg"].update({"status": "skipped"}), "unlisted")

    def test_binary_collision(self):
        self.bad_partition(lambda d: d["rust-suites"].update({"other": copy.deepcopy(d["rust-suites"]["pkg"])}),
                           "ambiguous nextest")

    def test_binary_id_collision(self):
        def mutate(doc):
            other = copy.deepcopy(doc["rust-suites"]["pkg"])
            other["package-name"] = "other"
            doc["rust-suites"]["other"] = other
        self.bad_partition(mutate, "ambiguous nextest")

    def test_binary_identity_collision(self):
        def mutate(doc):
            other = copy.deepcopy(doc["rust-suites"]["pkg"])
            other["binary-id"] = "other"
            doc["rust-suites"]["other"] = other
        self.bad_partition(mutate, "ambiguous nextest")

    def test_no_binary(self):
        self.bad_partition(lambda d: d.update({"test-count": 0, "rust-suites": {}}), "no nextest")

    def test_target_identity(self):
        self.assertEqual(checker.target_identity("p", ["test"], "t"), ("p", "test", "t"))
        for kind in ([], ["lib", "test"], "lib", "x"):
            with self.assertRaisesRegex(ValueError, "target kind"):
                checker.target_identity("p", kind, "t")
        with self.assertRaisesRegex(ValueError, "nonempty"):
            checker.target_identity("", ["lib"], "t")
        with self.assertRaisesRegex(ValueError, "nonempty"):
            checker.target_identity(1, ["lib"], "t")

    def test_libtest(self):
        self.assertEqual(checker.libtest_list(""), set())
        self.assertEqual(checker.libtest_list("a::b: test\n"), {"a::b"})
        for text, message in ((None, "invalid"), ("a: test", "truncated"),
                              ("1 test, 0 benchmarks\n", "unsupported"),
                              ("a: benchmark\n", "unsupported"),
                              (": test\n", "nonempty"),
                              ("a: test\na: test\n", "duplicate")):
            with self.assertRaisesRegex(ValueError, message):
                checker.libtest_list(text)

    def test_empty_executable(self):
        with self.assertRaisesRegex(ValueError, "invalid cargo artifact"):
            checker.cargo_artifacts(cargo([dict(artifact(), executable=""), artifact()]))

    def test_cargo(self):
        a = artifact()
        self.assertEqual(list(checker.cargo_artifacts(cargo()).values()), [a])
        no_test = dict(a, profile={"test": False})
        no_exe = dict(a, executable=None)
        self.assertEqual(len(checker.cargo_artifacts(cargo([no_test, no_exe, a,
            {"reason": "compiler-message"}, {"reason": "build-script-executed"}]))), 1)
        for text, message in (("", "truncated"), ("\n", "Expecting value"), (cargo().rstrip(), "truncated"),
                              (json.dumps(a) + "\n", "build-finished"),
                              (cargo([a, a]), "duplicate cargo"), (cargo([]), "no cargo"),
                              (cargo([dict(a, profile={"test": "false"})]), "invalid cargo artifact"),
                              (cargo([dict(a, executable=1)]), "invalid cargo artifact"),
                              (cargo([dict(a, executable="")]), "invalid cargo artifact"),
                              (cargo([dict(a, manifest_path="")]), "nonempty"),
                              (cargo([{"reason": "unknown"}]), "unexpected cargo")):
            with self.assertRaisesRegex(ValueError, message):
                checker.cargo_artifacts(text)

    def test_shadow(self):
        for change, message in ((lambda d: d.update(version=2), "version"),
            (lambda d: d.update(version=True), "version"),
            (lambda d: d.update(executables=[]), "missing shadow"),
            (lambda d: d["executables"].append(d["executables"][0]), "repeated shadow"),
            (lambda d: d["executables"][0].update(package_id="unknown"), "unexpected"),
            (lambda d: d["executables"][0].update(ignored="missing: test\n"), "outside list")):
            doc = copy.deepcopy(self.shadow)
            change(doc)
            with self.assertRaisesRegex(ValueError, message):
                checker.shadow_tests(cargo(), doc)

    def test_identity_not_path(self):
        a = artifact(); a["executable"] = "/different/hash"
        self.write("feature-on-shadow/cargo-tests.jsonl", cargo([a]))
        checker.compare(self.root)

    def test_distinct_targets(self):
        other = dict(artifact(), package_id="other@1.0.0", target={"kind": ["test"], "name": "pkg"})
        self.write("feature-on-shadow/cargo-tests.jsonl", cargo([artifact(), other]))
        self.shadow["executables"].append({"package_id": "other@1.0.0", "package": "other",
            "kind": ["test"], "target": "pkg", "tests": "one: test\n", "ignored": ""})
        self.write("feature-on-shadow/shadow.json", json.dumps(self.shadow))
        for shard in (1, 2, 3):
            doc = listing(shard)
            doc["test-count"] += 1
            doc["rust-suites"]["other"] = {"package-name": "other", "status": "listed",
                "binary-id": "other::pkg", "binary-name": "pkg", "kind": "test",
                "testcases": {"one": {"kind": "test", "ignored": False, "filter-match": {"status": "matches"} if shard == 1
                                      else {"status": "mismatch", "reason": "partition"}}}}
            self.write(f"feature-on-shard-{shard}/partition.json", json.dumps(doc))
        self.write("feature-on-shard-1/target/nextest/ci/junit.xml", junit("one").replace('<testsuites tests="1">', '<testsuites tests="2">').replace('</testsuites>',
            '<testsuite name="other::pkg" tests="1"><testcase name="one" classname="other::pkg"/></testsuite></testsuites>'))
        checker.compare(self.root)

    def test_capture(self):
        manifest = self.root / "Cargo.toml"
        manifest.write_text('[package]\nname = "package"\n')
        a = artifact(); a["manifest_path"] = str(manifest)
        source = self.root / "cargo.jsonl"
        source.write_text(cargo([a, {"reason": "build-script-executed", "linked_paths": ["native=/build/native"]}]))
        output = self.root / "captured.json"
        with patch.object(checker.runpy, "run_path", return_value=self.helper) as load, \
                patch.object(checker.subprocess, "run") as run:
            run.side_effect = [subprocess.CompletedProcess([], 0, "a: test\nb: test\n"),
                               subprocess.CompletedProcess([], 0, "b: test\n")]
            checker.capture(source, output)
            load.assert_called_once_with(str(SCRIPT.with_name("check-proof-matrix.py")))
            self.assertEqual(run.call_args_list[0].args[0], [a["executable"], "--list", "--format", "terse"])
            self.assertEqual(run.call_args_list[1].args[0], [a["executable"], "--list", "--ignored", "--format", "terse"])
            for call in run.call_args_list:
                self.assertEqual(call.kwargs, {"check": True, "capture_output": True, "text": True,
                                               "cwd": manifest.parent, "env": {"LD_LIBRARY_PATH": "/libraries"}})
            self.helper["search_path"].assert_called_once_with("native=/build/native")
            self.helper["dylib_environment"].assert_called_once_with(
                Path(a["executable"]), [Path("/build/native")], Path("/sysroot/lib"))
        doc = json.loads(output.read_text())
        self.assertEqual(checker.shadow_tests(cargo([a]), doc),
                         ({("package", "lib", "pkg", "a"), ("package", "lib", "pkg", "b")},
                          {("package", "lib", "pkg", "b")}))

    def test_capture_bad_lists(self):
        source = self.root / "cargo.jsonl"
        source.write_text(cargo())
        with patch.object(checker.tomllib, "loads", return_value={"package": {"name": "pkg"}}), \
                patch.object(checker.Path, "read_text", return_value=cargo()), \
                patch.object(checker.runpy, "run_path", return_value=self.helper), \
                patch.object(checker.subprocess, "run") as run:
            run.side_effect = [subprocess.CompletedProcess([], 0, "a: test\n"),
                               subprocess.CompletedProcess([], 0, "b: test\n")]
            with self.assertRaisesRegex(ValueError, "outside list"):
                checker.capture(source, self.root / "bad.json")

    def test_capture_libdir(self):
        source = self.root / "cargo.jsonl"
        manifest = self.root / "Cargo.toml"
        manifest.write_text('[package]\nname = "pkg"\n')
        source.write_text(cargo([dict(artifact(), manifest_path=str(manifest))]))
        self.helper["target_libdir"].return_value = None
        with patch.object(checker.runpy, "run_path", return_value=self.helper), \
                patch.object(checker.subprocess, "run", side_effect=[
                    subprocess.CompletedProcess([], 0, "a: test\n"), subprocess.CompletedProcess([], 0, "")]):
            with self.assertRaisesRegex(ValueError, "cannot locate Rust libraries"):
                checker.capture(source, self.root / "bad.json")

    def test_cli_capture(self):
        with patch.object(sys, "argv", [str(SCRIPT), "--capture", "a", "b"]), \
                patch.object(checker, "capture") as capture:
            self.assertEqual(checker.main(), 0)
            capture.assert_called_once_with(Path("a"), Path("b"))

    def test_cli_capture_error(self):
        with patch.object(sys, "argv", [str(SCRIPT), "--capture", "a", "b"]), \
                patch.object(checker, "capture", side_effect=subprocess.CalledProcessError(1, ["test-exe"])), \
                patch.object(sys, "stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(checker.main(), 1)
            self.assertTrue(stderr.getvalue().startswith("FAIL:"))

    def test_cli_malformed(self):
        for text in ("{", "[]", "{}", '{"rust-suites": []}'):
            self.write("feature-on-shard-1/partition.json", text)
            result = subprocess.run([sys.executable, str(SCRIPT), str(self.root)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertTrue(result.stderr.startswith("FAIL:"), result.stderr)
        self.write("feature-on-shard-1/partition.json", json.dumps(listing(1)))
        self.write("feature-on-shard-1/target/nextest/ci/junit.xml", "<testsuites>")
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.root)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue(result.stderr.startswith("FAIL:"), result.stderr)

    def test_cli(self):
        for args, expected in (([str(self.root)], 0), ([str(self.root), "extra"], 1),
                               ([str(self.root / "missing")], 1)):
            result = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)
            self.assertEqual(result.returncode, expected, result.stderr)
            if expected:
                self.assertTrue(result.stderr.startswith("FAIL:"), result.stderr)


if __name__ == "__main__":
    unittest.main()
