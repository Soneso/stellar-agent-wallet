#!/usr/bin/env python3
"""Exercise input selection, real Git endpoints, and conservative failures."""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import changed_paths

SPEC = importlib.util.spec_from_file_location("selector", Path(__file__).with_name("classify-self-tests.py"))
selector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(selector)
GROUPS = {"scripts", "rust", "docs", "preflight"}
ENV = {"EVENT_NAME": "pull_request", "BASE_REF": "next", "BASE_SHA": "a" * 40, "HEAD_SHA": "b" * 40}

# Expected groups are independent of the implementation's pattern table.
PATHS = {
    "unrelated.txt": set(),
    "build.rs": {"rust"},
    "nested/deep/build.rs": {"rust"},
    "nested/notbuild.rs": set(),
    "crates/example/src/lib.rs": {"rust"},
    "docs/maintainers/building.md": {"rust", "docs", "preflight"},
    "README.md": {"docs"},
    "nested/deep/guide.md": {"docs"},
    "changelog.d/entry.changed.md": {"docs", "preflight"},
    "skills/example/data.bin": {"docs", "preflight"},
    ".claude-plugin/plugin.json": {"docs"},
    "changelog.d/raw": {"preflight"},
    "CHANGELOG.md": {"docs", "preflight"},
    "CONTRIBUTING.md": {"docs", "preflight"},
    "crates/stellar-agent-smart-account/vendor/cap85-beacon/v0.1.0/REFERENCE.md": {"rust", "docs", "preflight"},
    **{f"crates/stellar-agent-{crate}/src/lib.rs": {"rust", "preflight"}
       for crate in ("sep7", "sep5", "windows-identity", "test-support")},
    **{path: GROUPS for path in (".github/workflows/ci.yml", "Cargo.toml", "deep/nested/Cargo.toml",
                               "Cargo.lock", "deep/nested/Cargo.lock", "rust-toolchain.toml",
                               "Cross.toml", "deny.toml", "scripts/helper", "contracts/code")},
    "nested/Cross.toml": set(),
    "nested/notCargo.toml": set(),
    "GUIDE.MD": set(),
}


class Selection(unittest.TestCase):
    def assert_groups(self, actual, expected):
        self.assertEqual(actual, {group: group in expected for group in GROUPS})

    def test_paths(self):
        for path, expected in PATHS.items():
            with self.subTest(path=path), patch.object(selector, "collect", side_effect=[([path], ""), ([], "")]):
                self.assert_groups(selector.classify(ENV)[0], expected)

    def test_deletion(self):
        with patch.object(selector, "collect", side_effect=[(["unrelated.txt"], ""), (["unrelated.txt"], "")]):
            self.assert_groups(selector.classify(ENV)[0], {"scripts"})

    def test_failures(self):
        for side_effect in ([(None, "unknown")], [(["unrelated.txt"], ""), (None, "unknown")]):
            with self.subTest(side_effect=side_effect), patch.object(selector, "collect", side_effect=side_effect):
                self.assert_groups(selector.classify(ENV)[0], GROUPS)

    def test_output(self):
        for files, expected in ((["unrelated.txt"], set()), (["Cargo.toml"], GROUPS)):
            output = io.StringIO()
            with patch.object(selector, "collect", side_effect=[(files, ""), ([], "")]), \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(selector.main(), 0)
            self.assertEqual(output.getvalue(), "".join(f"selftest_{g}={'true' if g in expected else 'false'}\n"
                                                      for g in ("scripts", "rust", "docs", "preflight")))

    def test_unexpected_error(self):
        with patch.object(selector, "collect", side_effect=RuntimeError("broken")), \
                self.assertRaisesRegex(RuntimeError, "broken"):
            selector.main()

    def test_event_uncertainties(self):
        push = {"EVENT_NAME": "push", "REF": "refs/heads/next", "BEFORE_SHA": "a" * 40,
                "AFTER_SHA": "b" * 40, "FORCED": "false"}
        events = [dict(ENV, BASE_REF="main"), dict(push, REF="refs/heads/main"),
                  {"EVENT_NAME": "schedule"}, {"EVENT_NAME": "workflow_dispatch"}, {},
                  dict(push, FORCED="true"), dict(push, FORCED=""), dict(ENV, BASE_REF="")]
        for template, keys in ((ENV, ("BASE_SHA", "HEAD_SHA")), (push, ("BEFORE_SHA", "AFTER_SHA"))):
            for key in keys:
                for value in ("", "HEAD", "123"):
                    events.append(dict(template, **{key: value}))
        events += [dict(push, BEFORE_SHA="0" * 40), dict(push, AFTER_SHA="0" * 40)]
        for env in events:
            with self.subTest(env=env), patch.object(changed_paths, "changed_files") as diff:
                self.assert_groups(selector.classify(env)[0], GROUPS)
                diff.assert_not_called()

    def test_diff_failures(self):
        for result in (None, []):
            with self.subTest(result=result), patch.object(changed_paths, "changed_files", return_value=result):
                self.assert_groups(selector.classify(ENV)[0], GROUPS)
        for effect in (OSError("no git"), subprocess.CompletedProcess([], 1, b"", b"bad diff")):
            options = {"side_effect": effect} if isinstance(effect, OSError) else {"return_value": effect}
            with self.subTest(effect=effect), patch.object(changed_paths.subprocess, "run", **options), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assert_groups(selector.classify(ENV)[0], GROUPS)

    def test_diff_arguments_and_bytes(self):
        for push in (False, True):
            for deleted in (False, True):
                with self.subTest(push=push, deleted=deleted), patch.object(changed_paths.subprocess, "run",
                        return_value=subprocess.CompletedProcess([], 0, b"a\nname\0bad-\xff\0", b"")) as run:
                    self.assertEqual(changed_paths.changed_files("a", "b", push=push, deleted=deleted),
                                     ["a\nname", "bad-\udcff"])
                    self.assertEqual(run.call_args.args[0],
                                     ["git", "-c", "core.quotePath=false", "diff", "--name-only", "--no-renames", "-z",
                                      *(["--diff-filter=D"] if deleted else []),
                                      *(["a", "b"] if push else ["a...b"]), "--"])

    def test_diff_diagnostics(self):
        for effect, expected in (
                (OSError("no git"), "changed_paths: git did not start: no git\n"),
                (subprocess.CompletedProcess([], 2, b"", b"bad diff\n"),
                 "changed_paths: git diff exited 2: bad diff\n")):
            options = {"side_effect": effect} if isinstance(effect, OSError) else {"return_value": effect}
            output = io.StringIO()
            with self.subTest(effect=effect), patch.object(changed_paths.subprocess, "run", **options), \
                    contextlib.redirect_stderr(output):
                self.assertIsNone(changed_paths.changed_files("a", "b"))
            self.assertEqual(output.getvalue(), expected)

    def test_sha_forms(self):
        for length in (40, 64):
            with patch.object(changed_paths, "changed_files", return_value=["unrelated.txt"]):
                self.assertIsNotNone(changed_paths.collect(dict(ENV, BASE_SHA="a" * length, HEAD_SHA="b" * length))[0])
        push = {"EVENT_NAME": "push", "REF": "refs/heads/next", "BEFORE_SHA": "A" * 40,
                "AFTER_SHA": "B" * 40, "FORCED": "false"}
        with patch.object(changed_paths, "changed_files", return_value=["unrelated.txt"]):
            self.assertIsNotNone(changed_paths.collect(push)[0])

    def test_real_git(self):
        # Scratch histories live in TMPDIR, never in the repository being changed.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = dict(os.environ, GIT_AUTHOR_NAME="Fixture", GIT_COMMITTER_NAME="Fixture",
                       GIT_AUTHOR_EMAIL="fixture", GIT_COMMITTER_EMAIL="fixture",
                       GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")

            def git(*args):
                return subprocess.run(["git", "-C", str(root), *args], env=env, check=True,
                                      capture_output=True, text=True).stdout.strip()

            git("init", "--quiet", "--initial-branch=next")
            for path in ("old.txt", "guide.md", "gone.txt"):
                (root / path).write_text(path + "\n")
            git("add", "--all")
            git("commit", "--quiet", "-m", "base")
            base = git("rev-parse", "HEAD")
            for old, new, expected in (("old.txt", "old.txt", set()),
                                       ("old.txt", "new.md", {"scripts", "docs"}),
                                       ("guide.md", "new.txt", {"scripts", "docs"}),
                                       ("gone.txt", None, {"scripts"})):
                git("checkout", "--quiet", "--detach", base)
                if new == old:
                    (root / old).write_text("modified\n")
                elif new:
                    git("mv", old, new)
                else:
                    (root / old).unlink()
                git("add", "--all")
                git("commit", "--quiet", "-m", "head")
                head = git("rev-parse", "HEAD")
                for event in (dict(ENV, BASE_SHA=base, HEAD_SHA=head),
                              {"EVENT_NAME": "push", "REF": "refs/heads/next", "BEFORE_SHA": base,
                               "AFTER_SHA": head, "FORCED": "false"}):
                    result = subprocess.run([sys.executable, str(Path(selector.__file__).resolve())], cwd=root,
                                            env=dict(env, **event), capture_output=True, text=True, check=True)
                    self.assertEqual(result.stdout, "".join(f"selftest_{g}={'true' if g in expected else 'false'}\n"
                                                           for g in ("scripts", "rust", "docs", "preflight")))
            # Divergent endpoints distinguish a direct push diff from a merge-base diff.
            git("checkout", "--quiet", "--detach", base)
            (root / "crates").mkdir()
            (root / "crates/example.rs").write_text("source\n")
            git("add", "--all")
            git("commit", "--quiet", "-m", "before")
            before = git("rev-parse", "HEAD")
            git("checkout", "--quiet", "--detach", base)
            (root / "guide.md").write_text("edited\n")
            git("add", "--all")
            git("commit", "--quiet", "-m", "after")
            after = git("rev-parse", "HEAD")
            for event, expected in ((dict(ENV, BASE_SHA=before, HEAD_SHA=after), {"docs"}),
                                    ({"EVENT_NAME": "push", "REF": "refs/heads/next", "BEFORE_SHA": before,
                                      "AFTER_SHA": after, "FORCED": "false"}, {"scripts", "rust", "docs"})):
                result = subprocess.run([sys.executable, str(Path(selector.__file__).resolve())], cwd=root,
                                        env=dict(env, **event), capture_output=True, text=True, check=True)
                self.assertEqual(result.stdout, "".join(f"selftest_{g}={'true' if g in expected else 'false'}\n"
                                                       for g in ("scripts", "rust", "docs", "preflight")))


if __name__ == "__main__":
    unittest.main()
