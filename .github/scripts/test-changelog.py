#!/usr/bin/env python3
"""Exercise fragment modes with memory fixtures, Git histories, and mutation controls."""

import ast
from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("changelog.py")
VERSION = "1.2.3-alpha.4"
FIXTURE = """# Changelog

## [Unreleased]

## [1.2.3-alpha.4] - 2026-11-13

Release introduction.

### Added

- Existing addition.

### Fixed

### Security

- Existing security entry.

## [1.2.2] - 2026-11-01

### Changed

- Historical change.

[Unreleased]: keep-unreleased-link
[1.2.3-alpha.4]: keep-release-link
"""
BODIES = {
    "zeta-entry.added.md": "- Zeta item.\n",
    "new-deprecation.deprecated.md": "- Deprecated item.\n",
    "empty-fix.fixed.md": "- Fixed item.\n",
    "alpha-entry.added.md": "- Alpha item with `code` and café.\n  Continuation.\n  * Nested item.\n",
}
SUBCASES_RUN = 0


def subcase():
    global SUBCASES_RUN
    SUBCASES_RUN += 1


def scenarios(*values):
    for value in values:
        subcase()
        yield value


class History:
    """Keep real commit graphs in scratch repositories without working files."""

    def __init__(self):
        scratch = SCRIPT.resolve().parents[2] / "target" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="changelog-guard-", dir=scratch))
        self.git("init", "--bare", "--initial-branch=main")
        self.initial = self.commit(b"- Initial.\n")
        self.git("update-ref", "refs/remotes/origin/main", self.initial)

    def git(self, *args, data=None):
        env = dict(os.environ, GIT_AUTHOR_NAME="Fixture", GIT_COMMITTER_NAME="Fixture",
                   GIT_AUTHOR_EMAIL="fixture", GIT_COMMITTER_EMAIL="fixture")
        result = subprocess.run(["git", *args], cwd=self.root, input=data,
                                capture_output=True, env=env, check=True)
        return result.stdout.decode("ascii").strip()

    def commit(self, body, *parents, note=b"Note.\n", blob=None):
        blob = blob or self.git("hash-object", "-w", "--stdin", data=body)
        other = self.git("hash-object", "-w", "--stdin", data=note)
        tree = self.git("mktree", "--missing", data=(
            f"100644 blob {blob}\tCHANGELOG.md\n100644 blob {other}\tnote.md\n").encode())
        args = [arg for parent in parents for arg in ("-p", parent)]
        return self.git("commit-tree", tree, *args, data=b"Fixture commit.\n")

    def main(self, commit):
        self.git("update-ref", "refs/remotes/origin/main", commit)

    def assert_guard(self, mod, base, head, expected=0, refused=(), main_ref="refs/remotes/origin/main"):
        rc, out, err = cli(mod, ["guard", "--root", str(self.root), "--base", base,
                                 "--head", head, "--main-ref", main_ref])
        require(rc == expected, f"guard must return {expected}, receives {rc}: {err}")
        if expected == 0:
            require("integration guard passes" in err and not out, "guard must report a successful history check")
        else:
            require(bool(err), "guard must explain its refusal")
        for commit in refused:
            require(commit + ": CHANGELOG.md edit is refused." in err
                    and "remove edits from branch history" in err, "guard must name every refused commit and its remedy")


class MemoryPath:
    def __init__(self, fs, name=""):
        self.fs, self.relative = fs, name

    def __truediv__(self, name):
        return MemoryPath(self.fs, (self.relative + "/" + str(name)).lstrip("/"))

    @property
    def name(self):
        return self.relative.rsplit("/", 1)[-1]

    def iterdir(self):
        return [self / name for name in self.fs.entries]

    def is_symlink(self):
        return self.fs.kinds.get(self.name) == "symlink"

    def is_file(self):
        return self.fs.kinds.get(self.name, "file") == "file"

    def read_bytes(self):
        self.fs.reads.append(self.relative)
        value = self.fs.files[self.relative]
        if isinstance(value, Exception):
            raise value
        return value.encode("utf-8") if isinstance(value, str) else value

    def open(self, *args, **kwargs):
        fs, relative = self.fs, self.relative
        fs.writes.append(relative)

        class Writer(io.StringIO):
            def close(self):
                fs.files[relative] = self.getvalue()
                super().close()

        return Writer()

    def replace(self, destination):
        if self.fs.fail_replace:
            raise OSError("replacement refused")
        self.fs.files[destination.relative] = self.fs.files.pop(self.relative)

    def unlink(self):
        self.fs.unlinks.append(self.relative)
        del self.fs.files[self.relative]
        self.fs.entries.remove(self.name)


class Memory:
    def __init__(self, bodies=None, text=FIXTURE):
        bodies = BODIES if bodies is None else bodies
        self.files = {"CHANGELOG.md": text, "changelog.d/README.md": "Instructions"}
        self.files.update({"changelog.d/" + name: body for name, body in bodies.items()})
        self.entries = list(bodies) + ["README.md"]
        self.kinds, self.reads, self.writes, self.unlinks = {}, [], [], []
        self.fail_replace = False
        self.root = MemoryPath(self)

    @property
    def text(self):
        return self.files["CHANGELOG.md"]


def module(source):
    ast.parse(source)
    mod = types.ModuleType("changelog_under_test")
    mod.__file__ = str(SCRIPT)
    exec(compile(source, str(SCRIPT), "exec"), mod.__dict__)
    return mod


def require(value, message):
    assert value, message


def invalid(mod, call, diagnostic=""):
    try:
        call()
    except mod.Invalid as error:
        require(diagnostic in str(error), f"diagnostic lacks {diagnostic!r}: {error}")
    else:
        raise AssertionError("invalid content must return 1")


def cli(mod, args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            rc = mod.main(args)
        except SystemExit as error:
            rc = error.code
    return rc, out.getvalue(), err.getvalue()


def cases(mod):
    def c01():
        for name in scenarios(".added.md", "Upper.added.md", "under_score.fixed.md", "x.fixed.more.md", "x.fixed.markdown"):
            invalid(mod, lambda: mod.validate_fragment_name(name))

    def c02():
        invalid(mod, lambda: mod.validate_fragment_name("x.misc.md"), "category")

    def c03():
        for body in scenarios("", " \n\t\n"):
            invalid(mod, lambda: mod.validate_fragment_body(body), "empty")

    def c04():
        for body in scenarios("prose", "* Item", "+ Item", "2. Item", "# Heading", "```", "<!-- note -->", "\ufeff- Item"):
            invalid(mod, lambda: mod.validate_fragment_body("- Valid.\n" + body))

    def c05():
        for name, kind in scenarios(("notes.txt", "file"), (".hidden", "file"), ("README2.md", "file"),
                           ("nested", "directory"), ("linked.added.md", "symlink")):
            fs = Memory({name: "- Entry.\n"})
            fs.kinds[name] = kind
            invalid(mod, lambda: mod.load_fragments(fs.root))

    def c06():
        fs = Memory({})
        subcase()
        require(mod.check(fs.root) == 0, "README alone must pass")
        fs.entries.clear()
        subcase()
        invalid(mod, lambda: mod.load_fragments(fs.root), "README.md")
        subcase()
        invalid(mod, lambda: mod.check(fs.root), "README.md")

    def c07():
        for category in ("added", "changed", "deprecated", "removed", "fixed", "security"):
            for slug in scenarios("0day-fix", "x", "a-1-b"):
                require(mod.validate_fragment_name(f"{slug}.{category}.md") == category.title(), "valid name must pass")

    def c08():
        subcase()
        mod.validate_fragment_body("- First.\n\n  Continuation.\n  + Nested.\n  * Nested.\n  2. Nested.\n- Last.\n")
        subcase()
        invalid(mod, lambda: mod.validate_fragment_body("  Continuation.\n"))

    def c09():
        invalid(mod, lambda: mod.validate_fragment_body("  Opening.\n- Item.\n"), "line 1")

    def c10():
        invalid(mod, lambda: mod.validate_fragment_body("- \n"), "empty list item")

    def c11():
        subcase()
        fs = Memory()
        mod.check(fs.root)
        require("CHANGELOG.md" not in fs.reads and not fs.writes and not fs.unlinks, "check must only read fragments")
        operation = mod.check
        subcase()
        with patch.object(mod, "check", lambda root: operation(Memory({"bad.added.md": "Paragraph."}).root)):
            rc, _, err = cli(mod, ["check"])
        require(rc == 1 and "expected a '- ' list item" in err, "check must reject invalid fragments through main")

    def c12():
        for failure in scenarios(b"\xff", OSError("read refused")):
            fs = Memory({"broken.added.md": failure})
            operation = mod.check
            with patch.object(mod, "check", lambda root: operation(fs.root)):
                rc, _, err = cli(mod, ["check"])
            require(rc == 2 and "changelog.d/broken.added.md" in err, "read failure must return 2 with relative path")
        operation = mod.check
        subcase()
        with patch.object(MemoryPath, "iterdir", side_effect=OSError("listing refused")):
            with patch.object(mod, "check", lambda root: operation(Memory({}).root)):
                rc, _, err = cli(mod, ["check"])
            require(rc == 2 and "changelog.d/:" in err, "directory failure must return 2 with relative path")
        subcase()
        with patch.object(MemoryPath, "is_file", side_effect=OSError("inspection refused")):
            with patch.object(mod, "check", lambda root: operation(Memory({}).root)):
                rc, _, err = cli(mod, ["check"])
            require(rc == 2 and "changelog.d/README.md:" in err, "inspection failure must return 2 with relative path")

    def c13():
        fs = Memory({"line.added.md": "- CRLF.\r\n  More.\r- Final."})
        rendered = mod.fold_section("## [Unreleased]\n", mod.load_fragments(fs.root))
        require("- CRLF.\n  More.\n- Final.\n" in rendered and "\r" not in rendered, "fragment lines must normalize to LF")

    def c14():
        for separator in scenarios("\u2028", "\u0085", "\f", "\v"):
            body = "- Text" + separator + "### Fixes" + separator + "## [9.9.9]" + separator + "continues.\n"
            mod.validate_fragment_body(body)
            rendered = mod.fold_section("## [Unreleased]\n", mod.load_fragments(Memory({"text.added.md": body}).root))
            require(body in rendered, "non-LF separators must remain fragment text")
            lines, start, end = mod.section_bounds(rendered, "Unreleased")
            require("".join(lines[start:end]) == rendered and mod.fold_section(rendered, []) == rendered,
                    "non-LF separators must not create headings or section boundaries")
        subcase()
        invalid(mod, lambda: mod.validate_fragment_body("- Text\ncontinues.\n"))

    def p01():
        fs = Memory({"only.added.md": "- Preview.\n"})
        out = io.StringIO()
        with redirect_stdout(out):
            mod.preview(fs.root)
        require(out.getvalue().startswith("## [Unreleased]\n") and "- Preview.\n" in out.getvalue()
                and "## [1.2.3" not in out.getvalue(), "preview must end before the next release")

    def p02():
        fs = Memory()
        out = io.StringIO()
        with redirect_stdout(out):
            mod.preview(fs.root)
        require(bool(out.getvalue()), "preview must print content")
        require(not fs.writes and not fs.unlinks, "preview must not write or unlink")

    def p03():
        for text in scenarios(FIXTURE.replace("## [Unreleased]", "## [Upcoming]"), "## [Unreleased]\n" + FIXTURE):
            invalid(mod, lambda: mod.preview(Memory({}, text).root), "exactly one Unreleased")

    def r01():
        text = FIXTURE.replace("Release introduction.", "Release introduction.\n\n[local]: local-reference\n\nMore introduction.")
        fs = Memory({"incoming.added.md": "- Incoming.\n"}, text)
        mod.release(fs.root, VERSION)
        expected = text.replace("- Existing addition.\n", "- Existing addition.\n- Incoming.\n")
        require(fs.text == expected, "release must append and preserve unrelated bytes")

    def r02():
        fs = Memory()
        mod.release(fs.root, VERSION)
        require(fs.text.count("### Fixed\n") == 1 and "### Fixed\n\n- Fixed item." in fs.text,
                "empty Fixed category must receive one item under one heading")

    def r03():
        fs = Memory()
        mod.release(fs.root, VERSION)
        require(fs.text.index("### Added") < fs.text.index("### Deprecated") < fs.text.index("### Fixed"),
                "Deprecated must precede Fixed")

    def r04():
        fs = Memory()
        mod.release(fs.root, VERSION)
        require(fs.text.count("- Alpha item") == fs.text.count("- Zeta item") == 1, "both Added fragments must appear once")

    def r05():
        paths = [f.path.name for f in mod.load_fragments(Memory().root)]
        require(paths == sorted(BODIES), "loader must sort complete filenames ascending")

    def r06():
        bodies = {**BODIES, "security.security.md": "- Security item.\n"}
        fs = Memory(bodies)
        mod.release(fs.root, VERSION)
        require(set(fs.unlinks) == {"changelog.d/" + name for name in bodies}
                and fs.entries == ["README.md"], "release must consume every fragment and retain README")

    def r07():
        subcase()
        fs = Memory()
        mod.release(fs.root, VERSION)
        require(fs.text != FIXTURE and len(fs.writes) == 1, "first release must change content and write once")
        text, writes = fs.text, len(fs.writes)
        subcase()
        require(mod.release(fs.root, VERSION) == 0 and fs.text == text and len(fs.writes) == writes,
                "second release must leave bytes and writes unchanged")

    def r08():
        fs = Memory({"invalid.added.md": "Paragraph.\n"})
        invalid(mod, lambda: mod.release(fs.root, VERSION))
        require(not fs.writes and not fs.unlinks, "invalid fragment must abort before writes or unlinks")

    def r09():
        for text in scenarios(FIXTURE.replace(f"## [{VERSION}]", "## [3.0.0]"),
                     FIXTURE + f"\n## [{VERSION}]\n", FIXTURE.replace("### Fixed", "### Added\n\n### Fixed")):
            invalid(mod, lambda: mod.release(Memory({}, text).root, VERSION))
        historical = FIXTURE.replace("- Historical change.", "- Historical change.\n\n### Changed\n")
        subcase()
        require(mod.release(Memory({}, historical).root, VERSION) == 0, "older duplicate categories must be ignored")

    def r10():
        invalid(mod, lambda: mod.release(Memory().root, "1.2.2"), "first release")

    def r11():
        fs = Memory()
        fs.fail_replace = True
        operation = mod.release
        with patch.object(mod, "release", lambda root, version: operation(fs.root, version)):
            rc, _, err = cli(mod, ["release", "--version", VERSION])
        require(rc == 2 and "CHANGELOG.md: cannot replace content" in err and not fs.unlinks,
                "failed replacement must return 2 without consuming fragments")

    def r12():
        fs = Memory()
        mod.release(fs.root, VERSION)
        require(BODIES["alpha-entry.added.md"] in fs.text, "continuations and Unicode must survive exactly")

    def r13():
        body = "- Quoted headings.\n  ## [9.9.9]\n  ### Fixed\n"
        fs = Memory({"quoted.added.md": body})
        mod.release(fs.root, VERSION)
        lines, start, end = mod.section_bounds(fs.text, VERSION)
        rendered = mod.fold_section("".join(lines[start:end]), [])
        require(body in rendered and "- Existing security entry." in rendered,
                "indented headings must remain item text")

    def r14():
        fs = Memory({}, FIXTURE.replace("### Fixed", "### Fixes"))
        operation = mod.release
        with patch.object(mod, "release", lambda root, version: operation(fs.root, version)):
            rc, _, err = cli(mod, ["release", "--version", VERSION])
        require(rc == 1 and "unknown category heading" in err, "unknown target category must return 1")
        require(not fs.writes and not fs.unlinks, "unknown category must abort before writes")

    def r15():
        text = FIXTURE[:FIXTURE.index("## [1.2.2]")] + FIXTURE[FIXTURE.index("[Unreleased]:"):]
        fs = Memory({"last.security.md": "- Last security entry.\n"}, text.replace("### Security\n\n- Existing security entry.\n\n", ""))
        mod.release(fs.root, VERSION)
        require("### Security\n\n- Last security entry.\n\n[Unreleased]:" in fs.text,
                "missing category must precede comparison definitions")
        require(fs.text.endswith(text[text.index("[Unreleased]:"):]), "comparison definitions must remain unchanged")

    def r16():
        fs = Memory({"empty.fixed.md": "- Fixed item.\n"}, FIXTURE.replace("### Fixed\n\n### Security", "### Fixed\n### Security"))
        mod.release(fs.root, VERSION)
        require("### Fixed\n\n- Fixed item.\n\n### Security\n" in fs.text,
                "adjacent category headings must retain a blank separator after insertion")

    def g01():
        h = History()
        edit = h.commit(b"- Edit.\n", h.initial)
        h.assert_guard(mod, h.initial, edit, 1, [edit])

    def g02():
        h = History()
        edit = h.commit(b"- Edit.\n", h.initial)
        revert = h.commit(b"- Initial.\n", edit)
        h.assert_guard(mod, h.initial, revert, 1, [edit, revert])

    def g03():
        h = History()
        topic = h.commit(b"- Initial.\n", h.initial, note=b"Topic.\n")
        h.assert_guard(mod, h.initial, topic)

    def g04():
        h = History()
        topic = h.commit(b"- Initial.\n", h.initial, note=b"Topic.\n")
        main = h.commit(b"- Release.\n", h.initial)
        h.main(main)
        merge = h.commit(b"- Release.\n", topic, main, note=b"Topic.\n")
        subcase()
        h.assert_guard(mod, topic, merge)
        subcase()
        h.assert_guard(mod, topic, main)

    def g05():
        h = History()
        base = h.commit(b"- Integration.\n", h.initial)
        main = h.commit(b"- Release.\n", h.initial)
        h.main(main)
        merge = h.commit(b"- Release.\n", base, main)
        h.assert_guard(mod, base, merge)

    def g06():
        h = History()
        base = h.commit(b"- Integration.\n", h.initial)
        main = h.commit(b"- Release.\n", h.initial)
        h.main(main)
        merge = h.commit(b"- Release.\n- Own edit.\n", base, main)
        h.assert_guard(mod, base, merge, 1, [merge])

    def g07():
        h = History()
        base = h.commit(b"- Initial.\n", h.initial, note=b"Topic.\n")
        third = h.commit(b"- Third.\n", h.initial)
        merge = h.commit(b"- Third.\n", base, third)
        h.assert_guard(mod, base, merge, 1, [third, merge])

    def g08():
        h = History()
        base = h.commit(b"- Integration.\n", h.initial)
        side = h.commit(b"- Side.\n", h.initial)
        other = h.commit(b"- Release.\n", h.initial)
        main = h.commit(b"- Main.\n", side, other)
        h.main(main)
        merge = h.commit(b"- Release.\n", base, side, other)
        subcase()
        h.assert_guard(mod, base, merge)
        third = h.commit(b"- Third.\n", h.initial)
        mixed = h.commit(b"- Release.\n", base, other, third)
        subcase()
        h.assert_guard(mod, base, mixed, 1, [third, mixed])

    def g09():
        h = History()
        topic = h.commit(b"- Initial.\n", h.initial, note=b"Topic.\n")
        moved = h.commit(b"- Initial.\n", h.initial, note=b"Moved base.\n")
        subcase()
        h.assert_guard(mod, moved, topic)
        edit = h.commit(b"- Edit.\n", topic)
        subcase()
        h.assert_guard(mod, moved, edit, 1, [edit])

    def g10():
        h = History()
        h.assert_guard(mod, h.initial, h.initial, 2, main_ref="refs/remotes/origin/missing")

    def g11():
        h = History()
        for base, head in scenarios(("f" * 40, h.initial), (h.initial, "f" * 40)):
            h.assert_guard(mod, base, head, 2)

    def g12():
        h = History()
        base = h.commit(b"- Initial.\n", h.initial, note=b"Topic.\n")
        main = h.commit(b"- Release.\n", h.initial)
        h.main(main)
        merge = h.commit(b"", base, main, blob="f" * 40)
        h.assert_guard(mod, base, merge, 2)

    def g13():
        h = History()
        head = h.commit(b"- Initial.\n", h.initial, note=b"Topic.\n")
        h.git("update-ref", "refs/heads/main", head)
        shallow = h.root / "shallow-copy"
        h.git("clone", "--no-local", "--depth=1", str(h.root), str(shallow))
        h.root = shallow
        h.assert_guard(mod, head, head, 1)

    def a01():
        for mode in ("check", "preview", "release", "guard"):
            for extra in scenarios([], ["--root", "target/tmp/fixture"]):
                with patch.object(mod, mode, return_value=0) as operation:
                    options = (["--version", VERSION] if mode == "release" else
                               ["--base", "base", "--head", "head", "--main-ref", "main"] if mode == "guard" else [])
                    rc, _, _ = cli(mod, [mode] + extra + options)
                    expected = Path("target/tmp/fixture") if extra else SCRIPT.resolve().parents[2]
                    expected_args = (expected, VERSION) if mode == "release" else (expected, "base", "head", "main") if mode == "guard" else (expected,)
                    require(rc == 0 and operation.call_args.args == expected_args, "mode must dispatch the selected root and arguments")

    def a02():
        with patch.object(mod, "release", return_value=0):
            for args in scenarios([], ["unknown"], ["release"], ["check", "extra"], ["preview", "--version", VERSION], ["guard"]):
                require(cli(mod, args)[0] == 2, "invalid arguments must return 2")
            subcase()
            require(cli(mod, ["release", "--version", VERSION])[0] == 0, "valid arguments must dispatch successfully")

    def a03():
        fs = Memory({}, FIXTURE.replace(VERSION, "v1.2.3"))
        invalid(mod, lambda: mod.release(fs.root, "v1.2.3"), "version")
        require(not fs.writes, "invalid version must not write")

    return {name.upper(): function for name, function in locals().items() if len(name) == 3 and callable(function)}


MUTATIONS = {
    "C01": ('([a-z0-9-]+)', '([a-z0-9_-]+)'),
    "C02": ('|security)\\.md', '|security|misc)\\.md'),
    "C03": ('raise Invalid("line 1: empty fragment")', 'return'),
    "C04": ('enumerate(text.split("\\n"), 1)', 'enumerate(text.split("\\n")[:1], 1)'),
    "C05": ('if path.name == "README.md":', 'if path.name == "README.md" or path.name.endswith(".txt"):'),
    "C06": ('if not any(path.name == "README.md" for path in entries):', 'if False:'),
    "C07": ('([a-z0-9-]+)', '([a-z][a-z0-9-]*)'),
    "C08": ('if not line.strip():\n            continue',
            'if not line.strip():\n            if number < len(text.split("\\n")):\n                raise Invalid("blank line")\n            continue'),
    "C09": ('if not seen:', 'if False:'),
    "C10": ('if not line[2:].strip():', 'if False:'),
    "C11": ('def check(root):', 'def check(root):\n    read_changelog(root)'),
    "C12": ('raise OSError(f"changelog.d/{path.name}: cannot read UTF-8 content")',
            'raise Invalid(f"changelog.d/{path.name}: cannot read UTF-8 content")'),
    "C13": ('body = body.replace("\\r\\n", "\\n").replace("\\r", "\\n")', 'body = body'),
    "C14": ('enumerate(text.split("\\n"), 1)', 'enumerate(text.splitlines(), 1)'),
    "P01": ('print(rendered, end="", file=sys.stdout)', 'print(rendered + "".join(lines[end:end + 1]), end="", file=sys.stdout)'),
    "P02": ('print(rendered, end="", file=sys.stdout)', 'replace_changelog(root, rendered)\n    print(rendered, end="", file=sys.stdout)'),
    "P03": ('if len(starts) != 1:', 'if label == "Unreleased":\n        starts = starts[:1]\n    if len(starts) != 1:'),
    "R01": ('insertion = end\n', 'insertion = start + 1\n'),
    "R02": ('lines[insertion:insertion] = ["\\n"]', 'continue'),
    "R03": ('insertion = min(later, default=len(lines))', 'insertion = len(lines)'),
    "R04": ('payload = lf_lines("".join(incoming))', 'payload = lf_lines("".join(incoming[:1]))'),
    "R05": ('key=lambda path: path.name)', 'key=lambda path: path.name, reverse=True)'),
    "R06": ('fragment.path.unlink()', 'fragment.path.unlink() if fragment.category != "Security" else None'),
    "R07": ('if not fragments:\n        return 0', 'if not fragments:\n        replace_changelog(root, text)\n        return 0'),
    "R08": ('    fragments = load_fragments(root)\n    text = read_changelog(root)',
            '    if any(p.name != "README.md" for p in (root / "changelog.d").iterdir()):\n'
            '        replace_changelog(root, read_changelog(root))\n    fragments = load_fragments(root)\n    text = read_changelog(root)'),
    "R09": ('if category in positions:\n                raise Invalid', 'if False:\n                raise Invalid'),
    "R10": ('if start != un_end or unreleased >= start:', 'if False:'),
    "R11": ('    replace_changelog(root, updated)\n    for fragment in fragments:\n'
            '        try:\n            fragment.path.unlink()\n        except OSError as error:\n'
            '            raise OSError(f"changelog.d/{fragment.path.name}: cannot consume fragment") from error\n',
            '    for fragment in fragments:\n'
            '        try:\n            fragment.path.unlink()\n        except OSError as error:\n'
            '            raise OSError(f"changelog.d/{fragment.path.name}: cannot consume fragment") from error\n'
            '    replace_changelog(root, updated)\n'),
    "R12": ('payload = lf_lines("".join(incoming))',
            'payload = lf_lines("".join(incoming).encode("ascii", "ignore").decode())'),
    "R13": ('if lines[i].startswith("## [")', 'if lines[i].lstrip().startswith("## [")'),
    "R14": ('raise Invalid("CHANGELOG.md: unknown category heading")', 'pass'),
    "R15": ('or i == definitions', ''),
    "R16": ('if following < len(lines) and lines[following].startswith("### "):', 'if False:'),
    "A01": ('root = args.root', 'root = Path(__file__).resolve().parents[2]'),
    "A02": ('sub.add_argument("--version", required=True)', 'sub.add_argument("--version", default="1.2.3")'),
    "A03": ('r"[0-9]+\\.[0-9]+', 'r"v?[0-9]+\\.[0-9]+'),
}

CONSTANT_SUBJECTS = {
    "validate_fragment_name": ["C01", "C02", "C07"],
    "validate_fragment_body": ["C03", "C04", "C08", "C09", "C10", "C14"],
    "load_fragments": ["C05", "C06", "C13", "R05"],
    "check": ["C06", "C11", "C12"],
    "preview": ["P01", "P02", "P03"],
    "release": [f"R{i:02}" for i in range(1, 17) if i != 5] + ["A03"],
    "fold_section": ["C13", "C14", "R13"],
    "section_bounds": ["C14", "R13"],
    "main": ["A01", "A02"],
    "guard": [f"G{i:02}" for i in range(1, 14)],
}


def run(mod, selected=None):
    global SUBCASES_RUN
    SUBCASES_RUN = 0
    failures = {}
    for name, function in cases(mod).items():
        if selected and selected != name:
            continue
        try:
            before = SUBCASES_RUN
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                function()
        except Exception as error:
            failures[name] = str(error)
        finally:
            if SUBCASES_RUN == before:
                SUBCASES_RUN += 1
    return failures


def main(argv):
    source = SCRIPT.read_text()
    selected = None
    all_cases = cases(module(source))
    if argv[:1] == ["--case"] and len(argv) == 2 and argv[1] in all_cases:
        selected = argv[1]
    elif argv not in ([], ["--mutations"], ["--constants"]):
        return 2
    failures = run(module(source), selected)
    for name, error in failures.items():
        print(f"FAIL {name}: {error}")
    if failures:
        return 1
    print(f"{1 if selected else len(all_cases)} fragment cases pass; {SUBCASES_RUN} executed subcases")
    if argv == ["--constants"]:
        covered = set()
        count = 0
        for subject, labels in CONSTANT_SUBJECTS.items():
            for value in (None, 0, 1, 2):
                mod = module(source)
                with patch.object(mod, subject, lambda *args, **kwargs: value):
                    for label in labels:
                        actual = run(mod, label)
                        require(label in actual, f"{label}: constant {subject}={value!r} must fail")
                        print(f"{label}: constant {subject}={value!r} fails: {actual[label]}")
                        covered.add(label)
                        count += 1
        require(covered == set(all_cases), "constant controls must cover every case")
        print(f"{count} constant controls fail; {len(covered)} cases covered")
    if argv == ["--mutations"]:
        for name, (old, new) in MUTATIONS.items():
            require(source.count(old) == 1, f"{name}: mutation target count differs")
            mutated = source.replace(old, new)
            actual = run(module(mutated))
            expected = {"C04": {"C04", "C14"}, "C09": {"C08", "C09"},
                        "R02": {"R02", "R16"}, "R08": {"R07", "R08"},
                        "R12": {"C14", "R12"},
                        "A01": {"A01", "G13", *(f"G{i:02}" for i in range(1, 10))}}.get(name, {name})
            require(set(actual) == expected, f"{name}: actual failing IDs {actual}")
            require(not run(module(source)), f"{name}: restored control fails")
            print(f"{name}: parses; failures {sorted(actual)}: {actual[name]}; restored {len(all_cases)}/{len(all_cases)}")
        print(f"{len(MUTATIONS)} parsing mutants match exact failures; {len(MUTATIONS)} restored controls pass")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
