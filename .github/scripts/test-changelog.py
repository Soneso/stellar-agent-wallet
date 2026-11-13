#!/usr/bin/env python3
"""Exercise fragment modes with in-memory files and isolated semantic mutations."""

import ast
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import sys
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
        for name in (".added.md", "Upper.added.md", "under_score.fixed.md", "x.fixed.more.md", "x.fixed.markdown"):
            invalid(mod, lambda: mod.validate_fragment_name(name))

    def c02():
        invalid(mod, lambda: mod.validate_fragment_name("x.misc.md"), "category")

    def c03():
        for body in ("", " \n\t\n"):
            invalid(mod, lambda: mod.validate_fragment_body(body), "empty")

    def c04():
        for body in ("prose", "* Item", "+ Item", "2. Item", "# Heading", "```", "<!-- note -->", "\ufeff- Item"):
            invalid(mod, lambda: mod.validate_fragment_body("- Valid.\n" + body))

    def c05():
        for name, kind in (("notes.txt", "file"), (".hidden", "file"), ("README2.md", "file"),
                           ("nested", "directory"), ("linked.added.md", "symlink")):
            fs = Memory({name: "- Entry.\n"})
            fs.kinds[name] = kind
            invalid(mod, lambda: mod.load_fragments(fs.root))

    def c06():
        fs = Memory({})
        require(mod.check(fs.root) == 0, "README alone must pass")
        fs.entries.clear()
        invalid(mod, lambda: mod.load_fragments(fs.root), "README.md")

    def c07():
        for category in ("added", "changed", "deprecated", "removed", "fixed", "security"):
            for slug in ("0day-fix", "x", "a-1-b"):
                require(mod.validate_fragment_name(f"{slug}.{category}.md") == category.title(), "valid name must pass")

    def c08():
        mod.validate_fragment_body("- First.\n\n  Continuation.\n  + Nested.\n  * Nested.\n  2. Nested.\n- Last.\n")

    def c09():
        invalid(mod, lambda: mod.validate_fragment_body("  Opening.\n- Item.\n"), "line 1")

    def c10():
        invalid(mod, lambda: mod.validate_fragment_body("- \n"), "empty list item")

    def c11():
        fs = Memory()
        mod.check(fs.root)
        require("CHANGELOG.md" not in fs.reads and not fs.writes and not fs.unlinks, "check must only read fragments")

    def c12():
        for failure in (b"\xff", OSError("read refused")):
            fs = Memory({"broken.added.md": failure})
            operation = mod.check
            with patch.object(mod, "check", lambda root: operation(fs.root)):
                rc, _, err = cli(mod, ["check"])
            require(rc == 2 and "changelog.d/broken.added.md" in err, "read failure must return 2 with relative path")
        operation = mod.check
        with patch.object(MemoryPath, "iterdir", side_effect=OSError("listing refused")):
            with patch.object(mod, "check", lambda root: operation(Memory({}).root)):
                rc, _, err = cli(mod, ["check"])
            require(rc == 2 and "changelog.d/:" in err, "directory failure must return 2 with relative path")
        with patch.object(MemoryPath, "is_file", side_effect=OSError("inspection refused")):
            with patch.object(mod, "check", lambda root: operation(Memory({}).root)):
                rc, _, err = cli(mod, ["check"])
            require(rc == 2 and "changelog.d/README.md:" in err, "inspection failure must return 2 with relative path")

    def c13():
        fs = Memory({"line.added.md": "- CRLF.\r\n  More.\r- Final."})
        rendered = mod.fold_section("## [Unreleased]\n", mod.load_fragments(fs.root))
        require("- CRLF.\n  More.\n- Final.\n" in rendered and "\r" not in rendered, "fragment lines must normalize to LF")

    def p01():
        fs = Memory({"only.added.md": "- Preview.\n"})
        out = io.StringIO()
        with redirect_stdout(out):
            mod.preview(fs.root)
        require(out.getvalue().startswith("## [Unreleased]\n") and "- Preview.\n" in out.getvalue()
                and "## [1.2.3" not in out.getvalue(), "preview must end before the next release")

    def p02():
        fs = Memory()
        mod.preview(fs.root)
        require(not fs.writes and not fs.unlinks, "preview must not write or unlink")

    def p03():
        for text in (FIXTURE.replace("## [Unreleased]", "## [Upcoming]"), "## [Unreleased]\n" + FIXTURE):
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
        fs = Memory()
        mod.release(fs.root, VERSION)
        text, writes = fs.text, len(fs.writes)
        require(mod.release(fs.root, VERSION) == 0 and fs.text == text and len(fs.writes) == writes,
                "second release must leave bytes and writes unchanged")

    def r08():
        fs = Memory({"invalid.added.md": "Paragraph.\n"})
        invalid(mod, lambda: mod.release(fs.root, VERSION))
        require(not fs.writes and not fs.unlinks, "invalid fragment must abort before writes or unlinks")

    def r09():
        for text in (FIXTURE.replace(f"## [{VERSION}]", "## [3.0.0]"),
                     FIXTURE + f"\n## [{VERSION}]\n", FIXTURE.replace("### Fixed", "### Added\n\n### Fixed")):
            invalid(mod, lambda: mod.release(Memory({}, text).root, VERSION))
        historical = FIXTURE.replace("- Historical change.", "- Historical change.\n\n### Changed\n")
        require(mod.release(Memory({}, historical).root, VERSION) == 0, "older duplicate categories must be ignored")

    def r10():
        invalid(mod, lambda: mod.release(Memory().root, "1.2.2"), "first release")

    def r11():
        fs = Memory()
        fs.fail_replace = True
        operation = mod.release
        with patch.object(mod, "release", lambda root, version: operation(fs.root, version)):
            rc, _, _ = cli(mod, ["release", "--version", VERSION])
        require(rc == 2 and not fs.unlinks, "failed replacement must return 2 without consuming fragments")

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

    def a01():
        for mode in ("check", "preview", "release"):
            for extra in ([], ["--root", "target/tmp/fixture"]):
                with patch.object(mod, mode, return_value=0) as operation:
                    rc, _, _ = cli(mod, [mode] + extra + (["--version", VERSION] if mode == "release" else []))
                    expected = Path("target/tmp/fixture") if extra else SCRIPT.resolve().parents[2]
                    require(rc == 0 and operation.call_args.args[0] == expected, "mode must dispatch the selected root")

    def a02():
        with patch.object(mod, "release", return_value=0):
            for args in ([], ["unknown"], ["release"], ["check", "extra"], ["preview", "--version", VERSION]):
                require(cli(mod, args)[0] == 2, "invalid arguments must return 2")

    def a03():
        fs = Memory({}, FIXTURE.replace(VERSION, "v1.2.3"))
        invalid(mod, lambda: mod.release(fs.root, "v1.2.3"), "version")
        require(not fs.writes, "invalid version must not write")

    return {name.upper(): function for name, function in locals().items() if len(name) == 3 and callable(function)}


MUTATIONS = {
    "C01": ('([a-z0-9-]+)', '([a-z0-9_-]+)'),
    "C02": ('|security)\\.md', '|security|misc)\\.md'),
    "C03": ('raise Invalid("line 1: empty fragment")', 'return'),
    "C04": ('enumerate(text.splitlines(), 1)', 'enumerate(text.splitlines()[:1], 1)'),
    "C05": ('if path.name == "README.md":', 'if path.name == "README.md" or path.name.endswith(".txt"):'),
    "C06": ('if not any(path.name == "README.md" for path in entries):', 'if False:'),
    "C07": ('([a-z0-9-]+)', '([a-z][a-z0-9-]*)'),
    "C08": ('if not line.strip():\n            continue', 'if not line.strip():\n            raise Invalid("blank line")'),
    "C09": ('if not seen:', 'if False:'),
    "C10": ('if not line[2:].strip():', 'if False:'),
    "C11": ('def check(root):', 'def check(root):\n    read_changelog(root)'),
    "C12": ('raise OSError(f"changelog.d/{path.name}: cannot read UTF-8 content")',
            'raise Invalid(f"changelog.d/{path.name}: cannot read UTF-8 content")'),
    "C13": ('body = body.replace("\\r\\n", "\\n").replace("\\r", "\\n")', 'body = body'),
    "P01": ('print(rendered, end="", file=sys.stdout)', 'print(rendered + "".join(lines[end:end + 1]), end="", file=sys.stdout)'),
    "P02": ('print(rendered, end="", file=sys.stdout)', 'replace_changelog(root, rendered)\n    print(rendered, end="", file=sys.stdout)'),
    "P03": ('if len(starts) != 1:', 'if label == "Unreleased":\n        starts = starts[:1]\n    if len(starts) != 1:'),
    "R01": ('insertion = end\n', 'insertion = start + 1\n'),
    "R02": ('lines[insertion:insertion] = ["\\n"]', 'continue'),
    "R03": ('insertion = min(later, default=len(lines))', 'insertion = len(lines)'),
    "R04": ('payload = "".join(incoming)', 'payload = "".join(incoming[:1])'),
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
    "R12": ('payload = "".join(incoming).splitlines(keepends=True)',
            'payload = "".join(incoming).encode("ascii", "ignore").decode().splitlines(keepends=True)'),
    "R13": ('if lines[i].startswith("## [")', 'if lines[i].lstrip().startswith("## [")'),
    "A01": ('root = args.root', 'root = Path(__file__).resolve().parents[2]'),
    "A02": ('sub.add_argument("--version", required=True)', 'sub.add_argument("--version", default="1.2.3")'),
    "A03": ('r"[0-9]+\\.[0-9]+', 'r"v?[0-9]+\\.[0-9]+'),
}

SUBCASES = {name: 1 for name in MUTATIONS}
SUBCASES.update(C01=5, C03=2, C04=8, C05=5, C06=2, C07=18, C12=4, P03=2, R09=4, A01=6, A02=5)


def run(mod, selected=None):
    failures = {}
    for name, function in cases(mod).items():
        if selected and selected != name:
            continue
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                function()
        except Exception as error:
            failures[name] = str(error)
    return failures


def main(argv):
    source = SCRIPT.read_text()
    selected = None
    if argv[:1] == ["--case"] and len(argv) == 2 and argv[1] in MUTATIONS:
        selected = argv[1]
    elif argv not in ([], ["--mutations"]):
        return 2
    failures = run(module(source), selected)
    for name, error in failures.items():
        print(f"FAIL {name}: {error}")
    if failures:
        return 1
    count = SUBCASES[selected] if selected else sum(SUBCASES.values())
    print(f"{1 if selected else len(MUTATIONS)} fragment cases pass; {count} subcases")
    if argv == ["--mutations"]:
        for name, (old, new) in MUTATIONS.items():
            require(source.count(old) == 1, f"{name}: mutation target count differs")
            mutated = source.replace(old, new)
            actual = run(module(mutated))
            require(set(actual) == {name}, f"{name}: actual failing IDs {actual}")
            require(not run(module(source)), f"{name}: restored control fails")
            print(f"{name}: parses; fails only {name}: {actual[name]}; restored 32/32")
        print("32 parsing mutants pass isolation; 32 restored controls pass")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
