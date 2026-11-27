#!/usr/bin/env python3
"""Exercise fragment modes with memory fixtures, Git histories, and mutation controls."""

import ast
from contextlib import redirect_stderr, redirect_stdout
import io
import multiprocessing
import os
from pathlib import Path
import re
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
UNMERGED_REMEDY = "CHANGELOG.md differs from the clean three-way merge; a maintainer resolves and merges it."
FRAGMENT_REMEDY = "Move entries to new fragments and remove edits from branch history."


def subcase():
    global SUBCASES_RUN
    SUBCASES_RUN += 1


def scenarios(*values):
    for value in values:
        subcase()
        yield value


class History:
    """Keep real commit graphs in scratch repositories without working files."""

    def __init__(self, body=b"- Initial.\n"):
        scratch = SCRIPT.resolve().parents[2] / "target" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="changelog-guard-", dir=scratch))
        self.git("init", "--bare", "--initial-branch=main")
        self.initial = self.commit(body)
        self.git("update-ref", "refs/remotes/origin/main", self.initial)

    def git(self, *args, data=None):
        env = dict(os.environ, GIT_AUTHOR_NAME="Fixture", GIT_COMMITTER_NAME="Fixture",
                   GIT_AUTHOR_EMAIL="fixture", GIT_COMMITTER_EMAIL="fixture")
        result = subprocess.run(["git", *args], cwd=self.root, input=data,
                                capture_output=True, env=env, check=True)
        return result.stdout.decode("ascii").strip()

    def commit(self, body, *parents, note=b"Note.\n", blob=None, mode="100644", path="CHANGELOG.md", extra=""):
        blob = blob or self.git("hash-object", "-w", "--stdin", data=body)
        other = self.git("hash-object", "-w", "--stdin", data=note)
        tree = self.git("mktree", "--missing", data=(
            f"{mode} blob {blob}\t{path}\n100644 blob {other}\tnote.md\n{extra}").encode())
        args = [arg for parent in parents for arg in ("-p", parent)]
        return self.git("commit-tree", tree, *args, data=b"Fixture commit.\n")

    def main(self, commit):
        self.git("update-ref", "refs/remotes/origin/main", commit)

    def fragments(self, entries):
        rows = []
        for path, value in entries.items():
            mode, body = value if isinstance(value, tuple) else ("100644", value)
            oid = self.git("hash-object", "-w", "--stdin", data=body)
            rows.append(f"{mode} blob {oid}\t{path}\n")
        tree = self.git("mktree", data="".join(rows).encode())
        return f"040000 tree {tree}\tchangelog.d\n"

    def fragment_commit(self, entries, *parents):
        return self.commit(b"- Initial.\n", *parents, extra=self.fragments(entries))

    def assert_guard(self, mod, base, head, expected=0, refused=(), main_ref="refs/remotes/origin/main", merged=()):
        try:
            rc, out, err = cli(mod, ["guard", "--root", str(self.root), "--base", base,
                                     "--head", head, "--main-ref", main_ref])
        except Exception as error:
            raise AssertionError(f"guard must report status {expected}; it raises {error!r}") from error
        require(rc == expected, f"guard must return {expected}, receives {rc}: {err}")
        if expected == 0:
            require("integration guard passes" in err and not out, "guard must report a successful history check")
        else:
            require(bool(err), "guard must explain its refusal")
        for commit in refused:
            require(commit + ": CHANGELOG.md edit is refused." in err
                    and "remove edits from branch history" in err, "guard must name every refused commit and its remedy")
        # A sync merge that differs from the clean merge names the maintainer remedy.
        for commit in merged:
            require(commit + ": CHANGELOG.md edit is refused. " + UNMERGED_REMEDY in err,
                    "guard must name every refused merge and the maintainer remedy")
        return err


MERGE_BASE = b"- First.\n\n### Middle\n\n- Middle.\n\n### Last\n\n- Last.\n"
MERGE_OURS = MERGE_BASE.replace(b"- First.", b"- First.\n- Integration.")
MERGE_THEIRS = MERGE_BASE.replace(b"- Last.", b"- Last.\n- Main.")
MERGE_BOTH = MERGE_OURS.replace(b"- Last.", b"- Last.\n- Main.")


def sync_history():
    h = History(MERGE_BASE)
    base = h.commit(MERGE_OURS, h.initial)
    main = h.commit(MERGE_THEIRS, h.initial)
    h.main(main)
    return h, base, main


def document_texts():
    for path in scenarios("CONTRIBUTING.md", "changelog.d/README.md", "docs/maintainers/releasing.md"):
        text = (SCRIPT.resolve().parents[2] / path).read_text()
        yield " ".join(text.split())


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
    exec(compile(source, str(SCRIPT), "exec", dont_inherit=True), mod.__dict__)
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
        h, base, main = sync_history()
        merge = h.commit(MERGE_BOTH, base, main)
        before = {p.relative_to(h.root): p.read_bytes() for p in h.root.rglob("*") if p.is_file()}
        h.assert_guard(mod, base, merge)
        after = {p.relative_to(h.root): p.read_bytes() for p in h.root.rglob("*") if p.is_file()}
        require(before == after, "guard must leave all repository files and objects unchanged")

    def g06():
        h, base, main = sync_history()
        merge = h.commit(MERGE_BOTH + b"- Own edit.\n", base, main)
        h.assert_guard(mod, base, merge, 1, merged=[merge])

    def g07():
        h = History()
        base = h.commit(b"- Initial.\n", h.initial, note=b"Topic.\n")
        third = h.commit(b"- Third.\n", h.initial)
        merge = h.commit(b"- Third.\n", base, third)
        h.assert_guard(mod, base, merge, 1, [third, merge])

    def g08():
        h = History()
        base = h.commit(b"- Initial.\n", h.initial, note=b"Topic.\n")
        side = h.commit(b"- Side.\n", h.initial)
        other = h.commit(b"- Release.\n", h.initial)
        main = h.commit(b"- Main.\n", side, other)
        h.main(main)
        merge = h.commit(b"- Side.\n", base, side, other)
        subcase()
        h.assert_guard(mod, base, merge, 1, [merge])
        fourth = h.commit(b"- Fourth.\n", main)
        h.main(fourth)
        octopus = h.commit(b"- Side.\n", base, side, other, fourth)
        subcase()
        h.assert_guard(mod, base, octopus, 1, [octopus])
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

    def g14():
        h, base, main = sync_history()
        merge = h.commit(MERGE_THEIRS, base, main)
        h.assert_guard(mod, base, merge, 1, merged=[merge])

    def g15():
        h = History()
        older = h.commit(b"- Older.\n", h.initial)
        main = h.commit(b"- Main.\n", older)
        base = h.commit(b"- Integration.\n", main)
        h.main(main)
        for parent, body in scenarios((older, b"- Older.\n"), (h.initial, b"- Initial.\n")):
            merge = h.commit(body, base, parent)
            with patch.object(mod, "clean_changelog_merge", wraps=mod.clean_changelog_merge) as clean:
                h.assert_guard(mod, base, merge, 1, [merge])
                require(not clean.called, "already-contained parents must be refused before content merging")

    def g16():
        h = History()
        base = h.commit(b"- Integration.\n", h.initial)
        main = h.commit(b"- Main.\n", h.initial)
        h.main(main)
        for body in scenarios(b"- Main.\n", b"- Hand resolution.\n", b"- Integration.\n"):
            merge = h.commit(body, base, main)
            err = h.assert_guard(mod, base, merge, 1, [merge])
            require("a maintainer resolves and merges it" in err,
                    "conflict refusal must say a maintainer resolves and merges it")

    def g17():
        h = History(MERGE_BASE)
        base = h.commit(MERGE_OURS, h.initial)
        main = h.commit(MERGE_BASE, h.initial, note=b"Main work.\n")
        h.main(main)
        merge = h.commit(MERGE_OURS, base, main)
        h.assert_guard(mod, base, merge)

    def g18():
        h, base, main = sync_history()
        merge = h.commit(MERGE_OURS, base, main)
        h.assert_guard(mod, base, merge, 1, merged=[merge])

    def g19():
        for mode, path, body in scenarios(("100644", "OLD.md", MERGE_BOTH),
                                          ("120000", "CHANGELOG.md", b"note.md"),
                                          ("100755", "CHANGELOG.md", MERGE_BOTH)):
            h, base, main = sync_history()
            for parents in scenarios((base,), (base, main)):
                edit = h.commit(body, *parents, mode=mode, path=path)
                h.assert_guard(mod, base, edit, 1, [edit])

    def g20():
        h, base, main = sync_history()
        merge = h.commit(MERGE_BOTH, base, main)
        real = mod.git
        for command, output, expected in scenarios(
                (("rev-parse", "--is-shallow-repository"), b"unknown\n", 1),
                (("rev-parse", "--verify"), b"nonsense\n", 2),
                (("rev-list", "--topo-order"), b"nonsense\n", 2),
                (("rev-list", "--parents"), b"\n", 2),
                (("diff-tree", "-r"), b"OTHER.md\n", 2),
                (("merge-base", "--is-ancestor"), b"true\n", 2),
                (("ls-tree", "-z"), b"unexpected\n", 1)):
            def unexpected(root, *args, **kwargs):
                result = real(root, *args, **kwargs)
                if args[:2] == command:
                    result.stdout = output
                return result
            with patch.object(mod, "git", unexpected):
                h.assert_guard(mod, base, merge, expected)

    def g21():
        h, base, main = sync_history()
        left = h.commit(MERGE_BOTH, base, main)
        right = h.commit(MERGE_BOTH, main, base, note=b"Other merge.\n")
        h.main(right)
        merge = h.commit(MERGE_BOTH + b"- Edit.\n", left, right)
        err = h.assert_guard(mod, left, merge, 1, [merge])
        require("ambiguous merge bases" in err, "multiple merge bases must fail closed")

    def g22():
        h = History()

        def fragments(names):
            entries = []
            for name in names:
                blob = h.git("hash-object", "-w", "--stdin", data=("- " + name + ".\n").encode())
                entries.append(f"100644 blob {blob}\t{name}.fixed.md\n")
            if not entries:
                return ""
            tree = h.git("mktree", data="".join(entries).encode())
            return f"040000 tree {tree}\tchangelog.d\n"

        shared = h.commit(b"- Initial.\n", h.initial, extra=fragments(["released"]))
        base = h.commit(b"- Initial.\n", shared, extra=fragments(["pending", "released"]))
        main = h.commit(b"- Released.\n", shared)
        h.main(main)
        tree = h.git("merge-tree", "--write-tree", base, main)
        paths = h.git("ls-tree", "-r", "--name-only", tree).splitlines()
        require("changelog.d/released.fixed.md" not in paths,
                "sync merge must delete the unchanged folded fragment")
        require("changelog.d/pending.fixed.md" in paths,
                "sync merge must preserve the new unreleased fragment")
        merge = h.commit(b"- Released.\n", base, main, extra=fragments(["pending"]))
        h.assert_guard(mod, base, merge)

    def g23():
        h = History()
        result = subprocess.run([sys.executable, "-", "guard", "--base", h.initial,
                                 "--head", h.initial, "--main-ref", "refs/remotes/origin/main"],
                                input=SCRIPT.read_bytes(), cwd=h.root, capture_output=True)
        require(result.returncode == 0 and b"integration guard passes" in result.stderr,
                "the piped base script must use the current repository without changing arguments")

    def g24():
        for body in scenarios(MERGE_BOTH + b"- Own edit.\n", MERGE_THEIRS, MERGE_OURS):
            h, base, main = sync_history()
            merge = h.commit(body, base, main)
            err = h.assert_guard(mod, base, merge, 1, merged=[merge])
            require(err.splitlines() == [f"{merge}: CHANGELOG.md edit is refused. {UNMERGED_REMEDY}"],
                    "a differing sync merge must name only the maintainer remedy")
            require("fragment" not in err and "branch history" not in err,
                    "a differing sync merge must not print the fragment remedy")
        h = History()
        edit = h.commit(b"- Edit.\n", h.initial)
        subcase()
        err = h.assert_guard(mod, h.initial, edit, 1, [edit])
        require(err.splitlines() == [f"{edit}: CHANGELOG.md edit is refused. use a two-parent sync merge "
                                     f"that preserves the clean merge result. {FRAGMENT_REMEDY}"],
                "a direct edit must keep its refusal text")
        base = h.commit(b"- Integration.\n", h.initial)
        main = h.commit(b"- Main.\n", h.initial)
        h.main(main)
        merge = h.commit(b"- Main.\n", base, main)
        subcase()
        err = h.assert_guard(mod, base, merge, 1, [merge])
        require(err.splitlines() == [f"{merge}: CHANGELOG.md edit is refused. CHANGELOG.md conflicts; "
                                     f"a maintainer resolves and merges it. {FRAGMENT_REMEDY}"],
                "a conflicting merge must keep its refusal text")

    def fragment_history():
        h = History()
        entries = {"old.fixed.md": b"- Original.\n", "README.md": b"Rules.\n"}
        base = h.fragment_commit(entries, h.initial)
        h.main(base)
        return h, entries, base

    def assert_fragment(h, base, head, path, message):
        err = h.assert_guard(mod, base, head, 1)
        require(f"{head}: changelog.d/{path}: {message}" in err,
                "guard must name the refused fragment and reason: " + err)

    def g25():
        for value in scenarios(b"- Edited.\n", None, ("100755", b"- Original.\n"), ("120000", b"target")):
            h, entries, base = fragment_history()
            changed = entries | {"old.fixed.md": value}
            if value is None:
                del changed["old.fixed.md"]
            edit = h.fragment_commit(changed, base)
            assert_fragment(h, base, edit, "old.fixed.md", "protected path changes outside a sync merge")

    def g26():
        for value in scenarios(b"Edited rules.\n", None, ("100755", b"Rules.\n"), ("120000", b"target")):
            h, entries, base = fragment_history()
            changed = entries | {"README.md": value}
            if value is None:
                del changed["README.md"]
            edit = h.fragment_commit(changed, base)
            assert_fragment(h, base, edit, "README.md", "protected path changes outside a sync merge")
        h = History()
        edit = h.fragment_commit({"README.md": b"New rules.\n"}, h.initial)
        assert_fragment(h, h.initial, edit, "README.md", "protected path changes outside a sync merge")

    def g27():
        h, entries, base = fragment_history()
        edit = h.fragment_commit(entries | {"old.fixed.md": b"- Edited.\n"}, base)
        revert = h.fragment_commit(entries, edit)
        err = h.assert_guard(mod, base, revert, 1)
        require("changelog.d/old.fixed.md: protected path changes" in err, "edit and revert must fail")

    def g28():
        h, entries, base = fragment_history()
        added = h.fragment_commit(entries | {"new.fixed.md": b"- New.\n"}, base)
        edited = h.fragment_commit(entries | {"new.fixed.md": b"- Revised.\n"}, added)
        h.assert_guard(mod, base, edited)
        redundant = h.fragment_commit(entries | {"new.fixed.md": b"- Revised in merge.\n"}, added, base)
        subcase()
        h.assert_guard(mod, base, redundant)

    def g29():
        h, entries, base = fragment_history()
        ours = entries | {"pending.fixed.md": b"- Pending.\n"}
        left = h.fragment_commit(ours, base)
        theirs = {"README.md": entries["README.md"]}
        right = h.fragment_commit(theirs, base)
        h.main(right)
        merge = h.fragment_commit(theirs | {"pending.fixed.md": ours["pending.fixed.md"]}, left, right)
        h.assert_guard(mod, left, merge)

    def g30():
        h, entries, base = fragment_history()
        right = h.commit(b"- Initial.\n", base, note=b"Main.\n", extra=h.fragments(entries))
        h.main(right)
        merge = h.fragment_commit({"README.md": entries["README.md"]}, base, right)
        assert_fragment(h, base, merge, "old.fixed.md", "only an unchanged fragment deleted on the incoming branch may be dropped")

    def g31():
        h, entries, base = fragment_history()
        left = h.fragment_commit(entries | {"old.fixed.md": b"- Next edit.\n"}, base)
        right = h.fragment_commit({"README.md": entries["README.md"]}, base)
        h.main(right)
        merge = h.fragment_commit({"README.md": entries["README.md"]}, left, right)
        assert_fragment(h, left, merge, "old.fixed.md", "only an unchanged fragment deleted on the incoming branch may be dropped")

    def g32():
        h, entries, base = fragment_history()
        right = h.fragment_commit({"README.md": entries["README.md"]}, base)
        h.main(right)
        merge = h.fragment_commit(entries, base, right)
        assert_fragment(h, base, merge, "old.fixed.md", "fragment differs from the clean three-way merge")

    def g33():
        h, entries, base = fragment_history()
        right = h.commit(b"- Initial.\n", base, note=b"Main.\n", extra=h.fragments(entries))
        h.main(right)
        for changed in scenarios(entries | {"old.fixed.md": b"- Smuggled.\n"},
                                 entries | {"smuggled.fixed.md": b"- Smuggled.\n"}):
            merge = h.fragment_commit(changed, base, right)
            path = "smuggled.fixed.md" if "smuggled.fixed.md" in changed else "old.fixed.md"
            assert_fragment(h, base, merge, path, "fragment differs from the clean three-way merge")

    def g34():
        for incoming in ("main", "next"):
            for left_body, right_body, result_body in scenarios(
                    (MERGE_OURS, MERGE_THEIRS, MERGE_BOTH),
                    (MERGE_OURS, MERGE_OURS, MERGE_OURS),
                    (MERGE_OURS, MERGE_THEIRS, MERGE_THEIRS),
                    (MERGE_OURS, MERGE_BASE, MERGE_OURS),
                    (None, MERGE_BASE, MERGE_BASE),
                    (None, None, None),
                    (MERGE_BASE, None, None),
                    (MERGE_BASE, None, MERGE_BASE),
                    (MERGE_BASE, MERGE_THEIRS, None),
                    (MERGE_BASE, MERGE_THEIRS, b"Smuggled.\n")):
                h, entries, base = fragment_history()
                original = h.fragment_commit(entries | {"README.md": MERGE_BASE}, base)
                trees = [{"old.fixed.md": entries["old.fixed.md"]}
                         | ({"README.md": body} if body is not None else {})
                         for body in (left_body, right_body, result_body)]
                left = h.commit(b"- Initial.\n", original, note=b"First parent.\n", extra=h.fragments(trees[0]))
                right = h.fragment_commit(trees[1], original)
                h.main(right if incoming == "main" else left)
                merge = h.fragment_commit(trees[2], left, right)
                assert_fragment(h, left if incoming == "main" else right, merge, "README.md",
                                "README.md must remain present and cleanly propagate the incoming version")

    def g35():
        h, entries, base = fragment_history()
        theirs = entries | {"README.md": b"Main rules.\n"}
        right = h.fragment_commit(theirs, base)
        h.main(right)
        merge = h.fragment_commit(theirs, base, right)
        h.assert_guard(mod, base, merge)

    def g36():
        h, entries, base = fragment_history()
        theirs = entries | {"imported.fixed.md": b"- Main bytes.\n"}
        right = h.fragment_commit(theirs, base)
        h.main(right)
        merge = h.fragment_commit(theirs | {"imported.fixed.md": b"- Altered bytes.\n"}, base, right)
        assert_fragment(h, base, merge, "imported.fixed.md", "fragment differs from the clean three-way merge")

    def g37():
        h, entries, base = fragment_history()
        theirs = entries | {"imported.fixed.md": b"- Main bytes.\n"}
        right = h.fragment_commit(theirs, base)
        h.main(right)
        merge = h.fragment_commit(theirs, base, right)
        h.assert_guard(mod, base, merge)
        edit = h.fragment_commit(theirs | {"imported.fixed.md": b"- Later edit.\n"}, merge)
        assert_fragment(h, base, edit, "imported.fixed.md", "protected path changes outside a sync merge")

    def g38():
        h, entries, base = fragment_history()
        side = h.commit(b"- Initial.\n", base, note=b"Side.\n", extra=h.fragments(entries))
        merge = h.fragment_commit({"README.md": entries["README.md"]}, base, side)
        assert_fragment(h, base, merge, "old.fixed.md", "protected path changes outside a sync merge")

    def g39():
        # The changed next fragment predates the PR; only its sync merge is guarded.
        for actual, expected in scenarios((MERGE_BOTH, 0), (MERGE_OURS, 1),
                                          (("100755", MERGE_BOTH), 1)):
            h = History()
            base = h.fragment_commit({"entry.fixed.md": MERGE_BASE}, h.initial)
            left = h.fragment_commit({"entry.fixed.md": MERGE_OURS}, base)
            right = h.fragment_commit({"entry.fixed.md": MERGE_THEIRS}, base)
            h.main(right)
            merge = h.fragment_commit({"entry.fixed.md": actual}, left, right)
            h.assert_guard(mod, left, merge, expected)
        h = History()
        base = h.fragment_commit({"entry.fixed.md": MERGE_BASE}, h.initial)
        left = h.fragment_commit({"entry.fixed.md": MERGE_OURS}, base)
        right = h.fragment_commit({"entry.fixed.md": ("120000", MERGE_THEIRS)}, base)
        h.main(right)
        merge = h.fragment_commit({"entry.fixed.md": MERGE_BOTH}, left, right)
        subcase()
        err = h.assert_guard(mod, left, merge, 1)
        require("fragment merge conflicts" in err, "a type change must fail even when text merges cleanly")
        for theirs in scenarios(b"- Conflict.\n", None, ("120000", b"target")):
            h, entries, base = fragment_history()
            left_entries = entries | {"old.fixed.md": b"- Next.\n"}
            left = h.fragment_commit(left_entries, base)
            right_entries = entries | {"old.fixed.md": theirs}
            if theirs is None:
                del right_entries["old.fixed.md"]
            right = h.fragment_commit(right_entries, base)
            h.main(right)
            merge = h.fragment_commit(left_entries, left, right)
            err = h.assert_guard(mod, left, merge, 1)
            require(f"{merge}: changelog.d/old.fixed.md: fragment merge conflicts" in err,
                    "conflicting fragment merge must name the decoded path")

    def g40():
        # A base-only addition does not protect a fragment created on this PR.
        h, entries, common = fragment_history()
        base = h.fragment_commit(entries | {"own.fixed.md": b"- Base.\n"}, common)
        added = h.fragment_commit(entries | {"own.fixed.md": b"- Own.\n"}, common)
        edited = h.fragment_commit(entries | {"own.fixed.md": b"- Revised.\n"}, added)
        h.assert_guard(mod, base, edited)

    def g41():
        h = History()
        base = h.fragment_commit({"entry.fixed.md": MERGE_BASE}, h.initial)
        left = h.fragment_commit({"entry.fixed.md": MERGE_OURS}, base)
        right = h.fragment_commit({"entry.fixed.md": MERGE_THEIRS}, base)
        h.main(right)
        merge = h.fragment_commit({"entry.fixed.md": MERGE_BOTH}, left, right)
        fragment = h.git("rev-parse", f"{left}:changelog.d/entry.fixed.md")
        real = mod.git
        def warning(root, *args, **kwargs):
            result = real(root, *args, **kwargs)
            if "merge-file" in args and args[-3] == fragment:
                result.stderr = b"unexpected merge warning"
            return result
        with patch.object(mod, "git", warning):
            err = h.assert_guard(mod, left, merge, 2)
            require("unexpected merge output" in err, "fragment merge warnings must report a tool failure")

    def g42():
        h, entries, base = fragment_history()
        added = {"new.fixed.md": b"- New from another root.\n"}
        side = h.commit(b"Other root.\n", path="other.md", extra=h.fragments(added))
        merge = h.fragment_commit(entries | added, base, side)
        h.assert_guard(mod, base, merge)

    def g43():
        h, entries, base = fragment_history()
        right = h.fragment_commit(entries | {"README.md": b"Main rules.\n"}, base)
        h.main(right)
        merge = h.fragment_commit(entries, base, right)
        assert_fragment(h, base, merge, "README.md",
                        "README.md must remain present and cleanly propagate the incoming version")

    def g44():
        for kind in scenarios("fragment", "README", "deleted", "altered", "kept", "compiled"):
            h, entries, common = fragment_history()
            own = entries | {"own.fixed.md": b"- Own.\n"}
            left = h.fragment_commit(own, common)
            incoming = entries | {"next.fixed.md": b"- Next.\n"}
            if kind == "README":
                incoming["README.md"] = b"Next rules.\n"
            if kind in ("deleted", "kept"):
                del incoming["old.fixed.md"]
            body = b"- Next compiled.\n" if kind == "compiled" else b"- Initial.\n"
            right = h.commit(body, common, extra=h.fragments(incoming))
            # The incoming parent may be older than the current base.
            base = h.commit(body, right, note=b"Next tip.\n", extra=h.fragments(incoming))
            actual = incoming | {"own.fixed.md": own["own.fixed.md"]}
            if kind == "altered":
                actual["next.fixed.md"] = b"- Altered.\n"
            if kind == "kept":
                actual["old.fixed.md"] = entries["old.fixed.md"]
            merge = h.commit(body, left, right, extra=h.fragments(actual))
            if kind in ("altered", "kept"):
                path = "next.fixed.md" if kind == "altered" else "old.fixed.md"
                assert_fragment(h, base, merge, path, "fragment differs from the clean three-way merge")
            else:
                h.assert_guard(mod, base, merge)

    def g45():
        for diamond in scenarios(False, True):
            h, entries, base = fragment_history()
            added = entries | {"imported.fixed.md": b"- Own.\n"}
            left = h.fragment_commit(added, base)
            revised = entries | {"imported.fixed.md": b"- Shared.\n"}
            edit = h.fragment_commit(revised, left)
            right = h.fragment_commit(revised, base)
            h.main(right)
            if diamond:
                sync = h.fragment_commit(revised, base, right)
                head = h.fragment_commit(revised, sync, edit)
                real = mod.git
                def sibling_order(root, *args, **kwargs):
                    result = real(root, *args, **kwargs)
                    if args[0] == "rev-list" and f"{base}..{head}" in args:
                        result.stdout = ("\n".join((sync, left, edit, head)) + "\n").encode()
                    return result
                with patch.object(mod, "git", sibling_order):
                    h.assert_guard(mod, base, head)
            else:
                head = h.fragment_commit(revised, edit, right)
            h.assert_guard(mod, base, head)
            later = h.fragment_commit(added, head)
            assert_fragment(h, base, later, "imported.fixed.md", "protected path changes outside a sync merge")

    def g46():
        h, entries, base = fragment_history()
        head = h.fragment_commit(entries | {"own.fixed.md": b"- Own.\n"}, base)
        real = mod.git
        def truncated(root, *args, **kwargs):
            result = real(root, *args, **kwargs)
            if args[:3] == ("ls-tree", "-r", "-z"):
                result.stdout = result.stdout[:-1]
            return result
        with patch.object(mod, "git", truncated):
            err = h.assert_guard(mod, base, head, 2)
            require("unterminated fragment tree" in err, "truncated ls-tree output must fail as a tool error")

    def g47():
        h, entries, common = fragment_history()
        left = h.fragment_commit(entries | {"own.fixed.md": b"- Own.\n"}, common)
        right = h.fragment_commit(entries | {"next.fixed.md": b"- Next.\n"}, common)
        merge = h.fragment_commit(entries | {"own.fixed.md": b"- Own.\n", "next.fixed.md": b"- Next.\n"}, left, right)
        real = mod.git
        def ambiguous(root, *args, **kwargs):
            result = real(root, *args, **kwargs)
            if args == ("merge-base", "--all", left, right):
                result.stdout += (common + "\n").encode()
            return result
        with patch.object(mod, "git", ambiguous):
            err = h.assert_guard(mod, right, merge, 1)
            require("ambiguous merge bases" in err, "base updates need a unique merge base")

    def d01():
        for path in scenarios("CONTRIBUTING.md", "changelog.d/README.md"):
            text = (SCRIPT.resolve().parents[2] / path).read_text()
            require("Lowercase it and replace every character outside `a-z`, `0-9`, and `-` with `-`." in text,
                    "slug instructions must match the accepted character grammar")
            require("`fix/Login_v2.1` becomes `fix-login-v2-1`" in text,
                    "slug instructions must include the normalized mixed-character example")
        slug = re.sub("[^a-z0-9-]", "-", "fix/Login_v2.1".lower())
        require(mod.validate_fragment_name(slug + ".fixed.md") == "Fixed", "documented slug must validate")

    def d02():
        for text in document_texts():
            require("Never edit an existing fragment. Add a new file for a further entry." in text,
                    "fragment instructions must forbid edits and require a new file")
            require("Each fragment file belongs to one pull request and is never reused." in text,
                    "fragment instructions must prohibit reuse between pull requests")

    def d03():
        for text in document_texts():
            require("A sync merge deletes fragments that `main` folds and deletes." in text,
                    "fragment instructions must explain folded fragment deletion")
            require("It never deletes a fragment that holds an unreleased entry under this rule." in text,
                    "fragment instructions must preserve unreleased entries")

    def d04():
        for text in document_texts():
            require("exactly two parents" in text and "preserving both sides' lines" in text,
                    "sync instructions must preserve both sides in a two-parent merge")
            require("a maintainer resolves and merges them" in text and "never accepts hand-resolved" in text,
                    "sync instructions must assign conflicts to a maintainer")

    def d05():
        text = " ".join((SCRIPT.resolve().parents[2] / "docs/maintainers/releasing.md").read_text().split())
        require("Only release preparation pull requests to `main` change the compiled changelog; reviewers enforce this policy on `main`." in text,
                "release instructions must state the review policy for main pull requests")

    def d06():
        text = (SCRIPT.resolve().parents[2] / "CONTRIBUTING.md").read_text()
        section = text.split("## Changelog entries\n", 1)[1].split("\n## ", 1)[0]
        require(all(len(line) <= 80 for line in section.splitlines()),
                "contributor changelog instructions must wrap within 80 columns")

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
    "G25": ('if left != result and (path in current or path == b"changelog.d/README.md"):', 'if False:'),
    "G26": ('or path == b"changelog.d/README.md"', ''),
    "G30": ('elif left is not None and result is None and not (', 'elif False and ('),
    "G32": ('if result != expected:', 'if False:'),
    "G34": ('elif path == b"changelog.d/README.md" and (', 'elif False and ('),
    "G37": ('current.update(theirs.keys() - original.keys())', 'current.update(())'),
    "G39": ('if result[0] != b"100644" or git(', 'if False and git('),
    "G39-conflict": ('                    if merged.returncode:', '                    if False:'),
    "G39-type": ('if any(value is None or value[0] != b"100644" for value in (left, ancestor_value, right)):', 'if False:'),
    "G41": ('                    if merged.stderr:', '                    if False:'),
    "G44": ('update = (len(parents) == 2 and ancestor(root, parents[1], base)', 'update = (False and ancestor(root, parents[1], base)'),
    "G44-compiled": ('allowed = (len(parents) == 2 and (ancestor(root, parents[1], main) or ancestor(root, parents[1], base))',
                     'allowed = (len(parents) == 2 and ancestor(root, parents[1], main)'),
    "G45": ('"--topo-order", "--reverse",', ''),
    "G45-inheritance": ('current = protected.union(*(inherited.get(parent, set()) for parent in parents))', 'current = protected.copy()'),
    "G45-siblings": ('current = protected.union(*(inherited.get(parent, set()) for parent in parents))', 'current = protected'),
    "G46": ('if entries and not entries.endswith(b"\\0"):', 'if False:'),
    "G47": ('if (len(parents) != 2 or not (ancestor(root, parents[1], main) or ancestor(root, parents[1], base))',
            'if (len(parents) != 2 or not ancestor(root, parents[1], main)'),
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
    "G24": ('refused.append(f"{commit}: CHANGELOG.md edit is refused. {error}.")',
            'refused.append(f"{commit}: CHANGELOG.md edit is refused. {error}. '
            'Move entries to new fragments and remove edits from branch history.")'),
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
    "guard": [f"G{i:02}" for i in range(1, 23)] + [f"G{i:02}" for i in range(24, 48)],
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


def check_mutation(task):
    source, name, old, new = task
    require(source.count(old) == 1, f"{name}: mutation target count differs")
    mutated = source.replace(old, new)
    actual = run(module(mutated))
    expected = {"C04": {"C04", "C14"}, "C09": {"C08", "C09"},
                "G25": {"G25", "G26", "G27", "G37", "G38", "G45"},
                "G30": {"G30", "G31"},
                "G32": {"G32", "G33", "G36", "G44"},
                "G34": {"G34", "G43"},
                "G37": {"G37", "G45"},
                "G39-conflict": {"G39"}, "G39-type": {"G39"},
                "G44": {"G34", "G44"},
                "G44-compiled": {"G34", "G44", "G47"}, "G45-siblings": {"G45"},
                "G45": {"G20", "G37", "G45"}, "G45-inheritance": {"G37", "G45"},
                "R02": {"R02", "R16"}, "R08": {"R07", "R08"},
                "R12": {"C14", "R12"},
                "A01": {"A01", "G13", *(f"G{i:02}" for i in range(1, 10)),
                        *(f"G{i:02}" for i in range(14, 23)), *(f"G{i:02}" for i in range(24, 48))}}.get(name, {name})
    require(set(actual) == expected, f"{name}: actual failing IDs {actual}")
    require(not run(module(source)), f"{name}: restored control fails")
    count = len(cases(module(source)))
    return f"{name}: parses; failures {sorted(actual)}: {next(iter(actual.values()))}; restored {count}/{count}"


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
        require(covered == {name for name in all_cases if name not in {"G23"} and not name.startswith("D")},
                "constant controls must cover every in-process utility case")
        print(f"{count} constant controls fail; {len(covered)} cases covered")
    if argv == ["--mutations"]:
        tasks = [(source, name, old, new) for name, (old, new) in MUTATIONS.items()]
        with multiprocessing.get_context("spawn").Pool(processes=4) as pool:
            for result in pool.imap(check_mutation, tasks):
                print(result, flush=True)
        print(f"{len(MUTATIONS)} parsing mutants match exact failures; {len(MUTATIONS)} restored controls pass")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
