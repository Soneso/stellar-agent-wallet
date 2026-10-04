#!/usr/bin/env python3
"""Exercise the docs checker against scratch copies of tracked Markdown.

Usage: test-check-docs-style.py [ROOT]

Each rule case checks every diagnostic line, hit count, and allowance.
Passing cases cover code, links, spelling, exclusions, and baseline allowances.
Scratch repositories use the system temp directory and are removed on exit.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    print(
        "test-check-docs-style.py needs Python 3.11 or later; "
        f"this is Python {sys.version.split()[0]}",
        file=sys.stderr,
    )
    sys.exit(2)

import importlib.util
import json
import pathlib
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Callable

HERE = pathlib.Path(__file__).resolve().parent
CHECK = HERE / "check-docs-style.py"
PROBE = "docs/style-probe.md"
BASELINE = pathlib.Path(".github/scripts/docs-style-baseline.json")


def load_check():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("check_docs_style", CHECK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(tree: pathlib.Path, path: str | pathlib.Path, text: str, tracked: bool = True) -> None:
    target = tree / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    if tracked:
        subprocess.run(["git", "add", "--", str(path)], cwd=tree, check=True, capture_output=True)


def allowance(tree: pathlib.Path, path: str, counts: dict[str, int]) -> None:
    baseline = json.loads((tree / BASELINE).read_text(encoding="utf-8"))
    baseline[path] = counts
    write(tree, BASELINE, json.dumps(baseline))


@dataclass
class Case:
    name: str
    mutate: Callable[[pathlib.Path], None]
    code: int = 0
    rule: str | None = None
    path: str = PROBE
    line: int = 3
    args: tuple[str, ...] = ()
    error: str | None = None
    hits: int = 1
    allowed: int = 0
    lines: tuple[int, ...] = ()


def cases() -> list[Case]:
    samples = [
        ("em-dash", "em dash", "Read\u2014write."),
        ("en-dash", "joined en dash", "Read\u2013write."),
        ("en-dash", "spaced en dash", "Read \u2013 write."),
        ("en-dash", "wrapped en dash", "Read \u2013\nwrite."),
        ("curly-quotes", "left single quote", "\u2018Read."),
        ("curly-quotes", "right single quote", "Reader\u2019s guide."),
        ("curly-quotes", "left double quote", "\u201cRead."),
        ("curly-quotes", "right double quote", "Read.\u201d"),
        ("curly-quotes", "low quote", "\u201eRead."),
        ("filler", "lowercase filler", "A comprehensive guide."),
        ("filler", "uppercase filler", "A COMPREHENSIVE guide."),
        ("emoji", "face emoji", "Read \U0001f600."),
        ("emoji", "symbol emoji", "Read \u2705."),
        ("emoji", "keycap emoji", "Read 1\ufe0f\u20e3."),
        ("emoji", "flag emoji", "Read \U0001f1fa\U0001f1f8."),
        ("emoji", "joined emoji", "Read \U0001f469\U0001f3fd\u200d\U0001f4bb."),
        ("emoji", "skin-tone emoji", "Read \U0001f44d\U0001f3fd."),
        ("emoji", "variation emoji", "Read \u00a9\ufe0f."),
        ("british-initialis", "initialization stem", "Initialise the client."),
        ("british-initialis", "prefixed initialization stem", "Reinitialisation finishes."),
        ("british-serialis", "serialization stem", "Serialise the value."),
        ("british-serialis", "prefixed serialization stem", "Deserialisation finishes."),
        ("british-recognis", "recognition stem", "Recognition is unrecognisable."),
        ("british-authoris", "authorization stem", "Authorization is unauthorised."),
        ("british-behaviour", "behavior stem", "A behavioural rule."),
        ("british-licence", "license noun", "A licence applies."),
        ("british-licence", "plural license noun", "Two LICENCES apply."),
    ]
    result = [Case("passing tree", lambda tree: None)]
    for rule, name, text in samples:
        result.append(Case(
            name, lambda tree, text=text: write(tree, PROBE, "# Probe\n\n" + text + "\n"),
            1, rule,
        ))

    poison = "Read\u2014write \u2013 prose \u2018 comprehensive \U0001f600 initialise serialise recognise authorise behaviour licence"
    accepted = [
        ("backtick fence", f"```text\n{poison}\n```\n"),
        ("tilde fence", f"~~~text\n{poison}\n~~~\n"),
        ("long fence with shorter inner fence", f"````\n```\n{poison}\n````\n"),
        ("unclosed fence", f"```\n{poison}\n"),
        ("indented list fence", f"- ```\n  {poison}\n  ```\n"),
        ("numbered list fence", f"1. ~~~\n   {poison}\n   ~~~\n"),
        ("blockquote fence", f"> ```\n> {poison}\n> ```\n"),
        ("inline span", f"Read `{poison}` now.\n"),
        ("long inline span", f"Read ``{poison} ` value`` now.\n"),
        ("multiline inline span", f"Read `value\n{poison}` now.\n"),
        ("triple inline span", f"```{poison}```\n"),
        ("escaped backtick inside span", f"Read `{poison}\\` now.\n"),
        ("even backslashes before span", f"Read \\\\`{poison}` now.\n"),
        ("American spelling and word boundaries",
         "Initialize and reinitialize. Serialize and deserialize. Recognize and authorize.\n"
         "Behavior and behavioral rules. A license, licensed code, and licensing terms.\n"
         "A licencee and a comprehensively indexed guide.\n"),
        ("numeric ranges and text symbols", "Read pages 1\u20133 and 1 \u2013 3. Use A-Z, x \u2192 y, \u00a9, and \u2122.\n"),
        ("initialism and serialism", "An initialism, two initialisms, and serialism.\n"),
        ("autolink license path", "Read <https://example.com/licence>.\n"),
        ("autolink en dash path", "Read <https://example.com/read\u2013write>.\n"),
        ("link license destination", "Read [terms](https://example.com/licence).\n"),
        ("link en dash destination", "Read [guide](docs/read\u2013write.md).\n"),
        ("nested link destination", "Read [guide](docs/(licence)/read\u2013write.md).\n"),
        ("escaped link destination", "Read [guide](docs/part\\)/licence).\n"),
        ("reference definition license destination", "[terms]: docs/licence.md\n"),
        ("indented definition with a title", "   [guide]: docs/read\u2013write.md \"read\u2013write\"\n"),
        ("angle definition destination", "[guide]: <docs/read\u2013write.md> 'licence'\n"),
        ("angle URL definition with a title", "[terms]: <https://e.test/a> \"a licence\"\n"),
        ("backticks in a definition destination", "[terms]: docs/`part`/licence\n"),
        ("bare URL en dash path", "Read https://example.com/read\u2013write now.\n"),
        ("balanced parentheses in a plain URL", "See https://example.com/a(b)/licence today.\n"),
        ("scheme path without angle brackets", "Read ftp://example.com/licence.\n"),
        ("uppercase scheme path", "Read HTTPS://example.com/licence.\n"),
        ("link destination with a URL and parentheses", "Read [guide](https://example.com/a(b)/licence).\n"),
    ]
    for name, text in accepted:
        result.append(Case(name, lambda tree, text=text: write(tree, PROBE, text)))

    outside = [
        ("prose after closed fence", "```\nvalue\n```\nRead\u2014write.\n", 4),
        ("prose after closed tilde fence", "~~~\nvalue\n~~~\nRead\u2014write.\n", 4),
        ("prose beside inline span", "Read `value` then\u2014write.\n", 1),
        ("unmatched backtick", "Read `value\u2014write.\n", 1),
        ("escaped opening backtick", "Read \\`value\u2014write`.\n", 1),
        ("unequal inline delimiters", "Read ``value\u2014write`.\n", 1),
        ("span stops at paragraph", "Read `value\n\nRead\u2014write`.\n", 3),
        ("span stops at heading", "Read `value\n## Heading\nRead\u2014write`.\n", 3),
        ("fence info with backtick", "```value` Read\u2014write.\n", 1),
    ]
    for name, text, line in outside:
        result.append(Case(name, lambda tree, text=text: write(tree, PROBE, text), 1, "em-dash", line=line))

    for rule, name, text in [
        ("british-licence", "license prose beside link", "A licence applies beside [terms](https://example.com/licence).\n"),
        ("en-dash", "en dash prose beside link", "Read\u2013write beside [guide](docs/read\u2013write.md).\n"),
        ("british-licence", "license link label", "Read [licence](https://example.com/licence).\n"),
        ("british-licence", "license prose beside autolink", "A licence applies beside <https://example.com/licence>.\n"),
        ("british-licence", "unclosed link destination", "Read [terms](licence.\n"),
        ("british-licence", "reference definition license label", "[licence]: docs/licence.md\n"),
        ("british-licence", "bare URL license prose", "A licence applies beside https://example.com/licence.\n"),
        ("british-licence", "prose after an angle URL definition", "[terms]: <https://e.test/a> licence\n"),
        ("british-licence", "prose after a code span in a definition", "[terms]: `code` licence\n"),
        ("british-licence", "tab before a definition", "\t[terms]: docs/licence\n"),
        ("british-licence", "four spaces before a definition", "    [terms]: docs/licence\n"),
        ("british-licence", "opening angle inside a destination", "[terms]: docs/<licence\n"),
        ("british-licence", "closing angle inside a destination", "[terms]: docs/licence>\n"),
        ("british-licence", "angle pair inside a destination", "[terms]: docs/<licence>\n"),
        ("british-licence", "nonbreaking space after a plain URL", "https://e.test/a\u00a0licence\n"),
        ("british-licence", "definition-like prose", "[word]: this licence applies.\n"),
        ("curly-quotes", "curly quote after a plain URL", "See https://example.com/path\u201d now.\n"),
        ("em-dash", "unmatched parenthesis after a plain URL", "(see https://example.com/path)\u2014 now.\n"),
    ]:
        result.append(Case(name, lambda tree, text=text: write(tree, PROBE, text), 1, rule, line=1))
    result.append(Case(
        "prose line after a definition",
        lambda tree: write(tree, PROBE, "[terms]: https://example.com/path\nA licence applies.\n"),
        1, "british-licence", line=2,
    ))

    for stem in ("initialis", "serialis"):
        text = "\n".join(stem + suffix for suffix in ("e", "es", "ed", "ing", "ation", "ations", "er", "ers"))
        result.append(Case(
            f"{stem} inflections", lambda tree, text=text: write(tree, PROBE, text + "\n"),
            1, f"british-{stem}", hits=8, lines=tuple(range(1, 9)),
        ))

    for path in ("CHANGELOG.md", "crates/sample/vendor/nested/probe.md"):
        result.append(Case(f"excluded {path}", lambda tree, path=path: write(tree, path, poison)))
        result.append(Case(
            f"explicit excluded {path}", lambda tree, path=path: write(tree, path, poison),
            2, args=(path,), error="not a scanned path",
        ))
    for path in ("docs/space name.md", "crates/sample/tests/fixtures/probe.md", "docs/CHANGELOG.md", "docs/vendor/probe.md"):
        result.append(Case(
            f"scanned {path}", lambda tree, path=path: write(tree, path, "Read\u2014write.\n"),
            1, "em-dash", path=path, line=1,
        ))
    result.append(Case("untracked file skipped", lambda tree: write(tree, PROBE, poison, tracked=False)))
    result.append(Case(
        "explicit untracked file", lambda tree: write(tree, PROBE, "Read\u2014write.\n", tracked=False),
        1, "em-dash", line=1, args=(PROBE,),
    ))
    result.append(Case("explicit clean file", lambda tree: write(tree, PROBE, "Read.\n", tracked=False), args=(PROBE,)))
    result.append(Case("missing explicit file", lambda tree: None, 2, args=(PROBE,), error="check-docs-style:"))
    result.append(Case(
        "explicit file outside root", lambda tree: (tree.parent / "outside.md").write_text("Read.\n", encoding="utf-8"),
        2, args=("../outside.md",), error="check-docs-style:",
    ))
    result.append(Case(
        "explicit non-Markdown file", lambda tree: write(tree, "docs/probe.txt", poison),
        2, args=("docs/probe.txt",), error="not a scanned path",
    ))
    result.append(Case("tracked non-Markdown file skipped", lambda tree: write(tree, "docs/probe.txt", poison)))

    for rule, _, text in samples:
        if any(case.name == f"{rule} exceeds allowance" for case in result):
            continue

        def baselined(tree: pathlib.Path, rule=rule, text=text, copies=2, limit=1):
            write(tree, PROBE, "# Probe\n\n" + (text + "\n") * copies)
            allowance(tree, PROBE, {rule: limit})

        result.extend([
            Case(f"{rule} exceeds allowance", baselined, 1, rule, hits=2, allowed=1, lines=(3, 4)),
            Case(f"{rule} equals allowance", lambda tree, edit=baselined: edit(tree, copies=1)),
            Case(f"{rule} below allowance", lambda tree, edit=baselined: edit(tree, copies=1, limit=2)),
        ])

    result.append(Case(
        "multiple hits on one line", lambda tree: write(tree, PROBE, "Read\u2014write\u2014save.\n"),
        1, "em-dash", line=1, hits=2,
    ))
    result.append(Case(
        "hits on separated lines", lambda tree: write(tree, PROBE, "Read\u2014write.\n\nRead\u2014save.\n\nRead\u2014close.\n"),
        1, "em-dash", hits=3, lines=(1, 3, 5),
    ))

    def different_rule(tree: pathlib.Path):
        write(tree, PROBE, "# Probe\n\nRead\u2014write.\n")
        allowance(tree, PROBE, {"emoji": 1})

    result.append(Case("allowance is per rule", different_rule, 1, "em-dash"))

    def different_path(tree: pathlib.Path):
        write(tree, PROBE, "# Probe\n\nRead\u2014write.\n")
        allowance(tree, "docs/another-file.md", {"em-dash": 1})

    result.append(Case("allowance is per file", different_path, 1, "em-dash"))

    def removed_entry(tree: pathlib.Path):
        write(tree, PROBE, "# Probe\n\nRead\u2014write.\n")
        allowance(tree, PROBE, {"em-dash": 1})
        baseline = json.loads((tree / BASELINE).read_text(encoding="utf-8"))
        del baseline[PROBE]
        write(tree, BASELINE, json.dumps(baseline))

    result.append(Case("removed allowance exposes hits", removed_entry, 1, "em-dash"))
    invalid = [
        ("invalid JSON", "{"),
        ("invalid root", "[]"),
        ("duplicate path", '{"a.md": {"em-dash": 1}, "a.md": {"em-dash": 1}}'),
        ("duplicate rule", '{"a.md": {"em-dash": 1, "em-dash": 1}}'),
        ("unknown rule", '{"a.md": {"unknown": 1}}'),
        ("negative count", '{"a.md": {"em-dash": -1}}'),
        ("boolean count", '{"a.md": {"em-dash": true}}'),
        ("fractional count", '{"a.md": {"em-dash": 1.5}}'),
        ("empty counts", '{"a.md": {}}'),
        ("parent path", '{"../a.md": {"em-dash": 1}}'),
        ("absolute path", '{"/a.md": {"em-dash": 1}}'),
        ("excluded baseline path", '{"CHANGELOG.md": {"em-dash": 1}}'),
    ]
    for name, text in invalid:
        result.append(Case(name, lambda tree, text=text: write(tree, BASELINE, text), 2, error="check-docs-style:"))
    result.append(Case("missing baseline", lambda tree: (tree / BASELINE).unlink(), 2, error="check-docs-style:"))
    return result


def main(argv: list[str]) -> int:
    root = pathlib.Path(argv[1] if len(argv) > 1 else HERE.parents[1]).resolve()
    check = load_check()
    tests = cases()
    failures = 0
    with tempfile.TemporaryDirectory(prefix="docs-style-") as scratch:
        pristine = pathlib.Path(scratch) / "pristine"
        for relative in [*check.scanned_files(root), str(BASELINE)]:
            target = pristine / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / relative, target)
        subprocess.run(["git", "init", "-q", str(pristine)], check=True, capture_output=True)
        subprocess.run(["git", "add", "-A"], cwd=pristine, check=True, capture_output=True)
        for index, case in enumerate(tests):
            result = None
            tree = pathlib.Path(scratch) / f"case-{index:03d}"
            shutil.copytree(pristine, tree)
            try:
                case.mutate(tree)
                result = subprocess.run(
                    [sys.executable, str(CHECK), "--root", str(tree), *case.args],
                    capture_output=True, text=True, check=False,
                )
                assert result.returncode == case.code, f"exit {result.returncode}, expected {case.code}"
                if case.rule:
                    violations = result.stdout.splitlines()
                    expected = [
                        f"{case.path}:{line}: rule {case.rule}: {case.hits} hits exceed baseline {case.allowed}"
                        for line in (case.lines or (case.line,))
                    ]
                    assert violations == expected, f"expected {expected}, got {violations}"
                if case.error:
                    assert case.error in result.stderr, f"expected {case.error}"
                print(f"ok    {case.name}: exit {result.returncode}")
            except (AssertionError, OSError, subprocess.CalledProcessError) as error:
                failures += 1
                print(f"FAIL  {case.name}: {error}")
                if result is not None:
                    print(result.stdout + result.stderr)
            finally:
                shutil.rmtree(tree)
    masks = [
        (
            "punctuation after a plain URL",
            "https://e.test/licence.\u201d\n(https://e.test/licence)\n",
            " " * len("https://e.test/licence") + ".\u201d\n("
            + " " * len("https://e.test/licence") + ")\n",
        ),
        (
            "definition and URL source offsets",
            '[terms]: docs/licence "read\u2013write"\r\n'
            "See https://e.test/a(b)/licence.\nA licence applies.\n",
            "[terms]: " + " " * len('docs/licence "read\u2013write"\r') + "\n"
            "See " + " " * len("https://e.test/a(b)/licence") + ".\nA licence applies.\n",
        ),
    ]
    for name, text, expected in masks:
        try:
            masked = check.prose(text)
            assert masked == expected, f"expected {expected!r}, got {masked!r}"
            print(f"ok    {name}")
        except AssertionError as error:
            failures += 1
            print(f"FAIL  {name}: {error}")
    total = len(tests) + len(masks)
    print(f"docs style self-test: {total - failures} of {total} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
