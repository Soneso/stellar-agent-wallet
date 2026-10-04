#!/usr/bin/env python3
"""Check mechanical writing rules in Markdown prose.

Usage: check-docs-style.py [--root ROOT] [FILE ...]

ROOT defaults to this repository, and FILE paths are relative to ROOT. With no
FILE, scan tracked Markdown except
CHANGELOG.md and crates/*/vendor/**. Explicit files may be untracked.
Explicit files use the same exclusions and .md filter; other paths exit 2
with "not a scanned path".
Fenced code, inline code spans, autolinks, link destinations and titles,
and bare URLs are exempt. Link and reference labels remain subject to the
prose rules.

Rules:
- em-dash: U+2014 fails; ASCII hyphens pass.
- en-dash: U+2013 between letters fails; numeric ranges pass.
- curly-quotes: U+2018 through U+201F fail; straight quotes pass.
- filler: The banned praise word fails as a standalone word; longer words pass.
- emoji: Pictographs, dingbats, flags, keycaps, and joined sequences fail.
  Plain copyright and trademark symbols pass without emoji presentation.
- british-initialis: British initialize inflections fail; initialism passes.
- british-serialis: British serialize inflections fail; serialism passes.
- british-recognis: Words containing this British stem fail; recognize passes.
- british-authoris: Words containing this British stem fail; authorize passes.
- british-behaviour: Words containing this British stem fail; behavior passes.
- british-licence: The singular and plural noun spellings fail; licensing passes.
  This rule matches whole words without inferring grammatical roles.

docs-style-baseline.json maps each file path to rule names and positive counts.
A path or rule absent from the baseline allows zero hits.
Maintainers lower counts as prose changes and remove entries for clean files.
Exit codes are 0 for a passing tree, 1 for violations, and 2 for input errors.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    print(
        "check-docs-style.py needs Python 3.11 or later; "
        f"this is Python {sys.version.split()[0]}",
        file=sys.stderr,
    )
    sys.exit(2)

import argparse
import bisect
import json
import pathlib
import re
import subprocess
from collections import Counter

BASELINE = pathlib.Path(".github/scripts/docs-style-baseline.json")
RULES = {
    "em-dash": re.compile(r"\u2014"),
    "en-dash": re.compile(r"(?<=[^\W\d_])\s*\u2013\s*(?=[^\W\d_])"),
    "curly-quotes": re.compile(r"[\u2018-\u201f]"),
    "filler": re.compile(r"\bcomprehensive\b", re.IGNORECASE),
    # Whole symbol blocks include dingbats because the style rule covers them.
    "emoji": re.compile(
        r"[0-9#*]\ufe0f?\u20e3"
        r"|[\U0001f1e6-\U0001f1ff]{2}"
        r"|[\u00a9\u00ae\u2122\u2194-\u2199\u21a9\u21aa]\ufe0f"
        r"|[\u231a\u231b\u2328\u23cf\u23e9-\u23f3\u23f8-\u23fa"
        r"\u24c2\u25aa\u25ab\u25b6\u25c0\u25fb-\u25fe\u2600-\u27bf"
        r"\u2934\u2935\u2b05-\u2b07\u2b1b\u2b1c\u2b50\u2b55"
        r"\u3030\u303d\u3297\u3299\U0001f000-\U0001faff]"
        r"(?:[\ufe0e\ufe0f\U0001f3fb-\U0001f3ff]|"
        r"\u200d[\u2600-\u27bf\U0001f000-\U0001faff])*"
    ),
    "british-initialis": re.compile(r"\b[a-z]*initialis(?:e|es|ed|ing|ation|ations|er|ers)\b", re.IGNORECASE),
    "british-serialis": re.compile(r"\b[a-z]*serialis(?:e|es|ed|ing|ation|ations|er|ers)\b", re.IGNORECASE),
    "british-recognis": re.compile(r"\b[a-z]*recognis[a-z]*\b", re.IGNORECASE),
    "british-authoris": re.compile(r"\b[a-z]*authoris[a-z]*\b", re.IGNORECASE),
    "british-behaviour": re.compile(r"\b[a-z]*behaviour[a-z]*\b", re.IGNORECASE),
    "british-licence": re.compile(r"\blicences?\b", re.IGNORECASE),
}
FENCE = re.compile(r"^(`{3,}|~{3,})(.*)$")
CONTAINER = re.compile(r"^(?:>[ \t]?|(?:[-*+]|[0-9]{1,9}[.)])[ \t]+)")


def excluded(path: str) -> bool:
    parts = pathlib.PurePosixPath(path).parts
    return path == "CHANGELOG.md" or (
        len(parts) >= 4 and parts[0] == "crates" and parts[2] == "vendor"
    )


def scanned_files(root: pathlib.Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", "*.md"],
        capture_output=True,
        check=True,
    )
    return sorted({
        path for path in result.stdout.decode("utf-8").split("\0")
        if path and not excluded(path) and (root / path).is_file()
    })


def blank(text: str) -> str:
    """Preserve offsets and newlines while hiding exempt text."""
    return re.sub(r"[^\n]", " ", text)


def container_content(line: str) -> str:
    content = line.lstrip(" \t")
    while match := CONTAINER.match(content):
        content = content[match.end():].lstrip(" \t")
    return content.rstrip("\r\n")


def mask_inline(text: str) -> str:
    runs = list(re.finditer(r"`+", text))
    pieces = list(text)
    index = 0
    while index < len(runs):
        opening = runs[index]
        before = text[:opening.start()]
        escapes = len(before) - len(before.rstrip("\\"))
        if escapes % 2:
            index += 1
            continue
        closing = next(
            (end for end in range(index + 1, len(runs))
             if len(runs[end].group()) == len(opening.group())),
            None,
        )
        if closing is None:
            index += 1
            continue
        stop = runs[closing].end()
        pieces[opening.start():stop] = blank(text[opening.start():stop])
        index = closing + 1
    return "".join(pieces)


DEFINITION = re.compile(
    r"^ {0,3}\[[^\]\n]+\]:[ \t]*(?P<target><[^<>\n]*>|[^\s<>]+)"
    r"(?:[ \t]+(?:\"[^\"\n]*\"|'[^'\n]*'|\([^()\n]*\)))?[ \t]*\r?$",
    re.MULTILINE,
)
SCHEME = re.compile(r"(?<![\w<])[a-zA-Z][a-zA-Z0-9+.-]*://")
# Sentence punctuation after a bare URL belongs to the prose.
URL_TAIL = ".,;:!?\"'\u201d\u2019"


def mask_definition(match: re.Match[str]) -> str:
    """Keep the label of a reference definition; mask its destination and title."""
    cut = match.start("target") - match.start()
    return match[0][:cut] + blank(match[0][cut:])


def mask_links(text: str) -> str:
    """Mask link targets and bare URLs, preserving labels and source offsets."""
    text = re.sub(r"<[a-zA-Z][a-zA-Z0-9+.-]*://[^<>\s]*>", lambda match: blank(match[0]), text)
    pieces = list(text)
    for opening in re.finditer(r"\]\(", text):
        depth = 1
        index = opening.end()
        while index < len(text) and depth:
            if text[index] == "\\":
                index += 2
                continue
            if text[index] == "(":
                depth += 1
            elif text[index] == ")":
                depth -= 1
            index += 1
        if depth == 0:
            pieces[opening.start() + 1:index] = blank(text[opening.start() + 1:index])
    text = "".join(pieces)
    pieces = list(text)
    # A bare URL ends at whitespace, an angle or square bracket, or an unmatched
    # closing parenthesis; inline destinations are already masked at this point.
    for scheme in SCHEME.finditer(text):
        index = scheme.end()
        depth = 0
        while index < len(text) and not text[index].isspace() and text[index] not in "<>[]":
            if text[index] == "(":
                depth += 1
            elif text[index] == ")":
                if depth == 0:
                    break
                depth -= 1
            index += 1
        while index > scheme.end() and text[index - 1] in URL_TAIL:
            index -= 1
        pieces[scheme.start():index] = blank(text[scheme.start():index])
    return "".join(pieces)


def prose(text: str) -> str:
    """Mask Markdown code and link targets while preserving source line numbers."""
    lines = []
    fence = None
    for line in text.splitlines(keepends=True):
        content = container_content(line)
        if fence is not None:
            lines.append(blank(line))
            character, length = fence
            if re.fullmatch(re.escape(character) + "{" + str(length) + r",}[ \t]*", content):
                fence = None
            continue
        opening = FENCE.match(content)
        # Backtick fence info strings exclude backticks under CommonMark.
        if opening and (opening[1][0] == "~" or "`" not in opening[2]):
            fence = (opening[1][0], len(opening[1]))
            lines.append(blank(line))
        else:
            lines.append(line)
    # Definition targets are recognized while their Markdown delimiters are intact.
    text = DEFINITION.sub(mask_definition, "".join(lines))
    # Blank lines and ATX headings bound paragraphs, so code spans stop there.
    parts = re.split(r"(\n[ \t]*\n|^ {0,3}#{1,6}[ \t]+[^\n]*\n?)", text, flags=re.MULTILINE)
    return "".join(mask_links(mask_inline(part)) for part in parts)


def findings(text: str) -> list[tuple[int, str]]:
    visible = prose(text)
    newlines = [match.start() for match in re.finditer("\n", visible)]
    return sorted(
        (bisect.bisect_right(newlines, match.start()) + 1, rule)
        for rule, pattern in RULES.items()
        for match in pattern.finditer(visible)
    )


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate baseline key: {key}")
        result[key] = value
    return result


def load_baseline(root: pathlib.Path) -> dict[str, dict[str, int]]:
    baseline = json.loads((root / BASELINE).read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    if not isinstance(baseline, dict):
        raise ValueError("baseline must be an object of paths and rule counts")
    for path, counts in baseline.items():
        parts = pathlib.PurePosixPath(path)
        if (parts.is_absolute() or ".." in parts.parts or parts.as_posix() != path
                or "\\" in path or not path.endswith(".md") or excluded(path)):
            raise ValueError(f"invalid baseline path: {path}")
        if not isinstance(counts, dict) or not counts:
            raise ValueError(f"baseline counts must be a nonempty object: {path}")
        for rule, count in counts.items():
            if rule not in RULES or type(count) is not int or count <= 0:
                raise ValueError(f"invalid baseline count: {path}: {rule}")
    return baseline


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[2])
    parser.add_argument("files", nargs="*", type=pathlib.Path)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        baseline = load_baseline(root)
        if args.files:
            paths = sorted({(root / path).resolve().relative_to(root).as_posix() for path in args.files})
            for path in paths:
                if excluded(path) or not path.endswith(".md"):
                    raise ValueError(f"not a scanned path: {path}")
        else:
            paths = scanned_files(root)
        failures = 0
        for path in paths:
            hits = findings((root / path).read_text(encoding="utf-8"))
            counts = Counter(rule for _, rule in hits)
            for rule, count in sorted(counts.items()):
                allowed = baseline.get(path, {}).get(rule, 0)
                if count > allowed:
                    for line in sorted({line for line, name in hits if name == rule}):
                        print(f"{path}:{line}: rule {rule}: {count} hits exceed baseline {allowed}")
                    failures += 1
        if failures:
            return 1
        print(f"docs style: {len(paths)} files pass")
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"check-docs-style: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
