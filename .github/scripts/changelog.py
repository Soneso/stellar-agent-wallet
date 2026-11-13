#!/usr/bin/env python3
"""Validate pending entries, preview Unreleased, or fold a prepared release."""

import argparse
from collections import namedtuple
from pathlib import Path
import re
import sys
import uuid

CATEGORIES = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")
NAME = re.compile(r"([a-z0-9-]+)\.(added|changed|deprecated|removed|fixed|security)\.md")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?")
Fragment = namedtuple("Fragment", "path category body")


class Invalid(ValueError):
    """The supplied content violates the fragment or section contract."""


def validate_fragment_name(name):
    match = NAME.fullmatch(name)
    if not match:
        raise Invalid(f"changelog.d/{name}: invalid filename or category")
    return match[2].title()


def validate_fragment_body(text):
    if not text.strip():
        raise Invalid("line 1: empty fragment")
    seen = False
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if line[0].isspace():
            if not seen:
                raise Invalid(f"line {number}: continuation before first item")
        elif line.startswith("- "):
            if not line[2:].strip():
                raise Invalid(f"line {number}: empty list item")
            seen = True
        else:
            raise Invalid(f"line {number}: expected a '- ' list item")


def load_fragments(root):
    directory = root / "changelog.d"
    try:
        entries = sorted(directory.iterdir(), key=lambda path: path.name)
    except OSError as error:
        raise OSError("changelog.d/: cannot list directory") from error
    if not any(path.name == "README.md" for path in entries):
        raise Invalid("changelog.d/README.md: required file is missing")
    fragments = []
    for path in entries:
        try:
            regular = not path.is_symlink() and path.is_file()
        except OSError as error:
            raise OSError(f"changelog.d/{path.name}: cannot inspect entry") from error
        if not regular:
            raise Invalid(f"changelog.d/{path.name}: expected a regular file")
        if path.name == "README.md":
            continue
        category = validate_fragment_name(path.name)
        try:
            body = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeError) as error:
            raise OSError(f"changelog.d/{path.name}: cannot read UTF-8 content") from error
        body = body.replace("\r\n", "\n").replace("\r", "\n")
        try:
            validate_fragment_body(body)
        except Invalid as error:
            raise Invalid(f"changelog.d/{path.name}: {error}") from error
        fragments.append(Fragment(path, category, body if body.endswith("\n") else body + "\n"))
    return fragments


def section_bounds(text, label):
    lines = text.splitlines(keepends=True)
    heading = re.compile(r"^## \[" + re.escape(label) + r"\](?:[^\S\n].*)?\n?$")
    starts = [i for i, line in enumerate(lines) if heading.fullmatch(line)]
    if len(starts) != 1:
        raise Invalid(f"CHANGELOG.md: expected exactly one {label} heading")
    start = starts[0]
    definitions = next((i for i in range(start + 1, len(lines))
                        if re.match(r"^\[[^\]]+\]:", lines[i])
                        and all(not line.strip() or re.match(r"^\[[^\]]+\]:", line) for line in lines[i:])), len(lines))
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].startswith("## [") or i == definitions), len(lines))
    return lines, start, end


def category_positions(lines):
    positions = {}
    for i, line in enumerate(lines):
        match = re.fullmatch(r"### (Added|Changed|Deprecated|Removed|Fixed|Security)\s*", line)
        if match:
            category = match[1]
            if category in positions:
                raise Invalid(f"CHANGELOG.md: duplicate {category} category")
            positions[category] = i
        elif line.startswith("### "):
            raise Invalid("CHANGELOG.md: unknown category heading")
    return positions


def fold_section(text, fragments):
    lines = text.splitlines(keepends=True)
    category_positions(lines)
    for category in CATEGORIES:
        incoming = [fragment.body for fragment in fragments if fragment.category == category]
        if not incoming:
            continue
        positions = category_positions(lines)
        payload = "".join(incoming).splitlines(keepends=True)
        if category in positions:
            start = positions[category]
            end = min((i for i in positions.values() if i > start), default=len(lines))
            insertion = end
            while insertion > start + 1 and not lines[insertion - 1].strip():
                insertion -= 1
            if insertion == start + 1:
                lines[insertion:insertion] = ["\n"]
                insertion += 1
            if insertion and not lines[insertion - 1].endswith("\n"):
                lines[insertion - 1] += "\n"
            lines[insertion:insertion] = payload
        else:
            later = [i for name, i in positions.items() if CATEGORIES.index(name) > CATEGORIES.index(category)]
            insertion = min(later, default=len(lines))
            prefix = [] if insertion and lines[insertion - 1] == "\n" else ["\n"]
            lines[insertion:insertion] = prefix + [f"### {category}\n", "\n"] + payload + ["\n"]
    return "".join(lines)


def read_changelog(root):
    try:
        return (root / "CHANGELOG.md").read_bytes().decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise OSError("CHANGELOG.md: cannot read UTF-8 content") from error


def check(root):
    fragments = load_fragments(root)
    print(f"{len(fragments)} fragments valid; 1 README", file=sys.stderr)
    return 0


def preview(root):
    fragments = load_fragments(root)
    lines, start, end = section_bounds(read_changelog(root), "Unreleased")
    rendered = fold_section("".join(lines[start:end]), fragments)
    print(rendered, end="", file=sys.stdout)
    return 0


def replace_changelog(root, text):
    temporary = root / f".CHANGELOG.{uuid.uuid4().hex}.tmp"
    try:
        with temporary.open("x", encoding="utf-8", newline="") as stream:
            stream.write(text)
        temporary.replace(root / "CHANGELOG.md")
    except OSError as error:
        raise OSError("CHANGELOG.md: cannot replace content") from error


def release(root, version):
    if not VERSION.fullmatch(version):
        raise Invalid("version: expected major.minor.patch with an optional prerelease")
    fragments = load_fragments(root)
    text = read_changelog(root)
    lines, start, end = section_bounds(text, version)
    _, unreleased, un_end = section_bounds(text, "Unreleased")
    if start != un_end or unreleased >= start:
        raise Invalid("CHANGELOG.md: target must be the first release after Unreleased")
    rendered = fold_section("".join(lines[start:end]), fragments)
    if not fragments:
        return 0
    updated = "".join(lines[:start]) + rendered + "".join(lines[end:])
    replace_changelog(root, updated)
    for fragment in fragments:
        try:
            fragment.path.unlink()
        except OSError as error:
            raise OSError(f"changelog.d/{fragment.path.name}: cannot consume fragment") from error
    print(f"{len(fragments)} fragments released under {version}", file=sys.stderr)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    for mode in ("check", "preview", "release"):
        sub = modes.add_parser(mode)
        sub.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
        if mode == "release":
            sub.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    root = args.root
    try:
        if args.mode == "release":
            return release(root, args.version)
        return {"check": check, "preview": preview}[args.mode](root)
    except Invalid as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, UnicodeError) as error:
        print(f"changelog: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
