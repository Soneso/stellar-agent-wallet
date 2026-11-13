#!/usr/bin/env python3
"""Validate entries, preview or fold a release, and guard integration history."""

import argparse
from collections import namedtuple
from pathlib import Path
import re
import subprocess
import sys
import uuid

CATEGORIES = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")
NAME = re.compile(r"([a-z0-9-]+)\.(added|changed|deprecated|removed|fixed|security)\.md")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?")
Fragment = namedtuple("Fragment", "path category body")


class Invalid(ValueError):
    """The supplied content violates the fragment or section contract."""


class Unmerged(Invalid):
    """The merge result differs from the clean three-way merge."""


def validate_fragment_name(name):
    match = NAME.fullmatch(name)
    if not match:
        raise Invalid(f"changelog.d/{name}: invalid filename or category")
    return match[2].title()


def validate_fragment_body(text):
    if not text.strip():
        raise Invalid("line 1: empty fragment")
    seen = False
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    for number, line in enumerate(text.split("\n"), 1):
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


def lf_lines(text):
    lines = text.split("\n")
    return [line + "\n" for line in lines[:-1]] + ([lines[-1]] if lines[-1] else [])


def section_bounds(text, label):
    lines = lf_lines(text)
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
    lines = lf_lines(text)
    category_positions(lines)
    for category in CATEGORIES:
        incoming = [fragment.body for fragment in fragments if fragment.category == category]
        if not incoming:
            continue
        positions = category_positions(lines)
        payload = lf_lines("".join(incoming))
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
            following = insertion + len(payload)
            if following < len(lines) and lines[following].startswith("### "):
                lines[following:following] = ["\n"]
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


def git(root, *args, allowed=(0,)):
    result = subprocess.run(["git", "--no-replace-objects", "--no-optional-locks", *args],
                            cwd=root, capture_output=True, check=False)
    if result.returncode not in allowed:
        raise OSError(f"guard: git {args[0]} fails; check Git support, restore complete history, and retry")
    return result


def object_ids(output):
    if not re.fullmatch(rb"(?:[0-9a-f]{40}(?:[0-9a-f]{24})?\n)*", output):
        raise OSError("guard: unexpected object list; restore complete history and retry")
    return output.decode("ascii").splitlines()


def changelog_blob(root, commit):
    entry = git(root, "ls-tree", "-z", commit, "--", "CHANGELOG.md").stdout
    match = re.fullmatch(rb"100644 blob ([0-9a-f]{40}(?:[0-9a-f]{24})?)\tCHANGELOG.md\0", entry)
    if not match:
        raise Invalid("use a regular CHANGELOG.md with mode 100644 and its original path")
    oid = match[1].decode("ascii")
    return oid, git(root, "cat-file", "blob", oid).stdout


def ancestor(root, older, newer):
    result = git(root, "merge-base", "--is-ancestor", older, newer, allowed=(0, 1))
    if result.stdout or result.stderr:
        raise OSError("guard: unexpected ancestry output; restore complete history and retry")
    return result.returncode == 0


def clean_changelog_merge(root, parents, commit):
    bases = object_ids(git(root, "merge-base", "--all", *parents).stdout)
    if len(bases) != 1:
        raise Invalid("a maintainer resolves and merges ambiguous merge bases")
    ours, original, theirs, actual = [changelog_blob(root, ref)
                                     for ref in (*parents[:1], bases[0], parents[1], commit)]
    # Object input and stdout avoid writes to files, the index, and the object store.
    # merge-file uses Git's built-in text merge without attributes or merge drivers.
    merged = git(root, "-c", "merge.conflictStyle=merge", "merge-file", "-p", "--object-id",
                 ours[0], original[0], theirs[0], allowed=tuple(range(128)))
    if merged.returncode:
        raise Invalid("CHANGELOG.md conflicts; a maintainer resolves and merges it")
    if merged.stderr:
        raise OSError("guard: unexpected merge output; check Git support and retry")
    return actual[1] == merged.stdout


def guard(root, base, head, main_ref):
    if git(root, "rev-parse", "--is-shallow-repository").stdout != b"false\n":
        raise Invalid("guard: shallow history; supply complete history and retry")
    refs = [object_ids(git(root, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}").stdout)
            for ref in (base, head, main_ref)]
    if any(len(ids) != 1 for ids in refs):
        raise OSError("guard: unexpected ref output; restore complete history and retry")
    base, head, main = [ids[0] for ids in refs]
    commits = object_ids(git(root, "rev-list", f"{base}..{head}", "--not", main).stdout)
    refused = []
    checked = 0
    for commit in commits:
        try:
            row = git(root, "rev-list", "--parents", "-n", "1", commit).stdout
            family = object_ids(row.replace(b" ", b"\n"))
            if not family or family[0] != commit:
                raise OSError("guard: unexpected parents; restore complete history and retry")
            parents = family[1:]
            comparison = [parents[0], commit] if parents else ["--root", commit]
            changed = git(root, "diff-tree", "-r", "--no-renames", "--no-commit-id",
                          "--name-only", *comparison, "--", "CHANGELOG.md").stdout
            if changed not in (b"", b"CHANGELOG.md\n"):
                raise OSError("guard: unexpected diff output; restore complete history and retry")
            if not changed:
                # A sync merge cannot silently discard incoming main entries.
                if (len(parents) != 2 or not ancestor(root, parents[1], main)
                        or ancestor(root, parents[1], parents[0])):
                    continue
            checked += 1
            allowed = (len(parents) == 2 and ancestor(root, parents[1], main)
                       and not ancestor(root, parents[1], parents[0]))
            if not allowed:
                raise Invalid("use a two-parent sync merge that preserves the clean merge result")
            if not clean_changelog_merge(root, parents, commit):
                raise Unmerged("CHANGELOG.md differs from the clean three-way merge; a maintainer resolves and merges it")
        except Unmerged as error:
            # A maintainer resolves a differing sync merge, so the refusal names only that remedy.
            refused.append(f"{commit}: CHANGELOG.md edit is refused. {error}.")
        except Invalid as error:
            refused.append(f"{commit}: CHANGELOG.md edit is refused. {error}. "
                           "Move entries to new fragments and remove edits from branch history.")
        except OSError as error:
            raise OSError(f"{commit}: {error}") from error
    if refused:
        raise Invalid("\n".join(refused))
    print(f"{checked} changelog commits checked; integration guard passes", file=sys.stderr)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    for mode in ("check", "preview", "release", "guard"):
        sub = modes.add_parser(mode)
        default_root = Path.cwd() if __file__ == "<stdin>" else Path(__file__).resolve().parents[2]
        sub.add_argument("--root", type=Path, default=default_root)
        if mode == "release":
            sub.add_argument("--version", required=True)
        if mode == "guard":
            for argument in ("base", "head", "main-ref"):
                sub.add_argument("--" + argument, required=True)
    args = parser.parse_args(argv)
    root = args.root
    try:
        if args.mode == "guard":
            return guard(root, args.base, args.head, args.main_ref)
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
