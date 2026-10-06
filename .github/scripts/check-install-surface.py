#!/usr/bin/env python3
"""Check the documented install surface, secret-seed procedures, and binstall metadata.

Usage: check-install-surface.py [ROOT]

ROOT defaults to the current directory and must be a git work tree. The check
reads the Markdown files `git ls-files '*.md'` lists, except `CHANGELOG.md`,
`crates/*/vendor/**`, and `crates/*/tests/fixtures/**`, plus the root
`Cargo.toml` and the manifests of the two wallet crates. It prints one line per
violation and exits 1 when it finds any, 0 when it finds none, and 2 when it
cannot run.

Fenced blocks. A fence opens on a line of three or more backticks or tildes,
after optional indentation and list markers such as `-` or `1.`. A backtick
line whose info string holds a backtick opens no fence, because it starts an
inline code span. A fence closes on a line of at least as many of its
character, or at the end of the file.

Command units. Rule 1 and rule 3b evaluate command units:

- The code of a fenced-block line: the line without its shell comment, with
  backslash continuations joined to the next line. A comment starts at a `#`
  that begins a word outside single and double quotes.
- The content of an inline code span. Spans are parsed per paragraph, so a span
  can wrap across lines; a line break inside a span reads as a space.
- A command named in prose, in a shell comment or on a prose line outside
  every inline code span. The unit runs from a `cargo install` or
  `cargo binstall` token to the next such token or the end of the line, with
  backticks removed.
  This covers prose commands and YAML frontmatter such as the `SKILL.md`
  `compatibility` value. A comment is its own unit, so a flag it names does
  not count for the code.

Each unit is split into commands at `&&`, `||`, `;`, and `|`. A crate name
matches only when neither a word character nor `-` adjoins it, so
`stellar-agent-mcp-macros` is not `stellar-agent-mcp`.

Rule 1, locked installs:
- A `cargo install` command that names `stellar-agent-cli`,
  `stellar-agent-mcp`, or `Soneso/stellar-agent-wallet` passes `--locked`.
- A `cargo binstall` command that names one of them passes `--locked` and
  `--disable-strategies` with a value that includes both `quick-install` and
  `compile`. The value may be a comma list, quoted or not, in the `=` or the
  space form, and the check merges repeated flags.
- In a fenced block whose code or comments name `git clone` of
  `Soneso/stellar-agent-wallet`, every `cargo build` command passes `--locked`.

Rule 2, version pins. In the scanned Markdown, each of these equals
`[workspace.package].version` of the root `Cargo.toml`:
- the version of `stellar-agent-cli@<semver>` and `stellar-agent-mcp@<semver>`;
- the tag of `git clone ... --branch v<semver>`, `--branch=v<semver>`, or
  `-b v<semver>`;
- the tag of each `releases/download/v<semver>`, whatever follows it: an
  archive name, `/SHA256SUMS`, or the quote that closes a base URL. The tag
  is the longest semver after the `v`.
A name `stellar-agent-<semver>...`, such as a release archive, starts with
`stellar-agent-<version>` and ends there or continues with `.`, or with `-` and
then a placeholder or the architecture of a release target. A prerelease may
contain `-`, so the architecture marks where the version ends: at version
`0.1.0`, the name `stellar-agent-0.1.0-alpha.9-aarch64-apple-darwin.tar.xz`
fails. The check ignores a placeholder such as `<version>`, which is not a
semver, and a sentence-final dot is not part of a semver.

Rule 3, typed seeds: no line of the scanned Markdown assigns an S-strkey
literal (a full 56-character seed, or a placeholder such as `S...`, `S…`, or
`SABC...WXYZ`):
- a shell assignment `NAME=S...`, quoted or not, with or without `export`,
  standalone or as a command prefix, in a fence, an inline span, or prose;
- a PowerShell assignment `$env:NAME = 'S...'` or `"S..."`, with `env` in any
  case;
- a cmd assignment `set NAME=S...` or `set "NAME=S..."`.

Rule 3b, unset after a hidden read. A secret read is a command `read` in the
code of a fenced-block line, after any leading `NAME=value` assignments, whose
option words (words that start with `-`) together contain the letter `s`.
Examples are `read -rs NAME`, `read -sr NAME`, `read -r -s NAME`, and
`IFS= read -rs NAME`. It reads each identifier word among its arguments. For
each secret read of NAME, the first of these that follows it decides the
outcome:
- `unset` naming NAME in the code of a later line of the block or of a later
  block, or in an inline code span of the first paragraph after the block: the
  read passes;
- another secret read of NAME in a later fenced block: violation;
- the next Markdown heading, of any level, or the end of the file: violation.
A paragraph that follows a heading is not the paragraph after the block.

Rule 4, binstall metadata: in both wallet crate manifests,
`package.metadata.binstall` equals EXPECTED_BINSTALL exactly, so a changed,
missing, or extra key or override table fails. Both manifests set
`package.repository` to `{ workspace = true }`, and the root
`[workspace.package].repository` equals EXPECTED_REPOSITORY, which binstall's
`{ repo }` template expands to.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    print(
        "check-install-surface.py needs Python 3.11 or later for tomllib; "
        f"this is Python {sys.version.split()[0]}",
        file=sys.stderr,
    )
    sys.exit(2)

import pathlib
import re
import subprocess
import tomllib
from dataclasses import dataclass, field
from typing import NoReturn

EXPECTED_REPOSITORY = "https://github.com/Soneso/stellar-agent-wallet"
WALLET_MANIFESTS = (
    "crates/stellar-agent-cli/Cargo.toml",
    "crates/stellar-agent-mcp/Cargo.toml",
)
EXPECTED_BINSTALL = {
    "pkg-url": (
        "{ repo }/releases/download/v{ version }/stellar-agent-{ version }-{ target }.tar.xz"
    ),
    "pkg-fmt": "txz",
    "bin-dir": "stellar-agent-{ version }-{ target }/{ bin }{ binary-ext }",
    "disabled-strategies": ["quick-install", "compile"],
    "overrides": {
        'cfg(target_os = "windows")': {
            "pkg-url": (
                "{ repo }/releases/download/v{ version }/stellar-agent-{ version }-{ target }.zip"
            ),
            "pkg-fmt": "zip",
        },
    },
}
REQUIRED_DISABLED_STRATEGIES = set(EXPECTED_BINSTALL["disabled-strategies"])

SEMVER = r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
WALLET_TARGET = re.compile(
    r"(?<![\w-])(?:stellar-agent-cli|stellar-agent-mcp)(?![\w-])"
    r"|Soneso/stellar-agent-wallet(?![\w-])"
)
CARGO_INSTALL = re.compile(r"(?<![\w-])cargo\s+install(?![\w-])")
CARGO_BINSTALL = re.compile(r"(?<![\w-])cargo\s+binstall(?![\w-])")
CARGO_BUILD = re.compile(r"(?<![\w-])cargo\s+build(?![\w-])")
INSTALL_TOKEN = re.compile(r"(?<![\w-])cargo\s+b?install(?![\w-])")
LOCKED = re.compile(r"(?<![\w-])--locked(?![\w-])")
DISABLE_STRATEGIES = re.compile(r"(?<![\w-])--disable-strategies(?:=|\s+)([^\s]+)")
CLONES_WALLET = re.compile(r"(?<![\w-])git\s+clone\b.*Soneso/stellar-agent-wallet(?![\w-])")
# `||` splits as two `|`; commands() drops the empty part between them.
COMMAND_SEPARATOR = re.compile(r"&&|;|\|")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

CRATE_PIN = re.compile(r"(?<![\w-])stellar-agent-(?:cli|mcp)@(" + SEMVER + r")")
CLONE_PIN = re.compile(
    r"(?<![\w-])git\s+clone\b[^\n]*?(?:--branch[=\s]+|(?<![\w-])-b\s+)v(" + SEMVER + r")"
)
RELEASE_TAG = re.compile(r"releases/download/v(" + SEMVER + r")")
VERSIONED_NAME = re.compile(r"(?<![\w-])stellar-agent-([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z_.-]*)")
# The architectures of the release targets in `.github/workflows/release.yml`.
RELEASE_ARCHITECTURES = ("x86_64", "aarch64")

SEED = r"S(?:[A-Z2-7]{55}(?![A-Z2-7])|[A-Z2-7]{0,54}(?:\.{2,}|…))"
SEED_ASSIGNMENTS = (
    ("shell", re.compile(r"(?:^|[\s;&|(`])[A-Za-z_][A-Za-z0-9_]*=[\"']?" + SEED)),
    ("PowerShell", re.compile(r"\$[Ee][Nn][Vv]:[A-Za-z_][A-Za-z0-9_]*\s*=\s*[\"']?" + SEED)),
    ("cmd", re.compile(r"(?<![\w-])[Ss][Ee][Tt]\s+\"?[A-Za-z_][A-Za-z0-9_]*=" + SEED)),
)

FENCE_OPEN = re.compile(r"^[ \t]*(?:(?:[-*+]|[0-9]{1,9}[.)])[ \t]+)*(`{3,}|~{3,})(.*)$")
HEADING = re.compile(r"^ {0,3}#{1,6}(?:\s|$)")
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass
class Fence:
    """A fenced code block: its opening and closing line numbers and its content lines."""

    open_line: int
    close_line: int
    lines: list[tuple[int, str]]


@dataclass
class Span:
    """An inline code span: its first line, its content, and its offsets in the paragraph text."""

    line: int
    content: str
    start: int
    end: int


@dataclass
class Paragraph:
    """Consecutive non-blank prose lines, with the inline code spans they hold."""

    lines: list[tuple[int, str]]
    spans: list[Span] = field(default_factory=list)


@dataclass
class Document:
    """A Markdown file split into fenced blocks, paragraphs, and headings."""

    path: str
    lines: list[str]
    fences: list[Fence]
    paragraphs: list[Paragraph]
    headings: list[int]
    paragraph_after_fence: dict[int, Paragraph]


class Report:
    """Violations, printed sorted by path and line."""

    def __init__(self) -> None:
        self.entries: list[tuple[str, int, str]] = []

    def add(self, path: str, line: int | None, rule: str, message: str) -> None:
        where = f"{path}:{line}" if line is not None else path
        self.entries.append((path, line or 0, f"{where}: rule {rule}: {message}"))

    def lines(self) -> list[str]:
        return [text for _, _, text in sorted(self.entries)]


def fail_to_run(message: str) -> NoReturn:
    print(f"check-install-surface: {message}", file=sys.stderr)
    sys.exit(2)


def is_scanned(path: str) -> bool:
    """Whether the check reads PATH, relative to ROOT, when Git tracks it.

    preflight.sh selects the self-test of this check when a changed path
    passes, so the self-test runs whenever a file it injects into changes.
    """
    if path == "Cargo.toml" or path in WALLET_MANIFESTS:
        return True
    if not path.endswith(".md") or path == "CHANGELOG.md":
        return False
    parts = path.split("/")
    if len(parts) > 3 and parts[0] == "crates" and parts[2] == "vendor":
        return False
    return not (len(parts) > 4 and parts[0] == "crates" and parts[2:4] == ["tests", "fixtures"])


def scanned_markdown(root: pathlib.Path) -> list[str]:
    """Return the tracked Markdown paths the check reads, relative to ROOT."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--", "*.md"],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        fail_to_run(f"git ls-files failed in {root}: {error}")
    paths = (raw.decode("utf-8") for raw in result.stdout.split(b"\0") if raw)
    return sorted(path for path in paths if is_scanned(path))


def scanned_files(root: pathlib.Path) -> list[str]:
    """Return every path the check reads: the Markdown set and the three manifests."""
    return scanned_markdown(root) + ["Cargo.toml", *WALLET_MANIFESTS]


def find_spans(text: str, line_starts: list[int], first_line: int) -> list[Span]:
    """Parse CommonMark inline code spans in one paragraph's text."""
    spans = []
    runs = list(re.finditer(r"`+", text))
    index = 0
    while index < len(runs):
        opener = runs[index]
        escaped = 0
        position = opener.start() - 1
        while position >= 0 and text[position] == "\\":
            escaped += 1
            position -= 1
        if escaped % 2 == 1:
            index += 1
            continue
        width = len(opener.group(0))
        closer_index = next(
            (j for j in range(index + 1, len(runs)) if len(runs[j].group(0)) == width),
            None,
        )
        if closer_index is None:
            index += 1
            continue
        closer = runs[closer_index]
        content = text[opener.end() : closer.start()].replace("\n", " ")
        offset_line = max(i for i, start in enumerate(line_starts) if start <= opener.start())
        spans.append(Span(first_line + offset_line, content, opener.start(), closer.end()))
        index = closer_index + 1
    return spans


def fence_opening(line: str) -> str | None:
    """Return the fence marker LINE opens, or None when it opens no fence."""
    opening = FENCE_OPEN.match(line)
    if opening is None:
        return None
    marker, info = opening.group(1), opening.group(2)
    if marker[0] == "`" and "`" in info:
        return None
    return marker


def parse_markdown(path: str, text: str) -> Document:
    """Split TEXT into fenced blocks, paragraphs with their spans, and headings."""
    lines = text.split("\n")
    fences: list[Fence] = []
    paragraphs: list[Paragraph] = []
    headings: list[int] = []
    paragraph_after_fence: dict[int, Paragraph] = {}
    current: list[tuple[int, str]] = []
    pending_fence: Fence | None = None

    def close_paragraph() -> None:
        nonlocal current, pending_fence
        if not current:
            return
        joined = "\n".join(line for _, line in current)
        starts = []
        offset = 0
        for _, line in current:
            starts.append(offset)
            offset += len(line) + 1
        paragraph = Paragraph(current, find_spans(joined, starts, current[0][0]))
        paragraphs.append(paragraph)
        if pending_fence is not None:
            paragraph_after_fence[pending_fence.open_line] = paragraph
            pending_fence = None
        current = []

    index = 0
    while index < len(lines):
        line = lines[index]
        marker = fence_opening(line)
        if marker is not None:
            close_paragraph()
            open_index = index
            close_index = len(lines) - 1
            body: list[tuple[int, str]] = []
            index += 1
            while index < len(lines):
                candidate = lines[index].strip()
                if candidate and set(candidate) == {marker[0]} and len(candidate) >= len(marker):
                    close_index = index
                    break
                body.append((index + 1, lines[index]))
                index += 1
            fence = Fence(open_index + 1, close_index + 1, body)
            fences.append(fence)
            pending_fence = fence
            index = close_index + 1
            continue
        if not line.strip():
            close_paragraph()
        elif HEADING.match(line):
            close_paragraph()
            pending_fence = None
            headings.append(index + 1)
        else:
            current.append((index + 1, line))
        index += 1
    close_paragraph()
    return Document(path, lines, fences, paragraphs, headings, paragraph_after_fence)


def split_comment(line: str) -> tuple[str, str]:
    """Split LINE into its code and its shell comment, a `#` that begins a word outside quotes."""
    quote = None
    previous = " "
    for index, char in enumerate(line):
        if quote is not None:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "#" and previous.isspace():
            return line[:index], line[index:]
        previous = char
    return line, ""


def fence_comments(fence: Fence) -> list[tuple[int, str]]:
    """The shell comment of each fenced-block line that has one."""
    comments = []
    for number, line in fence.lines:
        comment = split_comment(line)[1]
        if comment:
            comments.append((number, comment))
    return comments


def logical_lines(fence: Fence) -> list[tuple[int, str]]:
    """The code of a fenced block: shell comments removed, backslash continuations joined."""
    joined = []
    buffer = ""
    start = None
    for number, line in fence.lines:
        if start is None:
            start = number
        code = split_comment(line)[0].rstrip()
        if code.endswith("\\"):
            buffer += code[:-1] + " "
            continue
        joined.append((start, buffer + code))
        buffer = ""
        start = None
    if start is not None:
        joined.append((start, buffer))
    return joined


def commands(unit: str) -> list[str]:
    """Split a unit into commands at `&&`, `||`, `;`, and `|`."""
    return [part.strip() for part in COMMAND_SEPARATOR.split(unit) if part.strip()]


def named_commands(text: str) -> list[tuple[int, str]]:
    """Each `cargo install` or `cargo binstall` command named in TEXT, with its offset."""
    named = []
    tokens = list(INSTALL_TOKEN.finditer(text))
    for position, token in enumerate(tokens):
        end = tokens[position + 1].start() if position + 1 < len(tokens) else len(text)
        tail = text[token.start() : end].replace("`", "")
        named.extend((token.start(), command) for command in commands(tail))
    return named


def command_units(document: Document) -> list[tuple[int, str]]:
    """Every rule 1 command, with the line it starts on."""
    units = []
    for fence in document.fences:
        for number, line in logical_lines(fence):
            units.extend((number, command) for command in commands(line))
        for number, comment in fence_comments(fence):
            units.extend((number, command) for _, command in named_commands(comment))
    for paragraph in document.paragraphs:
        for span in paragraph.spans:
            units.extend((span.line, command) for command in commands(span.content))
        joined_offset = 0
        for number, line in paragraph.lines:
            for offset, command in named_commands(line):
                absolute = joined_offset + offset
                if not any(span.start <= absolute < span.end for span in paragraph.spans):
                    units.append((number, command))
            joined_offset += len(line) + 1
    return units


def disabled_strategies(command: str) -> set[str]:
    """Strategies every `--disable-strategies` flag of COMMAND names."""
    values = set()
    for match in DISABLE_STRATEGIES.finditer(command):
        values.update(value.strip("\"'") for value in match.group(1).split(","))
    return values


def check_rule_1(document: Document, report: Report) -> None:
    for number, command in command_units(document):
        if not WALLET_TARGET.search(command):
            continue
        if CARGO_INSTALL.search(command) and not LOCKED.search(command):
            message = f"`cargo install` of a wallet crate without --locked: {command}"
            report.add(document.path, number, "1", message)
        if CARGO_BINSTALL.search(command):
            if not LOCKED.search(command):
                message = f"`cargo binstall` of a wallet crate without --locked: {command}"
                report.add(document.path, number, "1", message)
            if not REQUIRED_DISABLED_STRATEGIES <= disabled_strategies(command):
                message = (
                    "`cargo binstall` of a wallet crate without "
                    f"--disable-strategies quick-install,compile: {command}"
                )
                report.add(document.path, number, "1", message)
    for fence in document.fences:
        lines = logical_lines(fence)
        named = [line for _, line in lines] + [comment for _, comment in fence_comments(fence)]
        if not any(CLONES_WALLET.search(text) for text in named):
            continue
        for number, line in lines:
            for command in commands(line):
                if CARGO_BUILD.search(command) and not LOCKED.search(command):
                    message = (
                        "`cargo build` after a clone of this repository without --locked: "
                        f"{command}"
                    )
                    report.add(document.path, number, "1", message)


def check_rule_2(document: Document, version: str, report: Report) -> None:
    def differs(line: int, found: str, text: str) -> None:
        message = f"pin {found} differs from the workspace version {version}: {text}"
        report.add(document.path, line, "2", message)

    for index, line in enumerate(document.lines, start=1):
        for pattern in (CRATE_PIN, CLONE_PIN, RELEASE_TAG):
            for match in pattern.finditer(line):
                if match.group(1) != version:
                    differs(index, match.group(1), match.group(0))
        for match in VERSIONED_NAME.finditer(line):
            if not names_version(match.group(1), version):
                differs(index, match.group(1), match.group(0))


def names_version(name: str, version: str) -> bool:
    """Whether NAME, the text after `stellar-agent-`, starts with VERSION as rule 2 defines."""
    if name == version or name.startswith(f"{version}."):
        return True
    if not name.startswith(f"{version}-"):
        return False
    rest = name[len(version) + 1 :]
    return rest == "" or rest.startswith(tuple(f"{arch}-" for arch in RELEASE_ARCHITECTURES))


def check_rule_3(document: Document, report: Report) -> None:
    for index, line in enumerate(document.lines, start=1):
        for form, pattern in SEED_ASSIGNMENTS:
            match = pattern.search(line)
            if match:
                message = f"{form} assignment of a secret seed literal: {match.group(0).strip()}"
                report.add(document.path, index, "3", message)


def read_names(command: str) -> list[str]:
    """Names a secret `read` sets, or an empty list when COMMAND is not one."""
    words = command.split()
    while words and ASSIGNMENT.match(words[0]):
        words = words[1:]
    if not words or words[0] != "read":
        return []
    options = [word for word in words[1:] if word.startswith("-")]
    if not any("s" in option[1:] for option in options):
        return []
    return [word for word in words[1:] if not word.startswith("-") and IDENTIFIER.match(word)]


def unset_names(command: str) -> set[str]:
    """Names an `unset` command removes, or an empty set for any other command."""
    words = command.split()
    if not words or words[0] != "unset":
        return set()
    return {word for word in words[1:] if IDENTIFIER.match(word)}


def check_rule_3b(document: Document, report: Report) -> None:
    for fence_index, fence in enumerate(document.fences):
        lines = logical_lines(fence)
        for line_index, (number, line) in enumerate(lines):
            for command in commands(line):
                for name in read_names(command):
                    outcome = unset_outcome(document, fence_index, lines[line_index + 1 :], name)
                    if outcome is not None:
                        message = f"`read` of {name} with no later `unset {name}` {outcome}"
                        report.add(document.path, number, "3b", message)


def unset_outcome(
    document: Document, fence_index: int, rest: list[tuple[int, str]], name: str
) -> str | None:
    """Return None when an unset of NAME follows, else why the read fails."""
    if any(name in unset_names(command) for _, line in rest for command in commands(line)):
        return None
    fence = document.fences[fence_index]
    after = document.paragraph_after_fence.get(fence.open_line)
    if after is not None and any(
        name in unset_names(command) for span in after.spans for command in commands(span.content)
    ):
        return None
    boundary = next((heading for heading in document.headings if heading > fence.close_line), None)
    for later in document.fences[fence_index + 1 :]:
        if boundary is not None and later.open_line > boundary:
            break
        for _, line in logical_lines(later):
            for command in commands(line):
                if name in unset_names(command):
                    return None
                if name in read_names(command):
                    return f"before the next read of {name} (line {later.open_line})"
    if boundary is not None:
        return f"before the heading at line {boundary}"
    return "before the end of the file"


def check_rule_4(root: pathlib.Path, workspace: dict, report: Report) -> None:
    repository = workspace.get("workspace", {}).get("package", {}).get("repository")
    if repository != EXPECTED_REPOSITORY:
        message = (
            f"[workspace.package].repository is {repository!r}, expected {EXPECTED_REPOSITORY!r}"
        )
        report.add("Cargo.toml", None, "4", message)
    for manifest in WALLET_MANIFESTS:
        package = load_toml(root, manifest).get("package", {})
        if package.get("repository") != {"workspace": True}:
            message = (
                f"package.repository is {package.get('repository')!r}, "
                "expected { workspace = true }"
            )
            report.add(manifest, None, "4", message)
        binstall = package.get("metadata", {}).get("binstall")
        if binstall != EXPECTED_BINSTALL:
            prefix = "package.metadata.binstall"
            for difference in table_differences(prefix, binstall, EXPECTED_BINSTALL):
                report.add(manifest, None, "4", difference)


def table_differences(prefix: str, actual: object, expected: object) -> list[str]:
    """Describe each key path where ACTUAL differs from EXPECTED."""
    if isinstance(actual, dict) and isinstance(expected, dict):
        differences = []
        for key in sorted(set(actual) | set(expected)):
            if key not in actual:
                differences.append(f"{prefix}.{key} is missing")
            elif key not in expected:
                differences.append(f"{prefix}.{key} is not expected")
            else:
                differences.extend(table_differences(f"{prefix}.{key}", actual[key], expected[key]))
        return differences
    if actual != expected:
        return [f"{prefix} is {actual!r}, expected {expected!r}"]
    return []


def load_toml(root: pathlib.Path, relative: str) -> dict:
    try:
        with open(root / relative, "rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail_to_run(f"cannot read {relative}: {error}")


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        fail_to_run("usage: check-install-surface.py [ROOT]")
    root = pathlib.Path(argv[1] if len(argv) == 2 else ".").resolve()
    workspace = load_toml(root, "Cargo.toml")
    version = workspace.get("workspace", {}).get("package", {}).get("version")
    if not isinstance(version, str) or not re.fullmatch(SEMVER, version):
        manifest = root / "Cargo.toml"
        fail_to_run(f"[workspace.package].version in {manifest} is not a semver: {version!r}")
    report = Report()
    markdown = scanned_markdown(root)
    for relative in markdown:
        path = root / relative
        if not path.is_file():
            continue
        document = parse_markdown(relative, path.read_text(encoding="utf-8"))
        check_rule_1(document, report)
        check_rule_2(document, version, report)
        check_rule_3(document, report)
        check_rule_3b(document, report)
    check_rule_4(root, workspace, report)
    violations = report.lines()
    for violation in violations:
        print(violation)
    if violations:
        print(f"install surface: {len(violations)} violation(s)", file=sys.stderr)
        return 1
    manifests = 1 + len(WALLET_MANIFESTS)
    print(
        f"install surface: {len(markdown)} Markdown files and {manifests} manifests checked, "
        "no violations"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
