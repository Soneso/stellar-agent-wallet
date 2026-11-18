#!/usr/bin/env python3
"""Check that the docs-tests registry covers every documentation read.

Usage: check-docs-reads.py [--root ROOT] [--registry FILE] [--list]

The check scans the Rust sources of every workspace member for reads of a
documentation path, the paths .github/scripts/classify-docs-only.py treats as
documentation:

- ``docs/**/*.md``
- ``*.md`` at the repository root
- ``changelog.d/*.md``
- ``skills/stellar-agent-wallet/**/*.md``

The documentation directories are ``docs``, ``changelog.d``, and ``skills``
with their subdirectories.

It walks each target of each package from its root file through ``mod``
declarations, ``#[path]`` attributes, and ``include!``. The targets are
``src/lib.rs``, the binaries, the ``tests/`` targets, the examples, and the
build script (the ``build`` manifest key or ``build.rs``), which is
production code. The walk gives every function its full module path and its
target, and tells test code apart: a test target, a ``#[cfg(test)]`` module
and everything it declares or includes, and a function with a test
attribute.

These forms count as a documentation read:

- ``include_str!`` or ``include_bytes!`` of a documentation path, anywhere,
  in an attribute too. A plain literal resolves against the directory of the
  source file; ``concat!(env!("CARGO_MANIFEST_DIR"), "...")`` resolves
  against the package directory.
- A crate doc: an inner ``#![doc = include_str!(..)]`` outside any item at
  the top of a target's root file. Any other doc attribute that includes a
  documentation file, item-level ``#[doc = include_str!(..)]``, a module's
  inner doc, and ``cfg_attr`` forms included, is an include of the first
  kind, since a derive such as ``schemars`` compiles item documentation into
  the binary.
- A string literal in test code or in a build script that names a
  documentation path or directory. A literal resolves against the
  repository root and against the package directory, where cargo runs tests
  and build scripts. It counts in each of these shapes:
  - a path, such as ``"../../docs/mcp.md"``;
  - a slash-free documentation directory, such as ``"docs"`` for a
    ``read_dir`` walk or ``"skills"`` joined from parts, or a file that
    exists at the repository root, such as ``"README.md"``;
  - a prefix up to the first placeholder or wildcard (``{``, ``*``, ``?``)
    that names a documentation path or directory, such as
    ``"../../docs/{name}.md"`` or ``"../../docs/**/*.md"``;
  - a documentation directory component after a placeholder or wildcard,
    such as ``"{}/../../docs/guide.md"``;
  - a root documentation file after a placeholder or wildcard, reached
    through ``..`` only, such as ``"{}/../../README.md"`` or ``"../../*.md"``;
    a plain name counts when that file exists at the root.
  A literal with whitespace in the matched part is prose, not a path. The
  check treats every such literal as a read, whatever API reads it.

These forms stay invisible to the check:

- a test that walks the repository root and filters by extension;
- a test that calls a helper in another package where the helper holds the
  documentation path;
- an include whose file name arrives as a macro argument, such as
  ``include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/", $name))``;
- a proc macro that reads a documentation file while it expands, and an
  embedding crate that takes a directory, such as ``include_dir!``.

The full suite still covers them, as the workflow triggers set it: every
pull request into ``main`` runs the full ``ci.yml`` suite (``ci.yml:26-27``);
every push to ``mainnet-write`` or ``main`` runs the workspace tests of the
Coverage workflow, whose push trigger has no paths filter and whose
measuring jobs run on every push (``coverage.yml:21-22``, ``:48``); a push that
changes a path other than Markdown, ``LICENSE``, or ``.claude-plugin/**``
runs ``ci.yml`` (``ci.yml:15-25``). A push that changes only Markdown skips
``ci.yml``.

The registry ``.github/docs-tests.tsv`` holds one row per test: package,
target, and the exact test name with its module path. The target is ``lib``,
``bin:<name>``, ``test:<name>``, or ``doc`` for the doctests of a crate whose
crate docs include a documentation file; a ``doc`` row has ``-`` as its name.

The rules:

- A read in test code needs a row for every test that reaches it: the test
  itself, or every test of the same target that reaches the holding helper
  or constant through calls or references, transitively. The row must name
  the package, the test's target, and the test's full name, so a moved or
  retargeted test fails this check.
- An ``include_str!`` or ``include_bytes!`` of a documentation path outside
  test code, and any documentation path literal in a build script, fails: a
  documentation change must never change a built artifact. Only a crate-doc
  include needs a ``doc`` row instead.

The check prints each uncovered read as ``file:line: reason`` and exits 1. It
exits 2 on an unreadable registry or workspace. ``--list`` prints every read
it finds with the tests that reach it.
"""

import argparse
import fnmatch
import posixpath
import re
import sys
import tomllib
from pathlib import Path

REGISTRY = ".github/docs-tests.tsv"
DOC_DIRS = ("docs", "changelog.d", "skills")
TEST_ATTR = re.compile(r"^(?:[\w:]+::)?(?:test|rstest|test_case|wasm_bindgen_test)\b")
KEYWORDS = {"if", "while", "for", "match", "loop", "return", "fn", "let", "mut", "move", "async", "await",
            "unsafe", "impl", "where", "as", "in", "ref", "pub", "crate", "super", "self", "Self", "mod",
            "use", "struct", "enum", "trait", "type", "const", "static", "dyn", "else", "break", "continue",
            "Some", "None", "Ok", "Err", "assert", "assert_eq", "assert_ne", "format", "vec", "println",
            "panic", "matches", "concat", "env", "include_str", "include_bytes", "include", "cfg"}
INCLUDES = ("include_str", "include_bytes")


def is_documentation(path):
    """Whether one normalized repository-relative path is a documentation path."""
    if not path.endswith(".md"):
        return False
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    if len(parts) == 1:
        return True
    if parts[0] == "docs":
        return True
    if parts[0] == "changelog.d":
        return len(parts) == 2
    return parts[:2] == ["skills", "stellar-agent-wallet"] and len(parts) > 2


def is_documentation_dir(path):
    """Whether a path is a documentation directory or lies below one."""
    return any(path == top or path.startswith(top + "/") for top in DOC_DIRS)


def normalize(base, literal):
    """Returns the normalized repository-relative path of literal from base, or None outside the root."""
    joined = posixpath.normpath(posixpath.join(base, literal.lstrip("/")) if base else literal.lstrip("/"))
    if joined in (".", "..") or joined.startswith("../") or posixpath.isabs(joined):
        return None
    return joined


def literal_read(literal, bases, root_files):
    """Returns the documentation path or directory a test-code literal names, or None."""
    prefix = re.split(r"[{*?]", literal, maxsplit=1)[0]
    rest = literal[len(prefix):]
    if rest and not re.search(r"\s", literal):
        # After a placeholder or wildcard, a documentation directory component
        # marks a read, as in "{}/../../docs/guide.md".
        parts = re.sub(r"\{[^}]*\}", "\0", rest).split("/")
        for position, part in enumerate(parts):
            if part in DOC_DIRS:
                path = []
                for piece in parts[position:]:
                    if re.search(r"[\0*?]", piece):
                        break
                    path.append(piece)
                path = "/".join(path)
                return path if is_documentation(path) else part
        # A root documentation file, such as "{}/../../README.md" or "*.md":
        # a Markdown name reached through placeholders, wildcards, and ".."
        # only. A plain name counts when that file exists at the root, as
        # for a slash-free literal; a wildcard name always counts.
        tail = parts[-1]
        if tail.endswith(".md") and "\0" not in tail \
                and (tail in root_files or re.search(r"[*?]", tail)) \
                and all(piece in ("", ".", "..") for piece in prefix.split("/")) \
                and all(re.fullmatch(r"[\0*?]*|\.\.?", piece) for piece in parts[:-1]):
            return tail
    if not prefix or re.search(r"\s|}", prefix):
        return None
    for base in bases:
        path = normalize(base, prefix)
        if path is None:
            continue
        if "/" not in path and path not in root_files and path not in DOC_DIRS:
            continue
        if is_documentation(path) or is_documentation_dir(path):
            return path
    return None


# --- Tokenizer -------------------------------------------------------------

TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<line_comment>//[^\n]*)
  | (?P<block_comment>/\*)
  | (?P<raw>b?r(?P<hashes>\#*)")
  | (?P<string>b?"(?:\\.|[^"\\])*")
  | (?P<char>b?'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.)|[^'\\\n])')
  | (?P<lifetime>'[A-Za-z_]\w*)
  | (?P<ident>[A-Za-z_]\w*)
  | (?P<number>\d[\w.]*)
  | (?P<punct>::|=>|->|[{}()\[\]\#!;,.=<>&*:|+\-/%^@?$~])
""", re.VERBOSE | re.DOTALL)

ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", "'": "'", '"': '"'}


def unescape(body):
    out, index = [], 0
    while index < len(body):
        char = body[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        nxt = body[index + 1] if index + 1 < len(body) else ""
        if nxt == "\n":
            index += 2
            while index < len(body) and body[index] in " \t\n\r":
                index += 1
        elif nxt in ESCAPES:
            out.append(ESCAPES[nxt])
            index += 2
        elif nxt == "x":
            out.append(chr(int(body[index + 2:index + 4], 16)))
            index += 4
        elif nxt == "u":
            end = body.index("}", index)
            out.append(chr(int(body[index + 3:end], 16)))
            index = end + 1
        else:
            out.append(nxt)
            index += 2
    return "".join(out)


def tokenize(text):
    """Returns [(kind, value, line)] for Rust source; strings carry their decoded value."""
    tokens, position, line, length = [], 0, 1, len(text)
    while position < length:
        match = TOKEN.match(text, position)
        if not match:
            position += 1
            continue
        kind = match.lastgroup
        if kind == "hashes":
            kind = "raw"
        start = position
        if kind == "block_comment":
            depth, cursor = 1, position + 2
            while depth and cursor < length:
                if text.startswith("/*", cursor):
                    depth, cursor = depth + 1, cursor + 2
                elif text.startswith("*/", cursor):
                    depth, cursor = depth - 1, cursor + 2
                else:
                    cursor += 1
            position = cursor
        elif kind == "raw":
            hashes = match.group("hashes") or ""
            close = text.find('"' + hashes, match.end())
            close = length if close < 0 else close
            tokens.append(("string", text[match.end():close], line))
            position = close + 1 + len(hashes)
        elif kind == "string":
            body = match.group(0)
            body = body[2:-1] if body.startswith("b") else body[1:-1]
            tokens.append(("string", unescape(body), line))
            position = match.end()
        else:
            if kind in ("ident", "punct"):
                tokens.append((kind, match.group(0), line))
            position = match.end()
        line += text.count("\n", start, position)
    return tokens


def attribute_span(tokens, start):
    """Returns (text, end index, inner) of the attribute at tokens[start] == '#', or (None, start + 1, False)."""
    index = start + 1
    inner = index < len(tokens) and tokens[index][1] == "!"
    if inner:
        index += 1
    if index >= len(tokens) or tokens[index][1] != "[":
        return None, start + 1, False
    depth, parts = 0, []
    while index < len(tokens):
        kind, value, _ = tokens[index]
        if kind == "punct" and value == "[":
            depth += 1
        elif kind == "punct" and value == "]":
            depth -= 1
            if depth == 0:
                return " ".join(parts), index + 1, inner
        if depth >= 1 and not (depth == 1 and value == "[" and kind == "punct"):
            parts.append(value if kind != "string" else '"' + value + '"')
        index += 1
    return " ".join(parts), index, inner


def is_cfg_test(attribute):
    compact = attribute.replace(" ", "")
    return compact.startswith("cfg(") and re.search(r"(?<![\w!])test(?!\w)", compact) is not None \
        and "not(test)" not in compact


def closing(tokens, open_index):
    """Returns the index of the parenthesis that closes tokens[open_index]."""
    depth = 0
    for index in range(open_index, len(tokens)):
        if tokens[index][0] == "punct" and tokens[index][1] in "([{":
            depth += 1
        elif tokens[index][0] == "punct" and tokens[index][1] in ")]}":
            depth -= 1
            if depth == 0:
                return index
    return len(tokens) - 1


def include_path(tokens, index, file_dir, package_dir):
    """Returns the repository-relative path that include_str!/include_bytes! at index names, or None."""
    if index + 3 >= len(tokens) or tokens[index + 1][1] != "!" or tokens[index + 2][1] != "(":
        return None
    end = closing(tokens, index + 2)
    inner = tokens[index + 3:end]
    if inner and inner[0][0] == "string":
        return normalize(file_dir, inner[0][1])
    if len(inner) < 3 or inner[0][1] != "concat" or inner[1][1] != "!":
        return None
    base, pieces, cursor = file_dir, [], 3
    while cursor < len(inner) - 1:
        kind, value, _ = inner[cursor]
        if kind == "ident" and value == "env" and cursor + 3 < len(inner) and inner[cursor + 3][0] == "string":
            if inner[cursor + 3][1] != "CARGO_MANIFEST_DIR":
                return None
            base = package_dir
            cursor = closing(inner, cursor + 2) + 1
            continue
        if kind == "string":
            pieces.append(value)
        cursor += 1
    return normalize(base, "".join(pieces)) if pieces else None


# --- Packages and targets --------------------------------------------------

class Package:
    def __init__(self, root, directory):
        self.root, self.dir = root, directory
        manifest = tomllib.loads((root / directory / "Cargo.toml").read_text())
        self.name = manifest["package"]["name"]
        self.rel = directory.as_posix()
        base = root / directory
        self.targets = []
        lib = (manifest.get("lib") or {}).get("path", "src/lib.rs")
        if (base / lib).is_file():
            self.targets.append(("lib", posixpath.normpath(lib)))
        bins = manifest.get("bin") or []
        for entry in bins:
            path = entry.get("path") or (f"src/bin/{entry['name']}.rs" if entry["name"] != self.name
                                         else "src/main.rs")
            self.targets.append((f"bin:{entry['name']}", posixpath.normpath(path)))
        if not bins and (base / "src/main.rs").is_file():
            self.targets.append((f"bin:{self.name}", "src/main.rs"))
        if (base / "src/bin").is_dir():
            named = {t[1] for t in self.targets}
            for path in sorted((base / "src/bin").glob("*.rs")):
                if f"src/bin/{path.name}" not in named:
                    self.targets.append((f"bin:{path.stem}", f"src/bin/{path.name}"))
        tests = {}
        for entry in manifest.get("test") or []:
            tests[posixpath.normpath(entry.get("path") or f"tests/{entry['name']}.rs")] = entry["name"]
        if (base / "tests").is_dir():
            for path in sorted((base / "tests").iterdir()):
                if path.suffix == ".rs":
                    tests.setdefault(f"tests/{path.name}", path.stem)
                elif path.is_dir() and (path / "main.rs").is_file():
                    tests.setdefault(f"tests/{path.name}/main.rs", path.name)
        self.targets += [(f"test:{name}", path) for path, name in sorted(tests.items(), key=lambda i: i[1])]
        if (base / "examples").is_dir():
            for path in sorted((base / "examples").glob("*.rs")):
                self.targets.append((f"example:{path.stem}", f"examples/{path.name}"))
        # The build script is production code: its output is a built artifact.
        build = manifest["package"].get("build", "build.rs" if (base / "build.rs").is_file() else False)
        if isinstance(build, str) and (base / build).is_file():
            self.targets.append(("build", posixpath.normpath(build)))


class Holder:
    """A function, or a const or static outside a function, with the names it references."""

    def __init__(self, package, target, file, line, name, full, is_test):
        self.package, self.target, self.file, self.line = package, target, file, line
        self.name, self.full, self.is_test = name, full, is_test
        self.refs = set()


class Read:
    def __init__(self, package, target, file, line, path, kind, holder, in_test):
        self.package, self.target, self.file, self.line = package, target, file, line
        self.path, self.kind, self.holder, self.in_test = path, kind, holder, in_test


class Walker:
    """Walks the files of one target and records holders and reads."""

    def __init__(self, root, package, target, root_files, holders, reads, cache):
        self.root, self.package, self.target = root, package, target
        self.root_files, self.holders, self.reads, self.cache = root_files, holders, reads, cache
        self.root_file = dict(package.targets)[target]
        self.seen = set()

    def tokens(self, rel):
        if rel not in self.cache:
            path = self.root / self.package.rel / rel
            self.cache[rel] = tokenize(path.read_text(errors="replace")) if path.is_file() else None
        return self.cache[rel]

    def walk(self, rel, modpath, in_test, module_dir):
        """Walks one file whose items sit at modpath; module_dir holds its child module files."""
        key = (rel, tuple(modpath))
        tokens = self.tokens(rel)
        if tokens is None or key in self.seen:
            return
        self.seen.add(key)
        file = posixpath.join(self.package.rel, rel)
        file_dir = posixpath.dirname(file)
        bases = ("", self.package.rel)
        # Each scope: (kind, name, test, holder); kind is mod, fn, item, impl, or block.
        stack, attrs, pending = [], [], None
        file_test = in_test
        index = 0

        def testing():
            return file_test or any(scope[2] for scope in stack)

        def holder():
            for scope in reversed(stack):
                if scope[0] in ("fn", "item"):
                    return scope[3]
            return None

        def inline_mods():
            return [scope[1] for scope in stack if scope[0] == "mod"]

        while index < len(tokens):
            kind, value, line = tokens[index]
            if kind == "punct" and value == "#":
                text, end, inner = attribute_span(tokens, index)
                if text is not None:
                    if inner and is_cfg_test(text):
                        if stack:
                            stack[-1] = (stack[-1][0], stack[-1][1], True, stack[-1][3])
                        else:
                            file_test = True
                    elif not inner:
                        attrs.append(text)
                    # Only an inner doc attribute at the top of the target's
                    # root file documents the crate; a derive can compile any
                    # other doc attribute into the binary.
                    crate_doc = inner and text.startswith("doc") and not stack and rel == self.root_file
                    for cursor in range(index, end):
                        if tokens[cursor][0] == "ident" and tokens[cursor][1] in INCLUDES:
                            path = include_path(tokens, cursor, file_dir, self.package.rel)
                            if path and is_documentation(path):
                                self.reads.append(Read(
                                    self.package, self.target, file, tokens[cursor][2], path,
                                    "crate-doc include" if crate_doc else tokens[cursor][1] + "!",
                                    None if crate_doc else holder(), False if crate_doc else testing()))
                    index = end
                    continue
            if kind == "ident" and value == "mod" and index + 2 < len(tokens) and tokens[index + 1][0] == "ident":
                name = tokens[index + 1][1]
                cfg_test = any(is_cfg_test(a) for a in attrs)
                path_attr = next((m.group(1) for a in attrs
                                  for m in [re.match(r'path = "([^"]*)"', a)] if m), None)
                if tokens[index + 2][1] == ";":
                    inline = inline_mods()
                    if path_attr:
                        child = posixpath.normpath(posixpath.join(posixpath.dirname(rel), *inline, path_attr)) \
                            if not inline else posixpath.normpath(posixpath.join(module_dir, *inline, path_attr))
                        child_dir = posixpath.dirname(child) if posixpath.basename(child) == "mod.rs" \
                            else posixpath.join(posixpath.dirname(child), posixpath.basename(child)[:-3])
                    else:
                        child_dir = posixpath.join(module_dir, *inline, name)
                        child = child_dir + ".rs"
                        if self.tokens(child) is None:
                            child = posixpath.join(child_dir, "mod.rs")
                    self.walk(child, modpath + inline + [name], testing() or cfg_test, child_dir)
                    attrs, index = [], index + 3
                    continue
                pending = ("mod", name, cfg_test)
                attrs, index = [], index + 2
                continue
            if kind == "ident" and value == "fn" and index + 1 < len(tokens) and tokens[index + 1][0] == "ident":
                name = tokens[index + 1][1]
                is_test = any(TEST_ATTR.match(a.replace(" ", "")) for a in attrs)
                pending = ("fn", name, any(is_cfg_test(a) for a in attrs) or is_test, is_test, line)
                attrs, index = [], index + 2
                continue
            if kind == "ident" and value in ("impl", "trait") and pending is None:
                pending = ("impl", None, any(is_cfg_test(a) for a in attrs))
                attrs = []
            if kind == "ident" and value in ("const", "static") and pending is None and holder() is None \
                    and index + 1 < len(tokens) and tokens[index + 1][0] == "ident" \
                    and tokens[index + 1][1] not in ("fn", "mut", "unsafe", "async", "extern"):
                name = tokens[index + 1][1]
                item = Holder(self.package, self.target, file, line, name,
                              "::".join(modpath + inline_mods() + [name]), False)
                self.holders.append(item)
                stack.append(("item", name, any(is_cfg_test(a) for a in attrs), item))
                attrs, index = [], index + 2
                continue
            if kind == "ident" and value == "include" and index + 3 < len(tokens) \
                    and tokens[index + 1][1] == "!" and tokens[index + 3][0] == "string":
                child = posixpath.normpath(posixpath.join(posixpath.dirname(rel), tokens[index + 3][1]))
                self.walk(child, modpath + inline_mods(), testing(), posixpath.join(module_dir, *inline_mods()))
                index += 4
                continue
            if kind == "ident" and value in INCLUDES:
                path = include_path(tokens, index, file_dir, self.package.rel)
                if path and is_documentation(path):
                    self.reads.append(Read(self.package, self.target, file, line, path, value + "!",
                                           holder(), testing()))
                index = closing(tokens, index + 2) + 1 if index + 2 < len(tokens) else index + 1
                continue
            if kind == "ident":
                current = holder()
                if current is not None and value not in KEYWORDS and value != current.name:
                    current.refs.add(value)
            if kind == "string" and (testing() or self.target == "build"):
                path = literal_read(value, bases, self.root_files)
                if path and self.target == "build":
                    # A build script reads at run time through any API, and its
                    # output is a built artifact.
                    self.reads.append(Read(self.package, self.target, file, line, path,
                                           "build-script string literal", holder(), False))
                elif path:
                    self.reads.append(Read(self.package, self.target, file, line, path, "string literal",
                                           holder(), True))
            if kind == "punct" and value == "{":
                if pending is not None and pending[0] == "fn":
                    _, name, test, is_test, fn_line = pending
                    item = Holder(self.package, self.target, file, fn_line, name,
                                  "::".join(modpath + inline_mods() + [name]), is_test)
                    self.holders.append(item)
                    stack.append(("fn", name, test, item))
                elif pending is not None:
                    stack.append((pending[0], pending[1], pending[2], None))
                else:
                    stack.append(("block", None, False, None))
                pending, attrs = None, []
            elif kind == "punct" and value == "}":
                if stack:
                    stack.pop()
            elif kind == "punct" and value == ";":
                if stack and stack[-1][0] == "item":
                    stack.pop()
                if pending is not None and pending[0] == "fn":
                    pending = None
                attrs = []
            index += 1


def workspace_members(root):
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    members = []
    for pattern in manifest.get("workspace", {}).get("members", []):
        members.extend(sorted(p.relative_to(root) for p in root.glob(pattern) if (p / "Cargo.toml").is_file()))
    excluded = manifest.get("workspace", {}).get("exclude", [])
    return [m for m in members if not any(fnmatch.fnmatch(m.as_posix(), e) for e in excluded)]


def analyse(root):
    """Returns (packages, holders, reads) for the workspace at root."""
    packages, holders, reads = [], [], []
    root_files = {path.name for path in root.iterdir() if path.is_file()}
    for directory in workspace_members(root):
        package = Package(root, directory)
        packages.append(package)
        cache = {}
        for target, root_file in package.targets:
            walker = Walker(root, package, target, root_files, holders, reads, cache)
            module_dir = posixpath.dirname(root_file)
            walker.walk(root_file, [], target.startswith("test:"), module_dir)
    return packages, holders, reads


def reaching_tests(read, holders):
    """Returns the tests of the read's target that reach the read's holder."""
    if read.holder is None:
        return []
    if read.holder.is_test:
        return [read.holder]
    same = [h for h in holders if h.package is read.package and h.target == read.target]
    names, frontier = {read.holder.name}, [read.holder.name]
    while frontier:
        name = frontier.pop()
        for holder in same:
            if name in holder.refs and holder.name not in names and not holder.is_test:
                names.add(holder.name)
                frontier.append(holder.name)
    return [h for h in same if h.is_test and h.refs & names]


def load_registry(path):
    rows, problems = [], []
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) != 3 or not all(fields):
            problems.append(f"{path.name}:{number}: expected package, target, and test name separated by tabs")
            continue
        package, target, name = fields
        if not (target in ("lib", "doc") or re.fullmatch(r"(bin|test):[\w-]+", target)):
            problems.append(f"{path.name}:{number}: unknown target {target}")
        if (target == "doc") != (name == "-"):
            problems.append(f"{path.name}:{number}: a doc row, and only a doc row, has - as its test name")
        rows.append((package, target, name, number))
    return rows, problems


def check(root, registry_path, listing=False):
    try:
        rows, problems = load_registry(registry_path)
    except OSError as err:
        print(f"check-docs-reads: cannot read {registry_path}: {err}", file=sys.stderr)
        return 2
    try:
        packages, holders, reads = analyse(root)
    except (OSError, KeyError, tomllib.TOMLDecodeError) as err:
        print(f"check-docs-reads: cannot read the workspace: {err}", file=sys.stderr)
        return 2
    names = {p.name for p in packages}
    registered = {(r[0], r[1], r[2]) for r in rows}
    for package, _, _, number in rows:
        if package not in names:
            problems.append(f"{registry_path.name}:{number}: {package} is not a workspace member")
    # A file that several targets compile yields one read per target; a test
    # is covered when one of its targets has its row.
    grouped = {}
    for read in reads:
        grouped.setdefault((read.file, read.line, read.path, read.kind), []).append(read)
    uncovered = []
    for (file, line, path, kind), instances in grouped.items():
        where = f"{file}:{line}"
        package = instances[0].package
        if kind == "crate-doc include":
            if (package.name, "doc", "-") not in registered:
                uncovered.append(f"{where}: crate docs include {path}; add: {package.name}\tdoc\t-")
            elif listing:
                print(f"{where}: {path}: doctests of {package.name}")
            continue
        if kind != "string literal" and not any(r.in_test for r in instances):
            uncovered.append(f"{where}: {kind} of {path} outside test code; a documentation change must "
                             f"never change a built artifact")
            continue
        tests = {}
        for read in instances:
            for test in reaching_tests(read, holders):
                tests.setdefault((test.file, test.line, test.name), []).append(test)
        if not tests:
            holder = instances[0].holder.name if instances[0].holder else "module scope"
            uncovered.append(f"{where}: {kind} of {path} in {holder}, which no test of {package.name} reaches")
            continue
        for (test_file, test_line, test_name), variants in sorted(tests.items()):
            if any((package.name, v.target, v.full) in registered for v in variants):
                if listing:
                    print(f"{where}: {path}: {package.name} {variants[0].target} {variants[0].full}")
                continue
            wanted = "; ".join(f"{package.name}\t{v.target}\t{v.full}" for v in variants)
            uncovered.append(f"{where}: {kind} of {path} in test {test_name} ({test_file}:{test_line}) "
                             f"has no registry row; add: {wanted}")
    for problem in problems:
        print(problem)
    for problem in sorted(set(uncovered)):
        print(problem)
    if problems or uncovered:
        print(f"check-docs-reads: {len(set(uncovered))} uncovered read(s), {len(problems)} registry problem(s)")
        return 1
    print(f"check-docs-reads: {len(grouped)} documentation reads covered by {len(rows)} registry rows")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    registry = args.registry or args.root / REGISTRY
    return check(args.root, registry, args.list)


if __name__ == "__main__":
    sys.exit(main())
