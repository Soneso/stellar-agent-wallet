#!/usr/bin/env python3
"""Compares regenerated crate archives with the verify job's SHA256SUMS.

Usage: ``compare-crate-sums.py <sums> <package-dir> <version>``

``<sums>`` comes from a job that ran dependency build scripts, so it is read
as data only. Every line must be ``<64 lowercase hex>  <name>-<version>.crate``
with two spaces and no path. Names must be unique, at least one entry must
exist, and the names must equal the ``*.crate`` files in ``<package-dir>`` in
both directions. Each listed hash must equal the sha256 of the file of that
name. Any other outcome fails.
"""

import hashlib
import os
import re
import stat
import sys

VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?")


class Mismatch(Exception):
    pass


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_sums(path, line_re):
    with open(path, "rb") as handle:
        raw = handle.read()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise Mismatch(f"{path}: not ASCII")
    if not text:
        raise Mismatch(f"{path}: empty")
    if not text.endswith("\n"):
        raise Mismatch(f"{path}: last line has no newline")
    entries = {}
    for number, line in enumerate(text[:-1].split("\n"), start=1):
        match = line_re.fullmatch(line)
        if match is None:
            raise Mismatch(f"{path}:{number}: malformed line {line!r}")
        digest, name = match.group(1), match.group(2)
        if name in entries:
            raise Mismatch(f"{path}:{number}: duplicate entry for {name}")
        entries[name] = digest
    return entries


def read_package_dir(path, name_re):
    crates = {}
    for entry in sorted(os.listdir(path)):
        if not entry.endswith(".crate"):
            continue
        if name_re.fullmatch(entry) is None:
            raise Mismatch(f"{path}: unexpected crate file name {entry!r}")
        full = os.path.join(path, entry)
        if not stat.S_ISREG(os.lstat(full).st_mode):
            raise Mismatch(f"{full}: not a regular file")
        crates[entry] = full
    return crates


def compare(sums_path, package_dir, version):
    if VERSION_RE.fullmatch(version) is None:
        raise Mismatch(f"version {version!r} does not match {VERSION_RE.pattern}")
    name = r"[a-z0-9_-]+-" + re.escape(version) + r"\.crate"
    line_re = re.compile(r"([0-9a-f]{64})  (" + name + r")")
    expected = read_sums(sums_path, line_re)
    actual = read_package_dir(package_dir, re.compile(name))
    missing = sorted(set(actual) - set(expected))
    extra = sorted(set(expected) - set(actual))
    if missing or extra:
        details = []
        if missing:
            details.append(f"regenerated but not in the sums: {', '.join(missing)}")
        if extra:
            details.append(f"in the sums but not regenerated: {', '.join(extra)}")
        raise Mismatch("; ".join(details))
    differing = []
    for crate in sorted(expected):
        digest = sha256_of(actual[crate])
        if digest != expected[crate]:
            differing.append(f"{crate}: sums {expected[crate]}, regenerated {digest}")
    if differing:
        raise Mismatch("hash mismatch: " + "; ".join(differing))
    return len(expected)


def main(argv):
    if len(argv) != 4:
        print(f"usage: {argv[0]} <sums> <package-dir> <version>", file=sys.stderr)
        return 2
    try:
        count = compare(argv[1], argv[2], argv[3])
    except (Mismatch, OSError) as err:
        print(f"refused: {err}", file=sys.stderr)
        return 1
    print(f"{count} crate archives match {argv[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
