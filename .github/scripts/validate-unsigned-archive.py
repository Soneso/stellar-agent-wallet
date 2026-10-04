#!/usr/bin/env python3
"""Validates and unpacks the unsigned macOS binaries handed to the signing job.

Usage: ``validate-unsigned-archive.py <tar> <out-dir> <arch>``

The archive comes from a build job that ran dependency build scripts, so its
content is untrusted. The archive must be an uncompressed tar holding exactly
two regular-file members named ``stellar-agent`` and ``stellar-agent-mcp``.
Each member must be a thin 64-bit Mach-O executable for ``<arch>``
(``arm64`` or ``x86_64``); the script refuses a fat binary, and it refuses a
damaged tar before it writes anything. It writes the members into
``<out-dir>``, which must not exist yet, with mode 0755. It executes nothing
and does not use tarfile's own extraction, so member paths, links, and owners
never reach the file system.

Runs on Python 3.9 and later (``/usr/bin/python3`` on the macOS runner).
"""

import os
import shutil
import struct
import sys
import tarfile

EXPECTED_MEMBERS = ("stellar-agent", "stellar-agent-mcp")
MH_MAGIC_64 = 0xFEEDFACF
MH_EXECUTE = 0x2
FAT_MAGICS = {0xCAFEBABE, 0xCAFEBABF, 0xBEBAFECA, 0xBFBAFECA}
CPU_TYPES = {"arm64": 0x0100000C, "x86_64": 0x01000007}
# Upper bound per member; release binaries are much smaller.
MAX_MEMBER_BYTES = 512 * 1024 * 1024
CHUNK = 1024 * 1024


class Refusal(Exception):
    pass


def check_macho(name, header, cputype):
    if len(header) < 32:
        raise Refusal(f"{name}: shorter than a Mach-O header")
    (magic_be,) = struct.unpack(">I", header[:4])
    if magic_be in FAT_MAGICS:
        raise Refusal(f"{name}: fat binary; a thin binary for one architecture is required")
    magic, cpu, _subtype, filetype = struct.unpack("<IIII", header[:16])
    if magic != MH_MAGIC_64:
        raise Refusal(f"{name}: not a little-endian 64-bit Mach-O file (magic 0x{magic_be:08x})")
    if cpu != cputype:
        raise Refusal(f"{name}: cputype 0x{cpu:08x}, expected 0x{cputype:08x}")
    if filetype != MH_EXECUTE:
        raise Refusal(f"{name}: Mach-O file type {filetype}, expected an executable")


def checked_members(archive, cputype):
    # getmembers reads every header and raises a TarError when a member's
    # data is cut short, so every member is complete once it returns.
    members = archive.getmembers()
    names = [m.name for m in members]
    if len(members) != len(EXPECTED_MEMBERS) or sorted(names) != sorted(EXPECTED_MEMBERS):
        raise Refusal(f"archive members {names}, expected exactly {list(EXPECTED_MEMBERS)}")
    for member in members:
        if not member.isreg() or member.issparse():
            raise Refusal(f"{member.name}: not a regular file")
        if member.size > MAX_MEMBER_BYTES:
            raise Refusal(f"{member.name}: {member.size} bytes exceeds {MAX_MEMBER_BYTES}")
        check_macho(member.name, archive.extractfile(member).read(32), cputype)
    return members


def validate(tar_path, out_dir, arch):
    if arch not in CPU_TYPES:
        raise Refusal(f"unknown architecture {arch!r}; expected one of {sorted(CPU_TYPES)}")
    try:
        archive = tarfile.open(tar_path, mode="r:")
    except (tarfile.TarError, OSError) as err:
        raise Refusal(f"{tar_path}: not a readable uncompressed tar: {err}")
    with archive:
        try:
            members = checked_members(archive, CPU_TYPES[arch])
        except tarfile.TarError as err:
            raise Refusal(f"{tar_path}: damaged tar: {err}")
        os.mkdir(out_dir, 0o700)
        for member in members:
            target = os.path.join(out_dir, member.name)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
            with os.fdopen(fd, "wb") as out:
                shutil.copyfileobj(archive.extractfile(member), out, CHUNK)
                os.fchmod(out.fileno(), 0o755)


def main(argv):
    if len(argv) != 4:
        print(f"usage: {argv[0]} <tar> <out-dir> <arch>", file=sys.stderr)
        return 2
    tar_path, out_dir, arch = argv[1:]
    try:
        validate(tar_path, out_dir, arch)
    except Refusal as err:
        print(f"refused: {err}", file=sys.stderr)
        return 1
    except FileExistsError as err:
        print(f"refused: {err.filename} already exists", file=sys.stderr)
        return 1
    except OSError as err:
        print(f"refused: {err}", file=sys.stderr)
        return 1
    print(f"validated {', '.join(EXPECTED_MEMBERS)} for {arch} into {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
