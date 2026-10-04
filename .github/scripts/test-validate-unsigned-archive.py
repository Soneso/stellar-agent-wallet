#!/usr/bin/env python3
"""Offline regression checks for validate-unsigned-archive.py.

Each case builds a tar fixture with tarfile and 32-byte Mach-O header stubs,
runs the validator, and checks the exit status, the message, and the files
it writes. Runs on Linux and macOS with Python 3.9 or later.
"""

import io
import os
import pathlib
import struct
import subprocess
import sys
import tarfile
import tempfile

SCRIPT = pathlib.Path(__file__).resolve().parent / "validate-unsigned-archive.py"
ARM64 = 0x0100000C
X86_64 = 0x01000007


def macho(cputype=ARM64, magic=0xFEEDFACF, filetype=2, body=b"payload"):
    return struct.pack("<IIIIIIII", magic, cputype, 0, filetype, 0, 0, 0, 0) + body


def fat():
    return struct.pack(">II", 0xCAFEBABE, 2) + b"\0" * 24 + b"payload"


def regular(name, data):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o755
    return info, data


def link(name, target, kind):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = target
    return info, None


def directory(name):
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    return info, None


def write_tar(path, entries, mode="w"):
    with tarfile.open(path, mode, format=tarfile.USTAR_FORMAT) as archive:
        for info, data in entries:
            archive.addfile(info, io.BytesIO(data) if data is not None else None)


def both(cli=None, mcp=None):
    return [
        regular("stellar-agent", cli if cli is not None else macho(body=b"cli")),
        regular("stellar-agent-mcp", mcp if mcp is not None else macho(body=b"mcp")),
    ]


CASES = [
    # name, entries, arch, expected exit, message fragment, tar mode
    ("valid arm64 archive", both(), "arm64", 0, "validated", "w"),
    ("valid x86_64 archive", both(macho(X86_64), macho(X86_64)), "x86_64", 0, "validated", "w"),
    ("symlink member", [link("stellar-agent", "/etc/passwd", tarfile.SYMTYPE), both()[1]],
     "arm64", 1, "not a regular file", "w"),
    ("hard link member", [both()[1], link("stellar-agent", "stellar-agent-mcp", tarfile.LNKTYPE)],
     "arm64", 1, "not a regular file", "w"),
    ("extra member", both() + [regular("README.md", b"text")], "arm64", 1, "archive members", "w"),
    ("member under .github/", both() + [regular(".github/actions/macos-sign-notarize/action.yml", b"x")],
     "arm64", 1, "archive members", "w"),
    ("member under .github/ in place of a binary",
     [both()[0], regular(".github/actions/macos-sign-notarize/action.yml", macho())],
     "arm64", 1, "archive members", "w"),
    ("directory member", [directory("stellar-agent"), both()[1]], "arm64", 1, "not a regular file", "w"),
    ("wrong architecture", both(macho(X86_64), macho(X86_64)), "arm64", 1, "cputype", "w"),
    ("one binary with the wrong architecture", both(mcp=macho(X86_64)), "arm64", 1, "cputype", "w"),
    ("fat header", both(fat(), macho()), "arm64", 1, "fat binary", "w"),
    ("32-bit Mach-O", both(macho(magic=0xFEEDFACE)), "arm64", 1, "64-bit Mach-O", "w"),
    ("not an executable", both(macho(filetype=6)), "arm64", 1, "expected an executable", "w"),
    ("truncated header", both(b"\xcf\xfa\xed\xfe"), "arm64", 1, "shorter than a Mach-O header", "w"),
    ("dot-slash member names", [regular("./stellar-agent", macho()), regular("./stellar-agent-mcp", macho())],
     "arm64", 1, "archive members", "w"),
    ("parent-directory member name", [regular("../stellar-agent", macho()), both()[1]],
     "arm64", 1, "archive members", "w"),
    ("duplicate member", [both()[0], both()[0]], "arm64", 1, "archive members", "w"),
    ("compressed tar", both(), "arm64", 1, "not a readable uncompressed tar", "w:gz"),
    ("unknown architecture argument", both(), "ppc64", 1, "unknown architecture", "w"),
]


def run(tar_path, out_dir, arch):
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(tar_path), str(out_dir), arch],
        capture_output=True, text=True, check=False,
    )


def main():
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        for index, (label, entries, arch, want_rc, fragment, mode) in enumerate(CASES):
            tar_path = tmp / f"case{index}.tar"
            out_dir = tmp / f"out{index}"
            write_tar(tar_path, entries, mode)
            result = run(tar_path, out_dir, arch)
            output = result.stdout + result.stderr
            problems = []
            if result.returncode != want_rc:
                problems.append(f"exit {result.returncode}, expected {want_rc}")
            if fragment not in output:
                problems.append(f"output lacks {fragment!r}")
            if want_rc == 0:
                for info, data in entries:
                    written = out_dir / info.name
                    if not written.is_file() or written.is_symlink():
                        problems.append(f"{info.name} not written as a regular file")
                        continue
                    if written.read_bytes() != data:
                        problems.append(f"{info.name} content differs")
                    if written.stat().st_mode & 0o777 != 0o755:
                        problems.append(f"{info.name} mode {oct(written.stat().st_mode & 0o777)}")
                if sorted(os.listdir(out_dir)) != ["stellar-agent", "stellar-agent-mcp"]:
                    problems.append(f"output directory holds {sorted(os.listdir(out_dir))}")
            elif out_dir.exists():
                problems.append("output directory created for a refused archive")
            if problems:
                failures.append(f"{label}: {'; '.join(problems)}: {output.strip()}")
            else:
                print(f"ok   {label}")

        label = "existing output directory"
        tar_path = tmp / "existing.tar"
        out_dir = tmp / "existing"
        out_dir.mkdir()
        write_tar(tar_path, both())
        result = run(tar_path, out_dir, "arm64")
        output = result.stdout + result.stderr
        if result.returncode != 1 or "already exists" not in output or os.listdir(out_dir):
            failures.append(f"{label}: exit {result.returncode}: {output.strip()}")
        else:
            print(f"ok   {label}")

        label = "archive cut short inside a member"
        tar_path = tmp / "truncated.tar"
        out_dir = tmp / "truncated"
        write_tar(tar_path, both(mcp=macho(body=b"m" * 2000)))
        with tarfile.open(tar_path) as archive:
            cut = archive.getmember("stellar-agent-mcp").offset_data + 100
        with open(tar_path, "r+b") as handle:
            handle.truncate(cut)
        result = run(tar_path, out_dir, "arm64")
        output = result.stdout + result.stderr
        if result.returncode != 1 or "refused:" not in output or "damaged tar" not in output \
                or "Traceback" in output or out_dir.exists():
            failures.append(f"{label}: exit {result.returncode}: {output.strip()}")
        else:
            print(f"ok   {label}")

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"{len(failures)} validate-unsigned-archive case(s) failed", file=sys.stderr)
        return 1
    print("validate-unsigned-archive tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
