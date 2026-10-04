#!/usr/bin/env python3
"""Offline regression checks for compare-crate-sums.py.

Each case builds a package directory of fake crate archives and a sums file,
applies one change, runs the comparison, and checks the exit status and the
message.
"""

import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile

SCRIPT = pathlib.Path(__file__).resolve().parent / "compare-crate-sums.py"
VERSION = "1.2.3-alpha.4"
CRATES = {
    f"stellar-agent-core-{VERSION}.crate": b"core archive bytes",
    f"stellar-agent-cli-{VERSION}.crate": b"cli archive bytes",
    f"stellar_agent_x-{VERSION}.crate": b"underscore name",
}


def sums_text(crates):
    return "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(crates.items()))


def flip_byte(data):
    return bytes([data[0] ^ 1]) + data[1:]


def case_equal(pkg, crates, sums):
    return sums


def case_changed_byte(pkg, crates, sums):
    name = f"stellar-agent-core-{VERSION}.crate"
    (pkg / name).write_bytes(flip_byte(crates[name]))
    return sums


def case_regenerated_missing_from_sums(pkg, crates, sums):
    (pkg / f"stellar-agent-new-{VERSION}.crate").write_bytes(b"new")
    return sums


def case_sums_entry_without_crate(pkg, crates, sums):
    (pkg / f"stellar-agent-cli-{VERSION}.crate").unlink()
    return sums


def case_duplicate(pkg, crates, sums):
    return sums + sums.splitlines(keepends=True)[0]


def case_malformed(pkg, crates, sums):
    return sums + "not a sums line\n"


def case_slash(pkg, crates, sums):
    digest = hashlib.sha256(crates[f"stellar-agent-core-{VERSION}.crate"]).hexdigest()
    return sums + f"{digest}  target/package/stellar-agent-core-{VERSION}.crate\n"


def case_one_space(pkg, crates, sums):
    return sums.replace("  ", " ", 1)


def case_uppercase_hex(pkg, crates, sums):
    first, rest = sums.split("  ", 1)
    return first.upper() + "  " + rest


def case_crlf(pkg, crates, sums):
    return sums.replace("\n", "\r\n")


def case_no_final_newline(pkg, crates, sums):
    return sums[:-1]


def case_empty(pkg, crates, sums):
    for name in crates:
        (pkg / name).unlink()
    return ""


def case_other_version(pkg, crates, sums):
    return sums.replace(f"stellar-agent-cli-{VERSION}", "stellar-agent-cli-9.9.9")


def case_symlink_crate(pkg, crates, sums):
    name = f"stellar-agent-cli-{VERSION}.crate"
    target = pkg.parent / "elsewhere.crate"
    target.write_bytes(crates[name])
    (pkg / name).unlink()
    os.symlink(target, pkg / name)
    return sums


def case_unexpected_crate_name(pkg, crates, sums):
    (pkg / "README.crate").write_bytes(b"x")
    return sums


CASES = [
    ("equal sets", case_equal, VERSION, 0, "3 crate archives match"),
    ("one changed byte", case_changed_byte, VERSION, 1, "hash mismatch: stellar-agent-core"),
    ("regenerated crate missing from the sums", case_regenerated_missing_from_sums, VERSION, 1,
     "regenerated but not in the sums: stellar-agent-new"),
    ("sums entry with no crate", case_sums_entry_without_crate, VERSION, 1,
     "in the sums but not regenerated: stellar-agent-cli"),
    ("duplicate entry", case_duplicate, VERSION, 1, "duplicate entry"),
    ("malformed line", case_malformed, VERSION, 1, "malformed line"),
    ("name containing /", case_slash, VERSION, 1, "malformed line"),
    ("one space separator", case_one_space, VERSION, 1, "malformed line"),
    ("uppercase hex", case_uppercase_hex, VERSION, 1, "malformed line"),
    ("CRLF line endings", case_crlf, VERSION, 1, "malformed line"),
    ("no final newline", case_no_final_newline, VERSION, 1, "last line has no newline"),
    ("empty sums and no crates", case_empty, VERSION, 1, "empty"),
    ("entry for another version", case_other_version, VERSION, 1, "malformed line"),
    ("symlinked crate", case_symlink_crate, VERSION, 1, "not a regular file"),
    ("unexpected crate file name", case_unexpected_crate_name, VERSION, 1, "unexpected crate file name"),
    ("version argument with a shell metacharacter", case_equal, "1.2.3;true", 1, "does not match"),
]


def main():
    failures = []
    for label, mutate, version, want_rc, fragment in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            pkg = tmp / "package"
            pkg.mkdir()
            (pkg / "tmp-registry").mkdir()
            for name, data in CRATES.items():
                (pkg / name).write_bytes(data)
            sums = mutate(pkg, CRATES, sums_text(CRATES))
            sums_path = tmp / "SHA256SUMS"
            sums_path.write_bytes(sums.encode("ascii"))
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(sums_path), str(pkg), version],
                capture_output=True, text=True, check=False,
            )
            output = result.stdout + result.stderr
            if result.returncode != want_rc or fragment not in output:
                failures.append(f"{label}: exit {result.returncode} (expected {want_rc}), "
                                f"expected {fragment!r}: {output.strip()}")
            else:
                print(f"ok   {label}")
    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"{len(failures)} compare-crate-sums case(s) failed", file=sys.stderr)
        return 1
    print("compare-crate-sums tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
