#!/usr/bin/env python3
"""Per-crate line-coverage floor gate for the offline test suite.

Reads the ``llvm.coverage.json.export`` document produced by
``cargo llvm-cov --workspace ... --json`` and enforces a minimum line-coverage
percentage for each workspace crate. A crate's coverage is aggregated over every
instrumented file under ``crates/<crate>/src/`` (test and build files are
excluded).

The floors are a regression ratchet set a few points below the current offline
line coverage, not the aspirational 90% target. Several crates sit well below
90% because their remaining lines are live-network or on-chain paths exercised
only by the ``testnet-acceptance`` / ``testnet-integration`` suites, which do not
run in this offline gate; those crates carry an explicit lower floor. A crate
not listed here must clear ``DEFAULT_FLOOR``.

Usage: ``check-coverage.py <cov.json> --configuration feature-off|feature-on``
"""

import argparse
import collections
import fnmatch
import json
import pathlib
import re
import sys
import tomllib

# Minimum line-coverage percent per crate for the offline suite.
OFF_FLOORS = {
    "stellar-agent-anchor": 93,
    "stellar-agent-headless-keyring": 84,
    "stellar-agent-approval-remote": 83,
    "stellar-agent-approval-ui": 93,
    "stellar-agent-claimable": 94,
    "stellar-agent-cli": 42,
    "stellar-agent-core": 91,
    "stellar-agent-defi": 88,
    "stellar-agent-defindex": 60,
    "stellar-agent-sep5": 97,
    "stellar-agent-dex": 74,
    "stellar-agent-loopback-http": 95,
    "stellar-agent-mcp": 46,
    "stellar-agent-mcp-macros": 95,
    "stellar-agent-mpp": 90,
    "stellar-agent-network": 85,
    "stellar-agent-nonce": 95,
    "stellar-agent-pool": 88,
    "stellar-agent-sep10": 95,
    "stellar-agent-sep43": 95,
    "stellar-agent-sep45": 91,
    "stellar-agent-sep48": 93,
    "stellar-agent-sep53": 93,
    "stellar-agent-sep7": 93,
    "stellar-agent-smart-account": 67,
    "stellar-agent-soroban-auth": 95,
    "stellar-agent-stablecoin": 96,
    "stellar-agent-test-support": 92,
    "stellar-agent-toolsets": 93,
    "stellar-agent-toolsets-install": 91,
    "stellar-agent-toolsets-runtime": 91,
    "stellar-agent-webauthn-bridge": 89,
    "stellar-agent-windows-identity": 97,
    "stellar-agent-x402": 87,
    "stellar-agent-x402-identity": 87,
    "stellar-agent-xdr-limits": 97,
}

FLOORS = {"feature-off": OFF_FLOORS.copy(), "feature-on": OFF_FLOORS.copy()}

# A crate with no explicit entry must clear this floor. New crates that are
# legitimately testnet-covered below this bar must add an explicit entry above.
DEFAULT_FLOOR = 85

# The crate name is the one segment between `/crates/` and `/src/`, so a
# `crates` directory higher in the clone path and a `src` directory under
# `tests/` or `examples/` both fail to match.
CRATE_SRC = re.compile(r"/crates/([^/]+)/src/")


def crate_of(filename: str) -> str | None:
    """Returns the owning crate for a `crates/<crate>/src/...` path, else None."""
    match = CRATE_SRC.search(filename)
    return match.group(1) if match else None


EXEMPT_CRATE = "stellar-agent-smart-account-acceptance"
ROOT = pathlib.Path(__file__).resolve().parents[2]


def workspace_members(root):
    """Map manifest members to the directory names used in coverage reports."""
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    members = {}
    excluded = manifest["workspace"].get("exclude", [])
    for member in manifest["workspace"]["members"]:
        for path in sorted(root.glob(member)):
            if not (path / "Cargo.toml").is_file():
                continue
            if any(fnmatch.fnmatch(path.relative_to(root).as_posix(), pattern) for pattern in excluded):
                continue
            if path.name in members:
                raise ValueError(f"duplicate workspace member directory name: {path.name}")
            members[path.name] = path
    if not members:
        raise ValueError("workspace has no members with Cargo.toml after exclusions")
    return members


def comment_only(path):
    """The exemption lasts only while at least one Rust file contains comments alone."""
    files = list((path / "src").rglob("*.rs"))
    return bool(files) and all(
        not line.strip() or line.lstrip().startswith("//")
        for source in files for line in source.read_text().splitlines()
    )


def main(path: str, configuration: str, root=ROOT) -> int:
    floors = FLOORS[configuration]
    try:
        members = workspace_members(pathlib.Path(root))
        exempt = EXEMPT_CRATE in members and comment_only(members[EXEMPT_CRATE])
    except (OSError, ValueError, KeyError) as error:
        print(f"error: cannot read workspace sources: {error}", file=sys.stderr)
        return 1
    document = json.loads(pathlib.Path(path).read_text())
    # covered, total
    per_crate: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
    for export in document["data"]:
        for entry in export["files"]:
            crate = crate_of(entry["filename"])
            if crate is None:
                continue
            lines = entry["summary"]["lines"]
            per_crate[crate][0] += lines["covered"]
            per_crate[crate][1] += lines["count"]

    failures: list[str] = []
    unlisted: list[str] = []
    total_covered = total_lines = 0
    print(f"{'crate':38} {'covered/total':>15} {'line%':>8} {'floor':>6}  status")
    for crate in sorted(members.keys() | per_crate.keys()):
        covered, count = per_crate.get(crate, [0, 0])
        if crate == EXEMPT_CRATE and exempt and count == 0:
            print(f"{crate}: exempt while src contains only blank lines or // comments")
            continue
        if crate not in per_crate or count == 0:
            reason = "missing from report" if crate not in per_crate else "zero lines in report"
            if crate == EXEMPT_CRATE:
                reason += "; exemption ends when src has executable code or no .rs files"
            failures.append(f"{crate}: {reason}")
            print(f"{crate}: FAIL: {reason}")
            continue
        total_covered += covered
        total_lines += count
        pct = 100.0 * covered / count
        floor = floors.get(crate, DEFAULT_FLOOR)
        if crate not in floors:
            unlisted.append(crate)
        # 0.05 tolerance guards against float-formatting boundary noise.
        ok = pct >= floor - 0.05
        print(
            f"{crate:38} {f'{covered}/{count}':>15} {pct:7.2f}% {floor:>5}%  "
            f"{'ok' if ok else 'FAIL'}"
        )
        if not ok:
            failures.append(f"{crate}: {pct:.2f}% < floor {floor}%")

    workspace_pct = 100.0 * total_covered / total_lines if total_lines else 100.0
    print(f"{'-- workspace src total --':38} {f'{total_covered}/{total_lines}':>15} {workspace_pct:7.2f}%")

    for crate in unlisted:
        print(f"note: {crate} has no explicit floor; applied DEFAULT_FLOOR={DEFAULT_FLOOR}%")

    if failures:
        print("\ncoverage floor breached:")
        for line in failures:
            print(f"  {line}")
        return 1
    print("\nall crates meet their coverage floor")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path")
    parser.add_argument("--configuration", required=True, choices=tuple(FLOORS))
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    args = parser.parse_args()
    sys.exit(main(args.path, args.configuration, args.root))
