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

Usage: ``check-coverage.py <cov.json>``
"""

import collections
import json
import pathlib
import sys

# Minimum line-coverage percent per crate for the offline suite.
FLOORS = {
    "stellar-agent-anchor": 93,
    "stellar-agent-approval-remote": 83,
    "stellar-agent-approval-ui": 93,
    "stellar-agent-blend": 76,
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
    "stellar-agent-network": 85,
    "stellar-agent-nonce": 95,
    "stellar-agent-pool": 88,
    "stellar-agent-sep10": 93,
    "stellar-agent-sep43": 95,
    "stellar-agent-sep45": 91,
    "stellar-agent-sep48": 93,
    "stellar-agent-sep53": 93,
    "stellar-agent-sep7": 93,
    "stellar-agent-smart-account": 67,
    "stellar-agent-stablecoin": 96,
    "stellar-agent-test-support": 92,
    "stellar-agent-toolsets": 93,
    "stellar-agent-toolsets-install": 91,
    "stellar-agent-toolsets-runtime": 91,
    "stellar-agent-webauthn-bridge": 89,
    "stellar-agent-windows-identity": 97,
    "stellar-agent-x402": 67,
    "stellar-agent-x402-identity": 83,
    "stellar-agent-xdr-limits": 97,
}

# A crate with no explicit entry must clear this floor. New crates that are
# legitimately testnet-covered below this bar must add an explicit entry above.
DEFAULT_FLOOR = 85


def crate_of(filename: str) -> str | None:
    """Returns the owning crate for a `crates/<crate>/src/...` path, else None."""
    if "/crates/" not in filename or "/src/" not in filename:
        return None
    return filename.split("/crates/", 1)[1].split("/", 1)[0]


def main(path: str) -> int:
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

    if not per_crate:
        print("error: no crate source files found in the coverage document", file=sys.stderr)
        return 2

    failures: list[str] = []
    unlisted: list[str] = []
    total_covered = total_lines = 0
    print(f"{'crate':38} {'covered/total':>15} {'line%':>8} {'floor':>6}  status")
    for crate in sorted(per_crate):
        covered, count = per_crate[crate]
        total_covered += covered
        total_lines += count
        pct = 100.0 * covered / count if count else 100.0
        floor = FLOORS.get(crate, DEFAULT_FLOOR)
        if crate not in FLOORS:
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
    if len(sys.argv) != 2:
        print("usage: check-coverage.py <cov.json>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
