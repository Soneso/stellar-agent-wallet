#!/usr/bin/env python3
"""Keep the maintainer guide's gate-tool versions aligned with CI."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ("cargo-llvm-cov", "cargo-machete", "cargo-deny")


def one_match(pattern: str, text: str, source: str, tool: str) -> str:
    matches = re.findall(pattern, text, flags=re.MULTILINE)
    if len(matches) != 1:
        raise ValueError(f"expected one {tool} version in {source}, found {len(matches)}")
    return matches[0]


def main() -> int:
    guide = (ROOT / "docs/maintainers/building.md").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    failed = False

    for tool in TOOLS:
        documented = one_match(
            rf"^cargo install --locked {re.escape(tool)} --version ([^\s]+)$",
            guide,
            "docs/maintainers/building.md",
            tool,
        )
        configured = one_match(
            rf"^\s*tool:\s*{re.escape(tool)}@([^\s#]+)\s*$",
            workflow,
            ".github/workflows/ci.yml",
            tool,
        )
        if documented != configured:
            print(f"{tool}: guide says {documented}, CI uses {configured}", file=sys.stderr)
            failed = True

    if failed:
        return 1
    print("Maintainer guide gate-tool versions match CI.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
