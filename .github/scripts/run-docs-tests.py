#!/usr/bin/env python3
"""Run the tests that read documentation, as .github/docs-tests.tsv lists them.

Usage: run-docs-tests.py [--no-default-features] [--features LIST]
                         [--registry FILE] [--cargo-flag FLAG ...] [--dry-run]

The feature arguments are those of a ci.yml test job. Each package receives
the listed features it declares, so one argument set serves every package.

For each package of the registry, in order, the script runs:

1. ``cargo check --all-targets -p PACKAGE``, so a renamed or deleted file that
   an ``include_str!`` names fails.
2. For each target, ``cargo test -p PACKAGE <target> -- --exact NAME ...`` with
   every listed name of that target. The run must report one test result
   with as many passed tests as listed names, and none failed or ignored.
   A ``doc`` row runs ``cargo test -p PACKAGE --doc`` and needs one passing
   result.

Every command runs even after a failure. The script prints one line per
command with its exit code and counts, then exits 1 if any command failed and
0 otherwise. It exits 2 on an unreadable registry or manifest.
"""

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / ".github" / "docs-tests.tsv"
RESULT = re.compile(r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored", re.MULTILINE)


def load_registry(path):
    """Returns {package: {target: [names]}} in registry order."""
    plan = {}
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) != 3 or not all(fields):
            raise ValueError(f"{path.name}:{number}: expected package, target, and test name separated by tabs")
        package, target, name = fields
        names = plan.setdefault(package, {}).setdefault(target, [])
        if target != "doc":
            names.append(name)
    return plan


def package_features(root):
    """Returns {package name: declared feature names} for the workspace members."""
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    features = {}
    for pattern in manifest["workspace"]["members"]:
        for directory in sorted(root.glob(pattern)):
            member = tomllib.loads((directory / "Cargo.toml").read_text())
            features[member["package"]["name"]] = set(member.get("features", {}))
    return features


def feature_args(args, declared):
    out = ["--no-default-features"] if args.no_default_features else []
    wanted = [f for f in (args.features or "").split(",") if f]
    selected = [f for f in wanted if f in declared]
    if selected:
        out += ["--features", ",".join(selected)]
    return out


def target_args(target):
    if target == "lib":
        return ["--lib"]
    if target == "doc":
        return ["--doc"]
    kind, name = target.split(":", 1)
    return [f"--{kind}", name]


def run(command, dry_run):
    print("+ " + " ".join(command), flush=True)
    if dry_run:
        return 0, ""
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            check=False)
    sys.stdout.write(result.stdout)
    return result.returncode, result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--no-default-features", action="store_true")
    parser.add_argument("--features", default="")
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    parser.add_argument("--cargo-flag", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        plan = load_registry(args.registry)
        features = package_features(ROOT)
    except (OSError, ValueError, KeyError, tomllib.TOMLDecodeError) as err:
        print(f"run-docs-tests: {err}", file=sys.stderr)
        return 2
    if not plan:
        print("run-docs-tests: the registry lists no test", file=sys.stderr)
        return 2
    summary, failed = [], False
    for package, targets in plan.items():
        if package not in features:
            summary.append(f"FAIL {package}: not a workspace member")
            failed = True
            continue
        common = ["-p", package, *feature_args(args, features[package]), *args.cargo_flag]
        rc, _ = run(["cargo", "check", "--all-targets", *common], args.dry_run)
        summary.append(f"{'ok  ' if rc == 0 else 'FAIL'} {package}: cargo check --all-targets: exit {rc}")
        failed |= rc != 0
        for target, names in targets.items():
            filters = ["--", "--exact", *names] if target != "doc" else []
            rc, output = run(["cargo", "test", *common, *target_args(target), *filters], args.dry_run)
            if args.dry_run:
                summary.append(f"dry  {package} {target}: {len(names)} listed")
                continue
            results = RESULT.findall(output)
            passed = sum(int(r[1]) for r in results)
            bad = sum(int(r[2]) + int(r[3]) for r in results)
            if target == "doc":
                good = rc == 0 and len(results) == 1 and passed > 0 and bad == 0
                detail = f"{passed} doctests passed"
            else:
                good = rc == 0 and len(results) == 1 and passed == len(names) and bad == 0
                detail = f"{passed} of {len(names)} listed tests passed, {bad} failed or ignored"
            summary.append(f"{'ok  ' if good else 'FAIL'} {package} {target}: exit {rc}, {detail}")
            failed |= not good
    print("\nrun-docs-tests summary:")
    for line in summary:
        print(line)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
