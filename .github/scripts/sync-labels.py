#!/usr/bin/env python3
"""Validate and create or update repository labels without deleting labels.

Usage: sync-labels.py [--check] [--repo owner/name] [labels-file]
Needs Python 3.9+ and PyYAML. gh reads GH_TOKEN from the environment.
"""

import argparse
import pathlib
import re
import subprocess
import sys

import yaml

FIELDS = ("name", "color", "description")
DEFAULT_LABELS = pathlib.Path(__file__).resolve().parents[1] / "labels.yml"


def validate(document):
    """Return one diagnostic per validation error, before any label writes."""
    errors = []
    if not isinstance(document, list):
        return ["labels: expected a list"]
    names = set()
    for index, entry in enumerate(document, start=1):
        where = f"entry {index}"
        if not isinstance(entry, dict):
            errors.append(f"{where}: expected a mapping")
            continue
        if set(entry) != set(FIELDS):
            errors.append(f"{where}: expected exactly name, color, and description keys")
            continue
        for field in FIELDS:
            value = entry[field]
            if not isinstance(value, str):
                errors.append(f"{where}: {field} must be a string")
                continue
            if value != value.strip():
                errors.append(f"{where}: {field} has leading or trailing whitespace")
            if field == "name":
                if not value:
                    errors.append(f"{where}: name must not be empty")
                if value in names:
                    errors.append(f"{where}: duplicate name {value!r}")
                names.add(value)
            if field == "color" and re.fullmatch(r"[0-9a-f]{6}", value) is None:
                errors.append(f"{where}: color must be six lowercase hex digits without #")
            if field == "description" and len(value) >= 100:
                errors.append(f"{where}: description must be under 100 characters")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="validate without calling gh")
    parser.add_argument("--repo", help="GitHub repository as owner/name")
    parser.add_argument("labels_file", nargs="?", type=pathlib.Path, default=DEFAULT_LABELS)
    args = parser.parse_args()
    try:
        document = yaml.safe_load(args.labels_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        print(f"labels: cannot read valid YAML: {' '.join(str(error).splitlines())}", file=sys.stderr)
        return 1
    errors = validate(document)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    if args.check:
        return 0
    for entry in document:
        command = ["gh", "label", "create", entry["name"], "--color", entry["color"],
                   "--description", entry["description"], "--force"]
        if args.repo is not None:
            command.extend(["--repo", args.repo])
        try:
            result = subprocess.run(command, capture_output=True, check=False)
        except OSError:
            print(f"gh failed for label {entry['name']!r}: cannot execute gh", file=sys.stderr)
            return 2
        if result.returncode != 0:
            sys.stderr.write(result.stderr.decode("utf-8", "replace"))
            print(f"gh failed for label {entry['name']!r}: exit {result.returncode}", file=sys.stderr)
            return 2
        print(f"synced {entry['name']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
