#!/usr/bin/env python3
"""Check the release proof matrix against the test lists of one build.

Usage: check-proof-matrix.py --configuration feature-off|feature-on
           [--workspace] [--complete] [--listing-file F]

The matrix is proof-matrix.toml beside this script. It names the value tools
of MCP and the CLI as rows, the testnet-only value tools as excluded entries
with their mainnet refusal tests, the claims the release proves, the changes
that deliver a pending claim, and one cell per claim and set of rows.

The check reads the test executables of the build, each with its package,
target kind and target name, from ``cargo --color never test <selection>
<features> --lib --bins --tests --no-run --message-format json``, and runs
each executable with ``--list --format terse``, then again with
``--ignored``, under the dynamic library search path cargo gives a test it
runs. The selection is ``--workspace`` with that flag, else one
``-p`` per package the refs name, with the features those packages declare.
The features of each configuration equal the offline test steps of the CI
workflow, so the build compiles nothing the test step did not.
``--listing-file`` names a JSON listing instead: an array of objects with
``package``, ``kind`` (the target kinds cargo reports), ``name``, ``list`` and
``ignored`` (the output of the two runs).

A ref's target resolves within its package: ``lib`` is the package's library
target, ``bin:<name>`` a binary target and ``test:<name>`` an integration
test target. A ``-`` in a package or target name reads ``_``.

The check refuses:
- a listing without an executable or without a test, an entry that is not
  an object of strings, and an executable whose target kind is neither a
  library, a binary nor a test;
- a ref of this build whose package has no such target, a target listed more
  than once, a target that does not hold the test, and a ref of this build
  the ignored list holds;
- an unknown field, id, surface, family, phase, build or delivery key, a
  duplicate id, an empty statement, reason or change, a row source that is
  missing or names no file, and a delivery key no cell uses;
- a cell without exactly one of tests, pending and not_applicable, a cell
  row the claim does not apply to, and a (claim, row) pair no cell or two
  cells cover;
- a proven cell without a ref that runs in each build its claim applies
  to, and a ref that runs in a build its claim does not apply to;
- with --complete, every pending cell.

The counts of the summary cover the cells whose claim applies to the build;
the other cells count as outside it.

Exit codes are 0 for a matrix that holds, 1 for violations, each listed on
its own line, and 2 for usage errors.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    print("check-proof-matrix.py requires Python 3.11 or later", file=sys.stderr)
    sys.exit(2)

import argparse
import json
import os
import pathlib
import re
import subprocess
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]
MATRIX = pathlib.Path(__file__).resolve().with_name("proof-matrix.toml")

# The cargo feature arguments of each configuration, equal to the offline test
# steps of the CI workflow.
NO_DEFAULT_FEATURES = {"feature-off": True, "feature-on": False}
FEATURES = {
    "feature-off": ("test-helpers", "test-hooks", "test-loopback", "verifier-registry"),
    "feature-on": (
        "mainnet-write",
        "test-helpers",
        "test-hooks",
        "test-loopback",
        "verifier-registry",
    ),
}

FAMILIES = frozenset(
    {
        "approval",
        "sizing",
        "audit",
        "halt",
        "feature-matrix",
        "status",
        "notification",
        "revocation",
        "remote-approval",
    }
)
SURFACE_PHASES = {"mcp": ("prepare", "commit", "single"), "cli": ("verb",)}
PHASES = ("prepare", "commit", "single", "verb")
BUILDS = ("both", "feature-off", "feature-on")
BUILD_SETS = {
    "both": frozenset({"feature-off", "feature-on"}),
    "feature-off": frozenset({"feature-off"}),
    "feature-on": frozenset({"feature-on"}),
}

ROW_FIELDS = {"id", "surface", "name", "phase", "source"}
EXCLUDED_FIELDS = {"id", "surface", "name", "reason", "refusal"}
CLAIM_FIELDS = {"id", "family", "statement", "applies", "builds"}
DELIVERY_FIELDS = {"key", "change"}
CELL_FIELDS = {"claim", "rows", "tests", "pending", "not_applicable"}
CELL_OUTCOMES = ("tests", "pending", "not_applicable")
REF_FIELDS = {"package", "target", "name", "builds"}
TABLES = {"row", "excluded", "claim", "delivery", "cell"}

TEST_LINE = re.compile(r"^(\S+): test$")
TARGET = re.compile(r"^(lib|bin:[A-Za-z0-9_-]+|test:[A-Za-z0-9_-]+)$")
LIBRARY_KINDS = frozenset({"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"})
LISTING_FIELDS = ("package", "name", "list", "ignored")
SEARCH_KINDS = frozenset({"native", "crate", "dependency", "framework", "all"})


def normal(name):
    """A package or target name with each ``-`` read as ``_``."""
    return name.replace("-", "_")


def target_key(package, target):
    """The (package, kind, name) a ref's target resolves to; a package has
    one library target, so its name is empty."""
    if target == "lib":
        return (normal(package), "lib", "")
    kind, name = target.split(":", 1)
    return (normal(package), kind, normal(name))


def target_kind(kinds):
    """The ref kind of an executable from the target kinds cargo reports, or
    None for a target that is neither a library, a binary nor a test."""
    if kinds == ["bin"]:
        return "bin"
    if kinds == ["test"]:
        return "test"
    if kinds and set(kinds) <= LIBRARY_KINDS:
        return "lib"
    return None


def test_names(text):
    """The test names a ``--list --format terse`` run prints."""
    return {match.group(1) for match in map(TEST_LINE.match, text.splitlines()) if match}


def parse_listing(entries, problems):
    """The tests and the ignored tests of each target in a listing, by
    (package, kind, name), with the number of entries that list each target."""
    tests = {}
    ignored = {}
    listed = {}
    count = 0
    if not isinstance(entries, list) or not entries:
        problems.append("the listing holds no executable")
        return None
    for index, entry in enumerate(entries):
        where = f"listing entry {index}"
        if not isinstance(entry, dict):
            problems.append(f"{where}: is not an object")
            continue
        missing = [field for field in LISTING_FIELDS if not isinstance(entry.get(field), str)]
        kinds = entry.get("kind")
        if not isinstance(kinds, list) or not all(isinstance(kind, str) for kind in kinds):
            missing.append("kind")
        if missing:
            problems.append(f"{where}: {', '.join(missing)} missing or of the wrong type")
            continue
        kind = target_kind(kinds)
        if kind is None:
            problems.append(
                f"{where}: {entry['package']} {entry['name']}: unrecognized target kind {kinds}"
            )
            continue
        name = "" if kind == "lib" else normal(entry["name"])
        key = (normal(entry["package"]), kind, name)
        listed[key] = listed.get(key, 0) + 1
        names = test_names(entry["list"])
        tests.setdefault(key, set()).update(names)
        ignored.setdefault(key, set()).update(test_names(entry["ignored"]))
        count += len(names)
    if count == 0:
        problems.append("the listing holds no test")
    return tests, ignored, listed


def unknown_fields(entry, allowed, where, problems):
    for field in sorted(set(entry) - allowed):
        problems.append(f"{where}: unknown field {field!r}")


def text_field(entry, field, where, problems):
    value = entry.get(field)
    if not isinstance(value, str) or not value.strip():
        problems.append(f"{where}: {field} is missing or empty")
        return ""
    return value


def check_ref(ref, where, problems):
    """Validates a ref's shape and returns it with its builds, or None."""
    if not isinstance(ref, dict):
        problems.append(f"{where}: a ref is not a table")
        return None
    unknown_fields(ref, REF_FIELDS, where, problems)
    package = text_field(ref, "package", where, problems)
    target = text_field(ref, "target", where, problems)
    name = text_field(ref, "name", where, problems)
    builds = ref.get("builds", "both")
    if not isinstance(builds, str) or builds not in BUILDS:
        problems.append(f"{where}: unknown build {builds!r}")
        return None
    if target and not TARGET.match(target):
        problems.append(f"{where}: unknown target {target!r}")
        return None
    if not (package and target and name):
        return None
    return {"package": package, "target": target, "name": name, "builds": builds}


def check_refs(refs, where, problems):
    if not isinstance(refs, list) or not refs:
        problems.append(f"{where}: names no ref")
        return []
    return [r for r in (check_ref(ref, where, problems) for ref in refs) if r]


def load(path, problems):
    try:
        with open(path, "rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        problems.append(f"{path.name}: cannot be read: {error}")
        return None
    for table in sorted(set(document) - TABLES):
        problems.append(f"{path.name}: unknown table {table!r}")
    for table in sorted(TABLES):
        value = document.get(table, [])
        if not isinstance(value, list) or not all(isinstance(e, dict) for e in value):
            problems.append(f"{path.name}: {table} is not an array of tables")
            document[table] = []
    return document


def check_matrix(document, root, configuration, complete, problems):
    """Validates the matrix and returns every ref with where it stands, and
    the cell counts of `configuration`."""
    refs = []
    rows = {}
    for entry in document["row"]:
        where = f"row {entry.get('id', '?')!r}"
        unknown_fields(entry, ROW_FIELDS, where, problems)
        row_id = text_field(entry, "id", where, problems)
        surface = entry.get("surface")
        phase = entry.get("phase")
        surface = surface if isinstance(surface, str) else repr(surface)
        phase = phase if isinstance(phase, str) else repr(phase)
        text_field(entry, "name", where, problems)
        source = entry.get("source")
        if surface not in SURFACE_PHASES:
            problems.append(f"{where}: unknown surface {surface!r}")
        elif phase not in SURFACE_PHASES[surface]:
            problems.append(f"{where}: unknown phase {phase!r} for surface {surface}")
        if not isinstance(source, str) or not source.strip():
            problems.append(f"{where}: the row source is missing")
        elif not (root / source).is_file():
            problems.append(f"{where}: the row source {source} names no file")
        if row_id in rows:
            problems.append(f"{where}: duplicate id")
        elif row_id:
            rows[row_id] = phase
    excluded = set()
    for entry in document["excluded"]:
        where = f"excluded {entry.get('id', '?')!r}"
        unknown_fields(entry, EXCLUDED_FIELDS, where, problems)
        entry_id = text_field(entry, "id", where, problems)
        if not isinstance(entry.get("surface"), str) or entry["surface"] not in SURFACE_PHASES:
            problems.append(f"{where}: unknown surface {entry.get('surface')!r}")
        text_field(entry, "name", where, problems)
        text_field(entry, "reason", where, problems)
        if entry_id and (entry_id in excluded or entry_id in rows):
            problems.append(f"{where}: duplicate id")
        excluded.add(entry_id)
        refs.extend((where, ref) for ref in check_refs(entry.get("refusal"), where, problems))
    claims = {}
    for entry in document["claim"]:
        where = f"claim {entry.get('id', '?')!r}"
        unknown_fields(entry, CLAIM_FIELDS, where, problems)
        claim_id = text_field(entry, "id", where, problems)
        if not isinstance(entry.get("family"), str) or entry["family"] not in FAMILIES:
            problems.append(f"{where}: unknown family {entry.get('family')!r}")
        text_field(entry, "statement", where, problems)
        applies = entry.get("applies")
        if not isinstance(applies, list) or not applies:
            problems.append(f"{where}: applies names no phase")
            applies = []
        for phase in applies:
            if not isinstance(phase, str) or phase not in PHASES:
                problems.append(f"{where}: unknown phase {phase!r}")
        builds = entry.get("builds", "both")
        if not isinstance(builds, str) or builds not in BUILDS:
            problems.append(f"{where}: unknown build {builds!r}")
            builds = "both"
        if claim_id in claims:
            problems.append(f"{where}: duplicate id")
        elif claim_id:
            claims[claim_id] = {
                "phases": {phase for phase in applies if isinstance(phase, str)},
                "builds": BUILD_SETS[builds],
            }
    keys = {}
    for entry in document["delivery"]:
        where = f"delivery {entry.get('key', '?')!r}"
        unknown_fields(entry, DELIVERY_FIELDS, where, problems)
        key = text_field(entry, "key", where, problems)
        text_field(entry, "change", where, problems)
        if key in keys:
            problems.append(f"{where}: duplicate key")
        elif key:
            keys[key] = 0
    covered = {}
    counts = {outcome: 0 for outcome in CELL_OUTCOMES + ("outside",)}
    for entry in document["cell"]:
        claim = entry.get("claim")
        if not isinstance(claim, str):
            claim = repr(claim)
        cell_rows = entry.get("rows")
        where = f"cell {claim!r} {cell_rows!r}"
        unknown_fields(entry, CELL_FIELDS, where, problems)
        if claim not in claims:
            problems.append(f"{where}: unknown claim id {claim!r}")
        if not isinstance(cell_rows, list) or not cell_rows:
            problems.append(f"{where}: names no row")
            cell_rows = []
        outcomes = [outcome for outcome in CELL_OUTCOMES if outcome in entry]
        if len(outcomes) != 1:
            problems.append(
                f"{where}: holds {' and '.join(outcomes) or 'no outcome'}; a cell holds "
                "exactly one of tests, pending and not_applicable"
            )
        claim_builds = claims[claim]["builds"] if claim in claims else BUILD_SETS["both"]
        for outcome in outcomes:
            counts[outcome if configuration in claim_builds else "outside"] += 1
        if "tests" in entry:
            cell_refs = check_refs(entry["tests"], where, problems)
            refs.extend((where, ref) for ref in cell_refs)
            if claim in claims:
                check_cell_builds(cell_refs, claim_builds, where, problems)
        if "pending" in entry:
            key = entry["pending"]
            if isinstance(key, str) and key in keys:
                keys[key] += 1
                if complete:
                    problems.append(f"{where}: pending {key}")
            else:
                problems.append(f"{where}: unknown delivery key {key!r}")
        if "not_applicable" in entry:
            reason = entry["not_applicable"]
            if not isinstance(reason, str) or not reason.strip():
                problems.append(f"{where}: the not_applicable reason is empty")
        for row in cell_rows:
            if not isinstance(row, str) or row not in rows:
                problems.append(f"{where}: unknown row id {row!r}")
                continue
            if claim in claims and rows[row] not in claims[claim]["phases"]:
                problems.append(f"{where}: claim {claim} does not apply to row {row}")
                continue
            covered.setdefault((claim, row), []).append(where)
    for claim, spec in claims.items():
        for row, phase in rows.items():
            if phase not in spec["phases"]:
                continue
            cells = covered.get((claim, row), [])
            if not cells:
                problems.append(f"claim {claim} row {row}: no cell covers the pair")
            elif len(cells) > 1:
                problems.append(f"claim {claim} row {row}: covered by {len(cells)} cells")
    for key, uses in keys.items():
        if uses == 0:
            problems.append(f"delivery {key!r}: no cell uses the key")
    return refs, counts


def check_cell_builds(cell_refs, claim_builds, where, problems):
    """A proven cell names a ref that runs in each build its claim applies to
    and no ref that runs in another."""
    for ref in cell_refs:
        for build in sorted(BUILD_SETS[ref["builds"]] - claim_builds):
            problems.append(
                f"{where}: ref {ref['package']} {ref['target']} {ref['name']} runs in the "
                f"{build} build, which the claim does not apply to"
            )
    for build in sorted(claim_builds):
        if not any(build in BUILD_SETS[ref["builds"]] for ref in cell_refs):
            problems.append(f"{where}: names no ref that runs in the {build} build")


def cargo_listing(configuration, packages, workspace, problems):
    """Builds the test executables of the build without running them, and
    returns the listing of their tests."""
    features = list(FEATURES[configuration])
    if workspace:
        selection = ["--workspace"]
    else:
        declared = set()
        for package in packages:
            declared |= declared_features(package, problems)
        features = [feature for feature in features if feature in declared]
        selection = [word for package in packages for word in ("-p", package)]
    feature_args = ["--no-default-features"] if NO_DEFAULT_FEATURES[configuration] else []
    if features:
        feature_args += ["--features", ",".join(features)]
    command = (
        ["cargo", "--color", "never", "test"]
        + selection
        + feature_args
        + ["--lib", "--bins", "--tests", "--no-run", "--message-format", "json"]
    )
    result = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        tail = "\n".join(result.stderr.splitlines()[-20:])
        problems.append(f"{' '.join(command)} exited {result.returncode}:\n{tail}")
        return None
    libdir = target_libdir(problems)
    if libdir is None:
        return None
    messages = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    native = [
        search_path(linked)
        for message in messages
        if message.get("reason") == "build-script-executed"
        for linked in message.get("linked_paths", [])
    ]
    names = {}
    entries = []
    for message in messages:
        if message.get("reason") != "compiler-artifact" or not message.get("executable"):
            continue
        if not message.get("profile", {}).get("test"):
            continue
        manifest = pathlib.Path(message["manifest_path"])
        if manifest not in names:
            with open(manifest, "rb") as handle:
                names[manifest] = tomllib.load(handle)["package"]["name"]
        entry = {
            "package": names[manifest],
            "kind": message["target"]["kind"],
            "name": message["target"]["name"],
        }
        environment = dylib_environment(pathlib.Path(message["executable"]), native, libdir)
        for field, extra in (("list", []), ("ignored", ["--ignored"])):
            run = [message["executable"], "--list", "--format", "terse"] + extra
            listing = subprocess.run(
                run,
                cwd=manifest.parent,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
            if listing.returncode != 0:
                tail = "\n".join(listing.stdout.splitlines()[-20:])
                problems.append(f"{' '.join(run)} exited {listing.returncode}:\n{tail}")
                return None
            entry[field] = listing.stdout
        entries.append(entry)
    return entries


def search_path(linked):
    """The directory of a build script search path, without its kind."""
    kind, separator, path = linked.partition("=")
    if separator and kind in SEARCH_KINDS:
        return pathlib.Path(path)
    return pathlib.Path(linked)


def target_libdir(problems):
    """The library directory of the host target in the sysroot of the rustc
    cargo builds with, where a proc-macro test finds the standard library it
    links dynamically."""
    command = [os.environ.get("RUSTC", "rustc"), "--print", "target-libdir"]
    result = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        problems.append(f"{' '.join(command)} exited {result.returncode}: {result.stderr.strip()}")
        return None
    return pathlib.Path(result.stdout.strip())


def dylib_environment(executable, native, libdir):
    """The environment for running `executable` with the dynamic library search
    path cargo sets for a test it runs: the build script search paths inside
    the output directory, the deps and output directories, the sysroot target
    library directory, then the inherited path."""
    deps = executable.parent
    output = deps.parent
    if sys.platform == "win32":
        variable = "PATH"
    elif sys.platform == "darwin":
        variable = "DYLD_FALLBACK_LIBRARY_PATH"
    elif sys.platform.startswith("aix"):
        variable = "LIBPATH"
    else:
        variable = "LD_LIBRARY_PATH"
    search = [path for path in native if path.is_relative_to(output)]
    search += [deps, output, libdir]
    inherited = [entry for entry in os.environ.get(variable, "").split(os.pathsep) if entry]
    search += [pathlib.Path(entry) for entry in inherited]
    if sys.platform == "darwin" and not inherited:
        # The loader's fallback defaults apply only while the variable is unset.
        if "HOME" in os.environ:
            search.append(pathlib.Path(os.environ["HOME"]) / "lib")
        search += [pathlib.Path("/usr/local/lib"), pathlib.Path("/usr/lib")]
    environment = dict(os.environ)
    environment[variable] = os.pathsep.join(str(path) for path in search)
    return environment


def declared_features(package, problems):
    """The features the workspace member named `package` declares."""
    with open(ROOT / "Cargo.toml", "rb") as handle:
        members = tomllib.load(handle)["workspace"]["members"]
    for member in members:
        manifest = ROOT / member / "Cargo.toml"
        with open(manifest, "rb") as handle:
            document = tomllib.load(handle)
        if document.get("package", {}).get("name") == package:
            return set(document.get("features", {}))
    problems.append(f"package {package} is no workspace member")
    return set()


def check_refs_against_listing(refs, configuration, listing):
    problems = []
    tests, ignored_tests, listed = listing
    checked = 0
    for where, ref in refs:
        if ref["builds"] not in ("both", configuration):
            continue
        checked += 1
        key = target_key(ref["package"], ref["target"])
        label = f"{where}: ref {ref['package']} {ref['target']} {ref['name']}"
        if listed.get(key, 0) == 0:
            problems.append(
                f"{label}: the {configuration} listing has no target {ref['target']} "
                f"in {ref['package']}"
            )
            continue
        if listed[key] > 1:
            problems.append(f"{label}: the target {ref['target']} is ambiguous in the listing")
            continue
        if ref["name"] not in tests[key]:
            problems.append(f"{label}: absent from the {configuration} list")
            continue
        if ref["name"] in ignored_tests.get(key, set()):
            problems.append(f"{label}: ignored in the {configuration} build")
    return problems, checked


def main(argv):
    parser = argparse.ArgumentParser(
        prog="check-proof-matrix.py",
        description="Check the release proof matrix against the test lists of one build.",
    )
    parser.add_argument("--configuration", required=True, choices=sorted(FEATURES))
    parser.add_argument("--workspace", action="store_true")
    parser.add_argument("--complete", action="store_true")
    parser.add_argument("--listing-file", type=pathlib.Path)
    args = parser.parse_args(argv)
    if args.listing_file is not None and args.workspace:
        parser.error("--listing-file and --workspace exclude each other")

    problems = []
    document = load(MATRIX, problems)
    if document is None:
        return report(problems)
    refs, counts = check_matrix(document, ROOT, args.configuration, args.complete, problems)

    if args.listing_file is not None:
        try:
            entries = json.loads(args.listing_file.read_text())
        except (OSError, ValueError) as error:
            problems.append(f"the listing file cannot be read: {error}")
            return report(problems)
    else:
        packages = sorted({ref["package"] for _, ref in refs})
        entries = cargo_listing(args.configuration, packages, args.workspace, problems)
        if entries is None:
            return report(problems)
    listing_problems = []
    listing = parse_listing(entries, listing_problems)
    problems.extend(listing_problems)
    if listing_problems:
        return report(problems)
    ref_problems, checked = check_refs_against_listing(refs, args.configuration, listing)
    problems.extend(ref_problems)
    if problems:
        return report(problems)
    print(
        f"proof matrix holds for {args.configuration}: {counts['tests']} cells proven, "
        f"{counts['pending']} pending, {counts['not_applicable']} not applicable, "
        f"{counts['outside']} outside this build; {checked} refs checked"
    )
    return 0


def report(problems):
    for problem in problems:
        print(f"check-proof-matrix: {problem}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
