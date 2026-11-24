#!/usr/bin/env python3
"""Offline regression checks for check-proof-matrix.py.

Each case copies the checker into a scratch tree under TMPDIR, writes a
fixture matrix beside it and the row source files it names, runs it on a
fixture listing file, and checks the exit status and the message. One case
compares the checker's feature lists with the offline test steps of the CI
workflow.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    print("test-check-proof-matrix.py requires Python 3.11 or later", file=sys.stderr)
    sys.exit(2)

import importlib.util
import json
import pathlib
import re
import shutil
import subprocess
import tempfile

SCRIPT = pathlib.Path(__file__).resolve().parent / "check-proof-matrix.py"
WORKFLOW = pathlib.Path(__file__).resolve().parents[1] / "workflows" / "ci.yml"

MATRIX = """\
[[row]]
id = "mcp.pay"
surface = "mcp"
name = "stellar_pay"
phase = "prepare"
source = "src/pay.rs"

[[row]]
id = "mcp.pay_commit"
surface = "mcp"
name = "stellar_pay_commit"
phase = "commit"
source = "src/pay.rs"

[[row]]
id = "cli.pay"
surface = "cli"
name = "pay"
phase = "verb"
source = "src/cli_pay.rs"

[[excluded]]
id = "mcp.trade"
surface = "mcp"
name = "stellar_dex_trade"
reason = "testnet only"
refusal = [{ package = "demo-mcp", target = "lib", name = "tools::trade::refuses_mainnet" }]

[[claim]]
id = "halt.refuses_first"
family = "halt"
statement = "a halted profile refuses first"
applies = ["prepare", "commit", "verb"]

[[claim]]
id = "status.view"
family = "status"
statement = "the status reports state"
applies = ["commit", "verb"]

[[claim]]
id = "notification.event"
family = "notification"
statement = "a transition emits one event"
applies = ["commit", "verb"]

[[claim]]
id = "approval.mainnet"
family = "approval"
statement = "a mainnet commit needs presence"
applies = ["commit"]
builds = "feature-on"

[[delivery]]
key = "status-views"
change = "status views"

[[delivery]]
key = "row-test"
change = "a row test follows"

[[cell]]
claim = "halt.refuses_first"
rows = ["mcp.pay", "mcp.pay_commit"]
tests = [{ package = "demo-mcp", target = "test:mcp", name = "halt::every_tool_refuses" }]

[[cell]]
claim = "halt.refuses_first"
rows = ["cli.pay"]
tests = [
  { package = "demo-cli", target = "bin:demo-agent", name = "commands::pay::tests::halted_off", builds = "feature-off" },
  { package = "demo-cli", target = "bin:demo-agent", name = "commands::pay::tests::halted_on", builds = "feature-on" },
]

[[cell]]
claim = "status.view"
rows = ["mcp.pay_commit"]
pending = "status-views"

[[cell]]
claim = "status.view"
rows = ["cli.pay"]
pending = "row-test"

[[cell]]
claim = "notification.event"
rows = ["mcp.pay_commit"]
pending = "status-views"

[[cell]]
claim = "notification.event"
rows = ["cli.pay"]
not_applicable = "the CLI reports state through its status verb"

[[cell]]
claim = "approval.mainnet"
rows = ["mcp.pay_commit"]
tests = [{ package = "demo-mcp", target = "lib", name = "tools::mainnet::presence", builds = "feature-on" }]
"""

def entry(package, kind, name, tests, ignored=()):
    """One listing entry: an executable and the output of its two list runs."""
    listed = "".join(f"{test}: test\n" for test in tests)
    return {
        "package": package,
        "kind": kind,
        "name": name,
        "list": f"{listed}\n{len(tests)} tests, 0 benchmarks\n",
        "ignored": "".join(f"{test}: test\n" for test in ignored),
    }


def listing(configuration):
    """The listing of the fixture packages in `configuration`."""
    halted = "halted_off" if configuration == "feature-off" else "halted_on"
    mainnet = ["tools::mainnet::presence"] if configuration == "feature-on" else []
    return [
        entry("demo-mcp", ["lib"], "demo_mcp",
              ["tools::trade::refuses_mainnet", "tools::other"] + mainnet),
        entry("demo-cli", ["bin"], "demo-agent", [f"commands::pay::tests::{halted}"]),
        entry("demo-mcp", ["test"], "mcp", ["halt::every_tool_refuses", "pay::slow_submit"],
              ["pay::slow_submit"]),
    ]


def replace(old, new):
    def edit(text):
        if old not in text:
            raise AssertionError(f"fixture edit does not apply: {old!r}")
        return text.replace(old, new, 1)

    return edit


def same(text):
    return text


def with_entries(*extra):
    """The standard listing with `extra` entries appended."""
    def entries(configuration):
        return listing(configuration) + list(extra)

    return entries


def standard(configuration):
    return listing(configuration)


HALT_TEST = 'name = "halt::every_tool_refuses"'
HALTED_ON = ('  { package = "demo-cli", target = "bin:demo-agent", '
             'name = "commands::pay::tests::halted_on", builds = "feature-on" },\n')
PRESENCE = 'name = "tools::mainnet::presence", builds = "feature-on"'
STATUS_CELL = '''[[cell]]
claim = "status.view"
rows = ["cli.pay"]
pending = "row-test"
'''

# (label, matrix edit, lists, configuration, extra arguments, exit code,
# message fragments)
CASES = [
    ("valid matrix, feature-off", same, standard, "feature-off", [], 0,
     ["holds for feature-off: 2 cells proven, 3 pending, 1 not applicable, 1 outside this build; "
      "3 refs checked"]),
    ("valid matrix, feature-on", same, standard, "feature-on", [], 0,
     ["holds for feature-on: 3 cells proven, 3 pending, 1 not applicable, 0 outside this build; "
      "4 refs checked"]),
    ("a listing without an executable", same, lambda configuration: [], "feature-off", [], 1,
     ["the listing holds no executable"]),
    ("a listing without a test", same,
     lambda configuration: [entry("demo-mcp", ["lib"], "demo_mcp", [])], "feature-off", [], 1,
     ["the listing holds no test"]),
    ("an empty listing file", same, lambda configuration: "", "feature-off", [], 1,
     ["the listing file cannot be read"]),
    ("a listing entry without its fields", same,
     lambda configuration: listing(configuration) + [{"package": "demo-mcp", "kind": ["test"]}],
     "feature-off", [], 1, ["listing entry 3: name, list, ignored missing or of the wrong type"]),
    ("an executable of an unrecognized kind", same,
     with_entries(entry("demo-mcp", ["example"], "walkthrough", ["main_flow"])),
     "feature-off", [], 1, ["listing entry 3: demo-mcp walkthrough: unrecognized target kind ['example']"]),
    ("a second binary target that a bin ref finds",
     replace('name = "commands::pay::tests::halted_off", builds = "feature-off" }',
             'name = "commands::pay::tests::halted_off", builds = "feature-off" },\n'
             '  { package = "demo-cli", target = "bin:demo-tool", name = "tool::tests::halted" }'),
     with_entries(entry("demo-cli", ["bin"], "demo-tool", ["tool::tests::halted"])),
     "feature-off", [], 0, ["holds for feature-off: 2 cells proven, 3 pending, 1 not applicable, "
                            "1 outside this build; 4 refs checked"]),
    ("a library target of several crate types", same,
     lambda configuration: [dict(e, kind=["cdylib", "rlib"]) if e["kind"] == ["lib"] else e
                            for e in listing(configuration)],
     "feature-off", [], 0, ["holds for feature-off"]),
    ("an ambiguous target", same,
     with_entries(entry("demo-mcp", ["test"], "mcp", ["halt::every_tool_refuses"])),
     "feature-off", [], 1, ["ref demo-mcp test:mcp halt::every_tool_refuses: the target test:mcp is ambiguous"]),
    ("a ref with the wrong package",
     replace('{ package = "demo-mcp", target = "test:mcp"', '{ package = "demo-cli", target = "test:mcp"'),
     standard, "feature-off", [], 1,
     ["ref demo-cli test:mcp halt::every_tool_refuses: the feature-off listing has no target "
      "test:mcp in demo-cli"]),
    ("equal test stems in two packages resolve by package",
     replace(HALT_TEST + " }]", HALT_TEST + ' },\n'
             '  { package = "demo-cli", target = "test:mcp", name = "cli_halt::refuses" }]'),
     with_entries(entry("demo-cli", ["test"], "mcp", ["cli_halt::refuses"])),
     "feature-off", [], 0, ["holds for feature-off: 2 cells proven, 3 pending, 1 not applicable, "
                            "1 outside this build; 4 refs checked"]),
    ("a ref to a test of the other package with an equal stem",
     replace(HALT_TEST + " }]", HALT_TEST + ' },\n'
             '  { package = "demo-cli", target = "test:mcp", name = "halt::every_tool_refuses" }]'),
     with_entries(entry("demo-cli", ["test"], "mcp", ["cli_halt::refuses"])),
     "feature-off", [], 1,
     ["ref demo-cli test:mcp halt::every_tool_refuses: absent from the feature-off list"]),
    ("a ref absent from its target",
     replace(HALT_TEST, 'name = "halt::every_tool_refuse"'), standard, "feature-off", [], 1,
     ["cell 'halt.refuses_first' ['mcp.pay', 'mcp.pay_commit']: ref demo-mcp test:mcp "
      "halt::every_tool_refuse: absent from the feature-off list"]),
    ("a ref whose target is absent",
     replace('target = "test:mcp"', 'target = "test:cli"'), standard, "feature-off", [], 1,
     ["the feature-off listing has no target test:cli in demo-mcp"]),
    ("an ignored ref", replace(HALT_TEST, 'name = "pay::slow_submit"'), standard,
     "feature-off", [], 1, ["ref demo-mcp test:mcp pay::slow_submit: ignored in the feature-off build"]),
    ("a ref of both builds absent from one",
     replace('builds = "feature-off" }', 'builds = "both" }'), standard, "feature-on", [], 1,
     ["commands::pay::tests::halted_off: absent from the feature-on list"]),
    ("a bin name with an underscore names the same target",
     replace('package = "demo-cli", target = "bin:demo-agent", name = "commands::pay::tests::halted_off"',
             'package = "demo-cli", target = "bin:demo_agent", name = "commands::pay::tests::halted_off"'),
     standard, "feature-off", [], 0, ["holds for feature-off"]),
    ("a proven cell without a ref in a build its claim applies to", replace(HALTED_ON, ""), standard,
     "feature-off", [], 1,
     ["cell 'halt.refuses_first' ['cli.pay']: names no ref that runs in the feature-on build"]),
    ("a ref of both builds under a claim of one build",
     replace(PRESENCE, 'name = "tools::mainnet::presence"'), standard, "feature-on", [], 1,
     ["cell 'approval.mainnet' ['mcp.pay_commit']: ref demo-mcp lib tools::mainnet::presence runs "
      "in the feature-off build, which the claim does not apply to"]),
    ("a ref of the other build under a claim of one build",
     replace(PRESENCE, 'name = "tools::mainnet::presence", builds = "feature-off"'), standard,
     "feature-on", [], 1,
     ["ref demo-mcp lib tools::mainnet::presence runs in the feature-off build, which the claim "
      "does not apply to",
      "cell 'approval.mainnet' ['mcp.pay_commit']: names no ref that runs in the feature-on build"]),
    ("an unknown claim build", replace('applies = ["commit"]\nbuilds = "feature-on"',
                                       'applies = ["commit"]\nbuilds = "on"'),
     standard, "feature-off", [], 1, ["claim 'approval.mainnet': unknown build 'on'"]),
    ("an uncovered pair", replace(STATUS_CELL, ""), standard, "feature-off", [], 1,
     ["claim status.view row cli.pay: no cell covers the pair",
      "delivery 'row-test': no cell uses the key"]),
    ("a twice-covered pair",
     replace(STATUS_CELL, STATUS_CELL + '\n[[cell]]\nclaim = "status.view"\nrows = ["cli.pay"]\n'
             'pending = "status-views"\n'),
     standard, "feature-off", [], 1, ["claim status.view row cli.pay: covered by 2 cells"]),
    ("a row the claim does not apply to",
     replace('rows = ["mcp.pay_commit"]\npending = "status-views"',
             'rows = ["mcp.pay", "mcp.pay_commit"]\npending = "status-views"'),
     standard, "feature-off", [], 1, ["claim status.view does not apply to row mcp.pay"]),
    ("an unknown row id",
     replace('rows = ["cli.pay"]\npending = "row-test"', 'rows = ["cli.pay", "cli.payy"]\npending = "row-test"'),
     standard, "feature-off", [], 1, ["unknown row id 'cli.payy'"]),
    ("an unknown claim id",
     replace('claim = "status.view"\nrows = ["cli.pay"]', 'claim = "status.viewx"\nrows = ["cli.pay"]'),
     standard, "feature-off", [], 1, ["unknown claim id 'status.viewx'",
                                      "claim status.view row cli.pay: no cell covers the pair"]),
    ("an unknown family", replace('family = "status"', 'family = "statuses"'), standard,
     "feature-off", [], 1, ["claim 'status.view': unknown family 'statuses'"]),
    ("an unknown claim phase", replace('applies = ["commit", "verb"]', 'applies = ["commit", "verbs"]'),
     standard, "feature-off", [], 1, ["claim 'status.view': unknown phase 'verbs'"]),
    ("an unknown row phase", replace('phase = "prepare"', 'phase = "simulate"'), standard,
     "feature-off", [], 1, ["row 'mcp.pay': unknown phase 'simulate' for surface mcp"]),
    ("an unknown surface", replace('surface = "cli"\nname = "pay"', 'surface = "web"\nname = "pay"'),
     standard, "feature-off", [], 1, ["row 'cli.pay': unknown surface 'web'"]),
    ("an unknown build", replace('builds = "feature-off"', 'builds = "off"'), standard,
     "feature-off", [], 1, ["unknown build 'off'"]),
    ("an unknown target", replace('target = "test:mcp"', 'target = "tests:mcp"'), standard,
     "feature-off", [], 1, ["unknown target 'tests:mcp'"]),
    ("an unknown delivery key", replace('pending = "row-test"', 'pending = "row-tests"'), standard,
     "feature-off", [], 1, ["unknown delivery key 'row-tests'", "delivery 'row-test': no cell uses the key"]),
    ("a key no cell uses",
     replace('[[delivery]]\nkey = "row-test"', '[[delivery]]\nkey = "spare"\nchange = "spare"\n\n'
             '[[delivery]]\nkey = "row-test"'),
     standard, "feature-off", [], 1, ["delivery 'spare': no cell uses the key"]),
    ("a used key leaves the delivery list",
     replace('[[delivery]]\nkey = "status-views"\nchange = "status views"\n', ''), standard,
     "feature-off", [], 1, ["unknown delivery key 'status-views'"]),
    ("an unknown field", replace('reason = "testnet only"', 'reason = "testnet only"\nnote = "x"'),
     standard, "feature-off", [], 1, ["excluded 'mcp.trade': unknown field 'note'"]),
    ("a duplicate row id", replace('id = "mcp.pay_commit"', 'id = "mcp.pay"'), standard,
     "feature-off", [], 1, ["row 'mcp.pay': duplicate id"]),
    ("a duplicate claim id",
     replace('[[claim]]\nid = "status.view"', '[[claim]]\nid = "status.view"\nfamily = "status"\n'
             'statement = "the status reports state"\napplies = ["commit"]\n\n[[claim]]\nid = "status.view"'),
     standard, "feature-off", [], 1, ["claim 'status.view': duplicate id"]),
    ("a duplicate delivery key",
     replace('[[delivery]]\nkey = "row-test"', '[[delivery]]\nkey = "status-views"\nchange = "again"\n\n'
             '[[delivery]]\nkey = "row-test"'),
     standard, "feature-off", [], 1, ["delivery 'status-views': duplicate key"]),
    ("a duplicate excluded id",
     replace('[[claim]]\nid = "halt.refuses_first"',
             '[[excluded]]\nid = "mcp.trade"\nsurface = "mcp"\nname = "stellar_dex_trade"\n'
             'reason = "testnet only"\nrefusal = [{ package = "demo-mcp", target = "lib", '
             'name = "tools::trade::refuses_mainnet" }]\n\n[[claim]]\nid = "halt.refuses_first"'),
     standard, "feature-off", [], 1, ["excluded 'mcp.trade': duplicate id"]),
    ("an excluded id equal to a row id", replace('id = "mcp.trade"', 'id = "mcp.pay"'), standard,
     "feature-off", [], 1, ["excluded 'mcp.pay': duplicate id"]),
    ("an unknown cell field",
     replace('rows = ["cli.pay"]\npending = "row-test"', 'rows = ["cli.pay"]\npending = "row-test"\nnote = "x"'),
     standard, "feature-off", [], 1, ["cell 'status.view' ['cli.pay']: unknown field 'note'"]),
    ("an empty excluded reason", replace('reason = "testnet only"', 'reason = " "'), standard,
     "feature-off", [], 1, ["excluded 'mcp.trade': reason is missing or empty"]),
    ("an excluded entry without a refusal",
     replace('refusal = [{ package = "demo-mcp", target = "lib", name = "tools::trade::refuses_mainnet" }]\n', ''),
     standard, "feature-off", [], 1, ["excluded 'mcp.trade': names no ref"]),
    ("an empty not_applicable reason",
     replace('not_applicable = "the CLI reports state through its status verb"', 'not_applicable = ""'),
     standard, "feature-off", [], 1, ["the not_applicable reason is empty"]),
    ("an empty statement", replace('statement = "the status reports state"', 'statement = ""'),
     standard, "feature-off", [], 1, ["claim 'status.view': statement is missing or empty"]),
    ("a missing row source", replace('source = "src/cli_pay.rs"\n', ''), standard, "feature-off",
     [], 1, ["row 'cli.pay': the row source is missing"]),
    ("a row source that names no file", replace('source = "src/cli_pay.rs"', 'source = "src/gone.rs"'),
     standard, "feature-off", [], 1, ["row 'cli.pay': the row source src/gone.rs names no file"]),
    ("a proven cell that is also pending",
     replace(HALT_TEST + " }]\n", HALT_TEST + ' }]\npending = "row-test"\n'), standard,
     "feature-off", [], 1, ["holds tests and pending; a cell holds exactly one of tests, pending and not_applicable"]),
    ("a cell without an outcome",
     replace('rows = ["cli.pay"]\nnot_applicable = "the CLI reports state through its status verb"\n',
             'rows = ["cli.pay"]\n'),
     standard, "feature-off", [], 1, ["holds no outcome; a cell holds exactly one"]),
    ("complete refuses every pending cell", same, standard, "feature-off", ["--complete"], 1,
     ["cell 'status.view' ['mcp.pay_commit']: pending status-views",
      "cell 'status.view' ['cli.pay']: pending row-test",
      "cell 'notification.event' ['mcp.pay_commit']: pending status-views"]),
]


def run_case(root, matrix, lists, configuration, extra):
    scripts = root / ".github" / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy(SCRIPT, scripts / SCRIPT.name)
    (scripts / "proof-matrix.toml").write_text(matrix)
    (root / "src").mkdir()
    (root / "src" / "pay.rs").write_text("")
    (root / "src" / "cli_pay.rs").write_text("")
    entries = lists(configuration)
    listing_file = root / "listing.json"
    listing_file.write_text(entries if isinstance(entries, str) else json.dumps(entries))
    command = [
        sys.executable,
        str(scripts / SCRIPT.name),
        "--configuration",
        configuration,
        "--listing-file",
        str(listing_file),
        *extra,
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    return result.returncode, result.stdout + result.stderr


def check_cases(failures):
    for label, edit, lists, configuration, extra, want_rc, fragments in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            rc, output = run_case(pathlib.Path(tmp), edit(MATRIX), lists, configuration, extra)
        missing = [fragment for fragment in fragments if fragment not in output]
        if rc != want_rc or missing:
            failures.append(f"{label}: exit {rc}, expected {want_rc}; missing {missing}; output:\n{output}")
        else:
            print(f"ok   {label}")


def check_usage(failures):
    for label, args in (
        ("usage: no configuration", []),
        ("usage: an unknown configuration", ["--configuration", "feature-all"]),
        ("usage: a listing file with the workspace", ["--configuration", "feature-off",
                                                       "--workspace", "--listing-file", "x.json"]),
    ):
        result = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True,
                                text=True, check=False)
        if result.returncode != 2:
            failures.append(f"{label}: exit {result.returncode}, expected 2")
        else:
            print(f"ok   {label}")


def check_ci_features(failures):
    """The checker's feature lists equal the offline test steps of ci.yml."""
    spec = importlib.util.spec_from_file_location("check_proof_matrix", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    text = WORKFLOW.read_text()
    steps = re.findall(r"^\s*run: cargo test --workspace( --no-default-features)? --features (\S+)\s*$",
                       text, re.MULTILINE)
    workflow = {
        ("feature-off" if no_default else "feature-on"): (bool(no_default), tuple(features.split(",")))
        for no_default, features in steps
    }
    checker = {
        configuration: (module.NO_DEFAULT_FEATURES[configuration], module.FEATURES[configuration])
        for configuration in module.FEATURES
    }
    if len(steps) != 2 or workflow != checker:
        failures.append(f"the checker's features {checker} differ from ci.yml {workflow}")
    else:
        print("ok   the feature lists equal the offline test steps of ci.yml")


def main():
    failures = []
    check_cases(failures)
    check_usage(failures)
    check_ci_features(failures)
    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"{len(failures)} check-proof-matrix case(s) failed", file=sys.stderr)
        return 1
    print("check-proof-matrix tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
