#!/usr/bin/env python3
"""Offline behavior test for the welcome workflow.

Usage: test-welcome-workflow.py [ROOT] [--mutations | --case NAME ...]

The structure case pins the workflow header, ignoring comments and blank lines.
This uses the Python standard library; actionlint checks the YAML syntax.
Each behavior case runs the run block under bash with step variables and a
stub gh on PATH. Cases assert exact calls, comment bodies, exit codes, and
single-line output. Needs Python 3.11+, bash, and jq.

The structure case always runs. --case selects named behavior cases.
--mutations removes guards or changes rules in scratch copies and requires
the named cases to fail with exit 1.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field, replace

WORKFLOW = ".github/workflows/welcome.yml"
REPO = "o/r"
NUMBER = "12"
ENDPOINT = f"repos/{REPO}/issues/{NUMBER}/comments"
STRUCTURE = "workflow structure"
PR_BODY = """Thanks for the pull request, @<login>, and welcome. A maintainer replies within one working day. The review follows within three working days for documentation, scripts, or workflows, and within five for Rust code. CI on a first contribution starts after a maintainer approves the run, which comes with the review.

Three things that save a review round:

- Fill in the pull request template: what the change does, `Closes #N` on its own line, and the commands you ran with their exit codes.
- Keep one pull request per issue.
- Keep editor and tool directories out of the branch.

The checks CI runs are listed in CONTRIBUTING.md under "Gate suite". Nothing else is needed from you until the review."""
ISSUE_BODY = "Thanks for the report, @<login>, and welcome. A maintainer replies within one working day. A security vulnerability goes through SECURITY.md, never a public issue."

# Exact blocks pin the job, step, environment, and permission boundaries.
HEADER = {
    "name": "name: Welcome\n",
    "triggers": "on:\n  pull_request_target:\n    types: [opened]\n  issues:\n    types: [opened]\n",
    "workflow permissions": "permissions: {}\n",
    "job": "jobs:\n  welcome:\n",
    "bot condition": "    if: >-\n"
    "      (github.event.pull_request.user.type || github.event.issue.user.type) != 'Bot'\n",
    "runner": "    runs-on: ubuntu-latest\n",
    "job permissions": "    permissions:\n      issues: write\n      pull-requests: write\n",
    "timeout": "    timeout-minutes: 5\n",
    "concurrency": "    concurrency:\n"
    "      group: welcome-${{ github.event.issue.number || github.event.pull_request.number }}\n"
    "      cancel-in-progress: false\n",
    "step": "    steps:\n      - name: Welcome the first contribution\n",
    "shell": "        shell: bash\n",
    "environment": "        env:\n"
    "          GH_TOKEN: ${{ github.token }}\n"
    "          GH_REPO: ${{ github.repository }}\n"
    "          NUMBER: ${{ github.event.issue.number || github.event.pull_request.number }}\n"
    "          EVENT: ${{ github.event_name }}\n"
    "          LOGIN: ${{ github.event.pull_request.user.login || github.event.issue.user.login }}\n"
    "          ASSOCIATION: ${{ github.event.pull_request.author_association || github.event.issue.author_association }}\n",
}

STUB = r'''#!PYTHON
import json, os, sys

state_path = os.environ["WELCOME_STATE"]
with open(state_path, encoding="utf-8") as handle:
    state = json.load(handle)


def save():
    with open(state_path, "w", encoding="utf-8") as handle:
        json.dump(state, handle)


args = sys.argv[1:]
state["calls"].append(args)
save()
if os.environ.get("GH_TOKEN") != "test-token":
    sys.exit("stub gh: missing job token")
if args[:4] == ["api", "-X", "GET", "search/issues"]:
    if state["fail"] == "search":
        sys.exit("stub gh: search fails\nsecond diagnostic line")
    print(state["response"])
elif args == ["api", "--paginate",
              f"repos/{os.environ['GH_REPO']}/issues/{os.environ['NUMBER']}/comments"]:
    if state["fail"] == "lookup":
        sys.exit("stub gh: comment lookup fails\nsecond diagnostic line")
    if state["lookup_response"] is not None:
        print(state["lookup_response"])
    else:
        pages = [[comment] for comment in state["comments"]] or [[]]
        for page in pages:
            print(json.dumps(page))
elif args[:4] == ["api", "--method", "POST",
                  f"repos/{os.environ['GH_REPO']}/issues/{os.environ['NUMBER']}/comments"]:
    if len(args) != 6 or args[4] != "-f" or not args[5].startswith("body="):
        sys.exit("stub gh: missing body field")
    if state["fail"] == "comment":
        sys.exit("stub gh: comment fails\nsecond diagnostic line")
    state["comments"].append({"user": {"login": "github-actions[bot]"}, "body": args[5][5:]})
    save()
    if state["fail"] == "comment response":
        sys.exit("stub gh: comment response fails\nsecond diagnostic line")
    print(json.dumps({"id": len(state["comments"])}))
else:
    sys.exit(f"stub gh: unsupported call {args}")
'''


def search_call(login="bob"):
    return ["api", "-X", "GET", "search/issues", "-f", f"q=repo:{REPO} author:{login}", "-f", "per_page=1"]


def lookup_call():
    return ["api", "--paginate", ENDPOINT]


def post_call(body):
    return ["api", "--method", "POST", ENDPOINT, "-f", f"body={body}"]


def response(count=1, number=12):
    return json.dumps(dict(total_count=count, incomplete_results=False,
                           items=[{"number": number}]))


def comment(body, login="github-actions[bot]"):
    return {"user": {"login": login}, "body": body}


@dataclass
class Case:
    name: str
    event: str = "pull_request_target"
    association: str = "NONE"
    login: str = "bob"
    number: str = NUMBER
    response: str = field(default_factory=response)
    comments: list = field(default_factory=list)
    lookup_response: str | None = None
    fail: str = ""
    rerun: bool = False
    want_rc: int = 0
    want_calls: list = field(default_factory=lambda: [search_call()])
    want_comments: list = field(default_factory=list)
    want_out: str = ""
    want_error: str = ""


def welcome(name, event="pull_request_target", login="bob", **kwargs):
    body = (PR_BODY if event == "pull_request_target" else ISSUE_BODY).replace("<login>", login)
    return Case(name, event=event, login=login,
                want_calls=[search_call(login), lookup_call(), post_call(body)],
                want_comments=kwargs.get("comments", []) + [comment(body)],
                want_out=f"welcome comment on #{NUMBER}\n", **kwargs)


def error(name, message, **kwargs):
    return Case(name, want_rc=1, want_error=f"::error::Cannot welcome #{NUMBER}: {message}.\n", **kwargs)


CASES = [
    welcome("first pull request by NONE"),
    Case("second pull request", response=response(2),
         want_out=f"no welcome on #{NUMBER}: contribution count is 2\n"),
    welcome("first issue", event="issues"),
    Case("second issue", event="issues", response=response(2),
         want_out=f"no welcome on #{NUMBER}: contribution count is 2\n"),
]
for association in ("OWNER", "MEMBER", "COLLABORATOR"):
    for event, noun in (("pull_request_target", "pull request"), ("issues", "issue")):
        CASES.append(Case(f"{association} {noun}", event=event, association=association,
                          want_calls=[], want_out=f"no welcome on #{NUMBER}: maintainer\n"))
for association in ("FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "CONTRIBUTOR", ""):
    CASES.append(welcome(f"external association {association or 'empty'}", association=association))
CASES += [
    welcome("login case stays intact", login="BoB"),
    welcome("shell payload stays data", login='$(touch PWNED) `touch PWNED`; "\\',
            association="$(touch PWNED)"),
    Case("empty search", response=response(0),
         want_out=f"no welcome on #{NUMBER}: contribution count is 0\n"),
    Case("another contribution in the search index", response=response(number=9),
         want_out=f"no welcome on #{NUMBER}: search names another contribution\n"),
    error("search error", "search fails", fail="search"),
    error("comment error", "comment fails", fail="comment",
          want_calls=[search_call(), lookup_call(), post_call(PR_BODY.replace("<login>", "bob"))]),
    error("malformed search", "invalid search result", response="<html>bad gateway</html>"),
    error("incomplete search", "invalid search result",
          response=json.dumps({"total_count": 1, "incomplete_results": True, "items": [{"number": 12}]})),
    error("invalid search items", "invalid search result",
          response=json.dumps({"total_count": 1, "incomplete_results": False, "items": {}})),
    error("missing search count", "invalid search result",
          response=json.dumps({"incomplete_results": False, "items": []})),
    error("string search count", "invalid search result", response=response("1")),
    error("negative search count", "invalid search result", response=response(-1)),
    error("fractional search count", "invalid search result", response=response(1.5)),
    error("unsupported event", "unsupported event", event="issue_comment", want_calls=[]),
    Case("invalid number", number="abc", want_rc=1, want_calls=[],
         want_error="::error::Cannot welcome #abc: NUMBER must contain only digits.\n"),
]
CASES += [
    welcome("pull request rerun", rerun=True),
    welcome("issue rerun", event="issues", rerun=True),
    error("accepted comment with client error", "comment fails", fail="comment response", rerun=True,
          want_calls=[search_call(), lookup_call(), post_call(PR_BODY.replace("<login>", "bob"))],
          want_comments=[comment(PR_BODY.replace("<login>", "bob"))]),
    error("comment lookup error", "comment lookup fails", fail="lookup",
          want_calls=[search_call(), lookup_call()]),
    welcome("welcome text from another user",
            comments=[comment("Thanks for the pull request, @bob, and welcome.", login="alice")]),
]
second_page = [comment("Thanks for contributing."), comment("Thanks for the report, @bob, and welcome.")]
CASES.append(Case("welcome on second page", comments=second_page, want_comments=second_page,
                  want_calls=[search_call(), lookup_call()],
                  want_out=f"no welcome on #{NUMBER}: welcome exists\n"))
for name, raw in (
    ("malformed comment lookup", "<html>bad gateway</html>"),
    ("empty comment lookup", ""),
    ("object comment lookup", "{}"),
    ("null comment lookup", "null"),
    ("non-object comment lookup", '[]\n[null]'),
    ("non-array second comment page", '[]\n{}'),
):
    CASES.append(error(name, "invalid comment lookup", lookup_response=raw,
                       want_calls=[search_call(), lookup_call()]))


def check_structure(workflow_path):
    source = workflow_path.read_text(encoding="utf-8")
    header, separator, block = source.partition("        run: |\n")
    header = "".join(line + "\n" for line in header.splitlines()
                     if line.strip() and not line.lstrip().startswith("#"))
    problems = [name for name, text in HEADER.items() if text not in header]
    if header != "".join(HEADER.values()):
        problems.append("exact header with one job and one step")
    if not separator or any(line.strip() and not line.startswith("          ")
                            for line in block.splitlines()):
        problems.append("one literal run block")
    script = textwrap.dedent(block)
    if "${{" in script:
        problems.append("no expression in run")
    if "checkout" in script:
        problems.append("no checkout in run")
    return script, problems


def run_case(case, script, bindir):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        state_path = tmp / "state.json"
        state_path.write_text(json.dumps({"response": case.response, "fail": case.fail,
                                          "lookup_response": case.lookup_response,
                                          "calls": [], "comments": case.comments}), encoding="utf-8")
        env = {
            "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}",
            "WELCOME_STATE": str(state_path), "GH_TOKEN": "test-token", "GH_REPO": REPO,
            "NUMBER": case.number, "EVENT": case.event, "ASSOCIATION": case.association,
            "LOGIN": case.login, "LC_ALL": "C",
        }
        runs = [case]
        if case.rerun:
            runs.append(replace(case, want_rc=0,
                                want_calls=case.want_calls + [search_call(case.login), lookup_call()],
                                want_out=f"no welcome on #{NUMBER}: welcome exists\n", want_error=""))
        problems = []
        for attempt, expected in enumerate(runs, 1):
            result = subprocess.run(["bash", "-c", script], env=env, cwd=tmp, capture_output=True,
                                    text=True, stdin=subprocess.DEVNULL, timeout=30)
            final = json.loads(state_path.read_text(encoding="utf-8"))
            for name, got, want in (
                ("exit", result.returncode, expected.want_rc),
                ("calls", final["calls"], expected.want_calls),
                ("comments", final["comments"], expected.want_comments),
                ("output", result.stdout, expected.want_out),
                ("error", result.stderr, expected.want_error),
            ):
                if got != want:
                    problems.append(f"run {attempt} {name}: got {got!r}, want {want!r}")
            if len((result.stdout + result.stderr).splitlines()) != 1:
                problems.append(f"run {attempt}: output must contain exactly one line")
        if (tmp / "PWNED").exists():
            problems.append("event text runs as shell code")
        return problems


def run_suite(root, selected=None):
    script, problems = check_structure(root / WORKFLOW)
    failures = []
    if problems:
        failures.append(STRUCTURE)
        print(f"FAIL  {STRUCTURE}: {', '.join(problems)}")
    else:
        print(f"ok    {STRUCTURE}")
    cases = CASES
    if selected is not None:
        behavior = [name for name in selected if name != STRUCTURE]
        cases = [case for case in CASES if case.name in behavior]
        if len(cases) != len(behavior):
            raise AssertionError("selection names an unknown case")
    with tempfile.TemporaryDirectory() as bindir:
        stub = pathlib.Path(bindir) / "gh"
        stub.write_text(STUB.replace("#!PYTHON", f"#!{sys.executable}", 1), encoding="utf-8")
        stub.chmod(0o755)
        for case in cases:
            problems = run_case(case, script, bindir)
            if problems:
                failures.append(case.name)
                print(f"FAIL  {case.name}\n        " + "\n        ".join(problems))
            else:
                print(f"ok    {case.name}")
    print(f"welcome workflow test: {1 + len(cases) - len(failures)} of {1 + len(cases)} passed")
    return 1 if failures else 0


def mutation_controls(root):
    source = (root / WORKFLOW).read_text(encoding="utf-8")
    mutations = [(name, text, "", [STRUCTURE]) for name, text in HEADER.items()]
    for association in ("OWNER", "MEMBER", "COLLABORATOR"):
        mutations.append((f"skip {association}", "OWNER | MEMBER | COLLABORATOR",
                          " | ".join(role for role in ("OWNER", "MEMBER", "COLLABORATOR")
                                     if role != association),
                          [f"{association} pull request", f"{association} issue"]))
    mutations += [
        ("number guard", 'if ! [[ "$NUMBER" =~ ^[0-9]+$ ]]; then', 'if false; then', ["invalid number"]),
        ("event guard", 'pull_request_target | issues) ;;', '*) ;;', ["unsupported event"]),
        ("count guard", 'if [[ "$count" != 1 ]]; then', 'if false; then',
         ["second pull request", "second issue", "empty search"]),
        ("complete search", '.incomplete_results == false and ', '', ["incomplete search"]),
        ("search items", ' and (.items | type == "array")', '', ["invalid search items"]),
        ("nonnegative count", '. >= 0 and ', '', ["negative search count"]),
        ("integer count", ' and floor == .', '', ["string search count", "fractional search count"]),
        ("current contribution", 'if ! jq -e --arg number "$NUMBER" '
         "'.items[0].number == ($number | tonumber)' <<<\"$search\" >/dev/null 2>&1; then",
         'if false; then', ["another contribution in the search index"]),
        ("existing welcome", 'if jq -e \'any(.[]; .user.login? == "github-actions[bot]" and (.body | type == "string")\n'
         '            and (.body | startswith("Thanks for the pull request, @") or startswith("Thanks for the report, @")))\' '
         '<<<"$comments" >/dev/null 2>&1; then', 'if false; then', ["pull request rerun"]),
        ("welcome identity", '.user.login? == "github-actions[bot]" and ', '', ["welcome text from another user"]),
        ("lookup error exit", 'echo "::error::Cannot welcome #$NUMBER: comment lookup fails." >&2\n            exit 1',
         'echo "::error::Cannot welcome #$NUMBER: comment lookup fails." >&2', ["comment lookup error"]),
        ("repository search", 'q=repo:$GH_REPO author:$LOGIN', 'q=author:$LOGIN',
         ["first pull request by NONE", "first issue"]),
        ("author search", 'q=repo:$GH_REPO author:$LOGIN', 'q=repo:$GH_REPO', ["first pull request by NONE"]),
        ("combined search", 'q=repo:$GH_REPO author:$LOGIN', 'q=repo:$GH_REPO author:$LOGIN is:pr',
         ["first issue"]),
        ("search GET", 'gh api -X GET search/issues', 'gh api search/issues', ["first pull request by NONE"]),
        ("pull request body", 'if [[ "$EVENT" == pull_request_target ]]; then', 'if false; then',
         ["first pull request by NONE"]),
        ("issue body", 'Thanks for the report, @%s, and welcome.', 'Welcome, @%s.', ["first issue"]),
        ("comment post", 'if ! gh api --method POST "repos/$GH_REPO/issues/$NUMBER/comments" '
         '-f "body=$body" >/dev/null 2>&1; then', 'if false; then', ["first pull request by NONE", "first issue"]),
        ("search error exit", 'echo "::error::Cannot welcome #$NUMBER: search fails." >&2\n            exit 1',
         'echo "::error::Cannot welcome #$NUMBER: search fails." >&2\n            exit 0', ["search error"]),
        ("parse error exit", 'echo "::error::Cannot welcome #$NUMBER: invalid search result." >&2\n            exit 1',
         'echo "::error::Cannot welcome #$NUMBER: invalid search result." >&2\n            exit 0', ["malformed search"]),
        ("comment error exit", 'echo "::error::Cannot welcome #$NUMBER: comment fails." >&2\n            exit 1',
         'echo "::error::Cannot welcome #$NUMBER: comment fails." >&2\n            exit 0', ["comment error"]),
        ("search diagnostic line", '-f per_page=1 2>/dev/null', '-f per_page=1', ["search error"]),
        ("comment diagnostic line", '-f "body=$body" >/dev/null 2>&1', '-f "body=$body" >/dev/null', ["comment error"]),
        ("run expression", '          set -euo pipefail\n',
         "          set -euo pipefail\n          : '${{ github.event.issue.body }}'\n", [STRUCTURE]),
        ("checkout step", '    steps:\n', '    steps:\n      - uses: actions/checkout@v4\n', [STRUCTURE]),
        ("checkout command", '          set -euo pipefail\n',
         '          set -euo pipefail\n          git checkout HEAD\n', [STRUCTURE]),
    ]
    failures = 0
    for name, old, new, cases in mutations:
        found = source.count(old)
        if found != 1:
            print(f"FAIL  mutation {name}: pattern found {found} times, want 1")
            failures += 1
            continue
        with tempfile.TemporaryDirectory() as tmp:
            scratch = pathlib.Path(tmp)
            target = scratch / WORKFLOW
            target.parent.mkdir(parents=True)
            target.write_text(source.replace(old, new, 1), encoding="utf-8")
            command = [sys.executable, str(pathlib.Path(__file__).resolve()), str(scratch)]
            for case in cases:
                command += ["--case", case]
            result = subprocess.run(command, capture_output=True, text=True,
                                    stdin=subprocess.DEVNULL, timeout=60)
            detected = result.returncode == 1 and all(f"FAIL  {case}\n" in result.stdout
                        or f"FAIL  {case}:" in result.stdout for case in cases)
            if not detected:
                failures += 1
                print(f"FAIL  mutation {name}: exit {result.returncode}\n{result.stdout}{result.stderr}")
            else:
                print(f"ok    mutation {name}: exit {result.returncode}; fails {', '.join(cases)}")
    print(f"welcome mutation controls: {len(mutations) - failures} of {len(mutations)} passed")
    return 1 if failures else 0


def main():
    args = sys.argv[1:]
    root = pathlib.Path(__file__).resolve().parents[2]
    if args and not args[0].startswith("--"):
        root = pathlib.Path(args.pop(0))
    if args == ["--mutations"]:
        return mutation_controls(root)
    selected = []
    while args:
        if args.pop(0) != "--case" or not args:
            sys.exit("usage: test-welcome-workflow.py [ROOT] [--mutations | --case NAME]")
        selected.append(args.pop(0))
    return run_suite(root, selected or None)


if __name__ == "__main__":
    sys.exit(main())
