#!/usr/bin/env python3
"""Offline behavior test for the triage workflow.

Usage: test-triage-workflow.py [ROOT] [--mutations | --case NAME ...]

Loads the workflow with PyYAML and checks its structure, including the exact
job condition that skips bots and the per-issue concurrency group. Each
behavior case runs its run block under bash with six step variables and a stub
gh on PATH. The stub stores labels per issue in JSON and records every
argument list. Cases assert exact calls, labels, output, and exit codes. Needs
Python 3.9+, PyYAML, bash, and jq.

--case selects behavior cases by name. The structure case always runs, and
--case "workflow structure" runs it alone. Mutation controls remove a rule, a
guard, the bot condition, or the concurrency group in scratch copies and
require named cases to fail.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

import yaml

WORKFLOW = ".github/workflows/triage.yml"
REPO = "o/r"
NUMBER = "12"
ENDPOINT = f"repos/{REPO}/issues/{NUMBER}"
MAINTAINER = "waiting on maintainer"
AUTHOR = "waiting on author"
READ = ["api", ENDPOINT]
STRUCTURE = "workflow structure"
BOT_CONDITION = (
    "(github.event.comment.user.type || github.event.review.user.type "
    "|| github.event.pull_request.user.type || github.event.issue.user.type) != 'Bot'"
)

STUB = r'''#!PYTHON
import json, os, sys
from urllib.parse import unquote

state_path = os.environ["TRIAGE_STATE"]
with open(state_path, encoding="utf-8") as handle:
    state = json.load(handle)


def save():
    with open(state_path, "w", encoding="utf-8") as handle:
        json.dump(state, handle)


args = sys.argv[1:]
state["calls"].append(args)
save()
if not args or args[0] != "api":
    sys.exit(f"stub gh: unsupported command {args}")
method, path, fields = "GET", None, []
rest = args[1:]
while rest:
    word = rest.pop(0)
    if word == "--method":
        method = rest.pop(0)
    elif word == "-f":
        fields.append(rest.pop(0))
    elif path is None:
        path = word
    else:
        sys.exit(f"stub gh: unexpected argument {word}")
key = f"{method} {path}"
if key in state["fail"]:
    sys.exit(f"stub gh: HTTP 502 for {key}")
if key in state["malformed"]:
    print("<html>bad gateway</html>")
    sys.exit(0)
prefix = f"repos/{os.environ['GH_REPO']}/issues/"
parts = path[len(prefix):].split("/") if path.startswith(prefix) else []
if not parts or parts[0] not in state["issues"]:
    sys.exit(f"stub gh: unknown endpoint {key}")
issue = state["issues"][parts[0]]
if method == "GET" and len(parts) == 1 and not fields:
    body = {"labels": [{"name": label} for label in issue["labels"]]}
    if issue["pr"]:
        body["pull_request"] = {"url": "https://example.invalid/pull"}
    print(json.dumps(body))
elif method == "POST" and parts[1:] == ["labels"] and len(fields) == 1:
    if not fields[0].startswith("labels[]="):
        sys.exit("stub gh: missing labels[] field")
    label = fields[0].split("=", 1)[1]
    if label not in issue["labels"]:
        issue["labels"].append(label)
    save()
    print("[]")
elif method == "DELETE" and len(parts) == 3 and parts[1] == "labels" and not fields:
    label = unquote(parts[2])
    if label not in issue["labels"]:
        sys.exit("stub gh: HTTP 404 for absent label")
    issue["labels"].remove(label)
    save()
    print("[]")
else:
    sys.exit(f"stub gh: unknown endpoint {key}")
'''


def edit_call(operation, label):
    if operation == "add":
        return ["api", "--method", "POST", f"{ENDPOINT}/labels", "-f", f"labels[]={label}"]
    return ["api", "--method", "DELETE", f"{ENDPOINT}/labels/{label.replace(' ', '%20')}"]


@dataclass
class Case:
    name: str
    event: str = "issues:opened"
    association: str = "NONE"
    pr: bool = False
    body: str = "Thanks for the details."
    number: str = NUMBER
    labels: tuple = ("bug",)
    fail: tuple = ()
    malformed: tuple = ()
    want_rc: int = 0
    want_calls: list = field(default_factory=lambda: [READ])
    want_labels: tuple = ("bug",)
    want_out: str = f"no change on #{NUMBER}: no matching rule\n"
    want_error: str = ""


def change(name, event, labels, want_labels, edits, **kwargs):
    return Case(name, event=event, labels=labels, want_labels=want_labels,
                want_calls=[READ] + [edit_call(*edit) for edit in edits],
                want_out="".join(f"{op} {label} on #{NUMBER}\n" for op, label in edits)
                or f"no change on #{NUMBER}: labels already match\n", **kwargs)


CASES = []
for action in ("opened", "reopened"):
    CASES.append(change(f"external issue {action}", f"issues:{action}", ("bug", AUTHOR),
                        ("bug", AUTHOR, MAINTAINER), [("add", MAINTAINER)]))
for action in ("opened", "reopened", "synchronize"):
    CASES.append(change(f"external pull request {action}", f"pull_request_target:{action}",
                        ("bug", AUTHOR), ("bug", MAINTAINER),
                        [("add", MAINTAINER), ("remove", AUTHOR)], pr=True))
for pr, noun in ((False, "issue"), (True, "pull request")):
    CASES.append(change(f"external comment on {noun}", "issue_comment:created",
                        ("bug", AUTHOR), ("bug", MAINTAINER),
                        [("add", MAINTAINER), ("remove", AUTHOR)], pr=pr))
for association in ("OWNER", "MEMBER", "COLLABORATOR"):
    for event, noun in (("issue_comment:created", "comment"), ("pull_request_review:submitted", "review")):
        CASES.append(change(f"{association} {noun} on pull request", event,
                            ("bug", MAINTAINER), ("bug", AUTHOR),
                            [("add", AUTHOR), ("remove", MAINTAINER)], pr=True, association=association))
    CASES.append(change(f"{association} comment on issue", "issue_comment:created",
                        ("bug", MAINTAINER, AUTHOR), ("bug", AUTHOR),
                        [("remove", MAINTAINER)], association=association))
for association in ("CONTRIBUTOR", "FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "MANNEQUIN", ""):
    CASES.append(change(f"external association {association or 'empty'}", "issues:opened",
                        (), (MAINTAINER,), [("add", MAINTAINER)], association=association))

CASES += [
    change("issue already waits on maintainer", "issues:opened", ("bug", MAINTAINER, AUTHOR),
           ("bug", MAINTAINER, AUTHOR), []),
    change("maintainer issue comment with absent label", "issue_comment:created", ("bug", AUTHOR),
           ("bug", AUTHOR), [], association="OWNER"),
    change("maintainer issue comment adds no author label", "issue_comment:created", (MAINTAINER,),
           (), [("remove", MAINTAINER)], association="OWNER"),
]
for event, association, target, opposite, prefix in (
    ("pull_request_target:synchronize", "NONE", MAINTAINER, AUTHOR, "external pull request"),
    ("issue_comment:created", "NONE", MAINTAINER, AUTHOR, "external comment"),
    ("issue_comment:created", "MEMBER", AUTHOR, MAINTAINER, "maintainer comment"),
    ("pull_request_review:submitted", "MEMBER", AUTHOR, MAINTAINER, "maintainer review"),
):
    for suffix, labels, want_labels, edits in (
        ("both labels", ("bug", target, opposite), ("bug", target), [("remove", opposite)]),
        ("neither label", ("bug",), ("bug", target), [("add", target)]),
        ("labels already match", ("bug", target), ("bug", target), []),
    ):
        CASES.append(change(f"{prefix}: {suffix}", event, labels, want_labels, edits,
                            pr=True, association=association))

for event, pr in (
    ("issues:opened", False), ("issues:reopened", False),
    ("pull_request_target:opened", True), ("pull_request_target:reopened", True),
    ("pull_request_target:synchronize", True),
):
    CASES.append(Case(f"maintainer {event}", event=event, pr=pr, association="OWNER",
                      labels=("bug", MAINTAINER, AUTHOR), want_labels=("bug", MAINTAINER, AUTHOR)))
for event, pr, association in (
    ("pull_request_review:submitted", True, "NONE"),
    ("pull_request_review:submitted", False, "MEMBER"),
    ("pull_request_review:dismissed", True, "MEMBER"),
    ("pull_request_target:closed", True, "NONE"),
    ("issues:closed", False, "NONE"),
    ("issue_comment:edited", True, "NONE"),
    ("unknown:created", True, "NONE"),
):
    CASES.append(Case(f"no rule for {event} pr={pr} {association}", event=event, pr=pr,
                      association=association, labels=(AUTHOR,), want_labels=(AUTHOR,)))
for association in ("NONE", "MEMBER"):
    for pr in (False, True):
        CASES.append(Case(f"claim comment {association} pr={pr}", event="issue_comment:created",
                          association=association, pr=pr, body="Please\nTAKE THIS one.\nThanks!",
                          labels=(MAINTAINER, AUTHOR), want_labels=(MAINTAINER, AUTHOR),
                          want_calls=[], want_out=f"no change on #{NUMBER}: claim comment\n"))
CASES += [
    change("shell payload stays data", "issue_comment:created", (), (MAINTAINER,), [("add", MAINTAINER)],
           body='$(touch PWNED) `touch PWNED`; "\\\n${{ github.token }}',
           association='$(touch PWNED)'),
    change("empty comment body", "issue_comment:created", (), (MAINTAINER,), [("add", MAINTAINER)], body=""),
    Case("claim text on another event", body="take this", event="pull_request_review:submitted", pr=True),
    Case("label read fails", fail=(f"GET {ENDPOINT}",), want_rc=1, want_out="",
         want_error="::error::Cannot read labels."),
    Case("label read malformed", malformed=(f"GET {ENDPOINT}",), want_rc=1, want_out="",
         want_error="::error::Cannot parse labels."),
    Case("label addition fails", fail=(f"POST {ENDPOINT}/labels",), want_rc=1,
         want_calls=[READ, edit_call("add", MAINTAINER)], want_out="", want_error="::error::Cannot add label."),
    Case("label removal fails", event="issue_comment:created", association="MEMBER",
         labels=("bug", MAINTAINER), want_labels=("bug", MAINTAINER),
         fail=(f"DELETE {ENDPOINT}/labels/waiting%20on%20maintainer",), want_rc=1,
         want_calls=[READ, edit_call("remove", MAINTAINER)], want_out="", want_error="::error::Cannot remove label."),
    Case("second edit fails", event="pull_request_target:synchronize", pr=True,
         labels=(AUTHOR,), want_labels=(AUTHOR, MAINTAINER),
         fail=(f"DELETE {ENDPOINT}/labels/waiting%20on%20author",), want_rc=1,
         want_calls=[READ, edit_call("add", MAINTAINER), edit_call("remove", AUTHOR)],
         want_out=f"add {MAINTAINER} on #{NUMBER}\n", want_error="::error::Cannot remove label."),
]
for number in ("abc", "", "12/labels", "12; touch PWNED", "$(touch PWNED)", "12\n", "１２"):
    CASES.append(Case(f"invalid number {number!r}", number=number, want_rc=1,
                      want_calls=[], want_out="", want_error="::error::NUMBER must contain only digits."))


def check_structure(workflow_path):
    doc = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    # PyYAML reads the bare key on as the boolean True.
    trigger = doc.get(True, doc.get("on"))
    job = doc["jobs"]["triage"]
    step = job["steps"][0]
    expected = {
        "triggers": trigger == {
            "issues": {"types": ["opened", "reopened"]},
            "issue_comment": {"types": ["created"]},
            "pull_request_target": {"types": ["opened", "reopened", "synchronize"]},
            "pull_request_review": {"types": ["submitted"]},
        },
        "workflow permissions": doc.get("permissions") == {},
        "job permissions": job.get("permissions") == {"issues": "write", "pull-requests": "write"},
        "one job, one step": list(doc["jobs"]) == ["triage"] and len(job["steps"]) == 1,
        "no action or checkout": "uses" not in job and all("uses" not in s for s in job["steps"])
        and "checkout" not in step["run"],
        "bot condition": " ".join(str(job.get("if", "")).split()) == BOT_CONDITION,
        "runner": job.get("runs-on") == "ubuntu-latest",
        "timeout": job.get("timeout-minutes") == 5,
        "concurrency": job.get("concurrency") == {
            "group": "triage-${{ github.event.issue.number || github.event.pull_request.number }}",
            "cancel-in-progress": False,
        },
        "shell": step.get("shell") == "bash",
        "environment": step.get("env") == {
            "GH_TOKEN": "${{ github.token }}",
            "GH_REPO": "${{ github.repository }}",
            "NUMBER": "${{ github.event.issue.number || github.event.pull_request.number }}",
            "EVENT": "${{ format('{0}:{1}', github.event_name, github.event.action) }}",
            "ASSOCIATION": "${{ github.event.comment.author_association || github.event.review.author_association "
            "|| github.event.pull_request.author_association || github.event.issue.author_association }}",
            "COMMENT_BODY": "${{ github.event.comment.body }}",
        },
        "no expression in run": "${{" not in step["run"],
    }
    return step["run"], [name for name, ok in expected.items() if not ok]


def run_case(case, script, bindir):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        state_path = tmp / "state.json"
        state = {
            "issues": {NUMBER: {"labels": list(case.labels), "pr": case.pr},
                       "99": {"labels": ["untouched"], "pr": False}},
            "calls": [], "fail": case.fail, "malformed": case.malformed,
        }
        state_path.write_text(json.dumps(state), encoding="utf-8")
        env = {
            "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}",
            "TRIAGE_STATE": str(state_path), "GH_TOKEN": "test-token", "GH_REPO": REPO,
            "NUMBER": case.number, "EVENT": case.event, "ASSOCIATION": case.association,
            "COMMENT_BODY": case.body, "LC_ALL": "C",
        }
        result = subprocess.run(["bash", "-c", script], env=env, cwd=tmp, capture_output=True,
                                text=True, stdin=subprocess.DEVNULL, timeout=30)
        final = json.loads(state_path.read_text(encoding="utf-8"))
        problems = []
        for name, got, want in (
            ("exit", result.returncode, case.want_rc),
            ("calls", final["calls"], case.want_calls),
            ("labels", sorted(final["issues"][NUMBER]["labels"]), sorted(case.want_labels)),
            ("other issue", final["issues"]["99"], state["issues"]["99"]),
            ("output", result.stdout, case.want_out),
        ):
            if got != want:
                problems.append(f"{name}: got {got!r}, want {want!r}")
        if case.want_error and case.want_error not in result.stderr:
            problems.append(f"stderr {result.stderr!r} lacks {case.want_error!r}")
        if not case.want_error and result.stderr:
            problems.append(f"unexpected stderr {result.stderr!r}")
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
            raise AssertionError("mutation names an unknown case")
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
    print(f"triage workflow test: {1 + len(cases) - len(failures)} of {1 + len(cases)} passed")
    return 1 if failures else 0


def mutation_controls(root):
    source = (root / WORKFLOW).read_text(encoding="utf-8")
    mutations = [
        ("rule 1", "            add='waiting on maintainer'\n", "            :\n", 3,
         ["external issue opened", "external issue reopened"]),
        ("rule 2", "            add='waiting on maintainer'\n            remove='waiting on author'\n",
         "            :\n", 2, ["external pull request synchronize"]),
        ("rule 3", "          elif [[ \"$EVENT\" == issue_comment:created && \"$maintainer\" == false ]]; then\n"
         "            add='waiting on maintainer'\n            remove='waiting on author'\n",
         "          elif [[ \"$EVENT\" == issue_comment:created && \"$maintainer\" == false ]]; then\n"
         "            :\n", 1, ["external comment on issue", "external comment on pull request"]),
        ("rule 4", "            add='waiting on author'\n            remove='waiting on maintainer'\n",
         "            :\n", 1, ["OWNER comment on pull request", "MEMBER review on pull request"]),
        ("rule 5", "            remove='waiting on maintainer'\n          else\n",
         "            :\n          else\n", 1, ["OWNER comment on issue"]),
        ("rule 6 fallback", "            echo \"no change on #$NUMBER: no matching rule\"\n            exit 0\n",
         "            add='waiting on maintainer'\n", 1,
         ["no rule for pull_request_review:submitted pr=True NONE"]),
        ("rule 6 add idempotence", " && ! jq -e --arg label \"$add\" 'index($label) != null' <<<\"$labels\" >/dev/null",
         "", 1, ["issue already waits on maintainer", "maintainer comment: labels already match"]),
        ("rule 6 remove idempotence", " && jq -e --arg label \"$remove\" 'index($label) != null' <<<\"$labels\" >/dev/null",
         "", 1, ["external pull request: labels already match", "maintainer issue comment with absent label"]),
        ("claim skip", "            echo \"no change on #$NUMBER: claim comment\"\n            exit 0\n",
         "            :\n", 1, ["claim comment NONE pr=False", "claim comment MEMBER pr=True"]),
        ("bot filter", "      (github.event.comment.user.type || github.event.review.user.type\n"
         "      || github.event.pull_request.user.type || github.event.issue.user.type) != 'Bot'",
         "      'true'", 1, [STRUCTURE]),
        ("concurrency", "    concurrency:\n"
         "      group: triage-${{ github.event.issue.number || github.event.pull_request.number }}\n"
         "      cancel-in-progress: false\n", "", 1, [STRUCTURE]),
    ]
    failures = 0
    for name, old, new, count, cases in mutations:
        found = source.count(old)
        if found != count:
            print(f"FAIL  mutation {name}: pattern found {found} times, want {count}")
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
            sys.exit("usage: test-triage-workflow.py [ROOT] [--mutations | --case NAME]")
        selected.append(args.pop(0))
    return run_suite(root, selected or None)


if __name__ == "__main__":
    sys.exit(main())
