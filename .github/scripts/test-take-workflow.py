#!/usr/bin/env python3
"""Offline behavior test for the take workflow.

Usage: test-take-workflow.py [ROOT]

Loads .github/workflows/take.yml from ROOT (default: this repository) with
PyYAML. One case checks the workflow structure: the trigger, the permissions,
the job condition, the timeout, the concurrency group, and that event text
reaches the script only through the step environment. Every other case runs
the step's `run:` block under bash with the five step variables and a stub
`gh` first on PATH.

The stub serves a simulated repository from a JSON state file. It answers the
issue read, the paginated assignee listing, the assignment, the removal, and
the comment calls. It applies their effects to the state and records each call
with its method, endpoint, and fields. A case can make a call fail, return a
malformed body, or drop the assignment. A hook can change the state or run a
second claim before a call. Each case asserts the exact call list, the final
assignees, the comments, the exit code, and a fragment of the output. Needs
PyYAML, bash, and jq.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

import yaml

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parents[2])
WORKFLOW = ".github/workflows/take.yml"
REPO = "o/r"
LISTING = f"repos/{REPO}/issues?state=open&assignee=bob&per_page=100"
RULE = "Each contributor holds one open assignment at a time."
CURLY = chr(8217)

STUB = r'''#!PYTHON
import json, os, subprocess, sys

state_path = os.environ["TAKE_STATE"]
run_label = os.environ["TAKE_RUN"]


def load():
    with open(state_path, encoding="utf-8") as handle:
        return json.load(handle)


def save(state):
    with open(state_path, "w", encoding="utf-8") as handle:
        json.dump(state, handle)


def holds(issue, login):
    return any(a.lower() == login.lower() for a in issue["assignees"])


def render(issue):
    body = {
        "number": issue["number"],
        "state": issue["state"],
        "labels": [{"name": name} for name in issue["labels"]],
        "assignees": [{"login": login} for login in issue["assignees"]],
    }
    if issue["pr"]:
        body["pull_request"] = {"url": "https://example.invalid/pull"}
    return body


args = sys.argv[1:]
if not args or args[0] != "api":
    sys.exit(f"stub gh: unsupported command {args}")
method, paginate, path, fields = "GET", False, None, []
rest = args[1:]
while rest:
    word = rest.pop(0)
    if word == "--method":
        method = rest.pop(0)
    elif word == "--paginate":
        paginate = True
    elif word == "-f":
        fields.append(rest.pop(0))
    elif path is None:
        path = word
    else:
        sys.exit(f"stub gh: unexpected argument {word}")
call = " ".join([run_label, method, path] + (["--paginate"] if paginate else []) + fields)

state = load()
state["calls"].append(call)
save(state)

hook_key = " ".join([method, path])
for hook in state["hooks"]:
    if hook["on"] == f"{run_label} {hook_key}" and not hook["fired"]:
        hook["fired"] = True
        save(state)
        if hook["kind"] == "run":
            env = dict(os.environ)
            env.update(hook["env"])
            result = subprocess.run(["bash", "-c", os.environ["TAKE_SCRIPT"]], env=env,
                                    capture_output=True, text=True, stdin=subprocess.DEVNULL)
            state = load()
            state["nested"].append({"run": hook["env"]["TAKE_RUN"], "rc": result.returncode,
                                    "stdout": result.stdout, "stderr": result.stderr})
        else:
            state = load()
            issue = state["issues"][str(hook["issue"])]
            if hook["kind"] == "assign":
                issue["assignees"].append(hook["login"])
            else:
                issue["assignees"] = [a for a in issue["assignees"] if a.lower() != hook["login"].lower()]
        save(state)
        break

occurrence = sum(1 for c in state["calls"] if c.split(" ")[:3] == [run_label, method, path])
if hook_key in state["fail"] or f"{hook_key} #{occurrence}" in state["fail"]:
    sys.exit(f"stub gh: HTTP 502 for {hook_key}")
if hook_key in state["malformed"]:
    print("<html>bad gateway</html>")
    sys.exit(0)

prefix = f"repos/{os.environ['GH_REPO']}/issues"
issues = state["issues"]
if method == "GET" and path.startswith(prefix + "?"):
    query = dict(part.split("=", 1) for part in path.split("?", 1)[1].split("&"))
    login = query["assignee"]
    items = [render(i) for i in issues.values() if i["state"] == "open" and holds(i, login)]
    items += state["noise"]
    items.sort(key=lambda item: item["number"], reverse=True)
    size = state["page_size"]
    pages = [items[start:start + size] for start in range(0, len(items), size)] or [[]]
    for page in pages:
        print(json.dumps(page))
    sys.exit(0)

parts = path[len(prefix) + 1:].split("/") if path.startswith(prefix + "/") else []
if not parts or parts[0] not in issues:
    sys.exit(f"stub gh: unknown endpoint {method} {path}")
issue = issues[parts[0]]
values = {}
for item in fields:
    key, value = item.split("=", 1)
    values.setdefault(key, []).append(value)
if method == "GET" and len(parts) == 1:
    print(json.dumps(render(issue)))
elif method == "POST" and parts[1:] == ["assignees"]:
    if not state["drop_assignment"]:
        for login in values["assignees[]"]:
            if not holds(issue, login):
                issue["assignees"].append(state["canonical"].get(login, login))
    save(state)
    print(json.dumps(render(issue)))
elif method == "DELETE" and parts[1:] == ["assignees"]:
    for login in values["assignees[]"]:
        issue["assignees"] = [a for a in issue["assignees"] if a.lower() != login.lower()]
    save(state)
    print(json.dumps(render(issue)))
elif method == "POST" and parts[1:] == ["comments"]:
    state["comments"].setdefault(parts[0], []).append(values["body"][0])
    save(state)
    print(json.dumps({"id": len(state["comments"][parts[0]])}))
else:
    sys.exit(f"stub gh: unknown endpoint {method} {path}")
'''


def issue(number, labels=("help wanted",), assignees=(), state="open", pr=False):
    return {"number": number, "state": state, "labels": list(labels),
            "assignees": list(assignees), "pr": pr}


def calls(run, number, *steps):
    """Expands step names into the exact call strings of one run."""
    expanded = []
    for step in steps:
        kind, _, arg = step.partition(":")
        if kind == "read":
            expanded.append(f"{run} GET repos/{REPO}/issues/{arg or number}")
        elif kind == "list":
            expanded.append(f"{run} GET {LISTING} --paginate")
        elif kind == "assign":
            expanded.append(f"{run} POST repos/{REPO}/issues/{number}/assignees assignees[]=bob")
        elif kind == "remove":
            expanded.append(f"{run} DELETE repos/{REPO}/issues/{arg}/assignees assignees[]=bob")
        elif kind == "comment":
            target, _, text = arg.partition("|")
            expanded.append(f"{run} POST repos/{REPO}/issues/{target}/comments body={text}")
        else:
            raise AssertionError(f"unknown step {step}")
    return expanded


FREE = ("read", "list", "assign", "list")
FAILS = "nonzero"


@dataclass
class Case:
    name: str
    body: str = "I'll take this"
    number: int = 7
    issues: list = field(default_factory=lambda: [issue(7)])
    noise: list = field(default_factory=list)
    page_size: int = 100
    fail: list = field(default_factory=list)
    malformed: list = field(default_factory=list)
    drop_assignment: bool = False
    canonical: dict = field(default_factory=dict)
    hooks: list = field(default_factory=list)
    # FAILS accepts any nonzero exit code.
    want_rc: object = 0
    want_calls: list = None
    want_assignees: dict = None
    want_comments: dict = field(default_factory=dict)
    want_out: str = ""
    want_nested: dict = field(default_factory=dict)


def no_claim(name, body):
    return Case(name, body=body, want_calls=[], want_assignees={7: []}, want_out="not a claim")


def claim(name, body):
    return Case(name, body=body, want_calls=calls("R", 7, *FREE), want_assignees={7: ["bob"]},
                want_out="Assigned issue #7 to bob.")


CASES = [
    claim("straight apostrophe", "I'll take this"),
    claim("final period", "I'll take this."),
    claim("surrounding spaces", " i'll take this "),
    claim("typographic apostrophe", f"I{CURLY}ll take this"),
    claim("case, blank lines, CRLF, and period", "\n\nI'LL TAKE THIS.\r\n"),
    no_claim("newline before the period", "I'll take this\n."),
    no_claim("empty body", ""),
    no_claim("space before the period", "I'll take this ."),
    no_claim("two periods", "I'll take this.."),
    no_claim("exclamation mark", "I'll take this!"),
    no_claim("extra word", "I'll take this one"),
    no_claim("question", "Can I take this?"),
    no_claim("second line", "I'll take this\nThanks"),
    no_claim("quotes and backslashes", "\"I'll take this\\\""),
    no_claim("shell payload", "I'll take this $(touch PWNED) `touch PWNED`; touch PWNED"),
    Case("closed issue", issues=[issue(7, state="closed")], want_calls=calls("R", 7, "read"),
         want_assignees={7: []}, want_out="No assignment: not-open."),
    Case("pull request", issues=[issue(7, pr=True)], want_calls=calls("R", 7, "read"),
         want_assignees={7: []}, want_out="No assignment: not-open."),
    Case("neither label", issues=[issue(7, labels=("bug",))], want_calls=calls("R", 7, "read"),
         want_assignees={7: []}, want_out="No assignment: unlabeled."),
    Case("own assignment, other case", issues=[issue(7, assignees=("BoB",))],
         want_calls=calls("R", 7, "read"), want_assignees={7: ["BoB"]}, want_out="No assignment: own."),
    Case("taken by one", issues=[issue(7, assignees=("alice",))],
         want_calls=calls("R", 7, "read", "comment:7|@bob, this issue is already assigned to @alice."),
         want_assignees={7: ["alice"]},
         want_comments={7: ["@bob, this issue is already assigned to @alice."]},
         want_out="assigned to @alice"),
    Case("taken by two", issues=[issue(7, assignees=("alice", "carol"))],
         want_calls=calls("R", 7, "read", "comment:7|@bob, this issue is already assigned to @alice and @carol."),
         want_assignees={7: ["alice", "carol"]},
         want_comments={7: ["@bob, this issue is already assigned to @alice and @carol."]},
         want_out="assigned to @alice and @carol"),
    Case("taken by three", issues=[issue(7, assignees=("alice", "carol", "dave"))],
         want_calls=calls("R", 7, "read",
                          "comment:7|@bob, this issue is already assigned to @alice, @carol, and @dave."),
         want_assignees={7: ["alice", "carol", "dave"]},
         want_comments={7: ["@bob, this issue is already assigned to @alice, @carol, and @dave."]},
         want_out="assigned to @alice, @carol, and @dave"),
    Case("free, help wanted", want_calls=calls("R", 7, *FREE), want_assignees={7: ["bob"]},
         want_out="Assigned issue #7 to bob."),
    Case("free, good first issue", issues=[issue(7, labels=("good first issue",))],
         want_calls=calls("R", 7, *FREE), want_assignees={7: ["bob"]}, want_out="Assigned issue #7 to bob."),
    Case("assignment answers with another login case", canonical={"bob": "Bob"},
         want_calls=calls("R", 7, *FREE), want_assignees={7: ["Bob"]}, want_out="Assigned issue #7 to bob."),
    Case("held issue on the second page, with a pull request and other users",
         issues=[issue(7), issue(30, assignees=("bob",), pr=True), issue(12, assignees=("BOB",))],
         noise=[{"number": 20, "assignees": [{"login": "dave"}]}], page_size=2,
         want_calls=calls("R", 7, "read", "list", f"comment:7|@bob, you already hold #12. {RULE}"),
         want_assignees={7: [], 12: ["BOB"], 30: ["bob"]},
         want_comments={7: [f"@bob, you already hold #12. {RULE}"]}, want_out="bob holds #12"),
    Case("only an assigned pull request in the listing",
         issues=[issue(7), issue(30, assignees=("bob",), pr=True)],
         want_calls=calls("R", 7, *FREE), want_assignees={7: ["bob"], 30: ["bob"]},
         want_out="Assigned issue #7 to bob."),
    Case("this issue listed for the commenter", noise=[{"number": 7, "assignees": [{"login": "bob"}]}],
         want_calls=calls("R", 7, *FREE), want_assignees={7: ["bob"]}, want_out="Assigned issue #7 to bob."),
    Case("assignment dropped by GitHub", drop_assignment=True,
         want_rc=1, want_calls=calls("R", 7, "read", "list", "assign"), want_assignees={7: []},
         want_out="::error::GitHub did not assign issue #7 to bob."),
    Case("issue read fails", fail=[f"GET repos/{REPO}/issues/7"], want_rc=1,
         want_calls=calls("R", 7, "read"), want_assignees={7: []}),
    Case("issue read malformed", malformed=[f"GET repos/{REPO}/issues/7"], want_rc=FAILS,
         want_calls=calls("R", 7, "read"), want_assignees={7: []}),
    Case("taken comment fails", issues=[issue(7, assignees=("alice",))],
         fail=[f"POST repos/{REPO}/issues/7/comments"], want_rc=1,
         want_calls=calls("R", 7, "read", "comment:7|@bob, this issue is already assigned to @alice."),
         want_assignees={7: ["alice"]}),
    Case("listing fails", fail=[f"GET {LISTING}"], want_rc=1,
         want_calls=calls("R", 7, "read", "list"), want_assignees={7: []}),
    Case("assignment fails", fail=[f"POST repos/{REPO}/issues/7/assignees"], want_rc=1,
         want_calls=calls("R", 7, "read", "list", "assign"), want_assignees={7: []}),
    Case("second listing fails", fail=[f"GET {LISTING} #2"], want_rc=1,
         want_calls=calls("R", 7, *FREE), want_assignees={7: ["bob"]}),
    Case("lower claim waits while a claim on a higher issue completes",
         number=5, issues=[issue(5), issue(9)],
         hooks=[{"on": f"R POST repos/{REPO}/issues/5/assignees", "kind": "run",
                 "env": {"TAKE_RUN": "R9", "NUMBER": "9"}}],
         want_calls=calls("R", 5, "read", "list", "assign")
         + calls("R9", 9, "read", "list", "assign", "list")
         + calls("R", 5, "list", "read:9", "remove:9", f"comment:9|@bob, you already hold #5. {RULE}"),
         want_assignees={5: ["bob"], 9: []}, want_comments={9: [f"@bob, you already hold #5. {RULE}"]},
         want_out="Assigned issue #5 to bob.",
         want_nested={"R9": (0, "Assigned issue #9 to bob.")}),
    Case("higher claim waits while a claim on a lower issue completes",
         number=9, issues=[issue(5), issue(9)],
         hooks=[{"on": f"R POST repos/{REPO}/issues/9/assignees", "kind": "run",
                 "env": {"TAKE_RUN": "R5", "NUMBER": "5"}}],
         want_calls=calls("R", 9, "read", "list", "assign")
         + calls("R5", 5, "read", "list", "assign", "list")
         + calls("R", 9, "list", "read:9", "remove:9", f"comment:9|@bob, you already hold #5. {RULE}"),
         want_assignees={5: ["bob"], 9: []}, want_comments={9: [f"@bob, you already hold #5. {RULE}"]},
         want_out="No assignment: bob holds #5, so #9 is released.",
         want_nested={"R5": (0, "Assigned issue #5 to bob.")}),
    Case("racing claim already released its higher issue",
         number=5, issues=[issue(5), issue(9)],
         hooks=[{"on": f"R POST repos/{REPO}/issues/5/assignees", "kind": "assign", "issue": 9, "login": "bob"},
                {"on": f"R GET repos/{REPO}/issues/9", "kind": "unassign", "issue": 9, "login": "bob"}],
         want_calls=calls("R", 5, "read", "list", "assign", "list", "read:9"),
         want_assignees={5: ["bob"], 9: []}, want_out="Assigned issue #5 to bob."),
    Case("removal fails", number=5, issues=[issue(5), issue(9)],
         hooks=[{"on": f"R POST repos/{REPO}/issues/5/assignees", "kind": "assign", "issue": 9, "login": "bob"}],
         fail=[f"DELETE repos/{REPO}/issues/9/assignees"], want_rc=1,
         want_calls=calls("R", 5, "read", "list", "assign", "list", "read:9", "remove:9"),
         want_assignees={5: ["bob"], 9: ["bob"]}),
]


def check_structure(workflow_path):
    doc = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    # PyYAML reads the bare key `on` as the boolean True.
    trigger = doc.get(True, doc.get("on"))
    job = doc["jobs"]["take"]
    step = job["steps"][0]
    condition = " ".join(job["if"].split())
    problems = []
    expected = {
        "trigger": trigger == {"issue_comment": {"types": ["created"]}},
        "workflow permissions": doc.get("permissions") == {"issues": "write"},
        "no job permissions": "permissions" not in job,
        "one job, one step": list(doc["jobs"]) == ["take"] and len(job["steps"]) == 1,
        "no action": all("uses" not in s for s in job["steps"]),
        "condition": condition == ("!github.event.issue.pull_request && github.event.issue.state == 'open' "
                                   "&& github.event.comment.user.type != 'Bot' "
                                   "&& contains(github.event.comment.body, 'take this')"),
        "timeout": job["timeout-minutes"] == 5,
        "concurrency": job["concurrency"] == {"group": "take-${{ github.event.issue.number }}",
                                              "cancel-in-progress": False},
        "shell": step.get("shell") == "bash",
        "environment": step["env"] == {
            "GH_TOKEN": "${{ github.token }}",
            "GH_REPO": "${{ github.repository }}",
            "COMMENT_BODY": "${{ github.event.comment.body }}",
            "LOGIN": "${{ github.event.comment.user.login }}",
            "NUMBER": "${{ github.event.issue.number }}",
        },
        "no expression in run": "${{" not in step["run"],
    }
    for name, ok in expected.items():
        if not ok:
            problems.append(name)
    return step["run"], problems


def run_case(case, script, bindir):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        state = {
            "issues": {str(i["number"]): i for i in case.issues},
            "noise": case.noise, "page_size": case.page_size, "fail": case.fail,
            "malformed": case.malformed, "drop_assignment": case.drop_assignment,
            "canonical": case.canonical, "hooks": [dict(h, fired=False) for h in case.hooks],
            "calls": [], "comments": {}, "nested": [],
        }
        state_path = tmp / "state.json"
        state_path.write_text(json.dumps(state), encoding="utf-8")
        env = {
            "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}",
            "TAKE_STATE": str(state_path), "TAKE_SCRIPT": script, "TAKE_RUN": "R",
            "GH_TOKEN": "test-token", "GH_REPO": REPO, "COMMENT_BODY": case.body,
            "LOGIN": "bob", "NUMBER": str(case.number), "LC_ALL": "C.UTF-8",
        }
        result = subprocess.run(["bash", "-c", script], env=env, cwd=tmp, capture_output=True,
                                text=True, stdin=subprocess.DEVNULL, timeout=60)
        final = json.loads(state_path.read_text(encoding="utf-8"))
        problems = []
        if case.want_rc == FAILS:
            if result.returncode == 0:
                problems.append("exit 0, want a failure")
        elif result.returncode != case.want_rc:
            problems.append(f"exit {result.returncode}, want {case.want_rc}")
        got_calls = final["calls"]
        want_calls = case.want_calls
        if got_calls != want_calls:
            problems.append("calls differ:\n          got  " + "\n               ".join(got_calls)
                            + "\n          want " + "\n               ".join(want_calls))
        for number, want in (case.want_assignees or {}).items():
            got = final["issues"][str(number)]["assignees"]
            if got != want:
                problems.append(f"assignees of #{number}: {got}, want {want}")
        got_comments = {int(k): v for k, v in final["comments"].items()}
        if got_comments != case.want_comments:
            problems.append(f"comments {got_comments}, want {case.want_comments}")
        if case.want_out not in result.stdout:
            problems.append(f"output {result.stdout!r} lacks {case.want_out!r}")
        for run, (rc, out) in case.want_nested.items():
            nested = [n for n in final["nested"] if n["run"] == run]
            if len(nested) != 1 or nested[0]["rc"] != rc or out not in nested[0]["stdout"]:
                problems.append(f"nested run {run}: {nested}, want exit {rc} and {out!r}")
        if (tmp / "PWNED").exists():
            problems.append("the comment body ran as shell code")
        if problems and result.stderr.strip():
            problems.append(f"stderr {result.stderr.strip()!r}")
        return problems


def main():
    workflow_path = ROOT / WORKFLOW
    script, problems = check_structure(workflow_path)
    failures = 0
    total = 1 + len(CASES)
    if problems:
        failures += 1
        print(f"FAIL  workflow structure: {', '.join(problems)}")
    else:
        print("ok    workflow structure")
    with tempfile.TemporaryDirectory() as bindir:
        stub = pathlib.Path(bindir) / "gh"
        stub.write_text(STUB.replace("#!PYTHON", f"#!{sys.executable}", 1), encoding="utf-8")
        stub.chmod(0o755)
        for case in CASES:
            problems = run_case(case, script, bindir)
            if problems:
                failures += 1
                print(f"FAIL  {case.name}\n        " + "\n        ".join(problems))
            else:
                print(f"ok    {case.name}")
    print(f"take workflow test: {total - failures} of {total} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
