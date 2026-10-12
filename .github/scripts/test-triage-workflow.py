#!/usr/bin/env python3
"""Offline behavior test for the triage workflow.

Usage: test-triage-workflow.py [ROOT] [--mutations | --case NAME ...]

Loads the workflow with PyYAML and checks its triggers, job conditions,
permissions, and concurrency groups. Each behavior case runs the live or
sweep run block under bash with step variables and a stub gh on PATH.
The stub serves per-case JSON pages, stores labels per issue, and records
every argument list. Cases assert exact calls, labels, output, and exit codes.
Needs Python 3.9+, PyYAML, bash, and jq.

--case selects behavior cases by name. The structure case always runs, and
--case "workflow structure" runs it alone. Mutation controls remove rules,
guards, triggers, job conditions, concurrency groups, sweep filters, the
contributor review input, and head or label-time comparisons in scratch
copies.
Each control requires named cases to fail.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field, replace

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
    "github.event_name != 'schedule' && github.event_name != 'workflow_dispatch' && "
    "((github.event.comment.user.type || github.event.pull_request.user.type "
    "|| github.event.issue.user.type) != 'Bot')"
)
SWEEP_CONDITION = "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"
LISTING = f"repos/{REPO}/issues?state=open&labels=waiting%20on%20maintainer&per_page=100"
LIST = ["api", LISTING, "--paginate"]
REVIEWS = f"repos/{REPO}/pulls/{NUMBER}/reviews"
PULL = f"repos/{REPO}/pulls/{NUMBER}"
COMMENTS = f"{ENDPOINT}/comments"
REVIEW_COMMENTS = f"{PULL}/comments"
EVENTS = f"{ENDPOINT}/events"
SWEEP_READS = [LIST, ["api", REVIEWS, "--paginate"], ["api", PULL],
               ["api", COMMENTS, "--paginate"], ["api", REVIEW_COMMENTS, "--paginate"],
               ["api", EVENTS, "--paginate"], READ]
CURRENT_HEAD = "a" * 40
PREVIOUS_HEAD = "b" * 40
EARLY = "2026-10-12T10:00:00Z"
MIDDLE = "2026-10-12T11:00:00Z"
LATE = "2026-10-12T12:00:00Z"

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
method, path, fields, paginate = "GET", None, [], False
rest = args[1:]
while rest:
    word = rest.pop(0)
    if word == "--method":
        method = rest.pop(0)
    elif word == "-f":
        fields.append(rest.pop(0))
    elif word == "--paginate":
        paginate = True
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
if method == "GET" and path in state["pages"] and paginate and not fields:
    for page in state["pages"][path]:
        print(json.dumps(page))
    sys.exit(0)
if paginate:
    sys.exit(f"stub gh: unknown paginated endpoint {key}")
if method == "GET" and path in state["responses"] and not fields:
    print(json.dumps(state["responses"][path]))
    sys.exit(0)
prefix = f"repos/{os.environ['GH_REPO']}/issues/"
parts = path[len(prefix):].split("/") if path.startswith(prefix) else []
if not parts or parts[0] not in state["issues"]:
    sys.exit(f"stub gh: unknown endpoint {key}")
issue = state["issues"][parts[0]]
if method == "GET" and len(parts) == 1 and not fields:
    body = {"labels": [{"name": label} for label in issue["labels"]],
            "state": issue.get("state", "open")}
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


def edit_call(operation, label, number=NUMBER):
    endpoint = f"repos/{REPO}/issues/{number}"
    if operation == "add":
        return ["api", "--method", "POST", f"{endpoint}/labels", "-f", f"labels[]={label}"]
    return ["api", "--method", "DELETE", f"{endpoint}/labels/{label.replace(' ', '%20')}"]


@dataclass
class Case:
    name: str
    event: str = "issues:opened"
    association: str = "NONE"
    pr: bool = False
    state: str = "open"
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


def closing(name, event, labels, want_labels, removed, **kwargs):
    return Case(name, event=event, state="closed", labels=labels, want_labels=want_labels,
                want_calls=[READ] + [edit_call("remove", label) for label in removed],
                want_out="".join(f"remove {label} on #{NUMBER}\n" for label in removed)
                or f"no change on #{NUMBER}: closed without waiting labels\n", **kwargs)


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
    CASES.append(change(f"{association} comment on pull request", "issue_comment:created",
                        ("bug", MAINTAINER), ("bug", AUTHOR),
                        [("add", AUTHOR), ("remove", MAINTAINER)], pr=True, association=association))
    CASES.append(change(f"{association} comment on issue", "issue_comment:created",
                        ("bug", MAINTAINER, AUTHOR), ("bug", AUTHOR),
                        [("remove", MAINTAINER)], association=association))
for association in ("CONTRIBUTOR", "FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "MANNEQUIN", ""):
    CASES.append(change(f"external association {association or 'empty'}", "issues:opened",
                        (), (MAINTAINER,), [("add", MAINTAINER)], association=association))

CASES += [
    closing("closed pull request: both waiting labels", "pull_request_target:closed",
            (MAINTAINER, AUTHOR), (), [MAINTAINER, AUTHOR], pr=True),
    closing("closed pull request: author label only", "pull_request_target:closed",
            ("bug", AUTHOR), ("bug",), [AUTHOR], pr=True, association="MEMBER"),
    closing("closed issue: maintainer label", "issues:closed", ("bug", MAINTAINER), ("bug",),
            [MAINTAINER]),
    closing("closed pull request: no waiting label", "pull_request_target:closed", ("bug",),
            ("bug",), [], pr=True),
    replace(closing("closed pull request: label removal fails", "pull_request_target:closed",
                    ("bug", MAINTAINER, AUTHOR), ("bug", MAINTAINER, AUTHOR), [MAINTAINER], pr=True),
            fail=(f"DELETE {ENDPOINT}/labels/waiting%20on%20maintainer",), want_rc=1, want_out="",
            want_error="::error::Cannot remove label."),
    replace(closing("closed pull request: second label removal fails", "pull_request_target:closed",
                    ("bug", MAINTAINER, AUTHOR), ("bug", AUTHOR), [MAINTAINER, AUTHOR], pr=True),
            fail=(f"DELETE {ENDPOINT}/labels/waiting%20on%20author",), want_rc=1,
            want_out=f"remove {MAINTAINER} on #{NUMBER}\n", want_error="::error::Cannot remove label."),
    Case("closed pull request: maintainer comment", event="issue_comment:created", association="MEMBER",
         pr=True, state="closed", labels=("bug", MAINTAINER), want_labels=("bug", MAINTAINER),
         want_out=f"no change on #{NUMBER}: closed\n"),
    Case("closed issue: external comment", event="issue_comment:created", state="closed",
         labels=("bug", AUTHOR), want_labels=("bug", AUTHOR), want_out=f"no change on #{NUMBER}: closed\n"),
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
    ("pull_request_target:edited", True, "NONE"),
    ("issues:edited", False, "NONE"),
    ("issue_comment:edited", True, "NONE"),
    ("unknown:created", True, "NONE"),
):
    CASES.append(Case(f"no rule for {event} pr={pr} {association}", event=event, pr=pr,
                      association=association, labels=(AUTHOR,), want_labels=(AUTHOR,)))
for event, pr in (("pull_request_target:closed", True), ("issues:closed", False)):
    CASES.append(Case(f"reopened before the run: {event}", event=event, pr=pr,
                      labels=("bug", MAINTAINER, AUTHOR), want_labels=("bug", MAINTAINER, AUTHOR),
                      want_out=f"no change on #{NUMBER}: reopened\n"))
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
    Case("claim text on another event", body="take this", event="pull_request_target:opened",
         pr=True, association="MEMBER"),
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


@dataclass
class SweepCase:
    name: str
    issues: dict
    pages: dict
    want_calls: list
    want_labels: dict
    want_out: str
    fail: tuple = ()
    malformed: tuple = ()
    want_rc: int = 0
    want_error: str = ""
    responses: dict = field(default_factory=dict)


def review(time=MIDDLE, association="MEMBER", user_type="User", state="APPROVED", commit=CURRENT_HEAD):
    return {"submitted_at": time, "author_association": association,
            "user": {"type": user_type}, "state": state, "commit_id": commit}


def comment(time=LATE, association="CONTRIBUTOR", user_type="User"):
    return {"created_at": time, "author_association": association, "user": {"type": user_type}}


def label_event(time=EARLY, event="labeled", label=MAINTAINER):
    return {"created_at": time, "event": event, "label": {"name": label}}


def listing_entry(number=NUMBER, labels=("bug", MAINTAINER), pr=True, user_type="User"):
    entry = {"number": int(number), "labels": [{"name": label} for label in labels],
             "user": {"type": user_type}}
    if pr:
        entry["pull_request"] = {"url": "https://example.invalid/pull"}
    return entry


def sweep_case(name, reviews=None, comments=None, review_comments=None, labels=("bug", MAINTAINER),
               fresh_labels=None, head=CURRENT_HEAD, events=None,
               edits=(("add", AUTHOR), ("remove", MAINTAINER)),
               want_labels=("bug", AUTHOR), reason="", read_count=7):
    return SweepCase(
        name=name,
        issues={NUMBER: {"labels": list(labels if fresh_labels is None else fresh_labels), "pr": True}},
        pages={LISTING: [[listing_entry(labels=labels)]],
               REVIEWS: [[review()]] if reviews is None else reviews,
               COMMENTS: [[]] if comments is None else comments,
               REVIEW_COMMENTS: [[]] if review_comments is None else review_comments,
               EVENTS: [[label_event()]] if events is None else events},
        responses={PULL: {"head": {"sha": head}}},
        want_calls=SWEEP_READS[:read_count] + [edit_call(*edit) for edit in edits],
        want_labels={NUMBER: list(want_labels)},
        want_out=(f"no change on #{NUMBER}: {reason}\n" if reason else
                  "".join(f"{op} {label} on #{NUMBER}\n" for op, label in edits))
        + f"sweep: 1 pull requests checked, {1 if edits else 0} flipped\n",
    )


SWEEP_CASES = [
    sweep_case("sweep review on the current head"),
    sweep_case("sweep review older than the label", events=[[label_event(LATE)]],
               edits=(), want_labels=("bug", MAINTAINER), reason="label after the review", read_count=6),
    sweep_case("sweep review equals the label", events=[[label_event(MIDDLE)]],
               edits=(), want_labels=("bug", MAINTAINER), reason="label after the review", read_count=6),
    sweep_case("sweep no label event", events=[[]], edits=(), want_labels=("bug", MAINTAINER),
               reason="no label event", read_count=6),
    sweep_case("sweep ignores unrelated label events", events=[[
        label_event(), label_event(LATE, event="unlabeled"), label_event(LATE, label=AUTHOR)]]),
    sweep_case("sweep latest label event across pages", events=[[label_event()], [label_event(LATE)]],
               edits=(), want_labels=("bug", MAINTAINER), reason="label after the review", read_count=6),
    sweep_case("sweep reopen after the review", events=[[
        label_event(), {"event": "reopened", "created_at": LATE}, label_event(LATE)]],
               edits=(), want_labels=("bug", MAINTAINER), reason="label after the review", read_count=6),
    sweep_case("sweep contributor review after the review",
               reviews=[[review()], [review(LATE, association="CONTRIBUTOR", state="COMMENTED")]],
               edits=(), want_labels=("bug", MAINTAINER), reason="comment after the review", read_count=5),
    sweep_case("sweep push after the review", reviews=[[review(commit=PREVIOUS_HEAD)]],
               edits=(), want_labels=("bug", MAINTAINER), reason="push after the review", read_count=3),
    sweep_case("sweep comment after the review", comments=[[], [comment()]],
               edits=(), want_labels=("bug", MAINTAINER), reason="comment after the review", read_count=5),
    sweep_case("sweep review comment after the review", review_comments=[[], [comment()]],
               edits=(), want_labels=("bug", MAINTAINER), reason="comment after the review", read_count=5),
    sweep_case("sweep maintainer comment after the review",
               comments=[[comment(association=a) for a in ("OWNER", "MEMBER", "COLLABORATOR")]],
               review_comments=[[comment(association=a) for a in ("OWNER", "MEMBER", "COLLABORATOR")]]),
    sweep_case("sweep bot comment after the review", comments=[[comment(user_type="Bot")]],
               review_comments=[[comment(user_type="Bot")]]),
    sweep_case("sweep earlier and simultaneous comments", comments=[[comment(EARLY), comment(MIDDLE)]],
               review_comments=[[comment(EARLY), comment(MIDDLE)]]),
    sweep_case("sweep label gone before the write", fresh_labels=("bug", AUTHOR), edits=(),
               reason="labels already match"),
    sweep_case("sweep author label already present", labels=("bug", MAINTAINER, AUTHOR),
               edits=(("remove", MAINTAINER),)),
    sweep_case("sweep latest review across pages",
               reviews=[[review(EARLY, commit=PREVIOUS_HEAD)], [review(LATE)]],
               comments=[[comment(MIDDLE)]]),
]
for name, reviews in (
    ("bot review", [[review(user_type="Bot")]]),
    ("non-maintainer review", [[review(association="CONTRIBUTOR")]]),
    ("no review", [[]]),
    ("pending review", [[review(state="PENDING")]]),
    ("dismissed review", [[review(state="DISMISSED")]]),
):
    SWEEP_CASES.append(sweep_case(f"sweep {name}", reviews=reviews, edits=(),
                                 want_labels=("bug", MAINTAINER),
                                 reason="no maintainer review", read_count=2))
for association, state in (("OWNER", "CHANGES_REQUESTED"), ("COLLABORATOR", "COMMENTED")):
    SWEEP_CASES.append(sweep_case(f"sweep {association} {state}",
                                 reviews=[[review(association=association, state=state)]]))

SWEEP_CASES.append(SweepCase(
    "sweep two pull requests with one flip",
    issues={NUMBER: {"labels": ["bug", MAINTAINER], "pr": True},
            "34": {"labels": [MAINTAINER], "pr": True}},
    pages={LISTING: [[listing_entry()], [listing_entry("34", labels=(MAINTAINER,))]],
           REVIEWS: [[review(commit=PREVIOUS_HEAD)]],
           f"repos/{REPO}/pulls/34/reviews": [[review()]],
           f"repos/{REPO}/issues/34/comments": [[]],
           f"repos/{REPO}/pulls/34/comments": [[]],
           f"repos/{REPO}/issues/34/events": [[label_event()]]},
    responses={PULL: {"head": {"sha": CURRENT_HEAD}},
               f"repos/{REPO}/pulls/34": {"head": {"sha": CURRENT_HEAD}}},
    want_calls=SWEEP_READS[:3] + [["api", f"repos/{REPO}/pulls/34/reviews", "--paginate"],
                                 ["api", f"repos/{REPO}/pulls/34"],
                                 ["api", f"repos/{REPO}/issues/34/comments", "--paginate"],
                                 ["api", f"repos/{REPO}/pulls/34/comments", "--paginate"],
                                 ["api", f"repos/{REPO}/issues/34/events", "--paginate"],
                                 ["api", f"repos/{REPO}/issues/34"],
                                 edit_call("add", AUTHOR, "34"), edit_call("remove", MAINTAINER, "34")],
    want_labels={NUMBER: ["bug", MAINTAINER], "34": [AUTHOR]},
    want_out=f"no change on #{NUMBER}: push after the review\n"
             f"add {AUTHOR} on #34\nremove {MAINTAINER} on #34\n"
             "sweep: 2 pull requests checked, 1 flipped\n",
))
for name, listing in (
    ("empty listing", [[]]),
    ("skips issues and bot pull requests", [[listing_entry(pr=False), listing_entry("99", user_type="Bot")]]),
):
    SWEEP_CASES.append(SweepCase(
        f"sweep {name}",
        issues={NUMBER: {"labels": ["bug", MAINTAINER], "pr": False},
                "99": {"labels": ["bug", MAINTAINER], "pr": True}},
        pages={LISTING: listing}, want_calls=[LIST],
        want_labels={NUMBER: ["bug", MAINTAINER], "99": ["bug", MAINTAINER]},
        want_out="sweep: 0 pull requests checked, 0 flipped\n",
    ))

for name, endpoint, calls, error, labels, output in (
    ("listing", f"GET {LISTING}", SWEEP_READS[:1], "Cannot read pull requests.",
     ("bug", MAINTAINER), ""),
    ("reviews", f"GET {REVIEWS}", SWEEP_READS[:2], "Cannot read reviews.", ("bug", MAINTAINER), ""),
    ("pull request", f"GET {PULL}", SWEEP_READS[:3], "Cannot read pull request.", ("bug", MAINTAINER), ""),
    ("comments", f"GET {COMMENTS}", SWEEP_READS[:4], "Cannot read comments.", ("bug", MAINTAINER), ""),
    ("review comments", f"GET {REVIEW_COMMENTS}", SWEEP_READS[:5],
     "Cannot read review comments.", ("bug", MAINTAINER), ""),
    ("events", f"GET {EVENTS}", SWEEP_READS[:6], "Cannot read label events.", ("bug", MAINTAINER), ""),
    ("label re-read", f"GET {ENDPOINT}", SWEEP_READS, "Cannot read labels.", ("bug", MAINTAINER), ""),
    ("addition", f"POST {ENDPOINT}/labels", SWEEP_READS + [edit_call("add", AUTHOR)],
     "Cannot add label.", ("bug", MAINTAINER), ""),
    ("removal", f"DELETE {ENDPOINT}/labels/waiting%20on%20maintainer",
     SWEEP_READS + [edit_call("add", AUTHOR), edit_call("remove", MAINTAINER)],
     "Cannot remove label.", ("bug", MAINTAINER, AUTHOR), f"add {AUTHOR} on #{NUMBER}\n"),
):
    SWEEP_CASES.append(replace(sweep_case(f"sweep {name} API failure"), fail=(endpoint,),
                               want_rc=1, want_calls=calls, want_labels={NUMBER: list(labels)},
                               want_out=output, want_error=f"::error::{error}"))
for name, endpoint, calls, error in (
    ("sweep malformed listing", LISTING, SWEEP_READS[:1], "Cannot parse pull requests."),
    ("sweep malformed reviews", REVIEWS, SWEEP_READS[:2], "Cannot parse reviews."),
    ("sweep malformed pull request", PULL, SWEEP_READS[:3], "Cannot parse pull request."),
    ("sweep malformed comments", COMMENTS, SWEEP_READS[:5], "Cannot parse comments."),
    ("sweep malformed review comments", REVIEW_COMMENTS, SWEEP_READS[:5], "Cannot parse comments."),
    ("sweep malformed events", EVENTS, SWEEP_READS[:6], "Cannot parse label events."),
    ("sweep malformed labels on the re-read", ENDPOINT, SWEEP_READS, "Cannot parse labels."),
):
    SWEEP_CASES.append(replace(sweep_case(name), malformed=(f"GET {endpoint}",),
                               want_rc=1, want_calls=calls, want_labels={NUMBER: ["bug", MAINTAINER]},
                               want_out="", want_error=f"::error::{error}"))


def check_structure(workflow_path):
    doc = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    # PyYAML reads the bare key on as the boolean True.
    trigger = doc.get(True, doc.get("on"))
    job = doc["jobs"]["triage"]
    step = job["steps"][0]
    sweep = doc["jobs"]["review-sweep"]
    expected = {
        "triggers": trigger == {
            "issues": {"types": ["opened", "reopened", "closed"]},
            "issue_comment": {"types": ["created"]},
            "pull_request_target": {"types": ["opened", "reopened", "synchronize", "closed"]},
            "schedule": [{"cron": "*/15 * * * *"}],
            "workflow_dispatch": None,
        },
        "workflow permissions": doc.get("permissions") == {},
        "two jobs": list(doc["jobs"]) == ["triage", "review-sweep"],
        "bot condition": " ".join(str(job.get("if", "")).split()) == BOT_CONDITION,
        "sweep condition": sweep.get("if") == SWEEP_CONDITION,
        "concurrency": job.get("concurrency") == {
            "group": "triage-${{ github.event.issue.number || github.event.pull_request.number }}",
            "cancel-in-progress": False,
        },
        "sweep concurrency": sweep.get("concurrency") == {
            "group": "triage-review-sweep", "cancel-in-progress": False,
        },
        "environment": step.get("env") == {
            "GH_TOKEN": "${{ github.token }}",
            "GH_REPO": "${{ github.repository }}",
            "NUMBER": "${{ github.event.issue.number || github.event.pull_request.number }}",
            "EVENT": "${{ format('{0}:{1}', github.event_name, github.event.action) }}",
            "ASSOCIATION": "${{ github.event.comment.author_association "
            "|| github.event.pull_request.author_association || github.event.issue.author_association }}",
            "COMMENT_BODY": "${{ github.event.comment.body }}",
        },
        "sweep environment": sweep["steps"][0].get("env") == {
            "GH_TOKEN": "${{ github.token }}", "GH_REPO": "${{ github.repository }}",
        },
    }
    scripts = {}
    for name, current in doc["jobs"].items():
        steps = current["steps"]
        script = steps[0]["run"]
        scripts[name] = script
        for check, ok in {
            "permissions": current.get("permissions") == {"issues": "write", "pull-requests": "write"},
            "one step": len(steps) == 1,
            "no action or checkout": "uses" not in current and all("uses" not in s for s in steps)
            and "checkout" not in script,
            "runner": current.get("runs-on") == "ubuntu-24.04",
            "timeout": current.get("timeout-minutes") == 5,
            "shell": steps[0].get("shell") == "bash",
            "strict shell": script.startswith("set -euo pipefail\n"),
            "no expression in run": "${{" not in script,
        }.items():
            expected[f"{name} {check}"] = ok
    return scripts, [name for name, ok in expected.items() if not ok]


def run_case(case, scripts, bindir):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        state_path = tmp / "state.json"
        env = {
            "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}",
            "TRIAGE_STATE": str(state_path), "GH_TOKEN": "test-token", "GH_REPO": REPO,
            "LC_ALL": "C",
        }
        if isinstance(case, SweepCase):
            script = scripts["review-sweep"]
            issues, pages = case.issues, case.pages
            responses = case.responses
            want_labels = case.want_labels
        else:
            script = scripts["triage"]
            issues = {NUMBER: {"labels": list(case.labels), "pr": case.pr, "state": case.state},
                      "99": {"labels": ["untouched"], "pr": False}}
            pages = {}
            responses = {}
            want_labels = {NUMBER: case.want_labels, "99": ["untouched"]}
            env.update(NUMBER=case.number, EVENT=case.event, ASSOCIATION=case.association,
                       COMMENT_BODY=case.body)
        state = {"issues": issues, "pages": pages, "responses": responses, "calls": [],
                 "fail": case.fail, "malformed": case.malformed}
        state_path.write_text(json.dumps(state), encoding="utf-8")
        result = subprocess.run(["bash", "-c", script], env=env, cwd=tmp, capture_output=True,
                                text=True, stdin=subprocess.DEVNULL, timeout=30)
        final = json.loads(state_path.read_text(encoding="utf-8"))
        problems = []
        for name, got, want in (
            ("exit", result.returncode, case.want_rc),
            ("calls", final["calls"], case.want_calls),
            ("labels", {n: sorted(issue["labels"]) for n, issue in final["issues"].items()},
             {n: sorted(labels) for n, labels in want_labels.items()}),
            ("issue metadata", {n: {k: v for k, v in issue.items() if k != "labels"}
                                for n, issue in final["issues"].items()},
             {n: {k: v for k, v in issue.items() if k != "labels"} for n, issue in issues.items()}),
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
    scripts, problems = check_structure(root / WORKFLOW)
    failures = []
    if problems:
        failures.append(STRUCTURE)
        print(f"FAIL  {STRUCTURE}: {', '.join(problems)}")
    else:
        print(f"ok    {STRUCTURE}")
    cases = CASES + SWEEP_CASES
    if selected is not None:
        behavior = [name for name in selected if name != STRUCTURE]
        cases = [case for case in cases if case.name in behavior]
        if len(cases) != len(behavior):
            raise AssertionError("mutation names an unknown case")
    with tempfile.TemporaryDirectory() as bindir:
        stub = pathlib.Path(bindir) / "gh"
        stub.write_text(STUB.replace("#!PYTHON", f"#!{sys.executable}", 1), encoding="utf-8")
        stub.chmod(0o755)
        for case in cases:
            problems = run_case(case, scripts, bindir)
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
         "            :\n", 2, ["OWNER comment on pull request", "MEMBER comment on pull request"]),
        ("rule 5", "            remove='waiting on maintainer'\n          else\n",
         "            :\n          else\n", 1, ["OWNER comment on issue"]),
        ("rule 6 fallback", "            echo \"no change on #$NUMBER: no matching rule\"\n            exit 0\n",
         "            add='waiting on maintainer'\n", 1,
         ["no rule for pull_request_target:edited pr=True NONE"]),
        ("rule 6 add idempotence", " && ! jq -e --arg label \"$add\" 'index($label) != null' <<<\"$labels\" >/dev/null",
         "", 1, ["issue already waits on maintainer", "maintainer comment: labels already match"]),
        ("rule 6 remove idempotence", " && jq -e --arg label \"$remove\" 'index($label) != null' <<<\"$labels\" >/dev/null",
         "", 1, ["external pull request: labels already match", "maintainer issue comment with absent label"]),
        ("claim skip", "            echo \"no change on #$NUMBER: claim comment\"\n            exit 0\n",
         "            :\n", 1, ["claim comment NONE pr=False", "claim comment MEMBER pr=True"]),
        ("bot filter", "      github.event_name != 'schedule' && github.event_name != 'workflow_dispatch' &&\n"
         "      ((github.event.comment.user.type || github.event.pull_request.user.type\n"
         "      || github.event.issue.user.type) != 'Bot')",
         "      'true'", 1, [STRUCTURE]),
        ("concurrency", "    concurrency:\n"
         "      group: triage-${{ github.event.issue.number || github.event.pull_request.number }}\n"
         "      cancel-in-progress: false\n", "", 1, [STRUCTURE]),
        ("closed rule", "          # Closing ends the wait on both sides, whoever closes the item.\n"
         '          if [[ "$EVENT" == issues:closed || "$EVENT" == pull_request_target:closed ]]; then\n',
         "          if false; then\n", 1,
         ["closed pull request: both waiting labels", "closed pull request: author label only",
          "closed issue: maintainer label"]),
        ("closed state check", "            if [[ $(jq -r '.state' <<<\"$issue\") != closed ]]; then\n"
         "              echo \"no change on #$NUMBER: reopened\"\n              exit 0\n            fi\n",
         "", 1, ["reopened before the run: pull_request_target:closed",
                 "reopened before the run: issues:closed"]),
        ("closed triggers", "    types: [opened, reopened, closed]\n", "    types: [opened, reopened]\n", 1,
         [STRUCTURE]),
        ("dispatch trigger", "  workflow_dispatch:\n", "", 1, [STRUCTURE]),
        ("dispatch exclusion", " && github.event_name != 'workflow_dispatch' &&\n", " &&\n", 1,
         [STRUCTURE]),
        ("sweep dispatch", f"    if: {SWEEP_CONDITION}\n", "    if: github.event_name == 'schedule'\n", 1,
         [STRUCTURE]),
        ("closed guard", '          if [[ $(jq -r \'.state\' <<<"$issue") == closed ]]; then\n'
         '            echo "no change on #$NUMBER: closed"\n            exit 0\n          fi\n',
         "", 1, ["closed pull request: maintainer comment"]),
        ("sweep head comparison", '            if [[ "$review_commit" != "$head" ]]; then\n',
         "            if false; then\n", 1, ["sweep push after the review"]),
        ("sweep comment filter", '            if [[ "$commented" == true ]]; then\n',
         "            if false; then\n", 1, ["sweep comment after the review"]),
        ("sweep time comparison", '            if ! [[ "$review_time" > "$label_time" ]]; then\n',
         "            if false; then\n", 1, ["sweep review older than the label"]),
        ("sweep contributor review input", r'''<<<"$comments"$'\n'"$review_comments"$'\n'"$reviews"''',
         r'''<<<"$comments"$'\n'"$review_comments"''', 1, ["sweep contributor review after the review"]),
        ("sweep association filter",
         '              | select(.author_association == "OWNER" or .author_association == "MEMBER" or .author_association == "COLLABORATOR")\n',
         "", 1, ["sweep non-maintainer review"]),
        ("sweep bot filter", '              | select(.user.type != "Bot")\n',
         "", 1, ["sweep bot review"]),
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
