#!/usr/bin/env python3
"""Offline checks of check-run-evidence.py against a fixture API.

Usage: test-check-run-evidence.py [--case LABEL] [--mutations]

Each case builds a world of workflow runs and jobs, serves it from an HTTP
server bound to 127.0.0.1, and runs the check against that server with
--poll-seconds 0. The server answers only the requests the check is meant to
make, with the exact query and token; any other request gets HTTP 400, 401
or 404. An accepting case requires exit 0 and exactly the accepted run lines;
a refusing case requires exit 1 and a failure line that starts with the
named workflow. --case runs one case. --mutations then applies each edit of
MUTATIONS to a scratch copy of the check under TMPDIR, requires every case
it names to fail, and requires the restored copy to pass them. No request
leaves 127.0.0.1: the check gets only the fixture URL, and the proxy
variables are removed from its environment.
"""

import argparse
import hashlib
import http.server
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import threading
import urllib.parse

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / "check-run-evidence.py"
REPO = "owner/wallet"
SHA = "4a86e0ce" + "1" * 32
OTHER_SHA = "4a86e0ce" + "2" * 32
TAG = "v1.2.3"
TOKEN = "fixture-token"
WORKFLOWS = ("ci.yml", "coverage.yml", "install-surface.yml", "vendored-wasm.yml", "changelog.yml")
STATE = {}


def ci_jobs(branch, conclusion="success"):
    return [{"name": "changes", "conclusion": "success"},
            {"name": f"ci-result ({branch})", "conclusion": conclusion}]


class World:
    def __init__(self):
        self.runs, self.jobs, self.errors, self.hooks, self.expect = [], {}, {}, [], {}
        self.next_id = 1000
        self.args = {}
        self.env = {"GH_TOKEN": TOKEN}
        for workflow in WORKFLOWS:
            self.add(workflow)

    def add(self, workflow, event="push", first=False, **fields):
        self.next_id += 1
        run = {"id": self.next_id, "name": workflow, "path": f".github/workflows/{workflow}", "event": event,
               "head_branch": "main", "head_sha": SHA, "run_attempt": 1, "status": "completed",
               "conclusion": "success", "repository": {"full_name": REPO}, "_file": workflow, "_event": event}
        run.update(fields)
        self.runs.insert(0, run) if first else self.runs.append(run)
        if workflow == "ci.yml":
            self.jobs[(run["id"], 1)] = ci_jobs(run["head_branch"])
        return run

    def push(self, workflow):
        return next(run for run in self.runs if run["_file"] == workflow and run["_event"] == "push")

    def remove(self, workflow):
        self.runs.remove(self.push(workflow))


def public(run):
    return {key: value for key, value in run.items() if not key.startswith("_")}


def page_of(key, items, page):
    return {"total_count": len(items), key: items[(page - 1) * 100:page * 100]}


def answer(world, target, authorization):
    parsed = urllib.parse.urlsplit(target)
    path, query = parsed.path, dict(urllib.parse.parse_qsl(parsed.query))
    for hook in list(world.hooks):
        hook(world, path)
    if authorization != f"Bearer {TOKEN}":
        return 401, {"message": "Bad credentials"}
    relative = path.removeprefix(f"/repos/{REPO}")
    if relative in world.errors:
        return world.errors[relative]
    page = query.get("page", "")
    if match := re.fullmatch(r"/actions/workflows/([\w.-]+)/runs", relative):
        event = query.get("event")
        expected = {"event": event, "head_sha": SHA, "per_page": "100", "page": page}
        if event == "push":
            expected["branch"] = TAG if match[1] == "release.yml" else "main"
        if event not in ("push", "workflow_dispatch") or query != expected or not page.isdigit():
            return 400, {"message": f"unexpected query {query}"}
        runs = [public(run) for run in world.runs if run["_file"] == match[1] and run["_event"] == event]
        return 200, page_of("workflow_runs", runs, int(page))
    if (match := re.fullmatch(r"/actions/runs/([0-9]+)", relative)) and "?" not in target:
        for run in world.runs:
            if run["id"] == int(match[1]):
                return 200, public(run)
    if match := re.fullmatch(r"/actions/runs/([0-9]+)/jobs", relative):
        run = next((run for run in world.runs if run["id"] == int(match[1])), {})
        jobs = world.jobs.get((int(match[1]), run.get("run_attempt")))
        if jobs is not None and query == {"filter": "latest", "per_page": "100", "page": page}:
            return 200, page_of("jobs", [{"status": "completed", "run_id": int(match[1]),
                                         "run_attempt": run.get("run_attempt"), **job} for job in jobs], int(page))
    if match := re.fullmatch(r"/actions/runs/([0-9]+)/attempts/([0-9]+)/jobs", relative):
        jobs = world.jobs.get((int(match[1]), int(match[2])))
        if jobs is not None and query == {"per_page": "100", "page": page} and page.isdigit():
            # A job is completed and belongs to the requested run and attempt unless the fixture says otherwise.
            jobs = [{"status": "completed", "run_id": int(match[1]), "run_attempt": int(match[2]), **job}
                    for job in jobs]
            return 200, page_of("jobs", jobs, int(page))
    return 404, {"message": "Not Found"}


class Truncated(bytes):
    """A body the server announces as 10 bytes longer than it sends."""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # The request line keeps the target as sent; self.path folds a leading //.
        target = self.requestline.split(" ")[1]
        status, body = answer(STATE["world"], target, self.headers.get("Authorization"))
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data) + (10 if isinstance(body, Truncated) else 0)))
        if isinstance(body, Truncated):
            self.close_connection = True
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def on_request(suffix, *changes):
    """A hook that applies changes[n] at the n-th request whose path ends
    with suffix, before the server answers it."""
    seen = [0]

    def hook(world, path):
        if path.endswith(suffix):
            if seen[0] < len(changes):
                changes[seen[0]](world)
            seen[0] += 1
    return hook


def update(workflow, **fields):
    return lambda world: world.push(workflow).update(fields)


def run_path(world, workflow):
    return f"/actions/runs/{world.push(workflow)['id']}"


def steps(*setups):
    def setup(world):
        for item in setups:
            item(world)
    return setup


def filler_runs(world):
    world.expect["coverage.yml"] = (world.push("coverage.yml")["id"], 1, "push")
    for _ in range(100):
        world.add("coverage.yml", first=True, head_sha=OTHER_SHA)


def filler_jobs(world):
    run = world.push("ci.yml")
    world.jobs[(run["id"], 1)] = [{"name": f"job {n}", "conclusion": "success"} for n in range(100)] + \
        ci_jobs("main")


def ignored_runs(world):
    world.remove("install-surface.yml")
    world.add("install-surface.yml", event="pull_request", _event="push", head_branch="feature")
    world.add("install-surface.yml", head_branch="next")
    world.add("install-surface.yml", head_sha=OTHER_SHA)


def ignored_beside(world):
    ignored_runs(world)
    good = world.add("install-surface.yml")
    world.expect["install-surface.yml"] = (good["id"], 1, "push")


def attempt_two(conclusion_one, conclusion_two, accept):
    def setup(world):
        run = world.push("ci.yml")
        run["run_attempt"] = 2
        world.jobs[(run["id"], 1)] = ci_jobs("main", conclusion_one)
        world.jobs[(run["id"], 2)] = ci_jobs("main", conclusion_two)
        if accept:
            world.expect["ci.yml"] = (run["id"], 2, "push")
    return setup


def dispatch(branch, path_ref, job_branch, push_conclusion="cancelled", accept=True, **fields):
    """Adds a dispatched ci.yml run; a push_conclusion of None removes the
    push run."""
    def setup(world):
        if push_conclusion is None:
            world.remove("ci.yml")
        else:
            world.push("ci.yml").update(conclusion=push_conclusion)
        path = ".github/workflows/ci.yml" + (f"@{path_ref}" if path_ref else "")
        run = world.add("ci.yml", event="workflow_dispatch", head_branch=branch, path=path, **fields)
        world.jobs[(run["id"], 1)] = ci_jobs(job_branch)
        if accept:
            world.expect["ci.yml"] = (run["id"], 1, "workflow_dispatch")
    return setup


def rerun_jobs(conclusion, job_conclusion="success", accept=False):
    """A re-run of the ci.yml push run starts during the attempt 1 job
    lookup and has completed when the first refetch reads it."""
    def setup(world):
        run = world.push("ci.yml")
        world.jobs[(run["id"], 2)] = ci_jobs("main", job_conclusion)
        world.hooks.append(on_request(f"/actions/runs/{run['id']}/attempts/1/jobs",
                                      update("ci.yml", run_attempt=2, status="in_progress", conclusion=None)))
        world.hooks.append(on_request(f"/actions/runs/{run['id']}",
                                      update("ci.yml", status="completed", conclusion=conclusion)))
        if accept:
            world.expect["ci.yml"] = (run["id"], 2, "push")
    return setup


def rerun_refetch(conclusion, accept=False):
    """A re-run of the coverage.yml push run starts before its refetch."""
    def setup(world):
        run = world.push("coverage.yml")
        world.hooks.append(on_request(f"/actions/runs/{run['id']}",
                                      update("coverage.yml", run_attempt=2, status="queued", conclusion=None),
                                      update("coverage.yml", status="in_progress"),
                                      update("coverage.yml", status="completed", conclusion=conclusion)))
        if accept:
            world.expect["coverage.yml"] = (run["id"], 2, "push")
    return setup


def refetch_as(workflow, **fields):
    def setup(world):
        run = world.push(workflow)
        world.hooks.append(on_request(f"/actions/runs/{run['id']}", update(workflow, **fields)))
    return setup


def error(relative, status, body):
    return lambda world: world.errors.update({relative(world): (status, body)})


def listing(workflow):
    return lambda world: f"/actions/workflows/{workflow}/runs"


def closed_port(world, scheme="http"):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    world.args["--api-url"] = f"{scheme}://127.0.0.1:{port}"


def arg(name, value):
    return lambda world: world.args.update({name: value})


def no_run(workflow):
    tail = "no dispatched run succeeded either" if workflow == "ci.yml" else "only ci.yml accepts a dispatched run"
    return f"{workflow}: no successful push run on main of {SHA} (no matching run); {tail}"


def push_refused(workflow, reason):
    return lambda world: (f"{workflow}: no successful push run on main of {SHA} "
                          f"(push run {world.push(workflow)['id']} {reason}")


def dispatch_refused(reason):
    """The ci.yml failure after a cancelled push run and the last listed
    dispatched run."""
    return lambda world: (f"ci.yml: no successful push run on main of {SHA} (push run "
                          f"{world.push('ci.yml')['id']} attempt 1: completed, cancelled; workflow_dispatch run "
                          f"{world.runs[-1]['id']} attempt 1: {reason}); no dispatched run succeeded either")


def ci_result_job(**fields):
    """Sets fields on the ci-result job of the ci.yml push run's attempt 1."""
    def setup(world):
        job = dict(ci_jobs("main")[1], **fields)
        world.jobs[(world.push("ci.yml")["id"], 1)] = [ci_jobs("main")[0], job]
    return setup


def ci_refused(reason):
    return lambda world: (f"ci.yml: no successful push run on main of {SHA} (push run "
                          f"{world.push('ci.yml')['id']} attempt 1: {reason}); no dispatched run succeeded either")


def dispatch_moved(world):
    """A dispatch on main whose refetch reports the tag as its branch."""
    dispatch("main", None, "main", accept=False)(world)
    run = world.runs[-1]
    world.hooks.append(on_request(f"/actions/runs/{run['id']}", lambda w: run.update(head_branch=TAG)))


def run_message(workflow, message):
    return lambda world: f"{workflow}: run {world.push(workflow)['id']} {message}"


NOOP = steps()
# label, setup, expected: None accepts, else the failure text after "FAIL: ",
# or a function of the world that returns it.
CASES = [
    ("all five accepted", NOOP, None),
    ("bare and ref-qualified paths accepted",
     steps(update("ci.yml", path=".github/workflows/ci.yml@refs/heads/main"),
           update("vendored-wasm.yml", path=".github/workflows/vendored-wasm.yml@refs/heads/main")), None),
    ("runs pagination", filler_runs, None),
    ("jobs pagination", filler_jobs, None),
    ("pending run completes within the limit",
     steps(update("coverage.yml", status="in_progress", conclusion=None),
           lambda world: world.hooks.append(on_request(
               "/actions/workflows/coverage.yml/runs", lambda w: None,
               update("coverage.yml", status="completed", conclusion="success")))), None),
    ("queued run completes within the limit",
     steps(update("changelog.yml", status="queued", conclusion=None),
           lambda world: world.hooks.append(on_request(
               "/actions/workflows/changelog.yml/runs", lambda w: None,
               update("changelog.yml", status="completed", conclusion="success")))), None),
    ("ignored runs beside the accepted run", ignored_beside, None),
    ("attempt 2 accepted on its own jobs", attempt_two("failure", "success", True), None),
    ("dispatch fallback on main", dispatch("main", "refs/heads/main", "main"), None),
    ("dispatch fallback on main with a bare path", dispatch("main", None, "main", "failure"), None),
    ("dispatch fallback on the tag", dispatch(TAG, f"refs/tags/{TAG}", TAG), None),
    ("dispatch fallback without a push run", dispatch(TAG, None, TAG, None), None),
    ("re-run during the job lookup accepted on attempt 2", rerun_jobs("success", accept=True), None),
    ("re-run before the refetch accepted", rerun_refetch("success", accept=True), None),

    ("wrong repository", update("coverage.yml", repository={"full_name": "fork/wallet"}), no_run("coverage.yml")),
    ("missing repository", update("coverage.yml", repository=None), no_run("coverage.yml")),
    ("wrong path", update("coverage.yml", path=".github/workflows/ci.yml"), no_run("coverage.yml")),
    ("wrong event", update("coverage.yml", event="pull_request"), no_run("coverage.yml")),
    ("wrong branch", update("coverage.yml", head_branch="next"), no_run("coverage.yml")),
    ("push run on the tag", update("coverage.yml", head_branch=TAG), no_run("coverage.yml")),
    ("repository as a string", update("coverage.yml", repository=REPO), no_run("coverage.yml")),
    ("wrong SHA", update("coverage.yml", head_sha=OTHER_SHA), no_run("coverage.yml")),
    ("pull request, next and wrong-SHA runs ignored", ignored_runs, no_run("install-surface.yml")),
    ("foreign path suffix", update("coverage.yml", path=".github/workflows/coverage.yml@refs/heads/next"),
     no_run("coverage.yml")),
    ("tag path suffix on a push run",
     update("coverage.yml", path=f".github/workflows/coverage.yml@refs/tags/{TAG}"), no_run("coverage.yml")),
    ("path with a file suffix", update("coverage.yml", path=".github/workflows/coverage.yml.orig"),
     no_run("coverage.yml")),
    ("full ref as head_branch", update("coverage.yml", head_branch="refs/heads/main"), no_run("coverage.yml")),
    ("absent run", lambda world: world.remove("changelog.yml"), no_run("changelog.yml")),
    ("failed run", update("vendored-wasm.yml", conclusion="failure"),
     push_refused("vendored-wasm.yml", "attempt 1: completed, failure); only ci.yml accepts a dispatched run")),
    ("cancelled run", update("vendored-wasm.yml", conclusion="cancelled"),
     push_refused("vendored-wasm.yml", "attempt 1: completed, cancelled")),
    ("skipped run", update("vendored-wasm.yml", conclusion="skipped"),
     push_refused("vendored-wasm.yml", "attempt 1: completed, skipped")),
    ("success without completion", update("vendored-wasm.yml", status="unknown"),
     push_refused("vendored-wasm.yml", "attempt 1: unknown, success")),
    *((f"{status} past the limit",
       steps(update("coverage.yml", status=status, conclusion=None), arg("--wait-minutes", "0")),
       lambda world, status=status: f"coverage.yml: push run {world.push('coverage.yml')['id']} attempt 1 "
                                    f"({status}) did not complete within 0 minutes")
      for status in ("requested", "waiting", "pending")),
    ("in_progress past the limit",
     steps(update("coverage.yml", status="in_progress", conclusion=None), arg("--wait-minutes", "0")),
     lambda world: f"coverage.yml: push run {world.push('coverage.yml')['id']} attempt 1 (in_progress) "
                   "did not complete within 0 minutes"),
    ("queued past the limit",
     steps(update("coverage.yml", status="queued", conclusion=None), arg("--wait-minutes", "0")),
     lambda world: f"coverage.yml: push run {world.push('coverage.yml')['id']} attempt 1 (queued) "
                   "did not complete within 0 minutes"),
    ("attempt zero", update("changelog.yml", run_attempt=0),
     push_refused("changelog.yml", "attempt 0: the run ID or attempt is not a positive integer")),
    ("attempt as a string", update("changelog.yml", run_attempt="1"),
     push_refused("changelog.yml", "attempt 1: the run ID or attempt is not a positive integer")),
    ("attempt as a boolean", update("changelog.yml", run_attempt=True),
     push_refused("changelog.yml", "attempt True: the run ID or attempt is not a positive integer")),
    ("run ID as a string",
     lambda world: world.push("changelog.yml").update(id=str(world.push("changelog.yml")["id"])),
     push_refused("changelog.yml", "attempt 1: the run ID or attempt is not a positive integer")),
    ("run ID zero", update("changelog.yml", id=0),
     "changelog.yml: no successful push run on main of " + SHA +
     " (push run 0 attempt 1: the run ID or attempt is not a positive integer)"),
    ("HTTP 404", error(listing("install-surface.yml"), 404, {"message": "Not Found"}),
     "install-surface.yml: GET /actions/workflows/install-surface.yml/runs: HTTP 404"),
    ("HTTP 500", error(lambda world: run_path(world, "coverage.yml"), 500, {"message": "Server Error"}),
     lambda world: f"coverage.yml: run {world.push('coverage.yml')['id']} attempt 1: "
                   f"GET {run_path(world, 'coverage.yml')}: HTTP 500"),
    ("malformed JSON", error(lambda world: run_path(world, "ci.yml") + "/attempts/1/jobs", 200, b"{"),
     lambda world: f"ci.yml: run {world.push('ci.yml')['id']} attempt 1: "
                   f"GET {run_path(world, 'ci.yml')}/attempts/1/jobs: malformed JSON"),
    ("jobs not a list", error(lambda world: run_path(world, "ci.yml") + "/attempts/1/jobs", 200, {"jobs": {}}),
     lambda world: f"ci.yml: run {world.push('ci.yml')['id']} attempt 1: "
                   f"GET {run_path(world, 'ci.yml')}/attempts/1/jobs: malformed response: jobs is not a list of objects"),
    ("schemeless API URL", lambda world: world.args.update({"--api-url": STATE["url"].removeprefix("http://")}),
     "arguments: --api-url '127.0.0.1:"),
    ("http API URL on another host",
     lambda world: world.args.update({"--api-url": STATE["url"].replace("127.0.0.1", "localhost")}),
     lambda world: f"arguments: --api-url {world.args['--api-url']!r} is neither https nor http on 127.0.0.1"),
    ("https API URL passes validation", lambda world: closed_port(world, "https"),
     "ci.yml: GET /actions/workflows/ci.yml/runs: <urlopen error"),
    ("https API URL without a host", arg("--api-url", "https:///api"),
     "arguments: --api-url 'https:///api' is neither https nor http on 127.0.0.1"),
    ("API URL with a malformed port", arg("--api-url", "http://127.0.0.1:port"),
     "arguments: --api-url 'http://127.0.0.1:port': Port could not be cast to integer value"),
    ("response not an object", error(listing("changelog.yml"), 200, []),
     "changelog.yml: GET /actions/workflows/changelog.yml/runs: malformed response: not an object"),
    ("runs not a list", error(listing("changelog.yml"), 200, {"workflow_runs": {}}),
     "changelog.yml: GET /actions/workflows/changelog.yml/runs: malformed response: "
     "workflow_runs is not a list of objects"),
    ("run not an object", error(listing("changelog.yml"), 200, {"workflow_runs": [1]}),
     "changelog.yml: GET /actions/workflows/changelog.yml/runs: malformed response: "
     "workflow_runs is not a list of objects"),
    ("network error", closed_port, "ci.yml: GET /actions/workflows/ci.yml/runs: <urlopen error"),
    ("truncated response", error(listing("install-surface.yml"), 200, Truncated(b'{"workflow_runs": []}')),
     "install-surface.yml: GET /actions/workflows/install-surface.yml/runs: IncompleteRead"),
    ("API URL with a trailing slash", lambda world: world.args.update({"--api-url": STATE["url"] + "/"}), None),
    ("latest attempt failed after a success",
     steps(update("coverage.yml", run_attempt=2, conclusion="failure")),
     push_refused("coverage.yml", "attempt 2: completed, failure")),
    ("ci latest attempt failed after a success",
     steps(attempt_two("success", "success", False), update("ci.yml", conclusion="failure")),
     lambda world: f"ci.yml: no successful push run on main of {SHA} (push run {world.push('ci.yml')['id']} attempt 2: "
     "completed, failure); no dispatched run succeeded either"),
    ("attempt 2 jobs failed after attempt 1 jobs succeeded", attempt_two("success", "failure", False),
     lambda world: f"ci.yml: no successful push run on main of {SHA} (push run {world.push('ci.yml')['id']} "
                   "attempt 2: job 'ci-result (main)' is completed, failure)"),
    ("re-run during the job lookup fails", rerun_jobs("failure"),
     run_message("ci.yml", "attempt 2: the latest attempt is completed, failure")),
    ("re-run during the job lookup without ci-result", rerun_jobs("success", "failure"),
     run_message("ci.yml", "attempt 2: job 'ci-result (main)' is completed, failure")),
    ("re-run before the refetch fails", rerun_refetch("failure"),
     run_message("coverage.yml", "attempt 2: the latest attempt is completed, failure")),
    ("re-run before the refetch cancelled", rerun_refetch("cancelled"),
     run_message("coverage.yml", "attempt 2: the latest attempt is completed, cancelled")),
    ("second re-run after an accepted re-run fails",
     lambda world: world.hooks.append(on_request(
         run_path(world, "coverage.yml"), update("coverage.yml", run_attempt=2),
         update("coverage.yml", run_attempt=3, conclusion="failure"))),
     run_message("coverage.yml", "attempt 3: the latest attempt is completed, failure")),
    ("re-run pending past the limit",
     steps(refetch_as("coverage.yml", run_attempt=2, status="in_progress", conclusion=None),
           arg("--wait-minutes", "0")),
     run_message("coverage.yml", "attempt 2 (in_progress) did not complete within 0 minutes")),
    ("refetch with another SHA", refetch_as("coverage.yml", head_sha=OTHER_SHA),
     run_message("coverage.yml", "attempt 1: the refetched run no longer matches")),
    ("refetch with another ID",
     lambda world: world.errors.update({run_path(world, "coverage.yml"): (200, dict(
         public(world.push("coverage.yml")), id=1))}),
     run_message("coverage.yml", "attempt 1: the refetched run no longer matches")),
    ("refetch with a boolean ID",
     lambda world: world.push("coverage.yml").update(id=1) or world.errors.update(
         {"/actions/runs/1": (200, dict(public(world.push("coverage.yml")), id=True))}),
     run_message("coverage.yml", "attempt 1: the refetched run no longer matches")),
    ("refetch of a dispatch on another branch", dispatch_moved,
     lambda world: f"ci.yml: run {world.runs[-1]['id']} attempt 1: the refetched run no longer matches"),
    ("refetch without an attempt", refetch_as("coverage.yml", run_attempt=None),
     run_message("coverage.yml", "attempt 1: the refetched attempt is not a positive integer")),
    ("refetch with an earlier attempt",
     steps(update("coverage.yml", run_attempt=2), refetch_as("coverage.yml", run_attempt=1)),
     run_message("coverage.yml", "attempt 1: refetched as completed, success after attempt 2")),
    ("refetch with a changed conclusion", refetch_as("coverage.yml", conclusion="failure"),
     run_message("coverage.yml", "attempt 1: refetched as completed, failure after attempt 1")),
    ("refetch with a changed status", refetch_as("coverage.yml", status="in_progress"),
     run_message("coverage.yml", "attempt 1: refetched as in_progress, success after attempt 1")),
    ("missing ci-result job",
     lambda world: world.jobs.update({(world.push("ci.yml")["id"], 1): ci_jobs("next")}),
     lambda world: f"ci.yml: no successful push run on main of {SHA} (push run {world.push('ci.yml')['id']} "
                   "attempt 1: 0 jobs named 'ci-result (main)', expected one); no dispatched run succeeded either"),
    ("failed ci-result job",
     lambda world: world.jobs.update({(world.push("ci.yml")["id"], 1): ci_jobs("main", "failure")}),
     lambda world: f"ci.yml: no successful push run on main of {SHA} (push run {world.push('ci.yml')['id']} "
                   "attempt 1: job 'ci-result (main)' is completed, failure)"),
    ("ci-result job in progress", ci_result_job(status="in_progress", conclusion="success"),
     ci_refused("job 'ci-result (main)' is in_progress, success")),
    ("ci-result job of another run", ci_result_job(run_id=7),
     ci_refused("job 'ci-result (main)' belongs to run 7 attempt 1")),
    ("ci-result job with a boolean run ID",
     steps(update("ci.yml", id=1), ci_result_job(run_id=True)),
     ci_refused("job 'ci-result (main)' belongs to run True attempt 1")),
    ("ci-result job with a boolean attempt", ci_result_job(run_attempt=True),
     lambda world: ci_refused(f"job 'ci-result (main)' belongs to run {world.push('ci.yml')['id']} attempt True")(world)),
    ("ci-result job of another attempt", ci_result_job(run_attempt=2),
     lambda world: ci_refused(f"job 'ci-result (main)' belongs to run {world.push('ci.yml')['id']} attempt 2")(world)),
    ("two ci-result jobs",
     lambda world: world.jobs.update({(world.push("ci.yml")["id"], 1): ci_jobs("main") + ci_jobs("main")}),
     lambda world: f"ci.yml: no successful push run on main of {SHA} (push run {world.push('ci.yml')['id']} "
                   "attempt 1: 2 jobs named 'ci-result (main)', expected one)"),
    ("dispatch with the wrong ci-result name", dispatch(TAG, None, "main", accept=False),
     dispatch_refused(f"0 jobs named 'ci-result ({TAG})', expected one")),
    ("dispatch offered for another workflow",
     steps(update("coverage.yml", conclusion="cancelled"),
           lambda world: world.add("coverage.yml", event="workflow_dispatch")),
     push_refused("coverage.yml", "attempt 1: completed, cancelled); only ci.yml accepts a dispatched run")),
    ("dispatch on another branch", dispatch("next", None, "next", accept=False),
     "ci.yml: no successful push run on main of " + SHA + " (push run"),
    ("dispatch with the full tag ref", dispatch(f"refs/tags/{TAG}", None, f"refs/tags/{TAG}", accept=False),
     "ci.yml: no successful push run on main of " + SHA + " (push run"),
    ("dispatch on main with a tag path", dispatch("main", f"refs/tags/{TAG}", "main", accept=False),
     "ci.yml: no successful push run on main of " + SHA + " (push run"),
    ("dispatch on the tag with a main path", dispatch(TAG, "refs/heads/main", TAG, accept=False),
     "ci.yml: no successful push run on main of " + SHA + " (push run"),
    ("dispatch failed", dispatch("main", None, "main", accept=False, conclusion="failure"),
     dispatch_refused("completed, failure")),
    ("dispatch pending past the limit",
     steps(dispatch("main", None, "main", accept=False, status="in_progress", conclusion=None),
           arg("--wait-minutes", "0")),
     lambda world: f"ci.yml: workflow_dispatch run {world.runs[-1]['id']} attempt 1 (in_progress) "
                   "did not complete within 0 minutes"),
    ("push pending holds the dispatch",
     steps(dispatch("main", None, "main", accept=False), update("ci.yml", status="in_progress", conclusion=None),
           arg("--wait-minutes", "0")),
     lambda world: f"ci.yml: push run {world.push('ci.yml')['id']} attempt 1 (in_progress) "
                   "did not complete within 0 minutes"),
    ("short SHA", arg("--sha", SHA[:12]), f"arguments: --sha '{SHA[:12]}' does not match [0-9a-f]{{40}}"),
    ("tag without v", arg("--tag", "1.2.3"), "arguments: --tag '1.2.3' does not match"),
    ("repository without owner", arg("--repository", "wallet"), "arguments: --repository 'wallet' does not match"),
    ("negative wait", arg("--wait-minutes", "-1"),
     "arguments: --wait-minutes and --poll-seconds must not be negative"),
    ("negative poll", arg("--poll-seconds", "-1"),
     "arguments: --wait-minutes and --poll-seconds must not be negative"),
    ("empty token", lambda world: world.env.update(GH_TOKEN=""), "arguments: GH_TOKEN is empty"),
]

# name: (text of check-run-evidence.py, replacement, cases that must fail).
MUTATIONS = {
    "required-list": ('"vendored-wasm.yml", "changelog.yml")', '"vendored-wasm.yml")', ["absent run"]),
    "dispatch-workflow": ('DISPATCH_WORKFLOW = "ci.yml"', 'DISPATCH_WORKFLOW = "coverage.yml"',
                          ["dispatch fallback on main", "missing ci-result job"]),
    "branch": ('BRANCH = "main"', 'BRANCH = "next"', ["all five accepted"]),
    "waiting-requested": ('WAITING = ("requested", ', "WAITING = (", ["requested past the limit"]),
    "waiting-waiting": ('"requested", "waiting", "pending"', '"requested", "pending"', ["waiting past the limit"]),
    "waiting-pending": ('"waiting", "pending", "queued"', '"waiting", "queued"', ["pending past the limit"]),
    "waiting-queued": ('"pending", "queued", "in_progress")', '"pending", "in_progress")',
                       ["queued run completes within the limit", "queued past the limit"]),
    "waiting-in-progress": ('"queued", "in_progress")', '"queued",)',
                            ["pending run completes within the limit", "in_progress past the limit"]),
    "repository-pattern": ('REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")',
                           'REPOSITORY = re.compile(r".+")', ["repository without owner"]),
    "sha-pattern": ('SHA = re.compile(r"[0-9a-f]{40}")', 'SHA = re.compile(r"[0-9a-f]+")', ["short SHA"]),
    "tag-pattern": ('TAG = re.compile(r"v[0-9]', 'TAG = re.compile(r"v?[0-9]', ["tag without v"]),
    "positive-type": ("type(value) is int and value > 0", "isinstance(value, int) and value > 0",
                      ["attempt as a boolean"]),
    "positive-bound": ("type(value) is int and value > 0", "type(value) is int", ["attempt zero", "run ID zero"]),
    "http-error": ('raise Failure(f"{where}: HTTP {err.code}") from None', 'return {}', ["HTTP 404", "HTTP 500"]),
    "network-error": ("except (OSError, http.client.HTTPException) as err:", "except http.client.HTTPException as err:",
                      ["network error"]),
    "malformed-json": ('raise Failure(f"{where}: malformed JSON") from None', "return {}", ["malformed JSON"]),
    "get-context": ('where = f"{context}GET {path}"', 'where = f"GET {path}"', ["HTTP 500", "malformed JSON"]),
    "refetch-context": ('current = self.get(f"/actions/runs/{run[\'id\']}", context=f"{label(run, attempt)}: ")',
                        'current = self.get(f"/actions/runs/{run[\'id\']}")', ["HTTP 500"]),
    "jobs-context": ('"jobs",\n                          f"{label(run, attempt)}: ")', '"jobs")',
                     ["malformed JSON", "jobs not a list"]),
    "pages-context": ("dict(query, per_page=PER_PAGE, page=page), context)", "dict(query, per_page=PER_PAGE, page=page))",
                      ["malformed JSON"]),
    "pages-message": ('raise Failure(f"{context}GET {path}: malformed response: {key}',
                      'raise Failure(f"GET {path}: malformed response: {key}', ["jobs not a list"]),
    "url-split": ("        url.port  # Raises", "        pass  # Raises", ["API URL with a malformed port"]),
    "url-https-host": ('(url.scheme == "https" and url.hostname)', '(url.scheme == "https")',
                       ["https API URL without a host"]),
    "url-https": ('(url.scheme == "https" and url.hostname) or ', "", ["https API URL passes validation"]),
    "url-http-host": ('(url.scheme == "http" and url.hostname == "127.0.0.1")', '(url.scheme == "http")',
                      ["http API URL on another host"]),
    "url-check": ('    if not ((url.scheme == "https" and url.hostname) or (url.scheme == "http" and url.hostname == '
                  '"127.0.0.1")):\n', "    if False:\n", ["schemeless API URL", "http API URL on another host"]),
    "not-object": ("if not isinstance(document, dict):", "if False:", ["response not an object"]),
    "page-list": ("if not isinstance(batch, list) or not all(isinstance(item, dict) for item in batch):",
                  "if not isinstance(batch, list):", ["run not an object"]),
    "page-type": ("if not isinstance(batch, list) or not all(isinstance(item, dict) for item in batch):",
                  "if batch is None:", ["runs not a list"]),
    "pagination": ("            page += 1\n", "            return items\n", ["runs pagination", "jobs pagination"]),
    "page-stop": ("if len(batch) < PER_PAGE:", "if len(batch) <= PER_PAGE:", ["runs pagination", "jobs pagination"]),
    "push-branches": ('if branch not in ((BRANCH,) if event == "push" else (BRANCH, self.args.tag)):',
                      "if branch not in (BRANCH, self.args.tag):", ["push run on the tag"]),
    "dispatch-branches": ('if branch not in ((BRANCH,) if event == "push" else (BRANCH, self.args.tag)):',
                          'if branch not in (BRANCH,):', ["dispatch fallback on the tag"]),
    "branch-check": ('if branch not in ((BRANCH,) if event == "push" else (BRANCH, self.args.tag)):',
                     "if False:", ["wrong branch", "dispatch on another branch", "full ref as head_branch",
                                   "dispatch with the full tag ref"]),
    "ref-main": ('ref = f"refs/heads/{BRANCH}" if branch == BRANCH else f"refs/tags/{self.args.tag}"',
                 'ref = f"refs/tags/{self.args.tag}"', ["bare and ref-qualified paths accepted",
                                                        "tag path suffix on a push run"]),
    "ref-tag": ('ref = f"refs/heads/{BRANCH}" if branch == BRANCH else f"refs/tags/{self.args.tag}"',
                'ref = f"refs/heads/{BRANCH}"', ["dispatch fallback on the tag", "dispatch on the tag with a main path"]),
    "repository-type": ("isinstance(repository, dict) and repository.get", "repository is not None and repository.get",
                        ["repository as a string"]),
    "repository-name": ('repository.get("full_name") == self.args.repository', "True", ["wrong repository"]),
    "path-exact": ('run.get("path") in (path, f"{path}@{ref}")', 'run.get("path") == f"{path}@{ref}"',
                   ["all five accepted"]),
    "path-qualified": ('run.get("path") in (path, f"{path}@{ref}")', 'run.get("path") == path',
                       ["bare and ref-qualified paths accepted", "dispatch fallback on the tag"]),
    "path-prefix": ('run.get("path") in (path, f"{path}@{ref}")', 'str(run.get("path")).startswith(path)',
                    ["foreign path suffix", "path with a file suffix", "tag path suffix on a push run"]),
    "event": ('and run.get("event") == event', "", ["wrong event"]),
    "head-sha": ('and run.get("head_sha") == self.args.sha)', ")", ["wrong SHA"]),
    "job-name": ('name = f"ci-result ({run[\'head_branch\']})"', 'name = "ci-result (main)"',
                 ["dispatch fallback on the tag", "dispatch with the wrong ci-result name"]),
    "job-attempt": ('/attempts/{attempt}/jobs"', '/attempts/1/jobs"', ["attempt 2 accepted on its own jobs"]),
    "job-count": ("if len(named) != 1:", "if not named:", ["two ci-result jobs"]),
    "job-conclusion": ('job.get("status") != "completed" or job.get("conclusion") != "success":',
                       'job.get("status") != "completed":', ["failed ci-result job"]),
    "job-status": ('job.get("status") != "completed" or job.get("conclusion") != "success":',
                   'job.get("conclusion") != "success":', ["ci-result job in progress"]),
    "job-run": ('if positive(job.get("run_id")) != run["id"] or positive(job.get("run_attempt")) != attempt:',
                'if positive(job.get("run_attempt")) != attempt:', ["ci-result job of another run"]),
    "job-run-type": ('if positive(job.get("run_id")) != run["id"] or',
                     'if job.get("run_id") != run["id"] or', ["ci-result job with a boolean run ID"]),
    "job-run-attempt-type": ('or positive(job.get("run_attempt")) != attempt:', 'or job.get("run_attempt") != attempt:',
                             ["ci-result job with a boolean attempt"]),
    "job-run-attempt": ('if positive(job.get("run_id")) != run["id"] or positive(job.get("run_attempt")) != attempt:',
                        'if positive(job.get("run_id")) != run["id"]:', ["ci-result job of another attempt"]),
    "wait-deadline": ("if remaining <= 0:", "if False:", ["in_progress past the limit"]),
    "wait-minutes": ("self.deadline = time.monotonic() + args.wait_minutes * 60",
                     "self.deadline = time.monotonic()", ["pending run completes within the limit"]),
    "push-query-branch": ('            query["branch"] = BRANCH\n', "            pass\n", ["all five accepted"]),
    "push-query-event": ('query = {"event": event, "head_sha": self.args.sha}',
                         'query = {"event": "push", "head_sha": self.args.sha}', ["dispatch fallback on main"]),
    "identity-skip": ("            if not self.matches(run, workflow, event):\n                continue\n", "",
                      ["wrong repository", "pull request, next and wrong-SHA runs ignored"]),
    "attempt-check": ("if attempt is None or positive(run.get(\"id\")) is None:", "if False:",
                      ["attempt zero", "attempt as a string"]),
    "id-check": ("if attempt is None or positive(run.get(\"id\")) is None:", "if attempt is None:",
                 ["run ID as a string"]),
    "pending": ("            if status in WAITING:\n                waiting.append",
                "            if False:\n                waiting.append",
                ["pending run completes within the limit"]),
    "status": ('if status != "completed" or conclusion != "success":\n                refused',
               'if conclusion != "success":\n                refused', ["success without completion"]),
    "conclusion": ('if status != "completed" or conclusion != "success":\n                refused',
                   'if status != "completed":\n                refused',
                   ["failed run", "cancelled run", "skipped run", "latest attempt failed after a success"]),
    "ci-jobs": ("            if workflow == DISPATCH_WORKFLOW:\n                problem = self.ci_result(run, attempt)",
                "            if False:\n                problem = self.ci_result(run, attempt)",
                ["missing ci-result job", "dispatch with the wrong ci-result name"]),
    "ci-problem": ("                if problem:\n                    refused.append", "                if False:\n"
                   "                    refused.append", ["failed ci-result job"]),
    "accept-push": ('                return (*accepted, "push")', '                pass', ["all five accepted"]),
    "fallback-workflow": ("if not waiting and workflow == DISPATCH_WORKFLOW:", "if False:",
                          ["dispatch fallback on main"]),
    "fallback-waiting": ("if not waiting and workflow == DISPATCH_WORKFLOW:", "if workflow == DISPATCH_WORKFLOW:",
                         ["push pending holds the dispatch"]),
    "fallback-other": ("if not waiting and workflow == DISPATCH_WORKFLOW:", "if not waiting:",
                       ["dispatch offered for another workflow"]),
    "fallback-accept": ('                    return (*accepted, "workflow_dispatch")', "                    pass",
                        ["dispatch fallback on main"]),
    "fallback-reasons": ("                refused += more\n", "", ["dispatch failed"]),
    "fallback-wait": ("            if not waiting:\n                fallback", "            if True:\n                fallback",
                      ["pending run completes within the limit", "dispatch pending past the limit"]),
    "fallback-message": ('fallback = ("no dispatched run succeeded either" if workflow == DISPATCH_WORKFLOW',
                         'fallback = ("no dispatched run succeeded either" if False',
                         ["missing ci-result job"]),
    "found-message": ('found = "; ".join(refused) or "no matching run"', 'found = "no matching run"',
                      ["failed run"]),
    "refetch-id": ('if (positive(current.get("id")) != run["id"] or ', "if (", ["refetch with another ID"]),
    "refetch-id-type": ('if (positive(current.get("id")) != run["id"] or ', 'if (current.get("id") != run["id"] or ',
                        ["refetch with a boolean ID"]),
    "refetch-branch": ('or current.get("head_branch") != run["head_branch"]', "",
                       ["refetch of a dispatch on another branch"]),
    "refetch-identity": ("                    or not self.matches(current, workflow, event)):",
                         "                    or False):", ["refetch with another SHA"]),
    "refetch-attempt": ("            if latest is None:\n", "            if False:\n", ["refetch without an attempt"]),
    "refetch-earlier": ("if latest < attempt or (latest == attempt", "if (latest == attempt",
                        ["refetch with an earlier attempt"]),
    "refetch-same": ('or (latest == attempt and (status, conclusion) != ("completed", "success")):',
                     "or False:", ["refetch with a changed conclusion", "refetch with a changed status"]),
    "refetch-return": ("            if latest == attempt:\n                return attempt\n",
                       "            if latest == attempt:\n                return attempt + 1\n", ["all five accepted"]),
    "refetch-wait": ("            if status in WAITING:\n                self.wait", "            if False:\n                self.wait",
                     ["re-run before the refetch accepted", "re-run pending past the limit"]),
    "refetch-conclusion": ('raise Failure(f"{label(current)}: the latest attempt is {status}, {conclusion}")',
                           "pass", ["re-run before the refetch fails", "re-run before the refetch cancelled",
                                    "re-run during the job lookup fails"]),
    "refetch-jobs": ("                problem = self.ci_result(current, latest)\n                if problem:",
                     "                problem = self.ci_result(current, latest)\n                if False:",
                     ["re-run during the job lookup without ci-result"]),
    "refetch-jobs-workflow": ("            if workflow == DISPATCH_WORKFLOW:\n                problem = self.ci_result(current",
                              "            if False:\n                problem = self.ci_result(current",
                              ["re-run during the job lookup without ci-result"]),
    "refetch-advance": ("            attempt = latest\n", "            return latest\n",
                        ["second re-run after an accepted re-run fails"]),
    "confirm": ("evidence.confirm(workflow, run, attempt, event)", "attempt",
                ["re-run before the refetch fails", "refetch with another SHA"]),
    "argument-bounds": ("if args.wait_minutes < 0 or args.poll_seconds < 0:", "if args.wait_minutes < 0:",
                        ["negative poll"]),
    "argument-wait": ("if args.wait_minutes < 0 or args.poll_seconds < 0:", "if args.poll_seconds < 0:",
                      ["negative wait"]),
    "token": ("        if not token:\n", "        if False:\n", ["empty token"]),
    "query": ("        if query:\n", "        if True:\n", ["all five accepted"]),
    "api-url-slash": ('args.api_url = args.api_url.rstrip("/")', "pass", ["API URL with a trailing slash"]),
    "incomplete-read": ("except (OSError, http.client.HTTPException) as err:", "except OSError as err:",
                        ["truncated response"]),
}


def release_world(change=lambda world, run: None):
    def setup(world):
        world.args["--mode"] = "release"
        run = world.add("release.yml", head_branch=TAG)
        world.jobs[(run["id"], 1)] = [
            {"name": "vendored-wasm / " + name, "conclusion": "success"}
            for name in ("tree check", "stellar-cli 25.2.0", "stellar-cli 28.1.0", "rebuild", "vendored-wasm")]
        world.jobs[(run["id"], 1)].append({"name": "verify-provenance", "conclusion": "success"})
        change(world, run)
        world.expect = {"release.yml": (run["id"], run["run_attempt"], "push")}
    return setup


def release_rerun(world, run):
    world.jobs[(run["id"], 1)][0]["conclusion"] = "failure"
    world.jobs[(run["id"], 2)] = [
        {**job, "conclusion": "success"} for job in world.jobs[(run["id"], 1)]]
    run["run_attempt"] = 2


RELEASE_CASES = [
    ("release success", release_world(), None),
    ("release qualified path", release_world(lambda w, r: r.update(
        path=f".github/workflows/release.yml@refs/tags/{TAG}")), None),
    ("release zero", release_world(lambda w, r: w.runs.remove(r)), "release.yml: 0 matching"),
    ("release two", release_world(lambda w, r: w.add("release.yml", head_branch=TAG)), "release.yml: 2 matching"),
    ("release failed latest", release_world(lambda w, r: r.update(run_attempt=2, conclusion="failure")),
     "release.yml: run 1006 attempt 2: latest Release attempt must be completed with success"),
    ("release pending", release_world(lambda w, r: r.update(status="in_progress")),
     "release.yml: run 1006 attempt 1: latest Release attempt must be completed with success"),
    ("release rerun success", release_world(release_rerun), None),
    ("release failed wasm", release_world(lambda w, r: w.jobs[(r["id"], 1)][0].update(conclusion="failure")),
     "release.yml: run 1006 attempt 1: job 'vendored-wasm / tree check' (completed, failure): must be completed with success"),
    ("release pending job", release_world(lambda w, r: w.jobs[(r["id"], 1)][0].update(status="in_progress")),
     "release.yml: run 1006 attempt 1: job 'vendored-wasm / tree check' (in_progress, success): must be completed with success"),
    ("release failed provenance", release_world(lambda w, r: w.jobs[(r["id"], 1)][-1].update(conclusion="failure")),
     "release.yml: run 1006 attempt 1: job 'verify-provenance' (completed, failure): must be completed with success"),
    ("release missing provenance", release_world(lambda w, r: w.jobs[(r["id"], 1)].pop()),
     "release.yml: run 1006 attempt 1: 0 jobs named 'verify-provenance', expected one"),
    ("release duplicate provenance", release_world(lambda w, r: w.jobs[(r["id"], 1)].append(
        {"name": "verify-provenance", "conclusion": "success"})),
     "release.yml: run 1006 attempt 1: 2 jobs named 'verify-provenance', expected one"),
    ("release missing wasm", release_world(lambda w, r: w.jobs.update({(r["id"], 1): w.jobs[(r["id"], 1)][-1:]})),
     "release.yml: run 1006 attempt 1: missing Release jobs:"),
    ("release invalid ID", release_world(lambda w, r: r.update(id=0)),
     "release.yml: run 0 attempt 1: Release run ID is not a positive integer"),
    ("release invalid attempt", release_world(lambda w, r: r.update(run_attempt=0)),
     "release.yml: run 1006 attempt 0: Release run attempt is not a positive integer"),
    ("release refetch identity", release_world(lambda w, r: w.hooks.append(on_request(
        f"/actions/runs/{r['id']}", lambda w: r.update(head_sha=OTHER_SHA)))),
     "release.yml: run 1006 attempt 1: the latest Release run no longer matches"),
    ("release refetch ID", release_world(lambda w, r: w.errors.update({
        f"/actions/runs/{r['id']}": (200, {**public(r), "id": 999})})),
     "release.yml: run 1006 attempt 1: the latest Release run no longer matches"),
    ("release lookup race", release_world(lambda w, r: w.hooks.append(on_request(
        f"/actions/runs/{r['id']}/jobs", lambda w: r.update(status="in_progress")))),
     "release.yml: run 1006 attempt 1: Release run changed during the job lookup: status"),
]
for field, value in (("head_sha", OTHER_SHA), ("head_branch", "v9.9.9"), ("event", "workflow_dispatch"),
                     ("path", ".github/workflows/ci.yml"), ("repository", {"full_name": "other/repo"}),
                     ("repository", "invalid")):
    RELEASE_CASES.append((f"release wrong {field} {value}", release_world(
        lambda w, r, field=field, value=value: r.update({field: value})), "release.yml: 0 matching"))
CASES += RELEASE_CASES

MUTATIONS.update({
    "release-mode": ('if args.mode == "release":', 'if False:', ["release success"]),
    "release-filter": ('runs = [run for run in runs if self.release_matches(run)]', 'runs = runs',
                       [case[0] for case in RELEASE_CASES if case[0].startswith("release wrong")]),
    "release-count": ('if len(runs) != 1:', 'if not runs:', ["release two"]),
    "release-latest": ('current = self.get(f"/actions/runs/{run[\'id\']}", context=f"{label(run)}: ")', 'current = run',
                       ["release refetch identity"]),
    "release-refetch-identity": (' or not self.release_matches(current):', ':',
                        ["release refetch identity"]),
    "release-refetch-id": ('positive(current.get("id")) != run["id"] or not self.release_matches(current)',
                          'not self.release_matches(current)',
                        ["release refetch ID"]),
    "release-state": ('if (current.get("status"), current.get("conclusion")) != ("completed", "success"):',
                      'if False:', ["release failed latest", "release pending"]),
    "release-wasm": ('if missing:', 'if False:', ["release missing wasm"]),
    "release-provenance-count": ('if len(provenance) != 1:', 'if False:',
                                ["release missing provenance", "release duplicate provenance"]),
    "release-job-state": ('if (job.get("status"), job.get("conclusion")) != ("completed", "success"):',
                          'if False:', ["release failed wasm", "release pending job", "release failed provenance"]),
    "release-race": ('if final.get(field) != current.get(field):', 'if False:', ["release lookup race"]),
    "release-id": ('if positive(run.get("id")) is None:', 'if False:', ["release invalid ID"]),
    "release-attempt": ('        if attempt is None:\n            raise Failure(f"{label(current)}: Release run attempt',
                         '        if False:\n            raise Failure(f"{label(current)}: Release run attempt', ["release invalid attempt"]),
    "release-output": ('output.write(f"run_id={run_id}\\nrun_attempt={attempt}\\n")',
                       'output.write(f"run_id={run_id}\\nrun_attempt=1\\n")', ["release rerun success"]),
    "release-return": ('return run["id"], attempt', 'return run["id"], 1', ["release rerun success"]),
})


def release_refetch(fields, final=False, one=False):
    def change(world, run):
        if one:
            world.jobs[(1, 1)] = world.jobs.pop((run["id"], 1))
            run["id"] = 1
        path = f"/actions/runs/{run['id']}"
        normal, changed = public(run), {**public(run), **fields}
        world.hooks.append(on_request(path, *[
            lambda w, body=body: w.errors.update({path: (200, body)})
            for body in ([normal, changed] if final else [changed, normal])]))
    return release_world(change)


for index, name in enumerate(("tree check", "stellar-cli 25.2.0", "stellar-cli 28.1.0", "rebuild", "vendored-wasm")):
    label = "release missing " + name
    CASES.append((label, release_world(lambda w, r, i=index: w.jobs[(r["id"], 1)].pop(i)),
                  "release.yml: run 1006 attempt 1: missing Release jobs: vendored-wasm / " + name))
    MUTATIONS[label] = ('if missing:', 'if False:', [label])

def release_job_field(world, run, index, field, value):
    if field == "run_id" and value is True:
        world.jobs[(1, 1)] = world.jobs.pop((run["id"], 1))
        run["id"] = 1
    world.jobs[(run["id"], 1)][index].update({field: value})


for name, field, value, message in (
    ("foreign run", "run_id", 999, "belongs to run 999"),
    ("boolean run", "run_id", True, "belongs to run True"),
    ("zero attempt", "run_attempt", 0, "invalid attempt 0, latest is 1"),
    ("boolean attempt", "run_attempt", True, "invalid attempt True, latest is 1"),
    ("string attempt", "run_attempt", "1", "invalid attempt 1, latest is 1"),
    ("future attempt", "run_attempt", 2, "invalid attempt 2, latest is 1"),
):
    for index, job_name in ((0, "vendored-wasm / tree check"), (-1, "verify-provenance")):
        label = f"release job {name} {index}"
        CASES.append((label, release_world(
            lambda w, r, i=index, f=field, v=value: release_job_field(w, r, i, f, v)),
            f"release.yml: run {1 if name == 'boolean run' else 1006} attempt 1: job {job_name!r} (completed, success): {message}"))
        needle, replacement = {
            "run_id": ('if positive(job.get("run_id")) != run["id"]:', 'if False:'),
            "run_attempt": ('if job_attempt is None or job_attempt > attempt:',
                            'if job_attempt is None:' if value == 2 else 'if job_attempt is not None and job_attempt > attempt:'),
        }[field]
        if name == "boolean run":
            replacement = 'if job.get("run_id") != run["id"]:'
        MUTATIONS[label] = (needle, replacement, [label])

CASES += [
    ("release boolean ID", release_world(lambda w, r: r.update(id=True)),
     "release.yml: run True attempt 1: Release run ID is not a positive integer"),
    ("release boolean attempt", release_world(lambda w, r: r.update(run_attempt=True)),
     "release.yml: run 1006 attempt True: Release run attempt is not a positive integer"),
    ("release run API error", release_world(lambda w, r: w.errors.update(
        {f"/actions/runs/{r['id']}": (500, {})})),
     "release.yml: run 1006 attempt 1: GET /actions/runs/1006: HTTP 500"),
    ("release jobs API error", release_world(lambda w, r: w.errors.update(
        {f"/actions/runs/{r['id']}/jobs": (500, {})})),
     "release.yml: run 1006 attempt 1: GET /actions/runs/1006/jobs: HTTP 500"),
    ("release final API error", release_world(lambda w, r: w.hooks.append(on_request(
        f"/actions/runs/{r['id']}", lambda w: None,
        lambda w: w.errors.update({f"/actions/runs/{r['id']}": (500, {})})))),
     "release.yml: run 1006 attempt 1: GET /actions/runs/1006: HTTP 500"),
    ("release older job attempt", release_world(lambda w, r: (
        release_rerun(w, r), w.jobs[(r["id"], 2)][0].update(run_attempt=1))), None),
    ("release extra wasm failed", release_world(lambda w, r: w.jobs[(r["id"], 1)].append(
        {"name": "vendored-wasm / extra", "conclusion": "failure"})),
     "release.yml: run 1006 attempt 1: job 'vendored-wasm / extra' (completed, failure): must be completed with success"),
    ("release metadata changed", release_refetch({"updated_at": "later", "extra": {}}, final=True), None),
    ("release current boolean ID", release_refetch({"id": True}, one=True),
     "release.yml: run 1 attempt 1: the latest Release run no longer matches"),
    ("release final boolean ID", release_refetch({"id": True}, final=True, one=True),
     "release.yml: run 1 attempt 1: refetched Release run no longer matches"),
    ("release final boolean attempt", release_refetch({"run_attempt": True}, final=True),
     "release.yml: run 1006 attempt 1: refetched Release run no longer matches"),
    ("release final repository", release_refetch({"repository": {"full_name": "other/repo"}}, final=True),
     "release.yml: run 1006 attempt 1: refetched Release repository no longer matches"),
    ("release output unset", release_world(lambda w, r: w.env.update(GITHUB_OUTPUT="unset")),
     "release.yml: GITHUB_OUTPUT is unset or empty in release mode"),
    ("release output empty", release_world(lambda w, r: w.env.update(GITHUB_OUTPUT="")),
     "release.yml: GITHUB_OUTPUT is unset or empty in release mode"),
]
for field, value in (("id", 999), ("path", ".github/workflows/other.yml"), ("event", "workflow_dispatch"),
                     ("head_branch", "v9.9.9"), ("head_sha", OTHER_SHA), ("run_attempt", 2),
                     ("status", "in_progress"), ("conclusion", "failure")):
    label = "release final " + field
    CASES.append((label, release_refetch({field: value}, final=True),
                  "release.yml: run 1006 attempt 1: Release run changed during the job lookup: " + field))
    # Matching identity fields still undergo the final repository check.
    needle = 'if final.get(field) != current.get(field):'
    MUTATIONS[label] = (needle, f'if field != {field!r} and final.get(field) != current.get(field):', [label])

MUTATIONS.update({
    "release-current-context": ('current = self.get(f"/actions/runs/{run[\'id\']}", context=f"{label(run)}: ")',
                                'current = self.get(f"/actions/runs/{run[\'id\']}")', ["release run API error"]),
    "release-jobs-context": ('"jobs", f"{label(current)}: ")', '"jobs")', ["release jobs API error"]),
    "release-final-context": ('final = self.get(f"/actions/runs/{run[\'id\']}", context=f"{label(current)}: ")',
                              'final = self.get(f"/actions/runs/{run[\'id\']}")', ["release final API error"]),
    "release-current-positive": ('positive(current.get("id")) != run["id"] or not self.release_matches(current)',
                                'current.get("id") != run["id"] or not self.release_matches(current)',
                                ["release current boolean ID"]),
    "release-final-positive": ('positive(final.get("id")) is None or attempt_of(final) is None',
                              'attempt_of(final) is None', ["release final boolean ID"]),
    "release-final-attempt": ('positive(final.get("id")) is None or attempt_of(final) is None',
                             'positive(final.get("id")) is None', ["release final boolean attempt"]),
    "release-final-repository": ('if not self.release_matches(final):', 'if False:', ["release final repository"]),
    "release-metadata": ('if final.get(field) != current.get(field):', 'if final != current:', ["release metadata changed"]),
    "release-older-job": ('job_attempt > attempt:', 'job_attempt != attempt:', ["release older job attempt"]),
    "release-output-required": ('if not output_path:', 'if False:', ["release output unset", "release output empty"]),
})
# Each status/conclusion clause has its own control.
for name, needle, labels in (
    ("release-state", 'if (current.get("status"), current.get("conclusion")) != ("completed", "success"):',
     ("release pending", "release failed latest")),
    ("release-job-state", 'if (job.get("status"), job.get("conclusion")) != ("completed", "success"):',
     ("release pending job", "release failed wasm")),
):
    del MUTATIONS[name]
    owner = "current" if name == "release-state" else "job"
    for omitted, kept, expected, label in (
        ("status", "conclusion", "success", labels[0]), ("conclusion", "status", "completed", labels[1])
    ):
        MUTATIONS[name + "-" + omitted] = (needle, f'if {owner}.get("{kept}") != "{expected}":', [label])

del MUTATIONS["release-filter"]
for field, label in (("event", "release wrong event workflow_dispatch"),
                     ("head_branch", "release wrong head_branch v9.9.9"),
                     ("head_sha", "release wrong head_sha " + OTHER_SHA)):
    MUTATIONS["release-filter-" + field] = (
        'all(run.get(key) == value for key, value in expected.items())',
        f'all(run.get(key) == value for key, value in expected.items() if key != {field!r})', [label])
for name, needle, replacement, label in (
    ("path", 'and run.get("path") in (path, f"{path}@refs/tags/{self.args.tag}")', '',
     "release wrong path .github/workflows/ci.yml"),
    ("repository", 'run["repository"].get("full_name") == self.args.repository', 'True',
     "release wrong repository {'full_name': 'other/repo'}"),
    ("repository-type", 'if not isinstance(run.get("repository"), dict):', 'if False:',
     "release wrong repository invalid"),
):
    MUTATIONS["release-filter-" + name] = (needle, replacement, [label])
MUTATIONS["release-zero-count"] = ('if len(runs) != 1:', 'if len(runs) > 1:', ["release zero"])
del MUTATIONS["release-provenance-count"]
for name, comparison, label in (("missing", "> 1", "release missing provenance"),
                                ("duplicate", "== 0", "release duplicate provenance")):
    MUTATIONS["release-provenance-" + name] = ('if len(provenance) != 1:', f'if len(provenance) {comparison}:', [label])


def run_case(script, case, url):
    label, setup, expected = case
    world = World()
    setup(world)
    STATE["world"] = world
    workflows = ("release.yml",) if world.args.get("--mode") == "release" else WORKFLOWS
    for workflow in workflows:
        if expected is None and workflow not in world.expect:
            world.expect[workflow] = (world.push(workflow)["id"], 1, "push")
    options = {"--repository": REPO, "--sha": SHA, "--tag": TAG, "--wait-minutes": "1",
               "--poll-seconds": "0", "--api-url": url}
    options.update(world.args)
    command = [sys.executable, "-B", str(script)] + [part for item in options.items() for part in item]
    env = {key: value for key, value in os.environ.items() if "proxy" not in key.lower() and key != "GH_TOKEN"}
    env.update(world.env, NO_PROXY="127.0.0.1")
    with tempfile.TemporaryDirectory() as scratch:
        output = pathlib.Path(scratch) / "outputs"
        if world.env.get("GITHUB_OUTPUT") != "unset":
            env["GITHUB_OUTPUT"] = world.env.get("GITHUB_OUTPUT", str(output))
        else:
            env.pop("GITHUB_OUTPUT", None)
        result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=300)
        if expected is None and workflows == ("release.yml",):
            run_id, attempt, _ = world.expect["release.yml"]
            if not output.exists() or output.read_text() != f"run_id={run_id}\nrun_attempt={attempt}\n":
                return "Release step outputs differ"
    if expected is None:
        wanted = "".join(f"check-run-evidence: {workflow}: accepted run {world.expect[workflow][0]} attempt "
                         f"{world.expect[workflow][1]} ({world.expect[workflow][2]})\n" for workflow in workflows)
        if result.returncode != 0 or result.stdout != wanted:
            return f"exit {result.returncode}, expected 0 with\n{wanted}got\n{result.stdout}{result.stderr}"
        return None
    message = expected(world) if callable(expected) else expected
    if result.returncode != 1 or f"check-run-evidence: FAIL: {message}" not in result.stderr:
        return f"exit {result.returncode}, expected 1 with FAIL: {message}\ngot {result.stdout}{result.stderr}"
    return None


def run_cases(script, cases, url, quiet=False):
    failed = []
    for case in cases:
        problem = run_case(script, case, url)
        if problem:
            failed.append(case[0])
            if not quiet:
                print(f"FAIL {case[0]}: {problem}", file=sys.stderr)
        elif not quiet:
            print(f"ok   {case[0]}")
    return failed


def mutations(url):
    source = SCRIPT.read_text()
    by_label = {case[0]: case for case in CASES}
    problems = 0
    with tempfile.TemporaryDirectory(prefix="check-run-evidence-") as scratch:
        copy = pathlib.Path(scratch) / SCRIPT.name
        for name, (old, new, labels) in MUTATIONS.items():
            cases = [by_label[label] for label in labels]
            if source.count(old) != 1 or not cases:
                print(f"FAIL mutation {name}: target found {source.count(old)} times, {len(cases)} cases",
                      file=sys.stderr)
                problems += 1
                continue
            copy.write_text(source.replace(old, new, 1))
            survived = set(labels) - set(run_cases(copy, cases, url, quiet=True))
            copy.write_text(source)
            if hashlib.md5(copy.read_bytes()).digest() != hashlib.md5(source.encode()).digest():
                raise SystemExit(f"FAIL mutation {name}: the restored copy differs")
            restored = run_cases(copy, cases, url, quiet=True)
            if survived or restored:
                print(f"FAIL mutation {name}: passes {sorted(survived)}; restored copy fails {restored}",
                      file=sys.stderr)
                problems += 1
            else:
                print(f"ok   mutation {name}: fails {', '.join(labels)}")
    return problems


def main():
    parser = argparse.ArgumentParser(description="Offline checks of check-run-evidence.py.")
    parser.add_argument("--case")
    parser.add_argument("--mutations", action="store_true")
    args = parser.parse_args()
    labels = [case[0] for case in CASES]
    if len(set(labels)) != len(labels):
        print("FAIL duplicate case labels", file=sys.stderr)
        return 1
    cases = [case for case in CASES if args.case in (None, case[0])]
    if not cases:
        print(f"FAIL no case {args.case!r}", file=sys.stderr)
        return 1
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = STATE["url"] = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        failed = run_cases(SCRIPT, cases, url)
        problems = len(failed)
        if not failed and args.mutations:
            problems += mutations(url)
    finally:
        server.shutdown()
        server.server_close()
    if problems:
        print(f"{problems} problem(s)", file=sys.stderr)
        return 1
    print("run evidence tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
