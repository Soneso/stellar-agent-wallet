#!/usr/bin/env python3
"""Require the push CI evidence of a release tag's commit.

Usage: check-run-evidence.py --repository OWNER/NAME --sha SHA --tag TAG
       --wait-minutes N --poll-seconds N [--api-url URL] [--mode ci|release]

Reads the GitHub REST API with the token in GH_TOKEN. Each workflow of
REQUIRED_WORKFLOWS needs a run of exactly the commit SHA on main, started by
a push, whose latest attempt completed with success. A ci.yml run also needs
exactly one successful job ci-result (main) in that attempt. Only ci.yml
accepts a dispatched run in place of a missing or failed push run: one on
main with ci-result (main), or one on the tag with ci-result (<tag>).

A run counts only when its repository, path, event, head_branch and head_sha
match. Its path is the workflow file, alone or followed by @ and the run's
own ref. A run in a WAITING status is waited for, polling every
--poll-seconds, up to --wait-minutes in total. Before success, every
selected run is fetched again by ID; a newer attempt is evaluated again, and
a run whose latest attempt is not a success fails the check.

Prints the accepted run ID and attempt per workflow and exits 0. Exits 1 on
every failure with a message that names the workflow, and the run ID and
attempt where one exists. Uses the standard library only.

With --mode release, require exactly one release.yml push run on the tag
and commit. Its latest attempt and every vendored-wasm and verify-provenance
job must succeed. Require the tree check, both stellar-cli builds, rebuild,
and gate by name. Each job belongs to this run and an attempt no later than
the latest. Write run_id and run_attempt to GITHUB_OUTPUT.
"""

import argparse
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REQUIRED_WORKFLOWS = ("ci.yml", "coverage.yml", "install-surface.yml", "vendored-wasm.yml", "changelog.yml")
# The one workflow whose dispatched run can stand in for its push run.
DISPATCH_WORKFLOW = "ci.yml"
BRANCH = "main"
PER_PAGE = 100
# The statuses of a run that has not finished yet.
WAITING = ("requested", "waiting", "pending", "queued", "in_progress")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
SHA = re.compile(r"[0-9a-f]{40}")
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?")
RELEASE_WASM_JOBS = {"vendored-wasm / " + name for name in (
    "tree check", "stellar-cli 25.2.0", "stellar-cli 28.1.0", "rebuild", "vendored-wasm")}
RELEASE_RUN_FIELDS = ("id", "path", "event", "head_branch", "head_sha", "run_attempt", "status", "conclusion")


class Failure(Exception):
    """A reason the evidence is refused."""


def positive(value):
    """The value when it is a positive integer, else None."""
    return value if type(value) is int and value > 0 else None


def attempt_of(run):
    return positive(run.get("run_attempt"))


def label(run, attempt=None):
    return f"run {run.get('id')} attempt {attempt if attempt is not None else run.get('run_attempt')}"


class Evidence:
    def __init__(self, args, token):
        self.args = args
        self.token = token
        self.deadline = time.monotonic() + args.wait_minutes * 60

    def get(self, path, query=None, context=""):
        """The JSON object at path; context names the run and attempt the
        request is for, when one is known."""
        where = f"{context}GET {path}"
        url = f"{self.args.api_url}/repos/{self.args.repository}{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        try:
            request = urllib.request.Request(url, headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
            })
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read()
        except urllib.error.HTTPError as err:
            raise Failure(f"{where}: HTTP {err.code}") from None
        except (OSError, http.client.HTTPException) as err:
            raise Failure(f"{where}: {err}") from None
        try:
            document = json.loads(body)
        except ValueError:
            raise Failure(f"{where}: malformed JSON") from None
        if not isinstance(document, dict):
            raise Failure(f"{where}: malformed response: not an object")
        return document

    def pages(self, path, query, key, context=""):
        items, page = [], 1
        while True:
            batch = self.get(path, dict(query, per_page=PER_PAGE, page=page), context).get(key)
            if not isinstance(batch, list) or not all(isinstance(item, dict) for item in batch):
                raise Failure(f"{context}GET {path}: malformed response: {key} is not a list of objects")
            items.extend(batch)
            if len(batch) < PER_PAGE:
                return items
            page += 1

    def matches(self, run, workflow, event):
        """Whether the run is a run of workflow for event on the tag commit."""
        branch = run.get("head_branch")
        if branch not in ((BRANCH,) if event == "push" else (BRANCH, self.args.tag)):
            return False
        ref = f"refs/heads/{BRANCH}" if branch == BRANCH else f"refs/tags/{self.args.tag}"
        path = f".github/workflows/{workflow}"
        repository = run.get("repository")
        return (isinstance(repository, dict) and repository.get("full_name") == self.args.repository
                and run.get("path") in (path, f"{path}@{ref}")
                and run.get("event") == event
                and run.get("head_sha") == self.args.sha)

    def ci_result(self, run, attempt):
        """None when the attempt has exactly one completed, successful
        ci-result job of the run's branch, for that run and attempt, else the
        reason."""
        name = f"ci-result ({run['head_branch']})"
        jobs = self.pages(f"/actions/runs/{run['id']}/attempts/{attempt}/jobs", {}, "jobs",
                          f"{label(run, attempt)}: ")
        named = [job for job in jobs if job.get("name") == name]
        if len(named) != 1:
            return f"{label(run, attempt)}: {len(named)} jobs named {name!r}, expected one"
        job = named[0]
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            return f"{label(run, attempt)}: job {name!r} is {job.get('status')}, {job.get('conclusion')}"
        if positive(job.get("run_id")) != run["id"] or positive(job.get("run_attempt")) != attempt:
            return (f"{label(run, attempt)}: job {name!r} belongs to run {job.get('run_id')} "
                    f"attempt {job.get('run_attempt')}")
        return None

    def wait(self, what):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise Failure(f"{what} did not complete within {self.args.wait_minutes} minutes")
        time.sleep(min(self.args.poll_seconds, remaining))

    def poll(self, workflow, event):
        """Returns (run, attempt) of an accepted run or None, the waiting
        runs, and the reasons each other matching run was refused."""
        query = {"event": event, "head_sha": self.args.sha}
        if event == "push":
            query["branch"] = BRANCH
        waiting, refused = [], []
        for run in self.pages(f"/actions/workflows/{workflow}/runs", query, "workflow_runs"):
            if not self.matches(run, workflow, event):
                continue
            attempt = attempt_of(run)
            if attempt is None or positive(run.get("id")) is None:
                refused.append(f"{event} {label(run)}: the run ID or attempt is not a positive integer")
                continue
            status, conclusion = run.get("status"), run.get("conclusion")
            if status in WAITING:
                waiting.append(f"{event} {label(run)} ({status})")
                continue
            if status != "completed" or conclusion != "success":
                refused.append(f"{event} {label(run)}: {status}, {conclusion}")
                continue
            if workflow == DISPATCH_WORKFLOW:
                problem = self.ci_result(run, attempt)
                if problem:
                    refused.append(f"{event} {problem}")
                    continue
            return (run, attempt), waiting, refused
        return None, waiting, refused

    def select(self, workflow):
        """Returns (run, attempt, event) of the accepted run of workflow."""
        while True:
            accepted, waiting, refused = self.poll(workflow, "push")
            if accepted:
                return (*accepted, "push")
            if not waiting and workflow == DISPATCH_WORKFLOW:
                accepted, waiting, more = self.poll(workflow, "workflow_dispatch")
                if accepted:
                    return (*accepted, "workflow_dispatch")
                refused += more
            if not waiting:
                fallback = ("no dispatched run succeeded either" if workflow == DISPATCH_WORKFLOW
                            else f"only {DISPATCH_WORKFLOW} accepts a dispatched run")
                found = "; ".join(refused) or "no matching run"
                raise Failure(f"no successful push run on {BRANCH} of {self.args.sha} ({found}); {fallback}")
            self.wait(", ".join(waiting))

    def confirm(self, workflow, run, attempt, event):
        """Fetches the run again until its latest attempt is accepted;
        returns that attempt. The refetched run keeps the selected run's ID
        and branch, so a dispatch stays bound to the ci-result job of its
        branch."""
        while True:
            current = self.get(f"/actions/runs/{run['id']}", context=f"{label(run, attempt)}: ")
            if (positive(current.get("id")) != run["id"] or current.get("head_branch") != run["head_branch"]
                    or not self.matches(current, workflow, event)):
                raise Failure(f"{label(run, attempt)}: the refetched run no longer matches")
            latest = attempt_of(current)
            if latest is None:
                raise Failure(f"{label(run, attempt)}: the refetched attempt is not a positive integer")
            status, conclusion = current.get("status"), current.get("conclusion")
            if latest < attempt or (latest == attempt and (status, conclusion) != ("completed", "success")):
                raise Failure(f"{label(current)}: refetched as {status}, {conclusion} after attempt {attempt}")
            if latest == attempt:
                return attempt
            if status in WAITING:
                self.wait(f"{label(current)} ({status})")
                continue
            if status != "completed" or conclusion != "success":
                raise Failure(f"{label(current)}: the latest attempt is {status}, {conclusion}")
            if workflow == DISPATCH_WORKFLOW:
                problem = self.ci_result(current, latest)
                if problem:
                    raise Failure(problem)
            attempt = latest

    def release_matches(self, run):
        if not isinstance(run.get("repository"), dict):
            return False
        path = ".github/workflows/release.yml"
        expected = {"event": "push", "head_branch": self.args.tag, "head_sha": self.args.sha}
        return (run["repository"].get("full_name") == self.args.repository
                and run.get("path") in (path, f"{path}@refs/tags/{self.args.tag}")
                and all(run.get(key) == value for key, value in expected.items()))

    def release(self):
        runs = self.pages("/actions/workflows/release.yml/runs",
                          {"event": "push", "branch": self.args.tag, "head_sha": self.args.sha}, "workflow_runs")
        runs = [run for run in runs if self.release_matches(run)]
        if len(runs) != 1:
            raise Failure(f"{len(runs)} matching Release runs, expected exactly one")
        run = runs[0]
        if positive(run.get("id")) is None:
            raise Failure(f"{label(run)}: Release run ID is not a positive integer")
        current = self.get(f"/actions/runs/{run['id']}", context=f"{label(run)}: ")
        if positive(current.get("id")) != run["id"] or not self.release_matches(current):
            raise Failure(f"{label(run)}: the latest Release run no longer matches")
        attempt = attempt_of(current)
        if attempt is None:
            raise Failure(f"{label(current)}: Release run attempt is not a positive integer")
        if (current.get("status"), current.get("conclusion")) != ("completed", "success"):
            raise Failure(f"{label(current)}: latest Release attempt must be completed with success")
        jobs = self.pages(f"/actions/runs/{run['id']}/jobs", {"filter": "latest"}, "jobs", f"{label(current)}: ")
        wasm = [job for job in jobs if str(job.get("name", "")).startswith("vendored-wasm / ")]
        provenance = [job for job in jobs if job.get("name") == "verify-provenance"]
        missing = RELEASE_WASM_JOBS - {job.get("name") for job in wasm}
        if missing:
            raise Failure(f"{label(current)}: missing Release jobs: {', '.join(sorted(missing))}")
        if len(provenance) != 1:
            raise Failure(f"{label(current)}: {len(provenance)} jobs named 'verify-provenance', expected one")
        for job in wasm + provenance:
            job_label = f"{label(current)}: job {job.get('name')!r} ({job.get('status')}, {job.get('conclusion')})"
            if (job.get("status"), job.get("conclusion")) != ("completed", "success"):
                raise Failure(f"{job_label}: must be completed with success")
            if positive(job.get("run_id")) != run["id"]:
                raise Failure(f"{job_label}: belongs to run {job.get('run_id')}")
            job_attempt = positive(job.get("run_attempt"))
            if job_attempt is None or job_attempt > attempt:
                raise Failure(f"{job_label}: invalid attempt {job.get('run_attempt')}, latest is {attempt}")
        # A rerun during the job lookup requires a fresh evidence check.
        final = self.get(f"/actions/runs/{run['id']}", context=f"{label(current)}: ")
        if positive(final.get("id")) is None or attempt_of(final) is None:
            raise Failure(f"{label(current)}: refetched Release run no longer matches")
        for field in RELEASE_RUN_FIELDS:
            if final.get(field) != current.get(field):
                raise Failure(f"{label(current)}: Release run changed during the job lookup: {field}")
        if not self.release_matches(final):
            raise Failure(f"{label(current)}: refetched Release repository no longer matches")
        return run["id"], attempt


def arguments(argv):
    parser = argparse.ArgumentParser(description="Require the push CI evidence of a release tag's commit.")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--mode", choices=("ci", "release"), default="ci")
    parser.add_argument("--wait-minutes", type=int, required=True)
    parser.add_argument("--poll-seconds", type=int, required=True)
    parser.add_argument("--api-url", default="https://api.github.com")
    args = parser.parse_args(argv)
    args.api_url = args.api_url.rstrip("/")
    # The tests serve their fixtures over http on 127.0.0.1; every other URL needs https.
    try:
        url = urllib.parse.urlsplit(args.api_url)
        url.port  # Raises ValueError for a port that is not a number from 0 to 65535.
    except ValueError as err:
        raise Failure(f"--api-url {args.api_url!r}: {err}") from None
    if not ((url.scheme == "https" and url.hostname) or (url.scheme == "http" and url.hostname == "127.0.0.1")):
        raise Failure(f"--api-url {args.api_url!r} is neither https nor http on 127.0.0.1")
    for name, pattern in (("repository", REPOSITORY), ("sha", SHA), ("tag", TAG)):
        if not pattern.fullmatch(getattr(args, name)):
            raise Failure(f"--{name} {getattr(args, name)!r} does not match {pattern.pattern}")
    if args.wait_minutes < 0 or args.poll_seconds < 0:
        raise Failure("--wait-minutes and --poll-seconds must not be negative")
    return args


def main(argv=None):
    workflow = "arguments"
    try:
        args = arguments(argv)
        token = os.environ.get("GH_TOKEN", "")
        if not token:
            raise Failure("GH_TOKEN is empty")
        evidence = Evidence(args, token)
        if args.mode == "release":
            workflow = "release.yml"
            output_path = os.environ.get("GITHUB_OUTPUT")
            if not output_path:
                raise Failure("GITHUB_OUTPUT is unset or empty in release mode")
            run_id, attempt = evidence.release()
            with open(output_path, "a", encoding="utf-8") as output:
                output.write(f"run_id={run_id}\nrun_attempt={attempt}\n")
            print(f"check-run-evidence: release.yml: accepted run {run_id} attempt {attempt} (push)")
            return 0
        selected = []
        for workflow in REQUIRED_WORKFLOWS:
            selected.append((workflow, *evidence.select(workflow)))
        accepted = []
        for workflow, run, attempt, event in selected:
            accepted.append((workflow, run["id"], evidence.confirm(workflow, run, attempt, event), event))
    except Failure as err:
        print(f"check-run-evidence: FAIL: {workflow}: {err}", file=sys.stderr)
        return 1
    for workflow, run_id, attempt, event in accepted:
        print(f"check-run-evidence: {workflow}: accepted run {run_id} attempt {attempt} ({event})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
