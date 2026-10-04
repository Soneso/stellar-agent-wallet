#!/usr/bin/env python3
"""Structural check of the release, publish, notarization, and maintenance workflows.

Usage: ``check-workflow-invariants.py [repository-root]``

Reads ``release.yml``, ``publish.yml``, ``notarize-smoke.yml``, ``labels.yml``,
``stale.yml``, and ``triage.yml`` under ``.github/workflows/``. Also reads the composite action
``.github/actions/macos-sign-notarize/action.yml``. Needs PyYAML.

A job is credentialed when it references ``secrets.``, passes secrets to a
reusable workflow, declares ``environment:``, or holds ``id-token: write``,
``contents: write``, or ``write-all`` (its own permissions, else the
workflow's). Shell text is read line by line, with continuation lines joined
and comment lines skipped. The check fails when any of these holds:

- ``unreadable``: a workflow or the composite action is missing or is not
  valid YAML.
- ``missing-job``: a job that a rule below names does not exist.
- ``workflow-permissions``: a workflow sets no top-level ``permissions``.
- ``cred-compile``: a credentialed job uses ``Swatinem/rust-cache``,
  ``actions/cache``, or a sub-action of either, runs ``cross``, or runs a
  cargo subcommand other than ``metadata``, ``-V``, ``--version``, or
  ``package``/``publish`` with ``--no-verify``. Every ``cargo`` command word
  on a line counts, also as the last component of a path and in quotes. The
  arguments of a call end at ``;``, ``&``, ``|``, ``)``, a backtick, or a
  comment. The check covers the job's ``run:`` blocks, the scripts under
  ``.github/scripts/`` or ``.github/actions/`` they name, and the composite
  actions the job uses.
- ``cred-toolchain``: a credentialed job installs a Rust toolchain, except
  the ``publish`` job of ``publish.yml``, whose install compiles nothing.
- ``signing-env``: a job other than the two signing jobs references
  ``release-signing`` or an ``APPLE_`` secret, or a signing job does not
  declare ``environment: release-signing``.
- ``checkout-credentials``: an ``actions/checkout`` step lacks
  ``persist-credentials: false``.
- ``run-inputs``: a ``run:`` block holds an expression that reads ``inputs.``.
- ``cred-run-outputs``: a credentialed job's ``run:`` block holds an
  expression that reads ``needs.`` or ``steps.``.
- ``cred-with-needs``: a credentialed job passes an expression that reads
  ``needs.`` to an action's ``with:``, or to a reusable workflow input other
  than the two of the SLSA provenance job: ``base64-subjects`` from the
  hashes job and ``provenance-name`` from the preflight version.
- ``cred-env-validation``: an expression that reads ``needs.`` or
  ``inputs.`` reaches a credentialed job through the workflow ``env`` or the
  job ``env``, or through the ``env`` of a step whose ``run:`` block has no
  ``=~`` test.
- ``cred-download-path``: a credentialed job downloads an artifact to a path
  outside ``${{ runner.temp }}`` or with a ``..`` segment.
- ``verify-crates-download``: a credentialed job can download
  ``verify-crates``.
- ``credential-order``: a signing job or the ``publish.yml`` publish job
  breaks one of these. The step that receives the credential exists: the
  signing action, or the step that mints the registry token. For each check
  that ``CREDENTIAL_GUARDS`` lists for the job, an earlier step holds its
  text on a line that is not a comment. A clean-checkout step runs between
  the last artifact download and the first step that holds the job's recheck
  text. Another runs after the last step that holds the recheck text and
  before the credential step. No earlier step that holds a check sets ``if``
  or ``continue-on-error``, turns off errexit with ``set +e``, or holds the
  check's text on a line with ``;``, ``&``, or ``|``. The job does not set
  ``continue-on-error``.
- ``composite-expression``: a ``run:`` block of the composite action holds an
  expression other than ``github.action_path``.
- ``publish-tag-ref``: a ``publish.yml`` checkout uses a ref other than
  ``refs/tags/...`` or ``github.workflow_sha``, or a ``publish.yml`` job has
  no ``refs/tags/`` checkout.
- ``ancestry-check``: the ``release.yml`` preflight or a ``publish.yml`` job
  has no line whose first word is the path of ``check-ref-on-main.sh`` and
  that holds no shell operator. The step of that line sets ``if`` or
  ``continue-on-error``, or the job sets ``continue-on-error``. A
  ``publish.yml`` job passes the script the dispatch commit (``GITHUB_SHA``).
"""

import fnmatch
import pathlib
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("check-workflow-invariants.py needs PyYAML (pip install PyYAML)")

WORKFLOWS = ("release.yml", "publish.yml", "notarize-smoke.yml", "labels.yml", "stale.yml", "triage.yml")
COMPOSITE = pathlib.PurePosixPath(".github/actions/macos-sign-notarize")
SIGNING_JOBS = {("release.yml", "sign-macos"), ("notarize-smoke.yml", "sign")}
TOOLCHAIN_ALLOWED = {("publish.yml", "publish")}
# The SLSA generator is a reusable workflow: its job has no steps that could
# validate an output first. It receives the base64 subjects the hashes job
# computes itself and the version the preflight validates, each through one
# named input.
REUSABLE_NEEDS_ALLOWED = {
    ("release.yml", "provenance", "base64-subjects"): "needs.hashes.outputs.subjects",
    ("release.yml", "provenance", "provenance-name"): "needs.preflight.outputs.version",
}
ANCESTRY_JOBS = {("release.yml", "preflight"), ("publish.yml", "verify"), ("publish.yml", "publish")}
# For each job: the action that receives a credential, and the text of the
# checks that earlier steps must hold. The third entry is the text of the
# workspace code that reads the downloaded data. A clean-checkout check must
# run before that step and again after it, before the action.
# The signing jobs validate the unsigned binaries and check the checkout. The
# publish job runs the ancestry check, the checksum comparison, the checkout
# check, and the toolchain check.
SIGNING_ACTION = "./.github/actions/macos-sign-notarize"
CLEAN_CHECK = "status --porcelain"
CREDENTIAL_GUARDS = {
    ("release.yml", "sign-macos"): (SIGNING_ACTION, ("validate-input.sh", CLEAN_CHECK), "validate-input.sh"),
    ("notarize-smoke.yml", "sign"): (SIGNING_ACTION, ("validate-input.sh", CLEAN_CHECK), "validate-input.sh"),
    ("publish.yml", "publish"): ("rust-lang/crates-io-auth-action", (
        "check-ref-on-main.sh", "compare-crate-sums.py", CLEAN_CHECK, "rustc -V"), "compare-crate-sums.py"),
}

EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
RUNNER_TEMP_PATH = re.compile(r"^\$\{\{\s*runner\.temp\s*\}\}(/|$)")
WORKFLOW_SHA_REF = re.compile(r"^\$\{\{\s*github\.workflow_sha\s*\}\}$")
SCRIPT_REF = re.compile(r"\.github/(?:scripts|actions)/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")
# A command word: the name alone or as the last component of a path, with an
# optional closing quote. The name inside another word, as in .cargo/bin,
# does not match.
COMMAND_WORD = r"(?<![\w.-]){}[\"']?"
# A cargo call up to its subcommand. Matching stops there, so every later
# cargo call on the same line is found as well.
CARGO_CALL = re.compile(COMMAND_WORD.format("cargo") + r"(?:\s+\+\S+)?\s+([^\s;&|)`]+)")
CROSS_CALL = re.compile(COMMAND_WORD.format("cross") + r"(?:\s+\+\S+)?\s+[a-z]")
# Where the arguments of one command end: a shell operator, the end of a
# command substitution or subshell, or a comment.
ARGUMENTS_END = re.compile(r"[;&|)`]|(?<!\S)#")
ALLOWED_CARGO = {"metadata", "-V", "--version"}
NO_VERIFY_CARGO = {"package", "publish"}
# A shell operator on a line that holds a check, which could chain the check,
# skip it, or discard its result.
SHELL_OPERATOR = re.compile(r"[;&|]")
# The set builtin turning off errexit.
ERREXIT_OFF = re.compile(r"(?<![\w-])set\s+(?:\+\w*e|\+o\s+errexit\b)")
# The ancestry script as the command of a line. Its path is the first word
# with or without quotes and holds only directory names and variables. No
# shell operator after it can chain or discard its result.
ANCESTRY_CALL = re.compile(
    r"""^\s*["']?(?:\$\{?[A-Za-z_]\w*\}?/|[\w.-]+/)*\.github/scripts/check-ref-on-main\.sh["']?(?:\s[^;&|]*)?$""")


class Checker:
    def __init__(self, root):
        self.root = root
        self.violations = []
        self.jobs_checked = 0

    def report(self, where, rule, message):
        self.violations.append(f"{where}: {rule}: {message}")

    def load(self, relative):
        path = self.root / relative
        try:
            with open(path) as handle:
                return yaml.safe_load(handle)
        except (OSError, yaml.YAMLError) as err:
            self.report(str(relative), "unreadable", str(err))
            return None

    @staticmethod
    def expressions(text):
        return [" ".join(m.split()) for m in EXPRESSION.findall(text or "")]

    @staticmethod
    def reads(value, pattern):
        return any(re.search(pattern, e) for e in Checker.expressions(str(value)))

    @staticmethod
    def logical_lines(text):
        joined = re.sub(r"\\\n", " ", text or "")
        return [line for line in joined.split("\n") if not line.lstrip().startswith("#")]

    def runs(self, run, text):
        """Whether a run: block holds text on a line that is not a comment."""
        return run is not None and any(text in line for line in self.logical_lines(run))

    @staticmethod
    def may_skip(step):
        """Whether the runner can skip a step, or the step can fail without failing its job."""
        return "if" in step or "continue-on-error" in step

    def check_shell(self, where, text):
        for line in self.logical_lines(text):
            if CROSS_CALL.search(line):
                self.report(where, "cred-compile", f"runs cross: {line.strip()}")
            for match in CARGO_CALL.finditer(line):
                sub = match.group(1).strip("\"'")
                arguments = ARGUMENTS_END.split(line[match.end():], maxsplit=1)[0]
                call = f"cargo {sub}{arguments}".strip()
                if sub in ALLOWED_CARGO:
                    continue
                if sub in NO_VERIFY_CARGO:
                    if "--no-verify" not in arguments.split():
                        self.report(where, "cred-compile", f"cargo {sub} without --no-verify: {call}")
                    continue
                self.report(where, "cred-compile", f"runs cargo {sub}: {call}")

    def check_referenced_files(self, where, text, seen):
        for ref in SCRIPT_REF.findall(text or ""):
            relative = pathlib.PurePosixPath(ref)
            if relative in seen:
                continue
            seen.add(relative)
            path = self.root / relative
            if path.is_dir():
                self.check_composite_use(where, relative, seen)
            elif path.is_file():
                content = path.read_text(errors="replace")
                self.check_shell(f"{where} -> {relative}", content)
                self.check_referenced_files(where, content, seen)
            else:
                self.report(where, "cred-compile", f"names {relative}, which does not exist")

    def check_step_uses(self, where, uses, workflow, job_id):
        if re.match(r"(Swatinem/rust-cache|actions/cache)(/[\w.-]+)*@", uses):
            self.report(where, "cred-compile", f"uses {uses}")
        if re.search(r"rust-toolchain@", uses) and (workflow, job_id) not in TOOLCHAIN_ALLOWED:
            self.report(where, "cred-toolchain", f"installs a Rust toolchain ({uses})")

    def check_composite_use(self, where, action_dir, seen):
        action = self.load(action_dir / "action.yml")
        if not isinstance(action, dict):
            return
        for index, step in enumerate(action.get("runs", {}).get("steps", []) or []):
            step_where = f"{where} -> {action_dir}/action.yml step {index + 1}"
            uses = step.get("uses", "")
            if uses:
                self.check_step_uses(step_where, uses, "", "")
                if uses.startswith("./"):
                    self.check_referenced_files(step_where, uses[2:], seen)
            if "run" in step:
                self.check_shell(step_where, step["run"])
        for path in sorted((self.root / action_dir).iterdir()):
            relative = action_dir / path.name
            if path.is_file() and path.suffix in (".sh", ".py") and relative not in seen:
                seen.add(relative)
                content = path.read_text(errors="replace")
                self.check_shell(f"{where} -> {relative}", content)
                self.check_referenced_files(where, content, seen)

    @staticmethod
    def credentialed(job, workflow_doc):
        if "secrets" in job or "environment" in job:
            return True
        if re.search(r"\bsecrets\.", yaml.safe_dump(job)):
            return True
        permissions = job.get("permissions", workflow_doc.get("permissions"))
        if permissions == "write-all":
            return True
        if isinstance(permissions, dict):
            return permissions.get("id-token") == "write" or permissions.get("contents") == "write"
        return False

    def check_credential_order(self, where, job, steps, action, checks, recheck):
        if "continue-on-error" in job:
            self.report(where, "credential-order", "the job sets continue-on-error")
        for index, step in enumerate(steps):
            if (step.get("uses") or "").split("@")[0] == action:
                break
        else:
            self.report(where, "credential-order", f"no step uses {action}")
            return
        earlier = steps[:index]
        for check in checks:
            if not any(self.runs(step.get("run"), check) for step in earlier):
                self.report(where, "credential-order", f"no step before {action} runs {check}")
        downloads = [i for i, step in enumerate(earlier)
                     if (step.get("uses") or "").startswith("actions/download-artifact@")]
        first = min((i for i, step in enumerate(earlier) if self.runs(step.get("run"), recheck)), default=len(earlier))
        if downloads and not any(self.runs(step.get("run"), CLEAN_CHECK) for step in earlier[downloads[-1] + 1:first]):
            self.report(where, "credential-order", f"no step between the download and {recheck} runs {CLEAN_CHECK}")
        last = max((i for i, step in enumerate(earlier) if self.runs(step.get("run"), recheck)), default=-1)
        if not any(self.runs(step.get("run"), CLEAN_CHECK) for step in earlier[last + 1:]):
            self.report(where, "credential-order", f"no step between {recheck} and {action} runs {CLEAN_CHECK}")
        for step in earlier:
            if self.may_skip(step) and any(self.runs(step.get("run"), check) for check in checks):
                self.report(where, "credential-order",
                            f"guard step {step.get('name', 'without a name')!r} sets if or continue-on-error")
            lines = self.logical_lines(step.get("run"))
            held = [check for check in checks if any(check in line for line in lines)]
            for check in held:
                if any(check in line and SHELL_OPERATOR.search(line) for line in lines):
                    self.report(where, "credential-order",
                                f"guard step {step.get('name', 'without a name')!r} holds {check} on a line with "
                                f"a shell operator")
            if held and any(ERREXIT_OFF.search(line) for line in lines):
                self.report(where, "credential-order",
                            f"guard step {step.get('name', 'without a name')!r} turns off errexit")

    def check_job(self, workflow, workflow_doc, job_id, job):
        self.jobs_checked += 1
        where = f"{workflow}:{job_id}"
        credentialed = self.credentialed(job, workflow_doc)
        dumped = yaml.safe_dump(job)
        environment = job.get("environment")
        if isinstance(environment, dict):
            environment = environment.get("name")
        steps = job.get("steps", []) or []

        if (workflow, job_id) in SIGNING_JOBS:
            if environment != "release-signing":
                self.report(where, "signing-env", "signing job does not declare environment: release-signing")
        else:
            if "release-signing" in dumped:
                self.report(where, "signing-env", "references release-signing")
            if re.search(r"\bsecrets\.APPLE_", dumped):
                self.report(where, "signing-env", "references an APPLE_ secret")

        if "uses" in job and credentialed:
            for key, value in (job.get("with") or {}).items():
                for expression in self.expressions(str(value)):
                    if re.search(r"\bneeds\.", expression) \
                            and REUSABLE_NEEDS_ALLOWED.get((workflow, job_id, key)) != expression:
                        self.report(where, "cred-with-needs",
                                    f"passes ${{{{ {expression} }}}} to the reusable workflow input {key}")

        if credentialed:
            for scope, env in (("workflow", workflow_doc.get("env")), ("job", job.get("env"))):
                for key, value in (env or {}).items():
                    if self.reads(value, r"\b(needs|inputs)\."):
                        self.report(where, "cred-env-validation", f"{scope} env {key} reads {value}")

        seen = set()
        tag_checkouts = 0
        ancestry_calls = []
        for index, step in enumerate(steps):
            step_where = f"{where} step {index + 1}" + (f" ({step['name']})" if "name" in step else "")
            uses = step.get("uses", "") or ""
            with_ = step.get("with") or {}
            run = step.get("run")

            if uses.startswith("actions/checkout@"):
                if with_.get("persist-credentials") not in (False, "false"):
                    self.report(step_where, "checkout-credentials", "actions/checkout without persist-credentials: false")
                if workflow == "publish.yml":
                    ref = str(with_.get("ref", ""))
                    if ref.startswith("refs/tags/"):
                        tag_checkouts += 1
                    elif not WORKFLOW_SHA_REF.match(ref):
                        self.report(step_where, "publish-tag-ref", f"checkout ref {ref!r} is neither refs/tags/... nor github.workflow_sha")

            if run is not None:
                for expression in self.expressions(run):
                    if re.search(r"\binputs\.", expression):
                        self.report(step_where, "run-inputs", f"run: reads ${{{{ {expression} }}}}")
                    if credentialed and re.search(r"\b(needs|steps)\.", expression):
                        self.report(step_where, "cred-run-outputs", f"run: reads ${{{{ {expression} }}}}")
                if any(ANCESTRY_CALL.match(line) for line in self.logical_lines(run)):
                    ancestry_calls.append((step_where, step))

            if not credentialed:
                continue
            for key, value in (step.get("env") or {}).items():
                if self.reads(value, r"\b(needs|inputs)\.") and not self.runs(run, "=~"):
                    self.report(step_where, "cred-env-validation", f"env {key} reads {value} with no =~ test in this step")
            if uses:
                self.check_step_uses(step_where, uses, workflow, job_id)
                if uses.startswith("./"):
                    self.check_referenced_files(step_where, uses[2:], seen)
            for key, value in with_.items():
                if self.reads(value, r"\bneeds\."):
                    self.report(step_where, "cred-with-needs", f"passes needs output to with: {key}")
            if uses.startswith("actions/download-artifact@"):
                path = str(with_.get("path", ""))
                if not RUNNER_TEMP_PATH.match(path) or ".." in path.split("/"):
                    self.report(step_where, "cred-download-path", f"downloads to {path or 'the workspace'}")
                name = with_.get("name")
                pattern = with_.get("pattern")
                if name == "verify-crates" or (pattern and fnmatch.fnmatchcase("verify-crates", str(pattern))) \
                        or (name is None and pattern is None):
                    self.report(step_where, "verify-crates-download", "can download verify-crates")
            if run is not None:
                self.check_shell(step_where, run)
                self.check_referenced_files(step_where, run, seen)

        if (workflow, job_id) in CREDENTIAL_GUARDS:
            self.check_credential_order(where, job, steps, *CREDENTIAL_GUARDS[(workflow, job_id)])
        if workflow == "publish.yml" and tag_checkouts == 0:
            self.report(where, "publish-tag-ref", "no checkout of refs/tags/...")
        if (workflow, job_id) in ANCESTRY_JOBS:
            if not ancestry_calls:
                self.report(where, "ancestry-check", "no line runs check-ref-on-main.sh as its command")
            if "continue-on-error" in job:
                self.report(where, "ancestry-check", "the job sets continue-on-error")
            for step_where, step in ancestry_calls:
                if self.may_skip(step):
                    self.report(step_where, "ancestry-check", "the ancestry step sets if or continue-on-error")
                if workflow == "publish.yml" and re.search(r"GITHUB_SHA|github\.sha", step["run"]):
                    self.report(step_where, "ancestry-check", "passes the dispatch commit, not the tag's HEAD")

    def check_workflow(self, workflow):
        doc = self.load(pathlib.PurePosixPath(".github/workflows") / workflow)
        if not isinstance(doc, dict):
            return
        if "permissions" not in doc:
            self.report(workflow, "workflow-permissions", "no top-level permissions")
        jobs = doc.get("jobs") or {}
        for wanted_workflow, wanted_job in ANCESTRY_JOBS | SIGNING_JOBS | set(CREDENTIAL_GUARDS):
            if wanted_workflow == workflow and wanted_job not in jobs:
                self.report(workflow, "missing-job", f"job {wanted_job} not found")
        for job_id, job in jobs.items():
            self.check_job(workflow, doc, job_id, job)

    def check_composite_expressions(self):
        relative = COMPOSITE / "action.yml"
        action = self.load(relative)
        if not isinstance(action, dict):
            return
        for index, step in enumerate(action.get("runs", {}).get("steps", []) or []):
            for expression in self.expressions(step.get("run", "")):
                if expression != "github.action_path":
                    self.report(f"{relative} step {index + 1}", "composite-expression",
                                f"run: holds ${{{{ {expression} }}}}")

    def run(self):
        for workflow in WORKFLOWS:
            self.check_workflow(workflow)
        self.check_composite_expressions()
        return self.violations


def main(argv):
    if len(argv) > 2:
        print(f"usage: {argv[0]} [repository-root]", file=sys.stderr)
        return 2
    root = pathlib.Path(argv[1]) if len(argv) == 2 else pathlib.Path.cwd()
    checker = Checker(root)
    violations = checker.run()
    if violations:
        for violation in violations:
            print(violation, file=sys.stderr)
        print(f"{len(violations)} workflow invariant violation(s)", file=sys.stderr)
        return 1
    print(f"workflow invariants hold ({checker.jobs_checked} jobs checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
