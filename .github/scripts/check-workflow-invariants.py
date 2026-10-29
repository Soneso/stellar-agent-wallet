#!/usr/bin/env python3
"""Structural check of the release, publish, notarization, maintenance,
coverage, and rehearsal workflows.

Usage: ``check-workflow-invariants.py [repository-root]``

Reads ``release.yml``, ``publish.yml``, ``notarize-smoke.yml``, ``labels.yml``,
``stale.yml``, ``triage.yml``, ``triage-review.yml``, ``triage-sweep.yml``,
``welcome.yml``, ``coverage.yml``, ``release-rehearsal.yml``, ``ci.yml``,
and ``vendored-wasm.yml``
under ``.github/workflows/``.
Also reads the composite action
``.github/actions/macos-sign-notarize/action.yml``, the shared build script
``.github/scripts/release/build.sh``, and the host recipe
``.github/scripts/release/check-host.sh``. Needs PyYAML.

A job is credentialed when it references ``secrets.``, passes secrets to a
reusable workflow, declares ``environment:``, or holds ``id-token: write``,
``contents: write``, or ``write-all`` (its own permissions, else the
workflow's). Shell text is read line by line, with continuation lines joined
and comment lines skipped. The check fails when any of these holds:

- ``unreadable``: a workflow or the composite action is missing or is not
  valid YAML.
- ``missing-job``: a job that a release, publish, or notarization rule below
  names does not exist.
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
- ``coverage-trigger``: ``coverage.yml`` has no ``pull_request`` trigger, a
  ``paths`` or ``paths-ignore`` filter, no ``types`` list, or a list missing
  an event in ``COVERAGE_EVENTS``. The rule reports every missing event.
- ``coverage-condition``: ``coverage.yml`` has no ``coverage`` job, or that
  job's ``if`` is not a string equal to ``COVERAGE_CONDITION`` after the check
  strips the surrounding whitespace and one enclosing ``${{ }}``.
- ``rehearsal-credentials``: ``release-rehearsal.yml`` holds a credential. A
  job is credentialed as above. The workflow permissions, or a job's own
  permissions or the workflow's when it sets none, are anything but exactly
  ``contents: read``. An expression reads the ``secrets`` context, the
  workflow token ``github.token``, or the ``github`` context other than by a
  named property. The expressions are the ``${{ }}`` parts of every key and
  value and the whole value of every ``if`` key, read without regard to case.
  An unterminated expression or quoted string is refused, and so is a parsed
  value other than a mapping, list, string, number, boolean, date or null.
  A double quote outside a single-quoted string is refused as well, because
  GitHub rejects one in an expression.

A command below runs unconditionally when a logical line of a step equals
it, outside any compound command and after no line that exits, returns, or
turns off errexit, in a step whose shell is bash with errexit. No comment,
prefix, operator, substitution, or variable can then skip the command or
discard its status. In a step that names the command, a line before the
call that leaves a quote, a substitution, a subshell, or a group open, that
opens a heredoc, that ends in &&, ||, | or |& and so makes the next line
conditional or piped, or that holds the command inside a longer line, is
reported as unmodelled shell syntax under the rule that looks for the
command. A function defined earlier in the step that shadows the counted
command, as bash() { return 0; } does, makes the check count a call that
runs the function.

- ``release-shared-scripts``: a build job of ``release.yml`` or
  ``release-rehearsal.yml`` does not call the shared Perl, sodium, and build
  scripts once each, or ``build.sh`` does not run the environment guard on
  its own checkout as its first command.
- ``release-guard-order``: the build does not immediately follow the Perl
  and sodium setup steps, so a command could follow their environment writes
  unguarded.
- ``release-packaged-gate``: ``hashes`` does not need ``verify-packaged``,
  ``verify-packaged`` does not need ``preflight``, ``build``, and
  ``sign-macos``, or a ``verify-packaged`` job of ``release.yml`` or
  ``release-rehearsal.yml`` does not run ``ARCHIVE_CHECK`` unconditionally.
- ``release-provenance-gate``: ``publish`` does not need
  ``verify-provenance``, ``verify-provenance`` does not need ``preflight``,
  ``provenance``, and ``hashes``, or it does not run each command of
  ``PROVENANCE_CHECKS`` unconditionally.
- ``publish-dry-gate``: the ``publish.yml`` publish job does not need
  ``verify``, or in ``verify`` and the rehearsal's ``verify-crates`` the
  packaging step does not create the start timestamp before it packages,
  unconditionally, or the next step does not run the packaged marker check.
- ``publish-install-gate``: ``verify-install`` does not need ``publish``, or
  does not run the install check of the dispatched commit unconditionally.
- ``release-check-unconditional``: a job of ``GUARDED_JOBS`` or one of its
  steps sets ``if`` or ``continue-on-error``, or a step turns off errexit or
  ends a line with ``|| true``, ``|| :``, or ``|| exit 0``. The publish
  dispatch's verify_only condition and the Rosetta step's target condition
  are the only exceptions.
- ``verification-credentials``: a job of ``VERIFY_JOBS`` is credentialed as
  above, has permissions other than exactly ``contents: read``, receives
  ``GH_TOKEN`` or ``GITHUB_TOKEN`` from the workflow, job, or step
  ``env``, or holds or inherits from the workflow ``env`` or ``defaults``
  an expression that reads the ``secrets`` context, the workflow token, or
  the ``github`` context other than by a named property, read as for
  ``rehearsal-credentials``, which covers the rehearsal's inherited level.
- ``release-verify-matrix``: a ``verify-packaged`` matrix of ``release.yml``
  or ``release-rehearsal.yml`` differs from ``VERIFY_RUNNERS``, the job does
  not run on ``${{ matrix.os }}``, the archive check does not take
  ``TARGET`` from ``${{ matrix.target }}``, or the job's first step is not
  the Rosetta check of the Intel macOS target.
- ``release-cache``: a job of ``release.yml`` or ``release-rehearsal.yml``
  uses ``Swatinem/rust-cache``, ``actions/cache``, or a sub-action of either,
  in any letter case, or passes a ``cache`` input to an ``actions/setup-*``
  action.
- ``release-wasm-gate``: the release lacks an unconditional local
  ``vendored-wasm`` workflow call without inputs or secrets, or ``hashes``
  or ``publish`` does not need it, so signing, provenance, and publication
  wait for the rebuild. The called workflow must declare ``workflow_call``.
  Its cache guards must lead with ``github.ref_type != 'tag'``; its rebuild
  must read both stellar-cli artifacts of its own run and use no cache. No
  job or step of it sets ``continue-on-error``, and no step of ``check``,
  ``rebuild``, or ``vendored-wasm`` suppresses a failure as for
  ``release-check-unconditional``. ``rebuild`` runs exactly on
  ``needs.check.outputs.rebuild == 'true'`` and its full-mode step
  unconditionally. The ``vendored-wasm`` job runs on ``always()``, needs
  exactly ``WASM_GATE_NEEDS``, and has one unconditional gate step that runs
  ``WASM_GATE_CALL`` with ``WASM_GATE_ENV``.
- ``release-publish-sums``: ``publish`` does not run the archive checksum
  check unconditionally before the GitHub Release action.
- ``release-toolchain``: ``RELEASE_TOOLCHAIN`` of ``release.yml`` or
  ``release-rehearsal.yml`` differs from that of ``publish.yml``, or either
  build job or the rehearsal's ``verify-crates`` does not install it and pin
  ``RUSTUP_TOOLCHAIN`` between the install and the build or packaging.
- ``ci-feature-jobs``: a job of ``CI_FEATURE_JOBS`` is missing, it or one of
  its steps sets ``if`` or ``continue-on-error``, or it does not run each of
  its commands unconditionally; or ``check-host.sh`` does not run each
  command of ``HOST_CHECKS`` unconditionally.
"""

import fnmatch
import pathlib
import re
import sys
from datetime import date

try:
    import yaml
except ImportError:
    sys.exit("check-workflow-invariants.py needs PyYAML (pip install PyYAML)")

WORKFLOWS = ("release.yml", "publish.yml", "notarize-smoke.yml", "labels.yml", "stale.yml", "triage.yml",
             "triage-review.yml", "triage-sweep.yml", "welcome.yml", "coverage.yml", "release-rehearsal.yml",
             "ci.yml", "vendored-wasm.yml")
# GitHub resolves action names in any letter case.
CACHE_ACTION = re.compile(r"(Swatinem/rust-cache|actions/cache)(/[\w.-]+)*@", re.IGNORECASE)
SETUP_ACTION = re.compile(r"actions/setup-[\w.-]+@", re.IGNORECASE)
# The jobs of vendored-wasm.yml whose results the gate job reads, the gate
# command, and the environment it reads them from. A tag run passes the gate
# only after a rebuild, so the release's dependents wait for one.
WASM_GATE_NEEDS = ["check", "rebuild", "stellar-cli-25", "stellar-cli-28"]
WASM_GATE_CALL = ('bash .github/scripts/rebuild-vendored-wasm.sh --gate "$CHECK" "$REBUILD" "$CLI25" "$CLI28" '
                  '"$REBUILD_JOB" "$REF_TYPE"')
WASM_GATE_ENV = {
    "CHECK": "${{ needs.check.result }}",
    "REBUILD": "${{ needs.check.outputs.rebuild }}",
    "CLI25": "${{ needs.stellar-cli-25.result }}",
    "CLI28": "${{ needs.stellar-cli-28.result }}",
    "REBUILD_JOB": "${{ needs.rebuild.result }}",
    "REF_TYPE": "${{ github.ref_type }}",
}
WASM_REBUILD_CONDITION = "needs.check.outputs.rebuild == 'true'"
WASM_FULL_MODE = "rebuild-vendored-wasm.sh --repo-root"
# Inputs that make actions/download-artifact read another run or repository.
FOREIGN_ARTIFACT_INPUTS = ("run-id", "github-token", "repository")
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
# Branch protection requires the `coverage` check. GitHub leaves a required
# check pending when a paths filter skips its workflow, so the coverage
# workflow runs on every pull request and its job condition decides whether a
# run measures. A run starts on every new head, and on every label change made
# by a person or with an app token.
COVERAGE_WORKFLOW = "coverage.yml"
COVERAGE_EVENTS = ("opened", "synchronize", "reopened", "labeled", "unlabeled")
# The coverage job measures on the schedule, on a dispatch, and on a pull
# request whose labels include `coverage`.
COVERAGE_CONDITION = ("github.event_name != 'pull_request' || "
                      "contains(github.event.pull_request.labels.*.name, 'coverage')")
# The release rehearsal builds the release targets of any branch on a
# dispatch. Its token reads the repository contents and nothing else, and no
# expression of the workflow reads a secret or the workflow token.
REHEARSAL_WORKFLOW = "release-rehearsal.yml"
REHEARSAL_PERMISSIONS = {"contents": "read"}
# Shared release build and platform setup scripts.
RELEASE_SCRIPTS = pathlib.PurePosixPath(".github/scripts/release")
BUILD_SCRIPT = RELEASE_SCRIPTS / "build.sh"
HOST_SCRIPT = RELEASE_SCRIPTS / "check-host.sh"
# The Perl and sodium setup calls and the build call that follows them.
BUILD_CALLS = ("./.github/scripts/release/windows-perl.ps1",
               "bash .github/scripts/release/sodium.sh",
               'bash .github/scripts/release/build.sh "$TARGET"')
BUILD_GUARD = ('python3 "$(dirname "${BASH_SOURCE[0]}")/../check-feature-discipline.py" '
               '--env-guard "$(dirname "${BASH_SOURCE[0]}")/../../.."')
# The release targets and the runner that executes each one's archive: the
# Intel macOS archive runs under Rosetta 2 on the Apple silicon runner.
VERIFY_RUNNERS = {
    "x86_64-unknown-linux-gnu": "ubuntu-24.04",
    "aarch64-unknown-linux-gnu": "ubuntu-24.04-arm",
    "x86_64-apple-darwin": "macos-26",
    "aarch64-apple-darwin": "macos-26",
    "x86_64-pc-windows-msvc": "windows-2025",
}
ROSETTA = {"run": "arch -x86_64 /usr/bin/true", "if": "matrix.target == 'x86_64-apple-darwin'"}
ARCHIVE_CHECK = ('bash .github/scripts/release/verify-archive.sh archives "$VERSION" "$TARGET" '
                 '"$EXPECTED_MAINNET_WRITE"')
PROVENANCE_CHECKS = (
    'python3 .github/scripts/check-provenance.py "provenance/stellar-agent-$VERSION.intoto.jsonl" '
    'provenance/SHA256SUMS "$GITHUB_SHA" "$GITHUB_REPOSITORY" "$GITHUB_REF"',
    "cargo fetch --locked",
    '"$RUNNER_TEMP/feature-check/bin/python" .github/scripts/check-feature-discipline.py')
PACKAGE_START = "touch target/package-verification-start"
PACKAGE_BUILD = "cargo package --workspace --locked"
PACKAGE_CHECKS = {
    "publish.yml": ('bash "$GITHUB_WORKSPACE/wf/.github/scripts/check-packaged-markers.sh" target '
                    'target/package-verification-start "$EXPECTED_MAINNET_WRITE"'),
    "release-rehearsal.yml": ('bash .github/scripts/check-packaged-markers.sh target '
                              'target/package-verification-start "$EXPECTED_MAINNET_WRITE"'),
}
INSTALL_CHECK = ('bash "$GITHUB_WORKSPACE/wf/.github/scripts/release/verify-install.sh" "$TAG" '
                 '"$EXPECTED_MAINNET_WRITE"')
TOOLCHAIN_PIN = 'echo "RUSTUP_TOOLCHAIN=$RELEASE_TOOLCHAIN" >> "$GITHUB_ENV"'
# The release checks, which no condition may skip and no command may ignore.
GUARDED_JOBS = {"release.yml": ("verify-packaged", "verify-provenance", "hashes", "publish"),
                "publish.yml": ("verify", "publish", "verify-install"),
                "release-rehearsal.yml": ("verify-packaged", "verify-crates")}
# The verification jobs, which hold no credential.
VERIFY_JOBS = (("release.yml", "verify-packaged"), ("release.yml", "verify-provenance"),
               ("publish.yml", "verify"), ("publish.yml", "verify-install"),
               ("release-rehearsal.yml", "verify-packaged"), ("release-rehearsal.yml", "verify-crates"))
TOKEN_ENV = {"GH_TOKEN", "GITHUB_TOKEN"}
# The feature jobs of ci.yml and the commands that define each of them.
CI_FEATURE_JOBS = {
    "feature-on-clippy": (
        'cargo clippy --workspace --all-targets --features "mainnet-write,$FEATURES_EXCEPT_MAINNET_WRITE" '
        '-- -D warnings',),
    "feature-on-doc": ('cargo doc --workspace --no-deps --features "mainnet-write,$FEATURES_EXCEPT_MAINNET_WRITE"',),
    "feature-on-test": (
        "cargo test --workspace --features mainnet-write,test-helpers,test-hooks,test-loopback,verifier-registry",
        "cargo check -p stellar-agent-network --features mainnet-write"),
    "feature-discipline": (
        "cargo fetch --locked",
        '"$RUNNER_TEMP/feature-check/bin/python" .github/scripts/check-feature-discipline.py',
        '"$RUNNER_TEMP/feature-check/bin/python" .github/scripts/test-check-feature-discipline.py --mutations',
        "bash .github/scripts/test-check-binary-marker.sh",
        "bash .github/scripts/test-release-checks.sh",
        '"$RUNNER_TEMP/feature-check/bin/python" .github/scripts/test-check-provenance.py'),
    "release-shape": ("bash .github/scripts/release/check-host.sh",),
}
# The host recipe: the release build for the host target and the marker
# check of both binaries.
HOST_CHECKS = ('bash .github/scripts/release/build.sh "$target"',
               'bash .github/scripts/check-binary-marker.sh "target/$target/release/stellar-agent" off',
               'bash .github/scripts/check-binary-marker.sh "target/$target/release/stellar-agent-mcp" off')
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

RUNNER_TEMP_PATH = re.compile(r"^\$\{\{\s*runner\.temp\s*\}\}(/|$)")
WORKFLOW_SHA_REF = re.compile(r"^\$\{\{\s*github\.workflow_sha\s*\}\}$")
SCRIPT_REF = re.compile(r"\.github/(?:scripts|actions)/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")
# A command word: the name alone or as the last component of a path, with an
# optional closing quote. The name inside another word, as in .cargo/bin,
# does not match.
COMMAND_WORD = r"(?<![\w.-]){}[\"']?"
# A cargo call up to its subcommand. Matching stops there, so every later
# cargo call on the same line is found as well.
CARGO_CALL = re.compile(COMMAND_WORD.format("cargo") + r"(?:[ \t]+\+[^ \t]+)?[ \t]+([^ \t;&|)`]+)")
CROSS_CALL = re.compile(COMMAND_WORD.format("cross") + r"(?:[ \t]+\+[^ \t]+)?[ \t]+[a-z]")
# Where the arguments of one command end: a shell operator, the end of a
# command substitution or subshell, or a comment.
ARGUMENTS_END = re.compile(r"[;&|)`]|(?<![^ \t])#")
ALLOWED_CARGO = {"metadata", "-V", "--version"}
NO_VERIFY_CARGO = {"package", "publish"}
# A shell operator on a line that holds a check, which could chain the check,
# skip it, or discard its result.
SHELL_OPERATOR = re.compile(r"[;&|]")
# The blanks that separate shell words.
BLANKS = " \t"
# The set builtin turning off errexit.
ERREXIT_OFF = re.compile(r"(?<![\w-])set[ \t]+(?:\+\w*e|\+o[ \t]+errexit\b)")
# The ancestry script as the command of a line. Its path is the first word
# with or without quotes and holds only directory names and variables. No
# shell operator after it can chain or discard its result.
ANCESTRY_CALL = re.compile(
    r"""^[ \t]*["']?(?:\$\{?[A-Za-z_]\w*\}?/|[\w.-]+/)*"""
    r"""\.github/scripts/check-ref-on-main\.sh["']?(?:[ \t][^;&|]*)?$""")
# A line that ends a check with an operator whose right side succeeds.
SUPPRESSION = re.compile(r"\|\|[ \t]*(?:true\b|:(?=[ \t;]|$)|exit[ \t]+0\b)")
# The runner and target expressions of a verification matrix leg.
MATRIX_RUNNER = re.compile(r"^\$\{\{\s*matrix\.os\s*\}\}$")
MATRIX_TARGET = re.compile(r"^\$\{\{\s*matrix\.target\s*\}\}$")
# The words that open and close a shell compound command, and the end of a
# line that closes the compound command it opens.
COMPOUND_OPEN = {"if", "case", "while", "until", "for", "select", "{"}
COMPOUND_CLOSE = {"fi", "esac", "done", "}"}
COMPOUND_END = re.compile(r"(?:^|[; \t])(?:fi|esac|done|\})$")
# A string literal of the expression syntax, whose text names no context.
EXPRESSION_STRING = re.compile(r"'(?:[^']|'')*'")
# A context name where a property chain starts. Expressions ignore case.
SECRETS_CONTEXT = re.compile(r"(?<![\w.-])secrets(?![\w-])", re.IGNORECASE)
GITHUB_CONTEXT = re.compile(r"(?<![\w.-])github(?![\w-])", re.IGNORECASE)
NAMED_PROPERTY = re.compile(r"\s*\.\s*([A-Za-z_][\w-]*)")


class Checker:
    def __init__(self, root):
        self.root = root
        self.violations = []
        self.jobs_checked = 0
        self.docs = {}
        self.unmodelled = set()

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
    def expressions(text, require_closed=False):
        """Returns the expressions of text.

        Each ends at the first ``}}`` outside a single-quoted string.
        GitHub rejects a double quote outside a single-quoted string. The
        rehearsal check refuses one through require_closed, so the boundary
        and the masking handle single-quoted strings only.

        Doubled single quotes belong to their string. With require_closed,
        a double quote outside a single-quoted string, an unfinished
        expression, and an unfinished string each raise ValueError.
        """
        text = "" if text is None else str(text)
        expressions = []
        position = 0
        while (start := text.find("${{", position)) != -1:
            position = start + 3
            quote = None
            while position < len(text):
                character = text[position]
                if quote is not None:
                    if character == quote:
                        quote = None
                elif character == "'":
                    quote = character
                elif character == '"' and require_closed:
                    raise ValueError("double quote outside a single-quoted string in expression")
                elif text.startswith("}}", position):
                    expressions.append(" ".join(text[start + 3:position].split()))
                    position += 2
                    break
                position += 1
            else:
                if require_closed:
                    raise ValueError("unterminated string in expression" if quote else "unterminated expression")
                break
        return expressions

    @staticmethod
    def reads(value, pattern):
        return any(re.search(pattern, e) for e in Checker.expressions(str(value)))

    @staticmethod
    def run_text(step):
        """The text of a step's run: value; YAML can parse one as another
        scalar type."""
        return "" if step.get("run") is None else str(step["run"])

    @staticmethod
    def logical_lines(text):
        joined = re.sub(r"\\\n", " ", "" if text is None else str(text))
        return [line for line in joined.split("\n") if not line.lstrip(BLANKS).startswith("#")]

    def runs(self, run, text):
        """Whether a run: block holds text on a line that is not a comment."""
        return run is not None and any(text in line for line in self.logical_lines(run))

    @staticmethod
    def unwrap_expression(value):
        """A condition's text without surrounding blanks and one enclosing ${{ }}."""
        text = str(value).strip()
        if text.startswith("${{") and text.endswith("}}"):
            text = text[3:-2].strip()
        return text

    def suppresses(self, step):
        """Whether a step's run: block turns off errexit or ends a line with
        an operator whose right side succeeds."""
        run = self.run_text(step)
        return bool(ERREXIT_OFF.search(run)) or any(SUPPRESSION.search(line) for line in self.logical_lines(run))

    @staticmethod
    def may_skip(step):
        """Whether the runner can skip a step, or the step can fail without failing its job."""
        return "if" in step or "continue-on-error" in step

    def check_shell(self, where, text):
        for line in self.logical_lines(text):
            if CROSS_CALL.search(line):
                self.report(where, "cred-compile", f"runs cross: {line.strip(BLANKS)}")
            for match in CARGO_CALL.finditer(line):
                sub = match.group(1).strip("\"'")
                arguments = ARGUMENTS_END.split(line[match.end():], maxsplit=1)[0]
                call = f"cargo {sub}{arguments}".strip(BLANKS)
                if sub in ALLOWED_CARGO:
                    continue
                if sub in NO_VERIFY_CARGO:
                    if "--no-verify" not in re.split(r"[ \t]+", arguments):
                        self.report(where, "cred-compile", f"cargo {sub} without --no-verify: {call}")
                    continue
                self.report(where, "cred-compile", f"runs cargo {sub}: {call}")

    def check_referenced_files(self, where, text, seen):
        for ref in SCRIPT_REF.findall("" if text is None else str(text)):
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
        if CACHE_ACTION.match(uses):
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
    def credential_reasons(job, workflow_doc):
        """Returns why a job is credentialed, one phrase per reason,
        or no phrase.
        """
        reasons = []
        if "secrets" in job:
            reasons.append("passes secrets")
        if "environment" in job:
            reasons.append("declares an environment")
        if re.search(r"\bsecrets\.", yaml.safe_dump(job)):
            reasons.append("references secrets.")
        permissions = job.get("permissions", workflow_doc.get("permissions"))
        if permissions == "write-all":
            reasons.append("holds write-all")
        if isinstance(permissions, dict):
            for scope in ("id-token", "contents"):
                if permissions.get(scope) == "write":
                    reasons.append(f"holds {scope}: write")
        return reasons

    @staticmethod
    def credentialed(job, workflow_doc):
        return bool(Checker.credential_reasons(job, workflow_doc))

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

    def check_coverage_trigger(self, workflow, doc):
        # PyYAML reads the key `on` as the boolean True. The shorthand forms
        # `on: pull_request` and `on: [pull_request, ...]`, and a null
        # `pull_request:` entry, name the event with an empty configuration.
        triggers = doc.get("on", doc.get(True))
        if isinstance(triggers, dict) and "pull_request" in triggers:
            trigger = triggers["pull_request"]
        elif triggers == "pull_request" or (isinstance(triggers, list) and "pull_request" in triggers):
            trigger = None
        else:
            self.report(workflow, "coverage-trigger", "pull_request trigger is absent")
            return
        if not isinstance(trigger, dict):
            trigger = {}
        if "paths" in trigger:
            self.report(workflow, "coverage-trigger", "pull_request trigger has a paths filter")
        if "paths-ignore" in trigger:
            self.report(workflow, "coverage-trigger", "pull_request trigger has a paths-ignore filter")
        types = trigger.get("types")
        if not isinstance(types, list):
            self.report(workflow, "coverage-trigger", "pull_request types are absent")
            return
        for event in COVERAGE_EVENTS:
            if event not in types:
                self.report(workflow, "coverage-trigger", f"pull_request types lack {event}")

    def check_coverage_condition(self, workflow, jobs):
        if "coverage" not in jobs:
            self.report(workflow, "coverage-condition", "job coverage not found")
            return
        job = jobs["coverage"]
        condition = job.get("if") if isinstance(job, dict) else None
        if isinstance(condition, str):
            condition = self.unwrap_expression(condition)
        if condition != COVERAGE_CONDITION:
            self.report(workflow, "coverage-condition", "coverage job runs without the label condition")

    @staticmethod
    def describe_permissions(permissions):
        if permissions is None:
            return "unset"
        if isinstance(permissions, dict):
            return ", ".join(f"{scope}: {level}" for scope, level in
                             sorted(permissions.items(), key=lambda item: str(item[0]))) or "{}"
        return str(permissions)

    @staticmethod
    def expression_values(node, key=None):
        """Yields the expressions of a parsed workflow node.

        These are the ${{ }} parts of each string, and the whole value of an
        if key, which GitHub evaluates as an expression without the braces.
        Every key is scanned for credential expressions whether or not
        GitHub evaluates it. An unterminated expression or quoted string is
        refused, and so is a parsed value other than a mapping, list, string,
        number, boolean, date or null.
        A double quote outside a single-quoted string is refused as well,
        because GitHub rejects one in an expression.
        """
        if isinstance(node, dict):
            for child_key, child in node.items():
                if isinstance(child_key, str):
                    yield from Checker.expressions(child_key, require_closed=True)
                yield from Checker.expression_values(child, child_key)
        elif isinstance(node, list):
            for child in node:
                yield from Checker.expression_values(child)
        elif isinstance(node, str):
            if key == "if" and not node.lstrip().startswith("${{"):
                node = "${{" + node + "}}"
            yield from Checker.expressions(node, require_closed=True)
        elif node is not None and not isinstance(node, (int, float, date)):
            raise ValueError(f"unsupported workflow node type: {type(node).__name__}")

    def check_credential_expressions(self, where, node, rule):
        try:
            expressions = list(self.expression_values(node))
        except ValueError as err:
            self.report(where, rule, str(err))
            return
        for expression in expressions:
            text = EXPRESSION_STRING.sub("''", expression)
            if SECRETS_CONTEXT.search(text):
                self.report(where, rule, f"an expression reads secrets: {expression}")
            for context in GITHUB_CONTEXT.finditer(text):
                name = NAMED_PROPERTY.match(text, context.end())
                if name is None:
                    self.report(where, rule,
                                f"an expression reads the github context other than by a named property: {expression}")
                elif name.group(1).lower() == "token":
                    self.report(where, rule, f"an expression reads the workflow token: {expression}")

    def check_rehearsal_credentials(self, workflow, doc, jobs):
        workflow_permissions = doc.get("permissions")
        if workflow_permissions != REHEARSAL_PERMISSIONS:
            self.report(workflow, "rehearsal-credentials",
                        f"workflow permissions are {self.describe_permissions(workflow_permissions)}, "
                        "expected exactly contents: read")
        for key, value in doc.items():
            if key != "jobs":
                self.check_credential_expressions(workflow, {key: value}, "rehearsal-credentials")
        for job_id, job in jobs.items():
            where = f"{workflow}:{job_id}"
            if not isinstance(job, dict):
                continue
            for reason in self.credential_reasons(job, doc):
                self.report(where, "rehearsal-credentials", f"the job {reason}")
            permissions = job.get("permissions", workflow_permissions)
            if permissions != REHEARSAL_PERMISSIONS:
                self.report(where, "rehearsal-credentials",
                            f"effective permissions are {self.describe_permissions(permissions)}, "
                            "expected exactly contents: read")
            self.check_credential_expressions(where, {job_id: job}, "rehearsal-credentials")

    def read_script(self, relative, rule):
        try:
            return (self.root / relative).read_text(errors="replace")
        except OSError as err:
            self.report(str(relative), rule, f"cannot be read: {err}")
            return None

    def job(self, workflow, name):
        return (self.docs.get(workflow, {}).get("jobs") or {}).get(name)

    @staticmethod
    def line_syntax(line):
        """Returns whether a line holds syntax the check does not model: an
        open quote, substitution, subshell or group, a heredoc operator
        outside quotes, or a closing &&, ||, | or |& that makes the next
        line conditional or piped."""
        quote, depth, backtick, group, heredoc, i = None, 0, False, 0, False, 0
        while i < len(line):
            char = line[i]
            if char == "\\" and quote != "'":
                i += 2
                continue
            if quote == "'":
                quote = None if char == "'" else quote
            elif line.startswith("$(", i):
                depth += 1
                i += 1
            elif char == "`":
                backtick = not backtick
            elif quote == '"':
                if char == '"':
                    quote = None
                elif char == ")" and depth:
                    depth -= 1
            elif char in "'\"":
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif char in "{}" and (i == 0 or line[i - 1] in " \t;&|") and line[i + 1:i + 2] in ("", " ", ";"):
                group += 1 if char == "{" else -1
            elif line.startswith("<<<", i):
                i += 3
                continue
            elif line.startswith("<<", i):
                heredoc = True
            i += 1
        joins = line.endswith(("&&", "||", "|", "|&"))
        return bool(quote or depth or backtick or group or heredoc or joins)

    def runs_line(self, run, command):
        """Returns (position, problem) for command in a run: block.

        position is the index of the logical line that runs command
        unconditionally, else -1. The line must equal command after each
        run of spaces and tabs is collapsed to one space, so no comment,
        prefix, operator, substitution or variable can skip it or discard
        its status, and no other character counts as a blank. A line
        inside a compound command, or after a line that exits, returns or
        turns off errexit, does not count. When the block names command, a
        line before the call whose syntax the check does not model fails
        closed: problem names the line that leaves a quote, a substitution,
        a subshell or a group open, opens a heredoc, ends in an operator
        that joins it to the next line, or holds command inside a longer
        line, so a heredoc in such a block is refused. Otherwise
        problem is None. Whether the block names command is read from the
        same joined logical lines that the match reads.
        """
        text = "" if run is None else str(run)
        lines = [" ".join(re.split(r"[ \t]+", line.strip(BLANKS))) for line in self.logical_lines(text)]
        names, depth = any(command in line for line in lines), 0
        for position, line in enumerate(lines):
            if not line:
                continue
            if line == command:
                return (position if depth == 0 else -1), None
            if names and (self.line_syntax(line) or command in line):
                return -1, f"logical line {position + 1}: {line}"
            word = line.split(" ")[0]
            if ERREXIT_OFF.search(line) or (word in ("exit", "return") and depth == 0):
                return -1, None
            if word in COMPOUND_OPEN or line.endswith("{"):
                if not COMPOUND_END.search(line):
                    depth += 1
            elif word in COMPOUND_CLOSE:
                depth -= 1
        return -1, None

    def step_position(self, workflow, name, index, step, command, rule):
        """Returns where step index of a job runs command unconditionally
        under errexit, or -1, and reports syntax the check does not model."""
        job = self.job(workflow, name) or {}
        defaults = [((owner.get("defaults") or {}).get("run") or {}).get("shell")
                    for owner in (job, self.docs[workflow])]
        shell = step.get("shell") or defaults[0] or defaults[1]
        position, problem = self.runs_line(step.get("run"), command)
        where = f"{workflow}:{name} step {index + 1}"
        if problem and (where, problem) not in self.unmodelled:
            self.unmodelled.add((where, problem))
            self.report(where, rule, f"unmodelled shell syntax around {command}: {problem}")
        return position if shell in (None, "bash") else -1

    def runs_in_job(self, workflow, name, command, rule):
        """Returns the index of the first step of a job that runs command
        unconditionally, or -1."""
        for index, step in enumerate((self.job(workflow, name) or {}).get("steps", [])):
            if self.step_position(workflow, name, index, step, command, rule) >= 0:
                return index
        return -1

    def needs(self, workflow, name, dependency, rule):
        values = (self.job(workflow, name) or {}).get("needs", [])
        values = [values] if isinstance(values, str) else values
        if dependency not in values:
            self.report(workflow, rule, f"{name} must need {dependency}")

    def check_shared_build(self):
        for workflow in ("release.yml", "release-rehearsal.yml"):
            job = self.job(workflow, "build") or {}
            steps = job.get("steps", [])
            calls = [self.run_text(step).strip(BLANKS + "\n") for step in steps]
            for call in BUILD_CALLS:
                if calls.count(call) != 1:
                    self.report(workflow, "release-shared-scripts", f"expected one call: {call}")
            if BUILD_CALLS[-1] in calls:
                index = calls.index(BUILD_CALLS[-1])
                if calls[max(0, index - 2):index] != list(BUILD_CALLS[:-1]):
                    self.report(workflow, "release-guard-order", "build must immediately follow Perl and sodium setup")
                if self.may_skip(steps[index]) or self.may_skip(job):
                    self.report(workflow, "release-check-unconditional", "build can be skipped")
        script = self.read_script(BUILD_SCRIPT, "release-shared-scripts")
        lines = list(self.logical_lines(script)) if script is not None else []
        if lines[:2] != ["set -euo pipefail", BUILD_GUARD]:
            self.report(str(BUILD_SCRIPT), "release-shared-scripts", "environment guard is not the first build action")

    def check_release_gates(self):
        self.needs("release.yml", "hashes", "verify-packaged", "release-packaged-gate")
        for dependency in ("preflight", "build", "sign-macos"):
            self.needs("release.yml", "verify-packaged", dependency, "release-packaged-gate")
        for workflow in ("release.yml", "release-rehearsal.yml"):
            if self.runs_in_job(workflow, "verify-packaged", ARCHIVE_CHECK, "release-packaged-gate") < 0:
                self.report(workflow, "release-packaged-gate", "verify-packaged does not run the archive check unconditionally")
        self.needs("release.yml", "publish", "verify-provenance", "release-provenance-gate")
        for dependency in ("preflight", "provenance", "hashes"):
            self.needs("release.yml", "verify-provenance", dependency, "release-provenance-gate")
        for command in PROVENANCE_CHECKS:
            if self.runs_in_job("release.yml", "verify-provenance", command, "release-provenance-gate") < 0:
                self.report("release.yml", "release-provenance-gate", f"verify-provenance does not run unconditionally: {command}")
        self.needs("publish.yml", "publish", "verify", "publish-dry-gate")
        for workflow, name in (("publish.yml", "verify"), ("release-rehearsal.yml", "verify-crates")):
            steps = (self.job(workflow, name) or {}).get("steps", [])
            def runs(command):
                return [i for i, step in enumerate(steps)
                        if self.step_position(workflow, name, i, step, command, "publish-dry-gate") >= 0]
            builds, checks = runs(PACKAGE_BUILD), runs(PACKAGE_CHECKS[workflow])
            if len(builds) != 1 or len(checks) != 1 or checks[0] != builds[0] + 1:
                self.report(workflow, "publish-dry-gate", "packaged marker check must immediately follow package verification")
            if builds:
                run = steps[builds[0]].get("run")
                if not 0 <= self.runs_line(run, PACKAGE_START)[0] < self.runs_line(run, PACKAGE_BUILD)[0]:
                    self.report(workflow, "publish-dry-gate", "package verification lacks the freshness timestamp")
        self.needs("publish.yml", "verify-install", "publish", "publish-install-gate")
        if self.runs_in_job("publish.yml", "verify-install", INSTALL_CHECK, "publish-install-gate") < 0:
            self.report("publish.yml", "publish-install-gate", "verify-install does not run the install check unconditionally")

    def check_unconditional(self):
        for workflow, names in GUARDED_JOBS.items():
            for name in names:
                job = self.job(workflow, name)
                if job is None:
                    self.report(workflow, "release-check-unconditional", f"missing {name}")
                    continue
                allowed = workflow == "publish.yml" and name == "publish"
                condition = str(job.get("if", "")).strip()
                if "continue-on-error" in job or ("if" in job and not (allowed and condition == "${{ !inputs.verify_only }}")):
                    self.report(workflow, "release-check-unconditional", f"{name} can be bypassed")
                for step in job.get("steps", []):
                    rosetta = step.get("run") == ROSETTA["run"] and step.get("if") == ROSETTA["if"]
                    if "continue-on-error" in step or ("if" in step and not rosetta):
                        self.report(workflow, "release-check-unconditional", f"{name} step can be bypassed")
                    if self.suppresses(step):
                        self.report(workflow, "release-check-unconditional", f"{name} suppresses failures")

    def check_verification_credentials(self):
        for workflow, name in VERIFY_JOBS:
            job = self.job(workflow, name)
            if job is None:
                continue
            where = f"{workflow}:{name}"
            if self.credentialed(job, self.docs[workflow]) or job.get("permissions") != {"contents": "read"}:
                self.report(where, "verification-credentials", "must be uncredentialed with contents: read")
            self.check_credential_expressions(where, {name: job}, "verification-credentials")
            # rehearsal-credentials reads every expression of the rehearsal.
            if workflow != REHEARSAL_WORKFLOW:
                inherited = {key: self.docs[workflow][key] for key in ("env", "defaults")
                             if key in self.docs[workflow]}
                self.check_credential_expressions(where, inherited, "verification-credentials")
            environments = (self.docs[workflow].get("env"), job.get("env"),
                            *(step.get("env") for step in job.get("steps", [])))
            for env in environments:
                for key in env or {}:
                    if str(key).upper() in TOKEN_ENV:
                        self.report(where, "verification-credentials", f"sets {key}")

    def check_verify_matrix(self):
        for workflow in ("release.yml", "release-rehearsal.yml"):
            job = self.job(workflow, "verify-packaged") or {}
            include = ((job.get("strategy") or {}).get("matrix") or {}).get("include") or []
            legs = sorted(tuple(sorted(leg.items())) for leg in include if isinstance(leg, dict))
            wanted = sorted((("os", runner), ("target", target)) for target, runner in VERIFY_RUNNERS.items())
            if len(legs) != len(include) or legs != wanted:
                self.report(workflow, "release-verify-matrix", "verify-packaged does not run each release target on its runner")
            if not MATRIX_RUNNER.match(str(job.get("runs-on", "")).strip()):
                self.report(workflow, "release-verify-matrix", "verify-packaged does not run on the runner of its matrix leg")
            archive = [step for step in job.get("steps", [])
                       if self.runs_line(step.get("run"), ARCHIVE_CHECK)[0] >= 0]
            if any(not MATRIX_TARGET.match(str((step.get("env") or {}).get("TARGET", "")).strip())
                   for step in archive):
                self.report(workflow, "release-verify-matrix", "the archive check does not read TARGET from the matrix leg")
            steps = job.get("steps") or [{}]
            if steps[0].get("run") != ROSETTA["run"] or steps[0].get("if") != ROSETTA["if"]:
                self.report(workflow, "release-verify-matrix", "the first verify-packaged step is not the Rosetta check")

    def check_release_cache(self):
        for workflow in ("release.yml", REHEARSAL_WORKFLOW):
            for name, job in (self.docs.get(workflow, {}).get("jobs") or {}).items():
                for step in job.get("steps", []):
                    uses = step.get("uses") or ""
                    if CACHE_ACTION.match(uses):
                        self.report(f"{workflow}:{name}", "release-cache", f"uses {uses}")
                    inputs = step.get("with") or {}
                    if SETUP_ACTION.match(uses) and any(str(key).lower() == "cache" for key in inputs):
                        self.report(f"{workflow}:{name}", "release-cache", f"passes a cache input to {uses}")

    def check_release_wasm_gate(self):
        rule = "release-wasm-gate"
        job = self.job("release.yml", "vendored-wasm") or {}
        if job.get("uses") != "./.github/workflows/vendored-wasm.yml" or any(
                key in job for key in ("if", "with", "secrets", "continue-on-error")):
            self.report("release.yml", rule, "vendored-wasm must call the local workflow unconditionally without inputs or secrets")
        self.needs("release.yml", "hashes", "vendored-wasm", rule)
        self.needs("release.yml", "publish", "vendored-wasm", rule)
        workflow = "vendored-wasm.yml"
        doc = self.docs.get(workflow, {})
        triggers = doc.get("on", doc.get(True))
        if not isinstance(triggers, dict) or "workflow_call" not in triggers:
            self.report(workflow, rule, "workflow_call is absent")
        for name, job in (doc.get("jobs") or {}).items():
            where = f"{workflow}:{name}"
            if "continue-on-error" in job:
                self.report(where, rule, f"{name} continues on error")
            for index, step in enumerate(job.get("steps", [])):
                if "continue-on-error" in step:
                    self.report(where, rule, f"{name} step {index + 1} continues on error")
                if name in ("check", "rebuild", "vendored-wasm") and self.suppresses(step):
                    self.report(where, rule, f"{name} step {index + 1} suppresses failures")
                if not CACHE_ACTION.match(step.get("uses") or ""):
                    continue
                if name == "rebuild":
                    self.report(where, rule, "rebuild uses a cache")
                condition = self.unwrap_expression(step.get("if", ""))
                guard = "github.ref_type != 'tag'"
                if condition != guard and not condition.startswith(guard + " && "):
                    self.report(where, rule, "cache guard must lead with github.ref_type != 'tag'")
        self.check_wasm_rebuild(workflow, rule)
        self.check_wasm_gate_job(workflow, rule)

    def check_wasm_rebuild(self, workflow, rule):
        job = self.job(workflow, "rebuild") or {}
        if self.unwrap_expression(job.get("if", "")) != WASM_REBUILD_CONDITION:
            self.report(workflow, rule, f"rebuild must run exactly on {WASM_REBUILD_CONDITION}")
        steps = job.get("steps", [])
        full = [step for step in steps if self.runs(step.get("run"), WASM_FULL_MODE)]
        if not full or any("if" in step for step in full):
            self.report(workflow, rule, "rebuild must rebuild and compare unconditionally")
        for step in steps:
            if not (step.get("uses") or "").startswith("actions/download-artifact@"):
                continue
            for key in FOREIGN_ARTIFACT_INPUTS:
                if key in (step.get("with") or {}):
                    self.report(workflow, rule, f"rebuild downloads an artifact with {key}")
        for version in (25, 28):
            artifact = f"vendored-wasm-stellar-cli-{version}"
            if not any((step.get("uses") or "").startswith("actions/download-artifact@")
                       and (step.get("with") or {}).get("name") == artifact
                       and not self.may_skip(step) for step in steps):
                self.report(workflow, rule, f"rebuild does not download {artifact} unconditionally")

    def check_wasm_gate_job(self, workflow, rule):
        job = self.job(workflow, "vendored-wasm") or {}
        if self.unwrap_expression(job.get("if", "")) != "always()":
            self.report(workflow, rule, "the vendored-wasm job must run on always()")
        needs = job.get("needs", [])
        needs = [needs] if isinstance(needs, str) else needs
        if not isinstance(needs, list) or sorted(str(value) for value in needs) != WASM_GATE_NEEDS:
            self.report(workflow, rule, f"the vendored-wasm job must need exactly {', '.join(WASM_GATE_NEEDS)}")
        gates = [step for step in job.get("steps", []) if self.runs(step.get("run"), "rebuild-vendored-wasm.sh --gate")]
        if len(gates) != 1 or "if" in gates[0]:
            self.report(workflow, rule, "the vendored-wasm job must run one gate step unconditionally")
        elif self.run_text(gates[0]).strip(BLANKS + "\n") != WASM_GATE_CALL:
            self.report(workflow, rule, f"the gate step must run exactly: {WASM_GATE_CALL}")
        if len(gates) == 1 and gates[0].get("env") != WASM_GATE_ENV:
            self.report(workflow, rule, "the gate step must read each job result and the ref type from its expression")

    def check_release_publish_sums(self):
        rule = "release-publish-sums"
        command = 'bash .github/scripts/release/verify-sums.sh "$RUNNER_TEMP/release"'
        check = self.runs_in_job("release.yml", "publish", command, rule)
        steps = (self.job("release.yml", "publish") or {}).get("steps", [])
        releases = [i for i, step in enumerate(steps)
                    if (step.get("uses") or "").startswith("softprops/action-gh-release@")]
        if (check < 0 or self.may_skip(steps[check])
                or self.may_skip(self.job("release.yml", "publish") or {})
                or not releases or any(check >= release for release in releases)):
            self.report("release.yml", rule, "publish must verify sums unconditionally before the release action")

    def check_release_toolchain(self):
        publish = (self.docs.get("publish.yml", {}).get("env") or {}).get("RELEASE_TOOLCHAIN")
        for workflow in ("release.yml", REHEARSAL_WORKFLOW):
            value = (self.docs.get(workflow, {}).get("env") or {}).get("RELEASE_TOOLCHAIN")
            if publish is None or value != publish:
                self.report(workflow, "release-toolchain", "RELEASE_TOOLCHAIN differs from publish.yml")
        for workflow, name, command in ((REHEARSAL_WORKFLOW, "verify-crates", PACKAGE_BUILD),
                                        ("release.yml", "build", BUILD_CALLS[-1]),
                                        (REHEARSAL_WORKFLOW, "build", BUILD_CALLS[-1])):
            job = self.job(workflow, name) or {}
            installs = [i for i, step in enumerate(job.get("steps", []))
                        if re.match(r"dtolnay/rust-toolchain@", step.get("uses") or "")
                        and (step.get("with") or {}).get("toolchain") == "${{ env.RELEASE_TOOLCHAIN }}"
                        and (name != "build" or (step.get("with") or {}).get("targets") == "${{ matrix.target }}")
                        and not self.may_skip(step)]
            pin = self.runs_in_job(workflow, name, TOOLCHAIN_PIN, "release-toolchain")
            build = self.runs_in_job(workflow, name, command, "release-toolchain")
            install = installs[0] if installs else -1
            problem, action = ((f"{name} does not package with RELEASE_TOOLCHAIN", "packaging")
                               if name == "verify-crates" else ("build does not compile with RELEASE_TOOLCHAIN", "build"))
            if not installs:
                self.report(workflow, "release-toolchain", f"{problem}: it installs another toolchain")
            elif pin < 0 or self.may_skip(job["steps"][pin]):
                self.report(workflow, "release-toolchain", f"{problem}: it does not pin RUSTUP_TOOLCHAIN")
            elif not install < pin < build:
                self.report(workflow, "release-toolchain",
                            f"{problem}: RUSTUP_TOOLCHAIN is not pinned between the install and the {action}")

    def check_ci_feature_jobs(self):
        for name, commands in CI_FEATURE_JOBS.items():
            job = self.job("ci.yml", name)
            if job is None:
                self.report("ci.yml", "ci-feature-jobs", f"missing {name}")
                continue
            if "if" in job or "continue-on-error" in job:
                self.report("ci.yml", "ci-feature-jobs", f"{name} can be bypassed")
            for step in job.get("steps", []):
                if "if" in step or "continue-on-error" in step:
                    self.report("ci.yml", "ci-feature-jobs", f"{name} step can be bypassed")
            for command in commands:
                if self.runs_in_job("ci.yml", name, command, "ci-feature-jobs") < 0:
                    self.report("ci.yml", "ci-feature-jobs", f"{name} does not run unconditionally: {command}")
        script = self.read_script(HOST_SCRIPT, "ci-feature-jobs")
        for command in HOST_CHECKS:
            position, problem = self.runs_line(script, command) if script is not None else (0, None)
            if problem:
                self.report(str(HOST_SCRIPT), "ci-feature-jobs", f"unmodelled shell syntax around {command}: {problem}")
            elif position < 0:
                self.report(str(HOST_SCRIPT), "ci-feature-jobs", f"does not run unconditionally: {command}")

    def check_release_checks(self):
        self.check_shared_build()
        self.check_release_gates()
        self.check_unconditional()
        self.check_verification_credentials()
        self.check_verify_matrix()
        self.check_release_cache()
        self.check_release_wasm_gate()
        self.check_release_publish_sums()
        self.check_release_toolchain()
        self.check_ci_feature_jobs()

    def check_workflow(self, workflow):
        doc = self.load(pathlib.PurePosixPath(".github/workflows") / workflow)
        if not isinstance(doc, dict):
            return
        self.docs[workflow] = doc
        if "permissions" not in doc:
            self.report(workflow, "workflow-permissions", "no top-level permissions")
        jobs = doc.get("jobs") or {}
        for wanted_workflow, wanted_job in ANCESTRY_JOBS | SIGNING_JOBS | set(CREDENTIAL_GUARDS):
            if wanted_workflow == workflow and wanted_job not in jobs:
                self.report(workflow, "missing-job", f"job {wanted_job} not found")
        if workflow == COVERAGE_WORKFLOW:
            self.check_coverage_trigger(workflow, doc)
            self.check_coverage_condition(workflow, jobs)
        if workflow == REHEARSAL_WORKFLOW:
            self.check_rehearsal_credentials(workflow, doc, jobs)
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
        self.check_release_checks()
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
