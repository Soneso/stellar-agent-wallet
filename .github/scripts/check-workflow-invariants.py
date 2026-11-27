#!/usr/bin/env python3
"""Structural check of the release, publish, notarization, maintenance,
coverage, and rehearsal workflows.

Usage: ``check-workflow-invariants.py [repository-root]``

Reads ``release.yml``, ``publish.yml``, ``notarize-smoke.yml``, ``labels.yml``,
``stale.yml``, ``triage.yml``, ``triage-review.yml``, ``triage-sweep.yml``,
``welcome.yml``, ``coverage.yml``, ``release-rehearsal.yml``, ``ci.yml``,
``vendored-wasm.yml``, ``changelog.yml``, ``testnet.yml``, ``install-surface.yml``, and ``take.yml``
under ``.github/workflows/``.
Also reads the composite action
``.github/actions/macos-sign-notarize/action.yml``, the shared build script
``.github/scripts/release/build.sh``, and the host recipe
``.github/scripts/release/check-host.sh``. The CI profile check reads
``.config/nextest.toml``. Toolchain checks read
``rust-toolchain.toml``, every ``*.yml`` and ``*.yaml`` workflow, and every
``action.yml`` under ``.github/actions/``. Needs Python 3.11 or later and PyYAML.

A job is credentialed when it references ``secrets.``, passes secrets to a
reusable workflow, declares ``environment:``, or holds ``id-token: write``,
``contents: write``, or ``write-all`` (its own permissions, else the
workflow's). Shared shell checks drop comment lines before joining continuation
lines. The release-evidence template keeps physical lines and comments.
The check fails when any of these holds:

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
  no ``refs/tags/`` checkout. The ``release-evidence`` job is exempt;
  ``publish-release-evidence`` binds its checkout to the verified commit.
- ``ancestry-check``: the ``release.yml`` preflight or a ``publish.yml`` job
  has no line whose first word is the path of ``check-ref-on-main.sh`` and
  that holds no shell operator. The step of that line sets ``if`` or
  ``continue-on-error``, or the job sets ``continue-on-error``. A
  ``publish.yml`` job passes the script the dispatch commit (``GITHUB_SHA``).
- ``coverage-trigger``: ``coverage.yml`` has no ``pull_request`` trigger, a
  ``paths`` or ``paths-ignore`` filter, no ``types`` list, or a list missing
  an event in ``COVERAGE_EVENTS``, or includes an extra or duplicate event.
  The rule reports every missing event and rejects extra or duplicate types.
- ``coverage-condition``: ``coverage.yml`` lacks a job of ``COVERAGE_PARTS``
  or the gate job ``coverage``. A part's ``if`` is not a string equal to
  ``COVERAGE_CONDITION``, or the gate's ``if`` is not a string equal to
  ``COVERAGE_GATE_CONDITION``, after the check strips the surrounding
  whitespace and one enclosing ``${{ }}``. The gate runs on always() only. Its first step must be ``decision`` and pass
  ``MEASURE`` the label and push docs-only clauses of the measuring jobs,
  with the same expression unwrapping. Every gate checkout, download and floor
  step must use the measured output guard, optionally enclosed in ``${{ }}``.
- ``coverage-names``: a job name is not its required plain constant.
- ``selftest-selection``: a self-test has an unknown group, the wrong condition,
  or a changed command inventory, or its CI job fails to run after changes fails.
- ``selftest-checks``: a check or setup step can be skipped or allowed to fail.
  The sole exception is "Check the skill archive", whose archive rule pins
  ``SKILL_ARCHIVE_CONDITION`` and failure behavior. A self-test step holds
  only listed self-test commands and cannot suppress failures.
- ``selftest-selector``: install surface lacks full history or the named selector
  immediately after checkout with the shared event environment.
- ``coverage-split``: a ``run:`` line of ``coverage.yml`` that names
  ``cargo llvm-cov`` or ``check-coverage.py`` differs from the two
  measurement and two floor commands, runs in another job than its own, or
  runs more than once there. The feature-off command belongs to
  ``coverage-off``, the feature-on command to ``coverage-on``, and both
  floors to ``coverage``. Or a part lacks an unconditional upload of its
  ``COVERAGE_EXPORTS`` report after its measurement, with
  ``if-no-files-found: error``.
- ``coverage-gate``: the gate does not need both parts and ``changes``. Its first
  step sets ``if``, differs from the literal decision id, environment keys and
  values or line-for-line ``COVERAGE_DECISION_RUN`` template, or fails to require
  successful classification. Its second and last steps do not reject a
  cancelled run: ``if`` equal to ``cancelled()``, no ``continue-on-error``,
  and ``exit 1`` as the only command. The last step does not follow both
  floors, or another step sets ``if`` except a checkout, download or floor
  guarded by the measured output (optionally enclosed in ``${{ }}``), or a
  checkout, download or floor lacks that guard. Or a report is not downloaded once,
  when measured, from this run, before the first floor.
- ``coverage-seed``: ``coverage.yml`` lacks a ``push`` trigger for both
  ``COVERAGE_SEED_BRANCHES``, filters pushes by path, or lets later runs
  cancel a running push.
- ``coverage-attempt``: an upload or download of ``coverage.yml`` names
  another artifact than a ``COVERAGE_EXPORTS`` report, whose name ends in
  ``${{ github.run_attempt }}``, or a download sets ``pattern`` or
  ``merge-multiple``. The gate then reads only reports of its own attempt.
- ``cache-save-if``: a ``Swatinem/rust-cache`` step, in any letter case, of
  any ``*.yml`` or ``*.yaml`` workflow that ``pull_request`` or
  ``pull_request_target`` triggers lacks ``save-if`` equal to
  ``CACHE_SAVE_CONDITION`` after the check strips one enclosing ``${{ }}``, or boolean ``false``.
  Only ci.yml's test and feature-on-test accept the additional matrix.shard == 1 condition.
  Feature-on clippy and rustdoc jobs must only restore the shared feature-on cache.
- ``ci-result``: the aggregate lacks its base-specific name, complete dependencies,
  matching script job set, cancellation guard, always-run result check, or exact environment.
- ``docs-classifier``: CI or coverage filters push paths, changes its classifier
  inputs or full-history checkout, or docs-tests saves its partial cache.
- ``push-concurrency``: CI, coverage, or install-surface shares groups between push runs.
- ``wasm-branches``: vendored Wasm pull request or push branches omit main or next.
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
  its own checkout as its first command. The normalized logical lines of
  ``build.sh`` differ from ``BUILD_BODY``, or those of the notarization
  smoke's build step differ from ``SMOKE_BUILD``, or those of
  ``copy-alias.sh`` differ from ``COPY_HELPER_BODY``: comments and blank lines
  are dropped and each run of blanks collapses to one space.
- ``rehearsal-security-probes``: the build job lacks exactly one optimized
  probe step immediately after ``Build binaries``, its name, Linux x86_64
  guard, bash shell or normalized command differs, or it has extra keys.
  A probe matches by name or a normalized cargo test command naming the
  integration target; comments do not count. The guard allows expression wrappers.
  Workflow, job and probe env must leave ``CARGO_BUILD_JOBS``, ``RUSTFLAGS``,
  ``CARGO_ENCODED_RUSTFLAGS`` and ``CARGO_PROFILE_*`` unset, as must earlier
  steps writing to ``GITHUB_ENV``. Job ``continue-on-error`` is also refused.
- ``signing-order``: ``sign-notarize.sh`` lacks the contiguous normalized
  ``SIGN_BLOCK``, which signs and verifies ``stellar-agent``, derives the
  alias from the signed file and packs both names; a codesign call other
  than ``SIGN_LINE`` signs; or the script does not end with ``SIGN_FINAL``;
  or the normalized logical lines of ``derive-alias.sh`` differ from
  ``DERIVE_BODY``.
- ``release-guard-order``: the build does not immediately follow the Perl
  and sodium setup steps, so a command could follow their environment writes
  unguarded.
- ``release-packaged-gate``: ``hashes`` does not need ``verify-packaged``,
  ``verify-packaged`` does not need ``preflight``, ``build``, and
  ``sign-macos``, or a ``verify-packaged`` job of ``release.yml`` or
  ``release-rehearsal.yml`` does not run ``ARCHIVE_CHECK`` unconditionally.
- ``release-provenance-gate``: ``publish`` does not need
  ``verify-provenance``, ``verify-provenance`` does not need ``preflight``,
  ``provenance``, ``hashes``, and ``sign``, or it does not run each command of
  ``PROVENANCE_CHECKS`` unconditionally.
- ``release-signatures``: ``sign`` or ``verify-provenance`` lacks the pinned
  cosign installer with ``cosign-release: v3.1.4``, or the signature upload
  does not set ``if-no-files-found: error``.
- ``publish-dry-gate``: the ``publish.yml`` publish job does not need
  ``verify``, or in ``verify`` and the rehearsal's ``verify-crates`` the
  packaging step does not create the start timestamp before it packages,
  unconditionally, or the next step does not run the packaged marker check.
- ``release-version-binding``: packaged checks do not use the validated
  version output, the rehearsal lacks one version step before packaging,
  or the install check does not use the validated tag output.
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
  ``vendored-wasm`` workflow call without inputs or secrets, or ``sign-macos``,
  ``hashes``, or ``publish`` does not need it, or ``sign-macos`` sets ``if``
  or ``continue-on-error``. Apple signing and notarization, hashing, cosign
  signing, provenance, and publication therefore wait for the rebuild. The
  called workflow must declare ``workflow_call``.
  Its cache guards must lead with
  ``github.ref_type != 'tag'``. Each cache step
  restores, or saves exactly on ``WASM_SAVE_CONDITION``, so only push and
  schedule runs save. Its rebuild
  must read both stellar-cli artifacts of its own run and use no cache. No
  job or step of it sets ``continue-on-error``, and no step of ``check``,
  ``rebuild``, or ``vendored-wasm`` suppresses a failure as for
  ``release-check-unconditional``. ``rebuild`` runs exactly on
  ``needs.check.outputs.rebuild == 'true'`` and its full-mode step
  unconditionally. The ``vendored-wasm`` job runs on ``always()``, needs
  exactly ``WASM_GATE_NEEDS``, and has one unconditional gate step that runs
  ``WASM_GATE_CALL`` with ``WASM_GATE_ENV``.
- ``publish-release-evidence``: publish needs the compile-free evidence job.
  It needs verify, runs on ubuntu-24.04 even for verify_only, and has exactly
  contents: read and actions: read, with no environment or id-token.
  It checks out the verified SHA and runs release-mode run selection,
  signature verification, the digest-pinned SLSA verifier, provenance checks
  bound to the selected run and latest attempt, and the offline tree check.
  Its steps equal PUBLISH_EVIDENCE_TEMPLATE: the same count, order, keys,
  and values, with no extra step, key, environment entry, comment, or run line.
  Run blocks split on newline characters, trim spaces and tabs, and drop empty
  lines; comments remain. The first differing step and field are reported.
  The job and template change in the same commit. Job settings and credential
  expressions remain checked separately; only the two pinned API steps may
  set GH_TOKEN to github.token. The template does not judge script contents,
  action behavior, downloaded artifacts, or runtime GitHub evidence.
  Publish itself runs exactly on ``${{ !inputs.verify_only }}``.
- ``release-vars``: an expression reads the ``vars`` context in
  ``release.yml``, in a local reusable workflow it calls, or in the
  ``action.yml`` of a local action it uses, followed through every local
  ``uses:`` of a job or step, or such a local reference names no file in the
  repository. The expressions are read as for ``rehearsal-credentials``, with
  string literals masked. The release provenance records the ``vars`` context
  as its parameters; this keeps a repository, organization, or environment
  variable out of the release build.
- ``release-publish-sums``: ``publish`` does not run the archive checksum
  check unconditionally before the GitHub Release action.
- ``release-toolchain``: ``RELEASE_TOOLCHAIN`` of ``release.yml`` or
  ``release-rehearsal.yml`` differs from that of ``publish.yml``, or either
  build job or the rehearsal's ``verify-crates`` does not install it and pin
  ``RUSTUP_TOOLCHAIN`` between the install and the build or packaging.
- ``wallet-toolchain``: the repository channel is not an exact Rust version,
  a workflow or local action installs another toolchain, or a release workflow
  does not use its matching ``RELEASE_TOOLCHAIN`` value. Toolchain overrides
  are forbidden except in ``vendored-wasm.yml`` and the release pin line.
- ``ci-feature-jobs``: a test job differs from CI_TEST_JOBS, including
  shard membership, setup, cache policy, doctests, and auxiliary commands.
  The nextest configuration must equal NEXTEST_PROFILE, including its group comment.
  Or a job of ``CI_FEATURE_JOBS`` is missing, it or one of
  its steps has an unsupported condition or sets ``continue-on-error``, or
  it does not run each of its commands. The ``feature-discipline`` job needs
  changes, runs unless cancelled, and selects its self-tests by their inputs.
  A job of ``DOCS_ONLY_SKIPPED_JOBS`` instead
  needs exactly ``changes`` and sets ``if`` to ``DOCS_ONLY_CONDITION`` within
  at most one enclosing ``${{ }}``. The ``docs-tests`` job is missing, does
  not need exactly ``changes``, sets ``if`` to anything but
  ``DOCS_TESTS_CONDITION``, it or one of its steps sets ``continue-on-error``
  or a step sets ``if``, or it does not run each of ``DOCS_TESTS_COMMANDS``
  unconditionally; a job of ``CONDITIONED_FEATURE_JOBS`` is
  missing, its ``if`` differs from its documented condition after the check
  strips the surrounding whitespace and one enclosing ``${{ }}``, it sets
  ``continue-on-error``, one of its steps sets ``if`` or
  ``continue-on-error``, or it does not run each of its commands
  unconditionally. A cancel rejection step of the coverage gate is exempt
  from the step rule: ``if`` equal to ``cancelled()``, no
  ``continue-on-error``, and ``exit 1`` as its only command. Gate checkouts,
  downloads and floors may use only the measured output guard, without
  ``continue-on-error``. Or
  ``check-host.sh`` does not run each command of
  ``HOST_CHECKS`` unconditionally.
- ``skill-archive``: ``release-contracts`` can be bypassed, or its skill
  archive step is missing, duplicated, allowed to fail, uses another command,
  or has a condition that differs from ``SKILL_ARCHIVE_CONDITION``.
  Its effective shell must be unset or ``bash``.
- ``apt-retries``: an ``apt-get`` call in any workflow's ``run:`` block lacks
  ``-o Acquire::Retries=3``. Each call is checked separately; comments are ignored.
- ``ci-triggers``: ``ci.yml`` lacks ``push``, a ``pull_request`` branch list
  containing ``main``, or ``workflow_dispatch`` without inputs, or adds an
  event that requires re-evaluating the archive condition.
- ``release-ci-evidence``: the ``release.yml`` preflight's permissions are not
  exactly ``RELEASE_EVIDENCE_PERMISSIONS``, the job sets ``if`` or
  ``continue-on-error``, or the workflow or another release job holds an
  ``actions`` scope or a string permission. Only the SLSA ``provenance``
  job, with exactly ``RELEASE_PROVENANCE_PERMISSIONS``, which the generator
  needs, the ``uses:`` of ``RELEASE_PROVENANCE_USES``, and no ``steps:``,
  keeps ``actions: read``. The preflight lacks exactly one
  ``RELEASE_EVIDENCE_STEP`` directly after the ancestry step, the step sets
  ``if`` or ``continue-on-error``, its effective shell is not the default
  bash, its command differs from ``RELEASE_EVIDENCE_COMMAND``, or its
  ``env`` differs from ``RELEASE_EVIDENCE_ENV``. The workflow ``env``, the
  job ``env``, or another step sets ``GH_TOKEN`` or ``GITHUB_TOKEN``, in any
  letter case. Any other expression of the preflight, or of the workflow
  ``env`` and ``defaults``, reads the ``secrets`` context, the workflow
  token, or the ``github`` context other than by a named property, read as
  for ``rehearsal-credentials``.
- ``changelog-check``: fragment validation or tests can be bypassed, or checkout lacks full history and the main ref.
- ``changelog-guard``: integration changelog protection differs from its condition, event SHAs, shell, or command.
- ``release-fragments``: preflight lacks the read-only pending-fragment check immediately after the version header check.
"""

import ast
import fnmatch
import pathlib
import re
import sys
import tomllib
from datetime import date

try:
    import yaml
except ImportError:
    sys.exit("check-workflow-invariants.py needs PyYAML (pip install PyYAML)")

WORKFLOWS = ("release.yml", "publish.yml", "notarize-smoke.yml", "labels.yml", "stale.yml", "triage.yml",
             "triage-review.yml", "triage-sweep.yml", "welcome.yml", "coverage.yml", "release-rehearsal.yml",
             "ci.yml", "vendored-wasm.yml", "changelog.yml", "testnet.yml", "install-surface.yml", "take.yml")
CHANGELOG_CONDITION = "github.event_name == 'pull_request' && github.base_ref == 'next'"
CHANGELOG_ARGS = 'guard --base "$BASE_SHA" --head "$HEAD_SHA" --main-ref refs/remotes/origin/main'
CHANGELOG_GUARD = ('set -euo pipefail\n'
                   'GUARD_ENTRY=$(git ls-tree "$BASE_SHA" -- .github/scripts/changelog.py)\n'
                   'if [ -n "$GUARD_ENTRY" ]; then\n'
                   '  git show "$BASE_SHA:.github/scripts/changelog.py" | python3 - ' + CHANGELOG_ARGS + '\n'
                   'else\n'
                   '  python3 .github/scripts/changelog.py ' + CHANGELOG_ARGS + '\n'
                   'fi')
CHANGELOG_FETCH = "git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main"
PENDING_FRAGMENTS = ('set -euo pipefail\n'
                     'PENDING=$(find changelog.d -mindepth 1 -maxdepth 1 ! -name README.md -print)\n'
                     'test -z "$PENDING"')
# GitHub resolves action names in any letter case.
CACHE_ACTION = re.compile(r"(Swatinem/rust-cache|actions/cache)(/[\w.-]+)*@", re.IGNORECASE)
RUST_CACHE_ACTION = re.compile(r"Swatinem/rust-cache(/[\w.-]+)*@", re.IGNORECASE)
# A rust-cache step in a workflow that a pull request triggers saves only on
# push runs, so a pull request run, also from a fork, restores only.
CACHE_SAVE_CONDITION = "github.event_name == 'push'"
# Only push and schedule runs save missing stellar-cli install roots; other
# events never save.
WASM_SAVE_CONDITION = ("github.ref_type != 'tag' && "
                       "(github.event_name == 'push' || github.event_name == 'schedule') && "
                       "steps.restore.outputs.cache-hit != 'true'")
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
# Commands that bind published Release evidence to the verified tag commit.
RELEASE_EVIDENCE_COMMANDS = (
    "[ \"$(git rev-parse HEAD)\" = \"$SOURCE_SHA\" ]",
    "echo \"RELEASE_DIR=$RUNNER_TEMP/release-evidence\" >> \"$GITHUB_ENV\"",
    "python3 .github/scripts/check-run-evidence.py --mode release \\\n--repository \"$GITHUB_REPOSITORY\" --sha \"$SOURCE_SHA\" --tag \"$TAG\" \\\n--wait-minutes 0 --poll-seconds 0",
    "mkdir -p \"$RELEASE_DIR\"/{all-artifacts,release-combined,all-signatures,provenance}",
    "gh release view \"$TAG\" --repo \"$GITHUB_REPOSITORY\" --json isDraft,assets > \"$RELEASE_DIR/release.json\"",
    "[ \"$(jq -r .isDraft \"$RELEASE_DIR/release.json\")\" = false ]",
    "gh release download \"$TAG\" --repo \"$GITHUB_REPOSITORY\" --pattern SHA256SUMS --dir \"$RELEASE_DIR/release-combined\"",
    "jq -e --rawfile sums \"$RELEASE_DIR/release-combined/SHA256SUMS\" --arg provenance \"stellar-agent-${TAG#v}.intoto.jsonl\" \\\n'($sums | split(\"\\n\") | map(select(length > 0) | .[66:])) as $archives | .isDraft == false and ($archives | length) == 5 and ([.assets[].name] | sort) == (($archives + [\"SHA256SUMS\"] + (($archives + [\"SHA256SUMS\"]) | map(. + \".sigstore.json\")) + [$provenance]) | sort)' \"$RELEASE_DIR/release.json\"",
    "gh release download \"$TAG\" --repo \"$GITHUB_REPOSITORY\" --pattern '*.tar.xz' --pattern '*.zip' --dir \"$RELEASE_DIR/all-artifacts\"",
    "gh release download \"$TAG\" --repo \"$GITHUB_REPOSITORY\" --pattern '*.sigstore.json' --dir \"$RELEASE_DIR/all-signatures\"",
    "gh release download \"$TAG\" --repo \"$GITHUB_REPOSITORY\" --pattern '*.intoto.jsonl' --dir \"$RELEASE_DIR/provenance\"",
    "bash .github/scripts/release/verify-signatures.sh \"$RELEASE_DIR\" \\\n\"https://github.com/$GITHUB_REPOSITORY/.github/workflows/release.yml@refs/tags/$TAG\" \\\nhttps://token.actions.githubusercontent.com \"$SOURCE_SHA\"",
    "shopt -s nullglob dotglob",
    "verifier=\"$RUNNER_TEMP/slsa-verifier\"",
    "curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \\\nhttps://github.com/slsa-framework/slsa-verifier/releases/download/v2.7.1/slsa-verifier-linux-amd64 --output \"$verifier\"",
    "echo \"946dbec729094195e88ef78e1734324a27869f03e2c6bd2f61cbc06bd5350339  $verifier\" | sha256sum --check --strict",
    "chmod +x \"$verifier\"",
    "provenance=(\"$RELEASE_DIR\"/provenance/*.intoto.jsonl)",
    "[ \"${#provenance[@]}\" -eq 1 ]",
    "for archive in \"$RELEASE_DIR\"/all-artifacts/*; do \\\n\"$verifier\" verify-artifact \"$archive\" --provenance-path \"${provenance[0]}\" \\\n--source-uri \"github.com/$GITHUB_REPOSITORY\" --source-tag \"$TAG\" \\\n--builder-id https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0; \\\ndone",
    "python3 .github/scripts/check-provenance.py \"${provenance[0]}\" \"$RELEASE_DIR/release-combined/SHA256SUMS\" \\\n\"$SOURCE_SHA\" \"$GITHUB_REPOSITORY\" \"refs/tags/$TAG\" \\\n--run-id \"$RELEASE_RUN_ID\" --run-attempt \"$RELEASE_RUN_ATTEMPT\"",
    "bash .github/scripts/rebuild-vendored-wasm.sh --check-tree --repo-root \"$GITHUB_WORKSPACE\"",
)
PUBLISH_EVIDENCE_ENV = {"TAG": "${{ inputs.tag }}", "SOURCE_SHA": "${{ needs.verify.outputs.sha }}"}
PUBLISH_EVIDENCE_API = {
    ("id", "release"): RELEASE_EVIDENCE_COMMANDS[2:3],
    ("name", "Download the published release assets"): ("set -euo pipefail", *RELEASE_EVIDENCE_COMMANDS[3:11]),
}

CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
COSIGN_INSTALLER = "sigstore/cosign-installer@756fe2d284c7292c4e9b62c8a28f1e5629c59532"
COSIGN_VERSION = "v3.1.4"

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
# Opening, pushing to, or reopening a pull request evaluates coverage.
# Editing or labeling a pull request starts no Coverage run.
COVERAGE_WORKFLOW = "coverage.yml"
COVERAGE_EVENTS = ("opened", "synchronize", "reopened")
COVERAGE_LABEL = "github.event_name != 'pull_request' || github.base_ref == 'main' || !(needs.changes.result == 'success' && needs.changes.outputs.docs_only == 'true') || contains(github.event.pull_request.labels.*.name, 'coverage')"
COVERAGE_DOCS_SKIP = ("github.event_name == 'push' && needs.changes.result == 'success' && "
                      "needs.changes.outputs.docs_only == 'true'")
COVERAGE_CONDITION = f"!cancelled() && ({COVERAGE_LABEL}) && !({COVERAGE_DOCS_SKIP})"
# The gate reports on every triggered event, including docs-only changes.
COVERAGE_GATE_CONDITION = "always()"
COVERAGE_MEASURE = "${{ (" + COVERAGE_LABEL + ") && !(" + COVERAGE_DOCS_SKIP + ") }}"
COVERAGE_MEASURED = "steps.decision.outputs.measured == 'true'"
COVERAGE_NAMES = {"changes": "changes", "coverage-off": "coverage (feature-off)",
                  "coverage-on": "coverage (feature-on)", "coverage": "coverage"}
COVERAGE_PARTS = ("coverage-off", "coverage-on")
COVERAGE_GATE = "coverage"
# Pushes to these branches seed the coverage caches, except docs-only pushes to next.
COVERAGE_SEED_BRANCHES = ("next", "main")
COVERAGE_SEED_CANCEL = "github.event_name == 'pull_request'"
COVERAGE_OFF_COMMAND = ("cargo llvm-cov --workspace --no-default-features --features "
                        "test-helpers,test-hooks,test-loopback,verifier-registry --json --output-path cov-feature-off.json")
COVERAGE_ON_COMMAND = ("cargo llvm-cov --workspace --features "
                       "mainnet-write,test-helpers,test-hooks,test-loopback,verifier-registry --json "
                       "--output-path cov-feature-on.json")
COVERAGE_OFF_FLOORS = "python3 .github/scripts/check-coverage.py cov-feature-off.json --configuration feature-off"
COVERAGE_ON_FLOORS = "python3 .github/scripts/check-coverage.py cov-feature-on.json --configuration feature-on"
COVERAGE_MEASURES = {"coverage-off": COVERAGE_OFF_COMMAND, "coverage-on": COVERAGE_ON_COMMAND}
# The artifact name and file of each part's report. The run attempt in the
# name binds each report to the attempt that produced it, so the gate reads
# only reports of its own attempt.
COVERAGE_ATTEMPT = "${{ github.run_attempt }}"
COVERAGE_EXPORTS = {"coverage-off": (f"cov-feature-off-{COVERAGE_ATTEMPT}", "cov-feature-off.json"),
                    "coverage-on": (f"cov-feature-on-{COVERAGE_ATTEMPT}", "cov-feature-on.json")}
# Download inputs that select reports by a pattern or merge several reports.
COVERAGE_SELECTION_INPUTS = ("pattern", "merge-multiple")
# The gate's first step reads both part results; the keys are quoted strings.
COVERAGE_RESULT_ENV = {"OFF": "${{ needs.coverage-off.result }}", "ON": "${{ needs.coverage-on.result }}",
                       "CHANGES": "${{ needs.changes.result }}", "MEASURE": COVERAGE_MEASURE}
COVERAGE_RESULT_CHECKS = ('test "$OFF" = success', 'test "$ON" = success')
# Pin the complete decision script literally, including its final newline.
COVERAGE_DECISION_RUN = '''test "$CHANGES" = success
if [ "$MEASURE" = false ]; then
  test "$OFF" = skipped
  test "$ON" = skipped
  echo "The change is docs-only; nothing was measured."
  echo "measured=false" >> "$GITHUB_OUTPUT"
  exit 0
fi
test "$MEASURE" = true
echo "feature-off: $OFF, feature-on: $ON"
test "$OFF" = success
test "$ON" = success
echo "measured=true" >> "$GITHUB_OUTPUT"
'''
# The gate steps that fail a cancelled run before and after the floors.
COVERAGE_CANCEL_CONDITION = "cancelled()"
COVERAGE_CANCEL_RUN = "exit 1"
# The release rehearsal builds the release targets of any branch on a
# dispatch. Its token reads the repository contents and nothing else, and no
# expression of the workflow reads a secret or the workflow token.
REHEARSAL_WORKFLOW = "release-rehearsal.yml"
REHEARSAL_PROBE_NAME = "Verify optimized Wasm identity and deployment security"
REHEARSAL_PROBE_COMMAND = "cargo test --release --locked --target x86_64-unknown-linux-gnu -p stellar-agent-smart-account --features test-helpers,deploy-cli --lib --test vendored_wasm_release_cfg -- vendored_wasm_tests deployment::deploy::tests:: vendored_table_entries embedded_wasm_constants digest_constants verifier_allowlist_ threshold_policy_hashes weighted_threshold_policy_hashes deploy_smart_account_dry_run deploy_webauthn_verifier_dry_run deploy_ed25519_verifier_dry_run deploy_spending_limit_policy_dry_run deploy_timelock_controller_dry_run deploy_policy_dry_run"

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
# The reviewed body of build.sh, read as normalized logical lines: comments
# and blank lines dropped, each run of blanks collapsed. It builds only the
# canonical executable, copies it to the alias name with copy_alias, and
# compares the bytes.
BUILD_BODY = (
    "set -euo pipefail",
    BUILD_GUARD,
    'if [ "$#" -ne 1 ]; then',
    'echo "usage: build.sh <target>" >&2',
    "exit 2",
    "fi",
    "TARGET=$1",
    'case "$TARGET" in',
    "'' | -* | *[!A-Za-z0-9_.-]*)",
    "echo \"build.sh: invalid target '$TARGET'\" >&2",
    "exit 2",
    ";;",
    "esac",
    'cd "$(dirname "${BASH_SOURCE[0]}")/../../.."',
    'if [ "$TARGET" = "aarch64-unknown-linux-gnu" ]; then',
    'cross build --release --locked --target "$TARGET" --bin stellar-agent',
    "else",
    'cargo build --release --locked --target "$TARGET" --bin stellar-agent',
    "fi",
    "suffix=",
    'case "$TARGET" in',
    "*-windows-*) suffix=.exe ;;",
    "esac",
    'release="target/$TARGET/release"',
    ". .github/scripts/release/copy-alias.sh",
    'copy_alias "$release/stellar-agent$suffix" "$release/stellar-agent-mcp$suffix"',
    'cmp "$release/stellar-agent$suffix" "$release/stellar-agent-mcp$suffix"',
)
# The reviewed run block of the notarization smoke build, normalized alike.
SMOKE_BUILD = (
    "set -euo pipefail",
    "cargo build --release --locked --target aarch64-apple-darwin --bin stellar-agent",
    "release=target/aarch64-apple-darwin/release",
    ". .github/scripts/release/copy-alias.sh",
    'copy_alias "$release/stellar-agent" "$release/stellar-agent-mcp"',
    'cmp "$release/stellar-agent" "$release/stellar-agent-mcp"',
)
# The reviewed body of the copy helper that build.sh, check-host.sh,
# verify-install.sh and the smoke build source, normalized alike: a new
# mktemp file, a destination that is a regular file or absent, and a
# rename(2) through perl that never follows a directory link.
COPY_HELPER = RELEASE_SCRIPTS / "copy-alias.sh"
COPY_HELPER_BODY = (
    "copy_alias() {",
    "local source=$1 destination=$2 temp",
    'if [ -L "$destination" ] || { [ -e "$destination" ] && [ ! -f "$destination" ]; }; then',
    'echo "copy_alias: $destination is not a regular file" >&2',
    "return 1",
    "fi",
    'temp=$(mktemp "$(dirname "$destination")/.stellar-agent-mcp.XXXXXX")',
    'if ! cp -p "$source" "$temp" ||',
    "! perl -e 'rename($ARGV[0], $ARGV[1]) or die \"copy_alias: $ARGV[1]: $!\\n\"' \"$temp\" \"$destination\"; then",
    'rm -f -- "$temp"',
    "return 1",
    "fi",
    "}",
)
# The reviewed body of derive-alias.sh, normalized alike: a canonical regular
# file with one link, an alias that is a regular file or absent, a new mktemp
# file, and a rename(2) through perl that never follows a directory link.
DERIVE_SCRIPT = pathlib.PurePosixPath(".github/actions/macos-sign-notarize/derive-alias.sh")
DERIVE_BODY = (
    "set -euo pipefail",
    "fail() {",
    'echo "derive-alias: $*" >&2',
    "exit 1",
    "}",
    "single_link_file() {",
    '[ -f "$1" ] && [ ! -L "$1" ] && [ -n "$(/usr/bin/find "$1" -prune -links 1)" ]',
    "}",
    'if [ "$#" -ne 2 ]; then',
    "echo 'usage: derive-alias.sh <dir> <suffix>' >&2",
    "exit 2",
    "fi",
    "dir=${1%/}",
    "suffix=$2",
    'case "$suffix" in',
    "'' | .exe) ;;",
    "*)",
    "echo \"derive-alias: unsupported suffix '$suffix'\" >&2",
    "exit 2",
    ";;",
    "esac",
    'canonical="$dir/stellar-agent$suffix"',
    'alias="$dir/stellar-agent-mcp$suffix"',
    'if [ -L "$canonical" ] || [ ! -f "$canonical" ]; then',
    'fail "$canonical is not a regular file"',
    "fi",
    'single_link_file "$canonical" || fail "$canonical has more than one link"',
    'if [ -L "$alias" ] || { [ -e "$alias" ] && [ ! -f "$alias" ]; }; then',
    'fail "$alias is not a regular file"',
    "fi",
    'temp="$(/usr/bin/mktemp "$dir/.stellar-agent-mcp.XXXXXX")"',
    "trap '/bin/rm -f \"$temp\"' EXIT",
    '/bin/cp -p "$canonical" "$temp"',
    "/usr/bin/perl -e 'rename($ARGV[0], $ARGV[1]) or die \"derive-alias: $ARGV[1]: $!\\n\"' \"$temp\" \"$alias\"",
    "trap - EXIT",
    'single_link_file "$alias" || fail "$alias is not a regular file with one link"',
    '/usr/bin/cmp "$canonical" "$alias" || fail "$alias differs from $canonical"',
)
# The signing script signs the canonical executable only, verifies it, then
# derives the alias from the signed file and packs both for notarization.
# SIGN_BLOCK holds those lines with their neighbours, contiguous and
# normalized; SIGN_FINAL is the closing verification of both names.
SIGN_SCRIPT = pathlib.PurePosixPath(".github/actions/macos-sign-notarize/sign-notarize.sh")
SIGN_LINE = ('/usr/bin/codesign --force --options runtime --timestamp --keychain "$KEYCHAIN" '
             '--sign "$IDENTITY" "$BINARY_DIR/stellar-agent"')
SIGN_BLOCK = (
    "fi",
    SIGN_LINE,
    '/usr/bin/codesign --verify --strict --verbose=2 "$BINARY_DIR/stellar-agent"',
    "/bin/bash \"${BASH_SOURCE[0]%/*}/derive-alias.sh\" \"$BINARY_DIR\" ''",
    '/usr/bin/zip -j "$SUBMIT_ZIP" "$BINARY_DIR/stellar-agent" "$BINARY_DIR/stellar-agent-mcp"',
    "printf '%s' \"$ASC_KEY_B64\" | /usr/bin/base64 -d >\"$ASC_KEY\"",
)
SIGN_FINAL = (
    "for bin in stellar-agent stellar-agent-mcp; do",
    '/usr/bin/codesign --verify --strict --verbose=2 "$BINARY_DIR/$bin"',
    "done",
)
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
    'bash .github/scripts/release/verify-signatures.sh "$RUNNER_TEMP/verify-release" '
    '"${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/.github/workflows/release.yml@${GITHUB_REF}" '
    '"https://token.actions.githubusercontent.com" "$GITHUB_SHA"',
    "cargo fetch --locked",
    '"$RUNNER_TEMP/feature-check/bin/python" .github/scripts/check-feature-discipline.py')
PACKAGE_START = "touch target/package-verification-start"
PACKAGE_BUILD = "cargo package --workspace --locked"
PACKAGE_CHECKS = {
    "publish.yml": ('bash "$GITHUB_WORKSPACE/wf/.github/scripts/check-packaged-markers.sh" target '
                    'target/package-verification-start "$EXPECTED_MAINNET_WRITE" "$VERSION"'),
    "release-rehearsal.yml": ('bash .github/scripts/check-packaged-markers.sh target '
                              'target/package-verification-start "$EXPECTED_MAINNET_WRITE" "$VERSION"'),
}
INSTALL_CHECK = ('bash "$GITHUB_WORKSPACE/wf/.github/scripts/release/verify-install.sh" "$TAG" '
                 '"$EXPECTED_MAINNET_WRITE"')
TOOLCHAIN_PIN = 'echo "RUSTUP_TOOLCHAIN=$RELEASE_TOOLCHAIN" >> "$GITHUB_ENV"'
RELEASE_WORKFLOWS = {"release.yml", "publish.yml", "release-rehearsal.yml"}
VERIFIED_SOURCE_CHECK = '[ "$(git -C src rev-parse HEAD)" = "$VERIFIED_SHA" ]'
# The release checks, which no condition may skip and no command may ignore.
GUARDED_JOBS = {"release.yml": ("verify-packaged", "verify-provenance", "hashes", "publish"),
                "publish.yml": ("verify", "publish", "verify-install"),
                "release-rehearsal.yml": ("verify-packaged", "verify-crates")}
# The verification jobs, which hold no credential.
VERIFY_JOBS = (("release.yml", "verify-packaged"), ("release.yml", "verify-provenance"),
               ("publish.yml", "verify"), ("publish.yml", "verify-install"),
               ("release-rehearsal.yml", "verify-packaged"), ("release-rehearsal.yml", "verify-crates"))
TOKEN_ENV = {"GH_TOKEN", "GITHUB_TOKEN"}
# The release preflight's run evidence check, the only preflight step that
# holds the workflow token. The preflight and the SLSA provenance call are
# the only release jobs with actions: read.
RELEASE_EVIDENCE_PERMISSIONS = {"contents": "read", "actions": "read"}
RELEASE_EVIDENCE_STEP = "Require the push CI evidence of the tag commit"
RELEASE_EVIDENCE_COMMAND = ('python3 .github/scripts/check-run-evidence.py --repository "$GITHUB_REPOSITORY" '
                            '--sha "$GITHUB_SHA" --tag "$GITHUB_REF_NAME" --wait-minutes 80 --poll-seconds 60')
RELEASE_EVIDENCE_ENV = {"GH_TOKEN": "${{ github.token }}"}
# The live job and this template change together; run lines retain comments and continuations.
PUBLISH_EVIDENCE_TEMPLATE = (
    {
        "uses": CHECKOUT_ACTION,
        "with": {"ref": "${{ needs.verify.outputs.sha }}", "persist-credentials": False},
    },
    {
        "name": "Require the verified checkout",
        "run": "\n".join(("set -euo pipefail", *RELEASE_EVIDENCE_COMMANDS[:2])),
    },
    {
        "name": "Select the successful Release run",
        "id": "release",
        "env": RELEASE_EVIDENCE_ENV,
        "run": "\n".join(PUBLISH_EVIDENCE_API[("id", "release")]),
    },
    {
        "name": "Download the published release assets",
        "env": RELEASE_EVIDENCE_ENV,
        "run": "\n".join(PUBLISH_EVIDENCE_API[("name", "Download the published release assets")]),
    },
    {
        "name": "Install cosign",
        "uses": COSIGN_INSTALLER,
        "with": {"cosign-release": COSIGN_VERSION},
    },
    {
        "name": "Verify release signatures",
        "run": RELEASE_EVIDENCE_COMMANDS[11],
    },
    {
        "name": "Verify provenance signatures and run binding",
        "env": {"RELEASE_RUN_ID": "${{ steps.release.outputs.run_id }}", "RELEASE_RUN_ATTEMPT": "${{ steps.release.outputs.run_attempt }}"},
        "run": "\n".join(("set -euo pipefail", *RELEASE_EVIDENCE_COMMANDS[12:21])),
    },
    {
        "name": "Check the tagged Wasm tree offline",
        "run": RELEASE_EVIDENCE_COMMANDS[21],
    },
)
# The SLSA generator call reads its own run, so the provenance job keeps
# exactly these permissions, this call, and no steps of its own.
RELEASE_PROVENANCE_PERMISSIONS = {"actions": "read", "id-token": "write", "contents": "write"}
RELEASE_PROVENANCE_USES = "slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0"
SKILL_ARCHIVE_CONDITION = "github.base_ref != 'next' && github.ref != 'refs/heads/next'"
# The feature jobs of ci.yml and the commands that define each of them. The
# off jobs pass --no-default-features, which keeps mainnet-write off; the
# binary packages enable it by default.
SELFTEST_GROUPS = ("scripts", "rust", "docs", "preflight")
SELFTESTS = {
    "ci.yml:feature-discipline": {
        "\"$RUNNER_TEMP/feature-check/bin/python\" .github/scripts/test-check-feature-discipline.py --mutations": "rust",
        "bash .github/scripts/test-check-binary-marker.sh": "rust",
        "bash .github/scripts/test-release-checks.sh": "rust",
        "\"$RUNNER_TEMP/feature-check/bin/python\" .github/scripts/test-check-provenance.py --mutations": "rust",
    },
    "ci.yml:release-contracts": {
        ".github/scripts/test-publish-crates-check.sh": "scripts",
        "bash .github/scripts/test-check-no-direct-sasignersetbaselined-emit.sh": "rust",
        "bash .github/scripts/test-check-ref-on-main.sh": "scripts",
        "bash .github/scripts/test-run-testnet-acceptance.sh": "rust",
        "bash .github/scripts/test-check-crates-exist.sh": "scripts",
        "bash .github/scripts/test-publish-crates-verify.sh": "scripts",
        "python3 .github/scripts/test-publish-release-evidence.py --mutations": "scripts",
        "python3 .github/scripts/test-compare-crate-sums.py": "scripts",
        "python3 .github/scripts/test-check-coverage.py": "scripts",
        "python3 .github/scripts/test-check-proof-matrix.py": "scripts",
        "python3 .github/scripts/test-classify-docs-only.py": "scripts",
        "python3 .github/scripts/test-classify-self-tests.py": "scripts",
        "python3 .github/scripts/test-ci-result.py": "scripts",
        "python3 .github/scripts/test-check-run-evidence.py --mutations": "scripts",
        "python3 .github/scripts/test-check-docs-reads.py": "scripts",
        "python3 .github/scripts/test-validate-unsigned-archive.py": "scripts",
        "\"$RUNNER_TEMP/workflow-check/bin/python\" .github/scripts/test-check-workflow-invariants.py": "scripts",
        "\"$RUNNER_TEMP/workflow-check/bin/python\" .github/scripts/test-take-workflow.py": "scripts",
        "\"$RUNNER_TEMP/workflow-check/bin/python\" .github/scripts/test-sync-labels.py": "scripts",
        "\"$RUNNER_TEMP/workflow-check/bin/python\" .github/scripts/test-triage-workflow.py": "scripts",
        "\"$RUNNER_TEMP/workflow-check/bin/python\" .github/scripts/test-welcome-workflow.py": "scripts",
        "\"$RUNNER_TEMP/workflow-check/bin/python\" .github/scripts/test-welcome-workflow.py --mutations": "scripts",
    },
    "install-surface.yml:install-surface": {
        "python3 .github/scripts/test-check-install-surface.py": "docs",
        "python3 .github/scripts/test-check-docs-style.py": "docs",
        "bash .github/scripts/test-check-gate-tool-versions.sh": "docs",
        "bash .github/scripts/test-preflight.sh": "preflight",
        "bash .github/scripts/test-preflight.sh --mutations": "preflight",
    },
}

# Reviewed test jobs: names, setup, partitions, doctests and auxiliary checks.
CI_TEST_JOBS = {'test': {'name': 'test (${{ matrix.shard }}/3)',
          'strategy': {'fail-fast': False, 'matrix': {'include': [{'shard': 1}, {'shard': 2}, {'shard': 3}]}},
          'needs': 'changes',
          'if': "${{ !cancelled() && needs.changes.outputs.docs_only != 'true' }}",
          'runs-on': 'ubuntu-24.04',
          'timeout-minutes': 90,
          'env': {'CARGO_PROFILE_TEST_DEBUG': '0'},
          'steps': [{'uses': 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
                     'with': {'persist-credentials': False}},
                    {'name': 'Free disk space',
                     'run': 'sudo rm -rf /usr/share/dotnet\n'
                            'sudo rm -rf /usr/local/lib/android\n'
                            'sudo rm -rf /opt/ghc\n'
                            'sudo rm -rf /opt/hostedtoolcache/CodeQL\n'
                            'sudo docker image prune --all --force >/dev/null 2>&1 || true\n'},
                    {'uses': 'dtolnay/rust-toolchain@683b588c487a69d01f6c6ddf40f036ff682cc2c8',
                     'with': {'toolchain': '1.100.0'}},
                    {'name': 'Install libudev (Linux hidapi)',
                     'run': 'sudo apt-get -o Acquire::Retries=3 update && sudo apt-get -o Acquire::Retries=3 '
                            'install -y libudev-dev pkg-config'},
                    {'uses': 'Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0',
                     'with': {'shared-key': 'test',
                              'save-if': "${{ github.event_name == 'push' && matrix.shard == 1 }}"}},
                    {'uses': 'taiki-e/install-action@25f51f6b1bf4e18876107cece836f4f77ac17c8c',
                     'with': {'tool': 'cargo-nextest@0.9.152'}},
                    {'name': 'Run the shard tests',
                     'run': 'cargo nextest run --workspace --no-default-features --features '
                            'test-helpers,test-hooks,test-loopback,verifier-registry --partition count:${{ '
                            'matrix.shard }}/3 --profile ci'}]},
 'test-extra': {'name': 'test-extra',
                'needs': 'changes',
                'if': "${{ !cancelled() && needs.changes.outputs.docs_only != 'true' }}",
                'runs-on': 'ubuntu-24.04',
                'timeout-minutes': 90,
                'env': {'CARGO_PROFILE_TEST_DEBUG': '0'},
                'steps': [{'uses': 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
                           'with': {'persist-credentials': False}},
                          {'name': 'Free disk space',
                           'run': 'sudo rm -rf /usr/share/dotnet\n'
                                  'sudo rm -rf /usr/local/lib/android\n'
                                  'sudo rm -rf /opt/ghc\n'
                                  'sudo rm -rf /opt/hostedtoolcache/CodeQL\n'
                                  'sudo docker image prune --all --force >/dev/null 2>&1 || true\n'},
                          {'uses': 'dtolnay/rust-toolchain@683b588c487a69d01f6c6ddf40f036ff682cc2c8',
                           'with': {'toolchain': '1.100.0'}},
                          {'name': 'Install libudev (Linux hidapi)',
                           'run': 'sudo apt-get -o Acquire::Retries=3 update && sudo apt-get -o '
                                  'Acquire::Retries=3 install -y libudev-dev pkg-config'},
                          {'uses': 'Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0',
                           'with': {'shared-key': 'test', 'save-if': False}},
                          {'name': 'Run the offline doctests',
                           'run': 'cargo test --workspace --no-default-features --features '
                                  'test-helpers,test-hooks,test-loopback,verifier-registry --doc'},
                          {'name': 'Check the proof matrix',
                           'run': 'python3 .github/scripts/check-proof-matrix.py --configuration feature-off '
                                  '--workspace'},
                          {'name': 'Run the test-support Friendbot unit tests',
                           'run': 'cargo test -p stellar-agent-test-support --no-default-features --features '
                                  'testnet-helpers --lib'},
                          {'name': 'Test the vendored Wasm release configuration',
                           'run': 'cargo test -p stellar-agent-smart-account --test '
                                  'vendored_wasm_release_cfg'},
                          {'name': 'Test the policy pin release configuration',
                           'run': 'cargo test -p stellar-agent-core --doc policy::pin'},
                          {'name': 'Check each test-support feature set',
                           'run': 'cargo check -p stellar-agent-test-support --no-default-features\n'
                                  'for feature in test-helpers testnet-helpers verifier-registry '
                                  'wiremock-helpers; do\n'
                                  '  cargo check -p stellar-agent-test-support --no-default-features '
                                  '--features "$feature"\n'
                                  'done\n'}]},
 'feature-on-test': {'name': 'feature-on-test (${{ matrix.shard }}/3)',
                     'strategy': {'fail-fast': False,
                                  'matrix': {'include': [{'shard': 1}, {'shard': 2}, {'shard': 3}]}},
                     'needs': 'changes',
                     'if': "${{ !cancelled() && needs.changes.outputs.docs_only != 'true' }}",
                     'runs-on': 'ubuntu-24.04',
                     'timeout-minutes': 90,
                     'env': {'CARGO_PROFILE_TEST_DEBUG': '0'},
                     'steps': [{'uses': 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
                                'with': {'persist-credentials': False}},
                               {'name': 'Free disk space',
                                'run': 'sudo rm -rf /usr/share/dotnet\n'
                                       'sudo rm -rf /usr/local/lib/android\n'
                                       'sudo rm -rf /opt/ghc\n'
                                       'sudo rm -rf /opt/hostedtoolcache/CodeQL\n'
                                       'sudo docker image prune --all --force >/dev/null 2>&1 || true\n'},
                               {'uses': 'dtolnay/rust-toolchain@683b588c487a69d01f6c6ddf40f036ff682cc2c8',
                                'with': {'toolchain': '1.100.0'}},
                               {'name': 'Install libudev (Linux hidapi)',
                                'run': 'sudo apt-get -o Acquire::Retries=3 update && sudo apt-get -o '
                                       'Acquire::Retries=3 install -y libudev-dev pkg-config'},
                               {'uses': 'Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0',
                                'with': {'shared-key': 'feature-on',
                                         'save-if': "${{ github.event_name == 'push' && matrix.shard == 1 "
                                                    '}}'}},
                               {'uses': 'taiki-e/install-action@25f51f6b1bf4e18876107cece836f4f77ac17c8c',
                                'with': {'tool': 'cargo-nextest@0.9.152'}},
                               {'name': 'Run the shard tests',
                                'run': 'cargo nextest run --workspace --features '
                                       'mainnet-write,test-helpers,test-hooks,test-loopback,verifier-registry '
                                       '--partition count:${{ matrix.shard }}/3 --profile ci'}]},
 'feature-on-test-extra': {'name': 'feature-on-test-extra',
                           'needs': 'changes',
                           'if': "${{ !cancelled() && needs.changes.outputs.docs_only != 'true' }}",
                           'runs-on': 'ubuntu-24.04',
                           'timeout-minutes': 90,
                           'env': {'CARGO_PROFILE_TEST_DEBUG': '0'},
                           'steps': [{'uses': 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
                                      'with': {'persist-credentials': False}},
                                     {'name': 'Free disk space',
                                      'run': 'sudo rm -rf /usr/share/dotnet\n'
                                             'sudo rm -rf /usr/local/lib/android\n'
                                             'sudo rm -rf /opt/ghc\n'
                                             'sudo rm -rf /opt/hostedtoolcache/CodeQL\n'
                                             'sudo docker image prune --all --force >/dev/null 2>&1 || '
                                             'true\n'},
                                     {'uses': 'dtolnay/rust-toolchain@683b588c487a69d01f6c6ddf40f036ff682cc2c8',
                                      'with': {'toolchain': '1.100.0'}},
                                     {'name': 'Install libudev (Linux hidapi)',
                                      'run': 'sudo apt-get -o Acquire::Retries=3 update && sudo apt-get -o '
                                             'Acquire::Retries=3 install -y libudev-dev pkg-config'},
                                     {'uses': 'Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0',
                                      'with': {'shared-key': 'feature-on', 'save-if': False}},
                                     {'name': 'Run the feature-on doctests',
                                      'run': 'cargo test --workspace --features '
                                             'mainnet-write,test-helpers,test-hooks,test-loopback,verifier-registry '
                                             '--doc'},
                                     {'name': 'Check network feature forwarding in isolation',
                                      'run': 'cargo check -p stellar-agent-network --features mainnet-write'},
                                     {'name': 'Check the proof matrix',
                                      'run': 'python3 .github/scripts/check-proof-matrix.py --configuration '
                                             'feature-on --workspace'}]}}

NEXTEST_PROFILE = "[profile.ci]\nfail-fast = false\nretries = 0\n\n[test-groups]\n# Tests that share a file path or a port across processes join a group with\n# max-threads = 1. The maintainer adds members from a measured run.\n"

CI_FEATURE_JOBS = {
    "clippy": (
        'cargo clippy --workspace --all-targets --no-default-features --features "$FEATURES_EXCEPT_MAINNET_WRITE" '
        '-- -D warnings',),
    "doc": ('cargo doc --workspace --no-deps --no-default-features --features "$FEATURES_EXCEPT_MAINNET_WRITE"',),
    "feature-on-clippy": (
        'cargo clippy --workspace --all-targets --features "mainnet-write,$FEATURES_EXCEPT_MAINNET_WRITE" '
        '-- -D warnings',),
    "feature-on-doc": ('cargo doc --workspace --no-deps --features "mainnet-write,$FEATURES_EXCEPT_MAINNET_WRITE"',),
    "feature-discipline": (
        "cargo fetch --locked",
        '"$RUNNER_TEMP/feature-check/bin/python" .github/scripts/check-feature-discipline.py',
        '"$RUNNER_TEMP/feature-check/bin/python" .github/scripts/test-check-feature-discipline.py --mutations',
        "bash .github/scripts/test-check-binary-marker.sh",
        "bash .github/scripts/test-release-checks.sh",
        '"$RUNNER_TEMP/feature-check/bin/python" .github/scripts/test-check-provenance.py --mutations'),
    "release-shape": ("bash .github/scripts/release/check-host.sh",),
}
# The feature jobs of ci.yml that skip a pull request into next that
# changes only documentation. Each needs only the changes job and runs under
# DOCS_ONLY_CONDITION. On such a pull request the docs-tests job runs under
# DOCS_TESTS_CONDITION instead and runs DOCS_TESTS_COMMANDS: the documentation
# read check and the registry tests in the feature states of test and
# feature-on-test.
DOCS_ONLY_SKIPPED_JOBS = ("clippy", "doc", "feature-on-clippy", "feature-on-doc",
                          "release-shape")
DOCS_ONLY_CONDITION = "!cancelled() && needs.changes.outputs.docs_only != 'true'"
DOCS_TESTS_JOB = "docs-tests"
DOCS_TESTS_CONDITION = "!cancelled() && needs.changes.outputs.docs_only == 'true'"
DOCS_TESTS_COMMANDS = (
    "python3 .github/scripts/check-docs-reads.py",
    "python3 .github/scripts/run-docs-tests.py --no-default-features "
    "--features test-helpers,test-hooks,test-loopback,verifier-registry",
    "python3 .github/scripts/run-docs-tests.py "
    "--features mainnet-write,test-helpers,test-hooks,test-loopback,verifier-registry",
)
# The feature jobs of other workflows that run under a documented job
# condition: for each workflow and job, that condition and the commands that
# define the job.
CONDITIONED_FEATURE_JOBS = {
    (COVERAGE_WORKFLOW, "coverage-off"): (COVERAGE_CONDITION, (COVERAGE_OFF_COMMAND,)),
    (COVERAGE_WORKFLOW, "coverage-on"): (COVERAGE_CONDITION, (COVERAGE_ON_COMMAND,)),
    (COVERAGE_WORKFLOW, COVERAGE_GATE): (COVERAGE_GATE_CONDITION, (
        COVERAGE_RESULT_CHECKS[0], COVERAGE_RESULT_CHECKS[1], 'test "$CHANGES" = success',
        COVERAGE_OFF_FLOORS, COVERAGE_ON_FLOORS)),
}
# The host recipe: the release build for the host target, which places the
# stellar-agent-mcp copy, the byte comparison of both names and the version and marker
# check of each; then the build of the CLI package alone, the copy of its
# debug executable to the alias name with copy_alias, the byte comparison,
# and the name, version, and marker check of both debug names.
HOST_ALIAS = "target/tmp/host-alias/stellar-agent-mcp"
HOST_CHECKS = ('bash .github/scripts/release/build.sh "$target"',
               'cmp "target/$target/release/stellar-agent" "target/$target/release/stellar-agent-mcp"',
               'bash .github/scripts/check-binary-marker.sh "target/$target/release/stellar-agent" on "stellar-agent $version"',
               'bash .github/scripts/check-binary-marker.sh "target/$target/release/stellar-agent-mcp" on "stellar-agent-mcp $version"',
               "cargo build --locked -p stellar-agent-cli",
               "mkdir -p target/tmp/host-alias",
               ". .github/scripts/release/copy-alias.sh",
               f"copy_alias target/debug/stellar-agent {HOST_ALIAS}",
               f"cmp target/debug/stellar-agent {HOST_ALIAS}",
               'bash .github/scripts/check-binary-marker.sh target/debug/stellar-agent on "stellar-agent $version"',
               f'bash .github/scripts/check-binary-marker.sh {HOST_ALIAS} on "stellar-agent-mcp $version"')
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
        "check-ref-on-main.sh", "compare-crate-sums.py", CLEAN_CHECK, "rustc -V", VERIFIED_SOURCE_CHECK), "compare-crate-sums.py"),
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
APT_GET_CALL = re.compile(COMMAND_WORD.format("apt-get") + r"(?=[ \t]|$)")
APT_RETRIES = re.compile(r"(?:^|[ \t])-o[ \t]+Acquire::Retries=3(?=[ \t]|$)")
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
VARS_CONTEXT = re.compile(r"(?<![\w.-])vars(?![\w-])", re.IGNORECASE)
WORKFLOW_DIR = pathlib.PurePosixPath(".github/workflows")


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
        lines = ("" if text is None else str(text)).split("\n")
        uncommented = "\n".join(line for line in lines if not line.lstrip(BLANKS).startswith("#"))
        return re.sub(r"\\\n", " ", uncommented).split("\n")

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
        # The evidence rule owns this job's permissions and compile restrictions.
        credentialed = self.credentialed(job, workflow_doc) and (workflow, job_id) != ("publish.yml", "release-evidence")
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
                if workflow == "publish.yml" and job_id != "release-evidence":
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
        if workflow == "publish.yml" and tag_checkouts == 0 and job_id != "release-evidence":
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
        if any(event not in COVERAGE_EVENTS for event in types) or len(types) != len(set(map(str, types))):
            self.report(workflow, "coverage-trigger", "pull_request types include extra or duplicate events")
        for event in COVERAGE_EVENTS:
            if event not in types:
                self.report(workflow, "coverage-trigger", f"pull_request types lack {event}")

    def check_coverage_condition(self, workflow, jobs):
        for name in COVERAGE_PARTS:
            if name not in jobs:
                self.report(workflow, "coverage-condition", f"job {name} not found")
                continue
            job = jobs[name]
            condition = job.get("if") if isinstance(job, dict) else None
            if isinstance(condition, str):
                condition = self.unwrap_expression(condition)
            if condition != COVERAGE_CONDITION:
                self.report(workflow, "coverage-condition", f"{name} job runs without the measure condition")
            if isinstance(job, dict) and job.get("needs") not in ("changes", ["changes"]):
                self.report(workflow, "coverage-condition", f"{name} must need changes")
        if COVERAGE_GATE not in jobs:
            self.report(workflow, "coverage-condition", f"job {COVERAGE_GATE} not found")
            return
        gate = jobs[COVERAGE_GATE] if isinstance(jobs[COVERAGE_GATE], dict) else {}
        gate_condition = gate.get("if")
        if isinstance(gate_condition, str):
            gate_condition = self.unwrap_expression(gate_condition)
        if gate_condition != COVERAGE_GATE_CONDITION:
            self.report(workflow, "coverage-condition", "coverage gate must run on always() only")
        steps = gate.get("steps", []) or []
        first = steps[0] if steps else {}
        if (first.get("id") != "decision"
                or self.unwrap_expression(str((first.get("env") or {}).get("MEASURE", ""))) != self.unwrap_expression(COVERAGE_MEASURE)):
            self.report(workflow, "coverage-condition", "coverage gate decision must use the measure expression")
        for step in steps:
            if self.coverage_measured_step(step) and self.unwrap_expression(str(step.get("if", ""))) != COVERAGE_MEASURED:
                self.report(workflow, "coverage-condition", "coverage gate checkout, download and floors must use the measured guard")

    def coverage_measured_step(self, step):
        """Steps that consume reports only when the gate's decision measured."""
        return (str(step.get("uses") or "").startswith(("actions/checkout@", "actions/download-artifact@"))
                or any(command in self.normalized(self.run_text(step))
                       for command in (COVERAGE_OFF_FLOORS, COVERAGE_ON_FLOORS)))

    def check_coverage_names(self, workflow, jobs):
        for name, title in COVERAGE_NAMES.items():
            job = jobs.get(name) or {}
            if job.get("name") != title:
                self.report(workflow, "coverage-names", f"{name} must have plain name {title}")

    def check_coverage_split(self, workflow, jobs):
        """Each measurement and floor command runs once, in its own job, and
        each part uploads its report after its measurement."""
        rule = "coverage-split"
        owners = {COVERAGE_OFF_COMMAND: "coverage-off", COVERAGE_ON_COMMAND: "coverage-on",
                  COVERAGE_OFF_FLOORS: COVERAGE_GATE, COVERAGE_ON_FLOORS: COVERAGE_GATE}
        counts = {}
        for name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for step in job.get("steps", []) or []:
                for line in self.normalized(self.run_text(step)):
                    if "cargo llvm-cov" not in line and "check-coverage.py" not in line:
                        continue
                    owner = owners.get(line)
                    if owner is None:
                        self.report(workflow, rule, f"unexpected coverage command in {name}: {line}")
                    elif name != owner:
                        self.report(workflow, rule, f"{line} runs in {name}, expected {owner}")
                    else:
                        counts[line] = counts.get(line, 0) + 1
        for line, count in counts.items():
            if count > 1:
                self.report(workflow, rule, f"{owners[line]} has {count} occurrences of {line}, expected one")
        for name, (artifact, path) in COVERAGE_EXPORTS.items():
            job = jobs.get(name)
            steps = (job.get("steps", []) or []) if isinstance(job, dict) else []
            measured = [index for index, step in enumerate(steps)
                        if COVERAGE_MEASURES[name] in self.normalized(self.run_text(step))]
            uploads = []
            for index, step in enumerate(steps):
                options = step.get("with") or {}
                if not str(step.get("uses") or "").startswith("actions/upload-artifact@") or "if" in step:
                    continue
                if options.get("name") != artifact or options.get("path") != path:
                    continue
                if options.get("if-no-files-found") != "error":
                    continue
                if not measured or index < measured[0]:
                    continue
                uploads.append(index)
            if not uploads:
                self.report(workflow, rule, f"{name} does not upload {artifact} after its measurement")

    def check_coverage_gate(self, workflow, jobs):
        """The gate needs both parts, checks their results first, rejects a
        cancelled run before and after the floors, and floors only the
        reports of its own run."""
        rule = "coverage-gate"
        gate = jobs.get(COVERAGE_GATE)
        if not isinstance(gate, dict):
            return
        steps = gate.get("steps", []) or []

        def rejects(step):
            condition = step.get("if")
            if not isinstance(condition, str) or self.unwrap_expression(condition) != COVERAGE_CANCEL_CONDITION:
                return False
            if "continue-on-error" in step:
                return False
            return self.normalized(self.run_text(step)) == [COVERAGE_CANCEL_RUN]

        needs = gate.get("needs")
        if not isinstance(needs, list) or set(map(str, needs)) != {"changes", *COVERAGE_PARTS}:
            self.report(workflow, rule, f"coverage gate needs {needs}, expected changes, coverage-off and coverage-on")
        first = steps[0] if steps else {}
        if first.get("id") != "decision" or first.get("run") != COVERAGE_DECISION_RUN:
            self.report(workflow, rule, "coverage gate decision must match the literal template")
        if "if" in first or any(self.runs_line(first.get("run"), check)[0] < 0 for check in COVERAGE_RESULT_CHECKS):
            self.report(workflow, rule, "coverage gate does not check the results first")
        env = first.get("env")
        if env != COVERAGE_RESULT_ENV:
            self.report(workflow, rule, f"coverage gate result check reads {env}")
        if self.runs_line(first.get("run"), 'test "$CHANGES" = success')[0] < 0:
            self.report(workflow, rule, "coverage gate must reject failed changes")
        if len(steps) < 2 or not rejects(steps[1]):
            self.report(workflow, rule, "coverage gate does not reject a cancelled run after its result check")
        floors = [index for index, step in enumerate(steps)
                  if any(self.runs_line(step.get("run"), command)[0] >= 0
                         for command in (COVERAGE_OFF_FLOORS, COVERAGE_ON_FLOORS))]
        if not (len(steps) > 2 and rejects(steps[-1]) and all(index < len(steps) - 1 for index in floors)):
            self.report(workflow, rule, "coverage gate does not reject a cancelled run after its floors")
        for index, step in enumerate(steps):
            if index in (1, len(steps) - 1) and rejects(step):
                continue
            if self.coverage_measured_step(step) and self.unwrap_expression(str(step.get("if", ""))) != COVERAGE_MEASURED:
                self.report(workflow, rule, "coverage gate consumer must use the measured guard")
            if "if" in step and not (self.coverage_measured_step(step) and self.unwrap_expression(str(step["if"])) == COVERAGE_MEASURED):
                self.report(workflow, rule, f"coverage gate step {index + 1} runs under {step['if']}")
        downloads = {}
        for index, step in enumerate(steps):
            if str(step.get("uses") or "").startswith("actions/download-artifact@"):
                downloads.setdefault((step.get("with") or {}).get("name"), []).append((index, step))
        first_floor = min(floors, default=len(steps))
        for artifact, _ in COVERAGE_EXPORTS.values():
            found = downloads.get(artifact, [])
            if len(found) != 1 or self.unwrap_expression(str(found[0][1].get("if", ""))) != COVERAGE_MEASURED:
                self.report(workflow, rule, f"coverage gate does not download {artifact}")
                continue
            index, step = found[0]
            options = step.get("with") or {}
            for key in FOREIGN_ARTIFACT_INPUTS:
                if key in options:
                    self.report(workflow, rule, f"coverage gate downloads {artifact} with {key}")
            if index > first_floor:
                self.report(workflow, rule, f"coverage gate checks floors before downloading {artifact}")

    def check_coverage_seed(self, workflow, doc):
        """Pushes to both base branches run without a paths filter or cancellation."""
        rule = "coverage-seed"
        triggers = doc.get("on", doc.get(True))
        seeds = triggers if isinstance(triggers, dict) else {}
        if "push" not in seeds:
            self.report(workflow, rule, "push trigger is absent")
        push = seeds.get("push")
        push = push if isinstance(push, dict) else {}
        branches = push.get("branches")
        branches = branches if isinstance(branches, list) else []
        for branch in COVERAGE_SEED_BRANCHES:
            if branch not in branches:
                self.report(workflow, rule, f"push branches lack {branch}")
        if any(key in push for key in ("paths", "paths-ignore")):
            self.report(workflow, rule, "push trigger has a paths filter")
        concurrency = doc.get("concurrency")
        cancel = concurrency.get("cancel-in-progress") if isinstance(concurrency, dict) else None
        if not isinstance(cancel, str) or self.unwrap_expression(cancel) != COVERAGE_SEED_CANCEL:
            self.report(workflow, rule, "later runs cancel a running push")

    def check_coverage_attempt(self, workflow, jobs):
        """Every upload and download of the workflow names a report of this
        run attempt and selects it by that name alone."""
        rule = "coverage-attempt"
        names = {artifact for artifact, _ in COVERAGE_EXPORTS.values()}
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for index, step in enumerate(job.get("steps", []) or []):
                uses = str(step.get("uses") or "")
                download = uses.startswith("actions/download-artifact@")
                if not download and not uses.startswith("actions/upload-artifact@"):
                    continue
                inputs = step.get("with") or {}
                where = f"{job_name} step {index + 1}"
                if inputs.get("name") not in names:
                    self.report(workflow, rule, f"{where} transfers {inputs.get('name')}, not a report of this run attempt")
                for key in COVERAGE_SELECTION_INPUTS:
                    if download and key in inputs:
                        self.report(workflow, rule, f"{where} downloads with {key}")

    def check_cache_save_if(self):
        """A rust-cache step of a workflow that a pull request triggers saves
        only on push runs."""
        directory = self.root / WORKFLOW_DIR
        for source in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):
            if source.name in WORKFLOWS:
                doc = self.docs.get(source.name)
            else:
                # apt-retries reports a file that does not parse.
                try:
                    doc = yaml.safe_load(source.read_text())
                except (OSError, yaml.YAMLError):
                    doc = None
            if not isinstance(doc, dict):
                continue
            triggers = doc.get("on", doc.get(True))
            if isinstance(triggers, dict):
                events = set(triggers.keys())
            elif isinstance(triggers, list):
                events = {str(event) for event in triggers}
            else:
                events = {triggers}
            if not events & {"pull_request", "pull_request_target"}:
                continue
            for name, job in (doc.get("jobs") or {}).items():
                if not isinstance(job, dict):
                    continue
                for index, step in enumerate(job.get("steps", []) or []):
                    if not RUST_CACHE_ACTION.match(str(step.get("uses") or "")):
                        continue
                    value = (step.get("with") or {}).get("save-if")
                    if source.name == "ci.yml" and name in ("feature-on-clippy", "feature-on-doc"):
                        if (step.get("with") or {}).get("shared-key") != "feature-on" or value is not False:
                            self.report(f"{source.name}:{name}", "cache-save-if",
                                        "feature-on lint and doc jobs must only restore the shared cache")
                    if value is False:
                        continue
                    expected = (CACHE_SAVE_CONDITION + " && matrix.shard == 1"
                                if source.name == "ci.yml" and name in ("test", "feature-on-test")
                                else CACHE_SAVE_CONDITION)
                    if not isinstance(value, str) or self.unwrap_expression(value) != expected:
                        self.report(f"{source.name}:{name} step {index + 1}", "cache-save-if",
                                    "rust-cache saves on pull request runs")

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

    def effective_shell(self, workflow, name, step):
        """The step shell overrides job defaults, which override workflow defaults."""
        job = self.job(workflow, name) or {}
        defaults = [((owner.get("defaults") or {}).get("run") or {}).get("shell")
                    for owner in (job, self.docs[workflow])]
        return step.get("shell") or defaults[0] or defaults[1]

    def step_position(self, workflow, name, index, step, command, rule):
        """Returns where step index of a job runs command unconditionally
        under errexit, or -1, and reports syntax the check does not model."""
        shell = self.effective_shell(workflow, name, step)
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

    def check_rehearsal_security_probes(self):
        workflow = "release-rehearsal.yml"
        job = self.job(workflow, "build") or {}
        steps = job.get("steps", [])
        probes = [i for i, step in enumerate(steps)
                  if step.get("name") == REHEARSAL_PROBE_NAME
                  or any(re.search(r"(?:^|[;&|] *)cargo test [^#;&|]*\bvendored_wasm_release_cfg\b", line)
                         for line in self.normalized(self.run_text(step)))]
        rule = "rehearsal-security-probes"
        if len(probes) != 1:
            self.report(workflow, rule, "expected exactly one optimized security probe step")
            return
        index = probes[0]
        builds = [i for i, step in enumerate(steps) if step.get("name") == "Build binaries"]
        if builds != [index - 1]:
            self.report(workflow, rule, "probes must immediately follow Build binaries")
        expected = {"name": REHEARSAL_PROBE_NAME,
                    "if": "matrix.target == 'x86_64-unknown-linux-gnu'",
                    "shell": "bash", "run": [REHEARSAL_PROBE_COMMAND]}
        actual = {**steps[index], "run": self.normalized(self.run_text(steps[index])),
                  "if": self.unwrap_expression(steps[index].get("if", ""))}
        if actual != expected:
            self.report(workflow, rule, "probe step differs from the required guard and command")
        forbidden = r"(?:CARGO_BUILD_JOBS|RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_PROFILE_\w*)"
        for scope, owner in (("workflow", self.docs[workflow]), ("job", job), ("probe", steps[index])):
            for key in (owner.get("env") or {}):
                if re.fullmatch(forbidden, str(key)):
                    self.report(workflow, rule, f"{scope} env: {key} must be unset")
        for earlier, step in enumerate(steps[:index]):
            for line in self.normalized(self.run_text(step)):
                if re.search(r"\$(?:GITHUB_ENV\b|\{GITHUB_ENV\}|env:GITHUB_ENV\b)", line):
                    for key in re.findall(r"\b(" + forbidden + r")(?==|<<)", line):
                        self.report(workflow, rule, f"step {earlier + 1} writes {key} to GITHUB_ENV before probes")
        if "continue-on-error" in job:
            self.report(workflow, rule, "probe job must not suppress failures")

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
        if script is not None and self.normalized(script) != list(BUILD_BODY):
            self.report(str(BUILD_SCRIPT), "release-shared-scripts", "build operations differ from BUILD_BODY")
        smoke = [step for step in (self.job("notarize-smoke.yml", "build") or {}).get("steps", [])
                 if step.get("name") == "Build binaries"]
        if len(smoke) != 1 or self.normalized(self.run_text(smoke[0])) != list(SMOKE_BUILD):
            self.report("notarize-smoke.yml", "release-shared-scripts", "smoke build operations differ from SMOKE_BUILD")
        helper = self.read_script(COPY_HELPER, "release-shared-scripts")
        if helper is not None and self.normalized(helper) != list(COPY_HELPER_BODY):
            self.report(str(COPY_HELPER), "release-shared-scripts", "copy operations differ from COPY_HELPER_BODY")
        self.check_signing_order()

    @classmethod
    def normalized(cls, text):
        """The logical lines of text without blank lines, each run of blanks
        collapsed to one space."""
        return [" ".join(re.split(r"[ \t]+", line.strip(BLANKS)))
                for line in cls.logical_lines(text) if line.strip(BLANKS)]

    def check_signing_order(self):
        script = self.read_script(SIGN_SCRIPT, "signing-order")
        if script is None:
            return
        lines, block = self.normalized(script), list(SIGN_BLOCK)
        if not any(lines[index:index + len(block)] == block for index in range(len(lines))):
            self.report(str(SIGN_SCRIPT), "signing-order", "signing, derivation and packing differ from SIGN_BLOCK")
        if [line for line in lines if "--sign" in line] != [SIGN_LINE]:
            self.report(str(SIGN_SCRIPT), "signing-order", "a codesign call signs another file than stellar-agent")
        if lines[-len(SIGN_FINAL):] != list(SIGN_FINAL):
            self.report(str(SIGN_SCRIPT), "signing-order", "the script does not end by verifying both signatures")
        derive = self.read_script(DERIVE_SCRIPT, "signing-order")
        if derive is not None and self.normalized(derive) != list(DERIVE_BODY):
            self.report(str(DERIVE_SCRIPT), "signing-order", "derivation operations differ from DERIVE_BODY")

    def check_release_gates(self):
        self.check_publish_release_evidence()
        for name in ("sign", "verify-provenance"):
            steps = (self.job("release.yml", name) or {}).get("steps", [])
            installers = [step for step in steps if step.get("name") == "Install cosign"]
            if [step.get("uses") for step in installers] != [
                    COSIGN_INSTALLER]:
                self.report(f"release.yml:{name}", "release-signatures", "requires the pinned cosign installer")
            if [(step.get("with") or {}).get("cosign-release") for step in installers] != [COSIGN_VERSION]:
                self.report(f"release.yml:{name}", "release-signatures", "requires cosign-release: v3.1.4")
        uploads = [step for step in (self.job("release.yml", "sign") or {}).get("steps", [])
                   if (step.get("with") or {}).get("name") == "signatures"]
        if [(step.get("with") or {}).get("if-no-files-found") for step in uploads] != ["error"]:
            self.report("release.yml:sign", "release-signatures", "signature upload requires if-no-files-found: error")
        self.needs("release.yml", "hashes", "verify-packaged", "release-packaged-gate")
        for dependency in ("preflight", "build", "sign-macos"):
            self.needs("release.yml", "verify-packaged", dependency, "release-packaged-gate")
        for workflow in ("release.yml", "release-rehearsal.yml"):
            if self.runs_in_job(workflow, "verify-packaged", ARCHIVE_CHECK, "release-packaged-gate") < 0:
                self.report(workflow, "release-packaged-gate", "verify-packaged does not run the archive check unconditionally")
        self.needs("release.yml", "publish", "verify-provenance", "release-provenance-gate")
        for dependency in ("preflight", "provenance", "hashes", "sign"):
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
            version = "${{ steps.tag.outputs.version }}" if workflow == "publish.yml" else "${{ steps.version.outputs.version }}"
            if any((steps[index].get("env") or {}).get("VERSION") != version for index in checks):
                self.report(workflow, "release-version-binding", "packaged check must use the validated version output")
            if workflow == "release-rehearsal.yml":
                versions = [i for i, step in enumerate(steps) if step.get("id") == "version"]
                if len(versions) != 1 or not builds or versions[0] >= builds[0]:
                    self.report(workflow, "release-version-binding", "workspace version must be read before packaging")
            if builds:
                run = steps[builds[0]].get("run")
                if not 0 <= self.runs_line(run, PACKAGE_START)[0] < self.runs_line(run, PACKAGE_BUILD)[0]:
                    self.report(workflow, "publish-dry-gate", "package verification lacks the freshness timestamp")
        self.needs("publish.yml", "verify-install", "publish", "publish-install-gate")
        install = self.runs_in_job("publish.yml", "verify-install", INSTALL_CHECK, "publish-install-gate")
        if install < 0:
            self.report("publish.yml", "publish-install-gate", "verify-install does not run the install check unconditionally")
        else:
            step = self.job("publish.yml", "verify-install")["steps"][install]
            if (step.get("env") or {}).get("TAG") != "${{ steps.tag.outputs.tag }}":
                self.report("publish.yml", "release-version-binding", "install check must use the validated tag output")

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

    @staticmethod
    def evidence_template_difference(steps):
        """Name the first differing step and field, keeping physical run lines."""
        for index in range(max(len(steps), len(PUBLISH_EVIDENCE_TEMPLATE))):
            location = f"step {index + 1}"
            if index >= len(steps):
                return f"{location} field step: missing"
            if index >= len(PUBLISH_EVIDENCE_TEMPLATE):
                return f"{location} field step: unexpected"
            actual, expected = steps[index], PUBLISH_EVIDENCE_TEMPLATE[index]
            for field in dict.fromkeys([*expected, *actual]):
                if field not in actual or field not in expected:
                    return f"{location} field {field}: missing or unexpected"
                value, wanted = actual[field], expected[field]
                if field == "run" and isinstance(value, str):
                    value = [line.strip(BLANKS) for line in value.split("\n") if line.strip(BLANKS)]
                    wanted = [line.strip(BLANKS) for line in wanted.split("\n") if line.strip(BLANKS)]
                # YAML serialization preserves scalar types, including nested booleans.
                if yaml.safe_dump(value, sort_keys=True) != yaml.safe_dump(wanted, sort_keys=True):
                    return f"{location} field {field}: differs"
        return None

    def check_publish_release_evidence(self):
        workflow, rule = "publish.yml", "publish-release-evidence"
        self.needs(workflow, "publish", "release-evidence", rule)
        if (self.job(workflow, "publish") or {}).get("if") != "${{ !inputs.verify_only }}":
            self.report(workflow, rule, "publish must run exactly on !inputs.verify_only")
        job = self.job(workflow, "release-evidence") or {}
        steps = job.get("steps", [])
        if job.get("needs") not in ("verify", ["verify"]):
            self.report(workflow, rule, "release-evidence must need exactly verify")
        if job.get("runs-on") != "ubuntu-24.04":
            self.report(workflow, rule, "release-evidence must run on ubuntu-24.04")
        if job.get("timeout-minutes") != 15:
            self.report(workflow, rule, "release-evidence must time out after 15 minutes")
        if job.get("permissions") != {"contents": "read", "actions": "read"}:
            self.report(workflow, rule, "release-evidence permissions must be contents: read and actions: read")
        if any(key in job for key in ("if", "continue-on-error", "environment", "secrets", "uses")):
            self.report(workflow, rule, "release-evidence must run unconditionally without an environment or secrets")
        if job.get("env") != PUBLISH_EVIDENCE_ENV:
            self.report(workflow, rule, "release-evidence job env must contain exactly TAG and SOURCE_SHA")
        difference = self.evidence_template_difference(steps)
        if difference:
            self.report(workflow, rule, f"release-evidence template: {difference}")
        # Strip only the permitted token value; scan every remaining key and value.
        scanned_steps = []
        for index, step in enumerate(steps):
            env = dict(step.get("env") or {})
            expected = PUBLISH_EVIDENCE_TEMPLATE[index] if index < len(PUBLISH_EVIDENCE_TEMPLATE) else {}
            if (expected.get("env") == RELEASE_EVIDENCE_ENV
                    and env.get("GH_TOKEN") == "${{ github.token }}"):
                del env["GH_TOKEN"]
            scanned_steps.append(dict(step, env=env))
        inherited = {key: self.docs[workflow][key] for key in ("env", "defaults") if key in self.docs[workflow]}
        scanned = dict(job, steps=scanned_steps)
        self.check_credential_expressions(workflow, {"release-evidence": scanned, **inherited}, rule)
        environments = [inherited.get("env"), job.get("env"), *(step["env"] for step in scanned_steps)]
        for env in environments:
            for key in env or {}:
                if str(key).upper() in TOKEN_ENV:
                    self.report(workflow, rule, f"release-evidence sets forbidden token variable {key}")

    def check_release_wasm_gate(self):
        rule = "release-wasm-gate"
        job = self.job("release.yml", "vendored-wasm") or {}
        if job.get("uses") != "./.github/workflows/vendored-wasm.yml" or any(
                key in job for key in ("if", "with", "secrets", "continue-on-error")):
            self.report("release.yml", rule, "vendored-wasm must call the local workflow unconditionally without inputs or secrets")
        self.needs("release.yml", "sign-macos", "vendored-wasm", rule)
        sign_macos = self.job("release.yml", "sign-macos") or {}
        if "if" in sign_macos:
            self.report("release.yml", rule, "sign-macos must not set if")
        if "continue-on-error" in sign_macos:
            self.report("release.yml", rule, "sign-macos must not set continue-on-error")
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
                    self.report(where, rule, f"cache guard must lead with {guard}")
                uses = str(step.get("uses") or "")
                if re.match(r"actions/cache/save@", uses, re.IGNORECASE):
                    if condition != WASM_SAVE_CONDITION:
                        self.report(where, rule, f"cache save must run exactly on {WASM_SAVE_CONDITION}")
                elif not re.match(r"actions/cache/restore@", uses, re.IGNORECASE):
                    self.report(where, rule, f"{name} step {index + 1} uses {uses}, which saves outside a save step")
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

    def check_wallet_toolchain(self):
        """Every wallet gate installs the repository's exact Rust version."""
        rule = "wallet-toolchain"
        try:
            toolchain = tomllib.loads((self.root / "rust-toolchain.toml").read_text())
            channel = (toolchain.get("toolchain") or {}).get("channel")
        except (OSError, tomllib.TOMLDecodeError) as err:
            self.report("rust-toolchain.toml", rule, str(err))
            return
        if not isinstance(channel, str) or not re.fullmatch(r"\d+\.\d+\.\d+", channel):
            self.report("rust-toolchain.toml", rule, "channel must be an exact Rust version")
            return

        directory = self.root / WORKFLOW_DIR
        paths = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml"),
                        *(self.root / ".github/actions").rglob("action.yml")])
        for path in paths:
            relative = path.relative_to(self.root)
            workflow = relative.parent == WORKFLOW_DIR
            doc = (self.docs.get(path.name) if workflow and path.name in WORKFLOWS
                   else self.load(relative))
            if not isinstance(doc, dict):
                continue
            release = workflow and path.name in RELEASE_WORKFLOWS
            expected = "${{ env.RELEASE_TOOLCHAIN }}" if release else channel
            if release and (doc.get("env") or {}).get("RELEASE_TOOLCHAIN") != channel:
                self.report(str(relative), rule, "RELEASE_TOOLCHAIN must equal the repository channel")

            scopes = [(str(relative), doc)]
            steps = []
            for name, job in (doc.get("jobs") or {}).items():
                if isinstance(job, dict):
                    where = f"{relative}:{name}"
                    scopes.append((where, job))
                    steps.extend((f"{where} step {i + 1}", step)
                                 for i, step in enumerate(job.get("steps") or []))
            steps.extend((f"{relative} step {i + 1}", step)
                         for i, step in enumerate((doc.get("runs") or {}).get("steps") or []))
            for where, step in steps:
                if not isinstance(step, dict):
                    continue
                scopes.append((where, step))
                if str(step.get("uses") or "").lower().startswith("dtolnay/rust-toolchain@"):
                    if (step.get("with") or {}).get("toolchain") != expected:
                        self.report(where, rule, f"with.toolchain must be {expected!r}")

            if workflow and path.name == "vendored-wasm.yml":
                continue
            for where, scope in scopes:
                if "RUSTUP_TOOLCHAIN" in (scope.get("env") or {}):
                    self.report(where, rule, "RUSTUP_TOOLCHAIN may only be set by the release pin line")
            for where, step in steps:
                if not isinstance(step, dict):
                    continue
                for line in self.logical_lines(self.run_text(step)):
                    if release and line.strip() == TOOLCHAIN_PIN:
                        continue
                    if re.search(r"\brustup\s+(?:toolchain\s+install|default|override)\b|\bcargo\s+\+\S+", line):
                        self.report(where, rule, "run must not install or override the toolchain")
                    if re.search(r"\bRUSTUP_TOOLCHAIN\s*[\"']?\s*=", line):
                        self.report(where, rule, "RUSTUP_TOOLCHAIN may only be set by the release pin line")

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

    def check_changelog_workflow(self):
        workflow, rule = "changelog.yml", "changelog-check"
        doc = self.docs.get(workflow, {})
        triggers = doc.get("on", doc.get(True))
        triggers = triggers if isinstance(triggers, dict) else {}
        if "push" not in triggers:
            self.report(workflow, rule, "push trigger is absent")
        if "pull_request" not in triggers:
            self.report(workflow, rule, "pull_request trigger is absent")
        events = ["opened", "synchronize", "reopened", "edited"]
        if (set(triggers) - {"push", "pull_request"}
                or triggers.get("push") is not None
                or ("pull_request" in triggers and triggers["pull_request"] != {"types": events})):
            self.report(workflow, rule, "event filters or types differ")
        job = self.job(workflow, "changelog")
        if job is None:
            self.report(workflow, rule, "missing changelog job")
            return
        if ("if" in job or "needs" in job or "continue-on-error" in job
                or job.get("runs-on") != "ubuntu-24.04" or set(doc.get("jobs", {})) != {"changelog"}
                or doc.get("permissions") != {"contents": "read"}
                or job.get("permissions", {"contents": "read"}) != {"contents": "read"}):
            self.report(workflow, rule, "changelog job can be bypassed or changes its execution contract")
        steps = job.get("steps", [])

        def named(name):
            found = [(i, step) for i, step in enumerate(steps) if step.get("name") == name]
            return found[0] if len(found) == 1 else (-1, {})

        _, check = named("Check changelog fragments")
        if not check:
            self.report(workflow, rule, "missing fragment check step")
        else:
            if self.may_skip(check) or self.effective_shell(workflow, "changelog", check) not in (None, "bash"):
                self.report(workflow, rule, "fragment check can be bypassed")
            if self.run_text(check).strip() != "python3 .github/scripts/changelog.py check":
                self.report(workflow, rule, "fragment check command differs")
        _, test = named("Test changelog fragments")
        if not test:
            self.report(workflow, rule, "missing fragment test step")
        elif (self.may_skip(test) or self.effective_shell(workflow, "changelog", test) not in (None, "bash")
              or self.run_text(test).strip() != "python3 .github/scripts/test-changelog.py"):
            self.report(workflow, rule, "fragment test can be bypassed or its command differs")
        guard_index, guard = named("Protect integration changelog")
        fetch_index, fetch = named("Fetch main for changelog protection")
        checkouts = [(i, step) for i, step in enumerate(steps)
                     if str(step.get("uses", "")).startswith("actions/checkout@")]
        checkout_index, checkout = checkouts[0] if len(checkouts) == 1 else (-1, {})
        options = checkout.get("with", {})
        setup = [step for step in steps if str(step.get("uses", "")).startswith("actions/setup-python@")]
        if (not checkout or self.may_skip(checkout) or options.get("fetch-depth") != 0
                or "ref" in options or options.get("persist-credentials") is not False
                or not re.fullmatch(r"actions/checkout@[0-9a-f]{40}", str(checkout.get("uses", "")))
                or len(setup) != 1 or self.may_skip(setup[0])
                or not re.fullmatch(r"actions/setup-python@[0-9a-f]{40}", str(setup[0].get("uses", "")))
                or str(setup[0].get("with", {}).get("python-version")) != "3.13"
                or not fetch or self.may_skip(fetch) or fetch.get("shell") != "bash"
                or self.run_text(fetch).strip() != CHANGELOG_FETCH
                or self.step_position(workflow, "changelog", fetch_index, fetch, CHANGELOG_FETCH, rule) < 0
                or not checkout_index < fetch_index
                or (guard and fetch_index >= guard_index)):
            self.report(workflow, rule, "checkout and main fetch must supply full history before the guard")
        if not guard:
            self.report(workflow, "changelog-guard", "missing integration guard")
            return
        condition = self.unwrap_expression(guard.get("if", ""))
        if condition != CHANGELOG_CONDITION:
            self.report(workflow, "changelog-guard", "integration guard condition differs")
        expected_env = {"BASE_SHA": "${{ github.event.pull_request.base.sha }}",
                        "HEAD_SHA": "${{ github.event.pull_request.head.sha }}"}
        if guard.get("env") != expected_env:
            self.report(workflow, "changelog-guard", "integration guard event SHAs differ")
        if self.run_text(guard).strip() != CHANGELOG_GUARD:
            self.report(workflow, "changelog-guard", "integration guard command differs")
        if "continue-on-error" in guard or guard.get("shell") != "bash":
            self.report(workflow, "changelog-guard", "integration guard shell or failure behavior differs")

    def check_release_fragments(self):
        workflow, rule = "release.yml", "release-fragments"
        job = self.job(workflow, "preflight") or {}
        steps = job.get("steps", [])
        headers = [i for i, step in enumerate(steps) if step.get("name") == "Verify CHANGELOG version header exists"]
        pending = [(i, step) for i, step in enumerate(steps)
                   if step.get("name") == "Verify no pending changelog fragments"]
        if (len(headers) != 1 or len(pending) != 1 or pending[0][0] != headers[0] + 1
                or self.may_skip(job) or "needs" in job or self.may_skip(pending[0][1])
                or pending[0][1].get("shell") != "bash"
                or self.run_text(pending[0][1]).strip() != PENDING_FRAGMENTS):
            self.report(workflow, rule, "pending fragments step must follow the version header check without bypasses")

    def check_release_ci_evidence(self):
        workflow, rule = "release.yml", "release-ci-evidence"
        doc = self.docs.get(workflow, {})
        job = self.job(workflow, "preflight") or {}
        if job.get("permissions") != RELEASE_EVIDENCE_PERMISSIONS or self.may_skip(job):
            self.report(workflow, rule, "preflight must hold exactly contents: read and actions: read, unconditionally")
        for owner, node in [("the workflow", doc),
                            *((name, other) for name, other in (doc.get("jobs") or {}).items()
                              if name != "preflight" and isinstance(other, dict))]:
            permissions = node.get("permissions")
            if (owner == "provenance" and permissions == RELEASE_PROVENANCE_PERMISSIONS
                    and node.get("uses") == RELEASE_PROVENANCE_USES and "steps" not in node):
                continue
            if isinstance(permissions, str) or (isinstance(permissions, dict) and "actions" in permissions):
                self.report(workflow, rule, f"{owner} must hold no actions scope")
        steps = job.get("steps", [])
        evidence = [i for i, step in enumerate(steps) if step.get("name") == RELEASE_EVIDENCE_STEP]
        ancestry = [i for i, step in enumerate(steps)
                    if any(ANCESTRY_CALL.match(line) for line in self.logical_lines(step.get("run")))]
        if len(evidence) != 1 or len(ancestry) != 1 or evidence[0] != ancestry[0] + 1:
            self.report(workflow, rule, "the evidence step must directly follow the ancestry step")
        for index in evidence:
            step = steps[index]
            if self.may_skip(step) or self.effective_shell(workflow, "preflight", step) not in (None, "bash") \
                    or self.run_text(step).strip() != RELEASE_EVIDENCE_COMMAND \
                    or step.get("env") != RELEASE_EVIDENCE_ENV:
                self.report(workflow, rule,
                            "the evidence step must run its command unconditionally in bash with only the token")
        for owner, env in [("workflow env", doc.get("env")), ("job env", job.get("env")),
                           *((f"step {i + 1}", step.get("env")) for i, step in enumerate(steps) if i not in evidence)]:
            if isinstance(env, dict) and {str(key).upper() for key in env} & TOKEN_ENV:
                self.report(workflow, rule, f"{owner} sets a token variable")
        # Every other expression of the preflight, and of the env and defaults
        # it inherits, reads neither secrets nor the token.
        scanned = dict(job, steps=[{key: value for key, value in step.items() if not (i in evidence and key == "env")}
                                   for i, step in enumerate(steps)])
        inherited = {key: doc[key] for key in ("env", "defaults") if key in doc}
        self.check_credential_expressions(f"{workflow}:preflight", {"preflight": scanned, **inherited}, rule)

    def check_ci_feature_jobs(self):
        profile = self.read_script(pathlib.Path(".config/nextest.toml"), "ci-feature-jobs")
        if profile is not None and profile != NEXTEST_PROFILE:
            self.report(".config/nextest.toml", "ci-feature-jobs", "nextest profile differs")
        for name in ("feature-on-clippy", "feature-on-doc"):
            cache_job = self.job("ci.yml", name) or {}
            caches = [step for step in cache_job.get("steps", [])
                      if RUST_CACHE_ACTION.match(str(step.get("uses") or ""))]
            if len(caches) != 1:
                self.report("ci.yml", "cache-save-if", f"{name} must have one shared cache restore")
        for name, expected in CI_TEST_JOBS.items():
            actual = yaml.safe_dump(self.job("ci.yml", name), sort_keys=True)
            expected = yaml.safe_dump(expected, sort_keys=True)
            if actual != expected:
                self.report("ci.yml", "ci-feature-jobs", f"test layout differs: {name}")
        for name, commands in CI_FEATURE_JOBS.items():
            job = self.job("ci.yml", name)
            if job is None:
                self.report("ci.yml", "ci-feature-jobs", f"missing {name}")
                continue
            if name in DOCS_ONLY_SKIPPED_JOBS:
                needs = job.get("needs")
                documented = (isinstance(job.get("if"), str)
                              and self.unwrap_expression(job["if"]) == DOCS_ONLY_CONDITION
                              and needs in ("changes", ["changes"]))
                if not documented or "continue-on-error" in job:
                    self.report("ci.yml", "ci-feature-jobs", f"{name} can be bypassed")
            elif name == "feature-discipline":
                if (self.unwrap_expression(str(job.get("if", ""))) != "!cancelled()"
                        or job.get("needs") not in ("changes", ["changes"]) or "continue-on-error" in job):
                    self.report("ci.yml", "ci-feature-jobs", f"{name} can be bypassed")
            elif "if" in job or "continue-on-error" in job:
                self.report("ci.yml", "ci-feature-jobs", f"{name} can be bypassed")
            for step in job.get("steps", []):
                if ("continue-on-error" in step or ("if" in step and not (
                        name == "feature-discipline" and self.selftest_commands(step)
                        and step["if"] == "needs.changes.outputs.selftest_rust != 'false'"))):
                    self.report("ci.yml", "ci-feature-jobs", f"{name} step can be bypassed")
            for command in commands:
                if self.runs_in_job("ci.yml", name, command, "ci-feature-jobs") < 0:
                    self.report("ci.yml", "ci-feature-jobs", f"{name} does not run unconditionally: {command}")
        job = self.job("ci.yml", DOCS_TESTS_JOB)
        if job is None:
            self.report("ci.yml", "ci-feature-jobs", f"missing {DOCS_TESTS_JOB}")
        else:
            documented = (isinstance(job.get("if"), str)
                          and self.unwrap_expression(job["if"]) == DOCS_TESTS_CONDITION
                          and job.get("needs") in ("changes", ["changes"]))
            if not documented or "continue-on-error" in job:
                self.report("ci.yml", "ci-feature-jobs", f"{DOCS_TESTS_JOB} can be bypassed")
            for step in job.get("steps", []):
                if "if" in step or "continue-on-error" in step:
                    self.report("ci.yml", "ci-feature-jobs", f"{DOCS_TESTS_JOB} step can be bypassed")
            for command in DOCS_TESTS_COMMANDS:
                if self.runs_in_job("ci.yml", DOCS_TESTS_JOB, command, "ci-feature-jobs") < 0:
                    self.report("ci.yml", "ci-feature-jobs",
                                f"{DOCS_TESTS_JOB} does not run unconditionally: {command}")
        for (workflow, name), (condition, commands) in CONDITIONED_FEATURE_JOBS.items():
            job = self.job(workflow, name)
            if job is None:
                self.report(workflow, "ci-feature-jobs", f"missing {name}")
                continue
            documented = isinstance(job.get("if"), str) and self.unwrap_expression(job["if"]) == condition
            if not documented or "continue-on-error" in job:
                self.report(workflow, "ci-feature-jobs", f"{name} can be bypassed")
            for step in job.get("steps", []):
                # The coverage gate guards report consumers by its measured output;
                # cancel rejections may run under cancelled() and only fail.
                if ("if" in step or "continue-on-error" in step) and not (
                        workflow == COVERAGE_WORKFLOW and name == COVERAGE_GATE
                        and isinstance(step.get("if"), str)
                        and "continue-on-error" not in step
                        and ((self.unwrap_expression(step["if"]) == COVERAGE_CANCEL_CONDITION
                              and self.normalized(self.run_text(step)) == [COVERAGE_CANCEL_RUN])
                             or (self.coverage_measured_step(step) and self.unwrap_expression(str(step["if"])) == COVERAGE_MEASURED))):
                    self.report(workflow, "ci-feature-jobs", f"{name} step can be bypassed")
            for command in commands:
                if self.runs_in_job(workflow, name, command, "ci-feature-jobs") < 0:
                    self.report(workflow, "ci-feature-jobs", f"{name} does not run unconditionally: {command}")
        script = self.read_script(HOST_SCRIPT, "ci-feature-jobs")
        for command in HOST_CHECKS:
            position, problem = self.runs_line(script, command) if script is not None else (0, None)
            if problem:
                self.report(str(HOST_SCRIPT), "ci-feature-jobs", f"unmodelled shell syntax around {command}: {problem}")
            elif position < 0:
                self.report(str(HOST_SCRIPT), "ci-feature-jobs", f"does not run unconditionally: {command}")

    def check_skill_archive(self):
        job = self.job("ci.yml", "release-contracts") or {}
        steps = [step for step in job.get("steps", [])
                 if step.get("name") == "Check the skill archive"]
        if len(steps) != 1:
            self.report("ci.yml", "skill-archive", "expected exactly one skill archive step")
            return
        step = steps[0]
        shell = self.effective_shell("ci.yml", "release-contracts", step)
        if (self.unwrap_expression(str(job.get("if", ""))) != "!cancelled()"
                or job.get("needs") not in ("changes", ["changes"]) or "continue-on-error" in job
                or "continue-on-error" in step or shell not in (None, "bash")):
            self.report("ci.yml", "skill-archive", "skill archive check can be bypassed")
        if self.unwrap_expression(step.get("if", "")) != SKILL_ARCHIVE_CONDITION:
            self.report("ci.yml", "skill-archive", "skill archive condition differs from the integration branch exception")
        if self.run_text(step).strip() != ".github/scripts/package-skill.sh --check":
            self.report("ci.yml", "skill-archive", "skill archive command differs from package-skill.sh --check")

    def check_ci_triggers(self):
        doc = self.docs.get("ci.yml", {})
        triggers = doc.get("on", doc.get(True))
        if not isinstance(triggers, dict):
            self.report("ci.yml", "ci-triggers", "expected push and pull_request triggers with branch filters")
            return
        for event in sorted(set(triggers) - {"push", "pull_request", "workflow_dispatch"}):
            self.report("ci.yml", "ci-triggers",
                        f"archive condition must be re-evaluated for the new event: {event}")
        if "push" not in triggers:
            self.report("ci.yml", "ci-triggers", "push trigger is absent")
        # The release preflight accepts a dispatched run as evidence; it takes no inputs.
        if "workflow_dispatch" not in triggers or triggers["workflow_dispatch"] not in (None, {}):
            self.report("ci.yml", "ci-triggers", "workflow_dispatch must be a trigger without inputs")
        pull_request = triggers.get("pull_request")
        branches = pull_request.get("branches") if isinstance(pull_request, dict) else None
        if not isinstance(branches, list) or "main" not in branches:
            self.report("ci.yml", "ci-triggers", "pull_request branches must include main")

    def check_ci_result(self):
        workflow, rule = "ci.yml", "ci-result"
        jobs = self.docs.get(workflow, {}).get("jobs", {})
        job = jobs.get("ci-result", {})
        expected = set(jobs) - {"ci-result"}
        if job.get("name") != "ci-result (${{ github.base_ref || github.ref_name }})":
            self.report(workflow, rule, "name must identify the base branch")
        if (self.unwrap_expression(str(job.get("if", ""))) != "always()"
                or job.get("runs-on") != "ubuntu-24.04"
                or job.get("permissions") != {"contents": "read"}
                or "continue-on-error" in job):
            self.report(workflow, rule, "job must always run with read-only permissions and fail on errors")
        if job.get("timeout-minutes") != 10:
            self.report(workflow, rule, "job must have timeout-minutes: 10")
        needs = job.get("needs")
        if not isinstance(needs, list) or set(needs) != expected:
            self.report(workflow, rule, "needs must include every other CI job")
        script = self.read_script(pathlib.PurePosixPath(".github/scripts/ci-result.py"), rule)
        docs_required = set()
        for name in sorted(expected):
            condition = self.unwrap_expression(str(jobs[name].get("if", "")))
            if ((name == DOCS_TESTS_JOB and condition == DOCS_TESTS_CONDITION)
                    or (name != DOCS_TESTS_JOB and "if" not in jobs[name])
                    or (name in ("feature-discipline", "release-contracts") and condition == "!cancelled()")):
                docs_required.add(name)
            elif name == DOCS_TESTS_JOB or condition != DOCS_ONLY_CONDITION:
                self.report(workflow, rule, f"{name} has an unsupported docs-only job condition")
        for constant, wanted, message in (
                ("EXPECTED_JOBS", expected, "job set must equal every other CI job"),
                ("DOCS_REQUIRED", docs_required, "DOCS_REQUIRED must match CI docs-only job conditions")):
            try:
                assignments = [node for node in ast.parse(script or "").body
                               if isinstance(node, ast.Assign)
                               and any(isinstance(target, ast.Name) and target.id == constant
                                       for target in node.targets)]
                actual = ast.literal_eval(assignments[0].value) if len(assignments) == 1 else None
                if actual != wanted:
                    raise ValueError("job set differs")
            except (ValueError, SyntaxError, TypeError):
                self.report(workflow, rule, f"ci-result.py {message}")
        steps = job.get("steps", [])
        for index, step in enumerate(steps):
            condition = "always() && cancelled()" if index in (0, len(steps) - 1) else "always()"
            if (self.unwrap_expression(str(step.get("if", ""))) != condition
                    or "continue-on-error" in step):
                self.report(workflow, rule, "every step must always run and fail on errors")
        first = steps[0] if steps else {}
        if (self.unwrap_expression(str(first.get("if", ""))) != "always() && cancelled()"
                or self.run_text(first).strip() != "exit 1"):
            self.report(workflow, rule, "first step must reject cancellation")
        last = steps[-1] if steps else {}
        if (len(steps) < 2 or self.unwrap_expression(str(last.get("if", ""))) != "always() && cancelled()"
                or self.run_text(last).strip() != "exit 1"):
            self.report(workflow, rule, "last step must reject cancellation")
        checkouts = [i for i, step in enumerate(steps)
                     if str(step.get("uses", "")).startswith("actions/checkout@")
                     and (step.get("with") or {}).get("persist-credentials") is False]
        checks = [(i, step) for i, step in enumerate(steps)
                  if self.run_text(step).strip() == "python3 .github/scripts/ci-result.py"]
        if (len(checks) != 1 or len(checkouts) != 1 or not 0 < checkouts[0] < checks[0][0]
                or checks[0][1].get("env") != {"NEEDS_JSON": "${{ toJSON(needs) }}",
                                              "DOCS_ONLY": "${{ needs.changes.outputs.docs_only }}"}):
            self.report(workflow, rule, "checkout must precede the result script with its exact environment")

    def check_docs_classifier(self):
        env = {"EVENT_NAME": "${{ github.event_name }}", "BASE_REF": "${{ github.base_ref }}",
               "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
               "HEAD_SHA": "${{ github.event.pull_request.head.sha }}", "REF": "${{ github.ref }}",
               "BEFORE_SHA": "${{ github.event.before }}", "AFTER_SHA": "${{ github.event.after }}",
               "FORCED": "${{ github.event.forced }}"}
        for workflow in ("ci.yml", "coverage.yml"):
            doc = self.docs.get(workflow, {})
            triggers = doc.get("on", doc.get(True))
            triggers = triggers if isinstance(triggers, dict) else {}
            push = triggers.get("push")
            push = push if isinstance(push, dict) else {}
            if "paths" in push or "paths-ignore" in push:
                self.report(workflow, "docs-classifier", "push must have no paths filter")
            job = self.job(workflow, "changes") or {}
            steps = job.get("steps", [])
            classifiers = [step for step in steps if step.get("id") == "classify"]
            command = 'python3 .github/scripts/classify-docs-only.py >> "$GITHUB_OUTPUT"'
            outputs = {"docs_only": "${{ steps.classify.outputs.docs_only }}"}
            if workflow == "ci.yml":
                command += '\npython3 .github/scripts/classify-self-tests.py >> "$GITHUB_OUTPUT"'
                outputs.update({f"selftest_{group}": "${{ steps.classify.outputs.selftest_" + group + " }}"
                                for group in SELFTEST_GROUPS})
            if (len(classifiers) != 1 or classifiers[0].get("env") != env
                    or self.run_text(classifiers[0]).strip() != command
                    or self.may_skip(classifiers[0])
                    or "if" in job or "needs" in job
                    or "continue-on-error" in job
                    or job.get("outputs") != outputs):
                self.report(workflow, "docs-classifier", "changes must call the classifier with the shared environment")
            if not any(str(step.get("uses", "")).startswith("actions/checkout@")
                       and (step.get("with") or {}).get("fetch-depth") == 0
                       and not self.may_skip(step) for step in steps):
                self.report(workflow, "docs-classifier", "changes must check out full history")
        for step in (self.job("ci.yml", "docs-tests") or {}).get("steps", []):
            if RUST_CACHE_ACTION.match(str(step.get("uses", ""))) and (step.get("with") or {}).get("save-if") is not False:
                self.report("ci.yml", "docs-classifier", "docs-tests must never save its partial test cache")


    @classmethod
    def selftest_commands(cls, step):
        return [line for line in cls.normalized(cls.run_text(step))
                if re.search(r'^(?:bash |python3 |"\$RUNNER_TEMP/[^"]+/bin/python" )?\.github/scripts/test-|--mutations', line)]

    def check_selftest_selection(self):
        for owner, commands in SELFTESTS.items():
            workflow, name = owner.split(":")
            job = self.job(workflow, name) or {}
            if workflow == "ci.yml" and (
                    job.get("needs") not in ("changes", ["changes"])
                    or self.unwrap_expression(str(job.get("if", ""))) != "!cancelled()"
                    or "continue-on-error" in job):
                self.report(workflow, "selftest-selection", f"{name} must run after changes even on failure")
            seen = set()
            for step in job.get("steps", []):
                tests = self.selftest_commands(step)
                if not tests:
                    # The archive rule owns the sole check-step exception,
                    # including its exact SKILL_ARCHIVE_CONDITION and errors.
                    archive = (owner == "ci.yml:release-contracts"
                               and step.get("name") == "Check the skill archive")
                    if self.may_skip(step) and not archive:
                        self.report(workflow, "selftest-checks", f"{name}: check steps must be unconditional")
                    continue
                seen.update(tests)
                groups = {commands.get(command) for command in tests}
                prefix = "steps.sel" if workflow == "install-surface.yml" else "needs.changes"
                if len(groups) != 1 or not groups.issubset(SELFTEST_GROUPS):
                    self.report(workflow, "selftest-selection", f"{name}: unknown or mixed self-test group")
                    continue
                group = next(iter(groups))
                if step.get("if") != f"{prefix}.outputs.selftest_{group} != 'false'":
                    self.report(workflow, "selftest-selection", f"{name}: self-test condition must select {group}")
                if ("continue-on-error" in step or self.suppresses(step)
                        or any(line not in tests
                               for line in self.normalized(self.run_text(step)))):
                    self.report(workflow, "selftest-checks", f"{name}: self-tests must be separate and fail on errors")
            if seen != set(commands):
                self.report(workflow, "selftest-selection", f"{name}: self-test command inventory differs")
        workflow = "install-surface.yml"
        steps = (self.job(workflow, "install-surface") or {}).get("steps", [])
        checkout = steps[0] if steps else {}
        selector = steps[1] if len(steps) > 1 else {}
        env = {"EVENT_NAME": "${{ github.event_name }}", "BASE_REF": "${{ github.base_ref }}",
               "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
               "HEAD_SHA": "${{ github.event.pull_request.head.sha }}", "REF": "${{ github.ref }}",
               "BEFORE_SHA": "${{ github.event.before }}", "AFTER_SHA": "${{ github.event.after }}",
               "FORCED": "${{ github.event.forced }}"}
        if (not str(checkout.get("uses", "")).startswith("actions/checkout@")
                or (checkout.get("with") or {}).get("fetch-depth") != 0 or self.may_skip(checkout)
                or selector.get("id") != "sel" or not selector.get("name") or self.may_skip(selector)
                or selector.get("env") != env or self.run_text(selector).strip() !=
                'python3 .github/scripts/classify-self-tests.py >> "$GITHUB_OUTPUT"'):
            self.report(workflow, "selftest-selector", "full checkout must immediately precede the named selector")

    def check_push_concurrency(self):
        for workflow in ("ci.yml", "coverage.yml", "install-surface.yml"):
            concurrency = self.docs.get(workflow, {}).get("concurrency")
            concurrency = concurrency if isinstance(concurrency, dict) else {}
            group = "${{ github.workflow }}-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}"
            if (concurrency.get("group") != group
                    or self.unwrap_expression(str(concurrency.get("cancel-in-progress", ""))) != "github.event_name == 'pull_request'"):
                self.report(workflow, "push-concurrency", "only pull request runs may share a group or cancel predecessors")
        doc = self.docs.get("vendored-wasm.yml", {})
        triggers = doc.get("on", doc.get(True))
        triggers = triggers if isinstance(triggers, dict) else {}
        for event in ("push", "pull_request"):
            trigger = triggers.get(event)
            branches = trigger.get("branches") if isinstance(trigger, dict) else None
            if not isinstance(branches, list) or set(branches) != {"main", "next"}:
                self.report("vendored-wasm.yml", "wasm-branches", f"{event} must include main and next")

    def check_apt_retries(self):
        directory = self.root / WORKFLOW_DIR
        for path in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):
            doc = self.docs.get(path.name) if path.name in WORKFLOWS else self.load(WORKFLOW_DIR / path.name)
            if not isinstance(doc, dict):
                continue
            for name, job in (doc.get("jobs") or {}).items():
                for index, step in enumerate(job.get("steps", [])):
                    for line in self.logical_lines(self.run_text(step)):
                        line = re.split(r"(?<![^ \t])#", line, maxsplit=1)[0]
                        for match in APT_GET_CALL.finditer(line):
                            arguments = ARGUMENTS_END.split(line[match.end():], maxsplit=1)[0]
                            if not APT_RETRIES.search(arguments):
                                self.report(f"{path.name}:{name} step {index + 1}", "apt-retries",
                                            "apt-get call lacks -o Acquire::Retries=3")

    def check_release_checks(self):
        self.check_shared_build()
        self.check_rehearsal_security_probes()
        self.check_release_gates()
        self.check_unconditional()
        self.check_verification_credentials()
        self.check_verify_matrix()
        self.check_release_cache()
        self.check_release_wasm_gate()
        self.check_release_publish_sums()
        self.check_release_toolchain()
        self.check_ci_feature_jobs()
        self.check_skill_archive()
        self.check_ci_triggers()

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
            self.check_coverage_names(workflow, jobs)
            self.check_coverage_split(workflow, jobs)
            self.check_coverage_gate(workflow, jobs)
            self.check_coverage_seed(workflow, doc)
            self.check_coverage_attempt(workflow, jobs)
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

    @staticmethod
    def local_references(doc):
        """Yields the local uses: values of a workflow's jobs and steps or of
        an action's steps."""
        steps = []
        for job in (doc.get("jobs") or {}).values():
            if isinstance(job, dict):
                yield job.get("uses")
                steps.extend(job.get("steps") or [])
        runs = doc.get("runs")
        if isinstance(runs, dict):
            steps.extend(runs.get("steps") or [])
        for step in steps:
            if isinstance(step, dict):
                yield step.get("uses")

    def resolve_local(self, reference):
        """The file a local uses: value names: a workflow file, or the
        action.yml or action.yaml of an action directory; None when it names
        no file inside the repository."""
        relative = pathlib.PurePosixPath(reference[2:])
        if ".." in relative.parts:
            return None
        path = self.root / relative
        if path.is_dir():
            for name in ("action.yml", "action.yaml"):
                if (path / name).is_file():
                    return relative / name
            return None
        return relative if path.is_file() else None

    def check_release_vars(self):
        rule = "release-vars"
        pending, seen = [WORKFLOW_DIR / "release.yml"], set()
        while pending:
            relative = pending.pop(0)
            if relative in seen:
                continue
            seen.add(relative)
            # A listed workflow that does not load is reported as unreadable once.
            if relative.parent == WORKFLOW_DIR and relative.name in WORKFLOWS:
                doc = self.docs.get(relative.name)
            else:
                doc = self.load(relative)
            if not isinstance(doc, dict):
                continue
            try:
                expressions = list(self.expression_values(doc))
            except ValueError as err:
                self.report(str(relative), rule, str(err))
                expressions = []
            for expression in expressions:
                if VARS_CONTEXT.search(EXPRESSION_STRING.sub("''", expression)):
                    self.report(str(relative), rule, f"an expression reads the vars context: {expression}")
            for reference in self.local_references(doc):
                if not isinstance(reference, str) or not reference.startswith("./"):
                    continue
                target = self.resolve_local(reference)
                if target is None:
                    self.report(str(relative), rule, f"local reference {reference} names no file")
                else:
                    pending.append(target)

    def run(self):
        for workflow in WORKFLOWS:
            self.check_workflow(workflow)
        self.check_apt_retries()
        self.check_cache_save_if()
        self.check_composite_expressions()
        self.check_release_checks()
        self.check_wallet_toolchain()
        self.check_release_vars()
        self.check_changelog_workflow()
        self.check_release_fragments()
        self.check_release_ci_evidence()
        self.check_ci_result()
        self.check_docs_classifier()
        self.check_push_concurrency()
        self.check_selftest_selection()
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
