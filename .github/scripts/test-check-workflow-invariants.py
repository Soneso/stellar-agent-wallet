#!/usr/bin/env python3
"""Offline regression checks for check-workflow-invariants.py.

Copies the workflows, the composite action, and the scripts into a temporary
root. Each failing case applies its edits and must make the check exit 1. For
each rule and message fragment the case expects, in order, a line of its
output after the previous match must name the rule and hold the fragment. The
optional exact-count field also pins the number of reported violations. The
unmodified copy must pass, and so must each copy that a PASSING entry edits
into another accepted form. Each replacement changes every occurrence and must match the expected number
of times; a case whose text drifted fails. A fixture read from the live
workflows must match exactly once, or the run stops before any case.
Each named mutation of the check then must fail the entries it names, and
the restored check must pass them. With --case LABEL, the run checks the
unmodified copy and that one failing case or PASSING entry, and the
mutations that name it.
Use --decision-case docs|measured|invalid for one decision-shell branch, or
--coverage-behavior for the workflow expression event table alone.
"""

import ast
import hashlib
import itertools
import os
import pathlib
import pickle
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github/scripts/check-workflow-invariants.py"
RELEASE = ".github/workflows/release.yml"
PUBLISH = ".github/workflows/publish.yml"
SMOKE = ".github/workflows/notarize-smoke.yml"
TRIAGE = ".github/workflows/triage.yml"
TRIAGE_REVIEW = ".github/workflows/triage-review.yml"
TRIAGE_SWEEP = ".github/workflows/triage-sweep.yml"
WELCOME = ".github/workflows/welcome.yml"
COVERAGE = ".github/workflows/coverage.yml"
REHEARSAL = ".github/workflows/release-rehearsal.yml"
CI = ".github/workflows/ci.yml"
TESTNET = ".github/workflows/testnet.yml"
CHANGELOG = ".github/workflows/changelog.yml"
CHANGELOG_CONDITION = "github.event_name == 'pull_request' && github.base_ref == 'next'"
CHANGELOG_IF = f"        if: {CHANGELOG_CONDITION}\n"
CHANGELOG_ARGS = 'guard --base "$BASE_SHA" --head "$HEAD_SHA" --main-ref refs/remotes/origin/main'
CHANGELOG_COMMAND = ('set -euo pipefail\n'
                     'GUARD_ENTRY=$(git ls-tree "$BASE_SHA" -- .github/scripts/changelog.py)\n'
                     'if [ -n "$GUARD_ENTRY" ]; then\n'
                     '  git show "$BASE_SHA:.github/scripts/changelog.py" | python3 - ' + CHANGELOG_ARGS + '\n'
                     'else\n'
                     '  python3 .github/scripts/changelog.py ' + CHANGELOG_ARGS + '\n'
                     'fi')


def changelog_run(command):
    return "        run: |\n" + "".join("          " + line + "\n" for line in command.splitlines())


CHANGELOG_RUN = changelog_run(CHANGELOG_COMMAND)
CHANGELOG_FETCH = ("      - name: Fetch main for changelog protection\n        shell: bash\n"
                   "        run: git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main\n")
CHANGELOG_CHECK = ("      - name: Check changelog fragments\n"
                   "        run: python3 .github/scripts/changelog.py check\n")
CHANGELOG_TEST = ("      - name: Test changelog fragments\n"
                  "        run: python3 .github/scripts/test-changelog.py\n")
CHANGELOG_GUARD = ("      - name: Protect integration changelog\n" + CHANGELOG_IF + "        shell: bash\n"
                   "        env:\n          BASE_SHA: ${{ github.event.pull_request.base.sha }}\n"
                   "          HEAD_SHA: ${{ github.event.pull_request.head.sha }}\n" + CHANGELOG_RUN)
PENDING_STEP = ("      - name: Verify no pending changelog fragments\n        shell: bash\n        run: |\n"
                "          set -euo pipefail\n"
                "          PENDING=$(find changelog.d -mindepth 1 -maxdepth 1 ! -name README.md -print)\n"
                '          test -z "$PENDING"\n\n')


def changelog_edit(old, new, path=CHANGELOG):
    return [(path, old, new, 1)]


# Each group exercises independent defects of one predicate.
CHANGELOG_VARIANTS = {
    "W01": [changelog_edit("  push:\n", "")],
    "W02": [changelog_edit("  pull_request:\n    types: [opened, synchronize, reopened, edited]\n", "")],
    "W03": [changelog_edit("    types: [opened, synchronize, reopened, edited]", "    types: [opened, synchronize, reopened]")]
           + [changelog_edit("  " + event + ":\n", "  " + event + ":\n    " + field + ": [main]\n")
              for event in ("push", "pull_request") for field in ("branches", "branches-ignore", "paths", "paths-ignore", "tags", "tags-ignore")]
           + [changelog_edit("  push:\n", "  push:\n    types: [opened]\n")],
    "W04": [changelog_edit("  changelog:\n", "  other:\n")],
    "W05": [changelog_edit("  changelog:\n", "  changelog:\n    " + bypass + "\n")
            for bypass in ("if: false", "needs: other", "continue-on-error: true")],
    "W06": [changelog_edit(CHANGELOG_CHECK, "")],
    "W07": [changelog_edit(CHANGELOG_CHECK, CHANGELOG_CHECK + "        " + bypass + "\n")
            for bypass in ("if: false", "continue-on-error: true")],
    "W08": [changelog_edit("run: python3 .github/scripts/changelog.py check", "run: " + value)
            for value in ('"# python3 .github/scripts/changelog.py check"', "true", 'echo python3 .github/scripts/changelog.py check',
                          "python3 .github/scripts/changelog.py check || true")],
    "W09": [changelog_edit(CHANGELOG_TEST, "")],
    "W10": [changelog_edit("run: python3 .github/scripts/test-changelog.py", "run: python3 .github/scripts/test-changelog.py || true"),
             changelog_edit(CHANGELOG_TEST, CHANGELOG_TEST + "        if: false\n"),
             changelog_edit(CHANGELOG_TEST, CHANGELOG_TEST + "        continue-on-error: true\n"),
             changelog_edit("run: python3 .github/scripts/test-changelog.py", "run: true")],
    "W11": [changelog_edit("fetch-depth: 0", "fetch-depth: 1"),
             changelog_edit("fetch-depth: 0", "fetch-depth: 0\n          ref: main"),
             changelog_edit(CHANGELOG_FETCH, ""),
             changelog_edit(CHANGELOG_FETCH, CHANGELOG_FETCH + "        if: false\n"),
             changelog_edit(CHANGELOG_FETCH, CHANGELOG_FETCH.rstrip() + " || true\n"),
             changelog_edit(CHANGELOG_FETCH, CHANGELOG_FETCH.replace("refs/heads/main:", "refs/heads/other:")),
             changelog_edit(CHANGELOG_FETCH + CHANGELOG_GUARD, CHANGELOG_GUARD + CHANGELOG_FETCH)],
    "W12": [changelog_edit(CHANGELOG_GUARD, "")],
    "W13": [changelog_edit(CHANGELOG_IF, value) for value in ("", CHANGELOG_IF.replace("'next'", "'main'"),
             CHANGELOG_IF.replace("'pull_request'", "'push'"), CHANGELOG_IF.rstrip() + " && false\n")],
    "W14": [changelog_edit("HEAD_SHA: ${{ github.event.pull_request.head.sha }}", "HEAD_SHA: ${{ github.sha }}"),
             changelog_edit("BASE_SHA: ${{ github.event.pull_request.base.sha }}", "BASE_SHA: ${{ github.sha }}")],
    "W15": [changelog_edit(CHANGELOG_RUN, changelog_run(value)) for value in (
             CHANGELOG_COMMAND.replace(" --main-ref refs/remotes/origin/main", ""),
             CHANGELOG_COMMAND.replace("changelog.py", "other.py"),
             CHANGELOG_COMMAND.replace("$BASE_SHA", "$HEAD_SHA"),
             CHANGELOG_COMMAND.replace(" guard ", " check "),
             CHANGELOG_COMMAND.replace('python3 - guard', 'python3 - check'),
             CHANGELOG_COMMAND.replace('python3 .github/scripts/changelog.py guard', 'true # guard'),
             CHANGELOG_COMMAND.replace('git show "$BASE_SHA:', 'git show "$HEAD_SHA:'),
             CHANGELOG_COMMAND.replace('if [ -n', 'if [ -z'),
             CHANGELOG_COMMAND.replace('set -euo pipefail', 'set -eu'),
             CHANGELOG_COMMAND + " || true", "echo '" + CHANGELOG_COMMAND + "'",
             "\n".join("# " + line for line in CHANGELOG_COMMAND.splitlines()))],
    "W16": [changelog_edit(CHANGELOG_GUARD, CHANGELOG_GUARD + "        continue-on-error: true\n"),
             changelog_edit(CHANGELOG_GUARD, CHANGELOG_GUARD.replace("shell: bash", "shell: sh"))],
    "W18": [changelog_edit(PENDING_STEP, "", RELEASE),
             changelog_edit(PENDING_STEP, PENDING_STEP.replace("shell: bash", "shell: sh"), RELEASE),
             changelog_edit(PENDING_STEP, PENDING_STEP.replace("        shell:", "        if: false\n        shell:"), RELEASE),
             changelog_edit(PENDING_STEP, PENDING_STEP.replace("        shell:", "        continue-on-error: true\n        shell:"), RELEASE),
             changelog_edit(PENDING_STEP, PENDING_STEP.replace("-mindepth 1", "-mindepth 2"), RELEASE),
             changelog_edit(PENDING_STEP, "      - run: true\n\n" + PENDING_STEP, RELEASE)],
}
CHANGELOG_MESSAGES = {
    "W01": "push trigger is absent", "W02": "pull_request trigger is absent", "W03": "event filters or types differ",
    "W04": "missing changelog job", "W05": "changelog job can be bypassed", "W06": "missing fragment check step",
    "W07": "fragment check can be bypassed", "W08": "fragment check command differs", "W09": "missing fragment test step",
    "W10": "fragment test can be bypassed", "W11": "checkout and main fetch must supply full history",
    "W12": "missing integration guard", "W13": "integration guard condition differs", "W14": "integration guard event SHAs differ",
    "W15": "integration guard command differs", "W16": "integration guard shell or failure behavior differs",
    "W18": "pending fragments step must follow the version header check without bypasses",
}


def changelog_rule(label):
    return "release-fragments" if label == "W18" else "changelog-guard" if label in ("W12", "W13", "W14", "W15", "W16") else "changelog-check"


BASE_DOCUMENTS = {}
YAML_DUMPS = {}


def changelog_behavior(root, label):
    """Exercise shell failure behavior with read-only command doubles."""
    import yaml
    problems = []
    doc = yaml.safe_load((root / CHANGELOG).read_text())
    steps = doc["jobs"]["changelog"]["steps"]
    guard = next(step for step in steps if step.get("name") == "Protect integration changelog")
    if label == "W15 main-only changelog changes pass":
        for present, probe, show, status in ((1, 0, 0, 0), (1, 0, 0, 1), (1, 0, 0, 2),
                                            (0, 0, 0, 0), (0, 0, 0, 1), (0, 0, 0, 2),
                                            (1, 2, 0, 2), (1, 0, 2, 2)):
            fake = r'''
git() {
  if [[ "$*" == "ls-tree base -- .github/scripts/changelog.py" ]]; then
    if (( PRESENT )); then printf '100644 blob fixture\t.github/scripts/changelog.py\n'; fi
    return "$PROBE"
  fi
  [[ "$*" == "show base:.github/scripts/changelog.py" ]] || return 9
  printf 'base script\n'
  return "$SHOW"
}
python3() {
  if (( PRESENT )); then
    [[ "$*" == "- guard --base base --head head --main-ref refs/remotes/origin/main" ]] || return 9
    read -r source
    [[ "$source" == "base script" ]] || return 9
  else
    [[ "$*" == ".github/scripts/changelog.py guard --base base --head head --main-ref refs/remotes/origin/main" ]] || return 9
  fi
  return "$STATUS"
}
'''
            fake += f'PRESENT={present}; PROBE={probe}; SHOW={show}; STATUS={status}; BASE_SHA=base; HEAD_SHA=head;\n'
            result = subprocess.run(["bash", "-c", fake + guard["run"]], capture_output=True, check=False)
            if result.returncode != status:
                problems.append(f"base script selection: {present}, {probe}, {show}: exit {result.returncode}, expected {status}")
    if label == "W17":
        condition = guard["if"].strip()
        condition = condition[3:-2].strip() if condition.startswith("${{") else condition
        for event, base, expected in (("pull_request", "next", True), ("edited", "next", True),
                                      ("pull_request", "main", False), ("push", "next", False), ("tag", "", False)):
            name = "pull_request" if event == "edited" else "push" if event == "tag" else event
            expression = condition.replace("github.event_name", repr(name)).replace("github.base_ref", repr(base)).replace("&&", "and")
            if eval(expression, {"__builtins__": {}}, {}) != expected:
                problems.append("guard event truth table differs")
            for step_name in ("Check changelog fragments", "Test changelog fragments"):
                if "if" in next(step for step in steps if step.get("name") == step_name):
                    problems.append("fragment validation must run for every event")
    if label == "W18":
        release_doc = yaml.safe_load((root / RELEASE).read_text())
        step = next(s for s in release_doc["jobs"]["preflight"]["steps"] if s.get("name") == "Verify no pending changelog fragments")
        for pending, expected in (("", 0), ("entry.added.md", 1), (".hidden", 1), ("nested", 1)):
            fake = 'find() { printf "%s" "$ENTRIES"; }; ENTRIES=' + repr(pending) + '; '
            result = subprocess.run(["bash", "-c", fake + step["run"]], capture_output=True, check=False)
            if result.returncode != expected:
                problems.append(f"pending entries: exit {result.returncode}, expected {expected}")
    return problems
APT_LIBUDEV_RUN = ("        run: sudo apt-get -o Acquire::Retries=3 update && "
                   "sudo apt-get -o Acquire::Retries=3 install -y libudev-dev pkg-config\n")
SKILL_ARCHIVE_CONDITION = "github.base_ref != 'next' && github.ref != 'refs/heads/next'"
SKILL_ARCHIVE_IF = f"        if: {SKILL_ARCHIVE_CONDITION}\n"
SKILL_ARCHIVE_RUN = "        run: .github/scripts/package-skill.sh --check\n"
SKILL_ARCHIVE_STEP = "      - name: Check the skill archive\n" + SKILL_ARCHIVE_IF + SKILL_ARCHIVE_RUN
BUILD_SCRIPT = ".github/scripts/release/build.sh"
HOST_SCRIPT = ".github/scripts/release/check-host.sh"
ACTION = ".github/actions/macos-sign-notarize/action.yml"
SIGN_SCRIPT = ".github/actions/macos-sign-notarize/sign-notarize.sh"
PUBLISH_SCRIPT = ".github/scripts/publish-crates.sh"
# A full-length commit pin for the actions a case adds; the check matches the
# action name and ignores the revision.
PLACEHOLDER_REVISION = "0" * 40
COVERAGE_LABEL = "github.event_name != 'pull_request' || github.base_ref == 'main' || !(needs.changes.result == 'success' && needs.changes.outputs.docs_only == 'true') || contains(github.event.pull_request.labels.*.name, 'coverage')"
COVERAGE_DOCS_SKIP = ("github.event_name == 'push' && needs.changes.result == 'success' && "
                      "needs.changes.outputs.docs_only == 'true'")
COVERAGE_CONDITION = f"!cancelled() && ({COVERAGE_LABEL}) && !({COVERAGE_DOCS_SKIP})"
COVERAGE_IF_LINE = f"    if: ${{{{ {COVERAGE_CONDITION} }}}}\n"
COVERAGE_IF_UNWRAPPED_LINE = f'    if: "{COVERAGE_CONDITION}"\n'
COVERAGE_IF_SPACED_LINE = f'    if: "  ${{{{ {COVERAGE_CONDITION} }}}}  "\n'
COVERAGE_TYPES_LINE = "    types: [opened, synchronize, reopened]\n"
COVERAGE_PUSH_BLOCK = "  push:\n    branches: [next, main]\n"
COVERAGE_ON_BLOCK = (
    "on:\n"
    "  pull_request:\n"
    "    branches: [main, next]\n"
    + COVERAGE_TYPES_LINE
    + COVERAGE_PUSH_BLOCK +
    "  schedule:\n"
    "    # Weekly, Monday 04:41 UTC.\n"
    "    - cron: '41 4 * * 1'\n"
    "  workflow_dispatch:\n"
)
COVERAGE_CANCEL_LINE = "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n"
COVERAGE_LABEL_COMMENT = (
    '    # Pull requests measure main, code or uncertain diffs, and the coverage label.\n'
    '    # Label changes take effect on the next push or reopen.\n'
)
COVERAGE_OFF_HEADER = "  coverage-off:\n    name: coverage (feature-off)\n    needs: changes\n" + COVERAGE_LABEL_COMMENT + COVERAGE_IF_LINE
COVERAGE_ON_HEADER = "  coverage-on:\n    name: coverage (feature-on)\n    needs: changes\n" + COVERAGE_LABEL_COMMENT + COVERAGE_IF_LINE
COVERAGE_GATE_CONDITION = "always()"
COVERAGE_MEASURE = "${{ (" + COVERAGE_LABEL + ") && !(" + COVERAGE_DOCS_SKIP + ") }}"
COVERAGE_MEASURED_LINE = "        if: steps.decision.outputs.measured == 'true'\n"
COVERAGE_GATE_START = "  coverage:\n    name: coverage\n"
COVERAGE_GATE_NEEDS = "    needs: [changes, coverage-off, coverage-on]\n"
COVERAGE_GATE_COMMENT = (
    '    # Run on every triggered event so coverage passes docs-only next changes\n'
    '    # without measuring, unless a pull request carries the coverage label.\n'
    '    # Step 1 checks the results; steps 2 and 8 reject cancellation before and\n'
    '    # after the measured floors.\n'
)
COVERAGE_GATE_IF_LINE = f"    if: {COVERAGE_GATE_CONDITION}\n"
COVERAGE_GATE_HEADER = COVERAGE_GATE_START + COVERAGE_GATE_NEEDS + COVERAGE_GATE_COMMENT + COVERAGE_GATE_IF_LINE
COVERAGE_RESULT_ENV_LINES = ('          "OFF": ${{ needs.coverage-off.result }}\n'
                             '          "ON": ${{ needs.coverage-on.result }}\n')
COVERAGE_RESULT_STEP = "      - name: Check both measurements\n"
COVERAGE_RESULT_ON_CHECK = '          test "$ON" = success\n'
COVERAGE_CANCEL_EARLY = ("      - name: Reject a cancelled run before the floors\n"
                         "        if: cancelled()\n        run: exit 1\n")
COVERAGE_CANCEL_FINAL = ("      - name: Reject a cancelled run after the floors\n"
                         "        if: cancelled()\n        run: exit 1\n")
COVERAGE_OFF_COMMAND = ("cargo llvm-cov --workspace --no-default-features --features "
                        "test-helpers,test-hooks,test-loopback,verifier-registry --json --output-path cov-feature-off.json")
COVERAGE_OFF_STEP = "      - name: Measure offline line coverage\n        run: " + COVERAGE_OFF_COMMAND + "\n"
COVERAGE_ON_STEP_NAME = "      - name: Measure feature-on offline line coverage\n"
COVERAGE_UPLOAD_ACTION = "      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2\n"
COVERAGE_ATTEMPT = "${{ github.run_attempt }}"
COVERAGE_OFF_EXPORT = f"cov-feature-off-{COVERAGE_ATTEMPT}"
COVERAGE_ON_EXPORT = f"cov-feature-on-{COVERAGE_ATTEMPT}"
COVERAGE_OFF_NAME = f"          name: {COVERAGE_OFF_EXPORT}\n"
COVERAGE_UPLOAD_OFF = (COVERAGE_UPLOAD_ACTION + "        with:\n" + COVERAGE_OFF_NAME +
                       "          path: cov-feature-off.json\n          if-no-files-found: error\n"
                       "          retention-days: 1\n")
COVERAGE_UPLOAD_ON = (COVERAGE_UPLOAD_ACTION + f"        with:\n          name: {COVERAGE_ON_EXPORT}\n"
                      "          path: cov-feature-on.json\n          if-no-files-found: error\n"
                      "          retention-days: 1\n")
COVERAGE_DOWNLOAD_ACTION = "      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n"
COVERAGE_DOWNLOAD_OFF = COVERAGE_DOWNLOAD_ACTION + COVERAGE_MEASURED_LINE + "        with:\n" + COVERAGE_OFF_NAME
COVERAGE_DOWNLOAD_ON = COVERAGE_DOWNLOAD_ACTION + COVERAGE_MEASURED_LINE + f"        with:\n          name: {COVERAGE_ON_EXPORT}\n"
COVERAGE_OFF_FLOORS_STEP = ("      - name: Enforce per-crate line-coverage floors\n" + COVERAGE_MEASURED_LINE + "        run: python3 "
                            ".github/scripts/check-coverage.py cov-feature-off.json --configuration feature-off\n")
COVERAGE_ON_FLOORS_STEP = ("      - name: Enforce feature-on line-coverage floors\n" + COVERAGE_MEASURED_LINE + "        run: python3 "
                           ".github/scripts/check-coverage.py cov-feature-on.json --configuration feature-on\n")
CACHE_SAVE_LINE = "          save-if: ${{ github.event_name == 'push' }}\n"
RUST_CACHE_USES = "      - uses: Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 # v2.9.3\n"
RUST_CACHE_PLAIN = RUST_CACHE_USES + "        with:\n" + CACHE_SAVE_LINE
UNGUARDED_CACHE_STEP = RUST_CACHE_USES
CACHE_FIXTURE = ".github/workflows/cache-fixture.yaml"
CACHE_FIXTURE_TEXT = ("on: workflow_dispatch\npermissions: {contents: read}\njobs:\n  fixture:\n"
                      "    runs-on: ubuntu-24.04\n    steps:\n      - run: 'true'\n")


def cache_fixture(trigger):
    """The fixture workflow under a pull request trigger, with an unguarded rust-cache step."""
    return ("on: " + trigger + "\npermissions: {contents: read}\njobs:\n  fixture:\n"
            "    runs-on: ubuntu-24.04\n    steps:\n" + UNGUARDED_CACHE_STEP + "      - run: 'true'\n")


def coverage_move(text, before):
    """Moves a block of coverage.yml so that it directly precedes another one."""
    return [(COVERAGE, text, "", 1), (COVERAGE, before, text + before, 1)]
SIGN_MACOS_FIRST_STEP = (
    "      - name: Check tool paths\n"
    "        run: /bin/bash .github/actions/macos-sign-notarize/check-tools.sh\n"
    "\n"
    "      - name: Validate the release version\n"
)


def before_sign_macos_tools(text):
    return (RELEASE, SIGN_MACOS_FIRST_STEP, text + SIGN_MACOS_FIRST_STEP, 1)


REHEARSAL_TIMEOUT = "    timeout-minutes: 120\n"
REHEARSAL_JOB_PERMISSIONS = "    permissions:\n      contents: read\n    strategy:\n"
REHEARSAL_VERSION_ECHO = '          echo "Rehearsing version: $VERSION"\n'
REHEARSAL_ENV = '  EXPECTED_MAINNET_WRITE: "on"\n'
REHEARSAL_SODIUM_STEP = (
    "      - name: Prefetch libsodium dist (Windows)\n"
    "        if: matrix.target == 'x86_64-pc-windows-msvc'\n"
)
REHEARSAL_PROBE_STEP = (
    '      - name: Verify optimized Wasm identity and deployment security\n'
    "        if: matrix.target == 'x86_64-unknown-linux-gnu'\n"
    '        shell: bash\n'
    '        run: |\n'
    '          cargo test --release --locked --target x86_64-unknown-linux-gnu -p stellar-agent-smart-account \\\n'
    '            --features test-helpers,deploy-cli --lib --test vendored_wasm_release_cfg -- \\\n'
    '            vendored_wasm_tests deployment::deploy::tests:: \\\n'
    '            vendored_table_entries embedded_wasm_constants digest_constants \\\n'
    '            verifier_allowlist_ threshold_policy_hashes weighted_threshold_policy_hashes \\\n'
    '            deploy_smart_account_dry_run deploy_webauthn_verifier_dry_run \\\n'
    '            deploy_ed25519_verifier_dry_run deploy_spending_limit_policy_dry_run \\\n'
    '            deploy_timelock_controller_dry_run deploy_policy_dry_run\n'
    '\n'
)
REHEARSAL_BUILD_STEP = (
    '      - name: Build binaries\n'
    '        shell: bash\n'
    '        env:\n'
    '          TARGET: ${{ matrix.target }}\n'
    '        run: bash .github/scripts/release/build.sh "$TARGET"\n'
    '\n'
)
REHEARSAL_EXACT = "expected exactly contents: read"


def in_rehearsal_version_step(line):
    """Adds a line to the run: block of the rehearsal step that reads the
    version.
    """
    return (REHEARSAL, REHEARSAL_VERSION_ECHO, REHEARSAL_VERSION_ECHO + line, 1)


RELEASE_BUILD_STEP = (
    "      - name: Build binaries\n"
    "        shell: bash\n"
    "        env:\n"
    "          TARGET: ${{ matrix.target }}\n"
    '        run: bash .github/scripts/release/build.sh "$TARGET"\n'
    "\n"
)
RELEASE_PERL_STEP = "      - name: Provide a native Perl for the vendored OpenSSL build (Windows)\n"
ARCHIVE_RUN = 'run: bash .github/scripts/release/verify-archive.sh archives "$VERSION" "$TARGET" "$EXPECTED_MAINNET_WRITE"'
ARCHIVE_ENV = "          TARGET: ${{ matrix.target }}\n          VERSION: ${{ needs.preflight.outputs.version }}\n" \
    "        run: bash .github/scripts/release/verify-archive.sh"
SOURCE_DISCIPLINE_LINE = '          "$RUNNER_TEMP/feature-check/bin/python" .github/scripts/check-feature-discipline.py\n'
INSTALL_RUN = 'run: bash "$GITHUB_WORKSPACE/wf/.github/scripts/release/verify-install.sh" "$TAG" "$EXPECTED_MAINNET_WRITE"'
PROVENANCE_RUN = ('run: python3 .github/scripts/check-provenance.py "provenance/stellar-agent-$VERSION.intoto.jsonl" '
                  'provenance/SHA256SUMS "$GITHUB_SHA" "$GITHUB_REPOSITORY" "$GITHUB_REF"')
PACKAGE_CHECK_RUN = ('run: bash "$GITHUB_WORKSPACE/wf/.github/scripts/check-packaged-markers.sh" target '
                     'target/package-verification-start "$EXPECTED_MAINNET_WRITE" "$VERSION"')
VERIFY_PACKAGED_STEP = "      - name: Verify packaged binaries\n"
ROSETTA_STEP = (
    "      - name: Require Rosetta\n"
    "        if: matrix.target == 'x86_64-apple-darwin'\n"
    "        run: arch -x86_64 /usr/bin/true\n"
)
REHEARSAL_ARCHIVE_DOWNLOAD = "          name: rehearsal-${{ matrix.target }}\n          path: archives\n"
REHEARSAL_PIN_STEP = (
    "      # RUSTUP_TOOLCHAIN overrides the checkout's rust-toolchain.toml.\n"
    "      - name: Pin the toolchain for every later step\n"
    '        run: echo "RUSTUP_TOOLCHAIN=$RELEASE_TOOLCHAIN" >> "$GITHUB_ENV"\n'
)
RELEASE_WORKFLOW_ENV = ('env:\n  EXPECTED_MAINNET_WRITE: "on"\n'
                        "  # The toolchain publish.yml packages with; every build leg compiles with it.\n"
                        '  RELEASE_TOOLCHAIN: "1.100.0"\n')
CI_DISPATCH = "  workflow_dispatch:\n"
EVIDENCE_NAME = "      - name: Require the push CI evidence of the tag commit\n"
EVIDENCE_ENV = "        env:\n          GH_TOKEN: ${{ github.token }}\n"
EVIDENCE_RUN = ('        run: python3 .github/scripts/check-run-evidence.py --repository "$GITHUB_REPOSITORY" '
                '--sha "$GITHUB_SHA" --tag "$GITHUB_REF_NAME" --wait-minutes 80 --poll-seconds 60\n')
EVIDENCE_STEP = EVIDENCE_NAME + EVIDENCE_ENV + EVIDENCE_RUN
ANCESTRY_STEP = ('      - name: Refuse a tag whose commit is not on main\n'
                 '        run: .github/scripts/check-ref-on-main.sh "$GITHUB_SHA"\n')
WARN_STEP = "      - name: Warn when a workspace member is missing on crates.io\n"
VERSION_STEP = "      - name: Verify tag matches workspace version\n"
PREFLIGHT_PERMISSIONS = "    permissions:\n      contents: read\n      actions: read\n    outputs:\n"
WORKFLOW_PERMISSIONS = "permissions:\n  contents: read\n\nenv:\n"
# The tail of the release vendored-wasm call; WASM_CALL below holds the whole job.
EVIDENCE_WASM_CALL = ("    needs: preflight\n    permissions:\n      contents: read\n"
                      "    uses: ./.github/workflows/vendored-wasm.yml\n")
PROVENANCE_PERMISSIONS = "      actions: read\n      id-token: write\n"
EVIDENCE_COMMAND = "the evidence step must run its command unconditionally in bash with only the token"
PROVENANCE_USES = "    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0\n"
PREFLIGHT_STEPS_START = "    outputs:\n      version: ${{ steps.version.outputs.version }}\n    steps:\n"
EVIDENCE_ORDER = "the evidence step must directly follow the ancestry step"
EVIDENCE_PERMISSIONS = "preflight must hold exactly contents: read and actions: read, unconditionally"


def evidence_case(label, fragment, *edits):
    return (label, "release-ci-evidence", fragment, [(RELEASE, old, new, count) for old, new, count in edits])


RELEASE_EVIDENCE_CASES = [

    evidence_case("evidence step removed", EVIDENCE_ORDER, (EVIDENCE_STEP, "", 1)),
    evidence_case("evidence step duplicated", EVIDENCE_ORDER, (EVIDENCE_STEP, EVIDENCE_STEP * 2, 1)),
    evidence_case("evidence step before the ancestry step", EVIDENCE_ORDER,
                  (EVIDENCE_STEP, "", 1), (ANCESTRY_STEP, EVIDENCE_STEP + ANCESTRY_STEP, 1)),
    evidence_case("evidence step after another step", EVIDENCE_ORDER,
                  (EVIDENCE_STEP, "", 1), (VERSION_STEP, EVIDENCE_STEP + VERSION_STEP, 1)),
    evidence_case("ancestry step removed", EVIDENCE_ORDER, (ANCESTRY_STEP, "", 1)),
    evidence_case("evidence step with if", EVIDENCE_COMMAND, (EVIDENCE_NAME, EVIDENCE_NAME + "        if: always()\n", 1)),
    evidence_case("evidence step with continue-on-error", EVIDENCE_COMMAND,
                  (EVIDENCE_NAME, EVIDENCE_NAME + "        continue-on-error: true\n", 1)),
    evidence_case("evidence command changed", EVIDENCE_COMMAND, ("--wait-minutes 80", "--wait-minutes 0", 1)),
    evidence_case("evidence command suppressed", EVIDENCE_COMMAND, ("--poll-seconds 60\n", "--poll-seconds 60 || true\n", 1)),
    evidence_case("evidence step with another env", EVIDENCE_COMMAND,
                  (EVIDENCE_ENV, EVIDENCE_ENV + "          EXTRA: value\n", 1)),
    evidence_case("evidence step without the token", EVIDENCE_COMMAND, (EVIDENCE_ENV, "", 1)),
    # Each token below is added while the evidence step keeps its own.
    evidence_case("evidence step with another shell", EVIDENCE_COMMAND,
                  (EVIDENCE_NAME, EVIDENCE_NAME + "        shell: true {0}\n", 1)),
    evidence_case("evidence step under a job default shell", EVIDENCE_COMMAND,
                  (PREFLIGHT_STEPS_START, PREFLIGHT_STEPS_START.replace(
                      "    steps:\n", "    defaults:\n      run:\n        shell: sh\n    steps:\n"), 1)),
    evidence_case("token in the job env", "job env sets a token variable",
                  (PREFLIGHT_PERMISSIONS, PREFLIGHT_PERMISSIONS.replace(
                      "    outputs:\n", "    env:\n      GH_TOKEN: ${{ github.token }}\n    outputs:\n"), 1)),
    evidence_case("token name in the job env", "job env sets a token variable",
                  (PREFLIGHT_PERMISSIONS, PREFLIGHT_PERMISSIONS.replace(
                      "    outputs:\n", "    env:\n      gh_token: fixed\n    outputs:\n"), 1)),
    evidence_case("github token under another name in the job env", "an expression reads the workflow token",
                  (PREFLIGHT_PERMISSIONS, PREFLIGHT_PERMISSIONS.replace(
                      "    outputs:\n", "    env:\n      API: ${{ github.token }}\n    outputs:\n"), 1)),
    evidence_case("token in the workflow env", "workflow env sets a token variable",
                  (RELEASE_WORKFLOW_ENV, RELEASE_WORKFLOW_ENV + "  GITHUB_TOKEN: ${{ github.token }}\n", 1)),
    evidence_case("token variable in another preflight step", "step 6 sets a token variable",
                  (WARN_STEP, WARN_STEP + "        env:\n          GITHUB_TOKEN: fixed\n", 1)),
    evidence_case("token in another preflight step", "an expression reads secrets",
                  (WARN_STEP, WARN_STEP + "        env:\n          API: ${{ secrets.GITHUB_TOKEN }}\n", 1)),
    evidence_case("indexed github token in a preflight step", "other than by a named property",
                  (WARN_STEP, WARN_STEP + "        env:\n          API: ${{ github['token'] }}\n", 1)),
    evidence_case("whole github context in a preflight step", "other than by a named property",
                  (WARN_STEP, WARN_STEP + "        env:\n          API: ${{ toJSON(github) }}\n", 1)),
    evidence_case("evidence step reads the token through working-directory", "an expression reads the workflow token",
                  (EVIDENCE_NAME, EVIDENCE_NAME + "        working-directory: ${{ github.token }}\n", 1)),
    evidence_case("github token under another name in the workflow env", "an expression reads the workflow token",
                  (RELEASE_WORKFLOW_ENV, RELEASE_WORKFLOW_ENV + "  API: ${{ github.token }}\n", 1)),
    evidence_case("token in the workflow defaults", "an expression reads the workflow token",
                  (WORKFLOW_PERMISSIONS, WORKFLOW_PERMISSIONS.replace(
                      "\nenv:\n", "\ndefaults:\n  run:\n    working-directory: ${{ github.token }}\n\nenv:\n"), 1)),
    evidence_case("token in the preflight outputs", "an expression reads the workflow token",
                  (PREFLIGHT_STEPS_START, PREFLIGHT_STEPS_START.replace(
                      "    steps:\n", "      token: ${{ github.token }}\n    steps:\n"), 1)),
    evidence_case("provenance with another generator", "provenance must hold no actions scope",
                  (PROVENANCE_USES, PROVENANCE_USES.replace("@v2.1.0", "@v2.0.0"), 1)),
    evidence_case("provenance with steps", "provenance must hold no actions scope",
                  (PROVENANCE_USES, PROVENANCE_USES + "    steps:\n      - run: echo\n", 1)),
    evidence_case("preflight without actions: read", EVIDENCE_PERMISSIONS,
                  (PREFLIGHT_PERMISSIONS, PREFLIGHT_PERMISSIONS.replace("      actions: read\n", ""), 1)),
    evidence_case("conditional preflight", EVIDENCE_PERMISSIONS,
                  (PREFLIGHT_PERMISSIONS, "    if: always()\n" + PREFLIGHT_PERMISSIONS, 1)),
    evidence_case("actions: read on another release job", "vendored-wasm must hold no actions scope",
                  (EVIDENCE_WASM_CALL, EVIDENCE_WASM_CALL.replace(
                      "      contents: read\n", "      contents: read\n      actions: read\n"), 1)),
    evidence_case("read-all on another release job", "vendored-wasm must hold no actions scope",
                  (EVIDENCE_WASM_CALL, EVIDENCE_WASM_CALL.replace(
                      "    permissions:\n      contents: read\n", "    permissions: read-all\n"), 1)),
    evidence_case("actions: read on the workflow", "the workflow must hold no actions scope",
                  (WORKFLOW_PERMISSIONS, WORKFLOW_PERMISSIONS.replace("  contents: read\n",
                                                                      "  contents: read\n  actions: read\n"), 1)),
    evidence_case("provenance gains a scope", "provenance must hold no actions scope",
                  (PROVENANCE_PERMISSIONS, PROVENANCE_PERMISSIONS + "      checks: read\n", 1)),
]
REHEARSAL_MARKER_RUN = ('        run: bash .github/scripts/check-packaged-markers.sh target '
                        'target/package-verification-start "$EXPECTED_MAINNET_WRITE" "$VERSION"\n')
# The defining command of each feature job of ci.yml, as its run: line.
CI_FEATURE_JOBS = {
    "feature-on-clippy": 'cargo clippy --workspace --all-targets --features "mainnet-write,',
    "feature-on-doc": 'cargo doc --workspace --no-deps --features "mainnet-write,',
    "feature-discipline": "cargo fetch --locked",
    "release-shape": "bash .github/scripts/release/check-host.sh",
}
# The off jobs of ci.yml: the job's opening lines and the defining command as
# its run: line, which passes --no-default-features.
CI_OFF_JOBS = {
    "clippy": ("  clippy:\n    name: clippy\n",
               'cargo clippy --workspace --all-targets --no-default-features --features "$FEATURES_EXCEPT_MAINNET_WRITE"'),
    "doc": ("  doc:\n    name: rustdoc\n",
            'cargo doc --workspace --no-deps --no-default-features --features "$FEATURES_EXCEPT_MAINNET_WRITE"'),
}
# The dependency and condition lines that skip a ci.yml job on a docs-only
# pull request into next.
DOCS_ONLY_JOB = ("    needs: changes\n"
                 "    if: ${{ !cancelled() && needs.changes.outputs.docs_only != 'true' }}\n")
DOCS_ONLY_FEATURE_JOBS = ("clippy", "doc", "feature-on-clippy", "feature-on-doc",
                          "release-shape")
DOCS_TESTS_HEADER = ("  docs-tests:\n    name: docs-tests\n    needs: changes\n"
                     "    if: ${{ !cancelled() && needs.changes.outputs.docs_only == 'true' }}\n")
DOCS_TESTS_ON_RUN = ("        run: python3 .github/scripts/run-docs-tests.py "
                     "--features mainnet-write,test-helpers,test-hooks,test-loopback,verifier-registry\n")


def conditional_feature_job(header):
    """Returns the edit that runs a feature job under if: false."""
    job = header.split(":", 1)[0].strip()
    if job == "feature-discipline":
        header = "  feature-discipline:\n    needs: changes\n    if: ${{ !cancelled() }}\n"
        return (CI, header, header.replace("${{ !cancelled() }}", "false"), 1)
    if job in DOCS_ONLY_FEATURE_JOBS:
        return (CI, header + DOCS_ONLY_JOB, header + "    needs: changes\n    if: false\n", 1)
    return (CI, header, header + "    if: false\n", 1)


COVERAGE_OFF_RUN = "        run: cargo llvm-cov --workspace --no-default-features --features test-helpers,"
# The host recipe lines that build the CLI package alone, and the lines that
# derive its debug alias, compare the bytes and check both names, versions, and markers.
HOST_ALIAS = "target/tmp/host-alias/stellar-agent-mcp"
HOST_SINGLE_CLI = ("cargo build --locked -p stellar-agent-cli\n"
                   "mkdir -p target/tmp/host-alias\n")
HOST_ALIAS_COPY = f"copy_alias target/debug/stellar-agent {HOST_ALIAS}\n"
HOST_ALIAS_STEPS = (". .github/scripts/release/copy-alias.sh\n"
                    + HOST_ALIAS_COPY
                    + f"cmp target/debug/stellar-agent {HOST_ALIAS}\n"
                    'bash .github/scripts/check-binary-marker.sh target/debug/stellar-agent on "stellar-agent $version"\n'
                    f'bash .github/scripts/check-binary-marker.sh {HOST_ALIAS} on "stellar-agent-mcp $version"\n')
HOST_RELEASE_CMP = 'cmp "target/$target/release/stellar-agent" "target/$target/release/stellar-agent-mcp"\n'
# The copy and comparison lines of build.sh and of the smoke build step, a
# plain copy and mv in their place, and the rename line of the copy helper.
BUILD_COPY = 'copy_alias "$release/stellar-agent$suffix" "$release/stellar-agent-mcp$suffix"\n'
BUILD_PLAIN_MV = ('cp -p "$release/stellar-agent$suffix" "$release/.stellar-agent-mcp.tmp"\n'
                  'mv -f "$release/.stellar-agent-mcp.tmp" "$release/stellar-agent-mcp$suffix"\n')
BUILD_CMP = 'cmp "$release/stellar-agent$suffix" "$release/stellar-agent-mcp$suffix"\n'
SMOKE_COPY = '          copy_alias "$release/stellar-agent" "$release/stellar-agent-mcp"\n'
SMOKE_PLAIN_MV = ('          cp -p "$release/stellar-agent" "$release/.stellar-agent-mcp.tmp"\n'
                  '          mv -f "$release/.stellar-agent-mcp.tmp" "$release/stellar-agent-mcp"\n')
SMOKE_CMP = '          cmp "$release/stellar-agent" "$release/stellar-agent-mcp"\n'
COPY_HELPER = ".github/scripts/release/copy-alias.sh"
COPY_RENAME = ("    ! perl -e 'rename($ARGV[0], $ARGV[1]) or die \"copy_alias: $ARGV[1]: $!\\n\"' "
               '"$temp" "$destination"; then\n')
COPY_CHECK = 'if [ -L "$destination" ] || { [ -e "$destination" ] && [ ! -f "$destination" ]; }; then\n'
# The signing, verification and derivation lines of sign-notarize.sh.
SIGN_CANONICAL = ('/usr/bin/codesign --force --options runtime --timestamp \\\n'
                  '  --keychain "$KEYCHAIN" --sign "$IDENTITY" "$BINARY_DIR/stellar-agent"\n')
SIGN_DERIVE = "/bin/bash \"${BASH_SOURCE[0]%/*}/derive-alias.sh\" \"$BINARY_DIR\" ''\n"
DERIVE_SCRIPT = ".github/actions/macos-sign-notarize/derive-alias.sh"
DERIVE_RENAME = ("/usr/bin/perl -e 'rename($ARGV[0], $ARGV[1]) or die \"derive-alias: $ARGV[1]: $!\\n\"' "
                 '"$temp" "$alias"\n')
DERIVE_CHECK = 'if [ -L "$alias" ] || { [ -e "$alias" ] && [ ! -f "$alias" ]; }; then\n'
SIGN_VERIFY_BOTH = ('for bin in stellar-agent stellar-agent-mcp; do\n'
                    '  /usr/bin/codesign --verify --strict --verbose=2 "$BINARY_DIR/$bin"\ndone\n')


def archive_block(suffix):
    """The archive check as a block scalar with suffix after the command."""
    return "run: |\n          " + ARCHIVE_RUN[len("run: "):] + suffix


def commented(run):
    """A run: line as a block scalar whose command follows true and a
    shell comment, so the command text stays and never runs."""
    return "run: |\n          true # " + run[len("run: "):]


PUBLISH_CALL = 'cargo publish -p "$name" --locked --no-verify 2>&1 | tee "$log"'
PUBLISH_PACKAGE_RUN = '        run: cargo package --workspace --locked --no-verify --target-dir "$RUNNER_TEMP/publish-target"\n'
PUBLISH_ANCESTRY_CALL = '          "$GITHUB_WORKSPACE/wf/.github/scripts/check-ref-on-main.sh" "$(git rev-parse HEAD)"'
RELEASE_ANCESTRY_RUN = '        run: .github/scripts/check-ref-on-main.sh "$GITHUB_SHA"\n'
SIGN_MACOS_VERSION_TEST = (
    '          if ! [[ "$VERSION" =~ $version_re ]]; then\n'
    '            echo "release version does not match $version_re" >&2\n'
    "            exit 1\n"
    "          fi\n"
    '          echo "version=$VERSION" >> "$GITHUB_OUTPUT"\n'
    "\n"
    "      - uses: actions/download-artifact"
)
SIGN_MACOS_VERSION_OUTPUT = (
    '          echo "version=$VERSION" >> "$GITHUB_OUTPUT"\n'
    "\n"
    "      - uses: actions/download-artifact"
)
PUBLISH_COMPARE_STEP = (
    "      - name: Require the archives to equal the verify job's checksums\n"
    "        working-directory: src\n"
    "        env:\n"
    "          VERSION: ${{ steps.tag.outputs.version }}\n"
    "        run: |\n"
    "          set -euo pipefail\n"
    '          python3 "$GITHUB_WORKSPACE/wf/.github/scripts/compare-crate-sums.py" \\\n'
    '            "$RUNNER_TEMP/verify/SHA256SUMS" "$RUNNER_TEMP/publish-target/package" "$VERSION"\n'
    "\n"
)
SMOKE_CLEAN_CHECK = 'status="$(/usr/bin/git status --porcelain)"'
SIGN_MACOS_VALIDATE_STEP = (
    "      - name: Validate the unsigned binaries\n"
    "        env:\n"
    "          TARGET: ${{ matrix.target }}\n"
    "          ARCH: ${{ matrix.arch }}\n"
    "        run: |\n"
    "          /bin/bash .github/actions/macos-sign-notarize/validate-input.sh \\\n"
    '            "$RUNNER_TEMP/unsigned/unsigned-$TARGET.tar" "$RUNNER_TEMP/signing-input" "$ARCH"\n'
    "\n"
)
SMOKE_VALIDATE_STEP = (
    "      - name: Validate the unsigned binaries\n"
    "        run: |\n"
    "          /bin/bash .github/actions/macos-sign-notarize/validate-input.sh \\\n"
    '            "$RUNNER_TEMP/unsigned/unsigned-aarch64-apple-darwin.tar" "$RUNNER_TEMP/signing-input" arm64\n'
    "\n"
)
SIGNING_CLEAN_STEP = (
    "      - name: Refuse a modified checkout before signing\n"
    "        run: |\n"
    '          status="$(/usr/bin/git status --porcelain)"\n'
    '          if [ -n "$status" ]; then\n'
    '            echo "the checkout has local changes:" >&2\n'
    "            printf '%s\\n' \"$status\" >&2\n"
    "            exit 1\n"
    "          fi\n"
    "\n"
)
PUBLISH_CLEAN_CHECK = 'status=$(git -C "$tree" status --porcelain)'
PUBLISH_TOKEN_CLEAN_STEP = (
    "      - name: Refuse a modified checkout before the token\n"
    "        run: |\n"
    "          set -euo pipefail\n"
    "          for tree in src wf; do\n"
    '            status=$(git -C "$tree" status --porcelain)\n'
    '            if [ -n "$status" ]; then\n'
    '              echo "$tree has local changes:" >&2\n'
    "              printf '%s\\n' \"$status\" >&2\n"
    "              exit 1\n"
    "            fi\n"
    "          done\n"
    "\n"
)
PUBLISH_ANCESTRY_STEP = (
    "      - name: Refuse a tag whose commit is not on main\n"
    "        working-directory: src\n"
    "        run: |\n"
    "          set -euo pipefail\n"
    '          "$GITHUB_WORKSPACE/wf/.github/scripts/check-ref-on-main.sh" "$(git rev-parse HEAD)"\n'
    "\n"
)
PUBLISH_TOOLCHAIN_STEP = (
    "      - name: Require the pinned toolchain\n"
    "        working-directory: src\n"
    "        run: |\n"
    "          set -euo pipefail\n"
    '          read -r _ cargo_release _ <<<"$(cargo -V)"\n'
    '          read -r _ rustc_release _ <<<"$(rustc -V)"\n'
)
PUBLISH_AUTH = "        id: auth\n\n"
SIGNING_FIRST_CLEAN_BLOCK = (
    "      # The checkout stays unmodified from the download to the signing step:\n"
    "      # checked before the workspace scripts read the tar and again before\n"
    "      # signing.\n"
    "      - name: Refuse a modified checkout before validation\n"
    "        run: |\n"
    '          status="$(/usr/bin/git status --porcelain)"\n'
    '          if [ -n "$status" ]; then\n'
    '            echo "the checkout has local changes:" >&2\n'
    "            printf '%s\\n' \"$status\" >&2\n"
    "            exit 1\n"
    "          fi\n"
    "\n"
)


def live_text(relative, pattern, purpose):
    """Returns the unique live fixture so shape drift fails before mutation cases run."""
    matches = list(pattern.finditer((ROOT / relative).read_text()))
    if len(matches) != 1:
        raise SystemExit(f"{relative}: {purpose}: found {len(matches)} matches, expected 1")
    return matches[0].group(0)


# The pinned revision of the download action changes with every bump, so this
# fixture comes from the live workflow. The pattern pins the action, the
# artifact name, and the path, and nothing else.
SIGN_MACOS_DOWNLOAD_STEP = live_text(
    RELEASE,
    re.compile(
        r"^      - uses: actions/download-artifact@[0-9a-fA-F]{40} # v[^\n]*\n"
        r"        with:\n"
        r"          name: unsigned-\$\{\{ matrix\.target \}\}\n"
        r"          path: \$\{\{ runner\.temp \}\}/unsigned\n"
        r"\n",
        re.MULTILINE,
    ),
    "signing job download step",
)
PUBLISH_FIRST_CLEAN_BLOCK = (
    "      # Both trees stay unmodified from the download to the token step:\n"
    "      # checked before `cargo package` reads the tag's tree and again before\n"
    "      # the token.\n"
    "      - name: Refuse a modified checkout before packaging\n"
    "        run: |\n"
    "          set -euo pipefail\n"
    "          for tree in src wf; do\n"
    '            status=$(git -C "$tree" status --porcelain)\n'
    '            if [ -n "$status" ]; then\n'
    '              echo "$tree has local changes:" >&2\n'
    "              printf '%s\\n' \"$status\" >&2\n"
    "              exit 1\n"
    "            fi\n"
    "          done\n"
    "\n"
)
PUBLISH_COMPARE_CALL = (
    '          python3 "$GITHUB_WORKSPACE/wf/.github/scripts/compare-crate-sums.py" \\\n'
    '            "$RUNNER_TEMP/verify/SHA256SUMS" "$RUNNER_TEMP/publish-target/package" "$VERSION"\n'
)
SIGN_MACOS_VALIDATE_ARGS = '            "$RUNNER_TEMP/unsigned/unsigned-$TARGET.tar" "$RUNNER_TEMP/signing-input" "$ARCH"\n'
COMPARE_GUARD = "guard step \"Require the archives to equal the verify job's checksums\""
VALIDATE_GUARD = "guard step 'Validate the unsigned binaries'"
PUBLISH_TAG_TEST = (
    '          if ! [[ "$TAG" =~ $tag_re ]]; then\n'
    '            echo "tag input does not match $tag_re" >&2\n'
    "            exit 1\n"
    "          fi\n"
    '          echo "tag=$TAG" >> "$GITHUB_OUTPUT"\n'
    '          echo "version=${TAG#v}" >> "$GITHUB_OUTPUT"\n'
    "\n"
    "      - uses: actions/checkout"
)
PUBLISH_TAG_OUTPUT = (
    '          echo "tag=$TAG" >> "$GITHUB_OUTPUT"\n'
    '          echo "version=${TAG#v}" >> "$GITHUB_OUTPUT"\n'
    "\n"
    "      - uses: actions/checkout"
)
def publish_job_only(old, new, expected):
    """Edits every occurrence inside the publish job alone, refusing count drift."""
    job = live_text(PUBLISH, re.compile(r"  publish:\n.*?(?=\n  [a-z][\w-]*:|\Z)", re.DOTALL), "publish job")
    count = job.count(old)
    if count != expected:
        raise SystemExit(f"{PUBLISH}: publish job: replacement text drift: found {count} times, expected {expected}")
    return [(PUBLISH, job, job.replace(old, new), 1)]


WASM = ".github/workflows/vendored-wasm.yml"
WASM_CALL = (
    "  vendored-wasm:\n"
    "    name: vendored-wasm\n"
    "    needs: preflight\n"
    "    permissions:\n"
    "      contents: read\n"
    "    uses: ./.github/workflows/vendored-wasm.yml\n"
)
CACHE_STEP = (
    "      - uses: Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 # v2.9.3\n"
    "        with:\n"
    "          key: ${{ matrix.target }}\n"
)
CACHE_RESTORE = "      - uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0\n"
BUILD_PIN_STEP = (
    "      - name: Pin the build toolchain\n"
    "        shell: bash\n"
    '        run: echo "RUSTUP_TOOLCHAIN=$RELEASE_TOOLCHAIN" >> "$GITHUB_ENV"\n'
)
SUMS_STEP = (
    "      - name: Verify the publication archives\n"
    '        run: bash .github/scripts/release/verify-sums.sh "$RUNNER_TEMP/release"\n'
)
TAG_GUARD = "        if: github.ref_type != 'tag'\n"
WASM_SAVE_EVENTS = "(github.event_name == 'push' || github.event_name == 'schedule')"
WASM_SAVE_CONDITION = (f"github.ref_type != 'tag' && {WASM_SAVE_EVENTS} && "
                       "steps.restore.outputs.cache-hit != 'true'")
SAVE_GUARD = f"        if: {WASM_SAVE_CONDITION}\n"
WASM_OLD_SAVE_GUARD = "        if: github.ref_type != 'tag' && steps.restore.outputs.cache-hit != 'true'\n"


def wasm_save_events(events):
    """Both stellar-cli save guards with another event test in place of push or schedule."""
    return [(WASM, SAVE_GUARD, SAVE_GUARD.replace(WASM_SAVE_EVENTS, events), 2)]
BUILD_TOOLCHAIN = "          toolchain: ${{ env.RELEASE_TOOLCHAIN }}\n          targets: ${{ matrix.target }}\n"
RELEASE_LAST_LINE = "            release-provenance/*.intoto.jsonl\n"
BUILD_PYTHON = (
    "      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0\n"
    "        with:\n"
    '          python-version: "3.13"\n'
    "\n"
    "      # On MSVC"
)
WASM_REBUILD_JOB = "  rebuild:\n    name: rebuild\n"
WASM_REBUILD_IF = "    needs: [check, stellar-cli-25, stellar-cli-28]\n    if: needs.check.outputs.rebuild == 'true'\n"
WASM_DOWNLOAD_25 = "          name: vendored-wasm-stellar-cli-25\n          path: ${{ runner.temp }}/stellar-cli-artifacts\n"
WASM_COMPARE = '            --work "$RUNNER_TEMP/rebuild-work"\n'
WASM_COMPARE_STEP = "      - name: Rebuild and compare\n"
WASM_GATE_NEEDS = "    needs: [check, stellar-cli-25, stellar-cli-28, rebuild]\n"
WASM_GATE_IF = WASM_GATE_NEEDS + "    if: always()\n"
WASM_GATE_STEP = "      - name: Gate on every job result\n"
WASM_GATE_RUN = ('        run: bash .github/scripts/rebuild-vendored-wasm.sh --gate "$CHECK" "$REBUILD" "$CLI25" "$CLI28" '
                 '"$REBUILD_JOB" "$REF_TYPE"\n')
WASM_DECIDE_RUN = '          echo "rebuild=$rebuild" >>"$GITHUB_OUTPUT"\n'

PUBLISH_EVIDENCE = live_text(PUBLISH, re.compile(r"  release-evidence:\n.*?(?=  publish:)", re.DOTALL),
                              "publication Release evidence")
PUBLISH_SOURCE_STEP = live_text(PUBLISH, re.compile(
    r"      - name: Require the verified source commit\n.*?\n\n", re.DOTALL), "verified source step")
WASM_REF_TYPE = "          REBUILD_JOB: ${{ needs.rebuild.result }}\n          REF_TYPE: ${{ github.ref_type }}\n"
WASM_CACHE_COMBINED = ("      - uses: actions/cache@" + PLACEHOLDER_REVISION + "\n" + TAG_GUARD
                       + "        with:\n          path: x\n          key: y\n")
WASM_SAVE_STEP = "      - name: Save the install root\n"

# The coverage part jobs and the rust-cache steps of single jobs, read from
# the live workflows.
JOB_CACHE = r":\n.*?          save-if: \$\{\{ github.event_name == 'push' \}\}\n"
COVERAGE_OFF_JOB = live_text(COVERAGE, re.compile(r"^  coverage-off:\n.*?(?=^  coverage-on:\n)", re.DOTALL | re.MULTILINE),
                             "feature-off coverage job")
COVERAGE_ON_CACHE = live_text(COVERAGE, re.compile(r"^  coverage-on" + JOB_CACHE, re.DOTALL | re.MULTILINE),
                              "feature-on coverage cache")
CI_CLIPPY_CACHE = live_text(CI, re.compile(r"^  clippy" + JOB_CACHE, re.DOTALL | re.MULTILINE), "clippy job cache")
CI_FEATURE_ON_TEST_CACHE = live_text(CI, re.compile(r"^  feature-on-test" + JOB_CACHE.replace(" == 'push' ", " == 'push' && matrix.shard == 1 "), re.DOTALL | re.MULTILINE),
                                     "feature-on test job cache")


# Insertion points for a vars reference in release.yml, the workflow it
# calls and the signing action it uses, and the vendored-wasm tree check
# step a local reference follows.
WASM_JOBS = "permissions:\n  contents: read\n\njobs:\n"
WASM_TREE_CHECK = "        run: bash .github/scripts/rebuild-vendored-wasm.sh --check-tree --repo-root .\n"
ACTION_P12 = "        P12_B64: ${{ inputs.developer-id-p12-base64 }}\n"
VARS_READ = "${{ vars.SAMPLE }}"
VARS_TEXT = "vars.SAMPLE ${{ format('{0}', 'vars.SAMPLE') }}"
VARS_LOCATIONS = (
    ("release.yml", RELEASE, RELEASE_WORKFLOW_ENV, RELEASE_WORKFLOW_ENV + "  SAMPLE: {}\n"),
    ("the called vendored-wasm workflow", WASM, WASM_JOBS, "env:\n  SAMPLE: {}\n\n" + WASM_JOBS),
    ("the signing action", ACTION, ACTION_P12, "        SAMPLE: {}\n" + ACTION_P12),
)


# label, [(file, old, new, expected occurrences)];
# the edited copy must pass.
PASSING = [
    ('optimized probes pass', [(REHEARSAL, REHEARSAL_PROBE_STEP, REHEARSAL_PROBE_STEP, 1)]),
    ("W17", changelog_edit(CHANGELOG_IF, '        if: "  ${{ ' + CHANGELOG_CONDITION + ' }}  "\n')),
    ("W15 main-only changelog changes pass", []),
    ("CI workflow_dispatch as an empty mapping passes", [(CI, CI_DISPATCH, "  workflow_dispatch: {}\n", 1)]),
    ("release evidence step token passes", []),
    ("workflow env without a token passes",
     [(RELEASE, RELEASE_WORKFLOW_ENV, RELEASE_WORKFLOW_ENV + "  SAMPLE: ${{ github.ref_name }}\n", 1)]),
    ("skill archive block run passes", [
        (CI, SKILL_ARCHIVE_RUN, "        run: |\n          .github/scripts/package-skill.sh --check\n", 1)]),
    ("apt-get in comments passes", [
        (TESTNET, APT_LIBUDEV_RUN,
         "        run: |\n          # sudo apt-get update\n          true # sudo apt-get install -y libudev-dev\n", 2)]),
    ("wrapped skill archive condition passes", [
        (CI, SKILL_ARCHIVE_IF, f"        if: ${{{{ {SKILL_ARCHIVE_CONDITION} }}}}\n", 1)]),
    ("wrapped tag cache guard passes", [
        (WASM, TAG_GUARD, "        if: ${{ github.ref_type != 'tag' }}\n", 2)]),
    ("wrapped Wasm rebuild and gate conditions pass", [
        (WASM, WASM_REBUILD_IF,
         "    needs: [check, stellar-cli-25, stellar-cli-28]\n    if: ${{ needs.check.outputs.rebuild == 'true' }}\n", 1),
        (WASM, WASM_GATE_IF, WASM_GATE_NEEDS + "    if: ${{ always() }}\n", 1)]),
    ("Wasm gate needs in another order pass", [
        (WASM, WASM_GATE_NEEDS, "    needs: [rebuild, stellar-cli-28, stellar-cli-25, check]\n", 1)]),
    ("coverage job condition without expression wrapper passes", [
        (COVERAGE, COVERAGE_OFF_HEADER, COVERAGE_OFF_HEADER.replace(COVERAGE_IF_LINE, COVERAGE_IF_UNWRAPPED_LINE), 1)]),
    ("coverage job condition with surrounding whitespace passes", [
        (COVERAGE, COVERAGE_OFF_HEADER, COVERAGE_OFF_HEADER.replace(COVERAGE_IF_LINE, COVERAGE_IF_SPACED_LINE), 1)]),
    ("coverage gate condition wrapped in ${{ }} passes", [
        (COVERAGE, COVERAGE_GATE_HEADER,
         COVERAGE_GATE_HEADER.replace(COVERAGE_GATE_IF_LINE, f"    if: ${{{{ {COVERAGE_GATE_CONDITION} }}}}\n"), 1)]),
    ("coverage gate needs in another order pass", [
        (COVERAGE, COVERAGE_GATE_NEEDS, "    needs: [changes, coverage-on, coverage-off]\n", 1)]),
    ("coverage gate result keys in single quotes pass", [
        (COVERAGE, COVERAGE_RESULT_ENV_LINES, COVERAGE_RESULT_ENV_LINES.replace('"', "'"), 1)]),
    ("coverage gate cancel condition wrapped in ${{ }} passes", [
        (COVERAGE, COVERAGE_CANCEL_FINAL, COVERAGE_CANCEL_FINAL.replace("if: cancelled()", "if: ${{ cancelled() }}"), 1)]),
    ("coverage parts in another order pass", coverage_move(COVERAGE_OFF_JOB, COVERAGE_GATE_START)),
    ("coverage seed branches in another order pass", [
        (COVERAGE, COVERAGE_PUSH_BLOCK, "  push:\n    branches: [main, next]\n", 1)]),
    ("save-if as a quoted expression passes", [
        (CI, CACHE_SAVE_LINE, "          save-if: \"${{ github.event_name == 'push' }}\"\n", 4)]),
    ("save-if with inner spaces passes", [
        (CI, CACHE_SAVE_LINE, "          save-if: ${{  github.event_name == 'push'  }}\n", 4)]),
    ("cancel-in-progress with inner spaces passes", [
        (COVERAGE, COVERAGE_CANCEL_LINE, "  cancel-in-progress: ${{  github.event_name == 'pull_request'  }}\n", 1)]),
    ("Wasm save guard wrapped in ${{ }} passes", [
        (WASM, SAVE_GUARD, f"        if: ${{{{ {WASM_SAVE_CONDITION} }}}}\n", 2)]),
    ("Wasm saves on push and schedule only pass", [
        (WASM, SAVE_GUARD, SAVE_GUARD, 2)]),
    ("rehearsal job that inherits the workflow permissions passes", [
        (REHEARSAL, REHEARSAL_TIMEOUT + REHEARSAL_JOB_PERMISSIONS,
         REHEARSAL_TIMEOUT + "    strategy:\n", 1)]),
    ("rehearsal workflow env with a date and a float passes", [
        (REHEARSAL, REHEARSAL_ENV,
         REHEARSAL_ENV + "  RELEASE_DATE: 2026-10-21\n  RATIO: 1.5\n", 1)]),
    ("rehearsal quoted closing braces without credentials passes", [
        in_rehearsal_version_step("          echo \"${{ format('{0}}}', 'x') }}\"\n")]),
    ("rehearsal quoted expression opener without credentials passes", [
        in_rehearsal_version_step("          echo \"${{ format('}} ${{ github', 'x') }}\"\n")]),
    ("archive check after a here-string passes", [
        (RELEASE, ARCHIVE_RUN, "run: |\n          cat <<< \"x\"\n          " + ARCHIVE_RUN[len("run: "):], 1)]),
    ("heredoc in a step without the archive check passes", [
        (RELEASE, VERIFY_PACKAGED_STEP, "      - name: Write notes\n        shell: bash\n        run: |\n"
         "          cat <<'EOF'\n          notes\n          EOF\n" + VERIFY_PACKAGED_STEP, 1)]),
] + [
    (f"vars text outside the context in {where} passes", [
        (path, old, new.format(VARS_TEXT), 1)])
    for where, path, old, new in VARS_LOCATIONS
]

# label, expected rule, a fragment that one line naming the rule must hold,
# [(file, old, new, expected occurrences)], optional exact count; each edit
# replaces every occurrence. A case that expects several lines gives
# tuples of rules and fragments of the same length, in output order.
CASES = [
    ('optimized probes job absent', 'rehearsal-security-probes',
     'expected exactly one optimized security probe step', [
        (REHEARSAL, '  build:\n',
         '  other-build:\n', 1)]),
    ('optimized probes missing', 'rehearsal-security-probes',
     'expected exactly one optimized security probe step', [
        (REHEARSAL, REHEARSAL_PROBE_STEP,
         '', 1)]),
    ('optimized probes duplicated', 'rehearsal-security-probes',
     'expected exactly one optimized security probe step', [
        (REHEARSAL, REHEARSAL_PROBE_STEP,
         REHEARSAL_PROBE_STEP * 2, 1)]),
    ('optimized probes duplicate renamed', 'rehearsal-security-probes',
     'expected exactly one optimized security probe step', [
        (REHEARSAL, REHEARSAL_PROBE_STEP,
         REHEARSAL_PROBE_STEP + REHEARSAL_PROBE_STEP.replace(
             'Verify optimized Wasm identity and deployment security', 'Other probe'), 1)]),
    ('optimized probes before build', 'rehearsal-security-probes',
     'probes must immediately follow Build binaries', [
        (REHEARSAL, REHEARSAL_BUILD_STEP + REHEARSAL_PROBE_STEP,
         REHEARSAL_PROBE_STEP + REHEARSAL_BUILD_STEP, 1)]),
    ('optimized probes separated', 'rehearsal-security-probes',
     'probes must immediately follow Build binaries', [
        (REHEARSAL, REHEARSAL_PROBE_STEP,
         '      - run: echo gap\n\n' + REHEARSAL_PROBE_STEP, 1)]),
    ('optimized probes build renamed', 'rehearsal-security-probes',
     'probes must immediately follow Build binaries', [
        (REHEARSAL, REHEARSAL_BUILD_STEP,
         REHEARSAL_BUILD_STEP.replace('Build binaries', 'Compile binaries'), 1)]),
    ('optimized probes guard changed', 'rehearsal-security-probes',
     'probe step differs from the required guard and command', [
        (REHEARSAL, REHEARSAL_PROBE_STEP,
         REHEARSAL_PROBE_STEP.replace("if: matrix.target == 'x86_64-unknown-linux-gnu'", "if: matrix.target == 'aarch64-unknown-linux-gnu'"), 1)]),
    ('optimized probes filter dropped', 'rehearsal-security-probes',
     'probe step differs from the required guard and command', [
        (REHEARSAL, REHEARSAL_PROBE_STEP,
         REHEARSAL_PROBE_STEP.replace('vendored_wasm_tests ', ''), 1)]),
    ('optimized probes features changed', 'rehearsal-security-probes',
     'probe step differs from the required guard and command', [
        (REHEARSAL, REHEARSAL_PROBE_STEP,
         REHEARSAL_PROBE_STEP.replace('test-helpers,deploy-cli', 'test-helpers'), 1)]),
    ('optimized probes release dropped', 'rehearsal-security-probes',
     'probe step differs from the required guard and command', [
        (REHEARSAL, REHEARSAL_PROBE_STEP,
         REHEARSAL_PROBE_STEP.replace('--release ', ''), 1)]),
    ('optimized probes no-run added', 'rehearsal-security-probes',
     'probe step differs from the required guard and command', [
        (REHEARSAL, REHEARSAL_PROBE_STEP,
         REHEARSAL_PROBE_STEP.replace('cargo test ', 'cargo test --no-run '), 1)]),
    ('optimized probes continue-on-error', 'rehearsal-security-probes',
     'probe step differs from the required guard and command', [
        (REHEARSAL, REHEARSAL_PROBE_STEP,
         REHEARSAL_PROBE_STEP.replace('        shell: bash', '        continue-on-error: true\n        shell: bash'), 1)]),
    ('optimized probes failure swallowed', 'rehearsal-security-probes',
     'probe step differs from the required guard and command', [
        (REHEARSAL, REHEARSAL_PROBE_STEP,
         REHEARSAL_PROBE_STEP.replace('deploy_policy_dry_run\n', 'deploy_policy_dry_run || true\n'), 1)]),
    ('optimized probes jobs prefix', 'rehearsal-security-probes',
     'probe step differs from the required guard and command', [
        (REHEARSAL, REHEARSAL_PROBE_STEP,
         REHEARSAL_PROBE_STEP.replace('cargo test ', 'CARGO_BUILD_JOBS=6 cargo test '), 1)]),
    ('optimized probes jobs step env', 'rehearsal-security-probes',
     'probe step differs from the required guard and command', [
        (REHEARSAL, REHEARSAL_PROBE_STEP,
         REHEARSAL_PROBE_STEP.replace('        shell: bash', '        env:\n          CARGO_BUILD_JOBS: 6\n        shell: bash'), 1)]),
    ('optimized probes name changed', 'rehearsal-security-probes',
     'probe step differs from the required guard and command', [
        (REHEARSAL, REHEARSAL_PROBE_STEP,
         REHEARSAL_PROBE_STEP.replace('Verify optimized Wasm identity and deployment security', 'Other probe'), 1)]),
    ('optimized probes command absent', 'rehearsal-security-probes',
     'probe step differs from the required guard and command', [
        (REHEARSAL, REHEARSAL_PROBE_STEP,
         REHEARSAL_PROBE_STEP.split('        run: |')[0] + '        run: echo skipped\n\n', 1)]),
    ('optimized probes workflow jobs', 'rehearsal-security-probes',
     'CARGO_BUILD_JOBS must be unset', [
        (REHEARSAL, '  EXPECTED_MAINNET_WRITE: "on"\n',
         '  EXPECTED_MAINNET_WRITE: "on"\n  CARGO_BUILD_JOBS: 6\n', 1)]),
    ('optimized probes job jobs', 'rehearsal-security-probes',
     'CARGO_BUILD_JOBS must be unset', [
        (REHEARSAL, '    timeout-minutes: 120\n',
         '    timeout-minutes: 120\n    env:\n      CARGO_BUILD_JOBS: 6\n', 1)]),
    ('optimized probes job suppression', 'rehearsal-security-probes',
     'probe job must not suppress failures', [
        (REHEARSAL, '    timeout-minutes: 120\n',
         '    timeout-minutes: 120\n    continue-on-error: true\n', 1)]),
    ("skill archive step duplicated", "skill-archive", "expected exactly one skill archive step", [
        (CI, SKILL_ARCHIVE_STEP, SKILL_ARCHIVE_STEP * 2, 1)], 1),
    ("skill archive step shell bypass", "skill-archive", "skill archive check can be bypassed", [
        (CI, SKILL_ARCHIVE_RUN, SKILL_ARCHIVE_RUN + "        shell: true {0}\n", 1)], 1),
    ("skill archive job shell bypass", "skill-archive", "skill archive check can be bypassed", [
        (CI, "  release-contracts:\n",
         "  release-contracts:\n    defaults:\n      run:\n        shell: true {0}\n", 1)], 1),
    ("skill archive workflow shell bypass", "skill-archive", "skill archive check can be bypassed", [
        (CI, "name: CI\n", "name: CI\ndefaults:\n  run:\n    shell: true {0}\n", 1)]),
    ("apt-get without retries", "apt-retries", "apt-get call lacks -o Acquire::Retries=3", [
        (TESTNET, "sudo apt-get -o Acquire::Retries=3 install -y gnome-keyring dbus",
         "sudo apt-get install -y gnome-keyring dbus", 2)], 2),
    ("apt-get multiline second call without retries", "apt-retries", "apt-get call lacks -o Acquire::Retries=3", [
        (TESTNET, APT_LIBUDEV_RUN,
         "        run: |\n          sudo apt-get -o Acquire::Retries=3 update\n"
         "          sudo apt-get install -y libudev-dev pkg-config\n", 2)], 2),
    ("CI pull request branches without main", "ci-triggers", "pull_request branches must include main", [
        (CI, "  pull_request:\n    branches: [main, next]\n",
         "  pull_request:\n    branches: [next]\n", 1)], 1),
    ("CI adds repository_dispatch", "ci-triggers",
     "archive condition must be re-evaluated for the new event: repository_dispatch", [
        (CI, "on:\n", "on:\n  repository_dispatch:\n", 1)], 1),
    ("CI without workflow_dispatch", "ci-triggers", "workflow_dispatch must be a trigger without inputs", [
        (CI, CI_DISPATCH, "", 1)], 1),
    ("CI workflow_dispatch with inputs", "ci-triggers", "workflow_dispatch must be a trigger without inputs", [
        (CI, CI_DISPATCH, CI_DISPATCH + "    inputs:\n      full:\n        type: boolean\n", 1)], 1),
    *RELEASE_EVIDENCE_CASES,
    ("skill archive step removed", "skill-archive", "expected exactly one skill archive step", [
        (CI, SKILL_ARCHIVE_STEP, "", 1)], 1),
    ("skill archive skipped for main pull requests", "skill-archive", "skill archive condition differs", [
        (CI, SKILL_ARCHIVE_IF, SKILL_ARCHIVE_IF.replace("'next'", "'main'"), 1)], 1),
    ("skill archive skipped for main pushes", "skill-archive", "skill archive condition differs", [
        (CI, SKILL_ARCHIVE_IF, SKILL_ARCHIVE_IF.replace("refs/heads/next", "refs/heads/main"), 1)], 1),
    ("skill archive always skipped", "skill-archive", "skill archive condition differs", [
        (CI, SKILL_ARCHIVE_IF, "        if: false\n", 1)], 1),
    ("skill archive without integration exception", "skill-archive", "skill archive condition differs", [
        (CI, SKILL_ARCHIVE_IF, "", 1)], 1),
    ("skill archive command removed", "skill-archive", "skill archive command differs", [
        (CI, SKILL_ARCHIVE_RUN, "        run: true\n", 1)], 1),
    ("skill archive continues on error", "skill-archive", "skill archive check can be bypassed", [
        (CI, SKILL_ARCHIVE_IF, SKILL_ARCHIVE_IF + "        continue-on-error: true\n", 1)], 1),
    ("skill archive job skipped", ("skill-archive", "ci-result", "ci-result"), (
        "skill archive check can be bypassed",
        "release-contracts has an unsupported docs-only job condition",
        "DOCS_REQUIRED must match CI docs-only job conditions"), [
        (CI, "  release-contracts:\n    needs: changes\n    if: ${{ !cancelled() }}\n", "  release-contracts:\n    needs: changes\n    if: false\n", 1)], 4),
    ("Wasm gate uses wrong ref type", "release-wasm-gate", "gate step must read each job result and the ref type", [
        (WASM, WASM_REF_TYPE, WASM_REF_TYPE.replace("${{ github.ref_type }}", "branch"), 1)]),
    ("crate publish without verified source guard", "credential-order", "no step before rust-lang/crates-io-auth-action runs [ \"$(git -C src", [
        (PUBLISH, PUBLISH_SOURCE_STEP, "", 1)]),
    ("crate publish echoes verified source", "credential-order", "no step before rust-lang/crates-io-auth-action runs [ \"$(git -C src", [
        (PUBLISH, '[ "$(git -C src rev-parse HEAD)" = "$VERIFIED_SHA" ]', 'echo "$VERIFIED_SHA"', 1)]),
    ("release build cache", "release-cache", "uses Swatinem/rust-cache", [
        (RELEASE, RELEASE_BUILD_STEP, CACHE_STEP + RELEASE_BUILD_STEP, 1)]),
    ("rehearsal build cache", "release-cache", "uses Swatinem/rust-cache", [
        (REHEARSAL, RELEASE_BUILD_STEP, CACHE_STEP + RELEASE_BUILD_STEP, 1)]),
    ("release verification cache", "release-cache", "uses actions/cache/restore", [
        (RELEASE, VERIFY_PACKAGED_STEP, CACHE_RESTORE + VERIFY_PACKAGED_STEP, 1)]),
    ("mixed-case release cache action", "release-cache", "uses Swatinem/Rust-Cache", [
        (RELEASE, RELEASE_BUILD_STEP, CACHE_STEP.replace("Swatinem/rust-cache", "Swatinem/Rust-Cache")
         + RELEASE_BUILD_STEP, 1)]),
    ("release setup action with a cache input", "release-cache",
     "release.yml:build: release-cache: passes a cache input to actions/setup-python", [
        (RELEASE, BUILD_PYTHON, BUILD_PYTHON.replace('"3.13"\n', '"3.13"\n          cache: pip\n'), 1)]),
    ("rehearsal setup action with a cache input", "release-cache",
     "release-rehearsal.yml:build: release-cache: passes a cache input to actions/setup-python", [
        (REHEARSAL, '          python-version: "3.13"\n', '          python-version: "3.13"\n          cache: pip\n', 1)]),
    ("signing without Wasm dependency", "release-wasm-gate", "hashes must need vendored-wasm", [
        (RELEASE, "needs: [preflight, vendored-wasm, build, sign-macos, verify-packaged]",
         "needs: [preflight, build, sign-macos, verify-packaged]", 1)], 1),
    ("Apple signing without Wasm dependency", "release-wasm-gate", "sign-macos must need vendored-wasm", [
        (RELEASE, "  sign-macos:\n    name: sign ${{ matrix.target }}\n    needs: [preflight, vendored-wasm, build]\n",
         "  sign-macos:\n    name: sign ${{ matrix.target }}\n    needs: [preflight, build]\n", 1)], 1),
    ("Apple signing with always condition", "release-wasm-gate", "sign-macos must not set if", [
        (RELEASE, "  sign-macos:\n    name: sign ${{ matrix.target }}\n    needs: [preflight, vendored-wasm, build]\n",
         "  sign-macos:\n    name: sign ${{ matrix.target }}\n    needs: [preflight, vendored-wasm, build]\n"
         "    if: ${{ always() }}\n", 1)], 1),
    ("Apple signing with not-cancelled condition", "release-wasm-gate", "sign-macos must not set if", [
        (RELEASE, "  sign-macos:\n    name: sign ${{ matrix.target }}\n    needs: [preflight, vendored-wasm, build]\n",
         "  sign-macos:\n    name: sign ${{ matrix.target }}\n    needs: [preflight, vendored-wasm, build]\n"
         "    if: ${{ !cancelled() }}\n", 1)], 1),
    ("Apple signing continues on error", "release-wasm-gate", "sign-macos must not set continue-on-error", [
        (RELEASE, "  sign-macos:\n    name: sign ${{ matrix.target }}\n    needs: [preflight, vendored-wasm, build]\n",
         "  sign-macos:\n    name: sign ${{ matrix.target }}\n    needs: [preflight, vendored-wasm, build]\n"
         "    continue-on-error: true\n", 1)], 2),
    ("Wasm rebuild job continues on error", "release-wasm-gate",
     "vendored-wasm.yml:rebuild: release-wasm-gate: rebuild continues on error", [
        (WASM, WASM_REBUILD_JOB, WASM_REBUILD_JOB + "    continue-on-error: true\n", 1)], 1),
    ("Wasm step continues on error", "release-wasm-gate",
     "vendored-wasm.yml:stellar-cli-25: release-wasm-gate: stellar-cli-25 step 1 continues on error", [
        (WASM, "        run: rustup toolchain install \"$HOST_RUSTC\" --profile minimal\n",
         "        run: rustup toolchain install \"$HOST_RUSTC\" --profile minimal\n        continue-on-error: true\n", 2)], 2),
    ("Wasm rebuild suppresses a failure", "release-wasm-gate",
     "vendored-wasm.yml:rebuild: release-wasm-gate: rebuild step 8 suppresses failures", [
        (WASM, WASM_COMPARE, WASM_COMPARE.replace('-work"\n', '-work" || true\n'), 1)], 1),
    ("Wasm check turns off errexit", "release-wasm-gate",
     "vendored-wasm.yml:check: release-wasm-gate: check step 4 suppresses failures", [
        (WASM, WASM_DECIDE_RUN, WASM_DECIDE_RUN + "          set +e\n", 1)], 1),
    ("Wasm gate suppresses a failure", ("release-wasm-gate", "release-wasm-gate"),
     ("vendored-wasm.yml:vendored-wasm: release-wasm-gate: vendored-wasm step 2 suppresses failures",
      "vendored-wasm.yml: release-wasm-gate: the gate step must run exactly"), [
        (WASM, WASM_GATE_RUN, WASM_GATE_RUN.replace('"$REF_TYPE"\n', '"$REF_TYPE" || true\n'), 1)], 2),
    ("Wasm gate job without always", "release-wasm-gate", "the vendored-wasm job must run on always()", [
        (WASM, WASM_GATE_IF, WASM_GATE_NEEDS, 1)], 1),
    ("Wasm gate job on success only", "release-wasm-gate", "the vendored-wasm job must run on always()", [
        (WASM, WASM_GATE_IF, WASM_GATE_NEEDS + "    if: success()\n", 1)], 1),
    ("Wasm gate job without the rebuild dependency", "release-wasm-gate",
     "the vendored-wasm job must need exactly check, rebuild, stellar-cli-25, stellar-cli-28", [
        (WASM, WASM_GATE_NEEDS, "    needs: [check, stellar-cli-25, stellar-cli-28]\n", 1)], 1),
    ("Wasm gate job with an extra dependency", "release-wasm-gate",
     "the vendored-wasm job must need exactly check, rebuild, stellar-cli-25, stellar-cli-28", [
        (WASM, WASM_GATE_NEEDS, "    needs: [check, stellar-cli-25, stellar-cli-28, rebuild, rebuild]\n", 1)], 1),
    ("conditional Wasm gate step", "release-wasm-gate", "the vendored-wasm job must run one gate step unconditionally", [
        (WASM, WASM_GATE_STEP, WASM_GATE_STEP + "        if: github.ref_type == 'tag'\n", 1)], 1),
    ("Wasm gate step without the ref type", "release-wasm-gate", "the gate step must run exactly", [
        (WASM, WASM_GATE_RUN, WASM_GATE_RUN.replace(' "$REF_TYPE"', ""), 1)], 1),
    ("Wasm gate step with a fixed job result", "release-wasm-gate", "the gate step must read each job result", [
        (WASM, "          REBUILD_JOB: ${{ needs.rebuild.result }}\n", "          REBUILD_JOB: success\n", 1)], 1),
    ("Wasm rebuild on always", "release-wasm-gate", "rebuild must run exactly on needs.check.outputs.rebuild == 'true'", [
        (WASM, WASM_REBUILD_IF, "    needs: [check, stellar-cli-25, stellar-cli-28]\n    if: always()\n", 1)], 1),
    ("conditional Wasm rebuild and compare", "release-wasm-gate", "rebuild must rebuild and compare unconditionally", [
        (WASM, WASM_COMPARE_STEP, WASM_COMPARE_STEP + "        if: github.ref_type != 'tag'\n", 1)], 1),
    ("Wasm download from another run", "release-wasm-gate", "rebuild downloads an artifact with run-id", [
        (WASM, WASM_DOWNLOAD_25, WASM_DOWNLOAD_25 + "          run-id: 1\n", 1)], 1),
    ("Wasm download with a token", "release-wasm-gate", "rebuild downloads an artifact with github-token", [
        (WASM, WASM_DOWNLOAD_25, WASM_DOWNLOAD_25 + "          github-token: ${{ github.token }}\n", 1)], 1),
    ("Wasm download from another repository", "release-wasm-gate", "rebuild downloads an artifact with repository", [
        (WASM, WASM_DOWNLOAD_25, WASM_DOWNLOAD_25 + "          repository: other/repo\n", 1)], 1),
    ("release without Wasm call", "release-wasm-gate", "must call the local workflow", [
        (RELEASE, WASM_CALL, "", 1)]),
    ("conditional Wasm call", "release-wasm-gate", "must call the local workflow", [
        (RELEASE, WASM_CALL, WASM_CALL + "    if: false\n", 1)]),
    ("Wasm call with inputs", "release-wasm-gate", "must call the local workflow", [
        (RELEASE, WASM_CALL, WASM_CALL + "    with: {}\n", 1)]),
    ("Wasm call with secrets", "release-wasm-gate", "must call the local workflow", [
        (RELEASE, WASM_CALL, WASM_CALL + "    secrets: inherit\n", 1)]),
    ("publication without Wasm dependency", "release-wasm-gate", "publish must need vendored-wasm", [
        (RELEASE, "needs: [preflight, vendored-wasm, build, sign-macos, sign,", "needs: [preflight, build, sign-macos, sign,", 1)]),
    ("Wasm workflow not callable", "release-wasm-gate", "workflow_call is absent", [
        (WASM, live_text(WASM, re.compile(r"  workflow_call:\n.*?(?=  pull_request:)", re.DOTALL),
                          "workflow call inputs"), "", 1)]),
    ("Wasm restore without tag guard", "release-wasm-gate", "cache guard must lead", [
        (WASM, TAG_GUARD, "", 2)]),
    ("Wasm save with trailing tag guard", ("release-wasm-gate", "release-wasm-gate"),
     ("cache guard must lead", "cache save must run exactly"), [
        (WASM, SAVE_GUARD, "        if: steps.restore.outputs.cache-hit != 'true' && github.ref_type != 'tag'\n", 2)]),
    ("Wasm save on every event", "release-wasm-gate", "cache save must run exactly", [
        (WASM, SAVE_GUARD, WASM_OLD_SAVE_GUARD, 2)]),
    ("Wasm save on pull requests", "release-wasm-gate", "cache save must run exactly", wasm_save_events(
        "(github.event_name == 'push' || github.event_name == 'schedule' || github.event_name == 'pull_request')")),
    ("Wasm save on pull request targets", "release-wasm-gate", "cache save must run exactly", wasm_save_events(
        "(github.event_name == 'push' || github.event_name == 'schedule' || github.event_name == 'pull_request_target')")),
    ("Wasm save on dispatch", "release-wasm-gate", "cache save must run exactly", wasm_save_events(
        "(github.event_name == 'push' || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')")),
    ("Wasm save outside pull requests only", "release-wasm-gate", "cache save must run exactly",
     wasm_save_events("github.event_name != 'pull_request'")),
    ("Wasm save on pushes only", "release-wasm-gate", "cache save must run exactly",
     wasm_save_events("github.event_name == 'push'")),
    ("Wasm combined cache action", "release-wasm-gate", "which saves outside a save step", [
        (WASM, WASM_SAVE_STEP, WASM_CACHE_COMBINED + WASM_SAVE_STEP, 2)]),
    ("Wasm rebuild cache", "release-wasm-gate", "rebuild uses a cache", [
        (WASM, "      - name: Download stellar-cli 25\n", CACHE_RESTORE + "      - name: Download stellar-cli 25\n", 1)]),
    ("Wasm rebuild missing artifact", "release-wasm-gate", "rebuild does not download vendored-wasm-stellar-cli-25", [
        (WASM, "          name: vendored-wasm-stellar-cli-25\n          path: ${{ runner.temp }}/stellar-cli-artifacts",
         "          name: another-artifact\n          path: ${{ runner.temp }}/stellar-cli-artifacts", 1)]),
    ("release toolchain differs", "release-toolchain", "RELEASE_TOOLCHAIN differs from publish.yml", [
        (RELEASE, '  RELEASE_TOOLCHAIN: "1.100.0"\n', '  RELEASE_TOOLCHAIN: "1.98.0"\n', 1)]),
    ("release build on stable", "release-toolchain", "it installs another toolchain", [
        (RELEASE, BUILD_TOOLCHAIN, BUILD_TOOLCHAIN.replace("${{ env.RELEASE_TOOLCHAIN }}", "stable"), 1)]),
    ("release build without toolchain pin", "release-toolchain", "it does not pin RUSTUP_TOOLCHAIN", [
        (RELEASE, BUILD_PIN_STEP, "", 1)]),
    ("rehearsal build without toolchain pin", "release-toolchain", "it does not pin RUSTUP_TOOLCHAIN", [
        (REHEARSAL, BUILD_PIN_STEP, "", 1)]),
    ("publication without checksum check", "release-publish-sums", "publish must verify sums", [
        (RELEASE, SUMS_STEP, "", 1)]),
    ("conditional publication checksum check", "release-publish-sums", "publish must verify sums", [
        (RELEASE, SUMS_STEP, SUMS_STEP + "        if: false\n", 1)]),
    ("checksum check after publication", "release-publish-sums", "publish must verify sums", [
        (RELEASE, SUMS_STEP, "", 1),
        (RELEASE, RELEASE_LAST_LINE, RELEASE_LAST_LINE + SUMS_STEP, 1)]),
    ("labels workflow without top-level permissions", "workflow-permissions",
     'labels.yml: workflow-permissions: no top-level permissions', [
        (".github/workflows/labels.yml", "permissions: {}\n", "", 1)]),
    ("stale workflow without top-level permissions", "workflow-permissions",
     'stale.yml: workflow-permissions: no top-level permissions', [
        (".github/workflows/stale.yml", "permissions: {}\n", "", 1)]),
    ("labels checkout that persists credentials", "checkout-credentials",
     'labels.yml:sync step 1: checkout-credentials: actions/checkout without persist-credentials: false', [
        (".github/workflows/labels.yml", "persist-credentials: false", "persist-credentials: true", 1)]),
    ("triage workflow without top-level permissions", "workflow-permissions",
     'triage.yml: workflow-permissions: no top-level permissions', [
        (TRIAGE, "\npermissions: {}\n", "\n", 1)]),
    ("triage review workflow without top-level permissions", "workflow-permissions",
     'triage-review.yml: workflow-permissions: no top-level permissions', [
        (TRIAGE_REVIEW, "\npermissions: {}\n", "\n", 1)]),
    ("triage sweep workflow without top-level permissions", "workflow-permissions",
     'triage-sweep.yml: workflow-permissions: no top-level permissions', [
        (TRIAGE_SWEEP, "\npermissions: {}\n", "\n", 1)]),
    ("welcome workflow without top-level permissions", "workflow-permissions",
     'welcome.yml: workflow-permissions: no top-level permissions', [
        (WELCOME, "\npermissions: {}\n", "\n", 1)]),
    ("rust-cache in the signing job", "cred-compile",
     'release.yml:sign-macos step 2: cred-compile: uses Swatinem/rust-cache@', [before_sign_macos_tools(
        f"      - uses: Swatinem/rust-cache@{PLACEHOLDER_REVISION}\n\n")]),
    ("cargo build in the signing job", "cred-compile",
     'release.yml:sign-macos step 2: cred-compile: runs cargo build: cargo build --release --locked', [before_sign_macos_tools(
        "      - run: cargo build --release --locked\n\n")]),
    ("cargo alias with a toolchain override in the signing job", "cred-compile",
     'release.yml:sign-macos step 2: cred-compile: runs cargo b: cargo b', [before_sign_macos_tools(
        "      - run: cargo +stable b\n\n")]),
    ("cross in the signing job", "cred-compile",
     'release.yml:sign-macos step 2: cred-compile: runs cross: cross build --release', [before_sign_macos_tools(
        "      - run: cross build --release\n\n")]),
    ("cargo package without --no-verify in the publish job", "cred-compile",
     'cred-compile: cargo package without --no-verify: cargo package --workspace --locked --target-dir', [
        (PUBLISH, "--locked --no-verify --target-dir", "--locked --target-dir", 1)]),
    ("cargo publish without --no-verify in the publish script", "cred-compile",
     'publish-crates.sh: cred-compile: cargo publish without --no-verify: cargo publish -p "$name" --locked 2>', [
        (PUBLISH_SCRIPT, 'cargo publish -p "$name" --locked --no-verify 2>&1',
         'cargo publish -p "$name" --locked 2>&1', 1)]),
    ("cargo build after cargo -V on one line in the signing job", "cred-compile",
     'release.yml:sign-macos step 2: cred-compile: runs cargo build: cargo build --release', [before_sign_macos_tools(
        "      - run: cargo -V && cargo build --release\n\n")]),
    ("second cargo publish without --no-verify on the publish line", "cred-compile",
     'publish-crates.sh: cred-compile: cargo publish without --no-verify: cargo publish -p "$name" --locked 2>', [
        (PUBLISH_SCRIPT, PUBLISH_CALL,
         'cargo publish -p "$name" --locked --no-verify --dry-run 2>&1 && '
         'cargo publish -p "$name" --locked 2>&1 | tee "$log"', 1)]),
    ("cargo build in a command substitution after cargo -V", "cred-compile",
     'release.yml:sign-macos step 2: cred-compile: runs cargo build: cargo build --release', [before_sign_macos_tools(
        '      - run: echo "$(cargo -V) $(cargo build --release)"\n\n')]),
    ("cargo package whose --no-verify belongs to the next command", "cred-compile",
     'cred-compile: cargo package without --no-verify: cargo package --workspace --locked --target-dir', [
        (PUBLISH, PUBLISH_PACKAGE_RUN,
         '        run: cargo package --workspace --locked --target-dir "$RUNNER_TEMP/publish-target" '
         '&& echo --no-verify\n', 1)]),
    ("cargo package in a command substitution with --no-verify after it", "cred-compile",
     'cred-compile: cargo package without --no-verify: cargo package --workspace --locked --target-dir', [
        (PUBLISH, PUBLISH_PACKAGE_RUN,
         '        run: echo "$(cargo package --workspace --locked --target-dir "$RUNNER_TEMP/publish-target")" '
         '--no-verify\n', 1)]),
    ("cargo publish with --no-verify only in a trailing comment", "cred-compile",
     'publish-crates.sh: cred-compile: cargo publish without --no-verify: cargo publish -p "$name" --locked', [
        (PUBLISH_SCRIPT, PUBLISH_CALL, 'cargo publish -p "$name" --locked # --no-verify', 1)]),
    ("cargo build by absolute path in the signing job", "cred-compile",
     'release.yml:sign-macos step 2: cred-compile: runs cargo build: cargo build --release', [before_sign_macos_tools(
        "      - run: $HOME/.cargo/bin/cargo build --release\n\n")]),
    ("cargo build by a quoted path in the signing job", "cred-compile",
     'release.yml:sign-macos step 2: cred-compile: runs cargo build: cargo build --release', [before_sign_macos_tools(
        '      - run: |\n          "$HOME/.cargo/bin/cargo" build --release\n\n')]),
    ("cargo build in a composite action script", "cred-compile",
     'sign-notarize.sh: cred-compile: runs cargo build: cargo build --release', [
        (SIGN_SCRIPT, "umask 077\n", "umask 077\ncargo build --release\n", 1)]),
    ("rust-cache inside the composite action", "cred-compile",
     'action.yml step 1: cred-compile: uses Swatinem/rust-cache@', [
        (ACTION, "  steps:\n    - name: Sign and notarize\n",
         f"  steps:\n    - uses: Swatinem/rust-cache@{PLACEHOLDER_REVISION}\n"
         "    - name: Sign and notarize\n", 1)]),
    ("credentialed job names a missing script", "cred-compile",
     'cred-compile: names .github/scripts/publish-crates-missing.sh, which does not exist', [
        (PUBLISH, '"$GITHUB_WORKSPACE/wf/.github/scripts/publish-crates.sh"',
         '"$GITHUB_WORKSPACE/wf/.github/scripts/publish-crates-missing.sh"', 1)]),
    ("workflow-level id-token makes the smoke build job credentialed", "cred-compile",
     'notarize-smoke.yml:build step 4 (Build binaries): cred-compile: runs cargo build', [
        (SMOKE, "\npermissions:\n  contents: read\n\njobs:\n",
         "\npermissions:\n  contents: read\n  id-token: write\n\njobs:\n", 1)]),
    ("toolchain install in the signing job", "cred-toolchain",
     'release.yml:sign-macos step 2: cred-toolchain: installs a Rust toolchain', [before_sign_macos_tools(
        f"      - uses: dtolnay/rust-toolchain@{PLACEHOLDER_REVISION}\n"
        "        with:\n          toolchain: stable\n\n")]),
    ("build job references release-signing", "signing-env",
     'release.yml:build: signing-env: references release-signing', [
        (RELEASE, "    name: build ${{ matrix.target }}\n    needs: preflight\n",
         "    name: build ${{ matrix.target }}\n    needs: preflight\n    environment: release-signing\n", 1)]),
    ("release signing job without its environment", "signing-env",
     'release.yml:sign-macos: signing-env: signing job does not declare environment: release-signing', [
        (RELEASE, "    environment: release-signing\n    permissions:\n      contents: read\n    strategy:\n",
         "    permissions:\n      contents: read\n    strategy:\n", 1)]),
    ("smoke signing job without its environment", "signing-env",
     'notarize-smoke.yml:sign: signing-env: signing job does not declare environment: release-signing', [
        (SMOKE, "    environment: release-signing\n", "", 1)]),
    ("Apple secret in the hashes job", "signing-env",
     'release.yml:hashes: signing-env: references an APPLE_ secret', [
        (RELEASE, "        id: subjects\n        env:\n",
         "        id: subjects\n        env:\n          LEAK: ${{ secrets.APPLE_ASC_KEY_ID }}\n", 1)]),
    ("checkout that persists credentials", "checkout-credentials",
     'release.yml:preflight step 1: checkout-credentials: actions/checkout without persist-credentials: false', [
        (RELEASE, "          persist-credentials: false\n", "          persist-credentials: true\n", 7)]),
    ("checkout without the persist-credentials input", "checkout-credentials",
     'notarize-smoke.yml:build step 1: checkout-credentials: actions/checkout without persist-credentials: false', [
        (SMOKE, "        with:\n          persist-credentials: false\n", "", 2)]),
    ("input interpolated into a run block", "run-inputs",
     'publish.yml:verify step 11 (Build and package every crate): run-inputs: run: reads ${{ inputs.tag }}', [
        (PUBLISH, "          cargo package --workspace --locked\n",
         "        run: echo \"${{ inputs.tag }}\" && cargo package --workspace --locked\n", 1)]),
    ("job output interpolated into a credentialed run block", "cred-run-outputs",
     'release.yml:publish step 1 (Validate the release version): cred-run-outputs: run: reads ${{ needs.preflight.outputs.version }}', [
        (RELEASE, 'if [[ "$VERSION" == *-* ]]; then',
         'if [[ "${{ needs.preflight.outputs.version }}" == *-* ]]; then', 1)]),
    ("step output interpolated into a credentialed run block", "cred-run-outputs",
     "publish.yml:publish step 12 (Require the archives to equal the verify job's checksums): cred-run-outputs: run: reads ${{ steps.tag.outputs.version }}", [
        (PUBLISH, '"$RUNNER_TEMP/publish-target/package" "$VERSION"',
         '"$RUNNER_TEMP/publish-target/package" "${{ steps.tag.outputs.version }}"', 1)]),
    ("job output passed to an action in a credentialed job", "cred-with-needs",
     'release.yml:publish step 9 (Create GitHub Release): cred-with-needs: passes needs output to with: tag_name', [
        (RELEASE, "tag_name: v${{ steps.version.outputs.version }}",
         "tag_name: v${{ needs.preflight.outputs.version }}", 1)]),
    ("job output passed to a reusable workflow outside the allowlist", "cred-with-needs",
     'release.yml:attest: cred-with-needs: passes ${{ needs.hashes.outputs.subjects }} to the reusable workflow input base64-subjects', [
        (RELEASE, "  provenance:\n    name: provenance\n", "  attest:\n    name: provenance\n", 1),
        (RELEASE, "needs: [preflight, vendored-wasm, build, sign-macos, sign, hashes, provenance, verify-provenance]",
         "needs: [preflight, vendored-wasm, build, sign-macos, sign, hashes, attest, verify-provenance]", 1)]),
    ("another job output passed to the provenance generator", "cred-with-needs",
     "release.yml:provenance: cred-with-needs: passes ${{ needs.build.result == 'success' }} to the reusable workflow input compile-generator", [
        (RELEASE, "      upload-assets: false\n",
         "      upload-assets: false\n      compile-generator: ${{ needs.build.result == 'success' }}\n", 1)]),
    ("credentialed step reads a job output without a pattern test", "cred-env-validation",
     'release.yml:sign-macos step 3 (Validate the release version): cred-env-validation: env VERSION reads ${{ needs.preflight.outputs.version }} with no =~ test', [
        (RELEASE, SIGN_MACOS_VERSION_TEST, SIGN_MACOS_VERSION_OUTPUT, 1)]),
    ("credentialed step tests a job output only in a comment line", "cred-env-validation",
     'release.yml:sign-macos step 3 (Validate the release version): cred-env-validation: env VERSION reads ${{ needs.preflight.outputs.version }} with no =~ test', [
        (RELEASE, SIGN_MACOS_VERSION_TEST,
         '          # [[ "$VERSION" =~ $version_re ]]\n' + SIGN_MACOS_VERSION_OUTPUT, 1)]),
    ("credentialed job maps a job output into its job env", "cred-env-validation",
     'release.yml:publish: cred-env-validation: job env VERSION reads ${{ needs.preflight.outputs.version }}', [
        (RELEASE, "    permissions:\n      contents: write\n    steps:\n",
         "    permissions:\n      contents: write\n    env:\n"
         "      VERSION: ${{ needs.preflight.outputs.version }}\n    steps:\n", 1)]),
    ("credentialed download into the workspace", "cred-download-path",
     'release.yml:sign step 2: cred-download-path: downloads to artifacts', [
        (RELEASE, "          path: ${{ runner.temp }}/artifacts\n", "          path: artifacts\n", 1)]),
    ("credentialed download that leaves the temp directory", "cred-download-path",
     'release.yml:sign step 2: cred-download-path: downloads to ${{ runner.temp }}/../work/artifacts', [
        (RELEASE, "          path: ${{ runner.temp }}/artifacts\n",
         "          path: ${{ runner.temp }}/../work/artifacts\n", 1)]),
    ("credentialed download without a path", "cred-download-path",
     'publish.yml:publish step 9: cred-download-path: downloads to the workspace', [
        (PUBLISH, "          name: verify-sums\n          path: ${{ runner.temp }}/verify\n",
         "          name: verify-sums\n", 1)]),
    ("publish job downloads verify-crates", "verify-crates-download",
     'publish.yml:publish step 9: verify-crates-download: can download verify-crates', [
        (PUBLISH, "          name: verify-sums\n          path: ${{ runner.temp }}/verify\n",
         "          name: verify-crates\n          path: ${{ runner.temp }}/verify\n", 1)]),
    ("publish job downloads by a pattern that matches verify-crates", "verify-crates-download",
     'publish.yml:publish step 9: verify-crates-download: can download verify-crates', [
        (PUBLISH, "          name: verify-sums\n          path: ${{ runner.temp }}/verify\n",
         "          pattern: verify-*\n          path: ${{ runner.temp }}/verify\n", 1)]),
    ("publish job mints the token without the checksum comparison", "credential-order",
     'publish.yml:publish: credential-order: no step before rust-lang/crates-io-auth-action runs compare-crate-sums.py', [
        (PUBLISH, PUBLISH_COMPARE_STEP, "", 1)]),
    ("smoke signing job without a clean-checkout check", "credential-order",
     'notarize-smoke.yml:sign: credential-order: no step before ./.github/actions/macos-sign-notarize runs status --porcelain', [
        (SMOKE, SMOKE_CLEAN_CHECK, 'status=""', 2)]),
    ("release signing job without the signing action", "credential-order",
     'release.yml:sign-macos: credential-order: no step uses ./.github/actions/macos-sign-notarize', [
        (RELEASE, "        uses: ./.github/actions/macos-sign-notarize\n",
         "        uses: ./.github/actions/macos-sign-and-notarize\n", 1)]),
    ("cache restore in the signing job", "cred-compile",
     "release.yml:sign-macos step 2: cred-compile: uses actions/cache/restore@", [before_sign_macos_tools(
        f"      - uses: actions/cache/restore@{PLACEHOLDER_REVISION}\n"
        "        with:\n          path: ~/.cargo/bin\n          key: tools\n\n")]),
    ("cargo package in a backtick substitution with --no-verify after it", "cred-compile",
     "cred-compile: cargo package without --no-verify: cargo package --workspace --locked --target-dir", [
        (PUBLISH, PUBLISH_PACKAGE_RUN,
         '        run: echo `cargo package --workspace --locked --target-dir "$RUNNER_TEMP/publish-target"` '
         '--no-verify\n', 1)]),
    ("bare cargo package in backticks with --no-verify after it", "cred-compile",
     "cred-compile: cargo package without --no-verify: cargo package", [
        (PUBLISH, PUBLISH_PACKAGE_RUN, "        run: echo `cargo package` --no-verify\n", 1)]),
    ("bare cargo package in a command substitution with --no-verify after it", "cred-compile",
     "cred-compile: cargo package without --no-verify: cargo package", [
        (PUBLISH, PUBLISH_PACKAGE_RUN, '        run: echo "$(cargo package)" --no-verify\n', 1)]),
    ("publish job validates the tag input without a pattern test", "cred-env-validation",
     "publish.yml:publish step 1 (Validate the tag input): cred-env-validation: env TAG reads ${{ inputs.tag }} "
     "with no =~ test", [
        (PUBLISH, PUBLISH_TAG_TEST, PUBLISH_TAG_OUTPUT, 1)]),
    ("publish job maps the tag input into its job env", "cred-env-validation",
     "publish.yml:publish: cred-env-validation: job env TAG reads ${{ inputs.tag }}", [
        (PUBLISH, "    environment: crates-io\n",
         "    environment: crates-io\n    env:\n      TAG: ${{ inputs.tag }}\n", 1)]),
    ("publish workflow maps the tag input into its workflow env", "cred-env-validation",
     "publish.yml:publish: cred-env-validation: workflow env TAG_RAW reads ${{ inputs.tag }}", [
        (PUBLISH, '  RELEASE_TOOLCHAIN: "1.100.0"\n',
         '  RELEASE_TOOLCHAIN: "1.100.0"\n  TAG_RAW: ${{ inputs.tag }}\n', 1)]),
    ("release signing job without the archive validation", "credential-order",
     "release.yml:sign-macos: credential-order: no step before ./.github/actions/macos-sign-notarize "
     "runs validate-input.sh", [
        (RELEASE, SIGN_MACOS_VALIDATE_STEP, "", 1)]),
    ("release signing job without a clean-checkout check", "credential-order",
     "release.yml:sign-macos: credential-order: no step before ./.github/actions/macos-sign-notarize "
     "runs status --porcelain", [
        (RELEASE, SMOKE_CLEAN_CHECK, 'status=""', 2)]),
    ("smoke signing job without the archive validation", "credential-order",
     "notarize-smoke.yml:sign: credential-order: no step before ./.github/actions/macos-sign-notarize "
     "runs validate-input.sh", [
        (SMOKE, SMOKE_VALIDATE_STEP, "", 1)]),
    ("publish job checks ancestry only after the token step", "credential-order",
     "publish.yml:publish: credential-order: no step before rust-lang/crates-io-auth-action "
     "runs check-ref-on-main.sh",
     publish_job_only(PUBLISH_ANCESTRY_STEP, "", 1) + [(PUBLISH, PUBLISH_AUTH, PUBLISH_AUTH + PUBLISH_ANCESTRY_STEP, 1)]),
    ("publish job compares the checksums after the token step", "credential-order",
     "publish.yml:publish: credential-order: no step before rust-lang/crates-io-auth-action "
     "runs compare-crate-sums.py", [
        (PUBLISH, PUBLISH_COMPARE_STEP, "", 1),
        (PUBLISH, PUBLISH_AUTH, PUBLISH_AUTH + PUBLISH_COMPARE_STEP, 1)]),
    ("publish job without a clean-checkout check", "credential-order",
     "publish.yml:publish: credential-order: no step before rust-lang/crates-io-auth-action "
     "runs status --porcelain", publish_job_only(PUBLISH_CLEAN_CHECK, 'status=""', 2)),
    ("publish job toolchain check that never runs rustc -V", "credential-order",
     "publish.yml:publish: credential-order: no step before rust-lang/crates-io-auth-action runs rustc -V", [
        (PUBLISH, PUBLISH_TOOLCHAIN_STEP,
         "      - name: Require the pinned toolchain\n        working-directory: src\n        run: |\n"
         '          set -euo pipefail\n          read -r _ cargo_release _ <<<"$(cargo -V)"\n'
         "          rustc_release=$RELEASE_TOOLCHAIN\n", 1),
        (PUBLISH, "          cargo -V\n          rustc -V\n", "          cargo -V\n", 1)]),
    ("release signing job without the clean check before signing", "credential-order",
     "release.yml:sign-macos: credential-order: no step between validate-input.sh and "
     "./.github/actions/macos-sign-notarize runs status --porcelain", [
        (RELEASE, SIGNING_CLEAN_STEP, "", 1)]),
    ("smoke signing job without the clean check before signing", "credential-order",
     "notarize-smoke.yml:sign: credential-order: no step between validate-input.sh and "
     "./.github/actions/macos-sign-notarize runs status --porcelain", [
        (SMOKE, SIGNING_CLEAN_STEP, "", 1)]),
    ("publish job without the clean check before the token", "credential-order",
     "publish.yml:publish: credential-order: no step between compare-crate-sums.py and "
     "rust-lang/crates-io-auth-action runs status --porcelain", [
        (PUBLISH, PUBLISH_TOKEN_CLEAN_STEP, "", 1)]),
    ("publish job checksum comparison that may fail", "credential-order",
     "publish.yml:publish: credential-order: guard step \"Require the archives to equal the verify job's "
     "checksums\" sets if or continue-on-error", [
        (PUBLISH, "      - name: Require the archives to equal the verify job's checksums\n",
         "      - name: Require the archives to equal the verify job's checksums\n"
         "        continue-on-error: true\n", 1)]),
    ("release signing job validation that may be skipped", "credential-order",
     "release.yml:sign-macos: credential-order: guard step 'Validate the unsigned binaries' "
     "sets if or continue-on-error", [
        (RELEASE, "      - name: Validate the unsigned binaries\n        env:\n",
         "      - name: Validate the unsigned binaries\n        if: false\n        env:\n", 1)]),
    ("smoke signing job that may fail", "credential-order",
     "notarize-smoke.yml:sign: credential-order: the job sets continue-on-error", [
        (SMOKE, "    environment: release-signing\n",
         "    continue-on-error: true\n    environment: release-signing\n", 1)]),
    ("publish job discards the checksum comparison result", "credential-order",
     f"publish.yml:publish: credential-order: {COMPARE_GUARD} holds compare-crate-sums.py on a line with "
     "a shell operator", [
        (PUBLISH, PUBLISH_COMPARE_CALL, PUBLISH_COMPARE_CALL.replace('"$VERSION"\n', '"$VERSION" || true\n'), 1)]),
    ("publish job skips the checksum comparison behind a shell operator", "credential-order",
     f"publish.yml:publish: credential-order: {COMPARE_GUARD} holds compare-crate-sums.py on a line with "
     "a shell operator", [
        (PUBLISH, PUBLISH_COMPARE_CALL, PUBLISH_COMPARE_CALL.replace("python3 ", "true || python3 ", 1), 1)]),
    ("release signing job discards the archive validation result", "credential-order",
     f"release.yml:sign-macos: credential-order: {VALIDATE_GUARD} holds validate-input.sh on a line with "
     "a shell operator", [
        (RELEASE, SIGN_MACOS_VALIDATE_ARGS, SIGN_MACOS_VALIDATE_ARGS.replace('"$ARCH"\n', '"$ARCH" || true\n'), 1)]),
    ("release signing job runs the archive validation in the background", "credential-order",
     f"release.yml:sign-macos: credential-order: {VALIDATE_GUARD} holds validate-input.sh on a line with "
     "a shell operator", [
        (RELEASE, SIGN_MACOS_VALIDATE_ARGS, SIGN_MACOS_VALIDATE_ARGS.replace('"$ARCH"\n', '"$ARCH" &\n'), 1)]),
    ("publish job chains a command after the toolchain check", "credential-order",
     "publish.yml:publish: credential-order: guard step 'Require the pinned toolchain' holds rustc -V on a line "
     "with a shell operator", [
        (PUBLISH, "          cargo -V\n          rustc -V\n", "          cargo -V\n          rustc -V; true\n", 1)]),
    ("publish job compare step turns off errexit", "credential-order",
     f"publish.yml:publish: credential-order: {COMPARE_GUARD} turns off errexit", [
        (PUBLISH, "          set -euo pipefail\n" + PUBLISH_COMPARE_CALL, "          set +e\n" + PUBLISH_COMPARE_CALL, 1)]),
    ("release signing validation step turns off errexit by name", "credential-order",
     f"release.yml:sign-macos: credential-order: {VALIDATE_GUARD} turns off errexit", [
        (RELEASE, "          /bin/bash .github/actions/macos-sign-notarize/validate-input.sh \\\n" + SIGN_MACOS_VALIDATE_ARGS,
         "          set +o errexit\n          /bin/bash .github/actions/macos-sign-notarize/validate-input.sh \\\n"
         + SIGN_MACOS_VALIDATE_ARGS, 1)]),
    ("release signing job checks the checkout only before the download", "credential-order",
     "release.yml:sign-macos: credential-order: no step between the download and validate-input.sh "
     "runs status --porcelain", [
        (RELEASE, SIGNING_FIRST_CLEAN_BLOCK, "", 1),
        (RELEASE, SIGN_MACOS_DOWNLOAD_STEP, SIGNING_FIRST_CLEAN_BLOCK + SIGN_MACOS_DOWNLOAD_STEP, 1)]),
    ("smoke signing job without the clean check after the download", "credential-order",
     "notarize-smoke.yml:sign: credential-order: no step between the download and validate-input.sh "
     "runs status --porcelain", [
        (SMOKE, SIGNING_FIRST_CLEAN_BLOCK, "", 1)]),
    ("publish job without the clean check after the download", "credential-order",
     "publish.yml:publish: credential-order: no step between the download and compare-crate-sums.py "
     "runs status --porcelain", [
        (PUBLISH, PUBLISH_FIRST_CLEAN_BLOCK, "", 1)]),
    ("expression in a composite run block", "composite-expression",
     'action.yml step 2: composite-expression: run: holds ${{ inputs.version }}', [
        (ACTION, 'run: /bin/bash "$ACTION_DIR/archive.sh"\n',
         'run: /bin/bash "$ACTION_DIR/archive.sh" "${{ inputs.version }}"\n', 1)]),
    ("publish checkout of an unqualified tag", "publish-tag-ref",
     "publish.yml:verify step 2: publish-tag-ref: checkout ref '${{ steps.tag.outputs.tag }}' is neither refs/tags/... nor github.workflow_sha", [
        (PUBLISH, "ref: refs/tags/${{ steps.tag.outputs.tag }}", "ref: ${{ steps.tag.outputs.tag }}", 3)]),
    ("publish checkout without a ref", "publish-tag-ref",
     "publish.yml:verify step 3: publish-tag-ref: checkout ref '' is neither refs/tags/... nor github.workflow_sha", [
        (PUBLISH, "          ref: ${{ github.workflow_sha }}\n", "", 3)]),
    ("another local workflow call in publish.yml", "publish-tag-ref", "no checkout of refs/tags/...", [
        (PUBLISH, PUBLISH_EVIDENCE, PUBLISH_EVIDENCE + "  extra:\n    needs: verify\n    uses: ./.github/workflows/ci.yml\n\n", 1)]),
    ("release preflight without the ancestry check", "ancestry-check",
     'release.yml:preflight: ancestry-check: no line runs check-ref-on-main.sh as its command', [
        (RELEASE, '      - name: Refuse a tag whose commit is not on main\n'
                  '        run: .github/scripts/check-ref-on-main.sh "$GITHUB_SHA"\n\n', "", 1)]),
    ("publish verify job with the ancestry call commented out", "ancestry-check",
     'publish.yml:verify: ancestry-check: no line runs check-ref-on-main.sh as its command', [
        (PUBLISH, PUBLISH_ANCESTRY_CALL, PUBLISH_ANCESTRY_CALL.replace('          "', '          # "', 1), 2)]),
    ("publish verify job with the ancestry call commented out without a space", "ancestry-check",
     'publish.yml:verify: ancestry-check: no line runs check-ref-on-main.sh as its command', [
        (PUBLISH, PUBLISH_ANCESTRY_CALL, PUBLISH_ANCESTRY_CALL.replace('          "', '          #"', 1), 2)]),
    ("release preflight that only echoes the ancestry script name", "ancestry-check",
     'release.yml:preflight: ancestry-check: no line runs check-ref-on-main.sh as its command', [
        (RELEASE, RELEASE_ANCESTRY_RUN, '        run: echo "skipped .github/scripts/check-ref-on-main.sh"\n', 1)]),
    ("release preflight that ignores the ancestry result", "ancestry-check",
     'release.yml:preflight: ancestry-check: no line runs check-ref-on-main.sh as its command', [
        (RELEASE, RELEASE_ANCESTRY_RUN, '        run: .github/scripts/check-ref-on-main.sh "$GITHUB_SHA" || true\n', 1)]),
    ("release preflight that assigns the ancestry script path", "ancestry-check",
     "release.yml:preflight: ancestry-check: no line runs check-ref-on-main.sh as its command", [
        (RELEASE, RELEASE_ANCESTRY_RUN, "        run: x=.github/scripts/check-ref-on-main.sh\n", 1)]),
    ("release preflight ancestry step that may be skipped", "ancestry-check",
     "release.yml:preflight step 4 (Refuse a tag whose commit is not on main): ancestry-check: "
     "the ancestry step sets if or continue-on-error", [
        (RELEASE, "      - name: Refuse a tag whose commit is not on main\n" + RELEASE_ANCESTRY_RUN,
         "      - name: Refuse a tag whose commit is not on main\n        if: false\n" + RELEASE_ANCESTRY_RUN, 1)]),
    ("publish verify ancestry step that may fail", "ancestry-check",
     "publish.yml:verify step 7 (Refuse a tag whose commit is not on main): ancestry-check: "
     "the ancestry step sets if or continue-on-error", [
        (PUBLISH, "      - name: Refuse a tag whose commit is not on main\n        working-directory: src\n",
         "      - name: Refuse a tag whose commit is not on main\n        continue-on-error: true\n"
         "        working-directory: src\n", 2)]),
    ("release preflight job that may fail", "ancestry-check",
     "release.yml:preflight: ancestry-check: the job sets continue-on-error", [
        (RELEASE, "  preflight:\n    name: preflight\n",
         "  preflight:\n    name: preflight\n    continue-on-error: true\n", 1)]),
    ("publish verify job without the ancestry check", "ancestry-check",
     'publish.yml:verify: ancestry-check: no line runs check-ref-on-main.sh as its command', [
        (PUBLISH, '"$GITHUB_WORKSPACE/wf/.github/scripts/check-ref-on-main.sh" "$(git rev-parse HEAD)"',
         'true', 2)]),
    ("publish job checks the dispatch commit", "ancestry-check",
     "publish.yml:publish step 7 (Refuse a tag whose commit is not on main): ancestry-check: passes the dispatch commit, not the tag's HEAD", [
        (PUBLISH, '"$GITHUB_WORKSPACE/wf/.github/scripts/check-ref-on-main.sh" "$(git rev-parse HEAD)"\n'
                  '\n      - name: Verify every workspace member carries the tag\'s version\n'
                  '        working-directory: src\n        env:\n          TAG_VERSION: ${{ steps.tag.outputs.version }}\n'
                  '        run: |\n          set -euo pipefail\n'
                  '          "$GITHUB_WORKSPACE/wf/.github/scripts/release-preflight-version-check.sh"\n\n'
                  '      # SHA256SUMS',
         '"$GITHUB_WORKSPACE/wf/.github/scripts/check-ref-on-main.sh" "$GITHUB_SHA"\n'
         '\n      - name: Verify every workspace member carries the tag\'s version\n'
         '        working-directory: src\n        env:\n          TAG_VERSION: ${{ steps.tag.outputs.version }}\n'
         '        run: |\n          set -euo pipefail\n'
         '          "$GITHUB_WORKSPACE/wf/.github/scripts/release-preflight-version-check.sh"\n\n'
         '      # SHA256SUMS', 1)]),
    ("workflow without top-level permissions", "workflow-permissions",
     'notarize-smoke.yml: workflow-permissions: no top-level permissions', [
        (SMOKE, "\npermissions:\n  contents: read\n\njobs:\n", "\njobs:\n", 1)]),
    ("publish workflow without its verify job", "missing-job",
     'publish.yml: missing-job: job verify not found', [
        (PUBLISH, "  verify:\n    name: verify (${{ inputs.tag }})\n", "  check:\n    name: verify (${{ inputs.tag }})\n", 1)]),
    ("smoke workflow that is not valid YAML", "unreadable",
     '.github/workflows/notarize-smoke.yml: unreadable: ', [
        (SMOKE, "name: Notarization smoke\n", "name: [Notarization smoke\n", 1)]),
    ("coverage pull_request trigger with a paths filter", "coverage-trigger", "paths filter", [
        (COVERAGE, "    branches: [main, next]\n" + COVERAGE_TYPES_LINE,
         "    branches: [main, next]\n    paths: ['**.rs']\n" + COVERAGE_TYPES_LINE, 1)]),
    ("coverage pull_request trigger with a paths-ignore filter", "coverage-trigger", "paths-ignore filter", [
        (COVERAGE, "    branches: [main, next]\n" + COVERAGE_TYPES_LINE,
         "    branches: [main, next]\n    paths-ignore: ['**.md']\n" + COVERAGE_TYPES_LINE, 1)]),
    ("coverage pull_request trigger without reopened", "coverage-trigger", "lack reopened", [
        (COVERAGE, COVERAGE_TYPES_LINE, "    types: [opened, synchronize]\n", 1)]),
    ("coverage edited added", "coverage-trigger", "extra or duplicate events", [
        (COVERAGE, COVERAGE_TYPES_LINE, "    types: [opened, synchronize, reopened, edited]\n", 1)]),
    ("coverage labeled added", "coverage-trigger", "extra or duplicate events", [
        (COVERAGE, COVERAGE_TYPES_LINE, "    types: [opened, synchronize, reopened, labeled]\n", 1)]),
    ("coverage duplicate event", "coverage-trigger", "extra or duplicate events", [
        (COVERAGE, COVERAGE_TYPES_LINE, "    types: [opened, synchronize, reopened, opened]\n", 1)]),
    ("coverage workflow without a pull_request trigger", "coverage-trigger", "trigger is absent", [
        (COVERAGE, "  pull_request:\n    branches: [main, next]\n" + COVERAGE_TYPES_LINE, "", 1)]),
    ("coverage job without the measure condition", "coverage-condition", "coverage-off job runs without the measure condition", [
        (COVERAGE, COVERAGE_OFF_HEADER, COVERAGE_OFF_HEADER.replace(COVERAGE_IF_LINE, ""), 1)]),
    ("coverage job that always measures", "coverage-condition", "coverage-off job runs without the measure condition", [
        (COVERAGE, COVERAGE_OFF_HEADER, COVERAGE_OFF_HEADER.replace(
            COVERAGE_IF_LINE, "    if: true || contains(github.event.pull_request.labels.*.name, 'coverage')\n"), 1)]),
    ("coverage job that never measures", "coverage-condition", "coverage-off job runs without the measure condition", [
        (COVERAGE, COVERAGE_OFF_HEADER, COVERAGE_OFF_HEADER.replace(
            COVERAGE_IF_LINE, "    if: false && contains(github.event.pull_request.labels.*.name, 'coverage')\n"), 1)]),
    ("coverage job without the non-pull-request bypass", "coverage-condition",
     "coverage-off job runs without the measure condition", [
        (COVERAGE, COVERAGE_OFF_HEADER, COVERAGE_OFF_HEADER.replace(
            COVERAGE_IF_LINE, "    if: contains(github.event.pull_request.labels.*.name, 'coverage')\n"), 1)]),
    ("coverage workflow without its coverage job", "coverage-condition", "job coverage not found", [
        (COVERAGE, COVERAGE_GATE_START, "  measure:\n    name: coverage\n", 1)]),
    ("coverage pull_request trigger in the list shorthand", "coverage-trigger",
     "coverage.yml: coverage-trigger: pull_request types are absent", [
        (COVERAGE, COVERAGE_ON_BLOCK, "on: [pull_request, workflow_dispatch]\n", 1)]),
    ("coverage pull_request trigger in the scalar shorthand", "coverage-trigger",
     "coverage.yml: coverage-trigger: pull_request types are absent", [
        (COVERAGE, COVERAGE_ON_BLOCK, "on: pull_request\n", 1)]),
    ("coverage pull_request trigger without a configuration", "coverage-trigger",
     "coverage.yml: coverage-trigger: pull_request types are absent", [
        (COVERAGE, "  pull_request:\n    branches: [main, next]\n" + COVERAGE_TYPES_LINE, "  pull_request:\n", 1)]),
    ("coverage pull_request types as a string", "coverage-trigger",
     "coverage.yml: coverage-trigger: pull_request types are absent", [
        (COVERAGE, COVERAGE_TYPES_LINE, "    types: labeled\n", 1)]),
    ("coverage pull_request types as an empty list", ("coverage-trigger",) * 3, (
        "coverage.yml: coverage-trigger: pull_request types lack opened",
        "coverage.yml: coverage-trigger: pull_request types lack synchronize",
        "coverage.yml: coverage-trigger: pull_request types lack reopened"), [
        (COVERAGE, COVERAGE_TYPES_LINE, "    types: []\n", 1)]),
    ("coverage pull_request types missing two events", ("coverage-trigger",) * 2, (
        "coverage.yml: coverage-trigger: pull_request types lack synchronize",
        "coverage.yml: coverage-trigger: pull_request types lack reopened"), [
        (COVERAGE, COVERAGE_TYPES_LINE, "    types: [opened]\n", 1)]),
    ("coverage paths filter and a missing condition", ("coverage-trigger", "coverage-condition"), (
        "coverage.yml: coverage-trigger: pull_request trigger has a paths filter",
        "coverage.yml: coverage-condition: coverage-off job runs without the measure condition"), [
        (COVERAGE, "    branches: [main, next]\n" + COVERAGE_TYPES_LINE,
         "    branches: [main, next]\n    paths: ['**.rs']\n" + COVERAGE_TYPES_LINE, 1),
        (COVERAGE, COVERAGE_OFF_HEADER, COVERAGE_OFF_HEADER.replace(COVERAGE_IF_LINE, ""), 1)]),
    ("coverage gate retains docs-only clause", "coverage-condition", "always() only", [
        (COVERAGE, COVERAGE_GATE_IF_LINE, COVERAGE_GATE_IF_LINE.rstrip()
         + f" && ({COVERAGE_LABEL}) && !({COVERAGE_DOCS_SKIP})\n", 1)]),
    ("coverage decision without label", "coverage-condition", "decision must use the measure expression", [
        (COVERAGE, "          MEASURE: " + COVERAGE_MEASURE,
         "          MEASURE: ${{ !(" + COVERAGE_DOCS_SKIP + ") }}", 1)]),
    ("coverage decision without push exclusion", "coverage-condition", "decision must use the measure expression", [
        (COVERAGE, "          MEASURE: " + COVERAGE_MEASURE,
         "          MEASURE: ${{ (" + COVERAGE_LABEL + ") }}", 1)]),
    ("coverage decision bare measure expression", "coverage-condition", "decision must use the measure expression", [
        (COVERAGE, "          MEASURE: " + COVERAGE_MEASURE,
         "          MEASURE: " + COVERAGE_MEASURE.removeprefix("${{ ").removesuffix(" }}"), 1)]),
    ("coverage decision without id", ("coverage-condition", "coverage-gate"),
     ("decision must use the measure expression", "decision must match the literal template"), [
        (COVERAGE, "        id: decision\n", "", 1)]),
    ("coverage gate without always()", ("coverage-condition", "ci-feature-jobs"),
     ("coverage gate must run on always() only", "coverage.yml: ci-feature-jobs: coverage can be bypassed"), [
        (COVERAGE, COVERAGE_GATE_HEADER, COVERAGE_GATE_HEADER.replace(
            COVERAGE_GATE_IF_LINE, "    if: success()\n"), 1)]),
    ("coverage gate without if", "coverage-condition", "coverage gate must run on always() only", [
        (COVERAGE, COVERAGE_GATE_HEADER, COVERAGE_GATE_HEADER.replace(COVERAGE_GATE_IF_LINE, ""), 1)]),
    ("coverage gate adds event condition", "coverage-condition", "coverage gate must run on always() only", [
        (COVERAGE, COVERAGE_GATE_HEADER, COVERAGE_GATE_HEADER.replace(
            COVERAGE_GATE_IF_LINE, "    if: always() && github.event.action == 'opened'\n"), 1)]),
    ("coverage gate skipped on cancellation", "coverage-condition", "coverage gate must run on always() only", [
        (COVERAGE, COVERAGE_GATE_HEADER, COVERAGE_GATE_HEADER.replace(
            COVERAGE_GATE_IF_LINE, "    if: ${{ !cancelled() }}\n"), 1)]),
    ("coverage-on without the measure condition", "coverage-condition", "coverage-on job runs without the measure condition", [
        (COVERAGE, COVERAGE_ON_HEADER, COVERAGE_ON_HEADER.replace(COVERAGE_IF_LINE, ""), 1)]),
    ("coverage gate renamed", "coverage-names", "coverage must have plain name coverage", [
        (COVERAGE, COVERAGE_GATE_START, "  coverage:\n    name: coverage (gate)\n", 1)]),
    ("coverage-off job removed", ("coverage-condition", "ci-feature-jobs"),
     ("job coverage-off not found", "coverage.yml: ci-feature-jobs: missing coverage-off"), [
        (COVERAGE, COVERAGE_OFF_JOB, "", 1)]),
    ("feature-off measurement also in coverage-on", "coverage-split",
     f"{COVERAGE_OFF_COMMAND} runs in coverage-on, expected coverage-off", [
        (COVERAGE, COVERAGE_ON_STEP_NAME, COVERAGE_OFF_STEP + COVERAGE_ON_STEP_NAME, 1)]),
    ("feature-off measurement repeated in its owner", "coverage-split",
     f"coverage-off has 2 occurrences of {COVERAGE_OFF_COMMAND}, expected one", [
        (COVERAGE, COVERAGE_OFF_STEP, COVERAGE_OFF_STEP * 2, 1)]),
    ("feature-on floor repeated in the gate", "coverage-split",
     "coverage has 2 occurrences of python3 .github/scripts/check-coverage.py cov-feature-on.json", [
        (COVERAGE, COVERAGE_ON_FLOORS_STEP, COVERAGE_ON_FLOORS_STEP * 2, 1)]),
    ("feature-on floor absent", "ci-feature-jobs",
     "coverage.yml: ci-feature-jobs: coverage does not run unconditionally: python3 .github/scripts/check-coverage.py "
     "cov-feature-on.json", [
        (COVERAGE, COVERAGE_ON_FLOORS_STEP, "", 1)]),
    ("feature-on measurement without mainnet-write", ("coverage-split", "ci-feature-jobs"),
     ("unexpected coverage command in coverage-on", "coverage.yml: ci-feature-jobs: coverage-on does not run unconditionally"), [
        (COVERAGE, "--features mainnet-write,test-helpers", "--features test-helpers", 1)]),
    ("third measurement job", "coverage-split", f"{COVERAGE_OFF_COMMAND} runs in coverage-extra, expected coverage-off", [
        (COVERAGE, COVERAGE_GATE_START, "  coverage-extra:\n    runs-on: ubuntu-24.04\n    steps:\n"
         "      - run: " + COVERAGE_OFF_COMMAND + "\n\n" + COVERAGE_GATE_START, 1)]),
    ("floors in a measurement job", "coverage-split",
     "check-coverage.py cov-feature-off.json --configuration feature-off runs in coverage-off, expected coverage",
     coverage_move(COVERAGE_OFF_FLOORS_STEP, COVERAGE_UPLOAD_OFF)),
    ("coverage-on without upload", "coverage-split", f"coverage-on does not upload {COVERAGE_ON_EXPORT} after its measurement", [
        (COVERAGE, COVERAGE_UPLOAD_ON, "", 1)]),
    ("upload that tolerates a missing export", "coverage-split",
     f"coverage-off does not upload {COVERAGE_OFF_EXPORT} after its measurement", [
        (COVERAGE, "          if-no-files-found: error\n", "          if-no-files-found: warn\n", 2)]),
    ("upload before measurement", "coverage-split", f"coverage-off does not upload {COVERAGE_OFF_EXPORT} after its measurement",
     coverage_move(COVERAGE_UPLOAD_OFF, COVERAGE_OFF_STEP)),
    ("conditional upload", "ci-feature-jobs", "coverage.yml: ci-feature-jobs: coverage-off step can be bypassed", [
        (COVERAGE, COVERAGE_UPLOAD_OFF, COVERAGE_UPLOAD_ACTION + "        if: success()\n"
         + COVERAGE_UPLOAD_OFF[len(COVERAGE_UPLOAD_ACTION):], 1)]),
    ("coverage gate needs one part", "coverage-gate",
     "coverage gate needs ['coverage-off'], expected changes, coverage-off and coverage-on", [
        (COVERAGE, COVERAGE_GATE_NEEDS, "    needs: [coverage-off]\n", 1)]),
    ("coverage gate result check reads one part twice", "coverage-gate", "coverage gate result check reads", [
        (COVERAGE, COVERAGE_RESULT_ENV_LINES,
         COVERAGE_RESULT_ENV_LINES.replace("needs.coverage-on.result", "needs.coverage-off.result"), 1)]),
    ("coverage gate result keys unquoted", "coverage-gate", ", False:", [
        (COVERAGE, COVERAGE_RESULT_ENV_LINES, COVERAGE_RESULT_ENV_LINES.replace('"', ""), 1)]),
    ("coverage gate result check removed", "ci-feature-jobs",
     'coverage.yml: ci-feature-jobs: coverage does not run unconditionally: test "$ON" = success', [
        (COVERAGE, COVERAGE_RESULT_ON_CHECK, "", 1)]),
    ("coverage gate result check continues on error", "ci-feature-jobs", "coverage.yml: ci-feature-jobs: coverage step can be bypassed", [
        (COVERAGE, COVERAGE_RESULT_STEP, COVERAGE_RESULT_STEP + "        continue-on-error: true\n", 1)]),
    ("coverage gate result step under a condition", ("coverage-gate", "coverage-gate", "ci-feature-jobs"), (
        "coverage gate does not check the results first", "coverage gate step 1 runs under success()",
        "coverage.yml: ci-feature-jobs: coverage step can be bypassed"), [
        (COVERAGE, COVERAGE_RESULT_STEP, COVERAGE_RESULT_STEP + "        if: success()\n", 1)]),
    ("coverage gate without the early cancel rejection", "coverage-gate",
     "coverage gate does not reject a cancelled run after its result check", [
        (COVERAGE, COVERAGE_CANCEL_EARLY, "", 1)]),
    ("coverage gate without the final cancel rejection", "coverage-gate",
     "coverage gate does not reject a cancelled run after its floors", [
        (COVERAGE, COVERAGE_CANCEL_FINAL, "", 1)]),
    ("coverage gate cancel rejection that never fails", ("coverage-gate", "ci-feature-jobs"), (
        "coverage gate does not reject a cancelled run after its floors",
        "coverage.yml: ci-feature-jobs: coverage step can be bypassed"), [
        (COVERAGE, COVERAGE_CANCEL_FINAL, COVERAGE_CANCEL_FINAL.replace("run: exit 1", 'run: "true"'), 1)]),
    ("coverage gate cancel rejection on failure", ("coverage-gate", "ci-feature-jobs"), (
        "coverage gate does not reject a cancelled run after its floors",
        "coverage.yml: ci-feature-jobs: coverage step can be bypassed"), [
        (COVERAGE, COVERAGE_CANCEL_FINAL, COVERAGE_CANCEL_FINAL.replace("if: cancelled()", "if: failure()"), 1)]),
    ("coverage gate cancel rejection that continues on error", ("coverage-gate", "ci-feature-jobs"), (
        "coverage gate does not reject a cancelled run after its result check",
        "coverage.yml: ci-feature-jobs: coverage step can be bypassed"), [
        (COVERAGE, COVERAGE_CANCEL_EARLY, COVERAGE_CANCEL_EARLY + "        continue-on-error: true\n", 1)]),
    ("coverage gate cancel rejection before the floors only", "coverage-gate",
     "coverage gate does not reject a cancelled run after its floors",
     coverage_move(COVERAGE_CANCEL_FINAL, COVERAGE_OFF_FLOORS_STEP)),
    ("coverage gate downloads from another run", "coverage-gate", f"coverage gate downloads {COVERAGE_OFF_EXPORT} with run-id", [
        (COVERAGE, COVERAGE_DOWNLOAD_OFF, COVERAGE_DOWNLOAD_OFF + "          run-id: 1\n", 1)]),
    ("coverage gate missing a download", "coverage-gate", f"coverage gate does not download {COVERAGE_ON_EXPORT}", [
        (COVERAGE, COVERAGE_DOWNLOAD_ON, "", 1)]),
    ("coverage gate floors before download", "coverage-gate",
     f"coverage gate checks floors before downloading {COVERAGE_OFF_EXPORT}",
     coverage_move(COVERAGE_OFF_FLOORS_STEP, COVERAGE_DOWNLOAD_OFF)),
    ("coverage upload with a fixed name", "coverage-attempt",
     "coverage-off step 8 transfers cov-feature-off, not a report of this run attempt", [
        (COVERAGE, COVERAGE_UPLOAD_OFF, COVERAGE_UPLOAD_OFF.replace(COVERAGE_OFF_NAME, "          name: cov-feature-off\n"), 1)]),
    ("coverage download with a fixed name", "coverage-attempt",
     "coverage step 4 transfers cov-feature-off, not a report of this run attempt", [
        (COVERAGE, COVERAGE_DOWNLOAD_OFF, COVERAGE_DOWNLOAD_OFF.replace(COVERAGE_OFF_NAME, "          name: cov-feature-off\n"), 1)]),
    ("coverage download of another attempt", "coverage-attempt",
     "coverage step 4 transfers cov-feature-off-1, not a report of this run attempt", [
        (COVERAGE, COVERAGE_DOWNLOAD_OFF, COVERAGE_DOWNLOAD_OFF.replace(COVERAGE_OFF_NAME, "          name: cov-feature-off-1\n"), 1)]),
    ("coverage download by pattern", "coverage-attempt", "coverage step 4 downloads with pattern", [
        (COVERAGE, COVERAGE_DOWNLOAD_OFF, COVERAGE_DOWNLOAD_ACTION + COVERAGE_MEASURED_LINE + "        with:\n          pattern: cov-feature-off-*\n", 1)]),
    ("coverage download that merges reports", "coverage-attempt", "coverage step 4 downloads with merge-multiple", [
        (COVERAGE, COVERAGE_DOWNLOAD_OFF, COVERAGE_DOWNLOAD_OFF + "          merge-multiple: true\n", 1)]),
    ("coverage without push trigger", "coverage-seed", "coverage.yml: coverage-seed: push trigger is absent", [
        (COVERAGE, COVERAGE_PUSH_BLOCK, "", 1)]),
    ("coverage push on main only", "coverage-seed", "push branches lack next", [
        (COVERAGE, COVERAGE_PUSH_BLOCK, "  push:\n    branches: [main]\n", 1)]),
    ("coverage push on next only", "coverage-seed", "push branches lack main", [
        (COVERAGE, COVERAGE_PUSH_BLOCK, "  push:\n    branches: [next]\n", 1)]),
    ("coverage push with paths filter", "coverage-seed", "push trigger has a paths filter", [
        (COVERAGE, COVERAGE_PUSH_BLOCK, COVERAGE_PUSH_BLOCK + "    paths: ['**.rs']\n", 1)]),
    ("coverage push with paths-ignore filter", "coverage-seed", "push trigger has a paths filter", [
        (COVERAGE, COVERAGE_PUSH_BLOCK, COVERAGE_PUSH_BLOCK + "    paths-ignore: ['**.md']\n", 1)]),
    ("coverage push runs cancel each other", "coverage-seed", "later runs cancel a running push", [
        (COVERAGE, COVERAGE_CANCEL_LINE, "  cancel-in-progress: true\n", 1)]),
    ("ci clippy cache saves on pull requests", "cache-save-if", "ci.yml:clippy step 4: cache-save-if: rust-cache saves on pull request runs", [
        (CI, CI_CLIPPY_CACHE, CI_CLIPPY_CACHE.replace("        with:\n" + CACHE_SAVE_LINE, ""), 1)]),
    ("ci cache save-if always true", "cache-save-if", "ci.yml:feature-on-test step", [
        (CI, CI_FEATURE_ON_TEST_CACHE, CI_FEATURE_ON_TEST_CACHE.replace(CACHE_SAVE_LINE.replace(" == 'push' ", " == 'push' && matrix.shard == 1 "), "          save-if: true\n"), 1)]),
    ("coverage-on cache saves on pull requests", "cache-save-if", "coverage.yml:coverage-on step", [
        (COVERAGE, COVERAGE_ON_CACHE, COVERAGE_ON_CACHE.replace(CACHE_SAVE_LINE, ""), 1)]),
    ("rust-cache in another pull request workflow", "cache-save-if", "install-surface.yml:install-surface step", [
        (".github/workflows/install-surface.yml", "      - name: Check the install surface\n",
         UNGUARDED_CACHE_STEP + "      - name: Check the install surface\n", 1)]),
    ("rust-cache in pull_request_target workflow", "cache-save-if", "welcome.yml:welcome step 1", [
        (WELCOME, "      - name: Welcome the first contribution\n",
         UNGUARDED_CACHE_STEP + "      - name: Welcome the first contribution\n", 1)]),
    ("rust-cache in a yaml workflow", "cache-save-if", "cache-fixture.yaml:fixture step 1", [
        (CACHE_FIXTURE, CACHE_FIXTURE_TEXT, cache_fixture("[pull_request]"), 1)]),
    ("rust-cache in scalar pull_request workflow", "cache-save-if", "cache-fixture.yaml:fixture step 1", [
        (CACHE_FIXTURE, CACHE_FIXTURE_TEXT, cache_fixture("pull_request"), 1)]),
    ("rust-cache in upper case", "cache-save-if", "ci.yml:clippy step", [
        (CI, RUST_CACHE_PLAIN, RUST_CACHE_USES.replace("Swatinem/rust-cache", "swatinem/RUST-CACHE"), 2)]),
    ("rehearsal job with id-token: write", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: the job holds id-token: write", [
        (REHEARSAL, REHEARSAL_JOB_PERMISSIONS,
         "    permissions:\n      contents: read\n      id-token: write\n    strategy:\n", 2)]),
    ("rehearsal job in an environment", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: the job declares an environment", [
        (REHEARSAL, REHEARSAL_TIMEOUT, REHEARSAL_TIMEOUT + "    environment: rehearsal\n", 1)]),
    ("rehearsal job that inherits secrets", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: the job passes secrets", [
        (REHEARSAL, REHEARSAL_TIMEOUT, REHEARSAL_TIMEOUT + "    secrets: inherit\n", 1)]),
    ("rehearsal job with actions: write", "rehearsal-credentials",
     f"release-rehearsal.yml:build: rehearsal-credentials: effective permissions are actions: write, "
     f"contents: read, {REHEARSAL_EXACT}", [
        (REHEARSAL, REHEARSAL_JOB_PERMISSIONS,
         "    permissions:\n      actions: write\n      contents: read\n    strategy:\n", 2)]),
    ("rehearsal workflow with contents: write", "rehearsal-credentials",
     f"release-rehearsal.yml: rehearsal-credentials: workflow permissions are contents: write, {REHEARSAL_EXACT}", [
        (REHEARSAL, "\npermissions:\n  contents: read\n\nenv:\n", "\npermissions:\n  contents: write\n\nenv:\n", 1)]),
    ("rehearsal run line that reads a secret", ("rehearsal-credentials", "rehearsal-credentials"), (
        "release-rehearsal.yml:build: rehearsal-credentials: the job references secrets.",
        "release-rehearsal.yml:build: rehearsal-credentials: an expression reads secrets: secrets.RELEASE_KEY"), [
        in_rehearsal_version_step('          echo "${{ secrets.RELEASE_KEY }}"\n')]),
    ("rehearsal workflow env that reads a secret", "rehearsal-credentials",
     "release-rehearsal.yml: rehearsal-credentials: an expression reads secrets: secrets.RELEASE_KEY", [
        (REHEARSAL, REHEARSAL_ENV, REHEARSAL_ENV + "  RELEASE_KEY: ${{ secrets.RELEASE_KEY }}\n", 1)]),
    ("rehearsal workflow env key that reads a secret", "rehearsal-credentials",
     "release-rehearsal.yml: rehearsal-credentials: an expression reads secrets: secrets.RELEASE_KEY", [
        (REHEARSAL, REHEARSAL_ENV, REHEARSAL_ENV + "  '${{ secrets.RELEASE_KEY }}': value\n", 1)], 1),
    ("rehearsal step env key that reads the workflow token", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: an expression reads the workflow token: github.token", [
        (REHEARSAL, REHEARSAL_SODIUM_STEP,
         REHEARSAL_SODIUM_STEP + "        env:\n          '${{ github.token }}': value\n", 1)], 1),
    ("rehearsal top-level key that reads the workflow token", "rehearsal-credentials",
     "release-rehearsal.yml: rehearsal-credentials: an expression reads the workflow token: github.token", [
        (REHEARSAL, "\nenv:\n", "\n'${{ github.token }}': value\n\nenv:\n", 1)], 1),
    ("rehearsal job ID that reads the workflow token", "rehearsal-credentials",
     "release-rehearsal.yml:${{ github.token }}: rehearsal-credentials: "
     "an expression reads the workflow token: github.token", [
        (REHEARSAL, "  build:\n", "  '${{ github.token }}':\n", 1)], 6),
    ("rehearsal step env key with an unterminated expression", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: unterminated expression", [
        (REHEARSAL, REHEARSAL_SODIUM_STEP,
         REHEARSAL_SODIUM_STEP + '        env:\n          "${{ format(\'x\')": v\n', 1)], 1),
    ("rehearsal step env with a set node", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: unsupported workflow node type: set", [
        (REHEARSAL, REHEARSAL_SODIUM_STEP,
         REHEARSAL_SODIUM_STEP + "        env: !!set\n          ? UNEXPECTED\n", 1)], 1),
    ("rehearsal workflow env that reads a secret in another case", "rehearsal-credentials",
     "release-rehearsal.yml: rehearsal-credentials: an expression reads secrets: Secrets.RELEASE_KEY", [
        (REHEARSAL, REHEARSAL_ENV, REHEARSAL_ENV + "  RELEASE_KEY: ${{ Secrets.RELEASE_KEY }}\n", 1)]),
    ("rehearsal workflow secret after quoted closing braces", "rehearsal-credentials",
     "release-rehearsal.yml: rehearsal-credentials: an expression reads secrets: format('}}{0}', secrets.RELEASE_KEY)", [
        (REHEARSAL, REHEARSAL_ENV,
         REHEARSAL_ENV + "  RELEASE_KEY: ${{ format('}}{0}', secrets.RELEASE_KEY) }}\n", 1)]),
    ("rehearsal run line that reads the workflow token", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: an expression reads the workflow token: github.token", [
        in_rehearsal_version_step('          echo "${{ github.token }}"\n')]),
    ("rehearsal run token after quoted closing braces", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: an expression reads the workflow token: "
     "format('}}{0}', github.token)", [
        in_rehearsal_version_step("          echo \"${{ format('}}{0}', github.token) }}\"\n")]),
    ("rehearsal run token after double-quoted closing braces", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: double quote outside a single-quoted string in expression", [
        in_rehearsal_version_step('          echo \'${{ format("}}{0}", github.token) }}\'\n')], 1),
    ("rehearsal double-quoted apostrophes around the workflow token", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: double quote outside a single-quoted string in expression", [
        in_rehearsal_version_step('          echo ${{ format("\'", github.token, "\'") }}\n')], 1),
    ("rehearsal run token in a second expression", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: an expression reads the workflow token: "
     "format('it''s }}{0}', github.token)", [
        in_rehearsal_version_step("          echo \"${{ 'x' }} ${{ format('it''s }}{0}', github.token) }}\"\n")]),
    ("rehearsal run with an unterminated expression", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: unterminated expression", [
        in_rehearsal_version_step("          echo ${{ format('{0}', 'x')\n")]),
    ("rehearsal workflow env with an unterminated string", "rehearsal-credentials",
     "release-rehearsal.yml: rehearsal-credentials: unterminated string in expression", [
        (REHEARSAL, REHEARSAL_ENV, REHEARSAL_ENV + "  LITERAL: ${{ 'x }}\n", 1)], 1),
    ("rehearsal run with an unterminated double-quoted string", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: double quote outside a single-quoted string in expression", [
        in_rehearsal_version_step('          echo ${{ "x }}\n')], 1),
    ("rehearsal bare condition with an unterminated string", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: unterminated string in expression", [
        (REHEARSAL, REHEARSAL_SODIUM_STEP,
         "      - name: Prefetch libsodium dist (Windows)\n        if: github.ref == 'x\n", 1)]),
    ("rehearsal wrapped condition with an unterminated expression", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: unterminated expression", [
        (REHEARSAL, REHEARSAL_SODIUM_STEP,
         "      - name: Prefetch libsodium dist (Windows)\n        if: ${{ github.ref == 'x'\n", 1)]),
    ("rehearsal run line that reads the workflow token in another case", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: an expression reads the workflow token: GitHub.Token", [
        in_rehearsal_version_step('          echo "${{ GitHub.Token }}"\n')]),
    ("rehearsal step condition that reads the workflow token", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: an expression reads the workflow token: github.token != ''", [
        (REHEARSAL, REHEARSAL_SODIUM_STEP,
         "      - name: Prefetch libsodium dist (Windows)\n        if: github.token != ''\n", 1)]),
    ("rehearsal run line that serializes the github context", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: an expression reads the github context other than by a "
     "named property: toJSON(github)", [
        in_rehearsal_version_step('          echo "${{ toJSON(github) }}"\n')]),
    ("shared build call removed", "release-shared-scripts", "expected one call", [
        (RELEASE, 'run: bash .github/scripts/release/build.sh "$TARGET"', 'run: echo skipped', 1)]),
    ("rehearsal shared build call removed", "release-shared-scripts",
     "release-rehearsal.yml: release-shared-scripts: expected one call", [
        (REHEARSAL, 'run: bash .github/scripts/release/build.sh "$TARGET"', 'run: echo skipped', 1)]),
    ("guard moved before Perl", "release-guard-order", "build must immediately follow", [
        (RELEASE, RELEASE_BUILD_STEP, "", 1),
        (RELEASE, RELEASE_PERL_STEP, RELEASE_BUILD_STEP + RELEASE_PERL_STEP, 1)], 1),
    ("build guard removed", "release-shared-scripts", "environment guard is not", [
        (BUILD_SCRIPT, ' --env-guard', ' --help', 1)]),
    ("build without the alias comparison", "release-shared-scripts",
     "build.sh: release-shared-scripts: build operations differ from BUILD_BODY", [
        (BUILD_SCRIPT, BUILD_CMP, "", 1)]),
    ("build that ignores the alias comparison", "release-shared-scripts",
     "build.sh: release-shared-scripts: build operations differ from BUILD_BODY", [
        (BUILD_SCRIPT, BUILD_CMP, BUILD_CMP.strip() + " || true\n", 1)]),
    ("build with a plain copy and mv", "release-shared-scripts",
     "build.sh: release-shared-scripts: build operations differ from BUILD_BODY", [
        (BUILD_SCRIPT, BUILD_COPY, BUILD_PLAIN_MV, 1)]),
    ("copy helper with a plain mv", "release-shared-scripts",
     "copy-alias.sh: release-shared-scripts: copy operations differ from COPY_HELPER_BODY", [
        (COPY_HELPER, COPY_RENAME, '    ! mv -f -- "$temp" "$destination"; then\n', 1)]),
    ("copy helper without the destination check", "release-shared-scripts",
     "copy-alias.sh: release-shared-scripts: copy operations differ from COPY_HELPER_BODY", [
        (COPY_HELPER, "  " + COPY_CHECK, "  if false; then\n", 1)]),
    ("smoke build without the alias comparison", "release-shared-scripts",
     "notarize-smoke.yml: release-shared-scripts: smoke build operations differ from SMOKE_BUILD", [
        (SMOKE, SMOKE_CMP, "", 1)]),
    ("smoke build with a plain copy and mv", "release-shared-scripts",
     "notarize-smoke.yml: release-shared-scripts: smoke build operations differ from SMOKE_BUILD", [
        (SMOKE, SMOKE_COPY, SMOKE_PLAIN_MV, 1)]),
    ("signing of the alias name too", "signing-order",
     "sign-notarize.sh: signing-order: a codesign call signs another file than stellar-agent", [
        (SIGN_SCRIPT, SIGN_DERIVE, SIGN_DERIVE + SIGN_CANONICAL.replace(
            '"$BINARY_DIR/stellar-agent"', '"$BINARY_DIR/stellar-agent-mcp"'), 1)]),
    ("derivation before signing", "signing-order",
     "sign-notarize.sh: signing-order: signing, derivation and packing differ from SIGN_BLOCK", [
        (SIGN_SCRIPT, SIGN_DERIVE, "", 1),
        (SIGN_SCRIPT, SIGN_CANONICAL, SIGN_DERIVE + SIGN_CANONICAL, 1)]),
    ("derivation skipped by a condition", "signing-order",
     "sign-notarize.sh: signing-order: signing, derivation and packing differ from SIGN_BLOCK", [
        (SIGN_SCRIPT, SIGN_DERIVE, "if false; then\n  " + SIGN_DERIVE + "fi\n", 1)]),
    ("final verification of both names removed", "signing-order",
     "sign-notarize.sh: signing-order: the script does not end by verifying both signatures", [
        (SIGN_SCRIPT, SIGN_VERIFY_BOTH, "", 1)]),
    ("derivation with a plain mv", "signing-order",
     "derive-alias.sh: signing-order: derivation operations differ from DERIVE_BODY", [
        (DERIVE_SCRIPT, DERIVE_RENAME, '/bin/mv -f "$temp" "$alias"\n', 1)]),
    ("derivation without the alias check", "signing-order",
     "derive-alias.sh: signing-order: derivation operations differ from DERIVE_BODY", [
        (DERIVE_SCRIPT, DERIVE_CHECK, "if false; then\n", 1)]),
    ("packaged dependency removed", "release-packaged-gate", "hashes must need verify-packaged", [
        (RELEASE, 'needs: [preflight, vendored-wasm, build, sign-macos, verify-packaged]',
         'needs: [preflight, vendored-wasm, build, sign-macos]', 1)]),
    ("verify-packaged without sign-macos", "release-packaged-gate", "verify-packaged must need sign-macos", [
        (RELEASE, "    needs: [preflight, build, sign-macos]\n    runs-on: ${{ matrix.os }}\n",
         "    needs: [preflight, build]\n    runs-on: ${{ matrix.os }}\n", 1)]),
    ("archive check behind a comment", "release-packaged-gate",
     "release.yml: release-packaged-gate: verify-packaged does not run the archive check unconditionally", [
        (RELEASE, ARCHIVE_RUN, commented(ARCHIVE_RUN), 1)]),
    ("archive check through a variable", "release-packaged-gate",
     "verify-packaged does not run the archive check unconditionally", [
        (RELEASE, ARCHIVE_RUN, ARCHIVE_RUN.replace(".github/scripts/release/verify-archive.sh", '"$ARCHIVE_CHECK"'), 1)]),
    ("archive check replaced by a YAML boolean", "release-packaged-gate",
     "verify-packaged does not run the archive check unconditionally", [
        (RELEASE, ARCHIVE_RUN, "run: true", 1)]),
    ("archive check inside a condition", "release-packaged-gate",
     "verify-packaged does not run the archive check unconditionally", [
        (RELEASE, ARCHIVE_RUN, 'run: |\n          if [ -n "$TARGET" ]; then\n            '
         + ARCHIVE_RUN[len("run: "):] + "\n          fi", 1)]),
    ("archive check after an exit", "release-packaged-gate",
     "verify-packaged does not run the archive check unconditionally", [
        (RELEASE, ARCHIVE_RUN, "run: |\n          exit 0\n          " + ARCHIVE_RUN[len("run: "):], 1)]),
    ("archive check after errexit is off", "release-packaged-gate",
     "verify-packaged does not run the archive check unconditionally", [
        (RELEASE, ARCHIVE_RUN, "run: |\n          set +e\n          " + ARCHIVE_RUN[len("run: "):], 1)]),
    ("archive check under a shell without errexit", "release-packaged-gate",
     "verify-packaged does not run the archive check unconditionally", [
        (RELEASE, "      - name: Verify packaged binaries\n        shell: bash\n",
         "      - name: Verify packaged binaries\n        shell: bash {0}\n", 1)]),
    ("archive check ignored with echo", "release-packaged-gate",
     "verify-packaged does not run the archive check unconditionally", [
        (RELEASE, ARCHIVE_RUN, archive_block(" || echo skipped"), 1)]),
    ("archive check ignored with a colon", "release-check-unconditional", "verify-packaged suppresses failures", [
        (RELEASE, ARCHIVE_RUN, archive_block(" || :"), 1)]),
    ("archive check ignored with true", "release-check-unconditional", "verify-packaged suppresses failures", [
        (RELEASE, ARCHIVE_RUN, archive_block(" || true"), 1)]),
    ("archive check ignored with exit 0", "release-check-unconditional", "verify-packaged suppresses failures", [
        (RELEASE, ARCHIVE_RUN, archive_block(" || exit 0"), 1)]),
    ("provenance dependency removed", "release-provenance-gate", "publish must need verify-provenance", [
        (RELEASE, 'needs: [preflight, vendored-wasm, build, sign-macos, sign, hashes, provenance, verify-provenance]',
         'needs: [preflight, vendored-wasm, build, sign-macos, sign, hashes, provenance]', 1)]),
    ("verify-provenance without provenance", "release-provenance-gate", "verify-provenance must need provenance", [
        (RELEASE, "needs: [preflight, provenance, hashes, sign]", "needs: [preflight, hashes, sign]", 1)]),
    ("verify-provenance without sign", "release-provenance-gate", "verify-provenance must need sign", [
        (RELEASE, "needs: [preflight, provenance, hashes, sign]", "needs: [preflight, provenance, hashes]", 1)]),
    ("signature check removed", "release-provenance-gate", "verify-provenance does not run unconditionally: bash .github/scripts/release/verify-signatures.sh", [
        (RELEASE, "run: bash .github/scripts/release/verify-signatures.sh", "run: echo .github/scripts/release/verify-signatures.sh", 1)]),
    ("provenance check behind a comment", "release-provenance-gate",
     "verify-provenance does not run unconditionally: python3 .github/scripts/check-provenance.py", [
        (RELEASE, PROVENANCE_RUN, commented(PROVENANCE_RUN), 1)]),
    ("provenance check with swapped arguments", "release-provenance-gate",
     "verify-provenance does not run unconditionally: python3 .github/scripts/check-provenance.py", [
        (RELEASE, '"$GITHUB_SHA" "$GITHUB_REPOSITORY"', '"$GITHUB_REPOSITORY" "$GITHUB_SHA"', 1)]),
    ("source discipline behind a comment", "release-provenance-gate",
     "verify-provenance does not run unconditionally: \"$RUNNER_TEMP/feature-check/bin/python\" "
     ".github/scripts/check-feature-discipline.py", [
        (RELEASE, SOURCE_DISCIPLINE_LINE, "          # " + SOURCE_DISCIPLINE_LINE.lstrip(), 1)]),
    ("dry check removed", "publish-dry-gate", "packaged marker check must immediately follow", [
        (PUBLISH, 'check-packaged-markers.sh', 'unused-markers.sh', 1)]),
    ("dry check behind a comment", "publish-dry-gate", "packaged marker check must immediately follow", [
        (PUBLISH, PACKAGE_CHECK_RUN, commented(PACKAGE_CHECK_RUN), 1)]),
    ("package verification without the timestamp", "publish-dry-gate", "package verification lacks the freshness timestamp", [
        (PUBLISH, "          touch target/package-verification-start\n", "", 1)]),
    ("install check without publish", "publish-install-gate", "verify-install must need publish", [
        (PUBLISH, "    needs: publish\n    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n", 1)]),
    ("install check removed", "publish-install-gate", "verify-install does not run the install check unconditionally", [
        (PUBLISH, INSTALL_RUN, commented(INSTALL_RUN), 1)]),
    ("install check from the tag's tree", "publish-install-gate",
     "verify-install does not run the install check unconditionally", [
        (PUBLISH, INSTALL_RUN, INSTALL_RUN.replace('"$GITHUB_WORKSPACE/wf/', "src/").replace('verify-install.sh"', "verify-install.sh"), 1)]),
    ("R2 continue on error", "release-check-unconditional", "verify-packaged can be bypassed", [
        (RELEASE, '    name: verify-packaged ${{ matrix.target }}',
         '    continue-on-error: true\n    name: verify-packaged ${{ matrix.target }}', 1)]),
    ("conditional hashes", "release-check-unconditional", "hashes can be bypassed", [
        (RELEASE, '    name: hashes\n', '    name: hashes\n    if: false\n', 1)]),
    ("conditional verify-provenance step", "release-check-unconditional", "verify-provenance step can be bypassed", [
        (RELEASE, "      - name: Fetch the locked graph\n", "      - name: Fetch the locked graph\n        if: false\n", 1)]),
    ("verify step that continues on error", "release-check-unconditional", "verify step can be bypassed", [
        (PUBLISH, "      - name: Verify packaged feature state\n",
         "      - name: Verify packaged feature state\n        continue-on-error: true\n", 1)]),
    ("verification job with contents: write", "verification-credentials",
     "release.yml:verify-provenance: verification-credentials: must be uncredentialed with contents: read", [
        (RELEASE, "    timeout-minutes: 20\n    permissions:\n      contents: read\n",
         "    timeout-minutes: 20\n    permissions:\n      contents: write\n", 1)]),
    ("workflow token on verify-packaged", "verification-credentials",
     "release.yml:verify-packaged: verification-credentials: an expression reads the workflow token: github.token", [
        (RELEASE, ARCHIVE_ENV, ARCHIVE_ENV.replace("        run:", "          GH_TOKEN: ${{ github.token }}\n        run:"), 1)]),
    ("token variable on verify-install", "verification-credentials",
     "publish.yml:verify-install: verification-credentials: sets GITHUB_TOKEN", [
        (PUBLISH, "      - name: Verify registry installs\n        env:\n",
         "      - name: Verify registry installs\n        env:\n          GITHUB_TOKEN: unused\n", 1)]),
    ("verify-packaged matrix without a target", "release-verify-matrix",
     "release.yml: release-verify-matrix: verify-packaged does not run each release target on its runner", [
        (RELEASE, "          - target: aarch64-unknown-linux-gnu\n            os: ubuntu-24.04-arm\n", "", 1)]),
    ("rehearsal verify-packaged on another runner", "release-verify-matrix",
     "release-rehearsal.yml: release-verify-matrix: verify-packaged does not run each release target on its runner", [
        (REHEARSAL, "            os: ubuntu-24.04-arm\n", "            os: ubuntu-24.04\n", 1)]),
    ("rehearsal Rosetta step moved", "release-verify-matrix",
     "release-rehearsal.yml: release-verify-matrix: the first verify-packaged step is not the Rosetta check", [
        (REHEARSAL, ROSETTA_STEP, "", 1),
        (REHEARSAL, REHEARSAL_ARCHIVE_DOWNLOAD, REHEARSAL_ARCHIVE_DOWNLOAD + ROSETTA_STEP, 1)], 1),
    ("rehearsal toolchain differs", "release-toolchain", "RELEASE_TOOLCHAIN differs from publish.yml", [
        (REHEARSAL, '  RELEASE_TOOLCHAIN: "1.100.0"\n', '  RELEASE_TOOLCHAIN: "1.98.0"\n', 1)]),
    ("rehearsal crates on stable", "release-toolchain", "verify-crates does not package with RELEASE_TOOLCHAIN", [
        (REHEARSAL, "          toolchain: ${{ env.RELEASE_TOOLCHAIN }}\n      # RUSTUP_TOOLCHAIN", "          toolchain: stable\n      # RUSTUP_TOOLCHAIN", 1)]),
    ("rehearsal crates without the toolchain pin", "release-toolchain", "it does not pin RUSTUP_TOOLCHAIN", [
        (REHEARSAL, REHEARSAL_PIN_STEP, "", 1)], 1),
    ("release toolchain pinned after the build", "release-toolchain",
     "build does not compile with RELEASE_TOOLCHAIN: RUSTUP_TOOLCHAIN is not pinned between the install and the build", [
        (RELEASE, BUILD_PIN_STEP, "", 1),
        (RELEASE, RELEASE_BUILD_STEP, RELEASE_BUILD_STEP + BUILD_PIN_STEP, 1)], 1),
    ("rehearsal toolchain pinned after packaging", "release-toolchain",
     "RUSTUP_TOOLCHAIN is not pinned between the install and the packaging", [
        (REHEARSAL, REHEARSAL_PIN_STEP, "", 1),
        (REHEARSAL, REHEARSAL_MARKER_RUN, REHEARSAL_MARKER_RUN + REHEARSAL_PIN_STEP, 1)], 1),
    ("archive check inside a heredoc", "release-packaged-gate",
     "release.yml:verify-packaged step 4: release-packaged-gate: unmodelled shell syntax around "
     + ARCHIVE_RUN[len("run: "):] + ": logical line 1: cat <<'EOF'", [
        (RELEASE, ARCHIVE_RUN, "run: |\n          cat <<'EOF'\n          " + ARCHIVE_RUN[len("run: "):]
         + "\n          EOF", 1)]),
    ("archive check after an indented heredoc delimiter", "release-packaged-gate",
     "release.yml:verify-packaged step 4: release-packaged-gate: unmodelled shell syntax around "
     + ARCHIVE_RUN[len("run: "):] + ": logical line 1: cat <<'EOF'", [
        (RELEASE, ARCHIVE_RUN, "run: |\n          cat <<'EOF'\n            EOF\n          "
         + ARCHIVE_RUN[len("run: "):] + "\n          EOF", 1)]),
    ("archive check after a partly quoted heredoc delimiter", "release-packaged-gate",
     "release.yml:verify-packaged step 4: release-packaged-gate: unmodelled shell syntax around "
     + ARCHIVE_RUN[len("run: "):] + ": logical line 1: cat <<E\"OF\"", [
        (RELEASE, ARCHIVE_RUN, "run: |\n          cat <<E\"OF\"\n          E\n          "
         + ARCHIVE_RUN[len("run: "):] + "\n          EOF", 1)]),
    ("archive check in a suppressed subshell", "release-packaged-gate",
     "release.yml:verify-packaged step 4: release-packaged-gate: unmodelled shell syntax around", [
        (RELEASE, ARCHIVE_RUN, "run: |\n          (\n            " + ARCHIVE_RUN[len("run: "):]
         + "\n          ) || echo ignored", 1)]),
    ("archive check as the second heredoc body", "release-packaged-gate",
     "release.yml:verify-packaged step 4: release-packaged-gate: unmodelled shell syntax around "
     + ARCHIVE_RUN[len("run: "):] + ": logical line 1: cat <<'A' <<'B'", [
        (RELEASE, ARCHIVE_RUN, "run: |\n          cat <<'A' <<'B'\n          first\n          A\n          "
         + ARCHIVE_RUN[len("run: "):] + "\n          B", 1)]),
    ("archive check continued in a suppressed subshell", "release-packaged-gate",
     "release.yml:verify-packaged step 4: release-packaged-gate: unmodelled shell syntax around "
     + ARCHIVE_RUN[len("run: "):] + ": logical line 2: ( " + ARCHIVE_RUN[len("run: "):] + " ) || echo ignored", [
        (RELEASE, ARCHIVE_RUN, archive_block(" ) || echo ignored").replace(
            "run: |\n          ", "run: |\n          echo checking \\\n            archives\n          ( ")
         .replace(" archives \"", " archives \\\n            \""), 1)]),
    ("archive check after a conditional line", "release-packaged-gate",
     "release.yml:verify-packaged step 4: release-packaged-gate: unmodelled shell syntax around "
     + ARCHIVE_RUN[len("run: "):] + ": logical line 1: false &&", [
        (RELEASE, ARCHIVE_RUN, "run: |\n          false &&\n          " + ARCHIVE_RUN[len("run: "):], 1)]),
    ("archive check in a one-line subshell", "release-packaged-gate",
     "release.yml:verify-packaged step 4: release-packaged-gate: unmodelled shell syntax around", [
        (RELEASE, ARCHIVE_RUN, archive_block(" ) || echo ignored").replace("run: |\n          ", "run: |\n          ( "), 1)]),
    ("archive check inside an unbalanced quote", "release-packaged-gate",
     "release.yml:verify-packaged step 4: release-packaged-gate: unmodelled shell syntax around", [
        (RELEASE, ARCHIVE_RUN, 'run: |\n          echo "\n          ' + ARCHIVE_RUN[len("run: "):] + '\n          "', 1)]),
    ("verify-packaged on a fixed runner", "release-verify-matrix",
     "release.yml: release-verify-matrix: verify-packaged does not run on the runner of its matrix leg", [
        (RELEASE, "    runs-on: ${{ matrix.os }}\n    timeout-minutes: 15\n",
         "    runs-on: ubuntu-24.04\n    timeout-minutes: 15\n", 1)], 1),
    ("rehearsal archive check with a fixed target", "release-verify-matrix",
     "release-rehearsal.yml: release-verify-matrix: the archive check does not read TARGET from the matrix leg", [
        (REHEARSAL, "          TARGET: ${{ matrix.target }}\n          VERSION: ${{ needs.build.outputs.version }}\n",
         "          TARGET: x86_64-unknown-linux-gnu\n          VERSION: ${{ needs.build.outputs.version }}\n", 1)], 1),
    ("workflow token variable for the verification jobs", "verification-credentials",
     "release.yml:verify-packaged: verification-credentials: sets GH_TOKEN", [
        (RELEASE, RELEASE_WORKFLOW_ENV, RELEASE_WORKFLOW_ENV + "  GH_TOKEN: unused\n", 1)]),
    ("workflow env expression for the verification jobs", "verification-credentials",
     "release.yml:verify-packaged: verification-credentials: an expression reads the workflow token: github.token", [
        (RELEASE, RELEASE_WORKFLOW_ENV, RELEASE_WORKFLOW_ENV + "  LEAK: ${{ github.token }}\n", 1)]),
    ("workflow defaults expression for the verification jobs", "verification-credentials",
     "release.yml:verify-packaged: verification-credentials: an expression reads the workflow token: github.token", [
        (RELEASE, RELEASE_WORKFLOW_ENV,
         RELEASE_WORKFLOW_ENV + "defaults:\n  run:\n    working-directory: ${{ github.token }}\n", 1)]),
] + [
    (f"conditional {job}", "ci-feature-jobs", f"ci.yml: ci-feature-jobs: {job} can be bypassed",
     [conditional_feature_job(f"  {job}:\n    name: {job}\n")])
    for job in CI_FEATURE_JOBS
] + [
    (f"{job} step that continues on error", "ci-feature-jobs", f"ci.yml: ci-feature-jobs: {job} step can be bypassed", [
        (CI, f"        run: {command}", f"        continue-on-error: true\n        run: {command}", 1)])
    for job, command in CI_FEATURE_JOBS.items()
] + [
    ("release-shape that continues on error", "ci-feature-jobs", "ci.yml: ci-feature-jobs: release-shape can be bypassed", [
        (CI, "  release-shape:\n    name: release-shape\n",
         "  release-shape:\n    name: release-shape\n    continue-on-error: true\n", 1)]),
    ("conditional network forwarding check", "ci-feature-jobs", "test layout differs: feature-on-test-extra", [
        (CI, "        run: cargo check -p stellar-agent-network", "        if: false\n        run: cargo check -p stellar-agent-network", 1)]),
    ("feature-on clippy without mainnet-write", "ci-feature-jobs",
     "ci.yml: ci-feature-jobs: feature-on-clippy does not run unconditionally", [
        (CI, '--features "mainnet-write,$FEATURES_EXCEPT_MAINNET_WRITE" -- -D warnings',
         '--features "$FEATURES_EXCEPT_MAINNET_WRITE" -- -D warnings', 1)]),
    ("host recipe with a marker check in a subshell", "ci-feature-jobs",
     ".github/scripts/release/check-host.sh: ci-feature-jobs: unmodelled shell syntax around", [
        (HOST_SCRIPT, 'bash .github/scripts/check-binary-marker.sh "target/$target/release/stellar-agent-mcp" on "stellar-agent-mcp $version"\n',
         '( bash .github/scripts/check-binary-marker.sh "target/$target/release/stellar-agent-mcp" on "stellar-agent-mcp $version" ) || true\n', 1)]),
    ("host recipe without the MCP marker check", "ci-feature-jobs",
     ".github/scripts/release/check-host.sh: ci-feature-jobs: does not run unconditionally", [
        (HOST_SCRIPT, 'bash .github/scripts/check-binary-marker.sh "target/$target/release/stellar-agent-mcp" on "stellar-agent-mcp $version"\n', "", 1)]),
    ("host recipe that expects the release CLI off", "ci-feature-jobs",
     ".github/scripts/release/check-host.sh: ci-feature-jobs: does not run unconditionally: "
     'bash .github/scripts/check-binary-marker.sh "target/$target/release/stellar-agent" on', [
        (HOST_SCRIPT, '"target/$target/release/stellar-agent" on "stellar-agent $version"\n', '"target/$target/release/stellar-agent" off "stellar-agent $version"\n', 1)]),
    ("host recipe without the single CLI build", "ci-feature-jobs",
     ".github/scripts/release/check-host.sh: ci-feature-jobs: does not run unconditionally: "
     "cargo build --locked -p stellar-agent-cli", [
        (HOST_SCRIPT, HOST_SINGLE_CLI, "mkdir -p target/tmp/host-alias\n", 1)]),
    ("host recipe that expects the debug alias off", "ci-feature-jobs",
     ".github/scripts/release/check-host.sh: ci-feature-jobs: does not run unconditionally: "
     f"bash .github/scripts/check-binary-marker.sh {HOST_ALIAS} on", [
        (HOST_SCRIPT, f'{HOST_ALIAS} on "stellar-agent-mcp $version"\n', f'{HOST_ALIAS} off "stellar-agent-mcp $version"\n', 1)]),
    ("host recipe with the alias steps in a condition", "ci-feature-jobs",
     ".github/scripts/release/check-host.sh: ci-feature-jobs: does not run unconditionally: "
     f"cmp target/debug/stellar-agent {HOST_ALIAS}", [
        (HOST_SCRIPT, HOST_ALIAS_STEPS, "if false; then\n" + HOST_ALIAS_STEPS + "fi\n", 1)]),
    ("host recipe without the debug alias copy", "ci-feature-jobs",
     ".github/scripts/release/check-host.sh: ci-feature-jobs: does not run unconditionally: "
     + HOST_ALIAS_COPY.strip(), [
        (HOST_SCRIPT, HOST_ALIAS_COPY, "", 1)]),
    ("host recipe with a plain copy and mv", "ci-feature-jobs",
     ".github/scripts/release/check-host.sh: ci-feature-jobs: does not run unconditionally: "
     + HOST_ALIAS_COPY.strip(), [
        (HOST_SCRIPT, HOST_ALIAS_COPY,
         "cp -p target/debug/stellar-agent target/tmp/host-alias/.stellar-agent-mcp.tmp\n"
         f"mv -f target/tmp/host-alias/.stellar-agent-mcp.tmp {HOST_ALIAS}\n", 1)]),
    ("host recipe without the debug comparison", "ci-feature-jobs",
     ".github/scripts/release/check-host.sh: ci-feature-jobs: does not run unconditionally: "
     f"cmp target/debug/stellar-agent {HOST_ALIAS}", [
        (HOST_SCRIPT, f"cmp target/debug/stellar-agent {HOST_ALIAS}\n", "", 1)]),
    ("host recipe that ignores the release comparison", "ci-feature-jobs",
     ".github/scripts/release/check-host.sh: ci-feature-jobs: unmodelled shell syntax around " + HOST_RELEASE_CMP.strip(), [
        (HOST_SCRIPT, HOST_RELEASE_CMP, HOST_RELEASE_CMP.strip() + " || true\n", 1)]),
    ("host recipe without the release comparison", "ci-feature-jobs",
     ".github/scripts/release/check-host.sh: ci-feature-jobs: does not run unconditionally: " + HOST_RELEASE_CMP.strip(), [
        (HOST_SCRIPT, HOST_RELEASE_CMP, "", 1)]),
] + [
    (f"conditional {job}", "ci-feature-jobs", f"ci.yml: ci-feature-jobs: {job} can be bypassed",
     [conditional_feature_job(header)])
    for job, (header, _) in CI_OFF_JOBS.items()
] + [
    ("docs-only job without the changes dependency", "ci-feature-jobs", "ci.yml: ci-feature-jobs: doc can be bypassed", [
        (CI, CI_OFF_JOBS["doc"][0] + DOCS_ONLY_JOB, CI_OFF_JOBS["doc"][0] + DOCS_ONLY_JOB.replace(
            "needs: changes", "needs: [changes, fmt]"), 1)]),
    ("docs-only job that a failed changes job skips", "ci-feature-jobs",
     "ci.yml: ci-feature-jobs: release-shape can be bypassed", [
        (CI, "  release-shape:\n    name: release-shape\n" + DOCS_ONLY_JOB,
         "  release-shape:\n    name: release-shape\n" + DOCS_ONLY_JOB.replace("!cancelled() && ", ""), 1)]),
    ("docs-tests job removed", "ci-feature-jobs", "ci.yml: ci-feature-jobs: missing docs-tests", [
        (CI, DOCS_TESTS_HEADER, "  docs-tests-renamed:\n    name: docs-tests\n    needs: changes\n"
         "    if: ${{ !cancelled() && needs.changes.outputs.docs_only == 'true' }}\n", 1)]),
    ("docs-tests on every pull request", "ci-feature-jobs", "ci.yml: ci-feature-jobs: docs-tests can be bypassed", [
        (CI, DOCS_TESTS_HEADER, DOCS_TESTS_HEADER.replace("docs_only == 'true'", "docs_only != 'true'"), 1)]),
    ("docs-tests without the feature-on run", "ci-feature-jobs",
     "ci.yml: ci-feature-jobs: docs-tests does not run unconditionally: python3 .github/scripts/run-docs-tests.py "
     "--features mainnet-write", [
        (CI, DOCS_TESTS_ON_RUN, DOCS_TESTS_ON_RUN.replace("mainnet-write,", ""), 1)]),
    ("docs-tests step that continues on error", "ci-feature-jobs",
     "ci.yml: ci-feature-jobs: docs-tests step can be bypassed", [
        (CI, DOCS_TESTS_ON_RUN, DOCS_TESTS_ON_RUN + "        continue-on-error: true\n", 1)]),
] + [
    (f"{job} step that continues on error", "ci-feature-jobs", f"ci.yml: ci-feature-jobs: {job} step can be bypassed", [
        (CI, f"        run: {command}", f"        continue-on-error: true\n        run: {command}", 1)])
    for job, (_, command) in CI_OFF_JOBS.items()
] + [
    (f"{job} without --no-default-features", "ci-feature-jobs",
     f"ci.yml: ci-feature-jobs: {job} does not run unconditionally: {command}", [
        (CI, f"        run: {command}", f"        run: {command.replace(' --no-default-features', '')}", 1)])
    for job, (_, command) in CI_OFF_JOBS.items()
] + [
    ("coverage off measurement without --no-default-features", ("coverage-split", "ci-feature-jobs"), (
        "coverage.yml: coverage-split: unexpected coverage command in coverage-off",
        "coverage.yml: ci-feature-jobs: coverage-off does not run unconditionally: cargo llvm-cov --workspace "
        "--no-default-features"), [
        (COVERAGE, COVERAGE_OFF_RUN, COVERAGE_OFF_RUN.replace(" --no-default-features", ""), 1)]),
    ("coverage off measurement that continues on error", "ci-feature-jobs",
     "coverage.yml: ci-feature-jobs: coverage-off step can be bypassed", [
        (COVERAGE, COVERAGE_OFF_RUN, "        continue-on-error: true\n" + COVERAGE_OFF_RUN, 1)]),
    ("coverage job that continues on error", "ci-feature-jobs", "coverage.yml: ci-feature-jobs: coverage-off can be bypassed", [
        (COVERAGE, COVERAGE_OFF_HEADER, COVERAGE_OFF_HEADER + "    continue-on-error: true\n", 1)], 1),
    ("coverage job under another condition", ("coverage-condition", "ci-feature-jobs"), (
        "coverage.yml: coverage-condition: coverage-off job runs without the measure condition",
        "coverage.yml: ci-feature-jobs: coverage-off can be bypassed"), [
        (COVERAGE, COVERAGE_OFF_HEADER, COVERAGE_OFF_HEADER.replace(COVERAGE_IF_LINE, "    if: false\n"), 1)], 2),
    ("coverage workflow without its coverage job for the feature pin",
     ("coverage-condition", "coverage-split", "coverage-split", "ci-feature-jobs"), (
        "coverage.yml: coverage-condition: job coverage not found",
        "coverage.yml: coverage-split: python3 .github/scripts/check-coverage.py cov-feature-off.json --configuration "
        "feature-off runs in measure, expected coverage",
        "coverage.yml: coverage-split: python3 .github/scripts/check-coverage.py cov-feature-on.json --configuration "
        "feature-on runs in measure, expected coverage",
        "coverage.yml: ci-feature-jobs: missing coverage"), [
        (COVERAGE, COVERAGE_GATE_START, "  measure:\n    name: coverage\n", 1)], 5),
] + [
    (f"vars context in {where}", "release-vars",
     f"{path}: release-vars: an expression reads the vars context: vars.SAMPLE", [
        (path, old, new.format(VARS_READ), 1)], 1)
    for where, path, old, new in VARS_LOCATIONS
] + [
    ("unresolved local reference in the called vendored-wasm workflow", "release-vars",
     f"{WASM}: release-vars: local reference ./.github/actions/absent names no file", [
        (WASM, WASM_TREE_CHECK, WASM_TREE_CHECK + "      - uses: ./.github/actions/absent\n", 1)], 1),
]

# Each mutation of check-workflow-invariants.py: the text it replaces, the
# replacement, and the CASES or PASSING labels that must fail against the
# mutated copy and pass against the restored one.
CASES.extend((label, changelog_rule(label), CHANGELOG_MESSAGES[label], []) for label in CHANGELOG_VARIANTS)

CI_RESULT_SCRIPT = ".github/scripts/ci-result.py"
CI_RESULT_NAME = "    name: ci-result (${{ github.base_ref || github.ref_name }})\n"
CI_RESULT_NEEDS = ("    needs: [changes, fmt, clippy, doc, test, test-extra, feature-on-clippy, feature-on-doc, "
                   "feature-on-test, feature-on-test-extra, docs-tests, feature-discipline, release-shape, inbox-js, mpp-interop, "
                   "sdk-v17-interop, release-contracts, windows-storage, platform-keyring, deploy-scripts, machete, deny]\n")
CI_RESULT_CHECK = "      - name: Check every CI result\n        if: always()\n"
CI_RESULT_FIRST_CANCEL = ("      - name: Reject a cancelled run\n"
                          "        if: always() && cancelled()\n        run: exit 1\n")
CI_RESULT_LAST_CANCEL = ("      - name: Reject a run cancelled during result checks\n"
                         "        if: always() && cancelled()\n        run: exit 1\n")
CI_RESULT_DOCS_REQUIRED = 'DOCS_REQUIRED = {"changes", "docs-tests", "feature-discipline", "release-contracts"}\n'
CI_RESULT_TIMEOUT = "    runs-on: ubuntu-24.04\n    timeout-minutes: 10\n    permissions:\n"
CI_FMT_HEADER = ("  fmt:\n    name: fmt\n    needs: changes\n"
                 "    if: ${{ !cancelled() && needs.changes.outputs.docs_only != 'true' }}\n")
PUSH_GROUP = "  group: ${{ github.workflow }}-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}\n"
CASES.extend([
    ("ci-result missing need", "ci-result", "needs must include every other", [
        (CI, CI_RESULT_NEEDS, CI_RESULT_NEEDS.replace(", deny]", "]"), 1)]),
    ("ci-result wrong name", "ci-result", "name must identify the base", [
        (CI, CI_RESULT_NAME, "    name: ci-result\n", 1)]),
    ("ci-result step not always", "ci-result", "every step must always", [
        (CI, CI_RESULT_CHECK, CI_RESULT_CHECK.replace("        if: always()\n", ""), 1)]),
    ("ci-result job set differs", "ci-result", "job set must equal", [
        (CI_RESULT_SCRIPT, '    "machete", "deny",\n', '    "machete",\n', 1)]),
    ("ci-result can continue", "ci-result", "job must always run", [
        (CI, CI_RESULT_NAME, CI_RESULT_NAME + "    continue-on-error: true\n", 1)]),
    ("ci-result conditional job", "ci-result", "job must always run", [
        (CI, CI_RESULT_NEEDS + "    if: always()\n", CI_RESULT_NEEDS + "    if: success()\n", 1)]),
    ("ci-result cancellation ignored", "ci-result", "first step must reject cancellation", [
        (CI, CI_RESULT_FIRST_CANCEL, CI_RESULT_FIRST_CANCEL.replace("exit 1", "exit 0"), 1)]),
    ("ci-result without timeout", "ci-result", "timeout-minutes: 10", [
        (CI, CI_RESULT_TIMEOUT, CI_RESULT_TIMEOUT.replace("    timeout-minutes: 10\n", ""), 1)]),
    ("ci-result wrong timeout", "ci-result", "timeout-minutes: 10", [
        (CI, CI_RESULT_TIMEOUT, CI_RESULT_TIMEOUT.replace("timeout-minutes: 10", "timeout-minutes: 20"), 1)]),
    ("ci-result without final cancellation check", "ci-result", "last step must reject cancellation", [
        (CI, CI_RESULT_LAST_CANCEL, "", 1)]),
    ("ci-result final cancellation succeeds", "ci-result", "last step must reject cancellation", [
        (CI, CI_RESULT_LAST_CANCEL, CI_RESULT_LAST_CANCEL.replace("exit 1", "exit 0"), 1)]),
    ("ci-result final cancellation can continue", "ci-result", "every step must always", [
        (CI, CI_RESULT_LAST_CANCEL, CI_RESULT_LAST_CANCEL + "        continue-on-error: true\n", 1)]),
    ("ci-result docs-required adds skipped job", "ci-result", "DOCS_REQUIRED must match", [
        (CI_RESULT_SCRIPT, CI_RESULT_DOCS_REQUIRED, CI_RESULT_DOCS_REQUIRED.replace('{', '{"fmt", '), 1)]),
    ("ci-result docs-only workflow condition differs", "ci-result", "DOCS_REQUIRED must match", [
        (CI, CI_FMT_HEADER, CI_FMT_HEADER.split("    if:")[0], 1)]),
    ("ci-result docs-only workflow condition unknown", "ci-result", "unsupported docs-only job condition", [
        (CI, CI_FMT_HEADER, CI_FMT_HEADER.split("    if:")[0] + "    if: false\n", 1)]),
    ("ci-result docs-required job with empty condition", "ci-result",
     "release-contracts has an unsupported docs-only job condition", [
        (CI, "  release-contracts:\n    needs: changes\n    if: ${{ !cancelled() }}\n", '  release-contracts:\n    if: ""\n', 1)]),
    ("ci-result docs-tests condition on another job", "ci-result",
     "release-contracts has an unsupported docs-only job condition", [
        (CI, "  release-contracts:\n    needs: changes\n    if: ${{ !cancelled() }}\n", "  release-contracts:\n"
         "    if: ${{ !cancelled() && needs.changes.outputs.docs_only == 'true' }}\n", 1)]),
    ("ci-result environment differs", "ci-result", "exact environment", [
        (CI, "NEEDS_JSON: ${{ toJSON(needs) }}", "NEEDS_JSON: '{}'", 1)]),
    ("classifier environment differs", "docs-classifier", "shared environment", [
        (COVERAGE, "AFTER_SHA: ${{ github.event.after }}", "AFTER_SHA: ${{ github.sha }}", 1)]),
    ("classifier shallow checkout", "docs-classifier", "full history", [
        (COVERAGE, "          fetch-depth: 0\n", "          fetch-depth: 1\n", 1)]),
    ("docs-tests cache saves", "docs-classifier", "never save", [
        (CI, "          shared-key: test\n          save-if: false\n      - name: Check the documentation reads\n",
         "          shared-key: test\n" + CACHE_SAVE_LINE + "      - name: Check the documentation reads\n", 1)]),
    ("coverage changes failure ignored", "coverage-gate", "reject failed changes", [
        (COVERAGE, '          test "$CHANGES" = success\n', "", 1)]),
    ("coverage measurement missing changes", "coverage-condition", "must need changes", [
        (COVERAGE, COVERAGE_OFF_HEADER, COVERAGE_OFF_HEADER.replace("    needs: changes\n", ""), 1)]),
    ("coverage skips without successful classifier", "coverage-condition", "measure condition", [
        (COVERAGE, COVERAGE_OFF_HEADER, COVERAGE_OFF_HEADER.replace("needs.changes.result == 'success' && ", ""), 1)]),
])
for name in ("changes", "docs-tests", "feature-discipline", "release-contracts"):
    CASES.append((f"ci-result docs-required omits {name}", "ci-result", "DOCS_REQUIRED must match", [
        (CI_RESULT_SCRIPT, CI_RESULT_DOCS_REQUIRED,
         CI_RESULT_DOCS_REQUIRED.replace(f'"{name}", ', '').replace(f', "{name}"', ''), 1)]))
for workflow in (CI, COVERAGE):
    for key in ("paths", "paths-ignore"):
        CASES.append((f"{workflow} push {key}", "docs-classifier", "push must have no paths filter", [
            (workflow, "  push:\n", f"  push:\n    {key}: ['**/*.rs']\n", 1)]))
for workflow in (CI, COVERAGE, ".github/workflows/install-surface.yml"):
    CASES.append((f"{workflow} shared push group", "push-concurrency", "only pull request", [
        (workflow, PUSH_GROUP, "  group: ${{ github.workflow }}-${{ github.ref }}\n", 1)]))
    CASES.append((f"{workflow} cancels push runs", "push-concurrency", "only pull request", [
        (workflow, COVERAGE_CANCEL_LINE, "  cancel-in-progress: true\n", 1)]))
for event in ("push", "pull_request"):
    CASES.append((f"Wasm {event} omits next", "wasm-branches", f"{event} must include", [
        (WASM, f"  {event}:\n    branches: [main, next]", f"  {event}:\n    branches: [main]", 1)]))
for workflow in (TESTNET, ".github/workflows/install-surface.yml", ".github/workflows/take.yml"):
    CASES.append((f"{workflow} named permissions", "workflow-permissions", "no top-level permissions", [
        (workflow, "\npermissions:\n", "\nremoved-permissions:\n", 1)]))
CASES.append(("testnet checkout credentials", "checkout-credentials", "persist-credentials", [
    (TESTNET, "          persist-credentials: false\n", "          persist-credentials: true\n", 2)]))
CASES.append(("testnet config run input", "run-inputs", "run: reads", [
    (TESTNET, '          elif [ "$MAINNET_WRITE" = true ]; then',
     '          elif [ "${{ inputs.mainnet_write }}" = true ]; then', 1)]))
CASES.append(("testnet revision run input", "run-inputs", "run: reads", [
    (TESTNET, 'run: test "$(git rev-parse HEAD)" = "$EXPECTED_REVISION"',
     'run: test "$(git rev-parse HEAD)" = "${{ inputs.filter }}"', 2)]))
for action in ("actions/checkout", "actions/setup-python"):
    old = live_text(CHANGELOG, re.compile(rf"{action}@[0-9a-f]{{40}}"), f"{action} pin")
    revision = old.split("@")[1]
    alternative = "b" * 40 if revision == "a" * 40 else "a" * 40
    PASSING.append((f"{action} another full revision", [(CHANGELOG, old, f"{action}@{alternative}", 1)]))
    for label, value in (("tag", "v6"), ("short", "abcdef1"), ("branch", "main"), ("uppercase", "A" * 40)):
        CASES.append((f"{action} {label} revision", "changelog-check", "checkout and main fetch", [
            (CHANGELOG, old, f"{action}@{value}", 1)]))
    CASES.append((f"{action} wrong action", "changelog-check", "checkout and main fetch", [
        (CHANGELOG, old, "another/action@" + revision, 1)]))

CI_FMT_TOOLCHAIN = live_text(CI, re.compile(
    r"      - uses: dtolnay/rust-toolchain@[^\n]+\n        with:\n"
    r"          toolchain: [^\n]+\n          components: rustfmt\n"), "fmt toolchain step")
TOOLCHAIN_LINE = '          toolchain: "1.100.0"\n'
TOOLCHAIN_STEP = CI_FMT_TOOLCHAIN.replace("          components: rustfmt\n", "")
ACTION_TOOLCHAIN_FIXTURE = ".github/actions/toolchain-fixture/action.yml"
ACTION_TOOLCHAIN_TEXT = "runs:\n  using: composite\n  steps: []\n"
WALLET_TOOLCHAIN_CASES = [
    ("ci toolchain on stable", "with.toolchain", [
        (CI, CI_FMT_TOOLCHAIN, CI_FMT_TOOLCHAIN.replace('"1.100.0"', "stable"), 1)]),
    ("testnet toolchain differs", "with.toolchain", [
        (TESTNET, TOOLCHAIN_LINE, TOOLCHAIN_LINE.replace("1.100.0", "1.99.0"), 2)]),
    ("toolchain input absent", "with.toolchain", [
        (CI, CI_FMT_TOOLCHAIN, CI_FMT_TOOLCHAIN.replace(TOOLCHAIN_LINE, ""), 1)]),
    ("mixed-case toolchain action differs", "with.toolchain", [
        (CI, CI_FMT_TOOLCHAIN, CI_FMT_TOOLCHAIN.replace("dtolnay/rust-toolchain", "DtoLnAy/RuSt-ToOlChAiN")
         .replace('"1.100.0"', "stable"), 1)]),
    ("yaml workflow toolchain differs", "with.toolchain", [
        (CACHE_FIXTURE, CACHE_FIXTURE_TEXT, CACHE_FIXTURE_TEXT + TOOLCHAIN_STEP.replace("1.100.0", "1.99.0"), 1)]),
    ("ci uses release toolchain expression", "with.toolchain", [
        (CI, CI_FMT_TOOLCHAIN, CI_FMT_TOOLCHAIN.replace('"1.100.0"', "${{ env.RELEASE_TOOLCHAIN }}"), 1)]),
    ("repository channel floats", "channel must be an exact Rust version", [
        ("rust-toolchain.toml", 'channel = "1.100.0"', 'channel = "stable"', 1)]),
    ("release toolchains differ from repository", "RELEASE_TOOLCHAIN must equal", [
        (workflow, 'RELEASE_TOOLCHAIN: "1.100.0"', 'RELEASE_TOOLCHAIN: "1.99.0"', 1)
        for workflow in (RELEASE, PUBLISH, REHEARSAL)]),
    ("ci installs another toolchain", "run must not install or override", [
        (CI, CI_FMT_TOOLCHAIN, CI_FMT_TOOLCHAIN + "      - run: rustup toolchain install stable\n", 1)]),
    ("release preflight uses literal toolchain", "with.toolchain", [
        (RELEASE, "          toolchain: ${{ env.RELEASE_TOOLCHAIN }}\n", TOOLCHAIN_LINE, 3)]),
    ("local action toolchain differs", "with.toolchain", [
        (ACTION_TOOLCHAIN_FIXTURE, ACTION_TOOLCHAIN_TEXT,
         "runs:\n  using: composite\n  steps:\n" + TOOLCHAIN_STEP.replace("      ", "  ", 1)
         .replace("        with:", "    with:").replace("          toolchain:", "      toolchain:")
         .replace("1.100.0", "1.99.0"), 1)]),
]
for label, command in (
    ("rustup default override", "rustup default stable"),
    ("rustup directory override", "rustup override set stable"),
    ("cargo explicit toolchain", "cargo +stable metadata"),
    ("shell toolchain override", "RUSTUP_TOOLCHAIN=stable cargo metadata"),
    ("release pin line outside release", 'echo "RUSTUP_TOOLCHAIN=$RELEASE_TOOLCHAIN" >> "$GITHUB_ENV"'),
):
    message = "RUSTUP_TOOLCHAIN may only" if "RUSTUP_TOOLCHAIN" in command else "run must not install or override"
    WALLET_TOOLCHAIN_CASES.append((label, message, [
        (CACHE_FIXTURE, CACHE_FIXTURE_TEXT, CACHE_FIXTURE_TEXT + f"      - run: {command}\n", 1)]))
for label, old, new in (
    ("workflow toolchain env override", "jobs:\n", "env: {RUSTUP_TOOLCHAIN: stable}\njobs:\n"),
    ("job toolchain env override", "    runs-on:", "    env: {RUSTUP_TOOLCHAIN: stable}\n    runs-on:"),
    ("step toolchain env override", "      - run: 'true'\n",
     "      - run: 'true'\n        env: {RUSTUP_TOOLCHAIN: stable}\n"),
):
    WALLET_TOOLCHAIN_CASES.append((label, "RUSTUP_TOOLCHAIN may only", [
        (CACHE_FIXTURE, old, new, 1)]))
CASES.extend((label, "wallet-toolchain", message, edits, 1 if label == "repository channel floats" else None)
             for label, message, edits in WALLET_TOOLCHAIN_CASES)
PASSING.append(("vendored Wasm keeps compiler pins", []))

for job, title in (("changes", "changes"), ("coverage-off", "coverage (feature-off)"),
                   ("coverage-on", "coverage (feature-on)"), ("coverage", "coverage")):
    CASES.append((f"coverage name expression {job}", "coverage-names", "must have plain name", [
        (COVERAGE, f"    name: {title}\n", "    name: ${{ '" + title + "' }}\n", 1)]))


CASES.extend([
    ("coverage concurrency with event condition", "push-concurrency", "only pull request runs", [
        (COVERAGE, PUSH_GROUP, PUSH_GROUP.replace(
            "&& github.ref", "&& github.event.action == 'opened' && github.ref"), 1)]),
    ("coverage changes with event condition", "docs-classifier", "changes must call the classifier", [
        (COVERAGE, "  changes:\n", "  changes:\n    if: github.event.action == 'opened'\n", 1)]),
    ("S05 measure main", ("coverage-condition",) * 3,
     ("coverage-off job runs without the measure condition",
      "coverage-on job runs without the measure condition",
      "coverage gate decision must use the measure expression"), [
        (".github/workflows/coverage.yml", "github.event_name != 'pull_request' || github.base_ref == 'main' || !(needs.changes.result == 'success' && needs.changes.outputs.docs_only == 'true') || contains(github.event.pull_request.labels.*.name, 'coverage')", "github.event_name != 'pull_request' || !(needs.changes.result == 'success' && needs.changes.outputs.docs_only == 'true') || contains(github.event.pull_request.labels.*.name, 'coverage')", 3)]),
    ("S05 measure uncertain", ("coverage-condition",) * 3,
     ("coverage-off job runs without the measure condition",
      "coverage-on job runs without the measure condition",
      "coverage gate decision must use the measure expression"), [
        (".github/workflows/coverage.yml", "github.event_name != 'pull_request' || github.base_ref == 'main' || !(needs.changes.result == 'success' && needs.changes.outputs.docs_only == 'true') || contains(github.event.pull_request.labels.*.name, 'coverage')", "github.event_name != 'pull_request' || github.base_ref == 'main' || contains(github.event.pull_request.labels.*.name, 'coverage')", 3)]),
    ("S05 measure label", ("coverage-condition",) * 3,
     ("coverage-off job runs without the measure condition",
      "coverage-on job runs without the measure condition",
      "coverage gate decision must use the measure expression"), [
        (".github/workflows/coverage.yml", "github.event_name != 'pull_request' || github.base_ref == 'main' || !(needs.changes.result == 'success' && needs.changes.outputs.docs_only == 'true') || contains(github.event.pull_request.labels.*.name, 'coverage')", "github.event_name != 'pull_request' || github.base_ref == 'main' || !(needs.changes.result == 'success' && needs.changes.outputs.docs_only == 'true')", 3)]),
    ("S06 condition ci.yml Self-test feature discipline and assertions", "selftest-selection", "self-test condition", [
        (".github/workflows/ci.yml", "      - name: Self-test feature discipline and assertions\n        if: needs.changes.outputs.selftest_rust != 'false'\n", "      - name: Self-test feature discipline and assertions\n", 1)]),
    ("S07 check feature-discipline", "selftest-checks", "check steps must be unconditional", [
        (".github/workflows/ci.yml", "      - name: Check feature discipline and assertions\n", "      - name: Check feature discipline and assertions\n        if: false\n", 1)]),
    ("S08 job feature-discipline needs", "selftest-selection", "even on failure", [
        (".github/workflows/ci.yml", "  feature-discipline:\n    needs: changes\n    if: ${{ !cancelled() }}\n", "  feature-discipline:\n    if: ${{ !cancelled() }}\n", 1)]),
    ("S08 job feature-discipline failure", "selftest-selection", "even on failure", [
        (".github/workflows/ci.yml", "  feature-discipline:\n    needs: changes\n    if: ${{ !cancelled() }}\n", "  feature-discipline:\n    needs: changes\n    if: success()\n", 1)]),
    ("S08 job feature-discipline errors", "selftest-selection", "even on failure", [
        (".github/workflows/ci.yml", "  feature-discipline:\n    needs: changes\n    if: ${{ !cancelled() }}\n", "  feature-discipline:\n    needs: changes\n    if: ${{ !cancelled() }}\n    continue-on-error: true\n", 1)]),
    ("S06 condition ci.yml Self-test the publish tier check", "selftest-selection", "self-test condition", [
        (".github/workflows/ci.yml", "      - name: Self-test the publish tier check\n        if: needs.changes.outputs.selftest_scripts != 'false'\n", "      - name: Self-test the publish tier check\n", 1)]),
    ("S06 condition ci.yml Self-test the signer-set baseline gate", "selftest-selection", "self-test condition", [
        (".github/workflows/ci.yml", "      - name: Self-test the signer-set baseline gate\n        if: needs.changes.outputs.selftest_rust != 'false'\n", "      - name: Self-test the signer-set baseline gate\n", 1)]),
    ("S06 condition ci.yml Self-test the ref-on-main check", "selftest-selection", "self-test condition", [
        (".github/workflows/ci.yml", "      - name: Self-test the ref-on-main check\n        if: needs.changes.outputs.selftest_scripts != 'false'\n", "      - name: Self-test the ref-on-main check\n", 1)]),
    ("S06 condition ci.yml Self-test the testnet acceptance driver", "selftest-selection", "self-test condition", [
        (".github/workflows/ci.yml", "      - name: Self-test the testnet acceptance driver\n        if: needs.changes.outputs.selftest_rust != 'false'\n", "      - name: Self-test the testnet acceptance driver\n", 1)]),
    ("S06 condition ci.yml Self-test the crates.io existence check", "selftest-selection", "self-test condition", [
        (".github/workflows/ci.yml", "      - name: Self-test the crates.io existence check\n        if: needs.changes.outputs.selftest_scripts != 'false'\n", "      - name: Self-test the crates.io existence check\n", 1)]),
    ("S06 condition ci.yml Self-test the publish verification", "selftest-selection", "self-test condition", [
        (".github/workflows/ci.yml", "      - name: Self-test the publish verification\n        if: needs.changes.outputs.selftest_scripts != 'false'\n", "      - name: Self-test the publish verification\n", 1)]),
    ("S06 condition ci.yml Self-test the crate checksum comparison", "selftest-selection", "self-test condition", [
        (".github/workflows/ci.yml", "      - name: Self-test the crate checksum comparison\n        if: needs.changes.outputs.selftest_scripts != 'false'\n", "      - name: Self-test the crate checksum comparison\n", 1)]),
    ("S06 condition ci.yml Self-test the coverage floor gate", "selftest-selection", "self-test condition", [
        (".github/workflows/ci.yml", "      - name: Self-test the coverage floor gate\n        if: needs.changes.outputs.selftest_scripts != 'false'\n", "      - name: Self-test the coverage floor gate\n", 1)]),
    ("S06 condition ci.yml Self-test the proof matrix check", "selftest-selection", "self-test condition", [
        (".github/workflows/ci.yml", "      - name: Self-test the proof matrix check\n        if: needs.changes.outputs.selftest_scripts != 'false'\n", "      - name: Self-test the proof matrix check\n", 1)]),
    ("S06 condition ci.yml Self-test the docs-only classifier", "selftest-selection", "self-test condition", [
        (".github/workflows/ci.yml", "      - name: Self-test the docs-only classifier\n        if: needs.changes.outputs.selftest_scripts != 'false'\n", "      - name: Self-test the docs-only classifier\n", 1)]),
    ("S06 condition ci.yml Self-test the self-test classifier", "selftest-selection", "self-test condition", [
        (".github/workflows/ci.yml", "      - name: Self-test the self-test classifier\n        if: needs.changes.outputs.selftest_scripts != 'false'\n", "      - name: Self-test the self-test classifier\n", 1)]),
    ("S06 condition ci.yml Self-test the CI result gate", "selftest-selection", "self-test condition", [
        (".github/workflows/ci.yml", "      - name: Self-test the CI result gate\n        if: needs.changes.outputs.selftest_scripts != 'false'\n", "      - name: Self-test the CI result gate\n", 1)]),
    ("S06 condition ci.yml Self-test the run evidence check", "selftest-selection", "self-test condition", [
        (".github/workflows/ci.yml", "      - name: Self-test the run evidence check\n        if: needs.changes.outputs.selftest_scripts != 'false'\n", "      - name: Self-test the run evidence check\n", 1)]),
    ("S06 condition ci.yml Self-test the documentation read check", "selftest-selection", "self-test condition", [
        (".github/workflows/ci.yml", "      - name: Self-test the documentation read check\n        if: needs.changes.outputs.selftest_scripts != 'false'\n", "      - name: Self-test the documentation read check\n", 1)]),
    ("S06 condition ci.yml Self-test the unsigned archive validation", "selftest-selection", "self-test condition", [
        (".github/workflows/ci.yml", "      - name: Self-test the unsigned archive validation\n        if: needs.changes.outputs.selftest_scripts != 'false'\n", "      - name: Self-test the unsigned archive validation\n", 1)]),
    ("S06 condition ci.yml Self-test the workflow structure and the label sync", "selftest-selection", "self-test condition", [
        (".github/workflows/ci.yml", "      - name: Self-test the workflow structure and the label sync\n        if: needs.changes.outputs.selftest_scripts != 'false'\n", "      - name: Self-test the workflow structure and the label sync\n", 1)]),
    ("S07 check release-contracts", "selftest-checks", "check steps must be unconditional", [
        (".github/workflows/ci.yml", "      - name: Check the publish tiers\n", "      - name: Check the publish tiers\n        if: false\n", 1)]),
    ("S08 job release-contracts needs", "selftest-selection", "even on failure", [
        (".github/workflows/ci.yml", "  release-contracts:\n    needs: changes\n    if: ${{ !cancelled() }}\n", "  release-contracts:\n    if: ${{ !cancelled() }}\n", 1)]),
    ("S08 job release-contracts failure", "selftest-selection", "even on failure", [
        (".github/workflows/ci.yml", "  release-contracts:\n    needs: changes\n    if: ${{ !cancelled() }}\n", "  release-contracts:\n    needs: changes\n    if: success()\n", 1)]),
    ("S08 job release-contracts errors", "selftest-selection", "even on failure", [
        (".github/workflows/ci.yml", "  release-contracts:\n    needs: changes\n    if: ${{ !cancelled() }}\n", "  release-contracts:\n    needs: changes\n    if: ${{ !cancelled() }}\n    continue-on-error: true\n", 1)]),
    ("S06 condition install-surface.yml Self-test Python checks on Python 3.13", "selftest-selection", "self-test condition", [
        (".github/workflows/install-surface.yml", "      - name: Self-test Python checks on Python 3.13\n        if: steps.sel.outputs.selftest_docs != 'false'\n", "      - name: Self-test Python checks on Python 3.13\n", 1)]),
    ("S06 condition install-surface.yml Self-test the gate tool version check", "selftest-selection", "self-test condition", [
        (".github/workflows/install-surface.yml", "      - name: Self-test the gate tool version check\n        if: steps.sel.outputs.selftest_docs != 'false'\n", "      - name: Self-test the gate tool version check\n", 1)]),
    ("S06 condition install-surface.yml Self-test Python checks on Python 3.11", "selftest-selection", "self-test condition", [
        (".github/workflows/install-surface.yml", "      - name: Self-test Python checks on Python 3.11\n        if: steps.sel.outputs.selftest_docs != 'false'\n", "      - name: Self-test Python checks on Python 3.11\n", 1)]),
    ("S06 condition install-surface.yml Self-test the preflight", "selftest-selection", "self-test condition", [
        (".github/workflows/install-surface.yml", "      - name: Self-test the preflight\n        if: steps.sel.outputs.selftest_preflight != 'false'\n", "      - name: Self-test the preflight\n", 1)]),
    ("S07 check install-surface", "selftest-checks", "check steps must be unconditional", [
        (".github/workflows/install-surface.yml", "      - name: Check the install surface\n", "      - name: Check the install surface\n        if: false\n", 1)]),
    ("S09 unknown test", "selftest-selection", "unknown or mixed", [
        (".github/workflows/ci.yml", "        run: .github/scripts/test-publish-crates-check.sh\n", "        run: .github/scripts/test-unknown.sh\n", 1)]),
    ("S10 missing test", "selftest-selection", "inventory differs", [
        (".github/workflows/ci.yml", "        run: .github/scripts/test-publish-crates-check.sh\n", "        run: true\n", 1)]),
    ("S11 mixed groups", "selftest-selection", "unknown or mixed", [
        (".github/workflows/ci.yml", "        run: .github/scripts/test-publish-crates-check.sh\n", "        run: |\n          .github/scripts/test-publish-crates-check.sh\n          bash .github/scripts/test-run-testnet-acceptance.sh\n", 1)]),
    ("S12 mixed check", "selftest-checks", "separate and fail", [
        (".github/workflows/ci.yml", "        run: .github/scripts/test-publish-crates-check.sh\n", "        run: |\n          .github/scripts/test-publish-crates-check.sh\n          python3 .github/scripts/check-docs-reads.py\n", 1)]),
    ("S13 selftest errors", "selftest-checks", "separate and fail", [
        (".github/workflows/ci.yml", "        run: .github/scripts/test-publish-crates-check.sh\n", "        run: .github/scripts/test-publish-crates-check.sh\n        continue-on-error: true\n", 1)]),
    ("S14 selftest suppression", "selftest-checks", "separate and fail", [
        (".github/workflows/ci.yml", "        run: .github/scripts/test-publish-crates-check.sh\n", "        run: |\n          set +e\n          .github/scripts/test-publish-crates-check.sh\n", 1)]),
    ("S15 depth", "selftest-selector", "full checkout", [
        (".github/workflows/install-surface.yml", "          fetch-depth: 0\n", "          fetch-depth: 1\n", 1)]),
    ("S15 checkout", "selftest-selector", "full checkout", [
        (".github/workflows/install-surface.yml", "      - uses: actions/checkout@", "      - uses: invalid/checkout@", 1)]),
    ("S15 selector id", "selftest-selector", "full checkout", [
        (".github/workflows/install-surface.yml", "        id: sel\n", "        id: wrong\n", 1)]),
    ("S15 name", "selftest-selector", "full checkout", [
        (".github/workflows/install-surface.yml", "      - name: Select self-tests\n", "      - name: ''\n", 1)]),
    ("S15 selector skip", "selftest-selector", "full checkout", [
        (".github/workflows/install-surface.yml", "        id: sel\n", "        id: sel\n        if: false\n", 1)]),
    ("S15 selector error", "selftest-selector", "full checkout", [
        (".github/workflows/install-surface.yml", "        id: sel\n", "        id: sel\n        continue-on-error: true\n", 1)]),
    ("S15 env", "selftest-selector", "full checkout", [
        (".github/workflows/install-surface.yml", "AFTER_SHA: ${{ github.event.after }}", "AFTER_SHA: ${{ github.sha }}", 1)]),
    ("S15 command", "selftest-selector", "full checkout", [
        (".github/workflows/install-surface.yml", "        run: python3 .github/scripts/classify-self-tests.py >> \"$GITHUB_OUTPUT\"\n", "        run: true\n", 1)]),
    ("S16 output scripts", "docs-classifier", "shared environment", [
        (".github/workflows/ci.yml", "      selftest_scripts: ${{ steps.classify.outputs.selftest_scripts }}\n", "", 1)]),
    ("S16 output rust", "docs-classifier", "shared environment", [
        (".github/workflows/ci.yml", "      selftest_rust: ${{ steps.classify.outputs.selftest_rust }}\n", "", 1)]),
    ("S16 output docs", "docs-classifier", "shared environment", [
        (".github/workflows/ci.yml", "      selftest_docs: ${{ steps.classify.outputs.selftest_docs }}\n", "", 1)]),
    ("S16 output preflight", "docs-classifier", "shared environment", [
        (".github/workflows/ci.yml", "      selftest_preflight: ${{ steps.classify.outputs.selftest_preflight }}\n", "", 1)]),
    ("S17 classifier command", "docs-classifier", "shared environment", [
        (".github/workflows/ci.yml", "          python3 .github/scripts/classify-self-tests.py >> \"$GITHUB_OUTPUT\"\n", "", 1)]),
    ("S18 inverted false", ("selftest-selection",) * 3,
     ("install-surface: self-test condition must select docs",) * 3, [
        (".github/workflows/install-surface.yml", "steps.sel.outputs.selftest_docs != 'false'", "steps.sel.outputs.selftest_docs == 'true'", 3)]),
    ("S19 unknown group", ("selftest-selection",) * 3,
     ("feature-discipline: self-test condition must select rust",
      "release-contracts: self-test condition must select rust",
      "release-contracts: self-test condition must select rust"), [
        (".github/workflows/ci.yml", "needs.changes.outputs.selftest_rust != 'false'", "needs.changes.outputs.selftest_unknown != 'false'", 3)]),
])

INSTALL_JOB = live_text(".github/workflows/install-surface.yml", re.compile(
    r"  install-surface:\n.*", re.DOTALL), "install job")
INSTALL_CHECKOUT = live_text(".github/workflows/install-surface.yml", re.compile(
    r"      - uses: actions/checkout@[^\n]+\n        with:\n"
    r"          fetch-depth: 0\n          persist-credentials: false\n"), "install checkout")
CASES.extend([
    ("S20 empty steps", "selftest-selector", "full checkout", [
        (".github/workflows/install-surface.yml", INSTALL_JOB,
         "  install-surface:\n    runs-on: ubuntu-24.04\n    steps: []\n", 1)]),
    ("S21 checkout only", "selftest-selector", "full checkout", [
        (".github/workflows/install-surface.yml", INSTALL_JOB,
         "  install-surface:\n    runs-on: ubuntu-24.04\n    steps:\n" + INSTALL_CHECKOUT, 1)]),
    ("S22 conditional checkout", "selftest-selector", "full checkout", [
        (".github/workflows/install-surface.yml", INSTALL_CHECKOUT,
         INSTALL_CHECKOUT + "        if: false\n", 1)]),
    ("S23 selector order", "selftest-selector", "full checkout", [
        (".github/workflows/install-surface.yml", INSTALL_CHECKOUT,
         INSTALL_CHECKOUT + "      - run: true\n", 1)]),
])


# These cases exercise setup steps as well as commands without a script path.
for workflow, job, check_name in (
        (CI, "feature-discipline", "Check feature discipline and assertions"),
        (CI, "release-contracts", "Check the publish tiers"),
        (".github/workflows/install-surface.yml", "install-surface", "Check the install surface")):
    marker = f"      - name: {check_name}\n"
    CASES.append((f"S24 check errors {job}", "selftest-checks", "check steps must be unconditional", [
        (workflow, marker, marker + "        continue-on-error: true\n", 1)]))
    job_text = live_text(workflow, re.compile(
        rf"  {job}:\n.*?(?=\n  [a-z][\w-]*:|\Z)", re.DOTALL), f"{job} setup fixture")
    setup = re.search(r"      - uses: (?:dtolnay/rust-toolchain|actions/setup-python)@[^\n]+\n", job_text).group()
    CASES.append((f"S25 setup condition {job}", "selftest-checks", "check steps must be unconditional", [
        (workflow, job_text, job_text.replace(setup, setup + "        if: false\n", 1), 1)]))

for label, workflow, command, target in (
        ("actionlint", ".github/workflows/install-surface.yml", "actionlint",
         "          bash .github/scripts/test-preflight.sh\n"),
        ("cargo fetch", CI, "cargo fetch --locked",
         "          bash .github/scripts/test-check-binary-marker.sh\n"),
        ("script", CI, ".github/scripts/publish-crates.sh --check",
         "        run: .github/scripts/test-publish-crates-check.sh\n")):
    replacement = (target + f"          {command}\n" if label != "script" else
                   "        run: |\n          .github/scripts/test-publish-crates-check.sh\n"
                   f"          {command}\n")
    CASES.append((f"S26 moved {label}", "selftest-checks", "separate and fail", [
        (workflow, f"        run: {command}\n", "        run: true\n", 1),
        (workflow, target, replacement, 1)]))

CASES.append(("S27 archive name in another job", "selftest-checks", "check steps must be unconditional", [
    (".github/workflows/install-surface.yml", "      - name: Check the install surface\n",
     "      - name: Check the skill archive\n" + SKILL_ARCHIVE_IF, 1)]))
PASSING.append(("S28 unknown registry group rejected", []))

COSIGN_INSTALLER = "sigstore/cosign-installer@756fe2d284c7292c4e9b62c8a28f1e5629c59532"
for job in ("sign", "verify-provenance"):
    text = (ROOT / RELEASE).read_text()
    block = re.search(
        rf"(?ms)^  {job}:\n.*?(?=^  [a-z][a-z-]*:|\Z)", text).group()
    for label, old, new, message in (
            ("installer pin", COSIGN_INSTALLER, COSIGN_INSTALLER[:-1] + "0", "requires the pinned cosign installer"),
            ("cosign version", "cosign-release: v3.1.4", "cosign-release: v3.0.0", "requires cosign-release: v3.1.4")):
        CASES.append((f"{job} {label}", "release-signatures", f"{message}", [
            (RELEASE, block, block.replace(old, new), 1)]))

VERSION_STEP = re.search(r"(?ms)^      - name: Read workspace version\n.*?(?=^      - name:|\Z)",
                         (ROOT / REHEARSAL).read_text()).group()
CASES.extend([
    ("signature upload tolerates missing files", "release-signatures", "signature upload requires if-no-files-found: error", [
        (RELEASE, "name: signatures\n          if-no-files-found: error", "name: signatures\n          if-no-files-found: warn", 1)]),
    ("rehearsal version after build", "release-version-binding", "workspace version must be read before packaging", [
        (REHEARSAL, VERSION_STEP, "", 1),
        (REHEARSAL, '        run: bash .github/scripts/check-packaged-markers.sh target target/package-verification-start "$EXPECTED_MAINNET_WRITE" "$VERSION"\n',
         '        run: bash .github/scripts/check-packaged-markers.sh target target/package-verification-start "$EXPECTED_MAINNET_WRITE" "$VERSION"\n' + VERSION_STEP, 1)], 1),
    ("rehearsal version step missing", "release-version-binding", "workspace version must be read before packaging", [
        (REHEARSAL, VERSION_STEP, VERSION_STEP.replace("id: version", "id: unused"), 1)]),
    ("rehearsal package version binding", "release-version-binding", "packaged check must use the validated version output", [
        (REHEARSAL, "      - name: Verify packaged feature state\n        env:\n          VERSION: ${{ steps.version.outputs.version }}",
         "      - name: Verify packaged feature state\n        env:\n          VERSION: 0.0.0", 1)]),
    ("publish package version binding", "release-version-binding", "packaged check must use the validated version output", [
        (PUBLISH, "      - name: Verify packaged feature state\n        working-directory: src\n        env:\n          VERSION: ${{ steps.tag.outputs.version }}",
         "      - name: Verify packaged feature state\n        working-directory: src\n        env:\n          VERSION: 0.0.0", 1)]),
    ("publish install tag binding", "release-version-binding", "install check must use the validated tag output", [
        (PUBLISH, "TAG: ${{ steps.tag.outputs.tag }}", "TAG: ${{ inputs.tag }}", 1)]),
])

MUTATIONS = {
    "coverage-decision-id": (
        'first.get("id") != "decision"\n                or ', '', ["coverage decision without id"]),
    "coverage-decision-expression": (
        '(first.get("env") or {}).get("MEASURE", "") != COVERAGE_MEASURE', 'False',
        ["coverage decision without label", "coverage decision without push exclusion"]),
    'optimized-job-fallback': ('        workflow = "release-rehearsal.yml"\n        job = self.job(workflow, "build") or {}', '        workflow = "release-rehearsal.yml"\n        job = self.job(workflow, "build")', ['optimized probes job absent']),
    'optimized-workflow': ('workflow = "release-rehearsal.yml"\n        job = self.job(workflow, "build") or {}', 'workflow = "release.yml"\n        job = self.job(workflow, "build") or {}', ['optimized probes pass']),
    'optimized-index': ('index = probes[0]', 'index = probes[0] + 1', ['optimized probes pass']),
    'optimized-build-selection': ('builds = [i for i, step in enumerate(steps) if step.get("name") == "Build binaries"]', 'builds = []', ['optimized probes pass']),
    'optimized-normalization': ('actual = {**steps[index], "run": self.normalized(self.run_text(steps[index])),', 'actual = {**steps[index], "run": [self.run_text(steps[index])],', ['optimized probes pass']),
    'optimized-command-value': ('REHEARSAL_PROBE_COMMAND = "cargo test --release --locked', 'REHEARSAL_PROBE_COMMAND = "cargo test --locked', ['optimized probes pass']),

    'optimized-early-return': ('            self.report(workflow, rule, "expected exactly one optimized security probe step")\n            return', '            self.report(workflow, rule, "expected exactly one optimized security probe step")\n            pass', ['optimized probes missing']),
    'optimized-count': ('if len(probes) != 1:', 'if len(probes) < 1:', ['optimized probes duplicated']),
    'optimized-name-match': ('if step.get("name") == REHEARSAL_PROBE_NAME', 'if False', ['optimized probes command absent']),
    'optimized-command-match': (r'or any(re.search(r"(?:^|[;&|] *)cargo test [^#;&|]*\bvendored_wasm_release_cfg\b", line)', 'or any(False', ['optimized probes duplicate renamed']),
    'optimized-position': ('if builds != [index - 1]:', 'if False:', ['optimized probes before build', 'optimized probes separated', 'optimized probes build renamed']),
    'optimized-shape': (
        'if actual != expected:\n            self.report(workflow, rule, "probe step differs from the required guard and command")',
        'if False:\n            self.report(workflow, rule, "probe step differs from the required guard and command")',
        ['optimized probes guard changed', 'optimized probes filter dropped', 'optimized probes features changed', 'optimized probes release dropped', 'optimized probes no-run added', 'optimized probes continue-on-error', 'optimized probes failure swallowed', 'optimized probes jobs prefix', 'optimized probes jobs step env', 'optimized probes name changed', 'optimized probes command absent']),
    'optimized-job-suppression': ('if "continue-on-error" in job:\n            self.report(workflow, rule, "probe job must not suppress failures")', 'if False:\n            self.report(workflow, rule, "probe job must not suppress failures")', ['optimized probes job suppression']),
    'optimized-dispatch': ('        self.check_rehearsal_security_probes()', '        pass', ['optimized probes missing']),

    "signature-needs": (
        'for dependency in ("preflight", "provenance", "hashes", "sign"):',
        'for dependency in ("preflight", "provenance", "hashes"):',
        ["verify-provenance without sign"]),
    "signature-command": (
        'for command in PROVENANCE_CHECKS:', 'for command in (PROVENANCE_CHECKS[0], *PROVENANCE_CHECKS[2:]):',
        ["signature check removed"]),
    "signature-installer": (
        'if [step.get("uses") for step in installers] != [', 'if False and [step.get("uses") for step in installers] != [',
        ["sign installer pin", "verify-provenance installer pin"]),
    "signature-version": (
        'if [(step.get("with") or {}).get("cosign-release") for step in installers] != [COSIGN_VERSION]:', 'if False:',
        ["sign cosign version", "verify-provenance cosign version"]),
    "signature-upload": (
        'if [(step.get("with") or {}).get("if-no-files-found") for step in uploads] != ["error"]:', 'if False:',
        ["signature upload tolerates missing files"]),
    "package-version-binding": (
        'if any((steps[index].get("env") or {}).get("VERSION") != version for index in checks):', 'if False:',
        ["publish package version binding", "rehearsal package version binding"]),
    "package-version-order": (
        'if len(versions) != 1 or not builds or versions[0] >= builds[0]:', 'if False:',
        ["rehearsal version after build", "rehearsal version step missing"]),
    "install-tag-binding": (
        'if (step.get("env") or {}).get("TAG") != "${{ steps.tag.outputs.tag }}":', 'if False:',
        ["publish install tag binding"]),
    "testnet-input-channel": (r'if re.search(r"\binputs\.", expression):', 'if False:',
                            ["testnet config run input", "testnet revision run input"]),
    "testnet-checkout-credentials": ('if with_.get("persist-credentials") not in (False, "false"):',
                                    'if False:', ["testnet checkout credentials"]),
    "testnet-permissions": ('if "permissions" not in doc:', 'if False:',
                           [".github/workflows/testnet.yml named permissions"]),
    "wallet-toolchain": ("        self.check_wallet_toolchain()\n", "",
                         [label for label, _, _ in WALLET_TOOLCHAIN_CASES]),
    "wallet-toolchain-invalid-channel-return": (
        '            self.report("rust-toolchain.toml", rule, "channel must be an exact Rust version")\n            return\n',
        '            self.report("rust-toolchain.toml", rule, "channel must be an exact Rust version")\n',
        ["repository channel floats"]),
    "wallet-toolchain-wasm-exemption": ('if workflow and path.name == "vendored-wasm.yml":', 'if False:',
                                       ["vendored Wasm keeps compiler pins"]),
    "coverage-gate-needs-message": (
        'expected changes, coverage-off and coverage-on', 'expected coverage-off and coverage-on',
        ["coverage gate needs one part"]),
    "ci-result-first-cancel": ('self.report(workflow, rule, "first step must reject cancellation")', 'pass',
                               ["ci-result cancellation ignored"]),
    "ci-result-timeout": ('if job.get("timeout-minutes") != 10:', 'if False:',
                          ["ci-result without timeout", "ci-result wrong timeout"]),
    "ci-result-final-cancel": ('self.report(workflow, rule, "last step must reject cancellation")', 'pass',
                               ["ci-result without final cancellation check", "ci-result final cancellation succeeds"]),
    "ci-result-step-errors": (
        'self.unwrap_expression(str(step.get("if", ""))) != condition\n                    or "continue-on-error" in step',
        'self.unwrap_expression(str(step.get("if", ""))) != condition',
        ["ci-result final cancellation can continue"]),
    "ci-result-docs-required": ('if actual != wanted:', 'if constant == "EXPECTED_JOBS" and actual != wanted:',
        [f"ci-result docs-required omits {name}" for name in
         ("changes", "docs-tests", "feature-discipline", "release-contracts")] +
        ["ci-result docs-required adds skipped job", "ci-result docs-only workflow condition differs"]),
    "ci-result-docs-condition": (
        'self.report(workflow, rule, f"{name} has an unsupported docs-only job condition")', 'pass',
        ["ci-result docs-only workflow condition unknown", "ci-result docs-required job with empty condition",
         "ci-result docs-tests condition on another job"]),
    "push-cancel": (
        'or self.unwrap_expression(str(concurrency.get("cancel-in-progress", ""))) != "github.event_name == \'pull_request\'"',
        'or False', [f"{workflow} cancels push runs" for workflow in
                     (CI, COVERAGE, ".github/workflows/install-surface.yml")]),
    "coverage-part-unwrapped": ('condition = self.unwrap_expression(condition)', 'condition = condition[3:-2].strip()',
                                ["coverage job condition without expression wrapper passes"]),
    "ci-result-needs": ('if not isinstance(needs, list) or set(needs) != expected:', 'if False:',
                        ["ci-result missing need"]),
    "W01": ('if "push" not in triggers:\n            self.report(workflow, rule, "push trigger is absent")',
            'if False:\n            self.report(workflow, rule, "push trigger is absent")', ["W01"]),
    "W02": ('if "pull_request" not in triggers:', 'if False:', ["W02"]),
    "W03": ('triggers["pull_request"] != {"types": events}',
            'triggers["pull_request"] not in ({"types": events}, {"types": events[:-1]})', ["W03"]),
    "W04": ('self.report(workflow, rule, "missing changelog job")', 'pass', ["W04"]),
    "W05": ('"if" in job or "needs" in job or "continue-on-error" in job',
            '"needs" in job or "continue-on-error" in job', ["W05"]),
    "W06": ('self.report(workflow, rule, "missing fragment check step")', 'pass', ["W06"]),
    "W07": ('self.may_skip(check) or self.effective_shell', '"continue-on-error" in check or self.effective_shell', ["W07"]),
    "W08": ('self.run_text(check).strip() != "python3 .github/scripts/changelog.py check"',
            'self.run_text(check).strip().lstrip("# ") != "python3 .github/scripts/changelog.py check"', ["W08"]),
    "W09": ('self.report(workflow, rule, "missing fragment test step")', 'pass', ["W09"]),
    "W10": ('self.run_text(test).strip() != "python3 .github/scripts/test-changelog.py"',
            'self.run_text(test).strip().removesuffix(" || true") != "python3 .github/scripts/test-changelog.py"', ["W10"]),
    "W11": ('options.get("fetch-depth") != 0', 'options.get("fetch-depth") not in (0, 1)', ["W11"]),
    "W12": ('self.report(workflow, "changelog-guard", "missing integration guard")', 'pass', ["W12"]),
    "W13": ('if condition != CHANGELOG_CONDITION:',
            'if condition not in (CHANGELOG_CONDITION, CHANGELOG_CONDITION.replace("next", "main")):', ["W13"]),
    "W14": ('if guard.get("env") != expected_env:',
            'if guard.get("env") not in (expected_env, {**expected_env, "HEAD_SHA": "${{ github.sha }}"}):', ["W14"]),
    "W15": ('if self.run_text(guard).strip() != CHANGELOG_GUARD:',
            'if self.run_text(guard).strip().replace(" --main-ref refs/remotes/origin/main", "") '
            '!= CHANGELOG_GUARD.replace(" --main-ref refs/remotes/origin/main", ""):', ["W15"]),
    "W16": ('if "continue-on-error" in guard or guard.get("shell") != "bash":',
            'if guard.get("shell") != "bash":', ["W16"]),
    "W17": ('condition = self.unwrap_expression(guard.get("if", ""))', 'condition = guard.get("if", "")', ["W17"]),
    "W18": ('self.report(workflow, rule, "pending fragments step must follow the version header check without bypasses")',
            'pass', ["W18"]),
    "skill-archive-count": (
        'if len(steps) != 1:', 'if not steps:',
        ['skill archive step duplicated']),
    "skill-archive-strip": (
        'if self.run_text(step).strip() != ".github/scripts/package-skill.sh --check":',
        'if self.run_text(step) != ".github/scripts/package-skill.sh --check":',
        ['skill archive block run passes']),
    "skill-archive-shell": (
        ' or shell not in (None, "bash")):', '):',
        ['skill archive step shell bypass', 'skill archive job shell bypass',
         'skill archive workflow shell bypass']),
    "skill-archive-job-skip": (
        'self.unwrap_expression(str(job.get("if", ""))) != "!cancelled()"\n                or job.get("needs") not in ("changes", ["changes"])',
        'False',
        ['skill archive job skipped']),
    "skill-archive-step-error": (
        'or "continue-on-error" in step or shell not in (None, "bash")):',
        'or shell not in (None, "bash")):',
        ['skill archive continues on error']),
    "skill-archive-unwrap": (
        'if self.unwrap_expression(step.get("if", "")) != SKILL_ARCHIVE_CONDITION:',
        'if step.get("if", "") != SKILL_ARCHIVE_CONDITION:',
        ['wrapped skill archive condition passes']),
    "skill-archive-condition": (
        'if self.unwrap_expression(step.get("if", "")) != SKILL_ARCHIVE_CONDITION:', 'if False:',
        ['skill archive skipped for main pull requests']),
    "skill-archive-command": (
        'if self.run_text(step).strip() != ".github/scripts/package-skill.sh --check":', 'if False:',
        ['skill archive command removed']),
    "apt-retries-option": (
        'if not APT_RETRIES.search(arguments):', 'if False:',
        ['apt-get without retries', 'apt-get multiline second call without retries']),
    "apt-retries-comments": (
        '                    for line in self.logical_lines(self.run_text(step)):\n'
        '                        line = re.split(r"(?<![^ \\t])#", line, maxsplit=1)[0]\n',
        '                    for line in self.run_text(step).splitlines():\n',
        ['apt-get in comments passes']),
    "ci-trigger-main": (
        'if not isinstance(branches, list) or "main" not in branches:', 'if False:',
        ['CI pull request branches without main']),
    "ci-trigger-events": (
        'for event in sorted(set(triggers) - {"push", "pull_request", "workflow_dispatch"}):', 'for event in ():',
        ['CI adds repository_dispatch']),
    "ci-trigger-dispatch": (
        'if "workflow_dispatch" not in triggers or triggers["workflow_dispatch"] not in (None, {}):', 'if False:',
        ['CI without workflow_dispatch', 'CI workflow_dispatch with inputs']),
    "ci-trigger-dispatch-inputs": (
        'if "workflow_dispatch" not in triggers or triggers["workflow_dispatch"] not in (None, {}):',
        'if "workflow_dispatch" not in triggers:', ['CI workflow_dispatch with inputs']),
    "ci-trigger-dispatch-mapping": (
        'triggers["workflow_dispatch"] not in (None, {}):', 'triggers["workflow_dispatch"] is not None:',
        ['CI workflow_dispatch as an empty mapping passes']),
    "release-evidence-upper": (
        '{str(key).upper() for key in env} & TOKEN_ENV', '{str(key) for key in env} & TOKEN_ENV',
        ['token name in the job env']),
    "release-evidence-check": (
        '        self.check_release_ci_evidence()\n', '',
        [case[0] for case in RELEASE_EVIDENCE_CASES]),
    "release-evidence-permissions": (
        'if job.get("permissions") != RELEASE_EVIDENCE_PERMISSIONS or self.may_skip(job):',
        'if self.may_skip(job):', ['preflight without actions: read']),
    "release-evidence-job-skip": (
        'if job.get("permissions") != RELEASE_EVIDENCE_PERMISSIONS or self.may_skip(job):',
        'if job.get("permissions") != RELEASE_EVIDENCE_PERMISSIONS:', ['conditional preflight']),
    "release-evidence-provenance": (
        'if (owner == "provenance" and permissions == RELEASE_PROVENANCE_PERMISSIONS\n',
        'if (owner == "provenance"\n', ['provenance gains a scope']),
    "release-evidence-provenance-uses": (
        '                    and node.get("uses") == RELEASE_PROVENANCE_USES and "steps" not in node):',
        '                    and "steps" not in node):', ['provenance with another generator']),
    "release-evidence-provenance-steps": (
        '                    and node.get("uses") == RELEASE_PROVENANCE_USES and "steps" not in node):',
        '                    and node.get("uses") == RELEASE_PROVENANCE_USES):', ['provenance with steps']),
    "release-evidence-string": (
        'if isinstance(permissions, str) or (isinstance(permissions, dict) and "actions" in permissions):',
        'if isinstance(permissions, dict) and "actions" in permissions:', ['read-all on another release job']),
    "release-evidence-actions": (
        'if isinstance(permissions, str) or (isinstance(permissions, dict) and "actions" in permissions):',
        'if isinstance(permissions, str):',
        ['actions: read on another release job', 'actions: read on the workflow', 'provenance gains a scope']),
    "release-evidence-count": (
        'if len(evidence) != 1 or len(ancestry) != 1 or evidence[0] != ancestry[0] + 1:',
        'if not evidence or len(ancestry) != 1 or evidence[0] != ancestry[0] + 1:', ['evidence step duplicated']),
    "release-evidence-order": (
        'if len(evidence) != 1 or len(ancestry) != 1 or evidence[0] != ancestry[0] + 1:',
        'if len(evidence) != 1 or len(ancestry) != 1 or evidence[0] > ancestry[0] + 1:',
        ['evidence step before the ancestry step']),
    "release-evidence-directly": (
        'if len(evidence) != 1 or len(ancestry) != 1 or evidence[0] != ancestry[0] + 1:',
        'if len(evidence) != 1 or len(ancestry) != 1 or evidence[0] < ancestry[0]:',
        ['evidence step after another step']),
    "release-evidence-ancestry": (
        'if len(evidence) != 1 or len(ancestry) != 1 or evidence[0] != ancestry[0] + 1:',
        'if len(evidence) != 1 or (ancestry and evidence[0] != ancestry[0] + 1):', ['ancestry step removed']),
    "release-evidence-skip": (
        'if self.may_skip(step) or self.effective_shell(', 'if self.effective_shell(',
        ['evidence step with if', 'evidence step with continue-on-error']),
    "release-evidence-shell": (
        'self.effective_shell(workflow, "preflight", step) not in (None, "bash") \\', 'False \\',
        ['evidence step with another shell', 'evidence step under a job default shell']),
    "release-evidence-command": (
        '                    or self.run_text(step).strip() != RELEASE_EVIDENCE_COMMAND \\\n', '',
        ['evidence command changed', 'evidence command suppressed']),
    "release-evidence-env": (
        '                    or step.get("env") != RELEASE_EVIDENCE_ENV:',
        '                    or False:', ['evidence step with another env', 'evidence step without the token']),
    "release-evidence-workflow-env": (
        'for owner, env in [("workflow env", doc.get("env")), ', 'for owner, env in [',
        ['token in the workflow env']),
    "release-evidence-job-env": (
        '("job env", job.get("env")),\n', '\n', ['token in the job env', 'token name in the job env']),
    "release-evidence-steps": (
        'step.get("env")) for i, step in enumerate(steps) if i not in evidence)]:',
        'step.get("env")) for i, step in enumerate(steps) if False)]:', ['token variable in another preflight step']),
    "release-evidence-names": (
        'if isinstance(env, dict) and {str(key).upper() for key in env} & TOKEN_ENV:', 'if False:',
        ['token in the job env', 'token name in the job env', 'token in the workflow env',
         'token variable in another preflight step']),
    "release-evidence-expressions": (
        '        self.check_credential_expressions(f"{workflow}:preflight", {"preflight": scanned, **inherited}, rule)\n',
        '', ['github token under another name in the job env', 'token in another preflight step',
             'indexed github token in a preflight step', 'whole github context in a preflight step',
             'token in the workflow defaults', 'token in the preflight outputs']),
    "release-evidence-own-token": (
        'if not (i in evidence and key == "env")}', 'if True}', ['release evidence step token passes']),
    "release-evidence-step-env-key": (
        'if not (i in evidence and key == "env")}', 'if i not in evidence}',
        ['evidence step reads the token through working-directory']),
    "release-evidence-inherited-env": (
        'for key in ("env", "defaults") if key in doc}', 'for key in ("defaults",) if key in doc}',
        ['github token under another name in the workflow env']),
    "release-evidence-inherited-scope": (
        'inherited = {key: doc[key] for key in ("env", "defaults") if key in doc}', 'inherited = dict(doc)',
        ['workflow env without a token passes']),
    "release-evidence-inherited": (
        'inherited = {key: doc[key] for key in ("env", "defaults") if key in doc}', 'inherited = {}',
        ['token in the workflow defaults']),
    "release-evidence-defaults": (
        'for key in ("env", "defaults") if key in doc}', 'for key in ("env",) if key in doc}',
        ['token in the workflow defaults']),
    "skill-archive-check": (
        '        self.check_skill_archive()\n', '',
        ['skill archive step removed', 'skill archive skipped for main pull requests',
         'skill archive skipped for main pushes', 'skill archive command removed']),
    "release-wasm-ref-type": (
        '"REF_TYPE": "${{ github.ref_type }}",', '"REF_TYPE": "branch",',
        ['Wasm gate uses wrong ref type']),
    "publish-verified-source-order": (
        ', VERIFIED_SOURCE_CHECK), "compare-crate-sums.py"),', '), "compare-crate-sums.py"),',
        ['crate publish without verified source guard', 'crate publish echoes verified source']),
    "release-vars-context": (
        "if VARS_CONTEXT.search(EXPRESSION_STRING.sub(\"''\", expression)):", "if False:",
        [f"vars context in {where}" for where, *_ in VARS_LOCATIONS]),
    "release-vars-strings": (
        "if VARS_CONTEXT.search(EXPRESSION_STRING.sub(\"''\", expression)):",
        "if VARS_CONTEXT.search(expression):",
        [f"vars text outside the context in {where} passes" for where, *_ in VARS_LOCATIONS]),
    "release-vars-transitive": (
        "                    pending.append(target)\n", "                    pass\n",
        ["vars context in the called vendored-wasm workflow", "vars context in the signing action",
         "unresolved local reference in the called vendored-wasm workflow"]),
    "release-vars-unresolved": (
        'self.report(str(relative), rule, f"local reference {reference} names no file")', "pass",
        ["unresolved local reference in the called vendored-wasm workflow"]),
    "coverage-gate-condition": (
        "if gate_condition != COVERAGE_GATE_CONDITION:", "if False:",
        ["coverage gate without always()", "coverage gate without if"]),
    "coverage-gate-missing-if": (
        'gate_condition = gate.get("if")', 'gate_condition = gate.get("if", "always()")',
        ["coverage gate without if"]),
    "coverage-changes-condition": (
        'or "if" in job or "needs" in job', 'or "needs" in job',
        ["coverage changes with event condition"]),
    "coverage-concurrency-group": (
        'if (concurrency.get("group") != group', 'if (False',
        ["coverage concurrency with event condition", ".github/workflows/coverage.yml shared push group"]),
    "coverage-gate-label": (
        "if gate_condition != COVERAGE_GATE_CONDITION:", 'if not str(gate_condition).startswith("always()"):',
        ["coverage gate adds event condition"]),
    "coverage-gate-not-cancelled": (
        "if gate_condition != COVERAGE_GATE_CONDITION:",
        'if gate_condition not in (COVERAGE_GATE_CONDITION, "!cancelled()"):',
        ["coverage gate skipped on cancellation"]),
    "coverage-gate-unwrap": (
        "gate_condition = self.unwrap_expression(gate_condition)", "gate_condition = gate_condition",
        ["coverage gate condition wrapped in ${{ }} passes"]),
    "coverage-gate-name": ('if job.get("name") != title:', "if False:",
                           ["coverage gate renamed"] + [f"coverage name expression {job}"
                            for job in ("changes", "coverage-off", "coverage-on", "coverage")]),
    "coverage-part-condition": (
        "if condition != COVERAGE_CONDITION:", "if False:", ["coverage-on without the measure condition"]),
    "coverage-part-presence": (
        'self.report(workflow, "coverage-condition", f"job {name} not found")', "pass", ["coverage-off job removed"]),
    "coverage-split-owner": ("elif name != owner:", "elif False:", ["feature-off measurement also in coverage-on"]),
    "coverage-split-extra-owner": ("elif name != owner:", "elif False:", ["third measurement job"]),
    "coverage-split-floor-owner": ("elif name != owner:", "elif False:", ["floors in a measurement job"]),
    "coverage-split-measure-count": (
        "if count > 1:", "if count > 1 and owners[line] == COVERAGE_GATE:",
        ["feature-off measurement repeated in its owner"]),
    "coverage-split-floor-count": (
        "if count > 1:", "if count > 1 and owners[line] != COVERAGE_GATE:", ["feature-on floor repeated in the gate"]),
    "coverage-floor-command": (
        "COVERAGE_OFF_FLOORS, COVERAGE_ON_FLOORS)),", "COVERAGE_OFF_FLOORS)),", ["feature-on floor absent"]),
    "coverage-split-unknown": (
        'self.report(workflow, rule, f"unexpected coverage command in {name}: {line}")', "pass",
        ["feature-on measurement without mainnet-write"]),
    "coverage-split-upload": ("if not uploads:", "if False:", ["coverage-on without upload"]),
    "coverage-split-upload-missing-file": (
        'if options.get("if-no-files-found") != "error":', "if False:", ["upload that tolerates a missing export"]),
    "coverage-split-upload-order": (
        "if not measured or index < measured[0]:", "if False:", ["upload before measurement"]),
    "coverage-upload-condition": (
        'if ("if" in step or "continue-on-error" in step) and not (',
        'if ("continue-on-error" in step or ("if" in step and not str(step.get("uses", ""))'
        '.startswith("actions/upload-artifact@"))) and not (',
        ["conditional upload"]),
    "coverage-gate-needs": (
        "if not isinstance(needs, list) or set(map(str, needs)) != {\"changes\", *COVERAGE_PARTS}:", "if False:",
        ["coverage gate needs one part"]),
    "coverage-gate-env": ("if env != COVERAGE_RESULT_ENV:", "if False:", ["coverage gate result check reads one part twice"]),
    "coverage-gate-env-keys": (
        '        env = first.get("env")\n',
        '        env = { {False: "OFF", True: "ON"}.get(key, key): value for key, value in (first.get("env") or {}).items()}\n',
        ["coverage gate result keys unquoted"]),
    "coverage-gate-result-command": (
        "COVERAGE_RESULT_CHECKS[0], COVERAGE_RESULT_CHECKS[1], ", "COVERAGE_RESULT_CHECKS[0], ",
        ["coverage gate result check removed"]),
    "coverage-gate-result-error": (
        'if ("if" in step or "continue-on-error" in step) and not (',
        'if ("if" in step or ("continue-on-error" in step and COVERAGE_RESULT_CHECKS[0] not in self.run_text(step)))'
        ' and not (',
        ["coverage gate result check continues on error"]),
    "coverage-gate-result-first": (
        'if "if" in first or any(self.runs_line(first.get("run"), check)[0] < 0 for check in COVERAGE_RESULT_CHECKS):',
        "if False:", ["coverage gate result step under a condition"]),
    "coverage-gate-cancel-early": (
        "if len(steps) < 2 or not rejects(steps[1]):", "if False:", ["coverage gate without the early cancel rejection"]),
    "coverage-gate-cancel-final": (
        "if not (len(steps) > 2 and rejects(steps[-1]) and all(index < len(steps) - 1 for index in floors)):",
        "if False:", ["coverage gate without the final cancel rejection"]),
    "coverage-gate-cancel-command": (
        "return self.normalized(self.run_text(step)) == [COVERAGE_CANCEL_RUN]", "return True",
        ["coverage gate cancel rejection that never fails"]),
    "coverage-gate-cancel-condition": (
        "if not isinstance(condition, str) or self.unwrap_expression(condition) != COVERAGE_CANCEL_CONDITION:",
        "if not isinstance(condition, str):", ["coverage gate cancel rejection on failure"]),
    "coverage-gate-cancel-error": (
        'if "continue-on-error" in step:\n                return False',
        "if False:\n                return False", ["coverage gate cancel rejection that continues on error"]),
    # The complete final-rejection placement predicate, the last-step
    # requirement included, is disabled.
    "coverage-gate-cancel-order": (
        "if not (len(steps) > 2 and rejects(steps[-1]) and all(index < len(steps) - 1 for index in floors)):",
        "if False:", ["coverage gate cancel rejection before the floors only"]),
    "coverage-gate-cancel-exemption": (
        'and self.normalized(self.run_text(step)) == [COVERAGE_CANCEL_RUN])',
        ')', ["coverage gate cancel rejection that never fails"]),
    "coverage-gate-cancel-unwrap": (
        "self.unwrap_expression(condition) != COVERAGE_CANCEL_CONDITION", "condition != COVERAGE_CANCEL_CONDITION",
        ["coverage gate cancel condition wrapped in ${{ }} passes"]),
    "coverage-gate-foreign": (
        "for key in FOREIGN_ARTIFACT_INPUTS:\n                if key in options:",
        "for key in ():\n                if key in options:", ["coverage gate downloads from another run"]),
    "coverage-gate-download": (
        'self.report(workflow, rule, f"coverage gate does not download {artifact}")', "pass",
        ["coverage gate missing a download"]),
    "coverage-gate-order": ("if index > first_floor:", "if False:", ["coverage gate floors before download"]),
    "coverage-seed-push": ('if "push" not in seeds:', "if False:", ["coverage without push trigger"]),
    "coverage-seed-branch": (
        "for branch in COVERAGE_SEED_BRANCHES:", "for branch in COVERAGE_SEED_BRANCHES[1:]:", ["coverage push on main only"]),
    "coverage-seed-main-branch": (
        "for branch in COVERAGE_SEED_BRANCHES:", "for branch in COVERAGE_SEED_BRANCHES[:1]:",
        ["coverage push on next only"]),
    "coverage-seed-paths": (
        'if any(key in push for key in ("paths", "paths-ignore")):', "if False:", ["coverage push with paths filter"]),
    "coverage-seed-paths-ignore": (
        'for key in ("paths", "paths-ignore")):', 'for key in ("paths",)):', ["coverage push with paths-ignore filter"]),
    "coverage-seed-cancel": (
        "if not isinstance(cancel, str) or self.unwrap_expression(cancel) != COVERAGE_SEED_CANCEL:", "if False:",
        ["coverage push runs cancel each other"]),
    "coverage-seed-unwrap": (
        "self.unwrap_expression(cancel) != COVERAGE_SEED_CANCEL",
        'str(cancel).removeprefix("${{ ").removesuffix(" }}") != COVERAGE_SEED_CANCEL',
        ["cancel-in-progress with inner spaces passes"]),
    "cache-save-if-value": (
        "if not isinstance(value, str) or self.unwrap_expression(value) != expected:", "if False:",
        ["ci clippy cache saves on pull requests"]),
    "cache-save-if-boolean": (
        "if not isinstance(value, str) or self.unwrap_expression(value) != expected:",
        "if value is not True and (not isinstance(value, str) or self.unwrap_expression(value) != expected):",
        ["ci cache save-if always true"]),
    "cache-save-if-coverage": (
        'for source in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):',
        'for source in [path for path in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])'
        ' if path.name != COVERAGE_WORKFLOW]:',
        ["coverage-on cache saves on pull requests"]),
    "cache-save-if-scope": (
        'for source in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):',
        "for source in [directory / name for name in WORKFLOWS]:", ["rust-cache in a yaml workflow"]),
    "cache-save-if-target": (
        'if not events & {"pull_request", "pull_request_target"}:', 'if not events & {"pull_request"}:',
        ["rust-cache in pull_request_target workflow"]),
    "cache-save-if-extension": (
        'for source in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):',
        'for source in sorted(directory.glob("*.yml")):', ["rust-cache in a yaml workflow"]),
    "cache-save-if-list": (
        "events = {str(event) for event in triggers}", "events = set()", ["rust-cache in a yaml workflow"]),
    "cache-save-if-scalar": ("events = {triggers}", "events = set()", ["rust-cache in scalar pull_request workflow"]),
    "cache-save-if-case": (
        'RUST_CACHE_ACTION = re.compile(r"Swatinem/rust-cache(/[\\w.-]+)*@", re.IGNORECASE)',
        'RUST_CACHE_ACTION = re.compile(r"Swatinem/rust-cache(/[\\w.-]+)*@")', ["rust-cache in upper case"]),
    "cache-save-if-unwrap": (
        "self.unwrap_expression(value) != expected",
        'str(value).removeprefix("${{ ").removesuffix(" }}") != expected',
        ["save-if with inner spaces passes"]),
    "coverage-feature-on-pin": (
        '    (COVERAGE_WORKFLOW, "coverage-on"): (COVERAGE_CONDITION, (COVERAGE_ON_COMMAND,)),\n', "",
        ["feature-on measurement without mainnet-write"]),
    "coverage-trigger-reopened": (
        'COVERAGE_EVENTS = ("opened", "synchronize", "reopened")',
        'COVERAGE_EVENTS = ("opened", "synchronize")',
        ["coverage pull_request trigger without reopened"]),
    "coverage-trigger-extras": (
        "if any(event not in COVERAGE_EVENTS for event in types) or len(types) != len(set(map(str, types))):",
        "if False:",
        ["coverage edited added", "coverage labeled added", "coverage duplicate event"]),
    "coverage-attempt-name": (
        'if inputs.get("name") not in names:', "if False:",
        ["coverage upload with a fixed name", "coverage download with a fixed name",
         "coverage download of another attempt"]),
    "coverage-attempt-pattern": (
        'COVERAGE_SELECTION_INPUTS = ("pattern", "merge-multiple")', 'COVERAGE_SELECTION_INPUTS = ("merge-multiple",)',
        ["coverage download by pattern"]),
    "coverage-attempt-merge": (
        'COVERAGE_SELECTION_INPUTS = ("pattern", "merge-multiple")', 'COVERAGE_SELECTION_INPUTS = ("pattern",)',
        ["coverage download that merges reports"]),
    "wasm-save-push": ("if condition != WASM_SAVE_CONDITION:", "if False:", ["Wasm save on pull requests"]),
    "wasm-save-target": (
        "if condition != WASM_SAVE_CONDITION:",
        "if condition not in (WASM_SAVE_CONDITION, WASM_SAVE_CONDITION.replace(\"'schedule')\", "
        "\"'schedule' || github.event_name == 'pull_request_target')\")):",
        ["Wasm save on pull request targets"]),
    "wasm-save-dispatch": (
        "if condition != WASM_SAVE_CONDITION:",
        "if condition not in (WASM_SAVE_CONDITION, WASM_SAVE_CONDITION.replace(\"'schedule')\", "
        "\"'schedule' || github.event_name == 'workflow_dispatch')\")):",
        ["Wasm save on dispatch"]),
    "wasm-save-schedule": (
        "if condition != WASM_SAVE_CONDITION:",
        "if condition not in (WASM_SAVE_CONDITION, WASM_SAVE_CONDITION.replace("
        "\"(github.event_name == 'push' || github.event_name == 'schedule')\", \"github.event_name == 'push'\")):",
        ["Wasm save on pushes only"]),
    "wasm-save-exact": (
        "if condition != WASM_SAVE_CONDITION:", 'if not condition.startswith(guard + " && "):',
        ["Wasm save outside pull requests only"]),
    "wasm-save-combined": (
        'elif not re.match(r"actions/cache/restore@", uses, re.IGNORECASE):', "elif False:",
        ["Wasm combined cache action"]),
    "wasm-save-unwrap": (
        "if condition != WASM_SAVE_CONDITION:", 'if str(step.get("if", "")) != WASM_SAVE_CONDITION:',
        ["Wasm save guard wrapped in ${{ }} passes"]),
}


COUNT_CASES = [
    ("exact violation count rejects extra violations",
     "fixture.yml: rehearsal-credentials: first\n"
     "fixture.yml: rehearsal-credentials: second\n"
     "2 workflow invariant violation(s)\n",
     1, "2 violations, expected exactly 1"),
]


MUTATIONS.update({
    "S-selection-jobs": (
        "self.report(workflow, \"selftest-selection\", f\"{name} must run after changes even on failure\")", "pass",
        ["S08 job feature-discipline needs","S08 job release-contracts failure","S08 job release-contracts errors"]),
    "S-checks": (
        "self.report(workflow, \"selftest-checks\", f\"{name}: check steps must be unconditional\")", "pass",
        ["S07 check feature-discipline","S07 check release-contracts","S07 check install-surface"]),
    "S-groups": (
        "if len(groups) != 1 or not groups.issubset(SELFTEST_GROUPS):", "if False:",
        ["S09 unknown test","S11 mixed groups"]),
    "S-conditions": (
        "if step.get(\"if\") != f\"{prefix}.outputs.selftest_{group} != 'false'\":", "if False:",
        ["S06 condition ci.yml Self-test feature discipline and assertions","S06 condition ci.yml Self-test the publish tier check","S06 condition install-surface.yml Self-test the preflight","S06 condition ci.yml Self-test the run evidence check","S18 inverted false","S19 unknown group"]),
    "S-mixed": (
        "self.report(workflow, \"selftest-checks\", f\"{name}: self-tests must be separate and fail on errors\")", "pass",
        ["S12 mixed check","S13 selftest errors","S14 selftest suppression"]),
    "S-inventory": (
        "if seen != set(commands):", "if False:",
        ["S10 missing test"]),
    "S-selector": (
        "self.report(workflow, \"selftest-selector\", \"full checkout must immediately precede the named selector\")", "pass",
        ["S15 depth","S15 checkout","S15 selector id","S15 name","S15 selector skip","S15 selector error","S15 env","S15 command"]),
    "S-output": (
        "or job.get(\"outputs\") != outputs):", "): ",
        ["S16 output scripts","S16 output rust","S16 output docs","S16 output preflight"]),
})


MUTATIONS["S-selector"][2].extend(["S20 empty steps", "S21 checkout only", "S22 conditional checkout", "S23 selector order"])
MUTATIONS.update({
    "S-empty-steps": ("checkout = steps[0] if steps else {}", "checkout = steps[0]", ["S20 empty steps"]),
    "S-short-steps": ("selector = steps[1] if len(steps) > 1 else {}", "selector = steps[1]", ["S21 checkout only"]),
})


MEASURE = ("github.event_name != 'pull_request' || github.base_ref == 'main' || "
           "!(needs.changes.result == 'success' && needs.changes.outputs.docs_only == 'true') || "
           "contains(github.event.pull_request.labels.*.name, 'coverage')")
for name, clause in (
        ("main", "github.base_ref == 'main' || "),
        ("uncertain", "!(needs.changes.result == 'success' && needs.changes.outputs.docs_only == 'true') || "),
        ("label", " || contains(github.event.pull_request.labels.*.name, 'coverage')")):
    MUTATIONS[f"S-measure-{name}"] = (
        f'COVERAGE_LABEL = "{MEASURE}"', f'COVERAGE_LABEL = "{MEASURE.replace(clause, "")}"',
        [f"S05 measure {name}"])
MUTATIONS.update({
    "S-inverted-false": (
        "if step.get(\"if\") != f\"{prefix}.outputs.selftest_{group} != 'false'\":",
        "if step.get(\"if\") != f\"{prefix}.outputs.selftest_{group} == 'true'\":",
        ["S18 inverted false"]),
    "S-classifier-command": (
        "                command += '\\npython3 .github/scripts/classify-self-tests.py >> \"$GITHUB_OUTPUT\"'\n",
        "", ["S17 classifier command"]),
    "S-known-groups": (
        "not groups.issubset(SELFTEST_GROUPS)", "None in groups", ["S28 unknown registry group rejected"]),
    "S-check-may-skip": (
        "if self.may_skip(step) and not archive:", 'if "if" in step and "run" in step and not archive:',
        [f"S{number} {kind} {job}" for number, kind in ((24, "check errors"), (25, "setup condition"))
         for job in ("feature-discipline", "release-contracts", "install-surface")]),
    "S-mixed-commands": (
        "any(line not in tests", 'any(".github/scripts/" in line and line not in tests',
        ["S26 moved actionlint", "S26 moved cargo fetch"]),
    "S-archive-owner": (
        'archive = (owner == "ci.yml:release-contracts"\n                               and step.get("name") == "Check the skill archive")',
        'archive = (step.get("name") == "Check the skill archive")',
        ["S27 archive name in another job"]),
    "S-archive-exception": (
        "if self.may_skip(step) and not archive:", "if self.may_skip(step):",
        ["wrapped skill archive condition passes"]),
})
MUTATIONS["S-mixed"][2].extend(["S26 moved actionlint", "S26 moved cargo fetch", "S26 moved script"])


# Each evidence case changes one property and requires exactly its own rule.
EVIDENCE_PROPERTIES = [
    ("needs", "    needs: verify\n", "    needs: verify-install\n",
     "release-evidence must need exactly verify"),
    ("runner", "    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-22.04\n",
     "release-evidence must run on ubuntu-24.04"),
    ("permissions", "      actions: read\n", "",
     "release-evidence permissions must be contents: read and actions: read"),
    ("id-token", "      actions: read\n", "      actions: read\n      id-token: write\n",
     "release-evidence permissions must be contents: read and actions: read"),
    ("environment", "    needs: verify\n", "    needs: verify\n    environment: crates-io\n",
     "release-evidence must run unconditionally without an environment or secrets"),
    ("verify-only", "    needs: verify\n", "    needs: verify\n    if: ${{ !inputs.verify_only }}\n",
     "release-evidence must run unconditionally without an environment or secrets"),
    ("step-if", "      - name: Require the verified checkout\n",
     "      - name: Require the verified checkout\n        if: false\n", "release-evidence template:"),
    ("cargo", '          [ "$(git rev-parse HEAD)" = "$SOURCE_SHA" ]',
     '          cargo --version\n          [ "$(git rev-parse HEAD)" = "$SOURCE_SHA" ]',
     "release-evidence template:"),
    ("compile", '          [ "$(git rev-parse HEAD)" = "$SOURCE_SHA" ]',
     '          make\n          [ "$(git rev-parse HEAD)" = "$SOURCE_SHA" ]',
     "release-evidence template:"),
    ("toolchain", "      - name: Require the verified checkout\n",
     "      - uses: dtolnay/rust-toolchain@" + PLACEHOLDER_REVISION + "\n        with:\n          toolchain: ${{ env.RELEASE_TOOLCHAIN }}\n"
     "      - name: Require the verified checkout\n", "release-evidence template:"),
    ("checkout", "          ref: ${{ needs.verify.outputs.sha }}\n", "          ref: ${{ github.sha }}\n",
     "release-evidence template:"),
    ("run-id", "${{ steps.release.outputs.run_id }}", "${{ github.run_id }}",
     "release-evidence template:"),
    ("run-attempt", "${{ steps.release.outputs.run_attempt }}", "${{ github.run_attempt }}",
     "release-evidence template:"),
    ("timeout", "    timeout-minutes: 15\n", "    timeout-minutes: 16\n",
     "release-evidence must time out after 15 minutes"),
    ("cross", '          [ "$(git rev-parse HEAD)" = "$SOURCE_SHA" ]',
     '          cross check\n          [ "$(git rev-parse HEAD)" = "$SOURCE_SHA" ]',
     "release-evidence template:"),
    ("cosign-pin", "sigstore/cosign-installer@756fe2d284c7292c4e9b62c8a28f1e5629c59532",
     "sigstore/cosign-installer@" + PLACEHOLDER_REVISION, "release-evidence template:"),
    ("cosign-version", "cosign-release: v3.1.4", "cosign-release: v3.1.3", "release-evidence template:"),
]
for name, old, new, message in EVIDENCE_PROPERTIES:
    assert PUBLISH_EVIDENCE.count(old) == 1, name
    label = "evidence " + name
    CASES.append((label, "publish-release-evidence", message,
                  [(PUBLISH, PUBLISH_EVIDENCE, PUBLISH_EVIDENCE.replace(old, new), 1)]))
CASES.append(("evidence dependency", "publish-release-evidence", "publish must need release-evidence",
              [(PUBLISH, "needs: [verify, release-evidence]", "needs: [verify]", 1)], 1))
CASES.append(("evidence publish condition", "publish-release-evidence", "publish must run exactly on !inputs.verify_only",
              [(PUBLISH, "    if: ${{ !inputs.verify_only }}\n", "", 1)], 1))
MUTATIONS["evidence-publish-condition"] = (
    '        if (self.job(workflow, "publish") or {}).get("if") != "${{ !inputs.verify_only }}":',
    '        if False:', ["evidence publish condition"])
MUTATIONS["evidence-credential-scope"] = (
    ' and (workflow, job_id) != ("publish.yml", "release-evidence")', '', ["evidence environment"])
MUTATIONS["evidence-call"] = ('        self.check_publish_release_evidence()\n', '', ["evidence dependency"])
PASSING.append(("evidence needs list passes", [
    (PUBLISH, PUBLISH_EVIDENCE, PUBLISH_EVIDENCE.replace("    needs: verify\n", "    needs: [verify]\n"), 1)]))


EVIDENCE_COMMANDS = (
    '[ "$(git rev-parse HEAD)" = "$SOURCE_SHA" ]',
    'echo "RELEASE_DIR=$RUNNER_TEMP/release-evidence" >> "$GITHUB_ENV"',
    'python3 .github/scripts/check-run-evidence.py --mode release --repository "$GITHUB_REPOSITORY" --sha "$SOURCE_SHA" --tag "$TAG" --wait-minutes 0 --poll-seconds 0',
    'mkdir -p "$RELEASE_DIR"/{all-artifacts,release-combined,all-signatures,provenance}',
    'gh release view "$TAG" --repo "$GITHUB_REPOSITORY" --json isDraft,assets > "$RELEASE_DIR/release.json"',
    '[ "$(jq -r .isDraft "$RELEASE_DIR/release.json")" = false ]',
    'gh release download "$TAG" --repo "$GITHUB_REPOSITORY" --pattern SHA256SUMS --dir "$RELEASE_DIR/release-combined"',
    'jq -e --rawfile sums "$RELEASE_DIR/release-combined/SHA256SUMS" --arg provenance "stellar-agent-${TAG#v}.intoto.jsonl" \'($sums | split("\\n") | map(select(length > 0) | .[66:])) as $archives | .isDraft == false and ($archives | length) == 5 and ([.assets[].name] | sort) == (($archives + ["SHA256SUMS"] + (($archives + ["SHA256SUMS"]) | map(. + ".sigstore.json")) + [$provenance]) | sort)\' "$RELEASE_DIR/release.json"',
    'gh release download "$TAG" --repo "$GITHUB_REPOSITORY" --pattern \'*.tar.xz\' --pattern \'*.zip\' --dir "$RELEASE_DIR/all-artifacts"',
    'gh release download "$TAG" --repo "$GITHUB_REPOSITORY" --pattern \'*.sigstore.json\' --dir "$RELEASE_DIR/all-signatures"',
    'gh release download "$TAG" --repo "$GITHUB_REPOSITORY" --pattern \'*.intoto.jsonl\' --dir "$RELEASE_DIR/provenance"',
    'bash .github/scripts/release/verify-signatures.sh "$RELEASE_DIR" "https://github.com/$GITHUB_REPOSITORY/.github/workflows/release.yml@refs/tags/$TAG" https://token.actions.githubusercontent.com "$SOURCE_SHA"',
    'shopt -s nullglob dotglob',
    'verifier="$RUNNER_TEMP/slsa-verifier"',
    'curl --proto \'=https\' --tlsv1.2 --fail --silent --show-error --location https://github.com/slsa-framework/slsa-verifier/releases/download/v2.7.1/slsa-verifier-linux-amd64 --output "$verifier"',
    'echo "946dbec729094195e88ef78e1734324a27869f03e2c6bd2f61cbc06bd5350339 $verifier" | sha256sum --check --strict',
    'chmod +x "$verifier"',
    'provenance=("$RELEASE_DIR"/provenance/*.intoto.jsonl)',
    '[ "${#provenance[@]}" -eq 1 ]',
    'for archive in "$RELEASE_DIR"/all-artifacts/*; do "$verifier" verify-artifact "$archive" --provenance-path "${provenance[0]}" --source-uri "github.com/$GITHUB_REPOSITORY" --source-tag "$TAG" --builder-id https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0; done',
    'python3 .github/scripts/check-provenance.py "${provenance[0]}" "$RELEASE_DIR/release-combined/SHA256SUMS" "$SOURCE_SHA" "$GITHUB_REPOSITORY" "refs/tags/$TAG" --run-id "$RELEASE_RUN_ID" --run-attempt "$RELEASE_RUN_ATTEMPT"',
    'bash .github/scripts/rebuild-vendored-wasm.sh --check-tree --repo-root "$GITHUB_WORKSPACE"',
)

# Each command is independently removed, quoted, prefixed, commented, or bypassed.
import yaml


def evidence_job_edit(change):
    job = yaml.safe_load(PUBLISH_EVIDENCE)["release-evidence"]
    change(job)
    return "\n".join("  " + line for line in yaml.safe_dump({"release-evidence": job}, sort_keys=False).splitlines()) + "\n\n"


def command_edit(job, command, variant):
    for step in job["steps"]:
        lines = [re.sub(r"[ \t]+", " ", line.strip()) for line in
                 re.sub(r"\\\n", " ", step.get("run", "")).splitlines()]
        if command not in lines:
            continue
        if variant == "shell":
            step["shell"] = "sh"
        elif variant == "condition":
            step["if"] = False
        else:
            changed = {"missing": "true", "echo": "echo " + repr(command),
                       "prefix": "false && " + command, "comment": "# " + command}[variant]
            step["run"] = "\n".join(changed if line == command else line for line in lines)
        return
    raise AssertionError(command)


for number, command in enumerate(EVIDENCE_COMMANDS):
    for variant in ("missing", "echo", "prefix", "comment", "shell", "condition"):
        label = f"evidence command-{number}-{variant}"
        edited = evidence_job_edit(lambda job: command_edit(job, command, variant))
        CASES.append((label, "publish-release-evidence", "release-evidence template:",
                      [(PUBLISH, PUBLISH_EVIDENCE, edited, 1)]))

for name, addition, message in (
    ("secret", {"env": {"EXTRA": "${{ secrets.RELEASE_KEY }}"}}, "an expression reads secrets"),
    ("token-expression", {"env": {"EXTRA": "${{ github.token }}"}}, "an expression reads the workflow token"),
    ("github-context", {"env": {"EXTRA": "${{ toJson(github) }}"}}, "an expression reads the github context"),
    ("token-key", {"env": {"${{ github.token }}": "value"}}, "an expression reads the workflow token"),
    ("malformed-expression", {"env": {"EXTRA": "${{ github.token"}}, "unterminated expression"),
    ("token-variable", {"env": {"GH_TOKEN": "literal"}}, "release-evidence sets forbidden token variable GH_TOKEN"),
    ("other-token", {"env": {"GITHUB_TOKEN": "literal"}}, "release-evidence sets forbidden token variable GITHUB_TOKEN"),
):
    label = "evidence credential-" + name
    edited = evidence_job_edit(lambda job: job["steps"].append(dict(name="Extra", run="true", **addition)))
    CASES.append((label, "publish-release-evidence", message, [(PUBLISH, PUBLISH_EVIDENCE, edited, 1)]))
    if "variable" in message:
        needle = '                if str(key).upper() in TOKEN_ENV:\n                    self.report(workflow, rule, f"release-evidence'
        replacement = '                if False:\n                    self.report(workflow, rule, f"release-evidence'
    else:
        needle = '        self.check_credential_expressions(workflow, {"release-evidence": scanned, **inherited}, rule)\n'
        replacement = ""
    MUTATIONS[label] = (needle, replacement, [label])

for name, change, message in (
    ("api-secret", lambda j: j["steps"][2]["env"].update(EXTRA="${{ secrets.RELEASE_KEY }}"),
     "an expression reads secrets"),
    ("api-token-value", lambda j: j["steps"][2]["env"].update(GH_TOKEN="${{ secrets.RELEASE_KEY }}"),
     "an expression reads secrets"),
    ("non-api-token", lambda j: j["steps"][-1].update(env={"GH_TOKEN": "${{ github.token }}"}),
     "an expression reads the workflow token"),
    ("job-token", lambda j: j["env"].update(GH_TOKEN="literal"), "release-evidence sets forbidden token variable"),
    ("job-secret", lambda j: j["env"].update(EXTRA="${{ secrets.RELEASE_KEY }}"), "an expression reads secrets"),
):
    label = "evidence credential-" + name
    CASES.append((label, "publish-release-evidence", message,
                  [(PUBLISH, PUBLISH_EVIDENCE, evidence_job_edit(change), 1)]))
    needle = ('        self.check_credential_expressions(workflow, {"release-evidence": scanned, **inherited}, rule)\n'
              if "expression" in message else
              '                if str(key).upper() in TOKEN_ENV:\n                    self.report(workflow, rule, f"release-evidence')
    replacement = "" if "expression" in message else needle.replace('str(key).upper() in TOKEN_ENV', 'False')
    MUTATIONS[label] = (needle, replacement, [label])

CASES.append(("evidence build comments refused", "publish-release-evidence", "release-evidence template:", [
    (PUBLISH, PUBLISH_EVIDENCE, PUBLISH_EVIDENCE.replace('          set -euo pipefail',
     '          # cargo cross build rustup\n          set -euo pipefail\t# cargo cross build rustup', 1), 1)]))

for name, change, message in (
    ("command-order", lambda j: j["steps"][-2].update(run=j["steps"][-2]["run"].replace(
        '          ', '').replace('chmod +x "$verifier"\n', '').replace(
            'echo "946dbec', 'chmod +x "$verifier"\necho "946dbec')), "release-evidence template:"),
    ("cosign-missing", lambda j: j["steps"].pop(4), "release-evidence template:"),
    ("cosign-duplicate", lambda j: j["steps"].insert(4, j["steps"][4]), "release-evidence template:"),
):
    label = "evidence " + name
    CASES.append((label, "publish-release-evidence", message,
                  [(PUBLISH, PUBLISH_EVIDENCE, evidence_job_edit(change), 1)]))
PASSING.append(("evidence API tokens pass", []))
MUTATIONS["evidence-api-token-mask"] = ('                del env["GH_TOKEN"]', '                pass', ["evidence API tokens pass"])
CASES.append(("evidence selection-command-missing", "publish-release-evidence",
              "release-evidence template:",
              [(PUBLISH, PUBLISH_EVIDENCE, evidence_job_edit(
                  lambda j: command_edit(j, EVIDENCE_COMMANDS[2], "missing")), 1)]))

for name, change, message in (
    ("selection-id", lambda j: j["steps"][2].pop("id"), "release-evidence template:"),
    ("job-env", lambda j: j["env"].update(EXTRA="value"), "job env must contain exactly TAG and SOURCE_SHA"),
    ("job-sha", lambda j: j["env"].update(SOURCE_SHA="other"), "job env must contain exactly TAG and SOURCE_SHA"),
    ("job-tag", lambda j: j["env"].update(TAG="other"), "job env must contain exactly TAG and SOURCE_SHA"),
    ("selection-env", lambda j: j["steps"][2]["env"].update(EXTRA="value"), "release-evidence template:"),
    ("download-env", lambda j: j["steps"][3]["env"].update(EXTRA="value"), "release-evidence template:"),
    ("api-token-missing", lambda j: j["steps"][2].pop("env"), "release-evidence template:"),
    ("api-token-literal", lambda j: j["steps"][2]["env"].update(GH_TOKEN="literal"), "release-evidence template:"),
    ("download-name", lambda j: j["steps"][3].update(name="Other API step"), "release-evidence template:"),
    ("selection-extra-command", lambda j: j["steps"][2].update(run=j["steps"][2]["run"] + "echo extra\n"), "release-evidence template:"),
    ("download-extra-command", lambda j: j["steps"][3].update(run=j["steps"][3]["run"] + "echo extra\n"), "release-evidence template:"),
    ("checkout-order", lambda j: j["steps"].insert(5, j["steps"].pop(0)), "release-evidence template:"),
    ("cosign-signature-order", lambda j: j["steps"].insert(5, j["steps"].pop(4)), "release-evidence template:"),
    ("cosign-provenance-order", lambda j: j["steps"].insert(6, j["steps"].pop(4)), "release-evidence template:"),
    ("step-suppression", lambda j: j["steps"].append({"run": "set +e"}), "release-evidence template:"),
    ("step-continue", lambda j: j["steps"][-1].update({"continue-on-error": True}), "release-evidence template:"),
    ("job-continue", lambda j: j.update({"continue-on-error": True}), "must run unconditionally without an environment or secrets"),
    ("job-secrets", lambda j: j.update(secrets={}), "must run unconditionally without an environment or secrets"),
    ("job-uses", lambda j: j.update(uses="./.github/workflows/vendored-wasm.yml"), "must run unconditionally without an environment or secrets"),
    ("checkout-duplicate", lambda j: j["steps"].insert(0, j["steps"][0]), "release-evidence template:"),
    ("checkout-missing", lambda j: j["steps"].pop(0), "release-evidence template:"),
):
    label = "evidence " + name
    CASES.append((label, "publish-release-evidence", message,
                  [(PUBLISH, PUBLISH_EVIDENCE, evidence_job_edit(change), 1)]))

for name, command in (("double", 'echo "a # b"; cargo build'),
                      ("single", "echo 'a # b'; cargo build"),
                      ("escaped", r'echo \" "a # b"; cargo build'),
                      ("nested", 'echo "$(echo "a # b")"; make')):
    label = "evidence quoted-comment-" + name
    CASES.append((label, "publish-release-evidence", "release-evidence template:",
                  [(PUBLISH, PUBLISH_EVIDENCE, evidence_job_edit(lambda j, c=command: j["steps"].append({"run": c})), 1)]))

# Live job edits must report the first differing field.
for name, change, message in (
    ("non-api-env", lambda j: j["steps"][1].update(env={"TAG": "other", "SOURCE_SHA": "other", "RELEASE_DIR": "/tmp/other"}),
     "step 2 field env: missing or unexpected"),
    ("renamed-download", lambda j: (j["steps"][3].update(name="Other"), j["steps"][3].pop("env")),
     "step 4 field name: differs"),
    ("api-comment-continuation", lambda j: j["steps"][2].update(run=j["steps"][2]["run"] + "# x \\\nmake\n"),
     "step 3 field run: differs"),
    ("checkout-after-command", lambda j: j["steps"].insert(1, j["steps"].pop(0)),
     "step 1 field uses: missing or unexpected"),
    ("last-step-missing", lambda j: j["steps"].pop(), "step 8 field step: missing"),
    ("extra-step", lambda j: j["steps"].append({"run": "true"}), "step 9 field step: unexpected"),
    ("extra-key", lambda j: j["steps"][1].update(timeout=1), "step 2 field timeout: missing or unexpected"),
    ("run-type", lambda j: j["steps"][-1].update(run=True), "step 8 field run: differs"),
    ("with-type", lambda j: j["steps"][0]["with"].update({"persist-credentials": 0}), "step 1 field with: differs"),
    ("run-inner-space", lambda j: j["steps"][1].update(run=j["steps"][1]["run"].replace("git rev-parse", "git  rev-parse")),
     "step 2 field run: differs"),
    ("run-physical-lines", lambda j: j["steps"][2].update(run=EVIDENCE_COMMANDS[2]), "step 3 field run: differs"),
    ("run-carriage-return", lambda j: j["steps"][1].update(run=j["steps"][1]["run"].replace("\n", "\r\n", 1)),
     "step 2 field run: differs"),
    ("run-line-separator", lambda j: j["steps"][1].update(run=j["steps"][1]["run"].replace("\n", "\u2028", 1)),
     "step 2 field run: differs"),
    ("run-no-break-space", lambda j: j["steps"][1].update(run="\xa0" + j["steps"][1]["run"]),
     "step 2 field run: differs"),
    ("first-difference", lambda j: (j["steps"][1].update(name="Other"), j["steps"][2].pop("id")),
     "step 2 field name: differs"),
):
    label = "evidence " + name
    CASES.append((label, "publish-release-evidence", "release-evidence template: " + message,
                  [(PUBLISH, PUBLISH_EVIDENCE, evidence_job_edit(change), 1)], 1))


def evidence_run_whitespace(job):
    for step in job["steps"]:
        if "run" in step:
            step["run"] = "\n \t\n".join(" \t" + line.strip() + " \t" for line in step["run"].splitlines()) + "\n"


PASSING.append(("evidence run whitespace passes", [
    (PUBLISH, PUBLISH_EVIDENCE, evidence_job_edit(evidence_run_whitespace), 1)]))
# The template control covers every crafted step edit.
MUTATIONS["evidence-template"] = (
    "difference = self.evidence_template_difference(steps)", "difference = None",
    [case[0] for case in CASES if case[1] == "publish-release-evidence" and "release-evidence template:" in case[2]])
for name, needle, replacement, labels in (
    ("step-count", "range(max(len(steps), len(PUBLISH_EVIDENCE_TEMPLATE)))",
     "range(min(len(steps), len(PUBLISH_EVIDENCE_TEMPLATE)))",
     ["evidence last-step-missing", "evidence extra-step"]),
    ("step-number", 'location = f"step {index + 1}"', 'location = f"step {index}"',
     ["evidence first-difference"]),
    ("api-position", "PUBLISH_EVIDENCE_TEMPLATE[index] if index < len(PUBLISH_EVIDENCE_TEMPLATE) else {}",
     "{}", ["evidence API tokens pass"]),
    ("missing-step", 'return f"{location} field step: missing"', "return None", ["evidence last-step-missing"]),
    ("extra-step", 'return f"{location} field step: unexpected"', "return None", ["evidence extra-step"]),
    ("missing-field", 'return f"{location} field {field}: missing or unexpected"', "return None", ["evidence selection-id"]),
    ("extra-field", "dict.fromkeys([*expected, *actual])", "expected", ["evidence extra-key"]),
    ("field-value", "if yaml.safe_dump(value, sort_keys=True) != yaml.safe_dump(wanted, sort_keys=True):",
     "if False:", ["evidence download-name"]),
    ("scalar-types", "yaml.safe_dump(value, sort_keys=True) != yaml.safe_dump(wanted, sort_keys=True)",
     "value != wanted", ["evidence with-type"]),
    ("run-trim", r'line.strip(BLANKS) for line in value.split("\n")', r'line for line in value.split("\n")',
     ["evidence run whitespace passes"]),
    ("run-empty", r'value.split("\n") if line.strip(BLANKS)', r'value.split("\n")', ["evidence run whitespace passes"]),
    ("run-line-boundary", r'value.split("\n") if line.strip(BLANKS)', 'value.splitlines() if line.strip(BLANKS)',
     ["evidence run-carriage-return", "evidence run-line-separator"]),
    ("run-blank-characters", r'line.strip(BLANKS) for line in value.split("\n") if line.strip(BLANKS)',
     r'line.strip() for line in value.split("\n") if line.strip()', ["evidence run-no-break-space"]),
    ("run-normalize", 'if field == "run" and isinstance(value, str):', "if False:", ["evidence API tokens pass"]),
    ("first-field", 'return f"{location} field {field}: differs"', 'continue', ["evidence first-difference"]),
    ("api-token-scope", 'expected.get("env") == RELEASE_EVIDENCE_ENV', "True", ["evidence credential-non-api-token"]),
    ("api-token-value", 'and env.get("GH_TOKEN") == "${{ github.token }}"', 'and "GH_TOKEN" in env',
     ["evidence credential-api-token-value"]),
):
    MUTATIONS["evidence-" + name] = (needle, replacement, labels)

# Job rules have separate controls for each forbidden key.
for name, condition in (
    ("needs", 'job.get("needs") not in ("verify", ["verify"])'),
    ("runner", 'job.get("runs-on") != "ubuntu-24.04"'),
    ("timeout", 'job.get("timeout-minutes") != 15'),
    ("permissions", 'job.get("permissions") != {"contents": "read", "actions": "read"}'),
    ("job-env", 'job.get("env") != PUBLISH_EVIDENCE_ENV'),
):
    MUTATIONS["evidence-" + name] = ("if " + condition + ":", "if False:", ["evidence " + name])
for name, key in (("verify-only", "if"), ("environment", "environment"), ("job-continue", "continue-on-error"),
                  ("job-secrets", "secrets"), ("job-uses", "uses")):
    keys = ("if", "continue-on-error", "environment", "secrets", "uses")
    needle = "(" + ", ".join('"' + item + '"' for item in keys) + ")"
    replacement = "(" + ", ".join('"' + item + '"' for item in keys if item != key) + ")"
    MUTATIONS["evidence-" + name] = (needle, replacement, ["evidence " + name])

CASES.append(("comment continuation exposes cross", "cred-compile", "runs cross: cross build --release", [
    before_sign_macos_tools("      - run: |\n          # x \\\n          cross build --release\n\n")], 1))
MUTATIONS["logical-comment-continuation"] = (
    'uncommented = "\\n".join(line for line in lines if not line.lstrip(BLANKS).startswith("#"))',
    'uncommented = "\\n".join(lines)\n        uncommented = "\\n".join(line for line in re.sub(r"\\\\\\n", " ", uncommented).split("\\n") if not line.lstrip(BLANKS).startswith("#"))',
    ["comment continuation exposes cross"])

EVIDENCE_INHERITED = {
    "evidence inherited token": ({"env": {"GH_TOKEN": "literal"}}, "sets forbidden token variable GH_TOKEN"),
    "evidence inherited secret": ({"env": {"EXTRA": "${{ secrets.RELEASE_KEY }}"}}, "an expression reads secrets"),
    "evidence inherited defaults": ({"defaults": {"run": {"working-directory": "${{ github.token }}"}}},
                                    "an expression reads the workflow token"),
}
for label, (_, message) in EVIDENCE_INHERITED.items():
    CASES.append((label, "publish-release-evidence", message, [], 1))
    needle = ('inherited.get("env"), job.get("env")' if label.endswith("token") else
              'self.check_credential_expressions(workflow, {"release-evidence": scanned, **inherited}, rule)')
    replacement = ('job.get("env")' if label.endswith("token") else
                   'self.check_credential_expressions(workflow, {"release-evidence": scanned}, rule)')
    MUTATIONS[label] = (needle, replacement, [label])


def evidence_inherited_problems(script, label):
    """Check this rule alone because other jobs also reject inherited credentials."""
    import types
    checker = types.ModuleType("workflow_checker")
    exec(compile(script.read_text(), str(script), "exec", dont_inherit=True), checker.__dict__)
    instance = checker.Checker(ROOT)
    instance.docs["publish.yml"] = yaml.safe_load((ROOT / PUBLISH).read_text())
    instance.docs["publish.yml"].update(EVIDENCE_INHERITED[label][0])
    instance.check_publish_release_evidence()
    case = next(case for case in CASES if case[0] == label)
    return case_problems("\n".join(instance.violations), case)


def registry_group_problems(script):
    """A registry typo must fail even when the step selects the same unknown group."""
    import types
    checker = types.ModuleType("workflow_checker")
    exec(compile(script.read_text(), str(script), "exec", dont_inherit=True), checker.__dict__)
    instance = checker.Checker(ROOT)
    for workflow in ("ci.yml", "install-surface.yml"):
        instance.docs[workflow] = instance.load(pathlib.Path(".github/workflows") / workflow)
    commands = checker.SELFTESTS["install-surface.yml:install-surface"]
    for command, group in commands.items():
        if group == "docs":
            commands[command] = "unknown"
    for step in instance.docs["install-surface.yml"]["jobs"]["install-surface"]["steps"]:
        if step.get("if") == "steps.sel.outputs.selftest_docs != 'false'":
            step["if"] = "steps.sel.outputs.selftest_unknown != 'false'"
    instance.check_selftest_selection()
    expected = "install-surface.yml: selftest-selection: install-surface: unknown or mixed self-test group"
    if instance.violations != [expected] * 3:
        return [f"unknown registry group: {instance.violations}, expected three group refusals"]
    return []


decision_env = live_text(COVERAGE, re.compile(r"        id: decision\n        env:\n.*?(?=        run:)", re.DOTALL),
                         "coverage decision environment")
gate_body = live_text(COVERAGE, re.compile(r"^  coverage:\n.*\Z", re.DOTALL | re.MULTILINE), "coverage gate")
CASES.extend([
    ("coverage decision null environment", "coverage-condition", "decision must use the measure expression", [
        (COVERAGE, decision_env, "        id: decision\n        env: null\n", 1)]),
    ("coverage gate without steps", "coverage-condition", "decision must use the measure expression", [
        (COVERAGE, gate_body, gate_body.split("    steps:")[0] + "    steps: []\n", 1)]),
])

for consumer, block in (
        ("checkout", "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n" + COVERAGE_MEASURED_LINE),
        ("download off", COVERAGE_DOWNLOAD_OFF), ("download on", COVERAGE_DOWNLOAD_ON),
        ("floor off", COVERAGE_OFF_FLOORS_STEP), ("floor on", COVERAGE_ON_FLOORS_STEP)):
    label = "coverage " + consumer + " without measured guard"
    rules = ("coverage-condition", "coverage-gate")
    messages = ("must use the measured guard", "consumer must use the measured guard")
    if consumer.startswith("download"):
        rules += ("coverage-gate",)
        messages += ("coverage gate does not download",)
    CASES.append((label, rules, messages, [
        (COVERAGE, block, block.replace(COVERAGE_MEASURED_LINE, ""), 1)]))
    label = "coverage " + consumer + " with wrong guard"
    CASES.append((label, ("coverage-condition", "coverage-gate", "ci-feature-jobs"),
                  ("must use the measured guard", "runs under success()", "coverage step can be bypassed"), [
        (COVERAGE, block, block.replace(COVERAGE_MEASURED_LINE, "        if: success()\n"), 1)]))
    label = "coverage " + consumer + " continues on error"
    CASES.append((label, "ci-feature-jobs", "coverage step can be bypassed", [
        (COVERAGE, block, block.replace(COVERAGE_MEASURED_LINE,
         COVERAGE_MEASURED_LINE + "        continue-on-error: true\n"), 1)]))

CASES.append(("coverage unrelated guarded step", ("coverage-gate", "ci-feature-jobs"),
              ("runs under steps.decision.outputs.measured", "coverage step can be bypassed"), [
    (COVERAGE, COVERAGE_CANCEL_FINAL,
     "      - run: echo unrelated\n" + COVERAGE_MEASURED_LINE + COVERAGE_CANCEL_FINAL, 1)]))
CASES.append(("coverage conditional download", "coverage-gate", "coverage gate does not download", [
    (COVERAGE, COVERAGE_DOWNLOAD_OFF, COVERAGE_DOWNLOAD_OFF.replace(
        COVERAGE_MEASURED_LINE, ""), 1)]))

for name, line in (
        ("measured true output", '          echo "measured=true" >> "$GITHUB_OUTPUT"\n'),
        ("measured false output", '            echo "measured=false" >> "$GITHUB_OUTPUT"\n'),
        ("off skipped check", '            test "$OFF" = skipped\n'),
        ("docs exit", '            exit 0\n'),
        ("measure true check", '          test "$MEASURE" = true\n')):
    CASES.append(("coverage decision without " + name, "coverage-gate",
                  "decision must match the literal template", [(COVERAGE, line, "", 1)]))
CASES.extend([
    ("coverage decision extra line", "coverage-gate", "decision must match the literal template", [
        (COVERAGE, COVERAGE_CANCEL_EARLY, "          echo extra\n" + COVERAGE_CANCEL_EARLY, 1)]),
    ("coverage decision extra environment", "coverage-gate", "result check reads", [
        (COVERAGE, decision_env, decision_env + "          EXTRA: value\n", 1)]),
])
PASSING.extend([
    ("coverage measure expression as written passes", []),
    ("coverage measured guards wrapped passes", [
        (COVERAGE, COVERAGE_MEASURED_LINE,
         "        if: ${{ steps.decision.outputs.measured == 'true' }}\n", 5)]),
])
MUTATIONS.update({
    "coverage-template-id": (
        'first.get("id") != "decision" or first.get("run") != COVERAGE_DECISION_RUN',
        'first.get("run") != COVERAGE_DECISION_RUN', ["coverage decision without id"]),
    "coverage-measure-wrapper": (
        '(first.get("env") or {}).get("MEASURE", "") != COVERAGE_MEASURE',
        'self.unwrap_expression(str((first.get("env") or {}).get("MEASURE", ""))) != self.unwrap_expression(COVERAGE_MEASURE)',
        ["coverage decision bare measure expression"]),
    "coverage-template-run": (
        'first.get("run") != COVERAGE_DECISION_RUN', 'False',
        ["coverage decision without measured true output", "coverage decision without measured false output",
         "coverage decision without off skipped check", "coverage decision without docs exit",
         "coverage decision without measure true check", "coverage decision extra line"]),
    "coverage-consumer-condition": (
        'self.report(workflow, "coverage-condition", "coverage gate checkout, download and floors must use the measured guard")',
        'pass', ["coverage checkout without measured guard"]),
    "coverage-consumer-gate": (
        'self.report(workflow, rule, "coverage gate consumer must use the measured guard")',
        'pass', ["coverage floor off without measured guard"]),
    "coverage-classify-checkout": (
        '("actions/checkout@", "actions/download-artifact@")', '("actions/download-artifact@",)',
        ["coverage checkout without measured guard"]),
    "coverage-classify-download": (
        '("actions/checkout@", "actions/download-artifact@")', '("actions/checkout@",)',
        ["coverage download off without measured guard"]),
    "coverage-classify-floor-off": (
        'for command in (COVERAGE_OFF_FLOORS, COVERAGE_ON_FLOORS)))',
        'for command in (COVERAGE_ON_FLOORS,)))', ["coverage floor off without measured guard"]),
    "coverage-classify-floor-on": (
        'for command in (COVERAGE_OFF_FLOORS, COVERAGE_ON_FLOORS)))',
        'for command in (COVERAGE_OFF_FLOORS,)))', ["coverage floor on without measured guard"]),
    "coverage-classify-unrelated": (
        'return (str(step.get("uses") or "").startswith',
        'return True or (str(step.get("uses") or "").startswith', ["coverage unrelated guarded step"]),
    "coverage-gate-guard-value": (
        'if "if" in step and not (self.coverage_measured_step(step) and self.unwrap_expression(str(step["if"])) == COVERAGE_MEASURED):',
        'if "if" in step and not self.coverage_measured_step(step):', ["coverage checkout with wrong guard"]),
    "coverage-download-guard": (
        'if len(found) != 1 or self.unwrap_expression(str(found[0][1].get("if", ""))) != COVERAGE_MEASURED:',
        'if len(found) != 1:', ["coverage conditional download"]),
    "coverage-feature-guard": (
        'or (self.coverage_measured_step(step) and self.unwrap_expression(str(step["if"])) == COVERAGE_MEASURED))):',
        'or self.coverage_measured_step(step))):', ["coverage checkout with wrong guard"]),
    "coverage-measure-unwrap": (
        '(first.get("env") or {}).get("MEASURE", "") != COVERAGE_MEASURE',
        'self.unwrap_expression(str((first.get("env") or {}).get("MEASURE", ""))) != COVERAGE_MEASURE',
        ["coverage measure expression as written passes"]),
    "coverage-measure-expected-unwrap": (
        '!= COVERAGE_MEASURE):', '!= self.unwrap_expression(COVERAGE_MEASURE)):',
        ["coverage measure expression as written passes"]),
    "coverage-old-gate": (
        'if gate_condition != COVERAGE_GATE_CONDITION:',
        'if gate_condition not in (COVERAGE_GATE_CONDITION, COVERAGE_GATE_CONDITION + f" && ({COVERAGE_LABEL}) && !({COVERAGE_DOCS_SKIP})"):',
        ["coverage gate retains docs-only clause"]),
})
for name, needle in (
        ("condition", 'self.unwrap_expression(str(step.get("if", ""))) != COVERAGE_MEASURED:\n                self.report(workflow, "coverage-condition"'),
        ("consumer", 'self.unwrap_expression(str(step.get("if", ""))) != COVERAGE_MEASURED:\n                self.report(workflow, rule, "coverage gate consumer'),
        ("gate", 'self.unwrap_expression(str(step["if"])) == COVERAGE_MEASURED):'),
        ("download", 'self.unwrap_expression(str(found[0][1].get("if", ""))) != COVERAGE_MEASURED:'),
        ("feature", 'self.unwrap_expression(str(step["if"])) == COVERAGE_MEASURED))):')):
    MUTATIONS["coverage-unwrap-" + name] = (
        needle, needle.replace("self.unwrap_expression(", "str(", 1),
        ["coverage measured guards wrapped passes"])


REHEARSAL_PROBE_SETUP = "      - name: Provide a native Perl for the vendored OpenSSL build (Windows)\n"

# Each environment scope reports each forbidden variable independently.
PROBE_VARIABLES = ("CARGO_BUILD_JOBS", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
                   "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS", "CARGO_PROFILE_DEV_OPT_LEVEL")


def probe_extra_step(run):
    return "      - run: |\n" + "".join("          " + line + "\n" for line in run.split("\n")) + "\n"


for scope, anchor, indent in (
        ("workflow", REHEARSAL_ENV, "  "),
        ("job", REHEARSAL_TIMEOUT, "      "),
        ("probe", "        shell: bash\n", "          ")):
    for variable in PROBE_VARIABLES:
        env = ("" if scope == "workflow" else indent[:-2] + "env:\n") + indent + variable + ": '1'\n"
        old = REHEARSAL_PROBE_STEP if scope == "probe" else anchor
        new = old.replace(anchor, env + anchor) if scope == "probe" else old + env
        CASES.append((f"optimized env {scope} {variable}", "rehearsal-security-probes",
                      f"{scope} env: {variable} must be unset", [(REHEARSAL, old, new, 1)]))

for label, run in (
        ("comment", "# cargo test --test vendored_wasm_release_cfg\n\ntrue"),
        ("inline comment", "cargo test --help # vendored_wasm_release_cfg"),
        ("non-test", "cargo check --test vendored_wasm_release_cfg"),
        ("echo", "echo vendored_wasm_release_cfg"),
        ("target suffix", "cargo test --test vendored_wasm_release_cfg_other"),
        ("semicolon", "cargo test --help; echo vendored_wasm_release_cfg"),
        ("pipe", "cargo test --help | echo vendored_wasm_release_cfg"),
        ("ordinary env", 'echo "OTHER=1" >> "$GITHUB_ENV"'),
        ("env key prefix", 'echo "OTHER_RUSTFLAGS=1" >> "$GITHUB_ENV"'),
        ("other file", 'echo "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true" >> "$OTHER"'),
        ("env comment", '# echo "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true" >> "$GITHUB_ENV"\ntrue')):
    PASSING.append((f"optimized {label} passes", [
        (REHEARSAL, REHEARSAL_PROBE_SETUP, probe_extra_step(run) + REHEARSAL_PROBE_SETUP, 1)]))

PASSING.extend([
    ("optimized wrapped guard passes", [(REHEARSAL, REHEARSAL_PROBE_STEP,
        REHEARSAL_PROBE_STEP.replace("if: matrix.target == 'x86_64-unknown-linux-gnu'",
                                    "if: ${{ matrix.target == 'x86_64-unknown-linux-gnu' }}"), 1)]),
    ("optimized later env passes", [(REHEARSAL, REHEARSAL_PROBE_STEP,
        REHEARSAL_PROBE_STEP + probe_extra_step('echo "RUSTFLAGS=x" >> "$GITHUB_ENV"'), 1)]),
    ("optimized unrelated inherited env passes", [(REHEARSAL, REHEARSAL_ENV,
        REHEARSAL_ENV + "  OTHER: '1'\n  RUSTFLAGS_EXTRA: '1'\n", 1)]),
])
for label, run, variable in (
        ("earlier env", 'echo "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true" >> "$GITHUB_ENV"', PROBE_VARIABLES[3]),
        ("braced env", 'echo "RUSTFLAGS=x" >> "${GITHUB_ENV}"', "RUSTFLAGS"),
        ("powershell env", 'Add-Content $env:GITHUB_ENV "CARGO_ENCODED_RUSTFLAGS=x"', "CARGO_ENCODED_RUSTFLAGS"),
        ("multiline env", 'echo "CARGO_BUILD_JOBS<<EOF" >> "$GITHUB_ENV"', "CARGO_BUILD_JOBS")):
    CASES.append((f"optimized {label}", "rehearsal-security-probes",
                  f"step 7 writes {variable} to GITHUB_ENV before probes", [
        (REHEARSAL, REHEARSAL_PROBE_SETUP, probe_extra_step(run) + REHEARSAL_PROBE_SETUP, 1)]))

CASES.extend([
    ("optimized joined duplicate", "rehearsal-security-probes",
     "expected exactly one optimized security probe step", [(REHEARSAL, REHEARSAL_PROBE_STEP,
        REHEARSAL_PROBE_STEP + probe_extra_step("true; cargo test --test vendored_wasm_release_cfg"), 1)]),
    ("optimized env reports each variable", ("rehearsal-security-probes",) * len(PROBE_VARIABLES),
     tuple(f"workflow env: {key} must be unset" for key in PROBE_VARIABLES), [(REHEARSAL, REHEARSAL_ENV,
        REHEARSAL_ENV + "".join(f"  {key}: '1'\n" for key in PROBE_VARIABLES), 1)], len(PROBE_VARIABLES)),
])

PROBE_OWNERS = '(("workflow", self.docs[workflow]), ("job", job), ("probe", steps[index]))'
for scope, owner in (("workflow", "self.docs[workflow]"), ("job", "job"), ("probe", "steps[index]")):
    MUTATIONS[f"optimized-owner-{scope}"] = (
        PROBE_OWNERS, PROBE_OWNERS.replace(f'("{scope}", {owner})', f'("{scope}", {{}})'),
        [f"optimized env {scope} CARGO_BUILD_JOBS"])
for variable in PROBE_VARIABLES[:3] + ("CARGO_PROFILE_",):
    needle = 'forbidden = r"(?:CARGO_BUILD_JOBS|RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_PROFILE_\\w*)"'
    MUTATIONS[f"optimized-forbid-{variable}"] = (
        needle, needle.replace(variable, "ALLOWED_" + variable, 1),
        [f"optimized env workflow {PROBE_VARIABLES[3] if variable == 'CARGO_PROFILE_' else variable}"])
MUTATIONS.update({
    "optimized-comment-removal": (
        "for line in self.normalized(self.run_text(step)))]",
        "for line in [line.lstrip('# ') for line in self.run_text(step).splitlines()])]",
        ["optimized comment passes"]),
    "optimized-cargo-test": (
        r'cargo test [^#;&|]*\bvendored_wasm_release_cfg\b',
        r'cargo (?:test|check) [^#;&|]*\bvendored_wasm_release_cfg\b',
        ["optimized non-test passes"]),
    "optimized-inline-comment": (
        r'cargo test [^#;&|]*\bvendored_wasm_release_cfg\b',
        r'cargo test [^;&|]*\bvendored_wasm_release_cfg\b',
        ["optimized inline comment passes"]),
    "optimized-invocation": (
        r'(?:^|[;&|] *)cargo test [^#;&|]*\bvendored_wasm_release_cfg\b',
        r'\bvendored_wasm_release_cfg\b', ["optimized echo passes"]),
    "optimized-guard-unwrap": (
        'self.unwrap_expression(steps[index].get("if", ""))', 'steps[index].get("if", "")',
        ["optimized wrapped guard passes"]),
    "optimized-env-match": (
        'if re.fullmatch(forbidden, str(key)):', 'if False:', ["optimized env probe RUSTFLAGS"]),
    "optimized-env-fullmatch": (
        'if re.fullmatch(forbidden, str(key)):', 'if re.match(forbidden, str(key)):',
        ["optimized unrelated inherited env passes"]),
    "optimized-env-slice": (
        'enumerate(steps[:index])', 'enumerate(steps)', ["optimized later env passes"]),
    "optimized-env-earlier": (
        'enumerate(steps[:index])', 'enumerate([])', ["optimized earlier env"]),
    "optimized-env-path": (
        r'if re.search(r"\$(?:GITHUB_ENV\b|\{GITHUB_ENV\}|env:GITHUB_ENV\b)", line):',
        'if True:', ["optimized other file passes"]),
    "optimized-env-normalized": (
        'for line in self.normalized(self.run_text(step)):\n                if re.search',
        'for line in self.run_text(step).splitlines():\n                if re.search',
        ["optimized env comment passes"]),
    "optimized-env-key": (
        r'for key in re.findall(r"\b(" + forbidden + r")(?==|<<)", line):',
        'for key in ["RUSTFLAGS"]:', ["optimized ordinary env passes"]),
    "optimized-env-dollar": (
        r'GITHUB_ENV\b|\{GITHUB_ENV\}|env:GITHUB_ENV\b',
        r'OTHER_ENV\b|\{GITHUB_ENV\}|env:GITHUB_ENV\b', ["optimized earlier env"]),
    "optimized-env-braces": (
        r'GITHUB_ENV\b|\{GITHUB_ENV\}|env:GITHUB_ENV\b',
        r'GITHUB_ENV\b|\{OTHER_ENV\}|env:GITHUB_ENV\b', ["optimized braced env"]),
    "optimized-env-powershell": (
        r'GITHUB_ENV\b|\{GITHUB_ENV\}|env:GITHUB_ENV\b',
        r'GITHUB_ENV\b|\{GITHUB_ENV\}|env:OTHER_ENV\b', ["optimized powershell env"]),
    "optimized-env-assignment": (r'(?==|<<)', r'(?=<<)', ["optimized earlier env"]),
    "optimized-env-multiline": (r'(?==|<<)', r'(?==)', ["optimized multiline env"]),
    "optimized-command-separator": (r'(?:^|[;&|] *)cargo test', r'^cargo test', ["optimized joined duplicate"]),
    "optimized-target-boundary": (
        r'\bvendored_wasm_release_cfg\b", line)', r'\bvendored_wasm_release_cfg", line)',
        ["optimized target suffix passes"]),
    "optimized-semicolon": (r'[^#;&|]*', r'[^#&|]*', ["optimized semicolon passes"]),
    "optimized-pipe": (r'[^#;&|]*', r'[^#;&]*', ["optimized pipe passes"]),
    "optimized-env-key-boundary": (
        r're.findall(r"\b(" + forbidden', r're.findall(r"(" + forbidden', ["optimized env key prefix passes"]),
    "optimized-env-step-number": ('f"step {earlier + 1} writes {key}', 'f"step {earlier} writes {key}',
                                  ["optimized earlier env"]),
    "optimized-env-each": (
        'for key in (owner.get("env") or {}):', 'for key in list(owner.get("env") or {})[:1]:',
        ["optimized env reports each variable"]),
})


def copy_tree(destination):
    shutil.copytree(ROOT / ".github", destination / ".github")
    shutil.copytree(ROOT / ".config", destination / ".config")
    shutil.copy2(ROOT / "rust-toolchain.toml", destination / "rust-toolchain.toml")
    # A dispatch-only .yaml workflow that the cache-save-if cases edit; the
    # checker reads it as every other workflow outside WORKFLOWS.
    (destination / CACHE_FIXTURE).write_text(CACHE_FIXTURE_TEXT)
    action = destination / ACTION_TOOLCHAIN_FIXTURE
    action.parent.mkdir(parents=True)
    action.write_text(ACTION_TOOLCHAIN_TEXT)


def run_check(root, script=SCRIPT):
    result = subprocess.run([sys.executable, "-B", str(script), str(root)],
                            capture_output=True, text=True, check=False)
    return result.returncode, result.stdout + result.stderr


def entry_problems(root, label, script=SCRIPT):
    """Copies the tree to root, applies the edits of the CASES or PASSING
    entry with this label, runs script and returns its problems."""
    if label in EVIDENCE_INHERITED:
        return evidence_inherited_problems(script, label)
    if label in CHANGELOG_VARIANTS:
        return changelog_group(label, script)
    if label == "S28 unknown registry group rejected":
        return registry_group_problems(script)
    copy_tree(root)
    if label == "missing nextest configuration":
        (root / ".config/nextest.toml").unlink()
    try:
        passing = dict(PASSING)
        if label in passing:
            problems = apply_edits(root, passing[label])
            if not problems:
                rc, output = run_check(root, script)
                if rc != 0:
                    problems.append(f"exit {rc}, expected 0: {output.strip()}")
                problems.extend(changelog_behavior(root, label))
            return problems
        case = next(case for case in CASES if case[0] == label)
        problems = apply_edits(root, case[3])
        if not problems:
            rc, output = run_check(root, script)
            if rc != 1:
                problems.append(f"exit {rc}, expected 1")
            problems.extend(case_problems(output, case))
        return problems
    finally:
        shutil.rmtree(root)


def changelog_group(label, script):
    """Run grouped workflow edits through the checker without writing fixtures."""
    import types
    import yaml
    from unittest.mock import patch
    source = script.read_text()
    ast.parse(source)
    checker = types.ModuleType("workflow_checker")
    exec(compile(source, str(script), "exec", dont_inherit=True), checker.__dict__)
    original = pathlib.Path.read_text
    dump = yaml.safe_dump

    def memory_dump(data, *args, **kwargs):
        # Reuse serialization by complete contents and options across cases.
        # Every checker rule still runs for each variant and mutation.
        key = pickle.dumps((data, args, kwargs))
        if key not in YAML_DUMPS:
            YAML_DUMPS[key] = dump(data, *args, **kwargs)
        return YAML_DUMPS[key]

    problems = []
    for edits in CHANGELOG_VARIANTS[label]:
        texts = {}
        for relative, old, new, expected in edits:
            path = ROOT / relative
            text = texts.get(path, original(path))
            if text.count(old) != expected:
                problems.append(f"{label}: replacement count differs for {old!r}")
                continue
            texts[path] = text.replace(old, new)
            yaml.safe_load(texts[path])
        load = checker.Checker.load
        documents = {path: yaml.safe_load(text) for path, text in texts.items()}

        def memory_load(instance, relative):
            path = instance.root / relative
            if path in documents:
                return documents[path]
            if path not in BASE_DOCUMENTS:
                BASE_DOCUMENTS[path] = load(instance, relative)
            return BASE_DOCUMENTS[path]

        with patch.object(checker.Checker, "load", memory_load), \
                patch.object(yaml, "safe_dump", memory_dump):
            violations = checker.Checker(ROOT).run()
        case = (label, changelog_rule(label), CHANGELOG_MESSAGES[label], [])
        if not violations:
            problems.append("exit 0, expected 1")
        problems.extend(case_problems("\n".join(violations), case))
    if label == "W18":
        problems.extend(changelog_behavior(ROOT, label))
    return problems


def mutation_failures(tmp, selected):
    """Runs each mutation's entries against the mutated copy, which must
    fail them, and against the restored copy, which must pass them."""
    failures = []
    source = SCRIPT.read_text()
    path = pathlib.Path(tmp) / "mutant-check-workflow-invariants.py"
    for name, (needle, replacement, labels) in MUTATIONS.items():
        labels = [label for label in labels if not selected or selected == label]
        if not labels:
            continue
        if source.count(needle) != 1:
            failures.append(f"mutation-{name}: mutation target found {source.count(needle)} times")
            continue
        for phase, text in (("mutation", source.replace(needle, replacement, 1)), ("control", source)):
            ast.parse(text)
            path.write_text(text)
            path.touch()
            if phase == "control":
                assert hashlib.md5(path.read_bytes()).digest() == hashlib.md5(source.encode()).digest(), "restore differs"
            for label in labels:
                problems = entry_problems(pathlib.Path(tmp) / "mutant", label, path)
                if phase == "mutation" and not problems:
                    failures.append(f"mutation-{name}: {label}: passes against the mutated check")
                elif phase == "control" and problems:
                    failures.append(f"control-{name}: {label}: {'; '.join(problems)}")
                else:
                    detail = f": {problems[0].splitlines()[0]}" if problems else ""
                    print(f"ok   {phase}-{name}: {label}{detail}")
            if name.startswith("W") and not selected:
                new_labels = list(CHANGELOG_VARIANTS) + ["W17", "W15 main-only changelog changes pass"]
                actual = [label for label in new_labels if entry_problems(pathlib.Path(tmp) / "isolation", label, path)]
                wanted = labels if phase == "mutation" else []
                if actual != wanted:
                    failures.append(f"{phase}-{name}: isolation fails: {actual}, expected {wanted}")
                else:
                    print(f"ok   {phase}-{name} isolation: {actual}; {len(new_labels)} groups")
    return failures


def apply_edits(root, edits):
    """Applies each edit to the copy at root and returns one problem per edit whose text drifted."""
    problems = []
    for relative, old, new, expected in edits:
        path = root / relative
        text = path.read_text()
        count = text.count(old)
        if count != expected:
            problems.append(f"{relative}: replacement text found {count} times, expected {expected}")
            continue
        path.write_text(text.replace(old, new))
    return problems


def expectations(rule, fragment):
    """Returns the (rule, fragment) pairs a case expects, in output order."""
    if isinstance(rule, str):
        return [(rule, fragment)]
    return list(zip(rule, fragment, strict=True))


def first_unmatched(output, expected):
    """Returns the first expected pair that no line after the previous match holds, or None."""
    position = 0
    for line in output.splitlines():
        if position < len(expected):
            rule, fragment = expected[position]
            if f": {rule}: " in line and fragment in line:
                position += 1
    return expected[position] if position < len(expected) else None


def violation_count_problem(output, exact_count):
    """Returns a problem when the reported violations miss an exact count."""
    count = len(re.findall(r"^.+: [a-z][a-z-]*: ", output, re.MULTILINE))
    if exact_count is not None and count != exact_count:
        return f"{count} violations, expected exactly {exact_count}"
    return None


def case_problems(output, case):
    """Returns problems with a CASES entry's ordered matches and exact
    count.
    """
    _, rule, fragment, _, *count = case
    problems = []
    if case[1] == "publish-release-evidence":
        other = [line for line in output.splitlines() if re.match(r"^.+: [a-z][a-z-]*: ", line)
                 and ": publish-release-evidence: " not in line]
        if other:
            problems.append(f"evidence case fails another rule: {other}")
    missing = first_unmatched(output, expectations(rule, fragment))
    if missing is not None:
        problems.append(f"no {missing[0]} violation with {missing[1]!r} reported in order: {output.strip()}")
    problem = violation_count_problem(output, count[0] if count else None)
    if problem is not None:
        problems.append(problem)
    return problems


def coverage_behavior():
    """Evaluate the actual expressions against an independent event table."""
    import yaml
    doc = yaml.safe_load((ROOT / COVERAGE).read_text())
    problems = []
    compiled = {}

    def evaluate(expression, values, cancelled):
        expression = expression.strip().removeprefix("${{").removesuffix("}}").strip()

        def token(match):
            word = match.group()
            if word.startswith("'"):
                return word
            if word in values:
                return f"values[{word!r}]"
            return {"&&": " and ", "||": " or ", "!": " not ", "null": "None"}.get(word, word)

        if expression not in compiled:
            source = re.sub(r"'[^']*'|[\w.*]+|&&|\|\||!=|!", token, expression)
            compiled[expression] = compile(source.strip(), "<coverage expression>", "eval")
        return eval(compiled[expression], {"__builtins__": {}}, {"values": values, "cancelled": lambda: cancelled,
                    "always": lambda: True, "contains": lambda values, value: value in values})

    def render(template, values, cancelled):
        return re.sub(r"\$\{\{(.*?)\}\}", lambda match: str(evaluate(match.group(1), values, cancelled)), template)

    for event, action, base, docs, result, pr_labels, cancelled in itertools.product(
            ("pull_request", "push", "schedule", "workflow_dispatch"),
            ("opened", "synchronize", "reopened"),
            ("main", "next"), ("true", "false", ""), ("success", "failure", "skipped"),
            ((), ("other",), ("coverage",), ("other", "coverage")), (False, True)):
        if event != "pull_request" and base == "main" and docs == "true":
            continue  # The classifier cannot prove main docs-only.
        proven = result == "success" and docs == "true"
        measure = (event != "pull_request" or base == "main" or not proven or "coverage" in pr_labels)
        measure = measure and not (event == "push" and proven)
        values = {"github.event_name": event, "github.event.action": action, "github.base_ref": base,
                  "github.event.pull_request.labels.*.name": pr_labels, "needs.changes.result": result,
                  "needs.changes.outputs.docs_only": docs, "github.workflow": "Coverage",
                  "github.ref": "refs/pull/1/merge", "github.run_id": 123}
        for job_id, title in (("changes", "changes"), ("coverage-off", "coverage (feature-off)"),
                              ("coverage-on", "coverage (feature-on)"), ("coverage", "coverage")):
            job = doc["jobs"][job_id]
            expected = True if job_id in ("changes", "coverage") else measure and not cancelled
            if job_id == "changes":
                if "if" in job:
                    problems.append("changes: must have no if condition")
                actual = True
            else:
                actual = bool(evaluate(job["if"], values, cancelled))
            if actual != expected:
                problems.append(f"{job_id}: measurement condition differs: {values}, cancelled={cancelled}")
            if job["name"] != title:
                problems.append(f"{job_id}: plain name differs: {values}")
        decision = doc["jobs"]["coverage"]["steps"][0]
        if bool(evaluate(decision["env"]["MEASURE"], values, cancelled)) != measure:
            problems.append(f"coverage decision measurement differs: {values}")
        group = "refs/pull/1/merge" if event == "pull_request" else "123"
        if render(doc["concurrency"]["group"], values, cancelled) != "Coverage-" + group:
            problems.append(f"coverage concurrency differs: {values}")
    return problems


def coverage_decision(case=None):
    """Run the actual decision shell with every result tuple, without actions."""
    step = yaml.safe_load((ROOT / COVERAGE).read_text())["jobs"]["coverage"]["steps"][0]
    problems = []
    modes = {"docs": "false", "measured": "true", "invalid": "unexpected"}
    for label, measure in modes.items():
        if case and case != label:
            continue
        for changes, off, on in itertools.product(("success", "skipped", "failure", "cancelled", ""), repeat=3):
            with tempfile.NamedTemporaryFile() as output:
                result = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", step["run"]],
                    env={**os.environ, "MEASURE": measure, "CHANGES": changes, "OFF": off, "ON": on,
                         "GITHUB_OUTPUT": output.name}, capture_output=True, text=True, check=False)
                measured_output = output.read().decode()
            wanted = "skipped" if label == "docs" else "success"
            success = label != "invalid" and changes == "success" and off == on == wanted
            identity = f"decision-{label} {changes}/{off}/{on}"
            if (result.returncode == 0) != success:
                problems.append(f"{identity}: exit {result.returncode}, expected success={success}")
            if success:
                message = ("The change is docs-only; nothing was measured.\n" if label == "docs"
                           else "feature-off: success, feature-on: success\n")
                if result.stdout != message or measured_output != f"measured={measure}\n":
                    problems.append(f"{identity}: log/output differs: {result.stdout!r}, {measured_output!r}")
            elif measured_output:
                problems.append(f"{identity}: failed decision emitted measured output")
    return problems


# The baseline and these single-field edits pin each test job contract.
TEST_BLOCKS = {
    name: live_text(CI, re.compile(r"^  " + name + r":\n.*?(?=^  (?:[a-z#])|\Z)",
                                  re.DOTALL | re.MULTILINE), name)
    for name in ("test", "test-extra", "feature-on-test", "feature-on-test-extra")
}
PASSING.append(("test-layout baseline", []))
for job, block in TEST_BLOCKS.items():
    edits = {
        "name": block.replace("    name: " + job, "    name: renamed", 1),
        "needs": block.replace("    needs: ", "    needs: other # ", 1),
        "condition": block.replace("!cancelled()", "success()", 1),
        "runner": block.replace("runs-on: ubuntu-24.04", "runs-on: ubuntu-22.04", 1),
        "timeout": block.replace("timeout-minutes: ", "timeout-minutes: 1 # ", 1),
        "continue": block.replace("    steps:", "    continue-on-error: true\n    steps:", 1),
    }
    if job in ("test", "feature-on-test"):
        edits.update({
            "matrix": block.replace("- shard: 3", "- shard: 4"),
            "matrix-type": block.replace("- shard: 1", "- shard: true"),
            "fail-fast-type": block.replace("fail-fast: false", "fail-fast: 0"),
            "fail-fast": block.replace("fail-fast: false", "fail-fast: true"),
            "pin": block.replace("cargo-nextest@0.9.152", "cargo-nextest@0.9.151"),
            "run": block.replace("--profile ci", "--profile default"),
            "cache": block.replace(" && matrix.shard == 1", ""),
            "cache-key": re.sub(r"shared-key: (?:feature-on|test)", "shared-key: other", block),
        })
    if job in ("test-extra", "feature-on-test-extra"):
        edits["restore-only"] = block.replace("save-if: false", "save-if: true")
        edits["command"] = block.replace("run: cargo test", "run: echo cargo test", 1)
        edits["cache-key"] = re.sub(r"shared-key: (?:feature-on|test)", "shared-key: other", block)
    if job == "test-extra":
        for label, needle in (("proof", "--configuration feature-off"), ("friendbot", "--features testnet-helpers"),
                              ("wasm", "--test vendored_wasm_release_cfg"), ("policy", "--doc policy::pin"),
                              ("feature-sets", 'for feature in test-helpers')):
            edits[label] = block.replace(needle, needle + "-wrong")
    if job == "feature-on-test-extra":
        edits["network"] = block.replace("cargo check", "echo cargo check")
        edits["proof"] = block.replace("--configuration feature-on", "--configuration feature-off")
    for rule, edited in edits.items():
        assert edited != block, (job, rule)
        CASES.append((f"test-layout {job} {rule}", "ci-feature-jobs", f"test layout differs: {job}",
                      [(CI, block, edited, 1)]))
MUTATIONS["test-layout-layout"] = (
    'if actual != expected:\n                self.report("ci.yml", "ci-feature-jobs", f"test layout differs: {name}")',
    'if False:\n                self.report("ci.yml", "ci-feature-jobs", f"test layout differs: {name}")',
    [case[0] for case in CASES if case[0].startswith("test-layout ")])
MUTATIONS["test-layout-baseline"] = (
    'if actual != expected:\n                self.report("ci.yml", "ci-feature-jobs", f"test layout differs: {name}")',
    'if True:\n                self.report("ci.yml", "ci-feature-jobs", f"test layout differs: {name}")',
    ["test-layout baseline"])
MUTATIONS["test-layout-scalar-types"] = (
    'actual = yaml.safe_dump(self.job("ci.yml", name), sort_keys=True)\n            expected = yaml.safe_dump(expected, sort_keys=True)',
    'actual = self.job("ci.yml", name)',
    ["test-layout feature-on-test matrix-type", "test-layout feature-on-test fail-fast-type"])


SHARD_SAVE_LINE = CACHE_SAVE_LINE.replace(" == 'push' ", " == 'push' && matrix.shard == 1 ")
CASES.append(("test-layout cache other workflow", "cache-save-if", "rust-cache saves on pull request runs", [
    (CACHE_FIXTURE, CACHE_FIXTURE_TEXT,
     cache_fixture("[pull_request]").replace("  fixture:", "  feature-on-test:").replace(
         UNGUARDED_CACHE_STEP, UNGUARDED_CACHE_STEP + "        with:\n" + SHARD_SAVE_LINE), 1)]))
CASES.append(("test-layout cache other job", "cache-save-if", "ci.yml:clippy step", [
    (CI, CI_CLIPPY_CACHE, CI_CLIPPY_CACHE.replace(CACHE_SAVE_LINE, SHARD_SAVE_LINE), 1)]))
MUTATIONS["test-layout-cache-workflow"] = (
    'if source.name == "ci.yml" and name in ("test", "feature-on-test")',
    'if name in ("test", "feature-on-test")', ["test-layout cache other workflow"])
MUTATIONS["test-layout-cache-job"] = (
    'if source.name == "ci.yml" and name in ("test", "feature-on-test")',
    'if source.name == "ci.yml"', ["test-layout cache other job"])
MUTATIONS["test-layout-cache-value"] = (
    'CACHE_SAVE_CONDITION + " && matrix.shard == 1"', 'CACHE_SAVE_CONDITION', ["test-layout baseline"])


for name in ("feature-on-clippy", "feature-on-doc"):
    block = live_text(CI, re.compile(r"^  " + name + r":\n.*?(?=^  [a-z])", re.M | re.S), name)
    for label, changed in (
            ("key", block.replace("shared-key: feature-on", "shared-key: other")),
            ("writer", block.replace("save-if: false", "save-if: ${{ github.event_name == 'push' }}"))):
        CASES.append((f"test-layout {name} cache {label}", "cache-save-if", "must only restore the shared cache",
                      [(CI, block, changed, 1)]))
MUTATIONS["test-layout-lint-doc-cache"] = (
    'if (step.get("with") or {}).get("shared-key") != "feature-on" or value is not False:',
    'if False:', [f"test-layout {name} cache {label}" for name in ("feature-on-clippy", "feature-on-doc")
                  for label in ("key", "writer")])


PASSING.append(("test-layout lint cache other workflow", [
    (CACHE_FIXTURE, CACHE_FIXTURE_TEXT,
     cache_fixture("[pull_request]").replace("  fixture:", "  feature-on-doc:").replace(
         UNGUARDED_CACHE_STEP, UNGUARDED_CACHE_STEP + "        with:\n          save-if: false\n"), 1)]))
MUTATIONS["test-layout-lint-cache-scope"] = (
    'if source.name == "ci.yml" and name in ("feature-on-clippy", "feature-on-doc"):',
    'if name in ("feature-on-clippy", "feature-on-doc"):', ["test-layout lint cache other workflow"])
MUTATIONS["test-layout-lint-cache-key"] = (
    'if (step.get("with") or {}).get("shared-key") != "feature-on" or value is not False:',
    'if value is not False:', ["test-layout feature-on-clippy cache key"])
MUTATIONS["test-layout-lint-cache-writer"] = (
    'if (step.get("with") or {}).get("shared-key") != "feature-on" or value is not False:',
    'if (step.get("with") or {}).get("shared-key") != "feature-on":', ["test-layout feature-on-doc cache writer"])


for name in ("feature-on-clippy", "feature-on-doc"):
    block = live_text(CI, re.compile(r"^  " + name + r":\n.*?(?=^  [a-z])", re.M | re.S), name)
    cache = live_text(CI, re.compile(r"^  " + name + r":\n.*?(?=^  [a-z])", re.M | re.S), name)
    cache = re.search(r"      - uses: Swatinem/rust-cache@.*?          save-if: false\n", cache, re.S)[0]
    for label, value in (("missing", ""), ("duplicate", cache + cache)):
        CASES.append((f"test-layout {name} cache {label}", "cache-save-if", "must have one shared cache restore",
                      [(CI, block, block.replace(cache, value), 1)]))
MUTATIONS["test-layout-lint-cache-count"] = (
    "if len(caches) != 1:", "if False:",
    [f"test-layout {name} cache {label}" for name in ("feature-on-clippy", "feature-on-doc")
     for label in ("missing", "duplicate")])


CASES.append(("missing nextest configuration", "ci-feature-jobs", "cannot be read", [], 1))
MUTATIONS["nextest-profile-missing"] = (
    "if profile is not None and profile != NEXTEST_PROFILE:",
    "if profile != NEXTEST_PROFILE:", ["missing nextest configuration"])

NEXTEST_CONFIG = ".config/nextest.toml"
for label, old, new in (
        ("fail-fast", "fail-fast = false", "fail-fast = true"),
        ("retries", "retries = 0", "retries = 1"),
        ("group", "[test-groups]", "[test-groups.serial]\nmax-threads = 1"),
        ("comment", "# Tests that share", "# Suites that share"),
        ("extra-table", "[profile.ci]", "[profile.dev]\nretries = 0\n\n[profile.ci]")):
    CASES.append((f"nextest profile {label}", "ci-feature-jobs", "nextest profile differs",
                  [(NEXTEST_CONFIG, old, new, 1)]))
MUTATIONS["nextest-profile"] = (
    "if profile is not None and profile != NEXTEST_PROFILE:", "if False:",
    [case[0] for case in CASES if case[0].startswith("nextest profile ")])
MUTATIONS["nextest-profile-baseline"] = (
    "if profile is not None and profile != NEXTEST_PROFILE:", "if True:", ["test-layout baseline"])


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--decision-case":
        if sys.argv[2] not in ("docs", "measured", "invalid"):
            print("unknown decision case", file=sys.stderr)
            return 2
        problems = coverage_decision(sys.argv[2])
        for problem in problems:
            print(problem)
        return int(bool(problems))
    if sys.argv[1:] == ["--coverage-behavior"]:
        problems = coverage_behavior()
        for problem in problems[:10]:
            print(problem)
        return int(bool(problems))
    selected = None
    if len(sys.argv) == 3 and sys.argv[1] == '--case':
        selected = sys.argv[2]
        if selected not in [case[0] for case in CASES] + [label for label, _ in PASSING]:
            print('unknown case', file=sys.stderr)
            return 2
    elif len(sys.argv) != 1:
        return 2
    failures = [] if selected else coverage_behavior() + coverage_decision()
    for label, output, exact_count, expected in COUNT_CASES:
        problem = violation_count_problem(output, exact_count)
        if problem != expected:
            failures.append(f"{label}: {problem!r}, expected {expected!r}")
        else:
            print(f"ok   {label}")
    label = "case checks enforce the CASES count field"
    output = ("fixture.yml: rehearsal-credentials: first\n"
              "fixture.yml: rehearsal-credentials: second\n")
    case = (label, "rehearsal-credentials", "first", [], 1)
    problems = case_problems(output, case)
    expected = ["2 violations, expected exactly 1"]
    if problems != expected:
        failures.append(f"{label}: {problems!r}, expected {expected!r}")
    else:
        print(f"ok   {label}")
    with tempfile.TemporaryDirectory() as tmp:
        clean = pathlib.Path(tmp) / "clean"
        copy_tree(clean)
        rc, output = run_check(clean)
        if rc != 0:
            failures.append(f"unmodified tree: exit {rc}: {output.strip()}")
        else:
            print("ok   unmodified tree passes")

        for label in [label for label, _ in PASSING] + [case[0] for case in CASES]:
            if selected and selected != label:
                continue
            problems = entry_problems(pathlib.Path(tmp) / "entry", label)
            if problems:
                failures.append(f"{label}: {'; '.join(problems)}")
            else:
                print(f"ok   {label}")

        failures.extend(mutation_failures(tmp, selected))

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"{len(failures)} workflow invariant case(s) failed", file=sys.stderr)
        return 1
    print("workflow invariant tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
