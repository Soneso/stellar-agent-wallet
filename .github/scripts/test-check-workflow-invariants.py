#!/usr/bin/env python3
"""Offline regression checks for check-workflow-invariants.py.

Copies the workflows, the composite action, and the scripts into a temporary
root. Each failing case applies its edits and must make the check exit 1. For
each rule and message fragment the case expects, in order, a line of its
output after the previous match must name the rule and hold the fragment. The
optional exact-count field also pins the number of reported violations. The
unmodified copy must pass, and so must each copy that a PASSING entry edits
into another accepted form. Each replacement must match the expected number
of times; a case whose text drifted fails. A fixture read from the live
workflows must match exactly once, or the run stops before any case.
"""

import pathlib
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
BUILD_SCRIPT = ".github/scripts/release/build.sh"
PERL_SCRIPT = ".github/scripts/release/windows-perl.ps1"
SODIUM_SCRIPT = ".github/scripts/release/sodium.sh"
ACTION = ".github/actions/macos-sign-notarize/action.yml"
SIGN_SCRIPT = ".github/actions/macos-sign-notarize/sign-notarize.sh"
PUBLISH_SCRIPT = ".github/scripts/publish-crates.sh"
# A full-length commit pin for the actions a case adds; the check matches the
# action name and ignores the revision.
PLACEHOLDER_REVISION = "0" * 40
COVERAGE_CONDITION = "github.event_name != 'pull_request' || contains(github.event.pull_request.labels.*.name, 'coverage')"
COVERAGE_IF_LINE = f"    if: {COVERAGE_CONDITION}\n"
COVERAGE_IF_WRAPPED_LINE = f"    if: ${{{{ {COVERAGE_CONDITION} }}}}\n"
COVERAGE_IF_SPACED_LINE = f'    if: "  {COVERAGE_CONDITION}  "\n'
COVERAGE_TYPES_LINE = "    types: [opened, synchronize, reopened, labeled, unlabeled]\n"
COVERAGE_ON_BLOCK = (
    "on:\n"
    "  pull_request:\n"
    "    branches: [main]\n"
    + COVERAGE_TYPES_LINE +
    "  schedule:\n"
    "    # Weekly, Monday 04:41 UTC.\n"
    "    - cron: '41 4 * * 1'\n"
    "  workflow_dispatch:\n"
)
SIGN_MACOS_FIRST_STEP = (
    "      - name: Check tool paths\n"
    "        run: /bin/bash .github/actions/macos-sign-notarize/check-tools.sh\n"
    "\n"
    "      - name: Validate the release version\n"
)


def before_sign_macos_tools(text):
    return (RELEASE, SIGN_MACOS_FIRST_STEP, text + SIGN_MACOS_FIRST_STEP, 1)


REHEARSAL_TIMEOUT = "    timeout-minutes: 60\n"
REHEARSAL_JOB_PERMISSIONS = "    permissions:\n      contents: read\n    strategy:\n"
REHEARSAL_VERSION_ECHO = '          echo "Rehearsing version: $VERSION"\n'
REHEARSAL_ENV = '  EXPECTED_MAINNET_WRITE: "off"\n'
REHEARSAL_SODIUM_STEP = (
    "      - name: Prefetch libsodium dist (Windows)\n"
    "        if: matrix.target == 'x86_64-pc-windows-msvc'\n"
)
REHEARSAL_EXACT = "expected exactly contents: read"


def in_rehearsal_version_step(line):
    """Adds a line to the run: block of the rehearsal step that reads the
    version.
    """
    return (REHEARSAL, REHEARSAL_VERSION_ECHO, REHEARSAL_VERSION_ECHO + line, 1)


RELEASE_CARGO_BUILD = (
    "cargo build --release --locked --target ${{ matrix.target }} --bin stellar-agent --bin stellar-agent-mcp")
RELEASE_CROSS_BUILD = (
    "cross build --release --locked --target ${{ matrix.target }} --bin stellar-agent --bin stellar-agent-mcp")
SCRIPT_CARGO_BUILD = 'cargo build --release --locked --target "$TARGET" --bin stellar-agent --bin stellar-agent-mcp'
SCRIPT_CROSS_BUILD = 'cross build --release --locked --target "$TARGET" --bin stellar-agent --bin stellar-agent-mcp'
PERL_INSTALL = "  choco install strawberryperl --no-progress -y"
SODIUM_CURL = "  curl --fail --silent --show-error --location --retry 5 --retry-all-errors \\"


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
# Stands in for the verify job's copy of a text while a case edits the
# publish job's copy, and is put back by the last edit of the case.
HELD = "HELD-BY-THE-TEST"


def publish_job_only(old, new):
    """Edits the publish job's copy of a text the verify job also holds."""
    return [(PUBLISH, old, HELD, 2), (PUBLISH, old, new, 1), (PUBLISH, HELD, old, 1)]


# label, [(file, old, new, expected occurrences)];
# the edited copy must pass.
PASSING = [
    ("coverage job condition wrapped in ${{ }} passes", [
        (COVERAGE, COVERAGE_IF_LINE, COVERAGE_IF_WRAPPED_LINE, 1)]),
    ("coverage job condition with surrounding whitespace passes", [
        (COVERAGE, COVERAGE_IF_LINE, COVERAGE_IF_SPACED_LINE, 1)]),
    ("rehearsal job that inherits the workflow permissions passes", [
        (REHEARSAL, REHEARSAL_JOB_PERMISSIONS, "    strategy:\n", 1)]),
    ("rehearsal workflow env with a date and a float passes", [
        (REHEARSAL, REHEARSAL_ENV,
         REHEARSAL_ENV + "  RELEASE_DATE: 2026-10-21\n  RATIO: 1.5\n", 1)]),
    ("rehearsal quoted closing braces without credentials passes", [
        in_rehearsal_version_step("          echo \"${{ format('{0}}}', 'x') }}\"\n")]),
    ("rehearsal quoted expression opener without credentials passes", [
        in_rehearsal_version_step("          echo \"${{ format('}} ${{ github', 'x') }}\"\n")]),
    ("release build line with other whitespace passes", [
        (RELEASE, RELEASE_CARGO_BUILD,
         "cargo  build --release --locked --target ${{matrix.target}}  --bin stellar-agent --bin stellar-agent-mcp", 1)]),
]

# label, expected rule, a fragment that one line naming the rule must hold,
# [(file, old, new, expected occurrences)], optional exact count; each edit
# replaces only the first occurrence. A case that expects several lines gives
# tuples of rules and fragments of the same length, in output order.
CASES = [
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
        (RELEASE, "          persist-credentials: false\n", "          persist-credentials: true\n", 4)]),
    ("checkout without the persist-credentials input", "checkout-credentials",
     'notarize-smoke.yml:build step 1: checkout-credentials: actions/checkout without persist-credentials: false', [
        (SMOKE, "        with:\n          persist-credentials: false\n", "", 2)]),
    ("input interpolated into a run block", "run-inputs",
     'publish.yml:verify step 10 (Build and package every crate): run-inputs: run: reads ${{ inputs.tag }}', [
        (PUBLISH, "        run: cargo package --workspace --locked\n",
         "        run: echo \"${{ inputs.tag }}\" && cargo package --workspace --locked\n", 1)]),
    ("job output interpolated into a credentialed run block", "cred-run-outputs",
     'release.yml:publish step 1 (Validate the release version): cred-run-outputs: run: reads ${{ needs.preflight.outputs.version }}', [
        (RELEASE, 'if [[ "$VERSION" == *-* ]]; then',
         'if [[ "${{ needs.preflight.outputs.version }}" == *-* ]]; then', 1)]),
    ("step output interpolated into a credentialed run block", "cred-run-outputs",
     "publish.yml:publish step 11 (Require the archives to equal the verify job's checksums): cred-run-outputs: run: reads ${{ steps.tag.outputs.version }}", [
        (PUBLISH, '"$RUNNER_TEMP/publish-target/package" "$VERSION"',
         '"$RUNNER_TEMP/publish-target/package" "${{ steps.tag.outputs.version }}"', 1)]),
    ("job output passed to an action in a credentialed job", "cred-with-needs",
     'release.yml:publish step 8 (Create GitHub Release): cred-with-needs: passes needs output to with: tag_name', [
        (RELEASE, "tag_name: v${{ steps.version.outputs.version }}",
         "tag_name: v${{ needs.preflight.outputs.version }}", 1)]),
    ("job output passed to a reusable workflow outside the allowlist", "cred-with-needs",
     'release.yml:attest: cred-with-needs: passes ${{ needs.hashes.outputs.subjects }} to the reusable workflow input base64-subjects', [
        (RELEASE, "  provenance:\n    name: provenance\n", "  attest:\n    name: provenance\n", 1),
        (RELEASE, "needs: [preflight, build, sign-macos, sign, hashes, provenance]",
         "needs: [preflight, build, sign-macos, sign, hashes, attest]", 1)]),
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
     'publish.yml:publish step 8: cred-download-path: downloads to the workspace', [
        (PUBLISH, "          name: verify-sums\n          path: ${{ runner.temp }}/verify\n",
         "          name: verify-sums\n", 1)]),
    ("publish job downloads verify-crates", "verify-crates-download",
     'publish.yml:publish step 8: verify-crates-download: can download verify-crates', [
        (PUBLISH, "          name: verify-sums\n          path: ${{ runner.temp }}/verify\n",
         "          name: verify-crates\n          path: ${{ runner.temp }}/verify\n", 1)]),
    ("publish job downloads by a pattern that matches verify-crates", "verify-crates-download",
     'publish.yml:publish step 8: verify-crates-download: can download verify-crates', [
        (PUBLISH, "          name: verify-sums\n          path: ${{ runner.temp }}/verify\n",
         "          pattern: verify-*\n          path: ${{ runner.temp }}/verify\n", 1)]),
    ("publish job mints the token without the checksum comparison", "credential-order",
     'publish.yml:publish: credential-order: no step before rust-lang/crates-io-auth-action runs compare-crate-sums.py', [
        (PUBLISH, PUBLISH_COMPARE_STEP, "", 1)]),
    ("smoke signing job without a clean-checkout check", "credential-order",
     'notarize-smoke.yml:sign: credential-order: no step before ./.github/actions/macos-sign-notarize runs status --porcelain', [
        (SMOKE, SMOKE_CLEAN_CHECK, 'status=""', 2),
        (SMOKE, SMOKE_CLEAN_CHECK, 'status=""', 1)]),
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
        (PUBLISH, '  RELEASE_TOOLCHAIN: "1.99.0"\n',
         '  RELEASE_TOOLCHAIN: "1.99.0"\n  TAG_RAW: ${{ inputs.tag }}\n', 1)]),
    ("release signing job without the archive validation", "credential-order",
     "release.yml:sign-macos: credential-order: no step before ./.github/actions/macos-sign-notarize "
     "runs validate-input.sh", [
        (RELEASE, SIGN_MACOS_VALIDATE_STEP, "", 1)]),
    ("release signing job without a clean-checkout check", "credential-order",
     "release.yml:sign-macos: credential-order: no step before ./.github/actions/macos-sign-notarize "
     "runs status --porcelain", [
        (RELEASE, SMOKE_CLEAN_CHECK, 'status=""', 2),
        (RELEASE, SMOKE_CLEAN_CHECK, 'status=""', 1)]),
    ("smoke signing job without the archive validation", "credential-order",
     "notarize-smoke.yml:sign: credential-order: no step before ./.github/actions/macos-sign-notarize "
     "runs validate-input.sh", [
        (SMOKE, SMOKE_VALIDATE_STEP, "", 1)]),
    ("publish job checks ancestry only after the token step", "credential-order",
     "publish.yml:publish: credential-order: no step before rust-lang/crates-io-auth-action "
     "runs check-ref-on-main.sh",
     publish_job_only(PUBLISH_ANCESTRY_STEP, "") + [(PUBLISH, PUBLISH_AUTH, PUBLISH_AUTH + PUBLISH_ANCESTRY_STEP, 1)]),
    ("publish job compares the checksums after the token step", "credential-order",
     "publish.yml:publish: credential-order: no step before rust-lang/crates-io-auth-action "
     "runs compare-crate-sums.py", [
        (PUBLISH, PUBLISH_COMPARE_STEP, "", 1),
        (PUBLISH, PUBLISH_AUTH, PUBLISH_AUTH + PUBLISH_COMPARE_STEP, 1)]),
    ("publish job without a clean-checkout check", "credential-order",
     "publish.yml:publish: credential-order: no step before rust-lang/crates-io-auth-action "
     "runs status --porcelain", [
        (PUBLISH, PUBLISH_CLEAN_CHECK, HELD, 3),
        (PUBLISH, PUBLISH_CLEAN_CHECK, 'status=""', 2),
        (PUBLISH, PUBLISH_CLEAN_CHECK, 'status=""', 1),
        (PUBLISH, HELD, PUBLISH_CLEAN_CHECK, 1)]),
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
        (PUBLISH, "ref: refs/tags/${{ steps.tag.outputs.tag }}", "ref: ${{ steps.tag.outputs.tag }}", 2)]),
    ("publish checkout without a ref", "publish-tag-ref",
     "publish.yml:verify step 3: publish-tag-ref: checkout ref '' is neither refs/tags/... nor github.workflow_sha", [
        (PUBLISH, "          ref: ${{ github.workflow_sha }}\n", "", 2)]),
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
     "publish.yml:publish step 6 (Refuse a tag whose commit is not on main): ancestry-check: passes the dispatch commit, not the tag's HEAD", [
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
        (COVERAGE, "    branches: [main]\n" + COVERAGE_TYPES_LINE,
         "    branches: [main]\n    paths: ['**.rs']\n" + COVERAGE_TYPES_LINE, 1)]),
    ("coverage pull_request trigger with a paths-ignore filter", "coverage-trigger", "paths-ignore filter", [
        (COVERAGE, "    branches: [main]\n" + COVERAGE_TYPES_LINE,
         "    branches: [main]\n    paths-ignore: ['**.md']\n" + COVERAGE_TYPES_LINE, 1)]),
    ("coverage pull_request trigger without unlabeled", "coverage-trigger", "lack unlabeled", [
        (COVERAGE, "labeled, unlabeled]", "labeled]", 1)]),
    ("coverage workflow without a pull_request trigger", "coverage-trigger", "trigger is absent", [
        (COVERAGE, "  pull_request:\n    branches: [main]\n" + COVERAGE_TYPES_LINE, "", 1)]),
    ("coverage job without the label condition", "coverage-condition", "label condition", [
        (COVERAGE, COVERAGE_IF_LINE, "", 1)]),
    ("coverage job that always measures", "coverage-condition", "label condition", [
        (COVERAGE, COVERAGE_IF_LINE,
         "    if: true || contains(github.event.pull_request.labels.*.name, 'coverage')\n", 1)]),
    ("coverage job that never measures", "coverage-condition", "label condition", [
        (COVERAGE, COVERAGE_IF_LINE,
         "    if: false && contains(github.event.pull_request.labels.*.name, 'coverage')\n", 1)]),
    ("coverage job without the non-pull-request bypass", "coverage-condition", "label condition", [
        (COVERAGE, COVERAGE_IF_LINE, "    if: contains(github.event.pull_request.labels.*.name, 'coverage')\n", 1)]),
    ("coverage workflow without its coverage job", "coverage-condition", "job coverage not found", [
        (COVERAGE, "  coverage:\n    name: coverage\n", "  measure:\n    name: coverage\n", 1)]),
    ("coverage pull_request trigger in the list shorthand", "coverage-trigger",
     "coverage.yml: coverage-trigger: pull_request types are absent", [
        (COVERAGE, COVERAGE_ON_BLOCK, "on: [pull_request, workflow_dispatch]\n", 1)]),
    ("coverage pull_request trigger in the scalar shorthand", "coverage-trigger",
     "coverage.yml: coverage-trigger: pull_request types are absent", [
        (COVERAGE, COVERAGE_ON_BLOCK, "on: pull_request\n", 1)]),
    ("coverage pull_request trigger without a configuration", "coverage-trigger",
     "coverage.yml: coverage-trigger: pull_request types are absent", [
        (COVERAGE, "  pull_request:\n    branches: [main]\n" + COVERAGE_TYPES_LINE, "  pull_request:\n", 1)]),
    ("coverage pull_request types as a string", "coverage-trigger",
     "coverage.yml: coverage-trigger: pull_request types are absent", [
        (COVERAGE, COVERAGE_TYPES_LINE, "    types: labeled\n", 1)]),
    ("coverage pull_request types as an empty list", ("coverage-trigger",) * 5, (
        "coverage.yml: coverage-trigger: pull_request types lack opened",
        "coverage.yml: coverage-trigger: pull_request types lack synchronize",
        "coverage.yml: coverage-trigger: pull_request types lack reopened",
        "coverage.yml: coverage-trigger: pull_request types lack labeled",
        "coverage.yml: coverage-trigger: pull_request types lack unlabeled"), [
        (COVERAGE, COVERAGE_TYPES_LINE, "    types: []\n", 1)]),
    ("coverage pull_request types missing three events", ("coverage-trigger",) * 3, (
        "coverage.yml: coverage-trigger: pull_request types lack synchronize",
        "coverage.yml: coverage-trigger: pull_request types lack reopened",
        "coverage.yml: coverage-trigger: pull_request types lack unlabeled"), [
        (COVERAGE, COVERAGE_TYPES_LINE, "    types: [opened, labeled]\n", 1)]),
    ("coverage paths filter and a missing condition", ("coverage-trigger", "coverage-condition"), (
        "coverage.yml: coverage-trigger: pull_request trigger has a paths filter",
        "coverage.yml: coverage-condition: coverage job runs without the label condition"), [
        (COVERAGE, "    branches: [main]\n" + COVERAGE_TYPES_LINE,
         "    branches: [main]\n    paths: ['**.rs']\n" + COVERAGE_TYPES_LINE, 1),
        (COVERAGE, COVERAGE_IF_LINE, "", 1)]),
    ("rehearsal job with id-token: write", "rehearsal-credentials",
     "release-rehearsal.yml:build: rehearsal-credentials: the job holds id-token: write", [
        (REHEARSAL, REHEARSAL_JOB_PERMISSIONS,
         "    permissions:\n      contents: read\n      id-token: write\n    strategy:\n", 1)]),
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
         "    permissions:\n      actions: write\n      contents: read\n    strategy:\n", 1)]),
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
        (REHEARSAL, "  build:\n", "  '${{ github.token }}':\n", 1)], 1),
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
    ("build script line that drifts from the release build line", ("release-script-drift", "release-script-drift"), (
        f".github/scripts/release/build.sh: release-script-drift: lacks the release build line: {SCRIPT_CARGO_BUILD}",
        f".github/scripts/release/build.sh: release-script-drift: build line not in the release build job: "
        f"{SCRIPT_CARGO_BUILD} --features extra"), [
        (BUILD_SCRIPT, SCRIPT_CARGO_BUILD, SCRIPT_CARGO_BUILD + " --features extra", 1)]),
    ("build script with a build line the release lacks", "release-script-drift",
     f".github/scripts/release/build.sh: release-script-drift: build line not in the release build job: "
     f"{SCRIPT_CARGO_BUILD} --all-targets", [
        (BUILD_SCRIPT, SCRIPT_CARGO_BUILD + "\n",
         SCRIPT_CARGO_BUILD + "\n  " + SCRIPT_CARGO_BUILD + " --all-targets\n", 1)]),
    ("release build line that drifts from the build script", ("release-script-drift", "release-script-drift"), (
        f".github/scripts/release/build.sh: release-script-drift: lacks the release build line: "
        f"{SCRIPT_CROSS_BUILD} --verbose",
        f".github/scripts/release/build.sh: release-script-drift: build line not in the release build job: "
        f"{SCRIPT_CROSS_BUILD}"), [
        (RELEASE, RELEASE_CROSS_BUILD, RELEASE_CROSS_BUILD + " --verbose", 1)]),
    ("release build job without a build line", "release-script-drift",
     "release.yml:build: release-script-drift: runs no cargo build or cross build line", [
        (RELEASE, RELEASE_CROSS_BUILD, RELEASE_CROSS_BUILD.replace("cross build", "cross check"), 1),
        (RELEASE, RELEASE_CARGO_BUILD, RELEASE_CARGO_BUILD.replace("cargo build", "cargo check"), 1)]),
    ("Perl script that drifts from the release step", "release-script-drift",
     f".github/scripts/release/windows-perl.ps1: release-script-drift: body line 2 is "
     f"{PERL_INSTALL.replace(' --no-progress', '')!r}, the release step that writes OPENSSL_SRC_PERL has "
     f"{PERL_INSTALL!r}", [
        (PERL_SCRIPT, PERL_INSTALL, PERL_INSTALL.replace(" --no-progress", ""), 1)]),
    ("release libsodium step that drifts from the script", "release-script-drift",
     f".github/scripts/release/sodium.sh: release-script-drift: body line 7 is {SODIUM_CURL!r}, the release step "
     f"that writes SODIUM_DIST_DIR has {SODIUM_CURL.replace('--retry 5', '--retry 3')!r}", [
        (RELEASE, "--retry 5 --retry-all-errors", "--retry 3 --retry-all-errors", 1)]),
    ("libsodium script with a line the release step lacks", "release-script-drift",
     ".github/scripts/release/sodium.sh: release-script-drift: body line 11 is 'ls \"$DIST_DIR\"', the release step "
     "that writes SODIUM_DIST_DIR has no line", [
        (SODIUM_SCRIPT, 'echo "SODIUM_DIST_DIR=$DIST_DIR" >> "$GITHUB_ENV"\n',
         'echo "SODIUM_DIST_DIR=$DIST_DIR" >> "$GITHUB_ENV"\nls "$DIST_DIR"\n', 1)]),
    ("release build job without the libsodium step", "release-script-drift",
     "release.yml:build: release-script-drift: 0 steps write SODIUM_DIST_DIR to GITHUB_ENV, expected one", [
        (RELEASE, 'echo "SODIUM_DIST_DIR=$DIST_DIR" >> "$GITHUB_ENV"', 'echo "SODIUM_DIR=$DIST_DIR" >> "$GITHUB_ENV"', 1)]),
    ("release build job with two libsodium writers", "release-script-drift",
     "release.yml:build: release-script-drift: 2 steps write SODIUM_DIST_DIR to GITHUB_ENV, expected one", [
        (RELEASE, '          echo "SODIUM_DIST_DIR=$DIST_DIR" >> "$GITHUB_ENV"\n',
         '          echo "SODIUM_DIST_DIR=$DIST_DIR" >> "$GITHUB_ENV"\n'
         '\n      - name: Set libsodium directory\n'
         '        run: echo "SODIUM_DIST_DIR=$RUNNER_TEMP/sodium-dist" >> "$GITHUB_ENV"\n', 1)]),
]


COUNT_CASES = [
    ("exact violation count rejects extra violations",
     "fixture.yml: rehearsal-credentials: first\n"
     "fixture.yml: rehearsal-credentials: second\n"
     "2 workflow invariant violation(s)\n",
     1, "2 violations, expected exactly 1"),
]


def copy_tree(destination):
    shutil.copytree(ROOT / ".github", destination / ".github")


def run_check(root):
    result = subprocess.run([sys.executable, "-B", str(SCRIPT), str(root)],
                            capture_output=True, text=True, check=False)
    return result.returncode, result.stdout + result.stderr


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
        path.write_text(text.replace(old, new, 1))
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
    missing = first_unmatched(output, expectations(rule, fragment))
    if missing is not None:
        problems.append(f"no {missing[0]} violation with {missing[1]!r} reported in order: {output.strip()}")
    problem = violation_count_problem(output, count[0] if count else None)
    if problem is not None:
        problems.append(problem)
    return problems


def main():
    failures = []
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

        for index, (label, edits) in enumerate(PASSING):
            root = pathlib.Path(tmp) / f"passing{index}"
            copy_tree(root)
            problems = apply_edits(root, edits)
            if not problems:
                rc, output = run_check(root)
                if rc != 0:
                    problems.append(f"exit {rc}, expected 0: {output.strip()}")
            if problems:
                failures.append(f"{label}: {'; '.join(problems)}")
            else:
                print(f"ok   {label}")
            shutil.rmtree(root)

        for index, case in enumerate(CASES):
            label, edits = case[0], case[3]
            root = pathlib.Path(tmp) / f"case{index}"
            copy_tree(root)
            problems = apply_edits(root, edits)
            output = ""
            if not problems:
                rc, output = run_check(root)
                if rc != 1:
                    problems.append(f"exit {rc}, expected 1")
                problems.extend(case_problems(output, case))
            if problems:
                failures.append(f"{label}: {'; '.join(problems)}")
            else:
                print(f"ok   {label}")
            shutil.rmtree(root)

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"{len(failures)} workflow invariant case(s) failed", file=sys.stderr)
        return 1
    print("workflow invariant tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
