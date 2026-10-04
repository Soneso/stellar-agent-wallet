#!/usr/bin/env python3
"""Offline regression checks for check-workflow-invariants.py.

Copies the workflows, the composite action, and the scripts into a temporary
root, then applies one violation per case. The check must fail, and one line
of its output must name the case's rule and hold the case's message fragment.
The unmodified copy must pass. Each replacement must match the expected
number of times; a case whose text drifted fails.
"""

import pathlib
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
ACTION = ".github/actions/macos-sign-notarize/action.yml"
SIGN_SCRIPT = ".github/actions/macos-sign-notarize/sign-notarize.sh"
PUBLISH_SCRIPT = ".github/scripts/publish-crates.sh"

SIGN_MACOS_FIRST_STEP = (
    "      - name: Check tool paths\n"
    "        run: /bin/bash .github/actions/macos-sign-notarize/check-tools.sh\n"
    "\n"
    "      - name: Validate the release version\n"
)


def before_sign_macos_tools(text):
    return (RELEASE, SIGN_MACOS_FIRST_STEP, text + SIGN_MACOS_FIRST_STEP, 1)


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
SIGN_MACOS_DOWNLOAD_STEP = (
    "      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n"
    "        with:\n"
    "          name: unsigned-${{ matrix.target }}\n"
    "          path: ${{ runner.temp }}/unsigned\n"
    "\n"
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


# label, expected rule, a fragment that one line naming the rule must hold,
# [(file, old, new, expected occurrences)]; each edit replaces only the first
# occurrence.
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
    ("rust-cache in the signing job", "cred-compile",
     'release.yml:sign-macos step 2: cred-compile: uses Swatinem/rust-cache@', [before_sign_macos_tools(
        "      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2.9.2\n\n")]),
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
         "  steps:\n    - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2.9.2\n"
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
        "      - uses: dtolnay/rust-toolchain@7e38f4b43b4db5c8dd498af069a4f6196df1d067 # master\n"
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
        "      - uses: actions/cache/restore@0000000000000000000000000000000000000000\n"
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
]


def copy_tree(destination):
    shutil.copytree(ROOT / ".github", destination / ".github")


def run_check(root):
    result = subprocess.run([sys.executable, str(SCRIPT), str(root)],
                            capture_output=True, text=True, check=False)
    return result.returncode, result.stdout + result.stderr


def main():
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        clean = pathlib.Path(tmp) / "clean"
        copy_tree(clean)
        rc, output = run_check(clean)
        if rc != 0:
            failures.append(f"unmodified tree: exit {rc}: {output.strip()}")
        else:
            print("ok   unmodified tree passes")

        for index, (label, rule, fragment, edits) in enumerate(CASES):
            root = pathlib.Path(tmp) / f"case{index}"
            copy_tree(root)
            problems = []
            output = ""
            for relative, old, new, expected in edits:
                path = root / relative
                text = path.read_text()
                count = text.count(old)
                if count != expected:
                    problems.append(f"{relative}: replacement text found {count} times, expected {expected}")
                    continue
                path.write_text(text.replace(old, new, 1))
            if not problems:
                rc, output = run_check(root)
                if rc != 1:
                    problems.append(f"exit {rc}, expected 1")
                if not any(f": {rule}: " in line and fragment in line for line in output.splitlines()):
                    problems.append(f"no {rule} violation with {fragment!r} reported: {output.strip()}")
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
