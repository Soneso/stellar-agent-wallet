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
With --case LABEL, the run checks the unmodified copy and that one failing
case or PASSING entry.
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
CI = ".github/workflows/ci.yml"
BUILD_SCRIPT = ".github/scripts/release/build.sh"
HOST_SCRIPT = ".github/scripts/release/check-host.sh"
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
    "    branches: [main, mainnet-write]\n"
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


REHEARSAL_TIMEOUT = "    timeout-minutes: 120\n"
REHEARSAL_JOB_PERMISSIONS = "    permissions:\n      contents: read\n    strategy:\n"
REHEARSAL_VERSION_ECHO = '          echo "Rehearsing version: $VERSION"\n'
REHEARSAL_ENV = '  EXPECTED_MAINNET_WRITE: "on"\n'
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
                     'target/package-verification-start "$EXPECTED_MAINNET_WRITE"')
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
                        '  RELEASE_TOOLCHAIN: "1.99.0"\n')
REHEARSAL_MARKER_RUN = ('        run: bash .github/scripts/check-packaged-markers.sh target '
                        'target/package-verification-start "$EXPECTED_MAINNET_WRITE"\n')
# The defining command of each feature job of ci.yml, as its run: line.
CI_FEATURE_JOBS = {
    "feature-on-clippy": 'cargo clippy --workspace --all-targets --features "mainnet-write,',
    "feature-on-doc": 'cargo doc --workspace --no-deps --features "mainnet-write,',
    "feature-on-test": "cargo check -p stellar-agent-network --features mainnet-write",
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
    "test": ("  test:\n    name: test (offline)\n",
             "cargo test --workspace --no-default-features --features test-helpers,"),
}
COVERAGE_OFF_RUN = "        run: cargo llvm-cov --workspace --no-default-features --features test-helpers,"
# The host recipe lines that build each binary package alone and check its
# marker.
HOST_SINGLE_CLI = ("cargo build --locked -p stellar-agent-cli\n"
                   "bash .github/scripts/check-binary-marker.sh target/debug/stellar-agent on\n")
HOST_SINGLE_MCP = ("cargo build --locked -p stellar-agent-mcp\n"
                   "bash .github/scripts/check-binary-marker.sh target/debug/stellar-agent-mcp on\n")


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
# Stands in for the verify job's copy of a text while a case edits the
# publish job's copy, and is put back by the last edit of the case.
HELD = "HELD-BY-THE-TEST"


def publish_job_only(old, new):
    """Edits the publish job's copy of a text the verify job also holds."""
    return [(PUBLISH, old, HELD, 2), (PUBLISH, old, new, 1), (PUBLISH, HELD, old, 1)]


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
SAVE_GUARD = "        if: github.ref_type != 'tag' && steps.restore.outputs.cache-hit != 'true'\n"
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


# label, [(file, old, new, expected occurrences)];
# the edited copy must pass.
PASSING = [
    ("wrapped tag cache guard passes", [
        (WASM, TAG_GUARD, "        if: ${{ github.ref_type != 'tag' }}\n", 2)]),
    ("wrapped Wasm rebuild and gate conditions pass", [
        (WASM, WASM_REBUILD_IF,
         "    needs: [check, stellar-cli-25, stellar-cli-28]\n    if: ${{ needs.check.outputs.rebuild == 'true' }}\n", 1),
        (WASM, WASM_GATE_IF, WASM_GATE_NEEDS + "    if: ${{ always() }}\n", 1)]),
    ("Wasm gate needs in another order pass", [
        (WASM, WASM_GATE_NEEDS, "    needs: [rebuild, stellar-cli-28, stellar-cli-25, check]\n", 1)]),
    ("coverage job condition wrapped in ${{ }} passes", [
        (COVERAGE, COVERAGE_IF_LINE, COVERAGE_IF_WRAPPED_LINE, 1)]),
    ("coverage job condition with surrounding whitespace passes", [
        (COVERAGE, COVERAGE_IF_LINE, COVERAGE_IF_SPACED_LINE, 1)]),
    ("rehearsal job that inherits the workflow permissions passes", [
        (REHEARSAL, REHEARSAL_JOB_PERMISSIONS, "    strategy:\n", 2)]),
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
]

# label, expected rule, a fragment that one line naming the rule must hold,
# [(file, old, new, expected occurrences)], optional exact count; each edit
# replaces only the first occurrence. A case that expects several lines gives
# tuples of rules and fragments of the same length, in output order.
CASES = [
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
    ("Wasm rebuild job continues on error", "release-wasm-gate",
     "vendored-wasm.yml:rebuild: release-wasm-gate: rebuild continues on error", [
        (WASM, WASM_REBUILD_JOB, WASM_REBUILD_JOB + "    continue-on-error: true\n", 1)], 1),
    ("Wasm step continues on error", "release-wasm-gate",
     "vendored-wasm.yml:stellar-cli-25: release-wasm-gate: stellar-cli-25 step 1 continues on error", [
        (WASM, "        run: rustup toolchain install \"$HOST_RUSTC\" --profile minimal\n",
         "        run: rustup toolchain install \"$HOST_RUSTC\" --profile minimal\n        continue-on-error: true\n", 2)], 1),
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
        (WASM, "  workflow_call:\n", "", 1)]),
    ("Wasm restore without tag guard", "release-wasm-gate", "cache guard must lead", [
        (WASM, TAG_GUARD, "", 2)]),
    ("Wasm save with trailing tag guard", "release-wasm-gate", "cache guard must lead", [
        (WASM, SAVE_GUARD, "        if: steps.restore.outputs.cache-hit != 'true' && github.ref_type != 'tag'\n", 2)]),
    ("Wasm rebuild cache", "release-wasm-gate", "rebuild uses a cache", [
        (WASM, "      - name: Download stellar-cli 25\n", CACHE_RESTORE + "      - name: Download stellar-cli 25\n", 1)]),
    ("Wasm rebuild missing artifact", "release-wasm-gate", "rebuild does not download vendored-wasm-stellar-cli-25", [
        (WASM, "          name: vendored-wasm-stellar-cli-25\n          path: ${{ runner.temp }}/stellar-cli-artifacts",
         "          name: another-artifact\n          path: ${{ runner.temp }}/stellar-cli-artifacts", 1)]),
    ("release toolchain differs", "release-toolchain", "RELEASE_TOOLCHAIN differs from publish.yml", [
        (RELEASE, '  RELEASE_TOOLCHAIN: "1.99.0"\n', '  RELEASE_TOOLCHAIN: "1.98.0"\n', 1)]),
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
     'publish.yml:verify step 10 (Build and package every crate): run-inputs: run: reads ${{ inputs.tag }}', [
        (PUBLISH, "          cargo package --workspace --locked\n",
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
        (PUBLISH, "ref: refs/tags/${{ steps.tag.outputs.tag }}", "ref: ${{ steps.tag.outputs.tag }}", 3)]),
    ("publish checkout without a ref", "publish-tag-ref",
     "publish.yml:verify step 3: publish-tag-ref: checkout ref '' is neither refs/tags/... nor github.workflow_sha", [
        (PUBLISH, "          ref: ${{ github.workflow_sha }}\n", "", 3)]),
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
        (COVERAGE, "    branches: [main, mainnet-write]\n" + COVERAGE_TYPES_LINE,
         "    branches: [main, mainnet-write]\n    paths: ['**.rs']\n" + COVERAGE_TYPES_LINE, 1)]),
    ("coverage pull_request trigger with a paths-ignore filter", "coverage-trigger", "paths-ignore filter", [
        (COVERAGE, "    branches: [main, mainnet-write]\n" + COVERAGE_TYPES_LINE,
         "    branches: [main, mainnet-write]\n    paths-ignore: ['**.md']\n" + COVERAGE_TYPES_LINE, 1)]),
    ("coverage pull_request trigger without unlabeled", "coverage-trigger", "lack unlabeled", [
        (COVERAGE, "labeled, unlabeled]", "labeled]", 1)]),
    ("coverage workflow without a pull_request trigger", "coverage-trigger", "trigger is absent", [
        (COVERAGE, "  pull_request:\n    branches: [main, mainnet-write]\n" + COVERAGE_TYPES_LINE, "", 1)]),
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
        (COVERAGE, "  pull_request:\n    branches: [main, mainnet-write]\n" + COVERAGE_TYPES_LINE, "  pull_request:\n", 1)]),
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
        (COVERAGE, "    branches: [main, mainnet-write]\n" + COVERAGE_TYPES_LINE,
         "    branches: [main, mainnet-write]\n    paths: ['**.rs']\n" + COVERAGE_TYPES_LINE, 1),
        (COVERAGE, COVERAGE_IF_LINE, "", 1)]),
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
        (REHEARSAL, "  build:\n", "  '${{ github.token }}':\n", 1)], 5),
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
        (RELEASE, "needs: [preflight, provenance, hashes]", "needs: [preflight, hashes]", 1)]),
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
        (REHEARSAL, '  RELEASE_TOOLCHAIN: "1.99.0"\n', '  RELEASE_TOOLCHAIN: "1.98.0"\n', 1)]),
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
    (f"conditional {job}", "ci-feature-jobs", f"ci.yml: ci-feature-jobs: {job} can be bypassed", [
        (CI, f"  {job}:\n    name: {job}\n", f"  {job}:\n    name: {job}\n    if: false\n", 1)])
    for job in CI_FEATURE_JOBS
] + [
    (f"{job} step that continues on error", "ci-feature-jobs", f"ci.yml: ci-feature-jobs: {job} step can be bypassed", [
        (CI, f"        run: {command}", f"        continue-on-error: true\n        run: {command}", 1)])
    for job, command in CI_FEATURE_JOBS.items()
] + [
    ("release-shape that continues on error", "ci-feature-jobs", "ci.yml: ci-feature-jobs: release-shape can be bypassed", [
        (CI, "  release-shape:\n    name: release-shape\n",
         "  release-shape:\n    name: release-shape\n    continue-on-error: true\n", 1)]),
    ("conditional network forwarding check", "ci-feature-jobs", "feature-on-test step can be bypassed", [
        (CI, "        run: cargo check -p stellar-agent-network", "        if: false\n        run: cargo check -p stellar-agent-network", 1)]),
    ("feature-on clippy without mainnet-write", "ci-feature-jobs",
     "ci.yml: ci-feature-jobs: feature-on-clippy does not run unconditionally", [
        (CI, '--features "mainnet-write,$FEATURES_EXCEPT_MAINNET_WRITE" -- -D warnings',
         '--features "$FEATURES_EXCEPT_MAINNET_WRITE" -- -D warnings', 1)]),
    ("host recipe with a marker check in a subshell", "ci-feature-jobs",
     ".github/scripts/release/check-host.sh: ci-feature-jobs: unmodelled shell syntax around", [
        (HOST_SCRIPT, 'bash .github/scripts/check-binary-marker.sh "target/$target/release/stellar-agent-mcp" on\n',
         '( bash .github/scripts/check-binary-marker.sh "target/$target/release/stellar-agent-mcp" on ) || true\n', 1)]),
    ("host recipe without the MCP marker check", "ci-feature-jobs",
     ".github/scripts/release/check-host.sh: ci-feature-jobs: does not run unconditionally", [
        (HOST_SCRIPT, 'bash .github/scripts/check-binary-marker.sh "target/$target/release/stellar-agent-mcp" on\n', "", 1)]),
    ("host recipe that expects the release CLI off", "ci-feature-jobs",
     ".github/scripts/release/check-host.sh: ci-feature-jobs: does not run unconditionally: "
     'bash .github/scripts/check-binary-marker.sh "target/$target/release/stellar-agent" on', [
        (HOST_SCRIPT, '"target/$target/release/stellar-agent" on\n', '"target/$target/release/stellar-agent" off\n', 1)]),
    ("host recipe without the single CLI build", "ci-feature-jobs",
     ".github/scripts/release/check-host.sh: ci-feature-jobs: does not run unconditionally: "
     "cargo build --locked -p stellar-agent-cli", [
        (HOST_SCRIPT, HOST_SINGLE_CLI, "bash .github/scripts/check-binary-marker.sh target/debug/stellar-agent on\n", 1)]),
    ("host recipe that expects the single MCP binary off", "ci-feature-jobs",
     ".github/scripts/release/check-host.sh: ci-feature-jobs: does not run unconditionally: "
     "bash .github/scripts/check-binary-marker.sh target/debug/stellar-agent-mcp on", [
        (HOST_SCRIPT, "target/debug/stellar-agent-mcp on\n", "target/debug/stellar-agent-mcp off\n", 1)]),
    ("host recipe with the single builds in a condition", "ci-feature-jobs",
     ".github/scripts/release/check-host.sh: ci-feature-jobs: does not run unconditionally: "
     "cargo build --locked -p stellar-agent-mcp", [
        (HOST_SCRIPT, HOST_SINGLE_MCP, "if false; then\n" + HOST_SINGLE_MCP + "fi\n", 1)]),
] + [
    (f"conditional {job}", "ci-feature-jobs", f"ci.yml: ci-feature-jobs: {job} can be bypassed", [
        (CI, header, header + "    if: false\n", 1)])
    for job, (header, _) in CI_OFF_JOBS.items()
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
    ("coverage off measurement without --no-default-features", "ci-feature-jobs",
     "coverage.yml: ci-feature-jobs: coverage does not run unconditionally: cargo llvm-cov --workspace "
     "--no-default-features", [
        (COVERAGE, COVERAGE_OFF_RUN, COVERAGE_OFF_RUN.replace(" --no-default-features", ""), 1)]),
    ("coverage off measurement that continues on error", "ci-feature-jobs",
     "coverage.yml: ci-feature-jobs: coverage step can be bypassed", [
        (COVERAGE, COVERAGE_OFF_RUN, "        continue-on-error: true\n" + COVERAGE_OFF_RUN, 1)]),
    ("coverage job that continues on error", "ci-feature-jobs", "coverage.yml: ci-feature-jobs: coverage can be bypassed", [
        (COVERAGE, COVERAGE_IF_LINE, COVERAGE_IF_LINE + "    continue-on-error: true\n", 1)], 1),
    ("coverage job under another condition", ("coverage-condition", "ci-feature-jobs"), (
        "coverage.yml: coverage-condition: coverage job runs without the label condition",
        "coverage.yml: ci-feature-jobs: coverage can be bypassed"), [
        (COVERAGE, COVERAGE_IF_LINE, "    if: false\n", 1)], 2),
    ("coverage workflow without its coverage job for the feature pin", ("coverage-condition", "ci-feature-jobs"), (
        "coverage.yml: coverage-condition: job coverage not found",
        "coverage.yml: ci-feature-jobs: missing coverage"), [
        (COVERAGE, "  coverage:\n    name: coverage\n", "  measure:\n    name: coverage\n", 1)], 2),
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
    selected = None
    if len(sys.argv) == 3 and sys.argv[1] == '--case':
        selected = sys.argv[2]
        if selected not in [case[0] for case in CASES] + [label for label, _ in PASSING]:
            print('unknown case', file=sys.stderr)
            return 2
    elif len(sys.argv) != 1:
        return 2
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
            if selected and selected != label:
                continue
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
            if selected and selected != label:
                continue
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
