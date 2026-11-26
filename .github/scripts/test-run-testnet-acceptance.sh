#!/usr/bin/env bash
# Offline checks of run-testnet-acceptance.sh. Sources the driver for its
# suite lists and functions, and runs it once more with a filter that matches
# no suite, so no suite, cargo, or network call runs.
#
# (a) every live test file on disk, a *testnet* file or a
#     *_browser_acceptance file, has a SUITES entry for its crate and target,
#     and every SUITES entry names an existing test file;
# (b) every browser suite is a SUITES entry;
# (c) suite_features adds mainnet-write only under MAINNET_WRITE=on and only
#     for a crate whose manifest declares the feature;
# (d) a MAINNET_WRITE value other than on or off fails the run before the
#     first suite, with a message that names the variable; (d2) the empty
#     value is such a value;
# (e) run_suite passes the feature list of suite_features to cargo;
# (j) the MCP suites that compile the shared child driver first run the
#     paired CLI and MCP prebuild with the suite's flags in both feature
#     states, a failed prebuild stops the suite with status 3, and every
#     other suite keeps its single cargo call;
# (i) STELLAR_AGENT_TEST_KEYRING: unset keeps the headless default with a
#     fresh key and a preset backend; platform leaves both keyring variables
#     unset; any other value fails the run before the first suite, with a
#     message that names the variable.
# (k) browser trust: the trusted suites are the suites that compile the
#     trusted browser fixture; each attempt of one gets a fresh private
#     directory with a trusted and an untrusted chain, their openssl pins,
#     and two NSS databases holding only the trusted authority; cargo alone
#     receives the directory, with HOME unchanged, and the remote crate
#     builds with mainnet-write under MAINNET_WRITE=on; a failed setup
#     returns 3 before cargo; any other suite prepares nothing.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DRIVER="$ROOT/.github/scripts/run-testnet-acceptance.sh"
cd "$ROOT" || exit 2

# These contracts use source text, fixture files, and local shell arithmetic.
check_contracts() {
  python3 - "$@" <<'CONTRACTS'
from pathlib import Path
import datetime
import hashlib
import itertools
import json
import os
import re
import select
import subprocess
import sys
import tempfile

root = Path.cwd()
selected = sys.argv[1:] or ["payment", "workflow", "binary", "records"]
if "records" in selected:
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        driver = root / ".github/scripts/run-testnet-acceptance.sh"
        script = f'. "{driver}"\n' + """
run_suite() { echo fixture-log; LAST_SECONDS=7; LAST_SKIPS=2; return 0; }
LAST_SECONDS=99
LAST_SKIPS=99
ATTEMPT_STATUSES=""
record_attempt fixture feature fixture
status=$?
printf 'seconds:%s skips:%s\\n' "$LAST_SECONDS" "$LAST_SKIPS"
exit "$status"
"""
        def run(extra):
            return subprocess.run(["bash"], input=script, cwd=base,
                                  env={**os.environ, **extra}, capture_output=True, text=True)
        environment = dict(os.environ)
        environment.pop("TESTNET_ATTEMPT_DIR", None)
        result = subprocess.run(["bash"], input=script, cwd=base, env=environment,
                                capture_output=True, text=True)
        default = base / "target/tmp/testnet-attempts"
        assert (default / "fixture.attempt-1.status").is_file(), "default attempt directory"
        assert result.returncode == 0 and (default / "fixture.attempt-1.status").read_text() == "0\n", result
        result = run({"TESTNET_ATTEMPT_DIR": ""})
        assert result.returncode == 0 and (default / "fixture.attempt-2.status").is_file(), "empty override uses the default"
        directory = base / "records"
        directory.mkdir()
        first, second = directory / "fixture.attempt-1.log", directory / "fixture.attempt-2.status"
        first.write_text("retained-log")
        second.write_text("retained-status")
        result = run({"TESTNET_ATTEMPT_DIR": str(directory)})
        assert result.returncode == 0, result.stderr
        assert first.read_text() == "retained-log" and second.read_text() == "retained-status"
        assert (directory / "fixture.attempt-3.log").is_file(), "attempt log retained"
        assert (directory / "fixture.attempt-3.status").is_file(), "attempt status retained"
        assert (directory / "fixture.attempt-3.log").read_text() == "fixture-log\n"
        assert (directory / "fixture.attempt-3.status").read_text() == "0\n"
        assert (directory / "fixture.attempt-3.metrics").read_text() == "7 2\n"
        assert result.stdout == "fixture-log\nseconds:7 skips:2\n", "recording preserves duration and skips"
        (directory / "fixture.attempt-4.metrics").write_text("retained-metrics")
        result = run({"TESTNET_ATTEMPT_DIR": str(directory)})
        assert result.returncode == 0 and (directory / "fixture.attempt-5.status").read_text() == "0\n"
        assert (directory / "fixture.attempt-4.metrics").read_text() == "retained-metrics"
        blocker = base / "not-a-directory"
        blocker.write_text("retain")
        result = run({"TESTNET_ATTEMPT_DIR": str(blocker)})
        assert result.returncode == 3 and "fixture-log" not in result.stdout
        assert result.stdout == "seconds:0 skips:0\n", "failed record setup resets the duration and skips"
        assert f"attempt directory setup failed: {blocker}" in result.stderr
        race = base / "race"
        collision = script.replace('ATTEMPT_STATUSES=""', """
set() {
  printf competing-log > "$TESTNET_ATTEMPT_DIR/fixture.attempt-1.log"
  builtin set "$@"
}
ATTEMPT_STATUSES=""
""")
        result = subprocess.run(["bash"], input=collision, cwd=base,
                                env={**os.environ, "TESTNET_ATTEMPT_DIR": str(race)},
                                capture_output=True, text=True)
        assert result.returncode == 3, result
        assert (race / "fixture.attempt-1.log").read_text() == "competing-log"
        assert "attempt record reservation failed:" in result.stderr
        # A handshake proves output reaches the caller before the attempt ends.
        streaming = script.replace(
            'echo fixture-log; LAST_SECONDS=7; LAST_SKIPS=2; return 0;',
            'echo stream-ready; read -r ack; echo "$ack"; LAST_SECONDS=7; LAST_SKIPS=2; return 0;')
        with subprocess.Popen(["bash", "-c", streaming], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, cwd=base,
                              env={**os.environ, "TESTNET_ATTEMPT_DIR": str(base / "stream")}) as child:
            try:
                assert select.select([child.stdout], [], [], 5)[0], "attempt output must stream before completion"
                assert child.stdout.readline() == "stream-ready\n"
            finally:
                tail, errors = child.communicate("stream-ack\n", timeout=5)
            assert child.returncode == 0, errors
            assert tail == "stream-ack\nseconds:7 skips:2\n"
        assert (base / "stream/fixture.attempt-1.log").read_text() == "stream-ready\nstream-ack\n"
        # Exercise main as well: setup failures are share failures with their own notes.
        main_script = f'. "{driver}"\n' + """
SUITES=("stellar-agent-cli testnet-acceptance claim_testnet_acceptance")
FILTER=''
SHARE=''
build_acceptance_binary() { return 0; }
check_suite_completeness() { return 0; }
suite_features() { echo testnet-acceptance; }
run_suite() { echo unexpected-suite; return 0; }
main
"""
        for label, setup, directory, message in [
            ("mkdir", "", blocker, "attempt directory setup failed:"),
            *[(suffix, 'set() { printf competing > "$TESTNET_ATTEMPT_DIR/claim_testnet_acceptance.attempt-1.'
               + suffix + '"; builtin set "$@"; }\n', base / suffix, "attempt record reservation failed:")
              for suffix in ("log", "status", "metrics")],
        ]:
            summary = base / f"summary-{label}"
            result = subprocess.run(["bash"], input=main_script.replace("main\n", setup + "main\n"),
                                    cwd=base, text=True, capture_output=True,
                                    env={**os.environ, "TESTNET_ATTEMPT_DIR": str(directory),
                                         "GITHUB_STEP_SUMMARY": str(summary), "MAINNET_WRITE": "off"})
            assert result.returncode == 1, result
            assert "unexpected-suite" not in result.stdout
            assert message in result.stderr and message in result.stdout, result
            assert f"| stellar-agent-cli/claim_testnet_acceptance | FAIL ({message}" in summary.read_text()
            assert ", ," not in summary.read_text(), "setup failure has no empty attempt note"
            if label != "mkdir":
                assert (directory / f"claim_testnet_acceptance.attempt-1.{label}").read_text() == "competing"
        browser = main_script.replace(
            'stellar-agent-cli testnet-acceptance claim_testnet_acceptance',
            'stellar-agent-approval-remote operator-enroll-browser-acceptance operator_enroll_browser_acceptance')
        browser = browser.replace('echo unexpected-suite; return 0;',
                                  'echo first-failure; LAST_SECONDS=9; LAST_SKIPS=0; return 1;')
        browser = browser.replace('main\n', """
sleep() { :; }
mkdir() {
  if [ -e "$TESTNET_ATTEMPT_DIR/operator_enroll_browser_acceptance.attempt-1.status" ]; then return 1; fi
  command mkdir "$@"
}
main
""")
        summary = base / "browser-summary"
        result = subprocess.run(["bash"], input=browser, cwd=base, text=True, capture_output=True,
                                env={**os.environ, "TESTNET_ATTEMPT_DIR": str(base / "browser"),
                                     "GITHUB_STEP_SUMMARY": str(summary), "MAINNET_WRITE": "off"})
        assert result.returncode == 1 and result.stderr.count("attempt directory setup failed:") == 1, result
        assert "retrying once more" not in result.stdout, "record failures cannot trigger a browser retry"
        assert "attempt directory setup failed:" in summary.read_text()
        assert "attempt 1: 1, 0 s, 9 s total" in summary.read_text(), summary.read_text()
    print("ok attempt defaults, override, sparse records and directory refusal")
if "binary" in selected:
    files = {
        "caps": ["h1_16th_signer_refused", "h2_6th_policy_refused"],
        "list_rules": ["h3_cli_envelope_shape_on_testnet"],
        "session_rule_horizon": ["h_a_install_horizon_exceeded", "h_b_update_horizon_exceeded"],
    }
    for target, tests in files.items():
        source = (root / f"crates/stellar-agent-smart-account/tests/smart_account_{target}_testnet_acceptance.rs").read_text()
        assert '\nmod acceptance;' in source and '#[path =' not in source
        assert (root / 'crates/stellar-agent-smart-account/tests/acceptance/mod.rs').is_file()
        for test in tests:
            body = source.split(f"async fn {test}() {{\n", 1)[1]
            assert re.match(
                r'    stellar_agent_test_support::keyring_mock::install\(\).expect\("install the in-memory keyring"\);\n'
                r'    let binary = acceptance::require_acceptance_binary\(', body
            ), f"{test}: binary check must immediately follow keyring installation"
    print("ok binary preconditions precede network access")
if "payment" in selected:
    names = [
        "pay_with_approval_commits_and_submits_on_testnet",
        "pay_v1_engine_commit_records_matching_leg_content_on_testnet",
        "pay_v1_per_period_cap_second_payment_denied_by_persisted_window_on_testnet",
        "gated_toolset_first_invoke_and_policy_consent_testnet",
        "pay_v1_per_tx_cap_denies_over_cap_and_submits_under_cap",
    ]
    def rows(test, execution="live-testnet"):
        dimensions = [["native", "issued"], ["G", "M0", "Mmax"]]
        if test != names[-1]:
            dimensions.append(["allow", "approval"])
        return [dict(schema=1, test=test, execution=execution, revision="a" * 40,
                     feature_state="on", case="/".join(case), envelope_hash="b" * 64,
                     transaction_hash="c" * 64, audit_destination_sha256=hashlib.sha256(b"destination").hexdigest(),
                     destination="destination", ledger=1, amount_stroops="1", send_count=1,
                     debit_count=1, receipt={"transaction_hash": "c" * 64}, asset=case[0])
                for case in itertools.product(*dimensions)]
    def check(label, tests=names, options=(), mutate=None, error=None, execution="live-testnet"):
        with tempfile.TemporaryDirectory(prefix="payment-") as temp:
            directory = Path(temp)
            for test in tests:
                data = rows(test, execution)
                if mutate:
                    data = mutate(data)
                (directory / f"{test}.jsonl").write_text("".join(json.dumps(row) + "\n" for row in data))
            result = subprocess.run(
                [sys.executable, str(root / ".github/scripts/check-payment-evidence.py"), str(directory),
                 "--execution", execution, "--expected-revision", "a" * 40,
                 "--expected-feature-state", "on", *options], capture_output=True, text=True)
            output = result.stdout + result.stderr
            assert (result.returncode == 0) == (error is None), (label, result.returncode, output)
            if error:
                assert error in output, (label, output)
    check("share 1", names[:4], ["--share", "1/2"])
    check("share 2", names[4:], ["--share", "2/2"])
    check("full live set")
    check("valid off state", options=["--expected-feature-state", "off"],
          mutate=lambda data: [{**row, "feature_state": "off"} for row in data])
    check("another expected revision", options=["--expected-revision", "d" * 40],
          mutate=lambda data: [{**row, "revision": "d" * 40} for row in data])
    check("local selection unchanged", ["direct_and_cross_route_payment_matrix_with_local_rpc"],
          options=["--filter", "pay_commit"], execution="local-fixture")
    check("local share", names[:4], ["--share", "1/2"], execution="local-fixture")
    check("revision", mutate=lambda data: [{**row, "revision": "d" * 40} for row in data],
          error=f".jsonl: row 1: revision differs: expected {'a' * 40!r}, found {'d' * 40!r}")
    check("state", mutate=lambda data: [{**row, "feature_state": "off"} for row in data],
          error=".jsonl: row 1: feature state differs: expected 'on', found 'off'")
    check("later revision", mutate=lambda data: [data[0], {**data[1], "revision": "bad"}, *data[2:]],
          error=f".jsonl: row 2: revision differs: expected {'a' * 40!r}, found 'bad'")
    check("later state", mutate=lambda data: [data[0], {**data[1], "feature_state": "invalid"}, *data[2:]],
          error=".jsonl: row 2: feature state differs: expected 'on', found 'invalid'")
    for omitted in names:
        check(f"missing {omitted}", [name for name in names if name != omitted],
              error=f"missing executed tests: ['{omitted}']")
    check("missing case", mutate=lambda data: data[:-1], error="incomplete payment matrix")
    check("duplicate case", mutate=lambda data: data + data[:1], error="duplicate case")
    check("empty files", mutate=lambda data: [], error="zero cases executed")
    check("no files", [], error="no payment evidence files")
    check("no payment filter", [], ["--filter", "stellar-agent-pool"])
    check("filtered live", names[:3], ["--filter", "pay_commit"])
    check("filtered missing", [], ["--filter", "pay_commit"], error="no payment evidence files")
    check("nonpayment share", [], ["--share", "2/2", "--filter", "pay_commit"])
    for invalid in ["0/2", "3/2", "1/0", "a/b", "1/2/3"]:
        check("invalid share", [], ["--share", invalid], error="--share must be")
    check("invalid expected revision", options=["--expected-revision", "bad"],
          error="--expected-revision must be")
    check("invalid expected state", options=["--expected-feature-state", "invalid"], error="invalid choice")
    with tempfile.TemporaryDirectory() as temp:
        for missing, supplied in [
                ("--expected-revision", ["--expected-feature-state", "on"]),
                ("--expected-feature-state", ["--expected-revision", "a" * 40])]:
            result = subprocess.run([sys.executable, ".github/scripts/check-payment-evidence.py",
                                     temp, "--execution", "live-testnet", *supplied],
                                    capture_output=True, text=True)
            assert result.returncode and missing in result.stderr
        result = subprocess.run([sys.executable, ".github/scripts/check-payment-evidence.py",
                                 str(Path(temp) / "missing"), "--execution", "live-testnet",
                                 "--expected-revision", "a" * 40, "--expected-feature-state", "on"],
                                capture_output=True, text=True)
        assert result.returncode and "no payment evidence files" in result.stderr
    print("ok bound payment evidence and complete selections")
if "workflow" in selected:
    text = (root / ".github/workflows/testnet.yml").read_text()
    assert re.search(r"mainnet_write:\n(?:(?!      \w).*\n)*?        default: true\n", text)
    assert re.search(r"full_run:\n(?:(?!      \w).*\n)*?        default: false\n", text)
    config = text.split("  config:\n", 1)[1].split("  acceptance-1:\n", 1)[0]
    assert "checkout@" not in config
    assert "feature_state: ${{ steps.mode.outputs.feature_state }}" in config
    assert "EVENT_NAME: ${{ github.event_name }}" in config
    assert "MAINNET_WRITE: ${{ inputs.mainnet_write }}" in config
    script = config.split("        run: |\n", 1)[1]
    script = "\n".join(line[10:] for line in script.splitlines())
    assert "${{ inputs." not in script and "GITHUB_" + "ENV" not in script
    monday = int(datetime.datetime(2026, 11, 23, tzinfo=datetime.timezone.utc).timestamp())
    for epoch, event, value, expected in [
        (monday - 1, "schedule", "", "off"), (monday, "schedule", "", "on"),
        (monday + 3 * 86400, "schedule", "", "on"), (monday + 7 * 86400, "schedule", "", "off"),
        (monday, "workflow_dispatch", "true", "on"), (monday, "workflow_dispatch", "false", "off"),
    ]:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "output"
            result = subprocess.run(["bash"], input=f"date() {{ echo {epoch}; }}\n" + script,
                                    env={**os.environ, "EVENT_NAME": event, "MAINNET_WRITE": value,
                                         "GITHUB_OUTPUT": str(output)}, text=True, capture_output=True)
            assert result.returncode == 0, result.stderr
            assert output.read_text() == f"feature_state={expected}\n", (epoch, output.read_text())
    guard = "github.event_name != 'schedule' || (vars.TESTNET_SCHEDULE != 'off' && github.ref == 'refs/heads/main')"
    assert f"    if: {guard}\n" in config
    jobs = re.findall(r"^  (acceptance-[12]):\n(.*?)(?=^  [a-z].*:\n|\Z)", text, re.M | re.S)
    assert len(jobs) == 2
    second = "${{ !cancelled() && needs.config.result == 'success' && (" + guard + ") && (needs.acceptance-1.result == 'success' || (inputs.full_run && needs.acceptance-1.result == 'failure')) }}"
    for index, (_, body) in enumerate(jobs, 1):
        assert f"          SHARE: {index}/2\n" in body
        for value in [
            "    timeout-minutes: 360\n", "          FILTER: ${{ inputs.filter }}\n",
            "          MAINNET_WRITE: ${{ needs.config.outputs.feature_state }}\n",
            "          PAYMENT_FILTER: ${{ inputs.filter }}\n",
            "          EXPECTED_REVISION: ${{ github.sha }}\n",
            "          EXPECTED_FEATURE_STATE: ${{ needs.config.outputs.feature_state }}\n",
            "          ref: ${{ github.sha }}\n",
            'run: test "$(git rev-parse HEAD)" = "$EXPECTED_REVISION"',
            "          prefix-key: testnet\n          shared-key: testnet-${{ needs.config.outputs.feature_state }}",
            "            target/tmp/testnet-attempts/\n",
            "          STELLAR_AGENT_TESTNET_SECONDARY_RPC_URL: ${{ vars.TESTNET_SECONDARY_RPC_URL }}",
        ]:
            assert value in body, (index, value)
        command = (f'run: python3 .github/scripts/check-payment-evidence.py target/tmp/payment-evidence --execution live-testnet --share {index}/2 --filter "$PAYMENT_FILTER" --expected-revision "$EXPECTED_REVISION" --expected-feature-state "$EXPECTED_FEATURE_STATE"')
        assert command in body, f"share {index} checker arguments"
        assert body.index("Verify checked-out revision") < body.index("Run testnet acceptance suites")
        assert f"name: payment-evidence-share-{index}-mainnet-${{{{ needs.config.outputs.feature_state }}}}-attempt-${{{{ github.run_attempt }}}}" in body
        assert body.count("        if: always()\n") == 2
        assert "Setup Chromium" in body and "actions/setup-node@" in body
    assert f"    if: {guard}\n" in jobs[0][1] and "    needs: config\n" in jobs[0][1]
    assert f"    if: {second}\n" in jobs[1][1] and "    needs: [config, acceptance-1]\n" in jobs[1][1]
    expression = second[3:-3]
    for event, switch, ref, config_result, first, full, canceled in itertools.product(
            ["schedule", "workflow_dispatch"], ["on", "off"], ["refs/heads/main", "refs/heads/next"],
            ["success", "failure"], ["success", "failure", "skipped", "cancelled"], [True, False], [True, False]):
        values = {"github.event_name": event, "vars.TESTNET_SCHEDULE": switch, "github.ref": ref,
                  "needs.config.result": config_result, "needs.acceptance-1.result": first,
                  "inputs.full_run": full, "cancelled()": canceled}
        expanded = expression
        for key, value in values.items():
            expanded = expanded.replace(key, repr(value))
        actual = eval(expanded.replace("!=", "<>").replace("&&", " and ").replace("||", " or ").replace("!", " not ").replace("<>", "!=").strip())
        expected = (not canceled and config_result == "success"
                    and (event != "schedule" or switch != "off" and ref == "refs/heads/main")
                    and (first == "success" or full and first == "failure"))
        assert actual == expected, values
    keys = [re.search(r"shared-key: (.+)", body)[1] for _, body in jobs]
    assert keys[0] == keys[1]
    assert keys[0].replace("${{ needs.config.outputs.feature_state }}", "on") != keys[1].replace("${{ needs.config.outputs.feature_state }}", "off")
    assert re.search(r"^concurrency:\n  group: testnet-acceptance\n  cancel-in-progress: false$", text, re.M)
    print("ok run form, Monday parity, share conditions and config consumers")
CONTRACTS
}

if [ "${1:-}" = --case ] && [ "$2" != attempts ]; then
  check_contracts "$2"
  exit $?
fi
check_contracts || exit 1

# shellcheck source-path=SCRIPTDIR source=run-testnet-acceptance.sh
source "$DRIVER"

test_failures=0
fail() {
  echo "FAIL $*" >&2
  test_failures=$((test_failures + 1))
}
pass() {
  echo "ok   $*"
}

# Succeeds when SUITES holds an entry whose crate and target match.
has_entry() {
  local crate="$1" target="$2"
  printf '%s\n' "${SUITES[@]}" | awk -v c="$crate" -v t="$target" \
    '$1 == c && $3 == t { found = 1 } END { exit !found }'
}

# Succeeds when SUITES holds an entry for the target in any crate.
has_target() {
  printf '%s\n' "${SUITES[@]}" | awk -v t="$1" '$3 == t { found = 1 } END { exit !found }'
}

# (a) The files on disk against the suite list, in both directions.
files=0
while IFS= read -r f; do
  files=$((files + 1))
  crate=$(printf '%s\n' "$f" | cut -d/ -f2)
  target=$(basename "$f" .rs)
  if has_entry "$crate" "$target"; then
    pass "(a) $f has a SUITES entry"
  else
    fail "(a) $f has no SUITES entry for crate $crate and target $target"
  fi
done < <(find crates -path 'crates/*/tests/*' \( -name '*testnet*.rs' -o -name '*_browser_acceptance.rs' \) \
  -not -path '*fixtures*' | sort)
if [ "$files" -eq 0 ]; then
  fail "(a) no live test file found under crates/*/tests"
fi
for line in "${SUITES[@]}"; do
  read -r crate _ target extra <<< "$line"
  if [ -z "${target:-}" ] || [ -n "${extra:-}" ]; then
    fail "(a) SUITES entry '$line' is not '<crate> <feature> <target>'"
  elif [ -f "crates/$crate/tests/$target.rs" ]; then
    pass "(a) SUITES entry $crate/$target names an existing file"
  else
    fail "(a) SUITES entry $crate/$target names no file crates/$crate/tests/$target.rs"
  fi
done

# (b) Every browser suite is run by the driver.
for target in "${BROWSER_SUITE_TARGETS[@]}"; do
  if has_target "$target"; then
    pass "(b) browser suite $target is a SUITES entry"
  else
    fail "(b) browser suite $target is not a SUITES entry"
  fi
done

# (c) The feature list per crate and MAINNET_WRITE value. The pool crate is
# the case without a mainnet-write feature; the premise is checked so the
# case cannot pass on a manifest that changed under it.
if ! grep -qE '^mainnet-write *=' crates/stellar-agent-cli/Cargo.toml; then
  fail "(c) premise: crates/stellar-agent-cli/Cargo.toml declares no mainnet-write feature"
fi
if grep -qE '^mainnet-write *=' crates/stellar-agent-pool/Cargo.toml; then
  fail "(c) premise: crates/stellar-agent-pool/Cargo.toml declares a mainnet-write feature"
fi
expect_features() {
  local mainnet_write="$1" crate="$2" want="$3" got
  local target=claim_testnet_acceptance
  [ "$crate" != stellar-agent-pool ] || target=pool_testnet_init
  [ "$crate" != stellar-agent-approval-remote ] || target=mainnet_presence_browser_acceptance
  got=$(MAINNET_WRITE="$mainnet_write" suite_features "$crate" testnet-acceptance "$target")
  if [ "$got" = "$want" ]; then
    pass "(c) MAINNET_WRITE=$mainnet_write $crate builds with $want"
  else
    fail "(c) MAINNET_WRITE=$mainnet_write $crate builds with '$got', expected '$want'"
  fi
}
expect_features on stellar-agent-cli mainnet-write,testnet-acceptance
expect_features on stellar-agent-pool testnet-acceptance
expect_features off stellar-agent-cli testnet-acceptance
expect_features off stellar-agent-pool testnet-acceptance

# (d) The value check runs before the first suite. The filter matches no
# suite, so a driver without the check reaches the no-match error instead;
# the control run shows that error for a valid value.
NO_MATCH="no suite matches this filter"
run_driver() {
  MAINNET_WRITE="$1" FILTER="$NO_MATCH" PACE=0 RETRY_COOLDOWN=0 BROWSER_RETRY_COOLDOWN=0 \
    bash "$DRIVER" 2>&1
}
out=$(run_driver maybe)
rc=$?
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'MAINNET_WRITE must be on or off' \
  && ! printf '%s\n' "$out" | grep -qE '^::group::|no suite matched'; then
  pass "(d) MAINNET_WRITE=maybe fails before the first suite (exit $rc)"
else
  fail "(d) MAINNET_WRITE=maybe: exit $rc, output:"
  printf '%s\n' "$out" >&2
fi
out=$(run_driver '')
rc=$?
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q "MAINNET_WRITE must be on or off, not ''" \
  && ! printf '%s\n' "$out" | grep -qE '^::group::|no suite matched'; then
  pass "(d2) an empty MAINNET_WRITE fails before the first suite (exit $rc)"
else
  fail "(d2) empty MAINNET_WRITE: exit $rc, output:"
  printf '%s\n' "$out" >&2
fi
out=$(run_driver off)
rc=$?
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'no suite matched' \
  && ! printf '%s\n' "$out" | grep -q 'MAINNET_WRITE'; then
  pass "(d) control: MAINNET_WRITE=off reaches the suite loop (exit $rc)"
else
  fail "(d) control: MAINNET_WRITE=off: exit $rc, output:"
  printf '%s\n' "$out" >&2
fi

# (e) A stub cargo first on PATH records its arguments and reports one
# passed test, so run_suite counts the suite as passed without a build.
mkdir -p "$ROOT/target/tmp"
STUB=$(mktemp -d "$ROOT/target/tmp/test-run-testnet-acceptance.XXXXXX")
export TESTNET_ATTEMPT_DIR="$STUB/attempts"
cat > "$STUB/cargo" <<'STUB_EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$(dirname "$0")/args"
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
STUB_EOF
chmod +x "$STUB/cargo"
# Every driver run below prepares browser trust for the trusted browser
# suites. A stub certutil records its arguments, and fails when
# STUB_CERTUTIL is fail; a stub uname keeps the Linux path on any host.
cat > "$STUB/certutil" <<'STUB_EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$(dirname "$0")/certutil-args"
[ "${STUB_CERTUTIL:-}" != fail ]
STUB_EOF
cat > "$STUB/uname" <<'STUB_EOF'
#!/usr/bin/env bash
echo Linux
STUB_EOF
chmod +x "$STUB/certutil" "$STUB/uname"
expect_cargo() {
  local mainnet_write="$1" want="$2" args rc
  : > "$STUB/args"
  (MAINNET_WRITE="$mainnet_write" PATH="$STUB:$PATH" \
    run_suite stellar-agent-cli testnet-acceptance claim_testnet_acceptance > /dev/null 2>&1)
  rc=$?
  args=$(cat "$STUB/args")
  if [ "$rc" -eq 0 ] && [[ "$args" == *"--no-default-features --features $want --test "* ]]; then
    pass "(e) MAINNET_WRITE=$mainnet_write run_suite calls cargo with --features $want"
  else
    fail "(e) MAINNET_WRITE=$mainnet_write run_suite: exit $rc, cargo arguments '$args', expected --features $want"
  fi
}
expect_cargo on mainnet-write,testnet-acceptance
expect_cargo off testnet-acceptance
# (j) The paired prebuild. CHILD_DRIVER_SUITES lists exactly the MCP live
# suites that compile the shared tests/common module.
expected_children=$(grep -lE '^mod common;' crates/stellar-agent-mcp/tests/*testnet*.rs \
  | xargs -n1 basename | sed 's/\.rs$//' | sort | tr '\n' ' ')
listed_children=$(printf '%s\n' "${CHILD_DRIVER_SUITES[@]}" | sort | tr '\n' ' ')
if [ -n "$expected_children" ] && [ "$listed_children" = "$expected_children" ]; then
  pass "(j) CHILD_DRIVER_SUITES lists the suites that compile tests/common: $listed_children"
else
  fail "(j) CHILD_DRIVER_SUITES is '$listed_children', the suites that compile tests/common are '$expected_children'"
fi
# Each feature state runs the broad paired build, then the suite's own
# selection with the same flags.
expect_prebuild() {
  local mainnet_write="$1" want="$2" target="$3" args rc expected
  : > "$STUB/args"
  (MAINNET_WRITE="$mainnet_write" PATH="$STUB:$PATH" \
    run_suite stellar-agent-mcp testnet-acceptance "$target" > /dev/null 2>&1)
  rc=$?
  args=$(cat "$STUB/args")
  expected="test -p stellar-agent-cli -p stellar-agent-mcp --no-default-features --features $want --no-run
test -p stellar-agent-mcp --no-default-features --features $want --test $target -- --include-ignored --test-threads=1 --nocapture"
  if [ "$rc" -eq 0 ] && [ "$args" = "$expected" ]; then
    pass "(j) MAINNET_WRITE=$mainnet_write $target runs the paired prebuild, then the suite"
  else
    fail "(j) MAINNET_WRITE=$mainnet_write $target: exit $rc, cargo calls '$args', expected '$expected'"
  fi
}
for target in "${CHILD_DRIVER_SUITES[@]}"; do
  expect_prebuild on mainnet-write,testnet-acceptance "$target"
  expect_prebuild off testnet-acceptance "$target"
done
# Suites outside the list keep their single cargo call.
for entry in "stellar-agent-mcp claim_commit_testnet_acceptance" "stellar-agent-cli claim_testnet_acceptance" \
  "stellar-agent-network fee_bump_testnet"; do
  read -r crate target <<< "$entry"
  : > "$STUB/args"
  (MAINNET_WRITE=off PATH="$STUB:$PATH" run_suite "$crate" testnet-acceptance "$target" > /dev/null 2>&1)
  rc=$?
  args=$(cat "$STUB/args")
  if [ "$rc" -eq 0 ] && [ "$args" = "test -p $crate --no-default-features --features testnet-acceptance --test $target -- --include-ignored --test-threads=1 --nocapture" ]; then
    pass "(j) $crate/$target runs without a prebuild"
  else
    fail "(j) $crate/$target: exit $rc, cargo calls '$args'"
  fi
done
# A failed prebuild returns the deterministic status and never runs the suite.
cat > "$STUB/cargo" <<'STUB_EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$(dirname "$0")/args"
case " $* " in
  *' --no-run '*) echo 'error: could not compile `fixture`'; exit 101 ;;
esac
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
STUB_EOF
for mainnet_write in on off; do
  : > "$STUB/args"
  (MAINNET_WRITE="$mainnet_write" PATH="$STUB:$PATH" \
    run_suite stellar-agent-mcp testnet-acceptance "${CHILD_DRIVER_SUITES[0]}" > /dev/null 2>&1)
  rc=$?
  calls=$(wc -l < "$STUB/args" | tr -d ' ')
  if [ "$rc" -eq 3 ] && [ "$calls" -eq 1 ] && grep -q -- '--no-run' "$STUB/args"; then
    pass "(j) MAINNET_WRITE=$mainnet_write a failed prebuild returns 3 before the suite"
  else
    fail "(j) MAINNET_WRITE=$mainnet_write failed prebuild: exit $rc after $calls cargo call(s)"
  fi
done
# (f) Cargo and sleep stubs exercise attempts without network or waiting.
cat > "$STUB/cargo" <<'STUB_EOF'
#!/usr/bin/env bash
root=$(dirname "$0")
echo "$*" >> "$root/args"
if [ "$1" = build ]; then [ "$STUB_MODE" != binary-fail ]; exit $?; fi
count=$(grep -c '^test ' "$root/args")
case "$STUB_MODE" in
  build) echo 'error: could not compile fixture'; exit 101 ;;
  zero) echo 'test result: ok. 0 passed; 0 failed; 0 ignored'; exit 0 ;;
  partial|no-row) if [ "$count" -eq 1 ]; then
    python3 - "$STUB_MODE" "$TESTNET_ATTEMPT_DIR/evidence" <<'EVIDENCE'
from pathlib import Path
import hashlib
import json
import sys
mode, directory = sys.argv[1], Path(sys.argv[2])
directory.mkdir()
row = dict(schema=1, test="pay_v1_per_tx_cap_denies_over_cap_and_submits_under_cap",
           execution="live-testnet", revision="a" * 40, feature_state="off", case="native/G",
           envelope_hash="b" * 64, transaction_hash="c" * 64,
           audit_destination_sha256=hashlib.sha256(b"destination").hexdigest(),
           destination="destination", ledger=1, amount_stroops="1", send_count=1,
           debit_count=1, receipt={"transaction_hash": "c" * 64}, asset="native")
data = json.dumps(row) + "\n" if mode == "partial" else ""
(directory / "payment.jsonl").write_text(data)
print(data, end="")
EVIDENCE
    echo 'test result: FAILED. 0 passed; 1 failed'; exit 101
  fi ;;
  retry) if [ "$count" -eq 1 ]; then
    echo 'test result: FAILED. 0 passed; 1 failed'; exit 101
  fi ;;
  browser) if [ "$count" -le 2 ]; then echo 'test result: FAILED. 0 passed; 1 failed'; exit 101; fi ;;
  fail) echo 'test result: FAILED. 0 passed; 1 failed'; exit 101 ;;
esac
echo 'SKIP fixture prerequisite'
echo 'test result: ok. 1 passed; 0 failed; 0 ignored'
STUB_EOF
cat > "$STUB/sleep" <<'STUB_EOF'
#!/usr/bin/env bash
echo "$*" >> "$(dirname "$0")/sleeps"
STUB_EOF
chmod +x "$STUB/sleep"
run_main_with_stubs() {
  local mode="$1"
  local -a SUITES=("stellar-agent-cli testnet-acceptance claim_testnet_acceptance"
                   "stellar-agent-approval-remote operator-enroll-browser-acceptance operator_enroll_browser_acceptance")
  local -x PATH="$STUB:$PATH" STUB_MODE="$mode" GITHUB_STEP_SUMMARY="$STUB/summary"
  local -x TESTNET_ATTEMPT_DIR="$STUB/attempts-$mode"
  local FILTER='' MAINNET_WRITE=off
  if [ "$mode" = browser ]; then SUITES=("${SUITES[1]}"); fi
  check_suite_completeness() { return 0; }
  main
}
for mode in build zero retry browser fail pass partial no-row binary-fail; do
  : > "$STUB/args"
  : > "$STUB/sleeps"
  : > "$STUB/summary"
  out=$(run_main_with_stubs "$mode")
  rc=$?
  calls=$(wc -l < "$STUB/args" | tr -d ' ')
  [ "$(head -1 "$STUB/args")" = 'build --locked --release -p stellar-agent-cli --bin stellar-agent --no-default-features --features test-helpers --features stellar-agent-network/test-helpers' ] \
    || fail '(f) isolated build precedes attempts with the exact off features'
  sleeps=$(tr '\n' ',' < "$STUB/sleeps")
  case "$mode" in
    build) want_rc=1; want_calls=3; want_sleeps='30,'; note='build or target error' ;;
    zero) want_rc=1; want_calls=3; want_sleeps='30,'; note='vacuous: zero tests executed' ;;
    retry|partial|no-row) want_rc=1; want_calls=4; want_sleeps='60,30,'; note='attempt 1: 1, attempt 2: 0' ;;
    browser) want_rc=1; want_calls=4; want_sleeps='60,90,'; note='attempt 1: 1, attempt 2: 1, attempt 3: 0' ;;
    fail) want_rc=1; want_calls=6; want_sleeps='60,30,60,90,'; note='FAIL' ;;
    pass) want_rc=0; want_calls=3; want_sleeps='30,'; note='1 skip marker(s)' ;;
    binary-fail)
      if [ "$rc/$calls/$sleeps" = '3/1/' ] && [ ! -e "$STUB/attempts-binary-fail" ]; then
        pass '(f) failed isolated build runs no suite'
      else
        fail '(f) failed isolated build'
      fi
      continue ;;
  esac
  if [ "$rc/$calls/$sleeps" = "$want_rc/$want_calls/$want_sleeps" ] \
    && [[ "$out" == *"$note"* && "$out" == *'leg wall time:'* ]] \
    && grep -q '| suite | result | seconds |' "$STUB/summary" \
    && grep -q 'mainnet-write off' "$STUB/summary" \
    && grep -Fq "$note" "$STUB/summary" \
    && grep -q 'Leg wall time: [0-9]* s.' "$STUB/summary" \
    && grep -qE ' [0-9]+ s' "$STUB/summary"; then
    pass "(f) $mode attempts, pacing, cooldowns, continuation and summaries"
  else
    fail "(f) $mode: rc/calls/sleeps=$rc/$calls/$sleeps; output: $out"
  fi
  if ! python3 - "$STUB/attempts-$mode" "$mode" "$STUB/summary" <<'ATTEMPTS'
from pathlib import Path
import json
import subprocess
import sys
directory, mode, summary = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]).read_text()
statuses = sorted(directory.glob('*.status'))
expected = {'build': [3, 3], 'zero': [2, 2], 'retry': [1, 0, 0],
            'partial': [1, 0, 0], 'no-row': [1, 0, 0], 'browser': [1, 1, 0],
            'fail': [1, 1, 1, 1, 1], 'pass': [0, 0]}[mode]
assert [int(p.read_text()) for p in statuses] == expected, statuses
assert all(p.with_suffix('.log').read_text() for p in statuses)
for target in sorted({p.name.split('.attempt-')[0] for p in statuses}):
    attempts = sorted(directory.glob(f'{target}.attempt-*.status'))
    row = next(line for line in summary.splitlines() if f'/{target} |' in line)
    values = [int(p.read_text()) for p in attempts]
    if values[0] == 0:
        assert 'pass (1 skip marker(s),' in row, row
    else:
        note = {2: 'vacuous: zero tests executed', 3: 'build or target error'}.get(values[0])
        assert 'FAIL (' in row and (note is None or note in row), row
        assert ', '.join(f'attempt {i}: {value}' for i, value in enumerate(values, 1)) in row, row
if mode in ('partial', 'no-row'):
    evidence = directory / 'evidence/payment.jsonl'
    data = evidence.read_text()
    first_log = (directory / 'claim_testnet_acceptance.attempt-1.log').read_text()
    if mode == 'partial':
        assert len(data.splitlines()) == 1 and json.loads(data)['case'] == 'native/G'
        assert data in first_log, 'partial first-attempt row must be retained in its log'
    else:
        assert data == '' and '"case"' not in first_log, 'no-row failure retains empty evidence'
    result = subprocess.run([sys.executable, '.github/scripts/check-payment-evidence.py',
                             str(evidence.parent), '--execution', 'live-testnet',
                             '--filter', 'pay_policy_v1', '--expected-revision', 'a' * 40,
                             '--expected-feature-state', 'off'], capture_output=True, text=True)
    error = 'incomplete payment matrix' if mode == 'partial' else 'zero cases executed'
    assert result.returncode != 0 and f'payment.jsonl: {error}' in result.stderr, result
elif mode == 'retry':
    assert not (directory / 'evidence').exists(), 'retry-only fixture has no evidence artifact'
ATTEMPTS
  then fail "(f) $mode retained attempts"; fi
done
# A second invocation retains the bytes of both the first status and log.
first_log="$STUB/attempts-pass/claim_testnet_acceptance.attempt-1.log"
first_status="${first_log%.log}.status"
before=$(cksum "$first_log" "$first_status")
out=$(run_main_with_stubs pass)
rc=$?
if [ "$rc" -eq 0 ] && [ "$before" = "$(cksum "$first_log" "$first_status")" ] \
  && [ -s "$STUB/attempts-pass/claim_testnet_acceptance.attempt-2.log" ]; then
  pass '(f) repeated invocations never overwrite attempt records'
else
  fail '(f) repeated invocation lost or replaced attempt records'
fi
if [ "${1:-}" = --case ] && [ "$2" = attempts ]; then
  [ "$test_failures" -eq 0 ]
  exit $?
fi
# (g) Run the real registry through every share and compare ordered targets.
selection_case() {
  local share="$1" filter="$2" want_rc="$3" state="${4:-off}" index crate feature target expected='' actual out rc count=0
  : > "$STUB/args"; : > "$STUB/sleeps"; : > "$STUB/summary"
  for index in "${!SUITES[@]}"; do
    read -r crate feature target <<< "${SUITES[$index]}"
    if [ -n "$share" ] && [ "$((index % ${share#*/}))" -ne "$((${share%/*} - 1))" ]; then continue; fi
    [[ "$crate/$target" == *"$filter"* ]] || continue
    expected="${expected}${target} "
    count=$((count + 1))
  done
  out=$(SHARE="$share" FILTER="$filter" MAINNET_WRITE="$state" STUB_MODE=pass \
    PATH="$STUB:$PATH" GITHUB_STEP_SUMMARY="$STUB/summary" bash "$DRIVER" 2>&1)
  rc=$?
  actual=$(awk '{ for (i=1; i<=NF; i++) if ($i == "--test") printf "%s ", $(i+1) }' "$STUB/args")
  if [ "$rc" -eq "$want_rc" ] && [ "$actual" = "$expected" ] \
    && { [ "$rc" -ne 0 ] || { [[ "$out" == *"($count suites, share ${share:-all}, mainnet-write $state)"* ]] \
      && grep -q "($count suites, share ${share:-all}, mainnet-write $state)" "$STUB/summary" \
      && [ "$(grep -c '^| stellar-agent' "$STUB/summary")" -eq "$count" ]; }; }; then
    pass "(g) share ${share:-all}, filter '$filter': $count ordered suites, exit $rc"
  else
    fail "(g) share $share filter '$filter': exit $rc, targets '$actual', expected '$expected'; $out"
  fi
  if [ "$want_rc" -eq 0 ]; then
    local features=test-helpers
    [ "$state" != on ] || features=mainnet-write,test-helpers
    local expected_build="build --locked --release -p stellar-agent-cli --bin stellar-agent --no-default-features --features $features --features stellar-agent-network/test-helpers"
    [ "$(head -1 "$STUB/args")" = "$expected_build" ] && [ "$(grep -c '^build ' "$STUB/args")" -eq 1 ] \
      || fail "(g) exactly one $state binary build precedes all suites in share $share"
  fi
}
for denominator in 2 3; do
  for ((numerator=1; numerator<=denominator; numerator++)); do
    selection_case "$numerator/$denominator" '' 0
    selection_case "$numerator/$denominator" "$NO_MATCH" 2
  done
done
selection_case '' '' 0
# The first registered target belongs only to share 1/2.
read -r _ _ first_target <<< "${SUITES[0]}"
selection_case '1/2' "$first_target" 0
selection_case '2/2' "$first_target" 0
selection_case '1/2' "$first_target" 0 on
selection_case '2/2' "$first_target" 0 on
for share in 0/2 3/2 1/0 a/b 1/2/3; do
  : > "$STUB/args"
  out=$(SHARE="$share" MAINNET_WRITE=off STUB_MODE=pass PATH="$STUB:$PATH" bash "$DRIVER" 2>&1)
  rc=$?
  if [ "$rc" -eq 2 ] && [ ! -s "$STUB/args" ] \
    && [[ "$out" == "SHARE must be k/N with 1 <= k <= N, got '$share'" ]]; then
    pass "(g) invalid share '$share' refuses before cargo"
  else
    fail "(g) invalid share '$share': exit $rc; $out"
  fi
done
# Unset SHARE selects the full registry, including browser entries.
# shellcheck source-path=SCRIPTDIR source=run-testnet-acceptance.sh
if (unset SHARE; source "$DRIVER"; check_share && in_share 60); then
  pass '(g) unset SHARE selects every entry'
else
  fail '(g) unset SHARE rejects a registered entry'
fi
# (i) The keyring selection, read after sourcing the driver in a fresh shell
# whose keyring variables are the given assignments only. Prints the exported
# backend and key, each "unset" when absent.
keyring_env() {
  # shellcheck disable=SC2016 # The inner shell expands its own arguments.
  env -u STELLAR_AGENT_KEYRING_BACKEND -u STELLAR_AGENT_HEADLESS_KEYRING_KEY \
    -u STELLAR_AGENT_TEST_KEYRING "$@" bash -c '
      . "$1"
      printf "%s|%s\n" "$(printenv STELLAR_AGENT_KEYRING_BACKEND || echo unset)" \
        "$(printenv STELLAR_AGENT_HEADLESS_KEYRING_KEY || echo unset)"
    ' keyring "$DRIVER"
}
first=$(keyring_env)
second=$(keyring_env)
if [[ "$first" =~ ^headless-env\|[A-Za-z0-9_-]{43}$ ]] && [[ "$second" =~ ^headless-env\|[A-Za-z0-9_-]{43}$ ]] \
  && [ "$first" != "$second" ]; then
  pass '(i) unset STELLAR_AGENT_TEST_KEYRING selects headless-env with a fresh key per run'
else
  fail "(i) unset STELLAR_AGENT_TEST_KEYRING: '$first' then '$second'"
fi
got=$(keyring_env STELLAR_AGENT_KEYRING_BACKEND=headless-dpapi)
if [ "$got" = 'headless-dpapi|unset' ]; then
  pass '(i) a preset STELLAR_AGENT_KEYRING_BACKEND stays'
else
  fail "(i) a preset STELLAR_AGENT_KEYRING_BACKEND gave '$got'"
fi
got=$(keyring_env STELLAR_AGENT_TEST_KEYRING=platform)
if [ "$got" = 'unset|unset' ]; then
  pass '(i) STELLAR_AGENT_TEST_KEYRING=platform leaves both keyring variables unset'
else
  fail "(i) STELLAR_AGENT_TEST_KEYRING=platform gave '$got'"
fi
got=$(keyring_env STELLAR_AGENT_TEST_KEYRING=platform STELLAR_AGENT_KEYRING_BACKEND=headless-env \
  STELLAR_AGENT_HEADLESS_KEYRING_KEY=preset-key)
if [ "$got" = 'unset|unset' ]; then
  pass '(i) STELLAR_AGENT_TEST_KEYRING=platform unsets a preset backend and key'
else
  fail "(i) STELLAR_AGENT_TEST_KEYRING=platform with a preset backend gave '$got'"
fi
# The value check runs before the first suite, as in (d).
run_keyring_driver() {
  env -u STELLAR_AGENT_KEYRING_BACKEND -u STELLAR_AGENT_HEADLESS_KEYRING_KEY \
    STELLAR_AGENT_TEST_KEYRING="$1" MAINNET_WRITE=off FILTER="$NO_MATCH" PACE=0 RETRY_COOLDOWN=0 \
    BROWSER_RETRY_COOLDOWN=0 bash "$DRIVER" 2>&1
}
for value in unknown ''; do
  out=$(run_keyring_driver "$value")
  rc=$?
  if [ "$rc" -ne 0 ] \
    && printf '%s\n' "$out" | grep -qF "STELLAR_AGENT_TEST_KEYRING must be headless, platform or unset, not '$value'" \
    && ! printf '%s\n' "$out" | grep -qE '^::group::|no suite matched'; then
    pass "(i) STELLAR_AGENT_TEST_KEYRING='$value' fails before the first suite (exit $rc)"
  else
    fail "(i) STELLAR_AGENT_TEST_KEYRING='$value': exit $rc, output:"
    printf '%s\n' "$out" >&2
  fi
done
out=$(run_keyring_driver platform)
rc=$?
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'no suite matched' \
  && ! printf '%s\n' "$out" | grep -q 'STELLAR_AGENT_TEST_KEYRING'; then
  pass "(i) control: STELLAR_AGENT_TEST_KEYRING=platform reaches the suite loop (exit $rc)"
else
  fail "(i) control: STELLAR_AGENT_TEST_KEYRING=platform: exit $rc, output:"
  printf '%s\n' "$out" >&2
fi
# Each registered suite has an independently reviewed storage label.
expected_storage=$(cat <<'MATRIX'
stellar-agent-sep10 sep10_round_trip_testnet_acceptance no-keyring
stellar-agent-sep10 sep10_replay_adversarial no-keyring
stellar-agent-sep43 sep43_sdk_v17_interop_testnet_acceptance no-keyring
stellar-agent-sep48 sep48_preview_testnet_acceptance no-keyring
stellar-agent-sep7 sep7_testnet_acceptance no-keyring
stellar-agent-anchor anchor_testnet_acceptance no-keyring
stellar-agent-x402-identity sep10_gate_testnet_acceptance no-keyring
stellar-agent-network fee_bump_testnet no-keyring
stellar-agent-network fee_bump_idempotent_testnet no-keyring
stellar-agent-pool pool_testnet_init fixture
stellar-agent-pool pool_concurrent_testnet fixture
stellar-agent-pool load_testnet fixture
stellar-agent-stablecoin trustline_testnet_acceptance no-keyring
stellar-agent-x402 x402_exact_testnet_acceptance no-keyring
stellar-agent-mpp sponsored_testnet_acceptance fixture
stellar-agent-dex dex_swap_testnet_acceptance no-keyring
stellar-agent-defindex defindex_vault_testnet_acceptance no-keyring
stellar-agent-defindex defindex_deposit_submit_testnet_acceptance no-keyring
stellar-agent-mcp pay_commit_testnet_acceptance fixture
stellar-agent-mcp create_account_testnet_acceptance fixture
stellar-agent-mcp trustline_classic_testnet_acceptance fixture
stellar-agent-mcp policy_value_descriptor_testnet_acceptance fixture
stellar-agent-mcp rule_create_commit_testnet_acceptance fixture
stellar-agent-mcp sep43_sign_and_submit_transaction_testnet_acceptance fixture
stellar-agent-mcp toolset_sign_payment_gated_testnet_acceptance fixture
stellar-agent-mcp x402_create_payment_testnet_acceptance fixture
stellar-agent-mcp x402_authenticated_payment_testnet_acceptance fixture
stellar-agent-mcp claim_commit_testnet_acceptance fixture
stellar-agent-mcp approve_serve_testnet_acceptance fixture
stellar-agent-mcp dex_quote_wire_testnet_acceptance fixture
stellar-agent-cli claim_testnet_acceptance native-capable
stellar-agent-cli pay_policy_v1_testnet_acceptance native-capable
stellar-agent-cli pay_timeout_reconcile_testnet_acceptance native-capable
stellar-agent-cli cli_submit_only_network_binding_testnet_acceptance native-capable
stellar-agent-cli profile_init_enroll_signer_testnet_acceptance native-capable
stellar-agent-cli smart_account_execute_testnet_acceptance native-capable
stellar-agent-cli smart_account_multicall_cli_testnet_acceptance fixture
stellar-agent-cli cap85_external_ref_cli_testnet_acceptance native-capable
stellar-agent-smart-account deploy_c_testnet_acceptance no-keyring
stellar-agent-smart-account quorum_authorization_info_testnet_acceptance fixture
stellar-agent-smart-account smart_account_caps_testnet_acceptance fixture
stellar-agent-smart-account smart_account_signers_testnet_acceptance fixture
stellar-agent-smart-account smart_account_rules_testnet_acceptance fixture
stellar-agent-smart-account smart_account_rules_pinning_testnet_acceptance fixture
stellar-agent-smart-account smart_account_list_rules_testnet_acceptance fixture
stellar-agent-smart-account smart_account_policy_mutators_testnet_acceptance fixture
stellar-agent-smart-account smart_account_session_rule_expiry_testnet_acceptance fixture
stellar-agent-smart-account smart_account_session_rule_horizon_testnet_acceptance fixture
stellar-agent-smart-account smart_account_sim_audit_testnet_acceptance fixture
stellar-agent-smart-account smart_account_migrate_verifier_testnet_acceptance fixture
stellar-agent-smart-account-acceptance cap85_external_ref_testnet_acceptance fixture
stellar-agent-smart-account smart_account_multicall_testnet_acceptance fixture
stellar-agent-smart-account smart_account_timelock_testnet_acceptance fixture
stellar-agent-smart-account-acceptance smart_account_rules_webauthn_testnet_acceptance fixture
stellar-agent-smart-account smart_account_delegation_testnet_acceptance fixture
stellar-agent-smart-account-acceptance smart_account_policy_observability_testnet_acceptance fixture
stellar-agent-smart-account-acceptance smart_account_ergonomics_testnet_acceptance fixture
stellar-agent-approval-remote operator_enroll_browser_acceptance fixture
stellar-agent-approval-remote mainnet_presence_browser_acceptance fixture
stellar-agent-approval-remote remote_approval_browser_testnet_acceptance fixture
stellar-agent-approval-remote rule_proposal_remote_browser_testnet_acceptance fixture
MATRIX
)
while read -r crate target expected; do
  actual=$(suite_storage "$crate" "$target")
  if [ "$actual" = "$expected" ]; then pass "storage label $crate/$target $expected";
  else fail "storage label $crate/$target: $actual, expected $expected"; fi
done <<< "$expected_storage"
if suite_features stellar-agent-cli testnet-acceptance unclassified_fixture >/dev/null 2>&1; then
  fail "unclassified suite must refuse"
else pass "unclassified suite refuses"; fi
if (grep() { return 1; }; STELLAR_AGENT_TEST_KEYRING=platform suite_features stellar-agent-cli testnet-acceptance claim_testnet_acceptance) >/dev/null 2>&1; then
  fail "native route without its feature must refuse"
else pass "native route without its feature refuses"; fi
# (j) Every suite receives a marked home below target/tmp/test-sandboxes;
# the platform leg receives its permit and each declared live feature.
cat > "$STUB/cargo" <<'STUB_EOF'
#!/usr/bin/env bash
root=$(cd "$(dirname "$0")/../../.." && pwd)
case "${STELLAR_AGENT_HOME-}" in
  "$root"/target/tmp/test-sandboxes/*) ;;
  *) echo 'error: could not compile fixture: sandbox root missing'; exit 101 ;;
esac
if [ ! -f "$STELLAR_AGENT_HOME/.stellar-agent-test-sandbox" ]; then
  echo 'error: could not compile fixture: sandbox marker missing'; exit 101
fi
if [ "${STELLAR_AGENT_TEST_KEYRING-}" = platform ]; then
  if [ "${STELLAR_AGENT_TEST_LIVE_PLATFORM_KEYRING-}" != real-platform-keyring ]; then
    echo 'error: could not compile fixture: live permit missing'; exit 101
  fi
  suite_crate='' target='' next=''
  for arg in "$@"; do
    case "$next" in crate) suite_crate=$arg ;; target) target=$arg ;; esac
    next=''
    case "$arg" in -p) next=crate ;; --test) next=target ;; esac
  done
  # Independent expected matrix: only these seven CLI targets are native.
  want_native=0
  case "$suite_crate/$target" in
    stellar-agent-cli/claim_testnet_acceptance) want_native=1 ;;
    stellar-agent-cli/pay_policy_v1_testnet_acceptance) want_native=1 ;;
    stellar-agent-cli/pay_timeout_reconcile_testnet_acceptance) want_native=1 ;;
    stellar-agent-cli/cli_submit_only_network_binding_testnet_acceptance) want_native=1 ;;
    stellar-agent-cli/profile_init_enroll_signer_testnet_acceptance) want_native=1 ;;
    stellar-agent-cli/smart_account_execute_testnet_acceptance) want_native=1 ;;
    stellar-agent-cli/cap85_external_ref_cli_testnet_acceptance) want_native=1 ;;
  esac
  got_native=0
  case "$*" in *live-platform-keyring*) got_native=1 ;; esac
  if [ "$got_native" != "$want_native" ]; then
    echo "error: could not compile fixture: native route mismatch $suite_crate/$target"; exit 101
  fi
fi
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
STUB_EOF
for mainnet_write in off on; do
  for keyring in headless platform; do
    for share in '' 1/2 2/2; do
    if [ "$keyring" = platform ]; then
      out=$(env -u STELLAR_AGENT_TEST_LIVE_PLATFORM_KEYRING PATH="$STUB:$PATH" \
        STELLAR_AGENT_TEST_KEYRING=platform MAINNET_WRITE="$mainnet_write" FILTER='' SHARE="$share" \
        PACE=0 RETRY_COOLDOWN=0 BROWSER_RETRY_COOLDOWN=0 bash "$DRIVER" 2>&1)
    else
      out=$(env -u STELLAR_AGENT_TEST_KEYRING -u STELLAR_AGENT_TEST_LIVE_PLATFORM_KEYRING \
        PATH="$STUB:$PATH" STELLAR_AGENT_TEST_KEYRING=headless MAINNET_WRITE="$mainnet_write" FILTER='' SHARE="$share" \
        PACE=0 RETRY_COOLDOWN=0 BROWSER_RETRY_COOLDOWN=0 bash "$DRIVER" 2>&1)
    fi
    rc=$?
    expected=61
    case "$share" in 1/2) expected=31 ;; 2/2) expected=30 ;; esac
    labels=$(printf '%s\n' "$out" | grep -c '^::group::.* \[storage=')
    if [ "$rc" -eq 0 ] && [ "$labels" -eq "$expected" ]; then
      pass "(j) every suite receives labelled storage and the selected permit/features: $mainnet_write $keyring ${share:-all}"
    else
      fail "(j) suite storage contract: $mainnet_write $keyring exit $rc: $out"
    fi
    done
  done
done
selection_count=$(grep -cF "STELLAR_AGENT_TEST_KEYRING: \${{ inputs.keyring || 'headless' }}" .github/workflows/testnet.yml)
if [ "$selection_count" -eq 2 ] && grep -q 'default: headless' .github/workflows/testnet.yml; then
  pass 'workflow shares forward the same storage selection and default to headless'
else fail 'workflow storage selection differs between shares or default'; fi
# (k) Browser trust. The trusted suites are exactly the suites that compile
# the shared trusted browser fixture, and each is a browser suite.
expected_trusted=$(grep -lE '^mod trusted_browser;' crates/*/tests/*_browser_acceptance.rs \
  | xargs -n1 basename | sed 's/\.rs$//' | sort | tr '\n' ' ')
# The parent retains the constants from its own driver source.
# shellcheck disable=SC2031
listed_trusted=$(printf '%s\n' "${TRUSTED_BROWSER_SUITES[@]}" | sort | tr '\n' ' ')
if [ -n "$expected_trusted" ] && [ "$listed_trusted" = "$expected_trusted" ]; then
  pass "(k) TRUSTED_BROWSER_SUITES lists the suites that compile the trusted browser fixture: $listed_trusted"
else
  fail "(k) TRUSTED_BROWSER_SUITES is '$listed_trusted', the fixture's suites are '$expected_trusted'"
fi
# shellcheck disable=SC2031
for target in "${TRUSTED_BROWSER_SUITES[@]}"; do
  if is_browser_suite "$target"; then
    pass "(k) trusted suite $target is a browser suite"
  else
    fail "(k) trusted suite $target is not in BROWSER_SUITE_TARGETS"
  fi
done
# The remote approval crate forwards mainnet-write, so its suites build
# with the feature under MAINNET_WRITE=on.
if ! grep -qE '^mainnet-write *=' crates/stellar-agent-approval-remote/Cargo.toml; then
  fail "(k) premise: crates/stellar-agent-approval-remote/Cargo.toml declares no mainnet-write feature"
fi
expect_features on stellar-agent-approval-remote mainnet-write,testnet-acceptance
expect_features off stellar-agent-approval-remote testnet-acceptance
# A stub cargo records its arguments and the trust variable and HOME it sees.
cat > "$STUB/cargo" <<'STUB_EOF'
#!/usr/bin/env bash
root=$(dirname "$0")
printf '%s\n' "$*" >> "$root/args"
printf '%s|%s\n' "${STELLAR_AGENT_BROWSER_TRUST_DIR-unset}" "$HOME" >> "$root/env"
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
STUB_EOF
# run_suite runs in this shell, so a variable it leaked would remain here.
trust_case() {
  local mainnet_write="$1" target="$2"
  : > "$STUB/args"; : > "$STUB/env"; : > "$STUB/certutil-args"
  MAINNET_WRITE="$mainnet_write" PATH="$STUB:$PATH" \
    run_suite stellar-agent-approval-remote operator-enroll-browser-acceptance "$target" > /dev/null 2>&1
}
trust_dirs=''
for mainnet_write in on off; do
  want=operator-enroll-browser-acceptance
  [ "$mainnet_write" = on ] && want="mainnet-write,$want"
  trust_case "$mainnet_write" mainnet_presence_browser_acceptance
  rc=$?
  IFS='|' read -r dir home < "$STUB/env"
  trust_dirs="$trust_dirs $dir"
  problems=''
  [ "$rc" -eq 0 ] || problems="$problems exit $rc;"
  [[ "$(cat "$STUB/args")" == *"--no-default-features --features $want --test mainnet_presence_browser_acceptance "* ]] \
    || problems="$problems features '$(cat "$STUB/args")';"
  [ "$home" = "$HOME" ] || problems="$problems cargo HOME '$home';"
  [ -z "${STELLAR_AGENT_BROWSER_TRUST_DIR+set}" ] || problems="$problems the trust variable leaked;"
  case "$dir" in
    "$ROOT"/target/tmp/browser-trust/attempt.*) ;;
    *) problems="$problems trust directory '$dir';" ;;
  esac
  for name in trusted-chain.pem trusted-key.pem untrusted-chain.pem untrusted-key.pem trusted.pin untrusted.pin; do
    [ -s "$dir/$name" ] || problems="$problems $name missing;"
  done
  for name in trusted-key.pem untrusted-key.pem trusted-ca-key.pem untrusted-ca-key.pem; do
    [ "$(stat -c %a "$dir/$name" 2> /dev/null || stat -f %Lp "$dir/$name")" = 600 ] \
      || problems="$problems $name is not 0600;"
  done
  pin=$(openssl x509 -in "$dir/trusted-leaf.pem" -pubkey -noout | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -r | cut -c1-64)
  [ "$(cat "$dir/trusted.pin")" = "$pin" ] || problems="$problems trusted.pin differs from the leaf;"
  openssl verify -CAfile "$dir/trusted-ca.pem" "$dir/trusted-leaf.pem" > /dev/null 2>&1 \
    || problems="$problems the trusted leaf does not verify;"
  ! openssl verify -CAfile "$dir/trusted-ca.pem" "$dir/untrusted-leaf.pem" > /dev/null 2>&1 \
    || problems="$problems the untrusted leaf verifies against the trusted authority;"
  # shellcheck disable=SC2031
  openssl x509 -in "$dir/trusted-leaf.pem" -noout -ext subjectAltName 2> /dev/null \
    | grep -qF "DNS:$BROWSER_TRUST_HOST, DNS:$BROWSER_TRUST_FOREIGN_HOST" \
    || problems="$problems the leaf lacks DNS:$BROWSER_TRUST_HOST and DNS:$BROWSER_TRUST_FOREIGN_HOST;"
  expected_certutil=''
  for db in "$dir/home/.pki/nssdb" "$dir/home/.local/share/pki/nssdb"; do
    expected_certutil="${expected_certutil}-N --empty-password -d sql:$db
-A -d sql:$db -n stellar-agent-test-ca -t C,, -i $dir/trusted-ca.pem
"
  done
  [ "$(cat "$STUB/certutil-args")" = "${expected_certutil%$'\n'}" ] \
    || problems="$problems certutil calls '$(cat "$STUB/certutil-args")';"
  if [ -z "$problems" ]; then
    pass "(k) MAINNET_WRITE=$mainnet_write the presence browser suite gets fresh private trust and --features $want"
  else
    fail "(k) MAINNET_WRITE=$mainnet_write trust setup:$problems"
  fi
done
read -r first_dir second_dir <<< "$trust_dirs"
if [ -n "$first_dir" ] && [ "$first_dir" != "$second_dir" ]; then
  pass '(k) each attempt gets its own trust directory'
else
  fail "(k) attempts share the trust directory '$first_dir'"
fi
# A failed setup stops the suite before cargo, with the deterministic status.
STUB_CERTUTIL=fail trust_case off operator_enroll_browser_acceptance
rc=$?
if [ "$rc" -eq 3 ] && [ ! -s "$STUB/args" ] && [ -s "$STUB/certutil-args" ]; then
  pass '(k) a failed trust setup returns 3 before any cargo call'
else
  fail "(k) failed trust setup: exit $rc, cargo calls '$(cat "$STUB/args")'"
fi
# Another suite never prepares trust and never sees the variable.
: > "$STUB/args"; : > "$STUB/env"; : > "$STUB/certutil-args"
(MAINNET_WRITE=off PATH="$STUB:$PATH" run_suite stellar-agent-cli testnet-acceptance claim_testnet_acceptance \
  > /dev/null 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && [ ! -s "$STUB/certutil-args" ] && [ "$(cut -d'|' -f1 "$STUB/env")" = unset ]; then
  pass '(k) a suite outside TRUSTED_BROWSER_SUITES runs without trust setup'
else
  fail "(k) claim_testnet_acceptance: exit $rc, certutil '$(cat "$STUB/certutil-args")', env '$(cat "$STUB/env")'"
fi
rm -f "$STUB/sleep" "$STUB/sleeps" "$STUB/summary"
rm -f "$STUB/cargo" "$STUB/args" "$STUB/env" "$STUB/certutil" "$STUB/certutil-args" "$STUB/uname"
python3 - "$STUB" <<'CLEANUP'
import shutil
import sys
shutil.rmtree(sys.argv[1])
CLEANUP

if [ "$test_failures" -gt 0 ]; then
  echo "$test_failures testnet acceptance driver check(s) failed" >&2
  exit 1
fi
echo "testnet acceptance driver checks passed"
