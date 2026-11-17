#!/usr/bin/env python3
"""Validate retained payment acceptance records without contacting an endpoint."""

import argparse
import hashlib
import itertools
import json
from pathlib import Path
import re
import shlex


TESTS = {
    "pay_commit_testnet_acceptance": {
        "pay_with_approval_commits_and_submits_on_testnet",
        "pay_v1_engine_commit_records_matching_leg_content_on_testnet",
        "pay_v1_per_period_cap_second_payment_denied_by_persisted_window_on_testnet",
    },
    "toolset_sign_payment_gated_testnet_acceptance": {
        "gated_toolset_first_invoke_and_policy_consent_testnet",
    },
    "pay_policy_v1_testnet_acceptance": {
        "pay_v1_per_tx_cap_denies_over_cap_and_submits_under_cap",
    },
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--execution", choices=["live-testnet", "local-fixture"], required=True)
    parser.add_argument("--share", help="driver share k/N; only selected payment suites are required")
    parser.add_argument("--filter", default="", help="the driver's suite substring filter")
    args = parser.parse_args()
    expected_tests = set()
    if args.share:
        share, total_shares = map(int, args.share.split("/"))
        assert 1 <= share <= total_shares
        driver = Path(__file__).with_name("run-testnet-acceptance.sh").read_text()
        registry = re.search(r"^SUITES=\(\n(.*?)^\)", driver, re.M | re.S)
        assert registry, "the acceptance driver registry is missing"
        suites = shlex.split(registry.group(1), comments=True)
        for index, entry in enumerate(suites):
            package, _, target = entry.split()
            if index % total_shares == share - 1 and args.filter in f"{package}/{target}":
                expected_tests.update(TESTS.get(target, set()))
        if not expected_tests:
            print("payment evidence: no payment matrix selected in this driver share")
            return
    files = sorted(args.directory.glob("*.jsonl"))
    if not files:
        raise ValueError("no payment evidence files: zero cases executed")
    total = 0
    observed_tests = set()
    for path in files:
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        if not rows:
            raise ValueError(f"{path.name}: zero cases executed")
        cases = set()
        test = rows[0]["test"]
        observed_tests.add(test)
        for row in rows:
            assert row["schema"] == 1
            assert row["test"] == test
            assert row["execution"] == args.execution
            assert re.fullmatch(r"[0-9a-f]{40}", row["revision"])
            assert row["feature_state"] in {"off", "on"}
            for key in ["envelope_hash", "transaction_hash", "audit_destination_sha256"]:
                assert re.fullmatch(r"[0-9a-f]{64}", row[key]), key
            assert row["ledger"] > 0
            assert int(row["amount_stroops"]) > 0
            assert row["send_count"] == row["debit_count"] == 1
            assert row["audit_destination_sha256"] == hashlib.sha256(row["destination"].encode()).hexdigest()
            assert row["receipt"]["transaction_hash"] == row["transaction_hash"]
            assert row["asset"]
            assert row["case"] not in cases, "duplicate case"
            cases.add(row["case"])
        if test == "pay_v1_per_tx_cap_denies_over_cap_and_submits_under_cap":
            expected = {"/".join(case) for case in itertools.product(["native", "issued"], ["G", "M0", "Mmax"])}
        else:
            assert test in set().union(*TESTS.values()) | {"direct_and_cross_route_payment_matrix_with_local_rpc"}
            expected = {"/".join(case) for case in itertools.product(["native", "issued"], ["G", "M0", "Mmax"], ["allow", "approval"])}
        assert cases == expected, f"{path.name}: incomplete payment matrix"
        total += len(rows)
    assert expected_tests <= observed_tests, f"missing executed tests: {sorted(expected_tests - observed_tests)}"
    print(f"payment evidence: {len(files)} files, {total} executed cases")


if __name__ == "__main__":
    main()
