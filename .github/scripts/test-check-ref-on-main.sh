#!/usr/bin/env bash
# Offline regression checks for check-ref-on-main.sh against a temporary
# repository with a main branch, a side branch, and a commit ahead of main.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SCRIPT="$ROOT/.github/scripts/check-ref-on-main.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1

REPO="$TMP/repo"
git init -q -b work "$REPO"
cd "$REPO"
git commit -q --allow-empty -m one
ONE=$(git rev-parse HEAD)
git commit -q --allow-empty -m two
TIP=$(git rev-parse HEAD)
git tag -a -m annotated vtest "$ONE"
TAG_OBJECT=$(git rev-parse vtest)
git commit -q --allow-empty -m ahead
AHEAD=$(git rev-parse HEAD)
git checkout -q -b side "$ONE"
git commit -q --allow-empty -m side
SIDE=$(git rev-parse HEAD)
git checkout -q --detach "$TIP"
git update-ref refs/remotes/origin/main "$TIP"

failures=0
expect() {
  local want=$1 label=$2 pattern=$3
  shift 3
  local out rc
  set +e
  out=$("$@" 2>&1)
  rc=$?
  set -e
  if [ "$want" = pass ] && [ "$rc" -ne 0 ]; then
    echo "FAIL $label: expected exit 0, got $rc: $out" >&2
    failures=$((failures + 1))
  elif [ "$want" = fail ] && [ "$rc" -eq 0 ]; then
    echo "FAIL $label: expected a refusal, got exit 0: $out" >&2
    failures=$((failures + 1))
  elif ! grep -qE -- "$pattern" <<< "$out"; then
    echo "FAIL $label: output does not match '$pattern': $out" >&2
    failures=$((failures + 1))
  else
    echo "ok   $label"
  fi
}

expect pass "ancestor of main" "is on main" bash "$SCRIPT" "$ONE"
expect pass "tip of main" "is on main" bash "$SCRIPT" "$TIP"
expect pass "annotated tag object on main" "is on main" bash "$SCRIPT" "$TAG_OBJECT"
expect fail "side-branch commit" "not an ancestor" bash "$SCRIPT" "$SIDE"
expect fail "commit ahead of main" "not an ancestor" bash "$SCRIPT" "$AHEAD"
expect fail "unknown commit" "not in this repository" bash "$SCRIPT" 0123456789abcdef0123456789abcdef01234567
expect fail "abbreviated SHA" "not a full commit SHA" bash "$SCRIPT" "${ONE:0:12}"
expect fail "ref name" "not a full commit SHA" bash "$SCRIPT" origin/main
expect fail "no argument" "usage" bash "$SCRIPT"

git update-ref -d refs/remotes/origin/main
expect fail "missing origin/main" "origin/main is missing" bash "$SCRIPT" "$ONE"

if [ "$failures" -ne 0 ]; then
  echo "$failures check-ref-on-main case(s) failed" >&2
  exit 1
fi
echo "check-ref-on-main tests passed"
