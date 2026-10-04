#!/usr/bin/env bash
# Refuses a release commit that is not on main.
#
# Usage: check-ref-on-main.sh <commit-sha>
#
# Runs in the repository of the current directory and makes no network call.
# The checkout must carry every branch (actions/checkout with fetch-depth: 0
# fetches refs/heads/* into refs/remotes/origin/*). The commit passes only
# when refs/remotes/origin/main exists and the commit is an ancestor of it or
# equal to it. Every other outcome, including an unknown commit, fails.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <commit-sha>" >&2
  exit 2
fi
SHA=$1
if ! [[ "$SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "not a full commit SHA: $SHA" >&2
  exit 2
fi

if ! MAIN=$(git rev-parse --verify --quiet "refs/remotes/origin/main^{commit}"); then
  echo "refs/remotes/origin/main is missing; check out with fetch-depth: 0" >&2
  exit 1
fi
if ! COMMIT=$(git rev-parse --verify --quiet "$SHA^{commit}"); then
  echo "commit $SHA is not in this repository" >&2
  exit 1
fi

set +e
git merge-base --is-ancestor "$COMMIT" "$MAIN"
rc=$?
set -e
case $rc in
  0)
    echo "commit $COMMIT is on main ($MAIN)"
    ;;
  1)
    echo "commit $COMMIT is not an ancestor of origin/main ($MAIN)" >&2
    exit 1
    ;;
  *)
    echo "git merge-base failed with status $rc" >&2
    exit 1
    ;;
esac
