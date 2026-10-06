#!/usr/bin/env bash
# Checks that every publishable workspace member exists on crates.io.
#
# Usage: check-crates-exist.sh [--warn] [crate ...]
#
# crates.io Trusted Publishing uploads new versions of crates that exist, and
# it cannot create a crate. The publish run therefore halts at a member that
# has never been uploaded, until a maintainer uploads it once by hand.
#
# Without crate arguments the script checks the packages that cargo metadata
# lists without a source and with a publish field that is absent or a
# non-empty list. With crate arguments it checks exactly the crates named. It
# runs inside the workspace and needs cargo and jq for the workspace list, and
# curl.
#
# A crate passes only when the crates.io API answers HTTP 200 for it. HTTP 404
# marks it missing. Any other status or a failed request leaves its existence
# not confirmed. The script prints one line per crate, then a summary. It
# exits 0 when every crate passes, 1 when a crate is missing or not
# confirmed, and 2 for a usage error or an unreadable or empty workspace
# list.
#
# --warn, the only option, comes first. It adds one GitHub Actions warning
# annotation per crate that does not pass, and the script then exits 0. The
# release preflight runs in this mode. A member with workspace dependencies
# requires them at the release version, and those versions reach crates.io
# only through the publish run. The first upload of such a member is
# therefore possible only after the tag, when the publish run halts at it, so
# the preflight cannot require it before the tag.
set -euo pipefail

CRATES_IO_API="https://crates.io/api/v1/crates"
USER_AGENT="stellar-agent-wallet (https://github.com/Soneso/stellar-agent-wallet)"
NAME_PATTERN='^[A-Za-z0-9_-]+$'
GUIDE='docs/maintainers/releasing.md, section "Publish a new crate for the first time"'

usage() {
  echo "usage: $0 [--warn] [crate ...]" >&2
  exit 2
}

WARN=0
if [ "$#" -gt 0 ] && [ "$1" = "--warn" ]; then
  WARN=1
  shift
fi
# A crate name starts with a letter, so an argument that starts with a dash
# is an option, and --warn is the only one.
for arg in "$@"; do
  case "$arg" in
    -*)
      echo "unknown option or misplaced --warn: '$arg'" >&2
      usage
      ;;
  esac
done

CRATES=()
if [ "$#" -gt 0 ]; then
  CRATES=("$@")
else
  if ! METADATA=$(cargo metadata --format-version 1 --no-deps --offline --frozen); then
    echo "cargo metadata failed" >&2
    exit 2
  fi
  # cargo metadata reports publish = false as an empty list and an absent
  # publish field as null.
  if ! NAMES=$(jq -r '[.packages[]
      | select(.source == null)
      | select(.publish == null or (.publish | length) > 0)
      | .name] | sort | .[]' <<<"$METADATA"); then
    echo "cannot read the workspace members from cargo metadata" >&2
    exit 2
  fi
  while IFS= read -r name; do
    if [ -n "$name" ]; then
      CRATES+=("$name")
    fi
  done <<<"$NAMES"
  if [ "${#CRATES[@]}" -eq 0 ]; then
    echo "cargo metadata lists no publishable workspace member" >&2
    exit 2
  fi
fi

# Every name becomes part of a request URL, so each one is checked before the
# first request.
for name in "${CRATES[@]}"; do
  if ! [[ "$name" =~ $NAME_PATTERN ]]; then
    echo "not a crate name: '$name'" >&2
    usage
  fi
done

missing_count=0
missing_names=""
unconfirmed_count=0
unconfirmed_names=""
checked=0
for name in "${CRATES[@]}"; do
  # The crates.io data access policy allows API clients at most one request
  # per second.
  if [ "$checked" -gt 0 ]; then
    sleep 1
  fi
  checked=$((checked + 1))
  rc=0
  code=$(curl --silent --show-error --location --max-time 30 \
    --user-agent "$USER_AGENT" --output /dev/null --write-out '%{http_code}' \
    "$CRATES_IO_API/$name") || rc=$?
  if [ "$rc" -ne 0 ]; then
    status="no status (curl exit $rc)"
  elif [ "$code" = "200" ]; then
    echo "$name: exists"
    continue
  elif [ "$code" = "404" ]; then
    echo "$name: missing" >&2
    if [ "$WARN" -eq 1 ]; then
      echo "::warning::$name is missing on crates.io; the publish run halts at this crate until a maintainer uploads it once by hand, see $GUIDE"
    fi
    missing_count=$((missing_count + 1))
    missing_names="$missing_names $name"
    continue
  else
    status=${code:-no status}
  fi
  echo "$name: crates.io answered $status" >&2
  if [ "$WARN" -eq 1 ]; then
    echo "::warning::$name: crates.io answered $status, existence not confirmed"
  fi
  unconfirmed_count=$((unconfirmed_count + 1))
  unconfirmed_names="$unconfirmed_names $name"
done

if [ "$missing_count" -gt 0 ]; then
  echo "$missing_count crate(s) missing on crates.io:$missing_names" >&2
fi
if [ "$unconfirmed_count" -gt 0 ]; then
  echo "$unconfirmed_count crate(s) not confirmed on crates.io:$unconfirmed_names" >&2
fi
if [ "$missing_count" -gt 0 ] || [ "$unconfirmed_count" -gt 0 ]; then
  if [ "$WARN" -eq 1 ]; then
    exit 0
  fi
  exit 1
fi
if [ "$checked" -eq 1 ]; then
  echo "1 crate exists on crates.io"
else
  echo "$checked crates exist on crates.io"
fi
