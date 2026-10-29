#!/usr/bin/env bash
# Verify the version line, feature marker, and absence of test overrides.
set -euo pipefail
if [ "$#" -ne 2 ] || { [ "$2" != on ] && [ "$2" != off ]; }; then
  echo 'usage: check-binary-marker.sh <binary> <on|off>' >&2
  exit 2
fi
binary=$1
expected=$2
opposite=on
[ "$expected" != on ] || opposite=off
prefix=STELLAR_AGENT_BUILD_MAINNET_WRITE=
version=$("$binary" --version)
line=$(printf '%s\n' "$version" | sed -n '2p' | tr -d '\r')
if [ "$line" != "$prefix$expected" ]; then
  echo "marker: version line 2 differs from $prefix$expected" >&2
  exit 1
fi
if LC_ALL=C grep -aFq "$prefix$opposite" "$binary"; then
  echo 'marker: opposite literal is embedded' >&2
  exit 1
fi
if ! LC_ALL=C grep -aFq "$prefix$expected" "$binary"; then
  echo 'marker: expected literal is absent' >&2
  exit 1
fi
for literal in STELLAR_AGENT_HOME STELLAR_AGENT_TEST_; do
  if LC_ALL=C grep -aFq "$literal" "$binary"; then
    echo "marker: test override literal $literal is embedded" >&2
    exit 1
  fi
done
printf 'marker: %s is %s\n' "$binary" "$expected"
