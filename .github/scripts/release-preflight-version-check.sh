#!/usr/bin/env bash
set -euo pipefail

TAG_VERSION="${1:-${TAG_VERSION:-}}"
if [ -z "$TAG_VERSION" ]; then
  echo "usage: $0 <tag-version>"
  echo "or set TAG_VERSION=<tag-version>"
  exit 2
fi

FLAGS=${RELEASE_PREFLIGHT_CARGO_FLAGS:---offline --frozen}
read -r -a CARGO_FLAGS <<< "$FLAGS"
METADATA=$(cargo metadata --format-version 1 --no-deps "${CARGO_FLAGS[@]}")

# Every workspace member is checked, not a single designated oracle, so a
# version bump that misses one crate is caught regardless of whether that
# crate ships in a release archive.
MEMBER_VERSIONS=$(jq -er '
  .workspace_members as $workspace_members
  | .packages[]
  | select(.id as $id | ($workspace_members | index($id)) != null)
  | [.name, .version] | @tsv
' <<< "$METADATA")

if [ -z "$MEMBER_VERSIONS" ]; then
  echo "No workspace members reported by cargo metadata"
  echo "(expected at least one package ID in .workspace_members)."
  exit 1
fi

MISMATCH=$(awk -F'\t' -v tag="$TAG_VERSION" '$2 != tag { print }' <<< "$MEMBER_VERSIONS")
if [ -n "$MISMATCH" ]; then
  echo "Tag version ($TAG_VERSION) does not match these workspace members:"
  while IFS= read -r line; do
    echo "  - $line"
  done <<< "$MISMATCH"
  echo ""
  echo "All workspace member versions as resolved from Cargo.lock:"
  while IFS= read -r line; do
    echo "  - $line"
  done <<< "$MEMBER_VERSIONS"
  exit 1
fi
