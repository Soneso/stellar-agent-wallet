#!/bin/bash
# Delivers the canonical executable <dir>/stellar-agent<suffix> under its
# second name <dir>/stellar-agent-mcp<suffix> as a byte-equal copy. The
# canonical file must be a regular file with one link, and the alias a
# regular file or absent. The copy goes through a temporary regular file in
# <dir>, keeps the canonical permissions, and is published with rename(2)
# through perl, which replaces an earlier alias and never follows a directory
# link. The directory belongs to the account that runs the script. The alias
# must then be a regular file with one link and the canonical bytes. The suffix is empty or
# .exe. Every tool runs by absolute path. Runs on the macOS /bin/bash (3.2).
#
# Usage: derive-alias.sh <dir> <suffix>
set -euo pipefail

fail() {
  echo "derive-alias: $*" >&2
  exit 1
}

# Succeeds for a regular file, not a symbolic link, with exactly one link.
single_link_file() {
  [ -f "$1" ] && [ ! -L "$1" ] && [ -n "$(/usr/bin/find "$1" -prune -links 1)" ]
}

if [ "$#" -ne 2 ]; then
  echo 'usage: derive-alias.sh <dir> <suffix>' >&2
  exit 2
fi
dir=${1%/}
suffix=$2
case "$suffix" in
  '' | .exe) ;;
  *)
    echo "derive-alias: unsupported suffix '$suffix'" >&2
    exit 2
    ;;
esac
canonical="$dir/stellar-agent$suffix"
alias="$dir/stellar-agent-mcp$suffix"

if [ -L "$canonical" ] || [ ! -f "$canonical" ]; then
  fail "$canonical is not a regular file"
fi
single_link_file "$canonical" || fail "$canonical has more than one link"
if [ -L "$alias" ] || { [ -e "$alias" ] && [ ! -f "$alias" ]; }; then
  fail "$alias is not a regular file"
fi

temp="$(/usr/bin/mktemp "$dir/.stellar-agent-mcp.XXXXXX")"
trap '/bin/rm -f "$temp"' EXIT
/bin/cp -p "$canonical" "$temp"
/usr/bin/perl -e 'rename($ARGV[0], $ARGV[1]) or die "derive-alias: $ARGV[1]: $!\n"' "$temp" "$alias"
trap - EXIT

single_link_file "$alias" || fail "$alias is not a regular file with one link"
/usr/bin/cmp "$canonical" "$alias" || fail "$alias differs from $canonical"
