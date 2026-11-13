# Sourced by build.sh, check-host.sh, verify-install.sh and the notarization
# smoke build. copy_alias <source> <destination> places a copy of source at
# destination through a new mktemp file in the destination directory. The
# destination must be a regular file or absent; a symbolic link or a
# directory there refuses. The copy is published with rename(2) through perl,
# which replaces a link at the destination itself and never follows a
# directory link. The directories belong to the account that runs the script.
# The caller compares the bytes afterwards.

copy_alias() {
  local source=$1 destination=$2 temp
  if [ -L "$destination" ] || { [ -e "$destination" ] && [ ! -f "$destination" ]; }; then
    echo "copy_alias: $destination is not a regular file" >&2
    return 1
  fi
  temp=$(mktemp "$(dirname "$destination")/.stellar-agent-mcp.XXXXXX")
  if ! cp -p "$source" "$temp" ||
    ! perl -e 'rename($ARGV[0], $ARGV[1]) or die "copy_alias: $ARGV[1]: $!\n"' "$temp" "$destination"; then
    rm -f -- "$temp"
    return 1
  fi
}
