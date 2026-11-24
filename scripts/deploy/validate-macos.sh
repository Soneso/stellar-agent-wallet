#!/bin/bash
# Records the dedicated-account deployment on a macOS host.
#
# Usage: validate-macos.sh --record <dir> [--rpc-url <url>] [--providers <file>]
#          [--policy <file>] [--cert <file>] [--key <file>] [--bind <addr>]
#          [--rp-id <host>]
#
# Runs as the operator after bootstrap.sh, also over ssh without a desktop
# session. It reaches the wallet account only through
# "sudo -n -u stellar-agent <wrapper>" and reads no secret itself: the
# wrappers and security prompt on the terminal. The record directory must
# not exist; each measurement writes one entry file there.
#
# Entries: account, ownership, binary-identity, refusal-64, refusal-65, keychain-unlock,
# keychain-lock, keychain-unlock-again, provisioning-order,
# platform-read-write, refusal-66, mcp-stdio, cross-user-file-denial,
# cross-user-keyring-denial, approval-round-trip, access-lists,
# designated-requirement, signed-upgrade, dialog-counts, and
# no-desktop-session.
#
# Each entry holds the commands, their exit codes, their output, and a
# status: ok, refused, failed, skipped, or "not available" when a command
# or a native verb or option is missing. A read attempt on the wallet
# account's keyring records failed when the read succeeds. It records
# denied only on an interaction or authorization refusal of security,
# while the wallet account's own access-list record shows the signer item.
# Any other failure records inconclusive with its text. The dialog counts
# record inconclusive when the log shows no readable SecurityAgent event
# record.
#
# After every entry, the script exits 1 when the binary-identity entry is
# not ok, with a line that names both installed paths and the repair.
set -euo pipefail

# Fixed values.
ACCOUNT=stellar-agent
PREFIX=/usr/local/libexec/stellar-agent
HOME_DIR=/Users/stellar-agent
PROJECT_FILE=/usr/local/etc/stellar-agent/project
SUDOERS_FILE=/etc/sudoers.d/stellar-agent
SUDO=/usr/bin/sudo
SECURITY=/usr/bin/security
TTY_PATH=/dev/tty
SETTLE_SECONDS=3
RESPONSE_SECONDS=5
SIGNER_SERVICE=stellar-agent-signer-mainnet
SERVICE_PREFIX=stellar-agent-
# The dialog texts that keychain-measurement.md classes as an application
# request for an item and as a keychain password request.
ITEM_PROMPT='wants to use your confidential information stored in|wants to access key|wants to sign using key|wants to export key'
PASSWORD_PROMPT='wants to use the .*keychain|wants to make changes to the .*keychain'
# An event record of log show --style compact: date, time, type, and the
# SecurityAgent process column with a decimal process id and a hexadecimal
# thread id. The filter banner and the column header match no record.
EVENT_RECORD='^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+([+-][0-9]{4})? +[A-Za-z]{1,2} +SecurityAgent\[[0-9]+(:[0-9a-f]+)?\] '
# The texts with which security refuses an existing item to the asking
# account: an interaction or an authorization refusal.
DENIAL_TEXT='User interaction is not allowed|[Aa]uthorization was denied|[Nn]ot authorized|errSecInteractionNotAllowed|errSecAuthorizationDenied'

DATA_ROOT="$HOME_DIR/Library/Application Support/Soneso.stellar-agent"
KEYCHAIN="$HOME_DIR/Library/Keychains/login.keychain-db"
RECORD="" RPC_URL="" PROVIDERS="" POLICY="" CERT="" KEY="" BIND="" RP_ID=""
ENTRY_INDEX=0
ENTRY=""
SIGNER_PRESENT=no
STARTED=$(date '+%Y-%m-%d %H:%M:%S')

usage() {
  echo "usage: validate-macos.sh --record <dir> [--rpc-url <url>] [--providers <file>] [--policy <file>] [--cert <file>] [--key <file>] [--bind <addr>] [--rp-id <host>]" >&2
  exit 64
}

while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || usage
  case "$1" in
    --record) RECORD=$2 ;;
    --rpc-url) RPC_URL=$2 ;;
    --providers) PROVIDERS=$2 ;;
    --policy) POLICY=$2 ;;
    --cert) CERT=$2 ;;
    --key) KEY=$2 ;;
    --bind) BIND=$2 ;;
    --rp-id) RP_ID=$2 ;;
    *) usage ;;
  esac
  shift 2
done
[ -n "$RECORD" ] || usage
if [ -e "$RECORD" ]; then
  echo "validate-macos.sh: $RECORD exists; name a new record directory" >&2
  exit 64
fi
mkdir -m 700 "$RECORD"

# Starts entry $1: the next numbered file of the record directory.
entry() {
  ENTRY_INDEX=$((ENTRY_INDEX + 1))
  ENTRY=$(printf '%s/%02d-%s.txt' "$RECORD" "$ENTRY_INDEX" "$1")
  printf 'entry: %s\nhost: macOS\nstarted: %s\n' "$1" "$(date '+%Y-%m-%d %H:%M:%S')" >"$ENTRY"
  printf '== %s\n' "$1"
}

# Appends a line to the current entry.
note() {
  printf '%s\n' "$*" >>"$ENTRY"
}

# Prints the status of a finished step from its exit code $1 and output
# file $2. "not available" needs a positive sign that a native piece is
# missing: the shell found no command, or the wallet binary reported the
# verb or option unknown. Any other failure is refused or failed, and the
# record keeps its text.
status_of() {
  if [ "$1" -eq 0 ]; then
    echo ok
  elif [ "$1" -eq 127 ] || grep -qE 'command not found|unrecognized subcommand|unexpected argument' "$2"; then
    echo "not available"
  elif grep -q '^stellar-agent-wrapper: refused: ' "$2"; then
    echo refused
  else
    echo failed
  fi
}

# Runs "$@", a read attempt of the operator account on the wallet
# account's keyring, and records its exit code and standard error. With $1
# set to keep, the record also holds its standard output; with discard,
# the output never reaches the record or the terminal, since a read that
# succeeds prints the secret. A nonzero exit is a denial only with the
# denial text in standard error and SIGNER_PRESENT set to yes; a missing
# item or keychain, or any other error, leaves the result inconclusive.
read_attempt() {
  local keep=$1 errors output rc=0
  shift
  errors=$(mktemp "$RECORD/.step.XXXXXX")
  output=$(mktemp "$RECORD/.step.XXXXXX")
  note "command: $*"
  if [ "$keep" = keep ]; then
    "$@" >"$output" 2>"$errors" || rc=$?
  else
    "$@" >/dev/null 2>"$errors" || rc=$?
  fi
  note "exit: $rc"
  if [ "$rc" -eq 0 ]; then
    note "status: failed (the read succeeded)"
  elif [ "$rc" -eq 127 ] || grep -q 'command not found' "$errors"; then
    note "status: not available"
  elif ! grep -qE "$DENIAL_TEXT" "$errors"; then
    note "status: inconclusive (no access-denial text in standard error)"
  elif [ "$SIGNER_PRESENT" != yes ]; then
    note "status: inconclusive (the signer item is not shown present)"
  else
    note "status: denied"
  fi
  note "standard error:"
  sed 's/^/  /' "$errors" >>"$ENTRY"
  if [ "$keep" = keep ]; then
    note "standard output:"
    sed 's/^/  /' "$output" >>"$ENTRY"
  fi
  rm -f "$errors" "$output"
  printf 'read attempt exit %s\n' "$rc"
}

# Runs one step, "$@", and records its command, exit code, status, and
# output. The output also reaches the terminal, so prompts stay visible.
# Sets STEP_RC.
step() {
  local output
  output=$(mktemp "$RECORD/.step.XXXXXX")
  note "command: $*"
  set +e
  "$@" 2>&1 | tee "$output"
  STEP_RC=${PIPESTATUS[0]}
  set -e
  note "exit: $STEP_RC"
  note "status: $(status_of "$STEP_RC" "$output")"
  note "output:"
  sed 's/^/  /' "$output" >>"$ENTRY"
  rm -f "$output"
}

# Runs wrapper $1 with arguments $2... as the wallet account.
wallet() {
  local wrapper=$1
  shift
  "$SUDO" -n -u "$ACCOUNT" "$PREFIX/$wrapper" "$@"
}

# Runs wrapper $2... with standard input from file $1. The shell opens the
# file for the wrapper; the script never reads its content.
wallet_from() {
  local input=$1
  shift
  wallet "$@" <"$input"
}

# Records a skipped step that needs option $1.
skipped() {
  note "command: $2"
  note "status: skipped (no $1 given)"
}

# Asks the operator a question on the terminal and sets ANSWER. The answer
# is never a secret.
ask() {
  ANSWER=""
  printf '%s ' "$1" >&2
  IFS= read -r ANSWER <"$TTY_PATH" || true
}

# Prints the records of dump-keychain output file $1 whose service
# attribute starts with the wallet's service prefix.
wallet_items() {
  awk -v prefix="\"svce\"<blob>=\"$SERVICE_PREFIX" '
    /^keychain: / {
      if (keep) printf "%s", block
      block = ""
      keep = 0
    }
    { block = block $0 "\n" }
    index($0, prefix) { keep = 1 }
    END { if (keep) printf "%s", block }
  ' "$1"
}

# Records whether the wallet account's own access-list record holds the
# signer item, and sets SIGNER_PRESENT to yes when it does. The form runs
# security dump-keychain -a, which prints attributes and access lists only.
signer_presence() {
  local output errors rc=0
  output=$(mktemp "$RECORD/.step.XXXXXX")
  errors=$(mktemp "$RECORD/.step.XXXXXX")
  SIGNER_PRESENT=no
  note "command: $SUDO -n -u $ACCOUNT $PREFIX/cli-launch keychain-access-lists"
  wallet cli-launch keychain-access-lists >"$output" 2>"$errors" || rc=$?
  note "exit: $rc"
  if [ "$rc" -ne 0 ]; then
    note "status: $(status_of "$rc" "$errors")"
  elif wallet_items "$output" | grep -qF "\"svce\"<blob>=\"$SIGNER_SERVICE\""; then
    SIGNER_PRESENT=yes
    note "status: ok (the dump holds the $SIGNER_SERVICE item)"
  else
    note "status: failed (the dump holds no $SIGNER_SERVICE item)"
  fi
  note "standard error:"
  sed 's/^/  /' "$errors" >>"$ENTRY"
  rm -f "$output" "$errors"
  printf 'signer item present: %s\n' "$SIGNER_PRESENT"
}

# Records the access lists of the wallet's keychain items: the wallet
# account's keychain-access-lists form runs security dump-keychain -a,
# never with -d, -g, or -w, and the record keeps only the wallet's items.
access_lists() {
  local output errors items rc=0 count
  output=$(mktemp "$RECORD/.step.XXXXXX")
  errors=$(mktemp "$RECORD/.step.XXXXXX")
  items=$(mktemp "$RECORD/.step.XXXXXX")
  note "command: $SUDO -n -u $ACCOUNT $PREFIX/cli-launch keychain-access-lists"
  wallet cli-launch keychain-access-lists >"$output" 2>"$errors" || rc=$?
  wallet_items "$output" >"$items"
  count=$(grep -c '^keychain: ' "$items" || true)
  note "exit: $rc"
  if [ "$rc" -ne 0 ]; then
    note "status: $(status_of "$rc" "$errors")"
  elif [ "$count" -eq 0 ]; then
    note "status: failed (the dump holds no wallet item)"
  else
    note "status: ok ($count wallet items)"
  fi
  note "wallet items:"
  sed 's/^/  /' "$items" >>"$ENTRY"
  note "standard error:"
  sed 's/^/  /' "$errors" >>"$ENTRY"
  rm -f "$output" "$errors" "$items"
  printf 'access lists of %s wallet items\n' "$count"
}

# Records the keychain dialogs of the window from the start of the script
# to now. Each SecurityAgent event record matches an item-access dialog
# text, a password dialog text, or neither. The record keeps the matched
# records. No item-access prompt is ok only when the window shows readable
# SecurityAgent event records and none of them is redacted. Output without
# an event record, such as an empty one or the filter banner and column
# header alone, is inconclusive, and so is a redacted record.
dialog_counts() {
  local output events ended rc=0 lines readable redacted items passwords others
  ended=$(date '+%Y-%m-%d %H:%M:%S')
  output=$(mktemp "$RECORD/.step.XXXXXX")
  events=$(mktemp "$RECORD/.step.XXXXXX")
  note "window: $STARTED to $ended"
  note "command: log show --style compact --start '$STARTED' --end '$ended' --predicate 'process == \"SecurityAgent\"'"
  log show --style compact --start "$STARTED" --end "$ended" --predicate 'process == "SecurityAgent"' \
    >"$output" 2>&1 || rc=$?
  note "exit: $rc"
  if [ "$rc" -ne 0 ]; then
    note "status: $(status_of "$rc" "$output")"
    note "output:"
    sed 's/^/  /' "$output" >>"$ENTRY"
  else
    lines=$(wc -l <"$output" | tr -d ' ')
    grep -E "$EVENT_RECORD" "$output" >"$events" || true
    readable=$(grep -vcF '<private>' "$events" || true)
    redacted=$(grep -cF '<private>' "$events" || true)
    items=$(grep -cE "$ITEM_PROMPT" "$events" || true)
    passwords=$(grep -vE "$ITEM_PROMPT" "$events" | grep -cE "$PASSWORD_PROMPT" || true)
    others=$(grep -vE "$ITEM_PROMPT" "$events" | grep -vcE "$PASSWORD_PROMPT" || true)
    note "output lines: $lines"
    note "readable SecurityAgent lines: $readable"
    note "redacted SecurityAgent lines: $redacted"
    note "item-access prompts: $items"
    note "password prompts: $passwords"
    note "other SecurityAgent lines: $others"
    if [ "$items" -gt 0 ]; then
      note "status: failed (item-access prompts appeared)"
    elif [ "$readable" -eq 0 ]; then
      note "status: inconclusive (no dialog lines observed)"
    elif [ "$redacted" -gt 0 ]; then
      note "status: inconclusive (redacted dialog lines observed)"
    else
      note "status: ok (no item-access prompt)"
    fi
    note "prompt lines:"
    grep -E "$ITEM_PROMPT|$PASSWORD_PROMPT" "$events" | sed 's/^/  /' >>"$ENTRY" || true
  fi
  rm -f "$output" "$events"
  printf 'dialog counts recorded\n'
}

# Prints the CDHash that output $1 of codesign -dvvv reports, or nothing
# unless exactly one nonempty CDHash line is present.
single_cdhash() {
  local lines
  lines=$(printf '%s\n' "$1" | grep '^CDHash=' || true)
  if [ -n "$lines" ] && [ "$(printf '%s\n' "$lines" | wc -l | tr -d ' ')" -eq 1 ]; then
    printf '%s\n' "${lines#CDHash=}"
  fi
}

# Records whether the two installed names hold one executable: both exist
# as regular files, cmp finds equal bytes, and codesign -dvvv succeeds for
# each and reports one nonempty CDHash, equal for both. A missing file, a
# failed or unequal cmp, a failed codesign, or a missing or unequal CDHash
# records failed.
binary_identity() {
  local canonical="$PREFIX/bin/stellar-agent" alias="$PREFIX/bin/stellar-agent-mcp" output rc=0 file
  local hash first=""
  note "command: cmp $canonical $alias"
  if [ ! -f "$canonical" ] || [ ! -f "$alias" ]; then
    note "status: failed (an installed name is missing)"
    note "identity: failed"
    return 0
  fi
  output=$(cmp -- "$canonical" "$alias" 2>&1) || rc=$?
  note "exit: $rc"
  note "output:"
  printf '%s\n' "$output" | sed 's/^/  /' >>"$ENTRY"
  if [ "$rc" -ne 0 ]; then
    note "status: failed (the installed names differ or cmp failed)"
    note "identity: failed"
    return 0
  fi
  note "status: ok (equal bytes)"
  for file in "$canonical" "$alias"; do
    note "command: codesign -dvvv $file"
    rc=0
    output=$(codesign -dvvv "$file" 2>&1) || rc=$?
    note "exit: $rc"
    note "output:"
    printf '%s\n' "$output" | sed 's/^/  /' >>"$ENTRY"
    if [ "$rc" -ne 0 ]; then
      note "status: failed (codesign exited $rc)"
      note "identity: failed"
      return 0
    fi
    hash=$(single_cdhash "$output")
    if [ -z "$hash" ]; then
      note "status: failed (no single nonempty CDHash)"
      note "identity: failed"
      return 0
    fi
    note "status: ok (CDHash $hash)"
    if [ -z "$first" ]; then
      first=$hash
    elif [ "$hash" != "$first" ]; then
      note "status: failed (the CDHash values differ)"
      note "identity: failed"
      return 0
    fi
  done
  note "identity: ok"
}

# Prints the GUI login session of the wallet account; launchctl fails when
# there is none.
gui_session() {
  launchctl print "gui/$(id -u "$ACCOUNT")"
}

entry account
step id "$ACCOUNT"
step dscl . -read "/Users/$ACCOUNT" UserShell NFSHomeDirectory IsHidden
step dscl . -read "/Users/$ACCOUNT" AuthenticationAuthority

entry ownership
step ls -ld "$HOME_DIR"
step ls -ld "$PREFIX" "$PREFIX/bin"
step ls -l "$PREFIX" "$PREFIX/bin"
step ls -l "$PROJECT_FILE" "$SUDOERS_FILE"

entry binary-identity
binary_identity
PAIR_IDENTITY=$(tail -n 1 "$ENTRY")

entry refusal-64
step wallet cli-launch profile show --profile other

entry refusal-65
step wallet cli-launch profile show

entry keychain-unlock
step wallet cli-launch keychain-unlock

entry keychain-lock
step wallet cli-launch keychain-lock

entry keychain-unlock-again
step wallet cli-launch keychain-unlock

entry provisioning-order
if [ -n "$RPC_URL" ]; then
  step wallet provision profile init --network mainnet --rpc-url "$RPC_URL"
else
  skipped --rpc-url "provision profile init"
fi
step wallet provision profile rotate-audit-key
step wallet provision profile enroll-owner-key
step wallet provision profile enroll-signer
step wallet provision profile bind-signer
step wallet provision profile rotate-nonce-key
step wallet provision profile rotate-attestation-key
if [ -n "$PROVIDERS" ]; then
  step wallet_from "$PROVIDERS" provision providers
else
  skipped --providers "provision providers"
fi
if [ -n "$BIND" ] && [ -n "$RP_ID" ]; then
  step wallet provision remote-config --bind "$BIND" --rp-id "$RP_ID"
else
  skipped "--bind and --rp-id" "provision remote-config"
fi
if [ -n "$CERT" ]; then
  step wallet_from "$CERT" provision remote-cert
else
  skipped --cert "provision remote-cert"
fi
if [ -n "$KEY" ]; then
  step wallet_from "$KEY" provision remote-key
else
  skipped --key "provision remote-key"
fi
if [ -n "$POLICY" ]; then
  step wallet_from "$POLICY" provision policy-install
else
  skipped --policy "provision policy-install"
fi
step wallet provision profile sign-policy
step wallet cli-launch approve credential enroll --origin-from-installed
step wallet provision profile enable-mainnet
step wallet cli-launch profile enable-mainnet --state
step wallet cli-launch profile enable-mainnet --check

entry platform-read-write
step wallet provision profile rotate-nonce-key
step wallet cli-launch audit verify
step wallet cli-launch profile show

entry refusal-66
# The MCP server runs while this script holds its standard input open.
MCP_HOLD=$(mktemp "$RECORD/.mcp.XXXXXX")
MCP_INPUT="$RECORD/.mcp-input"
mkfifo -m 600 "$MCP_INPUT"
wallet mcp-launch <"$MCP_INPUT" >"$MCP_HOLD" 2>&1 &
MCP_JOB=$!
exec 7>"$MCP_INPUT"
sleep "$SETTLE_SECONDS"
step wallet cli-launch approve serve --open-by-operator
exec 7>&-
wait "$MCP_JOB" 2>/dev/null || true
note "mcp-launch output while held:"
sed 's/^/  /' "$MCP_HOLD" >>"$ENTRY"
rm -f "$MCP_HOLD" "$MCP_INPUT"

entry mcp-stdio
REQUEST='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"validate-macos","version":"1"}}}'
MCP_OUT=$(mktemp "$RECORD/.mcp.XXXXXX")
MCP_ERR=$(mktemp "$RECORD/.mcp-stderr.XXXXXX")
note "command: printf <initialize> | $SUDO -n -u $ACCOUNT $PREFIX/mcp-launch"
set +e
{ printf '%s\n' "$REQUEST"; sleep "$RESPONSE_SECONDS"; } | wallet mcp-launch >"$MCP_OUT" 2>"$MCP_ERR"
MCP_RC=$?
set -e
note "exit: $MCP_RC"
if head -n 1 "$MCP_OUT" | grep -q '"jsonrpc"'; then
  note "status: ok (the first standard output line is a JSON-RPC message)"
else
  note "status: failed (no JSON-RPC message on standard output)"
fi
note "first line: $(head -n 1 "$MCP_OUT")"
note "mcp-launch standard error:"
sed 's/^/  /' "$MCP_ERR" >>"$ENTRY"
rm -f "$MCP_OUT" "$MCP_ERR"

entry cross-user-file-denial
step cat "$DATA_ROOT/profiles/mainnet.toml"
step ls "$HOME_DIR"

entry cross-user-keyring-denial
# The wallet account's access-list record shows first whether the signer
# item exists. The operator account then asks the wallet account's
# keychain for it without -g or -w, so even a read that succeeds prints
# attributes only.
signer_presence
read_attempt keep "$SECURITY" find-generic-password -s "$SIGNER_SERVICE" "$KEYCHAIN"

entry approval-round-trip
ask "Create a pending approval through the MCP client, then enter its approval id (empty skips):"
if [ -n "$ANSWER" ]; then
  step wallet cli-launch approve --id "$ANSWER" --open-by-operator
  if [ "$STEP_RC" -ne 0 ]; then
    step wallet cli-launch approve --id "$ANSWER"
  fi
else
  skipped "approval id" "cli-launch approve --id <id> --open-by-operator"
fi

entry access-lists
access_lists

entry designated-requirement
step codesign -d -r- "$PREFIX/bin/stellar-agent"
step codesign -d -r- "$PREFIX/bin/stellar-agent-mcp"

entry signed-upgrade
step codesign -d -r- "$PREFIX/bin/stellar-agent"
ask "Rerun bootstrap.sh with the newly signed binaries, then press Enter (type skip to skip):"
if [ "$ANSWER" = skip ]; then
  skipped "upgrade" "bootstrap.sh with newly signed binaries"
else
  step codesign -d -r- "$PREFIX/bin/stellar-agent"
  step wallet cli-launch audit verify
fi

entry dialog-counts
dialog_counts

entry no-desktop-session
step gui_session
step who

printf 'validate-macos.sh: %s entries in %s\n' "$ENTRY_INDEX" "$RECORD"
# An unequal installed pair fails the run after every entry is recorded.
if [ "$PAIR_IDENTITY" != "identity: ok" ]; then
  echo "validate-macos.sh: $PREFIX/bin/stellar-agent and $PREFIX/bin/stellar-agent-mcp are not one executable; run bootstrap again with the same --cli source" >&2
  exit 1
fi
