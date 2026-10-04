#!/bin/bash
# Removes the signing keychain and every decoded key file. The action runs it
# after the signing steps whatever their outcome.
set -uo pipefail

# shellcheck source=SCRIPTDIR/common.sh
. "${BASH_SOURCE[0]%/*}/common.sh"

remove_signing_files
