#!/bin/bash
# Refuses to sign unless every tool the signing job runs exists at its
# absolute path on the runner image. The signing steps call each tool by
# this path and never through PATH.
set -euo pipefail

missing=0
for tool in /bin/bash /bin/chmod /bin/cp /bin/mkdir /bin/rm \
  /usr/bin/awk /usr/bin/base64 /usr/bin/codesign /usr/bin/find /usr/bin/git /usr/bin/grep \
  /usr/bin/lipo /usr/bin/sort \
  /usr/bin/python3 /usr/bin/security /usr/bin/tar /usr/bin/xcrun /usr/bin/zip; do
  if [ ! -x "$tool" ]; then
    echo "required tool missing: $tool" >&2
    missing=1
  fi
done
exit "$missing"
