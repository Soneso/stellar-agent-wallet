#!/usr/bin/env bash
# Five publication archives match SHA256SUMS; all six bundles are regular files.
set -euo pipefail
if [ "$#" -ne 1 ]; then
  echo 'usage: verify-sums.sh <release-dir>' >&2
  exit 2
fi
python3 - "$1" <<'PY'
import hashlib
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
try:
    sums = root / 'release-combined/SHA256SUMS'
    if sums.is_symlink() or not sums.is_file():
        raise ValueError('SHA256SUMS is not a regular file')
    expected = {}
    for line in sums.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]{64}) [ *]([^/\\]+\.(?:tar\.xz|zip))', line)
        if not match:
            raise ValueError('invalid SHA256SUMS entry')
        digest, name = match.groups()
        if name in expected:
            raise ValueError(f'duplicate SHA256SUMS name: {name}')
        expected[name] = digest.lower()
    if len(expected) != 5:
        raise ValueError('SHA256SUMS must list exactly five archives')
    archives = {}
    for path in (root / 'all-artifacts').rglob('*'):
        if path.name.endswith(('.tar.xz', '.zip')):
            if path.is_symlink() or not path.is_file():
                raise ValueError(f'archive is not a regular file: {path.name}')
            if path.name in archives:
                raise ValueError(f'duplicate archive name: {path.name}')
            archives[path.name] = path
    if archives.keys() != expected.keys():
        missing = sorted(expected.keys() - archives.keys())
        extra = sorted(archives.keys() - expected.keys())
        raise ValueError(f'archive set differs: missing={missing}, extra={extra}')
    for name, path in archives.items():
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != expected[name]:
            raise ValueError(f'SHA-256 differs: {name}')
    bundles = {}
    for path in (root / 'all-signatures').rglob('*.sigstore.json'):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f'bundle is not a regular file: {path.name}')
        if path.name in bundles:
            raise ValueError(f'duplicate bundle name: {path.name}')
        bundles[path.name] = path
    wanted = {name + '.sigstore.json' for name in (*expected, 'SHA256SUMS')}
    if bundles.keys() != wanted:
        raise ValueError(f'bundle set differs: missing={sorted(wanted - bundles.keys())}, '
                         f'extra={sorted(bundles.keys() - wanted)}')
except (OSError, UnicodeError, ValueError) as error:
    sys.exit(f'verify-sums: {error}')
print(f'verify-sums: {len(archives)} archives match SHA256SUMS')
PY
