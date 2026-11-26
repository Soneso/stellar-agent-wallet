#!/usr/bin/env bash
# Verify all six bundles against the exact release bytes and workflow claims.
set -euo pipefail
if [ "$#" -ne 4 ]; then
  echo 'usage: verify-signatures.sh <release-dir> <certificate-identity> <oidc-issuer> <workflow-sha>' >&2
  exit 2
fi
for claim in "$2" "$3" "$4"; do
  if [ -z "$claim" ]; then
    echo 'verify-signatures: identity, issuer and workflow SHA must be non-empty' >&2
    exit 2
  fi
done
script_dir=$(cd "$(dirname "$0")" && pwd)
bash "$script_dir/verify-sums.sh" "$1"
python3 - "$@" <<'PY'
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
files = {p.name: p for p in (root / 'all-artifacts').rglob('*')
         if p.name.endswith(('.tar.xz', '.zip'))}
files['SHA256SUMS'] = root / 'release-combined/SHA256SUMS'
bundles = {p.name: p for p in (root / 'all-signatures').rglob('*.sigstore.json')}
for name, path in sorted(files.items()):
    try:
        subprocess.run(['cosign', 'verify-blob', '--bundle', str(bundles[name + '.sigstore.json']),
                        '--certificate-identity', sys.argv[2], '--certificate-oidc-issuer', sys.argv[3],
                        '--certificate-github-workflow-sha', sys.argv[4], str(path)], check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        sys.exit(f'verify-signatures: {name}: {error}')
PY
