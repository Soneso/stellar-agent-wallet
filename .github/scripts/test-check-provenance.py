#!/usr/bin/env python3
"""Content assertions using the public alpha.12 predicate and checksums."""
import base64
import copy
import importlib.util
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('provenance', HERE / 'check-provenance.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def main():
    document = json.loads((HERE / 'fixtures/stellar-agent-0.1.0-alpha.12.intoto.jsonl').read_text())
    sums = (HERE / 'fixtures/SHA256SUMS').read_text()
    envelope = document['dsseEnvelope']
    statement = json.loads(base64.b64decode(envelope['payload']))
    source = statement['predicate']['invocation']['configSource']
    sha = source['digest']['sha1']
    repository, ref = re.fullmatch(r'git\+https://github\.com/([^@]+)@(.+)', source['uri']).groups()
    module.check(document, sums, sha, repository, ref)
    cases = {
        'predicate': lambda s: s.update(predicateType='unknown'),
        'builder': lambda s: s['predicate']['builder'].update(id='unknown'),
        'entry-point': lambda s: s['predicate']['invocation']['configSource'].update(entryPoint='other.yml'),
        'commit': lambda s: s['predicate']['invocation']['configSource']['digest'].update(sha1='0' * 40),
        'source-uri': lambda s: s['predicate']['invocation']['configSource'].update(
            uri=f'git+https://github.com/other/fork@{ref}'),
        'materials': lambda s: s['predicate'].update(materials=[]),
        'subjects': lambda s: s['subject'].pop(),
        'digest': lambda s: s['subject'][0]['digest'].update(sha256='0' * 64),
        'duplicate-subject': lambda s: s['subject'].append(s['subject'][0]),
    }
    for name, mutate in cases.items():
        changed = copy.deepcopy(statement)
        mutate(changed)
        wrapped = copy.deepcopy(document)
        wrapped['dsseEnvelope']['payload'] = base64.b64encode(json.dumps(changed).encode()).decode()
        try:
            module.check(wrapped, sums, sha, repository, ref)
        except ValueError:
            print(f'ok {name}')
        else:
            print(f'FAIL {name}: accepted altered provenance', file=sys.stderr)
            return 1
    # A commit that is not 40 lower-case hex digits fails even when the
    # predicate names the same value.
    short = copy.deepcopy(statement)
    short['predicate']['invocation']['configSource']['digest']['sha1'] = sha[:12]
    short['predicate']['materials'][0]['digest']['sha1'] = sha[:12]
    wrapped = copy.deepcopy(document)
    wrapped['dsseEnvelope']['payload'] = base64.b64encode(json.dumps(short).encode()).decode()
    for name, altered, checksum, commit, tag in [
        ('payload-type', {'dsseEnvelope': {**envelope, 'payloadType': 'unknown'}}, sums, sha, ref),
        ('envelope-key', envelope, sums, sha, ref),
        ('commit-shape', wrapped, sums, sha[:12], ref),
        ('tag-ref', document, sums, sha, 'refs/tags/v0.0.0'),
        ('checksum-duplicate', document, sums + sums.splitlines()[0] + '\n', sha, ref),
        ('checksum-invalid', document, 'invalid\n', sha, ref),
        ('checksum-empty', document, '', sha, ref),
    ]:
        try:
            module.check(altered, checksum, commit, repository, tag)
        except ValueError:
            print(f'ok {name}')
        else:
            print(f'FAIL {name}: accepted altered provenance', file=sys.stderr)
            return 1
    print('provenance tests passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
