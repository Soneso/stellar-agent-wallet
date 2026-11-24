#!/usr/bin/env python3
"""Check the release predicate and exact subject set of a provenance bundle.

The input is the Sigstore bundle that the SLSA generator writes as the
release's .intoto.jsonl asset; any other shape fails. This checks content,
not signatures: docs/verifying-releases.md describes signature
verification. The predicate must name the generator at v2.1.0, the release
workflow, the repository, tag and commit the job passes, and a material at
that commit, and its subjects must equal SHA256SUMS. Its build type is the
generator's generic one. Its environment is an object with exactly the 15
keys in ENVIRONMENT_KEYS. The github_sha1, github_ref and
github_repository_owner values match the commit, ref and repository owner
arguments; github_ref_type is tag and github_event_name is push. Other
environment values vary per run and are not compared. Its parameters hold
only the vars context, a mapping of names to string values.
The release workflow, the workflows it calls and its local actions
never read that context, which check-workflow-invariants.py enforces.
"""
import argparse
import base64
import json
import pathlib
import re
import sys

BUILDER = ('https://github.com/slsa-framework/slsa-github-generator/'
           '.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0')
BUILD_TYPE = 'https://github.com/slsa-framework/slsa-github-generator/generic@v1'
ENVIRONMENT_KEYS = {
    'github_actor', 'github_actor_id', 'github_base_ref', 'github_event_name',
    'github_event_payload', 'github_head_ref', 'github_ref', 'github_ref_type',
    'github_repository_id', 'github_repository_owner', 'github_repository_owner_id',
    'github_run_attempt', 'github_run_id', 'github_run_number', 'github_sha1',
}


def check_parameters(parameters):
    """The parameters are a mapping whose only key is vars, itself a mapping
    of strings to strings of any size."""
    if not isinstance(parameters, dict):
        raise ValueError('invocation.parameters is not a mapping')
    if set(parameters) != {'vars'}:
        unexpected = sorted(str(key) for key in parameters if key != 'vars')
        if unexpected:
            raise ValueError('invocation.parameters holds unexpected keys: ' + ', '.join(unexpected))
        raise ValueError('invocation.parameters lacks vars')
    variables = parameters['vars']
    if not isinstance(variables, dict):
        raise ValueError('invocation.parameters vars is not a mapping')
    if not all(isinstance(name, str) and isinstance(value, str) for name, value in variables.items()):
        raise ValueError('invocation.parameters vars holds a name or value that is not a string')


def check_environment(environment, sha, repository, ref):
    """The environment has the generator's keys and the expected tag push identity."""
    if not isinstance(environment, dict):
        raise ValueError('invocation.environment is not a mapping')
    if set(environment) != ENVIRONMENT_KEYS:
        raise ValueError('invocation.environment keys differ')
    expected = {
        'github_sha1': sha,
        'github_ref': ref,
        'github_ref_type': 'tag',
        'github_event_name': 'push',
        'github_repository_owner': repository.split('/', 1)[0],
    }
    for key, value in expected.items():
        if environment[key] != value:
            raise ValueError(f'invocation.environment {key} differs')


def check(document, sums, sha, repository, ref):
    envelope = document.get('dsseEnvelope') if isinstance(document, dict) else None
    if not isinstance(envelope, dict):
        raise ValueError('not a Sigstore bundle with a DSSE envelope')
    if envelope['payloadType'] != 'application/vnd.in-toto+json':
        raise ValueError('payload type differs')
    statement = json.loads(base64.b64decode(envelope['payload'], validate=True))
    if statement['predicateType'] != 'https://slsa.dev/provenance/v0.2':
        raise ValueError('predicate type differs')
    predicate = statement['predicate']
    if predicate['builder']['id'] != BUILDER:
        raise ValueError('builder differs')
    if predicate.get('buildType') != BUILD_TYPE:
        raise ValueError('buildType differs')
    check_parameters(predicate['invocation'].get('parameters'))
    check_environment(predicate['invocation'].get('environment'), sha, repository, ref)
    source = predicate['invocation']['configSource']
    if source['entryPoint'] != '.github/workflows/release.yml':
        raise ValueError('entry point differs')
    uri = f'git+https://github.com/{repository}@{ref}'
    if source['uri'] != uri:
        raise ValueError('source repository or ref differs')
    if not re.fullmatch(r'[0-9a-f]{40}', sha) or source['digest']['sha1'] != sha:
        raise ValueError('source commit differs')
    if {'uri': uri, 'digest': {'sha1': sha}} not in predicate['materials']:
        raise ValueError('materials lack the source at the commit')
    expected = {}
    for line in sums.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64}) [ *]([^/\\]+)', line)
        if match is None or match[2] in expected:
            raise ValueError('invalid or duplicate checksum')
        expected[match[2]] = {'sha256': match[1]}
    subjects = statement['subject']
    actual = {subject['name']: subject['digest'] for subject in subjects}
    if not expected or len(actual) != len(subjects) or actual != expected:
        raise ValueError('subjects differ from SHA256SUMS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=pathlib.Path)
    parser.add_argument('sums', type=pathlib.Path)
    parser.add_argument('sha')
    parser.add_argument('repository', help='owner/name, as GITHUB_REPOSITORY holds it')
    parser.add_argument('ref', help='the tag ref, as GITHUB_REF holds it')
    args = parser.parse_args()
    try:
        check(json.loads(args.bundle.read_text()), args.sums.read_text(), args.sha,
              args.repository, args.ref)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f'provenance: {error}', file=sys.stderr)
        return 1
    print('provenance: builder, source, subjects and build type match, '
          'the parameters hold only string vars, and the environment has exactly '
          'the 15 generator keys with matching commit, ref and repository owner '
          'and a tag push event')
    return 0


if __name__ == '__main__':
    sys.exit(main())
