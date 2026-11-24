#!/usr/bin/env python3
"""Content assertions using the public alpha.12 predicate and checksums.

--checker names the checker the assertions load. --mutations then changes
one build-configuration check at a time in a scratch copy of
check-provenance.py, requires the assertion each mutation names to fail
against the copy, and requires the assertions to pass once the copy holds
the unchanged checker again.
"""
import argparse
import base64
import contextlib
import copy
import importlib.util
import io
import json
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FIXTURE = HERE / 'fixtures/stellar-agent-0.1.0-alpha.12.intoto.jsonl'
SUMMARY = ('provenance: builder, source, subjects and build type match, '
           'the parameters hold only string vars, and the environment is empty\n')
# The values each build-configuration field refuses; 'missing' removes the
# field. The parameters accept a vars mapping of strings of any size.
REFUSED = (
    ('buildType', ('unknown', None, {}, [])),
    ('parameters', ({}, {'vars': {}, 'inputs': {}}, {'vars': []}, {'vars': {'TESTNET_SCHEDULE': 1}}, None, [])),
    ('environment', ({'RUSTFLAGS': '--cfg feature="mainnet-write"'}, {'extra': ''}, None, [])),
)
ACCEPTED_PARAMETERS = ({'vars': {}}, {'vars': {'TESTNET_SCHEDULE': 'off'}})
CONFIGURATION = 'provenance-build-configuration'
# Each mutation of check-provenance.py: the text it replaces, the
# replacement, and the assertion whose failure proves the check.
MUTATIONS = {
    'provenance-buildType': (
        "if predicate.get('buildType') != BUILD_TYPE:", 'if False:',
        f"{CONFIGURATION}: buildType='unknown': accepted"),
    'provenance-parameters': (
        "check_parameters(predicate['invocation'].get('parameters'))", 'pass',
        f'{CONFIGURATION}: parameters={{}}: accepted'),
    'provenance-environment': (
        "if predicate['invocation'].get('environment') != {}:", 'if False:',
        f"{CONFIGURATION}: environment={{'RUSTFLAGS': '--cfg feature=\"mainnet-write\"'}}: accepted"),
    'provenance-summary': (
        "print('provenance: builder, source, subjects and build type match, '\n"
        "          'the parameters hold only string vars, and the environment is empty')",
        "print('provenance: builder, source and subjects match')",
        f'{CONFIGURATION}: success summary differs'),
    'provenance-parameters-exact': (
        "check_parameters(predicate['invocation'].get('parameters'))",
        "if predicate['invocation'].get('parameters') != {'vars': {}}:\n"
        "        raise ValueError('invocation.parameters differs')",
        f"{CONFIGURATION}: parameters={{'vars': {{'TESTNET_SCHEDULE': 'off'}}}}: refused"),
    'provenance-parameters-keys': (
        "if set(parameters) != {'vars'}:", "if 'vars' not in parameters:",
        f"{CONFIGURATION}: parameters={{'vars': {{}}, 'inputs': {{}}}}: accepted"),
    'provenance-parameters-mapping': (
        'if not isinstance(variables, dict):', 'if False:',
        f"{CONFIGURATION}: parameters={{'vars': []}}: raised AttributeError"),
    'provenance-parameters-strings': (
        'if not all(isinstance(name, str) and isinstance(value, str) for name, value in variables.items()):',
        'if False:', f"{CONFIGURATION}: parameters={{'vars': {{'TESTNET_SCHEDULE': 1}}}}: accepted"),
    'provenance-parameters-sorted': (
        "unexpected = sorted(str(key) for key in parameters if key != 'vars')",
        "unexpected = [str(key) for key in parameters if key != 'vars']",
        f'{CONFIGURATION}: unexpected keys diagnostic differs'),
}


def load(path):
    spec = importlib.util.spec_from_file_location('provenance', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def with_field(document, field, value):
    """The bundle with one build-configuration field set, or removed for 'missing'."""
    wrapped = copy.deepcopy(document)
    statement = json.loads(base64.b64decode(wrapped['dsseEnvelope']['payload']))
    parent = statement['predicate'] if field == 'buildType' else statement['predicate']['invocation']
    if value == 'missing':
        del parent[field]
    else:
        parent[field] = value
    wrapped['dsseEnvelope']['payload'] = base64.b64encode(json.dumps(statement).encode()).decode()
    return wrapped


def configuration(module, checker, document, sums, sha, repository, ref):
    module.check(document, sums, sha, repository, ref)
    for field, values in REFUSED:
        for value in (*values, 'missing'):
            label = f'{CONFIGURATION}: {field}={value!r}'
            try:
                module.check(with_field(document, field, value), sums, sha, repository, ref)
            except ValueError as error:
                assert field in str(error), f'{label}: diagnostic lacks {field}: {error}'
            except Exception as error:
                raise AssertionError(f'{label}: raised {type(error).__name__}') from None
            else:
                raise AssertionError(f'{label}: accepted')
    for value in ACCEPTED_PARAMETERS:
        try:
            module.check(with_field(document, 'parameters', value), sums, sha, repository, ref)
        except ValueError as error:
            raise AssertionError(f'{CONFIGURATION}: parameters={value!r}: refused: {error}') from None
    try:
        module.check(with_field(document, 'parameters', {'vars': {}, 'zeta': '', 'inputs': {}}),
                     sums, sha, repository, ref)
    except ValueError as error:
        assert str(error) == 'invocation.parameters holds unexpected keys: inputs, zeta', \
            f'{CONFIGURATION}: unexpected keys diagnostic differs: {error}'
    else:
        raise AssertionError(f'{CONFIGURATION}: unexpected keys accepted')
    argv, output = sys.argv, io.StringIO()
    try:
        sys.argv = [str(checker), str(FIXTURE), str(HERE / 'fixtures/SHA256SUMS'), sha, repository, ref]
        with contextlib.redirect_stdout(output):
            result = module.main()
    finally:
        sys.argv = argv
    assert result == 0 and output.getvalue() == SUMMARY, f'{CONFIGURATION}: success summary differs'
    print(f'ok {CONFIGURATION}')


def named_mutations(checker):
    """Each mutation fails its named assertion; the restored copy passes."""
    source = checker.read_text()
    (ROOT / 'target/tmp').mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=ROOT / 'target/tmp') as scratch:
        for name, (needle, replacement, assertion) in MUTATIONS.items():
            assert source.count(needle) == 1, f'{name}: mutation target differs'
            path = pathlib.Path(scratch) / (name + '.py')
            for phase, text in (('mutation', source.replace(needle, replacement, 1)), ('control', source)):
                path.write_text(text)
                path.touch()
                result = subprocess.run([sys.executable, '-B', str(pathlib.Path(__file__).resolve()),
                                         '--checker', str(path)], text=True, capture_output=True)
                if phase == 'mutation':
                    assert result.returncode == 1 and 'FAIL ' + assertion in result.stderr, \
                        f'{name}: expected assertion does not fail: {result.stdout}\n{result.stderr}'
                    print(f'ok mutation-{name}: {result.stderr.strip()}')
                else:
                    assert result.returncode == 0, f'{name}: control fails: {result.stdout}\n{result.stderr}'
                    print(f'ok control-{name}')


def assertions(module, checker):
    document = json.loads(FIXTURE.read_text())
    sums = (HERE / 'fixtures/SHA256SUMS').read_text()
    envelope = document['dsseEnvelope']
    statement = json.loads(base64.b64decode(envelope['payload']))
    source = statement['predicate']['invocation']['configSource']
    sha = source['digest']['sha1']
    repository, ref = re.fullmatch(r'git\+https://github\.com/([^@]+)@(.+)', source['uri']).groups()
    module.check(document, sums, sha, repository, ref)
    configuration(module, checker, document, sums, sha, repository, ref)
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
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutations', action='store_true')
    parser.add_argument('--checker', type=pathlib.Path, default=HERE / 'check-provenance.py')
    args = parser.parse_args()
    try:
        result = assertions(load(args.checker), args.checker)
        if result == 0 and args.mutations:
            named_mutations(args.checker)
    except AssertionError as error:
        print(f'FAIL {error}', file=sys.stderr)
        return 1
    if result == 0:
        print('provenance tests passed')
    return result


if __name__ == '__main__':
    sys.exit(main())
