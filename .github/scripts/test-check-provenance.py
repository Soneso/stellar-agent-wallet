#!/usr/bin/env python3
"""Content assertions using the synthetic alpha.12 predicate fixture and checksums.

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
import hashlib
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
           'the parameters hold only string vars, and the environment has exactly '
           'the 15 generator keys with matching commit, ref and repository owner '
           'and a tag push event\n')
# The values each build-configuration field refuses; 'missing' removes the
# field. The parameters accept a vars mapping of strings of any size.
REFUSED = (
    ('buildType', ('unknown', None, {}, [])),
    ('parameters', ({}, {'vars': {}, 'inputs': {}}, {'vars': []}, {'vars': {'TESTNET_SCHEDULE': 1}}, None, [])),
    ('environment', ({'RUSTFLAGS': '--cfg feature="mainnet-write"'}, {'extra': ''}, None, [], {}, 'invalid', 1, False)),
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
        "check_environment(predicate['invocation'].get('environment'), sha, repository, ref)", 'pass',
        f"{CONFIGURATION}: environment={{'RUSTFLAGS': '--cfg feature=\"mainnet-write\"'}}: accepted"),
    'provenance-environment-mapping': (
        'if not isinstance(environment, dict):', 'if False:',
        f'{CONFIGURATION}: environment=None: raised TypeError'),
    'provenance-environment-missing-key': (
        'if set(environment) != ENVIRONMENT_KEYS:',
        "if set(environment) not in (ENVIRONMENT_KEYS, ENVIRONMENT_KEYS - {'github_actor'}):",
        f'{CONFIGURATION}: environment-missing-key: accepted'),
    'provenance-environment-extra-key': (
        'if set(environment) != ENVIRONMENT_KEYS:',
        "if set(environment) not in (ENVIRONMENT_KEYS, ENVIRONMENT_KEYS | {'extra'}):",
        f'{CONFIGURATION}: environment-extra-key: accepted'),
    'provenance-environment-sha1': (
        "        'github_sha1': sha,\n", '',
        f'{CONFIGURATION}: environment-github_sha1: accepted'),
    'provenance-environment-ref': (
        "        'github_ref': ref,\n", '',
        f'{CONFIGURATION}: environment-github_ref: accepted'),
    'provenance-environment-ref-type': (
        "        'github_ref_type': 'tag',\n", '',
        f'{CONFIGURATION}: environment-github_ref_type: accepted'),
    'provenance-environment-event-name': (
        "        'github_event_name': 'push',\n", '',
        f'{CONFIGURATION}: environment-github_event_name: accepted'),
    'provenance-environment-owner': (
        "        'github_repository_owner': repository.split('/', 1)[0],\n", '',
        f'{CONFIGURATION}: environment-github_repository_owner: accepted'),
    'provenance-environment-variable-values': (
        "        'github_sha1': sha,\n",
        "        'github_sha1': sha,\n        'github_actor': 'example-actor',\n",
        f'{CONFIGURATION}: environment-variable-values: refused'),
    'provenance-summary': (
        "print('provenance: builder, source, subjects and build type match, '\n"
        "          'the parameters hold only string vars, and the environment has exactly '\n"
        "          'the 15 generator keys with matching commit, ref and repository owner '\n"
        "          'and a tag push event')",
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


BINDING_CASES = (
    ('other-run', '2002', '1', None, 'provenance run ID differs'),
    ('future-attempt', '2001', '1', '2', 'provenance run attempt exceeds latest attempt'),
    ('equal-attempt', '2001', '1', None, None),
    ('lower-attempt', '2001', '2', None, None),
    ('decimal-future-attempt', '2001', '2', '10', 'provenance run attempt exceeds latest attempt'),
    ('decimal-lower-attempt', '2001', '10', '2', None),
    ('invalid-attempt', '2001', '2', '0', 'run binding needs positive decimal strings'),
    ('missing-latest', '2001', None, None, 'run binding needs positive decimal strings'),
    ('missing-run', None, '1', None, 'run binding needs positive decimal strings'),
    ('integer-attempt', '2001', '2', 1, 'run binding needs positive decimal strings'),
)
for name, needle, replacement, assertion in (
    ('other-run', "if environment['github_run_id'] != run_id:", 'if False:', 'accepted'),
    ('future-attempt', "if int(environment['github_run_attempt']) > int(run_attempt):", 'if False:', 'accepted'),
    ('equal-attempt', "if int(environment['github_run_attempt']) > int(run_attempt):",
     "if int(environment['github_run_attempt']) >= int(run_attempt):", 'refused'),
    ('lower-attempt', "if int(environment['github_run_attempt']) > int(run_attempt):",
     "if int(environment['github_run_attempt']) != int(run_attempt):", 'refused'),
    ('decimal-future-attempt', "if int(environment['github_run_attempt']) > int(run_attempt):",
     "if environment['github_run_attempt'] > run_attempt:", 'accepted'),
    ('decimal-lower-attempt', "if int(environment['github_run_attempt']) > int(run_attempt):",
     "if environment['github_run_attempt'] > run_attempt:", 'refused'),
    ('invalid-attempt', "re.fullmatch(r'[1-9][0-9]*', value)", "re.fullmatch(r'[0-9]+', value)", 'accepted'),
    ('integer-attempt', "isinstance(value, str) and re.fullmatch(r'[1-9][0-9]*', value)",
     "re.fullmatch(r'[1-9][0-9]*', str(value))", 'accepted'),
    ('missing-run', 'if run_id is not None or run_attempt is not None:', 'if run_id is not None:', 'accepted'),
    ('missing-latest', 'if run_id is not None or run_attempt is not None:', 'if run_attempt is not None:', 'accepted'),
):
    MUTATIONS['binding-' + name] = (needle, replacement, f'run-binding {name}: {assertion}', name)
MUTATIONS['binding-cli'] = ('args.repository, args.ref, args.run_id, args.run_attempt)',
                          'args.repository, args.ref)', 'run-binding cli: accepted', 'cli')


def run_binding(module, checker, document, sums, sha, repository, ref, selected):
    environment = json.loads(base64.b64decode(document['dsseEnvelope']['payload']))['predicate']['invocation']['environment']
    for name, run_id, latest, attempt, expected in BINDING_CASES:
        if selected and selected != name:
            continue
        wrapped = document if attempt is None else with_field(document, 'environment',
                                                               {**environment, 'github_run_attempt': attempt})
        try:
            module.check(wrapped, sums, sha, repository, ref, run_id, latest)
        except ValueError as error:
            assert expected is not None, f'run-binding {name}: refused: {error}'
            assert str(error) == expected, f'run-binding {name}: diagnostic differs: {error}'
        else:
            assert expected is None, f'run-binding {name}: accepted'
        print(f'ok run-binding {name}')
    if selected in (None, 'cli'):
        argv, errors = sys.argv, io.StringIO()
        try:
            sys.argv = [str(checker), str(FIXTURE), str(HERE / 'fixtures/SHA256SUMS'), sha, repository, ref,
                        '--run-id', '2002', '--run-attempt', '1']
            with contextlib.redirect_stderr(errors):
                result = module.main()
        finally:
            sys.argv = argv
        assert result == 1 and errors.getvalue() == 'provenance: provenance run ID differs\n', \
            'run-binding cli: accepted'
        print('ok run-binding cli')


def load(path):
    spec = importlib.util.spec_from_file_location('provenance', path)
    module = importlib.util.module_from_spec(spec)
    # Mutation and control loads use current source even when cached timestamps match.
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
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


def environment_configuration(module, document, sums, sha, repository, ref):
    statement = json.loads(base64.b64decode(document['dsseEnvelope']['payload']))
    environment = statement['predicate']['invocation']['environment']
    mismatches = {
        'github_sha1': '0' * 40,
        'github_ref': 'refs/tags/v0.0.0',
        'github_ref_type': 'branch',
        'github_event_name': 'workflow_dispatch',
        'github_repository_owner': 'other-owner',
    }
    cases = {key: ({**environment, key: value}, f'{key} differs')
             for key, value in mismatches.items()}
    cases['missing-key'] = ({key: value for key, value in environment.items()
                             if key != 'github_actor'}, 'keys differ')
    cases['extra-key'] = ({**environment, 'extra': ''}, 'keys differ')
    for name, (value, reason) in cases.items():
        label = f'{CONFIGURATION}: environment-{name}'
        try:
            module.check(with_field(document, 'environment', value), sums, sha, repository, ref)
        except ValueError as error:
            assert str(error) == f'invocation.environment {reason}', f'{label}: diagnostic differs: {error}'
        else:
            raise AssertionError(f'{label}: accepted')
        print(f'ok environment-{name}')
    variable_environment = {key: value if key in mismatches else 'synthetic-variable'
                            for key, value in environment.items()}
    try:
        module.check(with_field(document, 'environment', variable_environment), sums, sha, repository, ref)
    except ValueError as error:
        raise AssertionError(f'{CONFIGURATION}: environment-variable-values: refused: {error}') from None
    print('ok environment-variable-values')


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
    environment_configuration(module, document, sums, sha, repository, ref)
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
        for name, mutation in MUTATIONS.items():
            needle, replacement, assertion, *case = mutation
            assert source.count(needle) == 1, f'{name}: mutation target differs'
            path = pathlib.Path(scratch) / (name + '.py')
            for phase, text in (('mutation', source.replace(needle, replacement, 1)), ('control', source)):
                path.write_text(text)
                path.touch()
                if phase == 'control':
                    assert hashlib.md5(path.read_bytes()).digest() == hashlib.md5(source.encode()).digest()
                result = subprocess.run([sys.executable, '-B', str(pathlib.Path(__file__).resolve()),
                                         '--checker', str(path)] + (['--case', case[0]] if case else []), text=True, capture_output=True)
                if phase == 'mutation':
                    assert result.returncode == 1 and 'FAIL ' + assertion in result.stderr, \
                        f'{name}: expected assertion does not fail: {result.stdout}\n{result.stderr}'
                    print(f'ok mutation-{name}: {result.stderr.strip()}')
                else:
                    assert result.returncode == 0, f'{name}: control fails: {result.stdout}\n{result.stderr}'
                    print(f'ok control-{name}')


def assertions(module, checker, selected=None):
    document = json.loads(FIXTURE.read_text())
    sums = (HERE / 'fixtures/SHA256SUMS').read_text()
    envelope = document['dsseEnvelope']
    statement = json.loads(base64.b64decode(envelope['payload']))
    source = statement['predicate']['invocation']['configSource']
    sha = source['digest']['sha1']
    repository, ref = re.fullmatch(r'git\+https://github\.com/([^@]+)@(.+)', source['uri']).groups()
    run_binding(module, checker, document, sums, sha, repository, ref, selected)
    if selected:
        return 0
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
    short['predicate']['invocation']['environment']['github_sha1'] = sha[:12]
    short['predicate']['materials'][0]['digest']['sha1'] = sha[:12]
    wrapped = copy.deepcopy(document)
    wrapped['dsseEnvelope']['payload'] = base64.b64encode(json.dumps(short).encode()).decode()
    other_tag_environment = {**statement['predicate']['invocation']['environment'],
                             'github_ref': 'refs/tags/v0.0.0'}
    other_tag = with_field(document, 'environment', other_tag_environment)
    for name, altered, checksum, commit, tag in [
        ('payload-type', {'dsseEnvelope': {**envelope, 'payloadType': 'unknown'}}, sums, sha, ref),
        ('envelope-key', envelope, sums, sha, ref),
        ('commit-shape', wrapped, sums, sha[:12], ref),
        ('tag-ref', other_tag, sums, sha, 'refs/tags/v0.0.0'),
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
    parser.add_argument('--case')
    parser.add_argument('--mutations', action='store_true')
    parser.add_argument('--checker', type=pathlib.Path, default=HERE / 'check-provenance.py')
    args = parser.parse_args()
    if args.case is not None and args.case not in [row[0] for row in BINDING_CASES] + ['cli']:
        parser.error(f'unknown case: {args.case}')
    try:
        result = assertions(load(args.checker), args.checker, args.case)
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
