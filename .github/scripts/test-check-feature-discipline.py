#!/usr/bin/env python3
"""Synthetic Cargo fixtures and isolated rule regressions.

Every rule has a regression: a fixture that violates that rule alone,
which the rule must reject. A clean synthetic workspace passes D1 to D4
and D13,
and the copied live inputs pass D5 to D12 before each edit. Named unit
cases pin the command scanner, the translation, the Rust lexer and each
refusal branch; --case runs one of them, or units, graphs or a rule.

--mutations disables each rule in a scratch copy of the checker and
requires every regression of that rule to fail against the copy. It
proves that each regression depends on its rule rather than on another
rule or on the fixture alone. D3's target and dev-edge fixtures isolate
graph evaluation from D1 and D2, whose topology rules those declarations
violate too.
"""
import argparse
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
# The live inputs each workflow rule reads besides .github: D5 walks the
# fixture root itself, D12 reads the Rust sources under crates/.
RULE_INPUTS = {'D5': (), 'D6': ('Cross.toml',), 'D7': (),
               'D8': ('docs/maintainers/building.md',), 'D9': (),
               'D10': ('docs/maintainers/building.md',), 'D11': (),
               'D12': ('crates',), 'D13': ()}
# Violating variants per rule. D1 has a core forward missing from network's
# declaration, a sep10 forward missing from x402-identity's, an x402-identity
# forward missing from mcp's, and an x402-identity test-helpers feature that
# reaches the feature through sep10. D2 has a dev dependency that requests
# core's feature and one that requests x402's. D3 has a crate outside the
# workspace that enables core's feature in an off graph, and x402 off in an
# on graph of cli and mcp whose declaration does not forward to it. D7 has
# the workflow env map, an echo that appends a lower-case refused name to
# the environment file and a lower-case PowerShell assignment.
VARIANTS = {'D1': 4, 'D2': 2, 'D3': 2, 'D7': 3, 'D13': 6}
# The normal dependencies of each synthetic workspace member, in the order
# its mainnet-write declaration forwards to them; other declares no feature.
FIXTURE_DEPENDENCIES = {
    'core': [], 'network': ['core'], 'cli': ['core', 'network'],
    'mcp': ['core', 'network', 'sep43', 'x402', 'x402-identity'],
    'sep10': ['core', 'network'], 'sep43': ['core', 'network'],
    'x402': ['core', 'network', 'sep43'], 'x402-identity': ['core', 'network', 'sep10'],
    'other': [],
}
# The one error of each variant that targets a crate of the authorized
# mainnet items: the variant holds exactly one defect.
SINGLE_ERRORS = {
    ('D1', 1): 'D1: stellar-agent-x402-identity: declaration differs',
    ('D1', 2): 'D1: stellar-agent-mcp: declaration differs',
    ('D1', 3): 'D1: stellar-agent-x402-identity/test-helpers reaches mainnet-write',
    ('D2', 1): 'D2: stellar-agent-other: dev dependency enables mainnet-write',
    ('D3', 1): 'positive control lacks feature',
}
# The on graph of D3's second variant: both binaries reach every declaring
# crate, and neither selects x402 itself.
SELECTED_ON = 'cargo test -p stellar-agent-cli -p stellar-agent-mcp --features mainnet-write'
# Build-script output D4 accepts: literal directives, a cfg that is no
# feature, and formatted directives with a literal key and literal
# arguments.
SAFE_BUILD = (
    'use std::io::{self, Write};\n'
    'fn main() {\n'
    '    // println!("cargo:rustc-cfg=feature=\\"sample\\"");\n'
    '    println!("cargo:rerun-if-changed=build.rs");\n'
    '    println!("cargo:rustc-cfg=sample");\n'
    '    println!("cargo::rustc-check-cfg=cfg(sample)");\n'
    '    println!("cargo:rerun-if-changed={}", "src");\n'
    '    println!("cargo:warning={note}", note = "plain",);\n'
    '    let _ = writeln!(io::stderr(), "build.rs: {}", 1);\n'
    '    println!();\n'
    '}\n')
REVIEWED_LINE = 'println!("cargo:rerun-if-changed={}", path.display())'
REFUSED = 'RUST' + 'FLAGS'
LIVE = {}


def load(path):
    spec = importlib.util.spec_from_file_location('feature_discipline', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def live_packages(m):
    if 'packages' not in LIVE:
        LIVE['packages'] = m.Checker(ROOT).packages
    return LIVE['packages']


def workspace(root, mutation=None):
    names = list(FIXTURE_DEPENDENCIES)
    root.mkdir(parents=True)
    (root / 'Cargo.toml').write_text('[workspace]\nresolver="2"\nmembers=[' + ','.join(json.dumps(n) for n in names) + ']\n')
    for name in names:
        path = root / name
        (path / 'src').mkdir(parents=True)
        (path / 'src/lib.rs').write_text('pub fn sample() {}\n')
        if name in ('cli', 'mcp'):
            (path / 'src/main.rs').write_text('fn main() {}\n')
        dependencies = FIXTURE_DEPENDENCIES[name]
        edges = [f'stellar-agent-{dep}/mainnet-write' for dep in dependencies]
        features = '' if name == 'other' else 'mainnet-write=' + json.dumps(edges) + '\n'
        manifest = f'[package]\nname="stellar-agent-{name}"\nversion="0.0.0"\nedition="2024"\n[features]\ndefault=[]\n' + features
        manifest += '[dependencies]\n' + ''.join(f'stellar-agent-{dep}={{path="../{dep}"}}\n' for dep in dependencies)
        (path / 'Cargo.toml').write_text(manifest)
    if mutation:
        mutation(root)
    result = subprocess.run(['cargo', 'generate-lockfile', '--offline'], cwd=root, text=True, capture_output=True)
    if result.returncode:
        raise AssertionError(result.stderr)


def append(root, path, text):
    with (root / path).open('a') as stream:
        stream.write(text)


def replace(root, path, old, new):
    p = root / path
    text = p.read_text()
    assert old in text, (path, old)
    p.write_text(text.replace(old, new))


def graph_checker(m, root, command, state='off'):
    c = m.Checker(root)
    c.workflows = {'fixture.yml': {'jobs': {'test': {'steps': [{'name': 'test', 'run': command}]}}}}
    c.scripts = {}
    row = {'workflow': 'fixture.yml', 'job': 'test', 'step': 'test', 'source': 'fixture.yml',
           'command': command, 'relied_on': state, **m.translate(command)}
    m.INVOCATIONS = [row]
    return c


def bare_checker(m, root=None, workflows=None, scripts=None, packages=None):
    """A checker over the given inputs, without reading metadata."""
    c = object.__new__(m.Checker)
    c.root, c.errors = root, []
    c.workflows, c.scripts = workflows or {}, scripts or {}
    c.packages = packages or {}
    return c


def rejects(c, rule, fragment):
    c.errors = []
    getattr(c, rule)()
    assert any(e.startswith(rule + ':') and fragment in e for e in c.errors), \
        f'{rule}: no error with {fragment!r}: {c.errors}'


def accepts(c, rule, label):
    c.errors = []
    getattr(c, rule)()
    assert not c.errors, f'{label}: accepted form rejected: {c.errors}'


def live_root(rule, root):
    """Copy .github and the inputs RULE_INPUTS names for rule to root."""
    root.mkdir(parents=True)
    shutil.copytree(ROOT / '.github', root / '.github', ignore=shutil.ignore_patterns('__pycache__'))
    for relative in RULE_INPUTS[rule]:
        source = ROOT / relative
        if source.is_dir():
            for path in source.rglob('*.rs'):
                target = root / path.relative_to(ROOT)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
        else:
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, root / relative)
    return root


def rule_fixture(m, rule, directory, variant=0):
    if rule == 'D13':
        root = directory / rule
        def setup(r):
            replace(r, 'core/Cargo.toml', 'default=[]', 'default=[]\ntest-helpers=[]')
            replace(r, 'other/Cargo.toml', 'default=[]', 'default=[]\ntest-helpers=[]')
            replace(r, 'Cargo.toml', 'members=[', 'members=["test-support",')
            (r / 'test-support/src').mkdir(parents=True)
            (r / 'test-support/src/lib.rs').write_text('pub fn sample() {}\n')
            (r / 'test-support/Cargo.toml').write_text(
                '[package]\nname="stellar-agent-test-support"\nversion="0.0.0"\nedition="2024"\n')
        workspace(root, setup)
        c = m.Checker(root)
        c.D13()
        assert not c.errors, f'D13: baseline rejected: {c.errors}'
        manifest = 'other/Cargo.toml'
        if variant == 0:
            replace(root, manifest, 'default=[]', 'default=["test-helpers"]')
        elif variant in (1, 2):
            kind = '[build-dependencies]\n' if variant == 2 else ''
            append(root, manifest, kind + 'stellar-agent-core={path="../core",features=["test-helpers"]}\n')
        elif variant == 3:
            replace(root, manifest, 'default=[]', 'default=[]\nunclassified=[]')
        elif variant == 4:
            append(root, manifest, 'stellar-agent-test-support={path="../test-support"}\n')
        else:
            replace(root, manifest, 'default=[]', 'default=["dep:stellar-agent-test-support"]')
            append(root, manifest, 'stellar-agent-test-support={path="../test-support",optional=true}\n')
        c = m.Checker(root)
        for other in ('D1', 'D2', 'D4'):
            getattr(c, other)()
        assert not c.errors, f'D13: another rule rejects the fixture: {c.errors}'
    elif rule in ('D1', 'D2', 'D3', 'D4'):
        root = directory / rule
        def mutate(r):
            if rule == 'D1' and variant == 0:
                replace(r, 'network/Cargo.toml', 'mainnet-write=["stellar-agent-core/mainnet-write"]', 'mainnet-write=[]')
            elif rule == 'D1' and variant == 1:
                replace(r, 'x402-identity/Cargo.toml', ', "stellar-agent-sep10/mainnet-write"', '')
            elif rule == 'D1' and variant == 2:
                replace(r, 'mcp/Cargo.toml', ', "stellar-agent-x402-identity/mainnet-write"', '')
            elif rule == 'D1':
                replace(r, 'x402-identity/Cargo.toml', 'default=[]\n',
                        'default=[]\ntest-helpers=["stellar-agent-sep10/mainnet-write"]\n')
            elif rule == 'D2' and variant == 0:
                append(r, 'other/Cargo.toml', '[dev-dependencies]\nstellar-agent-core={path="../core",features=["mainnet-write"]}\n')
            elif rule == 'D2':
                append(r, 'other/Cargo.toml', '[dev-dependencies]\nstellar-agent-x402={path="../x402",features=["mainnet-write"]}\n')
            elif rule == 'D3' and variant == 1:
                replace(r, 'mcp/Cargo.toml', ', "stellar-agent-x402/mainnet-write"', '')
            elif rule == 'D3':
                (r / 'external/src').mkdir(parents=True)
                (r / 'external/src/lib.rs').write_text('pub fn sample() {}\n')
                (r / 'external/Cargo.toml').write_text('[package]\nname="external"\nversion="0.0.0"\nedition="2024"\n[dependencies]\nstellar-agent-core={path="../core",features=["mainnet-write"]}\n')
                append(r, 'other/Cargo.toml', 'external={path="../external"}\n')
                replace(r, 'Cargo.toml', 'resolver="2"', 'resolver="2"\nexclude=["external"]')
            elif rule == 'D4':
                (r / 'other/build.rs').write_text('fn main() { println!("cargo:rustc-cfg=feature=\\"mainnet-write\\""); }\n')
        workspace(root, mutate)
        if rule == 'D3' and variant == 1:
            c = graph_checker(m, root, SELECTED_ON, 'on')
        elif rule == 'D3':
            c = graph_checker(m, root, 'cargo build --workspace')
        else:
            c = m.Checker(root)
    else:
        root = live_root(rule, directory / rule)
        c = bare_checker(m, root, packages=live_packages(m))
        c.workflows, c.scripts = m.workflow_inputs(root)
        getattr(c, rule)()
        assert not c.errors, f'{rule}: baseline rejected: {c.errors}'
        if rule == 'D5':
            (root / 'contracts/sample/.cargo').mkdir(parents=True)
            (root / 'contracts/sample/.cargo/config.toml').write_text('[build]\n')
        elif rule == 'D6':
            append(root, 'Cross.toml', '\n[build.env]\npassthrough=["' + REFUSED + '"]\n')
        elif rule == 'D7':
            steps = c.workflows['release.yml']['jobs']['build']['steps']
            if variant == 0:
                c.workflows['ci.yml'].setdefault('env', {})[REFUSED] = '-C debuginfo=0'
            elif variant == 1:
                steps.append({'run': f'echo "{REFUSED.lower()}=-Cdebuginfo" >> "$GITHUB_ENV"'})
            else:
                steps.append({'shell': 'pwsh', 'run': f'$env:{REFUSED.lower()} = "-C debuginfo=0"'})
        elif rule == 'D8':
            append(root, 'docs/maintainers/building.md', '\ncargo build ' + m.ALL_FEATURES + '\n')
        elif rule == 'D9':
            c.workflows['release.yml']['jobs']['build']['steps'].append({'run': 'cargo build --features mainnet-write'})
        elif rule == 'D10':
            c.workflows['ci.yml']['env']['FEATURES_EXCEPT_MAINNET_WRITE'] = 'test-helpers'
        elif rule == 'D11':
            c.workflows['release.yml']['env']['EXPECTED_MAINNET_WRITE'] = 'on'
        elif rule == 'D12':
            append(root, 'crates/stellar-agent-core/src/lib.rs', '\nconst EXTRA: &str = "' + m.MARKER + 'off";\n')
    getattr(c, rule)()
    return c.errors


def regression(m, rule, directory, variant=0):
    errors = rule_fixture(m, rule, directory / f'{rule}-{variant}', variant)
    assert errors and all(e.startswith(rule + ':') for e in errors), \
        f'{rule}: violating fixture accepted: {errors}'
    single = SINGLE_ERRORS.get((rule, variant))
    assert single is None or (len(errors) == 1 and single in errors[0]), \
        f'{rule} variant {variant}: expected one error with {single!r}: {errors}'


def graph_cases(m, tmp, selected=None):
    def check(name, mutation, command, want, state='off', fragment=''):
        if selected and selected != name:
            return
        root = tmp / name
        workspace(root, mutation)
        c = graph_checker(m, root, command, state)
        with contextlib.redirect_stdout(io.StringIO()):
            c.D3()
        if bool(c.errors) != want:
            raise AssertionError(f'{name}: errors {c.errors}, expected failure={want}')
        print(f'ok {name}')
    check('graph-baseline', None, 'cargo build --workspace', False)
    check('graph-positive', None, 'cargo test --workspace --features mainnet-write', False, 'on')
    check('graph-positive-selected', None, SELECTED_ON, False, 'on')
    if not selected or selected == 'graph-positive-mutated':
        root = tmp / 'graph-positive-mutated'
        workspace(root)
        original = m.graph_state
        for name in m.PACKAGES:
            c = graph_checker(m, root, 'cargo test --workspace --features mainnet-write', 'on')
            states = {p: [True] for p in m.PACKAGES}
            states[name] = [False]
            m.graph_state = lambda _root, _query: states
            try:
                c.D3()
                assert c.errors, f'graph-positive-mutated: accepted missing activation on {name}'
            finally:
                m.graph_state = original
        print('ok graph-positive-mutated')
    check('graph-bin-workspace', lambda r: append(r, 'other/Cargo.toml',
          'stellar-agent-core={path="../core",features=["mainnet-write"]}\n'),
          'cargo build --bin stellar-agent-cli', True)
    check('graph-target-specific', lambda r: append(r, 'other/Cargo.toml',
          '[target.\'cfg(windows)\'.dependencies]\nstellar-agent-core={path="../core",features=["mainnet-write"]}\n'),
          'cargo build --workspace', True)
    dev = lambda r: append(r, 'other/Cargo.toml',
                           '[dev-dependencies]\nstellar-agent-core={path="../core",features=["mainnet-write"]}\n')
    check('graph-dev-build', dev, 'cargo build --workspace', False)
    check('graph-dev-test', dev, 'cargo test --workspace', True)
    check('graph-absent', None, 'cargo check -p stellar-agent-other', False)
    if not selected or selected == 'graph-missing-metadata':
        root = tmp / 'graph-missing-metadata'
        workspace(root)
        c = graph_checker(m, root, 'cargo build --workspace')
        del c.packages[m.PACKAGES[0]]
        c.D3()
        assert c.errors, 'graph-missing-metadata: missing queried crate accepted'
        print('ok graph-missing-metadata')
    if not selected or selected == 'synthetic-baseline':
        root = tmp / 'synthetic-baseline'
        workspace(root, lambda r: (r / 'core/build.rs').write_text(SAFE_BUILD))
        c = graph_checker(m, root, 'cargo build --workspace')
        for rule in ('D1', 'D2', 'D3', 'D4'):
            c.errors = []
            with contextlib.redirect_stdout(io.StringIO()):
                getattr(c, rule)()
            assert not c.errors, f'synthetic-baseline: {rule} rejected the clean workspace: {c.errors}'
            print(f'ok synthetic-baseline {rule}')
    if not selected or selected == 'D4-formatted':
        root = tmp / 'D4-formatted'
        workspace(root, lambda r: (r / 'other/build.rs').write_text(
            'fn main() { println!("cargo::rustc-cfg={}", "feature=\\"mainnet-write\\""); }\n'))
        c = m.Checker(root)
        rejects(c, 'D4', 'formatted rustc-cfg directive')
        print('ok D4-formatted')
    for name, mode in [('inventory-added', 'add'), ('inventory-vanished', 'remove'),
                       ('inventory-duplicate', 'duplicate'), ('inventory-drift', 'drift')]:
        if selected and selected != name:
            continue
        root = tmp / name
        workspace(root)
        c = graph_checker(m, root, 'cargo build --workspace')
        steps = c.workflows['fixture.yml']['jobs']['test']['steps']
        if mode == 'add':
            steps.append({'name': 'extra', 'run': 'cargo check --workspace'})
        elif mode == 'remove':
            steps.clear()
        elif mode == 'duplicate':
            m.INVOCATIONS = m.INVOCATIONS * 2
        else:
            steps[0]['run'] += ' --release'
        c.D3()
        assert c.errors, f'{name}: inventory drift accepted'
        print(f'ok {name}')


GRAPHS = ('graph-baseline', 'graph-positive', 'graph-positive-selected', 'graph-positive-mutated',
          'graph-bin-workspace',
          'graph-target-specific', 'graph-dev-build', 'graph-dev-test', 'graph-absent',
          'graph-missing-metadata', 'synthetic-baseline', 'D4-formatted', 'inventory-added',
          'inventory-vanished', 'inventory-duplicate', 'inventory-drift')
UNITS = {}


def unit(name):
    def register(function):
        UNITS[name] = function
        return function
    return register


def translation_case(family, edges):
    def case(m, tmp, checker):
        actual = m.translate(f'cargo {family} --bin sample --all-targets --target wasm32-unknown-unknown --locked --offline --release -- -D warnings')
        wanted = 'normal,build,dev' if family in ('build', 'check') else edges
        assert actual == {'selection': ['--workspace'], 'features': [], 'edges': wanted, 'target': 'wasm32-unknown-unknown'}, f'translation-{family}'
        actual = m.translate(f'cargo {family} -p sample --features helpers --no-default-features')
        assert actual['selection'] == ['-p', 'sample'] and actual['features'] == ['--features', 'helpers', '--no-default-features'], f'selection-{family}'
        assert actual['edges'] == edges, f'edges-{family}'
    return case


for _family, _edges in {'build': 'normal,build', 'check': 'normal,build',
                        'test': 'normal,build,dev', 'clippy': 'normal,build,dev',
                        'doc': 'normal,build,dev', 'llvm-cov': 'normal,build,dev'}.items():
    UNITS['translation-' + _family] = translation_case(_family, _edges)


@unit('translation-dev-targets')
def case_translation_dev_targets(m, tmp, checker):
    for family in ('build', 'check'):
        for flags in ('--all-targets', '--tests', '--test it', '--benches', '--bench b',
                      '--examples', '--example e'):
            edges = m.translate(f'cargo {family} -p sample {flags}')['edges']
            assert edges == 'normal,build,dev', f'translation-dev-targets: cargo {family} {flags}: {edges}'
        edges = m.translate(f'cargo {family} -p sample --bin sample --lib')['edges']
        assert edges == 'normal,build', f'translation-dev-targets: cargo {family} --bin: {edges}'


@unit('translation-errors')
def case_translation_errors(m, tmp, checker):
    for flag in ('--unknown', '--config=foo', '--all-' + 'features', '--bin'):
        try:
            m.translate('cargo build ' + flag)
        except ValueError:
            pass
        else:
            raise AssertionError(f'translation accepted {flag}')
    assert m.translate('cargo llvm-cov --json --output-path cov.json')['selection'] == ['--workspace']


@unit('command-inventory')
def case_command_inventory(m, tmp, checker):
    calls = list(m.commands('echo "cargo build"; cargo check --workspace; cargo test --lib\nX=$(cargo metadata --no-deps)\ncat <<END\ncargo build --features bad\nEND'))
    assert calls == ['cargo check --workspace', 'cargo test --lib', 'cargo metadata --no-deps'], f'command-inventory: {calls}'


@unit('command-separators')
def case_command_separators(m, tmp, checker):
    calls = list(m.commands('a&&cargo build --workspace;b;cargo check --workspace\n'
                            'x|cargo fmt --check\nY=`cargo tree`'))
    assert calls == ['cargo build --workspace', 'cargo check --workspace', 'cargo fmt --check',
                     'cargo tree'], f'command-separators: {calls}'


@unit('backtick-substitution')
def case_backtick_substitution(m, tmp, checker):
    calls = list(m.commands('X="`cargo metadata --no-deps`"'))
    assert calls == ['cargo metadata --no-deps'], f'backtick-substitution: {calls}'


def refuses_text(m, text, message, label, number=1):
    """commands() refuses text with the full diagnostic: the source, the
    line number, message and the quoted physical line."""
    expected = f'sample.sh:{number}: {message}: {text.split(chr(10))[number - 1]}'
    try:
        list(m.commands(text, 'sample.sh'))
    except ValueError as error:
        assert str(error) == expected, f'{label}: {error} differs from {expected}'
    else:
        raise AssertionError(f'{label}: unmodelled syntax accepted')


@unit('shell-string')
def case_shell_string(m, tmp, checker):
    for text, number in (("bash -c 'cargo check --workspace'", 1), ('true\nsh -ec "cargo build"', 2),
                         ('eval "cargo test"', 1), ("timeout 60 /bin/bash --norc -c 'cargo doc'", 1)):
        refuses_text(m, text, 'a shell string or eval runs cargo or cross', f'shell-string {text!r}', number)
    for text in ("bash -c 'echo ok'", 'echo "bash -c cargo build"'):
        assert list(m.commands(text, 'sample.sh')) == [], f'shell-string accepted {text!r}'


@unit('heredoc-interpreter')
def case_heredoc_interpreter(m, tmp, checker):
    refuses_text(m, "bash <<'EOF'\ncargo build\nEOF", 'an interpreter executes a heredoc that runs cargo or cross',
                 'heredoc-interpreter')
    refuses_text(m, "cat <<'EOF' | sh\ncargo build\nEOF", 'an interpreter executes a heredoc that runs cargo or cross',
                 'heredoc-interpreter pipe')
    refuses_text(m, "bash<<'EOF'\ncargo build\nEOF", 'an interpreter executes a heredoc that runs cargo or cross',
                 'heredoc-interpreter operator')
    assert list(m.commands("cat <<'EOF' > notes\ncargo build\nEOF")) == [], 'heredoc-interpreter data'


@unit('heredoc-grammar')
def case_heredoc_grammar(m, tmp, checker):
    for text in ('cat <<E"OF"\nnotes\nEOF\ncargo build\nE', 'cat <<-EOF\n\tcargo build\n\tEOF',
                 'cat <<\\EOF\ncargo build\nEOF'):
        refuses_text(m, text, 'a heredoc the scanner does not model', f'heredoc-grammar {text!r}')
    for text in ('cat << EOF\nnotes\nEOF\ncargo check', 'cat <<"EOF"\nnotes\nEOF\ncargo check'):
        assert list(m.commands(text)) == ['cargo check'], f'heredoc-grammar accepted {text!r}'


@unit('heredoc-continued-body')
def case_heredoc_continued_body(m, tmp, checker):
    refuses_text(m, 'cat <<EOF\nEO\\\nF\ncargo build', 'a heredoc body line the scanner cannot place',
                 'heredoc-continued-body unquoted', 2)
    found = list(m.commands("cat <<'EOF'\nnotes \\\nEOF\ncargo check"))
    assert found == ['cargo check'], f'heredoc-continued-body quoted: {found}'


@unit('heredoc-ascii-blank')
def case_heredoc_ascii_blank(m, tmp, checker):
    refuses_text(m, 'cat <<EOF\u00a0X\nnotes\nEOF\u00a0X', 'a heredoc the scanner does not model',
                 'heredoc-ascii-blank')
    found = list(m.commands('cargo\u00a0build --workspace'))
    assert found == [], f'heredoc-ascii-blank call word: {found}'


@unit('heredoc-raw-close')
def case_heredoc_raw_close(m, tmp, checker):
    found = list(m.commands("cat <<'EOF'\n  EOF\ncargo build\nEOF"))
    assert found == [], f'heredoc-raw-close indented delimiter: {found}'
    found = list(m.commands("cat <<'EOF'\nnotes \\\nEOF\ncargo check"))
    assert found == ['cargo check'], f'heredoc-raw-close continued body line: {found}'


@unit('heredoc-substitution')
def case_heredoc_substitution(m, tmp, checker):
    refuses_text(m, 'cat <<EOF\nversion $(cargo metadata --no-deps)\nEOF',
                 'a substitution in an unquoted heredoc runs cargo or cross', 'heredoc-substitution')
    refuses_text(m, 'cat <<EOF\nversion `cargo metadata --no-deps`\nEOF',
                 'a substitution in an unquoted heredoc runs cargo or cross', 'heredoc-substitution backtick')
    assert list(m.commands("cat <<'EOF'\nversion $(cargo metadata --no-deps)\nEOF")) == [], \
        'heredoc-substitution quoted'


@unit('here-string')
def case_here_string(m, tmp, checker):
    for text in ("bash <<< 'cargo check --workspace --features mainnet-write'",
                 "bash<<<'cargo check --workspace --features mainnet-write'",
                 "bash -x <<< 'cargo build'", 'echo x; sh<<<"cargo build"'):
        refuses_text(m, text, 'an interpreter or a command runner reads a here-string that runs cargo or cross',
                     f'here-string {text}')
    refuses_text(m, "cat <<< 'cargo build' | sh",
                 'an interpreter or a command runner reads a here-string that runs cargo or cross',
                 'here-string pipe')
    for text in ("cat <<< 'cargo build'", "cat <<< 'run bash then cargo build'"):
        assert list(m.commands(text)) == [], f'here-string data: {text}'
    assert list(m.commands('read -r x <<< "$(cargo metadata --no-deps)"')) == ['cargo metadata --no-deps'], \
        'here-string substitution'


@unit('here-string-unmodelled')
def case_here_string_unmodelled(m, tmp, checker):
    for text in ("'bash'<<<'cargo build'", "cat <<< 'cargo build' | 'sh'"):
        refuses_text(m, text, 'an unmodelled command word reads a here-string that runs cargo or cross',
                     f'here-string-unmodelled {text}')


@unit('here-string-quoted-pipe')
def case_here_string_quoted_pipe(m, tmp, checker):
    for text in ("cat <<< 'cargo build | sh -x'", "cat <<< 'cargo build' || sh fallback.sh"):
        assert list(m.commands(text)) == [], f'here-string-quoted-pipe {text}'


@unit('here-string-pipeline')
def case_here_string_pipeline(m, tmp, checker):
    for text in ("cat <<< 'cargo build' | grep x | sh", "cat <<< 'cargo build' |& grep x | sh"):
        refuses_text(m, text, 'an interpreter or a command runner reads a here-string that runs cargo or cross',
                     f'here-string-pipeline {text}')


@unit('here-string-substitution')
def case_here_string_substitution(m, tmp, checker):
    for text in ("cat <<< 'cargo build' $(true; true) | sh", "cat <<< 'cargo build' `true; true` | sh",
                 "echo \"$(bash <<< 'cargo build')\""):
        refuses_text(m, text, 'an interpreter or a command runner reads a here-string that runs cargo or cross',
                     f'here-string-substitution {text}')
    found = list(m.commands("cat <<< 'cargo build' $(true; true) | grep x"))
    assert found == [], f'here-string-substitution grep: {found}'


@unit('here-string-subshell')
def case_here_string_subshell(m, tmp, checker):
    for text in ("cat <<< 'cargo build' $( (true); true) | sh", "cat <<< 'cargo build' $( (true); (true) ) | sh"):
        refuses_text(m, text, 'an interpreter or a command runner reads a here-string that runs cargo or cross',
                     f'here-string-subshell {text}')
    found = list(m.commands("cat <<< 'cargo build' $( (true); true) | grep x"))
    assert found == [], f'here-string-subshell grep: {found}'


@unit('here-string-command-word')
def case_here_string_command_word(m, tmp, checker):
    refuses_text(m, "<<< 'cargo build' bash", 'a here-string before the command word runs cargo or cross',
                 'here-string-command-word before')
    for text in ("X=1 /bin/bash <<< 'cargo build'", "(bash <<< 'cargo build')"):
        refuses_text(m, text, 'an interpreter or a command runner reads a here-string that runs cargo or cross',
                     f'here-string-command-word {text}')


@unit('here-string-runner')
def case_here_string_runner(m, tmp, checker):
    for text in ("env bash <<< 'cargo build'", "exec bash<<<'cargo build'", "env <<< 'cargo build' bash",
                 "cat <<< 'cargo build' | env sh", "sudo -u x bash <<< 'cargo build'"):
        refuses_text(m, text, 'an interpreter or a command runner reads a here-string that runs cargo or cross',
                     f'here-string-runner {text}')


@unit('heredoc-quoted-operator')
def case_heredoc_quoted_operator(m, tmp, checker):
    calls = list(m.commands('echo "a<<EOF" >> notes\ncargo check --workspace'))
    assert calls == ['cargo check --workspace'], f'heredoc-quoted-operator: {calls}'


@unit('fd-redirect')
def case_fd_redirect(m, tmp, checker):
    calls = list(m.commands('cargo metadata --format-version 1 >out.json\n'
                            'cargo publish -p x 2>&1 | tee log'))
    assert calls == ['cargo metadata --format-version 1', 'cargo publish -p x'], f'fd-redirect: {calls}'


@unit('feature-loop')
def case_feature_loop(m, tmp, checker):
    workflow = {'ci.yml': {'jobs': {'check': {'steps': [{'name': 'loop', 'run':
        'for feature in test-helpers testnet-helpers; do\n'
        'cargo check -p sample --features "$feature"\ndone'}]}}}}
    rows = m.inventory(tmp, workflow, {})
    assert len(rows) == 2, 'feature-loop: literal list drift was ignored'
    assert {row['features'][-1] for row in rows} == {'test-helpers', 'testnet-helpers'}, 'feature-loop: incorrect expansion'


@unit('transitive-scripts')
def case_transitive_scripts(m, tmp, checker):
    workflow = {'ci.yml': {'jobs': {'check': {'steps': [{'name': 'outer', 'run': 'bash .github/scripts/outer.sh'}]}}}}
    scripts = {'.github/scripts/outer.sh': 'bash .github/scripts/inner.sh',
               '.github/scripts/inner.sh': 'cargo check -p sample'}
    rows = m.inventory(tmp, workflow, scripts)
    assert len(rows) == 1 and rows[0]['source'].endswith('inner.sh'), 'transitive-script: command omitted'


@unit('test-script-scanned')
def case_test_script_scanned(m, tmp, checker):
    workflow = {'ci.yml': {'jobs': {'check': {'steps': [{'name': 'self-test', 'run':
        'bash .github/scripts/test-sample.sh\nbash .github/scripts/test-preflight.sh'}]}}}}
    scripts = {'.github/scripts/test-sample.sh': 'cargo check -p sample',
               '.github/scripts/test-preflight.sh': 'cargo check -p data'}
    rows = m.inventory(tmp, workflow, scripts)
    assert [row['source'] for row in rows] == ['.github/scripts/test-sample.sh'], \
        f'test-script-scanned: {[row["source"] for row in rows]}'


@unit('scalar-run')
def case_scalar_run(m, tmp, checker):
    workflow = {'w.yml': job([{'run': True}, {'run': 'cargo check -p sample'}])}
    rows = m.inventory(tmp, workflow, {})
    assert [row['command'] for row in rows] == ['cargo check -p sample'], f'scalar-run: {rows}'


@unit('python-commands')
def case_python_commands(m, tmp, checker):
    source = 'example = ["cargo", "build"]\nimport subprocess\nsubprocess.run(["cargo", "check", "--workspace"])'
    calls = list(m.script_commands(pathlib.Path('helper.py'), source))
    assert calls == ['cargo check --workspace'], 'Python command classified as data'


@unit('yaml-workflows')
def case_yaml_workflows(m, tmp, checker):
    root = tmp / 'yaml-workflows'
    (root / '.github/workflows').mkdir(parents=True)
    (root / '.github/actions').mkdir()
    (root / '.github/workflows/sample.yaml').write_text(
        'jobs:\n  check:\n    steps:\n      - name: check\n        run: cargo check -p sample\n')
    workflows, scripts = m.workflow_inputs(root)
    rows = m.inventory(root, workflows, scripts)
    assert [row['workflow'] for row in rows] == ['sample.yaml'], f'yaml-workflows: {rows}'


@unit('composite-actions')
def case_composite_actions(m, tmp, checker):
    (tmp / 'docs/maintainers').mkdir(parents=True, exist_ok=True)
    (tmp / 'docs/maintainers/building.md').write_text('')
    for rule, feature in [('D8', m.ALL_FEATURES), ('D9', '--features ' + m.FEATURE)]:
        c = bare_checker(m, tmp, {'action.yml': {'runs': {'steps': [{'run': 'cargo build ' + feature}]}}})
        getattr(c, rule)()
        assert c.errors, f'{rule}: composite action activation accepted'


@unit('exemption-path')
def case_exemption_path(m, tmp, checker):
    c = bare_checker(m, scripts={'.github/actions/test-rebuild-vendored-wasm.sh': REFUSED + '=bad'})
    c.D7()
    assert c.errors, 'D7: exemption matched the wrong path'


@unit('unresolved-variable')
def case_unresolved_variable(m, tmp, checker):
    try:
        m.expand('cargo build --features $FLAGS', {'FLAGS': '$UNRESOLVED'})
    except ValueError:
        pass
    else:
        raise AssertionError('unresolved variable accepted')


@unit('tree-output')
def case_tree_output(m, tmp, checker):
    states = m.parse_tree(' mainnet-write-path v0.0.0 (/a/mainnet-write)\nmainnet-write stellar-agent-core v0.0.0 (/a path)\n stellar-agent-core v0.0.0 (/mainnet-write path) (*)\n')
    assert states[m.PACKAGES[0]] == [True, False] and states[m.PACKAGES[3]] == [], 'tree-output'


@unit('environment-guard')
def case_environment_guard(m, tmp, checker):
    home = str(tmp / 'cargo-home')
    for variable in ('RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTC',
                     'CARGO_BUILD_RUSTC_WRAPPER', REFUSED, 'CARGO_ENCODED_' + REFUSED,
                     'CARGO_BUILD_' + REFUSED, 'CARGO_TARGET_X_' + REFUSED, 'TARGET_X_' + REFUSED,
                     'CARGO_FEATURE_MAINNET_WRITE', 'CROSS_CONTAINER_OPTS'):
        assert m.env_guard(tmp, {variable: '', 'CARGO_HOME': home}), f'env-guard-{variable}'
    assert not m.env_guard(tmp, {'CARGO_PROFILE_RELEASE_DEBUG': '0', 'CARGO_HOME': home}), \
        'env-guard: a profile variable was refused'
    assert m.env_guard(tmp, {'RUSTDOCFLAGS': '--cfg feature="mainnet-write"', 'CARGO_HOME': home}), \
        'env-guard: RUSTDOCFLAGS with --cfg accepted'
    for location in (tmp / '.cargo', tmp / 'cargo-home'):
        location.mkdir(exist_ok=True)
        path = location / 'config.toml'
        path.write_text('')
        assert m.env_guard(tmp / 'child', {'CARGO_HOME': home}), 'env-guard-config'
        path.unlink()


@unit('rustdoc-variants')
def case_rustdoc_variants(m, tmp, checker):
    home = str(tmp / 'cargo-home')
    for name in ('CARGO_BUILD_RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS'):
        assert m.env_guard(tmp, {name: '--cfg x', 'CARGO_HOME': home}), f'rustdoc-variants: guard accepted {name}'
        assert not m.env_guard(tmp, {name: '-D warnings', 'CARGO_HOME': home}), f'rustdoc-variants: guard refused {name}'
        rejects(bare_checker(m, workflows={'w.yml': {'env': {name: '--cfg x'}}}), 'D7', name)


@unit('guard-root')
def case_guard_root(m, tmp, checker):
    outer, elsewhere, home = tmp / 'guard/outer', tmp / 'guard/elsewhere', tmp / 'guard/home'
    for directory in (outer / 'checkout', outer / '.cargo', elsewhere, home):
        directory.mkdir(parents=True)
    (outer / '.cargo/config.toml').write_text('')
    environ = {k: v for k, v in os.environ.items() if not m.refused(k) and k not in m.RUSTDOC_VARS}
    result = subprocess.run([sys.executable, '-B', str(checker), '--env-guard', str(outer / 'checkout')],
                            cwd=elsewhere, env={**environ, 'CARGO_HOME': str(home)},
                            capture_output=True, text=True)
    assert result.returncode == 1 and 'cargo config exists' in result.stderr, \
        f'guard-root: the guard ignored the named checkout: {result.returncode} {result.stderr}'


@unit('test-feature-topology')
def case_test_feature_topology(m, tmp, checker):
    dependency = {'name': 'stellar-agent-test-support', 'rename': 'support',
                  'features': ['test-helpers'], 'uses_default_features': False,
                  'kind': None, 'optional': True}
    package = {'features': {'default': [], 'test-helpers': ['dep:support']},
               'dependencies': [dependency]}
    c = bare_checker(m, packages={'fixture': package})
    c.D13()
    assert not c.errors, f'test-only optional dependency rejected: {c.errors}'
    for edge in ('dep:support', 'support/test-helpers', 'support/default'):
        package['features']['default'] = [edge]
        c.errors = []
        c.D13()
        assert c.errors == ['D13: fixture/default reaches a test feature or package'], (edge, c.errors)
    dependency['name'] = 'stellar-agent-smart-account-acceptance'
    package['features']['default'] = ['dep:support']
    c.errors = []
    c.D13()
    assert c.errors == ['D13: fixture/default reaches a test feature or package'], c.errors
    dependency['name'] = 'member'
    c.packages['member'] = {'features': {'default': ['test-hooks'], 'test-hooks': []}, 'dependencies': []}
    assert c.reaches('fixture', 'default', set(m.TEST_FEATURES)), 'transitive dependency default missed'


@unit('topology')
def case_topology(m, tmp, checker):
    c = bare_checker(m)
    dependency = {'name': 'core', 'rename': 'renamed', 'features': [],
                  'uses_default_features': True, 'kind': None, 'target': None}
    c.packages = {'core': {'features': {'mainnet-write': [], 'alias': ['mainnet-write'], 'default': ['alias']}, 'dependencies': []},
                  'other': {'features': {'local': ['next'], 'next': ['renamed/alias'],
                                         'weak': ['renamed?/alias'], 'dep': ['dep:renamed']},
                            'dependencies': [dependency]}}
    for feature in ('local', 'weak', 'dep'):
        assert c.reaches('other', feature, {m.FEATURE}), f'topology-{feature}: activation missed'
    assert c.dependency_reaches(dependency, {m.FEATURE}), 'topology-default: activation missed'
    dependency['uses_default_features'] = False
    assert not c.dependency_reaches(dependency, {m.FEATURE}), 'topology-default-disabled'
    dependency['features'] = ['alias']
    assert c.dependency_reaches(dependency, {m.FEATURE}), 'topology-dependency-features'
    for kind in ('dev', 'build'):
        for target in (None, 'cfg(windows)'):
            c.errors = []
            c.packages['core']['dependencies'] = [
                {**dependency, 'kind': kind, 'target': target, 'name': 'core'}]
            c.D2()
            assert c.errors, f'D2-{kind}-{target}: self dependency activation missed'


@unit('d1-normal-dependency')
def case_d1_normal_dependency(m, tmp, checker):
    core = m.PACKAGES[0]
    def dep(name, features=()):
        return {'name': name, 'rename': None, 'features': list(features),
                'uses_default_features': True, 'kind': None, 'target': None}
    packages = {}
    for name, declaration in m.DECLARATIONS.items():
        deps = [forward.split('/', 1)[0] for forward in declaration]
        packages[name] = {'features': {m.FEATURE: declaration, 'default': []},
                          'dependencies': [dep(d) for d in deps]}
    packages['other'] = {'features': {'default': []}, 'dependencies': [dep(core, [m.FEATURE])]}
    c = bare_checker(m, packages=packages)
    c.D1()
    assert c.errors == [f'D1: other: normal dependency {core} enables {m.FEATURE}'], f'd1-normal-dependency: {c.errors}'


@unit('d11-workflows')
def case_d11_workflows(m, tmp, checker):
    c = bare_checker(m)
    for workflow in ('release.yml', 'publish.yml', 'release-rehearsal.yml'):
        c.workflows = {name: {'env': {'EXPECTED_MAINNET_WRITE': 'off'}}
                       for name in ('release.yml', 'publish.yml', 'release-rehearsal.yml')}
        c.workflows[workflow]['env'].clear()
        rejects(c, 'D11', workflow)


@unit('cargo-error')
def case_cargo_error(m, tmp, checker):
    original = m.subprocess.run
    class Failed:
        returncode = 1
        stderr = 'fixture cargo error'
        stdout = ''
    m.subprocess.run = lambda *a, **k: Failed()
    try:
        try:
            m.run_cargo(tmp, ['tree'])
        except ValueError:
            pass
        else:
            raise AssertionError('cargo error accepted')
    finally:
        m.subprocess.run = original


@unit('inventory-order')
def case_inventory_order(m, tmp, checker):
    c = m.Checker(ROOT)
    c.workflows, c.scripts = m.workflow_inputs(ROOT)
    committed = list(m.INVOCATIONS)
    expected = len({json.dumps({key: row[key] for key in ('selection', 'features', 'edges')}, sort_keys=True)
                    for row in committed if row['relied_on'] != 'not relied on'})
    original, calls = m.graph_state, []
    def stub(_root, query):
        calls.append(query)
        on = m.FEATURE in ','.join(query['features'])
        return {name: [on] for name in m.PACKAGES}
    m.graph_state = stub
    try:
        for label, table in (('reversed', committed[::-1]), ('rotated', committed[1:] + committed[:1])):
            m.INVOCATIONS = table
            calls.clear()
            c.errors = []
            with contextlib.redirect_stdout(io.StringIO()):
                c.D3()
            assert not c.errors and expected and len(calls) == expected, \
                f'inventory-order {label}: {len(calls)} queries, expected {expected}: {c.errors[:2]}'
    finally:
        m.graph_state = original
        m.INVOCATIONS = committed


def problems(m, text):
    return [problem for _, problem, _ in m.cfg_emissions(text)]


@unit('d4-safe')
def case_d4_safe(m, tmp, checker):
    assert problems(m, SAFE_BUILD) == [], f'd4-safe: {problems(m, SAFE_BUILD)}'


@unit('d4-formatted-cfg')
def case_d4_formatted_cfg(m, tmp, checker):
    found = problems(m, 'fn main() { println!("cargo::rustc-cfg={}", "feature=\\"mainnet-write\\""); }\n')
    assert found == ['formatted rustc-cfg directive'], f'd4-formatted-cfg: {found}'


@unit('d4-dynamic-format')
def case_d4_dynamic_format(m, tmp, checker):
    found = problems(m, 'fn main() { println!(concat!("cargo:", "rerun-if-changed=x")); }\n')
    assert found == ['println! format is not a string literal'], f'd4-dynamic-format: {found}'


@unit('d4-split-key')
def case_d4_split_key(m, tmp, checker):
    for text in ('fn main() { println!("cargo:rustc-{}=feature=x", "cfg"); }\n',
                 'fn main() { println!("{}", "plain"); }\n'):
        found = problems(m, text)
        assert found == ['formatted directive without a literal key'], f'd4-split-key: {found}'


@unit('d4-concat-argument')
def case_d4_concat_argument(m, tmp, checker):
    found = problems(m, 'fn main() { println!("cargo:warning={}", '
                        'concat!("\\ncargo:rustc-", "cfg=feature=\\"mainnet-write\\"")); }\n')
    assert found == ['formatted output with a non-literal argument'], f'd4-concat-argument: {found}'


@unit('d4-variable-argument')
def case_d4_variable_argument(m, tmp, checker):
    found = problems(m, 'fn main() { let note = String::new(); println!("cargo:warning={}", note); }\n')
    assert found == ['formatted output with a non-literal argument'], f'd4-variable-argument: {found}'


@unit('d4-captured-argument')
def case_d4_captured_argument(m, tmp, checker):
    found = problems(m, 'fn main() { let note = 1; println!("cargo:warning={note}"); }\n')
    assert found == ['formatted output with a non-literal argument'], f'd4-captured-argument: {found}'


@unit('d4-token-argument')
def case_d4_token_argument(m, tmp, checker):
    for argument in ('"x\\ncargo:warning=y"', '"cargo:warning=y"', '"rustc-env=X=1"'):
        found = problems(m, 'fn main() { println!("cargo:warning={}", ' + argument + '); }\n')
        assert found == ['formatted output argument can start a directive'], f'd4-token-argument {argument}: {found}'


@unit('d4-literal-argument')
def case_d4_literal_argument(m, tmp, checker):
    for text in ('fn main() { println!("cargo:warning={}", "plain text"); }\n',
                 'fn main() { println!("cargo:warning={a} {b}", a = "one", b = r#"two"#); }\n'):
        assert problems(m, text) == [], f'd4-literal-argument: {problems(m, text)}'


@unit('d4-reviewed')
def case_d4_reviewed(m, tmp, checker):
    text = 'fn main() { let path = std::path::Path::new("src"); ' + REVIEWED_LINE + '; }\n'
    assert problems(m, text) == ['formatted output with a non-literal argument'], 'd4-reviewed: unreviewed accepted'
    found = [problem for _, problem, _ in m.cfg_emissions(text, {REVIEWED_LINE})]
    assert found == [], f'd4-reviewed: reviewed statement rejected: {found}'
    live = m.Checker(ROOT)
    live.D4()
    assert not live.errors, f'd4-reviewed: the live build script was rejected: {live.errors}'


@unit('d4-format-specification')
def case_d4_format_specification(m, tmp, checker):
    for text in ('fn main() { println!("cargo:warning={:\\n>2}argo:rustc-cfg=feature=\\"mainnet-write\\"", "c"); }\n',
                 'fn main() { println!("cargo:warning={:?}", "c"); }\n',
                 'fn main() { println!("cargo:warning={0}", "c"); }\n',
                 'fn main() { println!("cargo:warning={:>8}", "c"); }\n'):
        found = problems(m, text)
        assert found == ['formatted output with a format specification'], f'd4-format-specification {text}: {found}'
    for text in ('fn main() { println!("cargo:warning={}", "c"); }\n',
                 'fn main() { println!("cargo:warning={path}", path = "c"); }\n'):
        assert problems(m, text) == [], f'd4-format-specification accepted {text}: {problems(m, text)}'


@unit('d4-reviewed-exact')
def case_d4_reviewed_exact(m, tmp, checker):
    text = ('fn main() { let path = std::path::Path::new("src"); '
            'println!("cargo:rerun-if-changed={}", path.parent().unwrap().display()); }\n')
    found = [problem for _, problem, _ in m.cfg_emissions(text, {REVIEWED_LINE})]
    assert found == ['formatted output with a non-literal argument'], f'd4-reviewed-exact: {found}'


@unit('d4-newline-argument')
def case_d4_newline_argument(m, tmp, checker):
    found = problems(m, 'fn main() { println!("cargo:warning={}", "x\\ny"); }\n')
    assert found == ['formatted output argument can start a directive'], f'd4-newline-argument: {found}'


@unit('d4-cfg-outside-println')
def case_d4_cfg_outside_println(m, tmp, checker):
    found = problems(m, 'const CFG: &str = "cargo:rustc-cfg=feature=\\"mainnet-write\\"";\n'
                        'fn main() { let _ = CFG; }\n')
    assert found == ['rustc-cfg outside a println! format'], f'd4-cfg-outside-println: {found}'


@unit('d4-stdout')
def case_d4_stdout(m, tmp, checker):
    found = problems(m, 'use std::io::Write;\nfn main() {\n'
                        '    writeln!(std::io::stdout(), "x").unwrap();\n    print!("y");\n}\n')
    assert found == ['unsupported standard output'] * 2, f'd4-stdout: {found}'


@unit('rust-lexer')
def case_rust_lexer(m, tmp, checker):
    sample = ("let a = '\"'; // " + m.MARKER + "x\n"
              "/* outer /* inner */ " + m.MARKER + "y */ let b = r#\"x\"y\"#;\n"
              "let c = \"q\\\"r\"; let d: &'static str = \"s\";\n")
    code, strings = m.rust_code(sample)
    found = (m.MARKER in code, [value for _, _, value in strings], len(code), code.count('\n'))
    assert found == (False, ['x"y', 'q"r', 's'], len(sample), 3), f'rust-lexer: {found}'


def marker_root(m, tmp, name, build_info, extra):
    root = tmp / name
    core = root / 'crates/stellar-agent-core/src'
    core.mkdir(parents=True)
    (core / 'build_info.rs').write_text(build_info)
    for relative, text in extra.items():
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_text(text)
    return bare_checker(m, root)


@unit('d12-string-literal')
def case_d12_string_literal(m, tmp, checker):
    build_info = (ROOT / 'crates/stellar-agent-core/src/build_info.rs').read_text()
    c = marker_root(m, tmp, 'd12-string-literal', build_info, {
        'crates/sample/src/lib.rs': 'const URL: &str = "https://' + m.MARKER + 'off";\n',
        'crates/sample/src/notes.rs': '// ' + m.MARKER + 'off\n/* ' + m.MARKER + 'on */\n'})
    c.D12()
    assert c.errors == ['D12: crates/sample/src/lib.rs: 1 marker literals, expected 0'], f'd12-string-literal: {c.errors}'


@unit('d12-missing-literal')
def case_d12_missing_literal(m, tmp, checker):
    build_info = (ROOT / 'crates/stellar-agent-core/src/build_info.rs').read_text()
    assert build_info.count(m.MARKER + 'on"') == 1, 'd12-missing-literal: the core arm moved'
    c = marker_root(m, tmp, 'd12-missing-literal', build_info.replace(m.MARKER + 'on"', 'OTHER=on"'), {})
    c.D12()
    assert c.errors == ['D12: crates/stellar-agent-core/src/build_info.rs: 1 marker literals, expected 2'], \
        f'd12-missing-literal: {c.errors}'


def cross_checker(m, tmp, name, old='', new=''):
    root = tmp / name
    root.mkdir()
    text = (ROOT / 'Cross.toml').read_text()
    assert old in text, f'{name}: Cross.toml drifted'
    (root / 'Cross.toml').write_text(text.replace(old, new, 1))
    return bare_checker(m, root)


@unit('d6-image')
def case_d6_image(m, tmp, checker):
    digest = re.search(r'sha256:([0-9a-f]{64})', (ROOT / 'Cross.toml').read_text())[1]
    accepts(cross_checker(m, tmp, 'd6-live'), 'D6', 'd6-image live')
    accepts(cross_checker(m, tmp, 'd6-bump', digest, 'a' * 64), 'D6', 'd6-image digest bump')
    rejects(cross_checker(m, tmp, 'd6-repository', 'ghcr.io/cross-rs/', 'ghcr.io/other/'), 'D6', 'pinned by digest')
    rejects(cross_checker(m, tmp, 'd6-tag', '@sha256:' + digest, ':0.2.5'), 'D6', 'pinned by digest')


@unit('d6-pre-build')
def case_d6_pre_build(m, tmp, checker):
    rejects(cross_checker(m, tmp, 'd6-pre-build', 'libudev-dev:$CROSS_DEB_ARCH',
                          'libudev-dev:$CROSS_DEB_ARCH libssl-dev'), 'D6', 'pre-build commands differ')


def job(steps, **extra):
    return {'jobs': {'job': {'steps': steps, **extra}}}


@unit('d7-job-env')
def case_d7_job_env(m, tmp, checker):
    rejects(bare_checker(m, workflows={'w.yml': job([], env={REFUSED: '-C x'})}), 'D7', 'refused env mapping')


@unit('d7-step-env')
def case_d7_step_env(m, tmp, checker):
    rejects(bare_checker(m, workflows={'w.yml': job([{'env': {REFUSED: '-C x'}, 'run': 'true'}])}),
            'D7', 'refused env mapping')


@unit('d7-composite-env')
def case_d7_composite_env(m, tmp, checker):
    action = {'runs': {'steps': [{'env': {REFUSED.lower(): '-C x'}, 'run': 'true', 'shell': 'bash'}]}}
    rejects(bare_checker(m, workflows={'.github/actions/x/action.yml': action}), 'D7', 'refused env mapping')


@unit('d7-run-assignment')
def case_d7_run_assignment(m, tmp, checker):
    rejects(bare_checker(m, workflows={'w.yml': job([{'run': f'export {REFUSED}=-Cdebuginfo=0'}])}),
            'D7', 'refused assignment')


@unit('d7-powershell')
def case_d7_powershell(m, tmp, checker):
    run = f'$env:{REFUSED.lower()} = "-C x"'
    rejects(bare_checker(m, workflows={'w.yml': job([{'shell': 'pwsh', 'run': run}])}), 'D7', 'refused assignment')


OUTSIDE = 'environment-file line outside the modelled forms'
UNPLACED = 'a line the scanner cannot place in a text that names the environment file'
LOWER = REFUSED.lower()


def outside(m, lines, label):
    """Every line falls outside the modelled environment-file forms."""
    for line in lines:
        found = m.env_file_problem(line)
        assert found == OUTSIDE, f'{label} {line}: {found}'


@unit('d7-env-file-write')
def case_d7_env_file_write(m, tmp, checker):
    for run in (f'echo "{LOWER}=-Cx" >> "$GITHUB_ENV"', f"Add-Content $env:GITHUB_ENV '{LOWER}=-Cx'"):
        rejects(bare_checker(m, workflows={'w.yml': job([{'run': run}])}), 'D7', 'refused environment-file write')


@unit('d7-env-file-outside')
def case_d7_env_file_outside(m, tmp, checker):
    rejects(bare_checker(m, workflows={'w.yml': job([{'run': 'printf "SAFE=ok" >> "$GITHUB_ENV"'}])}), 'D7',
            OUTSIDE + ': printf "SAFE=ok" >> "$GITHUB_ENV"')
    rejects(bare_checker(m, workflows={'w.yml': job([{'run': 'echo "SAFE=ok" \\\n  >> "$GITHUB_ENV"'}])}), 'D7',
            'w.yml:2: ' + UNPLACED + ': >> "$GITHUB_ENV"')
    outside(m, (
        'printf "SAFE=ok" >> "$GITHUB_ENV"',
        'echo "SAFE=ok" | tee -a "$GITHUB_ENV"',
        'Set-Content $env:GITHUB_ENV "SAFE=ok"',
        'echo -e "SAFE=ok" >> "$GITHUB_ENV"',
        'echo -n SAFE=ok >> "$GITHUB_ENV"',
        'echo "SAFE=ok" "x" >> "$GITHUB_ENV"',
        "echo 'SAFE=ok' >> \"$GITHUB_ENV\"",
        'echo "NOTES<<D" >> "$GITHUB_ENV"',
        'Add-Content $env:GITHUB_ENV "NOTES<<D"',
        f'echo "SAFE=1\\n{REFUSED}=-Cx" >> "$GITHUB_ENV"',
        'echo "SAFE=a b" >> "$GITHUB_ENV"',
        'echo "SAFE=a\\nb" >> "$GITHUB_ENV"',
        'echo "SAFE=$(id)" >> "$GITHUB_ENV"',
        f'Add-Content $env:GITHUB_ENV "SAFE=ok`n{LOWER}=-Cx"',
        'Add-Content $env:GITHUB_ENV "SAFE=$x"',
        f'Add-Content $env:GITHUB_ENV "SAFE=ok","{LOWER}=-Cx"',
        'Add-Content -Path $env:GITHUB_ENV -Encoding utf8 -Value "SAFE=ok"',
        'Add-Content -Path $env:GITHUB_ENV -NoNewline -Value "SAFE="',
        'Add-Content $env:GITHUB_ENV SAFE=ok',
        "Add-Content $env:GITHUB_ENV \"SAFE=ok'",
        'Add-Content $env:GITHUB_ENV "SAFE=ok" | Out-Null',
        'echo "SAFE=ok" >> "$GITHUB_ENV" > /dev/null',
        'echo "SAFE=ok" > "$GITHUB_ENV"',
        'false && echo "SAFE=ok" >> "$GITHUB_ENV"',
        'echo "SAFE=ok" >> "$GITHUB_ENV"; true',
        'echo "SAFE=ok" >> "$GITHUB_ENV" # note',
        'echo "SAFE=ok" >> "$GITHUB_ENV}"',
        "echo \"SAFE=ok\" >> '$GITHUB_ENV'",
        'cat "$GITHUB_ENV"',
        'Add-Content $Env:GITHUB_ENV "SAFE=ok"',
        'Add-Content ${env:GITHUB_ENV} "SAFE=ok"',
    ), 'd7-env-file-outside')


@unit('d7-env-file-constraints')
def case_d7_env_file_constraints(m, tmp, checker):
    outside(m, (
        'echo "GITHUB_ENV_NOTE=x" >> "$OUT"',
        'echo "$NAME=ok" >> "$GITHUB_ENV"',
        'echo "SAFE=ok >> "$GITHUB_ENV"',
        'x; Add-Content $env:GITHUB_ENV "SAFE=ok"',
        'echo "SAFE=ok" >>"$GITHUB_ENV"',
        'ECHO "SAFE=ok" >> "$GITHUB_ENV"',
        'Add-Content -path $env:GITHUB_ENV -Value "SAFE=ok"',
        'echo "SAFE=ok" >> "$github_env"',
        'Add-Content $env:GITHUB_ENV "SAFE=a`b"',
        'echo "SAFE=ok" >> ${GITHUB_ENV',
        '\u00a0echo SAFE=ok >> "$GITHUB_ENV"',
        'echo "1SAFE=ok" >> "$GITHUB_ENV"',
        'Add-Content $env:GITHUB_ENV "1SAFE=ok"',
        'echo "SAFE=${VALUE" >> "$GITHUB_ENV"',
        'add-content $env:GITHUB_ENV "SAFE=ok"',
        'Add-Content -Path $env:GITHUB_ENV -value "SAFE=ok"',
        'Add-Content $env:GITHUB_ENV "SAFE=ok" "EXTRA=x"',
    ), 'd7-env-file-constraints')
    rejects(bare_checker(m, workflows={'w.yml': job([{'run': 'echo "SAFE=ok" >> "$github_env"'}])}), 'D7',
            OUTSIDE + ': echo "SAFE=ok" >> "$github_env"')


@unit('d7-env-file-context')
def case_d7_env_file_context(m, tmp, checker):
    for run, line in ((f'Write-Output "\n#"; Add-Content $env:GITHUB_ENV \'{LOWER}=-Cx\'', 'w.yml:1: '
                       + UNPLACED + ': Write-Output "'),
                      (f'echo \'x\n#\'; echo "{LOWER}=-Cx" >> "$GITHUB_ENV"', "w.yml:1: " + UNPLACED + ": echo 'x")):
        rejects(bare_checker(m, workflows={'w.yml': job([{'run': run}])}), 'D7', line)
    script = '# writes nothing to $GITHUB_ENV, the caller\'s file\necho "done"\n'
    rejects(bare_checker(m, scripts={'.github/scripts/sample.sh': script}), 'D7',
            '.github/scripts/sample.sh:1: ' + OUTSIDE + ": # writes nothing to $GITHUB_ENV, the caller's file")


@unit('d7-env-file-continuation')
def case_d7_env_file_continuation(m, tmp, checker):
    for run, line in (("printf '%s' \\\necho \"SAFE=ok\" >> \"$GITHUB_ENV\"", 'echo "SAFE=ok" >> "$GITHUB_ENV"'),
                      ("Write-Output x `\nAdd-Content $env:GITHUB_ENV \"SAFE=ok\"",
                       'Add-Content $env:GITHUB_ENV "SAFE=ok"'),
                      (f"printf '%s\\n' x\\\n#; printf '%s\\n' '{LOWER}=-Cx' >> \"$GITHUB_ENV\"\ntrue",
                       f"#; printf '%s\\n' '{LOWER}=-Cx' >> \"$GITHUB_ENV\"")):
        rejects(bare_checker(m, workflows={'w.yml': job([{'run': run}])}), 'D7', 'w.yml:2: ' + UNPLACED + ': ' + line)
    sodium = '.github/scripts/release/sodium.sh'
    accepts(bare_checker(m, scripts={sodium: (ROOT / sodium).read_text()}), 'D7', 'd7-env-file-continuation sodium')


@unit('d7-env-file-comment-line')
def case_d7_env_file_comment_line(m, tmp, checker):
    run = f"<#\n#> ; Add-Content $env:GITHUB_ENV '{LOWER}=-Cx'"
    rejects(bare_checker(m, workflows={'w.yml': job([{'shell': 'pwsh', 'run': run}])}), 'D7',
            f"w.yml:2: {OUTSIDE}: #> ; Add-Content $env:GITHUB_ENV '{LOWER}=-Cx'")


@unit('d7-python-env-file')
def case_d7_python_env_file(m, tmp, checker):
    sample = '.github/scripts/sample.py'
    text = f'import os\nopen(os.environ["GITHUB_ENV"], "a").write("{REFUSED}=-Cx\\n")\n'
    rejects(bare_checker(m, scripts={sample: text}), 'D7',
            f'{sample}:2: environment-file line in a Python script: open(os.environ["GITHUB_ENV"], "a")')
    lower = 'import os\nopen(os.environ["github_env"], "a")\n'
    rejects(bare_checker(m, scripts={sample: lower}), 'D7',
            f'{sample}:2: environment-file line in a Python script: open(os.environ["github_env"], "a")')
    accepts(bare_checker(m, scripts={sample: 'print("ok")\n'}), 'D7', 'd7-python-env-file plain script')
    readers = {path: (ROOT / path).read_text() for path in ('.github/scripts/check-workflow-invariants.py',
                                                           '.github/scripts/test-check-workflow-invariants.py')}
    accepts(bare_checker(m, scripts=readers), 'D7', 'd7-python-env-file readers')
    path = '.github/scripts/check-workflow-invariants.py'
    copy = {path: readers[path] + f"\nimport os\nos.environ['{REFUSED}'] = '-Cx'\n"}
    rejects(bare_checker(m, scripts=copy), 'D7', f'refused Python environment {REFUSED}')


@unit('d7-env-file-counterexamples')
def case_d7_env_file_counterexamples(m, tmp, checker):
    outside(m, (
        "Add-Content $env:GITHUB_ENV 'NOTES<<$env:GITHUB_ENV'",
        "Add-Content $env:GITHUB_ENV '$env:GITHUB_ENV','SAFE=ok'",
        f'Add-Content $env:GITHUB_ENV "{LOWER}=-C x"',
        'Add-Content -Path $env:GITHUB_ENV -Value "NOTES<<-Value"',
        f'Add-Content -Path $env:GITHUB_ENV -Value "{LOWER}=-C x"',
        'Add-Content -Path $env:GITHUB_ENV -Value "-Value"',
        'echo "NOTES<<D" >> "$GITHUB_ENV" > /dev/null',
        f"printf '%s=%s\\n' {REFUSED} '-C x' >> \"$GITHUB_ENV\"",
        'echo "NOTES<<D" >> "$GITHUB_ENV}"',
        "echo \"NOTES<<D\" >> '$GITHUB_ENV'",
        'false && echo "NOTES<<D" >> "$GITHUB_ENV"',
        'echo "NOTES<<D" >> "$GITHUB_ENV"',
        f"printf '%s=%s\\n' {REFUSED} '-C x' | tee -- \"$GITHUB_ENV\" -a",
        "echo -e 'SAFE=ok' >> \"$GITHUB_ENV\"",
    ), 'd7-env-file-counterexamples')


@unit('d7-env-file-accepted')
def case_d7_env_file_accepted(m, tmp, checker):
    run = ('echo "RUSTUP_TOOLCHAIN=$RELEASE_TOOLCHAIN" >> "$GITHUB_ENV"\n'
           'echo SAFE=ok >> $GITHUB_ENV\n'
           'echo "SODIUM_DIST_DIR=${DIST_DIR}/lib" >> "${GITHUB_ENV}"\n'
           'echo SAFE=ok >> ${GITHUB_ENV}\n'
           'Add-Content $env:GITHUB_ENV "OPENSSL_SRC_PERL=C:\\Strawberry\\perl\\bin\\perl.exe"\n'
           'Add-Content -Path $env:GITHUB_ENV -Value "SAFE=ok"\n'
           "Add-Content $env:GITHUB_ENV 'SAFE=ok'\n"
           'echo "SAFE=" >> "$GITHUB_ENV"\n'
           'Add-Content $env:GITHUB_ENV "SAFE="\n'
           "# the runner's step reads this file")
    accepts(bare_checker(m, workflows={'w.yml': job([{'run': run}])}), 'D7', 'd7-env-file-accepted')


@unit('d7-python-env')
def case_d7_python_env(m, tmp, checker):
    path = '.github/scripts/sample.py'
    for source, fragment in (
            ("import subprocess\nsubprocess.run(['x'], env={'" + REFUSED + "': '-C x'})\n",
             'refused Python environment'),
            ("import os\nos.environ['" + REFUSED + "'] = '-C x'\n", 'refused Python environment'),
            ("import subprocess\nname = 'X'\nsubprocess.run(['x'], env={name: '1'})\n",
             'environment name is not a literal')):
        rejects(bare_checker(m, scripts={path: source}), 'D7', fragment)


@unit('d8-workflow')
def case_d8_workflow(m, tmp, checker):
    (tmp / 'docs/maintainers').mkdir(parents=True, exist_ok=True)
    (tmp / 'docs/maintainers/building.md').write_text('')
    rejects(bare_checker(m, tmp, {'w.yml': job([{'run': 'cargo build ' + m.ALL_FEATURES}])}), 'D8', 'w.yml')


@unit('d8-reader')
def case_d8_reader(m, tmp, checker):
    (tmp / 'docs/maintainers').mkdir(parents=True, exist_ok=True)
    (tmp / 'docs/maintainers/building.md').write_text('')
    path = '.github/scripts/check-workflow-invariants.py'
    text = (ROOT / path).read_text() + '\n# cargo build ' + m.ALL_FEATURES + '\n'
    rejects(bare_checker(m, tmp, scripts={path: text}), 'D8', path)


@unit('d8-script')
def case_d8_script(m, tmp, checker):
    (tmp / 'docs/maintainers').mkdir(parents=True, exist_ok=True)
    (tmp / 'docs/maintainers/building.md').write_text('')
    rejects(bare_checker(m, tmp, scripts={'.github/scripts/s.sh': 'cargo build ' + m.ALL_FEATURES}),
            'D8', '.github/scripts/s.sh')


@unit('d9-script')
def case_d9_script(m, tmp, checker):
    rejects(bare_checker(m, scripts={'.github/scripts/s.sh': 'cargo build --features ' + m.FEATURE}),
            'D9', '.github/scripts/s.sh: feature activation')


@unit('d9-workflow-env')
def case_d9_workflow_env(m, tmp, checker):
    workflow = {'env': {'EXTRA': m.FEATURE}, **job([{'run': 'cargo build --features "$EXTRA"'}])}
    rejects(bare_checker(m, workflows={'release.yml': workflow}), 'D9', 'outside allowed jobs')


@unit('d9-echo-and-comments')
def case_d9_echo_and_comments(m, tmp, checker):
    run = (f'echo "{m.FEATURE} stays off"\necho ok # {m.FEATURE} stays off\n'
           f'# {m.FEATURE} is off\ncargo build --features test-helpers')
    workflows = {'release.yml': {'env': {'NOTE': m.FEATURE}, **job([{'run': run}])},
                 'ci.yml': {'jobs': {'feature-on-test': {'steps': [
                     {'run': 'cargo test --features ' + m.FEATURE}]}}}}
    accepts(bare_checker(m, workflows=workflows), 'D9', 'd9-echo-and-comments')


@unit('d10-documentation')
def case_d10_documentation(m, tmp, checker):
    import yaml
    root = tmp / 'd10-documentation'
    (root / 'docs/maintainers').mkdir(parents=True)
    text = (ROOT / 'docs/maintainers/building.md').read_text()
    line = re.search(r'^FEATURES_EXCEPT_MAINNET_WRITE=[\w,-]+$', text, re.M)[0]
    (root / 'docs/maintainers/building.md').write_text(text.replace(line, line.rsplit(',', 1)[0], 1))
    ci = yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text())
    c = bare_checker(m, root, {'ci.yml': ci}, packages=live_packages(m))
    c.D10()
    assert c.errors == ['D10: documented feature set differs from metadata'], f'd10-documentation: {c.errors}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutations', action='store_true')
    parser.add_argument('--case')
    parser.add_argument('--checker', type=pathlib.Path, default=HERE / 'check-feature-discipline.py')
    args = parser.parse_args()
    rules = [f'D{i}' for i in range(1, 14)]
    if args.case and args.case not in (*UNITS, *GRAPHS, *rules, 'units', 'graphs'):
        print(f'FAIL unknown case {args.case}', file=sys.stderr)
        return 2
    m = load(args.checker)
    (ROOT / 'target/tmp').mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(dir=ROOT / 'target/tmp') as scratch:
            tmp = pathlib.Path(scratch)
            for name, case in UNITS.items():
                if not args.case or args.case in (name, 'units'):
                    directory = tmp / 'units' / name
                    directory.mkdir(parents=True)
                    case(m, directory, args.checker)
                    print(f'ok {name}')
            if not args.case or args.case == 'graphs' or args.case in GRAPHS:
                graph_cases(m, tmp / 'graphs', None if args.case in (None, 'graphs') else args.case)
            mutants = {}
            for rule in rules:
                if args.case and args.case != rule:
                    continue
                for variant in range(VARIANTS.get(rule, 1)):
                    regression(m, rule, tmp / 'rules', variant)
                    print(f'ok {rule} variant {variant}')
                    if not args.mutations:
                        continue
                    if rule not in mutants:
                        source = args.checker.read_text()
                        needle = f'    def {rule}(self):\n'
                        assert source.count(needle) == 1, f'{rule}: rule method not found'
                        path = tmp / f'mutant-{rule}.py'
                        docstring = source.split(needle, 1)[1].split('\n', 1)[0] + '\n'
                        path.write_text(source.replace(needle + docstring, needle + docstring + '        return\n', 1))
                        mutants[rule] = load(path)
                    try:
                        regression(mutants[rule], rule, tmp / 'mutants', variant)
                    except AssertionError as error:
                        if 'violating fixture accepted' not in str(error):
                            raise
                        print(f'ok mutation-{rule} variant {variant}: the regression fails against the disabled rule')
                    else:
                        raise AssertionError(f'{rule}: the regression passed against the disabled rule')
    except (AssertionError, ValueError, OSError) as error:
        print(f'FAIL {error}', file=sys.stderr)
        return 1
    print('feature discipline tests passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
