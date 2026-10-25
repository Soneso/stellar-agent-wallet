#!/usr/bin/env python3
"""Fail closed on accidental mainnet-write activation in builds and releases.

Metadata and resolved graphs are read offline from the locked workspace.
The command inventory records the executable cargo and cross calls of the
workflows and of the scripts they name. DATA_SCRIPTS lists the scripts
whose cargo text is fixture data; their own self-tests and the preflight
drift check cover them. Shell syntax the scanner does not model fails
closed when its text runs cargo or cross.

Rules:
  D1  the four mainnet-write declarations hold, and no other feature, no
      default and no normal dependency declaration reaches mainnet-write
  D2  no dev or build dependency declaration requests a feature that
      reaches mainnet-write
  D3  every cargo and cross call matches the reviewed inventory, and each
      resolved graph has mainnet-write in the state its record relies on;
      spaces and tabs are the only blanks and a line ends at a line feed;
      a heredoc is read only when its delimiter, after << and at most one
      space, is an identifier, alone or in one pair of quotes, and, when
      unquoted, with no body line that ends in a backslash; a here-string
      that runs cargo is read only when each command word that reads it
      is a bare word that names no interpreter or command runner, and an
      interpreter outside that table, such as busybox sh, reads a
      here-string unseen
  D4  no custom-build source emits a feature cfg, and every line it
      prints is a literal or a formatted line with {} or {name}
      placeholders whose arguments are plain literals or form a reviewed
      statement
  D5  the tree holds no cargo configuration file
  D6  Cross.toml holds only a digest-pinned cross-rs aarch64 image and the
      two pre-build commands
  D7  no workflow, composite action or named script sets a variable that
      injects compiler flags, compiler wrappers or features; a text is a
      workflow or action string after YAML decoding, or a script file; a
      NAME is an ASCII letter or underscore followed by ASCII letters,
      digits or underscores; in a text that names the environment file,
      in any case, every line that is no comment holds balanced double
      and single quotes, no line naming the
      file follows a line ending in a backslash or a backtick, and each
      line naming the file, a comment included, is an echo of one
      NAME=VALUE argument appended to $GITHUB_ENV or an Add-Content of one
      quoted NAME=VALUE string to $env:GITHUB_ENV, words separated by
      spaces or tabs and spelled in exactly that case; every other such
      line is refused, among them printf, tee, Set-Content, multiline
      entries, options other than -Path and -Value, arrays and reads; a
      named Python script names the file on no line, apart from
      ENV_FILE_READERS; the value of a referenced variable is not read, so
      one that holds a line break, or backslashes under an echo that
      expands them, writes more entries; a function or alias defined
      earlier that redefines echo or Add-Content changes what a shape line
      writes; escaped quotes keep the raw counts even while an argument
      spans lines, as after printf "\\"; and a shape line inside a heredoc
      body or a PowerShell block comment is data and writes nothing
  D8  no workflow, named script or building.md enables every feature
  D9  only the CI feature-on jobs and the coverage job activate
      mainnet-write
  D10 the CI and documented feature lists equal the declared features
      except default and mainnet-write
  D11 the release, publish and rehearsal workflows expect the marker off
  D12 the marker literal appears in crates/ only in core's two cfg arms
"""
import argparse
import ast
from collections import Counter
import fnmatch
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tomllib

FEATURE = 'mainnet-write'
ALL_FEATURES = '--all-' + 'features'
MARKER = 'STELLAR_AGENT_BUILD_' + 'MAINNET_WRITE='
PACKAGES = tuple('stellar-agent-' + name for name in ('core', 'network', 'cli', 'mcp'))
DECLARATIONS = {
    PACKAGES[0]: [],
    PACKAGES[1]: [PACKAGES[0] + '/' + FEATURE],
    PACKAGES[2]: [PACKAGES[0] + '/' + FEATURE, PACKAGES[1] + '/' + FEATURE],
    PACKAGES[3]: [PACKAGES[0] + '/' + FEATURE, PACKAGES[1] + '/' + FEATURE],
}
REFUSED_VARS = ['RUST' + 'C', 'RUSTC_' + 'WRAPPER', 'RUSTC_WORKSPACE_' + 'WRAPPER',
                'CARGO_BUILD_' + 'RUSTC*', 'RUST' + 'FLAGS', 'CARGO_ENCODED_' + 'RUSTFLAGS',
                'CARGO_BUILD_' + 'RUSTFLAGS', 'CARGO_TARGET_*_' + 'RUSTFLAGS',
                'TARGET_*_' + 'RUSTFLAGS', 'CARGO_' + 'FEATURE_*', 'CROSS_' + '*']
# Rustdoc flag variables, refused when their value passes --cfg.
RUSTDOC_VARS = ('RUSTDOCFLAGS', 'CARGO_BUILD_RUSTDOCFLAGS',
                'CARGO_ENCODED_RUSTDOCFLAGS')
# D7 skips these paths, each for the reason given.
EXEMPT = {
    '.github/scripts/test-rebuild-vendored-wasm.sh':
        'assigns refused variables to prove that the rebuild refuses them',
    '.github/scripts/check-feature-discipline.py':
        'spells the refused variables as the list it enforces',
    '.github/scripts/test-check-feature-discipline.py':
        'assigns refused variables to prove that this checker refuses them',
}
# Named Python scripts that spell the environment file as text they read
# and never write it, each for the reason given. D7 skips only its
# environment-file line rule for them; D8 and the assignment scan still read
# them.
ENV_FILE_READERS = {
    '.github/scripts/check-workflow-invariants.py':
        'spells the release toolchain pin as the step text it requires',
    '.github/scripts/test-check-workflow-invariants.py':
        'holds that step text as a fixture',
}
# D3 and D9 read the cargo and cross text of these scripts as data, each
# for the reason given. Every other named script is scanned for commands.
DATA_SCRIPTS = {
    '.github/scripts/preflight.sh':
        'its registry rows mirror CI steps for local runs, and '
        'test-preflight.sh compares them with the workflows',
    '.github/scripts/test-preflight.sh':
        'runs preflight.sh against stub tools and expected registry rows',
    '.github/scripts/check-feature-discipline.py':
        'runs the metadata and tree queries this inventory derives',
    '.github/scripts/test-check-feature-discipline.py':
        'builds and queries scratch fixture workspaces only',
    '.github/scripts/test-check-crates-exist.sh':
        'drives check-crates-exist.sh with a stub cargo',
    '.github/scripts/test-publish-crates-check.sh':
        'reads workspace metadata into a stub fixture and runs '
        'publish-crates.sh, whose calls the publish tier step lists',
    '.github/scripts/test-publish-crates-verify.sh':
        'reads workspace metadata into a stub fixture and drives '
        'publish-crates.sh with a stub cargo',
    '.github/scripts/test-release-checks.sh':
        'drives the release check scripts with stub cargo, 7z and binaries',
}
# Each flag's arity is explicit. Compilation and output filters do not
# select crates.
DROP_FLAGS = {
    '--all-targets': 0, '--lib': 0, '--bins': 0, '--tests': 0, '--examples': 0,
    '--benches': 0, '--bin': 1, '--test': 1, '--example': 1, '--bench': 1,
    '--no-run': 0, '--release': 0, '--locked': 0, '--offline': 0, '--frozen': 0,
    '--target': 1, '--target-dir': 1, '--no-deps': 0, '--json': 0, '--lcov': 0,
    '--html': 0, '--text': 0, '--summary-only': 0, '--output-path': 1,
    '--output-dir': 1, '--ignore-filename-regex': 1, '--doctests': 0,
    '--show-instantiations': 0, '--branch': 0, '--no-report': 0,
    '--jobs': 1, '-j': 1, '--color': 1, '--message-format': 1,
}
FAMILIES = {'build': 'normal,build', 'check': 'normal,build',
            'test': 'normal,build,dev', 'clippy': 'normal,build,dev',
            'doc': 'normal,build,dev', 'llvm-cov': 'normal,build,dev'}
# Target selections that compile tests, benches or examples: a build or
# check with one of them resolves the dev-dependencies too.
DEV_TARGET_FLAGS = ('--all-targets', '--tests', '--test', '--benches',
                    '--bench', '--examples', '--example')
SCRIPT_REF = re.compile(r'\.github/(?:scripts|actions)/[\w./-]+\.(?:sh|py|ps1)')
# A cargo or cross command word followed by an argument.
CARGO_WORD = re.compile(r'(?<![\w.-])(?:cargo|cross)[ \t]')
# A shell that runs its -c argument as a script, and eval. The scanner
# does not model the command text they receive.
SHELL_STRING = re.compile(
    r'(?:(?:(?:ba|da|k|z)?sh|pwsh|powershell)[ \t]+(?:--?[A-Za-z-]+[ \t]+)*'
    r'-(?:[A-Za-z]*c[A-Za-z]*|Command|EncodedCommand)|eval)(?=[ \t])')
# A shell or interpreter that runs the text it reads.
INTERPRETER_NAME = (r'(?:(?:ba|da|k|z)?sh|pwsh|powershell|python3?|node|perl|'
                    r'ruby)')
# A command that executes a heredoc body as a program.
INTERPRETER = re.compile(
    r'(?:^|[ \t;&|(`/])' + INTERPRETER_NAME + r'(?=[ \t<|;&)]|$)')
# A command that runs another command named in its arguments.
COMMAND_RUNNER = (r'(?:env|exec|command|builtin|sudo|doas|nice|nohup|time|'
                  r'timeout|xargs|stdbuf|setsid)')
# The command word of a shell segment after its assignment words, the
# command word the scanner reads, and an interpreter or a command runner
# as that word.
COMMAND_WORD = re.compile(
    r'[ \t]*(?:[A-Za-z_]\w*=(?:"[^"]*"|\'[^\']*\'|[^ \t"\'])*[ \t]+)*([^ \t<>|;&()]*)')
BARE_WORD = re.compile(r'[A-Za-z0-9_./+-]+')
INTERPRETER_WORD = re.compile(
    r'(?:[^ \t]*/)?(?:' + INTERPRETER_NAME + '|' + COMMAND_RUNNER + ')')
# A heredoc operator and its delimiter: a bare word, or that word wholly
# inside one pair of single or double quotes, ending at a space, a tab, an
# operator or the end of the line.
HEREDOC = re.compile(
    r'<< ?(?:([A-Za-z_][A-Za-z0-9_]*)|\'([A-Za-z_][A-Za-z0-9_]*)\'|"([A-Za-z_][A-Za-z0-9_]*)")'
    r'(?=[ \t;&|<>)]|$)')
# The blanks that separate shell words.
BLANKS = ' \t'
# A bash assignment to an upper-case name, and a PowerShell environment
# assignment, whose name Windows reads without regard to case.
SHELL_ASSIGNMENT = re.compile(r'\b([A-Z][A-Z0-9_]*)\s*=')
POWERSHELL_ASSIGNMENT = re.compile(r'\$env:([A-Za-z_]\w*)\s*=', re.I)
# The two environment-file lines D7 models, each appending one NAME=VALUE
# entry: echo of one argument, bare or double-quoted, to the bash file
# reference, and Add-Content of one quoted string to the PowerShell
# reference. A bash value holds plain characters and variable references;
# a PowerShell value holds plain characters and backslashes, which
# PowerShell keeps as they stand.
ENV_NAME = r'[A-Za-z_][A-Za-z0-9_]*'
ENV_REFERENCE = r'\$' + ENV_NAME + r'|\$\{' + ENV_NAME + r'\}'
ENV_FILE_ECHO = re.compile(
    r'echo[ \t]+(?P<quote>"?)(?P<name>' + ENV_NAME
    + r')=(?P<value>(?:[A-Za-z0-9_./:@+-]|' + ENV_REFERENCE + r')*)'
    r'(?P=quote)[ \t]+>>[ \t]+'
    r'(?:"\$GITHUB_ENV"|\$GITHUB_ENV|"\$\{GITHUB_ENV\}"|\$\{GITHUB_ENV\})')
ENV_FILE_CONTENT = re.compile(
    r'Add-Content[ \t]+(?:\$env:GITHUB_ENV|-Path[ \t]+\$env:GITHUB_ENV[ \t]+-Value)[ \t]+'
    r'(?P<quote>["\'])(?P<name>' + ENV_NAME
    + r')=(?P<value>[A-Za-z0-9_./:\\@+-]*)'
    r'(?P=quote)')
# Rust comments, string and character literals, as the lexer finds them.
RUST_TOKEN = re.compile(
    r'(?P<line>//)|(?P<block>/\*)'
    r'|(?<!\w)(?P<raw>(?:br|cr|r)(?P<hashes>#*)")'
    r'|(?P<string>(?:(?<!\w)[bc])?")'
    r"|(?<!\w)(?P<char>b?'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|[^\n])"
    r"|[^\\'\n])')")
RUST_STRING_BODY = re.compile(r'(?:[^"\\]|\\.)*"', re.S)
RUST_BLOCK_EDGE = re.compile(r'/\*|\*/')
RUST_ESCAPE = re.compile(
    r'\\(?:\n\s*|x([0-9a-fA-F]{2})|u\{([0-9a-fA-F]{1,6})\}|(.))', re.S)
# A build-script directive with a literal key.
DIRECTIVE = re.compile(r'cargo::?([A-Za-z0-9_-]+)=')
# Text that lets a formatted argument start another directive line.
DIRECTIVE_TOKENS = ('\n', 'cargo:', 'rustc-')
# A placeholder of a format string, the placeholder field D4 supports
# beside the empty one, and a named format argument.
PLACEHOLDER = re.compile(r'\{([^{}]*)\}')
PLACEHOLDER_NAME = re.compile(r'[A-Za-z_]\w*')
NAMED_ARGUMENT = re.compile(r'\s*([A-Za-z_]\w*)\s*=(?!=)\s*')
# Formatted build-script emissions whose arguments D4 cannot read, each
# reviewed as printing one directive with a key other than rustc-cfg: the
# build script and the statement, whitespace collapsed. Any change to a
# statement makes it unreviewed again. The review covers how each
# argument is built: the smart-account path joins CARGO_MANIFEST_DIR and
# a constant vendored path, so a change to how that path is built needs
# the same review even when the statement text stays identical.
REVIEWED_EMISSIONS = {
    'crates/stellar-agent-smart-account/build.rs': {
        'println!("cargo:rerun-if-changed={}", path.display())',
    },
}
# The cross image Cross.toml may name; Cross.toml alone holds the digest.
CROSS_IMAGE = r'ghcr\.io/cross-rs/aarch64-unknown-linux-gnu@sha256:[0-9a-f]{64}'
CROSS_PRE_BUILD = ['dpkg --add-architecture $CROSS_DEB_ARCH',
                   'apt-get update && apt-get install --assume-yes libudev-dev:$CROSS_DEB_ARCH']


def run_cargo(root, args):
    result = subprocess.run(['cargo', *args], cwd=root, text=True, capture_output=True,
                            env={**os.environ, 'CARGO_NET_OFFLINE': 'true'})
    if result.returncode:
        raise ValueError('cargo ' + ' '.join(args) + ': ' + result.stderr.strip())
    return result.stdout


def numbered_lines(text, raw=lambda: False):
    """Yield (line number, logical line) of shell text.

    A physical line ends at a line feed. Continuation lines are joined,
    comment lines skipped and spaces and tabs stripped. The number is the
    first physical line of the logical line. While raw() holds, each
    physical line is yielded as it stands, so a heredoc body keeps its
    blanks, backslashes and comment lines.
    """
    pending, start = '', 1
    for number, line in enumerate(text.split('\n'), 1):
        if not pending and raw():
            yield number, line
            continue
        if line.lstrip(BLANKS).startswith('#'):
            continue
        if not pending:
            start = number
        line = pending + line.strip(BLANKS)
        if line.endswith('\\'):
            pending = line[:-1] + ' '
        else:
            pending = ''
            if line:
                yield start, line
    if pending:
        raise ValueError('unterminated shell continuation')


def logical_lines(text):
    for _, line in numbered_lines(text):
        yield line


def run_text(step):
    """The text of a step's run: value; YAML can parse one as another
    scalar type."""
    value = step.get('run')
    return '' if value is None else str(value)


def refused(name):
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in REFUSED_VARS)


def refused_value(name, value):
    """Whether a variable assignment can inject flags or features.

    Windows reads environment names without regard to case, so the name is
    compared in upper case.
    """
    name = str(name).upper()
    return refused(name) or (name in RUSTDOC_VARS and '--cfg' in str(value))


def config_paths(root):
    for directory, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ('target', 'node_modules', '.git')]
        if pathlib.Path(directory).name == '.cargo':
            for name in ('config', 'config.toml'):
                if name in files:
                    yield pathlib.Path(directory) / name


def env_guard(directory, environ):
    errors = [f'refused environment variable {name}' for name in environ if refused(name)]
    for name in RUSTDOC_VARS:
        if '--cfg' in environ.get(name, ''):
            errors.append(f'{name} contains --cfg')
    locations = [parent / '.cargo' for parent in (directory, *directory.parents)]
    cargo_home = pathlib.Path(environ.get('CARGO_HOME', str(pathlib.Path.home() / '.cargo')))
    locations.append(cargo_home)
    for location in dict.fromkeys(locations):
        for name in ('config', 'config.toml'):
            if (location / name).exists():
                errors.append(f'cargo config exists: {location / name}')
    return errors


def translate(command):
    words = shlex.split(command)
    if len(words) < 2 or words[0] not in ('cargo', 'cross') or words[1] not in FAMILIES:
        raise ValueError('unsupported resolving command family')
    family = words[1]
    edges = FAMILIES[family]
    selected, features, target = [], [], None
    i = 2
    while i < len(words):
        word = words[i]
        if word == '--':
            break
        flag, equal, value = word.partition('=')
        if flag in (ALL_FEATURES, '--config'):
            raise ValueError(f'forbidden flag {flag}')
        if flag in ('-p', '--package', '--features', '-F', '--exclude'):
            if not equal:
                i += 1
                if i == len(words):
                    raise ValueError(f'missing value for {flag}')
                value = words[i]
            if flag in ('--features', '-F'):
                features.extend(['--features', value])
            else:
                selected.extend(['-p' if flag in ('-p', '--package') else flag, value])
        elif flag in ('--workspace', '--no-default-features'):
            if equal:
                raise ValueError(f'unexpected value for {flag}')
            (selected if flag == '--workspace' else features).append(flag)
        elif flag in DROP_FLAGS:
            arity = DROP_FLAGS[flag]
            if flag in DEV_TARGET_FLAGS and family in ('build', 'check'):
                edges = 'normal,build,dev'
            if arity:
                if not equal:
                    i += 1
                    if i == len(words):
                        raise ValueError(f'missing value for {flag}')
                    value = words[i]
                if flag == '--target':
                    target = value
            elif equal:
                raise ValueError(f'unexpected value for {flag}')
        elif word.startswith('-') or family not in ('test', 'llvm-cov'):
            raise ValueError(f'unclassified argument {word}')
        i += 1
    if not selected or (selected and selected[0] == '--exclude'):
        selected.insert(0, '--workspace')
    return {'selection': selected, 'features': features, 'edges': edges, 'target': target}


def parse_tree(output):
    found = {name: [] for name in PACKAGES}
    for line in output.splitlines():
        if not line or line in ('[build-dependencies]', '[dev-dependencies]'):
            continue
        line = line.replace(' (*)', '')
        if ' ' not in line:
            raise ValueError(f'invalid cargo tree line: {line!r}')
        features, package = line.split(' ', 1)
        name = package.split(' ', 1)[0]
        if name in found:
            found[name].append(FEATURE in features.split(','))
    return found


def graph_state(root, translated):
    # Inverse package specs fail when a requested crate is absent. A single
    # forward graph preserves Cargo's package/feature selection and lets the
    # parser record absent declaring crates without suppressing Cargo errors.
    args = ['tree', '--locked', '--offline', '--prefix', 'none', '--target', 'all',
            '-e', translated['edges'] + ',features', '-f', '{f} {p}',
            *translated['selection'], *translated['features']]
    return parse_tree(run_cargo(root, args))


def expand(command, env):
    def expression(match):
        key = match[1].strip()
        if key.startswith('env.'):
            key = key[4:]
        if key not in env:
            raise ValueError(f'unresolved variable {key}')
        return str(env[key])
    command = re.sub(r'\$\{\{\s*(.*?)\s*\}\}', expression, command)
    def shell(match):
        key = match[1] or match[2]
        if key not in env:
            raise ValueError(f'unresolved variable {key}')
        return str(env[key])
    result = re.sub(r'\$\{([\w]+)\}|\$([A-Za-z_]\w*)', shell, command)
    if '$' in result:
        raise ValueError('unresolved variable in ' + result)
    return result


def check_heredoc(heredoc, source):
    """Refuse a heredoc body whose cargo or cross text could execute."""
    text = '\n'.join(heredoc['lines'])
    if not CARGO_WORD.search(text):
        return
    where = f"{source}:{heredoc['number']}"
    if heredoc['interpreter']:
        raise ValueError(f'{where}: an interpreter executes a heredoc that '
                         f'runs cargo or cross: {heredoc["line"]}')
    if not heredoc['quoted'] and ('$(' in text or '`' in text):
        raise ValueError(f'{where}: a substitution in an unquoted heredoc '
                         f'runs cargo or cross: {heredoc["line"]}')


def here_string_reader(word, own):
    """Return why the command word that reads a here-string whose text runs
    cargo or cross is refused, or None.

    own is true for the command of the here-string's own segment and false
    for a command a pipe feeds. The scanner reads only a BARE_WORD that
    names neither an interpreter nor a COMMAND_RUNNER.
    """
    if own and not word:
        return 'a here-string before the command word runs cargo or cross'
    if not BARE_WORD.fullmatch(word):
        return 'an unmodelled command word reads a here-string that runs cargo or cross'
    if INTERPRETER_WORD.fullmatch(word):
        return 'an interpreter or a command runner reads a here-string that runs cargo or cross'
    return None


def commands(text, source='run block'):
    """Extract the cargo and cross calls of shell text.

    Quoted words, comments and heredoc bodies are data. A command
    substitution, $( ) or a backtick pair, opens a new shell context even
    inside a double-quoted word. A call starts a command: at the start of
    a line, or after a blank, a slash, a parenthesis, ;, &, | or a
    backtick. A heredoc's delimiter is a HEREDOC word, and its body ends
    at the first physical line that equals the delimiter as it stands;
    any other text after << raises ValueError, and so does a body line of
    an unquoted heredoc that ends in a backslash, which the shell joins
    with the next line. Syntax the scanner does not model also raises
    ValueError naming the source, the line and the construct when its
    text runs cargo or cross: a shell's -c script, eval, a heredoc that an
    interpreter executes, a substitution inside an unquoted heredoc, and a
    here-string that here_string_reader refuses for the command word of
    its segment or of a command that a pipe outside quotes after it feeds.
    A segment starts after ;, &, | or (. A substitution keeps its own
    segment and pipeline, and the outer ones resume after it.
    """
    pending, body = [], None
    for number, line in numbered_lines(text, lambda: body is not None):
        if body is not None:
            if line == body['delimiter']:
                check_heredoc(body, source)
                body = pending.pop(0) if pending else None
            elif not body['quoted'] and line.endswith('\\'):
                raise ValueError(f'{source}:{number}: a heredoc body line the scanner '
                                 f'cannot place: {line}')
            else:
                body['lines'].append(line)
            continue
        # Each substitution context keeps its quote, segment, pipeline state
        # and depth of plain parentheses; only a ) at depth zero ends $( ).
        quote, stack, segment, fed, depth = None, [], 0, False, 0
        i = 0
        while i < len(line):
            char = line[i]
            if char == "\\" and quote != "'":
                i += 2
                continue
            if line[i:i + 2] == '$(' and quote != "'":
                stack.append((quote, segment, fed, depth, ')'))
                quote, segment, fed, depth = None, i + 2, False, 0
                i += 2
                continue
            if char == '`' and quote != "'":
                if stack and stack[-1][4] == '`':
                    quote, segment, fed, depth, _ = stack.pop()
                else:
                    stack.append((quote, segment, fed, depth, '`'))
                    quote, segment, fed, depth = None, i + 1, False, 0
                i += 1
                continue
            if char == ')' and quote is None and depth:
                depth -= 1
            elif char == ')' and quote is None and stack and stack[-1][4] == ')':
                quote, segment, fed, depth, _ = stack.pop()
            elif char in ("'", '"'):
                quote = None if quote == char else char if quote is None else quote
            elif quote is None:
                if char == '#' and (i == 0 or line[i - 1] in BLANKS):
                    break
                if char in ';&|(':
                    # A pipe hands a here-string's text to the next command;
                    # ||, ;, & and ( end that pipeline.
                    pipe = char == '|' and '|' not in (line[i - 1:i], line[i + 1:i + 2])
                    if pipe and fed:
                        reader = COMMAND_WORD.match(line, i + 2 if line[i + 1:i + 2] == '&' else i + 1)[1]
                        problem = here_string_reader(reader, False)
                        if problem:
                            raise ValueError(f'{source}:{number}: {problem}: {line}')
                    elif not pipe and line[i - 1:i + 1] != '|&':
                        fed = False
                    depth += char == '('
                    segment = i + 1
                if line.startswith('<<<', i):
                    if CARGO_WORD.search(line, i):
                        problem = here_string_reader(COMMAND_WORD.match(line, segment, i)[1], True)
                        if problem:
                            raise ValueError(f'{source}:{number}: {problem}: {line}')
                        fed = True
                    i += 3
                    continue
                if line.startswith('<<', i):
                    heredoc = HEREDOC.match(line, i)
                    if heredoc is None:
                        raise ValueError(f'{source}:{number}: a heredoc the scanner does not '
                                         f'model: {line}')
                    pending.append({
                        'delimiter': next(group for group in heredoc.groups() if group),
                        'quoted': heredoc[1] is None, 'lines': [], 'number': number,
                        'interpreter': bool(INTERPRETER.search(line)), 'line': line})
                    i = heredoc.end()
                    continue
                start = i == 0 or line[i - 1] in ' \t/(;&|`'
                data = start and re.match(r'[ \t]*(echo|printf)\b', line[segment:i])
                if start and not data and SHELL_STRING.match(line, i) and CARGO_WORD.search(line, i):
                    raise ValueError(f'{source}:{number}: a shell string or eval runs '
                                     f'cargo or cross: {line}')
                match = re.match(r'(cargo|cross)[ \t]+', line[i:]) if start else None
                if match and not data:
                    end, argument_quote = i + match.end(), None
                    while end < len(line):
                        c = line[end]
                        if c == "\\":
                            end += 2
                            continue
                        if c in ("'", '"'):
                            argument_quote = None if argument_quote == c else c if argument_quote is None else argument_quote
                        elif argument_quote is None and (c in ';&|)>`' or c == '#' and line[end - 1] in BLANKS):
                            break
                        end += 1
                    call = line[i:end].strip(BLANKS)
                    # Digits joined to > name a file descriptor, not an
                    # argument.
                    if end < len(line) and line[end] == '>' and line[end - 1].isdigit():
                        call = re.sub(r'[ \t]+\d+$', '', call)
                    yield call
                    i = end
                    continue
            i += 1
        if pending:
            body = pending.pop(0)
    if body is not None:
        check_heredoc(body, source)


def workflow_inputs(root):
    import yaml
    workflows, scripts = {}, {}
    directory = root / '.github/workflows'
    for path in sorted([*directory.glob('*.yml'), *directory.glob('*.yaml')]):
        document = yaml.safe_load(path.read_text())
        workflows[path.name] = document
        for job in (document.get('jobs') or {}).values():
            for step in job.get('steps', []):
                for reference in SCRIPT_REF.findall(run_text(step)):
                    scripts[reference] = None
    # Include transitive script references and local composite actions.
    actions = root / '.github/actions'
    for path in sorted([*actions.rglob('action.yml'), *actions.rglob('action.yaml')]):
        workflows[str(path.relative_to(root))] = yaml.safe_load(path.read_text())
        for reference in SCRIPT_REF.findall(path.read_text()):
            scripts[reference] = None
        for script in path.parent.rglob('*.sh'):
            scripts[str(script.relative_to(root))] = None
    pending = list(scripts)
    while pending:
        reference = pending.pop()
        path = root / reference
        if not path.is_file():
            raise ValueError(f'missing named script {reference}')
        source = path.read_text()
        scripts[reference] = source
        if reference in DATA_SCRIPTS or path.suffix == '.py':
            continue
        for child in SCRIPT_REF.findall('\n'.join(logical_lines(source))):
            if child not in scripts:
                scripts[child] = None
                pending.append(child)
    return workflows, scripts


def script_commands(path, source):
    """Yield a script's cargo calls; in Python, only literal subprocess
    calls count, never command examples or fixtures."""
    if path.suffix != '.py':
        yield from commands(source, path.as_posix())
        return
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or not node.args:
            continue
        if node.func.attr not in ('run', 'Popen', 'check_call', 'check_output', 'system', 'popen', 'execvp', 'execvpe'):
            continue
        argument = node.args[0]
        try:
            value = ast.literal_eval(argument)
        except (ValueError, TypeError):
            if isinstance(argument, (ast.List, ast.Tuple)) and argument.elts and isinstance(argument.elts[0], ast.Constant):
                if argument.elts[0].value in ('cargo', 'cross'):
                    raise ValueError('unresolved Python cargo argument') from None
            continue
        if isinstance(value, (list, tuple)) and value and value[0] in ('cargo', 'cross'):
            if not all(isinstance(word, str) for word in value):
                raise ValueError('non-string Python cargo argument')
            yield shlex.join(value)
        elif isinstance(value, str):
            yield from commands(value, path.as_posix())


def step_scripts(text, scripts):
    """Yield (path, source) of each non-data script a run block names,
    transitively, in the order the inventory reads them."""
    pending = list(dict.fromkeys(SCRIPT_REF.findall(text)))
    seen = set()
    while pending:
        reference = pending.pop(0)
        if reference in seen:
            continue
        seen.add(reference)
        if reference in DATA_SCRIPTS:
            continue
        path = pathlib.Path(reference)
        source = scripts[reference]
        yield path, source
        if path.suffix != '.py':
            pending.extend(SCRIPT_REF.findall('\n'.join(logical_lines(source))))


def inventory(root, workflows, scripts):
    rows = []
    def add(workflow, job, step, source, command, env):
        words = shlex.split(command)
        family = words[1] if len(words) > 1 else ''
        # Packaged and installed sources are checked by their binary markers.
        resolving = family in FAMILIES
        variants = [env]
        if '$feature' in command and source == 'ci.yml':
            loop = re.search(r'for[ \t]+feature[ \t]+in[ \t]+([^;\n]+);[ \t]*do', env['_run'])
            if loop is None or '$' in loop[1]:
                raise ValueError('feature loop must have a literal feature list')
            variants = [{**env, 'feature': f} for f in shlex.split(loop[1])]
        if source.endswith('/release/build.sh'):
            targets = env.get('_targets') or ['x86_64-unknown-linux-gnu']
            variants = [{**env, 'TARGET': t} for t in targets
                        if (words[0] == 'cross') == (t == 'aarch64-unknown-linux-gnu')]
        if source.endswith('run-testnet-acceptance.sh'):
            suites = re.search(r'^SUITES=\((.*?)^\)', scripts[source], re.M | re.S)
            if not suites:
                raise ValueError('SUITES literal is missing')
            variants = []
            for suite in shlex.split(suites[1], comments=True):
                # The script splits an entry on IFS: space, tab and line feed.
                fields = [field for field in re.split(r'[ \t\n]+', suite) if field]
                if len(fields) != 3:
                    raise ValueError('invalid SUITES entry')
                variants.append({**env, **dict(zip(('crate', 'feature', 'target'), fields))})
        for values in variants:
            expanded = expand(command, values) if resolving else command
            translated = translate(expanded) if resolving else None
            active = translated and FEATURE in ','.join(translated['features']).replace('/', ',').split(',')
            rows.append({'workflow': workflow, 'job': job, 'step': step, 'source': source,
                         'command': expanded, 'relied_on': ('on' if active else 'off') if resolving else 'not relied on',
                         **(translated or {'selection': [], 'features': [], 'edges': None, 'target': None})})
    for workflow, document in workflows.items():
        jobs = document.get('jobs') or {'composite': {'steps': document.get('runs', {}).get('steps', [])}}
        for job_name, job in jobs.items():
            env = {**document.get('env', {}), **job.get('env', {})}
            targets = [r['target'] for r in job.get('strategy', {}).get('matrix', {}).get('include', []) if 'target' in r]
            for step in job.get('steps', []):
                values = {**env, **step.get('env', {}), '_targets': targets,
                          '_run': run_text(step)}
                name = step.get('name', step.get('uses', 'unnamed'))
                text = run_text(step)
                for command in commands(text, f'{workflow}:{job_name}:{name}'):
                    add(workflow, job_name, name, workflow, command, values)
                for path, source in step_scripts(text, scripts):
                    for command in script_commands(path, source):
                        add(workflow, job_name, name, path.as_posix(), command, values)
    return sorted(rows, key=lambda row: json.dumps(row, sort_keys=True))


def activates(command, env):
    """Whether a cargo or cross call enables mainnet-write.

    The variables env defines are expanded first. An activation is a
    --features or -F value that names the feature, for any package.
    """
    def value(match):
        key = (match[1] or match[2] or match[3]).strip()
        key = key[4:] if key.startswith('env.') else key
        return str(env.get(key, match[0]))
    text = re.sub(r'\$\{\{\s*([^}]*?)\s*\}\}|\$\{(\w+)\}|\$([A-Za-z_]\w*)', value, command)
    words = shlex.split(text)
    lists, i = [], 2
    while i < len(words) and words[i] != '--':
        word = words[i]
        if word in ('--features', '-F') and i + 1 < len(words):
            lists.append(words[i + 1])
            i += 1
        elif word.startswith('--features='):
            lists.append(word.partition('=')[2])
        elif word.startswith('-F') and len(word) > 2:
            lists.append(word[2:])
        i += 1
    items = {item.rsplit('/', 1)[-1] for listed in lists for item in re.split(r'[\s,]+', listed)}
    return FEATURE in items


def rust_code(text):
    """Lex Rust source into code and string literals.

    Returns the source with every comment blanked, line breaks kept, and
    the string literals as (start, end, value) with their escapes decoded.
    Character literals stay code, so a quote inside one opens no string.
    """
    out, strings, position = [], [], 0
    while (match := RUST_TOKEN.search(text, position)) is not None:
        out.append(text[position:match.start()])
        if match['line'] is not None:
            end = text.find('\n', match.start())
            end = len(text) if end < 0 else end
            out.append(' ' * (end - match.start()))
        elif match['block'] is not None:
            depth, end = 1, match.end()
            while depth and (edge := RUST_BLOCK_EDGE.search(text, end)) is not None:
                depth += 1 if edge[0] == '/*' else -1
                end = edge.end()
            if depth:
                raise ValueError('unterminated block comment')
            out.append(re.sub(r'[^\n]', ' ', text[match.start():end]))
        elif match['raw'] is not None:
            closing = '"' + match['hashes']
            end = text.find(closing, match.end())
            if end < 0:
                raise ValueError('unterminated raw string')
            end += len(closing)
            strings.append((match.start(), end, text[match.end():end - len(closing)]))
            out.append(text[match.start():end])
        elif match['string'] is not None:
            body = RUST_STRING_BODY.match(text, match.end())
            if body is None:
                raise ValueError('unterminated string')
            end = body.end()
            strings.append((match.start(), end, rust_unescape(body[0][:-1])))
            out.append(text[match.start():end])
        else:
            end = match.end()
            out.append(match[0])
        position = end
    out.append(text[position:])
    return ''.join(out), strings


def rust_unescape(body):
    def value(match):
        if match[1] or match[2]:
            return chr(int(match[1] or match[2], 16))
        if match[3] is None:
            return ''
        return {'n': '\n', 'r': '\r', 't': '\t', '0': '\0'}.get(match[3], match[3])
    return RUST_ESCAPE.sub(value, body)


def directive_problems(value):
    """Yield why lines of a println! format literal escape D4.

    A line with a placeholder is safe when its literal head is no prefix
    of a directive, or names a literal key other than rustc-cfg. A literal
    rustc-cfg line must not set a feature.
    """
    for line in value.split('\n'):
        plain = line.replace('{{', '\0').replace('}}', '\0')
        cut = plain.find('{')
        head = plain if cut < 0 else plain[:cut]
        directive = DIRECTIVE.match(head)
        if directive is None:
            if cut >= 0 and (head.startswith('cargo:') or 'cargo:'.startswith(head)):
                yield 'formatted directive without a literal key'
        elif directive[1] == 'rustc-cfg':
            if cut >= 0:
                yield 'formatted rustc-cfg directive'
            elif re.match(r'\s*feature\b', head[directive.end():]):
                yield 'rustc-cfg sets a feature'


def format_arguments(code, bare, strings, start):
    """Return (statement end, arguments) of the println! call whose format
    literal starts at start: each argument as (name or None, literal value
    or None for an expression the check cannot read)."""
    ends = {s: (e, value) for s, e, value in strings}
    position, depth, pieces, piece = ends[start][0], 0, [], None
    while position < len(bare):
        char = bare[position]
        if char in '([{':
            depth += 1
        elif char in ')]}':
            if depth == 0:
                break
            depth -= 1
        elif char == ',' and depth == 0:
            if piece is not None:
                pieces.append((piece, position))
            piece = position + 1
        position += 1
    if piece is not None:
        pieces.append((piece, position))
    arguments = []
    for first, last in pieces:
        segment = code[first:last]
        if not segment.strip():
            continue
        named = NAMED_ARGUMENT.match(segment)
        offset = first + (named.end() if named else len(segment) - len(segment.lstrip()))
        literal = ends.get(offset)
        plain = literal is not None and not code[literal[0]:last].strip()
        arguments.append((named[1] if named else None, literal[1] if plain else None))
    return position, arguments


def cfg_emissions(text, reviewed=frozenset()):
    """Yield (line number, problem, line) for each refused build output.

    Standard output reaches cargo only through println! with a literal
    format; print! and output handles fail closed, and so does a rustc-cfg
    literal that is no println! format. A formatted line is accepted only
    when each placeholder is {} or {name}, without an index or a format
    specification, and either each argument is a plain string literal free
    of DIRECTIVE_TOKENS and each named placeholder names such an argument,
    or its statement is one of reviewed.
    """
    code, strings = rust_code(text)
    bare = list(code)
    for start, end, _ in strings:
        bare[start:end] = ' ' * (end - start)
    bare = ''.join(bare)
    lines = text.splitlines()
    def where(position):
        number = text.count('\n', 0, position) + 1
        return number, lines[number - 1].strip()
    formats = set()
    for match in re.finditer(r'(?<![\w])(?:print\s*!|stdout(?![\w]))', bare):
        number, line = where(match.start())
        yield number, 'unsupported standard output', line
    starts = {start: value for start, _, value in strings}
    for match in re.finditer(r'(?<![\w])println\s*!\s*\(', bare):
        number, line = where(match.start())
        start = match.end()
        while start < len(code) and code[start].isspace():
            start += 1
        if code[start:start + 1] == ')':
            continue
        if start not in starts:
            yield number, 'println! format is not a string literal', line
            continue
        formats.add(start)
        for problem in directive_problems(starts[start]):
            yield number, problem, line
        end, arguments = format_arguments(code, bare, strings, start)
        names = {name for name, value in arguments if name and value is not None}
        fields = PLACEHOLDER.findall(starts[start].replace('{{', '').replace('}}', ''))
        captured = [field for field in fields if field and field not in names]
        statement = ' '.join(code[match.start():end + 1].split())
        if any(field and not PLACEHOLDER_NAME.fullmatch(field) for field in fields):
            yield number, 'formatted output with a format specification', line
        elif (captured or any(value is None for _, value in arguments)) and statement not in reviewed:
            yield number, 'formatted output with a non-literal argument', line
        elif any(token in value for _, value in arguments if value for token in DIRECTIVE_TOKENS):
            yield number, 'formatted output argument can start a directive', line
    for start, _, value in strings:
        if 'rustc-cfg' in value and start not in formats:
            number, line = where(start)
            yield number, 'rustc-cfg outside a println! format', line


class Checker:
    def __init__(self, root):
        self.root = root
        self.errors = []
        self.metadata = json.loads(run_cargo(root, ['metadata', '--format-version', '1', '--locked', '--offline', '--no-deps']))
        self.packages = {p['name']: p for p in self.metadata['packages']}

    def fail(self, rule, message):
        self.errors.append(f'{rule}: {message}')

    def reaches(self, package, feature, seen=None):
        seen = set() if seen is None else seen
        key = (package, feature)
        if key in seen:
            return False
        seen.add(key)
        if feature == FEATURE:
            return True
        data = self.packages.get(package)
        if not data:
            return False
        for edge in data['features'].get(feature, []):
            if '/' in edge:
                dependency, child = edge.split('/', 1)
                dependency = dependency.rstrip('?')
                for dep in data['dependencies']:
                    if (dep.get('rename') or dep['name']) == dependency and self.reaches(dep['name'], child, seen):
                        return True
            elif edge.startswith('dep:'):
                for dep in data['dependencies']:
                    if (dep.get('rename') or dep['name']) == edge[4:] and self.dependency_reaches(dep, seen):
                        return True
            elif self.reaches(package, edge, seen):
                return True
        return False

    def dependency_reaches(self, dependency, seen=None):
        features = list(dependency['features'])
        if dependency['uses_default_features']:
            features.append('default')
        return any(self.reaches(dependency['name'], feature, seen) for feature in features)

    def D1(self):
        """The four declarations hold; nothing else reaches the feature."""
        for package, expected in DECLARATIONS.items():
            if self.packages.get(package, {}).get('features', {}).get(FEATURE) != expected:
                self.fail('D1', f'{package}: declaration differs')
        for name, package in self.packages.items():
            for feature in package['features']:
                if feature == FEATURE and name in DECLARATIONS:
                    continue
                if self.reaches(name, feature):
                    self.fail('D1', f'{name}/{feature} reaches {FEATURE}')
            for dependency in package['dependencies']:
                if dependency['kind'] is None and self.dependency_reaches(dependency):
                    self.fail('D1', f'{name}: normal dependency {dependency["name"]} enables {FEATURE}')

    def D2(self):
        """No dev or build dependency declaration reaches the feature."""
        for name, package in self.packages.items():
            for dependency in package['dependencies']:
                if dependency['kind'] in ('dev', 'build') and self.dependency_reaches(dependency):
                    self.fail('D2', f'{name}: {dependency["kind"]} dependency enables {FEATURE}')

    def D3(self):
        """The inventory matches; resolved graphs hold the relied-on state."""
        for name in PACKAGES:
            if name not in self.packages:
                self.fail('D3', f'queried package missing from metadata: {name}')
                return
        actual = inventory(self.root, self.workflows, self.scripts)
        # The records form a multiset: their order carries no meaning.
        expected = Counter(json.dumps(r, sort_keys=True) for r in INVOCATIONS)
        found = Counter(json.dumps(r, sort_keys=True) for r in actual)
        if found != expected:
            for row in sorted((found - expected).elements()):
                self.fail('D3', 'unlisted or changed invocation: ' + row)
            for row in sorted((expected - found).elements()):
                self.fail('D3', 'listed invocation vanished: ' + row)
            return
        queries = {}
        for row in actual:
            if row['relied_on'] == 'not relied on':
                continue
            query = {key: row[key] for key in ('selection', 'features', 'edges')}
            key = json.dumps(query, sort_keys=True)
            if key not in queries:
                queries[key] = graph_state(self.root, query)
                absent = [name for name, states in queries[key].items() if not states]
                if absent:
                    print(f'D3: absent (off): {", ".join(absent)}; {row["command"]}')
            states = queries[key]
            if row['relied_on'] == 'off' and any(any(v) for v in states.values()):
                self.fail('D3', f'{row["command"]}: resolved {FEATURE}')
            if row['relied_on'] == 'on':
                # The network-only forwarding tripwire selects only core
                # and network.
                wanted = PACKAGES[:2] if row['selection'] == ['-p', PACKAGES[1]] else PACKAGES
                if not all(states[name] and all(states[name]) for name in wanted):
                    self.fail('D3', f'{row["command"]}: positive control lacks feature on {wanted}')
                else:
                    print(f'D3: positive control on: {", ".join(wanted)}')
        print(f'D3: {len(queries)} distinct offline queries; absent packages recorded as off')

    def D4(self):
        """No custom-build source emits a feature cfg or an opaque line."""
        for package in self.packages.values():
            for target in package['targets']:
                if 'custom-build' in target['kind']:
                    path = pathlib.Path(target['src_path'])
                    try:
                        relative = path.resolve().relative_to(pathlib.Path(self.root).resolve()).as_posix()
                    except ValueError:
                        relative = None
                    reviewed = REVIEWED_EMISSIONS.get(relative, frozenset())
                    for number, problem, line in cfg_emissions(path.read_text(), reviewed):
                        self.fail('D4', f'{package["name"]}: {path.name}:{number}: {problem}: {line}')

    def D5(self):
        """The tree holds no cargo configuration file."""
        for path in config_paths(self.root):
            self.fail('D5', f'cargo config: {path.relative_to(self.root)}')

    def D6(self):
        """Cross.toml holds the pinned image and the pre-build commands."""
        cross = tomllib.loads((self.root / 'Cross.toml').read_text())
        targets = cross.get('target') if isinstance(cross.get('target'), dict) else {}
        entry = targets.get('aarch64-unknown-linux-gnu')
        entry = entry if isinstance(entry, dict) else {}
        if set(cross) != {'target'} or set(targets) != {'aarch64-unknown-linux-gnu'} \
                or set(entry) != {'image', 'pre-build'}:
            self.fail('D6', 'Cross.toml holds keys outside the image and pre-build allowlist')
        if not re.fullmatch(CROSS_IMAGE, str(entry.get('image'))):
            self.fail('D6', 'Cross.toml image is not a cross-rs aarch64 image pinned by digest')
        if entry.get('pre-build') != CROSS_PRE_BUILD:
            self.fail('D6', 'Cross.toml pre-build commands differ from the allowlist')

    def D7(self):
        """No workflow, action or named script sets a refused variable."""
        def walk(where, value):
            if isinstance(value, dict):
                for name, content in value.items():
                    if name == 'env' and isinstance(content, dict):
                        for variable, entry in content.items():
                            if refused_value(variable, entry):
                                self.fail('D7', f'{where}: refused env mapping {variable}')
                    walk(where, content)
            elif isinstance(value, list):
                for entry in value:
                    walk(where, entry)
            elif isinstance(value, str):
                self.refused_shell(where, value)
        for name, document in self.workflows.items():
            walk(name, document)
        for path, text in self.scripts.items():
            if path not in EXEMPT:
                if pathlib.Path(path).suffix == '.py':
                    self.refused_python(path, text)
                else:
                    self.refused_shell(path, text)

    def refused_shell(self, where, text):
        for number, line in numbered_lines(text):
            names = {match[1] for match in SHELL_ASSIGNMENT.finditer(line)}
            names |= {match[1] for match in POWERSHELL_ASSIGNMENT.finditer(line)}
            for name in sorted(names):
                if refused_value(name, line):
                    self.fail('D7', f'{where}:{number}: refused assignment {name}')
        # A text that names the environment file is read one physical line
        # at a time. A line other than a comment must hold an even number of
        # double quotes and of single quotes, so that no quote carries it
        # into the next line, and a line that names the file must not follow
        # a line that ends in a backslash or a backtick, which joins the two.
        # Only when every line passes is each line that names the file,
        # comments included, read against the shapes.
        if not re.search(r'GITHUB_ENV', text, re.I):
            return
        lines = text.split('\n')
        unplaced = [(number, line) for number, line in enumerate(lines, 1)
                    if (not line.lstrip(BLANKS).startswith('#')
                        and (line.count('"') % 2 or line.count("'") % 2))
                    or (number > 1 and lines[number - 2].endswith(('\\', '`'))
                        and re.search(r'GITHUB_ENV', line, re.I))]
        for number, line in unplaced:
            self.fail('D7', f'{where}:{number}: a line the scanner cannot place in a text '
                            f'that names the environment file: {line.strip(BLANKS)}')
        for number, line in [] if unplaced else enumerate(lines, 1):
            problem = env_file_problem(line)
            if problem:
                self.fail('D7', f'{where}:{number}: {problem}: {line.strip(BLANKS)}')

    def refused_python(self, path, text):
        if path not in ENV_FILE_READERS:
            for number, line in enumerate(text.split('\n'), 1):
                if re.search(r'GITHUB_ENV', line, re.I):
                    self.fail('D7', f'{path}:{number}: environment-file line in a Python '
                                    f'script: {line.strip(BLANKS)}')
        def names(node):
            """Yield (name node, value node) pairs an environment receives."""
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Subscript) and environ(target.value):
                        yield target.slice, node.value
            elif isinstance(node, ast.Call):
                function = node.func
                if isinstance(function, ast.Attribute) and environ(function.value) \
                        and function.attr in ('setdefault', 'update'):
                    if function.attr == 'setdefault' and node.args:
                        yield node.args[0], node.args[1] if len(node.args) > 1 else None
                    for argument in node.args if function.attr == 'update' else ():
                        yield from mapping(argument)
                    for keyword in node.keywords:
                        yield ast.Constant(keyword.arg), keyword.value
                if isinstance(function, ast.Attribute) and function.attr == 'putenv' and node.args:
                    yield node.args[0], node.args[1] if len(node.args) > 1 else None
                for keyword in node.keywords:
                    if keyword.arg == 'env':
                        yield from mapping(keyword.value)
        def mapping(node):
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if key is not None:
                        yield key, value
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'dict':
                for keyword in node.keywords:
                    if keyword.arg is not None:
                        yield ast.Constant(keyword.arg), keyword.value
        def environ(node):
            return isinstance(node, ast.Attribute) and node.attr == 'environ'
        for node in ast.walk(ast.parse(text)):
            for key, value in names(node):
                if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
                    self.fail('D7', f'{path}:{node.lineno}: environment name is not a literal')
                    continue
                literal = value.value if isinstance(value, ast.Constant) else ''
                if refused_value(key.value, literal):
                    self.fail('D7', f'{path}:{node.lineno}: refused Python environment {key.value}')

    def D8(self):
        """No workflow, named script or building.md enables every feature."""
        for name, text in self.texts():
            if ALL_FEATURES in text:
                self.fail('D8', f'{name}: forbidden feature umbrella')

    def texts(self):
        for name, document in self.workflows.items():
            jobs = document.get('jobs') or {'composite': {'steps': document.get('runs', {}).get('steps', [])}}
            for job in jobs.values():
                for step in job.get('steps', []):
                    yield name, '\n'.join(logical_lines(run_text(step)))
        for path, text in self.scripts.items():
            if path not in EXEMPT:
                yield path, text
        yield 'building.md', (self.root / 'docs/maintainers/building.md').read_text()

    def D9(self):
        """Only the CI feature-on jobs and the coverage job activate it."""
        for workflow, document in self.workflows.items():
            top = document.get('env', {})
            jobs = document.get('jobs') or {'composite': {'steps': document.get('runs', {}).get('steps', [])}}
            for job_name, job in jobs.items():
                allowed = workflow == 'ci.yml' and job_name in ('feature-on-clippy', 'feature-on-test', 'feature-on-doc')
                allowed = allowed or workflow == 'coverage.yml' and job_name == 'coverage'
                if allowed:
                    continue
                where = f'{workflow}:{job_name}'
                for step in job.get('steps', []):
                    env = {**top, **job.get('env', {}), **step.get('env', {})}
                    text = run_text(step)
                    calls = list(commands(text, where))
                    for path, source in step_scripts(text, self.scripts):
                        calls.extend(script_commands(path, source))
                    for command in calls:
                        if activates(command, env):
                            self.fail('D9', f'{where}: feature activation outside allowed jobs: {command}')
        for path, text in self.scripts.items():
            if path in DATA_SCRIPTS:
                continue
            for command in script_commands(pathlib.Path(path), text):
                if activates(command, {}):
                    self.fail('D9', f'{path}: feature activation: {command}')

    def D10(self):
        """CI and documented feature lists equal the declared features."""
        expected = set().union(*(p['features'] for p in self.packages.values())) - {'default', FEATURE}
        actual = self.workflows['ci.yml'].get('env', {}).get('FEATURES_EXCEPT_MAINNET_WRITE', '')
        if set(actual.split(',')) != expected:
            self.fail('D10', 'CI feature set differs from metadata')
        docs = (self.root / 'docs/maintainers/building.md').read_text()
        match = re.search(r'^FEATURES_EXCEPT_MAINNET_WRITE=["\']?([\w,-]+)', docs, re.M)
        if not match or set(match[1].split(',')) != expected:
            self.fail('D10', 'documented feature set differs from metadata')

    def D11(self):
        """Release, publish and rehearsal expect the marker off."""
        for workflow in ('release.yml', 'publish.yml', 'release-rehearsal.yml'):
            if self.workflows[workflow].get('env', {}).get('EXPECTED_MAINNET_WRITE') != 'off':
                self.fail('D11', f'{workflow}: expected marker is not off')

    def D12(self):
        """The marker literal appears only in core's two cfg arms."""
        for path in (self.root / 'crates').rglob('*.rs'):
            text = rust_code(path.read_text())[0]
            count = text.count(MARKER)
            expected = 2 if path.relative_to(self.root).as_posix() == 'crates/stellar-agent-core/src/build_info.rs' else 0
            if count != expected:
                self.fail('D12', f'{path.relative_to(self.root)}: {count} marker literals, expected {expected}')

    def run(self):
        self.workflows, self.scripts = workflow_inputs(self.root)
        for number in range(1, 13):
            rule = f'D{number}'
            try:
                getattr(self, rule)()
            except (ValueError, OSError, KeyError, TypeError, SyntaxError) as error:
                self.fail(rule, str(error))
        return self.errors


def env_file_problem(line):
    """Return why a line that names the GitHub environment file escapes D7,
    or None.

    A line names the file when it holds GITHUB_ENV in any case. D7 models
    two whole lines, ENV_FILE_ECHO and ENV_FILE_CONTENT, matched after
    spaces and tabs at both ends and no other character, each writing one
    NAME=VALUE entry whose name D7 then checks. Every other line that
    names the file is refused, valid shell or not: printf, tee,
    Set-Content, multiline entries, echo options, options other than -Path
    and -Value, arrays, further redirects, operators and reads.
    """
    if not re.search(r'GITHUB_ENV', line, re.I):
        return None
    text = line.strip(BLANKS)
    shape = ENV_FILE_ECHO.fullmatch(text) or ENV_FILE_CONTENT.fullmatch(text)
    if shape is None:
        return 'environment-file line outside the modelled forms'
    if refused_value(shape['name'], shape['value']):
        return f'refused environment-file write {shape["name"]}'
    return None


# Reviewed command records. Updating a workflow command requires reviewing its
# package selection, feature flags, edge kinds and expected feature state here.
INVOCATIONS = [
    {'workflow': 'publish.yml', 'job': 'publish', 'step': 'Require the pinned toolchain', 'source': 'publish.yml', 'command': 'cargo -V', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'publish.yml', 'job': 'publish', 'step': 'Require the pinned toolchain', 'source': 'publish.yml', 'command': 'cargo -V', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'release-rehearsal.yml', 'job': 'build', 'step': 'Build binaries', 'source': '.github/scripts/release/build.sh', 'command': 'cargo build --release --locked --target "aarch64-apple-darwin" --bin stellar-agent --bin stellar-agent-mcp', 'relied_on': 'off', 'selection': ['--workspace'], 'features': [], 'edges': 'normal,build', 'target': 'aarch64-apple-darwin'},
    {'workflow': 'release.yml', 'job': 'build', 'step': 'Build binaries', 'source': '.github/scripts/release/build.sh', 'command': 'cargo build --release --locked --target "aarch64-apple-darwin" --bin stellar-agent --bin stellar-agent-mcp', 'relied_on': 'off', 'selection': ['--workspace'], 'features': [], 'edges': 'normal,build', 'target': 'aarch64-apple-darwin'},
    {'workflow': 'release-rehearsal.yml', 'job': 'build', 'step': 'Build binaries', 'source': '.github/scripts/release/build.sh', 'command': 'cargo build --release --locked --target "x86_64-apple-darwin" --bin stellar-agent --bin stellar-agent-mcp', 'relied_on': 'off', 'selection': ['--workspace'], 'features': [], 'edges': 'normal,build', 'target': 'x86_64-apple-darwin'},
    {'workflow': 'release.yml', 'job': 'build', 'step': 'Build binaries', 'source': '.github/scripts/release/build.sh', 'command': 'cargo build --release --locked --target "x86_64-apple-darwin" --bin stellar-agent --bin stellar-agent-mcp', 'relied_on': 'off', 'selection': ['--workspace'], 'features': [], 'edges': 'normal,build', 'target': 'x86_64-apple-darwin'},
    {'workflow': 'release-rehearsal.yml', 'job': 'build', 'step': 'Build binaries', 'source': '.github/scripts/release/build.sh', 'command': 'cargo build --release --locked --target "x86_64-pc-windows-msvc" --bin stellar-agent --bin stellar-agent-mcp', 'relied_on': 'off', 'selection': ['--workspace'], 'features': [], 'edges': 'normal,build', 'target': 'x86_64-pc-windows-msvc'},
    {'workflow': 'release.yml', 'job': 'build', 'step': 'Build binaries', 'source': '.github/scripts/release/build.sh', 'command': 'cargo build --release --locked --target "x86_64-pc-windows-msvc" --bin stellar-agent --bin stellar-agent-mcp', 'relied_on': 'off', 'selection': ['--workspace'], 'features': [], 'edges': 'normal,build', 'target': 'x86_64-pc-windows-msvc'},
    {'workflow': 'release-rehearsal.yml', 'job': 'build', 'step': 'Build binaries', 'source': '.github/scripts/release/build.sh', 'command': 'cargo build --release --locked --target "x86_64-unknown-linux-gnu" --bin stellar-agent --bin stellar-agent-mcp', 'relied_on': 'off', 'selection': ['--workspace'], 'features': [], 'edges': 'normal,build', 'target': 'x86_64-unknown-linux-gnu'},
    {'workflow': 'release.yml', 'job': 'build', 'step': 'Build binaries', 'source': '.github/scripts/release/build.sh', 'command': 'cargo build --release --locked --target "x86_64-unknown-linux-gnu" --bin stellar-agent --bin stellar-agent-mcp', 'relied_on': 'off', 'selection': ['--workspace'], 'features': [], 'edges': 'normal,build', 'target': 'x86_64-unknown-linux-gnu'},
    {'workflow': 'ci.yml', 'job': 'release-shape', 'step': 'Build and check the release binaries', 'source': '.github/scripts/release/build.sh', 'command': 'cargo build --release --locked --target "x86_64-unknown-linux-gnu" --bin stellar-agent --bin stellar-agent-mcp', 'relied_on': 'off', 'selection': ['--workspace'], 'features': [], 'edges': 'normal,build', 'target': 'x86_64-unknown-linux-gnu'},
    {'workflow': 'notarize-smoke.yml', 'job': 'build', 'step': 'Build binaries', 'source': 'notarize-smoke.yml', 'command': 'cargo build --release --locked --target aarch64-apple-darwin --bin stellar-agent --bin stellar-agent-mcp', 'relied_on': 'off', 'selection': ['--workspace'], 'features': [], 'edges': 'normal,build', 'target': 'aarch64-apple-darwin'},
    {'workflow': 'ci.yml', 'job': 'feature-on-test', 'step': 'Check network feature forwarding in isolation', 'source': 'ci.yml', 'command': 'cargo check -p stellar-agent-network --features mainnet-write', 'relied_on': 'on', 'selection': ['-p', 'stellar-agent-network'], 'features': ['--features', 'mainnet-write'], 'edges': 'normal,build', 'target': None},
    {'workflow': 'ci.yml', 'job': 'test', 'step': 'Check each test-support feature set', 'source': 'ci.yml', 'command': 'cargo check -p stellar-agent-test-support --no-default-features --features "test-helpers"', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-test-support'], 'features': ['--no-default-features', '--features', 'test-helpers'], 'edges': 'normal,build', 'target': None},
    {'workflow': 'ci.yml', 'job': 'test', 'step': 'Check each test-support feature set', 'source': 'ci.yml', 'command': 'cargo check -p stellar-agent-test-support --no-default-features --features "testnet-helpers"', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-test-support'], 'features': ['--no-default-features', '--features', 'testnet-helpers'], 'edges': 'normal,build', 'target': None},
    {'workflow': 'ci.yml', 'job': 'test', 'step': 'Check each test-support feature set', 'source': 'ci.yml', 'command': 'cargo check -p stellar-agent-test-support --no-default-features --features "verifier-registry"', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-test-support'], 'features': ['--no-default-features', '--features', 'verifier-registry'], 'edges': 'normal,build', 'target': None},
    {'workflow': 'ci.yml', 'job': 'test', 'step': 'Check each test-support feature set', 'source': 'ci.yml', 'command': 'cargo check -p stellar-agent-test-support --no-default-features --features "wiremock-helpers"', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-test-support'], 'features': ['--no-default-features', '--features', 'wiremock-helpers'], 'edges': 'normal,build', 'target': None},
    {'workflow': 'ci.yml', 'job': 'test', 'step': 'Check each test-support feature set', 'source': 'ci.yml', 'command': 'cargo check -p stellar-agent-test-support --no-default-features', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-test-support'], 'features': ['--no-default-features'], 'edges': 'normal,build', 'target': None},
    {'workflow': 'ci.yml', 'job': 'feature-on-clippy', 'step': 'Run clippy', 'source': 'ci.yml', 'command': 'cargo clippy --workspace --all-targets --features "mainnet-write,test-helpers,test-hooks,test-loopback,testnet-acceptance,testnet-integration,testnet-helpers,verifier-registry,wiremock-helpers,deploy-cli,operator-enroll-browser-acceptance" -- -D warnings', 'relied_on': 'on', 'selection': ['--workspace'], 'features': ['--features', 'mainnet-write,test-helpers,test-hooks,test-loopback,testnet-acceptance,testnet-integration,testnet-helpers,verifier-registry,wiremock-helpers,deploy-cli,operator-enroll-browser-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'ci.yml', 'job': 'clippy', 'step': 'Run clippy', 'source': 'ci.yml', 'command': 'cargo clippy --workspace --all-targets --features "test-helpers,test-hooks,test-loopback,testnet-acceptance,testnet-integration,testnet-helpers,verifier-registry,wiremock-helpers,deploy-cli,operator-enroll-browser-acceptance" -- -D warnings', 'relied_on': 'off', 'selection': ['--workspace'], 'features': ['--features', 'test-helpers,test-hooks,test-loopback,testnet-acceptance,testnet-integration,testnet-helpers,verifier-registry,wiremock-helpers,deploy-cli,operator-enroll-browser-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'ci.yml', 'job': 'deny', 'step': 'Check licenses and advisories', 'source': 'ci.yml', 'command': 'cargo deny check', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'release.yml', 'job': 'preflight', 'step': 'unnamed', 'source': 'release.yml', 'command': 'cargo deny check', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'ci.yml', 'job': 'feature-on-doc', 'step': 'Build the rustdoc', 'source': 'ci.yml', 'command': 'cargo doc --workspace --no-deps --features "mainnet-write,test-helpers,test-hooks,test-loopback,testnet-acceptance,testnet-integration,testnet-helpers,verifier-registry,wiremock-helpers,deploy-cli,operator-enroll-browser-acceptance"', 'relied_on': 'on', 'selection': ['--workspace'], 'features': ['--features', 'mainnet-write,test-helpers,test-hooks,test-loopback,testnet-acceptance,testnet-integration,testnet-helpers,verifier-registry,wiremock-helpers,deploy-cli,operator-enroll-browser-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'ci.yml', 'job': 'doc', 'step': 'Build the rustdoc', 'source': 'ci.yml', 'command': 'cargo doc --workspace --no-deps --features "test-helpers,test-hooks,test-loopback,testnet-acceptance,testnet-integration,testnet-helpers,verifier-registry,wiremock-helpers,deploy-cli,operator-enroll-browser-acceptance"', 'relied_on': 'off', 'selection': ['--workspace'], 'features': ['--features', 'test-helpers,test-hooks,test-loopback,testnet-acceptance,testnet-integration,testnet-helpers,verifier-registry,wiremock-helpers,deploy-cli,operator-enroll-browser-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'ci.yml', 'job': 'feature-discipline', 'step': 'Fetch the locked graph', 'source': 'ci.yml', 'command': 'cargo fetch --locked', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'release.yml', 'job': 'verify-provenance', 'step': 'Fetch the locked graph', 'source': 'release.yml', 'command': 'cargo fetch --locked', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'ci.yml', 'job': 'fmt', 'step': 'Check formatting', 'source': 'ci.yml', 'command': 'cargo fmt --all -- --check', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'vendored-wasm.yml', 'job': 'stellar-cli-25', 'step': 'Build from a git archive of the tag', 'source': 'vendored-wasm.yml', 'command': 'cargo install --locked --path cmd/stellar-cli --root "$RUNNER_TEMP/stellar-cli-25"', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'publish.yml', 'job': 'verify-install', 'step': 'Verify registry installs', 'source': '.github/scripts/release/verify-install.sh', 'command': 'cargo install --locked --version "$V" "$package" --root "$RUNNER_TEMP/verify-install"', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'vendored-wasm.yml', 'job': 'stellar-cli-28', 'step': 'Build the crates.io package', 'source': 'vendored-wasm.yml', 'command': 'cargo install --locked stellar-cli --version "$CLI_VERSION" --root "$RUNNER_TEMP/stellar-cli-28"', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'release-rehearsal.yml', 'job': 'build', 'step': 'Install cross (for aarch64-unknown-linux-gnu)', 'source': 'release-rehearsal.yml', 'command': 'cargo install cross --version 0.2.5 --locked', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'release.yml', 'job': 'build', 'step': 'Install cross (for aarch64-unknown-linux-gnu)', 'source': 'release.yml', 'command': 'cargo install cross --version 0.2.5 --locked', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'coverage.yml', 'job': 'coverage', 'step': 'Measure feature-on offline line coverage', 'source': 'coverage.yml', 'command': 'cargo llvm-cov --workspace --features mainnet-write,test-helpers,test-hooks,test-loopback,verifier-registry --json --output-path cov-feature-on.json', 'relied_on': 'on', 'selection': ['--workspace'], 'features': ['--features', 'mainnet-write,test-helpers,test-hooks,test-loopback,verifier-registry'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'coverage.yml', 'job': 'coverage', 'step': 'Measure offline line coverage', 'source': 'coverage.yml', 'command': 'cargo llvm-cov --workspace --features test-helpers,test-hooks,test-loopback,verifier-registry --json --output-path cov-feature-off.json', 'relied_on': 'off', 'selection': ['--workspace'], 'features': ['--features', 'test-helpers,test-hooks,test-loopback,verifier-registry'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'ci.yml', 'job': 'machete', 'step': 'Check for unused dependencies', 'source': 'ci.yml', 'command': 'cargo machete', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'release-rehearsal.yml', 'job': 'build', 'step': 'Read the workspace version', 'source': 'release-rehearsal.yml', 'command': 'cargo metadata --format-version 1 --no-deps --locked', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'release.yml', 'job': 'preflight', 'step': 'Warn when a workspace member is missing on crates.io', 'source': '.github/scripts/check-crates-exist.sh', 'command': 'cargo metadata --format-version 1 --no-deps --offline --frozen', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'release.yml', 'job': 'preflight', 'step': 'Verify workspace.package.repository invariance', 'source': 'release.yml', 'command': 'cargo metadata --format-version 1 --no-deps --offline --frozen', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'release.yml', 'job': 'preflight', 'step': 'Verify tag matches workspace version', 'source': '.github/scripts/release-preflight-version-check.sh', 'command': 'cargo metadata --format-version 1 --no-deps "${CARGO_FLAGS[@]}"', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'publish.yml', 'job': 'publish', 'step': "Verify every workspace member carries the tag's version", 'source': '.github/scripts/release-preflight-version-check.sh', 'command': 'cargo metadata --format-version 1 --no-deps "${CARGO_FLAGS[@]}"', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'publish.yml', 'job': 'verify', 'step': "Verify every workspace member carries the tag's version", 'source': '.github/scripts/release-preflight-version-check.sh', 'command': 'cargo metadata --format-version 1 --no-deps "${CARGO_FLAGS[@]}"', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'publish.yml', 'job': 'publish', 'step': 'Publish all crates in dependency order', 'source': '.github/scripts/publish-crates.sh', 'command': 'cargo metadata --no-deps --format-version 1', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'ci.yml', 'job': 'release-contracts', 'step': 'Check the publish tiers', 'source': '.github/scripts/publish-crates.sh', 'command': 'cargo metadata --no-deps --format-version 1', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'publish.yml', 'job': 'publish', 'step': 'Regenerate the archives without building', 'source': 'publish.yml', 'command': 'cargo package --workspace --locked --no-verify --target-dir "$RUNNER_TEMP/publish-target"', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'publish.yml', 'job': 'verify', 'step': 'Build and package every crate', 'source': 'publish.yml', 'command': 'cargo package --workspace --locked', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'release-rehearsal.yml', 'job': 'verify-crates', 'step': 'Build and package every crate', 'source': 'release-rehearsal.yml', 'command': 'cargo package --workspace --locked', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'publish.yml', 'job': 'publish', 'step': 'Publish all crates in dependency order', 'source': '.github/scripts/publish-crates.sh', 'command': 'cargo publish -p "$name" --locked --no-verify', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'ci.yml', 'job': 'release-contracts', 'step': 'Check the publish tiers', 'source': '.github/scripts/publish-crates.sh', 'command': 'cargo publish -p "$name" --locked --no-verify', 'relied_on': 'not relied on', 'selection': [], 'features': [], 'edges': None, 'target': None},
    {'workflow': 'ci.yml', 'job': 'feature-on-test', 'step': 'Run the offline tests', 'source': 'ci.yml', 'command': 'cargo test --workspace --features mainnet-write,test-helpers,test-hooks,test-loopback,verifier-registry', 'relied_on': 'on', 'selection': ['--workspace'], 'features': ['--features', 'mainnet-write,test-helpers,test-hooks,test-loopback,verifier-registry'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'ci.yml', 'job': 'test', 'step': 'Run the offline tests', 'source': 'ci.yml', 'command': 'cargo test --workspace --features test-helpers,test-hooks,test-loopback,verifier-registry', 'relied_on': 'off', 'selection': ['--workspace'], 'features': ['--features', 'test-helpers,test-hooks,test-loopback,verifier-registry'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-anchor" --features "testnet-acceptance" --test "anchor_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-anchor'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-approval-remote" --features "operator-enroll-browser-acceptance" --test "operator_enroll_browser_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-approval-remote'], 'features': ['--features', 'operator-enroll-browser-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-approval-remote" --features "testnet-acceptance" --test "remote_approval_browser_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-approval-remote'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-approval-remote" --features "testnet-acceptance" --test "rule_proposal_remote_browser_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-approval-remote'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-cli" --features "testnet-acceptance" --test "cap85_external_ref_cli_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-cli'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-cli" --features "testnet-acceptance" --test "claim_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-cli'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-cli" --features "testnet-acceptance" --test "cli_submit_only_network_binding_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-cli'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-cli" --features "testnet-acceptance" --test "pay_policy_v1_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-cli'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-cli" --features "testnet-acceptance" --test "pay_timeout_reconcile_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-cli'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-cli" --features "testnet-acceptance" --test "profile_init_enroll_signer_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-cli'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-cli" --features "testnet-acceptance" --test "smart_account_execute_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-cli'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-cli" --features "testnet-acceptance" --test "smart_account_multicall_cli_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-cli'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-defindex" --features "testnet-acceptance" --test "defindex_deposit_submit_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-defindex'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-defindex" --features "testnet-acceptance" --test "defindex_vault_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-defindex'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-dex" --features "testnet-acceptance" --test "dex_swap_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-dex'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-mcp" --features "testnet-acceptance" --test "approve_serve_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-mcp'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-mcp" --features "testnet-acceptance" --test "claim_commit_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-mcp'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-mcp" --features "testnet-acceptance" --test "create_account_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-mcp'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-mcp" --features "testnet-acceptance" --test "dex_quote_wire_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-mcp'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-mcp" --features "testnet-acceptance" --test "pay_commit_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-mcp'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-mcp" --features "testnet-acceptance" --test "policy_value_descriptor_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-mcp'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-mcp" --features "testnet-acceptance" --test "rule_create_commit_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-mcp'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-mcp" --features "testnet-acceptance" --test "sep43_sign_and_submit_transaction_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-mcp'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-mcp" --features "testnet-acceptance" --test "toolset_sign_payment_gated_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-mcp'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-mcp" --features "testnet-acceptance" --test "trustline_classic_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-mcp'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-mcp" --features "testnet-acceptance" --test "x402_authenticated_payment_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-mcp'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-mcp" --features "testnet-acceptance" --test "x402_create_payment_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-mcp'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-mpp" --features "testnet-acceptance" --test "sponsored_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-mpp'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-network" --features "testnet-acceptance" --test "fee_bump_idempotent_testnet"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-network'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-network" --features "testnet-acceptance" --test "fee_bump_testnet"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-network'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-pool" --features "testnet-acceptance" --test "load_testnet"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-pool'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-pool" --features "testnet-acceptance" --test "pool_concurrent_testnet"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-pool'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-pool" --features "testnet-acceptance" --test "pool_testnet_init"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-pool'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-sep10" --features "testnet-integration" --test "sep10_replay_adversarial"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-sep10'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-sep10" --features "testnet-integration" --test "sep10_round_trip_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-sep10'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-sep43" --features "testnet-acceptance" --test "sep43_sdk_v17_interop_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-sep43'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-sep48" --features "testnet-acceptance" --test "sep48_preview_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-sep48'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-sep7" --features "testnet-acceptance" --test "sep7_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-sep7'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account-acceptance" --features "testnet-integration" --test "cap85_external_ref_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account-acceptance'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account-acceptance" --features "testnet-integration" --test "smart_account_ergonomics_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account-acceptance'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account-acceptance" --features "testnet-integration" --test "smart_account_policy_observability_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account-acceptance'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account-acceptance" --features "testnet-integration" --test "smart_account_rules_webauthn_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account-acceptance'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account" --features "testnet-integration" --test "deploy_c_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account" --features "testnet-integration" --test "quorum_authorization_info_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account" --features "testnet-integration" --test "smart_account_caps_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account" --features "testnet-integration" --test "smart_account_delegation_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account" --features "testnet-integration" --test "smart_account_list_rules_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account" --features "testnet-integration" --test "smart_account_migrate_verifier_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account" --features "testnet-integration" --test "smart_account_multicall_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account" --features "testnet-integration" --test "smart_account_policy_mutators_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account" --features "testnet-integration" --test "smart_account_rules_pinning_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account" --features "testnet-integration" --test "smart_account_rules_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account" --features "testnet-integration" --test "smart_account_session_rule_expiry_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account" --features "testnet-integration" --test "smart_account_session_rule_horizon_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account" --features "testnet-integration" --test "smart_account_signers_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account" --features "testnet-integration" --test "smart_account_sim_audit_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-smart-account" --features "testnet-integration" --test "smart_account_timelock_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account'], 'features': ['--features', 'testnet-integration'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-stablecoin" --features "testnet-acceptance" --test "trustline_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-stablecoin'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-x402-identity" --features "testnet-acceptance" --test "sep10_gate_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-x402-identity'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'testnet.yml', 'job': 'acceptance', 'step': 'Run testnet acceptance suites', 'source': '.github/scripts/run-testnet-acceptance.sh', 'command': 'cargo test -p "stellar-agent-x402" --features "testnet-acceptance" --test "x402_exact_testnet_acceptance"  -- --include-ignored --test-threads=1 --nocapture', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-x402'], 'features': ['--features', 'testnet-acceptance'], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'ci.yml', 'job': 'windows-storage', 'step': 'Approval + toolset-grant store persist regression (stellar-agent-core)', 'source': 'ci.yml', 'command': 'cargo test -p stellar-agent-core --lib -- approval::store::tests::persist approval::toolset_grant::tests::persist', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-core'], 'features': [], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'ci.yml', 'job': 'windows-storage', 'step': 'Audit-log regression (stellar-agent-core)', 'source': 'ci.yml', 'command': 'cargo test -p stellar-agent-core --lib audit_log::', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-core'], 'features': [], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'ci.yml', 'job': 'windows-storage', 'step': 'Build test binaries (unbounded compile phase)', 'source': 'ci.yml', 'command': 'cargo test -p stellar-agent-core -p stellar-agent-mpp -p stellar-agent-smart-account -p stellar-agent-mcp -p stellar-agent-headless-keyring -p stellar-agent-windows-identity -p stellar-agent-network --lib --no-run', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-core', '-p', 'stellar-agent-mpp', '-p', 'stellar-agent-smart-account', '-p', 'stellar-agent-mcp', '-p', 'stellar-agent-headless-keyring', '-p', 'stellar-agent-windows-identity', '-p', 'stellar-agent-network'], 'features': [], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'ci.yml', 'job': 'windows-storage', 'step': 'Headless keyring and Windows identity suites', 'source': 'ci.yml', 'command': 'cargo test -p stellar-agent-headless-keyring -p stellar-agent-windows-identity --lib', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-headless-keyring', '-p', 'stellar-agent-windows-identity'], 'features': [], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'ci.yml', 'job': 'windows-storage', 'step': 'MCP rule-tool suite (audit path end-to-end)', 'source': 'ci.yml', 'command': 'cargo test -p stellar-agent-mcp --lib -- tools::rules:: tools::rule_create::', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-mcp'], 'features': [], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'ci.yml', 'job': 'windows-storage', 'step': 'MPP authorization-store regression', 'source': 'ci.yml', 'command': 'cargo test -p stellar-agent-mpp --lib store::tests::', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-mpp'], 'features': [], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'ci.yml', 'job': 'windows-storage', 'step': 'DPAPI protect failure regression', 'source': 'ci.yml', 'command': 'cargo test -p stellar-agent-network --lib keyring::tests::dpapi_protect_failure_reaches_wallet_error -- --exact', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-network'], 'features': [], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'ci.yml', 'job': 'windows-storage', 'step': 'Smart-account wire-code suite', 'source': 'ci.yml', 'command': 'cargo test -p stellar-agent-smart-account --lib', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account'], 'features': [], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'ci.yml', 'job': 'test', 'step': 'Test the vendored Wasm release configuration', 'source': 'ci.yml', 'command': 'cargo test -p stellar-agent-smart-account --test vendored_wasm_release_cfg', 'relied_on': 'off', 'selection': ['-p', 'stellar-agent-smart-account'], 'features': [], 'edges': 'normal,build,dev', 'target': None},
    {'workflow': 'release-rehearsal.yml', 'job': 'build', 'step': 'Build binaries', 'source': '.github/scripts/release/build.sh', 'command': 'cross build --release --locked --target "aarch64-unknown-linux-gnu" --bin stellar-agent --bin stellar-agent-mcp', 'relied_on': 'off', 'selection': ['--workspace'], 'features': [], 'edges': 'normal,build', 'target': 'aarch64-unknown-linux-gnu'},
    {'workflow': 'release.yml', 'job': 'build', 'step': 'Build binaries', 'source': '.github/scripts/release/build.sh', 'command': 'cross build --release --locked --target "aarch64-unknown-linux-gnu" --bin stellar-agent --bin stellar-agent-mcp', 'relied_on': 'off', 'selection': ['--workspace'], 'features': [], 'edges': 'normal,build', 'target': 'aarch64-unknown-linux-gnu'},
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', nargs='?', type=pathlib.Path, default=pathlib.Path.cwd(),
                        help='the checkout; with --env-guard, the build directory')
    parser.add_argument('--env-guard', action='store_true')
    args = parser.parse_args()
    try:
        errors = env_guard(args.root.resolve(), os.environ) if args.env_guard else Checker(args.root).run()
    except (ValueError, OSError) as error:
        errors = [str(error)]
    for error in errors:
        print(error, file=sys.stderr)
    if not errors:
        print('feature discipline holds')
    return int(bool(errors))


if __name__ == '__main__':
    sys.exit(main())
