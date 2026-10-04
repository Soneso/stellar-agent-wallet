#!/usr/bin/env python3
"""Self-test for check-install-surface.py.

Usage: test-check-install-surface.py [ROOT]

Copies the files the check reads from ROOT (default: this repository) into a
temporary git work tree. Three trees must pass: the clean copy, the clean copy
plus near-miss text the check must accept, and the clean copy plus tracked
files the check excludes, each holding an unlocked install. Each named case then
injects one violation into a fresh copy and requires the check to exit 1 with a
violation of the expected rule on the expected file. Every injection asserts
that it changed the copy, so a case cannot pass on an unmodified tree.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    print(
        "test-check-install-surface.py needs Python 3.11 or later for tomllib; "
        f"this is Python {sys.version.split()[0]}",
        file=sys.stderr,
    )
    sys.exit(2)

import importlib.util
import pathlib
import shutil
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass
from typing import Callable

HERE = pathlib.Path(__file__).resolve().parent
CHECK = HERE / "check-install-surface.py"
CLI_MANIFEST = "crates/stellar-agent-cli/Cargo.toml"
MCP_MANIFEST = "crates/stellar-agent-mcp/Cargo.toml"


def load_check():
    # Importing the check must not leave a __pycache__ directory in the tree.
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("check_install_surface", CHECK)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def replace(tree: pathlib.Path, relative: str, old: str, new: str) -> None:
    path = tree / relative
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise AssertionError(
            f"injection into {relative} expected one match of {old!r}, found {count}"
        )
    path.write_text(text.replace(old, new), encoding="utf-8")


def append(tree: pathlib.Path, relative: str, addition: str) -> None:
    path = tree / relative
    text = path.read_text(encoding="utf-8")
    path.write_text(text.rstrip("\n") + "\n\n" + addition, encoding="utf-8")


def add_tracked(tree: pathlib.Path, relative: str, text: str) -> None:
    path = tree / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    subprocess.run(["git", "add", "--", relative], cwd=tree, check=True)


def fenced(language: str, body: str) -> str:
    return f"```{language}\n{body}\n```\n"


@dataclass
class Case:
    name: str
    rule: str
    path: str
    mutate: Callable[[pathlib.Path], None]
    line: int | None = None


def run_check(tree: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECK), str(tree)],
        capture_output=True,
        text=True,
        check=False,
    )


PAY_BLOCK_END = '  --memo-text "invoice-42"\nunset WALLET_SK\n'
PAY_BLOCK_END_WITHOUT_UNSET = '  --memo-text "invoice-42"\n'


def unset_in_later_section(tree: pathlib.Path) -> None:
    replace(tree, "docs/getting-started.md", PAY_BLOCK_END, PAY_BLOCK_END_WITHOUT_UNSET)
    append(tree, "docs/getting-started.md", "## Clean up\n\n" + fenced("bash", "unset WALLET_SK"))


def cases(version: str) -> list[Case]:
    unlocked_install = fenced("bash", f"cargo install stellar-agent-cli@{version}")
    full_seed = "S" + "A" * 55

    def locate(relative: str) -> Case:
        return Case(
            f"rule 1: unlocked install in {relative}",
            "1",
            relative,
            lambda tree: append(tree, relative, unlocked_install),
        )

    return [
        Case(
            "rule 1: unlocked install",
            "1",
            "README.md",
            lambda tree: replace(
                tree,
                "README.md",
                "cargo install --locked stellar-agent-cli@",
                "cargo install stellar-agent-cli@",
            ),
        ),
        Case(
            "rule 1: unlocked binstall",
            "1",
            "README.md",
            lambda tree: replace(
                tree,
                "README.md",
                "cargo binstall --locked --disable-strategies",
                "cargo binstall --disable-strategies",
            ),
        ),
        Case(
            "rule 1: binstall without --disable-strategies",
            "1",
            "docs/getting-started.md",
            lambda tree: replace(
                tree,
                "docs/getting-started.md",
                "cargo binstall --locked --disable-strategies quick-install,compile "
                "stellar-agent-cli@",
                "cargo binstall --locked stellar-agent-cli@",
            ),
        ),
        Case(
            "rule 1: binstall with quick-install alone",
            "1",
            "docs/mcp.md",
            lambda tree: replace(
                tree,
                "docs/mcp.md",
                "--disable-strategies quick-install,compile stellar-agent-mcp@",
                "--disable-strategies quick-install stellar-agent-mcp@",
            ),
        ),
        Case(
            "rule 1: --git form",
            "1",
            "docs/onboarding.md",
            lambda tree: append(
                tree,
                "docs/onboarding.md",
                fenced(
                    "bash",
                    f"cargo install --git https://github.com/Soneso/stellar-agent-wallet "
                    f"--tag v{version}",
                ),
            ),
        ),
        Case(
            "rule 1: continued command",
            "1",
            "docs/cli-reference/stellar-ops.md",
            lambda tree: append(
                tree,
                "docs/cli-reference/stellar-ops.md",
                fenced("bash", f"cargo install \\\n  stellar-agent-cli@{version}"),
            ),
        ),
        Case(
            "rule 1: wrapped inline span",
            "1",
            "docs/mcp.md",
            lambda tree: append(
                tree,
                "docs/mcp.md",
                f"Or run `cargo install\nstellar-agent-mcp@{version}` by hand.\n",
            ),
        ),
        Case(
            "rule 1: SKILL.md frontmatter",
            "1",
            "skills/stellar-agent-wallet/SKILL.md",
            lambda tree: replace(
                tree,
                "skills/stellar-agent-wallet/SKILL.md",
                "for example cargo binstall --locked --disable-strategies",
                "for example cargo binstall --disable-strategies",
            ),
            line=5,
        ),
        Case(
            "rule 1: clone block cargo build without --locked",
            "1",
            "README.md",
            lambda tree: replace(
                tree,
                "README.md",
                "cd stellar-agent-wallet\ncargo build --release --locked",
                "cd stellar-agent-wallet\ncargo build --release",
            ),
        ),
        Case(
            "rule 1: trailing comment names the flag",
            "1",
            "docs/onboarding.md",
            lambda tree: append(
                tree,
                "docs/onboarding.md",
                fenced(
                    "bash",
                    f"cargo install stellar-agent-cli@{version}  "
                    "# add --locked for a reproducible build",
                ),
            ),
        ),
        Case(
            "rule 1: unlocked install in a shell comment",
            "1",
            "docs/onboarding.md",
            lambda tree: append(
                tree,
                "docs/onboarding.md",
                fenced("bash", f"# or: cargo install stellar-agent-cli@{version}"),
            ),
        ),
        Case(
            "rule 1: clone named in a comment",
            "1",
            "docs/onboarding.md",
            lambda tree: append(
                tree,
                "docs/onboarding.md",
                fenced(
                    "bash",
                    "# git clone https://github.com/Soneso/stellar-agent-wallet\n"
                    "cargo build --release",
                ),
            ),
        ),
        Case(
            "rule 1: unlocked install after ||",
            "1",
            "docs/onboarding.md",
            lambda tree: append(
                tree,
                "docs/onboarding.md",
                fenced(
                    "bash",
                    "cargo binstall --locked --disable-strategies quick-install,compile "
                    f"stellar-agent-cli@{version} || cargo install stellar-agent-cli@{version}",
                ),
            ),
        ),
        Case(
            "rule 1: unlocked install after ;",
            "1",
            "docs/onboarding.md",
            lambda tree: append(
                tree,
                "docs/onboarding.md",
                fenced(
                    "bash",
                    f"cargo install --locked cargo-deny; cargo install stellar-agent-cli@{version}",
                ),
            ),
        ),
        Case(
            "rule 1: two prose commands on one line",
            "1",
            "docs/mcp.md",
            lambda tree: append(
                tree,
                "docs/mcp.md",
                f"Run cargo install stellar-agent-cli@{version}, or cargo binstall --locked "
                f"--disable-strategies quick-install,compile stellar-agent-cli@{version}.\n",
            ),
        ),
        Case(
            "rule 1: clone URL on a continuation line",
            "1",
            "docs/onboarding.md",
            lambda tree: append(
                tree,
                "docs/onboarding.md",
                fenced(
                    "bash",
                    f"git clone --branch v{version} \\\n"
                    "  https://github.com/Soneso/stellar-agent-wallet\n"
                    "cd stellar-agent-wallet\n"
                    "cargo build --release",
                ),
            ),
        ),
        Case(
            "rule 1: prose install after an inline triple-backtick span",
            "1",
            "docs/mcp.md",
            lambda tree: append(
                tree,
                "docs/mcp.md",
                f"```x``` is inline code; run cargo install stellar-agent-cli@{version} by hand.\n",
            ),
        ),
        locate("README.md"),
        locate("docs/getting-started.md"),
        locate("docs/cli-reference/index.md"),
        locate("skills/stellar-agent-wallet/SKILL.md"),
        locate("skills/stellar-agent-wallet/references/cli-reference.md"),
        locate("skills/README.md"),
        locate("crates/stellar-agent-cli/README.md"),
        Case(
            "rule 2: doc pin differs",
            "2",
            "docs/mcp.md",
            lambda tree: replace(
                tree,
                "docs/mcp.md",
                f"cargo install --locked stellar-agent-mcp@{version}",
                "cargo install --locked stellar-agent-mcp@0.0.1",
            ),
        ),
        Case(
            "rule 2: root version changed only",
            "2",
            "README.md",
            lambda tree: replace(
                tree,
                "Cargo.toml",
                f'[workspace.package]\nversion = "{version}"',
                '[workspace.package]\nversion = "9.9.9"',
            ),
        ),
        Case(
            "rule 2: --branch tag",
            "2",
            "docs/onboarding.md",
            lambda tree: replace(
                tree,
                "docs/onboarding.md",
                f"--branch v{version}",
                "--branch v0.0.1",
            ),
        ),
        Case(
            "rule 2: --branch= tag",
            "2",
            "docs/onboarding.md",
            lambda tree: append(
                tree,
                "docs/onboarding.md",
                fenced(
                    "bash",
                    "git clone --branch=v0.0.1 https://github.com/Soneso/stellar-agent-wallet",
                ),
            ),
        ),
        Case(
            "rule 2: -b tag",
            "2",
            "docs/onboarding.md",
            lambda tree: append(
                tree,
                "docs/onboarding.md",
                fenced(
                    "bash",
                    "git clone -b v0.0.1 https://github.com/Soneso/stellar-agent-wallet",
                ),
            ),
        ),
        Case(
            "rule 2: release URL",
            "2",
            "docs/getting-started.md",
            lambda tree: replace(
                tree,
                "docs/getting-started.md",
                f"releases/download/v{version}/stellar-agent-{version}-",
                "releases/download/v0.0.1/stellar-agent-0.0.1-",
            ),
        ),
        Case(
            "rule 2: release tag",
            "2",
            "docs/getting-started.md",
            lambda tree: replace(
                tree,
                "docs/getting-started.md",
                f"releases/download/v{version}/",
                "releases/download/v0.0.1/",
            ),
        ),
        Case(
            "rule 2: release archive name",
            "2",
            "README.md",
            lambda tree: replace(
                tree,
                "README.md",
                f"/stellar-agent-{version}-aarch64-apple-darwin.tar.xz\n",
                "/stellar-agent-0.0.1-aarch64-apple-darwin.tar.xz\n",
            ),
        ),
        Case(
            "rule 2: archive name in a tar line",
            "2",
            "README.md",
            lambda tree: replace(
                tree,
                "README.md",
                f"tar -xJf stellar-agent-{version}-",
                "tar -xJf stellar-agent-0.0.1-",
            ),
        ),
        Case(
            "rule 2: archive name of another version of the same length",
            "2",
            "README.md",
            lambda tree: replace(
                tree,
                "README.md",
                f"tar -xJf stellar-agent-{version}-",
                f"tar -xJf stellar-agent-{version[:-1]}{'1' if version[-1] == '0' else '0'}-",
            ),
        ),
        Case(
            "rule 2: prerelease archive name at the version",
            "2",
            "docs/onboarding.md",
            lambda tree: append(
                tree,
                "docs/onboarding.md",
                fenced(
                    "bash",
                    f"tar -xJf stellar-agent-{version}-rc.1-aarch64-apple-darwin.tar.xz",
                ),
            ),
        ),
        Case(
            "rule 3: quoted export",
            "3",
            "docs/cli-reference/stellar-ops.md",
            lambda tree: append(
                tree,
                "docs/cli-reference/stellar-ops.md",
                fenced("bash", 'export SPONSOR_SK="S..."'),
            ),
        ),
        Case(
            "rule 3: unquoted export",
            "3",
            "docs/profiles.md",
            lambda tree: append(
                tree,
                "docs/profiles.md",
                fenced("bash", "export WALLET_SK=S...signer-secret..."),
            ),
        ),
        Case(
            "rule 3: full-length seed",
            "3",
            "docs/profiles.md",
            lambda tree: append(
                tree,
                "docs/profiles.md",
                fenced("bash", f"export WALLET_SK={full_seed}"),
            ),
        ),
        Case(
            "rule 3: prefix assignment in a fenced line",
            "3",
            "skills/stellar-agent-wallet/references/smart-accounts.md",
            lambda tree: append(
                tree,
                "skills/stellar-agent-wallet/references/smart-accounts.md",
                fenced(
                    "bash",
                    'WALLET_SK=SABC...WXYZ stellar-agent pay GDEST...WXYZ "1 XLM" '
                    '--source GSRC...WXYZ --secret-env WALLET_SK',
                ),
            ),
        ),
        Case(
            "rule 3: prefix assignment in an inline span",
            "3",
            "docs/agent-delegation.md",
            lambda tree: append(
                tree,
                "docs/agent-delegation.md",
                "Or run `WALLET_SK=S... stellar-agent pay` once.\n",
            ),
        ),
        Case(
            "rule 3: PowerShell assignment",
            "3",
            "docs/getting-started.md",
            lambda tree: append(
                tree,
                "docs/getting-started.md",
                fenced("powershell", "$env:WALLET_SK = 'S...'"),
            ),
        ),
        Case(
            "rule 3: PowerShell assignment with $Env",
            "3",
            "docs/getting-started.md",
            lambda tree: append(
                tree,
                "docs/getting-started.md",
                fenced("powershell", "$Env:WALLET_SK = 'S...'"),
            ),
        ),
        Case(
            "rule 3: placeholder with an ellipsis character",
            "3",
            "docs/profiles.md",
            lambda tree: append(
                tree,
                "docs/profiles.md",
                fenced("bash", "export WALLET_SK=S\u2026"),
            ),
        ),
        Case(
            "rule 3: cmd set",
            "3",
            "docs/getting-started.md",
            lambda tree: append(
                tree,
                "docs/getting-started.md",
                fenced("bat", 'set "WALLET_SK=S..."'),
            ),
        ),
        Case(
            "rule 3b: missing unset",
            "3b",
            "docs/getting-started.md",
            lambda tree: replace(
                tree,
                "docs/getting-started.md",
                PAY_BLOCK_END,
                PAY_BLOCK_END_WITHOUT_UNSET,
            ),
        ),
        Case(
            "rule 3b: unset in a later section",
            "3b",
            "docs/getting-started.md",
            unset_in_later_section,
        ),
        Case(
            "rule 3b: unset sentence in the next section",
            "3b",
            "docs/profiles.md",
            lambda tree: append(
                tree,
                "docs/profiles.md",
                fenced("bash", "read -rs WALLET_SK") + "\n## Clean up\n\nRun `unset WALLET_SK`.\n",
            ),
        ),
        Case(
            "rule 3b: read -sr",
            "3b",
            "docs/profiles.md",
            lambda tree: append(tree, "docs/profiles.md", fenced("bash", "read -sr WALLET_SK")),
        ),
        Case(
            "rule 3b: read -r -s",
            "3b",
            "docs/profiles.md",
            lambda tree: append(tree, "docs/profiles.md", fenced("bash", "read -r -s WALLET_SK")),
        ),
        Case(
            "rule 3b: read with a prefix assignment",
            "3b",
            "docs/profiles.md",
            lambda tree: append(
                tree,
                "docs/profiles.md",
                fenced("bash", "IFS= read -rs WALLET_SK"),
            ),
        ),
        Case(
            "rule 3b: read in a tilde fence",
            "3b",
            "docs/profiles.md",
            lambda tree: append(tree, "docs/profiles.md", "~~~bash\nread -rs WALLET_SK\n~~~\n"),
        ),
        Case(
            "rule 3b: read in a fence opened on a list item",
            "3b",
            "docs/profiles.md",
            lambda tree: append(
                tree,
                "docs/profiles.md",
                "- ```bash\n  read -rs WALLET_SK\n  ```\n",
            ),
        ),
        Case(
            "rule 3b: second read before unset",
            "3b",
            "docs/cli-reference/stellar-ops.md",
            lambda tree: replace(
                tree,
                "docs/cli-reference/stellar-ops.md",
                "  --salt-random\nunset DEPLOYER_SK\n```\n\n"
                "Example: deploy with a registered WebAuthn passkey",
                "  --salt-random\n```\n\nExample: deploy with a registered WebAuthn passkey",
            ),
        ),
        Case(
            "rule 3b: missing unset sentence after a signer-source read",
            "3b",
            "docs/cli-reference/smart-account.md",
            lambda tree: replace(
                tree,
                "docs/cli-reference/smart-account.md",
                "After the last of those examples, run `unset WALLET_SK` "
                "to remove the seed from the shell.",
                "Those examples follow.",
            ),
        ),
        Case(
            "rule 4: changed pkg-url",
            "4",
            CLI_MANIFEST,
            lambda tree: replace(
                tree,
                CLI_MANIFEST,
                'pkg-url = "{ repo }/releases/download/v{ version }/'
                'stellar-agent-{ version }-{ target }.tar.xz"',
                'pkg-url = "https://example.com/{ version }/{ target }.tar.xz"',
            ),
        ),
        Case(
            "rule 4: changed pkg-fmt",
            "4",
            CLI_MANIFEST,
            lambda tree: replace(tree, CLI_MANIFEST, 'pkg-fmt = "txz"', 'pkg-fmt = "tgz"'),
        ),
        Case(
            "rule 4: changed bin-dir",
            "4",
            CLI_MANIFEST,
            lambda tree: replace(
                tree,
                CLI_MANIFEST,
                'bin-dir = "stellar-agent-{ version }-{ target }/{ bin }{ binary-ext }"',
                'bin-dir = "{ bin }{ binary-ext }"',
            ),
        ),
        Case(
            "rule 4: changed override pkg-url",
            "4",
            CLI_MANIFEST,
            lambda tree: replace(
                tree,
                CLI_MANIFEST,
                'pkg-url = "{ repo }/releases/download/v{ version }/'
                'stellar-agent-{ version }-{ target }.zip"',
                'pkg-url = "https://example.com/{ version }/{ target }.zip"',
            ),
        ),
        Case(
            "rule 4: changed override pkg-fmt",
            "4",
            CLI_MANIFEST,
            lambda tree: replace(tree, CLI_MANIFEST, 'pkg-fmt = "zip"', 'pkg-fmt = "bin"'),
        ),
        Case(
            "rule 4: extra override table",
            "4",
            CLI_MANIFEST,
            lambda tree: append(
                tree,
                CLI_MANIFEST,
                "[package.metadata.binstall.overrides.'cfg(target_os = \"linux\")']\n"
                'pkg-url = "https://example.com/{ version }/{ target }.tar.xz"\n',
            ),
        ),
        Case(
            "rule 4: extra key",
            "4",
            CLI_MANIFEST,
            lambda tree: replace(
                tree,
                CLI_MANIFEST,
                'disabled-strategies = ["quick-install", "compile"]\n',
                'disabled-strategies = ["quick-install", "compile"]\n'
                'signing = { algorithm = "minisign", pubkey = "RWQ" }\n',
            ),
        ),
        Case(
            "rule 4: missing disabled-strategies",
            "4",
            CLI_MANIFEST,
            lambda tree: replace(
                tree,
                CLI_MANIFEST,
                'disabled-strategies = ["quick-install", "compile"]\n',
                "",
            ),
        ),
        Case(
            "rule 4: violation in the MCP manifest only",
            "4",
            MCP_MANIFEST,
            lambda tree: replace(tree, MCP_MANIFEST, 'pkg-fmt = "txz"', 'pkg-fmt = "tgz"'),
        ),
        Case(
            "rule 4: crate-level repository",
            "4",
            CLI_MANIFEST,
            lambda tree: replace(
                tree,
                CLI_MANIFEST,
                "repository.workspace = true",
                'repository = "https://github.com/Soneso/stellar-agent-wallet"',
            ),
        ),
        Case(
            "rule 4: changed root repository",
            "4",
            "Cargo.toml",
            lambda tree: replace(
                tree,
                "Cargo.toml",
                'repository = "https://github.com/Soneso/stellar-agent-wallet"',
                'repository = "https://github.com/example/stellar-agent-wallet"',
            ),
        ),
    ]


def near_misses(tree: pathlib.Path) -> None:
    """Text the check must accept, added to the passing tree."""
    version = workspace_version(tree)
    append(
        tree,
        "docs/maintainers/building.md",
        "## Near-miss fixture\n\n"
        "A placeholder pin: "
        "`cargo install --locked stellar-agent-cli@<version> stellar-agent-mcp@<version>`.\n"
        "Run cargo install for each tool the gates use.\n"
        "Run cargo install other-stellar-agent-cli@0.0.1 for an unrelated tool.\n"
        f"The current release is stellar-agent-cli@{version}.\n"
        f"Its provenance file is stellar-agent-{version}.intoto.jsonl, "
        f"in the stellar-agent-{version} release.\n"
        f"The Linux archive is stellar-agent-{version}-x86_64-unknown-linux-gnu.tar.xz, "
        f"named after the template stellar-agent-{version}-<target>.tar.xz.\n"
        f"Run `cargo install stellar-agent-cli@{version}\n--locked` by hand.\n"
        "Run cargo binstall --locked --disable-strategies `quick-install,compile` "
        f"stellar-agent-cli@{version}.\n\n"
        + fenced(
            "bash",
            "cargo install --locked cargo-deny\n"
            "export STELLAR_AGENT_KEYRING_BACKEND=headless-env\n"
            "export STAGE=STAGING\n"
            "cargo install stellar-agent-mcp-macros@0.0.1\n"
            "cargo binstall --locked --disable-strategies quick-install "
            f"--disable-strategies=compile stellar-agent-cli@{version}\n"
            'cargo binstall --locked --disable-strategies "quick-install,compile" '
            f"stellar-agent-mcp@{version}\n"
            f'cargo install stellar-agent-cli@{version} --root "./a #b" --locked\n'
            f"cargo install stellar-agent-mcp@{version} --root './a #c' --locked\n"
            f"cargo install stellar-agent-cli@{version} --root ./a#d --locked",
        )
        + "\n"
        + fenced("bash", "read -rs NEAR_SAME_SK\nunset NEAR_SAME_SK")
        + "\n"
        + fenced("bash", "read -sr NEAR_ESCAPE_SK")
        + "\nType a literal \\` character, then run `unset NEAR_ESCAPE_SK`.\n",
    )


def excluded_files(tree: pathlib.Path) -> None:
    """Tracked files the check excludes, each holding an unlocked install."""
    version = workspace_version(tree)
    unlocked = fenced("bash", f"cargo install stellar-agent-cli@{version}")
    add_tracked(tree, "CHANGELOG.md", "# Changelog\n\n" + unlocked)
    add_tracked(tree, "crates/stellar-agent-cli/vendor/notes.md", unlocked)
    add_tracked(tree, "crates/stellar-agent-cli/tests/fixtures/notes.md", unlocked)


def workspace_version(tree: pathlib.Path) -> str:
    with open(tree / "Cargo.toml", "rb") as handle:
        return tomllib.load(handle)["workspace"]["package"]["version"]


BASELINES = (
    ("clean copy", None),
    ("clean copy with near misses", near_misses),
    ("clean copy with excluded files", excluded_files),
)


def main(argv: list[str]) -> int:
    root = pathlib.Path(argv[1] if len(argv) > 1 else HERE.parent.parent).resolve()
    check = load_check()
    version = workspace_version(root)
    failures = 0
    with tempfile.TemporaryDirectory(prefix="install-surface-") as scratch:
        pristine = pathlib.Path(scratch) / "pristine"
        for relative in check.scanned_files(root):
            source = root / relative
            if not source.is_file():
                continue
            target = pristine / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        subprocess.run(["git", "init", "-q"], cwd=pristine, check=True)
        subprocess.run(["git", "add", "-A"], cwd=pristine, check=True)

        def fresh(label: str) -> pathlib.Path:
            tree = pathlib.Path(scratch) / label
            shutil.copytree(pristine, tree)
            return tree

        for label, mutate in BASELINES:
            tree = fresh(label.replace(" ", "-"))
            try:
                if mutate is not None:
                    mutate(tree)
            except (AssertionError, OSError, subprocess.CalledProcessError) as error:
                failures += 1
                print(f"FAIL  {label}: {error}")
                continue
            result = run_check(tree)
            if result.returncode == 0:
                print(f"ok    {label} passes")
            else:
                failures += 1
                print(f"FAIL  {label}: exit {result.returncode}\n{result.stdout}{result.stderr}")

        for index, case in enumerate(cases(version)):
            tree = fresh(f"case-{index:02d}")
            try:
                case.mutate(tree)
            except (AssertionError, OSError) as error:
                failures += 1
                print(f"FAIL  {case.name}: {error}")
                continue
            result = run_check(tree)
            prefix = f"{case.path}:{case.line}:" if case.line is not None else f"{case.path}:"
            matched = [
                line
                for line in result.stdout.splitlines()
                if line.startswith(prefix) and f": rule {case.rule}: " in line
            ]
            if result.returncode == 1 and matched:
                print(f"ok    {case.name}: {matched[0]}")
            else:
                failures += 1
                print(
                    f"FAIL  {case.name}: exit {result.returncode}, "
                    f"no rule {case.rule} violation on {prefix}\n{result.stdout}{result.stderr}"
                )
    total = len(BASELINES) + len(cases(version))
    print(f"install surface self-test: {total - failures} of {total} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
