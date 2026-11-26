#!/usr/bin/env python3
"""Execute Publish evidence steps with local tools; no API or download occurs.

Usage: test-publish-release-evidence.py [--case NAME] [--mutations]
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/publish.yml"
CASES = ("assets-success", "draft", "draft-string", "missing-archive", "missing-bundle",
         "missing-manifest", "missing-provenance", "extra-archive", "extra-bundle",
         "extra-other", "extra-hidden", "duplicate", "four-archives",
         "verify-success", "verify-hidden", "digest-failure", "verifier-failure",
         "provenance-zero", "provenance-two", "run-binding")
DIGEST = "946dbec729094195e88ef78e1734324a27869f03e2c6bd2f61cbc06bd5350339"


def block(source, name):
    tail = source.split("      - name: " + name + "\n", 1)[1].split("        run: |\n", 1)[1]
    lines = tail.splitlines(keepends=True)
    end = next((i for i, line in enumerate(lines) if line.strip() and not line.startswith("          ")), len(lines))
    return textwrap.dedent("".join(lines[:end]))


def executable(path, source):
    path.write_text("#!" + sys.executable + "\n" + textwrap.dedent(source))
    path.chmod(0o755)


def case(source, name):
    with tempfile.TemporaryDirectory(prefix="publish-evidence-") as scratch:
        root = Path(scratch)
        tools, assets, release = (root / n for n in ("bin", "assets", "release"))
        tools.mkdir()
        assets.mkdir()
        fixture = json.loads((ROOT / ".github/scripts/fixtures/stellar-agent-0.1.0-alpha.12.intoto.jsonl").read_text())
        statement = json.loads(base64.b64decode(fixture["dsseEnvelope"]["payload"]))
        invocation = statement["predicate"]["invocation"]
        environment = invocation["environment"]
        tag = environment["github_ref"].removeprefix("refs/tags/")
        repository = invocation["configSource"]["uri"].split("github.com/", 1)[1].split("@")[0]
        sums = (ROOT / ".github/scripts/fixtures/SHA256SUMS").read_text()
        archives = [line[66:] for line in sums.splitlines()]
        provenance = "stellar-agent-" + tag.removeprefix("v") + ".intoto.jsonl"
        names = archives + ["SHA256SUMS"] + [n + ".sigstore.json" for n in archives + ["SHA256SUMS"]] + [provenance]
        for n in names:
            (assets / n).write_text("fixture")
        (assets / "SHA256SUMS").write_text(sums)
        (assets / provenance).write_text(json.dumps(fixture))
        document = {"isDraft": False, "assets": [{"name": n} for n in names]}
        if name == "draft":
            document["isDraft"] = True
        elif name == "draft-string":
            document["isDraft"] = "false"
        elif name.startswith("missing-"):
            index = {"missing-archive": 0, "missing-manifest": 5, "missing-bundle": 6, "missing-provenance": -1}[name]
            document["assets"].pop(index)
        elif name.startswith("extra-"):
            document["assets"].append({"name": {"extra-archive": "other.zip", "extra-bundle": "other.sigstore.json",
                                               "extra-other": "notes.txt", "extra-hidden": ".hidden"}[name]})
        elif name == "duplicate":
            document["assets"].append(document["assets"][0])
        elif name == "four-archives":
            (assets / "SHA256SUMS").write_text("\n".join(sums.splitlines()[1:]) + "\n")
            document["assets"] = [a for a in document["assets"] if a["name"] not in (archives[0], archives[0] + ".sigstore.json")]
        metadata = root / "metadata.json"
        metadata.write_text(json.dumps(document))
        log = root / "calls"
        log.write_text("")
        env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"], CALLS=str(log),
                   ASSETS=str(assets), METADATA=str(metadata), TAG=tag, GITHUB_REPOSITORY=repository,
                   RELEASE_DIR=str(release), RUNNER_TEMP=str(root), SOURCE_SHA=environment["github_sha1"],
                   RELEASE_RUN_ID="2001", RELEASE_RUN_ATTEMPT="1", PIN=DIGEST)
        executable(tools / "gh", '''
            import fnmatch, json, os, pathlib, shutil, sys
            args = sys.argv[1:]
            with open(os.environ["CALLS"], "a") as out:
                out.write(json.dumps(args) + "\\n")
            assert args[:1] == ["release"] and args[2:5] == [os.environ["TAG"], "--repo", os.environ["GITHUB_REPOSITORY"]]
            data = json.loads(pathlib.Path(os.environ["METADATA"]).read_text())
            if args[1] == "view":
                assert args[5:] == ["--json", "isDraft,assets"]
                print(json.dumps(data))
            else:
                assert args[1] == "download"
                patterns = [args[i+1] for i, a in enumerate(args) if a == "--pattern"]
                found = [a["name"] for a in data["assets"] if any(fnmatch.fnmatch(a["name"], p) for p in patterns)]
                if not found:
                    sys.exit(3)
                for name in found:
                    shutil.copyfile(pathlib.Path(os.environ["ASSETS"]) / name, pathlib.Path(args[-1]) / name)
        ''')
        verifying = name.startswith(("verify-", "digest-", "verifier-", "provenance-", "run-"))
        if not verifying:
            result = subprocess.run(["bash", "-c", block(source, "Download the published release assets")],
                                    env=env, cwd=ROOT, capture_output=True, text=True)
            assert (result.returncode == 0) == (name == "assets-success"), f"{name}: acceptance differs: {result.stderr}"
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            assert calls[0][1] == "view", f"{name}: inventory must be read first"
            if name == "draft":
                assert len(calls) == 1, f"{name}: draft downloaded assets"
            elif name != "assets-success":
                assert len(calls) == 2, f"{name}: invalid inventory downloaded archives"
            else:
                assert sorted(p.name for p in release.rglob("*") if p.is_file() and p.name != "release.json") == sorted(names), \
                    f"{name}: downloaded set differs"
            return
        for directory in ("all-artifacts", "release-combined", "provenance"):
            (release / directory).mkdir(parents=True)
        for n in archives:
            (release / "all-artifacts" / n).write_text("fixture")
        if name == "verify-hidden":
            (release / "all-artifacts" / archives[0]).rename(release / "all-artifacts" / ("." + archives[0]))
        (release / "release-combined/SHA256SUMS").write_text(sums)
        if name != "provenance-zero":
            (release / "provenance" / provenance).write_text(json.dumps(fixture))
        if name == "provenance-two":
            (release / "provenance/extra.intoto.jsonl").write_text(json.dumps(fixture))
        if name == "run-binding":
            env["RELEASE_RUN_ID"] = "999"
        env["BAD_DIGEST"] = "1" if name == "digest-failure" else ""
        env["BAD_VERIFIER"] = "1" if name == "verifier-failure" else ""
        verifier_source = '''
            import json, os, sys
            args = sys.argv[1:]
            with open(os.environ["CALLS"], "a") as out:
                out.write(json.dumps(args) + "\\n")
            assert args[0] == "verify-artifact" and args[2] == "--provenance-path"
            assert args[4:8] == ["--source-uri", "github.com/" + os.environ["GITHUB_REPOSITORY"], "--source-tag", os.environ["TAG"]]
            assert args[8:] == ["--builder-id", "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0"]
            sys.exit(7 if os.environ["BAD_VERIFIER"] else 0)
        '''
        env["VERIFIER_SOURCE"] = "#!" + sys.executable + "\n" + textwrap.dedent(verifier_source)
        executable(tools / "curl", '''
            import os, pathlib, sys
            assert sys.argv[1:-2] == ["--proto", "=https", "--tlsv1.2", "--fail", "--silent", "--show-error", "--location",
                "https://github.com/slsa-framework/slsa-verifier/releases/download/v2.7.1/slsa-verifier-linux-amd64"]
            assert sys.argv[-2] == "--output"
            pathlib.Path(sys.argv[-1]).write_text(os.environ["VERIFIER_SOURCE"])
        ''')
        executable(tools / "sha256sum", '''
            import os, pathlib, sys
            assert sys.argv[1:] == ["--check", "--strict"]
            digest, path = sys.stdin.read().split()
            assert digest == os.environ["PIN"] and not os.access(path, os.X_OK)
            sys.exit(1 if os.environ["BAD_DIGEST"] else 0)
        ''')
        result = subprocess.run(["bash", "-c", block(source, "Verify provenance signatures and run binding")],
                                env=env, cwd=ROOT, capture_output=True, text=True)
        success = name in ("verify-success", "verify-hidden")
        assert (result.returncode == 0) == success, f"{name}: acceptance differs: {result.stderr}"
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        expected = 0 if name in ("digest-failure", "provenance-zero", "provenance-two") else 1 if name == "verifier-failure" else 5
        assert len(calls) == expected, f"{name}: expected {expected} verifier calls, got {len(calls)}"
        if name == "digest-failure":
            assert not os.access(root / "slsa-verifier", os.X_OK), f"{name}: unchecked binary is executable"
        if name == "run-binding":
            assert "provenance run ID differs" in result.stderr, f"{name}: run binding did not run"


MUTATIONS = {
    "draft": ('[ "$(jq -r .isDraft "$RELEASE_DIR/release.json")" = false ]', "true"),
    "draft-string": (".isDraft == false and ", ""),
    "extra-hidden": ('([.assets[].name] | sort) == ', '([] | sort) != '),
    "four-archives": ("($archives | length) == 5 and ", ""),
    "digest-failure": ("| sha256sum --check --strict", "| cat"),
    "verify-hidden": ("shopt -s nullglob dotglob", "shopt -s nullglob"),
    "provenance-zero": ("shopt -s nullglob dotglob", "shopt -s dotglob"),
    "provenance-two": ('[ "${#provenance[@]}" -eq 1 ]', "true"),
    "verifier-failure": ("@refs/tags/v2.1.0; \\", "@refs/tags/v2.1.0 || true; \\"),
    "run-binding": ('--run-id "$RELEASE_RUN_ID" --run-attempt "$RELEASE_RUN_ATTEMPT"', ""),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=CASES)
    parser.add_argument("--mutations", action="store_true")
    parser.add_argument("--workflow", type=Path, default=WORKFLOW)
    args = parser.parse_args()
    source = args.workflow.read_text()
    try:
        for name in ([args.case] if args.case else CASES):
            case(source, name)
            print("ok", name)
        if args.mutations:
            with tempfile.TemporaryDirectory(prefix="publish-evidence-probes-") as scratch:
                path = Path(scratch) / "publish.yml"
                for name, (old, new) in MUTATIONS.items():
                    assert source.count(old) == 1, f"{name}: mutation target differs"
                    path.write_text(source.replace(old, new, 1))
                    result = subprocess.run([sys.executable, __file__, "--case", name, "--workflow", str(path)],
                                            capture_output=True, text=True)
                    assert result.returncode == 1 and f"FAIL {name}:" in result.stderr, f"{name}: mutant survives: {result.stderr}"
                    path.write_text(source)
                    assert hashlib.md5(path.read_bytes()).digest() == hashlib.md5(source.encode()).digest()
                    case(path.read_text(), name)
                    print("ok mutation/control", name)
    except AssertionError as error:
        print("FAIL", error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
