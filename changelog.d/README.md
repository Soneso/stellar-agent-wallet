# Pending changelog entries

A fragment is a pending changelog entry. Each change adds its own files here.
Release preparation folds fragments into the version section whose tag
contains the change.

Name each file `<slug>.<category>.md`.
The slug contains lowercase letters, digits, and hyphens.
Use a descriptive branch name as the slug.
Lowercase it and replace every character outside `a-z`, `0-9`, and `-` with `-`.
For example, `fix/Login_v2.1` becomes `fix-login-v2-1`.
Use a topic slug when the branch name is generic, such as `main` or `patch-1`.
The filename contains no pull request number.

| Category | Keep a Changelog heading |
|---|---|
| `added` | Added |
| `changed` | Changed |
| `deprecated` | Deprecated |
| `removed` | Removed |
| `fixed` | Fixed |
| `security` | Security |

Use one file for each category a change needs.
For example, `account-timeouts.fixed.md` holds the entry for an account timeout
fix. See the complete example in
[Contributing](../CONTRIBUTING.md#changelog-entries).
Each top-level item starts with `- ` and contains text.
Blank separators, indented continuations, and nested lists are permitted after
an item.
Headings, metadata, and unindented prose are invalid.
Files use UTF-8. The utility normalizes fragment line endings to LF.
Only this README and regular fragment files belong in this directory.

Add entries through new fragment paths. Keep this README and `CHANGELOG.md`
unchanged in contributing pull requests. Move direct entries into fragments.
Remove the `CHANGELOG.md` edits from the branch history.
For example, use an interactive rebase that drops or amends those commits.
A later revert commit still fails the integration guard.
Commits that `main` holds are exempt.
An eligible sync merge has exactly two parents and brings new ancestry from
`main` through its second parent.
Its `CHANGELOG.md` equals the clean three-way merge over the parents' merge
base, preserving both sides' lines.
The guard refuses conflicts; a maintainer resolves and merges them.
The guard never accepts hand-resolved changelog bytes.
Never edit an existing fragment. Add a new file for a further entry.
Each fragment file belongs to one pull request and is never reused.
A sync merge deletes fragments that `main` folds and deletes.
It never deletes a fragment that holds an unreleased entry under this rule.
Missing refs, shallow history, unreadable objects, and Git errors fail the
guard. Supply complete history before retrying.
The guard uses `git merge-file -p --object-id` on the three file blobs.
Git's built-in text merge reads fixed inputs without attributes or custom
merge drivers. It writes only to stdout.
The same inputs produce the same result on supported contributor and CI Git
versions. A Git version without object-input support fails closed.
The fragment test suite checks this capability before the CI guard runs.
Different filenames avoid changelog conflicts between pull requests.
Identical filenames with different content produce an add/add conflict;
rename one fragment to resolve it.

Validate the directory:

```bash
python3 .github/scripts/changelog.py check
```

Preview the folded Unreleased section without changing files:

```bash
python3 .github/scripts/changelog.py preview
```

During release preparation, create the dated version heading below a fresh
Unreleased heading.
Fold entries into that version, using its version string without `v`:

```bash
python3 .github/scripts/changelog.py release --version VERSION
```

Review the compiled entries and fragment deletions in the preparation pull
request to `main`.
Tag only the merged, passing commit with no pending fragments.
See [Releasing](../docs/maintainers/releasing.md) for version pins and release
checks.
