# Pending changelog entries

A fragment is a pending changelog entry. Each change adds its own files here.
Release preparation folds fragments into the version section whose tag
contains the change.

Name each file `<slug>.<category>.md`.
The slug contains lowercase letters, digits, and hyphens.
Use a descriptive branch name as the slug, replacing slashes with hyphens.
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
Other changelog edits pass only in sync merges whose non-first parents all
belong to `main` history.
The merge's `CHANGELOG.md` must equal that file in one of those parents, byte
for byte. A sync merge takes the file from `main`.
The integration branch keeps its pending entries in fragments.
Missing refs, shallow history, unreadable objects, and Git errors fail the
guard. Supply complete history before retrying.
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
