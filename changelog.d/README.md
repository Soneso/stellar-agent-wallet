# Pending changelog entries

A fragment is a pending changelog entry. Each change adds its own files here.
Release preparation folds fragments into the version section whose tag contains the change.

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
For example, `account-timeouts.fixed.md` holds the entry for an account timeout fix.
Each top-level item starts with `- ` and contains text.
Blank separators, indented continuations, and nested lists are permitted after an item.
Headings, metadata, and unindented prose are invalid.
Files use UTF-8. The utility normalizes fragment line endings to LF.
Only this README and regular fragment files belong in this directory.

Add entries through new fragment paths. Keep this README and `CHANGELOG.md` unchanged in contributing pull requests.
An open pull request with a `CHANGELOG.md` hunk moves its entries into fragments and drops that hunk.
The integration guard permits changelog changes from commits that `main` holds.
Different filenames avoid changelog conflicts between pull requests.
Identical filenames with different content produce an add/add conflict; rename one fragment to resolve it.

Validate the directory:

```bash
python3 .github/scripts/changelog.py check
```

Preview the folded Unreleased section without changing files:

```bash
python3 .github/scripts/changelog.py preview
```

During release preparation, create the dated version heading below a fresh Unreleased heading.
Fold entries into that version, using its version string without `v`:

```bash
python3 .github/scripts/changelog.py release --version VERSION
```

Review the compiled entries and fragment deletions in the preparation pull request to `main`.
Tag only the merged, passing commit with no pending fragments.
See [Releasing](../docs/maintainers/releasing.md) for version pins and release checks.
