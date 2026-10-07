## What this changes

<!-- Two or three sentences in present tense: what the change does and why. -->

Closes #N

<!-- Replace N with the number of the issue this pull request resolves. -->

## Gates run

<!--
Start local verification with `bash .github/scripts/preflight.sh` and paste its
table here. Also list issue-specific acceptance commands and their exit codes.
`bash .github/scripts/preflight.sh --full` runs the complete local registry,
including coverage. Local coverage, machete, and deny are optional reproductions.
CI runs the offline workspace suite on every pull request. Pull-request
coverage requires the `coverage` label; live acceptance uses its separate workflow.
-->

-

## Checklist

Confirm each item for this description, the documentation, and the code comments in the change. The rules are in the [Writing style](https://github.com/Soneso/stellar-agent-wallet/blob/main/CONTRIBUTING.md#writing-style) section of the contributing guide.

- [ ] "Allow edits by maintainers" is enabled, so a maintainer can push small fixes to the branch.
- [ ] Every sentence is under 35 words.
- [ ] No em dash.
- [ ] No filler adjectives.
- [ ] No history of how the code got there.
- [ ] No contrast with imagined wrong behavior.
- [ ] Comments state invariants.
- [ ] I understand every line of the change and can answer questions about it.
- [ ] Every new test fails when the behavior it pins is reverted (the self-review section of the review checklist).
