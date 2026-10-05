## What this changes

<!-- Two or three sentences in present tense: what the change does and why. -->

Closes #N

<!-- Replace N with the number of the issue this pull request resolves. -->

## Gates run

<!--
Paste the table that `bash .github/scripts/preflight.sh` prints. A change
outside documentation, scripts, and workflows also lists the acceptance gates
of CONTRIBUTING.md it ran, with their exit codes.
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
