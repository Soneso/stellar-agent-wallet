Read [AGENTS.md](AGENTS.md) first.
Start local verification with `bash .github/scripts/preflight.sh` and run the
issue-specific acceptance commands. `bash .github/scripts/preflight.sh --full`
runs the complete local registry, including coverage.
CI runs the offline workspace suite on every pull request. Pull-request
coverage requires the `coverage` label; live acceptance uses its separate
workflow. Local coverage, machete, and deny are optional reproductions.
Complete the [self-review](docs/maintainers/review-checklist.md#self-review-before-you-open-a-pull-request).

While editing, follow [Writing style](CONTRIBUTING.md#writing-style):

- Keep sentences under 35 words and in present tense; use American spelling and serial commas.
- Use a comma, a period, or a colon instead of an em dash or en dash.
- Use no emoji.
- State what holds and why in comments; omit history and contrasts with imagined wrong behavior.
- Cut filler words; give the number or measure.
