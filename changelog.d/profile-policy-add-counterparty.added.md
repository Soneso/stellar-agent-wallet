- `profile policy add-counterparty --profile <NAME> --recipient <ADDRESS>`
  adds one G, M, C, or W recipient to the target payment rules, and
  `--tool` narrows the selection. It previews the edited body on stderr with
  `edit_scope` before the authoring guard, the prompt, and any write.
  On an unsigned draft it edits the body, signs nothing, and names
  `profile sign-policy` as the next step.
  On a signed body it rechecks the file, the profile, and the pin under the
  guard and again after a hidden seed prompt, then signs the change with the
  next sequence. It compares the pin and replaces the file under the
  policy-state lock.
  A W recipient carries a note that the entry takes effect when the wallet
  pays W destinations. New codes: `profile.policy_changed_during_edit`,
  `profile.policy_owner_prompt_required`, `profile.policy_owner_rotation_pending`,
  and `profile.policy_version_required`.
