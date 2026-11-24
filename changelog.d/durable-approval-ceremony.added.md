- A mainnet CLI value command under an approval rule opens a durable approval
  record before the passkey ceremony and commits its consent before the
  witness returns. A rerun of the same operation reuses the record's entry,
  completes an attested entry's consent without a second ceremony, and removes
  the unattested entries of the same envelope that a crash left before the
  record opened. A presence refusal keeps the entry and the record until the
  waiting expiry. The open stores the prepare decision and ends the
  operation's waiting window at the earlier of the signed waiting expiry and
  the envelope's end. A new consent payload keeps a queued row's outbox
  reference, or names its row `written` or `recovered`.
