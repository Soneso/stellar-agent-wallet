- A crash between a committed recovery decision and the write of its receipt
  no longer leaves the receipt behind the decision. The next dispatch rewrites
  the receipt of every committed decision with the exact identity and failure
  code of its attempt, or names the missing fact. `tx status` and
  `stellar_transaction_status` run the same repair and report their result
  even when a repair fails. A repair keeps an operator clear and a consumed
  approval, and a refusal lists the repaired and the refused decisions.
