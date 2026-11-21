- `approve revoke` on a mainnet approval consumed inside its window now writes
  `revoked` and appends its `approval_revoked` audit row whatever the state of
  its operation. Before, a consumed record whose operation was closed returned
  its view without a write, and a child mint without an operation link, such
  as the payment under a used SEP-10 message authorization, could still
  succeed. Every later mint under the record now refuses as revoked.
- A consent commit under a revoked mainnet approval now refuses with
  `approval.revoked`, also when it repeats the receipt the record already
  holds. Before, that repeat returned the revoked record as a success and
  wrote nothing.
