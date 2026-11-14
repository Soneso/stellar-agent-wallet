- Window files use wire version 12.
- An operator clear and an accounting expiry keep a total debit counted. A
  checked failure or non-inclusion releases that attempt's total debit once
  and keeps its fee charged.
- A reservation that its writer cancels before the signed bytes leave the
  process releases its total debit. Any other cancellation keeps it counted.
- Every spelling of one asset, such as `native` and its asset contract,
  counts against one total-budget allocation.
