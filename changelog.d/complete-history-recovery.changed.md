- Recovery releases held funds when two endpoints confirm a transaction was
  never included across its full validity window. It checks the transaction
  again after saving the completed ledger scan. Accounts missing from both
  endpoints can use this recovery path.
