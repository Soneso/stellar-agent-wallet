- On mainnet, an unsigned profile threshold can no longer remove the oracle
  witness requirement. Before, when the signed policy carried no native
  threshold, raising `cross_check_threshold_stroops` in the profile let a
  native payment of any size that carries a memo sign without an oracle
  comparison. The same held for a token whose threshold existed only in
  `[cross_check_thresholds]`.
- A mainnet threshold now never exceeds the value that applies without a
  profile value: the signed threshold in `[mainnet.cross_check_thresholds]`,
  else 1000 XLM for XLM and its SAC. A profile value only lowers a threshold.
  Testnet thresholds are unchanged.
- A mainnet token payment that needs a witness threshold, x402 payments
  included, now needs a signed entry for the token in
  `[mainnet.cross_check_thresholds]`. Without one it refuses whatever the
  profile sets: `network.witness_unavailable` from the caller checks,
  `network.mainnet_authorization_refused` from the resolver. The refusal text
  names the signed table on mainnet and the profile table on other networks.
