- `stellar_x402_create_payment` and `stellar_x402_authenticated_payment` queue a payment for owner approval on testnet when the policy requires approval.
  The repeated call with the approval proof pays once.
- `stellar_agent_x402::exact::create_payment_with_pre_sign` runs a caller check immediately before the payer signs.
- `KeyringSignHandle::sign_soroban_address_auth_payload_checked` runs a caller check after the payer-key read, immediately before signing.
