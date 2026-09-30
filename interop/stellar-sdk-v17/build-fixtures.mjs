// Builds the envelope type 9 and CAP-71 type 10 authorization preimage
// fixtures with the pinned @stellar/stellar-sdk. Each fixture is an unsigned
// SorobanAuthorizationEntry built from fixed inputs, run through the SDK
// export buildAuthorizationEntryPreimage (the function authorizeEntry signs
// over), and hashed with the SDK hash(). No signer and no secret key is
// involved.
import {
  Address,
  Networks,
  StrKey,
  buildAuthorizationEntryPreimage,
  hash,
  xdr,
} from "@stellar/stellar-sdk";

export const NETWORK_PASSPHRASE = Networks.TESTNET;
export const NONCE = 0x1234_5678;
export const SIGNATURE_EXPIRATION_LEDGER = 9999;
// The account strkey of 32 bytes of 0x44: a fixed public key with no secret.
export const ADDRESS = StrKey.encodeEd25519PublicKey(new Uint8Array(32).fill(0x44));
export const CONTRACT = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
export const FUNCTION_NAME = "test_invoke";

const CREDENTIAL_VARIANTS = [
  {
    file: "preimage-v1.json",
    credentialType: "address",
    envelopeType: 9,
    wrap: (creds) => xdr.SorobanCredentials.sorobanCredentialsAddress(creds),
  },
  {
    file: "preimage-v2.json",
    credentialType: "address_v2",
    envelopeType: 10,
    wrap: (creds) => xdr.SorobanCredentials.sorobanCredentialsAddressV2(creds),
  },
];

function buildEntry(wrap) {
  const creds = new xdr.SorobanAddressCredentials({
    address: new Address(ADDRESS).toScAddress(),
    nonce: BigInt(NONCE),
    signatureExpirationLedger: SIGNATURE_EXPIRATION_LEDGER,
    signature: xdr.ScVal.scvVec([]),
  });
  const rootInvocation = new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({
        contractAddress: new Address(CONTRACT).toScAddress(),
        functionName: FUNCTION_NAME,
        args: [],
      }),
    ),
    subInvocations: [],
  });
  return new xdr.SorobanAuthorizationEntry({ credentials: wrap(creds), rootInvocation });
}

// Returns [{ file, fixture }] for the envelope type 9 and type 10 preimages.
export function buildFixtures() {
  return CREDENTIAL_VARIANTS.map(({ file, credentialType, envelopeType, wrap }) => {
    const preimage = buildAuthorizationEntryPreimage(
      buildEntry(wrap),
      SIGNATURE_EXPIRATION_LEDGER,
      NETWORK_PASSPHRASE,
    );
    return {
      file,
      fixture: {
        credentialType,
        envelopeType,
        networkPassphrase: NETWORK_PASSPHRASE,
        nonce: NONCE,
        signatureExpirationLedger: SIGNATURE_EXPIRATION_LEDGER,
        address: ADDRESS,
        contract: CONTRACT,
        functionName: FUNCTION_NAME,
        args: [],
        preimageXdr: preimage.toXdr("base64"),
        payloadHex: Buffer.from(hash(preimage.toXdr())).toString("hex"),
      },
    };
  });
}

// The exact text gen-fixture.mjs writes and check.mjs compares.
export function fixtureText(fixture) {
  return `${JSON.stringify(fixture, null, 2)}\n`;
}
