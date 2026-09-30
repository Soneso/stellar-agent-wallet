// Live SEP-43 round trip against a Soroban RPC with the pinned
// @stellar/stellar-sdk, driven over line-delimited JSON on stdin and stdout.
//
// Environment:
//   SDK_RPC_URL             Soroban RPC endpoint
//   SDK_NETWORK_PASSPHRASE  network passphrase
//   SDK_SOURCE_SECRET       secret of the funded transaction source account
//   SDK_PAYER_ADDRESS       G-strkey of the wallet key that authorizes transfer
//   SDK_CONTRACT            token contract (the native asset contract)
//   SDK_RECIPIENT           G-strkey of the transfer recipient
//
// On start the driver prints {"ready":true}. Commands:
//   {"cmd":"prepare"}
//     Simulates transfer(payer, recipient, 1) from the source account with
//     useUpgradedAuth, requires the payer's entry to carry AddressV2
//     credentials, and prints {entryXdr, preimageXdr, payloadHex, validUntil,
//     credentialType}.
//     preimageXdr is the output of buildAuthorizationEntryPreimage, the
//     preimage authorizeEntry signs over and signAuthEntries hands a wallet.
//   {"cmd":"assemble","signatureBase64":"..."}
//     Writes the signature into the entry of the last prepare through
//     authorizeEntry (which verifies it against the payer's key), re-simulates,
//     signs the envelope with the source secret, submits, polls to a final
//     status, and prints {status, hash, credentialType}, the credential type
//     read from the payer's entry in the ledger's transaction envelope.
// Any error prints {"error":"<message>"} and exits 1.
import { createInterface } from "node:readline";
import {
  Address,
  BASE_FEE,
  Keypair,
  Operation,
  TransactionBuilder,
  authorizeEntry,
  buildAuthorizationEntryPreimage,
  hash,
  nativeToScVal,
  rpc,
} from "@stellar/stellar-sdk";

const CREDENTIAL_TYPE_NAMES = {
  sorobanCredentialsSourceAccount: "source_account",
  sorobanCredentialsAddress: "address",
  sorobanCredentialsAddressV2: "address_v2",
  sorobanCredentialsAddressWithDelegates: "address_with_delegates",
};
const VALIDITY_LEDGERS = 100;
const POLL_ATTEMPTS = 60;

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set`);
  }
  return value;
}

function emit(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function fail(error) {
  emit({ error: error instanceof Error ? error.message : String(error) });
  process.exit(1);
}

// The address of an entry's address-credentialled node, or null.
function entryAddress(entry) {
  const credentials = entry.credentials;
  const node =
    credentials.type === "sorobanCredentialsAddress"
      ? credentials.address
      : credentials.type === "sorobanCredentialsAddressV2"
        ? credentials.addressV2
        : credentials.type === "sorobanCredentialsAddressWithDelegates"
          ? credentials.addressWithDelegates.addressCredentials
          : null;
  return node === null ? null : Address.fromScAddress(node.address).toString();
}

function credentialTypeName(entry) {
  const name = CREDENTIAL_TYPE_NAMES[entry.credentials.type];
  if (name === undefined) {
    throw new Error(`unknown credential type ${entry.credentials.type}`);
  }
  return name;
}

function payerEntryIndex(entries, payer) {
  const index = entries.findIndex((entry) => entryAddress(entry) === payer);
  if (index < 0) {
    throw new Error(`no authorization entry for the payer ${payer}`);
  }
  return index;
}

const config = {
  rpcUrl: requiredEnv("SDK_RPC_URL"),
  passphrase: requiredEnv("SDK_NETWORK_PASSPHRASE"),
  source: Keypair.fromSecret(requiredEnv("SDK_SOURCE_SECRET")),
  payer: requiredEnv("SDK_PAYER_ADDRESS"),
  contract: requiredEnv("SDK_CONTRACT"),
  recipient: requiredEnv("SDK_RECIPIENT"),
};
const server = new rpc.Server(config.rpcUrl);
let prepared = null;

async function prepare() {
  const account = await server.getAccount(config.source.publicKey());
  const tx = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: config.passphrase,
  })
    .addOperation(
      Operation.invokeContractFunction({
        contract: config.contract,
        function: "transfer",
        args: [
          new Address(config.payer).toScVal(),
          new Address(config.recipient).toScVal(),
          nativeToScVal(1n, { type: "i128" }),
        ],
      }),
    )
    .setTimeout(300)
    .build();
  const simulation = await server.simulateTransaction(tx, undefined, undefined, true);
  if (!rpc.Api.isSimulationSuccess(simulation)) {
    throw new Error(`simulation failed: ${simulation.error ?? "no result"}`);
  }
  const entries = simulation.result?.auth ?? [];
  const index = payerEntryIndex(entries, config.payer);
  const entry = entries[index];
  const credentialType = credentialTypeName(entry);
  if (credentialType !== "address_v2") {
    throw new Error(
      `the RPC returned ${credentialType} credentials for the payer with useUpgradedAuth set`,
    );
  }
  const validUntil = simulation.latestLedger + VALIDITY_LEDGERS;
  const preimage = buildAuthorizationEntryPreimage(entry, validUntil, config.passphrase);
  prepared = { tx, entries, index, validUntil };
  return {
    entryXdr: entry.toXdr("base64"),
    preimageXdr: preimage.toXdr("base64"),
    payloadHex: Buffer.from(hash(preimage.toXdr())).toString("hex"),
    validUntil,
    credentialType,
  };
}

async function assemble(signatureBase64) {
  if (prepared === null) {
    throw new Error("assemble requires a prior prepare");
  }
  if (typeof signatureBase64 !== "string") {
    throw new Error("assemble requires signatureBase64");
  }
  const { tx, entries, index, validUntil } = prepared;
  const signature = new Uint8Array(Buffer.from(signatureBase64, "base64"));
  const signed = await authorizeEntry(
    entries[index],
    () => signature,
    validUntil,
    config.passphrase,
    config.payer,
  );
  const auth = entries.map((entry, position) => (position === index ? signed : entry));
  const invoke = tx.operations[0];
  const withAuth = TransactionBuilder.cloneFrom(tx)
    .clearOperations()
    .addOperation(
      Operation.invokeHostFunction({ source: invoke.source, func: invoke.func, auth }),
    )
    .build();
  const simulation = await server.simulateTransaction(withAuth);
  if (!rpc.Api.isSimulationSuccess(simulation)) {
    throw new Error(`re-simulation failed: ${simulation.error ?? "no result"}`);
  }
  const final = rpc.assembleTransaction(withAuth, simulation).build();
  final.sign(config.source);
  const sent = await server.sendTransaction(final);
  if (sent.status !== "PENDING") {
    const detail = sent.errorResult ? sent.errorResult.toXdr("base64") : "no error result";
    throw new Error(`sendTransaction returned ${sent.status}: ${detail}`);
  }
  const outcome = await server.pollTransaction(sent.hash, {
    attempts: POLL_ATTEMPTS,
    sleepStrategy: () => 1000,
  });
  if (outcome.status === "NOT_FOUND") {
    throw new Error(`transaction ${sent.hash} not found after ${POLL_ATTEMPTS} polls`);
  }
  const ledgerTx = TransactionBuilder.fromXDR(outcome.envelopeXdr, config.passphrase);
  const ledgerAuth = ledgerTx.operations[0].auth ?? [];
  const credentialType = credentialTypeName(
    ledgerAuth[payerEntryIndex(ledgerAuth, config.payer)],
  );
  return { status: outcome.status, hash: sent.hash, credentialType };
}

async function handle(line) {
  const request = JSON.parse(line);
  switch (request.cmd) {
    case "prepare":
      return prepare();
    case "assemble":
      return assemble(request.signatureBase64);
    default:
      throw new Error(`unknown command ${JSON.stringify(request.cmd)}`);
  }
}

const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
let queue = Promise.resolve();
input.on("line", (line) => {
  if (line.trim() === "") {
    return;
  }
  queue = queue.then(() => handle(line).then(emit)).catch(fail);
});
input.on("close", () => {
  queue.then(() => process.exit(0));
});
emit({ ready: true });
