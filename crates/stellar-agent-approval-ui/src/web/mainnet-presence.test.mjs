// The mainnet approval credential enrollment page. The server renders
// data-purpose="mainnet-approval"; the page then stores and reads its own
// session proof key and derives the confirmation code under the mainnet
// domain. The vectors are those of the Rust test
// `mainnet_confirmation_code_vectors_match_browser`: challenge 0x00..0x1f,
// credential ID sixteen 0xa5 bytes, key 0x04 followed by 0x01..0x40.

import { test } from "node:test";
import assert from "node:assert/strict";
import { b64url, browser, jsonReply, until } from "./browser_harness.mjs";

const MAINNET_PROOF_KEY = "stellar-agent-mainnet-approval-enroll-session-proof";
const OPERATOR_PROOF_KEY = "stellar-agent-operator-enroll-session-proof";
const PROOF = "cd".repeat(32);

const VECTOR_CHALLENGE = Uint8Array.from({ length: 32 }, (_, i) => i);
const VECTOR_ID = new Uint8Array(16).fill(0xa5);
const VECTOR_KEY = Uint8Array.from({ length: 65 }, (_, i) => (i === 0 ? 4 : i));
const MAINNET_CODE = "415b-db8a-ac00-4222";
const OPERATOR_CODE = "305b-4244-62ef-fd53";

function credential({ id = VECTOR_ID, key = VECTOR_KEY } = {}) {
  const spki = new Uint8Array(26 + key.length);
  spki.fill(0x30, 0, 26);
  spki.set(key, 26);
  return {
    rawId: id.slice().buffer,
    response: {
      getPublicKey: () => spki.buffer,
      clientDataJSON: new TextEncoder().encode('{"type":"webauthn.create"}').buffer,
      attestationObject: Uint8Array.from([0xa3, 0x01, 0x02]).buffer,
    },
  };
}

function server(challenge = VECTOR_CHALLENGE) {
  return (url) => {
    if (url === "/enroll/challenge") {
      return jsonReply(200, {
        challenge: b64url(challenge),
        rp_id: "localhost",
        alg: -7,
        user_verification: "required",
        resident_key: "required",
        attestation: "none",
        timeout_ms: 300000,
      });
    }
    return jsonReply(200, { status: "awaiting_confirmation" });
  };
}

function mainnetPage(storage, { challenge, id, key } = {}) {
  const page = browser({
    islands: { "enroll-data": { csrfToken: "f".repeat(64), rpId: "localhost" } },
    attributes: { "enroll-data": { "data-purpose": "mainnet-approval" } },
    elements: ["label-input", "enroll-btn", "status", "confirmation-code"],
    storage,
    reply: server(challenge),
    credential: () => credential({ id, key }),
  });
  page.byId["label-input"].value = "laptop";
  page.run("../operator_enroll/web/operator-enroll.js");
  return page;
}

test("the mainnet page shows the mainnet code and names the owner's signature", async () => {
  const page = mainnetPage({ [MAINNET_PROOF_KEY]: PROOF });
  page.byId["enroll-btn"].listeners.click[0]();
  await until(() => page.byId["confirmation-code"].textContent !== "", "the mainnet confirmation code");
  assert.equal(page.byId["confirmation-code"].textContent, MAINNET_CODE);
  assert.notEqual(MAINNET_CODE, OPERATOR_CODE);
  const [challenge, posted] = page.fetches;
  assert.equal(challenge.init.headers["x-session-proof"], PROOF);
  assert.equal(posted.init.headers["x-session-proof"], PROOF);
  assert.equal(page.credentialCalls[0].publicKey.rp.id, "localhost");
  assert.match(page.byId.status.textContent, /mainnet\.approval_credentials/);
  assert.match(page.byId.status.textContent, /signs the policy/);
  assert.doesNotMatch(page.byId.status.textContent, /allowed_credentials/);
});

for (const [name, setup, code] of [
  ["challenge", { challenge: Uint8Array.from(VECTOR_CHALLENGE, (b, i) => (i === 0 ? b ^ 1 : b)) }, "67f8-9765-fe91-7daf"],
  ["credential ID", { id: Uint8Array.from(VECTOR_ID, (b, i) => (i === 0 ? b ^ 1 : b)) }, "b965-512c-4df9-c87d"],
  ["key", { key: Uint8Array.from(VECTOR_KEY, (b, i) => (i === 64 ? b ^ 1 : b)) }, "504b-3195-bc18-cf46"],
  ["credential ID length", { id: new Uint8Array(32).fill(0xa5) }, "1c3b-c8a8-faf5-58cb"],
]) {
  test(`the mainnet code changes with the ${name}, as the Rust vectors do`, async () => {
    const page = mainnetPage({ [MAINNET_PROOF_KEY]: PROOF }, setup);
    page.byId["enroll-btn"].listeners.click[0]();
    await until(() => page.byId["confirmation-code"].textContent !== "", `the mainnet code for ${name}`);
    assert.equal(page.byId["confirmation-code"].textContent, code);
  });
}

test("the operator enrollment proof does not open a mainnet ceremony", async () => {
  const page = mainnetPage({ [OPERATOR_PROOF_KEY]: PROOF });
  page.byId["enroll-btn"].listeners.click[0]();
  await until(() => /no wallet session/.test(page.byId.status.textContent), "the missing mainnet proof status");
  assert.equal(page.credentialCalls.length, 0);
  assert.equal(page.fetches.length, 0);
});
