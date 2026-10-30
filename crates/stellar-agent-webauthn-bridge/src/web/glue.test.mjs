// Page-script tests for the bridge's registration glue: the ceremony runs
// over the challenge the bridge issued, and the confirmation code appears
// only once the bridge accepted the response.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  b64url,
  browser,
  jsonReply,
  until,
} from "../../../stellar-agent-approval-ui/src/web/browser_harness.mjs";

const GLUE = "../../../stellar-agent-webauthn-bridge/src/web/glue.js";

// The vector the Rust confirmation-code tests share: challenge 0x00..0x1f,
// credential ID sixteen 0xa5 bytes, key 0x04 followed by 0x01..0x40.
const CHALLENGE = Uint8Array.from({ length: 32 }, (_, index) => index);
const CREDENTIAL_ID = new Uint8Array(16).fill(0xa5);
const SEC1 = Uint8Array.from({ length: 65 }, (_, index) => (index === 0 ? 0x04 : index));
const PASSKEY_CODE = "2235-dd14-e097-75ce";

// A P-256 SubjectPublicKeyInfo: the fixed 26-byte header, then the point.
const SPKI_HEADER = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex");

function island(overrides = {}) {
  return {
    flow: "register",
    nonce: "nonce-1",
    csrfToken: "c".repeat(64),
    rpId: "localhost",
    userHandle: b64url(new Uint8Array(32).fill(7)),
    challenge: b64url(CHALLENGE),
    ...overrides,
  };
}

function registrationCredential() {
  return {
    id: b64url(CREDENTIAL_ID),
    rawId: b64url(CREDENTIAL_ID),
    type: "public-key",
    response: {
      clientDataJSON: b64url(Buffer.from("{}")),
      attestationObject: b64url(Buffer.from("attestation")),
      publicKey: b64url(Buffer.concat([SPKI_HEADER, Buffer.from(SEC1)])),
      transports: ["internal"],
    },
  };
}

// A bridge page with the registration island, a fake vendored bundle that
// records the options it receives, and `reply` answering the POST.
function registrationPage({ islandValue = island(), reply }) {
  const started = [];
  const page = browser({
    islands: { "webauthn-options": islandValue },
    elements: ["status", "confirmation-code"],
    reply,
    globals: {
      SimpleWebAuthnBrowser: {
        startRegistration(args) {
          started.push(args);
          return Promise.resolve(registrationCredential());
        },
        startAuthentication() {
          throw new Error("the registration page authenticates nothing");
        },
      },
    },
  });
  page.byId["confirmation-code"].hidden = true;
  return { page, started };
}

test("registration uses the server challenge and shows the code only after the bridge accepts", async () => {
  let resolveReply;
  const { page, started } = registrationPage({
    reply: () => new Promise((resolve) => {
      resolveReply = resolve;
    }),
  });
  page.run(GLUE);

  await until(() => page.fetches.length === 1, "the credential POST");
  assert.equal(started.length, 1);
  assert.equal(started[0].optionsJSON.challenge, b64url(CHALLENGE));
  assert.equal(started[0].optionsJSON.rp.id, "localhost");
  const [{ url, init }] = page.fetches;
  assert.equal(url, "/register/nonce-1/credential");
  assert.equal(init.headers["X-Stellar-Approval-CSRF"], "c".repeat(64));
  const body = JSON.parse(init.body);
  assert.equal(body.id, b64url(CREDENTIAL_ID));
  assert.equal(body.rawId, b64url(CREDENTIAL_ID));
  assert.equal(body.response.publicKeySec1B64, Buffer.from(SEC1).toString("base64"));

  const code = page.byId["confirmation-code"];
  assert.equal(code.hidden, true, "no code before the bridge accepted the response");
  assert.equal(code.textContent, "");

  resolveReply(await jsonReply(200, { status: "recorded" }));
  await until(() => !code.hidden, "the confirmation code");
  assert.equal(code.textContent, PASSKEY_CODE);
  const status = page.byId.status;
  assert.equal(status.getAttribute("data-state"), "ok");
  assert.equal(
    status.textContent,
    `Passkey created. Type the code ${PASSKEY_CODE} at the terminal that started this registration. The passkey is registered only after the terminal accepts the code.`,
  );
});

test("a refused registration shows no code", async () => {
  const { page } = registrationPage({
    reply: () => jsonReply(400, { error: "webauthn_registration_invalid" }),
  });
  page.run(GLUE);

  const status = page.byId.status;
  await until(() => status.getAttribute("data-state") === "error", "the refusal");
  assert.equal(status.textContent, "Error: HTTP 400");
  const code = page.byId["confirmation-code"];
  assert.equal(code.hidden, true);
  assert.equal(code.textContent, "");
});

for (const [name, challenge] of [
  ["missing", undefined],
  ["short", b64url(new Uint8Array(31))],
  ["not base64url", "!!!"],
]) {
  test(`a page without a challenge creates no passkey (${name})`, async () => {
    const islandValue = island({ challenge });
    if (challenge === undefined) {
      delete islandValue.challenge;
    }
    const { page, started } = registrationPage({
      islandValue,
      reply: () => jsonReply(200, { status: "recorded" }),
    });
    page.run(GLUE);
    await new Promise((resolve) => setImmediate(resolve));

    assert.equal(started.length, 0, "no startRegistration call");
    assert.equal(page.fetches.length, 0, "no fetch");
    const status = page.byId.status;
    assert.equal(status.getAttribute("data-state"), "error");
    assert.equal(status.textContent, "Error: the registration page has no valid challenge");
    assert.equal(page.byId["confirmation-code"].hidden, true);
  });
}
