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

const CONSENT_KEY = "stellar-agent-mainnet-presence-session-proof";
const INBOX_KEY = "stellar-agent-approval-session-proof";
const SESSION_ENDED = "The consent session has ended. Restart the command for a new link.";
const ASSERTION_REPLY = { status: "presence_verified" };
const CHALLENGE_REPLY = {
  challenge: b64url(VECTOR_CHALLENGE), request_id: "request", allow_credentials: [b64url(VECTOR_ID)], timeout_ms: 120000
};
// A reply whose body is not JSON, as the bare 404 of an ended session is.
function bareReply(status) {
  return Promise.resolve({ ok: false, status, json: () => Promise.reject(new SyntaxError("Unexpected token N in JSON at position 0")) });
}
// The consent page of `mode`: the ceremony of one command ("one_shot", with
// Cancel) or the inbox ("inbox", with Reject). `replies` maps the action a
// POST names to its reply.
function consentPage({ webauthn = true, failure, mode = "one_shot", replies = {} } = {}) {
  const raw = Uint8Array.of(1, 2, 3).buffer;
  const storageKey = mode === "inbox" ? INBOX_KEY : CONSENT_KEY;
  const page = browser({
    webauthn,
    islands: { "presence-data": { nonce: "nonce", csrf: "csrf", consent_view_digest: "digest", storageKey, mode } },
    elements: ["presence-approve", mode === "inbox" ? "presence-reject" : "presence-cancel", "presence-result"],
    storage: { [storageKey]: PROOF },
    reply: (url) => {
      const action = url.split("/").at(-1);
      if (action in replies) return replies[action]();
      return jsonReply(200, action === "challenge" ? CHALLENGE_REPLY : action === "assertion" ? ASSERTION_REPLY : { status: "canceled" });
    },
    credential: () => {
      if (failure) throw { name: failure, message: "private exception" };
      return { rawId: raw, response: { authenticatorData: raw, clientDataJSON: raw, signature: raw } };
    }
  });
  page.run("./app_shared.js");
  return page;
}
test("the consent page requests pinned UV only on a trusted click and posts raw bytes", async () => {
  const page = consentPage(); page.run("./mainnet-presence.js");
  assert.equal(page.fetches.length, 0);
  await page.byId["presence-approve"].listeners.click[0]({ isTrusted: false });
  assert.equal(page.fetches.length, 0);
  await page.byId["presence-approve"].listeners.click[0]({ isTrusted: true });
  assert.equal(page.credentialCalls.length, 1);
  const options = page.credentialCalls[0].publicKey;
  assert.equal(options.rpId, "localhost"); assert.equal(options.userVerification, "required");
  assert.equal(b64url(options.challenge), b64url(VECTOR_CHALLENGE));
  assert.equal(b64url(options.allowCredentials[0].id), b64url(VECTOR_ID));
  assert.equal(options.timeout, 120000);
  assert.equal(page.fetches[0].init.headers["X-Session-Proof"], PROOF);
  assert.deepEqual(JSON.parse(page.fetches[0].init.body), { consent_view_digest: "digest" });
  assert.deepEqual(JSON.parse(page.fetches[1].init.body), { request_id: "request", credential_id_b64url: "AQID", authenticator_data_b64url: "AQID", client_data_json_b64url: "AQID", signature_der_b64url: "AQID" });
  assert.equal(page.byId["presence-result"].textContent, "Presence verified. Check the command result.");
});
for (const [setup, reason] of [[{ webauthn: false }, "browser_unavailable"], [{ failure: "NotAllowedError" }, "authenticator_canceled"], [{ failure: "SecurityError" }, "browser_unavailable"]]) {
  test(`the consent page cancels safely with ${reason} ${JSON.stringify(setup)}`, async () => {
    const page = consentPage(setup); page.run("./mainnet-presence.js");
    await page.byId["presence-approve"].listeners.click[0]({ isTrusted: true });
    assert.equal(JSON.parse(page.fetches.at(-1).init.body).reason, reason);
    assert.ok(page.fetches.every(({url}) => !url.endsWith("assertion")));
    assert.doesNotMatch(page.byId["presence-result"].textContent, /private exception/);
  });
}
test("the explicit consent cancel button sends operator_cancel", async () => {
  const page = consentPage(); page.run("./mainnet-presence.js");
  await page.byId["presence-cancel"].listeners.click[0]({ isTrusted: true });
  assert.equal(JSON.parse(page.fetches[0].init.body).reason, "operator_cancel");
  assert.equal(page.credentialCalls.length, 0);
});
test("an inbox approval renders the recorded attestation with the shared renderer", async () => {
  const page = consentPage({ mode: "inbox", replies: { assertion: () => jsonReply(200, { status: "attested", attestation: "BLOB", expires_at_unix_ms: 7 }) } });
  page.run("./mainnet-presence.js");
  assert.equal(page.byId["presence-reject"].listeners.click.length, 1);
  await page.byId["presence-approve"].listeners.click[0]({ isTrusted: true });
  const result = page.byId["presence-result"];
  assert.equal(result.className, "result");
  assert.equal(result.children[0].textContent, "Status: attested");
  const area = result.children.find((child) => child.name === "textarea");
  assert.equal(area.value, "BLOB");
  assert.ok(result.children.some((child) => child.textContent === "Copy attestation"));
  assert.equal(page.byId["presence-approve"].disabled, true);
});
test("a ceremony approval keeps its fixed text and names the command", async () => {
  const page = consentPage({ replies: { assertion: () => jsonReply(200, { status: "presence_verified", request_id: "request" }) } });
  page.run("./mainnet-presence.js");
  await page.byId["presence-approve"].listeners.click[0]({ isTrusted: true });
  assert.equal(page.byId["presence-result"].textContent, "Presence verified. Check the command result.");
  assert.equal(page.byId["presence-result"].children.length, 0);
});
for (const action of ["challenge", "assertion"]) {
  test(`the ${action} reply without a JSON body shows the ended session, never the parser text`, async () => {
    const page = consentPage({ mode: "inbox", replies: { [action]: () => bareReply(404) } });
    page.run("./mainnet-presence.js");
    await page.byId["presence-approve"].listeners.click[0]({ isTrusted: true });
    assert.equal(page.byId["presence-result"].textContent, SESSION_ENDED);
    assert.doesNotMatch(page.byId["presence-result"].textContent, /JSON|Unexpected/);
  });
}
test("a cancel reply without a JSON body shows the ended session", async () => {
  const page = consentPage({ replies: { cancel: () => bareReply(404) } });
  page.run("./mainnet-presence.js");
  await page.byId["presence-cancel"].listeners.click[0]({ isTrusted: true });
  assert.equal(page.byId["presence-result"].textContent, SESSION_ENDED);
});
test("the inbox Reject posts the guarded rejection and renders it as not recorded", async () => {
  const page = consentPage({ mode: "inbox", replies: { reject: () => jsonReply(200, { status: "rejected" }) } });
  page.run("./mainnet-presence.js");
  await page.byId["presence-reject"].listeners.click[0]({ isTrusted: false });
  assert.equal(page.fetches.length, 0);
  await page.byId["presence-reject"].listeners.click[0]({ isTrusted: true });
  assert.equal(page.fetches.length, 1);
  const [posted] = page.fetches;
  assert.equal(posted.url, "/approval/nonce/reject");
  assert.equal(posted.init.headers["X-Stellar-Approval-CSRF"], "csrf");
  assert.equal(posted.init.headers["X-Session-Proof"], PROOF);
  assert.equal(page.credentialCalls.length, 0);
  const result = page.byId["presence-result"];
  assert.equal(result.className, "result refused");
  assert.equal(result.children[0].textContent, "Not recorded: rejected");
  assert.equal(page.byId["presence-approve"].disabled, true);
});
test("a refused inbox rejection renders the server code", async () => {
  const page = consentPage({ mode: "inbox", replies: { reject: () => jsonReply(409, { error: "approval.presence_changed", message: "changed" }) } });
  page.run("./mainnet-presence.js");
  await page.byId["presence-reject"].listeners.click[0]({ isTrusted: true });
  assert.equal(page.byId["presence-result"].children[0].textContent, "Not recorded: approval.presence_changed");
  assert.notEqual(page.byId["presence-approve"].disabled, true);
});
test("a challenge reply that carries an entry outcome is rendered as not recorded", async () => {
  const page = consentPage({ mode: "inbox", replies: { challenge: () => jsonReply(200, { status: "expired" }) } });
  page.run("./mainnet-presence.js");
  await page.byId["presence-approve"].listeners.click[0]({ isTrusted: true });
  assert.equal(page.credentialCalls.length, 0);
  assert.equal(page.byId["presence-result"].children[0].textContent, "Not recorded: expired");
});
