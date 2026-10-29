import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import renderers from "./app_shared.js";

for (const [limit, rendered] of [
  [null, "unlimited"],
  ["0", "0 stroops (remove)"],
  ["123456789", "123456789 stroops"],
  ["9007199254740993", "9007199254740993 stroops"],
  ["9223372036854775807", "9223372036854775807 stroops"],
]) {
  test(`trustline summary preserves limit ${limit}`, () => {
    const issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
    const holder = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const view = { kind_name: "TrustlineSimulated", summary: {
      kind: "trustline", holder, asset_code: "USDC", asset_issuer: issuer,
      limit_stroops: limit, fee_stroops: "100", seq_num: 42,
    }};
    assert.equal(renderers.kindLabel(view), "TRUSTLINE");
    assert.equal(renderers.headlineText(view), `Trustline USDC:${issuer}`);
    assert.equal(renderers.metaText(view), `limit ${rendered} for ${holder} · memo none`);
  });
}

test("an inconsistent entry reads as one that cannot be approved", () => {
  const view = { kind_name: "PaymentSimulated", summary: {
    kind: "inconsistent", original_kind_name: "PaymentSimulated",
    reason: "the stored digest is not the digest of the stored envelope",
  }};
  assert.equal(renderers.kindLabel(view), "INCONSISTENT");
  assert.equal(renderers.headlineText(view), "Inconsistent PaymentSimulated");
  assert.equal(renderers.metaText(view), "cannot be approved");
});

function renderedRow(view) {
  function element() {
    return { children: [], textContent: "", appendChild(child) { this.children.push(child); } };
  }
  globalThis.document = { createElement: element, createTextNode(text) {
    return { textContent: text, children: [] };
  }, getElementById() { return null; } };
  const container = element();
  renderers.renderInbox(container, [view]);
  const main = container.children[0].children[1];
  return { headline: main.children[0].textContent, meta: main.children[1].textContent };
}

test("claim row renders signed fields and the ledger-value qualification", () => {
  const view = { summary: { kind: "claim", balance_id_strkey: "B123", source: "G123",
    fee_stroops: "100", seq_num: 42 } };
  const row = renderedRow(view);
  assert.equal(row.headline, "Claim balance B123");
  assert.equal(row.meta, "source G123 · fee 100 stroops · sequence 42 · asset and amount: not part of the signed claim transaction · memo none");
});

test("path payment row labels the ceiling and destination terms", () => {
  const view = { summary: { kind: "payment", to: "G123", amount_stroops: "10000000",
    asset: "XLM", dest_asset: "USD:G456", dest_amount_stroops: "20000000", memo: { kind: "none" } } };
  const row = renderedRow(view);
  assert.match(row.headline, /^maximum sent /);
  assert.match(row.headline, /1.*XLM/);
  assert.match(row.meta, /destination receives at least 2.*USD/);
  assert.match(row.meta, /to G123/);
});

// testdata/inbox_bidi.json is the inbox JSON the Rust test
// `inbox_json_bidi_fixture` asserts as parsed JSON, so this test renders
// exactly what the server emits.
test("Rust inbox JSON escapes bidi rule names and memos before DOM rendering", () => {
  const views = JSON.parse(readFileSync(new URL("./testdata/inbox_bidi.json", import.meta.url), "utf8"));
  assert.equal(views[0].summary.summary_line, "café\\u{202e}rule");
  assert.equal(views[0].summary.definition.name, "café\\u{202e}rule");
  assert.equal(views[1].summary.memo.value, "memo\\u{202e}");
  assert.ok(!JSON.stringify(views).includes("\u202e"));
  assert.equal(renderedRow(views[0]).headline, "café\\u{202e}rule");
  assert.match(renderedRow(views[1]).meta, /memo text "memo\\u\{202e\}"/);
});

test("memo types remain distinct through JSON and DOM rendering", () => {
  const meta = memo => renderedRow({summary: {kind: "payment", to: "G123",
    amount_stroops: "1", asset: "XLM", memo}}).meta;
  assert.match(meta({kind: "text", value: "id 7"}), /memo text "id 7"/);
  assert.match(meta({kind: "id", value: "7"}), /memo id 7$/);
  assert.match(meta({kind: "none"}), /memo none$/);
  assert.match(meta({kind: "text", value: "(none)"}), /memo text "\(none\)"$/);
  assert.match(meta({kind: "id", value: "18446744073709551615"}), /18446744073709551615$/);
  for (const kind of ["hash", "return"]) {
    assert.ok(meta({kind, value: Array(32).fill(171)}).endsWith(kind + " " + "ab".repeat(32)));
  }
});

// ── Session proof: the bootstrap page, the inbox, and the enrollment page ──
//
// Each browser script runs in a fresh VM context with a minimal DOM, a
// recorded sessionStorage, a recorded fetch, and a manual clock, so the tests
// observe exactly what the script stores, requests, and navigates to.

const INBOX_PROOF_KEY = "stellar-agent-approval-session-proof";
const ENROLL_PROOF_KEY = "stellar-agent-operator-enroll-session-proof";
const PROOF = "ab".repeat(32);

function source(relative) {
  return readFileSync(new URL(relative, import.meta.url), "utf8");
}

function fakeElement(name) {
  return {
    name,
    textContent: "",
    className: "",
    hidden: false,
    value: "",
    children: [],
    attributes: {},
    listeners: {},
    appendChild(child) {
      this.children.push(child);
      return child;
    },
    setAttribute(key, value) {
      this.attributes[key] = String(value);
    },
    getAttribute(key) {
      return key in this.attributes ? this.attributes[key] : null;
    },
    addEventListener(type, listener) {
      (this.listeners[type] ||= []).push(listener);
    },
  };
}

function browser({ islands = {}, elements = [], storage = {}, storageThrows = false, readBackDiffers = false } = {}) {
  const byId = {};
  for (const [id, value] of Object.entries(islands)) {
    byId[id] = fakeElement(id);
    byId[id].textContent = typeof value === "string" ? value : JSON.stringify(value);
  }
  for (const id of elements) {
    byId[id] ||= fakeElement(id);
  }
  const stored = new Map(Object.entries(storage));
  const log = [];
  const fetches = [];
  const intervals = [];
  const documentListeners = {};
  const clock = { now: 1_000_000 };
  const sessionStorage = {
    getItem(key) {
      if (storageThrows) throw new Error("storage denied");
      return stored.has(key) ? stored.get(key) : null;
    },
    setItem(key, value) {
      if (storageThrows) throw new Error("storage denied");
      log.push(["setItem", key]);
      stored.set(key, readBackDiffers ? "other" : String(value));
    },
  };
  class FakeDate extends Date {
    static now() {
      return clock.now;
    }
  }
  const document = {
    documentElement: fakeElement("html"),
    getElementById(id) {
      return byId[id] || null;
    },
    createElement(tag) {
      return fakeElement(tag);
    },
    createTextNode(text) {
      return { textContent: text, children: [] };
    },
    addEventListener(type, listener) {
      (documentListeners[type] ||= []).push(listener);
    },
  };
  const credentialCalls = [];
  const context = {
    document,
    window: {
      sessionStorage,
      location: {
        replace(url) {
          log.push(["replace", url]);
        },
      },
    },
    navigator: {
      credentials: {
        create(options) {
          credentialCalls.push(options);
          const spki = new Uint8Array(91).fill(7);
          const authData = new Uint8Array(37);
          authData[36] = 5;
          return Promise.resolve({
            rawId: new Uint8Array(16).fill(1).buffer,
            response: {
              getPublicKey: () => spki.buffer,
              getAuthenticatorData: () => authData.buffer,
            },
          });
        },
      },
    },
    crypto: { getRandomValues: (array) => array.fill(3) },
    btoa,
    console,
    Date: FakeDate,
    setInterval(callback, ms) {
      intervals.push({ callback, ms });
      return intervals.length;
    },
    fetch(url, init) {
      fetches.push({ url, init: init || {} });
      return new Promise(() => {});
    },
  };
  vm.createContext(context);
  return {
    byId,
    stored,
    log,
    fetches,
    intervals,
    clock,
    credentialCalls,
    run(file) {
      vm.runInContext(source(file), context, { filename: file });
    },
    dispatch(type, isTrusted) {
      for (const listener of documentListeners[type] || []) {
        listener({ type, isTrusted });
      }
    },
  };
}

async function settle() {
  for (let i = 0; i < 10; i++) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

test("bootstrap script stores the proof, clears it from the page, then navigates", () => {
  const page = browser({
    islands: { "session-bootstrap-data": { proof: PROOF, storageKey: INBOX_PROOF_KEY, next: "/inbox" } },
    elements: ["bootstrap-status"],
  });
  page.run("./session_bootstrap.js");
  assert.equal(page.stored.get(INBOX_PROOF_KEY), PROOF);
  assert.deepEqual(page.log, [["setItem", INBOX_PROOF_KEY], ["replace", "/inbox"]]);
  assert.equal(page.byId["session-bootstrap-data"].textContent, "");
});

for (const [label, options] of [
  ["throws", { storageThrows: true }],
  ["does not keep the value", { readBackDiffers: true }],
]) {
  test(`bootstrap script does not navigate when storage ${label}`, () => {
    const page = browser({
      islands: { "session-bootstrap-data": { proof: PROOF, storageKey: INBOX_PROOF_KEY, next: "/inbox" } },
      elements: ["bootstrap-status"],
      ...options,
    });
    page.run("./session_bootstrap.js");
    assert.ok(!page.log.some(([kind]) => kind === "replace"));
    assert.match(page.byId["bootstrap-status"].textContent, /did not let the wallet keep its session/);
    assert.equal(page.byId["session-bootstrap-data"].textContent, "");
  });
}

for (const next of ["https://example.invalid/", "//example.invalid", "/approval/x", ""]) {
  test(`bootstrap script refuses the landing path ${JSON.stringify(next)}`, () => {
    const page = browser({
      islands: { "session-bootstrap-data": { proof: PROOF, storageKey: INBOX_PROOF_KEY, next } },
      elements: ["bootstrap-status"],
    });
    page.run("./session_bootstrap.js");
    assert.deepEqual(page.log, []);
  });
}

function detailPage(storage) {
  const page = browser({
    islands: {
      "approval-data": { nonce: "NONCE", csrf: "c".repeat(64), activity_csrf: "d".repeat(64), approvable: true },
    },
    elements: ["approve-btn", "reject-btn", "result"],
    storage,
  });
  page.run("./app_shared.js");
  page.run("./app.js");
  return page;
}

for (const action of ["approve", "reject"]) {
  test(`${action} carries the session proof and the CSRF value`, () => {
    const page = detailPage({ [INBOX_PROOF_KEY]: PROOF });
    page.byId[`${action}-btn`].listeners.click[0]();
    assert.equal(page.fetches.length, 1);
    const { url, init } = page.fetches[0];
    assert.equal(url, `/approval/NONCE/${action}`);
    assert.equal(init.method, "POST");
    assert.equal(init.headers["X-Session-Proof"], PROOF);
    assert.equal(init.headers["X-Stellar-Approval-CSRF"], "c".repeat(64));
  });

  test(`${action} without a stored proof sends nothing and says why`, () => {
    const page = detailPage({});
    page.byId[`${action}-btn`].listeners.click[0]();
    assert.equal(page.fetches.length, 0);
    assert.match(page.byId.result.textContent, /no wallet session/);
    assert.equal(page.byId.result.className, "result refused");
  });
}

test("background polling never sends activity; trusted interaction does, once a minute", () => {
  const page = browser({
    islands: {
      "pending-data": { pending: [], expired_count: 0, include_expired: false, activity_csrf: "d".repeat(64) },
    },
    elements: ["inbox", "status", "empty-state"],
    storage: { [INBOX_PROOF_KEY]: PROOF },
  });
  page.run("./app_shared.js");
  page.run("./app.js");
  assert.equal(page.intervals.length, 1);
  for (let i = 0; i < 600; i++) {
    page.clock.now += 2000;
    page.intervals[0].callback();
  }
  assert.equal(page.fetches.length, 600);
  assert.ok(page.fetches.every(({ url, init }) => url.startsWith("/pending.json") && !init.method));

  page.dispatch("pointerdown", false);
  page.dispatch("keydown", false);
  assert.equal(page.fetches.length, 600, "synthetic events send nothing");

  page.dispatch("pointerdown", true);
  const activity = page.fetches.slice(600);
  assert.equal(activity.length, 1);
  assert.equal(activity[0].url, "/session/activity");
  assert.equal(activity[0].init.method, "POST");
  assert.equal(activity[0].init.keepalive, true);
  assert.equal(activity[0].init.headers["X-Session-Proof"], PROOF);
  assert.equal(activity[0].init.headers["X-Stellar-Approval-CSRF"], "d".repeat(64));

  page.clock.now += 59_999;
  page.dispatch("keydown", true);
  assert.equal(page.fetches.length, 601, "throttled within the minute");
  page.clock.now += 1;
  page.dispatch("wheel", true);
  assert.equal(page.fetches.length, 602);
});

test("the activity throttle spans page loads in the same tab", () => {
  const storage = { [INBOX_PROOF_KEY]: PROOF };
  const first = detailPage(storage);
  first.dispatch("pointerdown", true);
  assert.equal(first.fetches.length, 1);
  const lastSent = first.stored.get("stellar-agent-approval-session-activity-at");
  const second = detailPage({ [INBOX_PROOF_KEY]: PROOF, "stellar-agent-approval-session-activity-at": lastSent });
  second.clock.now = first.clock.now + 30_000;
  second.dispatch("pointerdown", true);
  assert.equal(second.fetches.length, 0);
});

test("a page without a proof sends no activity", () => {
  const page = detailPage({});
  page.dispatch("pointerdown", true);
  assert.equal(page.fetches.length, 0);
});

function enrollPage(storage) {
  const page = browser({
    islands: { "enroll-data": { csrfToken: "e".repeat(64), rpId: "localhost" } },
    elements: ["label-input", "enroll-btn", "status"],
    storage,
  });
  page.byId["label-input"].value = "laptop";
  page.run("../operator_enroll/web/operator-enroll.js");
  return page;
}

test("enrollment posts the credential with the session proof", async () => {
  const page = enrollPage({ [ENROLL_PROOF_KEY]: PROOF });
  page.byId["enroll-btn"].listeners.click[0]();
  await settle();
  assert.equal(page.credentialCalls.length, 1);
  assert.equal(page.fetches.length, 1);
  const { url, init } = page.fetches[0];
  assert.equal(url, "/enroll/credential");
  assert.equal(init.headers["x-session-proof"], PROOF);
  assert.equal(init.headers["x-stellar-approval-csrf"], "e".repeat(64));
});

test("enrollment without a stored proof creates no passkey and sends nothing", async () => {
  const page = enrollPage({ [INBOX_PROOF_KEY]: PROOF });
  page.byId["enroll-btn"].listeners.click[0]();
  await settle();
  assert.equal(page.credentialCalls.length, 0);
  assert.equal(page.fetches.length, 0);
  assert.match(page.byId.status.textContent, /no wallet session/);
});
