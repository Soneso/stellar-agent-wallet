import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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
