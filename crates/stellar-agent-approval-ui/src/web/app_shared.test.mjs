import { test } from "node:test";
import assert from "node:assert/strict";
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
    assert.equal(renderers.metaText(view), `limit ${rendered} for ${holder}`);
  });
}
