// Asserts the checked-in preimage fixtures equal what the pinned SDK builds
// today, and that each preimage decodes to the envelope type its credential
// arm selects.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { xdr } from "@stellar/stellar-sdk";
import { buildFixtures, fixtureText } from "./build-fixtures.mjs";

const EXPECTED_PREIMAGE_TYPE = {
  9: "envelopeTypeSorobanAuthorization",
  10: "envelopeTypeSorobanAuthorizationWithAddress",
};

const fixtures = buildFixtures();
assert.equal(fixtures.length, 2, "one fixture per credential version");
for (const { file, fixture } of fixtures) {
  const checkedIn = readFileSync(new URL(`./fixtures/${file}`, import.meta.url), "utf8");
  assert.equal(checkedIn, fixtureText(fixture), `fixtures/${file} differs from the pinned SDK output`);
  const preimage = xdr.HashIdPreimage.fromXdr(fixture.preimageXdr, "base64");
  assert.equal(preimage.type, EXPECTED_PREIMAGE_TYPE[fixture.envelopeType], file);
}
assert.notEqual(fixtures[0].fixture.payloadHex, fixtures[1].fixture.payloadHex);

console.log("stellar-sdk v17 preimage fixtures match");
