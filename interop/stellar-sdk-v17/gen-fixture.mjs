// Writes the SDK-built preimage fixtures to fixtures/. Run with the pinned
// SDK after a deliberate SDK pin change; check.mjs fails until they match.
import { writeFileSync } from "node:fs";
import { buildFixtures, fixtureText } from "./build-fixtures.mjs";

for (const { file, fixture } of buildFixtures()) {
  writeFileSync(new URL(`./fixtures/${file}`, import.meta.url), fixtureText(fixture));
  console.log(`wrote fixtures/${file} payloadHex=${fixture.payloadHex}`);
}
