- The acceptance runner gives the two approval browser suites a test certificate authority that only their Chromium trusts.
  Before each attempt it generates the authority and a leaf, installs the authority into fresh NSS databases below `target/tmp`, and fails the suite before cargo when setup fails.
  Each suite carries trust controls: a page served with a leaf the authority issued loads, and a signed listener with another authority's leaf never loads.
  The consent control stores nothing, and the enrollment control stages no registration.
  The operator-enroll suite enrolls a credential at the signed origin in Chromium and exports it only after the terminal confirmation of the displayed code.
  The consent suite consents at the signed origin through the approval link, and checks that an assertion from another origin, a page of another RP, and the local inbox under the signed policy cannot consent.
  The browser keeps certificate errors fatal; no host trust store or keychain changes, and the HTTPS cases run on Linux only.
  The testnet workflow installs `libnss3-tools` for `certutil`.
  `stellar-agent-approval-remote` gains a default-off `mainnet-write` feature that forwards to the core, network and MCP crates, so `MAINNET_WRITE=on` reaches its suites.
