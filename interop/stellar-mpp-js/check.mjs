import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { Buffer } from 'node:buffer'

import { Keypair } from '@stellar/stellar-sdk'
import { charge as chargeSchema } from '@stellar/mpp/charge'
import { stellar } from '@stellar/mpp/charge/server'
import { Challenge, Credential, Receipt } from 'mppx'
import { Mppx, Store } from 'mppx/server'

const contract = 'CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA'
const payer = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF'
const recipient = 'GAJZR5RMNUNEK7CRXJVEWXZ5XUXWT7FJGILCDDOITF7EC26RPWJ4UVOE'
const transaction = Buffer.alloc(32).toString('base64')

const challenge = Challenge.from(
  {
    id: 'challenge-interop-1',
    realm: 'merchant.example',
    method: 'stellar',
    intent: 'charge',
    expires: '2026-07-16T12:05:00Z',
    request: {
      amount: '10000000',
      currency: contract,
      methodDetails: {
        network: 'stellar:testnet',
        feePayer: true,
        credentialTypes: ['transaction'],
      },
      recipient,
    },
  },
  { methods: [chargeSchema] },
)
const challengeHeader = Challenge.serialize(challenge)
const authorization = Credential.serialize(
  Credential.from({
    challenge,
    payload: { type: 'transaction', transaction },
    source: `did:pkh:stellar:testnet:${payer}`,
  }),
)
const receipt = Receipt.from({
  method: 'stellar',
  reference: 'a'.repeat(64),
  status: 'success',
  timestamp: '2026-07-16T12:06:00Z',
})
const paymentReceipt = Receipt.serialize(receipt)

const actual = {
  provenance: {
    package: '@stellar/mpp@0.7.1',
    sourceCommit: '9f2f8254421e09906dfb7e983e2491a273120adf',
    stellarSdk: '15.1.0',
    mppx: '0.6.31',
    node: '24.5.0',
    pnpm: '10.33.0',
    license: 'MIT/Apache-2.0 dependency set',
  },
  challenge,
  challengeHeader,
  credential: { authorization, transaction },
  receipt: { paymentReceipt, value: receipt },
}

if (process.argv.includes('--emit')) {
  process.stdout.write(`${JSON.stringify(actual, null, 2)}\n`)
  process.exit(0)
}

const fixture = JSON.parse(
  await readFile(new URL('./fixtures/sponsored-charge.json', import.meta.url), 'utf8'),
)
assert.deepEqual(actual, fixture, 'released SDK output differs from the committed fixture')

const parsedChallenge = Challenge.deserialize(challengeHeader, { methods: [chargeSchema] })
assert.deepEqual(parsedChallenge, challenge)
const parsedCredential = Credential.deserialize(authorization)
assert.deepEqual(parsedCredential.challenge, challenge)
assert.deepEqual(parsedCredential.payload, { type: 'transaction', transaction })
assert.deepEqual(Receipt.deserialize(paymentReceipt), receipt)

const envelopeSigner = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 7))
const serverMethod = stellar.charge({
  currency: contract,
  recipient,
  network: 'stellar:testnet',
  feePayer: { envelopeSigner },
  store: Store.memory(),
})
const server = Mppx.create({
  secretKey: 'stellar-agent-mpp-interop-secret',
  methods: [serverMethod],
})
const gate = server.charge({ amount: '1', description: 'interop' })
const required = await gate(new Request('https://merchant.example/paid'))
assert.equal(required.status, 402)
const issued = Challenge.fromResponse(required.challenge, { methods: [serverMethod] })
assert.equal(issued.method, 'stellar')
assert.equal(issued.intent, 'charge')
assert.equal(issued.request.methodDetails.network, 'stellar:testnet')
assert.equal(issued.request.methodDetails.feePayer, true)
assert.deepEqual(issued.request.methodDetails.credentialTypes, ['transaction'])

const altered = structuredClone(issued)
altered.request.amount = (BigInt(altered.request.amount) + 1n).toString()
const alteredAuthorization = Credential.serialize(
  Credential.from({
    challenge: altered,
    payload: { type: 'transaction', transaction },
    source: `did:pkh:stellar:testnet:${payer}`,
  }),
)
const rejected = await gate(
  new Request('https://merchant.example/paid', {
    headers: { Authorization: alteredAuthorization },
  }),
)
assert.notEqual(rejected.status, 200, 'the released server accepted an altered challenge')

console.log('Stellar MPP released-SDK interoperability checks passed')
