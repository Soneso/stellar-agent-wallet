import http from 'node:http'

import { Keypair } from '@stellar/stellar-sdk'
import { stellar } from '@stellar/mpp/charge/server'
import { Mppx, Store } from 'mppx/server'

const required = (name) => {
  const value = process.env[name]
  if (!value) throw new Error(`missing ${name}`)
  return value
}

const recipient = required('MPP_RECIPIENT')
const currency = required('MPP_CURRENCY')
const rpcUrl = required('MPP_RPC_URL')
const envelopeSigner = Keypair.fromSecret(required('MPP_ENVELOPE_SIGNER_SECRET'))
const method = stellar.charge({
  currency,
  recipient,
  network: 'stellar:testnet',
  rpcUrl,
  feePayer: { envelopeSigner },
  store: Store.memory(),
  pollDelayMs: 1_000,
  pollMaxAttempts: 120,
  pollTimeoutMs: 120_000,
  simulationTimeoutMs: 30_000,
})
const mppx = Mppx.create({
  secretKey: required('MPP_CHALLENGE_SECRET'),
  methods: [method],
})
const gate = mppx.charge({ amount: '0.0001', description: 'wallet acceptance' })

const server = http.createServer(async (request, response) => {
  try {
    const headers = new Headers()
    for (const [name, value] of Object.entries(request.headers)) {
      if (Array.isArray(value)) value.forEach((item) => headers.append(name, item))
      else if (value !== undefined) headers.set(name, value)
    }
    const webRequest = new Request(`http://${request.headers.host}${request.url}`, {
      method: request.method,
      headers,
    })
    const result = await gate(webRequest)
    const webResponse =
      result.status === 402
        ? result.challenge
        : result.withReceipt(Response.json({ accepted: true }))
    response.statusCode = webResponse.status
    webResponse.headers.forEach((value, name) => response.setHeader(name, value))
    response.end(Buffer.from(await webResponse.arrayBuffer()))
  } catch {
    response.statusCode = 500
    response.setHeader('content-type', 'application/json')
    response.end('{"error":"settlement failed"}')
  }
})

server.listen(0, '127.0.0.1', () => {
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('unexpected listen address')
  process.stdout.write(`${JSON.stringify({ port: address.port })}\n`)
})

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)))
}
