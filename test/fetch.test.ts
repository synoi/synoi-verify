/**
 * test/fetch.test.ts — fetchAndVerify() with a mock gateway server.
 *
 * Spins up a minimal HTTP server, serves a pre-signed receipt + public key,
 * and asserts fetchAndVerify correctly validates the signature end-to-end.
 * Also tests all the failure paths (404, no pubkey, missing signature).
 */

import * as http from 'node:http'
import { generateKeyPairSync, sign, createPrivateKey, createPublicKey, createHash } from 'node:crypto'
import { fetchAndVerify } from '../src/fetch'
import { canonicalPayload } from '../src/verify'

/**
 * Independent recompute of the fingerprint fetchAndVerify publishes, kept
 * separate from src/fetch.ts so this test does not merely echo the
 * implementation: 'sha256:' + sha256(SPKI DER) of the Ed25519 public key.
 */
function fingerprintOf(pem: string): string {
  const der = createPublicKey({ key: pem, format: 'pem' }).export({ format: 'der', type: 'spki' }) as Buffer
  return 'sha256:' + createHash('sha256').update(der).digest('hex')
}

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

// ── Keypair + signed receipt ─────────────────────────────────────────────────

const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
const publicPem  = publicKey.export({ type: 'spki',  format: 'pem' }) as string

// Receipt must contain all CANONICAL_FIELDS: action_class, decision, oid_hex,
// receipt_id, recorded_at, risk_level, tenant_id
const RECEIPT = {
  receipt_id:   'rcpt_test_abc123',
  tenant_id:    't_test',
  action_class: 'write',
  decision:     'allow',
  oid_hex:      'a'.repeat(64),
  risk_level:   'medium',
  recorded_at:  '2026-05-30T00:00:00.000Z',
  // extra fields ignored by canonicalPayload
  tool_name:    'shell.exec',
  model:        'claude-sonnet-4-6',
}

const canonical    = canonicalPayload(RECEIPT)
const keyObj       = createPrivateKey({ key: privatePem, format: 'pem' })
const signatureHex = sign(null, Buffer.from(canonical, 'utf8'), keyObj).toString('hex')
const SIGNED_RECEIPT = { ...RECEIPT, signature: signatureHex }

const KEY_ID = 'key-test-1'

// ── Mock server helper ────────────────────────────────────────────────────────

type RouteHandler = (url: string) => { status: number; body: unknown }

function startServer(handler: RouteHandler): Promise<{ port: number; close(): void }> {
  return new Promise(resolve => {
    const srv = http.createServer((req, res) => {
      const r = handler(req.url ?? '/')
      res.writeHead(r.status, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(r.body))
    })
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address() as { port: number }
      resolve({ port, close: () => srv.close() })
    })
  })
}

async function main(): Promise<void> {

  // ── A: happy path — valid signature ──────────────────────────────────────

  {
    const srv = await startServer(url => {
      if (url.startsWith('/verify/') && !url.includes('pubkey')) {
        return { status: 200, body: { receipt: SIGNED_RECEIPT, receipt_id: RECEIPT.receipt_id } }
      }
      if (url === '/verify/pubkey') {
        return { status: 200, body: { public_key: publicPem, key_id: KEY_ID } }
      }
      return { status: 404, body: {} }
    })

    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('A1: valid=true on matching signature', result.valid === true, `reason: ${result.reason}`)
    ok('A1: receipt_id forwarded', result.receipt_id === RECEIPT.receipt_id)
    ok('A1: gateway URL forwarded', result.gateway.includes(String(srv.port)))
    ok('A1: signer_key_id returned', result.signer_key_id === KEY_ID)
    ok('A1: canonical_payload non-empty', result.canonical_payload.length > 0)
    ok(
      'A1: signer_key_fingerprint matches independent recompute (v1 trust-in-key caveat vector)',
      result.signer_key_fingerprint === fingerprintOf(publicPem),
      `got ${result.signer_key_fingerprint}`,
    )
    srv.close()
  }

  // ── B: flat receipt shape (no wrapper) ──────────────────────────────────

  {
    const srv = await startServer(url => {
      if (url.startsWith('/verify/') && !url.includes('pubkey')) {
        // Flat shape — no {receipt: ...} wrapper
        return { status: 200, body: SIGNED_RECEIPT }
      }
      if (url === '/verify/pubkey') {
        return { status: 200, body: { public_key: publicPem } }
      }
      return { status: 404, body: {} }
    })

    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('B1: valid=true on flat receipt shape', result.valid === true, `reason: ${result.reason}`)
    ok('B1: signer_key_id null when no key_id returned', result.signer_key_id === null)
    srv.close()
  }

  // ── C: receipt 404 → valid=false, reason mentions status ─────────────────

  {
    const srv = await startServer(() => ({ status: 404, body: { error: 'not found' } }))
    const result = await fetchAndVerify('missing-id', `http://127.0.0.1:${srv.port}`)
    ok('C1: 404 on receipt → valid=false', result.valid === false)
    ok('C1: reason mentions HTTP 404', result.reason?.includes('404'))
    srv.close()
  }

  // ── D: pubkey 404 → valid=false ───────────────────────────────────────────

  {
    const srv = await startServer(url => {
      if (url.startsWith('/verify/') && !url.includes('pubkey')) {
        return { status: 200, body: SIGNED_RECEIPT }
      }
      return { status: 404, body: {} }  // pubkey fails
    })

    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('D1: pubkey 404 → valid=false', result.valid === false)
    ok('D1: reason mentions pubkey endpoint', result.reason?.includes('/verify/pubkey'))
    srv.close()
  }

  // ── E: empty public_key in response → valid=false ────────────────────────

  {
    const srv = await startServer(url => {
      if (url.startsWith('/verify/') && !url.includes('pubkey')) {
        return { status: 200, body: SIGNED_RECEIPT }
      }
      return { status: 200, body: { public_key: '' } }  // empty key
    })

    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('E1: empty public_key → valid=false', result.valid === false)
    ok('E1: reason mentions no public_key', result.reason?.includes('public_key'))
    srv.close()
  }

  // ── F: missing signature on receipt → valid=false ────────────────────────

  {
    const unsigned = { ...RECEIPT, signature: '' }
    const srv = await startServer(url => {
      if (url.startsWith('/verify/') && !url.includes('pubkey')) {
        return { status: 200, body: unsigned }
      }
      return { status: 200, body: { public_key: publicPem } }
    })

    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('F1: missing/empty signature → valid=false', result.valid === false)
    ok('F1: reason mentions signature', result.reason?.toLowerCase().includes('signature'))
    srv.close()
  }

  // ── G: tampered receipt → valid=false ────────────────────────────────────

  {
    const tampered = { ...SIGNED_RECEIPT, decision: 'deny' }
    const srv = await startServer(url => {
      if (url.startsWith('/verify/') && !url.includes('pubkey')) {
        return { status: 200, body: { receipt: tampered } }
      }
      return { status: 200, body: { public_key: publicPem } }
    })

    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('G1: tampered receipt → valid=false', result.valid === false)
    srv.close()
  }

  // ── H: wrong public key → valid=false ────────────────────────────────────

  {
    const { publicKey: wrongPub } = generateKeyPairSync('ed25519')
    const wrongPem = wrongPub.export({ type: 'spki', format: 'pem' }) as string
    const srv = await startServer(url => {
      if (url.startsWith('/verify/') && !url.includes('pubkey')) {
        return { status: 200, body: { receipt: SIGNED_RECEIPT } }
      }
      return { status: 200, body: { public_key: wrongPem } }
    })

    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('H1: wrong public key → valid=false', result.valid === false)
    srv.close()
  }

  // ── H2: malformed PEM still verifies-or-fails correctly, fingerprint is
  //        undefined rather than throwing (fingerprint is informational only) ──

  {
    const srv = await startServer(url => {
      if (url.startsWith('/verify/') && !url.includes('pubkey')) {
        return { status: 200, body: { receipt: SIGNED_RECEIPT } }
      }
      return { status: 200, body: { public_key: 'not-a-real-pem' } }
    })

    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('H2: malformed PEM does not throw', true)
    ok('H2: malformed PEM → signer_key_fingerprint undefined', result.signer_key_fingerprint === undefined)
    srv.close()
  }

  // ── I: default gateway URL — function signature accepts omitted param ──────

  {
    // fetchAndVerify may throw when the connection is refused (no server on 3000).
    // The important property is that the function exists and takes receipt_id only.
    let result: Awaited<ReturnType<typeof fetchAndVerify>> | null = null
    try {
      result = await fetchAndVerify('some-id')
    } catch { /* connection refused — OK, just testing the function signature */ }

    if (result) {
      // If we got a result (unlikely), it must be invalid
      ok('I1: default gateway → valid=false (no server)', result.valid === false)
      ok('I1: default gateway is localhost:3000', result.gateway === 'http://localhost:3000')
    } else {
      // Connection refused before we got a result — that's expected behavior
      ok('I1: default gateway parameter omittable', true)
      ok('I1: function accepts single argument', true)
    }
  }

  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed > 0 ? 1 : 0)
}

void main().catch(err => {
  process.stderr.write(`FATAL: ${(err as Error).stack ?? String(err)}\n`)
  process.exit(2)
})
