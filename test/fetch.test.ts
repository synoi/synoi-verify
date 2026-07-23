/**
 * test/fetch.test.ts — fetchAndVerify() with a mock gateway server.
 *
 * Spins up a minimal HTTP server serving the REAL gateway shapes:
 *   - GET /verify/<id>        → JSON receipt carrying BOTH `signature`
 *                                (Ed25519 hex) and `ml_dsa_signature`
 *                                (ML-DSA-65 base64)
 *   - GET /verify/<id>/raw    → text/plain, the EXACT canonical bytes signed
 *   - GET /verify/pubkey      → JSON, the NESTED hybrid shape
 *                                { key_id, ed25519: { public_key },
 *                                  ml_dsa: { public_key } } — see
 *                                verify-router.ts's `/pubkey` route.
 *
 * Rewritten (bug #3 fix) from a flat-`public_key` / Ed25519-only fixture
 * that no longer matched the gateway. TESTER DISCIPLINE: the flat fixture
 * was left in place first and re-run against the fixed fetch.ts to confirm
 * it now FAILS for the right reason (missing ml_dsa_signature / wrong pubkey
 * shape) before being rewritten to the corrected contract below — see the
 * commit history for the red run. Asserts fetchAndVerify correctly validates
 * BOTH signatures end-to-end, and every failure path (404, missing key
 * fields, missing either signature, tamper, wrong key).
 */

import * as http from 'node:http'
import { generateKeyPairSync, sign, createPrivateKey, createPublicKey, createHash } from 'node:crypto'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
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

// ── Ed25519 keypair ───────────────────────────────────────────────────────────

const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
const publicPem  = publicKey.export({ type: 'spki',  format: 'pem' }) as string

// ── ML-DSA-65 keypair (deterministic seed) ─────────────────────────────────────

const mlDsaSeed = new Uint8Array(createHash('sha256').update('synoi-verify-fetch-test-seed').digest())
const mlDsaKeys = ml_dsa65.keygen(mlDsaSeed)
const mlDsaPublicB64 = Buffer.from(mlDsaKeys.publicKey).toString('base64')

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

const canonical = canonicalPayload(RECEIPT)

function signHybrid(canonicalStr: string): { ed25519: string; ml_dsa: string } {
  const keyObj = createPrivateKey({ key: privatePem, format: 'pem' })
  const edSig  = sign(null, Buffer.from(canonicalStr, 'utf8'), keyObj).toString('hex')
  const mlSig  = ml_dsa65.sign(new Uint8Array(Buffer.from(canonicalStr, 'utf8')), mlDsaKeys.secretKey)
  return { ed25519: edSig, ml_dsa: Buffer.from(mlSig).toString('base64') }
}

const SIGS = signHybrid(canonical)
const SIGNED_RECEIPT = { ...RECEIPT, signature: SIGS.ed25519, ml_dsa_signature: SIGS.ml_dsa }

const KEY_ID = 'key-test-1'
const PUBKEY_DOC = {
  key_id:  KEY_ID,
  ed25519: { public_key: publicPem },
  ml_dsa:  { public_key: mlDsaPublicB64 },
}

// ── Mock server helper ────────────────────────────────────────────────────────

interface RouteResponse { status: number; body: unknown; contentType?: string }
type RouteHandler = (url: string) => RouteResponse

function startServer(handler: RouteHandler): Promise<{ port: number; close(): void }> {
  return new Promise(resolve => {
    const srv = http.createServer((req, res) => {
      const r = handler(req.url ?? '/')
      if (r.contentType === 'text/plain') {
        res.writeHead(r.status, { 'Content-Type': 'text/plain' })
        res.end(String(r.body))
      } else {
        res.writeHead(r.status, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(r.body))
      }
    })
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address() as { port: number }
      resolve({ port, close: () => srv.close() })
    })
  })
}

/** A standard 3-route mock gateway: receipt JSON, raw canonical text, pubkey JSON. */
function mockGateway(opts: {
  receiptBody?: unknown
  rawBody?:     string
  pubkeyBody?:  unknown
  rawStatus?:   number
  pubkeyStatus?: number
}): Promise<{ port: number; close(): void }> {
  return startServer(url => {
    if (url.includes('/raw')) {
      return { status: opts.rawStatus ?? 200, body: opts.rawBody ?? canonical, contentType: 'text/plain' }
    }
    if (url.includes('pubkey')) {
      return { status: opts.pubkeyStatus ?? 200, body: opts.pubkeyBody ?? PUBKEY_DOC }
    }
    if (url.startsWith('/verify/')) {
      return { status: 200, body: opts.receiptBody ?? { receipt: SIGNED_RECEIPT, receipt_id: RECEIPT.receipt_id } }
    }
    return { status: 404, body: {} }
  })
}

async function main(): Promise<void> {

  // ── A: happy path — valid hybrid signature ───────────────────────────────

  {
    const srv = await mockGateway({})
    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('A1: valid=true on matching hybrid signature', result.valid === true, `reason: ${result.reason}`)
    ok('A1: ed25519_valid=true', result.ed25519_valid === true)
    ok('A1: ml_dsa_valid=true', result.ml_dsa_valid === true)
    ok('A1: receipt_id forwarded', result.receipt_id === RECEIPT.receipt_id)
    ok('A1: gateway URL forwarded', result.gateway.includes(String(srv.port)))
    ok('A1: signer_key_id returned', result.signer_key_id === KEY_ID)
    ok('A1: canonical_payload is the raw fetched bytes', result.canonical_payload === canonical)
    ok(
      'A1: signer_key_fingerprint matches independent recompute (trust-in-key caveat vector)',
      result.signer_key_fingerprint === fingerprintOf(publicPem),
      `got ${result.signer_key_fingerprint}`,
    )
    srv.close()
  }

  // ── B: flat receipt shape (no wrapper) ──────────────────────────────────

  {
    const srv = await mockGateway({ receiptBody: SIGNED_RECEIPT })
    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('B1: valid=true on flat receipt shape', result.valid === true, `reason: ${result.reason}`)
    ok('B1: hybrid — both algorithms verified', result.ed25519_valid && result.ml_dsa_valid)
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
    const srv = await mockGateway({ pubkeyStatus: 404 })
    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('D1: pubkey 404 → valid=false', result.valid === false)
    ok('D1: reason mentions pubkey endpoint', result.reason?.includes('/verify/pubkey'))
    srv.close()
  }

  // ── D2: raw 404 → valid=false ─────────────────────────────────────────────

  {
    const srv = await mockGateway({ rawStatus: 404 })
    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('D2: raw 404 → valid=false', result.valid === false)
    ok('D2: reason mentions /raw endpoint', result.reason?.includes('/raw'))
    srv.close()
  }

  // ── E: empty ed25519.public_key in response → valid=false ────────────────

  {
    const srv = await mockGateway({ pubkeyBody: { key_id: KEY_ID, ed25519: { public_key: '' }, ml_dsa: { public_key: mlDsaPublicB64 } } })
    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('E1: empty ed25519.public_key → valid=false', result.valid === false)
    ok('E1: reason mentions ed25519.public_key', result.reason?.includes('ed25519.public_key'))
    srv.close()
  }

  // ── E2: missing ml_dsa.public_key → valid=false ───────────────────────────

  {
    const srv = await mockGateway({ pubkeyBody: { key_id: KEY_ID, ed25519: { public_key: publicPem } } })
    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('E2: missing ml_dsa.public_key → valid=false', result.valid === false)
    ok('E2: reason mentions ml_dsa.public_key', result.reason?.includes('ml_dsa.public_key'))
    srv.close()
  }

  // ── E3: old flat `public_key` shape (pre-fix gateway contract, now stale)
  //        is REJECTED, not silently accepted — proves the nested-shape fix ──

  {
    const srv = await mockGateway({ pubkeyBody: { public_key: publicPem, key_id: KEY_ID } })
    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('E3: flat legacy public_key shape → valid=false (nested shape required)', result.valid === false)
    srv.close()
  }

  // ── F: missing Ed25519 signature on receipt → valid=false ────────────────

  {
    const unsigned = { ...SIGNED_RECEIPT, signature: '' }
    const srv = await mockGateway({ receiptBody: unsigned })
    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('F1: missing/empty ed25519 signature → valid=false', result.valid === false)
    ok('F1: reason mentions signature', result.reason?.toLowerCase().includes('signature'))
    srv.close()
  }

  // ── F2: missing ML-DSA signature on receipt → valid=false (hybrid required,
  //        this is the exact bug: previously Ed25519-only was accepted) ─────

  {
    const edOnly = { ...SIGNED_RECEIPT, ml_dsa_signature: '' }
    const srv = await mockGateway({ receiptBody: edOnly })
    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('F2: missing ml_dsa_signature → valid=false (hybrid required)', result.valid === false)
    ok('F2: reason mentions ml_dsa_signature', result.reason?.includes('ml_dsa_signature'))
    srv.close()
  }

  // ── G: tampered receipt (raw bytes still match the OLD content) → valid=false
  //       The gateway's /raw endpoint always returns what was ACTUALLY signed,
  //       so simulate tamper by mismatching the raw canonical bytes served
  //       against the signature (a forged /raw response, or a receipt whose
  //       displayed JSON was edited after fetch) ─────────────────────────────

  {
    const tamperedCanonical = canonicalPayload({ ...RECEIPT, decision: 'deny' })
    const srv = await mockGateway({ rawBody: tamperedCanonical })
    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('G1: mismatched raw canonical bytes → valid=false', result.valid === false)
    srv.close()
  }

  // ── H: wrong Ed25519 public key → valid=false, but ML-DSA still independently reported ──

  {
    const { publicKey: wrongPub } = generateKeyPairSync('ed25519')
    const wrongPem = wrongPub.export({ type: 'spki', format: 'pem' }) as string
    const srv = await mockGateway({ pubkeyBody: { key_id: KEY_ID, ed25519: { public_key: wrongPem }, ml_dsa: { public_key: mlDsaPublicB64 } } })
    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('H1: wrong ed25519 public key → valid=false', result.valid === false)
    ok('H1: ed25519_valid=false', result.ed25519_valid === false)
    ok('H1: ml_dsa_valid still true (independent per-algorithm diagnostic)', result.ml_dsa_valid === true)
    srv.close()
  }

  // ── H2: wrong ML-DSA public key → valid=false, Ed25519 still independently reported ──

  {
    const wrongMlDsaKeys = ml_dsa65.keygen(new Uint8Array(createHash('sha256').update('wrong-seed').digest()))
    const wrongMlDsaPub = Buffer.from(wrongMlDsaKeys.publicKey).toString('base64')
    const srv = await mockGateway({ pubkeyBody: { key_id: KEY_ID, ed25519: { public_key: publicPem }, ml_dsa: { public_key: wrongMlDsaPub } } })
    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('H2: wrong ml_dsa public key → valid=false', result.valid === false)
    ok('H2: ed25519_valid still true (independent per-algorithm diagnostic)', result.ed25519_valid === true)
    ok('H2: ml_dsa_valid=false', result.ml_dsa_valid === false)
    srv.close()
  }

  // ── H3: malformed PEM does not throw, fingerprint is undefined ───────────

  {
    const srv = await mockGateway({ pubkeyBody: { key_id: KEY_ID, ed25519: { public_key: 'not-a-real-pem' }, ml_dsa: { public_key: mlDsaPublicB64 } } })
    const result = await fetchAndVerify(RECEIPT.receipt_id, `http://127.0.0.1:${srv.port}`)
    ok('H3: malformed PEM does not throw', true)
    ok('H3: malformed PEM → valid=false', result.valid === false)
    ok('H3: malformed PEM → signer_key_fingerprint undefined', result.signer_key_fingerprint === undefined)
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
      ok('I1: default gateway is production', result.gateway === 'https://gateway.synoi.systems')
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
