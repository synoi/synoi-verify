/**
 * test/browser-v2.test.ts - @synoi/verify/browser verifies a REAL v2 receipt.
 *
 * WHY THIS EXISTS. Every receipt the gateway mints carries
 * `receipt_scheme: 'synoi.receipt/v2'` (synoi-gateway/src/gap/engine.ts:1998 and
 * :2821, both signed by signGapReceiptV2). Until this test, the browser entry
 * routed that scheme to a fail-closed stub with reason
 * `v2-not-supported-in-browser-build`, so the published browser build could not
 * verify a single real gateway receipt. "Verify it yourself, offline, with no
 * account" was therefore false wherever it was claimed against a browser build.
 *
 * WHAT UNBLOCKED IT. @synoi/sraid 0.3.0 adds the `./verify-browser` subpath: the
 * same hybrid DSSE verify (Ed25519 AND ML-DSA-65, both required over the PAE)
 * and the same content-core projection as the node entry, with no static
 * node:crypto anywhere in its graph. src/verify-v2-browser.ts is the thin
 * adapter over it; src/browser.ts injects it into the dispatcher factory.
 *
 * THREE THINGS ARE ASSERTED, and the third is the one that can regress silently:
 *
 *   A. FUNCTIONAL. A genuinely hybrid-signed v2 receipt verifies VALID through
 *      both verifyReceiptV2Browser directly and the browser dispatcher.
 *   B. FAIL-CLOSED. Tamper the body, strip ml-dsa-65, corrupt either signature,
 *      transplant the envelope: every one must be REJECTED. A verifier that
 *      accepts on Ed25519 alone reopens the sign-PQ vs verify-PQ asymmetry K1
 *      closed, so the stripped-ML-DSA case is the load-bearing one.
 *   C. STILL BROWSER-SAFE. Bundle the browser entry for platform:'browser' with
 *      the v2 path now in the graph and assert ZERO `node:` references. Pulling
 *      sraid's node-bound default entry in by accident is exactly the mistake
 *      this subpath exists to prevent, and it would not show up in A or B
 *      because those run under Node.
 *
 * PARITY. The node path is verified over the same bytes and must agree
 * outcome-for-outcome. A browser verifier that disagrees with the node verifier
 * about the same receipt is worse than no browser verifier.
 *
 * CLAIMS DISCIPLINE: no vector, no claim. This is that vector. NO em dashes.
 *
 *   npx tsx test/browser-v2.test.ts
 */

import { generateKeyPairSync, sign } from 'node:crypto'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { canonicalize, cdroContentCore, pae } from '@synoi/sraid'
import { build } from 'esbuild'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import * as browser from '../src/browser'
import { verifyReceiptV2 as verifyReceiptV2Node } from '../src/verify'

const HERE = dirname(fileURLToPath(import.meta.url))
const SRC = join(HERE, '..', 'src')

let passed = 0
let failed = 0

function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

// ── Keys (same construction as test/verify-v2.test.ts) ───────────────────────

const { privateKey: edPriv, publicKey: edPubKey } = generateKeyPairSync('ed25519')
const edSpki = edPubKey.export({ type: 'spki', format: 'der' }) as Buffer
const ed25519_pub = new Uint8Array(edSpki.subarray(edSpki.length - 32))

const mlKeys = ml_dsa65.keygen(new Uint8Array(32).fill(7))
const ml_dsa_pub = mlKeys.publicKey

interface Envelope {
  payloadType: string
  payload: string
  signatures: { alg: string; sig: string }[]
}

/**
 * A v2 receipt shaped like the ones the gateway emits: a CDRO envelope carrying
 * the receipt_scheme discriminator, signed as a detached DSSE attestation over
 * PAE(payloadType, canonicalize(content_core)).
 */
function buildReceipt(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type:           'synoi:decision_receipt',
    cof_version:    '1.0',
    tenant_id:      'founder',
    created_at_ms:  1747584000000,
    created_by:     'sha256:' + 'a'.repeat(64),
    receipt_scheme: browser.RECEIPT_SCHEME_V2,
    body: {
      decision:     'allow',
      action_class: 'B',
      risk_level:   'low',
    },
    ...overrides,
  }
}

function mintEnvelope(receipt: Record<string, unknown>): Envelope {
  const payload = canonicalize(cdroContentCore(receipt))
  const message = pae(browser.V2_PAYLOAD_TYPE, payload)
  const edSig = sign(null, Buffer.from(message), edPriv)
  const mlSig = ml_dsa65.sign(message, mlKeys.secretKey)
  return {
    payloadType: browser.V2_PAYLOAD_TYPE,
    payload,
    signatures: [
      { alg: 'ed25519',   sig: Buffer.from(edSig).toString('base64') },
      { alg: 'ml-dsa-65', sig: Buffer.from(mlSig).toString('base64') },
    ],
  }
}

/** Mint a receipt and attach its own valid attestation. */
function signedReceipt(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const r = buildReceipt(overrides)
  r.attestation = mintEnvelope(r)
  return r
}

/** Flip one byte in a base64 signature so it decodes but does not verify. */
function corrupt(sigB64: string): string {
  const bytes = Buffer.from(sigB64, 'base64')
  bytes[0] = bytes[0]! ^ 0xff
  return bytes.toString('base64')
}

async function bundleForBrowser(entry: string): Promise<{ errors: number; text: string; messages: string }> {
  try {
    const result = await build({
      entryPoints: [join(SRC, entry)],
      bundle:      true,
      write:       false,
      format:      'iife',
      platform:    'browser',
      logLevel:    'silent',
    })
    return { errors: 0, text: result.outputFiles.map((f) => f.text).join('\n'), messages: '' }
  } catch (err) {
    const e = err as { errors?: Array<{ text: string }> }
    return { errors: (e.errors ?? []).length || 1, text: '', messages: (e.errors ?? []).map((m) => m.text).join(' | ') }
  }
}

async function main(): Promise<void> {
  // ── A. FUNCTIONAL ──────────────────────────────────────────────────────────

  ok('browser entry exports verifyReceiptV2Browser',
     typeof browser.verifyReceiptV2Browser === 'function')

  {
    const receipt = signedReceipt()
    const res = await browser.verifyReceiptV2Browser({ receipt, ed25519_pub, ml_dsa_pub })
    ok('browser v2: valid hybrid receipt verifies VALID', res.valid, res.reasons.join(','))
    ok('browser v2: algorithm reported as hybrid DSSE',
       res.algorithm === 'DSSE(ed25519+ml-dsa-65)', res.algorithm)
    ok('browser v2: payload_type pinned', res.payload_type === browser.V2_PAYLOAD_TYPE)

    const disp = await browser.verifyReceiptByScheme({ receipt, ed25519_pub, ml_dsa_pub })
    ok('browser v2: dispatcher routes the v2 scheme and verifies VALID',
       disp.valid && disp.scheme === 'v2', disp.reasons.join(','))
    ok('browser v2: dispatcher no longer returns v2-not-supported-in-browser-build',
       !disp.reasons.includes('v2-not-supported-in-browser-build'))

    // PARITY: the node verifier must agree on the same bytes.
    const nodeRes = await verifyReceiptV2Node({ receipt, ed25519_pub, ml_dsa_pub })
    ok('parity: node and browser agree VALID on the same receipt',
       nodeRes.valid === res.valid && nodeRes.canonical_payload === res.canonical_payload)
  }

  // ── B. FAIL-CLOSED ─────────────────────────────────────────────────────────

  {
    // Tampered body: the envelope is validly signed, but over different bytes.
    const receipt = signedReceipt()
    ;(receipt.body as Record<string, unknown>).decision = 'deny'
    const res = await browser.verifyReceiptV2Browser({ receipt, ed25519_pub, ml_dsa_pub })
    ok('browser v2: tampered body REJECTED (payload-core-mismatch)',
       !res.valid && res.reasons.includes('payload-core-mismatch'), res.reasons.join(','))

    const nodeRes = await verifyReceiptV2Node({ receipt, ed25519_pub, ml_dsa_pub })
    ok('parity: node also rejects the tampered body with the same reason',
       nodeRes.valid === false && nodeRes.reasons.join(',') === res.reasons.join(','))
  }

  {
    // THE LOAD-BEARING CASE. ml-dsa-65 stripped: accepting this on the Ed25519
    // signature alone reopens the exact PQ asymmetry K1 closed.
    const receipt = buildReceipt()
    const env = mintEnvelope(receipt)
    env.signatures = env.signatures.filter((s) => s.alg !== 'ml-dsa-65')
    receipt.attestation = env
    const res = await browser.verifyReceiptV2Browser({ receipt, ed25519_pub, ml_dsa_pub })
    ok('browser v2: ml-dsa-65 STRIPPED REJECTED (not accepted on ed25519 alone)',
       !res.valid && res.reasons.includes('missing-ml-dsa-65'), res.reasons.join(','))
  }

  {
    const receipt = buildReceipt()
    const env = mintEnvelope(receipt)
    const ml = env.signatures.find((s) => s.alg === 'ml-dsa-65')!
    ml.sig = corrupt(ml.sig)
    receipt.attestation = env
    const res = await browser.verifyReceiptV2Browser({ receipt, ed25519_pub, ml_dsa_pub })
    ok('browser v2: corrupted ml-dsa-65 signature REJECTED',
       !res.valid && res.reasons.includes('ml-dsa-invalid'), res.reasons.join(','))
  }

  {
    const receipt = buildReceipt()
    const env = mintEnvelope(receipt)
    const ed = env.signatures.find((s) => s.alg === 'ed25519')!
    ed.sig = corrupt(ed.sig)
    receipt.attestation = env
    const res = await browser.verifyReceiptV2Browser({ receipt, ed25519_pub, ml_dsa_pub })
    ok('browser v2: corrupted ed25519 signature REJECTED',
       !res.valid && res.reasons.includes('ed25519-invalid'), res.reasons.join(','))
  }

  {
    // Transplant: a validly-signed envelope moved onto a different receipt body.
    // The content-core bind is the only thing that catches this.
    const donor  = signedReceipt()
    const target = buildReceipt({ tenant_id: 'other-tenant' })
    target.attestation = donor.attestation
    const res = await browser.verifyReceiptV2Browser({ receipt: target, ed25519_pub, ml_dsa_pub })
    ok('browser v2: transplanted envelope REJECTED (content-core bind holds)',
       !res.valid && res.reasons.includes('payload-core-mismatch'), res.reasons.join(','))
  }

  {
    const receipt = buildReceipt() // no attestation attached at all
    const res = await browser.verifyReceiptV2Browser({ receipt, ed25519_pub, ml_dsa_pub })
    ok('browser v2: missing attestation REJECTED',
       !res.valid && res.reasons.includes('missing-attestation'), res.reasons.join(','))
  }

  {
    // Wrong key: verification must fail, not silently pass on a shape check.
    const receipt = signedReceipt()
    const res = await browser.verifyReceiptV2Browser({
      receipt,
      ed25519_pub: new Uint8Array(32).fill(9),
      ml_dsa_pub,
    })
    ok('browser v2: wrong ed25519 public key REJECTED', !res.valid, res.reasons.join(','))
  }

  {
    // The dispatcher still requires both keys before it will run the v2 path.
    const receipt = signedReceipt()
    const res = await browser.verifyReceiptByScheme({ receipt, ed25519_pub })
    ok('browser v2: dispatcher rejects a v2 receipt with only one key supplied',
       !res.valid && res.reasons.includes('v2-scheme-requires-both-public-keys'),
       res.reasons.join(','))
  }

  // ── C. STILL BROWSER-SAFE (the one that can regress silently) ──────────────

  const browserBundle = await bundleForBrowser('browser.ts')
  ok('browser entry STILL bundles for platform:browser with ZERO errors',
     browserBundle.errors === 0, browserBundle.messages)

  const nodeRefs = (browserBundle.text.match(/node:[a-z_/]+/g) ?? [])
  ok('browser bundle STILL contains ZERO node: builtin references, with v2 in the graph',
     nodeRefs.length === 0, `found ${nodeRefs.length}: ${[...new Set(nodeRefs)].join(', ')}`)

  // The v2 path must actually be IN the bundle, not tree-shaken away, or the
  // scan above passes vacuously.
  ok('browser bundle actually contains the v2 verify path (scan is not vacuous)',
     browserBundle.text.includes('payload-core-mismatch'))

  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed > 0 ? 1 : 0)
}

main().catch((err) => {
  process.stdout.write(`FATAL ${(err as Error).stack ?? String(err)}\n`)
  process.exit(1)
})
