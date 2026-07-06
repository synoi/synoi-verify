/**
 * test/verify-by-scheme.test.ts — the fail-closed receipt_scheme dispatcher
 * (ADR_019 STEP 5 / finding 8).
 *
 * PROVES the ONE dispatcher (verifyReceiptByScheme) routes by the receipt's
 * `receipt_scheme` discriminator and is FAIL-CLOSED by the LOCKED founder
 * decision (allowLegacyV1 DEFAULTS TO FALSE; K2 enforcement now):
 *
 *   1. receipt_scheme='synoi.receipt/v2'  -> routes to the v2 hybrid DSSE path
 *      and verifies VALID for a correctly hybrid-signed receipt (scheme 'v2').
 *   2. receipt_scheme ABSENT, default opts (allowLegacyV1 unset=false)
 *      -> FAIL-CLOSED (scheme 'rejected'), NOT silently verified as v1.
 *   3. receipt_scheme = an UNKNOWN value -> FAIL-CLOSED (scheme 'rejected').
 *   4. receipt_scheme ABSENT with EXPLICIT allowLegacyV1:true + v1 key material
 *      -> routes to the v1 Ed25519-only path and verifies VALID (scheme 'v1').
 *
 * The v2 minting mirrors verify-v2.test.ts (Ed25519 via node:crypto, ML-DSA-65
 * via @noble/post-quantum, hybrid DSSE over PAE(payloadType, canonicalize(core))).
 * The v1 minting mirrors verify.test.ts (Ed25519 over canonicalPayload).
 *
 * CLAIMS DISCIPLINE: no vector, no claim. This is that vector. NO em dashes.
 *
 *   yarn test
 */

import { generateKeyPairSync, sign, createPrivateKey } from 'node:crypto'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { canonicalize, cdroContentCore, pae } from '@synoi/sraid'
import {
  verifyReceiptByScheme,
  canonicalPayload,
  V2_PAYLOAD_TYPE,
  RECEIPT_SCHEME_V2,
} from '../src/verify'

let passed = 0
let failed = 0

function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

// ── v2 keys ──────────────────────────────────────────────────────────────────
const { privateKey: edPriv, publicKey: edPubKey } = generateKeyPairSync('ed25519')
const edSpki = edPubKey.export({ type: 'spki', format: 'der' }) as Buffer
const ed25519_pub = new Uint8Array(edSpki.subarray(edSpki.length - 32))

const mlSeed = new Uint8Array(32).fill(7)
const mlKeys = ml_dsa65.keygen(mlSeed)
const ml_dsa_pub = mlKeys.publicKey

// ── v1 keys (Ed25519, PEM shape) ─────────────────────────────────────────────
const { privateKey: v1Priv, publicKey: v1Pub } = generateKeyPairSync('ed25519')
const v1PrivPem = v1Priv.export({ type: 'pkcs8', format: 'pem' }) as string
const v1PubPem  = v1Pub.export({ type: 'spki',  format: 'pem' }) as string

// ── Build a v2 receipt + hybrid DSSE envelope ────────────────────────────────
function buildV2Receipt(): Record<string, unknown> {
  return {
    type:           'synoi:decision_receipt',
    cof_version:    '1.0',
    tenant_id:      'founder',
    created_at_ms:  1747584000000,
    created_by:     'sha256:' + 'a'.repeat(64),
    receipt_scheme: RECEIPT_SCHEME_V2,
    body: {
      decision:     'allow',
      action_class: 'B',
      risk_level:   'low',
      settlement:   { cost: { amount: 1200, currency: 'usd' } },
    },
  }
}

function mintV2Envelope(receipt: Record<string, unknown>) {
  const payload = canonicalize(cdroContentCore(receipt))
  const message = pae(V2_PAYLOAD_TYPE, payload)
  const edSig = sign(null, Buffer.from(message), edPriv)
  const mlSig = ml_dsa65.sign(message, mlKeys.secretKey)
  return {
    payloadType: V2_PAYLOAD_TYPE,
    payload,
    signatures: [
      { alg: 'ed25519',   sig: Buffer.from(edSig).toString('base64') },
      { alg: 'ml-dsa-65', sig: Buffer.from(mlSig).toString('base64') },
    ],
  }
}

// ── Build a v1 receipt (flat canonical fields, no receipt_scheme) ────────────
function buildV1Receipt(): Record<string, unknown> {
  return {
    receipt_id:   'rcpt_by_scheme_v1',
    tenant_id:    'founder',
    decision:     'allow',
    action_class: 'B',
    risk_level:   'low',
    oid_hex:      '0123456789abcdef'.repeat(4),
    recorded_at:  1747584000000,
    // deliberately NO receipt_scheme field
  }
}

async function main(): Promise<void> {
  // ── 1: v2 scheme routes to the hybrid path and verifies VALID ──────────────
  {
    const receipt = buildV2Receipt()
    receipt.attestation = mintV2Envelope(receipt)
    const res = await verifyReceiptByScheme({ receipt, ed25519_pub, ml_dsa_pub })
    ok('1. v2 scheme routes to v2 verifier', res.scheme === 'v2', JSON.stringify(res.reasons))
    ok('1. v2 valid hybrid receipt verifies TRUE', res.valid, res.reasons.join(','))
  }

  // ── 1b: v2 scheme but a STRIPPED ml-dsa signature -> still routes v2, REJECT
  {
    const receipt = buildV2Receipt()
    const env = mintV2Envelope(receipt)
    env.signatures = env.signatures.filter(s => s.alg !== 'ml-dsa-65')
    receipt.attestation = env
    const res = await verifyReceiptByScheme({ receipt, ed25519_pub, ml_dsa_pub })
    ok('1b. v2 scheme with ml-dsa stripped -> routed v2 AND rejected (no ed25519-only fallthrough)',
       res.scheme === 'v2' && !res.valid && res.reasons.includes('missing-ml-dsa-65'),
       JSON.stringify(res.reasons))
  }

  // ── 2: MISSING scheme, DEFAULT opts (allowLegacyV1 unset=false) -> FAIL-CLOSED
  {
    const receipt = buildV1Receipt()
    // Even supplying v2 keys must NOT rescue a scheme-less receipt under default.
    const res = await verifyReceiptByScheme({ receipt, ed25519_pub, ml_dsa_pub })
    ok('2. missing scheme + default (allowLegacyV1 false) -> fail-closed (rejected)',
       res.scheme === 'rejected' && !res.valid, JSON.stringify(res))
    ok('2. fail-closed reason names the missing scheme + disallowed legacy',
       res.reasons.includes('missing-receipt-scheme-and-legacy-v1-not-allowed'),
       res.reasons.join(','))
  }

  // ── 3: UNKNOWN scheme value -> FAIL-CLOSED ─────────────────────────────────
  {
    const receipt = buildV2Receipt()
    receipt.receipt_scheme = 'synoi.receipt/v99-attacker'
    receipt.attestation = mintV2Envelope(receipt)
    const res = await verifyReceiptByScheme({ receipt, ed25519_pub, ml_dsa_pub })
    ok('3. unknown scheme -> fail-closed (rejected), never guessed',
       res.scheme === 'rejected' && !res.valid, JSON.stringify(res))
    ok('3. reject reason surfaces the unknown scheme',
       res.reasons.some(r => r.startsWith('unknown-receipt-scheme:')), res.reasons.join(','))
  }

  // ── 4: MISSING scheme + EXPLICIT allowLegacyV1:true + v1 material -> v1 VALID
  {
    const receipt = buildV1Receipt()
    const canonical = canonicalPayload(receipt)
    const keyObj = createPrivateKey({ key: v1PrivPem, format: 'pem' })
    const signatureHex = sign(null, Buffer.from(canonical, 'utf8'), keyObj).toString('hex')

    const res = await verifyReceiptByScheme({
      receipt,
      allowLegacyV1: true,
      legacy: { signatureHex, publicKeyPem: v1PubPem },
    })
    ok('4. missing scheme + explicit allowLegacyV1:true routes to v1', res.scheme === 'v1', JSON.stringify(res))
    ok('4. v1 legacy receipt verifies VALID under the opt-in', res.valid, res.reasons.join(','))
  }

  // ── 4b: missing scheme + allowLegacyV1:true but NO v1 material -> fail-closed
  {
    const receipt = buildV1Receipt()
    const res = await verifyReceiptByScheme({ receipt, allowLegacyV1: true })
    ok('4b. allowLegacyV1:true but no v1 key material -> fail-closed (cannot verify)',
       res.scheme === 'rejected' && !res.valid &&
       res.reasons.includes('legacy-v1-allowed-but-no-v1-key-material-supplied'),
       JSON.stringify(res))
  }

  // ── 4c: v1 opt-in but a TAMPERED signature -> routed v1 AND invalid ─────────
  {
    const receipt = buildV1Receipt()
    const canonical = canonicalPayload(receipt)
    const keyObj = createPrivateKey({ key: v1PrivPem, format: 'pem' })
    const sigBuf = sign(null, Buffer.from(canonical, 'utf8'), keyObj)
    sigBuf[0] ^= 0xff
    const res = await verifyReceiptByScheme({
      receipt,
      allowLegacyV1: true,
      legacy: { signatureHex: sigBuf.toString('hex'), publicKeyPem: v1PubPem },
    })
    ok('4c. v1 opt-in with tampered signature -> routed v1 AND rejected',
       res.scheme === 'v1' && !res.valid, JSON.stringify(res))
  }

  process.stdout.write(`\nverify-by-scheme: ${passed} passed, ${failed} failed\n`)
  process.exit(failed === 0 ? 0 : 1)
}

void main()
