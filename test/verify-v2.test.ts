/**
 * test/verify-v2.test.ts — Receipt v2 hybrid DSSE verifier round-trip.
 *
 * Mints a v2 receipt: an Ed25519 + ML-DSA-65 hybrid DSSE attestation over
 * PAE(payloadType, canonicalize(content_core)), then verifies it through
 * @synoi/verify's v2 path. @synoi/sraid exposes verify-only crypto (no signing
 * primitive), so the test signs the PAE itself: Ed25519 via node:crypto,
 * ML-DSA-65 via @noble/post-quantum, matching how the gateway mints receipts.
 *
 * The point of K1: the v2 path is HYBRID-both-required. A v2 receipt whose
 * ml-dsa-65 signature is stripped or corrupted MUST be rejected — verifying the
 * Ed25519 signature alone is not sufficient. This closes the sign-PQ vs
 * verify-PQ asymmetry.
 *
 *   yarn test
 */

import { generateKeyPairSync, sign } from 'node:crypto'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { canonicalize, cdroContentCore, pae } from '@synoi/sraid'
import { verifyReceiptV2, V2_PAYLOAD_TYPE, RECEIPT_SCHEME_V2 } from '../src/verify'

let passed = 0
let failed = 0

function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

// ── Keys ─────────────────────────────────────────────────────────────────────

// Ed25519: generate, export the RAW 32-byte public key from the SPKI DER (last
// 32 bytes), keep the KeyObject private key for signing (sign(null, …) wants it).
const { privateKey: edPriv, publicKey: edPubKey } = generateKeyPairSync('ed25519')
const edSpki = edPubKey.export({ type: 'spki', format: 'der' }) as Buffer
const ed25519_pub = new Uint8Array(edSpki.subarray(edSpki.length - 32))
ok('ed25519: raw public key is 32 bytes', ed25519_pub.length === 32)

// ML-DSA-65: deterministic keygen from a 32-byte seed.
const mlSeed = new Uint8Array(32).fill(7)
const mlKeys = ml_dsa65.keygen(mlSeed)
const ml_dsa_pub = mlKeys.publicKey
ok('ml-dsa-65: public key is 1952 bytes', ml_dsa_pub.length === 1952)

// ── Build a v2 receipt (CDRO-shaped) ────────────────────────────────────────

function buildReceipt(): Record<string, unknown> {
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

// Mint a hybrid DSSE envelope over PAE(payloadType, canonicalize(content_core)).
function mintEnvelope(receipt: Record<string, unknown>): {
  payloadType: string
  payload: string
  signatures: { alg: string; sig: string }[]
} {
  const payload = canonicalize(cdroContentCore(receipt))
  const message = pae(V2_PAYLOAD_TYPE, payload)
  const edSig = sign(null, Buffer.from(message), edPriv)
  // @noble ml-dsa API: sign(message, secretKey); verify(sig, message, publicKey).
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

async function main(): Promise<void> {
  // ── Positive: valid hybrid v2 receipt verifies TRUE ───────────────────────
  {
    const receipt = buildReceipt()
    receipt.attestation = mintEnvelope(receipt)
    const res = await verifyReceiptV2({ receipt, ed25519_pub, ml_dsa_pub })
    ok('v2: valid hybrid receipt verifies TRUE', res.valid, res.reasons.join(','))
    ok('v2: algorithm reported as hybrid DSSE',
       res.algorithm === 'DSSE(ed25519+ml-dsa-65)')
    ok('v2: payload_type pinned to sraid json', res.payload_type === V2_PAYLOAD_TYPE)
  }

  // ── PQ-asymmetry (the K1 acceptance): ml-dsa-65 STRIPPED → REJECT ─────────
  {
    const receipt = buildReceipt()
    const env = mintEnvelope(receipt)
    env.signatures = env.signatures.filter((s) => s.alg !== 'ml-dsa-65')
    receipt.attestation = env
    const res = await verifyReceiptV2({ receipt, ed25519_pub, ml_dsa_pub })
    ok('v2: ml-dsa-65 STRIPPED → REJECT (not accepted on ed25519 alone)',
       !res.valid && res.reasons.includes('missing-ml-dsa-65'),
       res.reasons.join(','))
  }

  // ── PQ-asymmetry: ml-dsa-65 INVALID (corrupted bytes) → REJECT ────────────
  {
    const receipt = buildReceipt()
    const env = mintEnvelope(receipt)
    const ml = env.signatures.find((s) => s.alg === 'ml-dsa-65')!
    const bad = Buffer.from(ml.sig, 'base64')
    bad[0] ^= 0xff
    ml.sig = bad.toString('base64')
    receipt.attestation = env
    const res = await verifyReceiptV2({ receipt, ed25519_pub, ml_dsa_pub })
    ok('v2: ml-dsa-65 INVALID → REJECT',
       !res.valid && res.reasons.includes('ml-dsa-invalid'),
       res.reasons.join(','))
  }

  // ── Symmetry: ed25519 stripped → REJECT ───────────────────────────────────
  {
    const receipt = buildReceipt()
    const env = mintEnvelope(receipt)
    env.signatures = env.signatures.filter((s) => s.alg !== 'ed25519')
    receipt.attestation = env
    const res = await verifyReceiptV2({ receipt, ed25519_pub, ml_dsa_pub })
    ok('v2: ed25519 STRIPPED → REJECT',
       !res.valid && res.reasons.includes('missing-ed25519'),
       res.reasons.join(','))
  }

  // ── ed25519 invalid → REJECT ──────────────────────────────────────────────
  {
    const receipt = buildReceipt()
    const env = mintEnvelope(receipt)
    const ed = env.signatures.find((s) => s.alg === 'ed25519')!
    const bad = Buffer.from(ed.sig, 'base64')
    bad[0] ^= 0xff
    ed.sig = bad.toString('base64')
    receipt.attestation = env
    const res = await verifyReceiptV2({ receipt, ed25519_pub, ml_dsa_pub })
    ok('v2: ed25519 INVALID → REJECT',
       !res.valid && res.reasons.includes('ed25519-invalid'),
       res.reasons.join(','))
  }

  // ── Tamper a signed field (settlement.cost.amount) → REJECT ───────────────
  {
    const receipt = buildReceipt()
    receipt.attestation = mintEnvelope(receipt)
    // mutate the body AFTER signing, without re-minting the envelope
    ;(receipt.body as { settlement: { cost: { amount: number } } }).settlement.cost.amount = 9999
    const res = await verifyReceiptV2({ receipt, ed25519_pub, ml_dsa_pub })
    ok('v2: tampered settlement.cost.amount → REJECT (content-core bind)',
       !res.valid && res.reasons.includes('payload-core-mismatch'),
       res.reasons.join(','))
  }

  // ── payloadType pin: wrong type → REJECT ──────────────────────────────────
  {
    const receipt = buildReceipt()
    const env = mintEnvelope(receipt)
    env.payloadType = 'application/vnd.someone-else+json'
    // payload still equals the content core, so the bind passes; the type-pin
    // inside verifyAttestation must reject.
    receipt.attestation = env
    const res = await verifyReceiptV2({ receipt, ed25519_pub, ml_dsa_pub })
    ok('v2: wrong payloadType → REJECT',
       !res.valid && res.reasons.includes('payload-type-mismatch'),
       res.reasons.join(','))
  }

  // ── Missing attestation → REJECT ──────────────────────────────────────────
  {
    const receipt = buildReceipt()
    const res = await verifyReceiptV2({ receipt, ed25519_pub, ml_dsa_pub })
    ok('v2: missing attestation → REJECT',
       !res.valid && res.reasons.includes('missing-attestation'),
       res.reasons.join(','))
  }

  // ── Wrong ml-dsa key → REJECT ─────────────────────────────────────────────
  {
    const receipt = buildReceipt()
    receipt.attestation = mintEnvelope(receipt)
    const otherSeed = new Uint8Array(32).fill(9)
    const otherMl = ml_dsa65.keygen(otherSeed)
    const res = await verifyReceiptV2({ receipt, ed25519_pub, ml_dsa_pub: otherMl.publicKey })
    ok('v2: wrong ml-dsa public key → REJECT',
       !res.valid && res.reasons.includes('ml-dsa-invalid'),
       res.reasons.join(','))
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed === 0 ? 0 : 1)
}

void main()
