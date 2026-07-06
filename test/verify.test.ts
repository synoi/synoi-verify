/**
 * test/verify.test.ts — verifier round-trip.
 *
 * Generates an Ed25519 keypair, signs a canonical payload using the
 * EXACT shape the gateway uses (verify-router.ts:canonicalPayload),
 * then verifies it with @synoi/verify. Catches drift between the two.
 *
 *   yarn test
 */

import { generateKeyPairSync, sign, createPrivateKey } from 'node:crypto'
import {
  verifyReceiptSignature,
  canonicalPayload,
  CANONICAL_FIELDS,
  OPTIONAL_CANONICAL_FIELDS,
} from '../src/verify'

let passed = 0
let failed = 0

function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

// ── Generate an Ed25519 keypair (same shape the gateway uses) ────────────────

const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
const publicPem  = publicKey.export({ type: 'spki',  format: 'pem' }) as string

ok('keypair: private PEM begins with PRIVATE KEY header',
   privatePem.startsWith('-----BEGIN PRIVATE KEY-----'))
ok('keypair: public PEM begins with PUBLIC KEY header',
   publicPem.startsWith('-----BEGIN PUBLIC KEY-----'))

// ── A receipt payload exactly as the gateway emits ──────────────────────────

const goodReceipt = {
  receipt_id:   'rcpt_test_01',
  tenant_id:    'founder',
  decision:     'allow',
  action_class: 'B',
  risk_level:   'low',
  oid_hex:      '0123456789abcdef'.repeat(4),       // 64 hex chars
  recorded_at:  1747584000000,
  // Non-canonical fields that MUST be ignored by the signature:
  intent_id:    'irrelevant',
  action_type:  'AnthropicMessages',
  latency_ms:   123,
}

const canonical = canonicalPayload(goodReceipt)
const expectedCanonical =
  '{"action_class":"B","decision":"allow","oid_hex":"' + '0123456789abcdef'.repeat(4) +
  '","receipt_id":"rcpt_test_01","recorded_at":1747584000000,"risk_level":"low","tenant_id":"founder"}'

ok('canonicalPayload: byte-identical to expected gateway output',
   canonical === expectedCanonical,
   canonical)

ok('canonicalPayload: ignores non-canonical fields',
   !canonical.includes('intent_id') && !canonical.includes('latency_ms'))

// ── Sign + verify ───────────────────────────────────────────────────────────

const keyObj = createPrivateKey({ key: privatePem, format: 'pem' })
const signatureHex = sign(null, Buffer.from(canonical, 'utf8'), keyObj).toString('hex')

ok('sign: produces 128 hex chars (64-byte Ed25519)', signatureHex.length === 128)

const verified = verifyReceiptSignature(goodReceipt, signatureHex, publicPem)
ok('verify: good payload + good signature + good key → valid',
   verified.valid,
   verified.reason)

ok('verify: canonical_payload matches', verified.canonical_payload === expectedCanonical)
ok('verify: algorithm reported as Ed25519', verified.algorithm === 'Ed25519')

// ── Negative cases ──────────────────────────────────────────────────────────

const tamperedReceipt = { ...goodReceipt, decision: 'deny' }
const tampered = verifyReceiptSignature(tamperedReceipt, signatureHex, publicPem)
ok('verify: tampered decision → invalid', !tampered.valid)
ok('verify: tampered payload result carries a reason', tampered.reason !== undefined)

// Tamper a non-canonical field — should still verify (those don't sign)
const noisedReceipt = { ...goodReceipt, latency_ms: 99999 }
const noised = verifyReceiptSignature(noisedReceipt, signatureHex, publicPem)
ok('verify: noise in non-canonical field is invisible to signature',
   noised.valid,
   noised.reason)

// Wrong public key
const { publicKey: wrongPub } = generateKeyPairSync('ed25519')
const wrongPubPem = wrongPub.export({ type: 'spki', format: 'pem' }) as string
const wrongKey = verifyReceiptSignature(goodReceipt, signatureHex, wrongPubPem)
ok('verify: wrong public key → invalid', !wrongKey.valid)

// Bad signature format
const badSig = verifyReceiptSignature(goodReceipt, 'not-hex', publicPem)
ok('verify: non-hex signature → invalid with reason', !badSig.valid && badSig.reason !== undefined)

const shortSig = verifyReceiptSignature(goodReceipt, '00'.repeat(32), publicPem)
ok('verify: 32-byte signature → invalid (Ed25519 is 64)', !shortSig.valid)

// Missing canonical field
const incomplete = { ...goodReceipt } as Record<string, unknown>
delete incomplete.tenant_id
const missing = verifyReceiptSignature(incomplete, signatureHex, publicPem)
ok('verify: missing canonical field → invalid with reason',
   !missing.valid && missing.reason?.includes('tenant_id') === true)

// ── Field set sanity ────────────────────────────────────────────────────────

ok('CANONICAL_FIELDS: exactly 7 required fields',
   CANONICAL_FIELDS.length === 7)
ok('CANONICAL_FIELDS: alphabetically sorted',
   [...CANONICAL_FIELDS].join(',') === [...CANONICAL_FIELDS].sort().join(','))
ok('OPTIONAL_CANONICAL_FIELDS: includes gateway_manifest_sha256',
   (OPTIONAL_CANONICAL_FIELDS as readonly string[]).includes('gateway_manifest_sha256'))

// ── Optional manifest field — Sprint 1.2 backward-compat ────────────────────
const receiptWithManifest = {
  ...goodReceipt,
  gateway_manifest_sha256: 'b'.repeat(64),
}
const canonicalWithManifest = canonicalPayload(receiptWithManifest)
ok('canonical: includes manifest hash when present',
   canonicalWithManifest.includes('gateway_manifest_sha256'))
ok('canonical: legacy receipt (no manifest) still produces canonical without it',
   !canonical.includes('gateway_manifest_sha256'))

const sigManifest = sign(null, Buffer.from(canonicalWithManifest, 'utf8'), keyObj).toString('hex')
const verifiedManifest = verifyReceiptSignature(receiptWithManifest, sigManifest, publicPem)
ok('verify: manifest-bearing receipt verifies', verifiedManifest.valid, verifiedManifest.reason)

const tamperedManifestField = { ...receiptWithManifest, gateway_manifest_sha256: 'c'.repeat(64) }
const tamperedManifestRes = verifyReceiptSignature(tamperedManifestField, sigManifest, publicPem)
ok('verify: tampering with manifest hash fails verification', !tamperedManifestRes.valid)

// ── Summary ─────────────────────────────────────────────────────────────────

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed === 0 ? 0 : 1)
