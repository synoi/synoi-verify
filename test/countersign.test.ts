/**
 * test/countersign.test.ts — @synoi/verify counter-signature verifier.
 *
 * Verifies the @synoi/verify package can validate SynOI Inc's Ed25519
 * counter-signature on an anchor-batch bundle. The signature is produced
 * on the control plane (synoi-control/src/integrity/countersign.ts); this
 * package is the receiver side that auditors run.
 */

import { generateKeyPairSync, sign } from 'node:crypto'
import { verifySynoiCountersignature } from '../src/countersign'

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

// Generate an Ed25519 keypair to simulate SynOI's signing key.
const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const pubKeyPem = publicKey.export({ type: 'spki', format: 'pem' }) as string
const pubKeyDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer
// Extract raw 32 bytes from the SPKI DER (last 32 bytes after the 12-byte prefix).
const pubKeyRawB64 = pubKeyDer.subarray(pubKeyDer.length - 32).toString('base64')

// Canonical bundle exactly as the control plane produces it (alphabetical keys).
const bundle = JSON.stringify({
  batch_created_at: 1747584000000,
  batch_root:       'a'.repeat(64),
  install_id:       'dev_test_install_xyz',
  leaf_count:       5,
  signed_at:        1747584060000,
  status:           'trusted',
  v:                1,
})
const sigBytes = sign(null, Buffer.from(bundle, 'utf-8'), privateKey)
const sigB64 = sigBytes.toString('base64')

// 1. Verify against PEM public key
{
  const r = verifySynoiCountersignature(bundle, sigB64, pubKeyPem)
  ok('PEM pubkey: signature verifies',     r.valid)
  ok('PEM pubkey: status surfaced',         r.status === 'trusted')
}

// 2. Verify against raw-32-byte base64 public key
{
  const r = verifySynoiCountersignature(bundle, sigB64, pubKeyRawB64)
  ok('raw32 pubkey: signature verifies',    r.valid)
  ok('raw32 pubkey: status surfaced',       r.status === 'trusted')
}

// 3. Tampered bundle → fails
{
  const tampered = bundle.replace('"a' + 'a'.repeat(63) + '"', '"' + 'b'.repeat(64) + '"')
  const r = verifySynoiCountersignature(tampered, sigB64, pubKeyPem)
  ok('tampered bundle → invalid',           !r.valid)
  ok('tampered bundle: reason set',         typeof r.reason === 'string' && r.reason.length > 0)
}

// 4. Wrong public key → fails
{
  const { publicKey: otherPub } = generateKeyPairSync('ed25519')
  const otherPem = otherPub.export({ type: 'spki', format: 'pem' }) as string
  const r = verifySynoiCountersignature(bundle, sigB64, otherPem)
  ok('wrong pubkey → invalid',              !r.valid)
}

// 5. Bad signature shape → fails with reason
{
  const r = verifySynoiCountersignature(bundle, Buffer.alloc(32, 0).toString('base64'), pubKeyPem)
  ok('32-byte sig (wrong length) → invalid', !r.valid)
  ok('32-byte sig: reason mentions length',  (r.reason ?? '').toLowerCase().includes('64'))
}

// 6. Raw pub key wrong length → fails with reason
{
  const tooShort = Buffer.alloc(16, 0).toString('base64')
  const r = verifySynoiCountersignature(bundle, sigB64, tooShort)
  ok('16-byte pubkey (wrong length) → invalid', !r.valid)
  ok('16-byte pubkey: reason mentions 32',      (r.reason ?? '').includes('32'))
}

// 7. Flagged-status bundle still verifies cleanly (signature is honest)
{
  const flaggedBundle = JSON.stringify({
    batch_created_at: 1747584000000,
    batch_root:       'c'.repeat(64),
    install_id:       'dev_test_install_xyz',
    leaf_count:       5,
    reason:           'install_unknown',
    signed_at:        1747584060000,
    status:           'flagged',
    v:                1,
  })
  const flaggedSig = sign(null, Buffer.from(flaggedBundle, 'utf-8'), privateKey).toString('base64')
  const r = verifySynoiCountersignature(flaggedBundle, flaggedSig, pubKeyPem)
  ok('flagged bundle: signature verifies',  r.valid)
  ok('flagged bundle: status === flagged',  r.status === 'flagged')
}

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed === 0 ? 0 : 1)
