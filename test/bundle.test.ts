/**
 * test/bundle.test.ts - offline EVIDENCE BUNDLE verification via the @synoi/verify
 * RE-EXPORT of @synoi/verify-core (ADR_019 STEP 8).
 *
 * The full behavioral matrix lives in @synoi/verify-core's own suite. This test
 * proves the @synoi/verify public re-export path (the async CJS wrapper around the
 * ESM core verifier) is wired correctly and preserves the v2 contract end to end:
 *   1. the valid v2 golden verifies through the wrapper,
 *   2. completeness tamper reds the signed digest (truncated relabel),
 *   3. a v1 bundle is hard-rejected unsupported-bundle-version (fail-closed),
 *   4. a representative body-tamper and tenant-mismatch still red.
 *
 * ONE CANONICAL TRUTH: verification reuses @synoi/sraid canonicalize +
 * verifyAttestation via @synoi/verify-core. No divergent canonicalizer here.
 *
 * NO em dashes. NO AI attribution.
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHash, createPublicKey } from 'node:crypto'
import { verifyEvidenceBundle, type EvidenceBundle } from '../src/bundle'

const GOLDEN = join(__dirname, '..', 'vectors', 'evidence-bundle.v2.golden.json')

function loadGolden(): EvidenceBundle {
  return JSON.parse(readFileSync(GOLDEN, 'utf8')) as EvidenceBundle
}
function clone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x)) as T
}
function fingerprintOf(pk: { ed25519_public_key_pem: string; ml_dsa_public_key_b64: string }): string {
  const edDer = createPublicKey({ key: pk.ed25519_public_key_pem, format: 'pem' }).export({
    format: 'der',
    type: 'spki',
  }) as Buffer
  const ml = Buffer.from(pk.ml_dsa_public_key_b64, 'base64')
  return 'sha256:' + createHash('sha256').update(edDer).update(ml).digest('hex')
}

async function main(): Promise<void> {
  let passed = 0
  let failed = 0
  function ok(label: string, cond: boolean, detail?: string): void {
    if (cond) {
      passed++
      process.stdout.write(`OK   ${label}\n`)
    } else {
      failed++
      process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`)
    }
  }

  const golden = loadGolden()
  const sraid = await import('@synoi/sraid')
  // Recompute the v2 signed-completeness digest exactly as the core producer does.
  const v2Digest = (b: EvidenceBundle): string => {
    const preimage = {
      bundle_version: b.bundle_version,
      tenant_id: b.tenant_id,
      receipt_count: b.manifest.receipt_count,
      absence_count: b.manifest.absence_count,
      truncated: b.honesty.truncated,
      body_filtered_omission: b.honesty.body_filtered_omission,
      filter: b.filter,
      receipts: b.receipts,
      absence_statements: b.absence_statements,
    }
    return 'sha256:' + createHash('sha256').update(sraid.canonicalize(preimage), 'utf8').digest('hex')
  }

  // ── 1. VALID v2 golden verifies through the re-export ─────────────────────────
  const v = await verifyEvidenceBundle(golden)
  ok('valid v2 golden verifies through @synoi/verify re-export', v.valid === true, 'reasons: ' + v.reasons.join(','))
  ok('content_digest_ok true', v.content_digest_ok === true)
  ok(
    'every receipt + absence verifies',
    v.receipt_results.every((r) => r.valid && r.ed25519_valid && r.ml_dsa_valid) &&
      v.absence_results.every((a) => a.valid),
    JSON.stringify({ r: v.receipt_results.filter((r) => !r.valid), a: v.absence_results.filter((a) => !a.valid) }),
  )
  ok(
    'golden publishes the golden key fingerprint',
    v.verifying_key_fingerprints.length === 1 && v.verifying_key_fingerprints[0] === `golden-v1 ${fingerprintOf(golden.key_history[0])}`,
    JSON.stringify(v.verifying_key_fingerprints),
  )

  // ── 2. COMPLETENESS TAMPER reds the signed digest ────────────────────────────
  const truthfulTrunc = clone(golden)
  truthfulTrunc.honesty.truncated = true
  truthfulTrunc.manifest.content_digest = v2Digest(truthfulTrunc)
  ok('a truthfully-truncated v2 bundle verifies', (await verifyEvidenceBundle(truthfulTrunc)).valid === true)
  const liedComplete = clone(truthfulTrunc)
  liedComplete.honesty.truncated = false // lie: "complete"
  const vLied = await verifyEvidenceBundle(liedComplete)
  ok(
    'truncated->complete relabel cannot verify green (content-digest-mismatch)',
    vLied.valid === false && vLied.reasons.includes('content-digest-mismatch'),
    vLied.reasons.join(','),
  )

  // ── 3. FAIL-CLOSED: a v1 bundle is hard-rejected ─────────────────────────────
  const v1Bundle = clone(golden)
  v1Bundle.bundle_version = 'synoi-evidence-bundle-v1'
  const vV1 = await verifyEvidenceBundle(v1Bundle)
  ok(
    'v1 bundle REJECTED unsupported-bundle-version',
    vV1.valid === false && vV1.reasons.includes('unsupported-bundle-version') && vV1.reasons.length === 1,
    vV1.reasons.join(','),
  )

  // ── 4. representative retained checks ────────────────────────────────────────
  const tByte = clone(golden)
  ;(tByte.receipts[0].body as Record<string, unknown>)['subject_oid'] = 'arn:res/HACKED'
  const vByte = await verifyEvidenceBundle(tByte)
  ok(
    'flipped receipt body byte REJECTED',
    vByte.valid === false &&
      (vByte.reasons.includes('content-digest-mismatch') || vByte.reasons.includes('receipt-signature-invalid')),
    vByte.reasons.join(','),
  )

  const tTenant = clone(golden)
  tTenant.tenant_id = 'other-tenant'
  tTenant.manifest.content_digest = v2Digest(tTenant)
  const vTenant = await verifyEvidenceBundle(tTenant)
  ok(
    'declared tenant != signed receipt tenant REJECTED (receipt-tenant-mismatch)',
    vTenant.valid === false && vTenant.reasons.includes('receipt-tenant-mismatch'),
    vTenant.reasons.join(','),
  )

  const vMal = await verifyEvidenceBundle({} as EvidenceBundle)
  ok('malformed bundle REJECTED', vMal.valid === false && vMal.reasons.includes('malformed-bundle'))

  process.stdout.write(`\nbundle: ${passed} passed, ${failed} failed\n`)
  process.exit(failed === 0 ? 0 : 1)
}

main().catch((err) => {
  process.stderr.write('bundle: fatal: ' + (err instanceof Error ? err.stack : String(err)) + '\n')
  process.exit(1)
})
