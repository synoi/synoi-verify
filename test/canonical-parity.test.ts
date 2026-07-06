/**
 * test/canonical-parity.test.ts — CROSS-PACKAGE canonicalization proof.
 *
 * Proves, byte-for-byte, that @synoi/verify's canonicalization agrees with the
 * signer:
 *   A. jcsCanonicalize (the ported RFC 8785 JCS in verify.ts) == the
 *      @synoi/sraid `canonicalize` (the ONE canonical truth) on a battery of
 *      values including the unicode / large-integer / control-char / nested
 *      edge cases M2 called out.
 *   B. canonicalPayload (verify.ts) == the gateway signer's flat
 *      JSON.stringify(sorted scalar projection) on real receipt shapes,
 *      including unicode tenant_id, unicode action_class, and a large-integer
 *      recorded_at. If these ever diverge, a valid receipt would verify as
 *      INVALID (or vice-versa) — this test fails loudly instead.
 *
 * @synoi/sraid is ESM-only; this test dynamic-imports it. Run under tsx.
 */

import { canonicalPayload, jcsCanonicalize } from '../src/verify'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

// The gateway signer's EXACT v1 canonical form: flat JSON.stringify over the
// sorted scalar projection, omitting undefined/null. Mirror of
// verify-router.ts:canonicalPayload.
const CANONICAL_FIELDS = [
  'action_class', 'decision', 'oid_hex', 'receipt_id',
  'recorded_at', 'risk_level', 'tenant_id',
]
const OPTIONAL = ['gateway_manifest_sha256']
function signerFlatCanonical(payload: Record<string, unknown>): string {
  const obj: Record<string, unknown> = {}
  for (const k of [...CANONICAL_FIELDS, ...OPTIONAL].sort()) {
    const v = payload[k]
    if (v !== undefined && v !== null) obj[k] = v
  }
  return JSON.stringify(obj)
}

async function main(): Promise<void> {
  const sraid = await import('@synoi/sraid')

  // ── A. jcsCanonicalize == sraid.canonicalize (the ONE canonical truth) ──────
  // ADR_019 decision 2 forbids non-integer numbers, so every legal case here is
  // an integer (or non-number). The former float cases (1e21, 0.0000001, -0) are
  // moved to the negative-parity block below: both canonicalizers must REJECT
  // them identically, which is the property that keeps them from diverging.
  const jcsCases: unknown[] = [
    { b: 2, a: 1 },
    { z: 1, a: 2, m: 3 },
    [3, 1, 2],
    [1, null, 2],
    { foo: 1, bar: 'hi' },
    'tенант-Ünïcøde',
    'deploy-\u{1F680}',
    'a\tb\nc',
    9007199254740991,
    -9007199254740991,
    1e21,
    0,
    true,
    false,
    null,
    { nested: { z: 1, a: { d: 4, c: 3 } }, arr: [{ b: 1, a: 2 }] },
    { 'ключ': 'значение', k2: [1, 2, { inner: 'x' }] },
  ]
  for (let i = 0; i < jcsCases.length; i++) {
    const v = jcsCases[i]
    const mine = jcsCanonicalize(v)
    const theirs = sraid.canonicalize(v)
    ok(`jcs parity [${i}] ${JSON.stringify(v).slice(0, 40)}`,
       mine === theirs,
       `mine=${JSON.stringify(mine)} sraid=${JSON.stringify(theirs)}`)
  }

  // ── A'. NEGATIVE parity (ADR_019): a non-integer number must be REJECTED by
  //        BOTH canonicalizers. If one accepted a float the other rejects, a
  //        float-bearing object could mint bytes on one surface that the other
  //        declares malformed - the exact signature-confusion this forbids. -0
  //        is a legal integer (Number.isInteger(-0) === true) so it is ACCEPTED
  //        by both and canonicalizes to "0"; it is proven in the accept case.
  // Genuinely non-integer values. (1e21 is Number.isInteger-true, so it is a
  // LEGAL large integer proven in the accept battery above, not a float here.)
  const floatCases: number[] = [0.0000001, 1.5, -2.5, 1e-21]
  for (const f of floatCases) {
    let mineThrew = false
    let theirsThrew = false
    try { jcsCanonicalize(f) } catch { mineThrew = true }
    try { sraid.canonicalize(f) } catch { theirsThrew = true }
    ok(`float ${f} rejected by BOTH (ADR_019 forbid-non-integer)`, mineThrew && theirsThrew,
       `mineThrew=${mineThrew} theirsThrew=${theirsThrew}`)
  }
  // -0 is an integer: both accept it and both serialize it to "0".
  ok('negative-zero accepted by both and canonicalizes to "0"',
     jcsCanonicalize(-0) === '0' && sraid.canonicalize(-0) === '0',
     `mine=${jcsCanonicalize(-0)} sraid=${sraid.canonicalize(-0)}`)

  // ── B. canonicalPayload == the gateway signer flat projection ───────────────
  const base = (over: Record<string, unknown>): Record<string, unknown> => ({
    receipt_id: 'r1', tenant_id: 't1', decision: 'allow', action_class: 'B',
    risk_level: 'low', oid_hex: 'sha256:' + 'ab'.repeat(32), recorded_at: 1,
    ...over,
  })
  const receiptCases: Array<[string, Record<string, unknown>]> = [
    ['ascii', base({})],
    ['unicode tenant_id', base({ tenant_id: 'tенант-Ünïcøde' })],
    ['unicode action_class', base({ action_class: 'nét-wörk-\u{1F680}' })],
    ['large-int recorded_at (MAX_SAFE)', base({ recorded_at: 9007199254740991 })],
    ['with manifest', base({ gateway_manifest_sha256: 'sha256:' + 'be'.repeat(32) })],
    ['null authority field omitted', base({ gateway_manifest_sha256: null })],
    // non-canonical noise fields must not appear
    ['noise ignored', base({ latency_ms: 999, intent_id: 'x' })],
  ]
  for (const [name, receipt] of receiptCases) {
    const mine = canonicalPayload(receipt)
    const signer = signerFlatCanonical(receipt)
    ok(`canonicalPayload == signer flat: ${name}`,
       mine === signer,
       `mine=${JSON.stringify(mine)} signer=${JSON.stringify(signer)}`)
  }

  // ── C. Fail-closed on a non-scalar canonical field ──────────────────────────
  let threw = false
  try {
    canonicalPayload(base({ action_class: { nested: 1 } }))
  } catch { threw = true }
  ok('canonicalPayload rejects a non-scalar canonical field (fail-closed)', threw)

  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed === 0 ? 0 : 1)
}

main().catch((err) => {
  process.stderr.write('canonical-parity.test.ts crashed: ' + (err as Error).stack + '\n')
  process.exit(1)
})
