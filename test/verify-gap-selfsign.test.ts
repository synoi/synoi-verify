/**
 * test/verify-gap-selfsign.test.ts — the lite self-sign receipt tier
 * (ADR_014 Section 10.1, the public lite-daemon carve-out).
 *
 * PROVES @synoi/verify can verify what @synoi/gap's `receipt()` one-liner
 * actually produces -- the gap the Architect confirmed 2026-07-11: neither the
 * v1 legacy flat schema nor the v2 KMS-hybrid-DSSE tier matches a `receipt()`
 * envelope, so lite receipts had no verifier in the published package until
 * this tier landed. Reproduce-first: this test file existed and asserted the
 * new behavior BEFORE verifyGapSelfSignedReceipt / the dispatcher branch were
 * implemented.
 *
 *   1. A receipt() envelope verifies VALID via verifyGapSelfSignedReceipt
 *      against the signing key's own public key.
 *   2. Tampering the envelope (any signed field) invalidates it.
 *   3. The wrong public key invalidates it.
 *   4. verifyReceiptByScheme routes receipt_scheme='synoi.receipt/gap-selfsign'
 *      to this verifier (scheme 'gap-selfsign') and requires gap_ed25519_pub;
 *      omitting it is a fail-closed 'rejected', NOT a silent pass.
 *   5. The verifier here is a thin delegate to @synoi/gap's OWN
 *      verifyReceiptSignature -- not a second hand-copied canonicalizer --
 *      proven by cross-checking both entry points agree on the same envelope.
 *
 * CLAIMS DISCIPLINE: no vector, no claim. This is that vector. NO em dashes.
 *
 *   yarn test
 */

import { receipt, generateReceiptKeyPair, verifyReceiptSignature as gapVerifyReceiptSignature, computeGapOid, RECEIPT_SCHEME_GAP_SELFSIGN as GAP_RECEIPT_SCHEME_GAP_SELFSIGN } from '@synoi/gap'
import {
  verifyGapSelfSignedReceipt,
  verifyReceiptByScheme,
  RECEIPT_SCHEME_GAP_SELFSIGN,
} from '../src/verify'

let passed = 0
let failed = 0

function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

async function main(): Promise<void> {
  // The two packages must agree on the wire string -- this is the drift check
  // the Architect flagged: a hand-copied constant here would silently diverge.
  ok('RECEIPT_SCHEME_GAP_SELFSIGN matches @synoi/gap\'s own constant',
     RECEIPT_SCHEME_GAP_SELFSIGN === GAP_RECEIPT_SCHEME_GAP_SELFSIGN)

  const keyPair = generateReceiptKeyPair('key:lite-operator')
  const r = receipt({
    subjectKind: 'capability_invocation',
    subjectOid: 'sha256:' + '11'.repeat(32),
    initiator: { actor_oid: 'oid-' + '22'.repeat(32), actor_type: 'human_user' },
  }, { keyPair })

  ok('receipt() envelope carries receipt_scheme = gap-selfsign',
     r.envelope.receipt_scheme === RECEIPT_SCHEME_GAP_SELFSIGN)

  // 1. Valid signature verifies through the new @synoi/verify entry point.
  const res1 = await verifyGapSelfSignedReceipt({
    receipt: r.envelope as unknown as Record<string, unknown>,
    ed25519_pub: keyPair.publicKey,
  })
  ok('verifyGapSelfSignedReceipt: valid gap-selfsign receipt verifies', res1.valid, res1.reason)
  ok('verifyGapSelfSignedReceipt: algorithm tag is Ed25519(gap-selfsign)',
     res1.algorithm === 'Ed25519(gap-selfsign)')

  // 2. Tamper detection.
  const tampered = { ...r.envelope, body: { ...r.envelope.body, status: 'denied' as const } }
  const res2 = await verifyGapSelfSignedReceipt({
    receipt: tampered as unknown as Record<string, unknown>,
    ed25519_pub: keyPair.publicKey,
  })
  ok('verifyGapSelfSignedReceipt: tampered body fails verification', !res2.valid)

  // 3. Wrong key fails.
  const otherKeyPair = generateReceiptKeyPair()
  const res3 = await verifyGapSelfSignedReceipt({
    receipt: r.envelope as unknown as Record<string, unknown>,
    ed25519_pub: otherKeyPair.publicKey,
  })
  ok('verifyGapSelfSignedReceipt: wrong public key fails verification', !res3.valid)

  // 4. Malformed / missing attestation-equivalent input still fails closed,
  //    never throws.
  const res4 = await verifyGapSelfSignedReceipt({
    receipt: { ...r.envelope, signature: undefined } as unknown as Record<string, unknown>,
    ed25519_pub: keyPair.publicKey,
  })
  ok('verifyGapSelfSignedReceipt: missing signature fails closed, does not throw', !res4.valid)

  // 4b. Security F2 (2026-07-12 quality gate, fixed in @synoi/gap): an
  //     oid/gap_version/supersedes rebind mismatch must be caught here too --
  //     this is a DELEGATION test proving the fix in @synoi/gap's
  //     verifyReceiptSignature is actually inherited by @synoi/verify's
  //     gap-selfsign path, not re-implemented (and therefore not at risk of
  //     silently NOT inheriting a future fix there).
  const tamperedOidReceipt = { ...r.envelope, oid: 'sha256:' + 'ff'.repeat(32) }
  const res4b = await verifyGapSelfSignedReceipt({
    receipt: tamperedOidReceipt as unknown as Record<string, unknown>,
    ed25519_pub: keyPair.publicKey,
  })
  ok('verifyGapSelfSignedReceipt: tampered oid fails verification (F2 fix inherited from @synoi/gap)', !res4b.valid)

  const tamperedSupersedesReceipt = { ...r.envelope, supersedes: 'sha256:' + 'aa'.repeat(32) }
  const res4c = await verifyGapSelfSignedReceipt({
    receipt: tamperedSupersedesReceipt as unknown as Record<string, unknown>,
    ed25519_pub: keyPair.publicKey,
  })
  ok('verifyGapSelfSignedReceipt: forged supersedes lineage edge fails verification (F2 fix inherited)', !res4c.valid)

  // 4d. ADVERSARY re-clear (2026-07-12): 4b/4c above only prove the LAZY
  //     variant (mutate a field, leave oid stale). computeGapOid is a
  //     PUBLIC, UNKEYED sha256 -- an attacker with no secret can mutate a
  //     field, RECOMPUTE a matching oid, and reuse the ORIGINAL signature
  //     bytes unchanged. Before @synoi/gap's EXCLUDED_FIELDS fix (bringing
  //     gap_version/supersedes/signature_key_id into the signed payload),
  //     this recompute-oid variant verified TRUE through this exact
  //     delegation path -- the live attack the Adversary proved, not
  //     defended by the oid-rebind check alone. Each variant here mutates a
  //     field AND recomputes a matching oid the same way receipt() does,
  //     then reuses the original signature; all three MUST fail through
  //     @synoi/verify's delegated dispatcher, not just through @synoi/gap
  //     directly (proving the fix is actually inherited, not merely present
  //     upstream).
  function recomputeOidFor(envelope: typeof r.envelope): string {
    return computeGapOid({
      type: envelope.type,
      gap_version: envelope.gap_version,
      receipt_scheme: envelope.receipt_scheme,
      tenant_id: envelope.tenant_id,
      created_at_ms: envelope.created_at_ms,
      created_by: envelope.created_by,
      body: envelope.body,
      supersedes: envelope.supersedes,
    })
  }

  const forgedGapVersion = { ...r.envelope, gap_version: '2.0' as unknown as typeof r.envelope.gap_version }
  forgedGapVersion.oid = recomputeOidFor(forgedGapVersion)
  const res4d = await verifyGapSelfSignedReceipt({
    receipt: forgedGapVersion as unknown as Record<string, unknown>,
    ed25519_pub: keyPair.publicKey,
  })
  ok('ADVERSARY (delegated): gap_version mutated + oid recomputed to match + original signature reused -> MUST fail',
     !res4d.valid)

  const forgedSupersedes = { ...r.envelope, supersedes: 'sha256:' + 'bb'.repeat(32) }
  forgedSupersedes.oid = recomputeOidFor(forgedSupersedes)
  const res4e = await verifyGapSelfSignedReceipt({
    receipt: forgedSupersedes as unknown as Record<string, unknown>,
    ed25519_pub: keyPair.publicKey,
  })
  ok('ADVERSARY (delegated): supersedes forged + oid recomputed to match + original signature reused -> MUST fail',
     !res4e.valid)

  const forgedKeyId = { ...r.envelope, signature_key_id: otherKeyPair.keyId ?? 'key:attacker-controlled' }
  const res4f = await verifyGapSelfSignedReceipt({
    receipt: forgedKeyId as unknown as Record<string, unknown>,
    ed25519_pub: keyPair.publicKey,
  })
  ok('ADVERSARY (delegated): signature_key_id swapped (oid unaffected, signature reused) -> MUST fail',
     !res4f.valid)

  // Sanity: dispatcher-level too, not just the direct verifyGapSelfSignedReceipt call.
  const dispForged = await verifyReceiptByScheme({
    receipt: forgedGapVersion as unknown as Record<string, unknown>,
    gap_ed25519_pub: keyPair.publicKey,
  })
  ok('ADVERSARY (dispatcher-level): forged gap_version + recomputed oid rejected via verifyReceiptByScheme too',
     dispForged.valid === false)

  // 5. Dispatcher routes by receipt_scheme.
  const disp1 = await verifyReceiptByScheme({
    receipt: r.envelope as unknown as Record<string, unknown>,
    gap_ed25519_pub: keyPair.publicKey,
  })
  ok('verifyReceiptByScheme: routes gap-selfsign scheme to scheme=\'gap-selfsign\'',
     disp1.scheme === 'gap-selfsign')
  ok('verifyReceiptByScheme: gap-selfsign receipt with correct key verifies VALID',
     disp1.valid, disp1.reasons.join(', '))

  // 6. Dispatcher fails closed when the gap_ed25519_pub key is omitted --
  //    NOT a silent pass, and NOT routed to a different tier's key.
  const disp2 = await verifyReceiptByScheme({
    receipt: r.envelope as unknown as Record<string, unknown>,
  })
  ok('verifyReceiptByScheme: gap-selfsign scheme without gap_ed25519_pub is REJECTED (fail-closed)',
     disp2.valid === false && disp2.scheme === 'rejected')
  ok('verifyReceiptByScheme: rejection reason names the missing key',
     disp2.reasons.includes('gap-selfsign-scheme-requires-ed25519-public-key'))

  // 7. Dispatcher tamper detection end-to-end.
  const disp3 = await verifyReceiptByScheme({
    receipt: tampered as unknown as Record<string, unknown>,
    gap_ed25519_pub: keyPair.publicKey,
  })
  ok('verifyReceiptByScheme: tampered gap-selfsign receipt is invalid, not rejected-for-other-reason',
     disp3.valid === false && disp3.scheme === 'gap-selfsign')

  // 8. Delegation, not reimplementation: @synoi/verify's answer matches
  //    @synoi/gap's own verifyReceiptSignature on the SAME inputs, for both
  //    the valid and the tampered case. If @synoi/verify silently forked its
  //    own canonicalizer/exclusion-set, this is the check that would catch it.
  const gapDirect = gapVerifyReceiptSignature(r.envelope, keyPair.publicKey)
  ok('cross-check: @synoi/verify and @synoi/gap agree on the valid receipt',
     res1.valid === gapDirect && gapDirect === true)
  const gapDirectTampered = gapVerifyReceiptSignature(tampered as typeof r.envelope, keyPair.publicKey)
  ok('cross-check: @synoi/verify and @synoi/gap agree on the tampered receipt',
     res2.valid === gapDirectTampered && gapDirectTampered === false)

  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed > 0 ? 1 : 0)
}

main()
