/**
 * test/merkle.test.ts — verify the Merkle audit-path verifier shipped in
 * @synoi/verify produces results compatible with the gateway's anchor
 * worker.
 *
 * Mirrors a subset of synoi-gateway/test/sprint3.test.ts (the verifier
 * side). If both packages compute the same Merkle root + audit-path
 * results, an auditor using @synoi/verify can validate gateway-emitted
 * anchors without the gateway's code.
 */

import { createHash } from 'node:crypto'
import {
  verifyAuditPath,
  hexProofToBuffers,
  leafHash,
  internalHash,
} from '../src/merkle'

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

// ── 1. Hashing primitives match RFC 6962 ─────────────────────────────────────

const l0 = leafHash(Buffer.from('a'))
const expectedL0 = createHash('sha256').update(Buffer.from([0x00])).update(Buffer.from('a')).digest()
ok('leafHash uses 0x00 prefix per RFC 6962',
   Buffer.compare(l0, expectedL0) === 0)

const left  = leafHash(Buffer.from('left'))
const right = leafHash(Buffer.from('right'))
const i01 = internalHash(left, right)
const expectedI01 = createHash('sha256').update(Buffer.from([0x01])).update(left).update(right).digest()
ok('internalHash uses 0x01 prefix per RFC 6962',
   Buffer.compare(i01, expectedI01) === 0)

// ── 2. Audit-path verification with a hand-built tree ──────────────────────

// Build a 4-leaf tree by hand:
//
//        root
//       /    \
//      H01    H23
//     /  \   /  \
//    L0  L1 L2  L3
const leaves = [
  leafHash(Buffer.from('leaf-0')),
  leafHash(Buffer.from('leaf-1')),
  leafHash(Buffer.from('leaf-2')),
  leafHash(Buffer.from('leaf-3')),
]
const h01  = internalHash(leaves[0]!, leaves[1]!)
const h23  = internalHash(leaves[2]!, leaves[3]!)
const root = internalHash(h01, h23)

// Audit path for leaf 0: sibling L1 (R), then sibling h23 (R)
const proof0 = [
  { sibling: leaves[1]!, position: 'R' as const },
  { sibling: h23,        position: 'R' as const },
]
ok('leaf 0 audit path verifies', verifyAuditPath(leaves[0]!, proof0, root))

// Audit path for leaf 1: sibling L0 (L), then sibling h23 (R)
const proof1 = [
  { sibling: leaves[0]!, position: 'L' as const },
  { sibling: h23,        position: 'R' as const },
]
ok('leaf 1 audit path verifies', verifyAuditPath(leaves[1]!, proof1, root))

// Audit path for leaf 3: sibling L2 (L), then sibling h01 (L)
const proof3 = [
  { sibling: leaves[2]!, position: 'L' as const },
  { sibling: h01,        position: 'L' as const },
]
ok('leaf 3 audit path verifies', verifyAuditPath(leaves[3]!, proof3, root))

// ── 3. Negative cases ──────────────────────────────────────────────────────

// Wrong leaf hash → fails
ok('wrong leaf fails verification',
   !verifyAuditPath(leafHash(Buffer.from('not-leaf-0')), proof0, root))

// Wrong root → fails
ok('wrong root fails verification',
   !verifyAuditPath(leaves[0]!, proof0, Buffer.alloc(32, 0xff)))

// Tampered position bit → fails
const tampered = [
  { sibling: leaves[1]!, position: 'L' as const },  // was 'R'
  { sibling: h23,        position: 'R' as const },
]
ok('flipped position bit fails verification',
   !verifyAuditPath(leaves[0]!, tampered, root))

// ── 4. Hex deserialization round-trip ──────────────────────────────────────

const hexProof = [
  { sibling: leaves[1]!.toString('hex'), position: 'R' as const },
  { sibling: h23.toString('hex'),        position: 'R' as const },
]
const bufProof = hexProofToBuffers(hexProof)
ok('hex proof deserializes + verifies',
   verifyAuditPath(leaves[0]!, bufProof, root))

// ── Summary ────────────────────────────────────────────────────────────────

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed === 0 ? 0 : 1)
