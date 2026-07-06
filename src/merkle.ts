/**
 * merkle.ts — RFC 6962 audit-path verifier for SynOI Decision Receipts.
 *
 * Used to verify the Merkle inclusion proof returned by
 * `GET /verify/:receipt_id/anchor` on a SynOI gateway. The same
 * algorithm is implemented in synoi-gateway/src/merkle.ts; this
 * package ships the verifier-only subset so auditors don't need to
 * pull in the gateway codebase.
 *
 * Verification flow:
 *
 *   const anchor = await fetch(`${gw}/verify/${id}/anchor`).then(r => r.json())
 *   const ok = verifyAuditPath(
 *     Buffer.from(anchor.leaf_hash, 'hex'),
 *     hexProofToBuffers(anchor.proof),
 *     Buffer.from(anchor.merkle_root, 'hex'),
 *   )
 *
 * For Bitcoin-anchored verification (when anchor.ots.proof_b64 is
 * present), the standard `ots verify` CLI from
 * github.com/opentimestamps/opentimestamps-client takes over.
 *
 * Reference: RFC 6962 §2.1.1 (Merkle Audit Paths).
 */

import { createHash } from 'node:crypto'

const LEAF_PREFIX     = Buffer.from([0x00])
const INTERNAL_PREFIX = Buffer.from([0x01])

export interface ProofStep {
  sibling:  Buffer
  position: 'L' | 'R'
}

export interface HexProofStep {
  sibling:  string
  position: 'L' | 'R'
}

/** Hash a leaf. SHA-256(0x00 || data). */
export function leafHash(data: Buffer | string): Buffer {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data
  return createHash('sha256').update(LEAF_PREFIX).update(buf).digest()
}

/** Hash an internal node. SHA-256(0x01 || left || right). */
export function internalHash(left: Buffer, right: Buffer): Buffer {
  return createHash('sha256').update(INTERNAL_PREFIX).update(left).update(right).digest()
}

/**
 * Verify a Merkle audit path against a known root.
 *
 * Folds the proof from `leaf` upward (in order), applying each sibling
 * on the indicated side. Returns true iff the result equals `expectedRoot`.
 */
export function verifyAuditPath(
  leaf:         Buffer,
  proof:        ProofStep[],
  expectedRoot: Buffer,
): boolean {
  let current = leaf
  for (const step of proof) {
    current = step.position === 'L'
      ? internalHash(step.sibling, current)
      : internalHash(current, step.sibling)
  }
  return Buffer.compare(current, expectedRoot) === 0
}

/** Convert the hex-serialized proof (as returned by /verify/:id/anchor) to Buffers. */
export function hexProofToBuffers(p: HexProofStep[]): ProofStep[] {
  return p.map(s => ({ sibling: Buffer.from(s.sibling, 'hex'), position: s.position }))
}
