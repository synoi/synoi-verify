/**
 * verify-v2-browser.ts — the v2 hybrid DSSE verifier, browser edition.
 *
 * WHY A SECOND FILE AND NOT A FLAG. ./verify's `verifyReceiptV2` dynamic-imports
 * `@synoi/sraid`, whose default entry statically imports node:crypto in three
 * places (ed25519.ts, mldsa.ts, oid.ts). That single edge is enough to break any
 * browser bundle that reaches it, which is why the browser entry previously
 * omitted v2 entirely and failed closed with `v2-not-supported-in-browser-build`.
 * A runtime flag would not have helped: the import edge exists in the module
 * graph whether or not the branch is taken, and a bundler follows the graph, not
 * the control flow. Two files, two graphs, is the only thing a bundler respects.
 *
 * WHAT THIS IMPORTS INSTEAD. `@synoi/sraid/verify-browser` (added in sraid
 * 0.3.0): the same hybrid DSSE verify and the same content-core projection, with
 * WebCrypto Ed25519 (@noble/curves fallback), @noble/post-quantum ML-DSA-65 and
 * WebCrypto SHA-256 in place of node:crypto. The PAE bytes, the AND policy and
 * the reason strings are shared byte-for-byte with the node entry via
 * internal/attestation-core and internal/content-core, so this is not a second
 * implementation of the scheme. There is still exactly ONE hybrid DSSE verifier
 * and ONE canonicalizer; this file selects a different crypto backend for it.
 *
 * THE ONE BEHAVIOURAL DIFFERENCE: sraid's browser `verifyAttestation` is async
 * (WebCrypto verify is Promise-based) where the node one is sync. `verifyReceiptV2`
 * was already async on both sides, so this difference does not reach callers.
 * The result shape, the `algorithm` string and every reason string are identical,
 * and test/browser-v2.test.ts asserts node/browser parity on the same bytes
 * rather than taking that on trust.
 *
 * WHAT IS DELIBERATELY NOT RELAXED. Both checks the node path performs are
 * performed here in the same order: (1) the content-core bind, which is the only
 * thing that stops a validly-signed envelope being transplanted onto a different
 * receipt body, and (2) the hybrid verify, which requires BOTH ed25519 and
 * ml-dsa-65. A browser build that accepted a v2 receipt on the Ed25519 signature
 * alone would reopen the sign-PQ vs verify-PQ asymmetry K1 closed, and would do
 * it on the surface a stranger is most likely to use.
 *
 * The dynamic import mirrors the gap-selfsign path in ./verify-shared and exists
 * for the same reason: @synoi/sraid is ESM-only and this package is CommonJS, so
 * the ESM contact is confined to one function that runs unchanged under both
 * Node's require(ESM) interop (>= 22) and a browser bundler's native import().
 */

import {
  V2_PAYLOAD_TYPE,
  type VerifyReceiptV2Input,
  type VerifyResultV2,
} from './verify-shared'

const V2_ALGORITHM = 'DSSE(ed25519+ml-dsa-65)' as const

/**
 * Verify a Receipt v2 hybrid DSSE attestation in a browser, Chrome-extension or
 * service-worker context. Same two checks, same order, same reasons as the node
 * `verifyReceiptV2`:
 *
 *   1. Content-core bind — recompute `canonicalize(cdroContentCore(receipt))`
 *      and require it to equal the envelope's `payload`.
 *   2. Hybrid signature verify — BOTH ed25519 AND ml-dsa-65 over the PAE, with
 *      the payloadType pinned.
 *
 * Returns `valid: true` only when both pass. Never throws: a missing subpath, an
 * unsupported crypto backend or a malformed envelope all resolve to a failed
 * outcome carrying a reason, because a verifier that throws where it should
 * return false invites a caller to treat the exception as "inconclusive" and
 * move on.
 */
export async function verifyReceiptV2Browser(
  input: VerifyReceiptV2Input,
): Promise<VerifyResultV2> {
  let sraid: typeof import('@synoi/sraid/verify-browser')
  try {
    sraid = await import('@synoi/sraid/verify-browser')
  } catch (err) {
    // The subpath is missing (@synoi/sraid < 0.3.0 exports only `.` and
    // `./canonicalize`). Fail closed and SAY SO, rather than reporting a
    // signature failure for what is actually a build problem.
    return {
      valid:     false,
      reasons:   ['sraid-verify-browser-unavailable: ' + (err as Error).message],
      algorithm: V2_ALGORITHM,
    }
  }

  const receipt = input.receipt
  const envelope = receipt.attestation as
    | { payloadType?: unknown; payload?: unknown; signatures?: unknown }
    | undefined

  if (envelope === undefined || envelope === null || typeof envelope !== 'object') {
    return { valid: false, reasons: ['missing-attestation'], algorithm: V2_ALGORITHM }
  }

  // (1) Bind the envelope payload to the receipt content core.
  let expected: string
  try {
    expected = sraid.canonicalize(sraid.cdroContentCore(receipt))
  } catch (err) {
    return {
      valid:     false,
      reasons:   ['content-core-uncanonicalizable: ' + (err as Error).message],
      algorithm: V2_ALGORITHM,
    }
  }

  if (envelope.payload !== expected) {
    return {
      valid:             false,
      reasons:           ['payload-core-mismatch'],
      algorithm:         V2_ALGORITHM,
      canonical_payload: expected,
    }
  }

  // (2) Hybrid DSSE verify (both ed25519 AND ml-dsa-65 required). ASYNC here,
  // because WebCrypto Ed25519 verify is Promise-based.
  const res = await sraid.verifyAttestation({
    envelope:            envelope as Parameters<typeof sraid.verifyAttestation>[0]['envelope'],
    ed25519_pub:         input.ed25519_pub,
    ml_dsa_pub:          input.ml_dsa_pub,
    expectedPayloadType: V2_PAYLOAD_TYPE,
  })

  return {
    valid:             res.valid,
    reasons:           res.reasons,
    algorithm:         V2_ALGORITHM,
    payload_type:      typeof envelope.payloadType === 'string' ? envelope.payloadType : undefined,
    canonical_payload: expected,
  }
}
