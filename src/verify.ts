/**
 * @synoi/verify — Node entry (default, `main`).
 *
 * This is the full-capability, Node-only verification surface. It re-exports the
 * browser-safe shared core (./verify-shared) and adds the two verifiers that
 * require a Node runtime:
 *
 *   - verifyReceiptSignature — v1 legacy Ed25519 over the flat CANONICAL_FIELDS
 *     projection, via `node:crypto`.
 *   - verifyReceiptV2 — v2 hybrid DSSE (Ed25519 + ML-DSA-65), via a dynamic
 *     import of @synoi/sraid (whose main entry statically imports node:crypto).
 *
 * It then composes `verifyReceiptByScheme` by injecting BOTH node-bound
 * verifiers into the shared factory, so the dispatcher routes v1, v2, and
 * gap-selfsign exactly as it always has. The public export surface of this
 * module (and therefore of the package `main`) is byte-identical to before the
 * browser split — the same names, the same behavior.
 *
 * For a browser / Chrome-extension / service-worker bundle, import
 * `@synoi/verify/browser` instead: it serves the gap-selfsign + pure surface
 * with NO static node:crypto import, and fails closed on the v1/v2 schemes.
 *
 * CANONICALIZATION discipline (ONE canonical truth, RFC 8785 JCS) is documented
 * on the ported `jcsCanonicalize` in ./verify-shared.
 */

import { verify, createPublicKey } from 'node:crypto'
import {
  canonicalPayload,
  createVerifyReceiptByScheme,
  V2_PAYLOAD_TYPE,
  type VerifyResult,
  type VerifyResultV2,
  type VerifyReceiptV2Input,
} from './verify-shared'

// Re-export the entire browser-safe shared surface so the package `main`
// exposes the same names it always has (canonicalization, gap-selfsign, the
// dispatcher factory, all scheme constants and types, renderReplayChain, …).
// The three node-only value exports below (verifyReceiptSignature,
// verifyReceiptV2, and the composed verifyReceiptByScheme const) are NOT
// exported by ./verify-shared, so there is no star-vs-local name collision.
export * from './verify-shared'

/**
 * Verify a receipt's Ed25519 signature against a PEM-encoded public key.
 *
 * @param payload   the receipt fields (must include all CANONICAL_FIELDS)
 * @param signatureHex  64-byte Ed25519 signature, hex-encoded
 * @param publicKeyPem  the gateway's public key in PEM/SPKI format
 *
 * Returns `{ valid: true }` on a verified signature, or
 * `{ valid: false, reason: '...' }` on any failure. Never throws.
 *
 * NODE-ONLY: uses node:crypto. This is the v1 legacy path. Browser bundles use
 * @synoi/verify/browser, which does not include this function.
 */
export function verifyReceiptSignature(
  payload:       Record<string, unknown>,
  signatureHex:  string,
  publicKeyPem:  string,
): VerifyResult {
  let canonical: string
  try {
    canonical = canonicalPayload(payload)
  } catch (err) {
    return {
      valid:             false,
      canonical_payload: '',
      algorithm:         'Ed25519',
      reason:            (err as Error).message,
    }
  }

  if (!/^[0-9a-fA-F]{128}$/.test(signatureHex)) {
    return {
      valid:             false,
      canonical_payload: canonical,
      algorithm:         'Ed25519',
      reason:            `signature must be 128 hex chars (64 bytes Ed25519); got ${signatureHex.length}`,
    }
  }

  try {
    const keyObj = createPublicKey({ key: publicKeyPem, format: 'pem' })
    const ok = verify(
      null,
      Buffer.from(canonical, 'utf8'),
      keyObj,
      Buffer.from(signatureHex, 'hex'),
    )
    return {
      valid:             ok,
      canonical_payload: canonical,
      algorithm:         'Ed25519',
      reason:            ok ? undefined : 'signature does not match canonical payload under this public key',
    }
  } catch (err) {
    return {
      valid:             false,
      canonical_payload: canonical,
      algorithm:         'Ed25519',
      reason:            (err as Error).message,
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Receipt v2 — hybrid DSSE verification (Ed25519 + ML-DSA-65, both required).
//
// v1 (above) is Ed25519-only over a flat canonical-field projection. v2 carries
// a detached DSSE AttestationEnvelope (the receipt's `attestation` field) signed
// over PAE(payloadType, canonicalize(content_core)). The verifier requires BOTH
// an ed25519 AND an ml-dsa-65 signature to verify — this is the hybrid
// classical + post-quantum guarantee, and it closes the sign-PQ vs verify-PQ
// asymmetry (a v2 receipt missing or carrying an invalid ML-DSA-65 signature is
// REJECTED, not silently accepted on the Ed25519 signature alone).
//
// The canonicalization and the DSSE/PAE verification both come from
// @synoi/sraid — the ONE canonical truth (RFC 8785 JCS). This package does not
// re-implement canonicalize/PAE; divergent canonicalizers are a signature-
// confusion hazard and are deliberately avoided.
//
// @synoi/sraid is ESM-only ("type":"module") AND node-bound (its main entry
// statically imports node:crypto). verifyReceiptV2 is async and dynamic-imports
// @synoi/sraid, so the ESM contact is confined to one function — AND, because
// @synoi/sraid pulls node:crypto, this function is deliberately kept in the
// Node-only entry and OUT of ./verify-shared, so it never enters a browser
// bundle graph.
//
// Runtime floor: under "module":"commonjs" the TypeScript compiler downlevels
// `await import(...)` to `require(...)` of the ESM module. Node loads an ESM
// module from `require()` on Node >= 22 (the require(ESM) interop), and
// @synoi/sraid already declares `engines.node >=22`, so the v2 path inherits
// that Node 22+ floor. The v1 Ed25519-only path keeps the package's >=18 floor.
// ─────────────────────────────────────────────────────────────────────────────

const V2_ALGORITHM = 'DSSE(ed25519+ml-dsa-65)' as const

/**
 * Verify a Receipt v2 hybrid DSSE attestation.
 *
 * Two checks, in order:
 *   1. Content-core bind — recompute `canonicalize(cdroContentCore(receipt))`
 *      and assert it equals the envelope's `payload`. This binds the signed
 *      envelope to the actual receipt body, so a validly-signed envelope cannot
 *      be transplanted onto a different receipt body. Without this, a correct
 *      signature over stale bytes would pass.
 *   2. Hybrid signature verify — delegate to @synoi/sraid `verifyAttestation`,
 *      which requires BOTH ed25519 and ml-dsa-65 to verify over the PAE and
 *      pins the payloadType.
 *
 * Returns `valid: true` only when BOTH checks pass. Never throws.
 *
 * NODE-ONLY: @synoi/sraid's main entry imports node:crypto. Not available in
 * the browser entry (which fails closed on the v2 scheme).
 */
export async function verifyReceiptV2(
  input: VerifyReceiptV2Input,
): Promise<VerifyResultV2> {
  // ESM-only, node-bound package: dynamic import keeps this CJS package
  // buildable/publishable AND keeps the node:crypto contact out of ./verify-shared.
  const sraid = await import('@synoi/sraid')

  const receipt = input.receipt
  const envelope = receipt.attestation as
    | { payloadType?: unknown; payload?: unknown; signatures?: unknown }
    | undefined

  if (
    envelope === undefined ||
    envelope === null ||
    typeof envelope !== 'object'
  ) {
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

  // (2) Hybrid DSSE verify (both ed25519 AND ml-dsa-65 required).
  const res = sraid.verifyAttestation({
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

// ─────────────────────────────────────────────────────────────────────────────
// verifyReceiptByScheme — the ONE fail-closed dispatcher (ADR_019 STEP 5).
//
// Composed from the shared factory with BOTH node-bound verifiers injected, so
// the Node entry routes v1 (legacy Ed25519), v2 (hybrid DSSE), and gap-selfsign
// exactly as before the browser split. The routing table, fail-closed policy,
// and reason strings all live in ./verify-shared's createVerifyReceiptByScheme.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Route a receipt to its verifier by `receipt_scheme`, FAIL-CLOSED. Never throws.
 *
 * See ./verify-shared `createVerifyReceiptByScheme` for the full routing table.
 * This Node binding injects the v1 (node:crypto) and v2 (@synoi/sraid) verifiers,
 * so all three schemes are supported. The browser entry omits both injections,
 * so v1/v2 fail closed there.
 */
export const verifyReceiptByScheme = createVerifyReceiptByScheme({
  legacyVerifier: verifyReceiptSignature,
  v2Verifier:     verifyReceiptV2,
})
