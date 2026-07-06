/**
 * bundle.ts - thin RE-EXPORT of @synoi/verify-core (ADR_019 STEP 8).
 *
 * There is now ONE offline evidence-bundle verifier, in @synoi/verify-core. This
 * module used to carry a full copy; it no longer does. It re-exports the ONE
 * function so the @synoi/verify public API and CLI are unchanged, while the gateway
 * self-verify imports the SAME function. Two copies cannot mechanically disagree
 * when there is only one.
 *
 * ASYNC WRAPPER. @synoi/verify-core (like @synoi/sraid) is ESM-only; @synoi/verify
 * is CommonJS. verifyEvidenceBundle stays ASYNC here (public API stability - the
 * CLI and downstream callers already await it) and dynamic-imports the ESM core,
 * then calls its SYNCHRONOUS verifier. The v1 receipt-verify paths in verify.ts are
 * unaffected.
 *
 * BUNDLE v2 + FAIL-CLOSED. The re-exported verifier accepts ONLY
 * synoi-evidence-bundle-v2 (completeness flags folded into the signed
 * content_digest) and HARD-REJECTS v1 bundles with reason
 * 'unsupported-bundle-version'. See @synoi/verify-core for the full contract.
 *
 * ONE CANONICAL TRUTH. Canonicalization (RFC 8785 JCS), cdroContentCore, and
 * hybrid DSSE verification come from @synoi/sraid, via @synoi/verify-core. No
 * divergent canonicalizer is defined here.
 *
 * NO em dashes. NO AI attribution.
 */

import type {
  EvidenceBundle as CoreEvidenceBundle,
  BundleVerifyResult as CoreBundleVerifyResult,
} from '@synoi/verify-core'

// Re-export the public types + constants unchanged so importers of @synoi/verify
// see a stable surface.
export type {
  EvidenceBundle,
  EvidenceBundleManifest,
  BundleHonesty,
  PublicKeyBundle,
  BundleVerifyReason,
  BundleVerifyResult,
  ReceiptVerifyDetail,
  AbsenceVerifyDetail,
} from '@synoi/verify-core'

export {
  EVIDENCE_BUNDLE_VERSION,
  GAP_RECEIPT_PAYLOAD_TYPE,
  STATE_ABSENCE_PAYLOAD_TYPE,
} from '@synoi/verify-core'

type VerifyCoreModule = typeof import('@synoi/verify-core')

/**
 * Verify an evidence bundle OFFLINE. Fail-closed, never throws. Delegates to the
 * ONE verifier in @synoi/verify-core (dynamic-imported because it is ESM-only and
 * this package is CommonJS). Public signature stays async for API stability; the
 * underlying core verifier is synchronous.
 */
export async function verifyEvidenceBundle(bundle: CoreEvidenceBundle): Promise<CoreBundleVerifyResult> {
  const core = (await import('@synoi/verify-core')) as VerifyCoreModule
  return core.verifyEvidenceBundle(bundle)
}
