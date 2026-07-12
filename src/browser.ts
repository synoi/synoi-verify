/**
 * @synoi/verify/browser — browser / Chrome-extension / service-worker entry.
 *
 * The default (`main`) entry statically imports `node:crypto` for its v1 legacy
 * path, which does not exist in a browser or service-worker context and breaks
 * any browser bundle that imports the package. This entry is the browser-safe
 * surface: it re-exports ONLY the shared core (./verify-shared), which has NO
 * static node:crypto import and never statically imports @synoi/sraid (whose
 * main entry is itself node:crypto-bound).
 *
 * WHAT WORKS HERE (SHIPPED):
 *   - gap-selfsign verification (verifyGapSelfSignedReceipt) — single Ed25519
 *     via @synoi/gap, which is @noble-only and fully browser-safe. This is the
 *     tier the lite self-host daemon and the AI Receipt extension actually use.
 *   - the pure surface: canonicalPayload, jcsCanonicalize, renderReplayChain,
 *     all scheme constants and result/input types.
 *   - verifyReceiptByScheme — routes gap-selfsign fully; v1 and v2 fail closed.
 *
 * WHAT DOES NOT (fail-closed / omitted):
 *   - verifyReceiptSignature (v1 legacy, node:crypto) — OMITTED from this entry.
 *   - verifyReceiptV2 (v2 hybrid DSSE) — OMITTED. It delegates to @synoi/sraid,
 *     whose main entry statically imports node:crypto (Ed25519 verify is
 *     node-only and cdroContentCore hashes via node:crypto). Bringing v2 to the
 *     browser is BLOCKED on @synoi/sraid exposing a browser-safe verify entry;
 *     that is a separate, cross-repo change. Until then, a v2 receipt routed
 *     through verifyReceiptByScheme fails closed with reason
 *     `v2-not-supported-in-browser-build`, and a scheme-less legacy-v1 receipt
 *     with reason `legacy-v1-not-available-in-this-build`.
 *
 * Omitting verifyReceiptV2 and verifyReceiptSignature (rather than shipping
 * fail-closed stubs) makes their absence a COMPILE-TIME signal: a consumer that
 * genuinely needs v1 or v2 learns it at build time, not via a runtime surprise.
 * The dispatcher still fails closed at runtime for callers that route arbitrary
 * receipts whose scheme is not known until execution.
 */

import { createVerifyReceiptByScheme } from './verify-shared'

// Re-export the full browser-safe shared surface: pure canonicalization,
// gap-selfsign, renderReplayChain, all scheme constants and types, and the
// createVerifyReceiptByScheme factory. This intentionally does NOT include
// verifyReceiptSignature (v1) or verifyReceiptV2 (v2) — those live only on the
// Node ./verify entry, because both are node:crypto-bound.
export * from './verify-shared'

/**
 * Route a receipt to its verifier by `receipt_scheme`, FAIL-CLOSED. Never throws.
 *
 * Browser binding: NEITHER node-bound verifier is injected, so the gap-selfsign
 * scheme is fully supported while the v1 (legacy Ed25519 / node:crypto) and v2
 * (hybrid DSSE / @synoi/sraid) schemes fail closed with an honest
 * build-capability reason. See ./verify-shared `createVerifyReceiptByScheme`
 * for the full routing table.
 */
export const verifyReceiptByScheme = createVerifyReceiptByScheme({})
