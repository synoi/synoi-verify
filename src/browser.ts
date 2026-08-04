/**
 * @synoi/verify/browser - browser / Chrome-extension / service-worker entry.
 *
 * The default (`main`) entry statically imports `node:crypto` for its v1 legacy
 * path, which does not exist in a browser or service-worker context and breaks
 * any browser bundle that imports the package. This entry is the browser-safe
 * surface: it re-exports ONLY the shared core (./verify-shared), which has NO
 * static node:crypto import and never statically imports @synoi/sraid (whose
 * main entry is itself node:crypto-bound).
 *
 * WHAT WORKS HERE (SHIPPED):
 *   - v2 hybrid DSSE verification (verifyReceiptV2Browser) - Ed25519 AND
 *     ML-DSA-65 both required, via @synoi/sraid/verify-browser. THIS IS THE TIER
 *     EVERY GATEWAY RECEIPT USES: engine.ts stamps
 *     `receipt_scheme: 'synoi.receipt/v2'` on every receipt it mints, so before
 *     this was wired the browser build could not verify a single real one.
 *   - gap-selfsign verification (verifyGapSelfSignedReceipt) - single Ed25519
 *     via @synoi/gap, which is @noble-only and fully browser-safe. This is the
 *     tier the lite self-host daemon and the AI Receipt extension actually use.
 *   - the pure surface: canonicalPayload, jcsCanonicalize, renderReplayChain,
 *     all scheme constants and result/input types.
 *   - verifyReceiptByScheme - routes v2 and gap-selfsign fully; v1 fails closed.
 *
 * WHAT DOES NOT (fail-closed / omitted):
 *   - verifyReceiptSignature (v1 legacy, node:crypto) - OMITTED from this entry.
 *     A scheme-less legacy-v1 receipt routed through verifyReceiptByScheme fails
 *     closed with reason `legacy-v1-not-available-in-this-build`. v1 is the
 *     older flat CANONICAL_FIELDS projection; it has no browser-safe verifier
 *     because node:crypto is its only backend here, and unlike v2 there is no
 *     demand for it on a browser surface.
 *
 * NOTE ON THE v2 IMPORT EDGE: the browser v2 verifier lives in its own module
 * (./verify-v2-browser) rather than behind a flag in ./verify. A bundler follows
 * the module graph, not the control flow, so a single `import '@synoi/sraid'`
 * edge anywhere reachable from this entry would drag node:crypto into the bundle
 * regardless of whether the branch is ever taken. Two files, two graphs, is the
 * only separation a bundler respects. test/browser-v2.test.ts bundles this entry
 * for platform:'browser' and asserts ZERO `node:` references, so that separation
 * is checked rather than assumed.
 *
 * Omitting verifyReceiptSignature (rather than shipping a fail-closed stub)
 * makes its absence a COMPILE-TIME signal: a consumer that genuinely needs v1
 * learns it at build time, not via a runtime surprise. The dispatcher still
 * fails closed at runtime for callers that route arbitrary receipts whose scheme
 * is not known until execution.
 */

import { createVerifyReceiptByScheme } from './verify-shared'
import { verifyReceiptV2Browser } from './verify-v2-browser'

// Re-export the full browser-safe shared surface: pure canonicalization,
// gap-selfsign, renderReplayChain, all scheme constants and types, and the
// createVerifyReceiptByScheme factory. This intentionally does NOT include
// verifyReceiptSignature (v1) - that lives only on the Node ./verify entry,
// because it is node:crypto-bound.
export * from './verify-shared'

/**
 * The v2 hybrid DSSE verifier, browser edition. Same two checks, same order and
 * the same reason strings as the Node `verifyReceiptV2`; only the crypto backend
 * differs (WebCrypto + @noble in place of node:crypto). Exported by name so a
 * caller who already knows a receipt is v2 can skip the dispatcher.
 */
export { verifyReceiptV2Browser } from './verify-v2-browser'

/**
 * Route a receipt to its verifier by `receipt_scheme`, FAIL-CLOSED. Never throws.
 *
 * Browser binding: the v2 verifier IS injected (the browser-safe one), so the v2
 * and gap-selfsign schemes are both fully supported. Only the v1 legacy
 * (node:crypto) verifier is absent, and a scheme-less legacy-v1 receipt fails
 * closed with an honest build-capability reason. See ./verify-shared
 * `createVerifyReceiptByScheme` for the full routing table.
 */
export const verifyReceiptByScheme = createVerifyReceiptByScheme({
  v2Verifier: verifyReceiptV2Browser,
})
