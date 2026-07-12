/**
 * test/browser-entry.test.ts — proves @synoi/verify/browser is browser-safe.
 *
 * BACKGROUND: the @synoi/verify default entry statically imports `node:crypto`
 * (for its legacy receipt-v1 path), which does not exist in a browser /
 * Chrome-extension / service-worker context and breaks any browser bundle that
 * imports the package. The AI Receipt Chrome extension hit exactly this wall
 * and had to route all verification through @synoi/gap directly. The new
 * `@synoi/verify/browser` subpath (src/browser.ts -> src/verify-shared.ts) is
 * the fix: the gap-selfsign + pure verification surface with NO static
 * node:crypto import.
 *
 * This test asserts two things, modeled on the AI Receipt repo's bundle scan:
 *
 *   A. BUNDLE SCAN (the load-clean proof). esbuild-bundle the browser entry for
 *      platform:'browser', following the FULL transitive graph (including the
 *      dynamic import of @synoi/gap), and assert the output contains ZERO
 *      `node:` references. A control bundle of the NODE entry proves the scan
 *      discriminates: the node entry DOES pull node:crypto and fails to bundle
 *      for the browser, exactly the breakage the browser entry avoids.
 *
 *   B. FUNCTIONAL. The browser entry actually verifies a gap-selfsign receipt,
 *      routes it through its dispatcher, and fails CLOSED (with honest,
 *      build-capability reasons) on the two node-bound schemes (v1 legacy and
 *      v2 hybrid DSSE) it deliberately does not carry. It also does NOT export
 *      the two node-only verifiers, so their absence is a compile-time signal.
 *
 * CLAIMS DISCIPLINE: no vector, no claim. This is that vector. NO em dashes.
 *
 *   yarn test  (or: tsx test/browser-entry.test.ts)
 */

import { build } from 'esbuild'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { receipt, generateReceiptKeyPair } from '@synoi/gap'

import * as browser from '../src/browser'
import * as nodeEntry from '../src/verify'

const HERE = dirname(fileURLToPath(import.meta.url))
const SRC = join(HERE, '..', 'src')

let passed = 0
let failed = 0

function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

/**
 * Bundle one entry for the browser and return { errors, text }. `format:'iife'`
 * forces esbuild to INLINE dynamic import() targets (so @synoi/gap is followed
 * into the output and scanned), and `platform:'browser'` makes node builtins
 * UNRESOLVABLE rather than silently external, so a stray node:crypto import
 * surfaces as either a build error or a literal `node:` reference in the output.
 */
async function bundleForBrowser(entry: string): Promise<{ errors: number; text: string; messages: string }> {
  try {
    const result = await build({
      entryPoints: [join(SRC, entry)],
      bundle:      true,
      write:       false,
      format:      'iife',
      platform:    'browser',
      logLevel:    'silent',
      // Keep the scan honest: do not let a define/alias hide a node import.
    })
    const text = result.outputFiles.map((f) => f.text).join('\n')
    return { errors: 0, text, messages: '' }
  } catch (err) {
    const e = err as { errors?: Array<{ text: string }> }
    const messages = (e.errors ?? []).map((m) => m.text).join(' | ')
    return { errors: (e.errors ?? []).length || 1, text: '', messages }
  }
}

/** Count `node:` builtin references (node:crypto, node:fs, ...) in bundle text. */
function countNodeRefs(text: string): { total: number; crypto: number } {
  const total  = (text.match(/node:[a-z_/]+/g) ?? []).length
  const crypto = (text.match(/node:crypto/g) ?? []).length
  return { total, crypto }
}

async function main(): Promise<void> {
  // ── A. BUNDLE SCAN ─────────────────────────────────────────────────────────
  const browserBundle = await bundleForBrowser('browser.ts')
  ok('browser entry bundles for platform:browser with ZERO errors',
     browserBundle.errors === 0, browserBundle.messages)

  const browserRefs = countNodeRefs(browserBundle.text)
  ok('browser bundle contains ZERO node:crypto references',
     browserRefs.crypto === 0, `found ${browserRefs.crypto}`)
  ok('browser bundle contains ZERO node: builtin references of any kind',
     browserRefs.total === 0, `found ${browserRefs.total} node: refs`)
  // Sanity: the bundle is non-trivial (the scan is not vacuously passing on an
  // empty output) and actually pulled the gap-selfsign verifier path in.
  ok('browser bundle is non-empty (real graph was bundled)',
     browserBundle.text.length > 1000, `${browserBundle.text.length} bytes`)

  // CONTROL: the NODE entry must NOT be browser-clean. If this ever bundles
  // clean, the scan above has stopped discriminating and proves nothing.
  const nodeBundle = await bundleForBrowser('index.ts')
  const nodeIsBroken =
    nodeBundle.errors > 0 || countNodeRefs(nodeBundle.text).crypto > 0
  ok('CONTROL: node default entry is NOT browser-safe (pulls node:crypto)',
     nodeIsBroken,
     nodeBundle.errors === 0 ? 'node entry unexpectedly bundled clean' : nodeBundle.messages)
  ok('CONTROL: node entry breakage names a node: builtin (discriminator works)',
     /node:/.test(nodeBundle.messages) || countNodeRefs(nodeBundle.text).crypto > 0,
     nodeBundle.messages)

  // ── B. FUNCTIONAL ──────────────────────────────────────────────────────────
  // The browser entry omits the two node-only verifiers entirely: their
  // absence is a compile-time signal, not a runtime surprise.
  ok('browser entry does NOT export verifyReceiptSignature (v1, node:crypto)',
     (browser as Record<string, unknown>)['verifyReceiptSignature'] === undefined)
  ok('browser entry does NOT export verifyReceiptV2 (v2, @synoi/sraid node-bound)',
     (browser as Record<string, unknown>)['verifyReceiptV2'] === undefined)
  // The pure + gap-selfsign surface IS present.
  ok('browser entry exports verifyGapSelfSignedReceipt',
     typeof browser.verifyGapSelfSignedReceipt === 'function')
  ok('browser entry exports verifyReceiptByScheme',
     typeof browser.verifyReceiptByScheme === 'function')
  ok('browser entry exports the pure canonicalization + render surface',
     typeof browser.canonicalPayload === 'function' &&
     typeof browser.jcsCanonicalize === 'function' &&
     typeof browser.renderReplayChain === 'function')

  // A real gap-selfsign receipt verifies through the browser entry.
  const keyPair = generateReceiptKeyPair('key:browser-operator')
  const r = receipt({
    subjectKind: 'capability_invocation',
    subjectOid:  'sha256:' + '11'.repeat(32),
    initiator:   { actor_oid: 'oid-' + '22'.repeat(32), actor_type: 'human_user' },
  }, { keyPair })

  const direct = await browser.verifyGapSelfSignedReceipt({
    receipt:     r.envelope as unknown as Record<string, unknown>,
    ed25519_pub: keyPair.publicKey,
  })
  ok('browser: valid gap-selfsign receipt verifies VALID', direct.valid, direct.reason)

  const disp = await browser.verifyReceiptByScheme({
    receipt:         r.envelope as unknown as Record<string, unknown>,
    gap_ed25519_pub: keyPair.publicKey,
  })
  ok('browser: dispatcher routes gap-selfsign scheme and verifies VALID',
     disp.valid && disp.scheme === 'gap-selfsign', disp.reasons.join(', '))

  const dispTampered = await browser.verifyReceiptByScheme({
    receipt: { ...r.envelope, body: { ...r.envelope.body, status: 'denied' as const } } as unknown as Record<string, unknown>,
    gap_ed25519_pub: keyPair.publicKey,
  })
  ok('browser: dispatcher rejects a tampered gap-selfsign receipt (not a false pass)',
     dispTampered.valid === false && dispTampered.scheme === 'gap-selfsign')

  // v2 scheme fails CLOSED in the browser build, even WITH both keys supplied
  // (the v2 verifier is node-bound and was not injected).
  const v2Attempt = await browser.verifyReceiptByScheme({
    receipt:     { receipt_scheme: browser.RECEIPT_SCHEME_V2, attestation: {} } as Record<string, unknown>,
    ed25519_pub: new Uint8Array(32),
    ml_dsa_pub:  new Uint8Array(1952),
  })
  ok('browser: v2 scheme fails closed with an honest build-capability reason',
     v2Attempt.valid === false &&
     v2Attempt.scheme === 'rejected' &&
     v2Attempt.reasons.includes('v2-not-supported-in-browser-build'),
     v2Attempt.reasons.join(', '))

  // Scheme-less legacy-v1: fails closed even when the caller opts in, because
  // the node:crypto verifier is not present in this build.
  const v1OptIn = await browser.verifyReceiptByScheme({
    receipt:       {} as Record<string, unknown>,
    allowLegacyV1: true,
    legacy:        { signatureHex: '00'.repeat(64), publicKeyPem: '-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----' },
  })
  ok('browser: opted-in legacy v1 fails closed (verifier not in this build)',
     v1OptIn.valid === false &&
     v1OptIn.scheme === 'rejected' &&
     v1OptIn.reasons.includes('legacy-v1-not-available-in-this-build'),
     v1OptIn.reasons.join(', '))

  const v1NoOptIn = await browser.verifyReceiptByScheme({ receipt: {} as Record<string, unknown> })
  ok('browser: scheme-less receipt without opt-in is rejected (fail-closed default)',
     v1NoOptIn.valid === false &&
     v1NoOptIn.reasons.includes('missing-receipt-scheme-and-legacy-v1-not-allowed'))

  // ── C. ADDITIVITY: the NODE entry is unchanged and still full-capability. ──
  ok('node entry STILL exports verifyReceiptSignature (v1 unchanged)',
     typeof nodeEntry.verifyReceiptSignature === 'function')
  ok('node entry STILL exports verifyReceiptV2 (v2 unchanged)',
     typeof nodeEntry.verifyReceiptV2 === 'function')
  const nodeDisp = await nodeEntry.verifyReceiptByScheme({
    receipt:         r.envelope as unknown as Record<string, unknown>,
    gap_ed25519_pub: keyPair.publicKey,
  })
  ok('node entry dispatcher still verifies the same gap-selfsign receipt VALID',
     nodeDisp.valid && nodeDisp.scheme === 'gap-selfsign', nodeDisp.reasons.join(', '))

  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed > 0 ? 1 : 0)
}

main().catch((err) => {
  process.stdout.write(`FATAL ${(err as Error).stack ?? String(err)}\n`)
  process.exit(1)
})
