/**
 * test/verify-v2-dist.smoke.cjs — published-artifact canary.
 *
 * Proves the COMPILED CommonJS dist (dist/verify.js) actually loads the
 * ESM-only @synoi/sraid and runs the v2 path under PLAIN node (not tsx). This
 * is the canary that no synchronous top-level ESM require leaked into the
 * published surface: under "module":"commonjs" tsc downlevels the async
 * `await import('@synoi/sraid')` to a require(ESM), which Node loads on >=22
 * (the floor @synoi/sraid mandates).
 *
 * Run AFTER `tsc` has emitted dist/. Resolves @synoi/sraid by absolute path via
 * a minimal require shim (this repo has no installed @synoi/* in this isolated
 * worktree). Node >= 22 only.
 *
 *   node test/verify-v2-dist.smoke.cjs
 */

const path = require('node:path')
const Module = require('node:module')

// Resolve the bare specifier '@synoi/sraid' to the sibling repo's built dist.
// Sibling layout: <...>/synoi-verify/<workspace>/  ->  <...>/synoi-sraid
const SRAID_INDEX = path.resolve(__dirname, '../../../../../synoi-sraid/dist/index.js')
const origResolve = Module._resolveFilename
Module._resolveFilename = function (request, ...rest) {
  if (request === '@synoi/sraid') return SRAID_INDEX
  return origResolve.call(this, request, ...rest)
}

const { generateKeyPairSync, sign } = require('node:crypto')

async function run() {
  // Load @synoi/sraid via require(ESM) — the SAME interop the compiled dist uses
  // (tsc downlevels its `await import` to require under "module":"commonjs").
  const sraid = require('@synoi/sraid')
  const { canonicalize, cdroContentCore, pae } = sraid
  const { ml_dsa65 } = require(
    path.resolve(__dirname, '../../../../../synoi-sraid/node_modules/@noble/post-quantum/ml-dsa.js')
  )

  // Load the COMPILED dist (not src) — this is the published artifact.
  const dist = require('../dist/verify.js')
  if (typeof dist.verifyReceiptV2 !== 'function') {
    console.log('FAIL dist: verifyReceiptV2 not exported from compiled dist')
    process.exit(1)
  }

  const { privateKey: edPriv, publicKey: edPubKey } = generateKeyPairSync('ed25519')
  const edSpki = edPubKey.export({ type: 'spki', format: 'der' })
  const ed25519_pub = new Uint8Array(edSpki.subarray(edSpki.length - 32))
  const mlKeys = ml_dsa65.keygen(new Uint8Array(32).fill(7))

  const receipt = {
    type: 'synoi:decision_receipt',
    cof_version: '1.0',
    tenant_id: 'founder',
    created_at_ms: 1747584000000,
    created_by: 'sha256:' + 'a'.repeat(64),
    receipt_scheme: dist.RECEIPT_SCHEME_V2,
    body: { decision: 'allow', settlement: { cost: { amount: 1200 } } },
  }
  const payload = canonicalize(cdroContentCore(receipt))
  const message = pae(dist.V2_PAYLOAD_TYPE, payload)
  receipt.attestation = {
    payloadType: dist.V2_PAYLOAD_TYPE,
    payload,
    signatures: [
      { alg: 'ed25519', sig: Buffer.from(sign(null, Buffer.from(message), edPriv)).toString('base64') },
      { alg: 'ml-dsa-65', sig: Buffer.from(ml_dsa65.sign(message, mlKeys.secretKey)).toString('base64') },
    ],
  }

  const okRes = await dist.verifyReceiptV2({ receipt, ed25519_pub, ml_dsa_pub: mlKeys.publicKey })
  if (!okRes.valid) { console.log('FAIL dist: valid v2 receipt did not verify', okRes.reasons); process.exit(1) }

  // PQ-asymmetry under the published artifact.
  const stripped = JSON.parse(JSON.stringify(receipt))
  stripped.attestation.signatures = stripped.attestation.signatures.filter((s) => s.alg !== 'ml-dsa-65')
  const badRes = await dist.verifyReceiptV2({ receipt: stripped, ed25519_pub, ml_dsa_pub: mlKeys.publicKey })
  if (badRes.valid || !badRes.reasons.includes('missing-ml-dsa-65')) {
    console.log('FAIL dist: stripped ml-dsa-65 was not rejected', badRes); process.exit(1)
  }

  console.log('OK   dist: compiled CJS loads ESM @synoi/sraid and runs v2 path (node ' + process.version + ')')
  console.log('OK   dist: PQ-asymmetry holds in published artifact (stripped ml-dsa-65 rejected)')
  console.log('\n2 passed, 0 failed')
}

run().catch((e) => {
  console.log('FAIL dist:', e && (e.code || e.message))
  if (e && e.stack) console.log(e.stack.split('\n').slice(0, 5).join('\n'))
  process.exit(1)
})
