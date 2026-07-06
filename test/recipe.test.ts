/**
 * test/recipe.test.ts — @synoi/verify Decision Recipe verifier.
 *
 * Verifies the verifier-side functionality matches the gateway side
 * (synoi-gateway Sprint 6) so auditors can independently confirm that
 * a gateway is running an authentic SynOI-signed recipe.
 */

import { generateKeyPairSync, sign } from 'node:crypto'
import { verifySynoiRecipe } from '../src/recipe'

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

// Generate an Ed25519 keypair to act as SynOI's recipes signing key.
const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const pubKeyPem = publicKey.export({ type: 'spki', format: 'pem' }) as string
const pubKeyDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer
const pubKeyRawB64 = pubKeyDer.subarray(pubKeyDer.length - 32).toString('base64')

function sortKeys(o: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const k of Object.keys(o).sort()) {
    const v = o[k]
    out[k] = (v && typeof v === 'object' && !Array.isArray(v))
      ? sortKeys(v as Record<string, unknown>)
      : v
  }
  return out
}

const payload = {
  recipe_id:     'routing',
  version:       'test-r1',
  schema:        1,
  data:          { hello: 'world' },
  generated_at:  1747584000000,
  refresh_after: 1747670400000,
}
const canonical_payload = JSON.stringify(sortKeys(payload))
const sigB64 = sign(null, Buffer.from(canonical_payload, 'utf-8'), privateKey).toString('base64')

const signed = {
  payload,
  signature:        sigB64,
  signer_key_id:    'synoi-recipes-v1',
  canonical_payload,
}

// 1. PEM pubkey verification
{
  const r = verifySynoiRecipe(signed, pubKeyPem)
  ok('PEM pubkey: signature verifies', r.valid)
  ok('PEM pubkey: recipe_id surfaced', r.recipe_id === 'routing')
  ok('PEM pubkey: version surfaced',    r.version === 'test-r1')
  ok('PEM pubkey: signer_key_id surfaced', r.signer_key_id === 'synoi-recipes-v1')
}

// 2. Raw-32-byte pubkey
{
  const r = verifySynoiRecipe(signed, pubKeyRawB64)
  ok('raw32 pubkey: signature verifies', r.valid)
}

// 3. Tampered signature
{
  const buf = Buffer.from(sigB64, 'base64')
  buf[0] ^= 0xff
  const tamperedSig = { ...signed, signature: buf.toString('base64') }
  const r = verifySynoiRecipe(tamperedSig, pubKeyPem)
  ok('tampered signature: invalid', !r.valid)
}

// 4. Canonical payload mismatch (forked gateway claims a different payload
//    than the one that was signed)
{
  const liedPayload = { ...payload, data: { hello: 'attacker' } }
  const forked = { ...signed, payload: liedPayload }
  const r = verifySynoiRecipe(forked, pubKeyPem)
  ok('canonical mismatch: invalid',
     !r.valid)
  ok('canonical mismatch: reason cites mismatch',
     (r.reason ?? '').toLowerCase().includes('canonical'))
}

// 5. Wrong pubkey
{
  const { publicKey: otherPub } = generateKeyPairSync('ed25519')
  const otherPem = otherPub.export({ type: 'spki', format: 'pem' }) as string
  const r = verifySynoiRecipe(signed, otherPem)
  ok('wrong pubkey: invalid', !r.valid)
}

// 6. Wrong signature shape (32 bytes)
{
  const badSig = { ...signed, signature: Buffer.alloc(32, 0).toString('base64') }
  const r = verifySynoiRecipe(badSig, pubKeyPem)
  ok('32-byte signature: invalid with shape reason',
     !r.valid && (r.reason ?? '').includes('64'))
}

// 7. Malformed signed-recipe (missing fields)
{
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const r = verifySynoiRecipe({} as any, pubKeyPem)
  ok('empty signed-recipe: invalid', !r.valid)
}

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed === 0 ? 0 : 1)
