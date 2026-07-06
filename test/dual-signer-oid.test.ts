/**
 * test/dual-signer-oid.test.ts
 *
 * S2.4 re-panel P1 finding F-V: both signer OIDs must be surfaced in verifier
 * output as SEPARATE fields -- never collapsed into one "signer_oid".
 *
 * Tests:
 *   - extractSignerOids returns ed25519_signer_oid and ml_dsa_signer_oid as
 *     distinct fields from explicit receipt fields.
 *   - v1 receipt (signer_oid only, no algorithm suffix) maps to ed25519_signer_oid;
 *     ml_dsa_signer_oid is null.
 *   - Receipt with both fields: both returned separately.
 *   - Receipt with neither: both null.
 *   - renderReceiptResult signer_oids carries both.
 *   - formatReceiptRenderResult emits two distinct signer rows in the output.
 *   - The two OID rows are labeled "Ed25519" and "ML-DSA-65" respectively.
 */

import {
  extractSignerOids,
  renderReceiptResult,
  formatReceiptRenderResult,
} from '../src/render'

let passed = 0
let failed = 0

function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

const ED_OID = 'sha256:' + 'e'.repeat(64)
const ML_OID = 'sha256:' + 'm'.repeat(64)

// ── A: extractSignerOids with both fields ─────────────────────────────────────

const both = extractSignerOids({
  receipt_id:         'rcpt_both',
  ed25519_signer_oid: ED_OID,
  ml_dsa_signer_oid:  ML_OID,
})

ok('extractSignerOids: ed25519_signer_oid returned correctly',
   both.ed25519_signer_oid === ED_OID,
   `got: ${both.ed25519_signer_oid}`)

ok('extractSignerOids: ml_dsa_signer_oid returned correctly',
   both.ml_dsa_signer_oid === ML_OID,
   `got: ${both.ml_dsa_signer_oid}`)

ok('extractSignerOids: ed25519 and ml_dsa are distinct fields (not the same value)',
   both.ed25519_signer_oid !== both.ml_dsa_signer_oid)

// ── B: v1 receipt (signer_oid only) ──────────────────────────────────────────

const v1 = extractSignerOids({
  receipt_id: 'rcpt_v1',
  signer_oid: ED_OID,
})

ok('extractSignerOids v1: signer_oid maps to ed25519_signer_oid',
   v1.ed25519_signer_oid === ED_OID,
   `got: ${v1.ed25519_signer_oid}`)

ok('extractSignerOids v1: ml_dsa_signer_oid is null when absent',
   v1.ml_dsa_signer_oid === null,
   `got: ${v1.ml_dsa_signer_oid}`)

// ── C: neither field present ──────────────────────────────────────────────────

const neither = extractSignerOids({ receipt_id: 'rcpt_none' })

ok('extractSignerOids: both null when no signer OID fields',
   neither.ed25519_signer_oid === null && neither.ml_dsa_signer_oid === null)

// ── D: renderReceiptResult carries both signer OIDs ──────────────────────────

const receipt: Record<string, unknown> = {
  receipt_id:         'rcpt_render_test',
  ed25519_signer_oid: ED_OID,
  ml_dsa_signer_oid:  ML_OID,
}

const result = renderReceiptResult({
  receipt,
  valid:     true,
  algorithm: 'DSSE(ed25519+ml-dsa-65)',
})

ok('renderReceiptResult: signer_oids.ed25519_signer_oid present',
   result.signer_oids.ed25519_signer_oid === ED_OID)

ok('renderReceiptResult: signer_oids.ml_dsa_signer_oid present',
   result.signer_oids.ml_dsa_signer_oid === ML_OID)

// ── E: formatReceiptRenderResult emits two labeled rows ──────────────────────

const formatted = formatReceiptRenderResult(result)

ok('formatted: contains Ed25519 label',
   /Ed25519/i.test(formatted),
   'Ed25519 label missing')

ok('formatted: contains ML-DSA-65 label',
   /ML-DSA-65/i.test(formatted),
   'ML-DSA-65 label missing')

ok('formatted: ed25519 OID value appears in output',
   formatted.includes(ED_OID))

ok('formatted: ml_dsa OID value appears in output',
   formatted.includes(ML_OID))

// The two OID values must appear at different positions (not merged/deduped).
const edPos = formatted.indexOf(ED_OID)
const mlPos = formatted.indexOf(ML_OID)
ok('formatted: ed25519 and ml_dsa OIDs appear at different positions',
   edPos !== mlPos && edPos >= 0 && mlPos >= 0,
   `edPos=${edPos} mlPos=${mlPos}`)

// ── F: partial receipt (only ed25519, no ml_dsa) ─────────────────────────────

const edOnly: Record<string, unknown> = {
  receipt_id:         'rcpt_ed_only',
  ed25519_signer_oid: ED_OID,
}
const resultEdOnly = renderReceiptResult({ receipt: edOnly, valid: true, algorithm: 'Ed25519' })
ok('ed-only receipt: ed25519_signer_oid present',
   resultEdOnly.signer_oids.ed25519_signer_oid === ED_OID)
ok('ed-only receipt: ml_dsa_signer_oid is null',
   resultEdOnly.signer_oids.ml_dsa_signer_oid === null)

const formattedEdOnly = formatReceiptRenderResult(resultEdOnly)
ok('ed-only formatted: "(not reported)" for absent ml_dsa OID',
   formattedEdOnly.includes('(not reported)'))

// ── G: "independent" must not appear ─────────────────────────────────────────

ok('formatted: word "independent" does not appear',
   !formatted.toLowerCase().includes('independent'),
   'VIOLATION: "independent" found in dual-signer render output')

// ── Summary ───────────────────────────────────────────────────────────────────

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed === 0 ? 0 : 1)
