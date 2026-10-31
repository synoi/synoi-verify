/**
 * test/unsigned-degraded-warning.test.ts — a legacy receipt's `degraded` value
 * is flagged as unsigned.
 *
 * A receipt the hosted gateway signed before #253 has no `degraded` in its
 * signed bytes. Founder decision (2026-10-30): such a receipt still verifies
 * (form 'legacy-without-degraded', as the gateway's own GET /verify/:id
 * fallback does), but when it CARRIES a `degraded` value the result must say,
 * machine-readably and in plain words, that the value was not signed.
 *
 *   - legacy + degraded true   -> valid, warning UNSIGNED_DEGRADED
 *   - legacy + degraded false  -> valid, warning UNSIGNED_DEGRADED
 *   - legacy without degraded  -> valid, no warning
 *   - current form             -> valid, no warning
 *   - tampered degraded on a current receipt -> INVALID (not a warning)
 *
 * The signer is an independent mirror of the gateway (field list copied, not
 * imported from ../src). Keys are throwaway test-fixture keys made per run.
 */

import { generateKeyPairSync, sign } from 'node:crypto'
import {
  verifyReceiptSignature,
  verifyReceiptByScheme,
  UNSIGNED_DEGRADED,
} from '../src/verify'
import type { VerifyResult } from '../src/verify'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: unknown): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else {
    failed++
    const d = detail === undefined ? '' : ' - ' + (typeof detail === 'string' ? detail : JSON.stringify(detail))
    process.stdout.write(`FAIL ${label}${d}\n`)
  }
}

// synoi-gateway src/verify-router.ts CANONICAL_FIELDS + canonicalPayload.
const GATEWAY_FIELDS = [
  'action_class', 'action_payload_hash', 'approver_ref', 'cited_oracle_inputs',
  'decision', 'decision_subject_oid', 'degraded', 'gateway_manifest_sha256',
  'grant_oid', 'intent_oid', 'oid_hex', 'policy_versions', 'prev', 'receipt_id',
  'recorded_at', 'replayed_after', 'risk_level', 'rule_id', 'sequence',
  'session_id', 'state_sha256', 'status', 'subject_oid', 'target_class',
  'target_id', 'tenant_id',
]
function gatewayCanonical(payload: Record<string, unknown>): string {
  const obj: Record<string, unknown> = {}
  for (const k of [...GATEWAY_FIELDS].sort()) {
    if (payload[k] !== undefined && payload[k] !== null) obj[k] = payload[k]
  }
  return JSON.stringify(obj)
}
const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string
const gwSign = (payload: Record<string, unknown>): string =>
  sign(null, Buffer.from(gatewayCanonical(payload), 'utf8'), privateKey).toString('hex')

function unsignedDegradedWarnings(r: VerifyResult): NonNullable<VerifyResult['warnings']> {
  return (r.warnings ?? []).filter((w) => w.code === 'UNSIGNED_DEGRADED')
}

// A pre-#253 receipt: signed WITHOUT degraded.
const legacy: Record<string, unknown> = {
  receipt_id: 'rcpt_legacy_warn', tenant_id: 'tenant-old', decision: 'allow',
  action_class: 'A', risk_level: 'low', oid_hex: '21'.repeat(32), recorded_at: 1780000000000,
  sequence: 9, gateway_manifest_sha256: '22'.repeat(32),
}
const legacySig = gwSign(legacy)

// ── constant ──────────────────────────────────────────────────────────────────
ok('UNSIGNED_DEGRADED is the stable code string', UNSIGNED_DEGRADED === 'UNSIGNED_DEGRADED', UNSIGNED_DEGRADED)

// ── legacy + degraded true / false ───────────────────────────────────────────
for (const value of [true, false] as const) {
  const r = verifyReceiptSignature({ ...legacy, degraded: value }, legacySig, pubPem)
  ok(`legacy + degraded ${value}: verifies via the legacy form`,
     r.valid && r.form === 'legacy-without-degraded', r)
  const w = unsignedDegradedWarnings(r)
  ok(`legacy + degraded ${value}: exactly one UNSIGNED_DEGRADED warning`, w.length === 1, r.warnings)
  ok(`legacy + degraded ${value}: the warning names the field`, w[0]?.field === 'degraded', w[0])
  ok(`legacy + degraded ${value}: plain-text message says it was not signed and must not be trusted`,
     typeof w[0]?.message === 'string' &&
     w[0]!.message.includes('signed before `degraded` was included in the signature') &&
     w[0]!.message.includes(`value (${value}) was not signed and must not be trusted`), w[0]?.message)
  ok(`legacy + degraded ${value}: unsigned_canonical_fields still lists degraded`,
     r.unsigned_canonical_fields?.includes('degraded') === true, r.unsigned_canonical_fields)
}

// A SQLite row export carries 0/1; a displayed value is still unsigned.
{
  const r = verifyReceiptSignature({ ...legacy, degraded: 1 }, legacySig, pubPem)
  ok('legacy + degraded 1 (row export): valid with UNSIGNED_DEGRADED',
     r.valid && unsignedDegradedWarnings(r).length === 1, r)
}

// ── legacy without degraded ──────────────────────────────────────────────────
{
  const r = verifyReceiptSignature(legacy, legacySig, pubPem)
  ok('legacy without degraded: verifies via the legacy form',
     r.valid && r.form === 'legacy-without-degraded', r)
  ok('legacy without degraded: warnings is an empty array', Array.isArray(r.warnings) && r.warnings.length === 0, r.warnings)
  const rNull = verifyReceiptSignature({ ...legacy, degraded: null }, legacySig, pubPem)
  ok('legacy with degraded: null (no value): no warning',
     rNull.valid && Array.isArray(rNull.warnings) && rNull.warnings.length === 0, rNull)
}

// ── current form ─────────────────────────────────────────────────────────────
for (const value of [true, false] as const) {
  const current = { ...legacy, receipt_id: `rcpt_current_${value}`, degraded: value }
  const r = verifyReceiptSignature(current, gwSign(current), pubPem)
  ok(`current form (degraded ${value}): verifies as current`, r.valid && r.form === 'current', r)
  ok(`current form (degraded ${value}): no warning`, Array.isArray(r.warnings) && r.warnings.length === 0, r.warnings)
}
{
  // A current receipt signed with degraded:false whose export omits it.
  const current = { ...legacy, receipt_id: 'rcpt_current_omitted', degraded: false }
  const sig = gwSign(current)
  const exported = { ...current }
  delete exported.degraded
  const r = verifyReceiptSignature(exported, sig, pubPem)
  ok('current form, degraded:false omitted from export: current, no warning',
     r.valid && r.form === 'current' && r.warnings?.length === 0, r)
}

// ── tampered degraded on a current receipt: fails, never warns ───────────────
for (const value of [true, false] as const) {
  const current = { ...legacy, receipt_id: `rcpt_tamper_${value}`, degraded: value }
  const sig = gwSign(current)
  const r = verifyReceiptSignature({ ...current, degraded: !value }, sig, pubPem)
  ok(`tamper: current receipt degraded ${value} -> ${!value} is INVALID`, !r.valid, r)
  ok(`tamper: current receipt degraded ${value} -> ${!value} carries no warning (it is a failure, not a warning)`,
     unsignedDegradedWarnings(r).length === 0, r.warnings)
  const stripped = { ...current }
  delete stripped.degraded
  if (value) {
    const rs = verifyReceiptSignature(stripped, sig, pubPem)
    ok('tamper: stripping degraded:true from a current receipt is INVALID', !rs.valid, rs)
  }
}

// ── the dispatcher surfaces the warning at the top level ────────────────────
async function dispatcher(): Promise<void> {
  const r = await verifyReceiptByScheme({
    receipt: { ...legacy, degraded: true },
    allowLegacyV1: true,
    legacy: { signatureHex: legacySig, publicKeyPem: pubPem },
  })
  ok('verifyReceiptByScheme v1: legacy + degraded is valid', r.valid && r.scheme === 'v1', r)
  ok('verifyReceiptByScheme v1: top-level warnings carry UNSIGNED_DEGRADED',
     r.warnings?.some((w) => w.code === 'UNSIGNED_DEGRADED') === true, r.warnings)
  const clean = await verifyReceiptByScheme({
    receipt: legacy,
    allowLegacyV1: true,
    legacy: { signatureHex: legacySig, publicKeyPem: pubPem },
  })
  ok('verifyReceiptByScheme v1: legacy without degraded has no warning',
     clean.valid && (clean.warnings ?? []).length === 0, clean.warnings)
}

dispatcher().then(() => {
  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed === 0 ? 0 : 1)
}, (e) => { console.error(e); process.exit(1) })
