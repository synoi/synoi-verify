/**
 * test/receipt-version-v1-3.test.ts: F2 (Joshua, Oct 31).
 *
 *   - Six degraded_reason codes, not seven: trust_token_unverified is folded
 *     into trust_token_absent (same grade B). A v1.2 receipt naming the old
 *     code no longer passes the value rules.
 *   - hosted-v1.3 ("grant-bound"): the hosted-v1.2 field set with grant_oid
 *     REQUIRED. The gateway emits it for receipts that carry a capability grant
 *     (A2A delegation); every other receipt stays hosted-v1.2. grant_oid was
 *     already an optional signed field of every earlier version.
 *   - Each version is checked against its OWN list: v1.0 / v1.1 / v1.2 vectors
 *     verify exactly as before; a v1.3 receipt cannot be read as v1.2 or as
 *     unversioned; an unknown version fails closed.
 *
 * Independent mirror: the field lists are written out here, not imported.
 */

import { generateKeyPairSync, sign } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import {
  verifyReceiptSignature,
  getReceiptVersion,
  RECEIPT_VERSION_REGISTRY,
  DEGRADED_REASON_CODES,
} from '../src/verify'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: unknown): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else {
    failed++
    const d = detail === undefined ? '' : ' -- ' + (typeof detail === 'string' ? detail : JSON.stringify(detail))
    process.stdout.write(`FAIL ${label}${d}\n`)
  }
}

// ── Independent mirror ──────────────────────────────────────────────────────
const SIX_CODES = {
  manifest_missing: 'D', modified_code: 'D', resilience_fallback: 'D',
  trust_token_absent: 'B', trust_token_expired: 'B', trust_token_flagged: 'C',
}
const V1_1_FIELDS = [
  'action_class', 'action_payload_hash', 'approver_ref', 'cited_oracle_inputs',
  'decision', 'decision_subject_oid', 'degraded', 'gateway_manifest_sha256',
  'grant_oid', 'intent_oid', 'oid_hex', 'policy_versions', 'prev', 'receipt_id',
  'recorded_at', 'replayed_after', 'risk_level', 'rule_id', 'sequence',
  'session_id', 'state_sha256', 'status', 'subject_oid', 'target_class',
  'target_id', 'tenant_id',
]
const V1_0_FIELDS = V1_1_FIELDS.filter((f) => f !== 'degraded')
const V1_2_FIELDS = [...V1_1_FIELDS, 'agent_id', 'degraded_reason', 'integrity_grade', 'owner_oid', 'schema_version']
const V1_3_FIELDS = V1_2_FIELDS
const V1_3_REQUIRED = [
  'action_class', 'decision', 'degraded', 'grant_oid', 'integrity_grade', 'oid_hex',
  'receipt_id', 'recorded_at', 'risk_level', 'schema_version', 'tenant_id',
]

function canonicalOver(fields: string[], payload: Record<string, unknown>): string {
  const obj: Record<string, unknown> = {}
  for (const k of [...fields].sort()) if (payload[k] !== undefined && payload[k] !== null) obj[k] = payload[k]
  return JSON.stringify(obj)
}
const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string
const signOver = (fields: string[], p: Record<string, unknown>): string =>
  sign(null, Buffer.from(canonicalOver(fields, p), 'utf8'), privateKey).toString('hex')

const GRANT = 'sha256:' + 'aa'.repeat(32)
const base: Record<string, unknown> = {
  receipt_id: 'rcpt_v13_0001', tenant_id: 'tenant-v13', decision: 'allow', action_class: 'B',
  risk_level: 'low', oid_hex: 'cd'.repeat(32), recorded_at: 1793404800000, sequence: 3,
}
const v13: Record<string, unknown> = {
  ...base, schema_version: 'hosted-v1.3', grant_oid: GRANT, degraded: true,
  degraded_reason: 'trust_token_absent', integrity_grade: 'B',
}
const sig13 = signOver(V1_3_FIELDS, v13)

// ── 1. Six codes, identical to synoi-gap ────────────────────────────────────
ok('DEGRADED_REASON_CODES is the six-code snapshot',
   JSON.stringify(Object.entries(DEGRADED_REASON_CODES).sort()) === JSON.stringify(Object.entries(SIX_CODES).sort()),
   DEGRADED_REASON_CODES)
ok('trust_token_unverified is not a code',
   !Object.prototype.hasOwnProperty.call(DEGRADED_REASON_CODES, 'trust_token_unverified'))
const vendoredPath = resolve(__dirname, '..', 'vectors', 'receipt-versions.json')
const vend = JSON.parse(readFileSync(vendoredPath, 'utf8')) as {
  versions: Array<{ id: string; schema_version: string | null; required_fields: string[]; optional_fields: string[] }>
  degraded_reason_codes: Record<string, string>
}
ok('vendored receipt-versions.json has the same six codes',
   JSON.stringify(Object.entries(vend.degraded_reason_codes).sort()) === JSON.stringify(Object.entries(SIX_CODES).sort()),
   vend.degraded_reason_codes)
const gapSchema = join(process.env['SYNOI_GAP_DIR'] ?? resolve(__dirname, '..', '..', 'synoi-gap'), 'schemas', 'receipt-versions.json')
if (existsSync(gapSchema)) {
  const gap = JSON.parse(readFileSync(gapSchema, 'utf8')) as { degraded_reason_codes: Record<string, string> }
  ok('synoi-gap receipt-versions.json has the same six codes',
     JSON.stringify(Object.entries(gap.degraded_reason_codes).sort()) === JSON.stringify(Object.entries(SIX_CODES).sort()))
} else {
  process.stdout.write(`SKIP synoi-gap six-code check: ${gapSchema} not present\n`)
}
{
  const v12old: Record<string, unknown> = {
    ...base, schema_version: 'hosted-v1.2', degraded: true, degraded_reason: 'trust_token_unverified', integrity_grade: 'B',
  }
  const r = verifyReceiptSignature(v12old, signOver(V1_2_FIELDS, v12old), pubPem)
  ok('a hosted-v1.2 receipt naming trust_token_unverified fails the value rules (unknown code)',
     !r.valid && /trust_token_unverified/.test(r.reason ?? ''), r.reason)
}

// ── 2. Registry entry ───────────────────────────────────────────────────────
const e13 = getReceiptVersion('hosted-v1.3')
const e12 = getReceiptVersion('hosted-v1.2')
ok('hosted-v1.3 is registered, explicit schema_version, status current',
   e13?.family === 'hosted-flat' && e13.schema_version === 'hosted-v1.3' && e13.status === 'current', e13)
ok('hosted-v1.2 is still current (receipts without a grant)', e12?.status === 'current', e12?.status)
const fieldsOf = (e: typeof e13): string[] =>
  e && e.family === 'hosted-flat' ? [...e.required_fields, ...e.optional_fields].sort() : []
ok('hosted-v1.3 signs the hosted-v1.2 field set', JSON.stringify(fieldsOf(e13)) === JSON.stringify([...V1_3_FIELDS].sort()), fieldsOf(e13))
ok('hosted-v1.3 required = hosted-v1.2 required + grant_oid',
   e13?.family === 'hosted-flat' && JSON.stringify([...e13.required_fields].sort()) === JSON.stringify(V1_3_REQUIRED), e13)
ok('hosted-v1.3 degraded_rule required, no unsigned display fields',
   e13?.family === 'hosted-flat' && e13.degraded_rule === 'required' && e13.display_unsigned.length === 0)
{
  const v = vend.versions.find((x) => x.id === 'hosted-v1.3')
  ok('vendored schema has hosted-v1.3 with the same lists',
     v !== undefined && v.schema_version === 'hosted-v1.3' &&
     JSON.stringify(v.required_fields) === JSON.stringify(V1_3_REQUIRED) &&
     JSON.stringify([...v.required_fields, ...v.optional_fields].sort()) === JSON.stringify([...V1_3_FIELDS].sort()), v)
}
ok('registry hosted ids: v1.0, v1.1, v1.2, v1.3',
   JSON.stringify(RECEIPT_VERSION_REGISTRY.filter((e) => e.family === 'hosted-flat').map((e) => e.id)) ===
   JSON.stringify(['hosted-v1.0', 'hosted-v1.1', 'hosted-v1.2', 'hosted-v1.3']))

// ── 3. Positive ─────────────────────────────────────────────────────────────
const r13 = verifyReceiptSignature(v13, sig13, pubPem)
ok('hosted-v1.3 receipt with grant_oid verifies as hosted-v1.3', r13.valid && r13.version === 'hosted-v1.3', r13)
ok('hosted-v1.3: grant_oid is a signed field', r13.signed_fields?.includes('grant_oid') === true, r13.signed_fields)
ok('hosted-v1.3: no warnings', r13.warnings?.length === 0, r13.warnings)
{
  const healthy = { ...v13, degraded: false, integrity_grade: 'A' } as Record<string, unknown>
  delete healthy['degraded_reason']
  ok('hosted-v1.3 not degraded verifies', verifyReceiptSignature(healthy, signOver(V1_3_FIELDS, healthy), pubPem).valid)
}

// ── 4. Tamper / strip / relabel ─────────────────────────────────────────────
for (const [f, v] of [
  ['grant_oid', 'sha256:' + 'ee'.repeat(32)], ['schema_version', 'hosted-v1.2'],
  ['degraded_reason', 'trust_token_expired'], ['integrity_grade', 'C'],
] as const) {
  ok(`tamper hosted-v1.3: changing ${f} fails`, !verifyReceiptSignature({ ...v13, [f]: v }, sig13, pubPem).valid)
}
{
  const x = { ...v13 }; delete x['grant_oid']
  const r = verifyReceiptSignature(x, sig13, pubPem)
  ok('strip hosted-v1.3: removing grant_oid fails as a missing required field', !r.valid && /grant_oid/.test(r.reason ?? ''), r.reason)
  const signedWithout = verifyReceiptSignature(x, signOver(V1_3_FIELDS, x), pubPem)
  ok('hosted-v1.3 signed WITHOUT grant_oid is refused (required), even with a good signature',
     !signedWithout.valid && /grant_oid/.test(signedWithout.reason ?? ''), signedWithout.reason)
}
for (const g of ['', 7, true]) {
  const x = { ...v13, grant_oid: g }
  const r = verifyReceiptSignature(x, signOver(V1_3_FIELDS, x), pubPem)
  ok(`hosted-v1.3 grant_oid ${JSON.stringify(g)} fails even though signed`, !r.valid && /grant_oid/.test(r.reason ?? ''), r.reason)
}
{
  const x = { ...v13, schema_version: 'hosted-v1.2' }; delete x['grant_oid']
  ok('downgrade: relabel hosted-v1.2 and drop grant_oid does not verify', !verifyReceiptSignature(x, sig13, pubPem).valid)
  const y = { ...v13 }
  for (const f of ['schema_version', 'integrity_grade', 'degraded_reason']) delete y[f]
  const r = verifyReceiptSignature(y, sig13, pubPem)
  ok('downgrade: stripping the version fields does not verify as hosted-v1.1 / v1.0', !r.valid && r.version === undefined, r)
}

// ── 5. Unknown versions fail closed ─────────────────────────────────────────
for (const bad of ['hosted-v1.4', 'hosted-v1.30', 'HOSTED-V1.3', '']) {
  const r = verifyReceiptSignature({ ...v13, schema_version: bad }, sig13, pubPem)
  ok(`unknown schema_version ${JSON.stringify(bad)} fails closed`, !r.valid && /unknown-schema-version/.test(r.reason ?? ''), r.reason)
}

// ── 6. Older versions verify exactly as before (each against its own list) ──
{
  const v12 = { ...base, schema_version: 'hosted-v1.2', degraded: false, integrity_grade: 'A' }
  const r12 = verifyReceiptSignature(v12, signOver(V1_2_FIELDS, v12), pubPem)
  ok('hosted-v1.2 without a grant verifies as hosted-v1.2', r12.valid && r12.version === 'hosted-v1.2', r12)
  const v12g = { ...v12, grant_oid: GRANT }
  const r12g = verifyReceiptSignature(v12g, signOver(V1_2_FIELDS, v12g), pubPem)
  ok('hosted-v1.2 with a signed (optional) grant_oid still verifies as hosted-v1.2', r12g.valid && r12g.version === 'hosted-v1.2', r12g)
  const v11 = { ...base, degraded: true, grant_oid: GRANT }
  const r11 = verifyReceiptSignature(v11, signOver(V1_1_FIELDS, v11), pubPem)
  ok('hosted-v1.1 with a signed grant_oid verifies as hosted-v1.1', r11.valid && r11.version === 'hosted-v1.1', r11)
  const v10 = { ...base, grant_oid: GRANT }
  const r10 = verifyReceiptSignature(v10, signOver(V1_0_FIELDS, v10), pubPem)
  ok('hosted-v1.0 with a signed grant_oid verifies as hosted-v1.0', r10.valid && r10.version === 'hosted-v1.0', r10)
  // The pre-fix A2A shape: grant_oid on the row, NOT in the signed bytes.
  const sigNoGrant = signOver(V1_1_FIELDS, { ...v11, grant_oid: undefined })
  ok('pre-fix A2A receipt (grant_oid displayed, never signed) fails: the verifier does not drop it',
     !verifyReceiptSignature(v11, sigNoGrant, pubPem).valid)
}

process.stdout.write(`\nreceipt-version-v1-3: ${passed} passed, ${failed} failed\n`)
process.exit(failed === 0 ? 0 : 1)
