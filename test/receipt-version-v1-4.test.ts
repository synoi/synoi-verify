/**
 * test/receipt-version-v1-4.test.ts: C1 (Joshua, Nov 1, t961u / t964u).
 *
 *   - hosted-v1.4 ("approver-bound"): the hosted-v1.3 field list plus
 *     approver_oid, with approver_oid REQUIRED. The gateway emits it for a
 *     receipt that records a human approval decision whose approver it has
 *     authenticated as an enrolled operator. approver_oid is that operator's
 *     OID ("oid-" + 64 lowercase hex, the same identity as owner_oid).
 *     ASSUMED: grant_oid stays optional (signed when present) in hosted-v1.4,
 *     because an approval receipt usually has no capability grant.
 *   - approver_oid is signed by NO earlier version. A receipt that carries an
 *     approver_oid but verifies under an earlier version is REFUSED, not
 *     shown with a warning: the approver would otherwise be displayed next to
 *     `valid: true` without the signature covering it (rule 14).
 *   - Each version is checked against its own list: v1.0 / v1.1 / v1.2 / v1.3
 *     vectors without approver_oid verify exactly as before.
 *   - Results name the version that verified with the registry id (C1 / I7
 *     decision 2). `form` stays a read-only alias on the two unversioned ids.
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
const V1_4_FIELDS = [...V1_3_FIELDS, 'approver_oid']
const V1_4_REQUIRED = [
  'action_class', 'approver_oid', 'decision', 'degraded', 'integrity_grade', 'oid_hex',
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

const APPROVER  = 'oid-' + 'ab'.repeat(32)
const APPROVER2 = 'oid-' + 'cd'.repeat(32)
const GRANT     = 'sha256:' + 'aa'.repeat(32)
const APPROVER_REF = JSON.stringify({ decided_by: APPROVER, hitl_id: 'hitl-c1-1', parent_receipt_id: 'rcpt-gated-1', v: 1 })
const base: Record<string, unknown> = {
  receipt_id: 'dr-hitl-c1-1', tenant_id: 'tenant-c1', decision: 'human_approved', action_class: 'B',
  risk_level: 'medium', oid_hex: 'cd'.repeat(32), recorded_at: 1793491200000, sequence: 4,
  policy_versions: '[]', approver_ref: APPROVER_REF,
}
const v14: Record<string, unknown> = {
  ...base, schema_version: 'hosted-v1.4', approver_oid: APPROVER, degraded: false, integrity_grade: 'A',
}
const sig14 = signOver(V1_4_FIELDS, v14)

// ── 1. Registry entry ───────────────────────────────────────────────────────
const e14 = getReceiptVersion('hosted-v1.4')
ok('hosted-v1.4 is registered, explicit schema_version, status current',
   e14?.family === 'hosted-flat' && e14.schema_version === 'hosted-v1.4' && e14.status === 'current', e14)
const fieldsOf = (e: typeof e14): string[] =>
  e && e.family === 'hosted-flat' ? [...e.required_fields, ...e.optional_fields].sort() : []
ok('hosted-v1.4 signs the hosted-v1.3 field set + approver_oid',
   JSON.stringify(fieldsOf(e14)) === JSON.stringify([...V1_4_FIELDS].sort()), fieldsOf(e14))
ok('hosted-v1.4 required = hosted-v1.2 required + approver_oid (grant_oid optional, ASSUMED)',
   e14?.family === 'hosted-flat' && JSON.stringify([...e14.required_fields].sort()) === JSON.stringify(V1_4_REQUIRED), e14)
ok('hosted-v1.4 degraded_rule required, no unsigned display fields',
   e14?.family === 'hosted-flat' && e14.degraded_rule === 'required' && e14.display_unsigned.length === 0)
for (const id of ['hosted-v1.0', 'hosted-v1.1', 'hosted-v1.2', 'hosted-v1.3']) {
  ok(`${id} does not sign approver_oid`, !fieldsOf(getReceiptVersion(id) as typeof e14).includes('approver_oid'))
}
ok('registry hosted ids: v1.0, v1.1, v1.2, v1.3, v1.4',
   JSON.stringify(RECEIPT_VERSION_REGISTRY.filter((e) => e.family === 'hosted-flat').map((e) => e.id)) ===
   JSON.stringify(['hosted-v1.0', 'hosted-v1.1', 'hosted-v1.2', 'hosted-v1.3', 'hosted-v1.4']))
{
  const vend = JSON.parse(readFileSync(resolve(__dirname, '..', 'vectors', 'receipt-versions.json'), 'utf8')) as {
    versions: Array<{ id: string; schema_version: string | null; required_fields: string[]; optional_fields: string[] }>
  }
  const v = vend.versions.find((x) => x.id === 'hosted-v1.4')
  ok('vendored schema has hosted-v1.4 with the same lists',
     v !== undefined && v.schema_version === 'hosted-v1.4' &&
     JSON.stringify(v.required_fields) === JSON.stringify(V1_4_REQUIRED) &&
     JSON.stringify([...v.required_fields, ...v.optional_fields].sort()) === JSON.stringify([...V1_4_FIELDS].sort()), v)
  const gapSchema = join(process.env['SYNOI_GAP_DIR'] ?? resolve(__dirname, '..', '..', 'synoi-gap'), 'schemas', 'receipt-versions.json')
  if (existsSync(gapSchema)) {
    const gap = readFileSync(gapSchema, 'utf8')
    ok('vendored vectors/receipt-versions.json is byte-identical to synoi-gap schemas/receipt-versions.json',
       gap === readFileSync(resolve(__dirname, '..', 'vectors', 'receipt-versions.json'), 'utf8'))
  } else {
    process.stdout.write(`SKIP synoi-gap drift check: ${gapSchema} not present\n`)
  }
}

// ── 2. Positive ─────────────────────────────────────────────────────────────
const r14 = verifyReceiptSignature(v14, sig14, pubPem)
ok('(b) hosted-v1.4 approval receipt verifies as hosted-v1.4', r14.valid && r14.version === 'hosted-v1.4', r14)
ok('(b) hosted-v1.4: approver_oid is a signed field', r14.signed_fields?.includes('approver_oid') === true, r14.signed_fields)
ok('(b) hosted-v1.4: no warnings, no form alias', r14.warnings?.length === 0 && r14.form === undefined, r14)
{
  const withGrant = { ...v14, grant_oid: GRANT }
  const r = verifyReceiptSignature(withGrant, signOver(V1_4_FIELDS, withGrant), pubPem)
  ok('hosted-v1.4 with a signed (optional) grant_oid verifies', r.valid && r.signed_fields?.includes('grant_oid') === true, r)
  const degraded = { ...v14, degraded: true, degraded_reason: 'trust_token_expired', integrity_grade: 'B' }
  ok('hosted-v1.4 degraded receipt verifies (v1.2 value rules)',
     verifyReceiptSignature(degraded, signOver(V1_4_FIELDS, degraded), pubPem).valid)
}

// ── 3. (c) Tamper / strip / relabel ─────────────────────────────────────────
{
  const r = verifyReceiptSignature({ ...v14, approver_oid: APPROVER2 }, sig14, pubPem)
  ok('(c) tampering approver_oid fails verification', !r.valid, r)
}
for (const [f, v] of [['schema_version', 'hosted-v1.3'], ['approver_ref', '{"decided_by":"mallory","v":1}'], ['decision', 'human_denied']] as const) {
  ok(`(c) tamper hosted-v1.4: changing ${f} fails`, !verifyReceiptSignature({ ...v14, [f]: v }, sig14, pubPem).valid)
}
{
  const x = { ...v14 }; delete x['approver_oid']
  const r = verifyReceiptSignature(x, sig14, pubPem)
  ok('strip hosted-v1.4: removing approver_oid fails as a missing required field', !r.valid && /approver_oid/.test(r.reason ?? ''), r.reason)
  const signedWithout = verifyReceiptSignature(x, signOver(V1_4_FIELDS, x), pubPem)
  ok('hosted-v1.4 signed WITHOUT approver_oid is refused (required), even with a good signature',
     !signedWithout.valid && /approver_oid/.test(signedWithout.reason ?? ''), signedWithout.reason)
}
for (const a of ['', 7, true, 'alice', 'oid-' + 'AB'.repeat(32), 'oid-' + 'ab'.repeat(31), 'actor:alice']) {
  const x = { ...v14, approver_oid: a }
  const r = verifyReceiptSignature(x, signOver(V1_4_FIELDS, x), pubPem)
  ok(`hosted-v1.4 approver_oid ${JSON.stringify(a)} fails even though signed (must be oid- + 64 lowercase hex)`,
     !r.valid && /approver_oid/.test(r.reason ?? ''), r.reason)
}
{
  // Downgrade: relabel to v1.3 / v1.2 / unversioned and keep the approver on display.
  for (const sv of ['hosted-v1.3', 'hosted-v1.2']) {
    const x = { ...v14, schema_version: sv, ...(sv === 'hosted-v1.3' ? { grant_oid: GRANT } : {}) }
    ok(`downgrade: relabelling hosted-v1.4 as ${sv} does not verify`, !verifyReceiptSignature(x, sig14, pubPem).valid)
  }
  const y = { ...v14 }
  for (const f of ['schema_version', 'integrity_grade']) delete y[f]
  ok('downgrade: stripping the version fields does not verify as hosted-v1.1 / v1.0', !verifyReceiptSignature(y, sig14, pubPem).valid)
}

// ── 4. (e) an earlier version carrying an UNSIGNED approver_oid is refused ──
{
  // A genuine, correctly signed v1.3 receipt; approver_oid added afterwards.
  const v13 = { ...base, schema_version: 'hosted-v1.3', grant_oid: GRANT, degraded: false, integrity_grade: 'A' }
  const sig13 = signOver(V1_3_FIELDS, v13)
  ok('control: the v1.3 receipt without approver_oid verifies as hosted-v1.3',
     verifyReceiptSignature(v13, sig13, pubPem).version === 'hosted-v1.3')
  const r = verifyReceiptSignature({ ...v13, approver_oid: APPROVER }, sig13, pubPem)
  ok('(e) hosted-v1.3 + unsigned approver_oid is REFUSED (valid:false), not a warning',
     !r.valid && /approver_oid/.test(r.reason ?? ''), r)
  const v12 = { ...base, schema_version: 'hosted-v1.2', degraded: false, integrity_grade: 'A' }
  const r12 = verifyReceiptSignature({ ...v12, approver_oid: APPROVER }, signOver(V1_2_FIELDS, v12), pubPem)
  ok('(e) hosted-v1.2 + unsigned approver_oid is refused', !r12.valid && /approver_oid/.test(r12.reason ?? ''), r12)
  const v11 = { ...base, degraded: false }
  const r11 = verifyReceiptSignature({ ...v11, approver_oid: APPROVER }, signOver(V1_1_FIELDS, v11), pubPem)
  ok('(e) hosted-v1.1 + unsigned approver_oid is refused', !r11.valid && /approver_oid/.test(r11.reason ?? ''), r11)
  const v10 = { ...base }
  const r10 = verifyReceiptSignature({ ...v10, approver_oid: APPROVER }, signOver(V1_0_FIELDS, v10), pubPem)
  ok('(e) hosted-v1.0 + unsigned approver_oid is refused', !r10.valid && /approver_oid/.test(r10.reason ?? ''), r10)
  // Even signed over an earlier version's list, which cannot cover it.
  const v13a = { ...v13, approver_oid: APPROVER }
  ok('(e) hosted-v1.3 "signed" with approver_oid in the payload is still refused (v1.3 cannot sign it)',
     !verifyReceiptSignature(v13a, signOver(V1_4_FIELDS, v13a), pubPem).valid)
}

// ── 5. (d) older versions verify exactly as before, named by version id ─────
{
  const v13 = { ...base, schema_version: 'hosted-v1.3', grant_oid: GRANT, degraded: false, integrity_grade: 'A' }
  const v12 = { ...base, schema_version: 'hosted-v1.2', degraded: false, integrity_grade: 'A' }
  const v11 = { ...base, degraded: true }
  const v10 = { ...base }
  const cases: Array<[string, Record<string, unknown>, string[], string | undefined]> = [
    ['hosted-v1.3', v13, V1_3_FIELDS, undefined],
    ['hosted-v1.2', v12, V1_2_FIELDS, undefined],
    ['hosted-v1.1', v11, V1_1_FIELDS, 'current'],
    ['hosted-v1.0', v10, V1_0_FIELDS, 'legacy-without-degraded'],
  ]
  for (const [id, p, fields, form] of cases) {
    const r = verifyReceiptSignature(p, signOver(fields, p), pubPem)
    ok(`(d) ${id} receipt (approver_ref, no approver_oid) verifies as ${id}`, r.valid && r.version === id, r)
    ok(`(d) ${id}: form alias is ${JSON.stringify(form)} (read-only, unversioned only)`, r.form === form, r.form)
  }
}

// ── 6. Unknown versions still fail closed ───────────────────────────────────
for (const bad of ['hosted-v1.5', 'hosted-v1.40', 'HOSTED-V1.4']) {
  const r = verifyReceiptSignature({ ...v14, schema_version: bad }, sig14, pubPem)
  ok(`unknown schema_version ${JSON.stringify(bad)} fails closed`, !r.valid && /unknown-schema-version/.test(r.reason ?? ''), r.reason)
}

process.stdout.write(`\nreceipt-version-v1-4: ${passed} passed, ${failed} failed\n`)
process.exit(failed === 0 ? 0 : 1)
