/**
 * test/receipt-version-v1-2.test.ts: hosted-v1.2 is the CURRENT hosted receipt
 * version, and it reserves two optional signed fields for the agent registry.
 *
 * Rules under test (src/receipt-versions.ts):
 *   - hosted-v1.2 is `current`; hosted-v1.1 and hosted-v1.0 are `legacy` and
 *     still verify.
 *   - hosted-v1.2 signs `agent_id` and `owner_oid` when present (absent or null
 *     = left out of the bytes). Present values must be non-empty strings.
 *   - Changing, adding or dropping either one fails the signature.
 *   - A hosted-v1.2 receipt cannot be read as hosted-v1.1 / v1.0 by dropping
 *     its v1.2-only fields.
 *   - An unversioned receipt that DISPLAYS agent_id / owner_oid verifies, with
 *     an UNSIGNED_FIELD warning for each (those versions never signed them).
 *   - The registry equals synoi-gap schemas/receipt-versions.json, vendored as
 *     vectors/receipt-versions.json.
 *
 * The signer here is an independent mirror: the field list is written out
 * below, NOT imported from ../src. Keys are throwaway test keys.
 */

import { generateKeyPairSync, sign } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import {
  verifyReceiptSignature,
  getReceiptVersion,
  RECEIPT_VERSION_REGISTRY,
  DEGRADED_REASON_CODES,
  INTEGRITY_GRADES,
  UNSIGNED_FIELD,
  UNSIGNED_DEGRADED,
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
const V1_2_FIELDS = [
  ...V1_1_FIELDS, 'agent_id', 'degraded_reason', 'integrity_grade', 'owner_oid', 'schema_version',
]

function canonicalOver(fields: string[], payload: Record<string, unknown>): string {
  const obj: Record<string, unknown> = {}
  for (const k of [...fields].sort()) {
    if (payload[k] !== undefined && payload[k] !== null) obj[k] = payload[k]
  }
  return JSON.stringify(obj)
}
const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string
const signOver = (fields: string[], p: Record<string, unknown>): string =>
  sign(null, Buffer.from(canonicalOver(fields, p), 'utf8'), privateKey).toString('hex')
const signV1_2 = (p: Record<string, unknown>): string => signOver(V1_2_FIELDS, p)
const signV1_1 = (p: Record<string, unknown>): string => signOver(V1_1_FIELDS, { ...p, degraded: !!p['degraded'] })
const signV1_0 = (p: Record<string, unknown>): string => signOver(V1_0_FIELDS, p)

const base: Record<string, unknown> = {
  receipt_id:   'rcpt_v12_0001',
  tenant_id:    'tenant-v12',
  decision:     'allow',
  action_class: 'B',
  risk_level:   'low',
  oid_hex:      'cd'.repeat(32),
  recorded_at:  1793404800000,
  sequence:     7,
}
const AGENT = 'agt_01HZX3V9TESTAGENT'
const OWNER = 'ef'.repeat(32)
const v12plain: Record<string, unknown> = {
  ...base, schema_version: 'hosted-v1.2', degraded: false, integrity_grade: 'A',
}
const v12agent: Record<string, unknown> = { ...v12plain, agent_id: AGENT, owner_oid: OWNER }
const v12agentDeg: Record<string, unknown> = {
  ...v12agent, degraded: true, degraded_reason: 'trust_token_expired', integrity_grade: 'B',
}

// ── 1. Registry status and field list ───────────────────────────────────────
const e10 = getReceiptVersion('hosted-v1.0')
const e11 = getReceiptVersion('hosted-v1.1')
const e12 = getReceiptVersion('hosted-v1.2')
ok('hosted-v1.2 status is current', e12?.status === 'current', e12?.status)
ok('hosted-v1.1 status is legacy', e11?.status === 'legacy', e11?.status)
ok('hosted-v1.0 status is legacy', e10?.status === 'legacy', e10?.status)
ok('hosted-v1.2 description no longer says "not yet emitted"',
   !/not yet emitted/i.test(e12?.description ?? ''), e12?.description)
const fieldsOf = (e: typeof e12): string[] =>
  e && e.family === 'hosted-flat' ? [...e.required_fields, ...e.optional_fields].sort() : []
ok('hosted-v1.2 signed fields = 26 + agent_id, degraded_reason, integrity_grade, owner_oid, schema_version',
   JSON.stringify(fieldsOf(e12)) === JSON.stringify([...V1_2_FIELDS].sort()), fieldsOf(e12))
ok('hosted-v1.2: agent_id and owner_oid are optional, not required',
   e12?.family === 'hosted-flat' &&
   e12.optional_fields.includes('agent_id') && e12.optional_fields.includes('owner_oid') &&
   !e12.required_fields.includes('agent_id') && !e12.required_fields.includes('owner_oid'), e12)
for (const e of [e10, e11]) {
  ok(`${e?.id}: displays agent_id / owner_oid as unsigned`,
     e?.family === 'hosted-flat' && e.display_unsigned.includes('agent_id') && e.display_unsigned.includes('owner_oid'), e)
}

// ── 2. Registry == vendored synoi-gap schemas/receipt-versions.json ─────────
const vendoredPath = resolve(__dirname, '..', 'vectors', 'receipt-versions.json')
ok('vectors/receipt-versions.json exists', existsSync(vendoredPath))
if (existsSync(vendoredPath)) {
  const vend = JSON.parse(readFileSync(vendoredPath, 'utf8')) as {
    versions: Array<{ id: string; schema_version: string | null; status: string; degraded_rule: string;
                      required_fields: string[]; optional_fields: string[] }>
    unversioned_order: string[]
    integrity_grades: string[]
    degraded_reason_codes: Record<string, string>
  }
  const hosted = RECEIPT_VERSION_REGISTRY.filter((e) => e.family === 'hosted-flat')
  ok('registry hosted ids == vendored version ids',
     JSON.stringify(hosted.map((e) => e.id)) === JSON.stringify(vend.versions.map((v) => v.id)))
  for (const v of vend.versions) {
    const e = getReceiptVersion(v.id)
    const h = e?.family === 'hosted-flat' ? e : undefined
    ok(`${v.id}: schema_version / status / degraded_rule match the vendored schema`,
       h !== undefined && h.schema_version === v.schema_version && h.status === v.status &&
       h.degraded_rule === v.degraded_rule, [h?.schema_version, h?.status, h?.degraded_rule])
    ok(`${v.id}: required_fields match the vendored schema`,
       JSON.stringify([...(h?.required_fields ?? [])].sort()) === JSON.stringify(v.required_fields), h?.required_fields)
    ok(`${v.id}: optional_fields match the vendored schema`,
       JSON.stringify([...(h?.optional_fields ?? [])].sort()) === JSON.stringify(v.optional_fields), h?.optional_fields)
  }
  ok('DEGRADED_REASON_CODES == vendored degraded_reason_codes',
     JSON.stringify(Object.entries(DEGRADED_REASON_CODES).sort()) ===
     JSON.stringify(Object.entries(vend.degraded_reason_codes).sort()))
  ok('INTEGRITY_GRADES == vendored integrity_grades',
     JSON.stringify(INTEGRITY_GRADES) === JSON.stringify(vend.integrity_grades))

  const gapDir = process.env['SYNOI_GAP_DIR'] ?? resolve(__dirname, '..', '..', 'synoi-gap')
  const gapSchema = join(gapDir, 'schemas', 'receipt-versions.json')
  if (existsSync(gapSchema)) {
    const upstream = readFileSync(gapSchema, 'utf8').replace(/\r\n/g, '\n')
    const local = readFileSync(vendoredPath, 'utf8').replace(/\r\n/g, '\n')
    ok(`vendored receipt-versions.json is identical to ${gapSchema}`, upstream === local,
       'vectors/receipt-versions.json has drifted from synoi-gap; re-copy it and update src/receipt-versions.ts')
  } else {
    process.stdout.write(`SKIP synoi-gap receipt-versions drift check: ${gapSchema} not present\n`)
  }
}

// ── 3. Positive ─────────────────────────────────────────────────────────────
const sigAgent = signV1_2(v12agent)
const rA = verifyReceiptSignature(v12agent, sigAgent, pubPem)
ok('hosted-v1.2 with agent_id + owner_oid verifies', rA.valid && rA.version === 'hosted-v1.2', rA)
ok('hosted-v1.2: signed_fields include agent_id and owner_oid',
   rA.signed_fields?.includes('agent_id') === true && rA.signed_fields?.includes('owner_oid') === true, rA.signed_fields)
ok('hosted-v1.2: canonical bytes carry agent_id and owner_oid',
   rA.canonical_payload.includes(`"agent_id":"${AGENT}"`) && rA.canonical_payload.includes(`"owner_oid":"${OWNER}"`),
   rA.canonical_payload)
ok('hosted-v1.2 with agent fields: no warnings', rA.warnings?.length === 0, rA.warnings)
const rP = verifyReceiptSignature(v12plain, signV1_2(v12plain), pubPem)
ok('hosted-v1.2 without agent fields verifies (they are optional)', rP.valid, rP)
ok('hosted-v1.2 without agent fields: bytes carry neither key',
   !rP.canonical_payload.includes('agent_id') && !rP.canonical_payload.includes('owner_oid'), rP.canonical_payload)
const rNull = verifyReceiptSignature({ ...v12plain, agent_id: null, owner_oid: null }, signV1_2(v12plain), pubPem)
ok('hosted-v1.2: agent_id / owner_oid null == absent (store rows export NULL)', rNull.valid, rNull)
const rOnlyAgent = { ...v12plain, agent_id: AGENT }
ok('hosted-v1.2: agent_id without owner_oid verifies (ownerless agent is representable)',
   verifyReceiptSignature(rOnlyAgent, signV1_2(rOnlyAgent), pubPem).valid)
const rDeg = verifyReceiptSignature(v12agentDeg, signV1_2(v12agentDeg), pubPem)
ok('hosted-v1.2 degraded with agent fields verifies', rDeg.valid, rDeg)

// ── 4. Tamper / add / drop ──────────────────────────────────────────────────
const sigDeg = signV1_2(v12agentDeg)
const tampers: Array<[string, unknown]> = [
  ['agent_id', AGENT + 'x'],
  ['owner_oid', '00'.repeat(32)],
  ['schema_version', 'hosted-v1.3'],
  ['degraded_reason', 'trust_token_absent'],
  ['integrity_grade', 'C'],
  ['degraded', false],
]
for (const [f, v] of tampers) {
  const r = verifyReceiptSignature({ ...v12agentDeg, [f]: v }, sigDeg, pubPem)
  ok(`tamper hosted-v1.2: changing ${f} fails`, !r.valid, r)
}
for (const f of ['agent_id', 'owner_oid', 'schema_version', 'degraded_reason', 'integrity_grade']) {
  const x = { ...v12agentDeg }
  delete x[f]
  ok(`drop hosted-v1.2: removing signed ${f} fails`, !verifyReceiptSignature(x, sigDeg, pubPem).valid)
}
const sigPlain = signV1_2(v12plain)
ok('add: agent_id on a receipt signed without it fails',
   !verifyReceiptSignature({ ...v12plain, agent_id: AGENT }, sigPlain, pubPem).valid)
ok('add: owner_oid on a receipt signed without it fails',
   !verifyReceiptSignature({ ...v12plain, owner_oid: OWNER }, sigPlain, pubPem).valid)

// ── 5. No downgrade ─────────────────────────────────────────────────────────
for (const drop of [
  ['schema_version'],
  ['schema_version', 'integrity_grade'],
  ['schema_version', 'integrity_grade', 'degraded_reason'],
  ['schema_version', 'integrity_grade', 'degraded_reason', 'agent_id', 'owner_oid'],
]) {
  const x = { ...v12agentDeg }
  for (const f of drop) delete x[f]
  const r = verifyReceiptSignature(x, sigDeg, pubPem)
  ok(`downgrade: dropping ${drop.join('+')} does not verify as hosted-v1.1 or v1.0`,
     !r.valid && r.version === undefined, r)
}
// Same with a degraded:false receipt, whose v1.1 bytes are closest to v1.2's.
{
  const x = { ...v12agent }
  for (const f of ['schema_version', 'integrity_grade', 'agent_id', 'owner_oid']) delete x[f]
  ok('downgrade: not-degraded v1.2 stripped to the 26 fields does not verify', !verifyReceiptSignature(x, sigAgent, pubPem).valid)
}
ok('relabel: v1.2 receipt claiming an unknown version fails closed',
   /unknown-schema-version/.test(verifyReceiptSignature({ ...v12agent, schema_version: 'hosted-v1.1' }, sigAgent, pubPem).reason ?? ''))

// ── 6. Value rules for the agent fields ─────────────────────────────────────
const semantic: Array<[string, Record<string, unknown>]> = [
  ['agent_id empty string', { ...v12plain, agent_id: '' }],
  ['owner_oid empty string', { ...v12plain, owner_oid: '' }],
  ['agent_id a number', { ...v12plain, agent_id: 42 }],
  ['owner_oid a boolean', { ...v12plain, owner_oid: true }],
]
for (const [label, rcpt] of semantic) {
  const r = verifyReceiptSignature(rcpt, signV1_2(rcpt), pubPem)
  ok(`hosted-v1.2 semantics: ${label} fails even though signed`, !r.valid && /agent_id|owner_oid/.test(r.reason ?? ''), r.reason)
}

// ── 7. Legacy receipts still verify; displayed agent fields warn ────────────
const v11 = { ...base, degraded: true }
const r11 = verifyReceiptSignature(v11, signV1_1(v11), pubPem)
ok('legacy hosted-v1.1 still verifies, no warnings', r11.valid && r11.version === 'hosted-v1.1' && r11.warnings?.length === 0, r11)
const r10 = verifyReceiptSignature(base, signV1_0(base), pubPem)
ok('legacy hosted-v1.0 still verifies, no warnings', r10.valid && r10.version === 'hosted-v1.0' && r10.warnings?.length === 0, r10)
const v11disp = { ...v11, agent_id: AGENT, owner_oid: OWNER }
const w11 = verifyReceiptSignature(v11disp, signV1_1(v11disp), pubPem)
ok('hosted-v1.1 displaying agent_id + owner_oid: verifies with UNSIGNED_FIELD for each',
   w11.valid && w11.version === 'hosted-v1.1' &&
   JSON.stringify((w11.warnings ?? []).map((w) => [w.code, w.field]).sort()) ===
   JSON.stringify([[UNSIGNED_FIELD, 'agent_id'], [UNSIGNED_FIELD, 'owner_oid']]), w11.warnings)
ok('hosted-v1.1 displaying agent fields: they are listed unsigned, not signed',
   w11.unsigned_canonical_fields?.includes('agent_id') === true && w11.signed_fields?.includes('agent_id') === false,
   [w11.unsigned_canonical_fields, w11.signed_fields])
const v10disp = { ...base, degraded: 0, agent_id: AGENT }
const w10 = verifyReceiptSignature(v10disp, signV1_0(v10disp), pubPem)
ok('hosted-v1.0 displaying degraded + agent_id: UNSIGNED_DEGRADED then UNSIGNED_FIELD',
   w10.valid && JSON.stringify((w10.warnings ?? []).map((w) => w.code)) === JSON.stringify([UNSIGNED_DEGRADED, UNSIGNED_FIELD]),
   w10.warnings)

process.stdout.write(`\nreceipt-version-v1-2: ${passed} passed, ${failed} failed\n`)
process.exit(failed === 0 ? 0 : 1)
