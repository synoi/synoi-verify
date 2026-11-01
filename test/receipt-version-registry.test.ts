/**
 * test/receipt-version-registry.test.ts: v1 (flat) receipts are verified
 * against a REGISTRY of explicit versions, never by guessing a form.
 *
 * Rules under test (src/receipt-versions.ts):
 *   - A receipt carrying `schema_version` is verified ONLY against the registry
 *     entry with that value. An unknown value fails closed with a clear reason,
 *     before any signature check.
 *   - A receipt with no `schema_version` (everything signed so far) maps to the
 *     closed set of unversioned legacy entries, hosted-v1.1 then hosted-v1.0.
 *     Their canonical bytes are disjoint by construction (v1.1 bytes always hold
 *     a "degraded" key, v1.0 bytes never do), so at most one can verify.
 *   - hosted-v1.2 (PROPOSED, not yet emitted by the gateway) signs
 *     schema_version, degraded (required), integrity_grade (required) and
 *     degraded_reason (present exactly when degraded), and its values must be
 *     internally consistent.
 *
 * The signer here is an independent mirror: each version's field list is
 * written out below, NOT imported from ../src. Keys are throwaway test keys.
 */

import { generateKeyPairSync, sign } from 'node:crypto'
import {
  verifyReceiptSignature,
  verifyReceiptByScheme,
  RECEIPT_VERSION_REGISTRY,
  getReceiptVersion,
  resolveHostedVersions,
  canonicalPayloadForVersion,
  HOSTED_V1_2_SCHEMA_VERSION,
  DEGRADED_REASON_CODES,
  INTEGRITY_GRADES,
  UNSIGNED_DEGRADED,
  UNSIGNED_FIELD,
  ALL_CANONICAL_FIELDS,
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

// ── Independent mirror of each version's signed-field list ──────────────────
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

function canonicalOver(fields: string[], payload: Record<string, unknown>): string {
  const obj: Record<string, unknown> = {}
  for (const k of [...fields].sort()) {
    if (payload[k] !== undefined && payload[k] !== null) obj[k] = payload[k]
  }
  return JSON.stringify(obj)
}

const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string
const signOver = (fields: string[], payload: Record<string, unknown>): string =>
  sign(null, Buffer.from(canonicalOver(fields, payload), 'utf8'), privateKey).toString('hex')

// The gateway signs v1.1 with degraded: !!degraded.
const signV1_1 = (p: Record<string, unknown>): string => signOver(V1_1_FIELDS, { ...p, degraded: !!p['degraded'] })
const signV1_0 = (p: Record<string, unknown>): string => signOver(V1_0_FIELDS, p)
const signV1_2 = (p: Record<string, unknown>): string => signOver(V1_2_FIELDS, p)

const base: Record<string, unknown> = {
  receipt_id:   'rcpt_reg_0001',
  tenant_id:    'tenant-reg',
  decision:     'deny',
  action_class: 'C',
  risk_level:   'high',
  oid_hex:      'ab'.repeat(32),
  recorded_at:  1793318400000,
  sequence:     42,
  session_id:   'sess-reg',
  approver_ref: '{"trace_id":"' + '0f'.repeat(16) + '","v":3}',
}

const v1_0: Record<string, unknown> = { ...base }
const v1_1: Record<string, unknown> = { ...base, degraded: true }
const v1_2ok: Record<string, unknown> = {
  ...base, schema_version: 'hosted-v1.2', degraded: false, integrity_grade: 'A',
}
const v1_2deg: Record<string, unknown> = {
  ...base, schema_version: 'hosted-v1.2', degraded: true,
  degraded_reason: 'modified_code,trust_token_absent', integrity_grade: 'D',
}

// ── 1. Registry shape ────────────────────────────────────────────────────────

const ids = RECEIPT_VERSION_REGISTRY.map((e) => e.id)
ok('registry: ids are unique', new Set(ids).size === ids.length, ids)
ok('registry: has hosted-v1.0, hosted-v1.1, hosted-v1.2, gap-v2-dsse, gap-selfsign',
   ['hosted-v1.0', 'hosted-v1.1', 'hosted-v1.2', 'gap-v2-dsse', 'gap-selfsign'].every((i) => ids.includes(i)), ids)
for (const e of RECEIPT_VERSION_REGISTRY) {
  ok(`registry ${e.id}: declares family, canonicalization, signature schemes, status`,
     typeof e.family === 'string' && typeof e.canonicalization === 'string' &&
     Array.isArray(e.signature_schemes) && e.signature_schemes.length > 0 &&
     ['current', 'legacy', 'proposed'].includes(e.status), e)
  ok(`registry ${e.id}: declares the warnings it may emit (array)`, Array.isArray(e.warnings), e.warnings)
}
const e10 = getReceiptVersion('hosted-v1.0')
const e11 = getReceiptVersion('hosted-v1.1')
const e12 = getReceiptVersion('hosted-v1.2')
ok('hosted-v1.0: unversioned, legacy, warns UNSIGNED_DEGRADED',
   e10?.family === 'hosted-flat' && e10.schema_version === null && e10.status === 'legacy' &&
   e10.warnings.includes(UNSIGNED_DEGRADED), e10)
ok('hosted-v1.1: unversioned, legacy (superseded by hosted-v1.2)',
   e11?.family === 'hosted-flat' && e11.schema_version === null && e11.status === 'legacy', e11)
ok('hosted-v1.2: explicit schema_version "hosted-v1.2", status current',
   e12?.family === 'hosted-flat' && e12.schema_version === HOSTED_V1_2_SCHEMA_VERSION &&
   HOSTED_V1_2_SCHEMA_VERSION === 'hosted-v1.2' && e12.status === 'current', e12)
const fieldsOf = (e: typeof e10): string[] =>
  e && e.family === 'hosted-flat' ? [...e.required_fields, ...e.optional_fields].sort() : []
ok('hosted-v1.0 signed fields = the 26 minus degraded', JSON.stringify(fieldsOf(e10)) === JSON.stringify([...V1_0_FIELDS].sort()), fieldsOf(e10))
ok('hosted-v1.1 signed fields = the vendored 26', JSON.stringify(fieldsOf(e11)) === JSON.stringify([...V1_1_FIELDS].sort()) &&
   JSON.stringify(fieldsOf(e11)) === JSON.stringify([...ALL_CANONICAL_FIELDS].sort()), fieldsOf(e11))
ok('hosted-v1.2 signed fields = the 26 + agent_id, degraded_reason, integrity_grade, owner_oid, schema_version',
   JSON.stringify(fieldsOf(e12)) === JSON.stringify([...V1_2_FIELDS].sort()), fieldsOf(e12))
ok('hosted-v1.2 requires schema_version, degraded, integrity_grade',
   e12?.family === 'hosted-flat' && ['schema_version', 'degraded', 'integrity_grade'].every((f) => e12.required_fields.includes(f)), e12)
const dsse = getReceiptVersion('gap-v2-dsse')
const lite = getReceiptVersion('gap-selfsign')
ok('gap-v2-dsse: keyed by receipt_scheme synoi.receipt/v2',
   dsse?.family === 'gap-cdro' && dsse.receipt_scheme === 'synoi.receipt/v2', dsse)
ok('gap-selfsign: keyed by receipt_scheme synoi.receipt/gap-selfsign',
   lite?.family === 'gap-cdro' && lite.receipt_scheme === 'synoi.receipt/gap-selfsign', lite)
ok('unknown id: getReceiptVersion returns undefined', getReceiptVersion('hosted-v9') === undefined)

// F2: six, not seven (trust_token_unverified folded into trust_token_absent).
ok('reason codes: the six derived from the gateway code',
   JSON.stringify(Object.keys(DEGRADED_REASON_CODES).sort()) === JSON.stringify([
     'manifest_missing', 'modified_code', 'resilience_fallback', 'trust_token_absent',
     'trust_token_expired', 'trust_token_flagged']),
   Object.keys(DEGRADED_REASON_CODES))
ok('grades: A, B, C, D', JSON.stringify(INTEGRITY_GRADES) === JSON.stringify(['A', 'B', 'C', 'D']), INTEGRITY_GRADES)

// ── 2. Resolution rules ──────────────────────────────────────────────────────

const rUnv = resolveHostedVersions(v1_1)
ok('resolve: no schema_version -> the unversioned legacy entries, v1.1 then v1.0',
   rUnv.ok && rUnv.rule === 'unversioned-legacy' &&
   JSON.stringify(rUnv.entries.map((e) => e.id)) === JSON.stringify(['hosted-v1.1', 'hosted-v1.0']), rUnv)
const rNull = resolveHostedVersions({ ...v1_1, schema_version: null })
ok('resolve: schema_version null is treated as absent (store rows export NULL)',
   rNull.ok && rNull.rule === 'unversioned-legacy', rNull)
const rExp = resolveHostedVersions(v1_2ok)
ok('resolve: schema_version hosted-v1.2 -> exactly that one entry',
   rExp.ok && rExp.rule === 'explicit' && rExp.entries.length === 1 && rExp.entries[0]!.id === 'hosted-v1.2', rExp)
for (const bad of ['hosted-v9', '', 'hosted-v1.1', 'hosted-v1.0', 'HOSTED-V1.2', 1, true, {}]) {
  const r = resolveHostedVersions({ ...v1_2ok, schema_version: bad })
  ok(`resolve: schema_version ${JSON.stringify(bad)} fails closed`,
     !r.ok && /schema_version/.test(r.reason), r)
}

// ── 3. Positive, per version ────────────────────────────────────────────────

const res10 = verifyReceiptSignature(v1_0, signV1_0(v1_0), pubPem)
ok('hosted-v1.0 receipt verifies, version hosted-v1.0, form legacy-without-degraded',
   res10.valid && res10.version === 'hosted-v1.0' && res10.form === 'legacy-without-degraded', res10)
const res11 = verifyReceiptSignature(v1_1, signV1_1(v1_1), pubPem)
ok('hosted-v1.1 receipt verifies, version hosted-v1.1, form current',
   res11.valid && res11.version === 'hosted-v1.1' && res11.form === 'current', res11)
const res12 = verifyReceiptSignature(v1_2ok, signV1_2(v1_2ok), pubPem)
ok('hosted-v1.2 (not degraded, grade A) verifies, version hosted-v1.2',
   res12.valid && res12.version === 'hosted-v1.2', res12)
ok('hosted-v1.2: result carries no PR-#1 `form` label', res12.form === undefined, res12.form)
ok('hosted-v1.2: signed_fields include schema_version and integrity_grade, not degraded_reason (absent)',
   res12.signed_fields?.includes('schema_version') === true && res12.signed_fields?.includes('integrity_grade') === true &&
   res12.signed_fields?.includes('degraded_reason') === false, res12.signed_fields)
ok('hosted-v1.2: no warnings', Array.isArray(res12.warnings) && res12.warnings.length === 0, res12.warnings)
const res12d = verifyReceiptSignature(v1_2deg, signV1_2(v1_2deg), pubPem)
ok('hosted-v1.2 (degraded, two reasons, grade D) verifies', res12d.valid && res12d.version === 'hosted-v1.2', res12d)
ok('hosted-v1.2 degraded: signed bytes carry the reason and grade',
   res12d.canonical_payload.includes('"degraded_reason":"modified_code,trust_token_absent"') &&
   res12d.canonical_payload.includes('"integrity_grade":"D"') &&
   res12d.canonical_payload.includes('"schema_version":"hosted-v1.2"'), res12d.canonical_payload)
// store rows export degraded as 0/1
const v1_2store = { ...v1_2deg, degraded: 1 }
ok('hosted-v1.2: a store row with degraded 1 verifies (coerced to the signed boolean)',
   verifyReceiptSignature(v1_2store, signV1_2(v1_2deg), pubPem).valid)

// ── 4. Tamper, per signed field, per version ────────────────────────────────

function mutate(v: unknown): unknown {
  if (typeof v === 'boolean') return !v
  if (typeof v === 'number') return v + 1
  return String(v) + 'x'
}
const tamperCases: Array<[string, Record<string, unknown>, string]> = [
  ['hosted-v1.0', v1_0, signV1_0(v1_0)],
  ['hosted-v1.1', v1_1, signV1_1(v1_1)],
  ['hosted-v1.2', v1_2ok, signV1_2(v1_2ok)],
  ['hosted-v1.2(degraded)', v1_2deg, signV1_2(v1_2deg)],
]
for (const [label, rcpt, sig] of tamperCases) {
  for (const f of Object.keys(rcpt)) {
    let changed: unknown = mutate(rcpt[f])
    // keep v1.2 enum values valid so the SIGNATURE is what catches the change
    if (f === 'integrity_grade') changed = rcpt[f] === 'A' ? 'B' : 'C'
    if (f === 'degraded_reason') changed = 'trust_token_absent'
    const r = verifyReceiptSignature({ ...rcpt, [f]: changed }, sig, pubPem)
    ok(`tamper ${label}: changing ${f} fails`, !r.valid, r)
  }
}
for (const f of ['schema_version', 'degraded', 'integrity_grade', 'degraded_reason', 'sequence', 'approver_ref']) {
  const src = f === 'degraded_reason' ? v1_2deg : v1_2ok
  const sig = signV1_2(src)
  const dropped = { ...src }
  delete dropped[f]
  const r = verifyReceiptSignature(dropped, sig, pubPem)
  ok(`drop hosted-v1.2: removing ${f} fails`, !r.valid, r)
}

// ── 5. Unknown / stripped / changed version ─────────────────────────────────

const sig12 = signV1_2(v1_2ok)
for (const bad of ['hosted-v9', 'hosted-v1.1', 'hosted-v1.0', '']) {
  const r = verifyReceiptSignature({ ...v1_2ok, schema_version: bad }, sig12, pubPem)
  ok(`version changed to ${JSON.stringify(bad)}: fails closed with unknown-schema-version`,
     !r.valid && /unknown-schema-version/.test(r.reason ?? ''), r.reason)
}
const stripped = { ...v1_2ok }
delete stripped['schema_version']
const rs = verifyReceiptSignature(stripped, sig12, pubPem)
ok('version stripped: falls to the unversioned entries, and neither verifies',
   !rs.valid && /hosted-v1\.1/.test(rs.reason ?? '') && /hosted-v1\.0/.test(rs.reason ?? ''), rs.reason)
// stripping every v1.2-only field still fails: the bytes were signed with them
const strippedAll = { ...v1_2ok }
for (const f of ['schema_version', 'integrity_grade', 'degraded_reason']) delete strippedAll[f]
ok('version + grade stripped: does not verify as hosted-v1.1 or v1.0',
   !verifyReceiptSignature(strippedAll, sig12, pubPem).valid)
// upgrade forgery: a genuine v1.1 receipt relabelled hosted-v1.2
const sig11 = signV1_1(v1_1)
const relabel = { ...v1_1, schema_version: 'hosted-v1.2', degraded_reason: 'trust_token_absent', integrity_grade: 'B' }
const rr = verifyReceiptSignature(relabel, sig11, pubPem)
ok('v1.1 receipt relabelled as hosted-v1.2: fails (only the v1.2 entry is tried)', !rr.valid, rr)
// downgrade: a v1.1 receipt cannot be read as v1.0 to unsign degraded:true
const down = { ...v1_1 }
delete down['degraded']
ok('v1.1 receipt with degraded:true stripped: fails (v1.1 rebuilds false, v1.0 lacks the key)',
   !verifyReceiptSignature(down, sig11, pubPem).valid)

// ── 6. Disjointness of the candidate bytes ──────────────────────────────────

for (const rcpt of [v1_0, v1_1, { ...base, degraded: false }]) {
  const b11 = canonicalPayloadForVersion(rcpt, 'hosted-v1.1').canonical_payload
  const b10 = canonicalPayloadForVersion(rcpt, 'hosted-v1.0').canonical_payload
  ok(`disjoint (${JSON.stringify(rcpt['degraded'])}): v1.1 bytes carry "degraded", v1.0 bytes never do`,
     b11.includes('"degraded":') && !b10.includes('"degraded":') && b10 !== b11, [b10, b11])
}
ok('disjoint: v1.2 bytes always carry "schema_version", v1.0/v1.1 bytes never do',
   canonicalPayloadForVersion(v1_2ok, 'hosted-v1.2').canonical_payload.includes('"schema_version":"hosted-v1.2"') &&
   !canonicalPayloadForVersion(v1_2ok, 'hosted-v1.1').canonical_payload.includes('schema_version') &&
   !canonicalPayloadForVersion(v1_2ok, 'hosted-v1.0').canonical_payload.includes('schema_version'))
let threw = ''
try { canonicalPayloadForVersion(v1_1, 'hosted-v9') } catch (e) { threw = (e as Error).message }
ok('canonicalPayloadForVersion: unknown id throws', /unknown/.test(threw), threw)

// ── 7. hosted-v1.2 semantics: validly SIGNED but inconsistent values fail ───

const semantic: Array<[string, Record<string, unknown>, RegExp]> = [
  ['degraded absent', (() => { const x = { ...v1_2ok }; delete x['degraded']; return x })(), /degraded/],
  ['integrity_grade absent', (() => { const x = { ...v1_2ok }; delete x['integrity_grade']; return x })(), /integrity_grade/],
  ['integrity_grade "E"', { ...v1_2ok, integrity_grade: 'E' }, /integrity_grade/],
  ['degraded:true with no reason', { ...v1_2deg, degraded_reason: undefined }, /degraded_reason/],
  ['degraded:false with a reason', { ...v1_2ok, degraded_reason: 'trust_token_absent' }, /degraded_reason/],
  ['not degraded but grade B', { ...v1_2ok, integrity_grade: 'B' }, /integrity_grade/],
  ['degraded but grade A', { ...v1_2deg, integrity_grade: 'A' }, /integrity_grade/],
  ['grade not the worst of the reasons', { ...v1_2deg, integrity_grade: 'B' }, /integrity_grade/],
  ['unknown reason code', { ...v1_2deg, degraded_reason: 'cosmic_rays', integrity_grade: 'D' }, /cosmic_rays/],
  ['reason codes unsorted', { ...v1_2deg, degraded_reason: 'trust_token_absent,modified_code' }, /sorted/],
  ['reason code repeated', { ...v1_2deg, degraded_reason: 'modified_code,modified_code' }, /sorted|repeat/],
  ['degraded "true" (string)', { ...v1_2deg, degraded: 'true' }, /degraded/],
]
for (const [label, rcpt, re] of semantic) {
  const r = verifyReceiptSignature(rcpt, signV1_2(rcpt), pubPem)
  ok(`hosted-v1.2 semantics: ${label} fails even though signed`, !r.valid && re.test(r.reason ?? ''), r.reason)
}
// each code maps to a grade, and one-reason receipts at that grade verify
for (const [code, grade] of Object.entries(DEGRADED_REASON_CODES)) {
  const rcpt = { ...v1_2ok, degraded: true, degraded_reason: code, integrity_grade: grade }
  ok(`hosted-v1.2: ${code} at grade ${grade} verifies`, verifyReceiptSignature(rcpt, signV1_2(rcpt), pubPem).valid)
}

// ── 8. Warnings ─────────────────────────────────────────────────────────────

const v1_0deg = { ...v1_0, degraded: true }
const w10 = verifyReceiptSignature(v1_0deg, signV1_0(v1_0deg), pubPem)
ok('hosted-v1.0 displaying degraded: UNSIGNED_DEGRADED (unchanged)',
   w10.valid && w10.warnings?.length === 1 && w10.warnings[0]!.code === UNSIGNED_DEGRADED, w10.warnings)
const v1_1disp = { ...v1_1, degraded_reason: 'modified_code', integrity_grade: 'D' }
const w11 = verifyReceiptSignature(v1_1disp, signV1_1(v1_1disp), pubPem)
ok('hosted-v1.1 displaying degraded_reason + integrity_grade: verifies, one UNSIGNED_FIELD warning each',
   w11.valid && w11.warnings?.length === 2 &&
   w11.warnings.every((w) => w.code === UNSIGNED_FIELD) &&
   JSON.stringify(w11.warnings.map((w) => w.field).sort()) === JSON.stringify(['degraded_reason', 'integrity_grade']), w11.warnings)
ok('hosted-v1.1 displaying degraded_reason: unsigned_canonical_fields lists them',
   JSON.stringify(w11.unsigned_canonical_fields) === JSON.stringify(['degraded_reason', 'integrity_grade']), w11.unsigned_canonical_fields)
const v1_0disp = { ...v1_0, degraded: 1, degraded_reason: 'no_trust_token' }
const w10b = verifyReceiptSignature(v1_0disp, signV1_0(v1_0disp), pubPem)
ok('hosted-v1.0 displaying degraded + degraded_reason: UNSIGNED_DEGRADED then UNSIGNED_FIELD',
   w10b.valid && JSON.stringify(w10b.warnings?.map((w) => w.code)) === JSON.stringify([UNSIGNED_DEGRADED, UNSIGNED_FIELD]), w10b.warnings)
ok('warning messages name the field', (w11.warnings ?? []).every((w) => w.message.includes(w.field)), w11.warnings)

// ── 9. Dispatcher ───────────────────────────────────────────────────────────

void (async () => {
  const d12 = await verifyReceiptByScheme({
    receipt: v1_2ok, allowLegacyV1: true, legacy: { signatureHex: sig12, publicKeyPem: pubPem },
  })
  ok('dispatcher: hosted-v1.2 receipt verifies on the v1 path, version in detail',
     d12.valid && d12.scheme === 'v1' && (d12.detail as { version?: string }).version === 'hosted-v1.2', d12)
  const dBad = await verifyReceiptByScheme({
    receipt: { ...v1_2ok, schema_version: 'hosted-v9' }, allowLegacyV1: true,
    legacy: { signatureHex: sig12, publicKeyPem: pubPem },
  })
  ok('dispatcher: unknown schema_version is rejected with the reason',
     !dBad.valid && dBad.reasons.some((r) => /unknown-schema-version/.test(r)), dBad)
  const dNoOpt = await verifyReceiptByScheme({ receipt: v1_2ok })
  ok('dispatcher: hosted-v1.2 without allowLegacyV1 still fails closed (K2 unchanged)',
     !dNoOpt.valid && dNoOpt.scheme === 'rejected', dNoOpt)

  process.stdout.write(`\nreceipt-version-registry: ${passed} passed, ${failed} failed\n`)
  if (failed > 0) process.exit(1)
})()
