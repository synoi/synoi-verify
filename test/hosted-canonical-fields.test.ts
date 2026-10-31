/**
 * test/hosted-canonical-fields.test.ts — RX-01: the published v1 verifier
 * rebuilds the SAME bytes the hosted gateway signs.
 *
 * The hosted gateway (synoi-gateway src/verify-router.ts CANONICAL_FIELDS)
 * signs 26 fields under omit-when-absent, including `degraded` and `sequence`.
 * Current risk receipts (src/risk-router.ts gateAndRecord) always carry
 * `degraded: false` and a per-tenant `sequence`. Before this fix the package
 * only knew 8 fields, so it rebuilt different bytes and reported "signature
 * does not match" on every current hosted receipt (G5 adversarial suite,
 * RX-01 hosted = FAIL).
 *
 * The signer below is an independent mirror of the gateway's signing code
 * (field list copied from the gateway, NOT imported from ../src), so a drift
 * in the package's list shows up here. Keys are throwaway test-fixture keys
 * generated per run.
 *
 * Also covered:
 *   - the gateway's legacy form without `degraded` (pre-#253 receipts) still
 *     verifies, and the result says which form verified;
 *   - tampering `degraded` or `sequence`, or dropping any signed field, fails
 *     (the verifier tries exactly two fixed forms, never field subsets);
 *   - the vendored field list matches vectors/canonical-receipt-fields.json,
 *     and that file matches synoi-gap's schema and the gateway's list when
 *     those sibling checkouts are present.
 */

import { generateKeyPairSync, sign } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import {
  verifyReceiptSignature,
  CANONICAL_FIELDS,
  OPTIONAL_CANONICAL_FIELDS,
  ALL_CANONICAL_FIELDS,
} from '../src/verify'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: unknown): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else {
    failed++
    const d = detail === undefined ? '' : ' — ' + (typeof detail === 'string' ? detail : JSON.stringify(detail))
    process.stdout.write(`FAIL ${label}${d}\n`)
  }
}

// ── Independent mirror of the gateway signer ────────────────────────────────
// synoi-gateway src/verify-router.ts CANONICAL_FIELDS + canonicalPayload, as of
// origin/main and buildout/G5-adversarial-suite (8a51366).
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

// ── Receipt shapes ──────────────────────────────────────────────────────────

// A current hosted risk receipt, as risk-router.ts gateAndRecord signs it.
const riskReceipt: Record<string, unknown> = {
  receipt_id:   'rcpt_risk_0001',
  tenant_id:    'tenant-rx01',
  decision:     'deny',
  action_class: 'C',
  risk_level:   'high',
  oid_hex:      'ab'.repeat(32),
  recorded_at:  1793318400000,
  degraded:     false,
  sequence:     42,
  intent_oid:   'sha256:' + 'cd'.repeat(32),
  session_id:   'sess-rx01',
}

// Every one of the 26 signed fields populated (scalars, as the gateway signs them).
const fullReceipt: Record<string, unknown> = {
  action_class:            'B',
  action_payload_hash:     'ef'.repeat(32),
  approver_ref:            '{"decided_by":"Ops Lead","hitl_id":"hitl_9","v":1}',
  cited_oracle_inputs:     '[{"subject_type":"ofac","value_hash":"00"}]',
  decision:                'allow',
  decision_subject_oid:    'sha256:' + '01'.repeat(32),
  degraded:                true,
  gateway_manifest_sha256: '02'.repeat(32),
  grant_oid:               'sha256:' + '03'.repeat(32),
  intent_oid:              'sha256:' + '04'.repeat(32),
  oid_hex:                 '05'.repeat(32),
  policy_versions:         '[{"id":"p1","version":3}]',
  prev:                    'sha256:' + '06'.repeat(32),
  receipt_id:              'rcpt_full_0001',
  recorded_at:             1793318400123,
  replayed_after:          'sha256:' + '07'.repeat(32),
  risk_level:              'medium',
  rule_id:                 'rule-17',
  sequence:                7,
  session_id:              'sess-full',
  state_sha256:            '08'.repeat(32),
  status:                  'ok',
  subject_oid:             'sha256:' + '09'.repeat(32),
  target_class:            'database',
  target_id:               'patients',
  tenant_id:               'tenant-full',
  // unsigned display fields the gateway also exports
  action_type:             'Bash',
  latency_ms:              12,
  signer_key_id:           'test-fixture-key',
}
ok('fixture: the full receipt populates all 26 gateway-signed fields',
   GATEWAY_FIELDS.every((f) => fullReceipt[f] !== undefined) && GATEWAY_FIELDS.length === 26)

// ── 1. Current hosted receipts verify ───────────────────────────────────────

const riskSig = gwSign(riskReceipt)
const riskRes = verifyReceiptSignature(riskReceipt, riskSig, pubPem)
ok('hosted risk receipt (degraded:false, sequence) verifies', riskRes.valid, riskRes)
ok('hosted risk receipt: canonical bytes equal the gateway signed bytes',
   riskRes.canonical_payload === gatewayCanonical(riskReceipt), riskRes.canonical_payload)
ok('hosted risk receipt: reports the current form', riskRes.form === 'current', riskRes.form)
ok('hosted risk receipt: signed_fields include degraded and sequence',
   riskRes.signed_fields?.includes('degraded') === true && riskRes.signed_fields?.includes('sequence') === true,
   riskRes.signed_fields)

const fullSig = gwSign(fullReceipt)
const fullRes = verifyReceiptSignature(fullReceipt, fullSig, pubPem)
ok('26-field hosted receipt verifies', fullRes.valid, fullRes)
ok('26-field hosted receipt: signed_fields is all 26, sorted',
   JSON.stringify(fullRes.signed_fields) === JSON.stringify([...GATEWAY_FIELDS].sort()), fullRes.signed_fields)
ok('26-field hosted receipt: nothing canonical is left unsigned',
   (fullRes.unsigned_canonical_fields ?? []).length === 0, fullRes.unsigned_canonical_fields)

// The gateway signs `!!receipt.degraded`; a SQLite row export carries 0/1.
const rowExport = { ...riskReceipt, degraded: 0 }
ok('row export with degraded:0 verifies (same value the gateway signed)',
   verifyReceiptSignature(rowExport, riskSig, pubPem).valid)
const noDegradedExport = { ...riskReceipt }
delete noDegradedExport.degraded
const noDegRes = verifyReceiptSignature(noDegradedExport, riskSig, pubPem)
ok('export that omits degraded:false verifies as the current form (gateway signs !!degraded)',
   noDegRes.valid && noDegRes.form === 'current', noDegRes)

// ── 2. Tampering degraded / sequence fails ──────────────────────────────────

ok('tamper: risk receipt degraded false -> true fails',
   !verifyReceiptSignature({ ...riskReceipt, degraded: true }, riskSig, pubPem).valid)
ok('tamper: risk receipt sequence 42 -> 43 fails',
   !verifyReceiptSignature({ ...riskReceipt, sequence: 43 }, riskSig, pubPem).valid)
ok('tamper: full receipt degraded true -> false fails',
   !verifyReceiptSignature({ ...fullReceipt, degraded: false }, fullSig, pubPem).valid)
const strippedDegraded = { ...fullReceipt }
delete strippedDegraded.degraded
ok('tamper: stripping degraded:true from a signed receipt fails',
   !verifyReceiptSignature(strippedDegraded, fullSig, pubPem).valid)
ok('tamper: full receipt sequence 7 -> 8 fails',
   !verifyReceiptSignature({ ...fullReceipt, sequence: 8 }, fullSig, pubPem).valid)
ok('tamper: non-boolean degraded ("false" string) fails closed',
   !verifyReceiptSignature({ ...riskReceipt, degraded: 'false' }, riskSig, pubPem).valid)

// Dropping ANY signed field must fail: no subset of the signed set is accepted.
for (const f of GATEWAY_FIELDS) {
  const dropped = { ...fullReceipt }
  delete dropped[f]
  const r = verifyReceiptSignature(dropped, fullSig, pubPem)
  ok(`drop: removing signed field ${f} fails`, !r.valid, r.form)
}
// Changing ANY signed field must fail.
for (const f of GATEWAY_FIELDS) {
  const v = fullReceipt[f]
  const changed = { ...fullReceipt, [f]: typeof v === 'number' ? v + 1 : typeof v === 'boolean' ? !v : String(v) + 'x' }
  ok(`change: altering signed field ${f} fails`, !verifyReceiptSignature(changed, fullSig, pubPem).valid)
}

// ── 3. Legacy receipts still verify, and say which form verified ────────────

// Pre-#253 hosted receipt: signed WITHOUT degraded, but already carrying
// sequence / session_id (the gateway's fallback form).
const legacyNoDegraded: Record<string, unknown> = {
  receipt_id: 'rcpt_legacy_253', tenant_id: 'tenant-old', decision: 'allow',
  action_class: 'A', risk_level: 'low', oid_hex: '11'.repeat(32), recorded_at: 1780000000000,
  sequence: 3, session_id: 'sess-old', gateway_manifest_sha256: '12'.repeat(32),
}
const legacySig = gwSign(legacyNoDegraded)
const legacyRes = verifyReceiptSignature(legacyNoDegraded, legacySig, pubPem)
ok('legacy receipt signed without degraded verifies', legacyRes.valid, legacyRes)
ok('legacy receipt: reports the legacy-without-degraded form',
   legacyRes.form === 'legacy-without-degraded', legacyRes.form)
ok('legacy receipt: canonical bytes are the ones it was signed over',
   legacyRes.canonical_payload === gatewayCanonical(legacyNoDegraded))
ok('legacy receipt: signed_fields exclude degraded',
   legacyRes.signed_fields?.includes('degraded') === false && legacyRes.signed_fields?.includes('sequence') === true,
   legacyRes.signed_fields)
ok('legacy receipt: tampered sequence still fails',
   !verifyReceiptSignature({ ...legacyNoDegraded, sequence: 4 }, legacySig, pubPem).valid)

// A legacy receipt whose store row later shows degraded=1: the signature never
// covered it, so the result must say so rather than vouch for it.
const legacyShowsDegraded = { ...legacyNoDegraded, degraded: true }
const lsd = verifyReceiptSignature(legacyShowsDegraded, legacySig, pubPem)
ok('legacy receipt displaying degraded:true: signature is valid over the legacy form',
   lsd.valid && lsd.form === 'legacy-without-degraded', lsd)
ok('legacy receipt displaying degraded:true: degraded is reported as NOT signed',
   lsd.unsigned_canonical_fields?.includes('degraded') === true, lsd.unsigned_canonical_fields)

// Original 7-field receipt (pre-manifest, pre-#101).
const seven: Record<string, unknown> = {
  receipt_id: 'rcpt_seven', tenant_id: 't7', decision: 'allow', action_class: 'B',
  risk_level: 'low', oid_hex: '13'.repeat(32), recorded_at: 1747584000000,
}
const sevenRes = verifyReceiptSignature(seven, gwSign(seven), pubPem)
ok('original 7-field receipt verifies', sevenRes.valid && sevenRes.form === 'legacy-without-degraded', sevenRes)

// ── 4. Field list parity: vendored copy, synoi-gap schema, gateway ──────────

const vendoredPath = resolve(__dirname, '..', 'vectors', 'canonical-receipt-fields.json')
const vendored = JSON.parse(readFileSync(vendoredPath, 'utf8')) as {
  legacy_required_fields: string[]; optional_fields: string[]
}
ok('src CANONICAL_FIELDS == vendored legacy_required_fields',
   JSON.stringify([...CANONICAL_FIELDS]) === JSON.stringify(vendored.legacy_required_fields),
   [...CANONICAL_FIELDS])
ok('src OPTIONAL_CANONICAL_FIELDS == vendored optional_fields',
   JSON.stringify([...OPTIONAL_CANONICAL_FIELDS]) === JSON.stringify(vendored.optional_fields),
   [...OPTIONAL_CANONICAL_FIELDS])
ok('src ALL_CANONICAL_FIELDS == the 26 gateway fields, sorted',
   JSON.stringify([...(ALL_CANONICAL_FIELDS ?? [])]) === JSON.stringify([...GATEWAY_FIELDS].sort()),
   [...(ALL_CANONICAL_FIELDS ?? [])])

// Sibling checkouts: SYNOI_GAP_DIR / SYNOI_GATEWAY_DIR, else ../synoi-gap and
// ../synoi-gateway next to this repo. Skipped (with a notice) when absent, e.g.
// in an npm consumer or a CI checkout of this repo alone.
const gapDir = process.env['SYNOI_GAP_DIR'] ?? resolve(__dirname, '..', '..', 'synoi-gap')
const gapSchema = join(gapDir, 'schemas', 'canonical-receipt-fields.json')
if (existsSync(gapSchema)) {
  const upstream = readFileSync(gapSchema, 'utf8').replace(/\r\n/g, '\n')
  const local = readFileSync(vendoredPath, 'utf8').replace(/\r\n/g, '\n')
  ok(`vendored schema is identical to ${gapSchema}`, upstream === local,
     'vectors/canonical-receipt-fields.json has drifted from synoi-gap; re-copy it and update src/canonical-fields.ts')
} else {
  process.stdout.write(`SKIP synoi-gap schema drift check: ${gapSchema} not present\n`)
}

const gwDir = process.env['SYNOI_GATEWAY_DIR'] ?? resolve(__dirname, '..', '..', 'synoi-gateway')
const gwRouter = join(gwDir, 'src', 'verify-router.ts')
if (existsSync(gwRouter)) {
  const src = readFileSync(gwRouter, 'utf8')
  const m = /export const CANONICAL_FIELDS = \[([\s\S]*?)\] as const/.exec(src)
  const gwFields = m ? [...m[1]!.matchAll(/'([a-z0-9_]+)'/g)].map((x) => x[1]!).sort() : []
  ok(`ALL_CANONICAL_FIELDS == ${gwRouter} CANONICAL_FIELDS`,
     JSON.stringify(gwFields) === JSON.stringify([...(ALL_CANONICAL_FIELDS ?? [])]), gwFields)
} else {
  process.stdout.write(`SKIP gateway field-list check: ${gwRouter} not present\n`)
}

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed === 0 ? 0 : 1)
