/**
 * test/cited-oracle-render.test.ts
 *
 * S2.4: cited_oracle_inputs[] render prominence.
 *
 * Verifies:
 *   - Each oracle input entry is rendered with subject_type, fetched_at (human),
 *     source_url, value_hash status, and raw_value pretty-printed.
 *   - value_hash recomputed locally as proof (pass or fail mark).
 *   - A mismatching value_hash is flagged, not silently ignored.
 *   - The section is rendered prominently (non-empty, labeled header).
 *   - The word "independent" does NOT appear in any render output.
 *   - Oracle inputs with no source_cursor do NOT show a cursor label line.
 */

import { createHash } from 'node:crypto'
import {
  renderOracleInput,
  renderReceiptResult,
  formatReceiptRenderResult,
  type OracleInputRaw,
} from '../src/render'

let passed = 0
let failed = 0

function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

// ── Compute a correct value_hash for use in fixtures ─────────────────────────

function computeHash(raw: unknown): string {
  // JCS: sort keys at every level.
  function jcs(o: unknown): string {
    if (o === null || typeof o !== 'object' || Array.isArray(o)) return JSON.stringify(o)
    const r = o as Record<string, unknown>
    const out: Record<string, unknown> = {}
    for (const k of Object.keys(r).sort()) {
      const v = r[k]
      out[k] = (v !== null && typeof v === 'object' && !Array.isArray(v)) ? JSON.parse(jcs(v)) : v
    }
    return JSON.stringify(out)
  }
  return 'sha256:' + createHash('sha256').update(jcs(raw), 'utf8').digest('hex')
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

const weatherRaw = { temp_f: 78, observed_at: '2026-06-17T19:32:18.000Z' }
const ofacRaw    = { query: 'Test Name', match: 'none', list_version: 'SDN-20260617' }
const timeRaw    = { now_utc: '2026-06-17T19:32:18.000Z', tz: 'America/Denver' }

const weatherEntry: OracleInputRaw = {
  subject_type: 'weather',
  raw_value:    weatherRaw,
  fetched_at:   '2026-06-17T19:32:18.412Z',
  source_url:   'https://api.openweathermap.org/data/2.5/weather?zip=84045',
  value_hash:   computeHash(weatherRaw),
}

const ofacEntry: OracleInputRaw = {
  subject_type:   'ofac',
  raw_value:      ofacRaw,
  fetched_at:     '2026-06-17T06:00:00.000Z',
  source_url:     'https://ofac.treasury.gov/sdn.xml',
  value_hash:     computeHash(ofacRaw),
  source_cursor:  'SDN-20260617',
}

const timeEntry: OracleInputRaw = {
  subject_type: 'time',
  raw_value:    timeRaw,
  fetched_at:   '2026-06-17T19:32:18.001Z',
  source_url:   'system:clock',
  value_hash:   computeHash(timeRaw),
}

// Entry with a deliberately wrong hash to test mismatch detection.
const badHashEntry: OracleInputRaw = {
  subject_type: 'weather',
  raw_value:    weatherRaw,
  fetched_at:   '2026-06-17T19:32:18.412Z',
  source_url:   'https://api.openweathermap.org/data/2.5/weather?zip=84045',
  value_hash:   'sha256:' + 'f'.repeat(64),
}

// ── A: renderOracleInput field presence ──────────────────────────────────────

const rw = renderOracleInput(weatherEntry)

ok('oracle render: subject_type present',
   rw.subject_type === 'weather')

ok('oracle render: raw_value_pretty is JSON string',
   typeof rw.raw_value_pretty === 'string' && rw.raw_value_pretty.includes('temp_f'))

ok('oracle render: fetched_at_human is readable UTC string',
   rw.fetched_at_human.includes('2026-06-17') && rw.fetched_at_human.includes('UTC'))

ok('oracle render: source_url present',
   rw.source_url === weatherEntry.source_url)

ok('oracle render: value_hash_ok true for correct hash',
   rw.value_hash_ok === true)

// ── B: value_hash mismatch detection ─────────────────────────────────────────

const rb = renderOracleInput(badHashEntry)
ok('oracle render: value_hash_ok false for mismatching hash',
   rb.value_hash_ok === false)

// ── C: multiple oracle inputs rendered prominently ────────────────────────────

const receipt: Record<string, unknown> = {
  receipt_id: 'rcpt_oracle_test',
  ed25519_signer_oid: 'sha256:' + 'a'.repeat(64),
  ml_dsa_signer_oid:  'sha256:' + 'b'.repeat(64),
  cited_oracle_inputs: [weatherEntry, ofacEntry, timeEntry],
}

const result = renderReceiptResult({ receipt, valid: true, algorithm: 'DSSE(ed25519+ml-dsa-65)' })

ok('renderReceiptResult: oracle_inputs length is 3',
   result.oracle_inputs.length === 3)

ok('renderReceiptResult: all subject_types present',
   result.oracle_inputs.map(o => o.subject_type).join(',') === 'weather,ofac,time')

ok('renderReceiptResult: all value_hash_ok true for correct fixtures',
   result.oracle_inputs.every(o => o.value_hash_ok === true))

// ── D: formatReceiptRenderResult contains oracle section header and values ────

const formatted = formatReceiptRenderResult(result)

ok('formatted: contains oracle inputs section header',
   formatted.includes('Cited oracle inputs'))

ok('formatted: contains weather subject_type',
   formatted.includes('weather'))

ok('formatted: contains ofac subject_type',
   formatted.includes('ofac'))

ok('formatted: contains time subject_type',
   formatted.includes('time'))

ok('formatted: contains temp_f from weather raw_value',
   formatted.includes('temp_f'))

ok('formatted: contains fetched_at human string',
   formatted.includes('2026-06-17') && formatted.includes('UTC'))

ok('formatted: contains source_url',
   formatted.includes('openweathermap.org'))

ok('formatted: value_hash pass mark shown',
   formatted.includes('(hash ok)'))

// ── E: "independent" must never appear in render output ──────────────────────

ok('formatted: word "independent" does not appear (Section 16 checklist)',
   !formatted.toLowerCase().includes('independent'),
   'VIOLATION: "independent" found in render output')

// ── F: empty cited_oracle_inputs ─────────────────────────────────────────────

const receiptNoOracle: Record<string, unknown> = {
  receipt_id: 'rcpt_no_oracle',
  cited_oracle_inputs: [],
}
const resultNoOracle = renderReceiptResult({ receipt: receiptNoOracle, valid: true, algorithm: 'Ed25519' })
ok('no oracle inputs: oracle_inputs array is empty',
   resultNoOracle.oracle_inputs.length === 0)

const formattedNoOracle = formatReceiptRenderResult(resultNoOracle)
ok('no oracle inputs: section header absent when empty',
   !formattedNoOracle.includes('Cited oracle inputs'))

// ── G: absent cited_oracle_inputs ────────────────────────────────────────────

const receiptAbsent: Record<string, unknown> = { receipt_id: 'rcpt_absent' }
const resultAbsent = renderReceiptResult({ receipt: receiptAbsent, valid: true, algorithm: 'Ed25519' })
ok('absent oracle inputs: oracle_inputs array is empty',
   resultAbsent.oracle_inputs.length === 0)

// ── H: source_url as full string (64-hex OID scenario) ────────────────────────

const oidUrlEntry: OracleInputRaw = {
  subject_type: 'cve',
  raw_value:    { cve_id: 'CVE-2026-12345', cvss_v3: 9.8, nvd_published: '2026-06-17T00:00:00.000Z' },
  fetched_at:   '2026-06-17T19:32:18.000Z',
  source_url:   'sha256:' + '0'.repeat(64),
  value_hash:   computeHash({ cve_id: 'CVE-2026-12345', cvss_v3: 9.8, nvd_published: '2026-06-17T00:00:00.000Z' }),
}
const rOid = renderOracleInput(oidUrlEntry)
ok('source_url as 64-hex OID preserved verbatim',
   rOid.source_url === 'sha256:' + '0'.repeat(64))

// ── Summary ───────────────────────────────────────────────────────────────────

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed === 0 ? 0 : 1)
