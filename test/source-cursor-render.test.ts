/**
 * test/source-cursor-render.test.ts
 *
 * ARCH.1 resolution 4 binding:
 *   source_cursor label for subject_type "ofac" MUST be "Feed snapshot".
 *   source_cursor label for all other subject_types MUST be "Feed cursor".
 *   The string "cache cursor" (any case) MUST NEVER appear in any render output.
 *
 * These are snapshot assertions: any label change that introduces "cache cursor"
 * or diverges from the above mapping is a build failure.
 */

import { sourceCursorLabel, renderOracleInput, formatReceiptRenderResult, renderReceiptResult } from '../src/render'

let passed = 0
let failed = 0

function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

// ── A: sourceCursorLabel direct unit tests ────────────────────────────────────

ok('ARCH.1: ofac -> "Feed snapshot"',
   sourceCursorLabel('ofac') === 'Feed snapshot',
   `got: ${sourceCursorLabel('ofac')}`)

ok('ARCH.1: weather -> "Feed cursor"',
   sourceCursorLabel('weather') === 'Feed cursor',
   `got: ${sourceCursorLabel('weather')}`)

ok('ARCH.1: cve -> "Feed cursor"',
   sourceCursorLabel('cve') === 'Feed cursor',
   `got: ${sourceCursorLabel('cve')}`)

ok('ARCH.1: webhook -> "Feed cursor"',
   sourceCursorLabel('webhook') === 'Feed cursor',
   `got: ${sourceCursorLabel('webhook')}`)

ok('ARCH.1: time -> "Feed cursor"',
   sourceCursorLabel('time') === 'Feed cursor',
   `got: ${sourceCursorLabel('time')}`)

ok('ARCH.1: sms_hitl -> "Feed cursor"',
   sourceCursorLabel('sms_hitl') === 'Feed cursor',
   `got: ${sourceCursorLabel('sms_hitl')}`)

// "cache cursor" string must never appear in any label output.
const allLabels = ['ofac', 'weather', 'cve', 'webhook', 'time', 'sms_hitl', 'unknown_type'].map(t => sourceCursorLabel(t))
ok('ARCH.1: "cache cursor" never appears in any label',
   !allLabels.some(l => l.toLowerCase().includes('cache cursor')),
   `offending labels: ${allLabels.filter(l => l.toLowerCase().includes('cache cursor')).join(', ')}`)

// ── B: renderOracleInput source_cursor_label field ────────────────────────────

const ofacEntryWithCursor = {
  subject_type: 'ofac',
  raw_value: { query: 'Test Name', match: 'none', list_version: 'v20260617' },
  fetched_at: '2026-06-17T19:32:18.000Z',
  source_url: 'https://ofac.treasury.gov/sdn.xml',
  value_hash: 'sha256:' + 'a'.repeat(64),
  source_cursor: 'SDN-20260617',
}

const renderedOfac = renderOracleInput(ofacEntryWithCursor)

ok('renderOracleInput: ofac source_cursor_label is "Feed snapshot"',
   renderedOfac.source_cursor_label === 'Feed snapshot',
   `got: ${renderedOfac.source_cursor_label}`)

ok('renderOracleInput: ofac source_cursor_value preserved',
   renderedOfac.source_cursor_value === 'SDN-20260617')

const weatherEntryWithCursor = {
  subject_type: 'weather',
  raw_value: { temp_f: 78, observed_at: '2026-06-17T19:32:18.000Z' },
  fetched_at: '2026-06-17T19:32:18.000Z',
  source_url: 'https://api.openweathermap.org/data/2.5/weather?zip=84045',
  value_hash: 'sha256:' + 'b'.repeat(64),
  source_cursor: 'page:1',
}

const renderedWeather = renderOracleInput(weatherEntryWithCursor)

ok('renderOracleInput: weather source_cursor_label is "Feed cursor"',
   renderedWeather.source_cursor_label === 'Feed cursor',
   `got: ${renderedWeather.source_cursor_label}`)

// ── C: renderOracleInput no source_cursor -> null ─────────────────────────────

const entryNoCursor = {
  subject_type: 'time',
  raw_value: { now_utc: '2026-06-17T19:32:18.000Z', tz: 'UTC' },
  fetched_at: '2026-06-17T19:32:18.000Z',
  source_url: 'system:clock',
  value_hash: 'sha256:' + 'c'.repeat(64),
}

const renderedNoC = renderOracleInput(entryNoCursor)

ok('renderOracleInput: absent source_cursor -> label null',
   renderedNoC.source_cursor_label === null)

ok('renderOracleInput: absent source_cursor -> value null',
   renderedNoC.source_cursor_value === null)

// ── D: formatReceiptRenderResult must never contain "cache cursor" ─────────────

const receipt: Record<string, unknown> = {
  receipt_id: 'rcpt_test_123',
  ed25519_signer_oid: 'sha256:' + 'e'.repeat(64),
  ml_dsa_signer_oid: 'sha256:' + 'f'.repeat(64),
  cited_oracle_inputs: [ofacEntryWithCursor, weatherEntryWithCursor],
}

const rendered = renderReceiptResult({ receipt, valid: true, algorithm: 'DSSE(ed25519+ml-dsa-65)' })
const formatted = formatReceiptRenderResult(rendered)

ok('formatted output never contains "cache cursor" (case-insensitive)',
   !formatted.toLowerCase().includes('cache cursor'),
   'offending text found')

ok('formatted output contains "Feed snapshot" for ofac cursor',
   formatted.includes('Feed snapshot'))

ok('formatted output contains "Feed cursor" for weather cursor',
   formatted.includes('Feed cursor'))

// ── Summary ───────────────────────────────────────────────────────────────────

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed === 0 ? 0 : 1)
