/**
 * render.ts -- human-readable terminal rendering of SynOI Decision Receipt
 * verification results.
 *
 * S2.4 additions (2026-06-18):
 *   - Dual signer OID rows (ed25519_signer_oid / ml_dsa_signer_oid), NOT
 *     collapsed into one signer_oid field. Addresses re-panel P1 finding F-V.
 *   - cited_oracle_inputs[] rendered prominently: subject_type label,
 *     raw_value pretty-printed, fetched_at as human-readable local time,
 *     source_url (full 64-hex OID), source_cursor labeled per ARCH.1 res 4
 *     ("Feed snapshot" for ofac subject_type, "Feed cursor" for all others;
 *     NEVER "cache cursor"), value_hash recomputed locally and shown as
 *     pass/fail mark.
 *
 * Contracts:
 *   - "independent" MUST NOT appear in any render output.
 *   - source_cursor label for ofac: "Feed snapshot"; others: "Feed cursor".
 *     The string "cache cursor" (case-insensitive) must never appear.
 *   - ed25519_signer_oid and ml_dsa_signer_oid are SEPARATE output fields.
 *   - value_hash is recomputed from raw_value (sha256 over JCS canonical form)
 *     and shown as a pass/fail mark. The computation is local -- no network.
 */

import { createHash } from 'node:crypto'

// ── Inbound receipt shape used by the render path ────────────────────────────

/** Minimal oracle input shape expected in receipt.cited_oracle_inputs[]. */
export interface OracleInputRaw {
  subject_type:    string
  raw_value:       unknown
  fetched_at:      string
  source_url:      string
  value_hash:      string
  feed_claimed_at?: string
  source_cursor?:  string
}

/** Dual-signer OID fields surfaced from the receipt attestation + envelope. */
export interface SignerOids {
  /** sha256:... OID of the Ed25519 signing key (operator / Steve's browser key). */
  ed25519_signer_oid: string | null
  /** sha256:... OID of the ML-DSA-65 signing key (SynOI published co-signer). */
  ml_dsa_signer_oid:  string | null
}

/** Rendered output for one cited_oracle_inputs[] entry. */
export interface RenderedOracleInput {
  /** e.g. "weather", "ofac", "time", "sms_hitl", "webhook", "cve" */
  subject_type:    string
  /** JSON.stringify of raw_value with 2-space indent. */
  raw_value_pretty: string
  /** Human-readable UTC string from fetched_at (RFC 3339 UTC). */
  fetched_at_human: string
  /** Full source_url (may be a 64-hex OID reference or an https URL). */
  source_url:       string
  /**
   * source_cursor label per ARCH.1 resolution 4:
   *   subject_type === "ofac" -> "Feed snapshot"
   *   all others              -> "Feed cursor"
   *   absent                  -> null
   * The string "cache cursor" (any casing) MUST NOT appear here.
   */
  source_cursor_label: string | null
  /** The raw cursor string from the receipt, if present. */
  source_cursor_value: string | null
  /** true = value_hash matches sha256(JCS(raw_value)); false = mismatch; null = could not compute. */
  value_hash_ok:       boolean | null
}

/** Full rendered result for one receipt verification. */
export interface ReceiptRenderResult {
  receipt_id:          string | null
  valid:               boolean
  algorithm:           string
  /**
   * Two distinct rows, one per algorithm half.
   * A null oid means the field was not present on the receipt.
   */
  signer_oids:         SignerOids
  /** Populated when the receipt carries cited_oracle_inputs[]. */
  oracle_inputs:       RenderedOracleInput[]
  /** Human-readable verification status line. */
  status_line:         string
  /** Failure reasons when valid === false. */
  reasons:             string[]
}

// ── Source-cursor label (ARCH.1 resolution 4) ────────────────────────────────

/**
 * Derive the source_cursor label for a given subject_type.
 *
 * ARCH.1 resolution 4 rules:
 *   - ofac: "Feed snapshot"   (OFAC SDN list is a versioned snapshot)
 *   - all others: "Feed cursor"
 *   - NEVER "cache cursor" (prohibited label; snapshot test enforces this)
 */
export function sourceCursorLabel(subjectType: string): string {
  return subjectType === 'ofac' ? 'Feed snapshot' : 'Feed cursor'
}

// ── value_hash local recompute ────────────────────────────────────────────────

/**
 * Recompute value_hash = "sha256:" + sha256hex(JSON.stringify(raw_value))
 * using a deterministic key-sorted JSON serialization (JCS-compatible for
 * plain objects -- mirrors the gateway's canonicalize() behavior for the
 * subject_type schemas actually used: flat objects with no special float
 * edge cases).
 *
 * Returns true on match, false on mismatch, null if raw_value is not
 * serializable or value_hash has no recognizable prefix.
 */
export function recomputeValueHashOk(entry: OracleInputRaw): boolean | null {
  try {
    if (typeof entry.raw_value !== 'object' || entry.raw_value === null) {
      return null
    }
    const canonical = jcsCanonical(entry.raw_value as Record<string, unknown>)
    const computed = 'sha256:' + createHash('sha256').update(canonical, 'utf8').digest('hex')
    return computed === entry.value_hash
  } catch {
    return null
  }
}

/** RFC 8785 JCS for plain objects (sorted keys, no float special cases). */
function jcsCanonical(obj: unknown): string {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    return JSON.stringify(obj)
  }
  const record = obj as Record<string, unknown>
  const sorted: Record<string, unknown> = {}
  for (const k of Object.keys(record).sort()) {
    sorted[k] = record[k]
  }
  // Recursively sort nested objects.
  const out: Record<string, unknown> = {}
  for (const k of Object.keys(sorted)) {
    const v = sorted[k]
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      out[k] = JSON.parse(jcsCanonical(v))
    } else {
      out[k] = v
    }
  }
  return JSON.stringify(out)
}

// ── Oracle input rendering ────────────────────────────────────────────────────

/** Render one cited_oracle_inputs[] entry. */
export function renderOracleInput(entry: OracleInputRaw): RenderedOracleInput {
  const fetched_at_human = formatUtcHuman(entry.fetched_at)
  const raw_value_pretty = JSON.stringify(entry.raw_value, null, 2)
  const value_hash_ok    = recomputeValueHashOk(entry)

  const source_cursor_label =
    entry.source_cursor !== undefined && entry.source_cursor !== null
      ? sourceCursorLabel(entry.subject_type)
      : null

  const source_cursor_value =
    typeof entry.source_cursor === 'string' ? entry.source_cursor : null

  return {
    subject_type:        entry.subject_type,
    raw_value_pretty,
    fetched_at_human,
    source_url:          entry.source_url,
    source_cursor_label,
    source_cursor_value,
    value_hash_ok,
  }
}

/** Format an RFC 3339 UTC string as a readable human string. */
function formatUtcHuman(iso: string): string {
  try {
    const d = new Date(iso)
    if (isNaN(d.getTime())) return iso
    // e.g. "2026-06-17 19:32:18 UTC"
    return d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, '') + ' UTC'
  } catch {
    return iso
  }
}

// ── Signer OID extraction ─────────────────────────────────────────────────────

/**
 * Extract ed25519_signer_oid and ml_dsa_signer_oid from a receipt.
 *
 * The receipt may carry:
 *   receipt.ed25519_signer_oid -- OID of the Ed25519 signing key
 *   receipt.ml_dsa_signer_oid  -- OID of the ML-DSA-65 co-signing key
 *
 * For v1 receipts (no signer_oid fields), receipt.signer_oid is treated
 * as the Ed25519 OID and ml_dsa is null (v1 was Ed25519-only).
 *
 * Two distinct fields are ALWAYS returned; they are NEVER collapsed.
 */
export function extractSignerOids(receipt: Record<string, unknown>): SignerOids {
  const ed =
    typeof receipt['ed25519_signer_oid'] === 'string'
      ? (receipt['ed25519_signer_oid'] as string)
      : typeof receipt['signer_oid'] === 'string'
        ? (receipt['signer_oid'] as string)
        : null

  const ml =
    typeof receipt['ml_dsa_signer_oid'] === 'string'
      ? (receipt['ml_dsa_signer_oid'] as string)
      : null

  return { ed25519_signer_oid: ed, ml_dsa_signer_oid: ml }
}

// ── Receipt render ────────────────────────────────────────────────────────────

/**
 * Render a receipt verification result into a structured ReceiptRenderResult.
 *
 * @param receipt  the raw receipt object (Record<string, unknown>)
 * @param valid    from the verify result
 * @param algorithm from the verify result (e.g. "DSSE(ed25519+ml-dsa-65)")
 * @param reasons  failure reasons when invalid
 */
export function renderReceiptResult(params: {
  receipt:   Record<string, unknown>
  valid:     boolean
  algorithm: string
  reasons?:  string[]
}): ReceiptRenderResult {
  const { receipt, valid, algorithm, reasons = [] } = params

  const receipt_id =
    typeof receipt['receipt_id'] === 'string' ? (receipt['receipt_id'] as string) : null

  const signer_oids = extractSignerOids(receipt)

  // cited_oracle_inputs: render each entry if present.
  const raw_inputs = receipt['cited_oracle_inputs']
  const oracle_inputs: RenderedOracleInput[] = []
  if (Array.isArray(raw_inputs)) {
    for (const entry of raw_inputs) {
      if (entry !== null && typeof entry === 'object') {
        oracle_inputs.push(renderOracleInput(entry as OracleInputRaw))
      }
    }
  }

  const status_line = valid
    ? 'VERIFIED -- signature is valid; receipt has not been tampered with.'
    : 'INVALID -- ' + (reasons.length > 0 ? reasons.join(', ') : 'verification failed')

  return {
    receipt_id,
    valid,
    algorithm,
    signer_oids,
    oracle_inputs,
    status_line,
    reasons,
  }
}

// ── Terminal render (for CLI use) ─────────────────────────────────────────────

/**
 * Format a ReceiptRenderResult as a human-readable terminal string.
 *
 * Rules:
 *   - Does NOT use the word "independent" anywhere.
 *   - Dual signer OID rows are always present, labeled separately.
 *   - cited_oracle_inputs are rendered prominently under a header line.
 *   - source_cursor label: "Feed snapshot" (ofac) or "Feed cursor" (other).
 *   - value_hash shown as "(hash ok)" or "(HASH MISMATCH -- data may be corrupted)".
 */
export function formatReceiptRenderResult(r: ReceiptRenderResult): string {
  const lines: string[] = ['']

  lines.push(`  Receipt ID    : ${r.receipt_id ?? '(not reported)'}`)
  lines.push(`  Algorithm     : ${r.algorithm}`)
  lines.push('')

  // Dual signer OID rows -- always two distinct entries.
  lines.push('  Signer keys:')
  lines.push(`    Ed25519     : ${r.signer_oids.ed25519_signer_oid ?? '(not reported)'}`)
  lines.push(`    ML-DSA-65   : ${r.signer_oids.ml_dsa_signer_oid ?? '(not reported)'}`)
  lines.push('')

  // Oracle inputs -- prominent section.
  if (r.oracle_inputs.length > 0) {
    lines.push(`  Cited oracle inputs (${r.oracle_inputs.length}):`)
    let idx = 0
    for (const o of r.oracle_inputs) {
      idx++
      const hashMark = o.value_hash_ok === true
        ? '(hash ok)'
        : o.value_hash_ok === false
          ? '(HASH MISMATCH -- data may be corrupted)'
          : '(hash not verified)'
      lines.push('')
      lines.push(`    [${idx}] Subject type : ${o.subject_type}`)
      lines.push(`        Fetched at    : ${o.fetched_at_human}`)
      lines.push(`        Source        : ${o.source_url}`)
      if (o.source_cursor_label !== null && o.source_cursor_value !== null) {
        lines.push(`        ${o.source_cursor_label.padEnd(14)}: ${o.source_cursor_value}`)
      }
      lines.push(`        Value hash    : ${hashMark}`)
      lines.push(`        Value:`)
      for (const vl of o.raw_value_pretty.split('\n')) {
        lines.push(`          ${vl}`)
      }
    }
    lines.push('')
  }

  // Status line.
  const mark = r.valid ? '  VERIFIED' : '  INVALID'
  lines.push(`${mark}`)
  lines.push(`  ${r.status_line}`)
  lines.push('')

  return lines.join('\n')
}
