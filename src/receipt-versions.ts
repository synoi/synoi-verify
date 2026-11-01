/**
 * Receipt version registry.
 *
 * Every receipt is verified against exactly ONE registered version's signed
 * field list, canonicalization and signature scheme. Nothing here guesses a
 * form by trying subsets of fields.
 *
 * How a receipt picks its entry:
 *
 *   receipt_scheme 'synoi.receipt/v2'           -> gap-v2-dsse
 *   receipt_scheme 'synoi.receipt/gap-selfsign' -> gap-selfsign
 *   receipt_scheme absent (hosted flat family):
 *     schema_version is a string               -> the hosted-flat entry whose
 *                                                 schema_version equals it, or
 *                                                 FAIL CLOSED if there is none
 *     schema_version absent or null            -> the closed set of unversioned
 *                                                 legacy entries, in order:
 *                                                 hosted-v1.1, hosted-v1.0
 *
 * Why the unversioned rule tries two entries, and why that is not guessing:
 * nothing signed so far names its own form, and no unsigned signal (date,
 * gateway version) is reliable, because each install picked up gateway #253 on
 * its own schedule. But the two entries' canonical bytes are DISJOINT by
 * construction: hosted-v1.1 always signs a "degraded" key (absent is signed as
 * false), hosted-v1.0 never does. So for a given receipt at most one entry's
 * bytes can match a signature, and which one matched is reported as `version`.
 * Neither entry signs `schema_version`, so a versioned receipt that has its
 * version stripped cannot verify as either of them.
 *
 * Legacy entries have schema_version null and are NOT addressable by an
 * explicit value: a receipt claiming schema_version 'hosted-v1.1' was never
 * signed by anything and fails closed like any unknown value.
 *
 * Browser-safe: pure data and string work, no node: imports.
 */

import { LEGACY_REQUIRED_FIELDS, OPTIONAL_FIELDS } from './canonical-fields'

// ── Warnings ─────────────────────────────────────────────────────────────────

/**
 * The receipt verified as hosted-v1.0 (signed before gateway #253 bound
 * `degraded`) but carries a `degraded` value. That value is not signed.
 */
export const UNSIGNED_DEGRADED = 'UNSIGNED_DEGRADED' as const

/**
 * The receipt carries a field its version does not sign, but which a LATER
 * version does sign (today: `degraded_reason`, `integrity_grade`, `agent_id`,
 * `owner_oid` on an unversioned receipt). Its value is display-only and must
 * not be trusted.
 */
export const UNSIGNED_FIELD = 'UNSIGNED_FIELD' as const

export type VerifyWarningCode = typeof UNSIGNED_DEGRADED | typeof UNSIGNED_FIELD

/** A machine-readable code plus a plain-text message for a human reader. */
export interface VerifyWarning {
  code:    VerifyWarningCode
  /** The receipt field the warning is about. */
  field:   string
  message: string
}

/**
 * The UNSIGNED_DEGRADED warning for a hosted-v1.0 receipt carrying `value`.
 * Only call this when the receipt verified as hosted-v1.0 AND carries a
 * non-null `degraded`.
 */
export function unsignedDegradedWarning(value: unknown): VerifyWarning {
  return {
    code:    UNSIGNED_DEGRADED,
    field:   'degraded',
    message:
      'This receipt was signed before `degraded` was included in the signature. ' +
      `Its \`degraded\` value (${JSON.stringify(value)}) was not signed and must not be trusted.`,
  }
}

/** The UNSIGNED_FIELD warning for `field` on a receipt verified as `versionId`. */
export function unsignedFieldWarning(field: string, value: unknown, versionId: string): VerifyWarning {
  return {
    code:    UNSIGNED_FIELD,
    field,
    message:
      `This receipt verified as ${versionId}, which does not sign \`${field}\`. ` +
      `Its \`${field}\` value (${JSON.stringify(value)}) was not signed and must not be trusted.`,
  }
}

// ── hosted-v1.2 vocabulary ───────────────────────────────────────────────────

/** The `schema_version` value a hosted-v1.2 receipt carries (and signs). */
export const HOSTED_V1_2_SCHEMA_VERSION = 'hosted-v1.2' as const

/** Integrity grades, best first. */
export const INTEGRITY_GRADES = ['A', 'B', 'C', 'D'] as const
export type IntegrityGrade = (typeof INTEGRITY_GRADES)[number]

/**
 * hosted-v1.2 `degraded_reason` codes and the grade each one implies. Every
 * code is a branch the gateway already takes when it sets `degraded` today
 * (synoi-gateway src/integrity.ts and src/anthropic-receipt-sign.ts); see the
 * gateway's docs/RECEIPT_VERSIONS.md for the source line of each.
 *
 *   A  not degraded: manifest present and matching, trusted unexpired token
 *   B  code matches its manifest, but the control plane has not vouched for it
 *   C  the control plane flagged this install
 *   D  code does not match its manifest (or has none), or the request was not
 *      governed at all
 */
export const DEGRADED_REASON_CODES: Readonly<Record<string, Exclude<IntegrityGrade, 'A'>>> = Object.freeze({
  manifest_missing:       'D',
  modified_code:          'D',
  resilience_fallback:    'D',
  trust_token_flagged:    'C',
  // F2: also covers a token whose control-plane status is unclear ('unknown'),
  // formerly its own code (trust_token_unverified).
  trust_token_absent:     'B',
  trust_token_expired:    'B',
})

/**
 * F2: the `schema_version` of a grant-bound receipt. hosted-v1.3 signs the
 * hosted-v1.2 field set with `grant_oid` REQUIRED; the gateway emits it for a
 * receipt that carries a capability grant (A2A delegation). `grant_oid` stays
 * optional (signed when present) in every earlier version.
 */
export const HOSTED_V1_3_SCHEMA_VERSION = 'hosted-v1.3' as const

/**
 * Optional hosted-v1.2 fields reserved for the agent registry: signed when
 * present, absent (or null) when the gateway does not know the agent.
 */
export const AGENT_REGISTRY_FIELDS = ['agent_id', 'owner_oid'] as const

// ── Registry types ───────────────────────────────────────────────────────────

export type VersionStatus = 'current' | 'legacy' | 'proposed'

interface VersionEntryBase {
  /** Registry key. */
  id:                string
  status:            VersionStatus
  canonicalization:  string
  signature_schemes: readonly string[]
  /** Warning codes this entry may emit on a valid result. */
  warnings:          readonly VerifyWarningCode[]
  description:       string
}

/** A flat hosted-gateway receipt (no receipt_scheme). */
export interface HostedFlatVersionEntry extends VersionEntryBase {
  family:          'hosted-flat'
  id:              HostedVersionId
  /** The receipt's `schema_version` for this entry; null = unversioned legacy. */
  schema_version:  string | null
  /** Signed, and must be present and non-null (`degraded`: see degraded_rule). */
  required_fields: readonly string[]
  /** Signed when present and non-null, omitted otherwise. */
  optional_fields: readonly string[]
  /**
   * 'unsigned'            not signed at all
   * 'absent-is-false'     always signed as a boolean; absent or null signs false
   * 'required'            always signed as a boolean; absent or null fails
   */
  degraded_rule:   'unsigned' | 'absent-is-false' | 'required'
  /**
   * Fields this entry does NOT sign that a receipt may still display. A
   * non-null value produces a warning (UNSIGNED_DEGRADED for `degraded`,
   * UNSIGNED_FIELD otherwise) and is listed in unsigned_canonical_fields.
   */
  display_unsigned: readonly string[]
  /** The PR #1 form label, kept for the two unversioned entries only. */
  form?:           'current' | 'legacy-without-degraded'
}

/** A GAP CDRO receipt verified by a delegated library, keyed by receipt_scheme. */
export interface GapCdroVersionEntry extends VersionEntryBase {
  family:          'gap-cdro'
  receipt_scheme:  string
  /** Signed: the whole envelope except these top-level fields. */
  signed_all_except: readonly string[]
  /** Signed fields that carry the version inside the signed bytes. */
  version_fields:  readonly string[]
}

export type ReceiptVersionEntry = HostedFlatVersionEntry | GapCdroVersionEntry
export type HostedVersionId = 'hosted-v1.0' | 'hosted-v1.1' | 'hosted-v1.2' | 'hosted-v1.3'

const OPTIONAL_WITHOUT_DEGRADED = OPTIONAL_FIELDS.filter((f) => f !== 'degraded')
const FLAT_CANON = 'flat-scalar-jcs: JCS over the present, non-null signed fields, keys sorted, scalars only'
const FLAT_SIGS  = ['ed25519 (hex)', 'ml-dsa-65 (base64, gateway only)'] as const

// ── The registry ─────────────────────────────────────────────────────────────

export const RECEIPT_VERSION_REGISTRY: readonly ReceiptVersionEntry[] = Object.freeze([
  {
    id:                'hosted-v1.0',
    family:            'hosted-flat',
    schema_version:    null,
    status:            'legacy',
    required_fields:   [...LEGACY_REQUIRED_FIELDS],
    optional_fields:   OPTIONAL_WITHOUT_DEGRADED,
    degraded_rule:     'unsigned',
    display_unsigned:  ['degraded', 'degraded_reason', 'integrity_grade', 'agent_id', 'owner_oid'],
    canonicalization:  FLAT_CANON,
    signature_schemes: FLAT_SIGS,
    warnings:          [UNSIGNED_DEGRADED, UNSIGNED_FIELD],
    form:              'legacy-without-degraded',
    description:
      'Hosted gateway receipt signed before gateway #253 bound `degraded`. No schema_version. ' +
      'Older field sets need no entry of their own: every non-required field is omit-when-absent.',
  },
  {
    id:                'hosted-v1.1',
    family:            'hosted-flat',
    schema_version:    null,
    status:            'legacy',
    required_fields:   [...LEGACY_REQUIRED_FIELDS, 'degraded'],
    optional_fields:   OPTIONAL_WITHOUT_DEGRADED,
    degraded_rule:     'absent-is-false',
    display_unsigned:  ['degraded_reason', 'integrity_grade', 'agent_id', 'owner_oid'],
    canonicalization:  FLAT_CANON,
    signature_schemes: FLAT_SIGS,
    warnings:          [UNSIGNED_FIELD],
    form:              'current',
    description:
      'Hosted gateway receipt since #253: `degraded` signed as !!degraded. No schema_version. ' +
      'What synoi-gateway emitted before hosted-v1.2. Its guard path (/v1/risk/evaluate) signed a literal false.',
  },
  {
    id:                'hosted-v1.2',
    family:            'hosted-flat',
    schema_version:    HOSTED_V1_2_SCHEMA_VERSION,
    status:            'current',
    required_fields:   [...LEGACY_REQUIRED_FIELDS, 'degraded', 'integrity_grade', 'schema_version'],
    optional_fields:   [...OPTIONAL_WITHOUT_DEGRADED, 'degraded_reason', 'agent_id', 'owner_oid'],
    degraded_rule:     'required',
    display_unsigned:  [],
    canonicalization:  FLAT_CANON,
    signature_schemes: FLAT_SIGS,
    warnings:          [],
    description:
      'What synoi-gateway emits (docs/RECEIPT_VERSIONS.md). Signs schema_version, the computed ' +
      '`degraded` on every path including the guard, integrity_grade (A-D), degraded_reason ' +
      '(sorted comma-joined codes) exactly when degraded, and, when the gateway knows them, ' +
      'the agent registry fields agent_id and owner_oid.',
  },
  {
    id:                'hosted-v1.3',
    family:            'hosted-flat',
    schema_version:    HOSTED_V1_3_SCHEMA_VERSION,
    status:            'current',
    required_fields:   [...LEGACY_REQUIRED_FIELDS, 'degraded', 'grant_oid', 'integrity_grade', 'schema_version'],
    optional_fields:   [...OPTIONAL_WITHOUT_DEGRADED.filter((f) => f !== 'grant_oid'), 'degraded_reason', 'agent_id', 'owner_oid'],
    degraded_rule:     'required',
    display_unsigned:  [],
    canonicalization:  FLAT_CANON,
    signature_schemes: FLAT_SIGS,
    warnings:          [],
    description:
      'Grant-bound hosted receipt (F2): the hosted-v1.2 field set and value rules, with grant_oid ' +
      'required. What synoi-gateway emits for a receipt that carries a capability grant (A2A ' +
      'delegation); receipts without a grant stay hosted-v1.2.',
  },
  {
    id:                'gap-v2-dsse',
    family:            'gap-cdro',
    receipt_scheme:    'synoi.receipt/v2',
    status:            'current',
    signed_all_except: ['oid', 'signature', 'ml_dsa_signature', 'signature_key_id', 'signature_algorithm', 'attestation'],
    version_fields:    ['receipt_scheme', 'gap_version'],
    canonicalization:  '@synoi/sraid canonicalize(cdroContentCore(receipt)), DSSE PAE over payloadType ' +
                       'application/vnd.synoi.gap+json',
    signature_schemes: ['dsse ed25519 + ml-dsa-65 (both required)'],
    warnings:          [],
    description:
      'GAP CDRO v2 (gateway engine and local-ingest). Has no `degraded` field. Verified by verifyReceiptV2.',
  },
  {
    id:                'gap-selfsign',
    family:            'gap-cdro',
    receipt_scheme:    'synoi.receipt/gap-selfsign',
    status:            'current',
    signed_all_except: ['oid', 'signature', 'ml_dsa_signature', 'attestation'],
    version_fields:    ['receipt_scheme', 'gap_version'],
    canonicalization:  '@synoi/gap receipt() envelope minus its EXCLUDED_FIELDS, canonicalized by @synoi/gap',
    signature_schemes: ['ed25519 (operator self-signed)'],
    warnings:          [],
    description:
      'Lite / self-host receipt from @synoi/gap receipt(). Has no `degraded` field. ' +
      'Verified by @synoi/gap verifyReceiptSignature (delegated, not re-implemented here).',
  },
] as ReceiptVersionEntry[])

/** The registry entry with this id, or undefined. */
export function getReceiptVersion(id: string): ReceiptVersionEntry | undefined {
  return RECEIPT_VERSION_REGISTRY.find((e) => e.id === id)
}

function hostedEntries(): HostedFlatVersionEntry[] {
  return RECEIPT_VERSION_REGISTRY.filter((e): e is HostedFlatVersionEntry => e.family === 'hosted-flat')
}

/** The unversioned legacy entries in the order they are tried. */
const UNVERSIONED_ORDER: readonly HostedVersionId[] = ['hosted-v1.1', 'hosted-v1.0']

export type HostedResolution =
  | { ok: true; rule: 'explicit' | 'unversioned-legacy'; entries: HostedFlatVersionEntry[] }
  | { ok: false; reason: string }

/**
 * Pick the hosted-flat entries a receipt may be verified against. Explicit
 * schema_version -> exactly one entry or a fail-closed reason. Absent or null
 * -> the unversioned legacy entries (see the file header).
 */
export function resolveHostedVersions(payload: Record<string, unknown>): HostedResolution {
  const v = payload['schema_version']
  if (v === undefined || v === null) {
    const all = hostedEntries()
    return {
      ok:      true,
      rule:    'unversioned-legacy',
      entries: UNVERSIONED_ORDER.map((id) => all.find((e) => e.id === id)!),
    }
  }
  const known = hostedEntries().filter((e) => e.schema_version !== null).map((e) => e.schema_version)
  if (typeof v !== 'string') {
    return { ok: false, reason: `unknown-schema-version: schema_version must be a string; got ${JSON.stringify(v)} (known: ${known.join(', ')})` }
  }
  const entry = hostedEntries().find((e) => e.schema_version === v)
  if (!entry) {
    return { ok: false, reason: `unknown-schema-version: schema_version ${JSON.stringify(v)} is not in the registry (known: ${known.join(', ')})` }
  }
  return { ok: true, rule: 'explicit', entries: [entry] }
}

// ── Canonicalization per entry ───────────────────────────────────────────────

export interface VersionCanonical {
  version:                   HostedVersionId
  canonical_payload:         string
  signed_fields:             string[]
  /** Fields the receipt carries that this version displays but does not sign. */
  unsigned_canonical_fields: string[]
}

function signedDegraded(value: unknown, rule: HostedFlatVersionEntry['degraded_rule'], id: string): boolean {
  if (value === true || value === 1) return true
  if (value === false || value === 0) return false
  if ((value === undefined || value === null) && rule === 'absent-is-false') return false
  if (value === undefined || value === null) {
    throw new Error(`${id}: 'degraded' is required`)
  }
  throw new Error(`${id}: 'degraded' must be a boolean (or 0/1); got ${JSON.stringify(value)}`)
}

/**
 * The exact bytes `versionId` signs for this receipt. Throws on an unknown id,
 * a missing required field, a non-scalar signed field, or a `degraded` value
 * the version cannot have signed. Serializer: `jcs` (passed in to keep the one
 * canonicalizer in ./verify-shared).
 */
export function canonicalForEntry(
  payload: Record<string, unknown>,
  entry:   HostedFlatVersionEntry,
  jcs:     (v: unknown) => string,
): VersionCanonical {
  const obj: Record<string, unknown> = {}
  const required = new Set(entry.required_fields)
  const fields = [...entry.required_fields, ...entry.optional_fields].sort()
  for (const key of fields) {
    let val = payload[key]
    if (key === 'degraded') val = signedDegraded(val, entry.degraded_rule, entry.id)
    if (val === undefined || val === null) {
      if (required.has(key)) throw new Error(`${entry.id}: missing required field '${key}'`)
      continue
    }
    // Fail closed on non-scalars: the signer only signs scalar fields, and JCS
    // would sort a nested object's keys where the signer's JSON.stringify did not.
    if (typeof val === 'object') {
      throw new Error(
        `canonicalPayload: canonical field '${key}' must be a scalar (string/number/boolean); ` +
          `got ${Array.isArray(val) ? 'array' : 'object'}. The signer never signs a non-scalar ` +
          `canonical field, so this receipt cannot be canonically reproduced.`,
      )
    }
    obj[key] = val
  }
  const unsigned = entry.display_unsigned.filter((f) => payload[f] !== undefined && payload[f] !== null)
  return {
    version:                   entry.id,
    canonical_payload:         jcs(obj),
    signed_fields:             Object.keys(obj).sort(),
    unsigned_canonical_fields: unsigned,
  }
}

/** Warnings for a VALID result under `entry`, in display_unsigned order. */
export function warningsForEntry(payload: Record<string, unknown>, entry: HostedFlatVersionEntry): VerifyWarning[] {
  const out: VerifyWarning[] = []
  for (const f of entry.display_unsigned) {
    const v = payload[f]
    if (v === undefined || v === null) continue
    out.push(f === 'degraded' ? unsignedDegradedWarning(v) : unsignedFieldWarning(f, v, entry.id))
  }
  return out
}

/**
 * hosted-v1.2 value rules, checked in addition to the signature (a signer bug
 * must not produce a receipt that verifies while saying two different things):
 *   - integrity_grade is one of A-D
 *   - degraded_reason is present exactly when degraded is true
 *   - degraded_reason is a sorted, comma-joined list of distinct known codes
 *   - integrity_grade is A when not degraded, else the worst grade of the codes
 * hosted-v1.3 has the same rules, and its grant_oid must be a non-empty string.
 * Returns a reason string on the first violation, or null.
 */
export function checkVersionSemantics(payload: Record<string, unknown>, entry: HostedFlatVersionEntry): string | null {
  if (entry.id !== 'hosted-v1.2' && entry.id !== 'hosted-v1.3') return null
  if (entry.id === 'hosted-v1.3') {
    const g = payload['grant_oid']
    if (typeof g !== 'string' || g === '') {
      return `${entry.id}: grant_oid must be a non-empty string; got ${JSON.stringify(g)}`
    }
  }
  // Agent registry fields: absent/null = unknown; when present, a non-empty string.
  for (const f of AGENT_REGISTRY_FIELDS) {
    const v = payload[f]
    if (v !== undefined && v !== null && (typeof v !== 'string' || v === '')) {
      return `${entry.id}: ${f} must be a non-empty string when present; got ${JSON.stringify(v)}`
    }
  }
  const degraded = payload['degraded'] === true || payload['degraded'] === 1
  const grade = payload['integrity_grade']
  if (typeof grade !== 'string' || !(INTEGRITY_GRADES as readonly string[]).includes(grade)) {
    return `${entry.id}: integrity_grade must be one of ${INTEGRITY_GRADES.join(', ')}; got ${JSON.stringify(grade)}`
  }
  const reason = payload['degraded_reason']
  const hasReason = reason !== undefined && reason !== null
  if (!degraded) {
    if (hasReason) return `${entry.id}: degraded_reason must be absent when degraded is false; got ${JSON.stringify(reason)}`
    if (grade !== 'A') return `${entry.id}: integrity_grade must be A when degraded is false; got ${grade}`
    return null
  }
  if (!hasReason) return `${entry.id}: degraded_reason is required when degraded is true`
  if (typeof reason !== 'string' || reason === '') {
    return `${entry.id}: degraded_reason must be a non-empty string; got ${JSON.stringify(reason)}`
  }
  const codes = reason.split(',')
  for (const c of codes) {
    if (!Object.prototype.hasOwnProperty.call(DEGRADED_REASON_CODES, c)) {
      return `${entry.id}: degraded_reason code ${JSON.stringify(c)} is not a known code (${Object.keys(DEGRADED_REASON_CODES).join(', ')})`
    }
  }
  const canonical = [...new Set(codes)].sort().join(',')
  if (canonical !== reason) {
    return `${entry.id}: degraded_reason codes must be sorted and must not repeat; expected ${JSON.stringify(canonical)}`
  }
  const worst = codes.map((c) => DEGRADED_REASON_CODES[c]!).sort().at(-1)!
  if (grade !== worst) {
    return `${entry.id}: integrity_grade must be ${worst} (the worst grade of ${reason}); got ${grade}`
  }
  return null
}
