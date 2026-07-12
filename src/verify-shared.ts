/**
 * @synoi/verify — browser-safe shared verification surface.
 *
 * This module is the portable core of @synoi/verify: everything that verifies
 * WITHOUT a static `node:crypto` import, so it can be imported into a browser,
 * Chrome-extension, or service-worker bundle. It carries:
 *
 *   - the pure canonicalization contract (jcsCanonicalize, canonicalPayload)
 *   - the v1 CANONICAL_FIELDS schema + result types (canonicalization only; the
 *     v1 SIGNATURE verifier lives in the Node-only ./verify entry because it
 *     needs node:crypto)
 *   - the gap-selfsign verifier (verifyGapSelfSignedReceipt) — browser-safe,
 *     it dynamic-imports @synoi/gap, which is @noble-only (zero node: bindings)
 *   - the scheme dispatcher as a FACTORY (createVerifyReceiptByScheme). The two
 *     node-bound branches (v1 legacy Ed25519 via node:crypto, and v2 hybrid
 *     DSSE via @synoi/sraid, whose main entry statically imports node:crypto)
 *     are INJECTED. The Node ./verify entry injects both so nothing regresses;
 *     the ./browser entry injects neither, so those two schemes fail closed.
 *
 * WHY THE SPLIT: @synoi/sraid's main entry (used by the v2 path) and Node's
 * `node:crypto` (used by the v1 path) both hard-require a Node runtime. Any
 * module the browser entry transitively imports must therefore avoid BOTH. The
 * v2 verifier's `await import('@synoi/sraid')` body deliberately stays in the
 * Node-only ./verify file — a dynamic-import edge is a code-split boundary that
 * bundlers preserve even across a tree-shaken function, so parking it here would
 * drag sraid's node:crypto into the browser build. The gap-selfsign verifier is
 * safe to keep here because @synoi/gap is genuinely browser-safe.
 *
 * CANONICALIZATION — ONE CANONICAL TRUTH (RFC 8785 JCS):
 * The v1 canonical payload is produced by the SAME RFC 8785 (JCS) serializer
 * the signer (@synoi/sraid `canonicalize`) uses, over the sorted scalar
 * projection of the receipt. `jcsCanonicalize` below is a byte-for-byte port
 * of @synoi/sraid/src/canonicalize.ts; the cross-package golden vectors in
 * synoi-conformance (`cof/verify.canonical.v1.vectors.json`) PROVE the two
 * emit identical bytes, and `selftest` re-checks them at runtime. It is a port
 * (not an import) only because @synoi/sraid is ESM-only and the v1 path is a
 * synchronous CommonJS API; the v2 path dynamic-imports @synoi/sraid directly.
 *
 * The signer (gateway verify-router.ts:canonicalPayload) signs a FLAT scalar
 * projection via `JSON.stringify`. On scalar values V8's JSON.stringify and
 * RFC 8785 JCS are byte-identical (JCS was specified to match ECMAScript string
 * escaping and Number.toString), so JCS reproduces the signed bytes exactly.
 * To keep that equivalence load-bearing, `canonicalPayload` REJECTS any
 * canonical field whose value is a nested object or array: the signer never
 * signs a non-scalar canonical field (e.g. policy_versions is signed as a JSON
 * string), and JCS-sorting a nested object's keys would silently diverge from
 * the signer's insertion-order JSON.stringify. Rejecting is fail-closed.
 */

/**
 * RFC 8785 (JCS) canonicalizer — a byte-for-byte port of
 * @synoi/sraid/src/canonicalize.ts. This is the single canonicalization
 * contract; any divergence from the sraid signer is a signature-confusion
 * hazard, so the port is deliberate and pinned by cross-package golden vectors.
 *
 * Reject-loud: throws a TypeError for any non-JSON value (NaN/Infinity,
 * undefined/function/symbol/bigint, objects with a toJSON()), matching sraid.
 */
export function jcsCanonicalize(value: unknown): string {
  const t = typeof value

  if (t === 'number') {
    if (!isFinite(value as number)) {
      throw new TypeError(
        `jcsCanonicalize: RFC 8785 forbids non-finite numbers; received ${String(value)}`,
      )
    }
    // ADR_019 decision 2: FORBID non-integer numbers everywhere. A number is
    // legal iff it is a finite integer. This is a byte-for-byte port of
    // @synoi/sraid canonicalize so the ONE canonical truth holds: a float that
    // sraid rejects before hashing must be rejected here too, else the local
    // canonicalizer would diverge and reintroduce the exact signature-confusion
    // hazard this repo already fixed once. Represent fractional quantities as
    // integer minor units (money) or integer millis (timestamps) before signing.
    //
    // -0: with floats forbidden, -0 can only arise as an explicit input;
    // Number.isInteger(-0) is true and JSON.stringify(-0) === '0', so no special
    // case is needed. This matches sraid, which deleted its former -0 branch.
    if (!Number.isInteger(value as number)) {
      throw new TypeError(
        `jcsCanonicalize: non-integer numbers are forbidden (ADR_019); received ${String(value)}. ` +
          'Represent fractional quantities as integer minor units (e.g. cents) before canonicalizing.',
      )
    }
    return JSON.stringify(value)
  }

  if (value === null) return 'null'
  if (t === 'string' || t === 'boolean') return JSON.stringify(value as string | boolean)

  if (t === 'undefined' || t === 'function' || t === 'symbol' || t === 'bigint') {
    throw new TypeError(
      `jcsCanonicalize: value of type "${t}" is not a JSON value and cannot be canonicalized`,
    )
  }

  if (Array.isArray(value)) {
    const parts: string[] = []
    for (let i = 0; i < value.length; i++) {
      if (!(i in value)) {
        throw new TypeError(
          `jcsCanonicalize: sparse array hole at index ${i} is not a JSON value`,
        )
      }
      parts.push(jcsCanonicalize(value[i]))
    }
    return '[' + parts.join(',') + ']'
  }

  if (typeof (value as { toJSON?: unknown }).toJSON === 'function') {
    throw new TypeError(
      'jcsCanonicalize: objects with a toJSON() method (e.g. Date) are not accepted; ' +
        'serialize them to a JSON value (e.g. an ISO string) before canonicalizing',
    )
  }

  const obj = value as Record<string, unknown>
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort()
  return (
    '{' +
    keys.map((k) => JSON.stringify(k) + ':' + jcsCanonicalize(obj[k])).join(',') +
    '}'
  )
}

/**
 * Required canonical fields, sorted alphabetically. Every receipt must
 * include these for the signature to be reproducible.
 */
export const CANONICAL_FIELDS = [
  'action_class',
  'decision',
  'oid_hex',
  'receipt_id',
  'recorded_at',
  'risk_level',
  'tenant_id',
] as const

/**
 * Optional canonical fields added after the original scheme. Receipts MAY
 * include these; if they do, they participate in the signature; if they
 * don't, the canonical form omits them. This preserves backward-compat with
 * receipts signed before the field was introduced.
 *
 * `gateway_manifest_sha256` was added 2026-05-19 (Sprint 1.2 of the
 * RE-protection design) to cryptographically bind a receipt to the manifest
 * hash of the gateway code that signed it.
 */
export const OPTIONAL_CANONICAL_FIELDS = [
  'gateway_manifest_sha256',
] as const

export interface ReceiptPayload {
  receipt_id:   string
  tenant_id:    string
  decision:     string
  action_class: string
  risk_level:   string
  oid_hex:      string
  recorded_at:  number
}

export interface VerifyResult {
  valid:             boolean
  canonical_payload: string
  algorithm:         'Ed25519'
  reason?:           string
}

/**
 * Build the canonical JSON payload from a receipt body. The receipt may carry
 * extra fields (intent_id, action_type, latency_ms, etc.) — only the canonical
 * fields contribute to the signature.
 *
 * Throws if any REQUIRED canonical field is missing. Optional canonical fields
 * (like gateway_manifest_sha256, introduced 2026-05-19) are included if
 * present and omitted otherwise — this preserves verification of receipts
 * signed before the optional fields existed.
 */
export function canonicalPayload(payload: Record<string, unknown>): string {
  const obj: Record<string, unknown> = {}
  const allKeys = [...CANONICAL_FIELDS, ...OPTIONAL_CANONICAL_FIELDS].sort()
  for (const key of allKeys) {
    const isRequired = (CANONICAL_FIELDS as readonly string[]).includes(key)
    const val = payload[key]
    // The gateway signer omits a canonical field that is absent OR explicitly
    // null (verify-router.ts:canonicalPayload). Mirror that exactly so a
    // receipt signed with a null authority field verifies whether the store
    // returns the field as null or absent.
    if (val === undefined || val === null) {
      if (isRequired && val === undefined) {
        throw new Error(`canonicalPayload: missing required field '${key}'`)
      }
      continue  // optional-absent, or any explicit-null → omitted (matches signer)
    }
    // Fail-closed: the signer only ever signs SCALAR canonical fields (strings,
    // numbers, booleans). It serializes the flat projection with JSON.stringify,
    // which preserves a nested object's INSERTION order; JCS below would SORT a
    // nested object's keys, diverging from the signed bytes. A non-scalar
    // canonical field therefore cannot be reproduced and MUST be rejected rather
    // than silently verified against wrong bytes.
    if (typeof val === 'object') {
      throw new Error(
        `canonicalPayload: canonical field '${key}' must be a scalar (string/number/boolean); ` +
          `got ${Array.isArray(val) ? 'array' : 'object'}. The signer never signs a non-scalar ` +
          `canonical field, so this receipt cannot be canonically reproduced.`,
      )
    }
    obj[key] = val
  }
  // ONE canonical truth: RFC 8785 JCS, byte-identical to the @synoi/sraid
  // signer. On the scalar projection above, JCS == the signer's JSON.stringify
  // (proven by synoi-conformance cof/verify.canonical.v1.vectors.json).
  return jcsCanonicalize(obj)
}

// ─────────────────────────────────────────────────────────────────────────────
// S2.3 — 2-receipt denial-then-execution chain render contract.
//
// When E1 carries `body.replayed_after`, the verifier MUST surface the D1 -> E1
// chain so the operator can confirm: "denied at T0, HITL approved at T1,
// executed at T2." This function is the render hook for that chain.
//
// NON-CLAIM discipline: the render output uses "denial-then-execution chain"
// language, NOT "Replay Approval". ADR_007 governs if/when external framing
// changes. See Section 17 of STEVE_DEMO_FALSIFICATION v2 doc for rationale.
// ─────────────────────────────────────────────────────────────────────────────

export interface ReplayChainLink {
  /** The denial receipt D1 (status=denied, no replayed_after). */
  denial:    Record<string, unknown>
  /** The execution receipt E1 (status=ok, body.replayed_after=D1.oid). */
  execution: Record<string, unknown>
  /** True when E1.prev === D1.oid (Merkle parent edge is present and correct). */
  merkle_edge_valid: boolean
  /** True when E1.body.replayed_after === D1.oid. */
  replayed_after_valid: boolean
  /**
   * HITL signal OID extracted from E1.body.detail when present.
   * Format: `hitl_approval_signal_oid=<oid>` in the detail string.
   */
  hitl_signal_oid?: string
}

/**
 * Render the D1 -> E1 2-receipt chain for display.
 *
 * Validates structural integrity of the chain:
 *   - E1.body.replayed_after must equal D1.oid
 *   - E1.prev must equal D1.oid (Merkle parent edge)
 *   - D1.body.status must be 'denied'
 *   - E1.body.status must be 'ok'
 *
 * Returns null with a reason string if E1 does not carry a replayed_after.
 * Never throws.
 *
 * Callers should call this in their receipt render path when the receipt
 * carries `body.replayed_after`. The render result is informational: it does
 * not re-verify cryptographic signatures (use verifyReceiptSignature / v2 for
 * that). Structural validation here ensures the chain references are consistent
 * before surfacing them to the operator.
 */
export function renderReplayChain(
  e1: Record<string, unknown>,
  d1: Record<string, unknown>,
): { ok: true; chain: ReplayChainLink } | { ok: false; reason: string } {
  // Extract body fields safely.
  const e1Body = (e1['body'] ?? {}) as Record<string, unknown>
  const d1Body = (d1['body'] ?? {}) as Record<string, unknown>

  const replayedAfter = e1Body['replayed_after']
  if (replayedAfter === undefined || replayedAfter === null) {
    return { ok: false, reason: 'E1 does not carry replayed_after -- not a 2-receipt chain' }
  }

  const d1Oid = d1['oid'] as string | undefined
  if (typeof d1Oid !== 'string' || d1Oid === '') {
    return { ok: false, reason: 'D1 has no oid field' }
  }

  const e1Prev = e1['prev'] as string | undefined
  const merkle_edge_valid    = e1Prev === d1Oid
  const replayed_after_valid = replayedAfter === d1Oid

  // Extract HITL signal OID from detail string when present.
  let hitl_signal_oid: string | undefined
  const detail = typeof e1Body['detail'] === 'string' ? e1Body['detail'] : ''
  const m = /hitl_approval_signal_oid=(\S+)/.exec(detail)
  if (m !== null && m[1] !== undefined) hitl_signal_oid = m[1]

  const chain: ReplayChainLink = {
    denial:    d1,
    execution: e1,
    merkle_edge_valid,
    replayed_after_valid,
    ...(hitl_signal_oid !== undefined ? { hitl_signal_oid } : {}),
  }

  return { ok: true, chain }
}

// ─────────────────────────────────────────────────────────────────────────────
// Receipt v2 — hybrid DSSE scheme constants + result/input TYPES.
//
// The v2 VERIFIER (verifyReceiptV2) lives in the Node-only ./verify entry
// because it dynamic-imports @synoi/sraid, whose main entry statically imports
// node:crypto (Ed25519 verify is node-only, and cdroContentCore hashes via
// node:crypto). Only the scheme string, payloadType, and the result/input
// shapes are portable, so only those live here.
// ─────────────────────────────────────────────────────────────────────────────

/** receipt_scheme discriminator that selects the v2 hybrid DSSE path. */
export const RECEIPT_SCHEME_V2 = 'synoi.receipt/v2'

/**
 * The DSSE payloadType for a SynOI SRAID object. Bound into the PAE, so a
 * signature minted for a different payloadType will not verify. Matches
 * AttestationEnvelope.payloadType in @synoi/sraid types.ts.
 */
export const V2_PAYLOAD_TYPE = 'application/vnd.synoi.gap+json' // migrated per ADR_007 payloadType split

export interface VerifyResultV2 {
  valid:              boolean
  /**
   * Failure reasons. Empty when valid. Includes the @synoi/sraid
   * verifyAttestation reasons ('missing-ed25519', 'missing-ml-dsa-65',
   * 'ed25519-invalid', 'ml-dsa-invalid', 'payload-type-mismatch',
   * 'envelope-malformed', …) plus this package's binding checks
   * ('missing-attestation', 'payload-core-mismatch').
   */
  reasons:            string[]
  algorithm:          'DSSE(ed25519+ml-dsa-65)'
  payload_type?:      string
  /** The canonical content-core string that was verified (when computable). */
  canonical_payload?: string
}

export interface VerifyReceiptV2Input {
  /** The full v2 receipt object, carrying a DSSE `attestation` field. */
  receipt:     Record<string, unknown>
  /**
   * RAW 32-byte Ed25519 public key. NOTE: v2 uses raw key bytes, NOT the PEM
   * string the v1 path (`verifyReceiptSignature`) takes. The two schemes have
   * different key shapes by design (raw is the @synoi/sraid verify surface).
   */
  ed25519_pub: Uint8Array
  /** RAW 1952-byte ML-DSA-65 public key. */
  ml_dsa_pub:  Uint8Array
}

// ─────────────────────────────────────────────────────────────────────────────
// Receipt gap-selfsign — @synoi/gap `receipt()` single-Ed25519 self-sign tier
// (ADR_014 Section 10.1, the public lite-daemon carve-out).
//
// This is a THIRD receipt tier, distinct from v1 legacy (flat CANONICAL_FIELDS
// schema, an older pre-GAP scheme) and v2 hybrid DSSE (KMS/managed-custody,
// Ed25519+ML-DSA-65 both required). The lite self-host daemon has neither a
// legacy-flat-schema producer nor managed key custody: it self-signs a GAP CDRO
// envelope with a single, operator-owned, locally-persisted Ed25519 key via
// @synoi/gap's `receipt()`. This verifier is the OSS counterpart: it delegates
// to @synoi/gap's OWN `verifyReceiptSignature` (same EXCLUDED_FIELDS set, same
// canonicalize call) rather than re-implementing the exclusion set here — a
// second hand-copied projection would silently drift from the signer on the
// next spec tweak, which is exactly the signature-confusion hazard the v1/v2
// canonicalization comments above warn about for every other tier.
//
// @synoi/gap is ESM-only ("type":"module") but browser-safe (@noble-only, zero
// node: bindings); @synoi/verify's Node entry is CommonJS. Dynamic import keeps
// this function async and lets it run unchanged in BOTH a CommonJS Node build
// (require(ESM) interop on Node >= 22) and a browser bundle (native import()).
// ─────────────────────────────────────────────────────────────────────────────

/** receipt_scheme discriminator that selects the gap-selfsign verifier. */
export const RECEIPT_SCHEME_GAP_SELFSIGN = 'synoi.receipt/gap-selfsign'

export interface VerifyResultGapSelfSign {
  valid:     boolean
  reason?:   string
  algorithm: 'Ed25519(gap-selfsign)'
}

export interface VerifyGapSelfSignedInput {
  /** The full receipt envelope, as produced by @synoi/gap `receipt()`. */
  receipt:     Record<string, unknown>
  /** RAW 32-byte Ed25519 public key (the operator's own, self-hosted key). */
  ed25519_pub: Uint8Array
}

/**
 * Verify a receipt minted by @synoi/gap's `receipt()` self-sign one-liner.
 * Delegates the actual signature check to @synoi/gap so there is exactly one
 * implementation of the gap-selfsign exclusion-set + canonicalize scheme (in
 * @synoi/gap itself); this function is a thin async adapter, not a second
 * copy. Never throws. Browser-safe: @synoi/gap has no node: bindings.
 */
export async function verifyGapSelfSignedReceipt(
  input: VerifyGapSelfSignedInput,
): Promise<VerifyResultGapSelfSign> {
  const algorithm = 'Ed25519(gap-selfsign)' as const
  try {
    // ESM-only but browser-safe package: dynamic import keeps this usable from
    // both the CommonJS Node build and a browser/service-worker bundle.
    const gap = await import('@synoi/gap')
    const valid = gap.verifyReceiptSignature(
      input.receipt as unknown as Parameters<typeof gap.verifyReceiptSignature>[0],
      input.ed25519_pub,
    )
    return valid
      ? { valid: true, algorithm }
      : { valid: false, algorithm, reason: 'signature does not match canonical payload under this public key' }
  } catch (err) {
    return { valid: false, algorithm, reason: (err as Error).message }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// createVerifyReceiptByScheme — the ONE fail-closed dispatcher (ADR_019 STEP 5),
// as a FACTORY so the two node-bound branches are injected.
//
// A receipt carries a `receipt_scheme` discriminator. The dispatcher reads it
// and routes to exactly ONE verifier. It is the single entry point a consumer
// should call so that scheme selection is not re-implemented (and
// mis-implemented) per call site. The routing is FAIL-CLOSED by LOCKED founder
// decision (K2 now):
//
//   receipt_scheme === 'synoi.receipt/v2'            -> injected v2Verifier (hybrid DSSE)
//   receipt_scheme === 'synoi.receipt/gap-selfsign'   -> verifyGapSelfSignedReceipt (lite self-sign)
//   receipt_scheme absent                             -> legacy v1 ONLY IF allowLegacyV1===true
//                                                        AND an injected legacyVerifier exists;
//                                                        otherwise FAIL-CLOSED (rejected)
//   receipt_scheme any other value                    -> FAIL-CLOSED (rejected)
//
// The v2 and v1 verifiers are INJECTED because both are node-bound (v2 via
// @synoi/sraid, v1 via node:crypto). The Node ./verify entry injects both, so
// its dispatcher behaves exactly as before. The ./browser entry injects
// NEITHER: a v2 or legacy-v1 receipt then fails closed with an honest
// build-capability reason rather than silently pulling node:crypto into the
// browser graph. gap-selfsign is browser-safe and always available.
//
// allowLegacyV1 DEFAULTS TO FALSE. A missing scheme is NOT silently trusted as
// v1: an attacker who strips the discriminator to force the weaker Ed25519-only
// path must be rejected unless the operator has EXPLICITLY opted into legacy
// acceptance. This closes the "unknown/missing scheme falls through to the
// weaker verifier" hazard.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The v1 legacy key material + signature, supplied only when the caller opts
 * into legacy verification (allowLegacyV1: true) AND the receipt carries no
 * receipt_scheme. The v1 path is Ed25519-only over the flat canonical-field
 * projection (verifyReceiptSignature).
 */
export interface LegacyV1VerifyInput {
  /** Hex-encoded 64-byte Ed25519 signature over the v1 canonical payload. */
  signatureHex: string
  /** PEM/SPKI-encoded Ed25519 public key. */
  publicKeyPem: string
}

export interface VerifyBySchemeInput {
  /** The full receipt object. Its `receipt_scheme` field selects the verifier. */
  receipt: Record<string, unknown>
  /** RAW 32-byte Ed25519 public key for the v2 hybrid path. */
  ed25519_pub?: Uint8Array
  /** RAW 1952-byte ML-DSA-65 public key for the v2 hybrid path. */
  ml_dsa_pub?: Uint8Array
  /**
   * RAW 32-byte Ed25519 public key for the gap-selfsign lite path. Distinct
   * from `ed25519_pub` above (which is v2-hybrid-scoped) so a caller cannot
   * accidentally satisfy the gap-selfsign branch with a key meant for v2, or
   * vice versa; each tier states its own key requirement explicitly.
   */
  gap_ed25519_pub?: Uint8Array
  /**
   * Opt-in to the legacy v1 Ed25519-only path for a scheme-less receipt.
   * DEFAULTS TO FALSE (LOCKED fail-closed decision, K2 enforcement now). When
   * false, a receipt without a receipt_scheme is REJECTED, not verified as v1.
   */
  allowLegacyV1?: boolean
  /** v1 key material + signature; required only when the v1 path is taken. */
  legacy?: LegacyV1VerifyInput
}

export interface VerifyBySchemeResult {
  valid: boolean
  /** Which verifier the dispatcher selected, or 'rejected' when it fails closed. */
  scheme: 'v2' | 'gap-selfsign' | 'v1' | 'rejected'
  /** Failure reasons (empty when valid). */
  reasons: string[]
  /** The underlying verifier result when one ran; absent on fail-closed. */
  detail?: VerifyResultV2 | VerifyResultGapSelfSign | VerifyResult
}

/** The node-bound verifiers a build injects into the dispatcher factory. */
export interface VerifyBySchemeDeps {
  /**
   * The v1 legacy Ed25519 verifier (node:crypto). Injected by the Node entry;
   * omitted by the browser entry, in which case a legacy-v1 receipt fails closed.
   */
  legacyVerifier?: (
    payload: Record<string, unknown>,
    signatureHex: string,
    publicKeyPem: string,
  ) => VerifyResult
  /**
   * The v2 hybrid DSSE verifier (@synoi/sraid, node:crypto). Injected by the
   * Node entry; omitted by the browser entry, in which case a v2 receipt fails
   * closed. Kept out of this browser-safe module so its `await
   * import('@synoi/sraid')` edge never enters a browser bundle graph.
   */
  v2Verifier?: (input: VerifyReceiptV2Input) => Promise<VerifyResultV2>
}

/**
 * Build a `verifyReceiptByScheme` bound to a specific set of node-bound
 * verifiers. See the block comment above for the full routing table. The
 * returned function never throws; it returns `scheme: 'rejected'` with a reason
 * whenever the dispatcher fails closed (unknown scheme, missing scheme with
 * allowLegacyV1 not enabled, or a scheme whose verifier this build did not
 * inject).
 */
export function createVerifyReceiptByScheme(
  deps: VerifyBySchemeDeps,
): (input: VerifyBySchemeInput) => Promise<VerifyBySchemeResult> {
  return async function verifyReceiptByScheme(
    input: VerifyBySchemeInput,
  ): Promise<VerifyBySchemeResult> {
    const scheme = input.receipt['receipt_scheme']

    // ── v2 hybrid DSSE path ──────────────────────────────────────────────────
    if (scheme === RECEIPT_SCHEME_V2) {
      if (deps.v2Verifier === undefined) {
        // Browser build: the v2 verifier is node-bound (@synoi/sraid) and was
        // not injected. Fail closed rather than pull node:crypto into the graph.
        return {
          valid:   false,
          scheme:  'rejected',
          reasons: ['v2-not-supported-in-browser-build'],
        }
      }
      if (input.ed25519_pub === undefined || input.ml_dsa_pub === undefined) {
        return {
          valid:   false,
          scheme:  'rejected',
          reasons: ['v2-scheme-requires-both-public-keys'],
        }
      }
      const res = await deps.v2Verifier({
        receipt:     input.receipt,
        ed25519_pub: input.ed25519_pub,
        ml_dsa_pub:  input.ml_dsa_pub,
      })
      return { valid: res.valid, scheme: 'v2', reasons: res.reasons, detail: res }
    }

    // ── gap-selfsign lite path (ADR_014 Section 10.1) ────────────────────────
    if (scheme === RECEIPT_SCHEME_GAP_SELFSIGN) {
      if (input.gap_ed25519_pub === undefined) {
        return {
          valid:   false,
          scheme:  'rejected',
          reasons: ['gap-selfsign-scheme-requires-ed25519-public-key'],
        }
      }
      const res = await verifyGapSelfSignedReceipt({
        receipt:     input.receipt,
        ed25519_pub: input.gap_ed25519_pub,
      })
      return {
        valid:   res.valid,
        scheme:  'gap-selfsign',
        reasons: res.valid ? [] : [res.reason ?? 'gap-selfsign-signature-invalid'],
        detail:  res,
      }
    }

    // ── missing scheme ───────────────────────────────────────────────────────
    // FAIL-CLOSED unless the operator EXPLICITLY opted into legacy v1 acceptance.
    if (scheme === undefined || scheme === null) {
      if (input.allowLegacyV1 !== true) {
        return {
          valid:   false,
          scheme:  'rejected',
          reasons: ['missing-receipt-scheme-and-legacy-v1-not-allowed'],
        }
      }
      if (deps.legacyVerifier === undefined) {
        // Browser build: the v1 verifier is node-bound (node:crypto) and was
        // not injected. Even with allowLegacyV1, there is no verifier to run.
        return {
          valid:   false,
          scheme:  'rejected',
          reasons: ['legacy-v1-not-available-in-this-build'],
        }
      }
      if (input.legacy === undefined) {
        return {
          valid:   false,
          scheme:  'rejected',
          reasons: ['legacy-v1-allowed-but-no-v1-key-material-supplied'],
        }
      }
      const res = deps.legacyVerifier(
        input.receipt,
        input.legacy.signatureHex,
        input.legacy.publicKeyPem,
      )
      return {
        valid:   res.valid,
        scheme:  'v1',
        reasons: res.valid ? [] : [res.reason ?? 'v1-signature-invalid'],
        detail:  res,
      }
    }

    // ── any other value ──────────────────────────────────────────────────────
    // Unknown scheme is ALWAYS fail-closed: a verifier that cannot reason about a
    // scheme must reject it, never guess.
    return {
      valid:   false,
      scheme:  'rejected',
      reasons: [`unknown-receipt-scheme:${String(scheme)}`],
    }
  }
}
