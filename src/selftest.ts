/**
 * selftest.ts — offline self-verification for third parties.
 *
 * Loads the shipped golden vectors (vectors/receipt.v1.canonical.vectors.json)
 * and confirms, with no network access, that this build of @synoi/verify:
 *   1. reproduces each vector's `expected_canonical` byte-for-byte
 *      (canonicalization parity with the signer / RFC 8785 JCS), and
 *   2. reproduces each vector's `expected_valid` verdict for its pinned
 *      signature + public key (Ed25519 signature parity).
 *
 * A third party runs `synoi-verify selftest` to gain confidence that the
 * verifier they installed agrees byte-for-byte with the SynOI signer before
 * they trust it to verify real receipts. The same vectors are mirrored into
 * synoi-conformance so a reimplementation in ANY language can confirm
 * byte-for-byte agreement.
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { canonicalPayload, verifyReceiptSignature } from './verify'

export interface SelfTestVector {
  name:               string
  description:        string
  receipt:            Record<string, unknown>
  expected_canonical: string
  signature_hex:      string
  public_key_pem:     string
  expected_valid:     boolean
  algorithm:          string
}

export interface SelfTestVectorSet {
  vector_set:                string
  spec:                      string
  note:                      string
  canonical_fields:          string[]
  optional_canonical_fields: string[]
  vectors:                   SelfTestVector[]
}

export interface SelfTestCaseResult {
  name:            string
  canonical_ok:    boolean
  verdict_ok:      boolean
  ok:              boolean
  detail?:         string
}

export interface SelfTestResult {
  ok:      boolean
  total:   number
  passed:  number
  failed:  number
  cases:   SelfTestCaseResult[]
}

/**
 * Locate the shipped vectors file. Ships in the package `vectors/` dir, which
 * sits next to `dist/` (dist/selftest.js -> ../vectors) and next to `src/`
 * when run from source (src/selftest.ts -> ../vectors).
 */
export function defaultVectorsPath(): string {
  return join(__dirname, '..', 'vectors', 'receipt.v1.canonical.vectors.json')
}

/** Load and parse a vector set from disk. */
export function loadVectors(path: string = defaultVectorsPath()): SelfTestVectorSet {
  const raw = readFileSync(path, 'utf8')
  return JSON.parse(raw) as SelfTestVectorSet
}

/**
 * Run the self-test over a loaded (or default) vector set. Pure over the input
 * set; performs no network or extra filesystem access beyond the initial load.
 */
export function runSelfTest(set: SelfTestVectorSet): SelfTestResult {
  const cases: SelfTestCaseResult[] = []

  for (const v of set.vectors) {
    let canonical_ok = false
    let canonicalDetail: string | undefined

    // (1) Canonicalization parity: our canonicalPayload MUST reproduce the
    //     pinned expected_canonical bytes exactly.
    try {
      const got = canonicalPayload(v.receipt)
      canonical_ok = got === v.expected_canonical
      if (!canonical_ok) {
        canonicalDetail =
          `canonical mismatch:\n    expected ${JSON.stringify(v.expected_canonical)}\n    got      ${JSON.stringify(got)}`
      }
    } catch (err) {
      canonicalDetail = 'canonicalPayload threw: ' + (err as Error).message
    }

    // (2) Signature-verdict parity: verify against the pinned key + signature
    //     and confirm the verdict equals expected_valid.
    const res = verifyReceiptSignature(v.receipt, v.signature_hex, v.public_key_pem)
    const verdict_ok = res.valid === v.expected_valid
    const verdictDetail = verdict_ok
      ? undefined
      : `verdict mismatch: expected valid=${v.expected_valid}, got valid=${res.valid} (${res.reason ?? 'no reason'})`

    const ok = canonical_ok && verdict_ok
    const detail = [canonicalDetail, verdictDetail].filter(Boolean).join('; ') || undefined
    cases.push({ name: v.name, canonical_ok, verdict_ok, ok, detail })
  }

  const passed = cases.filter((c) => c.ok).length
  const failed = cases.length - passed
  return { ok: failed === 0, total: cases.length, passed, failed, cases }
}

/** Convenience: load default vectors and run. */
export function selfTest(path?: string): SelfTestResult {
  return runSelfTest(loadVectors(path))
}
