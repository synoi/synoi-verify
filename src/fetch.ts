/**
 * Network helper — fetches a receipt + the gateway's public keys, then
 * verifies. Kept separate from verify.ts so the pure verifier has zero
 * I/O dependencies (importable in environments without `fetch`).
 *
 * HYBRID, BOTH SIGNATURES REQUIRED (aligned to the bundle path, bundle.ts /
 * @synoi/verify-core, which has always required both ed25519_valid AND
 * ml_dsa_valid). Every receipt produced by the current gateway signer
 * (signReceiptPayloadHybrid, verify-router.ts) carries both a `signature`
 * (Ed25519 hex) and an `ml_dsa_signature` (ML-DSA-65 base64) field; a receipt
 * missing either is rejected here, fail-closed, same posture as bundle mode.
 *
 * KEY SHAPE: GET /verify/pubkey returns the NESTED hybrid shape
 * `{ key_id, ed25519: { public_key }, ml_dsa: { public_key } }` — there is no
 * top-level `public_key` field. See verify-router.ts's `/pubkey` route.
 *
 * SIGNED BYTES: rather than reconstructing canonicalPayload(receipt) locally
 * (a second, independently-maintained field allowlist that can drift from the
 * gateway's — see verify-router.ts CANONICAL_FIELDS, which has grown well
 * past this package's CANONICAL_FIELDS over several sprints), this path
 * fetches the exact signed bytes from GET /verify/:id/raw, the endpoint the
 * gateway publishes for exactly this purpose ("Enables independent
 * verification with any Ed25519 library"). One canonicalizer (the gateway's,
 * published verbatim), not two.
 */

import { createHash, createPublicKey } from 'node:crypto'
import { verifyEd25519Raw, verifyMlDsaRaw, type VerifyResult } from './verify'

export interface FetchAndVerifyResult extends Omit<VerifyResult, 'algorithm'> {
  /** 'Ed25519 + ML-DSA-65 (hybrid)' — both signatures are required (see file header). */
  algorithm:             string
  receipt_id:            string
  gateway:               string
  receipt:               Record<string, unknown>
  signer_key_id:         string | null
  /** True iff the Ed25519 signature verified against the fetched Ed25519 public key. */
  ed25519_valid:          boolean
  /** True iff the ML-DSA-65 signature verified against the fetched ML-DSA public key. */
  ml_dsa_valid:           boolean
  /**
   * 'sha256:' + sha256(SPKI DER) of the Ed25519 public key this receipt was
   * checked against, when that key could be parsed. Informational only, not
   * load-bearing for the verdict: this path fetches the key from the SAME
   * origin as the receipt, so a valid signature proves internal consistency,
   * NOT that the key belongs to a legitimate SynOI gateway. That trust must be
   * anchored out of band (see the CLI's VERIFIED caveat).
   */
  signer_key_fingerprint: string | undefined
}

interface PubkeyDoc {
  key_id?:  string
  ed25519?: { public_key?: string }
  ml_dsa?:  { public_key?: string }
}

/**
 * Best-effort 'sha256:' + sha256(SPKI DER) fingerprint of an Ed25519 PEM
 * public key. Returns undefined rather than throwing if the PEM is malformed;
 * the fingerprint is informational, never load-bearing for the verify verdict.
 */
function ed25519KeyFingerprint(pem: string): string | undefined {
  try {
    const der = createPublicKey({ key: pem, format: 'pem' }).export({ format: 'der', type: 'spki' }) as Buffer
    return 'sha256:' + createHash('sha256').update(der).digest('hex')
  } catch {
    return undefined
  }
}

/**
 * Fetch `<gateway>/verify/<id>`, `<gateway>/verify/<id>/raw`, and
 * `<gateway>/verify/pubkey`, then hybrid-verify the receipt: BOTH the
 * Ed25519 AND the ML-DSA-65 signature must check out against the exact
 * signed bytes. The three endpoints are documented in the gateway's
 * verify-router.ts.
 *
 * @param receiptId  receipt id (e.g. "rcpt_abc_123")
 * @param gateway    base URL — defaults to https://gateway.synoi.systems
 */
export async function fetchAndVerify(
  receiptId: string,
  gateway:   string = 'https://gateway.synoi.systems',
): Promise<FetchAndVerifyResult> {
  const base = gateway.replace(/\/$/, '')

  // 1. fetch the receipt
  const receiptRes = await fetch(`${base}/verify/${encodeURIComponent(receiptId)}`, {
    headers: { Accept: 'application/json' },
  })
  if (!receiptRes.ok) {
    return makeFailure(receiptId, gateway, `GET /verify/${receiptId} → HTTP ${receiptRes.status}`)
  }
  const receiptDoc = (await receiptRes.json()) as Record<string, unknown>

  // The gateway wraps the receipt in { verified, receipt_id, receipt: {...} }.
  // Accept both wrapped and flat shapes for robustness.
  const receipt = (receiptDoc.receipt && typeof receiptDoc.receipt === 'object'
    ? receiptDoc.receipt as Record<string, unknown>
    : receiptDoc) as Record<string, unknown>

  const ed25519SignatureRaw = receipt.signature
  if (typeof ed25519SignatureRaw !== 'string' || ed25519SignatureRaw.length === 0) {
    return makeFailure(receiptId, gateway, 'receipt has no signature field (or empty)', receipt)
  }
  // Hybrid required — same fail-closed posture as bundle mode
  // (verifyEvidenceBundle always requires ed25519_valid AND ml_dsa_valid).
  const mlDsaSignatureRaw = receipt.ml_dsa_signature
  if (typeof mlDsaSignatureRaw !== 'string' || mlDsaSignatureRaw.length === 0) {
    return makeFailure(receiptId, gateway, 'receipt has no ml_dsa_signature field (or empty) — hybrid verification requires both Ed25519 and ML-DSA-65', receipt)
  }

  // 2. fetch the exact signed bytes — the gateway's own published canonical
  // form, not a locally-reconstructed projection (see file header).
  const rawRes = await fetch(`${base}/verify/${encodeURIComponent(receiptId)}/raw`, {
    headers: { Accept: 'text/plain' },
  })
  if (!rawRes.ok) {
    return makeFailure(receiptId, gateway, `GET /verify/${receiptId}/raw → HTTP ${rawRes.status}`, receipt)
  }
  const canonical = await rawRes.text()
  if (canonical.length === 0) {
    return makeFailure(receiptId, gateway, '/verify/:id/raw returned empty canonical payload', receipt)
  }

  // 3. fetch the public keys (nested hybrid shape)
  const keyRes = await fetch(`${base}/verify/pubkey`, {
    headers: { Accept: 'application/json' },
  })
  if (!keyRes.ok) {
    return makeFailure(receiptId, gateway, `GET /verify/pubkey → HTTP ${keyRes.status}`, receipt)
  }
  const keyDoc = (await keyRes.json()) as PubkeyDoc
  const ed25519PublicKey = keyDoc.ed25519?.public_key
  if (typeof ed25519PublicKey !== 'string' || ed25519PublicKey.length === 0) {
    return makeFailure(receiptId, gateway, '/verify/pubkey returned no ed25519.public_key field', receipt)
  }
  const mlDsaPublicKey = keyDoc.ml_dsa?.public_key
  if (typeof mlDsaPublicKey !== 'string' || mlDsaPublicKey.length === 0) {
    return makeFailure(receiptId, gateway, '/verify/pubkey returned no ml_dsa.public_key field', receipt)
  }

  // 4. verify — BOTH must pass.
  const edResult  = verifyEd25519Raw(canonical, ed25519SignatureRaw, ed25519PublicKey)
  const mlDsaValid = await verifyMlDsaRaw(canonical, mlDsaSignatureRaw, mlDsaPublicKey)
  const valid = edResult.valid && mlDsaValid

  let reason: string | undefined
  if (!valid) {
    const failed: string[] = []
    if (!edResult.valid) failed.push(`ed25519: ${edResult.reason ?? 'invalid'}`)
    if (!mlDsaValid)      failed.push('ml-dsa-65: signature does not match canonical payload under this public key')
    reason = failed.join('; ')
  }

  return {
    valid,
    canonical_payload:      canonical,
    algorithm:              'Ed25519 + ML-DSA-65 (hybrid)',
    reason,
    ed25519_valid:          edResult.valid,
    ml_dsa_valid:           mlDsaValid,
    receipt_id:             receiptId,
    gateway,
    receipt,
    signer_key_id:          keyDoc.key_id ?? null,
    signer_key_fingerprint: ed25519KeyFingerprint(ed25519PublicKey),
  }
}

function makeFailure(
  receiptId: string,
  gateway:   string,
  reason:    string,
  receipt:   Record<string, unknown> = {},
): FetchAndVerifyResult {
  return {
    valid:                  false,
    canonical_payload:      '',
    algorithm:              'Ed25519 + ML-DSA-65 (hybrid)',
    reason,
    ed25519_valid:          false,
    ml_dsa_valid:           false,
    receipt_id:             receiptId,
    gateway,
    receipt,
    signer_key_id:          null,
    signer_key_fingerprint: undefined,
  }
}
