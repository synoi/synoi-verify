/**
 * Network helper — fetches a receipt + the gateway's public key, then
 * verifies. Kept separate from verify.ts so the pure verifier has zero
 * I/O dependencies (importable in environments without `fetch`).
 */

import { createHash, createPublicKey } from 'node:crypto'
import { verifyReceiptSignature, type VerifyResult } from './verify'

export interface FetchAndVerifyResult extends VerifyResult {
  receipt_id:            string
  gateway:               string
  receipt:               Record<string, unknown>
  signer_key_id:         string | null
  /**
   * 'sha256:' + sha256(SPKI DER) of the Ed25519 public key this receipt was
   * checked against, when that key could be parsed. Informational only, not
   * load-bearing for the verdict: this v1 path fetches the key from the SAME
   * origin as the receipt, so a valid signature proves internal consistency,
   * NOT that the key belongs to a legitimate SynOI gateway. That trust must be
   * anchored out of band (see the CLI's VERIFIED caveat).
   */
  signer_key_fingerprint: string | undefined
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
 * Fetch `<gateway>/verify/<id>` + `<gateway>/verify/pubkey`, then verify the
 * receipt's signature against the public key. The two endpoints are
 * documented in the gateway's verify-router.ts.
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

  const signatureRaw = receipt.signature
  if (typeof signatureRaw !== 'string' || signatureRaw.length === 0) {
    return makeFailure(receiptId, gateway, 'receipt has no signature field (or empty)', receipt)
  }

  // 2. fetch the public key
  const keyRes = await fetch(`${base}/verify/pubkey`, {
    headers: { Accept: 'application/json' },
  })
  if (!keyRes.ok) {
    return makeFailure(receiptId, gateway, `GET /verify/pubkey → HTTP ${keyRes.status}`, receipt)
  }
  const keyDoc = (await keyRes.json()) as { public_key?: string; key_id?: string }
  if (typeof keyDoc.public_key !== 'string' || keyDoc.public_key.length === 0) {
    return makeFailure(receiptId, gateway, '/verify/pubkey returned no public_key field', receipt)
  }

  // 3. verify
  const result = verifyReceiptSignature(receipt, signatureRaw, keyDoc.public_key)
  return {
    ...result,
    receipt_id:             receiptId,
    gateway,
    receipt,
    signer_key_id:          keyDoc.key_id ?? null,
    signer_key_fingerprint: ed25519KeyFingerprint(keyDoc.public_key),
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
    algorithm:              'Ed25519',
    reason,
    receipt_id:             receiptId,
    gateway,
    receipt,
    signer_key_id:          null,
    signer_key_fingerprint: undefined,
  }
}
