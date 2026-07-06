/**
 * countersign.ts — verify SynOI's Ed25519 counter-signature on an anchor batch.
 *
 * When a receipt's `/verify/:id/anchor` response includes a `synoi` block,
 * that's SynOI Inc's signature over a canonical bundle (batch_root +
 * install_id + leaf_count + timestamps + status). The signature is
 * verified against SynOI's published Ed25519 public key (PEM SPKI).
 *
 * Verification flow:
 *
 *   const anchor = await fetch(`${gw}/verify/${id}/anchor`).then(r => r.json())
 *   if (anchor.synoi) {
 *     const pubKey = await fetchSynoiPubkey()   // base64-encoded raw 32 bytes
 *     const ok = verifySynoiCountersignature(
 *       anchor.synoi.canonical_bundle,
 *       anchor.synoi.signature,
 *       pubKey,
 *     )
 *     if (!ok) throw new Error('SynOI counter-signature invalid')
 *   }
 *
 * The signature is independent of:
 *   - The customer's per-receipt Ed25519 signature (verified separately
 *     via verifyReceiptSignature)
 *   - The Bitcoin / OpenTimestamps anchor (verified separately via `ots verify`)
 *
 * To forge a counter-signed receipt convincingly, an attacker would need
 * compromise BOTH the customer's signing key AND SynOI Inc's root key.
 */

import { verify } from 'node:crypto'

export interface SynoiCountersignatureBlock {
  signature:        string   // base64 — Ed25519 over canonical_bundle
  signer_key_id:    string
  status:           'trusted' | 'flagged'
  reason?:          string | null
  signed_at:        number
  canonical_bundle: string
}

export interface CountersignVerifyResult {
  valid:  boolean
  status: 'trusted' | 'flagged' | null
  reason?: string
}

/**
 * Verify SynOI's Ed25519 counter-signature.
 *
 * @param canonicalBundle — the exact bytes that SynOI signed
 * @param signatureB64    — base64-encoded 64-byte Ed25519 signature
 * @param publicKey       — SynOI's public key, either:
 *                          - base64 of raw 32 bytes  (preferred — matches the format SynOI publishes)
 *                          - PEM string with SPKI structure
 */
export function verifySynoiCountersignature(
  canonicalBundle: string,
  signatureB64:    string,
  publicKey:       string,
): CountersignVerifyResult {
  try {
    const sigBytes = Buffer.from(signatureB64, 'base64')
    if (sigBytes.length !== 64) {
      return {
        valid:  false,
        status: null,
        reason: `Ed25519 signature must be 64 bytes; got ${sigBytes.length}`,
      }
    }

    // Build a KeyObject from either PEM or raw-base64 form.
    let keyObj: import('node:crypto').KeyObject
    if (publicKey.includes('BEGIN')) {
      const { createPublicKey } = require('node:crypto') as typeof import('node:crypto')
      keyObj = createPublicKey({ key: publicKey, format: 'pem' })
    } else {
      // Raw 32 bytes — wrap in SPKI manually.
      const rawKey = Buffer.from(publicKey, 'base64')
      if (rawKey.length !== 32) {
        return {
          valid:  false,
          status: null,
          reason: `Ed25519 raw public key must be 32 bytes; got ${rawKey.length}`,
        }
      }
      // SPKI prefix for Ed25519 (RFC 8410): 0x30 0x2a 0x30 0x05 0x06 0x03 0x2b 0x65 0x70 0x03 0x21 0x00
      const spkiPrefix = Buffer.from([
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
      ])
      const spki = Buffer.concat([spkiPrefix, rawKey])
      const { createPublicKey } = require('node:crypto') as typeof import('node:crypto')
      keyObj = createPublicKey({ key: spki, format: 'der', type: 'spki' })
    }

    const ok = verify(null, Buffer.from(canonicalBundle, 'utf-8'), keyObj, sigBytes)

    // Try to surface the embedded status (the gateway returns it; we
    // re-parse so we can echo it on a valid verification).
    let status: 'trusted' | 'flagged' | null = null
    try {
      const parsed = JSON.parse(canonicalBundle) as { status?: 'trusted' | 'flagged' }
      status = parsed.status ?? null
    } catch { /* ignore — caller still gets valid/invalid */ }

    return { valid: ok, status, ...(ok ? {} : { reason: 'signature does not match canonical bundle under this public key' }) }
  } catch (err) {
    return {
      valid:  false,
      status: null,
      reason: (err as Error).message,
    }
  }
}
