# @synoi/verify

Offline Ed25519 verifier for SynOI Decision Receipts.

Anyone with a receipt ID — your auditor, your counterparty, your regulator —
can cryptographically prove the decision was real, was made by the gateway
they think it was, and hasn't been tampered with. Without contacting SynOI.

```bash
npx @synoi/verify rcpt_abc_123
```

```
  Gateway     : https://gateway.synoi.systems
  Receipt ID  : rcpt_abc_123
  Algorithm   : Ed25519
  Signer key  : key_2026_05_18
  Canonical   : {"action_class":"B","decision":"allow","oid_hex":"...","receipt_id":"rcpt_abc_123","recorded_at":1747584000000,"risk_level":"low","tenant_id":"founder"}

  ✓ VERIFIED — signature is valid; receipt has not been tampered with.
```

Exit code is `0` on a verified signature, `1` if invalid, `2` on usage / network errors.

## Verify a remote gateway

```bash
npx @synoi/verify rcpt_abc_123 --gateway https://gateway.synoi.systems
```

## Programmatic use

```ts
import { fetchAndVerify } from '@synoi/verify'

const result = await fetchAndVerify('rcpt_abc_123', 'https://gateway.synoi.systems')
if (!result.valid) {
  throw new Error(`Receipt rejected: ${result.reason}`)
}
console.log(result.canonical_payload)
```

For fully offline use (no fetch), import the pure verifier:

```ts
import { verifyReceiptSignature } from '@synoi/verify'

const result = verifyReceiptSignature(receiptJson, signatureHex, publicKeyPem)
```

## In a browser, a Chrome extension, or a service worker

Import `@synoi/verify/browser`. The default entry statically imports `node:crypto`
for its legacy v1 path, which does not exist in a browser and breaks the bundle;
the `/browser` subpath is the browser-safe surface.

```ts
import { verifyReceiptByScheme } from '@synoi/verify/browser'

const result = await verifyReceiptByScheme({
  receipt,      // the full receipt JSON, pasted or loaded from anywhere
  ed25519_pub,  // raw 32 bytes
  ml_dsa_pub,   // raw 1952 bytes
})
// result.scheme === 'v2', result.valid === true|false
```

What the browser build verifies, and what it does not:

| Receipt scheme | Browser | Node |
|---|---|---|
| `synoi.receipt/v2` (hybrid DSSE, Ed25519 **and** ML-DSA-65) | yes | yes |
| `synoi.receipt/gap-selfsign` (single Ed25519, lite daemon) | yes | yes |
| legacy v1, no `receipt_scheme` field | no, fails closed | opt-in only |

Every receipt the SynOI gateway mints carries `receipt_scheme: 'synoi.receipt/v2'`,
so the v2 row is the one that matters in practice. It requires **both** signatures:
a v2 receipt whose ML-DSA-65 signature is missing or invalid is rejected, never
accepted on the Ed25519 signature alone.

A receipt whose scheme this build cannot verify is **rejected with a reason**, never
passed. A missing `receipt_scheme` is not silently treated as v1, so stripping the
discriminator to force the weaker path does not work.

Requires `@synoi/sraid` >= 0.3.0, which is where the browser-safe hybrid verify
lives. Ed25519 runs on WebCrypto with a `@noble/curves` fallback, ML-DSA-65 on
`@noble/post-quantum`, SHA-256 on WebCrypto. No network call, no account, and
nothing you paste leaves the page.

## What's being verified

This section describes the **legacy v1** scheme, which is what the `npx @synoi/verify <id>`
CLI above checks. It is not what a current gateway receipt carries: those are
`synoi.receipt/v2`, whose detached DSSE attestation covers the receipt's whole
content core rather than a seven-field projection, and requires both an Ed25519
and an ML-DSA-65 signature. See the browser table above for scheme coverage.

Under v1, the signature covers exactly seven canonical fields, alphabetically sorted, JSON-stringified with default separators:

```
action_class, decision, oid_hex, receipt_id, recorded_at, risk_level, tenant_id
```

Any other fields on the receipt (`latency_ms`, `intent_id`, `action_type`, etc.) are operational metadata and **not** part of the signature. Tampering with them won't fail verification — by design.

Algorithm: **Ed25519** · Signature encoding: **128 hex chars (64 raw bytes)** · Public key: **PEM SPKI**, available at `GET <gateway>/verify/pubkey`.

## Why offline matters

The promise of the SynOI Decision Receipt is "verifiable by anyone, without SynOI infrastructure." This package is the proof artifact: once you have the receipt + the gateway's public key (which the gateway publishes openly), no further contact with SynOI or the gateway is needed. You can verify a receipt from five years ago on an airplane.

If the gateway disappears tomorrow, every receipt that has ever been issued is still cryptographically verifiable — as long as someone preserved the public key.
