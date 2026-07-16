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

## What's being verified

The signature covers exactly seven canonical fields, alphabetically sorted, JSON-stringified with default separators:

```
action_class, decision, oid_hex, receipt_id, recorded_at, risk_level, tenant_id
```

Any other fields on the receipt (`latency_ms`, `intent_id`, `action_type`, etc.) are operational metadata and **not** part of the signature. Tampering with them won't fail verification — by design.

Algorithm: **Ed25519** · Signature encoding: **128 hex chars (64 raw bytes)** · Public key: **PEM SPKI**, available at `GET <gateway>/verify/pubkey`.

## Why offline matters

The promise of the SynOI Decision Receipt is "verifiable by anyone, without SynOI infrastructure." This package is the proof artifact: once you have the receipt + the gateway's public key (which the gateway publishes openly), no further contact with SynOI or the gateway is needed. You can verify a receipt from five years ago on an airplane.

If the gateway disappears tomorrow, every receipt that has ever been issued is still cryptographically verifiable — as long as someone preserved the public key.
