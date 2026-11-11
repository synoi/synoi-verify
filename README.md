# @synoi/verify

Independent verifier for SynOI Decision Receipts. Hybrid Ed25519 + ML-DSA-65,
Node and browser, no SynOI account at any point.

Anyone holding a receipt (your auditor, your counterparty, your regulator) can
check its signatures themselves and see whether it has been altered since it was
signed. What you need to do that depends on what you are holding, and the
difference is not cosmetic:

- **You have the receipt JSON.** Verification is fully offline. Once you also
  have the signing public key, nothing is sent anywhere and no service is
  contacted, now or ever. See "Fully offline" and the browser section below.
- **You have only a receipt ID.** The ID is a lookup handle, not evidence. The
  CLI below fetches the receipt and the key from a gateway over the network. That
  is convenient, and it is not the same claim: you are trusting whoever answered.

```bash
npx @synoi/verify rcpt_abc_123
```

```
  Gateway     : https://gateway.synoi.systems
  Receipt ID  : rcpt_abc_123
  Algorithm   : Ed25519
  Signer key  : key_2026_05_18
  Canonical   : {"action_class":"B","decision":"allow","oid_hex":"...","receipt_id":"rcpt_abc_123","recorded_at":1747584000000,"risk_level":"low","tenant_id":"founder"}

  ✓ VERIFIED: the legacy v1 signature is valid over the seven canonical fields
    listed above. Fields outside that list are not covered. See "What's being
    verified".
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

Every receipt the **hosted** SynOI gateway mints carries
`receipt_scheme: 'synoi.receipt/v2'`, so the v2 row is the one that matters in
practice. The self-hosted lite daemon mints the `gap-selfsign` tier instead,
which is row two. v2 requires **both** signatures:
a v2 receipt whose ML-DSA-65 signature is missing or invalid is rejected, never
accepted on the Ed25519 signature alone.

A receipt whose scheme this build cannot verify is **rejected with a reason**, never
passed. A missing `receipt_scheme` is not silently treated as v1, so stripping the
discriminator to force the weaker path does not work.

The `gap-selfsign` row requires `@synoi/gap` >= 1.2.0, in Node and in the browser
alike. 1.2.0 is where `receipt()` began stamping `receipt_scheme` on the envelope
it mints, and where the signed payload widened to cover `gap_version`,
`supersedes`, and `signature_key_id`. A receipt minted by `@synoi/gap` 1.1.0 or
earlier carries no discriminator, so this dispatcher rejects it as
`missing-receipt-scheme-and-legacy-v1-not-allowed`: fail-closed, but it does not
verify.

Requires `@synoi/sraid` >= 0.3.0, which is where the browser-safe hybrid verify
lives. Ed25519 runs on WebCrypto with a `@noble/curves` fallback, ML-DSA-65 on
`@noble/post-quantum`, SHA-256 on WebCrypto. No network call, no account, and
nothing you paste leaves the page.

## What's being verified

This section describes the **v1 (flat)** scheme, which is what the `npx @synoi/verify <id>`
CLI above checks. It is what the hosted gateway's own Decision Receipts carry
(chat routes, `/v1/risk/evaluate`, HITL, policy-change, MCP/A2A, bypass, drift).
GAP CDRO receipts are different: `synoi.receipt/v2`, whose detached DSSE
attestation covers the receipt's whole content core and requires both an
Ed25519 and an ML-DSA-65 signature, and `synoi.receipt/gap-selfsign` (Lite).
See the browser table above for scheme coverage.

Under v1, the signature covers the canonical fields the receipt carries, alphabetically sorted and JSON-stringified with default separators. Seven are required on every receipt:

```
action_class, decision, oid_hex, receipt_id, recorded_at, risk_level, tenant_id
```

Nineteen more are signed when present and omitted when absent (`degraded`, `sequence`, `gateway_manifest_sha256`, `policy_versions`, `approver_ref`, ...). The full list of 26 is vendored from synoi-gap in `vectors/canonical-receipt-fields.json` and exported as `ALL_CANONICAL_FIELDS`.

Any other fields on the receipt (`latency_ms`, `intent_id`, `action_type`, etc.) are operational metadata and **not** part of the signature. Tampering with them won't fail verification, by design. This is the single most
important limit of the v1 scheme, and it is why v2 exists.

### Versions

Each v1 receipt is verified against exactly one entry of a version registry (`RECEIPT_VERSION_REGISTRY`, `src/receipt-versions.ts`). An entry declares its signed fields (required, and signed-when-present), canonicalization, signature schemes, status and the warnings it may emit. The result says which entry verified in `result.version`.

| version | carries `schema_version` | status | what it signs |
|---|---|---|---|
| `hosted-v1.0` | no | legacy | the 7 required + 18 when present; **not** `degraded` (signed before gateway #253) |
| `hosted-v1.1` | no | current (what the gateway emits today) | the same plus `degraded` as a boolean (absent is signed as `false`) |
| `hosted-v1.2` | `"hosted-v1.2"` | **proposed, not yet emitted by the gateway** | the v1.1 fields plus `schema_version`, `integrity_grade` (A-D), and `degraded_reason` exactly when `degraded` is true |

How a receipt picks its entry:

- **`schema_version` present:** only the entry with that value is tried. An unknown value (including `"hosted-v1.1"`, which nothing ever signed) fails closed with an `unknown-schema-version` reason, before any signature check.
- **`schema_version` absent or null** (every receipt signed so far): `hosted-v1.1`, then `hosted-v1.0`. This is not guessing. Their canonical bytes cannot coincide, because v1.1 bytes always contain a `"degraded"` key and v1.0 bytes never do, so at most one can match a signature. Neither signs `schema_version`, so stripping the version from a v1.2 receipt makes it fail rather than read as an older one.

`hosted-v1.2` also checks its values, beyond the signature: `degraded_reason` is a sorted, comma-joined list of distinct known codes (`DEGRADED_REASON_CODES`), present exactly when `degraded` is true, and `integrity_grade` is `A` when not degraded, else the worst grade of the codes.

`result.form` (`'current'` / `'legacy-without-degraded'`) is still set for the two unversioned entries; prefer `result.version`.

### Warnings

A `hosted-v1.0` receipt that still carries a `degraded` value (`true`, `false`, or a `0`/`1` row export) verifies, because its signature is valid over the fields it does cover. But that `degraded` value was never signed, so the result flags it:

```ts
const result = verifyReceiptSignature(receiptJson, signatureHex, publicKeyPem)
// result.valid === true, result.version === 'hosted-v1.0'
// result.unsigned_canonical_fields => ['degraded']
// result.warnings =>
// [{ code: 'UNSIGNED_DEGRADED', field: 'degraded',
//    message: 'This receipt was signed before `degraded` was included in the signature. Its `degraded` value (true) was not signed and must not be trusted.' }]
```

An unversioned receipt (`hosted-v1.0` or `hosted-v1.1`) that displays `degraded_reason` or `integrity_grade` gets an `UNSIGNED_FIELD` warning per field: only `hosted-v1.2` signs them.

Check `result.warnings` (also lifted to the top level of `verifyReceiptByScheme`'s v1 result) before acting on those fields. `warnings` is an empty array on every other valid result. A changed signed field is not a warning: it fails verification.

Algorithm: **Ed25519** · Signature encoding: **128 hex chars (64 raw bytes)** · Public key: **PEM SPKI**, available at `GET <gateway>/verify/pubkey`.

## Fully offline

The promise of the SynOI Decision Receipt is "verifiable by anyone, without SynOI
infrastructure." This package is the proof artifact, and the precondition is
exact: once you hold **the receipt JSON** and **the signing public key** (which
the gateway publishes openly), no further contact with SynOI or the gateway is
needed. You can verify a receipt from five years ago on an airplane.

Both halves are required. A receipt ID on its own is a lookup handle, so
`npx @synoi/verify <id>` is a network operation, not an offline one. Hold the
receipt and the key yourself and there is no network step at all.

If the gateway disappears tomorrow, every receipt that has ever been issued is
still cryptographically verifiable, as long as someone preserved the public key.
