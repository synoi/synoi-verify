# Changelog

## 0.3.1 (unreleased)

### Fixed

- **v1 receipts from the hosted gateway now verify (RX-01).** `verifyReceiptSignature`
  rebuilt the canonical bytes from 8 fields; the hosted gateway signs 26
  (including `degraded` and `sequence`), so every current hosted risk receipt
  reported "signature does not match". The signed-field list is now vendored
  from synoi-gap `schemas/canonical-receipt-fields.json` (version 1) into
  `src/canonical-fields.ts`, with a verbatim copy at
  `vectors/canonical-receipt-fields.json`.
- `verifyReceiptSignature` checks exactly two fixed forms, matching the
  gateway's own verifier: the current form (`degraded` bound as a boolean) and
  the legacy form signed before `degraded` was bound. It never tries subsets of
  the signed fields, so dropping or changing any signed field (including
  `degraded` or `sequence`) fails.

### Added

- `VerifyResult.form` (`'current' | 'legacy-without-degraded'`),
  `VerifyResult.signed_fields`, and `VerifyResult.unsigned_canonical_fields`
  (set when a legacy receipt displays a `degraded` value its signature does
  not cover).
- `ALL_CANONICAL_FIELDS`, `CANONICAL_FIELDS_SCHEMA_VERSION`, and
  `canonicalPayloadForms`.
- A drift test (`test/hosted-canonical-fields.test.ts`) that fails if the
  vendored list differs from synoi-gap's schema file or from the gateway's
  `CANONICAL_FIELDS`, when those checkouts are present next to this repo
  (or at `SYNOI_GAP_DIR` / `SYNOI_GATEWAY_DIR`).

### Changed

- `OPTIONAL_CANONICAL_FIELDS` now lists all 19 optional signed fields (was
  only `gateway_manifest_sha256`). `CANONICAL_FIELDS` is unchanged (the 7
  required fields).
- `canonicalPayload` now projects all 26 fields under omit-when-absent.
  Receipts that carry none of the newer fields produce the same bytes as before.
