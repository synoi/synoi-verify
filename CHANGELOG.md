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
- `verifyReceiptSignature` verifies against a **version registry**
  (`RECEIPT_VERSION_REGISTRY`, `src/receipt-versions.ts`), never by trying
  subsets of the signed fields. A receipt carrying `schema_version` is checked
  only against that entry; an unknown value fails closed with an
  `unknown-schema-version` reason. A receipt without one (everything signed so
  far) is checked against `hosted-v1.1` then `hosted-v1.0`, whose canonical
  bytes are disjoint (v1.1 always signs a `degraded` key, v1.0 never does).
  Dropping or changing any signed field (including `degraded` or `sequence`)
  fails.

### Added

- Version registry entries: `hosted-v1.0` (legacy, before gateway #253),
  `hosted-v1.1` (current), `hosted-v1.2` (**proposed, not yet emitted by the
  gateway**: signs `schema_version`, `integrity_grade`, and `degraded_reason`
  exactly when degraded, with value-consistency rules), plus descriptive
  entries for `gap-v2-dsse` and `gap-selfsign`. New exports:
  `RECEIPT_VERSION_REGISTRY`, `getReceiptVersion`, `resolveHostedVersions`,
  `canonicalPayloadForVersion`, `checkVersionSemantics`,
  `HOSTED_V1_2_SCHEMA_VERSION`, `DEGRADED_REASON_CODES`, `INTEGRITY_GRADES`,
  and their types. `VerifyResult.version` names the entry that verified.
- `UNSIGNED_FIELD` warning (and `unsignedFieldWarning`): an unversioned
  receipt that displays `degraded_reason` or `integrity_grade`, which only
  `hosted-v1.2` signs.
- Removed before release: `canonicalPayloadForms` and `CanonicalFormCandidate`
  (the two-form guesser this registry replaces). Both were added earlier in
  this unreleased 0.3.1 and never published.
- **`hosted-v1.2` is now `current`** and the gateway emits it. `hosted-v1.1`
  is now `legacy`. This supersedes the "proposed" wording above. `hosted-v1.2`
  reserves two optional signed fields for the agent registry, `agent_id` and
  `owner_oid`: absent or null when unknown, signed when present, and required
  to be non-empty strings when present. An unversioned receipt that displays
  either one gets `UNSIGNED_FIELD`. New export: `AGENT_REGISTRY_FIELDS`.
- `vectors/receipt-versions.json`: verbatim copy of synoi-gap
  `schemas/receipt-versions.json`. A drift test checks the registry's lists,
  reason codes and grades against it, and against the synoi-gap checkout
  (`SYNOI_GAP_DIR`) when one is present.

- `VerifyResult.form` (`'current' | 'legacy-without-degraded'`),
  `VerifyResult.signed_fields`, and `VerifyResult.unsigned_canonical_fields`
  (set when a legacy receipt displays a `degraded` value its signature does
  not cover).
- **`UNSIGNED_DEGRADED` warning.** `VerifyResult.warnings` is set on every
  valid `verifyReceiptSignature` result (an empty array when there is nothing
  to flag). When a receipt verifies via `legacy-without-degraded` and carries a
  `degraded` value (`true`, `false`, or `0`/`1`), it holds
  `{ code: 'UNSIGNED_DEGRADED', field: 'degraded', message }`, where the
  message reads "This receipt was signed before `degraded` was included in the
  signature. Its `degraded` value (...) was not signed and must not be
  trusted." The receipt still verifies (founder decision 2026-10-30, matching
  the gateway's own fallback). A legacy receipt with no `degraded` value and
  every current-form receipt get no warning; a changed `degraded` on a current
  receipt still fails. `verifyReceiptByScheme` lifts the v1 warnings to its
  top-level `warnings`. New exports: `UNSIGNED_DEGRADED`,
  `unsignedDegradedWarning`, and the types `VerifyWarning` and
  `VerifyWarningCode`.
- `ALL_CANONICAL_FIELDS` and `CANONICAL_FIELDS_SCHEMA_VERSION`.
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
