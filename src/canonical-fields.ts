/**
 * Vendored copy of the SynOI Decision Receipt canonical signing field list.
 *
 * Source of truth: synoi-gap `schemas/canonical-receipt-fields.json` (version 1,
 * synoi-gap 42c03e3), copied verbatim to `vectors/canonical-receipt-fields.json`
 * in this repo. A published npm package cannot read a sibling repo at runtime,
 * so the list is a literal here, like the gateway's and control's copies.
 *
 * test/hosted-canonical-fields.test.ts fails if these arrays drift from the
 * vendored JSON, if the vendored JSON drifts from synoi-gap's file (when a
 * synoi-gap checkout is present), or if the union drifts from the hosted
 * gateway's CANONICAL_FIELDS (when a synoi-gateway checkout is present).
 * To update: re-copy the schema file, then edit both arrays to match it.
 */

/** `legacy_required_fields`: every v1 receipt carries these. Sorted. */
export const LEGACY_REQUIRED_FIELDS = [
  'action_class',
  'decision',
  'oid_hex',
  'receipt_id',
  'recorded_at',
  'risk_level',
  'tenant_id',
] as const

/** `optional_fields`: signed when present and non-null, omitted otherwise. Sorted. */
export const OPTIONAL_FIELDS = [
  'action_payload_hash',
  'approver_ref',
  'cited_oracle_inputs',
  'decision_subject_oid',
  'degraded',
  'gateway_manifest_sha256',
  'grant_oid',
  'intent_oid',
  'policy_versions',
  'prev',
  'replayed_after',
  'rule_id',
  'sequence',
  'session_id',
  'state_sha256',
  'status',
  'subject_oid',
  'target_class',
  'target_id',
] as const

/** `version` of the vendored schema file. */
export const CANONICAL_FIELDS_SCHEMA_VERSION = 1
