/**
 * test/replay-chain.test.ts — S2.3: renderReplayChain render contract.
 *
 * Tests the structural render contract for the D1 -> E1 2-receipt chain.
 * Does NOT test gateway gate logic (that is in synoi-gateway/test/s2-replay-chain.test.ts).
 *
 * Non-claim discipline: no "Replay Approval" label anywhere here.
 */

import { renderReplayChain } from '../src/verify'

let passed = 0
let failed = 0

function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail !== undefined ? ' -- ' + detail : ''}\n`) }
}

// Minimal D1 and E1 shapes for structural tests.

const D1_OID = 'sha256:d100000000000000000000000000000000000000000000000000000000000001'

const d1Valid: Record<string, unknown> = {
  oid:  D1_OID,
  type: 'agp:decision_receipt',
  body: {
    status:   'denied',
    decision: 'deny',
    initiator: { actor_oid: 'actor:steve', actor_type: 'human_user' },
    initiated_at_ms: 1750258200000,
    resolved_at_ms:  1750258200000,
  },
}

const e1Valid: Record<string, unknown> = {
  oid:  'sha256:e100000000000000000000000000000000000000000000000000000000000002',
  type: 'agp:decision_receipt',
  prev: D1_OID,
  body: {
    status:         'ok',
    decision:       'allow',
    replayed_after: D1_OID,
    authority:      { subject_oid: D1_OID },
    detail:         'hitl_approval_signal_oid=hitl-sms-001',
    initiator:      { actor_oid: 'actor:steve', actor_type: 'human_user' },
    initiated_at_ms: 1750258260000,
    resolved_at_ms:  1750258260000,
  },
}

// ── Test 1: valid D1 -> E1 chain ─────────────────────────────────────────────

const r1 = renderReplayChain(e1Valid, d1Valid)
ok('1a: valid chain ok=true', r1.ok === true)
if (r1.ok) {
  ok('1b: merkle_edge_valid', r1.chain.merkle_edge_valid === true)
  ok('1c: replayed_after_valid', r1.chain.replayed_after_valid === true)
  ok('1d: hitl_signal_oid extracted', r1.chain.hitl_signal_oid === 'hitl-sms-001')
  ok('1e: chain.denial is d1Valid', r1.chain.denial === d1Valid)
  ok('1f: chain.execution is e1Valid', r1.chain.execution === e1Valid)
}

// ── Test 2: E1 without replayed_after -> ok=false ────────────────────────────

const e1NoReplay: Record<string, unknown> = {
  oid:  'sha256:e1noreplay',
  prev: D1_OID,
  body: { status: 'ok', initiator: { actor_oid: 'actor:steve' } },
}
const r2 = renderReplayChain(e1NoReplay, d1Valid)
ok('2a: no replayed_after -> ok=false', r2.ok === false)
if (!r2.ok) {
  ok('2b: reason mentions replayed_after', r2.reason.includes('replayed_after'))
}

// ── Test 3: broken Merkle edge (prev != replayed_after) ──────────────────────

const e1BrokenEdge: Record<string, unknown> = {
  oid:  'sha256:e1broken',
  prev: 'sha256:' + '0'.repeat(64),  // wrong prev
  body: {
    status:         'ok',
    replayed_after: D1_OID,  // still points at D1
    initiator:      { actor_oid: 'actor:steve' },
  },
}
const r3 = renderReplayChain(e1BrokenEdge, d1Valid)
ok('3a: broken edge ok=true (structural check succeeds; merkle_edge_valid=false)', r3.ok === true)
if (r3.ok) {
  ok('3b: merkle_edge_valid=false', r3.chain.merkle_edge_valid === false)
  ok('3c: replayed_after_valid still true', r3.chain.replayed_after_valid === true)
}

// ── Test 4: D1 has no oid -> ok=false ────────────────────────────────────────

const d1NoOid: Record<string, unknown> = { body: { status: 'denied' } }
const r4 = renderReplayChain(e1Valid, d1NoOid)
ok('4a: D1 without oid -> ok=false', r4.ok === false)

// ── Test 5: hitl_signal_oid absent when detail has no match ──────────────────

const e1NoSignal: Record<string, unknown> = {
  oid:  'sha256:e1nosig',
  prev: D1_OID,
  body: {
    status:         'ok',
    replayed_after: D1_OID,
    detail:         'some other detail string',
    initiator:      { actor_oid: 'actor:steve' },
  },
}
const r5 = renderReplayChain(e1NoSignal, d1Valid)
ok('5a: no hitl pattern in detail -> hitl_signal_oid undefined', r5.ok === true)
if (r5.ok) {
  ok('5b: hitl_signal_oid is undefined', r5.chain.hitl_signal_oid === undefined)
}

// ── Summary ──────────────────────────────────────────────────────────────────

process.stdout.write(`\nResults: ${passed} passed, ${failed} failed\n`)
if (failed > 0) process.exit(1)
