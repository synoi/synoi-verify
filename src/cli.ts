#!/usr/bin/env node
/**
 * synoi-verify — verify a SynOI Decision Receipt from the command line.
 *
 *   npx @synoi/verify <receipt-id>                          → verify against http://localhost:3000
 *   npx @synoi/verify <receipt-id> --gateway https://...    → verify against a remote gateway
 *   npx @synoi/verify --help
 *
 * Exit code: 0 on valid signature, 1 on invalid, 2 on usage / network errors.
 */

import { readFileSync } from 'node:fs'
import { fetchAndVerify } from './fetch'
import { selfTest } from './selftest'
import { verifyEvidenceBundle, type EvidenceBundle } from './bundle'

interface Args {
  receiptId?:  string
  gateway:     string
  help:        boolean
  json:        boolean
  selftest:    boolean
  bundle:      boolean
  bundleFile?: string
}

function parseArgs(argv: string[]): Args {
  const out: Args = { gateway: 'https://gateway.synoi.systems', help: false, json: false, selftest: false, bundle: false }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--help' || a === '-h')    { out.help = true; continue }
    if (a === '--json')                  { out.json = true; continue }
    if (a === 'selftest' || a === '--selftest') { out.selftest = true; continue }
    if (a === 'bundle') { out.bundle = true; continue }
    if (a === '--gateway' || a === '-g') { out.gateway = argv[++i] ?? out.gateway; continue }
    if (a !== undefined && !a.startsWith('-')) {
      // First positional after `bundle` is the bundle file; otherwise the receipt id.
      if (out.bundle && !out.bundleFile) { out.bundleFile = a; continue }
      if (!out.bundle && !out.receiptId) { out.receiptId = a; continue }
    }
  }
  return out
}

function printHelp(): void {
  process.stdout.write([
    '',
    'synoi-verify — verify a SynOI Decision Receipt',
    '',
    'Usage:',
    '  npx @synoi/verify <receipt-id> [--gateway <url>] [--json]',
    '  npx @synoi/verify selftest [--json]',
    '  npx @synoi/verify bundle <file.json> [--json]',
    '  npx @synoi/verify --help',
    '',
    'Options:',
    '  --gateway, -g <url>   Gateway base URL (default: https://gateway.synoi.systems;',
    '                        pass http://localhost:3000 for a local self-hosted gateway)',
    '  --json                Emit raw JSON result; suppress human-readable output',
    '  --help, -h            Show this message',
    '',
    'Commands:',
    '  selftest              Verify the shipped golden vectors offline. Proves this',
    '                        build reproduces the signer canonical bytes (RFC 8785',
    '                        JCS) and the pinned Ed25519 verdicts. No network needed.',
    '  bundle <file.json>    Verify an exported EVIDENCE BUNDLE offline. Recomputes',
    '                        the content_digest (JCS), then verifies every enclosed',
    '                        receipt + absence statement (hybrid Ed25519 + ML-DSA-65,',
    '                        both required) against the public key_history carried IN',
    '                        the bundle. No network + no external keys needed.',
    '',
    'Exit codes:',
    '  0   signature verified',
    '  1   signature invalid or receipt tampered',
    '  2   usage error or network failure',
    '',
    'Examples:',
    '  npx @synoi/verify rcpt_abc_123',
    '  npx @synoi/verify rcpt_abc_123 --gateway https://gateway.synoi.systems',
    '  npx @synoi/verify rcpt_abc_123 --json | jq .canonical_payload',
    '',
    'Verification is cryptographic and offline-capable: once you have the',
    'receipt body + the gateway public key, no further calls to SynOI are',
    'needed. For programmatic use, import { verifyReceiptSignature } from',
    "'@synoi/verify' directly.",
    '',
  ].join('\n'))
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2))

  if (args.help) {
    printHelp()
    return 0
  }

  if (args.selftest) {
    const result = selfTest()
    if (args.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + '\n')
      return result.ok ? 0 : 1
    }
    process.stdout.write('\n  synoi-verify selftest — offline golden-vector check\n\n')
    for (const c of result.cases) {
      const mark = c.ok ? '✓' : '✗'
      process.stdout.write(`  ${mark} ${c.name}\n`)
      if (!c.ok && c.detail) process.stdout.write(`      ${c.detail}\n`)
    }
    process.stdout.write(`\n  ${result.passed}/${result.total} vectors passed`)
    if (result.ok) {
      process.stdout.write(' — this build agrees byte-for-byte with the SynOI signer.\n\n')
      return 0
    }
    process.stdout.write(` — ${result.failed} FAILED. Do NOT trust this build.\n\n`)
    return 1
  }

  if (args.bundle) {
    if (!args.bundleFile) {
      process.stderr.write('\nERROR: bundle requires a file path: synoi-verify bundle <file.json>\n\n')
      return 2
    }
    let bundle: EvidenceBundle
    try {
      bundle = JSON.parse(readFileSync(args.bundleFile, 'utf8')) as EvidenceBundle
    } catch (err) {
      process.stderr.write(`\nERROR: cannot read/parse ${args.bundleFile}: ${err instanceof Error ? err.message : String(err)}\n\n`)
      return 2
    }

    const result = await verifyEvidenceBundle(bundle)

    if (args.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + '\n')
      return result.valid ? 0 : 1
    }

    process.stdout.write('\n  synoi-verify bundle -- offline evidence-bundle verification\n\n')
    process.stdout.write(`  File          : ${args.bundleFile}\n`)
    process.stdout.write(`  Tenant        : ${result.bundle_tenant_id ?? '(none declared)'}\n`)
    process.stdout.write(`  Content digest: ${result.content_digest_ok ? 'OK' : 'MISMATCH'}`)
    if (!result.content_digest_ok && result.recomputed_content_digest) {
      process.stdout.write(`  (recomputed ${result.recomputed_content_digest})`)
    }
    process.stdout.write('\n')
    process.stdout.write(`  Receipts      : ${result.receipt_results.length}\n`)
    for (const r of result.receipt_results) {
      const mark = r.valid ? 'PASS' : 'FAIL'
      process.stdout.write(`    ${mark}  ${r.oid}${r.valid ? '' : '  (' + (r.reason ?? 'invalid') + ')'}\n`)
    }
    process.stdout.write(`  Absence stmts : ${result.absence_results.length}\n`)
    for (const a of result.absence_results) {
      const mark = a.valid ? 'PASS' : 'FAIL'
      process.stdout.write(`    ${mark}  ${a.oid}${a.valid ? '' : '  (' + (a.reason ?? 'invalid') + ')'}\n`)
    }
    process.stdout.write('\n')
    process.stdout.write(`  Verified by   : ${result.verifying_key_fingerprints.length > 0 ? '' : '(none)'}\n`)
    for (const fp of result.verifying_key_fingerprints) {
      process.stdout.write(`    ${fp}\n`)
    }
    process.stdout.write('\n')
    if (result.valid) {
      process.stdout.write('  VERIFIED -- the enclosed contents were signed by the key(s) above and\n')
      process.stdout.write('  have not been altered since, and every item is bound to tenant\n')
      process.stdout.write(`  "${result.bundle_tenant_id ?? ''}".\n`)
      process.stdout.write('  This does NOT prove the key(s) above are legitimate SynOI gateway keys:\n')
      process.stdout.write('  you must anchor the fingerprint(s) out of band (publisher pubkey,\n')
      process.stdout.write('  transparency log, or a trusted channel) before trusting this evidence.\n\n')
      return 0
    }
    process.stdout.write(`  INVALID -- ${result.reasons.join(', ')}\n\n`)
    return 1
  }

  if (!args.receiptId) {
    printHelp()
    return 2
  }

  try {
    const result = await fetchAndVerify(args.receiptId, args.gateway)

    if (args.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + '\n')
      return result.valid ? 0 : 1
    }

    process.stdout.write('\n')
    process.stdout.write(`  Gateway     : ${result.gateway}\n`)
    process.stdout.write(`  Receipt ID  : ${result.receipt_id}\n`)
    process.stdout.write(`  Algorithm   : ${result.algorithm}\n`)
    process.stdout.write(`  Signer key  : ${result.signer_key_id ?? '(not reported)'}\n`)
    process.stdout.write(`  Key fprint  : ${result.signer_key_fingerprint ?? '(not derivable)'}\n`)
    if (result.canonical_payload) {
      process.stdout.write(`  Canonical   : ${result.canonical_payload}\n`)
    }
    process.stdout.write('\n')
    if (result.valid) {
      process.stdout.write('  VERIFIED -- signature is valid; receipt has not been tampered with.\n')
      process.stdout.write('  CAVEAT: this path is Ed25519-only (no post-quantum). The public key above\n')
      process.stdout.write('  was fetched from the SAME origin as the receipt, so this proves internal\n')
      process.stdout.write('  consistency only, NOT that the key belongs to a legitimate SynOI gateway.\n')
      process.stdout.write('  You must anchor the key/fingerprint above out of band (publisher pubkey,\n')
      process.stdout.write('  transparency log, or a trusted channel) before trusting this receipt.\n\n')
      return 0
    }
    process.stdout.write(`  INVALID -- ${result.reason ?? 'verification failed'}\n\n`)
    return 1
  } catch (err) {
    process.stderr.write(`\nERROR: ${err instanceof Error ? err.message : String(err)}\n\n`)
    return 2
  }
}

main().then(code => process.exit(code))
