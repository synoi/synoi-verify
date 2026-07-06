/**
 * test/selftest.test.ts — the shipped golden vectors self-verify.
 *
 * Runs the same `selfTest()` the CLI `synoi-verify selftest` runs, and asserts
 * every shipped vector passes (canonical bytes reproduced + verdict reproduced).
 * This guards the vectors/ fixture against drift in either direction.
 */

import { selfTest } from '../src/selftest'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

const result = selfTest()

ok('selftest: loaded a non-empty vector set', result.total > 0, `total=${result.total}`)
ok('selftest: overall ok', result.ok, `${result.failed} failed`)

for (const c of result.cases) {
  ok(`selftest vector: ${c.name}`, c.ok, c.detail)
}

// Sanity: at least one unicode vector and one large-int vector are present, so
// the M2 edge cases are actually exercised by the shipped fixture.
ok('selftest: covers a unicode vector',
   result.cases.some((c) => c.name.includes('unicode')))
ok('selftest: covers a large-int vector',
   result.cases.some((c) => c.name.includes('large_int')))
ok('selftest: covers a negative (tampered) vector',
   result.cases.some((c) => c.name.includes('tampered')))

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed === 0 ? 0 : 1)
