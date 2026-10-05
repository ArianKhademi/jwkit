// Runs the conformance fixtures through the TypeScript implementation of
// jwkit and writes what it produced for each case.
//
//   npx tsx ../conformance/run_ts/run.mts --fixtures ../conformance/fixtures.json --out ../conformance/results/ts.json
//
// The output is a JSON array of {"name", "result"} in fixture order, where
// result is "ok" or the name of the typed error. The Go runner writes the
// same format byte for byte, so the two files can be compared with diff. The
// exit status is 1 if any result differs from the fixture's expectation.

import { readFileSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { parseArgs } from 'node:util'

import { JwkitError, Verifier } from '../../ts/src/index.js'

interface Fixtures {
  config: { issuer: string; audience: string; now: number; clock_skew_sec: number; max_token_bytes: number }
  jwks: unknown
  cases: { name: string; token: string; expect: string }[]
}

const { values: args } = parseArgs({
  options: {
    fixtures: { type: 'string', default: 'fixtures.json' },
    out: { type: 'string' },
  },
})

const fx = JSON.parse(readFileSync(args.fixtures, 'utf8')) as Fixtures

// The verifier is exercised end to end, JWKS fetch included, against an
// in-process issuer that serves the fixture key set.
const jwks = JSON.stringify(fx.jwks)
const issuer = createServer((_req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' })
  res.end(jwks)
})
await new Promise<void>((resolve) => issuer.listen(0, '127.0.0.1', resolve))
const jwksUrl = `http://127.0.0.1:${(issuer.address() as AddressInfo).port}/`

const results: { name: string; result: string }[] = []
let mismatches = 0
for (const c of fx.cases) {
  // A fresh verifier per case keeps cases independent: no shared key cache
  // and no shared refetch rate limit.
  const verifier = new Verifier({
    issuer: fx.config.issuer,
    audience: fx.config.audience,
    jwksUrl,
    clockSkewSec: fx.config.clock_skew_sec,
    maxTokenBytes: fx.config.max_token_bytes,
    now: () => fx.config.now * 1000,
  })

  let got = 'ok'
  try {
    await verifier.verify(c.token)
  } catch (err) {
    got = err instanceof JwkitError ? err.code : `untyped error: ${String(err)}`
  }
  results.push({ name: c.name, result: got })
  if (got !== c.expect) {
    mismatches++
    console.error(`MISMATCH ${c.name}: expected ${c.expect}, got ${got}`)
  }
}
issuer.close()

const out = `${JSON.stringify(results, null, 2)}\n`
if (args.out === undefined) {
  process.stdout.write(out)
} else {
  writeFileSync(args.out, out)
  console.log(`run_ts: ${results.length} cases, ${mismatches} mismatches -> ${args.out}`)
}
if (mismatches > 0) {
  console.error(`run_ts: ${mismatches} case(s) differ from the fixture expectations`)
  process.exitCode = 1
}
