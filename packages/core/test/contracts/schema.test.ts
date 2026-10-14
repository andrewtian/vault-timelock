// The vt-job/1 JSON Schema (draft 2020-12) against the job fixtures, with a small validator for exactly the keywords
// the schema uses (an unknown keyword fails the test, so the validator can't silently skip a rule).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { publishModesFor } from '../../src/contracts/index.ts'

type S = Record<string, unknown>
const dir = new URL('../../contract/fixtures/jobs/', import.meta.url)
const schema = JSON.parse(readFileSync(new URL('../../src/contracts/vt-job-1.schema.json', import.meta.url), 'utf8')) as S
const ANNOTATIONS = new Set(['$schema', '$id', 'title', 'description', '$defs'])

function typeOk(t: string, v: unknown): boolean {
  switch (t) {
    case 'object': return v !== null && typeof v === 'object' && !Array.isArray(v)
    case 'array': return Array.isArray(v)
    case 'string': return typeof v === 'string'
    case 'number': return typeof v === 'number' && Number.isFinite(v)
    case 'integer': return Number.isInteger(v)
    case 'boolean': return typeof v === 'boolean'
    case 'null': return v === null
    default: throw new Error(`unsupported type ${t}`)
  }
}
const deepEq = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b)

function valid(s: S, v: unknown): boolean {
  for (const [k, x] of Object.entries(s)) {
    if (ANNOTATIONS.has(k)) continue
    switch (k) {
      case '$ref': { const name = String(x).replace('#/$defs/', ''); if (!valid((schema.$defs as Record<string, S>)[name], v)) return false; break }
      case 'type': if (!typeOk(x as string, v)) return false; break
      case 'const': if (!deepEq(x, v)) return false; break
      case 'enum': if (!(x as unknown[]).some((e) => deepEq(e, v))) return false; break
      case 'pattern': if (typeof v === 'string' && !new RegExp(x as string, 'u').test(v)) return false; break
      case 'minLength': if (typeof v === 'string' && [...v].length < (x as number)) return false; break
      case 'minimum': if (typeof v === 'number' && v < (x as number)) return false; break
      case 'maximum': if (typeof v === 'number' && v > (x as number)) return false; break
      case 'exclusiveMinimum': if (typeof v === 'number' && v <= (x as number)) return false; break
      case 'required': if (typeOk('object', v) && !(x as string[]).every((r) => Object.hasOwn(v as object, r))) return false; break
      case 'minProperties': if (typeOk('object', v) && Object.keys(v as object).length < (x as number)) return false; break
      case 'properties': if (typeOk('object', v)) for (const [p, ps] of Object.entries(x as Record<string, S>)) if (Object.hasOwn(v as object, p) && !valid(ps, (v as S)[p])) return false; break
      case 'additionalProperties':
        if (x !== false) throw new Error('only additionalProperties: false is used')
        if (typeOk('object', v) && !Object.keys(v as object).every((p) => Object.hasOwn((s.properties ?? {}) as object, p))) return false
        break
      case 'oneOf': if ((x as S[]).filter((o) => valid(o, v)).length !== 1) return false; break
      case 'anyOf': if (!(x as S[]).some((o) => valid(o, v))) return false; break
      case 'not': if (valid(x as S, v)) return false; break
      default: throw new Error(`unsupported keyword ${k}`)
    }
  }
  return true
}
const load = (p: string): unknown => JSON.parse(readFileSync(new URL(p, dir), 'utf8'))

test('draft 2020-12, additionalProperties: false on every object schema', () => {
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema')
  const walk = (s: unknown, at: string): void => {
    if (Array.isArray(s)) { s.forEach((x, i) => walk(x, `${at}[${i}]`)); return }
    if (s === null || typeof s !== 'object') return
    const o = s as S
    if (o.properties !== undefined || o.type === 'object') assert.equal(o.additionalProperties, false, at)
    for (const [k, x] of Object.entries(o)) if (k !== 'enum' && k !== 'const') walk(x, `${at}.${k}`)
  }
  walk(schema, '#')
})

test('publishMode enums come from the publish table', () => {
  const defs = schema.$defs as Record<string, { properties: Record<string, { enum: string[] }> }>
  assert.deepEqual(defs.ethChain.properties.publishMode.enum, publishModesFor('eth'))
  assert.deepEqual(defs.solChain.properties.publishMode.enum, publishModesFor('sol'))
  assert.deepEqual((schema.$defs as Record<string, { properties: Record<string, { enum: string[] }> }>).btcChain.properties.publishMode.enum, publishModesFor('btc'))
})

test('every valid fixture passes the schema', () => {
  for (const f of readdirSync(new URL('valid/', dir)).filter((x) => x !== 'expected.json')) assert.equal(valid(schema, load(`valid/${f}`)), true, f)
})

// Structural defects the schema itself catches; the rest are the validator's (EIP-55, base58 length, 2 decimals,
// clawback rules, reserved modes, messageFile at the API, key-like and IP-like names).
const SCHEMA_REJECTS = new Set([
  'unknown-key-autoArm.json', 'format-v2.json', 'network-missing.json', 'name-non-ascii.json', 'name-65.json', 'budget-0.json',
  'budget-1000.01.json', 'tip-cap-0.05.json', 'tip-cap-101.json', 'cu-cap-2000001.json', 'copies-0.json', 'copies-10001.json',
  'field-chain-tip-on-sol.json', 'recipient-legacy.json', 'publish-mode-wrong-chain.json', 'publish-mode-unknown.json',
  'fee-strategy-unknown.json', 'message-and-sha.json', 'publish-mode-dropped.json', 'arweave-copy-not-boolean.json',
  'text-kind-unknown.json', // textKind is a two-value enum (timelocked passes, reserved); E7b: btc is a schema chain now (testnet/mainnet btc and btc drain pass the schema)
  'btc-fee-rate-0.json', 'btc-fee-rate-501.json', 'btc-fee-rate-1.5.json', 'btc-clawback.json', 'btc-address-eth.json', 'btc-address-upper.json', 'btc-publish-mode-wrong-chain.json', 'btc-tip-field.json', 'fee-rate-on-eth.json',
])
test('invalid fixtures: the schema rejects exactly the structural ones', () => {
  for (const f of readdirSync(new URL('invalid/', dir)).filter((x) => x !== 'expected.json')) assert.equal(valid(schema, load(`invalid/${f}`)), !SCHEMA_REJECTS.has(f), f)
})
