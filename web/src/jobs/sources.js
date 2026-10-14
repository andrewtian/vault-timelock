// Funding sources (R47; API Task S5): labels the operator declares ("railgun-eth", "pool-b", ...). The page never sees
// a source's secrets: a source is only a LABEL the operator picks for each try. Endpoints (S5): GET /sources lists,
// POST /sources {label} adds (never deleted). Arm carries `sources: { <chain>: <label> }` for every armed chain once
// at least one source exists (api/src/arm.ts: `sources` required when ≥ 1 source exists).
import { api } from '@/lib/api.js'

export const SOURCES_PATH = '/sources'
export const SOURCE_LABEL = /^[a-z0-9][a-z0-9-]{0,23}$/

// The guards Arm may refuse with, in words (the id is always shown beside the text).
export const SOURCE_GUARDS = {
  'source.label': 'a source label is lowercase letters, digits and hyphens, 1 to 24 characters, starting with a letter or digit',
  'source.unknown': 'that source is not declared: add it first, then pick it',
  'source.reused': 'that source already paid an earlier try of this same message: pick a different one (a source is never reused for the same publication)',
  'source.exhausted': 'no unused source is left for this message: declare another funding source (or stop here)',
}

// -> { supported, labels } ; a 404 (an API without S5) or any failure means "no sources": the picker is not shown and
// Arm carries none, exactly as before. The answer may be an array or { sources: [...] } of labels or { label } objects.
export async function listSources() {
  try {
    const j = await api(SOURCES_PATH)
    const arr = Array.isArray(j) ? j : Array.isArray(j?.sources) ? j.sources : []
    const labels = arr.map((x) => (typeof x === 'string' ? x : x?.label)).filter((l) => typeof l === 'string' && SOURCE_LABEL.test(l))
    return { supported: true, labels }
  } catch (e) {
    return { supported: false, labels: [], error: e?.guard === 'api.http' && e?.status === 404 ? null : (e?.guard || 'error') }
  }
}

// S5 durable marks: GET /sources/tries/<messageSha256> -> { labelsUsed: [label...] }, the labels that already paid an earlier try of this
// message. Any failure (an API without it, a bad digest) means "none known": the API's source.reused refusal stays the authority.
export async function listTries(messageSha256) {
  if (typeof messageSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(messageSha256)) return []
  try {
    const j = await api(`${SOURCES_PATH}/tries/${messageSha256}`)
    return Array.isArray(j?.labelsUsed) ? j.labelsUsed.filter((l) => typeof l === 'string' && SOURCE_LABEL.test(l)) : []
  } catch { return [] }
}

export async function addSource(label) {
  return api(SOURCES_PATH, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ label }) })
}
