// Readiness rows beyond core's `preflight` (W4): what the API, the relay and the page server say about themselves.
// The rows come from core (executor/readiness.ts), the one source `vt preflight` also prints (C7, F9-5): same rows,
// same verdicts. Every row is { id, ok: true|false|null, label, detail }; null = informational.
import { pageRows as coreRows } from '@vault-timelock/core/executor'

export const MAINNET_TICKS = [
  { id: 'backup', label: 'Every lane key’s backup is saved, re-selected and verified, and kept off this machine.' },
  { id: 'funds', label: 'I fund only what I am willing to spend: the per-job cap is shown again at Arm.' },
  { id: 'permanence', label: 'The text is public at once, permanently, and cannot be taken back.' },
  { id: 'release', label: 'I ran vt release verify on this release and the digests match.' },
  { id: 'preflight', label: 'I read the pre-flight table above; every row is ✓ or I understand why not.' },
]

// extras: { pageBuild, serve: {release,digest,build}|null, release: {release,files,ok,mismatch,missing,digest}|null, services: GET /relay/services|null }  (same-origin reads)
export const pageRows = (input) => coreRows(input)
