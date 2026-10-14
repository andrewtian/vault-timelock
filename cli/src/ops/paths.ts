// cli/src/ops/paths.ts — where vt keeps its state, and the dev-tree rule (canonical vt spec §3.2; plan Task C1).
//
// $VT_HOME (default ~/.local/state/vt) holds releases/<buildId>/ and one directory per network. A run from a
// development tree must name both VT_HOME and VAULT_TIMELOCK_DIR explicitly (vt.dev-dirs-required): an agent or a
// test can then never fall back to the operator's real state or packages. Only a release tree
// ($VT_HOME/releases/<12 hex>/…, built and verified by `vt release`, C4) may use the defaults.
import type { Network } from '@vault-timelock/core/contracts'
import { assertNetwork, refuse } from '@vault-timelock/core/contracts'
import { realpathSync } from 'node:fs'
import { isAbsolute, join, relative, sep } from 'node:path'
import { assertProfilePath } from './sandbox.ts'

export type Env = Readonly<Record<string, string | undefined>>

const set = (v: string | undefined): v is string => v !== undefined && v !== ''

// VT_HOME, or ~/.local/state/vt. Either way an absolute, normalised path that is safe inside a sandbox profile
// (vt.path): every state dir below it ends up in apiProfile. An empty VT_HOME counts as unset.
export function vtHome(env: Env): string {
  const home = set(env.VT_HOME) ? env.VT_HOME : join(env.HOME ?? '', '.local', 'state', 'vt')
  assertProfilePath(home)
  return home
}

// $VT_HOME/<network> (0700 when C3 creates it).
export function stateDir(home: string, n: Network): string {
  assertNetwork(n)
  assertProfilePath(home)
  return join(home, n)
}

const BUILD_ID = /^[0-9a-f]{12}$/

// The build id of the release scriptRealPath (the real path of a file of the running tree) belongs to: <buildId> when
// it lies inside $home/releases/<buildId>/, else null. Both sides are compared as real paths; a home that does not
// exist holds no release.
export function releaseId(scriptRealPath: string, home: string): string | null {
  let releases: string
  try { releases = join(realpathSync(home), 'releases') } catch { return null }
  const rel = relative(releases, scriptRealPath)
  if (rel === '' || isAbsolute(rel)) return null
  const parts = rel.split(sep)
  return parts.length >= 2 && BUILD_ID.test(parts[0]) ? parts[0] : null
}

// True when scriptRealPath lies inside $home/releases/<buildId>/ (releaseId).
export function isReleaseTree(scriptRealPath: string, home: string): boolean {
  return releaseId(scriptRealPath, home) !== null
}

// A dev tree needs VT_HOME and VAULT_TIMELOCK_DIR, both set to absolute paths; a release tree may use the defaults.
export function assertDevDirs(env: Env, inRelease: boolean): void {
  const explicit = set(env.VT_HOME) && isAbsolute(env.VT_HOME) && set(env.VAULT_TIMELOCK_DIR) && isAbsolute(env.VAULT_TIMELOCK_DIR)
  const ok = inRelease === true || explicit
  if (!ok) refuse('vt.dev-dirs-required', 'this is a development tree: set both VT_HOME and VAULT_TIMELOCK_DIR to absolute paths (agents and tests: fresh temp dirs); only a release tree falls back to the default directories') // @guard:vt.dev-dirs-required
}
