// cli/src/ops/scope.ts — what the file-read allow-list of a sandboxed command's profile names (PF-C follow-ups 2 and 3), resolved to REAL paths:
//   · tree: only what the command imports of the code tree this file belongs to. A development tree: cli/src, packages/core/src, broadcast/src
//     (and the vt-broadcast files it reads by name) and the installed node_modules; never .git, docs, test, web, api or the other lanes' notes.
//     A release tree ($VT_HOME/releases/<id>): the release as built and verified;
//   · node: the `node` binary as PATH finds it (bin/vt starts that one inside the sandbox), each symlink on the way, its real file, and exactly the
//     dylibs it loads outside /usr and /System (otool -L, recursively, resolved to real files): literals, not its install directory;
//   · handed: every file named on the command line, as the absolute real path bin/vt rewrote the argument to.
// profile.ts prints the profile from it; tests build the expected profile from the same function.
import { spawnSync } from 'node:child_process'
import { userInfo } from 'node:os'
import { existsSync, lstatSync, readlinkSync, realpathSync } from 'node:fs'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { findTool } from './localnet.ts'
import { releaseId, vtHome } from './paths.ts'
import { handedFiles } from './sandbox.ts'
import type { ReadScope } from './sandbox.ts'
import { realPathOf } from './stack.ts'

const DEV_TREE_DIRS = ['cli/src', 'cli/node_modules', 'packages/core/src', 'packages/core/node_modules', 'broadcast/src', 'broadcast/node_modules', 'node_modules']
const DEV_TREE_FILES = ['cli/bin/vt', 'package.json', 'cli/package.json', 'packages/core/package.json', 'broadcast/package.json', 'broadcast/endpoints.json']
const SYSTEM = /^\/(usr|System)\//

// the symlinks on the way to a file (each as a literal the walk reads), then the real file
function chainOf(p: string): string[] {
  const out = [p]
  let cur = p
  for (let i = 0; i < 16 && lstatSync(cur).isSymbolicLink(); i++) {
    const t = readlinkSync(cur)
    cur = isAbsolute(t) ? t : join(dirname(cur), t)
    out.push(cur)
  }
  out.push(realpathSync(p))
  return out
}
export function dylibsOf(file: string, seen: Set<string> = new Set()): string[] {
  const r = spawnSync('/usr/bin/otool', ['-L', file], { encoding: 'utf8', timeout: 20_000 })
  if (r.status !== 0) return []
  const out: string[] = []
  for (const l of r.stdout.split('\n').slice(1)) {
    const m = /^\s+(\/[^ ]+) \(/.exec(l)
    if (m === null || SYSTEM.test(m[1]) || !existsSync(m[1])) continue
    const real = realpathSync(m[1])
    if (seen.has(real)) continue
    seen.add(real)
    out.push(m[1], real, ...dylibsOf(real, seen))
  }
  return [...new Set(out)]
}

// The regular files fds 0-2 are redirected to. bin/vt (outside the sandbox) resolves them with a pid-scoped lsof on ITS OWN fds and hands them in
// VT_STDIO0/1/2 (absolute paths; anything else, a pipe, a tty, /dev/null, is simply not set).
function stdioFiles(env: Readonly<Record<string, string | undefined>> = process.env): string[] {
  return ['VT_STDIO0', 'VT_STDIO1', 'VT_STDIO2'].map((k) => env[k]).filter((v): v is string => typeof v === 'string' && v.startsWith('/') && v !== '/dev/null' && !v.startsWith('/dev/'))
}

export function scopeFor(argv: readonly string[], env: Readonly<Record<string, string | undefined>>, cwd: string = process.cwd()): ReadScope {
  const realCwd = realpathSync(cwd)
  const passwdHome = realPathOf(userInfo().homedir)   // the password database's home, not $HOME (M-3)
  const cliRoot = realpathSync(dirname(dirname(dirname(fileURLToPath(import.meta.url)))))   // <tree>/cli (src/ops/scope.ts -> ..)
  const root = dirname(cliRoot)
  let release: string | null = null
  // releaseId wants a FILE inside the tree (>= 2 segments below releases/)
  try { release = releaseId(join(cliRoot, 'bin', 'vt'), vtHome(env))} catch { release = null }
  const here = (rel: string): string => join(root, rel)
  const nodeAsGiven = findTool('node', env.PATH)
  const nodeReal = realpathSync(process.execPath)
  const node = [...new Set([...(nodeAsGiven === null ? [] : chainOf(nodeAsGiven)), nodeReal, ...dylibsOf(nodeReal)])]
  return {
    tree: release !== null ? [root] : DEV_TREE_DIRS.map(here).filter(existsSync).map((p) => realpathSync(p)),
    treeFiles: release !== null ? [] : DEV_TREE_FILES.map(here).filter(existsSync),
    node,
    launcher: join(cliRoot, 'bin', 'vt'),
    stdio: [...new Set(stdioFiles(env))],
    userHome: passwdHome,
    userHomes: [...new Set([passwdHome, ...(env.HOME !== undefined && env.HOME !== '' ? [realPathOf(env.HOME)] : [])])],
    handed: handedFiles(argv).map((f) => realPathOf(resolve(realCwd, f))),
  }
}
