// api/src/stacks.ts — which network stacks run (spec §3.4, R71): the page server's GET /__stacks.
//
// readStacks(home) answers one entry per network, in NETWORKS order:
//   { network, up, pageUrl: 'http://127.0.0.1:<PORTS[network].page>/', build }
// `vt up` writes <home>/<network>/up.json (0600) = { network, pagePort, build, startedAt }; `vt down` removes it. An
// entry is up only when that file is a regular file of at most 4 KiB holding a JSON object whose network is this
// network, whose pagePort is this network's page port, whose build is a build id and whose startedAt is a positive
// integer. Anything else (missing, unreadable, a symlink, a FIFO, garbage, another network's file) is `up: false`.
// pageUrl always comes from PORTS, never from the file, so the selector (W1 safePageUrl) only ever navigates to a
// loopback page origin.
//
// It never reads outside <home>/<network>/up.json: it touches exactly <home>/<network> (lstat: a real directory, not a
// symlink) and <home>/<network>/up.json (opened O_NOFOLLOW | O_NONBLOCK, then fstat), for the three network names only.
// No directory is listed. A relative home reads nothing.
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs'
import { isAbsolute, join, normalize } from 'node:path'
import { NETWORKS, PORTS } from '@vault-timelock/core/contracts'
import type { Network, StackInfo } from '@vault-timelock/core/contracts'

export const UP_JSON = 'up.json'
const MAX_UP_JSON = 4096
const BUILD = /^[A-Za-z0-9._-]{1,64}$/
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

// The file system calls readStacks makes (injectable so a test can record every path).
export interface StacksIo {
  isRealDir(path: string): boolean
  readSmallFile(path: string, max: number): string | null
}

export const nodeStacksIo: StacksIo = {
  isRealDir(path) {
    try {
      const st = lstatSync(path)
      return st.isDirectory() && !st.isSymbolicLink()
    } catch {
      return false
    }
  },
  readSmallFile(path, max) {
    let fd = -1
    try {
      fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
      const st = fstatSync(fd)
      if (!st.isFile() || st.size > max) return null
      const buf = Buffer.alloc(st.size)
      let n = 0
      while (n < buf.length) {
        const got = readSync(fd, buf, n, buf.length - n, n)
        if (got === 0) break
        n += got
      }
      return n === buf.length ? UTF8.decode(buf) : null
    } catch {
      return null
    } finally {
      if (fd >= 0) closeSync(fd)
    }
  },
}

export const pageUrlOf = (network: Network): string => `http://127.0.0.1:${PORTS[network].page}/`

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)

// The build of a well-formed up.json for `network`, or null.
export function upBuild(network: Network, text: string | null): string | null {
  if (text === null) return null
  let v: unknown
  try { v = JSON.parse(text) } catch { return null }
  if (!isPlainObject(v)) return null
  const ok = v.network === network && v.pagePort === PORTS[network].page
    && typeof v.build === 'string' && BUILD.test(v.build)
    && Number.isSafeInteger(v.startedAt) && (v.startedAt as number) > 0
  return ok ? v.build as string : null
}

export function readStacks(home: string, io: StacksIo = nodeStacksIo): StackInfo[] {
  const usable = typeof home === 'string' && isAbsolute(home) && normalize(home) === home && !home.includes('\0')
  return NETWORKS.map((network) => {
    let build: string | null = null
    if (usable) {
      const dir = join(home, network)
      if (io.isRealDir(dir)) build = upBuild(network, io.readSmallFile(join(dir, UP_JSON), MAX_UP_JSON))
    }
    return { network, up: build !== null, pageUrl: pageUrlOf(network), build }
  })
}
