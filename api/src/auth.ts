// api/src/auth.ts — the API's two secrets and the bearer-token check.
//
// `vt up` writes <VT_HOME>/<network>/api.token (64 hex) and relay-ticket.key (64 hex = 32 bytes), both 0600, before
// each API start. The API refuses to start without either (api.token-missing): a symlink, a non-regular file, a file
// readable by group or others, or anything but 64 lowercase hex (one trailing newline allowed) counts as missing.
// Refusals never name the absolute path (it holds the account name) and never echo file contents.
//
// The token check compares `Authorization: Bearer <token>` with timingSafeEqual on equal-length buffers; a header of
// another length is refused without comparing. A token that is not 64 hex never authorizes anything (fail closed).
import { closeSync, constants, fstatSync, openSync, readFileSync } from 'node:fs'
import { timingSafeEqual } from 'node:crypto'
import { refuse } from 'vt-broadcast/src/guard.ts'

const HEX64 = /^[0-9a-f]{64}$/
const MAX_SECRET_FILE = 4096

function readPrivateText(file: string): string | null {
  let fd = -1
  try {
    fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW)
    const st = fstatSync(fd)
    if (!st.isFile() || (st.mode & 0o077) !== 0 || st.size > MAX_SECRET_FILE) return null
    return readFileSync(fd, 'utf8')
  } catch {
    return null
  } finally {
    if (fd >= 0) closeSync(fd)
  }
}

// The 64-hex secret in `file` (api.token or relay-ticket.key), or a refusal.
export function readSecretHex(file: string): string {
  const text = readPrivateText(file)
  const value = text === null ? '' : text.endsWith('\n') ? text.slice(0, -1) : text
  const ok = HEX64.test(value)
  if (!ok) refuse('api.token-missing', 'api.token or relay-ticket.key is missing, not a private (0600) regular file, or not 64 hex: run vt up') // @guard:api.token-missing
  return value
}

// True only for exactly `Bearer <token>` with a well-formed configured token.
export function bearerMatches(header: string | undefined, token: string): boolean {
  if (!HEX64.test(token) || typeof header !== 'string') return false
  const got = Buffer.from(header, 'utf8')
  const want = Buffer.from(`Bearer ${token}`, 'utf8')
  return got.length === want.length && timingSafeEqual(got, want)
}

// `header`: the request's single Authorization value (undefined when absent or repeated).
export function assertToken(header: string | undefined, token: string): void {
  const ok = bearerMatches(header, token)
  if (!ok) refuse('api.token', 'missing or wrong API token') // @guard:api.token
}
