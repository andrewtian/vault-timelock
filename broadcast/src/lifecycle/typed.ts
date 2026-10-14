// Typed confirmation words (spec B §6.4/§6.6: a mainnet record's `clear` and `resolve`; later `release`'s
// `broadcast`) are read from /dev/tty ONLY: never stdin, argv or the environment, so a pipe, a script or a cron job
// can't supply one. No controlling terminal (a detached process, CI) returns undefined, and the caller's own guard
// refuses (for the trigger latch: trigger.clear-typed). The word is not a secret: the terminal echoes it as usual
// (cooked mode, so line editing and Ctrl-C work). End of input (Ctrl-D) also returns undefined.
import { closeSync, constants, openSync, writeSync } from 'node:fs'
import { isatty, ReadStream } from 'node:tty'

const MAX_LINE = 256

export async function readTypedWord(prompt: string, ttyPath = '/dev/tty'): Promise<string | undefined> {
  let fd: number
  try { fd = openSync(ttyPath, constants.O_RDWR | constants.O_NOCTTY) } catch { return undefined } // ENXIO: no terminal
  if (!isatty(fd)) { closeSync(fd); return undefined }
  let wfd: number
  try { wfd = openSync(ttyPath, constants.O_WRONLY | constants.O_NOCTTY) } catch (e) { closeSync(fd); throw e }
  let rs: ReadStream
  try { rs = new ReadStream(fd) } catch (e) { closeSync(fd); closeSync(wfd); throw e }
  try {
    writeSync(wfd, prompt)
    return await new Promise<string | undefined>((resolve) => {
      let buf = Buffer.alloc(0)
      rs.on('data', (chunk: Buffer) => {
        buf = Buffer.concat([buf, chunk])
        const end = buf.findIndex((b) => b === 0x0a || b === 0x0d)
        if (end >= 0) resolve(buf.subarray(0, end).toString('utf8').trim())
        else if (buf.length > MAX_LINE) resolve(undefined)
      })
      for (const ev of ['end', 'close', 'error']) rs.on(ev, () => resolve(undefined))
    })
  } finally {
    rs.destroy() // closes fd
    closeSync(wfd)
  }
}
