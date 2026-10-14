// The single-instance lock api.lock: a second instance → api.already-running; a stale pid lock is taken over.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { pidAlive, takeLock } from '../src/lock.ts'
import { tempDir } from './helpers.ts'

const refusalOf = (fn: () => unknown): string => {
  try { fn() } catch (e) { return (e as { guardId: string }).guardId }
  assert.fail('expected a refusal')
}
function lockFile(t: { after(fn: () => void): void }): { dir: string; file: string } {
  const { dir, cleanup } = tempDir('vt-api-lock-')
  t.after(cleanup)
  return { dir, file: join(dir, 'api.lock') }
}
// The pid of a process that has exited (and been reaped).
function deadPid(): number {
  const r = spawnSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'], { encoding: 'utf8', env: { PATH: process.env.PATH ?? '' } })
  const pid = Number(r.stdout)
  assert.ok(Number.isInteger(pid) && pid > 0)
  assert.equal(pidAlive(pid), false)
  return pid
}

test('take: api.lock holds "<pid>\\n", mode 0600, no temp file left; release removes it', (t) => {
  const { dir, file } = lockFile(t)
  const lock = takeLock(file)
  assert.equal(readFileSync(file, 'utf8'), `${process.pid}\n`)
  assert.equal(statSync(file).mode & 0o777, 0o600)
  assert.deepEqual(readdirSync(dir), ['api.lock'])
  lock.release()
  assert.equal(existsSync(file), false)
  takeLock(file).release() // free again
})

test('a second instance (this process) → api.already-running; the first keeps its lock', (t) => {
  const { dir, file } = lockFile(t)
  const lock = takeLock(file)
  assert.equal(refusalOf(() => takeLock(file)), 'api.already-running')
  assert.equal(readFileSync(file, 'utf8'), `${process.pid}\n`)
  assert.deepEqual(readdirSync(dir), ['api.lock'])
  lock.release()
})

test('a lock held by another live process → api.already-running', async (t) => {
  const { file } = lockFile(t)
  const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 30000)'], { stdio: 'ignore', env: { PATH: process.env.PATH ?? '' } })
  t.after(() => { child.kill('SIGKILL') }) // by its recorded pid, never by pattern
  assert.ok(child.pid !== undefined && pidAlive(child.pid))
  writeFileSync(file, `${child.pid}\n`, { mode: 0o600 })
  assert.equal(refusalOf(() => takeLock(file)), 'api.already-running')
  assert.equal(readFileSync(file, 'utf8'), `${child.pid}\n`)
})

test('a stale pid lock (the process is gone) is taken over', (t) => {
  const { dir, file } = lockFile(t)
  writeFileSync(file, `${deadPid()}\n`, { mode: 0o600 })
  const lock = takeLock(file)
  assert.equal(readFileSync(file, 'utf8'), `${process.pid}\n`)
  assert.deepEqual(readdirSync(dir), ['api.lock'])
  lock.release()
})

test('a lock that is not a pid (garbage, empty) is stale too', (t) => {
  const { file } = lockFile(t)
  for (const junk of ['', 'garbage', '0\n', '-5\n', `${process.pid}`]) {
    writeFileSync(file, junk, { mode: 0o600 })
    const lock = takeLock(file)
    assert.equal(readFileSync(file, 'utf8'), `${process.pid}\n`, JSON.stringify(junk))
    lock.release()
  }
})

test('release leaves a lock that is no longer ours alone', (t) => {
  const { file } = lockFile(t)
  const lock = takeLock(file)
  writeFileSync(file, '12345\n')
  lock.release()
  assert.equal(readFileSync(file, 'utf8'), '12345\n')
})
