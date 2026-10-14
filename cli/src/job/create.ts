// cli/src/job/create.ts — `vt job create <file> [--message-file <path>] [--yes-publish-file <sha256>] [--normalize]
// [--json]` (spec §3.3 step 1, §4.1, §8; plan Task C5; security review: message file).
//   1. loadJobFile (validate.ts): the job file, and its message: inline, by digest, or --message-file <path> FROM THE
//      COMMAND LINE ONLY (message-file.ts: realpath, regular file, the denylist of keys, vault data and vt state; a job
//      JSON naming a file is refused), decoded strictly, checked by core normalizeJob / validateMessage (refused, never
//      rewritten; --normalize is the operator's explicit exception, summarised), for this network (job.network).
//   2. A message FILE is published permanently, so the operator confirms THAT file first (vt.publish-confirm): vt
//      prints its real path, size, sha256 and escaped first line, then
//      · at a terminal: the word `publish` typed (readTypedWord: /dev/tty only, never stdin, argv or the environment);
//      · otherwise: --yes-publish-file <sha256> naming exactly the digest of the bytes to be uploaded (after
//        --normalize, the normalized text's). Without either, nothing is uploaded.
//   3. PUT /messages/<sha256> with the text's exact bytes (message.*). The API's answer must name the same digest and
//      size (message.digest).
//   4. POST /jobs with the CANONICAL definition (messageSha256 + messageBytes, never the text: POST bodies are capped at
//      64 KiB and the text may be 16 MiB). 201 = created, 200 = the identical job already exists. The id the API
//      answers must be the one vt computed (jobId of the canonical definition).
// The text never appears in argv (vt is given a path) and never in a JSON body.
import type { JobDef, JobState } from '@vault-timelock/core/contracts'
import { refuse } from '@vault-timelock/core/contracts'
import { sha256Hex } from '@vault-timelock/core/job'
import { UsageError } from '../args.ts'
import type { JobIo } from './client.ts'
import { apiClient, emitJson, parseFlags, printLines } from './client.ts'
import { assertDigest, describeDef, describeFile, loadJobFile, summaryLine } from './validate.ts'

const USAGE = 'usage: vt job create <file> [--message-file <path>] [--yes-publish-file <sha256>] [--normalize] [--json]'
const SHA256 = /^[0-9a-f]{64}$/

function assertPublish(ok: boolean, why: string): void {
  if (!ok) refuse('vt.publish-confirm', why) // @guard:vt.publish-confirm
}

export async function createCommand(args: readonly string[], io: JobIo): Promise<number> {
  const { flags, pos } = parseFlags(args, { valued: ['--message-file', '--yes-publish-file'], bool: ['--normalize', '--json'], usage: USAGE })
  if (pos.length !== 1) throw new UsageError(USAGE)
  const mf = flags.get('--message-file')
  const yes = flags.get('--yes-publish-file')
  if (yes !== undefined && (typeof yes !== 'string' || !SHA256.test(yes))) throw new UsageError(`${USAGE} (--yes-publish-file: the 64 lowercase hex sha256 vt shows for the file)`)
  if (yes !== undefined && mf === undefined) throw new UsageError('--yes-publish-file confirms a --message-file; there is none')
  const j = loadJobFile(pos[0], { network: io.network, normalize: flags.has('--normalize'), messageFile: typeof mf === 'string' ? mf : null, env: io.env, cwd: io.cwd })
  if (j.normalized !== null) printLines(io, summaryLine(j.normalized), true)
  for (const w of j.warnings) printLines(io, `warning: ${w}`, true)
  if (j.file !== null) {
    // The file is about to be published permanently: the operator confirms exactly these bytes.
    printLines(io, `${describeFile(j)}\nthis file will be uploaded and PUBLISHED, permanently and publicly, when the job runs`, true)
    if (typeof yes === 'string') {
      assertPublish(yes === j.def.messageSha256, 'the --yes-publish-file digest is not the sha256 of this file\'s text; nothing was uploaded')
    } else {
      const w = await io.ask(`Type publish to upload this file (${j.bytes!.length} bytes, sha256 ${j.def.messageSha256.slice(0, 16)}…) for publication: `, 'publish')
      assertPublish(w !== undefined, 'publishing a file needs the word publish typed at a terminal, or --yes-publish-file <sha256> naming its exact digest; nothing was uploaded')
      assertPublish(w === 'publish', 'the typed word was not publish; nothing was uploaded')
    }
  }

  const api = apiClient(io)
  if (j.bytes !== null) {
    // The bytes sent are the ones confirmed: hashed again right before the upload (they were read once, from a verified
    // descriptor, and the path is never opened again).
    assertDigest(sha256Hex(j.bytes) === j.def.messageSha256 && j.bytes.length === j.def.messageBytes, 'the bytes to upload are not the confirmed ones; nothing was uploaded')
    const up = (await api.putMessage(j.def.messageSha256, j.bytes)).value as { sha256?: unknown; bytes?: unknown }
    assertDigest(up?.sha256 === j.def.messageSha256 && up?.bytes === j.def.messageBytes,
      'the jobs API stored the upload under another digest or size than the text vt sent; the job was not created')
  }
  const r = await api.json<{ id: string; def: JobDef; state: JobState }>('POST', '/jobs', j.def)
  if (r.value?.id !== j.id) throw new Error('the jobs API answered another job id than the definition\'s (nothing else was done)')
  if (flags.has('--json')) {
    emitJson(io, r.text)
    return 0
  }
  const phases = Object.entries(r.value.state?.chains ?? {}).map(([c, s]) => `${c} ${s?.phase ?? '?'}`).join(', ')
  printLines(io, [
    describeDef(j.id, j.def),
    `${j.bytes === null ? 'message: already uploaded (by digest)' : 'message: uploaded by digest'}`,
    `job ${j.id}: ${r.status === 201 ? 'created' : 'already exists (the identical definition)'}; ${r.value.state?.phase ?? '?'} (${phases})`,
    'next: load each chain\'s key in an executor (vt job run, or the page), fund it, then vt job arm ' + j.id,
  ].join('\n'))
  return 0
}
