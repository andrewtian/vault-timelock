// Reassembling a multi-part message BY HAND (W4; spec §15, carry-forward 4). One command per chain, from the vt-parts/1
// reader rules (core contracts/parts.ts): accept parts only from the publishing address; part 1 of N carries
// `sha256=<64hex>`; strip exactly the header line; join the chunks by index k; check sha256(result) against part 1's
// digest (and the job's own digest, embedded here). Raw calldata / memo bytes are read, never an indexer's decoded text.
// The scripts are plain python3 (run with -I so no local module is imported). They hold no URL, endpoint or key: the
// operator's node comes from $ETH_RPC_URL / $SOL_RPC_URL (mainnet: over Tor).
import { SOL } from '@vault-timelock/core/chains/constants.js'
import { PART_FORMAT } from '@vault-timelock/core/contracts'

// Shared body: parse the header, group, check, print. `texts()` below is set by each chain's reader.
const COMMON = String.raw`
import sys, re, json, hashlib
EXPECT, SIGNER = sys.argv[1], sys.argv[2].lower()
HDR = re.compile(r"\[([1-9][0-9]{0,8})/([1-9][0-9]{0,8}) ([0-9a-f]{8})(?: sha256=([0-9a-f]{64}))?\](?: \[copy [^\]]*\])?\n")
def objs(s):
    d, i = json.JSONDecoder(), 0
    while True:
        while i < len(s) and s[i].isspace(): i += 1
        if i >= len(s): return
        o, i = d.raw_decode(s, i); yield o
def finish(texts):
    parts, n, sha = {}, None, None
    for t in texts:
        m = HDR.match(t)
        if not m: sys.exit("a part has no vt-parts/1 header (a one-part message is plain text: its sha256 must equal " + EXPECT + ")")
        k, N, body = int(m[1]), int(m[2]), t[m.end():]
        n = N if n is None else n
        if N != n: sys.exit("parts disagree on N")
        if k in parts and parts[k] != body: sys.exit("two different payloads for part %d" % k)
        parts[k] = body
        if k == 1: sha = m[4]
    if n is None or sorted(parts) != list(range(1, n + 1)): sys.exit("missing parts: have %s of %s" % (sorted(parts), n))
    text = "".join(parts[k] for k in range(1, n + 1))
    got = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if sha is None or got != sha or got != EXPECT: sys.exit("sha256 MISMATCH: got " + got)
    sys.stdout.write(text); sys.stderr.write("\nreassembled OK sha256 " + got + "\n")
`
const ETH_READ = String.raw`
texts = []
for o in objs(sys.stdin.read()):
    if str(o.get("from", "")).lower() != SIGNER: sys.exit("a part was not sent by the publishing address")
    h = o["input"][2:] if o["input"][:2] == "0x" else o["input"]
    t = bytes.fromhex(h).decode("utf-8")
    texts.append(t[6:] if t.startswith("data:,") else t)
finish(texts)
`
const SOL_READ = String.raw`
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58(s):
    n = 0
    for c in s: n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(s) - len(s.lstrip("1"))) + raw
texts = []
for o in objs(sys.stdin.read()):
    m = o["result"]["transaction"]["message"]; keys = m["accountKeys"]
    if keys[0].lower() != SIGNER: sys.exit("a part was not paid by the publishing address")
    for ins in m["instructions"]:
        if keys[ins["programIdIndex"]] == "${SOL.MEMO_PROGRAM}": texts.append(b58(ins["data"]).decode("utf-8"))
finish(texts)
`
export const ETH_SCRIPT = COMMON + ETH_READ
export const SOL_SCRIPT = COMMON + SOL_READ

// The landed ids of ONE copy in part order (the first copy that has every part landed, else the first copy with any).
export function copyIds(txs) {
  const by = new Map()
  for (const t of txs) {
    if (t.state !== 'included' || !t.landedId) continue
    const c = by.get(t.copy) || { copy: t.copy, parts: t.parts, ids: new Map() }
    c.ids.set(t.part, t.landedId)
    by.set(t.copy, c)
  }
  const all = [...by.values()].sort((a, b) => a.copy - b.copy)
  const pick = all.find((c) => c.ids.size === c.parts) || all[0]
  return pick ? { copy: pick.copy, parts: pick.parts, complete: pick.ids.size === pick.parts, ids: [...pick.ids.entries()].sort((a, b) => a[0] - b[0]).map(([, id]) => id) } : null
}

const sq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`

// → { format, copy, parts, complete, idsFile, file, command, note } or null when no part has landed.
export function handReassembly({ chain, txs, signer, messageSha256, network }) {
  const pick = copyIds(txs)
  if (!pick) return null
  const idsFile = pick.ids.join('\n') + '\n'
  const file = chain === 'eth' ? 'eth-txids.txt' : 'sol-signatures.txt'
  const read = chain === 'eth'
    ? `while read -r t; do cast tx "$t" --json; done < ${file}`
    : `while read -r s; do curl -s -H 'content-type: application/json' --data "{\\"jsonrpc\\":\\"2.0\\",\\"id\\":1,\\"method\\":\\"getTransaction\\",\\"params\\":[\\"$s\\",{\\"encoding\\":\\"json\\",\\"maxSupportedTransactionVersion\\":0}]}" "$SOL_RPC_URL"; echo; done < ${file}`
  const command = `${read} | python3 -I -c ${sq(chain === 'eth' ? ETH_SCRIPT : SOL_SCRIPT)} ${messageSha256} ${signer}`
  const node = chain === 'eth' ? '$ETH_RPC_URL (read by cast)' : '$SOL_RPC_URL'
  return {
    format: PART_FORMAT, copy: pick.copy, parts: pick.parts, complete: pick.complete, idsFile, file, command,
    note: `Set ${node} to a node of the ${network} network${network === 'mainnet' ? ' reached over Tor' : ''}. Copy ${pick.copy}, ${pick.ids.length} of ${pick.parts} part(s) landed${pick.complete ? '' : ' (incomplete: the command will say which parts are missing)'}.`,
  }
}
