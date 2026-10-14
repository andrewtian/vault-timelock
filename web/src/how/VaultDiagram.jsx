import { useEffect, useMemo, useState } from 'react'

// Ported from the prototype at tag add7b-e540f8ae4d6b (src/how/VaultDiagram.jsx, tab 'vault' only).
// How 1password-timelock.sh turns a vault's entries into a sealed package — and back.
// Every value on this page is SYNTHETIC (item ids A–D, made-up JSON). No real vault is read.

const GENESIS = 1692803367 // drand quicknet genesis_time (2023-08-23T15:09:27Z)
const PERIOD = 3 // seconds per round
const roundFor = (t) => Math.floor((t - GENESIS) / PERIOD) + 1 // the script's round_for()
const iso = (s) => new Date(s * 1000).toISOString().replace('.000Z', 'Z')

// Synthetic entries, shaped like `op item get --format json --reveal` output (plaintext form, made up).
import RAW from './data/entries.json'
import { RepresentativeOutput } from './RepresentativeOutput.jsx'
const LETTERS = ['A', 'B', 'C', 'D']
export const ENTRIES = RAW.map((j, i) => ({
  id: LETTERS[i], uuid: j.id, title: j.title, cat: j.category, json: j,
  blank: j.category === 'LOGIN' && !j.fields.some((f) => f.purpose === 'PASSWORD' && f.value),
  fields: j.fields.length, sections: 0, files: j.files.length,
}))

async function sha256hex(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

// Task S1 grammar (queued): bare integer = years, else N<unit> terms in order y d h m s.
const UNIT = { y: 31556952, d: 86400, h: 3600, m: 60, s: 1 }
function durationSeconds(arg) {
  if (/^[1-9][0-9]{0,8}$/.test(arg)) return Number(arg) * UNIT.y
  const m = /^(?:([1-9][0-9]{0,8})y)?(?:([1-9][0-9]{0,8})d)?(?:([1-9][0-9]{0,8})h)?(?:([1-9][0-9]{0,8})m)?(?:([1-9][0-9]{0,8})s)?$/.exec(arg)
  if (!arg || !m) return null
  const t = ['y', 'd', 'h', 'm', 's'].reduce((a, u, i) => a + (m[i + 1] ? Number(m[i + 1]) * UNIT[u] : 0), 0)
  return t > 0 && t <= 100 * UNIT.y ? t : null
}

const TONE = {
  plain: { stroke: '#f59e0b', fill: 'rgba(245,158,11,0.10)', text: '#fcd34d' },
  enc: { stroke: '#10b981', fill: 'rgba(16,185,129,0.10)', text: '#6ee7b7' },
  meta: { stroke: '#38bdf8', fill: 'rgba(56,189,248,0.08)', text: '#7dd3fc' },
  cmd: { stroke: '#525252', fill: '#171717', text: '#e5e5e5' },
  src: { stroke: '#a78bfa', fill: 'rgba(167,139,250,0.10)', text: '#c4b5fd' },
}
const HL = '#fbbf24'

function Box({ x, y, w, h, tone = 'cmd', title, lines = [], mono = false, dashed = false, hl = false, onClick, small = false }) {
  const t = TONE[tone]
  return (
    <g onClick={onClick} style={{ cursor: onClick ? 'pointer' : 'default' }}>
      <rect x={x} y={y} width={w} height={h} rx="8" fill={t.fill} stroke={hl ? HL : t.stroke} strokeWidth={hl ? 2.5 : 1.2} strokeDasharray={dashed ? '5 4' : undefined} />
      <text x={x + 10} y={y + (small ? 18 : 21)} fill={hl ? HL : t.text} fontSize={small ? 12 : 13.5} fontWeight="600" fontFamily={mono ? 'ui-monospace, Menlo, monospace' : 'inherit'}>{title}</text>
      {lines.map((l, i) => (
        <text key={i} x={x + 10} y={y + (small ? 34 : 39) + i * 15} fill="#a3a3a3" fontSize="11.5" fontFamily={l.mono ? 'ui-monospace, Menlo, monospace' : 'inherit'}>{l.t ?? l}</text>
      ))}
    </g>
  )
}

function Arrow({ d, label, lx, ly, hl = false, dashed = false, anchor = 'middle' }) {
  return (
    <g>
      <path d={d} fill="none" stroke={hl ? HL : '#737373'} strokeWidth={hl ? 2.2 : 1.3} strokeDasharray={dashed ? '5 4' : undefined} markerEnd={hl ? 'url(#ahHL)' : 'url(#ah)'} />
      {label && <text x={lx} y={ly} fill={hl ? HL : '#a3a3a3'} fontSize="11" textAnchor={anchor} fontFamily="ui-monospace, Menlo, monospace">{label}</text>}
    </g>
  )
}

export function VaultDiagram() {
  const [sel, setSel] = useState('A')
  const [digests, setDigests] = useState({})
  const [dur, setDur] = useState('10')
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000))
  useEffect(() => { const t = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000); return () => clearInterval(t) }, [])
  useEffect(() => {
    Promise.all(ENTRIES.map(async (e) => [e.id, await sha256hex(JSON.stringify(e.json))])).then((kv) => setDigests(Object.fromEntries(kv)))
  }, [])
  const secs = durationSeconds(dur)
  const T = secs == null ? null : now + secs
  const R = T == null ? null : roundFor(T)
  const short = (h) => (h ? `${h.slice(0, 8)}…${h.slice(-4)}` : '…')

  const laneY = (i) => 115 + i * 90 // lane centre
  const params = useMemo(() => [
    ['vault', '"Personal" (synthetic, 4 entries: A–D)'],
    ['duration (typed)', dur || '—'],
    ['unlock time T (UTC)', T ? iso(T) : 'invalid duration'],
    ['drand round R', R ? String(R) : '—'],
    ['chain', 'quicknet 52db9ba7…c84e971 · period 3 s'],
    ['round formula', 'R = ⌊(T − genesis) / 3⌋ + 1'],
  ], [dur, T, R])

  return (
    <div data-testid="how-vault" className="space-y-1">
      <h2 className="text-lg font-semibold">How <span className="font-mono">1password-timelock.sh</span> seals a vault — inputs → outputs, per entry</h2>
      <p className="mb-4 text-sm text-neutral-400">Representative diagram with <b>synthetic</b> entries A–D (no real vault is read). Click an entry to follow it through the pipeline. Digests below are real SHA-256 values of the synthetic JSON.</p>

      <div className="mb-4 grid gap-3 md:grid-cols-3">
        {[
          ['① declared', '4', 'op item list --vault Personal --include-archive', 'what 1Password says the vault holds'],
          ['② captured', '4', 'MANIFEST.csv rows — count AND id set must equal ①', 'what was actually written to disk'],
          ['③ round-tripped', '4/4', 'decrypt the real ciphertext, extract, compare each sha256', 'what survives sealing — proven before the key is destroyed'],
        ].map(([k, v, cmd, why]) => (
          <div key={k} className="rounded-lg border border-neutral-800 bg-neutral-900/60 p-3">
            <div className="flex items-baseline justify-between"><span className="text-sm text-neutral-400">{k}</span><span className="font-mono text-xl text-emerald-400">{v} ✓</span></div>
            <div className="mt-1 font-mono text-xs text-neutral-300">{cmd}</div>
            <div className="text-xs text-neutral-500">{why}</div>
          </div>
        ))}
      </div>

      <div className="overflow-x-auto rounded-xl border border-neutral-800 bg-neutral-950 p-2">
        <svg viewBox="0 0 1440 1030" className="w-full min-w-[1100px]" role="img" aria-label="1password-timelock.sh pipeline diagram">
          <defs>
            <marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#737373" /></marker>
            <marker id="ahHL" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill={HL} /></marker>
          </defs>

          {/* column titles */}
          {[[20, 'INPUT · vault entries'], [318, 'CAPTURE · op item get ‹id›'], [588, 'MANIFEST · one row per entry'], [880, 'SEAL · whole vault, once'], [1200, 'OUTPUT · package directory']].map(([x, t]) => (
            <text key={t} x={x} y="52" fill="#d4d4d4" fontSize="12.5" fontWeight="700" letterSpacing="0.06em">{t}</text>
          ))}

          {/* vault container + entries */}
          <rect x="20" y="70" width="230" height="358" rx="10" fill="rgba(167,139,250,0.05)" stroke="#a78bfa" strokeDasharray="4 4" />
          {ENTRIES.map((e, i) => {
            const y = laneY(i), on = sel === e.id
            return (
              <g key={e.id}>
                <Box x={32} y={y - 34} w={196} h={68} tone="src" hl={on} onClick={() => setSel(e.id)}
                  title={`item ${e.id} · ${e.cat}`}
                  lines={[`${e.fields} field(s) · ${e.files} file(s)${e.blank ? ' · no password' : ''}`, 'title/URL/user: never printed']} />
                <Arrow d={`M228,${y} L316,${y}`} hl={on} label="--reveal" lx={286} ly={y - 8} />
                <Box x={318} y={y - 34} w={214} h={68} tone="plain" hl={on} mono
                  title={`items/${e.id}.json`}
                  lines={e.files ? [`+ files/${e.id}/${e.json.files[0].id}  (${e.cat === 'DOCUMENT' ? 'document' : 'attachment'})`, 'plaintext, exists for seconds'] : ['every field value, revealed', 'plaintext, exists for seconds']} />
                <Arrow d={`M532,${y} L586,${y}`} hl={on} label="sha256" lx={559} ly={y - 8} />
                <Box x={588} y={y - 34} w={262} h={68} tone="meta" hl={on} mono small
                  title={`${e.id},${short(digests[e.id])},${e.fields},${e.sections},${e.files}`}
                  lines={['uuid, sha256, fields, sections, files', e.blank ? { t: '→ also listed in BLANK-AT-SEAL.txt' } : 'no titles, no values']} />
                <Arrow d={`M850,${y} L878,${y}`} hl={on} />
              </g>
            )
          })}
          <text x="135" y="446" fill="#a78bfa" fontSize="11" textAnchor="middle">1Password vault "Personal" (synthetic)</text>

          {/* checks between capture and seal */}
          <rect x="318" y="448" width="532" height="110" rx="8" fill="#0a0a0a" stroke="#404040" />
          <text x="330" y="470" fill="#d4d4d4" fontSize="12.5" fontWeight="700">Refuse-to-seal checks (fail closed)</text>
          {['① = ② by count, and every declared id is in the manifest', 'ALL items blank / ALL concealed fields empty → refuse (= --reveal did not work)', 'some blanks (like C) are data, not failure → reported by UUID', 'an item with 0 fields AND 0 files is hollow → refuse'].map((t, i) => (
            <text key={t} x="332" y={492 + i * 17} fill="#a3a3a3" fontSize="11.5">· {t}</text>
          ))}

          {/* tar bar */}
          <rect x="880" y="78" width="34" height="345" rx="6" fill="#171717" stroke="#525252" />
          <text transform="translate(902,250) rotate(-90)" fill="#e5e5e5" fontSize="12" textAnchor="middle" fontFamily="ui-monospace, Menlo, monospace">tar czf  items/  files/  MANIFEST.csv</text>

          {/* seal column */}
          <Box x={950} y={218} w={210} h={64} tone="enc" title="age -r ‹data recipient›" lines={['ONE encryption for all entries']} hl={!!sel} />
          <Arrow d="M914,250 L948,250" hl={!!sel} />
          <Box x={950} y={330} w={210} h={64} tone="plain" mono title="identity.key" lines={['age-keygen: fresh X25519 data key', 'never stored in the clear']} />
          <Arrow d="M1055,330 L1055,284" label="recipient age1…" lx={1062} ly={312} anchor="start" />
          <Box x={950} y={440} w={210} h={64} tone="cmd" mono title="tle --encrypt --round=R" lines={['data key → drand round R']} />
          <Arrow d="M1055,394 L1055,438" />
          <Box x={950} y={540} w={210} h={64} tone="cmd" mono dashed title="age -r ‹your age1…›" lines={['optional --recovery-recipient']} />
          <Arrow d="M950,362 L932,362 L932,572 L948,572" dashed />

          <Box x={588} y={580} w={292} h={86} tone="src" title="drand quicknet (League of Entropy)"
            lines={['BLS signature every 3 s; the key for round R', 'does not exist until round R is signed', 'T = now + DURATION;  R = ⌊(T − genesis)/3⌋ + 1']} />
          <Arrow d="M880,600 L948,486" dashed label="round R" lx={925} ly={560} />

          {/* package column */}
          <rect x="1190" y="70" width="240" height="700" rx="10" fill="rgba(16,185,129,0.03)" stroke="#10b981" strokeDasharray="4 4" />
          <text x="1198" y="764" fill="#6ee7b7" fontSize="9.5" fontFamily="ui-monospace, Menlo, monospace">$OUT/1password-Personal-timelock-‹UTC›/</text>
          <Box x={1200} y={88} w={220} h={56} tone="meta" mono small title="MANIFEST.csv" lines={['UUIDs + digests; no values', 'verify completeness unopened']} hl={!!sel} />
          <Arrow d="M719,81 L719,74 L1180,74 L1180,110 L1198,110" dashed label="copied outside the seal" lx={1000} ly={68} hl={!!sel} />
          <Box x={1200} y={222} w={220} h={56} tone="enc" mono small title="vault.tar.gz.age" lines={['every entry, one ciphertext']} hl={!!sel} />
          <Arrow d="M1160,250 L1198,250" hl={!!sel} />
          <Box x={1200} y={300} w={220} h={56} tone="meta" mono small title="BLANK-AT-SEAL.txt" lines={['UUIDs blank at seal time: C', '(only if any)']} hl={sel === 'C'} />
          <Box x={1200} y={444} w={220} h={56} tone="enc" mono small title="unlock-TIME.age" lines={['data key, sealed to round R']} />
          <Arrow d="M1160,472 L1198,472" />
          <Box x={1200} y={544} w={220} h={56} tone="enc" mono small dashed title="unlock-KEY.age" lines={['data key to your key (optional)']} />
          <Arrow d="M1160,572 L1198,572" dashed />
          <Box x={1200} y={620} w={220} h={64} tone="meta" mono small title="round · chain-info · README" lines={['R, drand chain params,', 'how to open (both paths)']} />
          <Box x={1200} y={694} w={220} h={56} tone="meta" mono small dashed title="SEALED.txt (at seal time)" lines={['self-contained: info + open steps', '+ both files as armored age']} hl={!!sel} />

          {/* proof strip */}
          <rect x="20" y="790" width="1410" height="70" rx="8" fill="rgba(16,185,129,0.06)" stroke="#10b981" />
          <text x="34" y="814" fill="#6ee7b7" fontSize="12.5" fontWeight="700">Before identity.key is destroyed (any failure = refuse, nothing shipped):</text>
          <text x="34" y="834" fill="#a3a3a3" fontSize="11.5">✓ round-trip: decrypt vault.tar.gz.age with the real data key, extract, every items/‹id›.json sha256 = MANIFEST   ✓ unlock-TIME.age does NOT open now   ✓ vault.tar.gz.age does not open without a key</text>
          <text x="34" y="850" fill="#a3a3a3" fontSize="11.5">→ only then is the 0700 temp dir (items/, files/, identity.key) overwritten and removed</text>

          {/* open band */}
          <text x="20" y="886" fill="#d4d4d4" fontSize="12.5" fontWeight="700" letterSpacing="0.06em">OPEN · after round R (TIME path) — or any time with your recovery key (KEY path)</text>
          <Box x={20} y={900} w={210} h={56} tone="src" small title="drand signs round R" lines={['(at T; anyone can fetch it)']} />
          <Arrow d="M230,928 L258,928" />
          <Box x={260} y={900} w={220} h={56} tone="cmd" mono small title="tle --decrypt" lines={['unlock-TIME.age → identity.key']} />
          <Arrow d="M480,928 L508,928" />
          <Box x={510} y={900} w={150} h={56} tone="plain" mono small title="identity.key" lines={['the data key']} />
          <Arrow d="M660,928 L688,928" />
          <Box x={690} y={900} w={220} h={56} tone="cmd" mono small title="age -d vault.tar.gz.age" lines={['→ tar xzf → restored/']} />
          <Arrow d="M910,928 L938,928" hl={!!sel} />
          <Box x={940} y={900} w={200} h={56} tone="plain" mono small title={`restored/items/${sel}.json`} lines={['all entries come back together']} hl />
          <Arrow d="M1140,928 L1168,928" hl />
          <Box x={1170} y={900} w={260} h={56} tone="meta" mono small hl
            title={`sha256 vs MANIFEST: ${ENTRIES.map((e) => `${e.id}✓`).join(' ')}`} lines={['any mismatch → "NOT intact", refuse']} />
          <Box x={260} y={968} w={400} h={50} tone="cmd" mono small dashed title="KEY path: age -d -i recovery.key unlock-KEY.age" lines={['→ identity.key (works before round R)']} />
          <Arrow d="M585,968 L585,958" dashed />
        </svg>
      </div>

      <RepresentativeOutput entries={ENTRIES} sel={sel} setSel={setSel} digests={digests} />

      <div className="mt-4 grid gap-4 md:grid-cols-[1fr_420px]">
        <div className="space-y-3 text-sm text-neutral-300">
          <h2 className="font-semibold text-neutral-100">How each entry is timelocked</h2>
          <p><b>Entries are not locked one by one.</b> Each entry is captured separately (<span className="font-mono">op item get &lt;id&gt; --reveal</span> → <span className="font-mono">items/&lt;id&gt;.json</span>, attachments via <span className="font-mono">op document get</span>) and gets its own manifest row (UUID + SHA-256 + field/section/file counts). Then the <b>whole vault</b> is archived and encrypted <b>once</b> with a fresh age data key.</p>
          <p><b>The time lock is on the data key, not on the data.</b> <span className="font-mono">tle</span> encrypts the 1-line data key to drand round R. Nobody — including you — can decrypt it until the League of Entropy publishes round R’s signature at time T. Optionally the same data key is also encrypted to your own age key (KEY path), which opens at any time.</p>
          <p><b>So every entry unlocks at the same moment</b>, together. The per-entry evidence is the manifest row, kept <i>outside</i> the seal: it lets anyone check completeness (count, ids, digests) without opening anything, and <span className="font-mono">open</span> re-checks every entry’s digest on the way out.</p>
          <p className="text-neutral-400">Never emitted anywhere: titles, usernames, passwords, URLs, notes, TOTP seeds, file names — only counts, UUIDs and digests.</p>
        </div>
        <div className="rounded-lg border border-neutral-800 p-3">
          <div className="mb-2 flex items-center gap-2">
            <label className="text-sm text-neutral-400" htmlFor="dur">duration</label>
            <input id="dur" value={dur} onChange={(e) => setDur(e.target.value.trim())} className="w-32 rounded border border-neutral-700 bg-neutral-900 px-2 py-1 font-mono text-sm" />
            <span className="text-xs text-neutral-500">10 · 30d · 1h · 40m · 365d · 1y30d</span>
          </div>
          <table className="w-full text-sm"><tbody>
            {params.map(([k, v]) => (<tr key={k} className="border-b border-neutral-800"><td className="py-1 pr-3 text-neutral-400">{k}</td><td className={`py-1 font-mono ${v === 'invalid duration' ? 'text-red-400' : ''}`}>{v}</td></tr>))}
          </tbody></table>
          <p className="mt-2 text-xs text-neutral-500">Today the script takes whole years (default 10). Unit durations (30d, 1h, 40m…) arrive with Task S1.</p>
          <div className="mt-3 flex flex-wrap gap-3 text-xs">
            {[['plain', 'plaintext (temp dir only)'], ['enc', 'encrypted'], ['meta', 'public-safe metadata'], ['src', 'source / drand'], ['cmd', 'command']].map(([k, t]) => (
              <span key={k} className="flex items-center gap-1"><span className="inline-block h-3 w-3 rounded-sm" style={{ background: TONE[k].fill, border: `1px solid ${TONE[k].stroke}` }} />{t}</span>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
