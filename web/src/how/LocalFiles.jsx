// STRUCTURE.txt and SEALED-plaintext.txt: the two LOCAL-ONLY text files of a sealed package. Explainer only; this page
// shows no real content. The sample lines are SYNTHETIC (made-up ids) and abridged from the formats written by
// 1password-timelock.sh (STRUCT_JQ, vault-timelock-plaintext/1). Neither file is ever published or put in SEALED.txt.
const STRUCTURE_SAMPLE = `== vault-timelock structure: shape only, every value removed (LOCAL ONLY, never published) ==
format: vault-timelock-structure/1
binds-to: vault.tar.gz.age sha256=<64 hex>   (valid for this archive only)
totals: 2 items, 2 fields, 0 sections, ...

item 1  LOGIN  items/a1b2c3.json
  title          <set>
  field username     STRING     purpose=USERNAME   <set>
  field password     CONCEALED  purpose=PASSWORD   <set>
  urls           1 (1 primary)
  tags           0

item 2  DOCUMENT  items/d4e5f6.json
  title          <set>
  urls           0 (0 primary)
  tags           0
  file           document   files/d4e5f6/g7h8i9

== end ==`
const PLAINTEXT_SAMPLE = `== vault-timelock plaintext: every entry, decrypted (LOCAL ONLY — contains secrets) ==
format: vault-timelock-plaintext/1
[item 1] LOGIN  Example Mail (synthetic)
  username : alice@example.com
  password : synthetic-correct-horse-battery
== end (2 items, 1 files) ==`

function Card({ id, title, tone, children, sample }) {
  return (
    <div data-testid={id} className={`space-y-2 rounded-lg border p-3 text-sm ${tone}`}>
      <h3 className="font-semibold text-neutral-100">{title}</h3>
      <div className="space-y-1.5 text-neutral-300">{children}</div>
      <pre className="overflow-auto rounded border border-neutral-700 bg-neutral-900 p-2 font-mono text-[11px] leading-4 text-neutral-300" aria-label={`${title} synthetic sample`}>{sample}</pre>
    </div>
  )
}

export function LocalFiles() {
  return (
    <section data-testid="how-files" className="space-y-4">
      <p data-testid="files-local-only" className="rounded border border-rose-600/60 bg-rose-500/5 p-2 text-sm text-rose-200">
        Both files are <b>local only</b>. They are never published, never part of SEALED.txt, and never sent anywhere. Keep them mode 600 on your own disk.
      </p>
      <div className="grid gap-4 md:grid-cols-2">
        <Card id="file-structure" title="STRUCTURE.txt: the vault's shape, every value removed" tone="border-sky-500/50 bg-sky-500/5" sample={STRUCTURE_SAMPLE}>
          <p>Written by <span className="font-mono">seal</span> beside the package, after the round-trip proof. It says what the vault <i>holds</i> without saying what it <i>says</i>.</p>
          <p>Built from an allowlist, never by redaction: only a category and field type from the documented lists (else OTHER), whether a title or value exists (<span className="font-mono">&lt;set&gt;</span> or <span className="font-mono">&lt;empty&gt;</span>), counts of fields, sections, URLs and tags, and per file whether it is a document or attachment.</p>
          <p>Never: titles, labels, values, URLs, file names, sizes, tag text, times. It is audited for identifiers before it is written, and its counts must equal MANIFEST.csv or the seal refuses it.</p>
          <p><span className="font-mono">open</span> rebuilds it from <span className="font-mono">restored/</span> and compares: <span className="font-mono">structure ✓</span> means the local description matches what came out of the archive. It is a convenience, not proof; the digests are the proof.</p>
        </Card>
        <Card id="file-plaintext" title="SEALED-plaintext.txt: every entry, decrypted" tone="border-amber-500/60 bg-amber-500/5" sample={PLAINTEXT_SAMPLE}>
          <p data-testid="plaintext-only-open" className="font-semibold text-amber-200">It is produced only by <span className="font-mono">open --plaintext</span>, after the unlock time and a fully verified open. Nothing in this app, and nothing at seal time, writes it.</p>
          <p>It is the opposite of STRUCTURE.txt: <b>it holds every secret</b>, concealed values in full. It is written with mode 600, never through a link or an existing file (<span className="font-mono">--force</span> replaces only a regular file), excluded from Time Machine, and the tool prints its path, size and SHA-256 but never a byte of content.</p>
          <p>If the unlock time has not passed, or any check fails (a digest, the manifest, SEALED.txt not beside the package), no file is written. Read it, then delete it and <span className="font-mono">restored/</span> promptly.</p>
          <p>Run it yourself, on your machine, with <span className="font-mono">1password-timelock.sh open &lt;package&gt; --plaintext</span>. This page and the API never read it.</p>
        </Card>
      </div>
    </section>
  )
}
