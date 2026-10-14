# vault-timelock: cryptographic construction

This document describes what `1password-timelock.sh seal` and `timelock-key.sh seal` actually
compute, as of 2026-10-09 (after Task S2). It covers the primitives, the parameters, the security
argument and its assumptions, and the cases where those assumptions do not hold. Items marked **(m)**
were measured on 2026-10-09 on **synthetic data only** (age v1.3.1, tle v1.2.0, macOS bsdtar 3.5.3 /
libarchive 3.7.4); drand was contacted only through Tor. No real vault or package was inspected. Source
references are inline: `[AGE]`, `[TLOCK]`, etc. are listed in **Sources** at the end. Repository
references are `file:function` or `file:line`. It was reviewed by an independent cryptographer
(2026-10-09); the corrections of that review are applied here.

**In one paragraph.** A vault package uses two layers in the KEM/DEM style. The archive is encrypted once with
age to a fresh X25519 key pair, the *data key*. The data key's identity (one line, `AGE-SECRET-KEY-1…`)
is then encrypted twice: (i) with tlock to drand quicknet round `R` (a Boneh–Franklin IBE whose private
key for identity `R` is the beacon signature of round `R`), and (ii) optionally with age to a recipient
the operator holds. Before `R`, confidentiality of a published copy rests on: no one combining ≥ `t`
quicknet key shares (a trust assumption about every League committee from sealing until `R`); co-BDH
and co-GDH in BLS12-381 in the random-oracle model, which a cryptographically relevant quantum
computer (CRQC) would break; age's symmetric primitives; and correct implementations with a sound
RNG. At `R` the IBE key is broadcast, and every copy of the package opens for everyone.

**Glossary of the project's own labels.** R40: drand only through Tor. R44: `MANIFEST.csv`,
`README.txt` and `BLANK-AT-SEAL.txt` are never published. R45: `unlock-KEY.age` is never published.
"Spec A/B": the repository's publish and broadcast design documents. "Claims review F-n" and "expert
review E-n / m-n": the two 2026-10-09 reviews of the tools' security statements and of this document.

---

## 0. Threat model

| Adversary | What it holds | Its goal | Where addressed |
|---|---|---|---|
| Passive harvester | every published copy, kept forever | confidentiality before `R` | §3.1, §4(a) |
| Share coalition | ≥ `t` quicknet key shares (colluding, stolen or compelled; old shares count) | open early, silently | §3.1 T1, §4(b) |
| TLS origin / relay | answers to `/info` and `/public/R` (api.drand.sh or its CDN) | make TIME unopenable; lie about "too early" | §3.5, §4(b) |
| Sealing-host attacker | the sealing machine's disk or timing | read `A` or `I_D` | §3.1 T4, §4(g) |
| Package forger | nothing secret | pass off a package as genuine; plant hostile archive entries | §3.2 |
| Linker | public packages, relay logs, 1Password's server-side records | tie a package to the account or the sealing moment | §4(d) |

## 1. Objects and notation

| Symbol | Meaning |
|---|---|
| `G1, G2, GT, e` | BLS12-381 groups of prime order `q` (255-bit). `e: G1 × G2 → GT` is the pairing; generators `g1, g2` |
| `s`, `pk = s·g2` | quicknet group secret (`(t, n)`-shared by the League of Entropy, never assembled), group public key (96 B compressed, in G2) |
| `t`, `n` | drand's reconstruction threshold and committee size, `t ≥ ⌊n/2⌋ + 1` [DSPEC] |
| `τ(R)` | the nominal time of round `R` (§3.4) |
| `id(R)` | `SHA-256(BE64(R))`: the message drand signs for round `R` ([DRAND] `crypto/schemes.go`, `NewPedersenBLSUnchainedG1`) |
| `H1` | RFC 9380 hash-to-G1, DST `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_` ([DRAND] `schemes.go`) |
| `σ_R = s·H1(id(R))` | beacon signature of round `R`, in G1, 48 B. drand's `randomness` = `SHA-256(σ_R)` |
| `CH` | chain hash `52db9ba7…e971` (§6) |
| `FK_x` | the 128-bit age *file key* of file `x` |
| `(d, D)` | data key: X25519 secret scalar and public point |
| `x`, `X` | an X25519 ephemeral scalar and point (§2.5) |
| `I_D` | the data key's identity file, one line `AGE-SECRET-KEY-1<Bech32(d)>` (§2.4) |
| `A` | the gzip-compressed tar archive of the sanitised vault capture (§2.3) |
| `‖`, `⊕`, `←$` | concatenation, XOR, uniform sampling from Go `crypto/rand` |

**Files in a `1password-timelock.sh` package** (`1password-<vault>-timelock-<UTC>/`, mode 0700):

| File | Byte format | Plaintext inside | Published? |
|---|---|---|---|
| `vault.tar.gz.age` | age v1, one `X25519` stanza (binary, or PEM with `--armor`) | `A` under `FK_v` | yes: inline in `SEALED.txt` (`full`) or in the Arweave bundle (`key-only`) |
| `unlock-TIME.age` | age v1, one `tlock R CH` stanza | `I_D` under `FK_T` | yes, always |
| `unlock-KEY.age` | age v1, one `X25519` or `mlkem768x25519` stanza (only with `--recovery-recipient`) | `I_D` under `FK_K` | **never** (R45) |
| `round` | ASCII decimal `R` + LF | — | yes (bundle) |
| `chain-info.json` | the pinned constant `INFO_PINNED` (quicknet's info, canonical `jq -cS`, built from the pins), written only after `GET /CH/info` through Tor matched it exactly (§3.5): the exact bytes tle encrypted with (§2.6) | — | yes (bundle) |
| `MANIFEST.csv` | CSV: pseudonymous item id, SHA-256, counts, **real op item id** (§2.2) | — | **never** (R44); a copy without the real ids is inside `A` |
| `BLANK-AT-SEAL.txt`, `README.txt`, `ARMOR` | text | — | **never** (R44), not bundled |
| `SEALED.txt` | `vault-timelock-sealed/1` (spec B §5.6): the self-contained text, armored copies of the `.age` files and literal open steps | — | yes (chains, Arweave). Written at the end of every seal by `vt-broadcast seal-text --write` (`broadcast/src/sealed.ts`) |

Inside `A`: `items/<pseudo>.json` (sanitised item JSON), `files/<pseudo item>/<pseudo file>`
(attachment bytes), `MANIFEST.csv` and `ATTACHMENTS.csv` (pseudonyms, digests, counts).

**`seal --list` (lane B, 2026-10-14; `SEALED.txt` format `vault-timelock-sealed/2`, `layout: per-file`)** replaces
`vault.tar.gz.age` with one age file per file `A` would hold, all to the same data key `I_D`: `b0001` … `bN` (age v1, one
`X25519` stanza each; plaintext `gzip -n -9` of the file, zero-padded up to a size bucket with `--pad`; numbered by a
uniform random permutation), `index` (the same; plaintext `vault-timelock-index/1`, one line per block: block, path,
bytes, SHA-256, gzip bytes) and `layout` (`per-file`, the padding, the index's gzip length; public). The paths and digests
are only inside the encrypted index; the text shows the file count and each block's size. `unlock-TIME.age`,
`unlock-KEY.age`, `round`, `chain-info.json`, `MANIFEST.csv`, STRUCTURE.txt (bound to `index`) are as above.

**`timelock-key.sh`** writes one layer: `secret.tar.gz.age` (a path) or `payload.age` + `encoding`
(`raw`, stdin), each an age v1 file with one `tlock` stanza, plus `round`, `chain-info.json`,
`README.txt`, `SEALED.txt` and optionally `ARMOR`.

## 2. Construction, step by step (`1password-timelock.sh cmd_seal`)

Before any export: `need` checks the tools, including node and the `vt-broadcast` install that will
write `SEALED.txt`; Tor is preflighted; quicknet info is fetched through Tor and pinned. Plaintext
lives only in `$WORK = mktemp -d` (0700), and traps unlink it on every exit path.

### 2.1 Capture
`op item list --vault V --include-archive --format json` lists the ids. For each id, `op item get <id>
--format json --reveal --include-archive > items/<id>.json`, the byte string `J_id` exactly as `op`
emits it. Each `.files[]` entry is fetched by ID only (docs, never a real run):
`op read --out-file files/<id>/<file id> op://<vault id>/<id>/<file id>` for an attachment on any item,
`op document get <id> --vault <vault id> --include-archive --out-file …` for a Document item's one
file (archived Documents included). `op read` documents no `--include-archive`: an attachment of an
archived non-Document item that it cannot fetch refuses the seal, saying so. **Fail closed:**
a failed item or file fetch refuses (item/file ids only); per item, the files on disk and the listed
ids fetched must both equal `|.files|`; each file's byte count must equal the JSON's `.size`. Each
file's bytes and SHA-256 are recorded (`ATTACHMENTS.csv`).

### 2.2 Completeness proof, then sanitising
The completeness proof uses the **real** ids: the declared count and id set equal the captured ones;
the population check refuses an all-blank export (the `--reveal` failure mode); no item is hollow.

Then each item is **sanitised** before it is digested and archived (Task S2 §7; JSON shape per
[OPJSON], [OPCONN], [OPREF]):
- **dropped:** `vault {id, name}`, `last_edited_by` (an account member's UUID), `version`,
  `created_at`, `updated_at`; `content_path` (embeds vault, item and file ids) and `reference`
  (`op://vault/item/…`) wherever they occur;
- **pseudonymised** with fresh random 128-bit values per seal (`/dev/urandom`, 32 hex digits),
  consistently wherever the string occurs as a value: every `id` except `vault.id` (item, file,
  section, custom field, url ids) and a `REFERENCE` field's value. An id of 1–20 letters, `_` or
  space starting with a letter (`username`, `password`, `notesPlain`, `database_type`, `add more`) is
  a built-in field or section *name* and is kept; 1Password's generated ids are 26 characters;
- **kept:** every value, title, label, URL, tag, category, file name and file byte: the secrets are
  the payload.

Every digest goes through `sha256_of`, which refuses unless `shasum` gives 64 lowercase hex (a missing
`shasum` used to turn every digest into "", and "" = "" compares equal); `open` refuses a manifest or
attachment row whose recorded digest is not 64 hex. Item ids from `op item list` must be 26 characters
`[a-z0-9]` (the documented id pattern, [OPCONN]) before they are used as paths. With the metadata
dropped, the audit also asserts that no sanitised item keeps a `vault` key, and the audit line says
when a 1–2-character vault name was not searched.

The sealed `MANIFEST.csv` rows are `pseudo,SHA-256(sanitised JSON),|.fields|,|.sections|,|.files|`;
the sealed `ATTACHMENTS.csv` rows are `pseudo item,pseudo file,bytes,SHA-256`. The local
`MANIFEST.csv` beside the package adds `op_item_id`, the real UUID (R44: local only).
`--keep-item-metadata` and `--keep-item-ids` keep the dropped parts, each with a warning.
**What is hashed:** the sanitised JSON exactly as `jq` wrote it. There is **no canonicalisation, no
salt and no key**; the digest fingerprints this seal's bytes, not the item.

**The built-in audit** (`pii_audit`, fail closed) runs on the exact bytes after the archive is
written and the data key drawn, before anything is encrypted:
- `S` = every 1Password identifier in the RAW JSON, by category (item, file, section, field and url
  ids, content paths, references, vault id, member id, item times, versions), minus categories the
  operator chose to keep. `S` is searched **everywhere**: the whole uncompressed tar stream (headers,
  every item, every attachment, both CSVs) and the bytes of `I_D`.
- `P` = the operator: login name, full name, short host name, computer name, `$HOME`, the UTC offset
  as `±HH:MM`, the seal date in UTC and local time, the vault name. `P` is searched only where nothing
  of the user's belongs: `I_D`; the tar stream minus the archived content files (hits in the stream
  minus hits in the item JSONs and attachments, i.e. headers, padding and the two CSVs); and each
  sanitised JSON's structure (its keys and the values of `id`, `category`, `type`, `purpose`,
  `state`). A secret may legitimately contain the login name (a username field) or the vault name (a
  note): user content is not an operator leak, and values are never scanned for `P`.
- Exact, case-sensitive byte matches (`LC_ALL=C grep -F`). `S`: strings of 6+ characters (an item
  version, a short number, is not searched). `P`: 6+ characters and the UTC offset as substrings;
  3–5 characters as whole words (`grep -w`), so a short login name cannot match inside a hex digest or
  a JSON key; an operator identity string (login, full name, host, computer name, home) of 1–2
  characters cannot be searched and refuses the seal, naming the category, unless
  `--allow-short-operator-strings` (which warns); a 1–2-character vault name is not searched.
- Floors, fail closed: `P` must hold a login name and a home directory; `S` must hold at least one item
  id per declared item (unless `--keep-item-ids`), so an empty `S` from a jq or JSON-shape fault
  refuses; an id with no pseudonym refuses rather than mapping to itself; a `grep` that fails (exit > 1)
  refuses, never read as "no match". Any hit refuses with counts and category names only; a pass prints
  the number of strings searched per category.

### 2.3 Archive `A`
**(m)** A plain `tar czf` wrote every entry's owner name (the login name), uid/gid, seal-time mtimes
and modes, xattrs as pax records (`LIBARCHIVE.xattr.*` / `SCHILY.xattr.*`, e.g. Spotlight's
`kMDItemWhereFroms` download URLs) and the gzip header `MTIME`. Now (Task S2 §2): the work copies are
normalised (dirs 700, files 600, every mtime 2000-01-01T00:00:00Z, set with `TZ=UTC0` because
`touch -t` reads local time and would encode the UTC offset), then
`COPYFILE_DISABLE=1 tar --format ustar --no-mac-metadata --no-xattrs --no-acls --no-fflags --uid 0
--gid 0 --uname nobody --gname nobody -cf vault.tar …` (ustar has no pax records, so no xattrs), then
`gzip -n -9` (no name, `MTIME` 0, `OS` = 3), zero-padded to a multiple of 10,240 bytes, the granularity
bsdtar's own piped output had. So `|A| ≡ 0 (mod 10240)`. `timelock-key.sh` refuses a source whose identity (`stat`) it
cannot read, since the re-check before deleting it would otherwise compare nothing, and streams through bsdtar's
own gzip (`--options gzip:!timestamp`, padded the same way) and never modifies its source: the
source's own mtimes and modes remain in the archive.

### 2.4 Data key
`age-keygen 2>/dev/null | grep '^AGE-SECRET-KEY-1' > identity.key`: `d ←$ {0,1}^256`;
`D = X25519(d, 9)` per RFC 7748, which clamps `d` (clears bits 0–2 and 255, sets bit 254), so the
effective scalar carries 251 bits of entropy; `D` is a u-coordinate. `I_D` is **one** LF-terminated
line, `AGE-SECRET-KEY-1<Bech32(d), upper case>`, 75 B **(m)**. age-keygen's comment lines
(`# created: <local time with UTC offset>`, `# public key:`) never reach the disk: measured on a
synthetic package, they would have put the sealing time and the timezone inside `unlock-TIME.age`.
`D` is derived with `age-keygen -y` and is never written into the package.

### 2.5 Payload encryption: `vault.tar.gz.age = age(D, A)`
This is the age v1 format with the X25519 recipient ([AGE] "Encrypted file format", "X25519 recipient type"):
1. `FK_v ←$ {0,1}^128`.
2. `x ←$ {0,1}^256`, `X = X25519(x, 9)` (clamped as in §2.4), `ss = X25519(x, D)`; decryption aborts if `ss = 0^32`.
3. `wrap = HKDF-SHA-256(ikm = ss, salt = X ‖ D, info = "age-encryption.org/v1/X25519")` [RFC5869];
   stanza body = `ChaCha20-Poly1305_wrap(nonce = 0^96, FK_v)` [RFC8439], 32 B.
4. Header: `age-encryption.org/v1`, `-> X25519 b64(X)`, `b64(body)`, then the MAC line `--- b64(MAC)`. The MAC is
   `HMAC-SHA-256(HKDF-SHA-256(ikm = FK_v, salt = "", info = "header"), header through "---")`. `b64` is
   RFC 4648 standard base64, unpadded, wrapped at 64 columns. The header is 168 B **(m)**.
5. Payload: `N ←$ {0,1}^128`; `K = HKDF-SHA-256(ikm = FK_v, salt = N, info = "payload")`. `A` is cut into
   64 KiB chunks `c_i`, and `ct_i = ChaCha20-Poly1305_K(nonce = BE88(i) ‖ [0x01 if last else 0x00], c_i)`
   (STREAM [HRRV15]). The output is `N ‖ ct_0 ‖ ct_1 ‖ …`.

Size: `|vault.tar.gz.age| = 168 + 16 + |A| + 16·⌈|A|/65536⌉` (**m**: `|A| = 10240` gives 10,440 B).

### 2.6 Time layer: `unlock-TIME.age = tle(R, I_D)`
`R = round_for(now + L + J)` (§3.4). tle v1.2.0 embeds filippo.io/age v1.1.1; age draws a fresh `FK_T`
and hands it to `tleRecipient.Wrap` ([TLE] `tlock_age.go`).

*Key material, pinned (Task S2 §3, expert review E4).* tle takes the scheme and `pk` from its own
`GET /CH/info`; drand go-clients rejects any info whose hash ≠ `CH` ([GOC] `client/http/http.go:276`).
That hash is `SHA-256(BE32(period) ‖ BE64(genesis_time) ‖ pk ‖ groupHash ‖ "quicknet")` ([DRAND]
`common/chain/info.go`; recomputed to `52db…e971`, **m**). It binds the period, the genesis time,
`pk`, the group hash and the beacon id. **It does not bind `schemeID`.** **(m)** Against a loopback
server, tle v1.2.0 refuses an info whose period was changed ("does not advertise the expected drand
group") but *accepts* a hash-valid info saying `bls-unchained-on-g1` and encrypts to an identity drand
never signs. So the sealers (`info_serve`) serve tle the pinned constant `INFO_PINNED` (never the
fetched bytes) from `127.0.0.1` (node, that one path) and encrypt with `tle --encrypt
--network=http://127.0.0.1:<port> --chain=CH --round=R`: encryption uses exactly the pinned
parameters and makes no drand request. The fetched info must be exactly one JSON value, repeat no key
and equal `INFO_PINNED` as a JSON value: drand's Go decoder reads the first of several values and
folds key case (a `schemeid` beside `schemeID` would be read by it and not by jq), so anything but an
exact match refuses.

*IBE.* For scheme `bls-unchained-g1-rfc9380`, `TimeLock` calls kyber `ibe.EncryptCCAonG2` (master key
on G2, identities on G1) ([TLE] `tlock.go`; [KYB] `encrypt/ibe/ibe.go`). This is Boneh–Franklin
*FullIdent* (Fujisaki–Okamoto) [BF01] with message length ℓ = 128 bits, i.e. [TLOCK] §5.1 Alg. 1 with
the groups swapped (the paper's Alg. 1/2 contain typos this description does not copy):
```
Q    = H1(id(R)) ∈ G1
G_R  = e(Q, pk) ∈ GT                                   (the "round public key")
ς    ←$ {0,1}^128                                       (crypto/rand)
r    = H3(ς, FK_T) ∈ Z_q    h = SHA-256("IBE-H3" ‖ ς ‖ FK_T); for i = 1, 2, …:
                            x_i = SHA-256(LE16(i) ‖ h); x_i[0] ← x_i[0] >> 1 (a byte shift, not a mask);
                            r = BE(x_i) for the first i with BE(x_i) < q
U    = r·g2 ∈ G2                                       (96 B compressed)
V    = ς    ⊕ SHA-256("IBE-H2" ‖ ser(G_R^r))[0:16]
W    = FK_T ⊕ SHA-256("IBE-H4" ‖ ς)[0:16]
```
([KYB] `ibe.go:230-280`; kyber-bls12381 scalars are big-endian `mod.Int`.) The stanza is
`-> tlock <R> <CH>`, with body `b64(U ‖ V ‖ W)`: 128 B, three body lines ([TLE] `CiphertextToBytes`).
The payload is `I_D` under `FK_T`, as in §2.5 step 5: 16 + 75 + 16 = 107 B. The whole file is 434 B
with an 8-digit `R`, 435 B with a 9-digit `R` **(m)**. **The ciphertext contains** `R` and `CH` in
clear, `U, V, W`, the header MAC and the STREAM payload. Nothing in it identifies `D`, the vault or
the sealer.

### 2.7 KEY path, optional
`age -r RECIP identity.key > unlock-KEY.age` (the same one-line `I_D`). The only check on `RECIP` is
the prefix `age1`.
- An X25519 recipient: as in §2.5.
- `age1pq1…` (age ≥ 1.3, `age-keygen -pq`): the stanza is `-> mlkem768x25519 b64(enc)`, using HPKE SealBase
  with KEM MLKEM768-X25519 (X-Wing, draft-ietf-hpke-pq), HKDF-SHA256 and ChaCha20Poly1305, and
  `info = "age-encryption.org/mlkem768x25519"`. `enc` is 1120 B and the body 32 B ([AGE] "The MLKEM768-X25519
  (i.e. X-Wing) hybrid post-quantum recipient type"; **m**).
- Plugin recipients (`age1yubikey1…` and similar) also pass the check.

### 2.8 Armor (`--armor`)
Every age/tle call gets `--armor`. The output is PEM with the label `AGE ENCRYPTED FILE`, padded base64 in 64 columns, LF
line endings ([AGE] "ASCII armor": strict RFC 7468). `age -d` and `tle --decrypt` detect armor by content.
`sealed.ts` de-armors strictly (it requires `armor(dearmor(t)) = t`) and re-armors the binary, so `SEALED.txt` is byte-identical
for both forms, and its `[file … sha256=]` covers the binary. The scrypt stanza is never used.

### 2.9 Round-trip, negative controls, then disposal
`age -d -i identity.key vault.tar.gz.age` is extracted into `$WORK/rt`; every item's SHA-256 must equal
its sealed manifest row, every attachment its `ATTACHMENTS.csv` row, and `ATTACHMENTS.csv` must come
back byte-identical. This proves the payload opens with the data key; it cannot exercise
`unlock-TIME.age` (impossible before `R`) or `unlock-KEY.age` (that needs `recovery.key`); the
self-test exercises both on a 60 s seal. The negative controls follow (§3.5). Then `identity.key` and
`$WORK` are **unlinked, not wiped**. On APFS and SSDs, stale blocks still hold `A` and `I_D`;
FileVault is what keeps them ciphertext.

### 2.10 `SEALED.txt`, the last step
`vt-broadcast seal-text <package> --write` writes the self-contained text (spec B §5.6): what the
package is, its layers, `unlock-after` and round, the drand chain, scheme, signature URL and mirrors,
the tools at pinned versions with install lines, literal open steps (cut the blocks with `awk`, check
sizes and SHA-256, `tle --decrypt` through Tor, `age -d`, `tar` into `restored/`, `shasum -a 256 -c`
against the sealed manifests), notes on what keeps it shut, and the armored `.age` files. It names no
requested duration and no offset (§4(d)). If it cannot be written, the seal reports failure and keeps
the package. The self-tests copy only `SEALED.txt` into an empty directory and run its printed
commands exactly as printed, through Tor after the round.

### 2.11 Decryption paths
- **TIME** (once drand has published round `R`): tle fetches `σ_R` (`GET /CH/public/R`) and verifies
  `e(σ_R, g2) = e(H1(id(R)), pk)` (`TimeUnlock` → `VerifyBeacon`). Then ([KYB] `DecryptCCAonG2`):
  ```
  ς'  = V ⊕ SHA-256("IBE-H2" ‖ ser(e(σ_R, U)))[0:16]     since e(σ_R, U) = e(Q, g2)^{sr} = G_R^r
  FK' = W ⊕ SHA-256("IBE-H4" ‖ ς')[0:16]
  reject unless U = H3(ς', FK')·g2
  ```
  It then checks the header MAC under `FK'` and decrypts the STREAM, giving `I_D`. `age -d -i I_D` then yields `A`. `open`
  lists `A` before extracting it (regular files and directories only, relative paths, no `..`), extracts it with
  `--no-mac-metadata --no-xattrs --no-acls --no-fflags` into a new 0700 directory, then checks the result **on disk**
  (first giving the owner rwx on every directory and rw on every file of this new tree, so a mode-000
  directory cannot hide entries from the walk; no pipeline hides a failing `find`; a refused extraction is
  removed and its removal verified) (only regular files and directories; no xattr or ACL anywhere, the
  directory included) and re-checks every manifest
  and attachment digest, and each item's attachment rows against its manifest `file_count` (a manifest that lists
  attachments with no `ATTACHMENTS.csv` is not reported as verified). **(m)** A macOS AppleDouble member (`._y`) is invisible to `tar -t`/`-tv`, yet libarchive merges
  it into the next entry on extraction: that entry, listed as a regular file, lands as a symlink, or the files gain an
  "everyone allow" ACL and xattrs. Only `--no-mac-metadata` stops the ACL/xattr merge; nothing on the tar side stops
  the symlink merge, so the on-disk check is the wall. **The round signature is the BF private key for identity `id(R)`**: drand "extracts" it
  as a by-product of producing the beacon ([TLOCK] §2.3: Extract "essentially outputs a BLS
  signature").
- **KEY** (any time): `age -d -i recovery.key unlock-KEY.age` gives `I_D`, then the same steps as TIME.

### 2.12 `timelock-key.sh` (one layer)
`tar … -czvf - --options gzip:!timestamp … | tle --encrypt --network=<loopback> --chain=CH --round=R`
writes `secret.tar.gz.age`. With `-`, stdin goes raw into `tle` and becomes `payload.age`. There is
the same `tlock` stanza, but `FK_T` protects the content directly: no data key and no KEY path. The tar
carries the scrub of §2.3 except the source's own mtimes and modes (the source is never modified), and
the 10 KiB padding. Raw stdin has its exact length. A source *file* is unlinked after the package and
its `SEALED.txt` check out.

## 3. Security properties

### 3.1 Confidentiality before `R`
Let `𝒜` hold every published file before drand publishes round `R`. `𝒜` learns nothing about the
vault beyond §4(d)'s metadata **unless at least one of the following holds**:
- **T1 threshold.** Someone obtains `σ_R` before round `R` is due: ≥ `t` key shares of `s` are combined
  (collusion, theft or legal compulsion of their holders; shares from before a reshare count, §4(b)),
  or ≥ `t` nodes are induced to sign round `R` early (each node signs when its own clock says so; how
  far clock manipulation can advance a round is not analysed here). `t` is drand's reconstruction
  threshold, `t ≥ ⌊n/2⌋ + 1` [DSPEC]. [TLOCK] §6.1: "we only trust that there is never a threshold t
  of malicious nodes".
- **T2 cryptographic assumptions.** Against fewer than `t` shares, the TIME layer is Boneh–Franklin
  FullIdent [BF01] over a type-III pairing with the master key in G2. Its IND-ID-CCA argument (random
  oracles for SHA-256 and for `H1`, the RFC 9380 `_RO_` suite) reduces to co-BDH as defined in [TLOCK]
  §2.1: given `(g1, s·g1, b·g1, g2, s·g2, c·g2)`, compute `e(g1, g2)^{sbc}` (here `b·g1 = H1(id(R))`,
  `c = r`). The original FullIdent reduction was corrected by [Gal05]. No partial-signature set below
  `t` yields `σ_R` under co-GDH in (G1, G2) [BLS04, Bol03]. [TLOCK] §5.1 Theorem 1 claims tTLE-CCA
  security in the ROM under GDH and co-BDH, but (i) its `t` is a corruption bound `t < ⌊n/2⌋`, so it
  covers at most ⌊n/2⌋ − 1 corrupt parties (10 for n = 22), fewer than T1's `t − 1` (11); (ii) it
  assumes a static adversary and the GJKR DKG, whereas drand runs a Pedersen/Joint-Feldman DKG
  [DSPEC] (key bias possible [GJKR07]) and reshares; (iii) "A full proof will appear in the final
  version of the paper" and has not. BLS12-381 is "expected to be 126 rather than 128 bits"
  [PFC §4.2.1]. A CRQC breaks every assumption in T2 (§4(a)).
- **T3 symmetric.** `𝒜` breaks HKDF-SHA-256, HMAC-SHA-256 or ChaCha20-Poly1305 under 128-bit file keys.
- **T4 endpoints.** `𝒜` obtains `A` or `I_D` from the sealing machine (stale blocks, Time Machine,
  swap). Or `𝒜` holds a local package together with `recovery.key`. Or `𝒜` breaks the recovery recipient's KEM.

By a standard hybrid argument (a sketch, not a proof): replace the plaintext of `unlock-TIME.age`
(IND-ID-CPA suffices, §3.2), then of `unlock-KEY.age` if the adversary holds it, then `A` in
`vault.tar.gz.age` (age X25519, in the ROM, plus STREAM); the advantage is at most the sum. The X25519
wrap of `vault.tar.gz.age` is never the cheapest path: T1 and T2 both yield `d` itself.

### 3.2 Integrity and authenticity
- **Integrity under the key.** age authenticates the header (HMAC under `FK`) and every 64 KiB chunk
  (Poly1305). The last-chunk flag rules out truncation and extension. tlock's FO check binds `(U, V, W)` to
  `(ς, FK_T)`. Editing `R` fails (wrong identity: the FO check and the header MAC reject). Editing `CH`
  fails too, but tle v1.2.0 is not strict (`trustChainhash = true`): it switches to the stanza's chain
  and fetches its info and signature from the same host, so a hostile package chooses which chain tle
  queries ([TLE] `tlock.go:52-62`, `tlock_age.go:79-90`, `cmd/tle/tle.go:68-77`).
- **No origin authentication.** tlock encryption needs no secret, and X25519 encryption needs only a
  public key, so **anyone can build a well-formed package for any round** (a past round opens at
  once). The Arweave and chain signatures authenticate a fresh per-job key (spec A §4 step 5) that is
  unlinkable to the operator by design.
  - `SEALED.txt`'s `sha256=` and Arweave's `Package-SHA256` detect corruption in transit and nothing more.
  - The manifest of a *fetched* package comes from inside the archive (R44), so it is chosen by whoever built
    the archive and proves internal consistency only.
  - The tools treat fetched packages as hostile input (`tar_entries_ok`, then `extract_verified`'s
    on-disk check, §2.11; `mkdir` without `-p`; id charset checks). Users should treat the *contents* as unauthenticated unless they verify them out of band.
- **Incidental binding.** `D` is never published, so nobody can swap in a different
  `vault.tar.gz.age` that opens with the real `I_D`. Replacing both files is trivial.
- **Commitment.** ChaCha20-Poly1305 is not key-committing [LGR21]. age compensates: stanza bodies have
  a fixed length (32 B), checked before decryption "to mitigate partitioning oracle attacks" [AGE],
  and the header MAC is HMAC-SHA-256 with a 256-bit tag under HKDF(FK, "header"). A header that
  verifies under two file keys is an HMAC-SHA-256 collision, so a well-formed file determines one
  `FK`, one payload key and one plaintext (≈128-bit level; a standard argument, not one the age spec
  states). The tlock stanza is deterministic given `σ_R`, and the FO check fixes `FK_T`. Nothing binds
  `unlock-TIME.age` and `unlock-KEY.age` to the same `I_D`: a dishonest sealer can make the two paths
  open different things.
- **Which notion matters.** Before `R` no one can decrypt any round-`R` ciphertext, so there is no
  decryption oracle: confidentiality needs only IND-ID-CPA with extraction for every other round
  (all past signatures are public). FO/CCA buys non-malleability, which matters for hostile packages
  and after `R` ([TLOCK] §7 makes the same observation).
- **Integrity is relative to the file key.** The bullets above hold against parties who do not know
  `FK`. After `R` everyone can compute `FK_T` and re-encrypt; from then on, a fetched package is only
  as authentic as its out-of-band provenance.
- **Replay and re-publication.** The age files carry no associated data. Any copy can be re-posted
  with different tags or notes (`Unlock-After`, `Package-Kind`) and is indistinguishable from the
  original. The authoritative round is the one in the `tlock` stanza; tags are claims.

### 3.3 Availability
- **TIME path.** Before `R`, at least `t` quicknet nodes must still be live and produce round `R`; a stall
  delays the opening. After `R`, any stored copy of the 48-byte `σ_R` suffices. It verifies itself
  against `pk` (`chain-info.json`), so relays and archives need no trust. tle v1.2.0 cannot read a
  stored signature: it fetches `/CH/public/R` over HTTP. Using an archived `σ_R` needs a local endpoint
  that serves drand's JSON for `/CH/info` and `/CH/public/R`, or a few lines of Go calling
  `tlock.TimeUnlock`.
- **Group changes.** Resharing changes membership but keeps `s`, `pk` and `CH`. A new DKG makes a new chain,
  and old packages then need the old chain to have produced `R`. If the chain halts before `R`, the TIME
  path is lost and only the local KEY path remains.
- **Mirrors.** The mirrors are `api.drand.sh`, `api2`, `api3`. tle's HTTP timeout is 5 s
  ([TLE] `networks/http/http.go`), so a slow Tor circuit can fail the fetch. tle reports that failure as
  "too early" (§3.5); `open` reports it as a fetch failure once the round has passed by the pinned
  parameters and the clock.

### 3.4 Timing granularity, and the random offset
`R = ⌊(T − 1692803367)/3⌋ + 1`, where `T = now_sealer + L + J`: `L` is the requested duration and `J`
a uniform random offset in `[0, J_max]` (§4(d), Task S2 §6). The round's nominal time is
`τ(R) = 1692803367 + 3(R − 1)`, with `τ(R) ≤ T < τ(R) + 3`. `R` fixes the opening instant absolutely. A
sealer clock error `Δ` shifts `R` by about `Δ/3`. The README and `SEALED.txt` print `τ(R)`, so they stay
truthful; only the *requested* duration is off by `Δ` (and by `J`). drand signs at `τ(R)`, and clients
see `σ_R` after propagation, typically seconds later. The decryptor's clock plays no part in decryption.

### 3.5 Negative controls, as implemented

| Control | Code | Establishes | Does not establish |
|---|---|---|---|
| Pin | `chain_info` | curl's info is exactly one JSON value, repeats no key (`jq --stream`), and equals `INFO_PINNED` as a JSON value (no extra or case-variant key); the constant, not the fetched bytes, is kept and served to tle | — |
| Pinned encryption | `info_serve` | tle encrypts with exactly the pinned `chain-info.json` (served on loopback; tle checks `CH` on it) | — |
| Local future | `assert_future` | `R > round_now_local + 5` | anything if the local clock is wrong |
| tle "too early" | `assert_shut` (1) | `tle --decrypt` of the file as written failed with "too early": it parses as a tlock age file for this chain, and `U` decodes in G2 | that drand refused: tlock v1.2.0 maps **every** error fetching `σ_R` (HTTP 425, timeout, 5xx, circuit failure) to `ErrTooEarly` ([TLE] `tlock_age.go`, `Unwrap`) |
| drand 425 | `assert_shut` (2), `drand_status` | the relay answered `GET /CH/public/R` with HTTP 425 through Tor: its own, unauthenticated statement, by its own clock, that it has no signature for `R` yet (**m**: 425 `Requested future beacon` for a future round, 200 for a past one) | a drand signature or anything about the League; it is evidence about the relay |
| Unrelated identity | `cmd_seal` (1password) | an unrelated fresh key gets "no identity matched": the payload is an age file to a recipient, not plaintext and not scrypt | — (the old "no identity" check was vacuous: `age -d` without `-i` fails on any input **m**) |
| Round trip | `cmd_seal` | `vault.tar.gz.age` opens with `I_D`; every item and attachment matches its sealed digest | that `unlock-TIME.age` opens at `R`, or that `unlock-KEY.age` opens |
| PII/ID audit | `pii_audit` | `S` (item, file, section, field and url ids, content paths, references, vault id, member id, item times; 6+ chars) absent from the whole tar stream and `I_D`; `P` (login name, full name, host and computer name, `$HOME`, UTC offset, UTC and local seal date, vault name; 6+ chars as substrings, 3–5 as whole words) absent from `I_D`, the tar stream minus the item JSONs and attachments, and the JSON structure; floors on both sets; grep failures refuse (§2.2) | that the vault's own values say nothing about the operator; 1–2-char operator strings when `--allow-short-operator-strings` is given |
| Self-test | `cmd_selftest` | a real seal through Tor with a 60 s horizon: TIME refuses before `R`, opens after, digests verify; the literal `SEALED.txt` steps work as printed | anything about a particular package |

## 4. Non-properties and risks

**(a) Post-quantum.**
- **Cheapest attack.** The TIME layer is pairing-based and falls to Shor's algorithm. The cheapest attack is one ECDLP in G1, a curve
  over a 381-bit prime field: from any published `(id(r), σ_r)`, recover `s` from `σ_r = s·H1(id(r))`. That
  opens **every quicknet ciphertext for every round at once**, not only this package. A per-ciphertext
  attack (a DLP for `r` in G2, over F_{p²}) is no cheaper, so the global break is the relevant one.
- **Resources.** [RNSL17] bounds Shor for an n-bit prime field by ≤ 9n + 2⌈log₂n⌉ + 10 logical
  qubits and ≤ 448n³log₂n + 4090n³ Toffolis (n = 381: ≤ 3,457 and ≈ 4.4·10¹¹). Current estimates are
  far lower: for 256-bit ECDLP, "fewer than 1,200 logical qubits and fewer than 90 million Toffoli
  gates" (or < 1,450 and < 70 M), "fewer than half a million physical qubits" at 10⁻³ error rates,
  running in minutes [BZG+26]; see also [Lit23]. No published estimate targets BLS12-381's 381-bit
  base field; it should be the same order of magnitude in qubits and a few times more Toffolis
  (extrapolation, not a published figure).
- **The X25519 stanza.** The X25519 stanza of `vault.tar.gz.age` is not independently Shor-breakable,
  because `D`, which the HKDF salt needs, is never published. That is an accident of the format, not a
  property age claims, and it is moot here because TIME yields `d`.
- **No post-quantum TIME layer.** [TLOCK] §7: "A quantum-computer would currently be able to defeat both the BLS and IBE schemes".
  drand runs no post-quantum threshold-IBE network, so **the TIME layer cannot be made post-quantum today**.
  An `age1pq` recipient protects only the KEY wrap. `I_D` is still reachable through
  `unlock-TIME.age`, which is always published.
- **Harvest now, decrypt later.** Published copies (Arweave, Ethereum, Base, Arbitrum, Bitcoin) are
  permanent. A CRQC that arrives at any time before `R` opens the vault early. A 10-year seal made in 2026
  (`R` ≈ 1.38·10⁸, 2036) outlives NIST's planned retirement of ≥128-bit ECDH ("Disallowed after 2035",
  [NIST8547] §4.1.2 Table 4).
  drand, announcing tlock's audit (2023-05-26): "neither the BLS, nor the IBE scheme are 'quantum
  resistant'… we currently consider that you can expect a 'long term security' horizon of at least
  5 years" [DSA23]. A 10-year seal made in 2026 lies outside the horizon its designers claim. (NIST
  lists no pairing-based scheme; the ECDH row is the nearest analogue.) Expert-opinion surveys exist,
  but none gives a defensible probability of a CRQC by 2036, and published resource estimates keep
  falling.
- **What can be said honestly.** A published package stays confidential until the earliest of: `τ(R)`;
  ≥ `t` key shares being combined; a break of co-BDH/co-GDH on BLS12-381 (by a CRQC solving one ECDLP
  in G1, or classically); and, for a local copy, exposure of `recovery.key`. Grover's algorithm against
  128-bit file keys needs about 2⁶⁴ serial iterations, which is not considered practical.

**(b) Threshold and operators.**
- **Early opening by a coalition.** Any coalition of ≥ `t` key shares can compute `σ_R` at any time by
  Lagrange-combining partial signatures ([TLOCK] §2.2), and early decryption leaves no trace.
- **Who holds the shares.** The League of Entropy. At quicknet's general availability drand wrote:
  "current threshold is 12 out of 22 nodes, it should increase as the League of Entropy onboards new
  members" ([QN], 2023-10-16; the same post counts "currently 23 nodes" in the League's network).
  drand requires `t ≥ ⌊n/2⌋ + 1` [DSPEC]. Membership and `t` are set by League governance and change
  at reshares (fastnet: "from 21 with a threshold of 11 to a committee of 14 with a threshold of 8"
  [FN]), so the assumption covers every committee between sealing and `R`. `/info` exposes neither
  `n` nor `t`.
- **Old shares.** Shares from a sharing that predates a reshare still reconstruct `s`. Proactive security holds
  only if retired shares are destroyed.
- **Ongoing operation.** drand must keep publishing quicknet with the same `CH` until `R`.
- **Scheme, pinned (Task S2 §3).** `CH` does not bind `schemeID`. Whoever answers `GET /CH/info` over
  TLS (the api.drand.sh origin or its CDN; a Tor exit cannot) could return a `CH`-valid info saying
  `bls-unchained-on-g1` (same groups, `H1` with the G2 DST); tle would then encrypt to an identity
  drand never signs, and the TIME path would never open, with every other seal-time control passing.
  Confidentiality is unaffected. Pinning `schemeID` in `chain_info` checks curl's response only; tle
  fetches info separately and the stanza does not record the scheme. **The sealers therefore serve
  tle the pinned `chain-info.json` from a loopback endpoint** (§2.6): tle encrypts with pinned
  parameters, and an origin that answers the two requests differently cannot change them. The
  *decryption* path (after `R`, and the seal-time "too early" control) still takes the scheme from the
  origin; a wrong one there makes opening fail, which is an availability matter.

**(c) Forward secrecy** does not apply. The data is static, and its decryption key becomes public at
`R` by design. What matters is that nothing outside the design can open the package early later on: `t`
shares (b), `recovery.key` (f), and stale plaintext or `I_D` blocks on the sealing disk (§2.9).

**(d) Metadata.**
- **Public before `R` when published.**
  - `R`, so `τ(R)` to within 3 s; `CH`; the scheme.
  - The Arweave tags `Package-Kind: 1password-vault`, `Unlock-After`, `App-Platform`, the upload time,
    the uploader address and the note.
  - Sizes. `unlock-TIME.age` is 434 B, or 435 B once `R` has 9 digits (from 2033-02-23)
    (packages sealed before Task S2, whose identity file had two comment lines: 548/549 B, 5 B less if
    the sealer's time zone was UTC). `vault.tar.gz.age` is `184 + |A| + 16⌈|A|/65536⌉` with `|A|` a
    multiple of 10,240, which reveals the compressed vault size to within 10 KiB.
  - The sealing instant. With a guessable duration `L` (the default 10 y, or any whole number of
    units), `τ(R) − L` would be the moment of sealing to within 3 s; it can be matched to 1Password's
    server-side record of the `op item get --reveal` burst, to relay logs and to the upload time. **The
    sealers therefore add a uniformly random offset `J ∈ [0, J_max]` to `T` before computing `R`**
    (Task S2 §6): `J_max = min(24 h, L/10)` by default (10 y and 30d: 24 h; 1h: 6 min; 10m: 1 min),
    drawn from `/dev/urandom` by rejection sampling, never printed; `--jitter` sets `J_max`,
    `--jitter 0` disables it with a warning. The README prints `τ(R)` and `J_max`, so it stays
    truthful; `SEALED.txt` (published) prints neither `L` nor `J_max`. **Residual:** the seal's own drand
    requests for round `R` (the "too early" and HTTP 425 controls, through Tor) are made at the sealing
    moment, so a relay log still records when round `R` was first asked for; the offset removes the
    arithmetic link, not that one.
  - Length reflects compressibility. Content an attacker can place in the vault (a shared item, a
    saved document) is compressed together with secrets, so repeated published seals of one vault
    form a compression side channel at 10,240-B granularity: impractical for a few seals, not excluded.
- **Public at `R`.** Everything inside `A`: the sanitised item JSON (every value, title, label, URL,
  tag and file name; pseudonymous ids; no account metadata), the attachments, the two CSVs, and the
  tar headers (owner `nobody`, mtime 2000-01-01Z, modes 600/700; for `timelock-key.sh`, the source's
  own mtimes and modes). `I_D` is one secret-key line: no creation time, no UTC offset.
- **Local only (R44).** `MANIFEST.csv` (with the real op item ids), `BLANK-AT-SEAL.txt`, `README.txt`
  (vault name, seal time).
  - `STRUCTURE.txt` (Task S3): the sealed vault's shape built from an allowlist (categories, field types, set/empty, counts, the archive's own ids; no title, label, value, URL, tag or file name), mode 600, bound to `vault.tar.gz.age` by SHA-256 of its binary; audited like the payload, rebuilt and compared by `open`, never in `SEALED.txt`.
  - `SEALED-plaintext.txt` (Task SP, R74): every entry decrypted, written by `open --plaintext` only after the unlock time and a fully verified open (mode 600, fsynced, linked or renamed into place); it holds every secret, like `restored/`: never in `SEALED.txt`, never published; delete both when done.
  - **Why unsalted digests must not be published.** `SHA-256(J)` of an item's JSON is a deterministic function of the export
    bytes. Anyone holding a candidate `J` can confirm it offline before `R`: an older export, a leaked backup,
    or a guess at a low-entropy field when the item's other fields are known. Equal digests across two seals
    also reveal which items did not change.
  - **If a public commitment is ever wanted,** use `HMAC-SHA-256(k, J)` with a per-package 256-bit `k` stored
    inside `A`. It is useless before `R` and verifiable after.

**(e) "Opens at T" means "opens for everyone at T".** `σ_R` is a public broadcast that relays and archives
keep forever, and tlock has no recipient. From `τ(R)` on, anyone with a copy can read the plaintext,
permanently. Rotate any credential that will still be valid at `R`.

**(f) Recovery path (R45).** `unlock-KEY.age` is never published, so the published object's only key
is TIME. Locally, the package resists early opening only as well as the weaker of TIME and the custody of
`recovery.key`. Anyone holding `recovery.key` and any copy of the local package (a Time Machine copy of
`~/.local/share` counts) can open it today. An X25519 recovery recipient is quantum-vulnerable whenever
its public key is known. An `age1pq` recipient (ML-KEM-768 + X25519, X-Wing) is designed to stay secure
if either component holds; it protects only the local copy.

**(g) Implementation notes.**
- **Versions (m).**
  - tle v1.2.0 (go1.25.6): filippo.io/age v1.1.1, drand/kyber v1.3.1, kyber-bls12381 v0.3.1 →
    kilic/bls12-381 v0.1.0, drand/v2 v2.0.2, go-clients v0.2.0.
  - age CLI v1.3.1 (go1.25.5; filippo.io/hpke v0.4.0).
  - typage (npm `age-encryption`) 0.3.1 is used only by `broadcast/src/lifecycle/keystore.ts`, never to seal or open.
  - The READMEs and `SEALED.txt` pin `go install …/tle@v1.2.0`.
  - node (v24) serves the pinned chain info to tle on loopback during a seal, and runs `vt-broadcast`.
- **Constant time.** kilic/bls12-381 multiplies scalars with GLV/wNAF (`g2.go`) and exponentiates in GT by
  square-and-multiply (`fp12.go cyclotomicExp`), both with secret-dependent control flow. During encryption
  `r` is secret, and `r` reveals `G_R^r`, then `ς`, then `FK_T`. So a timing attacker on the sealing machine could in principle recover `FK_T`,
  but such an attacker with the user's file access can already read `$WORK`. Decryption uses only the public `σ_R`.
  A co-resident timing-only attacker (another account, a VM neighbour) cannot read `$WORK` but
  could in principle observe the variable-time G2 multiplication and GT exponentiation. There is no remote vector: tle does
  no network I/O after `r` is drawn. tlock, tlock-js and their dependencies were audited by Kudelski Security in 2023
  (1 High, 5 Medium, 3 Low, all reported fixed) [KS23].
- **Randomness.** `d`, `x`, every `FK`, `N` and `ς` all come from Go `crypto/rand`: "On macOS, iOS, and OpenBSD
  Reader, uses arc4random_buf(3)" [GORAND]. The pseudonyms and the round offset come from `/dev/urandom`.

## 5. Verification recipes (synthetic data only; drand only through Tor)

```sh
X=$(mktemp -d); cd "$X" || exit 1
CH=52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971; G=1692803367; P=3
PX="socks5h://verify:x@127.0.0.1:9050"
tor_() { env -u NO_PROXY -u no_proxy HTTPS_PROXY="$PX" https_proxy="$PX" "$@"; }
# 1. a made-up capture and its manifest (2.1, 2.2)
mkdir -p w/items w/files
printf '{"id":"0123456789abcdef0123456789abcdef","fields":[{"id":"password","type":"CONCEALED","value":"synthetic"}]}\n' > w/items/0123456789abcdef0123456789abcdef.json
{ echo item_id,sha256,field_count,section_count,file_count
  echo "0123456789abcdef0123456789abcdef,$(shasum -a 256 w/items/*.json | cut -d' ' -f1),1,0,0"; } > w/MANIFEST.csv
echo item_id,file_id,bytes,sha256 > w/ATTACHMENTS.csv
# 2. data key (one line), scrubbed archive, payload, time layer, as 1password-timelock.sh does them
age-keygen 2>/dev/null | grep '^AGE-SECRET-KEY-1' > id.key; D=$(age-keygen -y id.key)
find w -mindepth 1 -exec env TZ=UTC0 touch -h -t 200001010000 {} +
COPYFILE_DISABLE=1 tar --format ustar --no-mac-metadata --no-xattrs --no-acls --no-fflags --uid 0 --gid 0 \
  --uname nobody --gname nobody -cf - -C w items files MANIFEST.csv ATTACHMENTS.csv | gzip -n -9 | age -r "$D" -o vault.tar.gz.age
R=$(( ( $(date -u +%s) + 60 - G ) / P + 1 ))
# (the tools serve tle the pinned chain-info.json on loopback; through Tor directly is equivalent here)
tor_ tle --encrypt --chain=$CH --round=$R --output=unlock-TIME.age id.key && rm id.key
# 3. the stanzas: "-> tlock R CH" + 3 body lines; "-> X25519 <32-byte share>" + 1 body line
sed -n '1,/^---/p' unlock-TIME.age; sed -n '1,/^---/p' vault.tar.gz.age
python3 -I -c 'import base64,sys; l=open(sys.argv[1],"rb").read().split(b"\n"); b=b"".join(l[2:l.index(next(x for x in l if x.startswith(b"---")))]); print(len(base64.b64decode(b+b"="*(-len(b)%4))), "B = U(96)+V(16)+W(16)")' unlock-TIME.age
wc -c unlock-TIME.age   # 434 B with an 8-digit round
# 4. round <-> time, and the chain hash (binds period, genesis, pk, seed, beacon id; not the scheme)
date -u -r $(( G + (R - 1) * P )) +%Y-%m-%dT%H:%M:%SZ
curl -s --noproxy '' --proxy "$PX" https://api.drand.sh/$CH/info > info.json
python3 -I -c 'import json,hashlib,struct,sys; i=json.load(open(sys.argv[1])); print(i["schemeID"], hashlib.sha256(struct.pack(">I",i["period"])+struct.pack(">q",i["genesis_time"])+bytes.fromhex(i["public_key"])+bytes.fromhex(i["groupHash"])+i["metadata"]["beaconID"].encode()).hexdigest()==i["hash"])' info.json
# 5. before τ(R): drand answers 425 and tle says "too early" (and leaves an empty output file)
curl -s -o /dev/null -w 'HTTP %{http_code}\n' --noproxy '' --proxy "$PX" https://api.drand.sh/$CH/public/$R
tor_ tle --decrypt --output=/dev/null unlock-TIME.age
# 6. after τ(R) + 3 s: the TIME path, then the payload
sleep $(( G + (R - 1) * P + 3 - $(date -u +%s) )) 2>/dev/null
tor_ tle --decrypt --output=id.key unlock-TIME.age && mkdir r && age -d -i id.key vault.tar.gz.age | tar xzf - -C r
# 7. the manifest, iterating ROWS so a missing item is caught
tail -n +2 r/MANIFEST.csv | while IFS=, read -r id h _; do
  [ "$(shasum -a 256 "r/items/$id.json" 2>/dev/null | cut -d' ' -f1)" = "$h" ] && echo "ok $id" || echo "BAD $id"; done
cd / && rm -rf "$X"
```
The repository's own end-to-end checks are `sh 1password-timelock.sh --self-test` and
`sh timelock-key.sh --self-test`: a fake `op`, a synthetic vault with attachments and every
documented identifier type, real drand through Tor under a Tor-only sandbox, and the literal
`SEALED.txt` rehearsal.

## 6. Parameters

| Name | Value |
|---|---|
| chain hash `CH` | `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971` |
| `CH` formula | `SHA-256(BE32(3) ‖ BE64(1692803367) ‖ pk ‖ groupHash ‖ "quicknet")` |
| genesis | `1692803367` = 2023-08-23T15:09:27Z (round 1) |
| period | 3 s |
| scheme | `bls-unchained-g1-rfc9380`: signatures in G1 (48 B), `pk` in G2 (96 B); pinned (`SCHEME`) |
| `pk` | `83cf0f28…ece45a` (96 B, in `chain-info.json`, pinned as `PUBKEY`, re-fetched through Tor 2026-10-09) |
| groupHash (genesis seed) | `f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e` |
| `H1` DST | `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_` |
| identity | `id(R) = SHA-256(BE64(R))` |
| round from time | `R(T) = ⌊(T − 1692803367)/3⌋ + 1`, `T = now + L + J` |
| time of round | `τ(R) = 1692803367 + 3(R − 1)`; `τ(R) ≤ T < τ(R) + 3` |
| example | `T` = 2036-10-09T00:00:00Z (2107123200) gives `R = 138106612`, `τ(R) = T` |
| random offset | `J ∈ [0, J_max]`, `J_max = min(86400, ⌊L/10⌋)` s by default; `--jitter` |
| local margin | `MARGIN_ROUNDS = 5` (15 s) |
| duration units | y = 31,556,952 s; d = 86,400; h = 3,600; m = 60; s = 1; cap 100 y = 3,155,695,200 s |
| tlock body | `U ‖ V ‖ W` = 96 + 16 + 16 = 128 B; `ς` 128 bit; H2/H4 = SHA-256 truncated to 16 B |
| age | file key 128 bit; X25519 share 32 B; wrap body 32 B; payload nonce 16 B; chunk 65,536 B; chunk nonce 12 B |
| `I_D` | one line `AGE-SECRET-KEY-1…` + LF, 75 B |
| armor | PEM `AGE ENCRYPTED FILE`, padded base64, 64 columns, LF |
| tar | ustar, owner 0/0 `nobody`, mtime 946684800 (1password), gzip `MTIME` 0, `OS` = 3, padded to 10,240 B |
| drand future round | HTTP 425 `Requested future beacon` **(m)**; required by `assert_shut` |
| tle | HTTP timeout 5 s; any signature-fetch error is reported as "too early" |
| Tor | SOCKS5h `127.0.0.1:9050`, user `drand.<UTC minute>` (stream isolation) |

## Sources

- [AGE] C2SP, *age* v1, https://c2sp.org/age: "Encrypted file format", "Native recipient types"
  (X25519; scrypt; MLKEM768-X25519), "ASCII armor". Release notes for age v1.3.0:
  https://github.com/FiloSottile/age/releases/tag/v1.3.0.
- [TLOCK] N. Gailly, K. Melissaris, Y. Romailler, *tlock: Practical Timelock Encryption from
  Threshold BLS*, IACR ePrint 2023/189, https://eprint.iacr.org/2023/189 (§2.1, §2.2, §2.3, §5.1 Thm 1,
  §6.1, §7). A single, unrevised preprint; read from the Protocol Labs copy
  (research.protocol.ai, gailly2023.pdf), whose section and theorem numbers match.
- [TLE] github.com/drand/tlock v1.2.0: `tlock.go`, `tlock_age.go`, `networks/http/http.go`, `cmd/tle`.
- [KYB] github.com/drand/kyber v1.3.1: `encrypt/ibe/ibe.go`.
- [DRAND] github.com/drand/drand/v2 v2.0.2: `crypto/schemes.go`, `common/chain/info.go`, `common/time.go`,
  `common/key/group.go` (`MinimumT(n) = (n>>1)+1`).
- [GOC] github.com/drand/go-clients v0.2.0: `client/http/http.go`.
- [BF01] D. Boneh, M. Franklin, *Identity-Based Encryption from the Weil Pairing*, CRYPTO 2001.
- [Gal05] D. Galindo, *Boneh-Franklin Identity Based Encryption Revisited*, ICALP 2005.
- [BLS04] D. Boneh, B. Lynn, H. Shacham, *Short Signatures from the Weil Pairing*, J. Cryptology 2004.
- [Bol03] A. Boldyreva, *Threshold Signatures, Multisignatures and Blind Signatures Based on the
  Gap-Diffie-Hellman-Group Signature Scheme*, PKC 2003.
- [GJKR07] R. Gennaro, S. Jarecki, H. Krawczyk, T. Rabin, *Secure Distributed Key Generation for
  Discrete-Log Based Cryptosystems*, J. Cryptology 2007.
- [LGR21] J. Len, P. Grubbs, T. Ristenpart, *Partitioning Oracle Attacks*, USENIX Security 2021.
- [HRRV15] V. T. Hoang, R. Reyhanitabar, P. Rogaway, D. Vizár, *Online Authenticated-Encryption and
  its Nonce-Reuse Misuse-Resistance*, CRYPTO 2015 (STREAM).
- [RFC9380] *Hashing to Elliptic Curves*, https://www.rfc-editor.org/rfc/rfc9380.
- [RFC7748] *Elliptic Curves for Security* (X25519), https://www.rfc-editor.org/rfc/rfc7748.
- [RFC5869] *HKDF*, https://www.rfc-editor.org/rfc/rfc5869.
- [RFC8439] *ChaCha20 and Poly1305*, https://www.rfc-editor.org/rfc/rfc8439.
- [PFC] draft-irtf-cfrg-pairing-friendly-curves-11 §4.2.1,
  https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-11.
- [RNSL17] M. Roetteler, M. Naehrig, K. Svore, K. Lauter, *Quantum Resource Estimates for Computing
  Elliptic Curve Discrete Logarithms*, ASIACRYPT 2017, ePrint 2017/598 (abstract).
- [BZG+26] R. Babbush, A. Zalcman, C. Gidney et al., arXiv:2603.28846 (2026), abstract.
- [Lit23] D. Litinski, *How to compute a 256-bit elliptic curve private key with only 50 million
  Toffoli gates*, arXiv:2306.08585 (2023).
- [NIST8547] NIST IR 8547 ipd (2024-11-12), *Transition to Post-Quantum Cryptography Standards*,
  §4.1.2 Table 4, https://csrc.nist.gov/pubs/ir/8547/ipd.
- [GORAND] Go `crypto/rand` documentation, https://pkg.go.dev/crypto/rand.
- [QN] drand blog, *quicknet is live* (2023-10-16), https://docs.drand.love/blog/2023/10/16/quicknet-is-live.
- [FN] drand blog, *fastnet sunset, quicknet new* (2023-07-03), https://docs.drand.love/blog/2023/07/03/fastnet-sunset-quicknet-new.
- [DSA23] drand blog, *tlock security assessment* (2023-05-26), https://docs.drand.love/blog/2023/05/26/tlock-security-assessment.
- [KS23] Kudelski Security, audit report of tlock and tlock-js (2023), IPFS CID linked from [DSA23].
- [DSPEC] drand specification, https://docs.drand.love/docs/specification/ ("the threshold must be
  superior to 50%", "implements the Joint Feldman protocol").
- [OPJSON] 1Password CLI, item JSON template, https://www.1password.dev/cli/item-template-json.
- [OPCONN] 1Password Connect API, *Get vault item by ID* (the `File` object: id, name, size,
  content_path, section), https://www.1password.dev/connect/api-reference/get-vault-item-by-id.
- [OPREF] 1Password CLI, secret reference syntax (file attachments, ids in place of names, the
  `reference` key), https://www.1password.dev/cli/secret-reference-syntax; `op read`
  https://www.1password.dev/cli/reference/commands/read; `op document get`
  https://www.1password.dev/cli/reference/management-commands/document.
