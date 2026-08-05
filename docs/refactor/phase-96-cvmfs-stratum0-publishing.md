# Phase-96 — CVMFS Stratum-0 / Tier-0 publishing (release-manager plane)

**Goal:** give the project the *producing* half of CVMFS. Phases 68/84/85/87
built a near-complete **consume** stack — FUSE client, caching proxy,
conformance corpus, secure (scvmfs) serving — all of it downstream of somebody
else's Stratum-0. This phase adds the release-manager plane: repository
creation, key/whitelist lifecycle, publish transactions, catalog *generation*,
reflog + garbage collection, and a served repo tree that real CVMFS clients
(ours and the official one) can mount — including through the existing
**scvmfs** secure preamble, and with scvmfs-grade authn on the (deferred)
remote-ingest surface.

Terminology: WLCG says *Tier-0*; CVMFS says **Stratum-0**. Same thing here —
the master repository a release manager publishes into, from which Stratum-1s
replicate by plain HTTP GET.

**Provenance:** anchors below read from the tree at working state on
**2026-08-04** (post-phase-92/93/95, several waves uncommitted). Re-verify
anchors at the start of each wave and mark drift `DRIFT:` inline (phase-80
convention). Cross-references use F-numbers from
`docs/refactor/phase-85-cvmfs-swiss-army-features.md` and G-numbers from
`docs/refactor/phase-87-cvmfs-next-gen-storage-and-distribution.md`.

---

## 0.0 This is a scope REVERSAL — say so out loud

Both prior CVMFS phases state the non-goal in identical words: *"Write-back to
Stratum-1 / distributed consensus — the proxy stays a cache."* The read-only
stance is not a convention, it is an **enforced, tested contract**:

- non-GET/HEAD on a cvmfs location → 405 at runtime (`src/protocols/cvmfs/`
  gate; phase-84 srv corpus pins it);
- `brix_allow_write` / `brix_stage` on a cvmfs location → **EMERG at config
  load** (phase-84 `srv_config` pins it).

Phase-96 does **not** relax either. The publishing plane is a *new surface*
(client/tool-side writer + a distinct, gated ingest location), and with every
phase-96 gate off the phase-84 corpus must stay byte-for-byte unchanged —
including the 405 and the EMERG. On landing Wave A, add a reconciliation note
to the §Non-goals blocks of phase-85 and phase-87 pointing here ("the *proxy*
still never writes; publishing landed as a separate plane, phase-96").

## 0.1 Why this is cheaper than it looks — the two writers already in-tree

Every on-disk format is already pinned by parser + corpus, and **two working
repository writers already exist as test fixtures**:

- `tests/cvmfs/brix_mkrepo.c` (~170 lines, C) — mints a genuinely-signed,
  mountable repo: RSA-2048 master+cert keys, self-signed X.509 cert object,
  zlib CAS objects named by SHA-1 of the *stored* bytes at
  `data/<2hex>/<rest><suffix>`, real-DDL SQLite catalog (`catalog`,
  `nested_catalogs`, `properties`, `chunks`, md5path int64-pair keys),
  `.cvmfswhitelist` and `.cvmfspublished` signed with **raw RSA-PKCS#1-v1.5
  over the printed hash text, no DigestInfo** — the exact upstream convention.
- `tests/cvmfs/repo_forge.py` (~420 lines, Python) — declarative tree model
  (`File`/`Symlink`/`Chunk`/`Chunked`/`Dir(nested=True)`), **recursive
  nested-catalog generation** (`FLAG_DIR_NESTED_MOUNT` parent /
  `FLAG_DIR_NESTED_ROOT` child + `nested_catalogs` rows), chunked-file
  emission (`P`-suffix objects + `chunks` rows), configurable
  revision/TTL/expiry, tamper knobs. Signs via `openssl pkeyutl`.

Both are format-pinned against the C parsers and exercised by ~7 live
scenarios plus `tests/cvmfs/mock_stratum1.py --webroot` (which already serves
a forged tree as a synthetic origin). **Phase-96 Wave A is, at its core,
promoting `repo_forge.py`'s logic into `shared/cvmfs/` as product C code** —
with 1188 existing conformance tests acting as the reader-side oracle.

## 0.2 Reusable substrate (verified anchors)

| Need | Already in tree |
|---|---|
| Manifest/whitelist parse + verify | `shared/cvmfs/signature/{manifest,whitelist,verify}.{c,h}` (verify-only today) |
| Catalog **read** (lookup/nested/chunks/md5path/flags) | `shared/cvmfs/catalog/catalog.c` |
| CAS object decode (inflate + hash-verify), hash grammar | `shared/cvmfs/object/object.c`, `shared/cvmfs/grammar/hash.c` |
| CAS write store (atomic temp+rename, quota, dirfd) | `shared/cache/cas_store.c`; packed variant `shared/cache/cas_pack.c` |
| Raw RSA-PKCS#1-v1.5 sign primitive (CVMFS's exact convention) | `src/auth/gsi/gsi_rsa.c` |
| X.509 / key minting | `src/fs/backend/cred_mint.c`, `cred_mint_cert.c`, `src/auth/crypto/` |
| SQLite **write** patterns (WAL, prepared stmts, transactional subtree ops) | `src/fs/backend/pblock/sd_pblock_catalog*.c` — sqlite3 already a hard dep (`client/Makefile` links `-lsqlite3`) |
| Full-repo enumeration (GC mark phase) | `shared/cvmfs/walk/walk.c` |
| Refcount-CAS / last-reference-unlink models | `src/fs/cache/gcas.c` (G13), `src/fs/backend/pblock/pblock_refs.c` |
| Atomic staged-commit semantics | `src/core/compat/staged_file*.c`, `src/fs/vfs/vfs_staged.c` |
| Union overlay: copy-up + whiteouts over a RO cvmfs mount (a transaction's working tree) | `client/apps/fs/brixcvmfs_rw.c` + `_rw_ext.c`, `client/lib/fs/overlay.h` |
| Server-side manifest+whitelist chain verification | `src/fs/backend/cache/sd_cache_manifest.c` (`brix_cvmfs_verify_manifest`) |
| scvmfs secure preamble (TLS / bearer / x509-DN / VOMS) | `src/protocols/cvmfs/secure.c`, `secure_x509.c` — "policy glue only, zero crypto" |
| Serving a local repo tree over HTTP | `src/protocols/cvmfs/module.c` with a configured `brix_export` root (the `deploy/cvmfs/docker/` demo does exactly this) |
| Test origin + oracle harnesses | `tests/cvmfs/mock_stratum1.py`, `tests/cvmfs/harness.py`, `tests/cmdscripts/brixcvmfs_live.py` |

**Genuinely absent (the actual work):** signing entry points in product code ·
catalog *writer* · publish transaction lifecycle · `.cvmfsdirtab` nested-split
policy · hardlink groups / xattr BLOBs / `catalog_counters` · `.cvmfsreflog`
(classified, never read or written) · reflog-anchored GC · content-defined
chunking (no rolling hash anywhere; phase-87 §cross-cutting lists CDC as a
future idea) · repo lifecycle CLI · whitelist re-sign rotation loop ·
replication markers · remote-ingest gateway.

**Prime directives (inherited from phase-85/87, plus publishing-specific):**

1. **Shared core is the leverage.** Writers land beside their parsers:
   `shared/cvmfs/signature/sign.c`, `shared/cvmfs/catalog/catalog_write.c`,
   `shared/cvmfs/object/object_write.c`. Built once, unit-tested against the
   existing verify/parse code in the same directory, usable by CLI and (later)
   gateway alike.
2. **Publishing lives on the client/tool surface, not in nginx workers.** This
   is the G14 ruling (2026-07-27) applied forward: the proxy links only
   `shared/cvmfs/object`; catalog/walk machinery links only into client
   tooling. The release manager is a **`brixcvmfs` subcommand family**
   (`repo`/`transaction`/`publish`/`gc`), per the swiss-army-toolkit vision.
   nginx serves the published tree read-only, exactly as it serves any
   Stratum-1 today. Only S15 (remote ingest, deferred) touches the server, as
   its own gated location — never the cvmfs cache location.
3. **VFS seam is law (INVARIANT #12)** for anything under `src/`; client-side
   tooling writes through its own lib seams (`cas_store`, `catalog_write`),
   never scattered raw I/O.
4. **Guard contract reuse.** Rejected publish/ingest attempts emit the unified
   fail2ban line (`src/net/guard/`); the new `signal=` token lands in
   `guard.h`/`guard_audit.c` **with** the matching `deploy/fail2ban/`
   filter+jail in the same change.
5. **Surface-appropriate gating grammar.** Tool features = `brixcvmfs`
   subcommands/flags + `$BRIXCVMFS_*`; server features (S13/S14/S15) = nginx
   directives, default **off**.
6. **Standard discipline:** ngx-free shared core (libc + OpenSSL/zlib/zstd +
   sqlite3 only; no `goto`, no stubs); every new `.c` lands in the repo-root
   `./config` source list **and** `CMakeLists.txt`/`cmake/` **and**
   `client/Makefile` where client-linked (split_files_three_build_systems);
   3-test set per feature (success + error + security-negative); clean-room —
   **no `libcvmfs` linkage**, formats from our own pinned parsers + the wire.
7. **The official client is the external oracle.** Our corpus pins our
   readers; a *writer* bug that our reader tolerates would be invisible
   in-tree. Every wave's exit criterion includes mounting the published repo
   with the **official cvmfs client** (containerized, S9) in addition to
   brixcvmfs + the proxy.

**Fail-closed gating:** all server-side phase-96 behavior sits behind its own
directive, default off; with all gates off, phase-84 conformance is
byte-for-byte unchanged. Tool-side commands are inert unless invoked.

---

## 0.3 Scope and the feature roster

**In scope — 16 features in 5 waves.** Surface = Tool (`brixcvmfs`/client) /
Shared (`shared/cvmfs/`) / Proxy (nginx).

| # | Feature | Surface | Wave | Gate |
|---|---|---|---|---|
| S0 | Signing core: manifest + whitelist signers | Shared | A | n/a (library) |
| S1 | Catalog writer (DDL + row emission + nested rows) | Shared | A | n/a (library) |
| S2 | CAS object writer (compress → hash → store, suffix classes) | Shared | A | n/a (library) |
| S3 | Repo lifecycle CLI: `mkfs` / keys / whitelist mint + `resign` | Tool | A | `brixcvmfs repo …` |
| S4 | Publish transaction over the RW overlay (open/abort/publish) | Tool | B | `brixcvmfs transaction` / `publish` |
| S5 | Catalog delta application + revision bump + re-sign | Tool | B | (inside S4) |
| S6 | `.cvmfsdirtab` nested-catalog split policy | Tool | B | `--dirtab` |
| S7 | File chunking (fixed-size v1; CDC stretch) | Tool | B | `--chunk-size` |
| S8 | Catalog completeness: hardlink groups, xattrs, counters, schema props | Shared/Tool | C | n/a |
| S9 | Official-client oracle lane (containerized cvmfs mounts our repo) | Test | C | live-lab marker |
| S10 | `.cvmfsreflog` read + write | Shared/Tool | D | (inside S4) |
| S11 | Garbage collection (reflog-anchored mark & sweep, retention) | Tool | D | `brixcvmfs gc` |
| S12 | Tag / history database (`H` field) — named snapshots | Tool | D | `brixcvmfs tag` |
| S13 | Serve the published repo: nginx cvmfs location over the S0 tree + replication markers | Proxy | E | existing directives; `brix_cvmfs_stratum0_root` |
| S14 | **scvmfs on the Stratum-0**: TLS/bearer/x509/VOMS-gated serving of the published repo | Proxy | E | existing `brix_scvmfs_*` |
| S15 | Remote-ingest gateway (lease + object-pack upload), scvmfs-authenticated | Proxy | E′ | `brix_cvmfs_gateway` — **DEFERRED, decision required** |

**Non-goals (phase-96):**
- **No change to the cache/proxy read plane.** The cvmfs cache location stays
  GET/HEAD-only; publishing is a different location or a different tool.
- **No distributed consensus / multi-master.** Single release-manager lock
  (S4); the upstream gateway lease protocol arrives only with S15, deferred.
- **No overlayfs/root requirement.** Transactions ride the existing
  `brixcvmfs_rw` userspace overlay (unprivileged, WSL2-friendly) — not kernel
  overlayfs like upstream `cvmfs_server`.
- **CDC chunking** is stretch (S7 lands fixed-size; the phase-87 §cross-cutting
  CDC idea stays future).
- **S3-backed Stratum-0 storage**: not in this phase. The writer targets a
  POSIX tree first; routing the CAS store through a VFS backend export (and
  thus S3) is a natural follow-on because S2 writes through `cas_store`
  seams, but it is not an exit criterion.

---

## Wave A — writer core + repo lifecycle (the format inversion)

### S0 · Signing core

**Design.** `shared/cvmfs/signature/sign.{c,h}`: `cvmfs_sign_manifest()` and
`cvmfs_sign_whitelist()` producing the exact byte shapes the existing
`verify.c` accepts — body, `--\n` separator, sha1-hex-of-body line, raw
RSA-PKCS#1-v1.5 signature over the *printed hash text* (no DigestInfo). Lift
the primitive from `src/auth/gsi/gsi_rsa.c` (`EVP_PKEY_sign` raw mode) into
the ngx-free core (signature code cannot link `src/auth/`; the function is
~40 lines and moves cleanly). Key loading via OpenSSL PEM; cert-object
emission (`X` suffix) via the S2 writer. Whitelist body: expiry line,
`N<fqrn>`, uppercase-colon fingerprint lines — mirror `whitelist.c`'s parser
fields exactly.

**Tests (3).** (success) sign → `cvmfs_verify_manifest` /
`cvmfs_verify_whitelist` round-trip green, and byte-compare against a
`repo_forge.py` artifact for an identical input; (error) wrong-key sign →
verify fails with the existing error class; (security-neg) signature over
tampered body rejected; a `resign_with` foreign key rejected against the
pinned master fingerprint.

**Effort: S.** The verify side and two reference writers already fix every
byte.

### S1 · Catalog writer

**Design.** `shared/cvmfs/catalog/catalog_write.{c,h}`: create-from-DDL
(schema as `catalog.c` reads it: `catalog`, `nested_catalogs`, `properties`,
`chunks`; md5path int64-pair keys; flags bits), insert dirent rows
(file/dir/symlink modes, mtime, size, hash), nested-catalog rows
(`FLAG_DIR_NESTED_MOUNT`/`FLAG_DIR_NESTED_ROOT` pairing), `properties`
population (revision, TTL, fqrn, schema, previous_revision). WAL + explicit
transaction per catalog, mirroring `sd_pblock_catalog.c` conventions. The
written catalog is then zlib-compressed and CAS-stored with the `C` suffix by
S2 — hash-of-stored-bytes naming, as `brix_mkrepo.c` line-verifies.

**Tests (3).** (success) write → read back via `catalog.c` (lookup, readdir,
nested traversal, chunks) with field-level equality; (error) duplicate md5path
insert surfaces a clean error, partial transaction rolls back leaving a valid
catalog; (security-neg) catalog hash mismatch after tamper is caught by the
existing object verify when fetched.

**Effort: M.** DDL and keying are known; care is in flags/mode fidelity.

### S2 · CAS object writer

**Design.** `shared/cvmfs/object/object_write.{c,h}`:
`cvmfs_object_store(bytes, kind)` → deflate (zlib, stock levels) → hash the
**stored** (compressed) bytes (sha1 default; grammar already handles
rmd160/shake128) → `brix_cas_put`-style atomic write at
`data/<2hex>/<rest><suffix>` (`""` data, `C` catalog, `X` cert, `P` partial
chunk, `H` history, `L` reserved). Reuses `shared/cache/cas_store.c` atomic
temp+rename discipline (dirfd mode) rather than minting new I/O.

**Tests (3).** (success) store → `cvmfs_object_verify` (decompress +
hash-check) green for every suffix class; (error) ENOSPC/short-write leaves no
partial object visible (temp+rename asserted); (security-neg)
`store_uncompressed`-style tamper (the `repo_forge` knob) is rejected by the
reader.

**Effort: S.**

### S3 · Repo lifecycle CLI

**Design.** `brixcvmfs repo mkfs <fqrn> --repo-dir D --keys-dir K`: generate
master keypair + repo cert/key (reuse `cred_mint_cert.c` patterns), emit
`<fqrn>.pub` (rotated-key-dir compatible — `brixcvmfs_mount.c` already
consumes `*.pub` directories), mint the 30-day `.cvmfswhitelist`, write an
empty root catalog (S1) + cert object, sign `.cvmfspublished` at revision 1
(S0). `brixcvmfs repo resign` re-mints the whitelist before expiry (the
operational loop upstream runs from cron); `brixcvmfs repo info` prints
manifest/whitelist state via the existing parsers. Key material handling
follows the credential-tier conventions
(`docs/10-reference/credential-tiers-t-numbers.md`).

**Tests (3).** (success) `mkfs` → brixcvmfs mounts it (empty root readdir),
proxy serves it from `--webroot`-style config; (error) `mkfs` onto a non-empty
repo-dir refuses; `resign` with a missing master key fails cleanly;
(security-neg) expired whitelist → client refuses mount (existing behavior),
then `resign` heals it.

**Effort: S-M.**

**Wave-A exit criterion:** a `mkfs`-created repo, populated by hand-calling
the writer library from a unit driver, mounts under brixcvmfs and serves
through the proxy — no `repo_forge.py` involved. `repo_forge.py` and
`brix_mkrepo.c` then gain a guard asserting they agree byte-for-byte with the
product writers (they become *conformance fixtures for the writer*, not the
only writers).

---

## Wave B — the publish transaction

### S4 · Transaction lifecycle over the RW overlay

**Design.** `brixcvmfs transaction <fqrn>` mounts the repo RO and arms the
existing userspace union overlay (`brixcvmfs_rw.c`: upper tree at
`<mnt>/.brixwrites/upper`, copy-up on first write, whiteout markers) — the
overlay *is* the changeset representation, exactly as upstream derives its
changeset from overlayfs. `brixcvmfs publish` walks upper + whiteouts →
add/modify/delete set; `brixcvmfs abort` = `--overlay-reset` (already
implemented). A repo-dir lockfile (`O_EXCL`, staleness via pid+boot check)
enforces **single publisher** — concurrent `transaction` fails fast with the
upstream-style "is in a transaction" error. Publish applies the changeset
(S5), writes objects (S2), re-signs (S0), then swaps `.cvmfspublished`
last via the `staged_file` atomic-rename discipline so a crashed publish never
leaves a half-visible revision.

**Tests (3).** (success) transaction → add/modify/delete files → publish →
remount shows exactly the new tree at revision N+1, old revision's root
catalog still fetchable by hash; (error) crash between object writes and
manifest swap (kill-injected) leaves revision N fully intact and a re-run
publish completes; (security-neg) second concurrent transaction refused;
publish with a tampered upper-tree object never signs a manifest referencing
a hash that doesn't verify.

**Effort: M-L.** This is the core new machinery of the phase.

### S5 · Catalog delta application + revision bump

**Design.** Load the current root (and affected nested) catalogs via
`catalog.c`, apply the changeset as SQL mutations via S1 (insert/update/delete
rows, directory mtimes, `previous_revision` chain), rewrite affected catalogs
bottom-up (a nested catalog's new hash updates its parent's
`nested_catalogs` row, up to the root), bump revision, TTL from config,
re-sign. Unchanged nested catalogs are untouched — publish cost scales with
the touched subtree, not repo size.

**Tests (3).** (success) touching one file inside a nested catalog rewrites
only that catalog chain (assert by CAS-object count delta); (error) publish
into a repo whose root catalog fails verification refuses (no "repair"
publishing); (security-neg) a crafted upper tree attempting path escape
(`..`, absolute symlink targets are fine *in* CVMFS but the *tool* must not
follow them out of the upper dir during ingestion) is contained —
`beneath`-style resolution on the walk.

**Effort: M.**

### S6 · `.cvmfsdirtab` nested-catalog split policy

**Design.** Honor a repo-root `.cvmfsdirtab` (glob per line, `!` negation —
upstream grammar) to auto-create/dissolve nested catalogs at publish time;
plus a size-based heuristic gate (`--auto-nest N` entries) matching upstream's
recommendation. Implemented as a pre-pass over the S5 changeset.

**Tests (3).** (success) dirtab entry → subtree becomes a nested catalog
(reader sees `FLAG_DIR_NESTED_MOUNT`), removal re-inlines it; (error)
malformed dirtab line → publish refuses with line number; (security-neg)
dirtab glob cannot cause catalog creation outside the repo namespace.

**Effort: S-M.**

### S7 · File chunking

**Design.** Files over `--chunk-size` (default 32 MiB, upstream-compatible)
split into `P`-suffix partial objects + `chunks` rows (offset, size, hash) —
`repo_forge.py` already emits this shape; S7 productionizes it in the S2/S1
writers. Fixed-size boundaries in v1. **Stretch:** CDC (rolling-hash)
boundaries for cross-revision dedup — explicitly the phase-87 "CDC dedup
across revisions" future idea; do not block the wave on it.

**Tests (3).** (success) a 100 MiB file round-trips through brixcvmfs with
correct content and the reader's chunk path (existing `catalog.c` chunk
support) exercised; (error) chunk-size below the floor refused; (security-neg)
one tampered chunk fails that chunk's CAS verify without poisoning siblings.

**Effort: M.**

**Wave-B exit criterion:** `mkfs → transaction → cp -r /usr/share/foo →
publish → mount` end-to-end on both brixcvmfs and the proxy; kill-injection
crash matrix green.

---

## Wave C — catalog completeness vs the official oracle

### S8 · The fields our reader never taught us

**Design.** The consume stack tolerates absence of things a *real* publisher
must emit: **hardlink groups** (inode-group encoding in the dirent),
**xattr BLOBs**, **`catalog_counters`/statistics tables**, full `properties`
population (schema/schema_revision, last_modified), uid/gid/mode fidelity,
`.cvmfscatalog` marker files. Implement against the official catalog schema
(clean-room: schema read from published catalogs of real repos we already walk
live — `atlas.cern.ch`, `cms.cern.ch` in `brixcvmfs_live.py` — not from
libcvmfs source). Extend `catalog.c` reads where our reader is blind
(counters) so the corpus can pin them.

**Tests (3).** (success) a tree with hardlinks + xattrs publishes and the
official client (S9) sees correct link counts and xattrs; (error) counter
drift (mutation-injected) detected by a new `brixcvmfs fsck` check;
(security-neg) oversized xattr BLOB bounded, refused cleanly.

**Effort: M.** Oracle-driven; expect iteration.

### S9 · Official-client oracle lane

**Design.** A containerized lane (rootless podman, reusing the
`tests/cmdscripts/container_runtime.py` seam from phase-92) that mounts our
published repo with the **official cvmfs client** against our nginx serving
it, and diff-walks the tree (paths, sizes, modes, link counts, xattrs,
content-hash sample) against the publish manifest. This is the external
correctness gate directive 7 requires; live-lab marked (network + container),
default-skipped in the fast tier like the other live labs.

**Tests (3).** (success) full diff-walk green post-S4 and post-S8 publishes;
(error) lane cleanly SKIPs (not fails) without podman; (security-neg) official
client refuses our repo after a `flip_byte` tamper (proves we didn't build
something *only we* accept).

**Effort: S-M** (harness), plus the iteration cost it drives back into S8.

---

## Wave D — reflog, GC, tags

### S10 · `.cvmfsreflog`

**Design.** The classifier already routes `.cvmfsreflog`
(`grammar/classify.c`) and `sd_cache_manifest.c:311` notes it is unsigned and
skipped — today it is never read nor written. Add reader+writer in
`shared/cvmfs/` (it is a SQLite DB of referenced root objects:
catalogs/certificates/history/metainfo per revision); S4 publish appends the
new root catalog + cert + history refs; manifest gains the reflog-hash field
so replicas can fetch it. Unsigned per upstream — integrity via the manifest's
reflog checksum field.

**Tests (3).** (success) N publishes → reflog holds N root-catalog refs,
readable by our reader; (error) missing reflog on a GC attempt → refuse with
"reflog required" (upstream behavior); (security-neg) reflog checksum
mismatch vs manifest field → refuse GC (never sweep on an untrusted ref set).

**Effort: S-M.**

### S11 · Garbage collection

**Design.** `brixcvmfs gc <fqrn> --keep N|--keep-since T`: **mark** = union of
reachable objects over the kept revisions' root catalogs via
`shared/cvmfs/walk/walk.c` (subtree-scoped walk already enumerates every
catalog, file, and chunk hash — this is exactly the mark phase); **sweep** =
enumerate `data/` and unlink unmarked (age-guarded against racing an
in-flight publish; takes the S4 lock). Deletes swept revisions from the
reflog. Note `gcas.c` link-count GC and cache eviction are *not* equivalents —
this is revision-set reachability, new code, but the walk does the hard half.

**Tests (3).** (success) 5 revisions, keep 2 → exactly the unreachable
objects vanish, kept revisions still mount (both clients); (error) gc without
lock/against active transaction refused; (security-neg) gc can never delete
an object referenced by a *kept* revision (mutation test: inject a
mark-phase skip, assert the guard test catches it — mirror the
mutation-testing convention from the metrics suite).

**Effort: M.**

### S12 · Tag / history database

**Design.** The manifest's history field points to an `H`-suffix SQLite tag DB
(named snapshots → root hash + revision + timestamp). `brixcvmfs tag
add|list|rollback`: rollback republishes an old root catalog as a new
revision (never rewinds the revision counter). Optional but cheap once
S0-S5 exist, and it is what makes Stratum-0 operationally usable (rollback
after a bad publish).

**Tests (3).** (success) tag → rollback → tree matches the tagged revision at
a *new* revision number; (error) rollback to unknown tag refused;
(security-neg) tag DB tamper → hash mismatch → refused (it is CAS-addressed
like everything else).

**Effort: S-M.**

---

## Wave E — serving, scvmfs, replication surface

### S13 · Serve the published tree + replication markers

**Design.** Mostly configuration + pinning: point the existing cvmfs location
at the S0 repo tree (the module already serves a local namespace when
`brix_export` is rooted — the `deploy/cvmfs/docker/` shape). Add
`brix_cvmfs_stratum0_root` as an explicit alias directive so the intent is
visible in config and the location can refuse cache-fill upstream directives
in the same block (a Stratum-0 has no upstream). Emit
`.cvmfs_master_replica` marker so real Stratum-1s (`cvmfs_server add-replica`)
recognize it as a replication source; document the replication story: a
correct on-disk repo + HTTP GET *is* the Stratum-1 feed — no push protocol
needed. GeoAPI answering (`geo.c`) already exists and applies unchanged.

**Tests (3).** (success) phase-84-style srv suite pointed at the S0 tree
(manifest, whitelist, CAS, geo classes all green) + brixcvmfs mount through
it; (error) `brix_cvmfs_stratum0_root` combined with upstream fill directives
→ EMERG at config load; (security-neg) the location still 405s every write
method — publishing never leaks into the serve plane.

**Effort: S.**

### S14 · scvmfs on the Stratum-0

**Design.** The scvmfs preamble is deliberately transport-agnostic policy glue
(`secure.c`: "scvmfs can never drift behaviorally from cvmfs because it IS
cvmfs after this function") — so gating the *published* repo behind TLS +
bearer/SciToken (`brix_scvmfs_token_issuers`), x509 EEC-DN glob
(`brix_scvmfs_x509_dn`), or VOMS VO (`brix_scvmfs_voms`) should be pure
configuration. The phase-96 work is **proving and pinning that**: a secure
Stratum-0 lab (reusing the `tests/test_cvmfs_scvmfs_x509.py` /
`_voms.py` fixture patterns and GSI test credentials) serving an S3-minted
repo, plus documenting the private-repo Stratum-0 deployment shape in
`deploy/cvmfs/`. Any gap scvmfs shows against the S0 tree (e.g. authz
interaction with GeoAPI or reflog paths) is fixed in `secure*.c` under its
existing 3-test discipline.

**Tests (3).** (success) x509- and VOMS-gated mounts of the S0 repo succeed
with valid creds (both clients); (error) no-cred/expired-proxy → clean 401/403
class, fail2ban line unchanged; (security-neg) wrong-VO VOMS AC and
non-matching EEC DN refused; `.cvmfspublished` is **not** fetchable
anonymously when gated (no manifest leak around the preamble).

**Effort: S-M** (expected mostly config + tests; budget for small `secure*.c`
fixes).

### S15 · Remote-ingest gateway — **DEFERRED, requires its own decision**

**Sketch only.** Upstream's model: publishers on other machines lease a
path-scoped write session from a **gateway** (HTTP API), upload object packs,
and the gateway serializes catalog application. Ours would be a new gated
location (`brix_cvmfs_gateway on`, distinct from the cache location so the
405/EMERG contracts stand), **scvmfs-authenticated** (publisher authn = the
S14 preamble: x509/VOMS/bearer — this is where "including scvmfs" earns its
keep on the write side), speaking lease/upload/commit against the Wave-B
transaction core, with the unified guard line on refused publishers (new
`signal=pubauth` + fail2ban filter+jail in the same change). It reverses "the
proxy never writes" for one location and adds concurrent-publisher
arbitration — **large (L-XL), and not needed for a single-node Tier-0**.
Decision to green-light it belongs to a future phase; this doc only reserves
the design seam: everything S15 needs (writer library, transaction, lock,
authz preamble, guard contract) exists by end of Wave E.

---

## Cross-cutting

- **Fleet/test wiring:** new test servers register in `tests/fleet_specs.py`
  (`NginxInstanceSpec` via `RegistryLauncher`) — note the standing caveat that
  cvmfs conformance files currently spawn their own `LiveRun` instances;
  follow whichever pattern the touched suite already uses, do not mix within
  a file. New files claim a 20-port block in
  `docs/10-reference/test-fleet-ports.md` (cvmfs srv 13100+ / fuse 13300+
  neighborhoods).
- **Build wiring is part of the feature:** every new `.c` → `./config` +
  `CMakeLists.txt`/`cmake/` + `client/Makefile` (guards
  `check_config_coverage.py` / `check_client_build_coverage.py`); `bash -n
  config` after every `./config` edit; sqlite stays behind
  `BRIX_HAVE_SQLITE` on the nginx side (it is unconditional in
  `client/Makefile` already).
- **Guard fleet:** writer sources are subject to the CCN ≤ 15 and 600-line
  caps from day one — split `catalog_write` early rather than grandfathering.
- **CODEOWNERS** routes review for auth (S0 keys), parsers (S1/S10), build
  wiring, guard fleet — expect multi-area review on Waves A and E.
- **Docs:** `deploy/cvmfs/README.md` gains a Stratum-0 runbook section
  (mkfs → publish → serve → resign cron → gc cron); `docs/04-protocols/cvmfs.md`
  gains a "Stratum-0 mode" section; phase-85/87 §Non-goals get the
  reconciliation note (§0.0).
- **Corpus growth:** each wave adds its tests beside the phase-84 corpus
  (`tests/test_cvmfs_publish_*.py` naming), tagged into the slow/nightly tier
  like the rest; the writer↔forge byte-agreement guard keeps
  `repo_forge.py`/`brix_mkrepo.c` honest forever.

## Effort × impact (recommended sequencing)

| Wave | Features | Effort | What you can demo at the end |
|---|---|---|---|
| A | S0-S3 | **S-M** | `mkfs`-created signed repo mounts everywhere; product writers exist |
| B | S4-S7 | **M-L** | Full `transaction → publish` loop; crash-safe; nested + chunked |
| C | S8-S9 | **M** | The **official cvmfs client** mounts our published repos |
| D | S10-S12 | **M** | GC + rollback — operationally real Tier-0 |
| E | S13-S14 | **S-M** | Served (incl. scvmfs-secured) Stratum-0; Stratum-1s can replicate it |
| E′ | S15 | L-XL | *(deferred)* multi-publisher remote ingest |

Waves A+B are ~40% of the effort and deliver ~80% of the demonstrable
capability (a working single-node Stratum-0). Wave C is where correctness
risk concentrates (fields with no in-tree oracle); schedule S9 *early inside*
Wave C, not after it. Total shape: one phase-87-sized epic minus its Wave-C
kernel work — the formats are already conquered; the lifecycle is the work.

## Status

**DELIVERED (2026-08-04) — Waves A–E (S0–S14) landed and green; S15 remains
deferred per §S15.** Delivery notes worth keeping (the traps future work will
hit):

- **S9 / two signature schemes (Wave C).** The official client uses *two
  different* RSA conventions: the manifest signature is PKCS#1-v1.5 over a
  SHA-1 `DigestInfo` whose DER we hand-build (OpenSSL 3's default provider
  refuses SHA-1 signing via the EVP digest-sign path — policy, not math),
  while the whitelist signature is a *raw* RSA private-key operation over the
  ASCII hash text (no DigestInfo at all). Conflating them produces repos that
  verify in our stack and fail in the official client, or vice versa.
- **S9 / three official-client catalog conventions** the SQL schema does not
  document: the root catalog's own row carries `parent_1 = parent_2 = 0`;
  the `symlink` column is `''` and never NULL; the nested root's
  `root_prefix` property row is required for sub-catalog mounts.
- **Wave D.** `.cvmfsreflog` ordering is `ORDER BY timestamp DESC, rowid
  DESC` — the rowid tie-break matters because same-second publishes are
  routine in tests and replication replays. GC drops refs *before* sweeping
  CAS so a crash mid-GC leaves garbage (re-collectable), never a dangling
  ref. Tags pin their revision's root catalog against GC.
- **S13.** `brix_cvmfs_stratum0_root` is a strict alias for `brix_export`
  (fs path = root + full URI, so the repo lives at `<root>/cvmfs/<fqrn>/`);
  it EMERGs at `nginx -t` when combined with cache-fill grammar
  (`brix_cache_store`, http(s) `brix_storage_backend`,
  `brix_cvmfs_upstream_allow`) or a second root. The
  `.cvmfs_master_replica` marker is *synthesized in gate.c* from the REJECT
  branch — never on disk, never in the shared URL classifier (which the FUSE
  client and the 12,800-case fuzz corpus also depend on) — so it is
  directive-gated: a plain `brix_export` cache node cannot be spoofed into
  advertising itself as a replication source. Lane:
  `tests/test_cvmfs_stratum0_serve.py` (includes a real brixMount leg).
- **S14.** Proven pure configuration — zero `secure*.c` changes needed. The
  scvmfs preamble runs before the gate (`handler.c`), so manifest, CAS,
  GeoAPI *and the replication marker* all sit behind the credential wall;
  `.cvmfspublished` is not fetchable anonymously when gated. Lane:
  `tests/test_cvmfs_stratum0_scvmfs.py` (x509 + VOMS legs, port block
  `srv_s0_scvmfs` 13580).

**Follow-on (2026-08-05) — shipped surface + payload fsck.** Writing the
operator cookbook
([docs/05-operations/cvmfs-stratum0.md](../05-operations/cvmfs-stratum0.md))
against the *installed* binary rather than the standalone repotool build turned
up two gaps and closed both:

- `brixcvmfs` now exists as an `argv[0]` personality of `brixMount` (symlink
  from `client/Makefile` `OPT_LINKS`, dispatch in `brixmount.c`) with its own
  banner, usage and man page — until then the documented `brixcvmfs repo …`
  command line only worked in the test harness.
- **S8's `fsck` verified catalogs but never the payload**, so a flipped or
  deleted CAS object was invisible to the publisher and surfaced only as a
  client-side `EIO`. `cvmfs_fsck_run()` grew a `check_data` argument
  (`brixcvmfs repo fsck <dir> --data`): the certificate ('X'), every regular
  file's whole-file object and every chunk ('P') is checked for presence and
  CAS identity via the new `pub_verify_object()`, which hashes the *stored*
  form and never inflates. Opt-in on purpose — it is linear in repository
  size, so plain `fsck` stays cheap enough for every publish. Trap for future
  lanes: **gc retains older-revision objects**, so a random file under `data/`
  may be legitimately unreferenced; use `fsck --data` itself as the
  reachability oracle when picking a victim object.
- Lane: `tests/test_cvmfs_stratum0_quickstart.py` (14 tests, port block
  `srv_s0_quickstart` 13600) drives the shipped binary through the documented
  sequence — personality, publish of custom files (modes/symlink/chunking),
  add+modify+whiteout republish, tag/resign/gc, lifecycle refusals, 405s, and
  the tamper leg (fsck `--data` *and* client refusal). It also pins the
  layout's implicit security claim: the documented `keys/` (master key
  included) and a mid-publish `.brixtxn/upper/` live *inside* the served
  directory, and stay 403 because the gate answers only CVMFS traffic shapes.

Original prerequisite decisions, resolved as implemented: (1) scope-reversal
framing per §0.0 stands — phase-85/87 §Non-goals carry the reconciliation
note; (2) publishing landed on the tool surface (repotool CLI + shared
writers), no server-side publish directive exists; (3) S15 remains out of
scope until separately green-lit.
