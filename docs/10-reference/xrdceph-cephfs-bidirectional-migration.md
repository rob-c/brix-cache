# XrdCeph ⇄ CephFS migration — hyper-detailed reference

Zero-data-loss, **no-petabytes-over-the-wire** migration between stock **XrdCeph**
(`libradosstriper`) and **CephFS**, in either direction, using RADOS object
redirects + in-cluster materialisation.

Companion operational runbooks:
- forward (XrdCeph → CephFS): [`cephfs-migration-glasgow-ral.md`](cephfs-migration-glasgow-ral.md)
- reverse (CephFS → XrdCeph): [`cephfs-to-xrdceph-migration.md`](cephfs-to-xrdceph-migration.md)

> **Python implementations.** Both tools also exist as pure-Python 3 CLIs with
> identical semantics and CLI grammar — `tests/ceph/xrdceph_striper_migrate.py`
> and `tests/ceph/xrdceph_cephfs_to_striper.py` — needing only the distro
> `python3-rados` / `python3-cephfs` packages (the C++-only redirect ops are
> reached through `tests/ceph/pymigrate/radosbridge.py`; see the "Python
> migration tools" section of [`tests/ceph/README.md`](../../tests/ceph/README.md)).
> They add `--json` machine output, a resumable `--state` manifest,
> `--prefix`/`--match` worklist filters, progress reporting, and an O(N)
> source-pool index.
>
> **Site-profile config (all four tools):** `--config PATH` (or
> `$XRDCEPH_MIGRATE_CONF`) reads a flat `key = value` profile
> (`striper_pool meta_pool data_pool conf client fs_name dest_prefix strip`;
> unknown key = hard error). Precedence: explicit CLI > file > default; give
> the full positional arity or none. This also makes the ceph **client id**
> (previously hardcoded `admin`) and the CephFS **fs name** (multi-fs
> clusters, forward direction) configurable. C++ parser:
> `tests/ceph/xrdceph_migrate_config.h`; Python:
> `pymigrate.common.load_tool_config`. e2e coverage: `tests/ceph/run_py_migrate.sh`. Two fixes
> beyond C++ parity: forced re-migrate/rollback detach stubs via a
> **data-pool ino index** (the source-index detach loses stubs once sources
> are gone — [HAZARD] the async MDS purge then delete-throughs into
> same-named re-created source objects; the C++ tool shares this), and
> `--list` names files verbatim so rollback works after source deletion.

Legend for the labelled callouts used throughout:

```
[FACT]        a property of Ceph / the layouts that is always true
[VERIFIED]    empirically proven on Ceph reef 18.2.4 in this work
[REQUIREMENT] an operating precondition the tools enforce or assume
[HAZARD]      a way to lose/corrupt data, with its containment
[RULE]        the operating rule that keeps you safe
```

---

## 0. Table of contents

```
1.  The one-paragraph mental model
2.  Cluster topology: what moves, what doesn't
3.  The two on-RADOS layouts (byte-level)
4.  Why you cannot just "rename" — and why index-mapping is exact
5.  The three RADOS primitives
6.  Redirect semantics: read / write / delete  (the danger zone)
7.  The migration lifecycle (state machine)
8.  Tool 1 — xrdceph_striper_migrate (XrdCeph -> CephFS)
9.  Tool 2 — xrdceph_cephfs_to_striper (CephFS -> XrdCeph)
10. The CephFS-from-RADOS decoder (powers the reverse walk)
11. "No PB over the wire": the data-movement ledger
12. Data-safety model: hazards -> containment
13. Forward workflow (full flowchart + commands)
14. Reverse workflow (full flowchart + commands)
15. Round-trip and the no-data-loss invariant
16. Validated vs. validate-before-production
17. Source map + command reference
```

---

## 1. The one-paragraph mental model

```
                A file is just a set of RADOS objects in a pool.
   XrdCeph and CephFS disagree only on WHAT THOSE OBJECTS ARE NAMED and
            WHERE THE FILE'S METADATA LIVES — not on the bytes.

   So "migrating" = give the file's bytes a second NAME in the other
   layout's scheme (+ a little metadata).  Two ways to do that:

       (a) REDIRECT  the new name at the old object   -> 0 bytes moved
       (b) COPY      the bytes to the new name (OSD->OSD, in-cluster)

   Neither ever touches the site's external uplink.
```

---

## 2. Cluster topology: what moves, what doesn't

[FACT] XrdCeph and CephFS both store data as ordinary RADOS objects in pools in the
**same Ceph cluster**. Migration is intra-cluster.

```
                 ┌──────────────────────── SITE ────────────────────────┐
                 │                                                       │
   WAN / 10GbE   │   ┌───────────────  CEPH CLUSTER  ────────────────┐  │
  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄ │ ← │  internal cluster network (≫ external uplink)  │  │
   (clients,     │   │                                                │  │
    other sites) │   │   pool: striper        pool: cephfs_data       │  │
                 │   │   (XrdCeph LFN-keyed)   (CephFS inode-keyed)    │  │
                 │   │        ▲   │                 ▲   │              │  │
                 │   │        │   └── redirect/copy │   │              │  │
                 │   │        └────────────────────┘   │              │  │
                 │   │            (OSD <-> OSD)         │              │  │
                 │   │                          pool: cephfs_metadata  │  │
                 │   │                          (MDS namespace)        │  │
                 │   └────────────────────────────────────────────────┘  │
                 └───────────────────────────────────────────────────────┘

   MIGRATION DATA PATH:  striper-pool  <───OSD↔OSD───>  cephfs_data
   EXTERNAL UPLINK:      *** never used by the migration ***
```

[RULE] The migration host only ever issues *metadata* ops (redirect) or *triggers*
in-cluster copies (`copy_from`/`tier_promote`); file bytes flow OSD↔OSD.

---

## 3. The two on-RADOS layouts (byte-level)

A single 10 MiB file, default 4 MiB objects, in each layout:

```
 XrdCeph (libradosstriper), soid = logical path "atlas/x.root"
 ┌──────────────────────────────────────────────────────────────────────┐
 │ pool: striper                                                          │
 │  atlas/x.root.0000000000000000   [ 4 MiB ]  + xattrs:                  │
 │      ▲ 16 hex stripe index                   striper.layout.object_size│
 │                                              striper.layout.stripe_unit │
 │  atlas/x.root.0000000000000001   [ 4 MiB ]   striper.layout.stripe_cnt │
 │  atlas/x.root.0000000000000002   [ 2 MiB ]   striper.size              │
 │                                              (lock.striper.lock)        │
 │  NAMESPACE: none — the soid IS the key.                                │
 └──────────────────────────────────────────────────────────────────────┘

 CephFS, inode 0x10000000abc (allocated by the MDS)
 ┌──────────────────────────────────────────────────────────────────────┐
 │ pool: cephfs_data                                                      │
 │  10000000abc.00000000   [ 4 MiB ]  + xattrs: parent (backtrace), layout│
 │      ▲ 8 hex object no.                                                 │
 │  10000000abc.00000001   [ 4 MiB ]                                      │
 │  10000000abc.00000002   [ 2 MiB ]                                      │
 │                                                                        │
 │ pool: cephfs_metadata  (the MDS owns this)                            │
 │  <dir-ino>.00000000  OMAP: "x.root_head" -> encoded inode_t            │
 │      (inode_t carries file_layout_t = object_size/stripe_unit/count,   │
 │       size, mode, mtime, xattrs, ...)                                   │
 └──────────────────────────────────────────────────────────────────────┘
```

| Property | XrdCeph (striper) | CephFS |
|---|---|---|
| object name | `<soid>.<stripe %016x>` | `<ino %x>.<objno %08x>` |
| key is | the **LFN/path** | an **MDS-allocated inode** |
| geometry+size | xattrs on first object | MDS `inode_t` (`file_layout_t`) |
| namespace | none (path = key) | MDS (omaps + journal + inotable) |

---

## 4. Why you cannot just "rename" — and why index-mapping is exact

[FACT] **RADOS has no rename.** An object's name is fixed at creation; the only ways
to get the same bytes under a different name are **copy** or **redirect**.

[FACT] **Both layouts use Ceph's identical striping algorithm.** For the same
`(object_size, stripe_unit, stripe_count)`, file offset → object index is computed
the same way in both. Therefore:

```
   byte range of object index N  ==  identical in XrdCeph and CephFS
   only the NAME of object N differs:

        XrdCeph   <soid>.<N : 16 hex>     ─┐
                                           ├─ same bytes, 1:1 by index N
        CephFS    <ino>.<N : 8 hex>       ─┘

   => migration is a per-index NAME bridge, with NO byte re-chunking.
```

[VERIFIED] Byte-exact for `stripe_count` 1, 2 and 4 with `object_size ≥
stripe_unit` (multiple stripes per object + N-way interleave + object-set
wrapping), using a position-dependent pattern (each 8-byte word = its offset) that
would expose any mis-ordering.

---

## 5. The three RADOS primitives

```
 set_redirect(dst -> target)         tier_promote() + unset_manifest()    copy_from(src -> dst)
 ─────────────────────────────       ─────────────────────────────────   ────────────────────
 dst becomes a POINTER to target     materialise: OSD copies target's     atomic OSD->OSD copy
 reads are served from target        bytes into dst locally, then         of one object
 *** 0 bytes copied ***              detach the pointer => OWNED object    (in-cluster)
 (cross-pool, same cluster)          (in-cluster)                          used by --mode copy
```

[VERIFIED] Reads follow a `set_redirect` transparently for **plain librados**, the
**CephFS kernel/libcephfs client**, and **`libradosstriper`** — all three.

[FACT] `set_redirect` / `tier_promote` / `unset_manifest` are exposed in the C++
`librados` `ObjectWriteOperation` API (reef). The C API has none of them; the tools
are therefore C++.

---

## 6. Redirect semantics: read / write / delete  (the danger zone)

```
            read  R          write  W            delete  D
            ─────            ─────               ──────
  stub ─R─▶ target           stub ─W─▶ target    stub ─D─▶ target
  (served from target)       (WRITE-THROUGH!)    (DELETE-THROUGH!)
```

[VERIFIED][HAZARD] **Write-through.** A write to a redirect stub is applied to the
**target object**, not copy-on-written. (A marker written through CephFS appeared
in the source striper object's bytes.)
> [RULE] A redirect-migrated file is **READ-ONLY** until finalised. Serve the
> staged side read-only (read-only export/mount/caps).

[VERIFIED][HAZARD] **Delete-through.** Deleting a redirect stub deletes its
**target** — confirmed with AND without `--with-reference`, and even with the source
pool's `nodelete` flag set.
> [RULE] Never plain-`unlink` a redirect-migrated file. Roll back only with the
> tool's `--rollback`, which **detaches each stub (`unset_manifest`) FIRST**, then
> deletes — so the purge removes only empty stubs and the source survives.

[VERIFIED] **MDS backtrace coexists.** The MDS lazily writes a `parent` backtrace to
the first object; on a redirect stub this adds the xattr **without** breaking the
data read (survives MDS journal flush + cache drop). Data bytes are untouched and
XrdCeph still reads the object.

```
   SAFE-ROLLBACK SEQUENCE (per stub)
   ┌────────────────────┐   ┌──────────────┐   ┌────────────────────────┐
   │ unset_manifest(stub)│ → │ delete stub  │ → │ source target SURVIVES │
   │  (detach pointer)   │   │ (now empty)  │   │  (VERIFIED post-purge) │
   └────────────────────┘   └──────────────┘   └────────────────────────┘
   WITHOUT the detach:  delete stub ─D─▶ target GONE  (data loss)
```

---

## 7. The migration lifecycle (state machine)

A file moves through these states in EITHER direction. The names below are
direction-neutral ("source" = the layout you're leaving, "dest" = the one you're
adopting).

```
   ┌───────────┐   redirect    ┌────────────────────┐   finalize   ┌──────────────┐
   │  SOURCE   │ ────────────▶ │  STAGED (redirect) │ ───────────▶ │   OWNED      │
   │  only     │  0 bytes      │  dest name -> src  │  OSD↔OSD     │  dest owns   │
   │           │               │  READ-ONLY         │  copy        │  its objects │
   └───────────┘ ◀──────────── └────────────────────┘              └──────┬───────┘
        ▲          rollback                                                │
        │        (detach+del)                                             │ drop source
        │                                                                  ▼
        │                                                          ┌──────────────┐
        └────────── (still readable until you drop it) ────────────│  COMPLETE    │
                                                                    │ source gone, │
                                                                    │ dest R/W     │
                                                                    └──────────────┘

   STATE        data copies   writable?   reversible?   source needed?
   ──────       ───────────   ─────────   ───────────   ─────────────
   SOURCE       1 (source)    yes(src)    n/a           yes
   STAGED       1 (shared!)   NO          yes(rollback) YES (it is the data)
   OWNED        2 (transient) yes(dest)   no            no (droppable)
   COMPLETE     1 (dest)      yes(dest)   no            gone
```

[RULE] The data-loss-free invariant lives in this diagram: **never leave STAGED
while writing, and never drop the source before OWNED + verified.**

---

## 8. Tool 1 — `xrdceph_striper_migrate`  (XrdCeph → CephFS)

`tests/ceph/xrdceph_striper_migrate.cpp`.

[KEY INSIGHT] CephFS data objects are named by MDS-allocated inode, and inodes +
dentries + backtraces are MDS-owned. So **let the MDS build the namespace**: create
an empty CephFS file with a matching layout; the MDS allocates everything. The tool
then only bridges the data-object names and sets the size.

```
 PER-FILE (forward)                         pool: striper        pool: cephfs_data
 ─────────────────────────────────         ─────────────        ────────────────
 1. read geometry+size+xattrs  ◀───────────  <soid>.000...0
 2. MDS: create cpath, set layout ───────────────────────────▶  (MDS allocs ino,
    ino = statx(cpath)                                            dentry, backtrace)
 3. bridge each object index N:
      REDIRECT: <ino>.<N8>  ──set_redirect──▶  <soid>.<N16>   (0 bytes)
      COPY:     <soid>.<N16> ──copy_from────▶  <ino>.<N8>     (OSD↔OSD)
 4. carry user.XrdCks.* onto cpath
 5. ceph_truncate(cpath, size)
 6. [--verify] read cpath via CephFS, adler32 == carried?
 7. [--delete-source, copy only] remove <soid>.* striper objects
```

Modes & actions:

```
 --mode redirect (default)  ZERO-MOVE; cephfs objects are stubs -> striper. STAGED/RO.
 --mode copy                owned cephfs objects via copy_from (OSD↔OSD). -> OWNED.
 --finalize                 tier_promote + unset_manifest stubs -> OWNED (read-write).
 --rollback                 detach stubs FIRST, then unlink (source intact).
 --verify --delete-source --force --dry-run --threads N --list FILE --strip PFX
```

[VERIFIED] redirect (sc 1/2/4), durable across flush+cachedrop; copy mode; finalize
(writes go local, source droppable); safe rollback (source survives purge);
idempotent re-run; dry-run; delete-source.

---

## 9. Tool 2 — `xrdceph_cephfs_to_striper`  (CephFS → XrdCeph)

`tests/ceph/xrdceph_cephfs_to_striper.cpp`.

[REQUIREMENT] **The CephFS must be UNMOUNTED / quiesced** (stop clients, `ceph fs
fail`, flush the journal). The MDS actively owns the data objects, so it must not be
running while we front them. The tool refuses without `--assume-quiesced` and reads
the namespace straight from RADOS (no mount).

```
 THREE PASSES (reverse)
 ─────────────────────────────────────────────────────────────────────────
 PASS 1  index cephfs_data:        for every  <ino>.<objno>  -> map ino->[objno]
 PASS 2  walk namespace from RADOS: root ino 1 ──┐
            read dir-frag OMAP <dir>.<frag>       │ cephfs_decode_dentry()
            for each "<name>_head" value: ────────┘ -> child ino, type, layout, xattrs
            recurse dirs; emit files (path=soid, ino, layout, size, XrdCks)
 PASS 3  per file (parallel):
            REDIRECT: <soid>.<N16> ──set_redirect──▶ cephfs_data <ino>.<N8>   (0 bytes)
            stamp striper.layout.* + striper.size (+ XrdCks) on <soid>.000...0
            [--verify] libradosstriper read <soid>, adler32 check
            [--finalize] tier_promote+unset_manifest -> OWNED striper objects
            [--delete-source, finalize] delete cephfs_data <ino>.* objects
```

```
  namespace walk (PASS 2)
                      root ino=1
                        │  read OMAP of  1.00000000
            ┌───────────┼─────────────┐
         dir1_head    top.txt_head   ...           (decode each dentry value)
            │            (file)
       recurse 1000..0
            │
        hello.txt_head  sub_head
          (file)         (dir) ── recurse ...
```

[VERIFIED] `/lanc/a.dat` (6 MiB, position pattern + XrdCks): walked from RADOS →
redirect → **libradosstriper reads byte-exact through the redirects at its path** →
finalize → CephFS data deleted → **still byte-exact** (decoupled, owned).

[FACT] Asymmetry vs forward: the reverse **must** be quiesced (no live zero-move),
and the redirect phase is **read-only until finalize** (write-through to cephfs_data
otherwise).

---

## 10. The CephFS-from-RADOS decoder (powers the reverse walk)

Same code as the read-only `cephfsro` rescue backend.

```
 cephfs_denc.{c,h}     Ceph wire primitives: LE ints, length-prefixed strings,
                       ENCODE_START framing (struct_v/compat/len) + forward-skip.
        │
        ▼
 cephfs_layout.{c,h}   typed decoders (version-guarded, struct_v 2..19):
                         dentry value  -> primary inode | remote (hardlink)
                         inode_t       -> ino, mode, size, mtime, file_layout_t
                         file_layout_t -> object_size/stripe_unit/stripe_count/pool
                         fragtree_t    -> directory leaf fragments
                         xattr map     -> user.* (incl user.XrdCks.*)
```

[FACT] Field order + version guards are taken verbatim from the Ceph v18.2.4 source
and cross-checked byte-for-byte against captured fixtures.

---

## 11. "No PB over the wire": the data-movement ledger

```
 STEP                          BYTES MOVED        OVER WHICH NETWORK
 ───────────────────────────   ────────────────   ─────────────────────────
 redirect migrate (either)     0                  none (metadata only)
 --verify (optional)           read each file 1x  in-cluster -> migration host
 finalize (tier_promote)       1 copy / object    OSD <-> OSD (cluster internal)
 --mode copy (forward)         1 copy / object    OSD <-> OSD (cluster internal)
 EXTERNAL UPLINK               0                  *** never ***
```

```
   Cost timeline for a PB estate:

   |== redirect ==|============ run on dest (read-only) ============|== finalize ==|
    instant,        zero extra cost, fully reversible                 in-cluster
    0 bytes                                                            copy once,
                                                                       batch+delete
                                                                       to bound space

   At no point does a PB cross the 10GbE.  Finalize uses cluster-internal
   bandwidth + transient 2x space (bounded by per-batch source deletion).
```

[REQUIREMENT] "Free" assumes source and dest pools are in the **same Ceph cluster**
(they are — redirects and `copy_from` are intra-cluster ops).

---

## 12. Data-safety model: hazards → containment

```
 HAZARD                          ROOT CAUSE                 CONTAINMENT
 ─────────────────────────────  ─────────────────────────  ──────────────────────────
 write corrupts source          redirect write-through     serve STAGED side READ-ONLY
 delete destroys source         redirect delete-through     rollback DETACHES first
 reverse run vs live MDS        MDS owns objects            --assume-quiesced REQUIRED
 MDS xattrs on source (fwd)     backtrace write-through     cosmetic; data + reads OK
 premature source drop          --delete-source too early   gated to copy/finalize +
                                                            only after --verify, batched
 lost update at finalize        promote vs concurrent write finalize only after RO
                                                            validation; no writers
```

[RULE] The single rule that subsumes the table:
```
   KEEP THE SOURCE READABLE UNTIL THE DEST IS  (OWNED && VERIFIED).
   ONLY THEN DROP THE SOURCE.
```

---

## 13. Forward workflow (XrdCeph → CephFS): full flowchart

```
 START (data in striper pool, served by XrdCeph)
   │
   ▼
 [optional instant cut-over]                       [or single-step copy]
   │                                                  │
   ▼                                                  ▼
 redirect-migrate  ──► serve CephFS READ-ONLY      copy-migrate (--mode copy
 (--mode redirect      validate (reads/checksums)   --verify) ─► OWNED directly
   --verify)            │                              │
   │  not happy?        │ happy?                       ▼
   ▼                    ▼                            verify ─► flip READ-WRITE
 --rollback        --finalize ──► OWNED                │
 (detach+unlink)        │         flip READ-WRITE      ▼
   │                    ▼                            --delete-source (batches)
 back to XrdCeph    --delete-source / drop             │
                    striper pool                       ▼
                        │                            drop striper pool
                        ▼                              │
                   DONE: read-write CephFS  ◀──────────┘
                   XrdCeph decommissioned
```

Commands:

```bash
# 1. instant zero-move read-only cut-over
xrdceph_striper_migrate  <striper> <cephfs_data> /<dest>  --list files --verify
# 2. complete to read-write CephFS (in-cluster)
xrdceph_striper_migrate  <striper> <cephfs_data> /<dest>  --list files --finalize
# 3. reclaim / decommission XrdCeph
xrdceph_striper_migrate  <striper> <cephfs_data> /<dest>  --list batch --mode copy \
                          --verify --delete-source
# rollback before finalize
xrdceph_striper_migrate  <striper> <cephfs_data> /<dest>  --list files --rollback
```

---

## 14. Reverse workflow (CephFS → XrdCeph): full flowchart

```
 START (data in cephfs_data, served by CephFS)
   │
   ▼
 QUIESCE: stop clients ; ceph fs fail <fs> ; flush MDS journal   [REQUIREMENT]
   │
   ▼
 redirect-migrate (--assume-quiesced --verify)
   │   walks namespace from RADOS, builds soid=path,
   │   striper names -> cephfs_data objects (0 bytes)
   ▼
 serve XrdCeph READ-ONLY ; validate (libradosstriper reads via redirects)
   │  not happy?                         │ happy?
   ▼                                     ▼
 --rollback (detach+remove stubs)     --finalize (--assume-quiesced)
   │  bring MDS back up                  │  tier_promote -> OWNED striper objects
   ▼                                     ▼
 back to CephFS                        [--delete-source] drop cephfs_data objects
                                         │
                                         ▼
                                       drop CephFS metadata + data pools
                                         │
                                         ▼
                                       DONE: XrdCeph owns the data
                                       CephFS decommissioned
```

Commands:

```bash
# 0. quiesce CephFS first (clients off, fs fail, flush journal)
# 1. zero-move redirect, read-only
xrdceph_cephfs_to_striper  <meta> <cephfs_data> <striper>  --assume-quiesced --verify
# 2. complete + decouple (in-cluster)
xrdceph_cephfs_to_striper  <meta> <cephfs_data> <striper>  --assume-quiesced --finalize \
                            [--delete-source]
# rollback before finalize (then restart the MDS)
xrdceph_cephfs_to_striper  <meta> <cephfs_data> <striper>  --assume-quiesced --rollback
```

---

## 15. Round-trip and the no-data-loss invariant

You can migrate one way, run there, and later migrate back. Each leg is the same
redirect → finalize lifecycle.

```
        forward (live OK)                         reverse (quiesce required)
   XrdCeph ──redirect──▶ CephFS(staged)      CephFS ──quiesce──▶ ──redirect──▶ XrdCeph(staged)
         ◀──rollback──                                   ◀──rollback── (restart MDS)
                 │ finalize                                       │ finalize
                 ▼                                                ▼
            CephFS OWNED  ───── run ─────▶  (later)  ───────▶  XrdCeph OWNED
            drop striper                              drop CephFS
```

[RULE] No-data-loss invariant (applies to every leg):

```
   ┌──────────────────────────────────────────────────────────────┐
   │  while STAGED:  source = the only copy  -> read-only + no del  │
   │  drop source:   only after dest is OWNED (finalised) & VERIFIED│
   └──────────────────────────────────────────────────────────────┘
```

---

## 15a. Identifying what will NOT migrate (snapshots, hardlinks, …)

Both tools **detect and report** Ceph components they do not (or cannot safely)
handle, and **skip** them rather than mis-migrating. The reverse tool's namespace
walk classifies every entry; run `--report-only` for a pure inventory first.

```
 REVERSE (CephFS -> XrdCeph) per-dentry decision tree
 ────────────────────────────────────────────────────
 dir-omap key
   ├─ not "<name>_head"  ──► is "<name>_<hex snapid>"? ──► [SNAPSHOT dentry]  count, skip
   └─ "<name>_head" -> decode dentry
        ├─ REMOTE dentry ─────────────────────────────► [HARDLINK ALIAS]    skip (UNVERIFIED)
        └─ PRIMARY inode
             ├─ dir      ──► recurse (warn if fragtree truncated)
             ├─ symlink  ──────────────────────────────► [SYMLINK]          skip (no data)
             ├─ fifo/sock/dev ─────────────────────────► [SPECIAL]          skip (no data)
             └─ regular file
                  ├─ layout.pool_id != target ─────────► [OTHER-POOL]       skip
                  ├─ nlink > 1 ───────────────────────► [HARDLINKED FILE]  MIGRATE + flag UNVERIFIED
                  └─ else ────────────────────────────► migrate

 PLUS cluster-wide checks (both tools):
   mds_snaptable last_snap >= 2  ─► [CephFS SNAPSHOTS created]  reported (.snap NOT migrated)
   rados pool snap_list non-empty ─► [RADOS POOL SNAPSHOTS]     warned (NOT migrated)

 OUT OF SCOPE entirely: RBD / RGW pools, additional CephFS file systems.
```

[VERIFIED] On the test fs the inventory correctly reported a symlink, a hardlinked
file (`nlink=2`, flagged UNVERIFIED) + its alias dentry, and `mds_snaptable
last_snap=2` after a `.snap` snapshot was created.

| Component | Forward (XrdCeph→CephFS) | Reverse (CephFS→XrdCeph) |
|---|---|---|
| Hardlinks | n/a (striper has none) | **flagged UNVERIFIED**; alias names dropped |
| Symlinks / special files | n/a | skipped (reported) |
| CephFS snapshots (`.snap`) | n/a | reported (`mds_snaptable`); **not migrated** |
| RADOS pool snapshots | warned; not migrated | warned; not migrated |
| Files in other data pools | n/a | skipped (reported) |
| RBD/RGW/other fs | out of scope | out of scope |

[RULE] Run `--report-only` (reverse) / read the startup warnings (forward) and
**resolve or accept every flagged item before migrating** — especially snapshots
(handle `.snap`/pool snapshots out of band) and hardlinks (whose multi-name
semantics have no XrdCeph equivalent and are unverified).

## 16. Validated vs. validate-before-production

```
 VALIDATED (reef 18.2.4, this work)                STILL VALIDATE (healthy multi-OSD)
 ─────────────────────────────────────────────    ───────────────────────────────────
 read-through redirects: CephFS + libradosstriper  prompt RADOS reclaim of deletes
 byte-exact incl. stripe interleave (sc 1/2/4)     (demo lagged: degraded single-OSD;
 redirect durable: flush + cache drop; MDS          namespace-del + purge-enqueue OK)
   backtrace coexists                               deep-scrub / recovery / balancer of
 write-through & delete-through (=> the rules)        redirect(manifest) objects over time
 finalize -> owned, source-independent (both dirs)  cross-Ceph-version upgrade of
 safe rollback (detach-first) survives async purge   redirect/manifest objects
 checksum carry + verify (user.XrdCks.adler32)      hardlinks (remote dentries) &
 idempotent / parallel / dry-run                     snapshots (reverse walk skips them:
                                                      head + primary inodes only)
```

[FACT] The redirect/manifest mechanism is standard RADOS, but fronting CephFS or
striper data with it is off the well-trodden path.
> [RULE] Treat the zero-move redirect phase as a fast, reversible **staging** tool;
> **finalise** to reach a supported, fully-owned end state before decommissioning
> the other side.

---

## 17. Source map + command reference

```
 COMPONENT                          FILE
 ────────────────────────────────  ───────────────────────────────────────────────
 forward tool  XrdCeph->CephFS      tests/ceph/xrdceph_striper_migrate.cpp
 reverse tool  CephFS->XrdCeph      tests/ceph/xrdceph_cephfs_to_striper.cpp
 CephFS-from-RADOS decoder          src/fs/backend/rados/cephfs_layout.{c,h}
                                    src/fs/backend/rados/cephfs_denc.{c,h}
 forward runbook                    docs/10-reference/cephfs-migration-glasgow-ral.md
 reverse runbook                    docs/10-reference/cephfs-to-xrdceph-migration.md
 test record (Reef validation)      docs/10-reference/xrdceph-cephfs-migration-test-record.md
 mechanism spikes                   tests/ceph/spike_redirect_write.cpp   (write-through)
                                    tests/ceph/spike_finalize.cpp         (promote)
                                    tests/ceph/striper_redirect_cephfs.cpp(fwd redirect)
                                    tests/ceph/spike_cephfs_to_striper.cpp(rev copy)
 harness / seeders                  tests/ceph/run_striper_migrate.sh
                                    tests/ceph/striper_seed.c  cephfs_seed.c
```

```
 OPTION              FORWARD   REVERSE   MEANING
 ─────────────────   ───────   ───────   ─────────────────────────────────────────
 --mode redirect|copy  yes       (redirect only)  zero-move vs in-cluster copy
 --finalize            yes       yes       materialise redirects -> owned
 --rollback            yes       yes       remove overlay (detach-first); source intact
 --verify              yes       yes       read back + checksum compare
 --delete-source       copy      finalize  drop the source objects after verify
 --assume-quiesced     n/a       REQUIRED  assert CephFS unmounted/failed+flushed
 --report-only         n/a       yes       walk + classify unhandled components; migrate nothing
 --force               yes       -         re-do an already-migrated file
 --dry-run             yes       yes       report, write nothing
 --threads N           yes       yes       parallel workers
 --strip PFX / --list  yes       (--strip) soid/path shaping; explicit work list
```

---

*All claims marked [VERIFIED] were demonstrated on Ceph reef 18.2.4 against a live
single-node cluster during development. Re-validate on a production-representative
(multi-OSD, healthy) cluster before operational use, per §16.*
