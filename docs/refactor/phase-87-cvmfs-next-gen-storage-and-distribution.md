# Phase-87 — CVMFS *next-gen* storage & distribution (leapfrog the official client)

**Goal:** having proven in Phase-85 that the native CVMFS surfaces are **not
bound to stay bug-compatible with the official driver**, take the next step and
attack the two structural weaknesses the upstream stack cannot fix without a
rewrite: (1) the **one-file-per-chunk local cache** and the **FUSE read path**
on the client, and (2) the **RTT-per-file, whole-object, per-repo** distribution
model on the proxy. This phase turns `shared/cvmfs/` + `client/apps/fs/` into a
packed, kernel-native, workload-aware cache, and `src/protocols/cvmfs/` into a
batched, delta-aware, P2P-scalable, image-exporting distribution service.

Every feature is **additive and gated off by default**: with all gates off, the
FUSE driver and the proxy behave exactly as the phase-84 conformance corpus
pins them, and the on-disk cache stays in the official one-file-per-chunk layout.

**Provenance:** anchors below read from the tree at working state on
**2026-07-18** (post-Phase-85 F0–F12 landed, UNCOMMITTED). Re-verify anchors at
the start of each wave and mark drift `DRIFT:` inline (phase-80 convention).
This phase builds directly on Phase-85 seams — cross-references use the F-numbers
from `docs/refactor/phase-85-cvmfs-swiss-army-features.md`.

**Landed dependency — Phase-86 (FUSE client connection reuse) is COMPLETE.**
`docs/refactor/phase-86-fuse-client-connection-reuse.md` has landed, and this
phase assumes its deliverables are present in the client tree:
- **`brix_cpool`** (`client/lib/net/cpool.{c,h}`) — a transport-agnostic,
  thread-safe **slot pool** parameterized by a `{conn_size, connect, close}`
  vtable over opaque per-slot connection memory. `brix_pool` (root://) is now a
  thin adapter over it. **This is the client-side concurrency primitive every
  phase-87 FUSE feature that opens its own transport (G2 bundle consumer, G7/G9
  content materialization fetch, G12 peer pulls on the client leg) reuses — do
  not mint a second pool.**
- **`brix_kaconn` + `brix_webmeta`** (`client/lib/protocols/http/web_ka.{c,h}`) —
  a shared keep-alive HTTP/1.1 codec (connect / read-headers / read-body,
  drain-to-`Content-Length`, reconnect-on-sever) plus a pooled WebDAV-metadata
  connection. The **read and metadata paths now run one keep-alive
  implementation**; new client HTTP transports in this phase (bundle/delta pull)
  compose `brix_kaconn`, not a fresh socket loop.
- **Decision inherited verbatim:** **brixcvmfs stays on libcurl** (single-threaded
  `-s` by design, already reuses via libcurl's connection cache — Phase-86 §0/§7).
  So a phase-87 client feature that runs **inside the brixcvmfs actor/prefetch
  path** (G1 filter fetch, G2 bundle consumer, G3 dict fetch, G4/G5 store fills)
  reuses connections **through libcurl's handle**, exactly as F4's prefetch worker
  already does — it does **not** wrap those handles in `brix_cpool`. `brix_cpool`
  is for the multi-threaded `brix_io`-family transports (xrootdfs-web, and any
  new binary/peer transport a phase-87 feature adds). Pick the reuse primitive by
  which transport family the feature lives on; never introduce a third.

**Prime directives (inherited from Phase-85, plus storage-specific):**

1. **Shared core is the leverage.** Both surfaces sit on `shared/cvmfs/`:
   `walk/walk.c` (F0 verified catalog walk), `catalog/` (catalog parse),
   `signature/` (whitelist + manifest signature), `object/object.c`
   (`cvmfs_object_verify` — decompress + CAS-hash), `fetch/fetch.c` (cache-first
   verified fetch), `grammar/` (URL classify + hash). A capability built in the
   core lights up in **both** the driver and the proxy. Build it once.
2. **VFS seam is law (INVARIANT #12).** Any cache-storage feature routes through
   `brix_vfs_*` / the backend registry — no raw data syscalls outside
   `src/fs/backend/`. The next-gen local store (G4) is therefore a **backend**,
   not new I/O sprinkled through the client. See `[[data_posix_backend_confinement]]`.
3. **pblock is the storage engine, not a fork of it.** The packed/dedup/tiered
   store (Wave B) is realized as a **pblock export configuration** used as the
   cvmfs cache backend — reusing Phase-83's headered blocks, dedup catalog,
   snapshots, per-block transforms, and the `pblock-fsck` oracle. No parallel
   block engine.
4. **Guard contract reuse.** Security-relevant failures (integrity, tamper,
   attestation) emit the unified fail2ban line (`src/net/guard/`), never an
   ad-hoc shape. New `signal=` tokens land in `guard.h`/`guard_audit.c` with the
   matching `deploy/fail2ban/` filter+jail in the same change.
5. **Surface-appropriate gating grammar.** FUSE-driver features are **client-side
   opts** (`brixMount cvmfs -o <k>=<v>` / `$BRIXCVMFS_*`), following F4 (`-o
   prefetch=`) and F6 (`-o pin=`) — NOT nginx directives. Proxy features are
   **nginx directives** (`brix_cvmfs_*` / `brix_cache_*`), following F7–F12.
   Kernel-native mount features (Wave C) are `brixMount` subcommands/opts.
6. **Standard discipline:** ngx-free shared core (libc + OpenSSL/zlib/zstd only,
   no `goto`, no stubs); new `.c` files land in the repo-root `./config` source
   list **and** `CMakeLists.txt`/`cmake/` **and** `client/Makefile` where
   client-linked (split_files_three_build_systems); each feature ships the
   3-test set (success + error + security-negative); clean-room (no
   `libcvmfs`/`libXrd*` linkage).
7. **Three FUSE targets — Linux, macOS, Windows — one portable core, target-gated
   tail.** The FUSE driver now targets **Linux (libfuse3)**, **macOS
   (macFUSE/FSKit)**, *and* **Windows (WinFsp's FUSE compatibility layer)**. The
   rule: every FUSE-side feature's **portable substrate** (the shared
   `shared/cvmfs/` core, the pblock-backed store, mmap indexes, the xor filter,
   the keep-alive transports from Phase-86) is **written once and runs on all
   three**; only the **kernel-integration tail** (Wave C: EROFS/overlayfs,
   fs-verity, block-clone) is target-specific and MUST sit behind a
   compile-and-runtime **target gate** with a graceful fall-back to the portable
   FUSE read path — never an `#ifdef` that silently drops a feature. Per-target
   equivalents are named per feature (§0.6); where no equivalent exists, the
   feature **degrades to plain FUSE on that target** (fail-safe), it does not fail
   the mount. Platform branches live behind a thin `shared/cvmfs/platform/` shim
   (feature-probe + capability struct), not scattered `#ifdef __APPLE__` /
   `#ifdef _WIN32` — mirror how brixMount already abstracts the mount syscall
   across platforms (`[[cvmfs_automount_delivered]]`). **Portable-primitive
   mapping** the shim owns: `mmap`→`CreateFileMapping`/`MapViewOfFile` on Windows
   (allocation granularity 64 KiB, not page-sized); `fdatasync`→`F_FULLFSYNC`
   (macOS) / `FlushFileBuffers` (Windows); POSIX path semantics normalized for
   Windows' case-insensitive, `\`-separated, drive-letter-or-directory mount
   model (WinFsp mounts a drive letter **or** a directory).

**Fail-closed gating:** every behavior-altering feature sits behind its own
opt/directive, default **off**. With all gates off, phase-84 conformance is
byte-for-byte unchanged and the cache format is the stock layout.

---

## 0. Scope, non-goals, and the feature roster

**In scope — 17 features in 5 waves.** Surface = FUSE driver / Proxy / Both. FUSE
features target **Linux (libfuse3), macOS (macFUSE/FSKit), and Windows
(WinFsp)**; the per-target behaviour of the kernel-integration features
(G7/G8/G9) is governed by the **platform matrix in §0.6**.

| # | Feature | Surface | Wave | Gate |
|---|---|---|---|---|
| G1 | **Negative-lookup filter** — Bloom/xor filter of the repo path-set answers `ENOENT` in-process | FUSE | A | `-o negfilter` / `$BRIXCVMFS_NEGFILTER` + proxy `brix_cvmfs_pathset` |
| G2 | **Chunk-bundle / directory-pack endpoint** — one request streams a whole subtree's chunks | Proxy | A | `brix_cvmfs_bundle` |
| G3 | **Trained shared compression dictionaries** — per-repo zstd dict kills small-file overhead | Both | A | `brix_cvmfs_dict` + `-o dict` |
| G4 | **Packed log-structured content store** — retire one-file-per-chunk; pblock-backed pack heap + mmap index | FUSE | B | `-o cache_format=packed` |
| G5 | **Format-tiered content** — hot=raw-mmap / warm=zstd / cold=evict, temperature-driven | FUSE | B | `-o cache_tiering` (rides G4) |
| G6 | **Perfect-hash mmap catalog index** — retire per-catalog SQLite on the hot lookup path | FUSE | B | `-o index=mmap` |
| G7 | **Kernel-native reads** — composefs/EROFS image + overlay mount; reads bypass FUSE | FUSE | C | `brixMount cvmfs --kernel` |
| G8 | **fs-verity end-to-end integrity** — F1 verification enforced by the kernel on every page fault | FUSE | C | `--fsverity` (rides G7) |
| G9 | **reflink CoW fast-path** — materialize cache objects as real CoW files for mmap/exec (lighter alt to G7) | FUSE | C | `-o reflink` |
| G10 | **Cross-revision delta transfer** — ship binary deltas between revisions, not whole objects | Proxy | D | `brix_cvmfs_delta` |
| G11 | **Workload-learned predictive prewarm** — access-profile models drive the F4 prefetch engine | Proxy | D | `brix_cvmfs_learn` |
| G12 | **P2P swarm cold-start** — gossip/DHT membership over the F8 mesh for farm-scale releases | Proxy | D | `brix_cvmfs_swarm` (extends `brix_cache_peers`) |
| G13 | **Global cross-repo dedup CAS** — one content store across all repos on a proxy | Proxy | D | `brix_cache_global_cas` |
| G14 | **Repo-as-image export** — render a revision as OCI/composefs/SquashFS for containerd/K8s | Proxy | E | `brix_cvmfs_export_image` + API |
| G15 | **Runtime provenance / SLSA attestation** — signed record of exactly which hashes a job consumed | Proxy | E | `brix_cvmfs_attest` |
| G16 | **Virtual / composed repos** — union/filter/subset a namespace that doesn't exist upstream | Proxy | E | `brix_cvmfs_virtual_repo` |
| G17 | **Active integrity scrubbing / anti-entropy** — proactive re-verify + peer self-heal | Both | E | `brix_cvmfs_scrub` |

**Non-goals:**
- **Writable COW overlay of `/cvmfs`** — speced separately
  (`docs/superpowers/specs/2026-07-05-brixmount-cvmfs-writable-overlay-design.md`).
  G9's reflink materialization is *read-side* CoW only; the writable overlay is
  a distinct feature and out of scope here.
- **Write-back to Stratum-1 / distributed consensus** — the proxy stays a cache;
  G16 virtual repos are read-only compositions.
- **Replacing the wire protocol** — G2/G10/G14 are *additional* endpoints; a
  client that doesn't speak them falls back to stock per-chunk GETs (fail-safe).
- **New crypto** — G8/G15 reuse the existing verified-fetch + signing spine;
  fs-verity uses the kernel's own Merkle tree, not a bespoke one.

**Cross-phase reconciliation:** G11 (learned prewarm) is the *policy* layer over
F4/F5 (the *mechanism*); the clever-client spec
(`docs/superpowers/specs/2026-07-04-cvmfs-brix-clever-client-design.md`) owns
heuristic tuning — reconcile at Wave D start. G7's EROFS image builder and G14's
image export share one image-emitter core — build it in Wave C, reuse in Wave E.

---

## 0.6. Platform target matrix (FUSE-side features)

Proxy features (G2, G10–G17) are server-side nginx-module code and are
**platform-neutral** — they run wherever the module builds and are unaffected by
the client target. The matrix below governs the **FUSE-side** features (G1,
G4–G9) across the **three** client targets. Legend: **✅ native** = the portable
substrate runs as-is; **▲ mapped** = a target-specific mechanism substitutes;
**FUSE-fallback** = no equivalent, degrade to the portable FUSE read path.

| Feature | Linux (libfuse3) | macOS (macFUSE / FSKit) | Windows (WinFsp) | Notes |
|---|---|---|---|---|
| G1 negative-lookup filter | ✅ native | ✅ native | ✅ native | pure-C xor filter + mmap; `mmap`→`MapViewOfFile` in the shim |
| G4 packed store on pblock | ✅ native | ✅ native | ✅ native | pblock through the VFS seam; segment append + mmap index portable. Durable append: `fdatasync` / `F_FULLFSYNC` / `FlushFileBuffers` (§G4) |
| G5 format tiering | ✅ native | ✅ native | ✅ native | transform choice is data, not syscall; raw/zstd/evict all portable |
| G6 mmap perfect-hash index | ✅ native | ✅ native | ✅ native | MPH + FST + mapped view; granularity probed at runtime (Apple-silicon 16 KiB page, Windows 64 KiB alloc granularity) |
| G7 kernel-native reads | ✅ EROFS + overlayfs | ▲ mapped → **clone-materialize + bind**, else **FUSE-fallback** | ▲ mapped → **ReFS clone-materialize dir**, else **FUSE-fallback** | neither macOS nor Windows has EROFS/overlayfs; both fall to a clone-materialized read-only root (G9), else plain FUSE |
| G8 fs-verity | ✅ fs-verity | **FUSE-fallback** (read-time CAS) | **FUSE-fallback** (read-time CAS) | no fs-verity on macOS or Windows; macOS App-sandbox signing / Windows WDAC-CI are not per-page content equivalents. Degrade to read-time CAS + a logged NOTICE |
| G9 reflink CoW fast-path | ✅ `FICLONE`/`copy_file_range` (XFS/btrfs) | ▲ mapped → **APFS `clonefile(2)`** | ▲ mapped → **ReFS block clone (`FSCTL_DUPLICATE_EXTENTS_TO_FILE`)** | APFS is CoW-native & default on Mac ⇒ G9 preferred there; on Windows block-clone needs **ReFS / Dev Drive** (NTFS has no reflink) |

**Consequences for sequencing.**
- On **macOS the pragmatic kernel-native path is G9 (APFS `clonefile`)**, not G7:
  APFS clones are first-class, always available on a modern Mac, and need no image
  build or mount caps. G7's EROFS/overlay stack has **no macOS analogue**, so on
  Mac the "kernel-native" story is carried by **G9 + G5-raw objects** (materialize
  verified, raw-stored hot objects as APFS clones; exec/mmap them directly,
  bypassing the FUSE read path). This flips the Linux recommendation (G9 as a
  *stepping-stone* to G7) — on macOS **G9 is the destination**.
- On **Windows the kernel-native path is likewise G9 — but only on ReFS / Dev
  Drive**, where block cloning (`FSCTL_DUPLICATE_EXTENTS_TO_FILE`) is CoW like
  APFS/btrfs. **NTFS has no reflink**, so on an NTFS volume G9 auto-detects
  unavailable and G7-on-Windows degrades to **plain WinFsp FUSE reads**
  (fail-safe). The realistic Windows story: recommend a **Dev Drive (ReFS)** cache
  volume to unlock G9's exec/mmap-bypass; otherwise the driver is a correct,
  portable FUSE mount with all of Wave A/B but without the kernel-native read
  fast-path. No EROFS/overlay/verity on Windows at all.
- **Wave A + Wave B are fully portable** and must be validated on **all three**
  targets; Wave C is where the targets diverge and each item carries explicit
  macOS **and** Windows rows above.
- **Host-binding differences.** macFUSE (kernel extension) needs a user-approved
  system extension; recent macOS pushes userspace **FSKit**. **WinFsp** installs a
  signed kernel driver + a FUSE-compatible user library and mounts as a **drive
  letter or a directory**. All three host bindings are confined to the
  `shared/cvmfs/platform/` shim (directive 7); the portable core above them is
  identical. macFUSE-first on Mac (FSKit as a follow-up surface); WinFsp is the
  only Windows FUSE host.
- **Build governance for the extra targets:** macOS/Windows bits compile under the
  **client** build (`client/Makefile` + `CMakeLists.txt`) guarded by the platform
  shim's capability probe; no macOS/Windows-only file enters the nginx-module
  `./config` list (proxy is platform-neutral). CI gains a **macOS client-build
  lane and a Windows (MSVC/clang-cl + WinFsp) client-build lane** — each builds +
  runs the portable/Wave-A/Wave-B suites; Wave-C mapped paths run on the native
  runner (Mac runner / a Windows runner with a ReFS Dev Drive), else
  `skip-with-reason`.

---

## Wave A — cold-start & build-workload wins (low/med effort, ride existing seams)

Rationale: the fastest, highest-ROI wins target the two dominant cold-start cost
centres — **negative metadata lookups** (build/link storms) and **RTT-per-chunk
fetch** (workflow first-run). All three ride seams that already exist.

### G1 · Negative-lookup filter

**Problem.** Build systems, dynamic linkers, and `python`/`ROOT` import
machinery `stat()` a torrent of **non-existent** paths — every `-I` include dir,
every `LD_LIBRARY_PATH`/`sys.path` entry, every `.so.N` version probe. Each miss
is a catalog round-trip in the official client. On a cold compile this is the
dominant latency, and it is pure waste.

**Design.**
- The **proxy** publishes, per repo revision, a compact **membership filter** of
  the full path-set: a **binary-fuse (xor) filter** (≈9 bits/key, faster and
  smaller than Bloom, no false negatives). Built by walking the catalog set via
  the **F0 walk facade** (`shared/cvmfs/walk/walk.c`) at publish-observation
  time; served at a well-known URL (`/.cvmfs-pathset/<root-hash>`) gated by
  `brix_cvmfs_pathset on`. Signed under the same manifest trust chain (the
  filter's own hash is stamped in an extension line, verified like any object).
- The **FUSE client** (`-o negfilter` / `$BRIXCVMFS_NEGFILTER`) fetches the
  filter once per revision (pinned by root-hash, cache-resident), mmaps it, and
  answers `ENOENT` **in-process** for any path the filter rejects — zero network,
  zero catalog open. A filter *hit* falls through to the normal verified lookup
  (false-positive rate ~1/256 just costs a normal lookup; never wrong).
- Revision change ⇒ new root-hash ⇒ new filter; the old one is evicted. Honours
  F6 pinning (a pinned mount uses the pinned revision's filter).

**Why it beats upstream.** The official client has no negative-lookup shortcut;
every ENOENT is a catalog consultation. Turns cold `cmake`/`ld`/`import` from
network-bound to memory-bound. Tiny to ship, tiny to store.

**Files.** proxy: new `src/protocols/cvmfs/pathset.c` (build+serve, walk-driven),
directive in `directives_resilience.inc`. client: `shared/cvmfs/filter/xorf.c`
(pure-C xor filter, shared), wired in `shared/cvmfs/client/client.c` lookup path;
opt parsed in `client/apps/fs/brixcvmfs.c`. Shared → also usable proxy-side to
short-circuit known-404s (feeds the F9/negcache path).

**Tests (3).** (success) cold `stat()` of 1000 absent paths ⇒ 0 origin hits with
filter on, N without; (error) a filter for revision A applied after the repo
advances to B is refused/refreshed (root-hash mismatch), never serves a stale
ENOENT for a path that now exists; (security-neg) a tampered filter (bit-flipped
so a real path reads absent) fails its signed-hash check and is rejected —
`signal=cvmfs_tamper`, fall back to live lookups (never a fabricated ENOENT).

### G2 · Chunk-bundle / directory-pack endpoint

**Problem.** CVMFS has **no batch fetch** — every chunk is an individual GET, so
cold-starting a workflow is thousands of serialized RTTs. Even with HTTP/2
(F11), the client still issues N requests.

**Design.**
- Proxy endpoint `POST /.cvmfs-bundle` (gated `brix_cvmfs_bundle on`) accepting
  either (a) a catalog/directory root-hash — "give me every chunk this subtree
  references," computed server-side via the **F0 walk facade** — or (b) a
  client-supplied **want-list** of content hashes (git `want`/`have` style; the
  client sends what it already has as a compact filter so the proxy omits them).
- Response is a **framed pack stream**: `[u32 hash-len][hash][u64 len][bytes]…`
  for each object, each still individually CAS-verifiable by the client on
  arrival (integrity is per-object, not per-bundle — a corrupt member is
  discarded and re-fetched singly, never poisons the bundle). Chunks are streamed
  in **catalog/locality order** so the client writes them to the packed store
  (G4) sequentially.
- Fills the bundle from the existing tier spine (cold-tier F7 / peer-mesh F8 /
  origin) so a bundle is itself cache-accelerated. Bounded size + streaming so a
  huge subtree back-pressures rather than buffering.

**Why it beats upstream.** One request warms a whole directory subtree; cold
start goes from RTT-bound to bandwidth-bound. Composes with F11 multiplexing and
G3 dictionaries. No upstream equivalent.

**Files.** `src/protocols/cvmfs/bundle.c` (endpoint + pack framing), reuses
`shared/cvmfs/walk/`; client bundle-consumer in `shared/cvmfs/fetch/` (prefetch
worker F4 issues bundle requests instead of per-chunk when `-o bundle`).

**Tests (3).** (success) a bundle request for a 500-chunk subtree returns all
chunks in one response, each CAS-verifies, one origin round-trip; (error) a
want-list naming a mix of present/absent hashes returns only the present ones +
a per-hash miss marker, client fetches misses singly; (security-neg) a
corrupted member in the pack stream is rejected on its own CAS check and
re-fetched individually — the bundle never delivers unverified bytes.

### G3 · Trained shared compression dictionaries

**Problem.** Per-chunk zlib is near-useless for the **millions of tiny files**
typical of software repos (headers, `.py`, `.pyc`, small `.so`): the dictionary
resets every object, so there's no cross-file redundancy capture.

**Design.**
- Proxy trains a **zstd dictionary** per repo (or per file-type cluster) from a
  sample of the repo's small objects (`ZDICT_trainFromBuffer`), versions it by
  content-hash, and serves it at `/.cvmfs-dict/<id>` (gated `brix_cvmfs_dict
  on`). Ties into the F12 transcode path: when a dict is active, small-object
  responses are `Content-Encoding: zstd` **with the shared dict** (a private
  `zstd-dict` coding negotiated via a capability header).
- Client (`-o dict`) fetches the dict once (pinned, cache-resident), primes a
  `ZSTD_DCtx` with it, and decodes dict-framed objects. Falls back to
  dictless zstd/identity if absent (fail-safe).
- Reuses the existing codec substrate (`src/core/http/http_compress.c`,
  `src/core/compat/codec_zstd.c`) — this is the negotiate/transcode path from
  F12 made **dictionary-aware**, not a new codec.

**Why it beats upstream.** 2–5× better ratio on small files than independent
zlib, decoded faster. Ship the dict once, amortize across the whole repo.

**Tests (3).** (success) a corpus of 10k small files transfers with a trained
dict smaller than dictless-zstd and far smaller than zlib, all bytes correct;
(error) a client without the dict still gets correct bytes via dictless
fallback; (security-neg) a wrong/tampered dict (hash-mismatch) is rejected and
the client falls back rather than decoding garbage.

---

## Wave B — next-gen local storage (FUSE flagship)

This is the "next-gen on-disk storage model" the phase is named for. Realized as
a **pblock export used as the cvmfs cache backend** through the VFS seam — reusing
Phase-83 wholesale.

### G4 · Packed log-structured content store

**Problem with the stock cache.** One file per chunk under `cache/<ab>/<hash>`
+ a SQLite quota manager: **millions of tiny inodes** (inode exhaustion, slow
directory ops), **no locality** (a directory's chunks are scattered across the
disk), **fsync/unlink storms** on LRU eviction, fragmentation, and the page
cache holding **compressed** bytes it can't mmap.

**Design — a packed object heap on pblock.**
- **Pack files (segments).** Chunks are appended into large (e.g. 256 MiB–1 GiB)
  **append-only segments** — one inode per segment instead of per chunk. This is
  exactly a **pblock export**: pblock's headered blocks `[u32 llen][u32
  plen][phys]` + its dedup catalog + per-block transforms already are a packed,
  deduplicated, optionally-compressed object heap. The cvmfs cache becomes
  `brix_cvmfs_cache_store pblock:…`.
- **mmap'd content index.** `content_hash → (segment_id, offset, len, format,
  refcount)` in a memory-mapped open-addressed table (crash-consistent via a WAL
  or double-buffered checkpoint) — pblock's catalog table, reused. Lookups are
  pointer chases, not `open()`+`read()`.
- **Locality-preserving packing.** New chunks are grouped by **catalog subtree**
  (grouping known from the F0 walk / the G2 bundle order) so a workflow reading a
  directory reads **sequentially** off one segment. This is the single biggest
  read-throughput win over the scattered stock cache.
- **CDC dedup across revisions.** A rolling-hash content-defined-chunking layer
  (pblock dedup) means a new revision of a large slowly-changing artifact shares
  unchanged blocks with the prior revision — dedup CVMFS cannot do at the cache
  layer.
- **Eviction = compaction, not unlink storm.** Watermark eviction (reuse F7's
  `brix_cache_evict_one` / demote path) drops refcounts; a background compactor
  rewrites live objects out of sparse segments and frees whole segments
  (punch-hole/truncate). No per-object fsync/unlink.
- **Crash consistency.** Segment appends are fsync-batched; the index is
  recovered from the WAL/checkpoint + a segment scan on unclean shutdown
  (`pblock-fsck` leg, extended with a cvmfs-cache oracle). **Portability:** the
  durability primitive is target-mapped in the platform shim — `fdatasync` on
  Linux, `fcntl(fd, F_FULLFSYNC)` on macOS (plain `fsync` does not force the
  drive cache on APFS), `FlushFileBuffers` on Windows; the mmap index maps via
  `MapViewOfFile` on Windows (64 KiB view-alignment) vs `mmap` on Linux/macOS.
  The batched-append and index logic above are otherwise identical on all three
  targets.

**Migration.** A one-shot importer walks an existing stock cache and packs it;
`-o cache_format=packed` selects the new backend, absence keeps the stock
layout (default). Both can coexist during rollout.

**Why it beats upstream.** Orders of magnitude fewer inodes, sequential read
locality, cross-revision dedup, no eviction storms — all impossible in the stock
one-file-per-chunk model without a rewrite. And it's *mostly wiring*: pblock is
the engine.

**Files.** cvmfs-cache backend adapter `src/fs/backend/pblock/` (a cvmfs-cache
export profile) or a thin `shared/cvmfs/store/packed.c` that drives pblock via
the VFS seam; client opt in `brixcvmfs.c`; migration tool
`client/apps/fs/cvmfs-cache-pack.c`. Reuse `pblock-fsck`.

**Tests (3).** (success) fill 100k chunks, assert one-segment-per-N-chunks inode
count + byte-identical reads + sequential read of a directory hits one segment;
(error) an unclean kill mid-append recovers via fsck with no lost/duplicated
live object; (security-neg) a segment with a bit-flipped object fails the
per-object CAS check on read, is quarantined and re-filled — a packed store never
serves corrupt bytes (F1 preserved through the new format).

### G5 · Format-tiered content (decompress-once, store-optimal)

**Problem.** The stock cache stores chunks zlib-compressed and decompresses on
essentially every open; hot executables can't be page-cache-shared or mmap'd.

**Design.** With the packed store (G4), store each object in the format optimal
for its **temperature** (the pblock per-block transform, Phase-83 F12/F13):
- **hot** → stored **uncompressed, page-aligned** ⇒ mmap-able / exec-in-place,
  zero decode on read (the prerequisite for G7/G9 kernel-native mapping);
- **warm** → **zstd** (better ratio + much faster decode than zlib);
- **cold** → evicted (G4 compaction).
Temperature is tracked per object (access recency/frequency, already needed for
eviction); promotion re-packs hot objects uncompressed. Gated `-o cache_tiering`.

**Why it beats upstream.** Faster reads **and** smaller warm footprint at once —
the stock cache can only pick one compression level globally.

**Tests (3).** (success) a repeatedly-read object migrates to raw-uncompressed
and subsequent reads do zero decode (measured); (error) a demotion under memory
pressure re-compresses without data loss; (security-neg) format transitions
preserve the CAS hash of the *plaintext* (verify still binds the decompressed
content, never the on-disk stored form).

### G6 · Perfect-hash mmap catalog index

**Problem.** Deep repos = many nested SQLite catalogs; each lookup may open +
query a catalog DB. Metadata-heavy workloads (find, ls -R, build dep scans) pay
SQLite overhead per catalog.

**Design.** For a **pinned revision**, precompute a merged, mmap-able index:
`path → (content_hash, mode, size, mtime)` using a **minimal-perfect-hash** (CHD
/ BBHash) over the path-set, with paths stored in an **FST** (finite-state
transducer, Lucene/Tantivy-style) for prefix compression + fast `readdir`
enumeration. O(1) lookups, no SQLite on the hot path, survives remount, built
from the F0 walk output (same structure G1's filter is built from — share the
walk pass). Gated `-o index=mmap`; falls back to SQLite catalogs when absent or
for unpinned/rolling mounts.

**Why it beats upstream.** Removes per-catalog SQLite open/query from the hot
lookup path; makes `ls -R`/dep-scan on a huge repo memory-speed.

**Tests (3).** (success) `find /cvmfs/<repo>` over a deep tree does zero SQLite
opens with the index, correct listing; (error) index built for revision A is not
used against revision B (root-hash guard) — falls back to catalogs; (security-neg)
a tampered index entry (hash mismatch vs catalog) is caught at first read via the
CAS check and the index is invalidated.

---

## Wave C — kernel-native reads (highest impact, higher effort)

The single biggest structural win: get reads **out of FUSE** entirely. **This is
the wave where the three targets diverge** (§0.6): Linux gets EROFS + overlayfs
(G7) and fs-verity (G8); **macOS** (no EROFS/overlay/verity) gets its
kernel-native read path from **G9 (APFS `clonefile`)** with a raw-store lower
(G5); **Windows** (no EROFS/overlay/verity either) gets it from **G9 on ReFS
block cloning** where a ReFS/Dev-Drive cache volume is available, else stays on a
correct plain WinFsp FUSE mount. Each item below carries its explicit per-target
behavior; the portable content store (G4/G5) is the shared lower for all of them.

### G7 · Kernel-native reads via composefs / EROFS *(Linux)* — clone-materialize on macOS/Windows

**Problem.** Every FUSE `read()` is a userspace round-trip + a bytewise copy;
executables and shared libraries can't be cleanly `mmap`/exec'd or page-cache-
shared across processes. For exec-heavy and container workloads FUSE overhead
dominates.

**Design (composefs model).**
- Build a compact **read-only EROFS metadata image** per repo revision from the
  F0 walk / G6 index — directory structure + inode metadata + per-file
  **redirect** to the content store (by content-hash), *not* the file bytes.
- Mount it via **overlayfs + EROFS** (composefs style) with the lower content
  provided by the **packed store (G4)**, hot objects stored raw (G5) so the
  kernel maps them directly. Reads, `mmap`, and exec are **kernel-native**,
  page-cache-shared across all processes, zero FUSE hops.
- brixMount orchestrates: fetch/verify manifest → ensure content present (G2
  bundle warms it) → emit image → mount. `brixMount cvmfs --kernel <fqrn>`.
- Fallback: if the kernel lacks EROFS/overlay support or caps are unavailable,
  transparently fall back to the FUSE mount (fail-safe, never fails the mount).

**macOS / Windows design (no EROFS/overlayfs on either).** Neither macOS nor
Windows has EROFS or overlayfs, so the composefs model does not port to them.
`--kernel` on these targets instead materializes the **resolved directory tree**
into a per-revision materialization root — directories created, files provided as
**G9 clones** of the raw-stored (G5) verified content objects (metadata-cheap, no
byte copy, CoW-shared extents: **APFS `clonefile`** on macOS, **ReFS block clone**
on Windows) — and exposes it read-only. Reads/`mmap`/exec then hit a
**CoW-filesystem-native path, not FUSE**, which is the whole point of the wave.
This makes **G7-on-macOS/Windows a thin orchestration layer over G9** rather than
an image+overlay stack; the "image emitter" degenerates to "walk the resolved
tree and clone." If the clone primitive is unavailable (non-APFS volume on macOS;
**NTFS rather than ReFS/Dev-Drive** on Windows) it **degrades to the FUSE mount**
(fail-safe). The manifest/verify/warm steps are identical to Linux.

**Why it beats upstream.** Eliminates the FUSE read path — the largest fixed cost
in the official client for containers/conda/exec workloads. This is the design
OSTree/podman adopted; **nobody ships it for CVMFS.** The macOS APFS-clone and
Windows ReFS-clone materializations are likewise paths the official client does
not offer on those platforms.

**Effort/risk (honest).** Largest item in the phase. **Linux:** needs an image
emitter, mount orchestration, and mount/overlay capabilities (or a privileged
helper / fuse-overlayfs fallback for unprivileged mode). **macOS/Windows:** no
image/overlay stack, but needs the per-revision materialization root managed
(build, GC on revision change) and depends on G9's clone path; the FUSE fallback
itself has a host-driver prerequisite (macFUSE system-extension approval / WinFsp
signed-driver install). **Windows caveat:** the clone fast-path only exists on
ReFS/Dev-Drive — on a default NTFS box `--kernel` is plain WinFsp FUSE. Share the
Linux image emitter with G14 (proxy, always Linux — the emitter is not needed on
the Mac/Windows clone path).

**Files.** `client/apps/fs/cvmfs-erofs.c` (Linux image emitter, shared with G14),
`shared/cvmfs/image/` (emitter core, ngx-free, Linux), `shared/cvmfs/platform/`
mount shim (EROFS+overlay mount on Linux; clone-materialize + read-only bind on
macOS; clone-materialize + WinFsp/directory expose on Windows), brixMount
`--kernel` orchestration in `client/apps/fs/brixmount.c`.

**Tests (3).** (success) a `--kernel` mount serves byte-identical files and an
`mmap`+exec of a shared lib does zero FUSE ops (Linux: measured via absence of the
FUSE device traffic; macOS/Windows: the exec'd path resolves under the CoW
materialization root, not the macFUSE/WinFsp mount); (error) on a kernel without
EROFS *(Linux)* / a non-clone volume — non-APFS *(macOS)* or NTFS-not-ReFS
*(Windows)* — the mount falls back to FUSE and still serves correctly;
(security-neg) a content-store object whose hash doesn't match its image redirect
/ clone source is refused (Linux: and, with G8, blocked in-kernel; macOS/Windows:
refused at materialize time — an unverified object is never cloned into the root).

### G8 · fs-verity end-to-end integrity *(Linux)*

**Design.** Enable **fs-verity** on the content-store files backing the G7 mount:
the kernel builds a Merkle tree per file and **verifies every page on fault**.
Combined with the redirect-by-content-hash, this extends F1's "verified at fill"
to "**enforced by the kernel at runtime**" — a strictly stronger guarantee than
any CVMFS deployment offers. The expected verity digest is bound to the CVMFS
content hash and checked at enable time (`--fsverity`, rides G7).

**Platform.** fs-verity is a **Linux-only** ext4/f2fs/btrfs facility; **neither
macOS nor Windows has an equivalent** — macOS App-sandbox code-signing verifies
signed bundles, not arbitrary content pages, and Windows WDAC / Code Integrity
gates *signed executables*, not per-page content of an arbitrary cache file;
neither is a substitute. On macOS **and** Windows `--fsverity` is a **no-op that
logs a NOTICE and degrades to read-time CAS** (the fill-time F1 verify plus, on
the G9/G7 clone path, a re-hash-before-clone check) — the strongest guarantee
those platforms allow, short of per-page kernel enforcement. This is the one
Wave-C guarantee that is strictly weaker off Linux, and it is called out as such
rather than silently dropped.

**Why it beats upstream.** Runtime, in-kernel, per-page tamper detection of
executed content — supply-chain integrity that survives even a compromised
userspace cache manager.

**Tests (3).** (success) *(Linux)* a verity-enabled file reads correctly and its
measured verity digest matches the CVMFS hash; (error) a kernel/platform without
fs-verity (**all macOS and Windows**) degrades to G7/G9's read-time CAS check with
a logged NOTICE and still serves correctly; (security-neg) *(Linux)* flipping a
byte in a backing file after enable makes the kernel `EIO` the read — corrupt
bytes never reach the process — with a `signal=cvmfs_tamper` audit line; the
macOS/Windows degrade path still catches the same flip at materialize/read time
(re-hash mismatch ⇒ quarantine + `signal=cvmfs_tamper`), just not per-page
in-kernel.

### G9 · reflink CoW fast-path (lighter alternative to G7; the *preferred* Mac path)

**Design.** Where a kernel-native EROFS mount is too heavy (or caps are
unavailable), materialize cache objects as **real CoW files** into a per-mount
materialization tree, so exec/mmap of those files bypass the FUSE read path with
no image build. The clone primitive is **target-mapped** in the platform shim:
- **Linux** → `copy_file_range`/`FICLONE` on **XFS/btrfs** (reflink-capable FS);
- **macOS** → **`clonefile(2)` on APFS** — APFS is CoW-native and the default
  volume format on every modern Mac, so the reflink source is essentially always
  available (unlike Linux, where it needs XFS/btrfs);
- **Windows** → **ReFS block cloning** via `FSCTL_DUPLICATE_EXTENTS_TO_FILE` on a
  **ReFS or Dev-Drive** volume — CoW-shared extents like APFS/btrfs. **NTFS has no
  reflink**, so on NTFS the probe reports no clone support and G9 falls back to
  WinFsp FUSE reads. Recommend a Dev-Drive (ReFS) cache volume to unlock it.
Gated `-o reflink`; auto-detects a clone-capable backing FS via the shim's probe,
falls back to FUSE reads otherwise. The materialized file is always a clone of the
**verified, raw-stored (G5)** cache object, so no byte copy and shared extents on
every target that supports it.

**Platform note.** Because APFS clone is ubiquitous on macOS, **G9 is the
recommended kernel-native read path on Mac**; on **Windows it is the read
fast-path but only on ReFS/Dev-Drive** (else plain FUSE). On Linux G9 remains the
pragmatic stepping-stone/alternative to the full G7 EROFS mount. G9 is the
substrate G7-on-macOS/Windows (§0.6, G7 macOS/Windows design) is built on.

**Why it beats upstream.** ~80% of G7's exec/mmap benefit at a fraction of the
effort; a good default on reflink-capable nodes and the *primary* fast path on
macOS/APFS and Windows/ReFS.

**Tests (3).** (success) exec of a reflinked `.so` bypasses FUSE, correct bytes,
no extra disk usage — shared extents (Linux: XFS/btrfs `FICLONE`; macOS: APFS
`clonefile`; Windows: ReFS `FSCTL_DUPLICATE_EXTENTS_TO_FILE`); (error) a
non-clone-capable backing FS (Linux non-reflink / non-APFS macOS volume / **NTFS
on Windows**) falls back cleanly to FUSE reads; (security-neg) the clone source is
the verified cache object — a quarantined/unverified object is never materialized
on any target.

---

## Wave D — distribution & scale (proxy)

### G10 · Cross-revision delta transfer

**Design.** When a client holds revision N and the repo advances to N+1, the
proxy computes and ships a **binary delta** (CDC/zstd-dict/bsdiff) of changed
catalogs + chunks rather than whole objects. The client reconstructs against its
pinned N. Deltas are themselves CAS-verified after apply (reconstruct → hash →
compare). Gated `brix_cvmfs_delta on`; client advertises its held revision, proxy
falls back to whole-object if no delta base. Frequent-publish repos (nightlies,
calibration) get order-of-magnitude WAN savings.

**Tests (3).** (success) N→N+1 with 1% changed content transfers ~1% of the
bytes, reconstructed content byte-identical + CAS-verified; (error) a client with
no valid base gets whole objects; (security-neg) a delta that reconstructs to the
wrong hash is rejected, client re-fetches whole (never applies an unverified
delta).

### G11 · Workload-learned predictive prewarm

**Design.** The proxy learns **access-profile models** per (repo, workload
signature): an n-gram / Markov model of "requests for X are followed by Y."
Built passively from access telemetry (low-cardinality, INVARIANT #8). On a new
job's first accesses, recognize the pattern and drive the **F4/F5 prefetch
engine** to warm the predicted working set (optionally via a G2 bundle). Stable
profiles are publishable as named **"warm sets"** operators pin. Gated
`brix_cvmfs_learn on`; this is the *policy* layer over F4's *mechanism*.

**Tests (3).** (success) after training on a workload, a fresh job's working set
is pre-resident before it's requested (hit-rate lift measured); (error) an
unrecognized workload prewarms nothing (no mispredict storm); (security-neg)
profile keys are low-cardinality and carry no per-user/token content (privacy +
metric-cardinality invariant).

### G12 · P2P swarm cold-start

**Design.** Generalize the F8 mesh (`brix_cache_peers`, static 2–16 list) to a
**gossip/DHT membership** so a 10,000-node batch farm releasing a new software
version pulls from **each other** rather than hammering the Stratum-1 —
Dragonfly/Kraken-for-CVMFS. Reuse the HRW rendezvous (`sd_cache_hrw_fnv1a64`),
verified-peer safety, and tamper-signalling already built; add SWIM-style
membership + a bounded fan-out fetch. Gated `brix_cvmfs_swarm on` (extends
`brix_cache_peers`).

**Tests (3).** (success) a 20-node simulated swarm cold-starting a release does
O(1) origin fetches per object regardless of node count; (error) a dead peer is
detected and routed around (membership converges); (security-neg) a peer serving
a mismatched hash raises `signal=cvmfs_tamper` naming the sibling and is
quarantined (F8 semantics preserved at swarm scale).

### G13 · Global cross-repo dedup CAS

**Design.** One **content store shared across all repos** on a proxy: identical
files (same content-hash across ATLAS/CMS/conda/OS layers) stored **once**. The
CAS + cold-tier (F7) are already repo-agnostic byte stores keyed by content-hash
— this is mostly namespacing policy + a shared eviction domain. Gated
`brix_cache_global_cas on`. Composes with G4 (one packed heap for the whole
proxy).

**Tests (3).** (success) the same object referenced by two repos occupies the
store once, both serve it; (error) eviction accounts a shared object's combined
refcount (not double-freed); (security-neg) per-repo authz (F3) still gates
access — dedup at the byte layer never leaks a private repo's content to an
unauthorized repo request.

---

## Wave E — ecosystem & provenance (proxy, strategic)

### G14 · Repo-as-image export

**Design.** Render a repo revision as a standard artifact — **OCI layer /
composefs / SquashFS / EROFS** — content shared from the CAS via fs-verity, so a
Kubernetes **containerd snapshotter** or a batch image puller consumes CVMFS
content **without a CVMFS client at all**. Reuses the G7 image emitter. Endpoint
`GET /.cvmfs-image/<fqrn>/<rev>?format=…` + an API, gated
`brix_cvmfs_export_image`. A genuinely new distribution surface bridging CVMFS
into the container/K8s world.

**Tests (3).** (success) an exported EROFS/OCI image mounts and matches the repo
tree byte-for-byte; (error) an unknown format/revision is a clean 4xx; (security-
neg) export honours F3 repo authz + emits attestation (G15) — no anonymous export
of a gated repo.

### G15 · Runtime provenance / SLSA attestation

**Design.** Since the proxy verifies every byte (F1), emit a **signed record of
exactly which content hashes a job/session consumed** → in-toto / SLSA-style
supply-chain attestation and perfect reproducibility ("this result was produced
against precisely these bytes"). Gated `brix_cvmfs_attest on`; records are signed
under the proxy's key, queryable per session. Uniquely enabled by a *verifying*
proxy.

**Tests (3).** (success) a session's attestation lists exactly the consumed
hashes, signature verifies; (error) attestation off ⇒ no record, no overhead;
(security-neg) a replayed/forged attestation fails signature verification.

### G16 · Virtual / composed repos

**Design.** Compose a **virtual repo** as a read-only overlay/union of upstreams,
or a filtered/curated subset (expose only `/release/X`, or a thin repo). Serve a
namespace that doesn't physically exist upstream. Config-plane feature over the
existing multi-source fill + classify logic. Gated `brix_cvmfs_virtual_repo`.

**Tests (3).** (success) a union of two upstreams presents a merged tree with
deterministic precedence; (error) a path absent in all members is a clean 404;
(security-neg) each member's F3 authz is enforced independently — the composition
never elevates access.

### G17 · Active integrity scrubbing / anti-entropy

**Design.** Background re-verification of cached content against catalogs,
auto-healing corrupt/bitrotted objects from peers (F8/G12) or origin — silent-
bitrot protection the stock cache lacks. It's the F1 verify path run proactively
on a schedule (bounded rate, off the hot path), feeding the mesh for repair.
Gated `brix_cvmfs_scrub on` (interval/rate args). Runs on both surfaces.

**Tests (3).** (success) a deliberately corrupted cache object is detected by the
scrubber and re-healed from a peer/origin; (error) scrub rate is bounded (no hot-
path impact under load); (security-neg) a heal source that itself fails
verification is rejected (never heals corrupt-from-corrupt) with a tamper signal.

---

## Cross-cutting notes

- **The image emitter (G7) and export (G14) are one core** — `shared/cvmfs/image/`,
  ngx-free, built in Wave C and reused in Wave E. Don't fork it.
- **The F0 walk pass powers G1 (filter), G2 (bundle), G6 (index), and the G7/G14
  image** — build the walk-output structure once and let all four consume it.
- **pblock is the storage engine for G4/G5/G13** — the packed heap, dedup, per-
  block transforms, and fsck already exist (Phase-83); this phase configures and
  drives them, it doesn't reimplement block storage (INVARIANT #12, `[[pblock_lab_phase83]]`).
- **Every remote-source feature is allowlist + verify** — G2/G10/G12/G13 reuse
  the SSRF/tamper guard model (`[[cvmfs_proxyabuse_guard]]`, `[[notroot_wire_guard]]`)
  and the per-object CAS check; a bundle/delta/peer/global-CAS object is always
  independently verifiable, never trusted by container.
- **Connection reuse is Phase-86's, not this phase's.** Any FUSE feature that
  opens its own transport reuses the **landed** Phase-86 primitives — `brix_cpool`
  for the multi-threaded `brix_io`/binary/peer transports, `brix_kaconn` for
  keep-alive HTTP, and libcurl's own handle cache for anything on the
  single-threaded brixcvmfs actor/prefetch path (see Provenance). No phase-87
  feature mints a new pool or a new keep-alive socket loop.
- **Three FUSE targets, one core (directive 7 + §0.6).** FUSE-side portable
  substrate is written once for Linux, macOS **and** Windows; only Wave C's
  kernel-integration tail is target-specific, behind the `shared/cvmfs/platform/`
  shim with a FUSE fall-back. The off-Linux kernel-native read path is **G9 CoW
  cloning** — APFS `clonefile` on macOS, ReFS block clone on Windows (Dev-Drive) —
  not G7's EROFS/overlay stack; fs-verity (G8) has **no macOS or Windows
  equivalent** and degrades to read-time CAS. Windows on NTFS gets Wave A/B + a
  correct plain WinFsp FUSE mount with no kernel-native fast-path. Proxy features
  (G2, G10–G17) are platform-neutral.
- **Conformance safety:** the phase-84 corpus is the regression oracle — run it
  with all Phase-87 gates off at the end of every wave to prove additivity, and
  run the FUSE conformance suites (cache/catalog/read/refresh_failover/trust)
  against the packed store (G4) with `-o cache_format=packed` to prove the new
  format is behaviourally identical to the stock layout. **Run the portable
  suites (Wave A + Wave B) on the Linux, macOS and Windows client builds** so no
  target silently regresses; Wave-C mapped paths run on their native runner
  (Mac / Windows-ReFS) or `skip-with-reason`.
- **Build governance:** new shared `.c` → repo-root `./config` + `CMakeLists.txt`
  + `client/Makefile` (split_files_three_build_systems); build in the private
  tree ([[concurrent_session_build_contention]]); literal `--add-module` path.
  macOS **and Windows** client bits compile under `client/Makefile` +
  `CMakeLists.txt` behind the platform-shim capability probe (Windows via
  MSVC/clang-cl + the WinFsp SDK; keep the shared core C11-clean so it compiles
  under all three toolchains); no macOS/Windows-only file enters the nginx-module
  `./config` list (proxy is platform-neutral).

## Effort × impact (recommended sequencing)

| Feature | Impact | Effort | Notes |
|---|---|---|---|
| G1 negative-lookup filter | High | Low | Build-workload headline; ships fast |
| G2 chunk-bundle endpoint | Very high | Med | Kills cold-start RTT storms |
| G3 trained dictionaries | High | Low–Med | Direct F12 upgrade |
| G4 packed content store | Very high | Med | pblock does the hard parts |
| G5 format tiering | High | Low–Med | Rides G4 |
| G6 mmap catalog index | Med–High | Med | Shares G1's walk pass |
| G7 kernel-native reads | **Highest** | High | Biggest differentiator; needs mount caps |
| G8 fs-verity | High (strategic) | Med | Rides G7 |
| G9 reflink fast-path | High | Low–Med | 80% of G7 at fraction of effort |
| G10 delta transfer | High | Med | Frequent-publish repos |
| G11 learned prewarm | Med–High | Med | Policy over F4 |
| G12 P2P swarm | High (at scale) | Med–High | Extends F8 |
| G13 global dedup CAS | Med–High | Low–Med | Namespacing over CAS |
| G14 repo-as-image | High (strategic) | Med | Reuses G7 emitter |
| G15 attestation | Med (strategic) | Med | Unique to a verifying proxy |
| G16 virtual repos | Med | Med | Config-plane |
| G17 scrubbing | Med | Low–Med | F1 verify on a schedule |

**Recommended first wave to land:** **G1 + G2 + G3** (Wave A — a "cold-start &
build-workload" story, all low/medium effort on existing seams, and all portable
across **all three** FUSE targets), then commit to **G4 → G9 → G7/G8** as the
flagship "next-gen storage + kernel-native reads" arc that structurally leapfrogs
the official client. G9 (reflink/clone) is the pragmatic stepping-stone to the
full G7 EROFS mount on **Linux** and de-risks it; on **macOS G9 (APFS `clonefile`)
is the destination** and on **Windows G9 (ReFS block clone) is the destination on
Dev-Drive/ReFS** — the kernel-native read path itself, since EROFS/overlay (G7)
and fs-verity (G8) have no macOS or Windows equivalent (§0.6). Land the portable
Wave B on all three targets before the target-divergent Wave C. Phase-86's pooled
connection reuse is assumed present throughout (landed dependency).

## Status

**NOT STARTED — plan only (2026-07-18).** All 17 features are design-stage; no
code written. Re-verify anchors at the start of each wave (post-Phase-85 tree is
UNCOMMITTED — confirm the F0 walk facade, pblock exports, F7 tier spine, and F8
mesh are present in the working tree before building on them).

**Landed dependencies assumed present:** Phase-85 (F0–F12) and **Phase-86 (FUSE
client connection reuse — `brix_cpool` + `brix_kaconn`/`brix_webmeta`)**. Confirm
`client/lib/net/cpool.{c,h}` and `client/lib/protocols/http/web_ka.{c,h}` are in
the tree before any phase-87 FUSE feature that opens its own transport builds on
them; if Phase-86 is not yet landed at build time, treat it as a hard predecessor.

**Three FUSE targets (Linux/libfuse3, macOS/macFUSE, Windows/WinFsp) are in
scope** per directive 7 + §0.6: the portable Wave A/B substrate runs on all three;
Wave C diverges (Linux EROFS/overlay + fs-verity; macOS APFS-clone via G9;
Windows ReFS-clone via G9 on Dev-Drive/ReFS, plain WinFsp FUSE on NTFS; no
fs-verity off Linux). A **macOS client-build CI lane and a Windows (WinFsp)
client-build CI lane** are part of the definition of done for every FUSE-side
feature.

Every Phase-85 git-write discipline applies: no commits without explicit OP
approval.
