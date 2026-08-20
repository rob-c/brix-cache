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
| G7 | **Kernel-native reads** — composefs/EROFS image + overlay mount; reads bypass FUSE | FUSE | C | `brixMount cvmfs --kernel` |  <!-- client-flags-allow: G7 proposal; brixMount has no --kernel -->
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
  *Reconciliation (2026-08-04):* phase-96 reversed the adjacent "we never
  author repos" reading — BriX now publishes Stratum-0 repos on the **tool
  surface** (`brixcvmfs repo …`, honoring the G14 tool-not-directive ruling)
  and serves them read-only via `brix_cvmfs_stratum0_root`. The serve plane
  still never writes; write-back to a Stratum-1 remains a non-goal. See
  `phase-96-cvmfs-stratum0-publishing.md` §0.0.
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
directive in `directives_resilience.h`. client: `shared/cvmfs/filter/xorf.c`
(pure-C xor filter, shared), wired in `shared/cvmfs/client/client.c` lookup path;
opt parsed in `client/apps/fs/brixcvmfs.c`. Shared → also usable proxy-side to
short-circuit known-404s (feeds the F9/negcache path).

**Tests (3).** (success) cold `stat()` of 1000 absent paths ⇒ 0 origin hits with
filter on, N without; (error) a filter for revision A applied after the repo
advances to B is refused/refreshed (root-hash mismatch), never serves a stale
ENOENT for a path that now exists; (security-neg) a tampered filter (bit-flipped
so a real path reads absent) fails its signed-hash check and is rejected —
`signal=cvmfs_tamper`, fall back to live lookups (never a fabricated ENOENT).

**LANDED (2026-07-27) — as built.** Shared xor-filter core =
`shared/cvmfs/filter/xorf.c` (+ unit `xorf_unittest.c`, driver-unit lane
`xorf`). Client `-o negfilter` / `$BRIXCVMFS_NEGFILTER` builds the filter
**itself** from the verified F0 walk of the mounted revision and answers
ENOENT in-process; revision change rebuilds it. **Design divergence: the
proxy pathset endpoint was RETIRED, not built.** A client-side filter built
from already-verified catalogs is trustworthy by construction, needs no new
signing surface, and avoids dragging sqlite into the proxy hot path — a
downloaded filter would have added a tamper surface (the security-neg test
above) for zero trust gain. The well-known URL stays unclaimed; nothing on
the wire changed. Live coverage: `tests/test_cmd_brixcvmfs_live.py`
(`negfilter-live` lane).

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

**LANDED (2026-07-27) — as built.** Endpoint `POST /cvmfs/<repo>/.cvmfs-bundle`
(gate `brix_cvmfs_bundle`, default off) in `src/protocols/cvmfs/bundle.c`;
wire = `BXB1 | u32 count | { u32 path_len | path | u64 data_len | data }…`,
`data_len == UINT64_MAX` = per-item miss marker. **Design divergences:**
(a) **want-list only** — the server-side "walk a root-hash for me" variant
was dropped: the client already holds the verified walk (F0), so shipping
path lists it computed itself keeps the proxy dumb and the trust unchanged;
(b) **resident-only fills** — the bundle serves from the local cache tier
and misses everything else (no origin fan-out inside the bundle), so the
endpoint can never be used to amplify one POST into N origin fetches; the
client fetches misses singly through the normal path; (c) the client
consumer (`-o bundle` / `$BRIXCVMFS_BUNDLE=1`,
`shared/cvmfs/fetch/fetch_bundle.c`) **rides the F4 prefetch worker** — the
foreground fetch path is untouched, every member still runs the single-fetch
decode/verify/store path, and any bundle failure degrades silently to
per-object GETs. Suites: `tests/test_cvmfs_bundle.py` (server) +
`tests/test_cvmfs_bundle_client.py` (client vs a wire-conformant Python
origin); codec/ingest units in `fetch_unittest.c` + `bundle_unittest.c`.

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

**LANDED (2026-07-27) — as built.** Shared codec =
`shared/cvmfs/dict/dict.c` (train/id/compress/decompress; ngx-free, unit
lane `dict`; zstd-less server builds stub it via `-DBRIX_DICT_NO_ZSTD`).
Server = `src/protocols/cvmfs/dict.c`: `GET /cvmfs/<repo>/.cvmfs-dict/
(current|<40-hex>)` (gate `brix_cvmfs_dict`, default off) lazily trains per
worker and **samples only the repo's CACHE-RESIDENT complete objects via the
cache adapter's own enumeration** — `brix_sd_cache_cstore()` +
`brix_cstore_scan()` (COMPLETE-cinfo + per-repo `cvmfs/<repo>/data/` prefix
+ size/arena caps), reading through `brix_cstore_serve_open()`. This is
load-bearing: the cache sd chain's `opendir` forwards to the http *source*
instance, so a VFS directory walk can never see residents — the cstore scan
is the one honest resident view. No cache tier / too-few residents ⇒
memoized 404 (60 s retry), never an origin fan-out. **Design divergences:**
(a) the coding is a **reversible transform of the STORED object bytes** —
CAS verify runs on exactly what it always ran on, so a wrong/hostile dict
can only fail decode, never poison data; (b) negotiation is a **private
header pair**, not Accept-Encoding: the client offers `X-Brix-Dict: <id>`
and the server codes (`Content-Encoding: zstd-dict`, `Vary: X-Brix-Dict`)
only on exact id match, only for unranged CAS data GETs ≤ 256 KiB, and only
when strictly smaller than identity; (c) the dict id (sha1 of the bytes,
`X-Brix-Dict-Id`) is **transport integrity only — TRUST stays with CAS
verify**; (d) the client (`-o dict` / `$BRIXCVMFS_DICT=1`,
`client/apps/fs/brixcvmfs.c`) pins the dict **in memory for the mount
lifetime** — one GET per mount, self-certified, any failure (absent,
id-mismatch, undecodable body) degrades to identity for the rest of the
mount; suffixed metadata objects (catalog `…C`, whitelist `…X`) are never
offered. Suites: `tests/test_cvmfs_dict.py` (server, 16) +
`tests/test_cvmfs_dict_client.py` (client vs a wire-conformant Python
origin, 4); units in `dict_unittest.c`.

**Wave A status: G1 + G2 + G3 LANDED 2026-07-27** (fast cvmfs regression
green: dict/bundle/prefetch/driver-unit/live suites + phase-84 gates-off
parity slice — all wire changes are opt-in; with every gate off the wire is
byte-identical to phase-84).

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

**LANDED (2026-07-27) — as built.** Store = `shared/cache/cas_pack.c`: an
append-only log of crc32-framed records in `<cache>/pack/seg-*.dat` segments
(size via `$BRIXCVMFS_CACHE_SEG_BYTES`) plus a replayable `index.log` journal;
dispatch behind the unchanged `brix_cas_*` call sites = `shared/cache/cas_store.c`;
gate honoured before the mount in `client/apps/fs/brixcvmfs.c`
(`-o cache_format=packed` / `$BRIXCVMFS_CACHE_FORMAT=packed`) +
`cvmfs_client_cache_config`. **Divergence from the plan above:** NOT a pblock
export — pblock is nginx-linked under `src/fs/backend/` and cannot link into the
ngx-free client shared tree, so the store is a standalone log-structured heap
(store-level corpus in `cas_pack_unittest.c`). Locality-packing / CDC dedup /
compaction from the design are deferred with it. Integrity is unchanged: pack
record crc + the fetch layer's `.chk` sidecar re-verify on every hit, so a
damaged record is a purge+refetch, never a wrong serving. Live 3-test suite =
`tests/test_cvmfs_packed_client.py` (rollover + offline serving + journal
replay with zero refetches; torn segment tail + truncated journal recovered;
bit-flipped record never served). Migration importer not built (packed and flat
caches simply coexist per mount).

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

**LANDED (2026-07-27) — as built.** A WRITE-side knob on the G4 packed store
(`shared/cache/cas_pack.c`): with `-o cache_tiering` /
`$BRIXCVMFS_CACHE_TIERING` (gate in `brixcvmfs.c`), PUTs zstd-compress an entry
when that actually shrinks it past `TIER_MIN` (cold packing, fmt byte 1 —
incompressible bodies stay raw, tiering never inflates), and an entry that
proves hot (`BRIX_PACK_PROMOTE_HITS` get()s) is re-appended raw so the log's
FIFO eviction approximates LRU. The read path always understands both formats,
so tiering and plain packed mounts replay each other's caches freely.
**Divergence from the plan above:** no separate temperature tracker or
compactor demotion — promotion-by-hit-count + PUT-time cold packing carry the
hot/warm/cold split; page-aligned exec-in-place raw objects await G7/G9.
Integrity unchanged (crc over the stored form + sidecar re-verify binds the
plaintext hash). Live suite = `tests/test_cvmfs_tiered_client.py` (cold-packed
corpus smaller than plaintext with no plaintext needles in any segment +
offline + cross-mode replay; hot promotion observed raw in the log;
incompressible stored raw; flipped record refetched genuine).

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

**LANDED (2026-07-27) — as built.** Index = `shared/cvmfs/index/pathidx.{h,c}`:
a single mmap'd cache sidecar `pathidx.bxi` holding the full merged namespace —
header (magic `BXPI`, version, `sizeof(cvmfs_hash_t)`/entry-size ABI guards,
raw root `cvmfs_hash_t`, crc32 over the header itself), fixed-size entries
sorted by (dirname, name) so `readdir` is a binary-search + contiguous run,
a NUL-terminated path/symlink blob, and an FNV-1a-64 open-addressed bucket
table for O(1) `lookup`. **Divergence from the plan above:** sorted-run +
FNV table instead of CHD/BBHash MPH + FST (same O(1)/enumeration contract,
far simpler, and the table stays valid mmap'd cold); built from the CLIENT's
own verified catalog walk (`cvmfs_walk_paths`, whose items now carry the full
catalog dirent) rather than server-side F0 output — nothing new is trusted.
Lifecycle = `shared/cvmfs/client/client_pathidx.c` + hooks in `client.c`:
resolve/readdir/read answer from the index only while its recorded root equals
the served root (pin root if pinned, else manifest root — so revision A's
sidecar is refused for revision B and rolling refresh degrades to a rebuild),
and index-resolved unchunked reads go straight to CAS with the index's hash.
Entry payloads are deliberately NOT crc'd (lazy paging): a tampered entry is
caught at first read by the CAS verify-fetch and the client drops the whole
index — fail-safe over-invalidation, catalogs stay authoritative. Gate =
`-o index=mmap` / `$BRIXCVMFS_INDEX=mmap` in `brixcvmfs.c` (`pathidx built
from verified walk` / `loaded from sidecar` / `unavailable` log contract).
Store-level corpus = `pathidx_unittest.c` (driver-units lane `pathidx`); live
4-test suite = `tests/test_cvmfs_mmap_index_client.py` — the success leg
proves catalogs left the hot path by DELETING the nested catalog object from
origin+cache (indexed remount still lists/reads the nested subtree; a control
mount without the index loses it), plus the failed-build no-op leg (below),
the revision guard, and the tampered-entry-hash leg (wrong-hash fetch
observed at the origin, genuine bytes served from the catalog fallback).
**Hardening found by the index conformance parity run:** the build's walk
fetches every nested catalog, and on a repo with a broken/tampered nested
catalog those (expected) failures fed `cvmfs_failover_record` — on a
single-host mount that blacklisted the only origin and pushed the WHOLE
mount offline, killing the catalog fallback too (evil/craft control tests in
`test_cvmfs_conformance_fuse_catalog.py` caught it). Fix in
`cvmfs_client_pathidx_build`: snapshot the failover engine (flat struct)
before the walk and restore it when the build fails — an opportunistic build
must leave transport health exactly as it found it.

**Wave B status: G4 + G5 + G6 LANDED 2026-07-27** (packed/tiered/mmap-index
live suites + driver-unit lanes + fast cvmfs regression green). Conformance
parity: read/posix/catalog suites green under BOTH
`BRIXCVMFS_CACHE_FORMAT=packed` and `BRIXCVMFS_INDEX=mmap`;
`test_cvmfs_conformance_fuse_cache.py` self-skips under packed (it asserts
the FLAT store's on-disk contract — packed equivalents live in
`test_cvmfs_packed_client.py`) and stays green flat.

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
  bundle warms it) → emit image → mount. `brixMount cvmfs --kernel <fqrn>`.  <!-- client-flags-allow: G7 proposal; brixMount has no --kernel -->
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

**LANDED (2026-07-27) — as built (server leg).** `src/protocols/cvmfs/delta.c`
+ gate `brix_cvmfs_delta on|off` (default off). Wire: a CAS data GET carrying
`X-Brix-Delta-Base: <40-hex>` may be answered `Content-Encoding: zstd-delta`
(+ `X-Brix-Delta-Base` echo, `Vary`), where the payload is the target
compressed with the base object's bytes as a **raw-content zstd dictionary**
(patch-from semantics). Hooked in `cvmfs_tier_open_respond` **before** the G3
dict try-serve (a same-lineage base beats any trained dictionary); identical
`NGX_DECLINED`-falls-to-identity contract.

Divergences from the sketch, all deliberate:
- **No new delta codec**: CDC/bsdiff dropped — the delta IS the G3
  `cvmfs_dict_compress` codec with the base as the dict (zstd loads non-ZDICT
  bytes as a raw prefix). One codec, both features; ~1% churn on a ~350 KiB
  catalog deltas to well under 10% of identity (test-asserted).
- **Resident-only base** (the G2/G3 anti-amplification rule): the base is
  resolved via `brix_cstore_cinfo_load` (COMPLETE, ≤ 4 MiB) +
  `brix_cstore_serve_open` — a base miss can never trigger an origin fetch;
  the client just gets the whole object.
- **Per-object opt-in, no revision negotiation**: the client names the exact
  base hash (its pinned revision-N catalog when fetching N+1); the proxy keeps
  no revision model. The base inherits the target's CAS suffix class.
- **Trust unchanged**: a raw-content dictionary has no embedded dictID, so a
  wrong-base reconstruction *may* emit bytes — whose CAS hash cannot match the
  name; the client's ordinary CAS verify is the gate (test-asserted, plus
  no-tamper-signal assert: the coding transforms verified stored bytes and can
  never manufacture an origin-tamper event).
- **Client (FUSE) leg deferred**: threading the header into the phase-84
  atomic catalog-refresh machinery (held-revision tracking + sidecar base
  load) is its own bounded feature; the wire contract needs only one request
  header + raw-dict zstd decode + the existing CAS verify.
- 4 MiB base/target cap keeps request-pool buffering ≤ 12 MiB and both sides
  inside zstd level-19's window without advanced-parameter plumbing.

Tests: `tests/test_cvmfs_delta.py` (3/3 green — reconstruct+CAS-verify,
non-resident/malformed base → identity with no base fill, wrong-base CAS
rejection + whole-refetch heal). Regression: seam guard + 6-file cvmfs sweep
green.

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

**LANDED (2026-07-27) — as built (proxy leg).** `src/protocols/cvmfs/learn.c`
+ gate `brix_cvmfs_learn on|off` (default off). A per-worker Markov model of
CAS access sequences: the request path (`brix_cvmfs_learn_note`, hooked at
the classified CAS tier entry in `cvmfs_tier_get`) records this connection's
previous-key → current-key transition into a fixed successor table (256
nodes × 3 successors, FNV-1a64-indexed), then looks the current key up and
posts one bounded batch (≤ 4) of confident (count ≥ 2), non-resident
successors to the thread pool, where `brix_sd_cache_fill_key` runs the
ordinary verified whole-file fill. Lifecycle mirrors the G17 scrub
(config-time per-export registration in `cvmfs_merge_cache`, task built at
`init_process`) except it arms in EVERY worker — the model is
request-stream-local.

Divergences from the sketch, all deliberate:
- **No F4/F5 coupling**: F4/F5 are CLIENT-side (FUSE prefetch worker /
  `brixMount --prewarm`); the proxy leg drives the phase-64 cache-fill seam
  directly — the fill spine is already the verified, admission-gated,
  single-flight "mechanism", so G11 stays a pure policy layer with no
  transfer path of its own.
- **Connection-keyed sessions, not job signatures**: `r->connection->number`
  keys a 64-slot last-key table — a keep-alive request sequence IS the
  workload trace; no job/user identity is modeled at all (the security-neg
  test trains under two different `Authorization` identities and the
  prediction fires for an anonymous connection).
- **Mispredict-storm containment by construction**: an unrecognized access
  matches no node and prewarms nothing; one task in flight per export, ≤ 4
  keys per batch, 8 fills/s rate cap, and already-resident predictions are
  skipped via a cinfo lookup (event loop, L1) before posting.
- **Fixed memory, overwrite-on-collision**: a node-slot collision with a
  different predecessor resets the node and the demoted pattern re-learns —
  O(1) memory beats a perfect model here. "Named warm sets" (publishable
  pinned profiles) deferred with the F5 operator surface.
- **INVARIANT #8 by omission**: no metrics — observability is one DEBUG line
  on post and one INFO line on completion (counts and the export root only).

Tests: `tests/test_cvmfs_learn.py` (3/3 green — trained A→B transition
prewarms an evicted B from a single fresh GET of A, composing with the G17
scrub for the eviction; an unrecognized access grows the cache by only
itself; user-blind profile + no token material in logs). Regression: seam
guard + dict/delta/scrub/learn sweep 25/25 green.

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

**LANDED (2026-07-27) — as built.** Three planes:

*Data plane* (`src/fs/backend/cache/sd_cache{.h,.c,_internal.h,_fill.c}`): an
immutable `brix_sd_cache_ring_t` {n, self, peers[16]} published via
`brix_sd_cache_ring_swap` (event loop, `ngx_memory_barrier()` before the
`volatile` pointer store); the fill spine loads the pointer ONCE per fill and
the dynamic ring takes precedence over the static F8 ring
(`sd_cache_peer_owner` now takes an explicit peers/n). Published rings are
**never freed** — membership churn leaks ~4.5 KiB per swap by design (torn
reads are impossible; the verify gate bounds residual wrongness to efficiency,
never integrity). Verify/tamper paths are UNCHANGED: the actor comes from the
fill-source instance (`fs->src`), so a lying dynamic sibling raises
`signal=cvmfs_tamper` naming it with zero new code.
`brix_sd_cache_get_peers` exposes the static seed ring to the membership
plane.

*Membership plane* (`src/protocols/cvmfs/swarm.c`, scrub-style lifecycle,
EVERY worker — the ring is per-worker registry state): SWIM-lite **push-pull**
gossip. Seeds lazily from `brix_cache_peers`; a per-export timer round-robins
one member per interval and posts a thread-pool task doing a bounded
plain-socket HTTP/1.0 GET of the target's roster (RTT-probe socket precedent;
SO_RCVTIMEO/SNDTIMEO 5 s, 32 KB cap) with `?from=<label>&gen=<gen>`
**introducing the prober** — pull-only gossip can never propagate a new
member upstream, so the roster endpoint merges the caller as a live member.
Roster = `swarm-roster-v1` + `label state gen` lines. Merge rules: higher gen
wins; equal-gen dead-wins; a node seeing ITSELF dead at gen ≥ own bumps its
boot-time (time-seeded) generation — the SWIM refutation, so a rejoin
self-heals. 3 consecutive probe misses → dead (spread by gossip); a direct
probe answer beats gossip and resurrects. Ring rebuild: ALIVE labels sorted
lexicographically (deterministic swarm-wide — HRW then agrees with no
coordination), self must be present and n ≥ 2, non-self fill sources lazily
`brix_tier_build`-built (http, cached forever; build failure = NULL slot,
those keys fall to origin), published only on actual change.

*Roster endpoint*: intercepted in `brix_cvmfs_gate` BEFORE
`cvmfs_classify_url` (classify would 403 the shape), gated `brix_cvmfs_swarm`,
GET-only, URI suffix `/.swarm/roster`; world-readable by design (labels +
generations only). Directives: `brix_cvmfs_swarm` (flag) +
`brix_cvmfs_swarm_interval` (sec, default 3); config-time hard-fail without
`brix_cache_peers` (the seed ring names self). Init chain is now
rtt→scrub→learn→swarm (module.c).

Divergences from the sketch: membership view capped at 64 and the published
ring at 16 (`BRIX_SD_CACHE_MAX_PEERS`) with the lexicographic tail logged as
falling to origin (no silent caps) — true DHT scale (10k nodes) needs a
finger-table/consistent-hash ring and is deferred; SWIM indirect probes
(ping-req) omitted — misses are cheap at these sizes; the test swarm is 5
nodes (PortBlock capacity), not 20 — the O(1)-origin property is asserted
exactly (`sum(origin fetches) == 1` across the swarm for a cold object
fetched via two non-owners). Anti-amplification holds: gossip is node-to-node
metadata; no client request gains extra origin fetches.
`tests/test_cvmfs_swarm.py` (4: convergence+O(1) / dead-member route-around /
tamper naming the sibling / config refusal) green; mesh/learn/scrub/delta/
dict/bundle regression 48/48; `check_vfs_seam` OK.

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

**LANDED (2026-07-27) — as built.** Divergence from the sketch above: NOT a
shared keyspace/namespacing layer — that shape is unbuildable here, because the
single cache key is BOTH the store name AND the origin fetch path
(`sd_cache_forward` fills at the key path), and a global keyspace would serve
repo B's resident bytes to a repo-A request whose own origin never proved them.
As built it is **commit-time hardlink dedup**: keys, cinfo, authz and origin
fetches stay strictly per-repo (each repo fills — and honestly 404s — through
its OWN origin; F3 untouched); after a **cvmfs-cas-VERIFIED** commit the object
is hardlinked to a canonical repo-agnostic name
`<store>/.gcas/<2hex>/<resthex><suffix>`, so byte-identical cross-repo objects
collapse onto ONE inode. The filesystem's `st_nlink` IS the combined refcount —
no bookkeeping to double-free. WAN cost is unchanged (first access per repo
still fetches); the savings are storage.

Module = `src/fs/cache/gcas.{h,c}`: `brix_gcas_canonical_rel` (classify-gated —
only `CVMFS_URL_CAS` keys map), `brix_gcas_publish` (first appearance registers
the canonical via `link(2)`; later byte-identical fills ADOPT it via
link-to-`.gclnk`-temp + `rename(2)` — atomic, open readers keep their inode; a
size mismatch WARNs and never collapses), `brix_gcas_evict_gc` (called from
`brix_cstore_evict`; unlinks the canonical at `st_nlink<=1`). Armed once in
`brix_sd_cache_create` (`brix_cstore_enable_gcas`) so fills, evictions AND the
stream watermark reaper all see it; the publish hook at the end of
`cache_fill_commit` self-gates on `global_cas && fs->verified && verify ==
CVMFS_CAS` — best-effort/require modes verify an origin-advertised digest that
does NOT bind the key's hash, so they never publish. Directive =
`brix_cache_global_cas on` (12th `BRIX_TIER_DIRECTIVES` entry, both planes;
config-time constraint = posix store only — verify mode is deliberately NOT
constrained at config time so a GC-only stream reaper config parses). Reaper
interplay: `/.gcas/` names are ordinary LRU candidates — early eviction of a
canonical is harmless (other links keep the inode; GC no-ops on ENOENT via the
classify REJECT gate; only future dedup registration is lost). Tests =
`tests/test_cvmfs_global_cas.py` (3: dual-repo one-inode `st_nlink==3` dedup +
repo-B-fills-via-its-own-origin honesty; watermark-evict canonical GC drains
the store with no orphan inode, template
`tests/configs/nginx_cvmfs_gcas_evict.conf`, lifecycle port 30411; security-neg
= repo-B-only bytes requested via repo A → honest 404, no repo-A key
materialises, canonical untouched).

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

**RULED (2026-07-27) — DEFERRED, blocked on G7; client-plane alternative
registered.** Not landed, on three grounds. (1) The design's *defining*
property — an image whose content is SHARED from the CAS via
fs-verity/EROFS/composefs rather than copied — reuses the G7 image emitter,
and G7 is infra-blocked on this box (no root, no EROFS/overlay mount, no
fs-verity filesystem): landing an emitter none of whose success legs can
execute here would be dead unverifiable code, the same verify-before-report
rule that ruled Wave C. (2) The catalog→tree plane (nested-catalog fetch +
parse + walk) links only into the CLIENT (`shared/cvmfs/walk` +
`shared/cvmfs/catalog`, consumed by `client/apps/fs/brixcvmfs.c`); the proxy
links `shared/cvmfs/object` only. A proxy-side `GET /.cvmfs-image` endpoint
would have to pull that whole plane into nginx workers and is
amplification-shaped besides — one GET fanning out into a whole-tree origin
walk — colliding with the anti-amplification invariant every landed phase-87
proxy feature preserves (G2 bundle serves residents only; G16's member walk
is bounded by the configured member count). (3) The one leg that IS pure
userspace and verifiable without mounts — rendering a revision as an OCI tar
layer — is therefore a client-tool concern: `brixcvmfs` already owns
fetch+walk, and a future `brixcvmfs export --format=oci-tar` would deliver  <!-- client-flags-allow: explicitly future tooling; brixcvmfs has no export subcommand -->
"CVMFS content without a CVMFS client" as a userspace-verifiable artifact.
That leg is registered as future client-tooling work, not landed now: a tar
is a copy, not a CAS share, so it carries none of G14's distinguishing value,
which stays gated on G7.

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

**LANDED (2026-07-27) — as built.** `src/protocols/cvmfs/attest.c` + directive
`brix_cvmfs_attest <private-key.pem>` (unset = off; key loaded fail-fast at
config time with a cf->pool cleanup, same contract as the F1 trust anchor).
Mechanism: a data request tagged `X-Brix-Attest: <label>` (label BOUND before
use — 1..64 chars of `[A-Za-z0-9._-]`, phase-83 lesson; invalid labels are
NOTICE-logged and the request served untagged) has its label captured in the
gate; the **request-finalization observer** — the one place every serve path
converges, including the G16 member walk — records the served CAS hash
(`ctx->url.cas_hex`, a by-value classify field, so no freed-buffer hazard) on
final status 200/206 only. Zero hot-path work: nothing runs when the
directive is unset, and recording happens at request teardown. The record is
a SET (re-reads don't duplicate).

Query: `GET <loc>/.cvmfs-attest?session=<label>` (pre-classification
endpoint, swarm-roster idiom) returns a **DSSE envelope over an in-toto v1
Statement** — subject = the consumed digest set (40 hex → `sha1`, else the
neutral `cvmfs` DigestSet key), predicate `{session, count, truncated}`;
signature = SHA-256 `EVP_DigestSign` (RSA/ECDSA) over the DSSE PAE. Unknown
session → 404; missing/invalid `session=` → 400; endpoint with attest off →
403 (classify: not a CVMFS traffic shape).

Honest limits, documented in the file header: per-worker session table (32
sessions × 256 hashes, same documented-exception idiom as the T13 memo —
eviction and truncation both NOTICE-log exactly what dropped, no silent
caps); the label is a client-chosen capability, not an identity (records
carry hashes only). Suite `tests/test_cvmfs_attest.py` (3 green: exact
consumed-set + client-side DSSE/PAE signature verification with the real
pubkey; attest-off inert tagging + endpoint 403/404/400 matrix;
tampered-payload and attacker-key verification both fail). Neighbor
regression 116 green (virtual/repo_authz/swarm/srv_gate); VFS seam guard OK
(config-domain key reads carry seam-allow).

**HARDENED (2026-07-27, same day) — gated sessions sit behind the F3 gate.**
The depth-test sweep found the record endpoint (pre-classification) bypassing
F3: a token-gated repo's consumption record was anonymously readable, and the
`repo_authz_eval` helper silently declined there because `ctx->url.repo` is
only set by classify. Fail-closed fix: sessions now carry a sticky `gated`
bit, set whenever a recorded hash came from a repo matching a
`brix_cvmfs_repo_authz` entry (new pure-lookup helper
`brix_cvmfs_repo_authz_gated()` in secure.c). A gated session's record serves
only when the endpoint URL names a GATED repo (an ungated sibling name is a
401 — using it would be a gate bypass, since the session table is
location-global) and that repo's standard F3 eval passes (TLS + valid
READ-scope bearer; the endpoint parses the fqrn from its own URI and seeds
`ctx->url.repo` before eval). Sessions of only-open content keep the
documented open, label-as-capability contract. Location-coarse by design
(any gated repo's reader in the location qualifies) — noted in HONEST LIMITS.

**Depth tests (same sweep).** `tests/test_cvmfs_attest.py` grew to 8: ranged
(206) tagged reads attested; invalid/overlong labels serve untagged and a
tagged MISS creates no session; the 32-slot table evicts oldest-only under 33
sessions with neighbors intact; a G16 member-walk serve is attested with the
final member classify state; and the F3 security-neg above (anon 401, sibling
401, token 200+verify, open session stays open).
`tests/test_cvmfs_virtual_repo.py` grew to 6: a member origin 5xx SURFACES
(T20 hold→504) and never advances the walk — member[1] provably unconsulted —
with clean recovery after the origin heals; PUT/DELETE through the virtual
name are the same 405 as direct (no new write surface). Harness fact: the
default `brix_cvmfs_client_hold` (25s) outlives urllib timeouts — fault tests
set `brix_cvmfs_client_hold 2;`.

### G16 · Virtual / composed repos

**Design.** Compose a **virtual repo** as a read-only overlay/union of upstreams,
or a filtered/curated subset (expose only `/release/X`, or a thin repo). Serve a
namespace that doesn't physically exist upstream. Config-plane feature over the
existing multi-source fill + classify logic. Gated `brix_cvmfs_virtual_repo`.

**Tests (3).** (success) a union of two upstreams presents a merged tree with
deterministic precedence; (error) a path absent in all members is a clean 404;
(security-neg) each member's F3 authz is enforced independently — the composition
never elevates access.

**LANDED (2026-07-27) — as built.** `src/protocols/cvmfs/virtual.c` + directive
`brix_cvmfs_virtual_repo <virtual-fqrn> <member-fqrn>...` (multi-occurrence;
declaration order = member precedence). Mechanism: **gate-time in-place URI
rewrite**, not a parallel routing plane. `brix_cvmfs_virtual_enter()` runs in
`brix_cvmfs_gate` immediately after classify and BEFORE method police / proxy
bind / repo accounting / F3 repo-authz / class routing — a request naming the
virtual fqrn is rewritten to member[0] and then policed **exactly as a direct
request for that member**. Composition-never-elevates is structural, not
per-subsystem: F3 gates, per-repo metrics, upstream binding and cache keys all
see the member path automatically, so an object reached via the virtual name
and via direct member access is ONE cache entry (asserted by test).

**404-advance, two paths.** Only a definitive 404 advances the walk
(`brix_cvmfs_virtual_advance()`: bump `virt_idx`, re-rewrite from the SAVED
original uri, reset `cache_status`/`origin_used`/`repo` so a failed member[0]
fill never mislabels a member[1] hit). (a) Synchronous: the handler tail is a
gate→tier loop that advances on 404. (b) Asynchronous: a parked fill that
resolves ENOENT finalizes directly (reenter fires only on success), so the
**shared fill machinery gained an opt-in `on_fail` interceptor**
(`brix_http_fill_fail_pt`, trailing param on `brix_http_cache_fill_if_needed` /
`brix_http_fill_attach`; WebDAV/S3 pass NULL — behavior unchanged). cvmfs's
`cvmfs_fill_fail` re-runs the handler on 404+advance; a fresh park holds its
own reference and `finalize(NGX_DONE)` balances the old one. 401/403/5xx from
a member is FINAL (access denial is never papered over by a permissive
sibling); the T20 hold-expiry 504 path bypasses the interceptor (unreachable ≠
definitive answer). Anti-amplification: the walk is bounded by the CONFIGURED
member count, each member consulted at most once per request, driven only by
definitive 404s.

Config-time validation rejects duplicate virtual names, self-membership,
nesting (both declaration orders) and duplicate members. Divergences from the
sketch, deliberate: **no `expose=` filter and no catalog synthesis** — this is
HTTP-plane composition; the proxy cannot see logical paths inside CAS objects,
so `.cvmfspublished` comes from the first member that has it (deterministic
precedence, asserted) and filtered/curated subsets would need the G14/G7
catalog plane. Suite `tests/test_cvmfs_virtual_repo.py` (4 green: union +
precedence + shared-cache-entry; absent-everywhere clean 404 with both members
HEAD-probed exactly once; TLS+token security-neg — anonymous via virtual → 401
on the gated member, ungated sibling still serves, valid bearer opens it;
`nginx -t` validation matrix). Neighbor regression 151 (cvmfs
proxy/resilience/authz/swarm/mesh) + 24 (fill machinery, WebDAV/S3 fill users)
green; VFS seam guard OK. Test-harness facts learned: absence is discovered at
the fill's HEAD size-probe (mock logs GET fetches only — assert on
`/ctl/heads`), and `nginx -t` binds listen sockets (accept-case configs need a
real allocated port).

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

**LANDED (2026-07-27) — as built.** `src/protocols/cvmfs/scrub.c` + directives
`brix_cvmfs_scrub on|off` (default off), `brix_cvmfs_scrub_interval` (default
60s), `brix_cvmfs_scrub_rate` (objects per pass, default 20, clamp 256).
Registration at config time (`cvmfs_merge_cache`, same lifecycle as the T19 RTT
probe); at init_process **worker 0 only** arms a repeating timer per registered
export. Each pass: on the **event loop**, `brix_cstore_scan` collects up to
`rate` CAS-classified resident keys from a persistent cursor (wrap → cursor 0;
store mutation between passes drifts the window — best-effort by design); on the
**thread pool** (export's pool, fill-verify precedent) each object is re-hashed
via `brix_cache_verify_cvmfs_cas(path, key, log=NULL, …)`; back on the event
loop the done handler evicts mismatches via `brix_cstore_evict` and re-arms.

Divergences from the plan, all deliberate:
- **Heal is lazy, not eager**: a corrupt object is evicted so the *next access*
  re-fills verified through the ordinary fill machinery (retry budget,
  quarantine, verify gate all reused). No scrubber-initiated origin fetch.
- **No peer heal**: the F8/G12 mesh leg is deferred until G12 lands.
- **Proxy surface only**: the FUSE-client leg is not landed (client cache has
  its own sidecar verify story, phase-84 client hardening).
- **The security-neg test inverts the plan's wording, correctly**: a scrub
  mismatch is LOCAL corruption (disk bitrot — the origin proved these bytes at
  fill time) and must **never** raise `signal=cvmfs_tamper` — that signal names
  a lying *origin* and feeds the maxretry-1 instant-ban jail (cold-tier lesson).
  Hence `log=NULL` into the verify helper (its mismatch line blames origin
  transfer) and a scrubber-owned WARN naming the local actor instead. The
  "corrupt heal source rejected" clause still holds: it is enforced by the
  re-fill's own verify gate (persistent-corrupt origin ⇒ gateway ≥500, never a
  corrupt 200 — same contract as `test_cvmfs_conformance_srv_cas.py`).
- `/.gcas/` canonical names classify REJECT and are skipped by the visitor —
  correct: the canonical inode is verified through each repo-visible hardlink
  key that shares it (G13).

Tests: `tests/test_cvmfs_scrub.py` (3/3 green — detect+heal, rate-bounded
passes, no-tamper-for-local-rot + corrupt-origin-refill rejected). Regression:
seam guard + 5-file cvmfs sweep green.

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

**Waves A + B LANDED 2026-07-27 (UNCOMMITTED).** G1 negative filter, G2 bundle
endpoint, G3 dictionary transfer, G4 packed content store, G5 format tiering,
G6 mmap catalog index — each with a per-feature "LANDED — as built" block (and
recorded divergences from the plan) at the end of its section above.

**Wave D: G13 + G17 LANDED 2026-07-27 (UNCOMMITTED)** — G13: cross-repo dedup
CAS as commit-time hardlink dedup (`src/fs/cache/gcas.{h,c}`, directive
`brix_cache_global_cas`); see the "LANDED — as built" block in the G13 section
for the key-rewrite dead-end, the verified-fill publish gate, and the
reaper/`.gcas` interplay. G17: background CAS scrubbing
(`src/protocols/cvmfs/scrub.c`, `brix_cvmfs_scrub` + interval/rate), worker-0
timer, evict-then-lazy-heal, **no tamper signal for local rot**; divergences in
the G17 "LANDED — as built" block.

**Wave D: G10 LANDED 2026-07-27 (UNCOMMITTED)** — cross-revision delta
transfer, server leg (`src/protocols/cvmfs/delta.c`, `brix_cvmfs_delta`,
`X-Brix-Delta-Base` → `Content-Encoding: zstd-delta`): the G3 dict codec with
the client's held base as a raw zstd dictionary, resident-only base, trust
stays with CAS verify; FUSE-client leg deferred — see the G10 "LANDED — as
built" block. Remaining Wave D (G11/G12) proceeds next.

**Wave D: G11 LANDED 2026-07-27 (UNCOMMITTED)** — workload-learned
predictive prewarm (proxy leg): per-worker connection-keyed Markov model +
thread-pool prewarm through the cache-fill seam, gate `brix_cvmfs_learn`
(default off); `tests/test_cvmfs_learn.py` 3/3. Full detail in the G11
"LANDED — as built" block. Remaining Wave D (G12) proceeds next.

**Wave D: G12 LANDED 2026-07-27 (UNCOMMITTED) — Wave D COMPLETE.** P2P swarm
cold-start: immutable dynamic-ring seam in the sd_cache fill spine
(swap/never-free, static F8 ring as fallback) + SWIM-lite push-pull gossip in
`src/protocols/cvmfs/swarm.c` (roster endpoint pre-classification in the
gate, prober self-introduction, gen-based merge with dead-wins + refutation)
publishing the sorted-alive-label ring per worker. Gates `brix_cvmfs_swarm` +
`brix_cvmfs_swarm_interval` (requires `brix_cache_peers`).
`tests/test_cvmfs_swarm.py` 4/4 (swarm-wide O(1) origin cold start asserted
exactly); neighbor regression 48/48. Full detail in the G12 "LANDED — as
built" block. Wave E (G14/G15/G16, as feasible) is next.

**Wave E: G16 LANDED 2026-07-27 (UNCOMMITTED).** Virtual/composed repos:
`brix_cvmfs_virtual_repo` via gate-time in-place URI rewrite (member is policed
exactly as a direct request — composition never elevates structurally) + 404
member walk on both the synchronous handler-tail loop and the async fill path
(shared fill machinery gained an opt-in `on_fail` interceptor; WebDAV/S3
unaffected). No `expose=` filter / no catalog synthesis — HTTP-plane
composition only, ruled in the G16 "LANDED — as built" block.
`tests/test_cvmfs_virtual_repo.py` 4/4; neighbor regression 151 + 24 green;
VFS seam guard OK. Remaining Wave E: G15 attestation, G14 ruling.

**Wave E: G15 LANDED 2026-07-27 (UNCOMMITTED).** Runtime provenance
attestation: `brix_cvmfs_attest <key.pem>` — X-Brix-Attest session tagging
captured in the gate, consumed CAS hashes recorded at the request-finalization
observer (per-worker bounded table, no silent caps), signed DSSE/in-toto
record served at `/.cvmfs-attest?session=<label>`.
`tests/test_cvmfs_attest.py` 3/3; neighbors 116 green; seam guard OK. Full
detail in the G15 "LANDED — as built" block. Remaining Wave E: G14 ruling.

**Wave E COMPLETE (2026-07-27): G16 + G15 landed, G14 RULED deferred-on-G7.**
G14 (repo-as-image export) is not landed: its defining CAS-sharing property
reuses the G7 emitter (Wave C infra-blocked), the catalog→tree walk plane is
client-only (`shared/cvmfs/{walk,catalog}` link solely into
`client/apps/fs/brixcvmfs.c` — not in the proxy source list), and a proxy-side
image endpoint would be amplification-shaped. The feasible userspace leg is
registered as future client tooling (`brixcvmfs export --format=oci-tar`).  <!-- client-flags-allow: explicitly future tooling; brixcvmfs has no export subcommand -->
Full grounds in the G14 "RULED" block. Phase-87 is now closed except the
infra-blocked Wave C items.

**Wave C (G7/G8/G9) — INFRA-BLOCKED on the dev box (ruled 2026-07-27).** Every
success path needs kernel facilities this WSL2 environment cannot provide
without root: G7 needs EROFS+overlayfs mount capabilities; G8 needs an
fs-verity-enabled filesystem; G9 needs a reflink-capable FS (all local volumes
are ext4 — `FICLONE` is EOPNOTSUPP) and the FUSE-passthrough alternative needs
libfuse ≥ 3.17 (box has 3.10.2; kernel CONFIG_FUSE_PASSTHROUGH=y is present
but undrivable from this libfuse). No sudo ⇒ no loop-mounted XFS/btrfs lab
either. Per the verify-before-report rule, landing clone/EROFS/verity code
whose success legs can never execute here would be dead unverifiable code —
Wave C waits for a box/CI lane with root or a reflink volume (same class as
the phase-88 §4 infra-blocked register). Waves D–E (G10–G17, proxy-side, pure
userspace) are NOT blocked and proceed next. Re-verify anchors at the start of
each wave (tree is UNCOMMITTED — confirm the F0 walk facade, pblock exports,
F7 tier spine, and F8 mesh are present in the working tree before building on
them).

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

**Depth-test regression sweep + guard burndown (2026-07-27, later).** Full
CVMFS-family regression after the G15/G16 depth-test additions: **669 tests →
662 passed / 6 xfailed / 1 failed**, and the one failure was a real
observability gap, not test flake: `test_dead_member_detected_and_routed_around`
asserted the "marked dead" NOTICE, but that line only fired on the *direct*
probe-miss path — a death adopted via **gossip merge** (`gen >` transition, or
equal-gen dead-beats-alive) flipped `m->dead = 1` silently, so whichever node
learned of the death second logged nothing. Fixed in product (not the test):
`cvmfs_swarm_gossip_dead()` now emits "member … marked dead via gossip, its
keys route around it" on both adoption arms, making detection-order
irrelevant. Suites after fix: swarm 4/4 + peer_mesh 7/7, and the touched-area
lane (swarm/peer_mesh/virtual/attest/prewarm 28 + learn/srv_gate/srv_http
conformance 171+6xf) all green on the rebuilt binary.

Same session closed this lineage's CI-guard debt from the wave landings:
`handler.c` (644 ln) split → `handler_finalize.c` (finalize observer family,
seam decl in `cvmfs_module_internal.h`); `swarm.c` (811 ln) split →
`swarm_gossip.c` (probe thread/ring/lifecycle) + `swarm_internal.h` (types +
former-static seams, no new state); CCN decompositions to ≤15 for
`virtual.c::cvmfs_conf_virtual_repo`, `swarm.c` roster merge + roster endpoint,
`swarm_gossip.c::cvmfs_swarm_ring_publish`, and `learn.c::cvmfs_learn_predict`
(candidate collection + pool resolve extracted). `check_file_size`,
`check_complexity` (for these), `check_vfs_seam` and the 6 quick guards all
green; clean `-Werror` rebuild.

**Gossip-plane + learn depth tests (2026-07-27, later still).** Second
depth-test round targeting the paths the deflake/decomposition touched, which
until now had success-leg coverage only. `tests/test_cvmfs_swarm.py` grew 4→7:
a scripted `FakeMember` adversary (real HTTP listener, roster body chosen by
the test) drives (5) *slander of a live member* — death adopted **via gossip**
with its NOTICE, then resurrected by the next direct probe answer ("direct
proof beats gossip"), data plane never black-holed; (6) *garbage rosters +
self-slander* — bad-header and bad-line payloads are ignored whole, a real
self-slander triggers the SWIM refutation NOTICE and the node re-advertises
alive at a generation outbidding the lie; (7) *malformed introductions* — six
parse-failing `?from=` shapes, none may add a member or kill the endpoint.
The dead-member test now asserts BOTH survivors log "marked dead" (the exact
pre-fix flake). `tests/test_cvmfs_learn.py` grew 3→4: the confidence gate at
its boundary (1 observation never prewarms, the 2nd fires; the per-second
rate cap is deliberately untested — timing-flaky load-shedding valve, noted
in-file). Test-authoring gotchas: `self_gen` is boot wall-clock seconds, so a
refutation-worthy slander must outbid the node's CURRENT advertised
generation (read it from the node's own roster line); an equal-gen liar
re-kills on every probe (dead-beats-alive), so hostile fixtures must be
one-shot or the heal never settles. swarm 7/7 + peer_mesh 7/7 + learn 4/4,
3× stable; host-literal guard 8/8. One transient peer_mesh fixture-error
round when a run started seconds after the previous teardown = the known
cross-invocation port-contention class, not the new tests.

**Open CCN register — BURNED DOWN 2026-07-27, see the dated block at the end
of this section.** (original register kept for the record:) `check_complexity` still
reds on earlier-session phase-85/87 landings — `delta.c::brix_cvmfs_delta_try_serve`
(37), `dict.c::brix_cvmfs_dict_try_serve` (26), `gate.c::brix_cvmfs_gate` (33 >
frozen 17, grew across the F3/G15/G16 gate integrations),
`attest.c::brix_cvmfs_attest_gate` (19), `bundle.c::cvmfs_bundle_fill_one` (16),
`cvmfs_module_build.c::cvmfs_merge_cache` (16),
`handler.c::ngx_http_brix_cvmfs_handler` (16), `gcas.c::brix_gcas_publish` (16),
`client/apps/fs/brixcvmfs.c` ×5 (mount_run 26 · transport 27 · opts_o_list 24 ·
open 18 · pf_bundle_flush 17), plus other-workstream
`cms/server_recv_parse.c::cms_srv_parse_login` (17). These predate the
depth-test session and need their own deliberate decomposition pass (do NOT
`--regen` locally — lizard 1.23.0 drift vs CI). The 4 `check_duplication` reds
are all in other-workstream files (root-stream enums, webdav commands/dispatch,
tpc key_registry) — out of scope here.

**Storage-plane depth tests — delta/gcas/scrub (2026-07-27, third round).**
The three thinnest phase-87 suites (3 tests each) grew against contracts
pinned by reading the server code first. `tests/test_cvmfs_delta.py` 3→6:
(4) *guard branches decline to identity* — a ranged request is served from
identity bytes as a plain 206 (ranges address the identity representation;
a delta-coded 206 would be wrong bytes), base==target declines (zero delta,
identity already optimal), HEAD never advertises the coding; (5) *strictly-
smaller rule* — an unrelated incompressible resident pair falls back to exact
identity with no `Content-Encoding` and no base echo (the `out` buffer is
capped at `srclen`, so "no gain" surfaces as a compress failure → DECLINED);
(6) *no residue* — after a delta-coded serve, repeated plain GETs return full
identity bytes (Vary correctness: the coding can never poison delta-unaware
clients sharing the cache). `tests/test_cvmfs_global_cas.py` 3→5: (4) *publish
gate* — an origin serving bytes under a CAS name they don't hash to is
rejected ≥500 and registers NO `/.gcas` canonical and no per-repo key (the
gate is `fs->verified && verify==cvmfs-cas`, and a failed verify never reaches
commit at all); (5) *damaged canonical never adopted* — a size-mismatched
impostor at the canonical path is detected at adopt time ("canonical size
mismatch … dedup skipped" WARN), repo-B keeps its own verified inode and the
impostor is left untouched. (A SAME-size corrupt canonical is by-design
best-effort local-rot territory — the scrub's job, not gcas's; no test
asserts a re-hash at link time because the code deliberately doesn't do one.)
`tests/test_cvmfs_scrub.py` 3→5: (4) *no false positives* — three pristine
residents survive ≥4 scrub passes untouched and keep serving; (5) *truncation
rot* — size-changing corruption is caught by the same re-hash, evicted as
LOCAL corruption with no tamper signal, heals on next access. Suite totals
now: bundle 11 · dict 10 · delta 6 · cold_tier 5 · mmap_index 4 · gcas 5 ·
scrub 5 · swarm 7 · learn 4 · virtual 6 · attest 8. dict+delta+learn+gcas+
scrub 36/36 ×2 stable; host-literal guard 8/8. No src/ changes this round.

**CCN register burndown (2026-07-27, fourth session).** All 13 phase-87
over-cap functions decomposed to ≤15, pure refactors with verbatim semantics
(comments and vfs-seam-allow annotations moved with their code):
`delta.c` 37→ split base_id/resolve_base/load/emit; `dict.c` 26→ load/emit;
`gate.c` 33 (over frozen 17)→ meta/method/authz/count/route statics with a
slim orchestrating gate; `attest.c` 19→ capture_label/gated_authz;
`bundle.c::cvmfs_bundle_fill_one` 16→ fs_path + read_obj (close stays with
the opener); `gcas.c::brix_gcas_publish` 16→ gcas_adopt (0 = publish
finished, -1 = canonical evicted → retry); `cvmfs_module_build.c::
cvmfs_merge_cache` 16→ cvmfs_merge_services (scrub/learn/swarm
registrations); `handler.c` 16→ cvmfs_handler_ctx (ctx + finalize observer +
sesslog first-entry). Client `brixcvmfs.c`: transport 27→ dict_offer/
dict_decode/transport_url/transport_after/transport_stall (attempt-outcome
classifier returns done/hard-fail/immediate-retry/stall-retry);
opts_o_list 24→ opts_o_flag + opts_o_kv; mount_run 26→ arm_prefetch +
arm_sidecars; open 18→ open_pin_cache; pf_bundle_flush 17→ pf_bundle_want.
`check_complexity` now reds ONLY on other-workstream
`cms_srv_parse_login` (17); no `--regen`. Server + client rebuilt clean
(the two `-Wformat-truncation` lines on `to_https` are pre-existing — the
old inline shape warns identically in a minimal probe).

En route this session: `test_cvmfs_conformance_srv_manifest.py`'s ephemeral
fixtures hardcoded canonical ports 13124-13139, bypassing the PortBlock
session-tile shift — and the fleet's xrootd upstream-protocol stubs
legitimately own 13120-13126 (`settings.py STUB_*_BACKEND_PORT`), so all 8
ephemeral TTL tests failed "origin temporarily unreachable" whenever a fleet
was up (module-scoped fixtures passed: they ride the shifted tile). Fixed by
deriving ephemeral pairs from the block's shifted base (+4..+9/+14..+19);
suite 60/60 with the fleet live. Nothing here may name an absolute port.

Verification: phase-87 server suites (attest/bundle/delta/dict/gcas/scrub/
swarm/learn/virtual/cold_tier/repo_authz/classify) 86/86; srv conformance
sweep 571 passed + manifest 60/60 after the port fix; client suites
(bundle/dict/mmap_index/packed/tiered/prefetch/prewarm/pin_root/offline/
mock) 42/42; fuse conformance sweep green after the compile-list fix below
(whitelist 59+1xf, trust 64/64, remaining suites green).

Second latent-harness find: the fuse conformance suites' standalone
`brixcvmfs --check` compiles (`fuse_whitelist`, `fuse_trust`) carried private
copies of the shared-core source list that predate Waves A/B — once
`client.c`/`cas_store.c` referenced the G1 xorf, G6 pathidx, and G4 cas_pack
symbols unconditionally, whitelist link-failed (59 fixture ERRORs) and trust
silently skipped 64 tests behind its build-failure guard (`libbrix.a` never
contained the shared phase-87 objects). Fix: both suites now derive their
shared-core deps from the single-truth `BRIXCVMFS_CORE_DEPS`
(`tests/cmdscripts/cvmfs_driver_units.py`), filtered to `shared/*.c` (the
client-lib half still comes from the prebuilt archives). Any future seam
added to brixcvmfs updates one list.

Regression tests added (same session, success + error + security-neg per
surface):

* `tests/test_cvmfs_bundle.py` gained the two untested `cvmfs_bundle_read_obj`
  branches: a member whose stored form exceeds `CVMFS_BUNDLE_MAX_OBJ` stays a
  per-member miss (no origin fill, budget untouched, other members still hit
  byte-identical), and `CVMFS_BUNDLE_MAX_TOTAL` budget exhaustion misses
  exactly the members that no longer fit while sparing later small ones —
  verified against a differential oracle replaying the fill contract in want
  order.
* `tests/test_cvmfs_mount_opts.py` (new, 3 tests) pins the split brixcvmfs
  `-o` parser: unknown *values* of known keys (`cache_format=`, `index=`)
  warn by name and fall back with the mount still serving; an unknown *token*
  is forwarded to libfuse verbatim (mount refused with "unknown option" — not
  silently swallowed); `-o pin=` beats a hostile `$BRIXCVMFS_PIN` (garbage
  env cannot unpin/re-pin an explicitly pinned mount; `user.root_hash`
  reports the CLI pin).
* `tests/test_cvmfs_harness_guards.py` (new, 3 guards) pins both latent-
  harness failure modes: every compile-list entry exists on disk; the fuse
  suites consume `BRIXCVMFS_CORE_DEPS` and carry no literal shared-core list
  (AST check for list elements, so prose mentions survive); and an AST walk
  rejects any int literal inside the canonical PortBlock tile range in
  `test_cvmfs_conformance_*.py`. The port guard immediately caught two more
  offenders beyond `fuse_cache` — `fuse_refresh_failover` (13400–13421 named
  constants) and `srv_geo` (13208/13209 mock-sub-block literals) — all three
  now derive from `PortBlock.base`; migrated suites re-ran green
  (fuse_cache + refresh_failover + srv_geo 225 passed/1 known geo TTL flake
  that passes solo 60/60, bundle + mount_opts green in the same batch).

Every Phase-85 git-write discipline applies: no commits without explicit OP
approval.
