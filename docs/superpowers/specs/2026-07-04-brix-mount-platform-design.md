# brix Mount Platform — design (CVMFS-brix + XRootDFS-brix + shared hardened core)

**Date:** 2026-07-04
**Status:** approved design → implementation
**Author:** brainstorming session (Rob Currie)

---

## 1. Vision

One umbrella front-end — `brixMount <type> <endpoint> <mountdir>` — backed by pluggable,
hardened FUSE drivers over a shared **ngx-free** core and a **shared-with-`src/`** local
POSIX content-addressed cache. Positioning line: *"a hardened, iron-clad FUSE driver,
battle-tested against bad/evil networks."*

```
brixMount cvmfs atlas.cern.ch          ~/myAtlasMountDir/   → CVMFS-brix driver
brixMount eos   root://eoslhcb.cern.ch ~/myEOSMountDir/     → XRootDFS-brix driver
brixMount s3    s3://bucket@host        ~/myS3Dir/           → existing client/lib vfs_s3 backend
```

Two named products fall out of the platform:

- **CVMFS-brix** — a NEW native, read-only CVMFS FUSE client with **full real-repo
  interoperability** (mounts real upstream repos such as `atlas.cern.ch`) and **full
  stock-`cvmfs2`-client feature parity** including **autofs**.
- **XRootDFS-brix** — the EXISTING `xrootdfs` FUSE driver (`client/apps/xrootdfs.c`),
  rebranded and folded under `brixMount` as the `root://`/`eos` driver.

---

## 2. Guiding facts (why the architecture is shaped this way)

1. **The server `cvmfs://` module is a transparent content-addressed byte proxy.** It
   classifies URLs (CAS object / manifest / geo), caches immutable objects forever and
   manifests by TTL, and picks/fails-over replicas. It deliberately **never** decodes
   objects, reads catalogs, or (today) verifies signatures — so it can cache MANY repos
   without holding their keys (`src/protocols/cvmfs/`, phase-68).
2. **A real CVMFS client needs the full semantic stack on top:** verify the signed
   `.cvmfspublished` manifest + `.cvmfswhitelist`, read SQLite catalogs, walk nested
   catalogs, resolve chunked files, decompress + hash-verify content objects.
3. Therefore the shared surface is **two rings**, not one monolith:
   - **INNER ring** (server + client both link): URL/hash **grammar + classify**,
     **failover policy**, **signature verify**.
   - **OUTER ring** (client only): **catalog**, **object decode + verify**, **fetch
     orchestrator**.
4. **The local cache is genuinely shared code with `src/`.** `src/fs/cache/` is
   nginx-typed (`cinfo.c` has 37 `ngx_` refs), so sharing means extracting the pure-C
   essence into `shared/cache/` and refactoring the server's `cstore`/`cinfo` onto it
   (behavior-preserving), NOT duplicating the on-disk format.
5. **Pattern precedent:** the repo already ships ngx-free pure-C cores linked by both the
   nginx module and standalone tools (`src/net/guard`, `shared/`, `client/lib`). This
   design follows that precedent. zlib + zstd are already linked
   (`BRIX_HAVE_ZLIB`/`BRIX_HAVE_ZSTD`). RSA/X.509 verify exists on both sides
   (`client/lib/net/tls.c`, `src/auth/crypto`, `src/auth/token/signature.c`). The one NEW
   external dependency is **libsqlite3** (catalogs are SQLite), gated like zstd.

---

## 3. Layered architecture

```
client/apps/brixmount.c                 NEW umbrella front-end
  parse <type> → dispatch driver; also the autofs mount helper entry
  (mount.cvmfs / mount.brix)
    ├── CVMFS-brix driver (new)     full CVMFS semantics (read-only)
    ├── XRootDFS-brix driver        existing xrootdfs.c, rebranded
    └── s3/webdav                   existing client/lib/vfs backends

shared/cvmfs/        NEW ngx-free pure-C core (links: server + client)
  grammar/    URL+hash grammar; classify(CAS/manifest/whitelist/reflog/geo); hash parse/fmt
  signature/  .cvmfspublished + .cvmfswhitelist parse & X.509/RSA verify; expiry; cert chain
  failover/   replica list + proxy hierarchy (groups, RR, DIRECT); blacklist + timed reset;
              backoff; adaptive timeout; stall detection      ← crappy-network heart
  transport.h SEAM: fetch(url, range, sink) → status          (impl injected per side)
  cache.h     SEAM: has/get/put by content-hash, atomic       (uses shared/cache)
  catalog/    CLIENT ring: SQLite reader, md5-path lookup, readdir, nested catalogs, chunks, xattrs
  object/     CLIENT ring: decode stored object (zlib/zstd/none) + hash-verify (sha1/rmd160/shake128)
  fetch/      CLIENT ring: cache-first → failover-fetch → verify → store; hash-safe retry/resume

shared/cache/        NEW ngx-free pure-C content-addressed POSIX store (links: server + client)
  path layout · .cinfo v3 present-bitmap · atomic temp+rename · LRU/quota reap
  (extracted from src/fs/cache; server cstore/cinfo become thin ngx adapters over it)

src/protocols/cvmfs/  refactored onto shared/cvmfs INNER ring (classify + failover;
                      OPTIONAL: verify cached manifests via shared signature — closes the
                      current "T12 stopgap" no-verify gap)
src/fs/cache/         cstore/cinfo/cache_key/paths refactored onto shared/cache (behavior-preserving)
```

**Seam injection.** Both sides inject their own **transport** (client = `client/lib` HTTP +
`resilient.c`; server = nginx `sd_http`) and share one **cache** module. The
failover/verify/decode logic is written once and exercised in both worlds.

---

## 4. Data flow — client read path (CVMFS-brix)

1. **Mount.** Load repo pubkey + server/proxy config (`CVMFS_*` compatible) → fetch
   `.cvmfswhitelist` (verify vs master key, check expiry) → fetch `.cvmfspublished` (verify
   signature vs a certificate whitelisted by the whitelist) → obtain root-catalog hash + TTL.
2. **lookup / getattr.** `md5(path)` → catalog row (mode / size / flags / content-hash /
   symlink). Crossing a nested-catalog mountpoint transparently fetches + opens that catalog.
3. **open / read.** Resolve content hash (+ chunk list for large files) → `fetch/`: cache
   hit serves immediately; miss goes through `failover/` (proxy group → next group →
   `DIRECT` → next Stratum-1), streams into a cache **temp** file, **decompresses +
   hash-verifies**, atomic-renames into the content-addressed cache, serves the range.
4. **Resilience everywhere.** Any fetch failure retries the *next* mirror; because identity
   is the content hash, partial/resumed transfers are safe across mirrors and verified
   before use. All-upstreams-down → **offline/degraded mode** (serve cached objects,
   tolerate a stale-but-unexpired manifest).
5. **Refresh.** On catalog TTL expiry, re-fetch + re-verify the manifest; a new revision
   swaps the root catalog and invalidates stale catalog handles.

---

## 5. Four resilience pillars (shared `failover/` + `fetch/`)

- **Replica + proxy failover.** `CVMFS_HTTP_PROXY` semantics (groups, round-robin within a
  group, failover across groups, `DIRECT`), Stratum-1 replica-list failover, host+proxy
  blacklist with timed auto-reset. Server `origin_probe`/`geo`/`upstreams` refactor onto this
  same engine (behavior-preserving).
- **Hash-verified safe retry/resume.** Reuses the proven `resilient.c` offset-resume +
  bounded-backoff loop, made **mirror-agnostic** — resume/retry against any endpoint,
  correctness guaranteed by post-fetch hash verify.
- **Adaptive timeout + backoff.** Per-host connect/low-speed stall detection, exponential
  backoff, adaptive chunk halving on lossy links (the `XRDC_RFILE` idea), unified with the
  server stall logic.
- **Offline / degraded mode.** Full cache-only serving when every upstream is down, plus
  stale-manifest tolerance so a populated mount survives a total outage.

---

## 6. Full stock-cvmfs-client parity surface (end-state; phased)

autofs on-demand mount under `/cvmfs/<repo>` via **mount.cvmfs + `/etc/auto.cvmfs` program
map** · `CVMFS_*` config-file compatibility (`default.conf`, `domain.d`, `config.d`,
`keys/`) · pubkey / whitelist / blacklist trust · sha1 / rmd160 / shake128 · zlib / zstd /
none · nested catalogs · chunked large files · magic xattrs (`user.pubkey`, `user.hash`,
`user.revision`, `user.host`, `user.proxy`, `user.nchunks`, …) · catalog TTL + auto-refresh
on new revision · proxy hierarchy + Stratum-1 order + geo-sort + host/proxy failover&reset ·
shared cache dir + quota / LRU + cache-only / offline mode · `cvmfs_config` / `cvmfs_talk`-style
introspection (nice-to-have). Fixed-folder direct mount
(`brixMount cvmfs atlas.cern.ch ~/dir`) is the non-autofs path over the same driver.

---

## 7. Decomposition — 7 sub-projects (dependency-ordered)

Each sub-project gets its own detailed implementation plan and ends **green** (server suite
stays passing after A/B/C; a minimal real repo mounts after E; full parity + umbrella after
G). Every change carries the mandated **3 tests** (success + error + **security-negative**);
CVMFS security-negatives are signature-forgery, expired/blacklisted whitelist, hash mismatch,
and path-escape.

| SP | Title | Dep | Payload |
|----|-------|-----|---------|
| **A** | Shared cvmfs core foundation | — | `shared/cvmfs/grammar` (classify + hash) + `signature` (manifest + whitelist X.509/RSA verify) + config model; refactor server `src/protocols/cvmfs/classify.c` onto shared grammar (no behavior change) |
| **B** | Failover policy engine | A | `shared/cvmfs/failover`: proxy hierarchy + replica failover + blacklist/reset + adaptive timeout/backoff + stall detection; refactor server `origin_probe`/`geo`/`upstreams` onto it; client transport binding |
| **C** | Shared POSIX content-addressed cache | — | extract pure-C `shared/cache/` from `src/fs/cache` (path layout, `.cinfo` v3, atomic writes, LRU/quota reap); refactor server `cstore`/`cinfo` onto it — ⚠ load-bearing, behavior-preserving, guard-tested |
| **D** | Object decode + fetch orchestrator | B, C | `object/` (zlib/zstd/none decode + hash-verify) + `fetch/` (cache-first → failover-fetch → verify → store; hash-safe mirror-agnostic retry/resume); client `transport` impl over `client/lib` HTTP + `resilient.c` |
| **E** | Catalog engine | D | `catalog/`: SQLite reader (NEW libsqlite3 dep, gated), md5-path lookup, readdir, nested catalogs, chunked files, magic xattrs |
| **F** | CVMFS-brix FUSE driver + autofs | E | FUSE ops (getattr/lookup/readdir/open/read/readlink/listxattr/statfs), offline/degraded mode, mount.cvmfs + `auto.cvmfs`, `CVMFS_*` config compat, TTL auto-refresh; real + mock repo tests |
| **G** | brixMount umbrella + branding | F | `brixMount <type> <endpoint> <mountdir>` dispatch, rebrand `xrootdfs` → XRootDFS-brix (eos/root driver), docs/branding, man pages |

**Parallelism.** C has no dependency on A/B and can proceed in parallel; D joins A/B/C.

---

## 8. Build & dependency notes

- New source dirs `shared/cvmfs/` and `shared/cache/` are added to the repo-root `./config`
  source lists AND to `client/config` so both the nginx module and the client link them.
  `./configure` is required when these new files/dirs first appear.
- **libsqlite3** (SP-E) is detected via `pkg-config sqlite3` in `./config`, gated
  `-DBRIX_HAVE_SQLITE3=1`, degrading to "catalog engine unavailable" when absent (matches the
  zstd/zlib pattern).
- No `goto`; functional/modular; section-level WHAT/WHY/HOW docblocks; use existing helpers.
  Coding standard: `docs/09-developer-guide/coding-standards.md`.

---

## 9. Risks & mitigations

- **SP-C touches load-bearing server cache code.** Mitigation: behavior-preserving
  extraction, keep the server's ngx-typed API identical (thin adapter), run the full cache
  test suite (`run_cinfo_tests`, `run_cache_admit_tests`, `run_cache_reaper.sh`,
  `test_cache_partial_fill.py`) as the acceptance gate. If risk proves too high, fall back to
  a **format-compatible but separately-implemented** client cache (documented fallback; loses
  literal code sharing but keeps on-disk compatibility).
- **Full CVMFS spec fidelity is large.** Mitigation: SP-A→E each independently green;
  minimal single-catalog repo mountable at end of SP-E before nested/chunked polish.
- **Real-repo tests need network.** Mitigation: primary tests run against a **mock CVMFS
  repo** (static fixture served locally, mirroring `tests/cvmfs/`); real-repo mount is an
  opt-in nightly/integration check.
```

