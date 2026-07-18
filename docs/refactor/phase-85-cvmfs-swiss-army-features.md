# Phase-85 — CVMFS *swiss-army* features (beyond official-driver compatibility)

**Goal:** exploit the fact that the native CVMFS surfaces are **not bound to
"stay bug-compatible with the official driver"** to add capabilities the
upstream client/proxy cannot or will not — turning the FUSE driver
(`shared/cvmfs/`) and the site proxy (`src/protocols/cvmfs/`) from faithful
re-implementations into a security-enforcing, content-aware, horizontally
scalable CVMFS toolkit. Every feature here is **additive**: with its gate off,
both surfaces behave exactly as the conformance corpus (phase-84) pins them.

**Provenance:** anchors below read from the tree at working state on
**2026-07-17** (post-`8e15882c` + uncommitted P82/guard work, including the
`signal=proxyabuse` CVMFS guard just landed). Re-verify anchors at the start of
each wave and mark drift `DRIFT:` inline (phase-80 convention).

**Prime directives (inherited):**

1. **Shared core is the leverage.** Both surfaces sit on `shared/cvmfs/`:
   `catalog/` (catalog parse), `signature/verify.c` + `signature/whitelist.c`
   (whitelist + manifest signature), `object/object.c`
   (`cvmfs_object_verify` — zstd/gzip decompress + CAS-hash check),
   `fetch/fetch.c` (cache-first verified fetch), `grammar/` (URL classify +
   hash). A feature built in that core lights up in **both** the driver and the
   proxy. Build it once.
2. **VFS seam is law (INVARIANT #12).** Any cache-storage feature routes through
   `brix_vfs_*` / `brix_cvmfs_cache_store` — no raw data syscalls outside
   `src/fs/backend/`. Storage-tier features are therefore mostly wiring, not new
   I/O code. See `[[data_posix_backend_confinement]]`.
3. **Guard contract reuse.** Security-relevant failures emit the unified
   fail2ban line (`src/net/guard/` — `<ts> ip=… proto=cvmfs signal=… op=…
   path="…" status=…`), never an ad-hoc log shape. New `signal=` tokens are
   added in `guard.h`/`guard_audit.c` with the matching `deploy/fail2ban/`
   filter+jail in the same change (never one side alone).
4. **Standard discipline:** ngx-free shared core (libc + OpenSSL/zlib/zstd
   only, no `goto`, no stubs); new `.c` files land in the repo-root `./config`
   source list **and** `CMakeLists.txt`/`cmake/` (split_files_three_build_
   systems); each feature ships the 3-test set (success + error +
   security-negative); clean-room (no `libcvmfs`/`libXrd*` linkage).

**Fail-closed gating:** every behavior-altering feature sits behind its own
directive, default **off**. With all gates off, phase-84 conformance is
byte-for-byte unchanged.

---

## 0. Scope, non-goals, and the feature roster

**In scope — 13 features in 4 waves.** Surface = FUSE driver / Proxy / Both.

| # | Feature | Surface | Wave | Gate (directive) |
|---|---|---|---|---|
| F0 | Content-aware core: catalog-walk + verify facade reusable by both surfaces | Both | A | — (infrastructure) |
| F1 | **Verifying proxy** — edge CAS-hash + whitelist-signature enforcement | Proxy | A | `brix_cvmfs_verify_content` |
| F2 | Tamper telemetry → guard contract (`signal=cvmfs_tamper`) | Both | A | (rides F1/verify) |
| F3 | Token-gated / private repos (WLCG/SciToken entitlement) | Both | A | `brix_cvmfs_repo_authz` |
| F4 | Content-aware predictive prefetch (catalog-subtree readahead) | Both | B | `brix_cvmfs_prefetch` |
| F5 | Repo prewarm & snapshot pinning (admin/API-triggered) | Proxy | B | `brix_cvmfs_prewarm` + API |
| F6 | Reproducibility pin — enforce a root-hash at mount, audit drift | FUSE | B | `brix_cvmfs_pin_root` |
| F7 | VFS-backed tiered cache (hot NVMe / cold object-store, demote-not-delete) | Both | C | `brix_cvmfs_cache_tier` |
| F8 | Peer-mesh / sibling CAS fetch (consistent-hash local-miss sourcing) | Both | C | `brix_cvmfs_peers` |
| F9 | Per-VO / per-job QoS + fair-share fill throttling | Proxy | C | `brix_cvmfs_qos` |
| F10 | Full offline survival (signed-snapshot pinning through Stratum-1 outage) | Proxy | D | `brix_cvmfs_offline_ttl` |
| F11 | Modern transport — HTTP/2 + QUIC upstream, WAN tuning | Proxy | D | `brix_cvmfs_upstream_http_version` |
| F12 | Edge compression transcode (serve zstd to capable clients) | Proxy | D | `brix_cvmfs_transcode` |

**Non-goals:**
- **Writable COW overlay** — already speced separately
  (`docs/superpowers/plans/2026-07-05-brixmount-cvmfs-writable-overlay.md`);
  out of scope here to avoid duplication.
- The "clever client" prefetch heuristics overlap F4; F4 is the *mechanism*
  (catalog-subtree readahead), the spec
  (`docs/superpowers/specs/2026-07-04-cvmfs-brix-clever-client-design.md`) owns
  the *policy* tuning — reconcile at wave B start.
- No distributed consensus / write-back to Stratum-1; the proxy stays a cache.
- No production crypto review beyond correct use of the existing verified
  `signature/`+`object/` primitives.

**Ordering rationale.** Wave A is the security/differentiation story and reuses
the most already-tested code (`signature/`, `object/`, `secure.c`). Wave B is
content-aware performance for job waves. Wave C is horizontal scale + cost. Wave
D is transport/resilience. A and B are independent and can run in parallel by
surface; C depends on F0; D is standalone.

---

## Wave A — Integrity & access-control core

### F0 · Content-aware core (infrastructure) — **LANDED (2026-07-18)**
**As landed:** `shared/cvmfs/walk/walk.{h,c}` — pure ngx-free composition over
`fetch/` + `catalog/` + `object/`:
- `cvmfs_walk_catalog(fx, root, tmp_dir, max_depth, cb, ud, now)` enumerates
  every CAS reference a root catalog reaches — the catalogs themselves
  (`'C'`), whole-file objects (no suffix) and chunks (`'P'`) — each item
  carrying kind/hash/suffix/size and the owning repo-root-relative path.
  Catalogs are pulled VERIFIED through the fetch orchestrator (tampered
  catalog ⇒ walk aborts `-1`), spilled to a temp file, read with the catalog
  reader, recursed at nested mountpoints down to `max_depth` (0 = root
  catalog only; nested mountpoints still *emitted*, not descended). Callback
  returns nonzero to stop early (rc `1`).
- `cvmfs_walk_subtree(fx, root, tmp_dir, path, max_depth, cb, ud, now)` (added
  with F4) scopes the walk to directory `path`: it first descends across every
  nested-catalog mountpoint covering `path` (each hop hash-verified), then
  walks just that subtree. A path absent from the snapshot is an empty walk
  (rc 0); `""` delegates to the full walk.
- `cvmfs_verify_blob(expected, stored, len, out, outcap, outlen)` verifies one
  stored CAS object outside the orchestrator: stored-form hash check (the
  CVMFS identity rule), then inflate with plain-stored fallback (`-1` hash
  mismatch, `-3` out too small).
Registered in `client/Makefile` `BRIX_CVMFS_OBJS` (for F4/F5 client use) and
`tests/cmdscripts/cvmfs_driver_units.py` (`walk` runner). Not in the nginx
`config` list yet — the module link carries no sqlite3/fetch today; wire it
when a proxy-side consumer (F10/prewarm endpoint) lands.
**Tests:** `shared/cvmfs/walk/walk_unittest.c` (22 checks) — 3-catalog forge
(root → nested A with a 2-chunk file → nested B) served via mock transport:
exact 8-item CAS set, depth-0, early-stop, subtree scoping (plain dir /
mountpoint / cross-mountpoint / absent-path), tampered-nested-catalog abort
(security-neg), verify_blob good/flip/plain/too-small. Driven by
`tests/test_cvmfs_driver_units.py::test_cvmfs_driver_unit_ports[walk]`.

**Original sketch:**
**What:** a thin, ngx-free facade over `catalog/` + `object/` + `signature/`
that both surfaces call: `cvmfs_walk_catalog(root_hash, visit_fn)` (enumerate a
snapshot's catalogs + CAS references) and `cvmfs_verify_blob(hash, suffix, buf,
len)` (the CAS-hash + decompress check already in `cvmfs_object_verify`, wrapped
for the proxy's non-FUSE call site). No new I/O — pure composition of existing
verified primitives.
**Why:** F1/F4/F5/F10 all need "walk a snapshot" and "verify a blob" from the
**proxy** side, where today only the FUSE read stack calls them. Build the seam
once.
**Builds on:** `shared/cvmfs/catalog/catalog.c`, `object/object.c`
(`cvmfs_object_verify`), `signature/verify.c`, `signature/whitelist.c`.
**Tests:** walk a known 3-catalog snapshot → exact CAS set; verify a good blob →
OK; verify a bit-flipped blob → hash-mismatch error.

### F1 · Verifying proxy — the integrity firewall — **LANDED (2026-07-18)**
**What (as landed):** `brix_cvmfs_verify_manifest <master.pub>` pins the repo
master key; MANIFEST-class fills (`.cvmfspublished`/`.cvmfswhitelist`) are
verified on the fill thread before commit (`src/fs/backend/cache/
sd_cache_manifest.c`): whitelist sig vs master → expiry → cert fingerprint ∈
whitelist → manifest sig vs cert → `N` field names this repo. Definitive
failure = quarantine + failed fill (5xx) + `signal=cvmfs_tamper`; a
not-evaluable chain = EIO outage, no tamper line; `.cvmfsreflog` (unsigned in
stock CVMFS) skips the gate. CAS objects were already covered by
`brix_cache_verify cvmfs-cas` (on by default for cvmfs locations), so the
separate `brix_cvmfs_verify_content` switch from the original sketch was not
needed. Suite: `tests/test_cvmfs_verify_manifest.py` (7).
**Why (novel vs official):** the upstream proxy is a blind byte-cache — a
compromised or MITM'd Stratum-1 poisons the entire downstream site. A verifying
proxy makes tampered content **physically unservable** past the cache boundary.
This is the single highest-value differentiator and reuses the driver's
already-tested verification wholesale.
**Builds on:** F0; `handler.c` serve path; `gate.c` class routing (CAS vs
MANIFEST already distinguished).
**Gate:** `brix_cvmfs_verify_content on|off` (default off — perf/compat).
Interplay: with `unified_origin`, verify after failover selection.
**Tests:** good CAS byte-identical passthrough + cached; tampered CAS → 502 +
not cached + `signal=cvmfs_tamper` (F2); bad whitelist signature on a manifest →
502.
**Risks:** decompress cost on the fill path (one-time, cache-amortized);
document the CPU/throughput trade in `docs/04-protocols/cvmfs.md`.

### F2 · Tamper telemetry → guard contract — **LANDED (2026-07-17)**
**What:** a CAS-hash or signature-verification failure (F1) or a client-side
verify failure (FUSE) emits the unified guard line with a new reason
`GUARD_R_TAMPER` → token `cvmfs_tamper`, `op=read`, `path="<repo>/<hash>"`.
**Why:** content tampering is a *security* event, not an I/O hiccup — it must
reach fail2ban / the operator, fleet-wide, on the same contract as
`proxyabuse`/`notroot`.
**Builds on:** `src/net/guard/guard.h` + `guard_audit.c` (add the token,
mirroring the `proxyabuse` change from `[[cvmfs_proxyabuse_guard]]`);
`deploy/fail2ban/filter.d/xrootd-guard-cvmfs-tamper.conf` + jail (maxretry=1 —
a verified tamper is never accidental).
**Tests:** guard_test.c token+line; `test_fail2ban_regex.py` CASES + sample;
integration: tampered fill emits the line.

### F3 · Token-gated / private repos — **LANDED (proxy side, 2026-07-18)**
**What:** `brix_cvmfs_repo_authz <repo-fqrn|*> <scitokens.cfg>` (multi-
occurrence; exact fqrn or the `*` catch-all, first match wins) requires a
valid READ-scope WLCG/SciToken from the named issuer registry before ANY class
of request for that repo is served — CAS, signed metadata, and geo alike.
Reuses the `scvmfs://` bearer/registry validation already in `secure.c`.
Unauthorized → **401** (matching the scvmfs/WebDAV bearer precedent: the
failure is missing/invalid *authentication*, and 401 invites the client to
retry with a credential) + guard-core `signal=authfail` (the
`[xrootd-guard-authfail]` jail). FUSE/mount-side gate (`EACCES`) is future
work.
**Why (novel vs official):** CVMFS is world-readable by design. Token-gated
repos enable *private* software distribution (embargoed datasets, licensed
payloads, per-VO entitlement) that upstream simply cannot express.
**Builds on:** `secure.c` (`brix_token_validate_registry`, READ scope; setter
+ `brix_cvmfs_repo_authz_eval` live there); `gate.c` (authz step right after
the repo slot, before class routing; the guard emitter generalized to
`cvmfs_guard_emit`). Per-entry registries built at merge time
(`cvmfs_merge_secure`), config errors fail the load.
**Gate:** `brix_cvmfs_repo_authz` (absent or non-matching = today's open
behavior).
**Tests:** `tests/test_cvmfs_repo_authz.py` — valid token serves; unmatched
repo stays open; missing/garbage token → 401+authfail; scopeless token → 401
(security-negative); `*` gates every repo; cleartext gated repo → 400.
**Risks:** cleartext proxy + bearer = token on the wire — a gated repo on a
non-TLS connection is refused with **400 at runtime** (mirroring the scvmfs
transport gate) rather than at config load: the same location can carry both
listeners, and the runtime check is what the scvmfs precedent already
established.

---

## Wave B — Content-aware performance

### F4 · Predictive prefetch (catalog-subtree readahead) — **LANDED (client side, 2026-07-18)**
**As landed:** client-side, not an nginx directive (same precedent as F6): the
signal that predicts a package sweep — the first `readdir` of a directory —
lives in the FUSE mount, and the shared cache directory means everything it
pulls also serves later mounts. `client/apps/fs/brixcvmfs.c`:
- `-o prefetch=<depth>` (or `$BRIXCVMFS_PREFETCH`; depth = nested-catalog
  descent budget, off by default) + `-o prefetch_budget=<bytes>` (or
  `$BRIXCVMFS_PREFETCH_BUDGET`; 0 = unbounded).
- One detached worker thread; the first readdir of each directory enqueues it
  (FNV-1a dedupe, fixed 32-slot queue, full = drop silently — advisory
  readahead is never a failure). The worker walks the subtree via
  `cvmfs_walk_subtree` (F0) and pre-pulls FILE/CHUNK objects with
  `cvmfs_fetch_object`; CATALOG items are skipped (the walk itself caches
  them).
- Isolation: the worker owns its OWN curl easy handle (transport `ud` seam =
  `CURL **` slot; `NULL` = the foreground handle), its own failover snapshot
  (struct copy taken before `fuse_main`), its own CAS-store handle and 32 MiB
  scratch/out buffers. Sharing the cache *directory* is safe — `brix_cas_put`
  is O_EXCL-temp + rename atomic. A failed object fetch restores the pristine
  failover snapshot so one bad object's route-blacklist (2 s probation) cannot
  shadow the rest of the sweep.
- Budget hit ⇒ exactly ONE audit line `signal=prefetchcap repo=… budget=…
  spent=…` (no silent truncation), then the queue drains silently; all other
  prefetch errors are swallowed — they can never fail a foreground op.
**Tests:** `tests/test_cvmfs_prefetch.py` (3 green, origins on OS-assigned
ephemeral ports — a fixed PortBlock claim would shift the tile math under
already-running sessions) — listed
subtree readable OFFLINE for never-opened files + un-listed sibling stays cold
(scoping); budget cap = one audit line across further enqueues + foreground
unaffected; missing upstream object swallowed, rest of subtree still lands
(security-neg twin). Proxy-triggered prefetch (speculative pull on catalog
fetch) remains future work with F5/F10.

**Original sketch:**
**What:** on the first access into a directory/package, background-prefetch the
CAS chunks the catalog says that subtree needs, so subsequent opens are cache
hits. FUSE: triggered by `open`/`readdir`. Proxy: triggered by a
`.cvmfspublished`/catalog fetch (speculatively pull referenced catalogs+CAS).
Bounded by a concurrency + byte budget.
**Why:** per-file RTT dominates HPC job startup (thousands of tiny opens). Turns
a serial RTT storm into one bulk pull.
**Builds on:** F0 catalog-walk; `fetch/fetch.c`; proxy `origin_probe.c` async
machinery for the background pulls.
**Gate:** `brix_cvmfs_prefetch depth=<n> budget=<bytes>` (default off).
**Tests:** cold subtree read count vs prefetched (fills coalesced);
budget-exceeded stops early + logs the cap (no silent truncation);
error path (prefetch of a missing chunk never fails the foreground read).

### F5 · Repo prewarm & snapshot pinning — **LANDED (client sweep, 2026-07-18)**
**As landed:** `brixMount cvmfs --prewarm <repo.fqrn>` (`brixcvmfs_prewarm` in
`client/apps/fs/brixcvmfs.c`, dispatched like `--check`): verifies the trust
chain, then walks the WHOLE snapshot via `cvmfs_walk_catalog` (F0, unlimited
nesting depth) reusing the client's own fetch ctx — no mount, no FUSE, single-
threaded — and pulls every referenced CAS object into the local cache
(catalogs land as a side effect of the verified walk). Honors
`$BRIXCVMFS_PIN` (prewarm an exact snapshot; summary says "(pinned)") and the
usual `$BRIXCVMFS_{SERVER,PUBKEY,CACHE,TMP}`. Prints
repo/root/objects/bytes/errors and `WARM` (exit 0) or `INCOMPLETE` (exit 1 —
any fetch error or a walk abort; no silent truncation). A failed object fetch
restores the pristine failover snapshot (same blacklist-shadow fix as F4). A
site prewarns by pointing `$BRIXCVMFS_CACHE` at the shared cache dir.
The proxy-side API endpoint (`/api/v1.0/prewarm?tag=…`) + queryable status
remain future work (needs walk/sqlite3 wired into the nginx module link).
**Tests:** `tests/test_cvmfs_prewarm.py` (3 green, ephemeral-port origins) —
full snapshot lands (files across the nested-catalog boundary + both
catalogs, counts exact, WARM); missing object counted + rest still warms +
INCOMPLETE (no silent truncation); tampered nested catalog aborts the walk
and its subtree never reaches the cache (security-neg).

**Original sketch:**
**What:** an admin/API action (`GET /cvmfs/<repo>/api/v1.0/prewarm?tag=…` or a
control endpoint) walks a snapshot (F0) and pre-pulls **every** CAS object, so a
site is fully warm before a job wave. Status/pin queryable.
**Why:** job waves land on cold caches and hammer the Stratum-1 in lockstep;
prewarm front-loads that into one controlled sweep off the critical path.
**Builds on:** F0; `unified_origin` multi-endpoint fill; the geo API surface for
the endpoint shape (`geo_answer.c`).
**Gate:** `brix_cvmfs_prewarm on` + an authz'd control path (reuse F3).
**Tests:** prewarm populates the expected CAS set; a subsequent job is 100% hit;
prewarm of a bad tag → clean error, no partial-pin.

### F6 · Reproducibility pin (FUSE)
**What:** `brix_cvmfs_pin_root <repo> <root-hash>` mounts exactly that snapshot
and refuses silent catalog rollovers; a drift (upstream advanced) is surfaced as
an audit line, not silently followed. Lets a job assert "ran against exactly
this content."
**Why:** upstream tags can be re-pointed; scientific reproducibility wants an
immutable content assertion.
**Builds on:** `failover/failover.c` refresh path (add the pin check);
`signature/manifest.c`.
**Tests:** pinned mount serves the pinned hash; upstream-advanced → still serves
pinned + one drift audit line; tampered pin target → refused.

**LANDED 2026-07-18.** Client-side, not an nginx directive: the pin lives in the
shared client (`shared/cvmfs/client/`) and is set per-mount via `-o pin=<hash>`
/ `$BRIXCVMFS_PIN` (`client/apps/fs/brixcvmfs.c`), so it applies to `cvmfs` and
`cvmfs-rw` mounts alike; the roster's `brix_cvmfs_pin_root` phrasing is
superseded. Mechanics:

- `cvmfs_client_pin_root(cl, hex)` (call before mount) parses the pin into
  `cl->pin_root`/`pin_set`. The full trust chain still verifies on every
  mount/refresh; `load_trust_and_catalog` then opens the root catalog **by the
  pin hash** instead of the manifest's — the CAS fetch is hash-verified, so a
  tampered pin target is refused with no extra code — and records drift
  (`pin_drift`/`pin_drift_hex`) when the verified upstream manifest root
  differs. The manifest-S/catalog-revision cross-check (step 5) is skipped when
  pinned: a pin to an older publish legitimately disagrees with an advanced 'S'.
- `cvmfs_client_refresh` never swaps a pinned catalog and does not commit the
  advanced manifest, so `user.root_hash` reports the pin and `user.revision`
  the SERVED catalog's own revision property.
- FUSE layer: `brix_refresh()` polls `cvmfs_client_pin_drift()` after each
  TTL-gated refresh and emits exactly ONE stderr audit line per drift
  transition: `brixcvmfs: audit signal=pindrift repo=<fqrn> pinned=<hex>
  upstream=<hex> serving=pinned` (re-armed if upstream returns to the pin).
  An unparsable pin refuses the mount up front ("bad pin").

Tests: `tests/test_cvmfs_pin_root.py` (port block `fuse_pin` 13460) — 7 green:
pinned-serve class (pinned tree + xattrs + two-TTL never-swap + exactly-one
drift line) + tampered-pin-target refused + unparsable-pin refused. Driver unit
suite (4) still green; man page `brixMount.1` documents `BRIXCVMFS_PIN`.

---

## Wave C — Horizontal scale & cost

### F7 · VFS-backed tiered cache — **LANDED (2026-07-18)**
**What:** `brix_cvmfs_cache_tier hot=posix:/nvme cold=s3://… demote_after=…` —
hot objects on NVMe, cold demoted (not deleted) to an object-store tier via the
VFS seam. A cold hit promotes back.
**Why:** a site holds a far larger working set at lower cost; eviction stops
being data loss. Because `brix_cvmfs_cache_store` already rides the VFS seam,
this is wiring over existing backends (`posix`/`pblock`/`s3`/`ceph`), not new
I/O.
**Builds on:** `brix_cvmfs_cache_store`; VFS backends; the negative-cache/LRU
accounting in `gate.c`.
**Tests:** demote+promote round-trips byte-identical; cold-tier outage →
degrades to origin fill, never 5xx; verify (F1) still enforced on promote.

**LANDED 2026-07-18.** The sketch grammar above is SUPERSEDED: instead of a new
composite `brix_cvmfs_cache_tier hot=/cold=/demote_after=` directive, the cold
tier is one grammar-consistent store directive alongside the existing ten:

    brix_cache_store       posix:/nvme/hot;       # the hot tier (unchanged)
    brix_cache_cold_store  <store-url> [credential=…] [block_size=…];

`brix_cache_cold_store` is the 11th `BRIX_TIER_DIRECTIVES` entry
(`tier_directives.h`), adopted across http/webdav/s3/stream like the other tier
stores, parsed by the same `brix_tier_parse_store` (`BRIX_TIER_CACHE` role —
any VFS store scheme works: posix/pblock/s3/rados/http/xroot), registered as
`cold_tier` on the backend-registry entry
(`brix_vfs_backend_config_cache_cold_store`) and composed at cache-tier wrap
time via `brix_tier_build` + `brix_sd_cache_set_cold`
(`vfs_backend_registry.c`). It applies to EVERY cache-tier consumer (root
protocol, WebDAV, cvmfs proxy), not just cvmfs. `demote_after=` is deferred —
demotion is driven by the existing watermark eviction, not a timer.

Semantics (all in `sd_cache_fill.c` + `evict_policy.c`):
- **Promote (cold → hot):** a miss first attempts the cold copy as the fill
  SOURCE through the identical fill spine — same cvmfs-cas/manifest verify,
  same admission policy — so F1 verification is enforced on promote by
  construction. Success unlinks the cold copy (move semantics, `promoted …
  from the cold tier` INFO) and the object is a normal hot hit thereafter.
  Any cold failure (missing, I/O error, store down) silently falls back to
  the origin fill; only NGX_DECLINED (policy admission) short-circuits.
- **Cold verify-reject is NOT origin tamper:** a corrupt cold copy is
  quarantined + unlinked + refilled from origin (`cold-tier object failed
  verification …` NOTICE) with **no** `signal=cvmfs_tamper`, no origin
  penalty, and no WAN accounting — the actor is local disk, and a false
  signal would feed the maxretry=1 tamper jail.
- **Demote (hot → cold):** `brix_cache_evict_one` calls
  `brix_sd_cache_demote` (chunked copy via the cold store's staged-write
  path) before removing each space-pressure victim; demote failure WARNs and
  evicts anyway (never wedges the reaper). Write-invalidation removals do NOT
  demote — only watermark eviction.
- **Config gate:** `brix_cache_cold_store` without `brix_cache_store` is
  refused at `nginx -t` ("requires brix_cache_store (the hot tier)",
  `runtime_server_backend.c`). Cold-tier build failure at compose time
  degrades to hot-tier-only with an ERR, never a startup failure. The cold
  tier is deliberately NOT cloned onto T14 synthetic per-upstream entries.

Tests: `tests/test_cvmfs_cold_tier.py` **5 green** — promote with zero origin
data GETs + move semantics, cold-miss origin fallback, tampered-cold
security-neg (good bytes served, no tamper signal, cold copy removed),
config-gate `nginx -t`, and demote-on-evict via the stream watermark reaper
(4 backdated victims land byte-identical in the cold store). Regression:
`test_cvmfs_conformance_srv_cas.py` + both watermark suites, 65 green.

### F8 · Peer-mesh / sibling CAS fetch — LANDED (2026-07-18)
**What:** consistent-hash the CAS keyspace across a set of sibling nodes; a
local miss is fetched from the owning sibling before going upstream. Safe
because every fetched blob is hash-verified (F0/F1) — a malicious peer cannot
poison content.

**LANDED shape** (supersedes the sketch below, F7 precedent — the directive
joined the `brix_cache_*` tier grammar, not the cvmfs namespace):
- **Directive:** `brix_cache_peers self=host:port host:port ...;` (http-common
  plane, one declaration listing every ring member; exactly one `self=` marks
  this node's own slot; 2–16 members; identical list on every mesh node).
  Config gates at `nginx -t`: peers require `brix_cache_store`; missing/dup
  `self=`, <2 or >16 members, malformed `host:port` are all `[emerg]`.
- **Ownership:** rendezvous (highest-random-weight) hashing — FNV-1a 64 over
  `"<label>\n<key>"` per member label (`host:port`), owner = argmax, ties to
  the lower index (`sd_cache_hrw_fnv1a64`, mirrored bit-for-bit by the test).
  No coordination, no rebalance state; identical lists ⇒ identical owners.
- **Fill order:** cold tier (F7, if any) → rendezvous-owning peer (only when
  owner ≠ self and its instance built) → origin. The peer leg reuses the SAME
  `sd_cache_fill_attempt` spine, so a sibling blob passes the identical
  cvmfs-cas/manifest verify gate as an origin fill. Peers are composed per
  worker in `brix_vbr_wrap_cache_tier` as plain sd_http fill sources via
  `brix_tier_build` (peers serve the same `/cvmfs/...` URL space); a member
  whose build fails degrades to NULL (its keys fall through to the origin).
- **Per-source semantics** (`from_peer` beside F7's `from_cold`): no
  stale-serve on a peer attempt, no origin WAN/upstream accounting on a peer
  fill, silent origin fallback on any peer failure, `NGX_DECLINED` (admission)
  short-circuits. A peer verify-reject DOES raise `signal=cvmfs_tamper`
  naming the SIBLING authority (remote actor — jail-worthy), unlike F7's
  local cold corruption which stays signal-free. Sibling fetch is a COPY
  (the peer keeps its replica), unlike the cold promote's move semantics.
- **SSRF:** allowlist by construction — only the operator-configured ring
  members are ever contacted; no request-derived authority reaches a peer
  fetch, so no separate `signal=proxyabuse` path is needed.
- **Tests:** `tests/test_cvmfs_peer_mesh.py` 7 green (sibling hit with zero
  origin data traffic + copy semantics; self-owned key never self-fetches;
  tampered sibling blob → good bytes served, one origin refill,
  `signal=cvmfs_tamper`; dead sibling → clean origin fallback; 3 `nginx -t`
  gates). 76-test cold-tier/srv_cas/verify-manifest regression green.

**Why:** scales a site's cache horizontally instead of replicating everything N
times; a 1000-node launch becomes a swarm, not a proxy thundering herd.
**Builds on:** F0 verify (the safety guarantee); the F7 fill-source seam
(`sd_cache_fill_attempt`); the tier grammar (`brix_tier_build`).
**Gate:** `brix_cache_peers` (default off; the `brix_cvmfs_peers` name in the
roster table is the superseded sketch).

### F9 · Per-VO / per-job QoS + fair-share — **LANDED (2026-07-18)**
**What:** throttle fill bandwidth/concurrency per VO or per job so a runaway
consumer cannot starve the shared cache; token/DN → class mapping.
**Why:** shared site caches suffer noisy-neighbor collapse under a bad job.
**Builds on:** observability counters (`observability/metrics/`); F3 identity;
`origin_stall_*` machinery.
**Tests:** a throttled class is bounded while others flow; unclassified traffic
uses the default class; limit=0 disables (parity).

**Landed shape.**

- **Directive:** `brix_cvmfs_qos <class> sub=<subject>|default fills=<N>;`
  (TAKE3, multi-occurrence, http/server/location). `<class>` is a free label
  used in logs; `sub=<subject>` matches the VALIDATED bearer token subject,
  `default` catches the empty subject (anonymous / ungated traffic);
  `fills=<N>` is the class's origin-fill rate in fills/second, `fills=0` =
  unlimited (parity with no entry). First `sub=` match wins, else the first
  `default` entry; no match and no default → unthrottled.
- **What is charged:** ONLY remote miss-fills — the check sits in
  `cvmfs_tier_serve_or_fill` (`handler.c`) between the serve-offload
  fall-through and `brix_http_cache_fill_if_needed`, gated on
  `brix_sd_cache_fill_needs_offload(sd, key)`. Cache hits are never throttled,
  budget exhausted or not.
- **Mechanism:** token bucket per class in conf memory — capacity
  `fills × 1000` milli-fills (first sight = full), refill `fills`/ms-scaled
  off `ngx_current_msec`, one fill costs 1000. Per-worker COW after fork,
  event-loop only: no locks, no shm, no new globals; each worker bounds its
  own share (`worker_processes × fills` site-wide worst case, documented
  semantics for a per-worker limiter).
- **Classification is spoof-proof:** the subject is stashed into
  `ctx->token_sub` ONLY by the two validating paths (`scvmfs_check_bearer`,
  `brix_cvmfs_repo_authz_eval` — F3) after `brix_token_validate_registry`
  succeeds. An Authorization header on an ungated repo is never examined, so a
  CLAIMED sub cannot buy a privileged class — it stays in `default`
  (security-neg test proves it).
- **Refusal:** over budget → 429 (`NGX_HTTP_TOO_MANY_REQUESTS`) + NOTICE
  `cvmfs: qos class "<c>" fill budget exhausted (sub "<s>", <n> fills/s)`.
- **Files:** `cvmfs.h` (`brix_cvmfs_qos_t`, `lcf->qos`, `ctx->token_sub`),
  `secure.c` (parser `cvmfs_conf_qos` + matcher + `brix_cvmfs_qos_check`),
  `directives_core.inc`, `module.c`/`cvmfs_module_merge.c` (ptr init/merge),
  `handler.c` (enforcement), `cvmfs_module_internal.h`.
- **Tests:** `tests/test_cvmfs_qos.py` — 6 green: throttled class bounded
  while an unclassified sub flows; cache hits flow after budget spent;
  anonymous lands in `default`; `fills=0` parity; garbage `fills=` refused at
  config time; unvalidated sub claim cannot escape `default` (security-neg).
  Regression: authz + peer-mesh + srv_cas + srv_gate + cold-tier = 184 green.

---

## Wave D — Transport & resilience

### F10 · Full offline survival — **LANDED (2026-07-18)**
**What:** extend the existing `stale-if-error` + manifest-TTL window into
signed-snapshot pinning: through a total Stratum-1 outage the site keeps serving
a **coherent, signature-verified** last-known-good view for
`brix_cvmfs_offline_ttl`, refusing only genuinely-missing objects.
**Why:** a Stratum-1 outage shouldn't take a site's jobs down.
**Builds on:** the T12 manifest-TTL + stale window in `gate.c`; F1 verify; F0
snapshot coherence.
**Tests:** origin down → pinned snapshot still serves + one degraded-mode notice;
object outside the snapshot → clean 404; TTL expiry → normal error.

**Landed shape.**

- **Directive:** `brix_cvmfs_offline_ttl <time>;` (sec slot, http/server/
  location, default 0 = off = exact phase-68 behavior).
- **Mechanism:** ONE decision point — `sd_cache_stale_serve_ok`
  (`sd_cache_policy.c`) computes the survival horizon as
  `max(10 × manifest_ttl, offline_ttl)` measured from `filled_at` (which
  re-arms never touch). Inside the horizon a failed refill serves the cached
  copy and re-arms expiry one TTL forward, unchanged; past it, hard failure.
  When a serve lands beyond where phase-68 would have failed (≥ 10×TTL), it
  additionally emits one parsable NOTICE per serve:
  `sd_cache: event=offline-degraded key="…" (<n> s past fill, offline_ttl
  <t> s) - origin down, serving the pinned last-verified snapshot`.
- **Coherence + signatures for free:** the pinned manifest was verified by the
  F1 signature chain when it was FILLED, and the CAS objects it names are
  immutable/content-addressed — so the surviving view is the last verified
  snapshot, never a mix. Uncached objects during the outage surface the origin
  failure (5xx); bytes are never fabricated. (The spec's "outside-snapshot →
  clean 404" is answered by the T13 negative memo only while the origin can
  still answer 404s; during a TOTAL outage an uncached object is a 5xx —
  refusal either way, documented divergence.)
- **Plumbing:** `cvmfs.h` `offline_ttl` → `directives_core.inc` sec slot →
  `module.c`/`cvmfs_module_merge.c` (UNSET/merge 0) → `cvmfs_module_build.c` →
  `shared_conf.h cache_offline_ttl` → `runtime_server_backend.c` →
  `tier.h` policy `cvmfs_offline_ttl` → `sd_cache_policy.c`. No new state, no
  new files.
- **Tests:** `tests/test_cvmfs_offline.py` — 4 green: degraded window serves
  the pinned manifest + cached CAS with the notice (success); no offline_ttl →
  10×TTL refusal unchanged, no notice (parity); uncached object refused ≥500
  in degraded mode (security-neg); offline_ttl horizon eventually refuses
  after passing through the degraded window (bound is hard). Tests POLL for
  state transitions — WSL2 wall-clock skews vs CLOCK_MONOTONIC and
  filled_at/expiry are wall-clock (same hazard the srv_manifest suite
  documents). Harness: `offline_ttl` knob added to conformance_common
  `_KNOBS`. Regression: srv_manifest + srv_cas + qos + cold-tier + peer-mesh
  = 142 green.

### F11 · Modern upstream transport — LANDED 2026-07-18
**Landed shape:** `brix_cvmfs_origin_http_version 1.1|2|2-direct|3` (not the
sketch's `brix_cvmfs_upstream_http_version` — named for the `origin_*` knob
family it joins). Process-wide operator policy like the origin timeout/reuse
bounds: merged in `cvmfs_merge_resilience`, pushed pre-fork via
`brix_s3_origin_http_version_set()` into the shared curl transport
(`src/fs/cache/origin/s3_transport.c`), applied per request as
`CURLOPT_HTTP_VERSION` in `s3o_configure`. All fills ride this one transport
(sd_http sources, peers, cold-tier refills), so the policy covers every
origin-facing request. Values:

- **unset (default)** — `CURLOPT_HTTP_VERSION` never touched: libcurl's own
  policy, byte-frozen parity with every pre-F11 build;
- **`1.1`** — force HTTP/1.1;
- **`2`** — `CURL_HTTP_VERSION_2_0`: ALPN h2 over TLS, h2c Upgrade over
  cleartext, with libcurl's automatic fallback to 1.1 when the origin
  declines (the safe production value);
- **`2-direct`** — `CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE`: cleartext h2, no
  Upgrade dance, no fallback — for known-h2c origins (nghttpd/haproxy h2c);
- **`3`** — QUIC; **refused at nginx -t** when the linked libcurl lacks an
  HTTP/3 backend (`brix_s3_origin_http_version_supported()` probes
  `curl_version_info` features at config time — never a per-fill runtime
  failure). This box's libcurl (8.14.1 + nghttp2, no H3 backend) refuses it.

**Observability:** the upstream trace line (DEBUG; INFO under
`brix_cvmfs_trace on`) now carries `proto=<1.0|1.1|2|3|?>` — the version the
origin ACTUALLY negotiated via `CURLINFO_HTTP_VERSION` — so an H2→1.1
downgrade is loud, never silent. Existing trace consumers are
substring-anchored and unaffected.

**Files:** `cvmfs.h` (`origin_http_version` + `brix_cvmfs_origin_http_e`),
`module.c` (enum table + UNSET init), `directives_resilience.inc`,
`cvmfs_module_merge.c` (merge + config-time capability gate + setter),
`s3_transport.{c,h}` (`g_origin_http_version`, `s3o_apply_http_version`,
`s3o_negotiated_proto`, `proto=` trace field).

**Tests:** `tests/test_cvmfs_http2_origin.py` 3 green — genuine-H2 parity
(`2-direct` against `nghttpd --no-tls`, manifest + CAS object byte-identical
to the on-disk forge, every trace `proto=2`; nghttpd also ignores Range,
exercising the sd_http 200-full-body slice path), H1-fallback (`2` against
the HTTP/1.x-only python mock → 200s with `proto=1.0` recorded), and the
config gate (`3` → nginx -t "libcurl lacks", garbage → "invalid value",
`2` passes). Plus 478-test cvmfs regression green (qos/offline/cold-tier/
mesh feature suites + srv http/manifest/cas/resilience/config/gate corpora,
478 passed 6 xfailed). Survey note: nghttpd
speaks prior-knowledge h2c ONLY (no Upgrade) — that is why `2-direct`
exists; the `2` Upgrade path was validated against an H1 server falling
back cleanly. Deferred: 0-RTT/QUIC tuning until a lab libcurl ships H3.

### F12 · Edge compression transcode — **LANDED 2026-07-18**
**What:** serve the client's best `Accept-Encoding` codec (zstd preferred, then
br/gzip/…) for cvmfs GETs, reusing the shared outbound-compression path that
WebDAV and S3 already use.
**Why:** faster client-side decompress + smaller LAN transfer for capable
clients, without touching origin content.
**Builds on:** `core/http/http_compress.c` (`brix_http_compress_negotiate` /
`brix_http_send_file_compressed`), `shared/file_serve.c` `serve_try_compressed`;
cvmfs `handler.c` serve sites.

**Landed shape.** The directive is the **existing `brix_compress on|off`**
(default off) — NOT the sketch's `brix_cvmfs_transcode`. That flag already lives
on the shared common conf, is already merged into cvmfs's location conf by
`brix_http_common_adopt`, and is exactly the knob WebDAV (`get.c`) and S3
(`object.c`) thread into their serve opts. cvmfs simply never opted its serve
opts in: `cvmfs_serve_opts_init()` zeroed the struct and left `opts->compress`
= 0, so cvmfs GETs never reached `serve_try_compressed`. F12 is the one-flag
wiring — `cvmfs_serve_opts_init(opts, lcf->common.compress)` at **both** cvmfs
serve sites (`cvmfs_tier_serve_or_fill`'s offload opts and
`cvmfs_tier_open_respond`'s ranged opts, which now takes `lcf`). This supersedes
the `brix_cvmfs_transcode` sketch name for the same grammar-consistency reason
as F7/F8/F9/F10/F11 — reuse the established directive rather than mint a parallel
one.

* **Integrity (F1) is untouched by construction.** CAS verify-on-fill runs at
  *fill* time against the stored object; the Content-Encoding is a reversible
  *wire* transform applied at *serve* time and never alters the bytes on disk.
  The transcode path runs strictly after a fill that verify already accepted, so
  a corrupt fill can never be dressed up as a clean compressed 200.
* **Default-off = byte-frozen parity.** With `brix_compress` unset,
  `serve_try_compressed` early-returns (`!opts->compress`) and the sendfile /
  memory-backed pipeline is bit-identical to before — the phase-84 corpus is
  unaffected (it configures no `brix_compress`).
* **Negotiation is the shared one.** Ranges/HEAD, sub-256-byte objects, and
  already-compressed content types are skipped by `brix_http_compress_negotiate`
  unchanged. cvmfs CAS *data* objects are already zlib-compressed at the
  cvmfs-object layer and carry no content-type, so an operator enabling
  `brix_compress` on a cvmfs location accepts that those blobs are wire-recoded
  for ~0 gain; the real win is uncompressed metadata (manifest/whitelist/
  certificate) and any plaintext content. Correctness holds either way.

**Files:** `src/protocols/cvmfs/handler.c` (`cvmfs_serve_opts_init` gains a
`compress` param; `cvmfs_tier_open_respond` gains an `lcf` param; both serve
sites pass `lcf->common.compress`). No new directive, enum, merge, or header.

**Tests:** zstd-capable client gets `Content-Encoding: zstd` and the decoded
body is the exact stored object whose sha1 IS its CAS address (F1 preserved
through transcode); an identity-only client gets the verbatim object with no
Content-Encoding; a persistently corrupt origin object is still a 5xx under
`brix_compress on`, never a compressed 200 (`tests/test_cvmfs_transcode.py`
3 green — port block `srv_verify`). Plus a 462-test cvmfs regression green (srv
http/manifest/cas/resilience/config/gate corpora + transcode + http2-origin,
462 passed 6 xfailed 0 failed) proving additivity with `brix_compress` off.

---

## Cross-cutting notes

- **Security features compound.** F1 (verify) + F2 (tamper telemetry) + F3
  (repo authz) + F8's verified-peer safety together make a CVMFS site that is
  integrity-enforcing and access-controlled end-to-end — capabilities the
  official stack does not offer. Recommend landing Wave A first as a coherent
  security story.
- **One catalog-walk (F0) powers F4/F5/F10** — the content-aware performance and
  resilience features are cheap once F0 exists.
- **Every storage feature is VFS-seam wiring** (F7), and **every remote-source
  feature is an allowlist + verify** (F8), so the SSRF/tamper guard model from
  the 2026-07-17 guard work (`[[cvmfs_proxyabuse_guard]]`,
  `[[notroot_wire_guard]]`) is the reused security substrate throughout.
- **Conformance safety:** phase-84 corpus is the regression oracle — run it with
  all Phase-85 gates off at the end of every wave to prove additivity.

## Status

**Wave A LANDED + VERIFIED 2026-07-18** (F1 verifying proxy · F2 tamper guard ·
F3 token-gated repos — see the per-feature LANDED blocks above). All additive,
default-off; UNCOMMITTED.

**Wave A regression verification (2026-07-18, gates off).** Full phase-84
corpus against the Wave A binary with no phase-85 directive configured:
srv corpora (gate/manifest/cas/http/proxy/geo/resilience/config/smoke) green;
fuse corpora (cache/catalog/manifest_parse/posix/read/refresh_failover/trust/
whitelist) green; cvmfs unit files + guard core + fail2ban-regex + source
guards green; F1 (7) and F3 (7) feature suites green on the same binary.
Fallout fixed during the sweep (test-contract realignment, not behavior):

- 8 strict-xfail markers retired — their documented divergences were fixed in
  the tree on 2026-07-17/18: CAS digest lengths now exact 40/64/96/128
  (`classify.c`, retires 5 gate xfails), 416 carries `Content-Range: bytes
  */len`, 304 carries ETag (srv_http), EBADMSG retries rotate endpoints
  (srv_resilience).
- `cvmfs_core_unittest.c` CAS fixture realigned to a true 40-hex digest (was
  42, legal only under the old range rule).
- `client_unittest.c` listxattr call site updated to the hardened
  `(cl, path, out, outlen, now)` signature.
- proxyabuse guard test: select its own audit line (shared error log) and
  accept `host[:port]` in the path field per the documented contract.

Known flake (pre-existing, not Wave A): fuse_cache mount bring-up drops 2-4
*different* tests per full-file run under load (WSL2 FUSE churn + concurrent
session port/tmp contention); every failing test passes solo. Geo
`test_ttl_expiry_reprobes` is timing-sensitive the same way.

**Wave B: F6 LANDED 2026-07-18** (reproducibility pin, client-side `-o pin=` —
see the F6 LANDED block; `tests/test_cvmfs_pin_root.py` 7 green).
**F0 LANDED 2026-07-18** (`shared/cvmfs/walk/` walk+verify facade — see the F0
LANDED block; walk unittest 22 checks green via the `walk` driver-units
runner, incl. the F4-added `cvmfs_walk_subtree`).
**F4 LANDED 2026-07-18** (client-side `-o prefetch=` readdir-triggered subtree
readahead — see the F4 LANDED block; `tests/test_cvmfs_prefetch.py` 3 green).
**F5 LANDED 2026-07-18** (client-side `brixMount cvmfs --prewarm` full-snapshot
sweep — see the F5 LANDED block; `tests/test_cvmfs_prewarm.py` 3 green; the
proxy-side prewarm API endpoint remains future work).
**Wave C: F7 LANDED 2026-07-18** (`brix_cache_cold_store` hot/cold tier —
grammar-consistent 11th tier directive superseding the `brix_cvmfs_cache_tier`
sketch; see the F7 LANDED block; `tests/test_cvmfs_cold_tier.py` 5 green +
65-test srv_cas/watermark regression).
**F8 LANDED 2026-07-18** (`brix_cache_peers` rendezvous sibling mesh —
grammar-consistent supersession of the `brix_cvmfs_peers` sketch; see the F8
LANDED block; `tests/test_cvmfs_peer_mesh.py` 7 green + 76-test
cold-tier/srv_cas/verify-manifest regression).
**F9 LANDED 2026-07-18** (`brix_cvmfs_qos` per-class origin-fill token bucket
keyed on validated token subjects; see the F9 LANDED block;
`tests/test_cvmfs_qos.py` 6 green + 184-test authz/mesh/cas/gate/cold-tier
regression).
**Wave D: F10 LANDED 2026-07-18** (`brix_cvmfs_offline_ttl` offline-survival
horizon over the phase-68 stale window; see the F10 LANDED block;
`tests/test_cvmfs_offline.py` 4 green + 142-test
manifest/cas/qos/cold-tier/mesh regression).
**F11 LANDED 2026-07-18** (`brix_cvmfs_origin_http_version` HTTP-version
policy for the shared curl origin transport, with negotiated-`proto=` trace
observability and a config-time libcurl capability gate; see the F11 LANDED
block; `tests/test_cvmfs_http2_origin.py` 3 green + 478-test cvmfs
regression).
**F12 LANDED 2026-07-18** (edge compression transcode: cvmfs GETs opt into the
shared `brix_compress` outbound-codec path — superseding the `brix_cvmfs_transcode`
sketch — so a zstd-capable client is served zstd while integrity stays bound to
the plaintext at fill time; see the F12 LANDED block;
`tests/test_cvmfs_transcode.py` 3 green + cvmfs regression). **Phase-85 feature
roster (F0–F12) complete.**
Re-verify anchors at wave start.
