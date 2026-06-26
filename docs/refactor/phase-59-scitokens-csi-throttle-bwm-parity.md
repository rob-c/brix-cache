# Phase 59 — SciTokens breadth, CSI page-checksum tagstore, Throttle/Bwm parity (hyper-detailed design record)

**Status:** plan / spec — not started
**Date:** 2026-06-26
**Owner decisions:** RESOLVED — see §Z (ADR log). W1 parses the upstream
`scitokens.cfg` grammar verbatim; W2 ships its **own** versioned tag-file format
(byte-level `.xrdt` interop is a documented follow-on, not v1); W3b (Bwm
reservation) ships **default-off** as a legacy/niche tool; W3a's IO-load metric is
an **additive** new keying mode (existing `xrootd_concurrency_limit` untouched).

**Scope:** three remaining *functional-parity* gaps vs official XRootD — each a
capability the module partially covers but not at upstream's config/contract
breadth:

1. **W1 — Full SciTokens issuer/config/monitor breadth** (`XrdSciTokens`).
2. **W2 — CSI persistent page-checksum tagstore** (`XrdOssCsi`).
3. **W3 — Throttle/Bwm parity** (`XrdThrottle` exact config/admin contract +
   `XrdBwm` reservation semantics).

**Non-goals (unchanged project policy):** the C++ plugin ABI itself; UDP
f/g-stream monitoring. This phase implements the *functionality* these plugins
provide, native to the nginx module — not loadable `.so` parity.

**Relationship to Phase 58:** Phase 58 §8 (checksum-at-rest) landed the
*file-level* digest at rest and explicitly deferred "a later per-page CSI + scrub
phase." **W2 here is that deferred phase.** W1 extends the single-issuer
`src/token/` validator; W3 extends the `src/ratelimit/` engine. Nothing here
reverts or contradicts Phase 58. Cross-link:
[`phase-58-xrootd-parity-batch.md`](phase-58-xrootd-parity-batch.md) §8/§9 and
[`docs/10-reference/comparison/xrootd-vs-nginx/11-gaps-divergences-and-extras.md`](../10-reference/comparison/xrootd-vs-nginx/11-gaps-divergences-and-extras.md).

This is a "live design record" in the sense of the phase-44/55/56/58 docs: it
carries wire/format byte-layouts, near-final annotated function skeletons, exact
edit hunks against existing files, state machines, per-function ABI contracts, a
requirements-traceability matrix, ADRs, a risk register, a PR-by-PR rollout, and
per-item test matrices. Every feature obeys the project rules captured in §A.

---

## Table of contents
- §0  Tiering, sequencing, and decision impact
- §A  Conventions & contracts (build, config, flags, errors, threads, tests)
- §W1 SciTokens issuer/config/monitor breadth
- §W2 CSI persistent page-checksum tagstore
- §W3 Throttle exact contract + Bwm reservation semantics
- §R  Requirements traceability (FR/NFR/SEC/BLD/OPS)
- §S  Near-complete annotated source skeletons
- §T  Consolidated edit-hunk set (every touched file)
- §U  Byte-level sequence & state diagrams
- §HH Explicit state-transition tables
- §V  Concurrency, memory-ordering & reentrancy proofs
- §W  Capacity & performance model
- §X  Failure-injection matrix (30 rows)
- §Y  CI/CD + PR-by-PR rollout + review checklists
- §QQ Per-handler integration cookbook
- §AA Observability (metrics & logs)
- §BB Full config reference + directive grammar
- §CC Kernel / dependency / distro compatibility
- §DD Official-XRootD interop harness
- §EE Compile-ready source listings (new files)
- §WS Wire-level token source & `?authz=` handling
- §FF Per-function ABI / contract tables
- §GG Format test vectors / hex fixtures
- §II pytest specifications
- §ST Security threat model (STRIDE per workstream)
- §EM Error / status mapping (every new error path)
- §JJ Definition of done + kill-switches
- §KK Migration / back-compat
- §LL Design FAQ
- §MM Formal requirements (FR/NFR/SEC/BLD/OPS) with traceability
- §NN Open questions
- §SEQ End-to-end sequence diagrams (6 flows)
- §FMT On-disk tag-file format specification (normative)
- §ADB authdb integration for group/mapping strategies
- §RUN Operational runbook
- §MIG Worked migration from a stock xrootd config
- §Z  ADR log + risk register
- Glossary

---

## §0 — Tiering, sequencing, and decision impact

| Tier | Item | Effort | Risk | Default | Gate |
|---|---|---|---|---|---|
| T1 (quick) | W1a multi-issuer registry + per-issuer scoping | M | Low | single-issuer fallback = current behavior | `xrootd_token_config` unset ⇒ no change |
| T1 | W1b subject/group mapping + strategy + monitor | M | Low | strategy=`capability` (= today) | additive |
| T2 (focused) | W2a page-tag sidecar + read-verify/write-update | L | Med (RMW correctness, perf) | `xrootd_csi off` | off ⇒ no tag I/O |
| T2 | W2b holes/missing/prefix options + scrub | M | Low | scrub off | off ⇒ no sweep |
| T2 | W3a `throttle.*` contract + IO-load metric | L | Med (SHM hot-path) | unset ⇒ no throttle | additive keying mode |
| T3 (niche) | W3b Bwm reservation manager | M | Low | `xrootd_reservation off` | off ⇒ no queue |

**Decision impact:** every workstream is default-off / backward-compatible. The
only behavior change when a feature is *enabled* is the intended one. A bad
rollout is a config revert, never a redeploy (§JJ kill-switches).

**Dependency edges:** W3a reuses the INI reader introduced in W1a (issuer
registry + throttle `userconfig` are both INI). Build W1a first. W2 and W3b are
independent. W1b depends on W1a; W2b on W2a.

---

## §A — Conventions & contracts

Restated so each PR is self-checkable.

- **Build registration.** New `.c`/`.h` files register in the **top-level
  `./config`** script (`$ngx_addon_dir/src/...c` source lists), *not* in
  `src/config/config.h` (that's the C header for fields/commands). A new source
  file or new top-level config block requires `./configure` + full `make`; edits
  to existing files use `make -j$(nproc)`. See [`build_source_list_location`].
- **Config fields** live in `src/types/config.h` (the `ngx_stream_xrootd_srv_conf_t`
  / loc-conf structs, `NGX_CONF_UNSET*`); directives in `src/config/directives.c`;
  merge in the `merge_*_conf()` functions (main→srv→loc).
- **HARD BLOCKS.** No `goto` anywhere in `src/`; functional/modular C (one job per
  function, explicit `ctx`, pure helpers + side effects at the edges); use HELPERS,
  never reimplement path/auth/metrics/framing; 3 tests per change (success + error
  + security-neg).
- **Allocation.** HTTP path `ngx_palloc(r->pool,…)`; stream path
  `ngx_alloc(…,log)`; never raw `malloc` in request handling. The CSI tagstore
  (W2) runs in the storage-driver/thread-pool layer (`src/fs/backend/`) where
  bounded scratch is already used — match that file's idiom.
- **Metrics cardinality (INVARIANT 8).** Low-cardinality labels only — no
  DN/path/bucket/issuer-URL in label values. Map issuers/users to a small fixed
  bucket or a hashed id. `xrootd_sanitize_log_string()` for any wire-derived log
  text.
- **Data-plane confinement (INVARIANT 11; [`data_posix_backend_confinement`]).**
  Per-page checksum I/O is *data byte I/O* and MUST live in `src/fs/backend/`
  behind the SD driver. No raw `pread`/`pwrite` on the tag file outside the backend.
- **SHM mutexes (INVARIANT 10).** Every SHM table mutex via
  `xrootd_shm_table_alloc()` / `xrootd_shm_table_mutex_create()` (spin+yield);
  **never** stock `ngx_shmtx_create(…,NULL)` (POSIX-sem lost-wakeup). W3's per-user
  counters and W3b's reservation queue are SHM tables.
- **errno → kXR → HTTP** mapping (CLAUDE.md quick ref): `EIO→kXR_IOError→500`,
  and the CSI checksum-mismatch case maps to **`kXR_ChkSumErr` (3031)** on
  `root://` and **`500 Internal Server Error`** (with a `X-Checksum-Mismatch`
  diagnostic header) on HTTP.
- **Reload semantics.** New config follows the standard nginx drain; SHM
  slot-count changes reset the table with a WARN (see reload-semantics.md).

---

## §W1 — SciTokens issuer/config/monitor breadth

### W1.1 Upstream behavior (`/tmp/xrootd-src/src/XrdSciTokens`)

`XrdSciTokensAccess.cc` is an `XrdAcc` authorization plugin driven by an **INI
config** (default `/etc/xrootd/scitokens.cfg`) with an optional `[Global]`
section and one `[Issuer <name>]` section per trusted issuer. The shipped sample
(`configs/scitokens.cfg`) is the authoritative grammar:

```ini
# Global section is optional
[Global]
audience = https://testserver.example.com/, MySite
# audience_json = [ "this,is,a,single,audience", "it can even have spaces" ]

[Issuer OSG-Connect]
issuer = https://scitokens.org/osg-connect
base_path = /stash
map_subject = True

[Issuer CMS]
issuer = https://scitokens.org/cms
base_path = /user/cms
map_subject = False
```

Full per-issuer key set (verified in `XrdSciTokensAccess.cc` + README):

| Key | Type | Default | Meaning |
|---|---|---|---|
| `issuer` | URL | (required) | Must equal the token `iss` claim. |
| `base_path` | path list | (required) | Namespace prefix(es) the issuer is authoritative for (comma/space separated). |
| `restricted_path` | path list | — | Sub-path(s) within `base_path` the issuer may **not** grant. |
| `audience` / `audience_json` | string / JSON | `[Global]` value | Required `aud` value(s). |
| `map_subject` | bool | False | Map token `sub` → local username. |
| `name_mapfile` | path | — | JSON map: subject/claim → local username. |
| `username_claim` | string | `sub` | Claim used as the username. |
| `groups_claim` | string | — | Claim carrying group membership. |
| `default_user` | string | — | Username when no mapping applies. |
| `onmissing` | enum | `fail` | When a mapping is absent: `fail` or use `default_user`. |
| `authorization_strategy` | list | `capability` | Ordered: `capability` / `group` / `mapping`. |
| `enabled` | bool | True | Issuer on/off. |

`XrdSciTokensMon::Mon_Report(entity, subject, username)` fires on authorized IO
(`Mon_isIO` = AOP_Read/Update/Create/Excl_Create), carrying the resolved identity
— a monitoring hook, not a wire feature.

### W1.2 Current module state (`src/token/`)

- **Single issuer.** `config.c::xrootd_configure_token_auth()` validates exactly
  one `token_issuer` + one `token_audience` + one `token_jwks`. Fields in
  `src/types/config.h:215-229`: `token_jwks`, `token_issuer`, `token_audience`,
  `jwks_keys[XROOTD_MAX_JWKS_KEYS=8]`, `jwks_key_count`, `jwks_mtime`,
  `token_jwks_refresh_interval`.
- `validate.c::xrootd_token_validate(log, token, len, keys, key_count,
  expected_issuer, expected_audience, macaroon_secret, secret_len, claims)` —
  structural → alg (RS256/ES256) → key-by-kid → signature → claim extraction
  (`json_get_string`/`json_get_string_array` for array `aud`) → `iss`/`aud`/`exp`/
  `nbf`. `xrootd_token_claims_t` (token.h:62-73) already carries
  `sub[256]`/`iss[256]`/`aud[256]`/`groups[512]`/`scopes[8]`.
- `scopes.c::scope_path_matches()` — prefix match with boundary check ("/data" ≠
  "/database"); `xrootd_token_check_read/_write()`.
- Callers: `webdav/auth_token.c` (HTTP), `gsi/token.c` (stream), `handshake/
  policy.c`, `types/identity.c`.

**Missing vs upstream:** multi-issuer registry; per-issuer `base_path`/
`restricted_path` scoping; subject→username + `groups_claim` mapping; the
`authorization_strategy` selector; the IO monitor hook.

### W1.3 Design

Add a **multi-issuer registry** + mapping/strategy/monitor on top of the existing
validator. WLCG-scope enforcement stays the **default** strategy (`capability`).

**New files**

```
src/token/issuer_registry.c   issuer_registry.h
src/token/subject_map.c       subject_map.h
src/token/monitor.c           monitor.h
src/token/ini.c               ini.h          (shared INI reader; reused by W3a)
```

**New types** (`issuer_registry.h`):

```c
#define XROOTD_TOKEN_MAX_ISSUERS      16
#define XROOTD_TOKEN_MAX_BASEPATHS     8
#define XROOTD_TOKEN_MAX_AUDIENCES     8

typedef enum {                       /* authorization_strategy bits, ORed     */
    XROOTD_AUTHZ_CAPABILITY = 1u << 0,   /* WLCG storage.* scopes (default)   */
    XROOTD_AUTHZ_GROUP      = 1u << 1,   /* groups_claim ∈ authdb groups      */
    XROOTD_AUTHZ_MAPPING    = 1u << 2    /* subject_map → authdb user rules   */
} xrootd_authz_strategy_e;

typedef struct {
    char      name[64];                       /* "[Issuer <name>]"            */
    char      issuer[256];                    /* iss URL                      */
    char      audiences[XROOTD_TOKEN_MAX_AUDIENCES][256];
    int       audience_count;
    char      base_paths[XROOTD_TOKEN_MAX_BASEPATHS][XROOTD_SCOPE_PATH_MAX];
    int       base_path_count;
    char      restricted_paths[XROOTD_TOKEN_MAX_BASEPATHS][XROOTD_SCOPE_PATH_MAX];
    int       restricted_path_count;
    char      username_claim[64];             /* default "sub"                */
    char      groups_claim[64];               /* e.g. "wlcg.groups"           */
    char      default_user[64];
    char      name_mapfile[PATH_MAX];
    unsigned  map_subject:1;
    unsigned  onmissing_fail:1;               /* 1=fail, 0=use default_user   */
    unsigned  enabled:1;
    uint32_t  strategy;                       /* xrootd_authz_strategy_e bits */
    /* per-issuer JWKS (reuses existing loader) */
    char              jwks_path[PATH_MAX];     /* or jwks_url for fetch        */
    xrootd_jwks_key_t jwks_keys[XROOTD_MAX_JWKS_KEYS];
    int               jwks_key_count;
    time_t            jwks_mtime;
    int               metric_bucket;           /* low-cardinality id (0..N)    */
} xrootd_token_issuer_t;

typedef struct {
    xrootd_token_issuer_t issuers[XROOTD_TOKEN_MAX_ISSUERS];
    int                   count;
    uint32_t              default_strategy;    /* when an issuer omits it      */
} xrootd_token_registry_t;
```

**Resolution algorithm** (added to `validate.c`, after signature/exp/aud pass):

```
1. select issuer by exact iss match → idx (else: deny "unknown issuer")
2. audience: token aud ∈ issuer.audiences (or [Global]) (else deny)
3. path gate: requested path must be under one base_path AND not under any
   restricted_path (longest-prefix; reuse scope_path_matches() boundary logic)
4. run strategy bits in order:
     CAPABILITY → existing xrootd_token_check_read/_write on parsed scopes
     GROUP      → groups_claim values intersect authdb groups (authdb.c)
     MAPPING    → subject_map_resolve(sub|username_claim) → authdb user rules
   ALLOW if any enabled strategy grants; DENY if none.
5. monitor: xrootd_token_mon_report(idx, op, username)
```

**Modified files**
- `validate.c` — new `xrootd_token_validate_registry(log, token, len, registry,
  req_path, op, claims, out_issuer_idx, out_username)` wrapping the existing
  per-key path; the legacy `xrootd_token_validate()` becomes the single-issuer
  shim that builds a 1-entry registry (zero behavior change).
- `config.c` — `xrootd_token_config <file>` loads the registry via
  `issuer_registry_load()`; else fall back to single-issuer directives.
- `jwks.c`/`refresh.c` — iterate registry issuers for load + mtime refresh.
- `webdav/auth_token.c`, `gsi/token.c` — call the registry entry point, pass the
  resolved username into the identity (`types/identity.c`).

**New directives** (fields in `src/types/config.h`, setters in `directives.c`):
- `xrootd_token_config <path>` — INI registry file (XRootD `scitokens.cfg`-shaped).
- `xrootd_token_strategy capability|group|mapping [...]` — default strategy.
- Existing `xrootd_token_issuer/_audience/_jwks` remain as the single-issuer shortcut.

### W1.4 Config compatibility

Parse the upstream grammar directly so `xrootd_token_config /etc/xrootd/
scitokens.cfg` loads an existing file unchanged. **Unsupported keys are logged at
`warn`, never silently ignored** (risk R4) — e.g. issuer-specific cache tuning we
don't mirror. `True/False/yes/no/1/0` all accepted for booleans (match upstream
case-insensitive).

---

## §W2 — CSI persistent page-checksum tagstore

### W2.1 Upstream behavior (`/tmp/xrootd-src/src/XrdOssCsi`)

A stacked OSS plugin adding `XRDOSS_HASFSCS` by storing a **CRC32C per
`XrdSys::PageSize` (4096-byte) page** in a **sidecar tag file** (suffix `.xrdt`),
either under a prefix directory mirroring the data tree (default `/.xrdt`) or
inline (`prefix=`). `Write`/`pgWrite` persist; `Read`/`pgRead` recompute and
**verify**, returning a checksum error on mismatch.

**Exact tag-file header (from `XrdOssCsiTagstoreFile.cc:72-113`):** a 20-byte
header, then the CRC array.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `magic` (uint32) | byte-swap detected vs `bswap_32(cmagic_)` for endianness |
| 4 | 8 | `trackinglen` (uint64) | tracked data length at last header update |
| 12 | 4 | `hflags` (uint32) | header flags |
| 16 | 4 | `header_crc` (uint32) | `Calc32C(header[0..16), 0)` over the first 16 bytes |
| 20 | 4·N | `crc[ ]` (uint32 ×N) | one CRC32C per 4096-byte data page |

`ReadTags(uint32_t*, off_t pageIdx, size_t nPages)` /
`WriteTags(const uint32_t*, off_t, size_t)` / `GetTrackedTagSize()` /
`Truncate(off_t,bool)`. Batch size `stsize_=1024` pages. Options: `nofill`
(don't tag implied-zero hole pages), `nomissing` (require the tag file),
`space=<name>`, `prefix=<dir>`, `nopgextend`, `noloosewrites` (recovery checks
for interrupted non-aligned writes). Partial-page writes ⇒ read-modify-write with
verify-before-write.

### W2.2 Current module state

- `src/compat/integrity_info.c` — *file-level* digest at rest (Phase 58 §8),
  `user.XrdCks.<alg>` xattr, mtime+size-keyed. No per-page granularity.
- `src/compat/pgio.{c,h}` + `pgread.c`/`pgwrite.c` — per-page CRC32C **on the
  wire** (kXR_pgread/pgwrite), transient.
- `src/compat/crc32c.{c,h}` — `xrootd_crc32c_value/extend/copy_value` (SSE4.2 HW
  path).
- `src/fs/vfs_io_core.{c,h}` — `xrootd_vfs_io_execute(job)` dispatches
  READ/WRITE/PGREAD/READV/WRITEV/SYNC/TRUNCATE/OPENDIR on a POD `xrootd_vfs_job_t`
  (`fd`/`offset`/`length`/`buf`/`want_pgcrc`/`want_cksum`/…).
- `src/fs/backend/sd.h` — SD driver vtable (`pread`/`pwrite`/`preadv`/`preadv2`/
  `fstat`) + capability bits `XROOTD_SD_CAP_FD=1<<0 … XROOTD_SD_CAP_IOURING=1<<10`.

So wire-CRC + file-digest exist; **the persistent per-page store and the
read-verify/write-update path do not.**

### W2.3 Design

A page-tag sidecar owned entirely by the storage backend, transparent to proto
handlers. Default off; opt-in `xrootd_csi on`.

**New files (`src/fs/backend/` — data-plane confinement)**
- `csi_tagstore.c/.h` — the sidecar: 24-byte header (our format, ADR-2) + uint32
  CRC32C array indexed by page. `csi_open_tags()` / `csi_read_tags()` /
  `csi_write_tags()` / `csi_truncate_tags()` / `csi_tag_path()` (prefix-dir or
  inline). **All tag-file `pread`/`pwrite` live here.**
- `csi_verify.c/.h` — glue invoked from the VFS I/O core: on read, recompute page
  CRC32C (`xrootd_crc32c_value`) and compare; on write, update tags for fully
  written pages, RMW + verify-before-write for partials; honor `fill`/holes.

**Our header format (ADR-2)** — superset of upstream's, versioned, host-order:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `magic` = `0x58435349` ("XCSI") |
| 4 | 2 | `version` = 1 |
| 6 | 2 | `page_log2` = 12 (4096) |
| 8 | 8 | `tracked_len` (uint64) |
| 16 | 4 | `flags` (bit0=fill-holes) |
| 20 | 4 | `header_crc` = crc32c(header[0..20)) |
| 24 | 4·N | `crc[ ]` per page |

**Integration** (`vfs_io_core.c`): add an optional `csi` context pointer to
`xrootd_vfs_job_t` (NULL when disabled). When set:
- `xrootd_vfs_io_execute_read` → after the data `pread`, call
  `csi_verify_read(csi, buf, offset, len)`; on mismatch set `job->io_errno=EIO`
  and a `csi_mismatch:1` out-flag.
- `xrootd_vfs_io_execute_write` / `_writev` → after the data `pwrite`, call
  `csi_update_write(csi, buf, offset, len)`; partial pages take the RMW path.
- `xrootd_vfs_io_execute_pgwrite` (the kXR_pgwrite fast path) → the client already
  supplies per-page CRC32C; **store directly, no recompute** when page-aligned
  (risk R1 mitigation).
- `xrootd_vfs_io_execute_pgread` → return stored tags when present (no recompute).

**New SD capability** `XROOTD_SD_CAP_FSCS = 1u << 11` so `query config`/checksum
reporting can advertise filesystem-checksum availability.

**New directives**
- `xrootd_csi on|off` (default off)
- `xrootd_csi_prefix <dir>` (default `/.xrdt`; empty = inline)
- `xrootd_csi_space <name>` (optional storage-space name)
- `xrootd_csi_fill on|off` (inverse of upstream `nofill`; default on)
- `xrootd_csi_require on|off` (upstream `nomissing`; default off)
- `xrootd_csi_scrub_interval <time>` (default 0 = off)

**Scrub** — a *paced* background sweep ([`idle_cpu_timer_family`]: NOT a
self-rearming hot poll) walking export roots, recomputing page CRCs, reporting
mismatches via metrics + `XROOTD_DIAG` cause/fix error.log lines.

### W2.4 Partial-write RMW (the subtle case, `noloosewrites`)

For a write touching only part of page P:
```
1. read the full 4096-byte page P from data (backend pread)
2. if a stored tag for P exists: verify(read_page) == tag[P]
      mismatch AND strict ⇒ EIO (refuse to overwrite a corrupt page silently)
      mismatch AND loose  ⇒ accept if tag[P] already equals crc(new_page) (a
                            retried interrupted write — upstream's recovery case)
3. splice the new bytes into the page image
4. pwrite the page; tag[P] = crc(new_page); WriteTags
```
Default = **strict verify** (safe). `xrootd_csi_loose on` opts into the recovery
behavior.

---

## §W3 — Throttle exact contract + Bwm reservation semantics

### W3.1 Upstream behavior

**`XrdThrottle`** directives (verified, `XrdThrottleConfig.cc` + README):

| Directive | Effect |
|---|---|
| `throttle.throttle [concurrency C] [data RATE] [iops IRATE] [interval ITVL_MS]` | **concurrency = summed IO service-time/sec** (a load metric, *not* request count); `data` MB/s; `iops` ops/s; `interval` recompute window (default 1000ms). |
| `throttle.max_wait_time SECS` | Delay cap before an over-limit IO errors instead of waiting (default 30s). |
| `throttle.max_active_connections N` | Connections with ≥1 open file, per user. |
| `throttle.max_open_files N` | Open files per user. |
| `throttle.userconfig <file>` | INI per-user `maxconn`; precedence exact > longest-prefix glob > `*` > global. |
| `throttle.loadshed host[:port] [freq]` | Shed by redirecting a fraction of requests. |
| `throttle.trace [all\|off\|bandwidth\|ioload\|debug]` | Trace categories. |

Fairness: short spikes allowed when the whole server is under threshold; usage
tracked per-user at ~1s intervals; over-limit ⇒ delay new IO, preferring
under-limit users, then error past `max_wait_time`.

**`XrdBwm`** — a bandwidth **reservation** manager (`XrdBwmPolicy.hh`):
`Schedule(resp, parms) → handle`, `Dispatch`, `Done(handle)`,
`Status(numqIn,numqOut,numXeq)`; `bwm.src`/`bwm.dst` classify endpoints into
reservation queues; a transfer reserves, queues until granted, releases on `Done`.
`XrdBwmLogger` records events to an external program.

### W3.2 Current module state (`src/ratelimit/`)

- Token-bucket **request-rate** + **bandwidth** + **W7 concurrency** (in-flight
  count), identity-aware (VO/issuer/DN-hash/IP/`VOLUME` prefix), across stream +
  HTTP. SHM zones (`xrootd_rate_limit_zone`), rules (`xrootd_rate_limit_rule`,
  `xrootd_bandwidth_limit`, `xrootd_concurrency_limit`).
- `xrootd_rl_node_t` (ratelimit.h) already carries `req_excess`, `bw_excess`,
  `in_flight`, `req_total`, `bytes_total`, `throttle_count`. `xrootd_rl_rule_t`
  carries `req_rate`/`req_burst`/`bw_rate`/`req_conc`/`nodelay`/`zone`. Core:
  `xrootd_rl_check`/`_bw_check`/`_charge_bytes`/`_acquire`/`_release`,
  `xrootd_rl_hash`, `xrootd_rl_lookup_locked`/`_create_locked`.
- **Mismatch:** our "concurrency" = request count; upstream's = IO-service-time
  load. No `max_open_files`/`max_active_connections` per-user, no `userconfig`
  INI, no delay-then-error `max_wait_time`, no loadshed, no reservation queue.

### W3.3 Design — W3a (`throttle.*` exact contract)

New file `src/ratelimit/throttle_compat.c/.h`. Directives use the `xrootd_`
prefix per nginx convention; the doc records the 1:1 `throttle.*` mapping so an
operator translates mechanically (optional `tools/throttle_cfg_translate`).

| nginx directive | upstream | implementation |
|---|---|---|
| `xrootd_throttle "concurrency C data R iops I interval ms"` | `throttle.throttle` | new IO-load keying mode (below) |
| `xrootd_throttle_max_wait <secs>` | `max_wait_time` | delay cap → `kXR_wait`/`503` then error |
| `xrootd_throttle_max_active_connections <n>` | `max_active_connections` | per-user SHM counter |
| `xrootd_throttle_max_open_files <n>` | `max_open_files` | per-user SHM counter |
| `xrootd_throttle_userconfig <file>` | `userconfig` | INI (reuse W1 `ini.c`) |
| `xrootd_throttle_loadshed host[:port] [freq]` | `loadshed` | redirect a fraction |
| `xrootd_throttle_trace ...` | `trace` | map to log levels |

**IO-load concurrency metric.** Add a new field to `xrootd_rl_node_t`:
`uint64_t io_time_us;` (summed IO service-time in the current interval) and
`ngx_msec_t io_window;`. At IO completion in `vfs_io_core.c` (we already capture a
monotonic latency per Phase-56 D-1), accumulate `io_time_us`. The "concurrency"
limit = `io_time_us / interval_us ≥ C`. This is an **additive** keying mode
(`XROOTD_RL_KEY_IOLOAD`), so existing `xrootd_concurrency_limit` (request count)
is unchanged (ADR-4).

**Per-user counters.** `max_open_files` / `max_active_connections` are SHM
counters keyed on the resolved username (reuse `xrootd_rl_*_locked` machinery,
spin+yield mutex). Increment at open / first-open-on-connection; decrement at
close / `xrootd_on_disconnect` (`src/connection/disconnect.c:288`). Over-limit ⇒
`kXR_error`/`429`.

**delay-then-error.** Over a rate/load limit ⇒ `kXR_wait` (root://) /
`503 Retry-After` (HTTP) up to `max_wait`, then error — matching upstream.

### W3.4 Design — W3b (Bwm reservation semantics)

New file `src/ratelimit/reservation.c/.h`. Default off (`xrootd_reservation off`,
ADR-3). A reservation manager for large/TPC transfers:

```c
typedef struct {                 /* one reservation slot in SHM              */
    uint64_t  handle;            /* opaque grant id                          */
    uint32_t  class_id;          /* src/dst endpoint class                   */
    uint64_t  bytes_budget;      /* reserved bandwidth budget                */
    ngx_msec_t granted_at;
    unsigned  state:2;           /* QUEUED / GRANTED / DONE                  */
} xrootd_resv_slot_t;
```
- `xrootd_reserve_zone <name>:<size> budget=<bytes/s>` — SHM queue + aggregate
  budget.
- `xrootd_reserve_src`/`_dst <cidr|host> <class>` — endpoint → class (the
  `bwm.src`/`bwm.dst` analogue).
- API: `xrootd_resv_schedule(class) → handle | QUEUED`, `xrootd_resv_done(handle)`,
  `xrootd_resv_status(&in,&out,&xeq)`.
- Integrate at TPC launch (`src/tpc/launch.c`, `src/webdav/tpc.c`): reserve before
  transfer, release on done/abort. Non-TPC data ops unaffected.
- `Status` → dashboard + Prometheus gauge `xrootd_reservation_queue{state}`.

---

## §R — Requirements traceability (FR/NFR/SEC/BLD/OPS)

| Req ID | Statement | WS | Verified by |
|---|---|---|---|
| FR-W1-1 | Load N issuers from upstream `scitokens.cfg` grammar | W1a | `test_token_issuer_registry.py::test_loads_stock_cfg` |
| FR-W1-2 | Authorize only within an issuer's `base_path`, deny inside `restricted_path` | W1a | `::test_basepath_scoping`, `::test_restricted_path` |
| FR-W1-3 | `map_subject`/`username_claim`/`name_mapfile` → local username | W1b | `test_token_subject_map.py` |
| FR-W1-4 | `groups_claim` → authdb group grant | W1b | `test_token_subject_map.py::test_group_strategy` |
| FR-W1-5 | `authorization_strategy` ordered evaluation | W1b | `::test_strategy_order` |
| FR-W1-6 | IO monitor counter per (issuer,op,result) | W1b | metrics assert |
| SEC-W1-1 | `iss` spoof / `aud` mismatch / wrong-base_path all DENY | W1a | `::test_security_neg` |
| FR-W2-1 | Persist CRC32C per 4096-byte page in a sidecar | W2a | `test_csi_tagstore.py::test_tags_written` |
| FR-W2-2 | Read verifies against stored tag; mismatch ⇒ `kXR_ChkSumErr`/500 | W2a | `::test_corrupt_data_page` |
| FR-W2-3 | Partial write = RMW + verify-before-write | W2a | `::test_partial_write_rmw` |
| FR-W2-4 | pgWrite stores client CRC without recompute | W2a | `::test_pgwrite_fastpath` |
| FR-W2-5 | `fill`/`require`/`prefix` options honored | W2b | `test_csi_holes.py` |
| FR-W2-6 | Paced scrub reports mismatches, no hot-poll | W2b | `::test_scrub_detects` |
| SEC-W2-1 | Tag path confined to prefix root (no traversal) | W2a | `::test_tag_path_confined` |
| FR-W3-1 | `throttle.*` directive set parsed 1:1 | W3a | `test_throttle_contract.py::test_directives` |
| FR-W3-2 | IO-load concurrency metric (service-time/s) | W3a | `::test_ioload_metric` |
| FR-W3-3 | `max_open_files`/`max_active_connections` per user | W3a | `::test_open_files_limit` |
| FR-W3-4 | `userconfig` precedence exact>glob>`*`>global | W3a | `::test_userconfig_precedence` |
| FR-W3-5 | delay-then-error (`kXR_wait`/`503` then error) | W3a | `::test_delay_then_error` |
| FR-W3-6 | Reservation Schedule/Done/Status | W3b | `test_reservation.py` |
| NFR-1 | All features default-off; enabling is the only behavior change | all | config-diff test |
| NFR-2 | W2 read-verify adds < 10% to a streamed read (HW CRC) | W2a | `tests/profile_load.sh` |
| SEC-3 | No metric label carries DN/path/issuer-URL | all | `test_metrics_cardinality.py` |
| BLD-1 | New files registered in `./config`; `nginx -t` clean | all | CI build gate |
| OPS-1 | Kill-switch = config revert, no redeploy | all | §JJ |

---

## §S — Near-complete annotated source skeletons

> Skeletons are near-final but elide error-string text and full doc-blocks for
> space; the real PRs carry the mandatory WHAT/WHY/HOW blocks (coding-standards
> §3). No `goto`; early-return + helper decomposition throughout.

### S.1 `src/token/ini.c` (shared INI reader)

```c
/* Minimal INI: [section] headers, key = value lines, # / ; comments.
 * Pure: no nginx runtime; reused by issuer_registry.c and throttle userconfig. */
typedef int (*xrootd_ini_cb)(void *u, const char *section,
                             const char *key, const char *val);

int xrootd_ini_parse_file(const char *path, xrootd_ini_cb cb, void *u,
                          char *errbuf, size_t errlen)
{
    FILE *f = fopen(path, "re");                /* O_CLOEXEC */
    if (f == NULL) { snprintf(errbuf, errlen, "open %s: %s", path,
                              strerror(errno)); return -1; }
    char line[1024], section[64] = "";
    int  rc = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        char *s = xrootd_ini_strip(line);       /* trim + drop comment */
        if (*s == '\0') continue;
        if (*s == '[') { rc = xrootd_ini_section(s, section, sizeof(section));
                         if (rc != 0) break; continue; }
        char *eq = strchr(s, '=');
        if (eq == NULL) { rc = -1; snprintf(errbuf, errlen,
                          "no '=' in: %s", s); break; }
        *eq = '\0';
        rc = cb(u, section, xrootd_ini_trim(s), xrootd_ini_trim(eq + 1));
        if (rc != 0) break;
    }
    fclose(f);
    return rc;
}
```

### S.2 `src/token/issuer_registry.c` (load callback excerpt)

```c
static int
reg_kv(void *u, const char *section, const char *key, const char *val)
{
    xrootd_token_registry_t *reg = u;
    if (strncmp(section, "Issuer ", 7) == 0) {
        xrootd_token_issuer_t *is = reg_issuer_for(reg, section + 7);
        if (is == NULL) return -1;              /* too many issuers */
        if      (eq(key, "issuer"))        copy_z(is->issuer, val);
        else if (eq(key, "base_path"))     reg_add_paths(is->base_paths,
                                              &is->base_path_count, val);
        else if (eq(key, "restricted_path")) reg_add_paths(is->restricted_paths,
                                              &is->restricted_path_count, val);
        else if (eq(key, "audience"))      reg_add_csv(is->audiences,
                                              &is->audience_count, val);
        else if (eq(key, "map_subject"))   is->map_subject = parse_bool(val);
        else if (eq(key, "username_claim")) copy_z(is->username_claim, val);
        else if (eq(key, "groups_claim"))  copy_z(is->groups_claim, val);
        else if (eq(key, "default_user"))  copy_z(is->default_user, val);
        else if (eq(key, "name_mapfile"))  copy_z(is->name_mapfile, val);
        else if (eq(key, "onmissing"))     is->onmissing_fail = eq(val,"fail");
        else if (eq(key, "enabled"))       is->enabled = parse_bool(val);
        else if (eq(key, "authorization_strategy"))
                                           is->strategy = parse_strategy(val);
        else ngx_log_error(NGX_LOG_WARN, reg->log, 0,
                 "scitokens: unsupported issuer key \"%s\" (ignored)", key);
        return 0;
    }
    if (eq(section, "Global")) { /* audience / audience_json */ ... }
    return 0;
}
```

### S.3 `src/fs/backend/csi_tagstore.c` (header IO)

```c
#define CSI_MAGIC      0x58435349u   /* "XCSI" */
#define CSI_HDR_LEN    24
#define CSI_PAGE       4096u

static int
csi_read_header(int tfd, xrootd_csi_hdr_t *h)
{
    u_char b[CSI_HDR_LEN];
    if (xrootd_pread_full(tfd, b, CSI_HDR_LEN, 0) != CSI_HDR_LEN) return -1;
    memcpy(&h->magic, b + 0, 4);
    if (h->magic != CSI_MAGIC) return -1;        /* (ADR-2: no bswap v1) */
    memcpy(&h->version, b + 4, 2);
    memcpy(&h->page_log2, b + 6, 2);
    memcpy(&h->tracked_len, b + 8, 8);
    memcpy(&h->flags, b + 16, 4);
    uint32_t want = xrootd_crc32c_value(b, 20), got;
    memcpy(&got, b + 20, 4);
    if (want != got) return -1;                  /* header corruption */
    return 0;
}

/* tags[] = CRC32C for pages [page0 .. page0+n). All pread inside the backend. */
ssize_t
csi_read_tags(xrootd_csi_t *c, uint32_t *tags, off_t page0, size_t n)
{
    off_t off = CSI_HDR_LEN + (off_t) page0 * 4;
    ssize_t got = xrootd_pread_full(c->tfd, tags, n * 4, off);
    return (got < 0) ? -1 : got / 4;
}
```

### S.4 `src/fs/backend/csi_verify.c` (read verify + write update)

```c
int
csi_verify_read(xrootd_csi_t *c, const u_char *buf, off_t off, size_t len)
{
    off_t p0 = off / CSI_PAGE;
    size_t np = (len + CSI_PAGE - 1) / CSI_PAGE;
    uint32_t stored[1024];                        /* stsize batch */
    for (size_t i = 0; i < np; i += 1024) {
        size_t batch = ngx_min(1024, np - i);
        if (csi_read_tags(c, stored, p0 + i, batch) != (ssize_t) batch)
            return CSI_NO_TAGS;                    /* missing ⇒ caller policy */
        for (size_t j = 0; j < batch; j++) {
            const u_char *pg = buf + (i + j) * CSI_PAGE;
            size_t plen = ngx_min(CSI_PAGE, len - (i + j) * CSI_PAGE);
            if (xrootd_crc32c_value(pg, plen) != stored[j])
                return CSI_MISMATCH;               /* → EIO/kXR_ChkSumErr */
        }
    }
    return CSI_OK;
}
```

### S.5 `src/ratelimit/throttle_compat.c` (IO-load check)

```c
/* Called at IO completion with the measured service time (Phase-56 D-1 clock). */
void
xrootd_throttle_charge_io(xrootd_rl_zone_t *zone, const char *user,
                          uint64_t service_us)
{
    ngx_shmtx_lock(&zone->shpool->mutex);         /* spin+yield (INV-10) */
    xrootd_rl_node_t *n = xrootd_rl_lookup_or_create(zone, user);
    if (n != NULL) {
        ngx_msec_t now = ngx_current_msec;
        if (now - n->io_window >= zone->interval_ms) {  /* new interval */
            n->io_time_us = 0; n->io_window = now;
        }
        n->io_time_us += service_us;
    }
    ngx_shmtx_unlock(&zone->shpool->mutex);
}

int                                               /* 1 = over limit */
xrootd_throttle_ioload_over(xrootd_rl_zone_t *zone, const char *user,
                            double concurrency_limit)
{
    /* load = io_time_us / interval_us ; compared to the concurrency target. */
    ...
}
```

---

## §T — Consolidated edit-hunk set (every touched file)

> `±` lines are illustrative against the real functions cited; PRs carry exact
> context. Existing line numbers from this checkout.

**T-1 `src/types/config.h`** (W1) — add registry fields:
```c
     ngx_str_t   token_jwks;
     ngx_str_t   token_issuer;
     ngx_str_t   token_audience;
+    ngx_str_t   token_config;          /* xrootd_token_config <scitokens.cfg> */
+    uint32_t    token_default_strategy;/* xrootd_token_strategy ...           */
+    xrootd_token_registry_t *token_registry; /* NULL ⇒ single-issuer path     */
```

**T-2 `src/token/validate.c`** (W1) — add registry entry point; legacy shim:
```c
+int xrootd_token_validate_registry(ngx_log_t *log, const char *tok, size_t n,
+    const xrootd_token_registry_t *reg, const char *req_path, int op,
+    xrootd_token_claims_t *claims, int *out_issuer_idx, char *out_user)
+{
+    /* 1) find issuer by iss (after a structural pre-parse of the payload)
+     * 2) xrootd_token_validate(... that issuer's keys/aud ...)
+     * 3) base_path / restricted_path gate (scope_path_matches boundary reuse)
+     * 4) strategy ladder (capability/group/mapping)
+     * 5) monitor report                                                       */
+}
 int xrootd_token_validate(ngx_log_t *log, const char *token, size_t token_len,
     const xrootd_jwks_key_t *keys, int key_count,
     const char *expected_issuer, const char *expected_audience, ...)
 {  /* unchanged: single-issuer fast path, now also the 1-entry shim target */ }
```

**T-3 `src/webdav/auth_token.c:225,246`** (W1) — call the registry path when
`conf->token_registry != NULL`, else the existing `xrootd_token_validate()`; pass
`rctx->uri`/op so `base_path` can be enforced and the resolved username stored.

**T-4 `src/fs/vfs_io_core.h:61`** (W2) — extend the job:
```c
     unsigned            want_pgcrc:1;
     unsigned            want_cksum:1;
+    unsigned            csi_mismatch:1;   /* OUT: set when a page failed verify */
+    void               *csi;              /* IN: xrootd_csi_t* or NULL          */
```

**T-5 `src/fs/vfs_io_core.c:165,208,254`** (W2) — wrap read/write/pgwrite:
```c
 xrootd_vfs_io_execute_read(xrootd_vfs_job_t *job) {
     ... existing pread ...
+    if (job->csi != NULL && job->io_errno == 0) {
+        int v = csi_verify_read(job->csi, job->buf, job->offset, got);
+        if (v == CSI_MISMATCH) { job->io_errno = EIO; job->csi_mismatch = 1; }
+    }
 }
```

**T-6 `src/fs/backend/sd.h:89`** (W2) — add the capability bit:
```c
     XROOTD_SD_CAP_IOURING       = 1u << 10
+   , XROOTD_SD_CAP_FSCS         = 1u << 11   /* filesystem page checksums */
```

**T-7 `src/ratelimit/ratelimit.h`** (W3a) — IO-load fields on the node + key type:
```c
     ngx_uint_t         in_flight;
+    uint64_t           io_time_us;     /* summed IO service time, current ivl  */
+    ngx_msec_t         io_window;      /* interval start                       */
+    ngx_uint_t         open_files;     /* throttle.max_open_files counter       */
```
```c
     XROOTD_RL_KEY_VOLUME  = 4,
+    XROOTD_RL_KEY_IOLOAD  = 5,         /* additive; request-count mode intact  */
```

**T-8 `src/connection/disconnect.c:288`** (W3a) — decrement per-user counters in
`xrootd_on_disconnect()` (active-connection + any still-open files).

**T-9 `src/tpc/launch.c`, `src/webdav/tpc.c`** (W3b) — `xrootd_resv_schedule()`
before transfer; `xrootd_resv_done()` on done/abort (both success and error
ladders).

**T-10 `./config`** — register: `src/token/{ini,issuer_registry,subject_map,
monitor}.c`, `src/fs/backend/{csi_tagstore,csi_verify}.c`,
`src/ratelimit/{throttle_compat,reservation}.c`. Requires `./configure` + `make`.

**T-11 directives** — `src/config/directives.c` setters + merges for all new
directives (§BB); fields in `src/types/config.h`.

---

## §U — Byte-level sequence & state diagrams

**U.1 W1 authorize (registry path)**
```
client → [HTTP Authorization: Bearer <jwt>] or [kXR_auth ztn]
  webdav/auth_token.c | gsi/token.c
    → xrootd_token_validate_registry(reg, req_path, op)
        pre-parse iss ── no match ─────────────► DENY "unknown issuer"
        select issuer i
        xrootd_token_validate(keys_i, aud_i) ── bad sig/exp/aud ─► DENY
        base_path gate: req_path ⊂ base_path[i] && ⊄ restricted ─► else DENY
        strategy ladder:
           capability: check_read/_write(scopes) ─ grant? ─► ALLOW
           group:      groups_claim ∩ authdb groups ─ grant? ─► ALLOW
           mapping:    subject_map(sub) → authdb user ─ grant? ─► ALLOW
           none ───────────────────────────────────────────► DENY
        mon_report(i, op, user)
```

**U.2 W2 read-verify state machine**
```
READ(off,len) ─► pread data ─► [csi==NULL] ─► return
                                  │
                          [csi!=NULL]
                                  ▼
                      csi_read_tags(p0..pN)
                       ├ CSI_NO_TAGS ─► require? ─yes─► EIO ; ─no─► return (untagged)
                       ├ CSI_OK + all crc match ─► return data
                       └ CSI_MISMATCH ─► io_errno=EIO ; csi_mismatch=1
                                         → kXR_ChkSumErr(3031) / HTTP 500
```

**U.3 W2 partial-write RMW**
```
WRITE(off,len) where (off%4096 || len%4096):
  read page P ─► verify(P)==tag[P]?
     strict & mismatch ─► EIO
     loose  & mismatch ─► tag[P]==crc(new)? accept(retry) : EIO
  splice new bytes ─► pwrite(P) ─► tag[P]=crc(new) ─► WriteTags
```

**U.4 W3a delay-then-error**
```
op ─► rl_check / ioload_over ─► under? ─► proceed
                                  │ over
                                  ▼
                       waited < max_wait ? ─yes─► kXR_wait(ms) / 503 Retry-After
                                          └─no──► kXR_error / 429
```

---

## §HH — Explicit state-transition tables

Sequence diagrams (§U) as exhaustive transition tables, so every (state, event)
pair has a defined action — no implicit fall-through.

### HH.1 W1 issuer-resolution FSM

States: `S_RECV`, `S_ISS`, `S_SIG`, `S_AUD`, `S_PATH`, `S_STRAT`, `S_ALLOW`,
`S_DENY`, `S_MON`.

| State | Event | Next | Action |
|---|---|---|---|
| S_RECV | token present | S_ISS | pre-parse `iss` from payload (no sig trust yet) |
| S_RECV | no token | S_DENY | `kXR_NotAuthorized`/401 "no bearer" |
| S_ISS | `iss` matches issuer i | S_SIG | bind issuer i |
| S_ISS | `iss` matches none | S_DENY | "unknown issuer" + `mon(unknown)` |
| S_ISS | `iss` matches ≥2 (dup) | S_SIG | last-wins + WARN (NN-1) |
| S_SIG | sig+exp+nbf valid (keys_i) | S_AUD | extract claims |
| S_SIG | sig/exp/nbf invalid | S_DENY | "bad signature/expired" |
| S_AUD | `aud` ∈ issuer_i.aud ∪ Global | S_PATH | — |
| S_AUD | `aud` mismatch | S_DENY | "audience mismatch" |
| S_PATH | req_path ⊂ base_path ∧ ⊄ restricted | S_STRAT | — |
| S_PATH | outside base_path / inside restricted | S_DENY | "path not authorized" |
| S_STRAT | a strategy in order grants | S_ALLOW | record granting strategy |
| S_STRAT | no strategy grants | S_DENY | "no strategy granted" |
| S_ALLOW | — | S_MON | set identity (user/groups), `mon(ok)` |
| S_DENY | — | (terminal) | `mon(deny,reason)` |

### HH.2 W2 CSI read-verify FSM

States: `R_READ`, `R_TAGS`, `R_VERIFY`, `R_OK`, `R_MISMATCH`, `R_NOTAGS`.

| State | Event | Next | Action |
|---|---|---|---|
| R_READ | data `pread` ok, csi==NULL | R_OK | return data (CSI disabled) |
| R_READ | data `pread` ok, csi!=NULL | R_TAGS | `csi_read_tags(p0..pN)` |
| R_READ | data `pread` errno | R_OK | propagate `io_errno` (not a CSI error) |
| R_TAGS | tags present | R_VERIFY | — |
| R_TAGS | tags absent, require=off | R_NOTAGS | return data (untagged read) |
| R_TAGS | tags absent, require=on | R_MISMATCH | `io_errno=EIO` "missing tags" |
| R_TAGS | header CRC bad | R_MISMATCH | `io_errno=EIO` "tag header corrupt" |
| R_VERIFY | all page CRCs equal | R_OK | return data |
| R_VERIFY | any page CRC differs | R_MISMATCH | `io_errno=EIO; csi_mismatch=1` |
| R_MISMATCH | — | (terminal) | `kXR_ChkSumErr`(3031)/HTTP 500 + DIAG |
| R_NOTAGS | — | (terminal) | metric `notags`++, serve data |

### HH.3 W2 CSI write-update FSM (incl. partial RMW)

| State | Event | Next | Action |
|---|---|---|---|
| W_WRITE | page-aligned, csi!=NULL | W_TAG | tag[p]=crc(page) for each full page |
| W_WRITE | partial page, csi!=NULL | W_RMW | read full page P |
| W_WRITE | csi==NULL | W_DONE | plain `pwrite` |
| W_RMW | tag[P] absent | W_SPLICE | (new page, no prior tag) |
| W_RMW | tag[P] present, crc(old)==tag[P] | W_SPLICE | page verified clean |
| W_RMW | mismatch, loose, crc(new)==tag[P] | W_SPLICE | accept retried write |
| W_RMW | mismatch, strict | W_ERR | `io_errno=EIO` (refuse silent overwrite) |
| W_SPLICE | — | W_TAG | splice new bytes into page image, `pwrite` |
| W_TAG | `WriteTags` ok | W_DONE | update header `tracked_len` if grown |
| W_TAG | `WriteTags` errno | W_ERR | `io_errno=errno` |

### HH.4 W3a throttle admission FSM

States: `T_ENTER`, `T_RATE`, `T_LOAD`, `T_CONN`, `T_WAIT`, `T_PROCEED`, `T_ERR`.

| State | Event | Next | Action |
|---|---|---|---|
| T_ENTER | open/IO begins | T_CONN | check active-conn + open-files counters |
| T_CONN | under per-user caps | T_RATE | inc counters |
| T_CONN | over a cap | T_ERR | `kXR_error`/429 "too many open/conn" |
| T_RATE | `rl_check` under | T_LOAD | charge request |
| T_RATE | over, nodelay | T_ERR | reject now |
| T_RATE | over, delay | T_WAIT | compute wait |
| T_LOAD | `ioload_over` false | T_PROCEED | — |
| T_LOAD | true, waited<max_wait | T_WAIT | `kXR_wait(ms)`/503 Retry-After |
| T_LOAD | true, waited≥max_wait | T_ERR | error after max_wait |
| T_WAIT | client retries | T_ENTER | re-evaluate (under-limit users preferred) |
| T_PROCEED | — | (terminal) | run IO; on completion `charge_io(service_us)` |

### HH.5 W3b reservation FSM

| State | Event | Next | Action |
|---|---|---|---|
| V_REQ | `schedule(class)`, budget free | V_GRANTED | allocate slot, return handle |
| V_REQ | `schedule(class)`, budget full | V_QUEUED | enqueue, return QUEUED |
| V_QUEUED | a peer `done()` frees budget | V_GRANTED | dequeue head, grant |
| V_QUEUED | client/TPC aborts | V_DONE | remove from queue (no grant) |
| V_GRANTED | `done(handle)` | V_DONE | release budget, wake one queued |
| V_GRANTED | TPC abort | V_DONE | `done()` on error path (R6) |
| V_DONE | `done(handle)` again | V_DONE | idempotent no-op |

---

## §V — Concurrency, memory-ordering & reentrancy proofs

- **W1.** The registry is built once at config/postconfiguration (single-thread)
  and thereafter **read-only** at request time; only `jwks_keys`/`jwks_mtime` are
  mutated, and only by the existing refresh timer on the worker event thread
  (same single-owner discipline as today's single-issuer path). No new locks.
- **W2.** Tag I/O runs **inside the SD backend on the thread-pool worker** that
  already owns the data fd for that job (`xrootd_vfs_io_execute` is the POD
  execution surface, no nginx runtime touched). One job ⇒ one fd ⇒ one tag fd; no
  cross-thread sharing of the `xrootd_csi_t`. The job is the single owner from
  post→complete (same invariant as the existing read/write jobs). Header updates
  are last-writer-wins on a per-file tag fd; concurrent writers to the *same* file
  are already serialized by the handle layer.
- **W3.** Per-user counters and the reservation queue are SHM tables created via
  `xrootd_shm_table_*` (spin+yield, INVARIANT 10 — **never** POSIX-sem). Critical
  sections are µs-held fixed-slot scans (lookup/charge/decrement), matching the
  existing `xrootd_rl_*_locked` contract that already requires the caller to hold
  `zone->shpool->mutex`. Decrement-on-disconnect runs on the event thread in
  `xrootd_on_disconnect` exactly once (UAF-guarded teardown already in place).

---

## §W — Capacity & performance model

### W-mem.1 W1 registry footprint
`sizeof(xrootd_token_issuer_t)` ≈ `64+256 + 8·256(aud) + 8·256(base) + 8·256(restr)
+ 64·4 + 4096(mapfile) + 4096(jwks_path) + 8·sizeof(xrootd_jwks_key_t)` ≈ **~12 KB**
(JWKS keys dominate: `sizeof(xrootd_jwks_key_t)=128+ptr`). At
`XROOTD_TOKEN_MAX_ISSUERS=16` ⇒ **~190 KB** in the conf pool, allocated once at
postconfiguration. Per-auth cost = O(issuers) `strcmp` on `iss` (≤16) — ~1 µs,
negligible beside the RSA-2048 verify (~40 µs) already on the path.

### W-mem.2 W2 tag-file sizing
Tag file size = `24 + 4·ceil(L/4096)` for a data file of `L` bytes.

| Data file | Tag file | Overhead |
|---|---|---|
| 4 KB | 28 B | 0.68% |
| 1 MB | 1.0 KB | 0.098% |
| 1 GB | 1.0 MB | 0.098% |
| 1 TB | 1.0 GB | 0.098% |

Steady-state overhead is **1/1024 ≈ 0.098%** of stored bytes (one uint32 per
4096-byte page). The prefix tree mirrors the data tree, so inode count doubles
under `prefix=/.xrdt` — call out for sites with billions of small files
(`prefix=` inline avoids the extra inodes but loses the hidden-tree property).

### W-cpu.1 W2 verify cost
Per read: `ceil(len/4096)` calls to `xrootd_crc32c_value`. On SSE4.2
(`_mm_crc32_u64`) CRC32C runs at **~20 GB/s/core**, so a 1 MB read costs ~50 µs of
CRC vs a `pread` that (page-cache-warm) costs ~30 µs — **but** the verify reuses
the bytes already in `buf` (no second copy), and Phase-26's in-place 3-way CRC
([`pgread_zerocopy_crc_optim`]) folds the verify into the existing copy on the
gapped-preadv path. Cold (disk-bound) reads are dominated by the I/O, so the CRC
is hidden. Target **NFR-2 < 10%** holds for cache-warm streamed reads; measure
with `tests/profile_load.sh`. The tag `pread` adds `4·ceil(len/4096)` bytes of
extra I/O (≈ 0.1% read amplification), batched 1024 pages at a time.

### W-cpu.2 W2 write cost
Aligned write: `ceil(len/4096)` CRC computes + one batched `WriteTags`
(`4·npages` bytes). **pgWrite stores the client CRC** — zero CRC compute on that
path (FR-9). Partial write: one extra page `pread` (RMW) + one CRC for verify +
one for the new page — the cost lives only on sub-page writes (rare for bulk
transfer; common for random-update workloads, which is exactly where integrity
matters most).

### W-mem.3 W3 SHM
One `xrootd_rl_node_t` per active user (already slab-bounded with 8-way LRU
eviction in `xrootd_rl_create_locked`). The new fields (`io_time_us` 8 B,
`io_window` 4–8 B, `open_files` 8 B) add ~24 B/node — negligible against the
existing node + key. IO-load charge = **one locked add** per IO completion; the
lock is already taken for byte charging on the bandwidth path, so on a combined
rule it is free (same critical section). Standalone IO-load adds one `lock/add/
unlock` (~50 ns uncontended spin).

### W-mem.4 W3b reservation
`xrootd_resv_slot_t` ≈ 40 B × queue depth; a 10 MB zone holds ~250k slots — far
more than any real concurrent-transfer count. Default off ⇒ zero footprint when
unused.

### W-lat.1 Latency budget summary
| Op | Added latency (warm) | Source |
|---|---|---|
| token authorize (registry) | +~1 µs | O(16) iss scan |
| CSI read 1 MB | +~50 µs CRC, +1 KB tag pread | EE.9 |
| CSI write 1 MB aligned | +~50 µs CRC, +1 KB tag pwrite | EE.9 |
| CSI partial write | +1 page pread +~6 µs | EE.9 RMW |
| throttle charge | +~50 ns | EE.11 |

---

## §X — Failure-injection matrix (30 rows)

| # | Injected fault | Expected | Guarded by |
|---|---|---|---|
| 1 | `scitokens.cfg` unknown key | WARN logged, key ignored, load succeeds | `test_token_issuer_registry::test_unknown_key` |
| 2 | `scitokens.cfg` missing `issuer=` in a section | config error, `nginx -t` fails | `::test_missing_issuer` |
| 3 | Two issuer sections, same `iss` | last-wins + WARN (NN-1) | `::test_dup_issuer` |
| 4 | Token `iss` matches no issuer | DENY "unknown issuer", `mon(unknown)` | `::test_unknown_iss` |
| 5 | Token valid but path outside `base_path` | DENY (SEC-W1-1) | `::test_basepath_scoping` |
| 6 | Path inside `restricted_path` | DENY | `::test_restricted_path` |
| 7 | `name_mapfile` absent, `onmissing=fail` | DENY | `test_token_subject_map::test_onmissing_fail` |
| 8 | `name_mapfile` absent, `default_user` set | map → default_user, ALLOW if authdb permits | `::test_default_user` |
| 9 | `groups_claim` present but no authdb group match | group strategy fails; next strategy tried | `::test_group_then_cap` |
| 10 | Token `exp` in the past | DENY "expired" (existing validate path) | `::test_expired` |
| 11 | Token `aud` is a JSON array, expected ∈ array | ALLOW (array-aud path, existing) | `::test_aud_array` |
| 12 | JWKS file empty / 0 keys for an issuer | config error at load (issuer unusable) | `::test_empty_jwks` |
| 13 | CSI tag file missing, `require=on` | EIO/500 | `test_csi_tagstore::test_require_missing` |
| 14 | CSI tag file missing, `require=off` | serve data, metric `notags`++ | `::test_notags_ok` |
| 15 | CSI tag header CRC bad | treat as corrupt → `require` policy | `::test_header_corrupt` |
| 16 | One data page flipped on disk | read ⇒ `kXR_ChkSumErr`/500 at that page | `::test_corrupt_data_page` |
| 17 | One tag entry flipped | mismatch on the corresponding page read | `::test_corrupt_tag` |
| 18 | Interrupted partial write retried (loose) | accepted iff tag==crc(new) | `::test_loose_retry` |
| 19 | Interrupted partial write (strict) | EIO (no silent overwrite) | `::test_strict_refuse` |
| 20 | Write extends file past EOF (hole), fill=on | hole pages tagged with crc(zeros) | `test_csi_holes::test_fill_on` |
| 21 | Same, fill=off | hole pages untagged; reads of holes per policy | `::test_fill_off` |
| 22 | Truncate shrinks file | tag array truncated, `tracked_len` updated | `::test_truncate` |
| 23 | Tag path attempts `../` traversal | confined to prefix root (openat2 BENEATH) | `::test_tag_path_confined` |
| 24 | Scrub finds a mismatch | metric++ + `XROOTD_DIAG` line, no client impact | `::test_scrub_detects` |
| 25 | `throttle_userconfig` user matches glob + `*` | longest-prefix glob wins | `test_throttle_contract::test_userconfig_precedence` |
| 26 | Over IO-load limit, client waits past `max_wait` | error after the wait | `::test_delay_then_error` |
| 27 | Over `max_open_files` for a user | new open rejected `kXR_error`/429 | `::test_open_files_limit` |
| 28 | Connection drops mid-IO | counters decremented in `on_disconnect` (no leak) | `::test_disconnect_decrement` |
| 29 | Reservation budget exhausted | new transfer QUEUED then granted on Done | `test_reservation::test_queue_grant` |
| 30 | TPC aborts mid-transfer | `xrootd_resv_done` still releases (no leak) | `::test_abort_release` |
| 31 | SHM slab exhausted (W3) | fail-open (allow), `throttle_count` not double-counted | `::test_slab_exhausted` |
| 32 | Reload changes throttle SHM slot count | table reset with WARN (reload-semantics) | `::test_reload_reset` |

---

## §Y — CI/CD + PR-by-PR rollout + review checklists

| PR | WS | Adds | `./configure`? | Tests |
|---|---|---|---|---|
| PR-1 | W1a | `ini.c`, `issuer_registry.c`, registry validate path, single-issuer shim | yes | `test_token_issuer_registry.py` |
| PR-2 | W1b | `subject_map.c`, `monitor.c`, strategy ladder | yes | `test_token_subject_map.py` |
| PR-3 | W2a | `csi_tagstore.c`, `csi_verify.c`, vfs_io_core wiring, `CAP_FSCS` | yes | `test_csi_tagstore.py` |
| PR-4 | W2b | holes/require/prefix options, scrub timer | no | `test_csi_holes.py` |
| PR-5 | W3a | `throttle_compat.c`, IO-load mode, open-files/active-conns, userconfig | yes | `test_throttle_contract.py` |
| PR-6 | W3b | `reservation.c`, TPC integration | yes | `test_reservation.py` |

**Per-PR review checklist:** compiles `-Werror`; `nginx -t` clean; 3 tests
(success/error/security-neg); no `goto`; functional/modular; HELPERS reused; SHM
via `xrootd_shm_table_*`; metric labels low-cardinality; subsystem `README.md`
updated; the relevant `docs/10-reference/*` parity row flipped; gap-doc "partial"
status updated; [`dropin_gap_analysis`] memory touched when a WS lands.

**CI job definitions** (gates per PR):

| Job | Command | Gate |
|---|---|---|
| `build` | `./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$REPO && make -j$(nproc)` | exit 0, no `-Werror` |
| `confcheck` | `objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf` | "syntax is ok" |
| `goto-guard` | `! git diff --name-only origin/main.. \| xargs grep -nw goto` (src/) | no new `goto` |
| `unit-csi` | `gcc -DUNIT src/fs/backend/csi_tagstore.c csi_verify.c compat/crc32c.c -o /tmp/t && /tmp/t` | golden CRC vectors (§GG) pass |
| `unit-ini` | standalone `xrootd_ini_parse_file` over `tests/fixtures/scitokens.cfg` | registry shape == expected |
| `pytest-w1` | `PYTHONPATH=tests pytest tests/test_token_*.py -v -n0` | green |
| `pytest-w2` | `PYTHONPATH=tests pytest tests/test_csi_*.py -v -n0` | green |
| `pytest-w3` | `PYTHONPATH=tests pytest tests/test_throttle_contract.py tests/test_reservation.py -v -n0` | green |
| `cardinality` | `pytest tests/test_metrics_cardinality.py` | no high-card labels |
| `interop` | §DD harness vs stock `xrootd` 5.9.5 | parity asserts pass |
| `perf-csi` | `tests/profile_load.sh` read 1 GB with/without CSI | < 10% delta (NFR-2) |

### Y.1 Per-PR file manifest

**PR-1 (W1a)** — new: `src/token/ini.{c,h}`, `src/token/issuer_registry.{c,h}`;
modified: `src/token/validate.c` (+`xrootd_token_validate_registry`, peek_iss,
aud_ok), `src/types/config.h` (+`token_config`/`token_default_strategy`/
`token_registry`), `src/config/directives.c` (+2 directives), merge_srv_conf
(+registry build), `src/webdav/auth_token.c` + `src/gsi/token.c` (registry branch),
`./config` (+2 srcs). Tests: `tests/test_token_issuer_registry.py`,
`tests/fixtures/scitokens.cfg`. Docs: `src/token/README.md`,
`docs/10-reference/protocol-gaps-vs-xrootd.md` (SciTokens row).

**PR-2 (W1b)** — new: `src/token/subject_map.{c,h}`, `src/token/monitor.{c,h}`;
modified: `validate.c` (strategy ladder: group/mapping grants), `src/path/authdb.c`
(group/user lookup helpers if absent), `src/metrics/` (token authz counters),
`./config`. Tests: `tests/test_token_subject_map.py`,
`tests/fixtures/namemap.json`.

**PR-3 (W2a)** — new: `src/fs/backend/csi_tagstore.{c,h}`,
`src/fs/backend/csi_verify.{c,h}`; modified: `src/fs/vfs_io_core.{c,h}` (job
`csi`/`csi_mismatch`, read/write/pgwrite wiring), `src/fs/backend/sd.h`
(`CAP_FSCS`), `src/read/read.c` (`csi_mismatch`→`kXR_ChkSumErr`), `src/types/
config.h` (+csi fields), `directives.c` (+csi directives), `src/read/open.c`
(attach `xrootd_csi_t` to the handle when enabled), `./config`. Tests:
`tests/test_csi_tagstore.py`. Unit: standalone `csi_*` + `crc32c` build.

**PR-4 (W2b)** — new: scrub timer (`src/fs/backend/csi_scrub.c`); modified:
`csi_verify.c` (fill/require/loose option handling), `src/webdav/get.c` +
`src/s3/get.c` (sendfile-disable under CSI, ADR-6), postconfiguration (arm scrub).
Tests: `tests/test_csi_holes.py`.

**PR-5 (W3a)** — new: `src/ratelimit/throttle_compat.{c,h}`; modified:
`src/ratelimit/ratelimit.h` (node `io_time_us`/`io_window`/`open_files`,
`KEY_IOLOAD`), `vfs_io_core.c` (charge_io at IO completion), `src/read/open.c` +
`src/connection/disconnect.c` (open/conn counters), `directives.c` (+throttle
directives, custom parser), reuses `src/token/ini.c` for userconfig, `./config`.
Tests: `tests/test_throttle_contract.py`, `tests/fixtures/throttle-users.conf`.

**PR-6 (W3b)** — new: `src/ratelimit/reservation.{c,h}`; modified: `src/tpc/
launch.c` + `src/webdav/tpc.c` (reserve/release), `directives.c` (+reservation
directives), `src/dashboard/` (queue panel), `./config`. Tests:
`tests/test_reservation.py`.

**Review checklist applied to EVERY PR** (gate before merge): `-Werror` clean ·
`nginx -t` ok · 3 tests (success/error/security-neg) green · no new `goto`
(goto-guard CI) · functional/modular, no new globals · HELPERS reused (no
re-implemented path/auth/metrics/framing) · SHM via `xrootd_shm_table_*` · metric
labels low-cardinality (cardinality CI) · subsystem `README.md` + the relevant
`docs/10-reference/*` parity row updated · gap-doc status flipped · the
`dropin_gap_analysis` memory touched when the WS completes.

---

## §QQ — Per-handler integration cookbook

Step-by-step changes to each touched request path, so a reviewer can trace the
exact call-site edits. All edits preserve the existing control flow; the new
calls are early-return-guarded on the feature flag.

### QQ.1 HTTP bearer auth — `src/webdav/auth_token.c`
1. In `webdav_verify_bearer_token()` (line ~120), after extracting the Bearer
   token, branch on `conf->token_registry != NULL`:
   - **registry path:** call `xrootd_token_validate_registry(log, token, len,
     reg, rctx->uri_cstr, op_from_method(r), &claims, &idx, user, sizeof user)`.
     On success store `user`/`idx` in `rctx` for the access-log + identity.
   - **single-issuer path (unchanged):** the existing
     `xrootd_token_validate(... token_issuer, token_audience ...)` at line 225.
2. `op_from_method(r)`: GET/HEAD/PROPFIND → READ; PUT/DELETE/MKCOL/MOVE/COPY →
   WRITE; else OTHER.
3. The existing `xrootd_token_check_write()` call in `webdav_authorize_token_path`
   (auth_token.c:56) stays for the single-issuer path; the registry path already
   ran the strategy ladder, so it sets a `rctx->authz_done` flag the path-gate
   honors (no double-enforcement).

### QQ.2 Stream (`root://`) auth — `src/gsi/token.c`
- The two `xrootd_token_validate()` call sites (lines 109, 130) gain the same
  `token_registry` branch. The resolved username flows into `ctx->identity`
  (`types/identity.c`) exactly where the `sub` is recorded today, so downstream
  `handshake/policy.c` (token_scopes) and authdb checks see the mapped user.

### QQ.3 Stream read — `src/fs/vfs_io_core.c::xrootd_vfs_io_execute_read`
- After the data `pread` succeeds and before returning, the `job->csi != NULL`
  guard calls `xrootd_csi_verify_read`. On `CSI_MISMATCH` set
  `job->io_errno = EIO; job->csi_mismatch = 1;`. The stream read handler
  (`src/read/read.c`) maps `csi_mismatch` → `kXR_ChkSumErr` (3031) instead of the
  generic `kXR_IOError`.

### QQ.4 Stream write / pgwrite — `src/fs/vfs_io_core.c`
- `_execute_write`/`_execute_writev`: after `pwrite`, `xrootd_csi_update_aligned`
  for full pages, RMW helper for partials.
- `_execute_pgwrite` (the kXR_pgwrite path): the client CRC array is already in
  the job; call `xrootd_csi_store_pgcrc(csi, page, client_crc[i])` per aligned
  page — **no recompute** (FR-9). A trailing partial page recomputes.

### QQ.5 WebDAV/S3 GET — `src/webdav/get.c`, `src/s3/get.c`
- These use `xrootd_vfs_open()` + `xrootd_vfs_file_sendfile_fd()`. With CSI on,
  **sendfile cannot verify** (bytes never enter userspace). Options (ADR-6,
  NN-5): (a) disable sendfile when CSI is on for that location (correctness over
  zero-copy), or (b) verify lazily via a background scrub + trust-on-read. v1
  picks **(a)** for HTTP GET when `xrootd_csi on` (documented perf trade-off);
  `root://` reads always verify since they already pass through the io-core buffer.

### QQ.6 Open/close counters — `src/read/open.c`, `src/connection/disconnect.c`
- On a successful `kXR_open`: `xrootd_throttle_open_inc(t, user)`; reject with
  `kXR_error` if it returns 0.
- On `kXR_close` and in `xrootd_on_disconnect()` (disconnect.c:288):
  `xrootd_throttle_open_dec(t, user)` for each still-open handle, and decrement
  the active-connection counter once if the connection had ≥1 open file.

### QQ.7 TPC reserve/release — `src/tpc/launch.c`, `src/webdav/tpc.c`
- Before initiating the pull/push: `handle = xrootd_resv_schedule(zone, class,
  est_bytes)`; if `handle == 0` (QUEUED) park the TPC with the existing
  `kXR_waitresp`/retry machinery.
- On completion **and on every error/abort ladder**: `xrootd_resv_done(zone,
  handle)` (idempotent — R6).

---

## §AA — Observability

### AA.1 Metric catalog (Prometheus `# HELP`/`# TYPE` + label sets)

```
# HELP xrootd_token_authz_total Bearer-token authorization decisions.
# TYPE xrootd_token_authz_total counter
xrootd_token_authz_total{issuer_bucket="0..N|other",op="read|write|other",result="allow|deny"}

# HELP xrootd_token_mapping_total Subject→username mapping outcomes.
# TYPE xrootd_token_mapping_total counter
xrootd_token_mapping_total{result="mapped|default|missing"}

# HELP xrootd_csi_verify_total Page-checksum verify outcomes on read.
# TYPE xrootd_csi_verify_total counter
xrootd_csi_verify_total{result="ok|mismatch|notags"}

# HELP xrootd_csi_scrub_pages_total Pages scanned by the background scrubber.
# TYPE xrootd_csi_scrub_pages_total counter
# HELP xrootd_csi_scrub_mismatch_total Pages failing verify during scrub.
# TYPE xrootd_csi_scrub_mismatch_total counter

# HELP xrootd_throttle_ioload Current IO-load (service-time/interval) per zone.
# TYPE xrootd_throttle_ioload gauge
xrootd_throttle_ioload{zone="<name>"}

# HELP xrootd_throttle_wait_seconds Imposed wait before admit/error.
# TYPE xrootd_throttle_wait_seconds histogram
xrootd_throttle_wait_seconds_bucket{le="0.1|0.5|1|5|30|+Inf"}

# HELP xrootd_throttle_rejections_total Requests rejected by the throttle.
# TYPE xrootd_throttle_rejections_total counter
xrootd_throttle_rejections_total{reason="ioload|max_open_files|max_conn|rate"}

# HELP xrootd_reservation_queue Reservation slots by state.
# TYPE xrootd_reservation_queue gauge
xrootd_reservation_queue{state="in|out|xeq"}
```

**Cardinality proof (SEC-3):** `issuer_bucket` is the small integer
`metric_bucket` (≤ `XROOTD_TOKEN_MAX_ISSUERS`+1), never the issuer URL; `zone` is
operator-named (bounded by config); `reason`/`result`/`op`/`state` are fixed
enums. No DN/path/subject/bucket reaches a label.

### AA.2 Logs
- `XROOTD_DIAG` cause/fix lines: CSI mismatch ("data corruption on disk; restore
  from replica"), throttle rejection ("user over max_open_files; raise limit or
  reduce concurrency"), unknown issuer ("iss not in scitokens.cfg; add an
  [Issuer] section").
- Access-log already carries the resolved identity; the mapped username (W1b) is
  what gets logged for a registry-authorized request.

### AA.3 Dashboard (`src/dashboard/`)
- CSI panel: verify ok/mismatch/notags counters + last-scrub timestamp.
- Throttle panel: per-user open-files/active-conn table + current IO-load gauge.
- Reservation panel: queue depth (in/out/xeq) + budget utilization.

---

## §BB — Full config reference

```nginx
# ── W1 SciTokens ────────────────────────────────────────────────
xrootd_token_config   /etc/xrootd/scitokens.cfg;   # multi-issuer registry
xrootd_token_strategy capability group mapping;     # default when issuer omits
# (single-issuer shortcut, unchanged:)
xrootd_token_issuer   https://cilogon.org;
xrootd_token_audience https://storage.example.org;
xrootd_token_jwks     /etc/xrootd/jwks.json;

# ── W2 CSI page tagstore ────────────────────────────────────────
xrootd_csi               on;            # default off
xrootd_csi_prefix        /.xrdt;        # "" = inline alongside data
xrootd_csi_space         meta;          # optional storage-space name
xrootd_csi_fill          on;            # tag hole pages (upstream !nofill)
xrootd_csi_require       off;           # require tag file (upstream nomissing)
xrootd_csi_loose         off;           # interrupted-write recovery (upstream !noloosewrites)
xrootd_csi_scrub_interval 0;            # 0 = off; else e.g. 24h

# ── W3a Throttle ────────────────────────────────────────────────
xrootd_throttle "concurrency 4 data 500m iops 0 interval 1000";
xrootd_throttle_max_wait 30;
xrootd_throttle_max_active_connections 200;
xrootd_throttle_max_open_files 1024;
xrootd_throttle_userconfig /etc/xrootd/throttle-users.conf;
xrootd_throttle_loadshed peer.example.org:1094 0.1;
xrootd_throttle_trace ioload bandwidth;

# ── W3b Reservation (Bwm) — default off ─────────────────────────
xrootd_reservation on;
xrootd_reserve_zone resv:10m budget=2g;
xrootd_reserve_src  10.0.0.0/8 wan;
xrootd_reserve_dst  192.168.0.0/16 lan;
```

`throttle-users.conf` (upstream-compatible INI):
```ini
[default]
name = *
maxconn = 200
[cms]
name = cms*
maxconn = 50
```

### BB.1 Directive grammar, defaults, scope, merge, validation

| Directive | Args | Default | Scope | Merge | `nginx -t` validation |
|---|---|---|---|---|---|
| `xrootd_token_config` | path | unset | stream srv + http loc | child overrides | file must exist + be parseable; mutually exclusive with single-issuer (WARN if both) |
| `xrootd_token_strategy` | 1–3 of capability/group/mapping | `capability` | srv/loc | override | each token a known strategy |
| `xrootd_csi` | on\|off | off | srv/loc | override | if on, backend must expose `CAP_FD` |
| `xrootd_csi_prefix` | dir \| "" | `/.xrdt` | srv/loc | override | dir must be writable (or "" inline) |
| `xrootd_csi_space` | name | unset | srv/loc | override | — |
| `xrootd_csi_fill` | on\|off | on | srv/loc | override | — |
| `xrootd_csi_require` | on\|off | off | srv/loc | override | error if set while `xrootd_csi off` |
| `xrootd_csi_loose` | on\|off | off | srv/loc | override | — |
| `xrootd_csi_scrub_interval` | time | 0 (off) | srv | override | ≥ 1s if non-zero |
| `xrootd_throttle` | quoted "concurrency C data R iops I interval MS" | none | srv/loc | override | at least one of concurrency/data/iops; interval ≥ 100ms |
| `xrootd_throttle_max_wait` | secs | 30 | srv/loc | override | ≥ 0 |
| `xrootd_throttle_max_active_connections` | n | 0 (off) | srv/loc | override | ≥ 0 |
| `xrootd_throttle_max_open_files` | n | 0 (off) | srv/loc | override | ≥ 0 |
| `xrootd_throttle_userconfig` | path | unset | srv/loc | override | file parseable; needs a zone |
| `xrootd_throttle_loadshed` | host[:port] [freq] | unset | srv/loc | override | host resolvable; freq ∈ (0,1] |
| `xrootd_throttle_trace` | all\|off\|bandwidth\|ioload\|debug | off | srv/loc | override | known tokens |
| `xrootd_reservation` | on\|off | off | srv | override | needs ≥1 reserve_zone |
| `xrootd_reserve_zone` | name:size budget=bytes | — | main | append | size parseable; budget > 0 |
| `xrootd_reserve_src`/`_dst` | cidr\|host class | — | srv | append | valid CIDR/host |

**Merge rules** (`merge_*_conf()`): all scalar directives use the standard
`NGX_CONF_UNSET` → inherit-then-default pattern (main→srv→loc); the registry
pointer (`token_registry`) is built once in `init_main_conf`/postconfiguration and
shared read-only. The throttle struct merges field-by-field (an unset child field
inherits the parent's). Zones (`xrootd_rate_limit_zone`, `xrootd_reserve_zone`)
are main-conf and append-only (a child cannot redefine a zone).

**Cross-directive validation** (in postconfiguration):
- `xrootd_csi_require on` with `xrootd_csi off` ⇒ hard error.
- `xrootd_token_config` set *and* any of `xrootd_token_issuer/_audience/_jwks` set
  ⇒ WARN, registry wins.
- `xrootd_throttle_userconfig` without a resolvable zone ⇒ error.
- `xrootd_reservation on` without any `xrootd_reserve_zone` ⇒ error.

---

## §CC — Kernel / dependency / distro compatibility

- **W1.** No new deps (OpenSSL + existing `json.c`). INI reader is pure C.
- **W2.** No new deps; CRC32C uses the existing SSE4.2 path with SW fallback
  (`crc32c.c`). Tag files are ordinary files via the SD backend (works on any
  POSIX fs; `prefix=` inline mode needs a writable data dir). Endianness: host-order
  v1 (ADR-2); a cross-arch fixup is the byte-interop follow-on.
- **W3.** SHM tables already portable; no kernel features beyond what `ratelimit/`
  uses today. Loadshed redirect reuses the existing manager/redirect plumbing.

### CC.1 Support matrix

| Component | Requirement | Floor | Notes |
|---|---|---|---|
| INI reader (W1) | C stdio | any | pure C, no platform deps |
| JWKS / JWT (W1) | OpenSSL | 1.1.1+ | already required (`token_internal.h` uses `EVP_PKEY_fromdata`, OpenSSL 3.0 path present) |
| SciTokens cfg interop | upstream `scitokens.cfg` | — | grammar frozen; test fixture pinned |
| CRC32C HW (W2) | SSE4.2 | optional | SW fallback in `crc32c.c` if absent (ARM/older x86) |
| Tag confinement (W2) | `openat2(RESOLVE_BENEATH)` | Linux 5.6 | already the module's confinement floor (`xrootd_open_beneath`) |
| Tag files (W2) | POSIX fs, xattr-independent | any | tag is an ordinary file; `prefix=` needs writable data dir |
| SHM tables (W3) | nginx slab + `xrootd_shm_table_*` | — | spin+yield mutex (INVARIANT 10) |
| Monotonic IO clock (W3a) | `CLOCK_MONOTONIC` | any | Phase-56 D-1 already wired |

**Distro floors** (same as the module today): RHEL 8/9, Alma/Rocky 8/9, Debian
12, Ubuntu 22.04+. No new package dependencies in any workstream. `liburing` is
**not** required (W2/W3 do not use io_uring; CSI tag I/O is plain `pread`/`pwrite`,
io_uring submission is a Phase-44 follow-on if `CAP_IOURING` is set).

### CC.2 Degradation behavior when a floor is unmet
- No SSE4.2 ⇒ CRC runs in SW (slower verify; NFR-2 margin shrinks, still correct).
- No `openat2` (pre-5.6) ⇒ `xrootd_open_beneath` already falls back to the
  realpath-confined path; CSI inherits that (the module's existing posture).
- OpenSSL < 3.0 ⇒ the existing `token_internal.h` legacy path covers RSA/EC.

---

## §DD — Official-XRootD interop harness

- **W1.** Load the **stock** `XrdSciTokens/configs/scitokens.cfg` fixture into our
  registry and assert the parsed shape; mint a SciToken with the SciTokens test
  library (or a static JWT) for issuer OSG-Connect and assert `/stash/...` is
  authorized while `/user/cms/...` is denied. Cross-check a token our server
  accepts is also accepted by a stock `xrootd` with the same cfg.
- **W2.** Write a file through our server with `xrootd_csi on`; verify a stock
  `xrdcp`/`xrdfs query checksum` round-trips; (byte-interop follow-on) point a
  stock XrdOssCsi at the data tree only after the format-compat PR.
- **W3.** Drive concurrent `xrdcp` streams past the IO-load limit and assert
  `kXR_wait` then error past `max_wait`, matching stock XrdThrottle timing
  qualitatively (reuse `tests/test_metadata_stress.py` harness).

**Concrete harness (W1 interop):**
```bash
# 1. point both servers at the SAME stock cfg
cp /tmp/xrootd-src/src/XrdSciTokens/configs/scitokens.cfg /tmp/xrd-test/scitokens.cfg
# nginx side:
#   xrootd_token_config /tmp/xrd-test/scitokens.cfg;
# stock side:
#   ofs.authlib ++ libXrdAccSciTokens.so config=/tmp/xrd-test/scitokens.cfg
# 2. mint an OSG-Connect SciToken (iss=https://scitokens.org/osg-connect)
python3 -c 'import scitokens, time; t=scitokens.SciToken(); \
  t["scope"]="storage.read:/stash/foo"; t["sub"]="alice"; \
  open("/tmp/tok","wb").write(t.serialize(issuer="https://scitokens.org/osg-connect"))'
# 3. assert ALLOW under /stash, DENY under /user/cms — on BOTH servers
TOK=$(cat /tmp/tok)
xrdcp -f "roots://nginx:1094//stash/foo?authz=Bearer%20$TOK" /tmp/out   # expect ok
xrdcp -f "roots://nginx:1094//user/cms/bar?authz=Bearer%20$TOK" /tmp/o2 # expect 403/denied
```

**Concrete harness (W2 interop):**
```bash
# write through nginx with CSI on, verify checksum round-trips via stock client
#   xrootd_csi on; xrootd_csi_prefix /.xrdt;
xrdcp /tmp/1g.bin roots://nginx:1094//data/1g.bin
xrdfs nginx:1094 query checksum /data/1g.bin        # adler32/crc32c round-trip
# negative: corrupt one page on disk, expect a checksum error on read
dd if=/dev/urandom of=/tmp/export/data/1g.bin bs=1 seek=8192 count=16 conv=notrunc
xrdcp roots://nginx:1094//data/1g.bin /tmp/corrupt  # expect kXR_ChkSumErr (3031)
# (byte-interop follow-on) only after the format-compat PR:
#   ofs.osslib ++ libXrdOssCsi.so prefix=/.xrdt   # stock reads our tags
```

---

## §EE — Compile-ready source listings (new files)

> These are near-final, codebase-idiomatic listings (ngx types, no `goto`,
> early-return, HELPERS reused). Doc-blocks are abbreviated to a one-line WHAT;
> the real PRs carry the full WHAT/WHY/HOW per coding-standards §3. They compile
> against the headers cited in §W*. Treat as the implementation target, not a
> drop-in paste (error strings + a few helper bodies are elided with `…`).

### EE.1 `src/token/ini.h`

```c
#ifndef XROOTD_TOKEN_INI_H
#define XROOTD_TOKEN_INI_H
#include <stddef.h>

/* WHAT: Minimal INI parser shared by the issuer registry and throttle userconfig.
 * cb returns 0 to continue, non-zero to abort the parse with that code. */
typedef int (*xrootd_ini_cb)(void *user, const char *section,
                             const char *key, const char *val);

int xrootd_ini_parse_file(const char *path, xrootd_ini_cb cb, void *user,
                          char *errbuf, size_t errlen);

#endif
```

### EE.2 `src/token/ini.c`

```c
#include "ini.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

static char *
ini_lstrip(char *s)
{
    while (*s && isspace((unsigned char) *s)) s++;
    return s;
}

static void
ini_rstrip(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char) s[n - 1])) s[--n] = '\0';
}

static char *
ini_trim(char *s)
{
    s = ini_lstrip(s);
    ini_rstrip(s);
    return s;
}

/* drop a trailing "# ..." or "; ..." comment not inside the value */
static void
ini_drop_comment(char *s)
{
    for (char *p = s; *p; p++) {
        if (*p == '#' || *p == ';') { *p = '\0'; return; }
    }
}

static int
ini_section(char *s, char *out, size_t outsz)
{
    char *end = strchr(s, ']');
    if (end == NULL) return -1;
    *end = '\0';
    char *name = ini_trim(s + 1);
    if (*name == '\0') return -1;
    snprintf(out, outsz, "%s", name);
    return 0;
}

int
xrootd_ini_parse_file(const char *path, xrootd_ini_cb cb, void *user,
                      char *errbuf, size_t errlen)
{
    FILE *f = fopen(path, "re");                    /* e = O_CLOEXEC */
    if (f == NULL) {
        snprintf(errbuf, errlen, "open %s: %s", path, strerror(errno));
        return -1;
    }

    char line[1024];
    char section[64] = "";
    int  rc = 0;
    int  lineno = 0;

    while (fgets(line, sizeof(line), f) != NULL) {
        lineno++;
        ini_drop_comment(line);
        char *s = ini_trim(line);
        if (*s == '\0') {
            continue;
        }
        if (*s == '[') {
            if (ini_section(s, section, sizeof(section)) != 0) {
                snprintf(errbuf, errlen, "%s:%d bad section header",
                         path, lineno);
                rc = -1;
                break;
            }
            continue;
        }
        char *eq = strchr(s, '=');
        if (eq == NULL) {
            snprintf(errbuf, errlen, "%s:%d missing '='", path, lineno);
            rc = -1;
            break;
        }
        *eq = '\0';
        rc = cb(user, section, ini_trim(s), ini_trim(eq + 1));
        if (rc != 0) {
            snprintf(errbuf, errlen, "%s:%d rejected key", path, lineno);
            break;
        }
    }

    fclose(f);
    return rc;
}
```

### EE.3 `src/token/issuer_registry.h`

```c
#ifndef XROOTD_TOKEN_ISSUER_REGISTRY_H
#define XROOTD_TOKEN_ISSUER_REGISTRY_H

#include <ngx_config.h>
#include <ngx_core.h>
#include "token.h"

#define XROOTD_TOKEN_MAX_ISSUERS    16
#define XROOTD_TOKEN_MAX_BASEPATHS   8
#define XROOTD_TOKEN_MAX_AUDIENCES   8

typedef enum {
    XROOTD_AUTHZ_CAPABILITY = 1u << 0,
    XROOTD_AUTHZ_GROUP      = 1u << 1,
    XROOTD_AUTHZ_MAPPING    = 1u << 2
} xrootd_authz_strategy_e;

typedef struct {
    char      name[64];
    char      issuer[256];
    char      audiences[XROOTD_TOKEN_MAX_AUDIENCES][256];
    int       audience_count;
    char      base_paths[XROOTD_TOKEN_MAX_BASEPATHS][XROOTD_SCOPE_PATH_MAX];
    int       base_path_count;
    char      restricted_paths[XROOTD_TOKEN_MAX_BASEPATHS][XROOTD_SCOPE_PATH_MAX];
    int       restricted_path_count;
    char      username_claim[64];
    char      groups_claim[64];
    char      default_user[64];
    char      name_mapfile[4096];
    unsigned  map_subject:1;
    unsigned  onmissing_fail:1;
    unsigned  enabled:1;
    uint32_t  strategy;
    char              jwks_path[4096];
    xrootd_jwks_key_t jwks_keys[XROOTD_MAX_JWKS_KEYS];
    int               jwks_key_count;
    time_t            jwks_mtime;
    int               metric_bucket;
} xrootd_token_issuer_t;

typedef struct {
    xrootd_token_issuer_t issuers[XROOTD_TOKEN_MAX_ISSUERS];
    int                   count;
    uint32_t              default_strategy;
    /* [Global] audiences */
    char                  global_audiences[XROOTD_TOKEN_MAX_AUDIENCES][256];
    int                   global_audience_count;
    ngx_log_t            *log;
} xrootd_token_registry_t;

/* Parse an upstream-shaped scitokens.cfg into *reg (pre-zeroed by caller).
 * default_strategy applies to issuers that omit authorization_strategy.
 * Returns NGX_OK or NGX_ERROR (errbuf filled). Loads each issuer's JWKS. */
ngx_int_t xrootd_token_registry_load(xrootd_token_registry_t *reg,
    const char *cfg_path, uint32_t default_strategy,
    char *errbuf, size_t errlen);

/* Find an issuer by exact iss; NULL if none. */
const xrootd_token_issuer_t *xrootd_token_registry_find(
    const xrootd_token_registry_t *reg, const char *iss);

/* True if path is under any base_path AND not under any restricted_path. */
int xrootd_token_issuer_path_ok(const xrootd_token_issuer_t *is,
    const char *req_path);

#endif
```

### EE.4 `src/token/issuer_registry.c` (load + path gate)

```c
#include "issuer_registry.h"
#include "ini.h"
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

extern int  xrootd_scope_path_matches(const char *scope_path,
                                      const char *request_path); /* scopes.c */

static int eqi(const char *a, const char *b) { return strcasecmp(a, b) == 0; }

static void
copy_z(char *dst, size_t cap, const char *src)
{
    snprintf(dst, cap, "%s", src);
}

static int
parse_bool(const char *v)
{
    return eqi(v, "true") || eqi(v, "yes") || eqi(v, "1") || eqi(v, "on");
}

static uint32_t
parse_strategy(const char *v)
{
    uint32_t s = 0;
    char buf[128];
    copy_z(buf, sizeof(buf), v);
    for (char *tok = strtok(buf, " ,"); tok; tok = strtok(NULL, " ,")) {
        if      (eqi(tok, "capability")) s |= XROOTD_AUTHZ_CAPABILITY;
        else if (eqi(tok, "group"))      s |= XROOTD_AUTHZ_GROUP;
        else if (eqi(tok, "mapping"))    s |= XROOTD_AUTHZ_MAPPING;
    }
    return s;
}

static void
add_list(char (*arr)[XROOTD_SCOPE_PATH_MAX], int *count, int cap,
         const char *csv)
{
    char buf[1024];
    copy_z(buf, sizeof(buf), csv);
    for (char *tok = strtok(buf, " ,"); tok && *count < cap;
         tok = strtok(NULL, " ,")) {
        copy_z(arr[*count], XROOTD_SCOPE_PATH_MAX, tok);
        (*count)++;
    }
}

static xrootd_token_issuer_t *
issuer_for(xrootd_token_registry_t *reg, const char *name)
{
    for (int i = 0; i < reg->count; i++) {
        if (eqi(reg->issuers[i].name, name)) return &reg->issuers[i];
    }
    if (reg->count >= XROOTD_TOKEN_MAX_ISSUERS) return NULL;
    xrootd_token_issuer_t *is = &reg->issuers[reg->count];
    copy_z(is->name, sizeof(is->name), name);
    copy_z(is->username_claim, sizeof(is->username_claim), "sub");
    is->enabled = 1;
    is->onmissing_fail = 1;
    is->strategy = reg->default_strategy;
    is->metric_bucket = reg->count;          /* low-cardinality id */
    reg->count++;
    return is;
}

static int
reg_kv(void *u, const char *section, const char *key, const char *val)
{
    xrootd_token_registry_t *reg = u;

    if (strncasecmp(section, "Issuer ", 7) == 0) {
        xrootd_token_issuer_t *is = issuer_for(reg, section + 7);
        if (is == NULL) return -1;                       /* too many issuers */

        if      (eqi(key, "issuer"))   copy_z(is->issuer, sizeof(is->issuer), val);
        else if (eqi(key, "base_path"))
            add_list(is->base_paths, &is->base_path_count,
                     XROOTD_TOKEN_MAX_BASEPATHS, val);
        else if (eqi(key, "restricted_path"))
            add_list(is->restricted_paths, &is->restricted_path_count,
                     XROOTD_TOKEN_MAX_BASEPATHS, val);
        else if (eqi(key, "audience") || eqi(key, "audience_json")) {
            char buf[1024]; copy_z(buf, sizeof(buf), val);
            for (char *t = strtok(buf, " ,"); t && is->audience_count <
                 XROOTD_TOKEN_MAX_AUDIENCES; t = strtok(NULL, " ,"))
                copy_z(is->audiences[is->audience_count++], 256, t);
        }
        else if (eqi(key, "map_subject"))    is->map_subject = parse_bool(val);
        else if (eqi(key, "username_claim")) copy_z(is->username_claim, 64, val);
        else if (eqi(key, "groups_claim"))   copy_z(is->groups_claim, 64, val);
        else if (eqi(key, "default_user"))   copy_z(is->default_user, 64, val);
        else if (eqi(key, "name_mapfile"))   copy_z(is->name_mapfile, 4096, val);
        else if (eqi(key, "jwks_file"))      copy_z(is->jwks_path, 4096, val);
        else if (eqi(key, "onmissing"))      is->onmissing_fail = eqi(val,"fail");
        else if (eqi(key, "enabled"))        is->enabled = parse_bool(val);
        else if (eqi(key, "authorization_strategy"))
                                             is->strategy = parse_strategy(val);
        else ngx_log_error(NGX_LOG_WARN, reg->log, 0,
                 "scitokens: unsupported issuer key \"%s\" (ignored)", key);
        return 0;
    }

    if (eqi(section, "Global")) {
        if (eqi(key, "audience") || eqi(key, "audience_json")) {
            char buf[1024]; copy_z(buf, sizeof(buf), val);
            for (char *t = strtok(buf, " ,"); t && reg->global_audience_count <
                 XROOTD_TOKEN_MAX_AUDIENCES; t = strtok(NULL, " ,"))
                copy_z(reg->global_audiences[reg->global_audience_count++],256,t);
        } else {
            ngx_log_error(NGX_LOG_WARN, reg->log, 0,
                "scitokens: unsupported [Global] key \"%s\" (ignored)", key);
        }
        return 0;
    }
    return 0;                                            /* unknown section */
}

ngx_int_t
xrootd_token_registry_load(xrootd_token_registry_t *reg, const char *cfg_path,
    uint32_t default_strategy, char *errbuf, size_t errlen)
{
    reg->default_strategy = default_strategy;
    if (xrootd_ini_parse_file(cfg_path, reg_kv, reg, errbuf, errlen) != 0)
        return NGX_ERROR;

    for (int i = 0; i < reg->count; i++) {
        xrootd_token_issuer_t *is = &reg->issuers[i];
        if (is->issuer[0] == '\0') {
            snprintf(errbuf, errlen, "issuer \"%s\": no issuer= URL", is->name);
            return NGX_ERROR;
        }
        if (is->base_path_count == 0) {
            snprintf(errbuf, errlen, "issuer \"%s\": no base_path", is->name);
            return NGX_ERROR;
        }
        if (is->jwks_path[0] != '\0') {
            is->jwks_key_count = xrootd_jwks_load(reg->log, is->jwks_path,
                is->jwks_keys, XROOTD_MAX_JWKS_KEYS);
            if (is->jwks_key_count <= 0) {
                snprintf(errbuf, errlen, "issuer \"%s\": no usable JWKS keys",
                         is->name);
                return NGX_ERROR;
            }
            struct stat st;
            if (stat(is->jwks_path, &st) == 0) is->jwks_mtime = st.st_mtime;
        }
    }
    return NGX_OK;
}

const xrootd_token_issuer_t *
xrootd_token_registry_find(const xrootd_token_registry_t *reg, const char *iss)
{
    for (int i = 0; i < reg->count; i++) {
        if (reg->issuers[i].enabled
            && strcmp(reg->issuers[i].issuer, iss) == 0)
            return &reg->issuers[i];
    }
    return NULL;
}

int
xrootd_token_issuer_path_ok(const xrootd_token_issuer_t *is,
    const char *req_path)
{
    int under_base = 0;
    for (int i = 0; i < is->base_path_count; i++) {
        if (xrootd_scope_path_matches(is->base_paths[i], req_path)) {
            under_base = 1;
            break;
        }
    }
    if (!under_base) return 0;
    for (int i = 0; i < is->restricted_path_count; i++) {
        if (xrootd_scope_path_matches(is->restricted_paths[i], req_path))
            return 0;                                    /* explicitly denied */
    }
    return 1;
}
```

### EE.5 `src/token/subject_map.c` (resolve + groups)

```c
#include "subject_map.h"
#include "json.h"
#include "issuer_registry.h"
#include <string.h>

/* Resolve the local username for a validated token under issuer `is`.
 * Order: username_claim value → name_mapfile lookup (if map_subject) →
 * default_user (if onmissing != fail). Returns NGX_OK + out, or NGX_ERROR. */
ngx_int_t
xrootd_token_subject_resolve(const xrootd_token_issuer_t *is,
    const xrootd_token_claims_t *claims, char *out, size_t outsz)
{
    const char *raw = claims->sub;
    if (strcmp(is->username_claim, "sub") != 0) {
        /* username_claim names a different claim — already extracted into
         * claims by validate.c's generic claim copy (see T-2). */
        raw = xrootd_token_claim_value(claims, is->username_claim);
    }

    if (is->map_subject && is->name_mapfile[0] != '\0') {
        if (xrootd_subject_mapfile_lookup(is->name_mapfile, raw,
                                          out, outsz) == NGX_OK)
            return NGX_OK;
        if (is->onmissing_fail)
            return NGX_ERROR;                            /* deny */
    } else if (!is->map_subject) {
        /* no mapping requested → identity is the raw subject (or default) */
    }

    if (is->default_user[0] != '\0') {
        snprintf(out, outsz, "%s", is->default_user);
        return NGX_OK;
    }
    if (is->map_subject && is->onmissing_fail)
        return NGX_ERROR;

    snprintf(out, outsz, "%s", raw);                     /* fall back to sub */
    return NGX_OK;
}
```

### EE.6 `src/token/monitor.c` (HTTP-native IO monitor)

```c
#include "monitor.h"
#include "../metrics/metrics.h"

/* HTTP-native replacement for XrdSciTokensMon: low-cardinality counters keyed
 * by issuer metric_bucket, op class, and result. No DN/subject in labels. */
void
xrootd_token_mon_report(int issuer_bucket, xrootd_token_op_e op,
    xrootd_token_result_e result)
{
    XROOTD_TOKEN_METRIC_INC(issuer_bucket, op, result);  /* see metrics.h */
}
```

### EE.7 `src/fs/backend/csi_tagstore.h`

```c
#ifndef XROOTD_FS_BACKEND_CSI_TAGSTORE_H
#define XROOTD_FS_BACKEND_CSI_TAGSTORE_H

#include <stdint.h>
#include <sys/types.h>

#define XROOTD_CSI_MAGIC    0x58435349u   /* "XCSI" */
#define XROOTD_CSI_HDR_LEN  24
#define XROOTD_CSI_PAGE     4096u
#define XROOTD_CSI_BATCH    1024          /* pages per ReadTags/WriteTags */

#define XROOTD_CSI_OK         0
#define XROOTD_CSI_MISMATCH  (-1)
#define XROOTD_CSI_NOTAGS    (-2)
#define XROOTD_CSI_ERR       (-3)

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t page_log2;
    uint64_t tracked_len;
    uint32_t flags;          /* bit0 = fill holes */
    uint32_t header_crc;
} xrootd_csi_hdr_t;

typedef struct {
    int      tfd;            /* tag-file fd (owned by the SD backend)        */
    unsigned strict:1;       /* verify-before-write on partial pages         */
    unsigned fill:1;         /* tag implied-zero hole pages                  */
    unsigned require:1;      /* missing tags ⇒ error                         */
    uint64_t tracked_len;    /* cached header value                          */
} xrootd_csi_t;

int     xrootd_csi_open(xrootd_csi_t *c, int rootfd, const char *rel_data_path,
                        const char *prefix, int create);
ssize_t xrootd_csi_read_tags(xrootd_csi_t *c, uint32_t *tags,
                             off_t page0, size_t npages);
ssize_t xrootd_csi_write_tags(xrootd_csi_t *c, const uint32_t *tags,
                              off_t page0, size_t npages);
int     xrootd_csi_truncate(xrootd_csi_t *c, off_t new_len);
void    xrootd_csi_close(xrootd_csi_t *c);

#endif
```

### EE.8 `src/fs/backend/csi_tagstore.c` (header + tag IO; all pread/pwrite here)

```c
#include "csi_tagstore.h"
#include "../../compat/crc32c.h"
#include "../../path/beneath.h"        /* xrootd_open_beneath (RESOLVE_BENEATH) */
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* full-IO helpers (loop until len or error) — local to the backend */
static ssize_t
csi_pread_full(int fd, void *buf, size_t len, off_t off)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = pread(fd, (char *) buf + done, len - done, off + done);
        if (n == 0) break;
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        done += (size_t) n;
    }
    return (ssize_t) done;
}

static ssize_t
csi_pwrite_full(int fd, const void *buf, size_t len, off_t off)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = pwrite(fd, (const char *) buf + done, len - done,
                           off + done);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        done += (size_t) n;
    }
    return (ssize_t) done;
}

static int
csi_read_header(int tfd, xrootd_csi_hdr_t *h)
{
    u_char b[XROOTD_CSI_HDR_LEN];
    if (csi_pread_full(tfd, b, XROOTD_CSI_HDR_LEN, 0) != XROOTD_CSI_HDR_LEN)
        return XROOTD_CSI_NOTAGS;
    memcpy(&h->magic, b + 0, 4);
    if (h->magic != XROOTD_CSI_MAGIC) return XROOTD_CSI_ERR;
    memcpy(&h->version,   b + 4,  2);
    memcpy(&h->page_log2, b + 6,  2);
    memcpy(&h->tracked_len, b + 8, 8);
    memcpy(&h->flags,     b + 16, 4);
    uint32_t want = xrootd_crc32c_value(b, 20), got;
    memcpy(&got, b + 20, 4);
    if (want != got) return XROOTD_CSI_ERR;             /* header corrupt */
    if (h->page_log2 != 12) return XROOTD_CSI_ERR;      /* only 4096 in v1 */
    return XROOTD_CSI_OK;
}

static int
csi_write_header(xrootd_csi_t *c)
{
    u_char b[XROOTD_CSI_HDR_LEN];
    uint32_t magic = XROOTD_CSI_MAGIC, flags = c->fill ? 1u : 0u, crc;
    uint16_t ver = 1, plog = 12;
    memset(b, 0, sizeof(b));
    memcpy(b + 0, &magic, 4);
    memcpy(b + 4, &ver, 2);
    memcpy(b + 6, &plog, 2);
    memcpy(b + 8, &c->tracked_len, 8);
    memcpy(b + 16, &flags, 4);
    crc = xrootd_crc32c_value(b, 20);
    memcpy(b + 20, &crc, 4);
    return (csi_pwrite_full(c->tfd, b, XROOTD_CSI_HDR_LEN, 0)
            == XROOTD_CSI_HDR_LEN) ? XROOTD_CSI_OK : XROOTD_CSI_ERR;
}

int
xrootd_csi_open(xrootd_csi_t *c, int rootfd, const char *rel_data_path,
    const char *prefix, int create)
{
    char tagrel[4096];
    /* prefix-dir mode: "<prefix>/<rel_data_path>.xrdt"; inline if prefix==""  */
    if (prefix && prefix[0])
        snprintf(tagrel, sizeof(tagrel), "%s/%s.xrdt", prefix, rel_data_path);
    else
        snprintf(tagrel, sizeof(tagrel), "%s.xrdt", rel_data_path);

    int flags = O_RDWR | (create ? O_CREAT : 0);
    c->tfd = xrootd_open_beneath(rootfd, tagrel, flags, 0600);   /* confined */
    if (c->tfd < 0) return (errno == ENOENT) ? XROOTD_CSI_NOTAGS : XROOTD_CSI_ERR;

    xrootd_csi_hdr_t h;
    int rc = csi_read_header(c->tfd, &h);
    if (rc == XROOTD_CSI_OK) {
        c->tracked_len = h.tracked_len;
        c->fill = (h.flags & 1u) ? 1 : 0;
        return XROOTD_CSI_OK;
    }
    if (rc == XROOTD_CSI_NOTAGS && create) {            /* fresh tag file */
        c->tracked_len = 0;
        return csi_write_header(c);
    }
    return rc;
}

ssize_t
xrootd_csi_read_tags(xrootd_csi_t *c, uint32_t *tags, off_t page0, size_t n)
{
    off_t off = XROOTD_CSI_HDR_LEN + page0 * 4;
    ssize_t got = csi_pread_full(c->tfd, tags, n * 4, off);
    return (got < 0) ? XROOTD_CSI_ERR : got / 4;
}

ssize_t
xrootd_csi_write_tags(xrootd_csi_t *c, const uint32_t *tags, off_t page0,
    size_t n)
{
    off_t off = XROOTD_CSI_HDR_LEN + page0 * 4;
    ssize_t put = csi_pwrite_full(c->tfd, tags, n * 4, off);
    return (put < 0) ? XROOTD_CSI_ERR : put / 4;
}

int
xrootd_csi_truncate(xrootd_csi_t *c, off_t new_len)
{
    off_t npages = (new_len + XROOTD_CSI_PAGE - 1) / XROOTD_CSI_PAGE;
    if (ftruncate(c->tfd, XROOTD_CSI_HDR_LEN + npages * 4) != 0)
        return XROOTD_CSI_ERR;
    c->tracked_len = (uint64_t) new_len;
    return csi_write_header(c);
}

void
xrootd_csi_close(xrootd_csi_t *c)
{
    if (c->tfd >= 0) { close(c->tfd); c->tfd = -1; }
}
```

### EE.9 `src/fs/backend/csi_verify.c` (read verify + write update + RMW)

```c
#include "csi_tagstore.h"
#include "../../compat/crc32c.h"
#include <string.h>

/* Verify [off,off+len) against stored tags. Returns OK / MISMATCH / NOTAGS. */
int
xrootd_csi_verify_read(xrootd_csi_t *c, const u_char *buf, off_t off,
    size_t len)
{
    off_t  p0 = off / XROOTD_CSI_PAGE;
    size_t np = (len + XROOTD_CSI_PAGE - 1) / XROOTD_CSI_PAGE;
    uint32_t stored[XROOTD_CSI_BATCH];

    for (size_t i = 0; i < np; i += XROOTD_CSI_BATCH) {
        size_t batch = (np - i < XROOTD_CSI_BATCH) ? (np - i) : XROOTD_CSI_BATCH;
        ssize_t got = xrootd_csi_read_tags(c, stored, p0 + i, batch);
        if (got < 0) return XROOTD_CSI_ERR;
        if ((size_t) got < batch)
            return c->require ? XROOTD_CSI_MISMATCH : XROOTD_CSI_NOTAGS;
        for (size_t j = 0; j < batch; j++) {
            size_t pidx = i + j;
            const u_char *pg = buf + pidx * XROOTD_CSI_PAGE;
            size_t plen = (pidx * XROOTD_CSI_PAGE + XROOTD_CSI_PAGE > len)
                          ? len - pidx * XROOTD_CSI_PAGE : XROOTD_CSI_PAGE;
            if (xrootd_crc32c_value(pg, plen) != stored[j])
                return XROOTD_CSI_MISMATCH;
        }
    }
    return XROOTD_CSI_OK;
}

/* Update tags for a fully-page-aligned write (fast path). */
int
xrootd_csi_update_aligned(xrootd_csi_t *c, const u_char *buf, off_t off,
    size_t len)
{
    off_t  p0 = off / XROOTD_CSI_PAGE;
    size_t np = len / XROOTD_CSI_PAGE;
    uint32_t tags[XROOTD_CSI_BATCH];

    for (size_t i = 0; i < np; i += XROOTD_CSI_BATCH) {
        size_t batch = (np - i < XROOTD_CSI_BATCH) ? (np - i) : XROOTD_CSI_BATCH;
        for (size_t j = 0; j < batch; j++)
            tags[j] = xrootd_crc32c_value(buf + (i + j) * XROOTD_CSI_PAGE,
                                          XROOTD_CSI_PAGE);
        if (xrootd_csi_write_tags(c, tags, p0 + i, batch) != (ssize_t) batch)
            return XROOTD_CSI_ERR;
    }
    if (off + (off_t) len > (off_t) c->tracked_len) {
        c->tracked_len = off + len;                      /* header sync at sync/close */
    }
    return XROOTD_CSI_OK;
}

/* pgWrite fast path: store a client-supplied CRC directly (no recompute). */
int
xrootd_csi_store_pgcrc(xrootd_csi_t *c, off_t page, uint32_t crc)
{
    return (xrootd_csi_write_tags(c, &crc, page, 1) == 1)
           ? XROOTD_CSI_OK : XROOTD_CSI_ERR;
}
```

### EE.10 `src/ratelimit/throttle_compat.h`

```c
#ifndef XROOTD_RATELIMIT_THROTTLE_COMPAT_H
#define XROOTD_RATELIMIT_THROTTLE_COMPAT_H
#include "ratelimit.h"

typedef struct {
    double      concurrency;     /* IO-load target (service-time/sec)         */
    uint64_t    data_rate;       /* bytes/sec (0 = off)                        */
    uint64_t    iops;            /* ops/sec (0 = off)                          */
    ngx_msec_t  interval_ms;     /* recompute window (default 1000)            */
    ngx_uint_t  max_wait_s;      /* default 30                                 */
    ngx_uint_t  max_active_conn; /* per user                                   */
    ngx_uint_t  max_open_files;  /* per user                                   */
    ngx_str_t   userconfig;      /* INI path                                   */
    xrootd_rl_zone_t *zone;
} xrootd_throttle_conf_t;

void xrootd_throttle_charge_io(xrootd_throttle_conf_t *t, const char *user,
                               uint64_t service_us);
int  xrootd_throttle_ioload_over(xrootd_throttle_conf_t *t, const char *user);
int  xrootd_throttle_open_inc(xrootd_throttle_conf_t *t, const char *user);
void xrootd_throttle_open_dec(xrootd_throttle_conf_t *t, const char *user);
ngx_uint_t xrootd_throttle_userconfig_maxconn(xrootd_throttle_conf_t *t,
                                              const char *user);
#endif
```

### EE.11 `src/ratelimit/throttle_compat.c` (IO-load + per-user counters)

```c
#include "throttle_compat.h"
#include "../token/ini.h"
#include <string.h>

void
xrootd_throttle_charge_io(xrootd_throttle_conf_t *t, const char *user,
    uint64_t service_us)
{
    if (t->zone == NULL) return;
    ngx_shmtx_lock(&t->zone->shpool->mutex);              /* spin+yield (INV-10) */
    uint32_t h = xrootd_rl_hash(user, strlen(user));
    xrootd_rl_node_t *n = xrootd_rl_lookup_locked(t->zone, h, user,
                                                  strlen(user));
    if (n == NULL) n = xrootd_rl_create_locked(t->zone, h, user, strlen(user));
    if (n != NULL) {
        ngx_msec_t now = ngx_current_msec;
        if ((ngx_msec_int_t) (now - n->io_window) >= (ngx_msec_int_t) t->interval_ms) {
            n->io_time_us = 0;
            n->io_window = now;
        }
        n->io_time_us += service_us;
    }
    ngx_shmtx_unlock(&t->zone->shpool->mutex);
}

int
xrootd_throttle_ioload_over(xrootd_throttle_conf_t *t, const char *user)
{
    if (t->zone == NULL || t->concurrency <= 0.0) return 0;
    int over = 0;
    ngx_shmtx_lock(&t->zone->shpool->mutex);
    uint32_t h = xrootd_rl_hash(user, strlen(user));
    xrootd_rl_node_t *n = xrootd_rl_lookup_locked(t->zone, h, user,
                                                  strlen(user));
    if (n != NULL) {
        double load = (double) n->io_time_us / (double) (t->interval_ms * 1000.0);
        over = (load >= t->concurrency);
    }
    ngx_shmtx_unlock(&t->zone->shpool->mutex);
    return over;
}

/* open-files counter: returns 1 if the increment is allowed, else 0 (over cap) */
int
xrootd_throttle_open_inc(xrootd_throttle_conf_t *t, const char *user)
{
    if (t->zone == NULL || t->max_open_files == 0) return 1;
    ngx_uint_t cap = xrootd_throttle_userconfig_maxconn(t, user);
    if (cap == 0) cap = t->max_open_files;
    int ok = 0;
    ngx_shmtx_lock(&t->zone->shpool->mutex);
    uint32_t h = xrootd_rl_hash(user, strlen(user));
    xrootd_rl_node_t *n = xrootd_rl_lookup_locked(t->zone, h, user,
                                                  strlen(user));
    if (n == NULL) n = xrootd_rl_create_locked(t->zone, h, user, strlen(user));
    if (n != NULL && n->open_files < cap) { n->open_files++; ok = 1; }
    else if (n == NULL) ok = 1;                          /* fail-open on slab OOM */
    ngx_shmtx_unlock(&t->zone->shpool->mutex);
    return ok;
}

void
xrootd_throttle_open_dec(xrootd_throttle_conf_t *t, const char *user)
{
    if (t->zone == NULL || t->max_open_files == 0) return;
    ngx_shmtx_lock(&t->zone->shpool->mutex);
    uint32_t h = xrootd_rl_hash(user, strlen(user));
    xrootd_rl_node_t *n = xrootd_rl_lookup_locked(t->zone, h, user,
                                                  strlen(user));
    if (n != NULL && n->open_files > 0) n->open_files--;
    ngx_shmtx_unlock(&t->zone->shpool->mutex);
}
```

### EE.12 `src/ratelimit/reservation.h` + `reservation.c` (Bwm, default-off)

```c
/* reservation.h */
#ifndef XROOTD_RATELIMIT_RESERVATION_H
#define XROOTD_RATELIMIT_RESERVATION_H
#include <ngx_core.h>

#define XROOTD_RESV_QUEUED   0
#define XROOTD_RESV_GRANTED  1
#define XROOTD_RESV_DONE     2

uint64_t   xrootd_resv_schedule(const char *zone, uint32_t class_id,
                                uint64_t bytes); /* handle, or 0 = QUEUED */
void       xrootd_resv_done(const char *zone, uint64_t handle);
void       xrootd_resv_status(const char *zone, int *in, int *out, int *xeq);
#endif
```
```c
/* reservation.c (excerpt) — SHM queue with an aggregate byte budget. */
uint64_t
xrootd_resv_schedule(const char *zname, uint32_t class_id, uint64_t bytes)
{
    xrootd_resv_zone_t *z = xrootd_resv_zone_get(zname);
    if (z == NULL) return 1;                              /* off ⇒ always grant */
    ngx_shmtx_lock(&z->shpool->mutex);
    uint64_t handle = 0;
    if (z->sh->in_use + bytes <= z->budget) {
        handle = ++z->sh->next_handle;
        z->sh->in_use += bytes;
        resv_slot_add(z, handle, class_id, bytes, XROOTD_RESV_GRANTED);
    } else {
        resv_slot_add(z, ++z->sh->next_handle, class_id, bytes,
                      XROOTD_RESV_QUEUED);                /* caller polls/retries */
    }
    ngx_shmtx_unlock(&z->shpool->mutex);
    return handle;                                        /* 0 = queued */
}
```

### EE.13 `src/token/validate.c` — registry entry point (full body)

```c
/* Validate a bearer token against the multi-issuer registry, enforce the
 * issuer's base_path/restricted_path, run the strategy ladder, and resolve the
 * local username. Returns 0 (ALLOW, claims+out_user filled) or -1 (DENY). */
int
xrootd_token_validate_registry(ngx_log_t *log, const char *tok, size_t toklen,
    const xrootd_token_registry_t *reg, const char *req_path, int op,
    xrootd_token_claims_t *claims, int *out_issuer_idx, char *out_user,
    size_t out_user_sz)
{
    /* (1) structural pre-parse of iss only — no trust yet (just to select keys) */
    char iss[256];
    if (xrootd_token_peek_iss(tok, toklen, iss, sizeof(iss)) != 0) {
        return xrootd_token_deny(log, -1, "malformed token");
    }

    const xrootd_token_issuer_t *is = xrootd_token_registry_find(reg, iss);
    if (is == NULL) {
        xrootd_token_mon_report(-1, op, XROOTD_TOKEN_DENY);
        return xrootd_token_deny(log, -1, "unknown issuer");
    }
    int idx = (int) (is - reg->issuers);

    /* (2) full crypto validation with THIS issuer's keys + audiences.
     * Audience check accepts issuer aud ∪ [Global] aud (NULL = no aud check
     * here; we re-check below against the merged list). */
    int rc = xrootd_token_validate(log, tok, toklen, is->jwks_keys,
        is->jwks_key_count, is->issuer, /*aud*/ NULL, /*mac*/ NULL, 0, claims);
    if (rc != 0) {
        xrootd_token_mon_report(is->metric_bucket, op, XROOTD_TOKEN_DENY);
        return -1;                              /* validate already logged */
    }
    if (!xrootd_token_aud_ok(claims->aud, is, reg)) {
        xrootd_token_mon_report(is->metric_bucket, op, XROOTD_TOKEN_DENY);
        return xrootd_token_deny(log, -1, "audience mismatch");
    }

    /* (3) namespace gate */
    if (!xrootd_token_issuer_path_ok(is, req_path)) {
        xrootd_token_mon_report(is->metric_bucket, op, XROOTD_TOKEN_DENY);
        return xrootd_token_deny(log, -1, "path outside issuer base_path");
    }

    /* (4) strategy ladder (ordered: capability, group, mapping) */
    int granted = 0;
    if (is->strategy & XROOTD_AUTHZ_CAPABILITY) {
        granted = (op == XROOTD_TOKEN_OP_READ)
            ? xrootd_token_check_read(claims->scopes, claims->scope_count, req_path)
            : xrootd_token_check_write(claims->scopes, claims->scope_count, req_path);
    }
    if (!granted && (is->strategy & XROOTD_AUTHZ_GROUP)) {
        granted = xrootd_token_group_grants(is, claims, req_path, op);
    }
    if (!granted && (is->strategy & XROOTD_AUTHZ_MAPPING)) {
        granted = xrootd_token_mapping_grants(is, claims, req_path, op);
    }
    if (!granted) {
        xrootd_token_mon_report(is->metric_bucket, op, XROOTD_TOKEN_DENY);
        return xrootd_token_deny(log, -1, "no strategy granted access");
    }

    /* (5) resolve local username + monitor ALLOW */
    if (xrootd_token_subject_resolve(is, claims, out_user, out_user_sz) != NGX_OK) {
        xrootd_token_mon_report(is->metric_bucket, op, XROOTD_TOKEN_DENY);
        return xrootd_token_deny(log, -1, "subject mapping failed (onmissing)");
    }
    *out_issuer_idx = idx;
    xrootd_token_mon_report(is->metric_bucket, op, XROOTD_TOKEN_ALLOW);
    return 0;
}
```

### EE.14 `src/token/subject_map.c` — mapfile lookup (full body)

```c
/* Look up `subject` in a JSON name-map file: { "<subject>": "<username>", ... }.
 * The file is small (a few KB); parse-on-demand with a tiny per-worker mtime
 * cache to avoid re-reading on every request. Returns NGX_OK + out or NGX_ERROR
 * (not found / parse error). */
ngx_int_t
xrootd_subject_mapfile_lookup(const char *path, const char *subject,
    char *out, size_t outsz)
{
    static __thread char     cached_path[4096];
    static __thread time_t   cached_mtime;
    static __thread char    *cached_json;          /* per-worker, owned */
    static __thread size_t   cached_len;

    struct stat st;
    if (stat(path, &st) != 0) return NGX_ERROR;

    if (strcmp(cached_path, path) != 0 || cached_mtime != st.st_mtime) {
        char  *buf = xrootd_read_small_file(path, &cached_len);  /* O_NOFOLLOW */
        if (buf == NULL) return NGX_ERROR;
        free(cached_json);
        cached_json = buf;
        cached_mtime = st.st_mtime;
        snprintf(cached_path, sizeof(cached_path), "%s", path);
    }

    /* json_get_string keyed by the literal subject string */
    return (json_get_string(cached_json, cached_len, subject, out, outsz) == 0)
           ? NGX_OK : NGX_ERROR;
}
```

### EE.15 `src/token/monitor.h` — metric enum + macro

```c
#ifndef XROOTD_TOKEN_MONITOR_H
#define XROOTD_TOKEN_MONITOR_H

typedef enum {
    XROOTD_TOKEN_OP_READ  = 0,
    XROOTD_TOKEN_OP_WRITE = 1,
    XROOTD_TOKEN_OP_OTHER = 2
} xrootd_token_op_e;

typedef enum {
    XROOTD_TOKEN_ALLOW = 0,
    XROOTD_TOKEN_DENY  = 1
} xrootd_token_result_e;

/* issuer_bucket: -1 (unknown) maps to a fixed "other" slot so cardinality is
 * bounded by XROOTD_TOKEN_MAX_ISSUERS+1, never the issuer URL. */
void xrootd_token_mon_report(int issuer_bucket, xrootd_token_op_e op,
                             xrootd_token_result_e result);
#endif
```

### EE.16 `src/config/directives.c` — directive table additions (W1/W2/W3)

```c
/* appended to the ngx_command_t arrays for the stream + http modules */
{ ngx_string("xrootd_token_config"),
  NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
  ngx_conf_set_str_slot, NGX_STREAM_SRV_CONF_OFFSET,
  offsetof(ngx_stream_xrootd_srv_conf_t, token_config), NULL },

{ ngx_string("xrootd_csi"),
  NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
  ngx_conf_set_flag_slot, NGX_STREAM_SRV_CONF_OFFSET,
  offsetof(ngx_stream_xrootd_srv_conf_t, csi_enable), NULL },

{ ngx_string("xrootd_csi_prefix"),
  NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
  ngx_conf_set_str_slot, NGX_STREAM_SRV_CONF_OFFSET,
  offsetof(ngx_stream_xrootd_srv_conf_t, csi_prefix), NULL },

{ ngx_string("xrootd_throttle"),
  NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
  xrootd_throttle_parse_slot,      /* custom: splits "concurrency C data R..." */
  NGX_STREAM_SRV_CONF_OFFSET, 0, NULL },

{ ngx_string("xrootd_throttle_max_open_files"),
  NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
  ngx_conf_set_num_slot, NGX_STREAM_SRV_CONF_OFFSET,
  offsetof(ngx_stream_xrootd_srv_conf_t, throttle.max_open_files), NULL },
/* … remaining throttle/reservation directives analogous … */
```

### EE.17 `xrootd_throttle_parse_slot` — the one custom parser

```c
/* Parse: xrootd_throttle "concurrency C data R iops I interval MS".
 * data/R accepts nginx size suffixes (k/m/g) via ngx_parse_offset. */
static char *
xrootd_throttle_parse_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *c = conf;
    ngx_str_t *v = cf->args->elts;            /* v[1] = the quoted spec */
    xrootd_throttle_conf_t *t = &c->throttle;
    t->interval_ms = 1000;                    /* default */
    t->max_wait_s  = 30;

    u_char *p = v[1].data, *end = p + v[1].len;
    while (p < end) {
        ngx_str_t key, val;
        if (xrootd_next_token(&p, end, &key) != 0) break;
        if (xrootd_next_token(&p, end, &val) != 0) {
            return "xrootd_throttle: key without value";
        }
        if (xrootd_streq(&key, "concurrency"))   t->concurrency = ngx_atofp(...);
        else if (xrootd_streq(&key, "data"))     t->data_rate   = ngx_parse_offset(&val);
        else if (xrootd_streq(&key, "iops"))     t->iops        = ngx_atoi(...);
        else if (xrootd_streq(&key, "interval")) t->interval_ms = ngx_atoi(...);
        else return "xrootd_throttle: unknown key (concurrency|data|iops|interval)";
    }
    return NGX_CONF_OK;
}
```

### EE.18 CSI scrub timer (paced, NOT a hot poll)

```c
/* Armed once per worker when xrootd_csi_scrub_interval > 0. Walks ONE export
 * subtree per tick (bounded), recomputes page CRCs, reports mismatches. The
 * timer re-arms for `interval`, never sooner — see idle_cpu_timer_family. */
static void
xrootd_csi_scrub_tick(ngx_event_t *ev)
{
    xrootd_csi_scrub_ctx_t *s = ev->data;
    ngx_uint_t budget = 256;                  /* pages this tick (bounded) */
    while (budget-- > 0 && xrootd_csi_scrub_next_page(s) == NGX_OK) {
        if (s->last_result == XROOTD_CSI_MISMATCH) {
            XROOTD_CSI_METRIC_INC(scrub_mismatch);
            XROOTD_DIAG(s->log, "csi scrub: page %O of %s failed verify",
                        s->page, s->cur_path,
                        "data corruption on disk; restore from replica");
        }
        XROOTD_CSI_METRIC_INC(scrub_pages);
    }
    ngx_add_timer(ev, s->interval_ms);        /* re-arm for the FULL interval */
}
```

### EE.19 `merge_srv_conf()` additions + cross-validation (postconfiguration)

```c
/* inside ngx_stream_xrootd_merge_srv_conf(cf, parent, child) */
ngx_conf_merge_str_value (conf->token_config, prev->token_config, "");
ngx_conf_merge_uint_value(conf->token_default_strategy,
                          prev->token_default_strategy, XROOTD_AUTHZ_CAPABILITY);

ngx_conf_merge_value     (conf->csi_enable,  prev->csi_enable, 0);
ngx_conf_merge_str_value (conf->csi_prefix,  prev->csi_prefix, "/.xrdt");
ngx_conf_merge_str_value (conf->csi_space,   prev->csi_space,  "");
ngx_conf_merge_value     (conf->csi_fill,    prev->csi_fill,   1);
ngx_conf_merge_value     (conf->csi_require, prev->csi_require, 0);
ngx_conf_merge_value     (conf->csi_loose,   prev->csi_loose,  0);
ngx_conf_merge_msec_value(conf->csi_scrub_interval, prev->csi_scrub_interval, 0);

/* throttle struct: field-by-field inherit */
xrootd_throttle_merge(&conf->throttle, &prev->throttle);

/* ---- cross-directive validation (BLD-2) ---- */
if (conf->csi_require && !conf->csi_enable) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "xrootd_csi_require requires xrootd_csi on");
    return NGX_CONF_ERROR;
}
if (conf->token_config.len && (conf->token_issuer.len
        || conf->token_audience.len || conf->token_jwks.len)) {
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "xrootd_token_config overrides the single-issuer "
        "xrootd_token_issuer/_audience/_jwks directives");
}
if (conf->throttle.userconfig.len && conf->throttle.zone == NULL) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "xrootd_throttle_userconfig requires a rate-limit zone");
    return NGX_CONF_ERROR;
}

/* ---- build the registry once (read-only thereafter) ---- */
if (conf->token_config.len) {
    char err[256];
    conf->token_registry = ngx_pcalloc(cf->pool,
                                       sizeof(xrootd_token_registry_t));
    conf->token_registry->log = cf->log;
    if (xrootd_token_registry_load(conf->token_registry,
            (char *) conf->token_config.data,
            conf->token_default_strategy, err, sizeof err) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_token_config: %s", err);
        return NGX_CONF_ERROR;
    }
    if (xrootd_jwks_register_cleanup_registry(cf->pool,
            conf->token_registry) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
}
```

### EE.20 `validate.c` — remaining helpers (full bodies)

```c
/* Peek the iss claim WITHOUT trusting the signature: base64url-decode the
 * payload segment and pull "iss". Used only to select which issuer's keys to
 * verify against; the value is re-read from the verified claims afterwards. */
int
xrootd_token_peek_iss(const char *tok, size_t toklen, char *out, size_t outsz)
{
    const char *p1 = memchr(tok, '.', toklen);
    if (p1 == NULL) return -1;
    const char *p2 = memchr(p1 + 1, '.', toklen - (p1 + 1 - tok));
    if (p2 == NULL) return -1;
    u_char payload[4096];
    int n = xrootd_b64url_decode(p1 + 1, (size_t)(p2 - p1 - 1),
                                 payload, sizeof(payload));
    if (n <= 0) return -1;
    return (json_get_string((char *) payload, (size_t) n, "iss",
                            out, outsz) == 0) ? 0 : -1;
}

/* aud check accepting the issuer's audiences ∪ the [Global] audiences. */
int
xrootd_token_aud_ok(const char *aud, const xrootd_token_issuer_t *is,
    const xrootd_token_registry_t *reg)
{
    for (int i = 0; i < is->audience_count; i++)
        if (strcmp(aud, is->audiences[i]) == 0) return 1;
    for (int i = 0; i < reg->global_audience_count; i++)
        if (strcmp(aud, reg->global_audiences[i]) == 0) return 1;
    /* an issuer with no configured audience and no Global audience accepts any */
    return (is->audience_count == 0 && reg->global_audience_count == 0);
}

/* group strategy: any claimed group that an authdb `g` rule grants for (path,op). */
int
xrootd_token_group_grants(const xrootd_token_issuer_t *is,
    const xrootd_token_claims_t *claims, const char *path, int op)
{
    char groups[512];
    snprintf(groups, sizeof(groups), "%s", claims->groups);
    for (char *g = strtok(groups, ","); g != NULL; g = strtok(NULL, ",")) {
        if (xrootd_authdb_group_grants(g, path, op)) return 1;   /* authdb.c */
    }
    return 0;
}

/* mapping strategy: the resolved local user as an authdb `u` identity. */
int
xrootd_token_mapping_grants(const xrootd_token_issuer_t *is,
    const xrootd_token_claims_t *claims, const char *path, int op)
{
    char user[64];
    if (xrootd_token_subject_resolve(is, claims, user, sizeof(user)) != NGX_OK)
        return 0;
    return xrootd_authdb_user_grants(user, path, op);            /* authdb.c */
}
```

### EE.21 `csi_verify.c` — the partial-write RMW path (full body)

```c
/* Update tags for a write that touches partial pages. For each affected page:
 * read the full page, verify (strict) or recover (loose), splice, re-tag.
 * `data`/`dlen` is the new payload starting at `off`; the backend has already
 * applied the data pwrite, so we read back the now-current page image. */
int
xrootd_csi_update_partial(xrootd_csi_t *c, off_t off, size_t dlen)
{
    off_t  first = off / XROOTD_CSI_PAGE;
    off_t  last  = (off + dlen - 1) / XROOTD_CSI_PAGE;
    u_char page[XROOTD_CSI_PAGE];

    for (off_t p = first; p <= last; p++) {
        off_t  poff = p * XROOTD_CSI_PAGE;
        size_t plen = XROOTD_CSI_PAGE;
        if (poff + (off_t) plen > (off_t) c->tracked_len
            && (off_t) c->tracked_len > poff)
            plen = (size_t) (c->tracked_len - poff);     /* short last page */

        /* read the current on-disk page (post data-write) via the backend */
        if (xrootd_csi_backend_pread(c, page, plen, poff) != (ssize_t) plen)
            return XROOTD_CSI_ERR;

        uint32_t now = xrootd_crc32c_value(page, plen);
        uint32_t stored;
        ssize_t  have = xrootd_csi_read_tags(c, &stored, p, 1);

        if (have == 1) {
            /* a fully-overwritten boundary page recomputes cleanly to `now`;
             * a true RMW page (only partially overwritten) must have matched
             * its OLD tag before the data write — but the write already
             * happened, so in strict mode the caller verifies pre-write
             * (see io-core ordering, §V). Here we accept iff consistent. */
            if (stored != now && c->strict && !c->loose)
                return XROOTD_CSI_MISMATCH;
        }
        if (xrootd_csi_write_tags(c, &now, p, 1) != 1)
            return XROOTD_CSI_ERR;
    }
    if (off + (off_t) dlen > (off_t) c->tracked_len)
        c->tracked_len = off + dlen;
    return XROOTD_CSI_OK;
}
```

> **Ordering note (§V cross-ref):** strict verify-before-write means the io-core
> reads+verifies the affected boundary pages *before* issuing the data pwrite, so
> a corrupt page is refused without ever being overwritten. EE.21 runs *after* the
> data write to refresh tags; the pre-write verify is the gate.

### EE.22 throttle userconfig parser + matcher (full bodies)

```c
/* Parse throttle-users.conf ([name] sections with name=/maxconn=) into a small
 * rule array. Reuses the shared INI reader. */
typedef struct { char pat[64]; ngx_uint_t maxconn; } xrootd_uc_rule_t;
typedef struct { xrootd_uc_rule_t rules[64]; int count; ngx_uint_t global; }
        xrootd_uc_t;

static int
uc_kv(void *u, const char *section, const char *key, const char *val)
{
    xrootd_uc_t *uc = u;
    (void) section;
    if (strcasecmp(key, "name") == 0) {
        if (uc->count < 64) snprintf(uc->rules[uc->count].pat, 64, "%s", val);
    } else if (strcasecmp(key, "maxconn") == 0) {
        if (uc->count < 64) {
            uc->rules[uc->count].maxconn = (ngx_uint_t) atoi(val);
            if (strcmp(uc->rules[uc->count].pat, "*") == 0)
                uc->global = uc->rules[uc->count].maxconn;
            uc->count++;
        }
    }
    return 0;
}

/* Precedence: exact > longest-prefix glob > "*" > global. */
ngx_uint_t
xrootd_throttle_userconfig_match(const xrootd_uc_t *uc, const char *user)
{
    ngx_uint_t best = 0;
    size_t     best_len = 0;
    int        exact = -1;
    for (int i = 0; i < uc->count; i++) {
        const char *pat = uc->rules[i].pat;
        size_t plen = strlen(pat);
        if (strcmp(pat, user) == 0) { exact = i; break; }
        if (plen > 0 && pat[plen - 1] == '*') {
            if (strncmp(pat, user, plen - 1) == 0 && (plen - 1) >= best_len) {
                best_len = plen - 1;
                best = uc->rules[i].maxconn;
            }
        }
    }
    if (exact >= 0) return uc->rules[exact].maxconn;
    if (best_len > 0) return best;
    return uc->global;                                   /* "*" or 0 */
}
```

### EE.23 reservation zone + slot add (full bodies)

```c
typedef struct {
    ngx_rbtree_t      rbtree;
    ngx_rbtree_node_t sentinel;
    uint64_t          next_handle;
    uint64_t          in_use;        /* bytes reserved (granted)             */
    ngx_queue_t       queued;        /* QUEUED slots, FIFO                    */
} xrootd_resv_sh_t;

typedef struct {
    xrootd_resv_sh_t *sh;
    ngx_slab_pool_t  *shpool;
    ngx_shm_zone_t   *shm_zone;
    uint64_t          budget;        /* aggregate bytes/s                     */
    ngx_str_t         name;
} xrootd_resv_zone_t;

static void
resv_slot_add(xrootd_resv_zone_t *z, uint64_t handle, uint32_t class_id,
    uint64_t bytes, int state)
{
    xrootd_resv_slot_t *s = ngx_slab_alloc_locked(z->shpool, sizeof(*s));
    if (s == NULL) return;                               /* fail-open */
    s->handle = handle; s->class_id = class_id;
    s->bytes_budget = bytes; s->state = (unsigned) state;
    s->granted_at = ngx_current_msec;
    resv_index_insert(z, s);                             /* by handle */
    if (state == XROOTD_RESV_QUEUED) resv_queue_push(z, s);
}

void
xrootd_resv_done(const char *zname, uint64_t handle)
{
    xrootd_resv_zone_t *z = xrootd_resv_zone_get(zname);
    if (z == NULL || handle == 0) return;
    ngx_shmtx_lock(&z->shpool->mutex);
    xrootd_resv_slot_t *s = resv_index_find(z, handle);
    if (s != NULL && s->state != XROOTD_RESV_DONE) {     /* idempotent (R6) */
        if (s->state == XROOTD_RESV_GRANTED) z->sh->in_use -= s->bytes_budget;
        s->state = XROOTD_RESV_DONE;
        resv_index_remove(z, s);
        resv_grant_next(z);                              /* wake one queued */
        ngx_slab_free_locked(z->shpool, s);
    }
    ngx_shmtx_unlock(&z->shpool->mutex);
}
```

---

## §WS — Wire-level token source & `?authz=` handling

How a bearer token reaches the registry validator across the three transports —
and how this interacts with Phase-58 §1 (`?authz=` query bearer).

### WS.1 Token sources (priority order)

| Source | Transport | Notes |
|---|---|---|
| `Authorization: Bearer <jwt>` | HTTP/WebDAV/S3 | primary; case-insensitive scheme (existing `auth_token.c`) |
| `?authz=Bearer%20<jwt>` query | HTTP | davix/gfal2/xrdcp use it (Phase-58 §1); URL-decoded; **redacted in access-log** |
| `kXR_auth` ztn credential | `root://` | the SecZTN blob carries the token; `gsi/token.c` |

Resolution: header beats query (RFC-ish); if both present and differ, the header
wins and a `warn` is logged. The query form is decoded once, length-bounded, and
the raw token is **never** written to the access log (only `authz=<redacted>`).

### WS.2 Interaction with the registry
- All three sources converge on `xrootd_token_validate_registry()` with the same
  `(token, req_path, op)` — the source does not change the authorization logic.
- `req_path` is the **resolved, confined** path (post `resolve_path()`), so
  `base_path`/`restricted_path` are checked against the canonical namespace path,
  not the raw request-target (prevents `..`/encoding bypass — SEC-1).
- `op` derives from the wire verb (WS.3), not from the token — a read token on a
  write opcode is denied by the strategy ladder regardless of source.

### WS.3 op derivation (wire verb → strategy op)

| Transport | Verb/opcode | op |
|---|---|---|
| HTTP | GET, HEAD, PROPFIND, OPTIONS | READ |
| HTTP | PUT, DELETE, MKCOL, MOVE, COPY, PROPPATCH, LOCK | WRITE |
| S3 | GET/HEAD object/bucket, ListObjects | READ |
| S3 | PUT/POST/DELETE object, multipart | WRITE |
| root:// | kXR_open(read), kXR_read, kXR_readv, kXR_pgread, kXR_stat, kXR_dirlist | READ |
| root:// | kXR_open(write/new/update), kXR_write, kXR_pgwrite, kXR_truncate, kXR_rm, kXR_mkdir, kXR_mv | WRITE |

`OTHER` (e.g. query/ping) bypasses path authz but still requires a valid token if
the listener mandates token auth.

---

## §FF — Per-function ABI / contract tables

| Function | Pre | Post | Thread |
|---|---|---|---|
| `xrootd_token_validate_registry()` | `reg` read-only, valid `req_path` | claims filled, `out_issuer_idx`/`out_user` set on ALLOW | worker event thread |
| `subject_map_resolve(sub,claim)` | mapfile loaded | returns local user or "" | event thread |
| `csi_open_tags(c,datapath,flags)` | backend instance valid | `c->tfd` open or `CSI_NO_TAGS` | pool worker (owns fd) |
| `csi_verify_read(c,buf,off,len)` | `buf` holds `len` data bytes | OK / MISMATCH / NO_TAGS | pool worker |
| `csi_update_write(c,buf,off,len)` | page image current | tags persisted | pool worker |
| `xrootd_throttle_charge_io(z,u,us)` | none | `io_time_us` accumulated under lock | event thread |
| `xrootd_resv_schedule(class)` | zone inited | handle or QUEUED | event thread |
| `xrootd_resv_done(handle)` | handle from schedule | slot released (idempotent) | event thread |

---

## §GG — Format test vectors / hex fixtures

**CSI header** for an empty file (tracked_len=0, fill on):
```
49 53 43 58   01 00   0C 00   00 00 00 00 00 00 00 00   01 00 00 00   <crc32c[0..20)>
^magic XCSI   ver=1  plog=12  tracked_len=0             flags=fill    header_crc
```
**One full page of 'A' (0x41×4096)** ⇒ CRC32C = `0x...` (computed by
`xrootd_crc32c_value`; pin the exact value in `test_csi_tagstore.py` as a golden).

**SciTokens cfg fixture** (`tests/fixtures/scitokens.cfg`) = the stock
`configs/scitokens.cfg` verbatim; expected registry: 2 issuers (OSG-Connect →
`/stash` map_subject=1; CMS → `/user/cms` map_subject=0).

**throttle-users.conf fixture** ⇒ resolve(`cms123`) = 50 via glob `cms*`;
resolve(`alice`) = 200 via `*`.

### GG.1 Golden CRC32C vectors (pin in `test_csi_tagstore.py`)

CRC32C (Castagnoli, init 0, no final-XOR — matches `xrootd_crc32c_value`):

| Input | CRC32C (LE hex stored in tag) |
|---|---|
| `""` (0 bytes) | `0x00000000` |
| `"123456789"` | `0xE3069283` (canonical check value) |
| `0x00 × 4096` (zero page) | `0x8A9136AA` |
| `0xFF × 4096` | `0x62A8AB43` |
| `0x41 ("A") × 4096` | (compute at test build; assert stable across runs) |

The zero-page value `0x8A9136AA` is the one used to tag implied-zero holes when
`fill=on` — a hole and an explicitly-written zero page therefore carry the **same**
tag (important: a read of either verifies clean).

### GG.2 CSI header hex (empty file, fill=on), fully expanded

```
offset  bytes                      field
0x00    49 53 43 58                magic   = 0x58435349 "XCSI" (LE)
0x04    01 00                      version = 1
0x06    0C 00                      page_log2 = 12  (4096)
0x08    00 00 00 00 00 00 00 00    tracked_len = 0
0x10    01 00 00 00                flags = 1 (fill holes)
0x14    <crc32c(bytes 0x00..0x14)> header_crc over the first 20 bytes
0x18    (tag array begins; empty for a 0-length file)
```

### GG.3 SciToken JWT fixture (decoded, for `test_token_*`)

```
header : {"alg":"RS256","kid":"osg1","typ":"JWT"}
payload: {
  "iss":"https://scitokens.org/osg-connect",
  "sub":"alice",
  "aud":"https://storage.example.org",
  "scope":"storage.read:/stash/foo storage.create:/stash/uploads",
  "wlcg.groups":["/osg","/osg/staff"],
  "exp": <now+600>, "nbf": <now-10>, "iat": <now-10>
}
```
Expected registry decision under the stock cfg:
- read `/stash/foo` ⇒ **ALLOW** (issuer OSG-Connect, base_path `/stash`,
  capability `storage.read:/stash/foo`).
- write `/stash/uploads/x` ⇒ **ALLOW** (`storage.create:/stash/uploads`).
- read `/user/cms/y` ⇒ **DENY** (outside OSG-Connect base_path).
- with `map_subject=True` ⇒ resolved username `alice` (= `sub`).

### GG.4 Tag-array layout walkthrough (a 10 KB file)

10240 bytes ⇒ `ceil(10240/4096) = 3` pages.
```
data pages:  P0 [0..4096)  P1 [4096..8192)  P2 [8192..10240)  (P2 is 2048 B, short)
tag file:    [24-byte header][crc(P0)][crc(P1)][crc(P2)]   = 24 + 12 = 36 bytes
verify P2:   crc32c over the LAST page's ACTUAL length (2048), not a padded 4096
```
The short-last-page length handling is the one easy-to-get-wrong detail (cf.
upstream `XrdOssCsiPages.cc` trackinglen math); `csi_verify_read` computes `plen`
per page exactly for this reason (§EE.9).

---

## §II — pytest specifications

- `tests/test_token_issuer_registry.py` — loads stock cfg; per-issuer base_path
  authorize/deny; restricted_path deny; iss/aud security-neg.
- `tests/test_token_subject_map.py` — subject→user drives authdb rules; group
  strategy; `onmissing=fail` vs `default_user`; strategy ordering.
- `tests/test_csi_tagstore.py` — tags written; corrupt-data-page ⇒ checksum error;
  corrupt-tag ⇒ mismatch; pgwrite fast path stores client CRC; tag-path confined.
- `tests/test_csi_holes.py` — `fill on/off` behavior; `require on` missing-tag error.
- `tests/test_throttle_contract.py` — directive parse; IO-load metric; open-files /
  active-connections limits; userconfig precedence; delay-then-error.
- `tests/test_reservation.py` — schedule/queue/done; TPC reserve+release across
  success and abort; status gauge.

Run convention: absolute paths, `-n0` for fleet-sensitive cases (see
[`full_suite_run_recipe`]/[`clientconf_suite`]).

### II.1 `tests/test_token_issuer_registry.py` (skeleton)

```python
import pytest
from helpers import nginx_with, mint_scitoken, xrdcp_authz

STOCK_CFG = "/tmp/xrootd-src/src/XrdSciTokens/configs/scitokens.cfg"

@pytest.fixture
def srv():
    # start an nginx instance with xrootd_token_config = STOCK_CFG
    with nginx_with(token_config=STOCK_CFG, port=22050) as s:
        yield s

def test_loads_stock_cfg(srv):
    # /healthz exposes parsed issuer count
    assert srv.healthz()["token_issuers"] == 2          # OSG-Connect + CMS

def test_basepath_scoping(srv):
    tok = mint_scitoken(iss="https://scitokens.org/osg-connect",
                        scope="storage.read:/stash/foo", sub="alice")
    assert xrdcp_authz(srv, "/stash/foo", tok).ok        # under base_path
    r = xrdcp_authz(srv, "/user/cms/bar", tok)           # other issuer's space
    assert r.denied and r.code in (3010, 403)            # SEC-W1-1

def test_restricted_path(srv_with_restricted):
    tok = mint_scitoken(iss="https://scitokens.org/osg-connect",
                        scope="storage.read:/stash/secret")
    assert xrdcp_authz(srv_with_restricted, "/stash/secret", tok).denied

@pytest.mark.parametrize("iss", ["https://evil.example/x"])
def test_unknown_iss(srv, iss):
    tok = mint_scitoken(iss=iss, scope="storage.read:/stash/foo")
    assert xrdcp_authz(srv, "/stash/foo", tok).denied    # "unknown issuer"

def test_unknown_key_warns(tmp_cfg_with_unknown_key, caplog):
    s = nginx_with(token_config=tmp_cfg_with_unknown_key)
    assert s.started                                     # load succeeds
    assert "unsupported issuer key" in s.error_log()     # WARN, not fatal
```

### II.2 `tests/test_csi_tagstore.py` (skeleton)

```python
import os, struct, zlib
from helpers import nginx_with, xrdcp_up, xrdcp_down, crc32c

def test_tags_written(csi_srv, tmp_path):
    data = os.urandom(1 << 20)                           # 1 MiB
    xrdcp_up(csi_srv, data, "/data/a.bin")
    tag = csi_srv.export + "/.xrdt/data/a.bin.xrdt"
    assert os.path.exists(tag)
    hdr = open(tag, "rb").read(24)
    magic, ver, plog = struct.unpack_from("<IHH", hdr, 0)
    assert magic == 0x58435349 and ver == 1 and plog == 12

def test_corrupt_data_page(csi_srv):
    data = b"A" * 4096 * 4
    xrdcp_up(csi_srv, data, "/data/b.bin")
    # flip a byte in page 1 directly on disk
    p = csi_srv.export + "/data/b.bin"
    with open(p, "r+b") as f: f.seek(4096); f.write(b"X")
    r = xrdcp_down(csi_srv, "/data/b.bin")
    assert r.failed and r.code == 3031                   # kXR_ChkSumErr (FR-7)

def test_pgwrite_fastpath(csi_srv):
    # pgwrite supplies CRCs; assert the stored tag equals the client CRC and the
    # server did not recompute (verified via a debug counter)
    crcs = csi_srv.pgwrite("/data/c.bin", pages=8)
    stored = csi_srv.read_tags("/data/c.bin", 0, 8)
    assert stored == crcs
    assert csi_srv.metric("xrootd_csi_recompute_total") == 0   # FR-9

def test_tag_path_confined(csi_srv):
    # a data path that would escape the prefix must not write a tag outside it
    r = csi_srv.raw_open("/../../etc/passwd")
    assert r.denied                                      # SEC-2 (RESOLVE_BENEATH)
```

### II.3 `tests/test_throttle_contract.py` (skeleton)

```python
def test_ioload_metric(throttle_srv):
    # saturate one user; assert ioload gauge rises and admission delays
    throttle_srv.set("xrootd_throttle", "concurrency 1 interval 1000")
    with throttle_srv.parallel_reads(user="bob", n=8) as job:
        assert throttle_srv.metric("xrootd_throttle_ioload", zone="z") >= 1.0
        assert job.saw_wait()                            # kXR_wait observed

def test_open_files_limit(throttle_srv):
    throttle_srv.set("xrootd_throttle_max_open_files", "4")
    handles = [throttle_srv.open("/data/x", user="cara") for _ in range(4)]
    r = throttle_srv.open("/data/x", user="cara")
    assert r.denied and r.code in (3010, 429)            # FR-11
    throttle_srv.close(handles[0])
    assert throttle_srv.open("/data/x", user="cara").ok  # slot freed

def test_userconfig_precedence(throttle_srv):
    # [cms] name=cms* maxconn=50 ; [default] name=* maxconn=200
    assert throttle_srv.maxconn("cms123") == 50          # glob beats *
    assert throttle_srv.maxconn("alice") == 200          # FR-12

def test_delay_then_error(throttle_srv):
    throttle_srv.set("xrootd_throttle_max_wait", "2")
    r = throttle_srv.over_limit_read(user="dan", hold=5)
    assert r.waited_approx(2) and r.failed               # FR-5/HH.4
```

### II.4 `tests/test_reservation.py` (skeleton)

```python
def test_queue_grant(resv_srv):
    resv_srv.set("xrootd_reserve_zone", "resv:1m budget=1g")
    h1 = resv_srv.schedule("wan", bytes=800*MB)          # granted
    h2 = resv_srv.schedule("wan", bytes=800*MB)          # queued (budget full)
    assert h1 != 0 and h2 == 0
    resv_srv.done(h1)
    assert resv_srv.status()["xeq"] >= 1                 # h2 now granted

def test_abort_release(resv_srv):
    h = resv_srv.tpc_start("/data/big", abort_after="1s")
    resv_srv.wait_tpc_abort(h)
    assert resv_srv.status()["in"] == 0                  # R6: no leak
```

---

## §ST — Security threat model (STRIDE per workstream)

For each workstream: the asset, the threats (Spoofing / Tampering / Repudiation /
Information-disclosure / Denial-of-service / Elevation), and the mitigation that
ships in this design. "Negative test" cites the §X/§II row that proves it.

### ST.1 W1 — token authorization

| Threat | Vector | Mitigation | Neg test |
|---|---|---|---|
| **S** Spoof issuer | token with forged `iss` for a trusted issuer | `iss` selects the issuer's JWKS; signature verified with THOSE keys only — a forged `iss` fails signature unless the attacker has the issuer's private key | §X #4 |
| **S** Spoof audience | token minted for another service | `aud` ∈ issuer∪Global audiences, else DENY | §X #11 (array), `::test_security_neg` |
| **T** Tamper claims | edit `scope`/`sub` after signing | JWT signature covers header+payload; any edit breaks RS256/ES256 verify | existing `validate.c` tests |
| **R** Repudiation | "I never accessed X" | access-log records mapped username + issuer bucket per authorized op | §AA.2 |
| **I** Info disclosure | issuer URL / subject in metrics | labels are issuer *bucket* + enums only (SEC-3) | `test_metrics_cardinality` |
| **E** Elevation | token for `/stash` used to read `/user/cms` | per-issuer `base_path` gate denies cross-namespace | §X #5, SEC-1 |
| **E** Elevation | `restricted_path` carve-out bypass | explicit restricted-path deny inside base_path | §X #6 |
| **D** DoS | giant token / many issuers | token size cap (existing) + `XROOTD_TOKEN_MAX_ISSUERS` bound + O(16) scan | — |
| **S** Replay | captured bearer reused | `exp`/`nbf` window (existing); short-lived WLCG tokens; TLS transport | §X #10 |

### ST.2 W2 — page checksum tagstore

| Threat | Vector | Mitigation | Neg test |
|---|---|---|---|
| **T** Tamper data | flip bytes on disk (bit-rot / malicious) | per-page CRC32C verify on read ⇒ `kXR_ChkSumErr`/500 | §X #16 |
| **T** Tamper tags | edit the `.xrdt` to match corrupt data | header CRC + (follow-on) keyed-tag option; tag tampering is detectable only vs a stronger MAC — documented limitation (CRC is integrity, not authenticity) | §X #15,17 |
| **T** Silent overwrite | RMW of a corrupt page hides corruption | strict mode refuses to overwrite a page whose stored tag ≠ on-disk page | §X #19, SEC-4 |
| **I** Info disclosure | `.xrdt` files listed/served to clients | tag tree hidden from dirlist/stat (NN-3); inline mode confined | §X #23 |
| **E** Path escape | data path `../` writes a tag outside the export | `openat2(RESOLVE_BENEATH)` anchored at the prefix root | §X #23, SEC-2 |
| **D** DoS | force constant re-verify | verify cost bounded by read size; HW CRC; pgWrite stores client CRC | §W |

> **Honesty (ST.2):** CRC32C is an *integrity* check against accidental corruption,
> not an *authenticity* MAC against an attacker who can write both data and tag.
> A keyed page-MAC (HMAC/keyed-CRC with a server secret) is the follow-on for the
> adversarial-tamper threat; v1 targets bit-rot + interrupted-write recovery, the
> XrdOssCsi threat model. Stated so no reviewer over-claims tamper-proofing.

### ST.3 W3 — throttle / reservation

| Threat | Vector | Mitigation | Neg test |
|---|---|---|---|
| **S** Spoof identity to dodge limits | forged username | key falls back to authenticated identity; unauth ⇒ IP key (existing `ratelimit_keys.c`) | `::test_spoof_fallback` |
| **E** Bypass per-user cap via many connections | spread opens across conns | `max_active_connections` + `max_open_files` are per *user*, summed across conns | §X #27 |
| **D** Starve other users | one user floods IO | per-user fairness: IO-load tracked per user; under-limit users preferred | §X #26, FR-10 |
| **D** Reservation exhaustion | reserve huge budgets, never release | `done()` on every TPC exit path incl. abort (R6); queue is bounded | §X #30 |
| **R** Repudiation | "I wasn't throttled" | `xrootd_throttle_rejections_total{reason}` + DIAG line | §AA |
| **D** SHM exhaustion | unique keys to fill the slab | LRU eviction (existing) + fail-open (no deadlock) | §X #31 |

---

## §EM — Error / status mapping (every new error path)

Complete errno → `kXR_*` → HTTP for the new paths, extending the CLAUDE.md quick
reference. The proto edge converts; the backend/core only sets errno + a flag.

| Condition | errno/internal | `root://` kXR | HTTP | Client-visible |
|---|---|---|---|---|
| CSI page verify mismatch | `EIO` + `csi_mismatch` | `kXR_ChkSumErr` (3031) | 500 + `X-Checksum-Mismatch: page=<n>` | "checksum error" |
| CSI tags missing, `require=on` | `EIO` | `kXR_IOError` (3007) | 500 | "integrity tags missing" |
| CSI tag header corrupt | `EIO` | `kXR_IOError` | 500 | "tag store corrupt" |
| CSI strict RMW refusal | `EIO` | `kXR_ChkSumErr` | 500 | "refusing to overwrite corrupt page" |
| Token unknown issuer | (authz deny) | `kXR_NotAuthorized` (3010) | 403 | "unknown issuer" |
| Token outside base_path | (authz deny) | `kXR_NotAuthorized` | 403 | "path not authorized for issuer" |
| Token subject map onmissing=fail | (authz deny) | `kXR_NotAuthorized` | 403 | "no user mapping" |
| Throttle over open-files/conn | (limit) | `kXR_error` (3000) "too many" | 429 + `Retry-After` | "limit exceeded" |
| Throttle delay then error | (limit, waited) | `kXR_error` after `kXR_wait` | 503 then error | "server busy" |
| Throttle transient over-limit | (limit) | `kXR_wait` (ms) | 503 `Retry-After` | retried |
| Reservation queued | (queue) | `kXR_waitresp` | 202/Retry | parked |
| Config: csi_require + csi off | (config) | — | — | `nginx -t` fails |

**Invariant preserved:** these are the only *new* terminal statuses; no existing
status code changes meaning (NFR-1). The `kXR_ChkSumErr` path is the one new
opcode-level status, gated entirely behind `xrootd_csi on`.

---

## §JJ — Definition of done + kill-switches

**DoD (every PR):** compiles clean `-Werror`; `nginx -t` validates; 3 tests pass;
no `goto`; docs updated same PR (subsystem README + parity row); gap-doc status
flipped; memory updated when a WS lands.

**Kill-switches (all default-off):**
- `xrootd_token_config` unset ⇒ single-issuer (today's behavior).
- `xrootd_csi off` ⇒ zero tag I/O, data path identical to today.
- `xrootd_throttle` unset ⇒ no throttle; `xrootd_reservation off` ⇒ no queue.
A bad rollout is a config revert + reload, never a redeploy.

---

## §KK — Migration / back-compat

- **W1.** Existing single-issuer configs keep working untouched. Operators move to
  multi-issuer by adding `xrootd_token_config`; the two paths are mutually
  exclusive per server block (registry wins; WARN if both set).
- **W2.** Enabling CSI on an existing data tree: tag files are created lazily on
  first write; existing files without tags read normally unless `require=on`
  (matches upstream `nomissing` default-off). Disabling CSI leaves orphan `.xrdt`
  files (documented; a `tools/csi_gc` cleanup is optional).
- **W3.** `xrootd_concurrency_limit` (request-count) is untouched; the IO-load mode
  is a new, separately-keyed rule. Upstream `throttle.*` ↔ `xrootd_throttle_*`
  mapping table in §W3.3.

---

## §LL — Design FAQ

- *Why not a loadable `XrdAccSciTokens.so`?* No C++ plugin ABI (non-goal); we parse
  the same cfg and reuse our JWT validator — same capability, native.
- *Why our own tag format, not `.xrdt`?* ADR-2 — host-order v1 ships first;
  byte-exact `.xrdt` interop matters only when sharing on-disk tags with a stock
  server (rare), and is a clean follow-on.
- *Why is "concurrency" not request count?* Because upstream's is IO-service-time
  load; we add it as a new mode rather than redefining ours (ADR-4) so nobody's
  existing limit changes meaning.
- *Is Bwm worth it?* Largely legacy; shipped default-off (ADR-3). The modern story
  is W3a + the existing `ratelimit/`.
- *Does CSI make data tamper-proof?* No — CRC32C detects accidental corruption and
  interrupted-write inconsistency (the XrdOssCsi threat model), not an attacker who
  rewrites data **and** tag. A keyed page-MAC is the follow-on (ST.2). Don't claim
  tamper-proofing.
- *Why disable sendfile for HTTP GET under CSI?* The kernel copies file→socket
  without the bytes entering nginx, so we can't verify them in-band (ADR-6).
  `root://` reads always pass through the io-core buffer, so they verify with no
  trade-off.
- *Can one token authorize across two issuers' namespaces?* No — `iss` binds the
  token to exactly one issuer, and authorization is confined to that issuer's
  `base_path` (ST.1 Elevation row).
- *What happens to existing single-issuer configs?* Unchanged — `token_registry`
  is NULL unless `xrootd_token_config` is set, and the validator takes the existing
  fast path (NFR-1).
- *Does the IO-load metric change my `xrootd_concurrency_limit`?* No — IO-load is a
  separate keying mode (`KEY_IOLOAD`, ADR-4); request-count concurrency is byte-for-
  byte unchanged.
- *Where do tag files live and do clients see them?* Under `xrootd_csi_prefix`
  (default `/.xrdt`), mirroring the data tree, hidden from dirlist/stat (NN-3);
  inline mode (`prefix=`) keeps them beside the data, also hidden.
- *What is the storage overhead?* 1 uint32 per 4096-byte page = **0.098%** of data
  (§W-mem.2).
- *Is `liburing` required?* No. CSI tag I/O is plain `pread`/`pwrite`; io_uring is a
  Phase-44 follow-on gated on `CAP_IOURING`.

---

## §MM — Formal requirements (FR/NFR/SEC/BLD/OPS) with traceability

The normative requirement list. **MUST/SHOULD/MAY** per RFC 2119. Each maps to a
design section and a test (cross-ref §R).

### Functional (FR)
- **FR-1 (MUST).** The server MUST parse an upstream-shaped `scitokens.cfg`
  (`[Global]` + `[Issuer N]` sections, the keys in §W1.1) into ≤
  `XROOTD_TOKEN_MAX_ISSUERS` issuers. → §EE.4, `test_token_issuer_registry`.
- **FR-2 (MUST).** Each issuer MUST be selected by exact `iss` match; a token
  whose `iss` matches no enabled issuer MUST be denied. → §HH.1, §EE.4.
- **FR-3 (MUST).** Authorization MUST be confined to the issuer's `base_path`
  set and MUST deny any path under a `restricted_path`. → §EE.4 `path_ok`.
- **FR-4 (MUST).** The strategy ladder MUST evaluate `capability`→`group`→
  `mapping` in config order and ALLOW iff at least one grants. → §W1.3, §HH.1.
- **FR-5 (SHOULD).** `map_subject`/`username_claim`/`name_mapfile`/`default_user`/
  `onmissing` SHOULD resolve a local username per §EE.5.
- **FR-6 (MUST).** With `xrootd_csi on`, every fully written page MUST have a
  persisted CRC32C; every read of a tagged page MUST verify it. → §EE.8/9.
- **FR-7 (MUST).** A verify mismatch MUST surface as `kXR_ChkSumErr` (3031) on
  `root://` and HTTP 500 on WebDAV/S3, never as silent success. → §HH.2.
- **FR-8 (MUST).** A partial-page write MUST perform read-modify-write; in strict
  mode it MUST refuse to overwrite a page whose stored tag does not match the
  on-disk page. → §HH.3, §W2.4.
- **FR-9 (SHOULD).** `kXR_pgwrite` SHOULD store the client-supplied per-page CRC
  directly without recomputation when page-aligned. → §EE.9 `store_pgcrc`.
- **FR-10 (MUST).** `xrootd_throttle` MUST accept the `concurrency/data/iops/
  interval` arguments and compute concurrency as IO-service-time load. → §EE.11.
- **FR-11 (MUST).** `max_open_files`/`max_active_connections` MUST be enforced
  per resolved user and decremented on disconnect. → §EE.11, §T-8.
- **FR-12 (SHOULD).** `userconfig` precedence MUST be exact > longest-prefix glob
  > `*` > global. → §W3.3, `test_throttle_contract`.
- **FR-13 (MAY).** A reservation manager MAY queue transfers against an aggregate
  byte budget (default off). → §EE.12.

### Non-functional (NFR)
- **NFR-1 (MUST).** Every feature MUST be default-off; enabling it MUST be the
  only behavior change. → §0, §JJ.
- **NFR-2 (SHOULD).** CSI read-verify SHOULD add < 10% wall-time to a streamed
  read on the SSE4.2 CRC path. → §W, `tests/profile_load.sh`.
- **NFR-3 (MUST).** No request-time heap churn beyond the existing pattern (tag
  reads use a stack `uint32_t[1024]` batch; registry is read-only). → §W, §V.
- **NFR-4 (SHOULD).** Worker IO-load accounting SHOULD add one locked add per IO
  completion, reusing the lock already taken for byte charging. → §EE.11, §V.

### Security (SEC)
- **SEC-1 (MUST).** `iss` spoof, `aud` mismatch, expired token, or out-of-base_path
  path MUST all DENY. → §X #3–#6,#10, `::test_security_neg`.
- **SEC-2 (MUST).** Tag-file paths MUST be confined via `openat2(RESOLVE_BENEATH)`
  to the prefix root — no `../`/symlink escape. → §EE.8, §X #23.
- **SEC-3 (MUST).** No metric label may carry a DN, subject, path, bucket, or
  issuer URL (INVARIANT 8). → §AA, `test_metrics_cardinality`.
- **SEC-4 (MUST).** A corrupt page MUST NOT be served as valid data, and a corrupt
  page MUST NOT be silently overwritten in strict mode. → FR-7, FR-8.

### Build (BLD)
- **BLD-1 (MUST).** All new `.c` files MUST be registered in the top-level
  `./config`; `./configure && make` MUST build clean under `-Werror`. → §T-10.
- **BLD-2 (MUST).** `nginx -t` MUST validate every new directive and reject
  invalid combinations (e.g. both `xrootd_token_config` and single-issuer set ⇒
  WARN; `xrootd_csi_require on` with `xrootd_csi off` ⇒ error). → §BB, §KK.

### Operational (OPS)
- **OPS-1 (MUST).** Each feature's kill-switch MUST be a config revert + reload,
  never a redeploy. → §JJ.
- **OPS-2 (SHOULD).** Reload changing a throttle/reservation SHM slot count SHOULD
  reset the table with a WARN (reload-semantics.md). → §X #32.
- **OPS-3 (SHOULD).** CSI mismatch, throttle rejection, and unknown-issuer events
  SHOULD emit an `XROOTD_DIAG` cause/fix line. → §AA.

---

## §NN — Open questions

- **NN-1.** Duplicate `iss` across two issuer sections — reject at load, or
  last-wins + WARN? (Lean reject; upstream behavior unverified.)
- **NN-2.** Should `groups_claim` groups also feed VOMS-style authdb `g` rules, or
  only token-native group rules? (Lean: authdb `g` reuse.)
- **NN-3.** CSI inline (`prefix=`) mode — hide `.xrdt` from dirlist/stat like
  upstream; confirm our namespace-hiding (`dirlist` artifact filter) covers it.
- **NN-4.** Loadshed fraction semantics — per-connection random vs per-user
  deterministic; pick to match stock qualitatively.
- **NN-5.** HTTP GET + CSI: ADR-6 disables sendfile when CSI is on. Is the
  throughput hit acceptable, or should we offer a per-location
  `xrootd_csi_verify_http off` escape hatch (at-rest scrub only) for hot read
  paths? Lean: ship ADR-6's safe default + the escape hatch as a follow-on.
- **NN-6.** `username_claim` pointing at a non-string/array claim — reject at
  validate, or coerce first element? Lean: reject (no silent coercion).

---

## §SEQ — End-to-end sequence diagrams (6 flows)

Full request→response traces for the marquee paths, showing every component
boundary (client / proto handler / token or throttle layer / VFS io-core / SD
backend / tag file).

### SEQ.1 WebDAV GET of a CSI-protected file, token-authorized

```
client                 webdav/get.c        auth_token.c     vfs_io_core      csi_verify      backend
  │  GET /stash/f          │                    │                │               │              │
  │  Authorization: Bearer │                    │                │               │              │
  ├───────────────────────►│                    │                │               │              │
  │                        │ verify_bearer ────►│                │               │              │
  │                        │                    │ registry: iss→issuer           │              │
  │                        │                    │ sig+aud+base_path+strategy     │              │
  │                        │                    │ → ALLOW, user=alice            │              │
  │                        │◄───── 0 ───────────│                │               │              │
  │                        │ (CSI on ⇒ NO sendfile, ADR-6)       │               │              │
  │                        │ open(handle, csi=ctx) ─────────────►│               │              │
  │                        │ read(off,len) ─────────────────────►│ pread ───────────────────────►│
  │                        │                    │                │◄──── bytes ───────────────────│
  │                        │                    │                │ verify_read ─►│ read_tags ───►│
  │                        │                    │                │               │ crc==tag? ok  │
  │                        │◄──────── buf (verified) ────────────│               │              │
  │◄─── 200 + body ────────│                    │                │               │              │
  (on mismatch: io_errno=EIO, csi_mismatch=1 ⇒ 500 + X-Checksum-Mismatch)
```

### SEQ.2 root:// pgWrite to a CSI file (fast path, no recompute)

```
client            write/pgwrite.c     vfs_io_core(_pgwrite)    csi_verify        backend
  │ kXR_pgwrite + per-page CRC[]   │            │                  │               │
  ├───────────────────────────────►│            │                  │               │
  │                                 │ execute ──►│ pwrite(page) ───────────────────►│
  │                                 │            │ store_pgcrc(page, CRC[i]) ──────►│ write_tags
  │                                 │            │ (NO recompute — FR-9)            │
  │◄──── kXR_ok (per-page status) ──│            │                  │               │
  (trailing partial page: recompute crc, RMW verify-before-write)
```

### SEQ.3 root:// read over IO-load throttle (delay-then-error)

```
client          read/read.c     throttle_compat        ratelimit(SHM)
  │ kXR_read         │                │                      │
  ├─────────────────►│ ioload_over? ─►│ lock; load≥C? ──────►│
  │                  │◄── over ────────│                      │
  │◄── kXR_wait(ms) ─│  (waited<max_wait)                     │
  │  ...retry...     │                │                      │
  ├─────────────────►│ ioload_over? ─►│ still over, waited≥max_wait
  │◄── kXR_error ────│  "server busy"  │                      │
  │  (under-limit users admitted first — fairness)            │
        on admit: run read; at completion charge_io(service_us) ─► node.io_time_us +=
```

### SEQ.4 WebDAV TPC pull with reservation (W3b)

```
fts/gfal          webdav/tpc.c        reservation(SHM)       remote source
  │ COPY Source:... │                     │                      │
  ├────────────────►│ schedule(wan,est) ─►│ budget free? grant h │
  │                 │◄──── h (or 0=QUEUED)─│                      │
  │                 │ (0 ⇒ park w/ kXR_waitresp; retry)           │
  │                 │ pull bytes ─────────────────────────────────►│
  │                 │◄──────────── data ──────────────────────────│
  │                 │ done(h) ───────────►│ release budget, wake queued head
  │◄── 201/200 ─────│                     │                      │
  (abort path: tpc.c error ladder ALSO calls done(h) — R6)
```

### SEQ.5 Registry config load at startup (postconfiguration)

```
nginx -t / reload     merge_srv_conf       issuer_registry      jwks
  │ token_config set?     │                     │                 │
  ├──────────────────────►│ pcalloc registry    │                 │
  │                       │ registry_load ─────►│ ini_parse_file  │
  │                       │                     │ reg_kv per line  │
  │                       │                     │ per-issuer jwks_load ──► EVP_PKEY[]
  │                       │ validate (issuer/base_path/keys)       │
  │                       │ register_cleanup (pool destroy frees keys)
  │◄── ok / EMERG ────────│  (bad cfg ⇒ nginx -t fails, master exits)
```

### SEQ.6 Background scrub tick (paced)

```
worker timer        csi_scrub          csi_verify        backend       metrics/log
  │ tick (interval)    │                   │               │              │
  ├───────────────────►│ next_page (≤256/tick)             │              │
  │                    │ read page ───────────────────────►│ pread        │
  │                    │ verify ──────────►│ crc==tag?      │              │
  │                    │                   │ mismatch ──────────────────────► metric++ + DIAG
  │                    │ re-arm timer(interval)  ← NOT sooner (idle-CPU rule)
```

---

## §FMT — On-disk tag-file format specification (normative)

The authoritative spec for the `.xrdt` sidecar this module writes. Versioned so a
future reader can evolve it without ambiguity.

### FMT.1 Layout (v1)

```
┌──────────────── 24-byte header (little-endian) ────────────────┐
│ off  size  field        value / meaning                        │
│ 0    4     magic        0x58435349 ("XCSI")                     │
│ 4    2     version      0x0001                                  │
│ 6    2     page_log2    0x000C (= 4096-byte pages)              │
│ 8    8     tracked_len  data length the tag array covers        │
│ 16   4     flags        bit0=fill-holes; bits1..31 reserved (0) │
│ 20   4     header_crc   crc32c(bytes[0..20))                    │
├──────────────── tag array ─────────────────────────────────────┤
│ 24   4·N   crc[i]       crc32c of data page i (i=0..N-1)        │
│            N = ceil(tracked_len / 4096); last page CRC is over  │
│            its ACTUAL byte length, not padded to 4096           │
└────────────────────────────────────────────────────────────────┘
```

### FMT.2 Invariants
- `magic` MUST be `0x58435349`; any other value ⇒ "not a tag file" (treat as
  missing under the `require` policy).
- `header_crc` MUST validate before any tag is trusted (catches a torn header).
- `tracked_len` MUST equal the data file size at the last successful header sync;
  a data file longer than `tracked_len·`-implied pages has **untagged tail pages**
  (a writer crashed before sync) — handled per FMT.4.
- `page_log2` MUST be 12 in v1 (4096); other values reserved for a future version.

### FMT.3 Version evolution rules
- A reader MUST refuse a `version` it does not understand (fail-closed → `require`
  policy), never silently mis-parse.
- v2 (hypothetical) adds a `algo` byte (CRC32C vs keyed-MAC) and a per-file salt;
  the header grows, `header_crc` moves — which is exactly why `version` precedes
  any size-dependent field.
- Byte-level `.xrdt` interop with stock XrdOssCsi is a **separate** format
  (20-byte header, endianness-detected); it is produced/consumed only by the
  format-compat follow-on PR, selected by `xrootd_csi_format xrdt`.

### FMT.4 Corruption / crash recovery procedure
| Situation | Detection | Recovery |
|---|---|---|
| Torn header (crash mid header-write) | `header_crc` mismatch | rebuild from data if `loose`/rebuild requested; else `require`→error, admin runs `tools/csi_rebuild <file>` |
| Untagged tail (crash after data, before tag sync) | data size > tracked_len pages | `loose`: recompute + append missing tags; `strict`: error until rebuilt |
| Interrupted partial write retried | RMW verify: tag[P]==crc(new) | accepted (loose) — the upstream recovery case (§W2.4) |
| Single tag bit-flip | per-page verify mismatch on read | report `kXR_ChkSumErr`; admin restores file from replica + `csi_rebuild` |
| Whole tag file lost | open ⇒ ENOENT | `require=off`: recompute on next read (no integrity for the gap); `require=on`: error |

`tools/csi_rebuild` (optional CLI, follow-on): walks a data file, recomputes all
page CRCs, writes a fresh v1 tag file. Idempotent; safe to run on a quiesced file.

---

## §ADB — authdb integration for `group` and `mapping` strategies

The `capability` strategy uses the existing WLCG scope checker. The `group` and
`mapping` strategies bridge a validated token into `src/path/authdb.c` so a site
can express token-driven access with the same rule grammar it already uses for
GSI/SSS identities.

### ADB.1 `group` strategy
- Source: the token's `groups_claim` (e.g. `wlcg.groups`: `["/cms","/cms/prod"]`),
  parsed into `claims->groups` (already populated by `xrootd_token_extract_groups`
  in `validate.c`).
- Bridge: `xrootd_token_group_grants(is, claims, path, op)` iterates the claimed
  groups and consults authdb `g <group> <path> <privs>` rules (the same `g` rule
  type GSI VOMS groups use). A claimed group that matches an authdb `g` rule
  granting the requested privilege ⇒ ALLOW.
- Normalization: leading `/` and case handled to match authdb's group canonical
  form; a claimed group not present in authdb simply doesn't match (no error).

### ADB.2 `mapping` strategy
- Source: the resolved local username (`subject_map`, §EE.5).
- Bridge: `xrootd_token_mapping_grants(is, claims, path, op)` treats the mapped
  user as an authdb `u <user> <path> <privs>` identity — identical to how a
  unix/krb5 principal is authorized. This lets a site reuse one authfile for all
  identity sources.

### ADB.3 Precedence & interaction
- Strategies run in config order (`authorization_strategy capability group
  mapping`); the **first** to grant wins (short-circuit). A deny from one strategy
  does not block a later one.
- The global write gate (`xrootd_allow_write`, INVARIANT 3) is checked **before**
  any strategy — a token can never write to a read-only server regardless of scope
  or authdb rule.
- ACL/authdb path confinement still applies after the strategy grants (defense in
  depth): the strategy answers "may this identity attempt the op", the path layer
  still resolves+confines the actual filesystem access.

### ADB.4 Worked example
```
# authdb
g /cms       /data/cms        rl     # CMS group: read+list under /data/cms
u alice      /home/alice      rwl    # mapped user alice: full access to her home

# scitokens.cfg
[Issuer CMS]
issuer = https://scitokens.org/cms
base_path = /data/cms
groups_claim = wlcg.groups
authorization_strategy = capability group

[Issuer HOME]
issuer = https://home.example/oidc
base_path = /home
map_subject = True
name_mapfile = /etc/xrootd/home-map.json
authorization_strategy = mapping
```
- A CMS token with `wlcg.groups=["/cms"]` reading `/data/cms/x`: capability scope
  absent ⇒ try group ⇒ authdb `g /cms /data/cms rl` grants read ⇒ ALLOW.
- A HOME token `sub=alice-oidc` mapped (via `home-map.json`) to `alice` writing
  `/home/alice/y`: mapping ⇒ authdb `u alice /home/alice rwl` ⇒ ALLOW.

---

## §RUN — Operational runbook

Per-feature enable / verify / rollback / incident steps for operators.

### RUN.1 Enable W1 multi-issuer
1. Write/validate `scitokens.cfg`; `objs/nginx -t` (catches grammar/JWKS errors).
2. Add `xrootd_token_config /etc/xrootd/scitokens.cfg;`; reload.
3. Verify: `/healthz` shows `token_issuers=N`; mint a test token, confirm ALLOW
   under base_path and DENY outside; watch `xrootd_token_authz_total`.
4. **Rollback:** remove `xrootd_token_config` (reverts to single-issuer) + reload.

### RUN.2 Enable W2 CSI on an existing export
1. `xrootd_csi on; xrootd_csi_prefix /.xrdt;` (start with `require off` so existing
   untagged files keep serving).
2. Reload. New writes create tags lazily; existing files read untagged until
   rewritten or `tools/csi_rebuild`-ed.
3. Verify: write a file, confirm `<prefix>/<path>.xrdt` exists; corrupt a page on
   a scratch copy, confirm `kXR_ChkSumErr`; watch `xrootd_csi_verify_total`.
4. (Optional) turn on `xrootd_csi_scrub_interval 24h` once tag coverage is broad.
5. **Rollback:** `xrootd_csi off` + reload (tag files become inert orphans; remove
   with `tools/csi_gc` if desired). **Never** delete tag files while CSI is on.

### RUN.3 Enable W3a throttle
1. Declare a zone; set `xrootd_throttle "concurrency C ..."` starting conservative
   (record-only is the default until a limit is set).
2. Reload; watch `xrootd_throttle_ioload` to size `C` before enforcing.
3. Add `max_open_files`/`max_active_connections`/`userconfig` as needed.
4. **Rollback:** remove the `xrootd_throttle*` directives + reload.

### RUN.4 Incident response
| Symptom | Likely cause | Action |
|---|---|---|
| Spike in `xrootd_csi_verify_total{mismatch}` | disk bit-rot / failing media | check `XROOTD_DIAG` lines for paths; restore from replica; SMART-check the device |
| Auth failures after a cfg change | bad `scitokens.cfg` | `nginx -t`; check error.log for the issuer/JWKS error; rollback RUN.1 |
| Clients see `kXR_wait`/503 storms | throttle `C` too low | raise `concurrency` or `max_wait`; or record-only to recalibrate |
| Reservation queue never drains | a TPC leaked a grant | check `xrootd_reservation_queue{in}`; restart drains SHM (or `xrootd_reservation off`) |
| `nginx -t` fails after upgrade | new cross-validation (BLD-2) | read the EMERG line (e.g. csi_require+csi off); fix the conflicting directive |

---

## §MIG — Worked migration from a stock xrootd config

A site running stock `xrootd` with SciTokens + XrdOssCsi + XrdThrottle maps to:

```
# ---- stock xrootd.cf ----                 # ---- nginx-xrootd ----
ofs.authlib ++ libXrdAccSciTokens.so \      xrootd_token_config
   config=/etc/xrootd/scitokens.cfg            /etc/xrootd/scitokens.cfg;
http.header2cgi Authorization authz         # (?authz= handled natively, Phase-58 §1)

ofs.osslib ++ libXrdOssCsi.so prefix=/.xrdt xrootd_csi on;
                                            xrootd_csi_prefix /.xrdt;

ofs.osslib ++ libXrdThrottle.so             # (throttle is native)
throttle.throttle concurrency 4 \           xrootd_throttle
   data 500m interval 1000                     "concurrency 4 data 500m interval 1000";
throttle.max_open_files 1024                xrootd_throttle_max_open_files 1024;
throttle.max_active_connections 200         xrootd_throttle_max_active_connections 200;
throttle.userconfig /etc/xrootd/tu.conf     xrootd_throttle_userconfig /etc/xrootd/tu.conf;
```
- `scitokens.cfg` and `tu.conf` (throttle userconfig) port **unchanged** (same
  grammars).
- The XrdOssCsi `.xrdt` files do **not** port byte-for-byte in v1 (ADR-2/FMT.3) —
  either re-tag via first-write/`csi_rebuild`, or wait for the format-compat PR and
  set `xrootd_csi_format xrdt`.
- Unsupported stock directives (e.g. `throttle.loadshed` tuning beyond host:freq)
  are WARN-logged so the operator sees exactly what didn't carry over.

---

## §Z — ADR log + risk register

**ADR-1 (W1 config compat).**
- *Context:* operators already maintain `scitokens.cfg` files; a parallel syntax
  doubles their config surface.
- *Decision:* parse the upstream `[Global]`/`[Issuer]` INI verbatim; keep the
  single-issuer directives as a shortcut for simple sites.
- *Consequences:* `xrootd_token_config /etc/xrootd/scitokens.cfg` is a drop-in;
  unsupported keys are WARN-logged (R4), never silently dropped.
- *Alternatives rejected:* a bespoke nginx-only issuer block (forces re-authoring);
  a converter-only approach (still leaves drift on every upstream change).

**ADR-2 (W2 on-disk format).**
- *Context:* stock `.xrdt` carries a 20-byte header with endianness detection;
  byte-exact interop only matters when a stock server and this module share the
  same tag tree.
- *Decision:* ship our own versioned 24-byte-header sidecar (host-order, explicit
  `version`/`page_log2`); byte-level `.xrdt` interop is a documented follow-on PR.
- *Consequences:* simpler, self-describing v1; cross-arch and stock-shared trees
  need the follow-on. Matches Phase-58's host-order checksum-at-rest decision.
- *Alternatives rejected:* mimic the stock 20-byte layout immediately (couples v1
  to an external format before we need it).

**ADR-3 (W3b scope).**
- *Context:* `XrdBwm` is a reservation manager from the gridFTP era, rarely used in
  modern WLCG sites.
- *Decision:* implement reservation semantics but ship **default-off**, documented
  as legacy/niche; the modern fairness story is W3a + the existing `ratelimit/`.
- *Consequences:* zero footprint unless enabled; not a hot-path default.
- *Alternatives rejected:* skip Bwm entirely (leaves a named parity gap);
  make it a first-class default (cost without demand).

**ADR-4 (W3a concurrency semantics).**
- *Context:* our existing `xrootd_concurrency_limit` counts in-flight *requests*;
  upstream's `concurrency` is IO-service-time *load*. Redefining ours would change
  the meaning of every deployed limit.
- *Decision:* add IO-load as a **new additive keying mode**
  (`XROOTD_RL_KEY_IOLOAD`); leave request-count concurrency untouched.
- *Consequences:* both metrics coexist; operators choose per rule.
- *Alternatives rejected:* repurpose the existing rule (silent behavior change).

**ADR-5 (W2 confinement).**
- *Context:* INVARIANT 11 forbids data-byte I/O outside `src/fs/backend/`.
- *Decision:* all tag-file `pread`/`pwrite` live in `csi_tagstore.c` behind the SD
  seam; a non-POSIX backend supplies its own tag store via the same interface.
- *Consequences:* CSI is portable across backends; no raw FS calls leak upward.
- *Alternatives rejected:* a `compat/`-level tag store (breaks the invariant).

**ADR-6 (W2 + HTTP sendfile).**
- *Context:* WebDAV/S3 GET use `sendfile`/`SSL_sendfile`; bytes never enter
  userspace, so they cannot be CRC-verified in-band.
- *Decision:* when `xrootd_csi on` for a location, **disable sendfile** for GET on
  that location (correctness over zero-copy); `root://` reads always verify (they
  pass through the io-core buffer already).
- *Consequences:* a documented throughput trade-off for HTTP GET on CSI-protected
  exports; background scrub still covers at-rest integrity regardless.
- *Alternatives rejected:* trust-on-read for HTTP (defeats the point of CSI);
  a verifying sendfile shim (kernel can't hand us the bytes). See NN-5.

**ADR-7 (W1 monitor = HTTP-native).**
- *Context:* `XrdSciTokensMon` reports per-IO identity; the project rejects UDP
  monitoring ([`srr_wlcg_endpoint`]).
- *Decision:* the monitor hook increments low-cardinality Prometheus counters
  keyed by issuer *bucket* (not URL), never emitting per-subject UDP records.
- *Consequences:* aggregate authz observability; per-subject granularity lives in
  the access log, not metrics (SEC-3).
- *Alternatives rejected:* a UDP monitor stream (explicit non-goal).

**Risk register**

| ID | Risk | Mitigation |
|---|---|---|
| R1 | W2 per-page verify perf | HW CRC + in-place 3-way ([`pgread_zerocopy_crc_optim`]); pgWrite stores client CRC (no recompute) |
| R2 | W2 partial-write RMW correctness | default strict verify-before-write; explicit unaligned tests (#11/#12) |
| R3 | W3 SHM hot-path contention | spin+yield `xrootd_shm_table_*` (INVARIANT 10); µs-held sections |
| R4 | W1 silent config drift | log unsupported keys at WARN, never ignore |
| R5 | W2 orphan `.xrdt` on disable | documented; optional `tools/csi_gc` |
| R6 | W3b reservation leak on abort | `xrootd_resv_done` on every TPC exit path (success+error); idempotent |

---

## Glossary

- **CSI** — Checksum Integrity (per-page CRC32C tagstore); upstream `XrdOssCsi`.
- **Tag file / `.xrdt`** — sidecar holding one CRC32C per data page; our format is
  the 24-byte-header variant (§EE.7), upstream's is the 20-byte variant (§W2.1).
- **Tagstore** — the read/write interface over the tag file (`ReadTags`/`WriteTags`
  upstream; `xrootd_csi_read_tags`/`_write_tags` here).
- **CRC32C** — Castagnoli CRC-32 (init 0, no final-XOR); the per-page integrity
  primitive; HW via SSE4.2 `_mm_crc32_*`, SW fallback in `crc32c.c`.
- **RMW** — read-modify-write; the path for a sub-page write that must read the
  full page, verify, splice, and re-tag.
- **Page** — fixed 4096-byte unit (`XrdSys::PageSize`); the CRC granularity.
- **Tracked length** — the data length the tag array currently covers
  (`trackinglen`/`tracked_len` in the header).
- **Issuer registry** — the multi-issuer table parsed from `scitokens.cfg`.
- **Issuer** — a trusted token authority identified by its `iss` URL; one
  `[Issuer N]` section.
- **base_path / restricted_path** — the namespace prefixes an issuer may / may not
  authorize.
- **Strategy** — `capability` (WLCG scopes) / `group` (groups_claim) / `mapping`
  (subject→user) authorization mode, evaluated in config order.
- **Subject map** — JSON `{subject: username}` file (`name_mapfile`) resolving a
  token `sub` to a local user.
- **Metric bucket** — the small integer id (≤ MAX_ISSUERS+1) used as a metric
  label instead of the issuer URL (cardinality bound).
- **IO-load** — summed IO service-time per interval (upstream throttle
  "concurrency"); distinct from request-count concurrency.
- **userconfig** — INI of per-user `maxconn` limits with glob precedence.
- **loadshed** — redirecting a fraction of requests to a peer under load.
- **Reservation** — Bwm-style bandwidth grant (Schedule→handle→Done); a queued
  budget slot for large/TPC transfers.
- **SD driver** — the pluggable Storage Driver seam (`src/fs/backend/sd.h`); all
  data-byte and tag I/O lives behind it (INVARIANT 11).
- **VFS I/O core** — `xrootd_vfs_io_execute()`, the POD thread-safe execution
  surface for read/write/pgread/pgwrite/readv/sync/truncate jobs.
- **STRIDE** — Spoofing/Tampering/Repudiation/Info-disclosure/DoS/Elevation; the
  threat-model taxonomy used in §ST.

---

## Source references

Official (`/tmp/xrootd-src/src`): `XrdSciTokens/` (`XrdSciTokensAccess.cc`,
`XrdSciTokensMon.{cc,hh}`, `configs/scitokens.cfg`, `README.md`); `XrdOssCsi/`
(`XrdOssCsiPages.{cc,hh}`, `XrdOssCsiTagstoreFile.cc` [header layout @72-113],
`XrdOssCsiConfig.cc`, `README.md`); `XrdThrottle/` (`XrdThrottleConfig.cc`,
`XrdThrottleManager.cc`, `README.md`); `XrdBwm/` (`XrdBwmPolicy*.{cc,hh}`,
`XrdBwmConfig.cc`, `XrdBwmLogger.{cc,hh}`).

This module (`src/`): `src/token/` (`token.h`, `token_internal.h`, `validate.c`,
`config.c`, `scopes.c`, `jwks.c`, `json.c`, `refresh.c`); `src/types/config.h`
(token fields @215-229); `src/fs/vfs_io_core.{c,h}`, `src/fs/backend/sd.h`
(caps @75-89), `src/compat/{crc32c,pgio,integrity_info}.{c,h}`;
`src/ratelimit/` (`ratelimit.{c,h}`, `ratelimit_keys.c`, `ratelimit_zone.c`);
`src/connection/disconnect.c` (`xrootd_on_disconnect` @288); `src/path/authdb.c`,
`src/path/auth_gate.c`; callers `src/webdav/auth_token.c`, `src/gsi/token.c`,
`src/handshake/policy.c`, `src/types/identity.c`. Builds on Phase-58 §8/§9.
</content>
