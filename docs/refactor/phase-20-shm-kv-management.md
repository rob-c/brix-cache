# Phase 20 — Shared Memory & Key-Value Management

**Scope**: Replace eleven ad-hoc fixed-size SHM tables with a unified infrastructure:
a zone boilerplate macro layer, a generic hash-table KV store, and three concrete
consumers (JWT validation cache, auth result cache, rate limiting).

**Net LoC**: +~580 new / −~120 boilerplate = **+~460 net**  
**Risk**: Medium — touches shared infrastructure used across every protocol path;
existing tables are migrated incrementally, not replaced wholesale.  
**Build impact**: Two new source files registered in `config.h`; no `./configure`
re-run needed for incremental builds after that.  
**Requires**: `make -j$(nproc)` only after `config.h` update.

---

## Implementation status (as-built — reconciled 2026-06-13)

Audited against the code under `src/`. **The phase is functionally complete: the
KV store and all three consumers (token cache, auth cache, rate limiter) are
implemented, wired, and exported to Prometheus.** Two planned pieces were
intentionally not done (Step A macro layer; one of four Step-F directives), and a
few integration details diverge from the original design — all detailed below.

| Step | Component | Status | Evidence |
|------|-----------|--------|----------|
| **B** | Generic KV store (`src/core/shm/kv.{c,h}`) | ✅ **Done** | `kv.c` — FNV-1a 64-bit hash, linear-probe + backward-shift delete, load-factor ≤ 0.5, lazy TTL. Plus zone-registry helpers `xrootd_kv_find()` / `xrootd_kv_zone_directive()` not in the original API. |
| **A** | SHM zone boilerplate macros (`src/core/compat/shm_zone.h`) | ⛔ **Not implemented (and unnecessary)** | No `shm_zone.h`; no `XROOTD_SHM_ZONE_*` usage anywhere. The KV store made the macro layer moot — the three consumers wrap `xrootd_kv_t` directly with no SHM boilerplate. (`src/core/compat/shm_slots.h` is unrelated — free-slot helpers for the TPC/cache slot pools.) |
| **C** | JWT token validation cache (`src/auth/token/token_cache.{c,h}`) | ✅ **Done — integration point differs** | Wired at the auth callers `src/auth/gsi/token.c:87,138` and `src/webdav/auth_token.c:145,194`, **not** `token/validate.c` (which has no cache reference). Caches the full `xrootd_token_claims_t`, not the compact `xrootd_token_cache_val_t` the doc proposed. SHA-256 fingerprint key + 5-min TTL cap as designed. |
| **D** | Auth result cache (`src/path/auth_cache.{c,h}`) | ✅ **Done — matches design** | Wired in `src/auth/authz/auth_gate.c` (key build ~`:23-61`, lookup-before-scan ~`:91-114`, store-after ~`:64-78`). 3-byte `xrootd_auth_cache_val_t`, 32-byte SHA-256 key, 30 s default TTL. Stream-only. |
| **E** | Rate limiting (`src/core/shm/rate_limit.{c,h}`) | ✅ **Done — coexists with Phase 25** | Token-bucket on the KV store; called from `src/webdav/access.c:100` and `src/auth/gsi/auth.c:289`. Does **not** supersede / is not superseded by the separate Phase-25 leaky-bucket system in `src/net/ratelimit/` — both are active and independent (different directives, different algorithms). |
| **F** | Configurable existing-table sizes | ⚠️ **3 of 4 done** | `xrootd_session_slots`, `xrootd_registry_slots`, `xrootd_redir_cache_slots` implemented (conf fields + directives). `xrootd_tpc_slots` **still deferred** — `XROOTD_TPC_REGISTRY_SLOTS` (1024) remains a compile-time array dimension (`src/tpc/common/registry.c:16`) for the dual-call-site reason below. |
| — | Prometheus export | ✅ **Done** | `xrootd_kv_metrics_emit()` in `src/observability/metrics/writer.c` emits `xrootd_kv_{hits,misses,evictions}_total` + `xrootd_kv_{entries,capacity}` per zone. |
| — | `config.h` / build registration | ✅ **Done** | The four sources (`shm/kv.c`, `token/token_cache.c`, `path/auth_cache.c`, `shm/rate_limit.c`) are registered in the module `config` (NGX_ADDON_SRCS). |
| — | Directives wired | ✅ **Done** | `xrootd_kv_zone`, `xrootd_token_cache`, `xrootd_auth_cache`, `xrootd_rate_limit` registered in `src/stream/module.c` (stream) and `src/webdav/module.c` (HTTP — token_cache + rate_limit; auth_cache is stream-only). |

### As-built divergences from the design (none are defects)

1. **Step A macro layer was dropped.** The generic KV store eliminated the
   per-table boilerplate the macros were meant to remove, so the consumers need no
   macro layer. The "~30 LoC/table savings" would only have applied to migrating
   the legacy tables, which was never in scope for this phase.
2. **Token cache lives at the auth callers, not `validate.c`.** Integrating at
   `gsi/token.c` / `webdav/auth_token.c` puts the cache where the verified
   `xrootd_token_claims_t` and the per-listener `conf->token_cache_kv` are both in
   scope; `validate.c` stays a pure verifier. The cached value is the full claims
   struct (simpler, no separate serialization type).
3. **`xrootd_kv_configure()` takes `ngx_str_t *name`** (not `const char *`) and the
   counter fields are plain `uint64_t` updated under the zone spinlock (not
   `ngx_atomic_t`). Both are conventional, safe choices.
4. **Phase-25 rate limiting is a separate system**, added later — the original
   doc's concern about Phase-20 rate limiting being superseded is moot; the two
   coexist. See `phase-25-rate-limiting.md`.

### Still incomplete / pending

- **Step A** SHM zone macros — not implemented; recommend marking **won't-do**
  (superseded by the KV store) rather than pending.
- **Step F** `xrootd_tpc_slots` — pending; blocked on the dual-postconfig call-site
  issue described in Step F. The compile-time default (1024) is in effect.
- The "atomic get-modify-set" KV helper for strict rate-limit admission (noted in
  *Known constraints*) — not added; the best-effort get+set is what ships.

> **Forward note (Phase 30, M1.2):** `manager/redir_cache.c` — listed below as an
> O(n) linear-scan ring buffer — was subsequently converted to a bounded
> open-addressing hash (FNV-1a + fixed probe window) under its existing lock. The
> "Current state" table is historical (pre-Phase-20); the redirect cache is no
> longer an O(n) scan.

---

## Current state: independent SHM tables

> **Update:** the `xrootd_webdav_lock_registry` table listed below was **removed
> by Phase 16** (WebDAV lock state moved to xattrs / the unified prop store), so
> the module now has one fewer SHM table than at this phase's planning time.

The module had 11 `ngx_shm_zone_t` globals across 9 source files, each implementing
the same 5-function boilerplate pattern:

| Zone name | File | Table size | Lookup complexity |
|---|---|---|---|
| `xrootd_metrics` | `metrics/config.c` | Fixed Prometheus counters | Direct offset |
| `xrootd_sessions` | `session/registry.c` | 1024 slots (compile-time) | O(n) linear scan |
| `xrootd_session_handles` | `session/handles.c` | 1024 × 256 = 262144 entries | O(n) linear scan |
| `xrootd_srv` | `manager/registry.c` | 128 slots (compile-time) | O(n) linear scan |
| `xrootd_redir_cache` | `manager/redir_cache.c` | 512 ring-buffer slots | O(n) linear scan |
| `xrootd_pending_locate` | `manager/pending.c` | 32 slots | O(n) linear scan |
| `xrootd_tpc_keys` | `tpc/key_registry.c` | Compile-time | O(n) linear scan |
| `xrootd_tpc_transfers` | `tpc/common/registry.c` | 1024 slots | O(n) linear scan |
| ~~`xrootd_webdav_lock_registry`~~ | ~~`webdav/module.c`~~ | **removed (Phase 16 → xattr)** | — |
| `xrootd_dashboard` (×3) | `dashboard/config.c` | Fixed transfer/event/history | O(n) linear scan |

Every table except `xrootd_metrics` uses the same pattern (abbreviated):

```c
static ngx_shm_zone_t *zone;         /* (1) global zone pointer */
static ngx_shmtx_t     mutex;        /* (2) module-level spinlock */

static T *table(void) {              /* (3) null-check accessor */
    if (zone == NULL || zone->data == NULL || zone->data == (void *)1)
        return NULL;
    return (T *) zone->data;
}

static ngx_int_t init(ngx_shm_zone_t *shm_zone, void *data) { /* (4) */ }

ngx_int_t configure(ngx_conf_t *cf) {                         /* (5) */
    zone = ngx_shared_memory_add(...);
    zone->init = init;
    zone->data = (void *) 1;
    return NGX_OK;
}
```

**Problems:**

1. **O(n) linear scan under a spinlock** — with 1024 session slots and 64 workers each
   doing ~100 rps, the session lock is contested on every request. A full table scan while
   holding a spinlock is a latency spike visible in grid pilot benchmarks.

2. **Compile-time table sizes** — sites with >1024 concurrent sessions (Tier-1 sites),
   >1024 concurrent TPC transfers, or >1024 WebDAV locks can't grow the tables without
   recompiling.

3. **No cross-worker JWT validation cache** — `token/validate.c` calls
   `EVP_DigestVerify()` (RSA or ECDSA) on every request. For 1000 WLCG pilots each
   presenting a 5-minute token, this runs ~200 verifications per second at ~0.3 ms each
   = 60 ms/s of crypto load. The per-SSL-connection cache in `webdav/auth_cert.c` only
   caches GSI cert results and only for the TCP connection lifetime — a new connection,
   TLS session resumption on a different worker, or the stream protocol doesn't benefit.

4. **No auth result cache** — every request runs the authdb O(n) rule scan + VO ACL O(m)
   scan regardless of how recently the same {path, identity} pair was authorized. For
   hot data paths (e.g., a pilot repeatedly stat'ing the same directory) this is pure
   redundant work.

5. **No rate limiting** — the `auth.c` has `XROOTD_MAX_AUTH_ATTEMPTS` (per-connection),
   but there is no cross-worker per-identity or per-IP request throttle. A single client
   can saturate workers with repeated auth failures or stat storms.

6. **Boilerplate copies** — each new SHM-backed feature requires writing the same
   5-function pattern. The existing 9 files contain ~180 LoC of identical structural code.

---

## Architecture

The plan is in four layers, implemented bottom-up:

```
┌─────────────────────────────────────────────────────────┐
│  Layer 4 — consumers (new capabilities)                  │
│  token/token_cache.c  path/auth_cache.c  shm/rate_limit.c│
├─────────────────────────────────────────────────────────┤
│  Layer 3 — generic KV store                              │
│  src/core/shm/kv.h + kv.c                                    │
├─────────────────────────────────────────────────────────┤
│  Layer 2 — configurable zone sizes (existing tables)     │
│  Add ngx_command_t directives to existing configure()    │
├─────────────────────────────────────────────────────────┤
│  Layer 1 — SHM zone boilerplate macro                    │
│  src/core/compat/shm_zone.h                                   │
└─────────────────────────────────────────────────────────┘
```

---

## Step A — SHM zone boilerplate macro layer

> **Status: ⛔ NOT IMPLEMENTED (won't-do).** `src/core/compat/shm_zone.h` does not
> exist and no `XROOTD_SHM_ZONE_*` macros are used anywhere in `src/`. The Step-B
> KV store removed the need for this layer — the three consumers wrap `xrootd_kv_t`
> directly with no SHM boilerplate. The macro savings would only have applied to
> migrating the legacy tables, which is out of scope. The remainder of this section
> is retained as the original design for reference only.

**File**: `src/core/compat/shm_zone.h` (new, ~60 LoC)  
**Risk**: None — additive header only; nothing calls these macros until callers are updated.

### Macro API

```c
/* Declare the shm_zone pointer and mutex in a header. */
#define XROOTD_SHM_ZONE_EXTERN(sym) \
    extern ngx_shm_zone_t *sym##_shm_zone;  \
    extern ngx_shmtx_t     sym##_shm_mutex

/* Define storage in one .c file. */
#define XROOTD_SHM_ZONE_DEFINE(sym) \
    ngx_shm_zone_t *sym##_shm_zone; \
    ngx_shmtx_t     sym##_shm_mutex

/* Null-safe accessor: returns NULL if zone not yet initialised. */
#define XROOTD_SHM_ZONE_PTR(sym, T) \
    (((sym##_shm_zone) == NULL \
      || (sym##_shm_zone)->data == NULL \
      || (sym##_shm_zone)->data == (void *)1) \
     ? NULL : (T *)((sym##_shm_zone)->data))

/* Standard configure() body — add to ngx_shared_memory_add call site. */
#define XROOTD_SHM_ZONE_CONFIGURE(cf, sym, name_str, size, module, init_fn) \
    do { \
        ngx_str_t _z = ngx_string(name_str); \
        (sym##_shm_zone) = ngx_shared_memory_add((cf), &_z, (size), (module)); \
        if ((sym##_shm_zone) == NULL) return NGX_ERROR; \
        (sym##_shm_zone)->init = (init_fn); \
        (sym##_shm_zone)->data = (void *) 1; \
    } while (0)

/* Standard init() body — for the "already initialised" branch. */
#define XROOTD_SHM_ZONE_REINIT(shm_zone, sym, T) \
    do { \
        (shm_zone)->data = data; \
        return ngx_shmtx_create(&(sym##_shm_mutex), \
                                &((T *)(data))->lock, NULL); \
    } while (0)
```

### Migration path

After this header exists, any single existing table can opt in to use the macros
opportunistically (e.g. when nearby code is being touched for another reason). Full
migration of all 9 files is not required for this phase — the macros eliminate
future duplication and reduce new feature cost.

**Estimated LoC savings per table on migration**: ~30 LoC (5 functions → 4 macro calls).

---

## Step B — Generic SHM key-value store

**Files**: `src/core/shm/kv.h` (new, ~80 LoC), `src/core/shm/kv.c` (new, ~260 LoC)  
**Register in**: `src/core/config/config.h` under `NGX_ADDON_SRCS`  
**Risk**: Medium — new code, but consumers are all additive; no existing code path changes
until a consumer is wired in.

### Design: open-addressed hash table in shared memory

**Layout**:

```c
/* Fixed stride: header at offset 0, entries at offset sizeof(header). */
typedef struct {
    ngx_shmtx_sh_t  lock;       /* spinlock (must be first) */
    ngx_atomic_t    count;      /* live entries */
    ngx_atomic_t    hits;       /* cache hits (for Prometheus) */
    ngx_atomic_t    misses;     /* cache misses */
    ngx_atomic_t    evictions;  /* TTL-expiry + capacity evictions */
    uint32_t        capacity;   /* number of hash buckets (power of 2) */
    uint32_t        key_max;    /* max key bytes per entry */
    uint32_t        val_max;    /* max value bytes per entry */
    uint32_t        _pad;
} xrootd_kv_header_t;

typedef struct {
    uint64_t     hash;       /* FNV-1a 64-bit hash of key */
    uint32_t     key_len;    /* 0 = slot free */
    uint32_t     val_len;
    ngx_msec_t   expires;    /* ngx_current_msec at expiry; 0 = no expiry */
    /* char data[key_max + val_max] follows immediately */
} xrootd_kv_entry_t;
```

**Capacity and sizing**: the configure directive specifies zone size in bytes. The
implementation computes the largest power-of-2 `capacity` that fits given the header
and per-entry size. For a 4 MB zone with 64-byte keys and 128-byte values:

```
available = 4MiB - sizeof(header) = ~4,194,240 bytes
entry_stride = sizeof(entry_t) + 64 + 128 = 208 bytes
capacity = largest power-of-2 ≤ 4,194,240 / 208 = 20,165 → 16,384 buckets
```

**Hash function**: FNV-1a 64-bit (no external dependency):

```c
static uint64_t
xrootd_kv_hash(const void *key, size_t len)
{
    const uint8_t *p   = key;
    uint64_t       h   = 14695981039346656037ULL;
    size_t         i;
    for (i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}
```

**Collision resolution**: linear probing with wraparound. Probe distance is bounded:
after `capacity / 2` probes without finding the key, declare miss (load factor ≤ 0.5
is maintained by refusing `set` when `count >= capacity / 2`).

**Expiry**: `get` checks `expires` — if `expires > 0 && expires <= ngx_current_msec`,
treat as miss and mark slot free. No background sweep needed; expiry is lazy and
O(1) per access.

### API

```c
/* src/core/shm/kv.h */

typedef struct {
    ngx_shm_zone_t  *zone;
    ngx_shmtx_t      mutex;
} xrootd_kv_t;

/*
 * xrootd_kv_configure() — allocate and register the SHM zone.
 * Called during nginx configuration phase.
 * name:    nginx directive-supplied zone name (must be unique).
 * size:    bytes; minimum XROOTD_KV_MIN_SIZE (64 KiB).
 * key_max: maximum key length in bytes (e.g. 64 for SHA-256 hex, 256 for paths).
 * val_max: maximum value length in bytes.
 * module:  &ngx_http_xrootd_webdav_module or &ngx_stream_xrootd_module.
 */
ngx_int_t xrootd_kv_configure(ngx_conf_t *cf, xrootd_kv_t *kv,
    const char *name, size_t size, size_t key_max, size_t val_max,
    ngx_module_t *module);

/*
 * xrootd_kv_get() — look up a key. Returns 1 (hit), 0 (miss/expired).
 * out/out_len: populated on hit; out must be caller-allocated ≥ val_max bytes.
 */
int xrootd_kv_get(xrootd_kv_t *kv, const void *key, size_t key_len,
    void *out, size_t *out_len);

/*
 * xrootd_kv_set() — insert or overwrite.
 * ttl_ms: milliseconds until expiry; 0 = no expiry.
 * Returns NGX_OK or NGX_ERROR (zone full at load factor > 0.5).
 */
ngx_int_t xrootd_kv_set(xrootd_kv_t *kv, const void *key, size_t key_len,
    const void *val, size_t val_len, ngx_msec_t ttl_ms);

/*
 * xrootd_kv_delete() — remove a key. No-op if not present.
 */
void xrootd_kv_delete(xrootd_kv_t *kv, const void *key, size_t key_len);

/*
 * xrootd_kv_stats() — snapshot hit/miss/eviction counters for Prometheus.
 */
typedef struct {
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    uint64_t count;
    uint32_t capacity;
} xrootd_kv_stats_t;

void xrootd_kv_stats(xrootd_kv_t *kv, xrootd_kv_stats_t *out);
```

### Configuration directive

```c
/* New directive — placed in src/core/config/directives.c */

{ ngx_string("xrootd_kv_zone"),
  NGX_HTTP_MAIN_CONF|NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE3,
  ngx_conf_set_str_slot,   /* handled by custom parser below */
  0, 0, NULL },
```

Directive syntax:

```nginx
# xrootd_kv_zone <zone_name> <size> key=<bytes> val=<bytes>;
xrootd_kv_zone xrootd_token_kv  8m  key=64  val=512;
xrootd_kv_zone xrootd_auth_kv   4m  key=64  val=32;
xrootd_kv_zone xrootd_rl_kv     2m  key=256 val=24;
```

### Prometheus export

Add to `metrics/writer.c`:

```
xrootd_kv_hits_total{zone="xrootd_token_kv"} <N>
xrootd_kv_misses_total{zone="xrootd_token_kv"} <N>
xrootd_kv_evictions_total{zone="xrootd_token_kv"} <N>
xrootd_kv_entries{zone="xrootd_token_kv"} <N>
xrootd_kv_capacity{zone="xrootd_token_kv"} <N>
```

Metrics are tracked per zone and exported lazily by iterating a module-level
`xrootd_kv_t *zones[XROOTD_KV_MAX_ZONES]` array populated during configuration.

**Locking**: single zone-level spinlock (same as all existing tables). For the three
consumer zones (token cache, auth cache, rate limiter) contention is low because
`get` holds the lock only for a single O(1) probe sequence — no I/O or allocation
occurs under the lock.

---

## Step C — JWT token validation cache

> **Status: ✅ IMPLEMENTED — integration point differs from this design.** The
> cache is wired at the auth callers `src/auth/gsi/token.c:87,138` and
> `src/webdav/auth_token.c:145,194` (lookup before verify / store on success),
> **not** in `token/validate.c` (which keeps no cache reference). The cached value
> is the full `xrootd_token_claims_t`, not the compact `xrootd_token_cache_val_t`
> sketched below. SHA-256 fingerprint key and 5-minute TTL cap are as designed.

**Files**: `src/auth/token/token_cache.h`, `src/auth/token/token_cache.c` (implemented)  
**Register in**: `config` (NGX_ADDON_SRCS) — done  
**Integration point (as-built)**: `src/auth/gsi/token.c` and `src/webdav/auth_token.c`
→ cache lookup before signature verification, store after a successful verify.
(The original design targeted `src/auth/token/validate.c`.)

### Why the cross-worker token cache matters

The existing per-SSL-connection cache in `webdav/auth_cert.c` covers GSI certificates
and is bounded to one TCP connection lifetime. Bearer tokens are re-presented on every
HTTP request (stateless protocol) and arrive across many different TCP connections and
worker processes. Token signature verification (RSA PKCS#1 SHA-256 or ECDSA P-256) is
the most expensive single operation in the hot path:

- RSA-2048 verify: ~0.25 ms (OpenSSL 3.x, AVX-512)
- ECDSA P-256 verify: ~0.12 ms
- 1000 pilot jobs × 5 req/s × 0.25 ms = **1.25 seconds of crypto per second** at one worker

A cross-worker SHM cache keyed on the token fingerprint (SHA-256 of the raw token bytes,
truncated to 32 bytes for the key) caches the verified claims until the token expires.
Repeated presentations of the same token — the dominant pattern for pilot jobs — hit
the cache and skip the ECDSA/RSA operation entirely.

**Security note**: only successfully verified claims are cached. Failed verifications
are never cached (error result is not stored). The cached value includes the token's
`exp` claim; TTL is set to `exp - now_ms` capped at 5 minutes so a token that nears
its expiry is re-verified rather than served from stale cache. Revoked tokens cannot
be detected once cached — this is the standard tradeoff for stateless JWT validation
shared by all major OIDC deployments.

### Key and value layout

```c
/* key: 32 bytes — SHA-256 of raw token bytes (truncated) */
/* val: serialized xrootd_token_claims_t — fixed 480 bytes */

typedef struct {
    char       sub[256];             /* subject */
    char       iss[128];             /* issuer */
    char       groups[8][64];        /* VO groups (WLCG "wlcg.groups") */
    int        n_groups;
    xrootd_token_scope_t scopes[XROOTD_MAX_TOKEN_SCOPES];
    int        n_scopes;
    time_t     exp;                  /* token expiry (Unix seconds) */
} xrootd_token_cache_val_t;         /* ~480 bytes */
```

### Configuration directive

```nginx
# In http {} or stream {} block:
xrootd_kv_zone     xrootd_token_kv  8m key=32 val=512;

# In server {} or location {} block:
xrootd_token_cache zone=xrootd_token_kv;
```

New directive: `xrootd_token_cache zone=<name>;`

New field in `ngx_stream_xrootd_srv_conf_t` and `ngx_http_xrootd_webdav_loc_conf_t`:
```c
xrootd_kv_t  *token_cache_kv;   /* NULL = disabled */
```

### Integration in `src/auth/token/validate.c`

```c
/* Before EVP_DigestVerify: */
if (conf->token_cache_kv != NULL) {
    u_char fingerprint[32];
    SHA256((u_char *) token, token_len, fingerprint);

    xrootd_token_cache_val_t cached;
    size_t cached_len = sizeof(cached);
    if (xrootd_kv_get(conf->token_cache_kv,
                      fingerprint, sizeof(fingerprint),
                      &cached, &cached_len) == 1)
    {
        /* cache hit — populate claims from cached, skip EVP_DigestVerify */
        *out_claims = cached.claims;
        return 0;
    }
}

/* ... existing EVP_DigestVerify path ... */

/* On success, store in cache: */
if (conf->token_cache_kv != NULL && verify_ok) {
    ngx_msec_t remaining_ms = (ngx_msec_t)(claims.exp - now) * 1000;
    ngx_msec_t ttl = ngx_min(remaining_ms, 5 * 60 * 1000); /* cap at 5 min */
    if (ttl > 0) {
        xrootd_token_cache_val_t cv;
        /* ... populate cv from claims ... */
        xrootd_kv_set(conf->token_cache_kv, fingerprint, sizeof(fingerprint),
                      &cv, sizeof(cv), ttl);
    }
}
```

**Files changed**: `src/auth/token/validate.c` (+~25 LoC), `src/core/types/config.h` (+2 LoC),
`src/core/config/directives.c` (+~15 LoC)

---

## Step D — Auth result cache

**Files**: `src/auth/authz/auth_cache.h` (new, ~25 LoC), `src/auth/authz/auth_cache.c` (new, ~75 LoC)  
**Integration point**: `src/auth/authz/auth_gate.c` → checked before authdb+VO scan

### What gets cached

`xrootd_auth_gate()` runs three checks in sequence:

1. `xrootd_check_authdb()` — O(m) scan of `conf->authdb_rules` (typ. 5–50 rules)
2. `xrootd_check_vo_acl_identity()` — O(m) scan of `conf->vo_rules`
3. `xrootd_check_token_scope()` — O(k) scan of `conf->scopes` (max 8)

For hot data paths (a pilot job repeatedly reading the same directory tree), all three
return the same result for the same `{resolved_path, dn, vo_list}` triple. Caching the
combined result avoids the three scans on repeated requests.

### Key and value

```c
/*
 * Key: 32-byte SHA-256 of NUL-joined {resolved_path + "\0" + dn + "\0" + vo_list}
 * Val: 3 bytes — {allowed:1, auth_level_required:1, _pad:1}
 *
 * The path component in the key is the resolved canonical path, so
 * symlink/redirect differences are already collapsed before hashing.
 */
typedef struct {
    uint8_t  allowed;       /* 1 = grant, 0 = deny */
    uint8_t  auth_level;    /* XROOTD_AUTH_READ or XROOTD_AUTH_UPDATE */
    uint8_t  _pad;
} xrootd_auth_cache_val_t;   /* 3 bytes */
```

**TTL**: short (default 30 seconds) — authdb rules can be updated by config reload
(nginx `kill -HUP`) which zeroes the zone. 30 s is short enough that a config reload
clears stale entries within one expiry window.

### Configuration

```nginx
xrootd_kv_zone    xrootd_auth_kv  4m key=32 val=4;
xrootd_auth_cache zone=xrootd_auth_kv ttl=30;
```

New directive: `xrootd_auth_cache zone=<name> [ttl=<seconds>];`

### Integration in `src/auth/authz/auth_gate.c`

```c
ngx_int_t
xrootd_auth_gate(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_uint_t op_id, const char *op_name,
    const char *reqpath, const char *resolved,
    ngx_stream_xrootd_srv_conf_t *conf,
    int auth_level, int need_write)
{
    /* --- auth result cache check --- */
    if (conf->auth_cache_kv != NULL) {
        u_char key[32];
        xrootd_auth_cache_key(key, resolved, ctx->dn, ctx->vo_list);

        xrootd_auth_cache_val_t cv;
        size_t cv_len = sizeof(cv);
        if (xrootd_kv_get(conf->auth_cache_kv, key, sizeof(key),
                          &cv, &cv_len) == 1)
        {
            if (!cv.allowed) {
                XROOTD_OP_ERR(ctx, op_id);
                xrootd_log_access(ctx, c, op_name, resolved,
                                  "auth-cache: denied", 0,
                                  kXR_NotAuthorized, NULL, 0);
                ctx->write_rc = xrootd_send_error(ctx, c,
                    kXR_NotAuthorized, "not authorized");
                return NGX_DONE;
            }
            return NGX_OK;   /* cache hit: allowed */
        }
    }

    /* --- existing three-check path (unchanged) --- */
    ngx_int_t rc = xrootd_check_authdb(...);
    /* ... */

    /* --- store result in cache --- */
    if (conf->auth_cache_kv != NULL) {
        u_char key[32];
        xrootd_auth_cache_key(key, resolved, ctx->dn, ctx->vo_list);
        xrootd_auth_cache_val_t cv = { .allowed = 1, .auth_level = auth_level };
        xrootd_kv_set(conf->auth_cache_kv, key, sizeof(key),
                      &cv, sizeof(cv),
                      (ngx_msec_t) conf->auth_cache_ttl_secs * 1000);
    }

    return NGX_OK;
}
```

**Files changed**: `src/auth/authz/auth_gate.c` (+~30 LoC), `src/core/types/config.h` (+3 LoC)

---

## Step E — Rate limiting

**Files**: `src/core/shm/rate_limit.h` (new, ~40 LoC), `src/core/shm/rate_limit.c` (new, ~100 LoC)  
**Register in**: `config.h`  
**Integration points**: `src/auth/gsi/auth.c` (post-auth), `src/webdav/access.c` (access phase)

### Design: token bucket per identity

The token bucket algorithm uses the KV store to persist state across workers:

```c
/* Key: "rl:" prefix + DN (for stream) or client IP (for HTTP) — up to 256 bytes */
/* Value: {tokens_remaining:4, last_refill_ms:8} = 12 bytes */

typedef struct {
    uint32_t    tokens;       /* current token count */
    ngx_msec_t  last_refill;  /* ngx_current_msec at last refill */
} xrootd_rl_val_t;           /* 12 bytes */
```

**Refill logic** (executed inline on each check, under the KV zone spinlock):

```c
ngx_int_t
xrootd_rate_limit_check(xrootd_rate_limit_t *rl, const char *id, size_t id_len)
{
    char key[256 + 3];   /* "rl:" + id */
    size_t key_len = ngx_snprintf((u_char *)key, sizeof(key),
                                  "rl:%*s", id_len, id) - (u_char *)key;

    xrootd_rl_val_t v = { .tokens = rl->burst, .last_refill = ngx_current_msec };
    size_t v_len = sizeof(v);

    /* xrootd_kv_get_or_set: atomic get-then-set under the existing spinlock */
    xrootd_kv_get(rl->kv, key, key_len, &v, &v_len);

    /* Refill tokens based on elapsed time since last_refill */
    ngx_msec_t elapsed = ngx_current_msec - v.last_refill;
    uint32_t new_tokens = (uint32_t)(elapsed * rl->rate_per_ms);
    v.tokens = ngx_min(v.tokens + new_tokens, rl->burst);
    v.last_refill = ngx_current_msec;

    if (v.tokens == 0) {
        xrootd_kv_set(rl->kv, key, key_len, &v, sizeof(v), rl->window_ms);
        return NGX_HTTP_TOO_MANY_REQUESTS;  /* 429 / kXR_TooManyRequests */
    }

    v.tokens--;
    xrootd_kv_set(rl->kv, key, key_len, &v, sizeof(v), rl->window_ms);
    return NGX_OK;
}
```

**Note**: `get` + `set` are two separate lock operations, not one atomic RMW. Under
high concurrency, two workers may simultaneously read `tokens=5` and both decrement
to 4 — a small over-admission is acceptable for best-effort rate limiting. If strict
admission is required, a single `xrootd_kv_lock_get_update_set()` helper can be added
(acquire lock, read, compute, write, release — ~20 LoC), but that is not needed for the
initial implementation.

### Configuration

```nginx
xrootd_kv_zone        xrootd_rl_kv  2m key=256 val=16;

# Per-server stream block — limit by authenticated DN
xrootd_rate_limit     zone=xrootd_rl_kv rate=200r/s burst=500;

# Per-location WebDAV — limit by client IP for unauthenticated paths
xrootd_rate_limit     zone=xrootd_rl_kv rate=50r/s burst=100 key=ip;
```

New directives:
- `xrootd_rate_limit zone=<name> rate=<N>r/s burst=<N> [key=dn|ip];`

`key=dn` (default for stream/GSI): rate limit per authenticated DN.  
`key=ip`: rate limit per client IP address (used before auth completes).

**Response codes**: HTTP path → 429 Too Many Requests. Stream path → `kXR_TooManyRequests`
(if advertised in server capability flags; otherwise fall back to `kXR_NotAuthorized`).

---

## Step F — Configurable zone sizes for existing tables

Several existing tables have hard-coded compile-time sizes. Add `ngx_command_t` directives
that override the size at configure time. No SHM zone migration is needed — just pass
the directive value to `ngx_shared_memory_add()` instead of the hard-coded constant.

| Existing constant | Directive | Default | Status |
|---|---|---|---|
| `XROOTD_SESSION_REGISTRY_SLOTS` (1024) | `xrootd_session_slots <N>` | 1024 | ✅ implemented |
| `XROOTD_SRV_REGISTRY_SLOTS` (128) | `xrootd_registry_slots <N>` | 128 | ✅ implemented |
| `XROOTD_REDIR_CACHE_SLOTS` (512) | `xrootd_redir_cache_slots <N>` | 512 | ✅ implemented (flexible-array refactor) |
| `WEBDAV_LOCK_TABLE_SIZE` (1024) | `xrootd_webdav_lock_slots <N>` | — | ⛔ obsolete — Phase 16 moved locks to xattrs (no SHM table) |
| `XROOTD_TPC_REGISTRY_SLOTS` (1024) | `xrootd_tpc_slots <N>` | 1024 | ⚠️ deferred — see note below |

**Note on `xrootd_tpc_slots`**: unlike the other tables, the native-TPC transfer
registry SHM zone (`xrootd_tpc_transfers`) is created from **two** call sites —
`webdav/postconfig.c` (HTTP) and `config/postconfiguration.c` (stream) — and
`ngx_shared_memory_add()` requires both to request an identical zone size.
A per-`server`/per-`location` size directive cannot guarantee both call sites
resolve the same value (the HTTP side has no access to the stream srv conf, and
http/stream postconfiguration ordering is not fixed). Making this configurable
requires first restructuring TPC-registry creation to a single owner (or a shared
pre-postconfig resolution of the slot count). That is a focused architectural
change, not the "+10 LoC trivial" the original estimate assumed, and is left as
follow-up work. The compile-time default (1024) remains in effect.

**Implementation**: for each table, add one field to the relevant conf struct
(`ngx_uint_t session_slots; /* NGX_CONF_UNSET_UINT */`), add the directive, and pass
`conf->session_slots * sizeof(entry)` instead of the compile-time constant to
`ngx_shared_memory_add()`.

**Files changed**: `src/session/registry.c` (+~10 LoC), `src/webdav/module.c` (+~10 LoC),
`src/tpc/common/registry.c` (+~10 LoC), `src/net/manager/redir_cache.c` (+~10 LoC),
`src/core/config/directives.c` (+~40 LoC), `src/core/config/config.h` (+~5 LoC)

---

## Honest LoC accounting

```
Step A: shm_zone.h macro layer              +60 new
Step B: kv.h + kv.c (KV store)             +340 new
Step C: token_cache.h/c + validate.c hooks  +120 new
Step D: auth_cache.h/c + auth_gate.c hooks  +110 new
Step E: rate_limit.h/c                      +140 new
Step F: configurable zone sizes             +85 new
Prometheus export additions (metrics/)      +40 new
───────────────────────────────────────────────────
Gross additions:                           +895 LoC
Boilerplate reduction (if 3 existing zones
  adopt Step A macros opportunistically):  −90 LoC
───────────────────────────────────────────────────
Net:                                       +805 LoC
```

This is additive infrastructure. Unlike the refactoring phases, it adds capabilities
rather than reducing duplication. The boilerplate reduction is a long-term dividend
as existing tables are migrated opportunistically.

---

## Implementation order

| Step | Files | Prerequisite | Notes |
|------|-------|-------------|-------|
| B | `src/core/shm/kv.h`, `kv.c` | None | Foundation; no callers yet |
| A | `src/core/compat/shm_zone.h` | None | Header only; no compilation impact |
| F | existing configure() + directives.c | None | Trivial; size parameter only |
| C | `src/auth/token/token_cache.*`, `validate.c` | Step B | Token cache consumer |
| D | `src/path/auth_cache.*`, `auth_gate.c` | Step B | Auth cache consumer |
| E | `src/core/shm/rate_limit.*` | Step B | Rate limit consumer |

Steps A, B, and F are independent and can proceed in parallel. Steps C, D, E each
depend on Step B being complete and registered in `config.h`.

---

## config.h registration

```c
/* src/core/config/config.h — add to NGX_ADDON_SRCS */
$ngx_addon_dir/src/core/shm/kv.c \
$ngx_addon_dir/src/auth/token/token_cache.c \
$ngx_addon_dir/src/auth/authz/auth_cache.c \
$ngx_addon_dir/src/core/shm/rate_limit.c \
```

After adding these four lines, one `./configure ... --add-module=...` is needed, then
incremental `make -j$(nproc)` for all subsequent builds.

---

## Tests (minimum 3 per area)

### KV store (Step B)

```bash
# Validate cache hit/miss counters appear in Prometheus
curl http://localhost:9100/metrics | grep xrootd_kv_

# Validate TTL eviction: set with ttl=1s, sleep 2s, get should miss
PYTHONPATH=tests pytest tests/ -k "kv_store" -v

# Validate capacity enforcement: fill zone to >50%, get refusal
PYTHONPATH=tests pytest tests/ -k "kv_capacity" -v
```

### Token cache (Step C)

```bash
# With token cache enabled, second request with same token should hit cache
# Verify by checking Prometheus xrootd_kv_hits_total{zone="xrootd_token_kv"} increases
PYTHONPATH=tests pytest tests/test_credential_translation.py -v

# Verify expired tokens are not served from cache (present token close to expiry,
# then after expiry+1s, get should re-verify and fail)
PYTHONPATH=tests pytest tests/ -k "token_expiry" -v

# Verify cache miss on first request (cold cache)
PYTHONPATH=tests pytest tests/ -k "token_cold_cache" -v
```

### Auth result cache (Step D)

```bash
# Authorized path: second request should hit auth cache (no authdb scan)
# Verify by enabling debug logging and checking for "auth-cache: hit" log line
PYTHONPATH=tests pytest tests/ -k "auth_cache" -v

# Unauthorized path: denial should be cached and re-served from cache
PYTHONPATH=tests pytest tests/ -k "auth_deny_cached" -v

# Config reload (nginx -s reload) should reset auth cache zone
PYTHONPATH=tests pytest tests/ -k "auth_cache_reload" -v
```

### Rate limiting (Step E)

```bash
# Send N+1 requests where N = burst; last should get 429 / kXR_TooManyRequests
PYTHONPATH=tests pytest tests/ -k "rate_limit" -v

# Verify per-DN isolation: rate limit on one DN doesn't affect another DN
PYTHONPATH=tests pytest tests/ -k "rate_limit_isolation" -v

# Verify token refill: after hitting limit, wait 1/rate seconds, next request allowed
PYTHONPATH=tests pytest tests/ -k "rate_limit_refill" -v
```

---

## Known constraints and future work

| Constraint | Reason | Future fix |
|---|---|---|
| KV `set` + `get` not atomic (rate limiter) | Two separate spinlock acquisitions | Add `xrootd_kv_update()` for read-modify-write in single lock hold |
| Token cache does not detect revocation | Stateless JWT design — revocation requires OIDC token introspection endpoint | Phase 21: `xrootd_token_introspection_url` directive + async check |
| Auth cache TTL is wall-clock, not config-change-aware | nginx config reload clears zones but short TTL is the mitigation | Future: increment a config-version counter in the zone header; cache entries include version; stale version = miss |
| Linear probe degrades at load factor > 0.5 | Refusal to insert above 0.5 prevents worst-case degradation but wastes memory | Future: open-addressing with Robin Hood hashing improves average probe distance |
| Rate limiter key for stream = DN | DN is only available after kXR_auth, not during kXR_login | Pre-auth rate limiting uses client IP; post-auth uses DN |
| No zone persistence across nginx restart | Shared memory is process-lifetime; zones are re-zeroed on master restart | By design — token/auth/rate state should not persist across operator-initiated restart |

---

## Relationship to the refactor series

| Phase | Target area | Net ΔLoC |
|-------|-------------|----------|
| Phase 12 | Shared HTTP file-serve | −80–110 |
| Phase 13 | AIO task dispatch macro | −10 |
| Phase 14 | Table-driven Prometheus export | −83 |
| Phase 15 | Unified namespace layer | −16 |
| Phase 16 | Unified prop store | −277 |
| Phase 17 | Error-response macro collapse | −414 |
| Phase 18 | Auth gate completion | −47 |
| Phase 19 | HTTP/3 & QUIC support | +220 |
| **Phase 20** | SHM & KV management | **+805** |
| **Subtotal** | | **+98–68 LoC net** |

Phases 12–18 took the module from high-duplication to clean. Phases 19–20 add
capabilities. The series net is roughly zero additional LoC for a substantial feature
and correctness improvement — a good trade.
