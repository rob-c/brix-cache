# Phase 16 — Lock + Dead Props → Unified Prop Store

**Target**: migrate WebDAV lock persistence from a fixed-size shared-memory
slot table to extended attributes (xattrs), putting lock state in the same
storage layer as dead properties and eliminating the SHM lock infrastructure
entirely.

**Net LoC reduction**: ~290–320 LoC  
**Risk**: medium — behaviour change (locks survive restarts) and new lock
atomicity model; all RFC 4918 §7 lock semantics must be re-validated by tests  
**Requires**: `./configure` + `make -j$(nproc)` — `webdav/prop_xattr.c` is a
new source file

---

## What "unified prop store" means

Both dead properties and lock state are WebDAV _properties_ on resources:

| Property class | RFC | Current backend | New backend |
|---------------|-----|-----------------|-------------|
| Dead properties (arbitrary client XML) | RFC 4918 §4.2 | xattrs (`user.nginx_xrootd.webdav.*`) | unchanged |
| Lock state (`lockdiscovery`, `supportedlock`) | RFC 4918 §7 | SHM slot table + mutex | xattrs (`user.nginx_xrootd.lock.*`) |

After this phase both classes share the same storage layer, the same copy
propagation path, and the same "moves with the file" semantic.

---

## What changes

### Removed: SHM lock table infrastructure (~92 LoC)

**`webdav/webdav.h`**:
- Delete `webdav_lock_entry_t` struct (~26 LoC)
- Delete `webdav_lock_table_t` struct (~4 LoC)
- Delete `#define WEBDAV_LOCK_TABLE_SIZE` (1 LoC)

**`webdav/lock.c`**:
- Delete `static ngx_shmtx_t webdav_lock_mutex` (2 LoC)
- Delete `webdav_lock_init_shm()` (39 LoC)

**`webdav/config.c`**:
- Delete `shm_zone` registration and `lock_shm_zone` field wiring (~20 LoC)

### Removed: SHM scan loops inside lock handlers (~211 LoC)

**`webdav_check_locks()`** (currently 83 LoC):

The current implementation scans all 1024 SHM slots under a mutex, matching
exact path and depth-infinity parent paths.

After: walk parent path components checking `user.nginx_xrootd.lock.token`
xattr on each. For a path `/a/b/c/file`, check:
1. `/a/b/c/file` — direct lock
2. `/a/b/c` — depth-infinity from parent
3. `/a/b` — depth-infinity from grandparent
4. ... up to export root

This is O(path_depth) xattr reads vs O(1024) SHM slot iterations. For typical
HEP paths (depth 5–8) this is 5–8 syscalls vs 1024 comparisons, so faster for
the common case of no locks.

New implementation: ~35 LoC.  **Saves ~48 LoC.**

**`webdav_handle_lock()`** (currently 149 LoC):

The current implementation:
- Scans 1024 slots under mutex to find existing lock to refresh or conflicts
- Allocates free slot and writes lock entry

After:
- `getxattr(path, "user.nginx_xrootd.lock", ...)` to probe existing lock
- If present and client holds matching token: update `expires`
- If present and client does NOT hold token: return 423 Locked
- If absent: `setxattr(path, ..., XATTR_CREATE)` to atomically create
- `XATTR_CREATE` semantics: fails with `EEXIST` if another worker just created
  a lock between probe and creation → return 423 Locked (correct behavior)

New implementation: ~70 LoC.  **Saves ~79 LoC.**

**`webdav_handle_unlock()`** (currently 79 LoC):

After: `getxattr(path, ...)` to read lock, verify token via
`CRYPTO_memcmp`, then `removexattr(path, ...)`.

New implementation: ~35 LoC.  **Saves ~44 LoC.**

**`webdav_lock_append_discovery()`** (currently 70 LoC):

After: `getxattr(path, ...)` to read lock entry, parse, emit
`<D:activelock>` XML. No mutex, no loop.

New implementation: ~30 LoC.  **Saves ~40 LoC.**

### New: xattr lock encoding (in `webdav/prop_xattr.c`, new file)

Lock state is encoded as a single xattr value under key
`user.nginx_xrootd.lock` using pipe-delimited ASCII:

```
token=opaquelocktoken:UUID|owner=DN|expires=1234567890123|scope=exclusive|depth=infinity
```

- `expires` is milliseconds since epoch (same as `ngx_current_msec` units)
- `scope` is `exclusive` or `shared`
- `depth` is `0` or `infinity`

Single xattr per lock ensures atomic read/write — one `getxattr`/`setxattr`
call reads or writes all lock fields together.

**New functions** in `webdav/prop_xattr.c` (~50 LoC total):

```c
/* Encode lock entry into the xattr wire format. */
ngx_int_t webdav_lock_xattr_encode(const webdav_lock_xattr_t *e,
    char *out, size_t outsz);

/* Decode xattr wire format into a lock entry; returns NGX_DECLINED if
 * the xattr is absent or malformed, NGX_OK on success. */
ngx_int_t webdav_lock_xattr_decode(const char *raw, size_t rawlen,
    webdav_lock_xattr_t *e);

/* Write a lock entry to path.  flags = XATTR_CREATE or XATTR_REPLACE. */
ngx_int_t webdav_lock_xattr_write(ngx_log_t *log, const char *path,
    const webdav_lock_xattr_t *e, int flags);

/* Read the lock entry on path.  Returns NGX_DECLINED if no lock present,
 * NGX_OK on success (e filled), NGX_ERROR on I/O failure. */
ngx_int_t webdav_lock_xattr_read(ngx_log_t *log, const char *path,
    webdav_lock_xattr_t *e);

/* Remove the lock xattr.  Idempotent — ENODATA treated as success. */
ngx_int_t webdav_lock_xattr_delete(ngx_log_t *log, const char *path);
```

`webdav_lock_xattr_t` replaces `webdav_lock_entry_t` from webdav.h:

```c
#define WEBDAV_LOCK_XATTR_KEY    "user.nginx_xrootd.lock"
#define WEBDAV_LOCK_XATTR_MAXLEN  512

typedef struct {
    char        token[64];      /* opaquelocktoken:UUID */
    char        owner[256];     /* DN or free-form owner */
    ngx_msec_t  expires;        /* absolute expiry in msec */
    unsigned    exclusive:1;
    unsigned    depth_infinity:1;
} webdav_lock_xattr_t;
```

### New: shared xattr copy helper in `webdav/prop_xattr.c` (~25 LoC)

`dead_props.c` `webdav_dead_props_copy()` (35 LoC) and `namespace_ops.c`
`xrootd_ns_copy_fattrs()` (37 LoC) are structurally identical:

```c
/* Both do:
 * 1. listxattr(src, NULL, 0) → get required buffer size
 * 2. ngx_alloc() the name list
 * 3. listxattr(src, list, len) → fill the list
 * 4. for each name starting with <prefix>: getxattr → setxattr(dst)
 * 5. ngx_free(list)
 */
```

**Add to `webdav/prop_xattr.c`**:

```c
void webdav_xattr_copy_by_prefix(ngx_log_t *log,
    const char *src, const char *dst,
    const char *prefix, size_t prefix_len,
    size_t value_max);
```

**Callers become one-liners**:

```c
/* In dead_props.c — replaces 35 LoC with 4 LoC */
void webdav_dead_props_copy(ngx_log_t *log, const char *src, const char *dst)
{
    webdav_xattr_copy_by_prefix(log, src, dst,
        WEBDAV_DEAD_PROP_PREFIX, WEBDAV_DEAD_PROP_PREFIX_LEN,
        WEBDAV_DEAD_PROP_VALUE_MAX);
}

/* In namespace_ops.c — replaces 37 LoC with 4 LoC */
void xrootd_ns_copy_fattrs(ngx_log_t *log, const char *src, const char *dst)
{
    webdav_xattr_copy_by_prefix(log, src, dst,
        XROOTD_FATTR_XKEY_PFX, XROOTD_FATTR_XKEY_PFX_LEN,
        XROOTD_FATTR_MAX_VBUF);
}
```

**Saves ~68 LoC net** (removes 35 + 37, adds helper body ~25 + two 4-LoC calls).

Wait — `namespace_ops.c` is in `compat/` and importing from `webdav/` would
create a reverse dependency.  Resolution: move `webdav_xattr_copy_by_prefix()`
to **`compat/namespace_ops.c`** itself (it already imports path.h and fattr.h)
and expose it via `compat/namespace_ops.h`.  `dead_props.c` then calls the
function from that header.

### `webdav_lock_append_supported()` — unchanged (21 LoC)

This function emits static XML; it does not touch SHM or xattrs.

### `webdav_lock_xml_response()` — unchanged (72 LoC)

The XML format is identical; just the struct type changes from
`webdav_lock_entry_t` to `webdav_lock_xattr_t`.

---

## Atomicity model

### Lock creation

```
1. getxattr(path, LOCK_KEY)    — probe for existing lock
2. if present and token matches: refresh (XATTR_REPLACE) → 200 OK
3. if present and no token:     return 423 Locked
4. if absent:
   a. setxattr(path, LOCK_KEY, ..., XATTR_CREATE)
   b. if EEXIST: another worker won the race → return 423 Locked
   c. otherwise: return 201 Created
```

`XATTR_CREATE` makes step 4a atomic — if two workers race on the same
previously-unlocked resource, exactly one will succeed.

### Lock check (pre-operation guard)

For a path with N components, check at most N xattrs:

```c
for each prefix of path (from full path up to export root):
    rc = webdav_lock_xattr_read(log, prefix, &e);
    if rc == NGX_ERROR: return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if rc == NGX_DECLINED: continue;   /* no lock here */
    if expired(e): webdav_lock_xattr_delete(log, prefix); continue;
    if full path == prefix OR (e.depth_infinity && is_prefix_of(prefix, path)):
        if !webdav_lock_if_header_matches(r, e.token): return NGX_HTTP_LOCKED;
```

This walk terminates at the export root.  The existing
`webdav_lock_if_header_matches()` function is unchanged.

### Shared-lock support

RFC 4918 §7.5 permits multiple shared locks on one resource.  The current SHM
implementation tracks them in separate slots.  A single xattr supports at most
one lock token.

**Decision**: support only one lock per resource (exclusive or shared) in the
xattr model.  This is RFC-conformant for exclusive locks; shared lock
multiplicity (rare in practice with single-writer HEP workflows) is preserved
as a warning in the response rather than a hard requirement.  If a `<shared/>`
LOCK request arrives on an already-shared-locked path from the same client
(token matches), refresh the lock.

This simplification removes ~15 LoC of shared-lock conflict logic from
`webdav_handle_lock()`.

---

## Configuration simplification

**Before** (in `webdav/config.c`): `xrootd_webdav_lock_zone size=512k` directive allocates the SHM zone. This directive and its parser (~20 LoC) are removed.

**After**: no configuration needed — lock xattrs are stored on the files
themselves. The lock timeout directive (`lock_timeout`) remains unchanged.

The `lock_shm_zone` field in `ngx_http_xrootd_webdav_loc_conf_t` is removed.

---

## Behaviour changes and tradeoffs

| Aspect | Before (SHM) | After (xattr) |
|--------|-------------|---------------|
| Lock persistence | Lost on nginx restart | Survives restart |
| RFC 4918 §10.1 compliance | Compliant (ephemeral) | Diverges (persistent) — stale locks cleanable via UNLOCK |
| Max active locks | 1024 (WEBDAV_LOCK_TABLE_SIZE) | Unlimited (filesystem capacity) |
| Check cost | O(1024) SHM iterations + mutex | O(path_depth) xattr reads (5–10 typical) |
| Memory overhead | Fixed 1024×sizeof(entry) SHM | Zero (per-file, on demand) |
| Cross-worker | Mutex serialized | Kernel-serialized (atomic XATTR_CREATE) |
| Depth-infinity inherited locks | Inline in SHM scan | Walk parent dirs (additional syscalls) |
| Stale lock cleanup | Automatic on next SHM scan | Lazy: cleaned on next access to that path |

**The persistent-lock tradeoff is the most significant change.** In HEP
deployments, nginx is rarely restarted while jobs are running, and any
remaining locks after a restart were already stale. Clients that UNLOCK
explicitly (the correct pattern) are unaffected. A startup sweep can
optionally evict all lock xattrs if strict RFC compliance is required:

```c
/* Optional: in webdav_postconfig(), walk export root and remove all
 * "user.nginx_xrootd.lock" xattrs to restore ephemeral behaviour. */
```

If the startup sweep is implemented it restores exact current semantics and
removes the compliance concern.

---

## Honest LoC accounting

```
Removed from webdav/webdav.h (structs):             − 31 LoC
Removed from webdav/config.c (shm setup):           − 20 LoC
Removed from webdav/lock.c:
  webdav_lock_mutex global + init_shm:              − 41 LoC
  webdav_check_locks (83 → 35):                     − 48 LoC
  webdav_handle_lock (149 → 70):                    − 79 LoC
  webdav_handle_unlock (79 → 35):                   − 44 LoC
  webdav_lock_append_discovery (70 → 30):           − 40 LoC
Removed from dead_props.c (copy → helper call):     − 30 LoC
Removed from namespace_ops.c (copy → helper call):  − 32 LoC
───────────────────────────────────────────────────────────────
Total removed:                                      −365 LoC

New webdav/prop_xattr.c (encode/decode/read/write/delete + copy helper):
                                                    + 75 LoC
New struct webdav_lock_xattr_t in webdav.h:         + 10 LoC
Declaration in namespace_ops.h (xattr_copy_by_prefix):
                                                    +  3 LoC
───────────────────────────────────────────────────────────────
Total added:                                        + 88 LoC

Net:                                               −277 LoC
```

Uncertainty ±30 LoC depending on exact blank-line and comment counts.

---

## Implementation steps

1. **Add `webdav_lock_xattr_t` struct** to `webdav/webdav.h`; remove
   `webdav_lock_entry_t` and `webdav_lock_table_t`.

2. **Write `webdav/prop_xattr.c`** with the five lock xattr functions and
   the shared `xrootd_xattr_copy_by_prefix()` helper.  Register in the `config`
   shell script (`NGX_ADDON_SRCS`).  Run `./configure` once.

3. **Update `compat/namespace_ops.c`**: replace `xrootd_ns_copy_fattrs()` body
   with the helper call.  Declare in `namespace_ops.h`.

4. **Update `webdav/dead_props.c`**: replace `webdav_dead_props_copy()` body
   with the helper call.

5. **Rewrite `webdav/lock.c`**:
   - Delete `webdav_lock_mutex`, `webdav_lock_init_shm()`
   - Replace `webdav_check_locks()` with parent-walk implementation
   - Replace `webdav_handle_lock()` with xattr read/create flow
   - Replace `webdav_handle_unlock()` with xattr read/delete flow
   - Replace `webdav_lock_append_discovery()` with xattr read + XML emit
   - Keep `webdav_generate_uuid()`, `webdav_lock_xml_response()`,
     `webdav_lock_append_supported()` verbatim

6. **Update `webdav/config.c`**: remove `lock_shm_zone` allocation; remove
   `lock_shm_zone` field from `ngx_http_xrootd_webdav_loc_conf_t`.

7. **Optional** (implemented): add a user-configurable startup xattr sweep for
   strict RFC 4918 ephemeral compliance. Exposed as the
   `xrootd_webdav_lock_startup_sweep on|off` directive (default `off`). The
   sweep runs in `merge_loc_conf` once the per-location export `root_canon` is
   resolved (not `postconfig`, which only sees server-level config), and is
   guarded by `!ngx_test_config` so `nginx -t` never mutates the filesystem.
   Implementation: `webdav_lock_startup_sweep()` in `webdav/lock.c`
   (recursive `xrootd_fs_walk` + `removexattr`). Tests:
   `tests/test_webdav_lock_startup_sweep.py`.

8. **Build and test**:
   ```bash
   ./configure --with-stream --with-http_ssl_module --with-http_dav_module \
       --with-threads --add-module=$REPO && make -j$(nproc)
   /tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf
   ```

---

## Tests (minimum 3)

```bash
# LOCK / UNLOCK RFC 4918 protocol conformance
PYTHONPATH=tests pytest tests/test_conformance.py -v -k "lock or unlock"
PYTHONPATH=tests pytest tests/test_a_webdav_clients.py -v

# Lock conflict checking (423 Locked on competing LOCK)
PYTHONPATH=tests pytest tests/ -k "lock_conflict or lock_423" -v

# COPY / MOVE propagate dead properties correctly (uses shared xattr_copy)
PYTHONPATH=tests pytest tests/ -k "webdav and copy or move" -v
```

Additional manual checks:
1. Lock a file, restart nginx, verify the lock is still present (xattr survived)
2. Lock with `Depth: infinity`, attempt DELETE on child — confirm 423
3. Lock a file, let it expire, attempt a new LOCK — confirm it succeeds
4. Concurrent LOCK from two workers on the same path — confirm exactly one
   gets 201 Created and the other gets 423 Locked

---

## Relationship to overall 10% target

This phase contributes **~277 LoC net** — the largest single reduction in the
series. Combined with phases 12–15:

```
Phase 12 (shared HTTP file-serve):            − 80–110 LoC
Phase 13 (aio task dispatch macro):           −      10 LoC
Phase 14 (table-driven metrics):              −      83 LoC
Phase 15 (unified namespace layer):           −      16 LoC
Phase 16 (unified prop store):                −     277 LoC
──────────────────────────────────────────────────────────
Subtotal phases 12–16:                        −466–496 LoC
```

A 10% reduction on a ~8,000 LoC codebase requires ~800 LoC removed.
Phases 12–16 deliver roughly half that target; additional phases should
focus on the remaining ~300+ LoC gap.
