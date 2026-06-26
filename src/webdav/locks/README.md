# webdav/locks — WebDAV LOCK request-header & body parsers

## Overview

This subsystem is the **request-parsing layer** for WebDAV locking (RFC 4918,
`LOCK`/`UNLOCK`). It does **not** hold lock state and owns no storage — it is a
set of small, pure-ish helpers that extract the four pieces of client intent a
lock operation needs from the incoming HTTP request: the requested timeout, the
lock token presented in `If`/`Lock-Token`, the operation depth, and the lock
owner/scope from the XML request body. Each helper takes an
`ngx_http_request_t *` and returns a parsed primitive (msec, int, `ngx_int_t`
status, or fills a caller-owned buffer).

It exists to keep the lock *state machine* in `../lock.c` readable. `lock.c`
implements `webdav_handle_lock`/`webdav_handle_unlock` and the
`webdav_check_locks` / `webdav_check_locks_tree` gates that every mutating
WebDAV method calls before touching the filesystem; the header/body decoding
chores are factored out here so that file can focus on the actual lock logic
(read existing xattr, decide refresh vs. create vs. 423, persist). In the
request lifecycle these helpers run inside `../lock.c` after the access-phase
auth/CORS/scope checks and after `resolve_path()` has confined the target path
— i.e. they only ever see an already-authorized, already-confined request.

The actual lock record is stored as a **single extended attribute on the locked
resource** (`webdav_lock_xattr_t`, encoded by `../prop_xattr.c` under
`WEBDAV_LOCK_XATTR_KEY`), not in a shared-memory slot table. Lock creation is
serialized by the kernel via `XATTR_CREATE`; checking for a lock is an
`O(path_depth)` walk of xattr reads from the target up to the export root. The
parsers here feed that flow: `webdav_lock_parse_body` fills the `owner`/
`exclusive` fields, `webdav_lock_parse_timeout` computes the absolute
`expires`, `webdav_lock_if_header_matches` matches a presented token against an
existing record's `token`, and `webdav_lock_parse_depth` rejects malformed
`Depth` headers.

Only the WebDAV/`davs://`/`http://` HTTP protocol path uses this code; the
`root://` stream protocol and S3 REST surface have no notion of WebDAV locks.

## Files

| File | Responsibility |
|------|----------------|
| `request.c` | The four LOCK request parsers: `webdav_lock_parse_timeout` (decode `Timeout: Second-N`/`Infinite`, clamp to `conf->lock_timeout`, return absolute wall-clock (`ngx_time()` seconds) expiry), `webdav_lock_if_header_matches` (substring-match a token in the `If` header, falling back to `Lock-Token` for non-conformant clients), `webdav_lock_parse_depth` (parse `Depth: 0`/`infinity`, default infinity, `400` on anything else), `webdav_lock_parse_body` (extract owner + exclusive/shared scope from the `<lockinfo>` XML body via the shared XML parser). |
| `request.h` | Public prototypes for the four parsers; includes `../webdav.h` for `ngx_http_request_t`, `ngx_http_xrootd_webdav_loc_conf_t`, and the `webdav_tpc_find_header` helper. Guard `XROOTD_WEBDAV_LOCKS_REQUEST_H`. |

> Build registration is in the top-level `config` script (`request.h` ~line 225,
> `request.c` ~line 572 in `NGX_ADDON_SRCS`/`NGX_ADDON_DEPS`), **not** in
> `src/config/config.h`. A new source file in this directory must be added there
> and picked up by re-running `./configure`.

## Key types & data structures

This subsystem defines **no types of its own**. The structures it reads from and
writes into are owned elsewhere:

- **`webdav_lock_xattr_t`** (`../webdav.h`) — the persisted lock record:
  `char token[64]` (`opaquelocktoken:UUID`), `char owner[256]`,
  `int64_t expires` (absolute Unix **wall-clock** seconds, `ngx_time()`-based —
  reboot-stable, unlike the monotonic `ngx_current_msec`), the `exclusive` /
  `depth_infinity` bitfields, and `is_null` (lock-null placeholder). `request.c`
  populates the `owner`, `exclusive`, and (via the returned expiry) `expires`
  fields that `../lock.c` then stamps into this struct before calling
  `webdav_lock_xattr_write`. The xattr value is schema `v=2`; a legacy `v`-less
  record (monotonic expiry) is decoded as already-expired so it is released.
- **`ngx_http_xrootd_webdav_loc_conf_t::lock_timeout`** (`../webdav.h`, line
  175) — per-location maximum lock lifetime in seconds; the upper clamp and the
  value substituted for a `Timeout: Infinite` request.
- **`ngx_table_elt_t`** — nginx's header element, the input these parsers read
  via `webdav_tpc_find_header`.

## Control & data flow

**Entry:** every function here is called only from `../lock.c`
(`webdav_handle_lock`, `webdav_handle_unlock`, and the
`webdav_check_locks`/`check_locks_descendants` gates). There is no other caller.

- `webdav_lock_parse_timeout` → reads the `Timeout` header, clamps to
  `conf->lock_timeout`, returns `ngx_time() + seconds` (absolute wall-clock) →
  `../lock.c` stores it in `webdav_lock_xattr_t.expires`.
- `webdav_lock_if_header_matches` → reads `If` (or legacy `Lock-Token`) →
  `../lock.c` uses the boolean to decide *refresh* (token matches the existing
  xattr record) vs. *423 Locked* (conflicting lock) vs. *create*.
- `webdav_lock_parse_depth` → reads `Depth` → returns `NGX_OK` (with
  `depth_infinity` set) or `NGX_HTTP_BAD_REQUEST`.
- `webdav_lock_parse_body` → reads the buffered request body and delegates to
  `xrootd_xml_parse_lockinfo` in [`../../compat/xml.c`](../../compat/README.md)
  to extract `owner` and `exclusive`.

**Calls out to:**
- [`../../compat/xml.c`](../../compat/README.md) — `xrootd_xml_parse_lockinfo`
  (XXE-hardened libxml2 parse of the `<lockinfo>` body).
- `webdav_tpc_find_header` (declared in `../webdav.h`, defined in
  `../xrdhttp.c`) — the canonical header-lookup helper.

**Consumed by (the lock state machine and its callers):**
- `../lock.c` — turns these parsed primitives into `webdav_lock_xattr_t`
  reads/writes and the `423`/`507`/`200` responses.
- Path-confinement and the actual xattr persistence: `../prop_xattr.c`
  (`webdav_lock_xattr_read/write/delete`) and
  [`../../path/README.md`](../../path/README.md) (`resolve_path`/RESOLVE_BENEATH
  runs before any of this).
- Mutating methods that gate on locks before acting: `../dispatch.c`,
  `../methods_basic.c` (DELETE), `../copy.c`, `../move.c`, `../namespace.c`.

## Invariants, security & gotchas

- **No path/syscall access here.** These helpers operate purely on already-parsed
  HTTP headers and the buffered request body. They never touch the filesystem and
  must never be given a raw client path — confinement
  ([`../../path/README.md`](../../path/README.md), `openat2`+`RESOLVE_BENEATH`)
  is the caller's responsibility and has already happened by the time `../lock.c`
  invokes them.
- **Timeout is always clamped and bounded.** `webdav_lock_parse_timeout`
  (`request.c:35-36`) forces the result into `[1, conf->lock_timeout]` seconds —
  a hostile or absent `Timeout` header can never produce a zero/negative or
  unbounded lifetime. `Timeout: Infinite` is *not* honored literally; it is
  capped to `conf->lock_timeout`. Malformed `Second-N` falls back to the 3600s
  default.
- **`If`-header matching is intentionally lenient.** `webdav_lock_if_header_matches`
  does a `ngx_strstr` substring search of the token inside the header value
  (rather than full RFC 4918 `If` tagged-list parsing) and falls back to the
  `Lock-Token` header for clients that misuse it on refresh (`request.c:48-54`).
  This is a deliberate compatibility choice — reviewers should know it is *not* a
  full `If:` grammar implementation.
- **`If`/`Lock-Token` values are NUL-relied via `ngx_strstr`.** The match uses
  `ngx_strstr` on `h->value.data`; nginx header values are NUL-terminated, so
  this is safe for headers, but note it differs from the length-bounded
  (`.len`-based) discipline used elsewhere in the module.
- **Body parsing is size-guarded upstream.** `webdav_lock_parse_body` hands the
  raw buffer to `xrootd_xml_parse_lockinfo`, which enforces
  `XROOTD_XML_MAX_LOCKINFO_BODY` and parses with `XML_PARSE_NONET` +
  `XML_PARSE_NO_XXE` (no external entities / network) — the anti-XXE protection
  lives in `compat/xml.c`, not here.
- **Defaults are RFC-fail-safe.** `webdav_lock_parse_body` defaults
  `exclusive = 1` (RFC 4918 §9.10) and writes `owner[0]='\0'` before parsing,
  so a missing/garbled body yields a valid exclusive lock with an empty owner
  rather than uninitialized state. `webdav_lock_parse_depth` defaults to depth
  *infinity* when the header is absent.
- **Stale doc note:** older notes describe a fixed 1024-slot shared-memory lock
  table returning `507` at capacity. That design has been **replaced** by the
  per-resource xattr scheme (see the header comment in `../lock.c:4-10`): no SHM,
  no mutex, `XATTR_CREATE` gives kernel-serialized atomic creation, and a
  startup sweep (`webdav_lock_startup_sweep`) can purge persisted locks. Lock
  capacity is no longer a fixed slot count.

## Entry points / extending

To add support for a **new LOCK request header or body element**:

1. Add a parser to `request.c` following the existing shape — take
   `ngx_http_request_t *r`, fetch the header with
   `webdav_tpc_find_header(r, "Name", sizeof("Name")-1)`, and return a parsed
   primitive (clamp/validate aggressively; never trust client input).
2. Declare its prototype in `request.h`.
3. Call it from the relevant point in `../lock.c` (`webdav_handle_lock` /
   `webdav_handle_unlock` / `webdav_check_locks`) and stamp the result into the
   `webdav_lock_xattr_t` record if it must persist.
4. For body fields, prefer extending `xrootd_xml_parse_lockinfo` in
   `../../compat/xml.c` over hand-rolling XML parsing here.
5. If you add a **new `.c` file** in this directory, register it in the
   top-level `config` script (`NGX_ADDON_SRCS`/`NGX_ADDON_DEPS`) and re-run
   `./configure` — not in `src/config/config.h`.
6. Per the project rule, ship 3 tests with the change: success, error
   (malformed/oversized header or body), and a security-negative
   (e.g. token spoof / XXE / unbounded timeout attempt).

## See also

- [`../README.md`](../README.md) — WebDAV subsystem overview and method router
  (the lock state machine `lock.c` and its xattr persistence `prop_xattr.c` live
  one level up).
- [`../../compat/README.md`](../../compat/README.md) — `xrootd_xml_parse_lockinfo`
  and the XML/HTTP-header compatibility helpers.
- [`../../path/README.md`](../../path/README.md) — path confinement /
  RESOLVE_BENEATH applied before any lock operation.
- [`../../README.md`](../../README.md) — master subsystem index.
