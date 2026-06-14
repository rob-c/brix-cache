# Shared-Code Plan: Cross-Protocol Consolidation

This plan identifies code that is duplicated across the four HTTP-layer protocols
(WebDAV, XrdHttp, S3, and the stream-layer XRootD protocol) and proposes concrete
steps to consolidate it in `src/compat/`.

The goal is a smaller security surface: every security invariant — confinement,
NUL rejection, traversal blocking — maintained in one place rather than four.
This is not a refactoring-for-its-own-sake exercise.

---

## Current state: what is already shared

| Facility | Location | Used by |
|---|---|---|
| JWT / JWKS / scope validation | `src/token/` | stream, WebDAV, XrdHttp |
| XRootD confinement primitives | `src/path/resolve_confined_ops.c` | stream, WebDAV, S3 |
| Kernel-level path confinement | `xrootd_open_confined_canon` / `xrootd_unlink_confined_canon` | all HTTP ops |
| XML escape + text elements | `src/compat/xml.c` | WebDAV (via `util/xml.c`), S3 (direct) |
| Prometheus metrics export | `src/metrics/` | all four protocols |

---

## Opportunity catalogue

Each entry includes: **what** is duplicated, **where** each copy lives,
**divergences** that must be reconciled, estimated **LOC saved**, and a
**risk rating** (Low / Medium / High).

---

### 1. URL percent-decode  ★★★ highest value

**What:** HTTP percent-decode (`%HH → byte`).

**Where:**

| Copy | File | LOC | Key behaviour |
|---|---|---:|---|
| `webdav_urldecode` | `src/webdav/util/uri.c` | 65 | Rejects `%00` (NUL) → `NGX_HTTP_BAD_REQUEST`. Does NOT convert `+`. Returns `ngx_int_t`. |
| `s3_urldecode` | `src/s3/util.c` | 35 | Accepts NUL bytes (security gap). Converts `+` → space (needed for query params). Returns `ssize_t`. |

**Divergences:**
- NUL rejection: WebDAV has it; S3 lacks it. A decoded NUL in an S3 object key
  would produce a truncated C string passed to `xrootd_open_confined_canon` — the
  kernel open rejects it with `ENOENT` rather than `EINVAL`, so it is not an
  exploitable path-escape, but it silently corrupts the key and misleads error logs.
- `+` → space: Only needed for S3 query-param parsing, not for path components.

**Proposed resolution:** Extract `xrootd_http_urldecode(src, src_len, dst, dst_sz, flags)` to `src/compat/uri.c`:

```c
#define XROOTD_URLDECODE_REJECT_NUL      0x01  /* WebDAV paths */
#define XROOTD_URLDECODE_PLUS_TO_SPACE   0x02  /* S3 query params */
```

`webdav_urldecode` becomes a one-line wrapper passing `REJECT_NUL`.
`s3_urldecode` becomes a one-line wrapper, gaining `REJECT_NUL` for free.

**LOC saved:** ~80 (net, after wrapper stubs).
**Risk:** Low. Pure string processing; no nginx internals involved. Full unit-test coverage already exists via the path test suite.

---

### 2. URI-to-filesystem path resolver  ★★★ highest security value

**What:** Translate an HTTP request URI or key string into a canonicalized
filesystem path confined within `root_canon`.

**Where:**

| Copy | File | LOC | Key behaviour |
|---|---|---:|---|
| `ngx_http_xrootd_webdav_resolve_path` | `src/webdav/path.c` | 120 | URL-decodes `r->uri`, scans `..` components, calls `realpath()` twice (existing path / ENOENT parent strategy), verifies result within root. Returns `NGX_HTTP_*`. |
| `webdav_resolve_destination_path` | `src/webdav/path.c` | 100 | Same realpath strategy for pre-decoded Destination header paths (COPY/MOVE). |
| `s3_resolve_key` | `src/s3/util.c` | 45 | Concatenates root + key, scans for `..` components only. Does **not** call `realpath()`. Symlinks in the key path are **not** caught at the user-space layer. |

**Security gap in S3:** `s3_resolve_key` relies on the kernel's `RESOLVE_BENEATH`
(or `O_NOFOLLOW` fallback) inside `xrootd_open_confined_canon` to reject symlink
escapes at `open()` time. This means:

1. `s3_handle_delete` → `xrootd_unlink_confined_canon` — symlink escapes blocked
   at the `unlink()` layer.
2. `fstat(fd, …)` after a confined `open()` — always safe; fd is already confined.
3. `lstat(path, …)` calls in multipart helpers — **not** going through
   `xrootd_open_confined_canon`; symlink escapes are possible here for multipart
   staging paths.

**Proposed resolution:** Extract `xrootd_http_resolve_path(log, root_canon, raw_path, raw_len, out, outsz, flags)` to `src/compat/path.c`. Implement the full WebDAV-style strategy (realpath + parent fallback for ENOENT) so both WebDAV and S3 share one code path:

```c
#define XROOTD_RESOLVE_STRIP_TRAILING_SLASH  0x01  /* WebDAV: strip '/' from collections */
#define XROOTD_RESOLVE_ALLOW_NOT_EXIST       0x02  /* PUT/MKCOL: parent-resolution on ENOENT */
```

Replace:
- `ngx_http_xrootd_webdav_resolve_path` → thin wrapper in `path.c` with `STRIP_TRAILING_SLASH | ALLOW_NOT_EXIST`.
- `webdav_resolve_destination_path` → thin wrapper (no flags; caller has already stripped slash).
- `s3_resolve_key` → call `xrootd_http_resolve_path` with `ALLOW_NOT_EXIST`.

**LOC saved:** ~200 (net, after wrappers). Symlink escape coverage for S3 multipart
`lstat` paths as a bonus.

**Risk:** Medium. Both WebDAV and S3 call the resolver in hot paths; return code
changes (WebDAV uses `NGX_HTTP_*`; S3 currently uses `int`/`bool`) require callers
to be updated. Test coverage is strong (all 50 WebDAV tests + S3 GET/PUT/DELETE
tests exercise this path).

**Implementation order:** Path.c first, then update WebDAV callers (identical
behaviour), then S3 callers (behaviour change: returns 403 instead of 500 on
symlink escape; multipart lstat paths gain confinement).

---

### 3. errno → HTTP status mapping  ★★ medium value

**What:** Translate POSIX `errno` to an `NGX_HTTP_*` status code.

**Where:** Scattered `if (errno == ENOENT) return 404` chains in at least:

- `src/webdav/get.c`, `put.c`, `copy.c`, `move.c`, `namespace.c`
- `src/s3/object.c`, `put.c`, `multipart_helpers.c`, `multipart_complete_body.c`

Current mappings differ between WebDAV and S3:

| errno | WebDAV result | S3 result |
|---|---|---|
| `ENOENT` | 404 | 404 |
| `EACCES` | 403 | 403 |
| `ENOSPC` | 507 (WebDAV) | 500 (S3, should be 507) |
| `EROFS` | 403 | 403 |
| `EEXIST` | 409 | 409 |
| `ENAMETOOLONG` | 414 | 400 (inconsistent) |

**Proposed resolution:** Add `xrootd_http_errno_to_status(int err)` to `src/compat/errno.c`. S3 gains `ENOSPC → 507`. `ENAMETOOLONG` alignment to 414 across both protocols.

**LOC saved:** ~50 (net).
**Risk:** Low. Pure mapping table; behaviour change only in the `ENOSPC` and `ENAMETOOLONG` edge cases for S3.

---

### 4. Response header append  ★ low value

**What:** Add a single `key: value` response header.

**Where:**

- `s3_set_header` in `src/s3/object.c` (local static, also copy-pasted in `list_objects_v2.c`).
- WebDAV uses `ngx_list_push` directly from nginx's API; no helper.

**Proposed resolution:** Move `s3_set_header` to `src/s3/util.c` (S3-internal, not `src/compat/`) and remove the copy in `list_objects_v2.c`. This is an S3-only cleanup, not cross-protocol sharing.

**LOC saved:** ~20.
**Risk:** Low.

---

## What cannot and should not be shared

| Area | Reason |
|---|---|
| Auth logic (GSI / Bearer / SigV4) | Three incompatible wire formats. GSI uses X.509 proxy cert chains + VOMS. WebDAV/XrdHttp use OIDC bearer tokens. S3 uses HMAC-SHA256 request signing. A unified interface would add cost without benefit. |
| Request dispatch / routing | Stream uses a binary XProtocol framing state machine in `NGX_STREAM_CONTENT_PHASE`. HTTP modules use nginx's parsed request in `NGX_HTTP_CONTENT_PHASE`. Incompatible at the protocol layer. |
| TPC credential / header parsing | `src/webdav/tpc_headers.c` + `tpc_cred.c` are WLCG-specific. XrdHttp reuses them via symbol linkage. S3 has no TPC concept. No further sharing needed. |
| fd-cache / open-file cache | WebDAV `get.c` uses nginx's `ngx_open_cached_file` for hot-path GET. S3 opens fresh per request. Sharing would require S3 to adopt the nginx `open_file_cache` directive and module infrastructure — worthwhile only if S3 GET is benchmarked as hot. File a separate performance ticket if needed. |
| XML response builders | WebDAV PROPFIND (`propfind.c`, 564 LOC) and S3 list (`list_objects_v2.c`) both use `ngx_chain_t`-based XML. They already share the escape/element primitives in `src/compat/xml.c`. The higher-level serialization format (MultiStatus vs ListBucketResult) is protocol-specific; unifying it further would produce leaky abstractions. |

---

## Phased implementation

### Phase A — URL decode (1 day, no behaviour change)

1. Add `src/compat/uri.c` + `src/compat/uri.h` with `xrootd_http_urldecode`.
2. Replace `webdav_urldecode` body with a one-line wrapper.
3. Replace `s3_urldecode` body with a one-line wrapper; add `REJECT_NUL` flag.
4. Add `src/compat/uri.c` to `config` `ngx_module_srcs`.
5. Build + full test run. No behaviour change expected.

### Phase B — errno mapping (0.5 day)

1. Add `src/compat/errno.c` + `src/compat/errno.h` with `xrootd_http_errno_to_status`.
2. Update S3 call sites in `object.c`, `put.c`, `multipart_helpers.c`.
3. Update WebDAV call sites in `get.c`, `put.c`, `copy.c`, `move.c`.
4. Build + full test run. Behaviour change only in `ENOSPC` (S3: 500→507) and
   `ENAMETOOLONG` (S3: 400→414) edge cases — verify no test relies on old codes.

### Phase C — shared path resolver (2–3 days, medium risk)

1. Add `src/compat/path.c` + `src/compat/path.h` with `xrootd_http_resolve_path`.
   Implement the realpath + ENOENT-parent strategy from `webdav/path.c`.
2. Update WebDAV callers in `path.c` to use the shared function. Full WebDAV test
   suite must pass before touching S3.
3. Update `s3_resolve_key` to call `xrootd_http_resolve_path`. S3 now gains:
   - `realpath()` symlink rejection (user-space layer, before kernel confinement).
   - `ENOENT` parent verification for PUT targets.
   - Consistent 403 on traversal attempts.
4. Audit S3 multipart `lstat` call sites — replace with `xrootd_open_confined_canon`
   + `fstat` where possible (removes the remaining unconfined stat paths).
5. Build + full test run. 3 tests per change: success + error + security-negative
   (path traversal attempt must return 403, not 500).

### Phase D — S3 header helper cleanup (0.5 day, cosmetic)

1. Move `s3_set_header` to `src/s3/util.c`.
2. Remove duplicate in `list_objects_v2.c`.
3. Build + test.

---

## Metrics

| Phase | LOC removed (gross) | LOC added (compat layer) | Net reduction |
|---|---:|---:|---:|
| A — urldecode | ~100 | ~90 | −10 |
| B — errno | ~60 | ~25 | −35 |
| C — path resolver | ~265 | ~140 | −125 |
| D — S3 header | ~20 | 0 | −20 |
| **Total** | **~445** | **~255** | **−190** |

The net LOC reduction is modest. The primary payoff is **security surface
reduction**: traversal checking and NUL rejection live in one audited function
rather than three separately-evolved copies.

---

## Testing requirements

Per CLAUDE.md: 3 tests per change: success + error + security-negative.

Security-negative tests that must exist after Phase C:
- `test_get_path_traversal_s3` — GET `/bucket/../../etc/passwd` → 403.
- `test_put_symlink_escape_s3` — PUT to a key that resolves via symlink outside
  root → 403 (currently: EXDEV from kernel → 500; after Phase C: 403).
- `test_nul_byte_in_s3_key` — GET with `%00` in key → 400 (currently: passes NUL
  through; after Phase A: 400).
