# webdav/methods — Per-method WebDAV precondition helpers

## Overview

This subsystem holds small, method-specific helper logic that the main WebDAV
method handlers (`../get.c`, `../put.c`, `../copy.c`, `../move.c`, …) factor out
when the rule is too specialized to live in the generic `compat` HTTP layer but
too narrow to belong in the handler body. Today it contains exactly one helper:
the RFC 9110 / RFC 7232 conditional-precondition check for the **COPY** method's
*destination* resource.

It sits late in the WebDAV request lifecycle: after the access-phase auth/CORS/
write/scope checks and after `../dispatch.c` has routed the request to the COPY
content handler, `../copy.c` resolves and `stat`s both source and destination
under the export root, runs lock checks (`webdav_check_locks_tree`) and the
`Overwrite:` header check, then calls into this subsystem to evaluate
`If-Match` / `If-None-Match` against the destination before any bytes are
copied. The point is optimistic concurrency control: a COPY that ignores
conditionals can silently clobber a destination another client just modified.

This is a thin, deliberately-dumb wrapper. The actual ETag generation, list
parsing, and wildcard (`*`) semantics live in the shared
`../../compat/http_conditionals.c` / `../../compat/etag.c` helpers so that
WebDAV and S3 agree on conditional-request behaviour. This file's only added
value is to invoke that helper with COPY's policy (weak ETags, no weak-equiv
comparison flag) and to emit COPY-specific debug logging naming the destination
path on failure.

## Files

| File | Responsibility |
|------|----------------|
| `copy_conditionals.c` | `webdav_check_copy_conditionals()` — evaluate `If-Match`/`If-None-Match` against the COPY destination via the shared ETag-precondition helper; log destination context on failure. |
| `copy_conditionals.h` | Prototype for `webdav_check_copy_conditionals()`; pulls in `../webdav.h` and `<sys/stat.h>` for the `struct stat *` destination metadata. |

## Key types & data structures

This subsystem defines no types of its own. It operates on caller-supplied
state:

- `ngx_http_request_t *r` — the live COPY request; conditional headers are read
  from `r->headers_in` by the delegated helper.
- `const char *dst_path` — the resolved (confined) destination path, used only
  for debug logging here (path confinement already happened in `../copy.c`).
- `int dst_exists` — whether the destination currently exists (`stat() == 0` in
  the caller); drives `If-None-Match: *` "create-only" semantics.
- `const struct stat *dst_sb` — destination `stat` metadata; its `st_mtime` +
  `st_size` are what the shared helper turns into the destination ETag.

Relevant shared constants it passes through:
`XROOTD_ETAG_WEAK` (`../../compat/etag.h`) selects an RFC 7232 §2.1 weak ETag
(`W/"mtime-size"`); the final `condition_flags` argument is `0` (the
`XROOTD_HTTP_COND_WEAK_EQUIV` weak-equivalence flag is intentionally *not* set
for COPY).

## Control & data flow

**Entry:** the single public function

```c
ngx_int_t webdav_check_copy_conditionals(ngx_http_request_t *r,
    const char *dst_path, int dst_exists, const struct stat *dst_sb);
```

is called from one place: `../copy.c:306`, inside the COPY handler, after the
destination has been resolved and `stat`ed and after the lock-tree /
`Overwrite:` checks.

**Calls out to:**

- `xrootd_http_check_etag_preconditions()` (`../../compat/http_conditionals.c`)
  — does the real work: builds the destination ETag from `dst_sb`, parses the
  `If-Match` / `If-None-Match` header lists, applies wildcard semantics, and
  returns `NGX_OK`, `NGX_HTTP_NOT_MODIFIED` (304), or
  `NGX_HTTP_PRECONDITION_FAILED` (412).
- `xrootd_http_etag_str()` (`../../compat/etag.c`, via the helper above) — the
  underlying `mtime-size` → ETag string formatter, shared with S3 and PROPFIND.
- `ngx_log_debug1()` — COPY-specific failure logging only.

**Returns to caller:** the helper's return code is propagated verbatim. In
`../copy.c`, any non-`NGX_OK` result short-circuits the COPY before the
collection/file copy path (`webdav_copy_collection_*` /
`../io.c`/`../resource.c`) runs, so a failed precondition means nothing is
written.

Sibling subsystems in the same request:
[../README.md](../README.md) (WebDAV method router and handlers),
[../../compat/README.md](../../compat/README.md) (shared ETag / conditional /
header helpers), [../../path/README.md](../../path/README.md) (the confinement
that produced `dst_path` before this runs).

## Invariants, security & gotchas

- **This file does no path confinement and no syscalls of its own.** It trusts
  that `dst_path` / `dst_sb` were already produced by the confined resolve +
  `stat` in `../copy.c`. Do not add a raw `stat`/`open` on a client path here —
  per the module-wide invariant, all client paths must pass through
  `../../path/beneath.c` (`RESOLVE_BENEATH`) before any syscall.
- **Conditional logic is centralized, not duplicated.** All ETag parsing,
  weak-vs-strong handling, and `*` wildcard rules live in
  `../../compat/http_conditionals.c`. This wrapper must not reimplement them —
  doing so would let WebDAV and S3 drift apart on conditional-request behaviour.
  (See `copy_conditionals.c:42`.)
- **Weak ETags, no weak-equivalence comparison.** COPY passes
  `XROOTD_ETAG_WEAK` for ETag *generation* but `0` for `condition_flags`, so the
  comparison does not enable `XROOTD_HTTP_COND_WEAK_EQUIV`. Changing either flag
  changes overwrite/skip semantics — treat as a deliberate policy choice, not an
  arbitrary default.
- **Semantics enforced (via the shared helper):** `If-Match` ⇒ overwrite only
  if the destination ETag matches (or `*` and destination exists);
  `If-None-Match` ⇒ create-only / skip-if-exists (`*` against a non-existent
  destination passes). Both map a mismatch to `412 Precondition Failed`; this is
  what gives multi-client COPY optimistic-concurrency safety (RFC 9110 §13.1.2).
- **Fail-closed ordering.** This check runs *after* lock checks and the
  `Overwrite:` check in `../copy.c`, and *before* any data is copied. The
  ordering matters: never copy first and validate later.
- **`dst_path` is for logging only.** It is not re-validated here; do not start
  trusting it as a syscall target.

## Entry points / extending

To add another method's precondition/policy helper here, follow the
`copy_conditionals` shape:

1. Add `src/protocols/webdav/methods/<method>_<concern>.c` + `.h`, including
   `../webdav.h` and any `compat` headers you delegate to.
2. Implement a thin wrapper that calls the shared `../../compat/*` helper with
   your method's policy flags, returning `NGX_OK` / an `NGX_HTTP_*` status; keep
   parsing logic in `compat`, not here.
3. Register the new `.c` in the module source list — the top-level `config` script
   (the module's `ngx_module_srcs` / `NGX_ADDON_SRCS` list) — and re-run
   `./configure` so it compiles (a new file is not picked up by an incremental
   `make`).
4. Call it from the relevant handler in `../<method>.c`, short-circuiting on any
   non-`NGX_OK` return before mutating state.
5. Per project rule, ship three tests with the change: success, precondition
   failure (e.g. 412), and a security/negative case.

## See also

- [../README.md](../README.md) — WebDAV method router, dispatch, and handlers
  (`copy.c`, `move.c`, `put.c`, `get.c`, `propfind.c`, `lock.c`).
- [../../compat/README.md](../../compat/README.md) — shared HTTP conditional,
  ETag, header, and body helpers (`http_conditionals.c`, `etag.c`).
- [../../path/README.md](../../path/README.md) — path canonicalization and
  `RESOLVE_BENEATH` confinement that resolves COPY source/destination paths.
- [../../README.md](../../README.md) — master subsystem index.
