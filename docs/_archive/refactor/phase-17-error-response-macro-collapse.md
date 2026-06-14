# Phase 17 — Error-to-Response Macro Collapse

**Target**: apply the existing `XROOTD_RETURN_ERR` / `XROOTD_RETURN_OK` macros
to all remaining raw three-line patterns, add two missing macro variants
(`XROOTD_RETURN_REDIR` and `XROOTD_BAIL_ERR`), and fix six metric-less error
paths in `write/chkpoint_xeq.c` as a side effect.

**Net LoC reduction**: ~380–410 LoC  
**Risk**: very low — zero logic changes, zero new source files; the only
danger is mis-ordering the macro arguments  
**Requires**: `make -j$(nproc)` — no new source files, no `./configure`

---

## Background

Two collapse macros were added to `src/types/tunables.h` (lines 142–156) but
have not been applied consistently:

```c
#define XROOTD_RETURN_ERR(ctx, c, op, verb, path, detail, code, msg)
    /* log_access + XROOTD_OP_ERR + return xrootd_send_error */

#define XROOTD_RETURN_OK(ctx, c, op, verb, path, detail, bytes)
    /* log_access + XROOTD_OP_OK + return xrootd_send_ok(NULL, 0) */
```

Auditing all `.c` files containing `xrootd_log_access()` reveals four pattern
classes not yet using these macros:

| Pattern | Count | Lines/instance | Gross savings |
|---------|-------|----------------|---------------|
| `log_access + XROOTD_OP_ERR + return send_error` | 72 | 4.9 avg | 282 LoC |
| `log_access + XROOTD_OP_OK + return send_ok(NULL,0)` | ~18 | 4.6 avg | ~83 LoC |
| `log_access + XROOTD_OP_OK + return send_redirect` | 9 | 4.0 avg | 27 LoC |
| `log_access + XROOTD_OP_ERR + *rc=send_error; return 0` | 10 | 6.3 avg | 53 LoC |

Net after new macro declarations (~15 LoC): **~430 LoC gross − 15 LoC = ~415 LoC net**.

---

## What NOT to collapse

Three structurally different patterns share surface similarity but must be left
as-is:

**AIO/TPC callback pattern** (`src/aio/write.c`, `src/aio/dirlist.c`,
`src/tpc/done.c`, `src/cache/thread.c`, `src/cache/writethrough_flush.c` —
~30 instances):

```c
xrootd_log_access(ctx, c, "WRITE", t->path, detail, 0, kXR_IOError, msg, 0);
XROOTD_OP_ERR(ctx, op);
xrootd_send_error(ctx, c, kXR_IOError, msg);   /* no return — void callback */
xrootd_aio_resume(c);
return;
```

These are `void` callback functions.  `XROOTD_RETURN_ERR` contains a
`return ngx_int_t` and cannot be used here.

**Body-carrying send_ok** (`src/read/locate.c`, `src/response/basic.c`,
`src/query/checksum_qcksum.c` — instances where `send_ok` carries a non-NULL
body): these remain explicit because the response body size varies per call.

**Deferred / pipelined completions** (`src/session/login.c`,
`src/session/bind.c` — ~4 misc instances): log_access is called
unconditionally before the actual response is decided later in the flow.

---

## Change A — two new macros in `src/types/tunables.h`

Add immediately after the existing `XROOTD_RETURN_ERR` block (after line 156):

### `XROOTD_RETURN_REDIR`

```c
/*
 * Collapse: log_access + XROOTD_OP_OK + return send_redirect.
 * Used wherever the outcome is a successful redirect (locate, manager, etc.)
 */
#define XROOTD_RETURN_REDIR(ctx, c, op, verb, path, detail, host, port)  \
    do {                                                                   \
        xrootd_log_access((ctx), (c), (verb), (path), (detail),          \
                          1, kXR_ok, NULL, 0);                            \
        XROOTD_OP_OK((ctx), (op));                                        \
        return xrootd_send_redirect((ctx), (c), (host), (port));         \
    } while (0)
```

### `XROOTD_BAIL_ERR`

For helper functions that return `int` (0/1) and propagate the wire error via
an `ngx_int_t *rc` out-parameter:

```c
/*
 * Collapse: log_access + XROOTD_OP_ERR + *rc=send_error + return 0.
 * Used in helper functions (validate_handle, parse_op_path, etc.) that
 * signal failure to callers via an out-parameter and return int 0.
 */
#define XROOTD_BAIL_ERR(ctx, c, op, verb, path, detail, code, msg, rc)  \
    do {                                                                  \
        xrootd_log_access((ctx), (c), (verb), (path), (detail),         \
                          0, (code), (msg), 0);                          \
        XROOTD_OP_ERR((ctx), (op));                                      \
        *(rc) = xrootd_send_error((ctx), (c), (code), (msg));           \
        return 0;                                                         \
    } while (0)
```

**LoC cost: +15 LoC** (two macro bodies + whitespace).

---

## Change B — collapseable patterns by file

Files are listed in descending order of impact.  All changes are mechanical
argument mapping; no logic changes.

### `src/read/open_request.c` — 15 ERR, 4 REDIR

Largest single target.  Every instance follows the same three-argument shape:

```c
/* BEFORE (5-6 lines) */
xrootd_log_access(ctx, c, "OPEN", tpc_clean, "tpc-pull",
                  0, kXR_NotAuthorized, "authdb denied", 0);
XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
return xrootd_send_error(ctx, c, kXR_NotAuthorized, "authdb denied");

/* AFTER (1 line) */
XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_WR, "OPEN", tpc_clean,
                  "tpc-pull", kXR_NotAuthorized, "authdb denied");
```

The four redirect patterns (TPC redirect + static map redirects) use
`XROOTD_RETURN_REDIR`.

**Estimated savings: ~90 LoC** (15×5 + 4×3 = 87).

### `src/read/open_resolved_file.c` — 10 ERR

All patterns are `kXR_OPEN_RD` or `kXR_OPEN_WR` op with consistent verb
`"OPEN"`.

**Estimated savings: ~55 LoC** (10×5.5 avg).

### `src/dirlist/handler.c` — 9 ERR

Verb is `"DIRLIST"`, op is `XROOTD_OP_DIRLIST`.

**Estimated savings: ~40 LoC** (9×4.5 avg).

### `src/tpc/launch.c` — 7 ERR

Verb is `"TPC-PULL"` or `"TPC-PUSH"`, op varies by TPC direction.

**Estimated savings: ~32 LoC** (7×4.6 avg).

### `src/krb5/auth.c` — 6 ERR, 1 OK

Verb is `"KRB5"`, op is `XROOTD_OP_LOGIN`.

**Estimated savings: ~28 LoC** (7×4 avg).

### `src/write/common.c` — 5 BAIL_ERR

These are in `xrootd_parse_op_path()` and `xrootd_check_write_gate()`, which
return `int` (0/1) with `ngx_int_t *rc` out-parameter:

```c
/* BEFORE (6 lines) */
xrootd_log_access(ctx, c, verb, reqpath, "-",
                  0, kXR_ArgInvalid, "path exceeds maximum depth", 0);
XROOTD_OP_ERR(ctx, op);
*rc = xrootd_send_error(ctx, c, kXR_ArgInvalid, "path exceeds maximum depth");
return 0;

/* AFTER (1 line) */
XROOTD_BAIL_ERR(ctx, c, op, verb, reqpath, "-", kXR_ArgInvalid,
                "path exceeds maximum depth", rc);
```

**Estimated savings: ~28 LoC** (5×5.6 avg).

### `src/connection/fd_table.c` — 5 BAIL_ERR

In `xrootd_validate_file_handle()`, `xrootd_validate_read_handle()`, and
`xrootd_validate_write_handle()`:

```c
/* BEFORE (5 lines) */
xrootd_log_access(ctx, c, verb, "-", "-",
                  0, kXR_FileNotOpen, "invalid file handle", 0);
XROOTD_OP_ERR(ctx, op);
*rc = xrootd_send_error(ctx, c, kXR_FileNotOpen, "invalid file handle");
return 0;

/* AFTER (1 line) */
XROOTD_BAIL_ERR(ctx, c, op, verb, "-", "-", kXR_FileNotOpen,
                "invalid file handle", rc);
```

**Estimated savings: ~25 LoC** (5×5 avg).

### `src/cache/open_or_fill.c` — 4 ERR

Verb is `"OPEN"`, op is `XROOTD_OP_OPEN_RD`.

**Estimated savings: ~16 LoC**.

### `src/write/pgwrite.c` — 4 ERR

**Estimated savings: ~16 LoC**.

### `src/unix/auth.c` — 4 ERR, 1 OK

**Estimated savings: ~16 LoC**.

### `src/gsi/auth.c` — 3 ERR, 1 OK

**Estimated savings: ~12 LoC**.

### `src/gsi/token.c` — 3 ERR, 1 OK

**Estimated savings: ~12 LoC**.

### `src/query/metadata.c` — 3 ERR, 3 OK

**Estimated savings: ~18 LoC**.

### Remaining files (≤ 2 patterns each)

`src/sss/auth_identity_challenge.c`, `src/sss/auth_request.c`,
`src/session/lifecycle.c`, `src/read/stat.c`, `src/read/statx.c`,
`src/read/locate.c` (REDIR), `src/write/truncate.c`,
`src/write/writev.c`, `src/write/chkpoint.c`, `src/query/space.c`,
`src/cache/writethrough_flush.c` (1 ERR only — not the void callbacks).

**Estimated savings: ~30 LoC combined**.

---

## Change C — fix missing metrics in `src/write/chkpoint_xeq.c`

`chkpoint_xeq.c` contains 6 patterns that call `xrootd_log_access()` then
`return xrootd_send_error()` with NO intervening `XROOTD_OP_ERR`.  The same
file uses `XROOTD_RETURN_ERR` for 1 other pattern (line 269), confirming the
missing metric is an oversight.  `XROOTD_OP_CHKPOINT` is defined and used
in `chkpoint.c`.

Replace all 6 with `XROOTD_RETURN_ERR` calls.  This changes the LoC from 2
lines → 1 line (minor) but also **fixes the missing metric** — errors in
pgwrite, truncate, and writev sub-operations under a checkpoint are now counted
in `XROOTD_OP_CHKPOINT` error metrics.

---

## Honest LoC accounting

```
Change A  — two new macros in tunables.h:                       + 15 LoC

Change B  — pattern applications:
  open_request.c       (15 ERR + 4 REDIR):                      − 87 LoC
  open_resolved_file.c (10 ERR):                                 − 55 LoC
  dirlist/handler.c    ( 9 ERR):                                 − 40 LoC
  tpc/launch.c         ( 7 ERR):                                 − 32 LoC
  krb5/auth.c          ( 6 ERR + 1 OK):                         − 28 LoC
  write/common.c       ( 5 BAIL_ERR):                           − 28 LoC
  connection/fd_table.c( 5 BAIL_ERR):                           − 25 LoC
  cache/open_or_fill.c ( 4 ERR):                                 − 16 LoC
  write/pgwrite.c      ( 4 ERR):                                 − 16 LoC
  unix/auth.c          ( 4 ERR + 1 OK):                         − 16 LoC
  gsi/auth.c           ( 3 ERR + 1 OK):                         − 12 LoC
  gsi/token.c          ( 3 ERR + 1 OK):                         − 12 LoC
  query/metadata.c     ( 3 ERR + 3 OK):                         − 18 LoC
  read/locate.c        ( 1 OK + 3 REDIR):                       − 14 LoC
  remaining ~10 files  (≤2 patterns each):                       − 30 LoC
Change C  — chkpoint_xeq.c metric fix (net LoC ≈ 0):              0 LoC
─────────────────────────────────────────────────────────────────────────
Net:                                                            −414 LoC
```

Uncertainty ±30 LoC depending on actual blank-line and multi-line wrapping
counts.

---

## Argument mapping rules (apply before every change)

All macros share the same argument order. Verify each instance by reading
the raw call before converting:

| `xrootd_log_access(ctx, c,` | Macro arg |
|-----------------------------|-----------|
| arg 3 (verb string) | `verb` |
| arg 4 (path string) | `path` |
| arg 5 (detail string) | `detail` |
| arg 8 (error code) | `code` (ERR only) |
| arg 9 (message string) | `msg` (ERR only) |
| arg 10 (byte count) | `bytes` (OK only) |

The `success` flag (arg 6), `code` (arg 7), `msg` (arg 8), and `bytes` (arg 9)
are baked into the macro — do not pass them again.

**Common mistake**: switching `path` and `detail`.  The original `log_access`
call is the ground truth — copy the strings exactly.

---

## Implementation steps

All changes are sequential by file; do not edit two files in parallel since
the pattern verification is per-file.

1. **Add macros to `src/types/tunables.h`** (Change A). Build once to confirm
   they compile cleanly: `make -j$(nproc)`.

2. **Apply by file, heaviest first** (Change B).  For each file:
   a. Grep for `xrootd_log_access(` to list all instances.
   b. For each instance: verify the pattern type (ERR / OK / REDIR / BAIL_ERR),
      copy the argument values, write the macro call.
   c. Spot-check that no surrounding logic was disrupted (no early `return`
      was displaced, no `goto` was jumping past the old pattern).

3. **Fix `chkpoint_xeq.c`** (Change C): search for `xrootd_log_access` followed
   within 2 lines by `return xrootd_send_error` with no `XROOTD_OP_ERR`.
   Apply `XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, ...)`.

4. **Build and test**:
   ```bash
   make -j$(nproc)
   /tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf
   ```

---

## Tests (minimum 3)

No logic changes — the test suite verifies end-to-end protocol conformance,
not macro structure.

```bash
# Full conformance suite: exercises every handler that was touched
PYTHONPATH=tests pytest tests/test_conformance.py -v

# Auth-path coverage (krb5, gsi, unix, sss auth errors)
PYTHONPATH=tests pytest tests/ -k "auth" -v

# Write + checkpoint coverage (pgwrite, truncate, writev, chkpoint)
PYTHONPATH=tests pytest tests/ -k "write or chkpoint" -v
```

Additional manual check: after the changes, scan for any remaining
`xrootd_log_access` + `XROOTD_OP_ERR` + `return xrootd_send_error` triple in
the handler files to confirm nothing was missed:

```bash
grep -rn "xrootd_log_access" src/ --include="*.c" -A6 \
  | grep -B5 "return xrootd_send_error" \
  | grep -B3 "XROOTD_OP_ERR" \
  | grep "xrootd_log_access"
```

An empty result means all collapseable patterns have been converted.

---

## Relationship to overall 10% target

```
Phase 12 (shared HTTP file-serve):              − 80–110 LoC
Phase 13 (aio task dispatch macro):             −      10 LoC
Phase 14 (table-driven metrics):                −      83 LoC
Phase 15 (unified namespace layer):             −      16 LoC
Phase 16 (unified prop store):                  −     277 LoC
Phase 17 (error-response macro collapse):       −     414 LoC
──────────────────────────────────────────────────────────────
Subtotal phases 12–17:                          −880–910 LoC
```

This phase alone closes the remaining gap to the 10% target (~800 LoC for an
~8,000 LoC codebase).  Combined with phases 12–16, the series delivers
~880–910 LoC total — comfortably over the target even accounting for
measurement uncertainty.
