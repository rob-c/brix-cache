# Prometheus Metrics Bug Patterns

Reference document from a full correctness audit of the nginx-xrootd Prometheus metrics
layer (stream, WebDAV, S3, proxy) conducted 2026-05-27. Seven distinct bugs were found
across four bug patterns. Each section names the pattern, explains the root cause, lists
the specific instances found, and states the fix.

---

## Pattern 1 — Constant collision causing label misalignment

### What goes wrong

Two `#define` constants share the same integer value. The names array used by the
Prometheus exporter was written correctly (one entry per opcode), but the constants were
wrong, so every call site that uses the constant writes to the right slot for _one_ op
while overwriting it for the other. Every subsequent name in the array is then offset by
one, meaning every label past the collision point is exported under the wrong name.

### Instance found

`src/metrics/metrics.h` lines 45–46:

```c
#define XROOTD_OP_QUERY_CKSUM 17  /* kXR_query / kXR_QChecksum */
#define XROOTD_OP_QUERY_SPACE 17  /* kXR_query / kXR_QSpace    */  /* BUG: duplicate */
```

The `stream.c` names array already had a distinct entry for `"query_space"` at index 18
(the author intended SPACE = 18), but the constant was wrong. Effect:

| Slot | Prometheus label exported | Constant that actually writes here |
|------|--------------------------|-------------------------------------|
| 17   | `query_cksum`            | CKSUM **and** SPACE (merged)        |
| 18   | `query_space`            | READV                               |
| 19   | `readv`                  | PGREAD                              |
| …    | …(all shifted by one)…   | …                                   |
| 36   | `chkpoint`               | (no constant — unused slot)         |

Every SPACE op was silently counted as CKSUM. Every op from READV through CHKPOINT was
exported under the previous op's label. The label `"prepare"` was entirely absent.

### Fix

Renumber the constants. The names array needs no change — it was correct.

```c
/* Before */
#define XROOTD_OP_QUERY_SPACE 17
#define XROOTD_OP_READV       18
...
#define XROOTD_OP_CHKPOINT    35
#define XROOTD_NOPS           37

/* After */
#define XROOTD_OP_QUERY_SPACE 18   /* +1 */
#define XROOTD_OP_READV       19   /* +1 */
...
#define XROOTD_OP_CHKPOINT    36   /* +1 */
#define XROOTD_OP_PREPARE     37   /* new */
#define XROOTD_NOPS           38
```

### How to avoid

- Treat op-slot constants as a small ABI. After adding any constant, assert that the
  names array length matches `XROOTD_NOPS`:

  ```c
  /* compile-time check in stream.c */
  _Static_assert(sizeof(xrootd_op_names)/sizeof(xrootd_op_names[0]) == XROOTD_NOPS,
                 "xrootd_op_names length must equal XROOTD_NOPS");
  ```

- Never copy an existing constant line and change only the comment. Always bump the
  integer.

---

## Pattern 2 — New handler added without metric instrumentation

### What goes wrong

A new opcode handler is implemented and wired into the dispatch table but the author
never adds `XROOTD_OP_OK` / `XROOTD_OP_ERR` calls. The handler silently processes
traffic that is invisible to Prometheus; the corresponding constant may also be missing
entirely, which can mask a Pattern 1 collision later.

### Instance found

`src/query/prepare.c` — `xrootd_handle_prepare()` implemented fully (path validation,
auth checks, staging command invocation, cancel/evict handling) with zero metric calls.
No `XROOTD_OP_PREPARE` constant existed anywhere.

### Fix

1. Add the constant in `metrics.h`.
2. Add `"prepare"` to the names array in `stream.c`.
3. Add `XROOTD_OP_ERR` at every early-return error path and `XROOTD_OP_OK` at every
   success return. In `xrootd_handle_prepare` that meant five `XROOTD_OP_ERR` sites and
   three `XROOTD_OP_OK` sites.

### How to avoid

- The CLAUDE.md recipe for a new stream opcode explicitly lists adding the constant and
  calling `XROOTD_OP_OK`/`XROOTD_OP_ERR`. Follow the recipe.
- Add the `_Static_assert` from Pattern 1 — it will fire at compile time if a constant
  is added without a matching name.

---

## Pattern 3 — Error counter never incremented (success-only tracking)

### What goes wrong

A handler tracks successes (`op_ok`) but no failure path increments `op_err`. The
Prometheus counter for errors is always zero, making it impossible to detect failure
spikes or distinguish "low traffic" from "high error rate."

### Instance found

`src/session/login.c` — `xrootd_count_login_ok()` (a small helper calling
`op_ok[XROOTD_OP_LOGIN]`) was called on both success paths. Neither the CMS-suspended
rejection nor the invalid-username rejection called the corresponding `op_err`.

```c
if (conf->cms_suspended) {
    /* BUG: no XROOTD_OP_ERR here */
    return xrootd_send_error(ctx, c, kXR_Overloaded, "server suspended");
}
```

### Fix

Add `XROOTD_OP_ERR(ctx, XROOTD_OP_LOGIN)` before each `xrootd_send_error` call that
represents a rejected login.

### How to avoid

- When reviewing a handler, grep for all `return xrootd_send_error(...)` sites and
  verify each is preceded by the appropriate `XROOTD_OP_ERR`.
- The `XROOTD_RETURN_ERR` macro (used in many other handlers) encodes both steps
  atomically. Prefer it over inline `XROOTD_OP_ERR + return xrootd_send_error`.

---

## Pattern 4 — Per-IP-version byte counter tracks request count instead of bytes

### What goes wrong

The per-IP-version byte counters (`bytes_rx_ipv4_total`, `bytes_rx_ipv6_total`,
`bytes_tx_ipv4_total`, `bytes_tx_ipv6_total`) are intended to accumulate the actual
number of bytes transferred, split by the IP version of the client. Instead, the code
uses `_INC` (adds 1) rather than `_ADD(n)` (adds the byte count), and places the
increment at the wrong layer (at request arrival, before the body has been received).
The result: the counters show "requests per IP version," identical to the
`requests_total` label split — useless for capacity planning or cost attribution.

This bug appeared in two different protocol layers, independently.

### Instances found

**WebDAV — `src/webdav/access.c`** (the request-routing access handler):

```c
/* BUG: called before body is read; INC adds 1, not body bytes */
if (r->connection->sockaddr->sa_family == AF_INET6) {
    XROOTD_WEBDAV_METRIC_INC(bytes_rx_ipv6_total);
} else {
    XROOTD_WEBDAV_METRIC_INC(bytes_rx_ipv4_total);
}
```

**S3 — `src/s3/handler.c`** (the S3 dispatch handler):

```c
/* BUG: same pattern — INC at dispatch, before body read */
if (ip_ver == AF_INET) {
    XROOTD_S3_METRIC_INC(bytes_rx_ipv4_total);
} else {
    XROOTD_S3_METRIC_INC(bytes_rx_ipv6_total);
}
```

Both also had a secondary gap: `bytes_tx_ipv*` for S3 GET responses
(`src/s3/object.c`) and S3 LIST responses (`src/s3/list_objects_v2.c`) were never
updated, while the WebDAV GET path in `get.c` correctly called `_ADD`. PROPFIND and
multipart-range responses (`propfind.c`, `xrdhttp_multipart.c`) also updated
`bytes_tx_total` but omitted the per-IP split.

The reference implementation was `src/webdav/get.c`:

```c
/* CORRECT: called after send_len is known, uses _ADD not _INC */
XROOTD_WEBDAV_METRIC_ADD(bytes_tx_total, (size_t) send_len);
if (r->connection && r->connection->sockaddr) {
    switch (r->connection->sockaddr->sa_family) {
    case AF_INET6:
        XROOTD_WEBDAV_METRIC_ADD(bytes_tx_ipv6_total, (size_t) send_len);
        break;
    default:
        XROOTD_WEBDAV_METRIC_ADD(bytes_tx_ipv4_total, (size_t) send_len);
        break;
    }
}
```

### Fix summary

| File | Change |
|------|--------|
| `webdav/access.c` | Remove `_INC` calls entirely |
| `webdav/put.c` | Add `_ADD(body_summary.bytes)` after `bytes_rx_total` |
| `s3/handler.c` | Remove `_INC` calls entirely |
| `s3/put.c` (×2) | Add `_ADD(body_bytes)` in both `s3_put_aio_done` and `s3_put_finalize_ok` |
| `s3/object.c` | Add `_ADD(send_len)` after `bytes_tx_total` |
| `s3/list_objects_v2.c` | Add `_ADD(xml_len)` after `bytes_tx_total` |
| `webdav/propfind.c` | Add `_ADD(total_len)` after `bytes_tx_total` |
| `webdav/xrdhttp_multipart.c` | Add `_ADD(data_bytes)` after `bytes_tx_total` |

### How to avoid

- `_INC` and `_ADD` are visually similar. Treat any `_INC` on a `bytes_*` counter as
  a likely bug — byte counters should always use `_ADD`.
- The per-IP-version increment must come after the byte count is known and must be
  co-located with the `bytes_rx/tx_total` increment, not at a different layer.
- When adding a new response path that calls `XROOTD_*_METRIC_ADD(bytes_tx_total, n)`,
  immediately add the matching `bytes_tx_ipv4/ipv6_total` block. Treat the pair as
  atomic.

---

## Pattern 5 — Metric field exists but write site is missing

### What goes wrong

A metric field is defined in the struct, exported in the Prometheus output, and even
incremented in adjacent similar metrics — but one specific field is never written at the
only call site that could do so. The field is always zero in production.

### Instance found

`src/s3/list_objects_v2.c` — the S3 LIST response:

```c
/* present, correctly updated */
XROOTD_S3_METRIC_ADD(list_common_prefixes_total, (size_t) prefixes);
if (truncated) {
    XROOTD_S3_METRIC_INC(list_truncated_total);
}

/* BUG: 'contents' (object count emitted) is tracked locally but never written */
/* XROOTD_S3_METRIC_ADD(list_contents_total, (size_t) contents);  <-- missing */
```

`list_common_prefixes_total` and `list_truncated_total` were both present, but
`list_contents_total` — the parallel counter for objects returned — was zero forever.

### Fix

Add the missing line immediately adjacent to the others:

```c
XROOTD_S3_METRIC_ADD(list_contents_total, (size_t) contents);
XROOTD_S3_METRIC_ADD(list_common_prefixes_total, (size_t) prefixes);
```

### How to avoid

- When writing a group of related metrics (contents / prefixes / truncated), add all
  three lines together. A partial group is a red flag.
- Code review checklist: if a local variable tracking a count exists and is used only
  for logging, ask whether it should also be in metrics.

---

## Audit checklist derived from these bugs

Use this when reviewing new handlers or modifying existing ones.

```
[ ] Every XROOTD_OP_* constant maps to a unique integer (no duplicates).
[ ] XROOTD_NOPS == len(xrootd_op_names) — guarded by _Static_assert.
[ ] New opcode handler: constant added, name added, XROOTD_OP_OK/ERR at every return.
[ ] Every return xrootd_send_error(...) is preceded by XROOTD_OP_ERR (or uses XROOTD_RETURN_ERR).
[ ] bytes_* counters use _ADD, not _INC.
[ ] Per-IP-version _ADD is co-located with the matching bytes_rx/tx_total _ADD.
[ ] Per-IP-version _ADD comes after the byte count is known (i.e., not at dispatch time).
[ ] Related metric groups (contents / prefixes / truncated) are all written together.
[ ] New response path: bytes_tx_total AND bytes_tx_ipv4/ipv6_total both added.
[ ] New body-read path: bytes_rx_total AND bytes_rx_ipv4/ipv6_total both added.
```
