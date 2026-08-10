# Prometheus Metrics Bug Patterns

Reference document from a full correctness audit of the BriX-Cache Prometheus metrics
layer (stream, WebDAV, S3, proxy) conducted 2026-05-27, extended 2026-08-04 by the
query-count/byte-accuracy conformance audit (Patterns 6–8; verified by the 215-test
suite in `tests/test_cachemx_*.py`). Each section names the pattern, explains the root
cause, lists the specific instances found, and states the fix.

---

## Pattern 1 — Constant collision causing label misalignment

### What goes wrong

Two `#define` constants share the same integer value. The names array used by the
Prometheus exporter was written correctly (one entry per opcode), but the constants were
wrong, so every call site that uses the constant writes to the right slot for _one_ op
while overwriting it for the other. Every subsequent name in the array is then offset by
one, meaning every label past the collision point is exported under the wrong name.

### Instance found

`src/observability/metrics/metrics.h` lines 45–46:

```c
#define BRIX_OP_QUERY_CKSUM 17  /* kXR_query / kXR_QChecksum */
#define BRIX_OP_QUERY_SPACE 17  /* kXR_query / kXR_QSpace    */  /* BUG: duplicate */
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
#define BRIX_OP_QUERY_SPACE 17
#define BRIX_OP_READV       18
...
#define BRIX_OP_CHKPOINT    35
#define BRIX_NOPS           37

/* After */
#define BRIX_OP_QUERY_SPACE 18   /* +1 */
#define BRIX_OP_READV       19   /* +1 */
...
#define BRIX_OP_CHKPOINT    36   /* +1 */
#define BRIX_OP_PREPARE     37   /* new */
#define BRIX_NOPS           38
```

### How to avoid

- Treat op-slot constants as a small ABI. After adding any constant, assert that the
  names array length matches `BRIX_NOPS`:

  ```c
  /* compile-time check in stream.c */
  _Static_assert(sizeof(brix_op_names)/sizeof(brix_op_names[0]) == BRIX_NOPS,
                 "brix_op_names length must equal BRIX_NOPS");
  ```

- Never copy an existing constant line and change only the comment. Always bump the
  integer.

---

## Pattern 2 — New handler added without metric instrumentation

### What goes wrong

A new opcode handler is implemented and wired into the dispatch table but the author
never adds `BRIX_OP_OK` / `BRIX_OP_ERR` calls. The handler silently processes
traffic that is invisible to Prometheus; the corresponding constant may also be missing
entirely, which can mask a Pattern 1 collision later.

### Instance found

`src/protocols/root/query/prepare.c` — `brix_handle_prepare()` implemented fully (path validation,
auth checks, staging command invocation, cancel/evict handling) with zero metric calls.
No `BRIX_OP_PREPARE` constant existed anywhere.

### Fix

1. Add the constant in `metrics.h`.
2. Add `"prepare"` to the names array in `stream.c`.
3. Add `BRIX_OP_ERR` at every early-return error path and `BRIX_OP_OK` at every
   success return. In `brix_handle_prepare` that meant five `BRIX_OP_ERR` sites and
   three `BRIX_OP_OK` sites.

### How to avoid

- The CLAUDE.md recipe for a new stream opcode explicitly lists adding the constant and
  calling `BRIX_OP_OK`/`BRIX_OP_ERR`. Follow the recipe.
- Add the `_Static_assert` from Pattern 1 — it will fire at compile time if a constant
  is added without a matching name.

---

## Pattern 3 — Error counter never incremented (success-only tracking)

### What goes wrong

A handler tracks successes (`op_ok`) but no failure path increments `op_err`. The
Prometheus counter for errors is always zero, making it impossible to detect failure
spikes or distinguish "low traffic" from "high error rate."

### Instance found

`src/protocols/root/session/login.c` — `brix_count_login_ok()` (a small helper calling
`op_ok[BRIX_OP_LOGIN]`) was called on both success paths. Neither the CMS-suspended
rejection nor the invalid-username rejection called the corresponding `op_err`.

```c
if (conf->cms_suspended) {
    /* BUG: no BRIX_OP_ERR here */
    return brix_send_error(ctx, c, kXR_Overloaded, "server suspended");
}
```

### Fix

Add `BRIX_OP_ERR(ctx, BRIX_OP_LOGIN)` before each `brix_send_error` call that
represents a rejected login.

### How to avoid

- When reviewing a handler, grep for all `return brix_send_error(...)` sites and
  verify each is preceded by the appropriate `BRIX_OP_ERR`.
- The `BRIX_RETURN_ERR` macro (used in many other handlers) encodes both steps
  atomically. Prefer it over inline `BRIX_OP_ERR + return brix_send_error`.

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

**WebDAV — `src/protocols/webdav/access.c`** (the request-routing access handler):

```c
/* BUG: called before body is read; INC adds 1, not body bytes */
if (r->connection->sockaddr->sa_family == AF_INET6) {
    BRIX_WEBDAV_METRIC_INC(bytes_rx_ipv6_total);
} else {
    BRIX_WEBDAV_METRIC_INC(bytes_rx_ipv4_total);
}
```

**S3 — `src/protocols/s3/handler.c`** (the S3 dispatch handler):

```c
/* BUG: same pattern — INC at dispatch, before body read */
if (ip_ver == AF_INET) {
    BRIX_S3_METRIC_INC(bytes_rx_ipv4_total);
} else {
    BRIX_S3_METRIC_INC(bytes_rx_ipv6_total);
}
```

Both also had a secondary gap: `bytes_tx_ipv*` for S3 GET responses
(`src/protocols/s3/object.c`) and S3 LIST responses (`src/protocols/s3/list_objects_v2.c`) were never
updated, while the WebDAV GET path in `get.c` correctly called `_ADD`. PROPFIND and
multipart-range responses (`propfind.c`, `xrdhttp_multipart.c`) also updated
`bytes_tx_total` but omitted the per-IP split.

The reference implementation was `src/protocols/webdav/get.c`:

```c
/* CORRECT: called after send_len is known, uses _ADD not _INC */
BRIX_WEBDAV_METRIC_ADD(bytes_tx_total, (size_t) send_len);
if (r->connection && r->connection->sockaddr) {
    switch (r->connection->sockaddr->sa_family) {
    case AF_INET6:
        BRIX_WEBDAV_METRIC_ADD(bytes_tx_ipv6_total, (size_t) send_len);
        break;
    default:
        BRIX_WEBDAV_METRIC_ADD(bytes_tx_ipv4_total, (size_t) send_len);
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
- When adding a new response path that calls `BRIX_*_METRIC_ADD(bytes_tx_total, n)`,
  immediately add the matching `bytes_tx_ipv4/ipv6_total` block. Treat the pair as
  atomic.

---

## Pattern 5 — Metric field exists but write site is missing

### What goes wrong

A metric field is defined in the struct, exported in the Prometheus output, and even
incremented in adjacent similar metrics — but one specific field is never written at the
only call site that could do so. The field is always zero in production.

### Instance found

`src/protocols/s3/list_objects_v2.c` — the S3 LIST response:

```c
/* present, correctly updated */
BRIX_S3_METRIC_ADD(list_common_prefixes_total, (size_t) prefixes);
if (truncated) {
    BRIX_S3_METRIC_INC(list_truncated_total);
}

/* BUG: 'contents' (object count emitted) is tracked locally but never written */
/* BRIX_S3_METRIC_ADD(list_contents_total, (size_t) contents);  <-- missing */
```

`list_common_prefixes_total` and `list_truncated_total` were both present, but
`list_contents_total` — the parallel counter for objects returned — was zero forever.

### Fix

Add the missing line immediately adjacent to the others:

```c
BRIX_S3_METRIC_ADD(list_contents_total, (size_t) contents);
BRIX_S3_METRIC_ADD(list_common_prefixes_total, (size_t) prefixes);
```

### How to avoid

- When writing a group of related metrics (contents / prefixes / truncated), add all
  three lines together. A partial group is a red flag.
- Code review checklist: if a local variable tracking a count exists and is used only
  for logging, ask whether it should also be in metrics.

---

## Pattern 6 — Same logical operation observed at two layers

### What goes wrong

The unified `brix_io_ops_total` / `brix_io_bytes_*` / `brix_io_latency_usec` families
can be fed from three places: the protocol response path (`*_metrics_response` →
`brix_metric_op_done`), the VFS observer (`brix_vfs_observe_ctx_op`), and the
scrape-time fold of per-protocol wire ledgers. When two of them fire for the same
logical operation, every affected counter is exactly doubled — which looks plausible
on a dashboard and only falls out of an exact-delta conformance test.

### Instances found (2026-08 audit)

1. **Protocol response × VFS observer (namespace ops).** WebDAV/S3
   `*_metrics_response` emitted `op_done` for every method, but stat/delete/mkdir/
   rename/dirlist are already observed by the VFS layer. Fix: the protocol-level
   `op_done` is restricted to the data plane (GET→READ, PUT→WRITE) —
   `src/protocols/webdav/metrics.c`, `src/protocols/s3/metrics.c`.
2. **Wire-ledger fold × VFS observer (root:// namespace ops).** The scrape-time fold
   of the per-server `op_ok/op_err` slots into the unified stream rows originally
   folded every slot; namespace ops on root:// are also VFS-observed. Fix: the fold
   is restricted to READ/WRITE (`brix_unified_legacy_stream_op`,
   `src/observability/metrics/unified_export_io.c`).
Not every declared row has an owner by default — see Pattern 13 for the opposite
failure, a row that no layer books at all.

3. **VFS staged commit × protocol response (HTTP uploads).**
   `brix_vfs_staged_commit` metered `OP_WRITE` with the committed object size, while
   the owning protocol (WebDAV/S3 PUT) already books the WRITE row at response time
   and the rx-ledger fold supplies `io_bytes_written`. Every HTTP upload therefore
   counted write ops ×2, written bytes ×2 (VFS bytes + fold bytes), and latency
   observations ×2. Fix: staged commit calls the metric-suppressed observer
   (`brix_vfs_observe_ctx_op_ex(..., meter_io=0)`, `src/fs/vfs/vfs_staged.c`),
   keeping the per-backend `brix_storage_io_bytes_*` totals and the access-log line
   but leaving the unified WRITE row to the protocol layer.

### How to avoid

Every unified `(proto, op)` row has exactly ONE booking owner. All five protocol
planes — `stream`, `webdav`, `s3`, `cvmfs`, `gridftp` — write into the same
process-wide zone, so the table below is exhaustive by construction: a plane
missing from it books nothing, which is Pattern 13, not an omission here.

| Row | Sole owner |
|-----|-----------|
| webdav/s3 READ + WRITE ops & latency | protocol `*_metrics_response` (one per request, full-request latency) |
| stream READ + WRITE ops | wire-ledger fold (no latency observations) |
| gridftp READ + WRITE ops, latency & `io_bytes_*` | `brix_ftp_ev_metric_xfer()` at transfer completion (`src/protocols/gridftp/ev/ftp_ev_metrics.c`) — the gateway has no wire ledger to fold, so it books its own bytes |
| cvmfs data plane | the dedicated `brix_cvmfs_bytes_served_total` family + `brix_cache_hits_total`/`_misses_total{proto="cvmfs"}`. By design cvmfs books **no** unified `op="read"` row — the cache-disposition split is the authoritative view of what it served |
| namespace ops (all protocols) | VFS observer (per-call latency) |
| `op="tpc"` (webdav + stream) | `brix_tpc_metric_book()` in `src/tpc/common/metrics.c` — count-only, no latency |
| webdav/s3 `io_bytes_*` | per-protocol rx/tx ledger fold |
| stream `io_bytes_*` | per-server `servers[]` rx/tx fold |
| per-backend `brix_storage_io_bytes_*` | VFS/staged-commit layer |

If a change adds a metric emission on any of these paths, check the owner table
first; if the row already has an owner, do not emit.

---

## Pattern 7 — Async body-handler finalize bypasses response accounting

### What goes wrong

Handlers that read a request body return `NGX_DONE` to the dispatch wrapper, which
correctly skips its response accounting (the request isn't finished). The async
re-entry point (the body handler) then owns booking `responses_total` — but if it
finalizes with a bare `ngx_http_finalize_request()` instead of the metrics-aware
wrapper, the response is never counted: `requests_total{method}` moves while
`responses_total{method,*}` stays flat forever.

### Instance found

`src/protocols/webdav/propfind.c` — PROPFIND-with-body finalized directly, so 207
responses were never booked. PUT (`put_body.c`), PROPPATCH, and SEARCH already used
`webdav_metrics_finalize_request()`; only PROPFIND had the hole.

### Fix

`propfind_body_handler` now finalizes via `webdav_metrics_finalize_request(r, rc)`
(which internally skips only genuine `NGX_DONE` re-entries).

### Second instance (2026-08-04) — the off-loop cache fill park

The same hole, one layer over: a WebDAV GET whose object is not yet cached parks on
`brix_http_cache_fill_if_needed()` and returns `NGX_DONE`. The fill worker later
called `webdav_get_reenter` → `webdav_handle_get()` — the *raw* handler, not the
metrics-wrapped dispatch tail — and then `ngx_http_finalize_request()` directly. So
the one request that actually paid for an origin fetch was the one missing from
`brix_webdav_responses_total` and from `brix_io_ops_total{proto="webdav",op="read"}`.
Its bytes still appeared (they come from the scrape-time tx-ledger fold), so ops and
bytes disagreed by exactly one per cold object — invisible on a local-posix export
(no offload) and permanent on a remote-backed one. The failure tail was worse: a fill
that ends 404/403/502 never re-enters the handler at all, so those responses were
booked nowhere.

Fix (`src/protocols/webdav/get.c`): `webdav_get_reenter` returns through
`webdav_metrics_return()`, and the previously-NULL `on_fail` hook is now
`webdav_get_fill_failed`, which books the response before returning the status
unchanged. Pinned by `tests/test_cachemx_ops_grid.py::
test_webdav_over_remote_origin_miss_then_hit` and
`::test_webdav_over_remote_origin_missing_object_404`.

### How to avoid

- Any handler that returns `NGX_DONE` must re-enter the metrics layer at its async
  completion point. Grep body handlers for bare `ngx_http_finalize_request` calls.
- A park has TWO completion points — the re-entry and the failure tail. An
  `on_fail`/error callback left NULL is an unbooked response, not a no-op.
- Async accounting holes only show up on the plane that actually takes the async
  path. A conformance matrix needs at least one export per storage shape (local
  posix AND remote origin), or the offload path is never exercised.
- Conformance shape: for every method, drive one request and assert
  `Δrequests_total == Δ(sum of responses_total status classes) == 1`.

---

## Pattern 8 — Pipeline keeps evaluating after the first verdict

### What goes wrong

An authentication pipeline that runs checks in sequence books a result row per check
instead of per request. Once a verdict has been reached (and possibly a response
header sent), later stages must not run — otherwise one request produces two or more
`*_auth_total` rows, and rate/ratio queries built on them are silently wrong.

### Instance found

The S3 SigV4 pipeline continued past the first failure verdict, double-booking auth
results. Fix: every stage is guarded so evaluation stops at the first verdict
(`|| r->header_sent` guards in the SigV4 pipeline).

### How to avoid

- Auth pipelines book exactly ONE result row per request. Conformance shape: drive
  one request per failure mode and assert the deltas across ALL result labels sum
  to exactly 1 (see `assert_auth_singular` in `tests/test_cachemx_s3_planes.py`).

---

## Pattern 9 — Handled method missing from the metric enum folds into OTHER

### What goes wrong

A protocol handles a method end-to-end, but the method never got its own slot in the
metric enum, so its `requests_total`/`responses_total` rows silently fold into the
`method="OTHER"` bucket. Dashboards show zero traffic for a method that is actively
served, and OTHER becomes a mixed bag that can't be alerted on. The failure is
invisible to per-method tests that only assert on methods that *do* have slots.

### Instance found

WebDAV MOVE was fully implemented (`src/protocols/webdav/move.c`) but
`metrics_webdav.h` had no `BRIX_WEBDAV_METHOD_MOVE`, so `operation_table.c` mapped it
to `BRIX_WEBDAV_METHOD_OTHER`. Every MOVE booked `method="OTHER"` on both ledger
families. Fix: new enum slot 8 for MOVE (OTHER moved to 9), string-table entry in
`metrics/webdav.c`, and the `operation_table.c` row updated. Because the OTHER slot
*shifted*, the regression suite also pins that an unhandled method (PATCH) still
lands on OTHER at the new index — a stale string table would misattribute every
method after the insertion point.

### How to avoid

- When adding a handler for a new method, grep the metric enum FIRST — "it already
  works" does not mean "it is already counted".
- Enum + string table + operation table move together in one change; the string
  table length is pinned by `BRIX_WEBDAV_NMETHODS`, so a missed entry is a compile
  error, but a *wrong slot* is not — pin it with a conformance test per method.
- Regression shape: drive the method, assert its own label moved AND
  `method="OTHER"` did not (`tests/test_cachemx_move_rename.py`).

---

## Pattern 10 — Layer contract mismatch surfaces as a phantom error metric

### What goes wrong

Two adjacent layers disagree about the shape of an argument (relative vs absolute
path, encoded vs decoded name). Every call fails with a *misleading* errno, the
operation's error bucket climbs while its ok row stays at zero, and the symptom is
diagnosed as a storage problem instead of a calling-convention bug. The metric
symptom (a structurally impossible 100% error rate for one op) is the fastest tell.

### Instances found

1. **`sd_posix_rename` (2026-08-03).** The SD vtable passes export-RELATIVE keys
   to drivers, but `brix_ns_rename()` demands ABSOLUTE paths under `root_canon`
   and refuses anything outside it as a cross-root move. `sd_posix_rename`
   forwarded the relative keys unchanged, so every same-directory rename failed
   with EXDEV → HTTP 500. `sd_posix_mkdir`/`unlink` had already learned this
   lesson ("the relative-path form silently failed") — rename just never got the
   same treatment. Fix: build the absolutes in `sd_posix_ns.c` exactly as its
   siblings do.
2. **`sd_posix_server_copy` (2026-08-04) — the sibling the first fix missed.**
   Same contract, same file, same failure mode: relative keys handed to
   `brix_ns_local_copy`, whose `brix_beneath_strip_root()` rejects a path that
   does not start with `root_canon` → EXDEV. Server-side copy therefore could not
   succeed on any export with an explicit `brix_storage_backend` (WebDAV COPY
   answered 403, S3 CopyObject 500), while a plain export kept working because
   `brix_vfs_ctx_driver()` returns NULL there and `brix_vfs_copy` takes the VFS
   namespace branch instead. `brix_io_ops_total{op="copy"}` had a 100% `other`
   rate on driver-backed exports for as long as the row existed. Pinned by
   `tests/test_cachemx_ops_grid.py::test_webdav_local_copy_books_ok` and
   `::test_s3_copy_object_books_ok`.

### How to avoid

- When one function in an SD driver builds absolutes before calling `brix_ns_*`,
  ALL of them must — the vtable contract is uniform. Check the siblings. Two of
  the five slots in `sd_posix_ns.c` shipped broken for exactly this reason, a
  year apart; "the siblings do it" is not a review that was done until every
  slot is listed.
- Grep the whole file for `brix_ns_` when fixing one call site. A fix that
  touches one slot and stops has, historically, left another one broken.
- A per-op conformance pin (one success per op per protocol) catches this class
  wholesale: an op that CANNOT succeed is exactly what
  `tests/test_cachemx_move_rename.py::test_move_fresh_dest_created_201` exists for.
- Treat "error bucket moves, ok bucket never does, across every input" as a
  calling-convention smell, not an environment problem.

---

## Pattern 11 — Hand-rolled exposition emits an unquoted label value

**Bug.** `brix_user_sessions_total` was written with
`mw_printf(mw, "brix_user_sessions_total{hash=%08x} %lu\n", ...)` — no quotes
around the label value. The Prometheus text format requires
`label="value"`; strict parsers (promtool, the Rust/Go client libraries)
reject the whole scrape, while lenient dashboards silently drop the family.
Because most families go through the shared label-table writers (which quote
for you), the one hand-formatted `mw_printf` row was the only bad line on the
board — invisible until a strict parser consumed the endpoint.

**Fix.** Quote the value at the emit site:
`"brix_user_sessions_total{hash=\"%08x\"} %lu\n"`.

**Test.** `tests/test_cachemx_auth_matrix.py` pins the quoted form after a live
GSI session and asserts no `hash=<bare>` row exists; board-wide,
`tests/test_cachemx_label_schema.py::test_exposition_has_no_unparsed_label_residue`
strips every well-formed `key="value"` pair from every exposed line and fails
on ANY residue — so the next hand-rolled emit site cannot regress unnoticed.

**Lesson.** Any `mw_printf` that writes `{` by hand bypasses the quoting the
shared writers guarantee. Grep for `mw_printf.*{` when adding families; prefer
the label-table writers.

---

## Pattern 12 — Module and core filter both parse the same request header

**Bug.** The WebDAV GET path set `r->allow_ranges = 1` while
`brix_http_serve_file_ranged()` already does its own Range parse and emits
206/416 itself. For well-formed ranges the core filter stayed out (status was
already 206). But for a malformed `Range` (`bytes=abc`, backwards
`bytes=500-100`) the module — per RFC 9110 §14.2 — ignored the header and
served the full 200 body, booking `range_result="full"` and the full object
size on `brix_io_bytes_read`… after which nginx's core range filter re-parsed
the same header, rejected it, and rewrote the response to a 416 error page.
Wire truth: 416, 197 bytes. Ledger truth: full 200, 2000 bytes read. The
metrics were accounting for a response the client never received.

**Fix.** `src/protocols/webdav/get.c` — `r->allow_ranges = 0` on the serve
path (the module owns range semantics end-to-end) plus an explicit
`Accept-Ranges: bytes` header so clients still discover range support.

**Test.** `tests/test_cachemx_range_windows.py::test_dav_malformed_range_serves_full`
(200 + full body + `result="full"`, never `partial`) and
`test_dav_advertises_accept_ranges` (the advertisement survives the filter
being disabled). The S3 object path never set the flag — its identical
malformed-range test passed throughout, which is what localized the bug.

**Lesson.** When a handler implements a header's semantics itself, it must
also *disown* the core filter for that header. Two parsers with different
tolerance levels on one header means status code and accounting are decided
by different code — they will disagree exactly on the inputs the tests probe
last (the malformed edge).

---

## Pattern 13 — Declared row with no booking owner at all

**Bug.** `BRIX_METRIC_OP_TPC` was a full citizen of the unified grid: it had an
enum slot, an exposition label, and a mapping (`webdav_unified_op()` maps
`COPY → OP_TPC`). It was also unreachable. The protocol-level `op_done` is
deliberately restricted to READ/WRITE (Pattern 6 instance 1), so the one call
site that named `OP_TPC` could never fire it, and no other layer booked it.
`brix_io_ops_total{op="tpc"}` therefore exported a permanent `0` on every
protocol — the exact shape of a working metric that is measuring nothing.
Pattern 6's inverse: not two owners, zero.

**Why it survived.** Zero is the *correct* value for a server that has performed
no third-party copies, so nothing about the exposition looked wrong. The
TPC-specific families (`brix_tpc_transfers_total`, `brix_tpc_bytes_total`) were
booked correctly the whole time, so a TPC *was* observable — just not in the
unified per-op ledger where a dashboard joins it against every other operation.
A catalogue test that only asserts a row's presence and type cannot see this;
only driving the op and asserting movement can.

**Fix.** `brix_metric_op_count()` (`src/observability/metrics/unified_record.c`)
— the count-only sibling of `brix_metric_op_done`/`_op_latency` — called from
`brix_tpc_metric_book()` in `src/tpc/common/metrics.c`, the single funnel both
transports already reach (native root:// and WebDAV COPY). Count-only is not a
shortcut: a TPC's clock lives in the TPC registry across a detached thread, so
there is no request-scoped duration to file, and filing `0` would falsify the
lowest latency bucket. The row is deliberately absent from
`brix_io_latency_usec_*`.

**Test.** `tests/test_cachemx_ops_grid.py::test_tpc_pull_books_unified_op_and_exact_bytes`
(op row + byte-exact `brix_tpc_bytes_total` from one real pull leg) and
`::test_tpc_pull_count_only_no_latency_row` (the histogram must NOT move).

**Lesson.** "The row exists and parses" is not coverage. For every declared
`(proto, op)` pair, either a conformance test drives it to a nonzero value or
the pair is documented as structurally unreachable — otherwise the grid is
asserting the existence of measurements nobody takes. When auditing, enumerate
the declared cells and diff them against the cells any test has ever moved.

---

## Audit checklist derived from these bugs

Use this when reviewing new handlers or modifying existing ones.

```
[ ] Every BRIX_OP_* constant maps to a unique integer (no duplicates).
[ ] BRIX_NOPS == len(brix_op_names) — guarded by _Static_assert.
[ ] New opcode handler: constant added, name added, BRIX_OP_OK/ERR at every return.
[ ] Every return brix_send_error(...) is preceded by BRIX_OP_ERR (or uses BRIX_RETURN_ERR).
[ ] bytes_* counters use _ADD, not _INC.
[ ] Per-IP-version _ADD is co-located with the matching bytes_rx/tx_total _ADD.
[ ] Per-IP-version _ADD comes after the byte count is known (i.e., not at dispatch time).
[ ] Related metric groups (contents / prefixes / truncated) are all written together.
[ ] New response path: bytes_tx_total AND bytes_tx_ipv4/ipv6_total both added.
[ ] New body-read path: bytes_rx_total AND bytes_rx_ipv4/ipv6_total both added.
[ ] Each unified (proto, op) row has exactly ONE booking owner (see Pattern 6 table);
    never emit op_done on a path whose row is owned elsewhere.
[ ] ...and at least one: a declared (proto, op) with no owner exports a permanent
    zero (Pattern 13). Every declared cell is driven by a test or documented as
    structurally unreachable.
[ ] Handlers returning NGX_DONE finalize via the metrics-aware wrapper at the async
    completion point (never bare ngx_http_finalize_request in a body handler) —
    at BOTH completion points, the re-entry and the failure/on_fail tail.
[ ] Auth pipelines book exactly one result row per request — stop at first verdict.
[ ] Every HANDLED method has its own enum slot — nothing real folds into OTHER.
[ ] SD driver namespace ops all build absolutes before brix_ns_* (uniform contract).
[ ] Hand-formatted mw_printf rows quote every label value (label="value").
[ ] A handler that parses a request header itself disables the core filter for
    that header (e.g. allow_ranges=0 when the module emits its own 206/416).
```
