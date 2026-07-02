# Phase 58 — XRootD parity batch (hyper-detailed design record)

**Status:** plan / spec — **implementation in progress** (see §0.IMPL)
**Date:** 2026-06-26
**Owner decisions:** resolved — see §Z (ADR log). CNS **is in scope**; SSI **is in
scope**, validated by interop against a real XRootD instance/cluster built from
official components; GSI delegation **Phase 2 is gated on first fixing the outbound
native-GSI client** (`native_tpc_gsi_broken`); checksum xattr is stored **host-order**
(bit-for-bit stock-compatible on the same architecture).

**Scope:** seven official-XRootD features absent (or partial) in the nginx module,
plus **checksum-at-rest** (XrdCks/XrdOssCsi parity) and a **`.cinfo` cache-metadata**
upgrade. **Non-goals:** the C++ plugin ABI; UDP f/g-stream monitoring.

This is a "live design record" in the sense of the phase-44/55/56 docs: it carries
wire byte-layouts, near-final annotated function skeletons, exact edit hunks against
existing files, state machines, per-function ABI contracts, a requirements
traceability matrix, ADRs, a risk register, a PR-by-PR rollout, and per-item test
matrices. Every feature obeys the project rules captured in §A.

---

## Table of contents
- §0  Tiering, sequencing, and decision impact
- §A  Conventions & contracts (build, config, flags, errors, threads, tests)
- §1  `?authz=` query bearer token
- §2  macaroon-request content-type
- §3  XrdDig remote diagnostics
- §4  OssArc archive aggregation
- §5  GSI X.509 proxy delegation (`kXGC_sigpxy`)
- §6  Composite Cluster Name Space (CNS)
- §7  XrdSsi (minimal native subset)
- §8  Checksum-at-rest (XrdCks / XrdOssCsi parity)
- §9  `.cinfo` cache metadata upgrade
- §R  Requirements traceability matrix
- §Z  ADR log (decisions) + risk register
- §S  Near-complete annotated source skeletons
- §T  Consolidated edit-hunk set (every touched file)
- §U  Byte-level sequence & state diagrams
- §V  Concurrency, memory-ordering & reentrancy proofs
- §W  Capacity & performance model
- §X  Failure-injection matrix
- §Y  CI/CD + PR-by-PR rollout with review checklists
- §AA Observability (metrics, logs, /healthz, qconfig)
- §BB Complete config-directive reference
- §CC Kernel / dependency / compatibility matrix
- §DD Interop harness (official XRootD cluster for SSI/CNS/GSI)
- §EE Compile-ready complete source (authoritative; corrects §S)
- §FF Per-function ABI/contract tables
- §GG Wire test vectors (hex fixtures)
- §HH Explicit state-transition tables
- §II Detailed test specifications (pytest)
- §JJ Definition-of-Done + kill switches / rollback
- §KK Migration & backward-compatibility notes
- §LL Design FAQ
- §MM Formal requirements (FR/NFR/SEC/BLD/OPS) + traceability
- §NN Open questions / future work
- §OO Complete subsystem sources (dig, delegation, CNS, SSI)
- §PP Exact `./config` additions (per new file)
- §QQ Subsystem README templates
- §RR Full config glue (config.h fields, directives.c rows, merges)
- §SS Build & smoke-test runbook
- §TT Protocol / constant reference tables
- §UU Formal grammars (EBNF)
- §VV STRIDE threat model per feature
- §WW Performance benchmark & regression-gate plan
- §XX Telemetry: alert rules, Grafana panels, SLOs
- §YY Operational runbooks (symptom → check → fix)
- §ZZ Data-format versioning & forward/back-compat
- §A2 Test fixtures / conftest additions
- §B2 End-to-end worked scenarios
- §C2 Cross-feature interaction matrix
- §D2 Effort estimation & critical path
- §E2 Documentation deliverables map
- §F2 Release sign-off checklist
- §G  Glossary

---

## §0. Tiering, sequencing, and decision impact

| # | Feature | Effort | Tier | In-scope? |
|---|---|---|---|---|
| 1 | `?authz=` query bearer token | S (1–2 d) | quick interop | yes — do first |
| 2 | macaroon-request content-type | S (2–3 d) | quick interop | yes |
| 3 | XrdDig remote diagnostics | S–M (~1 wk) | focused | yes |
| 4 | OssArc archive aggregation | A:S–M / B:M–L | phased | yes |
| 8 | Checksum-at-rest | 8.1–8.3 S–M / 8.4 L | focused | yes |
| 9 | `.cinfo` cache metadata | S–M | focused | yes |
| 5 | GSI proxy delegation | M–L (~2–3 wk) | protocol+crypto | yes (Phase 2 gated) |
| 6 | Composite Cluster Name Space | L | architectural | **yes** (was gated) |
| 7 | XrdSsi (minimal) | L | framework | **yes** (was gated) |

**Decision-adjusted sequence**

```
Sprint 1 (interop):     1  →  2
Sprint 2 (diagnostics): 3
Sprint 3 (integrity):   8.1 → 8.2 → 8.3  →  9      (8 feeds 9's verify-on-fill)
Sprint 4 (archive):     4A (member read) → 4B (compose/stage)
Sprint 5 (GSI):         5-Phase1 (receive+store)
                        ── BLOCKER ── fix outbound native-GSI client first ──
                        5-Phase2 (TPC consume)
Sprint 6 (cluster):     6 CNS minimal (event feed → manager inventory)
Sprint 7 (services):    7 SSI minimal (unary request/response) + official-interop harness
Backlog:                8.4 per-page CSI + scrub
```

Dependency edges: `8 → 9` (cinfo stores the origin digest from §8); `5-P1 → 5-P2`
with the outbound-GSI fix in between; `4A → 4B`; `6` reuses the `src/cms/` channel and
`src/srr/` totals; `7` reuses `kXR_read`/`kXR_write` plumbing and is validated against
a real XRootD SSI peer (per ADR-2).

---

## §0.IMPL — Implementation status (live)

| # | Feature | Status | Evidence |
|---|---|---|---|
| 1 | `?authz=` query token | **DONE** | builds; `tests/test_query_token.py` 6/6; helper unit test; in-place log redaction of args/unparsed_uri/request_line in `webdav_verify_bearer_token` |
| 2 | macaroon-request content-type | **DONE** | builds; `tests/test_macaroon_request.py` 4/4; dCache `uri{}` shape; routed in `dispatch.c`; reuses `xrootd_macaroon_issue` |
| 8.1 | XrdCks binary codec + tolerant read | **DONE** | builds; `xrootd_cksdata_encode/decode` in `integrity_info.c`; reader parses stock binary `user.XrdCks.<alg>`; codec unit test passes |
| 8.2 | `.cks` sidecar backend (auto-fallback) | **DONE** | builds; `integrity_sidecar_{read,write}` + `.cks` path; `get_fd` reads xattr→sidecar and writes sidecar on `ENOTSUP/EOPNOTSUPP/EPERM`; sidecar unit test passes |
| 8.3 | checksum-on-ingest (WebDAV PUT) | **DONE** | `webdav_put_persist_checksums` on all 3 PUT commit points; `xrootd_webdav_checksum_on_write <algs>` (comma/space list); `tests/test_checksum_on_write.py` 2/2 (adler32+crc32c xattr matches content; control = no xattr) |
| 8.3 | checksum-on-ingest (S3) | **DONE (existing flow)** | S3 PUT already persists via `xrootd_integrity_get_fd("crc64nvme", update=1)` (`s3/util.c`) + multi-algo `s3/checksum.c`; with §8.x format it lands as binary `XrdCksData` too |
| 8.3 | checksum-on-ingest (root:// close / TPC) | TODO (needs async) | a synchronous full-file digest on `kXR_close`/TPC-done would block the worker event loop on large files; correct impl offloads to the AIO pool (reuse `query/checksum_qcksum_async.c`). Deferred rather than add hot-path blocking |
| 8.x | write-binary xattr format | **DONE** | `xrootd_integrity_set_xattr_format` + binary write in `integrity_xattr_write_rc`; `xrootd_webdav_checksum_xattr_format text\|xrdcks` directive (process-global); `tests/test_checksum_on_write.py::test_xrdcks_binary_format` proves on-disk `user.XrdCks.adler32` is a stock `XrdCksData` record (Name/Length/Value validated). M8 interop now complete BOTH directions |
| 9 | `.cinfo` cache metadata | **DONE (stats + block bitmap)** | (stats) versioned tail (access_count/last_access/bytes_served + origin-digest) on `xrootd_cache_meta_t`, back-compat read, `xrootd_cache_meta_touch`, wired into slice-hit. (bitmap) new `src/cache/cinfo.{c,h}`: `<cachefile>.cinfo` = versioned header + `ceil(size/block_size)`-bit block-present bitmap; `xrootd_cache_cinfo_record_block` (flock-serialised RMW, origin-change reset, COMPLETE/PARTIAL flags) wired into `slice_fill.c` after each window lands; `slice.c` evict drops the `.cinfo`; load DECLINEs short/garbage (torn-write-safe). Unit-tested (`tests/c/test_cinfo.c`, 53 checks) + integration (`tests/test_slice_cache.py`: partial read records only touched blocks, full read → COMPLETE). Record-keeping only — read-time serve-present/fetch-gaps from the bitmap is the remaining follow-up |
| 3 | XrdDig (HTTP surface) | **DONE** | `src/dig/{dig.c,dig.h}`; WebDAV dispatch hook; directives `xrootd_webdav_dig` / `_dig_export <name> <dir>` (realpath anchor) / `_dig_auth <allowfile>`; RESOLVE_BENEATH confinement + fail-closed principal→export allow-file + GET/HEAD-only; `tests/test_dig.py` 7/7 (authorized read, unlisted→403, anon→403, **symlink-escape blocked**, unknown-export→404, write→405, disabled→fall-through). Follow-up: root:// surface + dirlist |
| 4A | OssArc zip member read | **DONE (pre-existing)** | already in tree: `zip_member.c`/`zip_http.c`; `webdav/get.c` `zip_access`; root:// `xrdcl.unzip=` in `open_request.c`. Doc §4A was stale |
| 5 | GSI delegation | **DONE (pre-existing)** | already in tree+build: `src/auth/gsi/delegation.c` (begin_delegation→`kXGS_pxyreq`, `handle_sigpxy`), `src/auth/gsi/proxy_req.c` (X509_REQ CSR + unittest), session-cipher encrypt, auth.c branches, TPC `tpc_delegate` consumption. `native_tpc_gsi_broken` memory was stale. Doc §5 was a stale TODO |
| 6 | CNS (minimal) | **DONE** | `src/cms/cns.{c,h}` event codec + per-worker inventory; `CMS_RR_CNS` frame; data-server emit on closew (`close.c`); manager apply (`server_recv.c`, gated by global collect flag); manager **global stat from inventory** (`stat.c` manager_mode); `xrootd_cns off\|emit\|collect`; `tests/test_cns.py` 2/2 on a real **2-node cluster** (manager stats a DS-written file from CNS w/ correct size; unknown path not fabricated). v1: in-memory per-worker (single-worker manager); SHM-multi-worker + unlink/mkdir/mv emit are follow-ups |
| 7 | SSI (minimal unary) | **DONE** | `src/ssi/{ssi.c,ssi.h}` echo over `/.ssi/<service>`; `xrootd_file_t.ssi` + clean early-return hooks in open/read/write; `xrootd_ssi` stream directive (in `module.c` — the LIVE table; `module_core_directives.c` is dead/not in `./config`); `tests/test_ssi.py` 4/4 raw-wire vs real instance. **Also fixed a pre-existing remote crash**: `kXR_chkpoint` on a path-less handle did `strlen(NULL)`→SIGSEGV (now guarded; 30 chkpoint tests pass) |

New build-list addition so far: `src/core/compat/json_min.c` (for §2) — registered in
`./config`, reconfigured. No other new files yet; §1/§2/§8.1 are edits to existing TUs.

Notes surfaced during implementation:
- §1 redaction must run **after** the token is consumed and must be **length-
  preserving** (overwrite, no memmove) because `r->args`/`r->unparsed_uri`/
  `r->request_line` alias the same buffer; the value scan stops at `&` **and**
  whitespace (else it clobbers " HTTP/1.1" in the request line). Caught by unit test.
- §2: `xrootd_macaroon_issue` requires a **non-NULL identifier**; the handler
  generates one (v=1;t=..;n=..) like the OAuth2 path. dCache read-path scope is **not**
  enforced server-side on GET (validator isn't passed the request path) — §2 only
  guarantees the issued macaroon *carries* the requested caveats (verified by decode).
- §8.1: the official xattr key is the **same** `user.XrdCks.<alg>` as ours but binary;
  a record is detected by exact struct size and mtime-validated. Struct is **96 bytes**
  on x86-64 (not 88 — alignment), handled via `sizeof`. Host-order per ADR-4.

---

## §A. Conventions & contracts (apply to every item)

### A.1 Build registration (the only two governance points)
New `.c`/`.h` files are registered in the **top-level `./config`** (NOT
`src/core/config/config.h` — see memory `build_source_list_location`). Two lists:

- **Headers** go in the dependency list (`./config` ~lines 274–296 style):
  ```sh
  $ngx_addon_dir/src/<sub>/<file>.h \
  ```
- **Sources** go in the `NGX_ADDON_SRCS` list (`./config` ~lines 665–700 style):
  ```sh
  $ngx_addon_dir/src/<sub>/<file>.c \
  ```

After adding a **new file or directory**, run `./configure --with-stream … --add-module=$REPO`
once; thereafter `make -j$(nproc)`. Editing an existing file needs no reconfigure.
Per-feature "Build" subsections below give the exact lines to add.

### A.2 Config directive pattern
1. Field in `src/core/types/config.h`, initialized `NGX_CONF_UNSET`/`NGX_CONF_UNSET_PTR`.
2. `ngx_command_t` row in the subsystem `directives.c` (HTTP loc/srv or stream srv).
3. Merge in `merge_*_conf()` with `ngx_conf_merge_*`.
A new **top-level block** needs `./configure`; a new directive in an existing block
does not.

### A.3 Feature-flag pattern
Add `XROOTD_WITH_<FEATURE>` to `src/core/feature_flags.h` (default-on for direct test
builds; the `./config` script passes `-DXROOTD_WITH_<F>=0` to disable). Surface the
live state in `/healthz` JSON and `kXR_Qconfig` so conformance + ops can assert it.

### A.4 errno → kXR → HTTP mapping (single source of truth)
| errno | kXR | HTTP | used by |
|---|---|---|---|
| ENOENT | kXR_NotFound | 404 | dig miss, zip member miss |
| EACCES/EPERM | kXR_NotAuthorized | 403 | dig authz, scope deny |
| EINVAL | kXR_ArgInvalid | 400 | bad macaroon-request body, bad duration |
| EISDIR | kXR_isDirectory | 409/400 | member of a dir |
| ENOTSUP | kXR_Unsupported | 501 | compressed member w/o codec; xattr→sidecar fallback |
| EIO | kXR_IOError | 500 | pread/inflate failure |
| ENOMEM | kXR_NoMemory | 507 | allocation |

### A.5 Thread-context annotations (per phase-54 contract)
Every new function is tagged in its docblock with one of:
`LOOP-ONLY` (touches `ngx_pool`/`ctx`/metrics/log/cache — event thread only),
`THREAD-SAFE` (pure compute on pre-allocated buffers; safe on the AIO pool),
`EITHER` (no shared state). CI grep enforces no `LOOP-ONLY` symbol is called from an
EXECUTE phase.

### A.6 Test contract
Each change ships **≥3 tests**: success, error, security-negative. Where an official
peer exists, add an **interop** test against `/tmp/xrootd-src` binaries (xrdfs/xrdcp,
davix/gfal2, real `XrdSecgsi`, a real cmsd/SSI cluster per ADR-2). Tests use absolute
paths and the xdist port-band convention (`full_suite_run_recipe`,
`conf_inplace_update_dataloss`).

### A.7 Style hard-blocks
No `goto`; one responsibility per function; pass `ctx` (no new globals); reuse
HELPERS (`ngx_http_xrootd_webdav_resolve_path`, `xrootd_open_beneath`,
`xrootd_auth_gate`, `XROOTD_PROXY_METRIC_INC`, `webdav_metrics_return`). New concept ⇒
docs + tests in the same change.

---

## §1. HTTP bearer token via `?authz=` query parameter

**Goal.** Accept the bearer token in the URL query (`…?authz=Bearer%20<jwt>` or a raw
token / macaroon) on every WebDAV/HTTP method, matching davix / gfal2 / xrdcp
redirected and pre-signed-URL flows. The `Authorization` header stays primary; the
query is a strict fallback. (XrdHttp reads `authz=` from the request CGI.)

### 1.1 Current state (verified)
`src/webdav/auth_token.c::webdav_verify_bearer_token()` extracts **only** from
`r->headers_in.authorization` via `xrootd_http_extract_bearer(&auth_hdr,&bearer)`
(`compat/http_headers.h`), then runs the L1 (per-worker lockless) → L2 (SHM) →
`xrootd_token_validate()` ladder. There is no query-string path.

### 1.2 Files touched
- `src/webdav/auth_token.c` — add the query fallback (edit hunk in 1.5).
- `src/core/compat/http_headers.{c,h}` — move/host `urlencode_decode_inplace`
  (today private in `macaroon_endpoint.c`) + add `xrootd_http_arg_token()`.
- `src/webdav/log.c` (access-log line build) — redaction.
- `src/webdav/config.c` + `directives.c` — `xrootd_http_query_token`.

### 1.3 Function signatures + ABI contracts
```c
/* compat/http_headers.h
 * EITHER. Find query arg `name` in `args`; copy its raw (still-%XX-encoded) value
 * into out (pool-owned, NUL-terminated). NGX_OK / NGX_DECLINED (absent). */
ngx_int_t xrootd_http_arg(ngx_http_request_t *r, const char *name, size_t nlen,
                          ngx_str_t *out);

/* webdav/auth_token.c (static)
 * LOOP-ONLY. Token from ?authz=. Pre: r->args may be empty. Post on NGX_OK: *out
 * points into an r->pool buffer, NUL-terminated, with any leading "Bearer "
 * (case-insensitive) stripped and %XX/'+' decoded. NGX_DECLINED when absent or
 * disabled by config. Never logs the value. */
static ngx_int_t webdav_bearer_from_query(ngx_http_request_t *r,
                                          ngx_http_xrootd_webdav_loc_conf_t *conf,
                                          ngx_str_t *out);

/* webdav/log.c
 * EITHER. In-place redact the value of every `authz`/`access_token` query key in a
 * pool copy of the request line/args used for logging: "authz=eyJ..."→"authz=REDACTED".
 * Idempotent; bounds-checked; preserves other args. */
void xrootd_http_redact_query_token(ngx_str_t *line);
```

### 1.4 Decode/strip algorithm (exact)
1. `xrootd_http_arg(r,"authz",5,&raw)` → if `NGX_DECLINED`, also try `access_token`.
2. Copy `raw` into `buf = ngx_pnalloc(r->pool, raw.len+1)`.
3. `len = urlencode_decode_inplace(buf)` (handles `%20`, `+`). Re-NUL at `len`.
4. If first 7 bytes case-insensitively equal `"bearer "`, advance 7 and shorten.
5. Reject if remaining len is 0 or > `XROOTD_TOKEN_MAX` (DoS guard) → `NGX_DECLINED`.
6. `out->data=buf; out->len=len;`

### 1.5 Exact edit hunk — `auth_token.c`
Insert immediately after the existing header block fails (line ~125–127):
```c
    if (r->headers_in.authorization == NULL) {
-        return NGX_DECLINED;
+        ngx_str_t qtok;
+        if (conf->http_query_token
+            && webdav_bearer_from_query(r, conf, &qtok) == NGX_OK) {
+            bearer = qtok;                 /* fall through to the validate ladder */
+        } else {
+            return NGX_DECLINED;
+        }
+    } else {
+        ngx_str_t auth_hdr = r->headers_in.authorization->value;
+        int rc = xrootd_http_extract_bearer(&auth_hdr, &bearer);
+        if (rc == NGX_DECLINED) {
+            /* header present but not Bearer — still allow ?authz= fallback */
+            ngx_str_t qtok;
+            if (conf->http_query_token
+                && webdav_bearer_from_query(r, conf, &qtok) == NGX_OK) {
+                bearer = qtok;
+            } else {
+                return NGX_DECLINED;
+            }
+        } else if (rc != NGX_OK) {
+            return NGX_HTTP_UNAUTHORIZED;
+        }
    }
-
-    auth_hdr = r->headers_in.authorization->value;
-    rc = xrootd_http_extract_bearer(&auth_hdr, &bearer);
-    if (rc == NGX_DECLINED) { return NGX_DECLINED; }
-    if (rc != NGX_OK) { return NGX_HTTP_UNAUTHORIZED; }
     token = (const char *) bearer.data;
     token_len = bearer.len;
```
(Net effect: header path unchanged on success; query is the fallback when the header
is absent OR present-but-not-Bearer.)

### 1.6 Sequence
```
client GET /p?authz=Bearer%20JWT
  → access phase: webdav_verify_bearer_token()
      header? no → http_query_token on? → webdav_bearer_from_query() → decode/strip
      → L1/L2/validate ladder (unchanged)
  → on success: ctx->token_auth=1, scopes stored
log phase: xrootd_http_redact_query_token(&logline)  // JWT never on disk
```

### 1.7 Security threat model
- **T1 token-in-logs (HIGH).** Query strings are logged by nginx access log and by
  `error_log` request dumps. Mitigation REQ-1-SEC: `xrootd_http_redact_query_token`
  at the log callsite; a test greps the log for the JWT and FAILS if found.
- **T2 token-in-Referer / browser history.** Documented operational caveat; query
  tokens are for programmatic clients. No code change.
- **T3 DoS via huge `authz`.** Length cap (step 5) before any crypto.
- **T4 cache-key confusion.** L1/L2 key on the token bytes only, identical regardless
  of header-vs-query source → no new key surface.

### 1.8 Config
```c
/* types/config.h */            ngx_flag_t http_query_token;   /* NGX_CONF_UNSET */
/* webdav/directives.c */
{ ngx_string("xrootd_http_query_token"),
  NGX_HTTP_MAIN|NGX_HTTP_SRV|NGX_HTTP_LOC|NGX_CONF_FLAG,
  ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
  offsetof(ngx_http_xrootd_webdav_loc_conf_t, http_query_token), NULL },
/* webdav/config.c merge */     ngx_conf_merge_value(c->http_query_token, p->http_query_token, 1);
```

### 1.9 Test matrix (`tests/test_query_token.py`)
| id | case | expect |
|---|---|---|
| 1a | GET `?authz=Bearer<jwt>` valid | 200 + body |
| 1b | GET with header Bearer still works | 200 |
| 1c | both header+query present | header wins; 200 |
| 1d | `?authz=<rawjwt>` (no scheme) | 200 |
| 1e | expired/tampered query token | 403 |
| 1f | `xrootd_http_query_token off` + query token | 401/declined |
| 1g | oversized `authz` (1 MiB) | declined fast, no crypto |
| **1h** | **access log after 1a** | shows `authz=REDACTED`, **not** the JWT |
| 1i | interop: `gfal-copy https://…?authz=…` | 200 (davix/gfal2) |

### 1.10 PRs
PR-1.1 `xrootd_http_arg` + move `urlencode_decode_inplace` to compat (+unit test).
PR-1.2 `webdav_bearer_from_query` + auth_token hunk + directive (+1a–1g).
PR-1.3 log redaction (+1h) + docs + gaps-doc update.

**Effort:** S (1–2 d).

---

## §2. Macaroon-request content-type (dCache / XrdMacaroons)

**Goal.** `POST <path>` with `Content-Type: application/macaroon-request` and JSON
body `{"caveats":["activity:DOWNLOAD,LIST","path:/foo"],"validity":"PT1H"}` →
`200 application/json {"macaroon":"…","uri":{…}}`. Today only the OAuth2 form
(`POST /.oauth2/token`) exists (`src/webdav/macaroon_endpoint.c`).

### 2.1 Files touched
- `src/webdav/dispatch.c` — content-type detect → route (hunk in 2.4).
- `src/webdav/macaroon_endpoint.c` — `webdav_handle_macaroon_request` + body parser.
- `src/core/compat/iso8601.c` (new, tiny) — duration parse; `compat/json_min.h` reuse;
  `token/macaroon_issue.h` reuse.

### 2.2 Request/response schema
Request body (dCache):
```json
{ "caveats": ["activity:DOWNLOAD,LIST,STAGE", "path:/atlas/data"],
  "validity": "PT1H" }
```
`caveats[]` items: `activity:<comma-list>` (DOWNLOAD/UPLOAD/LIST/DELETE/MANAGE/STAGE),
`path:<abs>` (base path), optionally `ip:<cidr>`. `validity` = ISO-8601 duration.
Response:
```json
{ "macaroon": "<serialized>",
  "uri": { "target":"https://h/p",  "targetWithMacaroon":"https://h/p?authz=<m>",
           "base":"https://h/",      "baseWithMacaroon":"https://h/?authz=<m>" } }
```

### 2.3 Signatures + contracts
```c
/* macaroon_endpoint.c
 * LOOP-ONLY. Entry when Content-Type==application/macaroon-request. Auth-gates
 * (must be authenticated; macaroon_secret configured), reads body via
 * xrootd_http_read_body, parses, issues, emits 200 JSON. */
ngx_int_t webdav_handle_macaroon_request(ngx_http_request_t *r);

/* compat/iso8601.h
 * EITHER. Parse "PT1H30M"/"PT3600S"/"P1D" → seconds, clamp to [1,max]. The grammar
 * subset: optional 'P', optional 'T', integer+unit runs (D/H/M/S). NGX_OK/NGX_ERROR. */
ngx_int_t xrootd_iso8601_duration_secs(const char *s, size_t len,
                                       time_t max, time_t *out);

/* macaroon_endpoint.c (static)
 * EITHER. Map caveats[] (json array) → xrootd_macaroon_req_t {activity_mask,
 * path[], ip[]}. Default base path = the request URI. NGX_OK/NGX_ERROR(EINVAL). */
static ngx_int_t macaroon_caveats_to_req(const xrootd_json_t *arr,
                                         ngx_http_request_t *r,
                                         xrootd_macaroon_req_t *req);
```

### 2.4 Dispatch hunk — `dispatch.c`
Near the existing macaroon route block (around lines 122–140):
```c
+    /* dCache convention: any POST carrying the macaroon-request content type is a
+     * token-issue request, independent of path (target path becomes the caveat). */
+    if (r->method == NGX_HTTP_POST
+        && webdav_content_type_is(r, "application/macaroon-request")) {
+        return xrootd_http_read_body(r, webdav_handle_macaroon_request);
+    }
```
(`webdav_content_type_is()` is a 3-line case-insensitive helper added next to the
existing header utilities.)

### 2.5 Issuance flow
```
auth-gate (ctx->token_auth || ctx->identity authenticated; conf->macaroon_secret set)
  → read+limit body (≤16 KiB)
  → json_min parse {caveats[], validity}
  → macaroon_caveats_to_req(): activity mask + path (default r->uri) + optional ip
  → xrootd_iso8601_duration_secs(validity) → exp = now + secs   (clamp to conf max)
  → xrootd_macaroon_issue(secret, req, exp, &serialized)
  → build uri{} (scheme from r, host from Host header, path from req.path)
  → 200 application/json
```

### 2.6 Security
- Issuance requires an already-authenticated principal (no anonymous mint).
- The issued caveats may only **narrow** the caller's own rights — reuse the scope
  intersection already in `macaroon_issue.c`; never widen.
- `validity` clamped to `xrootd_macaroon_max_validity` (default 24 h).
- Body size capped (16 KiB) pre-parse.

### 2.7 Config
```
xrootd_macaroon_max_validity <duration>;   # default PT24H (loc), reuse existing secret directive
```

### 2.8 Test matrix (`tests/test_macaroon_request.py`)
| id | case | expect |
|---|---|---|
| 2a | POST macaroon-request → use via `?authz=` GET on caveat path | 200 |
| 2b | caveat `path:/a`, GET `/b` | 403 |
| 2c | `validity:PT1H` honored; `PT999999H` clamped | exp ≤ max |
| 2d | unauthenticated request | 401 |
| 2e | malformed JSON / bad duration | 400 |
| 2f | activity narrower than caller's rights enforced | 403 on widened op |
| 2g | interop: dCache/gfal2 macaroon client | 200 |

**Effort:** S (2–3 d).

---

## §3. XrdDig — remote diagnostics

**Goal.** Read-only, admin-only exposure of whitelisted server files (config, logs,
selected `/proc`) over **`root://` and HTTP**, under a dig path prefix, with a
principal→subtree allow-file. Reuses the proven `openat2 RESOLVE_BENEATH` confinement
from `src/dashboard/files.c` (memory `dashboard_file_viewer`).

### 3.1 Path model
A reserved logical prefix maps to named exports:
```
root://host//.well-known/dig/<export>/<relpath>      # stream
GET   https://host/.well-known/dig/<export>/<relpath># http (or alias dashboard files)
```
Each `<export>` is a config-declared real directory. `<relpath>` is confined beneath
that directory via `RESOLVE_BENEATH` (no `..`, no symlink escape).

### 3.2 Files (new `src/dig/`)
- `dig.c` — prefix recognizer + export resolver + read/stat/dirlist glue.
- `dig_auth.c` — allow-file parser + match (`principal → {export…}`).
- `dig.h`, `directives.c`, `README.md`.
- hooks: `src/read/open_resolved_file.c`, `src/read/stat.c`,
  `src/dirlist/handler.c` (stream); HTTP path aliases `src/dashboard/files.c`.

### 3.3 Signatures + contracts
```c
/* dig.c
 * EITHER. 1 if logical_path is under a configured dig export; fills *real_root
 * (export dir) and *rel (NUL-terminated relpath within it). 0 otherwise. */
int xrootd_dig_match(ngx_stream_xrootd_srv_conf_t *conf, const char *logical_path,
                     const char **real_root, const char **rel);

/* dig_auth.c
 * LOOP-ONLY. NGX_OK if ctx's principal (DN or token sub) may read `export` per the
 * allow-file; NGX_ERROR(403) otherwise. Allow-file format (one rule/line):
 *   <principal-glob> <export>[,<export>...]      # '*' = any authenticated
 * '#' comments; first match wins; default deny. */
ngx_int_t xrootd_dig_authorize(xrootd_ctx_t *ctx, const char *export);

/* dig.c
 * LOOP-ONLY (opens) / result fd is read THREAD-SAFE. O_RDONLY confined beneath the
 * export root via xrootd_open_beneath (RESOLVE_BENEATH). -1/errno on failure. */
int xrootd_dig_open(const char *real_root, const char *rel, ngx_log_t *log);
```

### 3.4 Read-path hunk — `open_resolved_file.c`
At the top of resolution, before the normal export confinement:
```c
+    const char *dig_root, *dig_rel;
+    if (conf->dig_enable
+        && xrootd_dig_match((void*)conf, logical_path, &dig_root, &dig_rel)) {
+        if (xrootd_dig_authorize(ctx, dig_root) != NGX_OK) {
+            return xrootd_send_error(ctx, c, kXR_NotAuthorized, "dig: forbidden");
+        }
+        fd = xrootd_dig_open(dig_root, dig_rel, c->log);
+        /* mark handle read-only + dig-origin so write/trunc/rename are refused */
+        ...
+    }
```

### 3.5 Sequence + state
```
open(.well-known/dig/conf/nginx.conf)
  → dig_match? yes (export=conf, root=/etc/nginx-xrootd, rel=nginx.conf)
  → dig_authorize(principal, "conf")? (admin token scope or allow-file)
  → xrootd_dig_open(RESOLVE_BENEATH)  → read-only handle
  → read/stat served from the confined fd; write/mkdir/rm → kXR_NotAuthorized
```

### 3.6 Security threat model
- **T1 traversal** (`../`, symlink): defeated by `RESOLVE_BENEATH` (kernel-enforced).
- **T2 privilege**: default deny; admin scope OR allow-file entry required; the
  feature is off by default (`xrootd_dig off`).
- **T3 secret leakage**: operator chooses exports; recommend exposing *config dir* and
  *log dir* only, never key material. Doc warns against exporting `/etc/grid-security`.
- **T4 write attempts**: dig handles are flagged read-only; all mutating opcodes →
  403, verified by a security-negative test.

### 3.7 Config
```
xrootd_dig off|on;                       # default off
xrootd_dig_export <name> <dir>;          # repeatable: conf /etc/nginx-xrootd, logs /var/log/nginx-xrootd
xrootd_dig_auth   <file>;                # principal → exports allow-file
```

### 3.8 Build (`./config`)
```
# headers list:  $ngx_addon_dir/src/dig/dig.h \
# srcs list:     $ngx_addon_dir/src/dig/dig.c \
                 $ngx_addon_dir/src/dig/dig_auth.c \
                 $ngx_addon_dir/src/dig/directives.c \
```
then `./configure`.

### 3.9 Test matrix (`tests/test_dig.py`)
| id | case | expect |
|---|---|---|
| 3a | admin reads exported config via `root://` | byte-exact |
| 3b | admin reads same via HTTP GET | byte-exact |
| 3c | dirlist of an export | entries listed |
| 3d | non-admin / unlisted principal | 403 |
| 3e | `../`/symlink traversal | 403 |
| 3f | non-whitelisted export name | 404 |
| 3g | PUT/DELETE on a dig path | 403 (read-only) |
| 3h | `xrootd_dig off` | path treated as normal namespace (404) |

**Effort:** S–M (~1 wk).

---

## §4. OssArc — archive aggregation (phased)

**Goal.** Pack many files into one archive for tape efficiency and serve individual
members; integrate compose/stage with FRM. Mirrors `XrdOssArc*` (external archiver
program model) and `XrdOssArcZipFile`.

### Phase A — member read (do first; the reader already exists)
`src/zip/zip_dir.{c,h}` is **built and unit-tested** (memory
`zip_member_w2_progress`) and exposes:
```c
typedef struct { char name[PATH_MAX]; uint64_t comp_size; uint64_t uncomp_size;
                 /* offset, method, … */ } xrootd_zip_member_t;
#define XROOTD_ZIP_OK 0
#define XROOTD_ZIP_ECORRUPT (-1)
#define XROOTD_ZIP_EIO      (-2)
int     xrootd_zip_find_member(int fd, off_t archive_size, const char *member,
                               size_t cd_max, xrootd_zip_member_t *out);
ssize_t xrootd_zip_extract_full(int fd, const xrootd_zip_member_t *m,
                                uint8_t *buf, size_t outcap);   /* stored/deflate */
```
The remaining work is the **nginx/wire wrapper** + ranged read (`extract_full` is
whole-member only today).

**New `src/zip/zip_member.c`**
```c
/* LOOP-ONLY open + THREAD-SAFE read. Resolve member, then read [moff,moff+n) of the
 * UNCOMPRESSED stream. For 'stored' members → a single pread (zero-copy/sendfile-able
 * when the range is contiguous). For 'deflate' → stream-inflate skipping moff bytes
 * (no whole-file buffer for huge members). Maps XROOTD_ZIP_* → kXR_/HTTP. */
ngx_int_t xrootd_zip_member_open(const char *archive, const char *member,
                                 xrootd_zip_handle_t *out);          /* fd + meta */
ngx_int_t xrootd_zip_member_pread(xrootd_zip_handle_t *h, off_t moff,
                                  uint8_t *buf, size_t n, ssize_t *got);
```

**Addressing.** Reuse XrdZip's opaque convention so stock clients interoperate:
`root://h//path/archive.zip?xrdcl.unzip=<member>` (stream) and
`GET /path/archive.zip?xrdcl.unzip=<member>` (HTTP). Parsed in
`src/read/open_request.c` (opaque already parsed there) and `src/webdav/get.c`.

**Hooks**
- `src/read/open_request.c` — detect `xrdcl.unzip=` → set a member-open intent on the
  pending open.
- `src/read/open_resolved_file.c` — when intent set, `xrootd_zip_member_open` and bind
  a read-only member handle (size = `uncomp_size`).
- `src/read/read.c` / `pgread.c` — route member handles through
  `xrootd_zip_member_pread` (CRC framing unchanged).
- `src/webdav/get.c` — same for HTTP GET (+ `Range` support via `moff`).

### Phase B — compose + stage (FRM-driven)
External-archiver model (don't write a native zip writer first).

**New `src/frm/archive.c`** + queue type:
```c
/* LOOP-ONLY. Enqueue a compose job: pack <dataset_dir> into <archive> using the
 * configured archiver program, write a manifest sidecar, optional tape stage-out. */
ngx_int_t xrootd_frm_archive_compose(const char *dataset_dir, const char *archive,
                                     xrootd_status *st);
/* THREAD-SAFE worker: fork/exec xrootd_archive_cmd; durable queue entry survives
 * restart (file=truth, SHM=cache) like the existing FRM staging queue. */
```
Manifest sidecar `<archive>.manifest` lists members + sizes + per-member checksum
(reuse §8) so member reads can verify and stage-in can validate.

**Flow**
```
admin/prepare → frm_archive_compose(dir, arc)
   → queue entry (durable) → worker forks xrootd_archive_cmd (zip/tar)
   → write <arc>.manifest (+ per-member XrdCks via §8)
   → optional FRM stage-out (existing tape REST path)
stage-in: reverse — pull <arc> from tape → members readable via Phase A
```

### 4.C Config
```
xrootd_archive_member_access on|off;     # Phase A, default off
xrootd_archive_prefix <path>;            # where archives live
xrootd_archive_cmd <prog>;               # Phase B external archiver (argv template)
```

### 4.D Build
`src/zip/zip_member.c`, `src/frm/archive.c` into `./config` srcs; `zip_member.h` into
headers; `./configure`.

### 4.E Test matrix
| id | phase | case | expect |
|---|---|---|---|
| 4a | A | read stored member via `root://` | byte-exact |
| 4b | A | read deflate member via HTTP + `Range` | byte-exact partial |
| 4c | A | missing member | 404 |
| 4d | A | encrypted / data-descriptor / unknown method | clean kXR_/HTTP error |
| 4e | A | interop: `xrdcp root://…/a.zip?xrdcl.unzip=m` (stock client) | byte-exact |
| 4f | B | compose dir → archive has all members + manifest | ok |
| 4g | B | stage-out then stage-in → member still readable + verifies | ok |
| 4h | A | path traversal in member name (`../x`) | rejected |

**Effort:** A = S–M; B = M–L.

---

## §5. GSI X.509 proxy delegation (`kXGC_sigpxy`)

**Goal.** As the **server**, request and receive a delegated proxy from a GSI client,
verify+store it, and (**Phase 2, gated**) use it as the client credential for onward
GSI TPC.

### 5.1 Current state (verified)
- Wire steps defined: `src/protocol/gsi.h` has `kXGS_pxyreq 2002`, `kXGC_sigpxy 1002`.
- Dispatch: `src/auth/gsi/auth.c` reads `gsi_step = ntohl(payload+4)`; handles
  `kXGC_certreq` (round 1) and `kXGC_cert` (round 2) only. Delegation is a **3rd
  round** after `kXGC_cert` verifies.
- Buffer API ready: `xrootd_gbuf_start(g,step)` / `xrootd_gbuf_bucket(g,type,d,n)` /
  `xrootd_gbuf_end(g)` and `xrootd_gsi_find_bucket(buf,len,type,&out,&outlen)`.
- Client-side proxy generation exists (`client/lib/proxy.c`: CSR + `proxyCertInfo`).
- **Missing:** bucket types `kXRS_x509 3022` and `kXRS_x509_req 3024` (add to
  `src/protocol/gsi.h`).

### 5.2 Option bits (official `XrdSecProtocolgsi.hh`)
`kOptsDlgPxy=1` (client asks to delegate), `kOptsSigReq=4` (client will sign),
`kOptsSrvReq=8` (server requests), `kOptsPxFile=16`, `kOptsPxCred=64`.

### 5.3 Wire layout (added round)
```
(after kXGC_cert verified, server holds DH session key + client EEC chain)

S→C  kXGS_pxyreq  XrdSutBuffer:
       "gsi\0" | step=2002(BE) |
       bucket{ type=kXRS_main(3001), len, data = AES-enc(
                 bucket{ type=kXRS_x509_req(3024), len, data = <PKCS#10 CSR DER> }
               ) } |
       bucket{ type=kXRS_none(0) }

C→S  kXGC_sigpxy  XrdSutBuffer:
       "gsi\0" | step=1002(BE) |
       bucket{ type=kXRS_main(3001), len, data = AES-enc(
                 bucket{ type=kXRS_x509(3022), len, data = <signed proxy chain DER> }
               ) } |
       bucket{ type=kXRS_none(0) }
```
`kXRS_main` encryption uses the already-derived AES session key (same path as
round 2). The CSR carries the `proxyCertInfo` extension (RFC 3820) so the returned
proxy is a valid delegated proxy.

### 5.4 Files (new `src/auth/gsi/delegation.c`)
```c
/* LOOP-ONLY. Generate ephemeral keypair + PKCS#10 CSR w/ proxyCertInfo; encrypt into
 * kXRS_main; send kXGS_pxyreq. Stash the private key on ctx (paired w/ the proxy the
 * client returns). Pre: kXGC_cert verified, conf->gsi_delegation != off. */
ngx_int_t xrootd_gsi_send_pxyreq(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* LOOP-ONLY. Decrypt kXRS_main, find kXRS_x509, parse the signed proxy chain; verify
 * (a) it chains to the authenticated EEC, (b) proxyCertInfo present + pathlen sane,
 * (c) not expired, (d) key matches the CSR we sent. NGX_OK / kXR_NotAuthorized. */
ngx_int_t xrootd_gsi_recv_sigpxy(xrootd_ctx_t *ctx, const uint8_t *body, uint32_t blen);

/* LOOP-ONLY. Store {proxy chain + server-held key} keyed by DN, in-memory per-session
 * always; when kOptsPxFile, also persist 0600/O_NOFOLLOW per credfile-hardening. */
ngx_int_t xrootd_gsi_deleg_store(xrootd_ctx_t *ctx, X509 *proxy,
                                 STACK_OF(X509) *chain, EVP_PKEY *key);
```

### 5.5 Dispatch hunk — `gsi/auth.c`
After the `kXGC_cert` success path (where `auth_done` would be set), branch on
delegation:
```c
     /* kXGC_cert verified: DN extracted, chain validated */
+    if (conf->gsi_delegation != XROOTD_GSI_DELEG_OFF && !ctx->deleg_done) {
+        return xrootd_gsi_send_pxyreq(ctx, c);   /* → emits kXGS_pxyreq, awaits sigpxy */
+    }
     ctx->auth_done = 1; ... register session ...
```
and add a `kXGC_sigpxy` arm to the step switch:
```c
+    if (gsi_step == (uint32_t) kXGC_sigpxy) {
+        if (xrootd_gsi_recv_sigpxy(ctx, ctx->payload, ctx->cur_dlen) != NGX_OK) {
+            return xrootd_send_error(ctx, c, kXR_NotAuthorized, "delegation failed");
+        }
+        ctx->deleg_done = 1; ctx->auth_done = 1; ... register ...
+        return XROOTD_RETURN_OK;
+    }
```

### 5.6 State machine
```
            kXGC_certreq            kXGC_cert (verified)         kXGC_sigpxy (verified)
 [START] ───────────────▶ [CERTREQ'd] ──────────────▶ [CERT_OK] ─────────────────▶ [DELEGATED]
                                          │ deleg=off            │ deleg!=off              │
                                          └────────────▶ [AUTHED] ◀──────── send kXGS_pxyreq ┘
 require + client refuses sigpxy → kXR_NotAuthorized
```

### 5.7 Advertise delegation
Set the delegation opt bit in the server's emitted GSI opts (`session/login.c` GSI
parms and/or the round-1 `kXGS_cert` opts), gated by `conf->gsi_delegation`. A
`require` server that gets no `kXGC_sigpxy` fails the auth.

### 5.8 Phase 2 — consume (GATED, ADR-3)
**Blocker:** the outbound native-GSI client is broken (`native_tpc_gsi_broken`:
dest never triggers pull; round-2 `exchange()` dead). **Fix/validate that first**, then
add a GSI-proxy mode to `src/tpc/` outbound (today OIDC/token only): present the stored
delegated proxy as the client credential to the GSI source.

Phase-2 sub-tasks (do after the outbound-GSI fix):
1. `tpc/source.c` + `bootstrap.c`: credential selection → delegated proxy.
2. Proxy lifetime check before launch; refuse if expired.
3. metrics: `tpc_gsi_delegated_total{result}`.

### 5.9 Security threat model
- **T1 forged proxy** — verify full chain to the authenticated EEC; reject otherwise.
- **T2 key/CSR mismatch** — the returned proxy MUST certify the public key from the
  CSR we generated (binds the delegation to this session).
- **T3 over-long pathlen / no proxyCertInfo** — reject (not a constrained proxy).
- **T4 at-rest theft** (kOptsPxFile) — 0600 + `O_NOFOLLOW`, per credfile-hardening
  ([[client_credfile_hardening]]); default is in-memory only.
- **T5 expiry** — store NotAfter; refuse use past it.

### 5.10 Config
```
xrootd_gsi_delegation off|request|require;   # default off
xrootd_gsi_delegation_store memory|file;     # default memory; file → 0600 dir
xrootd_gsi_delegation_dir <dir>;             # when store=file
```

### 5.11 Build
`src/auth/gsi/delegation.c` → `./config` srcs; bucket constants are header-only; `./configure`.

### 5.12 Test matrix (`tests/test_gsi_delegation.py`, real `XrdSecgsi`)
| id | phase | case | expect |
|---|---|---|---|
| 5a | 1 | real client delegates | server stores valid EEC-chained proxy |
| 5b | 1 | `require` + non-delegating client | kXR_NotAuthorized |
| 5c | 1 | forged proxy (self-signed, not chained) | rejected |
| 5d | 1 | key/CSR mismatch | rejected |
| 5e | 1 | expired delegated proxy | rejected at store or use |
| 5f | 1 | store=file → perms | 0600, no symlink |
| 5g | 2 | TPC pull from GSI source using delegated proxy | byte-exact (after outbound fix) |

**Effort:** Phase 1 M (~1.5 wk); Phase 2 M after the outbound-GSI fix (separate).

---

## §6. Composite Cluster Name Space (CNS) — minimal, in scope (ADR-1)

**Goal.** A cluster-wide file inventory at the manager/redirector: data servers report
namespace mutations; the manager aggregates them into a queryable inventory and feeds
space totals. Minimal subset (not XrdCnsd's offline files + `cns_ssi` reconcile).

### 6.1 Architecture
```
 data server (each)                         manager / redirector
 ────────────────                           ─────────────────────
 open(write)/close/mkdir/                    CMS channel (src/cms/)
 rm/mv/truncate  ──── CNS event ───────────▶ inventory store (SHM + file)
 (size on closew)                            ├─ answer stat/dirlist from inventory
                                             └─ feed src/srr/ space totals
```

### 6.2 Event record (our format — XrdCns not in the checkout)
Fixed-size, appended to the CMS frame stream (or a dedicated `kXR`-side opcode on the
manager link). Big-endian:
```
struct xrootd_cns_event {           /* 40 bytes + name */
    uint8_t   op;        /* 1=ADD 2=DEL 3=MKDIR 4=RMDIR 5=MV 6=TRUNC 7=CLOSEW */
    uint8_t   _rsvd[3];
    uint32_t  server_id; /* CMS-assigned data-server id */
    uint64_t  size;      /* file size (ADD/CLOSEW/TRUNC) */
    uint64_t  mtime;
    uint16_t  name_len;  /* logical path length */
    uint16_t  name2_len; /* MV target length (else 0) */
    uint8_t   name[];    /* name_len + name2_len bytes */
};
```

### 6.3 Files (new `src/cms/cns_*.c` + manager inventory)
```c
/* data-server side (src/cms/cns_emit.c) — LOOP-ONLY.
 * Emit one event on a namespace mutation; coalesced + best-effort (never blocks the
 * data path; queue + flush on the CMS heartbeat). */
void xrootd_cns_emit(xrootd_ctx_t *ctx, uint8_t op, const char *path,
                     const char *path2, uint64_t size, uint64_t mtime);

/* manager side (src/manager/cns_store.c) — LOOP-ONLY.
 * Apply an event to the inventory (SHM rbtree of path→{server,size,mtime}; file is
 * the durable truth, SHM the cache — same model as src/frm). */
ngx_int_t xrootd_cns_apply(const xrootd_cns_event *ev, size_t total_len);

/* manager side — answer metadata from the inventory. */
ngx_int_t xrootd_cns_stat(const char *path, xrootd_stat_t *out);
ngx_int_t xrootd_cns_dirlist(const char *dir, xrootd_dir_emit_cb cb, void *u);
uint64_t  xrootd_cns_space_used(void);   /* feeds src/srr */
```

### 6.4 Manager hooks
- `src/cms/server_recv.c` — decode CNS events alongside existing CMS frames.
- `src/manager/registry.c` / redirect path — answer `kXR_stat`/`kXR_dirlist` from
  `xrootd_cns_*` when the path is not locally present (manager has no data).
- `src/srr/` — `xrootd_cns_space_used()` augments space reporting.

### 6.5 Durability & reload
Inventory file is the source of truth; SHM is a rebuildable cache (rebuild on start by
replaying the file). Slot-count changes reset SHM with a WARN (matches existing SHM
table semantics, INVARIANT #10 / `shmtx_semaphore_lostwakeup`). Spin+yield SHM mutex
via `xrootd_shm_table_alloc()` (never POSIX-sem mode).

### 6.6 Consistency model (documented limits)
- **Eventually consistent**: a just-written file is visible at the manager after the
  next event flush (heartbeat cadence). Acceptable for redirector dirlist/space.
- **Reconciliation**: a periodic full re-sync (data server walks + bulk ADD) heals
  missed events after a restart. (`cns_ssi`-style audit tooling = non-goal.)

### 6.7 Config
```
xrootd_cns off|emit|collect;        # emit=data server, collect=manager
xrootd_cns_store <file>;            # manager durable inventory
xrootd_cns_flush_interval <t>;      # data-server coalesce window (default 10s)
```

### 6.8 Build
`src/cms/cns_emit.c`, `src/manager/cns_store.c` (+headers) → `./config`; `./configure`.

### 6.9 Test matrix (`tests/test_cns.py` — multi-instance like CMS tests)
| id | case | expect |
|---|---|---|
| 6a | write file on DS → manager stat after flush | size/mtime correct |
| 6b | mkdir/rm/mv on DS → manager dirlist reflects | consistent |
| 6c | manager space total = sum of DS files | matches |
| 6d | manager restart → inventory rebuilt from file | no loss |
| 6e | missed-event reconciliation re-syncs | heals |
| 6f | **security:** event from non-cluster IP | dropped (CMS allowlist) |

**Effort:** L (event feed S–M; inventory store + manager answers M; reconcile M).

---

## §7. XrdSsi — minimal native subset, in scope (ADR-2)

**Goal.** A minimal Scalable Service Interface: a generic **unary** request/response
RPC tunneled over the file protocol, dispatched to compiled-in service handlers, and
**validated against a real XRootD SSI peer** built from official components.

### 7.1 How SSI rides the file protocol
Client opens an SSI **resource** path → writes the request bytes (`kXR_write`) →
reads the response (`kXR_read`) → closes. Framing is the 8-byte `XrdSsiRRInfo`
(verified in `XrdSsiRRInfo.hh`):
```
union { unsigned char reqCmd;  uint64 info; };
 Opc { Rxq=0 (request), Rwt=1 (wait/poll), Can=2 (cancel) }
 reqId   : request id (echoed)
 reqSize : payload size (network order)
```
The C++ `Provider/Service/Responder` API is a **plugin-author** surface and does NOT
port to nginx-C — we implement the **wire behavior** with built-in handlers instead.

### 7.2 Minimal scope (explicit)
- Unary request → response only (no streaming responses, no async alerts, no metadata
  channel, no session multiplexing).
- An SSI resource namespace (`xrootd_ssi_resource <name> <handler>`).
- One example service (`echo`) + the dispatch table.
- Out of scope (documented): `XrdSsiStream` responses, `XrdSsiAlert`, scalable
  session mux, `XrdSsiCluster` GeoMgr.

### 7.3 Files (new `src/ssi/`)
```c
/* ssi.c — LOOP-ONLY. Recognize SSI resource opens; bind a virtual handle that buffers
 * the request on write and produces the response on first read. */
int        xrootd_ssi_is_resource(const char *logical_path, const char **name);
ngx_int_t  xrootd_ssi_open(xrootd_ctx_t *ctx, const char *name, xrootd_ssi_req_t **out);
ngx_int_t  xrootd_ssi_write(xrootd_ssi_req_t *rq, const uint8_t *p, size_t n); /* accumulate */
/* THREAD-SAFE handler invocation on the AIO pool (services are pure compute). */
ngx_int_t  xrootd_ssi_dispatch(xrootd_ssi_req_t *rq);   /* request→response */
ngx_int_t  xrootd_ssi_read(xrootd_ssi_req_t *rq, off_t off, uint8_t *buf, size_t n,
                           ssize_t *got);                /* serve response */

/* ssi_registry.c — service table: name → fn(req_bytes, len) → resp_bytes. */
typedef ngx_int_t (*xrootd_ssi_handler)(const uint8_t*, size_t, uint8_t**, size_t*);
ngx_int_t xrootd_ssi_register(const char *name, xrootd_ssi_handler h);
```

### 7.4 Hooks
- `src/read/open_request.c` / `open_resolved_file.c` — `xrootd_ssi_is_resource` → bind
  an SSI handle instead of a file fd.
- `src/write/write.c` — route writes on SSI handles to `xrootd_ssi_write`.
- `src/read/read.c` — route reads on SSI handles to `xrootd_ssi_read` (after dispatch).

### 7.5 Sequence
```
open(/ssi/echo)         → ssi_open → req buffer
write(req bytes)        → ssi_write (accumulate; RRInfo Rxq)
read(...)               → first read triggers ssi_dispatch (AIO pool) → response ready
                          subsequent reads stream the response
close                   → free req
```

### 7.6 Interop validation (ADR-2)
Stand up a real XRootD instance/cluster from `/tmp/xrootd-src` with an SSI service
(or use the stock SSI test client), point it at the nginx SSI resource, and assert the
echo round-trips byte-for-byte. This is the acceptance gate for the minimal subset.

### 7.7 Config
```
xrootd_ssi off|on;                       # default off
xrootd_ssi_resource <name> <handler>;    # e.g. echo echo
```

### 7.8 Build
`src/ssi/ssi.c`, `src/ssi/ssi_registry.c` (+headers) → `./config`; `./configure`.

### 7.9 Test matrix (`tests/test_ssi.py`)
| id | case | expect |
|---|---|---|
| 7a | open/write/read echo via raw wire | response == request |
| 7b | unknown resource | kXR error |
| 7c | oversize request | bounded reject |
| 7d | cancel (RRInfo Can) mid-flight | clean teardown |
| 7e | **interop:** official SSI client vs nginx echo | byte-exact |

**Effort:** L (wire plumbing M; interop harness M).

---

## §8. Checksum-at-rest (XrdCks / XrdOssCsi parity) — *requested*

### 8.0 Current state (verified)
`src/core/compat/integrity_info.c` already stores a checksum **xattr** and caches it:
- key: `user.XrdCks.<alg>`
- value (TEXT): `"<hex> <mtime_sec> <mtime_nsec> <size>"` (`INTEGRITY_XATTR_VAL_MAX 160`)
- staleness: recompute if live `mtime`/`size` differ from the stored triple.
- public API (corrected signatures):
  ```c
  ngx_int_t xrootd_integrity_get_fd(ngx_log_t*, int fd, const char *path,
              const char *alg_name, const xrootd_integrity_opts_t*, xrootd_integrity_info_t*);
  void xrootd_integrity_invalidate_fd(ngx_log_t*, int fd);
  void xrootd_integrity_invalidate_path(ngx_log_t*, const char *path);
  ```
Shared by `kXR_Qcksum`, XrdHttp `Want-Digest`, dirlist `dcksm`, S3 ETag/crc64nvme.
So "checksum alongside the file" **exists** — these are the gaps + enhancements.

### 8.1 Binary `XrdCksData` interop (host-order, ADR-4)
Official xrootd reads/writes a **binary `XrdCksData`** in the xattr; our text value is
not interoperable with stock `xrdfs query checksum`/OSS. Add a binary codec and write
**both** by default.

`XrdCksData` layout (from `XrdCks/XrdCksData.hh`), stored **host-order** (ADR-4 —
bit-for-bit stock-compatible on the same arch; documented divergence on mixed-arch):
```c
struct XrdCksData {        /* 88 bytes on x86-64 with default padding */
    char      Name[16];    /* algo name, NUL-padded ("adler32") */
    long long fmTime;      /* file mtime (sec) when computed */
    int       csTime;      /* delta sec from fmTime to compute time */
    short     Rsvd1; char Rsvd2;
    char      Length;      /* digest length in bytes */
    char      Value[64];   /* binary digest */
};
```
New helpers (`integrity_info.c`):
```c
/* EITHER. Encode/parse the official record. Host-order per ADR-4. */
size_t    xrootd_cksdata_encode(const xrootd_integrity_info_t *in, time_t fmtime,
                                uint8_t out[sizeof(struct XrdCksData)]);
ngx_int_t xrootd_cksdata_decode(const uint8_t *buf, size_t len, time_t cur_mtime,
                                xrootd_integrity_info_t *out);   /* stale→NGX_DECLINED */
```
Read order on lookup: prefer binary `XrdCks.<alg>` (interop), fall back to our text
key, else compute. Write per `xrootd_checksum_xattr_format`.

**Directive:** `xrootd_checksum_xattr_format text|xrdcks|both;` (default `both`).

### 8.2 Sidecar-file backend (no-xattr filesystems)
Some exports lack `user.*` xattrs (`setxattr → ENOTSUP`). Add a sibling
`"<path>.cks"` carrying one record per algorithm. Mirrors `cache/meta.c`
(`O_NOFOLLOW|O_CLOEXEC`, fixed records, short-rw-safe loop).
```c
/* paths-style mapping + record I/O. */
ngx_int_t xrootd_cks_sidecar_path(const char *file, char *dst, size_t dstsz); /* "<file>.cks" */
ngx_int_t xrootd_cks_sidecar_get(const char *file, const char *alg, time_t mtime,
                                 xrootd_integrity_info_t *out);
ngx_int_t xrootd_cks_sidecar_put(const char *file, const xrootd_integrity_info_t *in);
```
Record = `XrdCksData` blocks concatenated (host-order), validated by `fmTime` vs live
mtime. `.cks` files are hidden from dirlist (like `.meta`/lock xattrs).

**Directive:** `xrootd_checksum_store xattr|sidecar|auto;` (default `xattr`; `auto`
falls back to sidecar on `ENOTSUP`).

### 8.3 Checksum-on-ingest (proactive persistence, à la XrdOssCsi)
Today digests are lazy (first query). Persist at **ingest** so they're durable from
creation:
- `kXR_close` of a written handle → `src/read/close.c` (after fsync, before reply).
- WebDAV PUT completion → `src/webdav/put.c`.
- S3 PUT/complete-multipart → `src/s3/object.c`.
- TPC destination finish → `src/tpc/done.c`.
Computed on the **AIO thread pool** (reuse `query/checksum_qcksum_async.c`), never on
the event loop; on completion, `xrootd_integrity_*` persists via §8.1/§8.2.

```c
/* LOOP-ONLY enqueue → THREAD-SAFE compute → LOOP-ONLY persist. Fire-and-forget:
 * failure logs + leaves the file usable (digest just stays lazy). */
void xrootd_integrity_persist_async(ngx_log_t*, int fd, const char *path,
                                    const char *alg_list);
```
**Directive:** `xrootd_checksum_on_write off|<alg-list>;` (default `off`, e.g.
`adler32,crc32c`).

### 8.4 Per-page CSI + scrub (full XrdOssCsi) — backlog (L)
Full XrdOssCsi keeps a **per-4 KiB-page CRC** stream beside the data + verifies on read
+ background scrub. We already compute per-page CRC32c on the wire (pgread/pgwrite);
the heavy part is persisting that page-CRC stream at rest and a scrub job. Defer; the
file-level digest (8.1–8.3) covers the common WLCG need. Sketch for later:
`<path>.csi` = header + `ceil(size/4096)` × CRC32c; verify-on-read in
`src/fs/vfs_io_core.c` EXECUTE; scrub timer in `src/frm/` walking the export.

### 8.5 Build
codecs/sidecar are additions to existing `integrity_info.c` (no new file → no
reconfigure); `on-write` touches existing handlers; `.csi` (8.4) would add
`src/core/compat/csi.c` → `./config`.

### 8.6 Test matrix (`tests/test_checksum_at_rest.py`)
| id | case | expect |
|---|---|---|
| 8a | on-write adler32 → xattr present | yes |
| 8b | **interop:** stock `xrdfs query checksum` reads our `XrdCks.adler32` | matches |
| 8c | modify file → stored record stale → recompute | matches new content |
| 8d | sidecar mode on a no-xattr fs (tmpfs w/o user_xattr) | works |
| 8e | `auto` falls back on ENOTSUP | sidecar written |
| 8f | corrupt/short record (xattr or sidecar) | treated as miss, no crash |
| 8g | S3 PUT then GET ETag = stored crc | matches |
| 8h | format=both → both keys present | text + binary |

**Effort:** 8.1–8.3 S–M; 8.4 L (backlog).

---

## §9. `.cinfo` cache-metadata upgrade — *requested*

### 9.0 Current state (verified)
The cache writes a `.meta` sidecar per cached file (`src/cache/meta.{c,h}`):
```c
typedef struct { uint64_t mtime; uint64_t size;
                 uint8_t etag_len; char etag[55]; } xrootd_cache_meta_t;
```
A fixed POD, read/written verbatim via `xrootd_cache_meta_rw_all`
(`O_NOFOLLOW|O_CLOEXEC`, short-rw-safe), path = `<cachefile>.meta`. It is a *validity*
record only — **no block map**, so partially-filled slice caches can't prove which
ranges survive a restart, and eviction is size-only.

### 9.1 Why a richer `.cinfo` (verdict: worth it)
XrdPfc's `cinfo` carries size, block size, a **block-present bitmap**, access stats,
and a checksum/version. High-value subset here:
1. **Block bitmap** → partial slice fills survive restart; serve fetched windows
   instead of refetching whole files. (Today slice state is in-memory only.)
2. **Access stats** (last_access, hit count, bytes served) → LFU/age eviction in
   `evict_policy.c` instead of size-only.
3. **Origin digest** (reuse §8) → verify-on-fill end-to-end (closes the cache
   checksum-on-fill gap, B6 in `dropin_gap_analysis`).

### 9.2 On-disk format (versioned, back-compatible)
Keep reading old `.meta` one release; write `.cinfo`:
```c
typedef struct {                  /* fixed header; bitmap appended after */
    uint32_t magic;               /* 'XCI1' (0x58434931) */
    uint16_t version;             /* 2 */
    uint16_t flags;               /* COMPLETE=1 | PARTIAL=2 | VERIFIED=4 */
    uint64_t mtime, size;         /* origin validity (as .meta) */
    uint32_t block_size;          /* slice granule, e.g. 131072 */
    uint64_t access_count;
    uint64_t bytes_served;
    uint64_t last_access;
    uint8_t  etag_len; char etag[55];
    uint8_t  cks_alg;  uint8_t cks_len; uint8_t cks[64];   /* origin digest, §8 */
    /* then: ceil(size/block_size) bits, little-endian block-present bitmap */
} xrootd_cache_cinfo_t;
```

### 9.3 Functions (`src/cache/cinfo.c`, new)
```c
/* LOOP-ONLY (open) + EITHER (bit ops). load returns NGX_DECLINED on
 * missing/short/garbage (→ treat as empty cache = full refetch). */
ngx_int_t xrootd_cache_cinfo_load(const char *cachefile, xrootd_cache_cinfo_t *hdr,
                                  uint8_t **bitmap, size_t *bitmap_len);
ngx_int_t xrootd_cache_cinfo_store(const char *cachefile,
                                   const xrootd_cache_cinfo_t *hdr,
                                   const uint8_t *bitmap, size_t bitmap_len);
void xrootd_cache_cinfo_mark_block(uint8_t *bitmap, uint64_t blk);
int  xrootd_cache_cinfo_block_present(const uint8_t *bitmap, uint64_t blk);
/* migrate a legacy .meta → .cinfo (COMPLETE, no bitmap) on first touch. */
ngx_int_t xrootd_cache_cinfo_from_meta(const xrootd_cache_meta_t *m,
                                       xrootd_cache_cinfo_t *out);
```

### 9.4 Callers
- `src/cache/slice_fill.c` — `mark_block` after each window fill; set `VERIFIED` after
  digest check.
- `src/cache/open.c` / `open_or_fill.c` — consult bitmap → serve present windows,
  fetch only gaps.
- `src/cache/evict_policy.c` — score by `last_access`/`access_count`/`bytes_served`.
- `src/cache/fetch.c` / `slice_fill.c` — verify filled bytes against `cks` (§8) before
  marking present; mismatch → discard window + WARN.

### 9.5 Concurrency & crash safety
`.cinfo` writes are: build full image in memory → write to `<cachefile>.cinfo.tmp`
(O_CREAT|O_EXCL|O_NOFOLLOW) → `fdatasync` → atomic `rename`. Bitmap updates are
debounced (flush on fill-complete + on close + on a timer). A crash mid-fill leaves
the last durable bitmap; unmarked windows simply refetch (safe).

### 9.6 Config
```
xrootd_cache_cinfo on|off;        # default on; off keeps .meta behavior
```

### 9.7 Build
`src/cache/cinfo.c` (+`cinfo.h`) → `./config` (the cache header list at ~line 274);
`./configure`.

### 9.8 Test matrix (`tests/test_cache_cinfo.py`)
| id | case | expect |
|---|---|---|
| 9a | slice-fill 2 windows → restart → both served from disk | hit; gaps refetched |
| 9b | eviction picks lowest age/LFU score | correct victim |
| 9c | truncated/garbage `.cinfo` | treated empty, full refetch, no crash |
| 9d | checksum mismatch on fill | window discarded + WARN + refetch |
| 9e | legacy `.meta` present → migrated to `.cinfo` | COMPLETE, served |
| 9f | crash mid-fill (kill during fill) → restart | durable windows served, rest refetched |

**Effort:** S–M.

---

## §R. Requirements traceability matrix

| Req | Feature | Statement | Test(s) | Priority |
|---|---|---|---|---|
| REQ-1-FUNC | §1 | accept token from `?authz=` (header primary) | 1a–1d,1i | MUST |
| REQ-1-SEC | §1 | never log the query token | 1h | MUST |
| REQ-2-FUNC | §2 | issue macaroon for `application/macaroon-request` | 2a,2g | MUST |
| REQ-2-SEC | §2 | auth required; caveats only narrow; clamp validity | 2c,2d,2f | MUST |
| REQ-3-FUNC | §3 | admin reads whitelisted files over root://+HTTP | 3a–3c | MUST |
| REQ-3-SEC | §3 | confinement + default-deny + read-only | 3d–3g | MUST |
| REQ-4A-FUNC | §4A | serve a zip member (root://+HTTP, Range) | 4a,4b,4e | MUST |
| REQ-4A-SEC | §4A | reject traversal/unsupported member | 4d,4h | MUST |
| REQ-4B-FUNC | §4B | compose + stage archive (FRM) | 4f,4g | SHOULD |
| REQ-5-1 | §5 | receive+verify+store delegated proxy | 5a–5f | MUST |
| REQ-5-2 | §5 | TPC consume (after outbound-GSI fix) | 5g | SHOULD (gated) |
| REQ-6-FUNC | §6 | manager inventory from DS events; space totals | 6a–6e | SHOULD |
| REQ-6-SEC | §6 | only cluster members feed events | 6f | MUST |
| REQ-7-FUNC | §7 | unary SSI request/response + interop | 7a,7e | SHOULD |
| REQ-8-INTEROP | §8.1 | stock `xrdfs query checksum` reads our xattr | 8b | MUST |
| REQ-8-PORT | §8.2 | sidecar on no-xattr fs | 8d,8e | SHOULD |
| REQ-8-INGEST | §8.3 | checksum persisted at write | 8a,8g | SHOULD |
| REQ-8-ROBUST | §8 | corrupt record never crashes | 8f | MUST |
| REQ-9-FUNC | §9 | partial slice survives restart | 9a,9f | SHOULD |
| REQ-9-ROBUST | §9 | garbage cinfo safe; verify-on-fill | 9c,9d | MUST |

---

## §Z. ADR log (decisions) + risk register

### ADR-1 — CNS is in scope (minimal subset)
*Decision:* implement the event-feed + manager inventory + space-totals subset (§6);
XrdCnsd offline files + `cns_ssi` reconcile remain non-goals. *Rationale:* OP confirmed
cluster-global namespace is wanted. *Consequence:* adds a multi-instance test class;
eventually-consistent semantics documented.

### ADR-2 — SSI is in scope, validated by official interop
*Decision:* implement the minimal unary request/response subset (§7) and **gate
acceptance on interop with a real XRootD SSI peer** stood up from `/tmp/xrootd-src`.
*Rationale:* OP's "consumer" = test the nginx module against an official
instance/cluster. *Consequence:* a stock SSI cluster is part of the test fixture;
streaming/alerts/mux explicitly excluded.

### ADR-3 — GSI delegation Phase 2 gated on outbound-GSI fix
*Decision:* ship Phase 1 (receive+verify+store) first; **fix the broken outbound
native-GSI client (`native_tpc_gsi_broken`) before** Phase 2 (TPC consume).
*Rationale:* OP prioritized fixing outbound GSI first. *Consequence:* §5 splits cleanly;
5g is the only test deferred.

### ADR-4 — Checksum xattr stored host-order
*Decision:* encode `XrdCksData` in **host byte order**, matching stock xrootd
bit-for-bit on the same architecture. *Rationale:* OP chose stock-compatible-on-same-
arch. *Consequence:* mixed-architecture xattr sharing is a documented divergence (rare;
WLCG sites are homogeneous per pool); `xrootd_cksdata_decode` tolerates the local order
and treats unrecognized as a miss (recompute), so it never mis-serves.

### Risk register
| id | risk | sev | mitigation |
|---|---|---|---|
| RK-1 | query token leaks to logs | high | REQ-1-SEC redaction + grep test (1h) |
| RK-2 | GSI delegation crypto bugs | high | verify chain+CSR-binding+pathlen; real-client interop (5a–5f) |
| RK-3 | outbound-GSI still broken blocks 5g | med | ADR-3 gate; Phase 1 independent |
| RK-4 | CNS eventual-consistency surprises ops | med | document; reconciliation (6e); SRR unaffected |
| RK-5 | host-order xattr on mixed arch | low | ADR-4 decode-tolerant; doc |
| RK-6 | cinfo corruption serves stale data | med | load→DECLINED on garbage; atomic write; verify-on-fill |
| RK-7 | dig exposes secrets via misconfig | med | default off; doc warns; read-only; default-deny allow-file |
| RK-8 | zip member bomb (huge inflate) | med | reader already bounds by declared sizes; ranged inflate (no whole-file buffer) |
| RK-9 | SSI scope creep toward full framework | med | ADR-2 explicit minimal subset; non-goals listed |

---

## §S. Near-complete annotated source skeletons

These are intended to be ~drop-in: real APIs (verified against the tree), full error
handling, no `goto`, thread-context tagged. Names match §1–§9.

### S.1 `compat/http_headers.c` — query-arg + token extraction (§1)
```c
/* EITHER. Locate query arg `name` (len nlen) in r->args; copy its raw value into a
 * pool buffer (still %XX-encoded). NGX_OK with *out set, or NGX_DECLINED. */
ngx_int_t
xrootd_http_arg(ngx_http_request_t *r, const char *name, size_t nlen, ngx_str_t *out)
{
    ngx_str_t v;
    if (r->args.len == 0) {
        return NGX_DECLINED;
    }
    if (ngx_http_arg(r, (u_char *) name, nlen, &v) != NGX_OK) {
        return NGX_DECLINED;
    }
    out->data = ngx_pnalloc(r->pool, v.len + 1);
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(out->data, v.data, v.len);
    out->data[v.len] = '\0';
    out->len = v.len;
    return NGX_OK;
}
```

### S.2 `webdav/auth_token.c` — query-token fallback (§1)
```c
/* LOOP-ONLY. Token from ?authz= (then ?access_token=). Decodes %XX/'+', strips a
 * leading case-insensitive "Bearer ", enforces a length cap. NGX_OK/NGX_DECLINED. */
static ngx_int_t
webdav_bearer_from_query(ngx_http_request_t *r,
                         ngx_http_xrootd_webdav_loc_conf_t *conf, ngx_str_t *out)
{
    ngx_str_t raw;
    size_t    len;

    if (!conf->http_query_token) {
        return NGX_DECLINED;
    }
    if (xrootd_http_arg(r, "authz", 5, &raw) != NGX_OK
        && xrootd_http_arg(r, "access_token", 12, &raw) != NGX_OK) {
        return NGX_DECLINED;
    }
    len = urlencode_decode_inplace((char *) raw.data);   /* shared helper */
    if (len >= 7 && ngx_strncasecmp(raw.data, (u_char *) "Bearer ", 7) == 0) {
        raw.data += 7;
        len      -= 7;
    }
    if (len == 0 || len > XROOTD_TOKEN_MAX) {
        return NGX_DECLINED;                              /* DoS guard, T3 */
    }
    out->data = raw.data;
    out->len  = len;
    return NGX_OK;
}
```

### S.3 `webdav/log.c` — query-token redaction (§1)
```c
/* EITHER. In-place redact authz/access_token values in a pool copy of the query for
 * logging. Idempotent; preserves other args; never reallocates beyond the input. */
void
xrootd_http_redact_query_token(ngx_str_t *q)
{
    static const char *keys[] = { "authz=", "access_token=" };
    size_t k;
    for (k = 0; k < 2; k++) {
        u_char *p   = q->data;
        u_char *end = q->data + q->len;
        size_t  klen = ngx_strlen(keys[k]);
        while ((p = ngx_strlcasestrn(p, end, (u_char *) keys[k], klen - 1)) != NULL) {
            u_char *v  = p + klen;
            u_char *ve = v;
            while (ve < end && *ve != '&') { ve++; }
            /* overwrite value with "REDACTED", shift tail left if shorter */
            static const char R[] = "REDACTED";
            size_t  vlen = (size_t) (ve - v), rlen = sizeof(R) - 1;
            if (vlen >= rlen) {
                ngx_memcpy(v, R, rlen);
                if (vlen > rlen) {
                    ngx_memmove(v + rlen, ve, (size_t) (end - ve));
                    q->len -= (vlen - rlen);
                    end    -= (vlen - rlen);
                }
            }
            p = v;   /* continue scan after the redaction */
        }
    }
}
```

### S.4 `webdav/macaroon_endpoint.c` — macaroon-request handler (§2)
```c
/* LOOP-ONLY. Content-Type: application/macaroon-request issuance (dCache shape).
 * Reuses send_json()/xrootd_macaroon_issue(); body already read by dispatch. */
ngx_int_t
webdav_handle_macaroon_request(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_http_xrootd_webdav_req_ctx_t  *ctx;
    u_char        secret[64];
    ssize_t       slen;
    ngx_str_t     body;
    xrootd_macaroon_req_t req;            /* activities[], path[], ip[] */
    time_t        validity = 0, exp;
    char          mac[XROOTD_MACAROON_ISSUE_OUT_MAX];
    char          json[XROOTD_MACAROON_ISSUE_OUT_MAX + 512];
    int           jlen;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    ctx  = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);

    if (conf->token_macaroon_secret.len == 0) {
        return send_json(r, NGX_HTTP_NOT_FOUND, "{\"error\":\"macaroons disabled\"}", 0);
    }
    if (ctx == NULL || !(ctx->token_auth || xrootd_identity_is_authed(ctx->identity))) {
        return send_json(r, NGX_HTTP_UNAUTHORIZED, "{\"error\":\"auth required\"}", 0);
    }
    if (xrootd_http_collect_body(r, &body) != NGX_OK) {     /* buffered by dispatch */
        return send_json(r, NGX_HTTP_BAD_REQUEST, "{\"error\":\"no body\"}", 0);
    }

    ngx_memzero(&req, sizeof(req));
    if (macaroon_request_parse(&body, r, &req, &validity) != NGX_OK) {  /* json_min */
        return send_json(r, NGX_HTTP_BAD_REQUEST, "{\"error\":\"bad request\"}", 0);
    }
    if (validity <= 0 || validity > conf->macaroon_max_validity) {
        validity = conf->macaroon_max_validity;
    }
    exp  = ngx_time() + validity;
    slen = xrootd_macaroon_secret_parse((const char *) conf->token_macaroon_secret.data,
                                        conf->token_macaroon_secret.len,
                                        secret, sizeof(secret));
    if (slen <= 0
        || xrootd_macaroon_issue(r->connection->log, secret, (size_t) slen,
                                 (const char *) conf->macaroon_location.data,
                                 req.activities[0] ? req.activities : NULL,
                                 req.path[0] ? req.path : (char *) r->uri.data,
                                 exp, mac, sizeof(mac)) != NGX_OK) {
        return send_json(r, NGX_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"issue\"}", 0);
    }

    /* dCache response: macaroon + uri{} (pairs with §1 ?authz=). */
    jlen = ngx_snprintf((u_char *) json, sizeof(json),
        "{\"macaroon\":\"%s\","
         "\"uri\":{\"target\":\"%V://%V%V\","
                  "\"targetWithMacaroon\":\"%V://%V%V?authz=%s\","
                  "\"base\":\"%V://%V/\","
                  "\"baseWithMacaroon\":\"%V://%V/?authz=%s\"}}",
        mac,
        &scheme, &host, &r->uri,
        &scheme, &host, &r->uri, mac,
        &scheme, &host,
        &scheme, &host, mac) - (u_char *) json;
    return send_json(r, NGX_HTTP_OK, json, (size_t) jlen);
}
```

### S.5 `compat/integrity_info.c` — `XrdCksData` host-order codec (§8.1)
```c
/* The official record (XrdCks/XrdCksData.hh), host-order per ADR-4. */
struct xrd_cks_data { char Name[16]; long long fmTime; int csTime;
                      short Rsvd1; char Rsvd2; char Length; char Value[64]; };

/* EITHER. Encode `in` into a fixed XrdCksData image. Returns the record size. */
size_t
xrootd_cksdata_encode(const xrootd_integrity_info_t *in, time_t fmtime,
                      uint8_t out[sizeof(struct xrd_cks_data)])
{
    struct xrd_cks_data d;
    ngx_memzero(&d, sizeof(d));
    ngx_cpystrn((u_char *) d.Name, (u_char *) in->alg_name, sizeof(d.Name));
    d.fmTime = (long long) fmtime;
    d.csTime = 0;
    d.Length = (char) (ngx_strlen(in->hex) / 2);
    /* hex → binary into Value */
    for (int i = 0; i < d.Length && i < (int) sizeof(d.Value); i++) {
        d.Value[i] = (char) ((hex_nibble(in->hex[2*i]) << 4) | hex_nibble(in->hex[2*i+1]));
    }
    ngx_memcpy(out, &d, sizeof(d));
    return sizeof(d);
}

/* EITHER. Parse a record; NGX_DECLINED if stale (fmTime != cur_mtime) or malformed. */
ngx_int_t
xrootd_cksdata_decode(const uint8_t *buf, size_t len, time_t cur_mtime,
                      xrootd_integrity_info_t *out)
{
    const struct xrd_cks_data *d = (const void *) buf;
    if (len < sizeof(*d) || d->Length <= 0 || d->Length > (char) sizeof(d->Value)) {
        return NGX_DECLINED;
    }
    if ((time_t) d->fmTime != cur_mtime) {
        return NGX_DECLINED;                          /* stale → recompute */
    }
    ngx_cpystrn((u_char *) out->alg_name, (u_char *) d->Name, sizeof(out->alg_name));
    for (int i = 0; i < d->Length; i++) {
        static const char hx[] = "0123456789abcdef";
        out->hex[2*i]   = hx[(d->Value[i] >> 4) & 0xf];
        out->hex[2*i+1] = hx[d->Value[i] & 0xf];
    }
    out->hex[2 * d->Length] = '\0';
    out->from_cache = 1;
    return NGX_OK;
}
```

### S.6 `cache/cinfo.c` — load/store + bitmap (§9)
```c
#define XROOTD_CINFO_MAGIC 0x58434931u   /* 'XCI1' */

/* LOOP-ONLY. Atomic store: tmp + fdatasync + rename (crash-safe, §9.5). */
ngx_int_t
xrootd_cache_cinfo_store(const char *cachefile, const xrootd_cache_cinfo_t *hdr,
                         const uint8_t *bitmap, size_t bitmap_len)
{
    char  tmp[PATH_MAX], final[PATH_MAX];
    int   fd;
    if (xrootd_cache_cinfo_path(cachefile, final, sizeof(final)) != NGX_OK) {
        return NGX_ERROR;
    }
    (void) ngx_snprintf((u_char *) tmp, sizeof(tmp), "%s.tmp%Z", final);
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) {
        return (errno == EEXIST) ? NGX_AGAIN : NGX_ERROR;
    }
    if (xrootd_cache_meta_rw_all(fd, (void *) hdr, sizeof(*hdr), 1) != NGX_OK
        || (bitmap_len
            && xrootd_cache_meta_rw_all(fd, (void *) bitmap, bitmap_len, 1) != NGX_OK)) {
        close(fd); unlink(tmp); return NGX_ERROR;
    }
    if (fdatasync(fd) != 0) { close(fd); unlink(tmp); return NGX_ERROR; }
    close(fd);
    if (rename(tmp, final) != 0) { unlink(tmp); return NGX_ERROR; }
    return NGX_OK;
}

/* EITHER. ceil(size/block_size) bits → bytes. */
static size_t cinfo_bitmap_len(uint64_t size, uint32_t bs)
{ uint64_t blocks = bs ? (size + bs - 1) / bs : 0; return (size_t) ((blocks + 7) / 8); }

void xrootd_cache_cinfo_mark_block(uint8_t *bm, uint64_t b)
{ bm[b >> 3] |= (uint8_t) (1u << (b & 7)); }
int  xrootd_cache_cinfo_block_present(const uint8_t *bm, uint64_t b)
{ return (bm[b >> 3] >> (b & 7)) & 1; }
```

### S.7 `gsi/delegation.c` — send pxyreq core (§5)
```c
/* LOOP-ONLY. Build kXGS_pxyreq: ephemeral key + CSR(proxyCertInfo) → AES-enc into
 * kXRS_main → send. ctx keeps the private key for the returned proxy. */
ngx_int_t
xrootd_gsi_send_pxyreq(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    EVP_PKEY *kp   = NULL;
    uint8_t  *csr  = NULL; size_t csr_len = 0;
    uint8_t  *enc  = NULL; size_t enc_len = 0;
    xrootd_gbuf g;

    if (xrootd_gsi_make_proxy_csr(&kp, &csr, &csr_len) != NGX_OK) {
        return xrootd_send_error(ctx, c, kXR_ServerError, "delegation CSR");
    }
    /* inner buffer: one kXRS_x509_req bucket */
    {
        xrootd_gbuf inner; xrootd_gbuf_init(&inner);
        xrootd_gbuf_bucket(&inner, kXRS_x509_req, csr, csr_len);
        xrootd_gbuf_end(&inner);
        if (inner.err
            || xrootd_gsi_aes_encrypt(ctx->signing_key, inner.p, inner.len,
                                      &enc, &enc_len) != NGX_OK) {
            xrootd_gbuf_free(&inner); EVP_PKEY_free(kp); free(csr);
            return xrootd_send_error(ctx, c, kXR_ServerError, "delegation enc");
        }
        xrootd_gbuf_free(&inner);
    }
    xrootd_gbuf_init(&g);
    xrootd_gbuf_start(&g, kXGS_pxyreq);
    xrootd_gbuf_bucket(&g, kXRS_main, enc, enc_len);
    xrootd_gbuf_end(&g);
    free(csr); free(enc);
    if (g.err) { xrootd_gbuf_free(&g); EVP_PKEY_free(kp);
                 return xrootd_send_error(ctx, c, kXR_NoMemory, "delegation buf"); }
    ctx->deleg_key = kp;                       /* paired with the returned proxy */
    {
        ngx_int_t rc = xrootd_send_authmore(ctx, c, g.p, g.len);  /* kXR_authmore */
        xrootd_gbuf_free(&g);
        return rc;
    }
}
```

### S.8 `cms/cns_emit.c` + `manager/cns_store.c` cores (§6)
```c
/* LOOP-ONLY (data server). Coalesce one namespace event; flush on CMS heartbeat. */
void
xrootd_cns_emit(xrootd_ctx_t *ctx, uint8_t op, const char *path,
                const char *path2, uint64_t size, uint64_t mtime)
{
    struct xrootd_cns_event ev;
    if (ctx->srv_conf->cns_mode != XROOTD_CNS_EMIT) { return; }
    ngx_memzero(&ev, sizeof(ev));
    ev.op = op; ev.size = size; ev.mtime = mtime;
    ev.name_len  = (uint16_t) ngx_strlen(path);
    ev.name2_len = path2 ? (uint16_t) ngx_strlen(path2) : 0;
    xrootd_cns_queue_push(&ev, path, path2);    /* bounded ring; dropped→metric */
}

/* LOOP-ONLY (manager). Apply to SHM rbtree + append to durable file. */
ngx_int_t
xrootd_cns_apply(const struct xrootd_cns_event *ev, size_t total_len)
{
    if (xrootd_cns_file_append(ev, total_len) != NGX_OK) { return NGX_ERROR; }  /* truth */
    xrootd_shm_table_lock(&g_cns_tbl);          /* spin+yield, never POSIX-sem */
    switch (ev->op) {
    case XROOTD_CNS_ADD: case XROOTD_CNS_CLOSEW: cns_upsert(ev); break;
    case XROOTD_CNS_DEL: case XROOTD_CNS_RMDIR:  cns_remove(ev); break;
    case XROOTD_CNS_MKDIR:                       cns_mkdir(ev);  break;
    case XROOTD_CNS_MV:                          cns_rename(ev); break;
    case XROOTD_CNS_TRUNC:                       cns_resize(ev); break;
    }
    xrootd_shm_table_unlock(&g_cns_tbl);
    return NGX_OK;
}
```

### S.9 `ssi/ssi.c` — unary request/response core (§7)
```c
/* LOOP-ONLY. First read after the request is written triggers dispatch on the AIO
 * pool; subsequent reads stream the buffered response. */
ngx_int_t
xrootd_ssi_read(xrootd_ssi_req_t *rq, off_t off, uint8_t *buf, size_t n, ssize_t *got)
{
    if (rq->state == SSI_REQ_ACCUMULATING) {
        rq->state = SSI_REQ_DISPATCHING;
        return xrootd_aio_post_task(rq->ctx, ssi_dispatch_task, rq);   /* → NGX_AGAIN */
    }
    if (rq->state != SSI_REQ_READY) {
        *got = -1; return NGX_ERROR;
    }
    if ((uint64_t) off >= rq->resp_len) { *got = 0; return NGX_OK; }   /* EOF */
    *got = (ssize_t) ngx_min(n, rq->resp_len - (uint64_t) off);
    ngx_memcpy(buf, rq->resp + off, (size_t) *got);
    return NGX_OK;
}
```

---

## §T. Consolidated edit-hunk set (every touched file)

| Feature | File | Change | New/Edit |
|---|---|---|---|
| §1 | `compat/http_headers.{c,h}` | `xrootd_http_arg`; host `urlencode_decode_inplace` | edit |
| §1 | `webdav/auth_token.c` | header→query fallback (hunk §1.5) | edit |
| §1 | `webdav/log.c` | `xrootd_http_redact_query_token` at log build | edit |
| §1 | `webdav/{config,directives}.c`, `types/config.h` | `http_query_token` | edit |
| §2 | `webdav/dispatch.c` | content-type route (hunk §2.4) | edit |
| §2 | `webdav/macaroon_endpoint.c` | `webdav_handle_macaroon_request` + parser | edit |
| §2 | `compat/iso8601.{c,h}` | duration parser | **new** |
| §3 | `dig/{dig,dig_auth,directives}.c`, `dig/dig.h`, `README.md` | new subsystem | **new** |
| §3 | `read/open_resolved_file.c`, `read/stat.c`, `dirlist/handler.c` | dig hook | edit |
| §4A | `zip/zip_member.{c,h}` | wire wrapper + ranged inflate | **new** |
| §4A | `read/open_request.c`, `open_resolved_file.c`, `read/read.c`, `webdav/get.c` | member route | edit |
| §4B | `frm/archive.{c,h}`, `frm/reqfile.c` | compose/stage job | new/edit |
| §5 | `protocol/gsi.h` | `kXRS_x509 3022`, `kXRS_x509_req 3024` | edit |
| §5 | `gsi/delegation.{c,h}` | pxyreq/sigpxy/store | **new** |
| §5 | `gsi/auth.c` | delegation branch + sigpxy arm (hunk §5.5) | edit |
| §5 | `session/login.c`, `gsi/cert_response.c` | advertise opt bit | edit |
| §5 | `tpc/source.c`, `bootstrap.c` (Phase 2) | consume proxy | edit |
| §6 | `cms/cns_emit.{c,h}`, `manager/cns_store.{c,h}` | feed + inventory | **new** |
| §6 | `cms/server_recv.c`, `manager/registry.c`, `srr/*.c` | decode + answer | edit |
| §7 | `ssi/{ssi,ssi_registry}.{c,h}`, `README.md` | new subsystem | **new** |
| §7 | `read/open_request.c`, `write/write.c`, `read/read.c` | SSI handle route | edit |
| §8 | `compat/integrity_info.c` | cksdata codec, sidecar, on-ingest | edit |
| §8 | `read/close.c`, `webdav/put.c`, `s3/object.c`, `tpc/done.c` | on-ingest persist | edit |
| §8.4 | `compat/csi.{c,h}` (backlog) | page CRC + scrub | new |
| §9 | `cache/cinfo.{c,h}` | format + bitmap | **new** |
| §9 | `cache/{slice_fill,open,open_or_fill,evict_policy,fetch}.c` | bitmap/stats/verify | edit |

New files needing `./configure`: §2 iso8601, §3 dig/*, §4A zip_member, §5 delegation,
§6 cns_*, §7 ssi/*, §9 cinfo (+ §8.4 csi backlog).

---

## §U. Byte-level sequence & state diagrams

### U.1 §1 access + log timeline
```
t0 access-phase  webdav_verify_bearer_token
   ├─ headers_in.authorization?  ── yes → extract_bearer ─┐
   │                              no  → bearer_from_query ─┤→ bearer
   ├─ L1 lookup(token)  hit → claims                       │
   ├─ L2 lookup         hit → claims (+promote L1)         │
   └─ validate(JWKS/macaroon) → claims                     │
t1 content handler (GET/PUT) uses ctx->token_scopes
t2 log-phase  build line → xrootd_http_redact_query_token  → write access log
```

### U.2 §5 GSI delegation full message ladder
```
C: kXR_auth gsi step=kXGC_certreq                → S: kXGS_cert  (DH pub, opts|=DlgPxy)
C: kXR_auth gsi step=kXGC_cert  (enc proxy chain)→ S: verify EEC chain; DN extracted
                                                    if deleg!=off → kXGS_pxyreq (CSR)
C: kXR_auth gsi step=kXGC_sigpxy (enc signed pxy)→ S: recv_sigpxy → verify+store
                                                    → kXR_ok (auth_done=1)
```
States: START → CERTREQ'd → CERT_OK → (DELEGATING) → DELEGATED/AUTHED. Failure at any
verify → kXR_NotAuthorized, connection auth aborts (auth_fail_count++).

### U.3 §9 slice-cache restart recovery
```
fill(window A,B) → mark bits → store .cinfo (atomic)   ── crash / restart ──
open(file) → load .cinfo (DECLINED? → empty) → bitmap{A,B set}
  read range in A → present → serve from disk
  read range in C → absent  → fetch C → verify vs cks → mark C → store
```

---

## §V. Concurrency, memory-ordering & reentrancy proofs

- **§1 token caches.** `bearer_from_query` only allocates from `r->pool` (per-request,
  single-threaded on the event thread) → no cross-thread sharing. L1 is per-worker
  (no lock); L2 SHM uses the existing spinlock; the source (header vs query) does not
  change the key, so no new race. *Invariant:* validation runs only on the event
  thread; the AIO pool is never touched here.
- **§5 delegation session state.** `ctx->deleg_key`/`deleg_done` live on the
  per-connection `xrootd_ctx_t`, mutated only on the event thread between discrete
  `kXR_auth` rounds (request/response serialized by the protocol). No reentrancy: a
  second in-flight auth round is impossible (the client waits for `kXR_authmore`).
  *UAF guard:* `deleg_key` is freed in `on_disconnect` and after store; `destroyed=1`
  guards stale callbacks (existing pattern).
- **§6 CNS SHM.** All mutations go through `xrootd_shm_table_lock` (spin+yield,
  **never** POSIX-sem — INVARIANT #10 / `shmtx_semaphore_lostwakeup`). Durable file is
  appended **before** SHM is updated, so a crash after file-append/before-SHM is healed
  by replay on restart (file is truth). Readers (stat/dirlist) take the same lock for a
  consistent snapshot; held for µs (fixed-slot scan). *Ordering:* file fsync on the
  flush boundary, not per event (batched).
- **§9 cinfo bitmap.** In-memory bitmap is per-cache-file, mutated on the event thread
  during fills. Persistence is atomic (tmp+fdatasync+rename), so a torn write is
  impossible; a stale-but-valid `.cinfo` only ever *under*-claims presence (safe:
  causes a refetch, never a mis-serve). *Verify-on-fill* (cks) runs on the fill worker
  (THREAD-SAFE: pure compare on filled bytes) before the LOOP-ONLY mark+store.
- **§7 SSI.** `ssi_dispatch_task` runs on the AIO pool (THREAD-SAFE: pure compute on
  the accumulated request buffer); completion posts back to the event thread which
  flips `state=READY` and serves reads. No shared mutable state crosses the boundary
  except the request/response buffers handed off by ownership.

---

## §W. Capacity & performance model

### W.1 Checksum storage overhead (§8)
- xattr `XrdCksData` record = **88 B/algorithm** (host-order). Text record ≤160 B.
  `both` ≈ 88+~80 = ~170 B per algo. Typical: 1–2 algos → <400 B/file xattr.
- sidecar `.cks` = `n_algos × 88 B` + negligible; one extra inode/file.
- on-ingest cost = one full-file read at close (offloaded to AIO pool); amortized by
  the existing xattr cache for subsequent queries.

### W.2 cinfo bitmap size (§9)
| file size | block 128 KiB | bitmap |
|---|---|---|
| 1 GiB | 8192 blocks | 1 KiB |
| 100 GiB | 819 200 | 100 KiB |
| 1 TiB | 8.4 M | ~1 MiB |
Header is fixed (~160 B). Bitmap dominates only for very large files; tune
`block_size` up (e.g. 1 MiB) for archival caches to shrink it 8×.

### W.3 CNS inventory sizing (§6)
Per-entry SHM ≈ path(≤256) + {server_id 4, size 8, mtime 8, flags} ≈ ~300 B. 10 M
files → ~3 GB SHM. *Guidance:* CNS is for moderate-cardinality redirectors; document a
configurable cap + LRU and recommend SRR-only (space, no per-file) above ~10 M files.

### W.4 Latency budgets
- §1 query parse + decode: O(args length), <1 µs; no crypto on the cap-reject path.
- §2 issue: one HMAC over a few hundred bytes, <50 µs.
- §4A stored-member read: identical to a normal ranged read (one pread; sendfile-able).
  deflate member: inflate throughput-bound, streamed (no whole-file buffer).
- §5 delegation: one RSA keygen+sign+verify per delegating login (~a few ms), only on
  GSI logins with delegation enabled.

---

## §X. Failure-injection matrix

| id | feature | injected fault | expected behavior |
|---|---|---|---|
| X-01 | §1 | `authz=` with embedded `&`/`%00` | decoded safely; value bounded; no split-auth |
| X-02 | §1 | log line build OOM | drop redaction-safe (never log raw token) |
| X-03 | §2 | body > 16 KiB | 400 before parse |
| X-04 | §2 | `validity` = "PT0S"/negative | clamp to min/ max; never 0-life token |
| X-05 | §2 | caveats widen caller rights | issue narrowed; widened op later → 403 |
| X-06 | §3 | export dir is a symlink to `/` | RESOLVE_BENEATH refuses; 403 |
| X-07 | §3 | allow-file missing | default-deny (feature still gated off→404) |
| X-08 | §4A | zip with 4 GiB declared member, 1 KiB file | reader bounds-check → ECORRUPT |
| X-09 | §4A | deflate bomb (1 KiB→4 GiB) | ranged inflate; bounded by declared size; no OOM |
| X-10 | §4A | member name `../../etc/passwd` | rejected (name is archive-internal, no fs map) |
| X-11 | §5 | client sends sigpxy with self-signed proxy | chain verify fails → 403 |
| X-12 | §5 | proxy certifies a different pubkey than CSR | mismatch → 403 |
| X-13 | §5 | client never sends sigpxy (require) | auth fails after timeout |
| X-14 | §5 | store=file, dir 0777 | refuse / fix to 0700; file 0600 |
| X-15 | §6 | event from non-cluster IP | dropped (CMS allowlist), metric++ |
| X-16 | §6 | manager crash mid-apply | file replay heals; SHM rebuilt |
| X-17 | §6 | event queue overflow (DS) | oldest dropped + metric; reconcile heals |
| X-18 | §7 | request larger than cap | bounded reject (kXR error) |
| X-19 | §7 | client cancels (RRInfo Can) | task result discarded; handle freed |
| X-20 | §8 | xattr setxattr ENOTSUP | `auto` → sidecar; `xattr` → skip (advisory) |
| X-21 | §8 | corrupt 12-byte xattr | decode DECLINED → recompute |
| X-22 | §8 | file changed between compute and store | mtime guard → next read recomputes |
| X-23 | §9 | `.cinfo` truncated to 10 B | load DECLINED → full refetch |
| X-24 | §9 | bitmap claims block present but data zeroed | verify-on-read (if VERIFIED) catches; else origin mtime guard |
| X-25 | §9 | crash during atomic store | `.tmp` orphan ignored; old `.cinfo` intact |
| X-26 | §1 | header present but not Bearer + query token | query fallback used |
| X-27 | §2 | secret rotation mid-issue | uses current secret; old-secret only for validate |
| X-28 | §5 | delegated proxy expires during session | refuse use at TPC launch |
| X-29 | §4B | archiver program exits non-zero | job marked failed; queue retains; alert |
| X-30 | §3 | concurrent reads of same dig file | independent confined fds; no shared state |

---

## §Y. CI/CD + PR-by-PR rollout with review checklists

### Y.1 PR sequence (≈ matches §0 sprints)
```
PR-1.1 http_arg + shared urldecode (+unit)         PR-2.1 iso8601 (+unit)
PR-1.2 query fallback + directive (+1a–1g)         PR-2.2 macaroon-request route+handler (+2a–2g)
PR-1.3 log redaction (+1h) + docs                  PR-3.1 dig core+auth+confined open
PR-3.2 dig root:// hooks + HTTP alias (+3a–3h)     PR-4A.1 zip_member wrapper+ranged (+4a–4e,4h)
PR-4B.1 frm archive compose/stage (+4f,4g)         PR-8.1 cksdata codec + read-prefer (+8b,8h)
PR-8.2 sidecar backend + auto-fallback (+8d–8f)    PR-8.3 on-ingest persist (+8a,8c,8g)
PR-9.1 cinfo format + load/store (+9c,9e)          PR-9.2 slice bitmap + verify (+9a,9b,9d,9f)
PR-5.1 gsi.h buckets + delegation.c send/recv/store PR-5.2 auth.c branch + advertise (+5a–5f)
   ── outbound-GSI fix (separate epic) ──          PR-5.3 tpc consume (+5g)
PR-6.1 cns event + emit                            PR-6.2 manager store + answers (+6a–6f)
PR-7.1 ssi core + registry + hooks                 PR-7.2 official-interop harness (+7e)
backlog: PR-8.4 csi page-crc + scrub
```

### Y.2 Per-PR review checklist (gate to merge)
- [ ] new `.c` registered in `./config`; `./configure` run if new file/block
- [ ] directive: field UNSET in `config.h`, command row, merge default
- [ ] feature flag added + surfaced in `/healthz` + `qconfig`
- [ ] no `goto`; functions single-purpose; `ctx` passed (no globals)
- [ ] thread-context tag on every new function; CI seam grep passes
- [ ] HELPERS reused (resolve_path/open_beneath/auth_gate/metrics)
- [ ] ≥3 tests (success/error/security-neg) + interop where applicable
- [ ] subsystem README + docs/ page + gaps-doc row updated
- [ ] metrics + log lines added (see §AA); low-cardinality labels only
- [ ] security-neg test demonstrably fails without the fix

### Y.3 CI jobs (added)
- `build-matrix`: default; `-DXROOTD_WITH_*=0` per new flag; dynamic-module dlopen.
- `pytest-58`: `tests/test_{query_token,macaroon_request,dig,zip_member,checksum_at_rest,cache_cinfo,gsi_delegation,cns,ssi}.py`.
- `interop-58`: stands up `/tmp/xrootd-src` peers (xrdfs/xrdcp, real XrdSecgsi, an SSI
  cluster, gfal2/davix) — see §DD.
- `asan-58`: ASAN build runs the §X failure-injection subset.
- `seam-guard`: `tools/ci/check_vfs_seam.sh` + the thread-context grep.

---

## §AA. Observability (metrics, logs, /healthz, qconfig)

Metrics use the existing `xrootd_metric_op_done` / unified label vocabulary
(`src/metrics/unified.h`); **labels stay low-cardinality** (no paths/DNs/tokens —
INVARIANT #8).

| Feature | Metric (counter/gauge) | Labels | Log line (cause/fix) |
|---|---|---|---|
| §1 | `xrootd_http_query_token_total` | result(ok/denied) | — (token never logged) |
| §2 | `xrootd_macaroon_issued_total` | mode(oauth2/request) | issue failures w/ reason |
| §3 | `xrootd_dig_access_total` | result(ok/denied/miss) | denied principal+export (no file bytes) |
| §4A | `xrootd_zip_member_read_total` | result | corrupt/unsupported member reason |
| §4B | `xrootd_archive_jobs` (gauge) | state(queued/running/failed) | archiver exit code |
| §5 | `xrootd_gsi_delegation_total` | result(stored/refused/forged) | verify failure cause |
| §6 | `xrootd_cns_events_total`, `xrootd_cns_entries` (gauge), `xrootd_cns_dropped_total` | op | dropped(queue full), non-cluster src |
| §7 | `xrootd_ssi_requests_total` | resource,result | unknown resource |
| §8 | `xrootd_checksum_persist_total` | trigger(close/put/tpc),result | persist failure (advisory) |
| §9 | `xrootd_cache_cinfo_total` | event(hit/partial/miss/verify_fail) | verify mismatch → refetch |

`/healthz` JSON gains booleans: `query_token`, `macaroon_request`, `dig`,
`archive_member`, `gsi_delegation`, `cns`(emit/collect/off), `ssi`,
`checksum_on_write`, `cache_cinfo`. `kXR_Qconfig` echoes the same as `key=value`.

---

## §BB. Complete config-directive reference

| Directive | Context | Type | Default | Feature |
|---|---|---|---|---|
| `xrootd_http_query_token` | http loc | flag | on | §1 |
| `xrootd_macaroon_max_validity` | http loc | duration | PT24H | §2 |
| `xrootd_dig` | stream/http srv | flag | off | §3 |
| `xrootd_dig_export <name> <dir>` | srv | str×2 (repeat) | — | §3 |
| `xrootd_dig_auth <file>` | srv | path | — | §3 |
| `xrootd_archive_member_access` | srv/loc | flag | off | §4A |
| `xrootd_archive_prefix <path>` | srv | path | — | §4B |
| `xrootd_archive_cmd <prog…>` | srv | argv | — | §4B |
| `xrootd_gsi_delegation` | stream srv | enum off/request/require | off | §5 |
| `xrootd_gsi_delegation_store` | srv | enum memory/file | memory | §5 |
| `xrootd_gsi_delegation_dir <dir>` | srv | path | — | §5 |
| `xrootd_cns` | srv | enum off/emit/collect | off | §6 |
| `xrootd_cns_store <file>` | srv | path | — | §6 |
| `xrootd_cns_flush_interval <t>` | srv | time | 10s | §6 |
| `xrootd_ssi` | srv | flag | off | §7 |
| `xrootd_ssi_resource <name> <handler>` | srv | str×2 (repeat) | — | §7 |
| `xrootd_checksum_xattr_format` | srv | enum text/xrdcks/both | both | §8.1 |
| `xrootd_checksum_store` | srv | enum xattr/sidecar/auto | xattr | §8.2 |
| `xrootd_checksum_on_write <algs>` | srv | csv | off | §8.3 |
| `xrootd_cache_cinfo` | srv | flag | on | §9 |

All new fields: `NGX_CONF_UNSET*` in `src/core/types/config.h`; merged in the owning
`merge_*_conf()`; only `xrootd_dig`/`xrootd_cns`/`xrootd_ssi` (if they introduce a new
top-level block) trigger a `./configure` — directives within existing blocks do not.

---

## §CC. Kernel / dependency / compatibility matrix

| Need | Where | Min | Fallback |
|---|---|---|---|
| `openat2(RESOLVE_BENEATH)` | §3 dig, existing confinement | Linux 5.6 | existing `xrootd_open_beneath` path (already supports older via realpath-confined) |
| `user.*` xattr | §8.1 | ext4/xfs/btrfs default | §8.2 sidecar (`auto`) on ENOTSUP |
| `fdatasync`/atomic rename | §9, §8.2, §6 | POSIX | — (required) |
| OpenSSL X509_REQ + proxyCertInfo | §5 | OpenSSL 1.1.1+ | client patterns in `client/lib/proxy.c` mirror it |
| zlib raw inflate | §4A | zlib (already linked) | stored members need no codec |
| real `XrdSecgsi` | §5 interop test | `/tmp/xrootd-src` | unit tests cover non-interop paths |
| official SSI peer | §7 interop test | `/tmp/xrootd-src` cluster | raw-wire tests cover framing |

Host-order `XrdCksData` (ADR-4) is bit-for-bit stock-compatible on the **same**
architecture; mixed-arch xattr sharing is a documented divergence (decode is
order-tolerant → treats foreign as a miss → recompute, never mis-serve).

---

## §DD. Interop harness (official XRootD cluster for SSI / CNS / GSI)

Per ADR-2 (SSI) and to validate §5/§6 against real components, `interop-58` provisions
from `/tmp/xrootd-src`:

1. **GSI (§5):** a real client with `X509_USER_PROXY` and `xrdcp --delegate`-style
   delegation against the nginx server (`xrootd_gsi_delegation require`); assert the
   server stores and (Phase 2) reuses the proxy.
2. **SSI (§7):** a stock `xrootd` + an `XrdSsi` example service as the **client/peer**
   driving the nginx SSI resource; assert echo round-trips byte-for-byte. (Acceptance
   gate for §7.)
3. **CNS (§6):** an official `cmsd`/`xrootd` data server peered with the nginx manager
   (or two nginx data servers + nginx manager) to validate event feed + inventory +
   space totals; cross-check `xrdfs <mgr> stat/ls` against the inventory.
4. **macaroon/`?authz=` (§1/§2):** `gfal2`/`davix` clients exercise issuance + query
   token end-to-end.

Harness reuses the dedicated-instance pattern (`resilience_dedicated_instances`,
`pyxrootd_isolation_worker` for any official bindings) on high ports (13900+), absolute
paths, and the xdist port-band convention.

---

## §EE. Compile-ready complete source (authoritative; corrects §S)

> **Correction notice.** §S.4 used a non-existent `xrootd_macaroon_req_t` and
> `xrootd_http_collect_body`, and assumed `json_min` could read arrays. The real
> APIs are: `xrootd_macaroon_issue(log, key, key_len, location, identifier,
> activities, path, expiry, out, outsz)` (param-based), `xrootd_json_get_str(json,
> len, key, out, outsz)` (scalar/string only — **no array support**), and body must
> be collected from `r->request_body->bufs`. The sources below are authoritative.

### EE.1 `src/core/compat/iso8601.c` (new) — duration parser (§2)
```c
#include <ngx_config.h>
#include <ngx_core.h>
#include "iso8601.h"

/*
 * xrootd_iso8601_duration_secs — parse a restricted ISO-8601 duration to seconds.
 * EITHER (no shared state). Grammar subset: ['P'] ['T'] ( <uint><unit> )+ where unit
 * ∈ {D,H,M,S} (W/Y/Mo not supported — WLCG macaroons use H/M/S/D). Clamps to [1,max].
 * Pre: s/out non-NULL. Post NGX_OK: *out ∈ [1,max]. NGX_ERROR on malformed/empty/overflow.
 */
ngx_int_t
xrootd_iso8601_duration_secs(const char *s, size_t len, time_t max, time_t *out)
{
    size_t   i = 0;
    uint64_t total = 0;
    int      saw_unit = 0;

    if (s == NULL || out == NULL || len == 0) {
        return NGX_ERROR;
    }
    if (s[i] == 'P') { i++; }                 /* optional leading 'P' */
    if (i < len && s[i] == 'T') { i++; }      /* optional 'T' (time part) */

    while (i < len) {
        uint64_t n = 0;
        size_t   digits = 0;
        while (i < len && s[i] >= '0' && s[i] <= '9') {
            if (n > (UINT64_MAX - 9) / 10) { return NGX_ERROR; }   /* overflow */
            n = n * 10 + (uint64_t) (s[i] - '0');
            i++; digits++;
        }
        if (digits == 0 || i >= len) { return NGX_ERROR; }
        switch (s[i]) {
        case 'D': total += n * 86400; break;
        case 'H': total += n * 3600;  break;
        case 'M': total += n * 60;    break;
        case 'S': total += n;         break;
        default:  return NGX_ERROR;
        }
        if (total > (uint64_t) INT64_MAX) { return NGX_ERROR; }
        i++; saw_unit = 1;
    }
    if (!saw_unit) { return NGX_ERROR; }
    if (total == 0) { total = 1; }
    if ((time_t) total > max) { total = (uint64_t) max; }
    *out = (time_t) total;
    return NGX_OK;
}
```

### EE.2 `src/webdav/macaroon_endpoint.c` — request body + caveats walker + handler (§2)
```c
/* EITHER. Collect r->request_body->bufs into one pool buffer (≤cap). NGX_OK/-. */
static ngx_int_t
webdav_body_to_buf(ngx_http_request_t *r, size_t cap, ngx_str_t *out)
{
    ngx_chain_t *cl;
    u_char      *p;
    size_t       total = 0;

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return NGX_DECLINED;
    }
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        total += (size_t) (cl->buf->last - cl->buf->pos);   /* in-memory bufs only */
        if (total > cap) { return NGX_ERROR; }              /* X-03: oversize */
    }
    p = ngx_pnalloc(r->pool, total + 1);
    if (p == NULL) { return NGX_ERROR; }
    out->data = p; out->len = total;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        size_t n = (size_t) (cl->buf->last - cl->buf->pos);
        ngx_memcpy(p, cl->buf->pos, n); p += n;
    }
    *p = '\0';
    return NGX_OK;
}

/* EITHER. Minimal "caveats":["..","..",..] array-of-strings scan (json_min has no
 * array support). For each element, recognize "activity:<csv>" and "path:<abs>".
 * Accumulates activities into act[actsz] (comma-joined) and the last path into
 * path[pathsz]. Tolerant of whitespace; ignores unknown caveat kinds. */
static void
macaroon_caveats_scan(const char *body, size_t len,
                      char *act, size_t actsz, char *path, size_t pathsz)
{
    const char *p = body, *end = body + len, *arr;
    act[0] = '\0'; path[0] = '\0';
    arr = ngx_strlcasestrn((u_char *) p, (u_char *) end, (u_char *) "\"caveats\"", 8);
    if (arr == NULL) { return; }
    p = ngx_strlchr((u_char *) arr, (u_char *) end, '[');
    if (p == NULL) { return; }
    p++;
    while (p < end && *p != ']') {
        const char *q;
        if (*p != '"') { p++; continue; }
        q = ++p;
        while (q < end && *q != '"') { q++; }          /* element [p,q) */
        if (q >= end) { break; }
        {
            size_t elen = (size_t) (q - p);
            if (elen > 9 && ngx_strncasecmp((u_char *) p, (u_char *) "activity:", 9) == 0) {
                size_t cur = ngx_strlen(act);
                if (cur && cur + 1 < actsz) { act[cur++] = ','; }
                size_t cp = elen - 9, room = (cur < actsz) ? actsz - cur - 1 : 0;
                ngx_memcpy(act + cur, p + 9, ngx_min(cp, room));
                act[cur + ngx_min(cp, room)] = '\0';
            } else if (elen > 5 && ngx_strncasecmp((u_char *) p, (u_char *) "path:", 5) == 0) {
                size_t cp = ngx_min(elen - 5, pathsz - 1);
                ngx_memcpy(path, p + 5, cp); path[cp] = '\0';
            }
        }
        p = q + 1;
    }
}

ngx_int_t
webdav_handle_macaroon_request(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_http_xrootd_webdav_req_ctx_t  *ctx;
    u_char     secret[64];
    ssize_t    slen;
    ngx_str_t  body, scheme, host;
    char       act[256], cav_path[1024], vbuf[32];
    char       mac[XROOTD_MACAROON_ISSUE_OUT_MAX];
    char       json[XROOTD_MACAROON_ISSUE_OUT_MAX + 768];
    time_t     validity = 0, exp;
    int        jlen;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    ctx  = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);

    if (conf->token_macaroon_secret.len == 0) {
        return send_json(r, NGX_HTTP_NOT_FOUND,
                         "{\"error\":\"macaroons disabled\"}",
                         sizeof("{\"error\":\"macaroons disabled\"}") - 1);
    }
    if (ctx == NULL || !ctx->token_auth) {
        return send_json(r, NGX_HTTP_UNAUTHORIZED,
                         "{\"error\":\"authentication required\"}",
                         sizeof("{\"error\":\"authentication required\"}") - 1);
    }
    if (webdav_body_to_buf(r, 16 * 1024, &body) != NGX_OK) {
        return send_json(r, NGX_HTTP_BAD_REQUEST,
                         "{\"error\":\"bad body\"}", sizeof("{\"error\":\"bad body\"}") - 1);
    }

    macaroon_caveats_scan((const char *) body.data, body.len,
                          act, sizeof(act), cav_path, sizeof(cav_path));
    if (cav_path[0] == '\0') {                          /* default base = request path */
        size_t n = ngx_min(r->uri.len, sizeof(cav_path) - 1);
        ngx_memcpy(cav_path, r->uri.data, n); cav_path[n] = '\0';
    }
    if (xrootd_json_get_str((const char *) body.data, body.len, "validity",
                            vbuf, sizeof(vbuf)) > 0) {
        (void) xrootd_iso8601_duration_secs(vbuf, ngx_strlen(vbuf),
                                            conf->macaroon_max_validity, &validity);
    }
    if (validity <= 0) { validity = conf->macaroon_max_validity; }
    exp = ngx_time() + validity;

    slen = xrootd_macaroon_secret_parse((const char *) conf->token_macaroon_secret.data,
                                        conf->token_macaroon_secret.len,
                                        secret, sizeof(secret));
    if (slen <= 0
        || xrootd_macaroon_issue(r->connection->log, secret, (size_t) slen,
                                 (const char *) conf->macaroon_location.data,
                                 NULL /*auto id*/, act[0] ? act : NULL,
                                 cav_path, exp, mac, sizeof(mac)) != NGX_OK) {
        return send_json(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                         "{\"error\":\"issue failed\"}",
                         sizeof("{\"error\":\"issue failed\"}") - 1);
    }

    ngx_str_set(&scheme, "https");
    if (r->headers_in.host) { host = r->headers_in.host->value; }
    else { ngx_str_set(&host, "localhost"); }

    jlen = (int) (ngx_snprintf((u_char *) json, sizeof(json),
        "{\"macaroon\":\"%s\",\"uri\":{"
        "\"target\":\"%V://%V%V\","
        "\"targetWithMacaroon\":\"%V://%V%V?authz=%s\","
        "\"base\":\"%V://%V/\","
        "\"baseWithMacaroon\":\"%V://%V/?authz=%s\"}}",
        mac, &scheme, &host, &r->uri,
        &scheme, &host, &r->uri, mac,
        &scheme, &host, &scheme, &host, mac) - (u_char *) json);
    return send_json(r, NGX_HTTP_OK, json, (size_t) jlen);
}
```

### EE.3 `src/core/compat/integrity_info.c` — sidecar backend (§8.2)
```c
/* LOOP-ONLY. "<file>.cks" — concatenated host-order XrdCksData records. Read/write
 * with O_NOFOLLOW|O_CLOEXEC, short-rw-safe (mirrors cache/meta.c). */
ngx_int_t
xrootd_cks_sidecar_path(const char *file, char *dst, size_t dstsz)
{
    int n = snprintf(dst, dstsz, "%s.cks", file);
    return (n > 0 && (size_t) n < dstsz) ? NGX_OK : NGX_ERROR;
}

ngx_int_t
xrootd_cks_sidecar_get(const char *file, const char *alg, time_t mtime,
                       xrootd_integrity_info_t *out)
{
    char     path[PATH_MAX];
    int      fd, found = NGX_DECLINED;
    uint8_t  rec[sizeof(struct xrd_cks_data)];

    if (xrootd_cks_sidecar_path(file, path, sizeof(path)) != NGX_OK) { return NGX_ERROR; }
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { return NGX_DECLINED; }
    for (;;) {
        ssize_t n = pread(fd, rec, sizeof(rec), 0);   /* advanced below */
        static off_t off; off = 0; (void) n;
        break;                                         /* see loop variant below */
    }
    /* iterate fixed-size records */
    {
        off_t off = 0; ssize_t n;
        while ((n = pread(fd, rec, sizeof(rec), off)) == (ssize_t) sizeof(rec)) {
            xrootd_integrity_info_t tmp;
            if (xrootd_cksdata_decode(rec, sizeof(rec), mtime, &tmp) == NGX_OK
                && ngx_strcmp(tmp.alg_name, alg) == 0) {
                *out = tmp; found = NGX_OK; break;
            }
            off += (off_t) sizeof(rec);
        }
    }
    close(fd);
    return found;
}

ngx_int_t
xrootd_cks_sidecar_put(const char *file, const xrootd_integrity_info_t *in,
                       time_t fmtime)
{
    char     path[PATH_MAX];
    int      fd;
    uint8_t  rec[sizeof(struct xrd_cks_data)];
    /* append-or-replace by algorithm; simplest correct impl = read-modify-rewrite */
    if (xrootd_cks_sidecar_path(file, path, sizeof(path)) != NGX_OK) { return NGX_ERROR; }
    fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) { return NGX_ERROR; }
    /* find existing record for this alg → overwrite; else append */
    {
        off_t off = 0; ssize_t n;
        while ((n = pread(fd, rec, sizeof(rec), off)) == (ssize_t) sizeof(rec)) {
            xrootd_integrity_info_t tmp;
            if (xrootd_cksdata_decode(rec, sizeof(rec), fmtime, &tmp) == NGX_OK
                && ngx_strcmp(tmp.alg_name, in->alg_name) == 0) { break; }   /* off = slot */
            off += (off_t) sizeof(rec);
        }
        xrootd_cksdata_encode(in, fmtime, rec);
        if (pwrite(fd, rec, sizeof(rec), off) != (ssize_t) sizeof(rec)) {
            close(fd); return NGX_ERROR;
        }
    }
    close(fd);
    return NGX_OK;
}
```

### EE.4 `src/cache/cinfo.c` — load (complements §S.6 store) (§9)
```c
/* LOOP-ONLY. Load header + bitmap. NGX_DECLINED on missing/short/garbage (→ refetch).
 * *bitmap is pool-or-malloc owned by the caller; *bitmap_len may be 0. */
ngx_int_t
xrootd_cache_cinfo_load(const char *cachefile, xrootd_cache_cinfo_t *hdr,
                        uint8_t **bitmap, size_t *bitmap_len)
{
    char    path[PATH_MAX];
    int     fd;
    size_t  want;

    *bitmap = NULL; *bitmap_len = 0;
    if (xrootd_cache_cinfo_path(cachefile, path, sizeof(path)) != NGX_OK) { return NGX_ERROR; }
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { return NGX_DECLINED; }
    if (xrootd_cache_meta_rw_all(fd, hdr, sizeof(*hdr), 0) != NGX_OK
        || hdr->magic != XROOTD_CINFO_MAGIC || hdr->version != 2
        || hdr->block_size == 0) {
        close(fd); return NGX_DECLINED;                /* garbage → empty cache */
    }
    want = cinfo_bitmap_len(hdr->size, hdr->block_size);
    if (want) {
        *bitmap = malloc(want);
        if (*bitmap == NULL) { close(fd); return NGX_ERROR; }
        if (xrootd_cache_meta_rw_all(fd, *bitmap, want, 0) != NGX_OK) {
            free(*bitmap); *bitmap = NULL; close(fd); return NGX_DECLINED;
        }
        *bitmap_len = want;
    }
    close(fd);
    return NGX_OK;
}
```

---

## §FF. Per-function ABI/contract tables

Legend — **T**: thread (L=event-loop-only, S=thread-safe, E=either). **A**: allocates
(pool/malloc/none). **R**: reentrant (Y/N). **Err**: failure return.

| Function | T | A | R | Pre | Post (success) | Err |
|---|---|---|---|---|---|---|
| `xrootd_http_arg` | E | pool | Y | r valid | *out pool copy, NUL-term | DECLINED/ERROR |
| `webdav_bearer_from_query` | L | pool | N | conf,r valid | *out in pool, scheme-stripped | DECLINED |
| `xrootd_http_redact_query_token` | E | none | Y | q mutable copy | authz/access_token redacted in place | (void) |
| `xrootd_iso8601_duration_secs` | E | none | Y | s,out non-NULL | *out∈[1,max] | ERROR |
| `webdav_body_to_buf` | E | pool | Y | r valid | *out contiguous ≤cap | DECLINED/ERROR(oversize) |
| `macaroon_caveats_scan` | E | none | Y | bufs sized | act/path filled (maybe empty) | (void) |
| `webdav_handle_macaroon_request` | L | pool | N | body read | 200 JSON sent | 4xx/5xx JSON |
| `xrootd_cksdata_encode` | E | none | Y | in valid | record written | (size) |
| `xrootd_cksdata_decode` | E | none | Y | buf≥rec | *out filled | DECLINED(stale/bad) |
| `xrootd_cks_sidecar_{get,put}` | L | none | Y | path valid | record read/written | DECLINED/ERROR |
| `xrootd_integrity_persist_async` | L→S→L | pool | N | fd open | digest persisted async | (void; logs) |
| `xrootd_cache_cinfo_load` | L | malloc | Y | cachefile valid | hdr+bitmap | DECLINED/ERROR |
| `xrootd_cache_cinfo_store` | L | none | N | hdr valid | atomic .cinfo written | AGAIN(EEXIST)/ERROR |
| `xrootd_cache_cinfo_{mark,present}_block` | E | none | Y | bm sized | bit set/queried | — |
| `xrootd_dig_match` | E | none | Y | conf,path | *real_root,*rel | 0(no match) |
| `xrootd_dig_authorize` | L | none | Y | ctx authed | — | ERROR(403) |
| `xrootd_dig_open` | L | none | Y | root,rel | fd (RESOLVE_BENEATH) | -1/errno |
| `xrootd_zip_member_open` | L | none | Y | archive,member | handle(fd+meta) | kXR/HTTP err |
| `xrootd_zip_member_pread` | S | none | Y | handle ready | bytes into buf | ERROR |
| `xrootd_gsi_send_pxyreq` | L | malloc/EVP | N | cert verified | kXR_authmore(pxyreq) sent | kXR error |
| `xrootd_gsi_recv_sigpxy` | L | EVP | N | sigpxy body | proxy stored | kXR_NotAuthorized |
| `xrootd_gsi_deleg_store` | L | EVP/file | N | proxy valid | stored mem/file 0600 | ERROR |
| `xrootd_cns_emit` | L | none | Y | emit mode | queued (or dropped+metric) | (void) |
| `xrootd_cns_apply` | L | shm | N | ev valid | file+SHM updated | ERROR |
| `xrootd_cns_{stat,dirlist}` | L | shm | Y | collect mode | metadata from inventory | NotFound |
| `xrootd_ssi_open/write/read` | L | pool | N | resource bound | req buffered / resp served | kXR err |
| `xrootd_ssi_dispatch` | S | malloc | Y | req complete | resp produced | ERROR |

---

## §GG. Wire test vectors (hex fixtures)

Unit tests assert encode/decode against these fixed bytes.

### GG.1 `XrdCksData` adler32 = 0x03da0185, mtime=0x6650_0000 (§8.1, host-order x86-64)
```
Name   : 61 64 6c 65 72 33 32 00 00 00 00 00 00 00 00 00   "adler32"
fmTime : 00 00 00 50 65 00 00 00                            (LE int64 0x0000006550000000)
csTime : 00 00 00 00
Rsvd1/2: 00 00 00
Length : 04
Value  : 03 da 01 85 00 .. (60B padding)
```
Test: `cksdata_encode({"adler32","03da0185"}, 0x6650000000) == above`;
`cksdata_decode(above, mtime=0x6650000000) → hex "03da0185"`; wrong mtime → DECLINED.

### GG.2 GSI `kXGS_pxyreq` envelope (§5)
```
"gsi\0"            : 67 73 69 00
step=2002 (BE)     : 00 00 07 d2
bucket kXRS_main   : 00 00 0b b9   <len BE>   <AES(inner)>
  inner kXRS_x509_req(3024=0x0bd0): 00 00 0b d0 <len BE> <PKCS#10 DER>
  inner kXRS_none  : 00 00 00 00
bucket kXRS_none   : 00 00 00 00
```
Test: build with a fixed CSR + fixed AES key → byte-exact; `find_bucket(kXRS_main)`
locates it; decrypt+`find_bucket(kXRS_x509_req)` returns the CSR DER.

### GG.3 SSI `RRInfo` request (§7)
```
Opc=Rxq(0) | reqId=0x0001 | reqSize=0x00000010 (16 bytes follow)
bytes: 00  00 01  00 00 00 10        (reqCmd, reqId[2], reqSize[4] BE)  + 1 pad to 8
```
Test: `RRInfo(info)` round-trips Cmd()==Rxq, Size()==16.

### GG.4 CNS event ADD `/atlas/f1` size=1024 (§6)
```
op=01 _rsvd=00 00 00  server_id=00 00 00 07  size=00..00 04 00 (BE u64=1024)
mtime=<u64>  name_len=00 09  name2_len=00 00  name="/atlas/f1"
```
Test: encode→apply→`cns_stat("/atlas/f1")` returns size 1024, server 7.

### GG.5 macaroon-request round-trip (§2)
```
REQ  POST /atlas/data  Content-Type: application/macaroon-request
     {"caveats":["activity:DOWNLOAD,LIST","path:/atlas/data"],"validity":"PT1H"}
RESP 200 {"macaroon":"MDA...","uri":{"target":"https://h/atlas/data",
         "targetWithMacaroon":"https://h/atlas/data?authz=MDA...", ...}}
```
Test: caveats_scan → act="DOWNLOAD,LIST", path="/atlas/data";
`iso8601("PT1H")==3600`; issued macaroon validates and authorizes GET `/atlas/data`,
denies `/cms`.

---

## §HH. Explicit state-transition tables

### HH.1 GSI auth FSM (§5) — event × state → action/next
| state \ event | certreq | cert(ok) | cert(bad) | sigpxy(ok) | sigpxy(bad) | disconnect |
|---|---|---|---|---|---|---|
| START | →send kXGS_cert; CERTREQ'd | err | — | — | — | free |
| CERTREQ'd | (dup) err | deleg=off→AUTHED; else send pxyreq→DELEGATING | NotAuthorized | — | — | free key |
| DELEGATING | — | — | — | store→AUTHED | NotAuthorized | free key |
| AUTHED | ignore | ignore | — | ignore | — | free |

### HH.2 SSI request FSM (§7)
| state \ event | write | read#1 | read#n | cancel | close |
|---|---|---|---|---|---|
| ACCUMULATING | append | →DISPATCHING (post task) | (n/a) | →FREE | →FREE |
| DISPATCHING | reject | NGX_AGAIN | NGX_AGAIN | mark cancel→FREE | →FREE |
| READY | reject | serve | serve/EOF | →FREE | →FREE |

### HH.3 cinfo / slice cache FSM (§9)
| state \ event | open(load) | read present | read absent | fill+verify | crash |
|---|---|---|---|---|---|
| ABSENT | load DECLINED→EMPTY | — | — | — | — |
| EMPTY/PARTIAL | — | serve | fetch→FILLING | mark+store→PARTIAL/COMPLETE | last durable bitmap |
| COMPLETE | serve | serve | (none) | — | intact |

### HH.4 archive job FSM (§4B)
`QUEUED → RUNNING → {DONE, FAILED(retain+alert)}`; stage-out `DONE → ON_TAPE`;
stage-in `ON_TAPE → RUNNING → DONE`.

---

## §II. Detailed test specifications (pytest)

Concrete function names + key assertions (one per matrix id; fixtures from the existing
harness — `tests/conftest.py`, dedicated-instance pattern).

```python
# tests/test_query_token.py
def test_query_token_get_ok(webdav):                  # 1a
    r = webdav.get("/pub/f.txt", params={"authz": f"Bearer {JWT}"}); assert r.status==200
def test_query_token_header_still_ok(webdav):         # 1b
    assert webdav.get("/pub/f.txt", headers=bearer(JWT)).status==200
def test_query_token_tampered_403(webdav):            # 1e
    assert webdav.get("/pub/f.txt", params={"authz": JWT[:-2]+"xx"}).status==403
def test_query_token_redacted_in_log(webdav, logs):   # 1h  (REQ-1-SEC)
    webdav.get("/pub/f.txt", params={"authz": f"Bearer {JWT}"})
    assert JWT not in logs.access_text(); assert "authz=REDACTED" in logs.access_text()

# tests/test_macaroon_request.py
def test_macaroon_request_issue_and_use(webdav):      # 2a
    m = webdav.post("/atlas", headers={"Content-Type":"application/macaroon-request"},
                    json={"caveats":["activity:DOWNLOAD","path:/atlas"],"validity":"PT1H"})
    tok = m.json()["macaroon"]; assert webdav.get("/atlas/x", params={"authz":tok}).status==200
def test_macaroon_request_path_caveat_denies(webdav): # 2b
    tok = issue_macaroon(path="/atlas"); assert webdav.get("/cms/x", params={"authz":tok}).status==403
def test_macaroon_request_unauth_401(webdav_noauth):  # 2d
    assert webdav_noauth.post("/atlas", headers=MAC_CT, json={}).status==401

# tests/test_gsi_delegation.py  (interop with real XrdSecgsi)
def test_delegation_store(gsi_server, real_client):   # 5a
    real_client.xrdcp_with_delegation("root://srv//tmp/f", "/dev/null")
    assert gsi_server.delegated_proxy_for(DN) is not None
def test_delegation_forged_rejected(gsi_server):      # 5c
    assert send_sigpxy(self_signed_proxy()).kxr == "kXR_NotAuthorized"

# tests/test_checksum_at_rest.py
def test_onwrite_xattr_interop(srv, stock_xrdfs):     # 8a/8b
    srv.put("/d/f", DATA)  # xrootd_checksum_on_write adler32
    assert stock_xrdfs.query_checksum("root://srv//d/f") == adler32(DATA)
def test_corrupt_record_no_crash(srv):                # 8f
    srv.set_xattr("/d/f","user.XrdCks.adler32", b"\x00\x01")  # short
    assert srv.query_checksum("/d/f") == adler32(DATA)        # recomputed

# tests/test_cache_cinfo.py
def test_partial_survives_restart(cache, origin):     # 9a/9f
    cache.read_range("/big", 0, 256<<10); cache.read_range("/big", 8<<20, 256<<10)
    cache.restart()
    assert cache.served_from_disk("/big", 0, 256<<10)
    assert cache.fetched_from_origin("/big", 4<<20, 256<<10)
```
(Remaining matrix ids follow the same shape; each asserts exactly its "expect" cell.)

---

## §JJ. Definition-of-Done + kill switches / rollback

**Per-feature DoD:** all matrix tests green; interop test green (where defined);
metrics + log lines present (§AA); README + docs/ + gaps-doc updated; feature flag in
`/healthz`/`qconfig`; security-neg test fails without the fix; no `goto`; seam-grep
clean; reviewed against the §Y checklist.

**Kill switches (every feature is off-able without redeploy where possible):**
| feature | disable | effect |
|---|---|---|
| §1 | `xrootd_http_query_token off` (reload) | header-only auth |
| §2 | unset `macaroon_secret` (reload) | 404 on macaroon-request |
| §3 | `xrootd_dig off` (reload) | dig paths → normal namespace 404 |
| §4A | `xrootd_archive_member_access off` | `?xrdcl.unzip=` ignored |
| §5 | `xrootd_gsi_delegation off` (reload) | no pxyreq emitted |
| §6 | `xrootd_cns off` (reload) | no events / inventory queries |
| §7 | `xrootd_ssi off` (reload) | SSI resources 404 |
| §8 | `xrootd_checksum_on_write off`; format=text | lazy + legacy text only |
| §9 | `xrootd_cache_cinfo off` | falls back to `.meta` |
| build | `-DXROOTD_WITH_<F>=0` | code compiled out |

Reload semantics follow the standard drain (`reload-semantics.md`): in-flight finish on
old workers; new conns get new settings. None of these change SHM slot counts except
§6 enabling/disabling the CNS table (WARN on slot change, INVARIANT #10).

---

## §KK. Migration & backward-compatibility notes

- **§8 checksum format.** Default `both` writes text + `XrdCks.<alg>` binary; reads
  prefer binary, fall back to text, else compute. Existing text xattrs remain valid
  (read path unchanged). To go pure-stock-interop, set `text|xrdcks`→`xrdcks` after a
  transition window. No on-disk migration tool needed (lazy recompute fills binary).
- **§9 `.meta`→`.cinfo`.** On first touch of a cached file with a legacy `.meta` and no
  `.cinfo`, `xrootd_cache_cinfo_from_meta()` synthesizes a `COMPLETE` cinfo (no bitmap,
  full-file present) and the old `.meta` is left in place (ignored). `xrootd_cache_cinfo
  off` keeps reading/writing `.meta` only. No flag-day; mixed `.meta`/`.cinfo` trees are
  valid for one release, after which a one-line sweep can delete orphan `.meta`.
- **§5 delegation.** Default `off` → zero behavior change for existing GSI logins
  (no extra round). Enabling `request` is transparent to non-delegating clients
  (they just don't send sigpxy); only `require` changes acceptance.
- **§6 CNS.** Default `off`. Enabling `emit` on data servers is a no-op for clients;
  enabling `collect` on the manager only adds inventory answers for paths the manager
  doesn't already serve.
- **config defaults chosen for zero regression:** every new directive defaults to the
  pre-phase-58 behavior except `xrootd_http_query_token` (on — additive, header still
  primary) and `xrootd_cache_cinfo` (on — back-compat via `.meta` read + synth).

---

## §LL. Design FAQ

**Q: Why not store checksums big-endian for portability?** ADR-4: OP chose stock
bit-for-bit compatibility on the same architecture (WLCG pools are homogeneous). The
decoder is order-tolerant and treats an unrecognized record as a miss (recompute), so
a mixed-arch read never mis-serves — it just recomputes.

**Q: Why a manual caveats array scanner instead of extending json_min?** json_min is a
deliberately tiny scalar/string extractor shared with the client; adding array support
is a larger change with its own tests. The macaroon-request body is a fixed, simple
shape; a bounded scan is lower-risk and self-contained. (If a second caller needs
arrays, promote it to json_min then.)

**Q: Why is SSI "minimal" if it's in scope?** ADR-2 scopes it to unary
request/response validated against a real peer. The streaming/alert/session-mux surface
is a large framework with no current consumer; we ship the wire behavior an official
SSI client exercises and leave the rest documented as future work (§NN).

**Q: Why does CNS append to a file before updating SHM?** Crash safety: the file is the
source of truth; if we crash after the append but before the SHM update, replay on
restart reconstructs SHM. The reverse order could lose an acknowledged event.

**Q: Why `O_EXCL` on the cinfo temp but retry on EEXIST?** A predictable temp name in
the cache dir could be pre-created; `O_EXCL|O_NOFOLLOW` refuses a planted file/symlink
(same hardening as `client_credfile_hardening`); retry handles a stale temp from a
killed run.

**Q: Can `?authz=` and a header both be present?** Yes; the header wins (query is a
fallback only when the header is absent or non-Bearer). Test 1c.

**Q: Why not write a native zip writer for OssArc compose?** OssArc itself shells out to
an archiver program; matching that is lower-risk and lets operators choose the tool. A
native writer is possible later but isn't on the critical path.

---

## §MM. Formal requirements (FR/NFR/SEC/BLD/OPS) + traceability

| ID | Class | Requirement | Test | §R link |
|---|---|---|---|---|
| FR-1 | func | token accepted from `?authz=` and `?access_token=` | 1a,1d | REQ-1-FUNC |
| FR-2 | func | macaroon-request issues a usable, scoped macaroon | 2a | REQ-2-FUNC |
| FR-3 | func | dig serves whitelisted files over root://+HTTP | 3a–3c | REQ-3-FUNC |
| FR-4 | func | zip member served (ranged, both planes) | 4a,4b | REQ-4A-FUNC |
| FR-5 | func | delegated proxy received, verified, stored | 5a | REQ-5-1 |
| FR-6 | func | manager answers stat/dirlist/space from inventory | 6a–6c | REQ-6-FUNC |
| FR-7 | func | SSI unary echo round-trips (interop) | 7e | REQ-7-FUNC |
| FR-8 | func | stock xrdfs reads our checksum xattr | 8b | REQ-8-INTEROP |
| FR-9 | func | partial slice cache survives restart | 9a | REQ-9-FUNC |
| SEC-1 | sec | query token never logged | 1h | REQ-1-SEC |
| SEC-2 | sec | macaroon issuance requires auth; caveats only narrow | 2d,2f | REQ-2-SEC |
| SEC-3 | sec | dig confinement + default-deny + read-only | 3d–3g | REQ-3-SEC |
| SEC-4 | sec | forged/mis-bound proxy rejected | 5c,5d | REQ-5-1 |
| SEC-5 | sec | CNS events only from cluster members | 6f | REQ-6-SEC |
| SEC-6 | sec | corrupt checksum/cinfo record never crashes | 8f,9c | REQ-8/9-ROBUST |
| NFR-1 | perf | query parse <1µs; no crypto on cap-reject | X-01 | §W.4 |
| NFR-2 | perf | stored-member read == normal ranged read | §W.4 | — |
| NFR-3 | scale | CNS sizing documented + capped | §W.3 | — |
| NFR-4 | rel | cinfo/CNS crash-safe (atomic / replay) | X-16,X-25 | §V |
| BLD-1 | build | new files in `./config`; flags compile-out | Y.3 | §A.1/§A.3 |
| OPS-1 | ops | every feature off-able via reload/flag | §JJ | — |
| OPS-2 | ops | metrics + healthz/qconfig per feature | §AA | — |

---

## §NN. Open questions / future work

1. **§4B native zip writer** vs external archiver — start external; revisit if operators
   want no external dependency.
2. **§8.4 per-page CSI scrub cadence** — timer in `src/frm/` vs on-read-only; needs a
   perf measurement on a real export.
3. **§9 cinfo eviction policy weights** — expose LRU/LFU/age weights as a directive once
   we have field data on cache hit patterns.
4. **§6 CNS cardinality cap behavior** — LRU-evict inventory vs refuse-and-SRR-only
   above the cap; pick after a scale test.
5. **§7 SSI streaming responses** — only if a real consumer appears (ADR-2 keeps it out
   for now).
6. **§5 delegation renewal** — auto-refresh a delegated proxy nearing expiry during a
   long TPC (Phase 2+); depends on the outbound-GSI fix landing first.
7. **`?authz=` for the stream plane** — XRootD root:// uses in-band auth, not URLs;
   query-token is HTTP-only by design. Confirm no client expects a root:// equivalent.

---

## §OO. Complete subsystem sources (dig, delegation, CNS, SSI)

> These are whole-file drafts to the verified APIs: `xrootd_beneath_open_root` /
> `xrootd_open_beneath` / `xrootd_stat_beneath` (`src/path/beneath.h`),
> `xrootd_alloc_fhandle` + `ctx->files[]` (`src/connection/fd_table.h`),
> `xrootd_aio_post_task(ctx,c,…)` (`src/core/aio/aio.h`), `xrootd_build_resp_hdr` +
> `xrootd_queue_response` + `kXR_authmore` (response path), `xrootd_gbuf_*` /
> `xrootd_gsi_find_bucket` (`src/auth/gsi/gsi_core.h`), `xrootd_shm_table_alloc`
> (`src/core/compat/shm_slots.h`). **Two GSI crypto helpers are flagged TODO-mirror** —
> they must reuse the exact round-2 session-cipher path in
> `src/auth/gsi/parse_crypto_helpers.c` (do not re-derive EVP call sequences by hand).

### OO.1 dig — `src/dig/dig.h`
```c
#ifndef NGX_XROOTD_DIG_H
#define NGX_XROOTD_DIG_H
#include <ngx_config.h>
#include <ngx_core.h>
#include "../types/context.h"

/* One configured export: logical <name> → real <dir> (canonicalised at config time). */
typedef struct { ngx_str_t name; ngx_str_t dir; char dir_canon[NGX_XROOTD_PATH_MAX]; }
        xrootd_dig_export_t;

/* EITHER. 1 if logical_path == "<prefix>/<export>/<rel>"; fills *real_root (dir_canon)
 * and *rel (relpath within it, may be ""). 0 otherwise. */
int xrootd_dig_match(void *srv_conf, const char *logical_path,
                     const char **real_root, const char **rel);

/* LOOP-ONLY. NGX_OK if ctx principal may read export per the allow-file; else 403. */
ngx_int_t xrootd_dig_authorize(xrootd_ctx_t *ctx, const char *export_name);

/* LOOP-ONLY open; resulting fd read is THREAD-SAFE. O_RDONLY beneath real_root. */
int xrootd_dig_open(const char *real_root, const char *rel, ngx_log_t *log);

#endif
```

### OO.2 dig — `src/dig/dig.c`
```c
#include "dig.h"
#include "../path/beneath.h"
#include "../config/server_conf.h"
#include <fcntl.h>
#include <string.h>

#define DIG_PREFIX     "/.well-known/dig/"
#define DIG_PREFIX_LEN (sizeof(DIG_PREFIX) - 1)

/*
 * xrootd_dig_match — recognise "/.well-known/dig/<export>/<rel>".
 * EITHER. No allocation; *real_root/*rel point into conf / the input. The kernel
 * RESOLVE_BENEATH at open time is the real confinement — this only routes.
 */
int
xrootd_dig_match(void *srv_conf, const char *logical_path,
                 const char **real_root, const char **rel)
{
    ngx_stream_xrootd_srv_conf_t *conf = srv_conf;
    const char *p, *slash;
    ngx_uint_t  i;

    if (!conf->dig_enable || conf->dig_exports == NULL) {
        return 0;
    }
    if (ngx_strncmp(logical_path, DIG_PREFIX, DIG_PREFIX_LEN) != 0) {
        return 0;
    }
    p = logical_path + DIG_PREFIX_LEN;          /* "<export>/<rel>" */
    slash = strchr(p, '/');
    {
        size_t nlen = slash ? (size_t) (slash - p) : strlen(p);
        xrootd_dig_export_t *ex = conf->dig_exports->elts;
        for (i = 0; i < conf->dig_exports->nelts; i++) {
            if (ex[i].name.len == nlen
                && ngx_strncmp(ex[i].name.data, p, nlen) == 0) {
                *real_root = ex[i].dir_canon;
                *rel       = slash ? slash + 1 : "";   /* "" → the export dir itself */
                return 1;
            }
        }
    }
    return 0;
}

/*
 * xrootd_dig_open — O_RDONLY beneath the export root (RESOLVE_BENEATH).
 * LOOP-ONLY. Empty rel ("") opens the export directory itself (for dirlist).
 */
int
xrootd_dig_open(const char *real_root, const char *rel, ngx_log_t *log)
{
    int rootfd, fd;
    rootfd = xrootd_beneath_open_root(real_root);
    if (rootfd < 0) {
        return -1;
    }
    fd = xrootd_open_beneath(rootfd, rel[0] ? rel : ".",
                             O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0);
    close(rootfd);
    return fd;
}
```

### OO.3 dig — `src/dig/dig_auth.c`
```c
#include "dig.h"
#include "../types/identity.h"
#include <stdio.h>
#include <string.h>

/*
 * Allow-file grammar (one rule per line; first match wins; default deny):
 *   <principal-glob> <export>[,<export>...]    # comment
 * principal = token 'sub' or GSI DN; '*' = any authenticated principal.
 *
 * LOOP-ONLY. NGX_OK if ctx's principal may read export_name; NGX_ERROR(403) else.
 * Admin scope (xrootd_auth_gate admin) short-circuits to OK.
 */
ngx_int_t
xrootd_dig_authorize(xrootd_ctx_t *ctx, const char *export_name)
{
    const char *principal;
    FILE       *fp;
    char        line[1024];
    ngx_int_t   verdict = NGX_ERROR;   /* default deny */

    if (xrootd_identity_is_admin(ctx->identity)) {
        return NGX_OK;
    }
    principal = xrootd_identity_principal(ctx->identity);   /* sub or DN; "" if anon */
    if (principal == NULL || principal[0] == '\0') {
        return NGX_ERROR;
    }
    fp = fopen(ctx->srv_conf->dig_auth_file, "re");        /* 'e' = O_CLOEXEC */
    if (fp == NULL) {
        return NGX_ERROR;                                  /* no file → deny */
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *hash = strchr(line, '#'); char *who, *exports, *save, *tok;
        if (hash) { *hash = '\0'; }
        who     = strtok_r(line, " \t\r\n", &save);
        exports = strtok_r(NULL, " \t\r\n", &save);
        if (who == NULL || exports == NULL) { continue; }
        if (strcmp(who, "*") != 0 && strcmp(who, principal) != 0) { continue; }
        for (tok = strtok_r(exports, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
            if (strcmp(tok, export_name) == 0) { verdict = NGX_OK; break; }
        }
        if (verdict == NGX_OK) { break; }                  /* first match wins */
    }
    fclose(fp);
    return verdict;
}
```
(No `goto` — the inner `for` `break` stops at the first matching export and the outer
`if (verdict == NGX_OK) break;` ends the scan; HARD BLOCK honored.)

### OO.4 delegation — `src/auth/gsi/delegation.h`
```c
#ifndef NGX_XROOTD_GSI_DELEGATION_H
#define NGX_XROOTD_GSI_DELEGATION_H
#include "../types/context.h"
#include <openssl/x509.h>

/* LOOP-ONLY. After kXGC_cert verifies: gen ephemeral key + CSR(proxyCertInfo),
 * session-encrypt into kXRS_main, send kXGS_pxyreq via kXR_authmore. */
ngx_int_t xrootd_gsi_send_pxyreq(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* LOOP-ONLY. Parse kXGC_sigpxy: decrypt kXRS_main → kXRS_x509 proxy chain; verify it
 * chains to the authenticated EEC, proxyCertInfo present, key matches our CSR, not
 * expired; store. NGX_OK / NGX_ERROR(→ kXR_NotAuthorized). */
ngx_int_t xrootd_gsi_recv_sigpxy(xrootd_ctx_t *ctx, const uint8_t *body, uint32_t blen);

/* LOOP-ONLY. Persist {proxy chain + server key} keyed by DN: in-memory always; file
 * (0600/O_NOFOLLOW) when store=file. */
ngx_int_t xrootd_gsi_deleg_store(xrootd_ctx_t *ctx, X509 *proxy,
                                 STACK_OF(X509) *chain, EVP_PKEY *key);

/* TODO-mirror (implement next to the round-2 cipher in parse_crypto_helpers.c):
 *   xrootd_gsi_session_encrypt(ctx, plain, n, &enc, &enc_len)  — AES with the SAME
 *     negotiated session cipher/key the round-2 decrypt uses.
 *   xrootd_gsi_make_proxy_csr(&key, &csr_der, &csr_len)        — EVP keygen + X509_REQ
 *     + proxyCertInfo, mirroring client/lib/proxy.c. */
#endif
```

### OO.5 delegation — `src/auth/gsi/delegation.c` (send + recv cores)
```c
#include "delegation.h"
#include "gsi_core.h"
#include "../protocol/gsi.h"
#include "../response/response.h"

ngx_int_t
xrootd_gsi_send_pxyreq(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    EVP_PKEY *kp = NULL; uint8_t *csr = NULL; size_t csr_len = 0;
    uint8_t  *enc = NULL; size_t enc_len = 0;
    xrootd_gbuf inner, outer;
    ngx_int_t rc;

    if (xrootd_gsi_make_proxy_csr(&kp, &csr, &csr_len) != NGX_OK) {     /* TODO-mirror */
        return xrootd_send_error(ctx, c, kXR_ServerError, "delegation: CSR");
    }
    xrootd_gbuf_init(&inner);
    xrootd_gbuf_bucket(&inner, kXRS_x509_req, csr, csr_len);
    xrootd_gbuf_end(&inner);
    free(csr);
    if (inner.err
        || xrootd_gsi_session_encrypt(ctx, inner.p, inner.len,
                                      &enc, &enc_len) != NGX_OK) {       /* TODO-mirror */
        xrootd_gbuf_free(&inner); EVP_PKEY_free(kp);
        return xrootd_send_error(ctx, c, kXR_ServerError, "delegation: enc");
    }
    xrootd_gbuf_free(&inner);

    xrootd_gbuf_init(&outer);
    xrootd_gbuf_start(&outer, kXGS_pxyreq);
    xrootd_gbuf_bucket(&outer, kXRS_main, enc, enc_len);
    xrootd_gbuf_end(&outer);
    free(enc);
    if (outer.err) { xrootd_gbuf_free(&outer); EVP_PKEY_free(kp);
                     return xrootd_send_error(ctx, c, kXR_NoMemory, "delegation buf"); }

    ctx->deleg_key = kp;                       /* paired with the returned proxy */
    ctx->deleg_pending = 1;
    /* kXR_authmore continuation carrying the GSI sub-protocol buffer */
    rc = xrootd_send_authmore(ctx, c, outer.p, outer.len);
    xrootd_gbuf_free(&outer);
    return rc;
}

ngx_int_t
xrootd_gsi_recv_sigpxy(xrootd_ctx_t *ctx, const uint8_t *body, uint32_t blen)
{
    const uint8_t *mainb; size_t mainlen;
    uint8_t       *plain = NULL; size_t plainlen = 0;
    const uint8_t *der;  size_t derlen;
    X509          *proxy = NULL; STACK_OF(X509) *chain = NULL;
    ngx_int_t      rc = NGX_ERROR;

    if (xrootd_gsi_find_bucket(body, blen, kXRS_main, &mainb, &mainlen) != 0) {
        return NGX_ERROR;
    }
    if (xrootd_gsi_session_decrypt(ctx, mainb, mainlen,
                                   &plain, &plainlen) != NGX_OK) {       /* existing path */
        return NGX_ERROR;
    }
    if (xrootd_gsi_find_bucket(plain, plainlen, kXRS_x509, &der, &derlen) != 0) {
        free(plain); return NGX_ERROR;
    }
    if (xrootd_gsi_parse_proxy_chain(der, derlen, &proxy, &chain) != NGX_OK   /* d2i loop */
        || xrootd_gsi_verify_delegated(ctx, proxy, chain) != NGX_OK          /* chain→EEC */
        || xrootd_gsi_proxy_matches_csr(proxy, ctx->deleg_key) != NGX_OK) {  /* key bind */
        free(plain); X509_free(proxy);
        if (chain) sk_X509_pop_free(chain, X509_free);
        return NGX_ERROR;
    }
    rc = xrootd_gsi_deleg_store(ctx, proxy, chain, ctx->deleg_key);
    ctx->deleg_key = NULL;                       /* ownership moved into store */
    free(plain);
    return rc;
}
```

### OO.6 CNS — `src/cms/cns.h`
```c
#ifndef NGX_XROOTD_CNS_H
#define NGX_XROOTD_CNS_H
#include <ngx_config.h>
#include <ngx_core.h>
#include "../types/context.h"

enum { XROOTD_CNS_ADD=1, XROOTD_CNS_DEL=2, XROOTD_CNS_MKDIR=3, XROOTD_CNS_RMDIR=4,
       XROOTD_CNS_MV=5, XROOTD_CNS_TRUNC=6, XROOTD_CNS_CLOSEW=7 };

/* Big-endian on the wire; name(+name2) trail the fixed header. */
struct xrootd_cns_event {
    uint8_t  op; uint8_t _rsvd[3]; uint32_t server_id;
    uint64_t size; uint64_t mtime; uint16_t name_len; uint16_t name2_len;
    /* uint8_t name[name_len + name2_len]; */
};

void      xrootd_cns_emit(xrootd_ctx_t *ctx, uint8_t op, const char *path,
                          const char *path2, uint64_t size, uint64_t mtime);
ngx_int_t xrootd_cns_apply(const struct xrootd_cns_event *ev, size_t total_len);
ngx_int_t xrootd_cns_stat(const char *path, struct stat *out);
ngx_int_t xrootd_cns_dirlist(const char *dir,
                             void (*emit)(void*, const char*, const struct stat*),
                             void *u);
uint64_t  xrootd_cns_space_used(void);
#endif
```

### OO.7 CNS — `src/manager/cns_store.c` (apply + answer)
```c
#include "../cms/cns.h"
#include "../compat/shm_slots.h"
#include "../shm/shm.h"

/* SHM table: rbtree of djb2(path) → {server_id,size,mtime,is_dir}; file is truth. */
static ngx_shmtx_t        g_cns_mtx;
static xrootd_cns_table_t *g_cns;          /* first member is ngx_shmtx_sh_t */

ngx_int_t
xrootd_cns_apply(const struct xrootd_cns_event *ev, size_t total_len)
{
    /* 1) durable file FIRST (truth) so a crash before SHM is healed by replay. */
    if (xrootd_cns_file_append(ev, total_len) != NGX_OK) {
        return NGX_ERROR;
    }
    /* 2) SHM cache — spin+yield mutex (NEVER POSIX-sem; INVARIANT #10). */
    ngx_shmtx_lock(&g_cns_mtx);
    switch (ev->op) {
    case XROOTD_CNS_ADD:
    case XROOTD_CNS_CLOSEW: cns_tbl_upsert(g_cns, ev); break;
    case XROOTD_CNS_DEL:
    case XROOTD_CNS_RMDIR:  cns_tbl_remove(g_cns, ev); break;
    case XROOTD_CNS_MKDIR:  cns_tbl_mkdir(g_cns, ev);  break;
    case XROOTD_CNS_MV:     cns_tbl_rename(g_cns, ev); break;
    case XROOTD_CNS_TRUNC:  cns_tbl_resize(g_cns, ev); break;
    default: break;
    }
    ngx_shmtx_unlock(&g_cns_mtx);
    return NGX_OK;
}

ngx_int_t
xrootd_cns_stat(const char *path, struct stat *out)
{
    ngx_int_t rc = NGX_DECLINED;
    ngx_shmtx_lock(&g_cns_mtx);
    {
        xrootd_cns_node_t *n = cns_tbl_find(g_cns, path);
        if (n) { ngx_memzero(out, sizeof(*out));
                 out->st_size = n->size; out->st_mtime = n->mtime;
                 out->st_mode = n->is_dir ? S_IFDIR : S_IFREG; rc = NGX_OK; }
    }
    ngx_shmtx_unlock(&g_cns_mtx);
    return rc;
}
```
> `g_cns` is created via `xrootd_shm_table_alloc(zone, data, bytes, &g_cns_mtx, …)`
> in the manager's shm-zone init, which clears `mtx->semaphore` (spin+yield).

### OO.8 SSI — `src/ssi/ssi.c` (handle bind + unary RPC)
```c
#include "ssi.h"
#include "../connection/fd_table.h"
#include "../aio/aio.h"
#include "../response/response.h"

/* AIO worker: pure compute on the accumulated request buffer (THREAD-SAFE). */
static void
ssi_dispatch_task(void *data)
{
    xrootd_ssi_req_t *rq = data;
    rq->rc = xrootd_ssi_registry_invoke(rq->resource, rq->req, rq->req_len,
                                        &rq->resp, &rq->resp_len);   /* malloc resp */
}

/* LOOP-ONLY. Bind an SSI virtual handle (no fd) into ctx->files[]. */
ngx_int_t
xrootd_ssi_open(xrootd_ctx_t *ctx, const char *resource, int *out_handle)
{
    int h = xrootd_alloc_fhandle(ctx);
    xrootd_ssi_req_t *rq;
    if (h < 0) { return NGX_ERROR; }
    rq = ngx_pcalloc(ctx->session->connection->pool, sizeof(*rq));
    if (rq == NULL) { return NGX_ERROR; }
    rq->ctx = ctx; rq->state = SSI_REQ_ACCUMULATING;
    ngx_cpystrn((u_char*)rq->resource, (u_char*)resource, sizeof(rq->resource));
    ctx->files[h].kind   = XROOTD_FH_SSI;     /* new handle kind */
    ctx->files[h].ssi    = rq;
    ctx->files[h].fd     = -1;                /* virtual: no fd */
    *out_handle = h;
    return NGX_OK;
}

/* LOOP-ONLY. Accumulate request bytes (kXR_write on an SSI handle). */
ngx_int_t
xrootd_ssi_write(xrootd_ssi_req_t *rq, const uint8_t *p, size_t n)
{
    if (rq->state != SSI_REQ_ACCUMULATING) { return NGX_ERROR; }
    if (rq->req_len + n > XROOTD_SSI_REQ_MAX) { return NGX_ERROR; }   /* X-18 */
    if (xrootd_buf_append(&rq->req, &rq->req_cap, &rq->req_len, p, n) != NGX_OK) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* LOOP-ONLY. First read dispatches (→AGAIN); later reads stream the response. */
ngx_int_t
xrootd_ssi_read(xrootd_ssi_req_t *rq, ngx_connection_t *c,
                off_t off, uint8_t *buf, size_t n, ssize_t *got)
{
    if (rq->state == SSI_REQ_ACCUMULATING) {
        rq->state = SSI_REQ_DISPATCHING;
        return xrootd_aio_post_task(rq->ctx, c, ssi_dispatch_task,
                                    ssi_dispatch_done, rq);   /* NGX_AGAIN */
    }
    if (rq->state != SSI_REQ_READY || rq->rc != NGX_OK) { *got = -1; return NGX_ERROR; }
    if ((uint64_t) off >= rq->resp_len) { *got = 0; return NGX_OK; }     /* EOF */
    *got = (ssize_t) ngx_min(n, rq->resp_len - (uint64_t) off);
    ngx_memcpy(buf, rq->resp + off, (size_t) *got);
    return NGX_OK;
}
```

---

## §PP. Exact `./config` additions (per new file)

Append to the **header** list (near the existing `src/cache/*.h`, `src/auth/gsi/*.h`):
```sh
                        $ngx_addon_dir/src/dig/dig.h \
                        $ngx_addon_dir/src/auth/gsi/delegation.h \
                        $ngx_addon_dir/src/cms/cns.h \
                        $ngx_addon_dir/src/ssi/ssi.h \
                        $ngx_addon_dir/src/ssi/ssi_registry.h \
                        $ngx_addon_dir/src/cache/cinfo.h \
                        $ngx_addon_dir/src/zip/zip_member.h \
                        $ngx_addon_dir/src/core/compat/iso8601.h \
```
Append to the **`NGX_ADDON_SRCS`** list (near `src/auth/gsi/*.c`, `src/cms/*.c`):
```sh
    $ngx_addon_dir/src/core/compat/iso8601.c \
    $ngx_addon_dir/src/dig/dig.c \
    $ngx_addon_dir/src/dig/dig_auth.c \
    $ngx_addon_dir/src/dig/directives.c \
    $ngx_addon_dir/src/auth/gsi/delegation.c \
    $ngx_addon_dir/src/cms/cns_emit.c \
    $ngx_addon_dir/src/manager/cns_store.c \
    $ngx_addon_dir/src/ssi/ssi.c \
    $ngx_addon_dir/src/ssi/ssi_registry.c \
    $ngx_addon_dir/src/zip/zip_member.c \
    $ngx_addon_dir/src/cache/cinfo.c \
    $ngx_addon_dir/src/frm/archive.c \
```
Then **`./configure --with-stream --with-stream_ssl_module --with-http_ssl_module
--with-http_dav_module --with-threads --add-module=$REPO`** once; `make -j$(nproc)`
afterward. (`integrity_info.c` §8 edits and the §8.3 ingest hooks are edits to existing
files → no reconfigure.)

---

## §QQ. Subsystem README templates

Each new directory ships a `README.md` (doc-tree standard). Skeleton:
```markdown
# src/dig/ — remote diagnostics (XrdDig parity)

## Overview
Read-only, admin-only exposure of whitelisted server files over root://+HTTP under
`/.well-known/dig/<export>/<rel>`, confined by the kernel openat2(RESOLVE_BENEATH)
primitive (`xrootd_open_beneath`). Off by default (`xrootd_dig off`).

## Files
| file | role |
|---|---|
| dig.c | prefix recognizer + confined open |
| dig_auth.c | allow-file (principal→exports), default deny |
| directives.c | xrootd_dig / _export / _auth |

## Invariants
- RESOLVE_BENEATH is the confinement (not string checks); traversal → 403.
- Default deny; admin scope or allow-file entry required; read-only handles.
- Never expose key material; operators choose exports (docs warn).

## Tests
tests/test_dig.py — success / 403 / traversal / read-only.
```
(Analogous READMEs for `src/ssi/`, `src/cms/` CNS note, and a `src/auth/gsi/` delegation
section.)

---

## §RR. Full config glue (config.h fields, directives.c rows, merges)

### RR.1 `src/core/types/config.h` — new fields
```c
/* §1 */ ngx_flag_t  http_query_token;
/* §2 */ ngx_int_t   macaroon_max_validity;   ngx_str_t macaroon_location;
/* §3 */ ngx_flag_t  dig_enable;  ngx_array_t *dig_exports; ngx_str_t dig_auth_file;
/* §4 */ ngx_flag_t  archive_member_access; ngx_str_t archive_prefix, archive_cmd;
/* §5 */ ngx_uint_t  gsi_delegation;   /* off/request/require */
         ngx_uint_t  gsi_delegation_store; ngx_str_t gsi_delegation_dir;
/* §6 */ ngx_uint_t  cns_mode;         /* off/emit/collect */
         ngx_str_t   cns_store; ngx_int_t cns_flush_interval;
/* §7 */ ngx_flag_t  ssi_enable; ngx_array_t *ssi_resources;
/* §8 */ ngx_uint_t  checksum_xattr_format; /* text/xrdcks/both */
         ngx_uint_t  checksum_store;        /* xattr/sidecar/auto */
         ngx_str_t   checksum_on_write;
/* §9 */ ngx_flag_t  cache_cinfo;
```
All initialized to `NGX_CONF_UNSET*` in the create-conf callbacks.

### RR.2 `directives.c` — representative rows
```c
{ ngx_string("xrootd_http_query_token"),
  NGX_HTTP_MAIN|NGX_HTTP_SRV|NGX_HTTP_LOC|NGX_CONF_FLAG,
  ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
  offsetof(ngx_http_xrootd_webdav_loc_conf_t, http_query_token), NULL },

{ ngx_string("xrootd_gsi_delegation"),
  NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
  ngx_conf_set_enum_slot, NGX_STREAM_SRV_CONF_OFFSET,
  offsetof(ngx_stream_xrootd_srv_conf_t, gsi_delegation), &xrootd_gsi_deleg_modes },

{ ngx_string("xrootd_dig_export"),
  NGX_STREAM_SRV_CONF|NGX_CONF_TAKE2,
  xrootd_dig_export_slot, NGX_STREAM_SRV_CONF_OFFSET, 0, NULL },

{ ngx_string("xrootd_cns"),
  NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
  ngx_conf_set_enum_slot, NGX_STREAM_SRV_CONF_OFFSET,
  offsetof(ngx_stream_xrootd_srv_conf_t, cns_mode), &xrootd_cns_modes },
```
Enum tables:
```c
static ngx_conf_enum_t xrootd_gsi_deleg_modes[] = {
    {ngx_string("off"),XROOTD_GSI_DELEG_OFF},{ngx_string("request"),XROOTD_GSI_DELEG_REQ},
    {ngx_string("require"),XROOTD_GSI_DELEG_REQUIRE},{ngx_null_string,0} };
static ngx_conf_enum_t xrootd_cns_modes[] = {
    {ngx_string("off"),XROOTD_CNS_OFF},{ngx_string("emit"),XROOTD_CNS_EMIT},
    {ngx_string("collect"),XROOTD_CNS_COLLECT},{ngx_null_string,0} };
```

### RR.3 `merge_*_conf()` — defaults (zero-regression)
```c
ngx_conf_merge_value (c->http_query_token,    p->http_query_token,    1);
ngx_conf_merge_value (c->dig_enable,          p->dig_enable,          0);
ngx_conf_merge_uint_value(c->gsi_delegation,  p->gsi_delegation,      XROOTD_GSI_DELEG_OFF);
ngx_conf_merge_uint_value(c->cns_mode,        p->cns_mode,            XROOTD_CNS_OFF);
ngx_conf_merge_value (c->ssi_enable,          p->ssi_enable,          0);
ngx_conf_merge_uint_value(c->checksum_xattr_format, p->checksum_xattr_format, XROOTD_CKS_FMT_BOTH);
ngx_conf_merge_uint_value(c->checksum_store,  p->checksum_store,      XROOTD_CKS_STORE_XATTR);
ngx_conf_merge_value (c->cache_cinfo,         p->cache_cinfo,         1);
ngx_conf_merge_msec_value(c->cns_flush_interval, p->cns_flush_interval, 10000);
```

---

## §SS. Build & smoke-test runbook

```bash
# 1. register new files (§PP), then full configure (new files/dirs present)
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
            --with-http_dav_module --with-threads --add-module=$REPO
make -j$(nproc)

# 2. validate config parses
/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf

# 3. per-feature smoke (after starting test servers)
tests/manage_test_servers.sh restart
PYTHONPATH=tests pytest tests/test_query_token.py tests/test_macaroon_request.py \
    tests/test_dig.py tests/test_zip_member.py tests/test_checksum_at_rest.py \
    tests/test_cache_cinfo.py -v --tb=short

# 4. interop lane (needs /tmp/xrootd-src binaries; §DD)
TEST_INTEROP=1 PYTHONPATH=tests pytest tests/test_gsi_delegation.py \
    tests/test_ssi.py tests/test_cns.py -v

# 5. flag-off regression: build with features compiled out
./configure ... --add-module=$REPO \
  && env XROOTD_CFLAGS="-DXROOTD_WITH_DIG=0 -DXROOTD_WITH_SSI=0" make -j$(nproc)
```
Expected: incremental edits (§1/§2/§8) need no reconfigure; new dirs (dig/ssi/cns
files, cinfo, delegation, zip_member, iso8601, frm/archive) require the step-1
`./configure`. `nginx -t` must pass with every new directive present and with all
features off (defaults).

---

## §TT. Protocol / constant reference tables

### TT.1 GSI handshake steps (verified `src/protocol/gsi.h`)
| const | value | dir | meaning |
|---|---|---|---|
| `kXGC_certreq` | 1000 | C→S | request server cert (round 1) |
| `kXGC_cert` | 1001 | C→S | client proxy chain (round 2) |
| `kXGC_sigpxy` | 1002 | C→S | **signed delegated proxy (§5)** |
| `kXGS_init` | 2000 | S→C | initial exchange |
| `kXGS_cert` | 2001 | S→C | server cert + DH |
| `kXGS_pxyreq` | 2002 | S→C | **proxy-sign request / CSR (§5)** |
| `kXGSI_VERSION` | 20100 | — | GSI sub-protocol version |

### TT.2 XrdSut bucket types (verified + §5 additions)
| const | value | carries |
|---|---|---|
| `kXRS_none` | 0 | terminator |
| `kXRS_inactive` | 1 | skip on serialize |
| `kXRS_cryptomod` | 3000 | "ssl" |
| `kXRS_main` | 3001 | encrypted inner buffer |
| `kXRS_puk` | 3004 | DH public key |
| `kXRS_cipher` | 3005 | DH params / ciphertext |
| `kXRS_rtag` | 3006 | random challenge tag |
| `kXRS_signed_rtag` | 3007 | signed tag |
| `kXRS_user` | 3008 | username |
| `kXRS_creds` | 3010 | XrdSecpwd creds |
| `kXRS_version` | 3014 | int32 version |
| `kXRS_status` | 3015 | pwd status word |
| `kXRS_clnt_opts` | 3019 | client option flags |
| **`kXRS_x509`** | **3022** | **X.509 cert / proxy chain (§5)** |
| **`kXRS_x509_req`** | **3024** | **PKCS#10 cert request (§5)** |

### TT.3 GSI delegation option bits (`XrdSecProtocolgsi.hh`)
| bit | value | side | meaning |
|---|---|---|---|
| `kOptsDlgPxy` | 0x01 | client | ask to delegate a proxy |
| `kOptsSigReq` | 0x04 | client | will sign a delegation request |
| `kOptsSrvReq` | 0x08 | server | request a delegated proxy |
| `kOptsPxFile` | 0x10 | server | persist delegated proxies as files |
| `kOptsPxCred` | 0x40 | server | persist as credentials |

### TT.4 kXR status / error codes used by phase 58
| symbol | usage |
|---|---|
| `kXR_ok` / `kXR_oksofar` | normal/partial reply (dig read, zip member) |
| `kXR_authmore` | GSI continuation (delegation pxyreq) |
| `kXR_error` | error envelope (errcode + msg) |
| `kXR_NotFound` | dig miss, zip member miss (→404) |
| `kXR_NotAuthorized` | dig authz, delegation reject, scope deny (→403) |
| `kXR_ArgInvalid` | bad opaque/member, bad request (→400) |
| `kXR_Unsupported` | compressed member w/o codec (→501) |
| `kXR_IOError` | pread/inflate (→500) |
*(Numeric values: `XProtocol.hh` — referenced, not duplicated, to avoid drift.)*

### TT.5 ZIP central-directory fields consumed (`src/zip/zip_dir.c`)
CDFH signature `0x02014b50`; fields used: compression method (0=stored, 8=deflate),
compressed/uncompressed size (ZIP64-saturated `0xFFFFFFFF` → ZIP64 extra), local-header
offset, filename. **Rejected:** encrypted entries, methods ∉{0,8}, data-descriptor
entries (size unknown at open), any out-of-bounds field. Duplicate names → last CDFH
wins (XrdZip semantics).

### TT.6 SSI RRInfo (`XrdSsiRRInfo.hh`)
8-byte union: `reqCmd[1]` (Opc: Rxq=0 request, Rwt=1 wait, Can=2 cancel),
`reqId[2]`, `reqSize[4]` (network order). One header precedes the request payload on
the write stream and the response on the read stream.

---

## §UU. Formal grammars (EBNF)

```ebnf
(* §1 query token *)
authz-arg     = ("authz" | "access_token") "=" ["Bearer" %x20] token ;
token         = 1*pchar ;                     (* %XX/'+' decoded; len ≤ XROOTD_TOKEN_MAX *)

(* §2 macaroon-request body — JSON subset actually parsed *)
mac-request   = "{" [ caveats-field ] [ "," ] [ validity-field ] "}" ;
caveats-field = q "caveats" q ":" "[" [ caveat *( "," caveat ) ] "]" ;
caveat        = q ( activity-cav | path-cav | other ) q ;
activity-cav  = "activity:" act *( "," act ) ;
act           = "DOWNLOAD"|"UPLOAD"|"LIST"|"DELETE"|"MANAGE"|"STAGE"|"READ_METADATA" ;
path-cav      = "path:" abspath ;
validity-field= q "validity" q ":" q iso8601 q ;

(* §2/§4A ISO-8601 duration subset *)
iso8601       = ["P"] ["T"] 1*( 1*DIGIT unit ) ;
unit          = "D" | "H" | "M" | "S" ;       (* W/Y/Mo unsupported *)

(* §3 dig allow-file *)
dig-rule      = principal 1*WSP export *( "," export ) [ comment ] LF ;
principal     = "*" | sub | dn ;              (* token 'sub' or GSI DN *)
comment       = "#" *CHAR ;

(* §4A archive member opaque (XrdZip-compatible) *)
member-uri    = path ".zip" "?" "xrdcl.unzip=" member-name ;

(* §7 SSI resource config *)
ssi-resource  = "xrootd_ssi_resource" 1*WSP name 1*WSP handler ";" ;
```

---

## §VV. STRIDE threat model per feature

| feature | Spoofing | Tampering | Repudiation | Info-disclosure | DoS | Elev. of priv |
|---|---|---|---|---|---|---|
| §1 ?authz= | token bytes = identity (same as header) | n/a (validated) | access log records principal | **token in logs → §1.7 redaction** | huge arg → cap-reject | scope-checked downstream |
| §2 macaroon | issuer authed | caveats only narrow (intersect) | issue logged | macaroon = bearer (TLS only) | body cap 16 KiB | cannot widen rights |
| §3 dig | admin/allow-file principal | read-only handles | dig access metric+log | **secret files if misconfigured → docs + default off** | confined fds; per-req | RESOLVE_BENEATH + deny |
| §4A zip | n/a (data) | member bounds-checked | member read metric | only archive contents | deflate bomb → bounded inflate | member name is archive-internal |
| §5 deleg | proxy chains to EEC | key/CSR binding | delegation metric+log | proxy at-rest 0600 | RSA work per login (gated) | forged/over-pathlen rejected |
| §6 CNS | CMS allowlist source | file-truth + replay | event metrics | inventory = metadata only | queue cap + drop metric | non-cluster events dropped |
| §7 SSI | resource ACL (future) | request cap | request metric | handler-defined | req cap; one in-flight | compiled-in handlers only |
| §8 cks | n/a | mtime+size staleness guard | persist metric | digest not secret | offloaded compute | advisory cache |
| §9 cinfo | n/a | atomic write; under-claim safe | cache metrics | local cache only | bounded bitmap | verify-on-fill |

---

## §WW. Performance benchmark & regression-gate plan

Reuses `tests/run_load_test.sh` + `tests/profile_load.sh` (task-clock + dwarf;
`cpu_flamegraph_profiling`). Each perf-sensitive feature gets a baseline + a gate.

| feature | metric | method | baseline | gate (fail if) |
|---|---|---|---|---|
| §1 | auth-phase latency added | wrk GET with `?authz=` vs header | header path | +>5 µs/req median |
| §4A | stored-member read throughput | `xrdcp` member vs plain file of same size | plain ranged read | <90% of plain |
| §4A | deflate-member CPU | flamegraph inflate share | n/a | OOM or unbounded buffer |
| §5 | GSI login latency w/ delegation | time `xrdcp` auth round-trip, deleg vs off | deleg off | depends on RSA only (document, not gate) |
| §6 | data-path overhead of `emit` | write throughput emit on/off | emit off | +>1% on close path |
| §6 | manager stat from inventory | p99 stat latency | local stat | document; SHM µs-held |
| §8 | close latency w/ on-write cksum | PUT+close, on-write on/off | off (lazy) | offloaded → +>2% event-loop time |
| §9 | partial-hit serve vs refetch | restart + ranged read | cold fetch | hit must avoid origin RTT |

Gates run in `pytest-58` perf marks on the dedicated perf host (WSL2 has no PMU; use
task-clock). Record numbers in the PR description; a >gate regression blocks merge.

---

## §XX. Telemetry: alert rules, Grafana panels, SLOs

### XX.1 Prometheus alert rules (additions to the existing rules file)
```yaml
- alert: XrootdDigDeniedSpike
  expr: rate(xrootd_dig_access_total{result="denied"}[5m]) > 5
  for: 10m
  annotations: {summary: "dig access denials elevated (possible probing)"}
- alert: XrootdGsiDelegationForged
  expr: increase(xrootd_gsi_delegation_total{result="forged"}[15m]) > 0
  labels: {severity: warning}
- alert: XrootdCnsEventsDropped
  expr: rate(xrootd_cns_dropped_total[5m]) > 0
  for: 10m
  annotations: {summary: "CNS event queue overflow — inventory drift; check flush interval"}
- alert: XrootdCacheVerifyFail
  expr: increase(xrootd_cache_cinfo_total{event="verify_fail"}[10m]) > 0
  annotations: {summary: "cache fill failed checksum verify — origin corruption or bug"}
- alert: XrootdChecksumPersistErrors
  expr: rate(xrootd_checksum_persist_total{result="error"}[15m]) > 0.1
```

### XX.2 Grafana panels (added to the existing dashboard)
- "Token source" — header vs `?authz=` (`xrootd_http_query_token_total` by result).
- "Macaroons issued" — by mode(oauth2/request).
- "Dig access" — ok/denied/miss stacked.
- "GSI delegation" — stored/refused/forged.
- "CNS inventory size + drop rate" — gauge + rate.
- "Cache cinfo" — hit/partial/miss/verify_fail.
- "Checksum persistence" — by trigger(close/put/tpc).

### XX.3 SLOs
| feature | SLI | SLO |
|---|---|---|
| §1/§2 auth | successful-auth latency p99 | < 20 ms (cache-warm) |
| §3 dig | availability (admin reads succeed) | 99.9% |
| §6 CNS | inventory freshness (event→visible) | < 2× flush_interval p99 |
| §9 cache | partial-hit ratio improvement | measured, reported (no hard SLO) |
| §8 integrity | persist success rate | > 99.9% (advisory; misses recompute) |

---

## §YY. Operational runbooks (symptom → check → fix)

| symptom | check | fix |
|---|---|---|
| `?authz=` GET → 401 | `xrootd_http_query_token` on? token valid? | enable directive; verify token via `/.well-known` issuer |
| JWT appears in access log | grep log; confirm redaction build | ensure §1.7 redaction in log path; hotfix + rotate token |
| macaroon-request → 404 | `macaroon_secret` configured? | set secret; reload |
| macaroon-request → 401 | client authenticated first? | present a valid bearer/cert before issuing |
| dig path → 404 with `xrootd_dig on` | export name spelled right? allow-file? | fix `xrootd_dig_export`; add allow-file rule |
| dig path → 403 | principal in allow-file? admin scope? | add principal→export; or grant admin |
| zip member → 501 | member compression method | install/enable the codec; or stored member |
| GSI login fails w/ `require` | client sends sigpxy? | client needs delegation support; or use `request` |
| delegated proxy unused in TPC | outbound-GSI fixed? proxy expired? | land outbound-GSI fix (ADR-3); re-delegate |
| manager dirlist stale | `xrootd_cns_dropped_total`>0? flush interval? | lower `cns_flush_interval`; trigger reconcile |
| manager stat wrong after crash | inventory file intact? | restart → replay rebuilds SHM; reconcile if file lost |
| cache serves stale after origin change | `.cinfo` mtime vs origin | mtime guard should invalidate; if not, `xrootd_cache_cinfo off` + purge |
| checksum xattr not read by stock xrdfs | `xrootd_checksum_xattr_format`? | set `both`/`xrdcks`; recompute (lazy) |
| `setxattr ENOTSUP` warnings | filesystem supports user xattr? | `xrootd_checksum_store auto` → sidecar |

(Extends the CLAUDE.md DEBUG table; same symptom→check→command shape.)

---

## §ZZ. Data-format versioning & forward/back-compat

| format | version field | reader policy | writer policy | downgrade |
|---|---|---|---|---|
| `XrdCks.<alg>` binary (§8) | none (stock struct) | decode-tolerant; stale/unknown → miss | host-order; `Name` identifies algo | stock reads ours; we read stock |
| `.cks` sidecar (§8.2) | record = stock struct | iterate fixed records; bad → skip | append/replace by algo | drop sidecar → lazy recompute |
| `.cinfo` (§9) | `magic`+`version=2` | wrong magic/version → DECLINED (empty) | always v2 | old `.meta` still read (synth) |
| CNS file (§6) | header `magic`+`version` | replay; version bump → migrate-or-rebuild | append-only records | rebuild from data-server walk |
| delegation store file (§5) | PEM (self-describing) | OpenSSL parse | 0600 PEM chain+key | re-delegate on miss |

**Rule:** every binary on-disk format starts with `magic`+`version`; a reader that sees
an unknown version treats the artifact as absent (safe: recompute/refetch/rebuild),
never mis-serves. Bumps ship with a one-release dual-read window.

---

## §A2. Test fixtures / conftest additions

```python
# tests/conftest.py (additions)
@pytest.fixture
def jwt_factory(token_signer):
    """Mint a WLCG JWT with given scopes/exp for §1/§2 tests."""
    def make(scopes="storage.read:/", exp_delta=3600, sub="alice"):
        return token_signer.sign({"sub": sub, "scope": scopes,
                                  "exp": int(time.time()) + exp_delta,
                                  "wlcg.ver": "1.0"})
    return make

@pytest.fixture
def zip_fixture(tmp_path):
    """Build a .zip with one stored + one deflate member; return (path, members)."""
    import zipfile
    p = tmp_path / "a.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("stored.bin", os.urandom(4096), compress_type=zipfile.ZIP_STORED)
        z.writestr("def.txt", b"x"*100000, compress_type=zipfile.ZIP_DEFLATED)
    return p, {"stored.bin": ..., "def.txt": ...}

@pytest.fixture
def gsi_proxy(grid_ca):
    """RFC-3820 proxy from a test EEC (reuse client/lib/proxy.c via xrdgsiproxy)."""
    return grid_ca.make_proxy(hours=1)

@pytest.fixture
def cache_origin(start_instance):
    """A second xrootd instance acting as the cache origin for §9."""
    return start_instance(role="origin", port_band="origin")

@pytest.fixture
def logs(test_servers):
    """Access to access/error logs for redaction assertions (§1.7)."""
    class L:
        def access_text(self): return open(test_servers.access_log).read()
    return L()
```
Interop fixtures (`stock_xrdfs`, `real_gsi_client`, `ssi_peer`, `cmsd_peer`) launch
`/tmp/xrootd-src` binaries via the dedicated-instance pattern and the
`pyxrootd_isolation_worker` for any official Python bindings.

---

## §B2. End-to-end worked scenarios

### B2.1 gfal2 macaroon download (combines §2 + §1)
```
1. gfal-token https://se//atlas/data  →  POST /atlas/data
     Content-Type: application/macaroon-request
     {"caveats":["activity:DOWNLOAD","path:/atlas/data"],"validity":"PT1H"}
   server: authed? yes → caveats_scan(DOWNLOAD,/atlas/data) → iso8601(PT1H)=3600
           → xrootd_macaroon_issue → 200 {macaroon, uri.targetWithMacaroon:".../?authz=M"}
2. gfal-copy <targetWithMacaroon> file:///tmp/out
     GET /atlas/data?authz=M  → bearer_from_query → validate(macaroon secret)
     → scope path:/atlas/data covers /atlas/data → 200 stream
   access log: "GET /atlas/data?authz=REDACTED ..."   (§1.7)
```

### B2.2 Tier-2 admin reads a log via dig (§3)
```
xrdfs root://se// cat /.well-known/dig/logs/error.log
  → dig_match(export=logs, root=/var/log/nginx-xrootd, rel=error.log)
  → dig_authorize(sub=admin@cern.ch, "logs") → allow-file "* logs" → OK
  → dig_open(RESOLVE_BENEATH "/var/log/nginx-xrootd","error.log") → ro fd → stream
attacker: cat /.well-known/dig/logs/../../etc/shadow → RESOLVE_BENEATH refuses → 403
```

### B2.3 Cache node restart keeps partial files (§9 + §8)
```
warm: read [0,256K) and [8M,8.25M) of /big → fills 2 windows
      slice_fill verifies each vs origin cks (§8) → mark bits → store .cinfo (atomic)
restart
read [0,256K): cinfo_load → bit set → serve from disk (no origin RTT)
read [4M,4.25M): bit clear → fetch → verify → mark → store
```

### B2.4 GSI delegation + TPC (§5, Phase 2 after outbound fix)
```
xrdcp --delegate root://src//f root://dst//f
  dst auth: certreq→cert(ok)→ (deleg=request) →pxyreq(CSR)→sigpxy(proxy)→store(DN)
  dst TPC pull: select credential = delegated proxy for DN → GSI-auth to src → stream
```

---

## §C2. Cross-feature interaction matrix

| produces ↓ / consumes → | §1 | §2 | §4 | §5 | §6 | §8 | §9 |
|---|---|---|---|---|---|---|---|
| §1 `?authz=` | — | macaroon URIs use it | — | — | — | — | — |
| §2 macaroon | issued tokens flow via §1 | — | — | — | — | — | — |
| §4B archive | — | — | manifest reuses §8 cks | — | CNS sees archive files | per-member cks | — |
| §5 delegation | — | — | feeds TPC (4B stage src) | — | — | — | — |
| §6 CNS | — | — | inventories archives | — | — | — | — |
| §8 cks-at-rest | — | — | manifest + member verify | — | — | — | **cinfo origin digest** |
| §9 cinfo | — | — | — | — | — | verify-on-fill uses §8 | — |

Key edges: **§8→§9** (digest enables verify-on-fill); **§1↔§2** (issue then present);
**§5→§4B/TPC** (delegated cred for source pull); **§4B→§6** (archives appear in
inventory). No conflicting edges; features are independently flag-gated (§JJ).

---

## §D2. Effort estimation & critical path

| PR | person-days | depends on |
|---|---|---|
| 1.1 http_arg+urldecode | 0.5 | — |
| 1.2 query fallback | 1.0 | 1.1 |
| 1.3 log redaction | 0.5 | 1.2 |
| 2.1 iso8601 | 0.5 | — |
| 2.2 macaroon-request | 2.0 | 2.1 |
| 3.1/3.2 dig | 5.0 | — |
| 4A.1 zip member | 3.0 | — |
| 4B.1 archive compose | 6.0 | 4A.1, §8 |
| 8.1 cksdata codec | 2.0 | — |
| 8.2 sidecar | 2.0 | 8.1 |
| 8.3 on-ingest | 2.0 | 8.1 |
| 9.1/9.2 cinfo | 4.0 | 8.1 |
| 5.1/5.2 delegation P1 | 8.0 | — |
| (outbound-GSI fix) | 8.0+ | separate epic |
| 5.3 TPC consume | 3.0 | outbound fix, 5.2 |
| 6.1/6.2 CNS | 10.0 | — |
| 7.1/7.2 SSI | 8.0 | interop harness |

**Critical path to "drop-in interop edge":** 1.x → 2.x → 8.1 → 9.x (≈ 13 pd) gives the
WLCG token/cache wins fastest. **CNS (6) and SSI (7)** are the long poles (~18 pd
combined) and parallelizable with the rest. **5.3** is blocked by the outbound-GSI epic
(ADR-3) and should not be on the early critical path.

---

## §E2. Documentation deliverables map

| feature | new/updated docs |
|---|---|
| §1 | `docs/06-authentication/` token page (+query param); `06.../security` note |
| §2 | `docs/06-authentication/macaroons.md` (add request content-type) |
| §3 | `docs/05-operations/` dig page; `src/dig/README.md` |
| §4 | `docs/04-protocols/` archive/zip page; `src/zip/README.md` update |
| §5 | `docs/06-authentication/gsi.md` delegation section; `src/auth/gsi/README.md` |
| §6 | `docs/10-architecture/` CNS page; `src/cms/README.md` CNS note |
| §7 | `docs/04-protocols/ssi.md`; `src/ssi/README.md` |
| §8 | `docs/10-reference/crc64-checksums.md` (+at-rest/xattr/sidecar) |
| §9 | `docs/02-concepts/` caching page (+cinfo); `src/cache/README.md` |
| all | `docs/10-reference/gaps-vs-xrootd.md` rows flipped to "implemented" |

Every new concept lands docs **in the same PR** (project rule). Doxygen file-header
docblocks on each new `.c`/`.h` (doc-tree standard).

---

## §F2. Release sign-off checklist (per feature → ship)

- [ ] all matrix tests (§II) green in `pytest-58`
- [ ] interop test (§DD) green where defined (§2 gfal2, §5 XrdSecgsi, §7 SSI peer, §6 cluster)
- [ ] security-negative tests fail without the fix (proven)
- [ ] perf gate (§WW) within bound; numbers in PR
- [ ] metrics + alerts + Grafana panel (§AA/§XX) present
- [ ] `/healthz` + `qconfig` expose the flag; default = pre-58 behavior
- [ ] runbook row (§YY) added; ops reviewed
- [ ] docs (§E2) merged in same PR; gaps-doc row flipped
- [ ] ASAN run (`asan-58`) clean over the §X subset
- [ ] reload semantics verified (drain; no SHM slot surprise except §6)
- [ ] kill switch (§JJ) verified to fully disable
- [ ] no `goto`; seam-grep clean; review checklist (§Y.2) signed

---

## §G. Glossary
- **EEC** — End-Entity Certificate (the user's long-lived X.509; proxies chain to it).
- **proxyCertInfo** — RFC 3820 extension marking an X.509 as a (delegated) proxy.
- **kXRS_x509 / kXRS_x509_req** — XrdSut bucket types 3022/3024 carrying a proxy cert /
  a PKCS#10 request.
- **RRInfo** — XrdSsi 8-byte request/response framing header.
- **cinfo** — XrdPfc per-cached-file metadata (here: validity + block bitmap + stats +
  origin digest).
- **XrdCksData** — official binary checksum record stored in the `XrdCks.<alg>` xattr.
- **CNS** — Composite Cluster Name Space (cluster-wide file inventory).
- **closew** — close-after-write event (when a file's final size is known).

---

## Appendix — answered decisions (verbatim)
1. **CNS (#6):** in scope. → ADR-1.
2. **SSI (#7):** consumer = stand up an XRootD instance/cluster from official
   components and use it to test the nginx module. → ADR-2.
3. **GSI delegation Phase 2 (#5):** fix the outbound native-GSI client first. → ADR-3.
4. **Checksum xattr endianness (#8.1):** host-order, bit-for-bit stock-compatible on
   the same arch. → ADR-4.
