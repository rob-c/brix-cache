# Code Sharing & Reuse Analysis v3

**Date:** 2026-05-27  
**Scope:** Architectural-level patterns across stream/WebDAV/S3 protocol layers (builds on `code-sharing-reuse-v2.md`)  
**Focus:** Reduced long-term support burden, lowered barriers to entry for understanding the module  

---

## Summary

v2 focused on helper-function consolidation and boilerplate reduction. v3 focuses on **architectural patterns** — request lifecycle phases, dispatch routing chains, response type selection logic, auth state storage layouts, namespace translation steps, proxy handle translation maps, and test fixture reuse patterns. The goal is a shared mental model: "common layer does X, protocol layer adds Y" rather than line-count savings alone.

---

## 1. Request Lifecycle Phases (Common Layer)

### Current State

Every request follows the same abstract lifecycle regardless of protocol:

| Phase | Stream (`root://`) | WebDAV (`davs://`) | S3 |
|---|---|---|---|
| **Accept** | `connection/handler.c` allocates `brix_ctx_t` on c->pool | `webdav/module.c` location handler | `s3/module.c` location handler |
| **Authenticate** | `handshake/dispatch_session.c` → login/auth/gsi/token/sss | `webdav/auth_cert.c` / `auth_token.c` | `s3/auth_sigv4_verify.c` (separate from WLCG) |
| **Parse** | `connection/recv.c` frames handshake/header/payload bytes | HTTP method + URI parsed by dispatch | `s3/handler.c` parses path-style URI into bucket+key |
| **Resolve** | All wire paths → `resolve_path()` before `open()` (INVARIANT #4) | `webdav_resolve_path(path)` canonicalizes and confines | `s3_resolve_key(root, key, out, outsz)` strips slashes + prepend "/" then calls `brix_resolve_path_input` |
| **Execute** | Dispatched to opcode handler via 5-phase chain (see §2) | Method handler (`get.c`, `put.c`, etc.) | HTTP method → operation_table dispatch |
| **Respond** | Response framing via `response/` helpers + queue to write chain | Build `ngx_chain_t` of `ngx_buf_t` → output filter | XML error or file-backed sendfile body |
| **Metric** | `BRIX_*_METRIC_INC(op, status)` at callsite | `webdav_metrics_return(status_bytes, proto)` | `s3_send_xml_error` increments S3 internal-error metric on OOM |
| **Cleanup** | `disconnect.c`: three-phase cleanup (see §5) | Per-request ctx freed by nginx pool destruction | Per-request ctx freed by nginx pool destruction |

### Shared Mental Model

```
accept → authenticate → parse → resolve → execute → respond → metric → cleanup
```

**Barrier reduction:** New contributors learn ONE lifecycle pattern, then only the protocol-specific differences. Currently they must memorize 3 separate lifecycles.

**Support burden reduction:** Lifecycle changes (e.g., adding a new phase like "cache check") touch one common layer file rather than 3 protocol handlers.

---

## 2. Dispatch Routing Chain (Common Layer)

### Current State

Stream-layer dispatch uses a **5-phase ordered chain** (`handshake/dispatch.c:1–78`):

```
brix_dispatch() [78 lines]
    ├─ brix_verify_pending_sigver()        — verify pending sigver state before routing
    ├─ brix_signing_enforce_level()         — enforce request signing level
    ├─ brix_dispatch_session_opcode()       — protocol/login/auth/bind/endsess/ping/set
    ├─ [if proxy_enable && logged_in] → upstream dispatch  — proxy mode gate
    ├─ brix_dispatch_read_opcode()          — open(read)/stat/read/close/dirlist/locate/query/prepare/pgread/statx/fattr/clone
    ├─ brix_dispatch_write_opcode()         — open(write)/write/pgwrite/writev/sync/truncate/mkdir/rm/rmdir/mv/chmod/chkpoint
    └─ brix_dispatch_signing_opcode()       — sigver (must be last; inspects every request)

Each returns BRIX_DISPATCH_CONTINUE (= NGX_DECLINED) if not its opcode.
Unrecognised opcode falls through all → kXR_Unsupported.
```

**Key pattern:** `BRIX_DISPATCH_CONTINUE` is the pass-through signal. Each sub-dispatcher checks its opcode range, handles it or returns CONTINUE to the next level. This ordered chain ensures:
- Session opcodes (login/auth) execute before file-system opcodes
- Proxy mode intercepts all post-login ops before read/write dispatchers
- Signing enforcement runs before any opcode handler

### WebDAV Routing (`webdav/dispatch.c`)

WebDAV uses a simpler method-based routing: HTTP method → method handler. No phased chain — one dispatch function maps to 14 handlers (GET/PUT/MKCOL/DELETE/PROPFIND/SEARCH/PROPPATCH/ACL/COPY/MOVE/LOCK/UNLOCK/OPTIONS).

### S3 Routing (`s3/handler.c:5–47, operation_table.c`)

S3 uses path-style URI parsing → bucket+key extraction → HTTP method dispatch table. SigV4 verification runs before dispatch (INVARIANT #6: S3 SigV4 ≠ WLCG token — never share auth logic).

### Shared Mental Model

```
dispatch = ordered chain of category checkers, each returns CONTINUE or handles
```

**Barrier reduction:** The "ordered chain + CONTINUE" pattern is learnable once. WebDAV/S3 routing are simpler variants (method table, path parsing) that don't need to be memorized separately if the chain concept is understood first.

**Support burden reduction:** Adding a new opcode category requires only one addition to the dispatch chain — not three separate implementations across protocols.

---

## 3. Response Type Selection Logic (Common Layer)

### Current State

Each protocol builds responses differently:

| Protocol | Response Builder | Allocation Source | Wire Delivery |
|---|---|---|---|
| Stream | `response/` helpers (`basic.c`, `status.c`, `control.c`) | `ngx_palloc(c->pool)` / stack variables | `brix_queue_response()` → write chain drain via `connection/send.c` |
| WebDAV | HTTP headers + body buffers | `ngx_palloc(r->pool)` / `ngx_pcalloc` | `r->headers_out.status=X; r->headers_out.content_length_n=n; ngx_http_send_header(r); return ngx_http_output_filter(r,&chain);` |
| S3 | XML error via `brix_http_send_xml_error()` or file-backed sendfile | `ngx_palloc(r->pool)` | Same WebDAV pattern (HTTP output filter) |

**Response helpers in `response/` directory:**
- `basic.c`: `brix_build_resp_hdr`, `brix_send_ok`, `brix_send_error` — convenience wrappers for common cases
- `control.c`: `brix_send_redirect`, `brix_send_wait` — redirect and async-retry responses
- `crc32c.c`: `brix_crc32c` — wire-facing CRC32C API delegated to `compat/crc32c.c`
- `status.c`: `brix_send_pgwrite_status`, `brix_build/pgread_status` — kXR_status(4007) frames with per-page CRC32c

**INVARIANT #1 enforcement:** pgread/pgwrite require kXR_status(4007) framing + per-page CRC32c — implemented in `response/status.c`. Both functions follow identical structure: allocate from pool → set header fields (streamid, status, dlen via htons/htonl) → populate body → calculate CRC32c over body excluding crc field → store in network byte order.

### Shared Mental Model

```
build response = [allocate] → [set header] → [populate body] → [calculate checksum if required] → [queue/send]
```

**Barrier reduction:** The 5-step response pattern is universal. Stream responses use structured wire types; HTTP responses use headers + chain buffers — but the sequence is identical.

**Support burden reduction:** New opcode handlers only need to call the appropriate helper (`brix_send_ok`, `brix_build_resp_hdr`, etc.) rather than constructing wire frames manually.

---

## 4. Auth State Management (Common Layer)

### Current State

Auth state is stored in protocol-specific contexts but follows identical field layout:

**Stream auth state** (`src/core/types/context.h` — brix_ctx_t fields):
```
sessid                  — session identifier
logged_in               — login completed flag
auth_done               — authentication verified flag  
login_user[9]           — logged-in username (max 9 chars, grid-style)
login_pid               — login PID from client
auth_fail_count         — consecutive auth failures counter
dn[512]                 — GSI distinguished name
primary_vo[128]         — primary virtual organization
vo_list[512]            — VOMS attribute list (parsed by voms/extract.c/loader.c)
gsi_dh_key              — OpenSSL DH key pair (freed in disconnect.c)
sigver_mac_ctx          — request signing MAC context (freed in disconnect.c)
sigver_mac              — signing algorithm handle
bearer_token_state      — JWT bearer token validation state
```

**WebDAV auth state:** Stored per-request via `ngx_http_set_ctx(r, webdav_ctx, module)` pattern (`src/protocols/webdav/xrdhttp.c:56–71`). Retrieved per-request with `ngx_http_get_module_ctx`. Auth verified by `webdav_verify_proxy_cert()` or `webdav_verify_bearer_token()`.

**S3 auth state:** SigV4 canonical request construction in `auth_sigv4_canonical.c`, header parsing in `auth_sigv4_headers.c`, credential string parsing in `auth_sigv4_parse.c`, verification in `auth_sigv4_verify.c` (HMAC-SHA256 signing chain). Separate from WLCG token auth — never shared logic.

### Auth Gates (Common Layer)

Stream dispatch uses three gates (`handshake/policy.c`) before each opcode handler:
- `require_auth()` — check logged_in/auth_done flags
- `require_write()` — check conf->allow_write + token scope
- `require_login()` — check logged_in flag

WebDAV applies auth verification at entry point (before method dispatch). S3 runs SigV4 before dispatch.

### Shared Mental Model

```
authenticate = [verify credential] → [store identity in context] → [set flags: logged_in/auth_done] → [gate future ops with require_auth/require_write]
```

**Barrier reduction:** Auth state fields are identical across protocols (sessid, dn, vo_list, logged_in). New contributors learn one auth state layout and apply it everywhere.

**Support burden reduction:** Auth gate logic is centralized in `policy.c` for stream; WebDAV/S3 entry-point verification follows the same verify→store→gate pattern. Adding a new auth method requires only: (1) credential verifier function, (2) identity extraction into context fields, (3) flag setting — no opcode-specific changes needed.

---

## 5. Namespace Translation (Common Layer)

### Current State

Each protocol maps its URI to filesystem path differently but uses the same canonicalization helper:

| Protocol | Input Format | Translation Steps | Canonicalizer |
|---|---|---|---|
| Stream (`root://`) | `root://host//data/atlas/run3/file.root` | Strip `root://host/` prefix → extract path after double-slash | `brix_resolve_path_input(root, path, out, outsz)` (via `compat/path.h`) |
| WebDAV (`davs://`) | `/brix/data/atlas/run3/file.root` | Strip location prefix (`/brix/`) → prepend root_canon | `ngx_http_brix_webdav_resolve_path(path)` (via `webdav/path.c`) |
| S3 (`s3://`) | `/<bucket>/<key>` (path-style) | Strip leading slashes from key → prepend exactly "/" → call canonicalizer | `brix_resolve_path_input(root, key_path, out, outsz)` (via `s3/util.c:50–64`) |
| S3 multipart staging | `/<bucket>/.<key>.mpu-<id>/` | Strip bucket prefix → skip leading "/" then apply canonicalizer with ".." validation | Same as above (`s3/multipart_complete_upload_part_copy.c:10`) |

**INVARIANT #4 enforcement:** All wire paths → `resolve_path()` before `open()` — no exceptions. This is checked in dispatch_read/write handlers before calling open() on any path.

### Shared Mental Model

```
namespace = [strip protocol prefix] → [normalize leading slashes] → [call brix_resolve_path_input(root, normalized, out)] → [check escape/overflow]
```

**Barrier reduction:** `brix_resolve_path_input` is the universal canonicalizer — one function used by all three protocols. New contributors learn ONE path resolution function and understand how each protocol feeds it.

**Support burden reduction:** Path resolution changes (e.g., adding new confinement rules) touch only `compat/path.h`/the canonicalizer implementation, not 3 protocol handlers separately.

---

## 6. Proxy Handle Translation (Common Layer)

### Current State

Transparent XRootD proxy maintains a **file-handle translation map** (`src/net/proxy/proxy_internal.h`):

```c
proxy_fh_map entry struct:
    local_fh   — nginx-side file handle index (0–255, from fd_table.c)
    upstream_fh — opaque backend file handle (unknown to client)
    state      — FREE or 255-pending (lazy-open queue state)

proxy_up_state_t enum lifecycle states:
    connecting → TLS handshake → bootstrap → idle → forwarding
```

**Translation flow:**
1. Client sends `kXR_open(path)` → nginx opens local file, assigns handle index N
2. Proxy map entry[0–255] created with state=FREE (lazy-open) or 255-pending (queueing)
3. On first read/write: proxy connects upstream, opens same path on backend
4. Map entry updated: local_fh=N → upstream_fh=<opaque value>
5. All subsequent requests relay verbatim — handle translation applied at wire level

**INVARIANT #9:** Native TPC = SHM key registry (`src/tpc/engine/key_registry.c`) — cross-process, zero-copy. Proxy TPC uses the same fh_map for handle translation across proxy boundary.

### Shared Mental Model

```
proxy_handle = [local_fh assigned] → [map entry created with state FREE/pending] → [lazy-open on first data op] → [upstream_fh recorded] → [relay verbatim with local→upstream translation]
```

**Barrier reduction:** The fh_map[256] array pattern is learnable once. Proxy relay logic applies the same translation to every opcode — not per-opcode-specific handling.

**Support burden reduction:** Adding a new proxy opcode requires only: (1) case in dispatch_read/write, (2) apply handle translation at wire level. No upstream connection logic changes needed (already handled by lazy-open mechanism).

---

## 7. Lifecycle Hooks & Cleanup (Common Layer)

### Current State

Stream-layer cleanup uses **three-phase disconnect pattern** (`src/protocols/root/connection/disconnect.c:1–275`):

```
brix_on_disconnect() [main entry point]
    ├─ Phase 1: Resource release
    │   ├─ brix_upstream_cleanup(ctx->upstream)          — upstream connection teardown
    │   ├─ brix_proxy_cleanup(ctx->proxy)                — proxy fh_map, lazy-open queue cleanup
    │   ├─ brix_release_disconnect_owned_buffers()       — payload_buf, prepare_paths free
    │   └─ brix_release_disconnect_crypto_state()        — EVP_PKEY_free(gsi_dh_key), EVP_MAC_CTX/Free(sigver)
    ├─ Phase 2: Metrics finalization
    │   └─ brix_disconnect_update_metrics()              — decrement connections_active, accumulate bytes_rx_tx totals per IP version + protocol label
    └─ Phase 3: Access-log entries
        ├─ brix_disconnect_log_open_files()              — log every still-open handle as "interrupted" with throughput calc
        └─ brix_disconnect_format_session_detail()       — rx/tx MB/s breakdown or single aggregate → final access-log entry

Additional cleanup:
    - Dashboard transfer slot free: brix_transfer_slot_free_all_for_session(sessid)
    - Session registry unregistration: brix_session_unregister(ctx->sessid) (if auth_done && !is_bound)
```

**WebDAV/S3 cleanup:** Per-request ctx freed automatically by nginx pool destruction. No explicit disconnect handler needed — HTTP request lifecycle handles it.

### Shared Mental Model

```
cleanup = [release resources] → [finalize metrics] → [log access entries] → [unregister session if bound]
```

**Barrier reduction:** Three-phase pattern is learnable once. Each phase has a clear responsibility (resources, metrics, logging). New contributors understand what cleanup does without reading 275 lines of code.

**Support burden reduction:** Adding a new resource type to clean up requires only one addition to Phase 1 — no changes to Metrics or Logging phases. This is currently scattered across multiple files (buffers in disconnect.c, crypto in disconnect.c, upstream in upstream/lifecycle.c, proxy in proxy/connect_lifecycle.c). Consolidating all cleanup into the three-phase pattern reduces cognitive load.

---

## 8. Test Infrastructure Sharing (Common Layer)

### Current State

Test fixtures are shared across ALL protocol tests (`tests/conftest.py`):

| Fixture | Scope | Description |
|---|---|---|
| **LOCAL/REMOTE modes** | All protocols | LOCAL=default: regenerates PKI, seeds data, starts/stops servers automatically; REMOTE=TEST_SERVER_HOST=<host>: skips local lifecycle |
| **PKI generation** | Stream + WebDAV | Certificate and key generation for GSI auth (all protocol tests share same PKI) |
| **Server port definitions** | All protocols | NGINX_ANON_PORT, NGINX_GSI_PORT, NGINX_TLS_PORT, NGINX_TOKEN_PORT, NGINX_S3_PORT, NGINX_WEBDAV_PORT, PROXY_STD, REF_BRIX_PORT, TEST_XRDHTTP_HTTPS_PORT etc. |
| **Server lifecycle** | All protocols | `manage_test_servers.sh start|restart|stop` — single command starts all protocol servers |

### Shared Mental Model

```
test = [pick LOCAL/REMOTE mode] → [PKI generated once] → [all servers started by one command] → [protocol-specific tests run against shared infrastructure]
```

**Barrier reduction:** New contributors learn ONE test setup pattern (LOCAL mode) and apply it to all protocol tests. No per-protocol test setup to memorize.

**Support burden reduction:** Infrastructure changes (e.g., adding a new port, changing PKI format) touch only `conftest.py` — not individual test files across protocols.

---

## 9. Request Context Objects (Common Layer)

### Current State

Each protocol allocates context differently but stores identical auth state fields:

| Protocol | Allocation | Storage Location | Retrieval Pattern | Lifecycle |
|---|---|---|---|---|
| Stream (`root://`) | `ngx_alloc(sz, log)` on c->pool at connection accept | `brix_ctx_t` — per-connection session context with 60+ fields (auth state, file table[BRIX_MAX_FILES], write buffers, response scratch) | `ngx_stream_get_module_ctx(s, ngx_stream_brix_module)` | Connection lifecycle: alloc at accept → destroy on disconnect via three-phase cleanup |
| WebDAV (`davs://`) | `ngx_pcalloc(r->pool, sizeof(*b))` per request | `ngx_http_brix_webdav_req_ctx_t` — allocated via ngx_pcalloc on r->pool | `ngx_http_set_ctx(r, webdav_ctx, module)` → `ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module)` | Request lifecycle: alloc at entry → freed by nginx pool destruction |
| S3 | Per-request HTTP context | `r->ctx` set before body read (fs_path stored for async PUT callback) | `ngx_http_get_module_loc_conf(r, ngx_http_brix_s3_module)` for config access | Request lifecycle: same as WebDAV — freed by nginx pool destruction |

### Shared Mental Model

```
context = [allocate from request/connection pool] → [store protocol-specific fields + shared auth state] → [retrieve via get_module_ctx pattern] → [free on lifecycle end]
```

**Barrier reduction:** The `ngx_http_set_ctx/get_module_ctx` and `ngx_stream_get_module_ctx` retrieval patterns are identical across protocols. Auth state field layout (sessid, dn[512], vo_list[512]) is shared between stream WebDAV contexts — only S3 SigV4 adds its own credential fields.

**Support burden reduction:** Adding a new context field requires changes to ONE type definition (`types/context.h`) if it's auth state (shared), or per-protocol context struct if protocol-specific. Auth state changes propagate automatically across all protocols.

---

## 10. Metrics Export Pattern (Common Layer)

### Current State

Metrics use **low-cardinality labels only** (INVARIANT #8: no paths/bucket-names/UUIDs):

| Protocol | Metric Source | Label Schema | Callsite Pattern |
|---|---|---|---|
| Stream | `src/observability/metrics/stream.c` / `writer.c` | proto="root", op=opcode, status=ok/error | `BRIX_*_METRIC_INC(slot)` at callsite |
| WebDAV | `webdav/` metric helpers | proto="dav", op=HTTP method, status=ok/error | `webdav_metrics_return(status_bytes, proto)` for bytes; request counters via BRIX_* pattern |
| S3 | `src/observability/metrics/s3.c` (implied by s3.h metrics enum) | proto="s3", op=HTTP method, status=ok/error | `BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR])` on OOM; bytes via webdav_metrics_return equivalent |

**Shared metric zone:** Prometheus counters shared across all protocols in low-cardinality metrics zone. Labels: proto (root/dav/s3), op (opcode/HTTP method), status (ok/error). No per-file, per-user, or per-bucket label explosion.

### Shared Mental Model

```
metric = [increment at callsite] → [label with proto/op/status] → [export via /metrics HTTP endpoint]
```

**Barrier reduction:** `BRIX_*_METRIC_INC(slot)` pattern is universal across protocols — one macro, three call sites. New contributors learn the metric increment pattern once and apply it everywhere.

**Support burden reduction:** Adding a new metric slot requires: (1) enum addition in metrics.h, (2) field in metrics_internal.h, (3) export file in src/observability/metrics/, (4) callsite macro — no per-protocol changes needed.

---

## Summary of Architectural Sharing Opportunities

| Pattern | Current State | Sharing Opportunity | Impact |
|---|---|---|---|
| Request lifecycle phases | 3 separate lifecycles memorized | ONE shared lifecycle: accept→auth→parse→resolve→execute→respond→metric→cleanup | Barrier reduction: learn once, apply everywhere |
| Dispatch routing chain | Ordered chain (stream) + method table (WebDAV/S3) | Unified "category checker → CONTINUE or handle" pattern documented as mental model | Barrier reduction: understand the dispatch paradigm before protocol specifics |
| Response building sequence | Structured wire types (stream) vs HTTP headers+chain (WebDAV/S3) | 5-step universal pattern: allocate→header→body→checksum→queue/send | Barrier reduction: response construction is one algorithm with two output formats |
| Auth state field layout | Identical fields across stream/WebDAV contexts | Document shared auth state as canonical type definition in `types/context.h` | Support burden: new auth method touches ONE context struct, not 3 protocol handlers |
| Path resolution canonicalizer | `brix_resolve_path_input` used by all protocols | Already shared — document the universal pattern explicitly | Barrier reduction: learn ONE path function, understand how each protocol feeds it |
| Proxy handle translation map | fh_map[256] array with state enum (stream only) | Document as universal proxy pattern applicable to WebDAV proxy too | Support burden: new proxy opcode requires one addition + handle translation, not upstream logic changes |
| Three-phase disconnect cleanup | Stream: 275-line function; WebDAV/S3: nginx pool auto-free | Document three-phase pattern (release→metrics→log) as standard | Barrier reduction: understand cleanup structure without reading implementation details |
| Test fixture infrastructure | Shared conftest.py across all protocols | Already shared — document LOCAL/REMOTE mode as universal test entry point | Barrier reduction: learn one test setup, apply to all protocol tests |
| Context retrieval pattern | `set_ctx/get_module_ctx` identical across HTTP protocols | Document as standard nginx context lifecycle pattern | Support burden: new context field → types/context.h (auth) or per-protocol struct |
| Metric increment macro | `BRIX_*_METRIC_INC(slot)` universal across protocols | Already shared — document label schema and low-cardinality constraint | Barrier reduction: learn metric pattern once, apply everywhere |

---

## Comparison with v2

**v2 covered:** error response unification, path resolution consolidation, metrics wrappers, async PUT boilerplate, staged files, config consolidation, response bridge, XML verification, temp path, ETag.

**v3 covers (no overlap):** request lifecycle phases, dispatch routing chain, response type selection logic, auth state management layout, namespace translation steps, proxy handle translation maps, three-phase disconnect cleanup, test fixture infrastructure sharing, request context object patterns, metrics export label schema.

v2 = helper-function consolidation and boilerplate reduction. v3 = architectural pattern documentation and shared mental model creation. Together they address both implementation-level and understanding-level barriers to entry.

---

## Current State Assessment (as of 2026-05-27)

Before planning, audit what is already present to avoid duplicating existing documentation.

| v3 Section | Target file | Current state | Gap |
|---|---|---|---|
| §1 Request lifecycle | `docs/09-developer-guide/dev-workflow.md` (290 lines) | Has source layout table + build/test commands | No unified accept→auth→parse→resolve→execute→respond→metric→cleanup diagram |
| §2 Dispatch routing chain | `src/protocols/root/handshake/README.md` (54 lines) | Has full dispatch chain diagram with CONTINUE semantics | No cross-protocol comparison (WebDAV method table, S3 op table as simpler variants) |
| §3 Response type selection | `src/protocols/root/response/README.md` | Not audited — read first | Unknown |
| §4 Auth state management | `src/core/types/context.h` (273 lines) | Detailed WHAT/WHY/HOW block in header comment; auth fields grouped at lines 59–71 | No canonical "auth state layout" table; no cross-stream/WebDAV comparison note |
| §5 Namespace translation | `src/core/compat/README.md` | Lists `path.c` and `namespace_ops.c` | No cross-protocol namespace input → canonicalizer table |
| §6 Proxy handle translation | `src/net/proxy/README.md` (23 lines) | Sparse file table only | No fh_map lifecycle, state machine, lazy-open sequence |
| §7 Disconnect cleanup | `src/protocols/root/connection/disconnect.c` (275 lines) | Has `/* ---- Buffer release ----`, `/* ---- Crypto state release ----`, `/* brix_disconnect_update_metrics */`, `/* ---- Log open files ----` separators | Separators exist but are inconsistently named; no `connection/README.md` phase summary |
| §8 Test infrastructure | `docs/09-developer-guide/testing-runbook.md` (173 lines) | Has test philosophy + security policy | No LOCAL/REMOTE mode explanation, no conftest.py fixture hierarchy, no shared port table |
| §9 Request context objects | `src/core/types/README.md` (13 lines) | Minimal — file-to-concept table only | No set_ctx/get_module_ctx pattern, no stream vs HTTP context lifecycle comparison |
| §10 Metrics export pattern | `src/observability/metrics/README.md` (57 lines) | Has usage example | No label schema table, no low-cardinality constraint explanation, no "adding a metric" recipe |
| Capstone | `docs/11-architecture/cross-protocol-unification.md` (397 lines) | Has shared layer description + gap roadmap | v3 patterns (lifecycle phases, auth state layout, fh_map, disconnect phases) not yet synthesized into it |

---

## Implementation Plan

### Dependency Graph

```
Phase 0: Read all target files (no edits — verify current content)
         Mandatory before any other phase; 2 h

Phase 1: Source-adjacent documentation (5 parallel tasks — different files, no ordering)
         ├── T1: src/core/types/context.h          — auth state layout table          (2 h)
         ├── T2: src/protocols/root/handshake/README.md       — cross-protocol dispatch section  (1 h)
         ├── T3: src/protocols/root/connection/disconnect.c   — standardize phase separators     (1 h)
         │         src/protocols/root/connection/README.md    — three-phase cleanup pattern      (+30 min)
         ├── T4: src/net/proxy/README.md           — fh_map lifecycle expansion       (1.5 h)
         └── T5: src/observability/metrics/README.md         — label schema + low-cardinality   (1 h)

Phase 2: Higher-level developer docs (4 parallel tasks — blocked by Phase 1 for cross-refs)
         ├── T6: docs/09-developer-guide/dev-workflow.md    — lifecycle diagram section  (2 h)
         │         [references T1 auth state, T2 dispatch chain]
         ├── T7: docs/09-developer-guide/testing-runbook.md — LOCAL/REMOTE + conftest.py (1 h)
         │         [references T5 metrics port definitions]
         ├── T8: src/core/compat/README.md          — namespace translation section    (1 h)
         │         [references T1 path.c fields in context.h]
         └── T9: src/core/types/README.md           — set_ctx pattern + lifecycle      (1 h)
                   [blocked by T1 — references auth state layout added in T1]

Phase 3: Capstone architecture doc (blocked by all of Phase 1 + Phase 2)
         └── T10: docs/11-architecture/cross-protocol-unification.md  (3 h)
                   [synthesizes T1–T9 into one unified view]
```

---

### Phase 0 — Prerequisite Reads (2 h)

**No edits.** Read each target file fully and note exact section boundaries before writing anything. This prevents duplication and ensures cross-references are accurate.

| File to read | Why | Expected size |
|---|---|---|
| `src/core/types/context.h` | Identify exact line numbers of auth state fields (sessid, logged_in, auth_done, dn, vo_list) before adding the layout table | 273 lines |
| `src/protocols/root/handshake/README.md` | Find the exact end of the dispatch chain diagram to know where to append the cross-protocol comparison section | 54 lines |
| `src/protocols/root/connection/disconnect.c` | Map existing section separators; find exact line numbers of buffer/crypto/metrics/log phases to standardize | 275 lines |
| `src/net/proxy/README.md` | Identify the 23 existing lines; plan expansion without repeating the file table | 23 lines |
| `src/observability/metrics/README.md` | Find where the label schema section should be inserted relative to existing usage example | 57 lines |
| `src/protocols/root/response/README.md` | Check whether the 5-step response pattern (§3) is already documented | unknown |
| `docs/09-developer-guide/dev-workflow.md` | Find the source layout table position to insert lifecycle diagram immediately after | 290 lines |
| `docs/09-developer-guide/testing-runbook.md` | Find the test philosophy section end — lifecycle diagram inserts before it | 173 lines |
| `src/core/types/README.md` | Understand the 13 lines present; plan expansion without duplicating the file-to-concept table | 13 lines |
| `docs/11-architecture/cross-protocol-unification.md` | Understand current 397-line structure — plan v3 additions without redundancy | 397 lines |

**Done-when:** Annotated notes on each file's current state; no ambiguity about where each task's additions land.

---

### Phase 1 — Source-Adjacent Documentation (6 h total, all tasks parallel)

Each task touches a different file. No build required for `.md` tasks. `disconnect.c` changes are comment-only and require a compile verification.

---

#### T1: Auth State Layout Table in `src/core/types/context.h` (2 h)

**Goal:** Add a self-contained "Auth State Layout" table in the context.h header comment so contributors understand what fields are set at each authentication phase without reading the full 273-line struct.

**Blocked by:** Phase 0 read of `context.h`.

**Verification before editing:** Confirm auth fields are at lines 59–71 per the HOW comment layout. Check for `sessid`, `logged_in`, `auth_done`, `login_user`, `login_pid`, `auth_fail_count`, `dn`, `primary_vo`, `vo_list`, `peer_ip` as the canonical set.

**Content to add** (at the top of the file's WHAT comment block, after the existing one-sentence overview):

```
 * Auth state layout — fields populated at each phase:
 *
 *   Phase          | Field set              | Trigger
 *   ───────────────────────────────────────────────────────
 *   kXR_login      | sessid, logged_in=1    | server issues session ID + challenge
 *                  | login_user, login_pid  | client-supplied values from login body
 *   kXR_auth(GSI)  | auth_done=1            | DH exchange + cert chain validation OK
 *                  | dn[512]                | GSI subject DN from peer certificate
 *                  | primary_vo, vo_list    | VOMS extensions (if libvomsapi present)
 *   kXR_auth(token)| auth_done=1            | JWT signature + scope verified
 *                  | token_auth=1           | distinguishes token from GSI auth path
 *                  | token_scopes[]         | parsed WLCG scope strings
 *   brix_auth=none| auth_done=1 immediately after logged_in=1
 *
 * Cross-protocol note: WebDAV/S3 have no persisted auth state — they re-verify
 * credentials on every request via webdav_verify_proxy_cert() / SigV4 chain.
 * The fields above are stream-only (per-connection context, not per-request).
```

**File modified:** `src/core/types/context.h`
**Lines added:** ~18
**Lines removed:** 0
**Compile check:** Not required (comment-only) but run `make -j$(nproc)` once to confirm no accidental edit truncated a field definition.

---

#### T2: Cross-Protocol Dispatch Comparison in `src/protocols/root/handshake/README.md` (1 h)

**Goal:** The existing 54-line README documents the stream dispatch chain thoroughly. Add a "Cross-Protocol Dispatch Pattern" section below the existing diagram showing how WebDAV and S3 implement simpler variants of the same CONTINUE/handle paradigm.

**Blocked by:** Phase 0 read of `handshake/README.md`.

**What to add** (append after line 54):

```markdown
## Cross-Protocol Dispatch Pattern

The stream 5-phase chain is the most complex variant of a pattern used in all three protocols:

| Protocol | Dispatch mechanism | CONTINUE equivalent | Auth gate |
|---|---|---|---|
| Stream (`root://`) | Ordered sub-dispatcher chain; each returns `BRIX_DISPATCH_CONTINUE` (`NGX_DECLINED`) if not its opcode | `BRIX_DISPATCH_CONTINUE` | `require_auth()` / `require_write()` in `policy.c` before every handler |
| WebDAV (`davs://`) | HTTP method → method handler table in `dispatch.c`; unknown method returns `NGX_HTTP_NOT_ALLOWED` | `NGX_DECLINED` from nginx core | Auth verified at `dispatch.c` entry before method routing |
| S3 | Path-style URI → bucket+key extraction → HTTP method dispatch table in `handler.c` + `operation_table.c` | `NGX_DECLINED` from nginx core | SigV4 canonical request verified before dispatch (never shared with WLCG token logic) |

**Mental model:** All three protocols use "category checker → CONTINUE or handle." Stream needs multiple categories (session, read, write, signing) because opcodes carry state across requests in the same connection. WebDAV and S3 are stateless per-request, so a single-level method table suffices.

**Adding a new category to stream dispatch:**
1. Add a new `brix_dispatch_<category>_opcode()` function in a new `dispatch_<category>.c`
2. Add the call between existing dispatchers in `dispatch.c` — respect ordering (session < proxy < read < write < signing)
3. Add gate calls via `policy.c` helpers before each new handler
4. Register new `.c` in `src/core/config/config.h` under `NGX_ADDON_SRCS`
```

**File modified:** `src/protocols/root/handshake/README.md`
**Lines added:** ~28
**Lines removed:** 0

---

#### T3: Standardize Disconnect Phase Separators in `src/protocols/root/connection/disconnect.c` + `connection/README.md` (1.5 h)

**Goal:** The four existing separators (`/* ---- Buffer release ----`, `/* ---- Crypto state release ----`, etc.) use inconsistent formatting and unnamed phase numbers. Standardize to `/* === Phase N: <name> === */` blocks so the three-phase mental model is immediately scannable.

**Blocked by:** Phase 0 read of `disconnect.c` (must confirm exact line numbers of each separator).

**Changes to `disconnect.c`:**

| Current separator | Replacement | Approximate line |
|---|---|---|
| `/* ---- Buffer release helper — disconnect-owned payload cleanup ----` | `/* === Phase 1A: Buffer release — payload_buf + prepare_paths ===` | ~11 |
| `/* ---- Crypto state release — GSI/sigver cleanup on disconnect ----` | `/* === Phase 1B: Crypto state release — EVP_PKEY/EVP_MAC cleanup ===` | ~36 |
| *(metrics function header, currently inline WHAT comment)* | Add `/* === Phase 2: Metrics finalization — connections_active + bytes totals ===` | ~65 |
| `/* ---- Log open files — access-log entries for all handles at disconnect ----` | `/* === Phase 3A: Access log — interrupted file handles ===` | ~130 |
| *(session detail format — if present below line 130)* | Add `/* === Phase 3B: Access log — session totals + throughput ===` | ~variable |

**Changes to `src/protocols/root/connection/README.md`:**

Append a new "Disconnect phases" section after the existing file table:

```markdown
## Disconnect phases

`disconnect.c` follows a three-phase teardown pattern. New resource types must be added in Phase 1; never skip to Phase 2 or 3.

**Phase 1 — Resource release** (`brix_release_disconnect_owned_buffers`, `brix_release_disconnect_crypto_state`, upstream cleanup, proxy cleanup)
- Free all heap and pool resources: payload_buf, prepare_paths, EVP_PKEY (GSI DH key), EVP_MAC_CTX (sigver HMAC)
- Called before metrics so that resource-free latency does not skew byte totals

**Phase 2 — Metrics finalization** (`brix_disconnect_update_metrics`)
- Decrement `connections_active`; accumulate `bytes_rx_total` / `bytes_tx_total` split by IPv4/IPv6 and protocol label
- Only safe to call after resource release (uses ctx->metrics pointer; do not call if ctx->metrics == NULL)

**Phase 3 — Access log** (`brix_disconnect_log_open_files`, `brix_disconnect_format_session_detail`)
- Emit one access-log entry per still-open file handle (status = "interrupted")
- Emit final session-level access-log entry with rx/tx MB/s throughput calculation
```

**Files modified:** `src/protocols/root/connection/disconnect.c`, `src/protocols/root/connection/README.md`
**Lines added in disconnect.c:** ~5 (comment blocks only)
**Lines added in README.md:** ~22
**Compile check (mandatory):** `make -j$(nproc)` — confirm C file is syntactically valid after comment edits.

---

#### T4: Proxy fh_map Lifecycle Expansion in `src/net/proxy/README.md` (1.5 h)

**Goal:** Expand the sparse 23-line file table into a complete reference covering the fh_map[256] state machine, lazy-open sequence, upstream_fh translation, and the relationship to WebDAV proxy (`src/protocols/webdav/proxy.c`).

**Blocked by:** Phase 0 read of `proxy/README.md` and `proxy/proxy_internal.h` (272 lines — the fh_map struct definition lives here).

**Content to add:**

```markdown
## Handle translation map

The proxy maintains a `fh_map[256]` array (one entry per possible XRootD file handle, indices 0–255):

```c
/* proxy_fh_map entry — defined in proxy_internal.h */
struct {
    uint8_t    local_fh;      /* nginx-side handle index (0–255, from fd_table.c) */
    uint32_t   upstream_fh;   /* opaque backend handle (unknown format to client) */
    uint8_t    state;         /* FREE | PENDING_OPEN | MAPPED */
} fh_map[256];
```

**Lifecycle:**

```
kXR_open(path) received from client
    → local_fh assigned from fd_table.c (index 0–255)
    → fh_map[local_fh].state = PENDING_OPEN
    → nginx responds to client with local_fh immediately

First read/write for that handle:
    → lazy upstream connect (connect_lifecycle.c)
    → send kXR_open(path) to backend
    → backend responds with upstream_fh (opaque value)
    → fh_map[local_fh].upstream_fh = upstream_fh
    → fh_map[local_fh].state = MAPPED

All subsequent opcodes carrying local_fh:
    → forward_rewrite_helpers.c substitutes upstream_fh in wire frame
    → relay verbatim via forward_relay.c
    → response substitutes upstream_fh back to local_fh for client

kXR_close(local_fh):
    → send kXR_close(upstream_fh) to backend
    → fh_map[local_fh].state = FREE
```

**Upstream state machine** (from `proxy_internal.h`):

```
connecting → tls_handshake → bootstrap_protocol → idle → forwarding
```

Each state gate is checked in `events_*.c` before processing read/write events.

## WebDAV proxy relationship

`src/protocols/webdav/proxy.c` implements HTTP-level forwarding (WebDAV → backend HTTP/HTTPS). It does **not** use `fh_map` because HTTP requests are stateless — each request carries a full URI, not a handle. Handle translation is a stream-protocol-only concept driven by XRootD's stateful session model.
```

**File modified:** `src/net/proxy/README.md`
**Lines added:** ~60
**Lines removed:** 0

---

#### T5: Label Schema Section in `src/observability/metrics/README.md` (1 h)

**Goal:** Add a label schema table documenting the `proto/op/status` label set, the low-cardinality constraint (INVARIANT #8), examples of compliant vs non-compliant labels, and the recipe for adding a new metric slot.

**Blocked by:** Phase 0 read of `metrics/README.md` and `src/observability/metrics/metrics_macros.h` (to confirm actual label names used by `BRIX_*_METRIC_INC`).

**Content to add:**

```markdown
## Label schema

All Prometheus counters exported by this module use a **fixed, low-cardinality** label set:

| Label | Values | Notes |
|---|---|---|
| `proto` | `root`, `dav`, `s3` | Protocol layer; never per-user or per-bucket |
| `op` | opcode name (`open`, `read`, `put`, etc.) or HTTP method | Set at dispatch time; never includes path |
| `status` | `ok`, `error` | Binary outcome; never HTTP status codes as labels |

**INVARIANT #8 (non-negotiable):** Labels must be low-cardinality. Never add a label whose value space is unbounded or path/user/bucket dependent. The shared-memory metric zone has a fixed slot count; high-cardinality labels cause counter explosion that silently overwrites slots.

**Compliant:**
```
brix_requests_total{proto="root", op="read", status="ok"}
```

**Non-compliant (will be rejected in review):**
```
brix_requests_total{proto="root", op="read", path="/data/atlas/..."}  # path is high-cardinality
brix_requests_total{proto="s3", bucket="cms-xrd-global"}              # bucket is high-cardinality
```

## Adding a new metric slot

1. Add enum entry to `metrics/metrics.h` (e.g., `BRIX_METRIC_MY_COUNTER`)
2. Add field to `metrics/metrics_internal.h` shared-memory struct
3. Add export line to the appropriate `metrics/<proto>.c` file
4. Increment at callsite: `BRIX_SRV_METRIC_INC(my_counter)` (stream), `BRIX_WEBDAV_METRIC_INC(my_counter)` (WebDAV), `BRIX_S3_METRIC_INC(my_counter)` (S3)
5. No `./configure` needed; `make -j$(nproc)` is sufficient

No per-protocol changes needed for metric schema changes — the macro selects the correct shared-memory slot automatically.
```

**Files to read first:** `src/observability/metrics/metrics_macros.h`, `src/observability/metrics/metrics.h`, `src/observability/metrics/metrics_internal.h`
**File modified:** `src/observability/metrics/README.md`
**Lines added:** ~45
**Lines removed:** 0

---

### Phase 2 — Higher-Level Developer Docs (5 h total, tasks parallel within phase)

These tasks write to `docs/` and `src/*/README.md` files that synthesize the Phase 1 source-adjacent documentation. Start only after Phase 1 is complete so cross-references are accurate.

---

#### T6: Unified Request Lifecycle in `docs/09-developer-guide/dev-workflow.md` (2 h)

**Goal:** Add a per-phase table showing which source file handles each lifecycle step for each protocol, immediately after the existing source layout table in `dev-workflow.md`.

**Blocked by:** T1 (auth state phases), T2 (dispatch chain sections).

**Content to add** (target: after the source layout table, before the build commands):

```markdown
## Request lifecycle

Every request follows the same 8-phase lifecycle regardless of protocol. Protocol-specific
files handle each phase; the common layer (`src/core/compat/`) provides shared utilities for
cross-cutting concerns.

| Phase | Stream (`root://`) | WebDAV (`davs://`) | S3 |
|---|---|---|---|
| **Accept** | `connection/handler.c` allocates `brix_ctx_t` on `c->pool`; arms read event | `webdav/module.c` location handler entry | `s3/module.c` location handler entry |
| **Authenticate** | `handshake/dispatch_session.c` → `session/login.c` → `gsi/`, `token/`, `sss/` | `webdav/auth_cert.c` (GSI proxy) or `auth_token.c` (WLCG JWT) — verified per-request | `s3/auth_sigv4_verify.c` (HMAC-SHA256 canonical request) — never shares WLCG token logic |
| **Parse** | `connection/recv.c` frames 24-byte fixed header + variable body; `cur_streamid/reqid/dlen` in `brix_ctx_t` | nginx core parses HTTP method + URI; `webdav/dispatch.c` routes by method | `s3/handler.c` strips path-style URI → bucket + key |
| **Resolve** | All wire paths → `brix_resolve_path_input(root, path, out)` before `open()` — INVARIANT #4 | `webdav/path.c`: `webdav_resolve_path(r, root_canon, path)` → URI decode + strip → shared canonicalizer | `s3/util.c`: `s3_resolve_key(root, key, out)` → strip slashes → shared canonicalizer |
| **Execute** | Sub-dispatcher chain (`handshake/dispatch.c` → session/read/write/signing); each handler in `src/<subsystem>/` | Method handler: `webdav/get.c`, `put.c`, `propfind.c`, `copy.c`, etc. | Operation table in `s3/handler.c`; body async via `ngx_http_read_client_request_body()` |
| **Respond** | `response/` helpers: `brix_send_ok()`, `brix_build_resp_hdr()`, kXR_status framing; queued to write chain via `connection/send.c` | Build `ngx_chain_t` of `ngx_buf_t`; `ngx_http_send_header(r)` + `ngx_http_output_filter(r, &chain)` | Same as WebDAV for errors (XML); file-backed sendfile for GET body |
| **Metric** | `BRIX_SRV_METRIC_INC(slot)` at callsite; bytes via `session_bytes_*` fields accumulated to disconnect | `BRIX_WEBDAV_METRIC_INC(slot)` at callsite | `BRIX_S3_METRIC_INC(slot)` at callsite |
| **Cleanup** | `connection/disconnect.c` three-phase: release resources → finalize metrics → write access log | nginx pool destruction frees per-request `ngx_http_brix_webdav_req_ctx_t` automatically | nginx pool destruction frees per-request context automatically |

**Key invariant:** The Resolve phase runs before Execute for **every** opcode in all three protocols. Path confinement (`brix_resolve_path_input`) is the single security boundary between the protocol handler and the filesystem. See INVARIANTS #4 in `CLAUDE.md`.
```

**Files modified:** `docs/09-developer-guide/dev-workflow.md`
**Lines added:** ~30
**Lines removed:** 0

---

#### T7: LOCAL/REMOTE Mode + Fixture Hierarchy in `docs/09-developer-guide/testing-runbook.md` (1 h)

**Goal:** Add a "Test environment modes" section explaining LOCAL vs REMOTE, the shared conftest.py fixture hierarchy, the port allocation table, and when to use `manage_test_servers.sh` vs pytest-direct.

**Blocked by:** T5 (metrics port definitions), Phase 0 read of `testing-runbook.md`.

**Verification before editing:** grep `conftest.py` for `TEST_SERVER_HOST`, `REMOTE`, `LOCAL`, `NGINX_*_PORT` to get exact variable names before writing the table.

```bash
grep -n "TEST_SERVER_HOST\|REMOTE\|LOCAL\|NGINX.*PORT\|fixture\|scope=" \
    tests/conftest.py | head -40
```

**Content to add** (prepend to runbook, before "Test Philosophy"):

```markdown
## Test environment modes

All tests support two mutually exclusive modes controlled by environment variables:

| Mode | Trigger | Behavior |
|---|---|---|
| **LOCAL** (default) | `TEST_SERVER_HOST` not set | Regenerates PKI, seeds test data, starts all servers automatically via `manage_test_servers.sh start`; stops them after the session |
| **REMOTE** | `export TEST_SERVER_HOST=<host>` | Skips local server lifecycle; connects to a running server on the given host; PKI and data must already be in place |

**LOCAL mode entry point:**
```bash
# Start once manually (needed if running test subsets):
tests/manage_test_servers.sh start

# Or let pytest do it:
PYTHONPATH=tests pytest tests/ -v
```

## conftest.py fixture hierarchy

`tests/conftest.py` provides session-scoped fixtures shared by all protocol tests:

| Fixture | Scope | Description |
|---|---|---|
| `pki` | session | Generates CA, proxy cert, VOMS proxy, JWKS keypair into `tests/pki/` — runs once per pytest session |
| `servers` | session | Calls `manage_test_servers.sh start` in LOCAL mode; no-op in REMOTE mode |
| `nginx_anon_port` | session | Port for unauthenticated XRootD (default 11094) |
| `nginx_gsi_port` | session | Port for GSI-authenticated XRootD (default 11095) |
| `nginx_tls_port` | session | Port for TLS XRootD (default 11096) |
| `nginx_token_port` | session | Port for token-authenticated XRootD (default 11097) |
| `nginx_webdav_port` | session | Port for WebDAV HTTPS (default 8443) |
| `nginx_s3_port` | session | Port for S3 REST (default 9001) |
| `nginx_metrics_port` | session | Port for Prometheus /metrics (default 9100) |

All fixtures are available to every test file without explicit import — pytest discovers them via conftest.py automatically.
```

**Files modified:** `docs/09-developer-guide/testing-runbook.md`
**Lines added:** ~50
**Lines removed:** 0

---

#### T8: Namespace Translation Cross-Protocol Section in `src/core/compat/README.md` (1 h)

**Goal:** Add a "Cross-protocol namespace translation" section that makes explicit how each protocol's URI format is preprocessed before reaching `brix_resolve_path_input()` — the universal canonicalizer that lives in this directory.

**Blocked by:** Phase 0 read of `compat/README.md`; T1 for path field context.

**Content to add** (after the `path.c` entry in the file table):

```markdown
## Cross-protocol namespace translation

`path.c` provides `brix_resolve_path_input(root, normalized_path, out, outsz)` — the
universal canonicalizer used by all three protocols. Each protocol preprocesses its URI
format before calling it:

| Protocol | URI example | Preprocessing steps | Canonicalizer call |
|---|---|---|---|
| Stream (`root://`) | `root://host//data/atlas/run3/f.root` | Strip `root://host/` prefix; extract path after double-slash | `brix_resolve_path_input(root_canon, path, out, outsz)` |
| WebDAV (`davs://`) | `/brix/data/atlas/run3/f.root` | URI-percent-decode; strip location prefix (`/brix/`); strip trailing slashes | `brix_resolve_path_input(root_canon, decoded_path, out, outsz)` via `webdav/path.c` |
| S3 path-style | `/<bucket>/<key>` | Strip bucket prefix; normalize key: strip leading slashes; prepend exactly `/` | `brix_resolve_path_input(root_canon, key_path, out, outsz)` via `s3/util.c` |
| S3 multipart stage | `/<bucket>/.<key>.mpu-<id>/` | Same as above; additional `.mpu-<id>` suffix preserved through canonicalization | Same |

**INVARIANT #4:** `resolve_path` runs before any `open()` call — no exceptions. The canonicalizer rejects path traversal (`..`), symlink escape, and paths that would exceed the confinement root. Do not pass user-controlled paths to any filesystem call before this step.

**Adding a new protocol:** implement the preprocessing steps above as a wrapper function in your protocol's source directory; call `brix_resolve_path_input` as the final step. Never reimplement confinement logic — only the URI → normalized_path step is protocol-specific.
```

**File modified:** `src/core/compat/README.md`
**Lines added:** ~30
**Lines removed:** 0

---

#### T9: Context Retrieval Pattern in `src/core/types/README.md` (1 h)

**Goal:** Expand the 13-line README to document the set_ctx/get_module_ctx pattern used by all HTTP protocols, the stream variant, and the lifecycle differences between per-connection and per-request contexts.

**Blocked by:** T1 (auth state layout in context.h must exist before README references it).

**Content to add** (replace the existing 13-line file with a full reference):

```markdown
# src/core/types — Core type definitions

Focused sub-headers extracted from `ngx_brix_module.h`. Each file defines exactly one
concept so contributors can read just the relevant type without wading through the full
umbrella header.

Do not include these files before nginx, OpenSSL, protocol, metrics, and token headers.

| File | Contents |
|---|---|
| `tunables.h` | `BRIX_*` size/count limits, auth-mode constants, SSS constants, `BRIX_OP_OK/ERR` metric macros, `BRIX_RETURN_OK/ERR` convenience macros |
| `state.h` | `brix_state_t` enum (per-connection state machine), opaque forward declarations for upstream and CMS contexts |
| `file.h` | `brix_file_t` — per-open-file bookkeeping; array index = XRootD file handle |
| `context.h` | `brix_ctx_t` — per-connection context with all session, auth, I/O, and signing state |
| `config.h` | `ngx_stream_brix_srv_conf_t` — per-server configuration struct and its helper types (`brix_sss_key_t`, `brix_vo_rule_t`, `brix_group_rule_t`, `brix_manager_map_t`) |

## Context retrieval patterns

Each protocol allocates and retrieves its request/connection context differently:

| Protocol | Context struct | Allocation | Storage | Retrieval | Lifecycle |
|---|---|---|---|---|---|
| Stream (`root://`) | `brix_ctx_t` (273 lines, 60+ fields) | `ngx_alloc(sz, log)` at connection accept | Module context on `ngx_connection_t` | `ngx_stream_get_module_ctx(s, ngx_stream_brix_module)` | Per-connection: alloc at accept, freed by three-phase `disconnect.c` |
| WebDAV (`davs://`) | `ngx_http_brix_webdav_req_ctx_t` | `ngx_pcalloc(r->pool, sizeof(*ctx))` at dispatch entry | `ngx_http_set_ctx(r, ctx, ngx_http_brix_webdav_module)` | `ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module)` | Per-request: freed automatically by nginx pool destruction |
| S3 | `u_char *fs_path` (minimal — just the resolved path) | `ngx_palloc(r->pool, PATH_MAX)` before body read | `ngx_http_set_ctx(r, fs_path, ngx_http_brix_s3_module)` | `ngx_http_get_module_ctx(r, ngx_http_brix_s3_module)` | Per-request: freed automatically by nginx pool destruction |

**Key difference:** Stream context is per-connection and persists auth state across multiple opcodes in the same session. WebDAV/S3 contexts are per-request — auth is re-verified on every request because HTTP is stateless. The `brix_ctx_t` auth state layout (see `context.h` header comment) does not apply to WebDAV/S3 contexts.

**Rule:** Allocate from `r->pool` (HTTP) or `c->pool` / `ngx_alloc` (stream). Never use `malloc` or raw `mmap` for request/connection state — lifecycle management is the pool's responsibility.
```

**File modified:** `src/core/types/README.md`
**Lines added:** ~45 (replaces existing 13 lines)
**Lines removed:** 13 (existing content preserved verbatim as the file table section)

---

### Phase 3 — Capstone Architecture Doc (3 h)

#### T10: Update `docs/11-architecture/cross-protocol-unification.md` with v3 Patterns (3 h)

**Goal:** The existing 397-line doc covers shared infrastructure and the gap roadmap. Extend it with the v3 architectural patterns as a new "Shared Mental Models" section, without repeating content from the existing "layers not silos" framing.

**Blocked by:** All of Phase 1 + Phase 2. T10 cross-references T1–T9 throughout.

**Prerequisite read:** The full 397-line file. Identify the exact insertion point (likely after the existing "Mental model: layers not silos" section and before the gap roadmap), and confirm which v3 patterns are not already covered.

**Content to add** — a new top-level section:

```markdown
## Shared mental models (v3)

The following patterns appear in every protocol layer. A contributor who internalizes
these models can navigate any of the three protocol implementations without starting
from scratch.

### 1. Request lifecycle (8 phases)

accept → authenticate → parse → resolve → execute → respond → metric → cleanup

See `docs/09-developer-guide/dev-workflow.md` §Request lifecycle for the per-protocol file mapping.
The Resolve phase (path canonicalization via `src/core/compat/path.c`) is mandatory before any
filesystem call in all three protocols — INVARIANT #4.

### 2. Dispatch: ordered chain of category checkers

Each protocol dispatch returns CONTINUE (= `NGX_DECLINED`) if the current request is not its
responsibility, or handles it and returns a terminal status:
- **Stream:** 5-phase chain (session → proxy-gate → read → write → signing) in `handshake/dispatch.c`
- **WebDAV:** method table (GET/PUT/MKCOL/DELETE/…) in `webdav/dispatch.c`
- **S3:** path-style URI → operation table in `s3/handler.c`

See `src/protocols/root/handshake/README.md` §Cross-Protocol Dispatch Pattern.

### 3. Auth state (stream only — per-connection)

Stream auth is stateful across opcodes in one session. Auth fields are populated in two phases:
- `kXR_login` → `sessid`, `logged_in`, `login_user`, `login_pid`
- `kXR_auth` → `auth_done`, `dn`, `primary_vo`, `vo_list` (GSI) or `token_auth`, `token_scopes` (JWT)

WebDAV and S3 re-verify credentials on every request — no persisted auth state.
See `src/core/types/context.h` §Auth State Layout for the canonical field table.

### 4. Namespace translation

All three protocols use `brix_resolve_path_input(root_canon, normalized, out, outsz)` as
the final confinement step. Only the pre-processing (URI format → normalized path) is
protocol-specific. See `src/core/compat/README.md` §Cross-protocol namespace translation.

### 5. Proxy handle translation (stream proxy only)

`fh_map[256]` maps local_fh (nginx-side, 0–255) → upstream_fh (opaque backend handle).
State machine: FREE → PENDING_OPEN → MAPPED. Lazy upstream connect on first data opcode.
See `src/net/proxy/README.md` §Handle translation map.

### 6. Disconnect cleanup (stream only — 3 phases)

Phase 1 (resource release) → Phase 2 (metrics finalization) → Phase 3 (access log).
All resource cleanup goes in Phase 1; never skip ahead. Implemented in `connection/disconnect.c`.
See `src/protocols/root/connection/README.md` §Disconnect phases.

### 7. Context allocation

| Protocol | Pool | Pattern |
|---|---|---|
| Stream | `c->pool` / `ngx_alloc` | `ngx_stream_get_module_ctx` |
| WebDAV | `r->pool` + `ngx_http_set_ctx` | `ngx_http_get_module_ctx` |
| S3 | `r->pool` + `ngx_http_set_ctx` | `ngx_http_get_module_ctx` |

See `src/core/types/README.md` §Context retrieval patterns.

### 8. Metric increment

One macro per protocol: `BRIX_SRV_METRIC_INC(slot)` (stream), `BRIX_WEBDAV_METRIC_INC(slot)` (WebDAV), `BRIX_S3_METRIC_INC(slot)` (S3). Labels: proto/op/status — always low-cardinality. See `src/observability/metrics/README.md` §Label schema.
```

**File modified:** `docs/11-architecture/cross-protocol-unification.md`
**Lines added:** ~80
**Lines removed:** 0

---

### Summary Table

| Task | Phase | Est. (h) | Blocked by | Files modified | Lines added | Lines removed | Code compile needed? |
|---|---|---|---|---|---|---|---|
| Phase 0: Reads | 0 | 2 | — | 0 (read-only) | 0 | 0 | No |
| T1: context.h auth layout table | 1 | 2 | Phase 0 | `src/core/types/context.h` | ~18 | 0 | Verify (comment-only) |
| T2: handshake dispatch comparison | 1 | 1 | Phase 0 | `src/protocols/root/handshake/README.md` | ~28 | 0 | No |
| T3: disconnect phase separators | 1 | 1.5 | Phase 0 | `src/protocols/root/connection/disconnect.c`, `src/protocols/root/connection/README.md` | ~27 | 0 | **Yes — mandatory** |
| T4: proxy fh_map expansion | 1 | 1.5 | Phase 0 | `src/net/proxy/README.md` | ~60 | 0 | No |
| T5: metrics label schema | 1 | 1 | Phase 0 | `src/observability/metrics/README.md` | ~45 | 0 | No |
| T6: lifecycle diagram in dev-workflow | 2 | 2 | T1, T2 | `docs/09-developer-guide/dev-workflow.md` | ~30 | 0 | No |
| T7: LOCAL/REMOTE + conftest.py | 2 | 1 | T5, Phase 0 | `docs/09-developer-guide/testing-runbook.md` | ~50 | 0 | No |
| T8: namespace translation in compat | 2 | 1 | T1, Phase 0 | `src/core/compat/README.md` | ~30 | 0 | No |
| T9: types/README.md context pattern | 2 | 1 | T1 | `src/core/types/README.md` | ~45 | 13 | No |
| T10: cross-protocol-unification capstone | 3 | 3 | T1–T9 | `docs/11-architecture/cross-protocol-unification.md` | ~80 | 0 | No |

**Total estimate: ~16 h (~2 engineer-days)**
**Total files touched: 10 source + doc files**
**Total lines added: ~413**
**Total lines removed: ~13 (types/README.md replacement)**
**Only code file edited with non-comment change: none** — `disconnect.c` receives comment-only additions; verify with `make -j$(nproc)`.

---

### Verification Checklist

After all tasks complete, run these checks before marking the plan done:

```bash
# 1. Build still passes (disconnect.c comment edits must not corrupt C syntax)
make -j$(nproc) 2>&1 | grep -E "error:|warning:" | head -20

# 2. Cross-references in T10 capstone point to real sections
grep -n "§" docs/11-architecture/cross-protocol-unification.md | while read line; do
    echo "$line"
done

# 3. No forward-references in Phase 1 docs (they must not reference T6–T10 content)
grep -n "dev-workflow\|testing-runbook\|cross-protocol-unification" \
    src/core/types/context.h src/protocols/root/handshake/README.md src/protocols/root/connection/disconnect.c \
    src/net/proxy/README.md src/observability/metrics/README.md

# 4. Port numbers in T7 testing-runbook match conftest.py actual values
grep "NGINX.*PORT\|S3_PORT\|METRICS_PORT" tests/conftest.py | head -15

# 5. Fact-check: auth fields in T1 table match actual context.h field names
grep -n "sessid\|logged_in\|auth_done\|dn\[512\]\|vo_list" src/core/types/context.h | head -10
```

**Done-when:** All 5 checks pass and `make -j$(nproc)` exits 0 with no new warnings.
