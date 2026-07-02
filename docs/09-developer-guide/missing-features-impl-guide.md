# Missing Features — Historical Implementation Guide

Historical implementation guide for gaps that were tracked while moving this
module toward drop-in XRootD server coverage. For current reviewer-facing gaps,
prefer [`../10-reference/gaps-vs-xrootd.md`](../10-reference/gaps-vs-xrootd.md)
and [`../10-reference/source-verified-xrootd-comparison.md`](../10-reference/source-verified-xrootd-comparison.md).

Items below preserve the implementation notes for completed work and remaining
edge cases.

## Implementation Snapshot (updated 2026-06-14)

| Item | Status | Notes |
|---|---|---|
| 1. Outbound upstream auth | ✅ Partial complete | Transparent upstream bootstrap supports TLS upgrade and ztn token `kXR_authmore`; cache/write-through origin supports optional TLS but still uses anonymous login and fails on `kXR_authmore`. Transparent-upstream GSI and credentialed cache-origin auth remain. Native TPC outbound ztn/GSI is implemented separately in `src/tpc/gsi_outbound_*`. |
| 2. Prepare/stage tape dispatch | ✅ Implemented / partial parity | FRM durable queue, real request IDs, cancel/QPrep state, and Tape REST gateway exist; full upstream XrdFrm/MSS parity remains site-specific. Legacy `xrootd_prepare_command` fallback remains for FRM-off mode. |
| 3. JWKS hot refresh | ✅ Implemented | File mtime polling via `xrootd_token_jwks_refresh_interval`. |
| 4. PROPFIND `Depth: infinity` | ✅ Implemented | Recursive walk with a 10,000-entry cap. |
| 5. CMS escalation tests | ✅ Implemented | `kYR_try` and true three-tier escalation coverage. |
| 6. S3 presigned URLs | ✅ Implemented | Header/query SigV4 and expiry enforcement. |
| 7. Write-through cache | ✅ Implemented | Close/sync whole-file origin mirror with sync/async flush, origin write/truncate/sync helpers, and dirty tracking. |
| 8a. HTTP-TPC performance markers | ✅ Implemented | `202` chunked marker streaming. |
| 8b. Third-party macaroons | ✅ Implemented | AES-256-CBC vid decrypt + discharge bundle chain verification. |
| 8c. Authdb `HOST` identity | ✅ Implemented | Exact IP and CIDR `p` rules. |
| 8d. Delta CRL processing | ✅ Implemented | OpenSSL `X509_V_FLAG_USE_DELTAS`. |
| 8e. OCSP | ✅ Implemented | AIA responder queries + TLS stapling callback. |
| 8f. S3 session-token compatibility | ✅ Implemented | Static-secret `X-Amz-Security-Token` compatibility directive. |
| 8g. `kXR_fattrRecurse` | ✅ Implemented | Local extension bit `0x20`; `<relpath>:<U.name>\0` entries; depth cap 8. |

---

## 1. Outbound upstream authentication (`kXR_authmore` + `kXR_gotoTLS`)

**Status:** ✅ IMPLEMENTED for transparent-upstream TLS + ztn auth; native TPC
ztn/GSI is implemented separately; transparent-upstream GSI and credentialed
cache-origin auth remain follow-ups.
**Impact:** Important for transparent upstream redirector and cache-origin access.
Native TPC is no longer blocked on this path because it has its own credentialed
outbound implementation in `src/tpc/`.
**Effort:** 2–3 weeks

### Problem

Before Phase 1 and 2 landed, `src/net/upstream/bootstrap.c` aborted the upstream
connection if the remote server responded with:

- `kXR_gotoTLS` flag in the `kXR_protocol` response body — the server demands
  TLS upgrade before proceeding.
- `kXR_authmore` status to `kXR_login` — the server requires a credential
  exchange (GSI, token, or SSS) before accepting requests.

```c
/* src/net/upstream/bootstrap.c — historical abort stubs */
if (ntohl(flags_be) & kXR_gotoTLS) {
    xrootd_upstream_abort(up,
        "upstream requires TLS (not supported on outbound)");
    return;
}
/* ... */
if (up->resp_status == kXR_authmore) {
    xrootd_upstream_abort(up,
        "upstream requires authentication (not supported)");
    return;
}
```

Those stubs are now replaced for upstream TLS and ztn token auth. Native TPC
uses separate ztn/GSI paths in `src/tpc/gsi_outbound_*`; do not infer native TPC
credential gaps from the transparent-upstream bootstrap code.

### Phase 1 — Outbound TLS upgrade (`kXR_gotoTLS`) ✅ IMPLEMENTED

**Implemented in:**
- `src/net/upstream/tls.c` — `xrootd_upstream_start_tls()` wraps connection in SSL
  and `xrootd_upstream_tls_handshake_done()` resends `kXR_login` over TLS.
- `src/net/upstream/bootstrap.c` — `XRD_UP_BS_PROTOCOL` case detects `kXR_gotoTLS`
  flag and calls `xrootd_upstream_start_tls()` instead of aborting.
- `src/net/upstream/upstream_internal.h` — added `XRD_UP_BS_TLS` phase and
  `xrootd_upstream_build_login()` declaration.
- `src/core/types/config.h` — `upstream_tls`, `upstream_tls_ca`, `upstream_tls_name`,
  `upstream_tls_ctx` fields.
- `src/core/config/server_conf.c` — init + merge for new upstream TLS fields.
- `src/core/config/runtime_server.c` — builds `upstream_tls_ctx` SSL_CTX at
  postconfiguration when `xrootd_upstream_tls on`.
- `src/stream/module.c` — `xrootd_upstream_tls`, `xrootd_upstream_tls_ca`,
  `xrootd_upstream_tls_name` directives.
- `src/protocol/wire_core_requests.h` — added `ClientAuthRequest` typedef.
- `config` (module build file) — added `tls.c` and `auth.c` to source list.

**Configuration:**

```nginx
xrootd_upstream 127.0.0.1:1094;
xrootd_upstream_tls on;
xrootd_upstream_tls_ca  /etc/grid-security/certificates/ca.pem;
xrootd_upstream_tls_name storage.example.org;   # SNI override (optional)
```

When the protocol response has `kXR_gotoTLS` set and `xrootd_upstream_tls on`
is configured, the bootstrap:

1. Calls `xrootd_upstream_start_tls()` which wraps the existing plaintext
   `ngx_connection_t` in SSL via `ngx_ssl_create_connection()`.
2. Sets SNI from `xrootd_upstream_tls_name` (or the host from `xrootd_upstream`).
3. On handshake completion, resends `kXR_login` over TLS using
   `xrootd_upstream_build_login()` (the server discards the plaintext login).

If `kXR_gotoTLS` is signalled but `xrootd_upstream_tls` is off (or not built
with SSL), the upstream connection is aborted and `kXR_error` is returned to
the client.

### Phase 2 — Outbound bearer token auth (`kXR_authmore` with token) ✅ IMPLEMENTED

**Implemented in:**
- `src/net/upstream/auth.c` — `xrootd_upstream_send_token_auth()` reads the
  configured token file and sends a `kXR_auth` frame with `ztn\0` credential.
- `src/net/upstream/bootstrap.c` — `XRD_UP_BS_LOGIN` case detects `kXR_authmore`
  and calls `xrootd_upstream_send_token_auth()`; new `XRD_UP_BS_AUTH` case
  accepts or rejects the server's reply.
- `src/net/upstream/upstream_internal.h` — added `XRD_UP_BS_AUTH` phase and
  `authmore_count` field (prevents infinite auth loops).
- `src/core/types/config.h` — `upstream_token_file` field.
- `src/core/config/server_conf.c` — init + merge for `upstream_token_file`.
- `src/stream/module.c` — `xrootd_upstream_token_file` directive.

**Configuration:**

```nginx
xrootd_upstream 127.0.0.1:1094;
xrootd_upstream_token_file /run/secrets/xrootd-token;
```

When the upstream returns `kXR_authmore`, nginx reads the token file
synchronously (it is a small, local JWT refreshed by an external daemon),
builds a `kXR_auth` frame with `credtype="ztn\0"` followed by the raw JWT
bytes, and sends it.  A second `kXR_authmore` (multi-step auth) is not
supported and triggers an abort.

**Tests** (`tests/test_a_upstream_redirect.py::TestUpstreamAuth`):
- `test_upstream_token_auth_success` — success path with mock issuing
  `kXR_authmore` and accepting the ztn credential.
- `test_upstream_token_auth_no_file_aborts` — `kXR_authmore` but no
  `xrootd_upstream_token_file` configured → `kXR_error` to client.
- `test_upstream_gotorls_no_tls_configured_aborts` — `kXR_gotoTLS` but
  `xrootd_upstream_tls` is off → `kXR_error` to client (security negative).

### Phase 3 — Transparent-upstream / cache-origin credentialed auth

Still open for transparent-upstream GSI and for credentialed cache/write-through
origin bootstrap. Native TPC already uses `src/tpc/gsi_outbound_certreq.c`,
`gsi_outbound_common.c`, and `gsi_outbound_exchange.c` for the DH + X.509
exchange. A future upstream/cache implementation should reuse or extract those
helpers instead of reimplementing GSI.

### Tests (for Phase 1 & 2 — ✅ WRITTEN)

Phase 1 and 2 tests are in `tests/test_a_upstream_redirect.py::TestUpstreamAuth`:
- `test_upstream_token_auth_success` — mock issues `kXR_authmore`, nginx sends
  ztn JWT from configured token file, mock accepts, nginx forwards redirect.
- `test_upstream_token_auth_no_file_aborts` — `kXR_authmore` but no token
  file configured → `kXR_error` returned to client.
- `test_upstream_gotorls_no_tls_configured_aborts` — `kXR_gotoTLS` set but
  `xrootd_upstream_tls` is off → `kXR_error` (security negative).

Remaining tests to add (Phase 3 and cache integration):
- `tests/test_cache.py` — `test_cache_fill_from_tls_upstream`: nginx cache node
  with `xrootd_upstream_tls on` fetching from a TLS-only origin.
- Security negative: mock that issues `kXR_authmore` requesting GSI when no
  credential configured → nginx aborts without crashing.

---

## 2. `kXR_prepare` / `kXR_stage` tape backend dispatch

**Status:** ✅ IMPLEMENTED for the module's FRM/Tape REST design; partial versus
the full upstream XrdFrm/MSS ecosystem.
**Impact:** Tape-backed sites must validate real stage/cancel/evict/purge/recall
semantics against their storage manager.

### Problem

Before the FRM work, `src/query/prepare.c` validated paths, checked auth and VO
ACLs, then returned `kXR_ok` with a disk-only present/missing response. With
`xrootd_frm on`, `src/frm/` now owns durable queue records, host-qualified
request IDs, cancel handling, and queue-backed `kXR_QPrep` state. FRM-off mode
keeps the legacy disk-only behavior.

### Implementation

A **script-hook interface** remains available as the FRM-off fallback. FRM-on
deployments use the durable queue and Tape REST gateway described in
[`../../src/frm/README.md`](../../src/frm/README.md).

**New directive:** `xrootd_prepare_command /usr/local/bin/xrootd-stage.sh;`

**Key files:**
- `src/query/prepare_cmd.c` — `xrootd_prepare_invoke_command()`: `fork()+execv()` fire-and-forget launcher
- `src/query/prepare.c` — `xrootd_handle_prepare()`: path collection + command dispatch
- `src/query/query_internal.h` — `XROOTD_PREPARE_CMD_MAX_PATHS 512` constant
- `src/core/types/config.h` — `prepare_command` field (`ngx_str_t`)
- `src/stream/module.c` — `xrootd_prepare_command` directive registration

**Wire behaviour:**
- `kXR_stage` set + `xrootd_prepare_command` configured → resolved absolute paths collected for all validated files (including missing files when `kXR_noerrs` is set via `xrootd_resolve_path_noexist()`), then `fork()+execv()` with `argv=[cmd, path1, path2, ...]`. Parent does not `waitpid()`.
- `kXR_stage` set but `xrootd_prepare_command` not configured → `kXR_ok` silently accepted (no-op).
- `kXR_cancel` or `kXR_evict` → no-op returns `kXR_ok` immediately; command is never invoked.
- Command launch failure is logged at `NGX_LOG_ERR` but does NOT fail the client response.

**Config field** (in `src/core/types/config.h`):
```c
ngx_str_t  prepare_command;   /* shell command for kXR_stage recall */
```

**Directive** (in `src/stream/module.c`):
```c
{ ngx_string("xrootd_prepare_command"),
  NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
  ngx_conf_set_str_slot,
  NGX_STREAM_SRV_CONF_OFFSET,
  offsetof(ngx_stream_xrootd_srv_conf_t, prepare_command),
  NULL },
```

**`kXR_QPrep` status query**: FRM-off returns `A <path>` (on disk) or `M <path>`
(missing/unauthorized). FRM-on can report queued/staging/failed/available state
from durable records and uses real request IDs instead of the legacy `"0"`.

### Tests

New tests in `tests/test_prepare_staging.py` — class `TestPrepareStageCommand`:

```python
def test_stage_flag_invokes_command():
    """kXR_stage flag must invoke prepare_command with resolved paths."""

def test_no_stage_flag_skips_command():
    """kXR_prepare without kXR_stage must NOT invoke the command."""

def test_no_config_stage_silently_accepted():
    """No prepare_command configured → kXR_stage flag silently accepted (no error)."""

def test_stage_noerrs_missing_file_collected():
    """kXR_stage|kXR_noerrs for missing files must still pass path to command."""

def test_stage_cancel_skips_command():
    """kXR_cancel must not invoke the command even if prepare_command is configured."""
```

---

## 3. JWKS hot refresh / background key rotation

**Status:** ✅ IMPLEMENTED — mtime-poll hot refresh via `xrootd_token_jwks_refresh_interval` directive  
**Impact:** High for unattended production — WLCG IAM key rotation (≤24 h) causes token auth failures without operator intervention  
**Effort:** 3–5 days  
**Implemented in:** `src/auth/token/refresh.c` (new), `src/core/types/config.h`, `src/core/config/server_conf.c`, `src/auth/token/config.c`, `src/core/config/config.h`, `src/stream/module_core_directives.c`, `src/core/config/process.c`, `config`  
**Tests:** `tests/test_token_jwks_refresh.py`

### Problem

`src/auth/token/config.c` calls `xrootd_jwks_load()` once during
`ngx_stream_xrootd_merge_srv_conf()`. The resulting `xcf->jwks_keys[]` array
is fixed for the lifetime of the worker process. Key rotations at the issuer
are invisible until `nginx -s reload`.

### Implementation

#### Option A — Inotify-triggered reload (simplest, Linux-specific)

Add an `ngx_event_t` timer in the worker that periodically `stat()`s the
configured JWKS file path. If `st_mtime` changed, call `xrootd_jwks_free()` +
`xrootd_jwks_load()` under a write lock. This is the simplest path and works
with file-based JWKS (fetched by a cron job or cert-manager sidecar).

**Files:**
- `src/auth/token/refresh.c` (new) — `xrootd_token_jwks_schedule_refresh()`
- `src/auth/token/token.h` — add `time_t jwks_mtime` to `xrootd_jwks_state_t`
- `src/core/config/config.h` — add `ngx_msec_t token_jwks_refresh_interval`
  (default 60 000 ms)
- `src/core/config/directives.c` — add `xrootd_token_jwks_refresh_interval`
  directive (milliseconds)
- Worker init: call `xrootd_token_jwks_schedule_refresh()` after config merge

**`src/auth/token/refresh.c`:**

```c
static void
xrootd_token_jwks_refresh_handler(ngx_event_t *ev)
{
    ngx_stream_xrootd_srv_conf_t  *conf = ev->data;
    struct stat                    st;
    xrootd_jwks_key_t              new_keys[XROOTD_MAX_JWKS_KEYS];
    int                            new_count;

    if (stat((const char *) conf->token_jwks.data, &st) != 0) {
        goto reschedule;
    }

    if (st.st_mtime == conf->jwks_mtime) {
        goto reschedule;    /* file unchanged */
    }

    new_count = xrootd_jwks_load(ev->log,
                                 (const char *) conf->token_jwks.data,
                                 new_keys, XROOTD_MAX_JWKS_KEYS);
    if (new_count <= 0) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "xrootd: JWKS reload failed — keeping old keys");
        goto reschedule;
    }

    /* Swap atomically under the cycle lock (single-worker: no lock needed) */
    xrootd_jwks_free(conf->jwks_keys, conf->jwks_key_count);
    ngx_memcpy(conf->jwks_keys, new_keys,
               new_count * sizeof(xrootd_jwks_key_t));
    conf->jwks_key_count = new_count;
    conf->jwks_mtime     = st.st_mtime;

    ngx_log_error(NGX_LOG_INFO, ev->log, 0,
                  "xrootd: JWKS refreshed — %d key(s) loaded", new_count);

reschedule:
    ngx_add_timer(ev, conf->token_jwks_refresh_interval);
}

void
xrootd_token_jwks_schedule_refresh(ngx_cycle_t *cycle,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_event_t  *ev;

    if (conf->token_jwks.len == 0
        || conf->token_jwks_refresh_interval == NGX_CONF_UNSET_MSEC)
    {
        return;
    }

    ev = ngx_pcalloc(cycle->pool, sizeof(*ev));
    if (ev == NULL) { return; }

    ev->handler = xrootd_token_jwks_refresh_handler;
    ev->data    = conf;
    ev->log     = cycle->log;

    ngx_add_timer(ev, conf->token_jwks_refresh_interval);
}
```

Call `xrootd_token_jwks_schedule_refresh()` from the module's `init_worker`
callback (add one in `src/stream/module.c` if not present).

#### Option B — HTTP JWKS URI polling (for future work)

Extend the above to also accept `xrootd_token_jwks_uri https://iam.example.org/jwks` and use `ngx_http_upstream` or a subprocess `curl` to fetch the JWKS JSON. More complex; defer until Option A is in production.

### Tests

```python
# tests/test_token_auth.py
def test_jwks_hot_refresh_new_key():
    """Server picks up new signing key after file mtime changes, within refresh interval."""

def test_jwks_hot_refresh_keeps_old_key_on_parse_error():
    """Corrupt JWKS file → existing keys preserved, no auth outage."""

def test_jwks_hot_refresh_rejects_old_key_after_rotation():
    """Token signed with old key rejected after refresh interval elapses post-rotation."""
```

---

## 4. WebDAV `PROPFIND` `Depth: infinity`

**Status:** ✅ IMPLEMENTED — Option B (full recursive walk) with 10 000-entry cap  
**Impact:** Medium — blocks Cyberduck, GNOME GVFS, and some rucio WebDAV clients  
**Effort:** 2–3 days  
**Implemented in:** `src/protocols/webdav/propfind.c` (`propfind_parse_depth()`, `propfind_walk()`), `src/observability/metrics/metrics.h` (`XROOTD_WEBDAV_PROPFIND_DEPTH_INF`), `src/observability/metrics/webdav.c`  
**Tests:** `tests/test_propfind_infinity.py`

### Problem

`propfind_depth_is_one()` in `src/protocols/webdav/propfind.c` returns `0` for anything
that is not exactly `"1"`, including `"infinity"`. The handler then generates
only a single entry (depth 0). RFC 4918 §9.1.2 permits servers to refuse
`Depth: infinity` with `403 Depth Not Supported` but requires them to say so
explicitly rather than silently returning truncated results.

### Option A — Return `403 Depth Not Supported` (correct spec behavior, minimal change)

**Files:** `src/protocols/webdav/propfind.c`

```c
/* Replace propfind_depth_is_one() with propfind_parse_depth() */
static int
propfind_parse_depth(ngx_http_request_t *r)
{
    /* returns 0, 1, or -1 for "infinity" */
    ngx_list_part_t   *part;
    ngx_table_elt_t   *h;
    ngx_uint_t         i;

    part = &r->headers_in.headers.part;
    h    = part->elts;

    for (;;) {
        for (i = 0; i < part->nelts; i++) {
            if (h[i].key.len == 5
                && ngx_strncasecmp(h[i].key.data,
                                   (u_char *) "Depth", 5) == 0)
            {
                if (h[i].value.len == 1 && h[i].value.data[0] == '1') {
                    return 1;
                }
                if (h[i].value.len == 8
                    && ngx_strncasecmp(h[i].value.data,
                                       (u_char *) "infinity", 8) == 0)
                {
                    return -1;  /* infinity */
                }
                return 0;  /* "0" or unknown */
            }
        }
        if (part->next == NULL) { break; }
        part = part->next;
        h    = part->elts;
    }
    return 0;  /* header absent → depth 0 */
}

/* In webdav_handle_propfind(): */
int depth = propfind_parse_depth(r);
if (depth == -1) {
    /* RFC 4918 §9.1.2: MAY reject infinity */
    r->headers_out.status = 403;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    /* optionally add DAV: 1 header */
    return ngx_http_send_header(r);
}
```

### Option B — Implement recursive `Depth: infinity` (full feature)

Implement a bounded recursive walk (cap at 10 000 entries or a configurable
`xrootd_webdav_propfind_max_entries` directive to prevent runaway allocations).

**Files:** `src/protocols/webdav/propfind.c`

Add a recursive helper:

```c
static ngx_int_t
propfind_walk(ngx_http_request_t *r, const char *root_canon,
              const char *uri_base, const char *fs_path,
              ngx_chain_t **head, ngx_chain_t **tail,
              ngx_uint_t *entry_count, ngx_uint_t max_entries,
              int current_depth, int max_depth)
{
    DIR           *dir;
    struct dirent *de;
    struct stat    st;
    char           child_fs[PATH_MAX];
    char           child_uri[PATH_MAX];

    if (current_depth > max_depth || *entry_count >= max_entries) {
        return NGX_OK;  /* depth cap or entry cap reached */
    }

    dir = opendir(fs_path);
    if (dir == NULL) { return NGX_OK; }

    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') { continue; }

        snprintf(child_fs,  sizeof(child_fs),  "%s/%s", fs_path,  de->d_name);
        snprintf(child_uri, sizeof(child_uri), "%s%s",  uri_base, de->d_name);

        if (stat(child_fs, &st) != 0) { continue; }

        (*entry_count)++;
        if (propfind_entry(r->pool, head, tail, child_uri, &st) != NGX_OK) {
            closedir(dir);
            return NGX_ERROR;
        }

        if (S_ISDIR(st.st_mode)) {
            char child_uri_slash[PATH_MAX];
            snprintf(child_uri_slash, sizeof(child_uri_slash),
                     "%s/", child_uri);
            propfind_walk(r, root_canon, child_uri_slash, child_fs,
                          head, tail, entry_count, max_entries,
                          current_depth + 1, max_depth);
        }
    }

    closedir(dir);
    return NGX_OK;
}
```

**Note:** Large directory trees buffered entirely in memory before sending.
For production, consider streaming chunks earlier (send headers then write
chain in pieces). The current non-streaming design is acceptable for
directories with < ~50 000 entries.

### Tests

```python
# tests/test_http_webdav_status_codes.py
def test_propfind_depth_infinity_returns_403_or_recursive():
    """Depth: infinity must not silently return only the root."""

def test_propfind_depth_infinity_recursive_walks_subdirs():
    """Depth: infinity returns entries from nested subdirectories."""

def test_propfind_depth_infinity_caps_at_max_entries():
    """Entry cap prevents unbounded memory for huge directory trees."""
```

---

## 5. CMS escalation path integration tests

**Status:** ✅ IMPLEMENTED — `kYR_try` and true three-tier escalation tests added  
**Impact:** Medium — regressions in the escalation path go undetected  
**Effort:** 2–3 days

### Problem

The `XRD_ST_WAITING_CMS` session-suspension, `kYR_select`, and `kYR_try`
handlers are all implemented in `src/net/cms/recv.c`. The previous coverage gaps
were:

1. **`kYR_try` multi-alternative selection** — parent manager replies with an
   ordered list of alternative hosts; nginx picks the first reachable one.
2. **True CMS-escalation three-tier** — sub-manager local registry misses,
   sub-manager sends `kYR_locate` to meta-manager, meta-manager responds
   `kYR_select` naming a leaf; client gets `kXR_redirect` to the leaf.

Both gaps are now covered by `tests/test_manager_mode.py`.

### Implementation

Both tests live in `tests/test_manager_mode.py`, alongside the existing manager
mode and CMS registry coverage.

**Implemented tests:**

- `TestCmsKyrTry::test_locate_redirects_to_first_try_entry` — mock parent CMS
  replies with `kYR_try` containing two NUL-terminated host/port entries; nginx
  redirects the suspended client to the first entry and ignores later entries.
- `TestCmsEscalation::test_three_tier_escalation_redirects_to_leaf` — a
  sub-manager with an empty local registry sends `kYR_locate` to a mock
  meta-manager, receives `kYR_select`, wakes the client with `kXR_redirect`,
  then the client connects to the leaf data-server and opens the file.

The `kYR_try` payload used by the tests matches `src/net/cms/recv.c`:

```text
[hostname NUL-terminated]
[port 2 bytes big-endian]
[hostname NUL-terminated]
[port 2 bytes big-endian]
```

The mock CMS helpers are implemented inline in `tests/test_manager_mode.py`.

---

## 6. S3 presigned URL authentication (SigV4 query-string form)

**Status:** ✅ IMPLEMENTED — header and query-string SigV4 forms accepted  
**Impact:** Medium — AWS CLI `s3 presign`, boto3 `generate_presigned_url`, and many S3-compatible clients default to presigned URLs  
**Effort:** 3–5 days

### Problem

`src/protocols/s3/auth_sigv4_parse.c` parses only the `Authorization` header. Presigned
URL authentication passes credentials as query parameters:

```
GET /bucket/key
  ?X-Amz-Algorithm=AWS4-HMAC-SHA256
  &X-Amz-Credential=AKID/20260519/us-east-1/s3/aws4_request
  &X-Amz-Date=20260519T000000Z
  &X-Amz-Expires=3600
  &X-Amz-SignedHeaders=host
  &X-Amz-Signature=<hex>
```

### Implementation

**Implemented in:**
- `src/protocols/s3/auth_sigv4_parse.c` — detects `X-Amz-Signature`, extracts and
  URL-decodes `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`, and
  `X-Amz-SignedHeaders`.
- `src/protocols/s3/auth_sigv4_canonical.c` — canonicalizes query parameters from decoded
  values, sorts by name/value, and omits `X-Amz-Signature` while verifying
  presigned URLs.
- `src/protocols/s3/auth_sigv4_verify.c` — selects presigned auth before header auth,
  uses query `X-Amz-Date` in the string-to-sign, and rejects expired URLs.
- `src/protocols/s3/s3_auth_internal.h` — stores presigned metadata on
  `sigv4_components_t`.

### Tests

New coverage in `tests/test_s3_presigned.py`:
- `test_presigned_url_get_succeeds`
- `test_presigned_url_expired_returns_403`
- `test_presigned_url_bad_signature_returns_403`
- `test_sigv4_header_auth_still_works`

---

## 7. Write-through proxy/cache mode

**Status:** ✅ IMPLEMENTED — close/sync whole-file origin mirror  
**Impact:** Medium — enables active cache / ingest gateway deployments  
**Effort:** 5–7 days  
**Detailed plan:** `docs/09-developer-guide/pfc-write-through-plan.md`

The codebase now contains the write-through configuration surface, write
bookkeeping, and origin flush path needed for cache gateway deployments:

- `src/core/types/config.h`, `src/fs/cache/directives.c`, and `src/stream/module.c`
  define `xrootd_write_through`, `xrootd_wt_mode`, `xrootd_wt_origin`,
  `xrootd_wt_deny_prefix`, and `xrootd_wt_allow_prefix`.
- `src/fs/cache/writethrough_decision.c` evaluates prefix/size policy at
  `kXR_open`.
- `src/read/open_resolved_file.c` caches the decision on `xrootd_file_t`.
- `src/write/write.c`, `src/write/pgwrite.c`, `src/write/writev.c`,
  `src/write/truncate.c`, and AIO write completions track dirty data.
- `src/fs/cache/origin_connection.c` can connect to either the read-through
  cache origin or a dedicated `xrootd_wt_origin`.
- `src/fs/cache/origin_protocol.c` implements write-side origin operations:
  `xrootd_cache_origin_open_write()`, `xrootd_cache_origin_write_chunk()`,
  `xrootd_cache_origin_truncate()`, and `xrootd_cache_origin_sync()`.
- `src/fs/cache/writethrough_flush.c` mirrors the final local file to the
  origin in chunks, then issues origin truncate, sync, and close.
- `src/write/sync.c` performs a synchronous WT flush for dirty handles before
  returning `kXR_ok`; failures are returned as `kXR_IOError`.
- `src/read/close.c` flushes dirty WT handles on close. `sync` mode blocks
  during close; `async` mode posts an nginx thread-pool task and logs failures.

This implementation deliberately uses a **whole-file replacement** strategy at
`kXR_sync` / `kXR_close` rather than maintaining a persistent origin handle and
dual-dispatching every client write. That keeps the failure model simple: local
writes complete first, explicit `kXR_sync` reports origin flush failures, and
close remains fail-open while logging WT errors.

**Key entry points from the plan:**

| Phase | Files | What |
|---|---|---|
| 1 | `src/core/types/file.h`, `src/core/types/config.h` | ✅ Config and handle WT state |
| 2 | `src/fs/cache/origin_protocol.c` | ✅ Origin write-open, write, truncate, sync, close |
| 3 | `src/read/open_resolved_file.c` | ✅ Open-time WT policy cached on the handle |
| 4 | `src/core/aio/`, `src/write/*.c` | ✅ Dirty tracking for write, pgwrite, writev, truncate |
| 5 | `src/fs/cache/writethrough_flush.c`, `src/read/close.c`, `src/write/sync.c` | ✅ Close/sync origin flush |

**Remaining limitations:** the origin path must resolve under `xrootd_root` or
`xrootd_cache_root`, the origin must be a direct data server (redirect-following
is not implemented in the cache origin client), and cache/write-through origin
authentication is narrower than the native TPC outbound path. Cache-origin TLS
can be configured, but cache/write-through origin login is still anonymous and
does not complete ztn/GSI `kXR_authmore`.

---

## 8. Smaller gaps (self-contained, lower priority)

### 8a. HTTP-TPC `Performance-Marker` streaming (chunked 202)

**Status:** ✅ IMPLEMENTED — timer-polled curl subprocess with chunked `202` markers  
**Implemented in:** `src/protocols/webdav/tpc_marker.c`, `src/protocols/webdav/tpc.c`, `src/protocols/webdav/tpc_config.c`  
**Tests:** `tests/test_xrdhttp_tpc.py::TestXrdHttpTPC::test_tpc_marker_streaming_header_present`

FTS optionally parses `Performance-Marker:` lines from a `202 Accepted`
chunked body to display transfer rate. When
`xrootd_webdav_tpc_marker_interval <seconds>` is set, nginx now returns
`202 Accepted`, emits WLCG `Performance-Marker:` blocks while polling the curl
child with an nginx timer, and finishes the body with `success` or `failure`.
Without the directive, the legacy synchronous `201` / `204` completion path is
preserved.

### 8b. Third-party / discharge Macaroon support

**Status:** ✅ IMPLEMENTED — AES-256-CBC vid decryption and discharge bundle validation  
**Implemented in:** `src/auth/token/macaroon.c`, `src/auth/token/macaroon.h`  
**Tests:** `tests/test_macaroon_discharge.py` (23/23 passing)

Third-party caveats in a Macaroon are caveats that can only be discharged by a
separate trusted service (identified by a `vid` field). The discharging service
issues a discharge Macaroon which the client bundles with the root Macaroon.

The implementation adds full discharge bundle support to the existing Macaroon
validation pipeline:

- **Bundle format:** space-separated base64url tokens — `"<root> [<discharge> ...]"`. The
  new `xrootd_macaroon_validate_bundle()` function splits the bundle, validates
  the root token, then processes each third-party caveat.
- **`vid` decryption:** AES-256-CBC with the HMAC-derived sig-before-cid as the
  32-byte key and the first 16 bytes of vid as IV (PKCS#7 padding disabled).
  Recovers the 32-byte discharge Macaroon root key.
- **Discharge chaining:** for each third-party caveat, finds the discharge
  Macaroon whose identifier matches, decrypts its root key from the vid blob,
  validates the discharge signature, and intersects its path/activity/expiry
  caveats into the combined permission set.
- `xrootd_macaroon_validate()` now delegates to `xrootd_macaroon_validate_bundle()`
  so existing single-token flows are unchanged.

### 8c. Authdb `HOST` (`p`) identity type

**Status:** ✅ IMPLEMENTED — exact IP and CIDR host matching  
**Implemented in:** `src/core/types/context.h`, `src/connection/handler.c`, `src/auth/authz/authdb.c`  
**Tests:** `tests/test_authdb.py::test_host_rule_exact_peer_read`, `test_host_rule_cidr_peer_read`, `test_host_rule_nonmatching_peer_denied`

`p` rules in the authdb file now match the remote peer address recorded at
connection setup. Plain IDs match exact textual IP addresses (`127.0.0.1`,
`::1`); IDs containing `/` are parsed as IPv4 or IPv6 CIDR ranges. `p *`
matches any peer.

### 8d. Delta CRL processing

**Status:** ✅ IMPLEMENTED — OpenSSL delta-CRL verification flag enabled  
**Implemented in:** `src/auth/gsi/config.c`, `src/protocols/webdav/auth_store.c`  
**Regression tests:** `tests/test_crl.py`

Delta CRLs (RFC 5280 §5.2.4) carry only revocations issued since the last full
CRL, identified by the `freshestCRL` extension and referenced via `deltaCRLIndicator`.

The stream GSI and WebDAV X.509 stores now set
`X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL | X509_V_FLAG_USE_DELTAS`
when CRLs are configured. Because the existing CRL loaders add all CRLs from
the configured file/directory into the same `X509_STORE`, OpenSSL can merge
base and delta CRLs during chain verification.

### 8e. OCSP stapling and responder queries

**Status:** ✅ IMPLEMENTED — AIA responder queries and TLS stapling callback  
**Implemented in:** `src/auth/crypto/ocsp.c`, `src/auth/crypto/ocsp.h`, `src/auth/gsi/auth.c`, `src/session/tls_config.c`  
**New directives:** `xrootd_ocsp_enable`, `xrootd_ocsp_soft_fail`, `xrootd_ocsp_stapling`  
**Tests:** `tests/test_ocsp.py` (18/18 passing)

CRL-based revocation checking requires downloading and refreshing CRL files.
OCSP eliminates the file management by querying the CA's responder online.

Two sub-features were implemented:

1. **OCSP responder query** (client cert verification): after successfully
   verifying the X.509 chain in `src/auth/gsi/auth.c`, `xrootd_ocsp_check_cert()`
   extracts the OCSP responder URL from the leaf cert's `authorityInfoAccess`
   extension via `X509_get1_ocsp()`, builds a nonce-protected `OCSP_REQUEST`,
   POSTs it to the CA's responder via `BIO_new_connect()`, verifies the
   response signature, and rejects the cert if status is `REVOKED`. Controlled
   by `xrootd_ocsp_enable on/off` (default `off`) and `xrootd_ocsp_soft_fail
   on/off` (default `on` — network errors do not block auth).

2. **OCSP stapling** (server side): `xrootd_ocsp_staple_fetch()` fetches a DER
   OCSP response and caches it in the server config. A
   `SSL_CTX_set_tlsext_status_cb()` callback installed in
   `src/session/tls_config.c` copies the cached DER blob into each TLS
   handshake via `SSL_set_tlsext_status_ocsp_resp()`. Controlled by
   `xrootd_ocsp_stapling on/off` (default `off`).

### 8f. S3 STS session token (`X-Amz-Security-Token`)

**Status:** ✅ IMPLEMENTED — static-secret STS compatibility mode  
**Implemented in:** `src/protocols/s3/auth_sigv4_verify.c`, `src/protocols/s3/module.c`, `src/protocols/s3/s3.h`  
**Tests:** `tests/test_s3_presigned.py::test_session_token_rejected_by_default`, `test_session_token_header_allowed_with_static_secret`, `test_session_token_presigned_allowed_with_static_secret`

AWS STS `AssumeRole` returns temporary credentials: an access key ID, a secret
access key, and a session token. The session token appears in requests as the
`X-Amz-Security-Token` header (for header auth) or `X-Amz-Security-Token`
query parameter (for presigned URL auth).

SigV4 signing includes the session token in the canonical request as part of
the credential scope. The implemented compatibility mode is deliberately
static-secret based: by default, requests carrying `X-Amz-Security-Token` are
rejected with `403`. For sites using static access keys but clients that always
send a session-token field, enable:

```nginx
xrootd_s3_allow_unsigned_session_token on;
```

With that directive, nginx accepts header and presigned query session-token
forms, but still verifies the full SigV4 signature with the configured
`xrootd_s3_secret_key`. Header-auth requests must include
`x-amz-security-token` in `SignedHeaders`; presigned requests include
`X-Amz-Security-Token` in the canonical query string automatically.

Full AWS STS semantics with a credential store that maps session tokens to
temporary secret keys remains out of scope for this static-key module.

### 8g. `kXR_fattrRecurse` flag support

**Status:** ✅ IMPLEMENTED (local extension bit `0x20`)  
**Files:** `src/fattr/list.c`, `src/protocol/flags.h`, `src/fattr/ngx_xrootd_fattr.h`  
**Tests:** `tests/test_fattr_query.py::TestFattrRecurse` (3 tests, all passing)

**Background:** `XProtocol.hh` (protocol 5.2) only defines two `options` bits for
`ClientFattrRequest`: `isNew = 0x01` (for set) and `aData = 0x10` (for list).
No recurse flag exists in the upstream XRootD wire protocol; this feature is
implemented as a documented local extension.

**Implementation:**

- **`src/protocol/flags.h`** — defines `kXR_fa_recurse = 0x20` with a comment
  marking it as a local extension not present in the upstream wire protocol.
- **`src/fattr/list.c`** — when `options & kXR_fa_recurse` is set and the
  resolved path is a directory, `fattr_list()` delegates to a new
  `fattr_list_dir()` recursive helper instead of the single-file `listxattr(2)`
  path. `fattr_list_dir()` walks the tree with `opendir()`/`readdir()`, skips
  dot entries and non-regular files (via `lstat()` — symlinks are not followed),
  and appends one NUL-terminated entry per xattr found.
- **`src/fattr/ngx_xrootd_fattr.h`** — updated `fattr_list` comment to document
  the `kXR_fa_recurse` extension.

**Response format:**

```
<relpath>:<U.name>\0           # base entry (kXR_fa_recurse only)
<relpath>:<U.name>\0<4B-len><value>  # with kXR_fa_aData also set
```

where `<relpath>` is the path relative to the requested directory root
(e.g. `sub/nested.txt`).

**Limits:**

| Constant | Value | Purpose |
|---|---|---|
| `XROOTD_FATTR_RECURSE_MAX_DEPTH` | 8 | Guard against runaway recursion / symlink loops |
| `XROOTD_FATTR_RECURSE_BUF_MAX` | 2 MiB | Cap pool allocation for the response buffer |

If the path is not a directory, the recurse flag is silently ignored and
single-file list semantics apply.

---

## Sequencing recommendation

```text
Priority  Feature                              Unblocks
──────────────────────────────────────────────────────────
1 (now)   Outbound auth (authmore + gotoTLS)   native TPC + cache fill
2         kXR_prepare tape dispatch (hook)     tape-backed sites
3         JWKS hot refresh (inotify timer)     production token auth
4         PROPFIND Depth:infinity (403 form)   WebDAV clients
5         CMS escalation tests                 ✅ done — regression coverage
6         S3 presigned URLs                    ✅ done — boto3 / AWS CLI users
7         Write-through cache                  ✅ done — close/sync origin flush
          (depends on #1 for GSI credential fwd)
8a        HTTP-TPC perf markers               ✅ done — FTS observability
8c        Authdb HOST identity                 ✅ done — peer-based authdb
8d        Delta CRL processing                 ✅ done — revocation freshness
8f        S3 session-token compatibility       ✅ done — STS-shaped clients
8b        Discharge macaroon support           ✅ done — AES vid decrypt + bundle chain
8e        OCSP stapling + responder queries     ✅ done — AIA queries + TLS stapling
8g        fattr recurse                        ✅ done — local ext bit 0x20; <relpath>:<U.name>\0
```

The implementation-guide items are largely complete. Remaining reviewer-facing
gaps are transparent-upstream GSI auth, credentialed cache/write-through origin
auth, and full upstream XrdFrm/MSS parity; native TPC outbound ztn/GSI is
implemented in `src/tpc/`.
