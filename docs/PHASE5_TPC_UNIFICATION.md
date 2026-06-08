# Phase 5: Third-Party Copy Unification - Implementation Plan

**Status:** PLANNING  
**Phase:** 5 of 6 (Protocol Unification)  
**Depends On:** Phase 2 (Identity Abstraction), Phase 3 (VFS Operations)  
**Estimated Effort:** 14-20 hours  
**Risk Level:** HIGH (TPC is security-sensitive: credential forwarding, cross-site transfers)  
**Target:** Shared TPC credential, authorization, and transfer tracking layer consumed by both stream TPC and WebDAV TPC

---

## Executive Summary

Third-Party Copy (TPC) is the operation where the server itself initiates a data transfer between two storage endpoints on behalf of a client. This module supports TPC over two distinct paths:

- **Stream TPC** (`src/tpc/`): Client sends `kXR_prepare` with `kXR_Mv` flag; server uses a SHM key registry and spawns a thread to open a GSI-authenticated XRootD connection to the source.
- **WebDAV TPC** (`src/webdav/tpc*.c`): Client sends HTTP COPY with `Source:` and `Credential:` headers; server uses libcurl to fetch the source over HTTPS.

These two paths share the same *semantic* requirements but currently implement credential extraction, authorization checking, transfer tracking, and metric accounting entirely independently. Duplication means a security fix in one path often misses the other.

After Phase 5, both TPC paths share:
1. A unified credential extraction and validation layer.
2. A unified authorization check (identity → scope check via Phase 2 identity).
3. A unified transfer registry (replaces stream-only SHM key registry for bookkeeping).
4. Unified TPC metrics.

The transport layer (SHM+thread for stream, libcurl for WebDAV) remains protocol-specific.

---

## Current State Analysis

### Stream TPC (`src/tpc/`)

| File | Purpose |
|:---|:---|
| `key_registry.c` / `.h` | SHM-based registry mapping delegation keys to transfer metadata |
| `launch.c` | Thread launch for outbound XRootD connection |
| `thread.c` | Transfer thread: open source, read, write to destination |
| `io.c` | I/O within the transfer thread |
| `done.c` | Completion handling, cleanup |
| `parse.c` | Parse kXR_prepare TPC request parameters |
| `source.c` | Open source file via XRootD |
| `connect.c` | Outbound XRootD TCP + GSI handshake |
| `bootstrap.c` | Initialize TPC subsystem |
| `tpc_token.c` | Delegation token handling for stream TPC |
| `gsi_outbound_*.c` | GSI certificate chain for outbound connection |
| `tpc_internal.h` | Internal types |

Credential for outbound connection comes from `gsi_outbound_certreq.c` (proxy certificate delegation) or `tpc_token.c` (token delegation). **No reuse with WebDAV credential path.**

### WebDAV TPC (`src/webdav/tpc*.c`)

| File | Purpose |
|:---|:---|
| `tpc.c` | Main handler: parse COPY request, dispatch push/pull |
| `tpc_curl.c` | libcurl fetch from source URL |
| `tpc_cred.c` | Credential selection: proxy cert or bearer token |
| `tpc_cred_parse.c` | Parse `Credential:` header |
| `tpc_headers.c` | Parse `Source:`, `Destination:`, `TransferHeader*:` |
| `tpc_marker.c` | Perf marker (chunked progress response) |
| `tpc_thread.c` | Background curl thread |
| `tpc_config.c` / `.h` | Config directives for WebDAV TPC |
| `tpc_cred_internal.h` | Internal credential types |

Credential extraction in `tpc_cred.c` reads `Credential:` header; independently validates proxy certificates and bearer tokens without using Phase 2's `xrootd_identity_t`.

### Shared Duplication Surface

| Concern | Stream Path | WebDAV Path |
|:---|:---|:---|
| Credential parse | `tpc_token.c`, `gsi_outbound_certreq.c` | `tpc_cred.c`, `tpc_cred_parse.c` |
| Credential validation | `src/gsi/parse.c` (ad-hoc call) | `webdav_verify_proxy_cert()` (ad-hoc call) |
| Scope check | Manual bitmask on `kXR_prepare` flags | Manual `has_write_scope` check in `tpc.c` |
| Transfer tracking | `src/tpc/key_registry.c` (SHM) | None — lost on worker restart |
| Metrics | Not recorded | `src/webdav/metrics.c` partial |
| Authorization | Hardcoded in `parse.c` | Hardcoded in `tpc.c` |

---

## Target Architecture

### New Directory: `src/tpc/common/`

```
src/tpc/common/
  credential.h       — xrootd_tpc_credential_t definition
  credential.c       — Parse + validate TPC credentials (any source)
  auth.c             — Authorization check (identity → scope + ACL)
  registry.c         — Unified transfer registry (replaces SHM-only key_registry)
  registry.h         — Public registry API
  transfer.h         — xrootd_tpc_transfer_t (in-progress transfer state)
  progress.c         — Progress reporting (marker emission)
  metrics.c          — TPC-specific metric helpers
  metrics.h
```

### `xrootd_tpc_credential_t` — Unified Credential Type

```c
#ifndef XROOTD_TPC_CREDENTIAL_H
#define XROOTD_TPC_CREDENTIAL_H

#include <ngx_config.h>
#include <ngx_core.h>
#include "../../types/identity.h"

/*
 * TPC credential type — how the outbound connection authenticates.
 */
typedef enum {
    XROOTD_TPC_CRED_NONE    = 0,
    XROOTD_TPC_CRED_PROXY   = 1,    /* Delegated X.509 proxy certificate */
    XROOTD_TPC_CRED_TOKEN   = 2,    /* Delegated WLCG/SciToken bearer */
} xrootd_tpc_cred_type_t;

/*
 * xrootd_tpc_credential_t
 * WHAT: Holds a validated, ready-to-use outbound TPC credential.
 * WHY:  Stream and WebDAV TPC need the same outbound auth material.
 *       This struct unifies how that material is represented.
 */
typedef struct {
    xrootd_tpc_cred_type_t  type;
    ngx_str_t               proxy_pem;   /* PEM-encoded proxy (CRED_PROXY) */
    ngx_str_t               bearer;      /* Bearer token string (CRED_TOKEN) */
    xrootd_identity_t      *identity;    /* Verified identity from Phase 2 */
    time_t                  expires_at;  /* Credential expiry (Unix time) */
} xrootd_tpc_credential_t;

/*
 * Parse and validate a TPC credential.
 *
 * For WebDAV: reads the Credential: header value.
 * For Stream: reads the delegation key from the kXR_prepare TPC section.
 *
 * On success, fills *cred and returns NGX_OK.
 * On failure, returns NGX_HTTP_FORBIDDEN (403) or NGX_HTTP_UNAUTHORIZED (401).
 */
ngx_int_t xrootd_tpc_credential_parse(const ngx_str_t *raw_credential,
                                       xrootd_tpc_cred_type_t hint,
                                       xrootd_tpc_credential_t *cred,
                                       ngx_pool_t *pool,
                                       ngx_log_t *log);

/*
 * Validate the credential against the current time and configured trust roots.
 * Returns NGX_OK if valid, NGX_HTTP_FORBIDDEN otherwise.
 */
ngx_int_t xrootd_tpc_credential_validate(const xrootd_tpc_credential_t *cred,
                                          ngx_log_t *log);

#endif /* XROOTD_TPC_CREDENTIAL_H */
```

### `src/tpc/common/auth.c` — Unified TPC Authorization

```c
/*
 * xrootd_tpc_check_authz()
 *
 * WHAT: Check that the caller's identity (Phase 2) is authorized to
 *       initiate TPC to/from the given paths.
 * WHY:  Authorization rules are identical for stream and WebDAV TPC.
 *       Centralizing prevents the "stream allows but WebDAV denies"
 *       class of inconsistency.
 * HOW:
 *   1. Verify identity->has_write_scope for the destination path.
 *   2. Verify identity->has_read_scope for the source path.
 *   3. Call xrootd_check_authdb() from src/path/acl.c for each path.
 *   4. Check conf->allow_write is set.
 */
ngx_int_t xrootd_tpc_check_authz(const xrootd_identity_t *identity,
                                   const ngx_str_t *src_path,
                                   const ngx_str_t *dst_path,
                                   ngx_log_t *log);
```

### `src/tpc/common/registry.c` — Unified Transfer Registry

The stream TPC uses a SHM-based key registry (`src/tpc/key_registry.c`) to track in-progress transfers across worker processes. WebDAV TPC has no equivalent — a transfer in progress is invisible to other workers and lost on crash.

The unified registry uses the existing SHM mechanism but extends it to cover both stream and WebDAV transfers:

```c
/*
 * xrootd_tpc_transfer_t — in-progress TPC transfer record.
 */
typedef struct {
    uint64_t       id;              /* Unique transfer ID */
    ngx_uint_t     protocol;       /* XROOTD_TPC_PROTO_STREAM | _WEBDAV */
    ngx_str_t      src_url;
    ngx_str_t      dst_path;
    off_t          bytes_total;
    off_t          bytes_done;
    time_t         started_at;
    time_t         updated_at;
    ngx_uint_t     state;          /* PENDING | ACTIVE | DONE | ERROR */
} xrootd_tpc_transfer_t;

/* Register a new transfer; returns unique transfer ID or 0 on failure */
uint64_t xrootd_tpc_registry_add(xrootd_tpc_transfer_t *t, ngx_log_t *log);

/* Update progress for an existing transfer */
ngx_int_t xrootd_tpc_registry_update(uint64_t id, off_t bytes_done,
                                      ngx_uint_t state, ngx_log_t *log);

/* Remove a completed/failed transfer */
ngx_int_t xrootd_tpc_registry_remove(uint64_t id, ngx_log_t *log);

/* Find transfer by ID (for marker/progress queries) */
const xrootd_tpc_transfer_t *xrootd_tpc_registry_find(uint64_t id);
```

The stream-specific `src/tpc/key_registry.c` is **not deleted** in this phase — it remains for stream-only delegation key lookup. The new registry overlaps in purpose for progress tracking; both exist during the transition and the stream registry is retired in a follow-up cleanup.

---

## Refactoring Plan

### Step 1 — Credential Unification

**WebDAV:** Replace `src/webdav/tpc_cred.c` logic with a call to `xrootd_tpc_credential_parse()`. The `Credential:` header value is passed as `raw_credential`. `type` hint = `XROOTD_TPC_CRED_NONE` (auto-detect from header prefix: `"Bearer "` → TOKEN, `"-----BEGIN"` → PROXY).

**Stream:** Replace `src/tpc/tpc_token.c` and the inline GSI delegation in `gsi_outbound_certreq.c` with a call to `xrootd_tpc_credential_parse()`. The kXR delegation key resolves to a raw credential string; pass that directly.

**Validation:** Both paths call `xrootd_tpc_credential_validate()` before proceeding.

### Step 2 — Authorization Unification

**WebDAV:** `src/webdav/tpc.c` currently checks authorization with ad-hoc scope flags. Replace with `xrootd_tpc_check_authz(request_ctx->identity, src_path, dst_path, log)`.

**Stream:** `src/tpc/parse.c` authorization check replaced with `xrootd_tpc_check_authz(ctx->identity, src_path, dst_path, log)`.

Both paths now use Phase 2's `xrootd_identity_t` — meaning a token that grants write scope for `/store/data` is honored identically over stream and WebDAV TPC.

### Step 3 — Transfer Registry Integration

**WebDAV:** `src/webdav/tpc_thread.c` registers the transfer with `xrootd_tpc_registry_add()` at launch; calls `xrootd_tpc_registry_update()` on each libcurl progress callback; calls `xrootd_tpc_registry_remove()` on completion.

**Stream:** `src/tpc/launch.c` registers; `src/tpc/thread.c` updates; `src/tpc/done.c` removes.

### Step 4 — Progress / Marker Unification

WebDAV TPC sends chunked HTTP response lines (perf markers) via `src/webdav/tpc_marker.c`. Stream TPC has no equivalent (status is in the key registry). After Phase 5:

- A shared `src/tpc/common/progress.c` provides `xrootd_tpc_progress_emit()`.
- WebDAV TPC calls it to generate marker lines.
- Stream TPC ignores it (stream protocol has no perf marker concept).

Both paths read progress from the **same** registry entry, so a monitoring endpoint (dashboard or future REST API) can display all in-progress TPC transfers regardless of protocol.

---

## File Inventory

### New files
| File | Purpose |
|:---|:---|
| `src/tpc/common/credential.h` | `xrootd_tpc_credential_t` definition |
| `src/tpc/common/credential.c` | Parse + validate TPC credentials |
| `src/tpc/common/auth.c` | `xrootd_tpc_check_authz()` |
| `src/tpc/common/registry.c` | Unified transfer registry |
| `src/tpc/common/registry.h` | Public registry API |
| `src/tpc/common/transfer.h` | `xrootd_tpc_transfer_t` |
| `src/tpc/common/progress.c` | Progress emission helper |
| `src/tpc/common/metrics.c` | TPC metric helpers |
| `src/tpc/common/metrics.h` | Public metric API |

### Modified files
| File | Change |
|:---|:---|
| `src/tpc/tpc_token.c` | Delegate to `xrootd_tpc_credential_parse()` |
| `src/tpc/gsi_outbound_certreq.c` | Delegate credential validation to common layer |
| `src/tpc/parse.c` | Replace auth with `xrootd_tpc_check_authz()` |
| `src/tpc/launch.c` | Add `xrootd_tpc_registry_add()` call |
| `src/tpc/thread.c` | Add `xrootd_tpc_registry_update()` calls |
| `src/tpc/done.c` | Add `xrootd_tpc_registry_remove()` call |
| `src/webdav/tpc.c` | Replace auth with `xrootd_tpc_check_authz()` |
| `src/webdav/tpc_cred.c` | Delegate to `xrootd_tpc_credential_parse()` |
| `src/webdav/tpc_cred_parse.c` | Keep raw header parsing; remove validation logic (moved to common) |
| `src/webdav/tpc_thread.c` | Add registry integration |
| `src/webdav/tpc_marker.c` | Call `xrootd_tpc_progress_emit()` |
| `src/config/config.h` | Add `src/tpc/common/*.c` to `NGX_ADDON_SRCS` |

---

## Security Considerations

TPC is the highest-risk operation in the module. These invariants must be preserved:

1. **Credential forwarding scope**: A token with read scope on `/store/A` must never be forwarded to authenticate access to `/store/B`. `xrootd_tpc_credential_validate()` checks `identity->scopes` against both source and destination paths.
2. **Proxy certificate chain length**: Delegated proxies must not exceed configured `proxy_max_chain_depth`. Checked in `xrootd_tpc_credential_validate()`.
3. **SSRF via Source: URL**: The `Source:` URL must be validated against an allowlist (`xrootd_tpc_allowed_sources`) before curl initiates the connection. This validation already exists in `src/webdav/tpc.c` and must be preserved.
4. **SigV4 credentials never forwarded as TPC credentials**: S3 SigV4 access keys are not valid TPC credentials. `XROOTD_AUTHN_S3KEY` in `identity->auth_method` must cause `xrootd_tpc_check_authz()` to return `NGX_HTTP_FORBIDDEN`.
5. **Transfer registry overflow**: Registry is SHM-bounded. On overflow, reject new TPC requests with 503 rather than silently dropping old entries.

### Security Regression Test Set

| Scenario | Expected |
|:---|:---|
| Token with read-only scope requests TPC push | 403 |
| Delegated proxy with expired signer | 403 |
| `Source:` URL pointing to internal network (SSRF) | 403 |
| S3 access key used as TPC credential | 403 |
| Proxy chain depth > configured max | 403 |
| Valid token, valid paths, write scope present | 200 / transfer proceeds |

---

## Testing Strategy

### Unit Tests (`tests/test_tpc_common.py`)

1. **Credential parse:** Bearer token string → `XROOTD_TPC_CRED_TOKEN`, identity populated.
2. **Credential parse:** PEM proxy → `XROOTD_TPC_CRED_PROXY`, identity populated.
3. **Credential expired:** `expires_at` < now → `xrootd_tpc_credential_validate()` returns error.
4. **Authorization pass:** Valid token, write scope, within authdb → `NGX_OK`.
5. **Authorization fail:** Read-only token → `NGX_HTTP_FORBIDDEN`.

### Integration Tests (extend `tests/test_tpc.py`)

1. **Stream TPC** using delegated token — verify same credential parsing path as WebDAV.
2. **WebDAV TPC** with proxy certificate — verify same authz path as stream.
3. **Cross-check:** Same token accepted for WebDAV TPC must be accepted for stream TPC (and vice versa) if scopes match.
4. **Registry:** Start TPC transfer; query dashboard transfer list; confirm entry visible; complete transfer; confirm entry removed.
5. **SSRF:** `Source:` to `127.0.0.1` internal address → 403.

---

## Risk Assessment

| Risk | Mitigation |
|:---|:---|
| Stream TPC regression — GSI outbound cert | Keep `gsi_outbound_certreq.c` as wrapper; only validation logic moves to common |
| WebDAV curl credential injection | `xrootd_tpc_credential_validate()` runs before curl sees the credential |
| SHM registry overflow under load | Bounded size; overflow returns 503 (not silent failure) |
| Proxy depth bypass via renegotiation | Depth check in `xrootd_tpc_credential_validate()` applied to delegated chain |
| Phase 2 identity not available in stream TPC path | Stream TPC spawns from `src/tpc/parse.c` which has `xrootd_ctx_t`; identity attached in Phase 2 |

---

## Completion Criteria

- [ ] `src/tpc/common/` directory exists with all listed files
- [ ] Stream TPC credential parse calls `xrootd_tpc_credential_parse()`
- [ ] WebDAV TPC credential parse calls `xrootd_tpc_credential_parse()`
- [ ] Both TPC paths call `xrootd_tpc_check_authz()` — no local auth logic
- [ ] Both TPC paths register transfers in unified registry
- [ ] Dashboard shows in-progress TPC transfers from both protocols
- [ ] Security regression test set (6 scenarios) all pass
- [ ] Cross-protocol TPC credential acceptance test passes
- [ ] `make -j$(nproc)` clean with no warnings
