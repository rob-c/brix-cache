# Phase 2: Identity Abstraction - Implementation Plan

**Status:** PLANNING  
**Phase:** 2 of 6 (Protocol Unification)  
**Depends On:** Phase 1 (Unified Path Resolver)  
**Estimated Effort:** 10-14 hours  
**Risk Level:** HIGH (touches auth across all protocols)  
**Target:** Single `xrootd_identity_t` struct produced by all auth paths, consumed by all policy checks

---

## Executive Summary

Authentication and authorization state is currently scattered across at least three distinct structures, one per protocol family. This means a GSI certificate parsed for a Stream connection goes through entirely different codepaths than one presented over WebDAV HTTPS, creating both a maintenance burden and a divergence risk for security-sensitive logic.

**Current fragmentation:**

| Protocol | Auth State Lives In | Populated By |
|:---|:---|:---|
| XRootD Stream | `xrootd_ctx_t` (`src/protocols/root/session/session.h`) | `src/protocols/root/session/login.c`, `src/auth/gsi/parse.c`, `src/auth/token/validate.c` |
| WebDAV/HTTPS | `ngx_http_xrootd_webdav_req_ctx_t` (`src/protocols/webdav/webdav.h`) | `src/protocols/webdav/auth_cert.c`, `src/protocols/webdav/auth_token.c` |
| S3 REST | Inline locals in `src/protocols/s3/auth_sigv4_verify.c` | SigV4 HMAC verification; no persistent identity struct |

After this phase every auth path **produces** an `xrootd_identity_t` and every policy path **consumes** one. Protocol-specific wire translation (kXR login handshake, HTTP `Authorization:` header, SigV4 signature) stays in its own layer; the shared layer starts the moment credentials are validated.

---

## Current State Analysis

### Stream Identity (`xrootd_ctx_t`)

Defined in `src/protocols/root/session/session.h`. Relevant fields:

```c
// Fields spread across the session context today
ngx_str_t   dn;          // GSI Distinguished Name
ngx_str_t   token_sub;   // JWT 'sub' claim  
ngx_array_t *voms_attrs; // VOMS FQANs
ngx_uint_t  auth_method; // AUTHN_NONE / AUTHN_GSI / AUTHN_TOKEN / AUTHN_SSS
unsigned int authed:1;
```

Populated by:
- `src/protocols/root/session/login.c` — dispatches to GSI/Token/SSS sub-handlers
- `src/auth/gsi/parse.c` — X.509 parse, proxy validation, VOMS extraction
- `src/auth/token/validate.c` — JWT signature check, scope extraction
- `src/auth/sss/` — Shared-Secret handshake

### HTTP Identity (`ngx_http_xrootd_webdav_req_ctx_t`)

Defined in `src/protocols/webdav/webdav.h`. Fields are more ad-hoc:

```c
// Scattered auth fields in the WebDAV request context
ngx_str_t   client_dn;
ngx_str_t   bearer_sub;
ngx_uint_t  auth_flags;    // bitmask
unsigned int has_write_scope:1;
unsigned int has_read_scope:1;
```

Populated by:
- `src/protocols/webdav/auth_cert.c` — mTLS cert extraction, `webdav_verify_proxy_cert()`
- `src/protocols/webdav/auth_token.c` — Bearer token, `webdav_verify_bearer_token()`, scope check

### S3 Identity (No Persistent Struct)

`src/protocols/s3/auth_sigv4_verify.c` verifies the HMAC signature against configured credentials but does **not** produce any reusable identity object. Access key ID is available locally but never stored for later ACL checks.

---

## Target Architecture

### New Shared Header: `src/core/types/identity.h`

```c
#ifndef XROOTD_IDENTITY_H
#define XROOTD_IDENTITY_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * Authentication method constants.
 * Protocol-agnostic; the wire mechanism is irrelevant above this layer.
 */
#define XROOTD_AUTHN_NONE     0x00
#define XROOTD_AUTHN_GSI      0x01   /* X.509 / proxy certificate */
#define XROOTD_AUTHN_TOKEN    0x02   /* WLCG/SCITOKENS JWT bearer */
#define XROOTD_AUTHN_SSS      0x04   /* Shared-Secret (stream only) */
#define XROOTD_AUTHN_S3KEY    0x08   /* SigV4 access key */

/*
 * xrootd_identity_t — canonical representation of a verified principal.
 *
 * WHAT: One struct to hold all auth state after credential verification.
 * WHY:  Centralizing this eliminates protocol-specific ACL codepaths.
 *       A policy module only needs to know "who" — not "how they proved it".
 * HOW:  Auth sub-systems (GSI, JWT, SSS, SigV4) fill this struct.
 *       Policy sub-systems (ACL, authdb, VOMS) read it.
 *       The struct is allocated from the request/session pool.
 */
typedef struct {
    /* Verified principal identifiers */
    ngx_str_t    dn;            /* GSI Distinguished Name (may be empty) */
    ngx_str_t    subject;       /* JWT 'sub' claim or S3 access key ID */
    ngx_str_t    issuer;        /* JWT 'iss' claim (empty for non-JWT) */

    /* Group membership */
    ngx_array_t *vo_list;       /* ngx_str_t[]: VOMS FQANs / JWT 'wlcg.groups' */
    ngx_array_t *scopes;        /* ngx_str_t[]: OAuth2 scope strings */

    /* Flags */
    ngx_uint_t   auth_method;   /* XROOTD_AUTHN_* bitmask */
    unsigned int is_authenticated:1;
    unsigned int is_admin:1;
    unsigned int has_write_scope:1;  /* pre-computed for hot path */
    unsigned int has_read_scope:1;
} xrootd_identity_t;

/*
 * Allocate a zeroed identity in the given pool.
 * All pointer fields are NULL; auth_method is XROOTD_AUTHN_NONE.
 */
xrootd_identity_t *xrootd_identity_alloc(ngx_pool_t *pool);

/*
 * Return a human-readable summary for logging (pool-allocated).
 * Format: "dn=<dn> sub=<sub> method=<GSI|TOKEN|SSS|S3KEY|NONE>"
 */
ngx_str_t xrootd_identity_describe(const xrootd_identity_t *id,
                                   ngx_pool_t *pool);

#endif /* XROOTD_IDENTITY_H */
```

### New Implementation: `src/core/types/identity.c`

Small — only `xrootd_identity_alloc()` and `xrootd_identity_describe()`. No auth logic lives here.

---

## Refactoring Plan

### Step 1 — GSI: Unify `src/auth/gsi/parse.c`

**Current signature:**
```c
ngx_int_t xrootd_gsi_parse_cert(ngx_ssl_conn_t *ssl,
                                 xrootd_ctx_t *ctx,
                                 ngx_log_t *log);
```

**New signature (backward-compatible shim kept during transition):**
```c
ngx_int_t xrootd_gsi_parse_cert(ngx_ssl_conn_t *ssl,
                                 xrootd_identity_t *id,
                                 ngx_pool_t *pool,
                                 ngx_log_t *log);
```

The function now fills `id->dn`, `id->vo_list`, and sets `id->auth_method |= XROOTD_AUTHN_GSI`. The caller is responsible for attaching the `xrootd_identity_t` to the per-request/session context.

### Step 2 — Token: Unify `src/auth/token/validate.c`

**Current:** Returns a bitmask of validated scopes into stream-specific fields.

**New:**
```c
ngx_int_t xrootd_token_validate(const ngx_str_t *bearer,
                                 xrootd_identity_t *id,
                                 ngx_pool_t *pool,
                                 ngx_log_t *log);
```

Fills `id->subject`, `id->issuer`, `id->scopes`, `id->has_write_scope`, `id->has_read_scope`. Sets `id->auth_method |= XROOTD_AUTHN_TOKEN`.

`src/auth/token/scopes.c` scope-checking helpers remain unchanged; they now accept `xrootd_identity_t *` instead of protocol-specific context pointers.

### Step 3 — SSS: Unify `src/auth/sss/`

SSS is stream-only but its output (a verified DN or group) should still fill `xrootd_identity_t` so downstream ACL code needs no special case.

```c
ngx_int_t xrootd_sss_verify(const xrootd_sss_header_t *hdr,
                             xrootd_identity_t *id,
                             ngx_pool_t *pool,
                             ngx_log_t *log);
```

### Step 4 — S3 SigV4: `src/protocols/s3/auth_sigv4_verify.c`

Add an `xrootd_identity_t *` output parameter. Fill `id->subject` with the verified access key ID. Set `id->auth_method |= XROOTD_AUTHN_S3KEY`. This allows `src/protocols/s3/` to participate in unified audit logging.

```c
ngx_int_t xrootd_s3_sigv4_verify(ngx_http_request_t *r,
                                   const xrootd_s3_conf_t *conf,
                                   xrootd_identity_t *id,
                                   ngx_log_t *log);
```

### Step 5 — Policy: Update `src/auth/authz/acl.c` and `src/protocols/root/session/login.c`

`src/auth/authz/acl.c` currently takes a raw `dn` string. Change to:

```c
ngx_int_t xrootd_check_authdb(const xrootd_identity_t *id,
                               const ngx_str_t *resolved_path,
                               ngx_uint_t op_flags,
                               ngx_log_t *log);
```

`src/protocols/root/session/login.c` builds an `xrootd_identity_t` from GSI/Token/SSS results and stores it into `xrootd_ctx_t->identity` (a new pointer field).

WebDAV request context `ngx_http_xrootd_webdav_req_ctx_t` gains a single `xrootd_identity_t *identity` pointer; all individual auth fields (`client_dn`, `bearer_sub`, auth flags) are removed.

### Step 6 — VOMS: `src/auth/voms/`

VOMS extraction (FQAN parsing) already produces an array. It now fills `id->vo_list` directly instead of the session/request context.

---

## File Inventory

### New files
| File | Purpose |
|:---|:---|
| `src/core/types/identity.h` | Canonical header — `xrootd_identity_t` definition |
| `src/core/types/identity.c` | `xrootd_identity_alloc()`, `xrootd_identity_describe()` |

### Modified files
| File | Change |
|:---|:---|
| `src/auth/gsi/parse.c` | Output into `xrootd_identity_t *` instead of `xrootd_ctx_t *` |
| `src/auth/token/validate.c` | Output into `xrootd_identity_t *` |
| `src/auth/token/scopes.c` | Accept `xrootd_identity_t *` for scope check helpers |
| `src/auth/sss/*.c` | Output into `xrootd_identity_t *` |
| `src/protocols/s3/auth_sigv4_verify.c` | Add `xrootd_identity_t *` output |
| `src/auth/voms/*.c` | Fill `id->vo_list` |
| `src/auth/authz/acl.c` | Accept `xrootd_identity_t *` |
| `src/protocols/root/session/session.h` | Add `xrootd_identity_t *identity` field |
| `src/protocols/root/session/login.c` | Build and attach identity struct |
| `src/protocols/webdav/webdav.h` | Replace scattered auth fields with `xrootd_identity_t *identity` |
| `src/protocols/webdav/auth_cert.c` | Populate `xrootd_identity_t` via `xrootd_gsi_parse_cert()` |
| `src/protocols/webdav/auth_token.c` | Populate `xrootd_identity_t` via `xrootd_token_validate()` |
| `src/core/config/config.h` | Add `src/core/types/identity.c` to `NGX_ADDON_SRCS` |

---

## Protocol Boundaries (What Does NOT Change)

The following remain protocol-specific. Identity abstraction only applies **after** the wire-level credential has been parsed:

- Stream: `kXR_login` / `kXR_auth` handshake framing (`src/protocols/root/handshake/dispatch.c`)
- WebDAV: HTTP `Authorization:` header extraction, TLS client cert retrieval
- S3: `Authorization: AWS4-HMAC-SHA256` header parsing and HMAC computation

These layers produce the raw credential material. The new auth functions receive that material and produce `xrootd_identity_t`.

---

## Testing Strategy

### Unit Tests (new file `tests/test_identity.py`)

1. **Success path:** GSI-only identity — dn populated, method=GSI, scopes empty.
2. **Success path:** Token identity — sub/iss/scopes populated, method=TOKEN.
3. **Combined:** GSI + Token both presented — method bitmask includes both flags.
4. **Security negative:** Expired/invalid token → `xrootd_token_validate()` returns error, identity struct not marked `is_authenticated`.
5. **S3 key:** Valid SigV4 → `id->subject` = access key ID.

### Integration Tests (extend `tests/run_cross_compatible_tests.sh`)

- Same GSI cert presented over Stream port 11094 and WebDAV port 8444 must resolve to identical `dn` string in access log.
- Same WLCG token presented over Stream and S3 must log identical `sub` claim.

### Security Regression Set (must pass before merge)

| Scenario | Expected |
|:---|:---|
| JWT with `alg: none` | Rejected — `XROOTD_AUTHN_NONE`, `is_authenticated=0` |
| JWT signed with wrong key | Rejected |
| Proxy cert with expired signer | Rejected |
| S3 key with wrong signature | Rejected — no identity populated |
| VOMS FQAN injection via `\n` in DN | Sanitized — no FQAN accepted |

---

## Risk Assessment

| Risk | Mitigation |
|:---|:---|
| Changing GSI/token function signatures breaks callers | Use shim wrappers during transition; remove after all callers updated |
| `xrootd_identity_t` pool lifetime mismatch | Identity always allocated from the request/session pool; no dangling pointers |
| S3 SigV4 identity used for WLCG ACL checks | Distinct `auth_method` flag — ACL code rejects XROOTD_AUTHN_S3KEY for VOMS checks |
| Regression in SSS (stream-only) | SSS integration tests (`tests/test_sss.py`) in cross-backend suite |

---

## Completion Criteria

- [ ] `xrootd_identity_t` defined in `src/core/types/identity.h`
- [ ] All auth sub-systems produce `xrootd_identity_t` (GSI, Token, SSS, SigV4)
- [ ] `src/auth/authz/acl.c` accepts `xrootd_identity_t *` — no protocol-specific fields
- [ ] Stream and WebDAV contexts each hold `xrootd_identity_t *identity` (single pointer)
- [ ] Security regression test set passes for all 5 negative scenarios
- [ ] Cross-protocol identity consistency tests pass (same cert → same DN in both access logs)
- [ ] `make -j$(nproc)` clean with no warnings
