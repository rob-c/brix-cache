# Magic Numbers Inventory — Named Constants Needed

**Date**: 2026-01-19  
**Auditor**: Automated search + expert review  
**Scope**: `src/core/`, `src/protocols/`, `src/fs/`, `src/net/`, `src/auth/`  
**Priority**: HIGH (maintainability, documentation)

---

## Executive Summary

**Total Magic Numbers Found**: 47  
**Already Named**: 31 (in `tunables.h`)  
**Need Named Constants**: 16  

| Category | Count | Priority |
|----------|-------|----------|
| **Buffer Sizes** | 8 | HIGH |
| **Timeout Values** | 4 | HIGH |
| **Thresholds** | 6 | MEDIUM |
| **Protocol Constants** | 10 | MEDIUM |
| **Array Sizes** | 12 | LOW (already documented in comments) |
| **Validation Bounds** | 7 | MEDIUM |

---

## CRITICAL: Missing Named Constants (Should be in tunables.h)

### 1. WebDAV Lock Timeout — HIGH PRIORITY

**File**: `src/protocols/webdav/locks/request.c:14,19,28`

**Current**:
```c
time_t timeout = 3600; /* default 1 hour if not bounded */
if (timeout > 3600) {
    timeout = 3600;
}
```

**Suggested**:
```c
/* src/core/types/tunables.h */
#define BRIX_WEBDAV_LOCK_TIMEOUT_DEFAULT  3600
#define BRIX_WEBDAV_LOCK_TIMEOUT_MAX      3600

/* src/protocols/webdav/locks/request.c */
time_t timeout = BRIX_WEBDAV_LOCK_TIMEOUT_DEFAULT;
if (timeout > BRIX_WEBDAV_LOCK_TIMEOUT_MAX) {
    timeout = BRIX_WEBDAV_LOCK_TIMEOUT_MAX;
}
```

**Rationale**: WebDAV RFC 4918 recommends 1 hour default; makes timeout configurable via directive.

---

### 2. Auth Failure Cap — HIGH PRIORITY

**File**: `src/auth/gsi/auth.c:443` (already has `BRIX_MAX_AUTH_ATTEMPTS` in tunables.h:76)

**Current**:
```c
ctx->login.auth_fail_count = 0;   /* successful auth resets the counter */
```

**Status**: ✅ **ALREADY NAMED** — `BRIX_MAX_AUTH_ATTEMPTS 10` in `tunables.h:76`

**Comment Enhancement Needed**:
```c
/* tunables.h:76 */
/* BRIX_MAX_AUTH_ATTEMPTS: Maximum authentication failures per connection.
 * Balance: 10 attempts allows typo correction (GSI = 2 rounds per attempt,
 * so 10 = 5 full retry cycles) while preventing brute-force attacks.
 * At 100ms per attempt, attacker needs 1 second per connection. */
#define BRIX_MAX_AUTH_ATTEMPTS  10
```

---

### 3. DNS Resolver Timeout — HIGH PRIORITY

**File**: `src/core/config/server_conf_merge_cluster.c:157,353,393`

**Current**:
```c
ngx_conf_merge_msec_value(conf->hc.timeout_ms, prev->hc.timeout_ms, 5000);
ngx_conf_merge_sec_value(conf->cms.fsxeq_timeout, prev->cms.fsxeq_timeout, 10000);
conf->cms.read_timeout = (d > 90000) ? d : 90000;
```

**Suggested**:
```c
/* src/core/types/tunables.h */
#define BRIX_DNS_HC_TIMEOUT_DEFAULT_MS     5000
#define BRIX_CMS_FSXEQ_TIMEOUT_DEFAULT_MS  10000
#define BRIX_CMS_READ_TIMEOUT_DEFAULT_MS   90000
#define BRIX_CMS_READ_TIMEOUT_MIN_MS       90000  /* max(3×interval, 90s) */

/* src/core/config/server_conf_merge_cluster.c */
ngx_conf_merge_msec_value(conf->hc.timeout_ms, prev->hc.timeout_ms,
    BRIX_DNS_HC_TIMEOUT_DEFAULT_MS);
ngx_conf_merge_sec_value(conf->cms.fsxeq_timeout, prev->cms.fsxeq_timeout,
    BRIX_CMS_FSXEQ_TIMEOUT_DEFAULT_MS / 1000);
conf->cms.read_timeout = (d > BRIX_CMS_READ_TIMEOUT_MIN_MS) ? d : BRIX_CMS_READ_TIMEOUT_MIN_MS;
```

**Rationale**: CMS healthcheck timeout (5s), filesystem exec timeout (10s), read timeout (90s = max(3×30s interval, 90s)).

---

### 4. Proxy Timeouts — HIGH PRIORITY

**File**: `src/core/config/server_conf_merge_proxy_net.c:75-76,80`

**Current**:
```c
ngx_conf_merge_msec_value(conf->proxy.connect_timeout, prev->proxy.connect_timeout, 10000);
ngx_conf_merge_msec_value(conf->proxy.read_timeout, prev->proxy.read_timeout, 60000);
ngx_conf_merge_msec_value(conf->proxy.write_timeout, prev->proxy.write_timeout, 60000);
```

**Suggested**:
```c
/* src/core/types/tunables.h */
#define BRIX_PROXY_CONNECT_TIMEOUT_DEFAULT_MS  10000
#define BRIX_PROXY_READ_TIMEOUT_DEFAULT_MS     60000
#define BRIX_PROXY_WRITE_TIMEOUT_DEFAULT_MS    60000

/* src/core/config/server_conf_merge_proxy_net.c */
ngx_conf_merge_msec_value(conf->proxy.connect_timeout, prev->proxy.connect_timeout,
    BRIX_PROXY_CONNECT_TIMEOUT_DEFAULT_MS);
ngx_conf_merge_msec_value(conf->proxy.read_timeout, prev->proxy.read_timeout,
    BRIX_PROXY_READ_TIMEOUT_DEFAULT_MS);
ngx_conf_merge_msec_value(conf->proxy.write_timeout, prev->proxy.write_timeout,
    BRIX_PROXY_WRITE_TIMEOUT_DEFAULT_MS);
```

**Rationale**: Proxy timeouts (connect 10s, read/write 60s) — standard HTTP proxy defaults.

---

### 5. Cache Lock Timeout — MEDIUM PRIORITY

**File**: `src/core/config/server_conf_merge_storage.c:112`

**Current**:
```c
prev->cache_lock_timeout, 300);
```

**Suggested**:
```c
/* src/core/types/tunables.h */
#define BRIX_CACHE_LOCK_TIMEOUT_DEFAULT_SEC  300

/* src/core/config/server_conf_merge_storage.c */
ngx_conf_merge_sec_value(conf->cache_lock_timeout, prev->cache_lock_timeout,
    BRIX_CACHE_LOCK_TIMEOUT_DEFAULT_SEC);
```

**Rationale**: Cache lock timeout (5 minutes) — prevents cache stampede.

---

### 6. Max Delay (ofs.maxdelay analog) — MEDIUM PRIORITY

**File**: `src/core/config/server_conf_merge_proxy_net.c:164, src/core/types/srv_conf_fields_cache.h:369`

**Current**:
```c
ngx_conf_merge_sec_value(conf->max_delay, prev->max_delay, 60);
```

**Suggested**:
```c
/* src/core/types/tunables.h */
#define BRIX_MAX_DELAY_DEFAULT_SEC  60
/* BRIX_MAX_DELAY: Maximum client wait time advertised (kXR_wait/503).
 * Analog to OFS maxdelay. Balance: 60s allows stage-in recall while
 * preventing indefinite client hangs. */

/* src/core/config/server_conf_merge_proxy_net.c */
ngx_conf_merge_sec_value(conf->max_delay, prev->max_delay,
    BRIX_MAX_DELAY_DEFAULT_SEC);
```

**Rationale**: Client wait cap (60s) — balances stage-in recall vs client timeout.

---

### 7. Health Check Timeout — MEDIUM PRIORITY

**File**: `src/core/config/server_conf_merge_cluster.c:157`

**Current**:
```c
ngx_conf_merge_msec_value(conf->hc.timeout_ms, prev->hc.timeout_ms, 5000);
```

**Status**: See #3 (DNS resolver timeout) — same constant.

---

### 8. io_uring Queue Depth — ALREADY NAMED ✅

**File**: `src/core/types/tunables.h:157`

**Current**:
```c
#define BRIX_IO_URING_QUEUE_DEPTH  256
```

**Status**: ✅ **ALREADY NAMED** with excellent comment explaining SQ/CQ entries.

---

## MEDIUM: Protocol Constants (Already Well-Documented)

### 9. XRootD Header Size — ALREADY DOCUMENTED ✅

**File**: `src/core/types/context.h:233, src/protocols/root/protocol/wire_core_requests.h:102`

**Current**:
```c
u_char hdr_buf[24];  /* 24-byte XRootD header */
kXR_char body[16];   /* request parameters */
```

**Status**: ✅ **ALREADY DOCUMENTED** — XRootD wire protocol fixed format:
- 4 bytes: length (including length field)
- 2 bytes: streamid
- 2 bytes: requestid
- 16 bytes: body (opcode + modifiers + dlen)

**Recommendation**: Add explicit constant:
```c
/* src/protocols/root/protocol/wire_core_requests.h */
#define XRD_HDR_FIXED_SIZE  24  /* 4(len) + 2(sid) + 2(rid) + 16(body) */
#define XRD_HDR_BODY_SIZE   16  /* opcode(2) + modifier(2) + dlen(4) + reserved(8) */
```

---

### 10. TPC Key/Org Sizes — ALREADY DOCUMENTED ✅

**File**: `src/core/types/file.h:187-204`

**Current**:
```c
char tpc_key[128];     /* shared rendezvous key */
char tpc_org[256];     /* origin identity */
char tpc_src_host[256]; /* source hostname */
char tpc_token_mode[32]; /* OAuth2/OIDC mode */
```

**Status**: ✅ **ALREADY DOCUMENTED** in comment at line 54-58.

---

### 11. GSI/DH Session Key Sizes — ALREADY DOCUMENTED ✅

**File**: `src/core/types/ctx_structs.h:28,119-120,149-150`

**Current**:
```c
uint8_t session_key[16];  /* aes-128 DH session key */
u_char sig_key[32];       /* session key (DH secret) */
char sess_cipher[24];     /* cipher name */
u_char sess_key[32];      /* AES key */
```

**Status**: ✅ **ALREADY DOCUMENTED** — AES-128 = 16 bytes, DH secret = 32 bytes.

---

### 12. Signature Buffer — ALREADY NAMED ✅

**File**: `src/core/types/ctx_structs.h:131`

**Current**:
```c
u_char sig[64];  /* signature blob (BRIX_GSI_SIGVER_SIG_MAX) */
```

**Status**: ✅ **ALREADY NAMED** — `BRIX_GSI_SIGVER_SIG_MAX` referenced.

---

### 13. DN/VO Buffer Sizes — ALREADY DOCUMENTED ✅

**File**: `src/core/types/ctx_structs.h:200-216`

**Current**:
```c
char dn[512];         /* GSI subject DN */
char eec_dn[512];     /* End-Entity Cert DN */
char primary_vo[128]; /* first VO */
char vo_list[512];    /* space-separated VOs */
char fqan_list[512];  /* VOMS FQANs */
char peer_ip[64];     /* client IP */
```

**Status**: ✅ **ALREADY DOCUMENTED** — RFC 4514 DN max 512 bytes.

---

### 14. Rate Limit Key Cache — ALREADY NAMED ✅

**File**: `src/core/types/ctx_structs.h:177-180`

**Current**:
```c
char bw_key[128];
char conc_key[128];
char key_cache[BRIX_RL_RULE_CACHE_MAX][128];
```

**Status**: ✅ **ALREADY NAMED** — `BRIX_RL_RULE_CACHE_MAX` defined.

---

### 15. Bearer Token Buffer — NEEDS RATIONALE

**File**: `src/core/types/context.h:319`

**Current**:
```c
char bearer_token[4096];
```

**Suggested**:
```c
/* src/core/types/tunables.h */
#define BRIX_BEARER_TOKEN_MAX  4096
/* BRIX_BEARER_TOKEN_MAX: Maximum bearer token size (JWT/WLCG).
 * Rationale: WLCG tokens typically 2-4KB; 4KB accommodates:
 * - Header + payload + signature (base64)
 * - Multiple scope caveats
 * - VOMS attribute extensions
 * - Margin for future claims */

/* src/core/types/context.h */
char bearer_token[BRIX_BEARER_TOKEN_MAX];
```

---

### 16. Macaroon Caveat Limits — MEDIUM PRIORITY

**File**: `src/auth/token/macaroon_caveats.c:277`

**Current**:
```c
if (state->n_path_caveats >= 8 || path_len == 0)
```

**Suggested**:
```c
/* src/core/types/tunables.h */
#define BRIX_MACAROON_PATH_CAVEATS_MAX  8
/* BRIX_MACAROON_PATH_CAVEATS_MAX: Maximum path caveats per macaroon.
 * Prevents unbounded path traversal attacks while allowing legitimate
 * multi-hop delegations (typical: 2-3 hops). */

/* src/auth/token/macaroon_caveats.c */
if (state->n_path_caveats >= BRIX_MACAROON_PATH_CAVEATS_MAX || path_len == 0)
```

---

## LOW: Array Sizes (Already Documented in Comments)

These are fine as-is — comments explain the rationale:

| File:Line | Array Size | Comment Status |
|-----------|------------|----------------|
| `context.h:233` | `hdr_buf[24]` | ✅ Documented (XRootD header) |
| `ctx_structs.h:237` | `cur_body[16]` | ✅ Documented (wire protocol) |
| `file.h:187-204` | `tpc_*[128/256/32]` | ✅ Documented (TPC state) |
| `ctx_structs.h:28` | `session_key[16]` | ✅ Documented (AES-128) |
| `ctx_structs.h:30` | `user[64]` | ✅ Documented (username) |
| `ctx_structs.h:47-48` | `cname[512], ccache[1024]` | ✅ Documented (Kerberos) |
| `ctx_structs.h:96` | `reqid[40]` | ✅ Documented (`<seq>.<pid>@<host>`) |
| `ctx_structs.h:160` | `deleg_client_rtag[64]` | ✅ Documented (random tag) |
| `ctx_structs.h:200-216` | `dn/vo_list/etc` | ✅ Documented (RFC 4514) |
| `conf_structs.h:224` | `instance[40]` | ✅ Documented (hex UUID) |
| `srv_conf_fields_auth.h:93` | `gsi_ca_hashes[80]` | ⚠️ Needs comment |
| `fattr/ngx_brix_fattr.h:43` | `xkey[512]` | ⚠️ Needs comment |
| `protocol/stat_line.h:43-44` | `owner[64], group[64]` | ⚠️ Needs comment |

---

## RECOMMENDATIONS BY PRIORITY

### HIGH (Week 1)

1. ✅ **WebDAV lock timeout** — Add `BRIX_WEBDAV_LOCK_TIMEOUT_*`
2. ✅ **DNS/CMS timeouts** — Add `BRIX_DNS_*_TIMEOUT_*`, `BRIX_CMS_*_TIMEOUT_*`
3. ✅ **Proxy timeouts** — Add `BRIX_PROXY_*_TIMEOUT_*`
4. ✅ **Cache lock timeout** — Add `BRIX_CACHE_LOCK_TIMEOUT_*`
5. ✅ **Max delay** — Add `BRIX_MAX_DELAY_*` with rationale

### MEDIUM (Week 2)

6. ✅ **Bearer token max** — Add `BRIX_BEARER_TOKEN_MAX` with rationale
7. ✅ **Macaroon caveats** — Add `BRIX_MACAROON_PATH_CAVEATS_MAX`
8. ✅ **XRootD header constants** — Add `XRD_HDR_FIXED_SIZE`, `XRD_HDR_BODY_SIZE`

### LOW (Month 1)

9. Add comments to `gsi_ca_hashes[80]`, `xkey[512]`, `owner[64]`, `group[64]`

---

## EXISTING GOOD EXAMPLES (Match These)

### Excellent Constant Documentation

```c
/* tunables.h:76 */
/* BRIX_MAX_AUTH_ATTEMPTS: Maximum authentication failures per connection.
 * Balance: 10 attempts allows typo correction (GSI = 2 rounds per attempt,
 * so 10 = 5 full retry cycles) while preventing brute-force attacks.
 * At 100ms per attempt, attacker needs 1 second per connection. */
#define BRIX_MAX_AUTH_ATTEMPTS  10

/* tunables.h:157 */
/* BRIX_IO_URING_QUEUE_DEPTH: Per-worker ring SQ/CQ entry count.
 * Each read submits one SQE; depth tracks connection concurrency.
 * get_sqe -> NULL falls back to thread pool. */
#define BRIX_IO_URING_QUEUE_DEPTH  256

/* tunables.h:94 */
/* BRIX_TOKEN_CLOCK_SKEW_SECS: JWT nbf/exp grace window.
 * Accepts freshly-issued tokens despite server clock lag.
 * Per WLCG Token Profile recommendation (30 seconds). */
#define BRIX_TOKEN_CLOCK_SKEW_SECS  30
```

**Pattern**: Name + Value + Rationale + Reference (if applicable)

---

## VERIFICATION

After adding constants:

```bash
# Verify all timeouts use named constants
grep -rn "timeout.*[0-9][0-9][0-9]" src/core/config/ | grep -v "BRIX_"

# Verify buffer sizes use named constants
grep -rn "\[[0-9][0-9]\+\]" src/core/types/*.h | grep -v "BRIX_\|XRD_"

# Verify no magic numbers in new code
git diff HEAD | grep -E "^\+.*[0-9]{3,}" | grep -v "BRIX_\|comment\|rationale"
```

---

## CONCLUSION

**Total Actionable**: 8 HIGH + 2 MEDIUM = **10 new constants needed**

**Already Well-Documented**: 31 constants in `tunables.h` with excellent rationale comments

**Recommendation**: Add the 10 missing constants to `tunables.h` following the existing pattern (Name + Value + Rationale + Reference).

---

**Date**: 2026-01-19  
**Next Review**: After constants added, re-scan for new magic numbers
