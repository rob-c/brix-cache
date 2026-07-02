# Valgrind Memcheck Findings (Phase 27 leak-triage)

This document records the memory-safety defects found by running the production
binary under **Valgrind Memcheck** (`--leak-check=full --track-fds=yes`) while
exercising real request paths, plus the fixes applied. It is the companion to
`code-audit-findings*.md` and the Phase 27 hardening work.

## Why Valgrind (and not LSan) on this host

LeakSanitizer's at-exit reporting does **not** fire for nginx under WSL2 — the
nginx exit path (SIGTERM/SIGQUIT in single-process mode) does not reach the
module `exit_process` hook or libasan's `atexit`, so leaks are never reported
even though libasan is loaded and works for a standalone program. This was
verified by injecting a deliberate `malloc()` leak that LSan never reported.

**Valgrind Memcheck works correctly here** because it instruments at the
process-termination boundary, independent of the `atexit` path. It also catches
**uninitialised reads** that ASAN/LSan miss. It is therefore the recommended
leak/UAF/uninitialised-read tool for this environment.

The production binary already carries DWARF debug info, so traces are fully
symbolised with no special rebuild.

### How the exercise is run on this host (tooling caveat)

The Bash sandbox on this WSL2 host blocks foreground `sleep` and kills
`&`-backgrounded long-lived processes when the shell call returns, so a naive
inline `valgrind … &` never gets to write its log. The reliable recipe is a
self-contained script launched fully detached, then polled from separate shell
invocations:

```bash
setsid bash run.sh </dev/null >/dev/null 2>&1 & disown    # launch, fully detached
# … in a later, separate shell call:
grep DONE results.txt                                      # poll for completion marker
```

`run.sh` starts valgrind on a minimal self-contained nginx config, waits for the
listen port, fires the request mix (token valid/garbage/malformed + PUT + S3
bad-auth/anon), `SIGTERM`s nginx, waits for the Memcheck teardown, and appends a
`DONE`/`FINISHED` marker plus the resulting `vg.log` line count.

---

## Finding 1 — Uninitialised read of `addr_text` on the WebDAV path

**Severity:** Medium (uninitialised-memory read; can copy garbage into a
client-visible/dashboard field; not directly attacker-controlled).

**File:** `src/observability/dashboard/http_tracking.c`

**Symptom (Memcheck):** "Use of uninitialised value" on the WebDAV GET path,
10 errors, traced into `dashboard_http_client()` →
`xrootd_transfer_slot_alloc_ex()` → `ngx_cpystrn()`.

**Root cause:** `dashboard_http_client()` returned
`r->connection->addr_text.data` directly. `addr_text` is an `ngx_str_t` whose
`.data` is **not NUL-terminated** — only `.len` bytes are valid and the tail of
the backing buffer is uninitialised. The dashboard slot copier uses
`ngx_cpystrn()`, which scans for a NUL terminator; handed the raw `.data` it
reads past `.len` into uninitialised memory and can copy garbage bytes into the
dashboard `client_ip` field.

**Fix:** `dashboard_http_client()` now takes a caller-supplied buffer and makes
a NUL-terminated, length-bounded copy:

```c
n = ngx_min(r->connection->addr_text.len, bufsz - 1);
ngx_memcpy(buf, r->connection->addr_text.data, n);
buf[n] = '\0';
```

The call site declares `char ipbuf[NGX_SOCKADDR_STRLEN + 1];` and passes
`dashboard_http_client(r, ipbuf, sizeof(ipbuf))`.

**Verification:** Re-ran Memcheck on the WebDAV GET path → **ERROR SUMMARY: 0
errors** (was 10).

**General lesson:** Any `ngx_str_t` sourced from nginx (`addr_text`, `uri`,
header values, …) must never be passed to a C-string API (`ngx_cpystrn`,
`strlen`, `strcpy`, `printf("%s")`). Use `.len` + `ngx_memcpy`, or make a bounded
NUL-terminated copy first. See the CLAUDE.md FAQ entry on `ngx_str_t`.

---

## Finding 2 — JWKS public-key EVP_PKEY leak on every config reload

**Severity:** Medium (recurring leak on `nginx -s reload`; unbounded growth for
long-running gateways that reload config or rotate JWKS).

**Files:** `src/auth/token/jwks.c`, `src/auth/token/token.h`, `src/auth/token/config.c`
(stream), `src/webdav/config.c` (HTTP).

**Symptom (Memcheck):** `1,680 (152 direct, 1,528 indirect) bytes in 1 blocks
are definitely lost`, the parent of ~10 indirectly-lost OpenSSL allocations:

```
malloc
  CRYPTO_zalloc / EVP_PKEY_new
  EVP_PKEY_fromdata
  xrootd_token_rsa_pubkey_from_ne   (src/auth/token/keys.c:73)
  xrootd_jwks_load_jansson          (src/auth/token/jwks.c:76)
  xrootd_jwks_load                  (src/auth/token/jwks.c:177)
  ngx_http_xrootd_webdav_merge_loc_conf (src/webdav/config.c)
  ngx_http_merge_servers / ngx_http_block
  ngx_init_cycle / main
```

**Root cause:** `xrootd_jwks_load()` parses each JWKS key into an `EVP_PKEY`
(via OpenSSL `EVP_PKEY_fromdata`) and stores the handle in the **pool-allocated**
conf array `conf->jwks_keys[]`. A matching `xrootd_jwks_free()` exists, but it
was **never registered to run when the conf pool is destroyed**. Consequences:

- On `nginx -s reload`, nginx builds a new cycle (re-parsing the config, loading
  a fresh set of `EVP_PKEY`s) and then destroys the **old** cycle's pool. The
  old conf's `jwks_keys[]` array memory is freed, but `EVP_PKEY_free()` is never
  called on the handles it held → the OpenSSL key objects leak. **Every reload
  leaks the full key set.** A gateway that reloads on a cron / JWKS rotation
  leaks unboundedly over its lifetime.
- At shutdown the same handles leak (Memcheck reports them as `definitely lost`
  because the pool memory holding the pointers is freed before exit).

Both conf load sites had the defect: the stream module (`src/auth/token/config.c`)
and the HTTP/WebDAV module (`src/webdav/config.c`).

**Fix:** A new helper registers an `ngx_pool_cleanup_t` on the conf pool whose
handler calls `xrootd_jwks_free()`:

```c
/* src/auth/token/jwks.c */
typedef struct {
    xrootd_jwks_key_t *keys;
    int               *count;   /* pointer, not value — see note below */
} xrootd_jwks_cleanup_t;

static void
xrootd_jwks_pool_cleanup(void *data)
{
    xrootd_jwks_cleanup_t *c = data;
    xrootd_jwks_free(c->keys, *c->count);
}

ngx_int_t
xrootd_jwks_register_cleanup(ngx_pool_t *pool, xrootd_jwks_key_t *keys,
    int *count)
{
    ngx_pool_cleanup_t    *cln;
    xrootd_jwks_cleanup_t *c;

    cln = ngx_pool_cleanup_add(pool, sizeof(xrootd_jwks_cleanup_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }
    c = cln->data;
    c->keys = keys;
    c->count = count;
    cln->handler = xrootd_jwks_pool_cleanup;
    return NGX_OK;
}
```

Wired at both load sites, immediately after a successful load, e.g.:

```c
/* src/webdav/config.c */
conf->jwks_key_count = rc;
if (rc > 0
    && xrootd_jwks_register_cleanup(cf->pool, conf->jwks_keys,
                                    &conf->jwks_key_count) != NGX_OK)
{
    return NGX_CONF_ERROR;
}
```

```c
/* src/auth/token/config.c */
if (xcf->jwks_key_count > 0
    && xrootd_jwks_register_cleanup(cf->pool, xcf->jwks_keys,
                                    &xcf->jwks_key_count) != NGX_OK)
{
    return NGX_ERROR;
}
```

**Why the cleanup stores a pointer to the count, not the value:** the JWKS
refresh path (`src/auth/token/refresh.c`) rewrites the same `jwks_keys[]` array in
place — it calls `xrootd_jwks_free()` on the old set, then `memcpy`s the new set
in and updates `jwks_key_count`. Because the cleanup reads `*count` at
pool-destroy time (not at registration time), it frees whatever set is current,
and because `xrootd_jwks_free()` nulls each slot before the refresh overwrites
it with a new non-NULL handle, there is **no double-free**.

**nginx ordering guarantee relied upon:** pool cleanup handlers run *before* the
pool's memory blocks are freed, so reading `conf->jwks_key_count` (which lives in
that same pool) inside the handler is safe.

**Verification:** Rebuilt, re-ran the token/JWT Memcheck exercise → the JWKS
frames are **gone**; the only remaining `definitely lost` is the benign
nginx-core `ngx_set_environment` (nginx.c:591, 8 bytes — nginx's own startup
allocation, off-limits per build governance). Regression suite:
`test_token_auth.py`, `test_token_jwks_refresh.py`, `test_token_security.py`
(95 tests) and `test_phase27_memsafety.py` (11 tests) all pass.

---

## Residual Memcheck output (all benign, no action)

After both fixes, the token/S3 exercise leaves only non-module items:

| Item | Source | Disposition |
|---|---|---|
| `definitely lost: 8 bytes` | `ngx_set_environment` (nginx.c:591) | nginx-core; build governance forbids editing nginx source |
| `possibly lost: 128 bytes` | libc/pthread thread-local internals | library-internal; not module code |
| `still reachable: ~362 KB` | config-lifetime structures held until exit | intentional; freed by OS at exit |
| 4× FILE DESCRIPTORS open at exit | epoll eventfd, `epoll_create`, `error.log`, stderr `dup2` | nginx-core event/log fds; none are XRootD/module fds |

No XRootD/module-code leaks, uninitialised reads, fd leaks, or invalid accesses
remain on the exercised paths (stream login/stat/open/readv/close, WebDAV
GET/PUT, token JWT verify, S3 SigV4 reject/anon).

---

## Committed harness

The exercise is now a committed, repeatable harness under **`tests/valgrind/`**
(see its `README.md`):

- `nginx.conf.in` — one config covering all planes, run with `master_process on`
  + a single worker so **TLS actually serves** (the old `master_process off`
  scratch could not reach the GSI/TLS or TPC paths). Derived from the real
  `tests/configs/nginx_shared.conf` + `nginx_webdav_tpc.conf`.
- `run_valgrind.sh` — renders the config, launches Memcheck with
  `--trace-children=yes` and per-pid logs, drives the request mix, stops nginx
  gracefully so the **worker** (which handled the requests) flushes a complete
  report, then triages every log for module frames.
- `valgrind.supp` — native-format suppressions for benign nginx-core/library
  residuals only (never module frames).

A `VALGRIND=1` mode in `tests/manage_test_servers.sh` can additionally run the
whole generated fleet under Memcheck. Regression guards are in
`tests/test_valgrind_regression.py` (static markers that fail if either fix is
reverted, plus an opt-in `RUN_VALGRIND=1` end-to-end run).

### Worker-vs-master shutdown note

With a real worker, the nginx **master** reaps the worker on shutdown and runs
`ngx_unlock_mutexes()` → `ngx_shmtx_force_unlock()` over the (single-worker,
uninitialised) accept mutex, which NULL-derefs **under valgrind** (it does not
without valgrind; the fleet stops cleanly). This is nginx-**core** only
(`ngx_shmtx.c` / `ngx_process.c`, off-limits to edit). The harness sidesteps it
by discarding the master's log and triaging the clean worker report.

## Coverage

**Now exercised under Memcheck (all module-clean — 0 leaks, 0 uninitialised
reads, 0 invalid accesses, no module frames):** stream `root://`
(login/stat/open/read/readv/close incl. open-without-close + disconnect — fd
reclaim confirmed), WebDAV GET/PUT, bearer-token verify (valid / garbage /
malformed → jansson + OpenSSL EVP RSA), **GSI/TLS x509 proxy-cert auth**
(OpenSSL chain verify; client-cert accepted, no-cert/bad-cert rejected),
**libcurl TPC** (WebDAV `COPY` reaching the curl perform + failure-cleanup paths
— no curl/SSL fd left open at exit), the **macaroon `/.oauth2/token` endpoint**,
and S3 SigV4 (bad-signature reject + anonymous). The extended run surfaced **no
new defects** — Findings 1 and 2 remain the only module-code issues found.

**Residual gaps (documented, not blocking):**
- Macaroon **minting** returns a small response in the harness (the issued-token
  body was not consumed for a follow-up verify); the endpoint parse + HMAC path
  is exercised, but a full mint→use round-trip is a future improvement.
- OAuth2 token-exchange against a live IdP (`src/auth/token/oauth2.c`) is only reached
  via the TPC token-endpoint delegation path; not driven standalone here.
