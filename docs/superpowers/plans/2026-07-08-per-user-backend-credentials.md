# Per-User Backend Credentials (Phase 1: Selection) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When a davs:// or S3 request authenticated as user U reads from or writes to a remote `root://` origin through the VFS, the origin session for that request authenticates as U's admin-provisioned x509 proxy — falling back to the static service credential only when `brix_storage_credential_fallback allow` (the default); `deny` refuses loudly.

**Architecture:** Origin sessions are already per-open (`sd_xroot.c` builds a fresh TCP+bootstrap per `driver->open`), so per-user auth is a per-open credential override on the per-open `brix_cache_fill_t` — no connection-pool or session-keying rework. Identity already flows into `brix_vfs_ctx_t.identity`; the only new seam is two optional driver-vtable slots (`open_cred`, `staged_open_cred`) that the `sd_cache`/`sd_stage` decorators forward to `sd_xroot`. For detached write-back, the owning identity (credential key + principal + cred dir + fallback mode) is recorded in the stage-engine's durable journal record and re-resolved from the credential directory at flush time, so expiry is checked at the moment of use.

**Tech Stack:** nginx module C (ngx types), OpenSSL (PEM parse + SHA256), shell e2e against a GSI origin, standalone C unit tests linked against build-tree `.o` files.

## Global Constraints

- **NO `goto`** anywhere in `src/` (CLAUDE.md HARD BLOCK). Early-return + helper decomposition only.
- Every function gets a `/* ---- summary ---- WHAT/WHY/HOW */` doc block (coding-standards §3).
- **NO new mutable globals** — identity/credential state passes as parameters or embedded struct copies (coding-standards §8.2). Borrowed pointers into request pools must NEVER be stored in detached tasks: copy into fixed `char[]` fields.
- Raw file I/O on credential files is allowed only because `ucred.c` lives in `src/fs/backend/` (tier-1). `tools/ci/check_vfs_seam.sh` must stay green.
- New `.c` files MUST be added to `ngx_module_srcs` in the repo-root `./config`, then `./configure` re-run (BUILD GOVERNANCE). Incremental `make -j$(nproc)` otherwise. Build is `-Werror`.
- Error paths that reject a request use errno `EACCES` so existing mapping gives kXR_NotAuthorized / HTTP 403.
- **NO git write commands (add/commit/stash/checkout/...) without Rob's explicit approval in the live conversation.** Every "Commit" step below means: STOP, ask Rob, and skip (leave uncommitted) unless he approves.
- Build commands: `export REPO=/home/rcurrie/HEP-x/nginx-xrootd; cd /tmp/nginx-1.28.3 && ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$REPO && make -j$(nproc)` (configure only when `./config` changed). Use the literal repo path if `$REPO` is empty — an empty `--add-module=` silently builds bare nginx.

## Out of scope (record as follow-ups in the docs page, Task 9)

1. Delegation capture endpoints (GridSite/HTTP POST of a delegated proxy) — Phase 2.
2. S3 SigV4 → x509 minting.
3. Per-user credentials for non-xroot backends (`sd_http` bearer, `sd_ceph`, `sd_s3`).
4. root:// (stream-side) per-user origin credentials — the stream plane passes `identity = NULL` into the VFS today.
5. Namespace ops (stat/mkdir/rename/unlink/xattr) against the remote origin still ride the **service** credential in Phase 1 — only data-plane opens (read fill, write, staged upload, flush) are credential-scoped. Documented limitation; Phase 2 threads cred through the ns slots.
6. Per-user **bearer** (`.token`) files — Phase 1 is x509 proxies (`.pem`) only.
7. Prometheus counters for select/fallback/deny — Phase 1 observability is ERR/WARN/INFO logs + the xfer audit ledger (`principal=` + `result=denied`), which already has the schema. Counter family is a small follow-up via the "New metric" recipe.

---

## Interfaces created by this plan (shared vocabulary — exact names)

```c
/* sd.h (Task 3) */
typedef struct {
    const char *x509_proxy;      /* resolved per-user proxy PEM path            */
    const char *key;             /* credential-dir lookup key (audit+re-resolve)*/
    const char *principal;       /* authenticated principal (audit/ledger)      */
    const char *cred_dir;        /* export credential dir (flush re-resolve)    */
    unsigned    fallback_deny:1; /* 1 = service-cred fallback forbidden         */
} brix_sd_cred_t;
/* new OPTIONAL vtable slots, appended at the end of brix_sd_driver_s: */
brix_sd_obj_t    *(*open_cred)(brix_sd_instance_t *, const char *, int, mode_t,
                                 const brix_sd_cred_t *, int *);
brix_sd_staged_t *(*staged_open_cred)(brix_sd_instance_t *, const char *, mode_t,
                                        const brix_sd_cred_t *, int *);
/* + inline forwarders brix_sd_open_maybe_cred() / brix_sd_staged_open_maybe_cred() */

/* ucred.h (Task 2) */
typedef struct {
    char     path[1024];       /* resolved proxy PEM path      */
    char     key[128];         /* matched lookup key           */
    char     principal[512];   /* derived principal string     */
    unsigned expired:1;        /* found a candidate but expired */
} brix_sd_ucred_t;
ngx_int_t brix_sd_ucred_principal(const brix_identity_t *id, char *buf, size_t cap);
ngx_int_t brix_sd_ucred_key(const char *principal, char *key, size_t cap);
ngx_int_t brix_sd_ucred_select(const char *cred_dir, const brix_identity_t *id,
    brix_sd_ucred_t *out);                       /* OK / DECLINED / ERROR */
ngx_int_t brix_sd_ucred_resolve(const char *cred_dir, const char *key,
    brix_sd_ucred_t *out);                       /* by-key (flush path)   */

/* stage_engine.h (Task 6) */
typedef struct {                 /* POD, no bitfields — embedded in the journal */
    char    key[128];
    char    principal[512];
    char    dir[1024];
    uint8_t deny;
} brix_stage_cred_t;
ngx_int_t brix_stage_run_inline_cred(brix_stage_kind_t, brix_sd_instance_t *,
    const char *, brix_sd_instance_t *, const char *, const brix_stage_cred_t *);
ngx_int_t brix_sreq_decode(const void *buf, size_t n, brix_sreq_t *out);
/* brix_stage_opts_t gains: const brix_stage_cred_t *cred;
 * brix_sreq_t gains (APPENDED at end): brix_stage_cred_t cred; */

/* vfs.h / vfs_internal.h (Task 4) */
void brix_vfs_ctx_bind_backend_cred(brix_vfs_ctx_t *vctx,
    const ngx_str_t *cred_dir, ngx_uint_t fallback_deny);
ngx_int_t brix_vfs_backend_cred(brix_vfs_ctx_t *ctx, brix_sd_ucred_t *store,
    brix_sd_cred_t *cred, int *use_cred, int *err_out);   /* internal */
/* brix_vfs_ctx_t gains: const char *storage_cred_dir; unsigned storage_cred_deny:1; */

/* shared_conf.h (Task 1) */
/* fields: ngx_str_t storage_credential_dir; ngx_uint_t storage_credential_fallback;
 * directives: brix_storage_credential_dir <dir>;
 *             brix_storage_credential_fallback allow|deny;   (default allow) */

/* cache_internal.h (Task 3) — brix_cache_fill_t gains embedded copies:
 * char cred_x509_proxy[1024]; char cred_principal[512]; */

/* sd_stage.h (Task 5) — reflush gains the cred:
 * ngx_int_t brix_sd_stage_reflush(brix_sd_instance_t *inst, const char *key,
 *     const brix_stage_cred_t *cred); */
```

### Credential-directory naming scheme (document verbatim in Task 9)

- **Principal string**: GSI → the parsed cert DN exactly as `identity->dn` holds it (the same string the origin logs in `GSI auth OK dn="..."` for direct logins); bearer token → the `sub` claim (`identity->subject`); S3 → the SigV4 access-key id (`identity->subject`).
- **Lookup key candidates**, tried in order; the first candidate whose `.pem` file EXISTS decides (a valid one is used; an existing-but-expired one reports `expired`):
  1. the literal principal, only when it is filesystem-safe: matches `[A-Za-z0-9@._][A-Za-z0-9@._-]{0,63}` (never true for a DN — DNs contain `/`);
  2. `x5h-<first 32 lowercase hex of SHA256(principal)>`.
- **File**: `<brix_storage_credential_dir>/<key>.pem` — a ready RFC-3820 proxy (cert + key + chain, same format as `cache_origin_x509_proxy`).
- Admin discovery: the server logs the derived `key=` on every fallback/deny decision, so `run once + grep` yields the filename to provision. Also derivable: `printf '%s' "$PRINCIPAL" | sha256sum | cut -c1-32`.
- **Caveat (docs)**: token principals use `sub` only; two issuers sharing a `sub` share a credential. Multi-issuer sites must rely on authorization gating or wait for the Phase-2 `iss|sub` scheme.

---

### Task 1: Config directives `brix_storage_credential_dir` + `brix_storage_credential_fallback`

**Files:**
- Modify: `src/core/config/shared_conf.h` (fields after `storage_credential` at :45-49; init at :157-158; merge at :266-267)
- Modify: `src/core/config/http_common.c` (command table after the `brix_storage_credential` entry at :42-47; adopt at :174)
- Test: `tests/run_ucred_conf.sh` (new)

**Interfaces:** Produces the two `common.*` fields named above. HTTP-only (unified-directive rule: owned once in http_common); stream gets no directive (follow-up #4).

- [ ] **Step 1: Write the failing test**

```bash
#!/bin/sh
# tests/run_ucred_conf.sh — parse-level checks for the per-user credential directives.
# 1 accepted with valid args; 2 rejected with a bad fallback value; 3 defaults (absent) parse.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
NGINX=${NGINX:-/tmp/nginx-1.28.3/objs/nginx}
PFX=/tmp/ucred-conf-test; rm -rf "$PFX"; mkdir -p "$PFX/logs" "$PFX/export" "$PFX/creds"
ok()  { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; FAILED=1; }
FAILED=0

mkconf() { # $1 = extra directives
cat > "$PFX/nginx.conf" <<EOF
daemon off; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
events { worker_connections 16; }
http { server { listen 127.0.0.1:18443;
    location / { brix_webdav on; brix_export $PFX/export; $1 }
} }
EOF
}

mkconf "brix_storage_credential_dir $PFX/creds; brix_storage_credential_fallback deny;"
"$NGINX" -t -c "$PFX/nginx.conf" >/dev/null 2>&1 && ok "valid directives accepted" \
    || bad "valid directives rejected"

mkconf "brix_storage_credential_fallback sometimes;"
"$NGINX" -t -c "$PFX/nginx.conf" >/dev/null 2>&1 && bad "bad fallback value accepted" \
    || ok "bad fallback value rejected"

mkconf ""
"$NGINX" -t -c "$PFX/nginx.conf" >/dev/null 2>&1 && ok "defaults (absent) parse" \
    || bad "defaults broke parsing"
exit $FAILED
```

- [ ] **Step 2: Run it to verify it fails** — `sh tests/run_ucred_conf.sh` — Expected: `FAIL: valid directives rejected` (directive unknown).

- [ ] **Step 3: Implement.** In `shared_conf.h`, directly after the `storage_credential` field:

```c
    ngx_str_t           storage_credential_dir; /* [brix_storage_credential_dir
                                             * <dir>] — directory of per-identity
                                             * x509 proxy PEMs for a remote
                                             * backend (phase-1 per-user backend
                                             * credentials); "" = feature off.   */
    ngx_uint_t          storage_credential_fallback; /* [brix_storage_credential_
                                             * fallback allow|deny] — 0 allow the
                                             * static service credential when the
                                             * identity has no per-user file
                                             * (default); 1 deny (fail EACCES).  */
```

In `ngx_http_brix_shared_init()` (next to the `storage_credential` lines):

```c
    conf->storage_credential_dir.len   = 0;
    conf->storage_credential_dir.data  = NULL;
    conf->storage_credential_fallback  = NGX_CONF_UNSET_UINT;
```

In `ngx_http_brix_shared_merge()` (next to the `storage_credential` merge):

```c
    ngx_conf_merge_str_value(conf->storage_credential_dir,
                             prev->storage_credential_dir, "");
    ngx_conf_merge_uint_value(conf->storage_credential_fallback,
                              prev->storage_credential_fallback, 0);
```

In `http_common.c`, above the command table:

```c
static ngx_conf_enum_t  brix_http_ucred_fallback_enum[] = {
    { ngx_string("allow"), 0 },
    { ngx_string("deny"),  1 },
    { ngx_null_string, 0 }
};
```

after the `brix_storage_credential` command entry:

```c
    { ngx_string("brix_storage_credential_dir"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_credential_dir),
      NULL },

    { ngx_string("brix_storage_credential_fallback"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_credential_fallback),
      &brix_http_ucred_fallback_enum },
```

and in `brix_shared_adopt_unified()`:

```c
    BRIX_ADOPT_STR(storage_credential_dir);
    BRIX_ADOPT_VAL(storage_credential_fallback, NGX_CONF_UNSET_UINT);
```

- [ ] **Step 4: Build** (`make -j$(nproc)` in `/tmp/nginx-1.28.3` — no configure; no new source file) and re-run the test — Expected: 3× PASS, exit 0.
- [ ] **Step 5: Commit** — ask Rob first (Global Constraints); otherwise leave uncommitted.

---

### Task 2: Credential selection helper `src/fs/backend/ucred.{h,c}` + C unit test

**Files:**
- Create: `src/fs/backend/ucred.h`, `src/fs/backend/ucred.c`
- Modify: `./config` (add `ucred.c` to `ngx_module_srcs` next to line 699 `sd_xroot.c`; add `ucred.h` to the matching deps list)
- Modify: `src/fs/backend/README.md` (one table row)
- Test: `tests/c/test_ucred.c`, `tests/c/run_ucred_tests.sh`

**Interfaces:** Produces `brix_sd_ucred_t` + the four `brix_sd_ucred_*` functions declared in the vocabulary block above. Consumes `brix_identity_t` (`core/types/identity.h`: `dn`, `subject` are `ngx_str_t`, `is_authenticated`).

- [ ] **Step 1: Write the failing unit test** `tests/c/test_ucred.c` (pattern: `tests/c/run_cinfo_tests.sh` — plain `cc` against build-tree `.o`):

```c
/* test_ucred.c — unit tests for per-user backend credential selection.
 * Covers: principal derivation, fs-safe literal vs DN-hash keying, select
 * found/missing/expired, by-key resolve. Run via tests/c/run_ucred_tests.sh. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "core/types/identity.h"
#include "fs/backend/ucred.h"

static void write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    assert(f != NULL);
    fputs(content, f);
    fclose(f);
}

/* Make a throwaway self-signed cert PEM with the given validity (days; negative
 * = already expired) via the openssl CLI — keeps the test free of raw ASN.1. */
static void mint_pem(const char *path, int days) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null "
        "-subj /CN=ucredtest -days %d -out %s 2>/dev/null", days, path);
    assert(system(cmd) == 0);
}

int main(void) {
    char dir[] = "/tmp/ucred-test-XXXXXX";
    char buf[512], key[128], path[1200];
    brix_identity_t id;
    brix_sd_ucred_t out;

    assert(mkdtemp(dir) != NULL);

    /* principal: dn wins over subject; unauthenticated fails */
    memset(&id, 0, sizeof(id));
    assert(brix_sd_ucred_principal(&id, buf, sizeof(buf)) == NGX_ERROR);
    id.is_authenticated = 1;
    id.subject.data = (u_char *) "AKIAEXAMPLE"; id.subject.len = 11;
    assert(brix_sd_ucred_principal(&id, buf, sizeof(buf)) == NGX_OK);
    assert(strcmp(buf, "AKIAEXAMPLE") == 0);
    id.dn.data = (u_char *) "/DC=test/CN=Alice"; id.dn.len = 17;
    assert(brix_sd_ucred_principal(&id, buf, sizeof(buf)) == NGX_OK);
    assert(strcmp(buf, "/DC=test/CN=Alice") == 0);

    /* keying: fs-safe literal kept, DN hashed with the x5h- prefix */
    assert(brix_sd_ucred_key("AKIAEXAMPLE", key, sizeof(key)) == NGX_OK);
    assert(strcmp(key, "AKIAEXAMPLE") == 0);
    assert(brix_sd_ucred_key("/DC=test/CN=Alice", key, sizeof(key)) == NGX_OK);
    assert(strncmp(key, "x5h-", 4) == 0 && strlen(key) == 4 + 32);

    /* select: missing → DECLINED, expired=0 */
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_DECLINED);
    assert(!out.expired && out.key[0] != '\0' && out.principal[0] == '/');

    /* select: valid hash-keyed PEM → OK with the resolved path */
    snprintf(path, sizeof(path), "%s/%s.pem", dir, key);
    mint_pem(path, 30);
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_OK);
    assert(strcmp(out.path, path) == 0 && strcmp(out.key, key) == 0);

    /* select: expired PEM → DECLINED, expired=1 */
    mint_pem(path, -1);
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_DECLINED);
    assert(out.expired);

    /* select: garbage PEM (unparseable) → DECLINED, treated as missing */
    write_file(path, "not a pem\n");
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_DECLINED);

    /* resolve by key (the flush path) */
    mint_pem(path, 30);
    assert(brix_sd_ucred_resolve(dir, key, &out) == NGX_OK);
    assert(brix_sd_ucred_resolve(dir, "x5h-doesnotexist0000000000000000", &out)
           == NGX_DECLINED);

    /* literal fs-safe key select for the S3 identity */
    memset(&id, 0, sizeof(id));
    id.is_authenticated = 1;
    id.subject.data = (u_char *) "AKIAEXAMPLE"; id.subject.len = 11;
    snprintf(path, sizeof(path), "%s/AKIAEXAMPLE.pem", dir);
    mint_pem(path, 30);
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_OK);
    assert(strcmp(out.key, "AKIAEXAMPLE") == 0);

    printf("test_ucred: all assertions passed\n");
    return 0;
}
```

`tests/c/run_ucred_tests.sh` (mirror `run_cinfo_tests.sh`'s compile pattern; adjust the `addon/` objdir name to what `ls /tmp/nginx-1.28.3/objs/addon/` shows for `src/fs/backend/`):

```bash
#!/bin/sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../.." && pwd)
OBJS=/tmp/nginx-1.28.3/objs
BIN=/tmp/test_ucred
UCRED_OBJ=$(find "$OBJS/addon" -name 'ucred.o' | head -1)
[ -n "$UCRED_OBJ" ] || { echo "SKIP: build ucred.o first (make)"; exit 1; }
cc -O -Wall -o "$BIN" "$HERE/test_ucred.c" "$UCRED_OBJ" \
    -I "$REPO/src" -I /tmp/nginx-1.28.3/src/core -I /tmp/nginx-1.28.3/src/event \
    -I /tmp/nginx-1.28.3/src/os/unix -I "$OBJS" -lcrypto
"$BIN"
```

- [ ] **Step 2: Run to verify it fails** — `sh tests/c/run_ucred_tests.sh` — Expected: `SKIP: build ucred.o first` (file does not exist yet).

- [ ] **Step 3: Implement `ucred.h`** — the vocabulary-block API with a file doc block (WHAT: identity→credential-file selection + expiry; WHY: per-user origin auth without delegation capture; HOW: principal → key candidates → `<dir>/<key>.pem` → notAfter gate). `#pragma once`-style per standards (`#ifndef` also fine — match `sd.h`). Constants: `BRIX_UCRED_KEY_MAX 128`, `BRIX_UCRED_PATH_MAX 1024`, `BRIX_UCRED_PRINC_MAX 512`.

- [ ] **Step 4: Implement `ucred.c`.** Small pure helpers, side effects (stat/PEM read) at the edges:

```c
/*
 * ucred.c — per-user backend-credential selection (phase-1). See ucred.h.
 */
#include "ucred.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

/* ---- Is `principal` usable verbatim as a credential filename stem? ----
 * WHAT: 1 iff principal matches [A-Za-z0-9@._][A-Za-z0-9@._-]{0,63}.
 * WHY:  Human-manageable filenames for token subs / S3 access keys; DNs
 *       (which contain '/') always fall through to the hash form.
 * HOW:  1. reject empty/oversized/leading '-'; 2. scan the charset. */
static int
ucred_principal_fs_safe(const char *principal)
{
    size_t i, len = strlen(principal);

    if (len == 0 || len > 64 || principal[0] == '-') {
        return 0;
    }
    for (i = 0; i < len; i++) {
        char c = principal[i];
        int  ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
               || (c >= '0' && c <= '9') || c == '@' || c == '.'
               || c == '_' || c == '-';
        if (!ok) {
            return 0;
        }
    }
    return 1;
}

/* ---- Classify one candidate credential file ----
 * WHAT: NGX_OK valid; NGX_DECLINED absent/unreadable/unparseable;
 *       NGX_DECLINED with *expired=1 when parseable but past notAfter.
 * WHY:  Expiry must be checked at the moment of use — a proxy can lapse
 *       between the request open and a deferred flush.
 * HOW:  1. fopen; 2. PEM_read_X509 (first block = the proxy cert);
 *       3. X509_cmp_current_time(notAfter) must be > 0. */
static ngx_int_t
ucred_check_pem(const char *path, int *expired)
{
    FILE *f;
    X509 *cert;
    int   cmp;

    *expired = 0;
    f = fopen(path, "r");
    if (f == NULL) {
        return NGX_DECLINED;
    }
    cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    if (cert == NULL) {
        return NGX_DECLINED;                  /* unparseable = treated missing */
    }
    cmp = X509_cmp_current_time(X509_get0_notAfter(cert));
    X509_free(cert);
    if (cmp <= 0) {
        *expired = 1;
        return NGX_DECLINED;
    }
    return NGX_OK;
}
```

`brix_sd_ucred_principal()`: `NGX_ERROR` when `id == NULL || !id->is_authenticated` or both `dn.len` and `subject.len` are 0 or the winner does not fit `cap`; else copy `id->dn` (preferred when `len > 0`) or `id->subject` NUL-terminated into `buf`, `NGX_OK`. (ngx_str_t is not NUL-terminated: `memcpy` + explicit `buf[len] = 0`.)

`brix_sd_ucred_key()`: if `ucred_principal_fs_safe` → copy verbatim; else `SHA256((u_char*)principal, strlen, digest)` and `snprintf(key, cap, "x5h-%02x…")` over the first 16 digest bytes (32 hex chars). `NGX_ERROR` on empty principal or overflow.

`brix_sd_ucred_resolve(dir, key, out)`: build `<dir>/<key>.pem` with a bounded `snprintf` (overflow → `NGX_ERROR`, errno `ENAMETOOLONG`); `ucred_check_pem`; on `NGX_OK` fill `out->path`/`out->key`, clear `expired`; on declined set `out->expired` and return `NGX_DECLINED`. `out->principal` untouched here.

`brix_sd_ucred_select(dir, id, out)`: zero `*out`; derive principal into `out->principal` (failure → `NGX_DECLINED` with `out->key[0]=0` — an unauthenticated identity simply has no credential); build candidate list: literal (only if fs-safe) then hash; for each candidate call `brix_sd_ucred_resolve`; first `NGX_OK` wins (return `NGX_OK`); remember the FIRST candidate key in `out->key` for logging and OR-in any `expired`; if none valid return `NGX_DECLINED` (with `out->key` = hash-form key so the deny/fallback log names the file the admin should provision — set `out->key` to the hash candidate before returning).

- [ ] **Step 5: Add to `./config`** next to line 699/700: `    $ngx_addon_dir/src/fs/backend/ucred.c \` in `ngx_module_srcs` and `ucred.h` in the corresponding `ngx_module_deps`. Add a row to `src/fs/backend/README.md`.
- [ ] **Step 6: `./configure` + `make -j$(nproc)`** (new source file) — Expected: exit 0, no warnings.
- [ ] **Step 7: Run the unit test** — `sh tests/c/run_ucred_tests.sh` — Expected: `test_ucred: all assertions passed`.
- [ ] **Step 8: Commit** — ask Rob first.

---

### Task 3: SD seam (`open_cred`/`staged_open_cred`) + sd_xroot per-open override + origin bootstrap consult

**Files:**
- Modify: `src/fs/backend/sd.h` (type + 2 slots + 2 inline forwarders)
- Modify: `src/fs/cache/cache_internal.h` (`brix_cache_fill_t` fields, after `source_inst` at :112)
- Modify: `src/fs/cache/origin_protocol.c` (:172-192)
- Modify: `src/fs/backend/xroot/sd_xroot.c`

**Interfaces:** Consumes `brix_sd_cred_t` semantics; produces working per-open user auth for every sd_xroot data-plane open. All later tasks call `brix_sd_open_maybe_cred()` / `brix_sd_staged_open_maybe_cred()`.

- [ ] **Step 1: `sd.h`** — add the `brix_sd_cred_t` typedef (vocabulary block, with its doc comment: borrowed pointers valid only for the call; drivers that defer copy the strings) above the vtable; append the two optional slots at the END of `struct brix_sd_driver_s` (designated initializers keep every driver source-compatible); add below the capability accessors:

```c
/* ---- credential-scoped open forwarders ----
 * WHAT: Route through the cred-scoped slot when a per-user credential is
 *       present AND the driver implements it; else the plain slot.
 * WHY:  One forwarding rule shared by the VFS and every decorator, so no
 *       tier can accidentally drop the credential on the floor.
 * HOW:  cred+slot → *_cred; otherwise the legacy slot. */
static ngx_inline brix_sd_obj_t *
brix_sd_open_maybe_cred(brix_sd_instance_t *inst, const char *path,
    int sd_flags, mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    if (cred != NULL && inst->driver->open_cred != NULL) {
        return inst->driver->open_cred(inst, path, sd_flags, mode, cred,
                                       err_out);
    }
    return inst->driver->open(inst, path, sd_flags, mode, err_out);
}

static ngx_inline brix_sd_staged_t *
brix_sd_staged_open_maybe_cred(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    if (cred != NULL && inst->driver->staged_open_cred != NULL) {
        return inst->driver->staged_open_cred(inst, final_path, mode, cred,
                                              err_out);
    }
    return inst->driver->staged_open(inst, final_path, mode, err_out);
}
```

- [ ] **Step 2: `cache_internal.h`** — append to `brix_cache_fill_t` (after `source_inst`):

```c
    /* Phase-1 per-user backend credential: when cred_x509_proxy is non-empty the
     * origin bootstrap authenticates with THIS proxy instead of the conf's static
     * service credential. Embedded copies — a fill task can outlive the request
     * whose identity selected the credential. */
    char      cred_x509_proxy[1024];
    char      cred_principal[512];
```

- [ ] **Step 3: `origin_protocol.c`** — inside the `if (needs_auth) {` block at :172, BEFORE the existing ztn branch, insert (the override must win over every static credential — a ztn+gsi origin must not swallow the user's request into the service bearer):

```c
            /* Phase-1 per-user credential: a per-task x509 override WINS over
             * every static service credential — this session must carry the
             * user's identity, never the service's. */
            if (t->cred_x509_proxy[0] != '\0') {
                if (has_gsi) {
                    return brix_cache_origin_auth_gsi(t, oc, gsi_parms,
                                                        t->cred_x509_proxy);
                }
                brix_cache_set_error(t, kXR_AuthFailed, 0,
                    "origin does not advertise gsi for the per-user credential");
                return -1;
            }
```

(The later `kXR_authmore`-only branch at :197-204 needs the same guard: if `t->cred_x509_proxy[0] != '\0'` there, fail with the same message rather than presenting the service bearer.)

- [ ] **Step 4: `sd_xroot.c`** — thread the cred:
  - `sd_xroot_origin_open(conf, path, want_write, mode, size_out, err_out)` gains `const brix_sd_cred_t *cred` (after `conf`); after the `ngx_cpystrn(clean_path…)` copy:

```c
    if (cred != NULL && cred->x509_proxy != NULL && cred->x509_proxy[0] != '\0') {
        ngx_cpystrn((u_char *) t->cred_x509_proxy, (u_char *) cred->x509_proxy,
                    sizeof(t->cred_x509_proxy));
        if (cred->principal != NULL) {
            ngx_cpystrn((u_char *) t->cred_principal,
                        (u_char *) cred->principal, sizeof(t->cred_principal));
        }
    }
```

  - Extract the body of `sd_xroot_open()` into `sd_xroot_open_common(inst, path, sd_flags, mode, cred, err_out)`; `sd_xroot_open()` = `open_common(…, NULL, …)`; new `sd_xroot_open_cred()` = `open_common(…, cred, …)`. Same split for `sd_xroot_staged_open()` → `sd_xroot_staged_open_common()` + `sd_xroot_staged_open_cred()` (copy the same two fields into the staged task `t`). Existing callers inside the file (`sd_xroot_stat` at :259, everything in `sd_xroot_ns.c`) pass `NULL` — namespace ops stay on the service credential in Phase 1 (documented).
  - Register in the vtable: `.open_cred = sd_xroot_open_cred, .staged_open_cred = sd_xroot_staged_open_cred,`.

- [ ] **Step 5: Build** (`make -j$(nproc)`, no configure — no new file) — Expected: exit 0, no warnings. Run the existing suite smoke: `PYTHONPATH=tests pytest tests/ -k "cache and origin" -x -q` — Expected: no regressions (override fields are zeroed by `calloc`, so behavior is unchanged until a caller sets them).
- [ ] **Step 6: Commit** — ask Rob first.

---

### Task 4: VFS credential selection + protocol binding (davs GET/PUT, S3)

**Files:**
- Create: `src/fs/vfs/vfs_cred.c`
- Modify: `src/fs/vfs/vfs.h` (2 ctx fields + `brix_vfs_ctx_bind_backend_cred` decl), `src/fs/vfs/vfs_internal.h` (`brix_vfs_backend_cred` decl), `src/fs/vfs/vfs_open.c` (:441-473 branch), `src/fs/vfs/vfs_staged.c` (:142-162 branch)
- Modify: `src/protocols/webdav/get.c` (:174), `src/protocols/webdav/put.c` (:57, :426), `src/protocols/s3/util.c` (`s3_build_vfs_ctx`), `src/protocols/s3/put_aio.c` (:113), `src/protocols/s3/put_chunk.c` (:36), `src/protocols/s3/put_finalize.c` (:44)
- Modify: `./config` (add `vfs_cred.c`)

**Interfaces:** Consumes Task 2 (`brix_sd_ucred_select`) + Task 3 (`brix_sd_cred_t`, forwarders). Produces `brix_vfs_ctx_bind_backend_cred()` + `brix_vfs_backend_cred()`.

- [ ] **Step 1: ctx fields** in `brix_vfs_ctx_t` (after `cache_writethrough_cfg`):

```c
    /* Phase-1 per-user backend credentials: the export's credential dir
     * (borrowed from conf, NUL-terminated; NULL/"" = feature off) and the
     * fallback policy. Set via brix_vfs_ctx_bind_backend_cred(). */
    const char          *storage_cred_dir;
    unsigned             storage_cred_deny:1;
```

(`brix_vfs_ctx_init` zeroes the struct already — verify it memzeros; if it assigns field-by-field, add the two clears.)

- [ ] **Step 2: `vfs_cred.c`** (include `vfs_internal.h`, `fs/backend/ucred.h`):

```c
/* ---- Bind the export's per-user credential policy onto a VFS ctx ----
 * WHAT: Copies the conf's credential-dir pointer + fallback mode onto the ctx.
 * WHY:  brix_vfs_ctx_init predates the feature and is called from ~30 sites;
 *       a separate bind keeps the signature stable and lets the data-plane
 *       callsites opt in explicitly.
 * HOW:  nginx conf tokens are NUL-terminated, so the ngx_str_t data pointer is
 *       usable as a C string for the conf's lifetime (outlives every request). */
void
brix_vfs_ctx_bind_backend_cred(brix_vfs_ctx_t *vctx,
    const ngx_str_t *cred_dir, ngx_uint_t fallback_deny)
{
    vctx->storage_cred_dir  = (cred_dir != NULL && cred_dir->len > 0)
                            ? (const char *) cred_dir->data : NULL;
    vctx->storage_cred_deny = (fallback_deny == 1) ? 1u : 0u;
}

/* ---- Select the per-user backend credential for this request ----
 * WHAT: NGX_OK with *use_cred=1 and *cred filled (backed by *store) when the
 *       identity has a valid credential; NGX_OK with *use_cred=0 for feature-
 *       off or an allowed service-cred fallback; NGX_ERROR (errno/err_out =
 *       EACCES) when fallback=deny and no usable credential exists.
 * WHY:  The single policy gate: deny mode must reject BEFORE any origin
 *       connection is attempted, so a request can never ride the service
 *       credential (or another user's) when the operator forbade it.
 * HOW:  1. feature-off → service; 2. ucred_select; 3. found + driver supports
 *       open_cred → use; found but unsupported backend → deny? EACCES : warn+
 *       service; 4. missing/expired → deny? EACCES+ERR : INFO fallback. */
ngx_int_t
brix_vfs_backend_cred(brix_vfs_ctx_t *ctx, brix_sd_ucred_t *store,
    brix_sd_cred_t *cred, int *use_cred, int *err_out)
{
    ngx_int_t rc;

    *use_cred = 0;
    if (ctx->storage_cred_dir == NULL || ctx->storage_cred_dir[0] == '\0') {
        return NGX_OK;
    }

    rc = brix_sd_ucred_select(ctx->storage_cred_dir, ctx->identity, store);

    if (rc == NGX_OK) {
        if (ctx->sd == NULL || ctx->sd->driver->open_cred == NULL) {
            if (ctx->storage_cred_deny) {
                ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                    "brix: backend \"%s\" cannot scope a session to a user "
                    "credential (fallback=deny) - refusing principal=\"%s\"",
                    brix_sd_backend_name(ctx->sd), store->principal);
                errno = EACCES;
                if (err_out != NULL) { *err_out = EACCES; }
                return NGX_ERROR;
            }
            ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                "brix: backend \"%s\" cannot scope a session to a user "
                "credential - using the service credential for \"%s\"",
                brix_sd_backend_name(ctx->sd), store->principal);
            return NGX_OK;
        }
        cred->x509_proxy    = store->path;
        cred->key           = store->key;
        cred->principal     = store->principal;
        cred->cred_dir      = ctx->storage_cred_dir;
        cred->fallback_deny = ctx->storage_cred_deny;
        *use_cred = 1;
        return NGX_OK;
    }

    if (ctx->storage_cred_deny) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "brix: per-user backend credential %s for principal=\"%s\" "
            "key=%s dir=\"%s\" (fallback=deny) - refusing",
            store->expired ? "EXPIRED" : "missing", store->principal,
            store->key, ctx->storage_cred_dir);
        errno = EACCES;
        if (err_out != NULL) { *err_out = EACCES; }
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
        "brix: no per-user backend credential for principal=\"%s\" key=%s - "
        "falling back to the service credential",
        store->principal, store->key);
    return NGX_OK;
}
```

- [ ] **Step 3: `vfs_open.c`** — in the non-default-backend branch (:441), select then route through the forwarder:

```c
    if (ctx->sd != NULL && ctx->sd->driver != brix_sd_default_driver()
        && ctx->sd->driver->open != NULL)
    {
        brix_sd_obj_t   *o;
        int                sderr = 0;
        brix_sd_ucred_t  ustore;
        brix_sd_cred_t   ucred;
        int                use_cred = 0;

        if (brix_vfs_backend_cred(ctx, &ustore, &ucred, &use_cred, err_out)
            != NGX_OK)
        {
            return NULL;
        }
        o = brix_sd_open_maybe_cred(ctx->sd,
                                    brix_vfs_export_relative(ctx, path),
                                    brix_vfs_to_sd_flags(flags), 0644,
                                    use_cred ? &ucred : NULL, &sderr);
        …   /* rest of the branch unchanged */
```

The rootfd/POSIX branches (:491+) are untouched — a local export never talks to an origin.

- [ ] **Step 4: `vfs_staged.c`** — same pattern in the driver-staged branch (:147-151): select via `brix_vfs_backend_cred` (deny → return NULL with `*err_out`), then `st->driver_staged = brix_sd_staged_open_maybe_cred(ctx->sd, final_path, mode, use_cred ? &ucred : NULL, err_out);`.

- [ ] **Step 5: Protocol binding.** After each listed `brix_vfs_ctx_init` call (the data-plane read/write sites), add one line, using that site's loc-conf variable (all six have the conf or its `common` in scope; for the S3 AIO tasks, thread the two values through the task struct exactly like `root_canon` already is if the conf pointer is not directly available):

```c
    brix_vfs_ctx_bind_backend_cred(&vctx, &conf->common.storage_credential_dir,
                                     conf->common.storage_credential_fallback);
```

Sites: `webdav/get.c:174`, `webdav/put.c:57` (inside `webdav_put_vfs_ctx_init`), `webdav/put.c:426`, `s3/util.c` (`s3_build_vfs_ctx` — covers S3 GET/PUT object flows), `s3/put_aio.c:113`, `s3/put_chunk.c:36`, `s3/put_finalize.c:44`.

- [ ] **Step 6: `./config`** — add `vfs_cred.c`; `./configure` + full `make` — Expected: exit 0.
- [ ] **Step 7: Regression run** — `PYTHONPATH=tests pytest tests/ -k "webdav or s3" -x -q -m "not slow" -n12` — Expected: green (feature off ⇒ `storage_cred_dir == NULL` ⇒ identical behavior).
- [ ] **Step 8: Commit** — ask Rob first.

---

### Task 5: Decorator forwarding — sd_cache (read fills) + sd_stage (write-back)

**Files:**
- Modify: `src/fs/backend/cache/sd_cache.c` (fill spine :39-59, partial-fill state + :281-285, passthrough :424-465)
- Modify: `src/fs/backend/stage/sd_stage.c`, `src/fs/backend/stage/sd_stage.h`

**Interfaces:** Consumes Task 3 forwarders + Task 6's `brix_stage_cred_t`/`brix_stage_run_inline_cred` (build order note: implement Task 6 FIRST or in the same build — sd_stage's flush calls the new engine API. Recommended order: 6 then 5, or land both before building).

- [ ] **Step 1: `sd_cache.c`.**
  - `sd_cache_fill(st, key)` gains `const brix_sd_cred_t *cred`; its source open (:59) becomes `brix_sd_open_maybe_cred(src, key, BRIX_SD_O_READ, 0, cred, &err)`.
  - The per-object partial-fill state (the struct holding `src_obj`/`source`, opened lazily at :281-285 during later preads) gains embedded copies — later range-fills run after the request's cred storage is gone:

```c
    char      cred_proxy[1024];   /* per-user origin credential ("" = service) */
    char      cred_key[128];
    char      cred_principal[512];
```

    populated at object-open when a cred is present; at :285 build a stack `brix_sd_cred_t` from them (only when `cred_proxy[0] != '\0'`) and use `brix_sd_open_maybe_cred`.
  - `sd_cache_open` → extract `sd_cache_open_common(inst, path, sd_flags, mode, cred, err_out)`; plain `.open` passes NULL; new `sd_cache_open_cred` passes cred. Forward at the passthrough sites (:435, :465) with the same helper. Register `.open_cred = sd_cache_open_cred`. If sd_cache implements `staged_open` (grep; forward the cred analogously with a `staged_open_cred` if it delegates to the source).

- [ ] **Step 2: `sd_stage.c`.**
  - `sd_stage_wb_state` and `sd_stage_staged_state` each gain `brix_stage_cred_t cred;` (zeroed = none).
  - New `sd_stage_open_cred(inst, path, sd_flags, mode, cred, err_out)`: write-open → `sd_stage_open_writeback(...)` extended with the cred param, which copies `cred->key/principal/cred_dir/fallback_deny` into `wb->cred` (store-side open stays plain — the stage store is local); read-open → `brix_sd_open_maybe_cred(is->source, path, sd_flags, mode, cred, err_out)`.
  - New `sd_stage_staged_open_cred(...)`: same copy into `ss->cred`; inner store staged_open stays plain.
  - `sd_stage_wb_flush` (:135): `rc = brix_stage_run_inline_cred(BRIX_STAGE_FLUSH, is->store, wb->key, is->source, wb->key, (wb->cred.key[0] != '\0') ? &wb->cred : NULL);`
  - `sd_stage_staged_commit`: async (:409) sets `o.cred = (ss->cred.key[0] != '\0') ? &ss->cred : NULL;`; sync (:417) uses `brix_stage_run_inline_cred(..., (ss->cred.key[0] != '\0') ? &ss->cred : NULL)`.
  - `brix_sd_stage_reflush(inst, key)` (:557) gains `const brix_stage_cred_t *cred` and passes it through to `brix_stage_run_inline_cred` (:566); update `sd_stage.h`.
  - Register `.open_cred = sd_stage_open_cred, .staged_open_cred = sd_stage_staged_open_cred`.

- [ ] **Step 3: Build + regression** — `make -j$(nproc)`; `PYTHONPATH=tests pytest tests/ -k "cache or stage or tier" -x -q` — Expected: green.
- [ ] **Step 4: Commit** — ask Rob first.

---

### Task 6: Stage engine — owner identity in the durable record, cred re-resolution at flush

**Files:**
- Modify: `src/fs/xfer/stage_engine.h`, `src/fs/xfer/stage_engine.c`
- Test: `tests/c/test_sreq_compat.c`, `tests/c/run_sreq_compat.sh`

**Interfaces:** Produces `brix_stage_cred_t`, `brix_stage_run_inline_cred()`, `brix_sreq_decode()`, `brix_stage_opts_t.cred`, `brix_sreq_t.cred` (appended). Consumes Task 2's `brix_sd_ucred_resolve` + Task 3's `brix_sd_staged_open_maybe_cred`.

- [ ] **Step 1: Write the failing journal-compat unit test** `tests/c/test_sreq_compat.c` (compile pattern of Task 2, linking `stage_engine.o` + `ucred.o` + whatever the linker demands, or — if the engine's ngx deps make standalone linking heavy — compile `brix_sreq_decode` by `#include`-ing a tiny decode-only TU; keep it to the decode function):

```c
/* test_sreq_compat.c — a pre-feature (shorter) journal record must decode with
 * a zeroed cred; a full-size record round-trips; garbage sizes are rejected. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/xfer/stage_engine.h"

int main(void) {
    brix_sreq_t rec, out;
    size_t legacy = offsetof(brix_sreq_t, cred);

    memset(&rec, 0, sizeof(rec));
    snprintf(rec.reqid, sizeof(rec.reqid), "r-1");
    rec.kind = BRIX_STAGE_FLUSH;
    snprintf(rec.cred.key, sizeof(rec.cred.key), "x5h-abc");
    rec.cred.deny = 1;

    /* full-size record round-trips with the cred */
    assert(brix_sreq_decode(&rec, sizeof(rec), &out) == NGX_OK);
    assert(strcmp(out.cred.key, "x5h-abc") == 0 && out.cred.deny == 1);

    /* legacy-size record decodes with a zeroed cred */
    assert(brix_sreq_decode(&rec, legacy, &out) == NGX_OK);
    assert(out.cred.key[0] == '\0' && out.cred.deny == 0);
    assert(strcmp(out.reqid, "r-1") == 0);

    /* anything else is corrupt */
    assert(brix_sreq_decode(&rec, legacy - 1, &out) == NGX_ERROR);
    assert(brix_sreq_decode(&rec, sizeof(rec) + 1, &out) == NGX_ERROR);

    printf("test_sreq_compat: all assertions passed\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails** (no `brix_sreq_decode`, no `cred` member) — compile error. Expected.

- [ ] **Step 3: `stage_engine.h`** — add `brix_stage_cred_t` (POD, `uint8_t deny`, doc block: wire-stable, embedded in the durable record); append `brix_stage_cred_t cred;` as the LAST member of `brix_sreq_t` (append-only keeps `offsetof(brix_sreq_t, cred)` == the legacy record size); add `const brix_stage_cred_t *cred;` to `brix_stage_opts_t`; declare `brix_stage_run_inline_cred()` and `brix_sreq_decode()`.

- [ ] **Step 4: `stage_engine.c`.**
  - `stage_pending_t` += `brix_stage_cred_t cred;`; `brix_stage_submit` copies `*opts->cred` into `p->cred` when non-NULL; `stage_journal_write` copies `p->cred` into `rec.cred`.
  - New pure decode helper (the unit under test):

```c
/* ---- Decode one durable request record with size tolerance ----
 * WHAT: NGX_OK with *out filled from a full-size OR legacy (pre-cred) record
 *       buffer; NGX_ERROR for any other size (corrupt).
 * WHY:  brix_sreq_t grew an appended cred; journals written before the
 *       upgrade must replay (with a zeroed cred → service-credential flush,
 *       matching their pre-feature semantics).
 * HOW:  legacy size == offsetof(brix_sreq_t, cred) because the cred is the
 *       final member; memzero then copy exactly n bytes. */
ngx_int_t
brix_sreq_decode(const void *buf, size_t n, brix_sreq_t *out)
{
    if (n != sizeof(brix_sreq_t) && n != offsetof(brix_sreq_t, cred)) {
        return NGX_ERROR;
    }
    ngx_memzero(out, sizeof(*out));
    ngx_memcpy(out, buf, n);
    return NGX_OK;
}
```

  - `stage_reconcile_one` (:561-599): read into a `char rbuf[sizeof(brix_sreq_t)]`, `n = read(...)`; replace the exact-size check with `brix_sreq_decode(rbuf, (size_t) n, &rec)` (decode failure → unlink + return -1, as today); pass `(rec.cred.key[0] != '\0') ? &rec.cred : NULL` into `brix_sd_stage_reflush(inst, rec.dst_key, cred)`.
  - `stage_engine_run(kind, src, src_key, dst, dst_key)` gains `const brix_stage_cred_t *cred` and performs the re-resolution BEFORE moving (deny fails without touching the origin):

```c
    brix_sd_cred_t   sdcred;
    brix_sd_cred_t  *credp = NULL;
    brix_sd_ucred_t  ru;

    if (cred != NULL && cred->key[0] != '\0') {
        if (brix_sd_ucred_resolve(cred->dir, cred->key, &ru) == NGX_OK) {
            ngx_memzero(&sdcred, sizeof(sdcred));
            sdcred.x509_proxy    = ru.path;
            sdcred.key           = cred->key;
            sdcred.principal     = cred->principal;
            sdcred.cred_dir      = cred->dir;
            sdcred.fallback_deny = cred->deny ? 1u : 0u;
            credp = &sdcred;
        } else if (cred->deny) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "xrootd stage: %s of \"%s\" DENIED - per-user credential "
                "key=%s principal=\"%s\" %s (fallback=deny)",
                brix_stage_kind_str(kind), dst_key, cred->key,
                cred->principal, ru.expired ? "EXPIRED" : "missing");
            brix_xfer_finish(stage_kind_to_xfer(kind), stage_kind_dir(kind),
                dst_key, cred->principal, 0, BRIX_XFER_DENIED, EACCES, log);
            errno = EACCES;
            return BRIX_XFER_DENIED;
        } else {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "xrootd stage: per-user credential key=%s %s - flushing "
                "\"%s\" with the service credential (fallback=allow)",
                cred->key, ru.expired ? "EXPIRED" : "missing", dst_key);
        }
    }
```

    (verify the exact `BRIX_XFER_DENIED` enumerator name in `src/fs/xfer/xfer.h` — the result vocabulary includes a DENIED member; use its exact spelling.)
  - `stage_engine_move` gains `const brix_sd_cred_t *cred`; the dst open (:224) becomes `ds = brix_sd_staged_open_maybe_cred(dst, dst_key, mode, cred, &oerr);`. Source open stays plain (the stage store is local).
  - The audit line (:307): pass the principal instead of NULL: `(cred != NULL && cred->principal[0] != '\0') ? cred->principal : NULL`.
  - `brix_stage_run_inline_cred` = the old `brix_stage_run_inline` body with the cred threaded; `brix_stage_run_inline` becomes a one-line wrapper passing NULL.
  - `stage_flush_task_t` += `brix_stage_cred_t cred;` copied in `stage_flush_offload`; `stage_flush_thread` passes `&t->cred` (or NULL when `key[0]=='\0'`) into `stage_engine_run`. Same for the inline scheduler path (`p->cred`).

- [ ] **Step 5: Build + run both unit tests** — `make -j$(nproc)`; `sh tests/c/run_sreq_compat.sh`; `sh tests/c/run_ucred_tests.sh` — Expected: all pass.
- [ ] **Step 6: Commit** — ask Rob first.

---

### Task 7: xfer-ledger principal for every staged transfer (audit completeness)

**Files:**
- Modify: `src/fs/xfer/stage_engine.c` (done in Task 6 — this task VERIFIES end-to-end and covers the non-cred case)
- Test: extend `tests/run_xfer_audit_sink.sh` (already in the working tree, untracked) or add assertions to Task 8's e2e.

- [ ] **Step 1:** Confirm `brix_xfer_ledger_record` sanitizes the principal (`xfer_ledger.c` :212-214 — it does, via `brix_sanitize_log_string`). No code change.
- [ ] **Step 2:** Add to the Task 8 e2e (below): after the credentialed PUT, `grep 'kind=wt' "$AUDIT_LOG" | tail -1` must contain `principal="<A's DN>"`; after a deny-mode flush denial, the line must show `result=denied` (match the ledger's exact result-string table in `xfer.h`/`xfer_ledger.c`). This step lands as assertions in Task 8's script; nothing separate to build.

---

### Task 8: e2e — two users against a GSI origin, deny/allow/expiry/async-replay

**Files:**
- Create: `tests/run_user_backend_cred.sh`

**Interfaces:** Consumes everything above. Pattern: `tests/run_credential_xroot_gsi.sh` (own two-node fleet, PKI via `tests/pki_helpers.py`, DN assertions via the origin's error log `GSI auth OK dn="..."`).

**Design note (flag to Rob):** the shared fleet's GSI origin on port 11095 carries concurrent suite traffic, which makes "count auth lines by DN" assertions racy, and its PKI has a single test user. This script therefore spins its OWN GSI origin configured identically to the fleet's 11095 server (same `brix_auth gsi` + fleet PKI + a second user minted from the same CA), defaulting `OPORT=11195`; run with `OPORT=11095 ATTACH_FLEET=1` to point at the live fleet origin instead (assertions then only check line PRESENCE, not counts).

- [ ] **Step 1: Write the script** (it fails until the whole feature is in):

```bash
#!/bin/sh
# run_user_backend_cred.sh — Phase-1 per-user backend credentials, e2e.
#   1  user A (cred provisioned)  : davs PUT+GET → origin logs A's DN, bytes exact
#   2  user B (no cred), deny     : 403; origin sees NO new service/B auth line
#   3  user B (no cred), allow    : succeeds via the service DN + WARN fallback
#   4  expired cred for A, deny   : 403 + "EXPIRED" in the frontend error log
#   5  async flush ownership      : A's PUT (stage_flush async) → flush conn logs A's DN
#   6  restart replay             : journal record replayed after restart AS A
#   7  audit ledger               : kind=wt line carries principal="A's DN"
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
NGINX=${NGINX:-/tmp/nginx-1.28.3/objs/nginx}
TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"
PFX=/tmp/ucred-e2e; rm -rf "$PFX"
mkdir -p "$PFX/o/logs" "$PFX/o/root" "$PFX/f/logs" "$PFX/f/export" \
         "$PFX/f/stage" "$PFX/f/journal" "$PFX/creds"
OPORT=${OPORT:-11195}; FPORT=${FPORT:-18445}
CA_CERT="$TEST_ROOT/pki/ca/ca.pem"; CA_DIR="$TEST_ROOT/pki/ca"
SERVER_CERT="$TEST_ROOT/pki/server/hostcert.pem"
SERVER_KEY="$TEST_ROOT/pki/server/hostkey.pem"
PROXY_A="$TEST_ROOT/pki/user/proxy_std.pem"           # fleet test user = user A
ok()  { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; FAILED=1; }
FAILED=0

# -- PKI: reuse the fleet PKI; mint USER B from the same CA ------------------
if [ ! -f "$CA_CERT" ] || [ ! -f "$PROXY_A" ] \
   || ! openssl x509 -in "$PROXY_A" -noout -checkend 300 >/dev/null 2>&1; then
    ( cd "$HERE/tests" && PYTHONPATH=. python3 -c \
        "import pki_helpers; pki_helpers.blitz_test_pki()" ) \
        >"$PFX/o/logs/pki.log" 2>&1 || { echo "SKIP: PKI provisioning failed"; exit 0; }
fi
CA_KEY=$(ls "$CA_DIR"/ca*.key 2>/dev/null | head -1)
[ -n "$CA_KEY" ] || { echo "SKIP: CA key not found for user-B mint"; exit 0; }
B_DIR="$PFX/userb"; mkdir -p "$B_DIR"
openssl req -new -newkey rsa:2048 -nodes -keyout "$B_DIR/key.pem" \
    -subj "/DC=test/DC=xrootd/CN=Test User B/CN=67890" -out "$B_DIR/req.pem" \
    >/dev/null 2>&1
openssl x509 -req -in "$B_DIR/req.pem" -CA "$CA_CERT" -CAkey "$CA_KEY" \
    -set_serial 0x$(openssl rand -hex 8) -days 2 \
    -extfile /dev/stdin -out "$B_DIR/cert.pem" >/dev/null 2>&1 <<'EXT'
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EXT
A_DN=$(openssl x509 -in "$PROXY_A" -noout -subject -nameopt oneline 2>/dev/null)

# -- ORIGIN: GSI-only root:// (the fleet-11095 shape) ------------------------
if [ "${ATTACH_FLEET:-0}" != "1" ]; then
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${OPORT}; brix_root on; brix_export $PFX/o/root;
    brix_allow_write on;
    brix_auth gsi;
    brix_certificate     $SERVER_CERT;
    brix_certificate_key $SERVER_KEY;
    brix_trusted_ca      $CA_CERT;
} }
EOF
"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" || { echo "SKIP: origin start failed"; exit 0; }
OLOG="$PFX/o/logs/e.log"
else
OLOG="$TEST_ROOT/logs/error.log"
fi

# -- FRONTEND: davs with remote backend + per-user creds + async staging -----
mkfront() { # $1 = fallback mode
cat > "$PFX/f/nginx.conf" <<EOF
daemon on; error_log $PFX/f/logs/e.log info; pid $PFX/f/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    brix_credential origin { x509_proxy $PROXY_A; ca_dir $CA_DIR; }
    server {
        listen 127.0.0.1:${FPORT} ssl;
        ssl_certificate     $SERVER_CERT;
        ssl_certificate_key $SERVER_KEY;
        ssl_client_certificate $CA_CERT;
        ssl_verify_client optional;
        ssl_verify_depth 4;
        location / {
            brix_webdav on; brix_allow_write on;
            brix_export $PFX/f/export;
            brix_auth_cert on;
            brix_storage_backend root://127.0.0.1:${OPORT};
            brix_storage_credential origin;
            brix_storage_credential_dir $PFX/creds;
            brix_storage_credential_fallback $1;
            brix_stage on; brix_stage_store posix:$PFX/f/stage;
            brix_stage_flush async;
        }
    }
}
EOF
}
front() { mkfront "$1"; "$NGINX" -p "$PFX/f" -c "$PFX/f/nginx.conf"; sleep 0.3; }
front_stop() { [ -f "$PFX/f/nginx.pid" ] && kill "$(cat "$PFX/f/nginx.pid")" 2>/dev/null; sleep 0.3; }
CURL_A="curl -sk --cert $PROXY_A --key $PROXY_A"
CURL_B="curl -sk --cert $B_DIR/cert.pem --key $B_DIR/key.pem"
URL="https://127.0.0.1:${FPORT}"

# -- provision A's credential: derive the key from the frontend's own log ----
front deny
head -c 65536 /dev/urandom > /tmp/ucred_payload.bin
$CURL_A -o /dev/null -w '%{http_code}' -T /tmp/ucred_payload.bin "$URL/a1.bin" >/dev/null
A_KEY=$(grep -o 'key=x5h-[0-9a-f]*' "$PFX/f/logs/e.log" | head -1 | cut -d= -f2)
[ -n "$A_KEY" ] || { bad "no derived key logged for user A"; exit 1; }
cp "$PROXY_A" "$PFX/creds/$A_KEY.pem"

# 1: A with cred — PUT then GET byte-exact; origin saw A's DN
CODE=$($CURL_A -o /dev/null -w '%{http_code}' -T /tmp/ucred_payload.bin "$URL/a2.bin")
[ "$CODE" = "201" ] || [ "$CODE" = "204" ] && ok "A PUT accepted ($CODE)" || bad "A PUT -> $CODE"
sleep 2   # async flush tick
grep -q 'GSI auth OK dn=".*Test User' "$OLOG" && ok "origin authenticated a user DN" \
    || bad "no GSI user auth line at the origin"
$CURL_A -o /tmp/ucred_back.bin "$URL/a2.bin"
cmp -s /tmp/ucred_payload.bin /tmp/ucred_back.bin && ok "A GET byte-exact" || bad "A GET differs"

# 2: B without cred, deny — 403 and no fallback ride
SVC_LINES=$(grep -c 'GSI auth OK' "$OLOG" || true)
CODE=$($CURL_B -o /dev/null -w '%{http_code}' -T /tmp/ucred_payload.bin "$URL/b1.bin")
[ "$CODE" = "403" ] && ok "B PUT denied (403)" || bad "B PUT -> $CODE (want 403)"
grep -q 'fallback=deny.*refusing\|refusing.*fallback=deny' "$PFX/f/logs/e.log" \
    && ok "deny logged with principal" || bad "no deny ERR log"
NEW_LINES=$(grep -c 'GSI auth OK' "$OLOG" || true)
[ "$NEW_LINES" = "$SVC_LINES" ] && ok "B never reached the origin (no service-cred ride)" \
    || bad "origin auth lines grew during a denied request"

# 3: B without cred, allow — succeeds on the service credential
front_stop; front allow
CODE=$($CURL_B -o /dev/null -w '%{http_code}' -T /tmp/ucred_payload.bin "$URL/b2.bin")
{ [ "$CODE" = "201" ] || [ "$CODE" = "204" ]; } && ok "B PUT allowed via fallback ($CODE)" \
    || bad "B PUT fallback -> $CODE"
grep -q 'falling back to the service credential' "$PFX/f/logs/e.log" \
    && ok "fallback WARN/INFO logged" || bad "no fallback log"

# 4: expired credential for A, deny — 403 + EXPIRED
front_stop
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$PFX/creds/expired.key" \
    -subj "/CN=expired" -days -1 -out "$PFX/creds/$A_KEY.pem" >/dev/null 2>&1
front deny
CODE=$($CURL_A -o /dev/null -w '%{http_code}' -T /tmp/ucred_payload.bin "$URL/a3.bin")
[ "$CODE" = "403" ] && ok "expired cred denied (403)" || bad "expired cred -> $CODE"
grep -q 'EXPIRED' "$PFX/f/logs/e.log" && ok "expiry named in the log" || bad "no EXPIRED log"
cp "$PROXY_A" "$PFX/creds/$A_KEY.pem"      # restore for the replay test

# 5+6: async flush ownership + restart replay: PUT as A, kill BEFORE the tick,
# restart, reconcile must replay the journal record AS A.
front_stop; front deny
OLD_AUTH=$(grep -c 'GSI auth OK' "$OLOG" || true)
$CURL_A -o /dev/null -T /tmp/ucred_payload.bin "$URL/a4.bin"
kill -9 "$(cat "$PFX/f/nginx.pid")" 2>/dev/null   # crash before the scheduler tick
front deny; sleep 3                                # reconcile + tick replays the flush
NEW_AUTH=$(grep -c 'GSI auth OK' "$OLOG" || true)
[ "$NEW_AUTH" -gt "$OLD_AUTH" ] && ok "restart replay reauthenticated at the origin" \
    || bad "no origin auth after restart replay"
grep 'GSI auth OK' "$OLOG" | tail -1 | grep -q 'Test User' \
    && ok "replayed flush carried the OWNER's DN" || bad "replayed flush wrong identity"

# 7: audit ledger principal
AUDIT=$(ls "$PFX"/f/logs/xfer_audit.log 2>/dev/null || true)
if [ -n "$AUDIT" ]; then
    grep 'kind=wt' "$AUDIT" | grep -q 'principal="' \
        && ok "ledger carries the flush principal" || bad "ledger principal missing"
else
    echo "NOTE: no xfer_audit.log at the default sink - set BRIX_XFER_AUDIT_LOG to assert"
fi

front_stop
[ "${ATTACH_FLEET:-0}" != "1" ] && [ -f "$PFX/o/nginx.pid" ] \
    && kill "$(cat "$PFX/o/nginx.pid")" 2>/dev/null
exit $FAILED
```

- [ ] **Step 2: Run to verify it fails** at the first feature assertion (before Tasks 1-6 land: unknown directive → frontend start fails). Expected while developing; after all tasks: every PASS, exit 0.
- [ ] **Step 3: Iterate.** Reconcile the script against reality where the harness guesses (fleet CA key filename; the exact `GSI auth OK dn=` format; whether the frontend needs the origin-write staging journal `brix_stage_engine_init` wiring for `$PFX/f/journal` — check how existing tests enable the journal dir, e.g. grep `stage_journal|journal_dir` in tests/ and conf directives; adjust `sleep` waits to the scheduler tick). Fix the PRODUCT when the product is wrong, the script when the harness is wrong — never weaken an assertion to pass.
- [ ] **Step 4: Full regression** — `tests/run_suite.sh --fast` — Expected: green.
- [ ] **Step 5: Commit** — ask Rob first.

---

### Task 9: Documentation

**Files:**
- Create: `docs/10-reference/per-user-backend-credentials.md`
- Modify: `src/fs/backend/README.md` (done in Task 2), `src/fs/vfs/README.md` (one row for `vfs_cred.c`)

- [ ] **Step 1:** Write the reference page: the two directives (+ defaults), the credential-directory **naming scheme verbatim from this plan's vocabulary section**, the key-discovery log line, expiry semantics (checked at request open AND at flush; deny ⇒ EACCES/403 + `result=denied` ledger line), async-ownership design (journal record carries key+principal+dir+mode; re-resolved at flush; legacy records replay on the service credential), the Phase-1 limitations table (namespace ops on service cred; x509-only; HTTP-plane only) and the follow-ups list from this plan's out-of-scope section.
- [ ] **Step 2:** `tools/ci/check_links.sh` (or the repo's link guard) + `tools/ci/check_vfs_seam.sh` — Expected: green.
- [ ] **Step 3: Commit** — ask Rob first.

---

## Self-review checklist (run after drafting, before execution)

1. **Spec coverage**: directive ✓(T1), naming scheme ✓(T2+docs), selection at session creation ✓(T3/T4), session keying answered (per-open; no pooling) ✓, async ownership across restart ✓(T6), expiry loud-fail ✓(T2/T4/T6), identity plumbing without globals ✓(T4 params + embedded copies), 3-test rule ✓(T8 cases 1/2/4 + security-negative 2+5/6), e2e vs GSI origin ✓(T8), no goto ✓, helpers reused (auth_gsi, credential threading, sanitize) ✓.
2. **Known verify-on-site points** (implementer must check, listed deliberately): exact `BRIX_XFER_DENIED` enumerator spelling; `brix_vfs_ctx_init` zeroing; sd_cache partial-fill struct name; S3 AIO conf availability; journal-dir enablement directive for the e2e; fleet CA key filename; `GSI auth OK dn=` exact format.
3. **Type consistency**: `brix_stage_cred_t` uses `uint8_t deny` (POD journal), `brix_sd_cred_t` uses a bitfield (never persisted) — intentional, do not "harmonize".
