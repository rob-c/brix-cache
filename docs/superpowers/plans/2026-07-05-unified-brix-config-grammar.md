# Unified brix Config Grammar Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One guessable directive grammar across root://, WebDAV, S3, and cvmfs — per-protocol enables plus a unified bare storage directive set (`brix_export`, `brix_cache_store`, `brix_stage`, …) owned by a new HTTP common module — with a production-grade 3-line cvmfs site cache, loud config errors for unsupported combinations, and matching docs.

**Architecture:** A new `ngx_http_brix_common_module` registers the unified storage/namespace directives exactly once for the HTTP plane, storing them in an `ngx_http_brix_shared_conf_t` it owns; webdav/s3/cvmfs copy the merged values into their embedded `common` structs at `merge_loc_conf` time (module emission order in `./config` guarantees the common module merges first). The stream plane already uses the bare names and only renames its enable (`xrootd`→`brix_export`) and export path (`brix_export`→`brix_export`). Old names are hard-renamed — no aliases.

**Tech Stack:** nginx module C (no goto, functional/modular per `docs/09-developer-guide/coding-standards.md`), bash test harnesses, pytest fleet.

**Spec:** `docs/superpowers/specs/2026-07-05-unified-brix-config-grammar-design.md`

## Global Constraints

- **NO `goto`**; early-return + helper decomposition; WHAT/WHY/HOW doc blocks on every function.
- 3 tests per change-class: success + error + security-negative.
- Never reimplement HELPERS (CLAUDE.md list); use `ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, …); return NGX_CONF_ERROR;` for config rejections (pattern: `src/protocols/cvmfs/module.c:371-382`).
- New source file ⇒ update `./config`, then `rm -rf /tmp/nginx-1.28.3/objs && (cd /tmp/nginx-1.28.3 && ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=/home/rcurrie/HEP-x/nginx-xrootd) && make -j$(nproc)` — configure over old objs produces mixed-ABI garbage. No new file ⇒ `make -j$(nproc)` only. Build is `-Werror`.
- Commit directly to `main` after each task (Rob: no feature branches). Do NOT run destructive git commands (stash/reset/checkout/clean).
- `site/src/pages/for/sysadmins.astro` and `site/src/pages/index.astro` carry UNCOMMITTED user edits — touch only directive-name occurrences, via Edit tool, never git-restore.
- Test fleet: `tests/manage_test_servers.sh start|restart|stop`; heavy suites cap xdist at `-n12`; `TEST_OWN_FLEET=1` runs must be SERIAL.
- Hard rename means NO alias code and NO "renamed to X" messages anywhere.

---

### Task 1: `ngx_http_brix_common_module` (additive — old names keep working)

**Files:**
- Create: `src/core/config/http_common.h`
- Create: `src/core/config/http_common.c`
- Modify: `./config` (emit the new module BEFORE the webdav/s3/cvmfs module blocks, ~line 960)
- Modify: `src/protocols/webdav/config.c` (`ngx_http_brix_webdav_merge_loc_conf`)
- Modify: `src/protocols/s3/module.c:77` (`ngx_http_s3_merge_loc_conf`)
- Modify: `src/protocols/cvmfs/module.c:~280` (`ngx_http_brix_cvmfs_merge_loc_conf`)
- Test: `tests/run_unified_conf.sh`

**Interfaces:**
- Produces: `ngx_module_t ngx_http_brix_common_module`; `typedef struct { ngx_http_brix_shared_conf_t common; } ngx_http_brix_common_conf_t;`; `void brix_shared_adopt_unified(ngx_http_brix_shared_conf_t *dst, const ngx_http_brix_shared_conf_t *src);` (copies each unified field into `dst` only where `dst` is UNSET and `src` is set); `void brix_http_common_adopt(ngx_conf_t *cf, ngx_http_brix_shared_conf_t *dst);` (fetch + adopt).
- Consumes: `ngx_http_brix_shared_init/merge` (`src/core/config/shared_conf.h:130,210`), `BRIX_TIER_DIRECTIVES` (`src/core/config/tier_directives.h:44`), `brix_conf_set_store_slot`.

- [ ] **Step 1: Write the failing test**

Create `tests/run_unified_conf.sh` (model: `tests/run_cvmfs_reverse.sh` harness conventions — `ok`/`bad` helpers, scratch prefix, `nginx -t`):

```bash
#!/usr/bin/env bash
# Unified brix config grammar: bare storage directives valid on the HTTP
# plane, inherited server->location, coexisting with (for now) old names.
set -u
NGINX_BIN=${NGINX_BIN:-/tmp/nginx-1.28.3/objs/nginx}
PFX=$(mktemp -d /tmp/unified-conf.XXXXXX); mkdir -p "$PFX"/{logs,data,cache}
pass=0; fail=0
ok()  { echo "ok  - $1"; pass=$((pass+1)); }
bad() { echo "FAIL- $1"; fail=$((fail+1)); }

t() { # t <name> <expect:0|1> <config-body>
    local name=$1 expect=$2 body=$3
    cat > "$PFX/nginx.conf" <<EOF
daemon off; pid $PFX/nginx.pid; error_log $PFX/logs/err.log warn;
thread_pool default threads=2;
events { worker_connections 64; }
http { $body }
EOF
    "$NGINX_BIN" -t -c "$PFX/nginx.conf" -p "$PFX" >/dev/null 2>&1
    local rc=$?
    if [ "$expect" = 0 ] && [ $rc -eq 0 ]; then ok "$name";
    elif [ "$expect" = 1 ] && [ $rc -ne 0 ]; then ok "$name";
    else bad "$name (rc=$rc, expected exit $expect)"; fi
}

# success: unified names at location level under webdav
t "unified names parse in webdav location" 0 "
server { listen 127.0.0.1:18499;
  location /dav/ {
    brix_webdav on;
    brix_export $PFX/data;
    brix_cache_store posix:$PFX/cache;
    brix_cache_evict_at 85; brix_cache_evict_to 70;
  } }"

# success: server-level unified directives inherit into locations
t "server-level brix_cache_store inherits" 0 "
server { listen 127.0.0.1:18499;
  brix_cache_store posix:$PFX/cache;
  brix_export $PFX/data;
  location /dav/ { brix_webdav on; }
  location /v/   { brix_s3 on; brix_s3_bucket b; } }"

# error: malformed unified directive still rejected
t "brix_cache_evict_at rejects non-numeric" 1 "
server { listen 127.0.0.1:18499;
  location /dav/ { brix_webdav on; brix_export $PFX/data;
    brix_cache_evict_at lots; } }"

echo "unified_conf: $pass passed, $fail failed"; rm -rf "$PFX"
[ $fail -eq 0 ]
```

- [ ] **Step 2: Run it to verify it fails**

Run: `bash tests/run_unified_conf.sh`
Expected: FAIL — `unknown directive "brix_export"` / `"brix_cache_store"` in http context (only per-proto names exist today).

- [ ] **Step 3: Write `src/core/config/http_common.h`**

```c
/* http_common.h — unified brix storage/namespace directives (HTTP plane)
 *
 * WHAT: one module owns the bare storage grammar (brix_export,
 *       brix_storage_backend, brix_cache_*, brix_stage*, brix_thread_pool,
 *       brix_cache_verify, brix_allow_write, brix_read_only, brix_compress)
 *       so every brix HTTP protocol shares a single directive surface.
 * WHY:  nginx's ngx_conf_handler is first-module-wins on directive names,
 *       so a shared name must be registered by exactly one http module.
 * HOW:  values land in this module's ngx_http_brix_shared_conf_t; protocol
 *       modules copy the merged values into their embedded `common` via
 *       brix_http_common_adopt() at merge_loc_conf time.  Module emission
 *       order in ./config puts this module before the protocol modules, so
 *       its merge for a given location always precedes theirs.
 */
#ifndef BRIX_HTTP_COMMON_H
#define BRIX_HTTP_COMMON_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "core/config/shared_conf.h"

typedef struct {
    ngx_http_brix_shared_conf_t  common;
} ngx_http_brix_common_conf_t;

extern ngx_module_t  ngx_http_brix_common_module;

/* Copy every unified field from src into dst where dst is still UNSET.
 * Pure, no allocation; both structs must be shared_init()-initialized. */
void brix_shared_adopt_unified(ngx_http_brix_shared_conf_t *dst,
                               const ngx_http_brix_shared_conf_t *src);

/* Fetch the common module's conf for the location currently being merged
 * and adopt it into dst.  Call from a protocol's merge_loc_conf BEFORE
 * ngx_http_brix_shared_merge(). */
void brix_http_common_adopt(ngx_conf_t *cf,
                            ngx_http_brix_shared_conf_t *dst);

#endif /* BRIX_HTTP_COMMON_H */
```

- [ ] **Step 4: Write `src/core/config/http_common.c`**

```c
/* http_common.c — see http_common.h for the WHAT/WHY/HOW. */
#include "core/config/http_common.h"
#include "core/config/tier_directives.h"

static void *brix_http_common_create_loc_conf(ngx_conf_t *cf);
static char *brix_http_common_merge_loc_conf(ngx_conf_t *cf,
                                             void *parent, void *child);

/* brix_cache_verify values on the HTTP plane.  Only the cvmfs-cas scheme
 * exists here today (stream has best-effort/require via its own handler);
 * protocol merges validate which values they support. */
static ngx_conf_enum_t  brix_http_cache_verify_enum[] = {
    { ngx_string("off"),       0 },                          /* BRIX_CACHE_VERIFY_OFF */
    { ngx_string("cvmfs-cas"), 3 },                          /* BRIX_CACHE_VERIFY_CVMFS_CAS */
    { ngx_null_string, 0 }
};
/* NOTE for implementer: replace the literals 0/3 with the
 * BRIX_CACHE_VERIFY_OFF / BRIX_CACHE_VERIFY_CVMFS_CAS enumerators from
 * src/fs/cache/verify.h:38-44 and include that header. */

#define BRIX_HTTP_ALL_CONF \
    (NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF)

static ngx_command_t  brix_http_common_commands[] = {

    { ngx_string("brix_export"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.root),
      NULL },

    { ngx_string("brix_storage_backend"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_backend),
      NULL },

    { ngx_string("brix_storage_credential"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_credential),
      NULL },

    { ngx_string("brix_allow_write"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.allow_write),
      NULL },

    { ngx_string("brix_read_only"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.read_only),
      NULL },

    { ngx_string("brix_compress"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.compress),
      NULL },

    { ngx_string("brix_thread_pool"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.thread_pool_name),
      NULL },

    { ngx_string("brix_cache_verify"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.cache_verify_mode),
      &brix_http_cache_verify_enum },

    /* The 10 tier directives: brix_cache_store, brix_stage,
     * brix_stage_store, brix_stage_flush, brix_cache_max_object,
     * brix_cache_evict_at, brix_cache_evict_to, brix_cache_index_cache,
     * brix_cache_meta, brix_cache_slice_size. */
    BRIX_TIER_DIRECTIVES("brix_", ngx_http_brix_common_conf_t,
                         BRIX_HTTP_ALL_CONF, NGX_HTTP_LOC_CONF_OFFSET)

      ngx_null_command
};

static ngx_http_module_t  brix_http_common_module_ctx = {
    NULL, NULL,                          /* pre/postconfiguration */
    NULL, NULL,                          /* create/init main conf */
    NULL, NULL,                          /* create/merge srv conf */
    brix_http_common_create_loc_conf,
    brix_http_common_merge_loc_conf
};

ngx_module_t  ngx_http_brix_common_module = {
    NGX_MODULE_V1,
    &brix_http_common_module_ctx,
    brix_http_common_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

static void *
brix_http_common_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_brix_common_conf_t  *c;

    c = ngx_pcalloc(cf->pool, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }
    ngx_http_brix_shared_init(&c->common);
    return c;
}

/* Inheritance-only merge: propagate parent values into unset child slots.
 * Deliberately applies NO defaults — per-protocol defaults still come from
 * ngx_http_brix_shared_merge() in each protocol's merge, so a field left
 * unset here stays UNSET and lets each protocol pick its own default. */
static char *
brix_http_common_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_brix_common_conf_t  *prev = parent;
    ngx_http_brix_common_conf_t  *conf = child;

    brix_shared_adopt_unified(&conf->common, &prev->common);
    return NGX_CONF_OK;
}

#define BRIX_ADOPT_STR(f) \
    do { if (dst->f.data == NULL && src->f.data != NULL) dst->f = src->f; } while (0)
#define BRIX_ADOPT_VAL(f, unset) \
    do { if (dst->f == (unset) && src->f != (unset)) dst->f = src->f; } while (0)
#define BRIX_ADOPT_PTR(f) \
    do { if (dst->f == NULL && src->f != NULL) dst->f = src->f; } while (0)

void
brix_shared_adopt_unified(ngx_http_brix_shared_conf_t *dst,
                          const ngx_http_brix_shared_conf_t *src)
{
    BRIX_ADOPT_STR(root);
    BRIX_ADOPT_STR(storage_backend);
    BRIX_ADOPT_STR(storage_credential);
    BRIX_ADOPT_STR(thread_pool_name);
    BRIX_ADOPT_STR(cache_store);
    BRIX_ADOPT_PTR(cache_store_args);
    BRIX_ADOPT_STR(stage_store);
    BRIX_ADOPT_PTR(stage_store_args);
    BRIX_ADOPT_VAL(allow_write,       NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(read_only,         NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(compress,          NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(stage_enable,      NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(stage_flush_async, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(cache_max_object,  NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(cache_evict_at,    NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(cache_evict_to,    NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(cache_index_cache, (size_t) NGX_CONF_UNSET_SIZE);
    BRIX_ADOPT_VAL(cache_meta_mode,   NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(cache_slice_size,  (size_t) NGX_CONF_UNSET_SIZE);
    BRIX_ADOPT_VAL(cache_verify_mode, NGX_CONF_UNSET_UINT);
}

void
brix_http_common_adopt(ngx_conf_t *cf, ngx_http_brix_shared_conf_t *dst)
{
    ngx_http_brix_common_conf_t  *ucf;

    ucf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_brix_common_module);
    if (ucf == NULL) {
        return;
    }
    brix_shared_adopt_unified(dst, &ucf->common);
}
```

**Implementer notes (verify against the real headers, do not guess):**
- Field names/UNSET sentinels come from `src/core/config/shared_conf.h:32-116` — check the exact type of each field (`ngx_flag_t` uses `NGX_CONF_UNSET`, `ngx_uint_t` uses `NGX_CONF_UNSET_UINT`, `size_t` uses `NGX_CONF_UNSET_SIZE`, `off_t` uses `NGX_CONF_UNSET`). Fix the macros' unset args to match, and adopt ANY additional unified fields the struct carries for these directives.
- Check `BRIX_TIER_DIRECTIVES`'s exact parameter meaning at `tier_directives.h:44` — S3 passes `NGX_HTTP_LOC_CONF`; passing `BRIX_HTTP_ALL_CONF` widens context to main/srv. If the macro hardcodes a trailing context internally, widen there instead.
- `brix_cache_evict_at` and the enum literal cleanup per the NOTE comments.

- [ ] **Step 5: Register in `./config`**

Find the webdav HTTP module emission block (`ngx_module_name=ngx_http_brix_webdav_module`, ~line 960). BEFORE it, add a new emission block modeled on it exactly (same `xrd_emit_module` / `. auto/module` wrapper the file uses):

```sh
ngx_module_type=HTTP
ngx_module_name=ngx_http_brix_common_module
ngx_module_srcs="$ngx_addon_dir/src/core/config/http_common.c"
ngx_module_deps="$ngx_addon_dir/src/core/config/http_common.h \
                 $ngx_addon_dir/src/core/config/shared_conf.h \
                 $ngx_addon_dir/src/core/config/tier_directives.h"
```

(Adapt to the file's actual emission idiom — read the webdav block first and mirror it.) Module order requirement: common BEFORE webdav/s3/cvmfs, so its `merge_loc_conf` runs first for every location.

- [ ] **Step 6: Add adopt calls to the three protocol merges**

At the TOP of each merge function, before any `ngx_http_brix_shared_merge` call:

```c
    /* Unified directives (brix_export, brix_cache_store, ...) live in the
     * common module; pull the merged values for this location into our
     * embedded preamble before protocol merge applies defaults. */
    brix_http_common_adopt(cf, &conf->common);
```

Locations: `ngx_http_brix_webdav_merge_loc_conf` (`src/protocols/webdav/config.c`), `ngx_http_s3_merge_loc_conf` (`src/protocols/s3/module.c:77`), `ngx_http_brix_cvmfs_merge_loc_conf` (`src/protocols/cvmfs/module.c:~280`). Add `#include "core/config/http_common.h"` to each file.

- [ ] **Step 7: Full rebuild (new source file)**

```bash
cd /tmp/nginx-1.28.3 && rm -rf objs && \
  ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
    --with-http_dav_module --with-threads \
    --add-module=/home/rcurrie/HEP-x/nginx-xrootd && make -j$(nproc)
```
Expected: exit 0, `-Werror` clean.

- [ ] **Step 8: Run the test**

Run: `bash tests/run_unified_conf.sh`
Expected: `unified_conf: 3 passed, 0 failed`

- [ ] **Step 9: Regression: fleet still green with OLD names**

```bash
tests/manage_test_servers.sh restart
PYTHONPATH=tests pytest tests/ -k "webdav or s3" -n12 -m "not slow" -q --tb=short
```
Expected: pass rates identical to pre-change (old per-proto directives untouched; adopt only fills unset fields).

- [ ] **Step 10: Commit**

```bash
git add src/core/config/http_common.c src/core/config/http_common.h config \
        src/protocols/webdav/config.c src/protocols/s3/module.c \
        src/protocols/cvmfs/module.c tests/run_unified_conf.sh
git commit -m "feat(config): unified brix storage grammar via http common module"
```

---

### Task 2: One protocol per location / per port (config-load validation)

**Files:**
- Create: `src/protocols/shared/proto_exclusive.c`
- Create: `src/protocols/shared/proto_exclusive.h`
- Modify: `src/protocols/webdav/postconfig.c:17` (call the check at the end of `ngx_http_brix_webdav_postconfiguration`)
- Modify: `./config` (add the new .c to the webdav or shared source list + header dep)
- Test: extend `tests/run_unified_conf.sh`

**Interfaces:**
- Produces: `ngx_int_t brix_http_proto_exclusive_check(ngx_conf_t *cf);` — returns `NGX_OK` or logs EMERG and returns `NGX_ERROR`.
- Consumes: `ngx_http_brix_webdav_loc_conf_t.common.enable`, `ngx_http_s3_loc_conf_t.common.enable`, `ngx_http_brix_cvmfs_loc_conf_t.cvmfs.enable`; `ngx_http_core_module` location tree.

- [ ] **Step 1: Write the failing tests** — append to `tests/run_unified_conf.sh`:

```bash
# error: two protocols in one location
t "two protocols in one location rejected" 1 "
server { listen 127.0.0.1:18499;
  location / { brix_webdav on; brix_export $PFX/data;
               brix_s3 on; brix_s3_bucket b; } }"

# error: two protocols under one listen port (different locations)
t "two protocols on one port rejected" 1 "
server { listen 127.0.0.1:18499;
  location /dav/ { brix_webdav on; brix_export $PFX/data; }
  location /v/   { brix_s3 on; brix_s3_bucket b; brix_export $PFX/data; } }"

# success: same two protocols on different ports
t "protocols on separate ports accepted" 0 "
server { listen 127.0.0.1:18499;
  location /dav/ { brix_webdav on; brix_export $PFX/data; } }
server { listen 127.0.0.1:18498;
  location /v/   { brix_s3 on; brix_s3_bucket b; brix_export $PFX/data; } }"
```

- [ ] **Step 2: Run to verify the two error cases fail** (`bash tests/run_unified_conf.sh` — the "rejected" tests report FAIL because nginx accepts the configs today).

- [ ] **Step 3: Implement the walker** — `src/protocols/shared/proto_exclusive.c`:

```c
/* proto_exclusive.c — enforce "one brix protocol per location, per port".
 *
 * WHAT: config-load validation that at most one brix protocol (webdav, s3,
 *       cvmfs) is enabled in any location, and that all brix-enabled
 *       locations under one listen port speak the same protocol.
 * WHY:  the unified storage directives (brix_cache_store, brix_export, ...)
 *       are per-location; a single owning protocol keeps their meaning
 *       unambiguous, and one-protocol-per-port is the deployment model.
 * HOW:  called from the webdav postconfiguration (which runs after ALL
 *       module merges).  Walks cmcf->ports -> addrs -> servers, and each
 *       server's location tree, reading each protocol's enable flag.
 *       brix_scvmfs is a layer on cvmfs, not a second protocol.  The
 *       stream-plane handoff mux is out of scope (stream, not http).
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "protocols/shared/proto_exclusive.h"
#include "protocols/webdav/webdav.h"
#include "protocols/s3/s3.h"
#include "protocols/cvmfs/cvmfs.h"

#define BRIX_PROTO_NONE    0u
#define BRIX_PROTO_WEBDAV  (1u << 0)
#define BRIX_PROTO_S3      (1u << 1)
#define BRIX_PROTO_CVMFS   (1u << 2)

static const char *
brix_proto_name(ngx_uint_t bit)
{
    if (bit & BRIX_PROTO_WEBDAV) return "brix_webdav";
    if (bit & BRIX_PROTO_S3)     return "brix_s3";
    return "brix_cvmfs";
}

/* Which brix protocols does this location's conf array enable? */
static ngx_uint_t
brix_proto_mask(void **loc_conf)
{
    ngx_uint_t                        mask = BRIX_PROTO_NONE;
    ngx_http_brix_webdav_loc_conf_t  *w;
    ngx_http_s3_loc_conf_t           *s;
    ngx_http_brix_cvmfs_loc_conf_t   *c;

    w = loc_conf[ngx_http_brix_webdav_module.ctx_index];
    s = loc_conf[ngx_http_brix_s3_module.ctx_index];
    c = loc_conf[ngx_http_brix_cvmfs_module.ctx_index];

    if (w != NULL && w->common.enable == 1)  mask |= BRIX_PROTO_WEBDAV;
    if (s != NULL && s->common.enable == 1)  mask |= BRIX_PROTO_S3;
    if (c != NULL && c->cvmfs.enable == 1)   mask |= BRIX_PROTO_CVMFS;
    return mask;
}

/* Recurse a location tree, OR-ing protocol masks; error on a location
 * that enables more than one protocol itself. */
static ngx_int_t
brix_proto_walk_locations(ngx_conf_t *cf, ngx_http_core_loc_conf_t *clcf,
                          ngx_uint_t *server_mask)
{
    ngx_queue_t                *q;
    ngx_http_location_queue_t  *lq;
    ngx_http_core_loc_conf_t   *sub;
    ngx_uint_t                  mask;

    mask = brix_proto_mask(clcf->loc_conf);
    if (mask & (mask - 1)) {            /* more than one bit set */
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "two brix protocols enabled in location \"%V\" — "
            "one brix protocol per location", &clcf->name);
        return NGX_ERROR;
    }
    *server_mask |= mask;

    if (clcf->locations == NULL) {
        return NGX_OK;
    }
    for (q = ngx_queue_head(clcf->locations);
         q != ngx_queue_sentinel(clcf->locations);
         q = ngx_queue_next(q))
    {
        lq = (ngx_http_location_queue_t *) q;
        sub = lq->exact ? lq->exact : lq->inclusive;
        if (sub == NULL) {
            continue;
        }
        if (brix_proto_walk_locations(cf, sub, server_mask) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

static ngx_int_t
brix_proto_server_mask(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
                       ngx_uint_t *mask)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = cscf->ctx->loc_conf[ngx_http_core_module.ctx_index];
    return brix_proto_walk_locations(cf, clcf, mask);
}

ngx_int_t
brix_http_proto_exclusive_check(ngx_conf_t *cf)
{
    ngx_uint_t                  p, a, s;
    ngx_uint_t                  port_mask, srv_mask;
    ngx_http_conf_port_t       *port;
    ngx_http_conf_addr_t       *addr;
    ngx_http_core_srv_conf_t  **cscf;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (cmcf->ports == NULL) {
        return NGX_OK;
    }

    port = cmcf->ports->elts;
    for (p = 0; p < cmcf->ports->nelts; p++) {
        port_mask = BRIX_PROTO_NONE;
        addr = port[p].addrs.elts;

        for (a = 0; a < port[p].addrs.nelts; a++) {
            cscf = addr[a].servers.elts;
            for (s = 0; s < addr[a].servers.nelts; s++) {
                srv_mask = BRIX_PROTO_NONE;
                if (brix_proto_server_mask(cf, cscf[s], &srv_mask)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
                port_mask |= srv_mask;
            }
        }

        if (port_mask & (port_mask - 1)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "%s and %s both enabled under listen port %ui — "
                "one brix protocol per port",
                brix_proto_name(port_mask & -port_mask),
                brix_proto_name(port_mask & (port_mask - 1)),
                (ngx_uint_t) ntohs(port[p].port));
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}
```

**Implementer notes:** verify the `ngx_http_conf_port_t`/`ngx_http_conf_addr_t` field names against the nginx 1.28 headers (`ngx_http_core_module.h`) — `port[p].port` is in network order in some versions, host order in others; print with the correct conversion. Verify `addr[a].servers` element type (`ngx_http_core_srv_conf_t *`). Header `proto_exclusive.h`: standard guard + the one prototype.

- [ ] **Step 4: Call it from webdav postconfig** — at the end of `ngx_http_brix_webdav_postconfiguration` (before the final `return NGX_OK;`):

```c
    if (brix_http_proto_exclusive_check(cf) != NGX_OK) {
        return NGX_ERROR;
    }
```

Add `#include "protocols/shared/proto_exclusive.h"`. Add the `.c` to `./config` (webdav module srcs list) and the header to its deps.

- [ ] **Step 5: Full rebuild** (new source file ⇒ `rm -rf objs && ./configure && make`). Expected exit 0.

- [ ] **Step 6: Run tests** — `bash tests/run_unified_conf.sh`. Expected: all 6 pass. Also `manage_test_servers.sh restart` must still come up green (the existing fleet never mixes protocols on a port — if any test config legitimately does, examine it: metrics/healthz locations don't count, only brix protocol enables).

- [ ] **Step 7: Commit** — `git commit -m "feat(config): enforce one brix protocol per location and per port"`

---

### Task 3: cvmfs rejections + geo validation

**Files:**
- Modify: `src/protocols/cvmfs/module.c` (merge_loc_conf, around the existing `conf->common.allow_write = 0;` at ~line 445)
- Test: extend `tests/run_unified_conf.sh`

**Interfaces:**
- Consumes: `conf->common.stage_enable/stage_store/cache_slice_size/allow_write` (set via unified directives after Task 1), `conf->cvmfs.origin_select/origin_coords`, existing geo check `cvmfs_geo_rank_config` (`module.c:166-173`).

- [ ] **Step 1: Failing tests** — append to `tests/run_unified_conf.sh`:

```bash
CV="brix_cvmfs on; brix_storage_backend http://127.0.0.1:1;
    brix_cache_store posix:$PFX/cache;"

t "brix_stage under cvmfs rejected" 1 "
server { listen 127.0.0.1:18499; location / { $CV brix_stage on; } }"

t "brix_cache_slice_size under cvmfs rejected" 1 "
server { listen 127.0.0.1:18499; location / { $CV brix_cache_slice_size 1m; } }"

t "brix_allow_write under cvmfs rejected" 1 "
server { listen 127.0.0.1:18499; location / { $CV brix_allow_write on; } }"

t "origin_select geo without brix_cvmfs_here rejected" 1 "
server { listen 127.0.0.1:18499; location / { $CV
  brix_cvmfs_origin_select geo; } }"
```

- [ ] **Step 2: Run — verify** stage/slice/allow_write cases FAIL today (silently accepted); the geo case may already pass (existing check at `module.c:166-173` — if so, keep the test as regression coverage).

- [ ] **Step 3: Implement** — in `ngx_http_brix_cvmfs_merge_loc_conf`, inside the `if (conf->cvmfs.enable == 1)` region (create a small helper to keep the merge function readable):

```c
/* Reject storage grammar cvmfs cannot honor.  cvmfs is a read-only
 * content-addressed cache: staging and writes have no meaning, and CAS
 * objects are immutable whole objects so slicing never applies. */
static char *
brix_cvmfs_reject_unsupported(ngx_conf_t *cf,
                              ngx_http_brix_cvmfs_loc_conf_t *conf)
{
    if (conf->common.stage_enable == 1
        || conf->common.stage_store.data != NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_stage/brix_stage_store: cvmfs is a read-only protocol");
        return NGX_CONF_ERROR;
    }
    if (conf->common.cache_slice_size != NGX_CONF_UNSET_SIZE
        && conf->common.cache_slice_size != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_slice_size: cvmfs CAS objects are immutable "
            "whole objects; slicing is not supported");
        return NGX_CONF_ERROR;
    }
    if (conf->common.allow_write == 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_allow_write: cvmfs is a read-only protocol");
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}
```

Call it BEFORE the existing hard-force `conf->common.allow_write = 0;` (the force stays as belt-and-braces; the reject fires only on explicit `on`). Check the UNSET sentinels against the real field types. Ordering caution: the check must run AFTER `brix_http_common_adopt()` (Task 1) so unified-directive values are visible, and AFTER `conf->cvmfs.enable` is merged (`module.c:316`).

Geo: confirm `cvmfs_geo_rank_config` already EMERGs on geo-without-here; add the WARN for coords-without-geo next to it:

```c
    if (conf->cvmfs.origin_select != BRIX_CVMFS_SELECT_GEO
        && conf->cvmfs.origin_coords != NULL)
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix_cvmfs_origin_coords set but brix_cvmfs_origin_select "
            "is not geo — coordinates are ignored");
    }
```

(WARN not NOTICE — config-parse NOTICE is dropped, `cf->log` is ERR-level.)

- [ ] **Step 4: `make -j$(nproc)`** (no new file), then `bash tests/run_unified_conf.sh` — all pass.
- [ ] **Step 5: cvmfs regression** — `bash tests/run_cvmfs_reverse.sh && bash tests/run_cvmfs_proxy.sh`. Expected: PASS unchanged.
- [ ] **Step 6: Commit** — `git commit -m "feat(cvmfs): reject staging/slicing/writes at config load; warn on stray geo coords"`

---

### Task 4: Default flips — cache_verify=cvmfs-cas, origin_select=rtt

**Files:**
- Modify: `src/protocols/cvmfs/module.c` (merge: origin_select default at `:327-329`; verify default near the shared_merge call)
- Test: extend `tests/run_cvmfs_verify.sh` (default-on case) and `tests/run_cvmfs_select.sh` (default-rtt case)

**Interfaces:**
- Consumes: `BRIX_CACHE_VERIFY_CVMFS_CAS` (`src/fs/cache/verify.h:38-44`), `BRIX_CVMFS_SELECT_RTT` (`src/protocols/cvmfs/cvmfs.h:27-31`), rtt registration `brix_cvmfs_rtt_register` (`origin_probe.c:44-74` — a single-origin export makes probing a no-op).

- [ ] **Step 1: Failing tests.** In `run_cvmfs_verify.sh`, add a scenario whose nginx config OMITS `brix_cache_verify` entirely and assert the corrupt-fill case is still rejected/quarantined (copy the existing corrupt-fill scenario, drop the directive). In `run_cvmfs_select.sh`, add a config without `brix_cvmfs_origin_select` and assert rtt behavior (the script already has an rtt scenario to model — assert the rtt-probe log/ranking evidence the existing rtt case asserts). Also add an explicit opt-out test: `brix_cache_verify off;` admits the corrupt object (existing verify=off scenario probably covers this — keep it).

- [ ] **Step 2: Run both scripts** — new default-on cases FAIL (defaults are off/static today).

- [ ] **Step 3: Implement.** `origin_select` (module.c:327-329):

```c
    ngx_conf_merge_uint_value(conf->cvmfs.origin_select,
                              prev->cvmfs.origin_select,
                              BRIX_CVMFS_SELECT_RTT);
```

`cache_verify`: the shared merge defaults `cache_verify_mode` to 0 (off) at `shared_conf.h:250`, so capture unset-ness BEFORE calling `ngx_http_brix_shared_merge` in the cvmfs merge (after `brix_http_common_adopt` and after `cvmfs.enable` is knowable — note `enable` merges from prev too, so test both conf and prev):

```c
    /* cvmfs default: verify fills against their CAS SHA-1.  Must run
     * before shared_merge, which turns "unset" into "off". */
    if (conf->common.cache_verify_mode == NGX_CONF_UNSET_UINT
        && prev->common.cache_verify_mode == NGX_CONF_UNSET_UINT)
    {
        conf->common.cache_verify_mode = BRIX_CACHE_VERIFY_CVMFS_CAS;
    }
```

Guard placement: this block must only run when this location is a cvmfs location (`conf->cvmfs.enable == 1` after its own merge line — reorder so the enable merge happens first; it already does at `:316` if the verify-default block is placed after it and before the shared_merge call — confirm the actual call order in the function and place accordingly).

- [ ] **Step 4: `make -j$(nproc)`; run `run_cvmfs_verify.sh`, `run_cvmfs_select.sh`** — all pass, including pre-existing cases.
- [ ] **Step 5: Broader cvmfs regression** — `bash tests/run_cvmfs_resilience.sh && bash tests/run_cvmfs_manifest.sh` (rtt-default touches origin selection paths). Expected: PASS.
- [ ] **Step 6: Commit** — `git commit -m "feat(cvmfs): default cache_verify=cvmfs-cas and origin_select=rtt"`

---

### Task 5: THE FLIP — hard rename in C + repo-wide config/doc migration

One atomic commit: old names cease to exist in the binary AND every in-repo config/doc moves to the new names. Build + `nginx -t` + suites are the oracle.

**Files:**
- Modify: `src/protocols/root/stream/module.c:71` (`"xrootd"` → `"brix_export"`), `:81` (`"brix_export"` → `"brix_export"`)
- Modify: `src/protocols/root/stream/directives_cache.inc:15` (`"brix_cache_export"` → `"brix_cache_export"`)
- Modify: `src/protocols/webdav/module.c` + `src/protocols/webdav/directives_storage.inc` (DELETE: `brix_export`, `brix_allow_write`, `brix_compress`, and every per-proto duplicate of a unified directive — enumerate by inventory below; DELETE the `BRIX_TIER_DIRECTIVES("brix_webdav_", …)` expansion)
- Modify: `src/protocols/s3/module.c` (DELETE: `brix_export`, `brix_allow_write`, `brix_read_only`, `brix_compress`, `brix_storage_backend`, `brix_storage_credential`, `brix_thread_pool`; DELETE `BRIX_TIER_DIRECTIVES("brix_s3_", …)` at `:333`)
- Modify: `src/protocols/cvmfs/directives_core.inc` (DELETE: `brix_cache_store` `:94`, `brix_thread_pool` `:102`, `brix_storage_backend` `:87`, `brix_cache_verify` `:29` — all now owned by the common module)
- Modify: `src/protocols/cvmfs/module.c:459` and `src/core/config/runtime_server.c:257` (`root_opts.directive_name` strings → `"brix_export"`)
- Create: `tools/refactor/config_rename_2026_07.sh` (the migration script — kept in-repo like `tools/refactor/p66_apply.py`)
- Modify (mechanical, via the script): `tests/configs/*.conf` (59), `tests/*.sh` heredocs (17 cvmfs + others), `tests/**/*.py` config fixtures, `k8s-tests/` (286 files), `deploy/`, `docs/`, `site/` (1 occurrence — surgical, respect uncommitted edits)

**Interfaces:**
- Consumes: Task 1's common module (the unified names must already work, or every migrated config breaks).

- [ ] **Step 1: Definitive inventory (do not trust this plan's list blindly).**

```bash
grep -rhn 'ngx_string("brix_webdav_\|ngx_string("brix_s3_\|ngx_string("brix_cvmfs_cache\|ngx_string("brix_cvmfs_storage\|ngx_string("brix_cvmfs_thread' \
  src/protocols/{webdav,s3,cvmfs}/ | sed 's/.*ngx_string("\([^"]*\)").*/\1/' | sort
```

For each name, decide by rule: **is it a per-proto spelling of a unified directive** (root/export, allow_write, read_only, compress, storage_backend, storage_credential, thread_pool, the 10 tier names, cache_verify)? → DELETE from the protocol table (the common module owns the bare name). **Anything else** (auth, CORS, bucket keys, cvmfs behavior knobs, legacy `brix_webdav_cache_root`/`brix_s3_cache_root`) → KEEP untouched. Record the final delete-list in the commit message.

- [ ] **Step 2: Write the migration script** — `tools/refactor/config_rename_2026_07.sh`:

```bash
#!/usr/bin/env bash
# One-shot migration to the unified brix config grammar (2026-07-05 spec).
# Ordering is load-bearing:
#   1. brix_cache_export        -> brix_cache_export   (before any brix_export pass)
#   2. per-proto tier + preamble names -> bare names (longest names first)
#   3. brix_export/brix_export   -> brix_export
#   4. brix_export <path>        -> brix_export        (all remaining brix_export
#      tokens are the stream path directive at this point)
#   5. directive-position `xrootd on|off;` -> brix_export on|off;
#      (LAST, so it cannot collide with step 4; restricted to directive
#      syntax so prose about "xrootd" is untouched)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TARGETS=(tests deploy docs k8s-tests site)

sed_all() { # sed_all <sed-expr>
    grep -rlZ -e "$2" "${TARGETS[@]/#/$ROOT/}" 2>/dev/null \
      | xargs -0 -r sed -i -E "$1"
}

# 1. legacy stream cache export
sed_all 's/\bbrix_cache_root\b/brix_cache_export/g' 'brix_cache_export'

# 2. tier + preamble de-prefixing (exact names only — never wildcard)
for p in webdav s3 cvmfs; do
  for d in cache_store stage_store stage_flush stage cache_max_object \
           cache_evict_at cache_evict_to cache_index_cache cache_meta \
           cache_slice_size storage_backend storage_credential \
           thread_pool allow_write read_only compress; do
    sed_all "s/\bbrix_${p}_${d}\b/brix_${d}/g" "brix_${p}_${d}"
  done
done

# 3. per-proto roots -> brix_export
sed_all 's/\bbrix_webdav_root\b/brix_export/g' 'brix_export'
sed_all 's/\bbrix_s3_root\b/brix_export/g'     'brix_export'

# 4. stream path directive -> brix_export
sed_all 's/\bbrix_root\b/brix_export/g' 'brix_export'

# 5. stream enable (directive position only)
sed_all 's/^([[:space:]]*)xrootd([[:space:]]+(on|off)[[:space:]]*;)/\1brix_root\2/' \
        '^[[:space:]]*xrootd[[:space:]]+(on|off)[[:space:]]*;'

echo "done — review with: git diff --stat"
```

**Caveats for the implementer:** step 2's loop must NOT rename names that are NOT per-proto duplicates — cross-check each `brix_${p}_${d}` against the Step-1 delete-list before running; drop loop entries that don't exist as directives (e.g. if `brix_storage_credential` was never a directive, the sed is a harmless no-op, but confirm no FIELD or doc heading uses the token in another sense). `grep` here is ugrep — if `\b` misbehaves, use `-E` POSIX classes as written and verify on one file first.

- [ ] **Step 3: Apply the C-side renames/deletions** (files listed above, Edit tool, exact `ngx_string` entries + the two `directive_name` message strings). Do NOT delete the underlying struct fields — only the `ngx_command_t` entries.

- [ ] **Step 4: Run the migration script**, then audit:

```bash
bash tools/refactor/config_rename_2026_07.sh
git diff --stat | tail -5
# nothing left behind (0 hits expected in configs; prose "xrootd" is fine):
grep -rn '\bbrix_webdav_root\b\|\bbrix_s3_root\b\|\bbrix_webdav_cache_store\b\|\bbrix_s3_cache_store\b\|\bbrix_cvmfs_cache_store\b\|\bbrix_cvmfs_storage_backend\b\|\bbrix_cache_root\b' tests deploy docs k8s-tests site || echo CLEAN
# directive-position xrootd must be gone:
grep -rnE '^[[:space:]]*xrootd[[:space:]]+(on|off)[[:space:]]*;' tests deploy docs k8s-tests || echo CLEAN
```

Manually review the `site/src/pages` hunk (uncommitted user edits — directive-name-only changes allowed).

- [ ] **Step 5: Build (`make -j$(nproc)` — no new module files; the new tools script isn't compiled) and validate the fleet:**

```bash
tests/manage_test_servers.sh restart          # regenerates + nginx -t all configs
bash tests/run_unified_conf.sh                # update its configs if any used old names
PYTHONPATH=tests pytest tests/ -n12 -m "not slow" -q --tb=short   # --pr gate
for s in tests/run_cvmfs_*.sh; do bash "$s" || echo "FAILED: $s"; done
```

Expected: fleet restart clean; --pr gate at its usual pass rate (load-flaky families pass serially per test_suite_fast_tier memory); every cvmfs script green. Any failure whose log says `unknown directive` is a missed migration site — fix the config, not the code.

- [ ] **Step 6: Commit** (one atomic commit):

```bash
git add -u && git add tools/refactor/config_rename_2026_07.sh
git commit -m "feat(config)!: hard-rename to unified brix grammar

xrootd->brix_export, brix_export/brix_export/brix_export->brix_export,
per-proto tier+preamble directives -> bare unified names (common module),
brix_cache_export->brix_cache_export. No aliases. All in-repo configs and
docs migrated via tools/refactor/config_rename_2026_07.sh.
Deleted per-proto directives: <paste Step-1 delete-list>"
```

(Do NOT `git add -A` — phase-66 memory: it sweeps junk. `-u` + explicit new files only.)

---

### Task 6: Docs — cvmfs reference, 3-line examples, migration table

**Files:**
- Modify: `docs/03-configuration/directives.md` (new "Unified storage grammar" intro + full cvmfs directive table with defaults)
- Modify: `docs/03-configuration/examples.md` (cvmfs minimal + production examples)
- Modify: `docs/03-configuration/quick-reference.md` (cvmfs entries)
- Modify: `deploy/cvmfs/README.md` (shrink examples; defaults table)
- Create: `docs/03-configuration/migration-unified-grammar.md` (old→new table)
- Modify: `CLAUDE.md` (grep for renamed directives in ROUTING/RECIPES/FAQ; update hits)

**Interfaces:** consumes the final directive surface from Task 5 and defaults from Task 4/recon (manifest_ttl 61, negative_ttl 10, client_hold 25, fill_max_life 300, upstream_max 8, connect 2s, stall 4s/1B, rtt_interval 60, evict_at 90/evict_to 80, verify cvmfs-cas, select rtt).

- [ ] **Step 1: directives.md** — add the grammar rules (three bullets from the spec §1) at the top of the storage section; add a cvmfs table: every `brix_cvmfs_*` + `brix_scvmfs_*` directive with args, default, one-line purpose (source: `directives_core.inc`, `directives_resilience.inc`, merge defaults). Mark unified directives once, not per protocol.
- [ ] **Step 2: examples.md** — lead the cvmfs section with the 3-line config (spec §3 verbatim), then a "tuned" variant showing ONLY non-default knobs (`brix_cache_verify off`, `brix_cvmfs_origin_select static`, eviction overrides), each with a comment saying what the default already does.
- [ ] **Step 3: quick-reference.md** — one cvmfs row-block mirroring the webdav/s3 style.
- [ ] **Step 4: deploy/cvmfs/README.md** — replace the ~30-line production example with minimal + defaults table; keep monitoring/client/troubleshooting sections; keep the Squid mapping table (update directive names — Task 5's script already did the mechanical part; this step is prose coherence).
- [ ] **Step 5: migration-unified-grammar.md** — the full old→new table (from Task 5 Step 1 delete-list + stream renames), one line of context per family, statement that old names are gone (stock `unknown directive` error).
- [ ] **Step 6: Verify docs contain no stale names:**

```bash
grep -rn 'brix_export\|brix_export\|brix_cache_store\|brix_cache_store\|brix_cache_store' docs/ deploy/ && echo STALE || echo CLEAN
```
Expected: CLEAN (migration-table file legitimately contains old names — allowlist it in the grep or name them in backticks with a `<!-- old-names-ok -->` marker and exclude that file).

- [ ] **Step 7: Commit** — `git commit -m "docs(config): unified grammar reference, 3-line cvmfs examples, migration table"`

---

### Task 7: New behavior tests + full verification

**Files:**
- Create: `tests/run_cvmfs_minimal.sh` (3-line-config e2e)
- Create: `tests/run_cvmfs_evict.sh` (eviction under cvmfs)
- Test: full suites

- [ ] **Step 1: `run_cvmfs_minimal.sh`** — clone the harness skeleton of `tests/run_cvmfs_reverse.sh` (mock origin + nginx + curl) but the nginx location block contains ONLY the three directives (`brix_cvmfs on; brix_cache_store …; brix_storage_backend …;`). Assert: (success) a CAS object fetch round-trips byte-exact and lands in the cache store; (security-neg) a corrupt object from the mock origin is rejected (verify is on by default — reuse the corrupt-fill trick from `run_cvmfs_verify.sh`); (error) a 404 path returns 404 and the negative-TTL caches it (model `run_cvmfs_manifest.sh` assertions).
- [ ] **Step 2: `run_cvmfs_evict.sh`** — model `tests/run_tier_remote_evict.sh` + `run_cvmfs_reverse.sh`: tiny cache store (a small tmpfs or a low `brix_cache_evict_at 50; brix_cache_evict_to 20;` with a few MB of objects), fill past the threshold via the mock origin, assert the reaper evicts (object count/bytes drop; `cache_reap.c` runs on a per-worker timer — poke via enough fills + wait, mirroring how the watermark tests wait). Assert dirty/manifest objects survive per existing eviction-guard semantics.
- [ ] **Step 3: Run both new scripts** — expected PASS (they test behavior already landed in Tasks 1–5; if eviction proves un-triggerable in a quick script, mark the eviction assertion clearly and check with Rob rather than shipping a fake-green test).
- [ ] **Step 4: Full verification sweep:**

```bash
tests/manage_test_servers.sh restart
PYTHONPATH=tests pytest tests/ -n12 -m "not slow" -q --tb=short   # --pr gate
for s in tests/run_cvmfs_*.sh tests/run_unified_conf.sh; do bash "$s" || echo "FAILED: $s"; done
tools/ci/check_config_coverage.sh && tools/ci/check_vfs_seam.sh && tools/ci/check_file_size.sh
```
Expected: gate green (known load-flakes pass serially), all scripts green, all guards green.
- [ ] **Step 5: Update CLAUDE.md AGENT GUIDE** — OP→FILE: add `unified config / common module | src/core/config/http_common.c, proto_exclusive.c`; RECIPES "New config directive": note unified storage names live in the common module; ROUTING/example directives if any renamed ones appear.
- [ ] **Step 6: Commit** — `git commit -m "test(cvmfs): 3-line-config e2e + eviction coverage; agent-guide updates"`

---

## Self-review notes (already applied)

- Spec §1 (grammar+renames)→Tasks 1+5; §2 (foot-guns+exclusivity)→Tasks 2+3 (+eviction exposure free via Task 1); §3 (defaults)→Task 4; §4 (docs)→Task 6; §5 (tests)→every task + Task 7. Coverage complete.
- Deliberate sequencing: unified names become VALID (Task 1) → validations/defaults on the new surface (2–4) → old names removed atomically with config migration (5) → docs (6) → behavior tests + sweep (7). Every commit leaves the tree green.
- Known-risk steps flagged inline: tier-macro context widening (T1 S4), nginx port/addr struct fields (T2 S3), verify-default placement relative to shared_merge (T4 S3), sed scope discipline (T5 S2). Implementers must verify against real headers, not this plan's sketches.
