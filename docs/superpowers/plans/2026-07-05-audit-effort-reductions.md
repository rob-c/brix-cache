# Audit-Effort Reductions (src/ consolidations + client/ busybox) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the remaining copy-pasted config plumbing in src/ (common-conf merge, tier directive tables, ngx_str null-termination) and shrink the client binary/test surface (busybox multi-call tools + one `make test`).

**Architecture:** All src/ work converges existing duplication onto helpers that already exist or follow existing repo patterns (shared_conf.h helpers currently have ZERO callers; the X-macro approach mirrors `src/core/types/proto_list.h`; the ngx-free-core header mirrors `af_policy.h`). Client work converts 8 micro-binaries into 2 multi-call binaries with argv[0]-dispatch symlinks so every existing caller (15+ test files, stock-parity interop suites) keeps working unchanged.

**Tech Stack:** C (nginx module + libbrix client), GNU make, pytest.

## Global Constraints

- **NO `goto`**; functional/modular style per `docs/09-developer-guide/coding-standards.md`. WHAT/WHY/HOW doc blocks on every function.
- **NO git commands** in this plan's execution — the working tree holds uncommitted WIP from other phases (phase-69 client move, god-header split). OP commits. Where the writing-plans template says "Commit", SKIP.
- Build: `cd /tmp/nginx-1.28.3 && make -j$(nproc)`; validate `objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf`. New headers go into `./config` dep lists; **no new `.c` files in src/** in this plan, so no `./configure` re-run is needed EXCEPT once after editing `./config` (Task 5/6 header adds) — then use `make -j$(nproc)` from the existing objs (header-only additions do not need `rm -rf objs`).
- Tests: 3 per change (success + error + security-neg). Fleet: `tests/manage_test_servers.sh start` if not up; conftest auto-attaches.
- **Behavior parity is the acceptance bar** for Tasks 1–5: same directives accepted, same defaults, same read_only/allow_write semantics. Any intentional behavior gain (cvmfs read_only enforcement) is called out explicitly.
- Client build: `make -C client -j$(nproc)`; binaries land in `client/bin/`.

## Pre-verified facts (do not re-derive)

- `ngx_http_brix_shared_init()` / `ngx_http_brix_shared_merge()` in `src/core/config/shared_conf.h:129-212` have **zero callers** — s3/webdav/cvmfs each hand-roll the same init/merge (s3 `src/protocols/s3/module.c:54-159`, webdav `src/protocols/webdav/config.c:110-440`, cvmfs `src/protocols/cvmfs/module.c:54-380`).
- Deltas between the manual blocks and the shared helpers: helpers lack `compress`, `storage_staging`, `cache_verify_mode`; webdav's root default is `"/"` (s3/cvmfs `""`); cvmfs does not init/merge `ktls`/`thread_pool` uniformly and never calls `brix_shared_apply_read_only` (adopting it is a deliberate hardening gain); cvmfs does not reference `common.ktls` anywhere (`grep -rn ktls src/protocols/cvmfs/` is empty) so gaining the merge is inert.
- Conditional-request gate is ALREADY unified (`src/core/http/http_conditionals.c` consumed by webdav get/put/copy/move, s3/conditional.c, cvmfs/handler.c). **No task for it** — record as done.
- Tier directive tables: s3 `src/protocols/s3/module.c:403-461` and webdav `src/protocols/webdav/directives_storage.inc:33-95` declare the IDENTICAL 10 entries (cache_store, stage, stage_store, stage_flush, cache_max_object, cache_evict_at, cache_evict_to, cache_index_cache, cache_meta, cache_slice_size) differing only in name prefix, conf type, and per-module enum-table names. cvmfs deliberately exposes only a subset (`cache_store` at `directives_core.inc:94`) — leave cvmfs's table alone.
- ngx_str null-termination: 43 `buf[x.len] = '\0'` sites across 36 files in src/ (`grep -rn "\.len\] = '\\\\0'" src/ --include='*.c'`).
- Client: `client/Makefile` BINS at line 148; per-binary `<name>_OBJS` at 172-190; `.SECONDEXPANSION` link rule at 236. `client/tests/c/{cli_cred_unit,cred_unit,cred_store_unit,vfs_posix_unit,vfs_block_unit,vfs_s3_smoke}.c` have **no Makefile rules at all**. `vfs_s3_smoke` needs an external S3 server — exclude from `make test`.
- Binary names are load-bearing: 15+ test files + gfal/official-xrootd interop invoke `xrdcrc32c/xrdcrc64/xrdadler32/xrdckverify/xrdcinfo/xrdqstats/wait41/mpxstats` by name → symlinks are mandatory.
- `xrddiag` main is `client/apps/diag/xrddiag.c:555`; existing subcommands come from `DX_RULES` + probe names — none named `qstats`/`wait41`/`mpxstats` (verify with `grep -n '"qstats"\|"wait41"\|"mpxstats"' client/apps/diag/*.c` before wiring).

---

### Task 1: Extend shared_conf.h helpers to the full common.* union; adopt in S3

**Files:**
- Modify: `src/core/config/shared_conf.h:129-212`
- Modify: `src/protocols/s3/module.c:54-159`
- Test: existing suite (`pytest tests/ -k "s3" ...`) + `nginx -t`

**Interfaces:**
- Produces: `ngx_http_brix_shared_init(ngx_http_brix_shared_conf_t *conf)` (unchanged signature, more fields), `ngx_http_brix_shared_merge(ngx_conf_t *cf, ngx_http_brix_shared_conf_t *prev, ngx_http_brix_shared_conf_t *conf, const char *root_default)` (NEW 4th param). Tasks 2–4 call these.

- [ ] **Step 1: Extend the two helpers in `shared_conf.h`**

In `ngx_http_brix_shared_init()` add after the `read_only` line (keep alignment style):

```c
    conf->compress           = NGX_CONF_UNSET;
    conf->storage_staging    = NGX_CONF_UNSET;
    conf->cache_verify_mode  = NGX_CONF_UNSET_UINT;
```

Change `ngx_http_brix_shared_merge` signature to take `const char *root_default` and use it; add the missing merges; fold in the read-only enforcement so no protocol can forget it. Replace the whole function body's opening merges with:

```c
static inline char *
ngx_http_brix_shared_merge(ngx_conf_t *cf,
                             ngx_http_brix_shared_conf_t *prev,
                             ngx_http_brix_shared_conf_t *conf,
                             const char *root_default)
{
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->root, prev->root, root_default);
    ngx_conf_merge_value(conf->allow_write, prev->allow_write, 0);
    ngx_conf_merge_value(conf->read_only, prev->read_only, 0);
    ngx_conf_merge_value(conf->compress, prev->compress, 0);
    ngx_conf_merge_value(conf->ktls, prev->ktls, 1);   /* default ON (offload-gated) */
    ngx_conf_merge_value(conf->storage_staging, prev->storage_staging, 0);
```

…keep the existing str/tier merges, and append before the pmark merge:

```c
    ngx_conf_merge_uint_value(conf->cache_verify_mode, prev->cache_verify_mode,
                              BRIX_CACHE_VERIFY_OFF);

    /* Hard read-only: force allow_write off HERE so no protocol merge can
     * forget the enforcement (it must run before token-scope checks). */
    brix_shared_apply_read_only(conf, cf->log);
```

`BRIX_CACHE_VERIFY_OFF` needs `#include "fs/cache/verify.h"` at the top of shared_conf.h (src-rooted include; it is a plain enum header). Update the helper doc blocks (WHY: zero callers today → these are now the single audit point). NOTE: `brix_shared_apply_read_only` is defined BELOW `shared_merge` in the header today — move `brix_shared_apply_read_only` ABOVE `ngx_http_brix_shared_merge` so the inline call compiles.

- [ ] **Step 2: Adopt in S3.** In `ngx_http_s3_create_loc_conf` replace lines 61-76 (`c->common.enable = NGX_CONF_UNSET;` … `c->common.cache_slice_size = NGX_CONF_UNSET_SIZE;` including the pmark init) with `ngx_http_brix_shared_init(&c->common);`. In `ngx_http_s3_merge_loc_conf` replace every `conf->common.*` merge line and the pmark-merge block (lines 96-102, 116, 122-159) with a single call placed FIRST in the function:

```c
    if (ngx_http_brix_shared_merge(cf, &prev->common, &conf->common, "")
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
```

Delete the now-redundant `brix_shared_apply_read_only(&conf->common, cf->log);` at line 100. Keep all `conf-><s3-specific>` merges untouched. Diff-check the removed block field-by-field against the helper before building: every removed field must appear in the helper with the same default.

- [ ] **Step 3: Build + validate**

Run: `cd /tmp/nginx-1.28.3 && make -j$(nproc) && objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf`
Expected: exit 0, `syntax is ok`.

- [ ] **Step 4: Tests (success + error + security-neg)**

Run: `tests/manage_test_servers.sh start` (if not running), then
`PYTHONPATH=tests pytest tests/ -k "s3 and (conditional or put or get or read_only)" -v --tb=short -x`
and the read-only security-neg specifically: `PYTHONPATH=tests pytest tests/ -k "read_only" -v --tb=short`.
Expected: same pass set as before the change (run the same selection on a stashed-nothing baseline is NOT possible — instead rely on parity: any new failure is a regression; investigate before proceeding).

- [ ] **Step 5: SKIP commit** (OP commits; tree has unrelated WIP).

---

### Task 2: Adopt shared init/merge in WebDAV

**Files:**
- Modify: `src/protocols/webdav/config.c:110-440`

**Interfaces:**
- Consumes: `ngx_http_brix_shared_init/merge` from Task 1 (root_default = `"/"`).

- [ ] **Step 1:** In `ngx_http_brix_webdav_create_loc_conf` replace the scattered `conf->common.*` init lines (117, 124-142 — enable, allow_write, read_only, compress, ktls, storage_staging, pblock_block_size, storage_instance, stage/cache scalars, pmark init) with `ngx_http_brix_shared_init(&conf->common);` placed right after the PCALLOC. Leave every non-`common.` init untouched.

- [ ] **Step 2:** In `ngx_http_brix_webdav_merge_loc_conf` delete ALL `conf->common.*` merge lines and the pmark block (lines 324-393: enable, root("/"), storage_backend, pblock_block_size, cache_store/args, stage_*, cache_*; and the later allow_write/read_only/compress/ktls/storage_staging cluster + `brix_shared_apply_read_only` + pmark merge), replacing with, as the FIRST statement:

```c
    if (ngx_http_brix_shared_merge(cf, &prev->common, &conf->common, "/")
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
```

CAREFUL: webdav has no `thread_pool_name`/`storage_credential` merge today — the shared helper now merges them (default `""`), which is a no-op vs pcalloc-zeroed but check nothing reads `.data == NULL` as a sentinel: `grep -n "thread_pool_name.data == NULL\|storage_credential.data == NULL" src/protocols/webdav/ -r` — if any hit, keep behavior by reviewing that site (expected: none; ngx_conf_merge_str_value to "" sets len=0 data="", and all consumers gate on `.len`).

- [ ] **Step 3: Build + validate** — same commands as Task 1 Step 3. Expected exit 0.

- [ ] **Step 4: Tests** — `PYTHONPATH=tests pytest tests/test_webdav.py -v --tb=short` (success), `PYTHONPATH=tests pytest tests/ -k "webdav and (auth or lock)" -v --tb=short -x` (error paths), `PYTHONPATH=tests pytest tests/ -k "read_only" -v` (security-neg: read_only must still force writes rejected before token scope). Expected: parity.

- [ ] **Step 5: SKIP commit.**

---

### Task 3: Adopt shared init/merge in cvmfs (gains read_only enforcement)

**Files:**
- Modify: `src/protocols/cvmfs/module.c:54-380`

- [ ] **Step 1:** Replace the `c->common.*` init block (lines 60-77 EXCEPT `c->common.rootfd = -1;` which the helper also sets — verify, then drop it too) with `ngx_http_brix_shared_init(&c->common);`. Replace the merge block (lines 323-372, all `conf->common.*` + pmark) with the shared call, root_default `""`:

```c
    if (ngx_http_brix_shared_merge(cf, &prev->common, &conf->common, "")
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
```

Two deliberate behavior gains, document in the module.c header comment: (a) cvmfs now honors `read_only` → allow_write forced off (hardening; cvmfs is read-path anyway); (b) `common.ktls` now merges to 1 — inert, nothing in cvmfs/ reads it.

- [ ] **Step 2: Build + validate** — as Task 1 Step 3.

- [ ] **Step 3: Tests** — `PYTHONPATH=tests pytest tests/ -k "cvmfs" -v --tb=short` (covers success + error absorb/resilience paths); for security-neg, run `tests/run_cvmfs_core_unit.sh` if present and green pre-change. Expected: parity.

- [ ] **Step 4: SKIP commit.**

---

### Task 4: Check the stream (root://) common merge; adopt if it embeds the same struct

**Files:**
- Investigate: `src/core/config/merge.c`, `src/core/config/server_conf.c`, `src/core/types/config.h`
- Modify (conditional): `src/core/config/merge.c`

- [ ] **Step 1:** `grep -n "common\." src/core/config/merge.c src/core/config/server_conf.c | head -50`. If the stream srv conf embeds `ngx_http_brix_shared_conf_t common` and hand-merges it, replace with `ngx_http_brix_shared_init/merge` exactly as Tasks 1–3 (root_default: check the current stream default — memory says pure-cache nodes default root to `"/"`; copy whatever the current merge line uses VERBATIM). If the stream side uses a different struct or different defaults that don't map 1:1, DO NOT force it — leave a one-line comment in merge.c pointing at shared_conf.h and record the skip in the final report.

- [ ] **Step 2 (if adopted): Build + validate + tests** — `PYTHONPATH=tests pytest tests/ -k "conf and root" -v --tb=short -x` plus `PYTHONPATH=tests pytest tests/test_conf_sequences.py -v --tb=short`. Expected: parity.

- [ ] **Step 3: SKIP commit.**

---

### Task 5: X-macro tier-directive table shared by S3 + WebDAV

**Files:**
- Create: `src/core/config/tier_directives.h`
- Modify: `src/protocols/s3/module.c` (delete enum tables + 10 entries), `src/protocols/webdav/directives_storage.inc:33-95` + the enum tables at `src/protocols/webdav/module.c:21-33`, repo-root `./config` (add the new header to the module's header dep list, next to `shared_conf.h`)

**Interfaces:**
- Produces: `BRIX_TIER_DIRECTIVES(pfx, conf_t)` — expands to the 10 `ngx_command_t` initializers; `brix_tier_stage_flush_enum[]`, `brix_tier_cache_meta_enum[]` (static, defined in the header).

- [ ] **Step 1: Write the header** (content below is complete; enum values: copy the EXACT entries from the existing `brix_s3_stage_flush_enum`/`brix_s3_cache_meta_enum` and `brix_webdav_*` twins — they must be identical between modules; if they differ, STOP and report):

```c
/*
 * tier_directives.h — X-macro for the phase-64 composable tier grammar
 * (brix_<proto>_{cache_store,stage,stage_store,stage_flush,cache_max_object,
 * cache_evict_at,cache_evict_to,cache_index_cache,cache_meta,cache_slice_size}).
 *
 * WHAT: BRIX_TIER_DIRECTIVES(pfx, conf_t) expands to the ten ngx_command_t
 *       initializers every HTTP protocol module declares for its tier grammar.
 * WHY:  S3 and WebDAV declared byte-identical tables differing only in the
 *       directive prefix and conf struct — a parity bug magnet and a double
 *       audit surface. One macro guarantees cross-protocol parity.
 * HOW:  The including module writes BRIX_TIER_DIRECTIVES("brix_s3_",
 *       ngx_http_s3_loc_conf_t) inside its commands[] array. The shared enum
 *       tables are static in each including TU (same pattern as the per-module
 *       tables they replace). cvmfs deliberately exposes only cache_store and
 *       is NOT converted.
 */

#ifndef _NGX_BRIX_TIER_DIRECTIVES_H
#define _NGX_BRIX_TIER_DIRECTIVES_H

#include "core/config/shared_conf.h"   /* brix_conf_set_store_slot */
#include "fs/cache/cstore.h"           /* BRIX_CMETA_* */

static ngx_conf_enum_t brix_tier_stage_flush_enum[] = {
    /* COPY VERBATIM from brix_s3_stage_flush_enum */
    { ngx_null_string, 0 }
};

static ngx_conf_enum_t brix_tier_cache_meta_enum[] = {
    /* COPY VERBATIM from brix_s3_cache_meta_enum */
    { ngx_null_string, 0 }
};

#define BRIX_TIER_DIRECTIVES(pfx, conf_t)                                     \
    { ngx_string(pfx "cache_store"),                                          \
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234,                                  \
      brix_conf_set_store_slot,                                               \
      NGX_HTTP_LOC_CONF_OFFSET,                                               \
      offsetof(conf_t, common.cache_store),                                   \
      (void *) offsetof(conf_t, common.cache_store_args) },                   \
    { ngx_string(pfx "stage"),                                                \
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,                                      \
      ngx_conf_set_flag_slot,                                                 \
      NGX_HTTP_LOC_CONF_OFFSET,                                               \
      offsetof(conf_t, common.stage_enable),                                  \
      NULL },                                                                 \
    { ngx_string(pfx "stage_store"),                                          \
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234,                                  \
      brix_conf_set_store_slot,                                               \
      NGX_HTTP_LOC_CONF_OFFSET,                                               \
      offsetof(conf_t, common.stage_store),                                   \
      (void *) offsetof(conf_t, common.stage_store_args) },                   \
    { ngx_string(pfx "stage_flush"),                                          \
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,                                     \
      ngx_conf_set_enum_slot,                                                 \
      NGX_HTTP_LOC_CONF_OFFSET,                                               \
      offsetof(conf_t, common.stage_flush_async),                             \
      brix_tier_stage_flush_enum },                                           \
    { ngx_string(pfx "cache_max_object"),                                     \
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,                                     \
      ngx_conf_set_off_slot,                                                  \
      NGX_HTTP_LOC_CONF_OFFSET,                                               \
      offsetof(conf_t, common.cache_max_object),                              \
      NULL },                                                                 \
    { ngx_string(pfx "cache_evict_at"),                                       \
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,                                     \
      ngx_conf_set_num_slot,                                                  \
      NGX_HTTP_LOC_CONF_OFFSET,                                               \
      offsetof(conf_t, common.cache_evict_at),                                \
      NULL },                                                                 \
    { ngx_string(pfx "cache_evict_to"),                                       \
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,                                     \
      ngx_conf_set_num_slot,                                                  \
      NGX_HTTP_LOC_CONF_OFFSET,                                               \
      offsetof(conf_t, common.cache_evict_to),                                \
      NULL },                                                                 \
    { ngx_string(pfx "cache_index_cache"),                                    \
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,                                     \
      ngx_conf_set_size_slot,                                                 \
      NGX_HTTP_LOC_CONF_OFFSET,                                               \
      offsetof(conf_t, common.cache_index_cache),                             \
      NULL },                                                                 \
    { ngx_string(pfx "cache_meta"),    /* auto|local|xattr|sidecar */         \
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,                                     \
      ngx_conf_set_enum_slot,                                                 \
      NGX_HTTP_LOC_CONF_OFFSET,                                               \
      offsetof(conf_t, common.cache_meta_mode),                               \
      brix_tier_cache_meta_enum },                                            \
    { ngx_string(pfx "cache_slice_size"),  /* <size> (0 = whole-file) */      \
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,                                     \
      ngx_conf_set_size_slot,                                                 \
      NGX_HTTP_LOC_CONF_OFFSET,                                               \
      offsetof(conf_t, common.cache_slice_size),                              \
      NULL }

#endif /* _NGX_BRIX_TIER_DIRECTIVES_H */
```

- [ ] **Step 2:** In s3/module.c: `#include "core/config/tier_directives.h"`, delete `brix_s3_stage_flush_enum`/`brix_s3_cache_meta_enum` (verify no other user: `grep -rn brix_s3_cache_meta_enum src/`), replace the 10 entries (lines 403-461) with `BRIX_TIER_DIRECTIVES("brix_s3_", ngx_http_s3_loc_conf_t),`. Same in webdav: include from module.c, delete its two enum tables, replace `directives_storage.inc:33-95` with `BRIX_TIER_DIRECTIVES("brix_webdav_", ngx_http_brix_webdav_loc_conf_t),`.

- [ ] **Step 3:** Add `$ngx_addon_dir/src/core/config/tier_directives.h` to the header dep list in the repo-root `./config` (find where `shared_conf.h` is listed; add adjacent). Then `cd /tmp/nginx-1.28.3 && ./configure <same flags as CLAUDE.md BUILD section> --add-module=/home/rcurrie/HEP-x/nginx-xrootd && make -j$(nproc)`. If the full rebuild trips -Werror on unrelated uncommitted WIP, fix ONLY trivial format-string issues in files this plan touches; otherwise report and stop.

- [ ] **Step 4: Parity check + tests.** `objs/nginx -t` against a conf exercising both prefixes (add `brix_s3_cache_evict_at 85;` and `brix_webdav_cache_evict_at 85;` to a scratch copy of the test conf, run `nginx -t`, then remove). Run `PYTHONPATH=tests pytest tests/ -k "tier or cache_store or stage" -v --tb=short`. Also the config-coverage guard: `tools/ci/check_config_coverage.sh` must stay green.

- [ ] **Step 5: SKIP commit.**

---

### Task 6: ngx_str null-termination helper + site migration

**Files:**
- Create: `src/core/compat/cstr.h`; add to `./config` header deps (same edit pattern as Task 5 Step 3 — do both `./config` edits in one configure cycle if executing sequentially)
- Create: `tests/cstr_unittest.c` (standalone gcc, mirrors `tests/af_policy_unittest.c`)
- Modify: the 36 files listed by `grep -rln "\.len\] = '\\\\0'" src/ --include='*.c'`

- [ ] **Step 1: Write the header** (ngx-free core + ngx wrappers, XRDPROTO_NO_NGX-style gate):

```c
/*
 * cstr.h — bounded ngx_str_t → NUL-terminated C-string conversion.
 *
 * WHAT: brix_cbuf_copy() copies len bytes into a caller buffer and
 *       NUL-terminates, refusing (NULL) when it would not fit;
 *       brix_str_cbuf() is the ngx_str_t wrapper; brix_pstrdup_z()
 *       pool-allocates len+1 and NUL-terminates.
 * WHY:  ~43 hand-rolled memcpy+buf[len]='\0' sites each carried their own
 *       bounds check — one audited helper replaces per-site review.
 * HOW:  Core is ngx-free (define BRIX_CSTR_NO_NGX) so tests/cstr_unittest.c
 *       compiles standalone, like af_policy.h.
 */

#ifndef BRIX_COMPAT_CSTR_H
#define BRIX_COMPAT_CSTR_H

#include <stddef.h>
#include <string.h>

static inline const char *
brix_cbuf_copy(char *buf, size_t bufsize, const void *data, size_t len)
{
    if (buf == NULL || bufsize == 0 || len >= bufsize) {
        return NULL;
    }
    if (len > 0) {
        memcpy(buf, data, len);
    }
    buf[len] = '\0';
    return buf;
}

#ifndef BRIX_CSTR_NO_NGX

static inline const char *
brix_str_cbuf(char *buf, size_t bufsize, const ngx_str_t *s)
{
    return brix_cbuf_copy(buf, bufsize, s->data, s->len);
}

static inline char *
brix_pstrdup_z(ngx_pool_t *pool, const ngx_str_t *s)
{
    char  *p;

    p = ngx_pnalloc(pool, s->len + 1);
    if (p == NULL) {
        return NULL;
    }
    ngx_memcpy(p, s->data, s->len);
    p[s->len] = '\0';
    return p;
}

#endif /* !BRIX_CSTR_NO_NGX */

#endif /* BRIX_COMPAT_CSTR_H */
```

(Do NOT include ngx headers in cstr.h — every including .c already has them via ngx_brix_module.h; the unittest defines BRIX_CSTR_NO_NGX.)

- [ ] **Step 2: Write the failing-then-passing unit test** `tests/cstr_unittest.c`:

```c
/* Standalone unit test for src/core/compat/cstr.h — gcc, no nginx. */
#define BRIX_CSTR_NO_NGX 1
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/core/compat/cstr.h"

int main(void)
{
    char buf[8];

    /* success: fits, NUL-terminated, content exact */
    assert(brix_cbuf_copy(buf, sizeof(buf), "abc", 3) == buf);
    assert(strcmp(buf, "abc") == 0);
    /* boundary success: len == bufsize-1 */
    assert(brix_cbuf_copy(buf, sizeof(buf), "1234567", 7) == buf);
    assert(buf[7] == '\0' && strcmp(buf, "1234567") == 0);
    /* error: exact-fit-without-NUL and larger both refuse, buffer untouched */
    memset(buf, 'X', sizeof(buf));
    assert(brix_cbuf_copy(buf, sizeof(buf), "12345678", 8) == NULL);
    assert(brix_cbuf_copy(buf, sizeof(buf), "123456789", 9) == NULL);
    assert(buf[0] == 'X');   /* refusal must not partially write */
    /* security-neg: embedded NUL and empty input are bounded, not trusted */
    assert(brix_cbuf_copy(buf, sizeof(buf), "a\0b", 3) == buf);
    assert(buf[3] == '\0' && memcmp(buf, "a\0b", 4) == 0);
    assert(brix_cbuf_copy(buf, sizeof(buf), "", 0) == buf && buf[0] == '\0');
    assert(brix_cbuf_copy(buf, 0, "", 0) == NULL);
    assert(brix_cbuf_copy(NULL, sizeof(buf), "a", 1) == NULL);
    printf("cstr_unittest: all checks passed\n");
    return 0;
}
```

Run: `gcc -Wall -Werror -o /tmp/claude-1000/-home-rcurrie-HEP-x-nginx-xrootd/d3ba2049-2183-4950-9299-2c5cd556817d/scratchpad/cstr_unittest tests/cstr_unittest.c && /tmp/.../cstr_unittest` → `cstr_unittest: all checks passed`.

- [ ] **Step 3: Migrate the sites.** Generate the list: `grep -rn -B4 "\.len\] = '\\\\0'" src/ --include='*.c'`. For each site, apply ONE of two transforms (NO semantic change):
  - Fixed buffer with its own bounds check (e.g. `webdav/auth_store.c:29-35`): replace check+memcpy+terminate with `if (brix_str_cbuf(cadir_buf, sizeof(cadir_buf), &conf->cadir) == NULL) { <the site's existing too-long handling>; }` — keep the site's exact error path (return NULL / NGX_ERROR / log) and keep using the buffer variable unchanged. Add `#include "core/compat/cstr.h"` (src-rooted) once per file.
  - `ngx_pnalloc(len+1)`+memcpy+terminate (e.g. `core/http/http_headers.c:478`): replace the three lines with `brix_pstrdup_z(pool, &v)` and keep the site's existing NULL handling.
  - A site that fits NEITHER shape exactly (offset writes like `cvmfs/handler.c:111` `path[rn + r->uri.len]`) → LEAVE IT, list it in the final report. Do not contort the helper.
  Work file-by-file; build (`make -j$(nproc)`) after every ~8 files to localize breakage. No blind retries: if an Edit misses twice, read the site and fix by hand.

- [ ] **Step 4: Build + full guard pass.** `make -j$(nproc)`, `objs/nginx -t`, `tools/ci/check_http_helper_reimpl.sh`, `tools/ci/check_file_size.sh`. Then a broad smoke: `PYTHONPATH=tests pytest tests/ -k "auth or gsi_handshake or dig or cvmfs" -v --tb=short -m "not slow"` (covers the migrated auth_store/dig/cvmfs paths: success + auth-error + path-security cases).

- [ ] **Step 5: SKIP commit.**

---

### Task 7: client — xrdcksum multi-call binary (5 → 1 + symlinks)

**Files:**
- Create: `client/apps/cksum/xrdcksum.c`
- Modify: `client/apps/cksum/xrdckverify.c` (`main` → `brix_xrdckverify_main(int argc, char **argv)`), `client/apps/cksum/xrdcinfo.c` (`main` → `brix_xrdcinfo_main(int argc, char **argv)`)
- Delete: `client/apps/cksum/xrdcrc32c.c`, `xrdcrc64.c`, `xrdadler32.c` (their 6-line bodies fold into the dispatch table; ALSO delete their stale `.o`/`.d`)
- Modify: `client/Makefile` (BINS line 148-150, `<name>_OBJS` 178-182, add symlink rules + install links)

**Interfaces:**
- Produces: `client/bin/xrdcksum` + symlinks `xrdcrc32c xrdcrc64 xrdadler32 xrdckverify xrdcinfo` → `xrdcksum`. Dispatch: basename(argv[0]) first; invoked as `xrdcksum`, argv[1] is the subcommand (`crc32c|crc64|adler32|verify|info`).

- [ ] **Step 1: Read the two mains being renamed** (`xrdckverify.c`, `xrdcinfo.c`) — confirm signatures/exit codes; rename `main` → the `brix_*_main` names; declare both in a small block at the top of `xrdcksum.c` (they are single-TU apps today; no shared header needed).

- [ ] **Step 2: Write `xrdcksum.c`:**

```c
/*
 * xrdcksum.c — multi-call front-end for the checksum tool family.
 *
 * WHAT: One binary serving xrdcrc32c / xrdcrc64 / xrdadler32 / xrdckverify /
 *       xrdcinfo (via argv[0] symlinks, stock-name compatible) and the
 *       subcommand form `xrdcksum <crc32c|crc64|adler32|verify|info> …`.
 * WHY:  Five installed binaries collapsed to one link target — one binary to
 *       audit/ship; per-tool behavior and exit codes are unchanged.
 * HOW:  basename(argv[0]) picks the personality; the bare `xrdcksum` name
 *       shifts argv and dispatches on argv[1]. Checksum personalities delegate
 *       to brix_cli_cksum_main() exactly as the old thin wrappers did.
 */
#include "brix.h"

#include <stdio.h>
#include <string.h>

int brix_xrdckverify_main(int argc, char **argv);
int brix_xrdcinfo_main(int argc, char **argv);

typedef struct {
    const char *name;        /* argv[0] basename / subcommand      */
    const char *algo_name;   /* brix_cli_cksum_main() algo string  */
    int         algo;        /* XRDC_CK_* enum                     */
    int         err_exit;    /* stock tool's failure exit code     */
} cksum_tool;

static const cksum_tool CKSUM_TOOLS[] = {
    { "xrdcrc32c",  "crc32c",  XRDC_CK_CRC32C,  3 },
    { "crc32c",     "crc32c",  XRDC_CK_CRC32C,  3 },
    { "xrdcrc64",   "crc64",   XRDC_CK_CRC64,   3 },
    { "crc64",      "crc64",   XRDC_CK_CRC64,   3 },
    { "xrdadler32", "adler32", XRDC_CK_ADLER32, 1 },
    { "adler32",    "adler32", XRDC_CK_ADLER32, 1 },
};

static const char *
tool_basename(const char *path)
{
    const char *slash = strrchr(path, '/');

    return slash != NULL ? slash + 1 : path;
}

static int
dispatch(const char *name, int argc, char **argv)
{
    size_t i;

    for (i = 0; i < sizeof(CKSUM_TOOLS) / sizeof(CKSUM_TOOLS[0]); i++) {
        const cksum_tool *t = &CKSUM_TOOLS[i];

        if (strcmp(name, t->name) == 0) {
            return brix_cli_cksum_main(argv[0], t->algo_name, t->algo,
                                       argc == 2 ? argv[1] : NULL,
                                       t->err_exit);
        }
    }
    if (strcmp(name, "xrdckverify") == 0 || strcmp(name, "verify") == 0) {
        return brix_xrdckverify_main(argc, argv);
    }
    if (strcmp(name, "xrdcinfo") == 0 || strcmp(name, "info") == 0) {
        return brix_xrdcinfo_main(argc, argv);
    }
    return -1;
}

int
main(int argc, char **argv)
{
    const char *name = tool_basename(argv[0]);
    int         rc;

    rc = dispatch(name, argc, argv);
    if (rc >= 0) {
        return rc;
    }
    /* bare `xrdcksum <sub> …`: shift so the personality sees itself at argv[0] */
    if (argc >= 2) {
        rc = dispatch(argv[1], argc - 1, argv + 1);
        if (rc >= 0) {
            return rc;
        }
    }
    fprintf(stderr,
            "usage: xrdcksum <crc32c|crc64|adler32|verify|info> [args…]\n"
            "       (or invoke via the xrdcrc32c/xrdcrc64/xrdadler32/"
            "xrdckverify/xrdcinfo symlinks)\n");
    return 50;
}
```

CHECK before coding: exact `err_exit` values and adler32's exit code — copy from the three deleted wrappers verbatim (xrdcrc32c uses 3; read xrdcrc64.c/xrdadler32.c for theirs; the values above are placeholders for adler32 — VERIFY). Also confirm `XRDC_CK_CRC64`/`XRDC_CK_ADLER32` enum names from `brix.h`.

- [ ] **Step 3: Makefile.** BINS: remove the 5 names, add `xrdcksum`. Replace the five `_OBJS` lines with `xrdcksum_OBJS := apps/cksum/xrdcksum.o apps/cksum/xrdckverify.o apps/cksum/xrdcinfo.o`. Add after the generic link rule:

```make
# Multi-call personalities: stock tool names stay invocable as symlinks.
CKSUM_LINKS := xrdcrc32c xrdcrc64 xrdadler32 xrdckverify xrdcinfo
CKSUM_LINK_PATHS := $(addprefix $(BINDIR)/,$(CKSUM_LINKS))
$(CKSUM_LINK_PATHS): $(BINDIR)/xrdcksum
	ln -sf xrdcksum $@
all: $(CKSUM_LINK_PATHS)
```

Install rule: after the `install -m755 $(BIN_EXES)` line add
`for l in $(CKSUM_LINKS); do ln -sf xrdcksum $(DESTDIR)$(PREFIX)/bin/$$l; done`.

- [ ] **Step 4: Build + behavior parity.**

```bash
make -C client -j$(nproc)
echo hello > /tmp/claude-1000/.../scratchpad/f.txt
client/bin/xrdcrc32c  /tmp/.../f.txt          # via symlink
client/bin/xrdcksum crc32c /tmp/.../f.txt     # via subcommand — SAME output
client/bin/xrdcksum crc32c /nonexistent; echo "exit=$?"   # expect the stock error exit (3)
```

Then the callers: `PYTHONPATH=tests pytest tests/test_clientconf_cksum.py tests/test_crc64.py tests/test_xrdckverify.py -v --tb=short` and `bash tests/c/test_xrdcinfo.sh`. Expected: all pass unchanged.

- [ ] **Step 5: SKIP commit.**

---

### Task 8: client — xrddiag absorbs xrdqstats / wait41 / mpxstats

**Files:**
- Modify: `client/apps/diag/xrdqstats.c`, `wait41.c`, `mpxstats.c` (`main` → `brix_qstats_main` / `brix_wait41_main` / `brix_mpxstats_main`, each `(int argc, char **argv)`; keep bodies byte-identical otherwise)
- Modify: `client/apps/diag/diag_internal.h` (declare the three), `client/apps/diag/xrddiag.c:555` (dispatch), `client/Makefile`

- [ ] **Step 1:** Verify no subcommand collision: `grep -n '"qstats"\|"wait41"\|"mpxstats"' client/apps/diag/*.c` → expect only the new code. Rename the three mains; declare in diag_internal.h.

- [ ] **Step 2:** In `xrddiag.c` `main()`, insert at the very top (before the `argc < 2` check):

```c
    /* Multi-call personalities (absorbed micro-tools; stock names via symlink) */
    {
        const char *base = strrchr(argv[0], '/');

        base = base != NULL ? base + 1 : argv[0];
        if (strcmp(base, "xrdqstats") == 0) { return brix_qstats_main(argc, argv); }
        if (strcmp(base, "wait41") == 0)    { return brix_wait41_main(argc, argv); }
        if (strcmp(base, "mpxstats") == 0)  { return brix_mpxstats_main(argc, argv); }
    }
    if (argc >= 2) {
        if (strcmp(argv[1], "qstats") == 0)   { return brix_qstats_main(argc - 1, argv + 1); }
        if (strcmp(argv[1], "wait41") == 0)   { return brix_wait41_main(argc - 1, argv + 1); }
        if (strcmp(argv[1], "mpxstats") == 0) { return brix_mpxstats_main(argc - 1, argv + 1); }
    }
```

Also add the three names to `usage()`.

- [ ] **Step 3: Makefile.** BINS: remove `xrdqstats wait41 mpxstats`; delete their `_OBJS` lines; append `apps/diag/xrdqstats.o apps/diag/wait41.o apps/diag/mpxstats.o` to `xrddiag_OBJS`. Symlinks, same pattern as Task 7 (`DIAG_LINKS := xrdqstats wait41 mpxstats`, target `xrddiag`), plus install-loop.

- [ ] **Step 4: Build + tests.** `make -C client -j$(nproc)`; parity: `client/bin/xrdqstats` with no args must print the usage naming `xrdqstats` (it prints argv[0] — symlink keeps that true) and exit 50; `client/bin/xrddiag qstats` same. Run the callers: `grep -rl "wait41\|xrdqstats\|mpxstats" tests/ | head` → run those (`PYTHONPATH=tests pytest tests/test_native_tools.py -v --tb=short` plus the two wait41 files found). Expected: parity.

- [ ] **Step 5: SKIP commit.**

---

### Task 9: client — unified `make test` for the C unit tests

**Files:**
- Modify: `client/Makefile` (new `test` target; add `test` to `.PHONY`)

- [ ] **Step 1:** Add near the other test-tool targets:

```make
# ---------------------------------------------------------------------------
# `make test` — build + run every self-contained C unit test under tests/c/.
# vfs_s3_smoke is excluded (needs an external S3 endpoint; run it manually).
CLIENT_UNIT_TESTS := cli_cred_unit cred_unit cred_store_unit vfs_posix_unit vfs_block_unit
test: $(CLIENT_LIB) | $(BINDIR)
	@set -e; for t in $(CLIENT_UNIT_TESTS); do \
	  echo "== $$t"; \
	  $(CC) $(ALL_CFLAGS) tests/c/$$t.c $(CLIENT_LIB) $(PROTO_LIB) $(LDLIBS) -o $(BINDIR)/$$t; \
	  $(BINDIR)/$$t; \
	done; echo "client unit tests: ALL PASS"
```

- [ ] **Step 2:** `make -C client test`. If any of the five needs extra libs or an env fixture, check how it was last run (header comment in the file) and either add its documented flags to a per-test `$(t)_TESTLIBS`-style override or exclude it WITH a comment naming the manual invocation — no silently-broken entries.
Expected final line: `client unit tests: ALL PASS`.

- [ ] **Step 3: SKIP commit.**

---

## Final verification (whole plan)

- [ ] `cd /tmp/nginx-1.28.3 && make -j$(nproc) && objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf`
- [ ] `tools/ci/check_config_coverage.sh && tools/ci/check_http_helper_reimpl.sh && tools/ci/check_vfs_seam.sh && tools/ci/check_file_size.sh`
- [ ] `make -C client -j$(nproc) && make -C client test`
- [ ] Fast suite: `tests/run_suite.sh --fast` (accept only pre-known load-flakes; anything new = regression, fix before reporting)
- [ ] Report: list the sites intentionally left unmigrated in Task 6 and whether Task 4 (stream adoption) happened.
