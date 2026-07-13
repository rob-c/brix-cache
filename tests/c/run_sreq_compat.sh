#!/usr/bin/env bash
#
# run_sreq_compat.sh — compile + run the brix_sreq_decode migration-compat unit
# test against the compiled stage_engine.o.
#
# Verifies:
#   (1) a full-size brix_sreq_t record round-trips with the cred intact;
#   (2) a legacy-size record (written before the cred field) decodes with a
#       zeroed cred (service-credential flush - same pre-feature semantics);
#   (3) any other size returns NGX_ERROR (corrupt / future version).
#
# Usage:  tests/c/run_sreq_compat.sh [path-to-nginx-src-dir]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
NGX_SRC="${1:-/tmp/nginx-1.28.3}"
OBJS_DIR="${NGX_SRC}/objs"
ENGINE_OBJ="${OBJS_DIR}/addon/xfer/stage_engine.o"
BIN="$(mktemp /tmp/test_sreq_compat.XXXXXX)"

if [[ ! -f "${ENGINE_OBJ}" ]]; then
    echo "ERROR: ${ENGINE_OBJ} not found. Build the module first (make)." >&2
    exit 2
fi

# Include dirs mirror the module build's ALL_INCS (nginx core + our src/).
INCS=(-I "${NGX_SRC}/src/core" -I "${NGX_SRC}/src/event"
      -I "${NGX_SRC}/src/event/modules" -I "${NGX_SRC}/src/os/unix"
      -I "${OBJS_DIR}" -I "${REPO}/src")

# Link stubs required by stage_engine.o that are not under test.
# brix_sreq_decode only calls ngx_memzero + ngx_memcpy (both inlined from the
# nginx header); nothing else is reachable in the assertions under test.
# We stub every external symbol stage_engine.o may pull in so the binary links
# without the full module.

STUB_SRC="$(mktemp /tmp/sreq_stubs.XXXXXX.c)"
cat > "${STUB_SRC}" <<'STUB_EOF'
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_thread_pool.h>

/* ---- link stubs (none reachable by the decode-only test path) ----------- */
void ngx_log_error_core(ngx_uint_t l, ngx_log_t *lg, ngx_err_t e,
    const char *f, ...) { (void)l;(void)lg;(void)e;(void)f; }
void *brix_vfs_backend_resolve(const char *r, void *l) {(void)r;(void)l;return NULL;}
unsigned brix_sd_cache_instance_is(void *i) {(void)i;return 0;}
void *brix_sd_cache_source_instance(void *i) {(void)i;return NULL;}
unsigned brix_sd_stage_instance_is(void *i) {(void)i;return 0;}
ngx_int_t brix_sd_stage_reflush(void *i, const char *k, const void *c)
{(void)i;(void)k;(void)c;return NGX_ERROR;}
void brix_xfer_finish(int k, const char *d, const char *p, const char *pr,
    size_t b, int r, int e, void *l)
{(void)k;(void)d;(void)p;(void)pr;(void)b;(void)r;(void)e;(void)l;}
ngx_pool_t *ngx_create_pool(size_t s, ngx_log_t *l){(void)s;(void)l;return NULL;}
void ngx_destroy_pool(ngx_pool_t *p){(void)p;}
ngx_thread_pool_t *ngx_thread_pool_get(ngx_cycle_t *c, ngx_str_t *n)
{(void)c;(void)n;return NULL;}
ngx_thread_task_t *ngx_thread_task_alloc(ngx_pool_t *p, size_t s)
{(void)p;(void)s;return NULL;}
ngx_int_t ngx_thread_task_post(ngx_thread_pool_t *tp, ngx_thread_task_t *t)
{(void)tp;(void)t;return NGX_ERROR;}
/* ucred_resolve stub (never reached by decode path) */
ngx_int_t brix_sd_ucred_resolve(const char *d, const char *k, void *out)
{(void)d;(void)k;(void)out;return NGX_ERROR;}
/* brix_task_bind: only linked when NGX_THREADS; prototype must match aio.h */
#if (NGX_THREADS)
void brix_task_bind(ngx_thread_task_t *task,
    void (*handler)(void *, ngx_log_t *),
    void (*completion)(ngx_event_t *))
{(void)task;(void)handler;(void)completion;}
#endif
volatile ngx_cycle_t *ngx_cycle = NULL;
STUB_EOF

cc -O -Wall "${INCS[@]}" -o "${BIN}" \
    "${HERE}/test_sreq_compat.c" "${ENGINE_OBJ}" "${STUB_SRC}"

rm -f "${STUB_SRC}"

"${BIN}"
rc=$?
rm -f "${BIN}"
exit "${rc}"
