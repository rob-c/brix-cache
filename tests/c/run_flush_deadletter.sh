#!/usr/bin/env bash
#
# run_flush_deadletter.sh — compile + run the deny-mode flush dead-letter unit
# test against the compiled stage_engine.o.
#
# Verifies:
#   (A) a journal record whose deny-flush keeps failing is MOVED to deadletter/
#       after BRIX_STAGE_DENY_MAX_ATTEMPTS drives and is no longer re-driven;
#   (B) the attempts count is persisted and incremented across drives;
#   (C) the age cap dead-letters a stale record even below the attempt count;
#   (D) a non-dead-lettered record can be cleaned up normally (no false positive).
#
# Usage:  tests/c/run_flush_deadletter.sh [path-to-nginx-src-dir]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
NGX_SRC="${1:-/tmp/nginx-1.28.3}"
OBJS_DIR="${NGX_SRC}/objs"
ENGINE_OBJ="${OBJS_DIR}/addon/xfer/stage_engine.o"
BIN="$(mktemp /tmp/test_flush_deadletter.XXXXXX)"

if [[ ! -f "${ENGINE_OBJ}" ]]; then
    echo "ERROR: ${ENGINE_OBJ} not found. Build the module first (make)." >&2
    exit 2
fi

# Include dirs mirror the module build's ALL_INCS (nginx core + our src/).
INCS=(-I "${NGX_SRC}/src/core" -I "${NGX_SRC}/src/event"
      -I "${NGX_SRC}/src/event/modules" -I "${NGX_SRC}/src/os/unix"
      -I "${OBJS_DIR}" -I "${REPO}/src")

# Stub source: provides all symbols stage_engine.o may pull in that are not
# under test.  The thread-pool header is included here (not in the test .c
# file) to avoid platform-specific event-header conflicts.
STUB_SRC="$(mktemp /tmp/deadletter_stubs.XXXXXX.c)"
cat > "${STUB_SRC}" <<'STUB_EOF'
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_thread_pool.h>

/* ---- link stubs (none reachable by the dead-letter test path) ----------- */
/* NOTE: ngx_log_error_core and ngx_cycle are defined in the test .c file
 * so that ngx_log_error_core can count ERR-level calls for assertions. */
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
ngx_int_t brix_sd_ucred_resolve(const char *d, const char *k, void *out)
{(void)d;(void)k;(void)out;return NGX_ERROR;}
#if (NGX_THREADS)
void brix_task_bind(ngx_thread_task_t *task,
    void (*handler)(void *, ngx_log_t *),
    void (*completion)(ngx_event_t *))
{(void)task;(void)handler;(void)completion;}
#endif
STUB_EOF

cc -O -Wall "${INCS[@]}" -o "${BIN}" \
    "${HERE}/test_flush_deadletter.c" "${ENGINE_OBJ}" "${STUB_SRC}"

rm -f "${STUB_SRC}"

"${BIN}"
rc=$?
rm -f "${BIN}"
exit "${rc}"
