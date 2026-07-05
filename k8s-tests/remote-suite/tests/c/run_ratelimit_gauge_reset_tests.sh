#!/usr/bin/env bash
#
# run_ratelimit_gauge_reset_tests.sh — compile + run the rate-limit gauge-reset
# regression against the compiled ratelimit_zone.o.
#
# Proves leaked in-use gauges (in_flight / open_files) are cleared on reload so
# a concurrency/throttle limit can't wedge a key forever after many restarts.
# See tests/c/test_ratelimit_gauge_reset.c for the rationale.
#
# Usage:  tests/c/run_ratelimit_gauge_reset_tests.sh [path-to-nginx-src-dir]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
NGX_SRC="${1:-/tmp/nginx-1.28.3}"
OBJS_DIR="${NGX_SRC}/objs"
ZONE_OBJ="${OBJS_DIR}/addon/ratelimit/ratelimit_zone.o"
BIN="$(mktemp /tmp/test_rl_gauge_reset.XXXXXX)"

if [[ ! -f "${ZONE_OBJ}" ]]; then
    echo "ERROR: ${ZONE_OBJ} not found. Build the module first (./configure && make)." >&2
    exit 2
fi

INCS=(-I "${NGX_SRC}/src/core" -I "${NGX_SRC}/src/event"
      -I "${NGX_SRC}/src/event/modules" -I "${NGX_SRC}/src/os/unix"
      -I "${OBJS_DIR}" -I "${NGX_SRC}/src/stream" -I "${NGX_SRC}/src/http"
      -I "${NGX_SRC}/src/http/modules" -I "${REPO}/src")

# ratelimit_zone.o pulls slab/rbtree/config symbols we never call (only the
# pure gauge-reset walk is exercised); satisfy the linker with abort stubs.
STUBS="$(mktemp /tmp/rl_stubs.XXXXXX.c)"
cat > "${STUBS}" <<'EOF'
#include <ngx_config.h>
#include <ngx_core.h>
#include <stdlib.h>
#define UNUSED(x) (void)(x)
void *ngx_slab_alloc(ngx_slab_pool_t *p, size_t s){UNUSED(p);UNUSED(s);abort();}
void *ngx_slab_alloc_locked(ngx_slab_pool_t *p, size_t s){UNUSED(p);UNUSED(s);abort();}
void ngx_slab_free_locked(ngx_slab_pool_t *p, void *v){UNUSED(p);UNUSED(v);abort();}
void ngx_rbtree_insert(ngx_rbtree_t *t, ngx_rbtree_node_t *n){UNUSED(t);UNUSED(n);abort();}
void ngx_rbtree_delete(ngx_rbtree_t *t, ngx_rbtree_node_t *n){UNUSED(t);UNUSED(n);abort();}
ngx_int_t ngx_memn2cmp(u_char *a,u_char *b,size_t la,size_t lb){UNUSED(a);UNUSED(b);UNUSED(la);UNUSED(lb);abort();}
void *ngx_pcalloc(ngx_pool_t *p, size_t s){UNUSED(p);UNUSED(s);abort();}
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *n, size_t s, void *t){UNUSED(cf);UNUSED(n);UNUSED(s);UNUSED(t);abort();}
u_char *ngx_sprintf(u_char *b, const char *f, ...){UNUSED(b);UNUSED(f);abort();}
void ngx_conf_log_error(ngx_uint_t l, ngx_conf_t *cf, ngx_err_t e, const char *f, ...){UNUSED(l);UNUSED(cf);UNUSED(e);UNUSED(f);}
void *ngx_brix_shm_zone;
EOF

cc -O -Wall "${INCS[@]}" -o "${BIN}" \
    "${HERE}/test_ratelimit_gauge_reset.c" "${STUBS}" "${ZONE_OBJ}"

"${BIN}"
rc=$?
rm -f "${BIN}" "${STUBS}"
exit "${rc}"
