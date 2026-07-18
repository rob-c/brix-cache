/*
 * pathres_shim.h — force-included (-include) into core/compat/path.c and its
 * unit test so the pure resolver compiles standalone.
 *
 * WHY: path.c pulls protocols/root/path/op_path.h only for the declaration of
 * brix_op_path_forbidden_component, but that header transitively includes the
 * heavy core/ngx_brix_module.h (all of nginx). For the standalone unit test the
 * compile passes -DBRIX_PATH_OP_PATH_H to suppress op_path.h, and this shim
 * supplies the handful of decls path.c actually references (NGX_OK, ngx_int_t,
 * and the two ngx-free lexical helpers). The helper bodies live in the test TU.
 * This mirrors the client/apps/ceph/ngx_shim.h force-include pattern.
 */
#ifndef BRIX_TEST_PATHRES_SHIM_H
#define BRIX_TEST_PATHRES_SHIM_H

#include <stdint.h>

#ifndef NGX_OK
#define NGX_OK 0
#endif
#ifndef NGX_ERROR
#define NGX_ERROR (-1)
#endif

typedef intptr_t ngx_int_t;

ngx_int_t brix_count_path_depth(const char *path);
int       brix_op_path_forbidden_component(const char *reqpath);

#endif /* BRIX_TEST_PATHRES_SHIM_H */
