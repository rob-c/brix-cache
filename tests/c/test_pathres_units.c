/*
 * test_pathres_units.c — the pure HTTP path resolver seam (brix_http_resolve_path
 * / brix_http_resolve_path_ex).
 *
 * Pins the trusted-cache-store-endpoint exception: with allow_internal set, a
 * reserved sidecar name (<key>.cinfo) resolves normally, while the default-deny
 * wrapper and allow_internal=0 still 404 it — and ONLY the internal-name guard is
 * relaxed (traversal/dotdot still 403, normal names unaffected either way).
 *
 * Compiled standalone against src/core/compat/path.c with -DBRIX_PATH_OP_PATH_H
 * (suppresses the ngx-heavy op_path.h) and -include tests/c/pathres_shim.h. The
 * two ngx-free lexical helpers path.c calls are defined here (faithful copies of
 * the src/ implementations), so the traversal guard is exercised for real.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "core/compat/path.h"

/* Export root is only lexically joined here (no realpath / no I/O), so any
 * canonical-looking absolute path serves. */
static const char *ROOT = "/export/data";

/* ---- Faithful ngx-free copies of the two helpers path.c links against. ----
 * (src/fs/path/helpers.c and src/protocols/root/path/op_path.c are ngx-coupled
 * translation units; the logic under test lives in path.c, and these inputs must
 * behave identically for the traversal assertion to be meaningful.) */

#define TEST_MAX_WALK_DEPTH 32

ngx_int_t
brix_count_path_depth(const char *path)
{
    const char *cursor = path;
    unsigned    count;

    while (*cursor == '/') {
        cursor++;
    }
    if (*cursor == '\0') {
        return NGX_OK;
    }
    count = 1;
    while (*cursor != '\0') {
        if (*cursor == '/') {
            cursor++;
            if (*cursor != '\0') {
                count++;
            }
        } else {
            cursor++;
        }
    }
    return (count > TEST_MAX_WALK_DEPTH) ? NGX_ERROR : NGX_OK;
}

int
brix_op_path_forbidden_component(const char *reqpath)
{
    const char *cursor = reqpath;
    const char *segment;
    size_t      segment_len;

    while (*cursor != '\0') {
        while (*cursor == '/') {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }
        segment = cursor;
        while (*cursor != '\0' && *cursor != '/') {
            cursor++;
        }
        segment_len = (size_t) (cursor - segment);
        if ((segment_len == 1 && segment[0] == '.')
            || (segment_len == 2 && segment[0] == '.' && segment[1] == '.'))
        {
            return 1;
        }
    }
    return 0;
}

int
main(void)
{
    char buf[4096];

    /* success: a reserved sidecar name is a legitimate target on a store
     * endpoint (allow_internal=1) → resolves 0. */
    assert(brix_http_resolve_path_ex(ROOT, "a/f.bin.cinfo",
                                     buf, sizeof(buf), 1) == 0);

    /* security-negative (default deny): the same name is invisible (404) via the
     * thin wrapper AND via the explicit allow_internal=0 seam. */
    assert(brix_http_resolve_path(ROOT, "a/f.bin.cinfo",
                                  buf, sizeof(buf)) == 404);
    assert(brix_http_resolve_path_ex(ROOT, "a/f.bin.cinfo",
                                     buf, sizeof(buf), 0) == 404);

    /* .meta / stage-marker / upload-temp names share the guard and relaxation. */
    assert(brix_http_resolve_path(ROOT, "d/x.meta", buf, sizeof(buf)) == 404);
    assert(brix_http_resolve_path_ex(ROOT, "d/x.meta",
                                     buf, sizeof(buf), 1) == 0);

    /* unaffected: a normal name resolves 0 under BOTH allow_internal values. */
    assert(brix_http_resolve_path_ex(ROOT, "a/f.bin",
                                     buf, sizeof(buf), 0) == 0);
    assert(brix_http_resolve_path_ex(ROOT, "a/f.bin",
                                     buf, sizeof(buf), 1) == 0);
    assert(brix_http_resolve_path(ROOT, "a/f.bin", buf, sizeof(buf)) == 0);

    /* unaffected: ONLY the internal-name branch is relaxed — a ".." traversal
     * still 403s even with allow_internal=1, including a traversal that also
     * carries a reserved suffix (dotdot rejection precedes the skipped guard). */
    assert(brix_http_resolve_path_ex(ROOT, "a/../f.bin",
                                     buf, sizeof(buf), 1) == 403);
    assert(brix_http_resolve_path_ex(ROOT, "../secret.cinfo",
                                     buf, sizeof(buf), 1) == 403);

    /* unaffected: NULL still 403 under the relaxed path. */
    assert(brix_http_resolve_path_ex(ROOT, NULL, buf, sizeof(buf), 1) == 403);

    printf("test_pathres_units: ALL PASS\n");
    return 0;
}
