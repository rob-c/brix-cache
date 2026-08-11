/*
 * get_internal.h — GET-pipeline state + cross-TU entry points shared by
 * get.c (orchestrator), get_serve.c (open/stat + serve phases) and
 * get_directory.c (§6.6 directory listing).  Split from the single 793-line
 * get.c at phase-103; behaviour unchanged.
 */
#pragma once

#include "webdav.h"
#include "fs/vfs/vfs.h"
#include "protocols/shared/file_serve.h"

/*
 * get_serve_state_t — the serve-ready handle + derived metadata produced by
 * the resolve/open phase and consumed by the serving phases.  It bundles the
 * open VFS handle with the POSIX-shaped stat (`sb`, used by the multipart and
 * pre-header paths), the VFS stat (`vst`, used by the ranged serve), and the
 * fd-cache bookkeeping (`from_cache`/`cache_path`) so the phase helpers take a
 * single explicit state object instead of a long parameter list.  It is filled
 * only when the resolve phase returns NGX_OK.
 */
typedef struct {
    brix_vfs_file_t *fh;           /* open handle (owned by the caller flow) */
    struct stat      sb;           /* POSIX stat for multipart/pre-header use */
    brix_vfs_stat_t  vst;          /* VFS stat for the ranged serve           */
    ngx_uint_t       from_cache;   /* fd came from the read-through cache tier */
    const char      *cache_path;   /* cache path for access accounting         */
} get_serve_state_t;

/* GET range/bytes metrics — defined in get.c, shared with the serve phases
 * (get_serve.c) and the off-loop serve completion so all report identically. */
void webdav_serve_metrics(ngx_http_request_t *r,
    const brix_http_serve_result_t *result);

/* get_serve.c — open/stat + the three serving phases. */
ngx_int_t webdav_get_resolve_and_stat(ngx_http_request_t *r,
    brix_vfs_ctx_t *vctx, const char *path, get_serve_state_t *st);
ngx_int_t webdav_get_serve_range(ngx_http_request_t *r,
    get_serve_state_t *st, const char *path);
ngx_int_t webdav_get_eval_conditionals(ngx_http_request_t *r,
    get_serve_state_t *st);
ngx_int_t webdav_get_serve_full(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_http_brix_webdav_req_ctx_t *wctx, get_serve_state_t *st,
    const char *path);

/* get_directory.c — §6.6 listingredir / HTML listing / listingdeny. */
ngx_int_t webdav_get_serve_directory(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path);
