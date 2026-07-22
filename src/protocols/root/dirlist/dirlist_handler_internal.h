#ifndef BRIX_DIRLIST_HANDLER_INTERNAL_H
#define BRIX_DIRLIST_HANDLER_INTERNAL_H

#include "core/ngx_brix_module.h"
#include "fs/vfs/vfs.h"                 /* brix_vfs_dir_t */

/*
 * brix_dirlist_walk_t — per-request dirlist state threaded through the
 * decode → redirect → open → stream pipeline below.
 *
 * Groups the decoded request options, resolved paths, the open VFS directory
 * handle, and the 64KB chunk accumulator so each pipeline stage receives one
 * explicit state pointer instead of a parameter fan-out.
 */
typedef struct {
    u_char             options;                     /* raw kXR_dirlist options */
    ngx_flag_t         want_stat;                   /* kXR_dstat or kXR_dcksm */
    ngx_flag_t         want_cksum;                  /* kXR_dcksm */
    char               cksum_algo[32];              /* negotiated cksum algo */
    char               reqpath[BRIX_MAX_PATH + 1];  /* client-supplied path */
    char               full_path[PATH_MAX];         /* confined absolute path */
    brix_vfs_dir_t    *dh;                          /* open directory handle */
    u_char            *chunk;                       /* hdr + data accumulator */
    size_t             chunk_cap;                   /* data capacity (64KB) */
    size_t             chunk_pos;                   /* bytes accumulated */
} brix_dirlist_walk_t;

/*
 * brix_dirlist_stream_entries — the chunked streaming loop: enumerate the
 * open directory, format each visible entry, flush full 64KB chunks as
 * kXR_oksofar frames, and finish with the kXR_ok final frame.
 *
 * Owns walk->dh from here on: the handle is closed on every exit path
 * (queue failure mid-stream or normal end-of-directory).
 *
 * Returns the final queue result (NGX_OK on success).
 */
ngx_int_t brix_dirlist_stream_entries(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_dirlist_walk_t *walk);

#endif /* BRIX_DIRLIST_HANDLER_INTERNAL_H */
