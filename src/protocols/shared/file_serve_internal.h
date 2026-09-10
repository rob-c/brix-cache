/*
 * file_serve_internal.h — the memory-backed body-send seam of the shared
 * file serve.
 *
 * WHAT: declares the one entry point file_serve.c calls when the backend
 *   exposes no single sendfile fd.
 * WHY: the memory-backed streamer carries its own read/emit/status helpers and
 *   its own error contract (a pre-header origin failure answers a real status,
 *   INVARIANT 2 keeps it strictly separate from the sendfile path), which is a
 *   whole file's worth of body; splitting it keeps file_serve.c inside the
 *   600-line contract and keeps the two send paths physically unmixable.
 * HOW: one declaration, shared only between file_serve.c and
 *   file_serve_memory.c — never a public header.
 */

#ifndef BRIX_FILE_SERVE_INTERNAL_H
#define BRIX_FILE_SERVE_INTERNAL_H

#include "file_serve.h"

/* Stream [start, start+len) of `fh` to the client through driver preads.
 * Returns the output-filter rc, NGX_ERROR once bytes are already on the wire,
 * or a terminal HTTP status when the origin failed before the header was sent.
 * The caller still owns closing `fh`. */
ngx_int_t brix_serve_memory_backed(ngx_http_request_t *r, brix_vfs_file_t *fh,
    off_t start, off_t len);

#endif /* BRIX_FILE_SERVE_INTERNAL_H */
