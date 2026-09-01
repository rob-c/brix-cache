/*
 * walk_offload.h — thread-offload for blocking metadata walks (phase 109).
 *
 * WHAT: Declares the gate + dispatch that move a WebDAV metadata build
 *       (PROPFIND today; SEARCH/LOCK are the planned W2 adopters) onto the
 *       shared thread pool when its VFS I/O would otherwise block the event
 *       loop against a remote storage backend.
 *
 * WHY:  phase-106 W5 traced a real availability defect: PROPFIND/SEARCH/LOCK
 *       run their backend I/O INLINE, so against a remote backend (the origin
 *       PROPFIND through the blocking curl transport) or under EXCHANGE-mode
 *       delegation (the RFC-8693 POST) one slow origin stalls every connection
 *       on the worker for up to the bounded timeout.  GET/PUT/COPY/MOVE already
 *       thread-offload; this extends the same pattern to the metadata methods.
 *
 * HOW:  See walk_offload.c.  The gate is deliberately narrow: remote backend,
 *       thread pool configured, and NOT under impersonation (the per-worker
 *       broker socket is single-user and the thread lacks the principal —
 *       the same decline copy_collection.c:300 established).
 */
#ifndef BRIX_WEBDAV_WALK_OFFLOAD_H
#define BRIX_WEBDAV_WALK_OFFLOAD_H

#include "webdav.h"

/* The two halves a metadata method hands the offload.  build runs on the
 * THREAD (all the VFS I/O + XML assembly, allocating only via
 * webdav_req_pool(r), which points at the task-private pool while offloaded);
 * send runs on the EVENT LOOP (headers + output filter).  `tail` is carried
 * for methods whose send wants it (SEARCH); PROPFIND leaves it NULL. */
typedef ngx_int_t (*webdav_walk_build_pt)(ngx_http_request_t *r,
    ngx_chain_t **head, ngx_chain_t **tail, off_t *total_len);
typedef ngx_int_t (*webdav_walk_send_pt)(ngx_http_request_t *r,
    ngx_chain_t *head, ngx_chain_t *tail, off_t total_len);

/* Post the method's build to the thread pool; the done handler runs send and
 * finalizes.  Returns NGX_DONE when the task was posted (the caller must NOT
 * finalize), or NGX_DECLINED when the offload does not apply (impersonation
 * on, local backend, no pool, or alloc failure) and the caller runs the
 * inline path unchanged. */
ngx_int_t webdav_walk_offload(ngx_http_request_t *r,
    webdav_walk_build_pt build, webdav_walk_send_pt send);

/* The SEARCH build/send halves (search.c), consumed by the adapter below. */
ngx_int_t webdav_search_build(ngx_http_request_t *r, ngx_chain_t **out_head,
                              ngx_chain_t **out_tail);
ngx_int_t webdav_search_send(ngx_http_request_t *r, ngx_chain_t *head,
                             ngx_chain_t *tail);

/* PROPFIND / SEARCH front doors (thin adapters over webdav_walk_offload). */
ngx_int_t webdav_propfind_offload(ngx_http_request_t *r);
ngx_int_t webdav_search_offload(ngx_http_request_t *r);

#endif /* BRIX_WEBDAV_WALK_OFFLOAD_H */
