/*
 * http_mirror_internal.h — declarations shared across the HTTP/WebDAV traffic
 * mirror files after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the one method-classification predicate and the five
 *       upstream callbacks that straddle the http_mirror.c / http_mirror_request.c
 *       boundary, plus the shared MIR_HTTP_INC counter macro.
 * WHY:  http_mirror.c (949 lines) split into three focused files under the
 *       500-line cap: http_mirror.c (method classifiers + phase-handler /
 *       subrequest orchestration), http_mirror_request.c (shadow HTTP
 *       request/response build + nginx upstream callbacks), and
 *       http_mirror_config.c (merge-time upstream setup + directive setters).
 *       The subrequest driver in http_mirror.c wires the five upstream callbacks
 *       that live in http_mirror_request.c, and the request builder there reuses
 *       the body-method predicate that lives in http_mirror.c — exactly those
 *       symbols become non-static and are declared here; nothing else crosses.
 * HOW:  http_mirror.c and http_mirror_request.c both include this header; none
 *       of the symbols is part of the mirror's public surface (http_mirror.h).
 *
 * Requires: protocols/webdav/webdav.h (ngx_http_request_t and the brix metrics
 *           accessor used by MIR_HTTP_INC) included before this header —
 *           satisfied transitively via http_mirror.h.
 */
#ifndef BRIX_MIRROR_HTTP_MIRROR_INTERNAL_H
#define BRIX_MIRROR_HTTP_MIRROR_INTERNAL_H

/* Mirror counters live in the shared root metrics struct (low cardinality, no
 * per-target labels per metrics INVARIANT 8).  Shared by the finalize path in
 * http_mirror_request.c and the sampling gate in http_mirror.c. */
#define MIR_HTTP_INC(field)                                                  \
    do {                                                                     \
        ngx_brix_metrics_t *_m = brix_metrics_shared();                  \
        if (_m != NULL) { (void) ngx_atomic_fetch_add(&_m->field, 1); }      \
    } while (0)

/* Defined in http_mirror.c. True if the method carries a request body the shadow
 * must receive (PUT).  Reused by the request builder in http_mirror_request.c. */
ngx_int_t brix_http_mirror_method_has_body(ngx_uint_t method);

/* ---- upstream callbacks (defined in http_mirror_request.c) ----------------
 * Wired onto r->upstream by brix_http_mirror_proxy() in http_mirror.c, so each
 * is non-static and declared here.  Everything else in the request builder
 * (plan struct, sizing/writing passes, mirror_process_header) stays file-local. */

/* create_request: build the shadow HTTP request line + headers (+ cloned PUT
 * body) into r->upstream->request_bufs.  NGX_OK / NGX_ERROR. */
ngx_int_t mirror_create_request(ngx_http_request_t *r);

/* reinit_request: reset the scratch status before an upstream retry.  NGX_OK /
 * NGX_ERROR. */
ngx_int_t mirror_reinit_request(ngx_http_request_t *r);

/* process_header (status-line entry): parse the shadow status line, then chain
 * to header parsing.  NGX_OK / NGX_AGAIN / upstream-invalid-header. */
ngx_int_t mirror_process_status_line(ngx_http_request_t *r);

/* abort_request: upstream abort hook (no-op for a fire-and-forget shadow). */
void mirror_abort_request(ngx_http_request_t *r);

/* finalize_request: count the shadow result and compare its status class to the
 * primary's for divergence metrics. */
void mirror_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

#endif /* BRIX_MIRROR_HTTP_MIRROR_INTERNAL_H */
