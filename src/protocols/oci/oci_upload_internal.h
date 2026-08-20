/*
 * oci_upload_internal.h — the two halves of the blob upload machine.
 *
 * WHAT: the request-scoped session record and the small answer helpers shared
 *       between the routing half (oci_upload.c) and the body half
 *       (oci_upload_seal.c).
 * WHY:  nginx splits every body-carrying method in two — a handler that
 *       DECIDES and a callback that ACTS, with only the request between them.
 *       The record below is that "only the request": it is what the decision
 *       leaves behind for the callback to find. Keeping the two halves in
 *       separate translation units keeps each one readable; keeping their
 *       contract in one header keeps them honest about it.
 */
#ifndef BRIX_PROTOCOLS_OCI_UPLOAD_INTERNAL_H
#define BRIX_PROTOCOLS_OCI_UPLOAD_INTERNAL_H

#include "oci_registry.h"

/* What the re-entered body handler is supposed to do. */
typedef enum {
    OCI_UP_MONOLITHIC = 0,   /* POST ?digest= with the whole blob inline */
    OCI_UP_PATCH,            /* append to an open session                */
    OCI_UP_SEAL              /* PUT: optional tail, then hash and commit */
} oci_upload_act_e;

typedef struct {
    oci_upload_act_e   act;
    brix_oci_store_t   st;
    brix_oci_digest_t  want;       /* the client's claimed digest (seal)  */
    char               session[BRIX_OCI_SESSION_MAX + 1];
    size_t             session_len;
    off_t              base;       /* part-file length before this write  */
} oci_upload_ctx_t;

/* The three headers every session answer carries: where to continue, how far
 * we got, and the id the client should quote. `end` is the byte COUNT; the
 * Range value is inclusive, and an empty session reports "0-0" because there
 * is no such thing as an inclusive empty range on this wire. */
ngx_int_t brix_oci_upload_headers(ngx_http_request_t *r,
    const brix_oci_req_t *req, const char *session, off_t end);

/* 201 for a blob that is now in the store, wherever it came from. */
ngx_int_t brix_oci_upload_created(ngx_http_request_t *r,
    const brix_oci_req_t *req, const brix_oci_digest_t *d);

/* The re-entry point nginx calls once the body has been read. */
void brix_oci_upload_body_handler(ngx_http_request_t *r);

#endif /* BRIX_PROTOCOLS_OCI_UPLOAD_INTERNAL_H */
