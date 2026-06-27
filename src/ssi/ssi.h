#ifndef NGX_XROOTD_SSI_H
#define NGX_XROOTD_SSI_H

/*
 * ssi.h — byte-exact XrdSsi-over-xroot request/response engine (§7, Tier C core).
 *
 * WHAT: a client opens an SSI resource ("/.ssi/<service>"), submits a request via
 *       kXR_write whose offset carries an XrdSsiRRInfo{Rxq,reqId,size}, then waits
 *       for the response via kXR_query(infotype=kXR_Qopaqug, body=RRInfo{Rwt}); the
 *       reply is [XrdSsiRRInfoAttn][metadata][data] (XrdSsiTaskReal::GetResp). A
 *       kXR_query body RRInfo{Can} cancels; large/streamed responses are pulled
 *       with kXR_read(offset=RRInfo{Rxq}).
 * WHY:  real interop with libXrdSsi clients, dispatched to compiled-in native
 *       services (no C++ plugin ABI). The wire codec is byte-exact (ssi_rrinfo).
 * HOW:  xrootd_handle_open binds a virtual handle whose ->ssi points at an
 *       xrootd_ssi_req_t. write accumulates the request and, once complete, runs
 *       the service through a synchronous responder that fills the response/
 *       metadata buffers. The query-wait builds the reply via ssi_reply. The
 *       read/write/query hooks are clean early-returns, so the normal data path is
 *       unchanged for non-SSI handles.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "../types/context.h"
#include "ssi_service.h"

#define XROOTD_SSI_PREFIX     "/.ssi/"
#define XROOTD_SSI_PREFIX_LEN (sizeof(XROOTD_SSI_PREFIX) - 1)
#define XROOTD_SSI_REQ_MAX    (1u << 20)   /* 1 MiB cap on a unary request */
#define XROOTD_SSI_RESP_MAX   (1u << 20)   /* 1 MiB cap on a response */
#define XROOTD_SSI_META_MAX   4096         /* metadata cap */

/* Per-handle SSI request state (connection-pool allocated). */
typedef struct {
    char       service[64];            /* service name from the resource path */
    xrootd_ssi_process_fn handler;     /* resolved service handler (open time) */

    u_char    *req;                    /* accumulated request bytes */
    size_t     req_len;
    size_t     req_expected;           /* total request size from the RRInfo */
    uint32_t   req_id;                 /* reqId from the RRInfo */
    unsigned   have_size:1;            /* req_expected is known */
    unsigned   dispatched:1;           /* service has been invoked */

    u_char    *resp;                   /* response bytes (responder-filled) */
    size_t     resp_len;
    u_char    *meta;                   /* metadata bytes (responder-filled) */
    size_t     meta_len;
    size_t     read_cursor;            /* kXR_read stream position */

    int        err_code;               /* SSI error code (0 = none) */
    char       err_text[128];
    unsigned   error:1;
    unsigned   responded:1;            /* response (or error) is ready */
    unsigned   streaming:1;            /* service delivered multi-chunk (read-pull) */

    ngx_pool_t *pool;                  /* connection pool for responder allocs */
} xrootd_ssi_req_t;

/* 1 if `path` is an SSI resource and SSI is enabled; fills *service (borrowed,
 * within the caller's path copy) and *service_len. 0 otherwise. */
int xrootd_ssi_match(ngx_stream_xrootd_srv_conf_t *conf, const char *path,
                     const char **service, size_t *service_len);

/* kXR_open of an SSI resource: resolve the service, bind a virtual handle, and
 * reply kXR_ok+fhandle. Unknown service → kXR_NotFound. */
ngx_int_t xrootd_ssi_open(xrootd_ctx_t *ctx, ngx_connection_t *c,
                          const char *service, size_t service_len,
                          uint16_t options);

/* kXR_write on an SSI handle: decode the RRInfo from the 8 raw offset bytes,
 * accumulate the request, and dispatch the service once the request is complete.
 * Replies kXR_ok (write ack). */
ngx_int_t xrootd_ssi_write(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
                           const unsigned char off8[8]);

/* kXR_query(kXR_Qopaqug) on an SSI handle: the response-wait/cancel. body is the
 * 8-byte RRInfo. Rwt → reply [RRInfoAttn][meta][data]; Can → cancel. */
ngx_int_t xrootd_ssi_query(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
                           const unsigned char *body, size_t body_len);

/* kXR_read on an SSI handle: serve streamed response bytes from the cursor. */
ngx_int_t xrootd_ssi_read(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
                          uint64_t offset, uint32_t rlen);

#endif /* NGX_XROOTD_SSI_H */
