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
#include "types/context.h"
#include "ssi_service.h"
#include "ssi_req.h"        /* xrootd_ssi_req_t (nginx-free data type) */

#define XROOTD_SSI_PREFIX     "/.ssi/"
#define XROOTD_SSI_PREFIX_LEN (sizeof(XROOTD_SSI_PREFIX) - 1)
#define XROOTD_SSI_REQ_MAX    (1u << 20)   /* 1 MiB cap on a unary request */
#define XROOTD_SSI_RESP_MAX   (1u << 20)   /* 1 MiB cap on a response */
#define XROOTD_SSI_META_MAX   4096         /* metadata cap */

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

/* Teardown hook for an SSI handle (an xrootd_ssi_session_t*). Cancels any armed
 * async-deferral timers and unregisters the session. Called from
 * xrootd_free_fhandle before the .ssi slot is cleared (on close + disconnect).
 * NULL-safe; a no-op for non-SSI handles. */
void xrootd_ssi_handle_cleanup(void *ssi_session);

#endif /* NGX_XROOTD_SSI_H */
