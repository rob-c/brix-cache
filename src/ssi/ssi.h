#ifndef NGX_XROOTD_SSI_H
#define NGX_XROOTD_SSI_H

/*
 * ssi.h — minimal XrdSsi-style request/response service over the root:// file
 * protocol (§7).
 *
 * WHAT: a client opens an SSI resource path ("/.ssi/<service>"), writes the
 *       request bytes (kXR_write), reads the response (kXR_read), and closes —
 *       a unary request→response RPC. The transport is the ordinary XRootD
 *       open/write/read/close; SSI handles carry no real fd.
 * WHY:  parity with XrdSsi's wire behaviour for the common unary case, dispatched
 *       to compiled-in service handlers (no C++ plugin ABI). Streaming responses,
 *       alerts, and session multiplexing are out of scope (documented non-goals).
 * HOW:  xrootd_handle_open intercepts an SSI resource path (when xrootd_ssi is on)
 *       and binds a virtual handle whose ->ssi points to an xrootd_ssi_req_t. The
 *       write handler appends to the request buffer; the first read dispatches the
 *       request to the named service (built-in "echo") and then streams the
 *       response. The read/write hooks are clean early-returns, so the normal file
 *       data path is byte-for-byte unchanged for non-SSI handles.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "../types/context.h"

#define XROOTD_SSI_PREFIX     "/.ssi/"
#define XROOTD_SSI_PREFIX_LEN (sizeof(XROOTD_SSI_PREFIX) - 1)
#define XROOTD_SSI_REQ_MAX    (1u << 20)   /* 1 MiB cap on a unary request */

/* Per-handle SSI state (connection-pool allocated). */
typedef struct {
    char      service[64];   /* service name from the resource path */
    u_char   *req;           /* accumulated request bytes (cap XROOTD_SSI_REQ_MAX) */
    size_t    req_len;
    u_char   *resp;          /* response bytes (echo: aliases req) */
    size_t    resp_len;
    unsigned  dispatched:1;  /* response produced on first read */
} xrootd_ssi_req_t;

/* 1 if `path` is an SSI resource and SSI is enabled; fills *service (borrowed,
 * NUL-terminated within the path copy the caller owns). 0 otherwise. */
int xrootd_ssi_match(ngx_stream_xrootd_srv_conf_t *conf, const char *path,
                     const char **service, size_t *service_len);

/* kXR_open of an SSI resource: bind a virtual handle and reply kXR_ok+fhandle.
 * Returns an ngx_int_t handler result (queued response) or an error reply. */
ngx_int_t xrootd_ssi_open(xrootd_ctx_t *ctx, ngx_connection_t *c,
                          const char *service, size_t service_len);

/* kXR_write on an SSI handle: append the current payload to the request buffer. */
ngx_int_t xrootd_ssi_write(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx);

/* kXR_read on an SSI handle: dispatch on first read, then serve response bytes. */
ngx_int_t xrootd_ssi_read(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
                          uint64_t offset, uint32_t rlen);

/* Invoke the named service: req[req_len] produces the response (resp + resp_len).
 * NGX_OK / NGX_ERROR. The built-in "echo" service returns the request verbatim. */
ngx_int_t xrootd_ssi_invoke(const char *service, u_char *req, size_t req_len,
                            u_char **resp, size_t *resp_len);

#endif /* NGX_XROOTD_SSI_H */
