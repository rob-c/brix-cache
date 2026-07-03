#ifndef BRIX_TYPES_STATE_H
#define BRIX_TYPES_STATE_H

/*
 * Per-connection state machine enum and opaque forward declarations.
 *
 * Normal flow (no TLS, no upstream):
 *   HANDSHAKE → REQ_HEADER → REQ_PAYLOAD (if dlen > 0) → REQ_HEADER → …
 *
 * SENDING: entered when brix_queue_response_base() gets EAGAIN from
 *   c->send().  The remaining bytes stay in ctx->wbuf; the write event
 *   is armed.  The read event is NOT active while SENDING.
 *
 * AIO: entered when a pread(2)/pwrite(2) is posted to the nginx thread
 *   pool.  Both read and write events are disarmed.  The completion
 *   callback re-arms the write event with the response already queued.
 *
 * TLS_HANDSHAKE: entered after sending kXR_haveTLS in a kXR_protocol
 *   response.  Both events are re-armed by the TLS accept machinery.
 *
 * UPSTREAM: entered while waiting for the redirector to reply.  The
 *   client-facing read event is disarmed; upstream events drive progress.
 */
typedef enum {
    XRD_ST_HANDSHAKE,     /* accumulating the 20-byte client hello  */
    XRD_ST_REQ_HEADER,    /* accumulating a 24-byte request header  */
    XRD_ST_REQ_PAYLOAD,   /* accumulating dlen bytes of payload     */
    XRD_ST_SENDING,       /* draining a large pending write buffer  */
    XRD_ST_AIO,           /* async file I/O posted to thread pool   */
    XRD_ST_TLS_HANDSHAKE, /* kXR_ableTLS: TLS accept in progress    */
    XRD_ST_UPSTREAM,      /* upstream redirector query in progress  */
    XRD_ST_PROXY,         /* proxy request forwarded, awaiting response */
    XRD_ST_WAITING_CMS,   /* kYR_locate sent to manager; awaiting kYR_select */
    XRD_ST_WAITING_FRM,   /* kXR_waitresp sent; awaiting async stage completion */
} brix_state_t;

/* Opaque upstream context — defined in src/upstream/ */
typedef struct brix_upstream_s brix_upstream_t;

/* Opaque proxy context — defined in src/proxy/ */
typedef struct brix_proxy_ctx_s brix_proxy_ctx_t;

/* Opaque CMS heartbeat context — defined in cms/connect.c */
typedef struct ngx_brix_cms_ctx_s ngx_brix_cms_ctx_t;

#endif /* BRIX_TYPES_STATE_H */
