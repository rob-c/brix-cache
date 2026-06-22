/*
 * aio.h — asynchronous, multi-in-flight transport for libxrdc (M1).
 *
 * WHAT: A single epoll event loop, on its own thread, that drives one or more
 *       already-brought-up XRootD connections (xrdc_conn) in NON-BLOCKING mode,
 *       pipelining many requests per connection and demultiplexing replies by
 *       streamid. Requests complete via a callback on the loop thread; a blocking
 *       convenience wrapper (xrdc_aio_call) lets the FUSE driver's worker threads
 *       issue ordinary synchronous calls that nonetheless pipeline over a shared
 *       socket.
 * WHY:  The synchronous core (sock.c/frame.c) is one-request-in-flight and a flat
 *       30 s timeout — on a high-RTT / lossy link that serialises throughput and
 *       turns any transient drop into a stalled, then EIO'd, operation. The async
 *       core hides RTT (pipelining), bounds every request with its own deadline,
 *       and is the substrate the resilience + resumption layers (M2/M3) build on.
 * HOW:  Bring a connection up synchronously the usual way (xrdc_connect: connect →
 *       [TLS] → login → auth), then hand it to the loop with xrdc_aconn_attach;
 *       the loop sets the fd non-blocking and owns all subsequent socket I/O. The
 *       per-connection state (out queue, in-flight map, parse buffer) is touched
 *       ONLY by the loop thread; other threads interact strictly through a
 *       mutex-guarded command queue woken by an eventfd. So the data plane needs
 *       no per-field locking.
 *
 * Clean-room: epoll/eventfd/pthreads + the existing wire framing only. No XrdCl.
 *
 * Limitation (M1): a connection with GSI request-signing active (conn->signing_
 * active) cannot go async yet — each request would need an inline kXR_sigver
 * round-trip. xrdc_aconn_attach rejects such a conn so the caller can fall back to
 * the synchronous pool. Anonymous / token (ztn) / unix sessions pipeline fine.
 */
#ifndef XRDC_AIO_H
#define XRDC_AIO_H

#include "xrdc.h"

/* Opaque to callers; defined in aio.c. */
typedef struct xrdc_loop  xrdc_loop;
typedef struct xrdc_aconn xrdc_aconn;

/*
 * Completion callback, invoked on the loop thread exactly once per request.
 *   rc == 0  → a terminal server frame arrived: `kxr` is the status (kXR_ok,
 *              and for the upper layers kXR_redirect / kXR_wait / kXR_error-as
 *              -rc<0). `body`/`blen` is the accumulated reply body (oksofar frames
 *              are concatenated); ownership passes to the callback, which must
 *              free(body).
 *   rc <  0  → the request failed at the transport/deadline level: `st` describes
 *              it (kxr is its kXR_* / XRDC_E* code), body is NULL.
 * The callback must not block the loop (it runs inline); the sync wrapper below
 * just signals a condvar.
 */
typedef void (*xrdc_aio_cb)(void *ctx, int rc, uint16_t kxr,
                            uint8_t *body, uint32_t blen, const xrdc_status *st);

/* ---- loop lifecycle ---- */
/* Create the loop and start its thread. NULL + st on failure. */
xrdc_loop *xrdc_loop_create(xrdc_status *st);
/* Stop the loop thread and free it. Any still-attached aconns are closed first
 * (their in-flight requests complete with rc<0). Does not free the underlying
 * xrdc_conn objects — the caller owns those. */
void       xrdc_loop_destroy(xrdc_loop *l);

/* ---- connection lifecycle ---- */
/* Hand a brought-up conn to the loop (fd set non-blocking, registered in epoll).
 * The aconn borrows `conn` (host/port/opts/creds for reconnect, M2); the caller
 * keeps ownership and must not touch conn->io while it is attached. Returns NULL +
 * st on failure (including a signing-active conn — see the file header). */
xrdc_aconn *xrdc_aconn_attach(xrdc_loop *l, xrdc_conn *conn, xrdc_status *st);
/* Detach + tear down an aconn (synchronous: returns once the loop has failed all
 * its in-flight requests and removed it). The underlying conn is left closed-by-
 * caller — call xrdc_close on it afterwards if you own it. */
void        xrdc_aconn_close(xrdc_aconn *ac);

/* ---- resilience tuning (M2) ---- */
/* Override an aconn's resilience policy (else sensible defaults apply at attach):
 *   max_stall_ms    — total patience across reconnect attempts before a parked
 *                     request is failed (the "bad wifi" budget). 0 disables
 *                     reconnect entirely (a drop fails in-flight immediately).
 *   keepalive_ms    — idle time before a kXR_ping heartbeat probes a quiet link
 *                     (proactive dead-peer detection). 0 disables the heartbeat.
 *   max_retries     — default transport-level re-issues for a retry-safe request.
 * Pass a negative value to leave that field at its current/default value. */
void xrdc_aconn_set_resilience(xrdc_aconn *ac, int max_stall_ms,
                               int keepalive_ms, int max_retries);

/* ---- request submission ---- */
/* Per-request options for xrdc_aio_submit_ex. */
typedef struct {
    int deadline_ms;   /* hard ceiling for this request; <= 0 ⇒ adaptive (RTT-based,
                        * bounded by the aconn's max_stall_ms) */
    int max_retries;   /* transport re-issues after a reconnect; < 0 ⇒ aconn default */
    int retry_safe;    /* 1 ⇒ idempotent + not handle-bound, so the engine may
                        * transparently re-issue it verbatim after a reconnect */
} xrdc_aio_opts;

/* Submit with explicit options (see xrdc_aio_opts). opts may be NULL (⇒ adaptive
 * deadline, aconn default retries, retry_safe=0). Thread-safe; 0 (queued) / -1 (st). */
int xrdc_aio_submit_ex(xrdc_aconn *ac, const void *hdr24,
                       const void *payload, uint32_t plen,
                       const xrdc_aio_opts *opts,
                       xrdc_aio_cb cb, void *ctx, xrdc_status *st);

/* Submit one request. `hdr24` is a 24-byte ClientRequestHdr with requestid + the
 * 16-byte body already filled; the engine assigns the streamid and writes dlen.
 * `payload` (plen bytes, may be NULL) is copied. `cb`/`ctx` receive the result.
 * deadline_ms <= 0 ⇒ adaptive deadline. Not auto-retried (retry_safe=0); use
 * xrdc_aio_submit_ex to opt an idempotent request into transparent reconnect
 * retry. Thread-safe; returns 0 (queued) or -1 (st). */
int xrdc_aio_submit(xrdc_aconn *ac, const void *hdr24,
                    const void *payload, uint32_t plen,
                    xrdc_aio_cb cb, void *ctx, int deadline_ms, xrdc_status *st);

/* Blocking convenience: submit + wait for completion on the calling thread. Many
 * callers may be in flight at once over a single aconn (that is the point). On
 * success returns 0 with *kxr set and the *body / *blen out-params holding the
 * malloc'd reply (caller frees; pass body=NULL to discard). -1 (st) on error. */
int xrdc_aio_call(xrdc_aconn *ac, const void *hdr24,
                  const void *payload, uint32_t plen,
                  uint16_t *kxr, uint8_t **body, uint32_t *blen,
                  int deadline_ms, xrdc_status *st);

/* Blocking call with explicit options (retry_safe etc.); see xrdc_aio_submit_ex.
 * opts may be NULL. The plain xrdc_aio_call is this with {deadline, -1, 0}. */
int xrdc_aio_call_ex(xrdc_aconn *ac, const void *hdr24,
                     const void *payload, uint32_t plen,
                     const xrdc_aio_opts *opts,
                     uint16_t *kxr, uint8_t **body, uint32_t *blen,
                     xrdc_status *st);

/* ============================================================================
 * Connection manager + resilient open files (M3)
 *
 * xrdc_mgr owns the loop and a small pool of attached connections; metadata calls
 * round-robin across them (transparently surviving reconnects when retry_safe).
 * xrdc_mfile is an open file that survives a connection drop: on a transport
 * failure or a stale handle it reopens (fresh fhandle, NON-destructively — never
 * re-truncating) and re-issues the read/write at the same absolute offset (which
 * is idempotent), so a mid-transfer cat/dd survives a server restart with no EIO.
 * ==========================================================================*/

typedef struct xrdc_mgr   xrdc_mgr;
typedef struct xrdc_mfile xrdc_mfile;

/* Create the loop + `nconns` attached connections to `u` (opts `o`, may be NULL),
 * each with the given resilience policy. NULL + st on failure. */
xrdc_mgr *xrdc_mgr_create(const xrdc_url *u, const xrdc_opts *o, int nconns,
                          int max_stall_ms, int keepalive_ms, int max_retries,
                          xrdc_status *st);
void      xrdc_mgr_destroy(xrdc_mgr *m);
/* Round-robin one of the pool's connections (for a new file or a metadata op). */
xrdc_aconn *xrdc_mgr_pick(xrdc_mgr *m);
/* Issue a metadata/path request over a pooled connection. retry_safe=1 for
 * idempotent ops (stat/dirlist/query/...) so they survive a reconnect. */
int xrdc_mgr_call(xrdc_mgr *m, const void *hdr24, const void *payload,
                  uint32_t plen, int retry_safe, uint16_t *kxr,
                  uint8_t **body, uint32_t *blen, xrdc_status *st);

/* Open a file on connection `ac` (e.g. from xrdc_mgr_pick). writable selects
 * read vs write/update; force is the tri-state from xrdc_file_open_opaque
 * (1=truncate, 0=create-excl, 2=update-in-place; ignored when !writable). opaque
 * may be NULL. NULL + st on failure. */
xrdc_mfile *xrdc_mfile_open(xrdc_aconn *ac, const char *path, int writable,
                            int force, int posc, const char *opaque,
                            int max_stall_ms, int max_retries, xrdc_status *st);
/* Read/write at an absolute offset; both transparently reopen + resume across a
 * connection drop. pread returns bytes read (0=EOF) or -1; pwrite 0 / -1. */
ssize_t xrdc_mfile_pread(xrdc_mfile *mf, int64_t off, void *buf, size_t len,
                         xrdc_status *st);
int     xrdc_mfile_pwrite(xrdc_mfile *mf, int64_t off, const void *buf,
                          size_t len, xrdc_status *st);
int     xrdc_mfile_sync(xrdc_mfile *mf, xrdc_status *st);
int     xrdc_mfile_close(xrdc_mfile *mf, xrdc_status *st);

#endif /* XRDC_AIO_H */
