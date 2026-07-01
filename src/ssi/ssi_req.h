#ifndef XROOTD_SSI_REQ_H
#define XROOTD_SSI_REQ_H

/*
 * ssi_req.h — the per-reqId SSI request state (pure data type).
 *
 * WHAT: xrootd_ssi_req_t, one slot in a session's rrtable (see session.h).
 * WHY:  kept free of nginx headers so the session/RRTable logic is unit-testable
 *       standalone; the nginx-bound hooks live in ssi.h/ssi.c.
 * HOW:  the only nginx type referenced is ngx_pool_t (an opaque pointer here);
 *       standalone unit tests forward-declare it via SSI_UT_STANDALONE.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef SSI_UT_STANDALONE
typedef struct ngx_pool_s ngx_pool_t;   /* opaque in unit tests */
#else
#include <ngx_config.h>
#include <ngx_core.h>
#endif

#include "respbuf.h"        /* xrootd_ssi_respbuf_t (growable response buffer) */

/* Per-reqId SSI request state; lives in the session's rrtable (session.h). */
typedef struct {
    uint32_t        req_id;            /* reqId from the RRInfo (slot key) */
    unsigned        in_use:1;          /* slot occupied */

    unsigned char  *req;               /* accumulated request bytes */
    size_t          req_len;
    size_t          req_expected;      /* total request size from the RRInfo */
    unsigned        have_size:1;       /* req_expected is known */
    unsigned        dispatched:1;      /* service has been invoked */

    xrootd_ssi_respbuf_t resp;         /* response bytes (responder-filled, grows) */
    unsigned char  *meta;              /* metadata bytes (responder-filled) */
    size_t          meta_len;
    size_t          read_cursor;       /* kXR_read stream position */

    int             err_code;          /* SSI error code (0 = none) */
    char            err_text[128];
    unsigned        error:1;
    unsigned        responded:1;       /* response (or error) is ready */
    unsigned        streaming:1;       /* service delivered multi-chunk (read-pull) */

    unsigned        deferred:1;        /* service will respond later (async push) */
    unsigned        waiting:1;         /* kXR_waitresp sent; client awaits a push */
    unsigned char   defer_streamid[2]; /* streamid of the submit, for asynresp */
    void           *defer_ctx;         /* async timer/job state (nginx side; opaque) */
    void           *svc_state;         /* service-private per-request cookie
                                        * (survives submit→completion; e.g. the
                                        * CTA queue entry) */
    size_t          response_max;      /* per-response cap (0 = compile default) */

    ngx_pool_t     *pool;              /* connection pool for responder allocs */
} xrootd_ssi_req_t;

#endif /* XROOTD_SSI_REQ_H */
