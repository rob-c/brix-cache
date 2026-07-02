#ifndef XROOTD_SSI_SESSION_H
#define XROOTD_SSI_SESSION_H

/*
 * session.h — SSI session + RRTable.
 *
 * WHAT: one open "/.ssi/<service>" handle becomes a session multiplexing many
 *       concurrent requests, each keyed by the reqId carried in the RRInfo.
 * WHY:  real libXrdSsi clients pipeline several requests on one resource handle.
 * HOW:  a fixed-size table of per-reqId request slots; find-or-create on write,
 *       lookup on query/read, drop on cancel/complete. Pool-allocated under the
 *       connection pool so teardown is automatic.
 *
 * Standalone unit tests compile this file with -DSSI_UT_STANDALONE and a libc
 * malloc/free shim instead of the nginx pool.
 */

#include <stddef.h>
#include <stdint.h>

#include "ssi_req.h"    /* xrootd_ssi_req_t + ngx_pool_t (nginx-free under SSI_UT_STANDALONE) */
#include "provider.h"   /* xrootd_ssi_provider_t */

#define XROOTD_SSI_MAX_INFLIGHT 8

typedef struct {
    char                   service[64];
    xrootd_ssi_provider_t  provider;
    ngx_pool_t            *pool;
    uint64_t               generation;  /* bumped each create; async-delivery guard key */
    uintptr_t              conn_id;     /* stable connection id for the registry */
    int                    max_inflight; /* runtime concurrency cap (0 = compile max) */
    size_t                 request_max;  /* per-request cap (0 = XROOTD_SSI_REQ_MAX) */
    size_t                 response_max; /* per-response cap (0 = XROOTD_SSI_RESP_MAX) */
    xrootd_ssi_req_t       rr[XROOTD_SSI_MAX_INFLIGHT];
} xrootd_ssi_session_t;

/* Allocate a session bound to a service + resolved provider. pool may be NULL in
 * standalone unit tests (libc malloc is used). */
xrootd_ssi_session_t *xrootd_ssi_session_create(ngx_pool_t *pool,
    const char *service, size_t service_len, const xrootd_ssi_provider_t *provider);

/* Find the slot for req_id. create=1 allocates a free slot if absent (NULL if the
 * table is full); create=0 returns NULL if absent. */
xrootd_ssi_req_t *xrootd_ssi_session_req(xrootd_ssi_session_t *s,
    uint32_t req_id, int create);

/* Release the slot for req_id (idempotent). */
void xrootd_ssi_session_drop(xrootd_ssi_session_t *s, uint32_t req_id);

#endif /* XROOTD_SSI_SESSION_H */
