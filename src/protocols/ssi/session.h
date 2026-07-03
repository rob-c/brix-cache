#ifndef BRIX_SSI_SESSION_H
#define BRIX_SSI_SESSION_H

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

#include "ssi_req.h"    /* brix_ssi_req_t + ngx_pool_t (nginx-free under SSI_UT_STANDALONE) */
#include "provider.h"   /* brix_ssi_provider_t */

#define BRIX_SSI_MAX_INFLIGHT 8

typedef struct {
    char                   service[64];
    brix_ssi_provider_t  provider;
    ngx_pool_t            *pool;
    uint64_t               generation;  /* bumped each create; async-delivery guard key */
    uintptr_t              conn_id;     /* stable connection id for the registry */
    int                    max_inflight; /* runtime concurrency cap (0 = compile max) */
    size_t                 request_max;  /* per-request cap (0 = BRIX_SSI_REQ_MAX) */
    size_t                 response_max; /* per-response cap (0 = BRIX_SSI_RESP_MAX) */
    brix_ssi_req_t       rr[BRIX_SSI_MAX_INFLIGHT];
} brix_ssi_session_t;

/* Allocate a session bound to a service + resolved provider. pool may be NULL in
 * standalone unit tests (libc malloc is used). */
brix_ssi_session_t *brix_ssi_session_create(ngx_pool_t *pool,
    const char *service, size_t service_len, const brix_ssi_provider_t *provider);

/* Find the slot for req_id. create=1 allocates a free slot if absent (NULL if the
 * table is full); create=0 returns NULL if absent. */
brix_ssi_req_t *brix_ssi_session_req(brix_ssi_session_t *s,
    uint32_t req_id, int create);

/* Release the slot for req_id (idempotent). */
void brix_ssi_session_drop(brix_ssi_session_t *s, uint32_t req_id);

#endif /* BRIX_SSI_SESSION_H */
