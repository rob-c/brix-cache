#ifndef BRIX_FS_BACKEND_HTTP_SD_HTTP_INTERNAL_H
#define BRIX_FS_BACKEND_HTTP_SD_HTTP_INTERNAL_H

/*
 * sd_http_internal.h — driver-private layout for the HTTP-origin driver.
 *
 * The per-endpoint + per-export instance state (a ranked, health-scored set of
 * origin endpoints) is shared by the selection/IO path (sd_http.c) and the
 * T19/T20 introspection API (sd_http_introspect.c).  Driver-private: not part of
 * the sd_http public surface (sd_http.h).
 */

#include "sd_http.h"            /* SD_HTTP_EP_MAX, brix_s3_transport_t, brix_sd_* */

#include <stdatomic.h>          /* _Atomic rank */

#define SD_HTTP_BASE_MAX   512                  /* URL base path prefix */
#define SD_HTTP_PATH_MAX   2048                 /* full URL path = base + key */
#define SD_HTTP_AUTH_MAX   4160                 /* "Authorization: Bearer <tok>\r\n" */

/* One ranked origin endpoint (phase-68 T11). fail_score is an integer EWMA of
 * transport failures (0 = healthy, decays 7/8 per outcome); rank is the
 * selection preference the T19 policies write (0 = most preferred). */
typedef struct {
    char  host[256];
    int   port;
    int   tls;
    char  base_path[SD_HTTP_BASE_MAX];
    int   fail_score;
    _Atomic int rank;                 /* T19 selection preference; relaxed */
} sd_http_endpoint;

/* Health breaks ties inside a rank; a preferred-but-sick endpoint is only
 * overridden after ~16 consecutive failures — preference is policy, health
 * is protection (phase-68 T19 contract). */
#define SD_HTTP_RANK_WEIGHT 4096

typedef struct {
    sd_http_endpoint             eps[SD_HTTP_EP_MAX];
    int                          n_eps;
    const brix_s3_transport_t *transport;
    void                        *tctx;
    int                          timeout_ms;
    void                       (*failover_note)(void);  /* T16 metric hook */
    void                       (*health_note)(const char *host, int port,
                                              int healthy);
    char                         last_origin[300]; /* "host:port" of the last
                                    endpoint that answered a read — display
                                    only ($cvmfs_origin); racy-by-design
                                    under concurrent fills. */
    int                          last_failover; /* 1 iff the last answering
                                    endpoint was NOT the first tried (a
                                    failover); pairs with last_origin.       */
    unsigned                     probe_tick;  /* half-open recovery probe clock */
    char                         auth_hdr[SD_HTTP_AUTH_MAX]; /* §14 bearer hdr or "" */
    ngx_log_t                   *log;         /* selection diagnostics (create-
                                    time log; the registry builds instances
                                    with the cycle log, which outlives any
                                    request/connection). */
    int                          cur_ep;      /* index of the endpoint that
                                    answered the last successful request, -1 =
                                    none yet. Written by fill threads without
                                    ordering (like last_origin): a duplicated
                                    or missed "origin switched" line under a
                                    concurrent-fill race is acceptable. */
} sd_http_inst_state;

/* 1 iff `inst` is an sd_http instance (defined in sd_http.c, beside the driver
 * struct it checks); guards the introspection accessors in sd_http_introspect.c. */
int sd_http_instance_is(const brix_sd_instance_t *inst);

#endif /* BRIX_FS_BACKEND_HTTP_SD_HTTP_INTERNAL_H */
