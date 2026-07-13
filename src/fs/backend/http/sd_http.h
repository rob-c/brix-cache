#ifndef BRIX_SD_HTTP_H
#define BRIX_SD_HTTP_H

/*
 * sd_http.h — read-only HTTP(S) source storage driver (phase-63 C-4).
 *
 * WHAT: A capability-typed SD driver (CAP_RANGE_READ only; every write/dir/xattr
 *       slot NULL) that serves open/stat/pread/fstat/close against a plain
 *       HTTP(S) endpoint — `open` HEADs the URL for the size, `pread` issues a
 *       byte-Range GET. The sibling of the S3 `sd_remote` driver minus SigV4: it
 *       is the *generic* web source for the composable stack, so an export
 *       (`brix_storage_backend http://host:port/base`) or a read cache can reach
 *       any HTTP origin through the SAME driver→driver fill path C-1 uses for
 *       root:// — no bespoke per-scheme libcurl in the cache.
 *
 * HOW:  The actual HTTP is performed by an INJECTED transport vtable
 *       (`brix_s3_transport_t`, the shared one the S3 driver uses) — the module
 *       passes the server libcurl singleton (`brix_s3_origin_curl_transport`),
 *       so this driver carries no libcurl dependency itself. No kernel fd ⇒ reads
 *       are memory-served. Blocking; runs on the cache-fill / AIO worker thread.
 *       Instances + objects are malloc-owned (no nginx pool), worker-safe.
 *
 * AUTH: anonymous GET by default. When `bearer_token` is set (the §14 credential
 *       block, threaded through the registry), every HEAD/GET carries
 *       `Authorization: Bearer <token>` — the WLCG / SciTokens path. Per-open
 *       credentials (open_cred) additionally present the requesting USER: a WLCG
 *       bearer as the Authorization header (phase-2 T7), or an x509 proxy PEM as
 *       a mutual-TLS client certificate on the origin handshake (phase-70 §5.1
 *       GSI-over-https) when the injected transport implements request_cred.
 */

#include "fs/backend/sd.h"
#include "fs/backend/s3/sd_s3_transport.h"

/* Cap on the ranked endpoint set of one instance (phase-68 T11 failover:
 * mirrors CVMFS_SERVER_URL's ordered Stratum-1 list). */
#define SD_HTTP_EP_MAX 8

/* Default per-request origin I/O timeout (milliseconds) when cfg leaves it unset. */
#define BRIX_SD_HTTP_DEFAULT_TIMEOUT_MS 60000

/* One additional endpoint of a multi-origin instance (strings are copied). */
typedef struct {
    const char *host;
    int         port;
    int         tls;
    const char *base_path;
} brix_sd_http_ep_cfg_t;

/* Endpoint for one HTTP source instance. Strings are copied. `base_path` is the
 * URL path prefix ("" or "/dir"); a request key "/file" is appended to it.
 * host/port/tls/base_path describe endpoint 0 (the primary and the WRITE
 * target); `extra`/`n_extra` add ranked read-failover endpoints (phase-68). */
typedef struct {
    const char                  *host;        /* endpoint host */
    int                          port;
    int                          tls;         /* 1 = https */
    const char                  *base_path;   /* URL path prefix ("" or "/sub") */
    const brix_s3_transport_t *transport;   /* injected HTTP transport */
    void                        *tctx;        /* transport context (NULL for curl) */
    int                          timeout_ms;
    const char                  *bearer_token; /* §14: Authorization: Bearer, or NULL */
    const char                  *ca_path;      /* §14/C-3: operator trusted-CA file or
                                    hashed dir for origin TLS verification, or NULL
                                    for the system bundle. Copied into the instance
                                    and handed to the curl transport as its tctx so
                                    the https backend leg verifies a site/test-CA
                                    origin (phase-70). Ignored when tctx is set. */
    const brix_sd_http_ep_cfg_t *extra;      /* endpoints 1.. (may be NULL)   */
    int                            n_extra;    /* count of `extra` entries      */
    void                         (*failover_note)(void);  /* T16: called when a
                                    read fails over to an alternate endpoint
                                    (driver is ngx-free; the owner injects
                                    its metric hook). NULL = no accounting. */
    void                         (*health_note)(const char *host, int port,
                                    int healthy);  /* endpoint health-state
                                    TRANSITION (EWMA hysteresis: degraded at
                                    score>=128 after a failure, recovered
                                    below 128 after a success). The owner
                                    injects its logger. NULL = silent. */
} brix_sd_http_cfg_t;

/* Build a read-only HTTP source instance. Returns a malloc-owned instance, or NULL
 * (errno set). Destroy with brix_sd_http_destroy. */
brix_sd_instance_t *brix_sd_http_create(const brix_sd_http_cfg_t *cfg,
    ngx_log_t *log);

/* Free an instance built by brix_sd_http_create. NULL-safe. */
void brix_sd_http_destroy(brix_sd_instance_t *inst);

/* ---- T19/T20 selection + introspection (no-ops on non-http instances) ----
 * Effective pick score = rank*4096 + fail_score: preference is policy, health
 * is protection — a preferred-but-sick origin is overridden only after ~16
 * consecutive failures. Ranks are relaxed atomics (event loop writes, fill
 * threads read; a momentarily stale rank costs one suboptimal fill). */
/* Force-primary read policy (process-global; set pre-fork from the cvmfs merge
 * when brix_cvmfs_fill_retry_policy is force-primary). When on, every read
 * targets the rank-preferred endpoint and never fails over to an alternate on a
 * transport failure — the fill loop retries the same origin on a fresh
 * connection. Off (default) keeps T11 alternate-endpoint failover. */
void sd_http_force_primary_set(int on);

void sd_http_set_ranks(brix_sd_instance_t *inst, const int *ranks, int n);
int  sd_http_endpoint_list(brix_sd_instance_t *inst, char hosts[][256],
                           int *ports, int max);
int  sd_http_n_endpoints(brix_sd_instance_t *inst);
int  sd_http_last_origin(brix_sd_instance_t *inst, char *buf, size_t cap);
int  sd_http_last_was_failover(brix_sd_instance_t *inst);
int  sd_http_health_snapshot(brix_sd_instance_t *inst, char hosts[][256],
                             int *ports, int *scores, int max);

#endif /* BRIX_SD_HTTP_H */
