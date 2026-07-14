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
    char                         ca_path[1024]; /* §14/C-3 operator trusted CA (file
                                    or hashed dir) for origin TLS; "" = system
                                    bundle. Handed to the curl transport as its
                                    tctx (phase-70 https backend leg). */
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

/* Per-request state threaded through the failover helpers so each stays under
 * the parameter cap and reads as one nameable step. Carries the immutable
 * request identity (method/key/headers/cert) plus the resp out-slot; the
 * mutable selection state (current/first endpoint) rides in locals. Defined
 * here because both the selection/failover path (sd_http_select.c) and the read
 * path (sd_http_read.c) construct it. */
typedef struct {
    sd_http_inst_state *is;
    const char         *method;
    const char         *key;
    const char         *extra_hdrs;
    const char         *cert_pem;
    brix_s3_resp_t     *resp;
    int                 force_primary;
} sd_http_req_t;

/* 1 iff `inst` is an sd_http instance (defined in sd_http.c, beside the driver
 * struct it checks); guards the introspection accessors in sd_http_introspect.c. */
int sd_http_instance_is(const brix_sd_instance_t *inst);

/* ---- Cross-file entry points (phase-79 file-size split) -------------------
 *
 * The driver was split into four translation units around one concept each:
 *   sd_http.c          — driver vtable + instance create/destroy
 *   sd_http_select.c   — endpoint selection, health scoring, read failover
 *   sd_http_read.c     — HEAD/GET read path + credential resolution
 *   sd_http_write.c    — staged whole-object PUT + DELETE write path
 * The symbols below are the seams between them (defined in one, called from
 * another); everything else stays file-private. */

/* Process-global force-primary read toggle (defined in sd_http_select.c beside
 * its setter; read by the read path when composing a request). See
 * sd_http_force_primary_set() in sd_http.h. */
extern int g_sd_http_force_primary;

/* Selection + one-alternate read failover (sd_http_select.c). sd_http_write_path
 * composes the endpoint-0 write-target URL path (writes never fail over). */
void sd_http_write_path(const sd_http_inst_state *is, const char *key,
    char *dst, size_t cap);
int  sd_http_request_fo(const sd_http_req_t *rq, sd_http_endpoint **used);

/* Per-open credential resolution shared by the read and write legs — cred_gate
 * refuses a proxy-only cred the transport cannot present in deny mode;
 * resolve_open_cred turns a cred into a bearer header line + x509 cert path
 * (defined in sd_http_read.c, also called from sd_http_write.c). */
int         sd_http_cred_gate(sd_http_inst_state *is,
    const brix_sd_cred_t *cred);
const char *sd_http_resolve_open_cred(sd_http_inst_state *is,
    const brix_sd_cred_t *cred, char *open_auth, size_t auth_cap);

/* Read-path vtable slots (sd_http_read.c), referenced by the driver struct. */
brix_sd_obj_t *sd_http_open(brix_sd_instance_t *inst, const char *path,
    int sd_flags, mode_t mode, int *err_out);
brix_sd_obj_t *sd_http_open_cred(brix_sd_instance_t *inst, const char *path,
    int sd_flags, mode_t mode, const brix_sd_cred_t *cred, int *err_out);
ngx_int_t sd_http_close(brix_sd_obj_t *obj);
ssize_t   sd_http_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off);
ngx_int_t sd_http_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out);
ngx_int_t sd_http_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out);
ngx_int_t sd_http_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred);

/* Write-path vtable slots (sd_http_write.c), referenced by the driver struct. */
brix_sd_staged_t *sd_http_staged_open(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, int *err_out);
brix_sd_staged_t *sd_http_staged_open_cred(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, const brix_sd_cred_t *cred,
    int *err_out);
ssize_t   sd_http_staged_write(brix_sd_staged_t *h, const void *buf,
    size_t len, off_t off);
ngx_int_t sd_http_staged_commit(brix_sd_staged_t *h, int noreplace);
void      sd_http_staged_abort(brix_sd_staged_t *h);
ngx_int_t sd_http_unlink(brix_sd_instance_t *inst, const char *path,
    int is_dir);

#endif /* BRIX_FS_BACKEND_HTTP_SD_HTTP_INTERNAL_H */
