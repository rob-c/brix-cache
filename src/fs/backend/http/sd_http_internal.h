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
#define SD_HTTP_REDIRECT_MAX 3                  /* origin 3xx hops per request */

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
    int                          put_checksum; /* #12: send Content-MD5 on the
                                    commit PUT so the origin validates the body
                                    and rejects a wire-corrupted upload (the
                                    outbound analogue of ingest s3_content_md5) */
    brix_sd_http_bearer_pt     bearer_provider; /* phase-104 D1: dynamic
                                    bearer supplier consulted on a 401 +
                                    WWW-Authenticate; NULL = no dance, the 401
                                    propagates. Set post-build through
                                    sd_http_set_bearer_provider. */
    void                        *bearer_ctx;   /* opaque provider context */
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
    int                *auth_failed;   /* out (may be NULL): set to 1 when the
                                          origin sent a 401 challenge and no
                                          bearer could be minted for it. Lets
                                          the read path tell "we failed to
                                          authenticate" (our problem) from
                                          "the origin refuses" (the client's). */
} sd_http_req_t;

/* One decided redirect hop (phase-104 D1.4). `carries_credential` records the
 * policy verdict — 1 only when the hop lands on the very same peer (host, port
 * and scheme) that answered — so the caller can drop the mutual-TLS client
 * certificate on the same terms the header block already dropped the bearer. */
typedef struct {
    char host[256];
    int  port;
    int  tls;
    char path[SD_HTTP_PATH_MAX];
    char hdrs[SD_HTTP_AUTH_MAX + 512];
    int  carries_credential;
} sd_http_redirect_t;

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

/* Redirect hop policy (sd_http_redirect.c). sd_http_redirect_is answers "is
 * this status a redirect we follow"; sd_http_redirect_next turns one
 * `Location:` into the next hop — 0 with *hop filled, or -1 when the Location
 * is one this driver refuses to chase (non-http(s), scheme-relative, relative,
 * a TLS→cleartext downgrade, or over-long). `extra_hdrs` is the header block
 * the current request used; hop->hdrs is the block for the NEXT one, with
 * every `Authorization:` line removed whenever the hop changes peer. */
int sd_http_redirect_is(int status);
int sd_http_redirect_next(const char *location, const sd_http_endpoint *from,
    const char *extra_hdrs, sd_http_redirect_t *hop);

/* PROPFIND XML seam (sd_http_dir.c): next start-tag in [p,end) whose LOCAL name
 * is `local`, namespace-prefix- and case-insensitive, skipping close/comment/PI
 * tags. Returns the '<' or NULL. The write path's resourcetype probe uses it so
 * "is this a collection?" is answered by one tag scanner in both readers. */
const char *sd_http_xml_open(const char *p, const char *end,
    const char *local);

/* Resource-type probe (sd_http_dir.c): PROPFIND Depth:0 on ONE key, answering
 * "does it exist, and is it a collection?" — 0 with *is_coll set, or -1 with
 * *err_out = ENOENT/EACCES/ENOTSUP/EIO. HTTP cannot distinguish a collection
 * from an empty object on a HEAD, so the stat slot (sd_http_read.c) and the
 * delete slot (sd_http_write.c) both go through this one probe rather than
 * guessing differently. `auth` is a resolved header line or NULL. */
int sd_http_probe_type(sd_http_inst_state *is, const char *key,
    const char *auth, const char *cert_pem, int *is_coll, int *err_out);

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
/* Namespace mutation (sd_http_write.c) — WebDAV MKCOL / MOVE. mkdir ignores mode
 * (a collection has no POSIX mode); rename composes an absolute Destination URI
 * and honours noreplace via the Overwrite header. Endpoint 0 only. */
ngx_int_t sd_http_mkdir(brix_sd_instance_t *inst, const char *path,
    mode_t mode);
ngx_int_t sd_http_rename(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace);
/* Credential-scoped namespace mutation (sd_http_write.c): the same MKCOL/MOVE/
 * DELETE as the plain slots, but presenting the requesting user's forwarded
 * credential (WLCG bearer → Authorization header; x509 proxy → mutual-TLS client
 * cert) to the origin instead of the static service credential — so the origin
 * authorizes the namespace op AS the end user, mirroring open_cred/staged_open_cred/
 * stat_cred (phase-70 §5.1). */
ngx_int_t sd_http_unlink_cred(brix_sd_instance_t *inst, const char *path,
    int is_dir, const brix_sd_cred_t *cred);
ngx_int_t sd_http_mkdir_cred(brix_sd_instance_t *inst, const char *path,
    mode_t mode, const brix_sd_cred_t *cred);
ngx_int_t sd_http_rename_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace, const brix_sd_cred_t *cred);

/* Directory-enumeration slots (sd_http_dir.c) — a WebDAV PROPFIND Depth:1 read
 * of the collection; opendir_cred presents the per-user credential. */
brix_sd_dir_t *sd_http_opendir(brix_sd_instance_t *inst, const char *path,
    int *err_out);
brix_sd_dir_t *sd_http_opendir_cred(brix_sd_instance_t *inst, const char *path,
    int *err_out, const brix_sd_cred_t *cred);
ngx_int_t sd_http_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out);
ngx_int_t sd_http_closedir(brix_sd_dir_t *d);

#endif /* BRIX_FS_BACKEND_HTTP_SD_HTTP_INTERNAL_H */
