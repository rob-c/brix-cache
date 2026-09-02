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
    char                         tape_api[SD_HTTP_BASE_MAX]; /* WLCG Tape REST
                                    API base path ("/api/v1"), or "" when the
                                    operator configured none. Non-empty is the
                                    ONLY thing that arms BRIX_SD_CAP_NEARLINE —
                                    see sd_http_nearline.c on why the cap is an
                                    explicit opt-in and never inferred. */
    _Atomic int                  cond_probe;  /* C6 (phase-107 W7): does the
                                    write origin HONOUR RFC 7232 conditional
                                    PUT? 0 = not yet probed, 1 = answers 412,
                                    -1 = ignores the header (conditional
                                    publish then refuses ENOTSUP — sending a
                                    precondition an origin ignores would
                                    publish unconditionally, §3.5). Probed
                                    lazily by the first conditional commit
                                    (sd_http_write.c), never at init: a probe
                                    needs an authenticated PUT. */
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
    /* OPTIONAL request entity, borrowed for the life of the call. NULL/0 (the
     * value every positional initialiser above leaves here) sends no body, which
     * is what every method on this driver but a NAMED-PROP PROPFIND wants: an
     * empty PROPFIND is "allprop", and allprop does not carry live properties
     * outside RFC 4918 — the RFC 4331 quota pair among them. Replayed verbatim
     * on a redirect hop and on the mint-and-retry, so it must stay valid for the
     * whole sd_http_request_fo call, not just the first send. */
    const void         *body;
    size_t              body_len;
} sd_http_req_t;

/* Per-open object state: an HTTP origin has no kernel fd, so the export key and
 * the per-user credential resolved at open time ride in the object itself. Built
 * by the read path (sd_http_read.c); also read by the checksum-offload slot
 * (sd_http_digest.c), which re-probes the SAME key under the SAME identity. */
typedef struct {
    char key[SD_HTTP_PATH_MAX];    /* export-relative key (leading '/'); the
                                      full URL path is composed per endpoint */
    char auth_hdr[SD_HTTP_AUTH_MAX]; /* per-open "Authorization: Bearer <tok>\r\n"
                                      (Phase 2 T7); "" when the object should
                                      fall back to the instance's static
                                      is->auth_hdr (plain open, or a cred with
                                      no usable bearer). A COPY of the bearer
                                      bytes — cred->bearer is only borrowed for
                                      the duration of the open() call. */
    char cert_pem[SD_HTTP_PATH_MAX]; /* per-open TLS client-cert PATH (phase-70
                                      §5.1 GSI-over-https): the user's proxy PEM
                                      (chain+key) presented via mutual-TLS on
                                      each read. "" when the open carries no
                                      x509 cred. A COPY of cred->x509_proxy,
                                      which is only borrowed for the open call. */
} sd_http_obj_state;

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

/* One PROPFIND request's identity: the key, the resolved credential, the depth
 * ("0" = this resource, "1" = its children), whether the request is pinned to
 * the primary endpoint, and an OPTIONAL request body. Bundled so the shared
 * issue helper keeps a small parameter list; every field is immutable for the
 * life of the call, and a NULL `body` (what the positional initialisers in
 * sd_http_dir.c leave) is the allprop spelling. Declared here rather than in
 * sd_http_dir.c because the RFC-4331 quota reader (sd_http_space.c) is a third
 * PROPFIND caller and must ask in exactly the same wire spelling as the other
 * two. */
typedef struct {
    const char *key;
    const char *auth;        /* resolved "Authorization: …\r\n" line, or NULL */
    const char *cert_pem;
    int         depth;
    int         force_primary;
    const char *body;        /* NUL-terminated request XML, or NULL = allprop */
} sd_http_pf_t;

/* Send ONE PROPFIND and hand back a usable 207 (sd_http_dir.c). 0 with `resp`
 * holding a body the caller must resp_free, or -1 with *err_out set and the
 * response already freed. */
int sd_http_propfind_issue(sd_http_inst_state *is, const sd_http_pf_t *pf,
    brix_s3_resp_t *resp, int *err_out);

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
/* Vectored read coalesced into ONE range GET (kXR_readv / pgread batches) — see
 * sd_http_read.c. Without it the generic fallback issues one GET per iovec. */
ssize_t   sd_http_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
              off_t off);
ngx_int_t sd_http_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out);
ngx_int_t sd_http_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out);
ngx_int_t sd_http_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred);

/* Checksum-offload vtable slot (sd_http_digest.c): one HEAD carrying a
 * `Want-Digest:` for the requested algorithm, answered from the origin's
 * RFC-3230 `Digest:` reply header. */
ngx_int_t sd_http_query_checksum(brix_sd_obj_t *obj, const char *algo,
    char *hex_out, size_t hex_sz);

/* Space-report vtable slot (sd_http_space.c): the ORIGIN's RFC-4331 quota pair
 * (`DAV:quota-available-bytes` / `DAV:quota-used-bytes`) over one Depth:0
 * PROPFIND on the export root, so kXR_statvfs/kXR_Qspace/kXR_QFSinfo/SRR report
 * the backend's capacity rather than the statvfs(2) of the gateway's own —
 * usually empty — export directory. NGX_ERROR on anything the origin does not
 * answer, so the caller falls back to that local statvfs. */
ngx_int_t sd_http_space(brix_sd_instance_t *inst, brix_sd_space_t *out);

/* Write-path vtable slots (sd_http_write.c), referenced by the driver struct. */
brix_sd_staged_t *sd_http_staged_open(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, off_t declared_size, int *err_out);
brix_sd_staged_t *sd_http_staged_open_cred(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, off_t declared_size,
    const brix_sd_cred_t *cred, int *err_out);
ssize_t   sd_http_staged_write(brix_sd_staged_t *h, const void *buf,
    size_t len, off_t off);
ngx_int_t sd_http_staged_commit(brix_sd_staged_t *h, brix_sd_precond_t *pre);
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

/* Server-side copy (sd_http_mutate.c) — WebDAV COPY (RFC 4918 §9.8), the same
 * absolute-Destination request MOVE uses. The duplicate is made INSIDE the
 * origin, so an intra-origin copy no longer drags the whole object down to this
 * host and straight back up. Overwrite: T — the no-clobber gate belongs to the
 * VFS pre-stat, not to a second refusal here. `bytes_out` is a best-effort
 * follow-up stat (COPY reports no byte count), 0 when it cannot confirm a size.
 * The _cred variant authorizes BOTH legs as the requesting user. */
ngx_int_t sd_http_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out);
ngx_int_t sd_http_server_copy_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, const brix_sd_cred_t *cred);

/* One namespace-mutation request (DELETE/MKCOL/MOVE/COPY/PROPPATCH) on endpoint
 * 0: the verb, the endpoint-0 absolute path, the already-resolved header block
 * (Authorization plus any Destination/Overwrite/Content-Type lines), the per-user
 * x509 proxy or NULL, and an OPTIONAL entity body — PROPPATCH is the one namespace
 * verb that carries one. Bundled so the sender keeps a small parameter list and so
 * the xattr file (sd_http_xattr.c) sends its bodied PROPPATCH through the SAME
 * no-failover sender the other mutations use, rather than opening a second one. */
typedef struct {
    const char *method;
    const char *path;
    const char *hdrs;
    const char *cert_pem;    /* per-user proxy PEM, or NULL = service identity */
    const void *body;        /* request entity, or NULL = none */
    size_t      body_len;
} sd_http_ns_req_t;

/* Send ONE namespace mutation (sd_http_mutate.c) on endpoint 0 — never failing
 * over, because replaying a mutation against a second endpoint could apply it
 * twice. 0 on a transport round trip (inspect `resp->status`), non-zero with
 * `errbuf` set on a transport failure. */
int sd_http_ns_send(sd_http_inst_state *is, const sd_http_ns_req_t *rq,
    brix_s3_resp_t *resp, char *errbuf, size_t errcap);

/* The WebDAV mutation status->errno verdict (sd_http_mutate.c): 401/403 -> EACCES,
 * 404/409 -> ENOENT, 405/412 -> EEXIST, anything else -> EIO. Shared so the property
 * writer (sd_http_xattr.c) overrides only the codes whose MEANING differs there,
 * instead of restating the common half. */
int sd_http_status_to_errno(long status);

/* Extended-attribute vtable slots (sd_http_xattr.c) — WebDAV dead properties
 * (RFC 4918 §15) read with a named-prop PROPFIND Depth:0 and written with
 * PROPPATCH. Each xattr name maps to one element in the BriX xattr namespace,
 * and both name and value travel hex-encoded, so an arbitrary binary value (or
 * one containing XML metacharacters) cannot inject markup into the request. The
 * _cred twins authorize as the requesting user, like every other _cred slot. */
ssize_t   sd_http_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t bufsz);
ssize_t   sd_http_getxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t bufsz, const brix_sd_cred_t *cred);
ssize_t   sd_http_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t bufsz);
ssize_t   sd_http_listxattr_cred(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t bufsz, const brix_sd_cred_t *cred);
ngx_int_t sd_http_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *value, size_t len, int flags);
ngx_int_t sd_http_setxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *value, size_t len, int flags,
    const brix_sd_cred_t *cred);
ngx_int_t sd_http_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name);
ngx_int_t sd_http_removexattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const brix_sd_cred_t *cred);

/* Advisory POSIX metadata (sd_http_setattr.c) — WebDAV gives a resource no mode,
 * no owner and no settable mtime, so kXR_chmod/kXR_setattr is persisted as the
 * reserved dead property every object backend shares and overlaid on stat. The
 * _cred twin authorizes the property write as the requesting user, for the same
 * reason setxattr_cred does. */
ngx_int_t sd_http_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr);
ngx_int_t sd_http_setattr_cred(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr, const brix_sd_cred_t *cred);

/* Nearline (tape/MSS) slots (sd_http_nearline.c) — the WLCG Tape REST API:
 * `archiveinfo` classifies a path without touching the tape system (residency),
 * `stage` queues the recall. Reachable only on an instance carrying
 * BRIX_SD_CAP_NEARLINE, which sd_http_tape_init arms from the operator's
 * configured API base — the cap is a contract the composing registry enforces
 * (a nearline backend REQUIRES a cache tier in front), never an inference. */
ngx_int_t sd_http_residency(brix_sd_instance_t *inst, const char *key,
    brix_sd_residency_t *out);
ngx_int_t sd_http_recall(brix_sd_instance_t *inst, const char *key,
    char reqid_out[40]);
ngx_int_t sd_http_recall_cred(brix_sd_instance_t *inst, const char *key,
    const brix_sd_cred_t *cred, char reqid_out[40]);
int       sd_http_tape_init(sd_http_inst_state *is, const char *base);

/* Directory-enumeration slots (sd_http_dir.c) — a WebDAV PROPFIND Depth:1 read
 * of the collection; opendir_cred presents the per-user credential. */
brix_sd_dir_t *sd_http_opendir(brix_sd_instance_t *inst, const char *path,
    int *err_out);
brix_sd_dir_t *sd_http_opendir_cred(brix_sd_instance_t *inst, const char *path,
    int *err_out, const brix_sd_cred_t *cred);
ngx_int_t sd_http_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out);
ngx_int_t sd_http_closedir(brix_sd_dir_t *d);

#endif /* BRIX_FS_BACKEND_HTTP_SD_HTTP_INTERNAL_H */
