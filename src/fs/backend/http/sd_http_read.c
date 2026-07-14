/*
 * sd_http_read.c — read path for the HTTP-origin storage driver.
 *
 * WHAT: The read-facing vtable slots — open/open_cred (HEAD the URL for its
 *       size, build a memory-served object shell), close, pread (byte-Range
 *       GET, slicing a whole-object 200 response so the fill loop terminates
 *       against a Range-ignoring origin), fstat, stat/stat_cred — plus the
 *       per-open credential resolution (bearer header + x509 client-cert path)
 *       the write leg (sd_http_write.c) shares.
 *
 * WHY:  Split out of sd_http.c (phase-79 file-size split): the read/credential
 *       path is one concept, distinct from selection/failover (sd_http_select.c),
 *       the write path (sd_http_write.c), and the driver vtable/lifecycle
 *       (sd_http.c). Every request goes through sd_http_request_fo (select.c),
 *       which owns endpoint choice + failover.
 *
 * HOW:  cred_gate + resolve_open_cred compute the presented identity once, so
 *       the HEAD size probe and the following reads authenticate identically;
 *       the identity travels as per-object state (no kernel fd / session on an
 *       HTTP origin). sd_http_cred_gate / sd_http_resolve_open_cred are exported
 *       (sd_http_internal.h) because the staged-write leg presents the SAME
 *       identity at commit.
 */

#include "sd_http_internal.h"    /* endpoint + inst_state + req_t layout */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define SD_HTTP_PREAD_MAX  (8LL * 1024 * 1024)

/* Per-open object state: an HTTP origin has no kernel fd, so the export key and
 * the per-user credential resolved at open time ride in the object itself. */
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

/* HEAD `key` → *size_out (−1 if no Content-Length). 0, or −1 with errno.
 * `auth_hdr`/`cert_pem` carry the per-open credential (bearer header and/or
 * GSI proxy client-cert path) so the size probe authenticates as the same
 * identity the following reads use; NULL/"" fall back to the instance static. */
static int
sd_http_head_size(sd_http_inst_state *is, const char *key,
    const char *auth_hdr, const char *cert_pem, int64_t *size_out)
{
    brix_s3_resp_t resp;
    char             cl[32];
    sd_http_req_t    rq = { is, "HEAD", key, auth_hdr, cert_pem, &resp,
                            g_sd_http_force_primary };

    if (sd_http_request_fo(&rq, NULL) != 0)
    {
        return -1;                              /* errno = EIO */
    }
    if (resp.status == 404) {
        is->transport->resp_free(&resp);
        errno = ENOENT;
        return -1;
    }
    if (resp.status != 200) {
        is->transport->resp_free(&resp);
        errno = (resp.status == 403 || resp.status == 401) ? EACCES : EIO;
        return -1;
    }
    if (is->transport->resp_header(&resp, "Content-Length", cl, sizeof(cl)) == 0) {
        *size_out = (int64_t) strtoll(cl, NULL, 10);
    } else {
        *size_out = -1;
    }
    is->transport->resp_free(&resp);
    return 0;
}

/* sd_http_cred_gate — decide whether a proxy-only x509 credential is presentable
 * to this HTTP origin, and refuse in deny mode when it is not.
 *
 * WHAT: An x509-proxy cred over an https backend leg is presented as a mutual-TLS
 *       client cert (phase-70 §5.1) — but ONLY if the injected transport can do
 *       so (it implements request_cred). Returns 0 when the open may proceed,
 *       -1 (errno=EACCES) when a deny-mode proxy cred cannot be presented.
 * WHY:  fallback_deny forbids silently serving a per-user request on the
 *       anonymous/service credential. If the user presented ONLY an x509 proxy
 *       (no bearer) and the transport cannot mutual-TLS, presenting it is
 *       impossible; deny rather than leak onto anonymous access.
 * HOW:  Only fires for a cred whose sole credential is x509_proxy (no bearer).
 *       When the transport lacks request_cred and deny is set → EACCES. A usable
 *       transport, a bearer-carrying cred, or allow-mode all return 0 (proceed;
 *       the open then wires whatever it can). */
int
sd_http_cred_gate(sd_http_inst_state *is, const brix_sd_cred_t *cred)
{
    int has_bearer;
    int has_proxy;

    if (cred == NULL) {
        return 0;
    }
    has_bearer = (cred->bearer != NULL && cred->bearer[0] != '\0');
    has_proxy  = (cred->x509_proxy != NULL && cred->x509_proxy[0] != '\0');
    if (has_bearer || !has_proxy) {
        return 0;                       /* bearer path, or no per-user cred    */
    }
    if (is->transport->request_cred == NULL && cred->fallback_deny) {
        errno = EACCES;                 /* proxy-only + can't mutual-TLS + deny */
        return -1;
    }
    return 0;
}

/* sd_http_resolve_open_cred — resolve a `cred` into the per-open bearer header
 * and x509 client-cert path used for both the HEAD probe and later reads.
 *
 * WHAT: Writes the "Authorization: Bearer <tok>\r\n" line into `open_auth`
 *       (empty when no usable bearer) and returns the x509 proxy PATH (NULL
 *       when none / the transport cannot present a client cert).
 * WHY:  The size probe and the object's reads must present the SAME identity;
 *       resolving once here keeps them consistent for an origin that authorizes
 *       per-object. cred==NULL leaves auth empty → fall back to the static.
 * HOW:  Bearer → snprintf into open_auth; x509 proxy → return cred->x509_proxy
 *       only when request_cred is available (both are borrowed, copied later). */
const char *
sd_http_resolve_open_cred(sd_http_inst_state *is, const brix_sd_cred_t *cred,
    char *open_auth, size_t auth_cap)
{
    open_auth[0] = '\0';
    if (cred == NULL) {
        return NULL;
    }
    if (cred->bearer != NULL && cred->bearer[0] != '\0') {
        snprintf(open_auth, auth_cap, "Authorization: Bearer %s\r\n",
                 cred->bearer);
    }
    if (cred->x509_proxy != NULL && cred->x509_proxy[0] != '\0'
        && is->transport->request_cred != NULL)
    {
        return cred->x509_proxy;
    }
    return NULL;
}

/* Resolved per-open result threaded into sd_http_build_obj: the credential the
 * object copies into its own buffers plus the size the HEAD probe returned. */
typedef struct {
    const char *open_auth;   /* bearer header line ("" = none) */
    const char *open_cert;   /* x509 client-cert PATH (NULL = none) */
    int64_t     size;        /* HEAD Content-Length (−1 if unknown) */
} sd_http_open_result_t;

/* sd_http_build_obj — allocate + populate the memory-served object shell.
 *
 * WHAT: Allocates the per-open object state and shell, copies the key and the
 *       resolved per-open credential (bearer header / cert path) into the
 *       object's own buffers, and fills the stat snapshot. NULL + *err_out on
 *       allocation failure.
 * HOW:  calloc both, COPY key/open_auth/open_cert into st (cred fields were only
 *       borrowed), wire the read-only regular-file snapshot. No kernel fd. */
static brix_sd_obj_t *
sd_http_build_obj(brix_sd_instance_t *inst, const char *path,
    const sd_http_open_result_t *res, int *err_out)
{
    sd_http_obj_state *st  = calloc(1, sizeof(*st));
    brix_sd_obj_t     *obj = calloc(1, sizeof(*obj));

    if (st == NULL || obj == NULL) {
        free(st);
        free(obj);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    snprintf(st->key, sizeof(st->key), "%s",
             (path != NULL && path[0]) ? path : "/");
    if (res->open_auth[0] != '\0') {
        snprintf(st->auth_hdr, sizeof(st->auth_hdr), "%s", res->open_auth);
    }
    if (res->open_cert != NULL) {
        snprintf(st->cert_pem, sizeof(st->cert_pem), "%s", res->open_cert);
    }

    obj->driver     = inst->driver;
    obj->inst       = inst;
    obj->fd         = NGX_INVALID_FILE;     /* no kernel fd — memory-served */
    obj->state      = st;
    obj->heap_shell = 1;
    obj->snap.size  = (off_t) res->size;
    obj->snap.mode  = S_IFREG | 0444;
    obj->snap.is_reg = 1;
    return obj;
}

/* The open-request quartet the vtable slots hand to the shared open path,
 * bundled so the common helper stays under the parameter cap. `cred` is NULL
 * for the plain (service/anonymous) slot, non-NULL for the per-user slot. */
typedef struct {
    const char             *path;
    int                     sd_flags;
    mode_t                  mode;
    const brix_sd_cred_t   *cred;
} sd_http_open_req_t;

/* sd_http_open_common — shared open path for the plain and credential-scoped
 * open slots.
 *
 * WHAT: HEADs `req->path` for its size and builds the per-open object. A `cred`
 *       with a usable bearer token sets the object's auth_hdr; a `cred` with an
 *       x509 proxy (a PEM chain+key path) sets the object's cert_pem so
 *       subsequent reads present that identity — the bearer via an Authorization
 *       header, the proxy via a mutual-TLS client cert on the origin handshake.
 * WHY:  Phase 2 T7 (bearer) + phase-70 §5.1 (x509) per-user backend credentials
 *       — an HTTP-origin driver has no kernel fd / session to re-scope per user,
 *       so the per-user identity travels as per-object state copied at open time.
 * HOW:  Refuse write intent; gate the cred; resolve it once (helper); HEAD the
 *       size with the SAME identity; then build the object (helper). Exactly one
 *       cred kind is ever set (the VFS gate populates one of bearer/x509_proxy). */
static brix_sd_obj_t *
sd_http_open_common(brix_sd_instance_t *inst, const sd_http_open_req_t *req,
    int *err_out)
{
    sd_http_inst_state *is = inst->state;
    int64_t             size = 0;
    char                open_auth[SD_HTTP_AUTH_MAX];
    const char         *open_cert;

    (void) req->mode;

    /* Read-only source: refuse any write/create/trunc intent. */
    if (req->sd_flags & (BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC
                    | BRIX_SD_O_APPEND))
    {
        if (err_out) { *err_out = EROFS; }
        return NULL;
    }

    if (sd_http_cred_gate(is, req->cred) != 0) {
        if (err_out) { *err_out = errno; }
        return NULL;
    }

    open_cert = sd_http_resolve_open_cred(is, req->cred, open_auth,
                                          sizeof(open_auth));

    if (sd_http_head_size(is, req->path,
                          open_auth[0] ? open_auth
                                       : (is->auth_hdr[0] ? is->auth_hdr : NULL),
                          open_cert, &size) != 0)
    {
        if (err_out) { *err_out = errno; }
        return NULL;
    }

    sd_http_open_result_t res = { open_auth, open_cert, size };
    return sd_http_build_obj(inst, req->path, &res, err_out);
}

/* sd_http_open — vtable open slot: service credential / anonymous.
 *
 * WHAT: Plain open for callers that do not carry a per-user credential.
 * WHY:  Preserves the existing public vtable signature; passes cred=NULL so
 *       the object falls back to the instance's static bearer_token header.
 * HOW:  Delegates to sd_http_open_common with cred=NULL. */
brix_sd_obj_t *
sd_http_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_http_open_req_t req = { path, sd_flags, mode, NULL };

    return sd_http_open_common(inst, &req, err_out);
}

/* sd_http_open_cred — vtable open_cred slot: per-user bearer-token credential.
 *
 * WHAT: Credential-scoped open that presents the requesting user's WLCG
 *       bearer token to the origin instead of the static service token.
 * WHY:  Phase 2 T7 — an HTTP/WebDAV/cvmfs origin authenticates purely on the
 *       Authorization header, so per-user auth is a per-open header swap.
 * HOW:  Delegates to sd_http_open_common with the supplied cred; the common
 *       path copies cred->bearer into the object's own auth_hdr buffer. */
brix_sd_obj_t *
sd_http_open_cred(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    sd_http_open_req_t req = { path, sd_flags, mode, cred };

    return sd_http_open_common(inst, &req, err_out);
}

ngx_int_t
sd_http_close(brix_sd_obj_t *obj)
{
    if (obj != NULL && obj->state != NULL) {
        free(obj->state);
        obj->state = NULL;
    }
    return NGX_OK;
}

ssize_t
sd_http_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_http_inst_state *is = obj->inst->state;
    sd_http_obj_state  *st = obj->state;
    brix_s3_resp_t    resp;
    char                hdrs[SD_HTTP_AUTH_MAX + 80];
    const void         *body;
    const char         *auth_hdr;
    size_t              blen = 0, n;
    int64_t             end;

    if (len == 0) {
        return 0;
    }
    if (len > (size_t) SD_HTTP_PREAD_MAX) {
        len = (size_t) SD_HTTP_PREAD_MAX;
    }
    end = (int64_t) off + (int64_t) len - 1;
    /* Phase 2 T7: a per-open bearer (open_cred) wins over the instance's
     * static bearer_token; "" (plain open, or no usable cred) falls back.
     * Phase-70 §5.1: a per-open x509 proxy path (st->cert_pem) is presented as
     * the mutual-TLS client cert on the read — orthogonal to the bearer header
     * (the VFS gate sets exactly one of the two). */
    auth_hdr = st->auth_hdr[0] ? st->auth_hdr : is->auth_hdr;
    snprintf(hdrs, sizeof(hdrs), "Range: bytes=%lld-%lld\r\n%s",
             (long long) off, (long long) end, auth_hdr);

    sd_http_req_t rq = { is, "GET", st->key, hdrs,
                         st->cert_pem[0] ? st->cert_pem : NULL, &resp,
                         g_sd_http_force_primary };
    if (sd_http_request_fo(&rq, NULL) != 0) {
        return -1;                              /* errno = EIO */
    }
    if (resp.status == 416) {
        is->transport->resp_free(&resp);
        return 0;                              /* range past EOF → EOF (0) */
    }
    if (resp.status != 206 && resp.status != 200) {
        is->transport->resp_free(&resp);
        errno = (resp.status == 404) ? ENOENT : EIO;
        return -1;
    }
    body = is->transport->resp_body(&resp, &blen);
    if (body == NULL || blen == 0) {
        is->transport->resp_free(&resp);
        return 0;                              /* EOF / empty range */
    }

    /* 206 → body is exactly the requested range, starting at `off`. 200 → the
     * origin ignored the Range header and returned the WHOLE object from byte 0
     * (stock python http.server, some proxies), so the bytes we want begin at
     * `off` within `body`; past EOF that is a short read of 0. Slicing here keeps
     * a correct, terminating fill loop against either kind of origin. */
    if (resp.status == 200) {
        if ((size_t) off >= blen) {
            is->transport->resp_free(&resp);
            return 0;                          /* requested range past EOF */
        }
        body  = (const char *) body + off;
        blen -= (size_t) off;
    }
    n = (blen < len) ? blen : len;
    memcpy(buf, body, n);
    is->transport->resp_free(&resp);
    return (ssize_t) n;
}

ngx_int_t
sd_http_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    *out = obj->snap;
    return NGX_OK;
}

/* sd_http_stat_fill — fill a brix_sd_stat_t from a HEAD-probed size.
 *
 * WHAT: Zero `out` then stamp the regular-file snapshot the size probe produced.
 * WHY:  The plain and credential-scoped stat slots derive an identical stat
 *       snapshot from the HEAD Content-Length; factoring it keeps the two slots
 *       from drifting on the mode/is_reg fields.
 * HOW:  ngx_memzero + size/mode/is_reg — the http origin exposes only read-only
 *       regular files (0444), same shape the object snapshot uses. */
static void
sd_http_stat_fill(brix_sd_stat_t *out, int64_t size)
{
    ngx_memzero(out, sizeof(*out));
    out->size   = (off_t) size;
    out->mode   = S_IFREG | 0444;
    out->is_reg = 1;
}

ngx_int_t
sd_http_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
{
    sd_http_inst_state *is = inst->state;
    int64_t             size = 0;

    /* Plain namespace stat runs on the instance's static credential — the
     * anonymous/service path used when no per-user credential is threaded. */
    if (sd_http_head_size(is, path, is->auth_hdr[0] ? is->auth_hdr : NULL,
                          NULL, &size) != 0) {
        return NGX_ERROR;                       /* errno set by head_size */
    }
    sd_http_stat_fill(out, size);
    return NGX_OK;
}

/* sd_http_stat_cred — vtable stat_cred slot: per-user credential-scoped stat.
 *
 * WHAT: Namespace stat (a HEAD size probe) that presents the requesting user's
 *       credential — a WLCG bearer as the Authorization header, or an x509 proxy
 *       as the mutual-TLS client cert — to the origin instead of the static
 *       service credential.
 * WHY:  Phase-70 §5.1 — an https backend leg authorizes EVERY request on the
 *       presented credential, so a namespace stat issued under a per-user policy
 *       (e.g. the root:// write pre-flight existence check, or a WebDAV lock-state
 *       probe on a remote origin) must carry the same forwarded identity the
 *       open/staged-open legs use. Without this slot the stat dispatched through
 *       the plain .stat and hit the auth-required origin ANONYMOUSLY, which the
 *       backend rejected — aborting the whole two-hop PUT even though the user's
 *       credential was fully resolved. sd_http has no kernel fd / session to
 *       re-scope, so — exactly like sd_http_open_cred — the credential is applied
 *       per request via the HEAD headers + client cert.
 * HOW:  Runs sd_http_cred_gate (deny a proxy-only cred the transport cannot
 *       mutual-TLS present), resolves the cred into a bearer header line + x509
 *       cert path with sd_http_resolve_open_cred (the SAME resolver the read open
 *       uses, so stat and open present one identity), then HEAD-probes with those
 *       — falling back to the instance static header only when the cred yields no
 *       bearer. cred==NULL degrades to the plain-stat behaviour. */
ngx_int_t
sd_http_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred)
{
    sd_http_inst_state *is = inst->state;
    int64_t             size = 0;
    char                open_auth[SD_HTTP_AUTH_MAX];
    const char         *open_cert;

    if (sd_http_cred_gate(is, cred) != 0) {
        return NGX_ERROR;                       /* errno = EACCES (set by gate) */
    }

    open_cert = sd_http_resolve_open_cred(is, cred, open_auth,
                                          sizeof(open_auth));

    if (sd_http_head_size(is, path,
                          open_auth[0] ? open_auth
                                       : (is->auth_hdr[0] ? is->auth_hdr : NULL),
                          open_cert, &size) != 0) {
        return NGX_ERROR;                       /* errno set by head_size */
    }
    sd_http_stat_fill(out, size);
    return NGX_OK;
}
