/*
 * copy_web_download.c - recursive web/S3 GET download + SigV4/bearer auth headers.
 * Phase-38 split of copy_recursive.c; behavior-identical.
 */
#include "copy_internal.h"

/* web transfer (davs:// / http(s):// / s3://) — production GET/PUT over  */
/* the streaming HTTP client. Auth: WebDAV bearer token or S3 SigV4.      */


/* Resolve the S3 access/secret key pair for SigV4 signing.
 *
 * WHY: precedence is frozen — explicit opts first, then the credential store
 * (co->cred) when set, then the AWS_* environment, so env-sourced credentials
 * behave identically to today.  A store-acquire failure is not an error: the
 * status is cleared and resolution falls through to the environment.  Either
 * pointer may come back NULL (anonymous access — the caller decides). */
static void
s3_resolve_keys(const brix_copy_opts *o, const brix_opts *co,
                const char **ak, const char **sk, brix_status *st)
{
    brix_cred_view sv;

    *ak = (o && o->s3_access) ? o->s3_access : NULL;
    *sk = (o && o->s3_secret) ? o->s3_secret : NULL;

    /* Prefer the cred store for S3 keys when no explicit opts override. */
    if ((*ak == NULL || *sk == NULL) && co != NULL && co->cred != NULL) {
        if (brix_cred_acquire(co->cred, XRDC_CRED_S3KEYS, 0, &sv, st) == 0) {
            if (*ak == NULL) { *ak = sv.s3_access; }
            if (*sk == NULL) { *sk = sv.s3_secret; }
        } else {
            brix_status_clear(st);
        }
    }
    /* Fall through to env when store not set or acquire failed. */
    if (*ak == NULL) { *ak = getenv("AWS_ACCESS_KEY_ID"); }
    if (*sk == NULL) { *sk = getenv("AWS_SECRET_ACCESS_KEY"); }
}


/* Build the S3 SigV4 Authorization block for a->u into hdrs[].
 *
 * HOW: resolve keys (opts → store → env; both missing = anonymous, empty
 * hdrs); host is signed as "host:port" to match the wire Host header
 * byte-for-byte (brackets IPv6 literals); UNSIGNED-PAYLOAD for every method
 * because the body streams and is not folded into the signature (both
 * nginx-xrootd's S3 and real AWS accept that).  Returns 0/-1 (a->st set). */
static int
auth_hdr_s3(const web_auth_ctx *a, char *hdrs, size_t hdrsz)
{
    const brix_weburl    *u  = a->u;
    const brix_copy_opts *o  = a->o;
    brix_status          *st = a->st;
    const char           *ak, *sk;
    const char           *rg = (o && o->s3_region) ? o->s3_region
                                                   : getenv("AWS_DEFAULT_REGION");
    char                  host[300], payhash[65];

    s3_resolve_keys(o, a->co, &ak, &sk, st);
    if (ak == NULL || sk == NULL) {
        return 0;   /* anonymous — server may permit unsigned access */
    }
    if (rg == NULL) { rg = "us-east-1"; }
    /* A '?' would split path vs query in the server's canonical request but
     * we sign the whole path as CanonicalURI — reject rather than mis-sign. */
    if (strchr(u->path, '?') != NULL) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "s3: query strings in the URL are not supported");
        return -1;
    }
    /* The SigV4 signed host MUST match the wire Host header byte-for-byte; that
     * header brackets IPv6 literals ([::1]:9000), so sign the same form. */
    brix_format_host_port(u->host, (uint16_t) u->port, host, sizeof(host));
    /* UNSIGNED-PAYLOAD for every method: the body isn't folded into the
     * signature (it streams), which both nginx-xrootd's S3 and real AWS accept. */
    snprintf(payhash, sizeof(payhash), "UNSIGNED-PAYLOAD");
    if (brix_s3_sign_v4(a->method, host, u->path, ak, sk, rg, payhash,
                        hdrs, hdrsz) != 0) {
        brix_status_set(st, XRDC_EAUTH, 0, "s3: failed to build SigV4 signature");
        return -1;
    }
    return 0;
}


/* Build the WebDAV/HTTP bearer Authorization header into hdrs[] (left empty
 * for an anonymous endpoint).
 *
 * WHY: precedence is frozen — explicit opts first, then the credential store
 * (co->cred) when set, then $BEARER_TOKEN; a store-acquire failure clears the
 * status and falls through to the environment.  Returns 0/-1 (st set). */
static int
auth_hdr_bearer(const brix_copy_opts *o, const brix_opts *co,
                char *hdrs, size_t hdrsz, brix_status *st)
{
    const char    *tok = (o && o->bearer) ? o->bearer : NULL;
    brix_cred_view bv;

    /* Prefer the cred store for the bearer token when no explicit opt override. */
    if (tok == NULL && co != NULL && co->cred != NULL) {
        if (brix_cred_acquire(co->cred, XRDC_CRED_BEARER, 0, &bv, st) == 0
            && bv.token != NULL) {
            tok = bv.token;
        } else {
            brix_status_clear(st);
        }
    }
    /* Fall through to env when store not set or acquire failed. */
    if (tok == NULL) { tok = getenv("BEARER_TOKEN"); }

    if (tok != NULL && tok[0] != '\0') {
        int n = snprintf(hdrs, hdrsz, "Authorization: Bearer %s\r\n", tok);
        if (n < 0 || (size_t) n >= hdrsz) {
            brix_status_set(st, XRDC_EUSAGE, 0, "bearer token too long");
            return -1;
        }
    }
    return 0;
}


/* Build the auth header block for a web request into hdrs[] (may be empty for an
 * anonymous endpoint). S3 → SigV4 (host signed as "host:port" to match the Host
 * header we send); WebDAV/HTTP → Authorization: Bearer if a token is available.
 *
 * a->co carries the credential store (co->cred); when set the store is tried
 * first for both the bearer token and S3 keys, falling back to opts/env on
 * failure so env-sourced credentials behave identically to today. */
int
web_auth_headers(const web_auth_ctx *a, char *hdrs, size_t hdrsz)
{
    hdrs[0] = '\0';
    if (a->u->is_s3) {
        return auth_hdr_s3(a, hdrs, hdrsz);
    }
    return auth_hdr_bearer(a->o, a->co, hdrs, hdrsz, a->st);
}


/* Transfer result of one streaming HTTP GET (web_dl_fetch out-params).
 * Bundled so the fetch wrapper stays under the 5-parameter gate. */
typedef struct {
    int       outfd;    /* IN:  destination fd (file or STDOUT_FILENO) */
    int       status;   /* OUT: HTTP status                            */
    long long blen;     /* OUT: body bytes written                     */
} web_dl_io;

/* Run one streaming HTTP GET of su into io->outfd.
 *
 * WHY: both the stdout and to-file branches of copy_web_download issue the
 * same brix_http_download call (empty hdrs → NULL, co-optional verify/CA
 * defaults); centralizing it keeps the two call sites literally identical. */
static int
web_dl_fetch(const brix_weburl *su, const brix_opts *co, const char *hdrs,
             web_dl_io *io, brix_status *st)
{
    char        proxybuf[512];
    const char *pcert = brix_web_proxy_pem(proxybuf, sizeof(proxybuf));

    return brix_http_download(su->host, su->port, su->tls, su->path,
                              hdrs[0] ? hdrs : NULL, co ? co->verify_host : 1,
                              co ? co->ca_dir : NULL, pcert, io->outfd,
                              XRDC_WEB_TIMEOUT_MS, &io->status, &io->blen, st);
}


int
copy_web_download(const web_dl_req *rq, brix_status *st)
{
    const brix_weburl    *su = rq->su;
    const brix_url       *du = rq->du;
    const brix_copy_opts *o  = rq->o;
    const brix_opts      *co = rq->co;
    char                  hdrs[8192];
    char                  tmp[XRDC_PATH_MAX];
    int                   rc;
    web_dl_io             io = { -1, 0, 0 };
    web_auth_ctx          a  = { su, "GET", o, co, st };

    if (web_auth_headers(&a, hdrs, sizeof(hdrs)) != 0) {
        return -1;
    }
    if (rq->to_stdout) {
        io.outfd = STDOUT_FILENO;
        return web_dl_fetch(su, co, hdrs, &io, st);
    }
    /* Refuse to overwrite an existing destination unless -f. */
    if (!(o && o->force) && access(du->path, F_OK) == 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "destination exists (use -f to overwrite): %s", du->path);
        return -1;
    }
    /* Download to a temp sibling and atomically rename on success: a failed
     * transfer must never truncate or delete a pre-existing destination. */
    io.outfd = open_download_temp(du->path, tmp, sizeof(tmp), st);
    if (io.outfd < 0) {
        return -1;
    }
    rc = web_dl_fetch(su, co, hdrs, &io, st);
    close(io.outfd);
    rc = atomic_dest_finish(tmp, du->path, rc, st);
    if (rc != 0) {
        return rc;
    }
    if (o && !o->silent) {
        fprintf(stderr, "xrdcp: downloaded %lld bytes (HTTP %d)\n",
                io.blen, io.status);
    }
    return 0;
}
