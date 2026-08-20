/* reg_blob.c — blob data plane: redirect-following digest-verified fetch
 * and the D4 upload-session push (see reg_client.h).
 *
 * The fetch streams over the http_internal seams (zero new socket code):
 * hand-built GET → read_resp_headers → Location on 3xx / dance on 401 /
 * httpx_download_body on 2xx. Authorization is stripped on every redirect
 * leg (the classic token-leak bug class, pinned by the D5.5 negative).
 * Verification is a sequential read-back of the just-written temp (one
 * page-cache-warm pass) — a true socket-side tee would mean re-implementing
 * the chunked/CL framing the seams already own. */
#include "oci/reg_internal.h"

#include "oci/digest.h"
#include "protocols/http/http_internal.h"

static void
hop_close(brix_io *io, int tls, void *tls_ctx)
{
    if (tls) {
        brix_tls_client_free(io, tls_ctx);
    }
    if (io->fd >= 0) {
        close(io->fd);
    }
}

/* Hash the temp back and compare; mismatch truncates the fd (no partial
 * bytes survive) — the caller owns the path and unlinks on failure. */
static int
blob_verify(int fd, const brix_oci_digest_t *want, char *err, size_t errlen)
{
    brix_oci_hash_ctx_t c;
    brix_oci_digest_t   got;
    const char         *alg = brix_oci_alg_name(want->alg);
    unsigned char       buf[65536];
    ssize_t             n;

    /* Hash under the algorithm the descriptor names, never a fixed one:
     * a sha512 layer summed with sha256 fails every honest fetch. */
    if (lseek(fd, 0, SEEK_SET) != 0
        || brix_oci_hash_init(&c, want->alg) != 0)
    {
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "blob verify: temp not seekable / %s init", alg);
    }
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (brix_oci_hash_update(&c, buf, (size_t) n) != 0) {
            brix_oci_hash_abort(&c);
            return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                             "blob verify: %s update failed", alg);
        }
    }
    if (n < 0) {
        brix_oci_hash_abort(&c);
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "blob verify: read-back failed");
    }
    if (brix_oci_hash_final(&c, &got) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "blob verify: %s final failed", alg);
    }
    if (!brix_oci_digest_eq(&got, want)) {
        if (ftruncate(fd, 0) != 0) {
            /* best-effort scrub: the caller unlinks the temp anyway */
        }
        return regc_fail(err, errlen, BRIX_OCI_REG_EVERIFY,
                         "blob digest mismatch: got %s:%s want %s:%s",
                         brix_oci_alg_name(got.alg), got.hex,
                         alg, want->hex);
    }
    return BRIX_OCI_REG_OK;
}

typedef enum {
    BLOB_REPLY_ERROR,
    BLOB_REPLY_AUTH,
    BLOB_REPLY_REDIRECT,
    BLOB_REPLY_DOWNLOAD
} blob_reply_t;

/* Classify a received response before deciding which hop action owns it. */
static blob_reply_t
blob_reply_action(int status, int at_origin, int danced)
{
    if (status == 401 && at_origin && !danced) {
        return BLOB_REPLY_AUTH;
    }
    if (status >= 300 && status < 400) {
        return BLOB_REPLY_REDIRECT;
    }
    if (status >= 200 && status < 300) {
        return BLOB_REPLY_DOWNLOAD;
    }
    return BLOB_REPLY_ERROR;
}

/* Release one connected hop and its copied response headers. */
static void
blob_hop_free(brix_io *io, int tls, void *tls_ctx, char *hdr)
{
    free(hdr);
    hop_close(io, tls, tls_ctx);
}

/* Connect and send one blob GET, returning its owned header block on success. */
static int
blob_get_headers(brix_oci_reg_t *r, const char *host, int port, int tls,
                 const char *path, const char *scope, brix_io *io,
                 void **tls_ctx, char **hdr, size_t *total, size_t *body_off,
                 int *status, brix_status *st, char *err, size_t errlen)
{
    char auth[4200], req[8192], host_port[300];
    int  req_len;

    memset(st, 0, sizeof(*st));
    if (httpx_connect(io, host, port, tls, r->verify, r->ca_dir,
                      r->client_cert, r->timeout_ms, tls_ctx, st) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "connect %s: %s", host, st->msg);
    }
    auth[0] = '\0';
    if (strcmp(host, r->host) == 0) {
        regc_auth_header(r, scope, auth, sizeof(auth));
    }
    brix_format_host_port(host, (uint16_t) port, host_port, sizeof(host_port));
    req_len = snprintf(req, sizeof(req),
                       "GET %s HTTP/1.1\r\nHost: %s\r\n"
                       "User-Agent: brixoci\r\n"
                       "Accept: application/octet-stream\r\n"
                       "Connection: close\r\n%s\r\n", path, host_port, auth);
    if (req_len < 0 || (size_t) req_len >= sizeof(req)) {
        hop_close(io, tls, *tls_ctx);
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "blob request too long");
    }
    if (brix_write_full(io, req, (size_t) req_len, st) != 0) {
        hop_close(io, tls, *tls_ctx);
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "blob GET send: %s", st->msg);
    }
    *hdr = malloc(XRDC_HDR_CAP);
    if (*hdr == NULL) {
        hop_close(io, tls, *tls_ctx);
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT, "out of memory");
    }
    if (read_resp_headers(io, *hdr, XRDC_HDR_CAP, r->timeout_ms, status,
                          total, body_off, st) != 0) {
        blob_hop_free(io, tls, *tls_ctx, *hdr);
        *hdr = NULL;
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "blob GET: %s", st->msg);
    }
    return BRIX_OCI_REG_OK;
}

/* Refresh an origin token from the single offered WWW-Authenticate challenge. */
static int
blob_auth_retry(brix_oci_reg_t *r, const char *hdr, const char *scope,
                int *danced, char *err, size_t errlen)
{
    char challenge[2048];

    if (!raw_header(hdr, "WWW-Authenticate", challenge, sizeof(challenge))) {
        return regc_status_fail(401, "blob GET", err, errlen);
    }
    *danced = 1;
    return regc_token_dance(r, challenge, scope, err, errlen);
}

/* Validate a redirect before assigning it to the next unauthenticated hop. */
static int
blob_redirect(brix_oci_reg_t *r, const char *location, char *host,
              size_t hostlen, int *port, int *tls, char *path,
              size_t pathlen, char *err, size_t errlen)
{
    char next_host[256], next_path[2048];
    int  next_port, next_tls;

    if (regc_url_split(location, host, *port, *tls, next_host,
                       sizeof(next_host), &next_port, &next_tls, next_path,
                       sizeof(next_path)) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "unparseable redirect Location");
    }
    if (!next_tls && !r->plain_http) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "refusing cleartext blob redirect");
    }
    snprintf(host, hostlen, "%s", next_host);
    snprintf(path, pathlen, "%s", next_path);
    *port = next_port;
    *tls = next_tls;
    return BRIX_OCI_REG_OK;
}

/* Stream the successful response into the caller's temp, then verify it. */
static int
blob_download(brix_oci_reg_t *r, brix_io *io, int tls, void *tls_ctx,
              char *hdr, size_t total, size_t body_off, int out_fd,
              const brix_oci_digest_t *want, brix_status *st, char *err,
              size_t errlen)
{
    long long body_len = 0;
    int       rc;

    rc = httpx_download_body(io, hdr, total, body_off, out_fd,
                             r->timeout_ms, &body_len, st);
    blob_hop_free(io, tls, tls_ctx, hdr);
    if (rc != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "blob body: %s", st->msg);
    }
    return blob_verify(out_fd, want, err, errlen);
}

int
brix_oci_reg_blob_fetch(brix_oci_reg_t *r, const char *name,
                        const char *digest, int out_fd, char *err,
                        size_t errlen)
{
    brix_oci_digest_t want;
    char              ename[512], path[2048], scope[600], host[256];
    int               port, tls, hop, danced = 0, rc;

    if (brix_oci_digest_parse(digest, strlen(digest), &want) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "invalid blob digest \"%s\"", digest);
    }
    if (regc_eff_name(r, name, ename, sizeof(ename)) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "repository name too long");
    }
    snprintf(path, sizeof(path), "/v2/%s/blobs/%s:%s", ename,
             brix_oci_alg_name(want.alg), want.hex);
    snprintf(scope, sizeof(scope), "repository:%s:pull", ename);
    snprintf(host, sizeof(host), "%s", r->host);
    port = r->port;
    tls = !r->plain_http;

    for (hop = 0; hop <= 4; hop++) {
        brix_io     io;
        brix_status st;
        void       *tls_ctx = NULL;
        char       *hdr = NULL;
        size_t      total = 0, body_off = 0;
        int         status = 0;
        int         at_origin = strcmp(host, r->host) == 0;
        blob_reply_t action;

        rc = blob_get_headers(r, host, port, tls, path, scope, &io,
                              &tls_ctx, &hdr, &total, &body_off, &status,
                              &st, err, errlen);
        if (rc != BRIX_OCI_REG_OK) {
            return rc;
        }
        action = blob_reply_action(status, at_origin, danced);
        if (action == BLOB_REPLY_AUTH) {
            rc = blob_auth_retry(r, hdr, scope, &danced, err, errlen);
            blob_hop_free(&io, tls, tls_ctx, hdr);
            if (rc != BRIX_OCI_REG_OK) {
                return rc;
            }
            hop--;    /* the auth retry is not a redirect hop */
            continue;
        }
        if (action == BLOB_REPLY_REDIRECT) {
            char location[2048];
            int  have_location = raw_header(hdr, "Location", location,
                                            sizeof(location));

            blob_hop_free(&io, tls, tls_ctx, hdr);
            if (!have_location) {
                return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                                 "redirect without Location");
            }
            rc = blob_redirect(r, location, host, sizeof(host), &port, &tls,
                               path, sizeof(path), err, errlen);
            if (rc != BRIX_OCI_REG_OK) {
                return rc;
            }
            continue;
        }
        if (action == BLOB_REPLY_ERROR) {
            blob_hop_free(&io, tls, tls_ctx, hdr);
            return regc_status_fail(status, "blob GET", err, errlen);
        }
        return blob_download(r, &io, tls, tls_ctx, hdr, total, body_off,
                             out_fd, &want, &st, err, errlen);
    }
    return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                     "too many redirects fetching blob");
}

static ssize_t
push_src(void *ctx, uint8_t *buf, int64_t off, size_t cap, brix_status *st)
{
    int     fd = *(const int *) ctx;
    ssize_t n = pread(fd, buf, cap, (off_t) off); /* vfs-seam-allow: OCI layout blob or anonymous registry staging fd, never an export VFS object */

    if (n < 0) {
        brix_status_set(st, XRDC_ESOCK, errno, "blob source read failed");
        return -1;
    }
    return n;
}

/* Probe an existing digest so content-addressed uploads can be skipped. */
static int
blob_push_probe(brix_oci_reg_t *r, const char *name,
                const brix_oci_digest_t *digest, const char *scope,
                int *exists, char *err, size_t errlen)
{
    brix_http_resp resp;
    char           path[2048];
    int            rc;

    snprintf(path, sizeof(path), "/v2/%s/blobs/%s:%s", name,
             brix_oci_alg_name(digest->alg), digest->hex);
    rc = regc_call(r, "HEAD", path, scope, NULL, NULL, 0, &resp, err,
                   errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    *exists = resp.status == 200;
    brix_http_resp_free(&resp);
    return BRIX_OCI_REG_OK;
}

/* Open an upload session and copy the server-owned Location header. */
static int
blob_push_session(brix_oci_reg_t *r, const char *name, const char *scope,
                  char *location, size_t location_len, char *err,
                  size_t errlen)
{
    brix_http_resp resp;
    char           path[2048];
    int            rc;

    snprintf(path, sizeof(path), "/v2/%s/blobs/uploads/", name);
    rc = regc_call(r, "POST", path, scope, "Content-Length: 0\r\n", NULL,
                   0, &resp, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    if (resp.status != 202) {
        rc = regc_status_fail(resp.status, "upload session open", err, errlen);
        brix_http_resp_free(&resp);
        return rc;
    }
    if (!brix_http_header(&resp, "Location", location, location_len)) {
        brix_http_resp_free(&resp);
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "202 without an upload Location");
    }
    brix_http_resp_free(&resp);
    return BRIX_OCI_REG_OK;
}

/* Restrict the session target to the registry origin and add its digest. */
static int
blob_push_target(brix_oci_reg_t *r, const char *location,
                 const brix_oci_digest_t *digest, char *upload,
                 size_t upload_len, int *tls, char *err, size_t errlen)
{
    char host[256], path[2048];
    int  port;

    if (regc_url_split(location, r->host, r->port, !r->plain_http, host,
                       sizeof(host), &port, tls, path, sizeof(path)) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "unparseable upload Location");
    }
    if (strcmp(host, r->host) != 0 || port != r->port) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "cross-host upload session unsupported");
    }
    if (snprintf(upload, upload_len, "%s%cdigest=%s%%3A%s", path,
                 strchr(path, '?') != NULL ? '&' : '?',
                 brix_oci_alg_name(digest->alg), digest->hex) >=
        (int) upload_len) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "upload URL too long");
    }
    return BRIX_OCI_REG_OK;
}

/* PUT a complete source into the session and map its terminal status. */
static int
blob_push_upload(brix_oci_reg_t *r, const char *scope, int tls,
                 const char *upload, int in_fd, size_t len, char *err,
                 size_t errlen)
{
    brix_status st;
    char        auth[4200], headers[4500];
    int         status = 0;

    regc_auth_header(r, scope, auth, sizeof(auth));
    snprintf(headers, sizeof(headers),
             "Content-Type: application/octet-stream\r\n%s", auth);
    memset(&st, 0, sizeof(st));
    if (brix_http_upload(r->host, r->port, tls, upload, headers, push_src,
                         &in_fd, (long long) len, r->verify, r->ca_dir,
                         r->client_cert, r->timeout_ms, &status, &st) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "blob PUT: %s", st.msg);
    }
    if (status < 200 || status >= 300) {
        return regc_status_fail(status, "blob PUT", err, errlen);
    }
    return BRIX_OCI_REG_OK;
}

int
brix_oci_reg_blob_push(brix_oci_reg_t *r, const char *name,
                       const char *digest, int in_fd, size_t len,
                       char *err, size_t errlen)
{
    brix_oci_digest_t d;
    char              ename[512], scope[600], loc[2048];
    char              up[2600];
    int               exists, ltls, rc;

    if (brix_oci_digest_parse(digest, strlen(digest), &d) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "invalid blob digest \"%s\"", digest);
    }
    if (regc_eff_name(r, name, ename, sizeof(ename)) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "repository name too long");
    }
    snprintf(scope, sizeof(scope), "repository:%s:push,pull", ename);

    /* dedupe probe — content addressing makes re-pushing pointless */
    rc = blob_push_probe(r, ename, &d, scope, &exists, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    if (exists) {
        return BRIX_OCI_REG_OK;
    }

    /* open an upload session */
    rc = blob_push_session(r, ename, scope, loc, sizeof(loc), err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    /* single-shot seal: PUT the whole body with ?digest= (':' encoded) */
    rc = blob_push_target(r, loc, &d, up, sizeof(up), &ltls, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    return blob_push_upload(r, scope, ltls, up, in_fd, len, err, errlen);
}
