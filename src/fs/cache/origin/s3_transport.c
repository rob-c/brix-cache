/*
 * s3_transport.c — server-side libcurl implementation of brix_s3_transport_t.
 * See the header. Runs only on the blocking cache-fill worker thread.
 *
 * This TU holds the response-capture buffers/callbacks, the synchronous request
 * execution body and the vtable entry points/accessors. Operator policy, the
 * per-thread curl handle lifecycle, per-request curl option configuration and
 * the upstream trace line live in s3_transport_setup.c; the shared seam is
 * s3_transport_internal.h.
 */

#include "s3_transport.h"
#include "s3_transport_internal.h"

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/path/path.h"                  /* brix_sanitize_log_string */

#include <curl/curl.h>
#include <ctype.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>

static long
s3o_ms_since(const struct timespec *t0)
{
    struct timespec now;
    long            ms;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    ms = (now.tv_sec - t0->tv_sec) * 1000L
       + (now.tv_nsec - t0->tv_nsec) / 1000000L;
    return ms < 0 ? 0 : ms;
}

/* Append `n` bytes to a growable buffer; returns 0 / -1 (OOM). */
static int
s3o_buf_append(char **buf, size_t *len, size_t *cap, const char *src, size_t n)
{
    if (*len + n + 1 > *cap) {
        size_t newcap = (*cap == 0) ? 8192 : *cap;
        char  *nb;

        while (*len + n + 1 > newcap) {
            newcap *= 2;
        }
        nb = realloc(*buf, newcap);
        if (nb == NULL) {
            return -1;
        }
        *buf = nb;
        *cap = newcap;
    }
    memcpy(*buf + *len, src, n);
    *len += n;
    (*buf)[*len] = '\0';
    return 0;
}

size_t
s3o_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    s3o_resp_t *r = userdata;
    size_t      n = size * nmemb;

    if (s3o_buf_append(&r->body, &r->body_len, &r->body_cap, ptr, n) != 0) {
        return 0;          /* signal write error → libcurl aborts */
    }
    return n;
}

size_t
s3o_header_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    s3o_resp_t *r = userdata;
    size_t      n = size * nmemb;

    if (s3o_buf_append(&r->hdrs, &r->hdrs_len, &r->hdrs_cap, ptr, n) != 0) {
        return 0;
    }
    return n;
}

/* s3o_request_impl — the shared request body for the plain and cred-scoped
 * transport slots.
 *
 * WHAT: Performs one synchronous libcurl request described by `req`, capturing
 *       the response into a heap s3o_resp_t handed back through `resp->opaque`.
 * WHY:  The GSI-over-https backend leg (phase-70 §5.1) authenticates the origin
 *       hop AS the end user by presenting the user's proxy PEM as the TLS client
 *       cert — the only structural difference from an anonymous/bearer request is
 *       the mutual-TLS options (in req->client_cert_pem), so both entry points
 *       share one body.
 * HOW:  Acquires this thread's persistent warm handle, builds the header list,
 *       configures every per-request option (s3o_configure), performs the
 *       transfer and emits the trace line. A per-request curl handle is reset
 *       between uses, so TLS/cert options do not leak into the next request. */
static int
s3o_request_impl(const s3o_request_t *req, brix_s3_resp_t *resp,
                 char *errbuf, size_t errcap)
{
    CURL              *curl;
    CURLcode           res;
    struct curl_slist *slist = NULL;
    s3o_resp_t        *r;
    long               status = 0;
    struct timespec    t0;
    s3o_trace_t        tr = { 0 };

    (void) clock_gettime(CLOCK_MONOTONIC, &t0);

    curl = s3o_curl_acquire();       /* this thread's persistent, warm handle */
    if (curl == NULL) {
        if (errbuf && errcap) { snprintf(errbuf, errcap, "curl handle unavailable"); }
        return -1;
    }

    r = calloc(1, sizeof(*r));
    if (r == NULL) {
        if (errbuf && errcap) { snprintf(errbuf, errcap, "out of memory"); }
        return -1;                   /* handle stays in TLS, reused next call */
    }

    slist = s3o_build_headers(req);
    s3o_configure(curl, req, r, slist);

    tr.method = req->method;
    tr.host   = req->host;
    tr.port   = req->port;
    tr.path   = req->path_and_query;

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        if (errbuf && errcap) {
            snprintf(errbuf, errcap, "curl: %s", curl_easy_strerror(res));
        }
        tr.status = -1;
        tr.dur_ms = s3o_ms_since(&t0);
        tr.err    = curl_easy_strerror(res);
        s3o_trace(&tr);
        curl_slist_free_all(slist);
        free(r->body);
        free(r->hdrs);
        free(r);
        return -1;                   /* handle persists (curl drops a dead
                                        connection from the pool by itself) */
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(slist);

    resp->status = (int) status;
    resp->opaque = r;
    tr.status = (int) status;
    tr.bytes  = r->body_len;
    tr.dur_ms = s3o_ms_since(&t0);
    tr.proto  = s3o_negotiated_proto(curl);
    s3o_trace(&tr);
    return 0;
}

/* Plain request slot: no client certificate (anonymous or header-borne auth). */
static int
s3o_request(void *tctx, const char *host, int port, int tls,
            const char *method, const char *path_and_query,
            const char *headers, const void *body, size_t body_len,
            int timeout_ms, brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    s3o_request_t req = {
        .tctx           = tctx,
        .host           = host,
        .port           = port,
        .tls            = tls,
        .method         = method,
        .path_and_query = path_and_query,
        .headers        = headers,
        .body           = body,
        .body_len       = body_len,
        .timeout_ms     = timeout_ms,
        .client_cert_pem = NULL,
    };

    return s3o_request_impl(&req, resp, errbuf, errcap);
}

/* Cred-scoped request slot: present `client_cert_pem` (a combined proxy PEM) as
 * the mutual-TLS client cert. NULL cert path degrades to a plain request. */
static int
s3o_request_cred(void *tctx, const char *host, int port, int tls,
                 const char *method, const char *path_and_query,
                 const char *headers, const void *body, size_t body_len,
                 int timeout_ms, const char *client_cert_pem,
                 brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    s3o_request_t req = {
        .tctx           = tctx,
        .host           = host,
        .port           = port,
        .tls            = tls,
        .method         = method,
        .path_and_query = path_and_query,
        .headers        = headers,
        .body           = body,
        .body_len       = body_len,
        .timeout_ms     = timeout_ms,
        .client_cert_pem = client_cert_pem,
    };

    return s3o_request_impl(&req, resp, errbuf, errcap);
}

static int
s3o_resp_header(const brix_s3_resp_t *resp, const char *name,
                char *out, size_t outcap)
{
    const s3o_resp_t *r = resp->opaque;
    size_t            namelen = strlen(name);
    const char       *p;

    if (r == NULL || r->hdrs == NULL) {
        return -1;
    }
    for (p = r->hdrs; *p != '\0'; ) {
        const char *eol = strpbrk(p, "\r\n");
        size_t      linelen = (eol != NULL) ? (size_t) (eol - p) : strlen(p);

        if (linelen > namelen && p[namelen] == ':'
            && strncasecmp(p, name, namelen) == 0)
        {
            const char *v = p + namelen + 1;
            size_t      vlen;

            while (v < p + linelen && (*v == ' ' || *v == '\t')) { v++; }
            vlen = (size_t) (p + linelen - v);
            if (vlen >= outcap) { vlen = outcap - 1; }
            memcpy(out, v, vlen);
            out[vlen] = '\0';
            return 0;
        }
        if (eol == NULL) { break; }
        p = eol + strspn(eol, "\r\n");
    }
    return -1;
}

/* Raw header block for enumeration (generic x-amz-meta-* listxattr). */
static const char *
s3o_resp_headers_raw(const brix_s3_resp_t *resp)
{
    const s3o_resp_t *r = resp->opaque;

    return (r != NULL) ? r->hdrs : NULL;
}

static const void *
s3o_resp_body(const brix_s3_resp_t *resp, size_t *len)
{
    const s3o_resp_t *r = resp->opaque;

    if (r == NULL) {
        if (len) { *len = 0; }
        return NULL;
    }
    if (len) { *len = r->body_len; }
    return r->body;
}

static void
s3o_resp_free(brix_s3_resp_t *resp)
{
    s3o_resp_t *r;

    if (resp == NULL || resp->opaque == NULL) {
        return;
    }
    r = resp->opaque;
    free(r->body);
    free(r->hdrs);
    free(r);
    resp->opaque = NULL;
}

const brix_s3_transport_t brix_s3_origin_curl_transport = {
    .request      = s3o_request,
    .request_cred = s3o_request_cred,
    .resp_header = s3o_resp_header,
    .resp_headers_raw = s3o_resp_headers_raw,
    .resp_body   = s3o_resp_body,
    .resp_free   = s3o_resp_free,
};
