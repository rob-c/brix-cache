/*
 * s3_transport.c — server-side libcurl implementation of xrootd_s3_transport_t.
 * See the header. Runs only on the blocking cache-fill worker thread.
 */

#include "s3_transport.h"

#include <curl/curl.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Transport-private response: the captured body + raw response header block. */
typedef struct {
    char   *body;
    size_t  body_len;
    size_t  body_cap;
    char   *hdrs;          /* raw "Name: value\r\n" lines as received */
    size_t  hdrs_len;
    size_t  hdrs_cap;
} s3o_resp_t;

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

static size_t
s3o_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    s3o_resp_t *r = userdata;
    size_t      n = size * nmemb;

    if (s3o_buf_append(&r->body, &r->body_len, &r->body_cap, ptr, n) != 0) {
        return 0;          /* signal write error → libcurl aborts */
    }
    return n;
}

static size_t
s3o_header_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    s3o_resp_t *r = userdata;
    size_t      n = size * nmemb;

    if (s3o_buf_append(&r->hdrs, &r->hdrs_len, &r->hdrs_cap, ptr, n) != 0) {
        return 0;
    }
    return n;
}

/* Split the CRLF-separated header block sd_s3 built into a curl_slist, dropping
 * blank lines and any trailing CR. Returns the list (caller frees) or NULL. */
static struct curl_slist *
s3o_build_slist(const char *headers)
{
    struct curl_slist *list = NULL;
    const char        *p = headers;

    while (p != NULL && *p != '\0') {
        const char *eol = strpbrk(p, "\r\n");
        size_t      linelen = (eol != NULL) ? (size_t) (eol - p) : strlen(p);

        if (linelen > 0) {
            char line[1024];

            if (linelen >= sizeof(line)) {
                linelen = sizeof(line) - 1;
            }
            memcpy(line, p, linelen);
            line[linelen] = '\0';
            list = curl_slist_append(list, line);
        }
        if (eol == NULL) {
            break;
        }
        p = eol + strspn(eol, "\r\n");   /* skip the CR/LF run */
    }
    return list;
}

static int
s3o_request(void *tctx, const char *host, int port, int tls,
            const char *method, const char *path_and_query,
            const char *headers, const void *body, size_t body_len,
            int timeout_ms, xrootd_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    CURL              *curl;
    CURLcode           res;
    struct curl_slist *slist = NULL;
    s3o_resp_t        *r;
    char               url[2048];
    char               host_hdr[300];
    long               status = 0;

    (void) tctx;

    curl = curl_easy_init();
    if (curl == NULL) {
        if (errbuf && errcap) { snprintf(errbuf, errcap, "curl_easy_init failed"); }
        return -1;
    }

    r = calloc(1, sizeof(*r));
    if (r == NULL) {
        curl_easy_cleanup(curl);
        if (errbuf && errcap) { snprintf(errbuf, errcap, "out of memory"); }
        return -1;
    }

    snprintf(url, sizeof(url), "%s://%s:%d%s",
             tls ? "https" : "http", host, port, path_and_query);

    slist = s3o_build_slist(headers);
    /* Force the Host header to "host:port" — sd_s3 signs the SigV4 canonical host
     * as host:port for EVERY port (xrootd_format_host_port always appends it), so
     * libcurl's default of omitting the port on a default port (80/443) would
     * break the signature. Always sending the port keeps the Host header byte-for-
     * byte what was signed. */
    snprintf(host_hdr, sizeof(host_hdr), "Host: %s:%d", host, port);
    slist = curl_slist_append(slist, host_hdr);
    /* Disable libcurl's automatic Expect: 100-continue on PUT/POST (some S3
     * servers stall on it); sd_s3 does not rely on it. */
    slist = curl_slist_append(slist, "Expect:");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, s3o_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, r);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, s3o_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, r);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long) (timeout_ms > 0 ? timeout_ms : 60000));
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    if (strcmp(method, "HEAD") == 0) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    } else if (strcmp(method, "GET") != 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
        if (body != NULL && body_len > 0) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                             (curl_off_t) body_len);
        } else {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) 0);
        }
    }

    if (tls) {
        /* Origin TLS verification is the operator's trust decision; default to
         * verifying (a misconfigured origin should fail loudly, not silently). */
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    }

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        if (errbuf && errcap) {
            snprintf(errbuf, errcap, "curl: %s", curl_easy_strerror(res));
        }
        curl_slist_free_all(slist);
        free(r->body);
        free(r->hdrs);
        free(r);
        curl_easy_cleanup(curl);
        return -1;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(slist);
    curl_easy_cleanup(curl);

    resp->status = (int) status;
    resp->opaque = r;
    return 0;
}

static int
s3o_resp_header(const xrootd_s3_resp_t *resp, const char *name,
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

static const void *
s3o_resp_body(const xrootd_s3_resp_t *resp, size_t *len)
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
s3o_resp_free(xrootd_s3_resp_t *resp)
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

const xrootd_s3_transport_t xrootd_s3_origin_curl_transport = {
    .request     = s3o_request,
    .resp_header = s3o_resp_header,
    .resp_body   = s3o_resp_body,
    .resp_free   = s3o_resp_free,
};
