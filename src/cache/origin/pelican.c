/*
 * pelican.c — Pelican-federation client fetch (see pelican.h for the contract).
 *
 * Two steps, both in a fill thread-pool worker: discover the federation's
 * Director via its .well-known/pelican-configuration JSON, then fetch the object
 * through the Director, letting libcurl follow the 307 to the nearest
 * cache/origin. The byte transfer + Digest capture + checksum-on-fill all reuse
 * http_transport.c, so this file is only discovery + URL assembly.
 */

#include "pelican.h"
#include "http_transport.h"
#include "transport.h"

#include <curl/curl.h>
#include <jansson.h>

#include <stdio.h>
#include <string.h>


/* Bounded in-memory sink for the (small) discovery JSON document. */
typedef struct {
    char    *buf;
    size_t   len;
    size_t   cap;
} xrootd_pelican_mem_t;

#define XROOTD_PELICAN_CFG_MAX  (64 * 1024)


static size_t
xrootd_pelican_mem_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    xrootd_pelican_mem_t *m = userdata;
    size_t                n = size * nmemb;

    if (n == 0 || m->len + n > m->cap) {
        return 0;                       /* overflow ⇒ abort the transfer */
    }
    ngx_memcpy(m->buf + m->len, ptr, n);
    m->len += n;
    return n;
}


/* xrootd_pelican_get_mem — GET an HTTPS URL into a caller buffer * Small bounded fetch used for the discovery document. CA verification mirrors
 * the data path (cache_origin_cadir / trusted_ca). Returns 0 / -1 (t error). */
static int
xrootd_pelican_get_mem(xrootd_cache_fill_t *t, const char *url,
    char *out, size_t outsz, size_t *outlen)
{
    ngx_stream_xrootd_srv_conf_t *conf = t->conf;
    CURL                         *curl;
    CURLcode                      res;
    xrootd_pelican_mem_t          mem;
    long                          code = 0;

    curl = curl_easy_init();
    if (curl == NULL) {
        xrootd_cache_set_error(t, kXR_NoMemory, 0, "curl_easy_init failed");
        return -1;
    }

    mem.buf = out;
    mem.len = 0;
    mem.cap = outsz - 1;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, xrootd_pelican_mem_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &mem);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 8L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long) XROOTD_CACHE_IO_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long) XROOTD_CACHE_IO_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "nginx-xrootd-cache/1.0");
#ifdef CURLOPT_PROTOCOLS_STR
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
#else
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, (long) CURLPROTO_HTTPS);
#endif
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    if (conf->cache_origin_cadir.len > 0) {
        curl_easy_setopt(curl, CURLOPT_CAPATH,
                         (char *) conf->cache_origin_cadir.data);
    } else if (conf->trusted_ca.len > 0) {
        curl_easy_setopt(curl, CURLOPT_CAPATH, (char *) conf->trusted_ca.data);
    }

    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    }
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || code < 200 || code >= 300) {
        char emsg[512];
        (void) snprintf(emsg, sizeof(emsg),
            "pelican discovery failed (%.80s, http %ld) for %.150s",
            curl_easy_strerror(res), code, url);
        xrootd_cache_set_error(t, kXR_IOError, 0, emsg);
        return -1;
    }

    out[mem.len] = '\0';
    *outlen = mem.len;
    return 0;
}


int
xrootd_cache_pelican_discover(xrootd_cache_fill_t *t, const char *fed_host,
    uint16_t fed_port, char *out, size_t outsz)
{
    char         url[512];
    char         doc[XROOTD_PELICAN_CFG_MAX];
    size_t       doclen = 0;
    json_t      *root;
    json_t      *ep;
    json_error_t jerr;
    const char  *director;
    int          n;

    n = snprintf(url, sizeof(url),
                 "https://%s:%u/.well-known/pelican-configuration",
                 fed_host, (unsigned) fed_port);
    if (n < 0 || (size_t) n >= sizeof(url)) {
        xrootd_cache_set_error(t, kXR_ArgInvalid, 0,
                               "pelican federation host too long");
        return -1;
    }

    if (xrootd_pelican_get_mem(t, url, doc, sizeof(doc), &doclen) != 0) {
        return -1;                      /* t error already set */
    }

    root = json_loads(doc, JSON_REJECT_DUPLICATES, &jerr);
    if (root == NULL) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "pelican-configuration is not valid JSON");
        return -1;
    }

    ep = json_object_get(root, "director_endpoint");
    director = json_is_string(ep) ? json_string_value(ep) : NULL;
    if (director == NULL || director[0] == '\0' || ngx_strlen(director) >= outsz) {
        json_decref(root);
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "pelican-configuration missing director_endpoint");
        return -1;
    }

    ngx_memcpy(out, director, ngx_strlen(director) + 1);
    json_decref(root);
    return 0;
}


int
xrootd_cache_pelican_download(xrootd_cache_fill_t *t)
{
    ngx_stream_xrootd_srv_conf_t *conf = t->conf;
    char                          director[512];
    char                          url[XROOTD_MAX_PATH + 640];
    size_t                        dlen;
    int                           n;

    if (conf->cache_origin_host.len == 0
        || conf->cache_origin_host.len >= sizeof(director))
    {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "pelican federation host not configured");
        return -1;
    }

    if (xrootd_cache_pelican_discover(t, (char *) conf->cache_origin_host.data,
                                      conf->cache_origin_port, director,
                                      sizeof(director)) != 0)
    {
        return -1;
    }

    /* Object URL = <director_endpoint><logical path>. Drop a trailing '/' on the
     * director so we don't produce "//namespace"; clean_path carries its own
     * leading '/'. curl follows the Director's 307 to the chosen cache/origin. */
    dlen = ngx_strlen(director);
    while (dlen > 0 && director[dlen - 1] == '/') {
        director[--dlen] = '\0';
    }

    n = snprintf(url, sizeof(url), "%s%s", director, t->clean_path);
    if (n < 0 || (size_t) n >= sizeof(url)) {
        xrootd_cache_set_error(t, kXR_ServerError, 0, "pelican object URL too long");
        return -1;
    }

    return xrootd_cache_http_get_url(t, url);
}
