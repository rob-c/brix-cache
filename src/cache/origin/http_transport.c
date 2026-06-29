/*
 * http_transport.c — HTTP(S) origin download for the read-through cache.
 *
 * See http_transport.h for the contract. Everything here runs in a fill
 * thread-pool worker (blocking libcurl); only the eventual *_done callback in
 * thread.c touches the connection. The downloaded bytes are streamed straight to
 * the ".part" fd; the origin's Digest header is captured and normalised into the
 * (alg, hex) form that verify.c compares against a local recomputation.
 */

#include "http_transport.h"
#include "transport.h"

#include "../../compat/checksum.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>


/* Captured response headers we care about. */
typedef struct {
    char    alg[16];      /* normalised digest algorithm, "" when none usable   */
    char    hex[129];     /* digest as lowercase hex                            */
    off_t   content_len;  /* Content-Length, -1 when absent                     */
} xrootd_http_hdrs_t;

/* Write-callback sink: a part fd plus a running offset for pwrite. */
typedef struct {
    int                  fd;
    off_t                written;
} xrootd_http_sink_t;


/* xrootd_http_load_bearer — pick the bearer token for the origin GET * Forward the client's token first when xrootd_cache_origin_forward_token is on
 * and one was presented (ctx->bearer_token); otherwise read the configured
 * cache credential file (xrootd_cache_origin_token_file). Returns 1 with the
 * token copied into out[outsz] (trailing whitespace trimmed), 0 when none. */
static int
xrootd_http_load_bearer(xrootd_cache_fill_t *t, char *out, size_t outsz)
{
    ngx_stream_xrootd_srv_conf_t *conf = t->conf;
    char                          path[PATH_MAX];
    ssize_t                       n;
    int                           fd;

    if (conf->cache_origin_forward_token && t->ctx != NULL
        && t->ctx->bearer_token[0] != '\0')
    {
        size_t len = ngx_strlen(t->ctx->bearer_token);
        if (len < outsz) {
            ngx_memcpy(out, t->ctx->bearer_token, len);
            out[len] = '\0';
            return 1;
        }
    }

    if (conf->cache_origin_token_file.len == 0
        || conf->cache_origin_token_file.len >= sizeof(path))
    {
        return 0;
    }
    ngx_memcpy(path, conf->cache_origin_token_file.data,
               conf->cache_origin_token_file.len);
    path[conf->cache_origin_token_file.len] = '\0';

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        return 0;
    }
    n = read(fd, out, outsz - 1);
    close(fd);
    if (n <= 0) {
        return 0;
    }
    out[n] = '\0';
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'
                     || out[n - 1] == ' ' || out[n - 1] == '\t')) {
        out[--n] = '\0';
    }
    return out[0] != '\0';
}


/* xrootd_http_norm_alg — normalise an RFC 3230 digest token name * Lowercase and strip '-' so "SHA-256" → "sha256", "adler32" stays. 0/-1. */
static int
xrootd_http_norm_alg(const char *raw, size_t len, char *out, size_t outsz)
{
    size_t o = 0;
    size_t i;

    for (i = 0; i < len && o + 1 < outsz; i++) {
        if (raw[i] == '-') {
            continue;
        }
        out[o++] = (char) tolower((unsigned char) raw[i]);
    }
    out[o] = '\0';
    return (o > 0) ? 0 : -1;
}


/* xrootd_http_digest_to_hex — one "name=value" digest token → (alg,hex) * Maps the token name to a known algorithm and renders its value as lowercase
 * hex: XRootD-style values are already hex; RFC sha-family values are base64 and
 * are decoded. Returns 0 on a usable mapping, -1 otherwise. */
static int
xrootd_http_digest_to_hex(const char *name, size_t nlen, const char *val,
    size_t vlen, char *alg_out, size_t alg_sz, char *hex_out, size_t hex_sz)
{
    char                   norm[16];
    char                   canon[32];
    xrootd_checksum_alg_t  alg;
    size_t                 want_hex;
    size_t                 i;
    int                    is_hex;

    if (xrootd_http_norm_alg(name, nlen, norm, sizeof(norm)) != 0) {
        return -1;
    }
    if (xrootd_checksum_parse(norm, ngx_strlen(norm), &alg, canon,
                              sizeof(canon)) != NGX_OK)
    {
        return -1;
    }

    if (xrootd_checksum_is_u32(alg)) {
        want_hex = 8;
    } else if (xrootd_checksum_is_u64(alg)) {
        want_hex = 16;
    } else if (alg == XROOTD_CHECKSUM_MD5) {
        want_hex = 32;
    } else if (alg == XROOTD_CHECKSUM_SHA1) {
        want_hex = 40;
    } else if (alg == XROOTD_CHECKSUM_SHA256) {
        want_hex = 64;
    } else {
        return -1;
    }

    if (want_hex + 1 > hex_sz || ngx_strlen(canon) + 1 > alg_sz) {
        return -1;
    }

    /* Already hex? (XRootD emits lowercase hex for adler32/crc families.) */
    is_hex = (vlen == want_hex);
    for (i = 0; is_hex && i < vlen; i++) {
        if (!isxdigit((unsigned char) val[i])) {
            is_hex = 0;
        }
    }

    if (is_hex) {
        for (i = 0; i < vlen; i++) {
            hex_out[i] = (char) tolower((unsigned char) val[i]);
        }
        hex_out[vlen] = '\0';
    } else {
        /* RFC base64 value → raw bytes → hex. */
        u_char     raw[64];
        ngx_str_t  src, dst;
        static const char hexd[] = "0123456789abcdef";

        if (ngx_base64_decoded_length(vlen) > sizeof(raw)) {
            return -1;
        }
        src.len = vlen;
        src.data = (u_char *) val;
        dst.len = 0;
        dst.data = raw;
        if (ngx_decode_base64(&dst, &src) != NGX_OK || dst.len * 2 != want_hex) {
            return -1;
        }
        for (i = 0; i < dst.len; i++) {
            hex_out[i * 2]     = hexd[raw[i] >> 4];
            hex_out[i * 2 + 1] = hexd[raw[i] & 0x0f];
        }
        hex_out[dst.len * 2] = '\0';
    }

    ngx_memcpy(alg_out, canon, ngx_strlen(canon) + 1);
    return 0;
}


/* xrootd_http_digest_capture — parse a Digest header value * Walk the comma-separated list and keep the first token we can map. */
static void
xrootd_http_digest_capture(xrootd_http_hdrs_t *h, const char *val, size_t len)
{
    const char *p = val;
    const char *end = val + len;

    while (p < end && h->alg[0] == '\0') {
        const char *comma = memchr(p, ',', (size_t) (end - p));
        const char *tok_end = (comma != NULL) ? comma : end;
        const char *eq = memchr(p, '=', (size_t) (tok_end - p));

        if (eq != NULL) {
            const char *name = p;
            size_t      nlen = (size_t) (eq - p);
            const char *v = eq + 1;
            size_t      vlen = (size_t) (tok_end - v);

            while (nlen > 0 && isspace((unsigned char) *name)) { name++; nlen--; }
            while (nlen > 0 && isspace((unsigned char) name[nlen - 1])) { nlen--; }
            while (vlen > 0 && isspace((unsigned char) *v)) { v++; vlen--; }
            while (vlen > 0 && isspace((unsigned char) v[vlen - 1])) { vlen--; }

            (void) xrootd_http_digest_to_hex(name, nlen, v, vlen,
                       h->alg, sizeof(h->alg), h->hex, sizeof(h->hex));
        }
        p = (comma != NULL) ? comma + 1 : end;
    }
}


/* libcurl callbacks */
static size_t
xrootd_http_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    xrootd_http_sink_t *s = userdata;
    size_t              n = size * nmemb;

    if (n == 0) {
        return 0;
    }
    if (xrootd_cache_fd_write_all(s->fd, ptr, n, s->written) != 0) {
        return 0;                       /* short write ⇒ abort the transfer */
    }
    s->written += (off_t) n;
    return n;
}

static size_t
xrootd_http_header_cb(char *buffer, size_t size, size_t nitems, void *userdata)
{
    xrootd_http_hdrs_t *h = userdata;
    size_t              n = size * nitems;
    const char         *p = buffer;
    size_t              len = n;

    /* Trim trailing CRLF. */
    while (len > 0 && (p[len - 1] == '\r' || p[len - 1] == '\n')) {
        len--;
    }

    if (len > 7 && ngx_strncasecmp((u_char *) p, (u_char *) "Digest:", 7) == 0) {
        const char *v = p + 7;
        size_t      vlen = len - 7;
        while (vlen > 0 && isspace((unsigned char) *v)) { v++; vlen--; }
        xrootd_http_digest_capture(h, v, vlen);
    } else if (len > 15
               && ngx_strncasecmp((u_char *) p, (u_char *) "Content-Length:",
                                  15) == 0)
    {
        const char *v = p + 15;
        while (*v == ' ') { v++; }
        h->content_len = (off_t) strtoll(v, NULL, 10);
    }

    return n;
}


int
xrootd_cache_http_get_url(xrootd_cache_fill_t *t, const char *url)
{
    ngx_stream_xrootd_srv_conf_t *conf = t->conf;
    CURL                         *curl;
    CURLcode                      res;
    struct curl_slist            *hdrs = NULL;
    xrootd_http_hdrs_t            caught;
    xrootd_http_sink_t            sink;
    char                          want[96];
    char                          authz[2048];
    char                          token[1536];
    long                          code = 0;
    int                           outfd, n, tls;

    /* TLS verification is keyed off the actual URL scheme so a Pelican director
     * URL (always https) and a plain https origin are handled identically, even
     * when curl later follows a redirect. */
    tls = (ngx_strncasecmp((u_char *) url, (u_char *) "https", 5) == 0);

    outfd = open(t->part_path,
                 O_CREAT | O_TRUNC | O_WRONLY | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW,
                 0644);
    if (outfd < 0) {
        xrootd_cache_set_syserror(t, kXR_IOError, "cache part file open failed");
        return -1;
    }

    curl = curl_easy_init();
    if (curl == NULL) {
        close(outfd);
        unlink(t->part_path);
        xrootd_cache_set_error(t, kXR_NoMemory, 0, "curl_easy_init failed");
        return -1;
    }

    ngx_memzero(&caught, sizeof(caught));
    caught.content_len = -1;
    sink.fd = outfd;
    sink.written = 0;

    /* Solicit a content digest for checksum-on-fill. */
    {
        const char *pref = conf->cache_verify_digest.len
            ? (const char *) conf->cache_verify_digest.data
            : "adler32, crc32c, sha-256";
        (void) snprintf(want, sizeof(want), "Want-Digest: %s", pref);
        hdrs = curl_slist_append(hdrs, want);
    }

    if (xrootd_http_load_bearer(t, token, sizeof(token))) {
        n = snprintf(authz, sizeof(authz), "Authorization: Bearer %s", token);
        if (n > 0 && (size_t) n < sizeof(authz)) {
            hdrs = curl_slist_append(hdrs, authz);
        }
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, xrootd_http_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sink);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, xrootd_http_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &caught);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 8L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long) XROOTD_CACHE_IO_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "nginx-xrootd-cache/1.0");
#ifdef CURLOPT_PROTOCOLS_STR
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
#else
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS,
                     (long) (CURLPROTO_HTTP | CURLPROTO_HTTPS));
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS,
                     (long) (CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif

    if (tls) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        if (conf->cache_origin_cadir.len > 0) {
            curl_easy_setopt(curl, CURLOPT_CAPATH,
                             (char *) conf->cache_origin_cadir.data);
        } else if (conf->trusted_ca.len > 0) {
            curl_easy_setopt(curl, CURLOPT_CAPATH,
                             (char *) conf->trusted_ca.data);
        }

        /* GSI / X.509-proxy client authentication (mutual TLS). When
         * xrootd_cache_origin_proxy is set, present it as the client cert + key —
         * a grid proxy is a single PEM holding the proxy cert, its chain, and the
         * proxy private key, so SSLCERT and SSLKEY both point at it. This brings
         * the http(s):// origin to auth parity with root:// (token OR GSI). */
        if (conf->cache_origin_proxy.len > 0) {
            char proxy[XROOTD_MAX_PATH];

            if (conf->cache_origin_proxy.len < sizeof(proxy)) {
                ngx_memcpy(proxy, conf->cache_origin_proxy.data,
                           conf->cache_origin_proxy.len);
                proxy[conf->cache_origin_proxy.len] = '\0';
                curl_easy_setopt(curl, CURLOPT_SSLCERT, proxy);
                curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
                curl_easy_setopt(curl, CURLOPT_SSLKEY, proxy);
                curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
            }
        }
    }

    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    }

    if (hdrs != NULL) {
        curl_slist_free_all(hdrs);
    }
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || code < 200 || code >= 300) {
        char emsg[512];
        close(outfd);
        unlink(t->part_path);
        (void) snprintf(emsg, sizeof(emsg),
            "cache HTTP origin fetch failed (%.80s, http %ld) for %.150s",
            curl_easy_strerror(res), code, url);
        xrootd_cache_set_error(t,
            (res == CURLE_OPERATION_TIMEDOUT) ? kXR_ServerError : kXR_IOError,
            0, emsg);
        return -1;
    }

    if (fsync(outfd) != 0) {
        close(outfd);
        unlink(t->part_path);
        xrootd_cache_set_syserror(t, kXR_IOError, "cache part fsync failed");
        return -1;
    }
    if (close(outfd) != 0) {
        unlink(t->part_path);
        xrootd_cache_set_syserror(t, kXR_IOError, "cache part close failed");
        return -1;
    }

    if (caught.content_len >= 0) {
        t->file_size = caught.content_len;
    }
    /* Hand the captured digest to the shared verify path. */
    if (caught.alg[0] != '\0') {
        ngx_memcpy(t->origin_cks_alg, caught.alg, sizeof(t->origin_cks_alg));
        ngx_memcpy(t->origin_cks_hex, caught.hex, sizeof(t->origin_cks_hex));
    }

    return 0;
}


int
xrootd_cache_http_download(xrootd_cache_fill_t *t)
{
    ngx_stream_xrootd_srv_conf_t *conf = t->conf;
    char                          url[XROOTD_MAX_PATH + 320];
    const char                   *scheme;
    int                           n, tls;

    tls = (conf->cache_origin_scheme == XROOTD_CACHE_SCHEME_HTTPS
           || conf->cache_origin_tls);
    scheme = tls ? "https" : "http";

    n = snprintf(url, sizeof(url), "%s://%s:%u%s", scheme,
                 (char *) conf->cache_origin_host.data,
                 (unsigned) conf->cache_origin_port, t->clean_path);
    if (n < 0 || (size_t) n >= sizeof(url)) {
        xrootd_cache_set_error(t, kXR_ServerError, 0, "cache origin URL too long");
        return -1;
    }

    return xrootd_cache_http_get_url(t, url);
}
