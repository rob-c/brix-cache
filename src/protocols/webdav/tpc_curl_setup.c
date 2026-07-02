/*
 * tpc_curl_setup.c - extracted concern
 * Phase-38 split of tpc_curl.c; behavior-identical.
 */
#include "tpc_curl_internal.h"


/*
 * tpc_curl_secure — enforce TLS verification and pin the SSRF-validated IP.
 *
 * Two defenses applied to every outbound curl handle (Phase 28 W2):
 *  (1) Explicit CURLOPT_SSL_VERIFYPEER/VERIFYHOST — never rely on curl's
 *      compile-time defaults, which a non-standard build could weaken.
 *  (2) Resolve the URL host once here (under SSRF policy) and pin the result
 *      via CURLOPT_RESOLVE.  curl then connects only to that exact address
 *      rather than performing its own independent DNS lookup, closing the
 *      DNS-rebind TOCTOU window between the policy check and the connect.
 *      TLS SNI/cert validation still uses the original hostname, so pinning
 *      does not weaken certificate checking.
 *
 * Runs in the TPC thread pool, so the blocking getaddrinfo() inside
 * check_dns_pin is safe here.  Returns 0 with *resolve_out set (caller frees
 * the slist after the transfer) on success; -1 when the host is prohibited or
 * unresolvable — the transfer MUST abort.
 */
int
tpc_curl_secure(CURL *curl, ngx_http_xrootd_webdav_loc_conf_t *conf,
    const char *url, ngx_log_t *log, struct curl_slist **resolve_out)
{
    xrootd_net_target_t        tgt;
    xrootd_net_target_policy_t pol;
    ngx_str_t                  url_str;
    char                       pin_ip[128];
    char                       err[256];
    char                       entry[512];   /* "[host]:port:addr" — room for a
                                              * bracketed IPv6/long host + addr */
    uint16_t                   port;
    struct curl_slist         *rs;

    *resolve_out = NULL;

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    url_str.data = (u_char *) url;
    url_str.len  = ngx_strlen(url);

    ngx_memzero(&pol, sizeof(pol));
    pol.require_https      = 1;
    pol.allow_local        = conf->tpc_allow_local;
    pol.allow_private      = conf->tpc_allow_private;
    pol.default_https_port = 443;

    if (xrootd_net_target_parse(NULL, &url_str, &tgt, err, sizeof(err)) != NGX_OK
        || xrootd_net_target_check_dns_pin(&tgt, &pol, pin_ip, sizeof(pin_ip),
                                           err, sizeof(err)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_webdav: TPC egress check blocked \"%s\": %s",
                      url, err);
        return -1;
    }

    port = tgt.has_port ? tgt.port : 443;
    {
        /* curl's CURLOPT_RESOLVE host field must bracket an IPv6 literal
         * ("[::1]:443:addr") to match the bracketed host in an IPv6 URL;
         * tgt.host arrives bare from net_target.  The resolved address (pin_ip)
         * stays bare — curl accepts a bare IPv6 in the address position. */
        char   hostz[256], hostb[288];
        size_t hl = ngx_min(tgt.host.len, sizeof(hostz) - 1);
        ngx_memcpy(hostz, tgt.host.data, hl);
        hostz[hl] = '\0';
        xrootd_format_host(hostz, hostb, sizeof(hostb));
        snprintf(entry, sizeof(entry), "%s:%u:%s",
                 hostb, (unsigned) port, pin_ip);
    }

    rs = curl_slist_append(NULL, entry);
    if (rs == NULL) {
        return -1;
    }
    curl_easy_setopt(curl, CURLOPT_RESOLVE, rs);
    *resolve_out = rs;
    return 0;
}



/* Per-stream write state for multi-stream pull. */

/*
 * Apply URL, TLS credentials, timeout, and forwarded headers to a curl handle.
 * The caller must free *hdrs_out via curl_slist_free_all() after cleanup.
 * Returns 0 on success, -1 on slist OOM.
 */
/*
 * Phase 39 (WS4): bound a stalled / black-holed TPC remote.  Always cap connect
 * time (a connect to a black hole otherwise hangs the thread-pool worker forever)
 * and enable TCP keepalive; optionally abort a transfer that stays below a
 * bytes/sec floor (idle / low-speed) WITHOUT killing a slow-but-progressing one.
 * Pure additive curl configuration — no data-copy cost; the low-speed bound is
 * off unless the operator sets both knobs.
 */
void
tpc_curl_apply_stall_bounds(CURL *curl, ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,
                     XROOTD_TPC_CONNECT_TIMEOUT_SECS);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    if (conf->tpc_low_speed_bytes > 0 && conf->tpc_low_speed_secs > 0) {
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT,
                         (long) conf->tpc_low_speed_bytes);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME,
                         (long) conf->tpc_low_speed_secs);
    }
}


int
tpc_curl_apply_conf(CURL *curl,
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    const char *url, ngx_array_t *transfer_headers, ngx_log_t *log,
    struct curl_slist **hdrs_out, struct curl_slist **resolve_out)
{
    ngx_uint_t         i;
    ngx_str_t         *headers;
    struct curl_slist *hdrs = NULL;

    *resolve_out = NULL;

    curl_easy_setopt(curl, CURLOPT_NOSIGNAL,    1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_URL, url);

#ifdef CURLOPT_PROTOCOLS_STR
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
#else
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, (long) CURLPROTO_HTTPS);
#endif

    /* TLS verification + DNS-rebind pin (W2). */
    if (tpc_curl_secure(curl, conf, url, log, resolve_out) < 0) {
        return -1;
    }

    if (conf->tpc_timeout > 0)
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long) conf->tpc_timeout);
    tpc_curl_apply_stall_bounds(curl, conf);   /* Phase 39 (WS4) */
    if (conf->tpc_cert.len > 0)
        curl_easy_setopt(curl, CURLOPT_SSLCERT,
                         (const char *) conf->tpc_cert.data);
    if (conf->tpc_key.len > 0)
        curl_easy_setopt(curl, CURLOPT_SSLKEY,
                         (const char *) conf->tpc_key.data);
    if (conf->tpc_cafile.len > 0)
        curl_easy_setopt(curl, CURLOPT_CAINFO,
                         (const char *) conf->tpc_cafile.data);
    if (conf->tpc_cadir.len > 0)
        curl_easy_setopt(curl, CURLOPT_CAPATH,
                         (const char *) conf->tpc_cadir.data);

    if (transfer_headers != NULL && transfer_headers->nelts > 0) {
        headers = transfer_headers->elts;
        for (i = 0; i < transfer_headers->nelts; i++) {
            struct curl_slist *next = curl_slist_append(
                hdrs, (const char *) headers[i].data);
            if (next == NULL) {
                if (hdrs) curl_slist_free_all(hdrs);
                *hdrs_out = NULL;
                return -1;
            }
            hdrs = next;
        }
    }

    *hdrs_out = hdrs;
    if (hdrs != NULL) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    }
    return 0;
}


/*
 * Issue a HEAD request to retrieve Content-Length.
 * Returns the size in bytes, or -1 if unknown / request failed.
 */
off_t
tpc_curl_head_size(ngx_log_t *log,
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    const char *url, ngx_array_t *transfer_headers)
{
    CURL              *curl;
    struct curl_slist *hdrs = NULL;
    struct curl_slist *resolve = NULL;
    CURLcode           res;
    off_t              content_length = -1;

    curl = curl_easy_init();
    if (curl == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_webdav: curl_easy_init() failed for HEAD");
        return -1;
    }

    if (tpc_curl_apply_conf(curl, conf, url, transfer_headers, log,
                            &hdrs, &resolve) < 0) {
        if (resolve) curl_slist_free_all(resolve);
        curl_easy_cleanup(curl);
        return -1;
    }
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
#ifdef CURLINFO_CONTENT_LENGTH_DOWNLOAD_T
        curl_off_t cl;
        curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &cl);
        content_length = (cl >= 0) ? (off_t) cl : -1;
#else
        double cl;
        curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &cl);
        content_length = (cl >= 1.0) ? (off_t) cl : -1;
#endif
    } else {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_webdav: HEAD for multi-stream size failed: %s",
                      curl_easy_strerror(res));
    }

    if (hdrs) curl_slist_free_all(hdrs);
    if (resolve) curl_slist_free_all(resolve);
    curl_easy_cleanup(curl);
    return content_length;
}
