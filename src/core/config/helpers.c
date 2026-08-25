/*
 * helpers.c — startup config-validation helpers (path checks + ngx_str_t copy).
 * Each function is documented at its definition below.
 */

#include "config.h"

/* Validate a configured path at startup: existence (stat), type
 * (file/dir/either), and access mode (R/W/X_OK).  A NULL/empty path is
 * optional and skipped.  Returns NGX_OK, or NGX_ERROR with an emerg log
 * naming the failure. */
ngx_int_t
brix_validate_path(ngx_conf_t *cf, const char *label, const ngx_str_t *path,
    brix_path_kind_t kind, int access_mode)
{
    struct stat st;

    if (path == NULL || path->len == 0 || path->data == NULL) {
        return NGX_OK;
    }

    if (stat((char *) path->data, &st) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "brix: %s path \"%s\" is not accessible",
                           label, path->data);
        return NGX_ERROR;
    }

    switch (kind) {
    case BRIX_PATH_REGULAR_FILE:
        if (!S_ISREG(st.st_mode)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "brix: %s path \"%s\" must be a regular file",
                               label, path->data);
            return NGX_ERROR;
        }
        break;

    case BRIX_PATH_DIRECTORY:
        if (!S_ISDIR(st.st_mode)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "brix: %s path \"%s\" must be a directory",
                               label, path->data);
            return NGX_ERROR;
        }
        break;

    case BRIX_PATH_FILE_OR_DIRECTORY:
        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "brix: %s path \"%s\" must be a file or directory",
                               label, path->data);
            return NGX_ERROR;
        }
        break;
    }

    if (access_mode != 0 && access((char *) path->data, access_mode) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "brix: %s path \"%s\" failed permission check",
                           label, path->data);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Copy an ngx_str_t into a NUL-terminated C string in cf->pool (ngx_str_t is
 * not NUL-terminated, so strtol/strchr/etc. need this).  Returns NGX_CONF_OK,
 * or NGX_CONF_ERROR on allocation failure. */
char *
brix_copy_conf_string(ngx_conf_t *cf, const ngx_str_t *src, ngx_str_t *dst)
{
    dst->data = ngx_pnalloc(cf->pool, src->len + 1);
    if (dst->data == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memcpy(dst->data, src->data, src->len);
    dst->data[src->len] = '\0';
    dst->len = src->len;
    return NGX_CONF_OK;
}

/* Resolve a host:port directive argument into a pool-allocated ngx_addr_t
 * (first resolved address; the port must be explicit — no default).  Shared
 * by the handoff/relay upstream directives.  Returns NULL on failure; a
 * resolve failure is logged with the directive's name. */
ngx_addr_t *
brix_conf_parse_addr(ngx_conf_t *cf, ngx_str_t *spec, const char *directive)
{
    ngx_url_t    url;
    ngx_addr_t  *addr;

    ngx_memzero(&url, sizeof(url));
    url.url = *spec;
    url.default_port = 0;

    if (ngx_parse_url(cf->pool, &url) != NGX_OK || url.no_port
        || url.naddrs == 0 || url.addrs == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "%s: could not resolve host:port in \"%V\"", directive, spec);
        return NULL;
    }

    addr = ngx_pcalloc(cf->pool, sizeof(ngx_addr_t));
    if (addr == NULL) {
        return NULL;
    }
    addr->sockaddr = ngx_pnalloc(cf->pool, url.addrs[0].socklen);
    if (addr->sockaddr == NULL) {
        return NULL;
    }
    ngx_memcpy(addr->sockaddr, url.addrs[0].sockaddr, url.addrs[0].socklen);
    addr->socklen = url.addrs[0].socklen;
    addr->name = url.addrs[0].name;
    return addr;
}

/* Whole-directive worker behind the single-argument upstream directives
 * (`brix_http_handoff host:port`, `brix_transparent_proxy host:port`):
 * duplicate check on *slot, record the raw spec in *name, resolve it via
 * brix_conf_parse_addr, and log the configured target.  The directive's own
 * name (cmd->name) labels both messages. */
char *
brix_conf_upstream_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    ngx_str_t *name, ngx_addr_t **slot)
{
    ngx_str_t *value = cf->args->elts;

    if (*slot != NULL) {
        return "is duplicate";
    }

    *name = value[1];
    *slot = brix_conf_parse_addr(cf, &value[1], (const char *) cmd->name.data);
    if (*slot == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: %V upstream configured: %V", &cmd->name, &value[1]);
    return NGX_CONF_OK;
}

/* brix_conf_set_backend_sss_keytab — `brix_backend_sss_keytab <path>` setter.
 *
 * WHAT: Store the identity-injection keytab path (plain str slot) and
 *       load-validate it immediately with the same loader the SSS *auth*
 *       keytabs go through (existence, regular file, private permissions,
 *       parseable keys).
 * WHY:  The delegation gate signs per-caller SSS credentials with this keytab
 *       at request time; a missing/world-readable/garbage keytab must fail
 *       `nginx -t`, not turn into a fleet-wide runtime deny (fail-closed but
 *       diagnosed at config load).  Phase-70 §5.6 / P90-70.3.
 * HOW:  ngx_conf_set_str_slot for storage (conf tokens are NUL-terminated, so
 *       the stored bytes are directly usable as a C path at request time),
 *       then brix_sss_load_keytab on the stored value; the parsed key array is
 *       discarded — it lives in cf->pool and only proves loadability. */
char *
brix_conf_set_backend_sss_keytab(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t    *path;
    ngx_array_t  *keys;
    char         *rv;

    rv = ngx_conf_set_str_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    path = (ngx_str_t *) ((char *) conf + cmd->offset);
    if (brix_sss_load_keytab(cf, path, &keys) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* brix_conf_set_backend_sts_endpoint — `brix_backend_s3_sts_endpoint <url>`
 * setter (phase-70 §5.5 origin leg; the §6 invariant that trust config is
 * validated at LOAD, not first use — the residual the phase-88 audit flagged,
 * mirroring the token-exchange endpoint).
 *
 * WHAT: Store the STS endpoint (plain str slot) and validate its shape at
 *       config time.
 * WHY:  The value is SigV4-signed then handed to libcurl's CURLOPT_URL verbatim
 *       (auth/s3/sts_http.c) and parsed for the "host" header by
 *       sts_host_from_url() (auth/s3/sts.c); a malformed endpoint would only
 *       surface as every S3 STS exchange fail-closing at first use.
 * HOW:  Require an http:// or https:// scheme with a non-empty host (the STS
 *       client pins CURLOPT_PROTOCOLS to http,https — SigV4 never transmits the
 *       secret, so a lab MinIO STS over http is legitimate, unlike the
 *       HTTPS-only exchange endpoint) and no whitespace/control bytes. */
char *
brix_conf_set_backend_sts_endpoint(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char       *rv;
    ngx_str_t  *ep;
    size_t      scheme;
    ngx_uint_t  i;

    rv = ngx_conf_set_str_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }
    ep = (ngx_str_t *) ((char *) conf + cmd->offset);

    if (ep->len > sizeof("https://") - 1
        && ngx_strncasecmp(ep->data, (u_char *) "https://", 8) == 0) {
        scheme = sizeof("https://") - 1;
    } else if (ep->len > sizeof("http://") - 1
        && ngx_strncasecmp(ep->data, (u_char *) "http://", 7) == 0) {
        scheme = sizeof("http://") - 1;
    } else {
        scheme = 0;
    }

    if (scheme == 0 || ep->data[scheme] == '/') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_backend_s3_sts_endpoint: \"%V\" is not an http:// or "
            "https:// URL with a host — it is SigV4-signed and handed to the "
            "STS client verbatim, so a malformed endpoint could never be "
            "reached", ep);
        return NGX_CONF_ERROR;
    }
    for (i = 0; i < ep->len; i++) {
        if (ep->data[i] <= ' ' || ep->data[i] == 0x7f) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_backend_s3_sts_endpoint: whitespace or control byte at "
                "offset %ui", i);
            return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}
