/*
 * api_admin_config.c - extracted concern
 * Phase-38 split of api_admin.c; behavior-identical.
 */
#include "dashboard_api_admin_internal.h"


/*
 * WHAT: Top-level router for the admin write API ("/xrootd/api/v1/admin/...").
 * WHY:  Authentication is enforced HERE, once, before any route is considered —
 *       every mutating handler below assumes the caller is already authorized.
 * HOW:  Auth first (403 + audit on failure), then match the resource (cluster
 *       registry vs dynamic proxy pool) and dispatch by HTTP method. Body-bearing
 *       routes go through brix_admin_read_body (async); the rest run inline.
 *       Unknown resource -> 404, wrong method on a known resource -> 405.
 */
/* POST body handler: flip the io_uring runtime kill switch.  Body {"enabled":
 * bool} — false disables io_uring fleet-wide on every worker's next op (the
 * no-reload CVE-response switch); true re-enables it.  404 if io_uring was not
 * enabled in the config (no SHM flag to flip). */
ngx_int_t
admin_io_uring_set(ngx_http_request_t *r, json_t *body)
{
    json_t *en = json_object_get(body, "enabled");
    int     enabled;

    if (!json_is_boolean(en)) {
        admin_audit(r, "io_uring", NULL, "bad_request");
        return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "missing_field");
    }
    enabled = json_is_true(en);

    if (brix_uring_killswitch_set(enabled ? 0 : 1) != NGX_OK) {
        admin_audit(r, "io_uring", NULL, "not_enabled");
        return admin_send_error(r, NGX_HTTP_NOT_FOUND, "io_uring_not_enabled");
    }

    admin_audit(r, "io_uring", enabled ? "enable" : "disable", "ok");
    {
        json_t *root = json_object();
        if (root == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        dashboard_json_set_schema(root);
        json_object_set_new(root, "result",
                            json_string(enabled ? "enabled" : "disabled"));
        return dashboard_json_send(r, NGX_HTTP_OK, root);
    }
}


/* GET /admin/io_uring: report whether the kill switch currently disables it. */
ngx_int_t
admin_io_uring_get(ngx_http_request_t *r)
{
    json_t *root = json_object();

    if (root == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    dashboard_json_set_schema(root);
    json_object_set_new(root, "disabled",
                        json_boolean(brix_uring_killswitch_get() != 0));
    return dashboard_json_send(r, NGX_HTTP_OK, root);
}


/* Directive setter for `brix_admin_allow <cidr>...`: append each CIDR arg to
 * the loc-conf allowlist array (created lazily). NGX_DONE from ngx_ptocidr means
 * the address had non-zero host bits, which is a warning, not an error. */
char *
brix_admin_set_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_dashboard_loc_conf_t *lcf = conf;
    ngx_str_t  *value = cf->args->elts;
    ngx_uint_t  i;

    (void) cmd;

    if (lcf->admin_allow == NULL) {
        lcf->admin_allow = ngx_array_create(cf->pool, cf->args->nelts - 1,
                                            sizeof(ngx_cidr_t));
        if (lcf->admin_allow == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_cidr_t *cidr = ngx_array_push(lcf->admin_allow);
        ngx_int_t   rc;
        if (cidr == NULL) {
            return NGX_CONF_ERROR;
        }
        rc = ngx_ptocidr(&value[i], cidr);
        if (rc == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid CIDR \"%V\" in brix_admin_allow",
                               &value[i]);
            return NGX_CONF_ERROR;
        }
        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "low address bits of \"%V\" in brix_admin_allow were ignored",
                &value[i]);
        }
    }
    return NGX_CONF_OK;
}


/*
 * WHAT: Directive setter for `brix_admin_secret <file>`: load the bearer token
 *       from a file at config time.
 * WHY:  Keeping the secret in a file (not inline in nginx.conf) limits exposure;
 *       the transient stack copy is OPENSSL_cleanse'd on every exit path so it
 *       does not linger in memory after parsing.
 * HOW:  Read the file, strip trailing whitespace/newlines, reject empty or
 *       sub-ADMIN_SECRET_MIN tokens (brute-force resistance), then copy the
 *       trimmed token into the pool.
 */
char *
brix_admin_set_secret(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_dashboard_loc_conf_t *lcf = conf;
    ngx_str_t   *value = cf->args->elts;
    ngx_str_t    path = value[1];
    ngx_file_t   file;
    u_char       rbuf[ADMIN_SECRET_MAX];
    ssize_t      n;
    size_t       len;

    (void) cmd;

    if (lcf->admin_secret.len > 0) {
        return "is duplicate";
    }
    if (ngx_conf_full_name(cf->cycle, &path, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&file, sizeof(file));
    file.name = path;
    file.log  = cf->log;
    file.fd   = ngx_open_file(path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "brix_admin_secret: cannot open \"%V\"", &path);
        return NGX_CONF_ERROR;
    }

    n = ngx_read_file(&file, rbuf, sizeof(rbuf), 0);
    ngx_close_file(file.fd);
    if (n <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_admin_secret: \"%V\" is empty or unreadable",
                           &path);
        return NGX_CONF_ERROR;
    }

    /* Trim trailing whitespace/newlines. */
    len = (size_t) n;
    while (len > 0 && (rbuf[len - 1] == '\n' || rbuf[len - 1] == '\r'
                       || rbuf[len - 1] == ' ' || rbuf[len - 1] == '\t')) {
        len--;
    }
    if (len == 0) {
        OPENSSL_cleanse(rbuf, sizeof(rbuf));
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_admin_secret: \"%V\" contains no token",
                           &path);
        return NGX_CONF_ERROR;
    }
    /* W6/E2 — reject trivially short secrets that invite brute force. */
    if (len < ADMIN_SECRET_MIN) {
        OPENSSL_cleanse(rbuf, sizeof(rbuf));
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_admin_secret: \"%V\" token is too short "
                           "(%uz bytes; need >= %d)", &path, len,
                           (int) ADMIN_SECRET_MIN);
        return NGX_CONF_ERROR;
    }

    lcf->admin_secret.data = ngx_pnalloc(cf->pool, len);
    if (lcf->admin_secret.data == NULL) {
        OPENSSL_cleanse(rbuf, sizeof(rbuf));
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(lcf->admin_secret.data, rbuf, len);
    lcf->admin_secret.len = len;
    /* W6/F1 — scrub the transient stack copy of the secret. */
    OPENSSL_cleanse(rbuf, sizeof(rbuf));
    return NGX_CONF_OK;
}
