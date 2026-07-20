/*
 * api_admin_config.c - extracted concern
 * Phase-38 split of api_admin.c; behavior-identical.
 */
#include "dashboard_api_admin_internal.h"


/*
 * WHAT: Top-level router for the admin write API ("/brix/api/v1/admin/...").
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


/* Dedicated admin-API rate-limit zone: one segment shared by every dashboard
 * location.  Per-IP nodes are ~200 bytes, so 128 KiB holds hundreds of client
 * IPs with LRU eviction beyond that — ample for an operator-facing surface. */
#define BRIX_ADMIN_RL_ZONE_SIZE  (128 * 1024)


/*
 * ---- Directive setter for `brix_admin_rate_limit` ----
 *
 * WHAT: Parses `brix_admin_rate_limit off` (disable the throttle) or
 *       `brix_admin_rate_limit <writes/min> [<reads/min>]` into the loc-conf
 *       per-minute fields.  Returns NGX_CONF_OK or a config-error string.
 *
 * WHY:  The admin API must not be a DoS vector, but sites legitimately poll it
 *       hard under load — so the limits are operator-tunable per method class,
 *       with a value of 0 meaning "unlimited" for that class.
 *
 * HOW:  1. Reject a duplicate declaration.
 *       2. A single literal "off" arg clears the enable flag and returns.
 *       3. Parse the mandatory writes/min; parse reads/min when present
 *          (absent leaves it UNSET so the merge default applies).
 */
char *
brix_admin_set_rate_limit(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_dashboard_loc_conf_t *lcf = conf;
    ngx_str_t  *value = cf->args->elts;
    ngx_int_t   per_min;

    (void) cmd;

    if (lcf->admin_rl_enable != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    if (value[1].len == 3 && ngx_strncmp(value[1].data, "off", 3) == 0) {
        if (cf->args->nelts != 2) {
            return "\"off\" takes no further arguments";
        }
        lcf->admin_rl_enable = 0;
        return NGX_CONF_OK;
    }

    per_min = ngx_atoi(value[1].data, value[1].len);
    if (per_min == NGX_ERROR) {
        return "first argument must be \"off\" or write requests/minute";
    }
    lcf->admin_rl_write_pm = (ngx_uint_t) per_min;

    if (cf->args->nelts == 3) {
        per_min = ngx_atoi(value[2].data, value[2].len);
        if (per_min == NGX_ERROR) {
            return "second argument must be read requests/minute";
        }
        lcf->admin_rl_read_pm = (ngx_uint_t) per_min;
    }

    lcf->admin_rl_enable = 1;
    return NGX_CONF_OK;
}


/*
 * ---- Build one per-IP admin throttle rule ----
 *
 * WHAT: Fills `rule` as a per-IP leaky-bucket request-rate rule draining at
 *       `per_min` requests/minute against `zone`.  per_min == 0 leaves
 *       req_rate 0, which brix_rl_check treats as "no limit".
 *
 * WHY:  The read and write rules differ only in their per-minute value; one
 *       builder keeps the fixed-point conversion and burst policy in one place.
 *
 * HOW:  1. Zero the rule and bind zone + IP key dimension.
 *       2. Convert requests/minute to the limiter's req/s × BRIX_RL_REQ_SCALE
 *          fixed point.
 *       3. Grant a burst of a quarter-minute's traffic (min 10) so bursty but
 *          legitimate clients (dashboard page loads, scripted sweeps) are not
 *          clipped by the steady-state rate.
 */
static void
admin_rl_build_rule(brix_rl_rule_t *rule, ngx_uint_t per_min,
    brix_rl_zone_t *zone)
{
    ngx_memzero(rule, sizeof(*rule));
    rule->key_type = BRIX_RL_KEY_IP;
    rule->zone     = zone;
    rule->req_rate = per_min * BRIX_RL_REQ_SCALE / 60;
    rule->req_burst = per_min / 4 > 10 ? per_min / 4 : 10;
}


/*
 * ---- Finalize the admin API throttle at config merge time ----
 *
 * WHAT: Declares (or re-attaches) the dedicated "brix_admin_api" SHM zone and
 *       builds the read/write per-IP rules from the merged per-minute values.
 *       Returns NGX_OK, or NGX_ERROR when the zone cannot be created.
 *
 * WHY:  The throttle is on by default with no configuration, so the zone must
 *       be provisioned by the module itself rather than by an operator
 *       `brix_rate_limit_zone` declaration; brix_rl_zone_add is idempotent, so
 *       multiple dashboard locations share the one segment.
 *
 * HOW:  1. brix_rl_zone_add the fixed-name zone (reuses an existing handle).
 *       2. Build the write and read rules bound to that zone.
 */
ngx_int_t
brix_admin_rl_finalize(ngx_conf_t *cf, ngx_http_brix_dashboard_loc_conf_t *lcf)
{
    static ngx_str_t  zone_name = ngx_string("brix_admin_api");
    brix_rl_zone_t *zone = NULL;

    if (brix_rl_zone_add(cf, &zone_name, BRIX_ADMIN_RL_ZONE_SIZE, &zone)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    admin_rl_build_rule(&lcf->admin_rl_write, lcf->admin_rl_write_pm, zone);
    admin_rl_build_rule(&lcf->admin_rl_read, lcf->admin_rl_read_pm, zone);
    return NGX_OK;
}
