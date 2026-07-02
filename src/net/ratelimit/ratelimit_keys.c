/*
 * ratelimit_keys.c — Phase 25 key extraction + directive parsing.
 *
 * Two planes expose identity through different context structs, so a pair of
 * extraction functions produce the canonical "<type>:<value>" key string used
 * for the rbtree lookup.  Anonymous principals (no VO / issuer / DN) fall back
 * to the client IP so unauthenticated bulk clients are always subject to at
 * least an IP-keyed rule (Phase 25 invariant 5).
 *
 * The three directive setters (zone / rate-rule / bandwidth-rule) are shared by
 * the WebDAV and stream command tables; the rule setters locate the per-conf
 * rules array via cmd->offset so one implementation serves both planes.
 */
#include "ratelimit.h"
#include "protocols/webdav/webdav.h"      /* ngx_http_xrootd_webdav_req_ctx_t */


/* key extraction */
/*
 * Emit a "dn:<hash>" key for a (potentially long, PII-bearing) GSI subject DN.
 * WHY hash rather than embed the DN verbatim: the key string is bounded by
 * XROOTD_RL_KEY_LEN and is exposed in dashboard/metrics snapshots, so we never
 * want the raw DN there.  The FNV-1a32 hash is rendered as fixed 8 hex digits
 * (%08xD = zero-padded uppercase 32-bit), giving a stable, short, collision-
 * tolerable bucket id for the same principal.
 */
static void
rl_key_dn_hash(const u_char *dn, size_t dn_len, char *out, size_t out_sz)
{
    uint32_t h = xrootd_rl_hash((const char *) dn, dn_len);
    ngx_snprintf((u_char *) out, out_sz, "dn:%08xD%Z", h);
}

/*
 * Stream-plane key builder: derive the "<type>:<value>" rbtree key for `rule`
 * from the connection's xrootd_ctx_t identity.  Each branch implements the
 * Phase 25 invariant-5 fallback: when the principal lacks the requested
 * dimension (anonymous VO/issuer/DN), fall back to keying on the client IP so
 * an unauthenticated bulk client is still subject to *some* bucket rather than
 * escaping the limiter entirely.  Returns NGX_DECLINED for a VOLUME rule whose
 * prefix does not match `path` (rule simply does not apply here).
 */
ngx_int_t
xrootd_rl_key_stream(xrootd_rl_rule_t *rule, xrootd_ctx_t *ctx,
    const char *path, char *out, size_t out_sz)
{
    switch (rule->key_type) {

    case XROOTD_RL_KEY_VO:
        if (ctx->primary_vo[0] == '\0') {
            ngx_snprintf((u_char *) out, out_sz, "ip:%s%Z", ctx->peer_ip);
        } else {
            ngx_snprintf((u_char *) out, out_sz, "vo:%s%Z", ctx->primary_vo);
        }
        break;

    case XROOTD_RL_KEY_ISSUER:
        if (ctx->identity == NULL || ctx->identity->issuer.len == 0) {
            ngx_snprintf((u_char *) out, out_sz, "ip:%s%Z", ctx->peer_ip);
        } else {
            ngx_snprintf((u_char *) out, out_sz, "iss:%V%Z",
                         &ctx->identity->issuer);
        }
        break;

    case XROOTD_RL_KEY_IP:
        ngx_snprintf((u_char *) out, out_sz, "ip:%s%Z", ctx->peer_ip);
        break;

    case XROOTD_RL_KEY_DN:
        if (ctx->dn[0] == '\0') {
            ngx_snprintf((u_char *) out, out_sz, "ip:%s%Z", ctx->peer_ip);
        } else {
            rl_key_dn_hash((u_char *) ctx->dn, ngx_strlen(ctx->dn),
                           out, out_sz);
        }
        break;

    case XROOTD_RL_KEY_VOLUME:
        /* Prefix match: the rule limits aggregate traffic under one storage
         * path (e.g. "/store/tape").  All requests below the prefix share the
         * single "vol:<prefix>" bucket; non-matching paths decline the rule. */
        if (path == NULL || rule->key_match.len == 0
            || ngx_strncmp(path, rule->key_match.data, rule->key_match.len) != 0)
        {
            return NGX_DECLINED;   /* rule does not apply to this path */
        }
        ngx_snprintf((u_char *) out, out_sz, "vol:%V%Z", &rule->key_match);
        break;

    default:
        return NGX_ERROR;
    }

    /* ngx_snprintf does not guarantee NUL on truncation; force-terminate so the
     * key is always a valid C string for the hash/copy in the zone layer. */
    out[out_sz - 1] = '\0';
    return NGX_OK;
}

/*
 * HTTP/WebDAV-plane key builder — the same dimension-and-fallback logic as
 * xrootd_rl_key_stream(), but reading identity from the WebDAV request ctx and
 * the nginx connection.  DN keying has an extra fallback step: prefer the
 * structured identity DN, then the cert-derived wctx->dn string, then IP.
 * wctx_v is an opaque ngx_http_xrootd_webdav_req_ctx_t* (header avoids the
 * webdav.h include in ratelimit.h) and may be NULL on early-phase requests.
 */
ngx_int_t
xrootd_rl_key_http(xrootd_rl_rule_t *rule, ngx_http_request_t *r,
    void *wctx_v, const char *path, char *out, size_t out_sz)
{
    ngx_http_xrootd_webdav_req_ctx_t *wctx = wctx_v;
    xrootd_identity_t                *id = wctx ? wctx->identity : NULL;
    ngx_str_t                        *ip = &r->connection->addr_text;

    switch (rule->key_type) {

    case XROOTD_RL_KEY_VO:
        if (id == NULL || id->vo_csv.len == 0) {
            ngx_snprintf((u_char *) out, out_sz, "ip:%V%Z", ip);
        } else {
            ngx_snprintf((u_char *) out, out_sz, "vo:%V%Z", &id->vo_csv);
        }
        break;

    case XROOTD_RL_KEY_ISSUER:
        if (id == NULL || id->issuer.len == 0) {
            ngx_snprintf((u_char *) out, out_sz, "ip:%V%Z", ip);
        } else {
            ngx_snprintf((u_char *) out, out_sz, "iss:%V%Z", &id->issuer);
        }
        break;

    case XROOTD_RL_KEY_IP:
        ngx_snprintf((u_char *) out, out_sz, "ip:%V%Z", ip);
        break;

    case XROOTD_RL_KEY_DN:
        /* Two DN sources can carry the subject: the unified identity (token/SSS
         * bridged) and the raw client-cert DN cached on wctx.  Prefer identity,
         * fall back to the cert string, then to IP if the request is anon. */
        if (id != NULL && id->dn.len > 0) {
            rl_key_dn_hash(id->dn.data, id->dn.len, out, out_sz);
        } else if (wctx != NULL && wctx->dn[0] != '\0') {
            rl_key_dn_hash((u_char *) wctx->dn, ngx_strlen(wctx->dn),
                           out, out_sz);
        } else {
            ngx_snprintf((u_char *) out, out_sz, "ip:%V%Z", ip);
        }
        break;

    case XROOTD_RL_KEY_VOLUME:
        if (path == NULL || rule->key_match.len == 0
            || ngx_strncmp(path, rule->key_match.data, rule->key_match.len) != 0)
        {
            return NGX_DECLINED;
        }
        ngx_snprintf((u_char *) out, out_sz, "vol:%V%Z", &rule->key_match);
        break;

    default:
        return NGX_ERROR;
    }

    out[out_sz - 1] = '\0';
    return NGX_OK;
}


/* directive parameter parsing */
/* Parse "key=<type>[:<prefix>]" into rule->key_type / rule->key_match.
 * sizeof("key=")-1 == 4 strips the literal prefix; the value tail is then split
 * on the first ':' into <type> and an optional <prefix> (used only by VOLUME). */
static ngx_int_t
rl_parse_key(ngx_conf_t *cf, ngx_str_t *v, xrootd_rl_rule_t *rule)
{
    ngx_str_t  val = { v->len - (sizeof("key=") - 1),
                       v->data + sizeof("key=") - 1 };
    u_char    *colon;
    ngx_str_t  type = val, prefix = { 0, NULL };

    /* If a ':' is present, narrow `type` to the part before it and point
     * `prefix` at the (non-NUL-terminated) remainder after it. */
    colon = ngx_strlchr(val.data, val.data + val.len, ':');
    if (colon != NULL) {
        type.len   = colon - val.data;
        prefix.data = colon + 1;
        prefix.len  = val.data + val.len - (colon + 1);
    }

    if (type.len == 2 && ngx_strncmp(type.data, "vo", 2) == 0) {
        rule->key_type = XROOTD_RL_KEY_VO;
    } else if (type.len == 6 && ngx_strncmp(type.data, "issuer", 6) == 0) {
        rule->key_type = XROOTD_RL_KEY_ISSUER;
    } else if (type.len == 2 && ngx_strncmp(type.data, "ip", 2) == 0) {
        rule->key_type = XROOTD_RL_KEY_IP;
    } else if (type.len == 2 && ngx_strncmp(type.data, "dn", 2) == 0) {
        rule->key_type = XROOTD_RL_KEY_DN;
    } else if (type.len == 6 && ngx_strncmp(type.data, "volume", 6) == 0) {
        rule->key_type  = XROOTD_RL_KEY_VOLUME;
        rule->key_match = prefix;        /* points into cf->args memory (persists) */
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd rate limit: unknown key \"%V\" (expected"
            " vo|issuer|ip|dn|volume[:<prefix>])", &type);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* Parse "<N>r/s" → requests/s (returns the integer N, or NGX_ERROR). */
static ngx_int_t
rl_parse_req_rate(ngx_str_t *v)
{
    if (v->len < 4 || ngx_strncmp(v->data + v->len - 3, "r/s", 3) != 0) {
        return NGX_ERROR;
    }
    return ngx_atoi(v->data, v->len - 3);
}

/* Parse "<N>[k|m|g]/s" → bytes/s.  Returns NGX_ERROR on bad input.
 * Layout: strip the trailing "/s", then consume an optional binary-unit suffix
 * (k/m/g = 1024^1..3) off the end so ngx_atoi sees only the digits. */
static ssize_t
rl_parse_bw_rate(ngx_str_t *v)
{
    ngx_str_t  num = *v;
    off_t      mult = 1;

    if (v->len < 3 || ngx_strncmp(v->data + v->len - 2, "/s", 2) != 0) {
        return NGX_ERROR;
    }
    num.len = v->len - 2;                         /* drop "/s" */
    switch (num.data[num.len - 1]) {              /* optional unit suffix */
    case 'k': case 'K': mult = 1024;          num.len--; break;
    case 'm': case 'M': mult = 1024 * 1024;   num.len--; break;
    case 'g': case 'G': mult = 1024L * 1024 * 1024; num.len--; break;
    default: break;
    }
    {
        ngx_int_t n = ngx_atoi(num.data, num.len);
        if (n == NGX_ERROR) { return NGX_ERROR; }
        return (ssize_t) ((off_t) n * mult);
    }
}

/* Parse "<N>[k|m|g]" → bytes (burst). */
static ssize_t
rl_parse_size(ngx_str_t *v)
{
    return ngx_parse_size(v);   /* nginx: handles k/m/g suffixes */
}


/* zone directive: xrootd_rate_limit_zone zone=NAME:SIZE */
char *
xrootd_rl_zone_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t  *value = cf->args->elts;
    ngx_str_t   spec, name, sizestr;
    u_char     *colon;
    ssize_t     size;
    ngx_uint_t  i;

    (void) cmd; (void) conf;

    name.len = 0; name.data = NULL;
    sizestr.len = 0; sizestr.data = NULL;

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len > 5
            && ngx_strncmp(value[i].data, "zone=", 5) == 0)
        {
            spec.data = value[i].data + 5;
            spec.len  = value[i].len - 5;
            colon = ngx_strlchr(spec.data, spec.data + spec.len, ':');
            if (colon == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_rate_limit_zone: expected zone=NAME:SIZE");
                return NGX_CONF_ERROR;
            }
            name.data = spec.data;
            name.len  = colon - spec.data;
            sizestr.data = colon + 1;
            sizestr.len  = spec.data + spec.len - (colon + 1);
        }
    }

    if (name.len == 0 || sizestr.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_rate_limit_zone: missing zone=NAME:SIZE");
        return NGX_CONF_ERROR;
    }
    size = rl_parse_size(&sizestr);
    if (size == NGX_ERROR || size <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_rate_limit_zone: bad size \"%V\"", &sizestr);
        return NGX_CONF_ERROR;
    }

    if (xrootd_rl_zone_add(cf, &name, (size_t) size, NULL) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


/* shared rule builder */
/*
 * Shared setter behind both xrootd_rate_limit_rule (is_bw=0) and
 * xrootd_bandwidth_limit (is_bw=1).  Pushes one xrootd_rl_rule_t onto the rules
 * array, parses the zone=/key=/rate=/burst=/nodelay= tokens, applies defaults,
 * and resolves the named zone handle.  is_bw selects whether rate=/burst= are
 * interpreted as bytes/s + byte burst or req/s + request burst.  Using
 * cmd->offset (below) lets the *same* function serve both the WebDAV loc-conf
 * and the stream srv-conf command tables without knowing the struct layout.
 */
static char *
rl_add_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, int is_bw)
{
    ngx_str_t        *value = cf->args->elts;
    ngx_array_t     **rulesp;
    xrootd_rl_rule_t *rule;
    ngx_str_t         zone_name = { 0, NULL };
    ngx_uint_t        i;
    int               have_key = 0, have_rate = 0;

    /* The rules array lives at cmd->offset inside the (loc or srv) conf;
     * create it lazily on the first rule for this conf. */
    rulesp = (ngx_array_t **) ((char *) conf + cmd->offset);
    if (*rulesp == NULL) {
        *rulesp = ngx_array_create(cf->pool, 4, sizeof(xrootd_rl_rule_t));
        if (*rulesp == NULL) { return NGX_CONF_ERROR; }
    }
    rule = ngx_array_push(*rulesp);
    if (rule == NULL) { return NGX_CONF_ERROR; }
    ngx_memzero(rule, sizeof(*rule));

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_str_t *a = &value[i];

        if (a->len > 5 && ngx_strncmp(a->data, "zone=", 5) == 0) {
            zone_name.data = a->data + 5;
            zone_name.len  = a->len - 5;

        } else if (a->len > 4 && ngx_strncmp(a->data, "key=", 4) == 0) {
            if (rl_parse_key(cf, a, rule) != NGX_OK) { return NGX_CONF_ERROR; }
            have_key = 1;

        } else if (a->len > 5 && ngx_strncmp(a->data, "rate=", 5) == 0) {
            ngx_str_t r = { a->len - 5, a->data + 5 };
            if (is_bw) {
                ssize_t bps = rl_parse_bw_rate(&r);
                if (bps == NGX_ERROR) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "xrootd_bandwidth_limit: bad rate \"%V\""
                        " (expected <N>[k|m|g]/s)", &r);
                    return NGX_CONF_ERROR;
                }
                rule->bw_rate = (ngx_uint_t) bps;
            } else {
                ngx_int_t rps = rl_parse_req_rate(&r);
                if (rps == NGX_ERROR || rps <= 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "xrootd_rate_limit_rule: bad rate \"%V\""
                        " (expected <N>r/s)", &r);
                    return NGX_CONF_ERROR;
                }
                /* Stored in milli-requests/s (×1000) so the leaky-bucket core
                 * can do sub-request-per-second fixed-point math without
                 * floats; req_excess in the node is in the same ×1000 unit. */
                rule->req_rate = (ngx_uint_t) rps * 1000;   /* store ×1000 */
            }
            have_rate = 1;

        } else if (a->len > 6 && ngx_strncmp(a->data, "burst=", 6) == 0) {
            ngx_str_t b = { a->len - 6, a->data + 6 };
            if (is_bw) {
                ssize_t sz = rl_parse_size(&b);
                if (sz == NGX_ERROR) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "xrootd_bandwidth_limit: bad burst \"%V\"", &b);
                    return NGX_CONF_ERROR;
                }
                rule->bw_burst = (ngx_uint_t) sz;
            } else {
                ngx_int_t n = ngx_atoi(b.data, b.len);
                if (n == NGX_ERROR) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "xrootd_rate_limit_rule: bad burst \"%V\"", &b);
                    return NGX_CONF_ERROR;
                }
                rule->req_burst = (ngx_uint_t) n;
            }

        } else if (a->len == sizeof("nodelay") - 1
                   && ngx_strncmp(a->data, "nodelay", 7) == 0) {
            rule->nodelay = 1;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd rate limit: unknown parameter \"%V\"", a);
            return NGX_CONF_ERROR;
        }
    }

    if (!have_key || !have_rate || zone_name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd rate limit: zone=, key= and rate= are required");
        return NGX_CONF_ERROR;
    }
    /* Apply burst defaults when the operator omitted burst=.  Bandwidth: one
     * second of rate (smooths bursty transfers); requests: 1 (strict). */
    if (is_bw && rule->bw_burst == 0) {
        rule->bw_burst = rule->bw_rate;       /* default burst = 1s of rate */
    }
    if (!is_bw && rule->req_burst == 0) {
        rule->req_burst = 1;
    }

    /* Bind to a zone declared earlier by xrootd_rate_limit_zone; resolution is
     * by name so http{} and stream{} rules can share one SHM zone. */
    rule->zone = xrootd_rl_zone_get(&zone_name);
    if (rule->zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd rate limit: unknown zone \"%V\" (declare it with"
            " xrootd_rate_limit_zone first)", &zone_name);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

char *
xrootd_rl_rule_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return rl_add_rule(cf, cmd, conf, 0);
}

char *
xrootd_rl_bw_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return rl_add_rule(cf, cmd, conf, 1);
}

/* xrootd_concurrency_limit zone=NAME key=<type> limit=N (W7) */
/*
 * Setter for xrootd_concurrency_limit — a non-leaky cap on the number of
 * simultaneously in-flight requests per principal (rule->req_conc), distinct
 * from the rate/bandwidth leaky buckets above.  Same cmd->offset/lazy-array and
 * zone-resolution pattern as rl_add_rule(); only the parsed parameters differ
 * (limit= instead of rate=/burst=).
 */
char *
xrootd_rl_conc_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t        *value = cf->args->elts;
    ngx_array_t     **rulesp;
    xrootd_rl_rule_t *rule;
    ngx_str_t         zone_name = { 0, NULL };
    ngx_uint_t        i;
    int               have_key = 0, have_limit = 0;

    rulesp = (ngx_array_t **) ((char *) conf + cmd->offset);
    if (*rulesp == NULL) {
        *rulesp = ngx_array_create(cf->pool, 4, sizeof(xrootd_rl_rule_t));
        if (*rulesp == NULL) { return NGX_CONF_ERROR; }
    }
    rule = ngx_array_push(*rulesp);
    if (rule == NULL) { return NGX_CONF_ERROR; }
    ngx_memzero(rule, sizeof(*rule));

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_str_t *a = &value[i];

        if (a->len > 5 && ngx_strncmp(a->data, "zone=", 5) == 0) {
            zone_name.data = a->data + 5;
            zone_name.len  = a->len - 5;

        } else if (a->len > 4 && ngx_strncmp(a->data, "key=", 4) == 0) {
            if (rl_parse_key(cf, a, rule) != NGX_OK) { return NGX_CONF_ERROR; }
            have_key = 1;

        } else if (a->len > 6 && ngx_strncmp(a->data, "limit=", 6) == 0) {
            ngx_int_t n = ngx_atoi(a->data + 6, a->len - 6);
            if (n == NGX_ERROR || n <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_concurrency_limit: bad limit \"%V\"", a);
                return NGX_CONF_ERROR;
            }
            rule->req_conc = (ngx_uint_t) n;
            have_limit = 1;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_concurrency_limit: unknown parameter \"%V\"", a);
            return NGX_CONF_ERROR;
        }
    }

    if (!have_key || !have_limit || zone_name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_concurrency_limit: zone=, key= and limit= are required");
        return NGX_CONF_ERROR;
    }

    rule->zone = xrootd_rl_zone_get(&zone_name);
    if (rule->zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_concurrency_limit: unknown zone \"%V\" (declare it with"
            " xrootd_rate_limit_zone first)", &zone_name);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}
