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
#include "protocols/webdav/webdav.h"      /* ngx_http_brix_webdav_req_ctx_t */


/* key extraction */
/*
 * Emit a "dn:<hash>" key for a (potentially long, PII-bearing) GSI subject DN.
 * WHY hash rather than embed the DN verbatim: the key string is bounded by
 * BRIX_RL_KEY_LEN and is exposed in dashboard/metrics snapshots, so we never
 * want the raw DN there.  The FNV-1a32 hash is rendered as fixed 8 hex digits
 * (%08xD = zero-padded uppercase 32-bit), giving a stable, short, collision-
 * tolerable bucket id for the same principal.
 */
static void
rl_key_dn_hash(const u_char *dn, size_t dn_len, char *out, size_t out_sz)
{
    uint32_t h = brix_rl_hash((const char *) dn, dn_len);
    ngx_snprintf((u_char *) out, out_sz, "dn:%08xD%Z", h);
}

/*
 * Stream-plane key builder: derive the "<type>:<value>" rbtree key for `rule`
 * from the connection's brix_ctx_t identity.  Each branch implements the
 * Phase 25 invariant-5 fallback: when the principal lacks the requested
 * dimension (anonymous VO/issuer/DN), fall back to keying on the client IP so
 * an unauthenticated bulk client is still subject to *some* bucket rather than
 * escaping the limiter entirely.  Returns NGX_DECLINED for a VOLUME rule whose
 * prefix does not match `path` (rule simply does not apply here).
 */
ngx_int_t
brix_rl_key_stream(brix_rl_rule_t *rule, brix_ctx_t *ctx,
    const char *path, char *out, size_t out_sz)
{
    switch (rule->key_type) {

    case BRIX_RL_KEY_VO:
        if (ctx->login.primary_vo[0] == '\0') {
            ngx_snprintf((u_char *) out, out_sz, "ip:%s%Z", ctx->login.peer_ip);
        } else {
            ngx_snprintf((u_char *) out, out_sz, "vo:%s%Z", ctx->login.primary_vo);
        }
        break;

    case BRIX_RL_KEY_ISSUER:
        if (ctx->identity == NULL || ctx->identity->issuer.len == 0) {
            ngx_snprintf((u_char *) out, out_sz, "ip:%s%Z", ctx->login.peer_ip);
        } else {
            ngx_snprintf((u_char *) out, out_sz, "iss:%V%Z",
                         &ctx->identity->issuer);
        }
        break;

    case BRIX_RL_KEY_IP:
        ngx_snprintf((u_char *) out, out_sz, "ip:%s%Z", ctx->login.peer_ip);
        break;

    case BRIX_RL_KEY_DN:
        if (ctx->login.dn[0] == '\0') {
            ngx_snprintf((u_char *) out, out_sz, "ip:%s%Z", ctx->login.peer_ip);
        } else {
            rl_key_dn_hash((u_char *) ctx->login.dn, ngx_strlen(ctx->login.dn),
                           out, out_sz);
        }
        break;

    case BRIX_RL_KEY_VOLUME:
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

/* rl_key_req_t (the resolved-identity bundle passed to brix_rl_key_http) is
 * declared in ratelimit.h so ratelimit_http.c can build the literal directly.
 * `wctx` is void* there to keep webdav.h out of the header; the branch helpers
 * below cast it to ngx_http_brix_webdav_req_ctx_t* where they read the cert DN. */

/* ---- Derive the DN key for an HTTP request, with the two-source fallback ----
 *
 * WHAT: Writes a "dn:<hash>" (or IP fallback) key into `out`.  Prefers the
 * unified identity DN, then the cert-derived wctx->dn string, then the client IP
 * when the request is anonymous.
 *
 * WHY: DN keying carries an extra fallback step over the other dimensions; the
 * unified identity (token/SSS bridged) and the raw client-cert DN cached on wctx
 * can each independently carry the subject.  Splitting it out keeps the main
 * switch flat.
 *
 * HOW: (1) identity DN present → hash it; (2) else cert DN present → hash it;
 * (3) else fall back to the IP key.
 */
static void
rl_key_http_dn(const rl_key_req_t *req, char *out, size_t out_sz)
{
    ngx_http_brix_webdav_req_ctx_t *wctx = req->wctx;

    if (req->id != NULL && req->id->dn.len > 0) {
        rl_key_dn_hash(req->id->dn.data, req->id->dn.len, out, out_sz);
    } else if (wctx != NULL && wctx->dn[0] != '\0') {
        rl_key_dn_hash((u_char *) wctx->dn, ngx_strlen(wctx->dn),
                       out, out_sz);
    } else {
        ngx_snprintf((u_char *) out, out_sz, "ip:%V%Z", req->ip);
    }
}

/* ---- Build the "<type>:<value>" key for one HTTP rule dimension ----
 *
 * WHAT: Emits the rbtree key for `rule->key_type` into `out`.  Returns NGX_OK on
 * success, NGX_DECLINED for a VOLUME rule whose prefix does not match the path,
 * and NGX_ERROR for an unknown key type.
 *
 * WHY: Isolates the per-key-type branch logic from brix_rl_key_http()'s frozen
 * six-argument public shell so the derivation reads as one small switch over an
 * explicit, already-resolved identity struct.  Each anon branch keeps the Phase
 * 25 invariant-5 IP fallback so an unauthenticated client is still bucketed.
 *
 * HOW: switch on key_type — VO/ISSUER fall back to IP when the dimension is
 * absent; IP is unconditional; DN defers to rl_key_http_dn(); VOLUME prefix-
 * matches `path` or declines.
 */
static ngx_int_t
rl_key_http_derive(brix_rl_rule_t *rule, const rl_key_req_t *req,
    char *out, size_t out_sz)
{
    switch (rule->key_type) {

    case BRIX_RL_KEY_VO:
        if (req->id == NULL || req->id->vo_csv.len == 0) {
            ngx_snprintf((u_char *) out, out_sz, "ip:%V%Z", req->ip);
        } else {
            ngx_snprintf((u_char *) out, out_sz, "vo:%V%Z", &req->id->vo_csv);
        }
        return NGX_OK;

    case BRIX_RL_KEY_ISSUER:
        if (req->id == NULL || req->id->issuer.len == 0) {
            ngx_snprintf((u_char *) out, out_sz, "ip:%V%Z", req->ip);
        } else {
            ngx_snprintf((u_char *) out, out_sz, "iss:%V%Z", &req->id->issuer);
        }
        return NGX_OK;

    case BRIX_RL_KEY_IP:
        ngx_snprintf((u_char *) out, out_sz, "ip:%V%Z", req->ip);
        return NGX_OK;

    case BRIX_RL_KEY_DN:
        rl_key_http_dn(req, out, out_sz);
        return NGX_OK;

    case BRIX_RL_KEY_VOLUME:
        if (req->path == NULL || rule->key_match.len == 0
            || ngx_strncmp(req->path, rule->key_match.data,
                           rule->key_match.len) != 0)
        {
            return NGX_DECLINED;
        }
        ngx_snprintf((u_char *) out, out_sz, "vol:%V%Z", &rule->key_match);
        return NGX_OK;

    default:
        return NGX_ERROR;
    }
}

/*
 * HTTP/WebDAV-plane key builder — the same dimension-and-fallback logic as
 * brix_rl_key_stream(), but reading identity from a caller-resolved rl_key_req_t
 * bundle instead of the WebDAV ctx and connection directly.  DN keying has an
 * extra fallback step: prefer the structured identity DN, then the cert-derived
 * wctx->dn string, then IP.  The caller (ratelimit_http.c) hoists the
 * side-effecting lookups (wctx->identity, connection addr) into `req` before the
 * call; the branch logic lives in rl_key_http_derive().
 */
ngx_int_t
brix_rl_key_http(brix_rl_rule_t *rule, const rl_key_req_t *req,
    char *out, size_t out_sz)
{
    ngx_int_t rc = rl_key_http_derive(rule, req, out, out_sz);

    if (rc != NGX_OK) {
        return rc;
    }
    out[out_sz - 1] = '\0';
    return NGX_OK;
}


/* directive parameter parsing */
/* Parse "key=<type>[:<prefix>]" into rule->key_type / rule->key_match.
 * sizeof("key=")-1 == 4 strips the literal prefix; the value tail is then split
 * on the first ':' into <type> and an optional <prefix> (used only by VOLUME). */
static ngx_int_t
rl_parse_key(ngx_conf_t *cf, ngx_str_t *v, brix_rl_rule_t *rule)
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
        rule->key_type = BRIX_RL_KEY_VO;
    } else if (type.len == 6 && ngx_strncmp(type.data, "issuer", 6) == 0) {
        rule->key_type = BRIX_RL_KEY_ISSUER;
    } else if (type.len == 2 && ngx_strncmp(type.data, "ip", 2) == 0) {
        rule->key_type = BRIX_RL_KEY_IP;
    } else if (type.len == 2 && ngx_strncmp(type.data, "dn", 2) == 0) {
        rule->key_type = BRIX_RL_KEY_DN;
    } else if (type.len == 6 && ngx_strncmp(type.data, "volume", 6) == 0) {
        rule->key_type  = BRIX_RL_KEY_VOLUME;
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


/* zone directive: brix_rate_limit_zone zone=NAME:SIZE */
char *
brix_rl_zone_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
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
                    "brix_rate_limit_zone: expected zone=NAME:SIZE");
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
            "brix_rate_limit_zone: missing zone=NAME:SIZE");
        return NGX_CONF_ERROR;
    }
    size = rl_parse_size(&sizestr);
    if (size == NGX_ERROR || size <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_rate_limit_zone: bad size \"%V\"", &sizestr);
        return NGX_CONF_ERROR;
    }

    if (brix_rl_zone_add(cf, &name, (size_t) size, NULL) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


/* shared rule builder */
/*
 * Mutable accumulator threaded through the per-token parsers of a rule
 * directive.
 *
 * WHY: A rule setter fills one brix_rl_rule_t plus three bits of side state (the
 * zone name and the required-token presence flags) as it walks the argument
 * list.  Bundling them into one struct keeps each token parser under the
 * five-parameter cap and makes the "what a token may mutate" surface explicit.
 * `have_extra` is the second required flag — have_rate for rate/bandwidth rules,
 * have_limit for concurrency rules.
 */
typedef struct {
    brix_rl_rule_t *rule;
    ngx_str_t       zone_name;
    int             have_key;
    int             have_extra;
} rl_rule_parse_t;

/* ---- Lazily create the per-conf rules array and push one zeroed rule ----
 *
 * WHAT: Resolves the `ngx_array_t*` living at cmd->offset inside `conf`,
 * creating it on first use, then pushes and zero-initialises one
 * brix_rl_rule_t.  Returns the new rule via *out_rule, or NGX_CONF_ERROR on
 * allocation failure.
 *
 * WHY: All three rate/bandwidth/concurrency setters share this exact prologue.
 * Using cmd->offset lets one implementation serve both the WebDAV loc-conf and
 * the stream srv-conf command tables without knowing the struct layout.
 *
 * HOW: (1) compute rulesp from conf+cmd->offset; (2) create the array lazily;
 * (3) push + memzero the rule.
 */
static char *
rl_rule_push(ngx_conf_t *cf, ngx_command_t *cmd, void *conf,
    brix_rl_rule_t **out_rule)
{
    ngx_array_t   **rulesp = (ngx_array_t **) ((char *) conf + cmd->offset);
    brix_rl_rule_t *rule;

    if (*rulesp == NULL) {
        *rulesp = ngx_array_create(cf->pool, 4, sizeof(brix_rl_rule_t));
        if (*rulesp == NULL) { return NGX_CONF_ERROR; }
    }
    rule = ngx_array_push(*rulesp);
    if (rule == NULL) { return NGX_CONF_ERROR; }
    ngx_memzero(rule, sizeof(*rule));

    *out_rule = rule;
    return NGX_CONF_OK;
}

/* ---- Resolve and bind the named SHM zone onto a rule ----
 *
 * WHAT: Looks up the zone named `zone_name` and stores the handle on
 * rule->zone.  Returns NGX_CONF_OK, or NGX_CONF_ERROR (with an emerg log using
 * `who` as the directive name) if the zone was never declared.
 *
 * WHY: Zone resolution is by name so http{} and stream{} rules can share one
 * SHM zone; shared by the rate/bandwidth and concurrency setters, which differ
 * only in the directive name printed on failure.
 *
 * HOW: brix_rl_zone_get(); on NULL emit the "declare it first" error.
 */
static char *
rl_rule_bind_zone(ngx_conf_t *cf, brix_rl_rule_t *rule,
    ngx_str_t *zone_name, const char *who)
{
    rule->zone = brix_rl_zone_get(zone_name);
    if (rule->zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "%s: unknown zone \"%V\" (declare it with"
            " brix_rate_limit_zone first)", who, zone_name);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

/* ---- Parse a rate= token into the rule's request or bandwidth rate ----
 *
 * WHAT: Parses the value tail `r` of a rate= token and stores it as either a
 * bandwidth rate (is_bw) or a scaled request rate.  Returns NGX_CONF_OK or
 * NGX_CONF_ERROR (with the matching per-directive error message).
 *
 * WHY: Splits the rate branch (two unit systems + two error strings) out of the
 * token loop so rl_add_rule stays flat.
 *
 * HOW: is_bw → rl_parse_bw_rate → bw_rate; else rl_parse_req_rate (>0) →
 * req_rate scaled by BRIX_RL_REQ_SCALE.
 */
static char *
rl_rule_set_rate(ngx_conf_t *cf, ngx_str_t *r, int is_bw, brix_rl_rule_t *rule)
{
    if (is_bw) {
        ssize_t bps = rl_parse_bw_rate(r);
        if (bps == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_bandwidth_limit: bad rate \"%V\""
                " (expected <N>[k|m|g]/s)", r);
            return NGX_CONF_ERROR;
        }
        rule->bw_rate = (ngx_uint_t) bps;
        return NGX_CONF_OK;
    }
    {
        ngx_int_t rps = rl_parse_req_rate(r);
        if (rps == NGX_ERROR || rps <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_rate_limit_rule: bad rate \"%V\""
                " (expected <N>r/s)", r);
            return NGX_CONF_ERROR;
        }
        /* Stored in milli-requests/s (×1000) so the leaky-bucket core can do
         * sub-request-per-second fixed-point math without floats; req_excess in
         * the node is in the same ×1000 unit. */
        rule->req_rate = (ngx_uint_t) rps * BRIX_RL_REQ_SCALE;
    }
    return NGX_CONF_OK;
}

/* ---- Parse a burst= token into the rule's request or bandwidth burst ----
 *
 * WHAT: Parses the value tail `b` of a burst= token and stores it as a byte
 * burst (is_bw) or a request-count burst.  Returns NGX_CONF_OK or
 * NGX_CONF_ERROR with the matching per-directive error message.
 *
 * WHY: Mirrors rl_rule_set_rate() — keeps the two-unit burst branch out of the
 * loop.
 *
 * HOW: is_bw → rl_parse_size → bw_burst; else ngx_atoi → req_burst.
 */
static char *
rl_rule_set_burst(ngx_conf_t *cf, ngx_str_t *b, int is_bw, brix_rl_rule_t *rule)
{
    if (is_bw) {
        ssize_t sz = rl_parse_size(b);
        if (sz == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_bandwidth_limit: bad burst \"%V\"", b);
            return NGX_CONF_ERROR;
        }
        rule->bw_burst = (ngx_uint_t) sz;
        return NGX_CONF_OK;
    }
    {
        ngx_int_t n = ngx_atoi(b->data, b->len);
        if (n == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_rate_limit_rule: bad burst \"%V\"", b);
            return NGX_CONF_ERROR;
        }
        rule->req_burst = (ngx_uint_t) n;
    }
    return NGX_CONF_OK;
}

/* ---- Parse one token of a rate/bandwidth rule directive ----
 *
 * WHAT: Interprets a single argument `a` (zone=/key=/rate=/burst=/nodelay=),
 * updating `rule`, `*zone_name`, and the have_key/have_rate flags.  Returns
 * NGX_CONF_OK, or NGX_CONF_ERROR for a malformed value or unknown parameter.
 *
 * WHY: Table-of-prefixes style dispatch keeps rl_add_rule a flat loop; the
 * per-field parsing (two unit systems for rate/burst) lives in dedicated
 * helpers.
 *
 * HOW: match the token prefix and delegate to rl_parse_key / rl_rule_set_rate /
 * rl_rule_set_burst, or set nodelay; unknown → emerg + error.
 */
static char *
rl_rule_parse_token(ngx_conf_t *cf, ngx_str_t *a, int is_bw,
    rl_rule_parse_t *st)
{
    if (a->len > 5 && ngx_strncmp(a->data, "zone=", 5) == 0) {
        st->zone_name.data = a->data + 5;
        st->zone_name.len  = a->len - 5;
        return NGX_CONF_OK;
    }
    if (a->len > 4 && ngx_strncmp(a->data, "key=", 4) == 0) {
        if (rl_parse_key(cf, a, st->rule) != NGX_OK) { return NGX_CONF_ERROR; }
        st->have_key = 1;
        return NGX_CONF_OK;
    }
    if (a->len > 5 && ngx_strncmp(a->data, "rate=", 5) == 0) {
        ngx_str_t r = { a->len - 5, a->data + 5 };
        if (rl_rule_set_rate(cf, &r, is_bw, st->rule) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
        st->have_extra = 1;
        return NGX_CONF_OK;
    }
    if (a->len > 6 && ngx_strncmp(a->data, "burst=", 6) == 0) {
        ngx_str_t b = { a->len - 6, a->data + 6 };
        return rl_rule_set_burst(cf, &b, is_bw, st->rule);
    }
    if (a->len == sizeof("nodelay") - 1
        && ngx_strncmp(a->data, "nodelay", 7) == 0)
    {
        st->rule->nodelay = 1;
        return NGX_CONF_OK;
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "xrootd rate limit: unknown parameter \"%V\"", a);
    return NGX_CONF_ERROR;
}

/*
 * Shared setter behind both brix_rate_limit_rule (is_bw=0) and
 * brix_bandwidth_limit (is_bw=1).  Pushes one brix_rl_rule_t onto the rules
 * array, parses the zone=/key=/rate=/burst=/nodelay= tokens, applies defaults,
 * and resolves the named zone handle.  is_bw selects whether rate=/burst= are
 * interpreted as bytes/s + byte burst or req/s + request burst.  Parsing and
 * the shared array/zone plumbing live in rl_rule_* helpers so this reads as a
 * flat token loop.
 */
static char *
rl_add_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, int is_bw)
{
    ngx_str_t       *value = cf->args->elts;
    rl_rule_parse_t  st = { NULL, { 0, NULL }, 0, 0 };
    ngx_uint_t       i;

    if (rl_rule_push(cf, cmd, conf, &st.rule) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    for (i = 1; i < cf->args->nelts; i++) {
        if (rl_rule_parse_token(cf, &value[i], is_bw, &st) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    if (!st.have_key || !st.have_extra || st.zone_name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd rate limit: zone=, key= and rate= are required");
        return NGX_CONF_ERROR;
    }
    /* Apply burst defaults when the operator omitted burst=.  Bandwidth: one
     * second of rate (smooths bursty transfers); requests: 1 (strict). */
    if (is_bw && st.rule->bw_burst == 0) {
        st.rule->bw_burst = st.rule->bw_rate;   /* default burst = 1s of rate */
    }
    if (!is_bw && st.rule->req_burst == 0) {
        st.rule->req_burst = 1;
    }

    return rl_rule_bind_zone(cf, st.rule, &st.zone_name, "xrootd rate limit");
}

char *
brix_rl_rule_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return rl_add_rule(cf, cmd, conf, 0);
}

char *
brix_rl_bw_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return rl_add_rule(cf, cmd, conf, 1);
}

/* brix_concurrency_limit zone=NAME key=<type> limit=N (W7) */
/*
 * Setter for brix_concurrency_limit — a non-leaky cap on the number of
 * simultaneously in-flight requests per principal (rule->req_conc), distinct
 * from the rate/bandwidth leaky buckets above.  Same cmd->offset/lazy-array and
 * zone-resolution pattern as rl_add_rule(); only the parsed parameters differ
 * (limit= instead of rate=/burst=).
 */
/* ---- Parse one token of a concurrency-limit directive ----
 *
 * WHAT: Interprets a single argument `a` (zone=/key=/limit=), updating `rule`,
 * `*zone_name`, and the have_key/have_limit flags.  Returns NGX_CONF_OK, or
 * NGX_CONF_ERROR for a malformed value or unknown parameter.
 *
 * WHY: Keeps brix_rl_conc_directive a flat loop; the concurrency grammar
 * (limit= instead of rate=/burst=) differs enough from the rate rule to warrant
 * its own token parser.
 *
 * HOW: match the token prefix and delegate to rl_parse_key or parse limit= via
 * ngx_atoi (>0); unknown → emerg + error.
 */
static char *
rl_conc_parse_token(ngx_conf_t *cf, ngx_str_t *a, rl_rule_parse_t *st)
{
    if (a->len > 5 && ngx_strncmp(a->data, "zone=", 5) == 0) {
        st->zone_name.data = a->data + 5;
        st->zone_name.len  = a->len - 5;
        return NGX_CONF_OK;
    }
    if (a->len > 4 && ngx_strncmp(a->data, "key=", 4) == 0) {
        if (rl_parse_key(cf, a, st->rule) != NGX_OK) { return NGX_CONF_ERROR; }
        st->have_key = 1;
        return NGX_CONF_OK;
    }
    if (a->len > 6 && ngx_strncmp(a->data, "limit=", 6) == 0) {
        ngx_int_t n = ngx_atoi(a->data + 6, a->len - 6);
        if (n == NGX_ERROR || n <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_concurrency_limit: bad limit \"%V\"", a);
            return NGX_CONF_ERROR;
        }
        st->rule->req_conc = (ngx_uint_t) n;
        st->have_extra = 1;
        return NGX_CONF_OK;
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "brix_concurrency_limit: unknown parameter \"%V\"", a);
    return NGX_CONF_ERROR;
}

char *
brix_rl_conc_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t       *value = cf->args->elts;
    rl_rule_parse_t  st = { NULL, { 0, NULL }, 0, 0 };
    ngx_uint_t       i;

    if (rl_rule_push(cf, cmd, conf, &st.rule) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    for (i = 1; i < cf->args->nelts; i++) {
        if (rl_conc_parse_token(cf, &value[i], &st) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    if (!st.have_key || !st.have_extra || st.zone_name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_concurrency_limit: zone=, key= and limit= are required");
        return NGX_CONF_ERROR;
    }

    return rl_rule_bind_zone(cf, st.rule, &st.zone_name,
                             "brix_concurrency_limit");
}
