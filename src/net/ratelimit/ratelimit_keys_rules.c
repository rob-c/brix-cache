/*
 * ratelimit_keys_rules.c — Phase 25 shared rate/bandwidth/concurrency rule
 * builders.
 *
 * The three directive setters (rate-rule / bandwidth-rule / concurrency-rule)
 * split out of ratelimit_keys.c.  They locate the per-conf rules array via
 * cmd->offset so one implementation serves both the WebDAV and stream command
 * tables, and delegate value parsing to the rl_parse_* primitives declared in
 * ratelimit_keys_internal.h.
 */
#include "ratelimit.h"
#include "protocols/webdav/webdav.h"      /* ngx_http_brix_webdav_req_ctx_t */
#include "ratelimit_keys_internal.h"


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
