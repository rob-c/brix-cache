/*
 * cache_urlcgi_conf.c — the brix_cache_urlcgi directive setter (2.0 F5,
 * upstream pfc.urlcgi).
 *
 * WHAT: brix_cache_urlcgi [blocksize {ignore|<min> <max>}]
 *                         [prefetch  {ignore|<min> <max>}]
 *   arms (or explicitly disarms) the two per-open client hints a root:// open
 *   may carry as CGI: pfc.blocksize=<bytes> and pfc.prefetch=<blocks>. A
 *   clause not named on the line is ignored, the upstream default.
 *
 * WHY: Upstream's pfc.urlcgi lets a client tune the slice granule and the
 *   prefetch runway per open, with the operator bounding what may be asked
 *   for. Same grammar; the bounds follow this cache's own rules — blocksize
 *   bounds are positive multiples of 1m like brix_cache_slice_size, prefetch
 *   bounds are block counts with max >= 1 (a real clamp never has max 0,
 *   which is the "ignored" encoding of brix_cache_urlcgi_conf_t).
 *
 * HOW: A word loop over cf->args: each clause keyword takes either `ignore`
 *   or exactly two bounds; a keyword repeated or unknown, a missing bound, or
 *   min > max is a configuration error, reported the nginx way (a string
 *   the core prefixes with the directive name and location).
 */

#include "config.h"
#include "cache_urlcgi_conf.h"

#define URLCGI_CLAUSE_BLOCKSIZE  0x1
#define URLCGI_CLAUSE_PREFETCH   0x2

static int
urlcgi_word_is(const ngx_str_t *v, const char *word)
{
    size_t n = ngx_strlen(word);

    return v->len == n && ngx_strncmp(v->data, word, n) == 0;
}

/* `blocksize <min> <max>`: sizes, positive multiples of the slice granule. */
static char *
urlcgi_parse_size_bounds(const ngx_str_t *lo, const ngx_str_t *hi,
    brix_cache_urlcgi_conf_t *u)
{
    ssize_t a = ngx_parse_size((ngx_str_t *) lo);
    ssize_t b = ngx_parse_size((ngx_str_t *) hi);

    if (a <= 0 || b <= 0) {
        return "blocksize: bad size";
    }
    if (a % BRIX_CACHE_SLICE_GRANULE != 0 || b % BRIX_CACHE_SLICE_GRANULE != 0) {
        return "blocksize: bounds must be positive multiples of 1m";
    }
    if (a > b) {
        return "blocksize: min exceeds max";
    }
    u->bs_min = (size_t) a;
    u->bs_max = (size_t) b;
    return NGX_CONF_OK;
}

/* `prefetch <min> <max>`: block counts, max >= 1 (min 0 lets a client switch
 * speculation off for its own handle). */
static char *
urlcgi_parse_count_bounds(const ngx_str_t *lo, const ngx_str_t *hi,
    brix_cache_urlcgi_conf_t *u)
{
    ngx_int_t a = ngx_atoi(lo->data, lo->len);
    ngx_int_t b = ngx_atoi(hi->data, hi->len);

    if (a == NGX_ERROR || b == NGX_ERROR) {
        return "prefetch: bad block count";
    }
    if (b < 1) {
        return "prefetch: max must be at least 1 block";
    }
    if (a > b) {
        return "prefetch: min exceeds max";
    }
    u->pf_min = (ngx_uint_t) a;
    u->pf_max = (ngx_uint_t) b;
    return NGX_CONF_OK;
}

/* One clause at value[i]: returns the words consumed via *step, or an error. */
static char *
urlcgi_parse_clause(const ngx_str_t *value, ngx_uint_t i, ngx_uint_t n,
    brix_cache_urlcgi_conf_t *u, unsigned *seen, ngx_uint_t *step)
{
    unsigned bit;

    if (urlcgi_word_is(&value[i], "blocksize")) {
        bit = URLCGI_CLAUSE_BLOCKSIZE;
    } else if (urlcgi_word_is(&value[i], "prefetch")) {
        bit = URLCGI_CLAUSE_PREFETCH;
    } else {
        return "unknown clause (expected blocksize or prefetch)";
    }
    if (*seen & bit) {
        return "clause repeated";
    }
    *seen |= bit;

    if (i + 1 < n && urlcgi_word_is(&value[i + 1], "ignore")) {
        *step = 2;                              /* the pair stays (0, 0) */
        return NGX_CONF_OK;
    }
    if (i + 2 >= n) {
        return "clause needs \"ignore\" or <min> <max>";
    }
    *step = 3;
    return (bit == URLCGI_CLAUSE_BLOCKSIZE)
           ? urlcgi_parse_size_bounds(&value[i + 1], &value[i + 2], u)
           : urlcgi_parse_count_bounds(&value[i + 1], &value[i + 2], u);
}

char *
brix_conf_set_cache_urlcgi(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    brix_cache_urlcgi_conf_t *u = (brix_cache_urlcgi_conf_t *)
                                  ((char *) conf + cmd->offset);
    const ngx_str_t          *value = cf->args->elts;
    ngx_uint_t                n = cf->args->nelts, i = 1, step;
    unsigned                  seen = 0;
    char                     *err;

    if (u->bs_max != NGX_CONF_UNSET_SIZE || u->pf_max != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }
    /* Naming the directive decides BOTH hints for this block: a clause left
     * unnamed is explicitly ignored (upstream default), not inherited. */
    u->bs_min = 0;
    u->bs_max = 0;
    u->pf_min = 0;
    u->pf_max = 0;

    while (i < n) {
        err = urlcgi_parse_clause(value, i, n, u, &seen, &step);
        if (err != NGX_CONF_OK) {
            return err;
        }
        i += step;
    }
    return NGX_CONF_OK;
}
