/*
 * identity_matrix_conf.c — directive setters for the TPC identity matrix
 * (2.0 F18).  One setter per directive, shared by EVERY plane: the shared conf
 * preamble (ngx_http_brix_shared_conf_t) is member 0 of both
 * ngx_stream_brix_srv_conf_t and ngx_http_brix_common_conf_t, so the cast from
 * a plane's conf to the preamble is valid — the same arrangement
 * brix_conf_set_tpc_verify_checksum uses in core/config/policy.c.
 *
 * Every rejection here is an [emerg] at `nginx -t`.  That is the point: a
 * confinement control that silently ignores a line it could not parse is a
 * control that quietly permits everything the operator meant to forbid.
 */
#include "tpc/common/identity_matrix.h"
#include "core/config/shared_conf_types.h"

/* Lazily create one of the three rule arrays.  NULL means "no rules" all the
 * way down (merge NULL-inherits, brix_tpc_matrix_check reads NULL as vacuous),
 * so the array only exists once a directive has actually been written. */
static ngx_array_t *
tpc_matrix_array(ngx_conf_t *cf, ngx_array_t **slot, size_t size)
{
    if (*slot == NULL) {
        *slot = ngx_array_create(cf->pool, 4, size);
    }
    return *slot;
}


/* Assign one `<key> <pattern>` pair into `rule`, or return the offending key.
 * A repeated key inside one rule is refused rather than last-wins: `allow vo a
 * vo b` reads as a disjunction but would silently become `vo b` alone. */
static const char *
tpc_allow_assign(brix_tpc_allow_rule_t *rule, ngx_str_t *key, ngx_str_t *val)
{
    const char **slot = NULL;

    if (key->len == 2 && ngx_strncmp(key->data, "dn", 2) == 0) {
        slot = &rule->dn;
    } else if (key->len == 5 && ngx_strncmp(key->data, "group", 5) == 0) {
        slot = &rule->group;
    } else if (key->len == 4 && ngx_strncmp(key->data, "host", 4) == 0) {
        slot = &rule->host;
    } else if (key->len == 2 && ngx_strncmp(key->data, "vo", 2) == 0) {
        slot = &rule->vo;
    }

    if (slot == NULL) {
        return "unknown selector";
    }
    if (*slot != NULL) {
        return "duplicate selector";
    }
    if (val->len == 0) {
        return "empty pattern";
    }
    *slot = (const char *) val->data;
    return NULL;
}


/*
 * brix_tpc_allow_identity dn|group|host|vo <pattern> [<key> <pattern>]...
 *
 * One rule per directive; the selectors written on the line are ANDed, and
 * separate directives OR — stock xrootd's `ofs.tpc allow [dn ..] [group ..]
 * [host ..] [vo ..]`.  Configuring ANY rule makes the allow stage fail-closed:
 * a subject matching no rule is denied, never defaulted.
 */
char *
brix_tpc_conf_allow_identity(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_shared_conf_t *sc = conf;
    ngx_str_t                   *value = cf->args->elts;
    brix_tpc_allow_rule_t       *rule;
    ngx_uint_t                   i;
    const char                  *why;

    (void) cmd;

    if ((cf->args->nelts - 1) % 2 != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_tpc_allow_identity: expects <selector> <pattern> pairs "
            "(dn, group, host, vo)");
        return NGX_CONF_ERROR;
    }
    if (tpc_matrix_array(cf, &sc->tpc_allow_identity, sizeof(*rule)) == NULL) {
        return NGX_CONF_ERROR;
    }

    rule = ngx_array_push(sc->tpc_allow_identity);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(rule, sizeof(*rule));

    for (i = 1; i < cf->args->nelts; i += 2) {
        why = tpc_allow_assign(rule, &value[i], &value[i + 1]);
        if (why != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_tpc_allow_identity: %s \"%V\" (known: dn, group, host, "
                "vo)", why, &value[i]);
            return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}


/* The party a `require` rule names.  -1 = unknown. */
static int
tpc_require_party(const ngx_str_t *tok)
{
    if (tok->len == 3 && ngx_strncmp(tok->data, "all", 3) == 0) {
        return BRIX_TPC_PARTY_ALL;
    }
    if (tok->len == 6 && ngx_strncmp(tok->data, "client", 6) == 0) {
        return BRIX_TPC_PARTY_CLIENT;
    }
    if (tok->len == 4 && ngx_strncmp(tok->data, "dest", 4) == 0) {
        return BRIX_TPC_PARTY_DEST;
    }
    return -1;
}


/*
 * Canonical auth label for an operator token, or NULL when unknown.  The
 * canonical spellings are exactly brix_identity_auth_label()'s, so a rule can
 * never name a method the identity layer would report differently.  XRootD's
 * own protocol names are accepted as aliases (`ztn` is its name for the WLCG
 * bearer token, `unix`/`krb5`/`gsi`/`sss`/`pwd`/`host` are already identical)
 * so an ofs.tpc stanza transplants without translation.  "none" is refused: a
 * rule demanding that a party be UNauthenticated is never what an operator
 * writing a confinement control meant.
 */
static const char *
tpc_require_auth(const ngx_str_t *tok)
{
    static const struct { const char *in; const char *out; } map[] = {
        { "gsi",   "GSI"   }, { "token", "TOKEN" }, { "ztn",  "TOKEN" },
        { "sss",   "SSS"   }, { "s3key", "S3KEY" }, { "krb5", "KRB5"  },
        { "unix",  "UNIX"  }, { "host",  "HOST"  }, { "pwd",  "PWD"   },
    };
    ngx_uint_t i;

    for (i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
        size_t n = ngx_strlen(map[i].in);
        if (tok->len == n
            && ngx_strncasecmp(tok->data, (u_char *) map[i].in, n) == 0)
        {
            return map[i].out;
        }
    }
    return NULL;
}


/*
 * brix_tpc_require all|client|dest <auth>
 *
 * Repeatable.  Rules naming the same party OR (any one satisfies it); a party
 * no rule names is unconstrained even when the other party is constrained.
 * `client` binds the leg the initiating client opened, `dest` the leg the peer
 * SERVER opened on its behalf (the one carrying tpc.org) — so `require dest`
 * can never be satisfied by the client's own credential.
 */
char *
brix_tpc_conf_require(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_shared_conf_t *sc = conf;
    ngx_str_t                   *value = cf->args->elts;
    brix_tpc_require_rule_t     *rule;
    int                          party;
    const char                  *auth;

    (void) cmd;

    party = tpc_require_party(&value[1]);
    if (party < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_tpc_require: unknown party \"%V\" (known: all, client, dest)",
            &value[1]);
        return NGX_CONF_ERROR;
    }

    auth = tpc_require_auth(&value[2]);
    if (auth == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_tpc_require: unknown authentication method \"%V\" (known: "
            "gsi, token (ztn), sss, s3key, krb5, unix, host, pwd)", &value[2]);
        return NGX_CONF_ERROR;
    }

    if (tpc_matrix_array(cf, &sc->tpc_require, sizeof(*rule)) == NULL) {
        return NGX_CONF_ERROR;
    }
    rule = ngx_array_push(sc->tpc_require);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }
    rule->party = party;
    rule->auth = auth;
    return NGX_CONF_OK;
}


/*
 * brix_tpc_restrict <path> [<path>...]
 *
 * Repeatable, and every argument on a line is appended — the stock
 * ngx_conf_set_str_array_slot keeps only the first, which for a confinement
 * list would silently drop everything after it (the footgun already fixed for
 * brix_tpc_source_allow).  Paths must be absolute; the total is capped so the
 * per-request pointer vector in brix_tpc_matrix_check stays a stack array.
 */
char *
brix_tpc_conf_restrict(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_shared_conf_t *sc = conf;
    ngx_str_t                   *value = cf->args->elts;
    ngx_str_t                   *slot;
    ngx_uint_t                   i;

    (void) cmd;

    if (tpc_matrix_array(cf, &sc->tpc_restrict, sizeof(ngx_str_t)) == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0 || value[i].data[0] != '/') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_tpc_restrict: \"%V\" must be an absolute path",
                &value[i]);
            return NGX_CONF_ERROR;
        }
        if (sc->tpc_restrict->nelts >= BRIX_TPC_RESTRICT_MAX) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_tpc_restrict: at most %d prefixes",
                BRIX_TPC_RESTRICT_MAX);
            return NGX_CONF_ERROR;
        }
        slot = ngx_array_push(sc->tpc_restrict);
        if (slot == NULL) {
            return NGX_CONF_ERROR;
        }
        *slot = value[i];
    }
    return NGX_CONF_OK;
}
