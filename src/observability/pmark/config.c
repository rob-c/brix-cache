/*
 * config.c — pmark per-server config lifecycle + directive parsing.
 *
 * WHAT: Initialise/merge the brix_pmark_conf_t embedded in the shared config
 *   preamble (config/shared_conf.h), and the custom directive setters for the
 *   repeatable / multi-token directives (firefly_dest, map_experiment,
 *   map_activity, domain).  Simple flag/str directives use the stock
 *   ngx_conf_set_*_slot setters wired directly in each module's command table.
 *
 * WHY: pmark config is shared across the stream (root://) and HTTP (WebDAV/S3)
 *   modules.  Because ngx_http_brix_shared_conf_t is the FIRST member of every
 *   protocol conf struct, a custom setter can cast its `conf` argument straight
 *   to ngx_http_brix_shared_conf_t* and reach ->pmark, so ONE setter serves all
 *   three protocols.
 *
 * HOW: init sets NGX_CONF_UNSET sentinels; merge applies SciTags-sane defaults
 *   (opt-in disabled; firefly + flowlabel + scitag-cgi on; domain remote; firefly
 *   port 10514).  Arrays inherit from the parent when the child did not set them.
 */

#include "pmark.h"
#include "core/config/shared_conf.h"


void
brix_pmark_conf_init(brix_pmark_conf_t *c)
{
    c->enable         = NGX_CONF_UNSET;
    c->firefly        = NGX_CONF_UNSET;
    c->flowlabel      = NGX_CONF_UNSET;
    c->scitag_cgi     = NGX_CONF_UNSET;
    c->firefly_origin = NGX_CONF_UNSET;
    c->http_plain     = NGX_CONF_UNSET;
    c->echo           = NGX_CONF_UNSET_MSEC;
    c->domain         = NGX_CONF_UNSET_UINT;
}


char *
brix_pmark_conf_merge(ngx_conf_t *cf, brix_pmark_conf_t *prev,
    brix_pmark_conf_t *conf)
{
    ngx_conf_merge_value(conf->enable,         prev->enable,         0);
    ngx_conf_merge_value(conf->firefly,        prev->firefly,        1);
    ngx_conf_merge_value(conf->flowlabel,      prev->flowlabel,      1);
    ngx_conf_merge_value(conf->scitag_cgi,     prev->scitag_cgi,     1);
    ngx_conf_merge_value(conf->firefly_origin, prev->firefly_origin, 0);
    ngx_conf_merge_value(conf->http_plain,     prev->http_plain,     0);
    ngx_conf_merge_msec_value(conf->echo,      prev->echo,           0);
    /* XRootD's pmark ffecho enforces a 30s floor on the "ongoing" refresh —
     * a shorter interval multiplies firefly UDP per active flow for no
     * monitoring benefit. Mirror it: warn and raise rather than reject so a
     * config written against stock xrootd semantics keeps working. */
    if (conf->echo > 0 && conf->echo < 30000) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix_pmark_echo %M ms is below the 30s minimum; raised to 30s",
            conf->echo);
        conf->echo = 30000;
    }
    ngx_conf_merge_uint_value(conf->domain,    prev->domain,
                              BRIX_PMARK_DOMAIN_REMOTE);
    ngx_conf_merge_str_value(conf->appname,    prev->appname,        "nginx-xrootd");
    ngx_conf_merge_str_value(conf->defsfile,   prev->defsfile,       "");

    if (conf->firefly_dest == NULL) { conf->firefly_dest = prev->firefly_dest; }
    if (conf->exp_rules    == NULL) { conf->exp_rules    = prev->exp_rules;    }
    if (conf->act_rules    == NULL) { conf->act_rules    = prev->act_rules;    }

    return NGX_CONF_OK;
}


/* Reach the pmark config from any protocol conf (common is the first member). */
static brix_pmark_conf_t *
pmark_conf(void *conf)
{
    return &((ngx_http_brix_shared_conf_t *) conf)->pmark;
}


char *
brix_pmark_set_firefly_dest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    brix_pmark_conf_t *pm = pmark_conf(conf);
    ngx_str_t           *value = cf->args->elts;
    ngx_str_t           *dest;

    (void) cmd;

    if (pm->firefly_dest == NULL) {
        pm->firefly_dest = ngx_array_create(cf->pool, 2, sizeof(ngx_str_t));
        if (pm->firefly_dest == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    dest = ngx_array_push(pm->firefly_dest);
    if (dest == NULL) {
        return NGX_CONF_ERROR;
    }

    /* Stored verbatim as "host[:port]"; resolved to a sockaddr per worker at
     * init (defaults to port 10514 when no :port is given). */
    *dest = value[1];
    return NGX_CONF_OK;
}


char *
brix_pmark_set_domain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    brix_pmark_conf_t *pm = pmark_conf(conf);
    ngx_str_t           *value = cf->args->elts;

    (void) cmd;

    if (ngx_strcmp(value[1].data, "any") == 0) {
        pm->domain = BRIX_PMARK_DOMAIN_ANY;
    } else if (ngx_strcmp(value[1].data, "local") == 0) {
        pm->domain = BRIX_PMARK_DOMAIN_LOCAL;
    } else if (ngx_strcmp(value[1].data, "remote") == 0) {
        pm->domain = BRIX_PMARK_DOMAIN_REMOTE;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid brix_pmark_domain \"%V\" (use any|local|remote)",
            &value[1]);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


/* Both map directives are the same shape — a keyword arm choosing the rule
 * kind, an optional <match> argument, and the mapped name as the last token —
 * differing only in which rule struct they fill and where the keyword sits.
 * One worker parses from a per-directive descriptor; the arm INDEX is the
 * rule's kind (both kind enums declare their values in table order from 0). */

typedef struct {
    const char *usage;                    /* EMERG text when no arm matches   */
    struct {
        const char *word;                 /* arm keyword at value[k]          */
        ngx_uint_t  nelts;                /* directive argc for this arm      */
        unsigned    has_match;            /* arm carries a <match> argument   */
    }           arms[3];
    ngx_uint_t  k;                        /* keyword index in value[]         */
    size_t      elt_size;                 /* rule struct size                 */
    size_t      rules_off;                /* conf offset of the rule array    */
    size_t      kind_off;                 /* rule offsets ...                 */
    size_t      match_off;
    size_t      name_off;                 /* exp_name / act_name              */
    size_t      pre_off;                  /* rule field taking value[1] up    */
}                                         /* front, or (size_t) -1 for none  */
pmark_map_desc_t;

static char *
pmark_map_directive(ngx_conf_t *cf, void *conf, const pmark_map_desc_t *d)
{
    brix_pmark_conf_t  *pm = pmark_conf(conf);
    ngx_str_t          *value = cf->args->elts;
    ngx_array_t       **rules = (ngx_array_t **) ((char *) pm + d->rules_off);
    u_char             *rule;
    ngx_uint_t          i;

    if (*rules == NULL) {
        *rules = ngx_array_create(cf->pool, 4, d->elt_size);
        if (*rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    rule = ngx_array_push(*rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(rule, d->elt_size);
    if (d->pre_off != (size_t) -1) {
        *(ngx_str_t *) (rule + d->pre_off) = value[1];
    }
    for (i = 0; i < 3; i++) {
        if (ngx_strcmp(value[d->k].data, d->arms[i].word) != 0
            || cf->args->nelts != d->arms[i].nelts)
        {
            continue;
        }
        *(int *) (rule + d->kind_off) = (int) i;    /* arm index == kind */
        if (d->arms[i].has_match) {
            *(ngx_str_t *) (rule + d->match_off) = value[d->k + 1];
        }
        *(ngx_str_t *) (rule + d->name_off) = value[d->arms[i].nelts - 1];
        return NGX_CONF_OK;
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", d->usage);
    return NGX_CONF_ERROR;
}


char *
brix_pmark_set_map_experiment(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    static const pmark_map_desc_t d = {
        .usage = "brix_pmark_map_experiment: use "
            "\"default <exp>\" | \"path <glob> <exp>\" | \"vo <name> <exp>\"",
        .arms  = { { "default", 3, 0 }, { "path", 4, 1 }, { "vo", 4, 1 } },
        .k         = 1,
        .elt_size  = sizeof(brix_pmark_exp_rule_t),
        .rules_off = offsetof(brix_pmark_conf_t, exp_rules),
        .kind_off  = offsetof(brix_pmark_exp_rule_t, kind),
        .match_off = offsetof(brix_pmark_exp_rule_t, match),
        .name_off  = offsetof(brix_pmark_exp_rule_t, exp_name),
        .pre_off   = (size_t) -1,
    };

    (void) cmd;
    return pmark_map_directive(cf, conf, &d);
}


char *
brix_pmark_set_map_activity(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    static const pmark_map_desc_t d = {
        .usage = "brix_pmark_map_activity: use \"<exp> default <act>\" | "
            "\"<exp> role <name> <act>\" | \"<exp> user <name> <act>\"",
        .arms  = { { "default", 4, 0 }, { "role", 5, 1 }, { "user", 5, 1 } },
        .k         = 2,
        .elt_size  = sizeof(brix_pmark_act_rule_t),
        .rules_off = offsetof(brix_pmark_conf_t, act_rules),
        .kind_off  = offsetof(brix_pmark_act_rule_t, kind),
        .match_off = offsetof(brix_pmark_act_rule_t, match),
        .name_off  = offsetof(brix_pmark_act_rule_t, act_name),
        .pre_off   = offsetof(brix_pmark_act_rule_t, exp_name),
    };

    (void) cmd;
    return pmark_map_directive(cf, conf, &d);
}
