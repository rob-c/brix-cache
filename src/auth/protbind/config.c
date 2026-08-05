/*
 * config.c — the `brix_protbind` directive parser.
 *
 * WHAT: Turns one `brix_protbind <host-template> [none | [only] <proto>...]`
 *       directive into a brix_protbind_rule_t appended to a caller-owned rule
 *       array, or into an nginx configuration error string.
 *
 * WHY:  Both the root:// stream server block and the HTTP location block accept
 *       the same grammar, so the parse — and the emerg diagnostic, which names
 *       the directive via cmd->name — lives once here and each module supplies
 *       only a one-line setter that hands over the address of its own array
 *       slot.  Keeping the grammar in one file is also what makes the
 *       stream-vs-HTTP behaviour provably identical.
 *
 * HOW:  Validates arity, records the template verbatim (matching happens at
 *       request time), then either records the `none` mode or walks the
 *       protocol tokens through brix_protbind_proto_id(), rejecting unknown
 *       names, duplicates and over-long lists at config time so a misconfigured
 *       server never starts.
 */

#include "core/ngx_brix_module.h"
#include "protbind.h"

/*
 * brix_protbind_rules_array — lazily create the rule array.
 *
 * WHAT: Returns the existing array, creating a small one on first use; NULL on
 *       allocation failure.
 *
 * WHY:  A NULL array is the "no protbind configured" sentinel the resolver and
 *       the config merge both rely on, so the array must not be pre-created by
 *       the module's create_conf.  Four slots covers essentially every real
 *       stanza without a realloc.
 *
 * HOW:  ngx_array_create from cf->pool on first call.
 */
static ngx_array_t *
brix_protbind_rules_array(ngx_conf_t *cf, ngx_array_t **rules)
{
    if (*rules == NULL) {
        *rules = ngx_array_create(cf->pool, 4, sizeof(brix_protbind_rule_t));
    }

    return *rules;
}

/*
 * brix_protbind_parse_protos — parse the protocol-token tail of a directive.
 *
 * WHAT: Fills rule->protos/count from args[first..last]; returns NGX_CONF_OK
 *       or a static error string.
 *
 * WHY:  Every rejection here is a misconfiguration that would otherwise fail
 *       open (an unknown name silently dropped) or produce a malformed sec
 *       token (a duplicated scheme).  Failing at config parse turns all of them
 *       into a refusal to start, which is the only safe outcome for an
 *       authentication policy.
 *
 * HOW:  1. Map each token to its BRIX_AUTH_* id, rejecting unknown names.
 *       2. Reject a repeat of an id already recorded for this rule.
 *       3. Reject more than BRIX_PROTBIND_MAX_PROTOS entries.
 */
static char *
brix_protbind_parse_protos(ngx_conf_t *cf, ngx_uint_t first,
    brix_protbind_rule_t *rule)
{
    ngx_str_t   *args = cf->args->elts;
    ngx_uint_t   arg, existing, proto;

    for (arg = first; arg < cf->args->nelts; arg++) {
        if (brix_protbind_proto_id(&args[arg], &proto) != NGX_OK) {
            return "has an unknown protocol name "
                   "(expected gsi, ztn/token, sss, unix, krb5, host or pwd)";
        }

        for (existing = 0; existing < rule->count; existing++) {
            if (rule->protos[existing] == proto) {
                return "lists the same protocol twice";
            }
        }

        if (rule->count >= BRIX_PROTBIND_MAX_PROTOS) {
            return "lists more protocols than the server supports";
        }

        rule->protos[rule->count++] = proto;
    }

    return NGX_CONF_OK;
}

/* ---- Parse one brix_protbind directive ----
 *
 * WHAT: Appends a parsed rule to *rules (creating the array on first use).
 *       Returns NGX_CONF_OK, NGX_CONF_ERROR on allocation failure, or a static
 *       message describing the grammar violation.
 *
 * WHY:  This is the whole configuration surface of the feature; expressing it
 *       as an ordinary nginx setter (cf->args in, error string out) lets both
 *       modules register it with no glue beyond computing the array address.
 *
 * HOW:  1. Require at least a template and one policy word.
 *       2. Reject an empty template.
 *       3. `none` must stand alone; `only` is an optional lead-in that must be
 *          followed by at least one protocol.
 *       4. Delegate the protocol tail to brix_protbind_parse_protos.
 */
static char *
brix_protbind_parse(ngx_conf_t *cf, ngx_array_t **rules)
{
    ngx_str_t             *args = cf->args->elts;
    ngx_array_t           *array;
    brix_protbind_rule_t  *rule;
    ngx_uint_t             first_proto;

    if (cf->args->nelts < 3) {
        return "requires a host template and "
               "\"none\" or a protocol list";
    }

    if (args[1].len == 0) {
        return "has an empty host template";
    }

    array = brix_protbind_rules_array(cf, rules);
    if (array == NULL) {
        return NGX_CONF_ERROR;
    }

    rule = ngx_array_push(array);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(rule, sizeof(*rule));
    rule->host_tpl = args[1];

    if (args[2].len == sizeof("none") - 1
        && ngx_strncmp(args[2].data, "none", sizeof("none") - 1) == 0)
    {
        if (cf->args->nelts != 3) {
            return "\"none\" takes no protocol list";
        }
        rule->mode = BRIX_PROTBIND_NONE;
        return NGX_CONF_OK;
    }

    first_proto = 2;

    if (args[2].len == sizeof("only") - 1
        && ngx_strncmp(args[2].data, "only", sizeof("only") - 1) == 0)
    {
        if (cf->args->nelts < 4) {
            return "\"only\" must be followed by at least one protocol";
        }
        rule->mode = BRIX_PROTBIND_ONLY;
        first_proto = 3;

    } else {
        rule->mode = BRIX_PROTBIND_ALL;
    }

    return brix_protbind_parse_protos(cf, first_proto, rule);
}

/*
 * brix_protbind_conf — the setter both frontends register.
 *
 * WHAT: Parses one directive into *rules and reports any grammar violation as
 *       an [emerg] prefixed with the directive's own name.  Returns
 *       NGX_CONF_OK or NGX_CONF_ERROR.
 *
 * WHY:  The stream and HTTP directives differ only in which array they fill and
 *       what they are called, and cmd->name already carries the latter — so the
 *       diagnostic belongs here rather than duplicated in two module wrappers
 *       that would then be free to drift.
 *
 * HOW:  Delegate to brix_protbind_parse(); pass the two sentinel returns
 *       through untouched and turn anything else (a static message) into an
 *       emerg naming the directive.
 */
char *
brix_protbind_conf(ngx_conf_t *cf, ngx_command_t *cmd, ngx_array_t **rules)
{
    char *rc = brix_protbind_parse(cf, rules);

    if (rc == NGX_CONF_OK || rc == NGX_CONF_ERROR) {
        return rc;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V: %s", &cmd->name, rc);
    return NGX_CONF_ERROR;
}
