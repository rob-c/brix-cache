/*
 * authdb_grammar.c — the native (`brix_authdb_engine native`) authdb line
 * grammar: the privilege alphabet, the field-1 identity-selector alphabet, and
 * the refusal vocabulary shared by both.
 *
 * Split from authdb_parse.c in 2.0 F20, which turned two silent-widening paths
 * into refused lines: a compound field-1 token used to be truncated to its lead
 * byte, and an unknown privilege letter used to be dropped.  Both now refuse
 * the line, and the `v` (VOMS vorg), `l` (VOMS role) selectors and the `x`
 * (stage/recall) privilege joined the alphabets.
 */
#include "core/ngx_brix_module.h"

#include <stddef.h>
#include <string.h>

#include "fs/path/path_internal.h"
#include "auth/authz/acc/acc.h"   /* brix_authdb_defect_refuse decl + formats */
#include "authdb_grammar.h"

/*
 * WHAT: map ONE native-engine privilege letter onto its BRIX_AUTH_* bits, or 0
 *       when the letter is not in the alphabet.
 * WHY:  2.0 F20 — the old switch folded "unknown letter" into `default: break;`
 *       so a typo (or the xrdacc-only letters `i`/`n`) silently evaporated and
 *       the operator got a rule weaker than the one they wrote.  Returning the
 *       bits lets the caller tell "no bits" from "not a letter".
 * HOW:  pure lookup.  'r' implies 'l' (you cannot read what you cannot look
 *       up); 'a' (append) folds into UPDATE because the FS-level write
 *       permission is identical; 'x' is the 2.0 stage/recall privilege.
 */
static uint32_t
adb_priv_bit(u_char c)
{
    switch (c) {
    case 'r': return BRIX_AUTH_READ | BRIX_AUTH_LOOKUP;
    case 'l': return BRIX_AUTH_LOOKUP;
    case 'w': return BRIX_AUTH_UPDATE;
    case 'a': return BRIX_AUTH_UPDATE;   /* append is update */
    case 'd': return BRIX_AUTH_DELETE;
    case 'm': return BRIX_AUTH_MKDIR;
    case 'k': return BRIX_AUTH_ADMIN;
    case 'x': return BRIX_AUTH_STAGE;    /* 2.0 F20: tape recall / evict */
    default:  return 0;
    }
}

/*
 * WHAT: OR-accumulate a whole privilege string into *out.  NGX_OK, or NGX_ERROR
 *       with *bad set to the first letter that is not in the alphabet.
 * WHY:  a privilege field is all-or-nothing: half a rule is a rule the operator
 *       never wrote, so the caller refuses the LINE rather than the character.
 * HOW:  adb_priv_bit per byte; an empty field legitimately yields 0 bits (a
 *       rule that grants nothing, which is how an operator spells "deny here").
 */
static ngx_int_t
brix_parse_privs(const char *p, size_t len, uint32_t *out, u_char *bad)
{
    uint32_t  privs = 0;
    uint32_t  bit;
    size_t    i;

    for (i = 0; i < len; i++) {
        bit = adb_priv_bit((u_char) p[i]);
        if (bit == 0) {
            *bad = (u_char) p[i];
            return NGX_ERROR;
        }
        privs |= bit;
    }

    *out = privs;
    return NGX_OK;
}
/*
 * WHAT: record (or immediately raise) a grammar defect on the current line.
 *       Always returns NGX_DECLINED so callers can `return adb_reject(...)`.
 * WHY:  one place owns the message shape, so every refusal an operator can hit
 *       names the file, the line number, and what was wrong with it.
 * HOW:  render into a stack buffer; with a defect slot keep the FIRST message
 *       (later lines are noise once the config is already refused), else log
 *       NGX_LOG_EMERG through cf directly.
 */
ngx_int_t
brix_adb_reject(adb_parse_ctx_t *pc, const char *reason)
{
    u_char   buf[512];
    u_char  *end;
    size_t   len;

    end = ngx_snprintf(buf, sizeof(buf) - 1,
                       "brix_authdb \"%V\" line %ui: %s",
                       pc->filename, pc->lineno, reason);
    *end = '\0';
    len = (size_t) (end - buf);

    if (pc->defect == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, pc->cf, 0, "%s", buf);
        return NGX_DECLINED;
    }
    if (pc->defect->len == 0) {
        pc->defect->data = ngx_pnalloc(pc->cf->pool, len + 1);
        if (pc->defect->data != NULL) {
            ngx_memcpy(pc->defect->data, buf, len + 1);
            pc->defect->len = len;
        }
    }
    return NGX_DECLINED;
}

/* As adb_reject, naming the offending byte (printable as a char, else hex). */
static ngx_int_t
adb_reject_char(adb_parse_ctx_t *pc, const char *what, u_char c)
{
    u_char  reason[128];

    if (c >= 0x20 && c < 0x7f) {
        ngx_snprintf(reason, sizeof(reason), "%s '%c'%Z", what, c);
    } else {
        ngx_snprintf(reason, sizeof(reason), "%s byte 0x%02xd%Z", what,
                     (int) c);
    }
    return brix_adb_reject(pc, (const char *) reason);
}

/* WHAT: 1 when `c` is a legal field-1 identity selector.
 * WHY:  the alphabet is the security surface — anything outside it must refuse
 *       the line, never be skipped (a skipped selector widens the rule).
 * HOW:  `u` DN, `g` VO/group, `p` peer host or CIDR, `a` any identity,
 *       `v` VOMS virtual organisation, `l` VOMS role (2.0 F20). */
static ngx_flag_t
adb_selector_ok(u_char c)
{
    return c == 'u' || c == 'g' || c == 'p' || c == 'a'
        || c == 'v' || c == 'l';
}

/* Copy [p, p+len) into a pool-owned NUL-terminated ngx_str_t. */
static ngx_int_t
adb_dup(ngx_conf_t *cf, ngx_str_t *dst, const u_char *p, size_t len)
{
    dst->len = len;
    dst->data = ngx_pnalloc(cf->pool, len + 1);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(dst->data, p, len);
    dst->data[len] = '\0';
    return NGX_OK;
}

/*
 * WHAT: read field 1 into rule->sel[] / rule->nsel.
 * WHY:  2.0 F20 (i) — a compound token used to be truncated to its lead byte,
 *       so `usergroup` was accepted as `u` and matched every DN.  Every byte is
 *       now either a distinct selector or a refused line.
 * HOW:  reject an out-of-alphabet byte, a repeat, `a` mixed with anything (it
 *       already means "any identity", so AND-ing it is either a no-op or a
 *       contradiction the operator did not intend), and more bytes than the
 *       alphabet holds.
 */
static ngx_int_t
adb_bind_selectors(adb_parse_ctx_t *pc, brix_authdb_rule_t *rule,
                   const adb_line_t *line)
{
    size_t  n = (size_t) (line->type_end - line->type_p);
    size_t  i, j;

    if (n > BRIX_AUTHDB_MAX_SELECTORS) {
        return brix_adb_reject(pc, "field 1 lists more identity selectors than the "
                              "alphabet `u g p a v l` holds");
    }

    for (i = 0; i < n; i++) {
        u_char c = line->type_p[i];

        if (!adb_selector_ok(c)) {
            return adb_reject_char(pc, "unknown identity selector", c);
        }
        if (c == 'a' && n > 1) {
            return brix_adb_reject(pc, "the `a` (any identity) selector cannot be "
                                  "combined with another selector");
        }
        for (j = 0; j < i; j++) {
            if ((u_char) rule->sel[j] == c) {
                return adb_reject_char(pc, "identity selector repeated", c);
            }
        }
        rule->sel[i] = (brix_auth_type_t) c;
    }

    rule->nsel = (ngx_uint_t) n;
    return NGX_OK;
}

/* Count the '|'-separated components of an id token (always >= 1). */
static ngx_uint_t
adb_id_components(const u_char *p, const u_char *end)
{
    ngx_uint_t  n = 1;

    for (; p < end; p++) {
        if (*p == '|') {
            n++;
        }
    }
    return n;
}

/*
 * WHAT: bind field 2 to the selectors bound by adb_bind_selectors.
 * WHY:  a single-selector rule must keep taking its id VERBATIM — DNs are full
 *       of punctuation and splitting them would break every deployed authdb —
 *       so only a compound rule reads '|' as a separator.
 * HOW:  arity must match exactly (one component per selector) and no component
 *       may be empty; both are refused lines, never a silently dropped
 *       selector.
 */
static ngx_int_t
adb_bind_ids(adb_parse_ctx_t *pc, brix_authdb_rule_t *rule,
             const adb_line_t *line)
{
    const u_char *p   = line->id_p;
    const u_char *end = line->id_end;
    ngx_uint_t    i;

    if (rule->nsel == 1) {
        return adb_dup(pc->cf, &rule->sel_id[0], p, (size_t) (end - p));
    }

    if (adb_id_components(p, end) != rule->nsel) {
        return brix_adb_reject(pc, "a compound rule needs exactly one "
                              "'|'-separated id component per selector");
    }

    for (i = 0; i < rule->nsel; i++) {
        const u_char *bar = p;

        while (bar < end && *bar != '|') {
            bar++;
        }
        if (bar == p) {
            return brix_adb_reject(pc, "a compound rule has an empty id component");
        }
        if (adb_dup(pc->cf, &rule->sel_id[i], p,
                    (size_t) (bar - p)) != NGX_OK)
        {
            return NGX_ERROR;
        }
        p = bar + 1;
    }

    return NGX_OK;
}

/*
 * WHAT: build ONE rule from a tokenized line and push it into `rules`.
 *       NGX_OK pushed; NGX_DECLINED the line was refused (nothing pushed);
 *       NGX_ERROR allocation failure.
 * WHY:  isolates the array-push + pool ownership from the tokenizer.  2.0 F20:
 *       the rule is assembled in a SCRATCH struct and only pushed once every
 *       field parsed, so a refused line can never leave a half-built rule (and
 *       therefore a half-built matcher) in the array.
 * HOW:  selectors -> ids -> path -> privs, each fallible; `type`/`id` are then
 *       set as the selector-0 alias every pre-F20 reader still uses, and
 *       resolved[] stays zeroed (filled later by brix_finalize_authdb_rules —
 *       deferred realpath).
 */
ngx_int_t
brix_adb_append(adb_parse_ctx_t *pc, ngx_array_t *rules,
    const adb_line_t *line)
{
    brix_authdb_rule_t   scratch;
    brix_authdb_rule_t  *rule;
    u_char               bad = 0;
    ngx_int_t            rc;

    ngx_memzero(&scratch, sizeof(scratch));

    rc = adb_bind_selectors(pc, &scratch, line);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = adb_bind_ids(pc, &scratch, line);
    if (rc != NGX_OK) {
        return rc;
    }

    if (adb_dup(pc->cf, &scratch.path, line->path_p,
                (size_t) (line->path_end - line->path_p)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (brix_parse_privs((const char *) line->privs_p,
                         (size_t) (line->privs_end - line->privs_p),
                         &scratch.privs, &bad) != NGX_OK)
    {
        return adb_reject_char(pc, "unknown privilege letter", bad);
    }

    scratch.type = scratch.sel[0];
    scratch.id   = scratch.sel_id[0];

    rule = ngx_array_push(rules);
    if (rule == NULL) {
        return NGX_ERROR;
    }
    *rule = scratch;
    return NGX_OK;
}

/*
 * WHAT: turn a deferred authdb grammar defect into an `nginx -t` failure, but
 *       only for the engine that actually reads the native grammar.
 * WHY:  `brix_authdb` is parsed by BOTH engines' parsers because the directive
 *       runs before `brix_authdb_engine` has settled.  An xrdacc authfile is
 *       full of bytes the native grammar has never accepted (record types
 *       `= x s h n o r t`, multi-pair lines, the `i`/`n` privilege letters), so
 *       raising at parse time would refuse every xrdacc deployment.
 * HOW:  called from the merge, where `format` is final.  Returns NGX_CONF_OK
 *       unless the native engine is selected AND a defect was recorded.
 */
char *
brix_authdb_defect_refuse(ngx_conf_t *cf, ngx_uint_t format,
                          const ngx_str_t *defect)
{
    if (format == BRIX_AUTHDB_FORMAT_XRDACC || defect == NULL
        || defect->len == 0)
    {
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "%V (the native authdb engine refuses a line it cannot "
                       "parse rather than silently dropping part of it; use "
                       "`brix_authdb_engine xrdacc` for XrdAcc-format files)",
                       defect);
    return NGX_CONF_ERROR;
}
