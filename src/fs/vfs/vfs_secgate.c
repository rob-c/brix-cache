/*
 * vfs_secgate.c — generic per-capability TLS gating (parser + gate + setter).
 *
 * WHAT: brix_tls_require_parse (directive grammar → 4-bit mask),
 *       brix_tls_gate_refused (mask × op-caps × transport → refused bits),
 *       brix_tls_cap_name (bit → token for refusal messages), and
 *       brix_conf_set_tls_require (offset-based ngx_conf_t setter shared by
 *       the stream and HTTP directive tables).
 *
 * WHY:  One implementation of the stock `xrootd.tls` capability policy for
 *       every plane — see vfs_secgate.h. Keeping parse/check pure lets the
 *       config-parse negatives and the enforcement paths be tested without
 *       touching each other.
 *
 * HOW:  Left-to-right token fold: `all` → BRIX_TLSREQ_ALL, a bare cap ORs its
 *       bit, `-cap` clears its bit, `none` → 0 and must be the only token.
 *       Unknown tokens (and `-all`/`-none`) fail the parse. The gate is one
 *       expression: bits that are (required by mask) AND (used by this op)
 *       AND (transport is cleartext); SESSION is a required bit on every
 *       post-handshake op its callers pass, so `session` alone locks the
 *       whole session exactly like stock.
 */

#include "vfs_secgate.h"

/* token → bit; "all"/"none" are handled structurally in the parser. */
static ngx_uint_t
secgate_cap_bit(ngx_str_t *tok)
{
    static const struct {
        const char *name;
        size_t      len;
        ngx_uint_t  bit;
    } caps[] = {
        { "login",   5, BRIX_TLSREQ_LOGIN   },
        { "session", 7, BRIX_TLSREQ_SESSION },
        { "data",    4, BRIX_TLSREQ_DATA    },
        { "tpc",     3, BRIX_TLSREQ_TPC     },
    };
    ngx_uint_t i;

    for (i = 0; i < sizeof(caps) / sizeof(caps[0]); i++) {
        if (tok->len == caps[i].len
            && ngx_strncmp(tok->data, caps[i].name, caps[i].len) == 0)
        {
            return caps[i].bit;
        }
    }
    return 0;
}

/* brix_tls_require_parse — fold directive tokens into a capability mask.
 *
 * Grammar (stock xrootd.tls shape): `none` alone, or any sequence of
 * `all|login|session|data|tpc` and `-login|-session|-data|-tpc` applied
 * left-to-right. Returns NGX_ERROR on an unknown token, `-all`/`-none`,
 * or `none` mixed with other tokens. */
ngx_int_t
brix_tls_require_parse(ngx_str_t *args, ngx_uint_t nargs, ngx_uint_t *mask_out)
{
    ngx_uint_t  i, bit, mask = 0;
    ngx_str_t   tok;

    for (i = 0; i < nargs; i++) {
        tok = args[i];

        if (tok.len == 4 && ngx_strncmp(tok.data, "none", 4) == 0) {
            if (nargs != 1) {
                return NGX_ERROR;      /* `none` must stand alone */
            }
            *mask_out = 0;
            return NGX_OK;
        }
        if (tok.len == 3 && ngx_strncmp(tok.data, "all", 3) == 0) {
            mask = BRIX_TLSREQ_ALL;
            continue;
        }
        if (tok.len > 1 && tok.data[0] == '-') {
            tok.data++;
            tok.len--;
            bit = secgate_cap_bit(&tok);
            if (bit == 0) {
                return NGX_ERROR;      /* -all / -none / unknown */
            }
            mask &= ~bit;
            continue;
        }
        bit = secgate_cap_bit(&tok);
        if (bit == 0) {
            return NGX_ERROR;
        }
        mask |= bit;
    }

    *mask_out = mask;
    return NGX_OK;
}

/* brix_tls_gate_refused — the one enforcement expression.
 *
 * `caps` is the capability set the current operation exercises (e.g. a
 * kXR_read passes SESSION|DATA); the result is the required-but-cleartext
 * subset, 0 when allowed. TLS transports are never refused. */
ngx_uint_t
brix_tls_gate_refused(ngx_uint_t mask, ngx_uint_t caps, ngx_uint_t is_tls)
{
    if (is_tls) {
        return 0;
    }
    return mask & caps;
}

/* First refused capability's token, for kXR_TLSRequired / 403 messages. */
const char *
brix_tls_cap_name(ngx_uint_t bits)
{
    if (bits & BRIX_TLSREQ_LOGIN)   { return "login"; }
    if (bits & BRIX_TLSREQ_SESSION) { return "session"; }
    if (bits & BRIX_TLSREQ_DATA)    { return "data"; }
    if (bits & BRIX_TLSREQ_TPC)     { return "tpc"; }
    return "none";
}

/* brix_conf_set_tls_require — `brix_tls_require <caps...>;` setter.
 *
 * Offset-based so the same function serves the HTTP common conf and the
 * stream srv conf (both hold the mask in their shared preamble). Rejects a
 * duplicate directive and any token the parser refuses. */
char *
brix_conf_set_tls_require(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char       *p = conf;
    ngx_uint_t *field;
    ngx_str_t  *value;

    field = (ngx_uint_t *) (p + cmd->offset);
    if (*field != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;
    if (brix_tls_require_parse(value + 1, cf->args->nelts - 1, field)
        != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid brix_tls_require capability; expected "
            "\"none\" or [all|login|session|data|tpc|-<cap>]...");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
