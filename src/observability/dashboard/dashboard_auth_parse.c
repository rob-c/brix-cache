#include "dashboard_auth_internal.h"

#include <string.h>
#include <ctype.h>

/*
 * dashboard/dashboard_auth_parse.c — request-parsing primitives for the
 * dashboard authentication unit (split from auth.c, phase-79).
 *
 * WHAT: Pure byte-range scanners over untrusted request input:
 *         - the Cookie: header, pair-by-pair, to find one named cookie value
 *           (dashboard_find_cookie), and
 *         - an application/x-www-form-urlencoded body, to extract and URL-decode
 *           one named field (dashboard_form_value).
 *
 * WHY: These parsers have no crypto or credential knowledge and are shared by
 *      both the cookie-verification path (auth.c) and the login flow
 *      (dashboard_auth_login.c). Isolating them keeps the parsing surface —
 *      the part that touches attacker-controlled bytes — small and reviewable.
 *      Behaviour is byte-for-byte identical to the original auth.c.
 */

/*
 * WHAT: Locate the first Cookie: request header, or NULL if the request has none.
 * WHY:  nginx 1.23.0 replaced the `headers_in.cookies` array (of
 *       ngx_table_elt_t *) with a single `headers_in.cookie` linked-list head,
 *       so read whichever the build's nginx provides — keeping the module
 *       buildable on EL stock nginx (1.20.x) as well as current releases.
 * HOW:  Either way we take the first Cookie header; dashboard_find_cookie() then
 *       walks the ';'-separated pairs inside its value.
 */
static ngx_table_elt_t *
dash_cookie_header(ngx_http_request_t *r)
{
#if (nginx_version >= 1023000)
    return r->headers_in.cookie;
#else
    if (r->headers_in.cookies.nelts > 0) {
        return ((ngx_table_elt_t **) r->headers_in.cookies.elts)[0];
    }
    return NULL;
#endif
}

/*
 * WHAT: Consume one ';'-delimited "name=value" pair from a Cookie header value,
 *       advancing *pp past it (including the trailing ';' if present).
 * WHY:  dashboard_find_cookie() walks the whole header pair-by-pair; isolating the scan of
 *       a single pair keeps the caller a flat match loop.
 * HOW:  Skip leading whitespace, then scan to ';' (or header end) remembering
 *       the FIRST '=' so name splits from value. Only the FIRST '=' splits; any
 *       later '=' is part of the value (cookie values may contain '=').
 *       Sets *start to the pair's name start, *eq to the '=' (or NULL for a
 *       valueless token); on return *pp points at the pair terminator before it
 *       is skipped by the caller — the value runs [*eq + 1, pair end).
 */
static void
dash_cookie_next_pair(u_char **pp, u_char *end, u_char **start, u_char **eq)
{
    u_char *p = *pp;

    /* skip whitespace */
    while (p < end && (*p == ' ' || *p == '\t')) { p++; }

    *start = p;

    *eq = NULL;
    while (p < end && *p != ';') {
        if (*p == '=' && *eq == NULL) { *eq = p; }
        p++;
    }

    *pp = p;
}

/*
 * Find the value of a named cookie in the Cookie: header.
 * Returns NGX_OK and sets *val / *val_len on success, NGX_DECLINED if not found.
 */
ngx_int_t
dashboard_find_cookie(ngx_http_request_t *r, const char *name, size_t name_len,
    u_char **val, size_t *val_len)
{
    ngx_table_elt_t  *cookie_hdr;
    u_char           *p, *end, *eq, *start;

    cookie_hdr = dash_cookie_header(r);
    if (cookie_hdr == NULL) {
        return NGX_DECLINED;
    }

    p   = cookie_hdr->value.data;
    end = p + cookie_hdr->value.len;

    /* Walk the "name1=val1; name2=val2" list one pair at a time. p advances
     * across the whole header; each iteration consumes one ';'-delimited pair. */
    while (p < end) {
        dash_cookie_next_pair(&p, end, &start, &eq);

        /* Name must match exactly (length + bytes); value is everything between
         * the '=' and the pair terminator p. */
        if (eq != NULL && (size_t)(eq - start) == name_len &&
            ngx_memcmp(start, name, name_len) == 0)
        {
            *val     = eq + 1;
            *val_len = (size_t)(p - (eq + 1));
            return NGX_OK;
        }

        if (p < end) { p++; }  /* skip ';' */
    }

    return NGX_DECLINED;
}

/* One "key=value" pair delimited inside an urlencoded body: [key_start,
 * key_start + key_len) is the raw key, [val_start, val_end) the raw value. */
typedef struct {
    size_t  key_start;
    size_t  key_len;
    size_t  val_start;
    size_t  val_end;
} dash_form_pair_t;

/*
 * WHAT: Scan the next complete "key=value" pair from an urlencoded body,
 *       advancing *pos past it (and past any valueless tokens before it).
 * WHY:  dashboard_form_value() only cares about pairs that HAVE a value;
 *       centralizing the '&'-walk keeps the caller a flat match loop.
 * HOW:  Scan the key up to its '=' (skipping whole tokens with no '='), then
 *       delimit the value from just after '=' to the next '&' or body end.
 *       Returns NGX_OK with *pair filled, or NGX_DECLINED at body end.
 */
static ngx_int_t
dash_form_next_pair(const u_char *body, size_t body_len, size_t *pos,
    dash_form_pair_t *pair)
{
    size_t i = *pos;

    while (i < body_len) {
        pair->key_start = i;

        /* Scan the key up to its '=' (or '&'/end if the pair has no value). */
        while (i < body_len && body[i] != '=' && body[i] != '&') {
            i++;
        }
        pair->key_len = i - pair->key_start;

        /* No '=' for this token: skip the whole valueless pair and continue. */
        if (i >= body_len || body[i] != '=') {
            while (i < body_len && body[i] != '&') {
                i++;
            }
            if (i < body_len) {
                i++;
            }
            continue;
        }

        /* Delimit the value: from just after '=' to the next '&' or body end. */
        i++;
        pair->val_start = i;
        while (i < body_len && body[i] != '&') {
            i++;
        }
        pair->val_end = i;

        if (i < body_len) {
            i++;    /* skip '&' */
        }
        *pos = i;
        return NGX_OK;
    }

    *pos = i;
    return NGX_DECLINED;
}

/*
 * WHAT: URL-decode one raw form value [val_start, val_end) into out->buf,
 *       NUL-terminated and truncated to out->size; decoded length -> out->len.
 * WHY:  Application/x-www-form-urlencoded values escape spaces as '+' and
 *       arbitrary bytes as "%HH"; the login fields must be decoded before any
 *       credential comparison.
 * HOW:  '+' -> space, "%HH" -> the byte, anything else verbatim; k+1 < size
 *       reserves space for the trailing NUL.
 */
static void
dash_form_decode_value(const u_char *body, size_t val_start, size_t val_end,
    dash_form_out_t *out)
{
    size_t j, k;

    for (j = val_start, k = 0; j < val_end && k + 1 < out->size; j++) {
        if (body[j] == '+') {
            out->buf[k++] = ' ';
        } else if (body[j] == '%' && j + 2 < val_end
                   && isxdigit(body[j + 1])
                   && isxdigit(body[j + 2]))
        {
            /* "%HH" escape: fold each hex nibble (case-insensitive via
             * |0x20) into the decoded byte (hi<<4 | lo); skip the 2 hex
             * chars consumed. */
            unsigned int hi, lo;
            hi = body[j + 1] <= '9' ? body[j + 1] - '0'
                 : (body[j + 1] | 0x20) - 'a' + 10;
            lo = body[j + 2] <= '9' ? body[j + 2] - '0'
                 : (body[j + 2] | 0x20) - 'a' + 10;
            out->buf[k++] = (char) ((hi << 4) | lo);
            j += 2;
        } else {
            out->buf[k++] = (char) body[j];
        }
    }
    out->buf[k] = '\0';
    out->len = k;
}

/*
 * WHAT: Extract and URL-decode one field from an application/x-www-form-urlencoded
 *       request body, writing the decoded value (NUL-terminated, truncated to
 *       out->size) to out->buf and its length to out->len.
 * HOW:  Iterate "key=value" pairs separated by '&' (dash_form_next_pair); on a
 *       name match, decode the value applying form rules (dash_form_decode_value).
 *       Returns NGX_OK on the first match, NGX_DECLINED if the field is absent.
 */
ngx_int_t
dashboard_form_value(const u_char *body, size_t body_len,
    const char *name, dash_form_out_t *out)
{
    size_t            name_len = strlen(name);
    size_t            i = 0;
    dash_form_pair_t  pair;

    if (out == NULL || out->buf == NULL || out->size == 0) {
        return NGX_DECLINED;
    }

    out->len = 0;
    out->buf[0] = '\0';

    while (dash_form_next_pair(body, body_len, &i, &pair) == NGX_OK) {
        if (pair.key_len == name_len
            && ngx_memcmp(body + pair.key_start, name, name_len) == 0)
        {
            dash_form_decode_value(body, pair.val_start, pair.val_end, out);
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}
