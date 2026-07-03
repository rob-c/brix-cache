/*
 * scitag.c — SciTags flow-id parsing from a client-supplied opaque/CGI string.
 *
 * WHAT: brix_pmark_parse_scitag() extracts the `scitag.flow=<N>` parameter a
 *   client may attach to a root:// open (opaque `?scitag.flow=N`) or send as an
 *   HTTP `SciTag:` header (rendered here as "scitag.flow=N"), validates it
 *   against the 16-bit SciTags range, and splits it into (experiment, activity).
 *   The flow-id encode/decode/validate helpers themselves are tiny inlines in
 *   pmark.h; this file holds the one non-trivial routine (untrusted parsing).
 *
 * WHY: A client tag is a top-priority override of the config-driven mapping
 *   (mapping.c), so it must be parsed defensively: out-of-range or malformed
 *   input is rejected (treated as "no tag"), never coerced to a bogus code, and
 *   the raw value never reaches the firefly JSON unescaped (we only ever emit the
 *   parsed integers, never the client's bytes).
 *
 * HOW: Scan for the "scitag.flow=" token at a parameter boundary (string start,
 *   or just after '?' / '&' / ';'), parse the following run of decimal digits,
 *   range-check [65,65535], and split via brix_pmark_flow_split().
 */

#include "pmark.h"

#define BRIX_PMARK_SCITAG_KEY      "scitag.flow="
#define BRIX_PMARK_SCITAG_KEY_LEN  (sizeof(BRIX_PMARK_SCITAG_KEY) - 1)

/* True if `p` begins a CGI parameter (start-of-string handled by caller). */
static ngx_inline int
pmark_is_param_boundary(char ch)
{
    return ch == '?' || ch == '&' || ch == ';';
}

/*
 * Parse the value of a located "scitag.flow=" token: `p` points at the run of
 * decimal digits just past the '='.  Range-checks the integer and splits it
 * into (experiment, activity).  Returns NGX_OK on a valid in-range flow,
 * NGX_ERROR on malformed / out-of-range input (caller treats as "no tag").
 */
static ngx_int_t
pmark_parse_flow_value(const char *p, ngx_uint_t *exp, ngx_uint_t *act)
{
    ngx_uint_t  flow = 0;
    int         have_digits = 0;

    /* Parse the run of decimal digits.  Bound the accumulator so a long digit
     * string cannot overflow before the range check rejects it. */
    while (*p >= '0' && *p <= '9') {
        have_digits = 1;
        flow = flow * 10 + (ngx_uint_t) (*p - '0');
        if (flow > BRIX_PMARK_FLOW_MAX) {
            return NGX_ERROR;          /* out of range -> "no tag" */
        }
        p++;
    }

    /* Must be exactly an integer terminated by end / next param. */
    if (!have_digits || (*p != '\0' && !pmark_is_param_boundary(*p))) {
        return NGX_ERROR;
    }

    if (brix_pmark_flow_split(flow, exp, act) != NGX_OK) {
        return NGX_ERROR;              /* < 65 etc. */
    }

    /* Defence in depth: the split fields must also be individually in range. */
    if (brix_pmark_codes_valid(*exp, *act) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
brix_pmark_parse_scitag(const char *cgi, ngx_uint_t *exp, ngx_uint_t *act)
{
    const char  *p;

    if (cgi == NULL || *cgi == '\0') {
        return NGX_DECLINED;
    }

    /* Find "scitag.flow=" at a parameter boundary, then parse its value. */
    for (p = cgi; *p; p++) {
        if (p != cgi && !pmark_is_param_boundary(p[-1])) {
            continue;
        }
        if (ngx_strncmp(p, BRIX_PMARK_SCITAG_KEY, BRIX_PMARK_SCITAG_KEY_LEN)
            == 0)
        {
            return pmark_parse_flow_value(p + BRIX_PMARK_SCITAG_KEY_LEN,
                                          exp, act);
        }
    }
    return NGX_DECLINED;
}
