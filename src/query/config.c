#include "query_internal.h"

#include <stdarg.h>

/*
 * kXR_Qconfig: best-effort server capability query.
 */

static void
xrootd_qconfig_skip_ws(const char **pp)
{
    while (**pp == ' ' || **pp == '\t' || **pp == '\n' || **pp == '\r') {
        (*pp)++;
    }
}


static ngx_flag_t
xrootd_qconfig_next_token(const char **pp, char *tok, size_t tok_sz)
{
    size_t len;

    xrootd_qconfig_skip_ws(pp);
    if (**pp == '\0') {
        return 0;
    }

    len = 0;
    while (**pp != '\0' && **pp != ' ' && **pp != '\t'
           && **pp != '\n' && **pp != '\r')
    {
        if (len + 1 < tok_sz) {
            tok[len++] = **pp;
        }
        (*pp)++;
    }

    tok[len] = '\0';
    return 1;
}


static ngx_flag_t
xrootd_qconfig_append(char *resp, size_t resp_sz, size_t *pos,
    const char *fmt, ...)
{
    va_list ap;
    int     n;
    size_t  remaining;

    if (resp == NULL || pos == NULL || *pos >= resp_sz) {
        return 0;
    }

    remaining = resp_sz - *pos;

    va_start(ap, fmt);
    n = vsnprintf(resp + *pos, remaining, fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t) n >= remaining) {
        resp[*pos] = '\0';
        return 0;
    }

    *pos += (size_t) n;
    return 1;
}


ngx_int_t
xrootd_query_config(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    char        resp[512];
    size_t      pos = 0;
    const char *p;
    char        key[128];
    int         tpc_capable;

    /* TPC pull is available on writable data servers with a thread pool. */
    tpc_capable = (conf->allow_write && conf->thread_pool != NULL) ? 1 : 0;

    p = (ctx->payload && ctx->cur_dlen > 0) ? (const char *) ctx->payload : "";

    /*
     * Keys are whitespace-separated (see libXrdCl FileSystem::Query config,
     * e.g. "tpc tpcdlg"). Lines in the response must match reference XRootD:
     *   tpc   → a line whose first character is '0' or '1' (atoi for XrdCl)
     *   tpcdlg → literal "tpcdlg" when HTTP-TPC delegation is unavailable
     */
    while (xrootd_qconfig_next_token(&p, key, sizeof(key))) {

        if (strcmp(key, "chksum") == 0) {
            if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                       "chksum=adler32\n")) {
                break;
            }

        } else if (strcmp(key, "readv") == 0) {
            if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                       "readv=1\n")) {
                break;
            }

        } else if (strcmp(key, "tpc") == 0) {
            /*
             * Return just the numeric value (1 or 0) to match the reference
             * XRootD server when XRDTPC is set.  XrdCl::Utils::CheckTPCLite
             * parses the first response line with isdigit() + atoi(), so a
             * leading "tpc=" prefix would cause it to reject TPC support.
             */
            if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                       "%d\n", tpc_capable)) {
                break;
            }

        } else if (strcmp(key, "tpcdlg") == 0) {
            if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                       "tpcdlg\n")) {
                break;
            }

        } else {
            if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                       "%s=0\n", key)) {
                break;
            }
        }
    }

    if (pos == 0) {
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    return xrootd_send_ok(ctx, c, resp, (uint32_t) pos);
}
