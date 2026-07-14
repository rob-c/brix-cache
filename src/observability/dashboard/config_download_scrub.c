/*
 * dashboard/config_download_scrub.c - in-place embedded-credential scrubbing.
 *
 * Split verbatim from config_download.c: the defence-in-depth layer that scrubs
 * secrets hiding INSIDE an otherwise-safe surviving value —
 * "scheme://user:pass@host" userinfo and "?token=/&secret=/&sig=" query params.
 * Never grows the buffer (see dashboard_redact_region). See config_download.c
 * for the full security model.
 */

#include "dashboard_http.h"
#include "core/http/http_headers.h"   /* brix_http_source_offer (AGPL sec.13) */
#include "core/compat/cstr.h"         /* brix_str_cbuf */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config_download_internal.h"

/*
 * Query-string credential keys whose value is scrubbed inside surviving URLs
 * ("?token=..." / "&sig=..."). Matched case-insensitively at a '?'/'&'
 * boundary; first hit wins (behavior-frozen table — do not reorder).
 */
static const char *const dashboard_cred_query_keys[] = {
    "token=", "access_token=", "secret=", "client_secret=", "password=",
    "passwd=", "apikey=", "api_key=", "key=", "sig=", "signature=",
    "x-amz-credential=", "x-amz-signature=", "x-amz-security-token=", NULL
};

/*
 * Overwrite the secret region [vs,ve) with the redaction marker. NEVER grow
 * the buffer: write min(marker,old) bytes (a sub-marker-length secret is
 * fully covered by a marker prefix), and only shrink (memmove the tail left)
 * when the secret is longer than the marker. Returns the new end pointer.
 */
static u_char *
dashboard_redact_region(u_char *vs, u_char *ve, u_char *end)
{
    size_t rep = ngx_strlen(DASHBOARD_REDACTED);
    size_t old = (size_t) (ve - vs);
    size_t n   = (rep < old) ? rep : old;

    ngx_memcpy(vs, DASHBOARD_REDACTED, n);
    if (old > rep) {
        ngx_memmove(vs + rep, ve, (size_t) (end - ve));
        end -= (old - rep);
    }
    return end;
}

/*
 * Scan the URL authority starting at `auth` (just past "://") for a
 * "user:pass@" userinfo block. Returns the '@' pointer when one is found
 * before the authority ends (path/query/fragment/whitespace/quote/';'),
 * else NULL. *colon receives the first ':' seen inside the scanned span
 * (may be set even when NULL is returned).
 */
static u_char *
dashboard_userinfo_at(u_char *auth, u_char *end, u_char **colon)
{
    u_char *q = auth;

    *colon = NULL;
    while (q < end && *q != '/' && *q != '?' && *q != '#'
           && *q != ' ' && *q != '\t' && *q != '"' && *q != '\''
           && *q != ';')
    {
        if (*q == ':' && *colon == NULL) { *colon = q; }
        if (*q == '@') { return q; }
        q++;
    }
    return NULL;
}

/*
 * Redact "scheme://user:pass@host" userinfo when `s` points at "://": both a
 * ':' and a later '@' must occur before the authority ends. On a rewrite,
 * *endp is updated (the buffer may shrink) and the resume pointer (start of
 * the rewritten authority) is returned so the caller re-scans from there;
 * otherwise NULL (no rewrite, caller advances normally).
 */
static u_char *
dashboard_scrub_userinfo(u_char *s, u_char **endp)
{
    u_char *end = *endp;
    u_char *auth, *at, *colon;

    if (s + 3 > end || s[0] != ':' || s[1] != '/' || s[2] != '/') {
        return NULL;
    }
    auth = s + 3;
    at = dashboard_userinfo_at(auth, end, &colon);
    if (at == NULL || colon == NULL || colon >= at) {
        return NULL;
    }
    *endp = dashboard_redact_region(auth, at, end);
    return auth;
}

/* End of a query-param value: up to '&' or a value delimiter. */
static u_char *
dashboard_query_value_end(u_char *vs, u_char *end)
{
    u_char *ve = vs;

    while (ve < end && *ve != '&' && *ve != ' ' && *ve != '\t'
           && *ve != '"' && *ve != '\'' && *ve != ';' && *ve != '#') {
        ve++;
    }
    return ve;
}

/*
 * Scrub one query parameter starting at `kv` (the byte after '?'/'&'): if it
 * matches a credential key from the table, overwrite its value with the
 * redaction marker (never growing — see dashboard_redact_region). Returns the
 * (possibly shrunk) new end pointer; first table hit wins.
 */
static u_char *
dashboard_scrub_query_param(u_char *kv, u_char *end)
{
    size_t i;

    for (i = 0; dashboard_cred_query_keys[i] != NULL; i++) {
        size_t kl = ngx_strlen(dashboard_cred_query_keys[i]);

        if (kv + kl <= end
            && dashboard_name_eq(kv, kl, dashboard_cred_query_keys[i]))
        {
            u_char *vs = kv + kl;
            u_char *ve = dashboard_query_value_end(vs, end);

            if (ve > vs) {
                end = dashboard_redact_region(vs, ve, end);
            }
            return end;
        }
    }
    return end;
}

/*
 * In-place scrub of embedded credentials in a surviving value region [p,end):
 *   scheme://user:pass@host          -> scheme://[redacted]@host
 *   ...?token=v / &secret=v / &sig=v -> ...?token=[redacted]&...
 * Returns the new end pointer (the region may shrink). Defence-in-depth for the
 * brix_*_url / upstream / origin directives that pass the keep test.
 */
u_char *
dashboard_scrub_value_creds(u_char *p, u_char *end)
{
    u_char *s = p;

    while (s < end) {
        /* userinfo: "://" ... ':' ... '@' before the authority ends */
        u_char *resume = dashboard_scrub_userinfo(s, &end);

        if (resume != NULL) {
            s = resume;   /* continue scanning after the rewrite */
            continue;
        }

        /* query credential params: <key>=<value> up to & / delimiter */
        if (*s == '?' || *s == '&') {
            end = dashboard_scrub_query_param(s + 1, end);
        }
        s++;
    }
    return end;
}
