/*
 * cli_conn.c — shared connect-and-report scaffold for the front-end tools.
 *
 * WHAT: brix_cli_connect() does the endpoint-parse → connect ladder every
 *       single-shot tool repeats, printing the canonical "prog: <msg>" (parse) /
 *       "prog: connect: <msg>" (connect) on failure and returning a process exit
 *       code (0 = connected).  brix_report_err() is the per-operation failure
 *       idiom — "tool: op path: msg" + a credential hint + the mapped shell code —
 *       that xrdfs repeats ~35×.
 * WHY:  Collapses the ~12 inline connect ladders in xrddiag and the bodies of the
 *       single-shot tools, and the xrdfs per-handler error block, to one call each
 *       — behaviour-preserving (identical messages, hints and exit codes).
 * HOW:  Mirrors the historical inline code exactly so adoption is a pure
 *       de-duplication: endpoint_parse failure → XRDC_EXIT_USAGE; connect failure
 *       → brix_shellcode(st); both after the same stderr line.
 *       brix_report_err accepts a nullable brix_url* to enable WS-3 (double-slash
 *       hint) and WS-7 (doctor referral) on the same error line (spec P3).
 */
#include "brix.h"
#include "cli/cli_hint.h"   /* brix_hint_url_double_slash, brix_hint_doctor_referral */

#include <stdio.h>

int
brix_cli_connect(const char *endpoint, const brix_opts *o,
                 brix_conn *c, const char *prog, brix_status *st)
{
    brix_url u;

    brix_status_clear(st);
    if (brix_endpoint_parse(endpoint, &u, st) != 0) {
        fprintf(stderr, "%s: %s\n", prog, st->msg);
        return XRDC_EXIT_USAGE;
    }
    if (brix_connect_resilient(c, &u, o, st) != 0) {
        fprintf(stderr, "%s: connect: %s\n", prog, st->msg);
        return brix_shellcode(st);
    }
    return 0;
}

/*
 * WHAT: build a "host[:port]" endpoint string from a parsed brix_url for the
 *       WS-7 doctor-referral hint ("xrddiag check <endpoint>").
 * WHY:  brix_report_err receives the parsed URL, not the original string;
 *       host[:port] is exactly what xrddiag check accepts as an endpoint.
 * HOW:  snprintf into the caller's buffer; returns the buffer on success or
 *       NULL when there is no host to report (the hint then falls back to a
 *       generic "<endpoint>" placeholder).  Sanitization (control-byte
 *       escaping) happens inside brix_hint_doctor_referral, not here.
 */
static const char *
report_err_endpoint(const brix_url *url, char *buf, size_t bufsz)
{
    if (url == NULL || url->host[0] == '\0') {
        return NULL;
    }
    if (url->port > 0) {
        snprintf(buf, bufsz, "%s:%d", url->host, url->port);
    } else {
        snprintf(buf, bufsz, "%s", url->host);
    }
    return buf;
}

int
brix_report_err(FILE *out, const char *tool, const char *op, const char *path,
                const brix_status *st, int want_write, const brix_url *url)
{
    /*
     * WHAT: print the "tool: op path: msg" line, then credential hint and
     *       the WS-3 / WS-7 canned hints where applicable.
     * WHY:  single shared error-reporter across xrdfs, xrd, xrdcp front-ends
     *       so WS-3/WS-7 hints are consistent and easy to audit.
     * HOW:  url is nullable.  The doctor referral (WS-7) is owned by
     *       brix_cred_hint_for_status_url — one canonical call chain — and
     *       here receives the host[:port] endpoint built from the parsed URL
     *       so the interactive hint names a concrete target.  The double-slash
     *       hint (WS-3) fires only for not-found-class failures on a URL whose
     *       single_slash_path bit is set (both gates live inside the helper).
     */
    char        epbuf[300];   /* host(256) + ':' + port digits + NUL */
    const char *endpoint;

    fprintf(out, "%s: %s %s: %s\n", tool, op, path, st->msg);
    endpoint = report_err_endpoint(url, epbuf, sizeof(epbuf));
    brix_cred_hint_for_status_url(st, want_write, out, endpoint); /* Phase 40 (c) + WS-7 */
    brix_hint_url_double_slash(st, url);                          /* spec WS-3 */
    return brix_shellcode(st);
}
