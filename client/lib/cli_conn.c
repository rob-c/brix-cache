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
 */
#include "brix.h"

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

int
brix_report_err(FILE *out, const char *tool, const char *op, const char *path,
                const brix_status *st, int want_write)
{
    fprintf(out, "%s: %s %s: %s\n", tool, op, path, st->msg);
    brix_cred_hint_for_status(st, want_write, out);   /* Phase 40 (c) */
    return brix_shellcode(st);
}
