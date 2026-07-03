/*
 * cli_opts.c — shared parser for the common connection/trace CLI flags.
 *
 * WHAT: brix_opts_init() zero-inits an brix_opts with the canonical defaults
 *       (verify_host on); brix_opts_parse_arg() recognises the connection flags
 *       every connecting tool accepts — --tls / --notlsok / --noverifyhost /
 *       --auth <p> / --wire-trace[=N] / --timing / --redirect-trace / --capture
 *       <p> — plus the resilience knobs --max-stall <ms> / --no-retry — and
 *       updates *o.
 * WHY:  This exact else-if ladder was copy-pasted into ~8 front-ends (xrdcp,
 *       xrddiag, xrdmapc, xrdgsitest, both FUSE drivers, ...); centralising it
 *       guarantees one canonical spelling/semantics and lets each tool's parse
 *       loop fall through to its OWN flags.
 * HOW:  A tool's option loop calls brix_opts_parse_arg() first; on 1 it `continue`s,
 *       on 0 it handles the arg itself.  Value-taking flags advance *i past the
 *       value, mirroring the historical `argv[++i]` idiom exactly (behaviour-
 *       preserving — the fields set are identical to the inline ladders).
 */
#include "brix.h"

#include <stdlib.h>
#include <string.h>

void
brix_opts_init(brix_opts *o)
{
    memset(o, 0, sizeof(*o));
    o->verify_host = 1;   /* default: check the server cert name */

    /* Resilience is ON by default: max_stall_ms left 0 ⇒ the library uses
     * XRDC_DEFAULT_MAX_STALL_MS. $XRDC_MAX_STALL_MS overrides — a positive value
     * widens/narrows the window; 0 (or negative) disables it (fail fast). */
    const char *e = getenv("XRDC_MAX_STALL_MS");
    if (e != NULL && *e != '\0') {
        int v = atoi(e);
        if (v <= 0) {
            o->no_retry = 1;
        } else {
            o->max_stall_ms = v;
        }
    }
}

int
brix_opts_parse_arg(brix_opts *o, int argc, char **argv, int *i)
{
    const char *a = argv[*i];

    if (strcmp(a, "--tls") == 0)             { o->want_tls = 1;     return 1; }
    if (strcmp(a, "--notlsok") == 0)         { o->notlsok = 1;      return 1; }
    if (strcmp(a, "--noverifyhost") == 0)    { o->verify_host = 0;  return 1; }
    if (strcmp(a, "--timing") == 0)          { o->timing = 1;       return 1; }
    if (strcmp(a, "--redirect-trace") == 0)  { o->redir_trace = 1;  return 1; }
    if (strcmp(a, "--wire-trace") == 0)      { o->wire_trace = 1;   return 1; }
    if (strncmp(a, "--wire-trace=", 13) == 0){ o->wire_trace = atoi(a + 13); return 1; }
    if (strcmp(a, "--auth") == 0 && *i + 1 < argc) {
        o->auth_force = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--capture") == 0 && *i + 1 < argc) {
        o->capture = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--no-retry") == 0)        { o->no_retry = 1;     return 1; }
    if (strcmp(a, "--max-stall") == 0 && *i + 1 < argc) {
        int v = atoi(argv[++(*i)]);
        if (v <= 0) {
            o->no_retry = 1;
        } else {
            o->max_stall_ms = v;
            o->no_retry = 0;
        }
        return 1;
    }
    return 0;
}
