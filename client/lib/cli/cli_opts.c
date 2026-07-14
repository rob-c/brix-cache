/*
 * cli_opts.c — shared parser for the common connection/trace CLI flags.
 *
 * WHAT: brix_opts_init() zero-inits an brix_opts with the canonical defaults
 *       (verify_host on); brix_opts_parse_arg() recognises the connection flags
 *       every connecting tool accepts — --tls / --notlsok / --noverifyhost /
 *       --auth <p> / --wire-trace[=N] / --timing / --redirect-trace / --capture
 *       <p> — plus the resilience knobs --max-stall <ms> / --no-retry — and
 *       updates *o.  Also handles two universal flags:
 *         --version   prints "<argv0-basename> (BriX-Cache client) <version>"
 *                     to stdout and exits 0 immediately.
 *         --help      returns 2; the CALLER must print its usage to stdout and
 *                     exit 0 (usage text is per-tool, so we cannot do it here).
 * WHY:  This exact else-if ladder was copy-pasted into ~8 front-ends (xrdcp,
 *       xrddiag, xrdmapc, xrdgsitest, both FUSE drivers, ...); centralising it
 *       guarantees one canonical spelling/semantics and lets each tool's parse
 *       loop fall through to its OWN flags.
 * HOW:  A tool's option loop calls brix_opts_parse_arg() first; on 1 it `continue`s,
 *       on 0 it handles the arg itself; on 2 it prints usage to stdout and returns 0.
 *       Value-taking flags advance *i past the value, mirroring the historical
 *       `argv[++i]` idiom exactly (behaviour-preserving — the fields set are
 *       identical to the inline ladders).
 */
#include "brix.h"
#include "brix_ops.h"
#include "core/version.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/*
 * opts_basename — return the basename of a file path without modifying the
 * input string (POSIX basename() may modify its argument; we avoid that).
 * WHY: --version uses argv[0] to print the personality name; a safe, in-place
 *      basename keeps the implementation self-contained.
 */
static const char *
opts_basename(const char *path)
{
    const char *s = strrchr(path, '/');
    return (s != NULL && s[1] != '\0') ? s + 1 : path;
}

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

/*
 * opts_parse_universal — handle the two flags every tool honours the same way.
 *
 * WHAT: --version prints "<argv0-basename> (BriX-Cache client) <version>" to
 *       stdout and exits 0; --help returns 2 (the caller prints its own usage);
 *       any other argument returns 0 (not a universal flag).
 * WHY:  --version is a clean terminal action with no partial-state concern, so
 *       exiting inside the parser is safe.  --help text is per-tool, so we defer
 *       to the caller rather than printing it here.
 * HOW:  Two strcmp checks; the split keeps the main dispatcher's complexity low.
 */
static int
opts_parse_universal(const char *a, char **argv)
{
    if (strcmp(a, "--version") == 0) {
        printf("%s (BriX-Cache client) %s\n",
               opts_basename(argv[0]), brix_client_version());
        exit(0);
    }
    if (strcmp(a, "--help") == 0) {
        return 2;   /* caller: print usage to stdout, exit 0 */
    }
    return 0;
}

/*
 * Table of the value-less boolean toggles.  Each row names the flag, the int
 * field within brix_opts it sets (via offsetof, so one loop drives them all),
 * and the value to store — 1 for the enabling flags, 0 for --noverifyhost which
 * CLEARS the default-on verify_host.  Order is irrelevant: every name is a
 * distinct exact match.
 */
typedef struct {
    const char *name;
    size_t      field_off;
    int         value;
} opts_toggle_t;

static const opts_toggle_t opts_toggles[] = {
    { "--tls",            offsetof(brix_opts, want_tls),    1 },
    { "--notlsok",        offsetof(brix_opts, notlsok),     1 },
    { "--noverifyhost",   offsetof(brix_opts, verify_host), 0 },
    { "--timing",         offsetof(brix_opts, timing),      1 },
    { "--redirect-trace", offsetof(brix_opts, redir_trace), 1 },
    { "--wire-trace",     offsetof(brix_opts, wire_trace),  1 },
    { "--no-retry",       offsetof(brix_opts, no_retry),    1 },
};

/*
 * opts_parse_toggle — match `a` against the value-less boolean flag table.
 *
 * WHAT: On an exact match, store the row's value into the named int field of *o
 *       and return 1; otherwise return 0 (not a toggle).
 * WHY:  Table dispatch replaces a seven-branch if-ladder with one loop, keeping
 *       both this helper and the main dispatcher well under the complexity cap.
 * HOW:  Linear scan; the matched field is addressed by byte offset (all listed
 *       fields are int), mirroring the historical `o->field = value` writes.
 */
static int
opts_parse_toggle(brix_opts *o, const char *a)
{
    size_t k;
    for (k = 0; k < sizeof(opts_toggles) / sizeof(opts_toggles[0]); k++) {
        if (strcmp(a, opts_toggles[k].name) == 0) {
            *(int *)((char *)o + opts_toggles[k].field_off) = opts_toggles[k].value;
            return 1;
        }
    }
    return 0;
}

/*
 * opts_parse_valued — handle the flags that consume an argument (or a =value).
 *
 * WHAT: --wire-trace=N sets wire_trace from the inline value; --auth <p> /
 *       --capture <p> / --max-stall <ms> each consume the following argv slot
 *       (advancing *i) exactly as the historical `argv[++i]` idiom.  Returns 1
 *       when a flag was consumed, 0 otherwise.  --max-stall <=0 disables retry.
 * WHY:  Grouping the value-taking flags away from the boolean toggles keeps each
 *       helper single-purpose and under the complexity cap.
 * HOW:  The value-consuming flags guard on `*i + 1 < argc` so a trailing flag
 *       with no value falls through (returns 0) rather than reading past argv.
 */
static int
opts_parse_valued(brix_opts *o, int argc, char **argv, int *i)
{
    const char *a = argv[*i];

    if (strncmp(a, "--wire-trace=", 13) == 0) {
        o->wire_trace = atoi(a + 13);
        return 1;
    }
    if (strcmp(a, "--auth") == 0 && *i + 1 < argc) {
        o->auth_force = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--capture") == 0 && *i + 1 < argc) {
        o->capture = argv[++(*i)];
        return 1;
    }
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

int
brix_opts_parse_arg(brix_opts *o, int argc, char **argv, int *i)
{
    const char *a = argv[*i];

    /*
     * Universal flags first (--version exits, --help returns 2), then the
     * value-less boolean toggles, then the flags that consume a value.  Each
     * helper returns 1 when it consumed the arg; 0 means "not mine", so the
     * whole function returns 0 and the caller handles the arg itself.
     */
    int r = opts_parse_universal(a, argv);
    if (r != 0) {
        return r;
    }
    if (opts_parse_toggle(o, a)) {
        return 1;
    }
    if (opts_parse_valued(o, argc, argv, i)) {
        return 1;
    }
    return 0;
}


/*
 * brix_cli_parse_io_uring — strict CLI parse for the --io-uring mode flag.
 *
 * WHAT: Map "on" / "off" / "auto" to XRDC_IO_URING_{ON,OFF,AUTO}; anything
 *       else (including NULL and empty string) returns -1.
 * WHY:  CLI flags must reject unknown values immediately with a usage error so
 *       the user gets clear feedback.  The env-var path (XRDC_IO_URING) stays
 *       lenient — it silently falls back to AUTO because env vars are often set
 *       system-wide and must survive software upgrades without breaking callers.
 *       Only the explicit CLI flag is strict.
 * HOW:  Three strcmp checks; anything not matching returns -1 so the caller can
 *       print a tailored "invalid mode 'bogus' (use on|off|auto)" and exit 50.
 */
int
brix_cli_parse_io_uring(const char *s)
{
    if (s == NULL || s[0] == '\0') { return -1; }
    if (strcmp(s, "on")   == 0)    { return XRDC_IO_URING_ON;   }
    if (strcmp(s, "off")  == 0)    { return XRDC_IO_URING_OFF;  }
    if (strcmp(s, "auto") == 0)    { return XRDC_IO_URING_AUTO; }
    return -1;
}
