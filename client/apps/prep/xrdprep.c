/*
 * xrdprep.c — issue a kXR_prepare (stage/cancel/evict/…) for one or more paths.
 *
 * WHAT: `xrdprep [-s|-c|-w|-f|-e] [-p PRTY] host[:port] <path>...` — a scriptable
 *       subset of `xrdfs prepare`. -s stage, -c cancel, -w write-mode, -f fresh,
 *       -e evict, -p priority (0-3).
 * WHY:  A thin front-end over the client library's brix_prepare. libXrdCl-free.
 * HOW:  brix_endpoint_parse → brix_connect → brix_prepare(options, optionX, prty).
 */
#include "brix.h"
#include "core/compat/crypto.h"
#include "core/version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XRDPREP_MAX_PATHS 64

/*
 * xrdprep_args — accumulated result of parsing the command line.
 *
 * options/optionX carry the kXR_prepare flag words exactly as the wire request
 * expects them (kXR_evict lives in optionX, all other flags in options); prty is
 * the 0-3 priority; endpoint is host[:port]; paths[]/np are the target paths.
 */
typedef struct {
    int          options;
    int          optionX;
    int          prty;
    int          np;
    const char  *endpoint;
    const char  *paths[XRDPREP_MAX_PATHS];
} xrdprep_args;

/*
 * xrdprep_flag_t — one boolean prepare flag, matched by short or long spelling.
 *
 * is_optionX selects which flag word the bit is OR-ed into (optionX for evict,
 * options for the rest), preserving the wire split the original ladder encoded.
 */
typedef struct {
    const char  *short_opt;
    const char  *long_opt;
    int          is_optionX;
    int          bit;
} xrdprep_flag_t;

/*
 * The boolean-flag table drives argument classification instead of an else-if
 * ladder (coding-standards §8.6). Order is irrelevant: each entry is a distinct
 * flag, and -p (priority, value-bearing) and the positional host/path arguments
 * are handled separately in the parse loop.
 */
static const xrdprep_flag_t xrdprep_flags[] = {
    { "-s", "--stage",  0, kXR_stage  },
    { "-c", "--cancel", 0, kXR_cancel },
    { "-w", "--wmode",  0, kXR_wmode  },
    { "-f", "--fresh",  0, kXR_fresh  },
    { "-e", "--evict",  1, kXR_evict  },
};

/* ---- Print the full --help usage text ----
 *
 * WHAT: Writes the multi-line usage block for xrdprep to stdout. No return value.
 *
 * WHY:  Keeps the (long, constant) help string out of the argument dispatcher so
 *       that dispatcher stays small and readable.
 *
 * HOW:  1. Emit a single printf with the option summary and the shared footer,
 *          substituting argv0 for the program name.
 */
static void
xrdprep_print_help(const char *argv0)
{
    printf("usage: %s [-s|-c|-w|-f|-e] [-p prty] host[:port] <path>...\n"
           "  -s, --stage     request tape staging\n"
           "  -c, --cancel    cancel a pending stage\n"
           "  -w, --wmode     write-mode hint\n"
           "  -f, --fresh     invalidate cached copy\n"
           "  -e, --evict     evict from disk cache\n"
           "  -p, --priority <prty>  priority 0-3 (default 0)\n"
           BRIX_USAGE_FOOTER("xrdprep"),
           argv0);
}

/* ---- Handle --version / --help / -h before normal parsing ----
 *
 * WHAT: If argv[1] is a recognised meta-flag, prints the requested text and
 *       returns 0 (the process exit code). Returns -1 when no meta-flag applies,
 *       signalling the caller to continue with normal argument parsing.
 *
 * WHY:  These flags short-circuit the tool and are checked positionally at
 *       argv[1] only — deliberately not routed through the shared flag table,
 *       matching the original behaviour exactly.
 *
 * HOW:  1. Require at least one user argument; otherwise report "not handled".
 *       2. On --version, print the client version banner and return 0.
 *       3. On --help or -h, print the usage block and return 0.
 *       4. Otherwise return -1.
 */
static int
xrdprep_handle_meta_flags(int argc, char **argv)
{
    if (argc < 2) {
        return -1;
    }
    if (strcmp(argv[1], "--version") == 0) {
        printf("xrdprep (BriX-Cache client) %s\n", brix_client_version());
        return 0;
    }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        xrdprep_print_help(argv[0]);
        return 0;
    }
    return -1;
}

/* ---- Match one argument against the boolean prepare-flag table ----
 *
 * WHAT: If `a` equals the short or long spelling of a table entry, OR-s that
 *       entry's bit into *options or *optionX and returns 1. Returns 0 when `a`
 *       is not a boolean flag.
 *
 * WHY:  Replaces the original per-flag else-if chain with a single table walk,
 *       keeping the wire split (kXR_evict → optionX, others → options) as data.
 *
 * HOW:  1. Scan every table row.
 *       2. On a short- or long-name hit, set the bit in the selected flag word
 *          and return 1.
 *       3. If no row matches, return 0.
 */
static int
xrdprep_match_flag(const char *a, int *options, int *optionX)
{
    size_t k;

    for (k = 0; k < sizeof(xrdprep_flags) / sizeof(xrdprep_flags[0]); k++) {
        const xrdprep_flag_t *f = &xrdprep_flags[k];
        if (strcmp(a, f->short_opt) == 0 || strcmp(a, f->long_opt) == 0) {
            if (f->is_optionX) {
                *optionX |= f->bit;
            } else {
                *options |= f->bit;
            }
            return 1;
        }
    }
    return 0;
}

/* ---- Parse the whole command line into an xrdprep_args ----
 *
 * WHAT: Walks argv[1..argc-1], filling *out with flag words, priority, endpoint,
 *       and up to XRDPREP_MAX_PATHS target paths. No return value; *out must be
 *       zero-initialised by the caller.
 *
 * WHY:  Isolates the argument grammar from main so main is a flat orchestrator.
 *
 * HOW:  1. For each argument, first try the boolean-flag table; on a match, skip
 *          to the next argument.
 *       2. Else, on -p/--priority with a following token, consume it via atoi.
 *       3. Else, the first non-flag token is the endpoint.
 *       4. Else, remaining tokens are paths, until the path array is full.
 */
static void
xrdprep_parse_args(int argc, char **argv, xrdprep_args *out)
{
    int i;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (xrdprep_match_flag(a, &out->options, &out->optionX)) {
            continue;
        }
        if ((strcmp(a, "-p") == 0 || strcmp(a, "--priority") == 0) && i + 1 < argc) {
            out->prty = atoi(argv[++i]);
        }
        else if (out->endpoint == NULL)              { out->endpoint = a; }
        else if (out->np < XRDPREP_MAX_PATHS)        { out->paths[out->np++] = a; }
    }
}

/* ---- Connect, send the prepare request, print any reply ----
 *
 * WHAT: Connects to args->endpoint, issues brix_prepare for the collected paths,
 *       prints a non-empty server reply, and returns the process exit code
 *       (0 on success, the connect rc or brix_shellcode(&st) on failure).
 *
 * WHY:  Groups the network side effects behind one call so main reads as parse →
 *       validate → run.
 *
 * HOW:  1. Open the connection; propagate a non-zero connect rc unchanged.
 *       2. On brix_prepare failure, print the error, close, and map st to a
 *          shell exit code.
 *       3. On success, close, print the reply if any, and return 0.
 */
static int
xrdprep_run(char **argv, const xrdprep_args *args)
{
    brix_conn    c;
    brix_status  st;
    char         reply[1024];

    int rc = brix_cli_connect(args->endpoint, NULL, &c, argv[0], &st);
    if (rc != 0) {
        return rc;
    }
    if (brix_prepare(&c, args->paths, args->np, args->options, args->optionX,
                     args->prty, reply, sizeof(reply), &st) != 0) {
        fprintf(stderr, "%s: %s\n", argv[0], st.msg);
        brix_close(&c);
        return brix_shellcode(&st);
    }
    brix_close(&c);
    if (reply[0] != '\0') {
        printf("%s\n", reply);
    }
    return 0;
}

/* ---- Program entry point ----
 *
 * WHAT: Parses the command line and issues one kXR_prepare, returning the process
 *       exit code (0 success, 50 on usage error, else the connect/prepare code).
 *
 * WHY:  Thin orchestrator over the parse and run helpers; libXrdCl-free.
 *
 * HOW:  1. Handle --version/--help/-h and return early if one applied.
 *       2. Parse the remaining arguments into an xrdprep_args.
 *       3. Require an endpoint and at least one path, else print usage, return 50.
 *       4. Delegate to xrdprep_run and return its exit code.
 */
int
main(int argc, char **argv)
{
    xrdprep_args args;

    int meta = xrdprep_handle_meta_flags(argc, argv);
    if (meta >= 0) {
        return meta;
    }

    memset(&args, 0, sizeof(args));
    xrdprep_parse_args(argc, argv, &args);

    if (args.endpoint == NULL || args.np == 0) {
        fprintf(stderr,
                "usage: %s [-s|-c|-w|-f|-e] [-p prty] host[:port] <path>...\n",
                argv[0]);
        return 50;
    }

    return xrdprep_run(argv, &args);
}
