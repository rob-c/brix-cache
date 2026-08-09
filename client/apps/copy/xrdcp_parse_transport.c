/*
 * xrdcp_parse_transport.c — xrdcp's transport-posture options (Phase-38 split).
 *
 * WHAT: the `--zip`/`--parallel`/`--no-metalink`/`--io-uring-direct` valueless
 *       flag table plus the three value-taking options that shape how bytes
 *       move: -S/--streams, --sources, and --io-uring.
 * WHY:  split from xrdcp_parse.c on the 600-line file gate. The family is one
 *       concept — nothing here touches credentials, manifests or filters — and
 *       it is the one option group expressed as data (coding-standards §8.6),
 *       so it carries its own descriptor table and its own doc surface.
 * HOW:  xrdcp_parse_transport_option() is the fan-out entry, reached from
 *       xrdcp_parse_option() in the sibling TU. It takes the brix_copy_opts
 *       target directly rather than the CLI scratch state: every option here
 *       writes only to copt, so the narrower parameter keeps the split contract
 *       (xrdcp_parse_internal.h) free of the parser's private state struct.
 *       Byte-frozen: same spellings, same order, same exit codes.
 */
#include "xrdcp_internal.h"
#include "xrdcp_parse_internal.h"

#include <stddef.h>   /* offsetof(): the xrdcp_transport_flags descriptor table */


/*
 * WHAT: One valueless transport spelling — an exact argv match that assigns a
 *       constant to one `int` field of brix_copy_opts.
 * WHY:  These flags differ only in name, field and value, so express the family
 *       as data rather than a branch ladder (coding-standards §8.6). A new
 *       spelling is a row; the matcher below never changes.
 * HOW:  `field` is an offsetof into brix_copy_opts, applied by
 *       xrdcp_set_transport_flag.
 */
typedef struct {
    const char *spelling;
    size_t      field;
    int         value;
} xrdcp_transport_flag_t;

/* --io-uring-direct's three spellings sit here so they are matched before the
 * --io-uring ones below; the shorter prefix must not swallow them. */
static const xrdcp_transport_flag_t  xrdcp_transport_flags[] = {
    /* --zip / --zip-append: store the local source as a ZIP member. */
    { "--zip",                 offsetof(brix_copy_opts, zip),             1 },
    { "--zip-append",          offsetof(brix_copy_opts, zip_append),      1 },
    /* --parallel: TRUE concurrent striped download (one thread per bound
     * stream, disjoint pwrite ranges).  Opt-in — fail-closed, no single-link
     * resilient ride-out; the serial resilient fan-out stays the default. */
    { "--parallel",            offsetof(brix_copy_opts, parallel),        1 },
    /* --no-metalink: copy .meta4/.metalink sources as plain files instead of
     * resolving them as virtual redirectors (phase-100). */
    { "--no-metalink",         offsetof(brix_copy_opts, metalink_off),    1 },
    { "--io-uring-direct",     offsetof(brix_copy_opts, io_uring_direct), 1 },
    { "--io-uring-direct=on",  offsetof(brix_copy_opts, io_uring_direct), 1 },
    { "--io-uring-direct=off", offsetof(brix_copy_opts, io_uring_direct), 0 },
};


/* ---- Apply a valueless transport flag ----
 *
 * WHAT: Assigns the table row whose spelling equals `a`, returning 1 when one
 *       matched and 0 when the argument is not a valueless transport flag.
 *
 * WHY:  Keeps the family's growth out of the parser's control flow — the
 *       ladder this replaces was the bulk of the caller's branch count.
 *
 * HOW:  1. Walk the table comparing spellings exactly.
 *       2. On a hit, write the row's value through its offsetof and report the
 *          match; otherwise report no match.
 */
static int
xrdcp_set_transport_flag(brix_copy_opts *o, const char *a)
{
    size_t  n;

    for (n = 0; n < sizeof(xrdcp_transport_flags)
                    / sizeof(xrdcp_transport_flags[0]); n++) {
        if (strcmp(a, xrdcp_transport_flags[n].spelling) == 0) {
            *(int *) ((char *) o + xrdcp_transport_flags[n].field) =
                xrdcp_transport_flags[n].value;
            return 1;
        }
    }
    return 0;
}


/* ---- Parse --sources N ----
 *
 * WHAT: Consumes `--sources N` (phase-100 extreme copy), returning 1 on
 *       success, 50 on a value outside 1..16 (usage printed), and 0 when the
 *       argument is not --sources or its value is missing.
 *
 * WHY:  Block-stealing download from up to N replicas (metalink mirrors /
 *       locate discovery); 1 = plain single source, and the engine caps at 16
 *       distinct connections, so a count outside that range is a CLI error
 *       rather than something to silently clamp.
 *
 * HOW:  1. Reject anything that is not --sources with a following value.
 *       2. atoi the value and bound it to 1..16.
 *       3. Store it and report the match.
 */
static int
xrdcp_parse_sources_opt(brix_copy_opts *o, int argc, char **argv, size_t *i)
{
    int  n;

    if (strcmp(argv[*i], "--sources") != 0 || *i + 1 >= (size_t) argc) {
        return 0;
    }

    n = atoi(argv[++(*i)]);
    if (n < 1 || n > 16) {
        fprintf(stderr, "xrdcp: --sources: expected a count in 1..16, "
                        "got '%s'\n", argv[*i]);
        usage(argv[0]);
        return 50;
    }

    o->sources = n;
    return 1;
}


/* ---- Parse the --io-uring mode, either spelling ----
 *
 * WHAT: Consumes `--io-uring=<mode>` or `--io-uring <mode>`, returning 1 on
 *       success, 50 on an unrecognised mode (usage printed), and 0 when the
 *       argument is neither spelling.
 *
 * WHY:  Both spellings validate the same way and must reject the same set, so
 *       one helper owns the mode vocabulary — a second copy would be a second
 *       source of truth for what "auto" means.
 *
 * HOW:  1. Take the mode text from after the '=' or from the next argv slot.
 *       2. Map it with brix_cli_parse_io_uring; a negative result is a clean
 *          CLI error, not a silent fallback.
 *       3. Store the mode and report the match.
 */
static int
xrdcp_parse_io_uring_opt(brix_copy_opts *o, int argc, char **argv, size_t *i)
{
    const char  *a = argv[*i];
    const char  *mode;
    int          v;

    if (strncmp(a, "--io-uring=", 11) == 0) {
        mode = a + 11;

    } else if (strcmp(a, "--io-uring") == 0 && *i + 1 < (size_t) argc) {
        mode = argv[++(*i)];

    } else {
        return 0;
    }

    v = brix_cli_parse_io_uring(mode);
    if (v < 0) {
        fprintf(stderr, "xrdcp: --io-uring: invalid mode '%s' (use on|off|auto)\n",
                mode);
        usage(argv[0]);
        return 50;
    }

    o->io_uring = v;
    return 1;
}


int
xrdcp_parse_transport_option(brix_copy_opts *o, int argc, char **argv, size_t *i)
{
    const char  *a = argv[*i];
    int          rc;

    if (xrdcp_set_transport_flag(o, a)) {
        return 1;
    }

    if ((strcmp(a, "-S") == 0 || strcmp(a, "--streams") == 0)
        && *i + 1 < (size_t) argc) {
        o->streams = atoi(argv[++(*i)]);
        return 1;
    }

    rc = xrdcp_parse_sources_opt(o, argc, argv, i);
    if (rc != 0) {
        return rc;
    }

    /* --max-stall / --no-retry are parsed by brix_opts_parse_arg into the shared
     * brix_opts (s->o->conn) — which runs first in xrdcp_parse_option — and are
     * folded into copt by finalize_resilience_posture().  Do NOT duplicate the
     * flag here: a second handler is unreachable dead code and a second source of
     * truth for the give-up window. */
    return xrdcp_parse_io_uring_opt(o, argc, argv, i);
}
