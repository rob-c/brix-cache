/*
 * xrdcp_parse.c — xrdcp command-line parse + validation pipeline (Phase-38 split).
 *
 * WHAT: turn argv into a finalized job — the option fan-out
 *       (basic/manifest/sync/auth/transport/remote), the flag-matrix validator,
 *       source-list assembly (positionals + --from manifest), and journal /
 *       resilience finalization.
 * WHY:  split from xrdcp.c to hold each TU within the Phase-38 size budget; CLI
 *       parsing is one cohesive concern with a single public entry point
 *       (parse_and_validate_args), distinct from credential build and transfer
 *       dispatch. Byte-frozen: same flags, same order, same exit codes.
 * HOW:  parse_and_validate_args builds an xrdcp_cli_state over the caller's
 *       xrdcp_opts_t/xrdcp_lists_t and walks argv once; the shared string-list,
 *       alias, URL/path and manifest helpers live in xrdcp.c and are reached
 *       through xrdcp_internal.h. No goto; early-return throughout.
 */
#include "xrdcp_internal.h"
#include "core/version.h"
#include "core/progname.h"  /* brix_prog_base(): argv[0]-derived identity + footer */

/*
 * WHAT: Per-CLI-parse scratch: the option target (`o`), list target (`l`), and
 *       a sticky out-of-memory flag the str_append callsites set.
 * WHY:  The option-parser fan-out (basic/manifest/sync/auth/transport/remote)
 *       all need the same two targets plus a shared OOM latch; a small state
 *       struct keeps each parser helper at three parameters.
 * HOW:  parse_and_validate_args builds it once and passes its address to every
 *       xrdcp_parse_* helper; `oom` is checked after the argv loop.
 */
typedef struct {
    xrdcp_opts_t  *o;
    xrdcp_lists_t *l;
    int            oom;
} xrdcp_cli_state;

/* ========================================================================
 * WHAT: Validate argument combinations and build source/destination lists
 * WHY:  Many flag combinations are invalid (--delete requires -r+--sync,
 *       --delete conflicts with --remove-source, --verify implies --cksum, etc.)
 * HOW:  Check constraints, derive implicit settings, build srcs list from pos
 *       and --from manifest, derive journal path from --resume+--from
 * PARAMS: All the parsed values from parse_and_validate_args
 * RETURNS: 0 on success, 50 on usage error, 51 on OOM
 * ======================================================================== */
static int
xrdcp_validate_flag_matrix(brix_copy_opts *opts, int sync_mode, int verify)
{
    /* --sync replaces destinations that differ, so the files it does copy must be
     * allowed to overwrite (skipped ones are left untouched by the size check). */
    if (sync_mode) {
        opts->force = 1;
    }
    opts->sync = sync_mode;   /* recursive walkers read o->sync (+ sync_cmp/algo) */
    
    /* --delete (mirror: make the destination match the source) and
     * --remove-source (move: delete each source once its transfer succeeds) are
     * contradictory.  Run together they destroy BOTH trees: on an upload the
     * per-file source unlink runs before the mirror-delete pass, which then sees
     * the now-missing local files and purges the freshly-uploaded remote copies.
     * Reject the pair before any bytes (or unlinks) move. */
    if (opts->sync_delete && opts->remove_source) {
        fprintf(stderr, "xrdcp: --delete and --remove-source are contradictory "
                        "(mirror vs move)\n");
        return 50;
    }
    
    /* --delete requires -r and --sync: without a recursive pass there is no
     * listing to diff against; without --sync the extra-deletion semantics are
     * ill-defined (we might delete a destination the caller wanted to keep). */
    if (opts->sync_delete && !(opts->recursive && sync_mode)) {
        fprintf(stderr, "xrdcp: --delete requires -r and --sync\n");
        return 50;
    }
    
    /* --verify: post-transfer checksum against the server. An explicit --cksum wins. */
    if (verify && opts->cksum == NULL) {
        opts->cksum = "adler32:source";
    }

    return 0;
}


static int
xrdcp_collect_sources(const xrdcp_strlist *pos, const char *from,
                      xrdcp_strlist *srcs)
{
    size_t i;
    int    oom = 0;

    for (i = 0; i + 1 < pos->n; i++) {
        if (str_append(&srcs->items, &srcs->n, &srcs->cap, pos->items[i]) != 0) {
            oom = 1;
        }
    }
    if (from != NULL
        && read_manifest(from, &srcs->items, &srcs->n, &srcs->cap) != 0) {
        return 51;
    }
    if (oom) {
        fprintf(stderr, "xrdcp: out of memory\n");
        return 51;
    }

    return 0;
}


static int
xrdcp_finalize_journal(xrdcp_opts_t *o)
{
    static char jbuf[XRDC_PATH_MAX];

    if (!o->resume || o->journal_path != NULL) {
        return 0;
    }
    if (o->from == NULL || strcmp(o->from, "-") == 0) {
        fprintf(stderr, "xrdcp: --resume needs --from <file> (not stdin) "
                        "or an explicit --journal <path>\n");
        return 50;
    }
    if ((size_t) snprintf(jbuf, sizeof(jbuf), "%s.journal", o->from)
            >= sizeof(jbuf)) {
        fprintf(stderr, "xrdcp: journal path too long\n");
        return 50;
    }
    o->journal_path = jbuf;
    return 0;
}


/*
 * WHAT: Fold the resilience posture (--max-stall / --no-retry / $XRDC_MAX_STALL_MS)
 *       from the shared brix_opts (o->conn) into the brix_copy_opts (o->copt).
 * WHY:  Those knobs are parsed/seeded into brix_opts by brix_opts_parse_arg and
 *       brix_opts_init, but the copy pump's give-up window is read from
 *       brix_copy_opts via copy_stall_ms().  Without this bridge the documented
 *       flag/env were silently no-ops for the transfer window — a hostile-network
 *       operator who set --max-stall to bound a slow-drip stall still got the 60 s
 *       default, so a tripped-deadline read would re-handshake for a full minute.
 * HOW:  no_retry (explicit fail-fast) dominates; otherwise a positive window is
 *       copied across.  conn is the sole parse target, so this is the one place
 *       the posture is mirrored — copt is never written by a flag handler directly.
 */
static void
finalize_resilience_posture(xrdcp_opts_t *o)
{
    if (o->conn->no_retry) {
        o->copt->no_retry = 1;
    } else if (o->conn->max_stall_ms > 0) {
        o->copt->max_stall_ms = o->conn->max_stall_ms;
    }
}


static int
validate_and_finalize_args(xrdcp_opts_t *o, xrdcp_lists_t *l, const char *prog)
{
    static char dstbuf[XRDC_PATH_MAX];
    int rc;

    finalize_resilience_posture(o);

    rc = xrdcp_validate_flag_matrix(o->copt, o->sync_mode, o->verify);
    if (rc != 0) {
        return rc;
    }

    /* Need a destination (the last positional) and at least one source. */
    if (l->pos.n < 1) {
        usage(prog);
        return 50;
    }
    brix_alias_resolve(l->pos.items[l->pos.n - 1], dstbuf, sizeof(dstbuf)); /* ~/.xrdrc */
    o->dst = dstbuf;

    rc = xrdcp_collect_sources(&l->pos, o->from, &l->srcs);
    if (rc != 0) {
        return rc;
    }

    /* --resume shorthand: derive journal path from the manifest path.  Must come
     * before nsrc==0 so the specific error fires even when there are no sources. */
    rc = xrdcp_finalize_journal(o);
    if (rc != 0) {
        return rc;
    }
    if (l->srcs.n == 0) {
        fprintf(stderr, "xrdcp: no source given\n");
        usage(prog);
        return 50;
    }

    return 0;
}


static int
xrdcp_parse_basic_option(xrdcp_cli_state *s, int argc, char **argv, size_t *i)
{
    const char     *a = argv[*i];
    brix_copy_opts *o = s->o->copt;

    (void) argc;
    if (strcmp(a, "-f") == 0) { o->force = 1; return 1; }
    if (strcmp(a, "-r") == 0 || strcmp(a, "-R") == 0) {
        o->recursive = 1;
        return 1;
    }
    if (strcmp(a, "-P") == 0 || strcmp(a, "--posc") == 0) {
        o->posc = 1;
        return 1;
    }
    if (strcmp(a, "-s") == 0) { o->silent = 1; return 1; }
    if (strcmp(a, "-v") == 0 || strcmp(a, "-d") == 0
        || strcmp(a, "--verbose") == 0 || strcmp(a, "--debug") == 0) {
        o->verbose = 1;
        return 1;
    }
    if (strcmp(a, "-N") == 0 || strcmp(a, "--no-progress") == 0) {
        s->o->no_progress = 1;
        return 1;
    }
    if (strcmp(a, "--dry-run") == 0 || strcmp(a, "-n") == 0) {
        o->dry_run = 1;
        return 1;
    }
    return 0;
}


static int
xrdcp_parse_manifest_option(xrdcp_cli_state *s, int argc, char **argv, size_t *i)
{
    const char   *a = argv[*i];
    xrdcp_opts_t *o = s->o;

    if (strcmp(a, "--from") == 0 && *i + 1 < (size_t) argc) {
        o->from = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--journal") == 0 && *i + 1 < (size_t) argc) {
        o->journal_path = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--resume") == 0) { o->resume = 1; return 1; }
    if (strcmp(a, "--retry") == 0 && *i + 1 < (size_t) argc) {
        o->retries = atoi(argv[++(*i)]);
        if (o->retries <= 0) {
            o->retries = 0;
            o->copt->no_retry = 1;
        }
        return 1;
    }
    if (strcmp(a, "--no-retry") == 0) { o->copt->no_retry = 1; return 1; }
    if ((strcmp(a, "-j") == 0 || strcmp(a, "--jobs") == 0)
        && *i + 1 < (size_t) argc) {
        o->jobs = atoi(argv[++(*i)]);
        return 1;
    }
    return 0;
}


static int
xrdcp_parse_sync_check(brix_copy_opts *opts, const char *mode, const char *prog)
{
    if (strcmp(mode, "size") == 0) {
        opts->sync_cmp = XRDC_SYNC_SIZE;
        return 1;
    }
    if (strcmp(mode, "mtime") == 0) {
        opts->sync_cmp = XRDC_SYNC_MTIME;
        return 1;
    }
    if (strncmp(mode, "cksum", 5) == 0
        && (mode[5] == '\0' || mode[5] == ':')) {
        opts->sync_cmp = XRDC_SYNC_CKSUM;
        opts->sync_cksum_algo = (mode[5] == ':' && mode[6] != '\0')
                                ? mode + 6 : "adler32";
        return 1;
    }
    fprintf(stderr, "xrdcp: --sync-check needs size|mtime|cksum[:algo]\n");
    usage(prog);
    return 50;
}


static int
xrdcp_parse_pattern_option(xrdcp_cli_state *s, int argc, char **argv, size_t *i)
{
    const char *a = argv[*i];

    if (strcmp(a, "--exclude") == 0 && *i + 1 < (size_t) argc) {
        if (str_append(&s->l->excl.items, &s->l->excl.n, &s->l->excl.cap,
                       argv[++(*i)]) != 0) { s->oom = 1; }
        return 1;
    }
    if (strcmp(a, "--include") == 0 && *i + 1 < (size_t) argc) {
        if (str_append(&s->l->incl.items, &s->l->incl.n, &s->l->incl.cap,
                       argv[++(*i)]) != 0) { s->oom = 1; }
        return 1;
    }
    return 0;
}


static int
xrdcp_parse_sync_filter_option(xrdcp_cli_state *s, int argc, char **argv, size_t *i)
{
    const char *a = argv[*i];

    if (strcmp(a, "--sync") == 0) { s->o->sync_mode = 1; return 1; }
    if (strcmp(a, "--sync-check") == 0 && *i + 1 < (size_t) argc) {
        int rc = xrdcp_parse_sync_check(s->o->copt, argv[++(*i)], argv[0]);
        s->o->sync_mode = 1;
        return rc;
    }
    if (xrdcp_parse_pattern_option(s, argc, argv, i)) { return 1; }
    if (strcmp(a, "--delete") == 0) { s->o->copt->sync_delete = 1; return 1; }
    if (strcmp(a, "--remove-source") == 0) { s->o->copt->remove_source = 1; return 1; }
    return 0;
}


static int
xrdcp_parse_auth_data_option(xrdcp_cli_state *s, int argc, char **argv, size_t *i)
{
    const char   *a = argv[*i];
    xrdcp_opts_t *o = s->o;

    if (strcmp(a, "--progress") == 0) { o->force_progress = 1; return 1; }
    if (strcmp(a, "--verify") == 0) { o->verify = 1; return 1; }
    if (strcmp(a, "--auto-refresh") == 0) { o->auto_refresh = 1; return 1; }
    if (strcmp(a, "--oidc-account") == 0 && *i + 1 < (size_t) argc) {
        o->oidc_account = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--proxy") == 0 && *i + 1 < (size_t) argc) {
        o->proxy = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--pgrw") == 0) { o->copt->pgrw = 1; return 1; }
    if (strcmp(a, "--cksum") == 0 && *i + 1 < (size_t) argc) {
        o->copt->cksum = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--compress") == 0 && *i + 1 < (size_t) argc) {
        o->copt->compress = argv[++(*i)];
        return 1;
    }
    return 0;
}


static int
xrdcp_parse_transport_option(xrdcp_cli_state *s, int argc, char **argv, size_t *i)
{
    const char     *a = argv[*i];
    brix_copy_opts *o = s->o->copt;

    if (strcmp(a, "--zip") == 0) { o->zip = 1; return 1; }
    if (strcmp(a, "--zip-append") == 0) { o->zip_append = 1; return 1; }
    if ((strcmp(a, "-S") == 0 || strcmp(a, "--streams") == 0)
        && *i + 1 < (size_t) argc) {
        o->streams = atoi(argv[++(*i)]);
        return 1;
    }
    /* --max-stall / --no-retry are parsed by brix_opts_parse_arg into the shared
     * brix_opts (s->o->conn) — which runs first in xrdcp_parse_option — and are
     * folded into copt by finalize_resilience_posture().  Do NOT duplicate the
     * flag here: a second handler is unreachable dead code and a second source of
     * truth for the give-up window. */
    /* Match the longer --io-uring-direct spellings BEFORE the --io-uring ones so
     * the shorter prefix does not swallow them. */
    if (strcmp(a, "--io-uring-direct") == 0) {
        o->io_uring_direct = 1;
        return 1;
    }
    if (strcmp(a, "--io-uring-direct=on") == 0)  { o->io_uring_direct = 1; return 1; }
    if (strcmp(a, "--io-uring-direct=off") == 0) { o->io_uring_direct = 0; return 1; }
    if (strncmp(a, "--io-uring=", 11) == 0) {
        int v = brix_cli_parse_io_uring(a + 11);
        if (v < 0) {
            fprintf(stderr, "xrdcp: --io-uring: invalid mode '%s' (use on|off|auto)\n",
                    a + 11);
            usage(argv[0]);
            return 50;
        }
        o->io_uring = v;
        return 1;
    }
    if (strcmp(a, "--io-uring") == 0 && *i + 1 < (size_t) argc) {
        const char *m = argv[++(*i)];
        int v = brix_cli_parse_io_uring(m);
        if (v < 0) {
            fprintf(stderr, "xrdcp: --io-uring: invalid mode '%s' (use on|off|auto)\n",
                    m);
            usage(argv[0]);
            return 50;
        }
        o->io_uring = v;
        return 1;
    }
    return 0;
}


static int
xrdcp_parse_tpc_mode(brix_copy_opts *opts, const char *mode, const char *prog)
{
    if (strcmp(mode, "first") == 0) {
        opts->tpc_mode = XRDC_TPC_FIRST;
        return 1;
    }
    if (strcmp(mode, "only") == 0) {
        opts->tpc_mode = XRDC_TPC_ONLY;
        return 1;
    }
    if (strcmp(mode, "delegate") == 0) {
        opts->tpc_mode = XRDC_TPC_DELEGATE;
        return 1;
    }
    fprintf(stderr, "xrdcp: --tpc needs first|only|delegate\n");
    usage(prog);
    return 50;
}


static int
xrdcp_parse_remote_auth_option(xrdcp_cli_state *s, int argc, char **argv, size_t *i)
{
    const char     *a = argv[*i];
    brix_copy_opts *o = s->o->copt;

    if (strcmp(a, "--tpc") == 0 && *i + 1 < (size_t) argc) {
        return xrdcp_parse_tpc_mode(o, argv[++(*i)], argv[0]);
    }
    if (strcmp(a, "--tpc-token-mode") == 0 && *i + 1 < (size_t) argc) {
        o->tpc_token_mode = argv[++(*i)];
        return 1;
    }
    if ((strcmp(a, "-T") == 0 || strcmp(a, "--token") == 0)
        && *i + 1 < (size_t) argc) {
        o->bearer = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--s3-access") == 0 && *i + 1 < (size_t) argc) {
        o->s3_access = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--s3-secret") == 0 && *i + 1 < (size_t) argc) {
        o->s3_secret = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--s3-region") == 0 && *i + 1 < (size_t) argc) {
        o->s3_region = argv[++(*i)];
        return 1;
    }
    return 0;
}


static int
xrdcp_parse_option(xrdcp_cli_state *s, int argc, char **argv, size_t *i)
{
    int oi = (int) *i;
    int pr = brix_opts_parse_arg(s->o->conn, argc, argv, &oi);
    int rc;

    if (pr == 2) { usage_fp(stdout, argv[0]); return 2; }
    if (pr) { *i = (size_t) oi; return 1; }
    rc = xrdcp_parse_basic_option(s, argc, argv, i);
    if (rc) { return rc; }
    rc = xrdcp_parse_manifest_option(s, argc, argv, i);
    if (rc) { return rc; }
    rc = xrdcp_parse_sync_filter_option(s, argc, argv, i);
    if (rc) { return rc; }
    rc = xrdcp_parse_auth_data_option(s, argc, argv, i);
    if (rc) { return rc; }
    rc = xrdcp_parse_transport_option(s, argc, argv, i);
    if (rc) { return rc; }
    rc = xrdcp_parse_remote_auth_option(s, argc, argv, i);
    if (rc) { return rc; }
    if (strcmp(argv[*i], "-V") == 0) {
        printf("%s (BriX-Cache client) %s\n", brix_prog_base(argv[0]),
               brix_client_version());
        return 2;
    }
    if (strcmp(argv[*i], "-h") == 0) { usage(argv[0]); return 2; }

    fprintf(stderr, "xrdcp: unknown option '%s'\n", argv[*i]);
    usage(argv[0]);
    return 50;
}


/*
 * WHAT: Parse and validate command-line arguments.
 *
 * WHY:  The main() function is CCN 187 (527 lines). Extracting the argument
 *       parsing and validation logic reduces complexity and improves testability.
 *
 * HOW:  Parse all CLI flags into the provided structures, validate flag
 *       interactions (--sync implies --force, --delete requires -r + --sync,
 *       etc.), build positional/exclusion/inclusion lists, and derive defaults.
 *       Returns 0 on success, 50 on usage error, 51 on OOM.
 */
int
parse_and_validate_args(int argc, char **argv, xrdcp_opts_t *o, xrdcp_lists_t *l)
{
    size_t          i;
    xrdcp_cli_state state;

    memset(&state, 0, sizeof(state));
    state.o = o;
    state.l = l;

    /* Phase 44: XRDC_IO_URING env is the default (auto) for the local-disk
     * overlap ring; --io-uring overrides it below.  auto = 0 = memset default. */
    {
        const char *e = getenv("XRDC_IO_URING");
        if (e != NULL) {
            if (strcmp(e, "on") == 0)       { o->copt->io_uring = XRDC_IO_URING_ON; }
            else if (strcmp(e, "off") == 0) { o->copt->io_uring = XRDC_IO_URING_OFF; }
            else                            { o->copt->io_uring = XRDC_IO_URING_AUTO; }
        }
    }
    /* XRDC_IO_URING_DIRECT env is the default for the O_DIRECT tier (off unless
     * set); --io-uring-direct overrides it below. */
    {
        const char *e = getenv("XRDC_IO_URING_DIRECT");
        if (e != NULL) {
            o->copt->io_uring_direct =
                (strcmp(e, "on") == 0 || strcmp(e, "1") == 0) ? 1 : 0;
        }
    }

    for (i = 1; i < (size_t) argc; i++) {
        const char *a = argv[i];
        if (a[0] == '-' && a[1] != '\0' && strcmp(a, "-") != 0) {
            int parsed = xrdcp_parse_option(&state, argc, argv, &i);
            if (parsed == 2) { return XRDCP_PARSE_EXIT_OK; }
            if (parsed == 50) { return 50; }
        } else if (str_append(&l->pos.items, &l->pos.n, &l->pos.cap, a) != 0) {
            fprintf(stderr, "xrdcp: out of memory\n");
            return 51;
        }
    }
    if (state.oom) {
        fprintf(stderr, "xrdcp: out of memory\n");
        return 51;
    }

    o->copt->excludes   = (const char *const *) l->excl.items;
    o->copt->n_excludes = l->excl.n;
    o->copt->includes   = (const char *const *) l->incl.items;
    o->copt->n_includes = l->incl.n;

    return validate_and_finalize_args(o, l, argv[0]);
}


/*
 * WHAT: Build credential store after alias resolution, glob expansion, and pre-flight.
 *
 * WHY:  Credential store construction requires expanded sources to determine auth
 *       needs, plus pre-flight validation to warn about expired/read-only credentials.
 *
 * HOW:  Merge ~/.xrdrc alias credentials, expand globs, validate --remove-source
 *       compatibility with web sources, run credential pre-flight (auto-refresh +
 *       diagnose), then build the credential store. Returns store on success,
 *       NULL on error (with cleanup of passed-in arrays).
 */
