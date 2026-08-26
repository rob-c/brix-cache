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
#include "xrdcp_parse_internal.h"
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

/* ---- Parse a stock RATE[k|m|g] string into bytes/sec ----
 *
 * WHAT: strtoll + one optional case-insensitive binary suffix; returns the
 *       rate in bytes/sec, or -1 for garbage, non-positive values, trailing
 *       junk, or multiplication overflow.
 *
 * WHY: --xrate/--xrate-threshold accept the stock spellings ("512k", "10m");
 *      a hostile value must fail the parse, never wrap into a tiny or
 *      negative rate.
 *
 * HOW: errno/end checks, single-suffix switch, INT64_MAX/mult overflow guard.
 */
static int64_t
xrdcp_parse_rate(const char *s)
{
    char      *end;
    long long  v;
    int64_t    mult = 1;

    if (s == NULL || *s == '\0') {
        return -1;
    }
    errno = 0;
    v = strtoll(s, &end, 10);
    if (errno != 0 || end == s || v <= 0) {
        return -1;
    }
    if (*end != '\0') {
        switch (*end | 0x20) {
        case 'k': mult = 1024LL; break;
        case 'm': mult = 1024LL * 1024; break;
        case 'g': mult = 1024LL * 1024 * 1024; break;
        default:  return -1;
        }
        if (end[1] != '\0') {
            return -1;
        }
    }
    if (v > (long long) (INT64_MAX / mult)) {
        return -1;
    }
    return (int64_t) v * mult;
}


static int
xrdcp_parse_basic_option(xrdcp_cli_state *s, int argc, char **argv, size_t *i)
{
    brix_copy_opts *o = s->o->copt;
    /* Stock xrdcp long spellings (--force/--recursive/--nopbar) are accepted
     * as aliases so drop-in scripts keep working (parity-audit §7.13).  One
     * spelling → one flag cell; the table replaces a CCN-19 strcmp ladder. */
    const struct { const char *name; int *dst; } flags[] = {
        { "-f", &o->force },     { "--force", &o->force },
        { "-r", &o->recursive }, { "-R", &o->recursive },
        { "--recursive", &o->recursive },
        { "-P", &o->posc },      { "--posc", &o->posc },
        { "-s", &o->silent },    { "--silent", &o->silent },
        { "-v", &o->verbose },   { "-d", &o->verbose },
        { "--verbose", &o->verbose }, { "--debug", &o->verbose },
        { "-N", &s->o->no_progress }, { "--no-progress", &s->o->no_progress },
        { "--nopbar", &s->o->no_progress },
        { "--dry-run", &o->dry_run }, { "-n", &o->dry_run },
    };
    size_t k;

    (void) argc;
    for (k = 0; k < sizeof(flags) / sizeof(flags[0]); k++) {
        if (strcmp(argv[*i], flags[k].name) == 0) {
            *flags[k].dst = 1;
            return 1;
        }
    }
    return 0;
}


/* --xrate / --xrate-threshold: stock RATE[k|m|g] values (serial-pump pacing). */
static int
xrdcp_parse_rate_option(const char *a, xrdcp_opts_t *o, int argc,
    char **argv, size_t *i)
{

    if ((strcmp(a, "-X") == 0 || strcmp(a, "--xrate") == 0)
        && *i + 1 < (size_t) argc) {
        o->copt->xrate_bps = xrdcp_parse_rate(argv[++(*i)]);
        if (o->copt->xrate_bps <= 0) {
            fprintf(stderr, "xrdcp: invalid --xrate value '%s' "
                            "(bytes/sec, optional k/m/g suffix)\n", argv[*i]);
            return 50;
        }
        return 1;
    }
    if (strcmp(a, "--xrate-threshold") == 0 && *i + 1 < (size_t) argc) {
        o->copt->xrate_min_bps = xrdcp_parse_rate(argv[++(*i)]);
        if (o->copt->xrate_min_bps <= 0) {
            fprintf(stderr, "xrdcp: invalid --xrate-threshold value '%s' "
                            "(bytes/sec, optional k/m/g suffix)\n", argv[*i]);
            return 50;
        }
        return 1;
    }
    return 0;
}

/* --retry-policy / --retry / --no-retry / -j|--jobs: the retry posture. */
static int
xrdcp_parse_retry_option(const char *a, xrdcp_opts_t *o, int argc,
    char **argv, size_t *i)
{

    if (strcmp(a, "--retry-policy") == 0 && *i + 1 < (size_t) argc) {
        const char *policy = argv[++(*i)];

        /* §7.13 stock semantics: how a RETRY treats the partial destination.
         * "continue" = resume at the partial's size — exactly the --continue
         * write mode, so it simply arms that engine (each retry then picks up
         * where the failed attempt stopped); "force" = restart from scratch,
         * the pre-existing default. */
        if (strcmp(policy, "continue") == 0) {
            o->copt->cont = 1;
        } else if (strcmp(policy, "force") != 0) {
            fprintf(stderr, "xrdcp: --retry-policy expects 'force' or "
                            "'continue', got '%s'\n", policy);
            return 50;
        }
        return 1;
    }
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
xrdcp_parse_manifest_option(const char *a, xrdcp_opts_t *o, int argc,
    char **argv, size_t *i)
{
    int           rc;

    if (strcmp(a, "--from") == 0 && *i + 1 < (size_t) argc) {
        o->from = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--journal") == 0 && *i + 1 < (size_t) argc) {
        o->journal_path = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--resume") == 0) { o->resume = 1; return 1; }
    rc = xrdcp_parse_rate_option(a, o, argc, argv, i);
    if (rc) { return rc; }
    return xrdcp_parse_retry_option(a, o, argc, argv, i);
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
xrdcp_parse_auth_data_option(const char *a, xrdcp_opts_t *o, int argc,
    char **argv, size_t *i)
{

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


/*
 * xrdcp_parse_compat_option — stock-xrdcp spellings that name a condition we
 * already satisfy unconditionally.
 *
 * WHAT: Accepts -A/--allow-http and does nothing with it.
 * WHY:  In stock xrdcp that flag is the gate on the XrdClHttp plugin — the
 *       client refuses http/davs URLs until it is given. This client has no
 *       plugin layer and no such gate: every scheme its transport understands
 *       is available on every invocation, so the permission is already
 *       granted. Rejecting the flag would be the wrong answer to a right
 *       command line — every WebDAV recipe in the field carries it, including
 *       the ones in this repo's own docs and the interop suite — and silently
 *       accepting it is not a fudge but the exact translation of what it asks
 *       for. It grants a capability; it does not relax one, so it must NOT be
 *       read as touching TLS posture or host verification.
 * HOW:  Matched here rather than in xrdcp_parse_basic_option() so that ladder
 *       stays under the complexity cap, and so the compat spellings have one
 *       visible home if more are ever adopted.
 */
static int
xrdcp_parse_compat_option(int argc, char **argv, size_t *i)
{
    const char *a = argv[*i];

    (void) argc;
    if (strcmp(a, "-A") == 0 || strcmp(a, "--allow-http") == 0) {
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
    const char   *a = argv[*i];
    xrdcp_opts_t *o = s->o;

    if (pr == 2) { usage_fp(stdout, argv[0]); return 2; }
    if (pr) { *i = (size_t) oi; return 1; }
    rc = xrdcp_parse_basic_option(s, argc, argv, i);
    if (rc) { return rc; }
    rc = xrdcp_parse_compat_option(argc, argv, i);
    if (rc) { return rc; }
    rc = xrdcp_parse_manifest_option(a, o, argc, argv, i);
    if (rc) { return rc; }
    rc = xrdcp_parse_sync_filter_option(s, argc, argv, i);
    if (rc) { return rc; }
    rc = xrdcp_parse_auth_data_option(a, o, argc, argv, i);
    if (rc) { return rc; }
    rc = xrdcp_parse_transport_option(s->o->copt, argc, argv, i);
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

    return xrdcp_validate_and_finalize_args(o, l, argv[0]);
}
