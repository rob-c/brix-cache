/*
 * xrdcp_parse_validate.c — flag-matrix validation + source-list / journal /
 * resilience finalization, split from xrdcp_parse.c (phase-103 size cap).
 *
 * WHAT: everything that runs AFTER the argv walk: the flag-matrix validator
 *       (decomposed from one CCN-19 block into delete / continue / rate
 *       sub-checks), source-list assembly (positionals + --from manifest) and
 *       journal / resilience finalization.
 * WHY:  one cohesive concern with a single entry point
 *       (xrdcp_validate_and_finalize_args) reached from parse_and_validate_args;
 *       byte-frozen semantics — same messages, same order, same exit codes.
 * HOW:  no goto; early-return throughout; shared helpers come from
 *       xrdcp_internal.h exactly as before the split.
 */
#include "xrdcp_internal.h"
#include "xrdcp_parse_internal.h"

/* --delete (mirror: make the destination match the source) and
 * --remove-source (move: delete each source once its transfer succeeds) are
 * contradictory.  Run together they destroy BOTH trees: on an upload the
 * per-file source unlink runs before the mirror-delete pass, which then sees
 * the now-missing local files and purges the freshly-uploaded remote copies.
 * Reject the pair before any bytes (or unlinks) move.  --delete also requires
 * -r and --sync: without a recursive pass there is no listing to diff
 * against; without --sync the extra-deletion semantics are ill-defined (we
 * might delete a destination the caller wanted to keep). */
static int
xrdcp_validate_delete_matrix(const brix_copy_opts *opts, int sync_mode)
{
    if (opts->sync_delete && opts->remove_source) {
        fprintf(stderr, "xrdcp: --delete and --remove-source are contradictory "
                        "(mirror vs move)\n");
        return 50;
    }
    if (opts->sync_delete && !(opts->recursive && sync_mode)) {
        fprintf(stderr, "xrdcp: --delete requires -r and --sync\n");
        return 50;
    }
    return 0;
}

/* --continue writes the destination in place and trusts the existing
 * partial — every mode that truncates, transforms, or re-frames the byte
 * stream contradicts it.  Reject the pairs before any bytes move. */
static int
xrdcp_validate_continue_matrix(const brix_copy_opts *opts)
{
    if (!opts->cont) {
        return 0;
    }
    if (opts->force) {
        fprintf(stderr, "xrdcp: --continue and --force are contradictory "
                        "(resume vs truncate)\n");
        return 50;
    }
    if (opts->pgrw || (opts->compress != NULL && opts->compress[0])) {
        fprintf(stderr, "xrdcp: --continue cannot combine with --pgrw or "
                        "--compress (byte-offset resume needs a plain "
                        "byte stream)\n");
        return 50;
    }
    if (opts->zip || opts->zip_append) {
        fprintf(stderr, "xrdcp: --continue cannot combine with --zip "
                        "modes\n");
        return 50;
    }
    return 0;
}

/* ========================================================================
 * WHAT: Validate argument combinations and derive implicit settings
 * WHY:  Many flag combinations are invalid (--delete requires -r+--sync,
 *       --delete conflicts with --remove-source, --verify implies --cksum, etc.)
 * HOW:  fold --sync into force/sync, then run the delete / continue matrices
 *       and the serial-only --xrate guard
 * RETURNS: 0 on success, 50 on usage error
 * ======================================================================== */
static int
xrdcp_validate_flag_matrix(brix_copy_opts *opts, int sync_mode, int verify)
{
    int rc;

    /* --sync replaces destinations that differ, so the files it does copy must be
     * allowed to overwrite (skipped ones are left untouched by the size check). */
    if (sync_mode) {
        opts->force = 1;
    }
    opts->sync = sync_mode;   /* recursive walkers read o->sync (+ sync_cmp/algo) */

    rc = xrdcp_validate_delete_matrix(opts, sync_mode);
    if (rc != 0) {
        return rc;
    }

    /* --verify: post-transfer checksum against the server. An explicit --cksum wins. */
    if (verify && opts->cksum == NULL) {
        opts->cksum = "adler32:source";
    }

    rc = xrdcp_validate_continue_matrix(opts);
    if (rc != 0) {
        return rc;
    }

    /* --xrate paces the serial pump; the striped/multi-source engines bypass
     * it entirely, so the combination would silently run unpaced. */
    if (opts->xrate_bps > 0 && (opts->parallel || opts->sources >= 2)) {
        fprintf(stderr, "xrdcp: --xrate applies to the serial path and cannot "
                        "combine with --parallel/--sources\n");
        return 50;
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

int
xrdcp_validate_and_finalize_args(xrdcp_opts_t *o, xrdcp_lists_t *l, const char *prog)
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

    /* --continue vs the journal family: two different resume systems; running
     * both would double-account progress.  One or the other. */
    if (o->copt->cont && (o->resume || o->journal_path != NULL)) {
        fprintf(stderr, "xrdcp: --continue and --journal/--resume are "
                        "different resume modes — pick one\n");
        return 50;
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
