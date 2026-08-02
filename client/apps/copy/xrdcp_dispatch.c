/*
 * xrdcp_dispatch.c — xrdcp transfer-mode dispatch (Phase-38 split).
 *
 * WHAT: route one finalized job to its transfer path — recursive web
 *       up/download, a single copy, or a journalled batch — plus the failed-
 *       source hint and per-mode progress wiring.
 * WHY:  split from xrdcp.c to hold each TU within the Phase-38 size budget;
 *       "execute the transfer(s)" is one cohesive concern with a single public
 *       entry point (dispatch_transfer), distinct from parsing and credential
 *       build. Byte-frozen: same routing, same exit codes.
 * HOW:  dispatch_transfer fills an xrdcp_transfer_ctx and selects the mode; the
 *       actual copy/relay/recursive primitives live in xrdcp_transfer.c /
 *       xrdcp_recursive.c and the shared URL/path helpers in xrdcp.c, all
 *       reached through xrdcp_internal.h. No goto; early-return throughout.
 */
#include "xrdcp_internal.h"
#include "core/version.h"
#include "core/progname.h"  /* brix_prog_base(): argv[0]-derived identity + footer */

typedef struct {
    brix_copy_opts          *opts;
    brix_opts               *conn;
    struct brix_cred_store  *cred_store;
    char                   **exp;
    size_t                   nexp;
    const char              *dst;
    const char              *from;
    const char              *journal_path;
    int                      retries;
    int                      jobs;
    int                      sync_mode;
    int                      force_progress;
    int                      no_progress;
} xrdcp_transfer_ctx;

/* Running batch outcome counters + the reusable status buffer for one
 * sequential batch pass. Bundled so the per-item worker stays under the
 * parameter gate; `batch_parallel` (extern) still takes the three counters by
 * address (&t.ok/&t.skip/&t.fail), so the wire-visible tally is unchanged. */
typedef struct {
    size_t      ok;
    size_t      skip;
    size_t      fail;
    brix_status st;
} xrdcp_tally_t;

static void
xrdcp_hint_failed_source(const char *src, const char *dst, const brix_status *st)
{
    brix_url    u_src;
    brix_status ps;

    brix_cred_hint_for_status_url(st, is_root_url(dst) || brix_is_web_url(dst),
                                  stderr, src);
    brix_status_clear(&ps);
    if (brix_url_parse(src, &u_src, &ps) == 0) {
        brix_hint_url_double_slash(st, &u_src);
    }
}


static int
xrdcp_dispatch_recursive_web_download(const xrdcp_transfer_ctx *ctx)
{
    brix_status st;
    size_t      i;
    size_t      bad = 0;

    brix_status_clear(&st);
    for (i = 0; i < ctx->nexp; i++) {
        if (brix_is_web_url(ctx->exp[i])) {
            if (recursive_web_download(ctx->exp[i], ctx->dst, ctx->opts,
                                       ctx->conn, ctx->retries) != 0) {
                bad++;
            }
        } else if (copy_one_with_retry(ctx->exp[i], ctx->dst, ctx->opts,
                                       ctx->conn, ctx->retries, &st) != 0) {
            bad++;
            fprintf(stderr, "xrdcp: %s: %s\n", ctx->exp[i], st.msg);
            xrdcp_hint_failed_source(ctx->exp[i], ctx->dst, &st);
        }
    }
    return (bad == 0) ? 0 : 1;
}


static int
xrdcp_dispatch_recursive_web_upload(const xrdcp_transfer_ctx *ctx)
{
    brix_status st;
    size_t      i;
    size_t      bad = 0;

    brix_status_clear(&st);
    if (ctx->opts->sync_delete) {
        fprintf(stderr, "xrdcp: --delete is not supported for web "
                        "destinations (ignored)\n");
    }
    for (i = 0; i < ctx->nexp; i++) {
        if (is_local_dir(ctx->exp[i])) {
            if (recursive_web_upload(ctx->exp[i], ctx->dst, ctx->opts,
                                     ctx->conn, ctx->retries) != 0) {
                bad++;
            }
        } else if (copy_one_with_retry(ctx->exp[i], ctx->dst, ctx->opts,
                                       ctx->conn, ctx->retries, &st) != 0) {
            bad++;
            fprintf(stderr, "xrdcp: %s: %s\n", ctx->exp[i], st.msg);
        }
    }
    return (bad == 0) ? 0 : 1;
}


static int
xrdcp_try_recursive_web(const xrdcp_transfer_ctx *ctx, int *handled)
{
    size_t i;
    int    any_web = 0;
    int    has_dir = 0;

    *handled = 0;
    if (!ctx->opts->recursive) {
        return 0;
    }
    for (i = 0; i < ctx->nexp; i++) {
        if (brix_is_web_url(ctx->exp[i])) { any_web = 1; }
        if (is_local_dir(ctx->exp[i])) { has_dir = 1; }
    }
    if (any_web) {
        *handled = 1;
        return xrdcp_dispatch_recursive_web_download(ctx);
    }
    if (brix_is_web_url(ctx->dst) && has_dir) {
        *handled = 1;
        return xrdcp_dispatch_recursive_web_upload(ctx);
    }
    return 0;
}


static void
xrdcp_enable_progress_if_needed(xrdcp_transfer_ctx *ctx, xrdcp_prog *ps,
                                char *label, size_t label_len)
{
    if (!((ctx->force_progress || (isatty(STDERR_FILENO) && !ctx->no_progress))
          && !ctx->opts->silent
          && !(ctx->exp[0][0] == '-' && ctx->exp[0][1] == '\0'))) {
        return;
    }

    path_basename(ctx->exp[0], label, label_len);
    ps->label = (label[0] != '\0') ? label : "transfer";
    ps->start_ns = brix_mono_ns();
    ps->last_ns = 0;
    ctx->opts->progress = xrdcp_progress;
    ctx->opts->progress_arg = ps;
}


static int
xrdcp_dispatch_single(xrdcp_transfer_ctx *ctx)
{
    brix_status st;
    char        label[XRDC_NAME_MAX];
    xrdcp_prog  ps;
    int         one;

    brix_status_clear(&st);
    xrdcp_enable_progress_if_needed(ctx, &ps, label, sizeof(label));
    one = transfer_one(ctx->exp[0], ctx->dst, ctx->opts, ctx->conn,
                       ctx->retries, ctx->sync_mode, &st);
    if (one == 1 && !ctx->opts->silent) {
        fprintf(stderr, "xrdcp: %s up-to-date, skipped\n", ctx->dst);
    } else if (one < 0 && !ctx->opts->silent) {
        fprintf(stderr, "xrdcp: %s\n", st.msg);
        xrdcp_hint_failed_source(ctx->exp[0], ctx->dst, &st);
    }
    return (one >= 0) ? 0 : brix_shellcode(&st);
}


static brix_journal *
xrdcp_open_batch_journal(const xrdcp_transfer_ctx *ctx, brix_status *st,
                         int *rc)
{
    *rc = 0;
    if (ctx->journal_path == NULL || ctx->opts->dry_run) {
        return NULL;
    }
    brix_status_clear(st);
    {
        brix_journal *jrn = brix_journal_open(ctx->journal_path, st);
        if (jrn == NULL) {
            fprintf(stderr, "xrdcp: %s\n", st->msg);
            *rc = 51;
        }
        return jrn;
    }
}


static void
xrdcp_batch_one(const xrdcp_transfer_ctx *ctx, brix_journal *jrn,
                xrdcp_tally_t *t, size_t idx)
{
    char dpath[XRDC_PATH_MAX];
    int  one;

    if (jrn != NULL && brix_journal_has(jrn, ctx->exp[idx])) {
        t->skip++;
        if (!ctx->opts->silent) {
            fprintf(stderr, "[%zu/%zu] %s (already transferred)\n",
                    t->ok + t->skip + t->fail, ctx->nexp, ctx->exp[idx]);
        }
        return;
    }
    one = batch_copy_one(ctx->exp[idx], ctx->dst, ctx->opts, ctx->conn,
                         ctx->retries, ctx->sync_mode, dpath, sizeof(dpath), &t->st);
    if (one == 0) {
        t->ok++;
        if (!ctx->opts->silent) {
            fprintf(stderr, "[%zu/%zu] %s -> %s\n",
                    t->ok + t->skip + t->fail, ctx->nexp, ctx->exp[idx], dpath);
        }
        if (jrn != NULL && !ctx->opts->dry_run) {
            (void) brix_journal_mark(jrn, ctx->exp[idx]);
        }
    } else if (one == 1) {
        t->skip++;
        if (!ctx->opts->silent) {
            fprintf(stderr, "[%zu/%zu] %s (up-to-date)\n",
                    t->ok + t->skip + t->fail, ctx->nexp, ctx->exp[idx]);
        }
    } else {
        t->fail++;
        fprintf(stderr, "xrdcp: %s: %s\n", ctx->exp[idx], t->st.msg);
        xrdcp_hint_failed_source(ctx->exp[idx], ctx->dst, &t->st);
    }
}


static int
xrdcp_dispatch_batch(xrdcp_transfer_ctx *ctx)
{
    xrdcp_tally_t t;
    brix_journal *jrn;
    size_t        i;
    int           rc;
    int           jobs = ctx->jobs;

    memset(&t, 0, sizeof(t));
    brix_status_clear(&t.st);
    if (dest_is_dir(ctx->dst, ctx->conn) != 1) {
        fprintf(stderr, "xrdcp: destination must be an existing directory for "
                        "multi-source copy: %s\n", ctx->dst);
        return 50;
    }
    jrn = xrdcp_open_batch_journal(ctx, &t.st, &rc);
    if (rc != 0) {
        return rc;
    }
    if (jobs > (int) ctx->nexp) { jobs = (int) ctx->nexp; }
    if (jobs > 1) {
        batch_parallel(ctx->exp, ctx->nexp, ctx->dst, ctx->opts, ctx->conn,
                       ctx->retries, ctx->sync_mode, jobs, jrn,
                       &t.ok, &t.skip, &t.fail);
    } else {
        for (i = 0; i < ctx->nexp; i++) {
            xrdcp_batch_one(ctx, jrn, &t, i);
        }
    }
    if (!ctx->opts->silent) {
        fprintf(stderr, "xrdcp: %zu copied, %zu skipped, %zu failed\n",
                t.ok, t.skip, t.fail);
    }
    return (t.fail == 0) ? 0 : 1;
}


/*
 * WHAT: Dispatch transfer based on mode (web recursive, single, or batch).
 *
 * WHY:  Main() had CCN 187 with complex mode routing. Extracting the dispatch
 *       logic (web recursive download/upload, single transfer with progress,
 *       batch sequential/parallel, journal lifecycle) reduces complexity.
 *
 * HOW:  Determine transfer mode from source types and flags. Route to:
 *       - Web recursive download/upload (davs/http collections)
 *       - Single transfer with progress bar (nexp==1)
 *       - Batch transfer with journal support (nexp>1)
 *       Returns 0 on success, 1 on partial failure, 50 on usage error, 51 on OOM.
 */
int
dispatch_transfer(xrdcp_opts_t *o, xrdcp_lists_t *l)
{
    xrdcp_transfer_ctx ctx;
    int                handled;
    int                rc;

    ctx.opts = o->copt;
    ctx.conn = o->conn;
    ctx.cred_store = o->cred_store;
    ctx.exp = l->exp.items;
    ctx.nexp = l->exp.n;
    ctx.dst = o->dst;
    ctx.from = o->from;
    ctx.journal_path = o->journal_path;
    ctx.retries = o->retries;
    ctx.jobs = o->jobs;
    ctx.sync_mode = o->sync_mode;
    ctx.force_progress = o->force_progress;
    ctx.no_progress = o->no_progress;

    rc = xrdcp_try_recursive_web(&ctx, &handled);
    if (handled) {
        return rc;
    }
    if (l->exp.n == 1 && o->from == NULL) {
        return xrdcp_dispatch_single(&ctx);
    }

    return xrdcp_dispatch_batch(&ctx);
}
