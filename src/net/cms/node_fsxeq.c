/*
 * node_fsxeq.c — 2.0 F17: run the operator program in place of a forwarded
 * namespace op.  See node_fsxeq.h for the contract.
 *
 * The three properties this file exists to hold, in the order they are checked:
 *
 *   1. CONFINEMENT.  The built-in POSIX leg cannot be escaped: every path goes
 *      through openat2 RESOLVE_BENEATH under the export rootfd, so a hostile
 *      manager's "/../etc/shadow" fails EXDEV inside the kernel.  An external
 *      program has no such floor — it is handed a path and trusted.  So the
 *      path is gated LEXICALLY here, with the same rule recv_prepare.c applies
 *      to a forwarded stage path, BEFORE the program exists: absolute, bounded,
 *      and free of "..".  This is the one security property the feature could
 *      quietly lose, and it is the reason the gate is in front of the fork
 *      rather than left to the operator's script.
 *
 *   2. THE WORKER SURVIVES A BAD PROGRAM.  The run is a thread-pool task, so a
 *      program that blocks for its whole deadline costs one thread-pool slot
 *      and one forwarded op; the event loop keeps answering everything else.
 *      brix_subprocess_run supplies the rest: the double-forked agent (nginx's
 *      SIGCHLD handler reaps a worker's direct children, so a plain fork loses
 *      the exit status — F4's lesson), the program's own session, closefrom(3)
 *      of every inherited descriptor, and the SIGKILL of its whole process
 *      group when brix_cms_fsxeq_timeout expires.
 *
 *   3. THE REPLY IS STILL CMSD'S.  Silent on success, kYR_error (kYR_EINVAL +
 *      text) on failure — byte-shape-identical to the built-in leg, so a stock
 *      manager cannot tell which leg answered.  The manager link may have gone
 *      away while the program ran, so the completion handler re-checks it.
 */

#include "cms_internal.h"
#include "recv_internal.h"
#include "node_ops.h"
#include "node_fsxeq.h"

#include "core/aio/aio.h"              /* brix_task_bind                     */
#include "core/compat/subprocess.h"    /* brix_subprocess_run                */
#include "fs/path/beneath.h"           /* brix_beneath_full_path             */

#include <errno.h>
#include <limits.h>
#include <stdio.h>

/* Captured program stdout kept for the operator-facing log line. */
#define FSXEQ_OUT_MAX   BRIX_CMS_FSXEQ_OUT_BUF

/*
 * One in-flight run.  Allocated with the task from its own pool, which the
 * completion handler destroys; the pool is the task's only owner, so a posted
 * run leaks nothing whatever the program does.
 *
 * conn/conn_number snapshot the manager link the request arrived on.  The ctx
 * itself is per-worker and outlives every run (it is freed only at worker
 * exit), but ctx->connection is re-dialled on every reconnect — answering a
 * streamid from a dead link on a fresh one would be a reply to a request the
 * new manager never made.
 */
typedef struct {
    ngx_pool_t          *pool;
    ngx_brix_cms_ctx_t  *ctx;
    ngx_connection_t    *conn;
    ngx_atomic_uint_t    conn_number;
    uint32_t             streamid;
    unsigned             timeout_ms;
    const char          *display;      /* the configured command (NUL-term.) */
    const char          *opname;
    char                *argv[BRIX_CMS_FSXEQ_ARGV_MAX];
    char                 numarg[32];   /* mode (octal) or trunc size          */
    char                 path[PATH_MAX];
    char                 path2[PATH_MAX];
    char                 out[FSXEQ_OUT_MAX];
    int                  rc;           /* brix_subprocess_run return          */
    int                  run_errno;
    int                  exit_code;
} fsxeq_task_t;

/* Slot index for a planned action, or -1 for an action cms.fsxeq never
 * covers (prepadd/prepdel are staging ops, not namespace ops). */
static ngx_int_t
fsxeq_slot(brix_cms_node_action_t action)
{
    switch (action) {
    case XRDCMS_NACT_CHMOD:  return BRIX_CMS_FSXEQ_CHMOD;
    case XRDCMS_NACT_MKDIR:  return BRIX_CMS_FSXEQ_MKDIR;
    case XRDCMS_NACT_MKPATH: return BRIX_CMS_FSXEQ_MKPATH;
    case XRDCMS_NACT_MV:     return BRIX_CMS_FSXEQ_MV;
    case XRDCMS_NACT_RM:     return BRIX_CMS_FSXEQ_RM;
    case XRDCMS_NACT_RMDIR:  return BRIX_CMS_FSXEQ_RMDIR;
    case XRDCMS_NACT_TRUNC:  return BRIX_CMS_FSXEQ_TRUNC;
    default:                 return -1;
    }
}

static const char *
fsxeq_opname(ngx_int_t slot)
{
    static const char *const  names[BRIX_CMS_FSXEQ_OPS] = {
        "chmod", "mkdir", "mkpath", "mv", "rm", "rmdir", "trunc"
    };

    return names[slot];
}

/*
 * The lexical confinement gate — see property 1 in the file header.  Identical
 * in rule to cms_prep_path_ok(): absolute, bounded, no ".." anywhere.  The
 * substring test also refuses a legitimate name containing "..", which is the
 * conservative direction and keeps the two forwarded-op gates one rule.
 */
static int
fsxeq_path_ok(const char *path)
{
    if (path == NULL || path[0] != '/' || ngx_strlen(path) >= PATH_MAX) {
        return 0;
    }
    return ngx_strstr(path, "..") == NULL;
}

/* Both paths a plan can carry, gated.  path2 is present only for mv. */
static int
fsxeq_plan_paths_ok(const brix_cms_node_plan_t *plan)
{
    if (!fsxeq_path_ok(plan->path)) {
        return 0;
    }
    return plan->path2 == NULL || fsxeq_path_ok(plan->path2);
}

/* Export-relative -> physical, the form stock hands its fsxeq program (the pfn,
 * not the lfn).  0 on success, -1 when the join would not fit. */
static int
fsxeq_physical(const char *root_canon, const char *rel, char *buf, size_t cap)
{
    return brix_beneath_full_path(root_canon, rel, buf, cap) < (int) cap
           ? 0 : -1;
}

/*
 * Append the op's own arguments after the configured command line, the way
 * XrdOucProg::Run() appends its arguments to the program's fixed prefix:
 *
 *   chmod|mkdir|mkpath  <mode octal>  <path>
 *   trunc               <size>        <path>
 *   mv                  <path>        <path2>
 *   rm|rmdir            <path>
 *
 * Returns the total argv token count, or 0 when a path did not fit.
 */
static ngx_uint_t
fsxeq_build_argv(fsxeq_task_t *t, const brix_cms_fsxeq_prog_t *prog,
    const brix_cms_node_plan_t *plan, const char *root_canon)
{
    ngx_uint_t  n = prog->argc;
    ngx_uint_t  i;

    for (i = 0; i < prog->argc; i++) {
        t->argv[i] = prog->argv[i];
    }
    if (fsxeq_physical(root_canon, plan->path, t->path, sizeof(t->path)) != 0) {
        return 0;
    }

    switch (plan->action) {

    case XRDCMS_NACT_MV:
        if (fsxeq_physical(root_canon, plan->path2, t->path2,
                           sizeof(t->path2)) != 0)
        {
            return 0;
        }
        t->argv[n++] = t->path;
        t->argv[n++] = t->path2;
        break;

    case XRDCMS_NACT_TRUNC:
        snprintf(t->numarg, sizeof(t->numarg), "%lld",
                 (long long) plan->size);
        t->argv[n++] = t->numarg;
        t->argv[n++] = t->path;
        break;

    case XRDCMS_NACT_RM:
    case XRDCMS_NACT_RMDIR:
        t->argv[n++] = t->path;
        break;

    default:            /* chmod, mkdir, mkpath — the mode-carrying ops */
        snprintf(t->numarg, sizeof(t->numarg), "%04o",
                 (unsigned) (plan->mode & BRIX_CMS_MODE_BITS_MASK));
        t->argv[n++] = t->numarg;
        t->argv[n++] = t->path;
        break;
    }

    t->argv[n] = NULL;
    return n;
}

/* The thread-pool half: one bounded run, no nginx call anywhere. */
static void
fsxeq_thread(void *data, ngx_log_t *log)
{
    fsxeq_task_t           *t = data;
    brix_subprocess_req_t   req;

    (void) log;

    t->out[0] = '\0';
    req.argv       = t->argv;
    req.out        = t->out;
    req.outsz      = sizeof(t->out);
    req.timeout_ms = t->timeout_ms;

    t->exit_code = -1;
    t->rc = brix_subprocess_run(&req, NULL, &t->exit_code);
    t->run_errno = errno;
}

/*
 * Answer the manager, if the link the request arrived on is still the live one.
 * A reconnect between post and completion retires the streamid with it.
 */
static void
fsxeq_reply_error(fsxeq_task_t *t, const char *text)
{
    ngx_brix_cms_ctx_t  *ctx = t->ctx;

    if (ctx->connection == NULL || ctx->connection != t->conn
        || ctx->connection->number != t->conn_number)
    {
        return;
    }
    (void) ngx_brix_cms_send_error(ctx, t->streamid, CMS_ERR_EINVAL, text);
}

/* The failure text, and the operator-facing log line that carries the program's
 * own first words.  Returns NULL when the run succeeded. */
static const char *
fsxeq_verdict(fsxeq_task_t *t, char *buf, size_t cap)
{
    if (t->rc != 0) {
        return t->run_errno == ETIMEDOUT
               ? "fsxeq program timed out" : "fsxeq program could not be run";
    }
    if (t->exit_code == 0) {
        return NULL;
    }
    ngx_snprintf((u_char *) buf, cap - 1, "fsxeq program exited %d%Z",
                 t->exit_code);
    return buf;
}

/* The event-loop half: log, reply, free.  Nothing may touch the task after the
 * pool goes. */
static void
fsxeq_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    fsxeq_task_t       *t = task->ctx;
    ngx_pool_t         *pool = t->pool;
    char                buf[64];
    const char         *why;

    (void) brix_rstrip(t->out);
    why = fsxeq_verdict(t, buf, sizeof(buf));

    if (why == NULL) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, t->ctx->cycle->log, 0,
            "brix: CMS node: fsxeq %s ok via \"%s\" (%s)",
            t->opname, t->display, t->out);
    } else {
        ngx_log_error(NGX_LOG_NOTICE, t->ctx->cycle->log, 0,
            "brix: CMS node: fsxeq %s path=%s via \"%s\" failed: %s%s%s",
            t->opname, t->path, t->display, why,
            t->out[0] ? "; said: " : "", t->out);
        fsxeq_reply_error(t, why);
    }

    ngx_destroy_pool(pool);
}

/* Everything the post needs, filled on the event loop before the thread runs. */
static void
fsxeq_task_init(fsxeq_task_t *t, ngx_pool_t *pool, ngx_brix_cms_ctx_t *ctx,
    uint32_t streamid, ngx_int_t slot)
{
    t->pool        = pool;
    t->ctx         = ctx;
    t->conn        = ctx->connection;
    t->conn_number = ctx->connection ? ctx->connection->number : 0;
    t->streamid    = streamid;
    t->timeout_ms  = (unsigned) ctx->conf->cms.fsxeq_timeout;
    t->display     = (const char *) ctx->conf->cms.fsxeq[slot]->display.data;
    t->opname      = fsxeq_opname(slot);
}

/* Build and post the run.  NGX_OK once the task owns the reply; NGX_DECLINED
 * when nothing could be posted and the caller must answer the refusal. */
static ngx_int_t
fsxeq_post(ngx_brix_cms_ctx_t *ctx, uint32_t streamid, ngx_int_t slot,
    const brix_cms_node_plan_t *plan)
{
    ngx_thread_pool_t  *tp = brix_shared_thread_pool(&ctx->conf->common);
    ngx_thread_task_t  *task;
    fsxeq_task_t       *t;
    ngx_pool_t         *pool;

    if (tp == NULL) {
        return NGX_DECLINED;
    }
    pool = ngx_create_pool(BRIX_CMS_MAX_CONNECTIONS, ctx->cycle->log);
    if (pool == NULL) {
        return NGX_DECLINED;
    }
    task = ngx_thread_task_alloc(pool, sizeof(fsxeq_task_t));
    if (task == NULL) {
        ngx_destroy_pool(pool);
        return NGX_DECLINED;
    }
    t = task->ctx;
    fsxeq_task_init(t, pool, ctx, streamid, slot);

    if (fsxeq_build_argv(t, ctx->conf->cms.fsxeq[slot], plan,
                         ctx->conf->common.root_canon) == 0)
    {
        ngx_destroy_pool(pool);
        return NGX_DECLINED;
    }

    brix_task_bind(task, fsxeq_thread, fsxeq_done);
    task->event.log = ctx->cycle->log;

    if (ngx_thread_task_post(tp, task) != NGX_OK) {
        ngx_destroy_pool(pool);
        return NGX_DECLINED;
    }
    return NGX_OK;
}

ngx_int_t
brix_cms_fsxeq_dispatch(ngx_brix_cms_ctx_t *ctx, u_char code,
    uint32_t streamid, const brix_cms_node_plan_t *plan, int *taken)
{
    ngx_int_t  slot = fsxeq_slot(plan->action);

    *taken = 0;
    if (slot < 0 || ctx->conf->cms.fsxeq[slot] == NULL) {
        return NGX_OK;
    }
    *taken = 1;

    if (!fsxeq_plan_paths_ok(plan)) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->cycle->log, 0,
            "brix: CMS node: forwarded op code=%ui refused before fsxeq: "
            "path denied", (ngx_uint_t) code);
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         "fsxeq path denied");
    }

    if (fsxeq_post(ctx, streamid, slot, plan) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ctx->cycle->log, 0,
            "brix: CMS node: fsxeq %s could not be posted (thread pool?)",
            fsxeq_opname(slot));
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         "fsxeq program not runnable");
    }
    return NGX_OK;
}
