/*
 * cms/perf_pgm.c — §2.11: external machine-load feed (stock cms.perf pgm).
 *
 * WHAT: Spawns the operator's load program once per CMS-client worker with
 * its stdout on a pipe; each stdout line "cpu net xeq mem pag" (five 0-100
 * integers, whitespace-separated) becomes the current machine-load override
 * consumed by the heartbeat (send.c calls brix_cms_perf_get before falling
 * back to the /proc meter).  A dead program is respawned with a 5s backoff;
 * an override older than 2x brix_cms_perf_interval goes stale and the /proc
 * meter takes back over — a wedged feed degrades, never lies.
 *
 * WHY: Stock cms.perf pgm parity — sites feed cmsd load figures from custom
 * monitors (batch-system pressure, GPU occupancy, SLA state) that /proc
 * cannot see.  The pgm form is NOT part of the excluded plugin architecture:
 * it is a config-driven child process, in scope per the audit.
 *
 * HOW: pipe2(O_NONBLOCK|O_CLOEXEC) + posix_spawn("/bin/sh -c <pgm>") with
 * stdout dup2'd onto the pipe.  The read end is wrapped in an
 * ngx_connection_t so the worker's event loop drives line parsing — no
 * threads, no blocking reads.  State is a per-worker static (one feed per
 * worker running the CMS client, which is worker 0 — cms_start.c).
 */

#include "cms_internal.h"
#include "perf_pgm.h"

#include <spawn.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>

extern char **environ;

/* One feed per worker (the CMS client runs on worker 0 only). */
typedef struct {
    ngx_cycle_t      *cycle;
    ngx_str_t         pgm;          /* NUL-terminated conf copy */
    ngx_msec_t        fresh_ms;     /* override validity: 2x perf_interval */
    ngx_connection_t *conn;         /* pipe read end in the event loop */
    pid_t             child;        /* spawned program; -1 = none */
    ngx_event_t       respawn;      /* backoff timer after child death */
    u_char            linebuf[256];
    size_t            line_pos;
    uint8_t           vals[5];      /* last parsed cpu net xeq mem pag */
    ngx_msec_t        updated;      /* ngx_current_msec of last good line */
    unsigned          have_vals:1;
} brix_cms_perf_t;

static brix_cms_perf_t  brix_cms_perf;

/*
 * perf_parse_line — parse "cpu net xeq mem pag" into vals[5].
 *
 * WHAT: Five whitespace-separated decimal integers, each clamped to 100.
 *       Returns 0 on success, -1 on a malformed line (ignored, feed keeps
 *       its previous values).
 * WHY:  A monitor emitting a partial/garbled line must not zero the node's
 *       advertised load — reject, don't guess.
 * HOW:  Manual cursor walk (no sscanf — bounded, locale-free).
 */
static int
perf_parse_line(const u_char *line, size_t len, uint8_t out5[5])
{
    size_t      cursor = 0;
    ngx_uint_t  field, value;

    for (field = 0; field < 5; field++) {
        while (cursor < len && (line[cursor] == ' ' || line[cursor] == '\t')) {
            cursor++;
        }
        if (cursor >= len || line[cursor] < '0' || line[cursor] > '9') {
            return -1;
        }
        value = 0;
        while (cursor < len && line[cursor] >= '0' && line[cursor] <= '9') {
            value = value * 10 + (ngx_uint_t) (line[cursor] - '0');
            if (value > 1000) {
                return -1;
            }
            cursor++;
        }
        out5[field] = (uint8_t) (value > 100 ? 100 : value);
    }

    while (cursor < len && (line[cursor] == ' ' || line[cursor] == '\t')) {
        cursor++;
    }
    return (cursor == len) ? 0 : -1;   /* trailing junk = malformed */
}

static void perf_spawn(brix_cms_perf_t *pf);

/* perf_teardown — close the pipe connection and reap the child, then arm the
 * respawn backoff.  Idempotent. */
static void
perf_teardown(brix_cms_perf_t *pf)
{
    if (pf->conn != NULL) {
        ngx_close_connection(pf->conn);
        pf->conn = NULL;
    }
    if (pf->child > 0) {
        (void) kill(pf->child, SIGTERM);
        (void) waitpid(pf->child, NULL, WNOHANG);
        pf->child = -1;
    }
    if (!ngx_exiting && !pf->respawn.timer_set) {
        ngx_add_timer(&pf->respawn, 5000);
    }
}

/*
 * perf_read_handler — drain stdout lines from the feed program.
 *
 * WHAT: Accumulates bytes into linebuf, parsing each complete line; a good
 *       line refreshes vals/updated.  EOF or a read error tears down and
 *       arms the respawn backoff.
 * WHY:  Event-driven so a chatty or silent monitor costs the worker nothing.
 * HOW:  Nonblocking read loop; over-long lines are discarded to the next
 *       newline (reject, don't truncate-and-parse).
 */
static void
perf_read_handler(ngx_event_t *ev)
{
    ngx_connection_t *c = ev->data;
    brix_cms_perf_t  *pf = c->data;
    u_char             chunk[256];
    ssize_t            got;
    ssize_t            i;

    for ( ;; ) {
        got = read(c->fd, chunk, sizeof(chunk));
        if (got == 0) {
            ngx_log_error(NGX_LOG_WARN, pf->cycle->log, 0,
                "brix: cms perf pgm exited (EOF) — respawning in 5s");
            perf_teardown(pf);
            return;
        }
        if (got < 0) {
            if (ngx_errno == NGX_EAGAIN) {
                return;
            }
            ngx_log_error(NGX_LOG_WARN, pf->cycle->log, ngx_errno,
                "brix: cms perf pgm read failed — respawning in 5s");
            perf_teardown(pf);
            return;
        }

        for (i = 0; i < got; i++) {
            if (chunk[i] == '\n') {
                uint8_t v[5];

                if (pf->line_pos < sizeof(pf->linebuf)
                    && perf_parse_line(pf->linebuf, pf->line_pos, v) == 0)
                {
                    ngx_memcpy(pf->vals, v, sizeof(pf->vals));
                    pf->updated = ngx_current_msec;
                    pf->have_vals = 1;
                } else if (pf->line_pos > 0) {
                    ngx_log_error(NGX_LOG_INFO, pf->cycle->log, 0,
                        "brix: cms perf pgm: malformed line ignored");
                }
                pf->line_pos = 0;
                continue;
            }
            if (pf->line_pos < sizeof(pf->linebuf)) {
                pf->linebuf[pf->line_pos] = chunk[i];
            }
            pf->line_pos++;   /* past the cap = line poisoned, drops above */
        }
    }
}

/*
 * perf_spawn — start the feed program with stdout on a fresh pipe.
 *
 * WHAT: pipe2 + posix_spawn("/bin/sh", "-c", pgm); wraps the read end in an
 *       ngx_connection_t with perf_read_handler.  On any failure arms the
 *       respawn backoff (the feed is an enhancement — its absence degrades
 *       to the /proc meter, never blocks the heartbeat).
 * WHY:  posix_spawn (not fork+exec) keeps the ASan/threads story simple and
 *       is the pattern the tree already uses for external programs.
 * HOW:  Child gets the pipe write end as fd 1; both pipe ends are CLOEXEC in
 *       the parent so respawns cannot leak fds into siblings.
 */
static void
perf_spawn(brix_cms_perf_t *pf)
{
    int                          fds[2];
    posix_spawn_file_actions_t   fa;
    char                        *argv[4];
    ngx_connection_t            *c;
    pid_t                        pid;
    int                          rc;

    if (pipe2(fds, O_CLOEXEC) != 0) {
        ngx_log_error(NGX_LOG_ERR, pf->cycle->log, ngx_errno,
                      "brix: cms perf pgm: pipe2 failed");
        perf_teardown(pf);
        return;
    }

    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, fds[1], 1);

    argv[0] = "/bin/sh";
    argv[1] = "-c";
    argv[2] = (char *) pf->pgm.data;
    argv[3] = NULL;

    rc = posix_spawn(&pid, "/bin/sh", &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(fds[1]);

    if (rc != 0) {
        ngx_log_error(NGX_LOG_ERR, pf->cycle->log, rc,
                      "brix: cms perf pgm: spawn of \"%V\" failed",
                      &pf->pgm);
        close(fds[0]);
        perf_teardown(pf);
        return;
    }
    pf->child = pid;

    if (fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0) {
        ngx_log_error(NGX_LOG_ERR, pf->cycle->log, ngx_errno,
                      "brix: cms perf pgm: O_NONBLOCK failed");
        close(fds[0]);
        perf_teardown(pf);
        return;
    }

    c = ngx_get_connection(fds[0], pf->cycle->log);
    if (c == NULL) {
        close(fds[0]);
        perf_teardown(pf);
        return;
    }
    c->data = pf;
    c->read->handler = perf_read_handler;
    c->write->handler = NULL;
    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        perf_teardown(pf);
        return;
    }
    pf->conn = c;
    pf->line_pos = 0;

    ngx_log_error(NGX_LOG_NOTICE, pf->cycle->log, 0,
                  "brix: cms perf pgm started: \"%V\" (pid %P)",
                  &pf->pgm, pid);
}

/* perf_respawn_timer — backoff expiry: try the spawn again. */
static void
perf_respawn_timer(ngx_event_t *ev)
{
    perf_spawn(ev->data);
}

void
brix_cms_perf_start(ngx_cycle_t *cycle, ngx_stream_brix_srv_conf_t *conf)
{
    brix_cms_perf_t *pf = &brix_cms_perf;
    u_char           *pgm_z;

    if (conf->cms.perf_pgm.len == 0 || pf->cycle != NULL) {
        return;   /* feature off, or already started on this worker */
    }

    /* NUL-terminated copy — posix_spawn argv needs a C string. */
    pgm_z = ngx_pnalloc(cycle->pool, conf->cms.perf_pgm.len + 1);
    if (pgm_z == NULL) {
        return;
    }
    ngx_memcpy(pgm_z, conf->cms.perf_pgm.data, conf->cms.perf_pgm.len);
    pgm_z[conf->cms.perf_pgm.len] = '\0';

    pf->cycle = cycle;
    pf->pgm.data = pgm_z;
    pf->pgm.len  = conf->cms.perf_pgm.len;
    pf->fresh_ms = conf->cms.perf_int * 2;
    pf->child = -1;
    pf->respawn.handler = perf_respawn_timer;
    pf->respawn.data = pf;
    pf->respawn.log = cycle->log;
    pf->respawn.cancelable = 1;

    perf_spawn(pf);
}

int
brix_cms_perf_get(uint8_t out5[5])
{
    brix_cms_perf_t *pf = &brix_cms_perf;

    if (!pf->have_vals
        || (ngx_msec_int_t) (ngx_current_msec - pf->updated)
           > (ngx_msec_int_t) pf->fresh_ms)
    {
        return 0;   /* never fed, or stale — caller uses the /proc meter */
    }
    ngx_memcpy(out5, pf->vals, 5);
    return 1;
}
