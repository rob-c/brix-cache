/*
 * xfer_ledger.c — the unified durable-transfer audit ledger.
 *
 * WHAT: xrootd_xfer_ledger_record() appends ONE consistent audit line for every
 *       terminal transfer (commit or abort), across all four kinds (stage, tape,
 *       write-through, TPC). One schema, one sink.
 *
 * WHY:  The four paths each had their own audit surface and only one emitted an
 *       access-log line, so "what objects got published, by whom, by which path"
 *       meant reading four places. Metrics keep their existing per-subsystem
 *       names (no dashboard breakage — each caller still books its own); the
 *       ledger adds the single audit line that unifies the picture. See
 *       docs/superpowers/specs/2026-06-28-unified-durable-transfer-engine-design.md
 *       §6.
 *
 * HOW:  A process-global append-only fd, lazy-opened on first record. O_APPEND
 *       makes concurrent writes from multiple workers atomic for the sub-PIPE_BUF
 *       lines we emit, so no lock is needed. The sink is $XROOTD_XFER_AUDIT_LOG,
 *       else <prefix>/logs/xfer_audit.log. Wire-sourced fields (path, principal)
 *       are escaped with the shared sanitizer. Auditing is best-effort: a sink
 *       that cannot be opened is warned once and skipped — it never fails a
 *       transfer. Early-return, no goto.
 */

#include "xfer.h"

#include "fs/path/path.h"   /* xrootd_sanitize_log_string — shared, never reimpl */

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

const char *
xrootd_xfer_kind_str(xrootd_xfer_kind_t kind)
{
    switch (kind) {
    case XROOTD_XFER_STAGE: return "stage";
    case XROOTD_XFER_TAPE:  return "tape";
    case XROOTD_XFER_WT:    return "wt";
    case XROOTD_XFER_TPC:   return "tpc";
    default:                return "?";
    }
}

const char *
xrootd_xfer_result_str(xrootd_xfer_result_t result)
{
    switch (result) {
    case XROOTD_XFER_OK:         return "ok";
    case XROOTD_XFER_DEFERRED:   return "deferred";
    case XROOTD_XFER_DENIED:     return "denied";
    case XROOTD_XFER_SRC_ERR:    return "src_err";
    case XROOTD_XFER_DST_ERR:    return "dst_err";
    case XROOTD_XFER_COMMIT_ERR: return "commit_err";
    case XROOTD_XFER_AGENT_FAIL: return "agent_fail";
    default:                     return "?";
    }
}

/* ----------------------------- the sink ---------------------------------- */

static int       xfer_audit_fd = -1;     /* per-worker append fd, lazy-opened   */
static ngx_int_t xfer_audit_failed;      /* a prior open failed → stop trying   */

/* Resolve the audit-log path: $XROOTD_XFER_AUDIT_LOG, else <prefix>/logs/. */
static void
xfer_audit_resolve_path(char *out, size_t outsz)
{
    const char *env = getenv("XROOTD_XFER_AUDIT_LOG");

    if (env != NULL && env[0] != '\0') {
        ngx_cpystrn((u_char *) out, (u_char *) env, outsz);
        return;
    }
    if (ngx_cycle != NULL && ngx_cycle->prefix.len > 0) {
        ngx_snprintf((u_char *) out, outsz, "%V%s%Z", &ngx_cycle->prefix,
                     "logs/xfer_audit.log");
        return;
    }
    ngx_cpystrn((u_char *) out, (u_char *) "logs/xfer_audit.log", outsz);
}

/* Lazily open the append-only audit fd. -1 (and a one-shot warn) on failure. */
static int
xfer_audit_fd_get(ngx_log_t *log)
{
    char path[PATH_MAX];

    if (xfer_audit_fd >= 0) {
        return xfer_audit_fd;
    }
    if (xfer_audit_failed) {
        return -1;
    }

    xfer_audit_resolve_path(path, sizeof(path));
    xfer_audit_fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
    if (xfer_audit_fd < 0) {
        xfer_audit_failed = 1;
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "xfer: cannot open audit log \"%s\" — transfer auditing "
                      "disabled this worker", path);
        return -1;
    }
    return xfer_audit_fd;
}

/* --------------------------- the record ---------------------------------- */

void
xrootd_xfer_ledger_record(const xrootd_xfer_audit_t *ev)
{
    char       line[2048];
    char       timebuf[64];
    char       safe_path[1024];
    char       safe_principal[256];
    struct tm  tm;
    ngx_time_t *tp;
    int        fd;
    int        n;

    if (ev == NULL) {
        return;
    }

    fd = xfer_audit_fd_get(ev->log);
    if (fd < 0) {
        return;
    }

    tp = ngx_timeofday();
    ngx_libc_localtime(tp->sec, &tm);
    strftime(timebuf, sizeof(timebuf), "%d/%b/%Y:%H:%M:%S %z", &tm);

    xrootd_sanitize_log_string(ev->path ? ev->path : "-", safe_path,
                               sizeof(safe_path));
    xrootd_sanitize_log_string((ev->principal && ev->principal[0]) ? ev->principal
                                                                    : "-",
                               safe_principal, sizeof(safe_principal));

    n = snprintf(line, sizeof(line),
                 "%s kind=%s dir=%s result=%s bytes=%zu errno=%d "
                 "principal=%s path=\"%s\"\n",
                 timebuf, xrootd_xfer_kind_str(ev->kind),
                 ev->direction ? ev->direction : "-",
                 xrootd_xfer_result_str(ev->result), ev->bytes,
                 (ev->result == XROOTD_XFER_OK) ? 0 : ev->sys_errno,
                 safe_principal, safe_path);
    if (n <= 0) {
        return;
    }
    if ((size_t) n > sizeof(line)) {
        n = (int) sizeof(line);
    }

    /* O_APPEND: atomic for sub-PIPE_BUF lines, so safe across workers unlocked.
     * Best-effort — a short/failed write loses one audit line, never a transfer. */
    if (write(fd, line, (size_t) n) < 0) {
        /* nothing we can do for an audit line; do not disturb the transfer */
    }
}
