/*
 * resilient.c — network resilience for the synchronous client tools.
 *
 * WHAT: gives the one-shot CLI tools the same recovery the xrootdfs FUSE driver
 *       has — reconnect + full re-auth + handle reopen + offset resume + bounded
 *       backoff — through two seams:
 *         - xrdc_with_resilience(): wrap any stateless op (stat/ls/query/mkdir/…)
 *           so a transport sever triggers reconnect + re-issue, gated by an
 *           idempotency class.
 *         - xrdc_rfile: a synchronous file handle that reopens and resumes a read
 *           or write at the same offset after a sever, with an adaptive read size.
 *
 * WHY:  a single xrdc_connect() + one-shot xrdc_send/xrdc_recv fails the whole
 *       operation on the first dropped connection (rc=51). These helpers ride the
 *       loss out, matching the FUSE driver, while staying off (single attempt)
 *       when the window is 0 so --no-retry preserves the legacy fail-fast path.
 *
 * HOW:  the read/write loops are lifted from the proven xrdcp pump (copy.c:
 *       pump_src_remote / pump_remote_reopen) and the async mfile_pwrite
 *       (aio_mgr.c); reconnect/re-auth is xrdc_reconnect (conn.c) to the home
 *       endpoint; retryability and backoff reuse xrdc_status_retryable /
 *       xrdc_backoff_sleep_fast. Raw ops and copy.c are left untouched, so there
 *       is no nested-retry surprise.
 */
#include "xrdc.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/* Adaptive read size: start large for full throughput on a clean link, halve on
 * each sever down to the floor so a lossy link converges on a request small
 * enough to get through (mirrors copy.c's XRDC_RESILIENT_FLOOR). */
#define XRDC_RFILE_CHUNK0 (4u * 1024u * 1024u)
#define XRDC_RFILE_FLOOR  (256u * 1024u)

/* Resolve the resilience window (ms) from options: 0 if disabled, else the
 * explicit value, else $XRDC_MAX_STALL_MS, else the built-in default. The env
 * fallback keeps the knob uniform for tools that don't route options through
 * cli_opts (e.g. the hand-rolled xrdfs parser). */
static int
opts_window_ms(const xrdc_opts *o)
{
    if (o != NULL) {
        if (o->no_retry) {
            return 0;
        }
        if (o->max_stall_ms > 0) {
            return o->max_stall_ms;
        }
    }
    const char *e = getenv("XRDC_MAX_STALL_MS");
    if (e != NULL && *e != '\0') {
        int v = atoi(e);
        return (v > 0) ? v : 0;
    }
    return XRDC_DEFAULT_MAX_STALL_MS;
}

int
xrdc_resilient_window_ms(const xrdc_conn *c)
{
    return opts_window_ms(&c->opts);
}

int
xrdc_connect_resilient(xrdc_conn *c, const xrdc_url *u, const xrdc_opts *o,
                       xrdc_status *st)
{
    int      window = opts_window_ms(o);
    int      rc = xrdc_connect(c, u, o, st);
    uint64_t deadline;
    unsigned attempt = 0;

    if (rc == 0 || window <= 0) {
        return rc;
    }
    deadline = xrdc_mono_ns() + (uint64_t) window * 1000000ULL;
    for (;;) {
        /* A connection that is actively REFUSED (nothing listening) is definitive,
         * not a transient stall — fail fast rather than burn the whole window
         * (matches copy.c's resilient_setup). A timeout/sever mid-handshake on a
         * lossy link stays retryable so the multi-RTT GSI login can ride it out. */
        if (st->kxr == XRDC_ESOCK && st->sys_errno == ECONNREFUSED) {
            return rc;
        }
        if (!xrdc_status_retryable(st) || xrdc_mono_ns() >= deadline) {
            return rc;
        }
        xrdc_backoff_sleep_fast(attempt++);
        rc = xrdc_connect(c, u, o, st);
        if (rc == 0) {
            return 0;
        }
    }
}

int
xrdc_reconnect_home(xrdc_conn *c, xrdc_status *st)
{
    const char *host = (c->home_host[0] != '\0') ? c->home_host : c->host;
    int         port = (c->home_port != 0) ? c->home_port : c->port;
    return xrdc_reconnect(c, host, port, st);
}

/* stateless op wrapper */
int
xrdc_with_resilience(xrdc_conn *c, int max_stall_ms, xrdc_op_class cls,
                     int benign_errno, xrdc_op_fn op, void *arg, xrdc_status *st)
{
    int rc = op(c, arg, st);
    if (rc == 0) {
        return 0;
    }
    /* Disabled, unsafe, or a definitive (non-transport) failure: surface as-is. */
    if (max_stall_ms <= 0 || cls == XRDC_OP_UNSAFE || !xrdc_status_retryable(st)) {
        return rc;
    }

    uint64_t deadline = xrdc_mono_ns() + (uint64_t) max_stall_ms * 1000000ULL;
    unsigned attempt = 0;
    for (;;) {
        if (xrdc_mono_ns() >= deadline) {
            return rc;   /* rc and st hold the last failure */
        }
        xrdc_backoff_sleep_fast(attempt++);
        if (xrdc_reconnect_home(c, st) != 0) {
            if (!xrdc_status_retryable(st) || xrdc_mono_ns() >= deadline) {
                return -1;
            }
            continue;    /* link still flaky — keep trying to reconnect */
        }

        rc = op(c, arg, st);
        if (rc == 0) {
            return 0;
        }
        if (cls == XRDC_OP_MUTATION_NORMALIZE) {
            /* Re-issue exactly ONCE for a mutation. If the first attempt had
             * already been applied server-side (its reply was lost to the sever),
             * the re-issue reports the benign "already in desired state" code —
             * normalize that to success rather than a spurious EEXIST/ENOENT. */
            if (benign_errno != 0 && xrdc_kxr_to_errno(st) == benign_errno) {
                xrdc_status_clear(st);
                return 0;
            }
            return rc;
        }
        if (!xrdc_status_retryable(st)) {
            return rc;   /* READONLY/IDEMPOTENT hit a hard error */
        }
        /* READONLY/IDEMPOTENT: loop until success or the deadline. */
    }
}

/* Resilient single-frame roundtrip. The high-level metadata/fs ops (ops_fs.c
 * fs_simple/fs_text, ops_meta.c stat) route through this, so every tool that
 * calls xrdc_stat/mkdir/rm/query/... inherits reconnect+retry transparently.
 * Re-sending the same hdr24/payload is safe: xrdc_send stamps a fresh streamid. */
int
xrdc_roundtrip_resilient(xrdc_conn *c, void *hdr24, const void *payload,
                         uint32_t plen, xrdc_op_class cls, int benign_errno,
                         uint16_t *status, uint8_t **body, uint32_t *blen,
                         xrdc_status *st)
{
    int window = xrdc_resilient_window_ms(c);
    int rc = xrdc_roundtrip(c, hdr24, payload, plen, status, body, blen, st);
    if (rc == 0) {
        return 0;
    }
    if (window <= 0 || cls == XRDC_OP_UNSAFE || !xrdc_status_retryable(st)) {
        return rc;
    }

    uint64_t deadline = xrdc_mono_ns() + (uint64_t) window * 1000000ULL;
    unsigned attempt = 0;
    for (;;) {
        if (xrdc_mono_ns() >= deadline) {
            return rc;
        }
        xrdc_backoff_sleep_fast(attempt++);
        if (xrdc_reconnect_home(c, st) != 0) {
            if (!xrdc_status_retryable(st) || xrdc_mono_ns() >= deadline) {
                return -1;
            }
            continue;
        }
        rc = xrdc_roundtrip(c, hdr24, payload, plen, status, body, blen, st);
        if (rc == 0) {
            return 0;
        }
        if (cls == XRDC_OP_MUTATION_NORMALIZE) {
            /* Re-issued ONCE after reconnect: if the original had already been
             * applied (its reply lost to the sever), the benign "already in the
             * desired state" code means success, not a spurious EEXIST/ENOENT. */
            if (benign_errno != 0 && xrdc_kxr_to_errno(st) == benign_errno) {
                xrdc_status_clear(st);
                return 0;
            }
            return rc;
        }
        if (!xrdc_status_retryable(st)) {
            return rc;
        }
        /* READONLY/IDEMPOTENT: keep retrying until success or the deadline. */
    }
}

/* resilient file */
/* (Re)open the handle on the CURRENT connection. Writes reopen in place via
 * kXR_open_updt (no truncate) so already-written bytes survive a mid-write
 * sever; reads use the opaque variant when an opaque suffix is present. */
static int
rfile_do_open(xrdc_rfile *rf, xrdc_status *st)
{
    if (rf->writable) {
        return xrdc_file_open_update(rf->c, rf->path, rf->posc, &rf->f, st);
    }
    if (rf->opaque[0] != '\0') {
        return xrdc_file_open_opaque(rf->c, rf->path, rf->opaque, 0, 0, 0,
                                     &rf->f, st);
    }
    return xrdc_file_open_read(rf->c, rf->path, &rf->f, st);
}

/* Reconnect to home + reopen the handle, replacing the dead one. 0 / -1. */
static int
rfile_reopen(xrdc_rfile *rf, xrdc_status *st)
{
    if (xrdc_reconnect_home(rf->c, st) != 0) {
        return -1;
    }
    return rfile_do_open(rf, st);
}

static int
rfile_canceled(const xrdc_rfile *rf)
{
    return rf->cancel != NULL && rf->cancel();
}

static void
rfile_init(xrdc_rfile *rf, xrdc_conn *c, const char *path, int pgrw,
           int max_stall_ms)
{
    memset(rf, 0, sizeof(*rf));
    rf->c = c;
    snprintf(rf->path, sizeof(rf->path), "%s", path);
    rf->pgrw = pgrw;
    rf->cur_chunk = XRDC_RFILE_CHUNK0;
    rf->max_stall_ms = (max_stall_ms > 0) ? max_stall_ms
                                          : xrdc_resilient_window_ms(c);
}

int
xrdc_rfile_open_read(xrdc_conn *c, const char *path, const char *opaque,
                     int pgrw, int max_stall_ms, xrdc_rfile *rf, xrdc_status *st)
{
    rfile_init(rf, c, path, pgrw, max_stall_ms);
    rf->writable = 0;
    if (opaque != NULL) {
        snprintf(rf->opaque, sizeof(rf->opaque), "%s", opaque);
    }

    uint64_t deadline = xrdc_mono_ns() + (uint64_t) rf->max_stall_ms * 1000000ULL;
    unsigned attempt = 0;
    for (;;) {
        if (rfile_do_open(rf, st) == 0) {
            return 0;
        }
        if (!xrdc_status_retryable(st) || rfile_canceled(rf)
            || rf->max_stall_ms <= 0 || xrdc_mono_ns() >= deadline) {
            return -1;
        }
        xrdc_backoff_sleep_fast(attempt++);
        (void) xrdc_reconnect_home(rf->c, st);   /* best-effort; loop re-opens */
    }
}

int
xrdc_rfile_open_write(xrdc_conn *c, const char *path, int force, int posc,
                      int pgrw, int max_stall_ms, xrdc_rfile *rf, xrdc_status *st)
{
    rfile_init(rf, c, path, pgrw, max_stall_ms);
    rf->writable = 1;
    rf->posc = posc;

    /* First open creates/truncates per `force`; nothing is written yet, so
     * retrying a create after a sever is safe. Subsequent reopens (rfile_reopen)
     * switch to in-place update so resumed writes never re-truncate. */
    uint64_t deadline = xrdc_mono_ns() + (uint64_t) rf->max_stall_ms * 1000000ULL;
    unsigned attempt = 0;
    for (;;) {
        if (xrdc_file_open_write(rf->c, rf->path, force, posc, &rf->f, st) == 0) {
            return 0;
        }
        if (!xrdc_status_retryable(st) || rfile_canceled(rf)
            || rf->max_stall_ms <= 0 || xrdc_mono_ns() >= deadline) {
            return -1;
        }
        xrdc_backoff_sleep_fast(attempt++);
        (void) xrdc_reconnect_home(rf->c, st);
    }
}

ssize_t
xrdc_rfile_pread(xrdc_rfile *rf, int64_t off, void *buf, size_t len,
                 xrdc_status *st)
{
    uint64_t deadline = xrdc_mono_ns() + (uint64_t) rf->max_stall_ms * 1000000ULL;
    unsigned attempt = 0;
    for (;;) {
        if (rfile_canceled(rf)) {
            xrdc_status_set(st, XRDC_EUSAGE, ECANCELED, "transfer canceled");
            return -1;
        }
        size_t  want = (len < rf->cur_chunk) ? len : rf->cur_chunk;
        ssize_t n = rf->pgrw ? xrdc_file_pgread(rf->c, &rf->f, off, buf, want, st)
                             : xrdc_file_read(rf->c, &rf->f, off, buf, want, st);
        if (n >= 0) {
            return n;
        }
        if (!xrdc_status_retryable(st) || rf->max_stall_ms <= 0
            || rfile_canceled(rf) || xrdc_mono_ns() >= deadline) {
            return -1;
        }
        /* Transport fault: shrink the request, reconnect+reopen, retry at the
         * same absolute offset (idempotent). */
        if (rf->cur_chunk > XRDC_RFILE_FLOOR) {
            rf->cur_chunk /= 2;
        }
        xrdc_backoff_sleep_fast(attempt++);
        (void) rfile_reopen(rf, st);
    }
}

int
xrdc_rfile_pwrite(xrdc_rfile *rf, int64_t off, const void *buf, size_t len,
                  xrdc_status *st)
{
    uint64_t deadline = xrdc_mono_ns() + (uint64_t) rf->max_stall_ms * 1000000ULL;
    unsigned attempt = 0;
    for (;;) {
        if (rfile_canceled(rf)) {
            xrdc_status_set(st, XRDC_EUSAGE, ECANCELED, "transfer canceled");
            return -1;
        }
        int rc = rf->pgrw ? xrdc_file_pgwrite(rf->c, &rf->f, off, buf, len, st)
                          : xrdc_file_write(rf->c, &rf->f, off, buf, len, st);
        if (rc == 0) {
            return 0;
        }
        if (!xrdc_status_retryable(st) || rf->max_stall_ms <= 0
            || rfile_canceled(rf) || xrdc_mono_ns() >= deadline) {
            return -1;
        }
        /* Re-issuing the same bytes at the same offset onto an in-place reopened
         * handle is idempotent (overwrites identical content). */
        xrdc_backoff_sleep_fast(attempt++);
        (void) rfile_reopen(rf, st);
    }
}

int
xrdc_rfile_close(xrdc_rfile *rf, xrdc_status *st)
{
    return xrdc_file_close(rf->c, &rf->f, st);
}
