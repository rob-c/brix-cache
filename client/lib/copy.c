/*
 * copy.c - (kept) routing + shared helpers
 * Phase-38 split of copy.c; behavior-identical.
 */
#include "copy_internal.h"

/* VFS backend link anchors — Phase 38: kept in copy.o (NOT the shared header) so
 * the weak posix/block backends are pulled from libxrdc.a when copy.o links. */
extern const xrdc_vfs_backend *xrdc_vfs_posix_backend(void);
__attribute__((used))
static const xrdc_vfs_backend *(*const s_vfs_posix_anchor)(void) =
    xrdc_vfs_posix_backend;
extern const xrdc_vfs_backend *xrdc_vfs_block_backend(void);
__attribute__((used))
static const xrdc_vfs_backend *(*const s_vfs_block_anchor)(void) =
    xrdc_vfs_block_backend;

volatile sig_atomic_t g_xrdc_copy_quit;


void
copy_signal_handler(int sig)
{
    (void) sig;
    g_xrdc_copy_quit = 1;
}


int
xrdc_copy_quit_requested(void)
{
    return g_xrdc_copy_quit != 0;
}


void
xrdc_copy_install_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = copy_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;   /* NO SA_RESTART: let blocked I/O return EINTR promptly */
    (void) sigaction(SIGINT, &sa, NULL);
    (void) sigaction(SIGTERM, &sa, NULL);

    /* A write to a peer severed mid-transfer (flaky link / firewall) must surface
     * as EPIPE, never kill the process with SIGPIPE. The cleartext path already
     * uses MSG_NOSIGNAL; this also covers the TLS write path (OpenSSL's internal
     * write()) and any other send site. */
    signal(SIGPIPE, SIG_IGN);
}


/*  * Shared chunked-transfer core (B5).
 *
 * Every byte-pump in this file is the same loop — fill a CHUNK-sized buffer from
 * a source, drain it to a sink, honour cooperative cancel + optional progress —
 * differing only in (a) where bytes come from (remote pgread/read vs a local
 * fd), (b) where they go (a local fd vs remote pgwrite/write), and (c) whether
 * the length is known up front (download/r2r: stop at si->size, where a 0-read
 * is a short-read ERROR) or EOF-driven (upload/recursive: a 0-read is the clean
 * end). transfer_pump() owns the loop once; the source/sink are supplied as
 * small read/write adapters, so each caller keeps its own open/close/teardown
 * verbatim — only the malloc+loop+free block collapses here.
 * ------------------------------------------------------------------------- */

/* Fill up to cap bytes at file offset off. Returns bytes read (>0), 0 for "no
 * more" (EOF for an EOF-driven pump; a short read for a sized pump), or -1 (st
 * set). */
/* Drain exactly n bytes at offset off. Returns 0 or -1 (st set). */

/* Smallest adaptive read request on a high packet-loss link. Balances two costs:
 * smaller = each read likelier to get through, but more reads ⇒ more (expensive,
 * multi-RTT) reconnects after the severs that do happen. 256 KiB is the sweet
 * spot measured against a fault proxy up to 15% per-segment loss. */

/* Effective resilience (max-stall) window in ms for a copy, honouring the
 * fail-fast knob: `no_retry` (set by --no-retry / --retry 0 / --max-stall 0)
 * yields 0 — every bounded copy loop then has a zero-length deadline and fails
 * on the first transport fault instead of spinning the default window against a
 * dead endpoint. Otherwise an explicit positive max_stall_ms wins, else `dflt`.
 * Centralises the choice the bounded loops below all make so `no_retry` can
 * never again be silently dropped (the raw `max_stall_ms > 0 ? : DEFAULT`
 * ternary could not distinguish "fail fast" from "use the default"). */
int
copy_stall_ms(const xrdc_copy_opts *o, int dflt)
{
    if (o != NULL && o->no_retry) {
        return 0;
    }
    if (o != NULL && o->max_stall_ms > 0) {
        return o->max_stall_ms;
    }
    return dflt;
}


/*
 * Resilient session bring-up for a download: connect + stat, retried within a
 * max_stall window on a transport fault (with fast backoff), so the MULTI-RTT
 * setup phase (handshake + login + stat) survives a flaky/lossy link instead of
 * failing the whole copy on the first sever — the same patience the read pump
 * gets. On success `c` is connected and `*si` is filled. 0 / -1 (st set).
 */
int
resilient_setup(xrdc_conn *c, const xrdc_url *su, const xrdc_opts *co,
                xrdc_statinfo *si, int max_stall_ms, xrdc_status *st)
{
    uint64_t deadline = xrdc_mono_ns() + (uint64_t) max_stall_ms * 1000000ULL;
    unsigned attempt = 0;
    int      up = 0;
    for (;;) {
        if (!up && xrdc_connect(c, su, co, st) == 0) {
            up = 1;
        }
        if (up && xrdc_stat(c, su->path, si, st) == 0) {
            return 0;
        }
        /* A connection that has NEVER established and is actively REFUSED is a
         * definitive failure (nothing is listening), not a transient stall — fail
         * fast instead of burning the whole max_stall window retrying it. Re-attempts
         * for a momentarily-down/restarting endpoint are the OUTER --retry's job
         * (it backs off with jitter between whole-copy attempts). A connect TIMEOUT
         * / unreachable (lossy link) or any fault AFTER we were up stays retryable. */
        if (!up && st->kxr == XRDC_ESOCK && st->sys_errno == ECONNREFUSED) {
            return -1;
        }
        if (!xrdc_status_retryable(st) || xrdc_copy_quit_requested()
            || xrdc_mono_ns() >= deadline) {
            if (up) {
                xrdc_close(c);
            }
            return -1;
        }
        if (up) {            /* drop the suspect session before reconnecting */
            xrdc_close(c);
            up = 0;
        }
        xrdc_backoff_sleep_fast(attempt++);
    }
}


/* recursive copy (-r): one connection per tree, dirlist/local walk     */

/* Copy one remote file (open under conn c) to a fresh local file. */
int
copy_one_r2l(xrdc_conn *c, const char *rpath, const char *lpath,
             int64_t expected_size, xrdc_status *st)
{
    xrdc_file         f;
    xrdc_vfs_file    *vf = NULL;
    xrdc_vfs_open_opts vopts;
    pump_local_t       lc;
    pump_remote_t      src = {0};
    int                rc;

    if (xrdc_file_open_read(c, rpath, &f, st) != 0) {
        return -1;
    }

    /* Atomic temp+rename + signal-abort via VFS, mirroring copy_download — so a
     * failed or interrupted recursive transfer leaves no partial/truncated tree
     * entry.  FORCE is always set: recursive copies overwrite existing files. */
    vopts.io_uring      = XRDC_IO_URING_AUTO;
    vopts.expected_size = expected_size;
    vopts.cred          = NULL;
    if (xrdc_vfs_open(lpath, XRDC_VFS_WRITE | XRDC_VFS_FORCE,
                      &vopts, &vf, st) != 0) {
        xrdc_file_close(c, &f, st);
        return -1;
    }

    /* remote → local VFS (plain read, recursive path; not paged). */
    src.c    = c;
    src.f    = &f;
    src.pgrw = 0;
    lc.vf    = vf;
    rc = transfer_pump(pump_src_remote, &src, pump_sink_local_vfs, &lc,
                       expected_size, NULL, expected_size, st);

    if (rc == 0) {
        rc = xrdc_vfs_commit(vf, st);
    } else {
        xrdc_vfs_abort(vf);
    }
    xrdc_vfs_close(vf);
    xrdc_file_close(c, &f, st);
    return rc;
}


/* Copy one local file to a fresh remote file (open under conn c). */
int
copy_one_l2r(xrdc_conn *c, const char *lpath, const char *rpath,
             const xrdc_copy_opts *o, xrdc_status *st)
{
    xrdc_file         f;
    xrdc_vfs_file    *vf = NULL;
    xrdc_vfs_open_opts vopts;
    pump_local_t       lc;
    pump_remote_t      sink = {0};
    int                rc;

    vopts.io_uring      = (o != NULL) ? o->io_uring : XRDC_IO_URING_AUTO;
    vopts.expected_size = -1;
    vopts.cred          = NULL;
    if (xrdc_vfs_open(lpath, XRDC_VFS_READ, &vopts, &vf, st) != 0) {
        return -1;
    }
    if (xrdc_file_open_write(c, rpath, 1 /*force*/, o ? o->posc : 0, &f, st) != 0) {
        xrdc_vfs_close(vf);
        return -1;
    }

    /* local VFS (EOF-driven) → remote, plain write (recursive path). On failure
     * the file is still closed (preserving the historical recursive teardown,
     * which never relied on POSC-discard the way single-file upload does). */
    sink.c    = c;
    sink.f    = &f;
    sink.pgrw = 0;
    lc.vf     = vf;
    rc = transfer_pump(pump_src_local_vfs, &lc, pump_sink_remote, &sink,
                       -1, NULL, 0, st);

    xrdc_vfs_close(vf);
    if (rc != 0) {
        xrdc_file_close(c, &f, st);
        return -1;
    }
    return xrdc_file_close(c, &f, st);
}


int
xrdc_copy(const char *src, const char *dst, const xrdc_copy_opts *o,
          const xrdc_opts *co_in, xrdc_status *st)
{
    xrdc_url su, du;
    int      src_remote, dst_remote, src_local, dst_local;

    /* copy.c manages its OWN reconnect/retry — resilient_setup() for the multi-RTT
     * bring-up and the read pump (pump_src_remote) for mid-transfer severs. Disable
     * the library's op-level baked resilience on the connections this path owns, so
     * stat/dirlist/mkdir don't double-retry inside copy's already-bounded loops. */
    xrdc_opts co_local;
    if (co_in != NULL) {
        co_local = *co_in;
    } else {
        memset(&co_local, 0, sizeof(co_local));
        co_local.verify_host = 1;
    }
    co_local.no_retry = 1;
    const xrdc_opts *co = &co_local;

    /* Web schemes (davs/http(s)/s3) take the HTTP transfer path, never the root://
     * session machinery. Check before xrdc_url_parse (which is root-only). */
    if (xrdc_is_web_url(src) || xrdc_is_web_url(dst)) {
        return copy_web(src, dst, o, co, st);
    }

    /* block:// (and /dev/) endpoints route through the VFS block backend.
     * xrdc_url_parse does not know the block:// scheme and would reject it,
     * so intercept here before the parse. */
    if (xrdc_is_block_url(src) || xrdc_is_block_url(dst)) {
        return copy_block(src, dst, o, co, st);
    }

    if (xrdc_url_parse(src, &su, st) != 0) {
        return -1;
    }
    if (xrdc_url_parse(dst, &du, st) != 0) {
        return -1;
    }

    src_remote = (su.scheme == XRDC_SCHEME_ROOT || su.scheme == XRDC_SCHEME_ROOTS);
    dst_remote = (du.scheme == XRDC_SCHEME_ROOT || du.scheme == XRDC_SCHEME_ROOTS);
    src_local  = (su.scheme == XRDC_SCHEME_LOCAL || su.scheme == XRDC_SCHEME_STDIO);
    dst_local  = (du.scheme == XRDC_SCHEME_LOCAL || du.scheme == XRDC_SCHEME_STDIO);

    if (o != NULL && o->recursive) {
        if (src_remote && dst_local) {
            return copy_recursive(&su, &du, 1, o, co, st);   /* remote tree → local */
        }
        if (src_local && dst_remote) {
            return copy_recursive(&su, &du, 0, o, co, st);   /* local tree → remote */
        }
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "recursive copy requires one remote and one local endpoint");
        return -1;
    }

    /* phase-42 W3 write: --zip / --zip-append stores a LOCAL source as a STORE
     * member of the destination ZIP archive (local or remote dst). */
    if (o != NULL && (o->zip || o->zip_append)) {
        if (!src_local) {
            xrdc_status_set(st, XRDC_EUSAGE, 0,
                            "--zip requires a local-file source");
            return -1;
        }
        return copy_zip_store(&su, &du, o, co, st);
    }

    if (src_remote && dst_local) {
        char member[XRDC_PATH_MAX], arch[XRDC_PATH_MAX];
        if (unzip_member_from_src(src, &su, member, sizeof(member),
                                  arch, sizeof(arch))) {
            return copy_unzip(&su, arch, member, &du, o, co, st);  /* ?xrdcl.unzip= */
        }
        return copy_download(&su, &du, o, co, st);   /* remote → local */
    }
    if (src_local && dst_remote) {
        return copy_upload(&su, &du, o, co, st);      /* local → remote */
    }
    if (src_remote && dst_remote) {
        if (o->tpc_mode == XRDC_TPC_ONLY) {
            return copy_tpc(&su, &du, o, co, st);            /* TPC or hard fail */
        }
        if (o->tpc_mode == XRDC_TPC_FIRST
            || o->tpc_mode == XRDC_TPC_DELEGATE) {
            if (copy_tpc(&su, &du, o, co, st) == 0) {
                return 0;
            }
            if (!o->silent) {
                fprintf(stderr, "xrdcp: TPC failed (%s); falling back to "
                        "client-mediated copy\n", st->msg);
            }
            return copy_remote_to_remote(&su, &du, o, co, st);
        }
        return copy_remote_to_remote(&su, &du, o, co, st);   /* default: client-mediated */
    }

    xrdc_status_set(st, XRDC_EUSAGE, 0,
                    "unsupported copy direction (local→local not supported)");
    return -1;
}
