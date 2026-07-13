/*
 * copy.c - (kept) routing + shared helpers
 * Phase-38 split of copy.c; behavior-identical.
 */
#include "copy_internal.h"

/* VFS backend link anchors — Phase 38: kept in copy.o (NOT the shared header) so
 * the weak posix/block backends are pulled from libbrix.a when copy.o links. */
extern const brix_vfs_backend *brix_vfs_posix_backend(void);
__attribute__((used))
static const brix_vfs_backend *(*const s_vfs_posix_anchor)(void) =
    brix_vfs_posix_backend;
extern const brix_vfs_backend *brix_vfs_block_backend(void);
__attribute__((used))
static const brix_vfs_backend *(*const s_vfs_block_anchor)(void) =
    brix_vfs_block_backend;

volatile sig_atomic_t g_brix_copy_quit;


void
copy_signal_handler(int sig)
{
    (void) sig;
    g_brix_copy_quit = 1;
}


int
brix_copy_quit_requested(void)
{
    return g_brix_copy_quit != 0;
}


void
brix_copy_install_signal_handlers(void)
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
copy_stall_ms(const brix_copy_opts *o, int dflt)
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
resilient_setup(brix_conn *c, const brix_url *su, const brix_opts *co,
                brix_statinfo *si, int max_stall_ms, brix_status *st)
{
    uint64_t deadline = brix_mono_ns() + (uint64_t) max_stall_ms * 1000000ULL;
    unsigned attempt = 0;
    int      up = 0;
    for (;;) {
        if (!up && brix_connect(c, su, co, st) == 0) {
            up = 1;
        }
        if (up && brix_stat(c, su->path, si, st) == 0) {
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
        if (!brix_status_retryable(st) || brix_copy_quit_requested()
            || brix_mono_ns() >= deadline) {
            if (up) {
                brix_close(c);
            }
            return -1;
        }
        if (up) {            /* drop the suspect session before reconnecting */
            brix_close(c);
            up = 0;
        }
        brix_backoff_sleep_fast(attempt++);
    }
}


/* recursive copy (-r): one connection per tree, dirlist/local walk     */

/* Copy one remote file (open under conn c) to a fresh local file. */
int
copy_one_r2l(brix_conn *c, const char *rpath, const char *lpath,
             int64_t expected_size, brix_status *st)
{
    brix_file         f;
    brix_vfs_file    *vf = NULL;
    brix_vfs_open_opts vopts;
    pump_local_t       lc;
    pump_remote_t      src = {0};
    int                rc;

    if (brix_file_open_read(c, rpath, &f, st) != 0) {
        return -1;
    }

    /* Atomic temp+rename + signal-abort via VFS, mirroring copy_download — so a
     * failed or interrupted recursive transfer leaves no partial/truncated tree
     * entry.  FORCE is always set: recursive copies overwrite existing files. */
    vopts.io_uring      = XRDC_IO_URING_AUTO;
    vopts.expected_size = expected_size;
    vopts.cred          = NULL;
    if (brix_vfs_open(lpath, XRDC_VFS_WRITE | XRDC_VFS_FORCE,
                      &vopts, &vf, st) != 0) {
        brix_file_close(c, &f, st);
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
        rc = brix_vfs_commit(vf, st);
    } else {
        brix_vfs_abort(vf);
    }
    brix_vfs_close(vf);
    brix_file_close(c, &f, st);
    return rc;
}


/* Copy one local file to a fresh remote file (open under conn c). */
int
copy_one_l2r(brix_conn *c, const char *lpath, const char *rpath,
             const brix_copy_opts *o, brix_status *st)
{
    brix_file         f;
    brix_vfs_file    *vf = NULL;
    brix_vfs_open_opts vopts;
    pump_local_t       lc;
    pump_remote_t      sink = {0};
    int                rc;

    vopts.io_uring      = (o != NULL) ? o->io_uring : XRDC_IO_URING_AUTO;
    vopts.expected_size = -1;
    vopts.cred          = NULL;
    if (brix_vfs_open(lpath, XRDC_VFS_READ, &vopts, &vf, st) != 0) {
        return -1;
    }
    if (brix_file_open_write(c, rpath, 1 /*force*/, o ? o->posc : 0, &f, st) != 0) {
        brix_vfs_close(vf);
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

    brix_vfs_close(vf);
    if (rc != 0) {
        brix_file_close(c, &f, st);
        return -1;
    }
    return brix_file_close(c, &f, st);
}


/*
 * WHAT: One classified root:// copy route — both parsed endpoint URLs plus the
 *       four scheme predicates the direction dispatch keys on (src/dst each
 *       remote-vs-local).
 * WHY:  brix_copy formerly parsed the URLs and derived src_remote/dst_remote/
 *       src_local/dst_local inline, then ran a long direction ladder over them in
 *       the same function (CCN 34). Bundling the parse result lets the classify
 *       step and each dispatch step take one const struct, so the orchestrator
 *       stays a flat sequence and the ladder splits per direction without passing
 *       six loose locals around.
 * HOW:  brix_copy_classify() fills one of these (the two brix_url members are
 *       owned by the struct — copied by value from brix_url_parse; the four ints
 *       are pure booleans); the dispatch helpers read it by const pointer and
 *       never mutate it.
 */
typedef struct {
    brix_url su;          /* parsed source URL      */
    brix_url du;          /* parsed destination URL */
    int      src_remote;  /* source is root:///roots:// */
    int      dst_remote;  /* dest is root:///roots://   */
    int      src_local;   /* source is local/stdio      */
    int      dst_local;   /* dest is local/stdio        */
} copy_route_t;


/*
 * WHAT: Parse both root:// endpoints and classify each end as remote vs local,
 *       filling a copy_route_t.
 * WHY:  Isolates the parse+classify computation from the direction dispatch so
 *       the orchestrator reads linearly and the scheme predicates live in one
 *       named place (§8: pure helper, side effects — the two parses — at the
 *       edge of the classification, error surfaced via st).
 * HOW:  Zero-init the route, run brix_url_parse on src then dst (each may set st
 *       and fail), then derive the four scheme booleans exactly as the former
 *       inline code did. Returns 0 on success (route filled), -1 on a parse
 *       failure (st set by brix_url_parse).
 */
static int
brix_copy_classify(const char *src, const char *dst, copy_route_t *r,
                   brix_status *st)
{
    memset(r, 0, sizeof(*r));

    if (brix_url_parse(src, &r->su, st) != 0) {
        return -1;
    }
    if (brix_url_parse(dst, &r->du, st) != 0) {
        return -1;
    }

    r->src_remote = (r->su.scheme == XRDC_SCHEME_ROOT
                     || r->su.scheme == XRDC_SCHEME_ROOTS);
    r->dst_remote = (r->du.scheme == XRDC_SCHEME_ROOT
                     || r->du.scheme == XRDC_SCHEME_ROOTS);
    r->src_local  = (r->su.scheme == XRDC_SCHEME_LOCAL
                     || r->su.scheme == XRDC_SCHEME_STDIO);
    r->dst_local  = (r->du.scheme == XRDC_SCHEME_LOCAL
                     || r->du.scheme == XRDC_SCHEME_STDIO);
    return 0;
}


/*
 * WHAT: Dispatch a remote-source → local-destination copy: an inline
 *       ?xrdcl.unzip= member extraction if the source names one, else a plain
 *       download.
 * WHY:  Lifts the two-way remote→local branch out of the direction ladder so
 *       brix_copy's dispatch stays flat (§5); behaviour is byte-identical to the
 *       former inline block.
 * HOW:  Try unzip_member_from_src on the raw src string + parsed URL; if it names
 *       an archive member, route through copy_unzip, otherwise copy_download.
 */
static int
brix_copy_dispatch_r2l(const char *src, const copy_route_t *r,
                       const brix_copy_opts *o, const brix_opts *co,
                       brix_status *st)
{
    char member[XRDC_PATH_MAX], arch[XRDC_PATH_MAX];

    if (unzip_member_from_src(src, &r->su, member, sizeof(member),
                              arch, sizeof(arch))) {
        return copy_unzip(&r->su, arch, member, &r->du, o, co, st);  /* ?xrdcl.unzip= */
    }
    return copy_download(&r->su, &r->du, o, co, st);   /* remote → local */
}


/*
 * WHAT: Dispatch a remote-source → remote-destination copy per the third-party-
 *       copy mode: TPC-only (hard fail if TPC fails), TPC-first/delegate (TPC
 *       then fall back to a client-mediated copy), or default client-mediated.
 * WHY:  The tpc_mode selection was the deepest arm of brix_copy's ladder (the
 *       CCN driver). Extracting it keeps the mode branching — including the
 *       fall-back diagnostic — in one named, testable place while the
 *       orchestrator stays flat.
 * HOW:  Branch on o->tpc_mode exactly as the former inline code: ONLY → copy_tpc;
 *       FIRST/DELEGATE → copy_tpc, on success return, else emit the same stderr
 *       fall-back note (unless silent) and copy_remote_to_remote; otherwise the
 *       default client-mediated copy_remote_to_remote.
 */
static int
brix_copy_dispatch_r2r(const copy_route_t *r, const brix_copy_opts *o,
                       const brix_opts *co, brix_status *st)
{
    if (o->tpc_mode == XRDC_TPC_ONLY) {
        return copy_tpc(&r->su, &r->du, o, co, st);          /* TPC or hard fail */
    }
    if (o->tpc_mode == XRDC_TPC_FIRST
        || o->tpc_mode == XRDC_TPC_DELEGATE) {
        if (copy_tpc(&r->su, &r->du, o, co, st) == 0) {
            return 0;
        }
        if (!o->silent) {
            fprintf(stderr, "xrdcp: TPC failed (%s); falling back to "
                    "client-mediated copy\n", st->msg);
        }
        return copy_remote_to_remote(&r->su, &r->du, o, co, st);
    }
    return copy_remote_to_remote(&r->su, &r->du, o, co, st);  /* default: client-mediated */
}


/*
 * WHAT: Dispatch a recursive (-r) copy: one remote↔local direction to
 *       copy_recursive, or a usage error for any other endpoint pairing.
 * WHY:  The recursive arm carried three of brix_copy_route's decisions on its
 *       own; extracting it drops the router under the CCN gate and keeps the
 *       "one remote + one local" rule in one named place (§1).
 * HOW:  Build the copy_recurse_req for the download (remote→local) or upload
 *       (local→remote) direction exactly as the former inline code did; any other
 *       pairing (both-remote / both-local) is the same XRDC_EUSAGE error.
 */
static int
brix_copy_dispatch_recursive(const copy_route_t *r, const brix_copy_opts *o,
                             const brix_opts *co, brix_status *st)
{
    if (r->src_remote && r->dst_local) {
        copy_recurse_req rq = { &r->su, &r->du, 1, o, co };
        return copy_recursive(&rq, st);   /* remote tree → local */
    }
    if (r->src_local && r->dst_remote) {
        copy_recurse_req rq = { &r->su, &r->du, 0, o, co };
        return copy_recursive(&rq, st);   /* local tree → remote */
    }
    brix_status_set(st, XRDC_EUSAGE, 0,
                    "recursive copy requires one remote and one local endpoint");
    return -1;
}


/*
 * WHAT: Route a classified root:// copy to the matching transfer path
 *       (recursive, --zip store, download, upload, or remote-to-remote).
 * WHY:  Holds the direction ladder itself, separated from URL classification and
 *       the co_local/web/block pre-steps in brix_copy, so each concern is one
 *       function (§1) and the ladder never re-derives the scheme predicates.
 * HOW:  Early-return through the same ordered checks the former inline code used
 *       — recursive first, then --zip store, then the three supported directions
 *       via the r2l/r2r dispatch helpers and copy_upload — ending in the
 *       unsupported-direction usage error.
 */
static int
brix_copy_route(const char *src, const copy_route_t *r, const brix_copy_opts *o,
                const brix_opts *co, brix_status *st)
{
    if (o != NULL && o->recursive) {
        return brix_copy_dispatch_recursive(r, o, co, st);
    }

    /* phase-42 W3 write: --zip / --zip-append stores a LOCAL source as a STORE
     * member of the destination ZIP archive (local or remote dst). */
    if (o != NULL && (o->zip || o->zip_append)) {
        if (!r->src_local) {
            brix_status_set(st, XRDC_EUSAGE, 0,
                            "--zip requires a local-file source");
            return -1;
        }
        return copy_zip_store(&r->su, &r->du, o, co, st);
    }

    if (r->src_remote && r->dst_local) {
        return brix_copy_dispatch_r2l(src, r, o, co, st);   /* remote → local */
    }
    if (r->src_local && r->dst_remote) {
        return copy_upload(&r->su, &r->du, o, co, st);       /* local → remote */
    }
    if (r->src_remote && r->dst_remote) {
        return brix_copy_dispatch_r2r(r, o, co, st);
    }

    brix_status_set(st, XRDC_EUSAGE, 0,
                    "unsupported copy direction (local→local not supported)");
    return -1;
}


int
brix_copy(const char *src, const char *dst, const brix_copy_opts *o,
          const brix_opts *co_in, brix_status *st)
{
    copy_route_t route;

    /* copy.c manages its OWN reconnect/retry — resilient_setup() for the multi-RTT
     * bring-up and the read pump (pump_src_remote) for mid-transfer severs. Disable
     * the library's op-level baked resilience on the connections this path owns, so
     * stat/dirlist/mkdir don't double-retry inside copy's already-bounded loops. */
    brix_opts co_local;
    if (co_in != NULL) {
        co_local = *co_in;
    } else {
        memset(&co_local, 0, sizeof(co_local));
        co_local.verify_host = 1;
    }
    co_local.no_retry = 1;
    const brix_opts *co = &co_local;

    /* Web schemes (davs/http(s)/s3) take the HTTP transfer path, never the root://
     * session machinery. Check before brix_url_parse (which is root-only). */
    if (brix_is_web_url(src) || brix_is_web_url(dst)) {
        return copy_web(src, dst, o, co, st);
    }

    /* block:// (and /dev/) endpoints route through the VFS block backend.
     * brix_url_parse does not know the block:// scheme and would reject it,
     * so intercept here before the parse. */
    if (brix_is_block_url(src) || brix_is_block_url(dst)) {
        return copy_block(src, dst, o, co, st);
    }

    if (brix_copy_classify(src, dst, &route, st) != 0) {
        return -1;
    }
    return brix_copy_route(src, &route, o, co, st);
}
