/*
 * xrootdfs.c - (kept) routing + shared helpers
 * Phase-38 split of xrootdfs.c; behavior-identical.
 */
#include "xrootdfs_internal.h"
#include "xrootdfs_argsplit.h"
#include "core/version.h"
#include "net/cpool.h"
#include "protocols/http/web_ka.h"

#include <unistd.h>     /* fork/setsid/pipe/dup2 — the daemonize helpers below */

brix_pool *g_pool;

/* Phase-86: pooled keep-alive WebDAV metadata (getattr/readdir) on web mounts.
 * NULL on root:// mounts. The template is copied into each slot by the vtable. */
brix_cpool         *g_web_pool;
static brix_webmeta g_web_tmpl;

static int
web_slot_connect(void *conn, void *ctx, brix_status *st)
{
    brix_webmeta *m = conn;
    *m = *(const brix_webmeta *) ctx;   /* copy host/port/tls/auth template */
    m->ka.connected = 0;
    m->ka.io.fd = -1;
    m->ka.tls_ctx = NULL;               /* fresh transport per slot */
    return brix_kaconn_connect(&m->ka, st);
}

static void
web_slot_close(void *conn)
{
    brix_kaconn_disconnect(&((brix_webmeta *) conn)->ka);
}

static const brix_cpool_vtbl WEB_VT = {
    sizeof(brix_webmeta), web_slot_connect, web_slot_close,
};

brix_url   g_url;

brix_opts  g_opts;

int        g_max_conns = 8;       

int          g_web = 0;

brix_weburl  g_weburl;

brix_mgr  *g_mgr;

int        g_streams     = 4;     /* async data connections; --streams */
int        g_lazy_streams = 0;    /* --lazy-streams: open 1 at mount, rest on demand */
int               g_max_stall   = 60000; /* reconnect patience ms; --max-stall */
 int        g_keepalive   = 15000; /* heartbeat-after-idle ms; --keepalive */
 int        g_max_retries = 5;     /* transient retries; --max-retries */

/* Kernel-side caching policy (set in xfs_init). */
 double     g_attr_timeout  = 1.0;

double     g_entry_timeout = 1.0;

int        g_kernel_cache  = 0;

int        g_xattr         = 0;

char       g_compress[32]  = "";

int        g_ext_setattr   = 0;

int        g_ext_symlink   = 0;

int        g_ext_readlink  = 0;

int        g_ext_link      = 0;

size_t     g_readahead = 1024 * 1024;

size_t     g_writeback = 1024 * 1024;

const struct fuse_operations xfs_ops = {
    .init     = xfs_init,
    .getattr  = xfs_getattr,
    .readdir  = xfs_readdir,
    .open     = xfs_open,
    .create   = xfs_create,
    .read     = xfs_read,
    .write    = xfs_write,
    .flush    = xfs_flush,
    .release  = xfs_release,
    .fsync    = xfs_fsync,
    .mkdir    = xfs_mkdir,
    .unlink   = xfs_unlink,
    .rmdir    = xfs_rmdir,
    .rename   = xfs_rename,
    .chmod    = xfs_chmod,
    .truncate = xfs_truncate,
    .chown    = xfs_chown,
    .utimens  = xfs_utimens,
    .symlink  = xfs_symlink,
    .readlink = xfs_readlink,
    .link     = xfs_link,
    .statfs   = xfs_statfs,
    .access   = xfs_access,
    .getxattr    = xfs_getxattr,
    .setxattr    = xfs_setxattr,
    .listxattr   = xfs_listxattr,
    .removexattr = xfs_removexattr,
};


const char  *g_bearer = NULL;     /* --token / $BEARER_TOKEN (else anon) */
int                 g_web_verify = 1;    /* TLS server-cert verification (https) */
const char         *g_web_ca = NULL;     /* CA hash dir (else $X509_CERT_DIR) */
static char         g_web_proxy_buf[512];
const char         *g_web_proxy = NULL;  /* X.509 proxy PEM for davs mutual TLS */
 char         g_base[XRDC_PATH_MAX] = "";  /* URL path prefix (export base) */

/* Defined with the daemonize helpers below; called from xfs_init() so the
 * launching shell blocks until the mount is actually live. */
static void xfs_daemon_ready(unsigned char status);

/* Map a FUSE path ("/file") to the server path under the export base. With an
 * empty base the FUSE path is used verbatim; with base "/data" → "/data/file"
 * and "/" → "/data". Shared by BOTH transports (root:// and http/WebDAV) so a
 * URL like root://host/data or https://host/data mounts that subtree. */
const char *
srv_path(const char *p, char *buf, size_t sz)
{
    if (g_base[0] == '\0') {
        return p;
    }
    if (strcmp(p, "/") == 0) {
        return g_base;
    }
    size_t bl = strlen(g_base);
    size_t pl = strlen(p);
    if (bl + pl + 1 > sz) {            /* impossible for real paths — fail safe */
        return g_base;
    }
    memcpy(buf, g_base, bl);
    memcpy(buf + bl, p, pl + 1);       /* includes the NUL */
    return buf;
}


/* File-I/O subsystem: the async manager (loop + connection pool for mfiles). */
/* phase-42 W4: -o compress=<codec> / --compress <codec> — request inline read
 * compression on every read open (transparently inflated by brix_mfile).  Empty
 * = plaintext (default). */

/* Vendor POSIX-extension capabilities, probed once at mount via kXR_Qconfig
 * "xrdfs.ext". When a capability is absent the driver keeps the honest fallback
 * (utimens/chown succeed as no-ops so `cp -p` still works; symlink/link → ENOTSUP). */

/* Per-handle I/O buffering sizes (0 disables). */


/* error mapping + helpers                                              */

/* Error mapping + the pooled metadata-op runner now live in lib/fuse_ops.c and
 * are shared with the legacy driver.  These keep the driver-local spellings as
 * thin wrappers: xfs_err/xfs_conn_healthy are used throughout the read/write/
 * open paths, and xfs_meta binds the runner to this driver's pool + retry budget
 * (g_max_retries > 0 → the resilient retry+backoff behaviour). */
int
xfs_err(const brix_status *st)
{
    return brix_fuse_errno(st);
}


int
xfs_conn_healthy(const brix_status *st)
{
    return brix_fuse_conn_healthy(st);
}


int
xfs_meta(brix_fuse_op_fn fn, void *ctx, brix_status *st)
{
    /* Deadline-bounded (g_max_stall) like the data plane — ride a lossy link out
     * for the patience window rather than giving up after a fixed count. */
    return brix_fuse_run(g_pool, g_max_retries, g_max_stall, 0, fn, ctx, st);
}


/* As xfs_meta, for a MUTATION whose re-issue after a sever can return a benign
 * "already in the desired state" code (the first attempt applied it, its reply
 * lost): benign_errno (EEXIST/ENOENT) is normalized to success on a retry. */
int
xfs_meta_idem(brix_fuse_op_fn fn, void *ctx, int benign_errno, brix_status *st)
{
    return brix_fuse_run(g_pool, g_max_retries, g_max_stall, benign_errno,
                         fn, ctx, st);
}


void
xfs_fill_stat(const brix_statinfo *si, struct stat *stbuf)
{
    /* allow_symlink=1: the async getattr uses lstat, so kXR_other → S_IFLNK. */
    brix_statinfo_to_stat(si, 1, stbuf);
}


int
xfs_link(const char *from, const char *to)
{
    if (g_web) return -EROFS;
    if (!g_ext_link) {
        return -ENOTSUP;
    }
    brix_status st; brix_status_clear(&st);
    char fbuf[XRDC_PATH_MAX], tbuf[XRDC_PATH_MAX];
    struct brix_fuse_ctx_link2 a = { srv_path(from, fbuf, sizeof(fbuf)),
                           srv_path(to, tbuf, sizeof(tbuf)) };
    return xfs_meta_idem(brix_fuse_op_link, &a, EEXIST, &st);
}


void *
xfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
    (void) conn;
    /* The session is up and the mountpoint is live: release the waiting parent
     * (no-op in the foreground). Doing it HERE rather than before fuse_main()
     * means `xrootdfs … && ls /mnt` cannot race the mount. If fuse_main fails
     * before init, the child exits, the pipe closes, and the parent's short
     * read reports the failure. */
    xfs_daemon_ready(0);
    cfg->attr_timeout     = g_attr_timeout;
    cfg->entry_timeout    = g_entry_timeout;
    cfg->negative_timeout = g_attr_timeout;
    cfg->kernel_cache     = g_kernel_cache;
    cfg->use_ino          = 1;
    return NULL;
}



/* main                                                                */


/* WHAT: consume one value-less command-line flag (boolean toggles).
 * WHY:  keeps the arg loop flat — each option family is one small matcher
 *       instead of a single branch ladder (phase-72 H3 decomposition).
 * HOW:  strcmp over the flag names, setting the matching global; returns 1
 *       when `a` was one of ours, 0 to let the caller keep matching. */
static int
aio_opt_novalue(const char *a)
{
    if (strcmp(a, "--tls") == 0)          { g_opts.want_tls = 1;    return 1; }
    if (strcmp(a, "--notlsok") == 0)      { g_opts.notlsok = 1;     return 1; }
    if (strcmp(a, "--noverifyhost") == 0) { g_opts.verify_host = 0; return 1; }
    if (strcmp(a, "--lazy-streams") == 0) { g_lazy_streams = 1;     return 1; }
    if (strcmp(a, "--kernel-cache") == 0) { g_kernel_cache = 1;     return 1; }
    if (strcmp(a, "--xattr") == 0)        { g_xattr = 1;            return 1; }
    return 0;
}


/* WHAT: consume one connection/resilience option that takes a value.
 * WHY:  splits the value-option ladder in two so each stays under the
 *       complexity gate; clamping (floors) is preserved verbatim.
 * HOW:  `v` is the next argv word (caller guarantees it exists and advances
 *       past it on a hit); returns 1 when `a` was consumed. */
static int
aio_opt_conn_value(const char *a, char *v)
{
    if (strcmp(a, "--auth") == 0) { g_opts.auth_force = v; return 1; }
    if (strcmp(a, "--max-conns") == 0) {
        g_max_conns = atoi(v);
        if (g_max_conns < 1) { g_max_conns = 1; }
        return 1;
    }
    if (strcmp(a, "--streams") == 0) {
        g_streams = atoi(v);
        if (g_streams < 1) { g_streams = 1; }
        return 1;
    }
    if (strcmp(a, "--max-stall") == 0) {
        g_max_stall = atoi(v);
        if (g_max_stall < 0) { g_max_stall = 0; }
        return 1;
    }
    if (strcmp(a, "--keepalive") == 0) {
        g_keepalive = atoi(v);
        if (g_keepalive < 0) { g_keepalive = 0; }
        return 1;
    }
    if (strcmp(a, "--max-retries") == 0) {
        g_max_retries = atoi(v);
        if (g_max_retries < 0) { g_max_retries = 0; }
        return 1;
    }
    if (strcmp(a, "--connect-timeout") == 0) { brix_tmo_set_connect_ms(atoi(v)); return 1; }
    if (strcmp(a, "--io-timeout") == 0)      { brix_tmo_set_io_ms(atoi(v));      return 1; }
    return 0;
}


/* WHAT: consume one caching/auth option that takes a value.
 * WHY:  second half of the value-option split (see aio_opt_conn_value).
 * HOW:  same contract — `v` is the next argv word; returns 1 on a hit. */
static int
aio_opt_cache_value(const char *a, char *v)
{
    if (strcmp(a, "--attr-timeout") == 0)  { g_attr_timeout = atof(v);  return 1; }
    if (strcmp(a, "--entry-timeout") == 0) { g_entry_timeout = atof(v); return 1; }
    if (strcmp(a, "--readahead") == 0) {
        long n = atol(v);
        g_readahead = (n > 0) ? (size_t) n : 0;
        return 1;
    }
    if (strcmp(a, "--writeback") == 0) {
        long n = atol(v);
        g_writeback = (n > 0) ? (size_t) n : 0;
        return 1;
    }
    if (strcmp(a, "--compress") == 0) {
        snprintf(g_compress, sizeof(g_compress), "%s", v);
        return 1;
    }
    if (strcmp(a, "--token") == 0) { g_bearer = v; return 1; }
    return 0;
}


/* WHAT: split the command line into our options, the endpoint, and the
 *       libfuse passthrough vector.
 * WHY:  our known options are honored ANYWHERE on the line (before OR after
 *       the endpoint), so a resilience flag placed after the URL is honored
 *       rather than silently leaking to libfuse. Unknown dash-args fall
 *       through to the fuse passthrough (so -f/-d/-s/-o still work); the
 *       first bare word is the endpoint, the next the mountpoint.
 * HOW:  value options are only matched when a next word exists (a trailing
 *       `--token` passes through to fuse, exactly as before). Returns -1 to
 *       proceed with the mount, or a process exit code (--version/--help/-h
 *       inside the line exit immediately with 0). */
static int
aio_parse_args(int argc, char **argv, char **fuse_argv, int *fuse_argc,
               const char **endpoint)
{
    int i;

    for (i = 1; i < argc; i++) {
        char *a = argv[i];
        if (a[0] == '-') {
            if (aio_opt_novalue(a)) { continue; }
            if (i + 1 < argc && aio_opt_conn_value(a, argv[i + 1]))  { i++; continue; }
            if (i + 1 < argc && aio_opt_cache_value(a, argv[i + 1])) { i++; continue; }
            if (strcmp(a, "--version") == 0) {
                printf("xrootdfs (BriX-Cache client) %s\n", brix_client_version());
                return 0;
            }
            if (strcmp(a, "--help") == 0) { usage_fp(stdout); return 0; }  /* WS-2 */
            if (strcmp(a, "-h") == 0)     { usage();          return 0; }  /* C1 */
        }
        xfs_arg_passthrough(a, a[0] == '-', fuse_argv, fuse_argc, endpoint);
    }
    return -1;
}


/* WHAT: set the export base (g_base) from a URL path component.
 * WHY:  shared by BOTH transports — the mount roots at the URL's /base
 *       subtree; srv_path() prepends it to every FUSE path.
 * HOW:  copy then trim trailing '/'; "/" or "" → empty base (verbatim FUSE
 *       paths). */
static void
aio_set_base(const char *path)
{
    size_t bl;

    snprintf(g_base, sizeof(g_base), "%s", path);
    bl = strlen(g_base);
    while (bl > 0 && g_base[bl - 1] == '/') {
        g_base[--bl] = '\0';
    }
}


/* ---- daemonize BEFORE any thread exists --------------------------------- *
 *
 * fuse_main() daemonizes by forking, and it does that AFTER the mount helpers
 * below have built the metadata pool and the async data-stream manager. The
 * manager owns a pthread (the aio event loop), and threads do NOT survive
 * fork(): the daemon child inherits the sockets but nobody to drive them, so
 * metadata still answers (the pool is synchronous on the calling thread) while
 * the first read() blocks forever in the kernel waiting for a completion that
 * can never arrive. Forking FIRST and letting the child do the whole setup puts
 * every thread on the correct side of the fork.
 *
 * The parent deliberately does not exit at fork time: it waits for the child to
 * report the setup outcome over a pipe, so the mount banner and any connect
 * error still reach the terminal in order, and the shell still sees the real
 * exit status — both of which a plain fuse_daemonize() would throw away.
 */
static int xfs_daemon_pipe = -1;    /* child's write end; -1 = foreground */

/* 1 when the caller already asked FUSE to stay in the foreground. `-d` implies
 * `-f` in libfuse, and `-o debug`/`-odebug` is the long spelling of `-d`. */
static int
xfs_wants_foreground(int fuse_argc, char **fuse_argv)
{
    for (int i = 1; i < fuse_argc; i++) {
        const char *a = fuse_argv[i];
        if (strcmp(a, "-f") == 0 || strcmp(a, "-d") == 0) return 1;
        if (strcmp(a, "-odebug") == 0) return 1;
        if (strcmp(a, "-o") == 0 && i + 1 < fuse_argc
            && strcmp(fuse_argv[i + 1], "debug") == 0) return 1;
    }
    return 0;
}

/* Fork into the background. Returns 0 in the child (which continues with setup),
 * never returns in the parent, and returns -1 if the fork itself failed. */
static int
xfs_daemonize(void)
{
    int fds[2];

    if (pipe(fds) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return -1; }

    if (pid > 0) {
        /* Parent: block until the child reports, then exit with its status. A
         * short read means the child died before reporting — treat as failure. */
        unsigned char status = 1;
        close(fds[1]);
        ssize_t n = read(fds[0], &status, 1);
        close(fds[0]);
        _exit(n == 1 ? (int) status : 1);
    }

    close(fds[0]);
    /* Detach from the controlling terminal and the cwd, but KEEP stdio until
     * xfs_daemon_ready() — that is what carries diagnostics to the user. */
    if (setsid() == (pid_t) -1) { /* already a leader; harmless */ }
    if (chdir("/") != 0)         { /* non-fatal */ }
    xfs_daemon_pipe = fds[1];
    return 0;
}

/* Report the setup outcome to the waiting parent and detach stdio. Call exactly
 * once per daemonized run: with 0 right before entering the FUSE loop, or with
 * the intended exit code on any earlier failure. A no-op in the foreground. */
static void
xfs_daemon_ready(unsigned char status)
{
    if (xfs_daemon_pipe < 0) return;

    ssize_t w = write(xfs_daemon_pipe, &status, 1);
    (void) w;                       /* parent gone → nothing to report to */
    close(xfs_daemon_pipe);
    xfs_daemon_pipe = -1;

    int nullfd = open("/dev/null", O_RDWR);
    if (nullfd >= 0) {
        (void) dup2(nullfd, STDIN_FILENO);
        (void) dup2(nullfd, STDOUT_FILENO);
        (void) dup2(nullfd, STDERR_FILENO);
        if (nullfd > STDERR_FILENO) close(nullfd);
    }
}

/* Daemonize (unless the caller asked for the foreground) and pin FUSE to the
 * foreground so fuse_main() cannot fork a second time behind our threads.
 * Returns 0 on success, or an exit code to return from the mount helper. */
static int
xfs_daemon_setup(int *fuse_argc, char **fuse_argv, size_t fuse_argv_cap)
{
    if (xfs_wants_foreground(*fuse_argc, fuse_argv)) return 0;

    /* One slot for "-f" plus the NULL terminator. */
    if ((size_t) *fuse_argc + 2 > fuse_argv_cap) {
        fprintf(stderr, "xrootdfs: too many mount options\n");
        return 2;
    }
    if (xfs_daemonize() != 0) {
        fprintf(stderr, "xrootdfs: cannot daemonize: %s\n", strerror(errno));
        return 2;
    }
    fuse_argv[(*fuse_argc)++] = (char *) "-f";
    fuse_argv[*fuse_argc]     = NULL;
    return 0;
}

#define __XROOTDFS_C_COMPILED__
#include "_xrootdfs_part2.c"
