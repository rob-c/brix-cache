/*
 * xrootdfs.c - (kept) routing + shared helpers
 * Phase-38 split of xrootdfs.c; behavior-identical.
 */
#include "xrootdfs_internal.h"
#include "core/version.h"

brix_pool *g_pool;

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
 char         g_base[XRDC_PATH_MAX] = "";  /* URL path prefix (export base) */

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
    cfg->attr_timeout     = g_attr_timeout;
    cfg->entry_timeout    = g_entry_timeout;
    cfg->negative_timeout = g_attr_timeout;
    cfg->kernel_cache     = g_kernel_cache;
    cfg->use_ino          = 1;
    return NULL;
}



/* main                                                                */

static void
usage_fp(FILE *out)
{
    fprintf(out,
        "usage: xrootdfs [opts] <endpoint> <mountpoint> [fuse-opts]\n"
        "  endpoint:   root[s]://host[:port][/base]      (binary XRootD; read-write)\n"
        "              http|https|dav|davs://host[:port][/base]\n"
        "                                (WebDAV/XrdHttp; READ-ONLY, ranged GET)\n"
        "              a /base path component roots the mount at that subtree\n"
        "  web-opts:   --token TOK       bearer token for http(s)  ($BEARER_TOKEN)\n"
        "              --noverifyhost    skip TLS server-cert check (self-signed beds)\n"
        "  conn-opts:  --tls --notlsok --noverifyhost --auth <gsi|ztn|unix>\n"
        "              --max-conns N    metadata connection pool size (default 8)\n"
        "              --version        print version and exit\n"
        "  resilience: --streams N      async data connections (default 4)\n"
        "              --lazy-streams   open 1 stream at mount, the rest on first\n"
        "                               I/O (lowest mount latency; first read warms up)\n"
        "              --max-stall MS   reconnect patience for a dropped link\n"
        "                               (default 60000; 0 = fail fast, no reconnect)\n"
        "              --keepalive MS   heartbeat after this idle time (default 15000)\n"
        "              --max-retries N  transient-error retries (default 5)\n"
        "              --connect-timeout MS  cap on connect+handshake+login\n"
        "                               (default 15000; tighten on a flaky firewall)\n"
        "              --io-timeout MS  steady-state read/write cap (default 30000)\n"
        "  cache-opts: --attr-timeout S --entry-timeout S --kernel-cache\n"
        "              --compress C     inline read compression (gzip|deflate|zstd|\n"
        "                               br|xz|bzip2); server opt-in, transparently\n"
        "                               inflated; ignored if the server declines\n"
        "              --readahead N    per-handle read-ahead bytes (default 1048576)\n"
        "              --writeback N    per-handle write-back bytes (default 1048576)\n"
        "              --xattr          enable extended attributes (kXR_fattr)\n"
        "  fuse-opts:  -f -d -s -o <opt>  (e.g. -o ro -o allow_other)\n"
        "  notes: open files survive a connection drop / server restart transparently\n"
        "         (reopen + resume at the same offset, byte-exact). utimens/chown are\n"
        "         no-ops (no XRootD wire op); symlinks are unsupported.\n"
        BRIX_USAGE_FOOTER("xrootdfs"));
}

void
usage(void)
{
    usage_fp(stderr);
}


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
            if (*fuse_argc < 61) { fuse_argv[(*fuse_argc)++] = argv[i]; }  /* fuse opt */
        } else if (*endpoint == NULL) {
            *endpoint = a;
        } else if (*fuse_argc < 61) {
            fuse_argv[(*fuse_argc)++] = argv[i];
        }
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


/* WHAT: mount an HTTP(S)/WebDAV endpoint (read-only, ranged GET).
 * WHY:  isolates the whole web transport bring-up (URL parse, bearer/TLS
 *       policy, reachability probe) from the root:// path in main.
 * HOW:  parse + validate the web URL, derive the export base, stat the
 *       export root up front (fail the mount early if unreachable/denied),
 *       then hand off to fuse_main. Returns the process exit code. */
static int
aio_web_mount(int fuse_argc, char **fuse_argv, const char *endpoint)
{
    brix_status   st;
    brix_statinfo si;

    brix_status_clear(&st);
    if (brix_weburl_parse(endpoint, &g_weburl) != 0) {
        fprintf(stderr, "xrootdfs: bad web URL: %s\n", endpoint);
        return 2;
    }
    if (g_weburl.is_s3) {
        fprintf(stderr, "xrootdfs: s3:// is not supported as a FUSE mount "
                        "(use http/https/dav/davs)\n");
        return 2;
    }
    g_web = 1;
    if (g_bearer == NULL) {
        g_bearer = getenv("BEARER_TOKEN");
    }
    g_web_verify = g_opts.verify_host;
    g_web_ca = brix_resolve_ca_dir(g_opts.ca_dir);
    /* export base = the URL path, trailing '/' trimmed; "/" → "" (verbatim). */
    aio_set_base(g_weburl.path);
    /* fail the mount up front if the export root is unreachable/denied. */
    if (brix_web_stat(&g_weburl, g_base[0] ? g_base : "/", g_bearer,
                      g_web_verify, g_web_ca, &si, &st) != 0) {
        fprintf(stderr, "xrootdfs: %s://%s:%d%s: %s\n",
                g_weburl.tls ? "https" : "http", g_weburl.host, g_weburl.port,
                g_weburl.path, st.msg);
        return brix_shellcode(&st);
    }
    fprintf(stderr,
            "xrootdfs: mounted %s:%d via %s%s (read-only WebDAV; "
            "verify=%d, auth=%s)\n",
            g_weburl.host, g_weburl.port, g_weburl.tls ? "HTTPS" : "HTTP",
            g_base, g_web_verify, g_bearer ? "bearer" : "anon");
    return fuse_main(fuse_argc, fuse_argv, &xfs_ops, NULL);
}


/* WHAT: probe the server's vendor POSIX extensions (kXR_Qconfig "xrdfs.ext")
 *       once at mount.
 * WHY:  utimens/chown/symlink/readlink/link adapt to what is advertised;
 *       absent capabilities keep the honest fallbacks.
 * HOW:  checkout a pooled metadata connection, probe, and check it back in
 *       (unhealthy on a probe failure that severed the link). */
static void
aio_probe_ext(brix_status *st)
{
    brix_conn *pc = brix_pool_checkout(g_pool, st);

    if (pc != NULL) {
        int ok = (brix_ext_probe(pc, &g_ext_setattr, &g_ext_symlink,
                                 &g_ext_readlink, &g_ext_link, st) == 0);
        brix_pool_checkin(g_pool, pc, ok ? 1 : xfs_conn_healthy(st));
    }
}


/* WHAT: mount a root[s]:// endpoint (binary XRootD; read-write, resilient).
 * WHY:  isolates the async-driver bring-up (metadata pool + data-stream
 *       manager + extension probe) and its teardown ordering from main.
 * HOW:  parse the endpoint, derive the export base, create the pool then the
 *       manager (destroyed in reverse order after fuse_main returns), probe
 *       extensions, run fuse. Returns the process exit code. */
static int
aio_root_mount(int fuse_argc, char **fuse_argv, const char *endpoint)
{
    brix_status st;
    int         rc;

    brix_status_clear(&st);
    if (brix_endpoint_parse(endpoint, &g_url, &st) != 0) {
        fprintf(stderr, "xrootdfs: %s\n", st.msg);
        return 2;
    }

    /* Export base = the URL path component (root://host/data → "/data"), so the
     * mount roots at that subtree.  Trailing '/' trimmed; a bare host (path "/" or
     * empty) → verbatim FUSE paths.  Shared with the web transport via srv_path(). */
    aio_set_base((g_url.path[0] == '/') ? g_url.path : "");

    g_pool = brix_pool_create(&g_url, &g_opts, g_max_conns, &st);
    if (g_pool == NULL) {
        fprintf(stderr, "xrootdfs: connect %s:%d: %s\n",
                g_url.host, g_url.port, st.msg);
        return brix_shellcode(&st);
    }
    /* Default: connect all data streams up front (in parallel — ~1×RTT mount).
     * --lazy-streams trades first-read warm-up for the lowest possible mount
     * latency by bringing up just one stream now and the rest on demand. */
    g_mgr = brix_mgr_create(&g_url, &g_opts, g_streams,
                            g_lazy_streams ? 1 : g_streams,
                            g_max_stall, g_keepalive, g_max_retries, &st);
    if (g_mgr == NULL) {
        fprintf(stderr, "xrootdfs: async manager: %s\n", st.msg);
        brix_pool_destroy(g_pool);
        return brix_shellcode(&st);
    }

    aio_probe_ext(&st);

    fprintf(stderr,
            "xrootdfs: mounted %s:%d (meta-pool=%d, data-streams=%d, "
            "max-stall=%dms; network-resilient; ext: setattr=%d symlink=%d "
            "readlink=%d link=%d)\n",
            g_url.host, g_url.port, g_max_conns, g_streams, g_max_stall,
            g_ext_setattr, g_ext_symlink, g_ext_readlink, g_ext_link);

    rc = fuse_main(fuse_argc, fuse_argv, &xfs_ops, NULL);

    brix_mgr_destroy(g_mgr);
    brix_pool_destroy(g_pool);
    return rc;
}


/* Entry point for the default (async/resilient) driver. Invoked by the unified
 * xrootdfs front-end (apps/xrootdfs_main.c); see xrootdfs_drivers.h. */
int
xrootdfs_aio_main(int argc, char **argv)
{
    const char *endpoint = NULL;
    char       *fuse_argv[64];
    int         fuse_argc = 0;
    int         rc;

    /* Check --version / --help before the argc < 3 guard so they work standalone. */
    if (argc >= 2) {
        if (strcmp(argv[1], "--version") == 0) {
            printf("xrootdfs (BriX-Cache client) %s\n", brix_client_version());
            return 0;
        }
        if (strcmp(argv[1], "--help") == 0) { usage_fp(stdout); return 0; }
        if (strcmp(argv[1], "-h") == 0)     { usage();          return 0; }
    }

    if (argc < 3) {
        usage();
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);   /* a dropped peer must never kill the mount */
    memset(&g_opts, 0, sizeof(g_opts));
    g_opts.verify_host = 1;
    brix_crypto_init();

    fuse_argv[fuse_argc++] = argv[0];

    rc = aio_parse_args(argc, argv, fuse_argv, &fuse_argc, &endpoint);
    if (rc >= 0) {
        return rc;
    }

    if (endpoint == NULL || fuse_argc < 2) {
        usage();
        return 2;
    }
    fuse_argv[fuse_argc] = NULL;

    /* HTTP(S)/WebDAV read-only mount when the endpoint is a web URL. */
    if (brix_is_web_url(endpoint)) {
        return aio_web_mount(fuse_argc, fuse_argv, endpoint);
    }

    return aio_root_mount(fuse_argc, fuse_argv, endpoint);
}
