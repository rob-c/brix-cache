/*
 * xrootdfs.c - (kept) routing + shared helpers
 * Phase-38 split of xrootdfs.c; behavior-identical.
 */
#include "xrootdfs_internal.h"

xrdc_pool *g_pool;

xrdc_url   g_url;

xrdc_opts  g_opts;

int        g_max_conns = 8;       

int          g_web = 0;

xrdc_weburl  g_weburl;

xrdc_mgr  *g_mgr;

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
 * compression on every read open (transparently inflated by xrdc_mfile).  Empty
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
xfs_err(const xrdc_status *st)
{
    return xrdc_fuse_errno(st);
}


int
xfs_conn_healthy(const xrdc_status *st)
{
    return xrdc_fuse_conn_healthy(st);
}


int
xfs_meta(xrdc_fuse_op_fn fn, void *ctx, xrdc_status *st)
{
    return xrdc_fuse_run(g_pool, g_max_retries, fn, ctx, st);
}


void
xfs_fill_stat(const xrdc_statinfo *si, struct stat *stbuf)
{
    /* allow_symlink=1: the async getattr uses lstat, so kXR_other → S_IFLNK. */
    xrdc_statinfo_to_stat(si, 1, stbuf);
}


int
xfs_link(const char *from, const char *to)
{
    if (g_web) return -EROFS;
    if (!g_ext_link) {
        return -ENOTSUP;
    }
    xrdc_status st; xrdc_status_clear(&st);
    char fbuf[XRDC_PATH_MAX], tbuf[XRDC_PATH_MAX];
    struct xrdc_fuse_ctx_link2 a = { srv_path(from, fbuf, sizeof(fbuf)),
                           srv_path(to, tbuf, sizeof(tbuf)) };
    return xfs_meta(xrdc_fuse_op_link, &a, &st);
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

void
usage(void)
{
    fprintf(stderr,
        "usage: xrootdfs [opts] <endpoint> <mountpoint> [fuse-opts]\n"
        "  endpoint:   root[s]://host[:port][/base]      (binary XRootD; read-write)\n"
        "              http|https|dav|davs://host[:port][/base]\n"
        "                                (WebDAV/XrdHttp; READ-ONLY, ranged GET)\n"
        "              a /base path component roots the mount at that subtree\n"
        "  web-opts:   --token TOK       bearer token for http(s)  ($BEARER_TOKEN)\n"
        "              --noverifyhost    skip TLS server-cert check (self-signed beds)\n"
        "  conn-opts:  --tls --notlsok --noverifyhost --auth <gsi|ztn|unix>\n"
        "              --max-conns N    metadata connection pool size (default 8)\n"
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
        "         no-ops (no XRootD wire op); symlinks are unsupported.\n");
}


/* Entry point for the default (async/resilient) driver. Invoked by the unified
 * xrootdfs front-end (apps/xrootdfs_main.c); see xrootdfs_drivers.h. */
int
xrootdfs_aio_main(int argc, char **argv)
{
    xrdc_status st;
    const char *endpoint = NULL;
    char       *fuse_argv[64];
    int         fuse_argc = 0;
    int         i, rc;

    if (argc < 3) {
        usage();
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);   /* a dropped peer must never kill the mount */
    memset(&g_opts, 0, sizeof(g_opts));
    g_opts.verify_host = 1;
    xrootd_crypto_init();

    fuse_argv[fuse_argc++] = argv[0];

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        /* Parse our known options ANYWHERE on the line (before OR after the
         * endpoint), so a resilience flag placed after the URL is honored rather
         * than silently leaking to libfuse. Unknown dash-args fall through to the
         * fuse passthrough (so -f/-d/-s/-o still work); the first bare word is the
         * endpoint, the next the mountpoint. */
        if (a[0] == '-') {
            if (strcmp(a, "--tls") == 0)               { g_opts.want_tls = 1; }
            else if (strcmp(a, "--notlsok") == 0)      { g_opts.notlsok = 1; }
            else if (strcmp(a, "--noverifyhost") == 0) { g_opts.verify_host = 0; }
            else if (strcmp(a, "--auth") == 0 && i + 1 < argc) { g_opts.auth_force = argv[++i]; }
            else if (strcmp(a, "--max-conns") == 0 && i + 1 < argc) {
                g_max_conns = atoi(argv[++i]);
                if (g_max_conns < 1) { g_max_conns = 1; }
            }
            else if (strcmp(a, "--streams") == 0 && i + 1 < argc) {
                g_streams = atoi(argv[++i]);
                if (g_streams < 1) { g_streams = 1; }
            }
            else if (strcmp(a, "--lazy-streams") == 0) { g_lazy_streams = 1; }
            else if (strcmp(a, "--max-stall") == 0 && i + 1 < argc) {
                g_max_stall = atoi(argv[++i]);
                if (g_max_stall < 0) { g_max_stall = 0; }
            }
            else if (strcmp(a, "--keepalive") == 0 && i + 1 < argc) {
                g_keepalive = atoi(argv[++i]);
                if (g_keepalive < 0) { g_keepalive = 0; }
            }
            else if (strcmp(a, "--max-retries") == 0 && i + 1 < argc) {
                g_max_retries = atoi(argv[++i]);
                if (g_max_retries < 0) { g_max_retries = 0; }
            }
            else if (strcmp(a, "--connect-timeout") == 0 && i + 1 < argc) {
                xrdc_tmo_set_connect_ms(atoi(argv[++i]));
            }
            else if (strcmp(a, "--io-timeout") == 0 && i + 1 < argc) {
                xrdc_tmo_set_io_ms(atoi(argv[++i]));
            }
            else if (strcmp(a, "--attr-timeout") == 0 && i + 1 < argc) {
                g_attr_timeout = atof(argv[++i]);
            }
            else if (strcmp(a, "--entry-timeout") == 0 && i + 1 < argc) {
                g_entry_timeout = atof(argv[++i]);
            }
            else if (strcmp(a, "--kernel-cache") == 0) { g_kernel_cache = 1; }
            else if (strcmp(a, "--readahead") == 0 && i + 1 < argc) {
                long v = atol(argv[++i]);
                g_readahead = (v > 0) ? (size_t) v : 0;
            }
            else if (strcmp(a, "--writeback") == 0 && i + 1 < argc) {
                long v = atol(argv[++i]);
                g_writeback = (v > 0) ? (size_t) v : 0;
            }
            else if (strcmp(a, "--xattr") == 0) { g_xattr = 1; }
            else if (strcmp(a, "--compress") == 0 && i + 1 < argc) {
                snprintf(g_compress, sizeof(g_compress), "%s", argv[++i]);
            }
            else if (strcmp(a, "--token") == 0 && i + 1 < argc) { g_bearer = argv[++i]; }
            else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { usage(); return 0; }
            else if (fuse_argc < 61) { fuse_argv[fuse_argc++] = argv[i]; }  /* fuse opt */
        } else if (endpoint == NULL) {
            endpoint = a;
        } else if (fuse_argc < 61) {
            fuse_argv[fuse_argc++] = argv[i];
        }
    }

    if (endpoint == NULL || fuse_argc < 2) {
        usage();
        return 2;
    }
    fuse_argv[fuse_argc] = NULL;

    xrdc_status_clear(&st);

    /* HTTP(S)/WebDAV read-only mount when the endpoint is a web URL. */
    if (xrdc_is_web_url(endpoint)) {
        xrdc_statinfo si;
        size_t        bl;
        if (xrdc_weburl_parse(endpoint, &g_weburl) != 0) {
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
        g_web_ca = xrdc_resolve_ca_dir(g_opts.ca_dir);
        /* export base = the URL path, trailing '/' trimmed; "/" → "" (verbatim). */
        snprintf(g_base, sizeof(g_base), "%s", g_weburl.path);
        bl = strlen(g_base);
        while (bl > 0 && g_base[bl - 1] == '/') {
            g_base[--bl] = '\0';
        }
        /* fail the mount up front if the export root is unreachable/denied. */
        if (xrdc_web_stat(&g_weburl, g_base[0] ? g_base : "/", g_bearer,
                          g_web_verify, g_web_ca, &si, &st) != 0) {
            fprintf(stderr, "xrootdfs: %s://%s:%d%s: %s\n",
                    g_weburl.tls ? "https" : "http", g_weburl.host, g_weburl.port,
                    g_weburl.path, st.msg);
            return xrdc_shellcode(&st);
        }
        fprintf(stderr,
                "xrootdfs: mounted %s:%d via %s%s (read-only WebDAV; "
                "verify=%d, auth=%s)\n",
                g_weburl.host, g_weburl.port, g_weburl.tls ? "HTTPS" : "HTTP",
                g_base, g_web_verify, g_bearer ? "bearer" : "anon");
        rc = fuse_main(fuse_argc, fuse_argv, &xfs_ops, NULL);
        return rc;
    }

    if (xrdc_endpoint_parse(endpoint, &g_url, &st) != 0) {
        fprintf(stderr, "xrootdfs: %s\n", st.msg);
        return 2;
    }

    /* Export base = the URL path component (root://host/data → "/data"), so the
     * mount roots at that subtree.  Trailing '/' trimmed; a bare host (path "/" or
     * empty) → verbatim FUSE paths.  Shared with the web transport via srv_path(). */
    {
        size_t bl;
        snprintf(g_base, sizeof(g_base), "%s",
                 (g_url.path[0] == '/') ? g_url.path : "");
        bl = strlen(g_base);
        while (bl > 0 && g_base[bl - 1] == '/') {
            g_base[--bl] = '\0';
        }
    }

    g_pool = xrdc_pool_create(&g_url, &g_opts, g_max_conns, &st);
    if (g_pool == NULL) {
        fprintf(stderr, "xrootdfs: connect %s:%d: %s\n",
                g_url.host, g_url.port, st.msg);
        return xrdc_shellcode(&st);
    }
    /* Default: connect all data streams up front (in parallel — ~1×RTT mount).
     * --lazy-streams trades first-read warm-up for the lowest possible mount
     * latency by bringing up just one stream now and the rest on demand. */
    g_mgr = xrdc_mgr_create(&g_url, &g_opts, g_streams,
                            g_lazy_streams ? 1 : g_streams,
                            g_max_stall, g_keepalive, g_max_retries, &st);
    if (g_mgr == NULL) {
        fprintf(stderr, "xrootdfs: async manager: %s\n", st.msg);
        xrdc_pool_destroy(g_pool);
        return xrdc_shellcode(&st);
    }

    /* Probe the server's vendor POSIX extensions (kXR_Qconfig "xrdfs.ext") once;
     * utimens/chown/symlink/readlink/link adapt to what is advertised. */
    {
        xrdc_conn  *pc = xrdc_pool_checkout(g_pool, &st);
        if (pc != NULL) {
            int ok = (xrdc_ext_probe(pc, &g_ext_setattr, &g_ext_symlink,
                                     &g_ext_readlink, &g_ext_link, &st) == 0);
            xrdc_pool_checkin(g_pool, pc, ok ? 1 : xfs_conn_healthy(&st));
        }
    }

    fprintf(stderr,
            "xrootdfs: mounted %s:%d (meta-pool=%d, data-streams=%d, "
            "max-stall=%dms; network-resilient; ext: setattr=%d symlink=%d "
            "readlink=%d link=%d)\n",
            g_url.host, g_url.port, g_max_conns, g_streams, g_max_stall,
            g_ext_setattr, g_ext_symlink, g_ext_readlink, g_ext_link);

    rc = fuse_main(fuse_argc, fuse_argv, &xfs_ops, NULL);

    xrdc_mgr_destroy(g_mgr);
    xrdc_pool_destroy(g_pool);
    return rc;
}
