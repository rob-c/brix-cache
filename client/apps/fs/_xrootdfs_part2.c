/* _xrootdfs_part2.c — fragment 2 of xrootdfs.c (auto-split).
 * Do not compile directly; it is #included by xrootdfs.c. */
#ifndef _XROOTDFS_PART2_C_INC
#define _XROOTDFS_PART2_C_INC
#ifndef __XROOTDFS_C_COMPILED__
/*
 * xrootdfs.c - (kept) routing + shared helpers
 * Phase-38 split of xrootdfs.c; behavior-identical.
 */
#include "xrootdfs_internal.h"
#include "core/version.h"
#include "net/cpool.h"
#include "protocols/http/web_ka.h"

#include <unistd.h>     /* fork/setsid/pipe/dup2 — the daemonize helpers below */

brix_pool *g_pool;

/* Phase-86: pooled keep-alive WebDAV metadata (getattr/readdir) on web mounts.
 * NULL on root:// mounts. The template is copied into each slot by the vtable. */
brix_cpool         *g_web_pool;
static brix_webmeta g_web_tmpl;

#endif /* __XROOTDFS_C_COMPILED__ */

/* WHAT: mount an HTTP(S)/WebDAV endpoint (read-only, ranged GET).
 * WHY:  isolates the whole web transport bring-up (URL parse, bearer/TLS
 *       policy, reachability probe) from the root:// path in main.
 * HOW:  parse + validate the web URL, derive the export base, stat the
 *       export root up front (fail the mount early if unreachable/denied),
 *       then hand off to fuse_main. Returns the process exit code. */
static int
aio_web_mount(int fuse_argc, char **fuse_argv, size_t fuse_argv_cap,
              const char *endpoint)
{
    brix_status   st;
    brix_statinfo si;
    int           drc;

    /* Same rule as the root:// path: fork before the connection pool exists.
     * The web pool is synchronous today, but keeping both transports on one
     * ordering means a future background thread here cannot silently
     * reintroduce the hang. */
    drc = xfs_daemon_setup(&fuse_argc, fuse_argv, fuse_argv_cap);
    if (drc != 0) return drc;

    brix_status_clear(&st);
    if (brix_weburl_parse(endpoint, &g_weburl) != 0) {
        fprintf(stderr, "xrootdfs: bad web URL: %s\n", endpoint);
        xfs_daemon_ready(2);
        return 2;
    }
    if (g_weburl.is_s3) {
        fprintf(stderr, "xrootdfs: s3:// is not supported as a FUSE mount "
                        "(use http/https/dav/davs)\n");
        xfs_daemon_ready(2);
        return 2;
    }
    g_web = 1;
    if (g_bearer == NULL) {
        g_bearer = getenv("BEARER_TOKEN");
    }
    g_web_verify = g_opts.verify_host;
    g_web_ca = brix_resolve_ca_dir(g_opts.ca_dir);
    g_web_proxy = brix_web_proxy_pem(g_web_proxy_buf, sizeof(g_web_proxy_buf));
    /* export base = the URL path, trailing '/' trimmed; "/" → "" (verbatim). */
    aio_set_base(g_weburl.path);
    /* fail the mount up front if the export root is unreachable/denied. */
    if (brix_web_stat(&g_weburl, g_base[0] ? g_base : "/", g_bearer,
                      g_web_verify, g_web_ca, g_web_proxy, &si, &st) != 0) {
        fprintf(stderr, "xrootdfs: %s://%s:%d%s: %s\n",
                g_weburl.tls ? "https" : "http", g_weburl.host, g_weburl.port,
                g_weburl.path, st.msg);
        xfs_daemon_ready((unsigned char) brix_shellcode(&st));
        return brix_shellcode(&st);
    }
    fprintf(stderr,
            "xrootdfs: mounted %s:%d via %s%s (read-only WebDAV; "
            "verify=%d, auth=%s, meta-pool=%d)\n",
            g_weburl.host, g_weburl.port, g_weburl.tls ? "HTTPS" : "HTTP",
            g_base, g_web_verify, g_bearer ? "bearer" : "anon", g_max_conns);

    /* Pool the metadata path: the probe above validated endpoint/auth/TLS, so
     * slot-0's eager connect will not be the first failure point. */
    brix_webmeta_init(&g_web_tmpl, g_weburl.host, g_weburl.port, g_weburl.tls,
                      g_web_verify, g_web_ca, g_web_proxy, g_bearer,
                      0 /* → default 30 s */);
    brix_status_clear(&st);
    g_web_pool = brix_cpool_create(&WEB_VT, &g_web_tmpl, g_max_conns, &st);
    if (g_web_pool == NULL) {
        fprintf(stderr, "xrootdfs: web pool: %s\n", st.msg);
        xfs_daemon_ready((unsigned char) brix_shellcode(&st));
        return brix_shellcode(&st);
    }
    /* Success is signalled from xfs_init() once the mount is live. */
    int rc = fuse_main(fuse_argc, fuse_argv, &xfs_ops, NULL);
    brix_cpool_destroy(g_web_pool);
    g_web_pool = NULL;
    return rc;
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
 * HOW:  daemonize FIRST (so every thread lands in the daemon), then parse the
 *       endpoint, derive the export base, create the pool then the manager
 *       (destroyed in reverse order after fuse_main returns), probe extensions,
 *       run fuse. Returns the process exit code. */
static int
aio_root_mount(int fuse_argc, char **fuse_argv, size_t fuse_argv_cap,
               const char *endpoint)
{
    brix_status st;
    int         rc;

    /* Before g_pool/g_mgr — the manager's event-loop thread must be created on
     * the daemon side of the fork or every read() hangs. */
    rc = xfs_daemon_setup(&fuse_argc, fuse_argv, fuse_argv_cap);
    if (rc != 0) return rc;

    brix_status_clear(&st);
    if (brix_endpoint_parse(endpoint, &g_url, &st) != 0) {
        fprintf(stderr, "xrootdfs: %s\n", st.msg);
        xfs_daemon_ready(2);
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
        xfs_daemon_ready((unsigned char) brix_shellcode(&st));
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
        xfs_daemon_ready((unsigned char) brix_shellcode(&st));
        return brix_shellcode(&st);
    }

    aio_probe_ext(&st);

    fprintf(stderr,
            "xrootdfs: mounted %s:%d (meta-pool=%d, data-streams=%d, "
            "max-stall=%dms; network-resilient; ext: setattr=%d symlink=%d "
            "readlink=%d link=%d)\n",
            g_url.host, g_url.port, g_max_conns, g_streams, g_max_stall,
            g_ext_setattr, g_ext_symlink, g_ext_readlink, g_ext_link);

    /* Success is signalled from xfs_init() once the mount is live. */
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
        return aio_web_mount(fuse_argc, fuse_argv,
                             sizeof(fuse_argv) / sizeof(fuse_argv[0]), endpoint);
    }

    return aio_root_mount(fuse_argc, fuse_argv,
                          sizeof(fuse_argv) / sizeof(fuse_argv[0]), endpoint);
}
#endif /* _XROOTDFS_PART2_C_INC */
