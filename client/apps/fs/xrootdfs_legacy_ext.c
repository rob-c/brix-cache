/*
 * xrootdfs_legacy_ext.c - legacy synchronous FUSE driver: xattr ops + CLI/mount startup.
 * Phase-38 split of xrootdfs_legacy.c; behavior-identical. See xrootdfs_legacy_internal.h.
 */
#define FUSE_USE_VERSION 31

#include "brix.h"
#include "xrootdfs_legacy_internal.h"
#include "posix/posix_map.h"
#include "fs/iobuf.h"
#include "posix/fuse_ops.h"
#include "core/compat/crypto.h"
#include "protocols/root/protocol/open_flags.h"

#include <fuse3/fuse.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>

/* extended attributes (opt-in via --xattr) *//* FUSE uses "user.<x>" names; the server stores them under its own "user.U."
 * prefix, so we send the bare "<x>" and the module re-prefixes. Only the user.*
 * namespace is exposed. Returns "<x>" or NULL for a non-user.* name. */
static const char *
lg_xfs_xattr_to_fattr(const char *name)
{
    if (strncmp(name, "user.", 5) == 0 && name[5] != '\0') {
        return name + 5;
    }
    return NULL;
}

int
lg_xfs_getxattr(const char *path, const char *name, char *value, size_t size)
{
    brix_status st;
    brix_conn  *c;
    int         rc;
    size_t      vlen = 0;
    const char *fname;

    if (!lg_xattr) {
        return -ENOTSUP;
    }
    brix_status_clear(&st);

    /* Virtual read-only checksum xattr: user.XrdCks.<algo> → kXR_Qcksum hex. */
    if (strncmp(name, XFS_CKS_XATTR_PFX, sizeof(XFS_CKS_XATTR_PFX) - 1) == 0) {
        const char *algo = name + sizeof(XFS_CKS_XATTR_PFX) - 1;
        char        hex[160];

        if (algo[0] == '\0') {
            return -ENODATA;
        }
        c = brix_pool_checkout(lg_pool, &st);
        if (c == NULL) {
            return lg_xfs_err(&st);
        }
        rc = brix_query_cksum(c, path, algo, hex, sizeof(hex), &st);
        brix_pool_checkin(lg_pool, c, rc == 0 ? 1 : lg_xfs_conn_healthy(&st));
        if (rc != 0) {
            return lg_xfs_err(&st);
        }
        vlen = strlen(hex);
        if (size == 0) {
            return (int) vlen;
        }
        if (vlen > size) {
            return -ERANGE;
        }
        memcpy(value, hex, vlen);
        return (int) vlen;
    }

    fname = lg_xfs_xattr_to_fattr(name);
    if (fname == NULL) {
        return -ENODATA;
    }
    c = brix_pool_checkout(lg_pool, &st);
    if (c == NULL) {
        return lg_xfs_err(&st);
    }
    rc = brix_fattr_get(c, path, fname, value, size, &vlen, &st);
    brix_pool_checkin(lg_pool, c, rc == 0 ? 1 : lg_xfs_conn_healthy(&st));
    if (rc != 0) {
        return lg_xfs_err(&st);
    }
    if (size == 0) {
        return (int) vlen;
    }
    if (vlen > size) {
        return -ERANGE;
    }
    return (int) vlen;
}

int
lg_xfs_setxattr(const char *path, const char *name, const char *value,
             size_t size, int flags)
{
    brix_status st;
    brix_conn  *c;
    int         rc;
    const char *fname;

    if (!lg_xattr) {
        return -ENOTSUP;
    }
    if (strncmp(name, XFS_CKS_XATTR_PFX, sizeof(XFS_CKS_XATTR_PFX) - 1) == 0) {
        return -EACCES;   /* checksum xattr is read-only */
    }
    fname = lg_xfs_xattr_to_fattr(name);
    if (fname == NULL) {
        return -ENOTSUP;
    }
    brix_status_clear(&st);
    c = brix_pool_checkout(lg_pool, &st);
    if (c == NULL) {
        return lg_xfs_err(&st);
    }
    rc = brix_fattr_set(c, path, fname, value, size,
                        (flags & XATTR_CREATE) ? 1 : 0, &st);
    brix_pool_checkin(lg_pool, c, rc == 0 ? 1 : lg_xfs_conn_healthy(&st));
    return rc != 0 ? lg_xfs_err(&st) : 0;
}

int
lg_xfs_removexattr(const char *path, const char *name)
{
    brix_status st;
    brix_conn  *c;
    int         rc;
    const char *fname;

    if (!lg_xattr) {
        return -ENOTSUP;
    }
    if (strncmp(name, XFS_CKS_XATTR_PFX, sizeof(XFS_CKS_XATTR_PFX) - 1) == 0) {
        return -EACCES;
    }
    fname = lg_xfs_xattr_to_fattr(name);
    if (fname == NULL) {
        return -ENODATA;
    }
    brix_status_clear(&st);
    c = brix_pool_checkout(lg_pool, &st);
    if (c == NULL) {
        return lg_xfs_err(&st);
    }
    rc = brix_fattr_del(c, path, fname, &st);
    brix_pool_checkin(lg_pool, c, rc == 0 ? 1 : lg_xfs_conn_healthy(&st));
    return rc != 0 ? lg_xfs_err(&st) : 0;
}

int
lg_xfs_listxattr(const char *path, char *list, size_t size)
{
    brix_status st;
    brix_conn  *c;
    int         rc;
    char        raw[16384];     /* server list: "U.<x>\0U.<y>\0..." */
    size_t      rawlen = 0;

    if (!lg_xattr) {
        return -ENOTSUP;
    }
    brix_status_clear(&st);
    c = brix_pool_checkout(lg_pool, &st);
    if (c == NULL) {
        return lg_xfs_err(&st);
    }
    rc = brix_fattr_list(c, path, raw, sizeof(raw), &rawlen, &st);
    brix_pool_checkin(lg_pool, c, rc == 0 ? 1 : lg_xfs_conn_healthy(&st));
    if (rc != 0) {
        return lg_xfs_err(&st);
    }
    if (rawlen > sizeof(raw)) {
        rawlen = sizeof(raw);    /* truncated listing — clamp defensively */
    }
    /* Convert each server name "U.<x>" → the FUSE name "user.<x>". */
    return brix_fattr_listxattr_xlate(raw, rawlen, list, size);
}

/* main                                                                */

static void
lg_usage(void)
{
    fprintf(stderr,
        "usage: xrootdfs_legacy [conn-opts] root[s]://host[:port][/] <mountpoint> [fuse-opts]\n"
        "  (the simple synchronous driver; the default resilient driver is xrootdfs(1))\n"
        "  conn-opts:  --tls --notlsok --noverifyhost --auth <gsi|ztn|unix>\n"
        "              --max-conns N      metadata connection pool size (default 8)\n"
        "              --connect-timeout MS  connect+handshake+login cap (default 15000)\n"
        "              --io-timeout MS    steady-state read/write cap (default 30000)\n"
        "  cache-opts: --attr-timeout S   attr cache seconds (default 1.0)\n"
        "              --entry-timeout S  lookup cache seconds (default 1.0)\n"
        "              --kernel-cache     cache file data across opens (read-mostly)\n"
        "              --readahead N      per-handle read-ahead buffer bytes (default\n"
        "                                 1048576; 0 disables)\n"
        "              --writeback N      per-handle write-back buffer bytes (default\n"
        "                                 1048576; 0 disables)\n"
        "              --xattr            enable extended attributes (kXR_fattr) +\n"
        "                                 read-only user.XrdCks.<algo> checksum xattr\n"
        "  fuse-opts:  -f (foreground) -d (debug) -s (single-threaded) -o <opt>\n"
        "              e.g. -o ro -o allow_other  (forwarded to libfuse)\n"
        "  notes: utimens/chown are accepted but no-op (XRootD has no set-time/owner\n"
        "         wire op); symlinks are unsupported.\n");
}

/* WHAT: handle a no-value dash-option (a bare flag), updating the driver's
 *       file-scope option globals in place.
 * WHY:  splitting the flag group from the value group (mirrors the async driver's
 *       aio_opt_novalue) keeps each option handler under the complexity gate; the
 *       option state already lives in file-scope globals, so this maps onto them
 *       directly (no new state introduced).
 * HOW:  returns 1 if `a` was a recognised flag, 0 otherwise. */
static int
lg_xfs_opt_novalue(const char *a)
{
    if (strcmp(a, "--tls") == 0)          { lg_opts.want_tls = 1;    return 1; }
    if (strcmp(a, "--notlsok") == 0)      { lg_opts.notlsok = 1;     return 1; }
    if (strcmp(a, "--noverifyhost") == 0) { lg_opts.verify_host = 0; return 1; }
    if (strcmp(a, "--kernel-cache") == 0) { lg_kernel_cache = 1;     return 1; }
    if (strcmp(a, "--xattr") == 0)        { lg_xattr = 1;            return 1; }
    return 0;
}

/* WHAT: handle a value-taking dash-option `a` with its already-extracted value
 *       word `v`, updating the driver's file-scope option globals in place.
 * WHY:  the value group split from the flag group (mirrors aio_opt_conn_value /
 *       aio_opt_cache_value) keeps this handler under the complexity gate.
 * HOW:  the caller only calls this when a next word exists, so `v` is always
 *       valid (a trailing value option therefore falls through to libfuse exactly
 *       as before). Returns 1 if `a` was a recognised value option, 0 otherwise. */
static int
lg_xfs_opt_value(const char *a, char *v)
{
    if (strcmp(a, "--auth") == 0) { lg_opts.auth_force = v; return 1; }
    if (strcmp(a, "--max-conns") == 0) {
        lg_max_conns = atoi(v);
        if (lg_max_conns < 1) { lg_max_conns = 1; }
        return 1;
    }
    if (strcmp(a, "--attr-timeout") == 0)  { lg_attr_timeout = atof(v);  return 1; }
    if (strcmp(a, "--entry-timeout") == 0) { lg_entry_timeout = atof(v); return 1; }
    if (strcmp(a, "--readahead") == 0) {
        long n = atol(v);
        lg_readahead = (n > 0) ? (size_t) n : 0;
        return 1;
    }
    if (strcmp(a, "--writeback") == 0) {
        long n = atol(v);
        lg_writeback = (n > 0) ? (size_t) n : 0;
        return 1;
    }
    if (strcmp(a, "--connect-timeout") == 0) { brix_tmo_set_connect_ms(atoi(v)); return 1; }
    if (strcmp(a, "--io-timeout") == 0)      { brix_tmo_set_io_ms(atoi(v));      return 1; }
    return 0;
}

/* WHAT: split the command line into our options, the endpoint, and the libfuse
 *       passthrough vector.
 * WHY:  our known options are honored ANYWHERE on the line (before OR after the
 *       endpoint); unknown dash-args fall through to libfuse (so -f/-d/-s/-o still
 *       work); the first bare word is the endpoint, the next the mountpoint.
 * HOW:  each dash-arg is offered to the flag group then (when a next word exists)
 *       the value group, matching the original inline argc guards; -h/--help print
 *       usage and stop. Returns -1 to proceed with the mount, or a process exit
 *       code (0 for -h/--help encountered inline). */
static int
lg_xfs_parse_args(int argc, char **argv, char **fuse_argv, int *fuse_argc,
               const char **endpoint)
{
    int i;

    for (i = 1; i < argc; i++) {
        char *a = argv[i];

        if (a[0] == '-') {
            if (lg_xfs_opt_novalue(a)) { continue; }
            if (i + 1 < argc && lg_xfs_opt_value(a, argv[i + 1])) { i++; continue; }
            if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
                lg_usage();
                return 0;
            }
            if (*fuse_argc < 61) { fuse_argv[(*fuse_argc)++] = argv[i]; }  /* fuse opt */
        } else if (*endpoint == NULL) {
            *endpoint = a;   /* first non-option = the root:// URL */
        } else if (*fuse_argc < 61) {
            fuse_argv[(*fuse_argc)++] = argv[i];   /* mountpoint + fuse flags */
        }
    }
    return -1;
}

/* WHAT: parse the endpoint, bring up the metadata connection pool, run the FUSE
 *       mount, and tear the pool down afterwards.
 * WHY:  isolates the mount bring-up + teardown ordering from the entry point so
 *       main() stays a short arg-parse → mount sequence.
 * HOW:  the pool connects one conn eagerly, so a bad endpoint/auth fails here
 *       (before fuse_main); the pool is destroyed after fuse_main returns.
 *       Returns the process exit code. */
static int
lg_xfs_root_mount(int fuse_argc, char **fuse_argv, const char *endpoint)
{
    brix_status st;
    int         rc;

    brix_status_clear(&st);
    if (brix_endpoint_parse(endpoint, &lg_url, &st) != 0) {
        fprintf(stderr, "xrootdfs: %s\n", st.msg);
        return 2;
    }
    /* The pool connects one conn eagerly, so a bad endpoint/auth fails here. */
    lg_pool = brix_pool_create(&lg_url, &lg_opts, lg_max_conns, &st);
    if (lg_pool == NULL) {
        fprintf(stderr, "xrootdfs: connect %s:%d: %s\n",
                lg_url.host, lg_url.port, st.msg);
        return brix_shellcode(&st);
    }
    fprintf(stderr, "xrootdfs: mounted %s:%d (pool=%d, multi-threaded)\n",
            lg_url.host, lg_url.port, lg_max_conns);

    rc = fuse_main(fuse_argc, fuse_argv, &lg_xfs_ops, NULL);

    brix_pool_destroy(lg_pool);
    return rc;
}

/* Entry point for the synchronous fallback driver. Invoked by the unified
 * xrootdfs front-end (apps/xrootdfs_main.c) when --legacy is given. */
int
xrootdfs_legacy_main(int argc, char **argv)
{
    const char *endpoint = NULL;
    char       *fuse_argv[64];
    int         fuse_argc = 0;
    int         rc;

    if (argc < 3) {
        lg_usage();
        return 2;
    }
    memset(&lg_opts, 0, sizeof(lg_opts));
    lg_opts.verify_host = 1;
    brix_crypto_init();

    fuse_argv[fuse_argc++] = argv[0];
    /* This entry point only runs in --legacy mode (the binary is `xrootdfs`), so
     * tag the kernel mount subtype explicitly: mounts then show as
     * fuse.xrootdfs_legacy and `xrd mount` can still tell the two apart. */
    fuse_argv[fuse_argc++] = (char *) "-osubtype=xrootdfs_legacy";

    rc = lg_xfs_parse_args(argc, argv, fuse_argv, &fuse_argc, &endpoint);
    if (rc >= 0) {
        return rc;
    }

    if (endpoint == NULL || fuse_argc < 2) {
        lg_usage();
        return 2;
    }
    fuse_argv[fuse_argc] = NULL;

    return lg_xfs_root_mount(fuse_argc, fuse_argv, endpoint);
}
