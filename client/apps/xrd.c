/*
 * xrd.c — the unified, git-style front-end for the native XRootD toolkit.
 *
 * WHAT: `xrd <command> [args]` dispatches to the right tool so users learn ONE
 *       command: `xrd cp`, `xrd get/put`, `xrd ls/stat/du/tree/find/...`, `xrd diag`.
 * WHY:  A "swiss-army-knife from the command line" wants a single entry point. The
 *       underlying tools (xrdcp/xrdfs/xrddiag) already resolve ~/.xrdrc aliases, so
 *       this is a thin, dependency-free dispatcher — and the natural home for future
 *       cross-tool verbs (xrd doctor, xrd login).
 * HOW:  Filesystem verbs map to `xrdfs <endpoint> <verb> [args]` (xrdfs's native
 *       "endpoint first" order); cp/get/put map to xrdcp; diag maps to xrddiag. The
 *       target binary is found next to argv[0] (so an in-tree ./xrd finds ./xrdfs),
 *       falling back to $PATH.
 *
 * Clean-room; exec-only — no libxrdc symbols needed.
 */
#include "xrdc.h"   /* alias resolution + URL parse, to split endpoint/path for xrdfs */
#include "compat/crypto.h"  /* xrootd_crypto_init for token/cert explain (doctor/login) */

#include <ctype.h>      /* mountinfo octal-escape decode */
#include <errno.h>
#include <fcntl.h>      /* doctor rw battery: tmpfile fds for checksum/transfer */
#include <libgen.h>
#include <stdarg.h>     /* doctor battery: variadic check-result detail */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>   /* unmount: fork + waitpid the fusermount helper */
#include <unistd.h>

/* xrdfs subcommands: `xrd <verb> <endpoint> [args]` -> `xrdfs <endpoint> <verb> [args]`. */
static const char *FS_VERBS[] = {
    "ls", "stat", "mkdir", "rm", "rmdir", "mv", "chmod", "touch", "ln", "readlink",
    "truncate", "cat", "head", "tail", "wc", "grep", "hexdump", "dd", "upload",
    "download", "cmp", "cksum", "xattr", "readv", "writev", "du", "df", "tree",
    "find", "locate", "query", "statvfs", "prepare", "stage", "evict", "explain", NULL
};

static int
is_fs_verb(const char *s)
{
    int i;
    for (i = 0; FS_VERBS[i] != NULL; i++) {
        if (strcmp(FS_VERBS[i], s) == 0) { return 1; }
    }
    return 0;
}

static void
usage(void)
{
    fprintf(stderr,
        "usage: xrd <command> [args]\n"
        "  the unified XRootD/WLCG toolkit front-end (~/.xrdrc aliases work everywhere)\n\n"
        "  transfer:\n"
        "    xrd cp [opts] <src>... <dst>     copy (-> xrdcp; supports -r -j --sync --from ...)\n"
        "    xrd get <url> [localdst]         download a file (default dst: cwd)\n"
        "    xrd put <localfile> <url>        upload a file\n"
        "    xrd upload   [rate=R] <localfile|-> <url>  rate-limited upload (bs=/-f)\n"
        "    xrd download [rate=R] <url> [localdst|-]   rate-limited download (bs=/-f)\n"
        "    xrd sync <srcdir> <dstdir>       recursive mirror (-> xrdcp -r --sync)\n\n"
        "  filesystem (-> xrdfs <endpoint> <verb>):\n"
        "    xrd ls|stat|du|df|tree|find|mkdir|rm|rmdir|mv|truncate <endpoint> [args]\n"
        "    xrd cat|head|tail|wc|grep|hexdump|dd|cmp|cksum|xattr <endpoint> [args]\n"
        "    xrd touch|chmod|ln|readlink|stage|evict <endpoint> [args]\n"
        "    xrd locate|query|statvfs|prepare|explain <endpoint> [args]\n"
        "      (ls/du/df -h; head/tail -c/-n; tail -f follows; grep -i/-n; ln [-s];\n"
        "       dd bs=/skip=/count=/rate=; upload bs=/rate=/-f)\n\n"
        "  diagnostics:\n"
        "    xrd diag <subcommand> [args]      (-> xrddiag: check/bench/watch/srr/tape/...)\n"
        "    xrd ping [-c N] <endpoint>       liveness + RTT probe\n"
        "    xrd certinfo <endpoint>          server host-cert validity + expiry\n"
        "    xrd clockskew <endpoint>         client<->server clock offset (token/GSI sanity)\n"
        "    xrd whoami <endpoint>            negotiated auth + presented identity\n"
        "    xrd caps <endpoint>              server role + kXR_Qconfig capability matrix\n"
        "    xrd replicas <url>               cluster holder + space map (-> xrdmapc)\n"
        "    xrd doctor [endpoint] [--rw] [--also URL]... [--insecure] [--json]\n"
        "       full endpoint health: creds/TLS/cert/clock/caps + a functional method\n"
        "       battery (--rw adds write tests; --also adds protocols; --json dumps all)\n"
        "    xrd login [--oidc-account N] [--read]  acquire/refresh a token and/or GSI proxy\n\n"
        "  FUSE mount (needs the libfuse3-built driver):\n"
        "    xrd mount [--legacy] <endpoint> <mountpoint> [fuse-opts]   mount via xrootdfs (--legacy: simple driver)\n"
        "    xrd mount | xrd mounts            list active XRootD FUSE mounts\n"
        "    xrd unmount [-z] <mountpoint>     unmount (fusermount3/fusermount/umount)\n\n"
        "    xrd version | help\n");
}

/* Exec `tool` (found next to this binary, else via PATH) with argv. Does not return
 * on success. */
static void
exec_tool(const char *tool, char **argv)
{
    char    self[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);

    if (n > 0) {
        char  dirbuf[PATH_MAX];
        char  path[PATH_MAX];
        char *dir;
        self[n] = '\0';
        snprintf(dirbuf, sizeof(dirbuf), "%s", self);
        dir = dirname(dirbuf);
        if ((size_t) snprintf(path, sizeof(path), "%s/%s", dir, tool) < sizeof(path)
            && access(path, X_OK) == 0) {
            execv(path, argv);
        }
    }
    execvp(tool, argv);   /* fall back to $PATH */
    fprintf(stderr, "xrd: cannot run %s: %s\n", tool, strerror(errno));
    _exit(127);
}

/* Map an fs-verb path-position arg to what xrdfs expects: a root:// URL (or an alias
 * resolving to one) becomes its path component (host/port must match `ehost:eport`);
 * anything else (a bare path or a flag) is passed through. Returns a malloc'd string,
 * or NULL with *mismatch=1 if the arg targets a different endpoint. */
static char *
map_fs_arg(const char *arg, const char *ehost, int eport, int *mismatch)
{
    char        resolved[XRDC_PATH_MAX];
    xrdc_url    u;
    xrdc_status st;

    *mismatch = 0;
    xrdc_status_clear(&st);
    xrdc_alias_resolve(arg, resolved, sizeof(resolved));
    if (xrdc_url_parse(resolved, &u, &st) == 0
        && (u.scheme == XRDC_SCHEME_ROOT || u.scheme == XRDC_SCHEME_ROOTS)) {
        if (strcmp(u.host, ehost) != 0 || u.port != eport) {
            *mismatch = 1;
            return NULL;
        }
        return strdup(u.path[0] != '\0' ? u.path : "/");
    }
    return strdup(arg);   /* a bare path or a flag — verbatim */
}

/* ---- endpoint diagnostic report (shared by the verbs below + doctor) ---- */

#define XRD_CAPS_MAX 16

typedef struct { char key[24]; char val[256]; } xrd_cap_kv;

/* One endpoint's diagnostic facts (filled piecemeal by the gatherers; doctor fills
 * all of it, the standalone verbs fill their own slice). */
typedef struct {
    char           host[256];
    int            port;
    int            connected;
    char           err[XRDC_MSG_MAX];   /* holds a full xrdc_status message */
    int            tls_active;
    const char    *tls_ver;
    const char    *tls_cipher;
    uint32_t       server_flags;
    char           auth[40];        /* negotiated auth ("anonymous" if none) */
    char           sec_list[256];
    xrdc_cert_info cert;
    xrd_cap_kv     caps[XRD_CAPS_MAX];
    int            ncaps;
    int            clock_have;
    const char    *clock_method;
    long           server_epoch;
    double         offset_s;
    double         rtt_ms;
} xrd_probe;

/* Defined further down (with the diagnostic verbs); forward-declared so doctor can
 * compose them. */
static const char *xrd_role_str(uint32_t flags);
static void        xrd_fmt_epoch(long e, char *buf, size_t sz);
static double      xrd_fabs(double x);
static void        xrd_probe_caps(xrdc_conn *c, xrd_probe *p);
static int         xrd_measure_clock_skew(const char *endpoint, const xrdc_opts *o,
                                          xrd_probe *p, char *err, size_t errsz);

/* ---- functional method battery (doctor --rw / multi-protocol) ----------- */

#define XRD_MAX_CHECKS 40

typedef struct {
    char name[40];
    int  ok;            /* 1 pass, 0 fail */
    int  skipped;       /* 1 = not run (n/a or rw not requested) */
    char detail[200];
} xrd_check;

/* One protocol face's functional results. */
typedef struct {
    char      endpoint[320];
    char      protocol[12];          /* "root" / "https" / "s3" / ... */
    int       reachable;
    char      err[XRDC_MSG_MAX];
    xrd_check checks[XRD_MAX_CHECKS];
    int       n, npass, nfail, nskip;
} xrd_battery;

/* Append a result. status: >0 pass, 0 fail, <0 skipped. */
static void
bat_add(xrd_battery *b, const char *name, int status, const char *fmt, ...)
{
    xrd_check *c;
    va_list    ap;
    if (b->n >= XRD_MAX_CHECKS) { return; }
    c = &b->checks[b->n++];
    snprintf(c->name, sizeof(c->name), "%s", name);
    c->ok      = (status > 0);
    c->skipped = (status < 0);
    va_start(ap, fmt);
    vsnprintf(c->detail, sizeof(c->detail), fmt, ap);
    va_end(ap);
    if (status < 0)      { b->nskip++; }
    else if (status > 0) { b->npass++; }
    else                 { b->nfail++; }
}

/* Fill `buf` (size n) with a deterministic, position-dependent pattern. */
static void
fill_pattern(uint8_t *buf, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) { buf[i] = (uint8_t) ((i * 7u + 3u) & 0xff); }
}

/* Write `buf` to an anonymous tmpfile and return its fd (rewound), or -1. */
static int
tmpfile_with(const uint8_t *buf, size_t n)
{
    FILE *f = tmpfile();
    int   fd;
    if (f == NULL) { return -1; }
    if (n > 0 && fwrite(buf, 1, n, f) != n) { fclose(f); return -1; }
    fflush(f);
    fd = dup(fileno(f));
    fclose(f);
    if (fd >= 0) { lseek(fd, 0, SEEK_SET); }
    return fd;
}

/* The native root:// functional battery: always-safe reads, then (do_write) a full
 * write/read/verify/checksum/metadata cycle under a temp dir that is cleaned up. */
static void
battery_root(const xrdc_url *u, const xrdc_opts *o, int do_write, xrd_battery *b)
{
    xrdc_conn     c;
    xrdc_status   st;
    xrdc_statinfo si;
    xrdc_dirent  *ents = NULL;
    size_t        nents = 0;
    char          reply[1024];
    int           ext_sa = 0, ext_sl = 0, ext_rl = 0, ext_ln = 0;

    snprintf(b->protocol, sizeof(b->protocol), "root");
    xrdc_status_clear(&st);
    if (xrdc_connect(&c, u, o, &st) != 0) {
        snprintf(b->err, sizeof(b->err), "%s", st.msg);
        return;
    }
    b->reachable = 1;

    /* ---- read-only methods ---- */
    xrdc_status_clear(&st);
    if (xrdc_stat(&c, "/", &si, &st) == 0) { bat_add(b, "stat", 1, "/ flags=0x%x", si.flags); }
    else { bat_add(b, "stat", 0, "%s", st.msg); }

    xrdc_status_clear(&st);
    if (xrdc_dirlist(&c, "/", 0, &ents, &nents, &st) == 0) {
        bat_add(b, "dirlist", 1, "%zu entries", nents);
        free(ents); ents = NULL;
    } else { bat_add(b, "dirlist", 0, "%s", st.msg); }

    xrdc_status_clear(&st);
    if (xrdc_statvfs(&c, "/", reply, sizeof(reply), &st) == 0) { bat_add(b, "statvfs", 1, "ok"); }
    else { bat_add(b, "statvfs", 0, "%s", st.msg); }

    xrdc_status_clear(&st);
    if (xrdc_query(&c, kXR_Qconfig, "chksum", reply, sizeof(reply), &st) == 0) {
        char *nl = strchr(reply, '\n'); if (nl) { *nl = '\0'; }
        bat_add(b, "query-config", 1, "%s", reply);
    } else { bat_add(b, "query-config", 0, "%s", st.msg); }

    /* negative: a traversal path must not resolve outside the export */
    xrdc_status_clear(&st);
    {
        int rc = xrdc_stat(&c, "/../../../../etc/passwd", &si, &st);
        bat_add(b, "path-confinement", rc != 0 ? 1 : 0,
                rc != 0 ? "escape rejected" : "LEAKED /etc/passwd");
    }

    (void) xrdc_ext_probe(&c, &ext_sa, &ext_sl, &ext_rl, &ext_ln, &st);

    if (!do_write) {
        bat_add(b, "write-suite", -1, "skipped (pass --rw to run write tests)");
        xrdc_close(&c);
        return;
    }

    /* ---- read/write cycle under a temp dir ---- */
    {
        char     dir[128], file[200], file2[200];
        uint8_t  payload[8192], rbuf[8192];
        char     srvck[160], locck[160];
        long     pid = (long) getpid();
        int      ok, rc, sym_left = 0;

        snprintf(dir,   sizeof(dir),   "/.xrd_doctor_%ld", pid);
        snprintf(file,  sizeof(file),  "%s/probe.bin", dir);
        snprintf(file2, sizeof(file2), "%s/probe.moved.bin", dir);
        fill_pattern(payload, sizeof(payload));

        xrdc_status_clear(&st);
        rc = xrdc_mkdir(&c, dir, 0755, 1, &st);
        bat_add(b, "mkdir", rc == 0 ? 1 : 0, "%s", rc == 0 ? dir : st.msg);

        /* write */
        {
            xrdc_file f;
            ok = 0;
            xrdc_status_clear(&st);
            if (xrdc_file_open_write(&c, file, 1, 0, &f, &st) == 0) {
                ok = (xrdc_file_write(&c, &f, 0, payload, sizeof(payload), &st) == 0);
                xrdc_file_close(&c, &f, &st);
            }
            bat_add(b, "write", ok ? 1 : 0, ok ? "%zu bytes" : "%s",
                    ok ? sizeof(payload) : (size_t) 0, ok ? "" : st.msg);
        }
        /* read-back + byte-exact verify */
        {
            xrdc_file f;
            ssize_t   got = -1;
            int       match = 0;
            xrdc_status_clear(&st);
            if (xrdc_file_open_read(&c, file, &f, &st) == 0) {
                got = xrdc_file_read(&c, &f, 0, rbuf, sizeof(rbuf), &st);
                xrdc_file_close(&c, &f, &st);
                match = (got == (ssize_t) sizeof(payload)
                         && memcmp(rbuf, payload, sizeof(payload)) == 0);
            }
            bat_add(b, "read-verify", match ? 1 : 0,
                    match ? "byte-exact %zd bytes" : "mismatch/short (%s)",
                    match ? got : 0, match ? "" : st.msg);
        }
        /* readv (two segments) */
        {
            xrdc_file      f;
            xrdc_readv_seg segs[2];
            int            match = 0;
            uint8_t        s0[64], s1[128];
            segs[0].offset = 0;    segs[0].len = sizeof(s0); segs[0].buf = s0; segs[0].got = 0;
            segs[1].offset = 1000; segs[1].len = sizeof(s1); segs[1].buf = s1; segs[1].got = 0;
            xrdc_status_clear(&st);
            if (xrdc_file_open_read(&c, file, &f, &st) == 0) {
                if (xrdc_file_readv(&c, &f, segs, 2, &st) >= 0) {
                    match = (memcmp(s0, payload, sizeof(s0)) == 0
                             && memcmp(s1, payload + 1000, sizeof(s1)) == 0);
                }
                xrdc_file_close(&c, &f, &st);
            }
            bat_add(b, "readv", match ? 1 : 0, match ? "2 segs verified" : "%s", st.msg);
        }
        /* checksum: server adler32 vs locally computed adler32 of the payload */
        {
            int fd = tmpfile_with(payload, sizeof(payload));
            int verified = 0;
            xrdc_status_clear(&st);
            if (fd >= 0
                && xrdc_cksum_fd(fd, XRDC_CK_ADLER32, locck, sizeof(locck), &st) == 0
                && xrdc_query_cksum(&c, file, "adler32", srvck, sizeof(srvck), &st) == 0) {
                verified = (strcmp(locck, srvck) == 0);
            }
            if (fd >= 0) { close(fd); }
            bat_add(b, "checksum-verify", verified ? 1 : 0,
                    verified ? "adler32 %s matches" : "server/local differ or n/a",
                    verified ? srvck : "");
        }
        /* setattr times (xrdfs.ext) */
        if (ext_sa) {
            struct timespec ts[2];
            ts[0].tv_sec = ts[1].tv_sec = 0;
            ts[0].tv_nsec = ts[1].tv_nsec = UTIME_NOW;
            xrdc_status_clear(&st);
            rc = xrdc_setattr(&c, file, 1, ts, 0, (uint32_t) -1, (uint32_t) -1, &st);
            bat_add(b, "setattr-times", rc == 0 ? 1 : 0, "%s", rc == 0 ? "mtime set" : st.msg);
        } else { bat_add(b, "setattr-times", -1, "server lacks xrdfs.ext"); }
        /* xattr set/get/del (xrdfs.ext fattr is always present, but gate on a probe) */
        {
            char   val[64]; size_t vlen = 0;
            int    okset, okget, okdel;
            xrdc_status_clear(&st);
            okset = (xrdc_fattr_set(&c, file, "doctor", "ok", 2, 0, &st) == 0);
            okget = okset && (xrdc_fattr_get(&c, file, "doctor", val, sizeof(val), &vlen, &st) == 0
                              && vlen == 2 && memcmp(val, "ok", 2) == 0);
            okdel = okget && (xrdc_fattr_del(&c, file, "doctor", &st) == 0);
            bat_add(b, "xattr", okdel ? 1 : (okset ? 0 : -1),
                    okdel ? "set/get/del roundtrip" : (okset ? "%s" : "not supported"),
                    okdel ? "" : st.msg);
        }
        /* symlink + readlink (xrdfs.ext). Note: if the server's rm resolves through
         * the final symlink it cannot unlink the link itself — we detect that and skip
         * the dir's rmdir rather than report a phantom "not empty" failure. */
        if (ext_sl && ext_rl) {
            char    lp[200], tgt[256];
            ssize_t rl;
            int     made;
            snprintf(lp, sizeof(lp), "%s/probe.link", dir);
            xrdc_status_clear(&st);
            made = (xrdc_symlink(&c, file, lp, &st) == 0);
            if (made && (rl = xrdc_readlink(&c, lp, tgt, sizeof(tgt), &st)) > 0
                && strcmp(tgt, file) == 0) {
                xrdc_status rs;
                xrdc_status_clear(&rs);
                if (xrdc_rm(&c, lp, &rs) != 0) {
                    sym_left = 1;
                    bat_add(b, "symlink+readlink", 1,
                            "create+readlink ok; unlink unsupported (rm follows the link)");
                } else {
                    bat_add(b, "symlink+readlink", 1, "create/readlink/unlink ok");
                }
            } else {
                bat_add(b, "symlink+readlink", made ? 0 : 0, "%s", st.msg);
                if (made) { xrdc_status rs; xrdc_status_clear(&rs);
                            if (xrdc_rm(&c, lp, &rs) != 0) { sym_left = 1; } }
            }
        } else { bat_add(b, "symlink+readlink", -1, "server lacks xrdfs.ext"); }
        /* rename */
        xrdc_status_clear(&st);
        rc = xrdc_mv(&c, file, file2, &st);
        bat_add(b, "rename", rc == 0 ? 1 : 0, "%s", rc == 0 ? "moved" : st.msg);
        /* truncate */
        xrdc_status_clear(&st);
        rc = xrdc_truncate(&c, file2, 10, &st);
        bat_add(b, "truncate", rc == 0 ? 1 : 0, "%s", rc == 0 ? "to 10 bytes" : st.msg);
        /* rm the file, then rmdir the now-empty temp dir (cleanup) */
        xrdc_status_clear(&st);
        rc = xrdc_rm(&c, file2, &st);
        bat_add(b, "rm", rc == 0 ? 1 : 0, "%s", rc == 0 ? "removed" : st.msg);
        if (sym_left) {
            bat_add(b, "rmdir", -1,
                    "skipped: temp dir retains a symlink the server cannot unlink");
        } else {
            xrdc_status_clear(&st);
            rc = xrdc_rmdir(&c, dir, &st);
            bat_add(b, "rmdir", rc == 0 ? 1 : 0, "%s", rc == 0 ? "removed" : st.msg);
        }
    }
    xrdc_close(&c);
}

/* The WebDAV/HTTP functional battery: OPTIONS + PROPFIND (read), then (do_write) a
 * MKCOL/PUT/GET-verify/PROPFIND/MOVE/DELETE cycle under a temp collection. bearer NULL
 * = anonymous. */
static void
battery_web(const xrdc_weburl *u, int do_write, const char *bearer, int verify,
            xrd_battery *b)
{
    xrdc_http_resp resp;
    xrdc_status    st;
    const char    *ca = getenv("X509_CERT_DIR");
    char           authhdr[1200];
    const char    *xtra = NULL;

    snprintf(b->protocol, sizeof(b->protocol), "%s", u->tls ? "https" : "http");
    if (bearer != NULL && bearer[0] != '\0') {
        snprintf(authhdr, sizeof(authhdr), "Authorization: Bearer %s\r\n", bearer);
        xtra = authhdr;
    }

    xrdc_status_clear(&st);
    if (xrdc_http_req(u->host, u->port, u->tls, "OPTIONS", "/", xtra, NULL, 0,
                      5000, verify, ca, &resp, &st) != 0) {
        snprintf(b->err, sizeof(b->err), "%s", st.msg);
        bat_add(b, "OPTIONS", 0, "%s", st.msg);
        return;
    }
    b->reachable = 1;
    {
        char dav[160] = "";
        xrdc_http_header(&resp, "DAV", dav, sizeof(dav));
        bat_add(b, "OPTIONS", (resp.status >= 200 && resp.status < 500) ? 1 : 0,
                "HTTP %d%s%s", resp.status, dav[0] ? " DAV=" : "", dav);
    }
    xrdc_http_resp_free(&resp);

    {
        const char *body = "<?xml version=\"1.0\"?><propfind xmlns=\"DAV:\"><allprop/></propfind>";
        char        hdr[1400];
        snprintf(hdr, sizeof(hdr), "Depth: 0\r\nContent-Type: application/xml\r\n%s",
                 xtra ? xtra : "");
        xrdc_status_clear(&st);
        if (xrdc_http_req(u->host, u->port, u->tls, "PROPFIND", "/", hdr, body,
                          strlen(body), 5000, verify, ca, &resp, &st) == 0) {
            bat_add(b, "PROPFIND", resp.status == 207 ? 1 : 0, "HTTP %d", resp.status);
            xrdc_http_resp_free(&resp);
        } else { bat_add(b, "PROPFIND", 0, "%s", st.msg); }
    }

    if (!do_write) { bat_add(b, "write-suite", -1, "skipped (pass --rw)"); return; }

    {
        char     dir[160], fpath[256], mpath[256], dst[2048];
        uint8_t  payload[4096], rbuf[4096];
        long     pid = (long) getpid();
        int      fd, st_code = 0, ok;
        long long blen = 0;

        snprintf(dir,   sizeof(dir),   "/.xrd_doctor_%ld/", pid);
        snprintf(fpath, sizeof(fpath), "%.150sprobe.bin", dir);
        snprintf(mpath, sizeof(mpath), "%.150sprobe.moved.bin", dir);
        fill_pattern(payload, sizeof(payload));

        /* MKCOL */
        xrdc_status_clear(&st);
        if (xrdc_http_req(u->host, u->port, u->tls, "MKCOL", dir, xtra, NULL, 0,
                          5000, verify, ca, &resp, &st) == 0) {
            bat_add(b, "MKCOL", (resp.status == 201 || resp.status == 405) ? 1 : 0,
                    "HTTP %d", resp.status);
            xrdc_http_resp_free(&resp);
        } else { bat_add(b, "MKCOL", 0, "%s", st.msg); }

        /* PUT */
        fd = tmpfile_with(payload, sizeof(payload));
        xrdc_status_clear(&st);
        if (fd >= 0 && xrdc_http_upload(u->host, u->port, u->tls, fpath, xtra, fd,
                                        (long long) sizeof(payload), verify, ca, 10000,
                                        &st_code, &st) == 0) {
            bat_add(b, "PUT", (st_code >= 200 && st_code < 300) ? 1 : 0, "HTTP %d", st_code);
        } else { bat_add(b, "PUT", 0, "%s", st.msg); }
        if (fd >= 0) { close(fd); }

        /* GET + byte-exact verify */
        fd = tmpfile_with(NULL, 0);
        xrdc_status_clear(&st);
        if (fd >= 0 && xrdc_http_download(u->host, u->port, u->tls, fpath, xtra, verify,
                                          ca, fd, 10000, &st_code, &blen, &st) == 0
            && blen == (long long) sizeof(payload)) {
            lseek(fd, 0, SEEK_SET);
            ok = (read(fd, rbuf, sizeof(rbuf)) == (ssize_t) sizeof(payload)
                  && memcmp(rbuf, payload, sizeof(payload)) == 0);
            bat_add(b, "GET-verify", ok ? 1 : 0, ok ? "byte-exact %lld" : "mismatch", blen);
        } else { bat_add(b, "GET-verify", 0, "HTTP %d %s", st_code, st.msg); }
        if (fd >= 0) { close(fd); }

        /* MOVE */
        snprintf(dst, sizeof(dst), "Destination: %s://%s:%d%s\r\n%s",
                 u->tls ? "https" : "http", u->host, u->port, mpath, xtra ? xtra : "");
        xrdc_status_clear(&st);
        if (xrdc_http_req(u->host, u->port, u->tls, "MOVE", fpath, dst, NULL, 0,
                          5000, verify, ca, &resp, &st) == 0) {
            bat_add(b, "MOVE", (resp.status >= 200 && resp.status < 300) ? 1 : 0,
                    "HTTP %d", resp.status);
            xrdc_http_resp_free(&resp);
        } else { bat_add(b, "MOVE", 0, "%s", st.msg); }

        /* DELETE the (moved) file and the collection */
        xrdc_status_clear(&st);
        if (xrdc_http_req(u->host, u->port, u->tls, "DELETE", mpath, xtra, NULL, 0,
                          5000, verify, ca, &resp, &st) == 0) {
            bat_add(b, "DELETE", (resp.status >= 200 && resp.status < 300) ? 1 : 0,
                    "HTTP %d", resp.status);
            xrdc_http_resp_free(&resp);
        } else { bat_add(b, "DELETE", 0, "%s", st.msg); }
        { xrdc_status rs; xrdc_status_clear(&rs);
          if (xrdc_http_req(u->host, u->port, u->tls, "DELETE", dir, xtra, NULL, 0,
                            5000, verify, ca, &resp, &rs) == 0) { xrdc_http_resp_free(&resp); } }
    }
}

/* The S3 functional battery: ListObjectsV2 (read), then (do_write) a SigV4-signed
 * PUT/GET-verify/DELETE of a temp object. ak/sk NULL = anonymous (writes skipped). */
static void
battery_s3(const xrdc_weburl *u, int do_write, const char *ak, const char *sk,
           const char *region, int verify, xrd_battery *b)
{
    xrdc_status st;
    const char *ca = getenv("X509_CERT_DIR");
    char      **keys = NULL;
    size_t      nk = 0;

    snprintf(b->protocol, sizeof(b->protocol), "s3");
    xrdc_status_clear(&st);
    if (xrdc_s3_list(u, ak, sk, region, verify, ca, &keys, &nk, &st) != 0) {
        snprintf(b->err, sizeof(b->err), "%s", st.msg);
        bat_add(b, "list-objects", 0, "%s", st.msg);
        return;
    }
    b->reachable = 1;
    bat_add(b, "list-objects", 1, "%zu keys", nk);
    xrdc_strv_free(keys, nk);

    if (!do_write) { bat_add(b, "write-suite", -1, "skipped (pass --rw)"); return; }
    if (ak == NULL || sk == NULL) {
        bat_add(b, "write-suite", -1, "no AWS_ACCESS_KEY_ID/SECRET — writes skipped");
        return;
    }
    {
        uint8_t  payload[2048], rbuf[2048];
        char     uri[320], phash[80], hdrs[2048], reqhdr[2100];
        long     pid = (long) getpid();
        int      fd, st_code = 0, ok;
        long long blen = 0;
        const char *bucket_path = (u->path[0] == '/') ? u->path : "/";

        fill_pattern(payload, sizeof(payload));
        snprintf(uri, sizeof(uri), "%.250s/.xrd_doctor_%ld.bin",
                 (strcmp(bucket_path, "/") == 0) ? "" : bucket_path, pid);
        if (uri[0] != '/') {   /* ensure path-style leading slash */
            memmove(uri + 1, uri, strlen(uri) + 1);
            uri[0] = '/';
        }

        /* PUT (body hash signed) */
        xrdc_s3_sha256_hex(payload, sizeof(payload), phash);
        xrdc_status_clear(&st);
        if (xrdc_s3_sign_v4("PUT", u->host, uri, ak, sk, region, phash, hdrs, sizeof(hdrs)) == 0) {
            fd = tmpfile_with(payload, sizeof(payload));
            if (fd >= 0 && xrdc_http_upload(u->host, u->port, u->tls, uri, hdrs, fd,
                                            (long long) sizeof(payload), verify, ca, 10000,
                                            &st_code, &st) == 0) {
                bat_add(b, "PUT", (st_code >= 200 && st_code < 300) ? 1 : 0, "HTTP %d", st_code);
            } else { bat_add(b, "PUT", 0, "%s", st.msg); }
            if (fd >= 0) { close(fd); }
        } else { bat_add(b, "PUT", 0, "sign failed"); }

        /* GET + verify (empty-body hash) */
        xrdc_s3_sha256_hex("", 0, phash);
        xrdc_status_clear(&st);
        if (xrdc_s3_sign_v4("GET", u->host, uri, ak, sk, region, phash, hdrs, sizeof(hdrs)) == 0) {
            fd = tmpfile_with(NULL, 0);
            if (fd >= 0 && xrdc_http_download(u->host, u->port, u->tls, uri, hdrs, verify,
                                              ca, fd, 10000, &st_code, &blen, &st) == 0
                && blen == (long long) sizeof(payload)) {
                lseek(fd, 0, SEEK_SET);
                ok = (read(fd, rbuf, sizeof(rbuf)) == (ssize_t) sizeof(payload)
                      && memcmp(rbuf, payload, sizeof(payload)) == 0);
                bat_add(b, "GET-verify", ok ? 1 : 0, ok ? "byte-exact %lld" : "mismatch", blen);
            } else { bat_add(b, "GET-verify", 0, "HTTP %d %s", st_code, st.msg); }
            if (fd >= 0) { close(fd); }
        } else { bat_add(b, "GET-verify", 0, "sign failed"); }

        /* DELETE */
        xrdc_s3_sha256_hex("", 0, phash);
        xrdc_status_clear(&st);
        if (xrdc_s3_sign_v4("DELETE", u->host, uri, ak, sk, region, phash, hdrs, sizeof(hdrs)) == 0) {
            xrdc_http_resp resp;
            (void) reqhdr;
            if (xrdc_http_req(u->host, u->port, u->tls, "DELETE", uri, hdrs, NULL, 0,
                              5000, verify, ca, &resp, &st) == 0) {
                bat_add(b, "DELETE", (resp.status >= 200 && resp.status < 300) ? 1 : 0,
                        "HTTP %d", resp.status);
                xrdc_http_resp_free(&resp);
            } else { bat_add(b, "DELETE", 0, "%s", st.msg); }
        } else { bat_add(b, "DELETE", 0, "sign failed"); }
    }
}

/* Route an endpoint to the right functional battery (root:// / WebDAV / S3). */
static void
xrd_run_battery(const char *endpoint, int do_write, int verify, xrd_battery *b)
{
    memset(b, 0, sizeof(*b));
    snprintf(b->endpoint, sizeof(b->endpoint), "%s", endpoint);

    if (xrdc_is_web_url(endpoint)) {
        xrdc_weburl w;
        if (xrdc_weburl_parse(endpoint, &w) != 0) {
            snprintf(b->protocol, sizeof(b->protocol), "web");
            snprintf(b->err, sizeof(b->err), "unparseable web URL");
            return;
        }
        if (w.is_s3) {
            const char *region = getenv("AWS_DEFAULT_REGION");
            battery_s3(&w, do_write, getenv("AWS_ACCESS_KEY_ID"),
                       getenv("AWS_SECRET_ACCESS_KEY"),
                       region ? region : "us-east-1", verify, b);
        } else {
            char *tok = xrdc_token_discover();
            battery_web(&w, do_write, tok, verify, b);
            if (tok != NULL) { free(tok); }
        }
        return;
    }
    {
        xrdc_url    u;
        xrdc_opts   o;
        xrdc_status st;
        memset(&o, 0, sizeof(o));
        o.verify_host = verify;
        xrdc_status_clear(&st);
        snprintf(b->protocol, sizeof(b->protocol), "root");
        if (xrdc_endpoint_parse(endpoint, &u, &st) != 0) {
            snprintf(b->err, sizeof(b->err), "%s", st.msg);
            return;
        }
        battery_root(&u, &o, do_write, b);
    }
}

/* Gather every endpoint fact doctor reports into *p: a normal (authenticated) connect
 * for liveness/TLS/auth/caps, plus a separate no-login insecure probe for the server
 * cert, plus a clock-skew measurement. Never fails hard — unreachable slices are left
 * zeroed (p->connected / p->cert.have / p->clock_have signal availability). */
static void
xrd_doctor_probe(const char *endpoint, xrd_probe *p)
{
    xrdc_url    u;
    xrdc_opts   o;
    xrdc_conn   c;
    xrdc_status st;
    char        errbuf[XRDC_MSG_MAX + 64];   /* room for a prefixed status msg */

    memset(p, 0, sizeof(*p));
    memset(&o, 0, sizeof(o));
    o.verify_host = 1;
    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(endpoint, &u, &st) != 0) {
        snprintf(p->err, sizeof(p->err), "%s", st.msg);
        return;
    }
    snprintf(p->host, sizeof(p->host), "%s", u.host);
    p->port = u.port;

    /* (1) authenticated connect: liveness, role, negotiated TLS + auth, caps. */
    if (xrdc_connect(&c, &u, &o, &st) != 0) {
        snprintf(p->err, sizeof(p->err), "%s", st.msg);
    } else {
        const char *ver = NULL, *cipher = NULL;
        p->connected    = 1;
        p->server_flags = c.server_flags;
        snprintf(p->auth, sizeof(p->auth), "%s",
                 c.diag.chosen_auth ? c.diag.chosen_auth : "anonymous");
        snprintf(p->sec_list, sizeof(p->sec_list), "%s", c.sec_list);
        if (xrdc_tls_info(&c, &ver, &cipher)) {
            p->tls_active = 1;
            p->tls_ver = ver; p->tls_cipher = cipher;
        }
        xrd_probe_caps(&c, p);
        xrdc_close(&c);
    }

    /* (2) no-login insecure probe for the server certificate (roots:// / gotoTLS). */
    {
        xrdc_conn   cc;
        xrdc_opts   co;
        xrdc_status cs;
        memset(&co, 0, sizeof(co));
        co.insecure_tls = 1; co.verify_host = 0;
        xrdc_status_clear(&cs);
        if (xrdc_connect_no_login(&cc, &u, &co, &cs) == 0) {
            xrdc_tls_peer_cert_info(&cc, &p->cert);
            xrdc_close(&cc);
        }
    }

    /* (3) clock skew (HTTP Date for web URLs, touch+stat for root://). */
    (void) xrd_measure_clock_skew(endpoint, &o, p, errbuf, sizeof(errbuf));
}

/* Emit a JSON string literal for `s` (escaped, NULL → ""). */
static void
xrd_json_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (; s != NULL && *s != '\0'; s++) {
        unsigned char ch = (unsigned char) *s;
        if (ch == '"' || ch == '\\') { fputc('\\', f); fputc((int) ch, f); }
        else if (ch == '\n') { fputs("\\n", f); }
        else if (ch == '\t') { fputs("\\t", f); }
        else if (ch == '\r') { fputs("\\r", f); }
        else if (ch < 0x20)  { fprintf(f, "\\u%04x", (unsigned) ch); }
        else { fputc((int) ch, f); }
    }
    fputc('"', f);
}

/* Dump the full endpoint report as a single JSON object on stdout. */
static void
xrd_doctor_json(const xrd_probe *p, int token_present, const char *token_path,
                int proxy_present, const char *proxy_path,
                const xrd_battery *bats, int nbats)
{
    char nb[32], na[32];
    int  i, j;

    printf("{\n");
    printf("  \"endpoint\": "); xrd_json_str(stdout, p->host);
    printf(",\n  \"port\": %d,\n", p->port);
    printf("  \"connected\": %s,\n", p->connected ? "true" : "false");
    if (!p->connected && p->err[0] != '\0') {
        printf("  \"connect_error\": "); xrd_json_str(stdout, p->err); printf(",\n");
    }
    printf("  \"role\": "); xrd_json_str(stdout, xrd_role_str(p->server_flags));
    printf(",\n  \"server_flags\": %u,\n", (unsigned) p->server_flags);
    printf("  \"auth\": "); xrd_json_str(stdout, p->connected ? p->auth : "");
    printf(",\n  \"sec_list\": "); xrd_json_str(stdout, p->sec_list); printf(",\n");

    printf("  \"tls\": { \"active\": %s", p->tls_active ? "true" : "false");
    if (p->tls_active) {
        printf(", \"version\": "); xrd_json_str(stdout, p->tls_ver);
        printf(", \"cipher\": ");  xrd_json_str(stdout, p->tls_cipher);
    }
    printf(" },\n");

    printf("  \"cert\": ");
    if (!p->cert.have) {
        printf("null,\n");
    } else {
        xrd_fmt_epoch(p->cert.not_before, nb, sizeof(nb));
        xrd_fmt_epoch(p->cert.not_after,  na, sizeof(na));
        printf("{\n    \"subject\": "); xrd_json_str(stdout, p->cert.subject);
        printf(",\n    \"issuer\": ");  xrd_json_str(stdout, p->cert.issuer);
        printf(",\n    \"sans\": ");    xrd_json_str(stdout, p->cert.sans);
        printf(",\n    \"not_before\": %ld", p->cert.not_before);
        printf(",\n    \"not_before_utc\": "); xrd_json_str(stdout, nb);
        printf(",\n    \"not_after\": %ld",  p->cert.not_after);
        printf(",\n    \"not_after_utc\": ");  xrd_json_str(stdout, na);
        printf(",\n    \"days_left\": %ld", p->cert.days_left);
        printf(",\n    \"expired\": %s",       p->cert.expired ? "true" : "false");
        printf(",\n    \"not_yet_valid\": %s", p->cert.not_yet_valid ? "true" : "false");
        printf(",\n    \"host_match\": %s",    p->cert.host_match ? "true" : "false");
        printf(",\n    \"self_signed\": %s\n  },\n", p->cert.self_signed ? "true" : "false");
    }

    printf("  \"clock\": ");
    if (!p->clock_have) {
        printf("null,\n");
    } else {
        printf("{ \"server_epoch\": %ld, \"offset_seconds\": %.1f, \"rtt_ms\": %.1f, \"method\": ",
               p->server_epoch, p->offset_s, p->rtt_ms);
        xrd_json_str(stdout, p->clock_method);
        printf(" },\n");
    }

    printf("  \"capabilities\": {");
    for (i = 0; i < p->ncaps; i++) {
        printf("%s\n    ", i ? "," : "");
        xrd_json_str(stdout, p->caps[i].key);
        printf(": ");
        xrd_json_str(stdout, p->caps[i].val);
    }
    printf("%s},\n", p->ncaps ? "\n  " : "");

    printf("  \"credentials\": {\n");
    printf("    \"bearer_token\": %s", token_present ? "true" : "false");
    if (token_present) { printf(",\n    \"bearer_token_path\": "); xrd_json_str(stdout, token_path); }
    printf(",\n    \"gsi_proxy\": %s", proxy_present ? "true" : "false");
    if (proxy_present) { printf(",\n    \"gsi_proxy_path\": "); xrd_json_str(stdout, proxy_path); }
    printf("\n  },\n");

    printf("  \"tests\": [");
    for (i = 0; i < nbats; i++) {
        const xrd_battery *bt = &bats[i];
        printf("%s\n    {\n", i ? "," : "");
        printf("      \"endpoint\": "); xrd_json_str(stdout, bt->endpoint);
        printf(",\n      \"protocol\": "); xrd_json_str(stdout, bt->protocol);
        printf(",\n      \"reachable\": %s", bt->reachable ? "true" : "false");
        if (!bt->reachable && bt->err[0] != '\0') {
            printf(",\n      \"error\": "); xrd_json_str(stdout, bt->err);
        }
        printf(",\n      \"passed\": %d, \"failed\": %d, \"skipped\": %d",
               bt->npass, bt->nfail, bt->nskip);
        printf(",\n      \"checks\": [");
        for (j = 0; j < bt->n; j++) {
            printf("%s\n        { \"name\": ", j ? "," : "");
            xrd_json_str(stdout, bt->checks[j].name);
            printf(", \"status\": ");
            xrd_json_str(stdout, bt->checks[j].skipped ? "skip"
                                 : (bt->checks[j].ok ? "pass" : "fail"));
            printf(", \"detail\": ");
            xrd_json_str(stdout, bt->checks[j].detail);
            printf(" }");
        }
        printf("%s]\n    }", bt->n ? "\n      " : "");
    }
    printf("%s]\n", nbats ? "\n  " : "");
    printf("}\n");
}

#define XRD_DOCTOR_MAX_EP 9   /* primary + up to 8 --also endpoints */

/* `xrd doctor [endpoint] [--rw] [--also URL]... [--insecure] [--json]` — one-stop
 * endpoint health: local credentials, and for each endpoint the connect/auth/TLS
 * posture, server host-cert validity, clock skew, the kXR_Qconfig capability matrix,
 * AND a functional method battery (read-only by default; --rw adds a full
 * write/read/verify/checksum/metadata cycle). --also adds protocol faces (root:// /
 * davs:// / s3://) so one run can cover every method on every protocol. --json emits
 * the whole report as one object. Exit nonzero on a fatal local cred problem, a failed
 * connect, an expired/skewed server, or any failed functional check. */
static int
xrd_doctor(int argc, char **argv)
{
    const char *endpoint = NULL;
    const char *also[XRD_DOCTOR_MAX_EP];
    int         nalso = 0;
    int         want_json = 0, do_rw = 0, verify = 1, fatal = 0, i;
    char       *tok;
    char        pxp[1024];
    int         token_present, proxy_present;
    xrd_battery bats[XRD_DOCTOR_MAX_EP];
    int         nbats = 0;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0)             { want_json = 1; }
        else if (strcmp(argv[i], "--rw") == 0
                 || strcmp(argv[i], "--write") == 0)    { do_rw = 1; }
        else if (strcmp(argv[i], "--insecure") == 0)    { verify = 0; }
        else if (strcmp(argv[i], "--also") == 0 && i + 1 < argc) {
            if (nalso < XRD_DOCTOR_MAX_EP - 1) { also[nalso++] = argv[++i]; }
            else { i++; }
        }
        else if (endpoint == NULL && argv[i][0] != '-') { endpoint = argv[i]; }
    }
    xrootd_crypto_init();   /* arm SHA-256/HMAC for token/proxy inspection */

    tok           = xrdc_token_discover();
    token_present = (tok != NULL);
    xrdc_proxy_default_path(pxp, sizeof(pxp));
    proxy_present = (access(pxp, R_OK) == 0);

    /* Run the functional battery on the primary endpoint + each --also face. */
    if (endpoint != NULL) {
        xrd_run_battery(endpoint, do_rw, verify, &bats[nbats++]);
    }
    for (i = 0; i < nalso; i++) {
        xrd_run_battery(also[i], do_rw, verify, &bats[nbats++]);
    }
    for (i = 0; i < nbats; i++) {
        if (bats[i].nfail > 0) { fatal = 1; }
    }

    if (want_json) {
        xrd_probe p;
        memset(&p, 0, sizeof(p));
        if (endpoint != NULL) { xrd_doctor_probe(endpoint, &p); }
        xrd_doctor_json(&p, token_present, token_present ? "(discovered)" : "",
                        proxy_present, pxp, bats, nbats);
        if (tok != NULL) { free(tok); }
        if (endpoint != NULL && !p.connected)               { fatal = 1; }
        if (p.cert.have && (p.cert.expired || p.cert.not_yet_valid)) { fatal = 1; }
        if (p.clock_have && (p.offset_s > 300.0 || p.offset_s < -300.0)) { fatal = 1; }
        return fatal ? 1 : 0;
    }

    /* human report */
    printf("== credentials ==\n");
    if (tok != NULL) { xrdc_token_explain(tok, stdout); free(tok); }
    else { printf("  bearer token: none discovered (BEARER_TOKEN / *_FILE / XDG / /tmp)\n"); }
    if (proxy_present) { xrdc_gsi_cert_explain(pxp, stdout); }
    else               { printf("  GSI proxy: none at %s\n", pxp); }
    if (xrdc_cred_diagnose(0, "  hint: ", stdout)) { fatal = 1; }

    if (endpoint == NULL && nbats == 0) {
        printf("(pass an endpoint to also test connect + TLS + cert + clock + caps;\n"
               " add --rw for write tests and --also <url> for more protocols)\n");
        return fatal ? 1 : 0;
    }

    if (endpoint != NULL) {
        xrd_probe p;
        char      nb[32], na[32];
        int       j;
        xrd_doctor_probe(endpoint, &p);
        printf("== endpoint %s:%d ==\n", p.host, p.port);
        if (!p.connected) {
            printf("  connect:  FAILED (%s)\n", p.err[0] ? p.err : "?");
            fatal = 1;
        } else {
            printf("  connect:  OK   role=%s  auth=%s\n",
                   xrd_role_str(p.server_flags), p.auth);
            if (p.sec_list[0] != '\0') { printf("  sec:      %s\n", p.sec_list); }
            if (p.tls_active) {
                printf("  TLS:      active (%s %s)\n",
                       p.tls_ver ? p.tls_ver : "?", p.tls_cipher ? p.tls_cipher : "?");
            } else {
                printf("  TLS:      cleartext\n");
            }
        }
        if (p.cert.have) {
            xrd_fmt_epoch(p.cert.not_before, nb, sizeof(nb));
            xrd_fmt_epoch(p.cert.not_after,  na, sizeof(na));
            printf("  cert:     %s\n", p.cert.subject);
            printf("            issuer %s\n", p.cert.issuer);
            if (p.cert.expired) {
                printf("            EXPIRED %ld day(s) ago (%s)\n", -p.cert.days_left, na);
                fatal = 1;
            } else if (p.cert.not_yet_valid) {
                printf("            NOT YET VALID (from %s)\n", nb);
                fatal = 1;
            } else {
                printf("            valid, %ld day(s) left (until %s)  host-match=%s\n",
                       p.cert.days_left, na, p.cert.host_match ? "yes" : "no");
            }
        } else {
            printf("  cert:     none (cleartext session)\n");
        }
        if (p.clock_have) {
            double ao = xrd_fabs(p.offset_s);
            printf("  clock:    offset %+.1f s, rtt %.1f ms (%s)\n",
                   p.offset_s, p.rtt_ms, p.clock_method);
            if (ao > 300.0) { fatal = 1; }
            if (ao > 60.0) {
                printf("            WARNING: skew may break token exp/nbf + GSI validity\n");
            }
        } else {
            printf("  clock:    not measured (need an HTTP endpoint or write access)\n");
        }
        if (p.ncaps > 0) {
            printf("  caps:    ");
            for (j = 0; j < p.ncaps; j++) {
                printf(" %s=%s", p.caps[j].key, p.caps[j].val);
            }
            printf("\n");
        }
    }

    /* functional method batteries (per protocol face) */
    for (i = 0; i < nbats; i++) {
        const xrd_battery *bt = &bats[i];
        int                j;
        printf("== %s tests: %s ==\n", bt->protocol, bt->endpoint);
        if (!bt->reachable) {
            printf("  unreachable (%s)\n", bt->err[0] ? bt->err : "?");
            continue;
        }
        for (j = 0; j < bt->n; j++) {
            const xrd_check *ck = &bt->checks[j];
            const char      *tag = ck->skipped ? "SKIP" : (ck->ok ? "PASS" : "FAIL");
            printf("  [%s] %-18s %s\n", tag, ck->name, ck->detail);
        }
        printf("  -> %d passed, %d failed, %d skipped%s\n",
               bt->npass, bt->nfail, bt->nskip, do_rw ? "" : "  (read-only; --rw for writes)");
    }
    return fatal ? 1 : 0;
}

/* `xrd login [--oidc-account N] [--read] [-v]` — acquire/refresh a bearer token
 * (oidc-agent) and/or a GSI proxy (xrdgsiproxy), then show the resulting posture.
 * Pure composition of xrdc_cred_autorefresh (best-effort: skips what isn't
 * configured). */
static int
xrd_login(int argc, char **argv)
{
    const char *account = getenv("OIDC_ACCOUNT");
    int         want_write = 1;   /* login acquires write-capable creds by default */
    int         verbose = 0, i, n;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--oidc-account") == 0 && i + 1 < argc) {
            account = argv[++i];
        } else if (strcmp(argv[i], "--read") == 0) {
            want_write = 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else {
            fprintf(stderr, "xrd login: unknown argument '%s'\n", argv[i]);
            return 50;
        }
    }
    xrootd_crypto_init();
    n = xrdc_cred_autorefresh(want_write, account, verbose, stderr);
    printf("xrd login: %d credential(s) acquired/refreshed\n", n);
    (void) xrdc_cred_diagnose(want_write, "  ", stdout);
    return 0;
}

/* `xrd ping [-c COUNT] <endpoint>` — connect once, then time COUNT (default 4) stat
 * round-trips to "/" and report min/avg/max RTT. A simple, dependency-free liveness +
 * latency probe (xrddiag has deeper net diagnostics). Exit nonzero on connect failure
 * or if every probe failed. */
static int
xrd_ping(int argc, char **argv)
{
    const char *endpoint = NULL;
    int         count = 4, i, ok = 0;
    double      tmin = 1e30, tmax = 0.0, tsum = 0.0;
    xrdc_url    u;
    xrdc_opts   o;
    xrdc_conn   c;
    xrdc_status st;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) { count = atoi(argv[++i]); }
        else if (endpoint == NULL && argv[i][0] != '-') { endpoint = argv[i]; }
    }
    if (endpoint == NULL || count <= 0) {
        fprintf(stderr, "usage: xrd ping [-c COUNT] <endpoint>\n");
        return 50;
    }
    memset(&o, 0, sizeof(o));
    o.verify_host = 1;
    xrootd_crypto_init();
    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(endpoint, &u, &st) != 0) {
        fprintf(stderr, "xrd ping: %s\n", st.msg);
        return 50;
    }
    if (xrdc_connect(&c, &u, &o, &st) != 0) {
        fprintf(stderr, "xrd ping: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return xrdc_shellcode(&st);
    }
    printf("PING %s:%d  (%d stat round-trips to /)\n", u.host, u.port, count);
    for (i = 0; i < count; i++) {
        struct timespec t0, t1;
        xrdc_statinfo   si;
        xrdc_status     pst;
        double          ms;
        xrdc_status_clear(&pst);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (xrdc_stat(&c, "/", &si, &pst) != 0) {
            printf("  seq %d: FAILED (%s)\n", i + 1, pst.msg);
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        ms = (double) (t1.tv_sec - t0.tv_sec) * 1000.0
           + (double) (t1.tv_nsec - t0.tv_nsec) / 1e6;
        printf("  seq %d: %.3f ms\n", i + 1, ms);
        ok++;
        tsum += ms;
        if (ms < tmin) { tmin = ms; }
        if (ms > tmax) { tmax = ms; }
    }
    xrdc_close(&c);
    if (ok == 0) {
        printf("%d probes, 0 successful\n", count);
        return 1;
    }
    printf("%d/%d ok  min/avg/max = %.3f/%.3f/%.3f ms\n",
           ok, count, tmin, tsum / ok, tmax);
    return 0;
}

/* ====================================================================== */
/* diagnostic verbs: certinfo / clockskew / whoami / caps (+ doctor JSON)  */
/* ====================================================================== */

/* kXR_Qconfig keys probed by `caps` and `doctor`. The module answers chksum/readv/
 * tpc/tpcdlg/xrdfs.ext meaningfully and echoes "<key>=0" for the rest; real XRootD
 * also answers version/role/sitename/pgread. */
static const char *XRD_CAP_KEYS[] = {
    "chksum", "readv", "tpc", "tpcdlg", "xrdfs.ext",
    "version", "role", "sitename", "pgread", NULL
};

/* Decode the server protocol flags into a short role label. */
static const char *
xrd_role_str(uint32_t flags)
{
    if (flags & kXR_isManager) {
        return (flags & kXR_isServer) ? "supervisor" : "manager";
    }
    if (flags & kXR_isServer) { return "server"; }
    return "unknown";
}

/* Format an epoch as "YYYY-MM-DD HH:MM:SSZ" (UTC), or "?" when unset. */
static void
xrd_fmt_epoch(long e, char *buf, size_t sz)
{
    time_t    t = (time_t) e;
    struct tm tmv;
    if (e == 0 || gmtime_r(&t, &tmv) == NULL) { snprintf(buf, sz, "?"); return; }
    strftime(buf, sz, "%Y-%m-%d %H:%M:%SZ", &tmv);
}

/* |x| for a double, avoiding a libm dependency. */
static double
xrd_fabs(double x) { return x < 0.0 ? -x : x; }

/* Probe the kXR_Qconfig capability keys on a live connection into p->caps. */
static void
xrd_probe_caps(xrdc_conn *c, xrd_probe *p)
{
    int i;
    p->ncaps = 0;
    for (i = 0; XRD_CAP_KEYS[i] != NULL && p->ncaps < XRD_CAPS_MAX; i++) {
        char        reply[256], *nl, *eq;
        const char *val;
        xrdc_status st;
        xrdc_status_clear(&st);
        if (xrdc_query(c, kXR_Qconfig, XRD_CAP_KEYS[i], reply, sizeof(reply), &st) != 0) {
            continue;
        }
        if ((nl = strchr(reply, '\n')) != NULL) { *nl = '\0'; }
        eq  = strchr(reply, '=');               /* "key=val" → val; else whole reply */
        val = (eq != NULL) ? eq + 1 : reply;
        snprintf(p->caps[p->ncaps].key, sizeof(p->caps[p->ncaps].key), "%s",
                 XRD_CAP_KEYS[i]);
        snprintf(p->caps[p->ncaps].val, sizeof(p->caps[p->ncaps].val), "%s", val);
        p->ncaps++;
    }
}

/* Parse an HTTP IMF-fixdate ("Sun, 06 Nov 1994 08:49:37 GMT") to epoch, locale-free.
 * 0 / -1. */
static int
xrd_parse_http_date(const char *s, time_t *out)
{
    static const char *MON = "JanFebMarAprMayJunJulAugSepOctNovDec";
    struct tm   tmv;
    char        mname[8];
    const char *m;
    int         d = 0, y = 0, hh = 0, mm = 0, ss = 0;

    memset(&tmv, 0, sizeof(tmv));
    if (sscanf(s, "%*3s, %d %3s %d %d:%d:%d", &d, mname, &y, &hh, &mm, &ss) != 6) {
        return -1;
    }
    m = strstr(MON, mname);
    if (m == NULL || (int) ((m - MON) % 3) != 0) { return -1; }
    tmv.tm_mday = d; tmv.tm_mon = (int) ((m - MON) / 3); tmv.tm_year = y - 1900;
    tmv.tm_hour = hh; tmv.tm_min = mm; tmv.tm_sec = ss;
    *out = timegm(&tmv);
    return (*out == (time_t) -1) ? -1 : 0;
}

/* Clock skew via an HTTP(S)/WebDAV endpoint's Date response header (read-only). */
static int
xrd_clockskew_http(const char *endpoint, xrd_probe *p, char *err, size_t errsz)
{
    xrdc_weburl     w;
    xrdc_http_resp  resp;
    xrdc_status     st;
    struct timespec t0, t1;
    char            date[128];
    time_t          srv;
    double          rtt_s, local_mid;

    if (xrdc_weburl_parse(endpoint, &w) != 0) { snprintf(err, errsz, "bad URL"); return -1; }
    clock_gettime(CLOCK_REALTIME, &t0);
    xrdc_status_clear(&st);
    if (xrdc_http_req(w.host, w.port, w.tls, "HEAD", w.path[0] ? w.path : "/",
                      NULL, NULL, 0, 5000, 0 /*verify off for a clock probe*/,
                      NULL, &resp, &st) != 0) {
        snprintf(err, errsz, "%s", st.msg);
        return -1;
    }
    clock_gettime(CLOCK_REALTIME, &t1);
    if (!xrdc_http_header(&resp, "Date", date, sizeof(date))
        || xrd_parse_http_date(date, &srv) != 0) {
        snprintf(err, errsz, "no parseable Date header");
        xrdc_http_resp_free(&resp);
        return -1;
    }
    xrdc_http_resp_free(&resp);
    rtt_s     = (double) (t1.tv_sec - t0.tv_sec) + (double) (t1.tv_nsec - t0.tv_nsec) / 1e9;
    local_mid = (double) t0.tv_sec + (double) t0.tv_nsec / 1e9 + rtt_s / 2.0;
    p->clock_have   = 1;
    p->clock_method = "HTTP Date header (1s granularity)";
    p->server_epoch = (long) srv;
    p->offset_s     = (double) srv - local_mid;
    p->rtt_ms       = rtt_s * 1000.0;
    return 0;
}

/* Clock skew via root://: create a temp file (server stamps mtime with its wall
 * clock), stat it, compare to the local clock, then remove it. Needs write access. */
static int
xrd_clockskew_root(const char *endpoint, const xrdc_opts *o, xrd_probe *p,
                   char *err, size_t errsz)
{
    xrdc_url      u;
    xrdc_conn     c;
    xrdc_status   st;
    xrdc_file     f;
    xrdc_statinfo si;
    char          tmp[128];
    time_t        t0, t1;

    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(endpoint, &u, &st) != 0) { snprintf(err, errsz, "%s", st.msg); return -1; }
    if (xrdc_connect(&c, &u, o, &st) != 0) { snprintf(err, errsz, "connect: %s", st.msg); return -1; }
    snprintf(tmp, sizeof(tmp), "/.xrd_clockskew_%ld", (long) getpid());
    t0 = time(NULL);
    if (xrdc_file_open_write(&c, tmp, 1 /*force*/, 0, &f, &st) != 0) {
        snprintf(err, errsz, "need an HTTP endpoint or write access (%s)", st.msg);
        xrdc_close(&c);
        return -1;
    }
    xrdc_file_close(&c, &f, &st);
    if (xrdc_stat(&c, tmp, &si, &st) != 0) {
        snprintf(err, errsz, "stat: %s", st.msg);
        { xrdc_status rs; xrdc_status_clear(&rs); xrdc_rm(&c, tmp, &rs); }
        xrdc_close(&c);
        return -1;
    }
    t1 = time(NULL);
    { xrdc_status rs; xrdc_status_clear(&rs); xrdc_rm(&c, tmp, &rs); }
    p->clock_have   = 1;
    p->clock_method = "root:// touch+stat (1s granularity)";
    p->server_epoch = (long) si.mtime;
    p->offset_s     = (double) si.mtime - ((double) t0 + (double) t1) / 2.0;
    p->rtt_ms       = (double) (t1 - t0) * 1000.0;
    xrdc_close(&c);
    return 0;
}

/* Measure client↔server clock skew: HTTP Date for web URLs, touch+stat for root://. */
static int
xrd_measure_clock_skew(const char *endpoint, const xrdc_opts *o, xrd_probe *p,
                       char *err, size_t errsz)
{
    if (xrdc_is_web_url(endpoint)) {
        return xrd_clockskew_http(endpoint, p, err, errsz);
    }
    return xrd_clockskew_root(endpoint, o, p, err, errsz);
}

/* `xrd certinfo <endpoint>` — connect (requesting TLS) and report the server's host
 * certificate: subject/issuer/SAN, validity window, days-until-expiry, host match.
 * Exit nonzero if the cert is expired or not yet valid. */
static int
xrd_certinfo(int argc, char **argv)
{
    const char    *endpoint = (argc >= 3 && argv[2][0] != '-') ? argv[2] : NULL;
    xrdc_url       u;
    xrdc_opts      o;
    xrdc_conn      c;
    xrdc_status    st;
    xrdc_cert_info ci;
    char           nb[32], na[32];

    if (endpoint == NULL) { fprintf(stderr, "usage: xrd certinfo <endpoint>\n"); return 50; }
    memset(&o, 0, sizeof(o));
    /* Inspect, don't gate: skip chain + host verification so an expired/untrusted/
     * self-signed cert is still reportable. TLS happens per the scheme (roots://,
     * or a server that requires it); a cleartext root:// endpoint reports "no cert". */
    o.insecure_tls = 1; o.verify_host = 0;
    xrootd_crypto_init();
    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(endpoint, &u, &st) != 0) {
        fprintf(stderr, "xrd certinfo: %s\n", st.msg); return 50;
    }
    if (xrdc_connect_no_login(&c, &u, &o, &st) != 0) {
        fprintf(stderr, "xrd certinfo: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return xrdc_shellcode(&st);
    }
    if (xrdc_tls_peer_cert_info(&c, &ci) != 0 || !ci.have) {
        printf("%s:%d — no server certificate (session is cleartext)\n", u.host, u.port);
        xrdc_close(&c);
        return 0;
    }
    xrd_fmt_epoch(ci.not_before, nb, sizeof(nb));
    xrd_fmt_epoch(ci.not_after,  na, sizeof(na));
    printf("server certificate for %s:%d\n", u.host, u.port);
    printf("  subject:    %s\n", ci.subject);
    printf("  issuer:     %s\n", ci.issuer);
    if (ci.sans[0] != '\0') { printf("  SAN:        %s\n", ci.sans); }
    printf("  validity:   %s .. %s\n", nb, na);
    if (ci.expired) {
        printf("  status:     EXPIRED %ld day(s) ago\n", -ci.days_left);
    } else if (ci.not_yet_valid) {
        printf("  status:     NOT YET VALID\n");
    } else {
        printf("  status:     valid, %ld day(s) left\n", ci.days_left);
    }
    printf("  host match: %s%s\n", ci.host_match ? "yes" : "no",
           ci.self_signed ? "   (self-signed)" : "");
    xrdc_close(&c);
    return (ci.expired || ci.not_yet_valid) ? 1 : 0;
}

/* `xrd clockskew <endpoint>` — report client↔server clock offset and RTT. Warns past
 * 60 s (token exp/nbf + GSI validity start failing); exits nonzero past 5 min. */
static int
xrd_clockskew(int argc, char **argv)
{
    const char *endpoint = (argc >= 3 && argv[2][0] != '-') ? argv[2] : NULL;
    xrdc_opts   o;
    xrd_probe   p;
    char        err[XRDC_MSG_MAX + 64] = "", sb[32];   /* room for a prefixed msg */
    double      ao;

    if (endpoint == NULL) { fprintf(stderr, "usage: xrd clockskew <endpoint>\n"); return 50; }
    memset(&o, 0, sizeof(o)); o.verify_host = 1;
    memset(&p, 0, sizeof(p));
    xrootd_crypto_init();
    if (xrd_measure_clock_skew(endpoint, &o, &p, err, sizeof(err)) != 0 || !p.clock_have) {
        fprintf(stderr, "xrd clockskew: %s\n", err[0] ? err : "unavailable");
        return 1;
    }
    ao = xrd_fabs(p.offset_s);
    xrd_fmt_epoch(p.server_epoch, sb, sizeof(sb));
    printf("server time:  %s  (%s)\n", sb, p.clock_method);
    printf("clock offset: %+.1f s  (server is %s the client)\n", p.offset_s,
           p.offset_s > 0.5 ? "ahead of" : (p.offset_s < -0.5 ? "behind" : "in sync with"));
    printf("round-trip:   %.1f ms\n", p.rtt_ms);
    if (ao > 60.0) {
        printf("WARNING: >60s skew — bearer-token exp/nbf and GSI/proxy validity "
               "checks may reject you\n");
    }
    return (ao > 300.0) ? 1 : 0;
}

/* `xrd whoami <endpoint>` — the negotiated auth protocol + the identity you are
 * presenting (local token subject / GSI proxy DN). Helps debug authz ("I have a
 * token but get 403 — what does the server see?"). */
static int
xrd_whoami(int argc, char **argv)
{
    const char *endpoint = (argc >= 3 && argv[2][0] != '-') ? argv[2] : NULL;
    xrdc_url    u;
    xrdc_opts   o;
    xrdc_conn   c;
    xrdc_status st;
    char       *tok;
    char        pxp[1024];

    if (endpoint == NULL) { fprintf(stderr, "usage: xrd whoami <endpoint>\n"); return 50; }
    memset(&o, 0, sizeof(o)); o.verify_host = 1;
    xrootd_crypto_init();
    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(endpoint, &u, &st) != 0) {
        fprintf(stderr, "xrd whoami: %s\n", st.msg); return 50;
    }
    if (xrdc_connect(&c, &u, &o, &st) != 0) {
        fprintf(stderr, "xrd whoami: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return xrdc_shellcode(&st);
    }
    printf("endpoint:   %s:%d\n", u.host, u.port);
    printf("auth used:  %s\n", c.diag.chosen_auth != NULL ? c.diag.chosen_auth : "anonymous (no credential)");
    if (c.sec_list[0] != '\0') { printf("offered:    %s\n", c.sec_list); }
    printf("presenting:\n");
    tok = xrdc_token_discover();
    if (tok != NULL) { xrdc_token_explain(tok, stdout); free(tok); }
    else             { printf("  bearer token: none discovered\n"); }
    xrdc_proxy_default_path(pxp, sizeof(pxp));
    if (access(pxp, R_OK) == 0) { xrdc_gsi_cert_explain(pxp, stdout); }
    else                        { printf("  GSI proxy: none at %s\n", pxp); }
    xrdc_close(&c);
    return 0;
}

/* `xrd caps <endpoint>` — server role + kXR_Qconfig capability matrix. */
static int
xrd_caps(int argc, char **argv)
{
    const char *endpoint = (argc >= 3 && argv[2][0] != '-') ? argv[2] : NULL;
    xrdc_url    u;
    xrdc_opts   o;
    xrdc_conn   c;
    xrdc_status st;
    xrd_probe   p;
    const char *ver = NULL, *cipher = NULL;
    int         i;

    if (endpoint == NULL) { fprintf(stderr, "usage: xrd caps <endpoint>\n"); return 50; }
    memset(&o, 0, sizeof(o)); o.verify_host = 1;
    memset(&p, 0, sizeof(p));
    xrootd_crypto_init();
    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(endpoint, &u, &st) != 0) {
        fprintf(stderr, "xrd caps: %s\n", st.msg); return 50;
    }
    if (xrdc_connect(&c, &u, &o, &st) != 0) {
        fprintf(stderr, "xrd caps: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return xrdc_shellcode(&st);
    }
    printf("server %s:%d  role=%s  tls=%s\n", u.host, u.port,
           xrd_role_str(c.server_flags),
           xrdc_tls_info(&c, &ver, &cipher) ? (ver ? ver : "yes") : "cleartext");
    printf("capabilities (kXR_Qconfig; 0 = unset/unsupported):\n");
    xrd_probe_caps(&c, &p);
    for (i = 0; i < p.ncaps; i++) {
        printf("  %-12s %s\n", p.caps[i].key, p.caps[i].val);
    }
    xrdc_close(&c);
    return 0;
}

/* Fork + exec `cmd_argv` (PATH-searched) and wait. Returns the child's exit code,
 * or 126 if it could not be exec'd (so callers can try a fallback tool), or -1 on
 * fork failure. */
static int
run_cmd(char *const cmd_argv[])
{
    pid_t pid = fork();
    int   status;

    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        execvp(cmd_argv[0], cmd_argv);
        _exit(126);   /* distinct from any normal tool exit → "couldn't exec" */
    }
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        /* retry */
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Decode mountinfo octal escapes (\040 space, \011 tab, \012 nl, \134 backslash)
 * from `in` into out[outsz]. */
static void
mountinfo_unescape(const char *in, char *out, size_t outsz)
{
    size_t o = 0;
    while (*in != '\0' && o + 1 < outsz) {
        if (in[0] == '\\' && in[1] >= '0' && in[1] <= '7'
            && in[2] >= '0' && in[2] <= '7' && in[3] >= '0' && in[3] <= '7') {
            out[o++] = (char) ((in[1] - '0') * 64 + (in[2] - '0') * 8 + (in[3] - '0'));
            in += 4;
        } else {
            out[o++] = *in++;
        }
    }
    out[o] = '\0';
}

/* `xrd mount` (no args) / `xrd mounts` / `xrd mount -l` — list active XRootD FUSE
 * mounts by parsing /proc/self/mountinfo (override with XRD_MOUNTINFO_PATH for tests).
 * Matches fuse.xrootdfs* filesystem types, plus any fuse mount whose source looks like
 * a root:// endpoint. Prints "ENDPOINT  MOUNTPOINT  DRIVER"; honest empty output (exit
 * 0) when nothing is mounted. Pure procfs parse — no network, no credentials. */
static int
xrd_list_mounts(void)
{
#ifndef __linux__
    fprintf(stderr, "xrd mount: mount listing is only supported on Linux\n");
    return 0;
#else
    const char *path = getenv("XRD_MOUNTINFO_PATH");
    FILE       *fp = fopen(path != NULL ? path : "/proc/self/mountinfo", "r");
    char       *line = NULL;
    size_t      cap = 0;
    ssize_t     r;
    int         header = 0;

    if (fp == NULL) {
        fprintf(stderr, "xrd mount: cannot read mountinfo: %s\n", strerror(errno));
        return 1;
    }
    while ((r = getline(&line, &cap, fp)) >= 0) {
        char       *fields[48];
        int         nf = 0, sep = -1, i;
        char       *tok, *save;
        const char *mp, *fstype, *src, *driver;
        char        mpbuf[PATH_MAX], srcbuf[PATH_MAX];

        (void) r;
        for (tok = strtok_r(line, " \n", &save); tok != NULL && nf < 48;
             tok = strtok_r(NULL, " \n", &save)) {
            fields[nf++] = tok;
        }
        for (i = 0; i < nf; i++) {
            if (strcmp(fields[i], "-") == 0) { sep = i; break; }
        }
        if (sep < 5 || sep + 2 >= nf) { continue; }   /* malformed / too few fields */
        mp     = fields[4];
        fstype = fields[sep + 1];
        src    = fields[sep + 2];
        if (strncmp(fstype, "fuse.xrootdfs", 13) != 0
            && !(strncmp(fstype, "fuse", 4) == 0 && strstr(src, "root") != NULL)) {
            continue;
        }
        driver = (strstr(fstype, "xrootdfs_legacy") != NULL) ? "legacy"
               : (strncmp(fstype, "fuse.xrootdfs", 13) == 0) ? "aio"
               :                                               "fuse";
        mountinfo_unescape(mp, mpbuf, sizeof(mpbuf));
        mountinfo_unescape(src, srcbuf, sizeof(srcbuf));
        if (!header) {
            printf("%-36s %-28s %s\n", "ENDPOINT", "MOUNTPOINT", "DRIVER");
            header = 1;
        }
        printf("%-36s %-28s %s\n", srcbuf, mpbuf, driver);
    }
    free(line);
    fclose(fp);
    return 0;
#endif
}

/* `xrd mount [--legacy|--driver aio|legacy] [driver-opts] <endpoint> <mountpoint>
 * [fuse-opts]` — mount an XRootD export via the single FUSE3 driver `xrootdfs`.
 * Defaults to its resilient mode; --legacy is forwarded to xrootdfs to select its
 * synchronous mode. Everything after the
 * driver selector is forwarded verbatim in the driver's native arg order
 * (`[opts] endpoint mountpoint [fuse-opts]`). The driver backgrounds itself unless
 * a fuse -f/-d is passed. exec's the driver (does not return on success). */
static int
xrd_mount(int argc, char **argv)
{
    /* One unified `xrootdfs` binary carries both drivers; `--legacy` selects the
     * synchronous one at run time (passed through to the driver). */
    const char *driver = "xrootdfs";
    int         i = 2, k = 0, list = 0, legacy = 0;
    char      **nv;
    char        endpoint[XRDC_PATH_MAX];

    /* Optional driver selector / --list, only as the leading token(s). */
    while (i < argc) {
        if (strcmp(argv[i], "--legacy") == 0) { legacy = 1; i++; }
        else if (strcmp(argv[i], "--aio") == 0) { legacy = 0; i++; }
        else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--list") == 0) {
            list = 1; i++;
        }
        else if (strcmp(argv[i], "--driver") == 0 && i + 1 < argc) {
            const char *d = argv[i + 1];
            if (strcmp(d, "legacy") == 0) { legacy = 1; }
            else if (strcmp(d, "aio") == 0 || strcmp(d, "resilient") == 0) { legacy = 0; }
            else {
                fprintf(stderr, "xrd mount: unknown driver '%s' (aio|legacy)\n", d);
                return 50;
            }
            i += 2;
        } else {
            break;
        }
    }
    /* No positional args (or an explicit --list) → list current XRootD mounts,
     * mirroring mount(8)'s no-arg behavior. */
    if (list || argc - i == 0) {
        return xrd_list_mounts();
    }
    if (argc - i < 2) {
        fprintf(stderr, "usage: xrd mount [--legacy] [driver-opts] <endpoint> "
                        "<mountpoint> [fuse-opts]\n"
                        "  e.g. xrd mount root://store//data /mnt/xrd -o ro\n");
        return 50;
    }
    /* +3: driver name, an optional "--legacy", and the NULL terminator. */
    nv = (char **) malloc((size_t) (argc - i + 3) * sizeof(char *));
    if (nv == NULL) {
        fprintf(stderr, "xrd: out of memory\n");
        return 51;
    }
    nv[k++] = (char *) driver;
    if (legacy) {
        nv[k++] = (char *) "--legacy";
    }
    /* Resolve a ~/.xrdrc alias for the endpoint (the first forwarded non-option
     * token) so `xrd mount lab:/data /mnt` works like the rest of xrd; the driver
     * itself doesn't expand aliases. A bare URL passes through verbatim. */
    if (i < argc && argv[i][0] != '-') {
        xrdc_alias_resolve(argv[i], endpoint, sizeof(endpoint));
        nv[k++] = endpoint;
        i++;
    }
    for (; i < argc; i++) {
        nv[k++] = argv[i];
    }
    nv[k] = NULL;
    exec_tool(driver, nv);   /* does not return on success */
    return 127;              /* unreachable (exec_tool _exit's on failure) */
}

/* `xrd unmount [-z|--lazy] <mountpoint>` (alias: umount) — unmount a FUSE export,
 * preferring fusermount3 (fuse3), then fusermount, then umount. -z/--lazy maps to
 * the lazy-detach flag of whichever tool is used. */
static int
xrd_unmount(int argc, char **argv)
{
    const char *mp = NULL;
    int         lazy = 0, i, rc;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-z") == 0 || strcmp(argv[i], "--lazy") == 0) {
            lazy = 1;
        } else if (mp == NULL && argv[i][0] != '-') {
            mp = argv[i];
        } else {
            fprintf(stderr, "xrd unmount: unexpected argument '%s'\n", argv[i]);
            return 50;
        }
    }
    if (mp == NULL) {
        fprintf(stderr, "usage: xrd unmount [-z] <mountpoint>\n");
        return 50;
    }
    {
        char *c[5]; int k = 0;
        c[k++] = (char *) "fusermount3"; c[k++] = (char *) "-u";
        if (lazy) { c[k++] = (char *) "-z"; }
        c[k++] = (char *) mp; c[k] = NULL;
        rc = run_cmd(c);
    }
    if (rc == 126) {   /* fusermount3 not present → fusermount */
        char *c[5]; int k = 0;
        c[k++] = (char *) "fusermount"; c[k++] = (char *) "-u";
        if (lazy) { c[k++] = (char *) "-z"; }
        c[k++] = (char *) mp; c[k] = NULL;
        rc = run_cmd(c);
    }
    if (rc == 126) {   /* neither fusermount → umount (-l = lazy) */
        char *c[4]; int k = 0;
        c[k++] = (char *) "umount";
        if (lazy) { c[k++] = (char *) "-l"; }
        c[k++] = (char *) mp; c[k] = NULL;
        rc = run_cmd(c);
    }
    if (rc == 126) {
        fprintf(stderr, "xrd unmount: no fusermount3/fusermount/umount found\n");
        return 127;
    }
    return (rc < 0) ? 1 : rc;
}

int
main(int argc, char **argv)
{
    const char *cmd;

    if (argc < 2 || strcmp(argv[1], "help") == 0 || strcmp(argv[1], "-h") == 0
        || strcmp(argv[1], "--help") == 0) {
        usage();
        return (argc < 2) ? 50 : 0;
    }
    cmd = argv[1];

    if (strcmp(cmd, "version") == 0 || strcmp(cmd, "-V") == 0) {
        printf("xrd (native XRootD toolkit, phase-37)\n");
        return 0;
    }

    /* cp/copy -> xrdcp [args...] */
    if (strcmp(cmd, "cp") == 0 || strcmp(cmd, "copy") == 0) {
        argv[1] = (char *) "xrdcp";
        exec_tool("xrdcp", &argv[1]);
    }

    /* get <url> [dst=.] -> xrdcp <url> <dst> */
    if (strcmp(cmd, "get") == 0) {
        char *nv[5];
        int   k = 0;
        if (argc < 3) { fprintf(stderr, "xrd get: needs a <url>\n"); return 50; }
        nv[k++] = (char *) "xrdcp";
        nv[k++] = argv[2];
        nv[k++] = (argc >= 4) ? argv[3] : (char *) ".";
        nv[k] = NULL;
        exec_tool("xrdcp", nv);
    }

    /* put <localfile> <url> -> xrdcp <localfile> <url> */
    if (strcmp(cmd, "put") == 0) {
        char *nv[4];
        if (argc < 4) { fprintf(stderr, "xrd put: needs <localfile> <url>\n"); return 50; }
        nv[0] = (char *) "xrdcp";
        nv[1] = argv[2];
        nv[2] = argv[3];
        nv[3] = NULL;
        exec_tool("xrdcp", nv);
    }

    /* diag ... -> xrddiag ... */
    if (strcmp(cmd, "diag") == 0) {
        argv[1] = (char *) "xrddiag";
        exec_tool("xrddiag", &argv[1]);
    }

    /* replicas <url> -> xrdmapc <url> (cluster holder + space map). */
    if (strcmp(cmd, "replicas") == 0) {
        argv[1] = (char *) "xrdmapc";
        exec_tool("xrdmapc", &argv[1]);
    }

    /* sync <srcdir> <dstdir> -> xrdcp -r --sync <src> <dst> (recursive mirror, skip
     * same-size). Extra flags after the two operands pass through to xrdcp. */
    if (strcmp(cmd, "sync") == 0) {
        char **nv;
        int    k = 0, j;
        if (argc < 4) {
            fprintf(stderr, "xrd sync: needs <srcdir> <dstdir>\n");
            return 50;
        }
        nv = (char **) malloc((size_t) (argc + 3) * sizeof(char *));
        if (nv == NULL) { fprintf(stderr, "xrd: out of memory\n"); return 51; }
        nv[k++] = (char *) "xrdcp";
        nv[k++] = (char *) "-r";
        nv[k++] = (char *) "--sync";
        for (j = 2; j < argc; j++) { nv[k++] = argv[j]; }
        nv[k] = NULL;
        exec_tool("xrdcp", nv);
    }

    /* ping [-c N] <endpoint>: inline liveness + RTT probe. */
    if (strcmp(cmd, "ping") == 0) { return xrd_ping(argc, argv); }

    /* endpoint diagnostics: inline composition over libxrdc. */
    if (strcmp(cmd, "certinfo") == 0)  { return xrd_certinfo(argc, argv); }
    if (strcmp(cmd, "clockskew") == 0) { return xrd_clockskew(argc, argv); }
    if (strcmp(cmd, "whoami") == 0)    { return xrd_whoami(argc, argv); }
    if (strcmp(cmd, "caps") == 0)      { return xrd_caps(argc, argv); }

    /* doctor / login: inline cross-tool verbs (composition, no exec). */
    if (strcmp(cmd, "doctor") == 0) { return xrd_doctor(argc, argv); }
    if (strcmp(cmd, "login") == 0)  { return xrd_login(argc, argv); }

    /* mount / mounts / unmount: drive the FUSE3 driver + fusermount, or list mounts. */
    if (strcmp(cmd, "mount") == 0) { return xrd_mount(argc, argv); }
    if (strcmp(cmd, "mounts") == 0) { return xrd_list_mounts(); }
    if (strcmp(cmd, "unmount") == 0 || strcmp(cmd, "umount") == 0) {
        return xrd_unmount(argc, argv);
    }

    /* filesystem verb. xrdfs separates the connect endpoint from the path, so when
     * the target is a full root:// URL (or an alias that resolves to one) carrying a
     * path, split it: `xrd stat root://h//d/f` -> `xrdfs root://h:port stat /d/f`.
     * A bare host:port (or anything not a root:// URL) is passed through unchanged. */
    if (is_fs_verb(cmd)) {
        char        resolved[XRDC_PATH_MAX];
        char        endpoint[320];
        xrdc_url    u;
        xrdc_status st;
        char      **nv;
        int         i, k = 0, split = 0, ep_idx = -1;

        if (argc < 3) {
            fprintf(stderr, "xrd %s: needs an <endpoint>\n", cmd);
            return 50;
        }
        /* Find the FIRST arg that resolves to a root:// URL; it fixes the connect
         * endpoint (path depth doesn't matter — `root://h//` targets the root).
         * Scanning (rather than assuming argv[2]) lets flags precede the endpoint,
         * e.g. `xrd df -h root://h//` or `xrd ln -s root://h//tgt root://h//link`. */
        for (i = 2; i < argc; i++) {
            xrdc_status_clear(&st);
            xrdc_alias_resolve(argv[i], resolved, sizeof(resolved));
            if (xrdc_url_parse(resolved, &u, &st) == 0
                && (u.scheme == XRDC_SCHEME_ROOT || u.scheme == XRDC_SCHEME_ROOTS)) {
                const char *scheme = (u.scheme == XRDC_SCHEME_ROOTS) ? "roots" : "root";
                int         v6 = (strchr(u.host, ':') != NULL);
                snprintf(endpoint, sizeof(endpoint), "%s://%s%s%s:%d", scheme,
                         v6 ? "[" : "", u.host, v6 ? "]" : "", u.port);
                split  = 1;
                ep_idx = i;
                break;
            }
        }
        nv = (char **) malloc((size_t) (argc + 3) * sizeof(char *));
        if (nv == NULL) { fprintf(stderr, "xrd: out of memory\n"); return 51; }
        nv[k++] = (char *) "xrdfs";
        if (split) {
            nv[k++] = endpoint;        /* connect endpoint (host:port) */
            nv[k++] = (char *) cmd;    /* the verb */
            /* Map every arg: the endpoint-bearing URL and any further same-endpoint
             * URL/alias become their path components; flags and bare paths pass
             * through. So flags-before-endpoint and multi-path verbs (mv/ln) work. */
            for (i = 2; i < argc; i++) {
                int   mism = 0;
                char *m;
                if (i == ep_idx) {
                    /* Emit an explicit path only when the URL carried one; a bare
                     * `root://h//` (path "/" or empty) leaves the verb to default. */
                    if (u.path[0] == '/' && u.path[1] != '\0') {
                        nv[k++] = strdup(u.path);
                    }
                    continue;
                }
                m = map_fs_arg(argv[i], u.host, u.port, &mism);
                if (mism) {
                    fprintf(stderr, "xrd %s: every path must be on the same endpoint "
                                    "(%s)\n", cmd, endpoint);
                    free(nv);
                    return 50;
                }
                nv[k++] = m;
            }
        } else {
            nv[k++] = argv[2];         /* bare endpoint as given */
            nv[k++] = (char *) cmd;
            for (i = 3; i < argc; i++) {   /* paths/flags verbatim */
                nv[k++] = argv[i];
            }
        }
        nv[k] = NULL;
        exec_tool("xrdfs", nv);
    }

    fprintf(stderr, "xrd: unknown command '%s'\n\n", cmd);
    usage();
    return 50;
}
